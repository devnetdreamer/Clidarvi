#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 devnetdreamer (https://github.com/devnetdreamer) and Clidarvi contributors
"""Generate a deterministic CycloneDX inventory from the pinned runtime lock.

The SBOM deliberately models a flat application-to-package dependency set. The
pip lock remains authoritative for resolution and artifact hashes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
import uuid
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = ROOT / "requirements-lock" / "runtime-py313.txt"
REQUIREMENT_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)")
HASH_RE = re.compile(r"--hash=sha256:([0-9a-f]{64})")

# These expressions describe the reviewed Python distributions in the official
# runtime lock. Compound expressions include material that an upstream wheel or
# sdist vendors (for example Netmiko's telnetlib and PyNaCl's libsodium). They do
# not replace the license files and nested-component notices shipped upstream.
#
# Coverage is intentionally exact and fail-closed: any package, version, or
# permitted-artifact hash change requires a fresh license review and explicit
# updates to both the reviewed mapping and fingerprint below.
REVIEWED_RUNTIME_LOCK_SHA256 = (
    "44643ce5bbdc6b657b214b948e6c66ed1750b9332c61b7a8034ff59c0d5b254d"  # pragma: allowlist secret
)
REVIEWED_RUNTIME_LICENSES = {
    "bcrypt": ("5.0.0", "Apache-2.0"),
    "cffi": ("2.1.1", "MIT-0"),
    "cryptography": ("50.0.1", "Apache-2.0 OR BSD-3-Clause"),
    "defusedxml": ("0.7.1", "PSF-2.0"),
    "invoke": ("3.0.3", "BSD-2-Clause"),
    "markdown-it-py": ("4.2.0", "MIT"),
    "mdurl": ("0.1.2", "MIT"),
    "netmiko": ("4.7.0", "MIT AND Python-2.0"),
    "ntc-templates": ("9.2.0", "Apache-2.0"),
    "paramiko": ("4.0.0", "LGPL-2.1-or-later"),
    "pycparser": ("3.0", "BSD-3-Clause"),
    "pygments": ("2.21.0", "BSD-2-Clause"),
    "pynacl": ("1.6.2", "Apache-2.0 AND ISC"),
    "pyqt6": ("6.11.0", "GPL-3.0-only"),
    "pyqt6-qt6": ("6.11.2", "LGPL-3.0-only AND GPL-3.0-only"),
    "pyqt6-sip": ("13.12.0", "BSD-2-Clause"),
    "pyserial": ("3.5", "BSD-3-Clause"),
    "pyyaml": ("6.0.3", "MIT"),
    "rich": ("15.0.0", "MIT"),
    "ruamel-yaml": ("0.19.1", "MIT"),
    "scp": ("0.16.1", "LGPL-2.1-or-later"),
    "textfsm": ("2.1.0", "Apache-2.0"),
}


def canonical_name(name: str) -> str:
    """Return the PEP 503 normalized distribution name."""

    return re.sub(r"[-_.]+", "-", name).lower()


def parse_lock(lock_text: str) -> list[tuple[str, str, list[str]]]:
    """Extract pinned packages and permitted distribution hashes."""

    packages: list[tuple[str, str, list[str]]] = []
    current_name: str | None = None
    current_version: str | None = None
    current_hashes: list[str] = []

    def finish() -> None:
        nonlocal current_name, current_version, current_hashes
        if current_name is None or current_version is None:
            return
        if not current_hashes:
            raise ValueError(f"{current_name}=={current_version} has no SHA-256 hashes")
        packages.append((current_name, current_version, sorted(set(current_hashes))))
        current_name = None
        current_version = None
        current_hashes = []

    for raw_line in lock_text.splitlines():
        line = raw_line.strip()
        match = REQUIREMENT_RE.match(line)
        if match:
            finish()
            current_name = canonical_name(match.group(1))
            current_version = match.group(2)
        if current_name is not None:
            current_hashes.extend(HASH_RE.findall(line))
    finish()

    if not packages:
        raise ValueError("lock contains no pinned packages")
    names = [name for name, _, _ in packages]
    if len(names) != len(set(names)):
        raise ValueError("lock contains duplicate normalized package names")
    return sorted(packages)


def build_sbom(lock_path: Path) -> dict[str, object]:
    lock_bytes = lock_path.read_bytes()
    lock_text = lock_bytes.decode("utf-8")
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    version = str(project["version"])
    app_ref = f"pkg:pypi/clidarvi@{quote(version, safe='')}"
    snapshot_digest = hashlib.sha256(lock_bytes).hexdigest()

    packages = parse_lock(lock_text)
    locked_versions = {name: package_version for name, package_version, _ in packages}
    locked_names = set(locked_versions)
    reviewed_names = set(REVIEWED_RUNTIME_LICENSES)
    unreviewed = sorted(locked_names - reviewed_names)
    stale_reviews = sorted(reviewed_names - locked_names)
    version_mismatches = sorted(
        name
        for name in locked_names & reviewed_names
        if locked_versions[name] != REVIEWED_RUNTIME_LICENSES[name][0]
    )
    if unreviewed or stale_reviews or version_mismatches:
        details: list[str] = []
        if unreviewed:
            details.append(f"unreviewed locked packages: {', '.join(unreviewed)}")
        if stale_reviews:
            details.append(f"license mappings absent from lock: {', '.join(stale_reviews)}")
        if version_mismatches:
            formatted = ", ".join(
                f"{name}=={locked_versions[name]} (reviewed {REVIEWED_RUNTIME_LICENSES[name][0]})"
                for name in version_mismatches
            )
            details.append(f"unreviewed package versions: {formatted}")
        raise ValueError("runtime license review does not match lock (" + "; ".join(details) + ")")
    if snapshot_digest != REVIEWED_RUNTIME_LOCK_SHA256:
        raise ValueError(
            "runtime lock artifact hashes or bytes have not been reviewed "
            f"(found {snapshot_digest}, reviewed {REVIEWED_RUNTIME_LOCK_SHA256})"
        )

    components: list[dict[str, object]] = []
    dependency_refs: list[str] = []
    for name, package_version, _hashes in packages:
        bom_ref = f"pkg:pypi/{quote(name, safe='')}@{quote(package_version, safe='')}"
        dependency_refs.append(bom_ref)
        component: dict[str, object] = {
            "type": "library",
            "bom-ref": bom_ref,
            "name": name,
            "version": package_version,
            "purl": bom_ref,
            "licenses": [{"expression": REVIEWED_RUNTIME_LICENSES[name][1]}],
        }
        components.append(component)

    bom: dict[str, object] = {
        "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": app_ref,
                "name": "clidarvi",
                "version": version,
                "purl": app_ref,
                "licenses": [{"expression": "GPL-3.0-only"}],
                "properties": [
                    {
                        "name": "clidarvi:runtime-lock",
                        "value": "requirements-lock/runtime-py313.txt",
                    },
                    {"name": "clidarvi:runtime-lock-sha256", "value": snapshot_digest},
                    {
                        "name": "clidarvi:dependency-model",
                        "value": "flattened pinned CPython 3.13 snapshot",
                    },
                    {
                        "name": "clidarvi:license-review-scope",
                        "value": (
                            "Python distribution level; consult each upstream package's "
                            "license files and nested-component notices"
                        ),
                    },
                ],
            }
        },
        "components": components,
        "dependencies": [{"ref": app_ref, "dependsOn": sorted(dependency_refs)}],
    }
    identity = json.dumps(bom, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    identity_digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"clidarvi-sbom:{identity_digest}")
    bom["serialNumber"] = f"urn:uuid:{serial}"
    return bom


def rendered_sbom(lock_path: Path) -> str:
    return json.dumps(build_sbom(lock_path), indent=2, sort_keys=True) + "\n"


def validate_cyclonedx(rendered: str) -> None:
    """Validate with CycloneDX's strict schema validator when requested."""

    try:
        from cyclonedx.schema import SchemaVersion
        from cyclonedx.validation.json import JsonStrictValidator
    except ImportError as exc:
        raise RuntimeError(
            "CycloneDX schema validation dependencies are missing; install dev-py313.txt"
        ) from exc

    result = JsonStrictValidator(SchemaVersion.V1_6).validate_str(rendered, all_errors=True)
    if result:
        errors = "\n".join(str(error) for error in result)
        raise ValueError(f"invalid CycloneDX 1.6 SBOM:\n{errors}")


def main() -> int:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    default_output = ROOT / "sbom" / f"clidarvi-{project['version']}.cdx.json"
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--output", type=Path, default=default_output)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--validate-schema", action="store_true")
    args = parser.parse_args()

    expected = rendered_sbom(args.lock)
    if args.validate_schema:
        try:
            validate_cyclonedx(expected)
        except (RuntimeError, ValueError) as exc:
            print(exc, file=sys.stderr)
            return 1
    if args.check:
        try:
            actual = args.output.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"missing SBOM: {args.output}", file=sys.stderr)
            return 1
        if actual != expected:
            print(f"stale SBOM: regenerate {args.output}", file=sys.stderr)
            return 1
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(expected, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
