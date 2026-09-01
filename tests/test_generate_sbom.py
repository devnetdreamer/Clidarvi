# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 devnetdreamer (https://github.com/devnetdreamer) and Clidarvi contributors

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "generate_sbom.py"
NOTICE_PATH = ROOT / "THIRD_PARTY_NOTICES.md"
SPEC = importlib.util.spec_from_file_location("clidarvi_generate_sbom", MODULE_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import machinery invariant
    raise RuntimeError(f"cannot load {MODULE_PATH}")
generate_sbom = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generate_sbom)


class SbomLicenseTests(unittest.TestCase):
    def test_runtime_lock_and_reviewed_license_snapshot_match_exactly(self):
        packages = generate_sbom.parse_lock(generate_sbom.DEFAULT_LOCK.read_text(encoding="utf-8"))
        locked_versions = {name: version for name, version, _hashes in packages}
        reviewed_versions = {
            name: version
            for name, (version, _expression) in generate_sbom.REVIEWED_RUNTIME_LICENSES.items()
        }

        self.assertEqual(locked_versions, reviewed_versions)
        self.assertEqual(len(locked_versions), 22)
        self.assertEqual(
            generate_sbom.hashlib.sha256(generate_sbom.DEFAULT_LOCK.read_bytes()).hexdigest(),
            generate_sbom.REVIEWED_RUNTIME_LOCK_SHA256,
        )

    def test_every_runtime_component_has_a_reviewed_license_expression(self):
        sbom = generate_sbom.build_sbom(generate_sbom.DEFAULT_LOCK)
        components = sbom["components"]

        self.assertEqual(len(components), 22)
        self.assertTrue(all(component.get("licenses") for component in components))
        by_name = {
            component["name"]: component["licenses"][0]["expression"] for component in components
        }
        self.assertEqual(by_name["cryptography"], "Apache-2.0 OR BSD-3-Clause")
        self.assertEqual(by_name["netmiko"], "MIT AND Python-2.0")
        self.assertEqual(by_name["paramiko"], "LGPL-2.1-or-later")
        self.assertEqual(by_name["pynacl"], "Apache-2.0 AND ISC")
        self.assertEqual(by_name["pyqt6-qt6"], "LGPL-3.0-only AND GPL-3.0-only")

    def test_notice_table_matches_reviewed_snapshot_exactly(self):
        notice_rows: dict[str, tuple[str, str]] = {}
        for line in NOTICE_PATH.read_text(encoding="utf-8").splitlines():
            if not line.startswith("| ") or line.startswith("| ---"):
                continue
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            if cells[0] == "Distribution":
                continue
            if len(cells) == 4:
                notice_rows[generate_sbom.canonical_name(cells[0])] = (cells[1], cells[2])

        self.assertEqual(notice_rows, generate_sbom.REVIEWED_RUNTIME_LICENSES)

    def test_unreviewed_locked_package_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            lock_path = Path(temporary_directory) / "runtime.txt"
            lock_path.write_text(
                "mystery-package==1.0 \\\n    --hash=sha256:" + "a" * 64 + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "unreviewed locked packages: mystery-package"):
                generate_sbom.build_sbom(lock_path)

    def test_stale_license_mapping_fails_closed(self):
        mappings = dict(generate_sbom.REVIEWED_RUNTIME_LICENSES)
        mappings["removed-package"] = ("1.0", "MIT")

        with patch.object(generate_sbom, "REVIEWED_RUNTIME_LICENSES", mappings):
            with self.assertRaisesRegex(
                ValueError, "license mappings absent from lock: removed-package"
            ):
                generate_sbom.build_sbom(generate_sbom.DEFAULT_LOCK)

    def test_same_name_version_change_requires_fresh_review(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            lock_path = Path(temporary_directory) / "runtime.txt"
            lock_path.write_bytes(
                generate_sbom.DEFAULT_LOCK.read_bytes().replace(
                    b"bcrypt==5.0.0", b"bcrypt==99.0.0", 1
                )
            )

            with self.assertRaisesRegex(
                ValueError, r"unreviewed package versions: bcrypt==99\.0\.0 \(reviewed 5\.0\.0\)"
            ):
                generate_sbom.build_sbom(lock_path)

    def test_same_versions_with_changed_artifact_hash_require_fresh_review(self):
        lock_bytes = generate_sbom.DEFAULT_LOCK.read_bytes()
        first_hash = generate_sbom.HASH_RE.search(lock_bytes.decode("utf-8"))
        self.assertIsNotNone(first_hash)
        original_digest = first_hash.group(1).encode("ascii")
        replacement_digest = b"0" * 64 if original_digest != b"0" * 64 else b"1" * 64

        with tempfile.TemporaryDirectory() as temporary_directory:
            lock_path = Path(temporary_directory) / "runtime.txt"
            lock_path.write_bytes(lock_bytes.replace(original_digest, replacement_digest, 1))

            with self.assertRaisesRegex(
                ValueError, "runtime lock artifact hashes or bytes have not been reviewed"
            ):
                generate_sbom.build_sbom(lock_path)

    def test_bom_identity_is_deterministic_and_changes_with_reviewed_content(self):
        first = generate_sbom.build_sbom(generate_sbom.DEFAULT_LOCK)
        second = generate_sbom.build_sbom(generate_sbom.DEFAULT_LOCK)
        self.assertEqual(first["serialNumber"], second["serialNumber"])

        mappings = dict(generate_sbom.REVIEWED_RUNTIME_LICENSES)
        mappings["bcrypt"] = ("5.0.0", "Apache-2.0 OR MIT")
        with patch.object(generate_sbom, "REVIEWED_RUNTIME_LICENSES", mappings):
            changed = generate_sbom.build_sbom(generate_sbom.DEFAULT_LOCK)

        self.assertNotEqual(first["serialNumber"], changed["serialNumber"])

    def test_sbom_declares_distribution_level_license_review_scope(self):
        sbom = generate_sbom.build_sbom(generate_sbom.DEFAULT_LOCK)
        properties = {
            item["name"]: item["value"] for item in sbom["metadata"]["component"]["properties"]
        }

        self.assertIn("Python distribution level", properties["clidarvi:license-review-scope"])
        self.assertIn("nested-component notices", properties["clidarvi:license-review-scope"])


if __name__ == "__main__":
    unittest.main()
