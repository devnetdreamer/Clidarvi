#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 devnetdreamer (https://github.com/devnetdreamer) and Clidarvi contributors
"""Create or verify deterministic SHA256SUMS for release artifacts."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path


def digest(path: Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def render(paths: list[Path]) -> str:
    by_name: dict[str, Path] = {}
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"not a regular file: {path}")
        if path.name in by_name:
            raise ValueError(f"duplicate artifact basename: {path.name}")
        by_name[path.name] = path
    if not by_name:
        raise ValueError("no release artifacts supplied")
    return "".join(f"{digest(by_name[name])}  {name}\n" for name in sorted(by_name))


def require_exact_directory(paths: list[Path], output: Path) -> None:
    """Require one flat release directory containing only inputs plus the manifest."""

    if not paths:
        raise ValueError("exact-directory validation requires explicit release artifacts")
    expected = {output.name}
    for path in paths:
        if path.parent != output.parent:
            raise ValueError(f"artifact must be a direct child of {output.parent}: {path}")
        if path.name == output.name:
            raise ValueError("checksum manifest cannot also be an input artifact")
        expected.add(path.name)
    try:
        entries = tuple(output.parent.iterdir())
    except OSError as exc:
        raise ValueError(f"cannot inspect release directory: {output.parent}") from exc
    non_regular = sorted(
        entry.name for entry in entries if entry.is_symlink() or not entry.is_file()
    )
    if non_regular:
        raise ValueError(
            "release directory contains non-regular entries: " + ", ".join(non_regular)
        )
    actual = {entry.name for entry in entries}
    if actual != expected:
        missing = ", ".join(sorted(expected - actual)) or "none"
        unexpected = ", ".join(sorted(actual - expected)) or "none"
        raise ValueError(
            f"release directory is not exact (missing: {missing}; unexpected: {unexpected})"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifacts", nargs="*", type=Path)
    parser.add_argument("--output", type=Path, default=Path("dist/SHA256SUMS"))
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--require-exact-directory", action="store_true")
    args = parser.parse_args()

    if args.require_exact_directory and not args.artifacts:
        parser.error("--require-exact-directory requires explicit artifacts")

    if args.check:
        try:
            actual = args.output.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"missing checksum manifest: {args.output}", file=sys.stderr)
            return 1
        if args.artifacts:
            try:
                expected = render(args.artifacts)
            except ValueError as exc:
                parser.error(str(exc))
            if actual != expected:
                print(
                    "FAILED: checksum manifest is incomplete, duplicated, out of order, "
                    "or stale for the supplied artifact set",
                    file=sys.stderr,
                )
                return 1
            if args.require_exact_directory:
                try:
                    require_exact_directory(args.artifacts, args.output)
                except ValueError as exc:
                    print(f"FAILED: {exc}", file=sys.stderr)
                    return 1
            return 0

        entries = actual.splitlines()
        failed = False
        seen_names: set[str] = set()
        for entry in entries:
            expected, separator, name = entry.partition("  ")
            path = args.output.parent / name
            valid_digest = len(expected) == 64 and all(c in "0123456789abcdef" for c in expected)
            safe_name = bool(name) and Path(name).name == name
            if (
                not separator
                or not valid_digest
                or not safe_name
                or name in seen_names
                or not path.is_file()
                or digest(path) != expected
            ):
                print(f"FAILED: {name or entry}", file=sys.stderr)
                failed = True
            seen_names.add(name)
        return int(failed or not entries)

    try:
        contents = render(args.artifacts)
    except ValueError as exc:
        parser.error(str(exc))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(contents, encoding="utf-8", newline="\n")
    if args.require_exact_directory:
        try:
            require_exact_directory(args.artifacts, args.output)
        except ValueError as exc:
            print(f"FAILED: {exc}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
