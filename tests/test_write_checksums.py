# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 devnetdreamer (https://github.com/devnetdreamer) and Clidarvi contributors

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "write_checksums.py"


class WriteChecksumsTests(unittest.TestCase):
    def _run(self, *arguments: Path | str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *(str(argument) for argument in arguments)],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_exact_directory_generation_and_check_accept_only_declared_payload(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            dist = Path(temporary_directory) / "dist"
            dist.mkdir()
            first = dist / "artifact-a.whl"
            second = dist / "artifact-b.tar.gz"
            output = dist / "SHA256SUMS"
            first.write_bytes(b"wheel\n")
            second.write_bytes(b"source\n")

            generated = self._run(
                second,
                first,
                "--output",
                output,
                "--require-exact-directory",
            )
            checked = self._run(
                first,
                second,
                "--output",
                output,
                "--check",
                "--require-exact-directory",
            )

            self.assertEqual(generated.returncode, 0, generated.stderr)
            self.assertEqual(checked.returncode, 0, checked.stderr)
            self.assertEqual(
                [line.split("  ", 1)[1] for line in output.read_text().splitlines()],
                ["artifact-a.whl", "artifact-b.tar.gz"],
            )

    def test_exact_directory_rejects_unexpected_file_on_generate_and_check(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            dist = Path(temporary_directory) / "dist"
            dist.mkdir()
            artifact = dist / "artifact.whl"
            output = dist / "SHA256SUMS"
            artifact.write_bytes(b"wheel\n")
            extra = dist / "unexpected.bin"
            extra.write_bytes(b"unexpected\n")

            rejected_generate = self._run(
                artifact,
                "--output",
                output,
                "--require-exact-directory",
            )
            extra.unlink()
            generated = self._run(
                artifact,
                "--output",
                output,
                "--require-exact-directory",
            )
            extra.write_bytes(b"unexpected again\n")
            rejected_check = self._run(
                artifact,
                "--output",
                output,
                "--check",
                "--require-exact-directory",
            )

            self.assertEqual(rejected_generate.returncode, 1)
            self.assertIn("unexpected.bin", rejected_generate.stderr)
            self.assertEqual(generated.returncode, 0, generated.stderr)
            self.assertEqual(rejected_check.returncode, 1)
            self.assertIn("unexpected.bin", rejected_check.stderr)

    def test_declared_symlink_artifact_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            dist = root / "dist"
            dist.mkdir()
            real_artifact = root / "real.whl"
            real_artifact.write_bytes(b"wheel\n")
            artifact = dist / "artifact.whl"
            try:
                artifact.symlink_to(real_artifact)
            except OSError as exc:
                self.skipTest(f"Symlink creation is unavailable: {exc}")

            rejected = self._run(
                artifact,
                "--output",
                dist / "SHA256SUMS",
                "--require-exact-directory",
            )

            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("not a regular file", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
