# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 devnetdreamer (https://github.com/devnetdreamer) and Clidarvi contributors

from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from clidarvi_io import (
    apply_private_permissions,
    atomic_copy_file,
    atomic_write_json,
    atomic_write_text,
    atomic_write_with,
)


class AtomicWriteTests(unittest.TestCase):
    def test_text_write_replaces_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            destination = Path(temporary_directory) / "output.txt"
            atomic_write_text(destination, "first")
            atomic_write_text(destination, "second")
            self.assertEqual(destination.read_text(encoding="utf-8"), "second")

    def test_json_write_is_valid_and_ends_with_newline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            destination = Path(temporary_directory) / "devices.json"
            atomic_write_json(destination, {"name": "r1"})
            payload = destination.read_text(encoding="utf-8")
            self.assertEqual(json.loads(payload), {"name": "r1"})
            self.assertTrue(payload.endswith("\n"))

    def test_json_write_rejects_nonfinite_numbers_without_publishing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            destination = Path(temporary_directory) / "devices.json"
            destination.write_text('{"name": "original"}\n', encoding="utf-8")

            with self.assertRaises(ValueError):
                atomic_write_json(destination, {"value": float("nan")})

            self.assertEqual(
                destination.read_text(encoding="utf-8"),
                '{"name": "original"}\n',
            )

    def test_failed_write_preserves_original_and_removes_temporary_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            destination = Path(temporary_directory) / "devices.json"
            destination.write_text("original", encoding="utf-8")

            def fail(_temporary: Path) -> None:
                raise RuntimeError("simulated failure")

            with self.assertRaisesRegex(RuntimeError, "simulated failure"):
                atomic_write_with(destination, fail)

            self.assertEqual(destination.read_text(encoding="utf-8"), "original")
            self.assertEqual(list(destination.parent.glob(".cv-*")), [])

    def test_writer_uses_a_private_staging_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            destination = Path(temporary_directory) / "output.txt"
            observed: dict[str, Path] = {}

            def write(temporary: Path) -> None:
                observed["temporary"] = temporary
                if os.name == "posix":
                    self.assertEqual(stat.S_IMODE(temporary.parent.stat().st_mode), 0o700)
                temporary.write_text("private payload", encoding="utf-8")

            atomic_write_with(destination, write)

            staged_path = observed["temporary"]
            self.assertEqual(staged_path.parent.parent, destination.parent)
            self.assertNotEqual(staged_path.parent, destination.parent)
            self.assertTrue(staged_path.parent.name.startswith(".cv-"))
            self.assertLessEqual(len(staged_path.parent.name), 20)
            self.assertFalse(staged_path.parent.exists())
            self.assertEqual(destination.read_text(encoding="utf-8"), "private payload")

    @unittest.skipUnless(
        os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
        "O_NOFOLLOW symlink assertion",
    )
    def test_writer_cannot_publish_a_swapped_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            parent = Path(temporary_directory)
            destination = parent / "output.txt"
            external = parent / "external.txt"
            external.write_text("external", encoding="utf-8")

            def replace_with_symlink(temporary: Path) -> None:
                temporary.unlink()
                temporary.symlink_to(external)

            with self.assertRaises(OSError):
                atomic_write_with(destination, replace_with_symlink)

            self.assertFalse(destination.exists())
            self.assertEqual(external.read_text(encoding="utf-8"), "external")
            self.assertEqual(list(parent.glob(".cv-*")), [])

    def test_inode_mismatch_is_rejected_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            destination = Path(temporary_directory) / "output.txt"
            destination.write_text("original", encoding="utf-8")

            with patch(
                "clidarvi_io._verified_regular_file",
                side_effect=OSError("Atomic-write staging file changed unexpectedly."),
            ):
                with self.assertRaisesRegex(OSError, "staging file changed"):
                    atomic_write_text(destination, "replacement")

            self.assertEqual(destination.read_text(encoding="utf-8"), "original")
            self.assertEqual(list(destination.parent.glob(".cv-*")), [])

    def test_permissions_are_not_applied_by_path_after_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            destination = Path(temporary_directory) / "output.txt"
            published = False
            real_replace = os.replace

            def track_replace(source: Path | str, target: Path | str, **kwargs) -> None:
                nonlocal published
                real_replace(source, target, **kwargs)
                published = True

            def reject_late_path_chmod(path: Path | str, _mode: int, *, strict: bool) -> bool:
                if published and Path(path) == destination:
                    self.fail("destination path was chmodded after publication")
                return True

            with (
                patch("clidarvi_io.os.replace", side_effect=track_replace),
                patch(
                    "clidarvi_io.apply_private_permissions",
                    side_effect=reject_late_path_chmod,
                ),
            ):
                atomic_write_text(destination, "safe")

            self.assertEqual(destination.read_text(encoding="utf-8"), "safe")

    def test_replace_failure_preserves_original_and_cleans_staging(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            parent = Path(temporary_directory)
            destination = parent / "output.txt"
            destination.write_text("original", encoding="utf-8")

            with patch("clidarvi_io.os.replace", side_effect=OSError("replace failed")):
                with self.assertRaisesRegex(OSError, "replace failed"):
                    atomic_write_text(destination, "replacement")

            self.assertEqual(destination.read_text(encoding="utf-8"), "original")
            self.assertEqual(list(parent.glob(".cv-*")), [])

    @unittest.skipUnless(os.name == "posix", "POSIX directory fsync behavior")
    def test_directory_fsync_failure_after_publication_is_not_a_false_save_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            destination = Path(temporary_directory) / "output.txt"
            destination.write_text("original", encoding="utf-8")
            real_fsync = os.fsync

            def fail_directory_fsync(descriptor: int) -> None:
                if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                    raise OSError("simulated unsupported directory fsync")
                real_fsync(descriptor)

            def write(temporary: Path) -> None:
                temporary.write_text("published", encoding="utf-8")

            with patch("clidarvi_io.os.fsync", side_effect=fail_directory_fsync):
                result = atomic_write_with(destination, write)

            self.assertEqual(result, destination)
            self.assertEqual(destination.read_text(encoding="utf-8"), "published")
            self.assertEqual(list(destination.parent.glob(".cv-*")), [])

    @unittest.skipUnless(os.name == "posix", "POSIX held-parent behavior")
    def test_replaced_parent_is_rejected_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            parent = root / "inventory"
            moved_parent = root / "inventory-moved"
            parent.mkdir()
            destination = parent / "output.txt"
            destination.write_text("original", encoding="utf-8")

            def swap_parent(temporary: Path) -> None:
                temporary.write_text("replacement", encoding="utf-8")
                parent.rename(moved_parent)
                parent.mkdir()

            with self.assertRaisesRegex(OSError, "parent directory changed"):
                atomic_write_with(destination, swap_parent)

            self.assertFalse(destination.exists())
            self.assertEqual(
                (moved_parent / destination.name).read_text(encoding="utf-8"),
                "original",
            )
            self.assertEqual(list(moved_parent.glob(".cv-*")), [])

    @unittest.skipUnless(
        os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
        "POSIX no-follow behavior",
    )
    def test_symlinked_parent_and_permission_target_are_never_followed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            real_parent = root / "real"
            alias = root / "alias"
            real_parent.mkdir(mode=0o750)
            alias.symlink_to(real_parent, target_is_directory=True)
            writer_called = False

            def write(_temporary: Path) -> None:
                nonlocal writer_called
                writer_called = True

            with self.assertRaises(OSError):
                atomic_write_with(alias / "output.txt", write)
            self.assertFalse(writer_called)
            self.assertFalse((real_parent / "output.txt").exists())

            original_mode = stat.S_IMODE(real_parent.stat().st_mode)
            self.assertFalse(apply_private_permissions(alias, 0o700))
            with self.assertRaises(OSError):
                apply_private_permissions(alias, 0o700, strict=True)
            self.assertEqual(stat.S_IMODE(real_parent.stat().st_mode), original_mode)

    @unittest.skipUnless(os.name == "posix", "POSIX inode-swap behavior")
    def test_writer_cannot_replace_payload_with_another_regular_inode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            parent = Path(temporary_directory)
            destination = parent / "output.txt"
            destination.write_text("original", encoding="utf-8")

            def replace_inode(temporary: Path) -> None:
                temporary.unlink()
                temporary.write_text("attacker replacement", encoding="utf-8")

            with self.assertRaisesRegex(OSError, "staging file changed"):
                atomic_write_with(destination, replace_inode)

            self.assertEqual(destination.read_text(encoding="utf-8"), "original")
            self.assertEqual(list(parent.glob(".cv-*")), [])

    def test_long_destination_name_does_not_expand_staging_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            parent = Path(temporary_directory)
            destination = parent / ("x" * 240)
            observed: list[str] = []

            class ObservationComplete(Exception):
                pass

            def write(temporary: Path) -> None:
                observed.append(temporary.parent.name)
                temporary.write_text("safe", encoding="utf-8")
                # Publishing this deliberately NAME_MAX-adjacent component would
                # also test the machine-wide Win32 long-path policy. Stop after
                # observing the independent staging name; normal publication is
                # covered by the surrounding atomic-write tests.
                raise ObservationComplete

            with self.assertRaises(ObservationComplete):
                atomic_write_with(destination, write)

            self.assertEqual(len(observed), 1)
            self.assertLessEqual(len(observed[0]), 20)
            self.assertFalse(destination.exists())
            self.assertEqual(list(parent.glob(".cv-*")), [])

    def test_atomic_copy_creates_last_known_good_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory) / "devices.json"
            backup = Path(temporary_directory) / "devices.json.bak"
            source.write_bytes(b'{"valid": true}\n')

            atomic_copy_file(source, backup)

            self.assertEqual(backup.read_bytes(), source.read_bytes())

    @unittest.skipUnless(os.name == "posix", "POSIX symlink behavior")
    def test_existing_destination_symlink_is_replaced_not_followed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            parent = Path(temporary_directory)
            external = parent / "external.txt"
            destination = parent / "output.txt"
            external.write_text("external", encoding="utf-8")
            destination.symlink_to(external)

            atomic_write_text(destination, "published")

            self.assertFalse(destination.is_symlink())
            self.assertEqual(destination.read_text(encoding="utf-8"), "published")
            self.assertEqual(external.read_text(encoding="utf-8"), "external")

    @unittest.skipUnless(os.name == "posix", "POSIX permission assertion")
    def test_atomic_writes_apply_private_file_mode_on_posix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            destination = Path(temporary_directory) / "private" / "output.json"
            atomic_write_json(destination, {"key": "value"}, secure_existing_parent=True)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
            self.assertEqual(destination.parent.stat().st_mode & 0o777, 0o700)

    @unittest.skipUnless(os.name == "posix", "POSIX permission assertion")
    def test_existing_parent_permissions_are_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            parent = Path(temporary_directory) / "shared"
            parent.mkdir()
            parent.chmod(0o750)
            atomic_write_text(parent / "output.txt", "safe")
            actual_mode = stat.S_IMODE(parent.stat().st_mode)
            self.assertEqual(actual_mode, 0o750)


if __name__ == "__main__":
    unittest.main()
