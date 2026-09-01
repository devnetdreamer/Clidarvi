# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 devnetdreamer (https://github.com/devnetdreamer) and Clidarvi contributors
# Additional warranty, liability, and operational terms: see DISCLAIMER.md and TERMS.md.

"""Safe, atomic filesystem helpers used by Clidarvi.

The UI lets users select arbitrary output locations.  Consequently these helpers
never change permissions on an existing parent directory unless the caller
explicitly marks it as application-owned.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import stat
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600


def apply_private_permissions(path: Path | str, mode: int, *, strict: bool = False) -> bool:
    """Apply *mode* on POSIX and report whether it succeeded.

    Permission changes are not portable to Windows.  There they are treated as a
    successful no-op.  Security-sensitive callers may request an exception on a
    POSIX failure with ``strict=True``.
    """

    if os.name != "posix":
        return True
    descriptor: int | None = None
    try:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(Path(path), flags)
        opened = os.fstat(descriptor)
        linked = os.lstat(Path(path))
        if not (
            stat.S_ISREG(opened.st_mode) or stat.S_ISDIR(opened.st_mode)
        ) or not os.path.samestat(opened, linked):
            raise OSError("Permission target changed unexpectedly or has an unsafe file type.")
        os.fchmod(descriptor, mode)
        return True
    except OSError:
        if strict:
            raise
        return False
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def ensure_directory(path: Path | str, *, private: bool = False) -> Path:
    """Create a directory and optionally restrict the final directory itself."""

    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True)
    if private:
        apply_private_permissions(directory, PRIVATE_DIRECTORY_MODE, strict=True)
    return directory


def _prepare_parent(path: Path, *, secure_existing_parent: bool) -> bool:
    """Ensure the parent exists and return whether it was newly observed."""

    parent_existed = path.parent.exists()
    path.parent.mkdir(parents=True, exist_ok=True)
    if secure_existing_parent or not parent_existed:
        apply_private_permissions(path.parent, PRIVATE_DIRECTORY_MODE, strict=True)
    return not parent_existed


def _apply_fd_permissions(fd: int, mode: int) -> None:
    """Set an already-open file's POSIX mode without resolving its path again."""

    if os.name == "posix":
        os.fchmod(fd, mode)


def _verified_regular_file(
    fd: int,
    path: Path | str,
    *,
    directory_fd: int | None = None,
) -> os.stat_result:
    """Return an open file's identity after verifying its directory entry."""

    opened = os.fstat(fd)
    if directory_fd is None:
        linked = os.lstat(path)
    else:
        linked = os.stat(path, dir_fd=directory_fd, follow_symlinks=False)
    if (
        not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(linked.st_mode)
        or not os.path.samestat(opened, linked)
    ):
        raise OSError("Atomic-write staging file changed unexpectedly.")
    return opened


def _open_verified_directory(path: Path) -> tuple[int, os.stat_result]:
    """Open and pin a POSIX directory without following its final component."""

    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        linked = os.lstat(path)
        if not stat.S_ISDIR(opened.st_mode) or not os.path.samestat(opened, linked):
            raise OSError("Atomic-write parent directory changed unexpectedly.")
        return descriptor, opened
    except BaseException:
        os.close(descriptor)
        raise


def _verify_directory_path(
    descriptor: int,
    identity: os.stat_result,
    path: Path,
    *,
    message: str,
) -> None:
    """Ensure *path* still names the directory pinned by *descriptor*."""

    opened = os.fstat(descriptor)
    linked = os.lstat(path)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(linked.st_mode)
        or not os.path.samestat(identity, opened)
        or not os.path.samestat(identity, linked)
    ):
        raise OSError(message)


def _create_posix_staging(parent_fd: int) -> tuple[str, int, os.stat_result]:
    """Create and open a short, private staging directory below *parent_fd*."""

    for _attempt in range(100):
        name = f".cv-{secrets.token_hex(6)}"
        try:
            os.mkdir(name, PRIVATE_DIRECTORY_MODE, dir_fd=parent_fd)
        except FileExistsError:
            continue
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            descriptor = os.open(name, flags, dir_fd=parent_fd)
        except BaseException:
            try:
                os.rmdir(name, dir_fd=parent_fd)
            except OSError:
                pass
            raise
        try:
            identity = os.fstat(descriptor)
            linked = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISDIR(identity.st_mode) or not os.path.samestat(identity, linked):
                raise OSError("Atomic-write staging directory changed unexpectedly.")
            return name, descriptor, identity
        except BaseException:
            os.close(descriptor)
            try:
                os.rmdir(name, dir_fd=parent_fd)
            except OSError:
                pass
            raise
    raise FileExistsError("Could not allocate a private atomic-write staging directory.")


def _verify_posix_staging(
    parent_fd: int,
    name: str,
    staging_fd: int,
    identity: os.stat_result,
) -> None:
    opened = os.fstat(staging_fd)
    linked = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(linked.st_mode)
        or not os.path.samestat(identity, opened)
        or not os.path.samestat(identity, linked)
    ):
        raise OSError("Atomic-write staging directory changed unexpectedly.")


def _best_effort_fsync(descriptor: int | None) -> None:
    """Attempt durability without changing a completed publication's result."""

    if descriptor is None:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass


def _quiet_close(descriptor: int | None) -> None:
    if descriptor is None:
        return
    try:
        os.close(descriptor)
    except OSError:
        pass


def atomic_write_with(
    path: Path | str,
    writer: Callable[[Path], None],
    *,
    mode: int = PRIVATE_FILE_MODE,
    secure_existing_parent: bool = False,
) -> Path:
    """Atomically replace *path* using a caller-provided temporary-file writer.

    A private staging directory lives beside the destination so ``os.replace``
    remains an atomic same-filesystem operation without exposing the temporary
    payload directly in a shared parent.  Existing parent permissions are
    preserved by default.

    Before publication, payload data and permissions are flushed and verified.
    POSIX publication is relative to held parent/staging descriptors and rejects
    a symlinked or replaced final parent directory.  After ``os.replace`` has
    succeeded, directory flushes and cleanup are deliberately best-effort:
    success means the atomic replacement happened, while crash durability still
    depends on the filesystem and operating system.  A late durability failure
    is never misreported as a failed save after the new file is already visible.
    """

    requested_destination = Path(path)
    destination = Path(os.path.abspath(os.fspath(requested_destination)))
    parent_was_created = _prepare_parent(
        destination,
        secure_existing_parent=secure_existing_parent,
    )

    if os.name == "posix":
        parent_fd: int | None = None
        staging_fd: int | None = None
        payload_fd: int | None = None
        staging_name: str | None = None
        staging_identity: os.stat_result | None = None
        payload_name = "payload.tmp"
        try:
            parent_fd, parent_identity = _open_verified_directory(destination.parent)
            if secure_existing_parent or parent_was_created:
                os.fchmod(parent_fd, PRIVATE_DIRECTORY_MODE)
                _verify_directory_path(
                    parent_fd,
                    parent_identity,
                    destination.parent,
                    message="Atomic-write parent directory changed unexpectedly.",
                )
            staging_name, staging_fd, staging_identity = _create_posix_staging(parent_fd)
            temporary = destination.parent / staging_name / payload_name
            create_flags = (
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            payload_fd = os.open(
                payload_name,
                create_flags,
                mode,
                dir_fd=staging_fd,
            )
            _apply_fd_permissions(payload_fd, mode)
            payload_identity = _verified_regular_file(
                payload_fd,
                payload_name,
                directory_fd=staging_fd,
            )

            writer(temporary)

            _verify_directory_path(
                parent_fd,
                parent_identity,
                destination.parent,
                message="Atomic-write parent directory changed before publication.",
            )
            _verify_posix_staging(
                parent_fd,
                staging_name,
                staging_fd,
                staging_identity,
            )
            linked_identity = _verified_regular_file(
                payload_fd,
                payload_name,
                directory_fd=staging_fd,
            )
            if not os.path.samestat(payload_identity, linked_identity):
                raise OSError("Atomic-write staging file changed unexpectedly.")
            _apply_fd_permissions(payload_fd, mode)
            os.fsync(payload_fd)
            _verified_regular_file(
                payload_fd,
                payload_name,
                directory_fd=staging_fd,
            )
            _verify_directory_path(
                parent_fd,
                parent_identity,
                destination.parent,
                message="Atomic-write parent directory changed before publication.",
            )
            _verify_posix_staging(
                parent_fd,
                staging_name,
                staging_fd,
                staging_identity,
            )

            os.replace(
                payload_name,
                destination.name,
                src_dir_fd=staging_fd,
                dst_dir_fd=parent_fd,
            )

            # Both sides of the cross-directory rename are flushed where the
            # platform supports it. Nothing after publication may turn the
            # completed replacement into a false failure report.
            _best_effort_fsync(staging_fd)
            _best_effort_fsync(parent_fd)
            return requested_destination
        finally:
            if staging_fd is not None:
                try:
                    os.unlink(payload_name, dir_fd=staging_fd)
                except OSError:
                    pass
            _quiet_close(payload_fd)
            _quiet_close(staging_fd)
            if parent_fd is not None and staging_name is not None and staging_identity is not None:
                try:
                    linked = os.stat(staging_name, dir_fd=parent_fd, follow_symlinks=False)
                    if os.path.samestat(staging_identity, linked):
                        os.rmdir(staging_name, dir_fd=parent_fd)
                except OSError:
                    pass
            _quiet_close(parent_fd)

    # Windows does not expose the directory-relative primitives used above.
    # Keep the staging name independent of the destination length (important at
    # NAME_MAX boundaries), and retain the original inode identity across the
    # writer before closing the CRT descriptor for ReplaceFile/MoveFileEx.
    staging = Path(
        tempfile.mkdtemp(
            prefix=".cv-",
            dir=str(destination.parent),
        )
    )
    temporary = staging / "payload.tmp"
    payload_fd: int | None = None
    try:
        # mkdtemp creates the directory with mode 0o700 atomically on POSIX.
        # Do not chmod this path afterward: in a shared parent that would
        # reintroduce a symlink-swap window before the payload is created.
        create_flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        payload_fd = os.open(temporary, create_flags, mode)
        _apply_fd_permissions(payload_fd, mode)
        payload_identity = os.fstat(payload_fd)

        writer(temporary)

        linked_identity = _verified_regular_file(payload_fd, temporary)
        if not os.path.samestat(payload_identity, linked_identity):
            raise OSError("Atomic-write staging file changed unexpectedly.")
        _apply_fd_permissions(payload_fd, mode)
        os.fsync(payload_fd)
        _verified_regular_file(payload_fd, temporary)
        os.close(payload_fd)
        payload_fd = None

        os.replace(temporary, destination)
        return requested_destination
    finally:
        _quiet_close(payload_fd)
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        try:
            staging.rmdir()
        except OSError:
            pass


def atomic_write_text(
    path: Path | str,
    content: str,
    *,
    mode: int = PRIVATE_FILE_MODE,
    secure_existing_parent: bool = False,
) -> Path:
    """Write UTF-8 text atomically with private file permissions."""

    def write(temporary: Path) -> None:
        with temporary.open("w", encoding="utf-8", newline="") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())

    return atomic_write_with(
        path,
        write,
        mode=mode,
        secure_existing_parent=secure_existing_parent,
    )


def atomic_copy_file(
    source: Path | str,
    destination: Path | str,
    *,
    mode: int = PRIVATE_FILE_MODE,
    secure_existing_parent: bool = False,
) -> Path:
    """Copy a file through the same atomic publication path as normal writes."""

    source_path = Path(source)

    def write(temporary: Path) -> None:
        with source_path.open("rb") as source_handle, temporary.open("wb") as destination_handle:
            shutil.copyfileobj(source_handle, destination_handle, length=1024 * 1024)
            destination_handle.flush()
            os.fsync(destination_handle.fileno())

    return atomic_write_with(
        destination,
        write,
        mode=mode,
        secure_existing_parent=secure_existing_parent,
    )


def atomic_write_json(
    path: Path | str,
    value: Any,
    *,
    mode: int = PRIVATE_FILE_MODE,
    secure_existing_parent: bool = False,
) -> Path:
    """Serialize JSON deterministically and atomically."""

    payload = json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    return atomic_write_text(
        path,
        payload,
        mode=mode,
        secure_existing_parent=secure_existing_parent,
    )
