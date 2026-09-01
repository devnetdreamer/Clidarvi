# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 devnetdreamer (https://github.com/devnetdreamer) and Clidarvi contributors
# Additional warranty, liability, and operational terms: see DISCLAIMER.md and TERMS.md.

"""Background workers for Clidarvi automation and interactive SSH sessions."""

from __future__ import annotations

import codecs
import ipaddress
import queue
import re
import socket
import threading
import time
import unicodedata
from collections import deque
from collections.abc import Mapping
from contextlib import contextmanager
from importlib import metadata as importlib_metadata
from pathlib import Path
from types import MappingProxyType

import paramiko
from netmiko import ConnectHandler
from PyQt6.QtCore import QThread, pyqtSignal

from clidarvi_core import validate_device_type
from clidarvi_policy import (
    CommandClass,
    PromptAction,
    classify_command,
    decide_follow_up,
    redact_command,
    redact_text_block,
)

MAX_COMMAND_LENGTH = 2048
MAX_PARALLEL_DEVICES = 10
MAX_DEVICE_TRANSCRIPT_CHARS = 500_000
MAX_TOTAL_TRANSCRIPT_CHARS = 5_000_000
MAX_DEVICE_LOG_ENTRY_CHARS = 100_000
MAX_COMMAND_RESPONSE_CHARS = 200_000
COMMAND_READ_TIMEOUT_SECONDS = 20.0
CONNECT_OPERATION_TIMEOUT_SECONDS = 30.0
MAX_LIVE_READ_BYTES_PER_TICK = 65_536
MAX_LIVE_READ_CHUNKS_PER_TICK = 8
MAX_LIVE_PENDING_INPUT_BYTES = 262_144
MAX_LIVE_INPUT_CHUNK_BYTES = 16_384
MAX_LIVE_PENDING_OUTPUT_CHARS = 262_144
MAX_DIAGNOSTIC_CHARS = 4_096
MAX_SSH_PRE_BANNER_BYTES = 4_096
MAX_SSH_IDENTIFICATION_LINE_BYTES = 255
MAX_SSH_SOCKET_RECV_BYTES = 64 * 1024
MAX_HOST_KEY_SSH_POST_BANNER_BYTES = 1 * 1024 * 1024
MAX_AUTOMATION_SSH_POST_BANNER_BYTES = 4 * 1024 * 1024
MAX_LIVE_SSH_POST_BANNER_BYTES = 16 * 1024 * 1024
UDM_READ_ONLY_DEVICE_TYPE = "ubiquiti_unifi_os"
UDM_READ_ONLY_COMMANDS = MappingProxyType(
    {
        "uptime": "uptime",
        "utc_time": "date -u",
        "kernel": "uname -a",
        "identity": "id",
    }
)
MAX_UDM_COMMAND_OUTPUT_BYTES = 128 * 1024
MAX_UDM_TOTAL_OUTPUT_BYTES = 512 * 1024
UDM_COMMAND_TIMEOUT_SECONDS = 15.0
UDM_CHANNEL_REQUEST_TIMEOUT_SECONDS = 5.0
EXPERIMENTAL_AUTOMATION_DEVICE_TYPES = frozenset({"aruba_os", "cisco_wlc", "fortinet"})
EXPERIMENTAL_AUTOMATION_NETMIKO_VERSION = "4.7.0"
GENERAL_AUTOMATION_BLOCKED_DEVICE_TYPES = frozenset({"generic", UDM_READ_ONLY_DEVICE_TYPE})
# Backward-compatible name for callers that only need the profiles which are
# still never eligible for general Automation.
AUTOMATION_LIVE_CLI_ONLY_DEVICE_TYPES = GENERAL_AUTOMATION_BLOCKED_DEVICE_TYPES
EXPERIMENTAL_AUTOMATION_SETUP_DISCLOSURES = MappingProxyType(
    {
        "aruba_os": (
            "the audited Netmiko 4.7.0 aruba_os driver can call enable() and send 'no paging' "
            "during session preparation before Clidarvi's reviewed plan"
        ),
        "cisco_wlc": (
            "the audited Netmiko 4.7.0 cisco_wlc driver can send 'config paging disable' "
            "session preparation; Clidarvi's abort-only teardown does not call its 'config "
            "paging enable' restoration cleanup"
        ),
        "fortinet": (
            "the audited Netmiko 4.7.0 fortinet driver can accept a login banner, inspect VDOM "
            "state, and send 'config global', 'config system console', and 'set output "
            "standard' before Clidarvi's reviewed plan; Clidarvi's abort-only teardown does "
            "not call its 'set output more' restoration cleanup"
        ),
    }
)
_LIVE_OUTPUT_OVERFLOW_NOTICE = (
    "\r\n[Live CLI closed: remote output queue safety limit reached.]\r\n"
)
_LIVE_RECEIVE_LIMIT_NOTICE = (
    "\r\n[Live CLI closed: the 16 MiB SSH receive safety quota was reached. "
    "Reopen the session to continue.]\r\n"
)

# Paramiko <=4.0.0 can otherwise negotiate SHA-1 for RSA signatures
# (CVE-2026-44405). Keep all connection paths fail-closed on legacy
# RSA/DSS, SHA-1 key exchange, SHA-1/MD5 MAC, and 3DES/CBC cipher algorithms.
SSH_DISABLED_ALGORITHMS = {
    "keys": ("ssh-rsa", "ssh-rsa-cert-v01@openssh.com", "ssh-dss"),
    "pubkeys": ("ssh-rsa", "ssh-rsa-cert-v01@openssh.com", "ssh-dss"),
    "kex": (
        "diffie-hellman-group-exchange-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group1-sha1",
    ),
    "macs": ("hmac-sha1", "hmac-sha1-96", "hmac-md5", "hmac-md5-96"),
    "ciphers": ("3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc"),
}


def ssh_disabled_algorithms() -> dict[str, list[str]]:
    """Return a fresh Paramiko/Netmiko algorithm policy for each transport."""

    return {category: list(names) for category, names in SSH_DISABLED_ALGORITHMS.items()}


COMMAND_ERROR_PATTERNS = (
    re.compile(
        r"^\s*%\s*(?:invalid input|incomplete command|ambiguous command)\b",
        re.IGNORECASE | re.MULTILINE,
    ),
    re.compile(
        r"^\s*(?:error\s*:\s*)?(?:invalid command|invalid input|unknown command|"
        r"invalid syntax|syntax error|command not found|command parse error|command fail)\b",
        re.IGNORECASE | re.MULTILINE,
    ),
)
AUTOMATIC_SAVE_DISABLED_MESSAGE = (
    "Library-managed automatic save is disabled in this experimental alpha. "
    "Put the vendor-documented save or commit command explicitly in the reviewed command plan."
)
AUTOMATIC_ENABLE_DISABLED_MESSAGE = (
    "Application-level enable mode is disabled in this experimental alpha. Clidarvi does "
    "not request optional enable mode after connection or supply a separate enable secret. "
    "An experimental driver's session setup may still invoke its own hidden privilege helper "
    "before control returns. Use an account that already has sufficient privilege for the "
    "reviewed command plan."
)
AUTOMATION_DISALLOWED_CONNECTION_OPTIONS = (
    "key_file",
    "pkey",
    "passphrase",
    "secret",
    "ssh_config_file",
)
CLI_PROMPT_SUFFIX_PATTERN = re.compile(r"(?:\s*\([^()\r\n]{1,128}\))*\s*[#>$%]\Z")
CISCO_IOS_TRUNCATED_PROMPT_SUFFIX_PATTERN = re.compile(
    r"[A-Za-z0-9_.-]{0,47}(?:\s*\([^()\r\n]{1,128}\))*\s*[#>]\Z"
)


class CommandExecutionError(Exception):
    """Raised when a device rejects a command."""


class SSHPreBannerLimitError(ConnectionError):
    """Raised before Paramiko can consume an oversized SSH identification stream."""


class SSHReceiveLimitError(ConnectionError):
    """Raised when an SSH transport exceeds its post-identification receive budget."""


def _reject_live_cli_only_automation_profiles(profiles) -> None:
    """Reject profiles which can never use general Automation."""

    blocked_profiles = sorted(set(profiles).intersection(GENERAL_AUTOMATION_BLOCKED_DEVICE_TYPES))
    if blocked_profiles:
        names = ", ".join(blocked_profiles)
        raise ValueError(
            "These profiles are not available through general Netmiko Automation in this "
            f"experimental alpha: {names}. Generic SSH has no validated platform-specific "
            "Automation driver. UniFi OS / UDM is restricted to its dedicated fixed "
            "diagnostics mode. Use that dedicated mode where available; otherwise use a "
            "reviewed Live CLI session."
        )


def validate_experimental_automation_runtime() -> str:
    """Require the exact Netmiko release whose hidden setup behavior was audited."""

    try:
        installed_version = importlib_metadata.version("netmiko")
    except importlib_metadata.PackageNotFoundError as exc:
        raise ValueError(
            "Experimental Automation requires Netmiko "
            f"{EXPERIMENTAL_AUTOMATION_NETMIKO_VERSION}, but Netmiko is not installed."
        ) from exc
    except Exception as exc:
        raise ValueError(
            "Experimental Automation is disabled because the exact installed Netmiko "
            "version could not be verified."
        ) from exc
    if installed_version != EXPERIMENTAL_AUTOMATION_NETMIKO_VERSION:
        raise ValueError(
            "Experimental Automation is disabled because its hidden driver setup was audited "
            f"only with Netmiko {EXPERIMENTAL_AUTOMATION_NETMIKO_VERSION}; installed version "
            f"is {installed_version}. Install the exact hashed runtime snapshot."
        )
    return installed_version


def _validate_netmiko_automation_profiles(
    values, *, allow_experimental_automation: bool = False
) -> tuple[str, ...]:
    """Validate a complete Automation scope before any network activity.

    Experimental Netmiko profiles are deliberately limited to one target and
    require an exact boolean opt-in. The scope is validated as a whole so a
    mixed or expanded run cannot bypass the one-target boundary.
    """

    if type(allow_experimental_automation) is not bool:
        raise ValueError("Experimental Automation opt-in must be an exact boolean value.")

    profiles = tuple(validate_device_type(value) for value in values)
    _reject_live_cli_only_automation_profiles(profiles)
    experimental_profiles = tuple(
        profile for profile in profiles if profile in EXPERIMENTAL_AUTOMATION_DEVICE_TYPES
    )
    if experimental_profiles:
        if not allow_experimental_automation:
            names = ", ".join(sorted(set(experimental_profiles)))
            raise ValueError(
                "Experimental Automation is disabled by default for these profiles: "
                f"{names}. Explicit per-run opt-in is required."
            )
        if len(profiles) != 1:
            raise ValueError(
                "Experimental Automation accepts exactly one target and cannot be mixed "
                "with any other Automation profile."
            )
        validate_experimental_automation_runtime()
    elif allow_experimental_automation:
        raise ValueError(
            "Experimental Automation opt-in is valid only for aruba_os, cisco_wlc, or fortinet."
        )
    return profiles


def _validate_netmiko_automation_profile(
    value, *, allow_experimental_automation: bool = False
) -> str:
    """Validate one Automation profile using the complete-scope policy."""

    return _validate_netmiko_automation_profiles(
        (value,), allow_experimental_automation=allow_experimental_automation
    )[0]


def _validated_automation_target_scope(devices, profiles) -> tuple[tuple[str, str, int, str], ...]:
    """Return the immutable target and strict known-hosts scope for this worker."""

    device_list = tuple(devices)
    profile_list = tuple(profiles)
    if len(device_list) != len(profile_list):
        raise ValueError("Automation target scope does not match the validated profile scope.")

    scope = []
    for device, profile in zip(device_list, profile_list, strict=True):
        host = device.get("host")
        if (
            not isinstance(host, str)
            or not host
            or host != host.strip()
            or len(host) > 253
            or any(
                character.isspace() or unicodedata.category(character) in {"Cc", "Cf", "Cs"}
                for character in host
            )
        ):
            raise ValueError("Automation target host is empty or contains invalid characters.")
        raw_port = device.get("port", 22)
        if isinstance(raw_port, bool):
            raise ValueError("Automation target port must be an integer from 1 to 65535.")
        try:
            port = int(raw_port)
        except (TypeError, ValueError) as exc:
            raise ValueError("Automation target port must be an integer from 1 to 65535.") from exc
        if not 1 <= port <= 65535:
            raise ValueError("Automation target port must be an integer from 1 to 65535.")

        if (
            device.get("ssh_strict") is not True
            or device.get("system_host_keys") is not False
            or device.get("alt_host_keys") is not True
        ):
            raise ValueError(
                "Automation requires strict host-key checking with only the selected "
                "application known-hosts file."
            )
        alt_key_file = device.get("alt_key_file")
        if (
            not isinstance(alt_key_file, str)
            or not alt_key_file
            or alt_key_file != alt_key_file.strip()
            or len(alt_key_file) > 4096
            or any(
                unicodedata.category(character) in {"Cc", "Cf", "Cs"} for character in alt_key_file
            )
        ):
            raise ValueError("Automation requires a non-empty application known-hosts file path.")
        scope.append((profile, host, port, alt_key_file))
    return tuple(scope)


class _BoundedSSHSocket:
    """Socket proxy that bounds raw reads before Paramiko sees them.

    Paramiko reads through this proxy. Until the server's ``SSH-``
    identification line is complete, every received byte is counted against a
    total cap and every pre-banner/identification line is counted against a
    line cap. Every delegated raw read is independently bounded so a
    peer-controlled SSH packet length cannot request a giant socket buffer. An
    optional cumulative budget can also fail closed on post-identification
    bytes. The stop event gates all sends: after ``close``/``stop`` returns, a
    late connector cannot perform session-preparation writes.
    """

    def __init__(
        self,
        connection,
        *,
        stop_event: threading.Event | None,
        max_post_banner_bytes: int | None = None,
    ):
        if max_post_banner_bytes is not None and (
            isinstance(max_post_banner_bytes, bool)
            or not isinstance(max_post_banner_bytes, int)
            or max_post_banner_bytes <= 0
        ):
            raise ValueError("Post-identification SSH receive limit must be a positive integer.")
        self._connection = connection
        self._stop_event = stop_event
        self._max_post_banner_bytes = max_post_banner_bytes
        self._identification_seen = False
        self._pre_banner_bytes = 0
        self._post_banner_bytes = 0
        self._receive_limit_exceeded = False
        self._current_line_bytes = 0
        self._current_line = bytearray()
        self._state_lock = threading.RLock()
        self._send_lock = threading.Lock()
        self._closed = False

    def _check_open(self) -> None:
        if self._closed or (self._stop_event is not None and self._stop_event.is_set()):
            raise ConnectionAbortedError("SSH socket closed or operation cancelled.")

    def _fail_limit(self, error: ConnectionError):
        try:
            self._connection.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            self._connection.close()
        except Exception:
            pass
        self._closed = True
        raise error

    def _fail_pre_banner(self, message: str):
        self._fail_limit(SSHPreBannerLimitError(message))

    def _count_post_banner_bytes(self, count: int) -> None:
        if count <= 0 or self._max_post_banner_bytes is None:
            return
        self._post_banner_bytes += count
        if self._post_banner_bytes > self._max_post_banner_bytes:
            self._receive_limit_exceeded = True
            self._fail_limit(
                SSHReceiveLimitError(
                    "SSH transport exceeded the post-identification receive safety limit."
                )
            )

    def receive_limit_exceeded(self) -> bool:
        """Return whether this socket aborted on its cumulative receive quota."""

        with self._state_lock:
            return self._receive_limit_exceeded

    def _inspect_received(self, data: bytes) -> None:
        if not data:
            return
        if self._identification_seen:
            self._count_post_banner_bytes(len(data))
            return
        for index, value in enumerate(data):
            self._pre_banner_bytes += 1
            self._current_line_bytes += 1
            if self._pre_banner_bytes > MAX_SSH_PRE_BANNER_BYTES:
                self._fail_pre_banner("SSH pre-banner exceeds the total byte safety limit.")
            if self._current_line_bytes > MAX_SSH_IDENTIFICATION_LINE_BYTES:
                self._fail_pre_banner("SSH pre-banner line exceeds the byte safety limit.")
            self._current_line.append(value)
            if value != 0x0A:
                continue
            line = bytes(self._current_line).rstrip(b"\r\n")
            if line.startswith(b"SSH-"):
                self._identification_seen = True
                self._current_line.clear()
                self._count_post_banner_bytes(len(data) - index - 1)
                return
            self._current_line.clear()
            self._current_line_bytes = 0

    def recv(self, size: int, flags: int = 0) -> bytes:
        with self._state_lock:
            self._check_open()
            bounded_size = min(max(1, int(size)), MAX_SSH_SOCKET_RECV_BYTES)
            if not self._identification_seen:
                bounded_size = min(bounded_size, MAX_SSH_IDENTIFICATION_LINE_BYTES + 1)
            elif self._max_post_banner_bytes is not None:
                remaining = self._max_post_banner_bytes - self._post_banner_bytes
                bounded_size = min(bounded_size, max(1, remaining + 1))
        # Do not hold the state lock across a blocking read: stop/close must be
        # able to close the raw socket immediately and interrupt this call.
        data = self._connection.recv(bounded_size, flags)
        with self._state_lock:
            self._check_open()
            self._inspect_received(data)
        return data

    def recv_into(self, buffer, nbytes: int = 0, flags: int = 0) -> int:
        requested = nbytes or len(buffer)
        data = self.recv(requested, flags)
        buffer[: len(data)] = data
        return len(data)

    def send(self, data, flags: int = 0) -> int:
        with self._send_lock:
            with self._state_lock:
                self._check_open()
            return self._connection.send(data, flags)

    def sendall(self, data, flags: int = 0):
        with self._send_lock:
            with self._state_lock:
                self._check_open()
            return self._connection.sendall(data, flags)

    def close(self) -> None:
        with self._state_lock:
            close_raw = not self._closed
            self._closed = True
        try:
            if close_raw:
                try:
                    self._connection.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                self._connection.close()
        finally:
            # Wait for a send that began before cancellation to finish. Since
            # the raw socket is already closed, it cannot stay live and no new
            # send can pass the closed-state check. Once close returns, no
            # connector write remains in flight.
            with self._send_lock:
                pass

    def __getattr__(self, name):
        return getattr(self._connection, name)


def _kill_connection_transport(connection) -> None:
    """Close the SSH transport without writing anything into the channel.

    A graceful Netmiko disconnect first writes RETURN and an ``exit`` command
    into the channel.  When the device is sitting at an unanswered
    confirmation prompt — for example one that policy just refused to answer —
    those bytes could accept the very action that was blocked, and the
    interactive reads can block for the full read timeout.  Closing the
    channel and client directly aborts the pending prompt on the device side
    and returns quickly without sending shell input.
    """

    for attribute in ("remote_conn", "remote_conn_pre"):
        endpoint = getattr(connection, attribute, None)
        if endpoint is None:
            continue
        try:
            endpoint.close()
        except Exception:
            pass


@contextmanager
def _abort_only_connection(connection):
    """Own a Netmiko connection without ever invoking graceful disconnect.

    Even a successful command can leave an unrecognized device prompt pending.
    Netmiko's normal context exit writes RETURN and ``exit``; raw transport
    closure is the only teardown that cannot accidentally answer that prompt.
    """

    try:
        yield connection
    finally:
        _kill_connection_transport(connection)


def _bound_diagnostic_text(text: str) -> str:
    """Apply the independent total cap for one diagnostic/log signal."""

    if len(text) <= MAX_DIAGNOSTIC_CHARS:
        return text
    marker = "\n...[diagnostic truncated]"
    retained = max(0, MAX_DIAGNOSTIC_CHARS - len(marker))
    return f"{text[:retained]}{marker}"


def _redact_sensitive_text(value: object, *secrets: str | None) -> str:
    """Make exception and device text safe enough for logs and transcripts."""

    text = str(value)
    for secret in secrets:
        if secret:
            text = text.replace(secret, "<redacted>")
    return _bound_diagnostic_text(redact_text_block(text))


def _run_interruptibly(
    operation,
    *,
    stop_event: threading.Event | None,
    timeout: float,
    late_result_cleanup=None,
):
    """Run one blocking network operation behind a bounded, cancellable wait.

    CPython cannot cancel a platform ``getaddrinfo`` or a third-party connector
    already executing in another thread. The caller can nevertheless stop
    waiting immediately; a daemon helper closes any connection that arrives
    after cancellation. Library socket/auth/banner timeouts remain the final
    bound for the helper itself.
    """

    result_queue: queue.Queue[tuple[bool, object]] = queue.Queue(maxsize=1)
    abandoned = threading.Event()
    delivery_lock = threading.Lock()

    def clean_late_result(succeeded: bool, value: object) -> None:
        if succeeded and late_result_cleanup is not None:
            try:
                late_result_cleanup(value)
            except Exception:
                pass

    def abandon() -> None:
        with delivery_lock:
            abandoned.set()
            try:
                succeeded, value = result_queue.get_nowait()
            except queue.Empty:
                return
            clean_late_result(succeeded, value)

    def invoke() -> None:
        try:
            value = operation()
        except BaseException as exc:
            value = exc
            succeeded = False
        else:
            succeeded = True
        with delivery_lock:
            if abandoned.is_set():
                clean_late_result(succeeded, value)
                return
            try:
                result_queue.put_nowait((succeeded, value))
            except queue.Full:
                clean_late_result(succeeded, value)

    threading.Thread(target=invoke, daemon=True, name="clidarvi-network-wait").start()
    deadline = time.monotonic() + max(0.1, float(timeout))
    while True:
        if stop_event is not None and stop_event.is_set():
            abandon()
            raise ConnectionAbortedError("Network operation cancelled.")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            abandon()
            raise TimeoutError(f"Network operation exceeded {timeout:g} seconds.")
        try:
            succeeded, value = result_queue.get(timeout=min(0.1, remaining))
        except queue.Empty:
            continue
        # Cancellation can race with queue delivery between the check at the
        # top of this loop and get(). Recheck before exposing a successfully
        # constructed SSH object; otherwise session preparation could finish
        # after stop and escape caller-side cancellation.
        if stop_event is not None and stop_event.is_set():
            with delivery_lock:
                abandoned.set()
            clean_late_result(succeeded, value)
            raise ConnectionAbortedError("Network operation cancelled.")
        if succeeded:
            return value
        raise value


def _open_tcp_connection(
    host: str,
    port: int,
    *,
    stop_event: threading.Event | None,
    timeout: float = 10.0,
):
    """Open TCP with a bounded caller wait, including DNS resolution time."""

    return _run_interruptibly(
        lambda: socket.create_connection((host, port), timeout=timeout),
        stop_event=stop_event,
        timeout=timeout + 1.0,
        late_result_cleanup=lambda connection: connection.close(),
    )


def validate_host(
    host: str,
    *,
    stop_event: threading.Event | None = None,
    timeout: float = 10.0,
) -> bool:
    if not isinstance(host, str) or not host:
        raise ValueError("Empty host field.")
    if (
        host != host.strip()
        or len(host) > 253
        or any(char.isspace() or unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in host)
    ):
        raise ValueError("Host contains invalid characters or is too long.")
    try:
        # Accept direct IPv4/IPv6 addresses.
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    try:
        # Fall back to DNS resolution so hostnames are supported. Platform DNS
        # calls are not natively cancellable, so wait on a daemon helper.
        _run_interruptibly(
            lambda: socket.getaddrinfo(host, None),
            stop_event=stop_event,
            timeout=timeout,
        )
        return True
    except socket.gaierror as exc:
        raise ValueError(f"Host not resolvable: {host}") from exc


class AutomationWorker(QThread):
    log = pyqtSignal(str)
    finished_with_log = pyqtSignal(str)

    def __init__(
        self,
        devices,
        commands_text,
        *,
        allow_destructive=False,
        allow_experimental_automation: bool = False,
        save_config=False,
        enter_enable_mode=False,
        connector_factory=ConnectHandler,
        socket_factory=None,
    ):
        super().__init__()
        if save_config:
            raise ValueError(AUTOMATIC_SAVE_DISABLED_MESSAGE)
        if enter_enable_mode:
            raise ValueError(AUTOMATIC_ENABLE_DISABLED_MESSAGE)
        device_list = []
        unvalidated_profiles = []
        for device in devices:
            if not isinstance(device, Mapping):
                raise ValueError("Each automation device must be a mapping.")
            snapshot = dict(device)
            for disallowed_option in AUTOMATION_DISALLOWED_CONNECTION_OPTIONS:
                snapshot.pop(disallowed_option, None)
            unvalidated_profiles.append(snapshot.get("device_type"))
            device_list.append(snapshot)
        validated_profiles = _validate_netmiko_automation_profiles(
            unvalidated_profiles,
            allow_experimental_automation=allow_experimental_automation,
        )
        validated_target_scope = _validated_automation_target_scope(device_list, validated_profiles)
        for snapshot, (profile, _host, port, _alt_key_file) in zip(
            device_list, validated_target_scope, strict=True
        ):
            snapshot["device_type"] = profile
            snapshot["port"] = port
        self.devices = tuple(MappingProxyType(snapshot) for snapshot in device_list)
        self._validated_profiles = validated_profiles
        self._validated_target_scope = validated_target_scope
        self.commands_text = commands_text
        self.allow_destructive = bool(allow_destructive)
        self.allow_experimental_automation = allow_experimental_automation
        self.save_config = False
        self.enter_enable_mode = False
        self.connector_factory = connector_factory
        self.socket_factory = socket_factory or _open_tcp_connection
        self._stop_event = threading.Event()
        self._user_stop_requested = False
        self._had_error = False
        self._active_connections = set()
        self._active_preconnect_sockets = set()
        self._connections_lock = threading.Lock()

    def _prepare_commands(self) -> list[str]:
        commands = []
        if not isinstance(self.commands_text, str):
            raise ValueError("Commands must be provided as text.")
        if any(
            unicodedata.category(char) in {"Cc", "Cf", "Cs"} and char not in "\r\n"
            for char in self.commands_text
        ):
            raise ValueError("Commands contain disallowed control characters.")
        normalized_commands = self.commands_text.replace("\r\n", "\n").replace("\r", "\n")
        for raw in normalized_commands.split("\n"):
            sanitized = self._sanitize_device_command(raw)
            if not sanitized or sanitized.startswith("#") or sanitized.startswith("!"):
                # Skip empty lines and friendly comments.
                continue
            commands.append(sanitized)
        return commands

    @staticmethod
    def _sanitize_device_command(command: str) -> str:
        """
        Normalize automation commands and reject lines containing control characters
        or unusually long payloads that could indicate malicious input.
        """
        if not isinstance(command, str):
            raise ValueError("Command must be text.")
        if any(unicodedata.category(ch) in {"Cc", "Cf", "Cs"} for ch in command):
            raise ValueError("Command contains non-printable control characters.")
        cleaned = command.strip()
        if not cleaned:
            return ""
        if MAX_COMMAND_LENGTH is not None and len(cleaned) > MAX_COMMAND_LENGTH:
            raise ValueError(f"Command exceeds maximum length of {MAX_COMMAND_LENGTH} characters.")
        try:
            cleaned.encode("latin-1")
        except UnicodeEncodeError as exc:
            raise ValueError(
                "Automation commands must use the Latin-1 character set so channel bytes can be "
                "decoded without silent deletion."
            ) from exc
        return cleaned

    @staticmethod
    def _clean_command_output(command: str, response: str) -> str:
        if not response:
            return ""
        normalized = response.replace("\r\n", "\n")
        if command and normalized.startswith(command):
            normalized = normalized[len(command) :]
        return normalized.strip()

    @staticmethod
    def _redact_output(text: str) -> str:
        if not text:
            return ""
        return redact_text_block(text)

    @staticmethod
    def _bound_command_response(text: object) -> str:
        """Bound already-redacted output while retaining its beginning and end."""

        if not isinstance(text, str):
            text = str(text or "")
        if len(text) <= MAX_COMMAND_RESPONSE_CHARS:
            return text
        marker = "\n...[redacted command output truncated after safety analysis]...\n"
        available = max(0, MAX_COMMAND_RESPONSE_CHARS - len(marker))
        head_length = available // 2
        tail_length = available - head_length
        tail = text[-tail_length:] if tail_length else ""
        return f"{text[:head_length]}{marker}{tail}"

    @classmethod
    def _safe_retained_output(cls, text: str) -> str:
        """Redact the complete response, then apply the retention bound."""

        return cls._bound_command_response(cls._redact_output(text))

    @staticmethod
    def _safe_prompt_label(text: str) -> str:
        """Return a bounded, redacted prompt label suitable for diagnostics."""

        safe = _redact_sensitive_text(text).replace("\n", " ").strip()
        return safe or "prompt"

    @staticmethod
    def _clip_for_log(text: str) -> str:
        if len(text) <= MAX_DEVICE_LOG_ENTRY_CHARS:
            return text
        marker = "\n...[log entry truncated]"
        retained = max(0, MAX_DEVICE_LOG_ENTRY_CHARS - len(marker))
        return f"{text[:retained]}{marker}"

    def _contains_command_error(self, text: str) -> bool:
        if not text:
            return False
        return any(pattern.search(text) is not None for pattern in COMMAND_ERROR_PATTERNS)

    @staticmethod
    def _validated_base_prompt(conn) -> str | None:
        """Return a strict, non-empty Netmiko base prompt or ``None``."""

        base_prompt = getattr(conn, "base_prompt", None)
        if not isinstance(base_prompt, str) or not base_prompt:
            return None
        if base_prompt != base_prompt.strip() or len(base_prompt) > 256:
            return None
        if any(unicodedata.category(character) in {"Cc", "Cf", "Cs"} for character in base_prompt):
            return None
        return base_prompt

    @classmethod
    def _require_valid_base_prompt(cls, conn) -> str:
        """Abort before automation if Netmiko did not establish a safe prompt."""

        base_prompt = cls._validated_base_prompt(conn)
        if base_prompt is None:
            _kill_connection_transport(conn)
            raise CommandExecutionError(
                "SSH session did not expose a validated non-empty base prompt; "
                "no automation commands were sent."
            )
        return base_prompt

    @classmethod
    def _has_verified_cli_prompt(cls, conn, response: str, vendor: str | None = None) -> bool:
        """Require explicit, control-free CLI-prompt evidence before advancing.

        ``send_command_timing`` stops after a quiet period rather than after a
        prompt-pattern match. Treating arbitrary or empty output as completion
        can send the next queued command into an unrecognized password or
        confirmation prompt. Do not call Netmiko ``find_prompt`` here because
        it writes RETURN into the channel.
        """

        if not isinstance(response, str) or not response:
            return False
        if any(
            unicodedata.category(character) in {"Cc", "Cf", "Cs"} and character not in "\r\n"
            for character in response
        ):
            return False
        final_line = ""
        for line in reversed(response.replace("\r\n", "\n").replace("\r", "\n").split("\n")):
            if line.strip():
                final_line = line.strip()
                break
        if not final_line or len(final_line) > 512:
            return False

        base_prompt = cls._validated_base_prompt(conn)
        if base_prompt is None:
            return False
        if len(base_prompt) == 1 and base_prompt in "#>$%":
            return final_line == base_prompt
        if not final_line.startswith(base_prompt):
            return False
        suffix = final_line[len(base_prompt) :]
        # Netmiko 4.7 deliberately stores only the first 16 characters of a
        # Cisco IOS/IOS-XE base prompt because IOS abbreviates long hostnames
        # in configuration modes. Accept only a bounded continuation made of
        # IOS hostname characters, and only for that exact driver/length.
        if vendor == "cisco_ios" and len(base_prompt) == 16:
            return CISCO_IOS_TRUNCATED_PROMPT_SUFFIX_PATTERN.fullmatch(suffix) is not None
        return CLI_PROMPT_SUFFIX_PATTERN.fullmatch(suffix) is not None

    def _clear_password_buffers(self) -> None:
        """Best-effort clear every mutable password buffer owned by this worker."""

        for device in self.devices:
            password_buffer = device.get("password")
            if isinstance(password_buffer, bytearray):
                for index in range(len(password_buffer)):
                    password_buffer[index] = 0

    def discard_unstarted_credentials(self) -> None:
        """Clear credential buffers after a QThread start failure."""

        if self.isRunning():
            raise RuntimeError("Cannot discard Automation credentials while the worker is running.")
        self._clear_password_buffers()

    def stop(self):
        self._user_stop_requested = True
        self._stop_event.set()
        # Kill the raw transports instead of a graceful disconnect: this call
        # runs on the GUI thread, and a graceful disconnect performs blocking
        # interactive reads and writes RETURN + "exit" into channels that may
        # be sitting at a confirmation prompt.  Each device thread still owns
        # normal cleanup of its own connection object.
        self._abort_active_connections()

    def _abort_active_connections(self) -> None:
        """Abort every active transport without sending shell input."""

        with self._connections_lock:
            connections = tuple(self._active_connections)
            preconnect_sockets = tuple(self._active_preconnect_sockets)
        # Close the application-owned socket first. A ConnectHandler still in
        # authentication/session preparation then fails before it can perform
        # any later channel writes. _BoundedSSHSocket serializes send/close, so
        # no send can begin after this close returns.
        for connection in preconnect_sockets:
            try:
                connection.close()
            except Exception:
                pass
        for connection in connections:
            _kill_connection_transport(connection)

    def _connect_interruptibly(self, connection_params: dict):
        """Connect with a cancellable, app-owned socket for real Netmiko use."""

        # Netmiko decodes channel bytes with ``errors="ignore"``. UTF-8 could
        # therefore delete attacker-controlled invalid bytes and synthesize an
        # allowlisted prompt. Latin-1 is total over all byte values: nothing is
        # silently discarded before Clidarvi's control/prompt policy sees it.
        connection_params["encoding"] = "latin-1"
        raw_socket = self.socket_factory(
            str(connection_params.get("host") or ""),
            int(connection_params.get("port", 22) or 22),
            stop_event=self._stop_event,
        )
        bounded_socket = _BoundedSSHSocket(
            raw_socket,
            stop_event=self._stop_event,
            max_post_banner_bytes=MAX_AUTOMATION_SSH_POST_BANNER_BYTES,
        )
        connection_params["sock"] = bounded_socket
        with self._connections_lock:
            self._active_preconnect_sockets.add(bounded_socket)
        if self._stop_event.is_set():
            bounded_socket.close()
            raise ConnectionAbortedError("Automation stopped before SSH setup.")
        try:
            connection = _run_interruptibly(
                lambda: self.connector_factory(**connection_params),
                stop_event=self._stop_event,
                timeout=CONNECT_OPERATION_TIMEOUT_SECONDS,
                late_result_cleanup=_kill_connection_transport,
            )
            # Some Netmiko vendor classes strip ANSI before returning command
            # output. That can join separated prompt tokens before our policy
            # sees them, so application command reads must preserve controls.
            connection.ansi_escape_codes = False
            return connection
        except BaseException:
            with self._connections_lock:
                self._active_preconnect_sockets.discard(bounded_socket)
            bounded_socket.close()
            raise

    def was_stopped(self) -> bool:
        return self._user_stop_requested

    def had_error(self) -> bool:
        return self._had_error

    def _execute_command(
        self, conn, command: str, params: dict
    ) -> tuple[list[tuple[str, str, bool]], CommandClass]:
        responses: list[tuple[str, str, bool]] = []
        self._require_valid_base_prompt(conn)
        vendor = params.get("device_type") or params.get("vendor")
        command_class = classify_command(command, vendor)
        display_command = redact_command(command)
        if self._stop_event.is_set():
            _kill_connection_transport(conn)
            raise ConnectionAbortedError("Automation stopped before command execution.")
        if command_class is CommandClass.DESTRUCTIVE and not self.allow_destructive:
            raise CommandExecutionError(f"Destructive command blocked by policy: {display_command}")

        delay_factor = params.get("global_delay_factor", 1)
        try:
            delay_factor = max(1, int(delay_factor))
        except (TypeError, ValueError):
            delay_factor = 1

        if command_class is CommandClass.READ_ONLY:
            try:
                # Pattern-based reads can stop at a prompt-looking line in
                # ordinary output while a later interactive prompt remains
                # unread. A bounded timing read drains until the channel is
                # quiet; the exact final base-prompt check below then decides
                # whether it is safe to advance.
                output = conn.send_command_timing(
                    command,
                    strip_command=False,
                    strip_prompt=False,
                    read_timeout=COMMAND_READ_TIMEOUT_SECONDS,
                )
            except Exception:
                # A read timeout here usually means the device is sitting at
                # an unexpected prompt; never let graceful teardown answer it.
                _kill_connection_transport(conn)
                raise
            if self._stop_event.is_set():
                _kill_connection_transport(conn)
                raise ConnectionAbortedError("Automation stopped while reading command output.")
            if not isinstance(output, str):
                output = str(output or "")
            output_stripped = output.strip()
            if self._contains_command_error(output) or self._contains_command_error(
                output_stripped
            ):
                raise CommandExecutionError(
                    self._safe_retained_output(output_stripped or output)
                    or f"Command '{display_command}' rejected"
                )
            decision = decide_follow_up(output, command, vendor)
            if decision.action is not PromptAction.NO_PROMPT:
                prompt_text = self._safe_prompt_label(
                    decision.prompt.text if decision.prompt else "prompt"
                )
                _kill_connection_transport(conn)
                raise CommandExecutionError(
                    f"Interactive prompt blocked ({prompt_text}): {decision.reason}"
                )
            if not self._has_verified_cli_prompt(conn, output, vendor):
                _kill_connection_transport(conn)
                raise CommandExecutionError(
                    "Read-only command completion could not be verified from the returned CLI "
                    "prompt; the transport was aborted before any later command."
                )
            responses.append((display_command, self._safe_retained_output(output_stripped), False))
            return responses, command_class

        response = conn.send_command_timing(
            command,
            strip_command=False,
            strip_prompt=False,
            delay_factor=delay_factor,
            read_timeout=COMMAND_READ_TIMEOUT_SECONDS,
        )
        if self._stop_event.is_set():
            _kill_connection_transport(conn)
            if self._user_stop_requested:
                raise ConnectionAbortedError("Automation stopped while reading command output.")
            raise CommandExecutionError("Automation was cancelled while reading command output.")
        if not isinstance(response, str):
            response = str(response or "")
        cleaned = self._clean_command_output(command, response)
        if self._contains_command_error(response) or self._contains_command_error(cleaned):
            raise CommandExecutionError(
                self._safe_retained_output(cleaned or response)
                or f"Command '{display_command}' rejected"
            )
        pending = response
        follow_ups = 0
        decision = decide_follow_up(
            pending,
            command,
            vendor,
            allow_destructive=self.allow_destructive,
            follow_up_count=follow_ups,
        )
        # Only retain output after error/prompt/control policy has examined the
        # complete raw response and redaction has processed it as one block.
        responses.append((display_command, self._safe_retained_output(cleaned), False))
        while True:
            if decision.action is PromptAction.NO_PROMPT:
                if not self._has_verified_cli_prompt(conn, pending, vendor):
                    _kill_connection_transport(conn)
                    raise CommandExecutionError(
                        "Command completion could not be verified from the returned CLI prompt; "
                        "the transport was aborted before any later command."
                    )
                break
            if decision.action in (PromptAction.BLOCKED, PromptAction.LIMIT_REACHED):
                prompt_text = self._safe_prompt_label(
                    decision.prompt.text if decision.prompt else "prompt"
                )
                # The device is still waiting at the unanswered prompt.  A
                # graceful teardown would write RETURN + "exit" into it, which
                # could accept the refused action, so the transport dies first.
                _kill_connection_transport(conn)
                raise CommandExecutionError(
                    f"Interactive prompt blocked ({prompt_text}): {decision.reason}"
                )

            send_text = decision.reply or ""
            follow_ups += 1
            display_label = send_text.strip()
            display_text = display_label if display_label else "<enter>"
            if self._stop_event.is_set():
                # A different device may have failed while this one was
                # waiting at a prompt. Never auto-confirm after cancellation.
                _kill_connection_transport(conn)
                if self._user_stop_requested:
                    raise ConnectionAbortedError(
                        "Automation stopped before an automatic prompt response."
                    )
                raise CommandExecutionError(
                    "Automation was cancelled before an automatic prompt response."
                )
            follow_response = conn.send_command_timing(
                send_text,
                strip_command=False,
                strip_prompt=False,
                delay_factor=delay_factor,
                read_timeout=COMMAND_READ_TIMEOUT_SECONDS,
            )
            if self._stop_event.is_set():
                _kill_connection_transport(conn)
                if self._user_stop_requested:
                    raise ConnectionAbortedError(
                        "Automation stopped while reading an automatic prompt response."
                    )
                raise CommandExecutionError(
                    "Automation was cancelled while reading an automatic prompt response."
                )
            if not isinstance(follow_response, str):
                follow_response = str(follow_response or "")
            cleaned_follow = self._clean_command_output(send_text, follow_response)
            if self._contains_command_error(follow_response) or self._contains_command_error(
                cleaned_follow
            ):
                # The device may have re-displayed the confirmation prompt
                # alongside the error, so teardown must not write into it.
                _kill_connection_transport(conn)
                raise CommandExecutionError(
                    self._safe_retained_output(cleaned_follow or follow_response)
                    or f"Auto-response '{display_text}' rejected"
                )
            if not follow_response:
                # Device state is unknown; do not write further shell input.
                _kill_connection_transport(conn)
                raise CommandExecutionError(
                    "No completion response was received after an automatic confirmation; "
                    "the device outcome is unknown."
                )
            if follow_response.strip() == pending.strip():
                # The prompt is still pending; a graceful exit could answer it.
                _kill_connection_transport(conn)
                raise CommandExecutionError(
                    "Device repeated the same confirmation prompt after an automatic reply."
                )
            pending = follow_response
            decision = decide_follow_up(
                pending,
                command,
                vendor,
                allow_destructive=self.allow_destructive,
                follow_up_count=follow_ups,
            )
            responses.append((display_text, self._safe_retained_output(cleaned_follow), True))

        return responses, command_class

    def run(self):
        transcript = ""
        try:
            transcript = self._run_devices()
        except Exception as exc:
            self._had_error = True
            safe_error = _redact_sensitive_text(exc)
            self.log.emit(
                _bound_diagnostic_text(f"[System] Automation worker failed: {safe_error}")
            )
            transcript = _bound_diagnostic_text(f"SYSTEM ERROR: {safe_error}")
        finally:
            self._clear_password_buffers()
            self.finished_with_log.emit(transcript)

    def _run_devices(self) -> str:
        from concurrent.futures import CancelledError, ThreadPoolExecutor, as_completed

        commands = self._prepare_commands()
        if not commands or not self.devices:
            return ""
        # Take one authoritative per-run snapshot and re-validate the exact
        # profile/host/port scope before scheduling any connector work.
        run_devices = []
        unvalidated_profiles = []
        for device in self.devices:
            if not isinstance(device, Mapping):
                raise ValueError("Each automation device must be a mapping.")
            snapshot = dict(device)
            unvalidated_profiles.append(snapshot.get("device_type"))
            run_devices.append(snapshot)
        current_profiles = _validate_netmiko_automation_profiles(
            unvalidated_profiles,
            allow_experimental_automation=self.allow_experimental_automation,
        )
        if current_profiles != self._validated_profiles:
            raise ValueError("Automation device profiles changed after initial validation.")
        current_target_scope = _validated_automation_target_scope(run_devices, current_profiles)
        if current_target_scope != self._validated_target_scope:
            raise ValueError(
                "Automation target profile, host, port, or host-key policy changed after "
                "validation."
            )
        for snapshot, (profile, _host, port, _alt_key_file) in zip(
            run_devices, current_target_scope, strict=True
        ):
            snapshot["device_type"] = profile
            snapshot["port"] = port
        run_devices = tuple(run_devices)

        stop_event = self._stop_event
        aggregate_lock = threading.Lock()
        aggregate_remaining = max(0, MAX_TOTAL_TRANSCRIPT_CHARS)
        aggregate_truncated = False

        def process_device(device):
            host = device.get("host")
            sanitized_lines = []
            transcript_length = 0
            transcript_truncated = False
            password_buffer = None
            password_text = None
            password_length = 0
            connection_params = dict(device)
            stop_local = stop_event.is_set()
            change_touched = False

            def append_transcript(value: str) -> None:
                nonlocal aggregate_remaining, aggregate_truncated
                nonlocal transcript_length, transcript_truncated
                if transcript_truncated:
                    return
                text = str(value)
                device_remaining = MAX_DEVICE_TRANSCRIPT_CHARS - transcript_length
                if device_remaining <= 0:
                    transcript_truncated = True
                    return
                with aggregate_lock:
                    permitted = min(len(text), device_remaining, aggregate_remaining)
                    aggregate_remaining -= permitted
                    if permitted < len(text):
                        aggregate_truncated = aggregate_remaining <= 0
                if permitted:
                    sanitized_lines.append(text[:permitted])
                    transcript_length += permitted
                if permitted < len(text):
                    transcript_truncated = True

            try:
                profile = _validate_netmiko_automation_profile(
                    connection_params.get("device_type"),
                    allow_experimental_automation=self.allow_experimental_automation,
                )
                connection_params["device_type"] = profile
                if profile in EXPERIMENTAL_AUTOMATION_DEVICE_TYPES:
                    disclosure = EXPERIMENTAL_AUTOMATION_SETUP_DISCLOSURES[profile]
                    disclosure_msg = (
                        f"[{host}] EXPERIMENTAL AUTOMATION PROFILE {profile}: {disclosure}. "
                        "Raw hidden driver setup bytes are not part of Clidarvi's command "
                        "transcript; verify device state before and after this isolated lab run."
                    )
                    self.log.emit(disclosure_msg)
                    append_transcript(disclosure_msg)
                password_value = connection_params.get("password")
                if isinstance(password_value, bytearray):
                    password_buffer = password_value
                    password_text = password_buffer.decode("utf-8", errors="strict")
                    connection_params["password"] = password_text
                    password_length = len(password_text)
                connection_params["port"] = int(connection_params.get("port", 22) or 22)
                connection_params["disabled_algorithms"] = ssh_disabled_algorithms()
                # Automation is password-only. Force this even when a caller
                # supplies a crafted device mapping, rather than relying on
                # Netmiko 4.7's current defaults or an SSH config file.
                connection_params["use_keys"] = False
                connection_params["allow_agent"] = False
                connection_params["ssh_strict"] = True
                connection_params["system_host_keys"] = False
                connection_params["alt_host_keys"] = True
                connection_params["conn_timeout"] = 10
                connection_params["auth_timeout"] = 15
                connection_params["banner_timeout"] = 15
                connection_params["blocking_timeout"] = 15
                connection_params["read_timeout_override"] = COMMAND_READ_TIMEOUT_SECONDS
                for disallowed_option in AUTOMATION_DISALLOWED_CONNECTION_OPTIONS:
                    connection_params.pop(disallowed_option, None)

                if stop_local:
                    skip_msg = f"[{host}] Skipped (stop requested)."
                    self.log.emit(skip_msg)
                else:
                    self.log.emit(f"[{host}] Connecting...")
                    with _abort_only_connection(
                        self._connect_interruptibly(connection_params)
                    ) as conn:
                        with self._connections_lock:
                            self._active_connections.add(conn)
                        try:
                            self.log.emit(f"[{host}] Connected with verified host key.")

                            if stop_event.is_set():
                                stop_local = True
                                stop_msg = (
                                    f"[{host}] Stop requested before command execution started."
                                )
                                self.log.emit(stop_msg)
                                append_transcript(stop_msg)
                                return "\n".join(sanitized_lines).strip()

                            self._require_valid_base_prompt(conn)

                            command_classes = [
                                classify_command(command, connection_params.get("device_type"))
                                for command in commands
                            ]
                            change_count = sum(
                                command_class in (CommandClass.CHANGE, CommandClass.UNKNOWN)
                                for command_class in command_classes
                            )
                            if change_count:
                                if stop_event.is_set():
                                    stop_local = True
                                if not stop_local:
                                    self.log.emit(
                                        f"[{host}] Approved change run started "
                                        f"({change_count} change/unknown command(s))."
                                    )

                            for command in commands:
                                if stop_event.is_set():
                                    stop_local = True
                                    break
                                responses, command_class = self._execute_command(
                                    conn, command, connection_params
                                )
                                if command_class in (CommandClass.CHANGE, CommandClass.UNKNOWN):
                                    change_touched = True
                                for display_cmd, output_text, auto_generated in responses:
                                    prefix = "[auto] " if auto_generated else ""
                                    log_entry = f"[{host}] {prefix}{display_cmd}"
                                    if output_text:
                                        log_entry = f"{log_entry}\n{output_text}"
                                    self.log.emit(self._clip_for_log(log_entry))

                                    append_transcript(f"{host} > {prefix}{display_cmd}")
                                    if output_text:
                                        append_transcript(output_text)
                                    append_transcript("")
                                if stop_event.is_set():
                                    stop_local = True
                                    break

                            if stop_local:
                                stop_msg = f"[{host}] Stop requested – halting remaining commands."
                                self.log.emit(stop_msg)

                            if change_touched and not stop_local:
                                self.log.emit(
                                    f"[{host}] Changes completed. Clidarvi did not send an "
                                    "implicit save or commit command."
                                )
                        except BaseException:
                            # Netmiko's context manager performs a graceful
                            # disconnect that may write RETURN/"exit". Abort
                            # first whenever a command, enable, mode, or save
                            # operation fails because remote state is unknown.
                            _kill_connection_transport(conn)
                            raise
                        finally:
                            with self._connections_lock:
                                self._active_connections.discard(conn)

            except CommandExecutionError as e:
                self._had_error = True
                stop_event.set()
                self._abort_active_connections()
                stop_local = True
                safe_error = _redact_sensitive_text(e, password_text)
                error_msg = _bound_diagnostic_text(f"[{host}] COMMAND ERROR: {safe_error}".strip())
                self.log.emit(error_msg)
                append_transcript(_bound_diagnostic_text(f"{host} COMMAND ERROR: {safe_error}"))
                cancel_msg = f"[{host}] Command error detected — cancelling automation."
                self.log.emit(cancel_msg)
                append_transcript(cancel_msg)
            except Exception as e:
                if stop_event.is_set() and self._user_stop_requested:
                    stop_local = True
                    stop_msg = f"[{host}] Connection interrupted by user stop request."
                    self.log.emit(stop_msg)
                    append_transcript(stop_msg)
                else:
                    self._had_error = True
                    safe_error = _redact_sensitive_text(e, password_text)
                    msg = _bound_diagnostic_text(f"[{host}] ERROR: {safe_error}")
                    self.log.emit(msg)
                    append_transcript(_bound_diagnostic_text(f"{host} ERROR: {safe_error}"))
            finally:
                preconnected_socket = connection_params.pop("sock", None)
                if preconnected_socket is not None:
                    with self._connections_lock:
                        self._active_preconnect_sockets.discard(preconnected_socket)
                    try:
                        preconnected_socket.close()
                    except Exception:
                        pass
                if "password" in connection_params:
                    if isinstance(connection_params["password"], str):
                        connection_params["password"] = "*" * password_length
                    try:
                        del connection_params["password"]
                    except KeyError:
                        pass
                if isinstance(password_buffer, bytearray):
                    for idx in range(len(password_buffer)):
                        password_buffer[idx] = 0
                if "username" in device:
                    device["username"] = None

            if stop_local:
                append_transcript(f"{host} STOP REQUESTED")
                append_transcript("")

            if transcript_truncated and sanitized_lines:
                sanitized_lines.append("...[device transcript truncated]")

            sanitized_text = "\n".join(line for line in sanitized_lines if line is not None).strip()
            return sanitized_text

        with ThreadPoolExecutor(
            max_workers=min(len(run_devices), MAX_PARALLEL_DEVICES),
            thread_name_prefix="clidarvi-device",
        ) as executor:
            futures = {
                executor.submit(process_device, device): idx
                for idx, device in enumerate(run_devices)
            }

            sanitized_ordered = {}
            for future in as_completed(futures):
                idx = futures[future]
                try:
                    sanitized = future.result()
                    if sanitized:
                        sanitized_ordered[idx] = sanitized
                except CancelledError:
                    continue
                except Exception as e:
                    self._had_error = True
                    safe_error = _redact_sensitive_text(e)
                    self.log.emit(_bound_diagnostic_text(f"Thread error: {safe_error}"))
                    error_msg = _bound_diagnostic_text(f"[Thread-{idx}] ERROR: {safe_error}")
                    sanitized_ordered.setdefault(idx, error_msg)
                if stop_event.is_set():
                    for pending in futures:
                        pending.cancel()

        payload_parts = []
        payload_length = 0
        for index in sorted(sanitized_ordered):
            block = sanitized_ordered[index]
            separator = "\n\n" if payload_parts else ""
            remaining = MAX_TOTAL_TRANSCRIPT_CHARS - payload_length - len(separator)
            if remaining <= 0:
                # The bound filled exactly on an earlier block; blocks are
                # still being dropped, so the truncation marker must appear.
                payload_parts.append("\n...[total transcript truncated]")
                break
            payload_parts.append(f"{separator}{block[:remaining]}")
            payload_length += len(separator) + min(len(block), remaining)
            if len(block) > remaining:
                payload_parts.append("\n...[total transcript truncated]")
                break
        if aggregate_truncated and "...[total transcript truncated]" not in payload_parts:
            payload_parts.append("\n...[total transcript truncated]")
        return "".join(payload_parts).strip()


class UdmReadOnlyAutomationWorker(QThread):
    """Run exact observational commands over non-interactive SSH exec channels.

    This is deliberately separate from :class:`AutomationWorker`. It never
    invokes Netmiko, requests a PTY, starts an interactive shell, supplies an
    environment, or writes to remote stdin. The accepted plan is exactly the
    complete, fixed-order tuple from :data:`UDM_READ_ONLY_COMMANDS`; every
    identifier maps to one fixed literal.
    """

    log = pyqtSignal(str)
    finished_with_log = pyqtSignal(str)

    def __init__(
        self,
        device,
        command_ids,
        *,
        verified_server_key,
        client_factory=paramiko.SSHClient,
        socket_factory=None,
    ):
        super().__init__()
        if not isinstance(device, Mapping):
            raise ValueError("The UDM observation target must be one device mapping.")
        device_source = dict(device)
        if device_source.get("device_type") != UDM_READ_ONLY_DEVICE_TYPE:
            raise ValueError(f"UDM observations require device_type {UDM_READ_ONLY_DEVICE_TYPE!r}.")
        if not callable(client_factory):
            raise ValueError("UDM observation client_factory must be callable.")
        if socket_factory is not None and not callable(socket_factory):
            raise ValueError("UDM observation socket_factory must be callable.")

        host = device_source.get("host")
        self._validate_host_syntax(host)
        port = device_source.get("port", 22)
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535:
            raise ValueError("UDM observation port must be an integer between 1 and 65535.")
        username = device_source.get("username")
        self._validate_username(username)

        if type(command_ids) is not tuple:
            raise ValueError("UDM observation command_ids must be an immutable tuple.")
        if command_ids != tuple(UDM_READ_ONLY_COMMANDS):
            raise ValueError(
                "UDM observations require the complete fixed-order read-only command tuple."
            )

        if not isinstance(verified_server_key, paramiko.PKey):
            raise ValueError("An exact in-memory trusted SSH host key is required.")
        try:
            key_name = verified_server_key.get_name()
            key_bytes = bytes(verified_server_key.asbytes())
            key_snapshot = paramiko.PKey.from_type_string(key_name, key_bytes)
        except Exception as exc:
            raise ValueError("Unable to snapshot the trusted SSH host key.") from exc
        if not key_name or not key_bytes:
            raise ValueError("The trusted SSH host key snapshot is empty.")

        # Copy credentials only after every non-secret plan and trust-anchor
        # validation has succeeded. A constructor failure must never leave an
        # otherwise unreachable password snapshot waiting for run() cleanup.
        source_password_buffer = device_source.get("password")
        if not isinstance(source_password_buffer, bytearray) or not source_password_buffer:
            raise ValueError("UDM observations require a non-empty password bytearray.")
        if len(source_password_buffer) > 4_096:
            raise ValueError("UDM observation password exceeds the 4096-byte safety limit.")
        password_snapshot = bytearray(source_password_buffer)
        try:
            password_snapshot.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            for index in range(len(password_snapshot)):
                password_snapshot[index] = 0
            raise ValueError("UDM observation password must be valid UTF-8.") from exc

        self.device = MappingProxyType(
            {
                "device_type": UDM_READ_ONLY_DEVICE_TYPE,
                "host": host,
                "port": port,
                "username": username,
            }
        )
        self.command_ids = tuple(command_ids)
        self.verified_server_key = key_snapshot
        self.client_factory = client_factory
        self.socket_factory = socket_factory or _open_tcp_connection
        self._source_password_buffer = source_password_buffer
        self._password_buffer = password_snapshot
        self._stop_event = threading.Event()
        self._user_stop_requested = False
        self._had_error = False
        self._resource_lock = threading.Lock()
        self._socket = None
        self._client = None
        self._channel = None

    @staticmethod
    def _validate_host_syntax(host) -> None:
        if not isinstance(host, str) or not host:
            raise ValueError("UDM observation host must be non-empty text.")
        if (
            host != host.strip()
            or len(host) > 253
            or any(
                character.isspace() or unicodedata.category(character) in {"Cc", "Cf", "Cs"}
                for character in host
            )
        ):
            raise ValueError("UDM observation host contains invalid characters or is too long.")

    @staticmethod
    def _validate_username(username) -> None:
        if not isinstance(username, str) or not username:
            raise ValueError("UDM observation username must be non-empty text.")
        if (
            username != username.strip()
            or len(username) > 256
            or any(unicodedata.category(character) in {"Cc", "Cf", "Cs"} for character in username)
        ):
            raise ValueError("UDM observation username contains unsafe characters or is too long.")
        if username != "root":
            raise ValueError("UDM observations require the root SSH username.")

    def was_stopped(self) -> bool:
        return self._user_stop_requested

    def had_error(self) -> bool:
        return self._had_error

    def discard_unstarted_credentials(self) -> None:
        """Clear both password snapshots after a QThread start failure."""

        if self.isRunning():
            raise RuntimeError("Cannot discard UDM credentials while the worker is running.")
        self._clear_password_buffers()

    def stop(self) -> None:
        self._user_stop_requested = True
        self._stop_event.set()
        self._abort_resources()

    close = stop

    def run(self) -> None:
        transcript = ""
        password_text = None
        try:
            if self._stop_event.is_set():
                raise ConnectionAbortedError("UDM observation stopped before execution.")
            # Resolve before opening the application-owned TCP socket. All
            # structural target, command, credential, and key validation has
            # already completed synchronously in __init__.
            validate_host(self.device["host"], stop_event=self._stop_event)
            if self._stop_event.is_set():
                raise ConnectionAbortedError("UDM observation cancelled before SSH setup.")
            password_text = self._password_buffer.decode("utf-8", errors="strict")
            transcript = self._run_commands(password_text)
        except Exception as exc:
            if self._user_stop_requested:
                message = f"[{self.device['host']}] UDM observation stopped by user."
            else:
                self._had_error = True
                safe_error = _redact_sensitive_text(exc, password_text)
                message = _bound_diagnostic_text(
                    f"[{self.device['host']}] UDM OBSERVATION ERROR: {safe_error}"
                )
            self.log.emit(message)
            transcript = message
        finally:
            self._abort_resources()
            self._clear_password_buffers()
            password_text = None
            self.finished_with_log.emit(transcript)

    def _run_commands(self, password_text: str) -> str:
        client = self._connect(password_text)
        transport = client.get_transport()
        if transport is None or not transport.is_active():
            raise ConnectionError("SSH transport was not active after authentication.")

        host = self.device["host"]
        transcript_parts = []
        total_output_bytes = 0
        self.log.emit(f"[{host}] Connected with the exact trusted SSH host key.")
        for command_id in self.command_ids:
            if self._stop_event.is_set():
                raise ConnectionAbortedError("UDM observation stopped before the next command.")
            command = UDM_READ_ONLY_COMMANDS[command_id]
            command_deadline = time.monotonic() + UDM_COMMAND_TIMEOUT_SECONDS
            channel = self._open_exec_channel(transport, command)
            try:
                stdout, stderr, status = self._drain_exec_channel(
                    channel,
                    total_output_bytes=total_output_bytes,
                    deadline=command_deadline,
                )
            finally:
                with self._resource_lock:
                    if self._channel is channel:
                        self._channel = None
                try:
                    channel.close()
                except Exception:
                    pass

            response_bytes = len(stdout) + len(stderr)
            total_output_bytes += response_bytes
            if status != 0:
                raise CommandExecutionError(
                    f"UDM observation {command_id!r} returned exit status {status}."
                )
            if stderr:
                raise CommandExecutionError(
                    f"UDM observation {command_id!r} produced unexpected stderr output."
                )
            output = self._decode_observation_output(stdout, command_id)
            safe_output = redact_text_block(output).strip()
            log_entry = f"[{host}] {command}"
            if safe_output:
                log_entry = f"{log_entry}\n{safe_output}"
            self.log.emit(log_entry)
            transcript_entry = f"{host} > {command}"
            if safe_output:
                transcript_entry = f"{transcript_entry}\n{safe_output}"
            transcript_parts.append(transcript_entry)
        return "\n\n".join(transcript_parts)

    def _connect(self, password_text: str):
        raw_socket = self.socket_factory(
            self.device["host"],
            self.device["port"],
            stop_event=self._stop_event,
        )
        bounded_socket = _BoundedSSHSocket(
            raw_socket,
            stop_event=self._stop_event,
            max_post_banner_bytes=MAX_AUTOMATION_SSH_POST_BANNER_BYTES,
        )
        with self._resource_lock:
            if self._stop_event.is_set():
                bounded_socket.close()
                raise ConnectionAbortedError("UDM observation cancelled before SSH setup.")
            self._socket = bounded_socket

        client = self.client_factory()
        with self._resource_lock:
            if self._stop_event.is_set():
                bounded_socket.close()
                raise ConnectionAbortedError("UDM observation cancelled before authentication.")
            self._client = client

        host_identifier = (
            self.device["host"]
            if self.device["port"] == 22
            else f"[{self.device['host']}]:{self.device['port']}"
        )
        client.get_host_keys().add(
            host_identifier,
            self.verified_server_key.get_name(),
            self.verified_server_key,
        )
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

        try:
            _run_interruptibly(
                lambda: client.connect(
                    self.device["host"],
                    self.device["port"],
                    sock=bounded_socket,
                    username=self.device["username"],
                    password=password_text,
                    pkey=None,
                    key_filename=None,
                    look_for_keys=False,
                    allow_agent=False,
                    gss_auth=False,
                    gss_kex=False,
                    compress=False,
                    timeout=10,
                    auth_timeout=15,
                    banner_timeout=15,
                    channel_timeout=UDM_CHANNEL_REQUEST_TIMEOUT_SECONDS,
                    disabled_algorithms=ssh_disabled_algorithms(),
                ),
                stop_event=self._stop_event,
                timeout=CONNECT_OPERATION_TIMEOUT_SECONDS,
            )
        except BaseException:
            self._abort_resources()
            raise
        return client

    def _open_exec_channel(self, transport, command: str):
        def open_and_execute():
            channel = transport.open_session(timeout=UDM_CHANNEL_REQUEST_TIMEOUT_SECONDS)
            try:
                # ``command`` can only come from the immutable UDM_READ_ONLY_COMMANDS
                # mapping after the constructor accepts its complete, exact-order key tuple.
                channel.exec_command(command)  # nosec B601
                channel.settimeout(0.0)
                return channel
            except BaseException:
                try:
                    channel.close()
                except Exception:
                    pass
                raise

        try:
            channel = _run_interruptibly(
                open_and_execute,
                stop_event=self._stop_event,
                timeout=UDM_CHANNEL_REQUEST_TIMEOUT_SECONDS,
                late_result_cleanup=lambda late_channel: late_channel.close(),
            )
        except BaseException:
            # In particular, Paramiko's exec-request acknowledgement wait is
            # otherwise unbounded. Raw-socket closure prevents a late helper
            # from sending any subsequent SSH or command bytes.
            self._abort_resources()
            raise
        with self._resource_lock:
            if self._stop_event.is_set():
                try:
                    channel.close()
                finally:
                    raise ConnectionAbortedError(
                        "UDM observation stopped while opening an exec channel."
                    )
            self._channel = channel
        return channel

    def _drain_exec_channel(
        self,
        channel,
        *,
        total_output_bytes: int,
        deadline: float,
    ) -> tuple[bytes, bytes, int]:
        stdout = bytearray()
        stderr = bytearray()
        while True:
            if self._stop_event.is_set():
                raise ConnectionAbortedError("UDM observation stopped while receiving output.")
            self._drain_ready_stream(
                channel.recv_ready,
                channel.recv,
                stdout,
                stderr,
                total_output_bytes,
            )
            self._drain_ready_stream(
                channel.recv_stderr_ready,
                channel.recv_stderr,
                stderr,
                stdout,
                total_output_bytes,
            )
            if time.monotonic() >= deadline:
                self._abort_resources()
                raise TimeoutError(
                    f"UDM observation command exceeded {UDM_COMMAND_TIMEOUT_SECONDS:g} seconds."
                )
            if channel.closed and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
            time.sleep(0.01)

        status = channel.recv_exit_status()
        if isinstance(status, bool) or not isinstance(status, int) or status < 0:
            raise CommandExecutionError(
                "UDM exec channel closed without a verifiable remote exit status."
            )
        return bytes(stdout), bytes(stderr), status

    @staticmethod
    def _drain_ready_stream(
        ready,
        receive,
        destination: bytearray,
        other_stream: bytearray,
        total_output_bytes: int,
    ) -> None:
        chunks = 0
        while ready() and chunks < MAX_LIVE_READ_CHUNKS_PER_TICK:
            try:
                data = receive(16_384)
            except socket.timeout:
                return
            if not isinstance(data, bytes):
                raise CommandExecutionError("UDM exec channel returned non-byte output.")
            if not data:
                return
            pending_command_bytes = len(destination) + len(other_stream) + len(data)
            if pending_command_bytes > MAX_UDM_COMMAND_OUTPUT_BYTES:
                raise CommandExecutionError(
                    "UDM observation output exceeded the per-command safety limit."
                )
            if total_output_bytes + pending_command_bytes > MAX_UDM_TOTAL_OUTPUT_BYTES:
                raise CommandExecutionError(
                    "UDM observation output exceeded the total run safety limit."
                )
            destination.extend(data)
            chunks += 1

    @staticmethod
    def _decode_observation_output(output: bytes, command_id: str) -> str:
        try:
            decoded = output.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise CommandExecutionError(
                f"UDM observation {command_id!r} returned invalid UTF-8 output."
            ) from exc
        if any(
            unicodedata.category(character) in {"Cc", "Cf", "Cs"} and character not in "\r\n"
            for character in decoded
        ):
            raise CommandExecutionError(
                f"UDM observation {command_id!r} returned terminal-control output."
            )
        return decoded.replace("\r\n", "\n").replace("\r", "\n")

    def _abort_resources(self) -> None:
        with self._resource_lock:
            connection, self._socket = self._socket, None
            channel, self._channel = self._channel, None
            client, self._client = self._client, None
        # Close the application-owned socket first. _BoundedSSHSocket waits for
        # an already-started send and rejects every send that begins afterwards.
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
        if channel is not None:
            try:
                channel.close()
            except Exception:
                pass
        if client is not None:
            try:
                client.close()
            except Exception:
                pass

    def _clear_password_buffers(self) -> None:
        for password_buffer in (self._password_buffer, self._source_password_buffer):
            for index in range(len(password_buffer)):
                password_buffer[index] = 0


# ---------- SSH Workers ----------
class HostKeyFetchWorker(QThread):
    succeeded = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, host: str, port: int):
        super().__init__()
        self.host = host
        self.port = port
        self._stop_event = threading.Event()
        self._resource_lock = threading.Lock()
        self._socket = None
        self._transport = None

    def run(self):
        try:
            if self._stop_event.is_set():
                return
            validate_host(self.host, stop_event=self._stop_event)
            if self._stop_event.is_set():
                return
            connection = _open_tcp_connection(
                self.host,
                self.port,
                stop_event=self._stop_event,
            )
            connection = _BoundedSSHSocket(
                connection,
                stop_event=self._stop_event,
                max_post_banner_bytes=MAX_HOST_KEY_SSH_POST_BANNER_BYTES,
            )
            with self._resource_lock:
                self._socket = connection
            if self._stop_event.is_set():
                return
            transport = paramiko.Transport(
                connection,
                disabled_algorithms=ssh_disabled_algorithms(),
            )
            with self._resource_lock:
                self._transport = transport
            transport.start_client(timeout=10)
            if not self._stop_event.is_set():
                self.succeeded.emit(transport.get_remote_server_key())
        except Exception as exc:
            if not self._stop_event.is_set():
                self.failed.emit(_redact_sensitive_text(exc))
        finally:
            self._cleanup()

    def stop(self):
        self._stop_event.set()
        self._cleanup()

    def _cleanup(self):
        with self._resource_lock:
            transport, self._transport = self._transport, None
            connection, self._socket = self._socket, None
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass
        # Paramiko 4's Transport.close() is a no-op while inactive, so always
        # close the underlying socket as well after partial negotiation.
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass


class InteractiveSSHWorker(QThread):
    output_received = pyqtSignal(str)
    connected = pyqtSignal()
    closed = pyqtSignal()

    def __init__(
        self,
        host,
        port=22,
        known_hosts_path=None,
        *,
        verified_server_key=None,
        username=None,
        password_buffer=None,
        use_keys=False,
        client_factory=paramiko.SSHClient,
    ):
        super().__init__()
        self.host = host
        self.port = port
        self.known_hosts_path = Path(known_hosts_path) if known_hosts_path else None
        self.verified_server_key = verified_server_key
        self.username = username
        self.password_buffer = password_buffer
        if use_keys:
            # Paramiko 4 can force ssh-rsa for an RSA user certificate against
            # OpenSSH <7.8 even when that pubkey algorithm is disabled. Until
            # Clidarvi can integrate and test a Paramiko revision that no
            # longer contains the affected code, password-only authentication
            # is the only fail-closed Live CLI option.
            raise ValueError(
                "SSH key and agent authentication are unavailable in this alpha; "
                "enter a password instead."
            )
        self.use_keys = False
        self.client_factory = client_factory
        self.client = None
        self.channel = None
        self._socket = None
        self._stop_event = threading.Event()
        self._input_queue = queue.Queue(maxsize=1024)
        self._resize_queue = queue.Queue(maxsize=32)
        self._resource_lock = threading.Lock()
        self._output_lock = threading.Lock()
        self._pending_output: deque[str] = deque()
        self._pending_output_chars = 0
        self._output_wakeup_pending = False
        self._output_overflowed = False

    def _queue_output(self, text: str) -> bool:
        """Queue output with at most one outstanding Qt wake-up signal.

        The queue never drops or reorders accepted terminal text. If accepting
        another chunk would exceed the cap, the chunk is rejected, an explicit
        local notice is queued after all accepted bytes, and the raw session is
        aborted. ``output_received`` remains a ``str`` signal for compatibility,
        but consumers should treat it as a wake-up and call :meth:`drain_output`.
        """

        if not text:
            return True
        emit_notification = None
        overflow = False
        with self._output_lock:
            if self._output_overflowed:
                return False
            payload_limit = MAX_LIVE_PENDING_OUTPUT_CHARS - len(_LIVE_OUTPUT_OVERFLOW_NOTICE)
            if self._pending_output_chars + len(text) > max(0, payload_limit):
                self._output_overflowed = True
                self._pending_output.append(_LIVE_OUTPUT_OVERFLOW_NOTICE)
                self._pending_output_chars += len(_LIVE_OUTPUT_OVERFLOW_NOTICE)
                overflow = True
                if not self._output_wakeup_pending:
                    self._output_wakeup_pending = True
                    emit_notification = _LIVE_OUTPUT_OVERFLOW_NOTICE
            else:
                self._pending_output.append(text)
                self._pending_output_chars += len(text)
                if not self._output_wakeup_pending:
                    self._output_wakeup_pending = True
                    emit_notification = text
        if emit_notification is not None:
            self.output_received.emit(emit_notification)
        if overflow:
            self.stop()
            return False
        return True

    def drain_output(self) -> str:
        """Atomically drain queued terminal output in original byte order."""

        with self._output_lock:
            if not self._pending_output:
                self._output_wakeup_pending = False
                return ""
            text = "".join(self._pending_output)
            self._pending_output.clear()
            self._pending_output_chars = 0
            self._output_wakeup_pending = False
            return text

    def pending_output_chars(self) -> int:
        """Expose the bounded pending size for diagnostics and tests."""

        with self._output_lock:
            return self._pending_output_chars

    def run(self):
        password_text = None
        connection = None
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        try:
            if self._stop_event.is_set():
                return
            validate_host(self.host, stop_event=self._stop_event)
            if self._stop_event.is_set():
                return
            connection = _open_tcp_connection(
                self.host,
                self.port,
                stop_event=self._stop_event,
            )
            connection = _BoundedSSHSocket(
                connection,
                stop_event=self._stop_event,
                max_post_banner_bytes=MAX_LIVE_SSH_POST_BANNER_BYTES,
            )
            with self._resource_lock:
                if self._stop_event.is_set():
                    connection.close()
                    return
                self._socket = connection
            client = self.client_factory()
            with self._resource_lock:
                self.client = client
            # GUI-created sessions pin the exact key just retrieved and
            # approved by Clidarvi. This avoids reopening a mutable pathname
            # between approval and authentication. The path fallback remains
            # for backwards-compatible direct worker use; system host keys are
            # never loaded.
            if self.verified_server_key is not None:
                host_identifier = self.host if self.port == 22 else f"[{self.host}]:{self.port}"
                client.get_host_keys().add(
                    host_identifier,
                    self.verified_server_key.get_name(),
                    self.verified_server_key,
                )
            elif self.known_hosts_path and self.known_hosts_path.exists():
                client.load_host_keys(str(self.known_hosts_path))
            client.set_missing_host_key_policy(paramiko.RejectPolicy())

            if isinstance(self.password_buffer, bytearray):
                password_text = self.password_buffer.decode("utf-8", errors="strict")
            client.connect(
                self.host,
                self.port,
                sock=connection,
                username=self.username or None,
                password=password_text,
                look_for_keys=self.use_keys,
                allow_agent=self.use_keys,
                timeout=10,
                auth_timeout=15,
                banner_timeout=15,
                disabled_algorithms=ssh_disabled_algorithms(),
            )

            channel = client.invoke_shell(term="xterm-256color", width=120, height=40)
            channel.settimeout(0.0)
            with self._resource_lock:
                self.channel = channel
            self.connected.emit()

            pending_send = bytearray()
            deferred_input = None
            while not self._stop_event.is_set():
                while len(pending_send) < MAX_LIVE_PENDING_INPUT_BYTES:
                    if deferred_input is not None:
                        queued, deferred_input = deferred_input, None
                    else:
                        try:
                            queued = self._input_queue.get_nowait()
                        except queue.Empty:
                            break
                    remaining = MAX_LIVE_PENDING_INPUT_BYTES - len(pending_send)
                    if len(queued) > remaining:
                        deferred_input = queued
                        break
                    pending_send.extend(queued)
                if pending_send and channel.send_ready():
                    sent = channel.send(bytes(pending_send))
                    if sent > 0:
                        del pending_send[:sent]

                latest_size = None
                while True:
                    try:
                        latest_size = self._resize_queue.get_nowait()
                    except queue.Empty:
                        break
                if latest_size:
                    width, height = latest_size
                    channel.resize_pty(width=width, height=height)

                received_any = False
                received_bytes = 0
                received_chunks = 0
                while (
                    not self._stop_event.is_set()
                    and channel.recv_ready()
                    and received_bytes < MAX_LIVE_READ_BYTES_PER_TICK
                    and received_chunks < MAX_LIVE_READ_CHUNKS_PER_TICK
                ):
                    raw = channel.recv(16_384)
                    if not raw:
                        self._stop_event.set()
                        break
                    received_any = True
                    received_bytes += len(raw)
                    received_chunks += 1
                    decoded = decoder.decode(raw, final=False)
                    if decoded and not self._queue_output(decoded):
                        break

                if channel.closed or channel.exit_status_ready():
                    break
                if received_any:
                    # Bound signal production as well as each inner read batch,
                    # so a noisy peer cannot indefinitely outrun the GUI queue.
                    self.msleep(10)
                else:
                    self.msleep(15)
        except Exception as e:
            if not self._stop_event.is_set():
                safe_error = _redact_sensitive_text(e, password_text)
                self._queue_output(_bound_diagnostic_text(f"SSH error: {safe_error}\n"))
        finally:
            final_text = decoder.decode(b"", final=True)
            if final_text:
                self._queue_output(final_text)
            if connection is not None and connection.receive_limit_exceeded():
                self._stop_event.set()
                self._queue_output(_LIVE_RECEIVE_LIMIT_NOTICE)
            self._cleanup_resources()
            if isinstance(self.password_buffer, bytearray):
                for index in range(len(self.password_buffer)):
                    self.password_buffer[index] = 0
            password_text = None
            self.username = None
            self.closed.emit()

    def send_input(self, data: str):
        if data and not self._stop_event.is_set():
            encoded = data.encode("utf-8")
            if len(encoded) > MAX_LIVE_INPUT_CHUNK_BYTES:
                self._queue_output(
                    "\r\n[Local input rejected: paste exceeds the 16 KiB safety limit.]\r\n"
                )
                return
            try:
                self._input_queue.put_nowait(encoded)
            except queue.Full:
                # Continuing after dropping arbitrary keystrokes could turn a
                # command into a different command. Abort the raw session.
                self._queue_output(
                    "\r\n[Live CLI closed: local input queue safety limit reached.]\r\n"
                )
                self.stop()
                return

    def resize_terminal(self, width: int, height: int):
        if width > 0 and height > 0 and not self._stop_event.is_set():
            try:
                self._resize_queue.put_nowait((width, height))
            except queue.Full:
                try:
                    self._resize_queue.get_nowait()
                except queue.Empty:
                    pass
                try:
                    self._resize_queue.put_nowait((width, height))
                except queue.Full:
                    pass

    def stop(self):
        self._stop_event.set()
        self._cleanup_resources()

    close = stop

    def _cleanup_resources(self):
        with self._resource_lock:
            channel, self.channel = self.channel, None
            client, self.client = self.client, None
            connection, self._socket = self._socket, None
        if channel is not None:
            try:
                channel.close()
            except Exception:
                pass
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
        if connection is not None:
            try:
                connection.close()
            except OSError:
                pass
