# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 devnetdreamer (https://github.com/devnetdreamer) and Clidarvi contributors

from __future__ import annotations

import threading
import unittest
from unittest.mock import patch

import paramiko
from netmiko.base_connection import BaseConnection
from netmiko.channel import SSHChannel
from PyQt6.QtCore import Qt

import clidarvi_workers


class _Endpoint:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class _SuccessfulConnection:
    base_prompt = "router"

    def __init__(self):
        self.remote_conn = _Endpoint()
        self.remote_conn_pre = _Endpoint()
        self.context_exit_calls = 0
        self.graceful_writes = []

    def __enter__(self):
        return self

    def __exit__(self, _kind, _value, _traceback):
        self.context_exit_calls += 1
        if not self.remote_conn.closed:
            self.graceful_writes.extend(["RETURN", "exit"])

    def send_command(self, command, **_kwargs):
        return f"{command}\nVersion 1\nrouter#"

    def send_command_timing(self, command, **_kwargs):
        return f"{command}\nVersion 1\nrouter#"


class _PassiveSocket:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def _passive_socket_factory(_host, _port, *, stop_event):
    del stop_event
    return _PassiveSocket()


class _UdmRawSocket:
    def __init__(self):
        self.closed = False

    def shutdown(self, _how):
        self.closed = True

    def close(self):
        self.closed = True


class _UdmExecChannel:
    def __init__(self, stdout=b"", stderr=b"", status=0, *, close_after_exec=True):
        self.stdout_chunks = [stdout] if stdout else []
        self.stderr_chunks = [stderr] if stderr else []
        self.status = status
        self.command = None
        self.timeout = None
        self.closed = False
        self.close_after_exec = close_after_exec
        self.close_calls = 0

    def exec_command(self, command):
        self.command = command
        self.closed = self.close_after_exec

    def settimeout(self, value):
        self.timeout = value

    def recv_ready(self):
        return bool(self.stdout_chunks)

    def recv(self, _size):
        return self.stdout_chunks.pop(0)

    def recv_stderr_ready(self):
        return bool(self.stderr_chunks)

    def recv_stderr(self, _size):
        return self.stderr_chunks.pop(0)

    def recv_exit_status(self):
        return self.status

    def close(self):
        self.close_calls += 1
        self.closed = True

    def get_pty(self, *_args, **_kwargs):
        raise AssertionError("UDM observation worker must never request a PTY.")

    def invoke_shell(self, *_args, **_kwargs):
        raise AssertionError("UDM observation worker must never invoke a shell.")

    def send(self, *_args, **_kwargs):
        raise AssertionError("UDM observation worker must never write remote stdin.")

    def update_environment(self, *_args, **_kwargs):
        raise AssertionError("UDM observation worker must never supply an environment.")


class _UdmTransport:
    def __init__(self, channels):
        self.channels = list(channels)
        self.open_timeouts = []

    def is_active(self):
        return True

    def open_session(self, *, timeout):
        self.open_timeouts.append(timeout)
        if not self.channels:
            raise AssertionError("Worker opened more exec channels than expected.")
        return self.channels.pop(0)


class _UdmClient:
    def __init__(self, transport):
        self.transport = transport
        self.host_keys = paramiko.HostKeys()
        self.policy = None
        self.connect_args = None
        self.connect_kwargs = None
        self.closed = False

    def get_host_keys(self):
        return self.host_keys

    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def connect(self, *args, **kwargs):
        self.connect_args = args
        self.connect_kwargs = kwargs

    def get_transport(self):
        return self.transport

    def invoke_shell(self, *_args, **_kwargs):
        raise AssertionError("UDM observation worker must never invoke a shell.")

    def exec_command(self, *_args, **_kwargs):
        raise AssertionError("Worker must own and bound the raw exec channel directly.")

    def close(self):
        self.closed = True


def _udm_device(password=None):
    return {
        "device_type": clidarvi_workers.UDM_READ_ONLY_DEVICE_TYPE,
        "host": "udm.example.net",
        "port": 22,
        "username": "root",
        "password": password if password is not None else bytearray(b"password"),
    }


def _udm_command_ids():
    return tuple(clidarvi_workers.UDM_READ_ONLY_COMMANDS)


_AUTOMATION_HOST_KEY_POLICY = {
    "ssh_strict": True,
    "system_host_keys": False,
    "alt_host_keys": True,
    "alt_key_file": "/tmp/clidarvi-test-known-hosts",
}


def _automation_device(device_type, *, host=None, port=22, password=None):
    return {
        "device_type": device_type,
        "host": host or f"{device_type.replace('_', '-')}.example.net",
        "port": port,
        "username": "admin",
        "password": password if password is not None else bytearray(b"password"),
        **_AUTOMATION_HOST_KEY_POLICY,
    }


class WorkerHardeningTests(unittest.TestCase):
    def test_udm_allowlist_is_fixed_immutable_and_netmiko_path_stays_blocked(self):
        self.assertEqual(
            dict(clidarvi_workers.UDM_READ_ONLY_COMMANDS),
            {
                "uptime": "uptime",
                "utc_time": "date -u",
                "kernel": "uname -a",
                "identity": "id",
            },
        )
        with self.assertRaises(TypeError):
            clidarvi_workers.UDM_READ_ONLY_COMMANDS["unsafe"] = "reboot"
        with self.assertRaisesRegex(ValueError, "not available through general Netmiko Automation"):
            clidarvi_workers.AutomationWorker(
                [_udm_device()],
                "uptime",
                connector_factory=lambda **_kwargs: self.fail("Netmiko connector was called."),
                socket_factory=_passive_socket_factory,
            )

    def test_udm_constructor_rejects_every_non_exact_plan_before_socket(self):
        key = paramiko.RSAKey.generate(1024)
        complete_plan = _udm_command_ids()
        socket_calls = []

        def socket_factory(*_args, **_kwargs):
            socket_calls.append(True)
            raise AssertionError("No socket may open for an invalid UDM plan.")

        cases = (
            (_udm_device(), list(complete_plan), key, "immutable tuple"),
            (_udm_device(), complete_plan[:-1], key, "complete fixed-order"),
            (_udm_device(), tuple(reversed(complete_plan)), key, "complete fixed-order"),
            (_udm_device(), complete_plan + ("reboot",), key, "complete fixed-order"),
            (_udm_device(), complete_plan, None, "trusted SSH host key"),
            ({**_udm_device(), "device_type": "generic"}, complete_plan, key, "device_type"),
            ({**_udm_device(), "port": True}, complete_plan, key, "port"),
            ({**_udm_device(), "username": "admin"}, complete_plan, key, "root SSH username"),
            ({**_udm_device(), "password": b"password"}, complete_plan, key, "bytearray"),
        )
        for device, command_ids, server_key, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    clidarvi_workers.UdmReadOnlyAutomationWorker(
                        device,
                        command_ids,
                        verified_server_key=server_key,
                        socket_factory=socket_factory,
                    )
        self.assertEqual(socket_calls, [])

    def test_udm_dns_validation_fails_before_socket_and_clears_password(self):
        password = bytearray(b"password")
        socket_calls = []
        finished = []
        worker = clidarvi_workers.UdmReadOnlyAutomationWorker(
            _udm_device(password),
            _udm_command_ids(),
            verified_server_key=paramiko.RSAKey.generate(1024),
            socket_factory=lambda *_args, **_kwargs: socket_calls.append(True),
        )
        worker.finished_with_log.connect(finished.append)

        with patch("clidarvi_workers.validate_host", side_effect=ValueError("not resolvable")):
            worker.run()

        self.assertTrue(worker.had_error())
        self.assertEqual(socket_calls, [])
        self.assertTrue(all(value == 0 for value in password))
        self.assertIn("not resolvable", finished[0])

    def test_udm_stop_before_run_is_clean_and_emits_a_stopped_transcript(self):
        password = bytearray(b"password")
        socket_calls = []
        worker = clidarvi_workers.UdmReadOnlyAutomationWorker(
            _udm_device(password),
            _udm_command_ids(),
            verified_server_key=paramiko.RSAKey.generate(1024),
            socket_factory=lambda *_args, **_kwargs: socket_calls.append(True),
        )
        logs = []
        transcripts = []
        worker.log.connect(logs.append)
        worker.finished_with_log.connect(transcripts.append)

        worker.stop()
        with patch(
            "clidarvi_workers.validate_host",
            side_effect=AssertionError("pre-stopped worker must not resolve a host"),
        ):
            worker.run()

        expected = "[udm.example.net] UDM observation stopped by user."
        self.assertTrue(worker.was_stopped())
        self.assertFalse(worker.had_error())
        self.assertEqual(socket_calls, [])
        self.assertEqual(logs, [expected])
        self.assertEqual(transcripts, [expected])
        self.assertTrue(all(value == 0 for value in password))

    def test_udm_stop_during_socket_setup_does_not_record_transport_error(self):
        password = bytearray(b"password")
        holder = {}

        def stopped_socket_factory(*_args, **_kwargs):
            holder["worker"].stop()
            raise OSError("socket closed by stop")

        worker = clidarvi_workers.UdmReadOnlyAutomationWorker(
            _udm_device(password),
            _udm_command_ids(),
            verified_server_key=paramiko.RSAKey.generate(1024),
            socket_factory=stopped_socket_factory,
        )
        holder["worker"] = worker
        transcripts = []
        worker.finished_with_log.connect(transcripts.append)

        with patch("clidarvi_workers.validate_host", return_value=True):
            worker.run()

        self.assertTrue(worker.was_stopped())
        self.assertFalse(worker.had_error())
        self.assertEqual(
            transcripts,
            ["[udm.example.net] UDM observation stopped by user."],
        )
        self.assertNotIn("socket closed", transcripts[0])
        self.assertTrue(all(value == 0 for value in password))

    def test_udm_stop_during_output_drain_does_not_record_paramiko_error(self):
        password = bytearray(b"password")
        holder = {}

        class StopDuringReadChannel(_UdmExecChannel):
            def recv_ready(self):
                holder["worker"].stop()
                raise paramiko.SSHException("channel closed by stop")

        channel = StopDuringReadChannel()
        raw_socket = _UdmRawSocket()
        client = _UdmClient(_UdmTransport([channel]))
        worker = clidarvi_workers.UdmReadOnlyAutomationWorker(
            _udm_device(password),
            _udm_command_ids(),
            verified_server_key=paramiko.RSAKey.generate(1024),
            client_factory=lambda: client,
            socket_factory=lambda *_args, **_kwargs: raw_socket,
        )
        holder["worker"] = worker
        transcripts = []
        worker.finished_with_log.connect(transcripts.append)

        with patch("clidarvi_workers.validate_host", return_value=True):
            worker.run()

        self.assertTrue(worker.was_stopped())
        self.assertFalse(worker.had_error())
        self.assertEqual(
            transcripts,
            ["[udm.example.net] UDM observation stopped by user."],
        )
        self.assertNotIn("channel closed", transcripts[0])
        self.assertTrue(raw_socket.closed)
        self.assertTrue(client.closed)
        self.assertGreaterEqual(channel.close_calls, 1)
        self.assertTrue(all(value == 0 for value in password))

    def test_udm_exec_worker_runs_exact_literals_with_strict_bounded_transport(self):
        channels = [
            _UdmExecChannel(b"up 10 days\n"),
            _UdmExecChannel(b"Sat Aug 22 12:00:00 UTC 2026\n"),
            _UdmExecChannel(b"Linux udm-lab.example.test 4.19\n"),
            _UdmExecChannel(b"uid=0(root) gid=0(root)\n"),
        ]
        transport = _UdmTransport(channels)
        client = _UdmClient(transport)
        raw_socket = _UdmRawSocket()
        key = paramiko.RSAKey.generate(1024)
        password = bytearray(b"password")
        source = _udm_device(password)
        worker = clidarvi_workers.UdmReadOnlyAutomationWorker(
            source,
            _udm_command_ids(),
            verified_server_key=key,
            client_factory=lambda: client,
            socket_factory=lambda *_args, **_kwargs: raw_socket,
        )
        log_messages = []
        transcripts = []
        worker.log.connect(log_messages.append)
        worker.finished_with_log.connect(transcripts.append)

        source["host"] = "mutated.example.net"
        source["username"] = "mutated"
        password[:] = b"different"
        with (
            patch("clidarvi_workers.validate_host", return_value=True),
            patch("clidarvi_workers.ConnectHandler") as netmiko_connector,
        ):
            worker.run()

        netmiko_connector.assert_not_called()
        self.assertFalse(worker.had_error())
        self.assertEqual(
            [channel.command for channel in channels],
            ["uptime", "date -u", "uname -a", "id"],
        )
        self.assertTrue(all(channel.timeout == 0.0 for channel in channels))
        self.assertEqual(
            transport.open_timeouts,
            [clidarvi_workers.UDM_CHANNEL_REQUEST_TIMEOUT_SECONDS] * 4,
        )
        self.assertEqual(client.connect_args, ("udm.example.net", 22))
        self.assertEqual(client.connect_kwargs["username"], "root")
        self.assertEqual(client.connect_kwargs["password"], "password")
        self.assertFalse(client.connect_kwargs["look_for_keys"])
        self.assertFalse(client.connect_kwargs["allow_agent"])
        self.assertIsNone(client.connect_kwargs["pkey"])
        self.assertIsNone(client.connect_kwargs["key_filename"])
        self.assertEqual(
            client.connect_kwargs["disabled_algorithms"],
            clidarvi_workers.ssh_disabled_algorithms(),
        )
        self.assertIsInstance(client.policy, paramiko.RejectPolicy)
        stored = client.host_keys.lookup("udm.example.net")
        self.assertEqual(stored[key.get_name()].asbytes(), key.asbytes())
        self.assertIsNot(stored[key.get_name()], key)
        self.assertIsInstance(client.connect_kwargs["sock"], clidarvi_workers._BoundedSSHSocket)
        self.assertEqual(
            client.connect_kwargs["sock"]._max_post_banner_bytes,
            clidarvi_workers.MAX_AUTOMATION_SSH_POST_BANNER_BYTES,
        )
        self.assertTrue(raw_socket.closed)
        self.assertTrue(client.closed)
        self.assertTrue(all(value == 0 for value in password))
        self.assertTrue(all(value == 0 for value in worker._password_buffer))
        self.assertIn("up 10 days", transcripts[0])
        self.assertIn("uid=0(root)", transcripts[0])
        self.assertTrue(any("exact trusted SSH host key" in message for message in log_messages))

    def test_udm_stderr_nonzero_or_missing_status_stops_before_later_commands(self):
        failures = (
            (_UdmExecChannel(b"partial\n", b"warning\n", 0), "stderr"),
            (_UdmExecChannel(b"partial\n", b"", 7), "exit status 7"),
            (_UdmExecChannel(b"partial\n", b"", -1), "without a verifiable"),
        )
        for failing_channel, expected in failures:
            with self.subTest(expected=expected):
                later_channel = _UdmExecChannel(b"must not run\n")
                transport = _UdmTransport([failing_channel, later_channel])
                client = _UdmClient(transport)
                password = bytearray(b"password")
                worker = clidarvi_workers.UdmReadOnlyAutomationWorker(
                    _udm_device(password),
                    _udm_command_ids(),
                    verified_server_key=paramiko.RSAKey.generate(1024),
                    client_factory=lambda: client,
                    socket_factory=lambda *_args, **_kwargs: _UdmRawSocket(),
                )
                transcripts = []
                worker.finished_with_log.connect(transcripts.append)

                with patch("clidarvi_workers.validate_host", return_value=True):
                    worker.run()

                self.assertTrue(worker.had_error())
                self.assertIsNone(later_channel.command)
                self.assertIn(expected, transcripts[0])
                self.assertNotIn("warning", transcripts[0])
                self.assertTrue(all(value == 0 for value in password))

    def test_udm_output_and_time_limits_abort_the_transport(self):
        cases = (
            (_UdmExecChannel(b"12345\n"), {"MAX_UDM_COMMAND_OUTPUT_BYTES": 4}, "per-command"),
            (
                _UdmExecChannel(close_after_exec=False),
                {"UDM_COMMAND_TIMEOUT_SECONDS": 0.001},
                "exceeded",
            ),
        )
        for channel, patched_values, expected in cases:
            with self.subTest(expected=expected):
                raw_socket = _UdmRawSocket()
                client = _UdmClient(_UdmTransport([channel]))
                worker = clidarvi_workers.UdmReadOnlyAutomationWorker(
                    _udm_device(),
                    _udm_command_ids(),
                    verified_server_key=paramiko.RSAKey.generate(1024),
                    client_factory=lambda: client,
                    socket_factory=lambda *_args, **_kwargs: raw_socket,
                )
                transcripts = []
                worker.finished_with_log.connect(transcripts.append)

                patches = [
                    patch.object(clidarvi_workers, name, value)
                    for name, value in patched_values.items()
                ]
                with patch("clidarvi_workers.validate_host", return_value=True):
                    for active_patch in patches:
                        active_patch.start()
                    try:
                        worker.run()
                    finally:
                        for active_patch in reversed(patches):
                            active_patch.stop()

                self.assertTrue(worker.had_error())
                self.assertTrue(raw_socket.closed)
                self.assertTrue(client.closed)
                self.assertIn(expected, transcripts[0])

    def test_udm_command_timeout_budget_includes_exec_channel_setup(self):
        channel = _UdmExecChannel(b"late output\n")
        client = _UdmClient(_UdmTransport([channel]))
        password = bytearray(b"password")
        worker = clidarvi_workers.UdmReadOnlyAutomationWorker(
            _udm_device(password),
            _udm_command_ids(),
            verified_server_key=paramiko.RSAKey.generate(1024),
            client_factory=lambda: client,
            socket_factory=lambda *_args, **_kwargs: _UdmRawSocket(),
        )
        clock = [100.0]
        transcripts = []
        worker.finished_with_log.connect(transcripts.append)

        def connect(_password_text):
            worker._client = client
            return client

        def open_after_budget(_transport, _command):
            clock[0] += clidarvi_workers.UDM_COMMAND_TIMEOUT_SECONDS
            return channel

        with (
            patch("clidarvi_workers.validate_host", return_value=True),
            patch.object(worker, "_connect", side_effect=connect),
            patch.object(worker, "_open_exec_channel", side_effect=open_after_budget),
            patch("clidarvi_workers.time.monotonic", side_effect=lambda: clock[0]),
        ):
            worker.run()

        self.assertTrue(worker.had_error())
        self.assertTrue(client.closed)
        self.assertTrue(all(value == 0 for value in password))
        self.assertIn("exceeded 15 seconds", transcripts[0])

    def test_udm_invalid_output_controls_abort_before_next_command(self):
        for output, expected in (
            (b"bad\xff\n", "invalid UTF-8"),
            (b"bad\x1b[2J\n", "terminal-control"),
        ):
            with self.subTest(expected=expected):
                first = _UdmExecChannel(output)
                later = _UdmExecChannel(b"must not run\n")
                client = _UdmClient(_UdmTransport([first, later]))
                worker = clidarvi_workers.UdmReadOnlyAutomationWorker(
                    _udm_device(),
                    _udm_command_ids(),
                    verified_server_key=paramiko.RSAKey.generate(1024),
                    client_factory=lambda: client,
                    socket_factory=lambda *_args, **_kwargs: _UdmRawSocket(),
                )
                transcripts = []
                worker.finished_with_log.connect(transcripts.append)

                with patch("clidarvi_workers.validate_host", return_value=True):
                    worker.run()

                self.assertTrue(worker.had_error())
                self.assertIsNone(later.command)
                self.assertIn(expected, transcripts[0])

    def test_general_automation_profile_sets_are_explicit_and_disjoint(self):
        self.assertEqual(
            clidarvi_workers.EXPERIMENTAL_AUTOMATION_DEVICE_TYPES,
            frozenset({"aruba_os", "cisco_wlc", "fortinet"}),
        )
        self.assertEqual(
            clidarvi_workers.GENERAL_AUTOMATION_BLOCKED_DEVICE_TYPES,
            frozenset({"generic", clidarvi_workers.UDM_READ_ONLY_DEVICE_TYPE}),
        )
        self.assertTrue(
            clidarvi_workers.EXPERIMENTAL_AUTOMATION_DEVICE_TYPES.isdisjoint(
                clidarvi_workers.GENERAL_AUTOMATION_BLOCKED_DEVICE_TYPES
            )
        )

    def test_generic_and_udm_stay_blocked_even_with_experimental_opt_in(self):
        for device_type in sorted(clidarvi_workers.GENERAL_AUTOMATION_BLOCKED_DEVICE_TYPES):
            for allow_experimental in (False, True):
                with self.subTest(
                    device_type=device_type,
                    allow_experimental=allow_experimental,
                ):
                    network_calls = []

                    with self.assertRaisesRegex(
                        ValueError,
                        "(?i)(blocked|not available|dedicated)",
                    ):
                        clidarvi_workers.AutomationWorker(
                            [_automation_device(device_type)],
                            "show version",
                            allow_experimental_automation=allow_experimental,
                            connector_factory=lambda **_kwargs: network_calls.append("connector"),
                            socket_factory=lambda *_args, **_kwargs: network_calls.append("socket"),
                        )

                    self.assertEqual(network_calls, [])

    def test_experimental_profiles_are_blocked_by_default_before_network(self):
        for device_type in sorted(clidarvi_workers.EXPERIMENTAL_AUTOMATION_DEVICE_TYPES):
            with self.subTest(device_type=device_type):
                network_calls = []

                with self.assertRaisesRegex(ValueError, "(?i)experimental"):
                    clidarvi_workers.AutomationWorker(
                        [_automation_device(device_type)],
                        "show version",
                        connector_factory=lambda **_kwargs: network_calls.append("connector"),
                        socket_factory=lambda *_args, **_kwargs: network_calls.append("socket"),
                    )

                self.assertEqual(network_calls, [])

    def test_each_experimental_profile_accepts_exact_true_for_one_target(self):
        for device_type in sorted(clidarvi_workers.EXPERIMENTAL_AUTOMATION_DEVICE_TYPES):
            with self.subTest(device_type=device_type):
                seen_profiles = []
                logs = []
                transcripts = []

                def connector(**kwargs):
                    seen_profiles.append(kwargs["device_type"])
                    return _SuccessfulConnection()

                worker = clidarvi_workers.AutomationWorker(
                    [_automation_device(device_type)],
                    "show version",
                    allow_experimental_automation=True,
                    connector_factory=connector,
                    socket_factory=_passive_socket_factory,
                )
                worker.log.connect(logs.append, Qt.ConnectionType.DirectConnection)
                worker.finished_with_log.connect(transcripts.append)

                worker.run()

                self.assertFalse(worker.had_error())
                self.assertEqual(seen_profiles, [device_type])
                self.assertEqual(len(transcripts), 1)
                disclosure_log = "\n".join(logs).lower()
                disclosure_transcript = transcripts[0].lower()
                for disclosure in (disclosure_log, disclosure_transcript):
                    self.assertIn("experimental", disclosure)
                    self.assertIn(device_type, disclosure)
                    self.assertTrue(
                        "session preparation" in disclosure or "driver setup" in disclosure,
                        disclosure,
                    )

    def test_experimental_opt_in_rejects_truthy_non_bool_values(self):
        for allow_experimental in (1, "yes", object()):
            with self.subTest(value=repr(allow_experimental)):
                network_calls = []
                with self.assertRaisesRegex(ValueError, "(?i)bool"):
                    clidarvi_workers.AutomationWorker(
                        [_automation_device("fortinet")],
                        "show version",
                        allow_experimental_automation=allow_experimental,
                        connector_factory=lambda **_kwargs: network_calls.append("connector"),
                        socket_factory=lambda *_args, **_kwargs: network_calls.append("socket"),
                    )
                self.assertEqual(network_calls, [])

    def test_experimental_runtime_must_match_exact_audited_netmiko_version(self):
        network_calls = []
        with (
            patch("clidarvi_workers.importlib_metadata.version", return_value="4.7.1"),
            self.assertRaisesRegex(ValueError, "4\\.7\\.0.*4\\.7\\.1"),
        ):
            clidarvi_workers.AutomationWorker(
                [_automation_device("fortinet")],
                "show version",
                allow_experimental_automation=True,
                connector_factory=lambda **_kwargs: network_calls.append("connector"),
                socket_factory=lambda *_args, **_kwargs: network_calls.append("socket"),
            )

        self.assertEqual(network_calls, [])

    def test_experimental_runtime_missing_package_is_controlled_and_fail_closed(self):
        network_calls = []
        with (
            patch(
                "clidarvi_workers.importlib_metadata.version",
                side_effect=clidarvi_workers.importlib_metadata.PackageNotFoundError("netmiko"),
            ),
            self.assertRaisesRegex(ValueError, "(?i)not installed"),
        ):
            clidarvi_workers.AutomationWorker(
                [_automation_device("cisco_wlc")],
                "show sysinfo",
                allow_experimental_automation=True,
                connector_factory=lambda **_kwargs: network_calls.append("connector"),
                socket_factory=lambda *_args, **_kwargs: network_calls.append("socket"),
            )

        self.assertEqual(network_calls, [])

    def test_experimental_runtime_metadata_failure_is_controlled_and_fail_closed(self):
        network_calls = []
        with (
            patch(
                "clidarvi_workers.importlib_metadata.version",
                side_effect=OSError("metadata unavailable"),
            ),
            self.assertRaisesRegex(ValueError, "(?i)could not be verified"),
        ):
            clidarvi_workers.AutomationWorker(
                [_automation_device("aruba_os")],
                "show version",
                allow_experimental_automation=True,
                connector_factory=lambda **_kwargs: network_calls.append("connector"),
                socket_factory=lambda *_args, **_kwargs: network_calls.append("socket"),
            )

        self.assertEqual(network_calls, [])

    def test_experimental_runtime_is_authoritatively_rechecked_before_network(self):
        network_calls = []
        with patch(
            "clidarvi_workers.importlib_metadata.version",
            side_effect=("4.7.0", "4.7.1"),
        ) as version_check:
            worker = clidarvi_workers.AutomationWorker(
                [_automation_device("fortinet")],
                "show version",
                allow_experimental_automation=True,
                connector_factory=lambda **_kwargs: network_calls.append("connector"),
                socket_factory=lambda *_args, **_kwargs: network_calls.append("socket"),
            )

            with self.assertRaisesRegex(ValueError, "4\\.7\\.0.*4\\.7\\.1"):
                worker._run_devices()

        self.assertEqual(version_check.call_count, 2)
        self.assertEqual(network_calls, [])

    def test_experimental_runs_reject_multiple_or_mixed_targets_before_network(self):
        cases = (
            [
                _automation_device("fortinet", host="fortinet-1.example.net"),
                _automation_device("fortinet", host="fortinet-2.example.net"),
            ],
            [
                _automation_device("cisco_ios"),
                _automation_device("fortinet"),
            ],
        )
        for devices in cases:
            with self.subTest(profiles=[device["device_type"] for device in devices]):
                network_calls = []
                with self.assertRaisesRegex(ValueError, "(?i)(one|single|mixed)"):
                    clidarvi_workers.AutomationWorker(
                        devices,
                        "show version",
                        allow_experimental_automation=True,
                        connector_factory=lambda **_kwargs: network_calls.append("connector"),
                        socket_factory=lambda *_args, **_kwargs: network_calls.append("socket"),
                    )
                self.assertEqual(network_calls, [])

    def test_experimental_opt_in_is_rejected_for_stable_profile(self):
        network_calls = []
        with self.assertRaisesRegex(ValueError, "(?i)(experimental|opt.in)"):
            clidarvi_workers.AutomationWorker(
                [_automation_device("cisco_ios")],
                "show version",
                allow_experimental_automation=True,
                connector_factory=lambda **_kwargs: network_calls.append("connector"),
                socket_factory=lambda *_args, **_kwargs: network_calls.append("socket"),
            )
        self.assertEqual(network_calls, [])

    def test_device_target_snapshot_is_copied_and_exposed_read_only(self):
        source = _automation_device("cisco_ios", host="router.example.net")
        seen_targets = []

        def connector(**kwargs):
            seen_targets.append((kwargs["device_type"], kwargs["host"], kwargs["port"]))
            return _SuccessfulConnection()

        worker = clidarvi_workers.AutomationWorker(
            [source],
            "show version",
            connector_factory=connector,
            socket_factory=_passive_socket_factory,
        )
        source.update(
            {
                "device_type": "fortinet",
                "host": "different.example.net",
                "port": 2222,
            }
        )

        worker._run_devices()

        self.assertEqual(seen_targets, [("cisco_ios", "router.example.net", 22)])
        with self.assertRaises(TypeError):
            worker.devices[0]["host"] = "mutated.example.net"

        worker._run_devices()

        self.assertEqual(
            seen_targets,
            [
                ("cisco_ios", "router.example.net", 22),
                ("cisco_ios", "router.example.net", 22),
            ],
        )

    def test_frozen_run_snapshot_closes_connector_time_mutation_window(self):
        seen_profiles = []
        mutation_errors = []
        worker = None

        def connector(**kwargs):
            seen_profiles.append(kwargs["device_type"])
            try:
                worker.devices[0]["device_type"] = "fortinet"
            except TypeError as exc:
                mutation_errors.append(exc)
            return _SuccessfulConnection()

        worker = clidarvi_workers.AutomationWorker(
            [_automation_device("cisco_ios", host="router.example.net")],
            "show version",
            connector_factory=connector,
            socket_factory=_passive_socket_factory,
        )

        worker._run_devices()
        worker._run_devices()

        self.assertEqual(seen_profiles, ["cisco_ios", "cisco_ios"])
        self.assertEqual(len(mutation_errors), 2)

    def test_wholesale_same_profile_target_replacement_is_rejected_before_network(self):
        network_calls = []
        worker = clidarvi_workers.AutomationWorker(
            [_automation_device("fortinet", host="approved.example.net")],
            "show version",
            allow_experimental_automation=True,
            connector_factory=lambda **_kwargs: network_calls.append("connector"),
            socket_factory=lambda *_args, **_kwargs: network_calls.append("socket"),
        )
        worker.devices = (
            _automation_device("fortinet", host="different.example.net") | {"port": 2222},
        )

        with self.assertRaisesRegex(ValueError, "(?i)(target|host|port).*changed"):
            worker._run_devices()

        self.assertEqual(network_calls, [])

    def test_wholesale_host_key_policy_replacement_is_rejected_before_network(self):
        cases = (
            ({"ssh_strict": False}, "(?i)strict host-key"),
            (
                {"alt_key_file": "/tmp/different-known-hosts"},
                "(?i)host-key policy.*changed",
            ),
        )
        for mutation, expected in cases:
            with self.subTest(mutation=mutation):
                network_calls = []
                worker = clidarvi_workers.AutomationWorker(
                    [_automation_device("fortinet", host="approved.example.net")],
                    "show version",
                    allow_experimental_automation=True,
                    connector_factory=lambda **_kwargs: network_calls.append("connector"),
                    socket_factory=lambda *_args, **_kwargs: network_calls.append("socket"),
                )
                replacement = _automation_device("fortinet", host="approved.example.net")
                replacement.update(mutation)
                worker.devices = (replacement,)

                with self.assertRaisesRegex(ValueError, expected):
                    worker._run_devices()

                self.assertEqual(network_calls, [])

    def test_run_early_validation_failure_clears_every_password_buffer(self):
        passwords = [bytearray(b"first-secret"), bytearray(b"second-secret")]
        devices = [
            {
                "device_type": "cisco_ios",
                "host": f"router-{index}.example.net",
                "username": "admin",
                "password": password,
                **_AUTOMATION_HOST_KEY_POLICY,
            }
            for index, password in enumerate(passwords)
        ]
        worker = clidarvi_workers.AutomationWorker(
            devices,
            object(),
            connector_factory=lambda **_kwargs: self.fail("Connector must not run."),
            socket_factory=_passive_socket_factory,
        )
        transcripts = []
        worker.finished_with_log.connect(transcripts.append)

        worker.run()

        self.assertTrue(worker.had_error())
        self.assertEqual(len(transcripts), 1)
        self.assertIn("Commands must be provided as text", transcripts[0])
        for password in passwords:
            self.assertEqual(password, bytearray(len(password)))

    def test_command_block_rejects_non_line_controls_before_splitting_or_stripping(self):
        samples = (
            "show version\vreload",
            "show version\x85reload",
            "show version\t",
            "show version\u2060",
            "show version\ud800",
        )
        for commands in samples:
            with self.subTest(commands=ascii(commands)):
                worker = clidarvi_workers.AutomationWorker([], commands)
                with self.assertRaisesRegex(ValueError, "control"):
                    worker._prepare_commands()

        ordinary = clidarvi_workers.AutomationWorker([], "show version\r\n# note\rwrite memory")
        self.assertEqual(ordinary._prepare_commands(), ["show version", "write memory"])

        non_latin = clidarvi_workers.AutomationWorker([], "description safe-\U0001f680")
        with self.assertRaisesRegex(ValueError, "Latin-1"):
            non_latin._prepare_commands()

    def test_host_key_fetch_error_is_control_sanitized(self):
        worker = clidarvi_workers.HostKeyFetchWorker("router.example.net", 22)
        failures = []
        worker.failed.connect(failures.append)

        with patch(
            "clidarvi_workers.validate_host",
            side_effect=ValueError("bad\x1b[31m banner\u202erouter"),
        ):
            worker.run()

        self.assertEqual(failures, ["<redacted> (terminal-control output)"])

    def test_host_key_fetch_passes_bounded_socket_to_paramiko(self):
        class FakeSocket:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

        class FakeTransport:
            def start_client(self, timeout):
                self.timeout = timeout

            def get_remote_server_key(self):
                return object()

            def close(self):
                return None

        raw_socket = FakeSocket()
        transport = FakeTransport()
        worker = clidarvi_workers.HostKeyFetchWorker("router.example.net", 22)
        with (
            patch("clidarvi_workers.validate_host", return_value=True),
            patch("clidarvi_workers._open_tcp_connection", return_value=raw_socket),
            patch("clidarvi_workers.paramiko.Transport", return_value=transport) as factory,
        ):
            worker.run()

        bounded_socket = factory.call_args.args[0]
        self.assertIsInstance(bounded_socket, clidarvi_workers._BoundedSSHSocket)
        self.assertEqual(
            bounded_socket._max_post_banner_bytes,
            clidarvi_workers.MAX_HOST_KEY_SSH_POST_BANNER_BYTES,
        )
        self.assertTrue(raw_socket.closed)

    def test_successful_automation_uses_abort_only_teardown(self):
        connection = _SuccessfulConnection()
        worker = clidarvi_workers.AutomationWorker(
            [
                {
                    "device_type": "cisco_ios",
                    "host": "router.example.net",
                    "username": "admin",
                    "password": bytearray(b"password"),
                    **_AUTOMATION_HOST_KEY_POLICY,
                }
            ],
            "show version",
            connector_factory=lambda **_kwargs: connection,
            socket_factory=_passive_socket_factory,
        )

        transcript = worker._run_devices()

        self.assertIn("Version 1", transcript)
        self.assertTrue(connection.remote_conn.closed)
        self.assertTrue(connection.remote_conn_pre.closed)
        self.assertEqual(connection.context_exit_calls, 0)
        self.assertEqual(connection.graceful_writes, [])

    def test_read_only_command_cannot_return_an_interactive_prompt(self):
        connection = _SuccessfulConnection()
        connection.send_command_timing = lambda _command, **_kwargs: "\x1b[31m[confirm]\x1b[0m"
        worker = clidarvi_workers.AutomationWorker([], "show version")

        with self.assertRaisesRegex(clidarvi_workers.CommandExecutionError, "prompt blocked"):
            worker._execute_command(
                connection,
                "show version",
                {"device_type": "cisco_ios"},
            )

        self.assertTrue(connection.remote_conn.closed)
        self.assertTrue(connection.remote_conn_pre.closed)

    def test_read_only_command_requires_verified_completion_before_command_two(self):
        class PartialReadConnection(_SuccessfulConnection):
            def __init__(self):
                super().__init__()
                self.commands = []

            def send_command_timing(self, command, **_kwargs):
                self.commands.append(command)
                return "inventory mentions router but output continues"

        connection = PartialReadConnection()
        worker = clidarvi_workers.AutomationWorker(
            [
                {
                    "device_type": "cisco_ios",
                    "host": "router.example.net",
                    "username": "admin",
                    "password": bytearray(b"password"),
                    **_AUTOMATION_HOST_KEY_POLICY,
                }
            ],
            "show version\nshow clock",
            connector_factory=lambda **_kwargs: connection,
            socket_factory=_passive_socket_factory,
        )

        worker._run_devices()

        self.assertTrue(worker.had_error())
        self.assertEqual(connection.commands, ["show version"])
        self.assertTrue(connection.remote_conn.closed)

    def test_read_only_uses_pattern_independent_timing_read(self):
        class KeywordConnection(_SuccessfulConnection):
            def __init__(self):
                super().__init__()
                self.kwargs = None
                self.pattern_reads = 0

            def send_command(self, command, **kwargs):
                self.pattern_reads += 1
                raise AssertionError("Pattern-based send_command must not be used.")

            def send_command_timing(self, command, **kwargs):
                self.kwargs = kwargs
                return f"{command}\nVersion 1\nrouter#"

        connection = KeywordConnection()
        worker = clidarvi_workers.AutomationWorker([], "show version")

        worker._execute_command(connection, "show version", {"device_type": "cisco_ios"})

        self.assertEqual(connection.pattern_reads, 0)
        self.assertIs(connection.kwargs["strip_command"], False)
        self.assertIs(connection.kwargs["strip_prompt"], False)

    def test_prompt_looking_output_cannot_hide_a_later_interactive_prompt(self):
        class DelayedPromptConnection(_SuccessfulConnection):
            def __init__(self):
                super().__init__()
                self.commands = []

            def send_command(self, _command, **_kwargs):
                raise AssertionError("Pattern-based reading would stop too early.")

            def send_command_timing(self, command, **_kwargs):
                self.commands.append(command)
                return "payload\nrouter#\nPassword:"

        connection = DelayedPromptConnection()
        worker = clidarvi_workers.AutomationWorker(
            [
                {
                    "device_type": "cisco_ios",
                    "host": "router.example.net",
                    "username": "admin",
                    "password": bytearray(b"password"),
                    **_AUTOMATION_HOST_KEY_POLICY,
                }
            ],
            "show version\nshow clock",
            connector_factory=lambda **_kwargs: connection,
            socket_factory=_passive_socket_factory,
        )

        transcript = worker._run_devices()

        self.assertTrue(worker.had_error())
        self.assertEqual(connection.commands, ["show version"])
        self.assertIn("prompt blocked", transcript)
        self.assertTrue(connection.remote_conn.closed)

    def test_netmiko_backspace_cleanup_cannot_synthesize_completion_prompt(self):
        connection = BaseConnection.__new__(BaseConnection)
        cleaned = connection.strip_command("show version", "ordinary output\nrou\x08ter#")

        self.assertEqual(cleaned, "ordinary output\nrouter#")

        class BackspaceConnection(_SuccessfulConnection):
            def __init__(self):
                super().__init__()
                self.kwargs = None

            def send_command_timing(self, _command, **kwargs):
                self.kwargs = kwargs
                return "ordinary output\nrou\x08ter#"

        raw_connection = BackspaceConnection()
        worker = clidarvi_workers.AutomationWorker([], "show version")

        with self.assertRaises(clidarvi_workers.CommandExecutionError):
            worker._execute_command(
                raw_connection,
                "show version",
                {"device_type": "cisco_ios"},
            )

        self.assertIs(raw_connection.kwargs["strip_command"], False)

    def test_automation_channel_decoding_preserves_every_raw_byte(self):
        class ByteChannel:
            def __init__(self, payload):
                self.payload = bytearray(payload)

            def recv_ready(self):
                return bool(self.payload)

            def recv(self, size):
                chunk = bytes(self.payload[:size])
                del self.payload[:size]
                return chunk

        payload = b"[con\xfffirm]"
        utf8_output = SSHChannel(ByteChannel(payload), "utf-8").read_channel()
        latin1_output = SSHChannel(ByteChannel(payload), "latin-1").read_channel()
        self.assertEqual(utf8_output, "[confirm]")
        self.assertNotEqual(latin1_output, "[confirm]")
        self.assertIn("\u00ff", latin1_output)

        worker = clidarvi_workers.AutomationWorker(
            [],
            "show version",
            connector_factory=lambda **_kwargs: _SuccessfulConnection(),
            socket_factory=_passive_socket_factory,
        )
        params = {"host": "router.example.net", "port": 22, "encoding": "utf-8"}
        connection = worker._connect_interruptibly(params)
        self.assertEqual(params["encoding"], "latin-1")
        self.assertFalse(connection.ansi_escape_codes)
        worker.stop()

    def test_netmiko_ansi_normalization_is_disabled_before_app_commands(self):
        raw_prompt = "[con\x1b[31mfirm\x1b[0m]"
        normalizer = object.__new__(BaseConnection)
        normalizer.RETURN = "\n"
        self.assertEqual(normalizer.strip_ansi_escape_codes(raw_prompt), "[confirm]")

        class AnsiConnection(_SuccessfulConnection):
            ansi_escape_codes = True

        connection = AnsiConnection()
        worker = clidarvi_workers.AutomationWorker(
            [],
            "show version",
            connector_factory=lambda **_kwargs: connection,
            socket_factory=_passive_socket_factory,
        )

        connected = worker._connect_interruptibly({"host": "router.example.net", "port": 22})

        self.assertIs(connected, connection)
        self.assertFalse(connected.ansi_escape_codes)
        worker.stop()

    def test_timing_reads_have_a_deadline_and_retained_output_is_bounded(self):
        class TimingConnection:
            base_prompt = "router"

            def __init__(self):
                self.kwargs = None

            def send_command_timing(self, _command, **kwargs):
                self.kwargs = kwargs
                return "A" * 1_000 + "\n[confirm]"

        connection = TimingConnection()
        worker = clidarvi_workers.AutomationWorker([], "write memory")

        with patch.object(clidarvi_workers, "MAX_COMMAND_RESPONSE_CHARS", 200):
            with self.assertRaisesRegex(
                clidarvi_workers.CommandExecutionError,
                "repeated",
            ):
                # The confirmation response is deliberately identical, proving
                # the bounded tail remains visible to prompt policy.
                worker._execute_command(
                    connection,
                    "write memory",
                    {"device_type": "cisco_ios"},
                )

        self.assertEqual(
            connection.kwargs["read_timeout"],
            clidarvi_workers.COMMAND_READ_TIMEOUT_SECONDS,
        )

    def test_full_response_error_is_checked_before_retention_truncation(self):
        class ErrorInMiddleConnection:
            base_prompt = "router"

            def send_command_timing(self, _command, **_kwargs):
                return (
                    "A" * 400 + "\n% Invalid input detected at marker\n" + "Z" * 400 + "\nrouter#"
                )

        worker = clidarvi_workers.AutomationWorker([], "show version")
        with patch.object(clidarvi_workers, "MAX_COMMAND_RESPONSE_CHARS", 120):
            with self.assertRaises(clidarvi_workers.CommandExecutionError):
                worker._execute_command(
                    ErrorInMiddleConnection(),
                    "show version",
                    {"device_type": "cisco_ios"},
                )

    def test_full_response_is_redacted_before_retention_cut(self):
        secret = "PRIVATE-MATERIAL-DO-NOT-RETAIN"  # pragma: allowlist secret
        key_label = "PRIVATE KEY"

        class KeyBlockConnection:
            base_prompt = "router"

            def send_command_timing(self, _command, **_kwargs):
                return (
                    f"prefix\n-----BEGIN {key_label}-----\n"
                    + (secret * 30)
                    + f"\n-----END {key_label}-----\n"
                    + ("tail" * 80)
                    + "\nrouter#"
                )

        worker = clidarvi_workers.AutomationWorker([], "write memory")
        with patch.object(clidarvi_workers, "MAX_COMMAND_RESPONSE_CHARS", 120):
            responses, _classification = worker._execute_command(
                KeyBlockConnection(),
                "write memory",
                {"device_type": "cisco_ios"},
            )

        retained = responses[0][1]
        self.assertLessEqual(len(retained), 120)
        self.assertNotIn(secret, retained)
        self.assertNotIn(f"BEGIN {key_label}", retained)
        self.assertIn("<redacted block>", retained)

    def test_control_in_earlier_output_blocks_final_confirmation(self):
        class ControlledResponseConnection(_SuccessfulConnection):
            def __init__(self):
                super().__init__()
                self.calls = 0

            def send_command_timing(self, _command, **_kwargs):
                self.calls += 1
                return "ordinary\u2060 output\n[confirm]"

        connection = ControlledResponseConnection()
        worker = clidarvi_workers.AutomationWorker([], "write memory")
        with self.assertRaisesRegex(clidarvi_workers.CommandExecutionError, "prompt blocked"):
            worker._execute_command(
                connection,
                "write memory",
                {"device_type": "cisco_ios"},
            )
        self.assertEqual(connection.calls, 1)
        self.assertTrue(connection.remote_conn.closed)

    def test_terminal_string_cannot_hide_prompt_and_receive_next_queued_command(self):
        class HiddenPromptConnection(_SuccessfulConnection):
            def __init__(self):
                super().__init__()
                self.commands = []

            def send_command_timing(self, command, **_kwargs):
                self.commands.append(command)
                return "\x1b]0;hidden\n[confirm]"

        connection = HiddenPromptConnection()
        worker = clidarvi_workers.AutomationWorker(
            [
                {
                    "device_type": "cisco_ios",
                    "host": "router.example.net",
                    "username": "admin",
                    "password": bytearray(b"password"),
                    **_AUTOMATION_HOST_KEY_POLICY,
                }
            ],
            "write memory\nhostname must-not-run",
            connector_factory=lambda **_kwargs: connection,
            socket_factory=_passive_socket_factory,
        )

        transcript = worker._run_devices()

        self.assertTrue(worker.had_error())
        self.assertEqual(connection.commands, ["write memory"])
        self.assertIn("terminal-control response", transcript)
        self.assertTrue(connection.remote_conn.closed)

    def test_long_directive_prompt_cannot_receive_next_queued_command(self):
        hidden_prompts = (
            "Continue " + ("x" * 129),
            "Enter " + ("x" * 129),
            "[" + ("a" * 129) + "/b]:",
            "(" + ("a" * 65) + "/b):",
            "[" * 100_000,
        )
        for hidden_prompt in hidden_prompts:
            with self.subTest(prefix=hidden_prompt.split()[0]):

                class LongPromptConnection(_SuccessfulConnection):
                    def __init__(self, response):
                        super().__init__()
                        self.response = response
                        self.commands = []

                    def send_command_timing(self, command, **_kwargs):
                        self.commands.append(command)
                        return self.response

                connection = LongPromptConnection(hidden_prompt)
                worker = clidarvi_workers.AutomationWorker(
                    [
                        {
                            "device_type": "cisco_ios",
                            "host": "router.example.net",
                            "username": "admin",
                            "password": bytearray(b"password"),
                            **_AUTOMATION_HOST_KEY_POLICY,
                        }
                    ],
                    "write memory\nhostname must-not-run",
                    connector_factory=lambda **_kwargs: connection,
                    socket_factory=_passive_socket_factory,
                )

                worker._run_devices()

                self.assertTrue(worker.had_error())
                self.assertEqual(connection.commands, ["write memory"])
                self.assertTrue(connection.remote_conn.closed)

    def test_unverified_timing_completion_cannot_receive_next_queued_command(self):
        ambiguous_responses = (
            "",
            "Password for admin:",
            "Please confirm",
            "Input value:",
            "partial command output",
            "different-router#",
        )
        for ambiguous_response in ambiguous_responses:
            with self.subTest(response=ambiguous_response):

                class AmbiguousConnection(_SuccessfulConnection):
                    base_prompt = "router"

                    def __init__(self, response):
                        super().__init__()
                        self.response = response
                        self.commands = []

                    def send_command_timing(self, command, **_kwargs):
                        self.commands.append(command)
                        return self.response

                connection = AmbiguousConnection(ambiguous_response)
                worker = clidarvi_workers.AutomationWorker(
                    [
                        {
                            "device_type": "cisco_ios",
                            "host": "router.example.net",
                            "username": "admin",
                            "password": bytearray(b"password"),
                            **_AUTOMATION_HOST_KEY_POLICY,
                        }
                    ],
                    "write memory\nhostname must-not-run",
                    connector_factory=lambda **_kwargs: connection,
                    socket_factory=_passive_socket_factory,
                )

                worker._run_devices()

                self.assertTrue(worker.had_error())
                self.assertEqual(connection.commands, ["write memory"])
                self.assertTrue(connection.remote_conn.closed)

        verifier = clidarvi_workers.AutomationWorker([], "write memory")
        verified_connection = type("Connection", (), {"base_prompt": "router"})()
        self.assertTrue(verifier._has_verified_cli_prompt(verified_connection, "router#"))
        self.assertTrue(
            verifier._has_verified_cli_prompt(verified_connection, "saved\nrouter(config)#")
        )

    def test_cli_prompt_requires_exact_base_and_mode_suffix_grammar(self):
        verifier = clidarvi_workers.AutomationWorker([], "write memory")
        samples = (
            ("router", "router#", True),
            ("router", "router(config-if-range)#", True),
            ("FGT", "FGT (root) #", True),
            ("(Cisco Controller)", "(Cisco Controller) >", True),
            ("admin@PA", "admin@PA>", True),
            ("#", "#", True),
            ("router", "routerevil#", False),
            ("router", "router Please confirm#", False),
            ("router", "router(config)#junk#", False),
            ("router", "router(config)(nested(test))#", False),
            ("", "router#", False),
        )

        for base_prompt, response, expected in samples:
            with self.subTest(base_prompt=base_prompt, response=response):
                connection = type("Connection", (), {"base_prompt": base_prompt})()
                self.assertEqual(
                    verifier._has_verified_cli_prompt(connection, response),
                    expected,
                )

        truncated = type("Connection", (), {"base_prompt": "abcdefghijklmnop"})()
        self.assertTrue(
            verifier._has_verified_cli_prompt(
                truncated,
                "output\nabcdefghijklmnopqrstuvwxyz0123456789#",
                "cisco_ios",
            )
        )
        self.assertTrue(
            verifier._has_verified_cli_prompt(
                truncated,
                "output\nabcdefghijklmnop(config-if)#",
                "cisco_ios",
            )
        )
        self.assertFalse(
            verifier._has_verified_cli_prompt(
                truncated,
                "output\nabcdefghijklmnop Please confirm#",
                "cisco_ios",
            )
        )
        self.assertFalse(
            verifier._has_verified_cli_prompt(
                truncated,
                "output\nabcdefghijklmnopqrstuvwxyz0123456789#",
                "arista_eos",
            )
        )

    def test_empty_base_prompt_aborts_before_any_automation_command(self):
        class EmptyPromptConnection(_SuccessfulConnection):
            base_prompt = ""

            def __init__(self):
                super().__init__()
                self.commands = []
                self.enable_calls = 0

            def send_command(self, command, **_kwargs):
                self.commands.append(command)
                return "must not run"

            def enable(self):
                self.enable_calls += 1

        connection = EmptyPromptConnection()
        worker = clidarvi_workers.AutomationWorker(
            [
                {
                    "device_type": "cisco_ios",
                    "host": "router.example.net",
                    "username": "admin",
                    "password": bytearray(b"password"),
                    **_AUTOMATION_HOST_KEY_POLICY,
                }
            ],
            "show version",
            connector_factory=lambda **_kwargs: connection,
            socket_factory=_passive_socket_factory,
        )

        transcript = worker._run_devices()

        self.assertTrue(worker.had_error())
        self.assertEqual(connection.commands, [])
        self.assertEqual(connection.enable_calls, 0)
        self.assertTrue(connection.remote_conn.closed)
        self.assertIn("validated non-empty base prompt", transcript)

    def test_sanitized_diagnostics_have_an_independent_total_cap(self):
        secret = "uri-secret"  # pragma: allowlist secret
        raw = f"https://user:{secret}@host/" + ("x" * 20_000)
        safe = clidarvi_workers._redact_sensitive_text(raw)
        self.assertLessEqual(len(safe), clidarvi_workers.MAX_DIAGNOSTIC_CHARS)
        self.assertNotIn(secret, safe)
        self.assertTrue(safe.endswith("...[diagnostic truncated]"))

    def test_blocking_network_wait_is_cancellable(self):
        stop_event = threading.Event()
        operation_started = threading.Event()
        release_operation = threading.Event()

        def operation():
            operation_started.set()
            release_operation.wait(2)
            return object()

        timer = threading.Timer(0.02, stop_event.set)
        timer.start()
        try:
            with self.assertRaises(ConnectionAbortedError):
                clidarvi_workers._run_interruptibly(
                    operation,
                    stop_event=stop_event,
                    timeout=1,
                )
        finally:
            release_operation.set()
            timer.cancel()
        self.assertTrue(operation_started.is_set())

    def test_late_network_result_is_closed_after_cancellation(self):
        class Resource:
            def __init__(self):
                self.cleaned = threading.Event()

        resource = Resource()
        stop_event = threading.Event()
        release_operation = threading.Event()

        def operation():
            release_operation.wait(2)
            return resource

        timer = threading.Timer(0.02, stop_event.set)
        timer.start()
        try:
            with self.assertRaises(ConnectionAbortedError):
                clidarvi_workers._run_interruptibly(
                    operation,
                    stop_event=stop_event,
                    timeout=1,
                    late_result_cleanup=lambda result: result.cleaned.set(),
                )
        finally:
            release_operation.set()
            timer.cancel()
        self.assertTrue(resource.cleaned.wait(1))

    def test_result_dequeued_after_stop_is_cleaned_and_never_returned(self):
        for _iteration in range(100):
            stop_event = threading.Event()
            cleanup_calls = []
            cleanup_finished = threading.Event()
            resource = object()

            def operation():
                stop_event.set()
                return resource

            def cleanup(value):
                cleanup_calls.append(value)
                cleanup_finished.set()

            with self.assertRaises(ConnectionAbortedError):
                clidarvi_workers._run_interruptibly(
                    operation,
                    stop_event=stop_event,
                    timeout=1,
                    late_result_cleanup=cleanup,
                )
            self.assertTrue(cleanup_finished.wait(1))
            self.assertEqual(cleanup_calls, [resource])

    def test_ssh_socket_rejects_an_oversized_pre_banner_line(self):
        class StreamSocket:
            def __init__(self, payload):
                self.payload = bytearray(payload)
                self.closed = False

            def recv(self, size, _flags=0):
                chunk = bytes(self.payload[:size])
                del self.payload[:size]
                return chunk

            def close(self):
                self.closed = True

        raw = StreamSocket(b"X" * 17)
        wrapped = clidarvi_workers._BoundedSSHSocket(raw, stop_event=threading.Event())
        with patch.object(clidarvi_workers, "MAX_SSH_IDENTIFICATION_LINE_BYTES", 16):
            with self.assertRaises(clidarvi_workers.SSHPreBannerLimitError):
                wrapped.recv(1024)
        self.assertTrue(raw.closed)

    def test_ssh_socket_rejects_excessive_total_pre_banner_bytes(self):
        class StreamSocket:
            def __init__(self, payload):
                self.payload = bytearray(payload)
                self.closed = False

            def recv(self, size, _flags=0):
                chunk = bytes(self.payload[:size])
                del self.payload[:size]
                return chunk

            def close(self):
                self.closed = True

        raw = StreamSocket(b"notice\n" * 8)
        wrapped = clidarvi_workers._BoundedSSHSocket(raw, stop_event=threading.Event())
        with (
            patch.object(clidarvi_workers, "MAX_SSH_IDENTIFICATION_LINE_BYTES", 16),
            patch.object(clidarvi_workers, "MAX_SSH_PRE_BANNER_BYTES", 24),
        ):
            with self.assertRaises(clidarvi_workers.SSHPreBannerLimitError):
                while True:
                    wrapped.recv(8)
        self.assertTrue(raw.closed)

    def test_ssh_socket_clamps_peer_controlled_huge_recv_request(self):
        class ChunkSocket:
            def __init__(self):
                self.chunks = [bytearray(b"SSH-2.0-test\r\n"), bytearray(b"payload")]
                self.requested_sizes = []

            def recv(self, size, _flags=0):
                self.requested_sizes.append(size)
                if not self.chunks:
                    return b""
                chunk = self.chunks[0]
                result = bytes(chunk[:size])
                del chunk[:size]
                if not chunk:
                    self.chunks.pop(0)
                return result

            def close(self):
                return None

        raw = ChunkSocket()
        wrapped = clidarvi_workers._BoundedSSHSocket(raw, stop_event=threading.Event())

        self.assertEqual(wrapped.recv(2**32 - 1), b"SSH-2.0-test\r\n")
        self.assertEqual(wrapped.recv(2**32 - 1), b"payload")

        self.assertLessEqual(
            raw.requested_sizes[0],
            clidarvi_workers.MAX_SSH_IDENTIFICATION_LINE_BYTES + 1,
        )
        self.assertEqual(
            raw.requested_sizes[1],
            clidarvi_workers.MAX_SSH_SOCKET_RECV_BYTES,
        )

    def test_ssh_socket_counts_post_banner_bytes_from_identification_recv(self):
        class StreamSocket:
            def __init__(self):
                self.payload = bytearray(b"SSH-2.0-test\r\n" + b"A" * 9)
                self.closed = False

            def recv(self, size, _flags=0):
                chunk = bytes(self.payload[:size])
                del self.payload[:size]
                return chunk

            def close(self):
                self.closed = True

        raw = StreamSocket()
        wrapped = clidarvi_workers._BoundedSSHSocket(
            raw,
            stop_event=threading.Event(),
            max_post_banner_bytes=8,
        )

        with self.assertRaises(clidarvi_workers.SSHReceiveLimitError):
            wrapped.recv(2**32 - 1)

        self.assertTrue(raw.closed)

    def test_paramiko_packetizer_huge_declared_packet_hits_receive_limit(self):
        packet_size = 2**31 + 4

        class DeclaredPacketSocket:
            def __init__(self):
                self.chunks = [
                    bytearray(b"SSH-2.0-test\r\n"),
                    bytearray(packet_size.to_bytes(4, "big") + b"\x04\x00\x00\x00"),
                ]
                self.requested_sizes = []
                self.closed = False

            def recv(self, size, _flags=0):
                self.requested_sizes.append(size)
                if self.chunks:
                    chunk = self.chunks[0]
                    result = bytes(chunk[:size])
                    del chunk[:size]
                    if not chunk:
                        self.chunks.pop(0)
                    return result
                return b"\x00" * size

            def close(self):
                self.closed = True

        raw = DeclaredPacketSocket()
        wrapped = clidarvi_workers._BoundedSSHSocket(
            raw,
            stop_event=threading.Event(),
            max_post_banner_bytes=64,
        )
        self.assertEqual(wrapped.recv(1024), b"SSH-2.0-test\r\n")
        packetizer = paramiko.Packetizer(wrapped)

        with self.assertRaises(clidarvi_workers.SSHReceiveLimitError):
            packetizer.read_message()

        self.assertTrue(raw.closed)
        self.assertTrue(wrapped.receive_limit_exceeded())
        self.assertLessEqual(
            max(raw.requested_sizes),
            clidarvi_workers.MAX_SSH_SOCKET_RECV_BYTES,
        )

    def test_automation_socket_enforces_cumulative_post_banner_limit(self):
        class ChunkSocket:
            def __init__(self):
                self.chunks = [
                    bytearray(b"SSH-2.0-test\r\n"),
                    bytearray(b"ABCD"),
                    bytearray(b"EFGH"),
                    bytearray(b"I"),
                ]
                self.requested_sizes = []
                self.closed = False

            def recv(self, size, _flags=0):
                self.requested_sizes.append(size)
                chunk = self.chunks[0]
                result = bytes(chunk[:size])
                del chunk[:size]
                if not chunk:
                    self.chunks.pop(0)
                return result

            def close(self):
                self.closed = True

        raw = ChunkSocket()

        def connector(**params):
            bounded = params["sock"]
            self.assertEqual(bounded.recv(2**32 - 1), b"SSH-2.0-test\r\n")
            self.assertEqual(bounded.recv(2**32 - 1), b"ABCD")
            self.assertEqual(bounded.recv(2**32 - 1), b"EFGH")
            bounded.recv(2**32 - 1)

        worker = clidarvi_workers.AutomationWorker(
            [],
            "show version",
            connector_factory=connector,
            socket_factory=lambda _host, _port, *, stop_event: raw,
        )
        with (
            patch.object(clidarvi_workers, "MAX_AUTOMATION_SSH_POST_BANNER_BYTES", 8),
            self.assertRaises(clidarvi_workers.SSHReceiveLimitError),
        ):
            worker._connect_interruptibly({"host": "router.example.net", "port": 22})

        self.assertTrue(raw.closed)
        self.assertEqual(raw.requested_sizes[-3:], [9, 5, 1])

    def test_automation_stop_closes_constructor_socket_and_blocks_late_writes(self):
        class RecordingSocket:
            def __init__(self):
                self.closed = False
                self.sent = []

            def send(self, data, _flags=0):
                if self.closed:
                    raise OSError("closed")
                self.sent.append(bytes(data))
                return len(data)

            def sendall(self, data, _flags=0):
                self.send(data)

            def close(self):
                self.closed = True

        raw_socket = RecordingSocket()
        constructor_entered = threading.Event()
        allow_late_setup = threading.Event()
        late_write_blocked = threading.Event()
        connector_finished = threading.Event()

        def paused_connector(**params):
            sock = params["sock"]
            sock.send(b"pre-stop-auth")
            constructor_entered.set()
            allow_late_setup.wait(2)
            try:
                sock.send(b"post-stop-session-prep")
            except (ConnectionAbortedError, OSError):
                late_write_blocked.set()
            connector_finished.set()
            return _SuccessfulConnection()

        worker = clidarvi_workers.AutomationWorker(
            [],
            "show version",
            connector_factory=paused_connector,
            socket_factory=lambda _host, _port, *, stop_event: raw_socket,
        )
        failures = []

        def connect():
            try:
                worker._connect_interruptibly({"host": "router.example.net", "port": 22})
            except BaseException as exc:
                failures.append(exc)

        caller = threading.Thread(target=connect)
        caller.start()
        self.assertTrue(constructor_entered.wait(1))
        worker.stop()
        self.assertTrue(raw_socket.closed)
        allow_late_setup.set()
        self.assertTrue(connector_finished.wait(1))
        caller.join(1)

        self.assertFalse(caller.is_alive())
        self.assertTrue(late_write_blocked.is_set())
        self.assertEqual(raw_socket.sent, [b"pre-stop-auth"])
        self.assertTrue(any(isinstance(exc, ConnectionAbortedError) for exc in failures))

    def test_live_cli_yields_after_a_bounded_receive_batch(self):
        class FakeSocket:
            def close(self):
                return None

        class NoisyChannel:
            def __init__(self):
                self.recv_count = 0
                self.force_closed = False

            @property
            def closed(self):
                return self.force_closed or (
                    self.recv_count >= clidarvi_workers.MAX_LIVE_READ_CHUNKS_PER_TICK
                )

            def settimeout(self, _value):
                return None

            def send_ready(self):
                return False

            def recv_ready(self):
                return True

            def recv(self, _size):
                self.recv_count += 1
                return b"x"

            def exit_status_ready(self):
                return False

            def close(self):
                self.force_closed = True

        class Client:
            def __init__(self, channel):
                self.channel = channel

            def load_system_host_keys(self):
                return None

            def set_missing_host_key_policy(self, _policy):
                return None

            def connect(self, *_args, **_kwargs):
                return None

            def invoke_shell(self, **_kwargs):
                return self.channel

            def close(self):
                return None

        channel = NoisyChannel()
        worker = clidarvi_workers.InteractiveSSHWorker(
            "router.example.net",
            client_factory=lambda: Client(channel),
        )

        with (
            patch("clidarvi_workers.validate_host", return_value=True),
            patch("clidarvi_workers._open_tcp_connection", return_value=FakeSocket()),
        ):
            worker.run()

        self.assertEqual(
            channel.recv_count,
            clidarvi_workers.MAX_LIVE_READ_CHUNKS_PER_TICK,
        )

    def test_live_output_uses_one_wakeup_and_preserves_order(self):
        worker = clidarvi_workers.InteractiveSSHWorker("router.example.net")
        notifications = []
        worker.output_received.connect(notifications.append)

        self.assertTrue(worker._queue_output("first"))
        self.assertTrue(worker._queue_output("-second"))

        self.assertEqual(notifications, ["first"])
        self.assertEqual(worker.drain_output(), "first-second")
        self.assertEqual(worker.pending_output_chars(), 0)

    def test_live_output_overflow_aborts_without_silent_drop_or_reordering(self):
        class ClosingSocket:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

        worker = clidarvi_workers.InteractiveSSHWorker("router.example.net")
        connection = ClosingSocket()
        worker._socket = connection
        notifications = []
        worker.output_received.connect(notifications.append)

        with patch.object(clidarvi_workers, "MAX_LIVE_PENDING_OUTPUT_CHARS", 128):
            self.assertTrue(worker._queue_output("A" * 40))
            self.assertFalse(worker._queue_output("B" * 40))
            retained = worker.drain_output()

        self.assertEqual(len(notifications), 1)
        self.assertTrue(retained.startswith("A" * 40))
        self.assertNotIn("B", retained)
        self.assertIn("remote output queue safety limit reached", retained)
        self.assertLessEqual(len(retained), 128)
        self.assertTrue(worker._stop_event.is_set())
        self.assertTrue(connection.closed)

    def test_live_cli_partial_sends_preserve_every_input_byte(self):
        class FakeSocket:
            def close(self):
                return None

        class PartialSendChannel:
            def __init__(self, expected: bytes):
                self.expected = expected
                self.sent = bytearray()
                self.send_calls = 0
                self.force_closed = False

            @property
            def closed(self):
                return self.force_closed or bytes(self.sent) == self.expected

            def settimeout(self, _value):
                return None

            def send_ready(self):
                return True

            def send(self, data):
                self.send_calls += 1
                accepted = min(2, len(data))
                self.sent.extend(data[:accepted])
                return accepted

            def recv_ready(self):
                return False

            def exit_status_ready(self):
                return False

            def close(self):
                self.force_closed = True

        class Client:
            def __init__(self, channel):
                self.channel = channel

            def set_missing_host_key_policy(self, _policy):
                return None

            def connect(self, *_args, **_kwargs):
                return None

            def invoke_shell(self, **_kwargs):
                return self.channel

            def close(self):
                return None

        expected = b"show version\n"
        channel = PartialSendChannel(expected)
        worker = clidarvi_workers.InteractiveSSHWorker(
            "router.example.net",
            client_factory=lambda: Client(channel),
        )
        worker.send_input(expected.decode("ascii"))

        with (
            patch("clidarvi_workers.validate_host", return_value=True),
            patch("clidarvi_workers._open_tcp_connection", return_value=FakeSocket()),
        ):
            worker.run()

        self.assertEqual(bytes(channel.sent), expected)
        self.assertGreater(channel.send_calls, 1)

    def test_live_cli_does_not_inherit_system_known_hosts(self):
        class FakeSocket:
            def close(self):
                return None

        class ClosedChannel:
            closed = True

            def settimeout(self, _value):
                return None

            def exit_status_ready(self):
                return False

            def close(self):
                return None

        class Client:
            def __init__(self):
                self.system_loads = 0

            def load_system_host_keys(self):
                self.system_loads += 1

            def set_missing_host_key_policy(self, _policy):
                return None

            def connect(self, *_args, **_kwargs):
                return None

            def invoke_shell(self, **_kwargs):
                return ClosedChannel()

            def close(self):
                return None

        client = Client()
        worker = clidarvi_workers.InteractiveSSHWorker(
            "router.example.net",
            client_factory=lambda: client,
        )
        connected_events = []
        worker.connected.connect(lambda: connected_events.append("connected"))

        with (
            patch("clidarvi_workers.validate_host", return_value=True),
            patch("clidarvi_workers._open_tcp_connection", return_value=FakeSocket()),
        ):
            worker.run()

        self.assertEqual(client.system_loads, 0)
        self.assertEqual(connected_events, ["connected"])

    def test_live_cli_pins_verified_key_without_reopening_known_hosts(self):
        class FakeSocket:
            def close(self):
                return None

        class ClosedChannel:
            closed = True

            def settimeout(self, _value):
                return None

            def close(self):
                return None

        class Client:
            def __init__(self):
                self.host_keys = paramiko.HostKeys()
                self.path_loads = []
                self.connect_sock = None

            def get_host_keys(self):
                return self.host_keys

            def load_host_keys(self, path):
                self.path_loads.append(path)

            def set_missing_host_key_policy(self, _policy):
                return None

            def connect(self, *_args, **kwargs):
                self.connect_sock = kwargs["sock"]

            def invoke_shell(self, **_kwargs):
                return ClosedChannel()

            def close(self):
                return None

        key = paramiko.RSAKey.generate(1024)
        client = Client()
        worker = clidarvi_workers.InteractiveSSHWorker(
            "router.example.net",
            known_hosts_path="/path/must/not/be/reopened",
            verified_server_key=key,
            client_factory=lambda: client,
        )

        with (
            patch("clidarvi_workers.validate_host", return_value=True),
            patch("clidarvi_workers._open_tcp_connection", return_value=FakeSocket()),
        ):
            worker.run()

        stored = client.host_keys.lookup("router.example.net")
        self.assertIsNotNone(stored)
        self.assertEqual(stored[key.get_name()], key)
        self.assertEqual(client.path_loads, [])
        self.assertIsInstance(client.connect_sock, clidarvi_workers._BoundedSSHSocket)
        self.assertEqual(
            client.connect_sock._max_post_banner_bytes,
            clidarvi_workers.MAX_LIVE_SSH_POST_BANNER_BYTES,
        )

    def test_live_cli_receive_limit_is_visible_and_reopenable(self):
        class StreamSocket:
            def __init__(self):
                self.chunks = [
                    bytearray(b"SSH-2.0-test\r\n"),
                    bytearray(b"A" * 9),
                ]
                self.closed = False

            def recv(self, size, _flags=0):
                chunk = self.chunks[0]
                result = bytes(chunk[:size])
                del chunk[:size]
                if not chunk:
                    self.chunks.pop(0)
                return result

            def close(self):
                self.closed = True

        class Client:
            def set_missing_host_key_policy(self, _policy):
                return None

            def connect(self, *_args, **kwargs):
                sock = kwargs["sock"]
                self.assertEqual(sock.recv(1024), b"SSH-2.0-test\r\n")
                sock.recv(1024)

            def close(self):
                return None

        raw = StreamSocket()
        client = Client()
        client.assertEqual = self.assertEqual
        worker = clidarvi_workers.InteractiveSSHWorker(
            "router.example.net",
            client_factory=lambda: client,
        )

        with (
            patch("clidarvi_workers.validate_host", return_value=True),
            patch("clidarvi_workers._open_tcp_connection", return_value=raw),
            patch.object(clidarvi_workers, "MAX_LIVE_SSH_POST_BANNER_BYTES", 8),
        ):
            worker.run()

        retained = worker.drain_output()
        self.assertTrue(raw.closed)
        self.assertTrue(worker._stop_event.is_set())
        self.assertIn("receive safety quota was reached", retained)
        self.assertIn("Reopen the session", retained)
        self.assertNotIn("AAAAAAAAA", retained)

    def test_oversized_live_cli_paste_is_rejected_not_partially_sent(self):
        worker = clidarvi_workers.InteractiveSSHWorker("router.example.net")
        messages = []
        worker.output_received.connect(messages.append)

        worker.send_input("x" * (clidarvi_workers.MAX_LIVE_INPUT_CHUNK_BYTES + 1))

        self.assertTrue(worker._input_queue.empty())
        self.assertTrue(any("rejected" in message for message in messages))


if __name__ == "__main__":
    unittest.main()
