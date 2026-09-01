# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 devnetdreamer (https://github.com/devnetdreamer) and Clidarvi contributors

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import Mock, patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import paramiko
from PyQt6.QtCore import QEvent, QPoint, Qt, QUrl
from PyQt6.QtGui import QIcon, QKeyEvent, QPixmap
from PyQt6.QtWidgets import QApplication, QTreeWidgetItem

import clidarvi
import clidarvi_workers


class _FakeConnection:
    def __init__(self, parameters):
        self.parameters = parameters
        self.base_prompt = "router"
        self.saved = False
        self.enabled = False
        self.disconnected = False
        self.timing_inputs = []

    def __enter__(self):
        return self

    def __exit__(self, _kind, _value, _traceback):
        self.disconnect()

    def disconnect(self):
        self.disconnected = True

    def send_command(self, command, **_kwargs):
        return f"{command}\nVersion 1\nrouter#"

    def send_command_timing(self, command, **_kwargs):
        self.timing_inputs.append(command)
        return f"{command}\nVersion 1\nrouter#"

    def enable(self):
        self.enabled = True
        return ""

    def check_config_mode(self):
        return False

    def save_config(self):
        self.saved = True
        return "saved"


class _TimingConnection(_FakeConnection):
    def __init__(self, responses):
        super().__init__({})
        self.responses = iter(responses)

    def send_command_timing(self, command, **_kwargs):
        self.timing_inputs.append(command)
        return next(self.responses)


class _FakeConnector:
    def __init__(self):
        self.connections = []

    def __call__(self, **parameters):
        connection = _FakeConnection(parameters)
        self.connections.append(connection)
        return connection


class _PassiveSocket:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def _passive_socket_factory(_host, _port, *, stop_event):
    del stop_event
    return _PassiveSocket()


_AUTOMATION_HOST_KEY_POLICY = {
    "ssh_strict": True,
    "system_host_keys": False,
    "alt_host_keys": True,
    "alt_key_file": "/tmp/test-known-hosts",
}


class _TerminalWorker:
    def __init__(self):
        self.inputs = []
        self.sizes = []

    def send_input(self, value):
        self.inputs.append(value)

    def resize_terminal(self, width, height):
        self.sizes.append((width, height))


class AutomationWorkerTests(unittest.TestCase):
    def test_command_error_markers_are_anchored_to_error_lines(self):
        worker = clidarvi.AutomationWorker([], "show version")

        self.assertTrue(worker._contains_command_error("router#\n% Invalid input detected"))
        self.assertFalse(
            worker._contains_command_error(
                "Banner documentation: an invalid command should be reported to support."
            )
        )

    def test_password_whitespace_and_strict_hostkey_options_reach_connector(self):
        connector = _FakeConnector()
        password = bytearray(b" leading and trailing ")
        device = {
            "device_type": "cisco_ios",
            "host": "router.example.net",
            "username": "admin",
            "password": password,
            "port": 22,
            "ssh_strict": True,
            "system_host_keys": False,
            "alt_host_keys": True,
            "alt_key_file": "/tmp/test-known-hosts",
            "use_keys": True,
            "allow_agent": True,
            "key_file": "/tmp/should-not-be-used",
            "pkey": object(),
            "passphrase": "should-not-be-used",  # pragma: allowlist secret
            "secret": "should-not-be-used",  # pragma: allowlist secret
            "ssh_config_file": "/tmp/should-not-be-used-config",
        }
        worker = clidarvi.AutomationWorker(
            [device],
            "show version",
            connector_factory=connector,
            socket_factory=_passive_socket_factory,
        )
        forbidden_options = ("key_file", "pkey", "passphrase", "secret", "ssh_config_file")
        for forbidden in forbidden_options:
            self.assertNotIn(forbidden, worker.devices[0])

        transcript = worker._run_devices()

        parameters = connector.connections[0].parameters
        self.assertEqual(parameters["password"], " leading and trailing ")
        self.assertTrue(parameters["ssh_strict"])
        self.assertTrue(parameters["alt_host_keys"])
        self.assertFalse(parameters["use_keys"])
        self.assertFalse(parameters["allow_agent"])
        self.assertEqual(parameters["encoding"], "latin-1")
        self.assertFalse(connector.connections[0].ansi_escape_codes)
        for forbidden in forbidden_options:
            self.assertNotIn(forbidden, parameters)
        self.assertIn("ssh-rsa", parameters["disabled_algorithms"]["keys"])
        self.assertIn("diffie-hellman-group1-sha1", parameters["disabled_algorithms"]["kex"])
        self.assertIn("3des-cbc", parameters["disabled_algorithms"]["ciphers"])
        self.assertIn("aes256-cbc", parameters["disabled_algorithms"]["ciphers"])
        self.assertIsInstance(parameters["sock"], clidarvi_workers._BoundedSSHSocket)
        self.assertIn("Version 1", transcript)
        self.assertEqual(password, bytearray(len(password)))

    def test_sensitive_commands_are_redacted_without_implicit_save(self):
        connector = _FakeConnector()
        device = {
            "device_type": "cisco_ios",
            "host": "router.example.net",
            "username": "admin",
            "password": bytearray(b"password"),
            **_AUTOMATION_HOST_KEY_POLICY,
        }
        worker = clidarvi.AutomationWorker(
            [device],
            "username admin secret swordfish",
            connector_factory=connector,
            socket_factory=_passive_socket_factory,
        )

        transcript = worker._run_devices()

        self.assertFalse(connector.connections[0].saved)
        self.assertNotIn("swordfish", transcript)
        self.assertIn("<redacted>", transcript)

    def test_imported_telnet_device_type_never_reaches_connector(self):
        connector = _FakeConnector()
        password = bytearray(b"secret")
        with self.assertRaisesRegex(ValueError, "Unsupported device_type"):
            clidarvi.AutomationWorker(
                [
                    {
                        "device_type": "cisco_ios_telnet",
                        "host": "router.example.net",
                        "username": "admin",
                        "password": password,
                    }
                ],
                "show version",
                connector_factory=connector,
                socket_factory=_passive_socket_factory,
            )

        self.assertFalse(connector.connections)
        self.assertEqual(password, bytearray(b"secret"))

    def test_repeated_and_unrecognized_prompts_abort_the_command(self):
        worker = clidarvi.AutomationWorker([], "write memory")
        repeated = _TimingConnection(["[confirm]", "[confirm]"])
        empty_after_reply = _TimingConnection(["[confirm]", ""])
        unknown = _TimingConnection(["Select target [primary/secondary]:"])

        with self.assertRaisesRegex(clidarvi.CommandExecutionError, "repeated"):
            worker._execute_command(repeated, "write memory", {"device_type": "cisco_ios"})
        with self.assertRaisesRegex(clidarvi.CommandExecutionError, "outcome is unknown"):
            worker._execute_command(
                empty_after_reply,
                "write memory",
                {"device_type": "cisco_ios"},
            )
        with self.assertRaisesRegex(clidarvi.CommandExecutionError, "unrecognized"):
            worker._execute_command(unknown, "write memory", {"device_type": "cisco_ios"})

    def test_device_transcript_truncates_at_the_documented_bound(self):
        class _VerboseConnection(_FakeConnection):
            def send_command_timing(self, command, **_kwargs):
                return f"{command}\n" + "output-line " * 40 + "\nrouter#"

        class _VerboseConnector(_FakeConnector):
            def __call__(self, **parameters):
                connection = _VerboseConnection(parameters)
                self.connections.append(connection)
                return connection

        device = {
            "device_type": "cisco_ios",
            "host": "router.example.net",
            "username": "admin",
            "password": bytearray(b"password"),
            **_AUTOMATION_HOST_KEY_POLICY,
        }
        worker = clidarvi.AutomationWorker(
            [device],
            "show version",
            connector_factory=_VerboseConnector(),
            socket_factory=_passive_socket_factory,
        )

        with patch.object(clidarvi_workers, "MAX_DEVICE_TRANSCRIPT_CHARS", 120):
            transcript = worker._run_devices()

        self.assertIn("...[device transcript truncated]", transcript)
        marker_free = transcript.replace("...[device transcript truncated]", "")
        self.assertLessEqual(len(marker_free.strip()), 120 + len("\n"))

    def test_total_transcript_truncates_and_always_carries_the_marker(self):
        class _VerboseConnection(_FakeConnection):
            def send_command_timing(self, command, **_kwargs):
                return f"{command}\n" + "x" * 200 + "\nrouter#"

        class _VerboseConnector(_FakeConnector):
            def __call__(self, **parameters):
                connection = _VerboseConnection(parameters)
                self.connections.append(connection)
                return connection

        devices = [
            {
                "device_type": "cisco_ios",
                "host": f"router-{index}.example.net",
                "username": "admin",
                "password": bytearray(b"password"),
                **_AUTOMATION_HOST_KEY_POLICY,
            }
            for index in range(3)
        ]
        worker = clidarvi.AutomationWorker(
            devices,
            "show version",
            connector_factory=_VerboseConnector(),
            socket_factory=_passive_socket_factory,
        )

        with patch.object(clidarvi_workers, "MAX_TOTAL_TRANSCRIPT_CHARS", 150):
            transcript = worker._run_devices()

        self.assertIn("...[total transcript truncated]", transcript)
        payload = transcript.replace("\n...[total transcript truncated]", "")
        self.assertLessEqual(len(payload), 150)

    def test_blocked_prompt_kills_the_transport_before_raising(self):
        class _TrackingChannel:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

        connection = _TimingConnection(["Select target [primary/secondary]:"])
        connection.remote_conn = _TrackingChannel()
        connection.remote_conn_pre = _TrackingChannel()
        worker = clidarvi.AutomationWorker([], "write memory")

        with self.assertRaisesRegex(clidarvi.CommandExecutionError, "unrecognized"):
            worker._execute_command(connection, "write memory", {"device_type": "cisco_ios"})

        self.assertTrue(connection.remote_conn.closed)
        self.assertTrue(connection.remote_conn_pre.closed)
        self.assertNotIn("exit", connection.timing_inputs[1:])

    def test_stop_kills_transports_without_calling_graceful_disconnect(self):
        class _TrackingChannel:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

        connection = _FakeConnection({})
        connection.remote_conn = _TrackingChannel()
        connection.remote_conn_pre = _TrackingChannel()
        worker = clidarvi.AutomationWorker([], "show version")
        worker._active_connections.add(connection)

        worker.stop()

        self.assertTrue(worker.was_stopped())
        self.assertTrue(connection.remote_conn.closed)
        self.assertTrue(connection.remote_conn_pre.closed)
        self.assertFalse(connection.disconnected)

    def test_cancellation_never_sends_a_pending_automatic_reply(self):
        class _TrackingChannel:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

        worker = clidarvi.AutomationWorker([], "write memory")
        connection = _TimingConnection([])
        connection.remote_conn = _TrackingChannel()
        connection.remote_conn_pre = _TrackingChannel()

        def first_response(command, **_kwargs):
            connection.timing_inputs.append(command)
            worker._stop_event.set()
            return "[confirm]"

        connection.send_command_timing = first_response

        with self.assertRaisesRegex(clidarvi.CommandExecutionError, "cancelled"):
            worker._execute_command(connection, "write memory", {"device_type": "cisco_ios"})

        self.assertEqual(connection.timing_inputs, ["write memory"])
        self.assertTrue(connection.remote_conn.closed)
        self.assertTrue(connection.remote_conn_pre.closed)

    def test_command_exception_aborts_transport_before_context_exit(self):
        class _TrackingChannel:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

        class _FailingConnection(_FakeConnection):
            def __init__(self, parameters):
                super().__init__(parameters)
                self.remote_conn = _TrackingChannel()
                self.remote_conn_pre = _TrackingChannel()
                self.graceful_writes = []

            def __exit__(self, _kind, _value, _traceback):
                if not self.remote_conn.closed:
                    self.graceful_writes.extend(["RETURN", "exit"])

            def send_command_timing(self, _command, **_kwargs):
                raise RuntimeError("simulated timing failure")

        connection = _FailingConnection({})
        worker = clidarvi.AutomationWorker(
            [
                {
                    "device_type": "cisco_ios",
                    "host": "router.example.net",
                    "username": "admin",
                    "password": bytearray(b"password"),
                    **_AUTOMATION_HOST_KEY_POLICY,
                }
            ],
            "hostname edge-router",
            connector_factory=lambda **_kwargs: connection,
            socket_factory=_passive_socket_factory,
        )

        transcript = worker._run_devices()

        self.assertTrue(worker.had_error())
        self.assertIn("simulated timing failure", transcript)
        self.assertTrue(connection.remote_conn.closed)
        self.assertTrue(connection.remote_conn_pre.closed)
        self.assertEqual(connection.graceful_writes, [])

    def test_library_managed_save_is_rejected_before_connection(self):
        connector = _FakeConnector()
        device = {
            "device_type": "cisco_ios",
            "host": "router.example.net",
            "username": "admin",
            "password": bytearray(b"password"),
        }
        with self.assertRaisesRegex(ValueError, "automatic save is disabled"):
            clidarvi.AutomationWorker(
                [device],
                "username admin secret swordfish",
                save_config=True,
                connector_factory=connector,
                socket_factory=_passive_socket_factory,
            )

        self.assertFalse(connector.connections)

    def test_library_managed_enable_is_rejected_before_connection(self):
        connector = _FakeConnector()
        device = {
            "device_type": "cisco_ios",
            "host": "router.example.net",
            "username": "admin",
            "password": bytearray(b"password"),
        }
        with self.assertRaisesRegex(ValueError, "enable mode is disabled"):
            clidarvi.AutomationWorker(
                [device],
                "hostname edge-router",
                enter_enable_mode=True,
                connector_factory=connector,
                socket_factory=_passive_socket_factory,
            )

        self.assertFalse(connector.connections)

    def test_approved_unknown_command_gets_change_safety_options(self):
        connector = _FakeConnector()
        worker = clidarvi.AutomationWorker(
            [
                {
                    "device_type": "cisco_ios",
                    "host": "router.example.net",
                    "username": "admin",
                    "password": bytearray(b"password"),
                    **_AUTOMATION_HOST_KEY_POLICY,
                }
            ],
            "frobnicate system",
            connector_factory=connector,
            socket_factory=_passive_socket_factory,
        )

        worker._run_devices()

        self.assertFalse(connector.connections[0].enabled)
        self.assertFalse(connector.connections[0].saved)

    def test_prestopped_interactive_worker_never_attempts_connection(self):
        class CountingClient:
            def __init__(self):
                self.connect_count = 0

            def connect(self, *_args, **_kwargs):
                self.connect_count += 1

            def close(self):
                return None

        client = CountingClient()
        worker = clidarvi.InteractiveSSHWorker(
            "does-not-need-to-resolve.invalid",
            client_factory=lambda: client,
        )

        worker.stop()
        worker.run()

        self.assertEqual(client.connect_count, 0)

    def test_interactive_worker_disables_legacy_ssh_algorithms(self):
        class FakeSocket:
            def close(self):
                return None

        class FakeChannel:
            closed = True

            def settimeout(self, _value):
                return None

            def recv_ready(self):
                return False

            def exit_status_ready(self):
                return False

            def close(self):
                return None

        class RecordingClient:
            def __init__(self):
                self.connect_kwargs = None

            def load_system_host_keys(self):
                return None

            def set_missing_host_key_policy(self, _policy):
                return None

            def connect(self, *_args, **kwargs):
                self.connect_kwargs = kwargs

            def invoke_shell(self, **_kwargs):
                return FakeChannel()

            def close(self):
                return None

        client = RecordingClient()
        worker = clidarvi.InteractiveSSHWorker(
            "router.example.net",
            client_factory=lambda: client,
        )

        with (
            patch("clidarvi_workers.validate_host", return_value=True),
            patch("clidarvi_workers.socket.create_connection", return_value=FakeSocket()),
        ):
            worker.run()

        self.assertIsNotNone(client.connect_kwargs)
        disabled = client.connect_kwargs["disabled_algorithms"]
        self.assertIn("ssh-rsa", disabled["pubkeys"])
        self.assertIn("hmac-md5", disabled["macs"])
        self.assertFalse(client.connect_kwargs["look_for_keys"])
        self.assertFalse(client.connect_kwargs["allow_agent"])

    def test_interactive_worker_rejects_key_and_agent_authentication(self):
        with self.assertRaisesRegex(ValueError, "unavailable in this alpha"):
            clidarvi.InteractiveSSHWorker("router.example.net", use_keys=True)

    def test_host_key_fetch_disables_legacy_ssh_algorithms(self):
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

        fake_socket = FakeSocket()
        fake_transport = FakeTransport()
        worker = clidarvi.HostKeyFetchWorker("router.example.net", 22)

        with (
            patch("clidarvi_workers.validate_host", return_value=True),
            patch("clidarvi_workers.socket.create_connection", return_value=fake_socket),
            patch("clidarvi_workers.paramiko.Transport", return_value=fake_transport) as factory,
        ):
            worker.run()

        disabled = factory.call_args.kwargs["disabled_algorithms"]
        self.assertIn("ssh-rsa", disabled["keys"])
        self.assertIn("diffie-hellman-group14-sha1", disabled["kex"])
        self.assertTrue(fake_socket.closed)


class MainWindowInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.application = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.data_path = Path(self.temporary_directory.name)
        self.data_patch = patch.object(
            clidarvi.MainWindow,
            "get_data_directory",
            return_value=self.data_path,
        )
        self.data_patch.start()
        self.window = clidarvi.MainWindow()

    def tearDown(self):
        self.window._shutdown_ready = True
        self.window.close()
        self.window.deleteLater()
        self.application.processEvents()
        self.data_patch.stop()
        self.temporary_directory.cleanup()

    def _risk_assets(
        self,
        *,
        terms_body="terms-v1\n",
        publisher="Clidarvi Test Publisher — publisher@example.invalid",
    ):
        asset_root = self.data_path / "release-assets"
        terms_text = (
            "# Test operational terms\n\n"
            f"**Terms ID:** `{clidarvi.RISK_TERMS_ID}`\n"
            f"**For application version:** `{clidarvi.__version__}`\n\n"
            f"**Publisher:** {publisher}\n\n"
            f"{terms_body}"
        )
        contents = {
            "TERMS.md": terms_text,
            "DISCLAIMER.md": "disclaimer-v1\n",
            "requirements-lock/runtime-py313.txt": "dependency==1.2.3 --hash=sha256:abc\n",
        }
        paths = {}
        for filename, content in contents.items():
            path = asset_root / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            paths[filename] = path

        def resolve(*names):
            for name in names:
                if name in paths:
                    path = paths[name]
                    return path, path.read_bytes()
            return None

        return paths, resolve

    @staticmethod
    def _accept_risk_dialog(dialog):
        for checkbox in dialog.acknowledgement_checkboxes:
            checkbox.setChecked(True)
        return clidarvi.QDialog.DialogCode.Accepted

    @staticmethod
    def _rendered_icon_signature(icon: QIcon, size: int = 20) -> tuple[int, ...]:
        """Compare what a user sees without relying on QIcon cache identity."""

        pixmap = icon.pixmap(size, size)
        if pixmap.isNull():
            return ()
        image = pixmap.toImage()
        return (
            image.width(),
            image.height(),
            *(image.pixel(x, y) for y in range(image.height()) for x in range(image.width())),
        )

    @staticmethod
    def _record_hash(payload: bytes) -> str:
        return base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()

    def _write_wheel_install_fixture(
        self,
        *,
        module_root: Path,
        asset_root: Path,
        record_native_root: Path,
    ) -> tuple[dict[str, Path], Path, Path]:
        """Create one complete synthetic installation with real RECORD ownership."""

        module_root.mkdir(parents=True, exist_ok=True)
        module_path = module_root / "clidarvi.py"
        module_payload = b'__version__ = "0.1.0a1"\n'
        module_path.write_bytes(module_payload)

        assets = {}
        asset_payloads = {}
        for asset_name in sorted(clidarvi._EXPECTED_WHEEL_ASSET_NAMES):
            asset_path = asset_root.joinpath(*asset_name.split("/"))
            asset_path.parent.mkdir(parents=True, exist_ok=True)
            payload = f"owned wheel asset: {asset_name}\n".encode()
            asset_path.write_bytes(payload)
            assets[asset_name] = asset_path
            asset_payloads[asset_name] = payload

        dist_info = module_root / f"clidarvi-{clidarvi.__version__}.dist-info"
        dist_info.mkdir()
        metadata_path = dist_info / "METADATA"
        metadata_payload = (
            f"Metadata-Version: 2.4\nName: clidarvi\nVersion: {clidarvi.__version__}\n\n"
        ).encode()
        metadata_path.write_bytes(metadata_payload)

        rows = []
        for asset_name in sorted(asset_payloads):
            record_asset = os.path.relpath(
                record_native_root.joinpath(*asset_name.split("/")),
                module_root,
            ).replace(os.sep, "/")
            payload = asset_payloads[asset_name]
            rows.append(f"{record_asset},sha256={self._record_hash(payload)},{len(payload)}\n")
        metadata_record = f"{dist_info.name}/METADATA"
        rows.extend(
            (
                f"{metadata_record},sha256={self._record_hash(metadata_payload)},"
                f"{len(metadata_payload)}\n",
                f"{dist_info.name}/RECORD,,\n",
                f"clidarvi.py,sha256={self._record_hash(module_payload)},{len(module_payload)}\n",
            )
        )
        (dist_info / "RECORD").write_text("".join(rows), encoding="utf-8")
        return assets, module_path, dist_info

    def _selector_index(self, *, kind: str, path: tuple[str, ...]) -> int:
        for index in range(self.window.selector.count()):
            data = self.window.selector.itemData(index)
            if not isinstance(data, dict):
                continue
            if data.get("kind") == kind and tuple(data.get("path", ())) == path:
                return index
        self.fail(f"Selector entry not found for {kind=} and {path=}")

    def test_first_launch_uses_synthetic_datacenter_sites_and_realistic_fqdns(self):
        expected_sites = (
            (
                "Alderhaven AMS-01 Data Campus",
                (
                    (
                        "AMS01-EDGE-RTR01",
                        "edge-rtr01.ams01.alderhaven.example",
                        "Cisco Router",
                        "cisco_ios",
                        "router",
                    ),
                    (
                        "AMS01-CORE-SW01",
                        "core-sw01.ams01.alderhaven.example",
                        "Cisco Switch",
                        "cisco_ios",
                        "switch",
                    ),
                    (
                        "AMS01-PERIM-FW01",
                        "perim-fw01.ams01.alderhaven.example",
                        "Palo Alto",
                        "paloalto_panos",
                        "firewall",
                    ),
                ),
            ),
            (
                "Rivermark RTM-01 Colocation Campus",
                (
                    (
                        "RTM01-EDGE-RTR01",
                        "edge-rtr01.rtm01.rivermark.example",
                        "Cisco Router",
                        "cisco_ios",
                        "router",
                    ),
                    (
                        "RTM01-CORE-SW01",
                        "core-sw01.rtm01.rivermark.example",
                        "Cisco Switch",
                        "cisco_ios",
                        "switch",
                    ),
                    (
                        "RTM01-PERIM-FW01",
                        "perim-fw01.rtm01.rivermark.example",
                        "Palo Alto",
                        "paloalto_panos",
                        "firewall",
                    ),
                ),
            ),
        )

        self.assertEqual(self.window.tree.topLevelItemCount(), len(expected_sites))
        self.assertEqual(
            self.window._site_placements_from_tree(),
            tuple(
                clidarvi.SitePlacement(
                    path=(site_name,),
                    site=clidarvi.SiteRecord(name=site_name, site_type="datacenter"),
                )
                for site_name, _devices in expected_sites
            ),
        )

        device_ids_by_label = {}
        visible_labels = []
        for site_index, (site_name, expected_devices) in enumerate(expected_sites):
            site_item = self.window.tree.topLevelItem(site_index)
            visible_labels.append(site_item.text(0))
            self.assertEqual(site_item.text(0), site_name)
            self.assertEqual(
                self.window._site_record_for_item(site_item),
                clidarvi.SiteRecord(name=site_name, site_type="datacenter"),
            )
            self.assertEqual(
                self._rendered_icon_signature(site_item.icon(0)),
                self._rendered_icon_signature(self.window._inventory_icons["datacenter_dark"]),
            )
            self.assertEqual(site_item.childCount(), len(expected_devices))

            for device_index, expected in enumerate(expected_devices):
                label, hostname, vendor, device_type, icon_role = expected
                device_item = site_item.child(device_index)
                visible_labels.append(device_item.text(0))
                record = clidarvi.DeviceRecord.from_mapping(
                    device_item.data(0, Qt.ItemDataRole.UserRole)
                )
                self.assertEqual(
                    (record.label, record.hostname, record.vendor, record.device_type),
                    (label, hostname, vendor, device_type),
                )
                self.assertTrue(record.hostname.endswith(".example"))
                self.assertTrue(record.id)
                self.assertNotIn(record.id, device_ids_by_label.values())
                device_ids_by_label[label] = record.id
                self.assertEqual(
                    self._rendered_icon_signature(device_item.icon(0)),
                    self._rendered_icon_signature(
                        self.window._inventory_icons[f"{icon_role}_dark"]
                    ),
                )

        self.assertEqual(len(device_ids_by_label), 6)
        self.assertTrue({"R1", "R2", "SW1", "SW2", "FW1"}.isdisjoint(visible_labels))

        snapshot = clidarvi.encode_inventory_document(
            self.window.tree_to_dict(),
            sites=self.window._site_placements_from_tree(),
        )
        self.window.restore_tree_state(snapshot)
        restored_ids = {
            node.text(0): clidarvi.DeviceRecord.from_mapping(
                node.data(0, Qt.ItemDataRole.UserRole)
            ).id
            for site_index in range(self.window.tree.topLevelItemCount())
            for node in (
                self.window.tree.topLevelItem(site_index).child(device_index)
                for device_index in range(self.window.tree.topLevelItem(site_index).childCount())
            )
        }
        self.assertEqual(restored_ids, device_ids_by_label)

    def test_redesigned_automation_page_renders_without_clipped_controls(self):
        self.window.show()
        self.application.processEvents()
        self.application.processEvents()

        for button in (
            self.window.back_btn,
            self.window.forward_btn,
            self.window.save_btn,
            self.window.import_btn,
            self.window.export_btn,
            self.window.new_device_btn,
            self.window.new_site_btn,
            self.window.add_btn,
            self.window.refresh_btn,
            self.window.stop_btn,
            self.window.run_btn,
        ):
            with self.subTest(button=button.text()):
                self.assertGreaterEqual(button.width(), button.minimumSizeHint().width())
                self.assertGreaterEqual(button.height(), button.minimumSizeHint().height())

        self.assertEqual(self.window.selector.focusPolicy(), Qt.FocusPolicy.StrongFocus)
        self.assertGreaterEqual(
            self.window.inventory_heading.width(),
            self.window.inventory_heading.minimumSizeHint().width(),
        )
        self.assertGreaterEqual(self.window.minimumHeight(), self.window.minimumSizeHint().height())
        screenshot = self.window.grab()
        self.assertFalse(screenshot.isNull())
        self.assertGreater(screenshot.width(), 1000)
        self.assertGreater(screenshot.height(), 650)

    def test_automation_and_cli_pages_both_render_offscreen(self):
        self.window.commands.setPlainText("show version")
        self.window.save_cb.setChecked(True)
        self.window.cli_btn.click()
        self.application.processEvents()
        self.application.processEvents()

        self.assertEqual(self.window.connect_btn.text(), "Connect selected")
        self.assertEqual(self.window.tabs.accessibleName(), "Live CLI session tabs")
        self.assertFalse(self.window.grab().isNull())

        self.window.automation_btn.click()
        self.application.processEvents()
        self.application.processEvents()

        self.assertEqual(self.window.run_btn.text(), "Run automation")
        self.assertEqual(self.window.commands.accessibleName(), "Command plan editor")
        self.assertEqual(self.window.commands.toPlainText(), "show version")
        self.assertTrue(self.window.save_cb.isChecked())
        self.assertFalse(self.window.grab().isNull())

    def test_mode_switch_requires_confirmation_before_closing_cli_sessions(self):
        class SessionWorker:
            def __init__(self):
                self.stopped = False

            def stop(self):
                self.stopped = True

        self.window.cli_btn.click()
        self.application.processEvents()
        worker = SessionWorker()
        session_marker = object()
        self.window.sessions[session_marker] = worker

        with patch.object(
            clidarvi.QMessageBox,
            "warning",
            return_value=clidarvi.QMessageBox.StandardButton.No,
        ):
            self.window.automation_btn.click()
            self.application.processEvents()

        self.assertTrue(self.window.cli_btn.isChecked())
        self.assertIn(session_marker, self.window.sessions)
        self.assertFalse(worker.stopped)

        with patch.object(
            clidarvi.QMessageBox,
            "warning",
            return_value=clidarvi.QMessageBox.StandardButton.Yes,
        ):
            self.window.automation_btn.click()
            self.application.processEvents()

        self.assertTrue(self.window.automation_btn.isChecked())
        self.assertFalse(self.window.sessions)
        self.assertTrue(worker.stopped)

    def test_closed_terminal_tab_releases_its_buffer_and_widget(self):
        self.window.cli_btn.click()
        self.application.processEvents()
        password_buffer = bytearray(b"secret")
        worker = clidarvi.InteractiveSSHWorker(
            "router.example.net",
            known_hosts_path=str(self.window.get_known_hosts_path()),
            username="admin",
            password_buffer=password_buffer,
        )
        terminal = clidarvi.TerminalWidget(worker)
        terminal.setPlainText("sensitive device output")
        self.window.tabs.addTab(terminal, "Lab")
        self.window.sessions[terminal] = worker
        self.window._session_workers.add(worker)
        self.window._active_password_buffers.append(password_buffer)

        stop_observations = []

        def observe_stop():
            stop_observations.append(bytes(password_buffer))

        with patch.object(worker, "stop", side_effect=observe_stop):
            self.window.close_session_tab(self.window.tabs.indexOf(terminal))

        self.assertEqual(self.window.tabs.count(), 0)
        self.assertNotIn(terminal, self.window.sessions)
        self.assertEqual(terminal.toPlainText(), "")
        self.assertIsNone(terminal.parent())
        self.assertEqual(password_buffer, bytearray(len(password_buffer)))
        self.assertNotIn(password_buffer, self.window._active_password_buffers)
        self.assertEqual(stop_observations, [bytes(len(password_buffer))])

    def test_close_all_sessions_zeroes_each_password_immediately(self):
        self.window.cli_btn.click()
        self.application.processEvents()
        password_buffer = bytearray(b"close-all-secret")
        worker = clidarvi.InteractiveSSHWorker(
            "router.example.net",
            username="admin",
            password_buffer=password_buffer,
        )
        terminal = clidarvi.TerminalWidget(worker)
        self.window.tabs.addTab(terminal, "Lab")
        self.window.sessions[terminal] = worker
        self.window._session_workers.add(worker)
        self.window._active_password_buffers.append(password_buffer)

        self.window._close_all_sessions()

        self.assertFalse(self.window.sessions)
        self.assertEqual(password_buffer, bytearray(len(password_buffer)))
        self.assertNotIn(password_buffer, self.window._active_password_buffers)

    def test_reset_draft_requires_confirmation_and_clears_all_options(self):
        self.window.commands.setPlainText("show version")
        self.window.enable_mode_cb.setChecked(True)
        self.window.save_config_cb.setChecked(True)
        self.window.experimental_automation_cb.setChecked(True)
        self.window.save_cb.setChecked(True)

        with patch.object(
            clidarvi.QMessageBox,
            "question",
            return_value=clidarvi.QMessageBox.StandardButton.No,
        ):
            self.window.refresh_automation()
        self.assertEqual(self.window.commands.toPlainText(), "show version")

        with patch.object(
            clidarvi.QMessageBox,
            "question",
            return_value=clidarvi.QMessageBox.StandardButton.Yes,
        ):
            self.window.refresh_automation()

        self.assertEqual(self.window.commands.toPlainText(), "")
        self.assertFalse(self.window.enable_mode_cb.isChecked())
        self.assertFalse(self.window.save_config_cb.isChecked())
        self.assertFalse(self.window.experimental_automation_cb.isChecked())
        self.assertFalse(self.window.save_cb.isChecked())
        self.assertIn("New automation draft ready", self.window.logs.toPlainText())

    def test_experimental_automation_opt_in_is_default_off_and_not_persisted(self):
        self.assertTrue(self.window.experimental_automation_cb.isEnabled())
        self.assertFalse(self.window.experimental_automation_cb.isChecked())

        self.window.commands.setPlainText("show version")
        self.window.experimental_automation_cb.setChecked(True)
        self.window._capture_automation_draft()
        self.assertFalse(
            self.window._automation_draft.get("experimental_automation", False),
            "The per-run experimental opt-in must never be captured in a draft.",
        )

        self.window.cli_btn.click()
        self.application.processEvents()
        self.window.automation_btn.click()
        self.application.processEvents()

        self.assertEqual(self.window.commands.toPlainText(), "show version")
        self.assertFalse(self.window.experimental_automation_cb.isChecked())

    def test_experimental_opt_in_is_consumed_by_incomplete_run_attempt(self):
        self.window.add_list.clear()
        self.window.commands.clear()
        self.window.experimental_automation_cb.setChecked(True)

        with patch.object(self.window, "_ensure_network_terms_accepted", return_value=True):
            self.window.run_automation()

        self.assertFalse(self.window.experimental_automation_cb.isChecked())
        self.assertIn("No commands provided", self.window.logs.toPlainText())

    def test_library_managed_options_stay_disabled_and_draft_cannot_restore_them(self):
        self.assertFalse(self.window.enable_mode_cb.isEnabled())
        self.assertFalse(self.window.enable_mode_cb.isChecked())
        self.assertIn("unavailable in alpha", self.window.enable_mode_cb.text())
        self.assertFalse(self.window.save_config_cb.isEnabled())
        self.assertFalse(self.window.save_config_cb.isChecked())
        self.assertIn("unavailable in alpha", self.window.save_config_cb.text())

        self.window._automation_draft = {
            "targets": [],
            "commands": "show version",
            "enable_mode": True,
            "save_config": True,
            "save_transcript": False,
            "experimental_automation": True,
        }
        self.window._restore_automation_draft()
        self.window._set_automation_running(True)
        self.window._set_automation_running(False)

        self.assertFalse(self.window.enable_mode_cb.isEnabled())
        self.assertFalse(self.window.enable_mode_cb.isChecked())
        self.assertFalse(self.window.save_config_cb.isEnabled())
        self.assertFalse(self.window.save_config_cb.isChecked())

        self.assertFalse(self.window.experimental_automation_cb.isChecked())

    def test_node_dialog_exposes_clear_primary_and_secondary_actions(self):
        dialog = clidarvi.NodeDialog("add", parent=self.window)
        try:
            self.assertEqual(dialog.ok_btn.objectName(), "PrimaryButton")
            self.assertEqual(dialog.cancel_btn.objectName(), "SecondaryButton")
            self.assertEqual(dialog.hostname_edit.accessibleName(), "Hostname or IP address")
            self.assertEqual(dialog.device_role_combo.accessibleName(), "Device role")
            self.assertEqual(dialog.port_spin.accessibleName(), "SSH port")
        finally:
            dialog.deleteLater()

    def test_node_dialog_exposes_exact_visual_role_choices(self):
        dialog = clidarvi.NodeDialog("add", parent=self.window)
        try:
            self.assertEqual(
                [
                    (
                        dialog.device_role_combo.itemData(index),
                        dialog.device_role_combo.itemText(index),
                    )
                    for index in range(dialog.device_role_combo.count())
                ],
                list(clidarvi.DEVICE_ROLE_CHOICES),
            )
            self.assertEqual(
                list(clidarvi.DEVICE_ROLE_CHOICES),
                [
                    ("", "Automatic (based on platform)"),
                    ("gateway", "Multifunction security gateway"),
                    ("router", "Router"),
                    ("switch", "Switch"),
                    ("firewall", "Firewall"),
                    ("wireless", "Wireless device"),
                    ("controller", "Network controller"),
                    ("server", "Server"),
                    ("generic", "Generic network device"),
                ],
            )
            self.assertIn("only the inventory icon", dialog.device_role_combo.toolTip())
            self.assertIn("does not change", dialog.device_role_combo.toolTip())
        finally:
            dialog.deleteLater()

    def test_node_dialog_automatic_role_resolves_from_selected_platform(self):
        dialog = clidarvi.NodeDialog("add", parent=self.window)
        try:
            dialog.hostname_edit.setText("edge.example.net")
            self.assertEqual(dialog.device_role_combo.currentData(), "")

            dialog.vendor_combo.setCurrentText("Cisco Router")
            self.assertEqual(dialog.device_type_edit.text(), "cisco_ios")
            self.assertEqual(dialog.get_node_data()["device_role"], "router")

            dialog.vendor_combo.setCurrentText("Fortinet")
            self.assertEqual(dialog.device_type_edit.text(), "fortinet")
            self.assertEqual(dialog.get_node_data()["device_role"], "firewall")
        finally:
            dialog.deleteLater()

    def test_node_dialog_edit_migrates_real_v3_legacy_udm_to_gateway_role(self):
        legacy_document = {
            "schema_version": 3,
            "tree": {
                "_nodes": [
                    {
                        "id": "udm-se",
                        "label": "Dream Machine SE",
                        "hostname": "udm-se.example.net",
                        "vendor": "Ubiquiti UniFi OS (Live CLI only)",
                        "device_type": "generic",
                        "port": 2222,
                    }
                ]
            },
            "sites": [],
        }
        original = clidarvi.decode_inventory_state(legacy_document).tree["_nodes"][0]
        self.assertEqual(original["device_role"], "gateway")

        dialog = clidarvi.NodeDialog("edit", original, self.window)
        try:
            self.assertEqual(dialog.device_role_combo.currentData(), "gateway")
            migrated = dict(original)
            migrated.update(
                {
                    "vendor": clidarvi.UBIQUITI_UNIFI_OS_VENDOR,
                    "device_type": clidarvi_workers.UDM_READ_ONLY_DEVICE_TYPE,
                }
            )
            self.assertEqual(dialog.get_node_data(), migrated)
        finally:
            dialog.deleteLater()

    def test_explicit_device_role_is_independent_from_vendor_and_device_type(self):
        dialog = clidarvi.NodeDialog("add", parent=self.window)
        try:
            dialog.hostname_edit.setText("appliance.example.net")
            dialog.device_role_combo.setCurrentIndex(dialog.device_role_combo.findData("gateway"))
            dialog.vendor_combo.setCurrentText("Cisco Switch")
            cisco = dialog.get_node_data()
            self.assertEqual(cisco["device_type"], "cisco_ios")
            self.assertEqual(cisco["device_role"], "gateway")

            dialog.vendor_combo.setCurrentText("Other")
            generic = dialog.get_node_data()
            self.assertEqual(generic["device_type"], "generic")
            self.assertEqual(generic["device_role"], "gateway")
        finally:
            dialog.deleteLater()

    def test_site_dialog_round_trips_location_fields_and_accessibility(self):
        original = clidarvi.SiteRecord(
            name="Example City DC",
            address="1 Example Avenue",
            city="Example City",
            region="Example Region",
            postal_code="0000 XX",
            country="Exampleland",
            notes="Meet the on-call engineer at reception.",
        )
        dialog = clidarvi.SiteDialog("edit", original.to_mapping(), self.window)
        try:
            self.assertEqual(dialog.get_site_record(), original)
            self.assertEqual(dialog.save_btn.objectName(), "PrimaryButton")
            self.assertEqual(dialog.cancel_btn.objectName(), "SecondaryButton")
            self.assertEqual(dialog.name_edit.accessibleName(), "Site name")
            self.assertEqual(dialog.site_type_combo.accessibleName(), "Site type")
            self.assertEqual(
                [
                    (
                        dialog.site_type_combo.itemText(index),
                        dialog.site_type_combo.itemData(index),
                    )
                    for index in range(dialog.site_type_combo.count())
                ],
                [
                    ("Enterprise site", "enterprise"),
                    ("Data center", "datacenter"),
                ],
            )
            self.assertEqual(dialog.site_type_combo.currentData(), "enterprise")
            self.assertEqual(dialog.address_edit.accessibleName(), "Street address")
            self.assertEqual(dialog.postal_code_edit.accessibleName(), "Postal code")
            self.assertEqual(dialog.city_edit.accessibleName(), "City")
            self.assertEqual(dialog.region_edit.accessibleName(), "State / province / region")
            self.assertEqual(dialog.country_edit.accessibleName(), "Country")
            self.assertEqual(dialog.notes_edit.accessibleName(), "Notes")
        finally:
            dialog.deleteLater()

        seeded_add_dialog = clidarvi.SiteDialog("add", original.to_mapping(), self.window)
        try:
            self.assertEqual(seeded_add_dialog.get_site_record(), original)
            self.assertEqual(seeded_add_dialog.name_edit.text(), "Example City DC")
        finally:
            seeded_add_dialog.deleteLater()

    def test_site_dialog_edit_round_trips_datacenter_type(self):
        original = clidarvi.SiteRecord(
            name="Example City DC",
            site_type="datacenter",
            address="1 Example Avenue",
            city="Example City",
        )
        dialog = clidarvi.SiteDialog("edit", original.to_mapping(), self.window)
        try:
            self.assertEqual(dialog.site_type_combo.currentText(), "Data center")
            self.assertEqual(dialog.site_type_combo.currentData(), "datacenter")
            self.assertEqual(dialog.get_site_record(), original)
        finally:
            dialog.deleteLater()

    def test_legacy_site_mapping_without_type_defaults_to_enterprise(self):
        legacy_mapping = {
            "name": "Legacy office",
            "address": "2 Example Plaza",
            "city": "Alternate City",
        }

        site = clidarvi.SiteRecord.from_mapping(legacy_mapping)
        self.assertEqual(site.site_type, "enterprise")
        self.assertEqual(site.to_mapping()["site_type"], "enterprise")

        item = self.window._make_folder_item(self.window.tree, site.name, site=site)
        self.assertEqual(
            self._rendered_icon_signature(item.icon(0)),
            self._rendered_icon_signature(self.window._inventory_icons["site_dark"]),
        )
        self.assertEqual(
            item.data(0, Qt.ItemDataRole.AccessibleDescriptionRole),
            "Physical enterprise site. 2 Example Plaza. Alternate City",
        )

    def test_site_button_adds_a_physical_site_with_metadata(self):
        self.window.tree.clear()
        site = clidarvi.SiteRecord(
            name="Sample City POP",
            address="3 Example Boulevard",
            city="Sample City",
            country="Exampleland",
        )

        with (
            patch.object(
                clidarvi.SiteDialog,
                "exec",
                return_value=clidarvi.QDialog.DialogCode.Accepted,
            ),
            patch.object(clidarvi.SiteDialog, "get_site_record", return_value=site),
        ):
            self.window.new_site_btn.click()

        item = self.window._find_folder_by_path(("Sample City POP",))
        self.assertIsNotNone(item)
        self.assertEqual(self.window.tree_to_dict()["Sample City POP"], {})
        self.assertEqual(self.window._site_record_for_item(item), site)
        self.assertIn("3 Example Boulevard", item.toolTip(0))
        self.assertIn(
            "Physical enterprise site",
            item.data(0, Qt.ItemDataRole.AccessibleDescriptionRole),
        )
        self.assertEqual(
            self.window._site_placements_from_tree(),
            (clidarvi.SitePlacement(path=("Sample City POP",), site=site),),
        )

    def test_invalid_site_names_warn_without_mutating_the_inventory(self):
        self.window.tree.clear()
        existing = self.window._make_folder_item(self.window.tree, "Existing")
        original = clidarvi.SiteRecord(name="Original", city="Alternate City")
        original_item = self.window._make_folder_item(
            self.window.tree,
            original.name,
            site=original,
        )

        for invalid_name in ("Existing", "_nodes"):
            with (
                self.subTest(add_name=invalid_name),
                patch.object(
                    clidarvi.SiteDialog,
                    "exec",
                    return_value=clidarvi.QDialog.DialogCode.Accepted,
                ),
                patch.object(
                    clidarvi.SiteDialog,
                    "get_site_record",
                    return_value=clidarvi.SiteRecord(name=invalid_name),
                ),
                patch.object(clidarvi.QMessageBox, "warning") as warning,
            ):
                result = self.window._add_site()

            self.assertIsNone(result)
            warning.assert_called_once()
            self.assertEqual(self.window.tree.topLevelItemCount(), 2)

        with (
            patch.object(
                clidarvi.SiteDialog,
                "exec",
                return_value=clidarvi.QDialog.DialogCode.Accepted,
            ),
            patch.object(
                clidarvi.SiteDialog,
                "get_site_record",
                return_value=clidarvi.SiteRecord(name=existing.text(0)),
            ),
            patch.object(clidarvi.QMessageBox, "warning") as warning,
        ):
            self.window._edit_site(original_item)

        warning.assert_called_once()
        self.assertEqual(original_item.text(0), "Original")
        self.assertEqual(self.window._site_record_for_item(original_item), original)

    def test_existing_folder_can_gain_and_remove_site_details_without_data_loss(self):
        self.window.tree.clear()
        folder = self.window._make_folder_item(self.window.tree, "Example City")
        self.window._make_node_item(
            folder,
            "Core",
            metadata={
                "id": "ams-core",
                "label": "Core",
                "hostname": "core.example.net",
            },
        )
        site = clidarvi.SiteRecord(
            name="Example City",
            address="<b>1 Example Avenue</b>",
            city="Example City",
            country="Exampleland",
        )

        with (
            patch.object(
                clidarvi.SiteDialog,
                "exec",
                return_value=clidarvi.QDialog.DialogCode.Accepted,
            ),
            patch.object(clidarvi.SiteDialog, "get_site_record", return_value=site),
        ):
            self.window._add_site_details(folder)

        self.assertEqual(self.window._site_record_for_item(folder), site)
        self.assertIn("&lt;b&gt;1 Example Avenue&lt;/b&gt;", folder.toolTip(0))
        self.assertNotIn("<b>1 Example Avenue</b>", folder.toolTip(0))
        self.assertIn(
            "Physical enterprise site",
            folder.data(0, Qt.ItemDataRole.AccessibleDescriptionRole),
        )
        self.assertIsNotNone(self.window._find_node_by_id("ams-core"))

        with patch.object(
            clidarvi.QMessageBox,
            "question",
            return_value=clidarvi.QMessageBox.StandardButton.Yes,
        ):
            self.window._remove_site_details(folder)

        self.assertIsNone(self.window._site_record_for_item(folder))
        self.assertEqual(folder.toolTip(0), "")
        self.assertIsNone(folder.data(0, Qt.ItemDataRole.AccessibleDescriptionRole))
        self.assertIsNotNone(self.window._find_node_by_id("ams-core"))

    def test_dismissing_site_context_menu_does_not_open_an_editor(self):
        self.window.tree.clear()
        site = clidarvi.SiteRecord(name="Example City")
        item = self.window._make_folder_item(self.window.tree, site.name, site=site)

        with (
            patch.object(self.window.tree, "itemAt", return_value=item),
            patch.object(clidarvi.QMenu, "exec", return_value=None),
            patch.object(clidarvi.SiteDialog, "exec") as site_dialog_exec,
            patch.object(clidarvi.QInputDialog, "exec") as name_dialog_exec,
        ):
            self.window.show_tree_menu(QPoint())

        site_dialog_exec.assert_not_called()
        name_dialog_exec.assert_not_called()

    def test_delayed_device_editor_ignores_deleted_window_and_item(self):
        self.window.tree.clear()
        item = self.window._make_node_item(
            self.window.tree,
            "Router",
            metadata={
                "id": "delayed-device",
                "label": "Router",
                "hostname": "router.example.net",
            },
        )
        callbacks = []

        def choose_edit_device(menu, *_args, **_kwargs):
            return next(action for action in menu.actions() if action.text() == "Edit Device")

        with (
            patch.object(self.window.tree, "itemAt", return_value=item),
            patch.object(clidarvi.QMenu, "exec", new=choose_edit_device),
            patch.object(
                clidarvi.QTimer,
                "singleShot",
                side_effect=lambda _delay, callback: callbacks.append(callback),
            ),
        ):
            self.window.show_tree_menu(QPoint())

        self.assertEqual(len(callbacks), 1)
        deleted_window = self.window
        deleted_window._shutdown_ready = True
        deleted_window.close()
        deleted_window.deleteLater()
        QApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        self.application.processEvents()
        self.window = clidarvi.MainWindow()

        callbacks[0]()

    def test_delayed_folder_editor_ignores_deleted_window_and_item(self):
        self.window.tree.clear()
        item = self.window._make_folder_item(self.window.tree, "Directory")
        callbacks = []

        def choose_edit_name(menu, *_args, **_kwargs):
            return next(action for action in menu.actions() if action.text() == "Edit Name")

        with (
            patch.object(self.window.tree, "itemAt", return_value=item),
            patch.object(clidarvi.QMenu, "exec", new=choose_edit_name),
            patch.object(
                clidarvi.QTimer,
                "singleShot",
                side_effect=lambda _delay, callback: callbacks.append(callback),
            ),
        ):
            self.window.show_tree_menu(QPoint())

        self.assertEqual(len(callbacks), 1)
        deleted_window = self.window
        deleted_window._shutdown_ready = True
        deleted_window.close()
        deleted_window.deleteLater()
        QApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        self.application.processEvents()
        self.window = clidarvi.MainWindow()

        callbacks[0]()

    def test_site_metadata_round_trips_without_entering_the_device_tree(self):
        self.window.tree.clear()
        region = self.window._make_folder_item(self.window.tree, "Exampleland")
        site = clidarvi.SiteRecord(
            name="Example City DC",
            site_type="datacenter",
            address="1 Example Avenue",
            city="Example City",
            region="Example Region",
            postal_code="0000 XX",
            country="Exampleland",
            notes="Rack hall A",
        )
        site_item = self.window._make_folder_item(region, site.name, site=site)
        self.window._make_node_item(
            site_item,
            "Core",
            metadata={
                "id": "ams-core",
                "label": "Core",
                "hostname": "core.ams.example.net",
            },
        )

        tree = self.window.tree_to_dict()
        placements = self.window._site_placements_from_tree()
        self.assertNotIn("sites", tree)
        self.assertEqual(placements[0].path, ("Exampleland", "Example City DC"))

        self.window._apply_tree_dict(tree, placements)

        restored = self.window._find_folder_by_path(("Exampleland", "Example City DC"))
        self.assertIsNotNone(restored)
        self.assertEqual(self.window._site_record_for_item(restored), site)
        self.assertIsNotNone(self.window._find_node_by_id("ams-core"))

    def test_undo_and_redo_preserve_site_metadata(self):
        self.window.tree.clear()
        self.window.history = []
        self.window.history_index = -1
        before = clidarvi.SiteRecord(name="Alternate City", city="Alternate City", notes="Before")
        site_item = self.window._make_folder_item(self.window.tree, before.name, site=before)
        self.window.capture_history_state()
        enterprise_icon = self._rendered_icon_signature(site_item.icon(0))
        after = clidarvi.SiteRecord(
            name="Alternate City",
            site_type="datacenter",
            city="Alternate City",
            notes="After",
        )
        self.window._set_site_record(site_item, after)
        datacenter_icon = self._rendered_icon_signature(site_item.icon(0))
        self.window.capture_history_state()

        self.assertNotEqual(enterprise_icon, datacenter_icon)
        self.assertEqual(
            site_item.data(0, Qt.ItemDataRole.AccessibleDescriptionRole),
            "Physical data center. Alternate City",
        )
        self.assertEqual(self.window.history[-1]["sites"][0]["site_type"], "datacenter")

        self.window.go_back()
        restored = self.window._find_folder_by_path(("Alternate City",))
        self.assertEqual(self.window._site_record_for_item(restored), before)
        self.assertEqual(
            self._rendered_icon_signature(restored.icon(0)),
            enterprise_icon,
        )
        self.assertEqual(
            restored.data(0, Qt.ItemDataRole.AccessibleDescriptionRole),
            "Physical enterprise site. Alternate City",
        )

        self.window.go_forward()
        restored = self.window._find_folder_by_path(("Alternate City",))
        self.assertEqual(self.window._site_record_for_item(restored), after)
        self.assertEqual(
            self._rendered_icon_signature(restored.icon(0)),
            datacenter_icon,
        )
        self.assertEqual(
            restored.data(0, Qt.ItemDataRole.AccessibleDescriptionRole),
            "Physical data center. Alternate City",
        )

    def test_site_metadata_is_saved_and_loaded_in_schema_v4(self):
        self.window.tree.clear()
        site = clidarvi.SiteRecord(
            name="Example Test Lab",
            site_type="datacenter",
            address="99 Test Campus",
            city="Test City",
            region="Test Region",
            postal_code="0000 YY",
            country="Exampleland",
            notes="Test environment",
        )
        site_item = self.window._make_folder_item(self.window.tree, site.name, site=site)
        self.window._make_node_item(
            site_item,
            "Lab switch",
            metadata={
                "id": "lab-switch",
                "label": "Lab switch",
                "hostname": "lab-switch.example.net",
            },
        )

        self.assertTrue(self.window.save_tree_to_file())
        with self.window.get_save_path().open("r", encoding="utf-8") as handle:
            document = json.load(handle)
        self.assertEqual(document["schema_version"], 4)
        self.assertEqual(document["sites"][0]["path"], ["Example Test Lab"])
        self.assertEqual(document["sites"][0]["site_type"], "datacenter")
        self.assertEqual(document["sites"][0]["address"], "99 Test Campus")

        decoded = self.window._read_inventory_path(self.window.get_save_path())
        self.assertEqual(decoded.tree["Example Test Lab"]["_nodes"][0]["id"], "lab-switch")
        self.assertEqual(decoded.sites[0].site, site)

        self.window.tree.clear()
        self.assertTrue(self.window.load_tree_from_file())
        restored = self.window._find_folder_by_path(("Example Test Lab",))
        self.assertEqual(self.window._site_record_for_item(restored), site)
        self.assertEqual(
            self._rendered_icon_signature(restored.icon(0)),
            self._rendered_icon_signature(self.window._inventory_icons["datacenter_dark"]),
        )
        self.assertIn(
            "Physical data center",
            restored.data(0, Qt.ItemDataRole.AccessibleDescriptionRole),
        )
        self.assertIsNotNone(self.window._find_node_by_id("lab-switch"))

    def test_bundled_route_logo_renders_at_sidebar_size(self):
        logo_path = clidarvi.find_asset_path("clidarvi_symbol.svg")
        self.assertIsNotNone(logo_path)
        pixmap = QPixmap(str(logo_path))
        self.assertFalse(pixmap.isNull())
        sidebar_logo = pixmap.scaled(
            38,
            38,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        self.assertEqual(sidebar_logo.size().width(), 38)
        self.assertEqual(sidebar_logo.size().height(), 38)

    def test_all_inventory_icon_assets_resolve_and_render_at_tree_size(self):
        roles = (
            "site",
            "datacenter",
            "router",
            "switch",
            "firewall",
            "wireless",
            "controller",
            "server",
            "gateway",
            "device",
        )
        for role in roles:
            for surface in ("dark", "light"):
                with self.subTest(role=role, surface=surface):
                    asset_path = clidarvi.find_asset_path(f"icons/inventory/{role}-{surface}.svg")
                    self.assertIsNotNone(asset_path)
                    icon = QIcon(str(asset_path))
                    self.assertFalse(icon.isNull())
                    rendered = icon.pixmap(20, 20)
                    self.assertFalse(rendered.isNull())
                    self.assertEqual((rendered.width(), rendered.height()), (20, 20))

        expected_keys = {f"{role}_{surface}" for role in roles for surface in ("dark", "light")}
        self.assertTrue(expected_keys.issubset(self.window._inventory_icons))
        self.assertTrue(
            all(not self.window._inventory_icons[key].isNull() for key in expected_keys)
        )

    def test_every_inventory_role_icon_is_visually_distinct_on_each_surface(self):
        roles = (
            "site",
            "datacenter",
            "router",
            "switch",
            "firewall",
            "wireless",
            "controller",
            "server",
            "gateway",
            "device",
        )
        for surface in ("dark", "light"):
            with self.subTest(surface=surface):
                signatures = {
                    role: self._rendered_icon_signature(
                        self.window._inventory_icons[f"{role}_{surface}"]
                    )
                    for role in roles
                }
                self.assertTrue(all(signatures.values()))
                self.assertEqual(len(signatures), len(set(signatures.values())))

    def test_generic_device_icon_is_visually_distinct_from_datacenter_icon(self):
        for surface in ("dark", "light"):
            with self.subTest(surface=surface):
                generic = self._rendered_icon_signature(
                    self.window._inventory_icons[f"device_{surface}"]
                )
                datacenter = self._rendered_icon_signature(
                    self.window._inventory_icons[f"datacenter_{surface}"]
                )
                self.assertTrue(generic)
                self.assertTrue(datacenter)
                self.assertNotEqual(generic, datacenter)

    def test_site_types_use_distinct_tree_and_selector_icons_instead_of_brand_logo(self):
        self.window.tree.clear()
        records = (
            (clidarvi.SiteRecord(name="Sample City office"), "site"),
            (
                clidarvi.SiteRecord(name="Example City DC", site_type="datacenter"),
                "datacenter",
            ),
        )
        tree_signatures = {}
        for site, role in records:
            with self.subTest(site=site.name, surface="dark"):
                item = self.window._make_folder_item(
                    self.window.tree,
                    site.name,
                    site=site,
                )
                signature = self._rendered_icon_signature(item.icon(0))
                tree_signatures[role] = signature
                self.assertTrue(signature)
                self.assertEqual(
                    signature,
                    self._rendered_icon_signature(self.window._inventory_icons[f"{role}_dark"]),
                )
                self.assertNotEqual(
                    signature,
                    self._rendered_icon_signature(self.window._brand_icon),
                )
                self.assertEqual(
                    item.data(0, Qt.ItemDataRole.AccessibleDescriptionRole),
                    clidarvi.INVENTORY_ICON_DESCRIPTIONS[role],
                )

        self.assertNotEqual(tree_signatures["site"], tree_signatures["datacenter"])

        self.window.populate_selector_from_tree()
        selector_signatures = {}
        for site, role in records:
            with self.subTest(site=site.name, surface="light"):
                selector_index = self._selector_index(kind="folder", path=(site.name,))
                selector_icon = self.window.selector.itemIcon(selector_index)
                signature = self._rendered_icon_signature(selector_icon)
                selector_signatures[role] = signature
                self.assertTrue(signature)
                self.assertEqual(
                    signature,
                    self._rendered_icon_signature(self.window._inventory_icons[f"{role}_light"]),
                )
                self.assertNotEqual(
                    signature,
                    self._rendered_icon_signature(self.window._brand_icon),
                )

        self.assertNotEqual(selector_signatures["site"], selector_signatures["datacenter"])

    def test_device_icon_role_mapping_uses_explicit_visual_metadata(self):
        cases = (
            ("Cisco Router", "cisco_ios", "router", "router"),
            ("Cisco Switch", "cisco_ios", "switch", "switch"),
            ("Cisco WLC", "cisco_wlc", "wireless", "wireless"),
            ("Fortinet", "fortinet", "firewall", "firewall"),
            ("Palo Alto", "paloalto_panos", "controller", "controller"),
            ("Aruba", "aruba_os", "server", "server"),
            ("Other", "generic", "gateway", "gateway"),
            ("Cisco Router", "cisco_ios", "generic", "device"),
        )
        for vendor, device_type, device_role, expected in cases:
            with self.subTest(vendor=vendor, device_role=device_role):
                record = clidarvi.DeviceRecord(
                    label=vendor,
                    hostname=f"{expected}.example.net",
                    vendor=vendor,
                    device_type=device_type,
                    device_role=device_role,
                )
                self.assertEqual(self.window._device_icon_key(record), expected)

        self.assertEqual(clidarvi.VENDOR_MAP["Cisco Router"], "cisco_ios")
        self.assertEqual(clidarvi.VENDOR_MAP["Cisco Switch"], "cisco_ios")
        router = clidarvi.DeviceRecord(
            label="Router",
            hostname="router.example.net",
            vendor="Other",
            device_type="cisco_ios",
            device_role="router",
        )
        switch = clidarvi.DeviceRecord(
            label="Switch",
            hostname="switch.example.net",
            vendor="Palo Alto",
            device_type="cisco_ios",
            device_role="switch",
        )
        router_item = QTreeWidgetItem(self.window.tree)
        switch_item = QTreeWidgetItem(self.window.tree)
        self.window._set_node_record(router_item, router)
        self.window._set_node_record(switch_item, switch)
        self.assertNotEqual(
            self._rendered_icon_signature(router_item.icon(0)),
            self._rendered_icon_signature(switch_item.icon(0)),
        )

    def test_setting_node_record_updates_icon_metadata_and_accessibility(self):
        item = QTreeWidgetItem(self.window.tree)
        router = clidarvi.DeviceRecord(
            id="icon-edit-probe",
            label="WAN router",
            hostname="wan.example.net",
            vendor="Cisco Router",
            device_type="cisco_ios",
            device_role="router",
        )
        self.window._set_node_record(item, router)

        router_signature = self._rendered_icon_signature(item.icon(0))
        self.assertTrue(router_signature)
        self.assertEqual(item.text(0), router.label)
        self.assertEqual(item.data(0, Qt.ItemDataRole.UserRole), router.to_mapping())
        self.assertIn(
            "router",
            item.data(0, Qt.ItemDataRole.AccessibleDescriptionRole).lower(),
        )

        firewall = clidarvi.DeviceRecord(
            id=router.id,
            label="Edge firewall",
            hostname="firewall.example.net",
            vendor="Fortinet",
            device_type="fortinet",
            device_role="firewall",
        )
        self.window._set_node_record(item, firewall)

        self.assertEqual(item.text(0), firewall.label)
        self.assertEqual(item.data(0, Qt.ItemDataRole.UserRole), firewall.to_mapping())
        self.assertIn(
            "firewall",
            item.data(0, Qt.ItemDataRole.AccessibleDescriptionRole).lower(),
        )
        self.assertNotEqual(router_signature, self._rendered_icon_signature(item.icon(0)))

    def test_selector_uses_matching_light_device_icon(self):
        self.window.tree.clear()
        record = clidarvi.DeviceRecord(
            id="selector-firewall",
            label="Perimeter firewall",
            hostname="firewall.example.net",
            vendor="Palo Alto",
            device_type="paloalto_panos",
            device_role="firewall",
        )
        self.window._make_node_item(
            self.window.tree,
            record.label,
            metadata=record.to_mapping(),
        )
        self.window.populate_selector_from_tree()

        selector_index = self._selector_index(kind="node", path=(record.label,))
        selector_icon = self.window.selector.itemIcon(selector_index)
        self.assertFalse(selector_icon.isNull())
        self.assertEqual(
            self._rendered_icon_signature(selector_icon),
            self._rendered_icon_signature(self.window._inventory_icons["firewall_light"]),
        )

    def test_gateway_role_sets_tree_selector_icons_and_accessibility(self):
        self.window.tree.clear()
        record = clidarvi.DeviceRecord(
            id="udm-se-gateway",
            label="Dream Machine SE",
            hostname="udm-se.example.net",
            vendor="Ubiquiti UniFi OS (Live CLI only)",
            device_type="generic",
            device_role="gateway",
        )
        item = self.window._make_node_item(
            self.window.tree,
            record.label,
            metadata=record.to_mapping(),
        )

        self.assertEqual(
            self._rendered_icon_signature(item.icon(0)),
            self._rendered_icon_signature(self.window._inventory_icons["gateway_dark"]),
        )
        self.assertEqual(
            item.data(0, Qt.ItemDataRole.AccessibleDescriptionRole),
            "Multifunction security gateway",
        )

        self.window.populate_selector_from_tree()
        selector_index = self._selector_index(kind="node", path=(record.label,))
        self.assertEqual(
            self._rendered_icon_signature(self.window.selector.itemIcon(selector_index)),
            self._rendered_icon_signature(self.window._inventory_icons["gateway_light"]),
        )

    def test_missing_inventory_icon_cache_does_not_break_inventory_updates(self):
        self.window.tree.clear()
        with patch.object(self.window, "_inventory_icons", {}):
            site_item = self.window._make_folder_item(
                self.window.tree,
                "Fallback site",
                site=clidarvi.SiteRecord(name="Fallback site"),
            )
            record = clidarvi.DeviceRecord(
                id="fallback-device",
                label="Fallback device",
                hostname="fallback.example.net",
                vendor="Other",
                device_type="generic",
            )
            node_item = self.window._make_node_item(
                site_item,
                record.label,
                metadata=record.to_mapping(),
            )
            self.window._set_node_record(node_item, record)
            self.window.populate_selector_from_tree()

        self.assertEqual(self.window._site_record_for_item(site_item).name, "Fallback site")
        self.assertEqual(
            node_item.data(0, Qt.ItemDataRole.UserRole),
            record.to_mapping(),
        )
        self.assertGreaterEqual(self.window.selector.count(), 3)

    def test_installed_asset_lookup_ignores_unrelated_site_packages_license(self):
        prefix_root = self.data_path / "prefix"
        module_root = prefix_root / "lib" / "python" / "site-packages"
        installed_root = prefix_root / "share" / "clidarvi"
        assets, module_path, _ = self._write_wheel_install_fixture(
            module_root=module_root,
            asset_root=installed_root,
            record_native_root=installed_root,
        )
        (module_root / "LICENSE").write_text("unrelated license", encoding="utf-8")

        with patch.object(clidarvi, "__file__", str(module_path)):
            resolved = clidarvi.find_asset_path("LICENSE")

        self.assertEqual(resolved.resolve(), assets["LICENSE"].resolve())

    def test_device_metadata_round_trip_is_lossless(self):
        self.window.tree.clear()
        folder = QTreeWidgetItem(self.window.tree, ["Site"])
        folder.setData(0, Qt.ItemDataRole.UserRole, "folder")
        original = {
            "id": "core-1",
            "label": "Core",
            "hostname": "core.example.net",
            "vendor": "Cisco Switch",
            "device_type": "cisco_ios",
            "port": 2222,
            "device_role": "controller",
        }
        self.window._make_node_item(folder, "Core", metadata=original)

        serialized = self.window.tree_to_dict()
        self.window._apply_tree_dict(self.window._sanitize_tree_dict(serialized))
        restored = self.window._find_node_by_id("core-1")

        self.assertIsNotNone(restored)
        self.assertEqual(restored.data(0, Qt.ItemDataRole.UserRole), original)

    def test_undo_and_redo_preserve_explicit_device_role(self):
        self.window.tree.clear()
        self.window.history = []
        self.window.history_index = -1
        gateway = clidarvi.DeviceRecord(
            id="role-history",
            label="Edge appliance",
            hostname="edge.example.net",
            vendor="Other",
            device_type="generic",
            device_role="gateway",
        )
        item = self.window._make_node_item(
            self.window.tree,
            gateway.label,
            metadata=gateway.to_mapping(),
        )
        self.assertTrue(self.window.capture_history_state())

        server = clidarvi.DeviceRecord.from_mapping(
            {**gateway.to_mapping(), "device_role": "server"}
        )
        self.window._set_node_record(item, server)
        self.assertTrue(self.window.capture_history_state())

        self.window.go_back()
        restored = self.window._find_node_by_id(gateway.id)
        restored_record = clidarvi.DeviceRecord.from_mapping(
            restored.data(0, Qt.ItemDataRole.UserRole)
        )
        self.assertEqual(restored_record.device_role, "gateway")
        self.assertEqual(
            self._rendered_icon_signature(restored.icon(0)),
            self._rendered_icon_signature(self.window._inventory_icons["gateway_dark"]),
        )

        self.window.go_forward()
        restored = self.window._find_node_by_id(gateway.id)
        restored_record = clidarvi.DeviceRecord.from_mapping(
            restored.data(0, Qt.ItemDataRole.UserRole)
        )
        self.assertEqual(restored_record.device_role, "server")
        self.assertEqual(
            self._rendered_icon_signature(restored.icon(0)),
            self._rendered_icon_signature(self.window._inventory_icons["server_dark"]),
        )

    def test_xml_import_preserves_explicit_role_and_infers_missing_legacy_role(self):
        root = clidarvi.ET.fromstring(
            "<Connections>"
            '<Connection Name="Dream Machine SE" Hostname="udm-se.example.net" '
            'Vendor="Ubiquiti UniFi OS (Live CLI only)" DeviceType="generic" '
            'DeviceRole="gateway" Port="22" />'
            '<Connection Name="Legacy router" Hostname="router.example.net" '
            'Vendor="Cisco Router" DeviceType="cisco_ios" Port="22" />'
            "</Connections>"
        )

        devices = self.window._sanitize_xml_tree(root)["_nodes"]

        self.assertEqual(devices[0]["vendor"], clidarvi.UBIQUITI_UNIFI_OS_VENDOR)
        self.assertEqual(devices[0]["device_type"], "generic")
        self.assertEqual(devices[0]["device_role"], "gateway")
        self.assertEqual(devices[1]["device_role"], "router")

    def test_xml_import_rejects_invalid_explicit_device_role(self):
        root = clidarvi.ET.fromstring(
            '<Connections><Connection Name="Bad" Hostname="bad.example.net" '
            'Vendor="Other" DeviceType="generic" DeviceRole="datacenter" />'
            "</Connections>"
        )

        with self.assertRaisesRegex(ValueError, "Unsupported device_role"):
            self.window._sanitize_xml_tree(root)

    def test_reserved_schema_key_is_rejected_as_a_folder_name(self):
        with self.assertRaisesRegex(ValueError, "reserved"):
            self.window._validated_folder_name("_nodes")

        xml_root = clidarvi.ET.fromstring(
            '<Connections><Connection Name="_nodes">'
            '<Connection Name="Router" Hostname="router.example.net" />'
            "</Connection></Connections>"
        )
        with self.assertRaisesRegex(ValueError, "reserved"):
            self.window._sanitize_xml_tree(xml_root)

    def test_unknown_commands_require_an_exact_typed_gate(self):
        record = clidarvi.DeviceRecord(label="Router", hostname="router.example.net")
        with patch.object(
            clidarvi.QInputDialog,
            "getText",
            return_value=("yes", True),
        ):
            rejected = self.window._prepare_and_confirm_commands("frobnicate system", [record])
        self.assertIsNone(rejected)

        with (
            patch.object(
                clidarvi.QInputDialog,
                "getText",
                return_value=("RUN UNKNOWN", True),
            ),
            patch.object(
                clidarvi.QMessageBox,
                "exec",
                return_value=clidarvi.QMessageBox.StandardButton.Yes,
            ),
        ):
            accepted = self.window._prepare_and_confirm_commands("frobnicate system", [record])
        self.assertEqual(accepted, (["frobnicate system"], False))

    def test_destructive_commands_require_an_exact_typed_gate(self):
        record = clidarvi.DeviceRecord(
            label="Router",
            hostname="router.example.net",
            vendor="Cisco Switch",
            device_type="cisco_ios",
        )
        with patch.object(
            clidarvi.QInputDialog,
            "getText",
            return_value=("RUN UNKNOWN", True),
        ):
            rejected = self.window._prepare_and_confirm_commands("reload", [record])
        self.assertIsNone(rejected)

        with (
            patch.object(
                clidarvi.QInputDialog,
                "getText",
                return_value=("RUN DESTRUCTIVE", True),
            ) as typed_gate,
            patch.object(
                clidarvi.QMessageBox,
                "exec",
                return_value=clidarvi.QMessageBox.StandardButton.Yes,
            ),
        ):
            accepted = self.window._prepare_and_confirm_commands("reload", [record])
        self.assertEqual(accepted, (["reload"], True))
        self.assertIn("RUN DESTRUCTIVE", typed_gate.call_args.args[2])

    def test_full_config_replacement_requires_the_destructive_gate(self):
        record = clidarvi.DeviceRecord(
            label="Router",
            hostname="router.example.net",
            vendor="Cisco Switch",
            device_type="cisco_ios",
        )
        command = "configure replace tftp://192.0.2.9/empty.cfg force"
        with patch.object(
            clidarvi.QInputDialog,
            "getText",
            return_value=("", False),
        ) as typed_gate:
            rejected = self.window._prepare_and_confirm_commands(command, [record])
        self.assertIsNone(rejected)
        self.assertIn("RUN DESTRUCTIVE", typed_gate.call_args.args[2])

    def test_mixed_vendor_unknown_classification_keeps_typed_unknown_gate(self):
        records = [
            clidarvi.DeviceRecord(
                label="Cisco",
                hostname="cisco.example.net",
                vendor="Cisco Switch",
                device_type="cisco_ios",
            ),
            clidarvi.DeviceRecord(
                label="Fortinet",
                hostname="fortinet.example.net",
                vendor="Fortinet",
                device_type="fortinet",
            ),
        ]
        command = "ip route 192.0.2.0 255.255.255.0 198.51.100.1"

        with (
            patch.object(
                clidarvi.QInputDialog,
                "getText",
                return_value=("RUN UNKNOWN", True),
            ) as typed_gate,
            patch.object(
                clidarvi.QMessageBox,
                "exec",
                return_value=clidarvi.QMessageBox.StandardButton.Yes,
            ),
        ):
            accepted = self.window._prepare_and_confirm_commands(command, records)

        self.assertEqual(accepted, ([command], False))
        self.assertIn("RUN UNKNOWN", typed_gate.call_args.args[2])

    def test_target_list_labels_refresh_after_a_rename(self):
        self.window.tree.clear()
        self.window._make_node_item(
            self.window.tree,
            "Old name",
            metadata={
                "id": "rename-probe",
                "label": "Old name",
                "hostname": "probe.example.net",
            },
        )
        item = self.window._find_node_by_id("rename-probe")
        from PyQt6.QtWidgets import QListWidgetItem

        target = QListWidgetItem(self.window._display_path_for_item(item))
        target.setData(Qt.ItemDataRole.UserRole, "rename-probe")
        self.window.add_list.addItem(target)
        self.assertIn("Old name", self.window.add_list.item(0).text())

        item.setText(0, "New name")
        self.window._prune_missing_automation_targets()

        self.assertEqual(self.window.add_list.count(), 1)
        self.assertIn("New name", self.window.add_list.item(0).text())
        self.assertNotIn("Old name", self.window.add_list.item(0).text())

    def test_target_list_full_path_refreshes_after_ancestor_rename(self):
        self.window.tree.clear()
        folder = self.window._make_folder_item(self.window.tree, "Old site")
        self.window._make_node_item(
            folder,
            "Core",
            metadata={
                "id": "ancestor-rename-probe",
                "label": "Core",
                "hostname": "core.example.net",
            },
        )
        item = self.window._find_node_by_id("ancestor-rename-probe")
        from PyQt6.QtWidgets import QListWidgetItem

        target = QListWidgetItem(self.window._display_path_for_item(item))
        target.setData(Qt.ItemDataRole.UserRole, "ancestor-rename-probe")
        self.window.add_list.addItem(target)
        self.assertEqual(self.window.add_list.item(0).text(), "Old site / Core")

        folder.setText(0, "New site")
        self.window._prune_missing_automation_targets()

        self.assertEqual(self.window.add_list.item(0).text(), "New site / Core")

    def test_find_asset_path_binds_record_native_user_layout(self):
        user_root = self.data_path / "user-base"
        module_root = user_root / "lib" / "python3.13" / "site-packages"
        installed_root = user_root / "share" / "clidarvi"
        assets, module_path, _ = self._write_wheel_install_fixture(
            module_root=module_root,
            asset_root=installed_root,
            record_native_root=installed_root,
        )

        with patch.object(clidarvi, "__file__", str(module_path)):
            found = clidarvi.find_asset_path("TERMS.md")

        self.assertEqual(found.resolve(), assets["TERMS.md"].resolve())

    def test_find_asset_path_binds_active_venv_below_user_base(self):
        prefix_root = self.data_path / "user-base" / "venvs" / "clidarvi"
        module_root = prefix_root / "lib" / "python3.13" / "site-packages"
        installed_root = prefix_root / "share" / "clidarvi"
        assets, module_path, _ = self._write_wheel_install_fixture(
            module_root=module_root,
            asset_root=installed_root,
            record_native_root=installed_root,
        )
        stale_target = module_root / "share" / "clidarvi" / "TERMS.md"
        stale_target.parent.mkdir(parents=True)
        stale_target.write_text("stale target data\n", encoding="utf-8")

        with patch.object(clidarvi, "__file__", str(module_path)):
            found = clidarvi.find_asset_path("TERMS.md")

        self.assertEqual(found.resolve(), assets["TERMS.md"].resolve())

    def test_find_asset_path_binds_target_nested_below_active_prefix(self):
        prefix_root = self.data_path / "prefix"
        module_root = prefix_root / "vendor-target"
        target_root = module_root / "share" / "clidarvi"
        native_root = prefix_root / "share" / "clidarvi"
        assets, module_path, _ = self._write_wheel_install_fixture(
            module_root=module_root,
            asset_root=target_root,
            record_native_root=native_root,
        )
        stale = native_root / "TERMS.md"
        stale.parent.mkdir(parents=True)
        stale.write_text("stale active-prefix asset\n", encoding="utf-8")

        with patch.object(clidarvi, "__file__", str(module_path)):
            found = clidarvi.find_asset_path("TERMS.md")

        self.assertEqual(found.resolve(), assets["TERMS.md"].resolve())

    def test_find_asset_path_binds_target_nested_below_user_base(self):
        user_root = self.data_path / "user-base"
        module_root = user_root / "vendor-target"
        target_root = module_root / "share" / "clidarvi"
        native_root = user_root / "share" / "clidarvi"
        assets, module_path, _ = self._write_wheel_install_fixture(
            module_root=module_root,
            asset_root=target_root,
            record_native_root=native_root,
        )
        stale = native_root / "TERMS.md"
        stale.parent.mkdir(parents=True)
        stale.write_text("stale user asset\n", encoding="utf-8")

        with patch.object(clidarvi, "__file__", str(module_path)):
            found = clidarvi.find_asset_path("TERMS.md")

        self.assertEqual(found.resolve(), assets["TERMS.md"].resolve())

    def test_find_asset_path_prioritizes_target_inside_unrelated_project(self):
        module_root = self.data_path / "host-project"
        target_root = module_root / "share" / "clidarvi"
        native_root = self.data_path / "share" / "clidarvi"
        assets, module_path, _ = self._write_wheel_install_fixture(
            module_root=module_root,
            asset_root=target_root,
            record_native_root=native_root,
        )
        (module_root / "pyproject.toml").write_text(
            '[project]\nname = "unrelated-host"\n',
            encoding="utf-8",
        )
        (module_root / "TERMS.md").write_text("unrelated host terms\n", encoding="utf-8")

        with patch.object(clidarvi, "__file__", str(module_path)):
            found = clidarvi.find_asset_path("TERMS.md")

        self.assertEqual(found.resolve(), assets["TERMS.md"].resolve())

    def test_find_asset_path_supports_target_at_exact_active_purelib(self):
        prefix_root = self.data_path / "prefix"
        module_root = prefix_root / "lib" / "python3.13" / "site-packages"
        target_root = module_root / "share" / "clidarvi"
        native_root = prefix_root / "share" / "clidarvi"
        assets, module_path, _ = self._write_wheel_install_fixture(
            module_root=module_root,
            asset_root=target_root,
            record_native_root=native_root,
        )
        stale = native_root / "TERMS.md"
        stale.parent.mkdir(parents=True)
        stale.write_text("stale interpreter asset\n", encoding="utf-8")

        with patch.object(clidarvi, "__file__", str(module_path)):
            found = clidarvi.find_asset_path("TERMS.md")

        self.assertEqual(found.resolve(), assets["TERMS.md"].resolve())

    def test_find_asset_path_supports_target_at_exact_user_site(self):
        user_root = self.data_path / "user-base"
        module_root = user_root / "lib" / "python3.13" / "site-packages"
        target_root = module_root / "share" / "clidarvi"
        native_root = user_root / "share" / "clidarvi"
        assets, module_path, _ = self._write_wheel_install_fixture(
            module_root=module_root,
            asset_root=target_root,
            record_native_root=native_root,
        )
        stale = native_root / "TERMS.md"
        stale.parent.mkdir(parents=True)
        stale.write_text("stale user-site asset\n", encoding="utf-8")

        with patch.object(clidarvi, "__file__", str(module_path)):
            found = clidarvi.find_asset_path("TERMS.md")

        self.assertEqual(found.resolve(), assets["TERMS.md"].resolve())

    def test_find_asset_path_binds_custom_prefix_install(self):
        custom_prefix = self.data_path / "custom-prefix"
        module_root = custom_prefix / "lib" / "python3.13" / "site-packages"
        installed_root = custom_prefix / "share" / "clidarvi"
        assets, module_path, _ = self._write_wheel_install_fixture(
            module_root=module_root,
            asset_root=installed_root,
            record_native_root=installed_root,
        )

        with patch.object(clidarvi, "__file__", str(module_path)):
            found = clidarvi.find_asset_path("TERMS.md")

        self.assertEqual(found.resolve(), assets["TERMS.md"].resolve())

    def test_find_asset_path_rejects_removed_target_before_stale_custom_prefix(self):
        prefix_root = self.data_path / "nested-target"
        module_root = prefix_root / "lib" / "python3.13" / "site-packages"
        target_root = module_root / "share" / "clidarvi"
        native_root = prefix_root / "share" / "clidarvi"
        assets, module_path, _ = self._write_wheel_install_fixture(
            module_root=module_root,
            asset_root=target_root,
            record_native_root=native_root,
        )
        shutil.copytree(target_root, native_root)
        (native_root / "TERMS.md").write_text("stale custom-prefix terms\n", encoding="utf-8")

        with patch.object(clidarvi, "__file__", str(module_path)):
            found = clidarvi.find_asset_path("TERMS.md")
            shutil.rmtree(module_root / "share")
            stale_only = clidarvi.find_asset_path("TERMS.md")

        self.assertEqual(found.resolve(), assets["TERMS.md"].resolve())
        self.assertIsNone(stale_only)

    def test_find_asset_path_rejects_two_complete_matching_layouts(self):
        prefix_root = self.data_path / "ambiguous"
        module_root = prefix_root / "lib" / "python3.13" / "site-packages"
        target_root = module_root / "share" / "clidarvi"
        native_root = prefix_root / "share" / "clidarvi"
        _, module_path, _ = self._write_wheel_install_fixture(
            module_root=module_root,
            asset_root=target_root,
            record_native_root=native_root,
        )
        shutil.copytree(target_root, native_root)

        with patch.object(clidarvi, "__file__", str(module_path)):
            found = clidarvi.find_asset_path("TERMS.md")

        self.assertIsNone(found)

    def test_find_asset_path_rejects_modified_owned_asset(self):
        prefix_root = self.data_path / "modified-asset"
        module_root = prefix_root / "lib" / "python3.13" / "site-packages"
        installed_root = prefix_root / "share" / "clidarvi"
        assets, module_path, _ = self._write_wheel_install_fixture(
            module_root=module_root,
            asset_root=installed_root,
            record_native_root=installed_root,
        )
        assets["TERMS.md"].write_text("modified after installation\n", encoding="utf-8")

        with patch.object(clidarvi, "__file__", str(module_path)):
            found = clidarvi.find_asset_path("TERMS.md")

        self.assertIsNone(found)

    def test_find_asset_path_rejects_modified_owned_module(self):
        prefix_root = self.data_path / "modified-module"
        module_root = prefix_root / "lib" / "python3.13" / "site-packages"
        installed_root = prefix_root / "share" / "clidarvi"
        _, module_path, _ = self._write_wheel_install_fixture(
            module_root=module_root,
            asset_root=installed_root,
            record_native_root=installed_root,
        )
        module_path.write_text("modified module\n", encoding="utf-8")

        with patch.object(clidarvi, "__file__", str(module_path)):
            found = clidarvi.find_asset_path("TERMS.md")

        self.assertIsNone(found)

    def test_find_asset_path_rejects_multiple_distribution_owners(self):
        prefix_root = self.data_path / "multiple-owners"
        module_root = prefix_root / "lib" / "python3.13" / "site-packages"
        installed_root = prefix_root / "share" / "clidarvi"
        _, module_path, _ = self._write_wheel_install_fixture(
            module_root=module_root,
            asset_root=installed_root,
            record_native_root=installed_root,
        )
        (module_root / "clidarvi-stale.dist-info").mkdir()

        with patch.object(clidarvi, "__file__", str(module_path)):
            found = clidarvi.find_asset_path("TERMS.md")

        self.assertIsNone(found)

    def test_find_asset_path_rejects_incomplete_runtime_record_set(self):
        prefix_root = self.data_path / "incomplete-record"
        module_root = prefix_root / "lib" / "python3.13" / "site-packages"
        installed_root = prefix_root / "share" / "clidarvi"
        _, module_path, dist_info = self._write_wheel_install_fixture(
            module_root=module_root,
            asset_root=installed_root,
            record_native_root=installed_root,
        )
        record_path = dist_info / "RECORD"
        rows = record_path.read_text(encoding="utf-8").splitlines(keepends=True)
        record_path.write_text(
            "".join(row for row in rows if not row.split(",", 1)[0].endswith("/TERMS.md")),
            encoding="utf-8",
        )

        with patch.object(clidarvi, "__file__", str(module_path)):
            found = clidarvi.find_asset_path("TERMS.md")

        self.assertIsNone(found)

    def test_find_asset_path_rejects_modified_distribution_metadata(self):
        prefix_root = self.data_path / "modified-metadata"
        module_root = prefix_root / "lib" / "python3.13" / "site-packages"
        installed_root = prefix_root / "share" / "clidarvi"
        _, module_path, dist_info = self._write_wheel_install_fixture(
            module_root=module_root,
            asset_root=installed_root,
            record_native_root=installed_root,
        )
        with (dist_info / "METADATA").open("ab") as handle:
            handle.write(b"locally modified\n")

        with patch.object(clidarvi, "__file__", str(module_path)):
            found = clidarvi.find_asset_path("TERMS.md")

        self.assertIsNone(found)

    def test_find_asset_path_rejects_symlinked_owned_asset(self):
        prefix_root = self.data_path / "symlinked-asset"
        module_root = prefix_root / "lib" / "python3.13" / "site-packages"
        installed_root = prefix_root / "share" / "clidarvi"
        assets, module_path, _ = self._write_wheel_install_fixture(
            module_root=module_root,
            asset_root=installed_root,
            record_native_root=installed_root,
        )
        terms_path = assets["TERMS.md"]
        real_path = installed_root / "terms-real"
        terms_path.replace(real_path)
        try:
            terms_path.symlink_to(real_path)
        except OSError as exc:
            self.skipTest(f"Symlink creation is unavailable: {exc}")

        with patch.object(clidarvi, "__file__", str(module_path)):
            found = clidarvi.find_asset_path("TERMS.md")

        self.assertIsNone(found)

    def test_bounded_asset_snapshot_rejects_resolve_runtime_error(self):
        asset_root = self.data_path / "looping-asset-root"
        asset_root.mkdir()

        with patch.object(
            clidarvi.Path,
            "resolve",
            side_effect=RuntimeError("symlink loop"),
        ):
            snapshot = clidarvi._bounded_asset_snapshot(asset_root, "TERMS.md")

        self.assertIsNone(snapshot)

    def test_installed_asset_lookup_rejects_candidate_root_resolve_runtime_error(self):
        prefix_root = self.data_path / "looping-prefix"
        module_root = prefix_root / "lib" / "python3.13" / "site-packages"
        installed_root = prefix_root / "share" / "clidarvi"
        _, module_path, _ = self._write_wheel_install_fixture(
            module_root=module_root,
            asset_root=installed_root,
            record_native_root=installed_root,
        )

        with patch.object(
            clidarvi.Path,
            "resolve",
            side_effect=RuntimeError("symlink loop"),
        ):
            present, snapshots = clidarvi._load_installed_wheel_asset_snapshots(module_path)

        self.assertTrue(present)
        self.assertIsNone(snapshots)

    def test_find_asset_path_rejects_module_resolve_runtime_error(self):
        with patch.object(
            clidarvi.Path,
            "resolve",
            side_effect=RuntimeError("symlink loop"),
        ):
            found = clidarvi.find_asset_path("TERMS.md")

        self.assertIsNone(found)

    def test_installed_asset_lookup_bounds_module_root_entries(self):
        module_path = self.data_path / "large-module-root" / "clidarvi.py"
        unrelated_entries = (
            self.data_path / f"unrelated-{index}"
            for index in range(clidarvi.MAX_WHEEL_MODULE_ROOT_ENTRIES + 1)
        )

        with patch.object(clidarvi.Path, "iterdir", return_value=unrelated_entries):
            present, snapshots = clidarvi._load_installed_wheel_asset_snapshots(module_path)

        self.assertTrue(present)
        self.assertIsNone(snapshots)

    def test_wheel_record_parser_rejects_unsafe_paths_and_encoding(self):
        digest = "A" * 43
        unsafe_records = (
            f"/share/clidarvi/TERMS.md,sha256={digest},0\n".encode(),
            f"..\\share\\clidarvi\\TERMS.md,sha256={digest},0\n".encode(),
            f"../nested/../share/clidarvi/TERMS.md,sha256={digest},0\n".encode(),
            f"../share/clidarvi/TERMS.md\x01,sha256={digest},0\n".encode(),
            ("../" + "a" * 1025 + f",sha256={digest},0\n").encode(),
            b"\xff,sha256=" + digest.encode() + b",0\n",
        )
        for raw_record in unsafe_records:
            with self.subTest(raw_record=raw_record[:80]):
                self.assertIsNone(clidarvi._parse_clidarvi_wheel_record(raw_record))

    def test_source_checkout_ignores_stale_target_assets_and_rejects_bad_dist_info(self):
        module_root = self.data_path / "source-checkout"
        module_root.mkdir()
        module_names = (
            "clidarvi",
            "clidarvi_core",
            "clidarvi_io",
            "clidarvi_policy",
            "clidarvi_workers",
        )
        for module_name in module_names:
            (module_root / f"{module_name}.py").write_text("# fixture\n", encoding="utf-8")
        (module_root / "pyproject.toml").write_text(
            "[project]\n"
            'name = "clidarvi"\n'
            "[project.gui-scripts]\n"
            'clidarvi = "clidarvi:main"\n'
            "[tool.setuptools]\n"
            'py-modules = ["clidarvi", "clidarvi_core", "clidarvi_io", '
            '"clidarvi_policy", "clidarvi_workers"]\n',
            encoding="utf-8",
        )
        source_terms = module_root / "TERMS.md"
        source_terms.write_text("source-owned terms\n", encoding="utf-8")
        stale_terms = module_root / "share" / "clidarvi" / "TERMS.md"
        stale_terms.parent.mkdir(parents=True)
        stale_terms.write_text("stale target terms\n", encoding="utf-8")
        module_path = module_root / "clidarvi.py"

        with patch.object(clidarvi, "__file__", str(module_path)):
            found = clidarvi.find_asset_path("TERMS.md")
            (module_root / "clidarvi-broken.dist-info").mkdir()
            blocked = clidarvi.find_asset_path("TERMS.md")

        self.assertEqual(found.resolve(), source_terms.resolve())
        self.assertIsNone(blocked)

    def test_find_asset_path_rejects_unsafe_requested_names(self):
        for name in ("../TERMS.md", "/TERMS.md", r"..\\TERMS.md", "C:/TERMS.md", ""):
            with self.subTest(name=name):
                self.assertIsNone(clidarvi.find_asset_path(name))

    def test_relative_xdg_data_home_is_ignored(self):
        fake_home = self.data_path / "home"
        expected = fake_home / ".local" / "share" / "Clidarvi"
        with (
            patch.object(clidarvi.sys, "platform", "linux"),
            patch.object(clidarvi.Path, "home", return_value=fake_home),
            patch.dict(clidarvi.os.environ, {"XDG_DATA_HOME": "relative-data"}),
            patch.object(clidarvi, "ensure_directory", side_effect=lambda path, private: path),
        ):
            result = clidarvi.get_application_data_directory()

        self.assertEqual(result, expected)
        self.assertTrue(result.is_absolute())

    def test_root_device_undo_and_selector_refresh(self):
        self.window.tree.clear()
        self.window.history = []
        self.window.history_index = -1
        self.window._make_node_item(
            self.window.tree,
            "Root device",
            metadata={
                "id": "root-device",
                "label": "Root device",
                "hostname": "root.example.net",
            },
        )
        self.window.capture_history_state()
        folder = QTreeWidgetItem(self.window.tree, ["Temporary"])
        folder.setData(0, Qt.ItemDataRole.UserRole, "folder")
        self.window.capture_history_state()

        self.window.go_back()

        self.assertIsNotNone(self.window._find_node_by_id("root-device"))
        selector_ids = [
            self.window.selector.itemData(index).get("device_ids", [])
            for index in range(self.window.selector.count())
            if isinstance(self.window.selector.itemData(index), dict)
        ]
        self.assertIn(["root-device"], selector_ids)

    def test_nested_duplicate_labels_target_by_stable_id(self):
        self.window.tree.clear()
        nested_folders = {}
        for site, device_id in (("Example City", "ams-core"), ("Sample City", "rtm-core")):
            folder = QTreeWidgetItem(self.window.tree, [site])
            folder.setData(0, Qt.ItemDataRole.UserRole, "folder")
            nested = QTreeWidgetItem(folder, ["Rack 1"])
            nested.setData(0, Qt.ItemDataRole.UserRole, "folder")
            nested_folders[site] = nested
            self.window._make_node_item(
                nested,
                "Core",
                metadata={
                    "id": device_id,
                    "label": "Core",
                    "hostname": f"{device_id}.example.net",
                },
            )
        self.window.populate_selector_from_tree()

        self.window.tree.setCurrentItem(nested_folders["Example City"])
        self.assertEqual(
            self.window.selector.currentData()["path"],
            ("Example City", "Rack 1"),
        )
        self.window.add_current_choice()

        self.window.tree.itemClicked.emit(nested_folders["Sample City"], 0)
        self.assertEqual(
            self.window.selector.currentData()["path"],
            ("Sample City", "Rack 1"),
        )
        self.window.add_current_choice()

        target_ids = {
            self.window.add_list.item(row).data(Qt.ItemDataRole.UserRole)
            for row in range(self.window.add_list.count())
        }
        self.assertEqual(target_ids, {"ams-core", "rtm-core"})
        target_paths = {
            self.window.add_list.item(row).text() for row in range(self.window.add_list.count())
        }
        self.assertEqual(
            target_paths,
            {
                "Example City / Rack 1 / Core",
                "Sample City / Rack 1 / Core",
            },
        )

    def test_clicking_a_site_adds_all_descendant_devices_as_targets_once(self):
        self.window.tree.clear()
        site = clidarvi.SiteRecord(name="Example City DC", city="Example City")
        site_item = self.window._make_folder_item(self.window.tree, site.name, site=site)
        rack = self.window._make_folder_item(site_item, "Rack 1")
        self.window._make_node_item(
            site_item,
            "Edge",
            metadata={"id": "ams-edge", "label": "Edge", "hostname": "edge.example.net"},
        )
        self.window._make_node_item(
            rack,
            "Core",
            metadata={"id": "ams-core", "label": "Core", "hostname": "core.example.net"},
        )
        other_site = self.window._make_folder_item(self.window.tree, "Sample City")
        self.window._make_node_item(
            other_site,
            "Other",
            metadata={"id": "rtm-other", "label": "Other", "hostname": "other.example.net"},
        )
        self.window.populate_selector_from_tree()

        self.window.tree.itemClicked.emit(site_item, 0)

        self.assertEqual(self.window.selector.currentData()["path"], ("Example City DC",))
        self.assertEqual(
            set(self.window.selector.currentData()["device_ids"]),
            {"ams-edge", "ams-core"},
        )
        self.window.add_btn.click()
        self.window.add_btn.click()

        target_ids = {
            self.window.add_list.item(row).data(Qt.ItemDataRole.UserRole)
            for row in range(self.window.add_list.count())
        }
        self.assertEqual(target_ids, {"ams-edge", "ams-core"})
        self.assertEqual(self.window.nodes_lbl.text(), "2 targets selected")
        self.assertIn("no new targets added", self.window.logs.toPlainText())

    def test_clicking_an_empty_folder_reports_that_it_has_no_devices(self):
        self.window.tree.clear()
        empty_site = self.window._make_folder_item(
            self.window.tree,
            "Empty POP",
            site=clidarvi.SiteRecord(name="Empty POP"),
        )
        self.window.populate_selector_from_tree()

        self.window.tree.itemClicked.emit(empty_site, 0)
        self.window.add_btn.click()

        self.assertEqual(self.window.add_list.count(), 0)
        self.assertIn("Empty POP: contains no devices", self.window.logs.toPlainText())

    def test_folder_scope_handles_partial_dedupe_and_same_label_collisions(self):
        self.window.tree.clear()
        folder = self.window._make_folder_item(self.window.tree, "Shared name")
        first = self.window._make_node_item(
            folder,
            "First",
            metadata={"id": "first", "label": "First", "hostname": "first.example.net"},
        )
        self.window._make_node_item(
            folder,
            "Second",
            metadata={"id": "second", "label": "Second", "hostname": "second.example.net"},
        )
        same_label_node = self.window._make_node_item(
            self.window.tree,
            "Shared name",
            metadata={
                "id": "same-label-node",
                "label": "Shared name",
                "hostname": "same-label.example.net",
            },
        )
        duplicate_label_node = self.window._make_node_item(
            self.window.tree,
            "Shared name",
            metadata={
                "id": "duplicate-label-node",
                "label": "Shared name",
                "hostname": "duplicate-label.example.net",
            },
        )
        self.window.populate_selector_from_tree()

        self.window.tree.itemClicked.emit(first, 0)
        self.window.add_btn.click()
        self.window.tree.itemClicked.emit(folder, 0)
        self.assertEqual(self.window.selector.currentData()["kind"], "folder")
        self.window.add_btn.click()

        target_ids = {
            self.window.add_list.item(row).data(Qt.ItemDataRole.UserRole)
            for row in range(self.window.add_list.count())
        }
        self.assertEqual(target_ids, {"first", "second"})
        self.assertIn("Shared name: 1 target(s) added", self.window.logs.toPlainText())

        self.window.tree.itemClicked.emit(same_label_node, 0)
        self.assertEqual(self.window.selector.currentData()["kind"], "node")
        self.assertEqual(
            self.window.selector.currentData()["device_ids"],
            ["same-label-node"],
        )
        self.window.tree.itemClicked.emit(duplicate_label_node, 0)
        self.assertEqual(
            self.window.selector.currentData()["device_ids"],
            ["duplicate-label-node"],
        )

    def test_close_uses_async_shutdown_path(self):
        self.window.close()
        self.application.processEvents()
        self.application.processEvents()

        self.assertTrue(self.window._shutdown_in_progress)
        self.assertTrue(self.window._shutdown_ready)

    def test_corrupt_primary_recovers_last_known_good_inventory(self):
        primary = self.window.get_save_path()
        backup = self.window._inventory_backup_path(primary)
        primary.write_text("{not valid json", encoding="utf-8")
        clidarvi.atomic_write_json(
            backup,
            clidarvi.encode_inventory_document(
                {
                    "_nodes": [
                        {
                            "id": "recovered",
                            "label": "Recovered",
                            "hostname": "recovered.example.net",
                        }
                    ]
                }
            ),
            secure_existing_parent=True,
        )
        self.window.tree.clear()

        loaded = self.window.load_tree_from_file()

        self.assertTrue(loaded)
        self.assertIsNotNone(self.window._find_node_by_id("recovered"))
        self.assertTrue(list(primary.parent.glob("devices.json.corrupt-*")))
        repaired_state = self.window._read_inventory_path(primary)
        self.assertEqual(repaired_state.tree["_nodes"][0]["id"], "recovered")

    def test_unpreserved_invalid_primary_is_never_overwritten(self):
        primary = self.window.get_save_path()
        original = b"X" * 1_025
        primary.write_bytes(original)
        clidarvi.atomic_write_json(
            self.window._inventory_backup_path(primary),
            clidarvi.encode_inventory_document({}),
            secure_existing_parent=True,
        )

        with patch.object(clidarvi, "MAX_IMPORT_FILE_SIZE", 1_024):
            self.assertTrue(self.window.load_tree_from_file())
            self.assertEqual(primary.read_bytes(), original)
            self.assertFalse(list(primary.parent.glob("devices.json.corrupt-*")))
            self.assertTrue(self.window._inventory_dirty)

            with patch.object(clidarvi.QMessageBox, "critical") as critical:
                self.assertFalse(self.window.save_tree_to_file())

        self.assertEqual(primary.read_bytes(), original)
        self.assertIn("Refusing to overwrite", critical.call_args.args[2])

    def test_oversized_valid_inventory_is_rejected_before_publication(self):
        primary = self.window.get_save_path()
        self.window.tree.clear()
        self.window._make_node_item(
            self.window.tree,
            "Large but valid device",
            metadata={
                "id": "large-valid-device",
                "label": "Large but valid device",
                "hostname": "large-valid-device.example.net",
            },
        )

        with (
            patch.object(clidarvi, "MAX_IMPORT_FILE_SIZE", 128),
            patch.object(clidarvi.QMessageBox, "critical") as critical,
        ):
            self.assertFalse(self.window.save_tree_to_file())

        self.assertFalse(primary.exists())
        self.assertIn("persisted-file limit", critical.call_args.args[2])

    def test_save_keeps_last_known_good_backup(self):
        self.window.tree.clear()
        self.window._make_node_item(
            self.window.tree,
            "Before",
            metadata={"id": "before", "label": "Before", "hostname": "before"},
        )
        self.window.save_tree_to_file()
        self.window.tree.clear()
        self.window._make_node_item(
            self.window.tree,
            "After",
            metadata={"id": "after", "label": "After", "hostname": "after"},
        )

        self.window.save_tree_to_file()

        backup_state = self.window._read_inventory_path(self.window._inventory_backup_path())
        self.assertEqual(backup_state.tree["_nodes"][0]["id"], "before")

    def test_unsaved_changes_are_visible_and_cancel_blocks_close(self):
        self.window._make_node_item(
            self.window.tree,
            "Unsaved probe",
            metadata={
                "id": "unsaved-probe",
                "label": "Unsaved probe",
                "hostname": "unsaved.example.net",
            },
        )
        self.window.capture_history_state()
        self.assertTrue(self.window._inventory_dirty)
        self.assertTrue(self.window.windowTitle().endswith(" *"))

        with patch.object(
            clidarvi.QMessageBox,
            "warning",
            return_value=clidarvi.QMessageBox.StandardButton.Cancel,
        ):
            self.window.close()
            self.application.processEvents()

        self.assertFalse(self.window._shutdown_in_progress)
        self.assertFalse(self.window._shutdown_ready)

        self.assertTrue(self.window.save_tree_to_file())
        self.assertFalse(self.window._inventory_dirty)
        self.assertFalse(self.window.windowTitle().endswith(" *"))

    def test_undo_to_the_saved_snapshot_clears_dirty_state(self):
        self.window.tree.clear()
        self.window._make_node_item(
            self.window.tree,
            "Saved",
            metadata={"id": "saved", "label": "Saved", "hostname": "saved.example.net"},
        )
        self.window.capture_history_state()
        self.assertTrue(self.window.save_tree_to_file())

        self.window._make_node_item(
            self.window.tree,
            "Later",
            metadata={"id": "later", "label": "Later", "hostname": "later.example.net"},
        )
        self.window.capture_history_state()
        self.assertTrue(self.window._inventory_dirty)

        self.window.go_back()

        self.assertIsNotNone(self.window._find_node_by_id("saved"))
        self.assertIsNone(self.window._find_node_by_id("later"))
        self.assertFalse(self.window._inventory_dirty)
        self.assertFalse(self.window.windowTitle().endswith(" *"))

    def test_duplicate_json_keys_and_nonregular_inputs_are_rejected(self):
        duplicate = self.data_path / "duplicate.json"
        duplicate.write_text(
            '{"schema_version":3,"tree":{"_nodes":[{"id":"x",'
            '"label":"x","hostname":"trusted","hostname":"attacker"}]},"sites":[]}',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "Duplicate JSON key"):
            self.window._read_inventory_path(duplicate)

        target = self.data_path / "target.json"
        target.write_text("{}", encoding="utf-8")
        link = self.data_path / "linked.json"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are unavailable on this platform")
        with self.assertRaisesRegex(ValueError, "regular, non-symlink"):
            clidarvi._read_bounded_regular_file(link, max_bytes=1024)

    def test_strict_json_rejects_nonfinite_numbers(self):
        for constant in ("NaN", "Infinity", "-Infinity", "1e999", "-1e999"):
            with self.subTest(constant=constant):
                raw = f'{{"schema_version": {constant}, "tree": {{}}, "sites": []}}'.encode()
                with self.assertRaisesRegex(ValueError, "Non-finite JSON number"):
                    clidarvi._load_strict_json_snapshot(raw)

        deeply_nested = b'{"tree":' + (b"[" * 10_000) + b"0" + (b"]" * 10_000) + b"}"
        with self.assertRaisesRegex(ValueError, "nesting depth"):
            clidarvi._load_strict_json_snapshot(deeply_nested)

    def test_invalid_json_unicode_and_constants_never_mutate_inventory_state(self):
        self.window.tree.clear()
        self.window._make_node_item(
            self.window.tree,
            "Original",
            metadata={
                "id": "original",
                "label": "Original",
                "hostname": "original.example.net",
            },
        )
        self.assertTrue(self.window.capture_history_state(mark_dirty=False))
        tree_before = self.window.tree_to_dict()
        history_before = self.window.history
        history_value_before = deepcopy(history_before)
        index_before = self.window.history_index
        dirty_before = self.window._inventory_dirty
        digest_before = self.window._saved_inventory_digest

        hostile_documents = {
            "surrogate": r'{"schema_version":3,"tree":{"_nodes":[{"id":"bad",'
            r'"label":"bad\ud800","hostname":"bad.example.net"}]},"sites":[]}',
            "nan": '{"schema_version":3,"tree":{},"sites":[],"extra":NaN}',
            "infinity": '{"schema_version":3,"tree":{},"sites":[],"extra":Infinity}',
            "negative-infinity": '{"schema_version":3,"tree":{},"sites":[],"extra":-Infinity}',
            "overflowing-positive-float": (
                '{"schema_version":3,"tree":{},"sites":[],"extra":1e999}'
            ),
            "overflowing-negative-float": (
                '{"schema_version":3,"tree":{},"sites":[],"extra":-1e999}'
            ),
        }
        for name, document in hostile_documents.items():
            with self.subTest(case=name):
                path = self.data_path / f"{name}.json"
                path.write_text(document, encoding="utf-8")
                with patch.object(
                    clidarvi.QFileDialog,
                    "getOpenFileName",
                    return_value=(str(path), "JSON Files (*.json)"),
                ):
                    self.window.import_tree_from_file()

                self.assertEqual(self.window.tree_to_dict(), tree_before)
                self.assertIs(self.window.history, history_before)
                self.assertEqual(self.window.history, history_value_before)
                self.assertEqual(self.window.history_index, index_before)
                self.assertEqual(self.window._inventory_dirty, dirty_before)
                self.assertEqual(self.window._saved_inventory_digest, digest_before)

    def test_json_and_xml_import_roll_back_after_post_apply_failure(self):
        self.window.tree.clear()
        site = clidarvi.SiteRecord(name="Original site", city="Example City")
        site_item = self.window._make_folder_item(self.window.tree, site.name, site=site)
        self.window._make_node_item(
            site_item,
            "Original",
            metadata={
                "id": "original",
                "label": "Original",
                "hostname": "original.example.net",
            },
        )
        self.assertTrue(self.window.capture_history_state(mark_dirty=False))
        self.window._make_node_item(
            self.window.tree,
            "Unsaved",
            metadata={
                "id": "unsaved",
                "label": "Unsaved",
                "hostname": "unsaved.example.net",
            },
        )
        self.assertTrue(self.window.capture_history_state())
        self.window.populate_selector_from_tree()
        for index in range(self.window.selector.count()):
            data = self.window.selector.itemData(index)
            if isinstance(data, dict) and data.get("device_ids") == ["original"]:
                self.window.selector.setCurrentIndex(index)
                break
        self.window.add_current_choice()

        tree_before = self.window.tree_to_dict()
        sites_before = self.window._site_placements_from_tree()
        history_before = self.window.history
        history_value_before = deepcopy(history_before)
        index_before = self.window.history_index
        dirty_before = self.window._inventory_dirty
        digest_before = self.window._saved_inventory_digest
        selector_before = [
            (
                self.window.selector.itemText(index),
                deepcopy(self.window.selector.itemData(index)),
            )
            for index in range(self.window.selector.count())
        ]
        selector_index_before = self.window.selector.currentIndex()
        targets_before = [
            (
                self.window.add_list.item(index).text(),
                self.window.add_list.item(index).data(Qt.ItemDataRole.UserRole),
            )
            for index in range(self.window.add_list.count())
        ]
        target_label_before = self.window.nodes_lbl.text()

        json_path = self.data_path / "replacement.json"
        json_path.write_text(
            '{"schema_version":3,"tree":{"_nodes":[{"id":"replacement",'
            '"label":"Replacement","hostname":"replacement.example.net"}]},"sites":[]}',
            encoding="utf-8",
        )
        xml_path = self.data_path / "replacement.xml"
        xml_path.write_text(
            '<Connections><Connection Name="Replacement" '
            'Hostname="replacement.example.net"/></Connections>',
            encoding="utf-8",
        )

        for path in (json_path, xml_path):
            with self.subTest(format=path.suffix):
                dialog_patch = patch.object(
                    clidarvi.QFileDialog,
                    "getOpenFileName",
                    return_value=(str(path), ""),
                )
                selector_failure = patch.object(
                    self.window,
                    "populate_selector_from_tree",
                    side_effect=RuntimeError("injected selector failure"),
                )
                if path.suffix == ".xml":
                    message_box = Mock()
                    merge_button = object()
                    replace_button = object()
                    cancel_button = object()
                    message_box.addButton.side_effect = [
                        merge_button,
                        replace_button,
                        cancel_button,
                    ]
                    message_box.clickedButton.return_value = replace_button
                    message_box_patch = patch.object(
                        clidarvi,
                        "QMessageBox",
                        return_value=message_box,
                    )
                else:
                    message_box_patch = patch.object(clidarvi, "QMessageBox", clidarvi.QMessageBox)

                with dialog_patch, selector_failure, message_box_patch:
                    self.window.import_tree_from_file()

                self.assertEqual(self.window.tree_to_dict(), tree_before)
                self.assertEqual(self.window._site_placements_from_tree(), sites_before)
                self.assertIs(self.window.history, history_before)
                self.assertEqual(self.window.history, history_value_before)
                self.assertEqual(self.window.history_index, index_before)
                self.assertEqual(self.window._inventory_dirty, dirty_before)
                self.assertEqual(self.window._saved_inventory_digest, digest_before)
                self.assertEqual(
                    [
                        (
                            self.window.selector.itemText(index),
                            self.window.selector.itemData(index),
                        )
                        for index in range(self.window.selector.count())
                    ],
                    selector_before,
                )
                self.assertEqual(self.window.selector.currentIndex(), selector_index_before)
                self.assertEqual(
                    [
                        (
                            self.window.add_list.item(index).text(),
                            self.window.add_list.item(index).data(Qt.ItemDataRole.UserRole),
                        )
                        for index in range(self.window.add_list.count())
                    ],
                    targets_before,
                )
                self.assertEqual(self.window.nodes_lbl.text(), target_label_before)

    @unittest.skipUnless(os.name == "posix", "FIFO behavior is POSIX-specific")
    def test_fifo_inventory_is_rejected_without_blocking(self):
        fifo = self.data_path / "inventory.fifo"
        os.mkfifo(fifo)

        with self.assertRaisesRegex(ValueError, "regular, non-symlink"):
            clidarvi._read_bounded_regular_file(fifo, max_bytes=1024)

    def test_xml_preflight_rejects_unknown_and_excess_elements(self):
        with self.assertRaisesRegex(ValueError, "Unsupported XML element"):
            self.window._parse_xml_snapshot(b"<Connections><Ignored/></Connections>")

        raw = b"<Connections>" + (b"<Connection Name='x'/>" * 4) + b"</Connections>"
        with (
            patch.object(clidarvi, "MAX_XML_ELEMENTS", 4),
            self.assertRaisesRegex(ValueError, "element count"),
        ):
            self.window._parse_xml_snapshot(raw)

    def test_tree_apply_rolls_back_after_a_qt_construction_failure(self):
        before = self.window.tree_to_dict()
        original = self.window._make_folder_item
        calls = 0

        def fail_on_second(parent, label, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("injected construction failure")
            return original(parent, label, **kwargs)

        with (
            patch.object(self.window, "_make_folder_item", side_effect=fail_on_second),
            self.assertRaisesRegex(RuntimeError, "injected construction failure"),
        ):
            self.window._apply_tree_dict({"First": {}, "Second": {}})

        self.assertEqual(self.window.tree_to_dict(), before)

    def test_invalid_manual_depth_is_rolled_back_without_dirty_state_drift(self):
        self.window.tree.clear()
        parent = self.window.tree
        for depth in range(clidarvi.MAX_DEVICE_TREE_DEPTH):
            parent = self.window._make_folder_item(parent, f"Level {depth}")
        self.assertTrue(self.window.capture_history_state(mark_dirty=False))
        before = self.window.tree_to_dict()

        self.window._make_folder_item(parent, "Too deep")
        with patch.object(clidarvi.QMessageBox, "warning") as warning:
            captured = self.window.capture_history_state()

        self.assertFalse(captured)
        warning.assert_called_once()
        self.assertEqual(self.window.tree_to_dict(), before)
        self.assertFalse(self.window._inventory_dirty)

    def test_history_digest_failure_cannot_partially_commit_an_undo_entry(self):
        self.window.tree.clear()
        self.window._make_node_item(
            self.window.tree,
            "Original",
            metadata={"id": "original", "label": "Original", "hostname": "original"},
        )
        self.assertTrue(self.window.capture_history_state(mark_dirty=False))
        history_before = self.window.history
        history_value_before = deepcopy(history_before)
        index_before = self.window.history_index
        tree_before = self.window.tree_to_dict()

        self.window._make_node_item(
            self.window.tree,
            "Uncommitted",
            metadata={
                "id": "uncommitted",
                "label": "Uncommitted",
                "hostname": "uncommitted",
            },
        )
        with (
            patch.object(
                self.window,
                "_inventory_digest",
                side_effect=ValueError("injected digest failure"),
            ),
            patch.object(clidarvi.QMessageBox, "warning"),
        ):
            captured = self.window.capture_history_state()

        self.assertFalse(captured)
        self.assertIs(self.window.history, history_before)
        self.assertEqual(self.window.history, history_value_before)
        self.assertEqual(self.window.history_index, index_before)
        self.assertEqual(self.window.tree_to_dict(), tree_before)
        self.assertFalse(self.window._inventory_dirty)

    def test_invalid_known_hosts_store_is_never_overwritten(self):
        known_hosts_path = self.window.get_known_hosts_path()
        invalid_content = "this is not a valid known-host entry\n"
        known_hosts_path.write_text(invalid_content, encoding="utf-8")
        server_key = paramiko.RSAKey.generate(1024)

        with (
            patch.object(self.window, "_ensure_network_terms_accepted", return_value=True),
            patch.object(clidarvi.QMessageBox, "critical"),
        ):
            trusted = self.window.ensure_host_key_trusted(
                "router.example.net",
                22,
                server_key=server_key,
            )

        self.assertFalse(trusted)
        self.assertEqual(known_hosts_path.read_text(encoding="utf-8"), invalid_content)

    def test_changed_host_key_is_detected_and_only_replaced_on_explicit_confirm(self):
        original_key = paramiko.RSAKey.generate(1024)
        rotated_key = paramiko.RSAKey.generate(1024)
        known_hosts_path = self.window.get_known_hosts_path()

        # Trust the original key first.
        with (
            patch.object(self.window, "_ensure_network_terms_accepted", return_value=True),
            patch.object(
                clidarvi.QMessageBox, "exec", return_value=clidarvi.QMessageBox.StandardButton.Yes
            ),
        ):
            self.assertTrue(
                self.window.ensure_host_key_trusted(
                    "router.example.net", 22, server_key=original_key
                )
            )
        stored_after_trust = known_hosts_path.read_text(encoding="utf-8")

        # A different key for the same host must be flagged as a mismatch; an
        # aborted mismatch leaves the stored key untouched and returns False.
        with (
            patch.object(self.window, "_ensure_network_terms_accepted", return_value=True),
            patch.object(
                clidarvi.QMessageBox, "exec", return_value=clidarvi.QMessageBox.StandardButton.No
            ) as prompt,
        ):
            trusted = self.window.ensure_host_key_trusted(
                "router.example.net", 22, server_key=rotated_key
            )
        self.assertFalse(trusted)
        prompt.assert_called()
        self.assertEqual(known_hosts_path.read_text(encoding="utf-8"), stored_after_trust)

        # Only an explicit confirmation replaces the pinned key.
        with (
            patch.object(self.window, "_ensure_network_terms_accepted", return_value=True),
            patch.object(
                clidarvi.QMessageBox, "exec", return_value=clidarvi.QMessageBox.StandardButton.Yes
            ),
        ):
            replaced = self.window.ensure_host_key_trusted(
                "router.example.net", 22, server_key=rotated_key
            )
        self.assertTrue(replaced)
        self.assertNotEqual(known_hosts_path.read_text(encoding="utf-8"), stored_after_trust)
        # The rotated key is now the trusted one; re-presenting it is a clean match.
        with patch.object(self.window, "_ensure_network_terms_accepted", return_value=True):
            self.assertTrue(
                self.window.ensure_host_key_trusted(
                    "router.example.net", 22, server_key=rotated_key
                )
            )

    def test_only_the_clidarvi_host_key_store_satisfies_the_automation_gate(self):
        key = paramiko.RSAKey.generate(1024)
        fake_home = self.data_path / "home"
        system_store = fake_home / ".ssh" / "known_hosts"
        system_store.parent.mkdir(parents=True)
        system_keys = paramiko.HostKeys()
        system_keys.add("router.example.net", key.get_name(), key)
        system_keys.save(str(system_store))

        with patch.object(clidarvi.Path, "home", return_value=fake_home):
            self.assertFalse(self.window._has_locally_trusted_host_key("router.example.net", 22))

        app_keys = paramiko.HostKeys()
        app_keys.add("router.example.net", key.get_name(), key)
        app_keys.save(str(self.window.get_known_hosts_path()))
        self.assertTrue(self.window._has_locally_trusted_host_key("router.example.net", 22))

    def test_host_key_worker_start_failure_is_sanitized_and_rolled_back(self):
        with (
            patch.object(self.window, "_ensure_network_terms_accepted", return_value=True),
            patch.object(
                clidarvi.HostKeyFetchWorker,
                "start",
                side_effect=RuntimeError("thread\x1b[31m failure"),
            ),
            patch.object(clidarvi.QMessageBox, "critical") as critical,
        ):
            self.window.verify_host_key_async("router.example.net", 22)

        self.assertFalse(self.window._host_key_workers)
        critical.assert_called_once()
        message = critical.call_args.args[2]
        self.assertIn("<redacted> (terminal-control output)", message)
        self.assertNotIn("\x1b", message)

    def test_current_host_key_result_forwards_the_exact_verified_key(self):
        server_key = paramiko.RSAKey.generate(1024)
        callback = Mock()
        with patch.object(self.window, "ensure_host_key_trusted", return_value=True):
            self.window._on_host_key_fetched(
                "router.example.net",
                22,
                server_key,
                callback,
            )

        callback.assert_called_once_with(server_key)

    def test_late_cli_host_key_result_cannot_open_a_hidden_session(self):
        self.window.cli_btn.click()
        self.application.processEvents()
        self.window.tree.clear()
        record = clidarvi.DeviceRecord(
            id="late-cli",
            label="Late CLI",
            hostname="late.example.net",
        )
        self.window._make_node_item(
            self.window.tree,
            record.label,
            record.hostname,
            record.to_mapping(),
        )
        self.window._cli_request_generation += 1
        token = self.window._cli_request_generation
        callback = Mock()
        server_key = paramiko.RSAKey.generate(1024)

        self.window.automation_btn.click()
        self.application.processEvents()
        with patch.object(self.window, "ensure_host_key_trusted") as trust:
            self.window._on_host_key_fetched(
                record.hostname,
                record.port,
                server_key,
                callback,
                token,
                True,
                record,
            )

        trust.assert_not_called()
        callback.assert_not_called()
        self.assertTrue(self.window.automation_btn.isChecked())
        with patch.object(clidarvi.QMessageBox, "critical") as critical:
            self.window._on_host_key_fetch_failed(
                record.hostname,
                record.port,
                "late failure",
                token,
                True,
                record,
            )
        critical.assert_not_called()

    def test_synchronous_host_key_fallback_fails_closed_without_network_io(self):
        with (
            patch.object(self.window, "_ensure_network_terms_accepted", return_value=True),
            patch.object(clidarvi, "HostKeyFetchWorker") as worker_factory,
            patch.object(clidarvi.QMessageBox, "critical") as critical,
        ):
            trusted = self.window.ensure_host_key_trusted("router.example.net", 22)

        self.assertFalse(trusted)
        worker_factory.assert_not_called()
        critical.assert_called_once()
        self.assertIn("background verifier", critical.call_args.args[2])

    def test_legal_notice_decodes_the_verified_snapshot_not_a_later_path_read(self):
        paths, resolve = self._risk_assets()
        snapshot = resolve("TERMS.md")
        paths["TERMS.md"].write_text("later unverified replacement\n", encoding="utf-8")

        with patch.object(clidarvi, "_resolve_bundled_asset", return_value=snapshot):
            notice = clidarvi.LegalDialog._read_notice("TERMS.md")

        self.assertIn("Test operational terms", notice)
        self.assertNotIn("later unverified replacement", notice)

    def test_risk_dialog_defaults_to_decline_and_saves_the_exact_snapshot(self):
        _paths, resolve = self._risk_assets()
        with patch.object(clidarvi, "_resolve_bundled_asset", side_effect=resolve):
            snapshot = clidarvi._load_risk_terms_snapshot()
        dialog = clidarvi.RiskAcknowledgementDialog(snapshot, self.window)
        export_path = self.data_path / "accepted-terms.txt"
        try:
            self.assertTrue(dialog.isModal())
            self.assertEqual(
                dialog.windowModality(),
                Qt.WindowModality.ApplicationModal,
            )
            # The documented gate is exactly these four acknowledgements; a
            # silently dropped or renamed box must fail here.
            self.assertEqual(
                [item[0] for item in clidarvi.RISK_ACKNOWLEDGEMENTS],
                [
                    "experimental_alpha",
                    "outage_and_rollback_risk",
                    "authorization_and_recovery",
                    "warranty_and_liability",
                ],
            )
            self.assertEqual(len(dialog.acknowledgement_checkboxes), 4)
            self.assertTrue(
                all(not checkbox.isChecked() for checkbox in dialog.acknowledgement_checkboxes)
            )
            self.assertFalse(dialog.accept_button.isEnabled())
            dialog.accept()
            self.assertNotEqual(dialog.result(), clidarvi.QDialog.DialogCode.Accepted)
            self.assertIn(snapshot["bundle_sha256"], dialog.metadata_label.text())
            self.assertIn(
                "does not ask you to accept the GPL",
                dialog.scope_label.text(),
            )
            self.assertIn("declared application version", dialog.scope_label.text())
            self.assertIn("does not verify the running executable", dialog.scope_label.text())
            self.assertIn("Declared application version:", dialog.metadata_label.text())
            self.assertIn(
                "does not hash or verify the running executable",
                snapshot["accepted_copy"],
            )

            with patch.object(
                clidarvi.QFileDialog,
                "getSaveFileName",
                return_value=(str(export_path), "Text Files (*.txt)"),
            ):
                dialog.save_button.click()
            self.assertEqual(
                export_path.read_bytes(),
                snapshot["accepted_copy"].encode("utf-8"),
            )

            for checkbox in dialog.acknowledgement_checkboxes:
                checkbox.setChecked(True)
            self.assertTrue(dialog.accept_button.isEnabled())
            dialog.accept()
            self.assertEqual(dialog.result(), clidarvi.QDialog.DialogCode.Accepted)
        finally:
            dialog.deleteLater()

    def test_missing_terms_fail_closed_before_any_host_key_worker(self):
        with (
            patch.object(clidarvi, "_resolve_bundled_asset", return_value=None),
            patch.object(clidarvi, "HostKeyFetchWorker") as worker_factory,
            patch.object(clidarvi.QMessageBox, "critical") as critical,
        ):
            self.window.verify_host_key_async("router.example.net", 22)

        worker_factory.assert_not_called()
        critical.assert_called_once()
        self.assertIn("Network features are disabled", critical.call_args.args[2])

    def test_unfilled_publisher_placeholders_fail_closed_before_the_dialog(self):
        for publisher in (
            clidarvi.RISK_PUBLISHER_PLACEHOLDER,
            "TODO: add publisher legal name and contact",
        ):
            with self.subTest(publisher=publisher):
                _paths, resolve = self._risk_assets(publisher=publisher)
                with (
                    patch.object(clidarvi, "_resolve_bundled_asset", side_effect=resolve),
                    patch.object(clidarvi.RiskAcknowledgementDialog, "exec") as execute,
                    patch.object(clidarvi.QMessageBox, "critical") as critical,
                ):
                    accepted = self.window._ensure_network_terms_accepted()

                self.assertFalse(accepted)
                execute.assert_not_called()
                critical.assert_called_once()
                self.assertIn("publisher placeholder", critical.call_args.args[2])
                self.assertFalse(self.window.get_risk_acknowledgement_path().exists())

        _paths, resolve = self._risk_assets(publisher="Jane Example <contact@example.invalid>")
        with patch.object(clidarvi, "_resolve_bundled_asset", side_effect=resolve):
            snapshot = clidarvi._load_risk_terms_snapshot()
        self.assertEqual(snapshot["declared_app_version"], clidarvi.__version__)

    def test_declining_terms_blocks_automation_cli_and_host_key_workers(self):
        _paths, resolve = self._risk_assets()
        record = clidarvi.DeviceRecord(label="Lab router", hostname="router.example.net")
        with (
            patch.object(clidarvi, "_resolve_bundled_asset", side_effect=resolve),
            patch.object(
                clidarvi.RiskAcknowledgementDialog,
                "exec",
                return_value=clidarvi.QDialog.DialogCode.Rejected,
            ),
            patch.object(clidarvi, "AutomationWorker") as automation_factory,
            patch.object(clidarvi, "HostKeyFetchWorker") as host_key_factory,
            patch.object(clidarvi, "InteractiveSSHWorker") as cli_factory,
            patch.object(clidarvi.QInputDialog, "getText") as credential_prompt,
        ):
            self.window.run_automation()
            self.window.verify_host_key_async(record.hostname, record.port)
            self.window._open_ssh_session(record)
            trusted = self.window.ensure_host_key_trusted(record.hostname, record.port)

        automation_factory.assert_not_called()
        host_key_factory.assert_not_called()
        cli_factory.assert_not_called()
        credential_prompt.assert_not_called()
        # The removed synchronous fallback must refuse before any network worker.
        self.assertFalse(trusted)
        self.assertFalse(self.window.get_risk_acknowledgement_path().exists())

    def _seed_ready_automation(self):
        """Wire up a run_automation that would reach AutomationWorker if allowed."""
        self.window.tree.clear()
        self.window._make_node_item(
            self.window.tree,
            "Lab router",
            metadata={
                "id": "run-probe",
                "label": "Lab router",
                "hostname": "router.example.net",
                "vendor": "Cisco IOS/IOS-XE",
                "device_type": "cisco_ios",
            },
        )
        node = self.window._find_node_by_id("run-probe")
        from PyQt6.QtWidgets import QListWidgetItem

        target = QListWidgetItem(self.window._display_path_for_item(node))
        target.setData(Qt.ItemDataRole.UserRole, "run-probe")
        self.window.add_list.addItem(target)
        self.window.commands.setPlainText("show version")

    def _seed_automation_records(self, records, commands_text):
        """Select exact records without exercising unrelated selector behavior."""

        from PyQt6.QtWidgets import QListWidgetItem

        self.window.tree.clear()
        self.window.add_list.clear()
        for record in records:
            self.window._make_node_item(
                self.window.tree,
                record.label,
                metadata=record.to_mapping(),
            )
            target = QListWidgetItem(record.label)
            target.setData(Qt.ItemDataRole.UserRole, record.id)
            self.window.add_list.addItem(target)
        self.window.commands.setPlainText(commands_text)

    @staticmethod
    def _automation_record(device_type, *, suffix="one", vendor=None):
        return clidarvi.DeviceRecord(
            id=f"{device_type}-{suffix}",
            label=f"{device_type} {suffix}",
            hostname=f"{device_type.replace('_', '-')}-{suffix}.example.net",
            vendor=vendor or device_type,
            device_type=device_type,
            device_role="switch",
        )

    @staticmethod
    def _dispatching_worker_factory():
        """Use the real command parser while replacing only dispatched workers."""

        worker_class = clidarvi.AutomationWorker
        dispatches = []

        def factory(devices, commands_text, *args, **kwargs):
            if not devices:
                return worker_class(devices, commands_text, *args, **kwargs)
            worker = Mock()
            worker.was_stopped.return_value = False
            worker.had_error.return_value = False
            dispatches.append(
                {
                    "devices": devices,
                    "commands_text": commands_text,
                    "args": args,
                    "kwargs": kwargs,
                    "worker": worker,
                }
            )
            return worker

        return dispatches, factory

    def test_risk_gate_is_the_only_thing_stopping_a_ready_automation(self):
        _paths, resolve = self._risk_assets()

        # Positive control: with the seeded state and terms accepted, the gate
        # is the sole obstacle and an AutomationWorker is constructed. This is
        # what makes the negative assertion below non-vacuous.
        self._seed_ready_automation()
        with (
            patch.object(self.window, "_ensure_network_terms_accepted", return_value=True),
            patch.object(self.window, "_has_locally_trusted_host_key", return_value=True),
            patch.object(
                clidarvi.QInputDialog, "getText", side_effect=[("admin", True), ("pw", True)]
            ),
            patch.object(clidarvi, "AutomationWorker") as accepted_factory,
        ):
            self.window.run_automation()
        self.assertTrue(accepted_factory.called)
        if self.window._automation_worker is not None:
            self.window._automation_worker = None

        # Same ready state, terms declined: no worker is ever constructed.
        self._seed_ready_automation()
        with (
            patch.object(clidarvi, "_resolve_bundled_asset", side_effect=resolve),
            patch.object(
                clidarvi.RiskAcknowledgementDialog,
                "exec",
                return_value=clidarvi.QDialog.DialogCode.Rejected,
            ),
            patch.object(self.window, "_has_locally_trusted_host_key", return_value=True),
            patch.object(clidarvi.QInputDialog, "getText") as credential_prompt,
            patch.object(clidarvi, "AutomationWorker") as declined_factory,
        ):
            self.window.run_automation()
        declined_factory.assert_not_called()
        credential_prompt.assert_not_called()

    def test_general_automation_blocked_profiles_ignore_experimental_opt_in(self):
        profiles = (
            ("Other", "generic"),
            ("Ubiquiti UniFi OS (Live CLI only)", "generic"),
        )
        for vendor, device_type in profiles:
            with self.subTest(device_type=device_type):
                self.window.add_list.clear()
                self._seed_ready_automation()
                self.window.experimental_automation_cb.setChecked(True)
                node = self.window._find_node_by_id("run-probe")
                metadata = dict(node.data(0, Qt.ItemDataRole.UserRole))
                metadata.update({"vendor": vendor, "device_type": device_type})
                node.setData(0, Qt.ItemDataRole.UserRole, metadata)

                with (
                    patch.object(self.window, "_ensure_network_terms_accepted", return_value=True),
                    patch.object(self.window, "_has_locally_trusted_host_key") as host_key,
                    patch.object(self.window, "_confirm_experimental_automation") as confirm,
                    patch.object(clidarvi.QInputDialog, "getText") as credential_prompt,
                    patch.object(clidarvi.QMessageBox, "warning") as warning,
                    patch.object(clidarvi, "AutomationWorker") as worker_factory,
                ):
                    self.window.run_automation()

                credential_prompt.assert_not_called()
                host_key.assert_not_called()
                confirm.assert_not_called()
                worker_factory.assert_not_called()
                warning.assert_called_once()
                self.assertEqual(warning.call_args.args[1], "Invalid Experimental Automation Scope")
                self.assertIn("generic ssh", warning.call_args.args[2].lower())

    def test_experimental_profiles_are_blocked_while_opt_in_is_unchecked(self):
        self.assertEqual(
            set(clidarvi.EXPERIMENTAL_AUTOMATION_DEVICE_TYPES),
            {"aruba_os", "cisco_wlc", "fortinet"},
        )
        for device_type in sorted(clidarvi.EXPERIMENTAL_AUTOMATION_DEVICE_TYPES):
            with self.subTest(device_type=device_type):
                record = self._automation_record(device_type)
                self._seed_automation_records([record], "show version")
                self.assertFalse(self.window.experimental_automation_cb.isChecked())

                with (
                    patch.object(self.window, "_ensure_network_terms_accepted", return_value=True),
                    patch.object(self.window, "_has_locally_trusted_host_key") as host_key,
                    patch.object(self.window, "_confirm_experimental_automation") as confirm,
                    patch.object(clidarvi.QInputDialog, "getText") as credential_prompt,
                    patch.object(clidarvi.QMessageBox, "warning") as warning,
                    patch.object(clidarvi, "AutomationWorker") as worker_factory,
                ):
                    self.window.run_automation()

                host_key.assert_not_called()
                confirm.assert_not_called()
                credential_prompt.assert_not_called()
                worker_factory.assert_not_called()
                warning.assert_called_once()
                self.assertIn(device_type, warning.call_args.args[2])

    def test_experimental_runtime_mismatch_blocks_before_host_or_credentials(self):
        record = self._automation_record("cisco_wlc")
        self._seed_automation_records([record], "show sysinfo")
        self.window.experimental_automation_cb.setChecked(True)

        with (
            patch.object(self.window, "_ensure_network_terms_accepted", return_value=True),
            patch.object(
                clidarvi,
                "validate_experimental_automation_runtime",
                side_effect=ValueError("requires audited Netmiko 4.7.0"),
            ) as runtime_check,
            patch.object(self.window, "_has_locally_trusted_host_key") as host_key,
            patch.object(self.window, "_confirm_experimental_automation") as confirm,
            patch.object(clidarvi.QInputDialog, "getText") as credential_prompt,
            patch.object(clidarvi.QMessageBox, "warning") as warning,
            patch.object(clidarvi, "AutomationWorker") as worker_factory,
        ):
            self.window.run_automation()

        runtime_check.assert_called_once_with()
        host_key.assert_not_called()
        confirm.assert_not_called()
        credential_prompt.assert_not_called()
        worker_factory.assert_not_called()
        warning.assert_called_once()
        self.assertEqual(warning.call_args.args[1], "Experimental Automation Runtime Mismatch")
        self.assertIn("No credentials", warning.call_args.args[2])

    def test_checked_experimental_run_rejects_wrong_or_cancelled_phrase(self):
        record = self._automation_record("aruba_os")
        phrase = clidarvi.EXPERIMENTAL_AUTOMATION_CONFIRMATION_PHRASE
        for response in (("wrong phrase", True), (phrase, False)):
            with self.subTest(response=response):
                self._seed_automation_records([record], "show version")
                self.window.experimental_automation_cb.setChecked(True)
                dispatches, worker_factory = self._dispatching_worker_factory()

                with (
                    patch.object(self.window, "_ensure_network_terms_accepted", return_value=True),
                    patch.object(self.window, "_has_locally_trusted_host_key", return_value=True),
                    patch.object(
                        clidarvi.QInputDialog, "getText", return_value=response
                    ) as text_prompt,
                    patch.object(clidarvi, "AutomationWorker", side_effect=worker_factory),
                ):
                    self.window.run_automation()

                self.assertEqual(text_prompt.call_count, 1)
                self.assertIn(phrase, text_prompt.call_args.args[2])
                self.assertFalse(dispatches)
                self.assertFalse(self.window.experimental_automation_cb.isChecked())
                self.assertIn("Experimental Automation cancelled", self.window.logs.toPlainText())

    def test_experimental_confirmation_discloses_hidden_setup_and_no_guarantees(self):
        record = self._automation_record("cisco_wlc")
        phrase = clidarvi.EXPERIMENTAL_AUTOMATION_CONFIRMATION_PHRASE

        with patch.object(
            clidarvi.QInputDialog,
            "getText",
            return_value=(phrase, False),
        ) as text_prompt:
            accepted = self.window._confirm_experimental_automation(record)

        self.assertFalse(accepted)
        title = text_prompt.call_args.args[1]
        prompt = text_prompt.call_args.args[2]
        self.assertIn("Isolated Lab Only", title)
        self.assertIn(record.label, prompt)
        self.assertIn(record.hostname, prompt)
        self.assertIn(record.device_type, prompt)
        self.assertIn("config paging disable", prompt)
        self.assertIn("hidden setup bytes", prompt)
        self.assertIn("not a compatibility", prompt.lower())
        self.assertIn("stop cannot roll back", prompt.lower())
        self.assertIn(phrase, prompt)

    def test_exact_experimental_phrase_dispatches_one_target_with_explicit_worker_flag(self):
        record = self._automation_record("aruba_os")
        self._seed_automation_records([record], "show version")
        self.window.experimental_automation_cb.setChecked(True)
        dispatches, worker_factory = self._dispatching_worker_factory()
        phrase = clidarvi.EXPERIMENTAL_AUTOMATION_CONFIRMATION_PHRASE

        with (
            patch.object(self.window, "_ensure_network_terms_accepted", return_value=True),
            patch.object(self.window, "_has_locally_trusted_host_key", return_value=True),
            patch.object(
                clidarvi.QInputDialog,
                "getText",
                side_effect=[(phrase, True), ("admin", True), ("password", True)],
            ) as text_prompt,
            patch.object(clidarvi, "AutomationWorker", side_effect=worker_factory),
        ):
            self.window.run_automation()

        self.assertEqual(len(dispatches), 1)
        dispatch = dispatches[0]
        self.assertEqual(len(dispatch["devices"]), 1)
        self.assertEqual(dispatch["devices"][0]["device_type"], "aruba_os")
        self.assertTrue(dispatch["kwargs"]["allow_experimental_automation"])
        self.assertFalse(dispatch["kwargs"]["allow_destructive"])
        self.assertFalse(dispatch["kwargs"]["save_config"])
        self.assertFalse(dispatch["kwargs"]["enter_enable_mode"])
        self.assertIn(phrase, text_prompt.call_args_list[0].args[2])
        self.assertFalse(self.window.experimental_automation_cb.isChecked())
        self.window._automation_worker = None

    def test_experimental_multiple_or_mixed_scope_blocks_before_host_or_credentials(self):
        aruba = self._automation_record("aruba_os")
        fortinet = self._automation_record("fortinet")
        cisco = self._automation_record("cisco_ios")
        for label, records in (
            ("multiple experimental", [aruba, fortinet]),
            ("mixed experimental and stable", [aruba, cisco]),
        ):
            with self.subTest(label=label):
                self._seed_automation_records(records, "show version")
                self.window.experimental_automation_cb.setChecked(True)

                with (
                    patch.object(self.window, "_ensure_network_terms_accepted", return_value=True),
                    patch.object(self.window, "_has_locally_trusted_host_key") as host_key,
                    patch.object(self.window, "_confirm_experimental_automation") as confirm,
                    patch.object(clidarvi.QInputDialog, "getText") as credential_prompt,
                    patch.object(clidarvi.QMessageBox, "warning") as warning,
                    patch.object(clidarvi, "AutomationWorker") as worker_factory,
                ):
                    self.window.run_automation()

                host_key.assert_not_called()
                confirm.assert_not_called()
                credential_prompt.assert_not_called()
                worker_factory.assert_not_called()
                warning.assert_called_once()
                self.assertEqual(warning.call_args.args[1], "Invalid Experimental Automation Scope")
                self.assertFalse(self.window.experimental_automation_cb.isChecked())

    def test_stable_cisco_and_panos_dispatch_without_experimental_confirmation(self):
        cases = (
            ("cisco_ios", "show version"),
            ("paloalto_panos", "show system info"),
        )
        for device_type, command in cases:
            with self.subTest(device_type=device_type):
                record = self._automation_record(device_type)
                self._seed_automation_records([record], command)
                dispatches, worker_factory = self._dispatching_worker_factory()

                with (
                    patch.object(self.window, "_ensure_network_terms_accepted", return_value=True),
                    patch.object(self.window, "_has_locally_trusted_host_key", return_value=True),
                    patch.object(
                        self.window, "_confirm_experimental_automation"
                    ) as experimental_confirm,
                    patch.object(
                        clidarvi.QInputDialog,
                        "getText",
                        side_effect=[("admin", True), ("password", True)],
                    ),
                    patch.object(clidarvi, "AutomationWorker", side_effect=worker_factory),
                ):
                    self.window.run_automation()

                experimental_confirm.assert_not_called()
                self.assertEqual(len(dispatches), 1)
                dispatch = dispatches[0]
                self.assertFalse(dispatch["kwargs"]["allow_experimental_automation"])
                self.assertFalse(dispatch["kwargs"]["save_config"])
                self.assertFalse(dispatch["kwargs"]["enter_enable_mode"])
                self.window._automation_worker = None
                self.window._set_automation_running(False)
                self.window._clear_password_buffers()

    def test_experimental_opt_in_never_converts_udm_to_general_automation(self):
        record = self._automation_record(
            clidarvi_workers.UDM_READ_ONLY_DEVICE_TYPE,
            vendor=clidarvi.UBIQUITI_UNIFI_OS_VENDOR,
        )
        self._seed_automation_records([record], clidarvi.UDM_OBSERVATION_PRESET_TEXT)
        self.window.experimental_automation_cb.setChecked(True)

        with (
            patch.object(self.window, "_ensure_network_terms_accepted", return_value=True),
            patch.object(self.window, "_trusted_server_key_snapshot") as trusted_key,
            patch.object(self.window, "_confirm_udm_observation_plan") as udm_confirm,
            patch.object(self.window, "_confirm_experimental_automation") as exp_confirm,
            patch.object(clidarvi.QInputDialog, "getText") as credential_prompt,
            patch.object(clidarvi.QMessageBox, "warning") as warning,
            patch.object(clidarvi, "UdmReadOnlyAutomationWorker") as udm_factory,
            patch.object(clidarvi, "AutomationWorker") as general_factory,
        ):
            self.window.run_automation()

        trusted_key.assert_not_called()
        udm_confirm.assert_not_called()
        exp_confirm.assert_not_called()
        credential_prompt.assert_not_called()
        udm_factory.assert_not_called()
        general_factory.assert_not_called()
        warning.assert_called_once()
        self.assertEqual(warning.call_args.args[1], "Invalid Experimental Automation Scope")

    def test_experimental_and_high_risk_typed_gates_compose_before_dispatch(self):
        phrase = clidarvi.EXPERIMENTAL_AUTOMATION_CONFIRMATION_PHRASE
        cases = (
            ("aruba_os", "traceroute example.net", "RUN UNKNOWN", False),
            ("fortinet", "execute reboot", "RUN DESTRUCTIVE", True),
        )
        for device_type, command, risk_phrase, allow_destructive in cases:
            with self.subTest(device_type=device_type, risk_phrase=risk_phrase):
                record = self._automation_record(device_type)
                self._seed_automation_records([record], command)
                self.window.experimental_automation_cb.setChecked(True)
                dispatches, worker_factory = self._dispatching_worker_factory()

                with (
                    patch.object(self.window, "_ensure_network_terms_accepted", return_value=True),
                    patch.object(self.window, "_has_locally_trusted_host_key", return_value=True),
                    patch.object(
                        clidarvi.QInputDialog,
                        "getText",
                        side_effect=[
                            (risk_phrase, True),
                            (phrase, True),
                            ("admin", True),
                            ("password", True),
                        ],
                    ) as text_prompt,
                    patch.object(
                        clidarvi.QMessageBox,
                        "exec",
                        return_value=clidarvi.QMessageBox.StandardButton.Yes,
                    ) as risk_approval,
                    patch.object(clidarvi, "AutomationWorker", side_effect=worker_factory),
                ):
                    self.window.run_automation()

                self.assertEqual(len(dispatches), 1)
                dispatch = dispatches[0]
                self.assertTrue(dispatch["kwargs"]["allow_experimental_automation"])
                self.assertEqual(dispatch["kwargs"]["allow_destructive"], allow_destructive)
                self.assertIn(risk_phrase, text_prompt.call_args_list[0].args[2])
                self.assertIn(phrase, text_prompt.call_args_list[1].args[2])
                risk_approval.assert_called_once()
                self.window._automation_worker = None
                self.window._set_automation_running(False)
                self.window._clear_password_buffers()

    def test_ubiquiti_platform_is_distinct_and_node_dialog_selects_it_explicitly(self):
        self.assertEqual(
            clidarvi.VENDOR_MAP[clidarvi.UBIQUITI_UNIFI_OS_VENDOR],
            clidarvi_workers.UDM_READ_ONLY_DEVICE_TYPE,
        )
        self.assertIn("generic", clidarvi_workers.AUTOMATION_LIVE_CLI_ONLY_DEVICE_TYPES)
        self.assertIn(
            clidarvi_workers.UDM_READ_ONLY_DEVICE_TYPE,
            clidarvi_workers.AUTOMATION_LIVE_CLI_ONLY_DEVICE_TYPES,
        )

        dialog = clidarvi.NodeDialog("add", parent=self.window)
        try:
            dialog.hostname_edit.setText("udm-se.example.net")
            dialog.vendor_combo.setCurrentText(clidarvi.UBIQUITI_UNIFI_OS_VENDOR)
            dialog.device_role_combo.setCurrentIndex(dialog.device_role_combo.findData("gateway"))
            record = clidarvi.DeviceRecord.from_mapping(dialog.get_node_data())
        finally:
            dialog.deleteLater()

        self.assertEqual(record.device_type, clidarvi_workers.UDM_READ_ONLY_DEVICE_TYPE)
        self.assertEqual(record.device_role, "gateway")

    def test_udm_confirmation_states_exact_limited_hardware_validation(self):
        record = clidarvi.DeviceRecord(
            id="udm-confirmation",
            label="Dream Machine SE",
            hostname="udm-se.example.net",
            vendor=clidarvi.UBIQUITI_UNIFI_OS_VENDOR,
            device_type=clidarvi_workers.UDM_READ_ONLY_DEVICE_TYPE,
            device_role="gateway",
        )
        expected_validation_notice = (
            "A limited development-worktree observation succeeded for all four fixed commands "
            "(uptime, date -u, uname -a and id) on one UDM-SE running UniFi OS 5.1.26. It did "
            "not use a final wheel or the final locked runtime; the failure/timeout/stop matrix "
            "and production use remain unvalidated."
        )

        with (
            patch.object(clidarvi.QMessageBox, "setInformativeText") as set_informative_text,
            patch.object(
                clidarvi.QMessageBox,
                "exec",
                return_value=clidarvi.QMessageBox.StandardButton.No,
            ),
        ):
            accepted = self.window._confirm_udm_observation_plan(
                record,
                tuple(clidarvi_workers.UDM_READ_ONLY_COMMANDS),
            )

        self.assertFalse(accepted)
        informative_text = set_informative_text.call_args.args[0]
        self.assertIn(expected_validation_notice, informative_text)
        self.assertNotIn("Only uptime has been observed", informative_text)

    def test_exact_udm_preset_dispatches_fixed_ids_to_dedicated_worker(self):
        record = clidarvi.DeviceRecord(
            id="udm-run",
            label="Dream Machine SE",
            hostname="udm-se.example.net",
            vendor=clidarvi.UBIQUITI_UNIFI_OS_VENDOR,
            device_type=clidarvi_workers.UDM_READ_ONLY_DEVICE_TYPE,
            device_role="gateway",
        )
        self._seed_automation_records([record], clidarvi.UDM_OBSERVATION_PRESET_TEXT)
        server_key = paramiko.RSAKey.generate(1024)
        with (
            patch.object(self.window, "_ensure_network_terms_accepted", return_value=True),
            patch.object(
                self.window,
                "_trusted_server_key_snapshot",
                return_value=server_key,
            ) as trusted_key,
            patch.object(self.window, "_confirm_udm_observation_plan", return_value=True),
            patch.object(
                clidarvi.QInputDialog,
                "getText",
                side_effect=[("root", True), ("password", True)],
            ),
            patch.object(clidarvi, "UdmReadOnlyAutomationWorker") as udm_factory,
            patch.object(clidarvi, "AutomationWorker") as general_factory,
        ):
            self.window.run_automation()

        trusted_key.assert_called_once_with(record.hostname, record.port)
        udm_factory.assert_called_once()
        general_factory.assert_not_called()
        device, command_ids = udm_factory.call_args.args
        self.assertEqual(command_ids, tuple(clidarvi_workers.UDM_READ_ONLY_COMMANDS))
        self.assertEqual(device["device_type"], clidarvi_workers.UDM_READ_ONLY_DEVICE_TYPE)
        self.assertEqual(device["host"], record.hostname)
        self.assertEqual(device["username"], "root")
        self.assertIs(udm_factory.call_args.kwargs["verified_server_key"], server_key)
        self.window._automation_worker = None

    def test_general_worker_start_failure_clears_worker_and_window_password_buffers(self):
        self._seed_ready_automation()
        created_workers = []
        worker_class = clidarvi.AutomationWorker

        def create_worker(*args, **kwargs):
            worker = worker_class(*args, **kwargs)
            created_workers.append(worker)
            return worker

        with (
            patch.object(self.window, "_ensure_network_terms_accepted", return_value=True),
            patch.object(self.window, "_has_locally_trusted_host_key", return_value=True),
            patch.object(
                clidarvi.QInputDialog,
                "getText",
                side_effect=[("admin", True), ("password", True)],
            ),
            patch.object(clidarvi, "AutomationWorker", side_effect=create_worker),
            patch.object(worker_class, "start", side_effect=RuntimeError("injected start failure")),
        ):
            self.window.run_automation()

        credential_workers = [worker for worker in created_workers if worker.devices]
        self.assertEqual(len(credential_workers), 1)
        worker = credential_workers[0]
        for device in worker.devices:
            password = device["password"]
            self.assertEqual(password, bytearray(len(password)))
        self.assertFalse(self.window._active_password_buffers)
        self.assertIsNone(self.window._automation_worker)
        self.assertFalse(self.window.stop_btn.isEnabled())
        self.assertIn("injected start failure", self.window.logs.toPlainText())

    def test_udm_worker_start_failure_clears_private_and_source_password_copies(self):
        record = clidarvi.DeviceRecord(
            id="udm-start-failure",
            label="Dream Machine SE",
            hostname="udm-se.example.net",
            vendor=clidarvi.UBIQUITI_UNIFI_OS_VENDOR,
            device_type=clidarvi_workers.UDM_READ_ONLY_DEVICE_TYPE,
            device_role="gateway",
        )
        self._seed_automation_records([record], clidarvi.UDM_OBSERVATION_PRESET_TEXT)
        server_key = paramiko.RSAKey.generate(1024)
        created_workers = []
        worker_class = clidarvi.UdmReadOnlyAutomationWorker

        def create_worker(*args, **kwargs):
            worker = worker_class(*args, **kwargs)
            created_workers.append(worker)
            return worker

        with (
            patch.object(self.window, "_ensure_network_terms_accepted", return_value=True),
            patch.object(
                self.window,
                "_trusted_server_key_snapshot",
                return_value=server_key,
            ),
            patch.object(self.window, "_confirm_udm_observation_plan", return_value=True),
            patch.object(
                clidarvi.QInputDialog,
                "getText",
                side_effect=[("root", True), ("password", True)],
            ),
            patch.object(clidarvi, "UdmReadOnlyAutomationWorker", side_effect=create_worker),
            patch.object(worker_class, "start", side_effect=RuntimeError("injected start failure")),
        ):
            self.window.run_automation()

        self.assertEqual(len(created_workers), 1)
        worker = created_workers[0]
        self.assertTrue(all(value == 0 for value in worker._password_buffer))
        self.assertTrue(all(value == 0 for value in worker._source_password_buffer))
        self.assertIsNone(self.window._automation_worker)
        self.assertFalse(self.window.stop_btn.isEnabled())
        self.assertIn("injected start failure", self.window.logs.toPlainText())

    def test_noncanonical_udm_plans_block_before_hostkey_credentials_or_workers(self):
        record = clidarvi.DeviceRecord(
            id="udm-plan-gate",
            label="Dream Machine SE",
            hostname="udm-se.example.net",
            vendor=clidarvi.UBIQUITI_UNIFI_OS_VENDOR,
            device_type=clidarvi_workers.UDM_READ_ONLY_DEVICE_TYPE,
            device_role="gateway",
        )
        preset = clidarvi.UDM_OBSERVATION_PRESET_TEXT
        lines = preset.splitlines()
        invalid_plans = {
            "unknown": "whoami",
            "case": preset.replace("uptime", "Uptime", 1),
            "leading whitespace": f" {preset}",
            "trailing whitespace": f"{preset} ",
            "duplicate": f"{preset}\nuptime",
            "injection": f"{preset}\nuptime; reboot",
            "reordered": "\n".join(reversed(lines)),
            "subset": lines[0],
        }

        for label, commands_text in invalid_plans.items():
            with self.subTest(label=label):
                self._seed_automation_records([record], commands_text)
                with (
                    patch.object(self.window, "_ensure_network_terms_accepted", return_value=True),
                    patch.object(self.window, "_trusted_server_key_snapshot") as trusted_key,
                    patch.object(self.window, "_confirm_udm_observation_plan") as confirm,
                    patch.object(clidarvi.QInputDialog, "getText") as credential_prompt,
                    patch.object(clidarvi.QMessageBox, "warning") as warning,
                    patch.object(clidarvi, "UdmReadOnlyAutomationWorker") as udm_factory,
                    patch.object(clidarvi, "AutomationWorker") as general_factory,
                ):
                    self.window.run_automation()

                trusted_key.assert_not_called()
                confirm.assert_not_called()
                credential_prompt.assert_not_called()
                udm_factory.assert_not_called()
                general_factory.assert_not_called()
                warning.assert_called_once()
                self.assertIn("exact fixed preset", warning.call_args.args[2])

    def test_udm_mixed_or_multiple_targets_block_before_credentials_or_workers(self):
        udm_one = clidarvi.DeviceRecord(
            id="udm-one",
            label="UDM one",
            hostname="udm-one.example.net",
            vendor=clidarvi.UBIQUITI_UNIFI_OS_VENDOR,
            device_type=clidarvi_workers.UDM_READ_ONLY_DEVICE_TYPE,
            device_role="gateway",
        )
        udm_two = clidarvi.DeviceRecord(
            id="udm-two",
            label="UDM two",
            hostname="udm-two.example.net",
            vendor=clidarvi.UBIQUITI_UNIFI_OS_VENDOR,
            device_type=clidarvi_workers.UDM_READ_ONLY_DEVICE_TYPE,
            device_role="gateway",
        )
        cisco = clidarvi.DeviceRecord(
            id="cisco-one",
            label="Cisco switch",
            hostname="switch.example.net",
            vendor="Cisco Switch",
            device_type="cisco_ios",
            device_role="switch",
        )

        for label, records in (
            ("multiple", [udm_one, udm_two]),
            ("mixed", [udm_one, cisco]),
        ):
            with self.subTest(label=label):
                self._seed_automation_records(records, clidarvi.UDM_OBSERVATION_PRESET_TEXT)
                with (
                    patch.object(self.window, "_ensure_network_terms_accepted", return_value=True),
                    patch.object(self.window, "_trusted_server_key_snapshot") as trusted_key,
                    patch.object(self.window, "_confirm_udm_observation_plan") as confirm,
                    patch.object(clidarvi.QInputDialog, "getText") as credential_prompt,
                    patch.object(clidarvi.QMessageBox, "warning") as warning,
                    patch.object(clidarvi, "UdmReadOnlyAutomationWorker") as udm_factory,
                    patch.object(clidarvi, "AutomationWorker") as general_factory,
                ):
                    self.window.run_automation()

                trusted_key.assert_not_called()
                confirm.assert_not_called()
                credential_prompt.assert_not_called()
                udm_factory.assert_not_called()
                general_factory.assert_not_called()
                warning.assert_called_once()
                self.assertIn("exactly one", warning.call_args.args[2])

    def test_udm_vendor_and_gateway_role_without_profile_do_not_dispatch(self):
        presentation_only = clidarvi.DeviceRecord(
            id="udm-spoof",
            label="Dream Machine-looking device",
            hostname="generic.example.net",
            vendor=clidarvi.UBIQUITI_UNIFI_OS_VENDOR,
            device_type="generic",
            device_role="gateway",
        )
        self._seed_automation_records(
            [presentation_only],
            clidarvi.UDM_OBSERVATION_PRESET_TEXT,
        )
        with (
            patch.object(self.window, "_ensure_network_terms_accepted", return_value=True),
            patch.object(self.window, "_trusted_server_key_snapshot") as trusted_key,
            patch.object(clidarvi.QInputDialog, "getText") as credential_prompt,
            patch.object(clidarvi.QMessageBox, "warning") as warning,
            patch.object(clidarvi, "UdmReadOnlyAutomationWorker") as udm_factory,
            patch.object(clidarvi, "AutomationWorker") as general_factory,
        ):
            self.window.run_automation()

        trusted_key.assert_not_called()
        credential_prompt.assert_not_called()
        udm_factory.assert_not_called()
        general_factory.assert_not_called()
        warning.assert_called_once()
        self.assertIn("generic", warning.call_args.args[2])

    def test_empty_live_cli_password_never_starts_a_worker(self):
        record = clidarvi.DeviceRecord(label="Lab router", hostname="router.example.net")
        self.window.cli_btn.click()
        self.application.processEvents()
        with (
            patch.object(self.window, "_ensure_network_terms_accepted", return_value=True),
            patch.object(
                clidarvi.QInputDialog,
                "getText",
                side_effect=[("admin", True), ("", True)],
            ),
            patch.object(clidarvi.QMessageBox, "warning") as warning,
            patch.object(clidarvi, "InteractiveSSHWorker") as worker_factory,
        ):
            self.window._open_ssh_session(record)

        worker_factory.assert_not_called()
        warning.assert_called_once()
        self.assertIn("password is required", warning.call_args.args[2].lower())

    def test_live_cli_session_limit_blocks_before_credentials_or_worker(self):
        record = clidarvi.DeviceRecord(label="Lab router", hostname="router.example.net")
        for _index in range(clidarvi.MAX_LIVE_CLI_SESSIONS):
            self.window.sessions[object()] = object()
        self.addCleanup(self.window.sessions.clear)

        with (
            patch.object(self.window, "_ensure_network_terms_accepted", return_value=True),
            patch.object(self.window, "_cli_request_is_current", return_value=True),
            patch.object(clidarvi.QInputDialog, "getText") as credential_prompt,
            patch.object(clidarvi.QMessageBox, "warning") as warning,
            patch.object(clidarvi, "InteractiveSSHWorker") as worker_factory,
        ):
            self.window._open_ssh_session(record)

        credential_prompt.assert_not_called()
        worker_factory.assert_not_called()
        warning.assert_called_once()
        self.assertIn("at most 8", warning.call_args.args[2].lower())

    def test_live_cli_pins_the_just_verified_key_in_memory(self):
        self.window.cli_btn.click()
        self.application.processEvents()
        record = clidarvi.DeviceRecord(label="Lab router", hostname="router.example.net")
        server_key = paramiko.RSAKey.generate(1024)
        with (
            patch.object(self.window, "_ensure_network_terms_accepted", return_value=True),
            patch.object(
                clidarvi.QInputDialog,
                "getText",
                side_effect=[("admin", True), ("secret", True)],
            ),
            patch.object(clidarvi.InteractiveSSHWorker, "start"),
        ):
            self.window._open_ssh_session(record, verified_server_key=server_key)

        worker = next(iter(self.window.sessions.values()))
        self.assertIs(worker.verified_server_key, server_key)
        self.assertIsNone(worker.known_hosts_path)
        self.window.close_session_tab(0)

    def test_live_cli_session_tab_is_compact_stateful_and_accessible(self):
        self.window.cli_btn.click()
        self.application.processEvents()
        label = "Ubiquiti Dream Machine SE with a deliberately long session label"
        record = clidarvi.DeviceRecord(label=label, hostname="udm-se.example.net")
        server_key = paramiko.RSAKey.generate(1024)
        with (
            patch.object(self.window, "_ensure_network_terms_accepted", return_value=True),
            patch.object(
                clidarvi.QInputDialog,
                "getText",
                side_effect=[("root", True), ("secret", True)],
            ),
            patch.object(clidarvi.InteractiveSSHWorker, "start"),
        ):
            self.window._open_ssh_session(record, verified_server_key=server_key)

        tabs = self.window.tabs
        tab_bar = tabs.tabBar()
        self.assertEqual(tabs.objectName(), "CLISessionTabs")
        self.assertFalse(tabs.tabsClosable())
        self.assertEqual(tab_bar.accessibleName(), "Open Live CLI sessions")
        self.assertFalse(tab_bar.expanding())
        self.assertEqual(tab_bar.elideMode(), Qt.TextElideMode.ElideRight)
        self.assertTrue(tab_bar.usesScrollButtons())
        self.assertEqual(tabs.tabText(0), label)
        self.assertEqual(tabs.tabToolTip(0), label)
        self.assertIn("alignment: left", tabs.styleSheet())

        terminal = tabs.widget(0)
        self.assertEqual(terminal.accessibleName(), f"Interactive SSH terminal for {label}")
        self.assertIn("border-top-left-radius: 0px", terminal.styleSheet())
        status_dot = tab_bar.tabButton(0, clidarvi.QTabBar.ButtonPosition.LeftSide)
        close_button = tab_bar.tabButton(0, clidarvi.QTabBar.ButtonPosition.RightSide)
        self.assertEqual(status_dot.property("state"), "connecting")
        self.assertIn("connecting", status_dot.accessibleName())
        self.assertEqual(close_button.objectName(), "SessionTabCloseButton")
        self.assertEqual(close_button.accessibleName(), f"Close CLI session for {label}")
        self.assertEqual(close_button.focusPolicy(), Qt.FocusPolicy.TabFocus)

        worker = self.window.sessions[terminal]
        worker.connected.emit()
        self.application.processEvents()
        self.assertEqual(status_dot.property("state"), "connected")
        self.assertIn("connected", status_dot.accessibleName())

        close_button.click()
        self.application.processEvents()
        self.assertEqual(tabs.count(), 0)
        self.assertFalse(self.window.sessions)
        self.assertIs(self.window.cli_stack.currentWidget(), self.window.cli_empty_state)

    def test_late_automation_popup_callback_after_page_deletion_is_ignored(self):
        self.window.build_automation_page()
        selector = self.window.selector

        with patch.object(clidarvi.sys, "excepthook") as excepthook:
            selector.showPopup()
            self.window.build_session_page()
            QApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
            self.application.processEvents()

        excepthook.assert_not_called()

    def test_late_cli_connected_signal_after_page_deletion_is_ignored(self):
        self.window.cli_btn.click()
        self.application.processEvents()
        record = clidarvi.DeviceRecord(label="Late signal", hostname="late.example.net")
        server_key = paramiko.RSAKey.generate(1024)
        with (
            patch.object(self.window, "_ensure_network_terms_accepted", return_value=True),
            patch.object(
                clidarvi.QInputDialog,
                "getText",
                side_effect=[("admin", True), ("secret", True)],
            ),
            patch.object(clidarvi.InteractiveSSHWorker, "start"),
        ):
            self.window._open_ssh_session(record, verified_server_key=server_key)

        worker = next(iter(self.window.sessions.values()))
        self.window.build_automation_page()
        automation_right = self.window.right
        automation_targets = self.window.add_list
        QApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        self.application.processEvents()

        with patch.object(clidarvi.sys, "excepthook") as excepthook:
            worker.connected.emit()
            self.application.processEvents()

        excepthook.assert_not_called()
        self.assertIs(self.window.right, automation_right)
        self.assertIs(self.window.add_list, automation_targets)
        self.assertFalse(self.window.sessions)

    def test_live_cli_start_failure_rolls_back_tab_worker_and_password(self):
        self.window.cli_btn.click()
        self.application.processEvents()
        record = clidarvi.DeviceRecord(label="Lab router", hostname="router.example.net")
        with (
            patch.object(self.window, "_ensure_network_terms_accepted", return_value=True),
            patch.object(
                clidarvi.QInputDialog,
                "getText",
                side_effect=[("admin", True), ("secret", True)],
            ),
            patch.object(
                clidarvi.InteractiveSSHWorker,
                "start",
                side_effect=RuntimeError("injected start failure"),
            ),
            patch.object(clidarvi.QMessageBox, "critical") as critical,
        ):
            self.window._open_ssh_session(record)

        critical.assert_called_once()
        self.assertEqual(self.window.tabs.count(), 0)
        self.assertFalse(self.window.sessions)
        self.assertFalse(self.window._session_workers)
        self.assertFalse(self.window._active_password_buffers)

    def test_acceptance_record_is_atomic_minimal_private_and_exact(self):
        paths, resolve = self._risk_assets()
        # Put real device data into the session first, so the negative
        # assertions below test values that actually exist in this run.
        self.window._make_node_item(
            self.window.tree,
            "Privacy probe",
            metadata={
                "id": "privacy-probe",
                "label": "Privacy probe",
                "hostname": "privacy-probe.example.net",
            },
        )
        session_inventory = json.dumps(self.window.tree_to_dict())
        self.assertIn("privacy-probe.example.net", session_inventory)
        with (
            patch.object(clidarvi, "_resolve_bundled_asset", side_effect=resolve),
            patch.object(
                clidarvi.RiskAcknowledgementDialog,
                "exec",
                new=self._accept_risk_dialog,
            ),
        ):
            accepted = self.window._ensure_network_terms_accepted()
            snapshot = clidarvi._load_risk_terms_snapshot()

        self.assertTrue(accepted)
        record_path = self.window.get_risk_acknowledgement_path()
        record = json.loads(record_path.read_text(encoding="utf-8"))
        self.assertEqual(record["declared_app_version"], clidarvi.__version__)
        self.assertEqual(record["terms_id"], clidarvi.RISK_TERMS_ID)
        self.assertEqual(record["bundle_sha256"], snapshot["bundle_sha256"])
        self.assertEqual(
            record["bundled_required_snapshot"],
            "requirements-lock/runtime-py313.txt",
        )
        self.assertIs(record["installed_runtime_verified"], False)
        self.assertNotIn("app_version", record)
        self.assertNotIn("dependency_snapshot", record)
        self.assertEqual(
            record["document_sha256"]["terms"],
            hashlib.sha256(paths["TERMS.md"].read_bytes()).hexdigest(),
        )
        self.assertEqual(
            record["acknowledgement_ids"],
            [item[0] for item in clidarvi.RISK_ACKNOWLEDGEMENTS],
        )
        self.assertTrue(record["accepted_at_utc"].endswith("Z"))
        serialized = json.dumps(record)
        for sensitive_value in (
            "privacy-probe.example.net",
            "privacy-probe",
            "Privacy probe",
            "router.example.net",
            "admin",
            "password",
            str(Path.home()),
        ):
            self.assertNotIn(sensitive_value, serialized)
        if os.name == "posix":
            self.assertEqual(record_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(record_path.parent.stat().st_mode & 0o777, 0o700)

    def test_matching_saved_acceptance_bypasses_dialog(self):
        _paths, resolve = self._risk_assets()
        with (
            patch.object(clidarvi, "_resolve_bundled_asset", side_effect=resolve),
            patch.object(
                clidarvi.RiskAcknowledgementDialog,
                "exec",
                new=self._accept_risk_dialog,
            ),
        ):
            self.assertTrue(self.window._ensure_network_terms_accepted())

        self.window._accepted_risk_bundle_this_run = None
        with (
            patch.object(clidarvi, "_resolve_bundled_asset", side_effect=resolve),
            patch.object(clidarvi.RiskAcknowledgementDialog, "exec") as execute,
        ):
            self.assertTrue(self.window._ensure_network_terms_accepted())
        execute.assert_not_called()

    def test_changed_corrupt_or_wrong_version_acceptance_requires_reacceptance(self):
        paths, resolve = self._risk_assets()
        with (
            patch.object(clidarvi, "_resolve_bundled_asset", side_effect=resolve),
            patch.object(
                clidarvi.RiskAcknowledgementDialog,
                "exec",
                new=self._accept_risk_dialog,
            ),
        ):
            self.assertTrue(self.window._ensure_network_terms_accepted())

        record_path = self.window.get_risk_acknowledgement_path()
        self.window._accepted_risk_bundle_this_run = None
        paths["TERMS.md"].write_text(
            "# Test operational terms\n\n"
            f"**Terms ID:** `{clidarvi.RISK_TERMS_ID}`\n"
            f"**For application version:** `{clidarvi.__version__}`\n\n"
            "**Publisher:** Clidarvi Test Publisher — publisher@example.invalid\n\n"
            "terms-v2\n",
            encoding="utf-8",
        )
        with (
            patch.object(clidarvi, "_resolve_bundled_asset", side_effect=resolve),
            patch.object(
                clidarvi.RiskAcknowledgementDialog,
                "exec",
                return_value=clidarvi.QDialog.DialogCode.Rejected,
            ) as execute,
        ):
            self.assertFalse(self.window._ensure_network_terms_accepted())
        execute.assert_called_once()

        record_path.write_text("{corrupt", encoding="utf-8")
        with (
            patch.object(clidarvi, "_resolve_bundled_asset", side_effect=resolve),
            patch.object(
                clidarvi.RiskAcknowledgementDialog,
                "exec",
                return_value=clidarvi.QDialog.DialogCode.Rejected,
            ) as execute,
        ):
            self.assertFalse(self.window._ensure_network_terms_accepted())
        execute.assert_called_once()

        with (
            patch.object(clidarvi, "_resolve_bundled_asset", side_effect=resolve),
            patch.object(
                clidarvi.RiskAcknowledgementDialog,
                "exec",
                new=self._accept_risk_dialog,
            ),
        ):
            self.assertTrue(self.window._ensure_network_terms_accepted())
        self.window._accepted_risk_bundle_this_run = None

        paths["TERMS.md"].write_text(
            "# Test operational terms\n\n"
            f"**Terms ID:** `{clidarvi.RISK_TERMS_ID}`\n"
            "**For application version:** `99.0.0a1`\n\n"
            "**Publisher:** Clidarvi Test Publisher — publisher@example.invalid\n\n"
            "terms-v3\n",
            encoding="utf-8",
        )
        with (
            patch.object(clidarvi, "_resolve_bundled_asset", side_effect=resolve),
            patch.object(clidarvi, "__version__", "99.0.0a1"),
            patch.object(
                clidarvi.RiskAcknowledgementDialog,
                "exec",
                return_value=clidarvi.QDialog.DialogCode.Rejected,
            ) as execute,
        ):
            self.assertFalse(self.window._ensure_network_terms_accepted())
        execute.assert_called_once()

    def test_about_legal_dialog_bundles_core_notices(self):
        dialog = clidarvi.LegalDialog(self.window)
        tabs = dialog.findChild(clidarvi.QTabWidget)

        self.assertIsNotNone(tabs)
        self.assertEqual(tabs.count(), 6)
        contents = [tabs.widget(index).toPlainText() for index in range(tabs.count())]
        self.assertIn("operational terms", contents[0])
        self.assertIn("info@clidarvi.io", contents[0])
        self.assertIn("GNU GENERAL PUBLIC LICENSE", contents[1])
        self.assertIn("No warranty", contents[2])
        self.assertIn("Privacy and local data", contents[3])
        self.assertIn("privacy@clidarvi.io", contents[3])
        self.assertIn("Third-party notices", contents[4])
        self.assertIn("Names and trademarks", contents[5])
        self.assertIn("Network acknowledgement:", dialog.acceptance_status_label.text())

        with (
            patch.object(clidarvi.LegalDialog, "exec") as execute,
            patch.object(self.window, "_ensure_network_terms_accepted") as network_gate,
        ):
            self.window.legal_btn.click()
        execute.assert_called_once_with()
        network_gate.assert_not_called()
        dialog.deleteLater()

    def test_legal_notice_links_only_navigate_to_allowlisted_local_documents(self):
        dialog = clidarvi.LegalDialog()
        try:
            tabs = dialog.notice_tabs
            terms_viewer = tabs.widget(0)
            self.assertFalse(terms_viewer.openLinks())
            self.assertFalse(terms_viewer.openExternalLinks())

            terms_viewer.anchorClicked.emit(QUrl("DISCLAIMER.md"))
            self.assertEqual(tabs.currentIndex(), dialog._notice_tab_indexes["DISCLAIMER.md"])
            self.assertEqual(tabs.count(), 6)

            terms_viewer.anchorClicked.emit(QUrl("SECURITY.md"))
            self.assertEqual(tabs.count(), 7)
            reference_viewer = dialog._reference_viewer
            self.assertIsNotNone(reference_viewer)
            self.assertEqual(reference_viewer.property("notice_filename"), "SECURITY.md")
            self.assertIn("Security policy", reference_viewer.toPlainText())
            self.assertIn("security@clidarvi.io", reference_viewer.toPlainText())

            reference_viewer.anchorClicked.emit(QUrl("docs/FIELD_TEST_CHECKLIST.md"))
            self.assertEqual(
                reference_viewer.property("notice_filename"),
                "docs/FIELD_TEST_CHECKLIST.md",
            )
            self.assertIn("disposable-lab field-test checklist", reference_viewer.toPlainText())

            current_index = tabs.currentIndex()
            current_text = reference_viewer.toPlainText()
            reference_viewer.anchorClicked.emit(QUrl("https://example.invalid/legal"))
            reference_viewer.anchorClicked.emit(QUrl("../../etc/passwd"))
            self.assertEqual(tabs.currentIndex(), current_index)
            self.assertEqual(reference_viewer.toPlainText(), current_text)
        finally:
            dialog.deleteLater()


class TerminalWidgetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.application = QApplication.instance() or QApplication([])

    def test_output_is_plain_text_and_terminal_controls_are_bounded(self):
        worker = _TerminalWorker()
        terminal = clidarvi.TerminalWidget(worker)

        terminal.handle_output("\x1b[31m<b>literal</b>\x1b[0m\n")
        terminal.handle_output("progress 10%\rprogress 20%")

        rendered = terminal.toPlainText()
        self.assertIn("<b>literal</b>", rendered)
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("progress 10%", rendered)
        self.assertIn("progress 20%", rendered)
        terminal.deleteLater()

    def test_terminal_parser_handles_split_controls_and_line_start_backspace(self):
        worker = _TerminalWorker()
        terminal = clidarvi.TerminalWidget(worker)

        terminal.handle_output("prefix\x1b[3")
        terminal.handle_output("1mred\x1b]0;title")
        terminal.handle_output("\x07\n\bnext")

        rendered = terminal.toPlainText()
        self.assertEqual(rendered, "prefixred\nnext")
        self.assertNotIn("\x1b", rendered)
        terminal.deleteLater()

    def test_terminal_parser_suppresses_all_string_controls_and_c1_st(self):
        worker = _TerminalWorker()
        terminal = clidarvi.TerminalWidget(worker)

        # DCS is split immediately before its ST terminator; PM uses its 8-bit
        # introducer and 8-bit ST. SOS/APC exercise the other string families.
        terminal.handle_output("head\x1bPdcs-private\x1b")
        terminal.handle_output("\\tail\x9epm-private")
        terminal.handle_output("\x9cvisible")
        terminal.handle_output("\x1bXsos-private\x1b\\")
        terminal.handle_output("\x1b_apc-private\x1b\\done")
        terminal.handle_output("\x1b(")
        terminal.handle_output("Bcharset-final")

        self.assertEqual(terminal.toPlainText(), "headtailvisibledonecharset-final")
        self.assertEqual(terminal._terminal_control_carry, "")
        terminal.deleteLater()

    def test_terminal_parser_keeps_discard_state_after_oversized_string(self):
        worker = _TerminalWorker()
        terminal = clidarvi.TerminalWidget(worker)

        terminal.handle_output("safe\x1b]" + ("x" * 5000))
        terminal.handle_output("still-private\x1b")
        terminal.handle_output("\\middle\x1bP" + ("y" * 5000))
        terminal.handle_output("also-private\x9cend")

        self.assertEqual(terminal.toPlainText(), "safemiddleend")
        self.assertIsNone(terminal._terminal_string_discard)
        self.assertFalse(terminal._terminal_string_escape_pending)
        terminal.deleteLater()

    def test_key_input_maps_to_the_documented_terminal_sequences(self):
        worker = _TerminalWorker()
        terminal = clidarvi.TerminalWidget(worker)

        def press(key, text="", modifiers=Qt.KeyboardModifier.NoModifier):
            event = QKeyEvent(QEvent.Type.KeyPress, key, modifiers, text)
            terminal.keyPressEvent(event)

        press(Qt.Key.Key_A, "a")
        press(Qt.Key.Key_Return)
        press(Qt.Key.Key_Backspace)
        press(Qt.Key.Key_Up)
        press(Qt.Key.Key_Tab, "\t")
        physical_control = (
            Qt.KeyboardModifier.MetaModifier
            if clidarvi.sys.platform == "darwin"
            else Qt.KeyboardModifier.ControlModifier
        )
        press(Qt.Key.Key_C, modifiers=physical_control)
        press(Qt.Key.Key_Z, modifiers=physical_control)

        self.assertEqual(
            worker.inputs,
            ["a", "\r", "\x7f", "\x1b[A", "\t", "\x03", "\x1a"],
        )
        terminal.deleteLater()

    def test_physical_control_key_maps_to_control_sequences_on_macos(self):
        worker = _TerminalWorker()
        terminal = clidarvi.TerminalWidget(worker)

        # Qt reports the physical Control key as MetaModifier on macOS; a
        # terminal user's Ctrl+C must still interrupt the remote command.
        with patch.object(clidarvi.sys, "platform", "darwin"):
            event = QKeyEvent(
                QEvent.Type.KeyPress,
                Qt.Key.Key_C,
                Qt.KeyboardModifier.MetaModifier,
                "",
            )
            terminal.keyPressEvent(event)

        self.assertEqual(worker.inputs, ["\x03"])
        terminal.deleteLater()

    def test_command_key_does_not_send_terminal_control_bytes_on_macos(self):
        worker = _TerminalWorker()
        terminal = clidarvi.TerminalWidget(worker)

        # Qt reports Command as ControlModifier on macOS. With no selected
        # text, Command+C must still remain a GUI shortcut, never remote ETX.
        with patch.object(clidarvi.sys, "platform", "darwin"):
            event = QKeyEvent(
                QEvent.Type.KeyPress,
                Qt.Key.Key_C,
                Qt.KeyboardModifier.ControlModifier,
                "",
            )
            terminal.keyPressEvent(event)

        self.assertEqual(worker.inputs, [])
        terminal.deleteLater()

    def test_command_option_is_not_treated_as_altgr_on_macos(self):
        worker = _TerminalWorker()
        terminal = clidarvi.TerminalWidget(worker)

        with patch.object(clidarvi.sys, "platform", "darwin"):
            event = QKeyEvent(
                QEvent.Type.KeyPress,
                Qt.Key.Key_Q,
                Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.AltModifier,
                "œ",
            )
            terminal.keyPressEvent(event)

        self.assertEqual(worker.inputs, [])
        terminal.deleteLater()

    def test_altgr_composed_text_is_sent_not_a_control_byte(self):
        worker = _TerminalWorker()
        terminal = clidarvi.TerminalWidget(worker)

        # AltGr is reported as Control+Alt on Windows/Linux and composes text
        # (e.g. "@" on many layouts); it must inject that text, never a C0 byte.
        with patch.object(clidarvi.sys, "platform", "linux"):
            altgr = QKeyEvent(
                QEvent.Type.KeyPress,
                Qt.Key.Key_Q,
                Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.AltModifier,
                "@",
            )
            terminal.keyPressEvent(altgr)
            # A plain Control chord on the same platform is still a control byte.
            ctrl_c = QKeyEvent(
                QEvent.Type.KeyPress,
                Qt.Key.Key_C,
                Qt.KeyboardModifier.ControlModifier,
                "",
            )
            terminal.keyPressEvent(ctrl_c)

        self.assertEqual(worker.inputs, ["@", "\x03"])
        terminal.deleteLater()

    def test_clipboard_paste_shortcut_sends_clipboard_text(self):
        worker = _TerminalWorker()
        terminal = clidarvi.TerminalWidget(worker)
        QApplication.clipboard().setText("show version\n")

        event = QKeyEvent(
            QEvent.Type.KeyPress,
            Qt.Key.Key_V,
            Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier,
            "",
        )
        terminal.keyPressEvent(event)

        self.assertEqual(worker.inputs, ["show version\n"])
        terminal.deleteLater()


if __name__ == "__main__":
    unittest.main()
