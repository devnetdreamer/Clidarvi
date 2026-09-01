# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 devnetdreamer (https://github.com/devnetdreamer) and Clidarvi contributors
# Additional warranty, liability, and operational terms: see DISCLAIMER.md and TERMS.md.

"""Clidarvi desktop application entry point and PyQt user interface."""

import base64
import copy
import csv
import getpass
import hashlib
import html
import io
import json
import math
import os
import re
import stat
import sys
import tomllib
import unicodedata
from email import policy
from email.parser import BytesParser

try:
    from defusedxml import ElementTree as ET
except ImportError as exc:
    raise ImportError(
        "Clidarvi requires the defusedxml package for secure XML parsing. "
        "Install it with 'pip install defusedxml'."
    ) from exc
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

import paramiko
from PyQt6.QtCore import QLockFile, QSize, Qt, QTimer, QUrl
from PyQt6.QtGui import QColor, QIcon, QKeySequence, QPainter, QPixmap, QTextCursor
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QTabBar,
    QTabWidget,
    QTextBrowser,
    QTextEdit,
    QToolButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from clidarvi_core import (
    NODES_KEY,
    DeviceRecord,
    InventoryState,
    SitePlacement,
    SiteRecord,
    decode_inventory_state,
    encode_inventory_document,
    infer_legacy_device_role,
    merge_tree_dicts,
    new_device_id,
    sanitize_label,
    sanitize_site_placements,
    sanitize_tree_dict,
)
from clidarvi_core import (
    count_tree_items as count_inventory_items,
)
from clidarvi_io import (
    apply_private_permissions,
    atomic_write_json,
    atomic_write_text,
    atomic_write_with,
    ensure_directory,
)
from clidarvi_policy import (
    CommandClass,
    classify_command,
    redact_command,
    redact_text_block,
)
from clidarvi_workers import (
    EXPERIMENTAL_AUTOMATION_DEVICE_TYPES,
    EXPERIMENTAL_AUTOMATION_SETUP_DISCLOSURES,
    GENERAL_AUTOMATION_BLOCKED_DEVICE_TYPES,
    UDM_READ_ONLY_COMMANDS,
    UDM_READ_ONLY_DEVICE_TYPE,
    AutomationWorker,
    CommandExecutionError,
    HostKeyFetchWorker,
    InteractiveSSHWorker,
    UdmReadOnlyAutomationWorker,
    ssh_disabled_algorithms,
    validate_experimental_automation_runtime,
    validate_host,
)

__all__ = [
    "AutomationWorker",
    "CommandExecutionError",
    "HostKeyFetchWorker",
    "InteractiveSSHWorker",
    "LegalDialog",
    "MainWindow",
    "NodeDialog",
    "RiskAcknowledgementDialog",
    "SiteDialog",
    "TerminalWidget",
    "main",
    "ssh_disabled_algorithms",
    "validate_host",
]

APP_NAME = "Clidarvi"
__version__ = "0.1.0a1"
DISPLAY_VERSION = "0.1.0 Alpha 1"
MAX_LIVE_CLI_SESSIONS = 8

RISK_ACKNOWLEDGEMENT_SCHEMA_VERSION = 2
RISK_TERMS_ID = "clidarvi-network-risk-acknowledgement-v1"
RISK_ACKNOWLEDGEMENT_FILENAME = "risk-acknowledgement.json"
RISK_PUBLISHER_PLACEHOLDER = "[INSERT IDENTIFIABLE PUBLISHER LEGAL NAME AND CONTACT]"
RISK_EXPLICIT_PUBLISHER_PLACEHOLDER_RE = re.compile(
    r"(?:\[\s*(?:INSERT|REPLACE|ENTER|FILL(?:\s+IN)?|TODO|TBD|TBC|FIXME|PLACEHOLDER)"
    r"\b[^\]\n]*\]|\{\{\s*[^}\n]*(?:PUBLISHER|LEGAL\s+NAME|CONTACT|TODO|TBD|TBC|"
    r"FIXME|PLACEHOLDER)[^}\n]*\}\}|<\s*(?=[^>@\n]*>)(?:PUBLISHER|LEGAL\s+NAME|CONTACT|INSERT|"
    r"TODO|TBD|TBC|FIXME|PLACEHOLDER)\b[^>\n]*>)",
    flags=re.IGNORECASE,
)
RISK_REQUIRED_DOCUMENTS = (
    ("terms", "TERMS.md"),
    ("disclaimer", "DISCLAIMER.md"),
    ("bundled_required_snapshot", "requirements-lock/runtime-py313.txt"),
)
RISK_ACKNOWLEDGEMENTS = (
    (
        "experimental_alpha",
        "I understand that this is experimental alpha software and that its final release "
        "artifact has not completed real-equipment or production field testing.",
    ),
    (
        "outage_and_rollback_risk",
        "I understand that commands may cause outages, configuration loss, or other "
        "damage, and that Stop does not roll back changes already sent.",
    ),
    (
        "authorization_and_recovery",
        "I confirm that I am authorized to access the selected systems and that I am "
        "responsible for verified backups and a tested recovery plan.",
    ),
    (
        "warranty_and_liability",
        "I agree to the warranty and liability terms shown below, only to the extent "
        "permitted by applicable law.",
    ),
)

# ---------- Shared constants ----------
UBIQUITI_UNIFI_OS_PROFILE = UDM_READ_ONLY_DEVICE_TYPE
UBIQUITI_UNIFI_OS_VENDOR = "Ubiquiti Dream Machine / UniFi OS"
LEGACY_VENDOR_ALIASES = {
    "Ubiquiti UniFi OS (Live CLI only)": UBIQUITI_UNIFI_OS_VENDOR,
}
VENDOR_MAP = {
    "Cisco Switch": "cisco_ios",
    "Cisco Router": "cisco_ios",
    "Cisco WLC": "cisco_wlc",
    "Fortinet": "fortinet",
    "Aruba": "aruba_os",
    "Palo Alto": "paloalto_panos",
    UBIQUITI_UNIFI_OS_VENDOR: UBIQUITI_UNIFI_OS_PROFILE,
    "Other": "generic",
}
UDM_OBSERVATION_PRESET_TEXT = "\n".join(UDM_READ_ONLY_COMMANDS.values())
EXPERIMENTAL_AUTOMATION_CONFIRMATION_PHRASE = "RUN EXPERIMENTAL AUTOMATION"
DEVICE_ROLE_CHOICES = (
    ("", "Automatic (based on platform)"),
    ("gateway", "Multifunction security gateway"),
    ("router", "Router"),
    ("switch", "Switch"),
    ("firewall", "Firewall"),
    ("wireless", "Wireless device"),
    ("controller", "Network controller"),
    ("server", "Server"),
    ("generic", "Generic network device"),
)
SITE_TYPE_LABELS = {
    "enterprise": "Enterprise site",
    "datacenter": "Data center",
}

INVENTORY_ICON_ASSETS = {
    f"{role}_{surface}": f"icons/inventory/{role}-{surface}.svg"
    for role in (
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
    for surface in ("dark", "light")
}
INVENTORY_ICON_DESCRIPTIONS = {
    "site": "Physical enterprise site",
    "datacenter": "Physical data center",
    "router": "Network router",
    "switch": "Network switch",
    "firewall": "Network firewall",
    "wireless": "Wireless network device",
    "controller": "Network controller",
    "server": "Network server",
    "gateway": "Multifunction security gateway",
    "device": "Network device",
}

APP_STYLESHEET = """
QMainWindow {
    background-color: #E8EDF5;
    color: #172033;
    font-family: "SF Pro Text", "Segoe UI", "Helvetica Neue", Arial, sans-serif;
    font-size: 10.5pt;
}
QWidget#RootContainer { background-color: #E8EDF5; }
QWidget#Sidebar {
    background-color: #0B1220;
    border: 1px solid #17243A;
    border-radius: 16px;
}
QWidget#WorkspaceCard {
    background-color: #F8FAFD;
    border: 1px solid #D8E0EB;
    border-radius: 16px;
}
QWidget#SectionCard {
    background-color: #FFFFFF;
    border: 1px solid #DCE4EF;
    border-radius: 12px;
}
QLabel {
    color: #172033;
    background-color: transparent;
    border: none;
}
QLabel#BrandTitle { color: #FFFFFF; font-size: 19pt; font-weight: 800; }
QLabel#BrandKicker { color: #7183A1; font-size: 8pt; font-weight: 700; }
QLabel#SidebarHeading { color: #7183A1; font-size: 8.5pt; font-weight: 700; }
QLabel#PageTitle { color: #111827; font-size: 20pt; font-weight: 750; }
QLabel#PageSubtitle { color: #64748B; font-size: 10pt; }
QLabel#SectionTitle { color: #1E293B; font-size: 11pt; font-weight: 700; }
QLabel#SectionHint { color: #7A879C; font-size: 9pt; }
QLabel#StatusBadge {
    background-color: #E8F0FF;
    color: #1D4ED8;
    border: 1px solid #C9D9FF;
    border-radius: 10px;
    padding: 5px 10px;
    font-size: 9pt;
    font-weight: 700;
}
QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QSpinBox {
    background-color: #FFFFFF;
    color: #172033;
    border: 1px solid #C9D4E3;
    border-radius: 8px;
    padding: 8px 10px;
    selection-background-color: #DCE8FF;
    selection-color: #17336C;
}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus, QSpinBox:focus {
    border: 1px solid #3B70E2;
}
QComboBox::drop-down { border: none; width: 28px; }
QComboBox QAbstractItemView {
    background-color: #FFFFFF;
    color: #172033;
    border: 1px solid #C9D4E3;
    selection-background-color: #E8F0FF;
    selection-color: #17336C;
    padding: 4px;
}
QListWidget {
    background-color: #F8FAFC;
    color: #172033;
    border: 1px solid #DCE4EF;
    border-radius: 9px;
    padding: 4px;
}
QListWidget::item { padding: 7px 9px; border-radius: 6px; }
QListWidget::item:hover { background-color: #EEF3FA; }
QListWidget::item:selected { background-color: #DFE9FF; color: #17336C; }
QCheckBox {
    color: #475569;
    spacing: 7px;
    background-color: transparent;
    border: none;
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #AAB7CA;
    border-radius: 4px;
    background-color: #FFFFFF;
}
QCheckBox::indicator:hover { border-color: #3B70E2; }
QCheckBox::indicator:checked { background-color: #2E63D4; border-color: #2E63D4; }
QPushButton {
    min-height: 36px;
    border-radius: 8px;
    padding: 0 15px;
    font-size: 10pt;
    font-weight: 650;
}
QPushButton#PrimaryButton {
    background-color: #2457C5;
    color: #FFFFFF;
    border: 1px solid #1E4BAE;
}
QPushButton#PrimaryButton:hover { background-color: #2F67DA; }
QPushButton#PrimaryButton:pressed { background-color: #1E4BAE; }
QPushButton#PrimaryButton:disabled {
    background-color: #AFC1E7;
    color: #F5F7FB;
    border-color: #AFC1E7;
}
QPushButton#SecondaryButton {
    background-color: #FFFFFF;
    color: #334155;
    border: 1px solid #C9D4E3;
}
QPushButton#SecondaryButton:hover { background-color: #F1F5F9; border-color: #AAB7CA; }
QPushButton#DangerButton {
    background-color: #FFF1F2;
    color: #BE123C;
    border: 1px solid #FECDD3;
}
QPushButton#DangerButton:hover { background-color: #FFE4E6; }
QPushButton#DangerButton:disabled {
    background-color: #F8FAFC;
    color: #AAB4C3;
    border-color: #E2E8F0;
}
QPushButton#SidebarButton {
    background-color: #111C30;
    color: #D9E2F0;
    border: 1px solid #22314A;
}
QPushButton#SidebarButton:hover { background-color: #192842; border-color: #31486C; }
QPushButton#SidebarPrimaryButton {
    background-color: #2E63D4;
    color: #FFFFFF;
    border: 1px solid #3971E4;
}
QPushButton#SidebarPrimaryButton:hover { background-color: #3971E4; }
QRadioButton#ModeSwitch {
    background-color: transparent;
    color: #8494AE;
    border: none;
    border-radius: 7px;
    padding: 9px 12px;
    font-size: 9.5pt;
    font-weight: 650;
}
QRadioButton#ModeSwitch:hover { color: #E5ECF7; background-color: #152238; }
QRadioButton#ModeSwitch:checked { color: #FFFFFF; background-color: #2457C5; }
QRadioButton#ModeSwitch::indicator { width: 0px; height: 0px; }
QTreeWidget#InventoryTree {
    background-color: #0E1829;
    color: #CBD5E1;
    border: 1px solid #1D2A40;
    border-radius: 10px;
    padding: 6px;
    font-family: "SF Mono", Menlo, Consolas, monospace;
    font-size: 9.5pt;
    outline: none;
}
QTreeWidget#InventoryTree::item {
    min-height: 27px;
    padding: 2px 5px;
    border-radius: 6px;
}
QTreeWidget#InventoryTree::item:hover { background-color: #16243A; }
QTreeWidget#InventoryTree::item:selected { background-color: #244C9F; color: #FFFFFF; }
QMenu {
    background-color: #FFFFFF;
    color: #172033;
    border: 1px solid #D4DDE9;
    padding: 5px;
}
QMenu::item { padding: 7px 24px 7px 10px; border-radius: 5px; }
QMenu::item:selected { background-color: #E8F0FF; color: #17336C; }
QToolTip {
    background-color: #111827;
    color: #F8FAFC;
    border: 1px solid #334155;
    padding: 6px 8px;
}
QSplitter::handle { background-color: transparent; }
QSplitter::handle:hover { background-color: #C8D3E1; }
"""

BUTTON_STYLE = """
QPushButton {
    background-color: #2457C5;
    color: #FFFFFF;
    border: 1px solid #1E4BAE;
    border-radius: 8px;
    min-height: 36px;
    padding: 0 15px;
    font-weight: 650;
}
QPushButton:hover { background-color: #2F67DA; }
QPushButton:pressed { background-color: #1E4BAE; }
QPushButton:disabled { background-color: #AFC1E7; border-color: #AFC1E7; }
"""

SMALL_BUTTON_STYLE = """
QPushButton {
    background-color: #111C30;
    color: #D9E2F0;
    border: 1px solid #22314A;
    border-radius: 7px;
    min-height: 32px;
    padding: 0 11px;
    font-size: 9.5pt;
    font-weight: 650;
}
QPushButton:hover { background-color: #192842; border-color: #31486C; }
QPushButton:pressed { background-color: #0D1728; }
QPushButton:disabled { color: #66758D; border-color: #1A273B; }
"""

GHOST_BUTTON_STYLE = """
QPushButton {
    background-color: transparent;
    color: #9DAAC0;
    border: 1px solid #263750;
    border-radius: 7px;
    min-height: 32px;
    padding: 0 12px;
    font-size: 9.5pt;
    font-weight: 650;
}
QPushButton:hover { background-color: #152238; color: #FFFFFF; border-color: #3A506F; }
QPushButton:pressed { background-color: #0D1728; }
QPushButton:disabled { color: #526178; border-color: #1A273B; }
"""

STOP_BUTTON_STYLE = """
QPushButton {
    background-color: #FFF1F2;
    color: #BE123C;
    border: 1px solid #FECDD3;
    border-radius: 8px;
    min-height: 36px;
    padding: 0 15px;
    font-weight: 650;
}
QPushButton:hover { background-color: #FFE4E6; }
QPushButton:pressed { background-color: #FECDD3; }
QPushButton:disabled { background-color: #F8FAFC; color: #AAB4C3; border-color: #E2E8F0; }
"""

MAX_DEVICE_TREE_NODES = 10_000
MAX_DEVICE_TREE_DEPTH = 32
MAX_LABEL_LENGTH = 256
MAX_IMPORT_FILE_SIZE = 20 * 1024 * 1024  # 20 MB
MAX_BUNDLED_TEXT_ASSET_SIZE = 2 * 1024 * 1024  # 2 MB per required notice/snapshot
MAX_SOURCE_PROJECT_METADATA_SIZE = 256 * 1024  # 256 KiB for source-layout detection
MAX_WHEEL_METADATA_SIZE = 256 * 1024
MAX_WHEEL_RECORD_SIZE = 2 * 1024 * 1024
MAX_WHEEL_RECORD_ROWS = 4096
MAX_WHEEL_DIST_INFO_CANDIDATES = 1
MAX_WHEEL_MODULE_ROOT_ENTRIES = 4096
MAX_WHEEL_RECORD_PATH_LENGTH = 1024
_EXPECTED_WHEEL_ASSET_NAMES = frozenset(
    {
        "DISCLAIMER.md",
        "LICENSE",
        "PRIVACY.md",
        "SECURITY.md",
        "TERMS.md",
        "THIRD_PARTY_NOTICES.md",
        "TRADEMARKS.md",
        "clidarvi_symbol.svg",
        "docs/FIELD_TEST_CHECKLIST.md",
        "requirements-lock/runtime-py313.txt",
        "sbom/clidarvi-0.1.0a1.cdx.json",
        *INVENTORY_ICON_ASSETS.values(),
    }
)
MAX_XML_ELEMENTS = MAX_DEVICE_TREE_NODES + 1  # root plus bounded inventory entries
MAX_HISTORY_STATES = 20
MAX_HISTORY_TOTAL_ITEMS = 50_000
SITE_DATA_ROLE = int(Qt.ItemDataRole.UserRole) + 1


class EmptyStateListWidget(QListWidget):
    """List widget that explains its empty state without adding a fake list item."""

    def __init__(self, empty_text: str, parent=None):
        super().__init__(parent)
        self._empty_text = empty_text

    def paintEvent(self, event):
        super().paintEvent(event)
        if self.count():
            return
        painter = QPainter(self.viewport())
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)
        painter.setPen(QColor("#8190A6"))
        font = painter.font()
        font.setPointSizeF(9.5)
        painter.setFont(font)
        painter.drawText(
            self.viewport().rect().adjusted(18, 10, -18, -10),
            Qt.AlignmentFlag.AlignCenter | Qt.TextFlag.TextWordWrap,
            self._empty_text,
        )


# ---------- Node Dialog (Add / Edit) ----------
class NodeDialog(QDialog):
    """
    Unified dialog for adding or editing a node.
    mode: "add" or "edit"
    If mode == "edit", pass canonical device metadata in node_data.
    """

    def __init__(self, mode="add", node_data=None, parent=None):
        super().__init__(parent)
        if mode not in ("add", "edit"):
            raise ValueError("NodeDialog mode must be 'add' or 'edit'.")
        self.mode = mode
        self.device_id = (
            str(node_data.get("id"))
            if isinstance(node_data, dict) and node_data.get("id")
            else new_device_id()
        )
        self.setWindowTitle("Add Device" if mode == "add" else "Edit Device")
        self.setModal(True)
        self.setMinimumWidth(460)
        self.setStyleSheet(
            APP_STYLESHEET
            + """
            QDialog { background-color: #F2F5F9; }
            QLabel#DialogTitle { color:#111827; font-size:18pt; font-weight:750; }
            QLabel#DialogSubtitle { color:#64748B; font-size:9.5pt; }
            QLabel#FieldLabel { color:#334155; font-size:9.5pt; font-weight:650; }
            """
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 24, 26, 24)
        layout.setSpacing(9)

        dialog_title = QLabel("Add network device" if mode == "add" else "Edit network device")
        dialog_title.setObjectName("DialogTitle")
        dialog_subtitle = QLabel(
            "Connection details stay on this machine and are used only when you start a run."
        )
        dialog_subtitle.setObjectName("DialogSubtitle")
        dialog_subtitle.setWordWrap(True)
        layout.addWidget(dialog_title)
        layout.addWidget(dialog_subtitle)
        layout.addSpacing(8)

        # Friendly label and connection target are deliberately separate.
        label_caption = QLabel("Display name")
        label_caption.setObjectName("FieldLabel")
        self.label_edit = QLineEdit()
        self.label_edit.setAccessibleName("Display name")
        self.label_edit.setPlaceholderText("Core switch Example City")
        label_caption.setBuddy(self.label_edit)
        layout.addWidget(label_caption)
        layout.addWidget(self.label_edit)

        hostname_caption = QLabel("Hostname or IP address")
        hostname_caption.setObjectName("FieldLabel")
        self.hostname_edit = QLineEdit()
        self.hostname_edit.setAccessibleName("Hostname or IP address")
        self.hostname_edit.setPlaceholderText("switch.example.net or 192.0.2.10")
        hostname_caption.setBuddy(self.hostname_edit)
        layout.addWidget(hostname_caption)
        layout.addWidget(self.hostname_edit)

        # Vendor
        vendor_caption = QLabel("Platform vendor")
        vendor_caption.setObjectName("FieldLabel")
        self.vendor_combo = QComboBox()
        self.vendor_combo.setAccessibleName("Platform vendor")
        self.vendor_combo.addItems(list(VENDOR_MAP.keys()))
        vendor_caption.setBuddy(self.vendor_combo)
        layout.addWidget(vendor_caption)
        layout.addWidget(self.vendor_combo)

        role_caption = QLabel("Device role")
        role_caption.setObjectName("FieldLabel")
        self.device_role_combo = QComboBox()
        self.device_role_combo.setAccessibleName("Device role")
        self.device_role_combo.setToolTip(
            "Controls only the inventory icon. It does not change the SSH driver "
            "or Automation support."
        )
        for role_id, role_label in DEVICE_ROLE_CHOICES:
            self.device_role_combo.addItem(role_label, role_id)
        role_caption.setBuddy(self.device_role_combo)
        layout.addWidget(role_caption)
        layout.addWidget(self.device_role_combo)

        # Device Type
        device_type_caption = QLabel("SSH automation profile")
        device_type_caption.setObjectName("FieldLabel")
        self.device_type_edit = QLineEdit()
        self.device_type_edit.setAccessibleName("SSH automation profile")
        self.device_type_edit.setReadOnly(True)
        device_type_caption.setBuddy(self.device_type_edit)
        layout.addWidget(device_type_caption)
        layout.addWidget(self.device_type_edit)

        port_caption = QLabel("SSH port")
        port_caption.setObjectName("FieldLabel")
        self.port_spin = QSpinBox()
        self.port_spin.setAccessibleName("SSH port")
        self.port_spin.setRange(1, 65_535)
        self.port_spin.setValue(22)
        port_caption.setBuddy(self.port_spin)
        layout.addWidget(port_caption)
        layout.addWidget(self.port_spin)

        # Buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(8)
        self.ok_btn = QPushButton("Add" if mode == "add" else "Save")
        self.cancel_btn = QPushButton("Cancel")
        self.ok_btn.setObjectName("PrimaryButton")
        self.cancel_btn.setObjectName("SecondaryButton")
        button_layout.addStretch()
        button_layout.addWidget(self.cancel_btn)
        button_layout.addWidget(self.ok_btn)
        layout.addSpacing(8)
        layout.addLayout(button_layout)

        # Signals
        self.vendor_combo.currentTextChanged.connect(self._update_device_type)
        self.ok_btn.clicked.connect(self._validate_and_accept)
        self.cancel_btn.clicked.connect(self.reject)

        # Prefill for edit mode
        if mode == "edit" and isinstance(node_data, dict):
            self.hostname_edit.setText(node_data.get("hostname", ""))
            self.label_edit.setText(node_data.get("label") or node_data.get("hostname", ""))
            raw_vendor = node_data.get("vendor", "Other")
            vendor = LEGACY_VENDOR_ALIASES.get(raw_vendor, raw_vendor)
            idx = self.vendor_combo.findText(vendor)
            if idx >= 0:
                self.vendor_combo.setCurrentIndex(idx)
            else:
                self.vendor_combo.setCurrentIndex(self.vendor_combo.findText("Other"))
            device_type = node_data.get("device_type") or VENDOR_MAP.get(
                self.vendor_combo.currentText(),
                "generic",
            )
            # Old releases persisted UniFi OS as ``generic`` because it was
            # Live-CLI-only. Opening and explicitly saving that legacy record
            # is the deliberate migration point to the bounded diagnostics
            # profile; merely importing the old presentation label never
            # activates the profile.
            if raw_vendor in LEGACY_VENDOR_ALIASES and device_type == "generic":
                device_type = VENDOR_MAP.get(vendor, device_type)
            self.device_type_edit.setText(device_type)
            raw_role = node_data.get("device_role")
            role_index = self.device_role_combo.findData(raw_role)
            if role_index >= 0:
                self.device_role_combo.setCurrentIndex(role_index)
            else:
                self.device_role_combo.setCurrentIndex(0)
            try:
                self.port_spin.setValue(int(node_data.get("port", 22)))
            except (TypeError, ValueError):
                self.port_spin.setValue(22)
        else:
            # Default device type based on current vendor
            self._update_device_type(self.vendor_combo.currentText())

        QTimer.singleShot(50, self.hostname_edit.setFocus)

    def _update_device_type(self, vendor):
        device_type = VENDOR_MAP.get(vendor, "generic")
        self.device_type_edit.setText(device_type)

    def get_node_data(self):
        hostname = self.hostname_edit.text().strip()
        label = self.label_edit.text().strip() or hostname
        vendor = self.vendor_combo.currentText()
        device_type = self.device_type_edit.text().strip()
        device_role = self.device_role_combo.currentData()
        if not device_role:
            device_role = infer_legacy_device_role(vendor, device_type)
        return DeviceRecord(
            id=self.device_id,
            label=label,
            hostname=hostname,
            vendor=vendor,
            device_type=device_type,
            port=self.port_spin.value(),
            device_role=device_role,
        ).to_mapping()

    def _validate_and_accept(self):
        try:
            self.get_node_data()
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid Device", str(exc))
            return
        self.accept()


class SiteDialog(QDialog):
    """Create or edit a physical site and its location metadata."""

    def __init__(self, mode="add", site_data=None, parent=None):
        super().__init__(parent)
        if mode not in ("add", "edit"):
            raise ValueError("SiteDialog mode must be 'add' or 'edit'.")
        self.mode = mode
        self.setWindowTitle("Add Site" if mode == "add" else "Edit Site")
        self.setModal(True)
        self.setMinimumWidth(540)
        self.setStyleSheet(
            APP_STYLESHEET
            + """
            QDialog { background-color: #F2F5F9; }
            QLabel#DialogTitle { color:#111827; font-size:18pt; font-weight:750; }
            QLabel#DialogSubtitle { color:#64748B; font-size:9.5pt; }
            QLabel#FieldLabel { color:#334155; font-size:9.5pt; font-weight:650; }
            """
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 24, 26, 24)
        layout.setSpacing(9)

        dialog_title = QLabel("Add physical site" if mode == "add" else "Edit physical site")
        dialog_title.setObjectName("DialogTitle")
        dialog_subtitle = QLabel(
            "Stored locally and included in inventory exports. Never enter credentials here."
        )
        dialog_subtitle.setObjectName("DialogSubtitle")
        dialog_subtitle.setWordWrap(True)
        layout.addWidget(dialog_title)
        layout.addWidget(dialog_subtitle)
        layout.addSpacing(8)

        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("Example City data center")
        self._add_field(layout, "Site name", self.name_edit)

        self.site_type_combo = QComboBox()
        for site_type, display_name in SITE_TYPE_LABELS.items():
            self.site_type_combo.addItem(display_name, site_type)
        self._add_field(layout, "Site type", self.site_type_combo)

        self.address_edit = QLineEdit()
        self.address_edit.setPlaceholderText("1 Example Avenue")
        self._add_field(layout, "Street address", self.address_edit)

        location_row = QHBoxLayout()
        location_row.setSpacing(10)
        postal_column = QVBoxLayout()
        postal_column.setSpacing(5)
        city_column = QVBoxLayout()
        city_column.setSpacing(5)
        self.postal_code_edit = QLineEdit()
        self.postal_code_edit.setPlaceholderText("0000 XX")
        self.city_edit = QLineEdit()
        self.city_edit.setPlaceholderText("Example City")
        self._add_field(postal_column, "Postal code", self.postal_code_edit)
        self._add_field(city_column, "City", self.city_edit)
        location_row.addLayout(postal_column, 1)
        location_row.addLayout(city_column, 2)
        layout.addLayout(location_row)

        region_row = QHBoxLayout()
        region_row.setSpacing(10)
        region_column = QVBoxLayout()
        region_column.setSpacing(5)
        country_column = QVBoxLayout()
        country_column.setSpacing(5)
        self.region_edit = QLineEdit()
        self.region_edit.setPlaceholderText("Example Region")
        self.country_edit = QLineEdit()
        self.country_edit.setPlaceholderText("Exampleland")
        self._add_field(region_column, "State / province / region", self.region_edit)
        self._add_field(country_column, "Country", self.country_edit)
        region_row.addLayout(region_column, 1)
        region_row.addLayout(country_column, 1)
        layout.addLayout(region_row)

        self.notes_edit = QTextEdit()
        self.notes_edit.setPlaceholderText(
            "Optional site notes, access instructions, rack areas or operational context…"
        )
        self.notes_edit.setMaximumHeight(105)
        self._add_field(layout, "Notes", self.notes_edit)

        button_layout = QHBoxLayout()
        button_layout.setSpacing(8)
        self.save_btn = QPushButton("Add site" if mode == "add" else "Save changes")
        self.cancel_btn = QPushButton("Cancel")
        self.save_btn.setObjectName("PrimaryButton")
        self.cancel_btn.setObjectName("SecondaryButton")
        button_layout.addStretch()
        button_layout.addWidget(self.cancel_btn)
        button_layout.addWidget(self.save_btn)
        layout.addSpacing(8)
        layout.addLayout(button_layout)

        self.save_btn.clicked.connect(self._validate_and_accept)
        self.cancel_btn.clicked.connect(self.reject)

        if isinstance(site_data, dict):
            record = SiteRecord.from_mapping(site_data)
            self.name_edit.setText(record.name)
            site_type_index = self.site_type_combo.findData(record.site_type)
            if site_type_index >= 0:
                self.site_type_combo.setCurrentIndex(site_type_index)
            self.address_edit.setText(record.address)
            self.city_edit.setText(record.city)
            self.region_edit.setText(record.region)
            self.postal_code_edit.setText(record.postal_code)
            self.country_edit.setText(record.country)
            self.notes_edit.setPlainText(record.notes)

        QTimer.singleShot(50, self.name_edit.setFocus)

    @staticmethod
    def _add_field(layout, caption: str, widget):
        label = QLabel(caption)
        label.setObjectName("FieldLabel")
        label.setBuddy(widget)
        widget.setAccessibleName(caption)
        layout.addWidget(label)
        layout.addWidget(widget)

    def get_site_record(self) -> SiteRecord:
        return SiteRecord(
            name=self.name_edit.text(),
            site_type=self.site_type_combo.currentData(),
            address=self.address_edit.text(),
            city=self.city_edit.text(),
            region=self.region_edit.text(),
            postal_code=self.postal_code_edit.text(),
            country=self.country_edit.text(),
            notes=self.notes_edit.toPlainText(),
        )

    def _validate_and_accept(self):
        try:
            self.get_site_record()
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid Site", str(exc))
            return
        self.accept()


class LegalDialog(QDialog):
    """Show the license, warranty notice, privacy information, and dependency notices."""

    NOTICE_TABS = (
        ("Operational terms", "TERMS.md", False),
        ("License", "LICENSE", True),
        ("Warranty & risk", "DISCLAIMER.md", False),
        ("Privacy", "PRIVACY.md", False),
        ("Third-party software", "THIRD_PARTY_NOTICES.md", False),
        ("Names & trademarks", "TRADEMARKS.md", False),
    )
    OFFLINE_LINK_TARGETS = frozenset(
        {
            "TERMS.md",
            "LICENSE",
            "DISCLAIMER.md",
            "PRIVACY.md",
            "THIRD_PARTY_NOTICES.md",
            "TRADEMARKS.md",
            "SECURITY.md",
            "docs/FIELD_TEST_CHECKLIST.md",
        }
    )

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"About & Legal — {APP_NAME}")
        self.setModal(True)
        self.resize(820, 650)
        self.setMinimumSize(680, 520)
        self.setStyleSheet(APP_STYLESHEET)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(12)

        title = QLabel(f"{APP_NAME} {DISPLAY_VERSION}")
        title.setObjectName("DialogTitle")
        title.setStyleSheet("font-size:18pt; font-weight:750; color:#111827;")
        layout.addWidget(title)

        summary = QLabel(
            "Copyright © 2026 devnetdreamer (https://github.com/devnetdreamer) and Clidarvi "
            "contributors. Licensed under GNU GPL version 3 only. "
            "You may redistribute and modify Clidarvi under that license. The software is "
            "provided WITHOUT ANY WARRANTY, to the extent permitted by applicable law."
        )
        summary.setWordWrap(True)
        summary.setAccessibleName("License and warranty summary")
        summary.setStyleSheet(
            "background:#FFF7ED; color:#7C2D12; border:1px solid #FED7AA; "
            "border-radius:9px; padding:11px 13px;"
        )
        layout.addWidget(summary)

        if parent is not None and hasattr(parent, "_risk_acknowledgement_status_text"):
            status_text = parent._risk_acknowledgement_status_text()
        else:
            status_text = "Network acknowledgement status is unavailable."
        self.acceptance_status_label = QLabel(status_text)
        self.acceptance_status_label.setWordWrap(True)
        self.acceptance_status_label.setAccessibleName("Network acknowledgement status")
        self.acceptance_status_label.setStyleSheet(
            "background:#EFF6FF; color:#1E3A8A; border:1px solid #BFDBFE; "
            "border-radius:9px; padding:9px 12px;"
        )
        layout.addWidget(self.acceptance_status_label)

        tabs = QTabWidget()
        tabs.setAccessibleName("Legal and safety documents")
        self.notice_tabs = tabs
        self._notice_tab_indexes: dict[str, int] = {}
        self._reference_viewer: QTextBrowser | None = None
        for tab_title, filename, plain_text in self.NOTICE_TABS:
            viewer = QTextBrowser()
            self._configure_notice_viewer(viewer, tab_title, filename)
            content = self._read_notice(filename)
            if plain_text:
                viewer.setPlainText(content)
            else:
                viewer.setMarkdown(content)
            self._notice_tab_indexes[filename] = tabs.addTab(viewer, tab_title)
        layout.addWidget(tabs, 1)

        close_button = QPushButton("Close")
        close_button.setObjectName("PrimaryButton")
        close_button.setDefault(True)
        close_button.clicked.connect(self.accept)
        button_row = QHBoxLayout()
        button_row.addStretch()
        button_row.addWidget(close_button)
        layout.addLayout(button_row)

    def _configure_notice_viewer(
        self,
        viewer: QTextBrowser,
        accessible_name: str,
        filename: str,
    ) -> None:
        viewer.setReadOnly(True)
        # All navigation is handled below from a fixed local allowlist. Disabling
        # both automatic link modes prevents a notice click from opening a browser
        # or resolving an untrusted local path.
        viewer.setOpenLinks(False)
        viewer.setOpenExternalLinks(False)
        viewer.setAccessibleName(accessible_name)
        viewer.setProperty("notice_filename", filename)
        viewer.anchorClicked.connect(
            lambda url, source_viewer=viewer: self._open_local_notice_link(
                source_viewer,
                url,
            )
        )

    @staticmethod
    def _resolve_notice_target(origin: str, relative_path: str) -> str | None:
        """Resolve a POSIX-style notice link without escaping the bundled root."""

        if not relative_path or relative_path.startswith(("/", "\\")):
            return None
        combined_parts = [*Path(origin).parent.parts, *Path(relative_path).parts]
        resolved_parts: list[str] = []
        for part in combined_parts:
            if part in ("", "."):
                continue
            if part == "..":
                if not resolved_parts:
                    return None
                resolved_parts.pop()
                continue
            resolved_parts.append(part)
        return "/".join(resolved_parts)

    def _open_local_notice_link(self, source_viewer: QTextBrowser, url: QUrl) -> None:
        """Open only explicitly bundled notices, never a browser or network URL."""

        if url.scheme() or url.authority() or url.hasQuery():
            return

        relative_path = url.path()
        if not relative_path:
            if url.fragment():
                source_viewer.scrollToAnchor(url.fragment())
            return

        origin = source_viewer.property("notice_filename")
        if not isinstance(origin, str):
            return
        target = self._resolve_notice_target(origin, relative_path)
        if target not in self.OFFLINE_LINK_TARGETS:
            return

        tab_index = self._notice_tab_indexes.get(target)
        if tab_index is not None:
            self.notice_tabs.setCurrentIndex(tab_index)
            target_viewer = self.notice_tabs.widget(tab_index)
            if url.fragment() and isinstance(target_viewer, QTextBrowser):
                target_viewer.scrollToAnchor(url.fragment())
            return

        content = self._read_notice(target)
        if self._reference_viewer is None:
            self._reference_viewer = QTextBrowser()
            self._configure_notice_viewer(
                self._reference_viewer,
                "Linked local legal or safety document",
                target,
            )
            tab_index = self.notice_tabs.addTab(self._reference_viewer, Path(target).name)
        else:
            tab_index = self.notice_tabs.indexOf(self._reference_viewer)
            self._reference_viewer.setProperty("notice_filename", target)
            self.notice_tabs.setTabText(tab_index, Path(target).name)
        self._reference_viewer.setMarkdown(content)
        self.notice_tabs.setCurrentIndex(tab_index)
        if url.fragment():
            self._reference_viewer.scrollToAnchor(url.fragment())

    @staticmethod
    def _read_notice(filename: str) -> str:
        snapshot = _resolve_bundled_asset(filename)
        if snapshot is None:
            return f"{filename} was not found in this installation."
        try:
            return snapshot[1].decode("utf-8")
        except UnicodeError as exc:
            return f"Unable to read {filename}: {exc}"


class RiskAcknowledgementDialog(QDialog):
    """Require an explicit operational-risk acknowledgement before networking."""

    def __init__(self, snapshot: dict[str, Any], parent=None):
        super().__init__(parent)
        self.snapshot = snapshot
        self.setWindowTitle("Safety & Operational Risk Acknowledgement")
        self.setModal(True)
        self.setWindowModality(Qt.WindowModality.ApplicationModal)
        self.resize(860, 760)
        self.setMinimumSize(720, 620)
        self.setStyleSheet(APP_STYLESHEET)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(12)

        title = QLabel("Review before using network features")
        title.setObjectName("DialogTitle")
        title.setStyleSheet("font-size:18pt; font-weight:750; color:#111827;")
        layout.addWidget(title)

        explanation = QLabel(
            "Clidarvi's legal documents remain available without accepting this "
            "acknowledgement. Continuing acknowledges operational risk for the declared "
            "application version and the bundled required-document snapshot. This record "
            "does not verify the running executable or installed dependencies. It does not "
            "ask you to accept the GPL or restrict any rights granted by the GPL."
        )
        explanation.setWordWrap(True)
        explanation.setAccessibleName("Acknowledgement scope")
        self.scope_label = explanation
        layout.addWidget(explanation)

        self.metadata_label = QLabel(
            f"Declared application version: {snapshot['declared_app_version']}\n"
            f"Terms ID: {snapshot['terms_id']}\n"
            f"Bundled required-document SHA-256: {snapshot['bundle_sha256']}"
        )
        self.metadata_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.metadata_label.setAccessibleName("Declared version and bundled-document hash")
        self.metadata_label.setStyleSheet(
            "background:#FFF7ED; color:#7C2D12; border:1px solid #FED7AA; "
            "border-radius:9px; padding:11px 13px; font-family:monospace;"
        )
        layout.addWidget(self.metadata_label)

        self.terms_viewer = QPlainTextEdit()
        self.terms_viewer.setReadOnly(True)
        self.terms_viewer.setPlainText(snapshot["accepted_copy"])
        self.terms_viewer.setAccessibleName(
            "Bundled acknowledgement documents and required runtime-lock snapshot"
        )
        layout.addWidget(self.terms_viewer, 1)

        self.acknowledgement_checkboxes = []
        for acknowledgement_id, label in RISK_ACKNOWLEDGEMENTS:
            checkbox = QCheckBox(label)
            checkbox.setChecked(False)
            checkbox.setProperty("acknowledgement_id", acknowledgement_id)
            checkbox.setAccessibleName(label)
            checkbox.toggled.connect(self._update_continue_state)
            self.acknowledgement_checkboxes.append(checkbox)
            layout.addWidget(checkbox)

        button_row = QHBoxLayout()
        self.save_button = QPushButton("Save exact copy…")
        self.save_button.setObjectName("SecondaryButton")
        self.save_button.clicked.connect(self._save_exact_copy)
        button_row.addWidget(self.save_button)
        button_row.addStretch()

        self.decline_button = QPushButton("Decline / Cancel")
        self.decline_button.setObjectName("SecondaryButton")
        self.decline_button.clicked.connect(self.reject)
        button_row.addWidget(self.decline_button)

        self.accept_button = QPushButton("Acknowledge and continue")
        self.accept_button.setObjectName("PrimaryButton")
        self.accept_button.setEnabled(False)
        self.accept_button.setDefault(False)
        self.accept_button.clicked.connect(self.accept)
        button_row.addWidget(self.accept_button)
        layout.addLayout(button_row)

    def is_fully_acknowledged(self) -> bool:
        return bool(self.acknowledgement_checkboxes) and all(
            checkbox.isChecked() for checkbox in self.acknowledgement_checkboxes
        )

    def _update_continue_state(self) -> None:
        self.accept_button.setEnabled(self.is_fully_acknowledged())

    def accept(self) -> None:
        if self.is_fully_acknowledged():
            super().accept()

    def _save_exact_copy(self) -> None:
        suggested = Path.home() / (
            f"Clidarvi-{self.snapshot['declared_app_version']}-accepted-terms.txt"
        )
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Exact Terms Copy",
            str(suggested),
            "Text Files (*.txt);;All Files (*)",
        )
        if not file_path:
            return
        try:
            atomic_write_text(Path(file_path), self.snapshot["accepted_copy"])
        except Exception as exc:
            QMessageBox.critical(self, "Save Failed", f"Unable to save the exact copy:\n{exc}")


# ---------- Utilities ----------
def _apply_secure_permissions(path: Path, mode: int):
    """Backward-compatible wrapper for callers that do not require strict chmod."""

    return apply_private_permissions(path, mode)


def safe_write_output(basedir: str, content: str) -> str:
    # Ensure the outputs directory exists and is locked down.
    outdir = ensure_directory(Path(basedir) / "outputs", private=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    fname = f"Clidarvi-{ts}.txt"
    return write_output_to_path(outdir / fname, content)


def write_output_to_path(path: Path, content: str) -> str:
    # Preserve permissions on an existing user-selected parent directory.
    return str(atomic_write_text(Path(path), content))


def get_application_data_directory() -> Path:
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    elif sys.platform == "win32":
        configured = os.environ.get("APPDATA")
        candidate = Path(configured) if configured else None
        base = (
            candidate
            if candidate is not None and candidate.is_absolute()
            else Path.home() / "AppData" / "Roaming"
        )
    else:
        configured = os.environ.get("XDG_DATA_HOME")
        candidate = Path(configured) if configured else None
        base = (
            candidate
            if candidate is not None and candidate.is_absolute()
            else Path.home() / ".local" / "share"
        )
    return ensure_directory(base / "Clidarvi", private=True)


def _read_bounded_regular_file(path: Path | str, *, max_bytes: int) -> bytes:
    """Read one immutable-enough regular-file snapshot through a single fd.

    Imports and startup state are local inputs, but they are still untrusted.
    Refuse symlinks and special files, cap bytes while reading, and reject a
    file that changed underneath the read instead of validating one pathname
    and later parsing another object.
    """

    source = Path(path)
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("The file-size limit must be a positive integer.")
    try:
        before_path = os.lstat(source)
    except OSError as exc:
        raise ValueError(f"Unable to access file: {exc}") from exc
    if stat.S_ISLNK(before_path.st_mode) or not stat.S_ISREG(before_path.st_mode):
        raise ValueError("Only a regular, non-symlink file can be read.")
    if before_path.st_size > max_bytes:
        raise ValueError("File is too large to be processed safely.")

    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    descriptor = None
    try:
        descriptor = os.open(source, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before_path, opened):
            raise ValueError("File changed before it could be read safely.")

        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise ValueError("File is too large to be processed safely.")
        finished = os.fstat(descriptor)
        if not os.path.samestat(opened, finished) or (
            opened.st_size != finished.st_size
            or getattr(opened, "st_mtime_ns", None) != getattr(finished, "st_mtime_ns", None)
        ):
            raise ValueError("File changed while it was being read.")
        return b"".join(chunks)
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError(f"Unable to read file safely: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _reject_duplicate_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key is not permitted: {key!r}")
        result[key] = value
    return result


def _reject_nonfinite_json_constant(value: str) -> Any:
    raise ValueError(f"Non-finite JSON number is not permitted: {value}")


def _parse_finite_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"Non-finite JSON number is not permitted: {value}")
    return parsed


def _load_strict_json_snapshot(raw: bytes) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("JSON inventory must be valid UTF-8.") from exc
    try:
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_json_pairs,
            parse_constant=_reject_nonfinite_json_constant,
            parse_float=_parse_finite_json_float,
        )
    except RecursionError as exc:
        raise ValueError("JSON document exceeds the permitted nesting depth.") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON inventory: {exc}") from exc
    if not isinstance(document, dict):
        raise ValueError("Inventory document must be a JSON object.")
    return document


def _render_bounded_inventory_document(document: dict[str, Any]) -> str:
    """Render an inventory that the same release can read back safely."""

    payload = json.dumps(document, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    if len(payload.encode("utf-8")) > MAX_IMPORT_FILE_SIZE:
        raise ValueError(
            "Inventory exceeds the 20 MiB persisted-file limit. Reduce site notes, "
            "folders, or devices before saving or exporting."
        )
    return payload


def _is_clidarvi_source_checkout(module_root: Path) -> bool:
    """Identify this project's source layout without trusting a filename alone."""

    try:
        raw_project = _read_bounded_regular_file(
            module_root / "pyproject.toml",
            max_bytes=MAX_SOURCE_PROJECT_METADATA_SIZE,
        )
        document = tomllib.loads(raw_project.decode("utf-8"))
    except (OSError, UnicodeError, ValueError, RecursionError):
        return False

    project = document.get("project")
    tool = document.get("tool")
    if not isinstance(project, dict) or not isinstance(tool, dict):
        return False
    gui_scripts = project.get("gui-scripts")
    setuptools = tool.get("setuptools")
    if not isinstance(gui_scripts, dict) or not isinstance(setuptools, dict):
        return False
    modules = setuptools.get("py-modules")
    if not isinstance(modules, list) or not all(isinstance(name, str) for name in modules):
        return False

    required_modules = {
        "clidarvi",
        "clidarvi_core",
        "clidarvi_io",
        "clidarvi_policy",
        "clidarvi_workers",
    }
    return (
        project.get("name") == "clidarvi"
        and gui_scripts.get("clidarvi") == "clidarvi:main"
        and required_modules.issubset(modules)
    )


def _normalized_asset_names(names: tuple[str, ...]) -> tuple[str, ...] | None:
    """Accept only canonical, relative POSIX asset names from the fixed bundle."""

    normalized = []
    for name in names:
        if not isinstance(name, str) or not name or len(name) > MAX_WHEEL_RECORD_PATH_LENGTH:
            return None
        if "\\" in name or any(ord(character) < 32 or ord(character) == 127 for character in name):
            return None
        posix_path = PurePosixPath(name)
        windows_path = PureWindowsPath(name)
        if posix_path.is_absolute() or windows_path.is_absolute() or windows_path.drive:
            return None
        if posix_path.as_posix() != name or any(
            part in {"", ".", ".."} for part in posix_path.parts
        ):
            return None
        normalized.append(name)
    return tuple(normalized)


def _record_payload_matches(
    payload: bytes,
    record_entry: tuple[str | None, int | None] | None,
) -> bool:
    if record_entry is None:
        return False
    expected_hash, expected_size = record_entry
    if expected_hash is None or expected_size is None or len(payload) != expected_size:
        return False
    actual_hash = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()
    return actual_hash == expected_hash


def _parse_clidarvi_wheel_record(
    raw_record: bytes,
) -> (
    tuple[
        dict[str, tuple[str | None, int | None]],
        dict[str, tuple[int, str, int]],
    ]
    | None
):
    """Parse one bounded wheel RECORD and extract its exact runtime asset set."""

    try:
        record_text = raw_record.decode("utf-8")
        rows = csv.reader(io.StringIO(record_text, newline=""), strict=True)
        entries: dict[str, tuple[str | None, int | None]] = {}
        assets: dict[str, tuple[int, str, int]] = {}
        row_count = 0
        for row in rows:
            row_count += 1
            if row_count > MAX_WHEEL_RECORD_ROWS or len(row) != 3:
                return None
            record_path, hash_field, size_field = row
            if (
                not record_path
                or len(record_path) > MAX_WHEEL_RECORD_PATH_LENGTH
                or "\\" in record_path
                or any(ord(character) < 32 or ord(character) == 127 for character in record_path)
            ):
                return None
            posix_path = PurePosixPath(record_path)
            windows_path = PureWindowsPath(record_path)
            if (
                posix_path.is_absolute()
                or windows_path.is_absolute()
                or windows_path.drive
                or posix_path.as_posix() != record_path
                or record_path in entries
                or len(tuple(part for part in posix_path.parts if part == "..")) > 8
                or any(
                    part == ".." and index > 0 and posix_path.parts[index - 1] != ".."
                    for index, part in enumerate(posix_path.parts)
                )
            ):
                return None

            if not hash_field and not size_field:
                entry: tuple[str | None, int | None] = (None, None)
            else:
                if (
                    re.fullmatch(r"sha256=([A-Za-z0-9_-]{43})", hash_field) is None
                    or re.fullmatch(r"(?:0|[1-9][0-9]{0,18})", size_field) is None
                ):
                    return None
                size = int(size_field)
                if size > MAX_BUNDLED_TEXT_ASSET_SIZE:
                    return None
                entry = (hash_field.removeprefix("sha256="), size)
            entries[record_path] = entry

            parts = posix_path.parts
            asset_offsets = [
                index
                for index in range(len(parts) - 1)
                if parts[index : index + 2] == ("share", "clidarvi")
            ]
            if not asset_offsets:
                continue
            if len(asset_offsets) != 1:
                return None
            offset = asset_offsets[0]
            leading_parts = parts[:offset]
            asset_parts = parts[offset + 2 :]
            if (
                len(leading_parts) > 8
                or any(part != ".." for part in leading_parts)
                or not asset_parts
                or any(part in {"", ".", ".."} for part in asset_parts)
                or entry[0] is None
                or entry[1] is None
            ):
                return None
            asset_name = "/".join(asset_parts)
            if asset_name in assets:
                return None
            assets[asset_name] = (len(leading_parts), entry[0], entry[1])
    except (csv.Error, UnicodeError, ValueError):
        return None

    if row_count == 0:
        return None
    return entries, assets


def _bounded_asset_snapshot(root: Path, asset_name: str) -> tuple[Path, bytes] | None:
    """Read a canonical asset beneath one resolved root without following it outside."""

    try:
        resolved_root = root.resolve()
        candidate = resolved_root.joinpath(*PurePosixPath(asset_name).parts)
        if not candidate.resolve().is_relative_to(resolved_root):
            return None
        payload = _read_bounded_regular_file(candidate, max_bytes=MAX_BUNDLED_TEXT_ASSET_SIZE)
    except (OSError, RuntimeError, ValueError):
        return None
    return candidate, payload


def _load_installed_wheel_asset_snapshots(
    module_path: Path,
) -> tuple[bool, dict[str, tuple[Path, bytes]] | None]:
    """Bind assets to exactly one RECORD-owned wheel layout.

    The boolean reports whether adjacent Clidarvi distribution metadata exists. Any
    malformed, incomplete, or ambiguous installation then fails closed instead of
    falling back to a source or interpreter-wide asset directory.
    """

    module_root = module_path.parent
    candidates = []
    try:
        for entry_count, child in enumerate(module_root.iterdir(), start=1):
            if entry_count > MAX_WHEEL_MODULE_ROOT_ENTRIES:
                return True, None
            if not (
                child.name.casefold().startswith("clidarvi-")
                and child.name.casefold().endswith(".dist-info")
            ):
                continue
            candidates.append(child)
            if len(candidates) > MAX_WHEEL_DIST_INFO_CANDIDATES:
                return True, None
    except OSError:
        return True, None
    if not candidates:
        return False, None

    dist_info = candidates[0]
    if dist_info.is_symlink() or not dist_info.is_dir() or module_path.name != "clidarvi.py":
        return True, None

    metadata_path = dist_info / "METADATA"
    record_path = dist_info / "RECORD"
    try:
        module_payload = _read_bounded_regular_file(
            module_path,
            max_bytes=MAX_BUNDLED_TEXT_ASSET_SIZE,
        )
        metadata_payload = _read_bounded_regular_file(
            metadata_path,
            max_bytes=MAX_WHEEL_METADATA_SIZE,
        )
        raw_record = _read_bounded_regular_file(
            record_path,
            max_bytes=MAX_WHEEL_RECORD_SIZE,
        )
        metadata = BytesParser(policy=policy.compat32).parsebytes(
            metadata_payload,
            headersonly=True,
        )
    except (OSError, UnicodeError, ValueError):
        return True, None

    if (
        metadata.defects
        or metadata.get_all("Name") != ["clidarvi"]
        or metadata.get_all("Version") != [__version__]
    ):
        return True, None

    parsed_record = _parse_clidarvi_wheel_record(raw_record)
    if parsed_record is None:
        return True, None
    entries, asset_records = parsed_record
    if set(asset_records) != _EXPECTED_WHEEL_ASSET_NAMES:
        return True, None
    if not _record_payload_matches(module_payload, entries.get("clidarvi.py")):
        return True, None
    metadata_record_name = f"{dist_info.name}/METADATA"
    if not _record_payload_matches(metadata_payload, entries.get(metadata_record_name)):
        return True, None

    leading_counts = {entry[0] for entry in asset_records.values()}
    if len(leading_counts) != 1:
        return True, None
    leading_count = leading_counts.pop()
    native_base = module_root
    for _ in range(leading_count):
        if native_base.parent == native_base:
            return True, None
        native_base = native_base.parent
    if native_base.parent == native_base:
        return True, None

    try:
        candidate_roots = {
            (native_base / "share" / "clidarvi").resolve(),
            (module_root / "share" / "clidarvi").resolve(),
        }
    except (OSError, RuntimeError, ValueError):
        return True, None
    matching_layouts: list[dict[str, tuple[Path, bytes]]] = []
    for root in candidate_roots:
        snapshots: dict[str, tuple[Path, bytes]] = {}
        for asset_name in sorted(_EXPECTED_WHEEL_ASSET_NAMES):
            snapshot = _bounded_asset_snapshot(root, asset_name)
            if snapshot is None:
                break
            _, expected_hash, expected_size = asset_records[asset_name]
            if not _record_payload_matches(snapshot[1], (expected_hash, expected_size)):
                break
            snapshots[asset_name] = snapshot
        else:
            matching_layouts.append(snapshots)

    if len(matching_layouts) != 1:
        return True, None
    return True, matching_layouts[0]


def _resolve_bundled_asset(*names: str) -> tuple[Path, bytes] | None:
    """Resolve and read one coherent source or RECORD-owned asset snapshot."""

    normalized_names = _normalized_asset_names(names)
    if not normalized_names:
        return None

    try:
        module_path = Path(__file__).resolve()
    except (OSError, RuntimeError, ValueError):
        return None
    installation_metadata_present, installed_assets = _load_installed_wheel_asset_snapshots(
        module_path
    )
    if installation_metadata_present:
        if installed_assets is None:
            return None
        for name in normalized_names:
            snapshot = installed_assets.get(name)
            if snapshot is not None:
                return snapshot
        return None

    module_root = module_path.parent
    if not _is_clidarvi_source_checkout(module_root):
        return None
    for name in normalized_names:
        snapshot = _bounded_asset_snapshot(module_root, name)
        if snapshot is not None:
            return snapshot
    return None


def find_asset_path(*names: str) -> Path | None:
    """Locate a validated bundled asset in one coherent source or wheel layout."""

    snapshot = _resolve_bundled_asset(*names)
    return snapshot[0] if snapshot is not None else None


def _load_risk_terms_snapshot() -> dict[str, Any]:
    """Hash the declared version and bundled documents presented for acknowledgement."""

    documents = []
    document_sha256 = {}
    for document_id, filename in RISK_REQUIRED_DOCUMENTS:
        snapshot = _resolve_bundled_asset(filename)
        if snapshot is None:
            raise FileNotFoundError(f"Required acknowledgement asset is missing: {filename}")
        raw_content = snapshot[1]
        try:
            content = raw_content.decode("utf-8")
        except UnicodeError as exc:
            raise RuntimeError(f"Unable to read acknowledgement asset {filename}: {exc}") from exc
        digest = hashlib.sha256(raw_content).hexdigest()
        document_sha256[document_id] = digest
        documents.append(
            {
                "id": document_id,
                "filename": filename,
                "sha256": digest,
                "content": content,
            }
        )

    terms_content = documents[0]["content"]
    terms_id_match = re.search(
        r"^\*\*Terms ID:\*\*\s*`([^`]+)`\s*$",
        terms_content,
        flags=re.MULTILINE,
    )
    version_match = re.search(
        r"^\*\*For application version:\*\*\s*`([^`]+)`\s*$",
        terms_content,
        flags=re.MULTILINE,
    )
    publisher_match = re.search(
        r"^\*\*Publisher:\*\*\s*(.+?)\s*$",
        terms_content,
        flags=re.MULTILINE,
    )
    if terms_id_match is None or terms_id_match.group(1) != RISK_TERMS_ID:
        raise RuntimeError("TERMS.md does not declare the required Terms ID")
    if version_match is None or version_match.group(1) != __version__:
        raise RuntimeError("TERMS.md does not match this application version")
    if publisher_match is None:
        raise RuntimeError("TERMS.md does not declare a Publisher line")
    publisher_value = publisher_match.group(1).strip().strip("`").strip()
    publisher_is_plain_placeholder = publisher_value.casefold() in {
        "",
        "n/a",
        "none",
        "placeholder",
        "publisher name",
        "publisher legal name and contact",
        "tbc",
        "tbd",
        "todo",
        "unknown",
        "your name",
        "your legal name",
    }
    if (
        RISK_PUBLISHER_PLACEHOLDER.casefold() in terms_content.casefold()
        or RISK_EXPLICIT_PUBLISHER_PLACEHOLDER_RE.search(terms_content)
        or publisher_is_plain_placeholder
        or re.match(
            r"^(?:TODO|TBD|TBC|FIXME|PLACEHOLDER)(?:\b|\s*:)",
            publisher_value,
            flags=re.IGNORECASE,
        )
    ):
        raise RuntimeError(
            "TERMS.md still contains an unfilled publisher placeholder; network features "
            "remain disabled"
        )

    canonical_bundle = {
        "schema_version": RISK_ACKNOWLEDGEMENT_SCHEMA_VERSION,
        "declared_app_version": __version__,
        "terms_id": RISK_TERMS_ID,
        "documents": documents,
    }
    canonical_bytes = json.dumps(
        canonical_bundle,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    bundle_sha256 = hashlib.sha256(canonical_bytes).hexdigest()

    copy_lines = [
        f"{APP_NAME} — bundled acknowledgement-material snapshot",
        f"Declared application version: {__version__}",
        f"Terms ID: {RISK_TERMS_ID}",
        f"Bundled required-document SHA-256: {bundle_sha256}",
        "",
        "The SHA-256 above covers the declared application version, terms ID, filenames, "
        "individual hashes, and exact UTF-8 content of the bundled documents below.",
        "It does not hash or verify the running executable, source tree, or installed "
        "runtime dependencies. The runtime lock is a bundled required-snapshot document.",
    ]
    for document in documents:
        filename = document["filename"]
        copy_lines.extend(
            (
                "",
                f"===== BEGIN {filename} =====",
                document["content"],
                f"===== END {filename} =====",
            )
        )
    accepted_copy = "\n".join(copy_lines)
    if not accepted_copy.endswith("\n"):
        accepted_copy += "\n"

    return {
        "schema_version": RISK_ACKNOWLEDGEMENT_SCHEMA_VERSION,
        "declared_app_version": __version__,
        "terms_id": RISK_TERMS_ID,
        "bundle_sha256": bundle_sha256,
        "document_sha256": document_sha256,
        "bundled_required_snapshot": RISK_REQUIRED_DOCUMENTS[-1][1],
        "documents": documents,
        "accepted_copy": accepted_copy,
    }


class TerminalWidget(QPlainTextEdit):
    MAX_BUFFER_CHARS = 200_000  # ~200 KB of terminal history

    def __init__(self, worker: InteractiveSSHWorker, parent=None):
        super().__init__(parent)
        self.worker = worker
        self._terminal_control_carry = ""
        self._terminal_string_discard = None
        self._terminal_string_escape_pending = False
        self.setStyleSheet(
            """
            QPlainTextEdit {
                background-color: #070D18;
                color: #D7E3F4;
                border: 1px solid #1D2A40;
                border-radius: 10px;
                border-top-left-radius: 0px;
                padding: 12px 14px;
                selection-background-color: #294268;
                selection-color: #FFFFFF;
                font-family: "SF Mono", "Cascadia Mono", Menlo, Consolas, monospace;
                font-size: 11pt;
            }
        """
        )
        self.setAccessibleName("Interactive SSH terminal")
        self.setReadOnly(True)
        self.setUndoRedoEnabled(False)
        self.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
            | Qt.TextInteractionFlag.TextSelectableByKeyboard
        )

    def _plain_terminal_chunk(self, text: str) -> str:
        """Strip terminal controls incrementally, including split CSI/OSC."""

        data = self._terminal_control_carry + text
        self._terminal_control_carry = ""
        output: list[str] = []
        index = 0
        length = len(data)

        # An unterminated terminal string can span arbitrarily many chunks.
        # Once its retained payload reaches the cap, remember only the parser
        # state and discard bytes until BEL/ST rather than forgetting that the
        # terminal is still inside an OSC/DCS/SOS/PM/APC string.
        if self._terminal_string_discard is not None:
            introducer = self._terminal_string_discard
            terminated = False
            if self._terminal_string_escape_pending:
                self._terminal_string_escape_pending = False
                if index < length and data[index] == "\\":
                    index += 1
                    terminated = True
            while not terminated and index < length:
                if introducer == "]" and data[index] == "\x07":
                    index += 1
                    terminated = True
                    break
                if data[index] == "\x9c":
                    index += 1
                    terminated = True
                    break
                if data[index] == "\x1b":
                    if index + 1 >= length:
                        self._terminal_string_escape_pending = True
                        index += 1
                        break
                    if data[index + 1] == "\\":
                        index += 2
                        terminated = True
                        break
                index += 1
            if not terminated:
                return ""
            self._terminal_string_discard = None

        while index < length:
            character = data[index]
            if character in {
                "\x1b",  # ESC: 7-bit control-sequence introducer
                "\x90",  # DCS
                "\x98",  # SOS
                "\x9b",  # CSI
                "\x9d",  # OSC
                "\x9e",  # PM
                "\x9f",  # APC
            }:
                start = index
                if character == "\x1b":
                    if index + 1 >= length:
                        self._terminal_control_carry = data[start:]
                        break
                    introducer = data[index + 1]
                    index += 2
                else:
                    introducer = {
                        "\x90": "P",
                        "\x98": "X",
                        "\x9b": "[",
                        "\x9d": "]",
                        "\x9e": "^",
                        "\x9f": "_",
                    }[character]
                    index += 1

                if introducer == "[":
                    while index < length and not ("@" <= data[index] <= "~"):
                        index += 1
                    if index >= length:
                        self._terminal_control_carry = data[start:]
                        break
                    index += 1
                    continue
                if introducer in {"]", "P", "X", "^", "_"}:
                    terminated = False
                    while index < length:
                        # BEL is the conventional OSC terminator. Other
                        # terminal strings require ST so embedded BEL bytes do
                        # not expose their remaining payload.
                        if introducer == "]" and data[index] == "\x07":
                            index += 1
                            terminated = True
                            break
                        if data[index] == "\x9c":
                            index += 1
                            terminated = True
                            break
                        if data[index] == "\x1b":
                            if index + 1 >= length:
                                break
                            if data[index + 1] == "\\":
                                index += 2
                                terminated = True
                                break
                        index += 1
                    if not terminated:
                        incomplete = data[start:]
                        if len(incomplete) > 4096:
                            self._terminal_string_discard = introducer
                            self._terminal_string_escape_pending = incomplete.endswith("\x1b")
                        else:
                            self._terminal_control_carry = incomplete
                        break
                    continue
                # ESC sequences may have intermediate bytes (for example
                # ESC ( B). Consume their final byte as well, retaining an
                # incomplete sequence for the next chunk.
                if "\x20" <= introducer <= "\x2f":
                    while index < length and "\x20" <= data[index] <= "\x2f":
                        index += 1
                    if index >= length:
                        self._terminal_control_carry = data[start:]
                        break
                    index += 1
                continue

            category = unicodedata.category(character)
            if character in {"\n", "\r", "\b", "\t"}:
                output.append(character)
            elif category not in {"Cc", "Cf"}:
                output.append(character)
            index += 1
        # Never retain attacker-controlled control sequences without a bound.
        if len(self._terminal_control_carry) > 4096:
            self._terminal_control_carry = ""
        return "".join(output)

    def handle_output(self, text: str):
        if not text:
            return
        plain_text = self._plain_terminal_chunk(text).replace("\r\n", "\n")
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        pending = []

        def flush_pending():
            if pending:
                cursor.insertText("".join(pending))
                pending.clear()

        for character in plain_text:
            if character == "\r":
                flush_pending()
                cursor.movePosition(QTextCursor.MoveOperation.StartOfLine)
                cursor.movePosition(
                    QTextCursor.MoveOperation.EndOfLine,
                    QTextCursor.MoveMode.KeepAnchor,
                )
                cursor.removeSelectedText()
            elif character == "\b":
                flush_pending()
                if cursor.positionInBlock() > 0:
                    cursor.deletePreviousChar()
            elif character == "\x00":
                continue
            else:
                pending.append(character)
        flush_pending()
        self.setTextCursor(cursor)
        doc = self.document()
        overflow = doc.characterCount() - self.MAX_BUFFER_CHARS
        if overflow > 0:
            cursor = QTextCursor(doc)
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            cursor.movePosition(
                QTextCursor.MoveOperation.Right,
                QTextCursor.MoveMode.KeepAnchor,
                overflow,
            )
            cursor.removeSelectedText()
        self.moveCursor(QTextCursor.MoveOperation.End)
        self.ensureCursorVisible()

    def handle_output_ready(self, _notification: str = ""):
        """Drain one bounded worker batch for a coalesced output wake-up."""

        text = self.worker.drain_output()
        if text:
            self.handle_output(text)

    def keyPressEvent(self, event):
        modifiers = event.modifiers()
        if event.matches(QKeySequence.StandardKey.Copy) and self.textCursor().hasSelection():
            self.copy()
            return
        if event.matches(QKeySequence.StandardKey.Paste) or (
            modifiers & Qt.KeyboardModifier.ControlModifier
            and modifiers & Qt.KeyboardModifier.ShiftModifier
            and event.key() == Qt.Key.Key_V
        ):
            self.worker.send_input(QApplication.clipboard().text())
            return

        key_sequences = {
            Qt.Key.Key_Return: "\r",
            Qt.Key.Key_Enter: "\r",
            Qt.Key.Key_Backspace: "\x7f",
            Qt.Key.Key_Tab: "\t",
            Qt.Key.Key_Up: "\x1b[A",
            Qt.Key.Key_Down: "\x1b[B",
            Qt.Key.Key_Right: "\x1b[C",
            Qt.Key.Key_Left: "\x1b[D",
            Qt.Key.Key_Home: "\x1b[H",
            Qt.Key.Key_End: "\x1b[F",
            Qt.Key.Key_Delete: "\x1b[3~",
            Qt.Key.Key_PageUp: "\x1b[5~",
            Qt.Key.Key_PageDown: "\x1b[6~",
            Qt.Key.Key_F1: "\x1bOP",
            Qt.Key.Key_F2: "\x1bOQ",
            Qt.Key.Key_F3: "\x1bOR",
            Qt.Key.Key_F4: "\x1bOS",
        }
        if event.key() in key_sequences:
            self.worker.send_input(key_sequences[event.key()])
            return

        # Qt swaps the semantic modifier names on macOS: physical Control is
        # MetaModifier and Command is ControlModifier. Select exactly one so a
        # Command shortcut can never become a terminal control byte.
        control_like = (
            Qt.KeyboardModifier.MetaModifier
            if sys.platform == "darwin"
            else Qt.KeyboardModifier.ControlModifier
        )
        alt_held = bool(modifiers & Qt.KeyboardModifier.AltModifier)
        # AltGr is reported as Control+Alt on Windows/Linux and composes text,
        # so it must never be treated as a C0 control key.
        if modifiers & control_like and not alt_held and event.key() != Qt.Key.Key_Shift:
            key = event.key()
            if Qt.Key.Key_A <= key <= Qt.Key.Key_Z:
                self.worker.send_input(chr(int(key) - int(Qt.Key.Key_A) + 1))
                return

        text = event.text()
        # macOS reports Command as ControlModifier and has no AltGr. Treating
        # Command+Option as AltGr would forward a desktop shortcut remotely.
        altgr_text = (
            sys.platform != "darwin"
            and alt_held
            and bool(modifiers & Qt.KeyboardModifier.ControlModifier)
        )
        shortcut_modifier = bool(
            modifiers & (Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.MetaModifier)
        )
        if text and (altgr_text or not shortcut_modifier):
            self.worker.send_input(text)
            return
        super().keyPressEvent(event)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        metrics = self.fontMetrics()
        character_width = max(metrics.horizontalAdvance("M"), 1)
        line_height = max(metrics.lineSpacing(), 1)
        width = max(self.viewport().width() // character_width, 20)
        height = max(self.viewport().height() // line_height, 5)
        self.worker.resize_terminal(width, height)


# ---------- Main Window ----------
class MainWindow(QMainWindow):
    LOG_MAX_CHARS = 120_000
    WINDOW_TITLE = f"{APP_NAME} {DISPLAY_VERSION}"

    # ---------- Initialization & Layout ----------
    def __init__(self):
        super().__init__()
        self.setWindowTitle(self.WINDOW_TITLE)
        self.resize(1320, 860)
        self.setMinimumSize(1040, 800)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet(APP_STYLESHEET)
        self.sessions = {}
        self._session_workers = set()
        self._host_key_workers = set()
        self._cli_request_generation = 0
        self._active_password_buffers = []
        self._automation_worker = None
        self._automation_draft = None
        self._pending_log_messages = []
        self._shutdown_in_progress = False
        self._shutdown_ready = False
        self._inventory_dirty = False
        self._saved_inventory_digest = None
        self._accepted_risk_bundle_this_run = None
        self.stop_btn = None

        # Splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(8)

        # Left: Device tree with branding header
        self._brand_icon = QIcon()
        logo_path = find_asset_path("clidarvi_symbol.svg")
        if logo_path is not None:
            app_icon = QIcon(str(logo_path))
            self._brand_icon = app_icon
            self.setWindowIcon(app_icon)
            app_instance = QApplication.instance()
            if app_instance is not None:
                app_instance.setWindowIcon(app_icon)
        self._inventory_icons = {}
        for key, relative_path in INVENTORY_ICON_ASSETS.items():
            asset_path = find_asset_path(relative_path)
            self._inventory_icons[key] = (
                QIcon(str(asset_path)) if asset_path is not None else QIcon()
            )
        left_panel = QWidget()
        left_panel.setObjectName("Sidebar")
        left_panel.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(18, 20, 18, 18)
        left_layout.setSpacing(14)
        left_panel.setMinimumWidth(270)
        left_panel.setMaximumWidth(320)

        # Branding header
        header_row = QHBoxLayout()
        header_row.setContentsMargins(2, 0, 2, 4)
        header_row.setSpacing(11)
        logo_label = QLabel()
        if logo_path is not None:
            pixmap = QPixmap(str(logo_path)).scaledToWidth(
                38,
                Qt.TransformationMode.SmoothTransformation,
            )
            logo_label.setPixmap(pixmap)
        logo_label.setFixedSize(40, 40)
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        brand_column = QVBoxLayout()
        brand_column.setSpacing(0)
        title_label = QLabel("Clidarvi")
        title_label.setObjectName("BrandTitle")
        brand_kicker = QLabel("NETWORK OPERATIONS")
        brand_kicker.setObjectName("BrandKicker")
        brand_column.addWidget(title_label)
        brand_column.addWidget(brand_kicker)

        header_row.addWidget(logo_label)
        header_row.addLayout(brand_column)
        header_row.addStretch()
        left_layout.addLayout(header_row)

        # Mode switch (Automation / CLI)
        mode_shell = QWidget()
        mode_shell.setObjectName("ModeSelector")
        mode_shell.setStyleSheet(
            "QWidget#ModeSelector { background-color:#0E192B; border:1px solid #1D2A40; "
            "border-radius:10px; }"
        )
        mode_row = QHBoxLayout()
        mode_row.setContentsMargins(4, 4, 4, 4)
        mode_row.setSpacing(4)
        mode_shell.setLayout(mode_row)
        self.automation_btn = QRadioButton("Automation")
        self.cli_btn = QRadioButton("Live CLI")
        self.automation_btn.setObjectName("ModeSwitch")
        self.cli_btn.setObjectName("ModeSwitch")
        self.automation_btn.setChecked(True)
        self.automation_btn.setMinimumHeight(36)
        self.cli_btn.setMinimumHeight(36)
        mode_group = QButtonGroup(self)
        mode_group.addButton(self.automation_btn)
        mode_group.addButton(self.cli_btn)
        mode_row.addWidget(self.automation_btn, 1)
        mode_row.addWidget(self.cli_btn, 1)
        left_layout.addWidget(mode_shell)

        # Navigation and Save Buttons
        nav_row = QHBoxLayout()
        nav_row.setSpacing(8)
        self.back_btn = QPushButton("Undo")
        self.save_btn = QPushButton("Save inventory")
        self.forward_btn = QPushButton("Redo")

        for btn in (self.back_btn, self.forward_btn):
            btn.setObjectName("SidebarButton")
            btn.setStyleSheet(SMALL_BUTTON_STYLE)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.save_btn.setObjectName("SidebarPrimaryButton")
        self.save_btn.setCursor(Qt.CursorShape.PointingHandCursor)

        nav_row.addWidget(self.back_btn, 1)
        nav_row.addWidget(self.forward_btn, 1)
        left_layout.addLayout(nav_row)
        left_layout.addWidget(self.save_btn)

        # Import / Export Buttons row (centered below main nav)
        import_export_row = QHBoxLayout()
        import_export_row.setSpacing(8)
        self.import_btn = QPushButton("Import")
        self.export_btn = QPushButton("Export")

        for btn in (self.import_btn, self.export_btn):
            btn.setObjectName("SidebarButton")
            btn.setStyleSheet(GHOST_BUTTON_STYLE)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)

        self.import_btn.setToolTip("Import a Clidarvi inventory file")
        self.export_btn.setToolTip("Export the current inventory")
        # Connect import/export buttons to their handlers
        self.import_btn.clicked.connect(self.import_tree_from_file)
        self.export_btn.clicked.connect(self.export_tree_to_file)

        import_export_row.addWidget(self.import_btn, 1)
        import_export_row.addWidget(self.export_btn, 1)
        left_layout.addLayout(import_export_row)

        # Connect radio buttons to mode switch function
        self.automation_btn.toggled.connect(
            lambda checked: self.switch_mode(0) if checked else None
        )
        self.cli_btn.toggled.connect(lambda checked: self.switch_mode(1) if checked else None)

        self.save_btn.clicked.connect(self.save_tree_to_file)
        self.back_btn.clicked.connect(self.go_back)
        self.forward_btn.clicked.connect(self.go_forward)

        left_layout.addSpacing(2)
        self.inventory_heading = QLabel("NETWORK INVENTORY")
        self.inventory_heading.setObjectName("SidebarHeading")
        left_layout.addWidget(self.inventory_heading)
        inventory_actions = QHBoxLayout()
        inventory_actions.setSpacing(8)
        self.new_device_btn = QPushButton("+ Device")
        self.new_device_btn.setObjectName("SidebarButton")
        self.new_device_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.new_device_btn.setToolTip("Add a device at the inventory root")
        self.new_device_btn.setStyleSheet(
            "QPushButton { background-color:#111C30; color:#B9C7DA; "
            "border:1px solid #263750; border-radius:6px; min-height:27px; "
            "padding:0 9px; font-size:8.5pt; font-weight:650; }"
            "QPushButton:hover { background-color:#192842; color:#FFFFFF; }"
        )
        self.new_site_btn = QPushButton("+ Site")
        self.new_site_btn.setObjectName("SidebarButton")
        self.new_site_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.new_site_btn.setToolTip("Add a physical site at the inventory root")
        self.new_site_btn.setStyleSheet(self.new_device_btn.styleSheet())
        self.new_device_btn.clicked.connect(self.add_root_device)
        self.new_site_btn.clicked.connect(self.add_root_site)
        inventory_actions.addWidget(self.new_site_btn, 1)
        inventory_actions.addWidget(self.new_device_btn, 1)
        left_layout.addLayout(inventory_actions)

        self.tree = QTreeWidget()
        self.tree.setObjectName("InventoryTree")
        self.tree.setAccessibleName("Network inventory")
        self.tree.setAccessibleDescription(
            "Physical sites, folders, and network devices. Right-click an item to manage it."
        )
        self.tree.setHeaderHidden(True)
        self.tree.setIndentation(16)
        self.tree.setIconSize(QSize(20, 20))
        left_layout.addWidget(self.tree)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.show_tree_menu)
        self.tree.itemDoubleClicked.connect(self._handle_inventory_double_click)
        self.tree.currentItemChanged.connect(self._select_automation_scope_from_tree)
        self.tree.itemClicked.connect(self._select_automation_scope_from_tree)
        self.tree.itemActivated.connect(self._select_automation_scope_from_tree)

        self.legal_btn = QPushButton("About, legal & safety")
        self.legal_btn.setObjectName("SidebarButton")
        self.legal_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.legal_btn.setAccessibleName("About, legal and safety information")
        self.legal_btn.setToolTip("View the license, warranty, privacy, and third-party notices")
        self.legal_btn.setStyleSheet(GHOST_BUTTON_STYLE)
        self.legal_btn.clicked.connect(self.show_legal_dialog)
        left_layout.addWidget(self.legal_btn)

        splitter.addWidget(left_panel)
        self._seed_tree()
        self.tree.expandAll()

        # Right: dynamic panel
        self.right = QWidget()
        self.right.setObjectName("WorkspaceCard")
        self.right.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.right_layout = QVBoxLayout(self.right)
        splitter.addWidget(self.right)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([292, 1000])

        root = QWidget()
        root.setObjectName("RootContainer")
        root.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(0)
        layout.addWidget(splitter)
        self.setCentralWidget(root)

        # Start in automation
        self.build_automation_page()

    def show_legal_dialog(self) -> None:
        LegalDialog(self).exec()

    def _risk_acknowledgement_record_matches(self, record: Any, snapshot: dict[str, Any]) -> bool:
        expected_keys = {
            "schema_version",
            "declared_app_version",
            "terms_id",
            "bundle_sha256",
            "document_sha256",
            "bundled_required_snapshot",
            "installed_runtime_verified",
            "accepted_at_utc",
            "acknowledgement_ids",
        }
        if not isinstance(record, dict) or set(record) != expected_keys:
            return False
        expected_values = {
            "schema_version": RISK_ACKNOWLEDGEMENT_SCHEMA_VERSION,
            "declared_app_version": snapshot["declared_app_version"],
            "terms_id": snapshot["terms_id"],
            "bundle_sha256": snapshot["bundle_sha256"],
            "document_sha256": snapshot["document_sha256"],
            "bundled_required_snapshot": snapshot["bundled_required_snapshot"],
            "installed_runtime_verified": False,
            "acknowledgement_ids": [item[0] for item in RISK_ACKNOWLEDGEMENTS],
        }
        if any(record.get(key) != value for key, value in expected_values.items()):
            return False
        accepted_at = record.get("accepted_at_utc")
        if not isinstance(accepted_at, str) or not accepted_at.endswith("Z"):
            return False
        try:
            parsed = datetime.fromisoformat(accepted_at.removesuffix("Z") + "+00:00")
        except ValueError:
            return False
        return parsed.tzinfo is not None and parsed.utcoffset().total_seconds() == 0

    def _read_valid_risk_acknowledgement(self, snapshot: dict[str, Any]) -> bool:
        path = self.get_risk_acknowledgement_path()
        try:
            record = _load_strict_json_snapshot(
                _read_bounded_regular_file(path, max_bytes=64 * 1024)
            )
            if not self._risk_acknowledgement_record_matches(record, snapshot):
                return False
            apply_private_permissions(path, 0o600, strict=True)
            return True
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
            return False

    def _risk_acknowledgement_status_text(self) -> str:
        """Return a local-only status summary for the legal dialog."""

        try:
            snapshot = _load_risk_terms_snapshot()
        except (OSError, RuntimeError) as exc:
            return f"Network acknowledgement: BLOCKED — {exc}"
        if self._accepted_risk_bundle_this_run == snapshot[
            "bundle_sha256"
        ] or self._read_valid_risk_acknowledgement(snapshot):
            return (
                "Network acknowledgement: stored record matches declared application version "
                f"{snapshot['declared_app_version']} and bundled required-document hash "
                f"{snapshot['bundle_sha256'][:12]}…. It does not verify the running "
                "executable or installed runtime."
            )
        return (
            "Network acknowledgement: required before the next DNS or SSH action for "
            "the bundled required-document set "
            f"{snapshot['bundle_sha256'][:12]}…."
        )

    def _ensure_network_terms_accepted(self) -> bool:
        """Fail closed until the currently bundled acknowledgement set is accepted."""

        try:
            snapshot = _load_risk_terms_snapshot()
        except (OSError, RuntimeError) as exc:
            message = (
                "Network features are disabled because the bundled Terms, Disclaimer, "
                f"or required runtime-lock snapshot cannot be verified.\n\n{exc}\n\n"
                "You can still review About, legal & safety. Reinstall an official, "
                "complete Clidarvi package before using network features."
            )
            self._append_log(f"[Safety] {exc}")
            QMessageBox.critical(self, "Required Safety Terms Unavailable", message)
            return False

        bundle_sha256 = snapshot["bundle_sha256"]
        if self._accepted_risk_bundle_this_run == bundle_sha256:
            return True
        if self._read_valid_risk_acknowledgement(snapshot):
            self._accepted_risk_bundle_this_run = bundle_sha256
            return True

        dialog = RiskAcknowledgementDialog(snapshot, self)
        result = dialog.exec()
        if result != QDialog.DialogCode.Accepted or not dialog.is_fully_acknowledged():
            self._append_log("[Safety] Network action cancelled; terms were not acknowledged.")
            return False

        # Detect a package or file change while the modal dialog was open.
        try:
            current_snapshot = _load_risk_terms_snapshot()
        except (OSError, RuntimeError) as exc:
            QMessageBox.critical(
                self,
                "Safety Terms Changed",
                f"The accepted material can no longer be verified:\n{exc}",
            )
            return False
        if current_snapshot["bundle_sha256"] != bundle_sha256:
            QMessageBox.warning(
                self,
                "Safety Terms Changed",
                "A bundled acknowledgement document changed while it was open. "
                "No network action was started. Review the current version and try again.",
            )
            return False

        record = {
            "schema_version": RISK_ACKNOWLEDGEMENT_SCHEMA_VERSION,
            "declared_app_version": snapshot["declared_app_version"],
            "terms_id": snapshot["terms_id"],
            "bundle_sha256": bundle_sha256,
            "document_sha256": snapshot["document_sha256"],
            "bundled_required_snapshot": snapshot["bundled_required_snapshot"],
            "installed_runtime_verified": False,
            "accepted_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "acknowledgement_ids": [item[0] for item in RISK_ACKNOWLEDGEMENTS],
        }
        try:
            path = self.get_risk_acknowledgement_path()
            atomic_write_json(path, record, secure_existing_parent=True)
        except Exception as exc:
            QMessageBox.critical(
                self,
                "Acknowledgement Not Saved",
                "Clidarvi could not securely and atomically save the local "
                f"acknowledgement record. No network action was started.\n\n{exc}",
            )
            return False
        if not self._read_valid_risk_acknowledgement(snapshot):
            QMessageBox.critical(
                self,
                "Acknowledgement Verification Failed",
                "The saved acknowledgement could not be verified. No network action was started.",
            )
            return False

        self._accepted_risk_bundle_this_run = bundle_sha256
        self._append_log(
            "[Safety] Operational-risk terms acknowledged for bundled required-document "
            f"set {bundle_sha256[:12]}…."
        )
        return True

    # ---------- Internal Utilities ----------
    def _default_node_meta(self, hostname) -> dict:
        return DeviceRecord(label=hostname, hostname=hostname).to_mapping()

    def _inventory_icon(self, role: str, surface: str = "dark") -> QIcon:
        icon = getattr(self, "_inventory_icons", {}).get(f"{role}_{surface}")
        return icon if isinstance(icon, QIcon) else QIcon()

    def _device_icon_key(self, record: DeviceRecord) -> str:
        """Return the presentation-only icon selected for a canonical device."""

        return "device" if record.device_role == "generic" else record.device_role

    def _set_node_record(self, item: QTreeWidgetItem, record: DeviceRecord) -> None:
        item.setText(0, record.label)
        item.setData(0, Qt.ItemDataRole.UserRole, record.to_mapping())
        role = self._device_icon_key(record)
        item.setIcon(0, self._inventory_icon(role))
        item.setData(
            0,
            Qt.ItemDataRole.AccessibleDescriptionRole,
            INVENTORY_ICON_DESCRIPTIONS[role],
        )

    def _make_node_item(self, parent, label, hostname=None, metadata=None) -> QTreeWidgetItem:
        raw = dict(metadata) if isinstance(metadata, dict) else {}
        raw["label"] = label or raw.get("label") or raw.get("hostname")
        raw["hostname"] = hostname or raw.get("hostname") or raw["label"]
        record = DeviceRecord.from_mapping(raw)
        item = QTreeWidgetItem(parent, [record.label])
        self._set_node_record(item, record)
        return item

    def _make_folder_item(
        self,
        parent,
        label: str,
        *,
        site: SiteRecord | None = None,
    ) -> QTreeWidgetItem:
        folder_label = self._sanitize_label(label)
        item = QTreeWidgetItem(parent, [folder_label])
        item.setData(0, Qt.ItemDataRole.UserRole, "folder")
        if site is not None:
            self._set_site_record(item, site)
        return item

    def _site_record_for_item(self, item: QTreeWidgetItem) -> SiteRecord | None:
        raw = item.data(0, SITE_DATA_ROLE)
        if not isinstance(raw, dict):
            return None
        return SiteRecord.from_mapping(raw)

    @staticmethod
    def _site_icon_key(site: SiteRecord) -> str:
        return "datacenter" if site.site_type == "datacenter" else "site"

    def _set_site_record(self, item: QTreeWidgetItem, site: SiteRecord) -> None:
        item.setText(0, site.name)
        item.setData(0, Qt.ItemDataRole.UserRole, "folder")
        item.setData(0, SITE_DATA_ROLE, site.to_mapping())
        icon_role = self._site_icon_key(site)
        site_icon = self._inventory_icon(icon_role)
        if not site_icon.isNull():
            item.setIcon(0, site_icon)
        location_line = " ".join(part for part in (site.postal_code, site.city) if part)
        region_line = ", ".join(part for part in (site.region, site.country) if part)
        details = [INVENTORY_ICON_DESCRIPTIONS[icon_role]]
        details.extend(part for part in (site.address, location_line, region_line) if part)
        accessible_details = list(details)
        if site.notes:
            details.append(site.notes)
        safe_details = [html.escape(part).replace("\n", "<br>") for part in details]
        item.setToolTip(0, f"<qt>{'<br>'.join(safe_details)}</qt>")
        item.setData(
            0,
            Qt.ItemDataRole.AccessibleDescriptionRole,
            ". ".join(accessible_details),
        )

    def _item_to_node_entry(self, item: QTreeWidgetItem) -> dict:
        label = sanitize_label(item.text(0))
        meta = item.data(0, Qt.ItemDataRole.UserRole)
        raw = dict(meta) if isinstance(meta, dict) else {}
        raw["label"] = label
        raw.setdefault("hostname", label)
        record = DeviceRecord.from_mapping(raw)
        canonical = record.to_mapping()
        item.setData(0, Qt.ItemDataRole.UserRole, canonical)
        return canonical

    def _sanitize_label(self, label: str) -> str:
        return sanitize_label(label, max_length=MAX_LABEL_LENGTH)

    def _strip_xml_tag(self, tag: str) -> str:
        if tag and "}" in tag:
            return tag.split("}", 1)[1]
        return tag or ""

    def _validated_folder_name(
        self,
        value: str,
        parent: QTreeWidgetItem | None = None,
        exclude: QTreeWidgetItem | None = None,
    ) -> str:
        label = self._sanitize_label(value)
        if label == NODES_KEY:
            raise ValueError(f"{NODES_KEY!r} is reserved for device entries.")
        if parent is None:
            siblings = [
                self.tree.topLevelItem(index) for index in range(self.tree.topLevelItemCount())
            ]
        else:
            siblings = [parent.child(index) for index in range(parent.childCount())]
        for sibling in siblings:
            if sibling is exclude:
                continue
            if sibling.data(0, Qt.ItemDataRole.UserRole) == "folder" and sibling.text(0) == label:
                raise ValueError(f"A folder named '{label}' already exists here.")
        return label

    def _count_tree_items(self) -> int:
        def recurse(item: QTreeWidgetItem) -> int:
            total = 0
            for idx in range(item.childCount()):
                child = item.child(idx)
                total += 1
                total += recurse(child)
            return total

        return recurse(self.tree.invisibleRootItem())

    def _count_dict_items(self, data: dict) -> int:
        return count_inventory_items(data)

    def _sanitize_tree_dict(self, data: dict) -> dict:
        return sanitize_tree_dict(
            data,
            max_depth=MAX_DEVICE_TREE_DEPTH,
            max_items=MAX_DEVICE_TREE_NODES,
            max_label_length=MAX_LABEL_LENGTH,
        )

    def _merge_tree_dict(self, target: dict, source: dict) -> None:
        merged = merge_tree_dicts(
            target,
            source,
            max_depth=MAX_DEVICE_TREE_DEPTH,
            max_items=MAX_DEVICE_TREE_NODES,
            max_label_length=MAX_LABEL_LENGTH,
        )
        target.clear()
        target.update(merged)

    def _apply_tree_dict(self, data: dict, sites=()) -> None:
        previous_items = [
            self.tree.topLevelItem(index).clone() for index in range(self.tree.topLevelItemCount())
        ]
        self.tree.setUpdatesEnabled(False)
        try:
            self.tree.clear()

            for node in data.get("_nodes", []):
                record = DeviceRecord.from_mapping(node)
                self._make_node_item(
                    self.tree,
                    record.label,
                    record.hostname,
                    record.to_mapping(),
                )

            for key, sub in data.items():
                if key == "_nodes":
                    continue
                label = self._sanitize_label(key)
                folder_item = self._make_folder_item(self.tree, label)
                self.build_tree_from_dict(folder_item, sub)

            self._apply_site_placements(sites)
            self.tree.expandAll()
        except BaseException:
            self.tree.clear()
            for item in previous_items:
                self.tree.addTopLevelItem(item)
            self.tree.expandAll()
            raise
        finally:
            self.tree.setUpdatesEnabled(True)

    def _validate_import_file_size(self, file_path: str) -> bytes:
        """Return the exact bounded regular-file snapshot that was validated."""

        return _read_bounded_regular_file(file_path, max_bytes=MAX_IMPORT_FILE_SIZE)

    def _parse_xml_snapshot(self, raw: bytes):
        """Preflight all XML elements before constructing the bounded DOM."""

        depth = 0
        element_count = 0
        root_seen = False
        for event, element in ET.iterparse(io.BytesIO(raw), events=("start", "end")):
            tag = self._strip_xml_tag(element.tag).lower()
            if event == "start":
                depth += 1
                element_count += 1
                if not root_seen:
                    root_seen = True
                    if tag != "connections":
                        raise ValueError("Root element is not <Connections>.")
                elif tag != "connection":
                    raise ValueError(f"Unsupported XML element <{tag or '?'}>.")
                if element_count > MAX_XML_ELEMENTS:
                    raise ValueError("XML import exceeds the permitted element count.")
                if depth > MAX_DEVICE_TREE_DEPTH + 2:
                    raise ValueError("XML import depth exceeds the permitted limit.")
            else:
                element.clear()
                depth -= 1
        if not root_seen:
            raise ValueError("XML inventory is empty.")

        root = ET.fromstring(raw)
        if self._strip_xml_tag(root.tag).lower() != "connections":
            raise ValueError("Root element is not <Connections>.")
        if not list(root):
            raise ValueError("XML inventory contains no <Connection> entries.")
        return root

    def _sanitize_xml_tree(self, root: Any) -> dict:
        counter = {"items": 0}

        def recurse(element: Any, depth: int) -> dict:
            if MAX_DEVICE_TREE_DEPTH is not None and depth > MAX_DEVICE_TREE_DEPTH:
                raise ValueError("XML import depth exceeds permitted limit.")

            sanitized = {}
            node_entries = []

            for child in element:
                if self._strip_xml_tag(child.tag).lower() != "connection":
                    continue
                name = child.attrib.get("Name", "")
                hostname = child.attrib.get("Hostname", "")
                children = [
                    grand
                    for grand in child
                    if self._strip_xml_tag(grand.tag).lower() == "connection"
                ]

                if hostname.strip() and not children:
                    host_clean = self._sanitize_label(hostname)
                    label_clean = self._sanitize_label(name or host_clean)
                    raw_vendor = child.attrib.get("Vendor", "Other")
                    vendor = LEGACY_VENDOR_ALIASES.get(raw_vendor, raw_vendor)
                    if vendor not in VENDOR_MAP:
                        vendor = "Other"
                    imported_device_type = child.attrib.get("DeviceType")
                    if imported_device_type:
                        device_type = imported_device_type
                    elif VENDOR_MAP[vendor] == UDM_READ_ONLY_DEVICE_TYPE:
                        # Presentation text is untrusted and cannot grant access
                        # to the dedicated UDM worker.
                        device_type = "generic"
                    else:
                        device_type = VENDOR_MAP[vendor]
                    port_value = child.attrib.get("Port", 22)
                    raw_device = {
                        "label": label_clean,
                        "hostname": host_clean,
                        "vendor": vendor,
                        "device_type": device_type,
                        "port": port_value,
                    }
                    if "DeviceRole" in child.attrib:
                        raw_device["device_role"] = child.attrib["DeviceRole"]
                    node_entries.append(DeviceRecord.from_mapping(raw_device).to_mapping())
                else:
                    label_clean = self._sanitize_label(name or "Group")
                    if label_clean == NODES_KEY:
                        raise ValueError(f"{NODES_KEY!r} is reserved for device entries.")
                    if label_clean in sanitized:
                        raise ValueError(f"Duplicate folder '{label_clean}' detected in XML.")
                    sanitized[label_clean] = recurse(child, depth + 1)

            if node_entries:
                counter["items"] += len(node_entries)
                sanitized["_nodes"] = node_entries

            counter["items"] += len([k for k in sanitized.keys() if k != "_nodes"])
            if MAX_DEVICE_TREE_NODES is not None and counter["items"] > MAX_DEVICE_TREE_NODES:
                raise ValueError("XML import exceeds maximum allowed node count.")
            return sanitized

        sanitized_root = recurse(root, 0)
        return sanitized_root

    def _seed_tree(self):
        load_result = self.load_tree_from_file()
        if load_result is None:
            example_sites = (
                (
                    "Alderhaven AMS-01 Data Campus",
                    (
                        (
                            "AMS01-EDGE-RTR01",
                            "edge-rtr01.ams01.alderhaven.example",
                            "Cisco Router",
                            "cisco_ios",
                        ),
                        (
                            "AMS01-CORE-SW01",
                            "core-sw01.ams01.alderhaven.example",
                            "Cisco Switch",
                            "cisco_ios",
                        ),
                        (
                            "AMS01-PERIM-FW01",
                            "perim-fw01.ams01.alderhaven.example",
                            "Palo Alto",
                            "paloalto_panos",
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
                        ),
                        (
                            "RTM01-CORE-SW01",
                            "core-sw01.rtm01.rivermark.example",
                            "Cisco Switch",
                            "cisco_ios",
                        ),
                        (
                            "RTM01-PERIM-FW01",
                            "perim-fw01.rtm01.rivermark.example",
                            "Palo Alto",
                            "paloalto_panos",
                        ),
                    ),
                ),
            )
            for site_name, devices in example_sites:
                site_item = self._make_folder_item(
                    self.tree,
                    site_name,
                    site=SiteRecord(name=site_name, site_type="datacenter"),
                )
                for label, hostname, vendor, device_type in devices:
                    self._make_node_item(
                        site_item,
                        label,
                        metadata={
                            "label": label,
                            "hostname": hostname,
                            "vendor": vendor,
                            "device_type": device_type,
                        },
                    )
        if load_result is False:
            self._set_inventory_dirty(True)
        self.capture_history_state(mark_dirty=self._inventory_dirty)

    def switch_mode(self, idx):
        if idx == 0:
            active_sessions = len(self.sessions)
            if active_sessions:
                decision = QMessageBox.warning(
                    self,
                    "Close Active CLI Sessions?",
                    f"Switching to Automation will close {active_sessions} active CLI "
                    "session(s). Continue?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                if decision != QMessageBox.StandardButton.Yes:
                    automation_was_blocked = self.automation_btn.blockSignals(True)
                    cli_was_blocked = self.cli_btn.blockSignals(True)
                    self.automation_btn.setChecked(False)
                    self.cli_btn.setChecked(True)
                    self.automation_btn.blockSignals(automation_was_blocked)
                    self.cli_btn.blockSignals(cli_was_blocked)
                    return
            # Invalidate host-key callbacks captured for the CLI page before
            # replacing it. A late network result must never open a hidden tab.
            self._cli_request_generation += 1
            self.build_automation_page()
        else:
            self.build_session_page()

    def _capture_automation_draft(self):
        if not all(
            hasattr(self, name)
            for name in (
                "add_list",
                "commands",
                "enable_mode_cb",
                "save_config_cb",
                "save_cb",
            )
        ):
            return
        targets = []
        for row in range(self.add_list.count()):
            item = self.add_list.item(row)
            targets.append((item.text(), item.data(Qt.ItemDataRole.UserRole)))
        self._automation_draft = {
            "targets": targets,
            "commands": self.commands.toPlainText(),
            "enable_mode": False,
            "save_config": False,
            "save_transcript": self.save_cb.isChecked(),
        }

    def _restore_automation_draft(self):
        draft = self._automation_draft
        if not isinstance(draft, dict):
            return
        for display_text, device_id in draft.get("targets", []):
            item = QListWidgetItem(str(display_text))
            item.setData(Qt.ItemDataRole.UserRole, device_id)
            self.add_list.addItem(item)
        self.commands.setPlainText(str(draft.get("commands", "")))
        self.enable_mode_cb.setChecked(False)
        self.save_config_cb.setChecked(False)
        self.experimental_automation_cb.setChecked(False)
        self.save_cb.setChecked(bool(draft.get("save_transcript")))
        self._prune_missing_automation_targets()
        self.nodes_lbl.setText(f"{self.add_list.count()} targets selected")

    def clear_right(self):
        while self.right_layout.count():
            item = self.right_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def _close_all_sessions(self):
        for widget, worker in list(self.sessions.items()):
            self._release_password_buffer(getattr(worker, "password_buffer", None))
            worker.stop()
            if hasattr(self, "tabs") and isinstance(widget, QWidget):
                try:
                    idx = self.tabs.indexOf(widget)
                    if idx != -1:
                        self._remove_cli_session_tab(idx)
                except Exception:
                    pass
            self._dispose_terminal_widget(widget, worker)
        self.sessions.clear()

    def _dispose_terminal_widget(self, widget, worker=None) -> None:
        if not isinstance(widget, TerminalWidget):
            return
        if worker is not None:
            try:
                worker.output_received.disconnect(widget.handle_output_ready)
            except (RuntimeError, TypeError):
                pass
        try:
            widget.clear()
            widget._terminal_control_carry = ""
            widget._terminal_string_discard = None
            widget._terminal_string_escape_pending = False
            widget.setParent(None)
            widget.deleteLater()
        except RuntimeError:
            pass

    def build_automation_page(self):
        # Close any lingering CLI sessions before swapping the panel
        self._close_all_sessions()
        # Recreate right panel cleanly (prevents grey artifacts after switching modes)
        splitter = self.centralWidget().layout().itemAt(0).widget()
        existing_right = splitter.widget(1)

        new_right = QWidget()
        new_right.setObjectName("WorkspaceCard")
        new_right.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        new_layout = QVBoxLayout(new_right)
        splitter.replaceWidget(1, new_right)
        if existing_right is not None:
            existing_right.deleteLater()
        self.right = new_right
        self.right_layout = new_layout

        self.right_layout.setContentsMargins(24, 22, 24, 22)
        self.right_layout.setSpacing(14)

        page_header = QHBoxLayout()
        page_header.setSpacing(10)
        page_heading = QVBoxLayout()
        page_heading.setSpacing(2)
        page_title = QLabel("Automation workspace")
        page_title.setObjectName("PageTitle")
        page_subtitle = QLabel("Build a validated command plan and run it across your inventory.")
        page_subtitle.setObjectName("PageSubtitle")
        page_subtitle.setWordWrap(True)
        page_heading.addWidget(page_title)
        page_heading.addWidget(page_subtitle)
        page_header.addLayout(page_heading, 1)

        self.refresh_btn = QPushButton("Reset draft")
        self.refresh_btn.setObjectName("SecondaryButton")
        self.refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setObjectName("DangerButton")
        self.stop_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.stop_btn.setEnabled(False)
        self.run_btn = QPushButton("Run automation")
        self.run_btn.setObjectName("PrimaryButton")
        self.run_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        page_header.addWidget(self.refresh_btn)
        page_header.addWidget(self.stop_btn)
        page_header.addWidget(self.run_btn)
        self.right_layout.addLayout(page_header)

        target_card = QWidget()
        target_card.setObjectName("SectionCard")
        target_card.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        target_layout = QVBoxLayout(target_card)
        target_layout.setContentsMargins(16, 14, 16, 16)
        target_layout.setSpacing(10)

        target_header = QHBoxLayout()
        target_heading = QVBoxLayout()
        target_heading.setSpacing(1)
        target_title = QLabel("Target devices")
        target_title.setObjectName("SectionTitle")
        target_hint = QLabel("Select in the inventory tree or choose a scope below.")
        target_hint.setObjectName("SectionHint")
        target_heading.addWidget(target_title)
        target_heading.addWidget(target_hint)
        target_header.addLayout(target_heading)
        target_header.addStretch()
        self.nodes_lbl = QLabel("0 targets selected")
        self.nodes_lbl.setObjectName("StatusBadge")
        self.nodes_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        target_header.addWidget(self.nodes_lbl)
        target_layout.addLayout(target_header)

        top_row = QHBoxLayout()
        top_row.setSpacing(8)
        self.selector = QComboBox()
        self.selector.setAccessibleName("Automation target scope")
        self.selector.setAccessibleDescription(
            "Select one device, every device below a folder or site, or the complete inventory."
        )
        self.selector.setEditable(False)
        self.selector.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.selector.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.selector.setMinimumHeight(38)
        self.selector.setMaxVisibleItems(8)
        self.selector.setIconSize(QSize(20, 20))

        selector = self.selector
        view = selector.view()
        view.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        view.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        view.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        view.setUniformItemSizes(True)

        def remember_index(index):
            selector._last_index = index

        selector.currentIndexChanged.connect(remember_index)

        _original_show_popup = selector.showPopup

        def stable_show_popup():
            try:
                _original_show_popup()
            except RuntimeError:
                return
            QTimer.singleShot(0, adjust_popup_scroll)

        def adjust_popup_scroll():
            try:
                if getattr(self, "selector", None) is not selector:
                    return
                if hasattr(selector, "_last_index"):
                    idx = selector._last_index
                    view.scrollTo(
                        view.model().index(idx, 0),
                        QAbstractItemView.ScrollHint.PositionAtCenter,
                    )
                popup = view.window()
                popup.move(selector.mapToGlobal(selector.rect().bottomLeft()))
            except RuntimeError:
                return

        selector.showPopup = stable_show_popup
        # --- End: macOS alignment-safe dropdown fix ---
        top_row.addWidget(self.selector, 1)

        self.add_btn = QPushButton("Add target")
        self.add_btn.setObjectName("SecondaryButton")
        self.add_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.add_btn.setToolTip(
            "Add the selected device, or all devices below the selected folder or site"
        )
        top_row.addWidget(self.add_btn)
        target_layout.addLayout(top_row)

        self.add_list = EmptyStateListWidget(
            "No targets in this run yet. Choose a scope above and select Add target."
        )
        self.add_list.setAccessibleName("Selected automation targets")
        self.add_list.setAccessibleDescription(
            "Devices that will receive the current command plan."
        )
        self.add_list.setMinimumHeight(78)
        self.add_list.setMaximumHeight(110)
        target_layout.addWidget(self.add_list)
        self.right_layout.addWidget(target_card)

        command_card = QWidget()
        command_card.setObjectName("SectionCard")
        command_card.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        command_layout = QVBoxLayout(command_card)
        command_layout.setContentsMargins(16, 14, 16, 16)
        command_layout.setSpacing(9)

        command_header = QHBoxLayout()
        command_heading = QVBoxLayout()
        command_heading.setSpacing(1)
        command_title = QLabel("Command plan")
        command_title.setObjectName("SectionTitle")
        command_hint = QLabel("Use one command per line. Risky changes require explicit approval.")
        command_hint.setObjectName("SectionHint")
        command_heading.addWidget(command_title)
        command_heading.addWidget(command_hint)
        command_header.addLayout(command_heading)
        command_header.addStretch()
        self.udm_diagnostics_btn = QPushButton("Load UDM diagnostics")
        self.udm_diagnostics_btn.setObjectName("SecondaryButton")
        self.udm_diagnostics_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.udm_diagnostics_btn.setToolTip(
            "Replace the command plan with Clidarvi's exact, fixed UDM observation preset."
        )
        command_header.addWidget(self.udm_diagnostics_btn)
        command_layout.addLayout(command_header)

        safety_row = QHBoxLayout()
        safety_row.setSpacing(18)
        self.enable_mode_cb = QCheckBox("Enable mode (unavailable in alpha)")
        self.enable_mode_cb.setToolTip(
            "Clidarvi's application-level option does not request optional enable mode or "
            "supply a separate enable secret. An experimental driver's setup may still invoke "
            "a hidden privilege helper before control returns. Use an account that already has "
            "sufficient privilege for the reviewed plan."
        )
        self.enable_mode_cb.setChecked(False)
        self.enable_mode_cb.setEnabled(False)
        self.save_config_cb = QCheckBox("Automatic save (unavailable in alpha)")
        self.save_config_cb.setToolTip(
            "Clidarvi does not call Netmiko's implicit save helpers in this alpha. "
            "Add a vendor-documented save or commit command to the reviewed command plan instead."
        )
        self.save_config_cb.setChecked(False)
        self.save_config_cb.setEnabled(False)
        safety_row.addWidget(self.enable_mode_cb)
        safety_row.addWidget(self.save_config_cb)
        safety_row.addStretch()
        command_layout.addLayout(safety_row)

        self.experimental_automation_cb = QCheckBox("Experimental Automation (one lab target)")
        self.experimental_automation_cb.setChecked(False)
        self.experimental_automation_cb.setToolTip(
            "One-run opt-in for exactly one aruba_os, cisco_wlc, or fortinet target. "
            "The pinned driver may send hidden privilege or state-changing setup commands "
            "before the reviewed plan; cleanup may not run. Never use this as a production "
            "compatibility or read-only guarantee."
        )
        safety_row.insertWidget(2, self.experimental_automation_cb)

        self.commands = QTextEdit()
        self.commands.setAccessibleName("Command plan editor")
        self.commands.setAccessibleDescription(
            "Enter one network command per line. UDM diagnostics only accept the exact fixed preset."
        )
        self.commands.setPlaceholderText(
            "show version\nshow interfaces status\n\nPaste or type one command per line…"
        )
        self.commands.setMinimumHeight(150)
        self.commands.setSizePolicy(
            self.commands.sizePolicy().horizontalPolicy(), QSizePolicy.Policy.Expanding
        )
        self.commands.setStyleSheet(
            "QTextEdit {"
            "background-color:#FFFFFF;"
            "color:#172033;"
            "selection-background-color:#DCE8FF;"
            "selection-color:#17336C;"
            "border:1px solid #C9D4E3;"
            "border-radius:9px;"
            "font-family:'SF Mono','Cascadia Mono','Menlo','Courier New',monospace;"
            "font-size:10.5pt;"
            "padding:11px 12px;"
            "}"
            "QTextEdit:focus { border:1px solid #3B70E2; }"
        )
        command_layout.addWidget(self.commands)
        self.right_layout.addWidget(command_card, stretch=3)

        activity_card = QWidget()
        activity_card.setObjectName("SectionCard")
        activity_card.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        activity_layout = QVBoxLayout(activity_card)
        activity_layout.setContentsMargins(16, 14, 16, 16)
        activity_layout.setSpacing(9)

        activity_header = QHBoxLayout()
        activity_heading = QVBoxLayout()
        activity_heading.setSpacing(1)
        activity_title = QLabel("Activity")
        activity_title.setObjectName("SectionTitle")
        activity_hint = QLabel("Validation, connection and command output appears here.")
        activity_hint.setObjectName("SectionHint")
        activity_heading.addWidget(activity_title)
        activity_heading.addWidget(activity_hint)
        activity_header.addLayout(activity_heading)
        activity_header.addStretch()
        self.save_cb = QCheckBox("Save transcript")
        self.save_cb.setToolTip("Write this run's activity transcript to a local file.")
        activity_header.addWidget(self.save_cb)
        activity_layout.addLayout(activity_header)

        self.logs = QTextEdit()
        self.logs.setAccessibleName("Automation activity log")
        self.logs.setReadOnly(True)
        self.logs.setPlaceholderText("Ready. Add targets and build a command plan to begin.")
        self.logs.setStyleSheet(
            "QTextEdit {"
            "background-color:#0B1220;"
            "color:#C9D5E7;"
            "selection-background-color:#294268;"
            "selection-color:#FFFFFF;"
            "font-family:'SF Mono','Cascadia Mono','Menlo','Courier New',monospace;"
            "font-size:9.5pt;"
            "border:1px solid #1D2A40;"
            "border-radius:9px;"
            "padding:9px 11px;"
            "}"
        )
        self.logs.setMinimumHeight(105)
        activity_layout.addWidget(self.logs)
        self.right_layout.addWidget(activity_card, stretch=2)
        pending_messages = list(getattr(self, "_pending_log_messages", []))
        self._pending_log_messages = []
        for pending_message in pending_messages:
            self._append_log(pending_message)

        # Signals
        self.add_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.add_list.customContextMenuRequested.connect(self.show_addlist_menu)
        self.add_btn.clicked.connect(self.add_current_choice)
        self.udm_diagnostics_btn.clicked.connect(self.load_udm_diagnostics_preset)
        if self.stop_btn:
            self.stop_btn.clicked.connect(self.stop_automation)
        self.run_btn.clicked.connect(self.run_automation)
        self.refresh_btn.clicked.connect(self.refresh_automation)

        self.populate_selector_from_tree()
        self._restore_automation_draft()

    def build_session_page(self):
        self._capture_automation_draft()
        splitter = self.centralWidget().layout().itemAt(0).widget()
        existing_right = splitter.widget(1)

        new_right = QWidget()
        new_right.setObjectName("WorkspaceCard")
        new_right.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        new_layout = QVBoxLayout(new_right)

        splitter.replaceWidget(1, new_right)
        if existing_right is not None:
            existing_right.deleteLater()
        self.right = new_right
        self.right_layout = new_layout
        self.right_layout.setContentsMargins(24, 22, 24, 22)
        self.right_layout.setSpacing(14)

        page_header = QHBoxLayout()
        page_header.setSpacing(10)
        page_heading = QVBoxLayout()
        page_heading.setSpacing(2)
        page_title = QLabel("Live CLI sessions")
        page_title.setObjectName("PageTitle")
        page_subtitle = QLabel(
            "Select a device in the inventory, then connect with verified SSH host keys."
        )
        page_subtitle.setObjectName("PageSubtitle")
        page_subtitle.setWordWrap(True)
        page_heading.addWidget(page_title)
        page_heading.addWidget(page_subtitle)
        page_header.addLayout(page_heading, 1)

        trust_badge = QLabel("STRICT HOST KEYS")
        trust_badge.setObjectName("StatusBadge")
        trust_badge.setToolTip("Unknown or changed SSH host keys require explicit approval.")
        page_header.addWidget(trust_badge)
        self.connect_btn = QPushButton("Connect selected")
        self.connect_btn.setObjectName("PrimaryButton")
        self.connect_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.connect_btn.clicked.connect(self.start_selected_cli_session)
        page_header.addWidget(self.connect_btn)
        self.right_layout.addLayout(page_header)

        cli_hint = QLabel(
            "Sessions open in tabs below. Right-click a device for host-key verification and more actions."
        )
        cli_hint.setObjectName("SectionHint")
        self.right_layout.addWidget(cli_hint)

        self.tabs = QTabWidget()
        self.tabs.setObjectName("CLISessionTabs")
        self.tabs.setAccessibleName("Live CLI session tabs")
        self.tabs.setTabsClosable(False)
        session_tab_bar = self.tabs.tabBar()
        session_tab_bar.setAccessibleName("Open Live CLI sessions")
        session_tab_bar.setDrawBase(False)
        session_tab_bar.setExpanding(False)
        session_tab_bar.setElideMode(Qt.TextElideMode.ElideRight)
        session_tab_bar.setUsesScrollButtons(True)
        session_tab_bar.setMovable(False)

        self.tabs.setStyleSheet(
            """
            QTabWidget#CLISessionTabs::pane {
                border: 0;
                background: transparent;
                top: -1px;
            }
            QTabWidget#CLISessionTabs::tab-bar {
                alignment: left;
                left: 0px;
            }
            QTabWidget#CLISessionTabs QTabBar {
                background: transparent;
            }
            QTabWidget#CLISessionTabs QTabBar::tab {
                background: #111C30;
                color: #9FB0C8;
                border: 1px solid #24344E;
                border-bottom: 0;
                border-top: 2px solid transparent;
                border-top-left-radius: 7px;
                border-top-right-radius: 7px;
                padding: 6px 9px;
                margin: 0 5px 0 0;
                min-height: 20px;
                max-width: 220px;
                font-weight: 600;
            }
            QTabWidget#CLISessionTabs QTabBar::tab:hover {
                background: #16243B;
                color: #D7E3F4;
            }
            QTabWidget#CLISessionTabs QTabBar::tab:selected {
                background: #0B1220;
                color: #F7FAFF;
                border-color: #2D4770;
                border-top-color: #4F83F1;
            }
            QTabWidget#CLISessionTabs QLabel#SessionStatusDot {
                border: 1px solid rgba(255, 255, 255, 45);
                border-radius: 4px;
                min-width: 8px;
                max-width: 8px;
                min-height: 8px;
                max-height: 8px;
                margin-left: 4px;
            }
            QTabWidget#CLISessionTabs QLabel#SessionStatusDot[state="connecting"] {
                background: #F5A524;
            }
            QTabWidget#CLISessionTabs QLabel#SessionStatusDot[state="connected"] {
                background: #34C98B;
            }
            QTabWidget#CLISessionTabs QToolButton#SessionTabCloseButton {
                background: transparent;
                color: #91A4BF;
                border: 0;
                border-radius: 6px;
                min-width: 18px;
                max-width: 18px;
                min-height: 18px;
                max-height: 18px;
                padding: 0;
                margin: 0 3px 0 2px;
                font-size: 13pt;
                font-weight: 600;
            }
            QTabWidget#CLISessionTabs QToolButton#SessionTabCloseButton:hover,
            QTabWidget#CLISessionTabs QToolButton#SessionTabCloseButton:focus {
                background: #263D60;
                color: #FFFFFF;
            }
            QTabWidget#CLISessionTabs QToolButton#SessionTabCloseButton:pressed {
                background: #315580;
            }
            """
        )

        self.cli_empty_state = QWidget()
        self.cli_empty_state.setObjectName("CLIEmptyState")
        self.cli_empty_state.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.cli_empty_state.setStyleSheet(
            """
            QWidget#CLIEmptyState {
                background-color: #0B1220;
                border: 1px solid #1D2A40;
                border-radius: 12px;
            }
            QLabel#CLIEmptyPrompt {
                color: #D7E3F4;
                font-size: 17pt;
                font-weight: 700;
            }
            QLabel#CLIEmptyHint {
                color: #7F91AD;
                font-size: 10pt;
            }
            QLabel#CLIEmptyGlyph {
                color: #70A0FF;
                background-color: #13213A;
                border: 1px solid #294268;
                border-radius: 18px;
                min-width: 54px;
                min-height: 54px;
                font-family: "SF Mono", Menlo, monospace;
                font-size: 18pt;
                font-weight: 700;
            }
            """
        )
        empty_layout = QVBoxLayout(self.cli_empty_state)
        empty_layout.setContentsMargins(32, 32, 32, 32)
        empty_layout.setSpacing(8)
        empty_layout.addStretch()
        empty_glyph = QLabel(">_")
        empty_glyph.setObjectName("CLIEmptyGlyph")
        empty_glyph.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty_layout.addWidget(empty_glyph, alignment=Qt.AlignmentFlag.AlignCenter)
        empty_layout.addSpacing(8)
        empty_title = QLabel("No active CLI sessions")
        empty_title.setObjectName("CLIEmptyPrompt")
        empty_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty_layout.addWidget(empty_title)
        empty_hint = QLabel("Select one device in the inventory and choose Connect selected.")
        empty_hint.setObjectName("CLIEmptyHint")
        empty_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty_layout.addWidget(empty_hint)
        empty_layout.addStretch()

        self.cli_stack = QStackedWidget()
        self.cli_stack.addWidget(self.cli_empty_state)
        self.cli_stack.addWidget(self.tabs)
        self.cli_stack.setCurrentWidget(self.cli_empty_state)
        self.right_layout.addWidget(self.cli_stack)

    # ---------- Automation Mode ----------
    def populate_selector_from_tree(self):
        selector = getattr(self, "selector", None)
        if not isinstance(selector, QComboBox):
            return
        try:
            selector.clear()
            selector.addItem("All Devices", {"kind": "all"})
            for index in range(self.tree.topLevelItemCount()):
                self._add_combo_entries(self.tree.topLevelItem(index), ())
            self._prune_missing_automation_targets()
        except RuntimeError:
            # The automation page may have been destroyed while switching mode.
            return

    def _select_automation_scope_from_tree(self, item, _column=0):
        """Mirror an explicitly clicked inventory item into the target selector."""

        selector = getattr(self, "selector", None)
        if item is None or not isinstance(selector, QComboBox):
            return
        wanted_path = self._path_for_item(item)
        role = item.data(0, Qt.ItemDataRole.UserRole)
        wanted_kind = "folder" if role == "folder" or item.childCount() > 0 else "node"
        wanted_device_id = None
        if wanted_kind == "node":
            wanted_device_id = self._device_id_for_item(item)
        try:
            for index in range(selector.count()):
                data = selector.itemData(index)
                raw_path = data.get("path") if isinstance(data, dict) else None
                if not (
                    isinstance(data, dict)
                    and data.get("kind") == wanted_kind
                    and isinstance(raw_path, (list, tuple))
                    and tuple(raw_path) == wanted_path
                ):
                    continue
                if wanted_kind == "node" and data.get("device_ids") != [wanted_device_id]:
                    continue
                selector.setCurrentIndex(index)
                return
        except RuntimeError:
            # The automation page may have been destroyed while switching mode.
            return

    def _add_combo_entries(self, item, parent_path):
        path = (*parent_path, item.text(0))
        display_path = " / ".join(path)
        role = item.data(0, Qt.ItemDataRole.UserRole)
        is_folder = role == "folder" or item.childCount() > 0
        if is_folder:
            device_ids = [self._device_id_for_item(node) for node in self._iter_leaf_nodes(item)]
            data = {"kind": "folder", "device_ids": device_ids, "path": path}
            site = self._site_record_for_item(item)
            if site is not None:
                site_icon = self._inventory_icon(self._site_icon_key(site), "light")
                if not site_icon.isNull():
                    self.selector.addItem(site_icon, display_path, data)
                else:
                    self.selector.addItem(display_path, data)
            else:
                self.selector.addItem(display_path, data)
            for child_index in range(item.childCount()):
                self._add_combo_entries(item.child(child_index), path)
            return

        data = {
            "kind": "node",
            "device_ids": [self._device_id_for_item(item)],
            "path": path,
        }
        metadata = item.data(0, Qt.ItemDataRole.UserRole)
        record = DeviceRecord.from_mapping(
            metadata if isinstance(metadata, dict) else {"label": item.text(0)}
        )
        icon = self._inventory_icon(self._device_icon_key(record), "light")
        if icon.isNull():
            self.selector.addItem(display_path, data)
        else:
            self.selector.addItem(icon, display_path, data)

    def _iter_leaf_nodes(self, item):
        role = item.data(0, Qt.ItemDataRole.UserRole)
        if role != "folder" and item.childCount() == 0:
            yield item
        else:
            for idx in range(item.childCount()):
                yield from self._iter_leaf_nodes(item.child(idx))

    def _iter_all_leaf_nodes(self):
        for index in range(self.tree.topLevelItemCount()):
            yield from self._iter_leaf_nodes(self.tree.topLevelItem(index))

    def _device_id_for_item(self, item: QTreeWidgetItem) -> str:
        return self._item_to_node_entry(item)["id"]

    def _find_node_by_id(self, device_id: str) -> QTreeWidgetItem | None:
        for item in self._iter_all_leaf_nodes():
            metadata = item.data(0, Qt.ItemDataRole.UserRole)
            if isinstance(metadata, dict) and metadata.get("id") == device_id:
                return item
        return None

    def _display_path_for_item(self, item: QTreeWidgetItem) -> str:
        return " / ".join(self._path_for_item(item))

    def _path_for_item(self, item: QTreeWidgetItem) -> tuple[str, ...]:
        parts = []
        current = item
        while current is not None:
            parts.append(current.text(0))
            current = current.parent()
        return tuple(reversed(parts))

    def _iter_folder_items(self):
        def recurse(parent):
            child_count = (
                parent.topLevelItemCount()
                if isinstance(parent, QTreeWidget)
                else parent.childCount()
            )
            for index in range(child_count):
                item = (
                    parent.topLevelItem(index)
                    if isinstance(parent, QTreeWidget)
                    else parent.child(index)
                )
                if item.data(0, Qt.ItemDataRole.UserRole) != "folder":
                    continue
                yield item
                yield from recurse(item)

        yield from recurse(self.tree)

    def _find_folder_by_path(self, path: tuple[str, ...]) -> QTreeWidgetItem | None:
        parent = None
        for depth, segment in enumerate(path):
            matches = []
            count = self.tree.topLevelItemCount() if parent is None else parent.childCount()
            for index in range(count):
                candidate = self.tree.topLevelItem(index) if parent is None else parent.child(index)
                if (
                    candidate.data(0, Qt.ItemDataRole.UserRole) == "folder"
                    and candidate.text(0) == segment
                ):
                    matches.append(candidate)
            if len(matches) != 1:
                return None
            parent = matches[0]
            if depth == len(path) - 1:
                return parent
        return None

    def _site_placements_from_tree(self) -> tuple[SitePlacement, ...]:
        placements = []
        for item in self._iter_folder_items():
            site = self._site_record_for_item(item)
            if site is not None:
                placements.append(SitePlacement(path=self._path_for_item(item), site=site))
        return sanitize_site_placements(
            self.tree_to_dict(),
            placements,
            max_depth=MAX_DEVICE_TREE_DEPTH,
            max_items=MAX_DEVICE_TREE_NODES,
            max_label_length=MAX_LABEL_LENGTH,
        )

    def _apply_site_placements(self, placements) -> None:
        canonical = sanitize_site_placements(
            self.tree_to_dict(),
            placements,
            max_depth=MAX_DEVICE_TREE_DEPTH,
            max_items=MAX_DEVICE_TREE_NODES,
            max_label_length=MAX_LABEL_LENGTH,
        )
        for placement in canonical:
            item = self._find_folder_by_path(placement.path)
            if item is None:
                raise ValueError(
                    f"Site path no longer exists in the inventory: {' / '.join(placement.path)}"
                )
            self._set_site_record(item, placement.site)

    def _prune_missing_automation_targets(self):
        target_list = getattr(self, "add_list", None)
        if not isinstance(target_list, QListWidget):
            return
        try:
            for row in range(target_list.count() - 1, -1, -1):
                target = target_list.item(row)
                node_item = self._find_node_by_id(target.data(Qt.ItemDataRole.UserRole))
                if node_item is None:
                    target_list.takeItem(row)
                    continue
                # Re-resolve the display text so renamed devices and moved
                # folders never show a stale path in the target list.
                current_path = self._display_path_for_item(node_item)
                if target.text() != current_path:
                    target.setText(current_path)
            if isinstance(getattr(self, "nodes_lbl", None), QLabel):
                self.nodes_lbl.setText(f"{target_list.count()} targets selected")
        except RuntimeError:
            return

    def add_current_choice(self):
        selection = self.selector.currentData()
        if not isinstance(selection, dict):
            return

        node_items_by_id = {
            self._device_id_for_item(item): item for item in self._iter_all_leaf_nodes()
        }
        if selection.get("kind") == "all":
            device_ids = list(node_items_by_id)
        else:
            device_ids = list(selection.get("device_ids") or [])

        selection_name = self.selector.currentText()
        if not device_ids:
            self._append_log(f"{selection_name}: contains no devices")
            self.nodes_lbl.setText(f"{self.add_list.count()} targets selected")
            return

        existing_ids = {
            self.add_list.item(row).data(Qt.ItemDataRole.UserRole)
            for row in range(self.add_list.count())
        }
        added = 0
        for device_id in device_ids:
            if device_id in existing_ids:
                continue
            node_item = node_items_by_id.get(device_id)
            if node_item is None:
                continue
            target_item = QListWidgetItem(self._display_path_for_item(node_item))
            target_item.setData(Qt.ItemDataRole.UserRole, device_id)
            self.add_list.addItem(target_item)
            existing_ids.add(device_id)
            added += 1

        if added:
            self._append_log(f"{selection_name}: {added} target(s) added")
        else:
            self._append_log(f"{selection_name}: no new targets added")

        self.nodes_lbl.setText(f"{self.add_list.count()} targets selected")

    def show_addlist_menu(self, pos):
        item = self.add_list.itemAt(pos)
        if not item:
            return
        menu = QMenu()
        remove_action = menu.addAction("Remove")
        action = menu.exec(self.add_list.viewport().mapToGlobal(pos))
        if action == remove_action:
            self.add_list.takeItem(self.add_list.row(item))
            self.nodes_lbl.setText(f"{self.add_list.count()} targets selected")

    def refresh_automation(self):
        if self._automation_worker and self._automation_worker.isRunning():
            QMessageBox.warning(
                self,
                "Automation Running",
                "Automation is still running. Stop it before resetting this draft.",
            )
            return
        has_draft = bool(
            self.add_list.count()
            or self.commands.toPlainText().strip()
            or self.logs.toPlainText().strip()
            or self.enable_mode_cb.isChecked()
            or self.save_config_cb.isChecked()
            or self.experimental_automation_cb.isChecked()
            or self.save_cb.isChecked()
        )
        if has_draft:
            decision = QMessageBox.question(
                self,
                "Reset Automation Draft?",
                "Clear all selected targets, commands, run options and activity from this draft?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if decision != QMessageBox.StandardButton.Yes:
                return
        self._clear_password_buffers()
        self.add_list.clear()
        self.nodes_lbl.setText("0 targets selected")
        self.logs.clear()
        self.commands.clear()
        self.enable_mode_cb.setChecked(False)
        self.save_config_cb.setChecked(False)
        self.experimental_automation_cb.setChecked(False)
        self.save_cb.setChecked(False)
        self._automation_draft = None
        self._append_log("[Draft] New automation draft ready.")

    def stop_automation(self):
        worker = getattr(self, "_automation_worker", None)
        if not worker or not worker.isRunning():
            self._append_log("[Run] No automation job is currently running.")
            return

        self._append_log(
            "[Run] Stop requested. Closing active transports; commands already sent "
            "are not rolled back."
        )
        worker.stop()
        if self.stop_btn:
            self.stop_btn.setEnabled(False)

    def load_udm_diagnostics_preset(self) -> None:
        """Load exact literals that map to fixed UDM diagnostic command IDs."""

        self.commands.setPlainText(UDM_OBSERVATION_PRESET_TEXT)
        self._append_log(
            "[Draft] Loaded the fixed UDM observation preset. Arbitrary shell commands "
            "remain blocked."
        )

    def _on_automation_worker_finished(self, worker):
        if self._automation_worker is worker:
            self._automation_worker = None
        worker.deleteLater()
        self._check_shutdown_complete()

    def _selected_device_records(self) -> list[DeviceRecord]:
        records = []
        for row in range(self.add_list.count()):
            target_item = self.add_list.item(row)
            device_id = target_item.data(Qt.ItemDataRole.UserRole)
            node_item = self._find_node_by_id(device_id)
            if node_item is None:
                self._append_log(
                    f"[{target_item.text()}] WARNING: Node no longer exists — skipping."
                )
                continue
            metadata = node_item.data(0, Qt.ItemDataRole.UserRole)
            records.append(
                DeviceRecord.from_mapping(
                    metadata if isinstance(metadata, dict) else {"label": node_item.text(0)}
                )
            )
        return records

    @staticmethod
    def _prepare_udm_observation_commands(commands_text: str) -> tuple[str, ...]:
        """Map only the byte-for-byte fixed UDM preset to internal command IDs."""

        if not isinstance(commands_text, str):
            raise ValueError("The UDM diagnostics plan must be text.")
        if commands_text != UDM_OBSERVATION_PRESET_TEXT:
            raise ValueError(
                "UDM diagnostics require the exact fixed preset. Use "
                "'Load UDM diagnostics'; do not edit, reorder or extend its lines."
            )
        return tuple(UDM_READ_ONLY_COMMANDS)

    def _confirm_udm_observation_plan(
        self, record: DeviceRecord, command_ids: tuple[str, ...]
    ) -> bool:
        commands = "\n".join(
            f"• {UDM_READ_ONLY_COMMANDS[command_id]}" for command_id in command_ids
        )
        prompt = QMessageBox(self)
        prompt.setIcon(QMessageBox.Icon.Warning)
        prompt.setWindowTitle("Experimental UDM Diagnostics")
        prompt.setText(f"Run fixed diagnostics on {record.label}?")
        prompt.setInformativeText(
            "This preview uses one SSH exec channel per fixed command; it does not open an "
            "interactive shell or accept arbitrary commands. A limited development-worktree "
            "observation succeeded for all four fixed commands (uptime, date -u, uname -a and "
            "id) on one UDM-SE running UniFi OS 5.1.26. It did not use a final wheel or the "
            "final locked runtime; the failure/timeout/stop matrix and production use remain "
            "unvalidated.\n\n"
            "These are observational commands, not a guarantee of zero writes: SSH login and "
            "the operating system may update audit or accounting data. Output can expose "
            "hostnames, kernel details and account identity. Do not publish raw transcripts.\n\n"
            f"Exact plan:\n{commands}"
        )
        prompt.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        prompt.setDefaultButton(QMessageBox.StandardButton.No)
        return prompt.exec() == QMessageBox.StandardButton.Yes

    def _confirm_experimental_automation(self, record: DeviceRecord) -> bool:
        """Require an additional exact, non-persistent lab-only opt-in."""

        disclosure = EXPERIMENTAL_AUTOMATION_SETUP_DISCLOSURES.get(
            record.device_type,
            "the pinned platform driver can perform setup outside the reviewed command plan",
        )
        confirmation, accepted = QInputDialog.getText(
            self,
            "Experimental Automation — Isolated Lab Only",
            f"Target: {record.label}\n"
            f"Address: {record.hostname}:{record.port}\n"
            f"Profile: {record.device_type}\n\n"
            f"Before your reviewed command plan, {disclosure}. Clidarvi cannot capture or "
            "classify those hidden setup bytes as plan commands. Cleanup may not run after "
            "failure or Stop, remote state may persist, and Stop cannot roll back writes "
            "already sent.\n\n"
            "This route is for one isolated, authorized, recoverable lab target. It is not "
            "a compatibility, read-only, production-safety, or successful-rollback claim. "
            "All normal host-key, command-risk, prompt, transport, and output gates still "
            "apply.\n\n"
            f"Type {EXPERIMENTAL_AUTOMATION_CONFIRMATION_PHRASE} to continue:",
        )
        return bool(accepted and confirmation == EXPERIMENTAL_AUTOMATION_CONFIRMATION_PHRASE)

    def _prepare_and_confirm_commands(
        self, commands_text: str, records: list[DeviceRecord]
    ) -> tuple[list[str], bool] | None:
        parser = AutomationWorker([], commands_text)
        try:
            commands = parser._prepare_commands()
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid Command", str(exc))
            return None
        if not commands:
            QMessageBox.warning(self, "No Commands", "No executable commands were found.")
            return None

        ranked_classes = {
            CommandClass.READ_ONLY: 0,
            CommandClass.CHANGE: 1,
            # A command that is understood for one target but unknown for another
            # must retain the stricter typed UNKNOWN gate for the mixed-vendor run.
            CommandClass.UNKNOWN: 2,
            CommandClass.DESTRUCTIVE: 3,
        }
        classified = []
        for command in commands:
            classes = [classify_command(command, record.device_type) for record in records]
            strongest = max(classes, key=ranked_classes.get)
            classified.append((command, strongest))

        risky = [
            (command, command_class)
            for command, command_class in classified
            if command_class is not CommandClass.READ_ONLY
        ]
        destructive = [
            command
            for command, command_class in classified
            if command_class is CommandClass.DESTRUCTIVE
        ]
        unknown = [
            command
            for command, command_class in classified
            if command_class is CommandClass.UNKNOWN
        ]
        allow_destructive = False

        if destructive or unknown:
            high_risk = destructive + unknown
            preview = "\n".join(f"• {redact_command(command)}" for command in high_risk[:10])
            phrase = "RUN DESTRUCTIVE" if destructive else "RUN UNKNOWN"
            title = "Destructive Automation" if destructive else "Unknown Automation Commands"
            confirmation, accepted = QInputDialog.getText(
                self,
                title,
                "These commands are destructive or cannot be proven safe. They may erase "
                "data, reload, or interrupt devices:\n\n"
                f"{preview}\n\nType {phrase} to continue:",
            )
            if not accepted or confirmation != phrase:
                self._append_log("[Run] High-risk automation cancelled.")
                return None
            allow_destructive = bool(destructive)

        if risky:
            preview_lines = [
                f"• [{command_class.value}] {redact_command(command)}"
                for command, command_class in risky[:12]
            ]
            if len(risky) > len(preview_lines):
                preview_lines.append(f"• ...and {len(risky) - len(preview_lines)} more")
            prompt = QMessageBox(self)
            prompt.setIcon(QMessageBox.Icon.Warning)
            prompt.setWindowTitle("Approve Automation Changes")
            prompt.setText(
                f"Approve {len(risky)} non-read-only command(s) for {len(records)} device(s)?"
            )
            prompt.setInformativeText(
                "\n".join(preview_lines)
                + "\n\nUnknown commands are treated as potentially changing."
            )
            prompt.setStandardButtons(
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            prompt.setDefaultButton(QMessageBox.StandardButton.No)
            if prompt.exec() != QMessageBox.StandardButton.Yes:
                self._append_log("[Run] Change automation cancelled.")
                return None

        return commands, allow_destructive

    def _set_automation_running(self, running: bool) -> None:
        for name in (
            "run_btn",
            "refresh_btn",
            "add_btn",
            "udm_diagnostics_btn",
            "experimental_automation_cb",
            "selector",
            "commands",
            "automation_btn",
            "cli_btn",
        ):
            widget = getattr(self, name, None)
            if isinstance(widget, QWidget):
                widget.setEnabled(not running)
        if isinstance(getattr(self, "save_config_cb", None), QCheckBox):
            self.save_config_cb.setChecked(False)
            self.save_config_cb.setEnabled(False)
        if isinstance(getattr(self, "enable_mode_cb", None), QCheckBox):
            self.enable_mode_cb.setChecked(False)
            self.enable_mode_cb.setEnabled(False)
        if isinstance(getattr(self, "stop_btn", None), QPushButton):
            self.stop_btn.setEnabled(running)

    def run_automation(self):
        """Validate, authorize and start a bounded multi-device automation job."""
        if not self._ensure_network_terms_accepted():
            return
        if self._automation_worker and self._automation_worker.isRunning():
            self._append_log("[Run] Automation is already running. Use Stop to cancel.")
            return

        experimental_opt_in = bool(self.experimental_automation_cb.isChecked())
        # Consume this one-run acknowledgement before draft validation so stale
        # intent cannot survive a failed or incomplete run attempt.
        self.experimental_automation_cb.setChecked(False)

        commands_text = self.commands.toPlainText()
        if not commands_text.strip():
            self._append_log("[Run] No commands provided.")
            return

        if self.add_list.count() == 0:
            self._append_log("[Run] No target nodes selected. Please add at least one device.")
            return

        try:
            records = self._selected_device_records()
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid Device", str(exc))
            return
        if not records:
            self._append_log("[Run] No valid devices found to run on.")
            return

        experimental_records = [
            record
            for record in records
            if record.device_type in EXPERIMENTAL_AUTOMATION_DEVICE_TYPES
        ]
        experimental_mode = bool(experimental_records)

        if experimental_opt_in and (len(records) != 1 or len(experimental_records) != 1):
            QMessageBox.warning(
                self,
                "Invalid Experimental Automation Scope",
                "The per-run opt-in applies only to exactly one aruba_os, cisco_wlc, or "
                "fortinet target. It cannot enable stable profiles, Generic SSH, UniFi OS / "
                "UDM, multiple targets, or mixed runs. The opt-in was consumed. No "
                "credentials, network connection, or commands were sent.",
            )
            return
        if experimental_mode and not experimental_opt_in:
            preview = "\n".join(
                f"• {record.label} ({record.device_type})" for record in experimental_records[:12]
            )
            QMessageBox.warning(
                self,
                "Experimental Automation Is Off",
                "General Automation for these profiles is disabled by default. Select "
                "'Experimental Automation (one lab target)' and run exactly one eligible "
                "target. No credentials, network connection, or "
                f"commands were sent.\n\n{preview}",
            )
            return
        if experimental_mode:
            try:
                validate_experimental_automation_runtime()
            except ValueError as exc:
                QMessageBox.warning(
                    self,
                    "Experimental Automation Runtime Mismatch",
                    f"{exc}\n\nNo credentials, network connection, or commands were sent.",
                )
                return

        udm_records = [
            record for record in records if record.device_type == UDM_READ_ONLY_DEVICE_TYPE
        ]
        udm_mode = bool(udm_records)
        udm_command_ids: tuple[str, ...] = ()
        verified_server_key: paramiko.PKey | None = None
        allow_destructive = False

        if udm_mode:
            if len(records) != 1 or len(udm_records) != 1:
                QMessageBox.warning(
                    self,
                    "UDM Diagnostics Require One Target",
                    "The experimental UDM diagnostics preview accepts exactly one "
                    "ubiquiti_unifi_os target and cannot be mixed with other profiles. "
                    "No credentials, network connection, or commands were sent.",
                )
                return
            try:
                udm_command_ids = self._prepare_udm_observation_commands(commands_text)
            except ValueError as exc:
                QMessageBox.warning(self, "Invalid UDM Diagnostics Plan", str(exc))
                return
            udm_record = udm_records[0]
            try:
                verified_server_key = self._trusted_server_key_snapshot(
                    udm_record.hostname, udm_record.port
                )
            except (OSError, ValueError, paramiko.SSHException) as exc:
                QMessageBox.warning(self, "Untrusted SSH Host Key", str(exc))
                return
            if not self._confirm_udm_observation_plan(udm_record, udm_command_ids):
                self._append_log("[Run] Experimental UDM diagnostics cancelled.")
                return
        else:
            blocked_records = [
                record
                for record in records
                if record.device_type in GENERAL_AUTOMATION_BLOCKED_DEVICE_TYPES
            ]
            if blocked_records:
                preview = "\n".join(
                    f"• {record.label} ({record.device_type})" for record in blocked_records[:12]
                )
                if len(blocked_records) > 12:
                    preview += f"\n• ...and {len(blocked_records) - 12} more"
                QMessageBox.warning(
                    self,
                    "Profile Is Not Available in General Automation",
                    "General Automation remains blocked for the listed profiles. Generic SSH "
                    "has no validated platform-specific Automation driver; UniFi OS / UDM uses "
                    "only its dedicated fixed diagnostics mode. Experimental opt-in cannot "
                    "override either restriction. No credentials, network connection, or "
                    f"commands were sent.\n\n{preview}",
                )
                return

            untrusted = [
                record
                for record in records
                if not self._has_locally_trusted_host_key(record.hostname, record.port)
            ]
            if untrusted:
                preview = "\n".join(
                    f"• {record.label} ({record.hostname}:{record.port})"
                    for record in untrusted[:12]
                )
                if len(untrusted) > 12:
                    preview += f"\n• ...and {len(untrusted) - 12} more"
                QMessageBox.warning(
                    self,
                    "Untrusted SSH Host Keys",
                    "Automation was blocked before credentials were requested.\n\n"
                    f"{preview}\n\nUse 'Verify / Trust Host Key' on each device first.",
                )
                return

            command_plan = self._prepare_and_confirm_commands(commands_text, records)
            if command_plan is None:
                return
            _commands, allow_destructive = command_plan
            if experimental_mode and not self._confirm_experimental_automation(records[0]):
                self._append_log("[Run] Experimental Automation cancelled.")
                return

        username_prompt = (
            "Enter UniFi OS console SSH username (required: root):"
            if udm_mode
            else "Enter admin username:"
        )
        username, ok = QInputDialog.getText(self, "Credentials", username_prompt)
        if not ok or not username.strip():
            self._append_log("Operation cancelled (no username provided).")
            return
        if udm_mode and username.strip() != "root":
            QMessageBox.warning(
                self,
                "Unsupported UDM SSH Account",
                "This first UDM diagnostics preview requires the console SSH account 'root'. "
                "No credentials, network connection, or commands were sent.",
            )
            return

        password, ok = QInputDialog.getText(
            self,
            "Credentials",
            f"Enter password for {username}:",
            QLineEdit.EchoMode.Password,
        )
        if not ok or password == "":
            self._append_log("Operation cancelled (no password provided).")
            return

        self._clear_password_buffers()
        self._active_password_buffers = []

        username_clean = username.strip()
        username = None
        password_clean = password
        password = None
        password_seed = bytearray(password_clean.encode("utf-8"))
        password_clean = None

        worker = None
        worker_started = False
        try:
            targets = []
            if udm_mode:
                record = records[0]
                password_buffer = bytearray(password_seed)
                self._active_password_buffers.append(password_buffer)
                targets.append(
                    {
                        "device_type": record.device_type,
                        "host": record.hostname,
                        "username": username_clean,
                        "password": password_buffer,
                        "port": record.port,
                    }
                )
            else:
                known_hosts_path = self.get_known_hosts_path()
                if not known_hosts_path.exists():
                    atomic_write_text(
                        known_hosts_path,
                        "",
                        secure_existing_parent=True,
                    )
                for record in records:
                    password_buffer = bytearray(password_seed)
                    self._active_password_buffers.append(password_buffer)

                    device = {
                        "device_type": record.device_type,
                        "host": record.hostname,
                        "username": username_clean,
                        "password": password_buffer,
                        "port": record.port,
                        "ssh_strict": True,
                        "system_host_keys": False,
                        "alt_host_keys": True,
                        "alt_key_file": str(known_hosts_path),
                        "conn_timeout": 10,
                        "auth_timeout": 15,
                        "banner_timeout": 15,
                        "blocking_timeout": 20,
                        "read_timeout_override": 90,
                    }
                    if device["device_type"] == "cisco_wlc":
                        device.update(
                            {
                                "fast_cli": False,
                                "timeout": 60,
                                "global_delay_factor": 6,
                            }
                        )
                    targets.append(device)

            if not targets:
                self._clear_password_buffers()
                self._append_log("[Run] No valid devices found to run on.")
                return

            self._set_automation_running(True)

            if udm_mode:
                self._append_log(
                    "[Run] Starting fixed UDM diagnostics for one device using isolated SSH "
                    "exec channels..."
                )
                if verified_server_key is None:
                    raise ValueError("The verified UDM host-key snapshot is missing.")
                worker = UdmReadOnlyAutomationWorker(
                    targets[0],
                    udm_command_ids,
                    verified_server_key=verified_server_key,
                )
            else:
                if experimental_mode:
                    self._append_log(
                        "[Run] Starting Experimental Automation for one isolated lab target..."
                    )
                else:
                    self._append_log(f"[Run] Starting automation for {len(targets)} devices...")
                worker = AutomationWorker(
                    targets,
                    commands_text,
                    allow_destructive=allow_destructive,
                    allow_experimental_automation=experimental_mode,
                    save_config=False,
                    enter_enable_mode=False,
                )
            self._automation_worker = worker

            def log_and_scroll(s):
                self._append_log(s)

            worker.log.connect(log_and_scroll)

            def finished_handler(final_log, worker=worker):
                status_msg = "[Run] Automation finished."
                if worker.was_stopped():
                    status_msg = "[Run] Automation stopped by user."
                elif worker.had_error():
                    status_msg = "[Run] Automation finished with errors."
                self._append_log(status_msg)
                self._set_automation_running(False)
                self._clear_password_buffers()
                self._append_log(
                    "Credential buffers cleared on a best-effort basis; Python cannot "
                    "guarantee physical memory erasure."
                )
                if not self._shutdown_in_progress and self.save_cb.isChecked():
                    sanitized_output = final_log.strip()
                    if sanitized_output:
                        default_dir = ensure_directory(
                            self.get_data_directory() / "outputs", private=True
                        )
                        suggested = (
                            default_dir / f"Clidarvi-{datetime.now().strftime('%Y%m%d-%H%M%S')}.txt"
                        )
                        file_path, _ = QFileDialog.getSaveFileName(
                            self,
                            "Save Command Transcript",
                            str(suggested),
                            "Text Files (*.txt);;All Files (*)",
                        )
                        if file_path:
                            try:
                                path = write_output_to_path(
                                    Path(file_path), sanitized_output + "\n"
                                )
                                self._append_log(f"Command transcript saved to: {path}")
                                self._append_log(
                                    "Handle this file securely; it contains device interaction output."
                                )
                            except Exception as e:
                                self._append_log(f"Failed to save output: {e}")
                        else:
                            self._append_log("Save output cancelled by user.")
                    else:
                        self._append_log(
                            "No device interaction output captured — nothing saved to disk."
                        )

            worker.finished_with_log.connect(finished_handler)
            worker.finished.connect(
                lambda automation_worker=worker: self._on_automation_worker_finished(
                    automation_worker
                )
            )
            worker.start()
            worker_started = True

        except Exception as e:
            self._append_log(f"[Run] Exception occurred: {redact_command(str(e))}")
        finally:
            if isinstance(password_seed, bytearray):
                for idx in range(len(password_seed)):
                    password_seed[idx] = 0
            username_clean = None
            if not worker_started:
                if worker is not None:
                    worker.discard_unstarted_credentials()
                    try:
                        worker.deleteLater()
                    except RuntimeError:
                        pass
                self._automation_worker = None
                self._clear_password_buffers()
                self._set_automation_running(False)

    # ---------- CLI Sessions & Events ----------
    def _handle_inventory_double_click(self, item, _column):
        if getattr(self, "cli_btn", None) and self.cli_btn.isChecked():
            role = item.data(0, Qt.ItemDataRole.UserRole)
            if role != "folder" and item.childCount() == 0:
                self.start_ssh_from_node(item)

    def start_selected_cli_session(self):
        item = self.tree.currentItem()
        if item is None:
            QMessageBox.information(
                self,
                "Select a Device",
                "Select a device in the inventory before starting a CLI session.",
            )
            return
        role = item.data(0, Qt.ItemDataRole.UserRole)
        if role == "folder" or item.childCount() > 0:
            QMessageBox.information(
                self,
                "Select a Device",
                "Folders cannot open CLI sessions. Select one device instead.",
            )
            return
        self.start_ssh_from_node(item)

    def start_ssh_from_node(self, item):
        if not self._ensure_network_terms_accepted():
            return
        # Only allow session start in CLI mode
        if not (getattr(self, "cli_btn", None) and self.cli_btn.isChecked()):
            QMessageBox.warning(self, "Mode Error", "You can only start a session in CLI Mode.")
            return

        # Ensure CLI tabs exist
        if not hasattr(self, "tabs"):
            self.build_session_page()

        if item.childCount() > 0:
            return

        display_name = item.text(0)
        metadata = item.data(0, Qt.ItemDataRole.UserRole)
        try:
            record = DeviceRecord.from_mapping(
                metadata
                if isinstance(metadata, dict)
                else {"label": display_name, "hostname": display_name}
            )
        except ValueError as exc:
            QMessageBox.warning(self, "SSH Error", f"Selected node is invalid:\n{exc}")
            return

        self._cli_request_generation += 1
        request_token = self._cli_request_generation
        self.verify_host_key_async(
            record.hostname,
            record.port,
            on_trusted=lambda server_key, device=record, token=request_token: (
                self._open_ssh_session(
                    device,
                    request_token=token,
                    verified_server_key=server_key,
                )
            ),
            request_token=request_token,
            require_cli_mode=True,
            request_record=record,
        )

    def _cli_request_is_current(
        self,
        request_token: int | None,
        record: DeviceRecord | None = None,
    ) -> bool:
        if request_token is not None and request_token != self._cli_request_generation:
            return False
        if not (getattr(self, "cli_btn", None) and self.cli_btn.isChecked()):
            return False
        if record is None or request_token is None:
            return True
        item = self._find_node_by_id(record.id)
        if item is None:
            return False
        metadata = item.data(0, Qt.ItemDataRole.UserRole)
        try:
            current = DeviceRecord.from_mapping(metadata)
        except (TypeError, ValueError):
            return False
        return current.to_mapping() == record.to_mapping()

    def _open_ssh_session(
        self,
        record: DeviceRecord,
        *,
        request_token: int | None = None,
        verified_server_key: paramiko.PKey | None = None,
    ):
        if not self._ensure_network_terms_accepted():
            return
        if self._shutdown_in_progress or not self._cli_request_is_current(request_token, record):
            return
        if len(self.sessions) >= MAX_LIVE_CLI_SESSIONS:
            QMessageBox.warning(
                self,
                "Live CLI Session Limit",
                f"At most {MAX_LIVE_CLI_SESSIONS} Live CLI sessions may be open at once. "
                "Close an existing tab before opening another session.",
            )
            return
        username, accepted = QInputDialog.getText(
            self,
            "SSH Authentication",
            "Username:",
            QLineEdit.EchoMode.Normal,
            getpass.getuser(),
        )
        if not accepted or not username.strip():
            return
        password, accepted = QInputDialog.getText(
            self,
            "SSH Authentication",
            "Password (required in this alpha):",
            QLineEdit.EchoMode.Password,
        )
        if not accepted or password == "":
            if accepted:
                QMessageBox.warning(
                    self,
                    "SSH Authentication",
                    "A password is required. SSH key and agent authentication are disabled "
                    "in this alpha.",
                )
            return
        password_buffer = bytearray(password.encode("utf-8"))
        password = None
        if password_buffer is not None:
            self._active_password_buffers.append(password_buffer)
        username_value = username.strip()
        username = None

        worker = None
        terminal = None
        try:
            worker = InteractiveSSHWorker(
                record.hostname,
                port=record.port,
                verified_server_key=verified_server_key,
                username=username_value,
                password_buffer=password_buffer,
                use_keys=False,
            )
            terminal = TerminalWidget(worker)
            terminal.setAccessibleName(f"Interactive SSH terminal for {record.label}")
            worker.output_received.connect(terminal.handle_output_ready)
            index = self._add_cli_session_tab(terminal, record.label)
            worker.connected.connect(lambda term=terminal: self._mark_cli_session_connected(term))
            self.tabs.setCurrentIndex(index)
            self._update_cli_session_state()
            self.sessions[terminal] = worker
            self._session_workers.add(worker)
            worker.closed.connect(lambda term=terminal: self._on_session_closed(term))
            worker.finished.connect(
                lambda session_worker=worker: self._on_session_worker_finished(session_worker)
            )
            worker.start()
        except Exception as e:
            self._release_password_buffer(password_buffer)
            if worker is not None:
                try:
                    worker.stop()
                except Exception:
                    pass
            if terminal is not None:
                self.sessions.pop(terminal, None)
                try:
                    index = self.tabs.indexOf(terminal)
                    if index != -1:
                        self._remove_cli_session_tab(index)
                except (AttributeError, RuntimeError):
                    pass
                self._dispose_terminal_widget(terminal, worker)
                self._update_cli_session_state()
            if worker is not None:
                try:
                    running = worker.isRunning()
                except RuntimeError:
                    running = False
                if not running:
                    self._session_workers.discard(worker)
                    try:
                        worker.password_buffer = None
                        worker.deleteLater()
                    except RuntimeError:
                        pass
            QMessageBox.critical(self, "SSH Error", redact_text_block(str(e)))
        finally:
            username_value = None

    def _update_cli_session_state(self):
        if not hasattr(self, "cli_stack") or not hasattr(self, "tabs"):
            return
        target = self.tabs if self.tabs.count() else self.cli_empty_state
        self.cli_stack.setCurrentWidget(target)

    def _add_cli_session_tab(self, terminal: TerminalWidget, label: str) -> int:
        """Add a compact, accessible session tab with stable widget-bound controls."""

        index = self.tabs.addTab(terminal, label)
        self.tabs.setTabToolTip(index, label)
        tab_bar = self.tabs.tabBar()

        status_dot = QLabel(tab_bar)
        status_dot.setObjectName("SessionStatusDot")
        status_dot.setProperty("state", "connecting")
        status_dot.setAccessibleName(f"{label} session connecting")
        status_dot.setToolTip("Connecting")
        tab_bar.setTabButton(index, QTabBar.ButtonPosition.LeftSide, status_dot)

        close_button = QToolButton(tab_bar)
        close_button.setObjectName("SessionTabCloseButton")
        close_button.setText("×")
        close_button.setAutoRaise(True)
        close_button.setCursor(Qt.CursorShape.PointingHandCursor)
        close_button.setFocusPolicy(Qt.FocusPolicy.TabFocus)
        close_button.setAccessibleName(f"Close CLI session for {label}")
        close_button.setToolTip(f"Close CLI session for {label}")
        close_button.clicked.connect(
            lambda _checked=False, widget=terminal: self._close_cli_session_widget(widget)
        )
        tab_bar.setTabButton(index, QTabBar.ButtonPosition.RightSide, close_button)
        return index

    def _mark_cli_session_connected(self, terminal: TerminalWidget) -> None:
        tabs = getattr(self, "tabs", None)
        if not isinstance(tabs, QTabWidget):
            return
        try:
            index = tabs.indexOf(terminal)
        except RuntimeError:
            return
        if index < 0:
            return
        status_dot = tabs.tabBar().tabButton(index, QTabBar.ButtonPosition.LeftSide)
        if not isinstance(status_dot, QLabel):
            return
        label = tabs.tabText(index)
        status_dot.setProperty("state", "connected")
        status_dot.setAccessibleName(f"{label} session connected")
        status_dot.setToolTip("Connected")
        status_dot.style().unpolish(status_dot)
        status_dot.style().polish(status_dot)
        status_dot.update()

    def _close_cli_session_widget(self, terminal: TerminalWidget) -> None:
        index = self.tabs.indexOf(terminal)
        if index >= 0:
            self.close_session_tab(index)

    def _remove_cli_session_tab(self, index: int) -> None:
        if not 0 <= index < self.tabs.count():
            return
        tab_bar = self.tabs.tabBar()
        for side in (QTabBar.ButtonPosition.LeftSide, QTabBar.ButtonPosition.RightSide):
            accessory = tab_bar.tabButton(index, side)
            if accessory is not None:
                tab_bar.setTabButton(index, side, None)
                accessory.deleteLater()
        self.tabs.removeTab(index)

    def verify_host_key_async(
        self,
        host: str,
        port: int,
        on_trusted=None,
        *,
        request_token: int | None = None,
        require_cli_mode: bool = False,
        request_record: DeviceRecord | None = None,
    ):
        if not self._ensure_network_terms_accepted():
            return
        if self._shutdown_in_progress:
            return
        worker = HostKeyFetchWorker(host, port)
        self._host_key_workers.add(worker)
        self._append_log(f"[Security] Retrieving host key for {host}:{port}...")
        worker.succeeded.connect(
            lambda server_key, h=host, p=port, callback=on_trusted, token=request_token, cli_only=require_cli_mode, record=request_record: (
                self._on_host_key_fetched(h, p, server_key, callback, token, cli_only, record)
            )
        )
        worker.failed.connect(
            lambda error, h=host, p=port, token=request_token, cli_only=require_cli_mode, record=request_record: (
                self._on_host_key_fetch_failed(h, p, error, token, cli_only, record)
            )
        )
        worker.finished.connect(
            lambda fetch_worker=worker: self._on_host_key_worker_finished(fetch_worker)
        )
        try:
            worker.start()
        except Exception as exc:
            try:
                worker.stop()
            except Exception:
                pass
            try:
                running = worker.isRunning()
            except RuntimeError:
                running = False
            if not running:
                self._host_key_workers.discard(worker)
                try:
                    worker.deleteLater()
                except RuntimeError:
                    pass
            safe_error = redact_text_block(str(exc))
            message = f"Unable to start host-key verification for {host}:{port}: {safe_error}"
            self._append_log(f"[Security] {message}")
            if not self._shutdown_in_progress:
                QMessageBox.critical(self, "SSH Error", message)

    def _on_host_key_fetched(
        self,
        host,
        port,
        server_key,
        on_trusted,
        request_token=None,
        require_cli_mode=False,
        request_record=None,
    ):
        if self._shutdown_in_progress:
            return
        if require_cli_mode and not self._cli_request_is_current(request_token, request_record):
            return
        if self.ensure_host_key_trusted(host, port, server_key=server_key):
            if callable(on_trusted):
                on_trusted(server_key)

    def _on_host_key_fetch_failed(
        self,
        host,
        port,
        error,
        request_token=None,
        require_cli_mode=False,
        request_record=None,
    ):
        if require_cli_mode and not self._cli_request_is_current(request_token, request_record):
            return
        message = f"Host key retrieval failed for {host}:{port}: {redact_text_block(str(error))}"
        self._append_log(f"[Security] {message}")
        if not self._shutdown_in_progress:
            QMessageBox.critical(self, "SSH Error", message)

    def _on_host_key_worker_finished(self, worker):
        self._host_key_workers.discard(worker)
        worker.deleteLater()
        self._check_shutdown_complete()

    def ensure_host_key_trusted(
        self, host: str, port: int, *, server_key: paramiko.PKey | None = None
    ) -> bool:
        """
        Ensure the SSH host key is trusted before opening an interactive session.
        Provides mismatch detection and explicit user confirmation.
        """
        if not self._ensure_network_terms_accepted():
            return False
        known_hosts_path = self.get_known_hosts_path()
        try:
            host_keys = self._load_clidarvi_host_keys()
        except Exception as exc:
            message = f"The Clidarvi known_hosts file is invalid and was not modified:\n{exc}"
            self._append_log(f"[Security] {message}")
            if not self._shutdown_in_progress:
                QMessageBox.critical(self, "SSH Host-Key Store Error", message)
            return False

        host_identifier = self._format_known_host_identifier(host, port)
        stored_entry = host_keys.lookup(host_identifier)
        fallback_identifier = None
        if not stored_entry and port == 22:
            fallback_identifier = host
            stored_entry = host_keys.lookup(host)

        if server_key is None:
            message = (
                "Host-key verification requires a key retrieved by the bounded background verifier."
            )
            self._append_log(f"[Security] {message}")
            if not self._shutdown_in_progress:
                QMessageBox.critical(self, "SSH Error", message)
            return False

        server_fingerprint = self._format_fingerprint(server_key)

        if stored_entry:
            if self._fingerprint_matches(stored_entry, server_key):
                return True

            existing_fingerprints = [
                f"{key_type}: {self._format_fingerprint(key)}"
                for key_type, key in stored_entry.items()
            ]
            mismatch_prompt = QMessageBox(self)
            mismatch_prompt.setIcon(QMessageBox.Icon.Warning)
            mismatch_prompt.setWindowTitle("Host Key Mismatch Detected")
            mismatch_prompt.setText(f"The SSH host key for {host}:{port} has changed!")
            mismatch_prompt.setInformativeText(
                "This can indicate a man-in-the-middle attack or the device was re-imaged.\n\n"
                "Previously trusted fingerprints:\n"
                f"{chr(10).join(existing_fingerprints)}\n\n"
                f"Presented fingerprint:\n{server_key.get_name()}: {server_fingerprint}\n\n"
                "Only replace the key if you have independently verified this change."
            )
            mismatch_prompt.setStandardButtons(
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            mismatch_prompt.setDefaultButton(QMessageBox.StandardButton.No)
            mismatch_prompt.button(QMessageBox.StandardButton.Yes).setText("Replace Key")
            mismatch_prompt.button(QMessageBox.StandardButton.No).setText("Abort")
            decision = mismatch_prompt.exec()

            if decision != QMessageBox.StandardButton.Yes:
                self._append_log(f"[Security] Host key mismatch aborted for {host}:{port}")
                return False

            target_identifier = (
                host_identifier
                if host_identifier in host_keys
                else fallback_identifier or host_identifier
            )
            if target_identifier in host_keys:
                host_keys.pop(target_identifier, None)

            host_keys.add(target_identifier, server_key.get_name(), server_key)
            try:
                atomic_write_with(
                    known_hosts_path,
                    lambda temporary: host_keys.save(str(temporary)),
                    secure_existing_parent=True,
                )
            except Exception as exc:
                QMessageBox.critical(
                    self,
                    "SSH Error",
                    f"Failed to store updated host key for {host}:{port}.\n{exc}",
                )
                return False

            self._append_log(f"[Security] Host key replaced for {host}:{port}")
            return True

        prompt = QMessageBox(self)
        prompt.setIcon(QMessageBox.Icon.Question)
        prompt.setWindowTitle("Trust SSH Host Key?")
        prompt.setText(f"{host}:{port} is not yet trusted.")
        prompt.setInformativeText(
            "Verify the fingerprint with a trusted source before continuing.\n\n"
            f"Key type: {server_key.get_name()}\n"
            f"Fingerprint: {server_fingerprint}\n\n"
            "Do you want to trust this host key?"
        )
        prompt.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        prompt.setDefaultButton(QMessageBox.StandardButton.No)
        decision = prompt.exec()

        if decision != QMessageBox.StandardButton.Yes:
            self._append_log(f"[Security] Host key rejected for {host}:{port}")
            return False

        host_keys.add(host_identifier, server_key.get_name(), server_key)
        try:
            atomic_write_with(
                known_hosts_path,
                lambda temporary: host_keys.save(str(temporary)),
                secure_existing_parent=True,
            )
        except Exception as exc:
            QMessageBox.critical(
                self,
                "SSH Error",
                f"Failed to store trusted host key for {host}:{port}.\n{exc}",
            )
            return False

        self._append_log(f"[Security] Trusted host key stored for {host}:{port}")
        return True

    def close_session_tab(self, index):
        widget = self.tabs.widget(index)
        worker = self.sessions.pop(widget, None)
        if worker:
            self._release_password_buffer(getattr(worker, "password_buffer", None))
            worker.stop()
        if 0 <= index < self.tabs.count():
            self._remove_cli_session_tab(index)
        self._dispose_terminal_widget(widget, worker)
        self._update_cli_session_state()

    def _on_session_closed(self, widget):
        worker = self.sessions.pop(widget, None)
        try:
            index = self.tabs.indexOf(widget)
            if index != -1:
                self._remove_cli_session_tab(index)
            self._dispose_terminal_widget(widget, worker)
            self._update_cli_session_state()
        except (AttributeError, RuntimeError):
            pass

    def _on_session_worker_finished(self, worker):
        self._session_workers.discard(worker)
        self._release_password_buffer(getattr(worker, "password_buffer", None))
        worker.password_buffer = None
        worker.deleteLater()
        self._check_shutdown_complete()

    def _release_password_buffer(self, buffer) -> None:
        if isinstance(buffer, bytearray):
            for index in range(len(buffer)):
                buffer[index] = 0
        self._active_password_buffers = [
            active for active in self._active_password_buffers if active is not buffer
        ]

    def _clear_password_buffers(self):
        if not getattr(self, "_active_password_buffers", None):
            self._active_password_buffers = []
            return
        for buffer in self._active_password_buffers:
            if isinstance(buffer, bytearray):
                for idx in range(len(buffer)):
                    buffer[idx] = 0
        self._active_password_buffers = []

    def _append_log(self, message: str):
        log_widget = getattr(self, "logs", None)
        if not isinstance(log_widget, QTextEdit):
            pending = getattr(self, "_pending_log_messages", None)
            if isinstance(pending, list):
                pending.append(str(message))
            return
        try:
            cursor = log_widget.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            if not log_widget.document().isEmpty():
                cursor.insertText("\n")
            cursor.insertText(str(message))
            log_widget.setTextCursor(cursor)
            log_widget.ensureCursorVisible()
            doc = log_widget.document()
            overflow = doc.characterCount() - self.LOG_MAX_CHARS
            if overflow > 0:
                cursor = QTextCursor(doc)
                cursor.movePosition(QTextCursor.MoveOperation.Start)
                cursor.movePosition(
                    QTextCursor.MoveOperation.Right,
                    QTextCursor.MoveMode.KeepAnchor,
                    overflow,
                )
                cursor.removeSelectedText()
        except RuntimeError:
            pending = getattr(self, "_pending_log_messages", None)
            if isinstance(pending, list):
                pending.append(str(message))

    def closeEvent(self, event):
        """Shut workers down asynchronously before allowing Qt to destroy them."""

        if self._shutdown_ready:
            event.accept()
            return

        event.ignore()
        if self._shutdown_in_progress:
            return

        if self._inventory_dirty:
            decision = QMessageBox.warning(
                self,
                "Unsaved Inventory Changes",
                "Save inventory changes before closing Clidarvi?",
                QMessageBox.StandardButton.Save
                | QMessageBox.StandardButton.Discard
                | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Save,
            )
            if decision == QMessageBox.StandardButton.Cancel:
                return
            if decision == QMessageBox.StandardButton.Save and not self.save_tree_to_file():
                return

        self._shutdown_in_progress = True
        self._cli_request_generation += 1
        self.setEnabled(False)
        self._append_log("[System] Closing active network sessions...")
        self._close_all_sessions()
        for host_key_worker in tuple(self._host_key_workers):
            host_key_worker.stop()
        worker = getattr(self, "_automation_worker", None)
        if worker is not None and worker.isRunning():
            worker.stop()
        # Zero GUI-owned password buffers immediately; do not retain them while
        # waiting for resolver or transport teardown.
        self._clear_password_buffers()
        QTimer.singleShot(0, self._check_shutdown_complete)

    def _check_shutdown_complete(self):
        if not self._shutdown_in_progress:
            return
        automation_running = bool(
            self._automation_worker is not None and self._automation_worker.isRunning()
        )
        sessions_running = any(worker.isRunning() for worker in tuple(self._session_workers))
        host_key_checks_running = any(
            worker.isRunning() for worker in tuple(self._host_key_workers)
        )
        if automation_running or sessions_running or host_key_checks_running:
            QTimer.singleShot(100, self._check_shutdown_complete)
            return

        self._clear_password_buffers()
        self._append_log("[System] Network workers stopped; credentials released.")
        self._shutdown_ready = True
        QTimer.singleShot(0, self.close)

    # ---------- Device Tree Context ----------
    def _add_site(self, parent: QTreeWidgetItem | None = None) -> QTreeWidgetItem | None:
        dialog = SiteDialog("add", parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return None
        try:
            site = dialog.get_site_record()
            label = self._validated_folder_name(site.name, parent)
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid Site", str(exc))
            return None
        if label != site.name:
            site = SiteRecord.from_mapping({**site.to_mapping(), "name": label})
        site_parent = parent if parent is not None else self.tree
        site_item = self._make_folder_item(site_parent, label, site=site)
        site_item.setExpanded(True)
        self.tree.setCurrentItem(site_item)
        self.capture_history_state()
        self.populate_selector_from_tree()
        return site_item

    def add_root_site(self):
        self._add_site()

    def _edit_site(self, item: QTreeWidgetItem) -> None:
        current = self._site_record_for_item(item)
        if current is None:
            return
        dialog = SiteDialog("edit", current.to_mapping(), self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            updated = dialog.get_site_record()
            label = self._validated_folder_name(updated.name, item.parent(), item)
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid Site", str(exc))
            return
        if label != updated.name:
            updated = SiteRecord.from_mapping({**updated.to_mapping(), "name": label})
        self._set_site_record(item, updated)
        self.capture_history_state()
        self.populate_selector_from_tree()

    def _add_site_details(self, item: QTreeWidgetItem) -> None:
        if self._site_record_for_item(item) is not None:
            self._edit_site(item)
            return
        initial = SiteRecord(name=item.text(0))
        dialog = SiteDialog("add", initial.to_mapping(), self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            site = dialog.get_site_record()
            label = self._validated_folder_name(site.name, item.parent(), item)
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid Site", str(exc))
            return
        if label != site.name:
            site = SiteRecord.from_mapping({**site.to_mapping(), "name": label})
        self._set_site_record(item, site)
        self.capture_history_state()
        self.populate_selector_from_tree()

    def _remove_site_details(self, item: QTreeWidgetItem) -> None:
        if self._site_record_for_item(item) is None:
            return
        decision = QMessageBox.question(
            self,
            "Remove Site Details",
            "Remove this site's address and location details? The folder and its devices "
            "will be kept.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if decision != QMessageBox.StandardButton.Yes:
            return
        item.setData(0, SITE_DATA_ROLE, None)
        item.setIcon(0, QIcon())
        item.setToolTip(0, "")
        item.setData(0, Qt.ItemDataRole.AccessibleDescriptionRole, None)
        self.capture_history_state()
        self.populate_selector_from_tree()

    def add_root_device(self):
        dialog = NodeDialog("add", parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        data = dialog.get_node_data()
        if not data["hostname"]:
            return
        node_item = self._make_node_item(self.tree, data["label"], metadata=data)
        self.tree.setCurrentItem(node_item)
        self.capture_history_state()
        self.populate_selector_from_tree()

    def show_tree_menu(self, pos):
        item = self.tree.itemAt(pos)
        # If no item at position, show root context menu (allow adding top-level nodes/directories)
        if not item:
            menu = QMenu()
            add_node_action = menu.addAction("Add Device")
            add_site_action = menu.addAction("Add Site")
            add_subdir_action = menu.addAction("Add Directory")
            action = menu.exec(self.tree.viewport().mapToGlobal(pos))

            if action == add_node_action:
                self.add_root_device()

            elif action == add_site_action:
                self.add_root_site()

            elif action == add_subdir_action:
                new_name, ok = QInputDialog.getText(
                    self, "Add Directory", "Enter subdirectory name:"
                )
                if ok and new_name.strip():
                    try:
                        folder_name = self._validated_folder_name(new_name)
                    except ValueError as exc:
                        QMessageBox.warning(self, "Invalid Directory", str(exc))
                        return
                    sub_item = self._make_folder_item(self.tree, folder_name)
                    sub_item.setExpanded(True)
                    self.capture_history_state()
                    self.populate_selector_from_tree()
            return

        role_data = item.data(0, Qt.ItemDataRole.UserRole)
        is_folder = role_data == "folder" or item.childCount() > 0

        is_node = not is_folder

        # ---------- NODE (LEAF) ----------
        if is_node:
            menu = QMenu()
            start_session_action = None
            if getattr(self, "cli_btn", None) and self.cli_btn.isChecked():
                start_session_action = menu.addAction("Start Session")
            trust_key_action = menu.addAction("Verify / Trust Host Key")
            edit_action = menu.addAction("Edit Device")
            delete_action = menu.addAction("Delete Device")
            action = menu.exec(self.tree.viewport().mapToGlobal(pos))

            if action and action == start_session_action:
                self.start_ssh_from_node(item)
                return

            if action == trust_key_action:
                metadata = item.data(0, Qt.ItemDataRole.UserRole)
                try:
                    record = DeviceRecord.from_mapping(
                        metadata if isinstance(metadata, dict) else {"label": item.text(0)}
                    )
                    self.verify_host_key_async(record.hostname, record.port)
                except ValueError as exc:
                    QMessageBox.warning(self, "Invalid Device", str(exc))
                return

            elif action == edit_action:
                menu.close()

                def open_edit_node_dialog():
                    try:
                        if item.treeWidget() is not self.tree:
                            return
                        self.activateWindow()
                        self.raise_()
                        QApplication.processEvents()
                        node_data = item.data(0, Qt.ItemDataRole.UserRole)
                        if not isinstance(node_data, dict):
                            node_data = {
                                "hostname": item.text(0),
                                "vendor": "Other",
                                "device_type": "generic",
                                "port": "22",
                            }
                        else:
                            node_data = dict(node_data)
                        node_data.setdefault("label", item.text(0))
                        dlg = NodeDialog("edit", node_data, self)
                        if dlg.exec() == QDialog.DialogCode.Accepted:
                            if item.treeWidget() is not self.tree:
                                return
                            new_data = dlg.get_node_data()
                            if new_data["hostname"]:
                                self._set_node_record(item, DeviceRecord.from_mapping(new_data))
                                self.capture_history_state()
                                self.populate_selector_from_tree()
                    except RuntimeError:
                        return

                QTimer.singleShot(200, open_edit_node_dialog)

            elif action == delete_action:
                decision = QMessageBox.question(
                    self,
                    "Delete Device",
                    f"Delete '{item.text(0)}' from the inventory?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                if decision != QMessageBox.StandardButton.Yes:
                    return
                parent = item.parent()
                if parent:
                    parent.removeChild(item)
                else:
                    index = self.tree.indexOfTopLevelItem(item)
                    if index != -1:
                        self.tree.takeTopLevelItem(index)
                self.capture_history_state()
                self.populate_selector_from_tree()
            return

        # ---------- FOLDER ----------
        if is_folder:
            site = self._site_record_for_item(item)
            menu = QMenu()
            add_node_action = menu.addAction("Add Device")
            add_site_action = menu.addAction("Add Site")
            add_subdir_action = menu.addAction("Add Subdirectory")
            menu.addSeparator()
            site_details_action = menu.addAction(
                "Edit Site Details" if site else "Add Site Details"
            )
            remove_site_details_action = None
            rename_action = None
            if site is not None:
                remove_site_details_action = menu.addAction("Remove Site Details")
            else:
                rename_action = menu.addAction("Edit Name")
            delete_action = menu.addAction("Delete Site" if site else "Delete Directory")

            action = menu.exec(self.tree.viewport().mapToGlobal(pos))

            if action == add_node_action:
                dlg = NodeDialog("add", parent=self)
                if dlg.exec() == QDialog.DialogCode.Accepted:
                    data = dlg.get_node_data()
                    if data["hostname"]:
                        self._make_node_item(item, data["label"], metadata=data)
                        self.capture_history_state()
                        self.populate_selector_from_tree()

            elif action == add_site_action:
                self._add_site(item)

            elif action == add_subdir_action:
                new_name, ok = QInputDialog.getText(
                    self, "Add Subdirectory", "Enter subdirectory name:"
                )
                if ok and new_name.strip():
                    try:
                        folder_name = self._validated_folder_name(new_name, item)
                    except ValueError as exc:
                        QMessageBox.warning(self, "Invalid Directory", str(exc))
                        return
                    sub_item = self._make_folder_item(item, folder_name)
                    sub_item.setExpanded(True)
                    self.capture_history_state()
                    self.populate_selector_from_tree()

            elif action == site_details_action:
                if site is not None:
                    self._edit_site(item)
                else:
                    self._add_site_details(item)

            elif remove_site_details_action is not None and action == remove_site_details_action:
                self._remove_site_details(item)

            elif rename_action is not None and action == rename_action:
                current_name = item.text(0)
                menu.close()

                def open_edit_dialog():
                    try:
                        if item.treeWidget() is not self.tree:
                            return
                        self.activateWindow()
                        self.raise_()
                        QApplication.processEvents()

                        dlg = QInputDialog(self)
                        dlg.setWindowTitle("Edit Name")
                        dlg.setLabelText("Enter new name:")
                        dlg.setTextValue(current_name)
                        if dlg.exec() == QDialog.DialogCode.Accepted:
                            if item.treeWidget() is not self.tree:
                                return
                            new_name = dlg.textValue()
                            if new_name.strip():
                                try:
                                    folder_name = self._validated_folder_name(
                                        new_name, item.parent(), item
                                    )
                                except ValueError as exc:
                                    QMessageBox.warning(self, "Invalid Directory", str(exc))
                                    return
                                item.setText(0, folder_name)
                                self.capture_history_state()
                                self.populate_selector_from_tree()
                    except RuntimeError:
                        return

                QTimer.singleShot(200, open_edit_dialog)

            elif action == delete_action:
                descendant_count = sum(1 for _ in self._iter_leaf_nodes(item))
                item_kind = "Site" if site is not None else "Directory"
                decision = QMessageBox.warning(
                    self,
                    f"Delete {item_kind}",
                    f"Delete '{item.text(0)}' and {descendant_count} contained device(s)?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                if decision != QMessageBox.StandardButton.Yes:
                    return
                parent = item.parent()
                if parent:
                    parent.removeChild(item)
                else:
                    index = self.tree.indexOfTopLevelItem(item)
                    if index != -1:
                        self.tree.takeTopLevelItem(index)
                self.capture_history_state()
                self.populate_selector_from_tree()

    # ---------- History Navigation ----------
    def _set_inventory_dirty(self, dirty: bool) -> None:
        self._inventory_dirty = bool(dirty)
        suffix = " *" if self._inventory_dirty else ""
        self.setWindowTitle(f"{self.WINDOW_TITLE}{suffix}")

    def _inventory_digest(self, state: dict[str, Any]) -> str:
        canonical = json.dumps(
            state,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def _current_inventory_state(self) -> dict[str, Any]:
        tree = self._sanitize_tree_dict(self.tree_to_dict())
        return encode_inventory_document(tree, sites=self._site_placements_from_tree())

    def _restore_last_valid_history_state(self, previous_dirty: bool) -> None:
        if not hasattr(self, "history") or not self.history or self.history_index < 0:
            return
        decoded = decode_inventory_state(copy.deepcopy(self.history[self.history_index]))
        tree = self._sanitize_tree_dict(decoded.tree)
        sites = sanitize_site_placements(
            tree,
            decoded.sites,
            max_depth=MAX_DEVICE_TREE_DEPTH,
            max_items=MAX_DEVICE_TREE_NODES,
            max_label_length=MAX_LABEL_LENGTH,
        )
        self._apply_tree_dict(tree, sites)
        self.populate_selector_from_tree()
        self._prune_missing_automation_targets()
        self._set_inventory_dirty(previous_dirty)

    def capture_history_state(self, *, mark_dirty: bool = True):
        previous_dirty = self._inventory_dirty
        try:
            state = self._current_inventory_state()
            digest = self._inventory_digest(state)
            existing_history = getattr(self, "history", [])
            existing_index = getattr(self, "history_index", -1)
            candidate_history = list(existing_history[: existing_index + 1])
            candidate_history.append(state)
            while len(candidate_history) > MAX_HISTORY_STATES:
                candidate_history.pop(0)
            while (
                len(candidate_history) > 1
                and sum(
                    self._count_dict_items(snapshot.get("tree", {}))
                    for snapshot in candidate_history
                )
                > MAX_HISTORY_TOTAL_ITEMS
            ):
                candidate_history.pop(0)
            candidate_index = len(candidate_history) - 1
        except (TypeError, ValueError, UnicodeError) as exc:
            self._restore_last_valid_history_state(previous_dirty)
            self._append_log(f"[Inventory] Invalid change was rolled back: {exc}")
            QMessageBox.warning(self, "Invalid Inventory Change", str(exc))
            return False

        # Commit only after canonicalization, digesting, and all bound checks
        # have succeeded.  A hostile string must never leave a partial undo
        # entry behind merely because UTF-8 digesting failed.
        self.history = candidate_history
        self.history_index = candidate_index
        if mark_dirty:
            self._set_inventory_dirty(digest != self._saved_inventory_digest)
        else:
            self._saved_inventory_digest = digest
            self._set_inventory_dirty(False)
        return True

    def restore_tree_state(self, state):
        decoded = decode_inventory_state(state)
        tree = self._sanitize_tree_dict(decoded.tree)
        sites = sanitize_site_placements(
            tree,
            decoded.sites,
            max_depth=MAX_DEVICE_TREE_DEPTH,
            max_items=MAX_DEVICE_TREE_NODES,
            max_label_length=MAX_LABEL_LENGTH,
        )
        self._apply_tree_dict(tree, sites)
        self.populate_selector_from_tree()
        self._prune_missing_automation_targets()
        digest = self._inventory_digest(encode_inventory_document(tree, sites=sites))
        self._set_inventory_dirty(digest != self._saved_inventory_digest)

    def go_back(self):
        if hasattr(self, "history") and self.history_index > 0:
            self.history_index -= 1
            self.restore_tree_state(self.history[self.history_index])
        self._append_log("Undo → restored previous tree state")

    def go_forward(self):
        if hasattr(self, "history") and self.history_index < len(self.history) - 1:
            self.history_index += 1
            self.restore_tree_state(self.history[self.history_index])
        self._append_log("Redo → reapplied last change")

    # ---------- Persistence Utilities ----------
    def build_tree_from_dict(self, parent, data: dict):
        nodes = data.get("_nodes", [])
        for node in nodes:
            record = DeviceRecord.from_mapping(
                node if isinstance(node, dict) else {"label": str(node)}
            )
            self._make_node_item(
                parent,
                record.label,
                record.hostname,
                record.to_mapping(),
            )

        for key, val in data.items():
            if key == "_nodes":
                continue
            folder_item = self._make_folder_item(parent, key)
            self.build_tree_from_dict(folder_item, val)

    def tree_to_dict(self) -> dict:
        def recurse(item: QTreeWidgetItem):
            data = {}
            node_entries = []
            for i in range(item.childCount()):
                child = item.child(i)
                role = child.data(0, Qt.ItemDataRole.UserRole)
                if child.childCount() > 0 or role == "folder":
                    label = self._sanitize_label(child.text(0))
                    data[label] = recurse(child)
                else:
                    node_entries.append(self._item_to_node_entry(child))
            if node_entries:
                data["_nodes"] = node_entries
            return data

        root = {}
        root_nodes = []
        for i in range(self.tree.topLevelItemCount()):
            top_item = self.tree.topLevelItem(i)
            role = top_item.data(0, Qt.ItemDataRole.UserRole)
            if top_item.childCount() > 0 or role == "folder":
                label = self._sanitize_label(top_item.text(0))
                root[label] = recurse(top_item)
            else:
                root_nodes.append(self._item_to_node_entry(top_item))
        if root_nodes:
            root["_nodes"] = root_nodes
        return root

    def _format_known_host_identifier(self, host: str, port: int) -> str:
        return host if port == 22 else f"[{host}]:{port}"

    def _load_clidarvi_host_keys(self) -> paramiko.hostkeys.HostKeys:
        path = self.get_known_hosts_path()
        keys = paramiko.hostkeys.HostKeys()
        if not path.exists():
            return keys
        raw = _read_bounded_regular_file(path, max_bytes=5 * 1024 * 1024)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("The Clidarvi known_hosts file is not valid UTF-8.") from exc
        for line_number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            try:
                entry = paramiko.hostkeys.HostKeyEntry.from_line(stripped, line_number)
            except (paramiko.hostkeys.InvalidHostKey, TypeError, ValueError) as exc:
                raise ValueError(f"Invalid known_hosts entry on line {line_number}.") from exc
            if entry is None or entry.key is None:
                raise ValueError(f"Invalid known_hosts entry on line {line_number}.")
            for hostname in entry.hostnames:
                keys.add(hostname, entry.key.get_name(), entry.key)
        return keys

    def _has_locally_trusted_host_key(self, host: str, port: int) -> bool:
        try:
            host_keys = self._load_clidarvi_host_keys()
        except (OSError, ValueError, paramiko.SSHException):
            return False
        identifier = self._format_known_host_identifier(host, port)
        return bool(host_keys.lookup(identifier) or (port == 22 and host_keys.lookup(host)))

    def _trusted_server_key_snapshot(self, host: str, port: int) -> paramiko.PKey:
        """Return one exact trusted key loaded before credentials are requested."""

        host_keys = self._load_clidarvi_host_keys()
        identifier = self._format_known_host_identifier(host, port)
        stored_entry = host_keys.lookup(identifier)
        if not stored_entry and port == 22:
            stored_entry = host_keys.lookup(host)
        if not stored_entry:
            raise ValueError(
                f"No trusted SSH host key is stored for {host}:{port}. "
                "Verify / Trust Host Key first."
            )
        trusted_keys = tuple(stored_entry.values())
        if len(trusted_keys) != 1:
            raise ValueError(
                f"UDM diagnostics require exactly one pinned host key for {host}:{port}; "
                "the local entry contains multiple keys. Resolve the entry and verify it again."
            )
        trusted_key = trusted_keys[0]
        if not isinstance(trusted_key, paramiko.PKey):
            raise ValueError("The stored SSH host key is invalid.")
        return trusted_key

    def _fingerprint_matches(self, stored_entry: dict, server_key: paramiko.PKey) -> bool:
        for key_type, key in stored_entry.items():
            if key_type == server_key.get_name() and key == server_key:
                return True
        return False

    def _format_fingerprint(self, key: paramiko.PKey) -> str:
        digest = hashlib.sha256(key.asbytes()).digest()
        encoded = base64.b64encode(digest).decode("ascii").rstrip("=")
        return f"SHA256:{encoded}"

    def get_data_directory(self) -> Path:
        return get_application_data_directory()

    def get_known_hosts_path(self) -> Path:
        return self.get_data_directory() / "known_hosts"

    def get_risk_acknowledgement_path(self) -> Path:
        return self.get_data_directory() / RISK_ACKNOWLEDGEMENT_FILENAME

    def get_save_path(self):
        return self.get_data_directory() / "devices.json"

    def save_tree_to_file(self) -> bool:
        try:
            tree = self._sanitize_tree_dict(self.tree_to_dict())
            data = encode_inventory_document(
                tree,
                sites=self._site_placements_from_tree(),
            )
            payload = _render_bounded_inventory_document(data)
            save_path = self.get_save_path()
            if save_path.exists():
                try:
                    previous = self._read_inventory_path(save_path)
                except Exception as existing_error:
                    raise ValueError(
                        "Refusing to overwrite the existing inventory because it cannot be "
                        "validated. Move or preserve devices.json manually, or export the "
                        "current inventory to a different file, before saving again."
                    ) from existing_error
                else:
                    previous_document = encode_inventory_document(
                        previous.tree,
                        sites=previous.sites,
                    )
                    atomic_write_text(
                        self._inventory_backup_path(save_path),
                        _render_bounded_inventory_document(previous_document),
                        secure_existing_parent=True,
                    )
            path = atomic_write_text(save_path, payload, secure_existing_parent=True)
            self._saved_inventory_digest = self._inventory_digest(data)
            self._set_inventory_dirty(False)
            self._append_log(f"[System] Inventory saved to {path}")
            return True
        except Exception as exc:
            self._append_log(f"[System] Save Error: {exc}")
            QMessageBox.critical(self, "Save Error", f"Failed to save inventory:\n{exc}")
            return False

    def load_tree_from_file(self):
        path = self.get_save_path()
        if not path.exists():
            return None
        try:
            state = self._read_inventory_path(path)
            if not _apply_secure_permissions(path, 0o600):
                self._append_log(f"[Security] Could not enforce private permissions on {path}.")
            self._apply_tree_dict(state.tree, state.sites)
            self._saved_inventory_digest = self._inventory_digest(
                encode_inventory_document(state.tree, sites=state.sites)
            )
            self._set_inventory_dirty(False)
            return True
        except Exception as e:
            recovery_path = path.with_name(
                f"{path.name}.corrupt-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}"
            )
            recovery_note = ""
            invalid_primary_preserved = False
            try:
                corrupt_snapshot = _read_bounded_regular_file(
                    path,
                    max_bytes=MAX_IMPORT_FILE_SIZE,
                )
                atomic_write_with(
                    recovery_path,
                    lambda temporary: Path(temporary).write_bytes(corrupt_snapshot),
                    secure_existing_parent=True,
                )
                invalid_primary_preserved = True
                recovery_note = f" A recovery copy was saved to {recovery_path}."
            except Exception as backup_error:
                recovery_note = f" Recovery copy failed: {backup_error}."

            backup_path = self._inventory_backup_path(path)
            if backup_path.exists():
                try:
                    recovered = self._read_inventory_path(backup_path)
                    self._apply_tree_dict(recovered.tree, recovered.sites)
                    repair_note = ""
                    if invalid_primary_preserved:
                        try:
                            recovered_document = encode_inventory_document(
                                recovered.tree,
                                sites=recovered.sites,
                            )
                            atomic_write_text(
                                path,
                                _render_bounded_inventory_document(recovered_document),
                                secure_existing_parent=True,
                            )
                            self._saved_inventory_digest = self._inventory_digest(
                                recovered_document
                            )
                            self._set_inventory_dirty(False)
                            repair_note = " The primary inventory was repaired atomically."
                        except Exception as repair_error:
                            repair_note = (
                                " The recovered data is open but repairing the primary failed: "
                                f"{repair_error}. Save the inventory manually."
                            )
                            self._set_inventory_dirty(True)
                    else:
                        repair_note = (
                            " The recovered backup is open, but the invalid primary was left "
                            "untouched because no exact recovery copy could be created. Move or "
                            "preserve it manually before saving."
                        )
                        self._set_inventory_dirty(True)
                    self._append_log(
                        f"[System] Primary inventory was invalid ({e}). Restored the "
                        f"last-known-good backup from {backup_path}.{recovery_note}{repair_note}"
                    )
                    return True
                except Exception as backup_error:
                    recovery_note += f" Backup recovery failed: {backup_error}."
            self._append_log(f"[System] Load Error: Failed to load inventory: {e}.{recovery_note}")
            return False

    def _inventory_backup_path(self, path: Path | None = None) -> Path:
        inventory_path = self.get_save_path() if path is None else Path(path)
        return inventory_path.with_name(f"{inventory_path.name}.bak")

    def _read_inventory_path(self, path: Path) -> InventoryState:
        raw = _read_bounded_regular_file(path, max_bytes=MAX_IMPORT_FILE_SIZE)
        document = _load_strict_json_snapshot(raw)
        decoded = decode_inventory_state(document)
        tree = self._sanitize_tree_dict(decoded.tree)
        sites = sanitize_site_placements(
            tree,
            decoded.sites,
            max_depth=MAX_DEVICE_TREE_DEPTH,
            max_items=MAX_DEVICE_TREE_NODES,
            max_label_length=MAX_LABEL_LENGTH,
        )
        return InventoryState(tree=tree, sites=sites)

    def _snapshot_import_transaction(self) -> dict[str, Any]:
        """Capture every mutable UI/history surface touched by an import."""

        selector_snapshot = None
        selector = getattr(self, "selector", None)
        if isinstance(selector, QComboBox):
            selector_snapshot = {
                "items": [
                    (
                        selector.itemIcon(index),
                        selector.itemText(index),
                        copy.deepcopy(selector.itemData(index)),
                    )
                    for index in range(selector.count())
                ],
                "current_index": selector.currentIndex(),
                "last_index": getattr(selector, "_last_index", None),
            }

        target_snapshot = None
        target_list = getattr(self, "add_list", None)
        if isinstance(target_list, QListWidget):
            target_snapshot = [
                target_list.item(index).clone() for index in range(target_list.count())
            ]

        return {
            "tree_items": [
                self.tree.topLevelItem(index).clone()
                for index in range(self.tree.topLevelItemCount())
            ],
            "history_present": hasattr(self, "history"),
            # capture_history_state commits by assigning a fresh list, so this
            # bounded immutable-snapshot list can safely be retained by reference.
            "history": getattr(self, "history", None),
            "history_index_present": hasattr(self, "history_index"),
            "history_index": getattr(self, "history_index", None),
            "saved_inventory_digest": self._saved_inventory_digest,
            "inventory_dirty": self._inventory_dirty,
            "selector": selector_snapshot,
            "targets": target_snapshot,
            "nodes_label": (
                self.nodes_lbl.text()
                if isinstance(getattr(self, "nodes_lbl", None), QLabel)
                else None
            ),
        }

    def _restore_import_transaction(self, snapshot: dict[str, Any]) -> None:
        """Restore a pre-import snapshot without invoking fallible model rebuilding."""

        tree_signals_blocked = self.tree.blockSignals(True)
        self.tree.setUpdatesEnabled(False)
        try:
            self.tree.clear()
            for item in snapshot["tree_items"]:
                self.tree.addTopLevelItem(item)
            self.tree.expandAll()
        finally:
            self.tree.setUpdatesEnabled(True)
            self.tree.blockSignals(tree_signals_blocked)

        if snapshot["history_present"]:
            self.history = snapshot["history"]
        elif hasattr(self, "history"):
            del self.history
        if snapshot["history_index_present"]:
            self.history_index = snapshot["history_index"]
        elif hasattr(self, "history_index"):
            del self.history_index
        self._saved_inventory_digest = snapshot["saved_inventory_digest"]

        selector_snapshot = snapshot["selector"]
        selector = getattr(self, "selector", None)
        if selector_snapshot is not None and isinstance(selector, QComboBox):
            selector_signals_blocked = selector.blockSignals(True)
            try:
                selector.clear()
                for icon, text, data in selector_snapshot["items"]:
                    selector.addItem(icon, text, data)
                selector.setCurrentIndex(selector_snapshot["current_index"])
                last_index = selector_snapshot["last_index"]
                if last_index is None:
                    if hasattr(selector, "_last_index"):
                        del selector._last_index
                else:
                    selector._last_index = last_index
            finally:
                selector.blockSignals(selector_signals_blocked)

        target_snapshot = snapshot["targets"]
        target_list = getattr(self, "add_list", None)
        if target_snapshot is not None and isinstance(target_list, QListWidget):
            target_signals_blocked = target_list.blockSignals(True)
            try:
                target_list.clear()
                for item in target_snapshot:
                    target_list.addItem(item)
            finally:
                target_list.blockSignals(target_signals_blocked)

        nodes_label = snapshot["nodes_label"]
        if nodes_label is not None and isinstance(getattr(self, "nodes_lbl", None), QLabel):
            self.nodes_lbl.setText(nodes_label)
        self._set_inventory_dirty(snapshot["inventory_dirty"])

    def _commit_import_state(self, tree: dict, sites=()) -> None:
        """Atomically apply one validated import to the model and dependent UI."""

        snapshot = self._snapshot_import_transaction()
        applied = False
        try:
            self._apply_tree_dict(tree, sites)
            applied = True
            if not self.capture_history_state():
                raise ValueError("Imported inventory could not be recorded in undo history.")
            self.populate_selector_from_tree()
        except BaseException:
            # _apply_tree_dict has its own rollback for failures during apply.
            # Once it returned successfully, however, history and selector work
            # must either commit together or restore the exact prior snapshot.
            if applied:
                self._restore_import_transaction(snapshot)
            raise

    def import_tree_from_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import Inventory", "", "JSON/XML Files (*.json *.xml)"
        )
        if not file_path:
            return
        try:
            raw_snapshot = self._validate_import_file_size(file_path)
            # --- XML import logic ---
            if file_path.lower().endswith(".xml"):
                # Custom message box with Merge, Replace, and Cancel buttons.
                # Without an explicit Cancel button Qt promotes the sole
                # NoRole button ("Replace") to the escape button, so Escape or
                # closing the window would silently replace the inventory.
                msg_box = QMessageBox(self)
                msg_box.setWindowTitle("Import Options")
                msg_box.setText(
                    "Do you want to merge this XML file with the existing device tree, "
                    "or replace it completely?"
                )
                merge_btn = msg_box.addButton("Merge", QMessageBox.ButtonRole.YesRole)
                replace_btn = msg_box.addButton("Replace", QMessageBox.ButtonRole.NoRole)
                cancel_btn = msg_box.addButton(QMessageBox.StandardButton.Cancel)
                msg_box.setEscapeButton(cancel_btn)
                msg_box.setDefaultButton(merge_btn)

                msg_box.exec()
                choice = msg_box.clickedButton()

                if choice is merge_btn:
                    mode = "merge"
                elif choice is replace_btn:
                    mode = "replace"
                else:
                    # Cancel, Escape, or closing the window all land here.
                    self._append_log("[System] Import cancelled by user.")
                    return

                root = self._parse_xml_snapshot(raw_snapshot)
                sanitized_xml = self._sanitize_xml_tree(root)

                if mode == "replace":
                    total_items = self._count_dict_items(sanitized_xml)
                    if MAX_DEVICE_TREE_NODES is not None and total_items > MAX_DEVICE_TREE_NODES:
                        raise ValueError("XML import would exceed maximum device tree size.")
                    self._commit_import_state(sanitized_xml, ())
                    self._append_log("[System] XML file replaced successfully.")
                elif mode == "merge":
                    current_dict = self._sanitize_tree_dict(self.tree_to_dict())
                    current_sites = self._site_placements_from_tree()
                    merged_dict = copy.deepcopy(current_dict)
                    self._merge_tree_dict(merged_dict, sanitized_xml)
                    total_items = self._count_dict_items(merged_dict)
                    if MAX_DEVICE_TREE_NODES is not None and total_items > MAX_DEVICE_TREE_NODES:
                        raise ValueError("Merged device tree exceeds maximum allowed size.")
                    added_items = total_items - self._count_dict_items(current_dict)
                    self._commit_import_state(merged_dict, current_sites)
                    self._append_log(
                        f"[System] XML file merged successfully ({max(added_items, 0)} new items added)."
                    )
                return

            # --- JSON fallback ---
            document = _load_strict_json_snapshot(raw_snapshot)
            decoded = decode_inventory_state(document)
            sanitized_dict = self._sanitize_tree_dict(decoded.tree)
            sites = sanitize_site_placements(
                sanitized_dict,
                decoded.sites,
                max_depth=MAX_DEVICE_TREE_DEPTH,
                max_items=MAX_DEVICE_TREE_NODES,
                max_label_length=MAX_LABEL_LENGTH,
            )
            total_items = self._count_dict_items(sanitized_dict)
            if MAX_DEVICE_TREE_NODES is not None and total_items > MAX_DEVICE_TREE_NODES:
                raise ValueError("JSON import exceeds maximum allowed device tree size.")
            self._commit_import_state(sanitized_dict, sites)
            self._append_log("[System] Inventory imported successfully.")
        except Exception as e:
            self._append_log(f"[System] Import Error: Failed to import inventory: {e}")
            if not isinstance(getattr(self, "logs", None), QTextEdit):
                QMessageBox.critical(self, "Import Error", f"Failed to import inventory: {e}")

    def export_tree_to_file(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Inventory",
            "clidarvi_devices.json",
            "JSON Files (*.json)",
        )
        if not file_path:
            return
        try:
            tree = self._sanitize_tree_dict(self.tree_to_dict())
            root_data = encode_inventory_document(
                tree,
                sites=self._site_placements_from_tree(),
            )
            atomic_write_text(file_path, _render_bounded_inventory_document(root_data))
            self._append_log(f"[System] Inventory exported successfully to: {file_path}")
        except Exception as e:
            self._append_log(f"[System] Export Error: Failed to export inventory: {e}")
            if not isinstance(getattr(self, "logs", None), QTextEdit):
                QMessageBox.critical(self, "Export Error", f"Failed to export inventory: {e}")


def main(argv=None) -> int:
    app = QApplication(list(sys.argv if argv is None else argv))
    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName(APP_NAME)
    app.setApplicationVersion(__version__)
    app.setOrganizationName(APP_NAME)

    data_directory = get_application_data_directory()
    instance_lock = QLockFile(str(data_directory / "clidarvi.lock"))
    instance_lock.setStaleLockTime(0)
    if not instance_lock.tryLock(100):
        QMessageBox.critical(
            None,
            "Clidarvi Already Running",
            "Another Clidarvi instance is using this inventory. Close it before "
            "starting a second instance.",
        )
        return 1
    app._clidarvi_instance_lock = instance_lock

    win = MainWindow()
    win.show()
    app._clidarvi_main_window = win
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
