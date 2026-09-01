# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 devnetdreamer (https://github.com/devnetdreamer) and Clidarvi contributors
# Additional warranty, liability, and operational terms: see DISCLAIMER.md and TERMS.md.

"""Pure data-model and tree utilities for Clidarvi.

The GUI stores its inventory as nested dictionaries.  Each dictionary key other
than ``_nodes`` is a folder name; ``_nodes`` contains the devices in that
folder.  This module deliberately has no PyQt dependency so the inventory rules
can be tested and reused independently from the UI.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Callable, Iterable, Iterator, Mapping
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, TypeAlias
from uuid import uuid4

MAX_DEVICE_TREE_NODES = 100_000
MAX_DEVICE_TREE_DEPTH = 32
# Raw JSON-container nesting limit applied to un-canonicalized legacy trees
# before deepcopy runs.  Real inventories nest ~<40 levels (folder depth is
# capped at MAX_DEVICE_TREE_DEPTH downstream); this generous bound only exists
# to stop a stack-exhaustion denial of service well below the interpreter's
# recursion limit.
MAX_INVENTORY_NESTING_DEPTH = 100
MAX_LABEL_LENGTH = 256
MAX_VENDOR_LENGTH = 256
MAX_DEVICE_TYPE_LENGTH = 64
MAX_DEVICE_ROLE_LENGTH = 32
MAX_SITE_FIELD_LENGTH = 512
MAX_SITE_NOTES_LENGTH = 4_096
MAX_SITE_TYPE_LENGTH = 32
DEFAULT_VENDOR = "Other"
DEFAULT_DEVICE_TYPE = "generic"
DEFAULT_DEVICE_ROLE = "generic"
DEFAULT_SSH_PORT = 22
DEFAULT_SITE_TYPE = "enterprise"
SUPPORTED_DEVICE_TYPES = frozenset(
    {
        "aruba_os",
        "cisco_ios",
        "cisco_wlc",
        "fortinet",
        "generic",
        "paloalto_panos",
        "ubiquiti_unifi_os",
    }
)
SUPPORTED_DEVICE_ROLES = frozenset(
    {
        "controller",
        "firewall",
        "gateway",
        "generic",
        "router",
        "server",
        "switch",
        "wireless",
    }
)
SUPPORTED_SITE_TYPES = frozenset({"datacenter", "enterprise"})
NODES_KEY = "_nodes"
INVENTORY_SCHEMA_VERSION = 4
LEGACY_INVENTORY_SCHEMA_VERSIONS = frozenset({2, 3})

DeviceMapping: TypeAlias = Mapping[str, Any]
SiteMapping: TypeAlias = Mapping[str, Any]
TreeDict: TypeAlias = dict[str, Any]
DevicePath: TypeAlias = tuple[str, ...]
SitePath: TypeAlias = tuple[str, ...]


def new_device_id() -> str:
    """Return a new opaque device identifier suitable for persistence."""

    return uuid4().hex


def _validate_max_label_length(value: Any) -> int:
    """Return a supported caller-supplied label cap."""

    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_LABEL_LENGTH:
        raise ValueError(f"max_label_length must be an integer between 1 and {MAX_LABEL_LENGTH}.")
    return value


def _normalize_safe_text(
    value: str,
    *,
    field_name: str,
    owner: str,
    allowed_controls: frozenset[str] = frozenset(),
) -> str:
    """Return NFC text after rejecting unsafe control and surrogate codepoints.

    Imported inventory strings are displayed, compared, and later written to
    logs.  Unicode format characters (category ``Cf``) include bidi overrides
    and isolates as well as invisible zero-width characters; accepting them
    would make labels visually ambiguous.  Control characters (``Cc``) are
    rejected too, except for the explicitly allowed line controls in notes.
    Surrogate codepoints (``Cs``) are never valid standalone Unicode scalar
    values and would make later UTF-8 persistence fail, so they are rejected.

    Rejection happens on the original value and again after normalization.  A
    caller therefore cannot hide a forbidden character at an edge where
    ``str.strip`` would otherwise remove it, and all collision checks operate
    on the same NFC representation.
    """

    rejected_categories = {"Cc", "Cf", "Cs"}
    for character in value:
        if (
            character not in allowed_controls
            and unicodedata.category(character) in rejected_categories
        ):
            raise ValueError(
                f"{owner} {field_name} may not contain control characters, surrogate "
                "codepoints, or Unicode format characters."
            )
    normalized = unicodedata.normalize("NFC", value)
    for character in normalized:
        if (
            character not in allowed_controls
            and unicodedata.category(character) in rejected_categories
        ):
            raise ValueError(
                f"{owner} {field_name} may not contain control characters, surrogate "
                "codepoints, or Unicode format characters."
            )
    return normalized


def sanitize_label(
    value: Any,
    *,
    field_name: str = "label",
    max_length: int | None = MAX_LABEL_LENGTH,
) -> str:
    """Validate and normalize a user-visible label-like string."""

    if not isinstance(value, str):
        raise ValueError(f"Device {field_name} must be a string.")
    clean = _normalize_safe_text(value, field_name=field_name, owner="Device").strip()
    if not clean:
        raise ValueError(f"Device {field_name} may not be empty.")
    if max_length is not None and len(clean) > max_length:
        raise ValueError(f"Device {field_name} exceeds the maximum length of {max_length}.")
    return clean


def _sanitize_text(
    value: Any,
    *,
    field_name: str,
    default: str,
    max_length: int,
) -> str:
    if value is None:
        value = default
    if not isinstance(value, str):
        raise ValueError(f"Device {field_name} must be a string.")
    clean = _normalize_safe_text(value, field_name=field_name, owner="Device").strip()
    if not clean:
        if not isinstance(default, str):
            raise ValueError(f"Device {field_name} default must be a string.")
        clean = _normalize_safe_text(default, field_name=field_name, owner="Device").strip()
    if not clean:
        raise ValueError(f"Device {field_name} may not be empty.")
    if len(clean) > max_length:
        raise ValueError(f"Device {field_name} exceeds the maximum length of {max_length}.")
    return clean


def validate_device_type(value: Any, *, default: str = DEFAULT_DEVICE_TYPE) -> str:
    """Return a supported SSH transport-profile identifier.

    Inventory files are untrusted input.  Restricting the value to the device
    families exposed by the UI prevents an imported ``*_telnet`` or serial
    profile from silently changing the transport used for automation. Most
    identifiers select pinned Netmiko SSH drivers; dedicated profiles may use
    a narrower application-owned SSH transport instead.
    """

    clean = _sanitize_text(
        value,
        field_name="device_type",
        default=default,
        max_length=MAX_DEVICE_TYPE_LENGTH,
    )
    if clean not in SUPPORTED_DEVICE_TYPES:
        supported = ", ".join(sorted(SUPPORTED_DEVICE_TYPES))
        raise ValueError(f"Unsupported device_type {clean!r}; expected one of: {supported}.")
    return clean


def validate_device_role(value: Any) -> str:
    """Return an exact supported visual inventory role.

    A device role controls only inventory presentation. It is deliberately
    independent from the Netmiko device_type used for transport and policy.
    Roles are stable persistence identifiers, so whitespace and case variants
    are rejected rather than silently canonicalized.
    """

    if not isinstance(value, str):
        raise ValueError("Device device_role must be a string.")
    clean = _normalize_safe_text(
        value,
        field_name="device_role",
        owner="Device",
    )
    if not clean:
        raise ValueError("Device device_role may not be empty.")
    if len(clean) > MAX_DEVICE_ROLE_LENGTH:
        raise ValueError(
            f"Device device_role exceeds the maximum length of {MAX_DEVICE_ROLE_LENGTH}."
        )
    if clean not in SUPPORTED_DEVICE_ROLES:
        supported = ", ".join(sorted(SUPPORTED_DEVICE_ROLES))
        raise ValueError(f"Unsupported device_role {clean!r}; expected one of: {supported}.")
    return clean


def infer_legacy_device_role(vendor: str, device_type: str) -> str:
    """Infer the historical icon role when an old record lacks device_role."""

    vendor_roles = {
        "Cisco Router": "router",
        "Cisco Switch": "switch",
        "Cisco WLC": "wireless",
        "Fortinet": "firewall",
        "Aruba": "switch",
        "Palo Alto": "firewall",
        "Ubiquiti UniFi OS (Live CLI only)": "gateway",
        "Ubiquiti Dream Machine / UniFi OS": "gateway",
    }
    if vendor in vendor_roles:
        return vendor_roles[vendor]
    return {
        "cisco_wlc": "wireless",
        "fortinet": "firewall",
        "aruba_os": "switch",
        "paloalto_panos": "firewall",
        "ubiquiti_unifi_os": "gateway",
    }.get(device_type, DEFAULT_DEVICE_ROLE)


def _validate_port(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("Device port must be an integer between 1 and 65535.")

    if isinstance(value, int):
        port = value
    elif isinstance(value, str):
        clean = value.strip()
        if not clean or not clean.isdecimal():
            raise ValueError("Device port must be an integer between 1 and 65535.")
        port = int(clean, 10)
    else:
        raise ValueError("Device port must be an integer between 1 and 65535.")

    if not 1 <= port <= 65_535:
        raise ValueError("Device port must be an integer between 1 and 65535.")
    return port


def _sanitize_site_text(
    value: Any,
    *,
    field_name: str,
    max_length: int,
    required: bool = False,
    multiline: bool = False,
) -> str:
    """Validate a site field without imposing locale-specific formats."""

    if value is None and not required:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"Site {field_name} must be a string.")
    allowed_controls = frozenset({"\r", "\n", "\t"}) if multiline else frozenset()
    clean = _normalize_safe_text(
        value,
        field_name=field_name,
        owner="Site",
        allowed_controls=allowed_controls,
    )
    clean = clean.replace("\r\n", "\n").replace("\r", "\n") if multiline else clean
    clean = clean.strip()
    if required and not clean:
        raise ValueError(f"Site {field_name} may not be empty.")
    if len(clean) > max_length:
        raise ValueError(f"Site {field_name} exceeds the maximum length of {max_length}.")

    return clean


def validate_site_type(value: Any) -> str:
    """Return an exact supported site classification.

    Site types are stable persistence identifiers rather than display text, so
    they are intentionally not stripped, normalized, or case-folded.  Failing
    closed prevents an imported typo from silently selecting the wrong site
    behavior or icon.
    """

    if not isinstance(value, str):
        raise ValueError("Site site_type must be a string.")
    if len(value) > MAX_SITE_TYPE_LENGTH:
        raise ValueError(f"Site site_type exceeds the maximum length of {MAX_SITE_TYPE_LENGTH}.")
    if value not in SUPPORTED_SITE_TYPES:
        supported = ", ".join(sorted(SUPPORTED_SITE_TYPES))
        raise ValueError(f"Unsupported site_type {value!r}; expected one of: {supported}.")
    return value


@dataclass(frozen=True, slots=True)
class SiteRecord:
    """Canonical descriptive metadata for one inventory folder."""

    name: str
    address: str = ""
    city: str = ""
    region: str = ""
    postal_code: str = ""
    country: str = ""
    notes: str = ""
    site_type: str = DEFAULT_SITE_TYPE

    def __post_init__(self) -> None:
        clean_name = _sanitize_site_text(
            self.name,
            field_name="name",
            max_length=MAX_LABEL_LENGTH,
            required=True,
        )
        clean_fields = {
            field_name: _sanitize_site_text(
                getattr(self, field_name),
                field_name=field_name,
                max_length=MAX_SITE_FIELD_LENGTH,
            )
            for field_name in ("address", "city", "region", "postal_code", "country")
        }
        clean_notes = _sanitize_site_text(
            self.notes,
            field_name="notes",
            max_length=MAX_SITE_NOTES_LENGTH,
            multiline=True,
        )
        clean_site_type = validate_site_type(self.site_type)

        object.__setattr__(self, "name", clean_name)
        for field_name, clean_value in clean_fields.items():
            object.__setattr__(self, field_name, clean_value)
        object.__setattr__(self, "notes", clean_notes)
        object.__setattr__(self, "site_type", clean_site_type)

    @classmethod
    def from_mapping(cls, value: SiteMapping) -> SiteRecord:
        """Create validated site metadata from its persistent representation."""

        if not isinstance(value, Mapping):
            raise ValueError("A site entry must be a mapping.")
        return cls(
            name=value.get("name"),
            address=value.get("address", ""),
            city=value.get("city", ""),
            region=value.get("region", ""),
            postal_code=value.get("postal_code", ""),
            country=value.get("country", ""),
            notes=value.get("notes", ""),
            site_type=value.get("site_type", DEFAULT_SITE_TYPE),
        )

    def to_mapping(self) -> dict[str, str]:
        """Return every persistent field in JSON-compatible form."""

        return {
            "name": self.name,
            "site_type": self.site_type,
            "address": self.address,
            "city": self.city,
            "region": self.region,
            "postal_code": self.postal_code,
            "country": self.country,
            "notes": self.notes,
        }


@dataclass(frozen=True, slots=True)
class SitePlacement:
    """Attach site metadata to an existing folder path without changing the tree."""

    path: SitePath
    site: SiteRecord

    def __post_init__(self) -> None:
        if not isinstance(self.path, tuple) or not self.path:
            raise ValueError("Site path must be a non-empty tuple of folder labels.")
        if len(self.path) > MAX_DEVICE_TREE_DEPTH:
            raise ValueError("Site path exceeds the permitted tree depth.")
        clean_path = tuple(
            _sanitize_site_text(
                part,
                field_name="path segment",
                max_length=MAX_LABEL_LENGTH,
                required=True,
            )
            for part in self.path
        )
        if not isinstance(self.site, SiteRecord):
            raise ValueError("Site placement metadata must be a SiteRecord.")
        if self.site.name != clean_path[-1]:
            raise ValueError("Site name must match the final folder label in its path.")
        object.__setattr__(self, "path", clean_path)

    @classmethod
    def from_mapping(cls, value: SiteMapping) -> SitePlacement:
        """Read a flattened ``path`` plus site-fields persistence mapping."""

        if not isinstance(value, Mapping):
            raise ValueError("A site placement must be a mapping.")
        raw_path = value.get("path")
        if not isinstance(raw_path, (list, tuple)):
            raise ValueError("Site path must be a list of folder labels.")
        return cls(path=tuple(raw_path), site=SiteRecord.from_mapping(value))

    def to_mapping(self) -> dict[str, Any]:
        """Return the flattened JSON-compatible persistence representation."""

        return {"path": list(self.path), **self.site.to_mapping()}


@dataclass(frozen=True, slots=True)
class InventoryState:
    """Decoded inventory tree together with optional folder-site metadata."""

    tree: TreeDict
    sites: tuple[SitePlacement, ...] = ()


@dataclass(frozen=True, slots=True)
class DeviceRecord:
    """Canonical, serializable device data.

    The class is frozen so an ID cannot accidentally be changed after widgets
    or jobs start referring to it.  Legacy records acquire an ID on first load;
    serializing that record persists the ID for all subsequent loads.
    """

    label: str
    hostname: str
    vendor: str = DEFAULT_VENDOR
    device_type: str = DEFAULT_DEVICE_TYPE
    port: int = DEFAULT_SSH_PORT
    id: str = field(default_factory=new_device_id)
    device_role: str = DEFAULT_DEVICE_ROLE

    def __post_init__(self) -> None:
        clean_label = sanitize_label(self.label)
        clean_hostname = sanitize_label(self.hostname, field_name="hostname")
        clean_vendor = _sanitize_text(
            self.vendor,
            field_name="vendor",
            default=DEFAULT_VENDOR,
            max_length=MAX_VENDOR_LENGTH,
        )
        clean_device_type = validate_device_type(self.device_type)
        clean_device_role = validate_device_role(self.device_role)
        clean_port = _validate_port(self.port)
        clean_id = sanitize_label(self.id, field_name="id", max_length=256)

        object.__setattr__(self, "label", clean_label)
        object.__setattr__(self, "hostname", clean_hostname)
        object.__setattr__(self, "vendor", clean_vendor)
        object.__setattr__(self, "device_type", clean_device_type)
        object.__setattr__(self, "device_role", clean_device_role)
        object.__setattr__(self, "port", clean_port)
        object.__setattr__(self, "id", clean_id)

    @classmethod
    def from_mapping(
        cls,
        value: DeviceMapping,
        *,
        default_vendor: str = DEFAULT_VENDOR,
        default_device_type: str = DEFAULT_DEVICE_TYPE,
        default_port: int = DEFAULT_SSH_PORT,
        id_factory: Callable[[], str] = new_device_id,
        max_label_length: int = MAX_LABEL_LENGTH,
    ) -> DeviceRecord:
        """Create a record from current or legacy inventory data.

        Older Clidarvi files may contain only ``label`` and ``hostname`` (or
        just one of them), represent the port as a string, and have no ID.
        Those forms are intentionally accepted and upgraded here.

        ``max_label_length`` may only tighten the canonical cap:
        ``__post_init__`` always re-validates at :data:`MAX_LABEL_LENGTH`, so a
        larger or unlimited value would be silently ineffective and is rejected.
        """

        max_label_length = _validate_max_label_length(max_label_length)
        if not isinstance(value, Mapping):
            raise ValueError("A device entry must be a mapping.")

        raw_label = value.get("label") or value.get("hostname")
        raw_hostname = value.get("hostname") or raw_label
        label = sanitize_label(raw_label, max_length=max_label_length)
        hostname = sanitize_label(
            raw_hostname,
            field_name="hostname",
            max_length=max_label_length,
        )

        raw_id = value.get("id") or value.get("device_id")
        if raw_id is None:
            raw_id = id_factory()

        raw_port = value.get("port", default_port)
        if raw_port is None or raw_port == "":
            raw_port = default_port
        raw_vendor = _sanitize_text(
            value.get("vendor"),
            field_name="vendor",
            default=default_vendor,
            max_length=MAX_VENDOR_LENGTH,
        )
        raw_device_type = _sanitize_text(
            value.get("device_type"),
            field_name="device_type",
            default=default_device_type,
            max_length=MAX_DEVICE_TYPE_LENGTH,
        )
        if "device_role" in value:
            raw_device_role = validate_device_role(value["device_role"])
        else:
            raw_device_role = infer_legacy_device_role(raw_vendor, raw_device_type)

        return cls(
            id=raw_id,
            label=label,
            hostname=hostname,
            vendor=raw_vendor,
            device_type=raw_device_type,
            port=raw_port,
            device_role=raw_device_role,
        )

    def to_mapping(self) -> dict[str, Any]:
        """Return every persistent field in JSON-compatible form."""

        return {
            "id": self.id,
            "label": self.label,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "device_type": self.device_type,
            "port": self.port,
            "device_role": self.device_role,
        }


def _device_from_entry(
    entry: Any,
    *,
    default_vendor: str,
    default_device_type: str,
    default_port: int,
    id_factory: Callable[[], str],
    max_label_length: int,
) -> DeviceRecord:
    if isinstance(entry, DeviceRecord):
        # Frozen records are canonical at the global cap, but a caller may
        # deliberately select a stricter cap for an import operation.
        sanitize_label(entry.label, max_length=max_label_length)
        sanitize_label(
            entry.hostname,
            field_name="hostname",
            max_length=max_label_length,
        )
        return entry
    if isinstance(entry, str):
        entry = {"label": entry, "hostname": entry}
    if not isinstance(entry, Mapping):
        raise ValueError("Unsupported device entry in inventory data.")
    return DeviceRecord.from_mapping(
        entry,
        default_vendor=default_vendor,
        default_device_type=default_device_type,
        default_port=default_port,
        id_factory=id_factory,
        max_label_length=max_label_length,
    )


def sanitize_tree_dict(
    data: Mapping[str, Any],
    *,
    max_depth: int | None = MAX_DEVICE_TREE_DEPTH,
    max_items: int | None = MAX_DEVICE_TREE_NODES,
    max_label_length: int = MAX_LABEL_LENGTH,
    default_vendor: str = DEFAULT_VENDOR,
    default_device_type: str = DEFAULT_DEVICE_TYPE,
    default_port: int = DEFAULT_SSH_PORT,
    id_factory: Callable[[], str] = new_device_id,
) -> TreeDict:
    """Return a validated canonical copy of an inventory tree.

    Device display labels do not need to be unique.  Stable IDs do: accepting
    duplicate IDs would make selector and merge behaviour ambiguous.
    ``max_items`` counts both folders and devices, matching the original GUI's
    import limit.
    """

    if not isinstance(data, Mapping):
        raise ValueError("Invalid tree structure: the root must be a mapping.")
    if max_depth is not None and max_depth < 0:
        raise ValueError("Maximum tree depth may not be negative.")
    if max_items is not None and max_items < 0:
        raise ValueError("Maximum tree size may not be negative.")
    max_label_length = _validate_max_label_length(max_label_length)

    item_count = 0
    seen_ids: set[str] = set()

    def add_item() -> None:
        nonlocal item_count
        item_count += 1
        if max_items is not None and item_count > max_items:
            raise ValueError("Device tree exceeds the maximum allowed size.")

    def recurse(branch: Mapping[str, Any], depth: int) -> TreeDict:
        if max_depth is not None and depth > max_depth:
            raise ValueError("Device tree depth exceeds the permitted limit.")
        if not isinstance(branch, Mapping):
            raise ValueError("Invalid tree structure: folders must be mappings.")

        clean_branch: TreeDict = {}
        if NODES_KEY in branch:
            raw_nodes = branch[NODES_KEY]
            if not isinstance(raw_nodes, list):
                raise ValueError("Device entries must be provided as a list.")
            clean_nodes: list[dict[str, Any]] = []
            for entry in raw_nodes:
                record = _device_from_entry(
                    entry,
                    default_vendor=default_vendor,
                    default_device_type=default_device_type,
                    default_port=default_port,
                    id_factory=id_factory,
                    max_label_length=max_label_length,
                )
                if record.id in seen_ids:
                    raise ValueError(f"Duplicate device id encountered: {record.id}")
                seen_ids.add(record.id)
                clean_nodes.append(record.to_mapping())
                add_item()
            if clean_nodes:
                clean_branch[NODES_KEY] = clean_nodes

        for raw_folder_name, raw_subtree in branch.items():
            if raw_folder_name == NODES_KEY:
                continue
            folder_name = sanitize_label(
                raw_folder_name,
                field_name="folder label",
                max_length=max_label_length,
            )
            if folder_name == NODES_KEY:
                raise ValueError(f"{NODES_KEY!r} is reserved for device entries.")
            if folder_name in clean_branch:
                raise ValueError(f"Duplicate folder label encountered: {folder_name}")
            add_item()
            clean_branch[folder_name] = recurse(raw_subtree, depth + 1)
        return clean_branch

    return recurse(data, 0)


def _folder_paths(
    data: Mapping[str, Any],
    *,
    max_depth: int | None,
    max_label_length: int,
) -> set[SitePath]:
    """Return canonical folder paths without interpreting any folder as metadata."""

    paths: set[SitePath] = set()

    def recurse(branch: Mapping[str, Any], path: SitePath) -> None:
        if not isinstance(branch, Mapping):
            raise ValueError("Invalid tree structure: folders must be mappings.")
        raw_nodes = branch.get(NODES_KEY, [])
        if not isinstance(raw_nodes, list):
            raise ValueError("Device entries must be provided as a list.")

        sibling_names: set[str] = set()
        for raw_name, subtree in branch.items():
            if raw_name == NODES_KEY:
                continue
            name = sanitize_label(
                raw_name,
                field_name="folder label",
                max_length=max_label_length,
            )
            if name in sibling_names:
                raise ValueError(f"Duplicate folder label encountered: {name}")
            sibling_names.add(name)
            child_path = (*path, name)
            if max_depth is not None and len(child_path) > max_depth:
                raise ValueError("Device tree depth exceeds the permitted limit.")
            if not isinstance(subtree, Mapping):
                raise ValueError("Invalid tree structure: folders must be mappings.")
            paths.add(child_path)
            recurse(subtree, child_path)

    recurse(data, ())
    return paths


def sanitize_site_placements(
    tree: Mapping[str, Any],
    placements: Iterable[SitePlacement | SiteMapping],
    *,
    max_depth: int | None = MAX_DEVICE_TREE_DEPTH,
    max_items: int | None = MAX_DEVICE_TREE_NODES,
    max_label_length: int = MAX_LABEL_LENGTH,
) -> tuple[SitePlacement, ...]:
    """Validate unique site metadata attached to real folders in ``tree``.

    Site records are sidecar metadata, so ``max_items`` limits the number of
    records rather than adding them to the folder/device count.
    """

    if not isinstance(tree, Mapping):
        raise ValueError("Invalid tree structure: the root must be a mapping.")
    if isinstance(placements, (str, bytes, Mapping)) or not isinstance(placements, Iterable):
        raise ValueError("Site placements must be provided as an iterable of entries.")
    if max_depth is not None and max_depth < 0:
        raise ValueError("Maximum site path depth may not be negative.")
    if max_items is not None and max_items < 0:
        raise ValueError("Maximum site count may not be negative.")
    max_label_length = _validate_max_label_length(max_label_length)

    valid_paths = _folder_paths(
        tree,
        max_depth=max_depth,
        max_label_length=max_label_length,
    )
    clean: list[SitePlacement] = []
    seen_paths: set[SitePath] = set()
    for raw_placement in placements:
        placement = (
            raw_placement
            if isinstance(raw_placement, SitePlacement)
            else SitePlacement.from_mapping(raw_placement)
        )
        if max_depth is not None and len(placement.path) > max_depth:
            raise ValueError("Site path exceeds the permitted tree depth.")
        clean_path = tuple(
            sanitize_label(
                part,
                field_name="site path segment",
                max_length=max_label_length,
            )
            for part in placement.path
        )
        if clean_path != placement.path:
            placement = SitePlacement(path=clean_path, site=placement.site)
        if placement.path not in valid_paths:
            display_path = " / ".join(placement.path)
            raise ValueError(f"Site path does not reference an existing folder: {display_path}")
        if placement.path in seen_paths:
            display_path = " / ".join(placement.path)
            raise ValueError(f"Duplicate site placement encountered: {display_path}")
        seen_paths.add(placement.path)
        clean.append(placement)
        if max_items is not None and len(clean) > max_items:
            raise ValueError("Site metadata exceeds the maximum allowed size.")
    return tuple(clean)


def merge_site_placements(
    target: Iterable[SitePlacement | SiteMapping],
    source: Iterable[SitePlacement | SiteMapping],
    *,
    tree: Mapping[str, Any],
    max_depth: int | None = MAX_DEVICE_TREE_DEPTH,
    max_items: int | None = MAX_DEVICE_TREE_NODES,
    max_label_length: int = MAX_LABEL_LENGTH,
) -> tuple[SitePlacement, ...]:
    """Merge path-keyed site metadata without silently overwriting conflicts."""

    options = {
        "max_depth": max_depth,
        "max_items": max_items,
        "max_label_length": max_label_length,
    }
    clean_target = sanitize_site_placements(tree, target, **options)
    clean_source = sanitize_site_placements(tree, source, **options)
    merged = list(clean_target)
    existing_by_path = {placement.path: placement for placement in clean_target}

    for placement in clean_source:
        existing = existing_by_path.get(placement.path)
        if existing is not None:
            if existing != placement:
                display_path = " / ".join(placement.path)
                raise ValueError(
                    f"Conflicting site metadata for folder {display_path!r}; merge was aborted."
                )
            continue
        merged.append(placement)
        existing_by_path[placement.path] = placement

    return sanitize_site_placements(tree, merged, **options)


def encode_inventory_document(
    data: Mapping[str, Any],
    *,
    sites: Iterable[SitePlacement | SiteMapping] = (),
) -> dict[str, Any]:
    """Wrap a tree and its validated site sidecar in a v4 envelope."""

    # A versioned envelope is a canonical persistence format.  Canonicalizing
    # the tree first keeps site paths and the returned tree in the same label
    # namespace, and makes encode -> decode -> encode stable.
    clean_tree = sanitize_tree_dict(data)
    clean_sites = sanitize_site_placements(clean_tree, sites)
    return {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "tree": clean_tree,
        "sites": [placement.to_mapping() for placement in clean_sites],
    }


def _assert_within_depth(
    tree: Mapping[str, Any], max_depth: int = MAX_INVENTORY_NESTING_DEPTH
) -> None:
    """Reject untrusted structures nested past ``max_depth`` before any recursion.

    Legacy inventories are returned without canonicalization, so this iterative
    walk runs before ``deepcopy`` (itself recursive) to keep a hostile document
    from raising ``RecursionError`` on load.  Every container level counts —
    folder mappings, ``_nodes`` lists, and any nested list or mapping inside a
    device entry — because ``deepcopy`` recurses through all of them, not only
    the folder chain.  The bound is generous relative to any real inventory
    (folder depth is capped far lower downstream) and exists purely to stop a
    denial-of-service via stack exhaustion.
    """

    stack: list[tuple[Any, int]] = [(tree, 0)]
    deepest_seen: dict[int, int] = {}
    while stack:
        obj, depth = stack.pop()
        if depth > max_depth:
            raise ValueError("Device tree nesting depth exceeds the permitted limit.")
        previous_depth = deepest_seen.get(id(obj))
        if previous_depth is not None and previous_depth >= depth:
            continue
        deepest_seen[id(obj)] = depth
        if isinstance(obj, Mapping):
            children: Iterable[Any] = (child for item in obj.items() for child in item)
        elif isinstance(obj, (list, tuple)):
            children = obj
        else:
            continue
        for value in children:
            if isinstance(value, (Mapping, list, tuple)):
                stack.append((value, depth + 1))


def _legacy_inventory_state(tree: Mapping[str, Any]) -> InventoryState:
    _assert_within_depth(tree)
    return InventoryState(tree=deepcopy(dict(tree)))


def decode_inventory_state(document: Mapping[str, Any]) -> InventoryState:
    """Decode v4, v3, v2, or legacy unversioned inventory data."""

    if not isinstance(document, Mapping):
        raise ValueError("Inventory document must be a JSON object.")
    if "schema_version" not in document:
        return _legacy_inventory_state(document)

    version = document.get("schema_version")
    # Before the versioned envelope existed, every root key represented a
    # folder. Preserve a legacy folder literally named ``schema_version``.
    if isinstance(version, Mapping):
        return _legacy_inventory_state(document)
    if isinstance(version, bool) or not isinstance(version, int):
        raise ValueError(f"Unsupported inventory schema version {version!r}.")
    supported_versions = {INVENTORY_SCHEMA_VERSION, *LEGACY_INVENTORY_SCHEMA_VERSIONS}
    if version not in supported_versions:
        supported = ", ".join(str(value) for value in sorted(supported_versions))
        raise ValueError(
            f"Unsupported inventory schema version {version!r}; expected one of: {supported}."
        )
    tree = document.get("tree")
    if not isinstance(tree, Mapping):
        raise ValueError("Versioned inventory document is missing a valid tree.")
    if version == 2:
        return _legacy_inventory_state(tree)

    # Versions 3 and 4 use the site sidecar. Normalize at the boundary so
    # the tree and its normalized site paths cannot describe different keys.
    clean_tree = sanitize_tree_dict(tree)

    raw_sites = document.get("sites", [])
    if not isinstance(raw_sites, list):
        raise ValueError("Versioned inventory site metadata must be a list.")
    sites = sanitize_site_placements(clean_tree, raw_sites)
    return InventoryState(tree=clean_tree, sites=sites)


def decode_inventory_document(document: Mapping[str, Any]) -> TreeDict:
    """Extract only the tree, preserving the pre-v3 public helper contract.

    A v3/v4 document still passes full canonicalization and site validation first,
    even though the sites themselves are discarded here.
    """

    return deepcopy(decode_inventory_state(document).tree)


def count_tree_items(data: Mapping[str, Any]) -> int:
    """Count folders and devices in a raw or canonical tree."""

    if not isinstance(data, Mapping):
        raise ValueError("Invalid tree structure: folders must be mappings.")
    total = 0
    raw_nodes = data.get(NODES_KEY, [])
    if not isinstance(raw_nodes, list):
        raise ValueError("Device entries must be provided as a list.")
    total += len(raw_nodes)
    for key, subtree in data.items():
        if key == NODES_KEY:
            continue
        total += 1 + count_tree_items(subtree)
    return total


def count_devices(data: Mapping[str, Any]) -> int:
    """Count devices, excluding folders, in a tree."""

    return sum(1 for _path, _device in walk_devices(data))


def walk_devices(
    data: Mapping[str, Any],
    *,
    _path: DevicePath = (),
) -> Iterator[tuple[DevicePath, DeviceRecord]]:
    """Yield ``(folder_path, device)`` pairs at every tree depth."""

    if not isinstance(data, Mapping):
        raise ValueError("Invalid tree structure: folders must be mappings.")
    nodes = data.get(NODES_KEY, [])
    if not isinstance(nodes, list):
        raise ValueError("Device entries must be provided as a list.")
    for entry in nodes:
        yield (
            _path,
            _device_from_entry(
                entry,
                default_vendor=DEFAULT_VENDOR,
                default_device_type=DEFAULT_DEVICE_TYPE,
                default_port=DEFAULT_SSH_PORT,
                id_factory=new_device_id,
                max_label_length=MAX_LABEL_LENGTH,
            ),
        )
    for folder_name, subtree in data.items():
        if folder_name == NODES_KEY:
            continue
        clean_folder_name = sanitize_label(folder_name, field_name="folder label")
        yield from walk_devices(subtree, _path=(*_path, clean_folder_name))


def iter_devices(data: Mapping[str, Any]) -> Iterator[DeviceRecord]:
    """Yield devices without their folder paths."""

    for _path, device in walk_devices(data):
        yield device


def find_device(data: Mapping[str, Any], device_id: str) -> DeviceRecord | None:
    """Find a device by stable ID, regardless of nesting depth."""

    wanted_id = sanitize_label(device_id, field_name="id", max_length=256)
    for _path, device in walk_devices(data):
        if device.id == wanted_id:
            return device
    return None


def find_device_path(data: Mapping[str, Any], device_id: str) -> DevicePath | None:
    """Return the containing folder path for a stable device ID."""

    wanted_id = sanitize_label(device_id, field_name="id", max_length=256)
    for path, device in walk_devices(data):
        if device.id == wanted_id:
            return path
    return None


def find_devices_by_label(
    data: Mapping[str, Any], label: str
) -> list[tuple[DevicePath, DeviceRecord]]:
    """Return all label matches; duplicate display labels are valid."""

    wanted_label = sanitize_label(label)
    return [(path, device) for path, device in walk_devices(data) if device.label == wanted_label]


def merge_tree_dicts(
    target: Mapping[str, Any],
    source: Mapping[str, Any],
    *,
    max_depth: int | None = MAX_DEVICE_TREE_DEPTH,
    max_items: int | None = MAX_DEVICE_TREE_NODES,
    max_label_length: int = MAX_LABEL_LENGTH,
    default_vendor: str = DEFAULT_VENDOR,
    default_device_type: str = DEFAULT_DEVICE_TYPE,
    default_port: int = DEFAULT_SSH_PORT,
    id_factory: Callable[[], str] = new_device_id,
) -> TreeDict:
    """Return a recursive union of two trees, de-duplicated by device ID.

    Identical records with the same ID are de-duplicated; conflicting metadata
    for one ID aborts the merge. Devices with the same display label but
    different IDs are both retained. IDs are global across all folders.
    """

    sanitize_options = {
        "max_depth": max_depth,
        "max_items": max_items,
        "max_label_length": max_label_length,
        "default_vendor": default_vendor,
        "default_device_type": default_device_type,
        "default_port": default_port,
        "id_factory": id_factory,
    }
    clean_target = sanitize_tree_dict(target, **sanitize_options)
    clean_source = sanitize_tree_dict(source, **sanitize_options)
    merged = deepcopy(clean_target)
    existing_by_id = {device.id: device for device in iter_devices(merged)}

    def merge_branch(target_branch: TreeDict, source_branch: TreeDict) -> None:
        for raw_entry in source_branch.get(NODES_KEY, []):
            device = DeviceRecord.from_mapping(raw_entry)
            existing = existing_by_id.get(device.id)
            if existing is not None:
                if existing != device:
                    raise ValueError(
                        f"Conflicting metadata for device id {device.id!r}; merge was aborted."
                    )
                continue
            target_branch.setdefault(NODES_KEY, []).append(device.to_mapping())
            existing_by_id[device.id] = device

        for folder_name, source_subtree in source_branch.items():
            if folder_name == NODES_KEY:
                continue
            target_subtree = target_branch.setdefault(folder_name, {})
            merge_branch(target_subtree, source_subtree)

    merge_branch(merged, clean_source)
    if max_items is not None and count_tree_items(merged) > max_items:
        raise ValueError("Merged device tree exceeds the maximum allowed size.")
    return merged


# Short aliases make the public helpers pleasant to use while keeping names that
# mirror the GUI's existing methods available during migration.
sanitize_tree = sanitize_tree_dict
merge_trees = merge_tree_dicts
merge_tree_dict = merge_tree_dicts


__all__ = [
    "DEFAULT_DEVICE_ROLE",
    "DEFAULT_DEVICE_TYPE",
    "DEFAULT_SITE_TYPE",
    "DEFAULT_SSH_PORT",
    "DEFAULT_VENDOR",
    "DevicePath",
    "DeviceRecord",
    "INVENTORY_SCHEMA_VERSION",
    "InventoryState",
    "LEGACY_INVENTORY_SCHEMA_VERSIONS",
    "MAX_DEVICE_TREE_DEPTH",
    "MAX_DEVICE_TREE_NODES",
    "MAX_DEVICE_ROLE_LENGTH",
    "MAX_DEVICE_TYPE_LENGTH",
    "MAX_LABEL_LENGTH",
    "MAX_SITE_FIELD_LENGTH",
    "MAX_SITE_NOTES_LENGTH",
    "MAX_SITE_TYPE_LENGTH",
    "MAX_VENDOR_LENGTH",
    "NODES_KEY",
    "SiteMapping",
    "SitePath",
    "SitePlacement",
    "SiteRecord",
    "SUPPORTED_DEVICE_TYPES",
    "SUPPORTED_DEVICE_ROLES",
    "SUPPORTED_SITE_TYPES",
    "TreeDict",
    "count_devices",
    "count_tree_items",
    "decode_inventory_document",
    "decode_inventory_state",
    "encode_inventory_document",
    "find_device",
    "find_device_path",
    "find_devices_by_label",
    "infer_legacy_device_role",
    "iter_devices",
    "merge_tree_dict",
    "merge_tree_dicts",
    "merge_site_placements",
    "merge_trees",
    "new_device_id",
    "sanitize_label",
    "sanitize_site_placements",
    "sanitize_tree",
    "sanitize_tree_dict",
    "validate_device_role",
    "validate_device_type",
    "validate_site_type",
    "walk_devices",
]
