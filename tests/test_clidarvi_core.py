# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 devnetdreamer (https://github.com/devnetdreamer) and Clidarvi contributors

import unittest
from copy import deepcopy
from dataclasses import FrozenInstanceError
from unittest.mock import patch

from clidarvi_core import (
    DEFAULT_DEVICE_ROLE,
    DEFAULT_SITE_TYPE,
    MAX_DEVICE_ROLE_LENGTH,
    MAX_LABEL_LENGTH,
    MAX_SITE_FIELD_LENGTH,
    MAX_SITE_NOTES_LENGTH,
    MAX_SITE_TYPE_LENGTH,
    MAX_VENDOR_LENGTH,
    SUPPORTED_DEVICE_ROLES,
    SUPPORTED_DEVICE_TYPES,
    DeviceRecord,
    InventoryState,
    SitePlacement,
    SiteRecord,
    count_devices,
    count_tree_items,
    decode_inventory_document,
    decode_inventory_state,
    encode_inventory_document,
    find_device,
    find_device_path,
    find_devices_by_label,
    merge_site_placements,
    merge_tree_dicts,
    sanitize_site_placements,
    sanitize_tree_dict,
    validate_device_type,
    walk_devices,
)


class DeviceRecordTests(unittest.TestCase):
    def test_legacy_record_is_upgraded_with_defaults(self):
        record = DeviceRecord.from_mapping(
            {"hostname": "  switch-01.example.net  ", "port": "2222"},
            id_factory=lambda: "legacy-device-id",
        )

        self.assertEqual(record.id, "legacy-device-id")
        self.assertEqual(record.label, "switch-01.example.net")
        self.assertEqual(record.hostname, "switch-01.example.net")
        self.assertEqual(record.vendor, "Other")
        self.assertEqual(record.device_type, "generic")
        self.assertEqual(record.device_role, DEFAULT_DEVICE_ROLE)
        self.assertEqual(record.port, 2222)
        self.assertIsInstance(record.port, int)

    def test_metadata_round_trip_is_lossless(self):
        original = DeviceRecord(
            id="device-123",
            label="Core Example City",
            hostname="core-ams.example.net",
            vendor="Cisco Switch",
            device_type="cisco_ios",
            device_role="switch",
            port=2201,
        )

        serialized = original.to_mapping()

        self.assertEqual(DeviceRecord.from_mapping(serialized), original)
        self.assertEqual(
            serialized,
            {
                "id": "device-123",
                "label": "Core Example City",
                "hostname": "core-ams.example.net",
                "vendor": "Cisco Switch",
                "device_type": "cisco_ios",
                "port": 2201,
                "device_role": "switch",
            },
        )
        with self.assertRaises(FrozenInstanceError):
            original.port = 22

    def test_unifi_os_profile_is_distinct_supported_and_not_inferred_from_presentation(self):
        profile = "ubiquiti_unifi_os"
        self.assertIn(profile, SUPPORTED_DEVICE_TYPES)
        self.assertEqual(validate_device_type(profile), profile)
        self.assertNotEqual(profile, "generic")

        record = DeviceRecord(
            id="udm-se",
            label="Dream Machine SE",
            hostname="udm-se.example.net",
            vendor="Ubiquiti Dream Machine / UniFi OS",
            device_type=profile,
            device_role="gateway",
        )
        self.assertEqual(DeviceRecord.from_mapping(record.to_mapping()), record)

        # Vendor text and the visual role are presentation metadata. Neither
        # may silently promote an imported/default record into the dedicated
        # UDM Automation profile.
        presentation_only = DeviceRecord.from_mapping(
            {
                "id": "udm-presentation-only",
                "label": "Dream Machine-looking device",
                "hostname": "generic.example.net",
                "vendor": "Ubiquiti Dream Machine / UniFi OS",
                "device_role": "gateway",
            }
        )
        self.assertEqual(presentation_only.device_type, "generic")
        self.assertEqual(presentation_only.device_role, "gateway")

    def test_invalid_ports_are_rejected(self):
        for invalid_port in (0, 65_536, -1, True, 22.5, "22.5", "", "ssh"):
            with self.subTest(port=invalid_port):
                with self.assertRaises(ValueError):
                    DeviceRecord(
                        id="device-1",
                        label="switch",
                        hostname="switch.example.net",
                        port=invalid_port,
                    )

    def test_invalid_labels_are_rejected(self):
        for invalid_label in ("", "   ", "bad\nlabel", "x" * 257, None):
            with self.subTest(label=invalid_label):
                with self.assertRaises(ValueError):
                    DeviceRecord(
                        id="device-1",
                        label=invalid_label,
                        hostname="switch.example.net",
                    )

    def test_c1_control_characters_are_rejected(self):
        for invalid in (
            "bad\x85label",
            "name\x9cend",
            "next\x80line",
            "\x85leading",
            "trailing\x85",
        ):
            with self.subTest(value=invalid):
                with self.assertRaisesRegex(ValueError, "control characters"):
                    DeviceRecord(id="device-1", label=invalid, hostname="switch.example.net")
                with self.assertRaisesRegex(ValueError, "control characters"):
                    DeviceRecord(id="device-1", label="switch", hostname=invalid)
                with self.assertRaisesRegex(ValueError, "control characters"):
                    DeviceRecord(
                        id="device-1",
                        label="switch",
                        hostname="switch.example.net",
                        vendor=invalid,
                    )
        with self.assertRaisesRegex(ValueError, "control characters"):
            sanitize_tree_dict({"\x85bad-folder": {}})
        with self.assertRaisesRegex(ValueError, "control characters"):
            SiteRecord(name="Site", city="Sample City\x85")

    def test_unicode_is_nfc_normalized_before_identity_and_folder_collisions(self):
        composed = "Caf\N{LATIN SMALL LETTER E WITH ACUTE}"
        decomposed = "Cafe\N{COMBINING ACUTE ACCENT}"
        record = DeviceRecord(
            id=decomposed,
            label=decomposed,
            hostname=f"{decomposed}.example.net",
            vendor=decomposed,
        )

        self.assertEqual(record.id, composed)
        self.assertEqual(record.label, composed)
        self.assertEqual(record.hostname, f"{composed}.example.net")
        self.assertEqual(record.vendor, composed)
        self.assertEqual(SiteRecord(name=decomposed).name, composed)

        normalized_site = sanitize_site_placements(
            {composed: {}},
            [{"path": [decomposed], "name": decomposed}],
        )
        self.assertEqual(normalized_site[0].path, (composed,))
        with self.assertRaisesRegex(ValueError, "Duplicate site placement"):
            sanitize_site_placements(
                {composed: {}},
                [
                    {"path": [composed], "name": composed},
                    {"path": [decomposed], "name": decomposed},
                ],
            )

        with self.assertRaisesRegex(ValueError, "Duplicate folder label"):
            sanitize_tree_dict({composed: {}, decomposed: {}})
        with self.assertRaisesRegex(ValueError, "Duplicate device id"):
            sanitize_tree_dict(
                {
                    "_nodes": [
                        {"id": composed, "label": "one", "hostname": "one"},
                        {"id": decomposed, "label": "two", "hostname": "two"},
                    ]
                }
            )

    def test_unicode_format_and_bidi_controls_are_rejected_in_all_text_families(self):
        for dangerous in ("\u200b", "\u202e", "\u2066", "\u2069", "\u00ad"):
            value = f"safe{dangerous}text"
            with self.subTest(codepoint=f"U+{ord(dangerous):04X}"):
                for field_name in (
                    "label",
                    "hostname",
                    "vendor",
                    "device_type",
                    "device_role",
                    "id",
                ):
                    kwargs = {
                        "id": "device-1",
                        "label": "switch",
                        "hostname": "switch.example.net",
                        "vendor": "Other",
                        "device_type": "generic",
                        "device_role": "generic",
                    }
                    kwargs[field_name] = value
                    with self.assertRaisesRegex(ValueError, "format characters"):
                        DeviceRecord(**kwargs)
                with self.assertRaisesRegex(ValueError, "format characters"):
                    sanitize_tree_dict({value: {}})
                with self.assertRaisesRegex(ValueError, "format characters"):
                    SiteRecord(name="Site", notes=value)

    def test_lone_unicode_surrogates_are_rejected_in_all_text_families(self):
        for dangerous in ("\ud800", "\udfff"):
            value = f"safe{dangerous}text"
            with self.subTest(codepoint=f"U+{ord(dangerous):04X}"):
                for field_name in (
                    "label",
                    "hostname",
                    "vendor",
                    "device_type",
                    "device_role",
                    "id",
                ):
                    kwargs = {
                        "id": "device-1",
                        "label": "switch",
                        "hostname": "switch.example.net",
                        "vendor": "Other",
                        "device_type": "generic",
                        "device_role": "generic",
                    }
                    kwargs[field_name] = value
                    with self.assertRaisesRegex(ValueError, "surrogate codepoints"):
                        DeviceRecord(**kwargs)
                with self.assertRaisesRegex(ValueError, "surrogate codepoints"):
                    sanitize_tree_dict({value: {}})
                with self.assertRaisesRegex(ValueError, "surrogate codepoints"):
                    SiteRecord(name="Site", notes=value)

    def test_every_persistent_device_text_field_is_bounded(self):
        for field_name in ("label", "hostname", "id"):
            kwargs = {
                "id": "device-1",
                "label": "switch",
                "hostname": "switch.example.net",
            }
            kwargs[field_name] = "x" * (MAX_LABEL_LENGTH + 1)
            with self.subTest(field=field_name):
                with self.assertRaisesRegex(ValueError, "maximum length"):
                    DeviceRecord(**kwargs)

        with self.assertRaisesRegex(ValueError, "maximum length"):
            DeviceRecord(
                id="device-1",
                label="switch",
                hostname="switch.example.net",
                vendor="x" * (MAX_VENDOR_LENGTH + 1),
            )
        with self.assertRaisesRegex(ValueError, "maximum length"):
            DeviceRecord.from_mapping(
                {"label": "switch", "hostname": "switch.example.net"},
                default_vendor="x" * (MAX_VENDOR_LENGTH + 1),
            )
        with self.assertRaisesRegex(ValueError, "maximum length"):
            DeviceRecord(
                id="device-1",
                label="switch",
                hostname="switch.example.net",
                device_role="x" * (MAX_DEVICE_ROLE_LENGTH + 1),
            )

    def test_device_role_is_an_exact_bounded_persistence_identifier(self):
        expected_roles = frozenset(
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
        self.assertEqual(SUPPORTED_DEVICE_ROLES, expected_roles)

        for role in sorted(expected_roles):
            with self.subTest(role=role):
                record = DeviceRecord(
                    id=f"role-{role}",
                    label=role,
                    hostname=f"{role}.example.net",
                    device_role=role,
                )
                self.assertEqual(record.device_role, role)
                self.assertEqual(record.to_mapping()["device_role"], role)
                self.assertEqual(DeviceRecord.from_mapping(record.to_mapping()), record)

        for invalid in (None, True, 1, [], "", "Router", " router", "router "):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    DeviceRecord(
                        id="invalid-role",
                        label="device",
                        hostname="device.example.net",
                        device_role=invalid,
                    )

    def test_missing_legacy_role_is_inferred_once_and_explicit_role_wins(self):
        cases = (
            ("Cisco Router", "cisco_ios", "router"),
            ("Cisco Switch", "cisco_ios", "switch"),
            ("Cisco WLC", "cisco_wlc", "wireless"),
            ("Fortinet", "fortinet", "firewall"),
            ("Aruba", "aruba_os", "switch"),
            ("Palo Alto", "paloalto_panos", "firewall"),
            # Historical fallback applied only after no exact vendor match.
            ("Other", "cisco_wlc", "wireless"),
            ("Other", "fortinet", "firewall"),
            ("Other", "aruba_os", "switch"),
            ("Other", "paloalto_panos", "firewall"),
            ("Other", "cisco_ios", "generic"),
            ("Ubiquiti UniFi OS (Live CLI only)", "generic", "gateway"),
            ("Ubiquiti Dream Machine / UniFi OS", "generic", "gateway"),
        )
        for vendor, device_type, expected in cases:
            with self.subTest(vendor=vendor, device_type=device_type):
                record = DeviceRecord.from_mapping(
                    {
                        "id": f"legacy-{vendor}-{device_type}",
                        "label": "Legacy device",
                        "hostname": "legacy.example.net",
                        "vendor": vendor,
                        "device_type": device_type,
                    }
                )
                self.assertEqual(record.device_role, expected)
                self.assertEqual(record.to_mapping()["device_role"], expected)

        # A direct/current record is never silently inferred, while an explicit
        # persisted role always overrides the legacy vendor/platform mapping.
        self.assertEqual(
            DeviceRecord(
                id="current-router",
                label="Router",
                hostname="router.example.net",
                vendor="Cisco Router",
                device_type="cisco_ios",
            ).device_role,
            "generic",
        )
        explicit = DeviceRecord.from_mapping(
            {
                "id": "explicit-server",
                "label": "Controller host",
                "hostname": "controller.example.net",
                "vendor": "Cisco WLC",
                "device_type": "cisco_wlc",
                "device_role": "server",
            }
        )
        self.assertEqual(explicit.device_role, "server")
        explicit_generic = DeviceRecord.from_mapping(
            {
                "id": "explicit-generic-udm",
                "label": "Explicit generic appliance",
                "hostname": "generic-udm.example.net",
                "vendor": "Ubiquiti Dream Machine / UniFi OS",
                "device_type": "ubiquiti_unifi_os",
                "device_role": "generic",
            }
        )
        self.assertEqual(explicit_generic.device_role, "generic")
        with self.assertRaisesRegex(ValueError, "device_role"):
            DeviceRecord.from_mapping(
                {
                    "label": "Invalid explicit role",
                    "hostname": "invalid.example.net",
                    "device_role": None,
                }
            )

    def test_legacy_role_is_canonicalized_and_persists_through_inventory_round_trip(self):
        legacy_tree = {
            "_nodes": [
                {
                    "id": "legacy-router",
                    "label": "WAN router",
                    "hostname": "wan.example.net",
                    "vendor": "Cisco Router",
                    "device_type": "cisco_ios",
                }
            ]
        }

        clean = sanitize_tree_dict(legacy_tree)
        self.assertEqual(clean["_nodes"][0]["device_role"], "router")
        document = encode_inventory_document(clean)
        decoded = decode_inventory_state(document)
        self.assertEqual(find_device(decoded.tree, "legacy-router").device_role, "router")
        self.assertEqual(
            encode_inventory_document(decoded.tree),
            document,
        )

    def test_label_length_parameter_must_be_within_the_canonical_range(self):
        entry = {"label": "switch", "hostname": "switch.example.net"}
        invalid_values = (None, 0, -1, MAX_LABEL_LENGTH + 1, 10_000, True, 1.5, "64")
        for invalid in invalid_values:
            with self.subTest(max_label_length=invalid):
                with self.assertRaisesRegex(ValueError, "max_label_length"):
                    DeviceRecord.from_mapping(entry, max_label_length=invalid)
                with self.assertRaisesRegex(ValueError, "max_label_length"):
                    sanitize_tree_dict({}, max_label_length=invalid)
                with self.assertRaisesRegex(ValueError, "max_label_length"):
                    sanitize_site_placements({}, [], max_label_length=invalid)
                with self.assertRaisesRegex(ValueError, "max_label_length"):
                    merge_site_placements([], [], tree={}, max_label_length=invalid)
                with self.assertRaisesRegex(ValueError, "max_label_length"):
                    merge_tree_dicts({}, {}, max_label_length=invalid)

        self.assertEqual(
            DeviceRecord.from_mapping(entry, max_label_length=64).label,
            "switch",
        )

    def test_stricter_label_cap_covers_folders_and_prebuilt_records(self):
        record = DeviceRecord(id="device-1", label="switch", hostname="sw.example.net")

        with self.assertRaisesRegex(ValueError, "maximum length of 3"):
            sanitize_tree_dict({"wide": {}}, max_label_length=3)
        with self.assertRaisesRegex(ValueError, "maximum length of 3"):
            sanitize_tree_dict({"_nodes": [record]}, max_label_length=3)

        self.assertEqual(sanitize_tree_dict({"abc": {}}, max_label_length=3), {"abc": {}})

    def test_non_ssh_or_unsupported_device_types_are_rejected(self):
        for device_type in ("cisco_ios_telnet", "generic_termserver_telnet", "cisco_serial"):
            with self.subTest(device_type=device_type):
                with self.assertRaisesRegex(ValueError, "Unsupported device_type"):
                    DeviceRecord(
                        id="device-1",
                        label="switch",
                        hostname="switch.example.net",
                        device_type=device_type,
                    )


class SiteRecordTests(unittest.TestCase):
    def test_site_record_and_placement_round_trip_is_lossless(self):
        site = SiteRecord(
            name="  Example City DC  ",
            address=" 1 Example Avenue ",
            city=" Example City ",
            region=" Example Region ",
            postal_code=" 0000 XX ",
            country=" Exampleland ",
            notes=" First line\r\nSecond line ",
            site_type="datacenter",
        )
        placement = SitePlacement(path=("Exampleland", "Example City DC"), site=site)

        self.assertEqual(site.name, "Example City DC")
        self.assertEqual(site.notes, "First line\nSecond line")
        self.assertEqual(SiteRecord.from_mapping(site.to_mapping()), site)
        self.assertEqual(SitePlacement.from_mapping(placement.to_mapping()), placement)
        self.assertEqual(
            placement.to_mapping(),
            {
                "path": ["Exampleland", "Example City DC"],
                "name": "Example City DC",
                "site_type": "datacenter",
                "address": "1 Example Avenue",
                "city": "Example City",
                "region": "Example Region",
                "postal_code": "0000 XX",
                "country": "Exampleland",
                "notes": "First line\nSecond line",
            },
        )
        with self.assertRaises(FrozenInstanceError):
            site.city = "Sample City"
        with self.assertRaises(FrozenInstanceError):
            placement.path = ("Sample City",)

    def test_site_type_is_exact_bounded_and_fail_closed(self):
        self.assertEqual(SiteRecord(name="Branch").site_type, DEFAULT_SITE_TYPE)
        self.assertEqual(
            SiteRecord.from_mapping({"name": "Legacy branch"}).site_type,
            "enterprise",
        )
        for site_type in ("enterprise", "datacenter"):
            with self.subTest(site_type=site_type):
                self.assertEqual(
                    SiteRecord(name="Site", site_type=site_type).site_type,
                    site_type,
                )

        for invalid in (None, True, 1, [], "", "Datacenter", " enterprise", "datacenter "):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    SiteRecord(name="Site", site_type=invalid)
        with self.assertRaisesRegex(ValueError, "maximum length"):
            SiteRecord(name="Site", site_type="x" * (MAX_SITE_TYPE_LENGTH + 1))

    def test_datacenter_site_type_survives_schema_and_merge_round_trips(self):
        tree = {"Example City DC": {}}
        placement = SitePlacement(
            path=("Example City DC",),
            site=SiteRecord(name="Example City DC", site_type="datacenter"),
        )

        document = encode_inventory_document(tree, sites=(placement,))
        state = decode_inventory_state(document)
        merged = merge_site_placements([], state.sites, tree=state.tree)

        self.assertEqual(document["schema_version"], 4)
        self.assertEqual(document["sites"][0]["site_type"], "datacenter")
        self.assertEqual(state.sites, (placement,))
        self.assertEqual(merged, (placement,))
        self.assertEqual(SitePlacement.from_mapping(placement.to_mapping()), placement)

        # Existing v3 documents did not contain site_type.  They remain valid
        # and acquire the canonical enterprise default when next serialized.
        legacy_v3 = {
            "schema_version": 3,
            "tree": {"Branch": {}},
            "sites": [{"path": ["Branch"], "name": "Branch"}],
        }
        legacy_state = decode_inventory_state(legacy_v3)
        self.assertEqual(legacy_state.sites[0].site.site_type, "enterprise")
        self.assertEqual(
            encode_inventory_document(legacy_state.tree, sites=legacy_state.sites)["sites"][0][
                "site_type"
            ],
            "enterprise",
        )

    def test_site_record_rejects_invalid_or_oversized_fields(self):
        for kwargs in (
            {"name": ""},
            {"name": "Site", "city": "bad\ncity"},
            {"name": "Site", "notes": "x" * (MAX_SITE_NOTES_LENGTH + 1)},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    SiteRecord(**kwargs)

        with self.assertRaisesRegex(ValueError, "must match"):
            SitePlacement(path=("Folder",), site=SiteRecord(name="Different"))

    def test_every_persistent_site_text_field_is_bounded(self):
        with self.assertRaisesRegex(ValueError, "maximum length"):
            SiteRecord(name="x" * (MAX_LABEL_LENGTH + 1))
        for field_name in ("address", "city", "region", "postal_code", "country"):
            with self.subTest(field=field_name):
                with self.assertRaisesRegex(ValueError, "maximum length"):
                    SiteRecord(name="Site", **{field_name: "x" * (MAX_SITE_FIELD_LENGTH + 1)})
        with self.assertRaisesRegex(ValueError, "maximum length"):
            SiteRecord(name="Site", notes="x" * (MAX_SITE_NOTES_LENGTH + 1))


class TreeHelperTests(unittest.TestCase):
    def test_reserved_nodes_key_cannot_be_used_as_a_folder(self):
        with self.assertRaisesRegex(ValueError, "Device entries must be provided as a list"):
            sanitize_tree_dict({"_nodes": {}})

    def test_site_like_folder_name_remains_valid_and_counted_normally(self):
        tree = {
            "_site": {"_nodes": [{"id": "inside-site-folder", "label": "R1", "hostname": "r1"}]}
        }

        clean = sanitize_tree_dict(tree)

        self.assertIn("_site", clean)
        self.assertEqual(count_tree_items(clean), 2)
        self.assertEqual(find_device_path(clean, "inside-site-folder"), ("_site",))

    def test_versioned_document_round_trip_and_legacy_support(self):
        tree = {"_site": {"_nodes": [{"id": "r1", "label": "R1", "hostname": "r1"}]}}
        placement = SitePlacement(
            path=("_site",),
            site=SiteRecord(name="_site", city="Example City", country="Exampleland"),
        )
        document = encode_inventory_document(tree, sites=(placement,))
        state = decode_inventory_state(document)
        canonical_tree = sanitize_tree_dict(tree)

        self.assertEqual(document["schema_version"], 4)
        self.assertEqual(document["tree"], canonical_tree)
        self.assertEqual(document["sites"], [placement.to_mapping()])
        self.assertIsInstance(state, InventoryState)
        self.assertEqual(state.tree, canonical_tree)
        self.assertEqual(state.sites, (placement,))
        self.assertEqual(decode_inventory_document(document), canonical_tree)
        self.assertEqual(
            encode_inventory_document(state.tree, sites=state.sites),
            document,
        )

        version_two = {"schema_version": 2, "tree": tree}
        self.assertEqual(decode_inventory_state(version_two), InventoryState(tree=tree))
        self.assertEqual(decode_inventory_document(version_two), tree)
        self.assertEqual(decode_inventory_document(tree), tree)
        self.assertEqual(decode_inventory_state(tree), InventoryState(tree=tree))

        legacy_schema_folder = {
            "schema_version": {
                "_nodes": [
                    {
                        "id": "legacy-schema-folder",
                        "label": "Legacy",
                        "hostname": "legacy.example.net",
                    }
                ]
            }
        }
        self.assertEqual(
            decode_inventory_state(legacy_schema_folder),
            InventoryState(tree=legacy_schema_folder),
        )

        with self.assertRaisesRegex(ValueError, "Unsupported inventory schema"):
            decode_inventory_document({"schema_version": 999, "tree": tree})

    def test_tree_size_and_depth_bounds_are_enforced(self):
        wide = {
            "_nodes": [
                {"label": f"d{index}", "hostname": f"d{index}.example.net", "id": f"id-{index}"}
                for index in range(3)
            ]
        }
        with self.assertRaisesRegex(ValueError, "maximum allowed size"):
            sanitize_tree_dict(wide, max_items=2)
        with self.assertRaisesRegex(ValueError, "depth"):
            sanitize_tree_dict({"a": {"b": {"c": {}}}}, max_depth=2)
        with self.assertRaisesRegex(ValueError, "maximum allowed size"):
            merge_tree_dicts({}, wide, max_items=2)

    def test_legacy_decode_rejects_untrusted_over_nesting_without_recursing(self):
        # A hostile document nested past the bound must raise a clean
        # ValueError, never a RecursionError, before any deepcopy runs — and
        # deepcopy recurses through every container, so the guard must catch
        # nesting via folders, _nodes lists, AND arbitrary nested lists.
        def folder_chain(depth):
            node = root = {}
            for _ in range(depth):
                node["f"] = {}
                node = node["f"]
            return root

        def nodes_chain(depth):
            node = root = {}
            for _ in range(depth):
                child = {}
                node["_nodes"] = [child]
                node = child
            return root

        def list_chain(depth):
            inner: object = {}
            for _ in range(depth):
                inner = [inner]
            return {"_nodes": [{"payload": inner}]}

        for build in (folder_chain, nodes_chain, list_chain):
            with self.subTest(shape=build.__name__):
                # The guard runs before decode's own deepcopy, so a deep shape
                # can be passed straight through — no deepcopy in the test,
                # which would itself recurse and mask the guard under test.
                with self.assertRaisesRegex(ValueError, "depth"):
                    decode_inventory_state(build(300))
                with self.assertRaisesRegex(ValueError, "depth"):
                    decode_inventory_state({"schema_version": 2, "tree": build(300)})

        # A shallow legacy tree still decodes unchanged.
        self.assertEqual(
            decode_inventory_state({"Example City": {"_nodes": []}}).tree,
            {"Example City": {"_nodes": []}},
        )

    def test_legacy_depth_guard_runs_before_deepcopy(self):
        root = current = {}
        for _ in range(300):
            child = {}
            current["child"] = child
            current = child

        with patch("clidarvi_core.deepcopy") as guarded_copy:
            with self.assertRaisesRegex(ValueError, "depth"):
                decode_inventory_state(root)
            guarded_copy.assert_not_called()

        cyclic: dict[str, object] = {}
        cyclic["self"] = cyclic
        with self.assertRaisesRegex(ValueError, "depth"):
            decode_inventory_state(cyclic)

    def test_v3_decode_canonicalizes_sites_and_migrates_to_v4(self):
        document = {
            "schema_version": 3,
            "tree": {" Example City ": {}},
            "sites": [{"path": ["Example City"], "name": "Example City"}],
        }
        state = decode_inventory_state(document)

        self.assertEqual(state.tree, {"Example City": {}})
        self.assertEqual(state.sites[0].path, ("Example City",))
        self.assertEqual(
            encode_inventory_document(state.tree, sites=state.sites),
            {
                "schema_version": 4,
                "tree": {"Example City": {}},
                "sites": [
                    {
                        "path": ["Example City"],
                        "name": "Example City",
                        "site_type": "enterprise",
                        "address": "",
                        "city": "",
                        "region": "",
                        "postal_code": "",
                        "country": "",
                        "notes": "",
                    }
                ],
            },
        )

    def test_site_placements_require_unique_existing_bounded_folder_paths(self):
        tree = {"Europe": {"Example City": {}, "Sample City": {}}}
        example_city = SitePlacement(
            path=("Europe", "Example City"),
            site=SiteRecord(name="Example City", country="Exampleland"),
        )

        self.assertEqual(sanitize_site_placements(tree, [example_city]), (example_city,))

        with self.assertRaisesRegex(ValueError, "Duplicate site placement"):
            sanitize_site_placements(tree, [example_city, example_city])
        with self.assertRaisesRegex(ValueError, "existing folder"):
            sanitize_site_placements(
                tree,
                [
                    SitePlacement(
                        path=("Europe", "Alternate City"), site=SiteRecord(name="Alternate City")
                    )
                ],
            )
        with self.assertRaisesRegex(ValueError, "depth"):
            sanitize_site_placements(tree, [example_city], max_depth=1)
        with self.assertRaisesRegex(ValueError, "maximum allowed size"):
            sanitize_site_placements(tree, [example_city], max_items=0)

    def test_site_merge_adds_one_sided_data_deduplicates_and_rejects_conflicts(self):
        tree = {"Example City": {}, "Sample City": {}}
        example_city = SitePlacement(
            path=("Example City",),
            site=SiteRecord(name="Example City", address="1 Example Avenue"),
        )
        sample_city = SitePlacement(
            path=("Sample City",),
            site=SiteRecord(name="Sample City", address="4 Example Square"),
        )

        merged = merge_site_placements(
            [example_city],
            [example_city, sample_city],
            tree=tree,
        )

        self.assertEqual(merged, (example_city, sample_city))
        conflicting = SitePlacement(
            path=("Example City",),
            site=SiteRecord(name="Example City", address="Different address"),
        )
        with self.assertRaisesRegex(ValueError, "Conflicting site metadata"):
            merge_site_placements([example_city], [conflicting], tree=tree)

    def test_sanitize_preserves_metadata_and_walks_arbitrary_depth(self):
        raw = {
            "Region": {
                "Site": {
                    "Rack": {
                        "_nodes": [
                            {
                                "id": "deep-device",
                                "label": "Deep switch",
                                "hostname": "203.0.113.40",
                                "vendor": "Fortinet",
                                "device_type": "fortinet",
                                "port": "2222",
                            }
                        ]
                    }
                }
            }
        }

        clean = sanitize_tree_dict(raw)
        walked = list(walk_devices(clean))

        self.assertEqual(len(walked), 1)
        path, device = walked[0]
        self.assertEqual(path, ("Region", "Site", "Rack"))
        self.assertEqual(device.id, "deep-device")
        self.assertEqual(device.vendor, "Fortinet")
        self.assertEqual(device.port, 2222)
        self.assertEqual(find_device(clean, "deep-device"), device)
        self.assertEqual(find_device_path(clean, "deep-device"), ("Region", "Site", "Rack"))
        self.assertEqual(count_devices(clean), 1)
        self.assertEqual(count_tree_items(clean), 4)

    def test_duplicate_display_labels_remain_distinct_by_id(self):
        raw = {
            "Example City": {
                "_nodes": [
                    {
                        "id": "ams-core",
                        "label": "Core",
                        "hostname": "ams-core.example.net",
                    }
                ]
            },
            "Sample City": {
                "_nodes": [
                    {
                        "id": "rtm-core",
                        "label": "Core",
                        "hostname": "rtm-core.example.net",
                    }
                ]
            },
        }

        clean = sanitize_tree_dict(raw)
        matches = find_devices_by_label(clean, "Core")

        self.assertEqual(len(matches), 2)
        self.assertEqual({device.id for _path, device in matches}, {"ams-core", "rtm-core"})
        self.assertEqual({path for path, _device in matches}, {("Example City",), ("Sample City",)})

    def test_merge_is_recursive_and_deduplicates_only_by_stable_id(self):
        target = {
            "Sites": {
                "_nodes": [
                    {
                        "id": "existing-id",
                        "label": "Access",
                        "hostname": "access-1.example.net",
                        "vendor": "Aruba",
                        "device_type": "aruba_os",
                        "port": 22,
                    }
                ]
            }
        }
        source = {
            "Sites": {
                "_nodes": [
                    {
                        "id": "existing-id",
                        "label": "Access",
                        "hostname": "access-1.example.net",
                        "vendor": "Aruba",
                        "device_type": "aruba_os",
                        "port": 22,
                    },
                    {
                        "id": "new-id",
                        "label": "Access",
                        "hostname": "access-2.example.net",
                        "vendor": "Palo Alto",
                        "device_type": "paloalto_panos",
                        "port": 2022,
                    },
                ]
            },
            "New Site": {
                "_nodes": [
                    {
                        "id": "third-id",
                        "label": "Edge",
                        "hostname": "edge.example.net",
                    }
                ]
            },
        }
        target_before = deepcopy(target)

        merged = merge_tree_dicts(target, source)

        self.assertEqual(count_devices(merged), 3)
        self.assertEqual(find_device(merged, "existing-id").label, "Access")
        self.assertEqual(find_device(merged, "new-id").label, "Access")
        self.assertEqual(find_device(merged, "new-id").port, 2022)
        self.assertEqual(find_device_path(merged, "third-id"), ("New Site",))
        self.assertEqual(target, target_before)

    def test_merge_rejects_same_id_with_conflicting_metadata(self):
        target = {"_nodes": [{"id": "collision", "label": "One", "hostname": "one"}]}
        source = {"_nodes": [{"id": "collision", "label": "Two", "hostname": "two"}]}

        with self.assertRaisesRegex(ValueError, "Conflicting metadata"):
            merge_tree_dicts(target, source)

    def test_duplicate_ids_inside_one_tree_are_rejected(self):
        tree = {
            "_nodes": [
                {"id": "same-id", "label": "One", "hostname": "one"},
                {"id": "same-id", "label": "Two", "hostname": "two"},
            ]
        }

        with self.assertRaisesRegex(ValueError, "Duplicate device id"):
            sanitize_tree_dict(tree)


if __name__ == "__main__":
    unittest.main()
