# Inventory format

Clidarvi stores and exports a validated JSON document. Version 4 preserves explicit visual device
roles and keeps optional physical-site metadata separate from the nested device tree.

## Schema v4 example

```json
{
  "schema_version": 4,
  "tree": {
    "Exampleland": {
      "Example City DC": {
        "_nodes": [
          {
            "id": "example-core-1",
            "label": "Core switch",
            "hostname": "192.0.2.10",
            "vendor": "Cisco Switch",
            "device_type": "cisco_ios",
            "device_role": "switch",
            "port": 22
          }
        ]
      }
    }
  },
  "sites": [
    {
      "path": ["Exampleland", "Example City DC"],
      "name": "Example City DC",
      "site_type": "datacenter",
      "address": "1 Example Avenue",
      "city": "Example City",
      "region": "Example Region",
      "postal_code": "0000 XX",
      "country": "Exampleland",
      "notes": "Non-secret operational note"
    }
  ]
}
```

Every key in `tree`, except the reserved `_nodes` key, is a folder label. `_nodes` is a list of
devices directly inside that folder. A device at the inventory root appears in `tree._nodes`.

Each site entry points to an existing folder by its complete `path`. `name` must equal the final
path segment. A site is metadata attached to a folder; it does not create a second subtree. This
sidecar design preserves `_site` and similar names as normal, backward-compatible folder labels.
`site_type` is either `enterprise` (**Enterprise site**) or `datacenter` (**Data center**). A
missing `site_type` is accepted as `enterprise`, so inventories created before site types were
introduced retain their original site appearance and behavior.

## Device fields

| Field | Meaning |
| --- | --- |
| `id` | Stable opaque identifier used for target deduplication and references. |
| `label` | Friendly display name. |
| `hostname` | DNS hostname or IP address used for the SSH connection. |
| `vendor` | User-facing compatibility label. |
| `device_type` | One of Clidarvi's supported SSH-only platform-profile identifiers. |
| `device_role` | Presentation-only inventory role; independent of connection behavior. |
| `port` | Integer SSH port from 1 through 65535. |

Credentials and trusted host keys are deliberately absent. A legacy device without `id` receives a
new ID during validation; save or export the inventory to make it persistent.

Most profile identifiers map directly to a Netmiko device type. `ubiquiti_unifi_os` is instead a
Clidarvi-owned identifier used for Live CLI and the separately bounded experimental UDM
observational-diagnostics path; it is not a claim that Netmiko provides a UDM driver. `generic`
remains the profile for **Other** and does not inherit UDM diagnostic eligibility.

An older record whose vendor label was **Ubiquiti UniFi OS (Live CLI only)** and whose profile is
`generic` remains ineligible when merely loaded or imported. Opening that device in the editor and
explicitly saving the new **Ubiquiti Dream Machine / UniFi OS** selection is the deliberate
migration to `ubiquiti_unifi_os`. Likewise, an XML vendor label by itself cannot activate the
dedicated profile. A visual `gateway` role never grants diagnostic eligibility.

`device_role` accepts exactly `controller`, `firewall`, `gateway`, `generic`, `router`,
`server`, `switch`, or `wireless`. Their UI labels are **Network controller**, **Firewall**,
**Multifunction security gateway**, **Generic network device**, **Router**, **Server**, **Switch**,
and **Wireless device**. The field controls only the icon and accessible description; it cannot
select a Netmiko driver, change command classification, or enable Automation. When an older record
lacks `device_role`, Clidarvi infers its historical icon from the stored vendor/profile once and
writes the resulting exact role on the next save or export.

## Validation limits in the desktop application

- Saved, exported, and imported inventory file: at most 20 MiB. Clidarvi refuses to publish a
  larger inventory so every file it writes remains readable by the same release.
- Combined folders and devices: at most 10,000.
- Folder depth: at most 32.
- Device/folder/site name and device ID: at most 256 characters.
- Device role: one of the eight exact identifiers documented above; unknown, differently cased,
  padded, or non-string values are rejected.
- Site type: `enterprise` or `datacenter`; omitted means `enterprise`.
- Each address, city, region, postal-code, or country field: at most 512 characters.
- Site notes: at most 4,096 characters; line breaks and tabs are permitted.
- Device transport: SSH-only profiles exposed by the application; imported Telnet/serial identifiers
  are rejected.

Control characters and structurally invalid values are rejected. Limits are defense-in-depth and
may become stricter in later releases.

## Compatibility and migration

- **Schema v4:** reads the validated `tree` and `sites` sidecar and persists exact device roles.
- **Schema v3:** reads the validated `tree` and `sites` sidecar. A site entry without `site_type`
  loads as `enterprise`. A device entry without `device_role` receives the historical role
  inferred from its stored vendor/profile; that exact role is retained when the inventory is next
  saved or exported.
- **Schema v2:** reads the `tree`; no physical-site sidecar exists.
- **Legacy unversioned JSON:** treats the root object as the tree. A historic root folder literally
  named `schema_version` remains valid when its value is a folder object.

Unsupported numeric schema versions fail closed. Loading does not silently reinterpret them.
Clidarvi writes schema v4 after the next successful save or export.

## Import and export behavior

- **JSON import replaces** the current in-memory inventory after full validation. The imported
  sites replace current site metadata. Use Export first if the current inventory must be retained.
- **XML import asks Merge or Replace.** XML has no Clidarvi site sidecar. Replace therefore clears
  site metadata. A device may carry an optional exact `DeviceRole` attribute; a missing role is
  inferred through the same legacy mapping, while an invalid explicit role aborts the import. Merge
  keeps existing site metadata and adds validated folders/devices; conflicting structures abort
  rather than silently overwrite data.
- **JSON export** writes schema v4, including device roles, site address, and notes, to a
  user-selected plaintext file.

An import updates the in-memory inventory and undo history. Save the inventory explicitly if the
change should survive application restart.

## Security and privacy

Treat inventory JSON as confidential operational data. Hostnames, IP addresses, physical
locations, and notes can be sensitive or personal. The format is not encrypted and JSON export does
not apply secret redaction to fields. Never place passwords, private keys, tokens, or recovery
codes in any field. See [PRIVACY.md](../PRIVACY.md) for storage and deletion details.
