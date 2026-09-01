# Changelog

All notable changes to Clidarvi are documented here. Releases use PEP 440-compatible version
identifiers; alpha and other pre-release versions may change behavior before a stable release.

## [Unreleased]

The changes below are intended for the 0.1.0a1 experimental alpha. They do not record a published
release yet.

### Added

- Hierarchical, versioned network-device inventory with stable device IDs.
- Physical sites selectable as an **Enterprise site** or **Data center**, with name, address, city,
  region, postal code, country, and notes; older records without a type default to enterprise.
- Direct tree-to-target selection for complete sites and folders, with stable-ID deduplication.
- Schema v4 device-role and site-metadata persistence across JSON save, import, and export, while
  retaining schema v3, schema v2, and unversioned inventory compatibility.
- Bounded parallel Netmiko automation and interactive Paramiko SSH sessions.
- Compact, left-aligned Live CLI session tabs with honest connecting/connected indicators,
  bounded long labels, and accessible per-session close controls.
- Strict SSH host-key verification and an explicit trust workflow.
- A fail-closed SSH algorithm policy that disables legacy RSA/DSS, SHA-1, MD5, and 3DES/CBC-cipher
  negotiation.
- Password-only Live CLI authentication while affected Paramiko 4 is pinned, as a scoped mitigation
  for its RSA/SHA-1 advisory rather than a claim that the dependency is patched.
- Conservative command classification, typed safety gates, and bounded prompt handling.
- Verified base/trailing CLI-prompt evidence before general Automation sends or advances commands;
  devices using Generic SSH (`generic`; shown as **Other** in the inventory editor) remain
  Live-CLI-only. The pinned Netmiko snapshot provides no dedicated
  Dream Machine/UDM driver.
- A separate experimental `ubiquiti_unifi_os` **UDM observational diagnostics** mode: exactly one
  target; the complete byte-for-byte four-line preset `uptime`, `date -u`, `uname -a`, then `id`;
  no subsets, comments, blank lines, or reordering; and Paramiko exec channels without a PTY. This
  constrained mode is not a promise that those commands are absolutely read-only on every device or
  firmware.
- Raw inbound SSH quotas of 1/4/16 MiB for host-key discovery/Automation/Live CLI, a 64 KiB raw-read
  cap, and an eight-session Live CLI limit.
- Byte-preserving Latin-1 Automation decoding, no Netmiko ANSI deletion in application reads, and
  no additional per-command prompt-discovery RETURN after Netmiko session preparation.
- Best-effort secret redaction, bounded logs, and a combined transcript with per-device/total
  bounds.
- Fail-closed disabling of application-level requests for Netmiko/library-managed automatic
  configuration saving. Persistence requires an explicit vendor-documented save or commit command
  in the reviewed plan, subject to the normal classification, approval, prompt, and completion
  gates.
- Fail-closed disabling of application-level optional enable mode; automation accounts must
  already have sufficient privilege for the reviewed plan. Experimental driver session preparation
  may still invoke hidden privilege or state helpers before control returns to Clidarvi.
- A default-off Experimental Automation lab path for accurately matched Aruba OS, Cisco WLC, and
  Fortinet profiles. Clidarvi enforces exactly one target and separate exact
  `RUN EXPERIMENTAL AUTOMATION` approval in addition to all normal command-risk gates; the operator
  must ensure that target is isolated and recoverable. Multiple or mixed targets fail before
  credentials or a connection.
- An exact local installed-distribution version gate for Experimental Automation: only Netmiko
  4.7.0, whose hidden driver setup was audited for this path, is accepted. Missing or different
  metadata fails before host-key lookup, credentials, or network activity, and the worker repeats
  the check independently. The standard Cisco IOS and Palo Alto path is unaffected.
- Worker-level default denial, explicit opt-in, one-target enforcement, and authoritative run-time
  revalidation for experimental profiles.
- Explicit disclosure that pinned drivers can issue hidden privilege, paging, terminal,
  output-mode, or other state-changing setup writes before the reviewed plan, and that
  abort-oriented teardown does not guarantee cleanup or restoration; a setup change can persist.
- Generic SSH remains Live-CLI-only because no validated platform-specific Automation driver
  satisfies the session/prompt invariant. The standard alpha path remains limited to accurately
  matched Cisco IOS and Palo Alto profiles. `ubiquiti_unifi_os` remains excluded from general
  Automation; UDM observational diagnostics are an independently bounded fixed-preset path.
- Atomic inventory writes, last-known-good recovery, single-instance locking, and async shutdown.
- A shared 20 MiB inventory read/write limit and fail-closed protection against overwriting an
  invalid primary that could not first be preserved exactly.
- Tests for policy, persistence, worker behavior, terminal handling, and UI shutdown.
- A distinctive Clidarvi application logo combining routing nodes with a command prompt.
- Presentation-only device roles selectable independently of SSH profiles: controller, firewall,
  multifunction security gateway, generic device, router, server, switch, and wireless device.
- A dedicated enterprise inventory icon set with distinct enterprise-site and data-center symbols,
  plus controller, firewall, multifunction-gateway, neutral generic-device, router, server, switch,
  and wireless-device symbols, with separate dark- and light-surface assets.
- A realistic-looking but wholly synthetic first-launch inventory with two fictional data-center
  campuses and six devices. Every supplied hostname uses the reserved `.example` suffix and must
  be replaced or removed before real use.
- An in-app legal/safety viewer plus user, privacy, inventory-format, and release documentation.
- A mixed-vendor safety gate that treats a command unknown on any selected platform as unknown.
- Explicit legacy-algorithm policy on every SSH host-key, automation, and interactive path.
- A fail-closed, four-part operational-risk acknowledgement before the first network action, with
  local versioned document-hash evidence and no asserted user identity.
- A version-pinned CPython 3.13 runtime lock with allowlisted artifact hashes, locked build and
  development environments, a CycloneDX SBOM, commit-bound release checksums, and tag-only
  GitHub/Sigstore provenance. Official tag attestation fails while the repository is private; the
  publication procedure also requires protected `v*` tags and an immutable GitHub pre-release.
- A complete reviewed license inventory for all 22 pinned runtime distributions, with SBOM
  generation bound fail-closed to exact package names, versions, artifact hashes, and synchronized
  third-party notices.
- A disposable-lab field-test checklist and explicit disclosure that the final release artifact,
  Experimental Automation path, and UDM diagnostics mode have not completed real-equipment or
  production testing. One development
  observation on 2026-08-22 produced one successful non-empty transcript block for each fixed preset
  command on an owned UDM-SE running UniFi OS 5.1.26. The operator reported WAN/internet, LAN, Wi-Fi,
  and the UniFi console normal afterward. The dirty/unfrozen worktree, final artifact, independent
  health/configuration evidence, recovery, and failure/timeout behavior remain unvalidated.

### Changed

- Refreshed the reviewed CPython 3.13 snapshots to cryptography 50.0.1 with OpenSSL 4.0.2,
  PyQt6-Qt6 6.11.2, Click 8.5.0, filelock 3.32.5, msgpack 1.2.2, platformdirs 4.11.7, and Ruff
  0.16.5; regenerated the binary-only hashes, third-party notices, and CycloneDX SBOM.
- Added an explicit all-dependency `scripts/compile_locks.sh --upgrade` path, retained a stable
  generated-command header, and verified a byte-identical no-option replay for this reviewed
  snapshot with the pinned, fail-closed build toolchain.

### Fixed

- Bind the exact 31-file runtime asset set to the wheel `RECORD` that owns the imported module,
  validating module, metadata, asset paths, sizes, SHA-256 digests, and one coherent native-prefix or
  target layout. Missing, modified, partial, ambiguous, or stale installations fail closed; verified
  source checkouts never borrow from a colocated `share/clidarvi` directory.
- Ignore a late Live CLI connected signal after its tab page has been destroyed instead of allowing
  a deleted Qt widget to raise through the event loop.
- Fail closed on Python 3.11/3.12 symlink-resolution loops, bound the installed-module directory
  scan, and ignore delayed Automation popup positioning or tree editors after their Qt owners have
  been destroyed.
- Clear every mutable general-Automation password buffer in the worker's final cleanup, including
  validation failures before any device task starts and GUI thread-start failures.
- Query current repository visibility through the GitHub REST API before exact-tag attestation,
  avoiding reliance on optional push-payload fields.
- Reject any unexpected file in the six-file CI payload, name every build/provenance input
  explicitly, and require the published release to contain exactly seven uploaded assets.
- Infer the multifunction-gateway visual role for genuine schema-v3 Ubiquiti/UniFi OS records that
  lacked `device_role`, while preserving every explicitly stored modern role including `generic`.
- Apply the 15-second UDM per-command deadline from before exec-channel setup through bounded output
  completion, so channel setup cannot extend the documented command budget.

### Planned release notes

- Planned first packaged experimental alpha as a Python wheel and source distribution.
- Licensed under GPL-3.0-only.
- No standalone installer is provided.
