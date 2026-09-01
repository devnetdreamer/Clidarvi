# Clidarvi user guide

Until an official `v0.1.0a1` GitHub pre-release exists, this guide covers an unreleased candidate.
Making its source repository public does not by itself create that pre-release. When published, the
experimental alpha will be distributed as a Python wheel and source package for authorized network
administration. Its final release artifact has not completed real-equipment field testing and has
not been tested in production. On 2026-08-22, one run from a dirty, unfrozen development worktree
produced one successful non-empty transcript block for each fixed
UDM diagnostic on an owned UDM-SE running UniFi OS 5.1.26. The operator reported WAN/internet, LAN,
Wi-Fi, and the UniFi console normal afterward. That limited observation did not validate the final
artifact, frozen commit or wheel, independent device or configuration state, recovery, failure
handling, or production fitness. Treat every command plan as a production change, including a
command that Clidarvi describes as observational or read-only. Begin with disposable lab equipment,
maintain verified backups, and keep a tested out-of-band recovery path.

## Install and start

Clidarvi declares compatibility with Python 3.11-3.13. The planned official reproducible release
snapshot targets CPython 3.13; Python 3.11 and 3.12 remain compatibility-test targets.

The following release-asset commands apply only after the official GitHub pre-release exists:

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes --only-binary=:all: \
  -r clidarvi-0.1.0a1-runtime-py313.txt
python -m pip install --no-deps clidarvi-0.1.0a1-py3-none-any.whl
clidarvi
```

On Windows PowerShell, activate with `.venv\Scripts\Activate.ps1`. The planned pre-release will
not include a signed installer or standalone executable. Follow the
[release-verification procedure](VERIFY_RELEASE.md) to verify
the checksums, signed tag, source commit, and GitHub/Sigstore provenance; then use only the exact
lock and wheel from that release and review its SBOM. An editable installation should use
`requirements-lock/dev-py313.txt` followed by
`pip install --no-deps --no-build-isolation -e .`. A bare `pip install .` resolves compatibility
ranges and is not the official reproducible installation. The planned release
asset `clidarvi-0.1.0a1-runtime-py313.txt` will be the versioned copy of the source-tree lock at
`requirements-lock/runtime-py313.txt`.

## Operational-risk acknowledgement

License, terms, privacy, and other legal documents remain viewable without accepting anything.
Before the first DNS, host-key-discovery, or SSH operation, the official application presents four
unchecked acknowledgements covering experimental status, outage/configuration risk, authorization
and recovery, and the qualified warranty/liability terms. No network operation starts unless all
four are selected.

The application then stores a local `risk-acknowledgement.json` record containing the declared
application version and hashes of the bundled terms, disclaimer, and required runtime lock. It does
not hash the application or verify the installed packages. A missing, corrupt, or mismatched record
causes the gate to appear again. This is not GPL acceptance, does not restrict GPL rights, and does
not prove the identity or authority of the person clicking. Read [TERMS.md](../TERMS.md) and
[PRIVACY.md](../PRIVACY.md) before continuing.

## Inventory model

The inventory contains three kinds of entries:

- **Device:** a display name, connection hostname or IP address, SSH port, platform profile, and
  presentation-only device role.
- **Folder:** a logical group that can contain folders, sites, and devices.
- **Site:** a folder identified as an **Enterprise site** or **Data center**, with optional physical
  address, city, region, postal code, country, and notes.

Use **+ Device** or **+ Site** for root entries. Right-click an entry to add children, edit it,
convert a normal folder to a site by adding site details, remove site details while preserving its
children, or delete it. Site notes are not a secret store; they are saved in plaintext and included
in JSON exports. Choose **Enterprise site** for an office, campus, branch, or similar business
location, and **Data center** for a facility centered on racks and hosted infrastructure. The
choice changes the inventory symbol and is retained in JSON. Existing site records that do not
contain a site type remain **Enterprise site** entries for backward compatibility.

When adding or editing a device, choose its visual role from **Network controller**, **Firewall**,
**Multifunction security gateway**, **Generic network device**, **Router**, **Server**, **Switch**,
or **Wireless device**, or leave the selector on **Automatic (based on platform)**. The saved role
changes only the inventory icon and accessible description, not the platform profile or safety gates.

The **Ubiquiti Dream Machine / UniFi OS** option stores the dedicated Clidarvi profile identifier
`ubiquiti_unifi_os`; it does not pretend that Netmiko provides a Dream Machine driver. The profile
supports Live CLI plus a separately bounded experimental **UDM observational diagnostics** path.
For a UDM-family device, use **Multifunction security gateway** as the visual role. That role remains
presentation-only and cannot grant diagnostic or Automation eligibility. Do not select a false
profile to bypass a gate; the inventory choice does not verify the actual model or firmware.

On first launch, when no saved inventory exists, Clidarvi demonstrates this model with two wholly
synthetic data-center campuses and six example devices. The campus identities are fictional, and
all supplied hostnames use the reserved documentation suffix `.example`; they are not real
deployment targets. Replace or remove every supplied site and device before using Clidarvi with a
real environment.

The tree selection also controls the automation target selector. Selecting a device targets that
device. Selecting a folder or site and clicking **Add target** adds every descendant device,
including devices nested in child folders and sites. Targets are deduplicated by stable device ID.
Always review the final target list before running commands.

## Recommended automation workflow

1. Add or import devices and verify every hostname, port, and platform profile.
2. Complete the [field-test checklist](FIELD_TEST_CHECKLIST.md) with a disposable lab and start by
   comparing read-only behavior to the earlier script or another independently validated baseline.
3. For each device, use **Verify / Trust Host Key** and compare the displayed fingerprint with an
   independent trusted source. Do not approve an unexpected changed key.
4. Select a device, folder, or site, click **Add target**, and review the expanded target list.
5. For general Automation, start with a vendor-documented observational command valid for every
   selected platform. Experimental Automation must use exactly one isolated, recoverable lab
   target. For UDM diagnostics, use only the exact preset described below.
6. Review the command classification and redacted preview. Unknown and destructive plans require
   an exact typed phrase; changing plans require a separate confirmation. Experimental Automation
   also requires its own exact `RUN EXPERIMENTAL AUTOMATION` confirmation.
7. Use an automation account that already has sufficient privilege for the reviewed plan.
8. Run during an approved change window with current backups and out-of-band access.
9. Review the result per device. If requested, save the combined, bounded transcript in a protected
   location and inspect it before sharing.

The **Automatic save (unavailable in alpha)** option is deliberately disabled in this alpha.
Clidarvi does not directly request a library-managed automatic-save operation after connection
because such a helper may send vendor-specific commands or confirmation replies outside the
visible command plan. If a reviewed change must be persisted, add the exact vendor-documented save
or commit command as an explicit line in the plan. It remains subject to Clidarvi's normal
classification, approval, prompt-handling, and exact completion-prompt gates. Verify the command
against the exact device and firmware first; Clidarvi does not infer a safe persistence command.

The application-level **Enable mode (unavailable in alpha)** option is likewise disabled. Clidarvi
does not directly request optional enable mode after connection or supply a separate enable secret.
However, an experimental Netmiko driver's own session preparation may invoke a hidden privilege or
enable helper before control returns to Clidarvi; those writes are outside the reviewed command
plan and may persist when cleanup does not run. Start Automation with an account that already has
the privilege required by the explicit plan. Do not add `enable` to the plan as a workaround: an
interactive password prompt is intentionally blocked.

General Automation has two deliberately different alpha paths:

- **Standard alpha path:** an accurately matched **Cisco IOS** or **Palo Alto** profile.
- **Experimental lab path:** an accurately matched **Aruba OS**, **Cisco WLC**, or **Fortinet**
  profile.

Experimental Automation is off by default and is not a general support claim. The operator must
explicitly enable the experimental lab gate for the current run, select exactly one target, and
type `RUN EXPERIMENTAL AUTOMATION` exactly. Multiple experimental targets, an experimental target
mixed with any other target, cancellation, or a non-exact phrase are rejected before credentials
or a network connection. The target must be isolated from production, recoverable, backed up, and
reachable through tested out-of-band access.
Before host-key lookup, credentials, or a new connection for this path, Clidarvi also reads local
installed-distribution metadata and requires it to report Netmiko exactly as version 4.7.0. A
missing or different version blocks Experimental Automation; the worker independently repeats the
same check before it can create a socket or connector. Use the exact hashed runtime snapshot. The
metadata check does not prove that an installation is untampered or that a driver is compatible,
safe, read-only, or suitable for production. Stable Cisco IOS and Palo Alto Automation do not use
this experimental-version gate.

The experimental confirmation is additional to every normal safeguard. The operational-risk
acknowledgement, locally trusted host key, password-only authentication, legacy-algorithm policy,
command parsing and classification, changing-command review, exact `RUN UNKNOWN` or
`RUN DESTRUCTIVE` phrase where applicable, prompt and response limits, transcript bounds, and
disabled application-level enable and automatic-save options all remain in effect. An experimental
phrase does not reclassify, approve, or make a command read-only. Experimental driver setup may
still invoke hidden privilege or state helpers before control returns to Clidarvi.

Pinned Netmiko setup for these profiles can send hidden privilege, paging, terminal-width,
output-mode, or other state-changing commands before Clidarvi receives the connection and before
the reviewed command plan begins. Those setup writes are not added to the visible plan. Clidarvi
uses abort-oriented transport shutdown to avoid sending unreviewed interactive exit input; driver
cleanup or restoration may therefore not run after success, failure, Stop, or another abort, and a
setup change can persist. Verify traffic and before/after device state independently for the exact
driver, model, firmware, and account. Experimental availability is only a route for collecting
lab evidence, not proof of compatibility, safety, read-only behavior, cleanup, or production
fitness.

Generic SSH (`generic`; shown as **Other** in the inventory editor) remains Live-CLI-only
because it has no validated platform-specific Automation driver. The `ubiquiti_unifi_os`
profile remains excluded from general Automation and retains only the separate fixed diagnostic
path below. Do not select a false profile to bypass any gate.

### Experimental UDM observational diagnostics

This is a distinct, narrow path rather than general UDM Automation. It accepts exactly one target
whose profile is `ubiquiti_unifi_os`. The command plan must equal this complete preset byte-for-byte
and in this order:

```text
uptime
date -u
uname -a
id
```

Subsets, duplicates, comments, blank lines, reordering, case changes, additional arguments, shell
chaining, pipes, redirection, substitutions, control characters, unlisted commands, multiple
targets, or a mixed target set are rejected. There is no typed override. Use **Load UDM
diagnostics** to restore the exact preset. After verified host-key and credential handling, Clidarvi
uses a Paramiko SSH exec channel without requesting a PTY or interactive shell for each accepted
diagnostic. It requests no environment and writes no remote stdin. This first preview accepts only
the UniFi OS console SSH username `root`; cancel rather than substituting a different account or
profile. A command may produce at most 128 KiB of stdout/stderr combined and run for at most 15
seconds; total output for the preset is limited to 512 KiB. A nonzero exit status, any stderr,
invalid UTF-8, terminal-control output, timeout, or output-limit breach aborts the remaining preset.
The fixed preset reduces the reachable behavior; it does **not** guarantee that a command is
harmless, passive, or read-only on every UDM image. SSH login itself and the operating system can
update audit, accounting, or access data. Server-side SSH configuration, command wrappers, aliases,
firmware, privilege, and dependencies remain outside Clidarvi's control.

On 2026-08-22, a permission-mode-`0600` local transcript from a dirty, unfrozen development
worktree was structurally and semantically checked. It contained exactly one successful non-empty
result block for each fixed diagnostic, no error marker or unexpected command header, and the `id`
result confirmed the required `root` context. The operator reported WAN/internet, LAN, Wi-Fi, and
the UniFi console normal afterward. This is a **limited development observation**, not independent
telemetry, a before/after configuration diff, verified backup or out-of-band recovery evidence, a
failure/timeout/limit/Stop test, final-wheel evidence, full-checklist completion, production testing,
or a compatibility claim for another UDM model, firmware, command, or environment. UDM diagnostics
on the frozen release commit, final wheel, and locked runtime remain real-device **NOT RUN**.

Diagnostic stdout and stderr can disclose hostnames, kernel and firmware versions, account and group
membership, local time, uptime, error text, banners, and other operational details. Review screen
logs and optional transcripts before retaining or sharing them. A fixed command can still affect
availability or expose data if the target behaves unexpectedly. Use a current verified backup,
an isolated/recoverable target, and tested independent recovery. Treat this root-authenticated mode
as highly privileged even though the accepted command literals are observational.

### General Automation command parsing and completion

On every General Automation profile, Netmiko can perform platform-specific session preparation
before the reviewed plan, such as terminal-width, paging, output-mode, privilege, or mode-detection
traffic. This traffic can include state-changing writes. Clidarvi does not guarantee that driver
cleanup will run or restore the prior state when its abort-oriented teardown closes a transport.
Treat starting a connection as active device interaction and verify the traffic and device state
in a disposable lab against the exact driver, model, firmware, and account before broader use.

Blank lines and lines beginning with `#` or `!` are ignored. Each remaining line is one command.
Multiline payloads, control characters, unusually long commands, and commands outside Latin-1 are
rejected. Automation intentionally uses byte-preserving Latin-1 channel decoding and disables
Netmiko ANSI stripping so invalid or invisible bytes cannot disappear before safety checks. As a
tradeoff, legitimate non-ASCII UTF-8 device output may display as mojibake. Classification, prompt
recognition, and redaction are conservative safeguards, not proof that a command is safe or that
output contains no secrets.

Before general Automation sends its first reviewed command, Netmiko must expose a non-empty base CLI
prompt.
After every command, including bounded timing-based read-only reads, Clidarvi sends no later command
unless the complete response ends in an exact, control-free supported prompt derived from that
base. Empty, unfamiliar, incomplete, or mismatched completion aborts the SSH transport.

Host-key discovery, Automation, and Live CLI accept at most 1 MiB, 4 MiB, and 16 MiB respectively
of post-identification raw inbound SSH data. SSH framing counts toward each quota, so usable command
output is smaller. Every delegated socket read is independently capped at 64 KiB. Reaching a quota
aborts rather than truncates the live protocol state.

**Stop** requests cancellation and disconnects active transports where possible. DNS resolution,
an operating-system socket call, a library call, or a device operation can continue until its
timeout. Confirm device state independently after cancellation or any connection loss.

## Live CLI

Switch to **Live CLI**, choose a device, and start a session. Clidarvi checks the local host-key
store and rejects unknown or changed keys. The embedded console is a bounded SSH text console, not
a complete terminal emulator; complex full-screen applications, every ANSI sequence, and every
vendor-specific keyboard behavior may not render correctly.

Live CLI requires a non-empty password in this alpha. SSH agent and default-private-key discovery
are disabled because the pinned Paramiko 4 line has an RSA-certificate/SHA-1 authentication path
that is covered by a reviewed advisory. This is a scoped Clidarvi mitigation, not a Paramiko patch
or a claim that the affected dependency is fixed. See [PRIVACY.md](../PRIVACY.md) and
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

At most eight Live CLI tabs may be active at once. Each tab has a 16 MiB lifetime raw inbound SSH
quota; if it closes at that boundary, investigate the device output before deliberately reopening.

Closing a tab requests transport shutdown. If the application reports that workers are still
stopping, wait for shutdown rather than forcing the process unless operational safety requires it.

## Saving, recovery, import, and export

Clidarvi marks unsaved inventory changes with `*` in the title. **Save inventory** writes a
validated schema-v4 JSON document using a same-directory temporary file, `fsync`, atomic
replacement, and a last-known-good backup. A startup load failure preserves a timestamped corrupt
copy when that can be done safely and attempts backup recovery. If exact preservation fails, the
primary stays untouched and in-place Save is blocked until you manually preserve, move, or resolve
it; use Export to write the open inventory to a different path.

The default data directory is documented in [PRIVACY.md](../PRIVACY.md). Only one Clidarvi instance
may use that inventory at a time. JSON import supports current schema v4, schema v3, schema v2,
and validated legacy unversioned trees. XML import is limited to the supported connection structure
and does not carry site metadata. Import into a disposable profile first when the source is not
trusted.

Exported inventories contain device roles, device addresses, and site metadata but not prompted
credentials. Treat exports as confidential operational data.

## Troubleshooting

### A device will not connect

- Verify DNS or the IP address and SSH port outside Clidarvi.
- Confirm the platform profile matches the device and uses SSH, not Telnet.
- Verify the host key first and investigate any mismatch rather than replacing it automatically.
- Modern SSH algorithms are required; devices limited to RSA/SHA-1, DSS, SHA-1 key exchange,
  SHA-1/MD5 MACs, or 3DES/CBC-mode ciphers are intentionally unsupported.

### A command is unknown or blocked

Use the exact syntax documented for that vendor and firmware. An unknown classification is a safety
signal, not a request to bypass the gate. Split mixed-vendor targets into separate reviewed plans
when syntax differs.

### The inventory is locked

Close other Clidarvi processes. If no process is running, inspect the application-data directory
and operating-system state before removing any stale lock. Keep a copy of `devices.json` and its
backup before manual recovery.

### Output appears incomplete

Logs and transcripts are deliberately bounded. Host-key discovery, Automation, and Live CLI also
abort at their 1/4/16 MiB raw inbound quotas; this is a safety failure, not successful truncation.
Query the device through an independently verified session when a complete audit record is required.

## Security, privacy, and legal notices

- Vulnerability reporting: [SECURITY.md](../SECURITY.md)
- Local data and deletion: [PRIVACY.md](../PRIVACY.md)
- Warranty and operational risk: [DISCLAIMER.md](../DISCLAIMER.md)
- Operational terms and risk acknowledgement: [TERMS.md](../TERMS.md)
- License: [LICENSE](../LICENSE)
- Third-party software: [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)

The same core notices are available from **About, legal & safety** inside the application without
accepting the operational acknowledgement. No acknowledgement or disclaimer eliminates every
possible legal claim or liability.
