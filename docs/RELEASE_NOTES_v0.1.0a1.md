# Clidarvi 0.1.0 Alpha 1

> **Publication status — draft.** No official `v0.1.0a1` tag or GitHub pre-release exists for this
> candidate yet. Revalidate this document against the exact tagged artifacts, public CI run, and
> release links before publishing it as release notes.

When published, Clidarvi's first packaged experimental alpha will be distributed as a Python wheel
and source package for network inventory, cautious multi-device automation, and host-key-verified
SSH access.

## Highlights

- A refreshed desktop interface and distinctive Clidarvi visual identity.
- Purpose-built inventory icons distinguish enterprise sites, data centers, controllers, firewalls,
  multifunction security gateways, generic devices, routers, servers, switches, and wireless
  devices without reusing the Clidarvi brand mark as topology.
- Device roles are retained independently of SSH platform profiles and affect only inventory icons
  and accessible descriptions, not connection behavior or Automation eligibility.
- Schema v4 persists exact device roles while retaining schema v3, schema v2, and unversioned
  inventory compatibility.
- A wholly synthetic first-launch inventory demonstrates two fictional data-center campuses with
  realistic device labels. All supplied hostnames use the reserved `.example` documentation
  suffix; replace or remove every example entry before using a real environment.
- Hierarchical inventory with **Enterprise site** and **Data center** choices, including address,
  city, region, postal code, country, and notes. Older site records without a type default to
  enterprise.
- Site metadata retained across JSON saves, imports, and exports, with older inventories remaining
  readable.
- Atomic inventory saves and recovery.
- Bounded parallel automation through Netmiko.
- Interactive SSH through Paramiko with strict host-key verification.
- Legacy RSA/DSS, SHA-1, MD5, and 3DES/CBC-cipher SSH negotiation disabled on every connection
  path.
- Password-only Live CLI authentication; key/default-key and agent authentication are disabled to
  reduce exposure to Paramiko 4's RSA/SHA-1 advisory. This is a scoped mitigation, not a patch.
- Read-only, changing, destructive, and unknown command classification.
- Typed approval gates for destructive and unknown command plans.
- Application-level requests for Netmiko/library-managed automatic configuration saving are
  disabled in the alpha UI and worker. Persistence requires an explicit vendor-documented save or
  commit command in the reviewed plan under the normal classification, approval, prompt, and
  completion gates.
- Application-level optional enable mode is disabled; Automation requires an account that already
  has sufficient privilege for the explicit reviewed plan. Experimental driver session preparation
  can still invoke hidden privilege or state helpers before control returns to Clidarvi, as
  disclosed below.
- A default-off Experimental Automation lab path for accurately matched Aruba OS, Cisco WLC, and
  Fortinet profiles. Clidarvi enforces exactly one target and explicit activation plus the separate
  exact phrase `RUN EXPERIMENTAL AUTOMATION`; the operator must ensure that target is isolated and
  recoverable. Every ordinary command-risk gate remains in force, and multiple or mixed targets
  fail before credentials or a connection.
- An exact installed-distribution version gate for Experimental Automation: local metadata must
  report Netmiko 4.7.0, whose hidden driver setup was audited for this path. Missing or different
  metadata fails before host-key lookup, credentials, or network activity, and the worker repeats
  the check independently. The check is not an installation-integrity or compatibility guarantee;
  the standard Cisco IOS and Palo Alto path is unaffected.
- Worker-level default denial, explicit opt-in, one-target enforcement, and authoritative run
  snapshot revalidation for experimental profiles.
- Pinned experimental drivers can issue hidden privilege, paging, terminal, output-mode, or other
  state-changing setup writes before the reviewed plan. Abort-oriented teardown does not guarantee
  cleanup or restoration, so setup state can persist. This path is not a compatibility, safety,
  read-only, cleanup, or production-fitness claim.
- Generic SSH (`generic`; shown as **Other** in the inventory editor) remains Live-CLI-only
  through Clidarvi's generic connection profile because no validated platform-specific Automation
  driver satisfies the session/prompt invariant. The standard alpha path remains
  limited to accurately matched Cisco IOS and Palo Alto profiles.
  `ubiquiti_unifi_os` remains excluded from general Automation and retains only the separate fixed
  diagnostic path.
- A separate experimental `ubiquiti_unifi_os` **UDM observational diagnostics** path accepts one
  UDM target and only the complete byte-for-byte preset `uptime`, `date -u`, `uname -a`, then `id`,
  in that order; subsets, comments, blank lines, reordering, and extra text are rejected. It uses
  Paramiko SSH exec channels without requesting a PTY, interactive shell, environment, or remote
  stdin; requires the console SSH account `root`; limits output to 128 KiB per command and 512 KiB
  per run; and limits each command to 15 seconds. The pinned Netmiko snapshot still has no dedicated
  Dream Machine driver. The fixed preset is not a warranty that a command is harmless or read-only
  on every device or firmware.
- A UDM-family device can use the presentation-only **Multifunction security gateway** role; that
  role does not enable or alter diagnostics.
- Fail-closed base-prompt/completion verification before Automation can send or advance any
  timing-based or read-only command.
- Post-identification raw inbound SSH quotas of 1 MiB for host-key discovery, 4 MiB for Automation,
  and 16 MiB per Live CLI session, a 64 KiB raw-read cap, and an eight-tab Live CLI limit.
- Byte-preserving Latin-1 Automation decoding, disabled Netmiko ANSI stripping for application
  reads, and no additional per-command prompt-discovery RETURN after session preparation.
- A combined bounded transcript and best-effort redaction of common secret patterns.
- In-app license, warranty, privacy, and third-party notices.
- 330+ automated tests covering core safety, persistence, UI, recovery, runtime-asset resolution,
  and wheel `RECORD` binding.
- A fail-closed operational-risk acknowledgement before any DNS, host-key-discovery, or SSH action,
  recording the declared application version and bundled terms, disclaimer, and runtime-lock hashes.
- Installed legal documents, icons, runtime lock, and SBOM are accepted only as one complete
  31-file bundle owned by the same wheel `RECORD` as the imported module. Normal prefix and
  `pip --target` layouts are supported; modified, partial, stale, or ambiguous bundles fail closed.
- A version-pinned CPython 3.13 runtime lock with allowlisted artifact hashes, CycloneDX SBOM,
  commit-bound release checksums, and tag-only GitHub/Sigstore provenance.
- A disposable-lab field-test protocol for comparison with the earlier script.

## Install

Use these release-asset commands only after the official GitHub pre-release exists and its evidence
has been verified:

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes --only-binary=:all: \
  -r clidarvi-0.1.0a1-runtime-py313.txt
python -m pip install --no-deps clidarvi-0.1.0a1-py3-none-any.whl
clidarvi
```

Declares compatibility with Python 3.11-3.13. The planned reproducible official snapshot targets
CPython 3.13; 3.11 and 3.12 remain compatibility-test targets. The planned release is gated on a
passing CI matrix: all three interpreters on Ubuntu plus exact hashed Python 3.13 wheel jobs on
Windows and macOS. This planned pre-release will have no standalone binary or installer.

## Important

This is experimental alpha network-administration software. Its final release artifact,
Experimental Automation path, and UDM observational-diagnostics path have automated or mocked
coverage but have **not completed real-equipment field testing or any production testing**. On
2026-08-22, one run from a dirty,
unfrozen development worktree produced one successful non-empty transcript block for each fixed
diagnostic on an owned UDM-SE running UniFi OS 5.1.26; the operator reported WAN/internet, LAN,
Wi-Fi, and the UniFi console normal afterward. This limited observation did not validate the frozen
commit, final wheel and locked runtime, independent device/configuration state, recovery, failure
behavior, full checklist, or production fitness. Use Clidarvi only on authorized, isolated,
disposable lab systems; review commands and expanded targets, keep verified snapshots, and maintain
tested out-of-band recovery. Follow `docs/FIELD_TEST_CHECKLIST.md` in the source distribution.

It will be provided without warranty under GPL-3.0-only. Read `TERMS.md`, `DISCLAIMER.md`, and
`PRIVACY.md` — bundled in the source distribution and wheel, and shown in-app under **About,
legal & safety** — before any network action. The
operational acknowledgement is separate from the GPL and does not restrict GPL permissions. No
acknowledgement, disclaimer, test, lock, or SBOM eliminates every possible defect, claim, or
liability.

## Required release record before publication

- Planned tag: `v0.1.0a1`
- Planned release type: **Pre-release**
- Final-candidate full real-equipment/production field-test status: **NOT RUN**
- Experimental Aruba OS Automation on the final wheel and locked runtime: **NOT RUN**
- Experimental Cisco WLC Automation on the final wheel and locked runtime: **NOT RUN**
- Experimental Fortinet Automation on the final wheel and locked runtime: **NOT RUN**
- UDM observational diagnostics on the final wheel and locked runtime: **NOT RUN**
- Limited development observation, not release evidence: a local permission-mode-`0600` transcript
  from the 2026-08-22 dirty/unfrozen worktree contained exactly one successful non-empty block for
  each fixed diagnostic, no error marker or unexpected command header, and confirmed the required
  `root` context on an owned UDM-SE running UniFi OS 5.1.26. The operator reported WAN/internet,
  LAN, Wi-Fi, and the UniFi console normal afterward. No independent telemetry, configuration diff,
  verified backup/out-of-band recovery, failure/timeout/limit/Stop, frozen-artifact, production, or
  broader compatibility result is claimed
- CI: require the full Python 3.11/3.12/3.13 Ubuntu matrix plus exact hashed Python 3.13 wheel jobs
  on Windows and macOS to pass before publishing
- Runtime snapshot: verify release assets `clidarvi-0.1.0a1-runtime-py313.txt`,
  `clidarvi-0.1.0a1.cdx.json`, `clidarvi-0.1.0a1-source-commit.txt`, and `SHA256SUMS` from the same
  release
- Origin: also verify the signed `v0.1.0a1` tag, immutable GitHub release and each downloaded
  asset, and tag-only GitHub/Sigstore provenance using `docs/VERIFY_RELEASE.md`; checksums alone do
  not authenticate the publisher
- Security reports: use GitHub Private Vulnerability Reporting or `security@clidarvi.io`; never
  attach credentials, real device data, raw configurations, host keys, or sensitive transcripts

## Known dependency exception

Netmiko 4.7.0 requires Paramiko below 5. The reviewed advisory lists Paramiko through 4.0.0 as
affected by PYSEC-2026-2858 and lists no patched release. Clidarvi disables related legacy
negotiation and public-key/agent user authentication as a scoped mitigation; it does not patch
Paramiko or alter the advisory status. CI permits only this named advisory. See
`THIRD_PARTY_NOTICES.md` in the distribution for the exact scope. Organizations that prohibit
any known affected dependency should not deploy this alpha.
