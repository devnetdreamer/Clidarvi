# Clidarvi disposable-lab field-test checklist

Clidarvi 0.1.0a1 has automated and mocked coverage, but its final release artifact, Experimental
Automation path, and experimental UDM observational-diagnostics path have not completed
real-equipment field testing or any production testing. On 2026-08-22, one dirty, unfrozen
development-worktree run produced one successful
non-empty transcript block for each fixed UDM diagnostic on an owned UDM-SE running UniFi OS 5.1.26;
the operator reported WAN/internet, LAN, Wi-Fi, and the UniFi console normal afterward. That limited
observation did not run this checklist or validate the final artifact, frozen commit or wheel,
independent device/configuration state, recovery, or failure cases. This checklist remains the
evidence protocol and a mandatory gate before beta promotion or any broader device, firmware, or
production-fitness claim. For the first experimental `v0.1.0a1` pre-release,
[RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) permits an explicit **DEFERRED / NOT RUN** decision;
that route does not pass this checklist or create field-test evidence. This is not a safety
certification, warranty, or permission to test systems you do not own or administer.

Do not use production devices, production credentials, real customer/employer inventories, or a
network path whose loss would affect anyone outside the test. Stop when the observed target,
command, prompt, traffic, or device state differs from the written plan.

## 1. Freeze the test subject

- [ ] Record the Clidarvi commit, `0.1.0a1` artifact SHA-256, operating system, architecture, Python
  version, `requirements-lock/runtime-py313.txt` hash, and
  `sbom/clidarvi-0.1.0a1.cdx.json` hash.
- [ ] Install the official wheel with the version-pinned CPython 3.13 runtime lock and its allowlisted
  artifact hashes; do not reuse a general-purpose environment.
- [ ] Record every lab device/vendor, model or virtual appliance, exact firmware/image version,
  enabled SSH algorithms, management address, and intended platform profile.
- [ ] Confirm the devices and network are disposable or recoverable and isolated from production.
- [ ] Use RFC documentation addresses in any evidence intended for publication.
- [ ] Use a dedicated least-privileged test account; keep secrets out of screenshots, logs, issue
  reports, and this checklist.
- [ ] Preserve an unmodified copy and SHA-256 of the earlier working script used as the behavioral
  baseline. Record its Python and dependency versions and known limitations.

## 2. Establish recovery before connecting

- [ ] Export and independently verify a pre-test configuration snapshot for every device.
- [ ] Prove console or other out-of-band access without relying on Clidarvi or the management path
  being tested.
- [ ] Write and rehearse the vendor-specific rollback/reset procedure.
- [ ] Define the expected configuration diff for every later change test and an objective success
  check after rollback.
- [ ] Configure a packet capture, firewall log, or equivalent observation point that can identify
  DNS and outbound TCP destinations from the Clidarvi host.
- [ ] Define stop conditions and identify the person authorized to reset the lab.

## 3. Baseline parity: read-only first

Use one device at a time. Run only a short, vendor-documented read-only command until every item in
this section passes.

- [ ] From a clean launch, inspect the GPL, `TERMS.md`, `DISCLAIMER.md`, privacy notice, and
  third-party notice without accepting the operational acknowledgement; confirm no network traffic
  occurs.
- [ ] Start host-key verification and confirm the four acknowledgement boxes begin unchecked and
  that Cancel produces no DNS or connection attempt.
- [ ] Accept all four, record the local acknowledgement metadata, restart, and confirm an unchanged
  legal/dependency bundle does not prompt again.
- [ ] Delete the record, corrupt it, and separately change a copy's bound document/snapshot value;
  confirm each case fails closed and re-prompts before network access.
- [ ] For the same device and command, capture the earlier script's destination, SSH negotiation,
  command bytes, device output, exit behavior, and configuration diff.
- [ ] Repeat with Clidarvi and compare those observations. Explain every difference; do not mark an
  unexplained difference as harmless.
- [ ] Confirm the inventory selection and expanded target list exactly match the test plan.
- [ ] Change only the device role through controller, firewall, gateway, generic, router, server,
  switch, and wireless. Confirm the tree and selector icons/accessibility change while the stored
  platform profile, connection parameters, command policy, and Automation eligibility do not.
- [ ] Confirm the UI classification and approval path match the vendor documentation.
- [ ] Verify independently that the device configuration did not change.

Repeat the read-only parity run at least twice from a fresh application start before continuing.

## 4. Host key, authentication, and connection failures

- [ ] Unknown host key: connection is refused until the fingerprint is independently verified and
  explicitly trusted.
- [ ] Changed host key: connection fails closed, identifies the mismatch, and does not overwrite the
  trusted key automatically.
- [ ] Wrong hostname/address and closed port: the error is bounded, accurate, and does not select a
  fallback target.
- [ ] Wrong username/password and insufficient privilege: the error is bounded and credentials do
  not appear in UI logs, exceptions, saved files, or transcripts.
- [ ] Empty Live CLI password: the connection is cancelled before a worker starts; SSH agent and
  default-private-key discovery remain disabled and no authentication request reaches the device.
- [ ] DNS, TCP connect, SSH negotiation, authentication, command, and device-response timeouts are
  exercised separately where the lab can simulate them.
- [ ] Legacy-only SSH algorithms are rejected as documented; no test weakens host-key checking or
  the algorithm policy.
- [ ] Source/unit gate: constructing `InteractiveSSHWorker(..., use_keys=True)` fails locally, and
  the password-auth connection call retains `look_for_keys=False` and `allow_agent=False`.
- [ ] After every failure, verify the device state independently and confirm no unexpected target
  was contacted.

## 5. Stop, close, concurrency, and partial work

- [ ] Request **Stop** while resolving, connecting, authenticating, waiting for a prompt, receiving
  output, and between commands. Record time to worker exit and any operation that reaches its
  timeout first.
- [ ] Confirm Stop never claims rollback and independently identify any command already accepted by
  the device.
- [ ] Close a Live CLI tab during connection, idle state, active input, and output; confirm transport
  cleanup and bounded application behavior.
- [ ] Close the application during a run and while a worker is stopping; verify its warning,
  eventual worker/transport state, inventory integrity, and device state.
- [ ] On standard Automation profiles, exercise two, then the configured maximum number of
  disposable targets. Verify stable target identity, the concurrency bound, per-device result
  attribution, deduplication, and cancellation. Separately confirm Experimental Automation rejects
  every multiple- or mixed-target selection before credentials or a connection.
- [ ] Include a mixed-vendor group whose command is unknown for one profile; confirm the complete
  plan requires `RUN UNKNOWN` and no per-device downgrade bypasses the gate.
- [ ] Simulate one slow, one unreachable, and one responsive device in the same run; confirm failures
  cannot redirect output or commands to another target.

## 6. Prompts, transcripts, and sensitive data

- [ ] Exercise a recognized confirmation prompt, an unfamiliar prompt, repeated prompts beyond the
  reply cap, and prompt-like text in normal output. Confirm only the documented final-line pattern
  is answered and ambiguous behavior fails closed.
- [ ] Confirm empty, partial, mismatched, and non-prompt read-only and timing responses abort before
  any later command. Confirm Generic SSH (`generic`; shown as **Other** in the inventory editor)
  is blocked before general-Automation connection setup; `ubiquiti_unifi_os`
  must enter only its dedicated fixed-diagnostic path, never the general Netmiko worker.
- [ ] Exercise the 1/4/16 MiB host-key/Automation/Live receive boundaries in a disposable mock/lab
  session and confirm they abort visibly rather than silently dropping output. Confirm a ninth
  simultaneous Live CLI tab is refused before credentials are requested.
- [ ] Confirm unknown and destructive phrases must be typed exactly and every changing-command
  review shows the final target and command set. Confirm `RUN EXPERIMENTAL AUTOMATION` is an
  additional exact
  gate and cannot replace or bypass any of those approvals.
- [ ] Confirm the automatic configuration-save option is disabled and cannot be selected, and that
  a direct worker invocation requesting library-managed saving fails before connecting or sending
  any command.
- [ ] Confirm the application-level enable-mode option is disabled and cannot be selected, and that
  a direct worker invocation requesting that option fails before connecting. Separately capture
  whether experimental driver session preparation invokes a hidden privilege or enable helper;
  the disabled application option is not proof that no such pre-plan write occurs. Run Automation
  only with an account already at the required privilege level.
- [ ] Confirm Experimental Automation is off by default for Aruba OS, Cisco WLC, and Fortinet.
  For each profile, verify that missing activation, cancellation, a case or whitespace variant, or
  any phrase other than exact `RUN EXPERIMENTAL AUTOMATION` fails before credentials or a
  connection.
- [ ] Confirm Experimental Automation requires local installed-distribution metadata to report
  Netmiko exactly as version 4.7.0. Simulate a missing distribution, a different version, and a
  metadata-read failure; verify GUI preflight fails before host-key lookup, credentials, DNS,
  socket creation, or worker startup. Confirm direct-worker construction independently fails
  before any socket or connector, while standard Cisco IOS and Palo Alto Automation remain
  unaffected.
- [ ] Confirm Experimental Automation accepts exactly one target. Same-profile multiple targets,
  mixed experimental profiles, and an experimental target mixed with a standard profile must fail
  before host-key lookup, credential prompts, DNS, socket creation, or worker startup.
- [ ] Confirm the experimental phrase is separate from changing-command confirmation and exact
  `RUN UNKNOWN` or `RUN DESTRUCTIVE` approval. Test read-only, changing, unknown, and destructive
  plans and verify that no experimental selection weakens normal parsing, prompt, or limit gates.
- [ ] Confirm a direct worker call rejects every experimental profile by default, accepts only an
  explicit experimental opt-in with one target, and repeats this validation on its authoritative
  run snapshot. The opt-in must never enable Generic SSH or `ubiquiti_unifi_os` general Automation.
- [ ] Confirm Generic SSH remains Live-CLI-only and cannot inherit experimental or UDM capability.
  Confirm `ubiquiti_unifi_os` cannot enter the general Netmiko worker even with an experimental
  opt-in and retains only the separate fixed-diagnostic path.
- [ ] For each experimental profile, use one isolated, recoverable device to capture pre-plan
  traffic and before/after state. Treat hidden privilege, paging, terminal, output-mode, or other
  pre-plan traffic as active device interaction. Record the exact bytes and state changes observed,
  including whether cleanup or restoration occurs after success, failure, Stop, and abort.
- [ ] Confirm `ubiquiti_unifi_os` is a Clidarvi profile rather than a claimed Netmiko UDM driver.
  Verify UDM observational diagnostics require the complete byte-for-byte preset `uptime`, `date
  -u`, `uname -a`, then `id`, and reject zero/multiple/mixed targets, subsets, duplicates, comments,
  blank lines, reordering, case changes, or extra text before the diagnostic connection starts.
  Confirm there is no approval override and that device role changes cannot affect eligibility.
- [ ] On an owned, isolated and recoverable UDM-family device, record exact model and firmware, then
  verify each accepted diagnostic uses a Paramiko exec channel without a requested PTY or
  interactive shell, environment, or remote stdin. Confirm the preview requires the exact `root`
  username, enforces 128 KiB per command, 512 KiB per run, and 15 seconds per command, and aborts on
  nonzero status, stderr, invalid UTF-8, terminal controls, timeout, or a limit. Independently verify
  target state after every command. Record output as confidential evidence and do not equate the
  fixed preset with guaranteed read-only behavior.
- [ ] Keep the UDM diagnostics field status **NOT RUN** until all four exact commands, invalid-plan
  pre-network failures, Stop/timeouts, output bounds, egress, before/after state, and recovery checks
  pass from the final wheel and locked runtime. The 2026-08-22 development transcript was stored
  locally with permission mode `0600` and checked for exactly one successful non-empty result block
  per fixed command, no error marker or unexpected command header, and the required `root` context.
  The operator also reported normal WAN/internet, LAN, Wi-Fi, and UniFi-console health afterward.
  This is only limited development evidence: it provides no independent telemetry, before/after
  configuration diff, verified backup/out-of-band recovery, failure/timeout/limit/Stop result,
  frozen-commit or final-wheel result, full-checklist completion, or production evidence, and does
  not satisfy this item.
- [ ] On every General Automation profile, capture pinned Netmiko's pre-plan session-preparation
  traffic and verify every terminal-width, paging, output-mode, privilege, mode-detection, or other
  write against the exact disposable-lab firmware and account. Record behavior after success,
  failure, Stop, and aborted transport; do not assume cleanup runs. Treat unexplained or persistent
  state change as a release failure for that exact profile.
- [ ] Use fake secrets covering documented redaction patterns. Verify screen logs and saved
  transcripts redact them, then record any format that is not redacted as a known limitation.
- [ ] Confirm Automation rejects non-Latin-1 commands, preserves control bytes for fail-closed
  handling, sends no additional per-command prompt-discovery RETURN after Netmiko session
  preparation, and documents mojibake for legitimate non-ASCII UTF-8 output.
- [ ] Reach per-device and combined transcript bounds and confirm truncation is visible and does not
  corrupt attribution.
- [ ] Confirm transcripts are created only when requested, in the selected location, with expected
  permissions; inspect them before sharing.
- [ ] Confirm inventory, backups, corrupt recovery copies, known hosts, acknowledgement records, and
  transcripts contain no prompted password.

## 7. Egress observation

- [ ] Begin with outbound traffic blocked. Allow only the intended resolver and documented lab SSH
  addresses/ports.
- [ ] Observe launch, legal-document viewing, acknowledgement acceptance/cancellation, inventory
  editing, import/export, host-key verification, automation, Live CLI, Stop, and shutdown.
- [ ] Compare packet capture/firewall evidence to the written expected flows in `PRIVACY.md`.
- [ ] Attribute every DNS query and connection to its process, dependency, destination, trigger,
  and purpose. Treat any unexplained or publisher-directed traffic as a failed release gate.
- [ ] Repeat after a clean install from the official hashed snapshot. Do not generalize the result
  to another dependency resolution, modified build, operating system, or later release.

Absence of observed traffic during this test is evidence for this scenario, not proof that no code
path can ever communicate.

## 8. Controlled configuration and rollback

Perform this section only after Sections 1–7 pass. Use a disposable configuration and one target.

- [ ] Record the exact vendor-documented change command, predicted classification, prompt, device
  diff, validation command, rollback command, and maximum acceptable outage before execution.
- [ ] If the test must persist the change, put the exact vendor-documented save or commit command in
  the visible reviewed plan. Confirm its classification and approval path, and verify that the same
  prompt-handling and exact completion gates apply; do not enable or invoke a library-managed save
  helper.
- [ ] Take a new verified snapshot and confirm out-of-band access immediately before the run.
- [ ] Execute one reversible, low-impact change and compare Clidarvi's sent bytes, prompt handling,
  output, and resulting diff against the written plan and earlier-script baseline where applicable.
- [ ] Exercise a Stop or connection loss after a lab-safe partial change; verify Clidarvi does not
  represent the device as rolled back or unchanged.
- [ ] Roll back independently, compare the resulting configuration to the pre-test snapshot, and
  prove the lab service returned to its baseline state.
- [ ] Do not test erase, reload, factory-reset, credential removal, management-path removal, or an
  equivalent destructive action unless the appliance is fully disposable and the exact scenario is
  separately reviewed.

## 9. Evidence record

For every scenario, retain a sanitized record containing:

| Field | Record |
| --- | --- |
| Test ID and UTC time | |
| Tester/reviewer | |
| Commit, artifact, lock, and SBOM hashes | |
| OS, Python, and architecture | |
| Device/vendor/model and exact firmware | |
| Inventory selection and expanded targets | |
| Preconditions, snapshot, and recovery method | |
| Earlier-script baseline and hash | |
| Exact sanitized commands and expected result | |
| Observed result and configuration diff | |
| Packet-capture/firewall evidence reference | |
| Transcript/log reference | |
| Stop/timeout duration where relevant | |
| Pass, fail, blocked, or accepted limitation | |
| Defect/issue reference and retest evidence | |

Keep raw evidence private if it contains network or personal data. Never publish credentials, real
hostnames, management addresses, host keys, configurations, or sensitive transcripts.

## 10. Promotion criteria from alpha to beta

Do not call Clidarvi a beta merely because the automated suite passes. Promotion requires all of
the following:

- [ ] Sections 1–9 pass on the exact candidate artifact with no unexplained network traffic.
- [ ] At least one owned, isolated physical device or official virtual appliance for every publicly
  claimed compatibility profile passes the applicable read-only, failure, concurrency, prompt,
  transcript, egress, and reversible-change cases.
- [ ] Experimental Automation availability is not counted as compatibility evidence. Each exact
  profile, device/image, firmware, account, pre-plan write, cleanup outcome, and failure path must
  pass before making a broader support claim or promoting that profile out of the lab path.
- [ ] Results identify exact models/images and firmware; claims are narrowed wherever evidence is
  absent or vendor behavior differs.
- [ ] Every safety-critical failure is fixed and retested. Remaining limitations are explicit,
  bounded, and accepted in a written release review.
- [ ] A second technically qualified person reviews the plan, sanitized evidence, configuration
  diffs, network capture findings, and recovery results.
- [ ] Tests are repeated from a clean environment using the final wheel, hashed lock, SBOM, and
  checksums from the exact commit proposed for tagging.
- [ ] `README.md`, `PRIVACY.md`, `DISCLAIMER.md`, `TERMS.md`, release notes, and the in-app notices
  match the observed behavior and make no broader compatibility, privacy, or safety claim.
- [ ] The release checklist, identity/legal review, dependency audit, CI matrix, packaging checks,
  and private vulnerability-reporting setup are complete.

A passing disposable-lab program supports a beta label only for the documented configurations. It
does not establish production fitness, eliminate the need for each operator's own validation, or
guarantee freedom from defects, incidents, claims, or liability.
