# Clidarvi operational terms and risk acknowledgement

**Terms ID:** `clidarvi-network-risk-acknowledgement-v1`

**For application version:** `0.1.0a1`

**Terms date:** 2026-08-23

**Publisher:** GitHub `@devnetdreamer` (https://github.com/devnetdreamer) (pseudonymous)

**General contact:** `info@clidarvi.io`

**Privacy contact:** `privacy@clidarvi.io`

**Security reports:** `security@clidarvi.io` or GitHub Private Vulnerability Reporting; see
[SECURITY.md](SECURITY.md)

> **Pseudonymous publisher notice.** The Publisher distributes Clidarvi under the GitHub account
> name above and has not published a verified legal name. The GitHub account, the listed
> `clidarvi.io` addresses, the repository issue tracker, and GitHub Private Vulnerability
> Reporting are the published contact channels for this distribution. Control of a domain,
> address, or account is not evidence of, and does not verify, any real-world legal identity. These
> terms do not claim that the acknowledgement described below forms a negotiated agreement with an
> identified counterparty. The acknowledgement is the local operational risk control described in
> section 9, and the warranty and liability terms apply only to the extent applicable law gives
> them effect for a pseudonymously published, free-of-charge distribution.

These terms document the operational risks acknowledged when a person (the **Operator**) chooses
to use network functionality in the unmodified official Clidarvi distribution supplied by the
Publisher. They supplement the no-warranty and liability terms in the GNU General Public License
version 3 and [DISCLAIMER.md](DISCLAIMER.md), only to the extent applicable law permits.

## 1. Separate from the GPL

Clidarvi is licensed under GPL-3.0-only. These operational terms are not acceptance of the GPL and
are not a condition on receiving or exercising the GPL permissions. They impose no copyright-
license restriction, charge, or field-of-use condition on running, studying, copying, modifying,
conveying, reverse engineering, or commercially using Clidarvi as the GPL permits. The official
distribution's pre-network acknowledgement is an interface risk control, not a condition of GPL
permission. Recipients may modify or remove that interface and convey their version under GPLv3,
subject to the GPL. Third-party components remain governed by their own licenses.

If these terms conflict with the GPL concerning rights in the software, the GPL controls. Nothing
here grants trademark rights or permission to misrepresent the origin of a modified distribution.

## 2. How acknowledgement occurs

The official application makes these terms and the incorporated disclaimer available before the
first DNS, host-key-discovery, or SSH operation. Network functionality remains disabled until the
Operator affirmatively selects each unchecked acknowledgement and continues.

The GPL, these terms, the disclaimer, privacy information, and other legal notices remain viewable
without acknowledgement. Viewing, copying, or declining them does not initiate a network action.

By continuing, the Operator affirmatively selects each of these four statements, which the
application presents verbatim:

1. "I understand that this is experimental alpha software and that its final release artifact has
   not completed real-equipment or production field testing."
2. "I understand that commands may cause outages, configuration loss, or other damage, and that
   Stop does not roll back changes already sent."
3. "I confirm that I am authorized to access the selected systems and that I am responsible for
   verified backups and a tested recovery plan."
4. "I agree to the warranty and liability terms shown below, only to the extent permitted by
   applicable law."

Section 3 describes the wider risk landscape these statements summarize, including security
exposure, device lockout, and partial changes left after a stop, timeout, failure, or exit.

The Operator must be legally capable of making this acknowledgement. A person acting for an
organization represents only that they have authority to operate the selected systems and to make
the operational decision; the local checkbox record is not proof of that authority or that the
organization is bound.

## 3. Experimental status and material risks

Version 0.1.0a1 has automated and mocked tests, but its final release artifact, Experimental
Automation path, and experimental UDM observational-diagnostics path have not completed
real-equipment field testing or any production testing. One development-worktree Live CLI
observation saw `uptime` succeed on an owned UDM-SE
running UniFi OS 5.1.26. A later limited run from a dirty, unfrozen development worktree produced one
successful non-empty transcript block for each fixed diagnostic, and the Operator reported normal
network and console health afterward. Neither observation independently established device state,
configuration equality, backup or recovery readiness, failure behavior, final-artifact behavior, or
production fitness. A compatibility label is not certification for any vendor, model, software
image, or firmware release. Command classification, fixed diagnostic allowlists, prompt recognition,
host-key handling, secret redaction, cancellation, transcript bounds, and persistence safeguards are
limited controls, not guarantees.

SSH connection setup is itself device interaction. Supported Automation profiles use pinned
Netmiko session preparation before Clidarvi's reviewed command state machine takes control; that
library may send platform-specific terminal-width, paging, output-mode, privilege, mode-detection,
or other state-changing traffic that is not included in the visible command plan.

Aruba OS, Cisco WLC, and Fortinet are exposed only through a default-off Experimental Automation
lab path. For each run, the Operator must explicitly enable that path, select exactly one isolated
and recoverable lab target, and type `RUN EXPERIMENTAL AUTOMATION` exactly. This confirmation is
separate from and does not replace the command-classification, changing-command, `RUN UNKNOWN`, or
`RUN DESTRUCTIVE` gates. Multiple or mixed targets, cancellation, and a non-exact phrase are
rejected before credentials or a network connection. The path also fails closed before host-key
lookup, credentials, or a new connection unless local installed-distribution metadata reports
Netmiko exactly as version 4.7.0, the version whose hidden driver setup was audited for this path.
The Operator must use the exact hashed runtime snapshot. A matching metadata string does not prove
that an installation is untampered or establish compatibility, safety, harmlessness, read-only
behavior, successful cleanup, or production fitness.

The Experimental Automation gate does not make hidden driver traffic reviewed, harmless,
read-only, reversible, or compatible with a device. Clidarvi uses abort-oriented transport
shutdown to avoid unreviewed interactive exit writes and does not guarantee that driver cleanup or
restoration will run after success, failure, Stop, or another abort. A pre-plan privilege, paging,
terminal, output-mode, or other state change can persist. Experimental availability is not a
compatibility, safety, cleanup, or production-fitness representation. Generic SSH (`generic`;
shown as **Other** in the inventory editor) remains Live-CLI-only because it has no validated
platform-specific Automation driver. The `ubiquiti_unifi_os` profile remains excluded from
general Automation and retains only its separate, fixed-diagnostic path.

The separate experimental UDM observational-diagnostics path accepts one `ubiquiti_unifi_os`
target and only one complete, fixed, four-command preset in its exact order. It rejects an altered,
partial, or expanded plan. It uses Paramiko SSH exec channels without requesting a PTY or interactive
shell. This narrower mechanism does not establish that a command is harmless, passive, or read-only
on a particular device; server configuration, wrappers, privilege, firmware, and returned
operational data remain material risks.

Network operations can, among other things, change or erase configuration; interrupt routing,
switching, authentication, management, or other services; expose credentials or operational data;
leave partial changes after a timeout, failure, cancellation, or application exit; and affect the
Operator or third parties. A read-only classification can be wrong or a device can interpret a
command unexpectedly.

## 4. Operator decisions and authorized use

The Operator remains responsible for deciding whether, where, and how to run Clidarvi. This
includes independently verifying authorization, target identity, host-key fingerprints, expanded
target lists, vendor syntax, privileges, commands, prompts, outputs, backups, rollback, change
windows, least privilege, and out-of-band recovery. The Operator must comply with applicable law,
contracts, organizational policy, licenses, confidentiality duties, and third-party rights.

The Publisher does not approve a deployment, command, target, or change merely because Clidarvi
allows it. The acknowledgement is not a substitute for the Operator's technical review, legal
authority, risk assessment, or the disposable-lab validation in
[docs/FIELD_TEST_CHECKLIST.md](docs/FIELD_TEST_CHECKLIST.md).

## 5. Dependencies, builds, and network behavior

The first-party Clidarvi 0.1.0a1 source does not intentionally implement telemetry, analytics,
advertising, cloud sync, or automatic updates. The official CPython 3.13 release procedure uses the
version-pinned runtime lock in `requirements-lock/runtime-py313.txt`, with an allowlist of upstream
artifact SHA-256 hashes; `sbom/clidarvi-0.1.0a1.cdx.json` records the package composition and lock
fingerprint. A hash can establish only that bytes match a chosen digest. It does not authenticate
who produced or published the digest, and neither a hash nor an SBOM proves security, fitness, lack
of telemetry, or lack of malicious or unexpected behavior.

Third-party dependencies, Python tooling, operating-system services, modified distributions, other
dependency versions, package indexes, and later releases are outside that first-party statement.
The Operator must independently review the exact build and apply egress controls when unexpected
network access must be technically prevented. See [PRIVACY.md](PRIVACY.md) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## 6. No warranty or professional service

TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, CLIDARVI IS PROVIDED **AS IS** AND **AS
AVAILABLE**, WITHOUT ANY EXPRESS, IMPLIED, OR STATUTORY WARRANTY OR REPRESENTATION. This includes
no warranty of merchantability, satisfactory quality, fitness for a particular purpose, title,
non-infringement, accuracy, security, reliability, availability, compatibility, data integrity, or
freedom from defects or harmful components.

Clidarvi and its documentation are not legal, security, compliance, engineering, or other
professional advice. Publication creates no support, maintenance, monitoring, security-fix,
update, availability, response-time, or continuation commitment. The complete warranty notice in
[DISCLAIMER.md](DISCLAIMER.md) is incorporated here.

## 7. Limitation of liability

TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, THE PUBLISHER, COPYRIGHT HOLDERS, AUTHORS,
CONTRIBUTORS, MAINTAINERS, AND DISTRIBUTORS WILL NOT BE LIABLE UNDER CONTRACT, TORT INCLUDING
NEGLIGENCE, STRICT LIABILITY, STATUTE, OR ANOTHER THEORY FOR DAMAGES, LOSSES, CLAIMS, COSTS, OR
LIABILITIES ARISING FROM OR CONNECTED WITH CLIDARVI, ITS USE, INABILITY TO USE, MODIFICATION,
DISTRIBUTION, OR RESULTS, EVEN IF ADVISED THAT DAMAGE WAS POSSIBLE.

This includes direct, indirect, incidental, special, consequential, exemplary, and punitive loss;
loss or corruption of data or configuration; outage, interruption, unauthorized access or
disclosure; lost connectivity, credentials, business, revenue, profit, opportunity, goodwill, or
reputation; and device, system, network, recovery, or replacement costs. The more detailed scope in
[DISCLAIMER.md](DISCLAIMER.md) is incorporated here.

## 8. Mandatory-law safeguard

Nothing in these terms excludes, restricts, transfers, or waives a right, remedy, warranty, duty,
or liability that applicable law does not permit the parties to exclude, restrict, transfer, or
waive. Any ineffective term applies only to the maximum lawful extent, and the remaining terms
continue where the law permits. These terms contain no operator indemnity, arbitration clause,
choice-of-law clause, or choice-of-forum clause.

No click, disclaimer, alpha label, test result, lock file, or technical safeguard guarantees that a
claim cannot be made or that liability cannot arise. Anyone needing protection for a specific
country, consumer relationship, commercial distribution, paid service, employment context, or
high-impact deployment should obtain advice from a qualified lawyer and appropriate insurance and
technical professionals.

## 9. Local record, availability, and changes

After acknowledgement, the official application stores `risk-acknowledgement.json` locally. The
record contains terms and schema identifiers, the application's declared version, acceptance time,
selected-item identifiers, hashes of the bundled terms, disclaimer and required runtime lock, the
required runtime dependency-snapshot identifier, a legal-bundle hash, and an
`installed_runtime_verified` flag that is always `false` in this version. The acknowledgement
record does not attest or verify the full installed runtime. For Experimental Automation, the
application separately reads only the local installed-distribution metadata string for Netmiko and
requires it to equal `4.7.0` as a narrow fail-closed eligibility check. That check does **not** hash
or attest the executable/source distribution or installed packages, prove that either code or
metadata is untampered, or prove that the running environment matches the lock.
It intentionally contains no asserted personal identity or device target and is not transmitted to
the Publisher by first-party Clidarvi code. It proves neither who clicked nor their authority,
understanding, or compliance.

The application requires a fresh acknowledgement when its terms identifier, legal-bundle hash,
application version, or tracked document/snapshot changes. A new terms version applies only after
it is presented and affirmatively acknowledged; changes are not retroactive. Operators can read,
copy, and retain this Markdown file before deciding. Deleting the local record causes the gate to
appear again for sessions that have not already verified an acceptance; an application instance
that verified the record earlier in its run re-checks at its next start.

This document, [DISCLAIMER.md](DISCLAIMER.md), [PRIVACY.md](PRIVACY.md), the GPL in
[LICENSE](LICENSE), and the exact release source should be retained together. The GPL governs
software permissions; these terms and the disclaimer address only operational acknowledgement,
warranty, and liability within their lawful scope.
