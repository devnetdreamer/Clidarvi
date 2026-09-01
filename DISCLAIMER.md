# Warranty, liability, and operational-risk notice

Clidarvi 0.1.0a1 is experimental alpha software for network administration. It has automated and
mocked test coverage, but its final release artifact, Experimental Automation path, and
experimental UDM observational-diagnostics path have not completed real-equipment field testing or
any production testing. One limited development-worktree run produced a successful non-empty
transcript block for each fixed diagnostic
on an owned UDM-SE running UniFi OS 5.1.26, and the operator reported normal network/console health
afterward. This was not a frozen artifact, independent health measurement, configuration diff,
backup/recovery proof, failure-path test, or production test. It does not validate other models,
firmware, environments, or production fitness. Clidarvi can send commands to remote devices, change
or erase configuration, interrupt connectivity, disclose sensitive operational information, damage
availability, or lock administrators out. Devices, firmware, operating systems, networks, and
third-party libraries can behave in ways Clidarvi does not anticipate.

## No warranty

Clidarvi is provided **AS IS** and **AS AVAILABLE**, with no warranty or representation of any
kind, express, implied, or statutory. To the maximum extent permitted by applicable law, all
warranties are disclaimed, including warranties of merchantability, satisfactory quality, fitness
for a particular purpose, title, non-infringement, accuracy, security, reliability, availability,
compatibility, data integrity, and freedom from defects or harmful components. The entire risk as
to the software's quality, operation, and results remains with the user. The user bears all costs
of servicing, repair, recovery, correction, and validation.

A version-pinned dependency lock, allowlisted hashes, SBOM, automated tests, command classification,
prompts, and other safeguards can reduce or expose particular risks. They do not certify the
software, prove the absence of vulnerabilities or unexpected network behavior, or substitute for
independent lab and field validation.

## Limitation of liability

To the maximum extent permitted by applicable law, the copyright holders, authors, contributors,
maintainers, and distributors of Clidarvi are not liable under contract, tort (including
negligence), strict liability, statute, or any other legal theory for any damages, losses, claims,
costs, or liabilities arising from or connected with the software or its use, inability to use,
modification, distribution, or results—even if advised that damage was possible.

This limitation includes direct, general, special, incidental, indirect, exemplary, punitive, and
consequential loss, and loss or corruption of data or configuration; unauthorized access or
disclosure; service interruption or outage; loss of connectivity, credentials, business, revenue,
profit, opportunity, goodwill, or reputation; device replacement or recovery costs; and damage to
systems, networks, equipment, or other property.

Nothing in this notice excludes, restricts, or waives a right, remedy, warranty, or liability that
cannot lawfully be excluded, restricted, or waived. Where a limitation is ineffective, it applies
only to the maximum extent the applicable law permits. No contributor assumes liability beyond
what they expressly agree to in a separate written instrument.

## Not a safety system or professional service

Clidarvi is not designed, tested, certified, or intended to be the sole control for life-safety,
emergency, medical, transportation, industrial-control, operational-technology, hazardous,
critical-infrastructure, or other safety-critical environments. Do not rely on it where failure or
delay could reasonably cause death, personal injury, severe environmental harm, or major physical
damage. This is a warning about non-reliance, not a restriction on the freedoms granted by the GPL.

Clidarvi, its output, and its documentation are not legal, cybersecurity, compliance, engineering,
or other professional advice. Command classification, prompt detection, secret redaction,
cancellation, SSH policy, and persistence controls reduce specific risks but cannot cover every
vendor, firmware release, prompt, failure mode, vulnerability, or secret format.

## User responsibilities

Users remain responsible for, at minimum:

- operating only systems they own or are explicitly authorized to administer;
- reviewing every command, option, and expanded target before execution;
- independently verifying SSH host-key fingerprints and investigating changed keys;
- testing against representative lab or non-production equipment first;
- using least-privileged, preferably short-lived credentials where the device and selected feature
  support them; the first experimental UDM diagnostics preview instead requires the privileged
  `root` console SSH account;
- maintaining current verified backups, approved change windows, peer review, and an out-of-band
  recovery path;
- checking vendor documentation and independently verifying device state after errors or stops;
- completing representative disposable-lab testing before exposing real systems and retaining the
  evidence needed for the operator's own change and risk decisions;
- protecting and lawfully processing credentials, inventories, site data, known-host files, logs,
  exports, and transcripts; and
- complying with applicable laws, regulations, contracts, licenses, policies, and third-party
  rights.

A Stop request can leave work in progress until DNS, socket, SSH, device, or library timeouts
complete. Best-effort redaction and memory cleanup do not guarantee removal of all secret copies.
Transcripts and exports can contain confidential or personal data. See [PRIVACY.md](PRIVACY.md).

## No service commitment

Publication of Clidarvi creates no service-level agreement, fiduciary relationship, duty to
support, maintenance obligation, security-monitoring commitment, update obligation, or promise to
continue the project. A report, contribution, or feature request does not create such a duty.

## Relationship to GPL-3.0-only

This notice supplements the disclaimer of warranty in section 15 and the limitation of liability
in section 16 of the GNU General Public License version 3, as interpreted by section 17 and as
permitted by section 7(a). It does not narrow the rights to run, study, copy, modify, or convey the
software under GPL-3.0-only and imposes no field-of-use restriction. If this notice and the GPL
conflict, the GPL controls.

The separate [TERMS.md](TERMS.md) operational-risk acknowledgement refers to this notice. It does
not replace the GPL or condition the GPL permissions to run, study, copy, modify, convey, or use the
software commercially. An acknowledgement record is evidence only that controls were completed on
one local installation; it does not prove the user's identity, authority, understanding, or
compliance.

No disclaimer guarantees immunity from a claim or overrides mandatory law. Anyone needing advice
for a particular country, commercial distribution, paid support, enterprise deployment, or a
safety-sensitive environment should obtain advice from a qualified lawyer and relevant technical
professionals before proceeding.
