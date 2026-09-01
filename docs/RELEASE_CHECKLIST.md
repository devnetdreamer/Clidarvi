# Public-source and first experimental-alpha release checklist

This checklist has two separate milestones:

1. **Public source repository:** changing the GitHub repository from private to public. This
   publishes source under the GPL, but it is not an official `v0.1.0a1` packaged release, does not
   authorize a release announcement, and is not evidence that a wheel, platform, or device passed
   release validation. Eligible public `main` or tag workflow runs can expose retained GitHub
   Actions build artifacts; those remain untrusted or candidate CI evidence until the complete
   official-release gate passes. Complete the public-source gate described below before changing
   visibility. Release-only boxes may remain open if the repository, `SECURITY.md`, and all
   marketing still say that no release exists.
2. **Official `v0.1.0a1` GitHub pre-release:** tagging and publishing the wheel, sdist, locks, SBOM,
   checksums, and provenance. Do not tag, publish release artifacts, or announce this milestone
   until every applicable release box is complete. An explicitly permitted **DEFERRED / NOT RUN**
   field-test decision counts only where this checklist says so; it is never a passed test.

A checked list is evidence of a process, not certification or immunity from claims. Keep the dated
checklist, review notes, hashes, deliberate deferrals, and sanitized test evidence with the release
record.

## Public source repository gate

Complete the pre-public checks before changing visibility. Complete the immediate post-public
checks directly afterward; they cannot all be verified while the repository is private.

### Pre-public checks

- [ ] Commit the intended public tree, review the complete staged diff and Git history, and confirm
  that it contains no credentials, private infrastructure, sensitive transcript, personal data,
  employer/client material, build output, or unintended local file.
- [ ] Review all retained GitHub Actions artifacts before changing visibility. Delete obsolete or
  unintended artifacts, or record their deliberate retention or expiry. Understand that eligible
  public `main` and tag pushes expose temporary CI payloads to signed-in readers; label them as
  untrusted or candidate evidence, never as official release assets.
- [ ] Run every command in **Local quality and security gate** from the exact commit in a clean,
  locked environment and obtain a completely green private GitHub CI matrix for that same commit.
- [ ] Confirm ownership and third-party licensing, accurate experimental/field-test/privacy claims,
  working published contact channels, repository URLs, and the absence of an unresolved publisher
  placeholder. Record any lawyer or trademark review still deliberately pending; do not describe
  the project as legally cleared or immune from claims.
- [ ] Confirm `SECURITY.md` truthfully says no release exists. Configure and verify the controls that
  are actually available and enforceable while private, including branch/ruleset protection where
  supported. Record any control that must wait until the repository is public instead of claiming
  that it is active.

### Immediate post-public checks

- [ ] Make the repository public without creating a tag or GitHub release. From a signed-out
  browser, inspect the public file list, license detection, contact links, and latest CI result. Do
  not publish an external release announcement at this milestone.
- [ ] Enable and verify any GitHub security feature that was not available or enforceable while the
  repository was private. Recheck Private Vulnerability Reporting and its **Report a vulnerability**
  link, Dependabot alerts, secret scanning and push protection, and branch/ruleset enforcement,
  wherever each feature is available. Externally test delivery to the advertised
  `security@clidarvi.io` fallback.
- [ ] Before creating any release tag, enable repository release immutability (which applies only to
  future releases) and verify an enforced tag ruleset matching `v*` blocks tag updates and deletions
  without a routine or broad bypass. Leave tag creation permitted for the maintainer and record both
  settings as they are actually enforced.

The remaining sections are the full official-release record unless a box explicitly says it is
also part of the public-source gate.

## Identity, ownership, and legal gate

- [x] Replace the publisher placeholder in `TERMS.md` with the distributing identity and durable
  contact. Done: pseudonymous publisher `GitHub @devnetdreamer`, general contact
  `info@clidarvi.io`, privacy contact `privacy@clidarvi.io`, and security reporting through
  `security@clidarvi.io` or GitHub Private Vulnerability Reporting, plus a
  pseudonymous-publisher notice. Re-confirm every advertised channel works before release.
- [ ] Confirm continued control of `clidarvi.io`, registrar auto-renewal and account MFA, and
  externally test inbound delivery and reply-from-identity behavior for `info@`, `privacy@`, and
  `security@`. Recheck configured SPF, DKIM, and DMARC records, spam placement, GitHub Private
  Vulnerability Reporting, and its notifications.
- [ ] Confirm the build/test gate and running application's network gate reject the publisher
  placeholder, so no release artifact can record acceptance of unidentified terms.
- [x] Choose the initial copyright holder's identity and replace generic holder references
  consistently. Done: `devnetdreamer (https://github.com/devnetdreamer) and Clidarvi contributors`
  in source/SVG headers and the About dialog; `pyproject.toml` identifies `devnetdreamer` as the
  package author and maintainer. Note: a pseudonymous holder is a deliberate privacy trade-off; it
  identifies the account, not a verified legal identity, and can weaken the evidentiary position
  compared to a legal name.
- [ ] Confirm Git author name/email. Use a GitHub no-reply address if personal-email privacy matters.
- [x] Add repository, issue tracker, changelog, and security URLs under `[project.urls]` in
  `pyproject.toml`. Verify every URL after the repository exists.
- [ ] Confirm the publisher owns or may distribute every code, test, document, and logo asset.
- [ ] Confirm no employer, client, school, contract, earlier project, or contributor owns or
  restricts the work; retain written clearance where relevant.
- [ ] Complete manual BOIP/TMview/WIPO and trade-name similarity checks for Clidarvi in relevant
  software/service classes; retain dated results. A preliminary knockout search is not legal
  clearance.
- [ ] Have a qualified lawyer for the intended publisher and target jurisdictions review
  `TERMS.md`, `DISCLAIMER.md`, the first-network-action acknowledgement flow, consumer/organization
  use, privacy wording, and mandatory-law carveouts. Record advice and implement required changes.
- [ ] Obtain jurisdiction-specific privacy advice before claiming complete privacy compliance or
  soliciting personal data. Where mandatory, publish the verified controller identity, legal
  bases, data-subject rights, retention criteria, and supervisory-authority complaint route;
  pseudonymous publication and the factual `PRIVACY.md` description do not waive those duties.
- [ ] Confirm the operational terms do not condition GPL permission or add restrictions on use,
  modification, redistribution, reverse engineering, production use, or commercial use.
- [ ] Confirm legal documents can be opened, copied, and retained before acceptance; no network
  action or GPL/legal-document viewing requires prior acceptance.
- [ ] After the final identity/legal edit, rebuild the legal-bundle hashes and confirm a stale local
  acknowledgement fails closed and requests fresh acknowledgement.
- [ ] Confirm the maintainer charges no price, offers no paid support or advertising, and does not
  intentionally operate publisher-directed application analytics or other monetization for this
  distribution. Do not treat this as a claim about hidden or unexpected third-party behavior. Re-run
  legal/CRA/product-liability review before those facts change.
- [ ] Remove unqualified claims such as “safe,” “secure,” “no telemetry,” “production ready,”
  “certified,” or “no liability” unless their exact, qualified scope is evidenced. Keep the explicit
  statement that no legal or technical measure guarantees immunity.

## Alpha status and field-test disclosure gate

- [ ] Confirm every public file, package version, About dialog, terms record, tag, and artifact uses
  `0.1.0a1` / `v0.1.0a1` and **experimental alpha**, not beta or stable.
- [ ] State prominently that the final 0.1.0a1 artifact, Experimental Automation path, and UDM
  diagnostics mode have automated or mocked coverage but have not completed real-equipment field
  testing or any production testing.
  Separately disclose the limited 2026-08-22 dirty/unfrozen development-worktree run of all four
  fixed diagnostics on an owned UDM-SE running UniFi OS 5.1.26 and the operator-reported normal
  post-run WAN/internet, LAN, Wi-Fi, and UniFi-console health. Do not present it as frozen-commit,
  final-wheel, independent-health, configuration-diff, recovery, failure-path, production, or
  broader compatibility evidence.
- [ ] Choose and record exactly one `v0.1.0a1` field-test disposition:
  **COMPLETE/PASSED** only if the complete [FIELD_TEST_CHECKLIST.md](FIELD_TEST_CHECKLIST.md) was
  performed successfully on the exact candidate; otherwise **DEFERRED / NOT RUN — accepted for
  this experimental alpha only**. The deferred route is allowed for the source-publication and
  `v0.1.0a1` pre-release milestones only while the limitation remains prominent and no Experimental
  Automation profile, UDM, device, firmware, or production-fitness claim is made. It is not a pass.
- [ ] Confirm the field-test checklist is published so operators and contributors can collect
  comparable disposable-lab evidence against the earlier working script.
- [ ] If any field scenario was run, preserve the baseline script hash/environment and sanitized
  evidence; identify every unrun, failed, blocked, or unexplained scenario. Do not cherry-pick a
  successful check into a broader compatibility claim.
- [ ] Do not promote to beta until every promotion criterion in the field-test checklist has passed
  and been independently reviewed. A beta label would still not mean production fitness.

## Reproducible dependency and supply-chain gate

- [ ] Confirm `requirements-lock/runtime-py313.txt` is generated from `runtime.in`, includes the
  complete CPython 3.13 runtime graph, pins every version exactly, and supplies SHA-256 hashes for
  every allowed artifact.
- [ ] Confirm `requirements-lock/build.txt` and `requirements-lock/dev-py313.txt` are exact locked
  environments. Bootstrap the disposable CPython 3.13 compiler environment from the hashed build
  lock. Use `scripts/compile_locks.sh` to reproduce existing pins and use its `--upgrade` option
  only for an intentional refresh of every compatible dependency. Review every version change,
  dependency-edge change, added or removed artifact hash, and generated-file change. Confirm the
  commit or pull request records the reviewed `--upgrade` run because the generated header shows
  the canonical no-option replay command; then replay it and require a byte-identical lock result.
- [ ] Review every direct and transitive dependency, source project, release change, artifact origin,
  license, and advisory. Confirm every locked distribution has an explicit reviewed SPDX expression
  in `scripts/generate_sbom.py` and `THIRD_PARTY_NOTICES.md`; the SBOM generator must fail if its
  reviewed package set differs from the runtime lock. Never auto-merge a dependency update.
- [ ] Generate and inspect `sbom/clidarvi-0.1.0a1.cdx.json`; confirm it matches the final lock and
  installed environment and passes deterministic regeneration plus strict CycloneDX 1.6 schema
  validation.
- [ ] Install runtime dependencies with
  `--require-hashes --only-binary=:all: -r requirements-lock/runtime-py313.txt`, then install the
  candidate wheel with `--no-deps`. Confirm pip cannot silently resolve a different version.
- [ ] Confirm hashes and the SBOM are described only as integrity/composition evidence, not proof of
  no telemetry, no vulnerabilities, or safe behavior.
- [ ] Run the egress section of `FIELD_TEST_CHECKLIST.md`; explain every observed destination and
  trigger. Treat unexplained or publisher-directed traffic as a release failure.
- [ ] Confirm `PRIVACY.md` scopes first-party/no-telemetry statements to the exact unmodified source
  and official pinned snapshot and excludes arbitrary dependencies, installers, modified builds,
  tooling, operating-system services, and later releases.
- [ ] Confirm privacy/user documentation and tests match the alpha's password-only Live CLI:
  empty passwords cancel locally, and SSH-agent/default-private-key discovery stays disabled.
- [ ] Confirm `PYSEC-2026-2858` is the only ignored advisory; re-check Netmiko's declared Paramiko
  range, the advisory's affected/patched-version fields, and every regression-tested mitigation.
  Do not describe Paramiko 5 or a Clidarvi mitigation as an upstream patched release while the
  reviewed advisory lists no patched version.
- [ ] Remove the advisory exception as soon as Clidarvi can integrate and test a dependency revision
  that no longer contains the affected code; retain the disclosure while the affected package
  remains.

## Local quality and security gate

Run from a clean checkout in a fresh environment created from the committed development lock. At a
minimum, run:

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes --only-binary=:all: \
  -r requirements-lock/dev-py313.txt
python -m pip install --no-deps --no-build-isolation -e .
QT_QPA_PLATFORM=offscreen python3 -B -m unittest discover -s tests -v
ruff check .
ruff format --check .
bandit -q -r clidarvi.py clidarvi_core.py clidarvi_io.py clidarvi_policy.py clidarvi_workers.py scripts -ll
git ls-files -z | xargs -0 detect-secrets-hook \
  --exclude-files '(^|/)LICENSE$|^sbom/.*\.cdx\.json$'
python scripts/generate_sbom.py --check --validate-schema
pip-audit --requirement requirements-lock/runtime-py313.txt --ignore-vuln PYSEC-2026-2858
pip-audit --requirement requirements-lock/build.txt
pip-audit --requirement requirements-lock/dev-py313.txt --ignore-vuln PYSEC-2026-2858
python3 -m build --no-isolation
```

- [ ] Confirm tests, Ruff, Bandit, tracked-file secret scan, audit, and build all pass. The only
  secret-scan exclusions are `LICENSE` and CycloneDX JSON: the SBOM contains the expected
  runtime-lock SHA-256 fingerprint and is instead checked by deterministic regeneration and strict
  schema validation.
- [ ] Confirm tests cover a missing/corrupt/stale acknowledgement, all four unchecked boxes,
  cancellation, no pre-acceptance network call, each network entry point, local-record contents,
  and no asserted identity/device data.
- [ ] Confirm network safeguards still fail closed: strict host keys, legacy-algorithm exclusion,
  password-only authentication while Paramiko 4 is pinned, mixed-vendor/unknown classification,
  destructive approval, exact base/completion prompts, default-off Experimental Automation,
  exact `RUN EXPERIMENTAL AUTOMATION`, its one-target worker-level enforcement,
  Generic SSH (`generic`; shown as **Other** in the inventory editor) rejection,
  separation of UDM diagnostics from the general worker, disabled application-level
  automatic-save and enable options, 1/4/16 MiB raw receive quotas, the eight-session Live CLI
  limit, bounded output, and cooperative shutdown.
- [ ] Confirm the automatic configuration-save option remains disabled in the UI and direct worker
  requests fail before connecting. Verify that documentation requires any vendor save or commit
  command to appear explicitly in the reviewed plan under the normal classification, approval,
  prompt, and completion gates.
- [ ] Confirm the application-level optional enable control remains disabled and direct worker
  requests for that option fail before connecting. Separately verify that documentation and tests
  disclose and observe any hidden privilege or enable helper invoked by experimental driver
  session preparation before control returns to Clidarvi. Automation accounts must already have
  sufficient privilege; do not use an explicit interactive `enable` command as a workaround.
- [ ] Confirm the standard General Automation path accepts only accurately matched Cisco IOS and
  Palo Alto profiles and retains its existing multi-target, host-key, classification, prompt,
  transport, authentication, output, and cancellation gates.
- [ ] Confirm Experimental Automation is off by default and accepts only an accurately matched
  Aruba OS, Cisco WLC, or Fortinet profile and enforces exactly one target. Verify the
  operator-facing text separately requires an isolated, recoverable lab target. Verify missing
  activation, cancellation, every non-exact phrase, multiple or mixed targets, and direct-worker
  use without explicit opt-in all fail before credentials or network setup.
- [ ] Confirm Experimental Automation fails closed unless local installed-distribution metadata
  reports Netmiko exactly as version 4.7.0. Cover a missing distribution, a mismatched version, and
  a metadata-read failure in GUI and direct-worker tests; every case must fail before host-key
  lookup, credentials, DNS, socket creation, or connector use. Confirm the standard Cisco IOS and
  Palo Alto path is unaffected, and do not describe the metadata check as an integrity or
  compatibility guarantee.
- [ ] Confirm exact `RUN EXPERIMENTAL AUTOMATION` is separate from and cannot replace the existing
  changing-command confirmation or exact `RUN UNKNOWN` and `RUN DESTRUCTIVE` gates. Direct-worker
  validation must repeat against the authoritative run snapshot.
- [ ] Capture pinned Netmiko's pre-plan traffic for every enabled profile, including privilege,
  paging, terminal-width, output-mode, mode-detection, and other writes. Exercise success, failure,
  Stop, and abort-oriented teardown; do not assume driver cleanup runs or restores prior state.
  Documentation and release evidence must disclose any unexplained or persistent change.
- [ ] Confirm Generic SSH remains Live-CLI-only and cannot inherit experimental capability.
  Confirm `ubiquiti_unifi_os` remains excluded from the general Netmiko worker even with an
  experimental opt-in and retains only its separately bounded fixed diagnostics.
- [ ] Resolve the final-wheel field-test status separately for Aruba OS, Cisco WLC, and Fortinet.
  Mark a profile **COMPLETE/PASSED** only after the exact wheel and locked runtime pass the
  single-target pre-plan traffic, before/after state, phrase, failure, Stop, teardown, egress, and
  recovery matrix on a recorded isolated/recoverable device or official image. Otherwise record
  **DEFERRED / NOT RUN — experimental lab path only**. A deferred profile must remain default-off,
  single-target, and explicitly non-compatible/non-production in every public claim; it is not a
  test pass.
- [ ] Confirm experimental UDM observational diagnostics accepts only one `ubiquiti_unifi_os`
  target and the complete byte-for-byte preset `uptime`, `date -u`, `uname -a`, then `id`, with no
  override. Verify the GUI rejects subsets, duplicates, comments, blank lines, reordering,
  imported-inventory mismatches, mixed targets, device-role changes, control characters, shell
  metacharacters, and extra text before a diagnostic connection. Separately confirm direct-worker
  validation accepts only immutable known command IDs without duplicates and cannot receive an
  arbitrary command literal. Confirm both GUI and direct worker require the username to equal `root`
  exactly; use Paramiko exec without a PTY, shell, environment, or remote stdin; enforce 128 KiB per
  command, 512 KiB per run, and 15 seconds per command; and fail closed on nonzero status, stderr,
  invalid UTF-8, terminal controls, timeout, or bounds. Documentation must warn about privileged
  device behavior and output privacy rather than promise absolute read-only behavior.
- [ ] Resolve the UDM final-wheel matrix by one of the two permitted routes. Either run the complete
  matrix against the exact final wheel and locked runtime on an owned, isolated/recoverable UDM-SE
  with recorded firmware, packet/egress evidence, before/after state, Stop/timeout cases, and
  recovery evidence; or record **DEFERRED / NOT RUN — accepted for this experimental alpha only**
  in the release record. Under the deferred route, preserve the 2026-08-22 UDM-SE 5.1.26
  four-command run and operator health report only as a limited dirty/unfrozen development
  observation, keep the final artifact and UDM diagnostics labelled not field-tested, and make no
  hardware-compatibility claim. The complete matrix is mandatory before beta promotion or any
  broader device/firmware compatibility claim.
- [ ] Run compatibility CI on Ubuntu with Python 3.11, 3.12, and 3.13. Build and install a wheel
  against the exact hashed CPython 3.13 runtime snapshot on native Windows and macOS jobs. Describe
  only CPython 3.13 as the official locked snapshot unless other interpreter locks are published.

## Artifact and documentation gate

- [ ] In the final release commit, change `SECURITY.md` from “no published release”; move the
  `CHANGELOG.md` changes from **Unreleased** into a dated `v0.1.0a1` entry; remove draft/no-tag
  wording from `RELEASE_NOTES_v0.1.0a1.md`; replace candidate/planned/future-release wording in
  `README.md` and `USER_GUIDE.md` with factually true released wording; and complete the published-
  key replacement required in `VERIFY_RELEASE.md`. Re-run every gate afterward; never ship a tagged
  wheel that still claims no release exists.
- [ ] Build wheel and sdist with `requirements-lock/build.txt` from the exact release commit.
- [ ] Install the wheel in another clean environment outside the source checkout using the official
  runtime lock and `--no-deps`; run the full test suite against the installed module and launch it.
- [ ] Inspect wheel and sdist contents. Confirm `LICENSE`, `TERMS.md`, `DISCLAIMER.md`, `PRIVACY.md`,
  `THIRD_PARTY_NOTICES.md`, `TRADEMARKS.md`, `README.md`, user guide, field-test checklist,
  inventory guide, changelog, security policy, release notes, release-verification guide, locks,
  SBOM, logo, and source are present and readable.
- [ ] From the installed wheel, render every dark/light inventory icon at tree size. Confirm the
  controller, firewall, gateway, generic, router, server, switch, and wireless roles are visually
  distinct from enterprise-site and data-center icons, and that generic is not a rack symbol.
- [ ] Open **About, legal & safety** from the installed wheel. Inspect every tab and confirm external
  links do not silently open or contact a service. Confirm each internal reference either navigates
  to a bundled local document or is explicitly presented as a noninteractive repository reference.
- [ ] Confirm the risk gate precedes automation, bounded background host-key
  verification/discovery, and Live CLI, while inventory editing and legal viewing remain available.
- [ ] Verify `risk-acknowledgement.json` contains only its documented schema/app/terms/snapshot/hash/
  time/item fields and no username, email, credential, host, command, IP, or hardware identifier.
- [ ] Confirm deleting the record causes reacceptance and that corrupt, unknown, or mismatched
  content never bypasses the gate.
- [ ] Generate `dist/SHA256SUMS` from exactly five payloads: final wheel, sdist, SBOM, versioned
  runtime lock, and `clidarvi-0.1.0a1-source-commit.txt`. Verify manifest completeness and every
  checksum from a separate clean directory; publish those five payloads with `SHA256SUMS`.
- [ ] Confirm the source-commit record is one lowercase 40-character commit ID, equals the tested
  workflow SHA, and equals the commit referenced by `v0.1.0a1`.
- [ ] Choose and configure the maintainer Git signing mechanism and key. Register the public key
  with the published GitHub identity, verify the exact no-reply email/key association, and publish
  the public verification material, stable key location, and fingerprint through that documented
  identity. Independently verify them from a clean machine, then replace the unreleased-key warning
  in `VERIFY_RELEASE.md` with those exact details.
- [ ] State that checksums prove byte equality only. Create and locally verify a cryptographically
  signed annotated Git tag tied to the published maintainer identity. Confirm its tagger is exactly
  `devnetdreamer <314994350+devnetdreamer@users.noreply.github.com>`. On the exact official tag,
  require the full CI matrix and the API-backed annotated-tag, target, tagger, and GitHub signature
  verification gate before the least-privilege pinned `actions/attest` job generates
  GitHub/Sigstore provenance for all five payloads plus `SHA256SUMS`.
- [ ] Follow `VERIFY_RELEASE.md` from a clean directory: verify checksum completeness, the signed
  tag, source-commit binding, repository identity, tagged workflow identity, and every provenance
  subject before publishing.
- [ ] Run a native GUI smoke test on every platform claimed as supported; do not infer platform or
  device support solely from offscreen unit tests.

## Staged-file, privacy, and history gate

- [ ] Review `git status --short`, `git diff --cached --check`, and the complete `git diff --cached`.
- [ ] Use `git ls-files` to confirm `.local-assets/`, `.pyinstaller-cache/`, build artifacts, caches,
  inventories, backups, corrupt copies, known-host stores, acknowledgement records, transcripts,
  `.env` files, and private keys are not tracked. Ignored local files still require inspection.
- [ ] Scan the full Git history, not only the working tree, for credentials, personal data,
  employer/client material, and old assets that should never have been published.
- [ ] Confirm network examples use IETF documentation address ranges and reserved example domains,
  postal and location examples are conspicuously fictitious, and no example contains real
  infrastructure, an unintended personal or third-party email address, username, absolute home
  path, credential, configuration, host key, or transcript. The approved public `clidarvi.io`
  project addresses are permitted.
- [ ] Review the final README, package metadata, release notes, screenshots, UI, and any external
  announcement together so public claims never exceed the evidence or qualifications in the legal
  documents.

## Safe GitHub publication sequence

An initial private bootstrap commit/push is not a release and necessarily precedes private CI. If
the private repository already exists, skip completed bootstrap-only actions and begin with a
reviewed candidate branch/commit. Never treat an older green run as evidence for a changed tree.

1. For a new private bootstrap only, inspect all staged files, run the applicable local
   quality/history/privacy checks, confirm ownership, create the private repository, and push
   without a tag or release. Record GitHub-only gates that cannot yet run.
2. For the actual public-source candidate, use a reviewed branch/commit, rerun the complete local
   gate, and wait for Ubuntu Python 3.11/3.12/3.13 plus the exact hashed Python 3.13 wheel jobs on
   Windows and macOS to pass on that exact SHA.
3. Merge only the reviewed candidate, confirm the unchanged `main` SHA remains green, and then
   confirm the gated `main` candidate artifact and source-commit record use that same workflow
   SHA. Treat those retained bytes as public CI evidence, not official release assets. Review
   GitHub's file list and license detection, and configure and verify every security and protection
   control that is actually available and enforceable while private. Record controls deferred until
   public visibility.
4. Make the repository public without creating a tag or release. Immediately complete the
   post-public security controls, signed-out inspection, contact-delivery test, and other checks in
   the public-source gate above.
5. Re-run CI on an unchanged public `main` commit and inspect the new gated candidate. Complete all
   remaining release, legal, field-status, dependency, packaging, identity, and manual-smoke gates.
6. Create a signed annotated tag `v0.1.0a1` for that exact passing commit using the published
   maintainer identity, verify it locally with `git verify-tag`, then push only that tag. Do not edit
   or rebuild locally between the passing candidate and tagging.
7. Require the tag-triggered full matrix and `tagged-release-provenance` job to pass. Download only
   the `clidarvi-0.1.0a1-attested-<commit>` artifact from that tagged run and complete every check in
   `VERIFY_RELEASE.md`.
8. With release immutability already enabled, create the GitHub **pre-release as a draft** from
   `docs/RELEASE_NOTES_v0.1.0a1.md` for the already-pushed signed tag. Require and verify that tag;
   never let GitHub create a new lightweight tag. Attach the exact wheel, sdist, runtime lock, SBOM,
   source-commit record, `SHA256SUMS`, and `clidarvi-0.1.0a1-attestation.sigstore.json` from the tagged
   run, inspect the complete draft, and only then publish it as a pre-release. Confirm through
   `gh release view --json assets` that the uploaded-asset names equal those seven files exactly;
   reject missing or unexpected uploaded assets. Then confirm the **Immutable** badge, run
   `gh release verify`, re-download all seven assets, and run `gh release verify-asset` for each one
   before announcing it.
9. Publish any external announcement only after the public pre-release is downloadable and its
   repository and release links work.

Do not upload a standalone executable or installer under this checklist. Bundling PyQt, Qt,
Paramiko, Netmiko, Python, or other libraries requires a fresh license, notice,
corresponding-source, security, privacy, reproducibility, and platform review.
