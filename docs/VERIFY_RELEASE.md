# Verify a Clidarvi release

Clidarvi release files must come from the GitHub pre-release at
`https://github.com/devnetdreamer/Clidarvi/releases/tag/v0.1.0a1`. A checksum proves byte equality
with the selected manifest; it does not authenticate the publisher. The signed Git tag and
GitHub/Sigstore provenance provide separate origin evidence and must also verify.

## 1. Obtain and verify the immutable release assets

Download these seven release files into one otherwise-empty directory:

- `clidarvi-0.1.0a1-py3-none-any.whl`;
- `clidarvi-0.1.0a1.tar.gz`;
- `clidarvi-0.1.0a1-runtime-py313.txt`;
- `clidarvi-0.1.0a1.cdx.json`;
- `clidarvi-0.1.0a1-source-commit.txt`;
- `SHA256SUMS`; and
- `clidarvi-0.1.0a1-attestation.sigstore.json`, the bundle emitted by the tagged GitHub
  Actions run.

First require the uploaded-asset names to equal that seven-file set exactly:

```bash
expected_assets="$(printf '%s\n' \
  clidarvi-0.1.0a1-py3-none-any.whl \
  clidarvi-0.1.0a1.tar.gz \
  clidarvi-0.1.0a1-runtime-py313.txt \
  clidarvi-0.1.0a1.cdx.json \
  clidarvi-0.1.0a1-source-commit.txt \
  SHA256SUMS \
  clidarvi-0.1.0a1-attestation.sigstore.json | LC_ALL=C sort)"
actual_assets="$(gh release view v0.1.0a1 \
  --repo devnetdreamer/Clidarvi \
  --json assets \
  --jq '.assets[].name' | LC_ALL=C sort)"
test "$actual_assets" = "$expected_assets"
```

Reject the release if that comparison fails. GitHub's automatically generated **Source code
(zip)** and **Source code (tar.gz)** links are not uploaded release assets returned by the `assets`
field and are not part of this seven-file comparison. The explicit Clidarvi source distribution
listed above remains an uploaded asset.

Use a current authenticated GitHub CLI to require GitHub's immutable-release attestation for the
release and every one of those seven downloaded assets:

```bash
gh release verify v0.1.0a1 --repo devnetdreamer/Clidarvi
for artifact in \
  clidarvi-0.1.0a1-py3-none-any.whl \
  clidarvi-0.1.0a1.tar.gz \
  clidarvi-0.1.0a1-runtime-py313.txt \
  clidarvi-0.1.0a1.cdx.json \
  clidarvi-0.1.0a1-source-commit.txt \
  SHA256SUMS \
  clidarvi-0.1.0a1-attestation.sigstore.json
do
  gh release verify-asset v0.1.0a1 "$artifact" --repo devnetdreamer/Clidarvi
done
```

Also confirm that GitHub displays the **Immutable** badge for the release. Reject a mutable release,
a missing or unexpected uploaded asset, or any failed asset verification. GitHub's immutable-release
checks and the tagged workflow provenance in section 4 are complementary; neither replaces the
other.

## 2. Verify the complete checksum set

On Linux:

```bash
sha256sum --check --strict SHA256SUMS
```

On macOS:

```bash
shasum -a 256 -c SHA256SUMS
```

The manifest must report exactly five payload files: the wheel, source archive, runtime lock,
SBOM, and source-commit record. Reject missing, additional, renamed, or failed entries. The
attestation bundle and `SHA256SUMS` cannot include their own digests in that manifest.

## 3. Verify the signed tag and source commit

No maintainer signing key, fingerprint, or stable key location is published by this unreleased
candidate. Do not treat it as an official release and do not tag it until the release checklist's
signing-identity gate is complete. Before publishing the official `v0.1.0a1` pre-release, replace
this paragraph with the exact public-key location and fingerprint that a clean-machine verifier
independently confirmed.

Clone the official repository, import or otherwise trust that published signing key, and use Git's
signature verifier:

```bash
git clone https://github.com/devnetdreamer/Clidarvi.git clidarvi-source
git -C clidarvi-source fetch --force --tags origin
git -C clidarvi-source verify-tag v0.1.0a1
test "$(git -C clidarvi-source rev-list -n 1 v0.1.0a1)" = \
  "$(cat clidarvi-0.1.0a1-source-commit.txt)"
```

The final `test` must exit successfully and compares the tag target with the single 40-character
hexadecimal line in `clidarvi-0.1.0a1-source-commit.txt`. Do not treat an unsigned, unverifiable, or
mismatched tag as a signed release. GitHub's web badge is useful corroboration but does not replace
local verification under the key and identity policy you trust.

The tagged workflow separately resolves the exact Git tag object through GitHub's API and rejects
a lightweight tag, wrong tagger identity, wrong target commit, or a tag GitHub does not report as
validly verified before any payload is attested. This repository-side gate is defense in depth; it
does not replace the independent `git verify-tag` check above.

## 4. Verify GitHub/Sigstore provenance

Using the current authenticated GitHub CLI, verify each file
named in `SHA256SUMS` plus the manifest itself against the official repository, workflow, tag, and
source-commit identities:

```bash
CLIDARVI_SOURCE_COMMIT=$(cat clidarvi-0.1.0a1-source-commit.txt)
for artifact in \
  clidarvi-0.1.0a1-py3-none-any.whl \
  clidarvi-0.1.0a1.tar.gz \
  clidarvi-0.1.0a1-runtime-py313.txt \
  clidarvi-0.1.0a1.cdx.json \
  clidarvi-0.1.0a1-source-commit.txt \
  SHA256SUMS
do
  gh attestation verify "$artifact" \
    --repo devnetdreamer/Clidarvi \
    --cert-identity \
    'https://github.com/devnetdreamer/Clidarvi/.github/workflows/ci.yml@refs/tags/v0.1.0a1' \
    --source-ref refs/tags/v0.1.0a1 \
    --source-digest "$CLIDARVI_SOURCE_COMMIT" \
    --deny-self-hosted-runners
done
```

The attestation must identify `devnetdreamer/Clidarvi`, the `v0.1.0a1` tag ref, the expected CI
workflow, and the same source commit. Provenance shows that GitHub Actions produced those bytes in
that repository workflow; it is not a warranty, vulnerability scan, code review, or proof of
production fitness.

The downloaded bundle preserves a copy of the attestation. Online verification above obtains the
matching record from GitHub. For offline verification, also obtain a current trusted-root bundle
on an online machine and follow GitHub's `gh attestation verify --bundle ... --custom-trusted-root
...` procedure; do not invent or reuse an unverified trust root.

If any checksum, signature, identity, tag, commit, or provenance check differs, do not install the
release. Report the mismatch through GitHub Private Vulnerability Reporting or
`security@clidarvi.io` without attaching credentials, inventories, host keys, or device output.
