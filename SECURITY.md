# Security policy

Clidarvi is maintained pseudonymously by GitHub `@devnetdreamer`. Report suspected
vulnerabilities through GitHub **Private Vulnerability Reporting** (preferred) or
`security@clidarvi.io`. The public issue tracker is for non-sensitive coordination only.

## Supported versions

| Version | Supported |
| --- | --- |
| Unreleased 0.1.0a1 candidate | Reports accepted |
| Published releases | None yet |
| Older versions | No |

Reports concerning the current unreleased 0.1.0a1 candidate are accepted and handled voluntarily
on a best-effort basis. After a release exists, this policy will cover the latest published
experimental alpha. No response time, investigation, fix, maintenance, support, update, or
disclosure deadline is promised.

## Reporting a vulnerability

Use GitHub **Private Vulnerability Reporting** from the repository's **Security** tab. If that
route is unavailable or you cannot use GitHub, email `security@clidarvi.io`. Do not publish
vulnerability details in an issue, discussion, pull request, transcript, or social post.

Ordinary internet email is not guaranteed to be end-to-end encrypted. Send only a sanitized
report; never include credentials, private keys, recovery codes, real production hostnames or
addresses, raw device configurations, host keys, or sensitive command transcripts. If
unsanitized material appears necessary, first send a minimal description and ask for a suitable
transfer method.

If neither non-public route is available, open a minimal public issue asking the maintainer to
enable a private channel. Include no vulnerability or exploit detail. Replace necessary examples
with fake hostnames and RFC documentation address ranges.

A useful private report contains:

- the affected Clidarvi version and operating system;
- a minimal reproduction using fake credentials and a mock or lab device;
- the expected and observed behavior;
- the security impact and any known workaround.

Relevant areas include host-key verification, command classification, prompt handling, secret
redaction, inventory parsing, atomic persistence, worker shutdown, and transcript bounds.

Please allow the maintainers a reasonable opportunity to investigate and publish a fix before
public disclosure. This policy does not promise a bounty or a specific response deadline.

Protect your own privacy when reporting. Use fake credentials and RFC documentation addresses, and
remove personal data, employer/client information, production hostnames, configurations, keys, and
transcripts. See [PRIVACY.md](PRIVACY.md).

Clidarvi 0.1.0a1 is experimental alpha network-administration software. Its final release
artifact, Experimental Automation path, and UDM observational-diagnostics mode have not completed
real-equipment or production field testing. A single development-worktree Live CLI `uptime`
observation on an owned UDM-SE 5.1.26 is now supplemented by one dirty/unfrozen development run whose
transcript showed all four fixed diagnostics completing and whose operator reported normal post-run
network/console health. These limited observations are not final-artifact, independent device-state,
failure-path, or broader compatibility evidence. Complete the disposable-lab validation in
[docs/FIELD_TEST_CHECKLIST.md](docs/FIELD_TEST_CHECKLIST.md) and review every command plan before
allowing it to contact a real system.
