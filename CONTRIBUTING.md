# Contributing to Clidarvi

Thanks for helping improve this open-source project. Safety-related fixes, tests, documentation,
and carefully scoped platform support are especially welcome.

## Before opening a pull request

1. Open or reference an issue for behavior-changing work.
2. Keep changes focused and explain the network-safety impact.
3. Use fake credentials and documentation IP ranges in tests and examples.
4. Never commit inventories, known-host files, raw configurations, logs, transcripts, tokens, or
   private keys.
5. Add or update tests for changed behavior.
6. Treat dependency updates as code changes: review every upstream release, artifact, license,
   advisory, version diff, and hash-only diff; regenerate every applicable lock and the SBOM; run
   the complete gate; and never merge an automated dependency update without human review.

Run `scripts/compile_locks.sh` in a disposable CPython 3.13 environment installed from the hashed
`requirements-lock/build.txt` to reproduce existing pins. Use `scripts/compile_locks.sh --upgrade`
only for an intentional refresh of every compatible dependency, followed by complete diff review.
The script rejects non-final or non-CPython runtimes, ignores ambient pip configuration, and resolves
binary artifacts only through official PyPI. Generated lock headers deliberately show the stable
no-option replay command; record use of `--upgrade` and the reviewed refresh rationale in the change
history or pull request.

Run these baseline contributor checks. Before a public-source or packaged release, also complete
the [full release quality and security gate](docs/RELEASE_CHECKLIST.md#local-quality-and-security-gate):

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
python3 -m build --no-isolation
```

## Safety expectations

- Unknown behavior must fail closed, especially for host keys, command classification, prompts,
  and persistence.
- Do not add Telnet or silently disable SSH host-key verification.
- Destructive actions must require explicit user intent.
- Logs and exceptions must not expose credentials.
- Network tests must use mocks or equipment you are authorized to control.
- A change that adds network traffic, telemetry, analytics, crash reporting, updates, or an external
  service must explicitly update `PRIVACY.md`, the operational-risk review, and relevant tests.
- Do not claim real-device compatibility based only on mocks. Record representative disposable-lab
  results using [docs/FIELD_TEST_CHECKLIST.md](docs/FIELD_TEST_CHECKLIST.md).

Report vulnerabilities through the private route in [SECURITY.md](SECURITY.md), not through a
public issue.

Clidarvi 0.1.0a1 is an experimental alpha whose final artifact, Experimental Automation path, and
UDM observational-diagnostics mode have no completed real-equipment or production field-test
evidence. The single development Live CLI observation and one later dirty/unfrozen development
run of the four-command preset on an
owned UDM-SE 5.1.26 are deliberately not treated as release evidence, even though the operator
reported normal post-run network/console health. Contributions and automated checks do not change
that status unless the documented promotion criteria are completed and reviewed.

## Contribution license

By submitting a contribution, you represent that you created it or otherwise have every right and
permission needed to submit it; that it contains no confidential, proprietary, personal, or
unauthorized material; and that it may be published under GPL-3.0-only with the rest of Clidarvi.
You retain copyright in your contribution. Do not submit third-party code, documentation, data, or
artwork unless its license is compatible and all required attribution and license material are
included.
