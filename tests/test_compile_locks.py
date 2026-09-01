# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 devnetdreamer (https://github.com/devnetdreamer) and Clidarvi contributors

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "compile_locks.sh"

FAKE_PYTHON = """#!/bin/sh
set -eu

log_path=${CLIDARVI_LOCK_TEST_LOG:?}
printf 'custom=%s\\tconfig=%s\\tindex=%s\\textra=%s\\tlinks=%s\\tno-index=%s\\tconstraint=%s\\targs=%s\\n' "${CUSTOM_COMPILE_COMMAND-}" "${PIP_CONFIG_FILE-}" "${PIP_INDEX_URL-}" "${PIP_EXTRA_INDEX_URL-}" "${PIP_FIND_LINKS-}" "${PIP_NO_INDEX-}" "${PIP_CONSTRAINT-}" "$*" >> "$log_path"

case "$*" in
    *sys.implementation.name*)
        printf '%s\\n' "${CLIDARVI_FAKE_RUNTIME:-cpython 3.13 final}"
        ;;
    *pip-tools*)
        printf '%s\\n' "${CLIDARVI_FAKE_PIP_TOOLS_VERSION:-7.6.1}"
        ;;
    *importlib.metadata*)
        printf '%s\\n' "${CLIDARVI_FAKE_PIP_VERSION:-26.2.1}"
        ;;
esac
"""


@unittest.skipIf(os.name == "nt", "POSIX lock compiler script")
class CompileLocksScriptTests(unittest.TestCase):
    EXPECTED_COMPILE_PREFIX = (
        "custom=scripts/compile_locks.sh\tconfig=/dev/null\t"
        "index=https://pypi.org/simple\textra=\tlinks=\tno-index=\tconstraint=\targs="
    )

    def _run(
        self,
        *arguments: str,
        pip_version: str = "26.2.1",
        pip_tools_version: str = "7.6.1",
        runtime: str = "cpython 3.13 final",
    ) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        with tempfile.TemporaryDirectory() as temporary_directory:
            checkout = Path(temporary_directory)
            scripts = checkout / "scripts"
            scripts.mkdir()
            script = scripts / SCRIPT.name
            shutil.copy2(SCRIPT, script)
            script.chmod(0o755)

            fake_bin = checkout / "fake-bin"
            fake_bin.mkdir()
            fake_python = fake_bin / "python"
            fake_python.write_text(FAKE_PYTHON, encoding="utf-8")
            fake_python.chmod(0o755)

            log_path = checkout / "python-calls.log"
            environment = os.environ.copy()
            environment["PATH"] = os.pathsep.join((str(fake_bin), environment.get("PATH", "")))
            environment["CLIDARVI_LOCK_TEST_LOG"] = str(log_path)
            environment["CLIDARVI_FAKE_PIP_VERSION"] = pip_version
            environment["CLIDARVI_FAKE_PIP_TOOLS_VERSION"] = pip_tools_version
            environment["CLIDARVI_FAKE_RUNTIME"] = runtime
            environment["PIP_CONFIG_FILE"] = str(checkout / "ambient-pip.conf")
            environment["PIP_INDEX_URL"] = "https://mirror.invalid/simple"
            environment["PIP_EXTRA_INDEX_URL"] = "https://extra.invalid/simple"
            environment["PIP_FIND_LINKS"] = str(checkout / "ambient-wheels")
            environment["PIP_NO_INDEX"] = "1"
            environment["PIP_CONSTRAINT"] = str(checkout / "ambient-constraints.txt")

            result = subprocess.run(
                [str(script), *arguments],
                cwd=checkout,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            calls = log_path.read_text(encoding="utf-8").splitlines() if log_path.exists() else []
        return result, calls

    @staticmethod
    def _compile_calls(calls: list[str]) -> list[str]:
        return [call for call in calls if "\targs=-m piptools compile " in call]

    def test_default_regeneration_uses_canonical_header_without_upgrade(self):
        result, calls = self._run()

        self.assertEqual(result.returncode, 0, result.stderr)
        compile_calls = self._compile_calls(calls)
        self.assertEqual(len(compile_calls), 3)
        self.assertTrue(
            all(call.startswith(self.EXPECTED_COMPILE_PREFIX) for call in compile_calls)
        )
        self.assertTrue(all("--upgrade" not in call for call in compile_calls))

    def test_explicit_upgrade_reaches_all_three_lock_compilations(self):
        result, calls = self._run("--upgrade")

        self.assertEqual(result.returncode, 0, result.stderr)
        compile_calls = self._compile_calls(calls)
        self.assertEqual(len(compile_calls), 3)
        self.assertTrue(all("--upgrade" in call for call in compile_calls))
        self.assertTrue(
            all(call.startswith(self.EXPECTED_COMPILE_PREFIX) for call in compile_calls)
        )

    def test_invalid_empty_and_extra_arguments_fail_before_python(self):
        for arguments in (("",), ("--invalid",), ("--upgrade", "extra")):
            with self.subTest(arguments=arguments):
                result, calls = self._run(*arguments)

                self.assertEqual(result.returncode, 2)
                self.assertIn("usage: scripts/compile_locks.sh [--upgrade]", result.stderr)
                self.assertEqual(calls, [])

    def test_pip_version_must_match_exactly(self):
        result, _calls = self._run(pip_version="126.2.10")

        self.assertEqual(result.returncode, 1)
        self.assertIn("pip 26.2.1 is required (found: 126.2.10)", result.stderr)

    def test_pip_tools_version_must_match_exactly(self):
        result, _calls = self._run(pip_tools_version="17.6.10")

        self.assertEqual(result.returncode, 1)
        self.assertIn("pip-tools 7.6.1 is required (found: 17.6.10)", result.stderr)

    def test_runtime_must_be_final_cpython_313(self):
        for runtime in ("pypy 3.13 final", "cpython 3.13 beta"):
            with self.subTest(runtime=runtime):
                result, _calls = self._run(runtime=runtime)

                self.assertEqual(result.returncode, 1)
                self.assertIn(
                    f"locks require final CPython 3.13 (found: {runtime})",
                    result.stderr,
                )


if __name__ == "__main__":
    unittest.main()
