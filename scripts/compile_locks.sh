#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 devnetdreamer (https://github.com/devnetdreamer) and Clidarvi contributors
# Regenerate Clidarvi's pinned CPython 3.13 dependency snapshots.
#
# Bootstrap once in a disposable Python 3.13 environment with:
#   python -m pip install --require-hashes --only-binary=:all: \
#     -r requirements-lock/build.txt
# Then run this script from anywhere inside the repository. Pass ``--upgrade``
# only for an explicit dependency refresh. Review every diff; lock regeneration
# is intentionally never automatic or auto-merged.
set -eu

usage() {
    echo "usage: scripts/compile_locks.sh [--upgrade]" >&2
    exit 2
}

case "$#" in
    0) upgrade_flag= ;;
    1)
        [ "$1" = "--upgrade" ] || usage
        upgrade_flag=--upgrade
        ;;
    *) usage ;;
esac

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

python_runtime=$(python -c 'import sys; print(f"{sys.implementation.name} {sys.version_info.major}.{sys.version_info.minor} {sys.version_info.releaselevel}")')
if [ "$python_runtime" != "cpython 3.13 final" ]; then
    echo "error: locks require final CPython 3.13 (found: $python_runtime)" >&2
    exit 1
fi

pip_version=$(python -c 'import importlib.metadata; print(importlib.metadata.version("pip"))')
if [ "$pip_version" != "26.2.1" ]; then
    echo "error: pip 26.2.1 is required (found: $pip_version)" >&2
    exit 1
fi

pip_tools_version=$(python -c 'import importlib.metadata; print(importlib.metadata.version("pip-tools"))')
[ "$pip_tools_version" = "7.6.1" ] || {
    echo "error: pip-tools 7.6.1 is required (found: $pip_tools_version)" >&2
    exit 1
}

# Resolve only against official PyPI, independent of ambient pip configuration,
# extra indexes, find-links directories, constraints, or target overrides.
export PIP_CONFIG_FILE=/dev/null
export PIP_INDEX_URL=https://pypi.org/simple
unset PIP_EXTRA_INDEX_URL PIP_FIND_LINKS PIP_NO_INDEX PIP_TRUSTED_HOST
unset PIP_CONSTRAINT PIP_BUILD_CONSTRAINT PIP_REQUIREMENT PIP_PRE
unset PIP_PLATFORM PIP_PYTHON_VERSION PIP_IMPLEMENTATION PIP_ABI PIP_NO_BINARY PIP_ONLY_BINARY

# Keep the generated header canonical so a later non-upgrading regeneration
# does not change lock bytes solely because the refresh mode is no longer set.
export CUSTOM_COMPILE_COMMAND="scripts/compile_locks.sh"

compile_lock() {
    input_file=$1
    output_file=$2
    python -m piptools compile \
        --allow-unsafe \
        --generate-hashes \
        --no-emit-index-url \
        --pip-args='--only-binary=:all: --index-url=https://pypi.org/simple' \
        --quiet \
        --resolver=backtracking \
        --strip-extras \
        ${upgrade_flag:+"$upgrade_flag"} \
        --output-file "$output_file" \
        "$input_file"
}

compile_lock requirements-lock/runtime.in requirements-lock/runtime-py313.txt
compile_lock requirements-lock/build.in requirements-lock/build.txt
compile_lock requirements-lock/dev.in requirements-lock/dev-py313.txt

python scripts/generate_sbom.py
