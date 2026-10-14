#!/bin/sh
# Installs the adapter into a new virtual environment ($1) from locked inputs only. pip cannot
# hash-check a git requirement, so the SDK is held by its full commit and every other package by
# hash; nothing builds in an isolated environment, which would fetch unpinned build tools.
set -eu
here=$(dirname "$0")
python3 -m venv "$1"
pip="$1/bin/pip"
"$pip" install --quiet --require-hashes --no-deps -r "$here/build.lock"
"$pip" install --quiet --require-hashes --no-deps -r "$here/requirements.lock"
"$pip" install --quiet --no-deps --no-build-isolation -r "$here/dependency.requirements.txt" "$here"
