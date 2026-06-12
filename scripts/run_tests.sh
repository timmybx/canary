#!/usr/bin/env bash
# Run the project test suite in Docker (the canonical Python 3.12 environment)
# and capture the complete output to test_output.txt in the repo root.
#
# Usage (from git bash, anywhere in the repo):
#   bash scripts/run_tests.sh                          # full suite, quiet
#   bash scripts/run_tests.sh -v tests/test_webapp.py  # any pytest args
#
# test_output.txt is gitignored; it exists so the run results can be reviewed
# (or read by Claude through the connected folder) after the run finishes.

set -u

cd "$(dirname "$0")/.."

if [ "$#" -eq 0 ]; then
    set -- -q
fi

{
    echo "=== pytest run started: $(date) ==="
    echo "=== git: $(git rev-parse --short HEAD 2>/dev/null || echo 'n/a'), $(git status --porcelain 2>/dev/null | wc -l | tr -d ' ') uncommitted change(s) ==="
    echo
} | tee test_output.txt

docker compose run --rm -T canary pytest "$@" 2>&1 | tee -a test_output.txt
status=${PIPESTATUS[0]}

{
    echo
    echo "=== pytest exit code: ${status} ==="
} | tee -a test_output.txt

exit "${status}"
