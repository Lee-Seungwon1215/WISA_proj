#!/usr/bin/env bash
# Phase 1 end-to-end golden test (run inside docker container).
#
# 1. pytest — parser/config unit tests
# 2. ctkat run against examples/toy_password — should:
#      - build PASS
#      - CT check FAIL (bad harness leaks)
#      - exit code 2 (findings present in some harness)
#      - CSV/JSON report written

set -uo pipefail

cd /workspace

echo "==> pytest"
PYTHONPATH=. pytest tests -v
pytest_rc=$?

echo
echo "==> ctkat run --config examples/toy_password/ctkat.yaml"
PYTHONPATH=. python -m ctkat run --config examples/toy_password/ctkat.yaml
ctkat_rc=$?

echo
echo "==> CSV head"
csv=examples/toy_password/reports/ctkat_report.csv
if [ -f "$csv" ]; then
    head -n 5 "$csv"
else
    echo "  (missing: $csv)"
fi

echo
echo "==> Verdict"
fail=0
if [ "$pytest_rc" -ne 0 ]; then
    echo "  [BAD]  pytest failed (rc=$pytest_rc)"
    fail=1
else
    echo "  [OK]   pytest passed"
fi
# ctkat exit 2 == findings detected → expected for bad harness
if [ "$ctkat_rc" -eq 2 ]; then
    echo "  [OK]   ctkat run flagged findings as expected (rc=2)"
else
    echo "  [BAD]  ctkat run rc=$ctkat_rc (expected 2)"
    fail=1
fi

exit $fail
