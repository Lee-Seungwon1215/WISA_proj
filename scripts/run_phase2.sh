#!/usr/bin/env bash
# Phase 2 end-to-end golden test (run inside docker container).
#
# 1. pytest — parser + config + harness_generator unit tests
# 2. Phase 1 regression: existing manual yaml still works
# 3. Phase 2 new: auto-generated harness yaml produces same verdict
#    (bad_auto FAIL, safe_auto PASS)
# 4. Verify generated .c file exists and contains taint markers.

set -uo pipefail

cd /workspace

echo "==> pytest"
PYTHONPATH=. pytest tests -v
pytest_rc=$?

echo
echo "==> [Phase 1 regression] ctkat run --config examples/toy_password/ctkat.yaml"
PYTHONPATH=. python -m ctkat run --config examples/toy_password/ctkat.yaml
phase1_rc=$?

echo
echo "==> [Phase 2] ctkat run --config examples/toy_password/ctkat_auto.yaml"
PYTHONPATH=. python -m ctkat run --config examples/toy_password/ctkat_auto.yaml
phase2_rc=$?

echo
echo "==> Generated source check"
gen_src=examples/toy_password/_generated/harness_bad_auto.c
gen_bin=examples/toy_password/_generated/harness_bad_auto
gen_ok=1
if [ -f "$gen_src" ]; then
    if grep -q "VALGRIND_MAKE_MEM_UNDEFINED(secret" "$gen_src" && \
       grep -q "bad_compare(secret, guess" "$gen_src"; then
        echo "  [OK]   $gen_src has taint markers and target call"
    else
        echo "  [BAD]  $gen_src missing expected content"
        gen_ok=0
    fi
else
    echo "  [BAD]  generated source missing: $gen_src"
    gen_ok=0
fi
if [ -x "$gen_bin" ]; then
    echo "  [OK]   $gen_bin compiled"
else
    echo "  [BAD]  generated binary missing/not-executable: $gen_bin"
    gen_ok=0
fi

echo
echo "==> Phase 2 CSV head"
csv=examples/toy_password/reports_auto/ctkat_report.csv
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
if [ "$phase1_rc" -eq 2 ]; then
    echo "  [OK]   Phase 1 yaml still flags findings (rc=2)"
else
    echo "  [BAD]  Phase 1 yaml rc=$phase1_rc (expected 2)"
    fail=1
fi
if [ "$phase2_rc" -eq 2 ]; then
    echo "  [OK]   Phase 2 auto yaml flags findings (rc=2)"
else
    echo "  [BAD]  Phase 2 auto yaml rc=$phase2_rc (expected 2)"
    fail=1
fi
if [ "$gen_ok" -ne 1 ]; then
    fail=1
fi

exit $fail
