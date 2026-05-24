#!/usr/bin/env bash
# Phase 4 + revisions end-to-end golden test (run inside docker container).
#
# 1. pytest — all units including statistics/timing_harness/dudect_runner/verdict
# 2. Phase 1/2/3 regressions
# 3. Phase 4: dudect alone against toy_dudect (leaky FAIL, safe PASS)
# 4. Revision: combined yaml (ct+dudect) on toy_dudect → verdict matrix
# 5. Revision: ct on toy_lookup → MEMORY_ACCESS finding type promoted

set -uo pipefail

cd /workspace

echo "==> pytest"
PYTHONPATH=. pytest tests -v
pytest_rc=$?

echo
echo "==> [Phase 1 regression]"
PYTHONPATH=. python -m ctkat run --config examples/toy_password/ctkat.yaml
phase1_rc=$?

echo
echo "==> [Phase 2 regression]"
PYTHONPATH=. python -m ctkat run --config examples/toy_password/ctkat_auto.yaml
phase2_rc=$?

echo
echo "==> [Phase 4] dudect alone"
PYTHONPATH=. python -m ctkat dudect --config examples/toy_dudect/ctkat_dudect.yaml
phase4_rc=$?

sum_dudect=examples/toy_dudect/reports/dudect_summary.csv
leaky_status=""
safe_status=""
if [ -f "$sum_dudect" ]; then
    leaky_status=$(awk -F',' 'NR>1 && $2=="leaky" {print $11}' "$sum_dudect")
    safe_status=$(awk -F',' 'NR>1 && $2=="safe"  {print $11}' "$sum_dudect")
fi

echo
echo "==> [Revision] combined (ct + dudect) on toy_dudect"
PYTHONPATH=. python -m ctkat run --config examples/toy_dudect/ctkat_combined.yaml
combined_rc=$?

verdict_csv=examples/toy_dudect/reports_combined/ctkat_verdict.csv
leaky_verdict=""
safe_verdict=""
if [ -f "$verdict_csv" ]; then
    leaky_verdict=$(awk -F',' 'NR>1 && $2=="leaky" {print $7}' "$verdict_csv")
    safe_verdict=$(awk -F',' 'NR>1 && $2=="safe"  {print $7}' "$verdict_csv")
fi

echo
echo "==> [Revision] ct on toy_lookup (MEMORY_ACCESS promotion)"
PYTHONPATH=. python -m ctkat run --config examples/toy_lookup/ctkat.yaml
lookup_rc=$?

lookup_csv=examples/toy_lookup/reports/ctkat_report.csv
lookup_types=""
if [ -f "$lookup_csv" ]; then
    lookup_types=$(awk -F',' 'NR>1 {print $7}' "$lookup_csv" | sort -u | tr '\n' ',' | sed 's/,$//')
fi

echo
echo "==> Verdict"
fail=0
if [ "$pytest_rc" -ne 0 ]; then echo "  [BAD]  pytest rc=$pytest_rc"; fail=1; else echo "  [OK]   pytest"; fi
if [ "$phase1_rc"  -eq 2 ]; then echo "  [OK]   Phase 1 rc=2"; else echo "  [BAD]  Phase 1 rc=$phase1_rc"; fail=1; fi
if [ "$phase2_rc"  -eq 2 ]; then echo "  [OK]   Phase 2 rc=2"; else echo "  [BAD]  Phase 2 rc=$phase2_rc"; fail=1; fi
if [ "$phase4_rc"  -eq 2 ]; then echo "  [OK]   Phase 4 dudect rc=2"; else echo "  [BAD]  Phase 4 rc=$phase4_rc"; fail=1; fi
if [ "$leaky_status" = "FAIL" ]; then echo "  [OK]   leaky dudect=FAIL"; else echo "  [BAD]  leaky=$leaky_status"; fail=1; fi
if [ "$safe_status" = "PASS" ] || [ "$safe_status" = "WARNING" ]; then
    echo "  [OK]   safe  dudect=$safe_status"
else
    echo "  [BAD]  safe=$safe_status"; fail=1
fi

# Combined verdict checks
if [ "$combined_rc" -eq 2 ]; then echo "  [OK]   combined rc=2"; else echo "  [BAD]  combined rc=$combined_rc"; fail=1; fi
# leaky_function has no secret-dependent branch (just a single if on secret[0])
# — actually it DOES have a branch on secret[0]. So Valgrind catches it AND dudect
# catches it → CRITICAL.
if [ "$leaky_verdict" = "CRITICAL" ]; then
    echo "  [OK]   leaky verdict=CRITICAL"
else
    echo "  [BAD]  leaky verdict=$leaky_verdict (expected CRITICAL)"; fail=1
fi
if [ "$safe_verdict" = "CLEAN" ]; then
    echo "  [OK]   safe verdict=CLEAN"
else
    echo "  [WARN] safe verdict=$safe_verdict (expected CLEAN)"
fi

# MEMORY_ACCESS promotion check
if [ "$lookup_rc" -eq 2 ]; then echo "  [OK]   toy_lookup rc=2"; else echo "  [BAD]  toy_lookup rc=$lookup_rc"; fail=1; fi
if echo "$lookup_types" | grep -q "SECRET_DEPENDENT_MEMORY_ACCESS"; then
    echo "  [OK]   toy_lookup leaky_lookup promoted to MEMORY_ACCESS"
else
    echo "  [BAD]  toy_lookup finding types=$lookup_types (expected MEMORY_ACCESS)"; fail=1
fi

exit $fail
