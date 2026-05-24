#!/usr/bin/env bash
# Golden test for Phase 0:
#   1. build both harnesses
#   2. run Valgrind on each
#   3. assert: bad_compare leaks (exit 99), safe_compare clean (exit 0)
#
# Run this INSIDE the docker container (valgrind not available on macOS host).

set -uo pipefail

cd "$(dirname "$0")/../examples/toy_password"

echo "==> make clean && make"
make clean >/dev/null
make

VG=(valgrind --tool=memcheck --track-origins=yes --error-exitcode=99 -q)

mkdir -p reports

echo
echo "==> Valgrind on harness_bad (expected: FAIL / exit 99)"
"${VG[@]}" --log-file=reports/bad.log ./build/harness_bad
bad_rc=$?
echo "    exit code: $bad_rc"

echo
echo "==> Valgrind on harness_safe (expected: PASS / exit 0)"
"${VG[@]}" --log-file=reports/safe.log ./build/harness_safe
safe_rc=$?
echo "    exit code: $safe_rc"

echo
echo "==> Verdict"
fail=0
if [ "$bad_rc" -eq 99 ]; then
    echo "  [OK]   bad_compare flagged by Valgrind"
else
    echo "  [BAD]  bad_compare NOT flagged (rc=$bad_rc) — Valgrind didn't catch the leak"
    fail=1
fi

if [ "$safe_rc" -eq 0 ]; then
    echo "  [OK]   safe_compare clean"
else
    echo "  [BAD]  safe_compare flagged (rc=$safe_rc) — false positive"
    fail=1
fi

echo
echo "Logs:"
echo "  examples/toy_password/reports/bad.log"
echo "  examples/toy_password/reports/safe.log"

exit $fail
