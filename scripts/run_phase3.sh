#!/usr/bin/env bash
# Phase 3 end-to-end golden test (run inside docker container).
#
# 1. pytest — all unit tests (parser + config + harness_generator
#    + header_parser + secret_infer)
# 2. Phase 1 regression: manual yaml still works
# 3. Phase 2 regression: auto-generated harness yaml still works
# 4. Phase 3 NEW: `ctkat infer` against fixtures and the toy project
#    - toy header: 'secret' assigned, 'guess' unknown, 'len' scalar
#    - kem fixture: crypto_kem_dec gets kem_dec profile

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
echo "==> [Phase 2 regression] ctkat run --config examples/toy_password/ctkat_auto.yaml"
PYTHONPATH=. python -m ctkat run --config examples/toy_password/ctkat_auto.yaml
phase2_rc=$?

echo
echo "==> [Phase 3] ctkat infer --header examples/toy_password/include/compare.h"
infer_toy=$(PYTHONPATH=. python -m ctkat infer --header examples/toy_password/include/compare.h)
infer_toy_rc=$?
echo "$infer_toy"

echo
echo "==> [Phase 3] ctkat infer --header tests/fixtures/headers/kem.h --function crypto_kem_dec"
infer_kem=$(PYTHONPATH=. python -m ctkat infer --header tests/fixtures/headers/kem.h --function crypto_kem_dec)
infer_kem_rc=$?
echo "$infer_kem"

echo
echo "==> Verdict"
fail=0
if [ "$pytest_rc" -ne 0 ]; then
    echo "  [BAD]  pytest failed (rc=$pytest_rc)"; fail=1
else
    echo "  [OK]   pytest passed"
fi
if [ "$phase1_rc" -eq 2 ]; then
    echo "  [OK]   Phase 1 yaml still flags findings (rc=2)"
else
    echo "  [BAD]  Phase 1 rc=$phase1_rc (expected 2)"; fail=1
fi
if [ "$phase2_rc" -eq 2 ]; then
    echo "  [OK]   Phase 2 yaml still flags findings (rc=2)"
else
    echo "  [BAD]  Phase 2 rc=$phase2_rc (expected 2)"; fail=1
fi
# toy header: 'secret' should be assigned secret, 'guess' should be unknown
if echo "$infer_toy" | grep -q "secret" && \
   echo "$infer_toy" | grep -q "unknown" && \
   echo "$infer_toy" | grep -q "scalar"; then
    echo "  [OK]   infer on toy header: secret/unknown/scalar all present"
else
    echo "  [BAD]  infer on toy header missing expected role classes"; fail=1
fi
# kem_dec profile
if echo "$infer_kem" | grep -q "kem_dec"; then
    echo "  [OK]   infer on crypto_kem_dec: kem_dec profile detected"
else
    echo "  [BAD]  infer on crypto_kem_dec: profile not detected"; fail=1
fi

exit $fail
