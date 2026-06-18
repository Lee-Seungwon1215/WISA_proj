#!/usr/bin/env bash
# Re-run the structural analyses on each corpus target and rebuild
# docs/corpus/{corpus_cells,corpus_summary}.csv.
#
# ⚠ NEEDS a Linux/Docker amd64 environment with valgrind + gcc-13/clang-18 +
#   objdump. It is NOT run in CI and was NOT executed when this script was
#   authored — treat it as the documented, reproducible recipe for the
#   otherwise-uncommitted Stage-A flow, and review its output before committing.
#
# ⚠ It deliberately does NOT regenerate docs/corpus/dudect_appendix.csv — that is
#   a FROZEN snapshot of one large (50k-measurement) dudect run. dudect is
#   non-reproducible run-to-run (TSC skew under QEMU). Refresh it by hand only,
#   deliberately.
set -euo pipefail
cd "$(dirname "$0")/.."

CCV=(--cc-version "gcc=13.3.0" --cc-version "clang=18.1.3")
ARCH="x86_64"
COMMIT="$(git rev-parse --short HEAD)"
if ! git diff --quiet || ! git diff --cached --quiet; then
  COMMIT="${COMMIT}-dirty"
fi
OUT="docs/corpus"
ASM_OPTS=(--opt -O0 --opt -O1 --opt -O2 --opt -O3 --opt -Os)

run_target() {  # <project-dir> <family> <target> [extra build_corpus_table args...]
  local dir="$1" family="$2" target="$3"; shift 3
  # Only the REPRODUCIBLE structural layers are re-run: ct-matrix (Valgrind) and
  # asm-scan (objdump). We deliberately do NOT re-run `ctkat dudect` — dudect is
  # timing-keyed and non-reproducible (TSC skew under QEMU), so its numbers in the
  # corpus (corpus_summary dudect_* columns AND dudect_appendix.csv) are FROZEN
  # snapshots; re-running here would silently change curated timing values.
  echo "[refresh] $target : ctkat ct-matrix + asm-scan (Docker) ..."
  # Fail closed: if either structural layer errors, stop before build_corpus_table
  # can merge stale/partial reports into the committed corpus CSVs.
  python3 -m ctkat ct-matrix  --config "$dir/ctkat.yaml"   # reports/ctkat_ct_matrix.csv
  python3 -m ctkat asm-scan   --config "$dir/ctkat.yaml" "${ASM_OPTS[@]}" --cc gcc --cc clang
  echo "[refresh] $target : build_corpus_table ..."
  python3 scripts/build_corpus_table.py \
    --project-dir "$dir" --family "$family" --target "$target" \
    --arch "$ARCH" --ctkat-commit "$COMMIT" "${CCV[@]}" --out-dir "$OUT" "$@"
}

# Per-target triage / manual verdict overrides (the human-judgment layer that the
# auto-classifier cannot derive — kept here so the corpus is reproducible).
SPHINCS_NOTE="sign=SPHINCS+ attribution review: treehashx1 (utilsx1.c:67 auth-path sibling check) and wots_gen_leafx1 (wotsx1.c:28 signing leaf selection, wotsx1.c:57 WOTS chain step save) are conditioned on signature/public state derived during signing, not accepted as function-wide safe names. R is computed from SK_PRF at sign.c:124 and is published in the signature; hash_message at sign.c:127 derives mhash/tree/idx_leaf from R, pk, and m. Split-taint probes show that SK_PRF, PUB_SEED, root, and full-sk taints surface the same tree/WOTS branch family, while SK_SEED-only leaves only the WOTS chain-save branch. A declassification probe that marks R, mhash, tree, idx_leaf, and intermediate roots public before tree/WOTS traversal clears the findings. This override is narrow to this harness/data flow; do not register treehashx1 or wots_gen_leafx1 wholesale."

run_target examples/pqc_mlkem512            ML-KEM    pqclean_mlkem512            --triage kem_dec=public --triage kem_dec_fo=public
run_target examples/pqc_mlkem768            ML-KEM    pqclean_mlkem768            --triage kem_dec=public --triage kem_dec_fo=public
run_target examples/pqc_mlkem1024           ML-KEM    pqclean_mlkem1024           --triage kem_dec=public --triage kem_dec_fo=public
run_target examples/pqc_mlkem768_kyberslash ML-KEM    pqclean_mlkem768_kyberslash --triage kem_dec=secret-risk
run_target examples/pqc_mldsa44             ML-DSA    pqclean_mldsa44             --triage sign=public --verdict sign=accepted-variable-time --note "sign=debug/no-inline cells localize accepted ML-DSA rejection/public-output timing; optimized crypto_sign_signature_ctx is reviewed as coarse parent-frame attribution, not registered wholesale"
run_target examples/pqc_mldsa65             ML-DSA    pqclean_mldsa65             --triage sign=public --verdict sign=accepted-variable-time --note "sign=debug/no-inline cells localize accepted ML-DSA rejection/public-output timing; optimized crypto_sign_signature_ctx is reviewed as coarse parent-frame attribution, not registered wholesale"
run_target examples/pqc_mldsa87             ML-DSA    pqclean_mldsa87             --triage sign=public --verdict sign=accepted-variable-time --note "sign=debug/no-inline cells localize accepted ML-DSA rejection/public-output timing; optimized crypto_sign_signature_ctx is reviewed as coarse parent-frame attribution, not registered wholesale"
run_target examples/pqc_sphincs_sha2_128f_simple SPHINCS+ pqclean_sphincs_sha2_128f_simple --triage sign=public --verdict sign=accepted-variable-time --note "$SPHINCS_NOTE"
run_target examples/pqc_falcon512           Falcon    pqclean_falcon512
run_target examples/toy_lookup              synthetic toy_lookup                 --verdict leaky=ct-leak   # manual confirmed leak
run_target examples/ct_matrix_flip          synthetic ct_matrix_flip             # build-sensitive auto

echo "[refresh] corpus CSVs rebuilt under $OUT/ (dudect_appendix.csv left untouched)."
