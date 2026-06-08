#!/usr/bin/env bash
# Phase 2 (Docker path — STAGE A→B): re-run the constant-time analyses on each
# corpus target and rebuild docs/corpus/{corpus_cells,corpus_summary}.csv.
#
# ⚠ NEEDS a Linux/Docker amd64 environment with valgrind + gcc-13/clang-18 +
#   objdump. It is NOT run in CI and was NOT executed when this script was
#   authored — treat it as the documented, reproducible recipe for the
#   otherwise-uncommitted Stage-A flow, and review its output before committing.
#
# ⚠ It deliberately does NOT regenerate docs/corpus/dudect_appendix.csv — that is
#   a FROZEN snapshot of one large (50k-measurement) dudect run. dudect is
#   non-reproducible run-to-run (TSC skew under QEMU), so re-running it would
#   change the paper's appendix numbers. Refresh it by hand only, deliberately.
#
# After this, run scripts/reproduce_paper_tables.sh to re-render the paper tables
# from the refreshed CSVs and verify sync.
set -euo pipefail
cd "$(dirname "$0")/.."

CCV=(--cc-version "gcc=13.3.0" --cc-version "clang=18.1.3")
ARCH="x86_64"
COMMIT="$(git rev-parse --short HEAD)"
OUT="docs/corpus"

run_target() {  # <project-dir> <family> <target> [extra build_corpus_table args...]
  local dir="$1" family="$2" target="$3"; shift 3
  # Only the REPRODUCIBLE structural layers are re-run: ct-matrix (Valgrind) and
  # asm-scan (objdump). We deliberately do NOT re-run `ctkat dudect` — dudect is
  # timing-keyed and non-reproducible (TSC skew under QEMU), so its numbers in the
  # corpus (corpus_summary dudect_* columns AND dudect_appendix.csv) are FROZEN
  # snapshots; re-running here would silently change the paper's t-statistics.
  echo "[refresh] $target : ctkat ct-matrix + asm-scan (Docker) ..."
  # Fail closed: if either structural layer errors, stop before build_corpus_table
  # can merge stale/partial reports into the committed corpus CSVs.
  python3 -m ctkat ct-matrix  --config "$dir/ctkat.yaml"   # reports/ctkat_ct_matrix.csv
  python3 -m ctkat asm-scan   --config "$dir/ctkat.yaml" --cc gcc --cc clang
  echo "[refresh] $target : build_corpus_table ..."
  python3 scripts/build_corpus_table.py \
    --project-dir "$dir" --family "$family" --target "$target" \
    --arch "$ARCH" --ctkat-commit "$COMMIT" "${CCV[@]}" --out-dir "$OUT" "$@"
}

# Per-target triage / manual verdict overrides (the human-judgment layer that the
# auto-classifier cannot derive — kept here so the corpus is reproducible).
run_target examples/pqc_mlkem768            ML-KEM    pqclean_mlkem768            --triage kem_dec=public
run_target examples/pqc_mlkem768_kyberslash ML-KEM    pqclean_mlkem768_kyberslash --triage kem_dec=secret-risk
run_target examples/pqc_mldsa65             ML-DSA    pqclean_mldsa65             # registry handles ML-DSA -> needs-analysis
run_target examples/toy_lookup              synthetic toy_lookup                 --verdict leaky=ct-leak   # manual confirmed leak
run_target examples/ct_matrix_flip          synthetic ct_matrix_flip             # build-sensitive auto

echo "[refresh] corpus CSVs rebuilt under $OUT/ (dudect_appendix.csv left untouched)."
echo "[refresh] next: scripts/reproduce_paper_tables.sh  (re-render + verify sync)."
