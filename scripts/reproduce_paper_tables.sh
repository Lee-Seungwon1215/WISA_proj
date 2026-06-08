#!/usr/bin/env bash
# Phase 2 (deterministic path): regenerate the paper's data tables + macros from
# the committed corpus CSVs and verify the paper is in sync with them.
#
# Pure CSV -> tables + a consistency test. NO valgrind / NO Docker — runs anywhere
# including CI. It does NOT re-run the constant-time analyses (that is Stage A,
# Docker-only; see scripts/refresh_corpus_docker.sh) and NEVER touches
# docs/corpus/*.csv or docs/corpus/dudect_appendix.csv (a frozen snapshot).
set -euo pipefail
cd "$(dirname "$0")/.."

# 1) Audit the COMMITTED tree first — this is the real drift check (it runs
#    against the snippets as committed, before we overwrite them). This is the
#    same assertion CI runs; a failure here means the committed generated files
#    are stale vs the CSVs and someone forgot to regenerate.
echo "[reproduce] auditing committed paper == corpus (the drift check) ..."
if python3 -m pytest -q tests/test_paper_corpus_sync.py; then
  echo "[reproduce] committed tree already in sync."
else
  echo "[reproduce] committed tree was STALE — regenerating below; review the git diff."
fi

# 2) Regenerate from the CSVs and re-verify.
echo "[reproduce] rendering paper/generated/*.tex from docs/corpus/*.csv ..."
python3 scripts/render_paper_tables.py
echo "[reproduce] re-verifying after regeneration ..."
python3 -m pytest -q tests/test_paper_corpus_sync.py

echo "[reproduce] OK — generated snippets in sync with docs/corpus/*.csv."
echo "[reproduce] NOTE: recompile paper/main.tex (pdflatex) to refresh the PDF."
