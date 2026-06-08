#!/usr/bin/env bash
# Compile the LNCS paper locally from the repo root. Keep this separate from
# reproduce_paper_tables.sh: table reproduction is deterministic/CI-safe, while
# LaTeX depends on a local TeX distribution.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 scripts/render_paper_tables.py
python3 -m pytest -q tests/test_paper_corpus_sync.py

cd paper
if command -v pdflatex >/dev/null 2>&1 && command -v bibtex >/dev/null 2>&1; then
  pdflatex -interaction=nonstopmode -halt-on-error main
  bibtex main
  pdflatex -interaction=nonstopmode -halt-on-error main
  pdflatex -interaction=nonstopmode -halt-on-error main
elif command -v tectonic >/dev/null 2>&1; then
  tectonic -k --keep-logs main.tex
else
  echo "[paper] no LaTeX engine found. Install MacTeX/TeX Live for pdflatex+bibtex," >&2
  echo "[paper] install tectonic, or upload paper/ to Overleaf and select pdfLaTeX." >&2
  exit 2
fi

echo "[paper] wrote paper/main.pdf"
