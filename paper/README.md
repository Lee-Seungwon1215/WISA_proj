# WISA paper — LaTeX source (Springer LNCS)

Camera-ready source for the WISA poster-track paper
**"Build-Configuration-Aware, Triage-Aware Constant-Time Screening for
Post-Quantum Cryptography."** 12-page LNCS limit.

## Upload to Overleaf

This folder is self-contained — `llncs.cls` and `splncs04.bst` are bundled, so it
compiles without picking a template.

1. Zip the `paper/` folder (or drag the files into a new blank Overleaf project).
2. Set the main document to `main.tex`, compiler **pdfLaTeX**.
3. Overleaf runs `pdflatex → bibtex → pdflatex → pdflatex` automatically.

Local build from the repository root (if you have a TeX distro):

```bash
scripts/reproduce_paper_tables.sh
scripts/build_paper_pdf.sh
```

`build_paper_pdf.sh` uses `pdflatex -> bibtex -> pdflatex -> pdflatex` when both
commands are installed. If not, it falls back to `tectonic` when available.

## Layout

```
main.tex              preamble + title + table floats + Fig.1 + \input glue
generated/            AUTO-GENERATED table bodies + macros (do NOT hand-edit)
references.bib        12 citations — source-checked 2026-06-09
figures/pipeline.tex  TikZ pipeline diagram (Fig.1)
sections/             one .tex per section (abstract, 00_intro … 06_conclusion)
llncs.cls             Springer LNCS class (bundled, v2.26)
splncs04.bst          LNCS BibTeX style (bundled)
```

## Source of truth for the numbers

Every numeric table in the paper is rendered from committed corpus CSVs:

- `../docs/corpus/corpus_summary.csv` → verdict-class corpus + ablation rows
- `../docs/corpus/dudect_appendix.csv` → dudect appendix + timing macros
- `../docs/corpus/corpus_cells.csv` → coverage evidence + ML-DSA attribution

The numbers are **single-sourced** (Phase 2): corpus, ablation, ML-DSA, dudect,
and every duplicated dudect figure / percentage / cardinality are generated from
the CSVs into `paper/generated/*.tex`, which `main.tex` and
`sections/04_results.tex` `\input` / use as `\newcommand` macros. Do NOT edit the
numbers in the `.tex` by hand — edit the CSV and regenerate:

```bash
python3 scripts/render_paper_tables.py            # CSV -> paper/generated/*.tex
python3 -m pytest tests/test_paper_corpus_sync.py # FAILS if paper != CSV
```

`tests/test_paper_corpus_sync.py` is the enforced contract (CI fails on any
paper↔CSV drift) — the old "CSV wins, update by hand" honor system is now a test.
`scripts/reproduce_paper_tables.sh` runs both steps. Rebuilding the CSVs from
scratch (re-running the constant-time analyses) is `scripts/refresh_corpus_docker.sh`
(Docker-only; it never touches the frozen `dudect_appendix.csv`).

## Before camera-ready (author checklist)

- [ ] Real author name(s) + ORCID in `main.tex` (currently placeholder).
- [x] Source-check all 12 references in `references.bib`; final human eyeball
      pass still recommended before camera-ready.
- [x] Keep `paper/main.pdf` within the 12-page LNCS target; it currently builds
      to 11 pages after compression.
- [x] Keep Table 1 as the single-coverage headline; the ablation/miss evidence
      is added as a supporting generated table, not a replacement.
- [x] Avoid "complete" as a framework claim; use "layer-justified in this
      corpus" / "validated on the corpus".
- [x] Promote ML-DSA per-cell attribution into a compact generated table:
      debug cells show registered rejection functions, optimized cells surface
      `crypto_sign_signature_ctx` / `pack_sig`.
- [ ] Confirm the dudect numbers natively (`taskset -c 0`, freq scaling off) —
      blocked on this macOS/arm64 workspace; use a native Linux/x86_64 or target
      machine. The corpus run was under QEMU/Docker; see Table 5 caveat.
- [x] Visual PDF pass: Fig.1 and Tables 1--5 render without overflow; Fig.1 is
      small but readable, and further polishing is optional rather than blocking.
