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

Local build (if you have a TeX distro):

```bash
pdflatex main && bibtex main && pdflatex main && pdflatex main
```

## Layout

```
main.tex              preamble + title + the 3 table floats + Fig.1 + \input glue
generated/            AUTO-GENERATED table bodies + macros (do NOT hand-edit)
references.bib        12 citations — VERIFY each before camera-ready
figures/pipeline.tex  TikZ pipeline diagram (Fig.1)
sections/             one .tex per section (abstract, 00_intro … 06_conclusion)
llncs.cls             Springer LNCS class (bundled, v2.26)
splncs04.bst          LNCS BibTeX style (bundled)
```

## Source of truth for the numbers

Every figure in the paper comes from real Docker runs recorded as CSV:

- `../docs/corpus/corpus_summary.csv` → Table 2 (verdict-class corpus)
- `../docs/corpus/dudect_appendix.csv` → Table 3 (dudect appendix)
- `../docs/corpus/corpus_cells.csv` → Table 1 evidence + build cells

The numbers are **single-sourced** (Phase 2): Table 2, Table 3, and every
duplicated dudect figure / percentage / cardinality are generated from the CSVs
into `generated/{tab_corpus,tab_dudect,corpus_macros}.tex`, which `main.tex` and
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
- [ ] Verify all 12 references in `references.bib` (LLM-drafted — check each).
- [ ] Confirm the dudect numbers natively (`taskset -c 0`, freq scaling off) —
      the corpus run was under QEMU/Docker; see Table 3 caveat.
- [ ] Check it fits 12 pages; §2/§4 compress first if over.
- [ ] Draw/replace Fig.1 if the TikZ needs polishing for print.
