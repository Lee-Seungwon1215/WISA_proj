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
main.tex              preamble + title + the 3 tables + Fig.1 float + \input glue
references.bib        12 citations — VERIFY each before camera-ready
figures/pipeline.tex  TikZ pipeline diagram (Fig.1)
sections/             one .tex per section (abstract, 00_intro … 06_conclusion)
llncs.cls             Springer LNCS class (bundled, v2.26)
splncs04.bst          LNCS BibTeX style (bundled)
```

## Source of truth for the numbers

Every figure in the paper is generated from real Docker runs and lives in the
repo as CSV:

- `../docs/corpus/corpus_summary.csv` → Table 2 (verdict-class corpus)
- `../docs/report_tables.md` → Tables 1 & 2 (curated)
- `../docs/corpus/dudect_appendix.csv` → Table 3 (dudect appendix)

If a number in the paper and the CSV ever disagree, the CSV wins — re-run
`scripts/build_corpus_table.py` and update the table.

## Before camera-ready (author checklist)

- [ ] Real author name(s) + ORCID in `main.tex` (currently placeholder).
- [ ] Verify all 12 references in `references.bib` (LLM-drafted — check each).
- [ ] Confirm the dudect numbers natively (`taskset -c 0`, freq scaling off) —
      the corpus run was under QEMU/Docker; see Table 3 caveat.
- [ ] Check it fits 12 pages; §2/§4 compress first if over.
- [ ] Draw/replace Fig.1 if the TikZ needs polishing for print.
