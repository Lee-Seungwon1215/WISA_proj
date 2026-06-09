# Camera-ready status (2026-06-09)

## Completed

- Paper builds successfully with `scripts/build_paper_pdf.sh`.
- `paper/main.pdf` is 11 pages under the 12-page LNCS target.
- Tables 1--5 and Fig.1 were visually checked from rendered PDF pages.
- `references.bib` was source-checked against public publisher/project metadata.
- Generated corpus tables remain drift-tested by `tests/test_paper_corpus_sync.py`.

## Reference check

| key | status | source used |
|---|---|---|
| `kyberslash` | ePrint metadata checked | `https://eprint.iacr.org/2024/1049` |
| `dudect` | DATE venue, pages, DOI checked | `https://past.date-conference.com/proceedings-archive/2017/html/0786.html` |
| `ctgrind` | project page checked | `https://github.com/agl/ctgrind` |
| `valgrind` | Valgrind publication page and DOI checked | `https://valgrind.org/docs/pubs.html` |
| `ctverif` | USENIX metadata, pages, URL checked | `https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/almeida` |
| `binsecrel` | IEEE S&P metadata, pages, DOI checked | `https://binsec.github.io/nutshells/sp-20.html` |
| `fips203` | NIST final publication and DOI checked | `https://csrc.nist.gov/pubs/fips/203/final` |
| `fips204` | NIST final publication and DOI checked | `https://csrc.nist.gov/pubs/fips/204/final` |
| `pqclean` | SSR paper metadata and DOI checked | `https://www.douglas.stebila.ca/research/papers/SSR-KSSW22/` |
| `kyber` | EuroS&P metadata, pages, DOI checked | `https://dblp.dagstuhl.de/rec/conf/eurosp/BosDKLLSSSS18.html` |
| `dilithium` | TCHES metadata and pages checked | `https://crypto.ethz.ch/publications/DKLLSS18.html` |
| `kocher` | CRYPTO/LNCS metadata, pages, DOI checked | `https://link.springer.com/book/10.1007/3-540-68697-5` |

## Still blocking

- Replace `First Author`, `0000-0000-0000-0000`, `F. Author`, affiliation, and
  email in `paper/main.tex` with the real submission metadata.

## Optional / environment-dependent

- Native dudect confirmation is not completed in this workspace: the current
  machine is macOS arm64 and has no Linux `taskset`. Run the timing confirmation
  on native Linux/x86_64 or on the actual target hardware with CPU pinning and
  frequency scaling disabled.
- Fig.1 is readable after PDF rendering, but it is small. A cleaner hand-tuned
  TikZ layout would improve polish, not correctness.
