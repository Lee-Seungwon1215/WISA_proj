# MDPI template provenance

The working manuscript vendors an unmodified copy of the official MDPI
article template bundle so that a build does not depend on a mutable global
TeX installation.

- Downloaded: 2026-08-17 (Asia/Seoul)
- Official author page: <https://www.mdpi.com/authors/latex>
- Official archive: <https://mdpi-res.com/data/MDPI_template_ACS.zip>
- Archive SHA-256: `44a9464c06e724889e1496a73be0e6f81099d534bcc9a3da94b99b52f0ecc563`
- Vendored class date: 27 July 2026
- Vendored class SHA-256: `5ca561720cb31ddd52436334b54d442ed03cf921571b39ddfcba95c1ac8047d4`
- Upstream `template.tex` SHA-256: `d10768ded633452ced9c07c918a1ab996681ea0ccd010e4b83cc5313897cbb62`

`Definitions/` and `upstream/template.tex` are upstream files. They must not
be reformatted or edited locally. `scripts/check_mdpi_paper.py` pins every
vendored file by SHA-256 and fails if any byte changes.

The `cryptography` class option in `main.tex` is only a provisional formatting
profile within the MDPI article class. It does **not** record a target-journal
decision. Once a journal is selected, replace that option with the journal's
current MDPI class option and re-check the journal-specific instructions.
