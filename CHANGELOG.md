# Changelog

All notable user-facing changes are recorded here. CT-KAT follows semantic
versioning while the public API is stabilizing.

## [0.2.0a1] - 2026-07-29

### Added

- Installable wheel/sdist release gate with bundled Jinja templates.
- `ctkat --version`.
- Python 3.11–3.13 CI, coverage, package smoke, Linux Valgrind, gcc/clang,
  Docker, corpus drift, and third-party provenance checks.
- Trusted/untrusted config execution profiles and explicit shell opt-in.
- Machine-checkable third-party inventory and human-readable notices.
- Rejection-review recovery roadmap.

### Changed

- Example and documentation build/KAT steps now use shell-free `argv`.
- README corpus results are generated from the committed summary CSV.
- Timing claims now say `dudect-inspired first-order screen`; official dudect
  protocol parity is not claimed.
- Package version advanced from `0.1.0` to the first `0.2.0` alpha.

### Fixed

- Wheels now contain every `ctkat/templates/*.j2` resource.
- Template loading works independently of a source checkout.
- Missing ML-DSA-65 CC0 notice and incomplete PQClean attribution were restored.

## [0.1.0] - 2026-05-24

- Initial research prototype.

[0.2.0a1]: https://github.com/Lee-Seungwon1215/WISA_proj/compare/b1ccd4d...main
[0.1.0]: https://github.com/Lee-Seungwon1215/WISA_proj/commits/20a20f72a65216bb2e4edafc0b054789281f3455
