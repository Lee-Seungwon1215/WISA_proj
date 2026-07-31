# mldsa-native source provenance

- Source: `https://github.com/pq-code-package/mldsa-native`
- Release: `v1.0.0-beta2` (published 2026-05-23)
- Revision: `9b0ee84f4cf399043eca59eca4e5f8531ca1d61b`
- Upstream paths: `LICENSE`, `README.md`, `META.yml`, `mldsa/`,
  `test/src/gen_KAT.c`, and `test/notrandombytes/`
- Local path: `examples/mldsa_native/upstream`
- License: `Apache-2.0 OR ISC OR MIT` for `mldsa/`; the test-only
  `notrandombytes` helper carries
  `LicenseRef-PD-hp OR CC0-1.0 OR 0BSD OR MIT-0 OR MIT`. See the imported
  `LICENSE` and per-file SPDX headers.
- Tree SHA-256:
  `a6899867ede95f0c5464c92b96ab314e83c610ff9e23c1cac6f3d78789e710ff`
- Local modifications: none; all 117 imported files are byte-identical to the
  recorded revision.
- Fetched: `2026-07-31`

The subset is the upstream-supported monolithic distribution plus its exact
KAT generator and KAT hashes. `scripts/check_diverse_upstreams.py` compiles the
imported `gen_KAT.c` and requires stdout to match `META.yml`; CT-KAT's lighter
matrix adapter is kept outside `upstream/`.

This is a beta-tagged release. Passing its build, KAT, and equivalence gates is
not a claim of API stability, production certification, or independent FIPS
validation. The upstream license also records ancestry from the public-domain
Dilithium reference implementation; shared-code fraction is unmeasured.
