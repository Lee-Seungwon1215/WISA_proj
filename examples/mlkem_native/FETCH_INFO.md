# mlkem-native source provenance

- Source: `https://github.com/pq-code-package/mlkem-native`
- Release: `v1.2.0` (published 2026-06-20)
- Revision: `0ba906cb14b1c241476134d7403a811b382ca498`
- Upstream paths: `LICENSE`, `README.md`, `META.yml`, `mlkem/`,
  `test/src/gen_KAT.c`, and `test/notrandombytes/`
- Local path: `examples/mlkem_native/upstream`
- License: `Apache-2.0 OR ISC OR MIT` for `mlkem/`; the test-only
  `notrandombytes` helper carries
  `LicenseRef-PD-hp OR CC0-1.0 OR 0BSD OR MIT-0 OR MIT`. See the imported
  `LICENSE` and per-file SPDX headers.
- Tree SHA-256:
  `7f4d1da13cd51f8cca65fcb6bb8e4eb0b697e8097488f3058beab26b21c1334d`
- Local modifications: none; all 130 imported files are byte-identical to the
  recorded revision.
- Fetched: `2026-07-31`

The subset is the upstream-supported monolithic distribution plus its exact
KAT generator and KAT hashes. `scripts/check_diverse_upstreams.py` compiles the
imported `gen_KAT.c` and requires stdout to match `META.yml`; CT-KAT's lighter
matrix adapter is kept outside `upstream/`.

The upstream license identifies mlkem-native as a fork of the public-domain
Kyber reference implementation. CT-KAT therefore counts it as a separately
maintained primary upstream lineage, not as a from-scratch algorithm lineage.
Shared-code fraction remains unmeasured and is not silently reported as zero.
