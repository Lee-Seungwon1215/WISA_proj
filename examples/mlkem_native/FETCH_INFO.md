# mlkem-native source provenance

- Source: `https://github.com/pq-code-package/mlkem-native`
- Release: `v1.3.0` (published 2026-08-03)
- Revision: `398050c877ff4353c96305c6434b63528accfc37`
- Release archive SHA-256:
  `70501bbf07e9172e4265b1cc94ef8ae6e66073863eab5f00203deafe0cc5a5de`
- Upstream paths: `LICENSE`, `README.md`, `META.yml`, `mlkem/`,
  `test/src/gen_KAT.c`, and `test/notrandombytes/`
- Local path: `examples/mlkem_native/upstream`
- License: `Apache-2.0 OR ISC OR MIT` for `mlkem/`; the test-only
  `notrandombytes` helper carries
  `LicenseRef-PD-hp OR CC0-1.0 OR 0BSD OR MIT-0 OR MIT`. See the imported
  `LICENSE` and per-file SPDX headers.
- Tree SHA-256:
  `101a2e35764993175c99dbbb7bb67c2f42970f525b0fd4493e5811eef162ec0a`
- Local modifications: none; all 131 imported files are byte-identical to the
  recorded revision.
- Fetched: `2026-08-07`

The subset is the upstream-supported monolithic distribution plus its exact
KAT generator and KAT hashes. `scripts/check_diverse_upstreams.py` compiles the
imported `gen_KAT.c` and requires stdout to match `META.yml`; CT-KAT's lighter
matrix adapter is kept outside `upstream/`.

The upstream license identifies mlkem-native as a fork of the public-domain
Kyber reference implementation. CT-KAT therefore counts it as a separately
maintained primary upstream lineage, not as a from-scratch algorithm lineage.
Shared-code fraction remains unmeasured and is not silently reported as zero.

The final pre-measurement freeze deliberately moved from v1.2.0 to v1.3.0
before collecting physical data.  v1.3.0 changes AArch64 feature selection,
adds assembly ABI checks, and renames backend assembly sources; no v1.2.0
physical result is mixed into the frozen campaign.
