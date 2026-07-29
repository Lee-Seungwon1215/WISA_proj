# PQClean ML-KEM-768 provenance

- Source: `https://github.com/PQClean/PQClean`
- Revision: `202a8f96315f9ed219387a50f7e40d04af037ea8`
- Originally fetched: `2026-05-23T08:36:53Z`

## Vendored snapshots

### Clean implementation

- Upstream path: `crypto_kem/ml-kem-768/clean`
- Local path: `examples/pqc_mlkem768/clean`
- License: `CC0-1.0`; see `examples/pqc_mlkem768/clean/LICENSE`
- Tree SHA-256: `c0cfee72c851bed51582749fa599b0f75a82aca31592528a203093f3dc9ca1cf`
- Local modifications: none; verified byte-identical to the recorded revision.

### Common support code

- Upstream path: `common`
- Local path: `examples/pqc_mlkem768/common`
- License: CC0/public-domain notices; see the source headers and the clean
  implementation's license notice.
- Tree SHA-256: `11cbb7363fc3211f42d4e9aef2191ab476da02f44e54dbeda239b8deb01e1dc7`
- Local modifications: none; verified byte-identical to the recorded revision.

### KyberSlash positive-control overlay

- Upstream baseline: `crypto_kem/ml-kem-768/clean/poly.c`
- Local path: `examples/pqc_mlkem768/clean_kyberslash`
- License: `CC0-1.0`; see
  `examples/pqc_mlkem768/clean_kyberslash/LICENSE`
- Tree SHA-256: `7c337f02539fe668109e6051fe5004405fc88f9a3f21df99dd2dcfcd019ffa64`
- Local modifications: `poly_compress` and `poly_tomsg` intentionally restore
  two historical `/KYBER_Q` expressions. The local README documents the exact
  expressions. This is a derived positive control, not verbatim PQClean.

The machine-readable inventory and hash algorithm live in
`third_party.toml` and `scripts/check_third_party.py`.
