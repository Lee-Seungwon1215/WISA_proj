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

### KyberSlash1-only differential overlay

- Upstream baseline: `crypto_kem/ml-kem-768/clean/poly.c`
- Local path: `examples/pqc_mlkem768/clean_kyberslash1`
- License: `CC0-1.0`; see
  `examples/pqc_mlkem768/clean_kyberslash1/LICENSE`
- Tree SHA-256: `76caf17c4296cbf9dfb780941167e5b0cf01397748f0777d09c792fd6de73225`
- Local modifications: `poly_tomsg` alone restores the historical
  KyberSlash1 `/KYBER_Q` expression.

### KyberSlash2-only differential overlay

- Upstream baseline: `crypto_kem/ml-kem-768/clean/{poly.c,polyvec.c}`
- Local path: `examples/pqc_mlkem768/clean_kyberslash2`
- License: `CC0-1.0`; see
  `examples/pqc_mlkem768/clean_kyberslash2/LICENSE`
- Tree SHA-256: `7d9d3d02d746d1adbfea6411c57929a0831cc7829f1a4efa96e34b26f00dd3e3`
- Local modifications: `poly_compress` and `polyvec_compress` restore the
  KyberSlash2 `/KYBER_Q` expressions; `poly_tomsg` remains patched.

### KyberSlash1+2 differential overlay

- Upstream baseline: `crypto_kem/ml-kem-768/clean/{poly.c,polyvec.c}`
- Local path: `examples/pqc_mlkem768/clean_kyberslash`
- License: `CC0-1.0`; see
  `examples/pqc_mlkem768/clean_kyberslash/LICENSE`
- Tree SHA-256: `2546d9487d13113d19be0c3fd54b2a8d1f201c3d34bcd347c44a922ae8a43dd4`
- Local modifications: `poly_tomsg`, `poly_compress`, and
  `polyvec_compress` intentionally restore the KS1 and KS2 `/KYBER_Q`
  expressions. This is a derived differential control, not verbatim PQClean.

The machine-readable inventory and hash algorithm live in
`third_party.toml` and `scripts/check_third_party.py`.
