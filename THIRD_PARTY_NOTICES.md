# Third-party notices

CT-KAT's MIT license does not relicense the material listed below.
Integrity hashes cover sorted relative paths and file bytes using
`scripts/check_third_party.py::tree_sha256`.

This file is generated from `third_party.toml`. Regenerate it with:

```bash
python scripts/check_third_party.py --write-notices
```

## PQClean ML-KEM-512 clean

- Local path: `examples/pqc_mlkem512/clean`
- Upstream: https://github.com/PQClean/PQClean
- Revision: `202a8f96315f9ed219387a50f7e40d04af037ea8`
- Upstream path: `crypto_kem/ml-kem-512/clean`
- License: `CC0-1.0`
- License file: `examples/pqc_mlkem512/clean/LICENSE`
- Tree SHA-256: `2271320c59315034be692b6ab7579cbb6b0f2f16477b2942bbad0eea75e5b036`
- Local modifications: Trailing whitespace removed from Makefile and Makefile.Microsoft_nmake; C and header sources are unchanged.
- Detailed provenance: `examples/pqc_mlkem512/FETCH_INFO.md`

## PQClean ML-KEM-768 clean

- Local path: `examples/pqc_mlkem768/clean`
- Upstream: https://github.com/PQClean/PQClean
- Revision: `202a8f96315f9ed219387a50f7e40d04af037ea8`
- Upstream path: `crypto_kem/ml-kem-768/clean`
- License: `CC0-1.0`
- License file: `examples/pqc_mlkem768/clean/LICENSE`
- Tree SHA-256: `c0cfee72c851bed51582749fa599b0f75a82aca31592528a203093f3dc9ca1cf`
- Local modifications: None; byte-identical to the recorded upstream directory.
- Detailed provenance: `examples/pqc_mlkem768/FETCH_INFO.md`

## PQClean ML-KEM-1024 clean

- Local path: `examples/pqc_mlkem1024/clean`
- Upstream: https://github.com/PQClean/PQClean
- Revision: `202a8f96315f9ed219387a50f7e40d04af037ea8`
- Upstream path: `crypto_kem/ml-kem-1024/clean`
- License: `CC0-1.0`
- License file: `examples/pqc_mlkem1024/clean/LICENSE`
- Tree SHA-256: `cc9fb85934d1bf9cc28817432f9651b48eb93e30023b718c913c3c9bcfbf2c20`
- Local modifications: Trailing whitespace removed from Makefile and Makefile.Microsoft_nmake; C and header sources are unchanged.
- Detailed provenance: `examples/pqc_mlkem1024/FETCH_INFO.md`

## PQClean common support code

- Local path: `examples/pqc_mlkem768/common`
- Upstream: https://github.com/PQClean/PQClean
- Revision: `202a8f96315f9ed219387a50f7e40d04af037ea8`
- Upstream path: `common`
- License: `CC0-1.0 and public-domain notices in source headers`
- License file: `examples/pqc_mlkem768/clean/LICENSE`
- Tree SHA-256: `11cbb7363fc3211f42d4e9aef2191ab476da02f44e54dbeda239b8deb01e1dc7`
- Local modifications: None; byte-identical to the recorded upstream directory.
- Detailed provenance: `examples/pqc_mlkem768/FETCH_INFO.md`

## KyberSlash-derived ML-KEM-768 overlay

- Local path: `examples/pqc_mlkem768/clean_kyberslash`
- Upstream: https://github.com/PQClean/PQClean
- Revision: `202a8f96315f9ed219387a50f7e40d04af037ea8`
- Upstream path: `crypto_kem/ml-kem-768/clean/poly.c (derived overlay)`
- License: `CC0-1.0`
- License file: `examples/pqc_mlkem768/clean_kyberslash/LICENSE`
- Tree SHA-256: `7c337f02539fe668109e6051fe5004405fc88f9a3f21df99dd2dcfcd019ffa64`
- Local modifications: Local README and license added; poly_compress and poly_tomsg intentionally restore two historical /KYBER_Q expressions as a positive control.
- Detailed provenance: `examples/pqc_mlkem768/FETCH_INFO.md`

## PQClean ML-DSA-44 clean

- Local path: `examples/pqc_mldsa44/clean`
- Upstream: https://github.com/PQClean/PQClean
- Revision: `202a8f96315f9ed219387a50f7e40d04af037ea8`
- Upstream path: `crypto_sign/ml-dsa-44/clean`
- License: `CC0-1.0`
- License file: `examples/pqc_mldsa44/clean/LICENSE`
- Tree SHA-256: `af0e11aa3873552535933e8b422713b89876f5b9eec4f9d82c6e14b8c7155e54`
- Local modifications: Trailing whitespace removed from Makefile and Makefile.Microsoft_nmake; C and header sources are unchanged.
- Detailed provenance: `examples/pqc_mldsa44/FETCH_INFO.md`

## PQClean ML-DSA-65 clean

- Local path: `examples/pqc_mldsa65/clean`
- Upstream: https://github.com/PQClean/PQClean
- Revision: `202a8f96315f9ed219387a50f7e40d04af037ea8`
- Upstream path: `crypto_sign/ml-dsa-65/clean`
- License: `CC0-1.0`
- License file: `examples/pqc_mldsa65/clean/LICENSE`
- Tree SHA-256: `4bdf0e7315114fd86deda9871460b47559dfa10c4f69804bb5fec1213b6d6e1a`
- Local modifications: Upstream Makefile and Makefile.Microsoft_nmake are omitted; source files are unchanged and the previously omitted LICENSE has been restored.
- Detailed provenance: `examples/pqc_mldsa65/FETCH_INFO.md`

## PQClean ML-DSA-87 clean

- Local path: `examples/pqc_mldsa87/clean`
- Upstream: https://github.com/PQClean/PQClean
- Revision: `202a8f96315f9ed219387a50f7e40d04af037ea8`
- Upstream path: `crypto_sign/ml-dsa-87/clean`
- License: `CC0-1.0`
- License file: `examples/pqc_mldsa87/clean/LICENSE`
- Tree SHA-256: `24d6fdadd19196de303d520b6ac2df5424b983250424f0a90c1c59be2edf9f97`
- Local modifications: Trailing whitespace removed from Makefile and Makefile.Microsoft_nmake; C and header sources are unchanged.
- Detailed provenance: `examples/pqc_mldsa87/FETCH_INFO.md`

## PQClean SPHINCS+-SHA2-128f-simple clean

- Local path: `examples/pqc_sphincs_sha2_128f_simple/clean`
- Upstream: https://github.com/PQClean/PQClean
- Revision: `202a8f96315f9ed219387a50f7e40d04af037ea8`
- Upstream path: `crypto_sign/sphincs-sha2-128f-simple/clean`
- License: `CC0-1.0`
- License file: `examples/pqc_sphincs_sha2_128f_simple/clean/LICENSE`
- Tree SHA-256: `141adb3182d39c2df825673b8a2e414c2ab35ba529873ca2837f426d6eff24f8`
- Local modifications: Trailing whitespace was removed from makefiles and final blank lines from hash_sha2.c/thash_sha2_simple.c; executable source is unchanged.
- Detailed provenance: `examples/pqc_sphincs_sha2_128f_simple/FETCH_INFO.md`

## PQClean Falcon-512 clean

- Local path: `examples/pqc_falcon512/clean`
- Upstream: https://github.com/PQClean/PQClean
- Revision: `202a8f96315f9ed219387a50f7e40d04af037ea8`
- Upstream path: `crypto_sign/falcon-512/clean`
- License: `MIT with upstream patent notice`
- License file: `examples/pqc_falcon512/clean/LICENSE`
- Tree SHA-256: `151dc842c4c9a0aa74b692f475380f675c3f968febe2399f2f9e5e7b70e2fd6d`
- Local modifications: None; byte-identical to the recorded upstream directory.
- Detailed provenance: `examples/pqc_falcon512/FETCH_INFO.md`

## official dudect statistical engine

- Local path: `ctkat/_vendor/dudect`
- Upstream: https://github.com/oreparaz/dudect
- Revision: `dc269651fb2567e46755cfb2a13d3875592968b5`
- Upstream path: `src/dudect.h and LICENSE`
- License: `MIT (dudect.h also carries a public-domain dedication)`
- License file: `ctkat/_vendor/dudect/LICENSE`
- Tree SHA-256: `a672e626a6c39b53f653ab6c754700e806423244396c2a9bc4ee3bab7355bca4`
- Local modifications: None; dudect.h and LICENSE are byte-identical to the pinned upstream revision. CT-KAT's adapter is maintained outside this vendored tree.
- Detailed provenance: `ctkat/_vendor/dudect_FETCH_INFO.md`
