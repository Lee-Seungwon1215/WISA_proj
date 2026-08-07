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

## KyberSlash1-only ML-KEM-768 overlay

- Local path: `examples/pqc_mlkem768/clean_kyberslash1`
- Upstream: https://github.com/PQClean/PQClean
- Revision: `202a8f96315f9ed219387a50f7e40d04af037ea8`
- Upstream path: `crypto_kem/ml-kem-768/clean/poly.c (derived overlay)`
- License: `CC0-1.0`
- License file: `examples/pqc_mlkem768/clean_kyberslash1/LICENSE`
- Tree SHA-256: `76caf17c4296cbf9dfb780941167e5b0cf01397748f0777d09c792fd6de73225`
- Local modifications: Local README/license added; poly_tomsg alone restores the historical KyberSlash1 /KYBER_Q expression.
- Detailed provenance: `examples/pqc_mlkem768/FETCH_INFO.md`

## KyberSlash2-only ML-KEM-768 overlay

- Local path: `examples/pqc_mlkem768/clean_kyberslash2`
- Upstream: https://github.com/PQClean/PQClean
- Revision: `202a8f96315f9ed219387a50f7e40d04af037ea8`
- Upstream path: `crypto_kem/ml-kem-768/clean/poly.c and polyvec.c (derived overlay)`
- License: `CC0-1.0`
- License file: `examples/pqc_mlkem768/clean_kyberslash2/LICENSE`
- Tree SHA-256: `7d9d3d02d746d1adbfea6411c57929a0831cc7829f1a4efa96e34b26f00dd3e3`
- Local modifications: Local README/license added; poly_compress and polyvec_compress restore the historical KyberSlash2 /KYBER_Q expressions.
- Detailed provenance: `examples/pqc_mlkem768/FETCH_INFO.md`

## KyberSlash1+2 ML-KEM-768 overlay

- Local path: `examples/pqc_mlkem768/clean_kyberslash`
- Upstream: https://github.com/PQClean/PQClean
- Revision: `202a8f96315f9ed219387a50f7e40d04af037ea8`
- Upstream path: `crypto_kem/ml-kem-768/clean/poly.c and polyvec.c (derived overlay)`
- License: `CC0-1.0`
- License file: `examples/pqc_mlkem768/clean_kyberslash/LICENSE`
- Tree SHA-256: `2546d9487d13113d19be0c3fd54b2a8d1f201c3d34bcd347c44a922ae8a43dd4`
- Local modifications: Local README/license added; poly_tomsg, poly_compress, and polyvec_compress restore the KS1 and KS2 /KYBER_Q expressions.
- Detailed provenance: `examples/pqc_mlkem768/FETCH_INFO.md`

## Historical pq-crystals Kyber reference before KyberSlash fixes

- Local path: `examples/pqc_kyber768_historical/ref`
- Upstream: https://github.com/pq-crystals/kyber
- Revision: `a621b8dde405cc507cbcfc5f794570a4f98d69cc`
- Upstream path: `ref`
- License: `Public domain/CC0 or Apache-2.0 with per-file notices`
- License file: `examples/pqc_kyber768_historical/LICENSE`
- Tree SHA-256: `3ca097d98e2a48fdd463740cfa0484cbc339bcd1f1f5f2ca0157762a0317ae4d`
- Local modifications: None inside ref; byte-identical snapshot. CT-KAT adapters live in the parent directory.
- Detailed provenance: `examples/pqc_kyber768_historical/FETCH_INFO.md`

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

## PQClean Falcon-1024 clean reference

- Local path: `examples/pqc_falcon1024/clean`
- Upstream: https://github.com/PQClean/PQClean
- Revision: `202a8f96315f9ed219387a50f7e40d04af037ea8`
- Upstream path: `crypto_sign/falcon-1024/clean`
- License: `MIT with upstream patent notice`
- License file: `examples/pqc_falcon1024/clean/LICENSE`
- Tree SHA-256: `c91baa9cc666a4b601cb793b362ab9b238755f15a530f4d54727588e099829bd`
- Local modifications: None; byte-identical to the recorded upstream directory.
- Detailed provenance: `examples/pqc_falcon1024/FETCH_INFO.md`

## c-fn-dsa prospective implementation snapshot

- Local path: `examples/fndsa_prospective/upstream`
- Upstream: https://github.com/pornin/c-fn-dsa
- Revision: `729698f031ea69bd33375d2fb0db3ac154ad1880`
- Upstream path: `repository root`
- License: `Unlicense/public-domain dedication`
- License file: `examples/fndsa_prospective/upstream/LICENSE`
- Tree SHA-256: `0fd17c0d7a05650657b8660496d3fd15b5d2ef907a520dfa48b0688800298429`
- Local modifications: None; all 45 tracked files are byte-identical. CT-KAT adapters and profiles live outside the vendored tree.
- Detailed provenance: `examples/fndsa_prospective/FETCH_INFO.md`

## mlkem-native v1.3.0 monolithic source and KAT subset

- Local path: `examples/mlkem_native/upstream`
- Upstream: https://github.com/pq-code-package/mlkem-native
- Revision: `398050c877ff4353c96305c6434b63528accfc37`
- Upstream path: `LICENSE, README.md, META.yml, mlkem/, test/src/gen_KAT.c, and test/notrandombytes/`
- License: `Apache-2.0 OR ISC OR MIT; test/notrandombytes is LicenseRef-PD-hp OR CC0-1.0 OR 0BSD OR MIT-0 OR MIT`
- License file: `examples/mlkem_native/upstream/LICENSE`
- Tree SHA-256: `101a2e35764993175c99dbbb7bb67c2f42970f525b0fd4493e5811eef162ec0a`
- Local modifications: None; all 131 imported files are byte-identical. CT-KAT adapters live outside the vendored tree.
- Detailed provenance: `examples/mlkem_native/FETCH_INFO.md`

## mldsa-native v1.0.0-beta2 monolithic source and KAT subset

- Local path: `examples/mldsa_native/upstream`
- Upstream: https://github.com/pq-code-package/mldsa-native
- Revision: `9b0ee84f4cf399043eca59eca4e5f8531ca1d61b`
- Upstream path: `LICENSE, README.md, META.yml, mldsa/, test/src/gen_KAT.c, and test/notrandombytes/`
- License: `Apache-2.0 OR ISC OR MIT; test/notrandombytes is LicenseRef-PD-hp OR CC0-1.0 OR 0BSD OR MIT-0 OR MIT`
- License file: `examples/mldsa_native/upstream/LICENSE`
- Tree SHA-256: `a6899867ede95f0c5464c92b96ab314e83c610ff9e23c1cac6f3d78789e710ff`
- Local modifications: None; all 117 imported files are byte-identical. The beta claim limit and CT-KAT adapters live outside the vendored tree.
- Detailed provenance: `examples/mldsa_native/FETCH_INFO.md`

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

## IACR KyberSlash TIMECOP Valgrind patch

- Local path: `ctkat/_vendor/kyberslash_timecop`
- Upstream: https://artifacts.iacr.org/tches/2025/a9
- Artifact SHA-256: `403af6cb4ff8d7a6a4057e280cd22e27c842fec97963645b66f9138e8b69a4b8`
- Upstream path: `kyberslash-demo/valgrind/valgrind-3.22.0-varlat.patch and COPYING.GPL2`
- License: `GPL-2.0-or-later`
- License file: `ctkat/_vendor/kyberslash_timecop/COPYING.GPL2`
- Tree SHA-256: `ff2ef869d78b57b87efe1470fcc5b217d4a79c31ab4ad643273d260435b6576c`
- Local modifications: Patch and license are byte-identical to the IACR artifact; local README and FETCH_INFO add provenance.
- Detailed provenance: `ctkat/_vendor/kyberslash_timecop_FETCH_INFO.md`
