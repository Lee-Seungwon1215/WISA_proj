# ML-DSA-44 source provenance

- Source: PQClean `https://github.com/PQClean/PQClean`
- Revision: `202a8f96315f9ed219387a50f7e40d04af037ea8`
- Path: `crypto_sign/ml-dsa-44/clean/`
- Local path: `examples/pqc_mldsa44/clean`
- License: `CC0-1.0`; see `examples/pqc_mldsa44/clean/LICENSE`
- Tree SHA-256: `af0e11aa3873552535933e8b422713b89876f5b9eec4f9d82c6e14b8c7155e54`

The only local change is trailing-whitespace removal in the two makefiles; C
and header sources are unchanged. Common dependencies (`fips202`,
`randombytes`) are reused from the separately inventoried
`../pqc_mlkem768/common`.

Secret regions follow the ML-DSA secret-key packing order in `packing.c`:
`rho | key | tr | s1 | s2 | t0`. CT-KAT taints `key`, `s1`, `s2`, and `t0`;
`rho` and `tr` are treated as public material embedded in the secret-key blob.
