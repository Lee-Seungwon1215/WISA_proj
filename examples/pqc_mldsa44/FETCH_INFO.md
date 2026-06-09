# ML-DSA-44 source provenance

- Source: PQClean `https://github.com/PQClean/PQClean`
- Revision: `202a8f96315f9ed219387a50f7e40d04af037ea8`
- Path: `crypto_sign/ml-dsa-44/clean/`

`clean/` is copied from PQClean. Common dependencies (`fips202`,
`randombytes`) are reused from `../pqc_mlkem768/common`.

Secret regions follow the ML-DSA secret-key packing order in `packing.c`:
`rho | key | tr | s1 | s2 | t0`. CT-KAT taints `key`, `s1`, `s2`, and `t0`;
`rho` and `tr` are treated as public material embedded in the secret-key blob.
