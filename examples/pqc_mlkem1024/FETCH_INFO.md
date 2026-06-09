# ML-KEM-1024 source provenance

- Source: PQClean `https://github.com/PQClean/PQClean`
- Revision: `202a8f96315f9ed219387a50f7e40d04af037ea8`
- Path: `crypto_kem/ml-kem-1024/clean/`

`clean/` is copied from PQClean. Common dependencies (`fips202`,
`randombytes`) are reused from `../pqc_mlkem768/common`.

Secret regions mirror the ML-KEM-768 corpus model: the IND-CPA secret-key
polynomial region and the FO rejection seed `z` are tainted; embedded public
key material and `H(pk)` are left public.
