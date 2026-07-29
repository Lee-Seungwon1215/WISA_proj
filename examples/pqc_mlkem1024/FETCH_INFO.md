# ML-KEM-1024 source provenance

- Source: PQClean `https://github.com/PQClean/PQClean`
- Revision: `202a8f96315f9ed219387a50f7e40d04af037ea8`
- Path: `crypto_kem/ml-kem-1024/clean/`
- Local path: `examples/pqc_mlkem1024/clean`
- License: `CC0-1.0`; see `examples/pqc_mlkem1024/clean/LICENSE`
- Tree SHA-256: `cc9fb85934d1bf9cc28817432f9651b48eb93e30023b718c913c3c9bcfbf2c20`

The only local change is trailing-whitespace removal in the two makefiles; C
and header sources are unchanged. Common dependencies (`fips202`,
`randombytes`) are reused from the separately inventoried
`../pqc_mlkem768/common`.

Secret regions mirror the ML-KEM-768 corpus model: the IND-CPA secret-key
polynomial region and the FO rejection seed `z` are tainted; embedded public
key material and `H(pk)` are left public.
