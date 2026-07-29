# ML-KEM-512 source provenance

- Source: PQClean `https://github.com/PQClean/PQClean`
- Revision: `202a8f96315f9ed219387a50f7e40d04af037ea8`
- Path: `crypto_kem/ml-kem-512/clean/`
- Local path: `examples/pqc_mlkem512/clean`
- License: `CC0-1.0`; see `examples/pqc_mlkem512/clean/LICENSE`
- Tree SHA-256: `2271320c59315034be692b6ab7579cbb6b0f2f16477b2942bbad0eea75e5b036`

The only local change is trailing-whitespace removal in the two makefiles; C
and header sources are unchanged. Common dependencies (`fips202`,
`randombytes`) are reused from the separately inventoried
`../pqc_mlkem768/common`.

Secret regions mirror the ML-KEM-768 corpus model: the IND-CPA secret-key
polynomial region and the FO rejection seed `z` are tainted; embedded public
key material and `H(pk)` are left public.
