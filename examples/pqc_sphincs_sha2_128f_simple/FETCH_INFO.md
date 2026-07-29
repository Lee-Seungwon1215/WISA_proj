# SPHINCS+-SHA2-128f-simple source provenance

- Source: PQClean `https://github.com/PQClean/PQClean`
- Revision: `202a8f96315f9ed219387a50f7e40d04af037ea8`
- Path: `crypto_sign/sphincs-sha2-128f-simple/clean/`
- Local path: `examples/pqc_sphincs_sha2_128f_simple/clean`
- License: `CC0-1.0`; see
  `examples/pqc_sphincs_sha2_128f_simple/clean/LICENSE`
- Tree SHA-256: `141adb3182d39c2df825673b8a2e414c2ab35ba529873ca2837f426d6eff24f8`

Trailing whitespace was removed from the two makefiles and final blank lines
from `hash_sha2.c` and `thash_sha2_simple.c`; executable source is unchanged.
SHA-2 and randombytes dependencies are reused from the separately inventoried
`../pqc_mlkem768/common`.

The API documents the secret-key layout as
`SK_SEED || SK_PRF || PUB_SEED || root`; CT-KAT taints only `SK_SEED` and
`SK_PRF` (`2*SPX_N`) and leaves the embedded public key material public.
