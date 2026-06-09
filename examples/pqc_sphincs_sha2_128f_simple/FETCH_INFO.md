# SPHINCS+-SHA2-128f-simple source provenance

- Source: PQClean `https://github.com/PQClean/PQClean`
- Revision: `202a8f96315f9ed219387a50f7e40d04af037ea8`
- Path: `crypto_sign/sphincs-sha2-128f-simple/clean/`

`clean/` is copied from PQClean. SHA-2 and randombytes dependencies are reused
from `../pqc_mlkem768/common`.

The API documents the secret-key layout as
`SK_SEED || SK_PRF || PUB_SEED || root`; CT-KAT taints only `SK_SEED` and
`SK_PRF` (`2*SPX_N`) and leaves the embedded public key material public.
