# ML-DSA-65 (Dilithium) source provenance

- **Source**: PQClean — https://github.com/PQClean/PQClean
- **Revision**: `202a8f96315f9ed219387a50f7e40d04af037ea8`
- **Path**: `crypto_sign/ml-dsa-65/clean/` (FIPS 204 ML-DSA-65, reference "clean" impl)
- **Local path**: `examples/pqc_mldsa65/clean`
- **License**: `CC0-1.0`; see `examples/pqc_mldsa65/clean/LICENSE`
- **Tree SHA-256**: `4bdf0e7315114fd86deda9871460b47559dfa10c4f69804bb5fec1213b6d6e1a`

The C/header source files match the recorded revision. The upstream Makefile
and Makefile.Microsoft_nmake are intentionally omitted because this target is
compiled through generated harnesses. The previously missing upstream LICENSE
has been restored. Common dependencies (`fips202`, `randombytes`) are reused
from the separately inventoried `../pqc_mlkem768/common`.

## secret_regions derivation (NOT guessed)

From `clean/packing.c` `pack_sk` — sk is packed in this byte order:

| field | bytes | secret? |
|---|---|---|
| rho | SEEDBYTES (32) | public (matrix seed) |
| key | SEEDBYTES (32) | **secret** (signing seed K) |
| tr  | TRBYTES (64) | public (= H(pk)) |
| s1  | L·POLYETA_PACKEDBYTES (5·128=640) | **secret** |
| s2  | K·POLYETA_PACKEDBYTES (6·128=768) | **secret** |
| t0  | K·POLYT0_PACKEDBYTES (6·416=2496) | secret (low bits of t; in sk, not pk) |

`ctkat.yaml` taints `key`, `s1`, `s2`, `t0` (everything except the public
`rho`/`tr`), with offsets/lengths written as the params.h macros so they track
the scheme rather than a hardcoded count.

## Status

Scaffold validated on host (config load + sign-harness render). The ct-matrix /
asm-scan **measurement is pending** (requires the Docker amd64 + Valgrind
environment). Once measured, merge via `scripts/build_corpus_table.py` →
corpus row (expected robust, an ML-DSA-family control).
