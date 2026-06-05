# ML-DSA-65 (Dilithium) source provenance

- **Source**: PQClean — https://github.com/PQClean/PQClean
- **Path**: `crypto_sign/ml-dsa-65/clean/` (FIPS 204 ML-DSA-65, reference "clean" impl)
- **Fetch**: sparse-checkout (`--filter=blob:none --depth 1` of master).

`clean/` holds the verbatim PQClean ML-DSA-65 reference sources. Common deps
(`fips202`, `randombytes`) are reused from `../pqc_mlkem768/common` (identical
PQClean files, no copy) — see `ctkat.yaml` include_dirs/sources.

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
