# Pinned c-fn-dsa comparators

This directory contains one exact upstream snapshot plus CT-KAT-owned adapters.
Four target directories compile the same source and deterministic signing path:

| Degree | Profile | Build selection |
|---|---|---|
| 512 | native FP | AVX2 disabled; architecture-native SSE2/NEON/RV64D path |
| 512 | integer FPR | SSE2, NEON, RV64D, and AVX2 disabled |
| 1024 | native FP | AVX2 disabled; architecture-native SSE2/NEON/RV64D path |
| 1024 | integer FPR | SSE2, NEON, RV64D, and AVX2 disabled |

The integer profile reaches `sign_fpr.c`'s software binary64 operations and
the integer-domain post-sampling path in `sign_core.c`. It is not simulated by
renaming a native build. The native profile is meaningful only when the build
manifest confirms one of SSE2, NEON, or RV64D; the audit fails closed
otherwise.

The adapter exposes a PQClean-shaped API solely so CT-KAT's existing signing
harness can be reused. Key generation and signing use fixed seeds for
reproducibility. The signing-key taint excludes byte 0 (public format/degree
header) and the final 64-byte hashed verifying key; only encoded `f`, `g`, and
`F` are tainted.

These targets describe commit
`729698f031ea69bd33375d2fb0db3ac154ad1880`, not final FN-DSA or FIPS 206.
