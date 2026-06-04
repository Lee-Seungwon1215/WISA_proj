# clean_kyberslash — real-crypto KyberSlash positive control

`poly.c` here is the PQClean ML-KEM-768 `clean/poly.c` with the **KyberSlash fix
deliberately reverted**: `poly_compress()` and `poly_tomsg()` use the original
**secret-dependent integer division by `KYBER_Q` (=3329)** instead of the shipped
reciprocal-multiply (`* 80635 >> 28`). That `/KYBER_Q` is the KyberSlash leak
(TCHES 2025, eprint 2024/1049). **Only those two functions differ** from
`../clean/poly.c`; the rest is verbatim, and it compiles against the existing
`../clean` + `../common` headers.

This is a **frozen positive control** for `ctkat asm-scan` — do not "fix" it.

## Run it (Docker, gcc)

```bash
./scripts/dev.sh
PYTHONPATH=. python -m ctkat asm-scan -c examples/pqc_mlkem768/ctkat_kyberslash.yaml
```

## What you'll see (measured on Docker amd64 gcc 13.3)

`poly_compress` / `poly_tomsg` carry a division that survives **only at `-Os`**:

| build | KyberSlash `div` in poly_compress/poly_tomsg |
|---|---|
| gcc `-O0` | none (gcc strength-reduces `/3329` to a reciprocal multiply) |
| gcc `-O2` | none (same) |
| gcc `-Os` | **present** (`idiv`/`div`) — KyberSlash |

The real shipped `clean/poly.c` shows none at any level. Two takeaways:

1. **asm-scan catches KyberSlash on real Kyber** — but only because it scans
   *multiple* opt levels; a single `-O0` scan would miss it entirely (the div
   only exists at `-Os`). This validates the multi-opt design on real code.
2. **The Valgrind/ct layer does NOT catch this.** Memcheck flags secret-dependent
   *branches/addresses*, not division-*latency*, so `ctkat ct` / `ct-matrix`
   report PASS on this vulnerable build. KyberSlash lives in asm-scan's lane, not
   the structural CT check's — that division of labor is the point.
