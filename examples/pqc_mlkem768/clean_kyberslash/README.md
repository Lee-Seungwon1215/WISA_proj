# `clean_kyberslash` — KyberSlash1+2 ground-truth overlay

This derived overlay restores all three Kyber-768 source sites represented by
the two vulnerability families:

- KyberSlash1: `poly_tomsg`
- KyberSlash2: `poly_compress` and `polyvec_compress`

The earlier positive control restored only the two functions in `poly.c` and
silently omitted the `polyvec_compress` KS2 site. That omission is now closed.
All unrelated code remains byte-identical to the pinned PQClean baseline. This
is a frozen differential control; do not "fix" it.

## Run it (Docker, gcc)

```bash
./scripts/dev.sh
PYTHONPATH=. python -m ctkat asm-scan -c examples/pqc_mlkem768/ctkat_kyberslash.yaml
```

## What you'll see (measured on Docker amd64 gcc 13.3)

The vulnerable helpers carry divisions whose survival depends on compiler and
optimization settings:

| build | KyberSlash division candidate |
|---|---|
| gcc `-O0` | none (gcc strength-reduces `/3329` to a reciprocal multiply) |
| gcc `-O2` | none (same) |
| gcc `-Os` | **present** (`idiv`/`div`) |

The real shipped `clean/poly.c` shows none at any level. Two takeaways:

1. **asm-scan catches KyberSlash candidates on real Kyber** — but only because it scans
   *multiple* opt levels; a single `-O0` scan would miss it entirely (the div
   only exists at `-Os`). This validates the multi-opt design on real code.
2. **Ordinary Valgrind/ct does NOT catch this.** Memcheck flags secret-dependent
   *branches/addresses*, not division-*latency*, so `ctkat ct` / `ct-matrix`
   report PASS on this vulnerable build. Final operand attribution uses the
   separately pinned TIMECOP-patched Valgrind backend; asm-scan alone remains
   candidate evidence.
