# KyberSlash ground truth

This directory freezes four comparable ML-KEM-768 variants:

| Variant | KS1 `poly_tomsg` | KS2 `poly_compress` | KS2 `polyvec_compress` |
|---|---:|---:|---:|
| `stock` | fixed | fixed | fixed |
| `ks1` | vulnerable | fixed | fixed |
| `ks2` | fixed | vulnerable | vulnerable |
| `ks1_ks2` | vulnerable | vulnerable | vulnerable |

The older combined positive control was incomplete: it restored
`poly_compress` but omitted KyberSlash2's `polyvec_compress` site. The frozen
overlays and machine-readable manifest now make that omission a test failure.

`ground_truth.yaml` pins the PQClean baseline, the vulnerable historical
`pq-crystals/kyber` snapshot, both fix commits, the IACR artifact, every source
marker, and the patched Valgrind backend. The patch files are exact unified
diffs from the stock PQClean sources.

Run the host-independent checks with:

```bash
python scripts/check_kyberslash_ground_truth.py
```

That command verifies provenance and diffs, compiles all four variants with a
deterministic `randombytes` interposer, exercises valid and invalid
decapsulation, and requires byte-identical full KEM transcripts.

For final operand attribution, use the dedicated Linux image:

```bash
docker compose --profile timecop build ctkat-timecop
docker compose --profile timecop run --rm ctkat-timecop \
  python scripts/run_kyberslash_timecop.py
```

The runner first executes a tainted integer-division canary. It then analyzes
all four variants plus the historical snapshot in two explicitly separate
scopes:

1. `kem_dec_secret_key_path` taints the KEM secret-key regions and follows the
   complete decapsulation call.
2. `site_operand_attribution` taints the inputs to `poly_tomsg`,
   `poly_compress`, and `polyvec_compress` directly.

It writes a lossless JSON artifact under
`measurement_runs/kyberslash_timecop/`. A result is promotion-ready only when
the patched-backend identity, canary, both scope exit statuses, and all exact
function sets match the manifest.

The report uses `schema_version: 2` and retains compiler commands, binary and
log hashes, parsed findings with origin frames, exact expected/actual function
sets, exit-status checks, backend identity, and host metadata. The same
contract was exercised on 2026-07-31 in a Linux/ARM64 container and Linux/AMD64
emulation; both produced `promotion_ready: true`. Those runs validate the
operand-attribution machinery only and are not native timing measurements.

## Evidence boundary

- Ordinary Memcheck checks branches, addresses, and undefined-value uses. The
  four modern controls are clean across the frozen x86_64 matrix; the
  historical snapshot separately exposes a compiler-induced
  `poly_frommsg` branch under clang `-O1`/`-Os`. Neither result models
  operand-dependent division latency.
- Assembly scanning identifies compiler/optimization/architecture-specific
  variable-latency instruction candidates.
- The patched TIMECOP backend attributes tainted operands reaching those
  instructions.
- In the full `kem_dec` dynamic-taint scope, undefinedness from the secret key
  reaches KS1 but does not survive the recovered-message and hash/re-encryption
  boundary to KS2. The separate site-operand scope attributes both KS2
  compression divisions. Treating the former's KS2 absence as a clean result
  would be scientifically wrong.
- Physical timing remains a separate native-host experiment. Docker or
  emulation output must never be promoted as timing evidence.

The imported historical tree is a source/provenance anchor and functional
smoke target, not a claim that the paper's full Cortex-M key-recovery attack
has been reproduced.
