# Falcon reference-vs-comparator study

This suite replaces the old single unresolved Falcon row with six directly
named build profiles:

| Degree | Implementation | FP profile | Identity |
|---|---|---|---|
| 512 | PQClean clean | integer floating-point emulation | Falcon reference |
| 1024 | PQClean clean | integer floating-point emulation | Falcon reference |
| 512 | c-fn-dsa | architecture-native binary64 | prospective FN-DSA snapshot |
| 512 | c-fn-dsa | integer binary64 emulation | prospective FN-DSA snapshot |
| 1024 | c-fn-dsa | architecture-native binary64 | prospective FN-DSA snapshot |
| 1024 | c-fn-dsa | integer binary64 emulation | prospective FN-DSA snapshot |

“Prospective” is not lawyerly garnish. At the pinned c-fn-dsa revision, its
own README says that no FN-DSA draft has been published, calls the encoding a
best guess of FIPS 206, and warns that compatibility is not promised before
1.0. NIST's selected-algorithms page still labels FALCON's FIPS as “coming
soon” at this suite's 2026-07-31 snapshot. Therefore none of these rows claims
FIPS 206 conformance. See the
[NIST selected-algorithms page](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/selected-algorithms)
and the pinned upstream `README.md`.

## What is actually compared

Both c-fn-dsa profiles compile the same exact source commit. The native profile
disables AVX2 dispatch but lets upstream select SSE2, NEON, or RV64D. The
integer profile explicitly disables every hardware-FP backend, selecting
`sign_fpr.c`'s software binary64 arithmetic and the integer post-sampling path.
The checker requires the two profiles to produce byte-identical deterministic
key/signature transcripts for both degrees.

The signing-key taint boundary is deliberately narrower than “all bytes”:

- PQClean: skip the public format byte and taint encoded `f`, `g`, and `F`.
- c-fn-dsa: additionally skip the final 64-byte hashed verifying key, which is
  public-derived material stored in the signing-key format.

The manifest maps decode, completion, sampler, acceptance, encoding, and full
API boundaries. PQClean's existing dynamic/tree core probes and its `f/g/F`
split probe remain attribution evidence. The degree-1024 peer now has the same
encoded-component split. c-fn-dsa's public C API is encoded-key-only at this
snapshot; an “expanded-key API” result is therefore recorded as unavailable,
not invented with a wrapper and mislabeled upstream.

## Frozen structural result

The versioned x86_64/QEMU snapshot records the following Linux runs. `x/y
FAIL` means `x` matrix cells out of `y` produced Memcheck-observable
secret-origin control/address uses; it is not a physical timing verdict.

| Target/profile | Matrix | Narrow attribution | Integer-div scan |
|---|---:|---|---:|
| PQClean Falcon-512 reference | 8/8 FAIL | `f`, `g`, and `F` each reach decode, completion, sampler, acceptance, and encoding; dynamic/tree core both retain sampler findings | 6 rows / 3 functions |
| PQClean Falcon-1024 reference | 4/4 FAIL | `f`, `g`, and `F` each reach the same full-sign boundary family | 3 rows / 3 functions |
| c-fn-dsa-512 native FP | 4/4 FAIL | direct decode: 1; sampler: 2; encoding: 3 findings | 0 |
| c-fn-dsa-512 integer FPR | 4/4 FAIL | all three encoded origins reach decode, sampler, bounded sign core, and encoding | 0 |
| c-fn-dsa-1024 native FP | 4/4 FAIL | direct decode: 1; sampler: 2; encoding: 3 findings | 0 |
| c-fn-dsa-1024 integer FPR | 4/4 FAIL | all three encoded origins reach decode, sampler, bounded sign core, and encoding | 0 |

This is intentionally not massaged into “reference bad, comparator good.”
c-fn-dsa's pinned sampler source argues probabilistic decorrelation and
isochrony for paths that a syntactic undefinedness screen still reports.
Those findings stay visible and unwhitelisted. Accepting or rejecting that
argument requires the missing native paired timing campaign and independent
review; the upstream's constant-time intent alone is not a result.

The component harnesses are named `sign_little_f_only`,
`sign_little_g_only`, and `sign_big_f_only`. Avoiding names distinguished only
by `f` versus `F` prevents generated binaries from colliding on
case-insensitive filesystems.

## Floating-point evidence

`audit_falcon_fp.py` preprocesses the selected feature macros, compiles the
seeded signer, disassembles it, and inventories FP, division, square-root,
conversion/rounding, and external math-library calls by function. It also
screens the native deterministic KAT for invalid, divide-by-zero, overflow,
and underflow FP exceptions. This tests one frozen execution only. It does not
prove that NaN, infinity, or denormal values are unreachable for every valid
key, and opcode presence alone is never promoted to a leak verdict.

Run the host-independent integrity and KAT checks:

```bash
python scripts/check_falcon_comparators.py
```

After regenerating the ignored raw reports, compare every matrix cell,
finding count/function set, effective profile flag, and asm row with the
versioned normalized snapshot:

```bash
python scripts/check_falcon_comparators.py --verify-local-reports
```

Run the Linux structural matrices and FP audit:

```bash
docker compose run --rm ctkat-dev \
  python3 -m ctkat ct-matrix --config examples/pqc_falcon512/ctkat.yaml
docker compose run --rm ctkat-dev \
  python3 -m ctkat ct-matrix --config examples/pqc_falcon1024/ctkat.yaml
docker compose run --rm ctkat-dev \
  python3 -m ctkat ct-matrix --config examples/c_fndsa512_prospective/ctkat.yaml
docker compose run --rm ctkat-dev \
  python3 -m ctkat ct-matrix --config examples/c_fndsa1024_prospective/ctkat.yaml
docker compose run --rm ctkat-dev \
  python3 -m ctkat run --config examples/c_fndsa512_prospective/ctkat_boundaries.yaml
docker compose run --rm ctkat-dev \
  python3 -m ctkat run --config examples/c_fndsa1024_prospective/ctkat_boundaries.yaml
docker compose run --rm ctkat-dev \
  python3 -m ctkat run --config examples/pqc_falcon512/ctkat_split.yaml
docker compose run --rm ctkat-dev \
  python3 -m ctkat run --config examples/pqc_falcon1024/ctkat_split.yaml
docker compose run --rm ctkat-dev \
  python3 -m ctkat run --config examples/pqc_falcon512/ctkat_core.yaml
docker compose run --rm ctkat-dev \
  python3 -m ctkat run --config examples/c_fndsa512_prospective/ctkat_split.yaml
docker compose run --rm ctkat-dev \
  python3 -m ctkat run --config examples/c_fndsa1024_prospective/ctkat_split.yaml
docker compose run --rm ctkat-dev \
  python3 -m ctkat asm-scan --config examples/pqc_falcon512/ctkat.yaml \
    --cc gcc --cc clang --opt=-O0 --opt=-O1 --opt=-O2 --opt=-O3 --opt=-Os
docker compose run --rm ctkat-dev \
  python3 -m ctkat asm-scan --config examples/pqc_falcon1024/ctkat.yaml \
    --cc gcc --cc clang --opt=-O0 --opt=-O1 --opt=-O2 --opt=-O3 --opt=-Os
docker compose run --rm ctkat-dev \
  python3 -m ctkat asm-scan --config examples/c_fndsa512_prospective/ctkat.yaml \
    --cc gcc --cc clang --opt=-O0 --opt=-O1 --opt=-O2 --opt=-O3 --opt=-Os
docker compose run --rm ctkat-dev \
  python3 -m ctkat asm-scan --config examples/c_fndsa1024_prospective/ctkat.yaml \
    --cc gcc --cc clang --opt=-O0 --opt=-O1 --opt=-O2 --opt=-O3 --opt=-Os
docker compose run --rm ctkat-dev \
  python3 scripts/audit_falcon_fp.py --output docs/ground_truth/falcon/fp_audit_x86_64.json
```

The direct and split runs exit `2` because their expected evidence is a
structural finding. Treating that exit as an infrastructure error would be as
wrong as treating it as a physical leak proof.

## Evidence ceiling

Structural findings tell us where secret-origin undefinedness reaches a
branch, address, or other Memcheck-observable use. c-fn-dsa's sampler comments
make a probabilistic decorrelation/isochrony argument; an ordinary syntactic
taint screen is allowed to flag such paths. Neither a structural pass nor fail
settles physical timing.

The bare-metal paired timing campaign remains `blocked-by-native-linux-host`.
When that host exists, run reference and comparator profiles under the same
pool/common-buffer/A-A protocol, split core versus full encoding, retain
signature-length correlation, and record fixed-key versus fresh-key axes.
