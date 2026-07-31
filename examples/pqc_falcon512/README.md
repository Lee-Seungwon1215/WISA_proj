# PQClean Falcon-512 Reference Target

This example imports PQClean `crypto_sign/falcon-512/clean` as an explicitly
named Falcon reference-family signing target. It is included in the paper
corpus only as a `needs-analysis` boundary row, not as prospective FN-DSA, a
constant-time implementation, or an accepted-variable-time row.

## Harness Policy

Falcon private keys are encoded as:

- `sk[0]`: public format/header byte
- `sk[1..]`: encoded private `f`, `g`, `F`

The CT harness taints only `sk[1..]`. Full-sk taint would mark the public header
secret and create an immediate false branch finding in the format check.
Key generation and signing randomness come from the repository-owned
`falcon_comparator_support/deterministic_randombytes.c` interposer, so repeated
structural runs analyze the same valid key/path. That interposer is not
production randomness and is excluded from physical timing.

## Frozen Structural Result

The versioned Docker/QEMU snapshot was regenerated on 2026-07-31 with
deterministic randomness:

- `ct-matrix`: FAIL in all eight gcc/clang debug/opt1/release/opt3 cells.
- Finding counts are gcc 28/40/40/40 and clang 24/30/31/31.
- Main finding families: private-key decode checks, private-key completion,
  Gaussian sampler/rejection, and signature compression.
- `asm-scan`: six rows across the Keccak rate divisions and
  `keygen.c:solve_NTRU_intermediate`. The keygen candidate is not signing-leak
  evidence by itself because keypair generation runs before taint.

The committed identity is `pqclean_falcon512_reference`. Treat it as
`needs-analysis`; do not promote it to an accepted row solely because this
example exists.

## Attribution Probes

Two follow-up probes are included:

- `ctkat_core.yaml`: manual harnesses that decode/complete/hash before taint,
  then taint either raw `f,g,F,G` (`sign_core_dyn`) or the expanded private key
  (`sign_core_tree`) before calling Falcon's internal signing functions.
- `ctkat_split.yaml`: template harnesses named `sign_little_f_only`,
  `sign_little_g_only`, and `sign_big_f_only`. These names remain distinct on
  case-insensitive filesystems.

Observed result:

- API wrapper noise is real but not the main story. Removing private-key decode,
  private-key completion, and signature compression still leaves structural
  findings in `fpr_floor`, `BerExp`, `PQCLEAN_FALCON512_CLEAN_sampler`, and the
  signing acceptance loop.
- `sign_core_dyn` and `sign_core_tree` both FAIL, so the core sampler/signing
  path remains tainted even after using pre-decoded or pre-expanded key material.
- `f`, `g`, and `F` split-taint runs all reach the same sampler/compression
  function family (26/25/25 findings respectively). This is not a single bad
  encoded-key field.

Interpretation: Falcon is valuable as a `needs-analysis` stress target, but it is
not currently a cheap `accepted-variable-time` corpus row. The signal is not the
same kind as ML-DSA's nonce-driven rejection or SPHINCS+'s public-output data
flow: Falcon's sampler path is reached from long-term private-key material. Under
CT-KAT's syntactic structural criterion, that is correctly flagged. Whether this
specific implementation is timing-safe depends on a Falcon-specific isochrony
argument for the Gaussian sampler, Bernoulli-exp path, floating-point emulation,
acceptance loop, and variable-size signature encoding under the exact build.
That argument is outside the automatic registry. Do not register
`sampler`/`BerExp`/`fpr_floor` wholesale.

## Commands

```bash
docker compose run --rm ctkat-dev python3 -m ctkat ct --config examples/pqc_falcon512/ctkat.yaml
docker compose run --rm ctkat-dev python3 -m ctkat ct-matrix --config examples/pqc_falcon512/ctkat.yaml
docker compose run --rm ctkat-dev python3 -m ctkat asm-scan --config examples/pqc_falcon512/ctkat.yaml --opt -O0 --opt -O1 --opt -O2 --opt -O3 --opt -Os --cc gcc --cc clang
docker compose run --rm ctkat-dev python3 -m ctkat run --config examples/pqc_falcon512/ctkat_core.yaml
docker compose run --rm ctkat-dev python3 -m ctkat ct --config examples/pqc_falcon512/ctkat_split.yaml
```
