# ML-KEM assembly evidence v1

This campaign replaces the legacy aggregate `asm-scan` report for paper-facing
ML-KEM public-attribution claims. The legacy report remains useful triage, but
it cannot prove that a candidate-free source was compiled at every optimization
level.

The frozen campaign is
[`mlkem_asm_evidence_v1.yaml`](mlkem_asm_evidence_v1.yaml). It covers every
active `ML-KEM` corpus row with `asm_attribution=public`: ML-KEM-512/768/1024,
both `kem_dec` and `kem_dec_fo`, with GCC and Clang at `-O0`, `-O1`, `-O2`,
`-O3`, and `-Os`. Each harness source is a separate cell.

## Native collection

Collection for paper evidence requires a clean, exact Git commit on native
Linux x86-64. First verify the committed scope:

```sh
uv run python scripts/check_asm_evidence.py --static
```

Then collect the bundle:

```sh
uv run python scripts/build_asm_evidence.py \
  --output-root artifact_runs/mlkem-asm-evidence-v1
```

The builder records, for every
`target × harness × source × compiler × optimization` cell:

- compile and disassembly status;
- compiler identity, version, resolved binary, and binary hash;
- exact compile, `objdump -dSl`, and `nm -n` argument vectors;
- the complete compiler-emitted user-header dependency closure, with every
  input required to be a Git-tracked regular non-symlink and bound by hash;
- content-addressed compiler stdout and stderr transcripts;
- config and source hashes;
- the exact object file, full `objdump -dSl` transcript, and `nm -n` transcript
  as separate SHA-256-addressed files; and
- candidate mnemonic, operand text, full instruction text, address, and
  function attribution.

One failed or missing cell makes coverage `incomplete` and prevents
`paper_eligible=true`. Engineering-only `--allow-dirty` and
`--allow-nonpaper-host` runs are available for debugging, but cannot pass the
paper checker.

## Independent verification

Keep the manifest and its `raw/sha256` directory together, then run:

```sh
uv run python scripts/check_asm_evidence.py \
  --bundle artifact_runs/mlkem-asm-evidence-v1/asm_evidence_bundle.json
```

The checker reconstructs the full expected cell set from the frozen configs,
checks the exact clean commit, requires the same compiler/`objdump`/`nm`
executable hashes, recompiles every source cell, reruns both inspection tools
over the rebuilt and preserved objects, compares canonical assembly and symbol
output to the preserved transcripts, recomputes coverage and attribution, and
verifies individual and aggregate raw hashes. Missing, edited, renamed,
unindexed, extra, or self-consistently fabricated object/transcript files fail
validation.

The verifier assumes the operating system and the recorded compiler/binutils
binaries execute honestly. Their resolved paths, full versions, and executable
hashes are bound and must match at verification, but a malicious compiler and
matching malicious inspection tools are outside this software-only threat
model. Preserve the native host image or a digest-pinned build environment in
addition to the evidence tree when making archival claims.

The large raw transcripts are deliberately excluded from Git by
`artifact_runs/`. Preserve the complete external directory for artifact review;
do not copy only the small JSON manifest.

## Corpus integration

The builder emits one small index per target under
`targets/<target>/ctkat_asm_evidence.json`. Feed that verified index to the
corpus builder:

```sh
uv run python scripts/build_corpus_table.py \
  --project-dir examples/pqc_mlkem768 \
  --family ML-KEM --target pqclean_mlkem768 \
  --asm-evidence-index \
    artifact_runs/mlkem-asm-evidence-v1/targets/pqclean_mlkem768/ctkat_asm_evidence.json \
  --asm-evidence-campaign docs/measurement/mlkem_asm_evidence_v1.yaml \
  --out-dir artifact_runs/mlkem-asm-evidence-v1/corpus-preview
```

The verified bundle supersedes the legacy `ctkat_varlat_candidates.csv/json`.
A harness/compiler/optimization row becomes assembly `PASS` only when every
expected source cell passed. The corpus summary note carries the campaign hash,
bundle path, raw directory, and aggregate raw hash.

## Claim boundary

This evidence proves complete compilation/disassembly coverage and preserves
the exact candidate operands needed for review. It does not itself prove that
an operand is public or secret. The final public attribution still requires the
two-reviewer process in
[`mlkem-public-attribution-v2.yaml`](../reviews/paper/mlkem-public-attribution-v2.yaml).
