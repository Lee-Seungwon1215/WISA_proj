# Paper native analysis v1

Status: **freeze before final measurement**

Implementation: `scripts/analyze_paper_native_results.py`

This document fixes the two-host merge and secondary statistical analysis. It
does not change the official-dudect primary endpoint in
`EXPERIMENT_PREREGISTRATION.md`.

## Fail-closed input contract

The named analysis accepts only a schema-v4 final measurement bundle with exactly
two distinct physical-host identities and exact, distinct CPU model strings.
Every component must be a complete `run_kind=final` campaign at the bundle's
40-hex measurement commit. A separate verification commit may differ only in
non-measurement-critical files. The component manifest, target artifact hashes, backend
report, and protocol trace hashes are checked before statistics are emitted.
The selected ML-KEM assembly bundle is part of the same contract and must bind
the measurement commit, preserved object files, `nm` transcripts, and fresh
`objdump`/`nm` verification.
All upstream campaign and same-corpus validators must pass. A missing target,
host, process repeat, class, hash, or signature correctness field aborts the
whole analysis rather than producing a partial clean result.

The named output records the SHA-256 and byte length of every consumed input and an
aggregate digest over the sorted input ledger. JSON, CSV, and Markdown outputs
contain no wall-clock timestamp and are byte-deterministic for the same inputs.

## Analyst-label blinding and byte parity

The custodian first runs `--output-mode blinded` with the private draft
blinding record. Every real component, target, target-family, harness/axis, and
logical input-ledger label is removed from analyst-facing JSON/CSV/Markdown.
Only randomly assigned target labels, opaque group/axis labels, and the
canonical label-map SHA-256 remain. A deterministic blinded manifest binds the
hash and byte length of every output file.

Before unblinding, the custodian records that manifest hash and the blinded
analysis completion time in the structured unblinding record. After
unblinding, `--output-mode unblinded` recomputes the named analysis, applies
the same opaque transform, and requires byte-for-byte equality with every
frozen blinded output. It also requires the blinded manifest SHA-256 to match
the structured record. Named results are not emitted if parity fails. Human
custodian/analyst separation and access ordering remain attestations; they are
not mislabeled as properties software alone can prove.

## Primary two-host decision

Each `(component, target, harness, axis)` remains separate. Both host results
are retained. The combined state is folded in this order:

1. a valid official-dudect `FAIL` on either host is `risk-detected`;
2. an invalid host result is `inconclusive`;
3. a valid `WARNING` on either host is `needs-review`;
4. only two valid `PASS` results become `no-finding-observed`.

Thus disagreement cannot average away a finding. None of the secondary tests
below can override the primary state.

## Repeat-level effect and pairwise contrasts

For each process repeat, the secondary effect is

`mean(cycles | class=1) - mean(cycles | class=0)`.

Dropped timing rows are excluded, while every requested row must still be
present in the protocol trace. For each preregistered family, every pair of
targets is compared with a two-sided Welch test over the six repeat effects
(three process repeats on each of two hosts). Raw p-values are retained and
Holm adjusted separately inside these families:

- full-ML-KEM fixed-key chosen-ciphertext;
- KyberSlash1 vulnerable/patched direct operand;
- KyberSlash2-poly vulnerable/patched direct operand;
- KyberSlash2-polyvec vulnerable/patched direct operand;
- Falcon-512;
- Falcon-1024;
- mlkem-native mixed valid-tuple profile;
- mldsa-native.

The contrast is a secondary diagnostic, not an additional implementation
lineage and not a replacement for the official 102-test dudect result.
The full-ML-KEM chosen-ciphertext family is a public-input comparison. The
three operand families are hardware-latency canaries. Neither is reported as
secret attribution, a full attack, or key recovery without separate evidence.
The mlkem-native family changes secret keys, matching public ciphertexts, and
embedded public-key material together. It is reported only as a valid-tuple
build-profile contrast and never as a secret-key leakage attribution.

## Host heterogeneity

Each axis reports the host mean repeat effect, Cochran's Q, its one-degree-of-
freedom p-value, and I-squared. A warning is recorded if raw statuses disagree,
effect directions disagree, or I-squared is at least 75%. If a host has zero
within-host repeat variance, Q/I-squared are reported as unavailable and this
is itself a warning. Heterogeneity never declassifies a host finding.

## Signature length association and correctness

Every signature protocol row must carry an integer
`signature_return_code=0`. The backend metadata for every target repeat and
the selected analysis repeat must state that return codes were recorded, the
signature correctness gate passed, zero measured contract failures occurred,
and a consistent `fixed` or `bounded` output-length contract applied. Any
failed call or contract violation invalidates the analysis.

For retained target rows, variable-length signatures report the Pearson
correlation and ordinary least-squares slope between output length and cycles.
A second Pearson result is calculated after centering length and cycles within
each secret class, so a class shift is not silently presented as a pure length
effect. Two-sided Student-t p-values are retained. Fixed or empirically
constant lengths are reported explicitly as `constant-length`, with
correlation, slope, and p-value left null rather than fabricated as zero.

## Reproduction

```bash
uv run python scripts/analyze_paper_native_results.py \
  --bundle /path/to/final-bundle.yaml \
  --verification-commit 0123456789abcdef0123456789abcdef01234567 \
  --output-mode blinded \
  --blinding-record /custodian/private/unblinding-draft.yaml \
  --output-root artifact_runs/paper-native-analysis-blinded

uv run python scripts/analyze_paper_native_results.py \
  --bundle /path/to/final-bundle.yaml \
  --verification-commit 0123456789abcdef0123456789abcdef01234567 \
  --output-mode unblinded \
  --blinded-output-root artifact_runs/paper-native-analysis-blinded \
  --output-root artifact_runs/paper-native-analysis-unblinded
```

Repeat either command with `--check-output` to compare regenerated bytes
without writing them.

The submission gate wraps this analysis in three explicit stages:

1. `reproduce_artifact.sh --profile verification` validates the bundle, checks
   blinded parity, emits named outputs, and creates the canonical
   `final_evidence_manifest.json` root.
2. Commit the root-bearing pending `native-promotion-v2.yaml` as R0. Two
   independent humans review that immutable candidate and exact clean R0
   contract, then a later R1 records both approvals with
   `reviewed_commit: R0`; partial approvals are never committed.
3. `--profile paper-ready --candidate-root ...` regenerates deterministic
   outputs in check mode and requires the completed packet to bind the same
   root. A descendant is accepted only when
   `docs/reviews/paper/native-promotion-v2.yaml` is the sole file changed after
   candidate verification.
