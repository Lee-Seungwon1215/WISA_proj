# Paper native analysis v2: single-host profile

Status: **frozen before the v6 final measurement**

Implementation: `scripts/analyze_paper_native_results.py`

This profile replaces the unavailable two-host and independent-analyst gates
for the v6 campaign. It does not relabel one machine as replicated evidence.
Every conclusion is scoped to the recorded physical CPU, OS, compiler, binary,
input distribution, and three process repeats.

## Admissible input

The named analysis accepts only a schema-v5 bundle containing exactly one
physical, non-virtualized Linux x86_64 host. All four native components and all
three same-corpus baselines must be complete `run_kind=final` results at one
clean commit. Each result must carry the automated frozen-input integrity gate,
must explicitly record `independent_human_review=false` and
`cross_host_reproducibility=false`, and must pass its original validator.

The host tree is bound by `SHA256SUMS`. Component run IDs are unique, host and
boot identity metadata are retained, compiler version/executable hashes must
agree, and the ML-KEM assembly evidence bundle must bind the same commit. A
missing target, process repeat, class, control, build seal, input contract, or
hash aborts the complete analysis.

## Primary decision

Each `(component, target, harness, axis)` is reported separately. A valid
official-dudect `FAIL` is `risk-detected`, an invalid/confounded result is
`inconclusive`, a valid `WARNING` is `needs-review`, and a valid `PASS` is
`no-finding-observed under this host and protocol`. No result is called a
constant-time proof.

There is no host merge, Cochran Q, or I-squared value in this profile. Those
fields are emitted as not applicable rather than fabricated from process
repeats. The three repeats estimate within-host stability; they are not three
independent machines.

## Secondary analysis

The predeclared pairwise families use a two-sided Welch test over the three
per-process class-mean deltas for each target. Raw p-values and family-local
Holm adjustments are retained. Falcon output-length association uses both the
ordinary and within-class-centered Pearson result. Secondary results never
override or declassify a primary finding.

ML-KEM `valid_tuple` changes matching public and secret material together.
Chosen-ciphertext comparisons are public-input contrasts. Operand-bin results
are hardware-latency canaries. These labels remain mandatory even for a large
statistic.

## Named deterministic output

Because no independent analyst is available, v6 does not claim analyst
blinding. The schema-v5 bundle freezes a named output directory. The analyzer
records every input hash and emits deterministic JSON, CSV, and Markdown files
without timestamps. Re-running with `--check-output` must reproduce the exact
bytes.

```bash
uv run --frozen python scripts/analyze_paper_native_results.py \
  --bundle /path/to/measurement_bundle.yaml \
  --verification-commit 0123456789abcdef0123456789abcdef01234567 \
  --output-mode named \
  --output-root /path/to/analysis/named
```

## Claim boundary

The resulting tables are paper-usable as a preregistered single-host
evaluation. They do not establish cross-host reproducibility, architecture
generality, independent human declassification, or inter-rater agreement.
Those are explicit limitations, not silently satisfied gates.
