# CT-KAT evidence schema v2.0

> Status: **ACTIVE / fail-closed** as of 2026-07-30.
>
> The frozen v1.2 inputs are preserved under
> `docs/corpus/archive/v1.2/`; its frozen v2 output is under
> `docs/corpus/archive/v2.0-from-v1.2/`. The deterministic migration is
> `python scripts/migrate_evidence_v1_to_v2.py --check`.

## Why v2 exists

The v1 `verdict_class` mixed raw detector output, human attribution, timing
quality, and the final action in one label. That allowed this contradictory row:

```text
dudect_status=FAIL, |t|=145.316, verdict_class=robust
```

The note explained that the timing harness was confounded, but a free-text note
cannot cancel a machine-readable `robust` headline. V2 separates every layer and
computes one five-state `overall` value with a single implementation:
`ctkat/evidence.py`.

The strongest clean-sounding value is now deliberately narrow:

> `no-finding-observed` means that the executed, interpretable layers produced
> no unresolved finding for this harness. It is not a constant-time proof.

## Core evidence object

Every summary row and every `ctkat screen` summary contains:

| field | allowed values | meaning |
|---|---|---|
| `schema_version` | `2.0` | breaking artifact schema version |
| `correctness` | `pass`, `fail`, `error`, `not-run` | KAT/correctness precondition |
| `structural` | `no-finding`, `finding`, `incomplete`, `error`, `not-run` | Valgrind/ct-matrix layer |
| `asm` | `no-candidate`, `candidate`, `incomplete`, `error`, `not-run` | emitted variable-latency instruction scan |
| `asm_attribution` | `public`, `secret-risk`, `mixed`, `unresolved`, `not-applicable` | human/source attribution of asm candidates |
| `timing_validity` | `valid`, `confounded`, `insufficient-power`, `environment-rejected`, `error`, `not-run` | whether the timing experiment is interpretable |
| `timing_signal` | `no-signal-observed`, `warning`, `signal`, `not-interpretable`, `not-run` | observed statistical signal, separate from validity |
| `review` | `not-needed`, `pending`, `reviewed`, `disputed`, `expired` | maturity of human judgment |
| `review_id` | artifact ID or empty | resolves to `docs/reviews/<id>.yaml` in the curated corpus |
| `overall` | `no-finding-observed`, `risk-detected`, `needs-review`, `inconclusive`, `tool-error` | computed user action |
| `legacy_verdict_class` | v1 taxonomy | migration provenance only; never the v2 headline |

The machine-readable core schema is
`ctkat/schemas/evidence-v2.schema.json` and is bundled in the wheel. JSON Schema checks shape and enums;
`EvidenceV2` additionally recomputes `overall` and rejects contradictions.

## Overall fold

`fold_overall()` applies this priority:

1. `correctness=fail` makes downstream interpretation `inconclusive`.
2. A confirmed structural/asm risk or a **valid** timing signal becomes
   `risk-detected`.
3. A layer `error` becomes `tool-error` unless a confirmed risk already exists.
4. Partial structural/asm coverage or timing that is
   `confounded|insufficient-power|environment-rejected` becomes `inconclusive`.
5. A timing warning, unresolved attribution, or
   `pending|disputed|expired` review becomes `needs-review`.
6. Only an otherwise consistent record becomes `no-finding-observed`.

Important invariants:

- `timing_validity != valid` can never supply clean or risk evidence.
- A raw timing `FAIL` with `timing_validity=confounded` is `inconclusive`, not
  `risk-detected` and certainly not clean.
- A raw timing `PASS` without power calibration is
  `insufficient-power / no-signal-observed`, therefore `inconclusive`.
- `review=reviewed|disputed|expired` requires a stable `review_id`.
- `asm=candidate` cannot use `asm_attribution=not-applicable`.
- `asm=no-candidate|not-run` must use `not-applicable`.
- An explicitly stored `overall` that differs from the fold is invalid.

## Timing migration and backend policy

The frozen v1.2 corpus used the old Python implementation and is therefore
recorded as `experimental-first-order-v1`. It is not relabelled after the fact.
New runs default to the pinned `official-dudect-dc269651` backend, which
executes the upstream 102-test family through a separate C adapter.

V1 rows had no A/A false-alarm budget or positive-control power curve.
Therefore:

- completed v1 timing defaults to `timing_validity=insufficient-power`;
- the ML-KEM-768 `sk` row is explicitly `confounded`;
- its timing-only `ct` axis has no matching v1 cell artifact, so migrated
  structural/asm layers are `not-run` instead of copying summary-only claims;
- raw `PASS|WARNING|FAIL`, `|t|`, sample count, seed, threshold, and axis remain
  visible as provenance;
- no historical timing row is silently promoted to `valid`.

Backend-v2 now records the environment, rejects QEMU and unpinned Linux
processes, preserves raw `INSUFFICIENT`, and carries explicit validity reasons.
Its committed synthetic calibration covers backend A/A, an injected-effect
power curve, and uncropped same-trace parity. That artifact validates the
statistical adapter only.

Timing-harness-v2 KEM/sign runs may emit `valid` only after their physical A/A,
target positive controls, pool/common-buffer symmetry, repeated-process, and
native-host gates all pass. Legacy KEM/sign artifacts remain `confounded` and
generic targets remain `insufficient-power`; an official raw PASS or FAIL is
non-decisional for the v2 headline unless those target-level gates pass.

The deferred native refresh is frozen in
[`measurement/native_timing_v2_campaign.yaml`](measurement/native_timing_v2_campaign.yaml).
Its runner emits a checked `corpus_timing_updates.csv`, but never rewrites this
curated corpus. Runtime report metadata is authoritative for backend, emitted
sample count, and analysis seed; YAML values are only fallbacks because a
campaign may deliberately override modest example defaults.

## Review artifacts

V1 used `basis=review` and often stored the entire judgment in `notes`. V2 does
not infer completion from either field.

For the curated corpus:

- `review=reviewed|disputed|expired` requires `review_id`;
- that ID must resolve to `docs/reviews/<review_id>.yaml`;
- the artifact status must match the row;
- its scope must include the exact `(target, harness)`;
- reviewers, decision, evidence, and limitations are mandatory.

The migrated records honestly say that they currently have one maintainer
review. Two independent reviewers remain a later paper-submission gate.

`triage.yaml` supports the same linkage:

```yaml
harnesses:
  kem_dec:
    varlat: public
    review: reviewed
    review_id: rvw-mlkem-evidence-v1
```

Public attribution without a completed artifact stays `review=pending` and
cannot clear the screen.

## `corpus_cells.csv`

One row per `(target, harness, combo)`:

```text
schema_version,family,target,harness,combo,cc,cc_version,opt,cflags,arch,
ctkat_commit,ct_status,ct_findings,ct_finding_funcs,ct_error,
asm_status,asm_div_count,asm_div_funcs,asm_error
```

The cell table preserves raw build evidence:

- both named `combo` and full `cflags`;
- compiler/version, architecture, and CT-KAT commit;
- structural status/findings/error separately from asm count/functions/error.
- `asm_status=PASS|ERROR|NOT_RUN` per build cell, so a compiler/opt outside the
  recorded asm-scan coverage cannot masquerade as zero candidates.
- an asm compiler/opt outside the structural matrix is retained as an
  `asm_only_*` combo with `ct_status=NA`, rather than silently dropping its
  candidate or error.

V1.2 did not have `asm_status`. Its frozen refresh recipe requested both
recorded compilers across the opt matrix, so the migration manifest explicitly
maps a legacy cell with empty `asm_error` to `PASS`. This assumption applies
only to the frozen archive; new producers require the JSON coverage manifest
and emit `NOT_RUN` when coverage is absent.

## `corpus_summary.csv`

One row per `(target, harness)`. Exact field order:

```text
schema_version,family,target,harness,
correctness,structural,asm,asm_attribution,
timing_validity,timing_signal,review,review_id,overall,
ct_flips,ct_status_set,ct_finding_funcs,
varlat_candidates,varlat_triage,
timing_backend,timing_raw_status,timing_abs_t,timing_measurements,
timing_leak_target,timing_seed,timing_threshold,
legacy_verdict_class,legacy_basis,notes
```

The first block is the normalized v2 decision object. The remaining columns are
raw or migration provenance:

- `ct_*` and `varlat_*` retain the per-layer observations;
- `timing_raw_status` preserves PASS/WARNING/FAIL/INSUFFICIENT/ERROR output;
- `timing_*` parameters make the experiment traceable; official dudect uses
  `timing_threshold=|t|>10;n0>=10001`, not the legacy `4.5/10.0` warning/fail
  pair;
- `legacy_*` makes the v1→v2 decision auditable but has no headline authority;
- `notes` can explain evidence but cannot override typed fields.

## Producers and gates

- `ctkat screen` emits v2 `screen_summary.csv`, JSON, and Markdown directly.
- `scripts/build_corpus_table.py` emits v2 corpus rows directly.
- `scripts/migrate_evidence_v1_to_v2.py` reproduces the frozen v2 migration
  snapshot from v1.2 inputs plus `evidence_migration.toml`. The active corpus
  was initialized from it but may evolve through later measured refreshes.
- `scripts/check_corpus.py` validates headers, enums, the recomputed overall
  fold, review artifact scope, JSON-schema enum drift, and raw provenance.
- `scripts/render_readme_corpus.py` generates the README snapshot from the v2
  summary, so old `FAIL + robust` prose cannot return unnoticed.

Any change to enum values, fold behavior, or CSV field order requires another
schema version and migration note.
