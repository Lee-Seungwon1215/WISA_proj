# Native timing experiment preregistration

Status: **internally frozen before physical measurement**

Freeze date: 2026-08-08
Machine-readable plan: `paper_native_campaign_v2.yaml`

This document fixes the hypotheses, units, exclusions, controls, and promotion
rules before a native Linux x86_64 measurement is inspected. It is an internal
preregistration committed with the code, not a claim of registration in an
external registry.

## Research questions and directional hypotheses

1. **Corpus refresh.** Does a paper-grade timing-harness-v2 campaign preserve
   or overturn each legacy timing row when setup is excluded, process repeats
   are independent, and physical controls pass? No direction is assumed.
2. **KyberSlash contrasts.** The full-ML-KEM layer holds one secret key fixed
   and compares frozen, publicly mutated ciphertext pools. Before timing, each
   member must produce the exact independently computed ML-KEM rejection key;
   a mutation or mismatch with the original shared secret alone is not
   accepted as an invalidity witness. This remains a non-directional
   chosen-input comparison and cannot establish secret attribution. In the
   separate direct-operand layer, each vulnerable
   KS1/KS2 site is expected to show a larger coefficient-bin timing signal than
   its matched reciprocal-multiply implementation. These canaries establish
   operand-dependent hardware latency only, not a full attack or key recovery.
3. **Falcon comparator.** Reference Falcon, c-fn-dsa native floating point,
   and c-fn-dsa integer-FPR profiles may differ in timing leakage. This is a
   non-directional comparison. It is not an FN-DSA conformance experiment.
4. **Source/build diversity.** The portable and x86_64-native builds of the
   same pinned mlkem-native or mldsa-native parameter set may produce different
   timing classifications. This is non-directional and does not treat the two
   profiles as independent implementation lineages.

## Experimental unit and frozen design

- A primary experimental unit is one `(physical host, target, harness,
  process seed)` trace.
- Final evidence requires two non-virtualized physical x86_64 Linux hosts with
  distinct CPU model strings, the same CT-KAT commit, and three process seeds
  per target axis on each host.
- A host must have one pinned CPU available, invariant-TSC-compatible RDTSCP,
  no detected emulation or virtualization, and the performance governor where
  the platform exposes one.
- Pilot results are kept outside final result directories. After a pilot, only
  operational changes that do not alter source, flags, protocol, hypotheses,
  thresholds, or exclusions are allowed. Any substantive change creates a new
  campaign version and invalidates prior final traces.
- A target repeated in two components (the corpus refresh and a family-local
  control) is executed independently in both. Cross-component trace reuse or
  best-replicate selection is forbidden; duplicate executions do not increase
  the implementation-lineage count.
- Frozen component manifests are checked by
  `python3 scripts/check_paper_campaign.py`.

## Primary and secondary endpoints

The primary endpoint for each axis is the official-dudect raw classification
from the complete target trace, with its fixed upstream threshold, conditional
on all CT-KAT physical controls and artifact-integrity checks passing. A result
whose controls fail is **inconclusive**, never clean.

Secondary endpoints are:

- signed and absolute Welch statistics for the predeclared analysis tests;
- effect direction and repeat consistency across process seeds and hosts;
- the observed detection fraction at each predeclared injected delay, plus an
  A/A-noise-derived nominal sensitivity diagnostic;
- for signature harnesses, output-length distribution and time/length
  association, reported separately from the primary full-API timing verdict;
- pairwise contrasts within KyberSlash and Falcon groups;
- build-profile contrasts within one upstream lineage.

Secondary endpoints do not override the primary classification and cannot
declassify a risk finding.

## Sample sizes and controls

- Every primary axis uses 30,000 requested target measurements per process.
- KEM controls use 10,000 requested measurements; signature controls use 5,000.
- Each target binary runs three process repeats, A/A, setup-only placebo, and a
  three-point positive-control curve. Effects are fixed in the component
  manifests and cannot be selected after observing a target trace.
- The largest predeclared injected delay must be detected in at least
  `ceil(target_power * process_repeats)` repeats; with the frozen three repeats
  and `target_power=0.8`, this means three detections. This observed fraction is
  an acceptance control, not a precise achieved-power estimate. Detection is
  directional: the delayed class 1 must have a positive mean delta and
  `t <= -positive_abs_t_threshold`; an equally large reversed effect does not
  pass. The separately reported A/A normal-approximation diagnostics include
  both the legacy alpha-based nominal sensitivity and the effect implied by the
  actual directional threshold. Neither bounds the target trace. All A/A runs
  must stay within the frozen limit. AUX/core migration, truncated traces, RNG
  interposition failure, malformed output lengths, or artifact-hash mismatch
  invalidate that unit.
- Every axis with a linked-binary contract must preserve the exact measured
  binary, generated source, compiler/config/source hashes, and full
  disassembly. The validator reparses that disassembly; a missing or
  unexpected division/FP instruction contract invalidates the unit before
  timing interpretation.
- Requested counts are not reported as retained counts. Dropped and retained
  counts are preserved in the artifact and tables use the latter.

## Exclusions fixed before observation

Exclude a unit only for a machine-checkable reason recorded by the runner:

1. virtualization, emulation, unsupported clock, missing affinity, or CPU
   migration;
2. compile/runtime timeout, non-zero harness failure, incomplete trace, schema
   failure, or hash mismatch;
3. control failure, insufficient official class counts, or failed seeded RNG
   interposition;
4. host or commit mismatch with the frozen campaign.

Thermal drift, an unexpected effect direction, a large statistic, or
disagreement with a prior result is not an exclusion reason. Outliers are kept;
the frozen official analysis owns its filtering and percentile tests.

## Analysis and multiplicity

- Report every predeclared target/axis/host result; no best-host or best-repeat
  selection is permitted.
- Primary claims are axis-specific. No single aggregate "accuracy" or global
  clean percentage is computed across unlike algorithms and threat models.
- Families of pairwise secondary comparisons use Holm adjustment within the
  full-ML-KEM chosen-ciphertext family; each of the three vulnerable/patched
  operand-site pairs; Falcon-512; Falcon-1024; mlkem-native; and mldsa-native.
  Both raw and adjusted values are retained.
- Host heterogeneity is reported explicitly. A leak on either valid host keeps
  the combined result at risk; disagreement cannot be averaged into clean.
- Absence of a threshold crossing is worded `no finding observed under this
  protocol`, not constant-time proof.

## Review and promotion

The runner writes immutable promotion candidates and never edits the curated
corpus. Promotion requires:

1. complete artifacts and recorded SHA-256 hashes from both hosts;
2. passing controls and schema checks;
3. passing automated engineering audits, which are provenance-bearing checks
   but never count as human approval;
4. two independent human reviewers, with no self-review, recorded in
   `docs/reviews/paper/`;
5. unanimous approval for a clean/declassification change. A reviewer reject
   makes the packet disputed; missing review keeps it pending;
6. an explicit, reviewed corpus update commit.

OpenSSL 3.5 is retained as a provider-API integration/build case only. It is
not included in the timing lineage comparison unless a separately versioned
adapter and preregistration are committed before its measurements begin.
