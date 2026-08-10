# Native timing experiment preregistration

Status: **v4 frozen after disclosed Falcon/diverse engineering calibrations; no final measurement collected**

Initial freeze date: 2026-08-08
V3 amendment freeze date: 2026-08-10
V4 amendment freeze date: 2026-08-10
Machine-readable plan: `paper_native_campaign_v4.yaml`

This document fixes the hypotheses, units, exclusions, controls, and promotion
rules before a native Linux x86_64 measurement is inspected. It is an internal
preregistration committed with the code, not a claim of registration in an
external registry.

## V4 mixed-input attribution and compile-contract amendment

An engineering-only diverse v1 run at commit
`b0b987d500bdb745d1c43035ee5330bb5579cd3d` completed the portable
mlkem-native target before any final run. The other three targets stopped at
compile time: both x86_64 profiles enabled upstream native backends without
passing their required metadata-header macros, and the ML-DSA timing adapter
did not expose the verifier required by the untimed sign-to-verify correctness
gate. These are harness/configuration defects, not timing results.

The completed portable ML-KEM target produced a large same-direction signal in
all three process repeats while A/A, setup-placebo, and positive controls
passed. Independent raw review showed that the legacy machine label `sk` did
not hold public input material fixed: class 0 repeated one valid `(sk, ct)`
tuple and class 1 selected fresh keypairs and their matching valid
ciphertexts. The secret key, public ciphertext, and public-key material
embedded in the secret key therefore varied together. A public seed is
explicitly declassified by the pinned implementation and feeds variable-work
rejection sampling, so the observed signal cannot be attributed to secret
material alone.

Diverse v2 replaces that ML-KEM label with the explicit `valid_tuple` axis and
requires every trace to carry a fail-closed input contract stating that both
public and secret material vary and that secret attribution is forbidden.
Every valid-tuple setup call and every untimed encapsulation-to-decapsulation
round trip must succeed before timing begins. It also fixes the two pinned
native-backend header selections and adds the
ML-DSA public-verifier adapter used by the correctness gate. Sample sizes,
controls, thresholds, seeds, process repeats, compiler optimization, upstream
snapshots, parameter sets, and comparison hypotheses remain unchanged.

The same class-construction problem also existed in the committed-corpus v2
`pqclean_mlkem768/kem_dec/sk` endpoint. Committed-corpus v3 retains the
historical `kem_dec` harness name only to preserve exact row coverage, replaces
its machine axis with `valid_tuple`, and binds the same per-trace metadata,
setup-return-code, and round-trip contract. Its `ct`, `fo`, and all non-ML-KEM
endpoints are unchanged. The paper v4 plan routes only the v3 core manifest.

The historical diverse v1 and committed-corpus v2 engineering artifacts are
calibration evidence only and cannot be reused, resumed, relabeled, or promoted
in their replacement final results.
Every v4 final component must start in a fresh output root on both hosts at one
post-amendment commit. Any further substantive change requires another
campaign version.

## V3 engineering-calibration amendment

An engineering-only Falcon v1 run at commit
`4349b239cf10f30c2a29d337756cfa031d1171e6` completed before any final run.
For `c_fndsa1024_fpr_emu`, the largest predeclared 65,536-tick positive
control had the correct effect direction in all three process repeats but did
not reach the frozen directional `t <= -10` threshold in any repeat
(`t=-3.79/-5.16/-5.16`). The three physical A/A controls were clean and their
reported per-repeat 80%-power directional diagnostics were approximately
156,523--196,831 ticks. Raw/control row counts, return codes, fixed 1,280-byte
signature contract, and artifact hashes all passed; the v1 result therefore
remained honestly `insufficient-power` rather than being relabeled clean.

Falcon v2 changes only that target's positive-control ladder from
`[512, 8192, 65536]` to `[65536, 262144, 1048576]`. The 262,144-tick point
exceeds the observed diagnostics and 1,048,576 is a robust ceiling of about
9.1% of the target's engineering runtime. Thresholds, target samples, control
samples, process repeats, target-trace configuration, hypotheses, exclusions,
binaries, and all other target curves are unchanged. The diagnostic is
per-repeat and is
not an achieved campaign-power estimate: requiring three detections out of
three is stricter than 80% detection probability in one repeat.

The historical v1 engineering artifacts are calibration evidence only and
cannot be reused in v2 final results. Every v3 final component must start in a
fresh output root on both hosts at one post-amendment commit. Any further
substantive change requires another campaign version.

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
   timing classifications. The ML-KEM endpoint is a mixed fixed-versus-fresh
   valid-tuple contrast, not a secret-key endpoint. This is non-directional and
   does not treat the two profiles as independent implementation lineages.

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
- A valid-tuple ML-KEM signal is reported only as a mixed public/secret input
  contrast. The axis label, input-contract metadata, or analysis must never
  shorten it to a secret-key leakage claim.
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
