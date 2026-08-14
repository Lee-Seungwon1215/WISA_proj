# Native timing experiment preregistration

Status: **v10 single-host protocol frozen; no v10 final measurement collected**

Initial freeze date: 2026-08-08
V3 amendment freeze date: 2026-08-10
V4 amendment freeze date: 2026-08-10
V5 amendment freeze date: 2026-08-11
V6 scope amendment freeze date: 2026-08-11
V7 setup-contract amendment freeze date: 2026-08-11
V8 explicit-RNG-contract amendment freeze date: 2026-08-12
V9 control-qualification amendment freeze date: 2026-08-14
V10 V2-A calibration and host-hygiene amendment freeze date: 2026-08-14
Machine-readable plan: `paper_native_campaign_v10.yaml`

This document fixes the hypotheses, units, exclusions, controls, and promotion
rules before a native Linux x86_64 measurement is inspected. It is an internal
preregistration committed with the code, not a claim of registration in an
external registry.

## V10 V2-A calibration and host-hygiene amendment

The first V2 control rehearsal at commit
`39a1cdeb94e768300e4d5bab5adbe0f14130d47c` ran uninterrupted from
2026-08-14 02:02:21Z through 03:26:04Z. Run
`34a8f9e74c094c0b97e5fc94e74a8777` completed all 28 smoke axes, all 28
native control axes, all three same-corpus baselines, assembly evidence, and
pipeline closure. Every execution and validation subprocess returned zero.
The aggregate rehearsal nevertheless exited nonzero, as designed, because its
final blocker matrix contained three predeclared safety-margin failures. The
exact report identifiers, observed values, source hashes, and non-reuse boundary
are frozen in `paper_control_rehearsal_v2_calibration.yaml`. No reduced target
statistic, target status, or target direction was inspected or used for this
amendment.

One blocker was ML-DSA-44 A/A repeat 0 at `|t|=3.7921`: inside the unchanged
final `|t|<4.5` validity rule but outside V2's additional `|t|<3.5` rehearsal
margin. The same seeded process schedule produced `|t|=3.7793` in V1. These
operational reruns are therefore not independent null draws. More importantly,
a null t statistic is not a monotone headroom measure. Applying a stricter
per-test cutoff to 168 A/A/placebo checks per rehearsal creates an avoidable
family-wise rejection mechanism and invites rerun-until-pass selection. V3
removes only that unsupported extra margin: every A/A and placebo must satisfy
the unchanged final `|t|<4.5` rule, with zero allowed failures. Counts, seeds,
repeats, final thresholds, and final multiplicity rules are unchanged.

The other two blockers were KyberSlash1 chosen-ciphertext positive-control
repeats at `t=-10.2053` and `t=-13.6501` for the 4,096-tick endpoint. Both pass
the unchanged directional final power threshold but miss the pre-final
`t<=-15` headroom rule. V10 does not tune only that failed row. It applies one
target-statistic-blind rule to every manifest target whose first two effects are
exactly 64 and 512 ticks: retain those sensitivity points and set the largest
effect to 16,384 ticks. The rule selects all 13 fast KEM/operand targets across
committed-corpus, KyberSlash, and diverse-lineage components. Falcon and ML-DSA
ladders are unchanged. Target/control sample counts, seeds, repeats, measured
code, hypotheses, final thresholds, and analysis remain unchanged.

V2-A also recorded active SMT and Intel turbo. V10 makes the intended stable
host state machine-enforced rather than advisory. Every component must reject
the host before compilation or sampling unless exactly one logical CPU is
pinned, the governor is `performance`, SMT is disabled, Intel turbo is disabled,
and the existing native-Linux/invariant-TSC/RDTSCP/clean-commit gates pass.

V1, V2-A, and every earlier final attempt remain immutable engineering-only
diagnostics. No row is copied, resumed, relabeled, or promoted. Before V10 final,
the exact candidate commit must complete two distinct blocker-free V3 control
rehearsals in fresh roots. Their different run IDs and wall-clock times provide
an operational repeat only; they are not claimed as independent inferential
replicates. A machine-generated qualification binds both reports and is reopened
by every V10 final command.

## V9 control-qualification amendment

A v8 final attempt at commit
`cd7dc6dacf83d66b5757ae4a6e5f86388f205ba5` completed only the
committed-corpus component (run `8b0b259d9e3f44099a5248f3be46df4b`). Its
ML-KEM valid-tuple largest positive control detected the injected delay in two
of three repeats, so the component was correctly non-promotable. The outer
supervisor then stopped before KyberSlash, Falcon, diverse, or any same-corpus
tool. The component report SHA-256 is
`c981bf821118f9ba30835dad94afc6da84ea935ae22f03843b87a8311ea336d0`.
No target statistic from this failed final attempt is used or promoted.

Before another final, commit `0ed9ea5359c00d7e1aac115001dbd9dc270d6d9a`
executed the non-promotable v1 control rehearsal from 2026-08-12
11:28:26Z through 12:53:51Z. Run
`18fc18bf328b417b9a4faf1ef2607406` completed compile/runtime smoke for all
28 axes, all four native components and their independent validators, three
same-corpus tools, assembly evidence, and pipeline closure. The aggregate
report SHA-256 is
`03385b3cb17d8103c2dacd4b9c185b02f026c1849738663bc4b885f7114fae65`.
Reduced target traces used 1,000 samples per process, were marked
non-interpretable in schema, and were not read or used to select this amendment.

The only final-equivalent failure was Falcon-1024 reference-signature positive
power: the 65,536-tick largest effect detected two of three repeats, with its
weakest repeat at `t=-9.6944` against the frozen directional `t<=-10` gate.
Seven additional blockers came from predeclared engineering safety margins,
including one ML-DSA-44 A/A repeat at `|t|=3.7793` (inside the final 4.5 limit)
and largest-effect repeats that passed final power but lacked the rehearsal
`t<=-15` headroom.

V9 applies one uniform **control-only** remediation rule to the complete
rehearsal matrix: select a manifest target when any of its axes has a
largest-effect worst-repeat `t>-20`, retain the first two injected-effect
points, and double only the largest point. The rule selects exactly nine
manifest targets recorded in
`paper_control_rehearsal_v1_calibration.yaml`. Because the committed-corpus
ML-KEM target shares one effect ladder across three harnesses, selecting its
valid-tuple axis updates the largest control effect for all three harnesses.
No target sample count, control count, process repeat, seed, threshold, setup,
source, compiler, binary contract, hypothesis, multiplicity rule, or claim
boundary changes. The single A/A safety-margin excursion causes no parameter
change; it must disappear naturally in fresh independent rehearsals.

Every v8 final and v1 rehearsal artifact remains immutable diagnostic evidence.
No row is resumed, copied, relabeled, or promoted into V9. Before any V9 final
command can start, the exact candidate commit must produce two distinct,
blocker-free v2 rehearsal reports satisfying all 28 axes, four components,
three baselines, assembly, pipeline closure, final controls, `|t|<3.5`
A/A/placebo headroom, and `t<=-15` largest-effect headroom. The qualification
tool hashes both reports, and the V9 final gate independently reopens and
validates the qualification plus both reports. Final execution then starts in
fresh empty roots at that same commit.

This V9 design is preserved as the historical pre-V2-A protocol. Its extra
3.5 null margin and V2 qualification were superseded by the V10 amendment above
after the complete V2-A diagnostic; no V9 final result was collected.

## V8 explicit randomness-contract amendment

One v7 final attempt was started at commit
`fe65820180167607f7032d771b761c47ef522d1f`. The committed-corpus component
(run `91d358cf91d540d0909f54fb3e07844c`) completed its six targets, and the
KyberSlash component (run `7b9c3a8f5cf1427bb16d62980567d527`) collected all
ten target artifacts. Validation then stopped the campaign before Falcon,
diverse-lineage, same-corpus baseline, bundle, or analysis execution.

The stop exposed a semantic contract bug rather than a target or control
failure. A null `randombytes_header` had been treated as proof that the target
must report `external-or-none`. The six operand adapters omit that declaration
header but call CT-KAT's weak deterministic `randombytes` interpose during
untimed corpus/key setup, so every trace correctly reported
`seeded-interpose`. The same distinction matters for c-fn-dsa: its adapter also
calls the seeded interpose despite using no declaration header. Conversely,
the self-contained toy baseline performs no such call and correctly reports
`external-or-none`. Header inclusion therefore cannot determine runtime RNG
semantics.

No v7 statistic, raw trace, control result, or completed component is promoted,
resumed, relabeled, or copied into v8. The complete v7 tree remains diagnostic
evidence only. V8 starts every component and baseline in fresh roots at one
later clean commit.

Before any v8 final sample, V8 adds a fail-closed `randomness_policy` to every
resolved timing harness. The default is `seeded-interpose`; an
`external-or-none` target must opt in explicitly and must have a null
`randombytes_header`. Reports record both the frozen expected policy and the
observed runtime policy, and the CLI, native validator, same-corpus validator,
and independent official-dudect verifier all require an exact match. The six
KyberSlash operand and four c-fn-dsa configurations explicitly require
`seeded-interpose`; only the deterministic toy baseline opts into
`external-or-none`. Operand-v3 traces additionally bind
`measured_rng_calls=0`, distinguishing allowed setup RNG from the measured
decapsulation interval.

This amendment does not change hypotheses, target/control sample counts,
process repeats, seeds, thresholds, positive-control effects, compiler flags,
component scope, multiplicity, or host claim limits. A short post-freeze
engineering execution may test the corrected contract but is non-promotable;
the final campaign still starts entirely fresh.

## V7 class-setup and same-corpus validity amendment

A v6 final attempt at commit
`4e171ea0edce322df127cc3c52836e4b3351be6d` completed all four primary
components, TIMECOP, and MicroWalk, but could not complete the predeclared
official-dudect same-corpus validity gate. The first dudect run
`70040e8fc5c74efcb561a329143f8e8a` retained every raw trace: the leaky target
was detected in all three repeats, but the largest 512-tick positive control
was detected in only two of three, while the negative target crossed the
threshold in one of three repeats. The second run
`891e3aabe154428291ec0bc2ff9c5c84` passed A/A, placebo, and power controls, but
exposed a fail-closed policy bug: both deterministic toy harnesses correctly
reported `external-or-none`, while the validator unconditionally required
`seeded-interpose` for every KEM template. Neither run is promoted.

Engineering diagnosis then exposed a second setup defect. The general KEM and
signature templates selected one of two pool addresses with a class-dependent
conditional immediately before `t0`. The placebo performed extra
normalization copies and therefore did not reproduce the final branch-history
boundary. A deliberately input-independent negative control could still
separate the classes, so the v6 primary traces cannot exclude this setup
confound even where their recorded placebo passed.

V7 makes three frozen corrections before any v7 final sample. First, a KEM or
signature harness with an explicitly null `randombytes_header` must report
`external-or-none`; all other such harnesses still require
`seeded-interpose`. Second, every non-operand KEM and signature iteration reads
both class slots and uses the no-inline `dual-read-masked-select-v4` routine to
materialize one class into the shared work buffers without a class-dependent
branch or source-address choice. Every trace records that exact setup contract
and validity fails closed on drift. The specialized KyberSlash operand-v3
contract remains `same-address-branchless-v3`. Third, the same-corpus negative
control performs a fixed 10,000-iteration volatile workload while ignoring
class-varying input bytes, and the baseline positive ladder is fixed at
`[512, 2048, 8192]` ticks after the observed 512-tick power failure.
The first rule in this historical V7 amendment was later falsified by the V7
final attempt and is superseded by the explicit V8 policy above.

Two independent engineering runs at commit
`adb68f8ff5cbd92bf427d2ea74561116bd476527` validated the corrected
baseline before this freeze. Their leaky repeat statistics all exceeded the
official threshold, their negative-control repeat statistics were
`[1.18, 2.82, 1.26]` and `[1.97, 1.55, 3.10]`, and both runs had zero A/A and
placebo failures with full directional power. These are calibration artifacts,
not final evidence. The v6 final tree and every pre-v7 engineering tree are
non-promotable and cannot be resumed, relabeled, or reused. Every v7 component,
baseline, assembly bundle, and analysis input must start fresh at one clean
post-amendment commit.

## V6 single-host scope and validation amendment

No v5 final measurement was collected before this amendment. Two distinct
physical hosts and two independent human reviewers are not available for the
current study. V6 therefore removes both as required execution/promotion gates
instead of fabricating host replication or reviewer identities. The frozen
measurement scope is exactly one non-virtualized physical Linux x86_64 host at
one clean commit. Results are paper-eligible only as host-scoped observations;
cross-host reproducibility, independent declassification, and inter-rater
agreement are explicitly not claimed.

The unavailable human gate is replaced by a machine-verifiable frozen-input
integrity gate. Before any `run_kind=final` sample, it requires a clean commit,
the exact v6 plan, all four component manifests, the same-corpus manifest, this
preregistration, the analysis contract, runner/analyzer sources, and dependency
locks. Their SHA-256 values are embedded in every component and baseline
report. This checks provenance and policy drift only; it is not described as
human approval.

The primary official-dudect result and all physical controls are unchanged.
The 28 axes, sample counts, process repeats, seeds, positive-control curves,
input contracts, build seals, exclusions, upstream revisions, and claim limits
are identical to v5. Only the host count, promotion authority, and analysis
fold change. V6 uses named deterministic analysis because no independent
analyst is available. It computes pairwise secondary tests from the three
within-host process-repeat effects, reports host heterogeneity as not
applicable, and binds the complete host tree with `SHA256SUMS`.

The earlier v5 two-host/blinded workflow remains in version control as a
superseded stronger profile. A later second host or independent review may be
reported as follow-up validation, but it is not required to interpret or
promote the v6 host-scoped tables and cannot be silently merged into this
frozen campaign.

## V5 KyberSlash operand and universal build-seal amendment

An engineering-only KyberSlash v2 run at commit
`2191d363137d3fee17354c96eef6bce741623b5c` completed before any final run.
The four fixed-key full-KEM chosen-ciphertext targets and their controls
completed, but code-and-artifact review found two setup confounds in the six
direct operand canaries. First, class selection read from two different
heap-backed ciphertext pools before copying to the common work buffer. Second,
the v2 setup-placebo copied a frozen ciphertext whose first coefficient was not
constrained to the valid `[0, 3328]` range; in the observed engineering corpus
it was `45124`, so the adapter returned before executing the arithmetic site.
The placebo therefore could not exclude either class-address setup effects or
site-local effects. No v2 operand statistic is promoted, corrected, resumed,
or reused.

KyberSlash v3 changes only the six direct-canary setup contracts. Both public
coefficient candidates are computed from the same pool index, selected with an
arithmetic mask, and written through one shared ciphertext work address while
one fixed secret-key address is used. The placebo overwrites that same address
with valid coefficient `1664`, every member of both 64-value bins must pass an
untimed decapsulation witness, warm-up return codes are checked, and any
non-zero measured decapsulation return count aborts the trace. The linked
binary contract additionally requires the measured decapsulation wrapper to
call the intended arithmetic-site symbol. Bins, samples, controls, thresholds,
seeds, process repeats, optimization flags, and the four full-KEM hypotheses
are unchanged.

Review of the completed diverse and KyberSlash engineering artifacts also
found that generated source and measured-binary hashes were preserved only on
axes carrying a specialized instruction contract. V5 therefore requires a
common pre-measurement build seal for every timing harness, independent of any
specialized contract. It binds the config, generated C, measured binary,
ordered linked sources and include directories, compiler executable/version,
flags, and replay argv; the runner checks it before and after every measured
subprocess, and the native validator reparses it into the target attestation.
Any missing or changed seal is an integrity error.

Every v5 final component starts in a fresh output root on both hosts at one
post-amendment commit. Cortex-M bare-metal evaluation is explicitly outside
this x86_64 desktop campaign; adding it requires a separately versioned board,
clock, transport, sample-size, and analysis preregistration and does not alter
or invalidate the desktop measurements defined here.

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
   its matched reciprocal-multiply implementation. Both classes use the same
   work addresses and fixed key; coefficient `1664` is the predeclared valid
   placebo path and every bin member must pass its return-code witness. These
   canaries establish operand-dependent hardware latency only, not a full
   attack or key recovery.
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
- Final v6 evidence requires one non-virtualized physical x86_64 Linux host at
  the frozen CT-KAT commit and three process seeds per target axis. This is one
  host with repeated processes, not hardware replication.
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
  `uv run --frozen python scripts/check_paper_campaign.py`.

## Primary and secondary endpoints

The primary endpoint for each axis is the official-dudect raw classification
from the complete target trace, with its fixed upstream threshold, conditional
on all CT-KAT physical controls and artifact-integrity checks passing. A result
whose controls fail is **inconclusive**, never clean.

Secondary endpoints are:

- signed and absolute Welch statistics for the predeclared analysis tests;
- effect direction and within-host consistency across process seeds;
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
- Every timing axis, including axes without a specialized instruction
  contract, must preserve and pass the common pre-measurement build seal. The
  generated C, measured binary, config, linked sources, compiler identity,
  flags, and replay argv are revalidated and included in the target
  attestation.
- Requested counts are not reported as retained counts. Dropped and retained
  counts are preserved in the artifact and tables use the latter.

## Exclusions fixed before observation

Exclude a unit only for a machine-checkable reason recorded by the runner:

1. virtualization, emulation, unsupported clock, missing affinity, or CPU
  migration;
2. compile/runtime timeout, non-zero harness failure, incomplete trace, schema
   failure, or hash mismatch;
3. control failure, insufficient official class counts, or a frozen/observed
   randomness-policy mismatch;
4. host or commit mismatch with the frozen campaign.

Thermal drift, an unexpected effect direction, a large statistic, or
disagreement with a prior result is not an exclusion reason. Outliers are kept;
the frozen official analysis owns its filtering and percentile tests.

## Analysis and multiplicity

- Report every predeclared target/axis result; no best-repeat
  selection is permitted.
- Primary claims are axis-specific. No single aggregate "accuracy" or global
  clean percentage is computed across unlike algorithms and threat models.
- Families of pairwise secondary comparisons use Holm adjustment within the
  full-ML-KEM chosen-ciphertext family; each of the three vulnerable/patched
  operand-site pairs; Falcon-512; Falcon-1024; mlkem-native; and mldsa-native.
  Both raw and adjusted values are retained.
- Host heterogeneity is not estimable from one host and is reported as not
  applicable. Process repeats are never relabeled as distinct hosts.
- Absence of a threshold crossing is worded `no finding observed under this
  protocol`, not constant-time proof.

## Review and promotion

The runner writes immutable promotion candidates and never edits the curated
corpus. V10 paper-result promotion requires:

1. one complete physical-host artifact tree and its recorded SHA-256 manifest;
2. a machine-validated qualification from two clean v3 control rehearsals at
   the exact final commit, followed by all 28 fresh final axes and three
   same-corpus tools;
3. passing correctness, input, build-seal, binary-contract, A/A, placebo,
   directional power, schema, and fresh-artifact checks;
4. a valid automated frozen-input integrity gate that explicitly records no
   independent human review and no cross-host reproducibility;
5. deterministic named analysis with byte-reproducible JSON/CSV/Markdown;
6. paper wording restricted to the host, software, compiler, and protocol
   actually measured.

Independent review packets remain optional follow-up evidence. They are not a
v10 measurement or paper-table gate, and V10 does not use them to declassify or
silently mutate the curated corpus.

OpenSSL 3.5 is retained as a provider-API integration/build case only. It is
not included in the timing lineage comparison unless a separately versioned
adapter and preregistration are committed before its measurements begin.
