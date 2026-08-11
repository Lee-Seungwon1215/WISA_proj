# Paper outline (premeasurement freeze)

## Working contribution

CT-KAT is presented as an evidence pipeline for reproducible, fail-closed
constant-time screening of post-quantum C implementations. The contribution is
not a claim that one dynamic tool proves constant-time behaviour. It is the
explicit composition of correctness, dynamic structural observations,
build-sensitive assembly candidates, operand attribution, controlled timing,
  and explicit claim-scoped validation.

## 1. Introduction

- Why branch/address-only dynamic analysis misses variable-latency operands.
- Why timing-only testing is confounded without correctness, setup separation,
  controls, exact build provenance, and review.
- Contributions: evidence schema, compiler/optimization matrix, KyberSlash
  ground truth, Falcon comparator, diverse source/build corpus, and a frozen
  single-physical-host timing protocol.

## 2. Threat model and claim vocabulary

- Secret-dependent branches, addresses, and variable-latency operands.
- Screening corpus versus source/build corpus versus timing campaign.
- `risk-detected`, `needs-review`, `inconclusive`, and
  `no-finding-observed`; never “proved constant-time.”
- The v6 timing tables claim neither independent human declassification nor
  cross-host reproducibility; public/mixed-input attribution boundaries stay
  explicit in every result.

## 3. System design

- Deterministic KAT/correctness gate.
- Valgrind/TIMECOP structural observation and compiler × flag sweep.
- Assembly candidate scan and attribution layer.
- timing-harness-v2: pre-generated pools, timed API boundary, seeded interpose,
  A/A, placebo, positive controls, process repeats, and artifact hashes.
- Fail-closed evidence fold and immutable promotion candidates.

## 4. Experimental design

- Frozen targets and upstream revisions from the machine-readable campaign.
- One physical Linux x86_64 host; pilot/final separation; no hardware
  replication claim.
- Primary and secondary endpoints, sample sizes, exclusions, and Holm-adjusted
  within-family secondary contrasts from the preregistration.
- Full-signature Falcon scope and separate output-length association analysis.

## 5. Evaluation

### 5.1 Screening-corpus coverage and evidence states

Use generated corpus counts, family counts, review readiness, and explicit
correctness gaps. Do not combine unlike threat models into an “accuracy” rate.

### 5.2 Ablation

Compare single gcc/O2 structural screening, full build matrix, matrix plus
assembly candidates, and the reviewed evidence fold. Candidate burden is not
labelled false-positive rate without an independently labelled oracle.

### 5.3 KyberSlash ground truth

Report stock, KS1-only, KS2-only, combined, and historical provenance/KAT
equivalence first; then report host-scoped timing without collapsing variants.

### 5.4 Falcon comparator

Report reference and prospective native-FP/integer-FPR profiles for 512 and
1024 separately. Report signature-length distributions alongside full-API
timing; make no FIPS 206 conformance claim for c-fn-dsa.

### 5.5 Diverse upstream and production integration evidence

Report lineage, ancestry caveat, architecture/profile/compiler/build cells,
KAT/equivalence, and OpenSSL provider integration as separate dimensions.
OpenSSL is not counted as a fifth implementation lineage.

### 5.6 Physical timing campaign

Populate only from complete schema-v5 single-host artifacts. Process repeats
remain within-host evidence and are not presented as multiple machines.

## 6. Limitations

- Dynamic coverage and input-distribution dependence.
- CPU-specific variable latency and only one final microarchitecture.
- Compiler and upstream revision scope.
- Shared ancestry is unmeasured, not zero.
- Beta mldsa-native API and prospective c-fn-dsa status.
- No independent human review in v6 and the absence of formal constant-time
  proof.

## 7. Reproducibility and artifact

- One-command premeasurement and postmeasurement profiles.
- Exact revisions, vendored tree hashes, generated tables, artifact hashes,
  automated frozen-input gate, deterministic named analysis, and explicit
  single-host/no-independent-review limitations.

Generated premeasurement tables live under `docs/paper/generated/` and must be
refreshed by the repository script, never hand-edited.
