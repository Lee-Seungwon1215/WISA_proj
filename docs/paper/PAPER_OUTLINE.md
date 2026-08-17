# CT-KAT MDPI paper outline (V10 pre-result)

Status: implemented in `paper/mdpi_working/main.tex`
Measurement commit: `1aeadb97e0409227aa203ba825a6bfc1d90445bc`

## Working contribution

CT-KAT is an auditable, fail-closed evidence pipeline for constant-time risk
screening of post-quantum C implementations. It does not claim that one
dynamic tool proves constant-time behavior. The contribution is the scoped
composition of correctness, branch/address observation, compiler-sensitive
assembly candidates, operand attribution, controlled timing, and immutable
artifact validation.

## 1. Introduction

- Functional KATs do not answer side-channel questions.
- Branch/address tools, assembly inspection, and timing answer different
  questions and must not be collapsed into one Boolean tool verdict.
- KyberSlash motivates operand-dependent latency outside ordinary
  branch/address observations.
- Contributions: declarative pipeline, four-state claim vocabulary,
  ground-truth/comparator suites, and frozen 28-axis single-host protocol.

## 2. Background and Related Work

- Threat model: secret-dependent control flow, memory addresses, and
  variable-latency instruction operands.
- `risk-detected`, `needs-review`, `inconclusive`, and
  `no-finding-observed`; never “proved constant-time.”
- ctgrind/Valgrind, dudect/TVLA, MicroWalk, compiler/build sensitivity.
- Scope separates screening corpus, source/build evidence, and physical
  timing campaign.

## 3. Materials and Methods

### 3.1 System overview

Single specification → build → correctness → generated harness → structural
screen → matrix/assembly attribution → controlled timing → fail-closed fold.

### 3.2 Correctness and harness generation

- Deterministic KAT/equivalence before security evidence.
- Exact measured API boundary and separated setup.
- Missing correctness is `inconclusive`, never clean.

### 3.3 Structural/build evidence

- Valgrind/TIMECOP branch/address observation.
- Compiler × optimization matrix.
- Assembly variable-latency candidate scan and semantic attribution.
- Candidate count measures reviewer burden, not accuracy/FPR.

### 3.4 Ground truth and comparators

- KyberSlash stock, KS1, KS2, combined, patched variants.
- Falcon reference, native-FP, integer-FPR for 512 and 1024.
- c-fn-dsa is prospective comparator evidence, not FIPS 206 conformance.
- Diverse upstream provenance and OpenSSL provider integration remain distinct.

### 3.5 V10 native timing

- One physical, non-virtualized Linux x86_64 host.
- Four components, 26 target executions, 28 axes, 8,220,000 rows.
- A/A, setup-placebo, positive controls, three process repeats.
- SMT/turbo policy, build seals, semantic randomness contracts.
- Named deterministic single-host analysis; no cross-host or independent
  analyst claim.

### 3.6 Integrity and disclosure

- Frozen commit, SHA-256 manifests, control qualification, deterministic output.
- Generative-AI assistance disclosed; authors retain responsibility.

## 4. Results

### 4.1 Committed screening corpus

- 25 target–harness pairs, 206 build cells.
- 6 risk-detected, 5 needs-review, 10 inconclusive, 4 no-finding-observed.
- Old ML-DSA/SLH-DSA declassification is expired, so unresolved pairs remain
  non-clean.

### 4.2 Ablation

- Single release: 11 candidate pairs.
- Full matrix: 13.
- Matrix plus assembly: 22.
- Reviewed fold reports evidence states separately.

### 4.3 Static case-study evidence

- KyberSlash provenance/equivalence and exact operand candidates.
- Falcon implementation-profile boundaries.
- Diverse upstream and provider-integration scope.

### 4.4 V10 result

Populate only from a complete hash-validated
`paper-native-single-host-analysis`. A pending draft contains no partial,
pilot, failed, engineering, or legacy value.

## 5. Discussion

- Evidence composition catches different failure modes without pretending
  universal coverage.
- Timing states remain host/protocol scoped.
- Secondary contrasts and signature-length association cannot override the
  primary verdict.
- Operational use is triage and auditable evidence production, not formal
  verification.

## 6. Limitations

- Dynamic path/input-distribution dependence.
- One x86_64 microarchitecture, no cross-host replication.
- No completed independent two-person review.
- Compiler/upstream/build scope and shared ancestry.
- Beta/prospective comparator status.
- No power, EM, fault, or formal proof.
- Cortex-M4 cross-compiled artifact support requires a separate ARM backend;
  no M4 result is claimed and V10 need not be rerun for that future work.

## 7. Conclusions

Summarize the fail-closed composition and static evidence. The native sentence
is conditional on complete generated results. Future work: second host,
independent review, ARM/M4 artifact backend, and formal/physical assurance.

## 8. MDPI back matter

Supplementary materials, author contributions, funding, IRB, informed
consent, data availability, acknowledgments/AI disclosure, conflicts,
abbreviations, and references. Unknown author/journal/archive metadata remains
explicitly withheld until the user supplies it.

Generated tables are never hand-edited. Build and submission gates are in
`paper/mdpi_working/README.md` and
`docs/paper/MDPI_SUBMISSION_CHECKLIST.md`.
