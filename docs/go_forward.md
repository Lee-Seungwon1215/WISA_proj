# Go-forward direction (post Phase D)

> Where the project stands and what to do next, written for the report/paper
> push. Phase D (the empirical corpus) is **complete**; this doc adds the
> per-feature coverage lens (the strongest report angle) and the small, concrete
> steps that make the evidence airtight before write-up.
>
> **Engineering-hardening arc** (error-handling/fail-open fixes, `ctkat screen`
> integration, paper-table auto-regeneration + drift test, B4/B5
> measurement-semantics) and the open engineering TODO live in
> **`engineering_status.md`** — this doc stays focused on the paper/report angle.

## Where we are

Phase D corpus is done — `docs/corpus/corpus_summary.csv`, 7 rows / 3 families /
5 verdict classes, backed by committed corpus CSVs with per-cell provenance:

| family | target | verdict_class |
|---|---|---|
| ML-KEM | pqclean_mlkem768 | robust |
| ML-KEM | pqclean_mlkem768_kyberslash | varlat-secret-risk |
| ML-DSA | pqclean_mldsa65 | needs-analysis |
| synthetic | toy_lookup (leaky) | ct-leak |
| synthetic | toy_lookup (safe) | robust |
| synthetic | ct_matrix_flip (leaky) | build-sensitive-ct |
| synthetic | ct_matrix_flip (safe) | robust |

Tooling: `ct-matrix` (compiler×cflags Valgrind), `asm-scan` (variable-latency
div), `dudect` (timing), the registry-backed triage policy with **default-deny** + the
cited `docs/accepted_variable_time.md` registry, and `scripts/build_corpus_table.py`
(merge -> cells/summary). The pytest count is intentionally not copied here;
run `python3 -m pytest -q` for the current artifact result.

## The strongest report lens: per-feature single-coverage

Ask, per tool feature: **"is there a case only THIS feature catches (the others
miss)?"** That is what proves each feature pulls its own weight.

| feature | what only it catches | single-coverage evidence | status |
|---|---|---|---|
| Valgrind secret memory/branch | secret → branch/address | toy_lookup `leaky` (S-box read) → `ct-leak` | ✅ in corpus |
| asm-scan variable-latency div | secret → div latency (Valgrind blind) | KyberSlash ML-KEM → `varlat-secret-risk` (ct PASS, asm FAIL) | ✅ in corpus |
| ct-matrix build-sensitivity | same source, verdict flips per build | `ct_matrix_flip` `leaky` (gcc_debug FAIL / release+size PASS) → `build-sensitive-ct` | ✅ in corpus |
| dudect timing | timing leak with no structural branch | `toy_dudect` (leaky FAIL \|t\|=181.5 / safe PASS \|t\|=1.65) | ✅ appendix (`docs/corpus/dudect_appendix.csv`) |
| registry-backed triage | ct FAIL with ambiguous attribution | ML-DSA → `needs-analysis` (held for review) | ✅ in corpus |

All 5 features now have airtight single-coverage *in the evidence set*: 4 as
`corpus_summary.csv` rows, and dudect as the committed appendix table
`docs/corpus/dudect_appendix.csv` (per the deliberate (a)-path choice in step 2 —
dudect is timing-keyed, not ct-matrix-keyed, so it sits beside the corpus rather
than inside it).

## Submission triage (2026-06-09)

The paper's edge is real but specific: this is a methodology / engineering
artifact paper, not a new-attack or new-formal-method paper. The strongest claim
is **build-configuration-aware, registry-backed CT screening for PQC**.
The weaknesses (synthetic controls, two real PQC families, candidate-level
asm-scan, QEMU dudect noise) are already disclosed in the Limitations section.
That supports the "honest by construction" story, but it also means a reviewer
will read those limits directly. Do not hide them; make the real-PQC cases
unmistakable:

- **Real cases**: KyberSlash ML-KEM for asm-scan and ML-DSA-65 for conservative
  triage under build-dependent attribution.
- **Synthetic support**: Valgrind lookup leak, build-matrix flip, and dudect
  timing control. These justify layers, but should not be oversold as PQC breadth.
- **Wording rule**: avoid saying the framework is "complete". Say
  **layer-justified in this corpus** / **validated on the corpus** instead.

### 0. Submission blockers — must clear before sending

- **Page limit currently cleared**. `paper/main.pdf` now builds to 11 pages under
  the 12-page LNCS target after Background/Results compression and compact
  support tables. Keep re-checking after edits.
- **Author / ORCID / affiliation**. `paper/main.tex` still carries a placeholder.
- **References source-checked**. `paper/references.bib` now has checked venue,
  page, DOI, and URL metadata where available. Keep a final human eyeball pass
  before camera-ready.
- **No "complete" claim**. Use "layer-justified in our corpus" in paper prose and
  planning docs.

### 1. Keep Table 1; keep ablation/miss evidence as generated support

Table 1's shape is good: "each layer has a single-coverage case" is the headline
argument. Do **not** replace it with a tool-pair miss matrix. The ablation/miss
rows stay auto-generated and drift-tested, but they no longer need a main-paper
float because they repeat Table 1 in reverse:

| If removed / ignored | Demonstrated miss | Evidence source |
|---|---|---|
| Valgrind structural taint | secret-indexed memory leak | `toy_lookup/leaky` |
| asm-scan | KyberSlash secret-derived division | `mlkem768_kyberslash/kem_dec` |
| ct-matrix | build-dependent verdict flip | `ct_matrix_flip/leaky` |
| dudect | black-box timing leak | `toy_dudect/leaky` |
| registry-backed triage | ML-DSA ambiguous attribution | `mldsa65/sign` |

Implemented path: this is generated from `docs/corpus/*.csv` beside the existing
paper table generator and drift-tested, but treated as support rather than a
headline table.

### 2. Promote ML-DSA per-cell triage evidence

The corpus already contains the evidence: debug cells show only registered
rejection-sampling functions, while optimized cells inline into
`crypto_sign_signature_ctx` and surface `pack_sig`. This is now promoted into a
compact generated paper table with per-cell function sets. It is framed as a
triage stress test: the debug build explains the accepted behavior, while
optimized builds create coarse/public-frame review items.

### 3. Improve dudect evidence if hardware is available

Re-run `toy_dudect` and the ML-KEM dudect observation on native x86 with CPU
pinning (`taskset -c 0`) and frequency scaling disabled. This can shorten the
QEMU caveat and make the timing appendix look less defensive. If native hardware
is not available, keep the caveat; the current large `|t|` positive control is
still usable because the paper explicitly reports the warning.

### 4. Defer structural FO-path Valgrind unless time is abundant

Structural FO-path coverage for invalid ML-KEM ciphertexts would improve PQC
depth, but it is a validation-heavy experiment. Do it only in a Docker/Valgrind
session where the path can be proven exercised. A half-validated FO harness would
weaken the "honest integration" story.

## Framing to preserve

Honest positioning (research novelty is modest; the phenomena are known):

> **Build-Configuration-Aware, Triage-Aware Constant-Time Screening for PQC** — a
> fail-closed framework binding Valgrind / asm-scan / dudect under one config,
> indexed by compiler × optimization, with a registry-backed triage policy and a
> cited accepted-variable-time registry; grounded in real PQC cases plus synthetic
> positive controls.

The differentiated contribution is the **workflow + conservative triage**:
KyberSlash shows structural CT alone is insufficient, and ML-DSA shows how
build-dependent attribution turns a structural FAIL into a precise review item
rather than an automatic leak or acceptance claim.
