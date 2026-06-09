# Report tables (WISA poster — camera-ready figures)

> Headline/support figures for the write-up:
> **coverage** — every tool layer pulls its own weight;
> **ablation** — every omitted layer has a concrete miss;
> **corpus** — every verdict class is grounded in a concrete run;
> **ML-DSA attribution** — default-deny is justified per build cell;
> **dudect appendix** — the one feature that lives beside the corpus.
> Numbers are rendered from committed corpus CSVs produced by the CT-KAT analysis
> workflow; per-cell compiler/version/architecture provenance lives in
> `docs/corpus/corpus_cells.csv`. Source-of-truth CSVs:
> `docs/corpus/corpus_summary.csv`, `docs/corpus/dudect_appendix.csv`.

---

## Coverage — Per-feature single-coverage (the headline figure)

The argument: a screening tool that bundles N checks is only justified if **each
check catches something the others miss**. For every layer we name a corpus case
that *only that layer* flags.

| # | tool layer | what ONLY it catches | single-coverage case | evidence |
|---|---|---|---|---|
| 1 | Valgrind secret mem/branch | secret → branch / memory address | `toy_lookup` `leaky` — S-box read `out[i]=sbox[secret[i]]` | `ct-leak`, FAIL all 6 builds |
| 2 | asm-scan variable-latency div | secret → division latency (**Valgrind-blind**) | KyberSlash ML-KEM (`pqclean_mlkem768_kyberslash`) | `varlat-secret-risk` — **ct PASS, asm FAIL** |
| 3 | ct-matrix build-sensitivity | same source, verdict flips per build config | `ct_matrix_flip` `leaky` | `build-sensitive-ct` — gcc_debug **FAIL** / release+size **PASS** |
| 4 | dudect timing | timing leak with **no structural branch** | `toy_dudect` `leaky` | FAIL \|t\|=181.5 vs safe PASS \|t\|=1.65 — see **dudect appendix** |
| 5 | taxonomy / default-deny triage | ct FAIL that is **not yet a confirmed leak** | ML-DSA-65 (`pqclean_mldsa65`) `sign` | `needs-analysis` — default-deny caught an over-claim |

**Why each row is "only this layer":**
- **(2)** is the sharpest result: KyberSlash passes Valgrind/Memcheck clean
  (no secret branch/address) yet leaks via variable-time division — asm-scan is
  the *only* layer that surfaces it. This is the existence proof that structural
  CT checking alone is insufficient for PQC.
- **(3)** the structural verdict itself is build-dependent — a single
  `ct` run at one opt-level would have reported PASS or FAIL depending on flags.
  Only the compiler×cflags matrix exposes the instability.
- **(5)** not a detection layer but a *judgment* layer: on real ML-DSA the ct
  check FAILs, and the default-deny taxonomy refused to auto-label it a leak —
  it surfaced unregistered leak-site functions for human triage instead of
  over-claiming. (This is the paper's spine, see §narrative below.)

---

## Ablation — each omitted layer misses something concrete

This is support, not a replacement for the coverage table's clearer argument.
It is auto-generated from the same corpus CSVs and drift-tested.

| If removed / ignored | Demonstrated miss | Evidence source |
|---|---|---|
| Valgrind structural taint | secret-indexed memory leak | `toy_lookup/leaky` |
| asm-scan | KyberSlash secret-derived division | `mlkem768_kyberslash/kem_dec` |
| ct-matrix | build-dependent verdict flip | `ct_matrix_flip/leaky` |
| dudect | black-box timing leak | `toy_dudect/leaky` |
| default-deny taxonomy | ML-DSA over-claim | `mldsa65/sign` |

---

## Corpus — Verdict-class corpus (every class grounded in a concrete run)

7 rows / 3 families / 5 verdict classes, backed by committed corpus runs.

| family | target | harness | ct (matrix) | varlat triage | verdict_class |
|---|---|---|---|---|---|
| ML-KEM | pqclean_mlkem768 | kem_dec | PASS (all builds) | public | **robust** |
| ML-KEM | pqclean_mlkem768_kyberslash | kem_dec | PASS | **secret-risk** | **varlat-secret-risk** |
| ML-DSA | pqclean_mldsa65 | sign | FAIL | public | **needs-analysis** |
| synthetic | toy_lookup | leaky | FAIL (all builds) | none | **ct-leak** |
| synthetic | toy_lookup | safe | PASS | none | robust |
| synthetic | ct_matrix_flip | leaky | **FAIL/PASS (flips)** | none | **build-sensitive-ct** |
| synthetic | ct_matrix_flip | safe | PASS | none | robust |

**Verdict-class definitions (triage-aware, default-deny):**
- `robust` — ct PASS across all builds AND varlat ∈ {none, public}.
- `varlat-secret-risk` — secret-derived variable-latency op (KyberSlash class);
  **ct/Valgrind may still PASS** (structural blind spot).
- `build-sensitive-ct` — ct verdict flips across build configs.
- `needs-analysis` — ct FAIL with ≥1 leak-site function NOT in the cited
  accepted-variable-time registry. **Default-deny**: never auto-labeled a leak.
- `ct-leak` — a CONFIRMED leak; reached **only** via a manual reviewer verdict,
  never auto-declared.

The decoupling is the methodological point: **ct-clean ≠ no-candidates**, and a
**ct FAIL ≠ broken**. Both require triage.

---

Real-PQC spine: stock ML-KEM grounds `robust`, KyberSlash ML-KEM grounds
`varlat-secret-risk`, and ML-DSA grounds `needs-analysis`. Synthetic controls
ground `ct-leak` and `build-sensitive-ct` deliberately, as controlled positives.

---

## ML-DSA attribution — why default-deny holds

The ML-DSA row is not merely "FAIL". Debug cells show only registered
rejection-sampling behavior; optimized cells surface unregistered parent/packer
names, so the framework keeps the row at `needs-analysis`.

| build cells | surfaced functions | triage meaning |
|---|---|---|
| `-O0 -fno-inline` | `make_hint`; `poly_challenge`; `poly_chknorm` | registered rejection-sampling behavior |
| `-O2/-Os` | adds `crypto_sign_signature_ctx`; `pack_sig` | held at `needs-analysis` |

---

## dudect appendix (timing single-coverage)

dudect is *timing-keyed* (per-target), not *ct-matrix-keyed*, so it does not
produce a `corpus_summary.csv` row — it sits beside the corpus as its own table.
Source: `docs/corpus/dudect_appendix.csv`.

| target | harness | n0 | n1 | mean0 (cyc) | mean1 (cyc) | \|t\| | status |
|---|---|---|---|---|---|---|---|
| toy_dudect | leaky | 13250 | 19912 | 42.7 | 5191.7 | **181.5** | **FAIL** |
| toy_dudect | safe | 19578 | 19773 | 10269.3 | 10267.9 | 1.65 | PASS |

**Honesty caveat (report it explicitly):** the `leaky` run dropped 33.7% of
zero-cycle samples *asymmetrically* (46.6% class-0 vs 20.9% class-1) under
QEMU/Docker TSC skew — the tool **loudly warns** about this. The class separation
is so large (|t|=181) the verdict is unambiguous, but a publication-grade number
should be confirmed natively (`taskset -c 0`, frequency scaling off). The same
caveat is already flagged on the ML-KEM `dudect WARNING` corpus row — consistent
honesty, not a one-off.

---

## How the tables work together

> **Coverage says** every layer is justified (each catches something unique).
> **Ablation says** removing any layer creates a concrete miss.
> **Corpus says** every verdict class is grounded in a concrete target.
> **ML-DSA says** default-deny prevented a real over-claim.
> Together: *"the framework is layer-justified in this corpus and validated on
> concrete targets."*

Use coverage and corpus as the two central panels; ablation, ML-DSA attribution,
and dudect are compact support.
