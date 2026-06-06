# Report tables (WISA poster — camera-ready figures)

> Headline figures for the write-up. Two tables carry the paper:
> **(T1) per-feature single-coverage** — every tool layer pulls its own weight;
> **(T2) verdict-class corpus** — every class is grounded in real PQC.
> **(A1) dudect appendix** — the one feature that lives beside the corpus.
> All numbers are from real Docker amd64 gcc-13.3 / clang-18.1.3 Valgrind/dudect
> runs. Source-of-truth CSVs: `docs/corpus/corpus_summary.csv`,
> `docs/corpus/dudect_appendix.csv`.

---

## T1 — Per-feature single-coverage (the headline figure)

The argument: a screening tool that bundles N checks is only justified if **each
check catches something the others miss**. For every layer we name a corpus case
that *only that layer* flags.

| # | tool layer | what ONLY it catches | single-coverage case | evidence |
|---|---|---|---|---|
| 1 | Valgrind secret mem/branch | secret → branch / memory address | `toy_lookup` `leaky` — S-box read `out[i]=sbox[secret[i]]` | `ct-leak`, FAIL all 6 builds |
| 2 | asm-scan variable-latency div | secret → division latency (**Valgrind-blind**) | KyberSlash ML-KEM (`pqclean_mlkem768_kyberslash`) | `varlat-secret-risk` — **ct PASS, asm FAIL** |
| 3 | ct-matrix build-sensitivity | same source, verdict flips per build config | `ct_matrix_flip` `leaky` | `build-sensitive-ct` — gcc_debug **FAIL** / release+size **PASS** |
| 4 | dudect timing | timing leak with **no structural branch** | `toy_dudect` `leaky` | FAIL \|t\|=181.5 vs safe PASS \|t\|=1.65 — see **A1** |
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

## T2 — Verdict-class corpus (every class grounded in real PQC)

7 rows / 3 families / 5 verdict classes, each from a real Docker run.

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

## A1 — dudect appendix (timing single-coverage)

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

## How the two tables work together

> **T1 says** every layer is justified (each catches something unique).
> **T2 says** every verdict class is grounded in real PQC, not a toy.
> Together: *"the framework is complete (T1) and validated (T2)."*

Pair them as the poster's two central panels; **A1** is a small supporting inset
under T1 row 4.
