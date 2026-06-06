# Go-forward direction (post Phase D)

> Where the project stands and what to do next, written for the report/paper
> push. Phase D (the empirical corpus) is **complete**; this doc adds the
> per-feature coverage lens (the strongest report angle) and the small, concrete
> steps that make the evidence airtight before write-up.

## Where we are

Phase D corpus is done — `docs/corpus/corpus_summary.csv`, 7 rows / 3 families /
5 verdict classes, all from real Docker amd64 gcc-13.3 / clang-18.1.3 runs:

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
div), `dudect` (timing), the triage-aware taxonomy with **default-deny** + the
cited `docs/accepted_variable_time.md` registry, and `scripts/build_corpus_table.py`
(merge → cells/summary). 381 tests pass.

## The strongest report lens: per-feature single-coverage

Ask, per tool feature: **"is there a case only THIS feature catches (the others
miss)?"** That is what proves each feature pulls its own weight.

| feature | what only it catches | single-coverage evidence | status |
|---|---|---|---|
| Valgrind secret memory/branch | secret → branch/address | toy_lookup `leaky` (S-box read) → `ct-leak` | ✅ in corpus |
| asm-scan variable-latency div | secret → div latency (Valgrind blind) | KyberSlash ML-KEM → `varlat-secret-risk` (ct PASS, asm FAIL) | ✅ in corpus |
| ct-matrix build-sensitivity | same source, verdict flips per build | `ct_matrix_flip` `leaky` (gcc_debug FAIL / release+size PASS) → `build-sensitive-ct` | ✅ in corpus |
| dudect timing | timing leak with no structural branch | `toy_dudect` (leaky FAIL / safe PASS) | ⚠️ example exists, **NOT in corpus** |
| taxonomy / default-deny | ct FAIL that is NOT a confirmed leak | ML-DSA → `needs-analysis` (default-deny caught an over-claim) | ✅ in corpus |

So 4 of 5 features now have airtight single-coverage *in the corpus table*;
**only dudect remains demonstrated in a standalone example**, not yet bound into
the evidence table.

## Recommended next steps (in order)

### 1. Add `ct_matrix_flip` to the corpus — ✅ DONE

Ran `ct-matrix` on `examples/ct_matrix_flip` (gcc debug/release/size, real Docker
amd64 Valgrind): `leaky` FAILs at `gcc_debug`, PASSes at `gcc_release`+`gcc_size`
→ `ct_flips=yes` → **`build-sensitive-ct`** (auto); `safe` PASSes everywhere →
`robust`. Merged via `build_corpus_table.py --family synthetic --target
ct_matrix_flip`. Corpus is now 7 rows / 5 verdict classes; build-sensitivity is a
row in the evidence table, not just a guarded test. `test_build_corpus_table.py`
still passes.

### 2. Bind a dudect positive control  — needs a small choice

`dudect` is per-target (timing), and the merge keys corpus rows on *ct-matrix*
harnesses, so a dudect-only target (`toy_dudect`) produces no row today — same
shape as the asm-scan-only case earlier. Two options:

- **(a, lighter) appendix evidence** — run `toy_dudect` and cite the
  `dudect_summary.csv` (leaky FAIL / safe PASS) as an appendix table; note in the
  report that dudect's single-coverage lives there, not in `corpus_summary.csv`.
- **(b, cleaner) merge enhancement** — let `build_corpus_table.py` emit a row for
  a dudect-only harness (ct fields = `NA`, dudect populated). Makes the one table
  cover all features uniformly.

Recommendation: **(a)** for the report deadline, **(b)** if time allows (it's the
honest "one table, all features" finish).

### 3. Build the feature-coverage table into the report

The table in this doc IS a headline figure: each feature with its
"only-this-catches-it" example. Pair it with the verdict-class table — together
they say "every layer is justified, and every verdict class is grounded in real
PQC".

### 4. Write-up — framing (Go, per §4.4)

Honest positioning (research novelty is modest; the phenomena are known):

> **Build-Configuration-Aware, Triage-Aware Constant-Time Screening for PQC** — a
> fail-closed framework binding Valgrind / asm-scan / dudect under one config,
> indexed by compiler × optimization, with a default-deny triage taxonomy and a
> cited accepted-variable-time registry; validated on a real PQC corpus.

The differentiated contribution is the **methodology + its self-validation**:
default-deny caught an over-claim on real ML-DSA, and surfaced that finding
*attribution* is build-dependent (inlining). That "the tool kept the human
honest" story is the report's spine — stronger and more honest than a clean
"everything passed".

## Optional / later (do NOT block the report)

- **Resolve ML-DSA `needs-analysis`** rigorously: classify accepted-vs-leak on the
  `-fno-inline` debug build (precise attribution) and triage `pack_sig` (public
  signature packer) on its own merits — see `docs/accepted_variable_time.md`
  Limitations. Completes the methodology but is not required for the report.
- **Corpus breadth**: another ML-DSA variant (44/87), Falcon, SPHINCS+, a
  table-based AES, constant-time memcmp. More data, diminishing return for the
  report's argument.
- **Phase E (patched Valgrind)** — only if div-candidate triage volume ever
  becomes unmanageable (it has not).
