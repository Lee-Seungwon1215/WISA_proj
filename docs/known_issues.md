# CT-KAT — Known Issues & Improvement Plan

Working document. Catalogs problems found after Bundles A/B/C/D were
merged, with stable issue IDs so they can be referenced by future
commits and PRs.

## Status

- **Last updated**: 2026-05-26
- **Audit sources**:
  - Internal review by Bundle A–D author (focused on dudect pipeline)
  - External independent reviewer (whole-pipeline audit)
- **Total findings**: 5 tiers, 17 issues
- **Verification**: all Tier 1 / Tier 2 claims verified against the
  current `main` (commit `d678617` or later) by reading the cited source
  lines.

## How to read this document

Each issue has:

- **Stable ID** (`F1`, `R2`, etc.). Refer by ID in commit messages
  (e.g., `Bundle E: fix F2 (valgrind crash → INCONCLUSIVE)`).
- **Severity**: 🚨 verdict-affecting / 🟡 correctness / 🟢 hygiene.
- **Where**: file path + line range. Verified at the timestamp above;
  line numbers may drift as code changes — search by function name if
  drift is large.
- **Symptom**: what observably goes wrong.
- **Why solve**: concrete failure mode for users (security tool's job
  is to *not* mislead).
- **Acceptance criteria**: testable definition of done.
- **Related**: cross-refs to other issues.
- **Suggested bundle**: which proposed work bundle (E/F/G/Docs) covers it.

Tiers are ordered by severity. Within a tier, order is not significant.

---

## Tier 1: Fail-Open Anti-Pattern (verdict integrity)

The framework's most fundamental invariant should be: **"if we couldn't
verify it, say we couldn't verify it."** Tier 1 issues all violate this.
The verdict CSV is intended to be the canonical CI gate; silent
fail-open in any tier-1 spot makes that gate unreliable.

### F1: KAT validates by exit code only 🚨

- **Where**: `ctkat/builder.py:17-30` (`run_shell`),
  `ctkat/cli.py:78-93` (`_do_kat`).
- **Symptom**: `kat.command` returning exit code 0 is treated as PASS
  regardless of what (if anything) was actually tested.
  - `make kat; true` passes.
  - An empty `main(){ return 0; }` binary passes.
  - Zero test vectors run → PASS.
- **Why solve**: KAT is advertised as layer 1 of the three-layer model
  (`README.md:96-114`). If a user wires a no-op into `kat.command`, the
  framework reports PASS, which combined with a Valgrind/dudect PASS on
  the same harness produces verdict CLEAN — implying "correctness +
  side-channel safety verified" when no correctness was checked at all.
- **Acceptance criteria**:
  1. New optional yaml field `kat.expected_min: int` (counts test vectors
     the user expects to have run).
  2. `_do_kat` greps `kat.command` stdout for a configurable pattern
     (default: `r"PASSED:?\s*(\d+)"` or similar; configurable per-yaml
     because test-runner output varies).
  3. If pattern matches with count `n < expected_min` → KAT FAIL with a
     clear error message.
  4. If pattern doesn't match at all and `expected_min` is set → KAT FAIL.
  5. Backward compatible: if `expected_min` is unset, current behavior
     (exit-code only) is preserved with a one-time runtime warning
     pointing users at the new field.
  6. Tests covering: missing count, count < expected, count >= expected,
     no `expected_min` set (warning emitted once).
- **Related**: F2 (same fail-open pattern, different stage), F3 (no
  verdict state for "checked nothing").
- **Suggested bundle**: E.

### F2: Valgrind harness crash → verdict CLEAN 🚨

- **Where**: `ctkat/cli.py:215-243` (`_do_ct`),
  `ctkat/cli.py:594-...` (`_compute_verdicts`),
  `ctkat/verdict.py:52-69` (`_MATRIX`).
- **Symptom**: When Valgrind exits with a code other than 0 or 99 (i.e.,
  the harness crashed — segfault, abort, OOM, missing binary), the code
  path is:
  1. `_do_ct` prints a warning.
  2. `_do_ct` reads the log file if it exists; otherwise empty string.
  3. `parse_valgrind_log("")` returns `[]` (no findings).
  4. `_compute_verdicts` sees empty findings → `valgrind_status="PASS"`.
  5. If dudect also PASS, `_MATRIX[("PASS","PASS")] → Verdict.CLEAN`.
  - **A crashed harness produces a CLEAN verdict.**
- **Why solve**: Verdict CSV is the documented CI gate
  (`README.md:247-251`, exit-code semantics). A CI script that auto-merges
  on `verdict=CLEAN` will merge code that crashed during analysis. The
  framework is advertising "constant-time verified" for code that wasn't
  successfully analyzed.
- **Acceptance criteria**:
  1. Introduce `valgrind_status="ERROR"` (in addition to PASS/FAIL/NONE).
  2. `_do_ct` returns a status, not just findings; emits `ERROR` when
     `returncode not in (0, 99)` or when the log file is missing.
  3. Add verdict matrix entries: `("ERROR", *) → Verdict.INCONCLUSIVE`
     (see F3 for the new state).
  4. The existing warning `_do_ct` already prints stays — it gives the
     diagnostic detail; status=ERROR is the machine-readable signal.
  5. Test: `test_compute_verdicts_handles_valgrind_error` —
     ERROR + (any dudect status) → INCONCLUSIVE, not CLEAN.
  6. Test: `test_do_ct_crashed_harness_returns_error_status` — synthetic
     fake valgrind returning rc=137 → status=ERROR not PASS.
- **Related**: F1 (same pattern, KAT stage), F3 (verdict state).
- **Suggested bundle**: E.

### F3: No verdict state for "checked but inconclusive" 🚨

- **Where**: `ctkat/verdict.py:20-26` (`Verdict` enum),
  `ctkat/verdict.py:52-69` (`_MATRIX`).
- **Symptom**: The five existing states (CLEAN / LOW_RISK / SUSPECT /
  RISKY / CRITICAL) all assume the stage ran successfully. There is
  no way to express "we attempted analysis but couldn't complete it."
- **Why solve**: Prerequisite for F1 and F2 fixes — without a target
  state, the fixes have nowhere to map ERROR conditions.
- **Acceptance criteria**:
  1. New enum member `Verdict.INCONCLUSIVE = "INCONCLUSIVE"`.
  2. Verdict style mapping in `VERDICT_STYLES` (e.g.,
     `Verdict.INCONCLUSIVE → "bold yellow on white"`).
  3. Matrix entries: any pair where at least one side is ERROR maps to
     INCONCLUSIVE. Both NONE stays CLEAN (vacuous). Other combinations
     unchanged.
  4. Update README verdict matrix section (`README.md:455-469` ish).
  5. CI exit-code semantics decision: should `verdict=INCONCLUSIVE`
     exit 2 (same as FAIL — "don't merge") or a new exit code 3? Pick
     option A (exit 2) for simplicity; document.
- **Related**: F1, F2 (consumers of this state).
- **Suggested bundle**: E.

### F4: dudect zero-cycle filter ignores class balance 🟡

- **Where**: `ctkat/dudect_runner.py:58-78` (`parse_timing_csv`),
  `ctkat/dudect_runner.py:24` (`_ZERO_CYCLE_WARN_THRESHOLD = 0.01`).
- **Symptom**: Bundle B's zero-filter drops `cycles==0` rows class-agnostically.
  Only emits a warning when *total* drop rate exceeds 1%. If the zero
  events are concentrated in one class (e.g., TSC anomalies fire more
  often on the fast class-0 fixed-secret path), the surviving samples
  are biased — drop rate per total stays small while per-class drop
  becomes large.
  - Concrete observation: post-Bundle-B `toy_dudect` `leaky` had
    n0=10924, n1=18705 (37%/63% split) after zero-filter, suggesting
    ~55% of class-0 samples were sub-resolution zeros while class-1 was
    nearly unaffected. Welch handles unequal n statistically, but the
    surviving class-0 samples are *not a random sample* of class-0
    timings — they're the slow tail.
- **Why solve**: Biased samples can either inflate or deflate the t-score
  in non-obvious ways depending on which class loses more. The user has
  no visibility into this (see S1, S2 for related transparency issue).
- **Acceptance criteria**:
  1. Track per-class drop count in `parse_timing_csv`.
  2. Emit a *separate* warning when per-class drop rate exceeds a threshold
     (suggest 5% per-class, regardless of total).
  3. Expose per-class drop counts as fields on `TimingSamples` so they
     can be reported downstream (see S1).
- **Related**: S1, S2 (sample transparency).
- **Suggested bundle**: F.

---

## Tier 2: Reproducibility / Calibration

### R1: `leak_target=ct` is non-reproducible on real KEMs 🚨

- **Where**: `ctkat/templates/timing_kem.c.j2:124` (the `crypto_kem_enc`
  call inside the ct-leak measurement loop), and by extension
  `ctkat/templates/timing_kem.c.j2:107` (the setup `enc` for `ct_fixed`).
- **Symptom**: PQClean's `crypto_kem_enc()` consumes entropy from
  `randombytes()` (default backend reads `/dev/urandom`). The harness's
  yaml `seed` (the xorshift state seeding `rand_bytes`) **does not control
  the ct values** generated by `enc()`. So two `ctkat dudect` runs with
  identical yaml against the same KEM source produce **different
  ciphertext sequences**.
  - **My fault**: introduced in Bundle D (commit `d678617`). I designed
    the ct-leak mode without realizing PQClean's enc has its own RNG.
  - The synthetic `toy_kem_ct_leak` example is unaffected (its trivial
    enc uses an internal counter and is reproducible per-process), but
    the `pqc_mlkem768` ct-leak harness is non-reproducible.
- **Why solve**: README claims (`README.md:191` ish) that `seed: 0xC0FFEE`
  gives "deliberately reproducing the same input sequence." This is
  *only true for sk-leak mode* now. For ct-leak mode on real KEMs, two
  runs with the same seed give different inputs → different t-scores →
  flaky CI gating, hard-to-debug measurement variance.
- **Acceptance criteria** (pick one or both):
  - **Option A — Documentation**: Add an explicit caveat to README
    (`README.md` ct-leak section) and to the yaml schema's `seed`
    comment, stating that `leak_target=ct` reproducibility depends on
    the KEM implementation's RNG. Cite that the synthetic toy is
    reproducible because it uses an internal counter; PQClean is not.
    Show the user how to verify (run twice, diff `dudect_raw_timings.csv`).
  - **Option B — Mechanism**: Override `randombytes()` in the timing
    harness to draw from a deterministic source seeded from `dud.seed`.
    Implementation: emit a `static int randombytes(unsigned char *buf, size_t n)`
    in the generated `timing_<name>.c` that uses xorshift64 keyed off
    `CTKAT_SEED`. Link order ensures it overrides the PQClean default.
    Considerably more invasive — verify the link order works against
    PQClean's `common/randombytes.c` (which is in the harness sources
    list per `examples/pqc_mlkem768/ctkat.yaml:89`).
- **Recommendation**: ship Option A in the immediate next bundle; consider
  Option B as a follow-up if reproducibility becomes important for
  external validation.
- **Related**: R3 (system noise — separate cause of non-reproducibility).
- **Suggested bundle**: F (A) or its own bundle (B).

### R2: Multi-cutoff `max|t|` inflates Type-I error vs single-test threshold 🟡

- **Where**: `ctkat/statistics.py:CROP_PERCENTILES` and
  `welch_with_cropping`,
  README `dudect_summary.csv` reference (`README.md:264-279` ish).
- **Symptom**: Bundle B runs Welch's t-test at 5 cutoffs (`[1.0, 0.99,
  0.95, 0.90, 0.75]`) and reports max |t|. The thresholds 4.5 / 10.0
  (`dudect.threshold_warning` / `fail`) are calibrated for a *single*
  Welch test under the H0 of no leak. Taking the max over 5 correlated
  tests increases the chance of exceeding 4.5 by random chance —
  empirically, on `toy_dudect/safe` the post-A `|t|=0.035` jumped to
  `|t|=0.994` after Bundle B's cropping. Still PASS (well below 4.5),
  but the effective threshold has shifted.
- **Why solve**: A borderline-clean implementation that scored
  `|t|=3.5` (PASS) under single-test could score `|t|=5.0` (WARNING)
  under max-of-5 with no actual leak change. False WARNINGs erode user
  trust in the framework. Conversely, cropping at 0.50 can cut the tail
  where a rare-trigger leak hides, masking real signal.
- **Acceptance criteria**:
  1. README adds a short calibration guide: "with 5 cutoffs, treat
     |t|≈4.5 as soft-WARNING and |t|>5.5 as confident-WARNING; |t|>10
     stays FAIL." Estimate inflation empirically — see acceptance test.
  2. Optional yaml flag `dudect.bonferroni_correct: bool = false` that,
     when true, scales the thresholds by sqrt(number_of_cutoffs) (Šidák
     correction is more accurate than Bonferroni for correlated tests
     but Bonferroni is good enough as a conservative bound).
  3. Test: run `welch_with_cropping` on synthetic IID noise (no leak,
     n=5000 per class, 1000 trials) and report empirical Type-I rate.
     If rate exceeds, say, 2× the nominal α implied by 4.5, document.
- **Related**: R3.
- **Suggested bundle**: G.

### R3: System noise causes |t| variation across docker runs 🟢

- **Where**: inherent — not a code defect, but undocumented.
- **Symptom**: Same yaml, same seed, two `docker compose run` invocations
  give different |t| values (±10-20% in observed runs of `toy_dudect`).
  Status-level outcomes (PASS/WARNING/FAIL) are stable in the toy
  cases, but borderline cases would not be.
- **Why solve**: A user comparing exact |t| values across machines or
  CI runs to verify "did Bundle X change the leak signal?" will be
  misled by system noise. README should call this out.
- **Acceptance criteria**:
  1. README adds a "reproducibility" note: "Identical yaml + seed
     guarantees identical PRNG-derived class sequence and input bytes
     (modulo R1). |t| values still vary by up to ~20% across runs due to
     OS scheduling, cache state, thermal throttling. Compare status
     and order-of-magnitude, not exact values."
- **Related**: R1, R2.
- **Suggested bundle**: Docs sweep.

---

## Tier 3: Sample Transparency

### S1: CSV `n0`/`n1` reports post-filter, post-crop counts only 🟡

- **Where**: `ctkat/cli.py:_emit_dudect_report`
  (current columns documented at `README.md:264-277`).
- **Symptom**: A user reading `dudect_summary.csv` sees `n0=10924`,
  `n1=18705` for a harness configured with `measurements: 50000`. The
  ~20k "missing" samples were dropped by the zero-filter (F4) and/or
  excluded by the winning crop cutoff. Neither is visible in the CSV.
- **Why solve**: Without raw-sample counts the user can't audit the
  measurement pipeline, can't reproduce the pre-filter dataset from
  `dudect_raw_timings.csv`, and can't diagnose F4-style asymmetry.
- **Acceptance criteria**:
  1. CSV gets new columns (appended after existing 17 to preserve
     awk-by-position compatibility):
     - col 18: `raw_n_total` — measurements actually run by the C harness
     - col 19: `dropped_zero_n0` — class-0 samples zero-filtered
     - col 20: `dropped_zero_n1` — class-1 samples zero-filtered
  2. README CSV reference updated.
  3. Tests assert the new columns and their semantics.
- **Related**: F4, S2.
- **Suggested bundle**: F.

### S2: zero-filter asymmetry not surfaced in console output 🟢

- **Where**: `ctkat/dudect_runner.py:parse_timing_csv` warning logic.
- **Symptom**: Same root as F4; this is the user-facing side. Console
  shows a single drop-rate warning when total exceeds 1%, but per-class
  asymmetry — the actually interesting case — gets no special message.
- **Why solve**: Per-class drop disparity is a smoking gun for biased
  sampling (see F4 rationale). User should see it loudly.
- **Acceptance criteria**:
  1. Per F4, emit a per-class warning. Format: `dropped 12.4% of class-0
     vs 0.3% of class-1 — sample bias likely, treat |t| skeptically`.
  2. Test it triggers on synthetic asymmetric input.
- **Related**: F4, S1.
- **Suggested bundle**: F.

### S3: No effect-size column (Cohen's d) 🟢

- **Where**: `ctkat/statistics.py:WelchResult`, CSV output.
- **Symptom**: t-score magnitude depends on both effect size and sample
  size. A "small leak, huge n" and "large leak, modest n" can yield the
  same |t|. The user has `mean0`, `mean1`, `var0`, `var1` to compute
  Cohen's d themselves, but it's not in the CSV.
- **Why solve**: Quality-of-life — interpreting "how big is this leak?"
  is easier with a normalized effect size. Especially useful when
  comparing leak strength across implementations or across Bundle
  baselines.
- **Acceptance criteria**:
  1. Add `cohens_d` to `WelchResult` (computed alongside t-score).
  2. CSV col 21: `cohens_d`.
  3. README CSV reference updated, with rough interpretation guide
     (0.2 small, 0.5 medium, 0.8 large per Cohen 1988).
- **Related**: none.
- **Suggested bundle**: G.

---

## Tier 4: User Misunderstanding Risk (documentation)

### U1: "PASS" is overstated — readers may infer "constant-time" 🚨

- **Where**: `README.md:96-125` (three-layer model + strengths table),
  `README.md:436-...` (Limitations section).
- **Symptom**: README enumerates what each layer catches but the
  cumulative claim is implicit. A reader who sees verdict CLEAN may
  conclude "this code is constant-time" when the actual claim is "the
  three layers we ran didn't find anything they're capable of finding."
- **Why solve**: Security tools that overclaim erode user calibration.
  Users may skip independent review or other tools (masking analysis,
  power-trace analysis, formal verification) believing this framework
  is sufficient.
- **Acceptance criteria**:
  1. New top-of-README paragraph explicitly: "PASS means *this
     framework's checks didn't trigger*, not 'constant-time.' Layers
     we don't run: power side-channels, EM, fault injection, formal
     verification, adversarial-input testing, …"
  2. Existing Limitations section beefed up with concrete examples of
     what would slip through (KyberSlash-style rare triggers, FO
     fallback paths, microarchitectural side channels, cache coloring
     attacks).
- **Related**: U2, U3, U4.
- **Suggested bundle**: Docs sweep.

### U2: FO-fallback path leak detection is not addressed 🟡

- **Where**: `ctkat/templates/timing_kem.c.j2` (both leak modes use valid
  ct generated by `enc()`).
- **Symptom**: dudect's ct-leak mode generates ct via `enc(pk_fixed)` for
  both classes — these are valid ciphertexts, exercising the normal dec
  path. Leaks in the *FO fallback* path (when invalid ct is passed and
  dec rejects via implicit secret-derived recovery) are not exercised.
- **Why solve**: Some real KEM vulnerabilities live in the FO fallback
  (e.g., timing differences between the success path and the
  re-encryption check). Our framework currently can't reach them.
- **Acceptance criteria**:
  1. Add to README "ct-leak 모드 한계" paragraph: explicitly mention
     FO-fallback paths are not tested.
  2. Optionally: future bundle adds a third `leak_target=fo` mode that
     uses invalid (random) ct for class 1 — out of scope for the
     immediate doc fix.
- **Related**: U1.
- **Suggested bundle**: Docs sweep.

### U3: Windows support claim is overoptimistic 🟢

- **Where**: `README.md:236-240` (clock auto resolution table).
- **Symptom**: Table lists "Windows AMD64" as resolving to rdtsc. True
  for `platform.machine()`, but the generated harness uses GCC/Clang
  intrinsics (`<x86intrin.h>`, `_mm_lfence`). On Windows this requires
  MinGW; MSVC has different intrinsic names. Untested on Windows.
- **Why solve**: Avoid false promises. Windows users will hit obscure
  compile errors.
- **Acceptance criteria**:
  1. Add a footnote/caveat to the clock table: "Windows: requires MinGW
     gcc; MSVC not supported."
- **Related**: U1.
- **Suggested bundle**: Docs sweep.

### U4: Function speed range assumptions undocumented 🟢

- **Where**: README (anywhere appropriate).
- **Symptom**: For very fast functions (sub-microsecond) the zero-filter
  drops most measurements. For very slow functions (>1ms) the 600s
  default timeout caps usable sample counts. Neither limit is documented.
- **Why solve**: Users running dudect against unusual targets will get
  confusing results.
- **Acceptance criteria**:
  1. README adds rough guidance: "this framework targets functions in
     the ~100ns – ~1ms range. Faster: zero-filter aggressive (consider
     batching multiple calls per measurement). Slower: bump `timeout=`
     and reduce `measurements`."
- **Related**: U1.
- **Suggested bundle**: Docs sweep.

### U5: No step-by-step "write your own dudect yaml" tutorial 🟢

- **Where**: `README.md` examples section.
- **Symptom**: Examples exist but a new user writing their own yaml has
  to reverse-engineer `buffers`, `args`, `role`, `prefix`. The `infer`
  subcommand helps but isn't tutorial-shaped.
- **Why solve**: Adoption friction.
- **Acceptance criteria**:
  1. Add `docs/tutorial.md` walking through wrapping a real function in
     ~30 lines of explanation.
- **Related**: none.
- **Suggested bundle**: Docs sweep (or its own follow-up).

---

## Tier 5: Long-term Technical Debt

### T1: Template code duplication between sk-leak and ct-leak 🟢

- **Where**: `ctkat/templates/timing_kem.c.j2` (two ~50-line `main()`
  bodies under `{% if leak_target ... %}`).
- **Symptom**: PRNG class assignment, timed-region pattern, cycles_buf
  assignment, printf loop are all duplicated across the two branches.
- **Why solve**: When Bundle E adds verdict ERROR handling or Bundle F
  adds per-class metrics, both branches must be edited in parallel —
  easy to introduce drift.
- **Acceptance criteria**: Pull common pieces into Jinja2 macros or
  share a base template via `{% include %}`. Refactor + tests confirm
  identical C output for both modes (modulo intended differences).
- **Suggested bundle**: opportunistic (during Bundle E or later edits to
  the kem template).

### T2: valgrind_parser substring matching is fragile 🟢

- **Where**: `ctkat/valgrind_parser.py:_LOOKUP_PATTERNS`.
- **Symptom**: Substring match against function names (`"sbox"`,
  `"ttable"`, `"tbox"`, `"lookup"`, `"_table"`). Promotes any function
  containing these substrings to `SECRET_DEPENDENT_MEMORY_ACCESS` HIGH.
  `verify_table_size`, `audit_lookup_counters`, etc. would be falsely
  promoted. README documents this as "false-positive preferred" policy,
  so it's a policy choice — but future-proofing is poor.
- **Why solve**: As the codebase scales, false positives erode trust.
- **Acceptance criteria**:
  1. Optional: more precise heuristics (e.g., require Valgrind to have
     reported a memory-access instruction, not just any annotation).
  2. Alternative: yaml field `ct.lookup_function_patterns:` that
     overrides the built-in list.
- **Suggested bundle**: TBD (not currently planned).

### T3: Whitelist-out Valgrind messages are silently dropped 🟢

- **Where**: `ctkat/valgrind_parser.py` (the dispatch over message types).
- **Symptom**: Messages whose Valgrind error type isn't in the parser's
  recognized set return None and are dropped. Valgrind version upgrade
  or locale change can break the recognized set silently.
- **Why solve**: Future regressions.
- **Acceptance criteria**: Emit a debug-level log line (or summary
  count at end) listing how many messages were dropped as unrecognized.
- **Suggested bundle**: TBD.

### T4: shell=True in user-yaml commands 🟢

- **Where**: `ctkat/builder.py:17-30 run_shell`.
- **Symptom**: `cfg.kat.command` and `cfg.build.command` are passed to
  `subprocess.run(shell=True)`. README discloses this is intentional
  but there's no input validation. Yaml file in untrusted hands becomes
  shell-injection-as-service.
- **Why solve**: Lowers the bar for "I yaml'd a yaml from the internet"
  attacks. Not a defect per se because README warns, but principle of
  least privilege suggests offering a structured alternative.
- **Acceptance criteria**:
  1. Add optional yaml field `kat.argv: List[str]` (and similar for
     build) as a structured alternative to `command: str`. When `argv`
     is set, `shell=False` is used.
- **Suggested bundle**: TBD (security hardening, not user-facing).

### T5: Completed task list accumulation 🟢

- 44 tasks completed in current session, never cleaned up.
- Acceptance: bulk-delete completed tasks at end of each Bundle commit.

---

## Roadmap (proposed bundles)

Order is bottom-up on severity. Each bundle is intended as a single
commit (precedent: Bundles A/B/C/D were each one commit, all ~150-400
LoC).

### Bundle E — Fail-Open Closure 🚨

**Closes**: F1, F2, F3, partially F4.
**LoC estimate**: ~150.
**Why this bundle goes first**: Every other improvement compounds on
top of verdict correctness. Building on a fail-open base produces
false safety stacked on false safety.

**Sketch**:
- New `Verdict.INCONCLUSIVE` enum member + matrix entries.
- New `valgrind_status="ERROR"` returned by `_do_ct` on crash.
- New `kat.expected_min` yaml field + stdout-grep validation in `_do_kat`.
- Tests for each: verdict matrix ERROR cases, KAT count-below-expected,
  KAT count-not-found.
- README updates: verdict matrix table, KAT section, exit-code semantics.

### Bundle F — Class Balance + Reproducibility 🟡

**Closes**: F4, R1 (Option A), S1, S2.
**LoC estimate**: ~120.

**Sketch**:
- Per-class drop tracking in `parse_timing_csv`.
- New CSV columns 18-20 (raw_n_total, dropped_zero_n0/n1).
- Per-class asymmetry warning.
- README explicit caveat on `leak_target=ct` reproducibility under PQClean.

### Bundle G — Calibration / Effect Size 🟢

**Closes**: R2, S3.
**LoC estimate**: ~80.

**Sketch**:
- Cohen's d in `WelchResult`, CSV col 21.
- Optional Bonferroni-like threshold scaling.
- README calibration guide for multi-cutoff inflation.

### Docs sweep — Honest Limitations

**Closes**: U1, U2, U3, U4, R3.
**LoC estimate**: ~80 (README) + ~80 (new `docs/tutorial.md` if U5 included).

**Sketch**:
- "PASS does not mean constant-time" paragraph.
- FO-fallback / KyberSlash / power side-channel limits.
- Windows MSVC caveat.
- Function speed range guidance.
- Reproducibility / system noise note.

### Cleanup

- T5 (task list).
- Opportunistic T1 (template dedup) during E or F.

---

## Document maintenance

- **Update on each merged bundle**: mark resolved issues with
  `**RESOLVED in <commit>**` rather than deleting. Future readers learn
  the history.
- **New issues found mid-bundle**: append in-place with a new ID.
- **Issue IDs are stable**: never reuse a freed ID.
- **External reviews**: append a "review log" section if more come in,
  citing source.
