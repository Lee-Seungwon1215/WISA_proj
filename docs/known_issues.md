# CT-KAT — Known Issues & Improvement Plan

Working document. Catalogs problems found after Bundles A/B/C/D were
merged, with stable issue IDs so they can be referenced by future
commits and PRs.

## Status

- **Last updated**: 2026-05-26 (v3 — see Review log at the bottom)
- **Audit sources**:
  - Internal review by Bundle A–D author (focused on dudect pipeline)
  - External independent reviewer, pass 1 (whole-pipeline audit)
  - External independent reviewer, pass 2 (audited v1 of this doc)
  - External independent reviewer, pass 3 (audited v2 + whole repo)
- **Total findings**: 5 tiers, 26 issues
  (v1: 20 → v2: +F5, +F6, +T6 → v3: +F7, +F8, +T7)
- **Verification**: All Tier 1 (F1–F8) and Tier 2 (F6, R1–R3) claims
  verified against `main` (commit `d678617` or later) by reading the
  cited source lines. v1's R1 was under-audited (focused only on the
  ct-leak branch of `timing_kem.c.j2`); v2 audit confirmed the same
  `randombytes()` dependency in the sk-leak branch too. v3 audit
  surfaced subcommand-level fail-opens (F7, F8) which had been missed
  by v1/v2 because those passes focused on `run` pipeline rather than
  the standalone `ctkat <stage>` commands.

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
  5. Always echo KAT stdout to console on PASS too (currently only
     printed on FAIL — user can't see "count: 0" until they look at
     reports/). Aggravates F1 because the user has no in-flow signal that
     the KAT was a no-op.
  6. Backward compatible: if `expected_min` is unset, current behavior
     (exit-code only) is preserved with a one-time runtime warning
     pointing users at the new field.
  7. Tests covering: missing count, count < expected, count >= expected,
     no `expected_min` set (warning emitted once).
- **Related**: F2, F5 (same fail-open pattern, different stages), F3 (no
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

### F5: CT manual binary mode skips function-call verification 🚨

- **Where**: `ctkat/cli.py:178-242` (`_do_ct`), specifically the
  `harness.binary is not None` branch around line 209.
- **Symptom**: In manual harness mode (`ct.harnesses[*].binary:
  ./path/to/bin`), `_do_ct` runs Valgrind against whatever path the
  user pointed at, with **no verification** that the binary actually
  invokes the target function with tainted (`VALGRIND_MAKE_MEM_UNDEFINED`)
  input.
  - `binary: /bin/true` → Valgrind sees 0 findings → CT PASS.
  - `binary: ./bin/old_unrelated_test` → Valgrind sees 0 findings → CT
    PASS.
  - Combined with dudect PASS (or NONE), verdict = CLEAN.
- **Why solve**: Manual mode is the documented option for full user
  control (`README.md:223`: `binary (수동) ↔ template (자동)은 상호
  배타`). Without any sanity check, the framework reports CLEAN for a
  binary that may not have called the function at all. Same shape of
  fail-open as F1, just one stage down the pipeline.
- **Acceptance criteria**:
  1. Document a convention: manual-mode harnesses must emit a sentinel
     line (e.g., `CTKAT-HARNESS-RAN: <name>`) at least once per run.
  2. `_do_ct` captures the Valgrind-wrapped process stdout and asserts
     the sentinel appears at least once for that harness name.
  3. Missing sentinel → status=ERROR (uses F3's INCONCLUSIVE).
  4. Backward compatibility: introduce yaml flag
     `ct.require_sentinel: bool = false` (default false to not break
     existing yamls); README pushes users to set it true; emit a
     one-time warning when running without it.
  5. Tests covering: sentinel present (PASS path), sentinel missing
     (status=ERROR), `require_sentinel=false` produces a warning.
- **Related**: F1 (same fail-open pattern, KAT stage), F2 (Valgrind
  crash fail-open), F3 (INCONCLUSIVE state), F6 (auto-mode misconfig
  fail-open).
- **Suggested bundle**: E.

### F7: `ctkat kat` subcommand exits 0 when no `kat` section in config 🚨

- **Where**: `ctkat/cli.py:752-757` (kat subcommand). Concretely:
  ```python
  if cfg.kat is None:
      console.print("[yellow]No `kat` section in config.[/]")
      raise typer.Exit(0)   # ← fail-open exit code
  ```
- **Symptom**: A user runs `ctkat kat -c bad.yaml` where `bad.yaml`
  is missing its `kat:` section entirely. The subcommand prints a
  yellow note and exits 0. CI scripts gating on exit code (e.g.,
  `ctkat kat -c x.yaml && echo OK`) report OK for a configuration
  that defined no KAT step at all.
- **Asymmetric with peer subcommands**: the dudect subcommand
  (`cli.py:560-562`) raises `typer.Exit(2)` in the same situation
  ("No `dudect` section in config"). kat's exit-0 is inconsistent
  and lenient where dudect is strict.
- **Why solve**: Same fail-open shape as F1, but one level up — F1
  is "KAT ran on a no-op binary"; F7 is "KAT didn't run at all but
  we still said OK." Single-stage subcommands are explicitly
  designed for CI gating (per `README.md:225+` CLI commands section),
  so subcommand exit codes are part of the contract.
- **Acceptance criteria**:
  1. `if cfg.kat is None`: `raise typer.Exit(2)`, matching the
     dudect subcommand. Update the printed message to red
     (`"[red]No `kat` section in config.[/]"`).
  2. Same fix for ct subcommand — see F8.
  3. README CLI section documents that single-stage subcommands
     exit non-zero when their stage is absent from the config (do
     not silently no-op).
  4. Test: `test_kat_command_exits_nonzero_when_kat_section_missing`.
- **Related**: F1, F8 (same pattern, different stages), F3
  (verdict state — but subcommands don't go through verdict
  matrix; this is exit-code-only).
- **Suggested bundle**: E.

### F8: `ctkat ct` subcommand reports "PASS" when no `ct` section 🚨

- **Where**: `ctkat/cli.py:729-745` (ct subcommand). No `cfg.ct is None`
  guard at all; control flow runs through `_do_generate` (which
  guards internally and returns `{}`) and `_do_ct` (also guards,
  returns `[]`) and falls through to:
  ```python
  any_finding = any(fs for _, fs in ct_results)   # False on empty
  if any_finding:
      console.print("[bold red][CTKAT] Constant-Time Check: FAIL[/]")
  else:
      console.print("[bold green][CTKAT] Constant-Time Check: PASS[/]")
  ```
- **Symptom**: User runs `ctkat ct -c bad.yaml` with no `ct:`
  section. Output: `[CTKAT] Constant-Time Check: PASS` and exit 0.
  **The framework explicitly reports a green PASS for a
  configuration that defined no CT check.**
- **Why solve**: Worse than F7 — kat prints a yellow note saying
  no kat section exists, at least giving the user a clue. ct
  prints "PASS" in bold green, actively misleading. Any CI script
  or downstream tool consuming this output will mis-record that
  CT was checked and passed.
- **Acceptance criteria**:
  1. Early guard in `ct` subcommand:
     ```python
     if cfg.ct is None:
         console.print("[red]No `ct` section in config.[/]")
         raise typer.Exit(2)
     ```
  2. Mirror in `dudect` and `kat` (F7) for consistency.
  3. Test: `test_ct_command_exits_nonzero_when_ct_section_missing`,
     `test_ct_command_does_not_print_PASS_when_section_missing`.
- **Related**: F7 (same pattern, kat stage), F1/F2 (CT-stage
  fail-opens in different sub-scenarios).
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
- **Acceptance criteria** (statistical correctness — F4 is the
  *logic* fix, S2 is the user-facing alert face of the same
  remediation; close both in one PR):
  1. Track per-class drop count in `parse_timing_csv`.
  2. Emit a *separate* warning when per-class drop rate exceeds a
     threshold (suggest 5% per-class, regardless of total) — this
     warning *is* the S2 deliverable.
  3. Expose per-class drop counts as fields on `TimingSamples` so they
     can be reported downstream (this also feeds the S1 raw-count
     columns).
- **Related**: **S2 (user-facing warning text — same fix, different
  surface)**, S1 (raw-count CSV columns — fed by the same tracking).
- **Suggested bundle**: F (close F4 + S1 + S2 together).

---

## Tier 2: Reproducibility / Calibration

### F6: Auto-template `secret_regions` size not cross-checked 🟡

(Numbered F-series because it's the same fail-open *pattern* as F1/F2/F5,
just less severe — requires user misconfiguration to trigger.)

- **Where**: `ctkat/config.py:HarnessConfig.secret_regions` validation
  (none currently for size sums); `ctkat/templates/harness_kem.c.j2` (and
  sign equivalent) where regions are emitted as
  `VALGRIND_MAKE_MEM_UNDEFINED(sk + offset, length)` calls.
- **Symptom**: User specifies `secret_regions` whose total length is
  much smaller than `CRYPTO_SECRETKEYBYTES`. Only the listed bytes get
  tainted, so secret-dependent code paths operating on the untainted
  remainder produce no Valgrind findings → false PASS.
  - Example typo: `length: 32` instead of `length: 2400` for ML-KEM —
    only 32 bytes tainted of 2400 → most of `sk` is treated as public.
- **Why solve**: README's ML-KEM walkthrough
  (`README.md` "Findings from real-world testing #1") teaches users
  that `secret_regions` is the right way to handle composite `sk`
  blobs, but a misnumbered length silently degrades coverage. The
  framework should at least warn when the sum looks suspicious.
- **Acceptance criteria**:
  1. Emit a tiny sentinel program at harness compile time that prints
     the actual byte counts (or reuses the same compile to extract
     macro values via `printf("%zu\n", sum)` ). Parse its output and
     compare against `CRYPTO_SECRETKEYBYTES`.
  2. If coverage < 50% (configurable), emit a startup warning naming
     the harness and the percentage. Don't fail — user may have a
     reason — but warn loudly.
  3. Document the convention in the README ML-KEM section.
- **Why this is Bundle F not Bundle E**: the cheap "integer-literal
  only" alternative was considered but rejected. PQClean uses macros
  (`KYBER_INDCPA_SECRETKEYBYTES` etc.) in exactly the case this issue
  is meant to protect — a literal-only check would skip the real
  target. Sentinel-program impl is not cheap (extra compile step,
  output parsing, error paths) so it doesn't fit Bundle E's
  exit-code-and-state scope.
- **Related**: F5 (related fail-open pattern, different config surface).
- **Suggested bundle**: **F** (final, no longer "E or F").

### R1: dudect KEM harness is non-reproducible on real PQClean targets — BOTH leak modes 🚨

- **Where** (all in `ctkat/templates/timing_kem.c.j2`):
  - **sk-leak branch** (default):
    - L102: `crypto_kem_keypair(pk_fixed, sk_fixed)` — fixed-class setup
    - L177: `crypto_kem_keypair(pk_random, sk_random)` — per class-1 iteration
  - **ct-leak branch**:
    - L102: `crypto_kem_keypair(pk_fixed, sk_fixed)`
    - L107: `crypto_kem_enc(ct_fixed, ss, pk_fixed)` — fixed-class ct setup
    - L125: `crypto_kem_enc(ct_random, ss, pk_fixed)` — per class-1 iteration
  - PQClean `randombytes.c` (`examples/pqc_mlkem768/common/randombytes.c`)
    uses `getrandom()`/`SYS_getrandom`/`/dev/urandom` — OS entropy, ignores
    yaml seed.
- **Symptom**: Both `leak_target=sk` and `leak_target=ct` are
  non-reproducible on real PQClean KEMs. Both branches call
  `crypto_kem_keypair()` and/or `crypto_kem_enc()`, which in turn call
  `randombytes()` for their internal entropy.
  - **sk-leak**: keypair() at setup + per class-1 iteration → every sk
    value differs across runs → every class-1 measurement uses a
    different sk.
  - **ct-leak**: keypair() once at setup + enc() at setup + enc() per
    class-1 iteration → every ct value differs across runs.
  - The synthetic `toy_kem_ct_leak` is unaffected — its `trivial_enc`
    uses an internal counter, deterministic per-process. Likewise for
    `toy_dudect` generic-template harnesses (those use `rand_bytes`
    which is the harness's xorshift PRNG).
- **History / framing correction**: The original v1 of this issue
  claimed Bundle D introduced this and that sk-leak was reproducible.
  Both claims were wrong — sk-leak has called PQClean `keypair()` since
  Bundle B (when the dudect KEM template was first added). Bundle D
  exposed the same flaw from a new angle but did not introduce it. The
  "My fault" self-attribution to Bundle D was over-narrow.
- **Why solve**: README and `config.py:DudectConfig.seed` doc both claim
  that `seed: 0xC0FFEE` "deliberately reproduces the same input
  sequence." This is only true for the xorshift-driven parts of the
  harness (notably `rand_bytes` filling generic-template buffers). Any
  PQClean-backed KEM harness — sk-leak or ct-leak — silently violates
  the documented reproducibility guarantee. Users diffing two
  `dudect_raw_timings.csv` files expecting bit-identical output will
  be confused; CI gates on exact |t| values will be flaky.
- **Acceptance criteria** (pick one):
  - **Option A — Documentation**: Add an explicit caveat to README
    (yaml schema `seed` description and the new "dudect 측정 강화"
    section) stating: "PQClean-backed KEM harnesses are non-reproducible
    regardless of `leak_target` — `crypto_kem_keypair()` and
    `crypto_kem_enc()` draw from OS entropy, ignoring `seed`. Synthetic
    harnesses (`toy_kem_ct_leak`, toys using the generic template) ARE
    reproducible. To verify: `dudect_raw_timings.csv` diff between two
    identical-yaml runs."
  - **Option B — Mechanism**: Override `randombytes()` symbol in the
    generated `timing_<name>.c` (link-time interpose) so PQClean uses a
    xorshift64 keyed from `CTKAT_SEED` instead of OS entropy.
    Implementation: emit a definition of
    `int randombytes(uint8_t *buf, size_t n)` at the top of the timing
    harness; the linker (when both this definition and PQClean's
    `common/randombytes.c` are in the link set) will pick whichever
    appears first. Verify link order in CI — may require
    `-Wl,--allow-multiple-definition` or moving PQClean's
    `randombytes.c` out of `sources:` and providing the override
    exclusively. Fixes both leak modes uniformly. **Note**: the
    randombytes override would need to be added in both branches of
    `timing_kem.c.j2` — see T1 (template dedup) for an opportunity to
    consolidate first or simultaneously.
- **Recommendation**: Option A should land **as soon as possible** —
  the doc currently lies about reproducibility, every day with the
  false claim is a day a user could be confused. Easiest path: a
  small dedicated docs commit before Bundle E (not even bundled),
  literally one README paragraph + one yaml-schema-comment line.
  Option B (mechanism fix) is the larger work, naturally co-targets
  T1 (template dedup) per its note, and can wait for its own bundle.
- **Related**: R3 (system noise — independent cause of non-reproducibility,
  also undocumented). T1 (template dedup — natural co-target with Option B).
- **Suggested bundle**: **Docs sweep / immediate quick commit** (A);
  separate bundle for (B).

### R2: Multi-cutoff `max|t|` inflates Type-I error + normality assumption is unaddressed 🟡

- **Where**: `ctkat/statistics.py:CROP_PERCENTILES` and
  `welch_with_cropping`,
  README `dudect_summary.csv` reference (`README.md:264-279` ish).
- **Symptom (multi-cutoff)**: Bundle B runs Welch's t-test at 5 cutoffs
  (`[1.0, 0.99, 0.95, 0.90, 0.75]`) and reports max |t|. The thresholds
  4.5 / 10.0 (`dudect.threshold_warning` / `fail`) are calibrated for a
  *single* Welch test under the H0 of no leak. Taking the max over 5
  correlated tests increases the chance of exceeding 4.5 by random
  chance — empirically, on `toy_dudect/safe` the post-A `|t|=0.035`
  jumped to `|t|=0.994` after Bundle B's cropping. Still PASS (well
  below 4.5), but the effective threshold has shifted.
- **Symptom (normality)**: Welch's t-test assumes approximately normal
  sample means. Cycle-count distributions on real hardware are
  heavy-tailed (closer to gamma/log-normal due to scheduling/cache
  bursts). The current cropping framing in README and commit messages
  positions cropping as *outlier handling* — implying outliers are
  rare anomalies. In reality, cropping is also *normalizing a
  non-normal sample* (a band-aid for assumption violation), and the
  band-aid effectiveness depends on the underlying distribution
  shape, which we don't characterize.
- **Why solve**: A borderline-clean implementation that scored
  `|t|=3.5` (PASS) under single-test could score `|t|=5.0` (WARNING)
  under max-of-5 with no actual leak change. False WARNINGs erode user
  trust. Conversely, cropping at 0.50 can cut the tail where a
  rare-trigger leak hides, masking real signal. The normality
  framing matters for users reading the README who might assume the
  framework's statistical guarantees are textbook-grade — they aren't.
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
- **Acceptance criteria** — **deliberately overlaps F4 #2**. The
  warning text *is* S2; the per-class tracking is F4. Close together.
  1. Per F4, emit a per-class warning. Format: `dropped 12.4% of class-0
     vs 0.3% of class-1 — sample bias likely, treat |t| skeptically`.
  2. Test it triggers on synthetic asymmetric input.
- **Related**: **F4 (same fix; F4 is the logic, S2 is the user-facing
  alert)**, S1.
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
  1. **Primary fix**: add a third `leak_target=fo` mode to
     `timing_kem.c.j2` that uses random/invalid ct for class 1 (class
     0 keeps a valid `enc()`-derived ct). Verifies the FO fallback
     decapsulation path is constant-time across valid-vs-invalid ct.
     New bundle territory (logically Bundle E-2 or D-2 follow-up).
  2. **Secondary fix (and quick interim)**: README "ct-leak 모드 한계"
     paragraph explicitly mentions FO-fallback paths are not covered
     by the current `leak_target=ct` mode. Lands in Docs sweep.
- **Related**: U1.
- **Suggested bundle**: Docs sweep (#2 interim), then a follow-up
  bundle for #1.

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
  easy to introduce drift. **Strong reason to land first**: R1 Option B
  (randombytes override) requires adding the same override block to
  both branches; doing it after a dedup refactor is a one-line change
  instead of two.
- **Acceptance criteria**: Pull common pieces into Jinja2 macros or
  share a base template via `{% include %}`. Refactor + tests confirm
  identical C output for both modes (modulo intended differences).
- **Related**: R1 (especially Option B mechanism path).
- **Suggested bundle**: opportunistic (during Bundle E or as preface to
  R1 Option B).

### T6: dudect harness timeout — hardcoded 600s + Python traceback 🟢→🟡

- **Where**:
  - `ctkat/dudect_runner.py:70-78` — `timeout: int = 600` is a function
    parameter default. Not propagated from yaml; user can't configure.
  - `ctkat/cli.py:461` (`run_timing_harness` call inside `_do_dudect`) —
    no try/except wrapper.
  - README — never documents the 600s ceiling.
- **Symptom (two distinct ones)**:
  1. **No graceful failure**: if a dudect harness infinite-loops or
     exceeds 600s, `subprocess.TimeoutExpired` propagates up through
     typer and the user sees a raw Python traceback. No verdict, no
     summary, just a stack trace.
  2. **Hardcoded ceiling**: a user running a slow target (e.g. 50µs
     per call × 50000 measurements ≈ 2500s on QEMU) hits the limit
     even without infinite loops. They have no yaml knob to bump it.
- **Why solve**: (1) is the same fail-mode class as F2 (analysis
  didn't complete cleanly). (2) is a usability ceiling that
  silently constrains the framework to fast targets — not documented
  anywhere, surfaces as a confusing crash.
- **Acceptance criteria**:
  1. Add `dudect.timeout: int = 600` to `DudectConfig` (yaml-configurable
     ceiling).
  2. Plumb the configured value through `_do_dudect` → `run_timing_harness`.
  3. Wrap `run_timing_harness` call with try/except for
     `subprocess.TimeoutExpired`.
  4. On timeout: log clear error (`harness X timed out after Ns`),
     attach status=ERROR (using F3's INCONCLUSIVE).
  5. Document the default and how to bump in README.
  6. Test: harness that sleeps forever → ERROR, not Python traceback;
     yaml `dudect.timeout: 60` → harness gets 60s.
- **Related**: F2 (similar fail-mode, different stage), F3 (ERROR state),
  U4 (function speed range documentation — closely related).
- **Suggested bundle**: E.

### T7: Jinja template context has no C-identifier validation 🟢

- **Where**: `ctkat/cli.py:97-140` (`_build_generic_context`,
  `_build_kem_context`, `_build_sign_context`). All three pass
  `h.function`, `h.prefix`, `h.args` etc. through to Jinja with no
  pattern check; `HarnessConfig` pydantic validation enforces
  `Optional[str]` but no `^[A-Za-z_][A-Za-z0-9_]*$` constraint.
- **Symptom**: A yaml with `function: '; system("rm -rf /")'` lands
  in the generated C file literally. Compile fails noisily, but the
  abuse surface is open.
- **Why solve**: Same family as T4 (`shell=True` on user yaml). The
  framework's stance "yaml ownership is the user's responsibility" is
  documented in README, but a defensive layer is cheap.
- **Acceptance criteria**:
  1. Add pydantic field validators on `HarnessConfig.function`,
     `HarnessConfig.prefix`, and `HarnessConfig.return_type` enforcing
     `^[A-Za-z_][A-Za-z0-9_:* ]*$` (C identifiers, plus `:`, `*`, space
     allowed for things like `unsigned int *`).
  2. `HarnessConfig.args` is trickier (each element may be `sizeof(x)`,
     etc.) — allow a broader pattern or skip.
  3. Test: confirm `function: "; system(...)"` raises ValidationError
     at config load.
- **Related**: T4 (shell=True), F1/F5/F6 (related "trust the yaml"
  posture).
- **Suggested bundle**: TBD (not currently planned; low-priority
  hardening).

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

**Closes**: F1, F2, F3, F5, F7, F8, T6, partially F4.
**LoC estimate**: ~350 (v1 ~150 → v2 ~250 → v3 ~350, expanded with each
external review pass).
**Why this bundle goes first**: Every other improvement compounds on
top of verdict correctness. Building on a fail-open base produces
false safety stacked on false safety. After external review pass 3 the
bundle's title ("fail-open closure") only fits if F7/F8 (subcommand
exit-code asymmetry) land alongside the verdict-matrix work.

**Sketch (ordered by inter-dependency)**:
- New `Verdict.INCONCLUSIVE` enum member + matrix entries (F3) —
  precondition for F2/F5/T6 mappings.
- New `valgrind_status="ERROR"` returned by `_do_ct` on crash (F2).
- New `kat.expected_min` yaml field + stdout-grep validation in `_do_kat`
  + always-echo stdout (F1).
- New `ct.require_sentinel` yaml field + sentinel-line check in `_do_ct`
  manual mode (F5). Includes updating example harnesses to emit the
  sentinel.
- Subcommand exit-code consistency: `cfg.kat is None → Exit(2)` (F7);
  add `cfg.ct is None → Exit(2)` guard to ct command (F8). Don't print
  "PASS" when section is absent.
- `dudect.timeout` yaml field; try/except around timing harness for
  TimeoutExpired → INCONCLUSIVE (T6).
- **Deferred to Bundle F**: F6 (`secret_regions` size check) — see F6
  body for rationale; needs sentinel program, doesn't fit E's scope.
- Tests for each fail-open mode (one regression test per F-issue
  closed).
- README updates: verdict matrix, KAT section, CT manual-mode section,
  CLI subcommand exit-code contract.

**Sizing risk**: ~350 LoC is at the upper end of single-commit comfort.
Splitting option:
- **E-1 (verdict-state + exit-code)**: F1, F3, F7, F8, T6. ~200 LoC.
- **E-2 (analysis-stage fail-open)**: F2, F5. ~150 LoC. Depends on E-1's
  INCONCLUSIVE state being available.

Author preference: keep as single E unless review feedback demands
split. Bundle B was 334 LoC single-commit precedent.

### Bundle F — Class Balance + Sample Transparency + F6 🟡

**Closes**: F4, F6, S1, S2.
**LoC estimate**: ~170 (was ~120; +50 for F6 sentinel program).

**Sketch**:
- Per-class drop tracking in `parse_timing_csv` (F4 logic + S2 warning).
- New CSV columns 18-20 (raw_n_total, dropped_zero_n0/n1) (S1).
- F6: emit a tiny sentinel program at harness compile to extract
  `CRYPTO_SECRETKEYBYTES` value; compare against `sum(secret_regions.length)`;
  warn at <50% coverage.

**Moved out**: R1 Option A is too small to wait — handled in Docs sweep
(or a standalone quick commit), not held back to F.

### Bundle G — Calibration / Effect Size 🟢

**Closes**: R2, S3.
**LoC estimate**: ~80.

**Sketch**:
- Cohen's d in `WelchResult`, CSV col 21.
- Optional Bonferroni-like threshold scaling.
- README calibration guide for multi-cutoff inflation.

### Docs sweep — Honest Limitations

**Closes**: U1, U2 (interim doc note — primary fix is separate bundle),
U3, U4, R1 (Option A), R3.
**LoC estimate**: ~100 (README) + ~80 (new `docs/tutorial.md` if U5 included).

**Sketch**:
- R1 Option A: PQClean reproducibility caveat (yaml seed only controls
  xorshift-driven parts, not `crypto_kem_*` calls). **Can ship as a
  standalone quick docs commit before Bundle E** to remove the
  misleading "deliberately reproducing" claim ASAP.
- "PASS does not mean constant-time" paragraph (U1).
- FO-fallback path note in ct-leak section (U2 interim).
- Windows MSVC caveat (U3).
- Function speed range guidance + cross-ref to `dudect.timeout` (U4 +
  T6's documentation half).
- Reproducibility / system noise note (R3).

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
- **External reviews**: log each pass with date, scope, key corrections.

---

## Review log

### v1 — initial (2026-05-26)

- Author: Bundle A–D author, after external review pass 1.
- Issues catalogued: F1–F4, R1–R3, S1–S3, U1–U5, T1–T5 (17 total).
- Bundle plan: E / F / G / Docs sweep.

### v2 — corrections after external review pass 2 (2026-05-26)

- Reviewer audited v1 itself against the codebase.
- Corrections:
  - **R1 was wrong about scope**: claimed only `leak_target=ct` had the
    reproducibility issue; in fact `leak_target=sk` has the same issue
    because `crypto_kem_keypair()` ALSO calls PQClean `randombytes()`.
    Bundle D was wrongly attributed as the introducing bundle —
    actually Bundle B (when the KEM dudect template was first added)
    already had this. Body and acceptance criteria rewritten.
  - **F5 added** (Tier 1): CT manual binary mode skips function-call
    verification — sibling of F1, same fail-open pattern in a different
    stage. Missed in v1.
  - **F6 added** (Tier 2 with F-numbering): `secret_regions` size not
    cross-checked against `CRYPTO_SECRETKEYBYTES`.
  - **T6 added** (Tier 5): dudect harness timeout produces raw Python
    traceback instead of graceful ERROR.
  - **R2 expanded**: added normality-assumption note (Welch assumes
    approximately normal sample means; cycle distributions are
    heavy-tailed; cropping is a band-aid not just outlier handling).
  - **F1 acceptance**: added "always echo stdout on PASS too" — without
    it the user never sees the count their `expected_min` is checking.
  - **T1 cross-ref**: noted that R1 Option B is a natural co-target with
    T1's template dedup work.
  - **Bundle E roadmap expanded**: now closes F5/T6 too (and optionally
    F6). LoC estimate bumped ~150 → ~250.
  - **Verification statement honesty**: noted that v1's R1 audit was
    too narrow (looked only at ct-leak branch).

### v3 — corrections after external review pass 3 (2026-05-26)

- Reviewer audited v2 + whole repo (not just files I'd touched).
- Net change: 23 → 26 issues.
- New issues:
  - **F7 added** (Tier 1): `ctkat kat` subcommand exits 0 when `kat:`
    section absent (`cli.py:756`). Asymmetric with `ctkat dudect`
    which exits 2 in the same case. v1/v2 missed because they focused
    on the `run` pipeline, not standalone subcommand semantics.
  - **F8 added** (Tier 1): `ctkat ct` subcommand prints
    "[CTKAT] Constant-Time Check: PASS" with exit 0 when `ct:` section
    is absent (`cli.py:729-745`, missing `cfg.ct is None` guard).
    Worse than F7 — actively reports green PASS.
  - **T7 added** (Tier 5): no C-identifier validation on yaml-supplied
    `function`/`prefix`/`return_type` before they hit Jinja templates.
    Compile will fail noisily but defense-in-depth is missing. Sibling
    of T4 (`shell=True`).
- Existing-issue updates:
  - **T6 elevated** 🟢→🟡: original framing covered only the
    Python-traceback half. v3 reviewer noted the 600s timeout is
    hardcoded (`dudect_runner.py:70`) and not yaml-configurable — this
    silently constrains usable function speed range. Acceptance
    criteria now covers both halves; `dudect.timeout` yaml field is
    primary deliverable.
  - **F4 ↔ S2 cross-ref tightened**: external noted the two issues had
    overlapping acceptance criteria. Confirmed they are deliberately
    paired — F4 is the logic fix, S2 is the user-facing warning text
    for the same fix. Both now explicitly note they close together.
  - **F6 bundle assignment finalized**: was "Bundle E or F"; now
    definitively Bundle F. Rationale: cheap "integer-literal only"
    check skips the macro-based case (e.g. PQClean ML-KEM) that
    motivates the issue. Sentinel-program impl is the right answer
    but doesn't fit E's exit-code-and-state scope.
  - **R1 Option A scheduling**: moved out of Bundle F into Docs sweep
    / standalone quick commit. v2 had it sitting in F; v3 reviewer
    pointed out the doc lies about reproducibility today, so the
    one-paragraph fix should land ASAP, not wait for F.
  - **U2 acceptance criteria reordered**: v2 listed README note first
    and the template `leak_target=fo` mode as "optionally". v3
    reviewer pointed out priority was inverted — the mode is the
    primary fix, the doc is interim. Now reflected.
  - **Bundle E LoC re-estimated**: v2 ~250 → v3 ~350 with F7/F8/T6
    expansion folded in. Added explicit E-1 / E-2 split option in
    case ~350 is too big to land in one commit.
  - **Bundle F closes F6 now** (not "deferred to F"): F6 is part of
    F's scope, ~170 LoC total.
