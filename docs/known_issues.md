# CT-KAT — Known Issues & Improvement Plan

Working document. Catalogs problems found after Bundles A/B/C/D were
merged, with stable issue IDs so they can be referenced by future
commits and PRs.

## Status

- **Last updated**: 2026-05-26 (v5 + Quick Docs — see Review log at the bottom)
- **Resolved so far**:
  - R1 Option A — PQClean reproducibility caveat in README (Quick Docs commit).
  - F9 #1+#2 — cflags asymmetry banner + README warning (Bundle E-3).
  - F1, F3, F7, F8, F10, F11, T6 — Bundle E-1 (fail-open closure +
    INCONCLUSIVE verdict state + per-stage exit-code contract).
  Pipeline progress: 7 fully closed (F1/F3/F7/F8/F10/F11/T6), 2 partial
  (R1, F9). Bundle E-2 next (analysis-stage fail-open: F2, F5).
- **Audit sources**:
  - Internal review by Bundle A–D author (focused on dudect pipeline)
  - External independent reviewer, pass 1 (whole-pipeline audit)
  - External independent reviewer, pass 2 (audited v1 of this doc)
  - External independent reviewer, pass 3 (audited v2 + whole repo)
  - External independent reviewer, pass 4 (audited v3 + cross-stage interactions)
  - Verification pass 5 (audited v4 line references against `main`)
- **Total findings**: 5 tiers, 35 issues (v1: 20 → v2: 23 → v3: 26 → v4: 35 → v5: 35)
  - v5: no new issues — all 35 v4 findings re-verified against `main`;
    line-reference drift corrected in 7 places (F1, F4, F5, F7, F9, R1,
    T6, T8). R1's sk-leak branch line was a real mis-cite (L102 → L157),
    not just drift.
- **Verification**: All Tier 1 (F1–F11) and Tier 2 (F6, R1–R3) claims
  verified against `main` (commit `d678617` or later) by reading the
  cited source lines. Earlier passes (v1–v3) focused tightly on the
  dudect pipeline and individual stages. v4 audit surfaced
  *cross-stage* fail-opens that span the whole `run` pipeline (F9
  compiler-flag asymmetry, F10 build-stage exit-code, F11
  continue-on-kat-fail leak) — these were structurally hard to spot
  without examining how the stages interact at the config level.

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

**Status: RESOLVED in Bundle E-1.** `_do_kat` now greps stdout with
`kat.expected_pattern` (default matches PQClean/NIST output) and compares
against `kat.expected_min`. Unset → legacy exit-code-only behavior with a
one-time warning. Stdout always echoed (previously hidden on PASS).

- **Where**: `ctkat/builder.py:17-30` (`run_shell`),
  `ctkat/cli.py:78-94` (`_do_kat`).
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

**Status: RESOLVED in Bundle E-1.** `Verdict.INCONCLUSIVE` enum + matrix
entries for any ERROR pair (and KAT FAIL pre-filter via F11). CI exit code
2 (same as FAIL) so existing `&& deploy` gates keep working.

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
  `if h.binary is None` guard at line 204 and the manual-binary
  assignment at line 210.
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

**Status: RESOLVED in Bundle E-1.** `ctkat kat` now raises `Exit(2)` —
symmetric with `ctkat ct` (F8) and `ctkat dudect`.

- **Where**: `ctkat/cli.py:755-757` (kat subcommand, inside the
  `@app.command()` kat function at `:748-759`). Concretely:
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

**Status: RESOLVED in Bundle E-1.** Early guard added; subcommand now
exits 2 with a red "No `ct` section in config." message instead of
bold-green PASS.

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

### F9: ct stage and dudect stage compile with DIFFERENT optimization levels 🚨

**Status**: **Criteria #1 (documentation) + #2 (CLI banner) RESOLVED in
Bundle E-3.** `ctkat run` now prints both stages' cflags side-by-side at
the top of the run, with a yellow `[CTKAT] WARNING: ... different cflags
... cmov vs branch ...` line when they differ. README §"컴파일 옵션
비대칭 경고" documents the trap.
Open: #3 (yaml `shared_cflags` convenience) and #4 (multi-target matrix).

- **Where**:
  - `ctkat/config.py:162-163` — `_default_cflags() = ["-O0", "-g",
    "-fno-inline", "-fno-omit-frame-pointer"]` (ct/Valgrind stage).
  - `ctkat/config.py:193-198` — `_default_dudect_cflags() = ["-O2", "-g",
    "-fno-omit-frame-pointer", "-fno-lto"]` (dudect stage).
- **Symptom**: A verdict `CLEAN` does NOT mean "both ct and dudect
  PASSed on the same code." The two stages compile the user's source
  with different optimization levels by default, producing
  structurally different binaries. Compiler may emit:
  - A secret-dependent branch at `-O0` (which Valgrind catches at
    ct stage as a secret-dependent jump).
  - A `cmov` (conditional move) at `-O2` (which Valgrind does NOT see
    as a branch).
  - Or vice versa — `-O2` keeps a branch the user thought would be
    optimized away.
  → ct may FAIL on `-O0` while dudect PASSes on `-O2`, or both PASS
  on their respective binaries while the user's actual production
  binary (typically `-O2` or `-O3`) has different secret-dependent
  behavior from both.
- **Why solve**: This is the verdict-reliability gap with the largest
  blast radius. Every user reading "verdict: CLEAN" assumes "this
  code, as I'll ship it, is verified." The framework currently makes
  no effort to ensure the two stages analyze the same code. It's a
  more concrete trap than U1 ("PASS ≠ constant-time") because it
  applies *even within the framework's own scope*.
- **Acceptance criteria** (escalating):
  1. **Documentation minimum**: README "dudect 측정 강화" section
     adds explicit warning. The default `-O0` for ct and `-O2` for
     dudect were chosen for different reasons (Valgrind debug
     friendliness vs realistic timing), but the user must understand
     they're analyzing different binaries.
  2. **Visibility**: print effective ct cflags vs dudect cflags side-
     by-side at run start; warn loudly when they differ.
  3. **Recommendation tooling**: support a yaml convenience
     `shared_cflags: List[str]` at top level; when set, BOTH stages
     adopt it (overriding their per-stage defaults). Users wanting
     "verify what I ship" can set `shared_cflags: [-O2, -g]` and
     accept the Valgrind debug-info loss as the cost of consistency.
  4. **Multi-target option** (deferred): allow yaml to declare
     multiple `(ct_cflags, dudect_cflags)` combos and run ct + dudect
     at each, producing a verdict matrix per combo. Out of scope for
     immediate fix.
- **Related**: U1 (PASS ≠ constant-time — F9 is the concrete-fail
  case); the existing README "Findings #3 -O0 / -O2 일관성" briefly
  touches the same concern in the context of PQClean but doesn't
  generalize.
- **Suggested bundle**: E (criteria #1+#2 are README + 10-line CLI
  banner change), separate follow-up for #3.

### F10: build stage validates by exit code only 🚨

**Status: RESOLVED in Bundle E-1.** `build.expected_artifacts: List[Path]`
added; `_do_build` now verifies every listed path exists after rc=0.
Unset → legacy behavior + one-time warning.

- **Where**: `ctkat/cli.py:63-75` (`_do_build`). Effectively the same
  shape as F1 but at the build stage.
- **Symptom**: `cfg.build.command` is run via `run_shell`; PASS iff
  exit code 0. `build.command: "true"` → build PASS. Combined with
  KAT no-op (F1) and a stale/fake harness binary (F5) → full pipeline
  fail-open.
- **Why solve**: F1's sibling that v1–v3 missed. The "fail-open
  closure" Bundle E title is incomplete without it. Subset of the
  same family: any user-supplied shell command that the framework
  trusts solely on exit code.
- **Acceptance criteria**:
  1. Optional yaml field `build.expected_artifacts: List[str]` — list
     of paths the build is expected to produce.
  2. After `run_shell`, verify each listed path exists and has been
     modified within the last N seconds (where N = run duration + a
     buffer). Missing/stale → build FAIL.
  3. Test: `build.command: "true"` with `expected_artifacts: [./bin/x]`
     → FAIL because `./bin/x` doesn't exist.
  4. Backward compatible: if `expected_artifacts` is unset, current
     behavior preserved with a one-time warning (mirrors F1's
     `expected_min` pattern).
- **Related**: F1 (same exit-code-only pattern, KAT stage), F5 (binary
  whose origin isn't verified).
- **Suggested bundle**: E.

### F11: `--continue-on-kat-fail` makes KAT FAIL invisible in verdict CSV 🚨

**Status: RESOLVED in Bundle E-1.** `kat_status` propagated through
`_compute_verdicts`; KAT FAIL pre-filters every harness verdict to
INCONCLUSIVE. Verdict CSV gets new `kat_status` + `kat_count` columns
(appended at end, awk `$7=verdict` position unchanged).

- **Where**:
  - `ctkat/cli.py:684-685` — the `--continue-on-kat-fail` flag swallows
    KAT failures and proceeds to ct/dudect stages.
  - `ctkat/cli.py:_compute_verdicts` — only consumes `ct_results` and
    `dudect_results`. KAT status is not part of the verdict matrix.
- **Symptom**: User runs `ctkat run --config x.yaml --continue-on-kat-fail`.
  KAT fails (e.g., real correctness regression). ct and dudect still
  run on the (incorrect) build artifact. Both report PASS (because
  Valgrind sees no taint propagation through a broken function, and
  dudect sees stable timing for the broken function). verdict CSV →
  `CLEAN`. A CI script gating on `verdict=CLEAN` merges code whose
  KAT failed.
- **Why solve**: The flag's intent is "I want to see how far the
  pipeline gets even if KAT is broken." Reasonable for dev iteration.
  But the verdict output should still reflect that KAT failed — and
  it doesn't. Verdict CSV is documented as the canonical CI gate
  (`README.md:247-251`). This breaks that contract silently.
- **Acceptance criteria**:
  1. Add `kat_status` as a third axis to the verdict matrix:
     PASS / FAIL / NONE (when no kat section).
  2. When `kat_status == "FAIL"`, the verdict is downgraded to at
     least `INCONCLUSIVE` (or a new state like `KAT_FAILED`),
     regardless of ct/dudect outcomes.
  3. Update verdict CSV columns: add `kat_status` column.
  4. README updates: verdict matrix table extended to 3 axes (or
     show kat_status as a precondition).
  5. Test: continue-on-kat-fail + KAT FAIL + ct PASS + dudect PASS
     → verdict ≠ CLEAN.
- **Related**: F1 (KAT fail-open in standalone subcommand), F3 (verdict
  state), F7 (kat subcommand).
- **Suggested bundle**: E.

### F4: dudect zero-cycle filter ignores class balance 🟡

- **Where**: `ctkat/dudect_runner.py:40-87` (`parse_timing_csv`),
  `ctkat/dudect_runner.py:19` (`_ZERO_CYCLE_WARN_THRESHOLD = 0.01`).
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

**Status**: **Option A RESOLVED in Quick Docs commit (pre-Bundle-E warmup).**
README §"재현성 (seed)" 표 + yaml seed 코멘트로 caveat 명시.
Option B (`randombytes` interpose mechanism) is still open — follow-up,
naturally co-targets T1 (template dedup).

- **Where** (all in `ctkat/templates/timing_kem.c.j2`):
  - **ct-leak branch** (`{% if leak_target | default("sk") == "ct" %}`):
    - L102: `crypto_kem_keypair(pk_fixed, sk_fixed)` — fixed-class setup
    - L107: `crypto_kem_enc(ct_fixed, ss, pk_fixed)` — fixed-class ct setup
    - L125: `crypto_kem_enc(ct_random, ss, pk_fixed)` — per class-1 iteration
  - **sk-leak branch** (default, `{% else %}`):
    - L157: `crypto_kem_keypair(pk_fixed, sk_fixed)` — fixed-class setup
    - L177: `crypto_kem_keypair(pk_random, sk_random)` — per class-1 iteration
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

### S4: partial dudect run discards all prior harnesses' data 🟡

- **Where**: `ctkat/cli.py:465-470` — inside the `for h in dud.harnesses:`
  loop, raises `typer.Exit(1)` when any single harness produces
  insufficient samples:
  ```python
  if len(c0) < 2 or len(c1) < 2:
      console.print(f"[red]Not enough samples per class for {h.name}: ...[/]")
      raise typer.Exit(1)
  ```
- **Symptom**: A yaml configures 5 dudect harnesses. The 4th has a
  build problem producing too-few samples. Raise happens *inside the
  loop*, before `_emit_dudect_report` is called. Results for the
  3 already-completed harnesses are dropped on the floor — no CSV
  emitted, no console summary persisted.
- **Why solve**: Long dudect runs are expensive (minutes per
  harness). Losing all of them because one is broken is poor UX
  and incentivizes users to debug failed harnesses by isolating them
  into separate yamls (defeating the per-yaml batch purpose).
- **Acceptance criteria**:
  1. On per-harness failure: log clearly, attach status=ERROR (uses
     F3's INCONCLUSIVE), `continue` to next harness instead of raise.
  2. After loop: still call `_emit_dudect_report` with whatever
     results were collected.
  3. Overall exit code = max severity across all harnesses (FAIL/
     ERROR/PASS).
  4. Test: 3 harnesses where 2nd fails — CSV contains all 3 rows
     (2 with data, 1 with ERROR), exit non-zero.
- **Related**: F2 / F3 / T6 (all part of the "graceful failure"
  refactor).
- **Suggested bundle**: F (the post-error-state work; logically
  follows Bundle E's ERROR-state introduction).

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

### U6: `Verdict.LOW_RISK` label undersells valgrind structural findings 🟡

- **Where**: `ctkat/verdict.py:55, 62` (matrix entries `(FAIL, PASS) →
  LOW_RISK`, `(FAIL, NONE) → LOW_RISK`).
- **Symptom**: When Valgrind reports a confirmed
  secret-dependent-branch or secret-dependent-memory-access finding,
  but dudect finds no timing difference, the verdict label is
  "LOW_RISK". The literal word "LOW" makes users think the finding
  is dismissible. In reality:
  - Valgrind FAIL is *structural*, confirmed evidence that secret
    values affect control flow / memory addressing.
  - dudect PASS just means the framework's *current* harness +
    measurement environment couldn't detect a timing difference. That
    doesn't mean there isn't one in production, or on a different
    micro-arch, or with adversarial inputs.
- **Why solve**: User reading "LOW_RISK" in a security review report
  may skip the finding. The framework should name this case in a way
  that pushes the user to investigate, not to dismiss.
- **Acceptance criteria** (pick one):
  - **Option A — Rename**: `LOW_RISK` → `STRUCTURAL_LEAK` (or
    `BRANCH_NOT_TIMED`). More accurate.
  - **Option B — Doc**: keep the label, but README verdict matrix
    section explicitly warns "LOW_RISK doesn't mean dismissible —
    Valgrind has confirmed a structural secret dependence; dudect
    just couldn't measure timing diff in this run."
  - Option A is cleaner if we're willing to break verdict CSV
    consumers. Option B is non-breaking.
- **Related**: U1 ("PASS ≠ constant-time" — same family of
  underclaim).
- **Suggested bundle**: Docs sweep (B) or its own bundle (A breaks
  CSV).

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

### T6: dudect harness uncaught exceptions — Python traceback (4 paths) 🟢→🟡

**Status: RESOLVED in Bundle E-1.** `dudect.timeout` yaml field added.
`_do_dudect` wraps all four paths (TimeoutExpired, RuntimeError rc!=0,
ValueError empty stdout, ValueError malformed CSV) → `status="ERROR"`
result, propagates to verdict INCONCLUSIVE. No raw Python traceback.

- **Where**:
  - `ctkat/dudect_runner.py:43` — `raise ValueError("empty timing harness output")`
  - `ctkat/dudect_runner.py:45` — `raise ValueError("unexpected CSV header: ...")`
  - `ctkat/dudect_runner.py:90-100` — `timeout: int = 600` is a function
    parameter default. Not propagated from yaml; user can't configure.
  - `ctkat/dudect_runner.py:102-106` — `raise RuntimeError("timing harness ... failed (rc=...)")`
  - `ctkat/cli.py:461` (`run_timing_harness` call inside `_do_dudect`) —
    no try/except wrapper for ANY of the above.
  - README — never documents the 600s ceiling.
- **Symptom (four distinct uncaught failure modes)**:
  1. **Timeout (`subprocess.TimeoutExpired`)**: infinite-loop / slow
     target exceeds 600s → raw Python traceback to user.
  2. **Harness crash (`RuntimeError` from rc≠0)**: segfault / abort
     → traceback.
  3. **Empty stdout (`ValueError("empty timing harness output")`)**:
     harness died before emitting any CSV → traceback.
  4. **Malformed CSV header (`ValueError("unexpected CSV header")`)**:
     harness wrote debug printf before the header line → traceback.
  Plus the separate problem:
  5. **Hardcoded 600s ceiling**: user running a slow target (e.g. 50µs
     per call × 50000 measurements ≈ 2500s on QEMU) hits the limit
     even without infinite loops. No yaml knob.
- **Why solve**: (1)–(4) are all the same fail-mode class as F2
  (analysis didn't complete cleanly). v3 framing covered only (1).
  All four should produce status=ERROR / verdict=INCONCLUSIVE, not
  raw stack traces. (5) is a usability ceiling that silently
  constrains the framework to fast targets.
- **Acceptance criteria** (revised, broader than v3):
  1. Add `dudect.timeout: int = 600` to `DudectConfig`
     (yaml-configurable ceiling).
  2. Plumb the configured value through `_do_dudect` →
     `run_timing_harness`.
  3. Wrap the `run_timing_harness` call in `_do_dudect` with try/except
     covering **all four**: `subprocess.TimeoutExpired`, `RuntimeError`
     (rc≠0), and `ValueError` (from `parse_timing_csv` — empty or
     malformed). Each → log clear diagnostic + status=ERROR (using
     F3's INCONCLUSIVE).
  4. Document the timeout default and how to bump in README.
  5. Tests, one per uncaught path: harness that sleeps forever,
     harness that segfaults (`exit(1)`), harness that prints nothing,
     harness that prints garbage header. Each → ERROR result, not
     traceback.
- **Related**: F2 (similar fail-mode, different stage), F3 (ERROR
  state), F5 (manual-binary fail-open with related stdout-discipline
  concerns), U4 (function speed range documentation).
- **Suggested bundle**: E.

### T8: dudect `measurements`/`warmup`/`batches` have no upper bound 🟢

- **Where**: `ctkat/config.py:264-266` (`measurements: int = 100_000`,
  `warmup: int = 1_000`, `batches: int = 10`). Pydantic enforces `int`
  typing only.
- **Symptom**: User types `measurements: 100000000` (extra zero or
  copy-paste mistake). Generated harness emits
  `static uint64_t cycles_buf[100000000];` and
  `static uint8_t classes_buf[100000000];` → ~800 MB + 100 MB in BSS.
  Compile typically succeeds; runtime OOM on memory-limited hosts
  (Docker default RAM, CI runners). Diagnostic is bad ("Killed" or
  segfault from page-fault), not "you wrote too big a number."
- **Why solve**: Defensive bounds on user input. Trivial pydantic
  constraint.
- **Acceptance criteria**:
  1. `measurements: int = Field(default=100_000, ge=100, le=10_000_000)`
     (10M is a defensible ceiling — 80MB BSS).
  2. Similar `ge`/`le` bounds on `warmup` (e.g., 0..measurements) and
     `batches` (e.g., 1..1000).
  3. README documents the bounds.
- **Related**: T7 (same family — pydantic field constraints).
- **Suggested bundle**: TBD (cheap, opportunistic).

### T9: `detect_qemu_emulation()` can false-positive 🟢

- **Where**: `ctkat/qemu_detect.py:23-31`. Substring match: any file
  in the candidate list containing `"QEMU"` → returns True.
- **Symptom**: A bare-metal host that happens to load QEMU-related
  modules (e.g., a workstation that runs VMs occasionally) may have
  the substring `"QEMU"` in `/proc/cpuinfo` or
  `/sys/class/dmi/id/sys_vendor`. `detect_qemu_emulation()` returns
  True → `clock: auto` resolves to `monotonic` → user loses rdtsc
  precision on native hardware.
- **Why solve**: Edge case but real. Workstation users with KVM/VMM
  setups would silently get worse measurements with no diagnostic.
- **Acceptance criteria**:
  1. Strengthen detection: require AT LEAST two signals to be present
     (e.g., `/proc/cpuinfo "QEMU"` AND `/sys/firmware/devicetree/base/...`
     paravirtualization hint).
  2. Or: respect an explicit yaml `clock: rdtsc` override — when set,
     bypass QEMU detection entirely (currently the F2-style warning
     fires but the auto-resolution still picks monotonic).
  3. Document the heuristic's failure mode in the clock auto section
     of README.
- **Related**: U3 (Windows support claim — similar arch-detection
  edge case).
- **Suggested bundle**: TBD (low-priority hardening).

### T10: no snapshot test pinning `dudect_summary.csv` column positions 🟢

- **Where**: `ctkat/cli.py:343-354` (the CSV header definition has a
  comment saying "1-14 stable for backward compatibility" but no test
  asserting the position contract). `scripts/run_phase4.sh:36-38`
  parses `$11` and `$2` via awk — depends on the positions.
- **Symptom**: A future refactor reorders the CSV columns. Existing
  unit tests still pass (they check semantics, not positions). The
  shell-script CI gate silently mis-parses the wrong column. Verdict
  decisions become wrong.
- **Why solve**: Belt-and-suspenders for an externally-observed
  contract. `test_cli.py:test_dudect_summary_csv_preserves_status_column_position`
  exists (Bundle B) but only checks `status` (col 11). The full
  contract is wider — all columns 1–14 are part of the public
  format.
- **Acceptance criteria**:
  1. Write a snapshot test asserting the exact header line of
     `dudect_summary.csv` (columns 1–17, with the v3 reference
     listing the canonical order).
  2. Anyone who needs to add a column appends after col 17 (or bumps
     a `CSV_SCHEMA_VERSION` and updates the test).
- **Related**: S1, S3 (CSV format), no direct functional dependency.
- **Suggested bundle**: opportunistic (during Bundle F or any future
  CSV column addition).

### T11: `header_parser._DECL_RE` doesn't match function-pointer params 🟢

- **Where**: `ctkat/header_parser.py:49-61` — regex
  `(?P<params>[^()]*)` matches everything inside the outermost parens
  but stops at nested parens.
- **Symptom**: `int register_cb(int (*cb)(int))` declarations are
  silently skipped. No error, no count, no log line — the function
  just doesn't show up in `ctkat infer` output. User wonders why
  their callback-based API doesn't appear.
- **Why solve**: Sharp edge for users running `infer` on
  general-purpose C headers. PQClean and similar PQC suites don't
  use this pattern, so the existing examples don't hit it.
- **Acceptance criteria**:
  1. Either upgrade the regex to handle one level of nested parens
     (`re` supports `(?:[^()]|\([^()]*\))*` style), OR …
  2. Emit a summary count at end of `infer`: "skipped N declarations
     with unparseable params (function pointers, variadic, etc.)"
     so the user has a heads-up.
- **Related**: none.
- **Suggested bundle**: TBD (low-priority parser hardening).

### T7: yaml-supplied identifiers reach Jinja / filesystem without validation 🟢

- **Where**:
  - `ctkat/cli.py:97-140` (`_build_generic_context`,
    `_build_kem_context`, `_build_sign_context`) — pass `h.function`,
    `h.prefix`, `h.args`, `h.return_type` straight through to Jinja
    with no pattern check.
  - `ctkat/harness_generator.py:93-94` — `source_path = output_dir /
    f"harness_{name}.c"` interpolates `name` directly into a file path.
  - `HarnessConfig` / `DudectHarnessConfig` pydantic models enforce
    `Optional[str]` typing but no regex constraints.
- **Symptom**: Multiple injection surfaces:
  1. `function: '; system("rm -rf /")'` lands in generated C
     literally. Compile fails noisily but the abuse surface is open.
  2. `name: "../../etc/passwd_pwn"` resolves to
     `_generated/harness_../../etc/passwd_pwn.c` → directory escape
     during the write step (typically fails on later compile, but
     the file write happens first).
- **Why solve**: Same family as T4 (`shell=True` on user yaml). The
  framework's "yaml ownership is the user's responsibility" stance
  is documented, but a defensive layer is cheap and the `name` →
  path case is a real path-traversal vector, not just code
  injection.
- **Acceptance criteria**:
  1. Add pydantic validators on `HarnessConfig` and
     `DudectHarnessConfig`:
     - `name`: `^[A-Za-z0-9_-]+$` (filename-safe, no path separators
       or `..`).
     - `function`, `return_type`: `^[A-Za-z_][A-Za-z0-9_:* ]*$` (C
       identifiers, plus `:`, `*`, space for things like
       `unsigned int *`).
     - `prefix`: `^[A-Za-z_][A-Za-z0-9_]*$` (must be empty string or
       a valid C identifier prefix ending in `_`).
  2. `args` items: trickier — each may be `sizeof(x)`, integer
     literals, identifiers. Allow a broader char class or skip.
  3. Tests: each of the malicious yaml values above raises
     `ValidationError` at config load.
- **Related**: T4 (shell=True), F1/F5/F6 (related "trust the yaml"
  posture).
- **Suggested bundle**: TBD (low-priority hardening). The `name`
  pattern guard is the most concrete win and could land as a cheap
  one-line pydantic validator before the rest.

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

**Closes**: F1, F2, F3, F5, F7, F8, F9 (#1+#2 only), F10, F11, T6,
partially F4.
**LoC estimate**: ~500 (v1 ~150 → v2 ~250 → v3 ~350 → v4 ~500). With
the v4 additions of F9/F10/F11 and T6 expansion, the bundle clearly
exceeds the comfort zone for a single commit. **Split now strongly
recommended.**
**Why this bundle goes first**: Every other improvement compounds on
top of verdict correctness. Building on a fail-open base produces
false safety stacked on false safety.

**Recommended split** (preserves "fail-open closure" theme across two
self-contained commits):

#### Bundle E-1 — Verdict state + per-stage exit-code contract (~250 LoC)

**Closes**: F1, F3, F7, F8, F10, F11, T6.

- New `Verdict.INCONCLUSIVE` enum + matrix entries (F3) — precondition
  for everything else.
- KAT stdout grep + `expected_min` yaml field + always-echo stdout
  (F1).
- Build artifact existence check + `expected_artifacts` yaml field
  (F10).
- Subcommand exit-code consistency: `kat`/`ct` None → Exit(2) (F7, F8).
- `kat_status` axis added to verdict matrix; `--continue-on-kat-fail`
  + KAT FAIL → verdict ≠ CLEAN (F11).
- `dudect.timeout` yaml field; try/except for all four dudect-runner
  uncaught paths → INCONCLUSIVE (T6).
- README updates: verdict matrix (now 3-axis: kat × ct × dudect),
  exit-code semantics across stages.

#### Bundle E-2 — Analysis-stage fail-open (~150 LoC)

**Closes**: F2, F5. Depends on E-1's INCONCLUSIVE state.

- New `valgrind_status="ERROR"` returned by `_do_ct` on crash (F2).
- `ct.require_sentinel` yaml field + sentinel-line check (F5).
  Includes updating example harnesses (toy_password, toy_lookup,
  toy_dudect) to emit the sentinel.

#### Bundle E-3 — Compiler-flag asymmetry minimum (~80 LoC)

**Closes**: F9 (criteria #1+#2 only — README + CLI banner). F9 criterion
#3 (`shared_cflags`) and #4 (multi-target matrix) deferred to their own
bundles.

- Print effective ct cflags vs dudect cflags side-by-side at run start;
  warn loudly when they differ.
- README "dudect 측정 강화" section: explicit "two stages may analyze
  different binaries" warning with concrete cmov vs branch example.

**Why this split is sensible**: each Bundle E-N is self-contained,
testable, and reviewable in 30-60 minutes. Total ~480 LoC across 3
commits is more honest than 500 LoC in one mega-commit. The F-series
issues group naturally — exit-code semantics (E-1), analysis-stage
hardening (E-2), compiler-flag visibility (E-3).

**Deferred from E entirely**:
- F4 (zero-filter class balance) → Bundle F.
- F6 (`secret_regions` size check) → Bundle F.
- F9 #3, #4 (yaml `shared_cflags`, multi-target matrix) → separate
  bundles.

### Bundle F — Class Balance + Sample Transparency + F6 + S4 🟡

**Closes**: F4, F6, S1, S2, S4.
**LoC estimate**: ~220 (v3 ~170 → v4 ~220; +50 for S4 graceful-skip
refactor of `_do_dudect`).

**Sketch**:
- Per-class drop tracking in `parse_timing_csv` (F4 logic + S2 warning).
- New CSV columns 18-20 (raw_n_total, dropped_zero_n0/n1) (S1).
- F6: emit a tiny sentinel program at harness compile to extract
  `CRYPTO_SECRETKEYBYTES` value; compare against `sum(secret_regions.length)`;
  warn at <50% coverage.
- S4: `_do_dudect` per-harness failure becomes `continue` with
  status=ERROR (uses Bundle E-1's INCONCLUSIVE); previously-completed
  harnesses' results still get emitted. (**Depends on Bundle E-1 landing
  first** for the ERROR state.)

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
U3, U4, U6 (Option B if not renaming), R1 (Option A), R3.
**LoC estimate**: ~120 (README) + ~80 (new `docs/tutorial.md` if U5 included).

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
- LOW_RISK label clarification: "LOW does not mean ignorable;
  Valgrind has confirmed a structural secret dependence; dudect
  just couldn't measure timing diff in this run" (U6 Option B).

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

### v5 — line-reference verification pass (2026-05-26)

- Reviewer re-walked every cited `path:line` against `main`
  (commit `74f1eb4` at audit time).
- Net change: **no new issues, no removed issues**. All 35 v4 findings
  remain valid; the code matches their descriptions.
- Line-reference corrections (file shrunk / functions moved up since v4
  was written):
  - **F1**: `cli.py:78-93` → `cli.py:78-94` (`_do_kat` is now 17 lines).
  - **F4**: `dudect_runner.py:58-78` → `:40-87` (`parse_timing_csv`
    starts at L40 now, not L58). `:24` → `:19` for the threshold const.
  - **F5**: "around line 209" → guard at `:204`, assignment at `:210`
    (clearer pointer to both halves of the branch).
  - **F7**: `cli.py:752-757` → `:755-757` (the `kat` `@app.command()`
    body starts at L753 now).
  - **F9**: `config.py:163` → `:162-163` (function span); `:194` →
    `:193-198` for `_default_dudect_cflags`.
  - **R1 (real mis-cite)**: sk-leak branch setup keypair was cited at
    L102, but L102 is actually the **ct-leak** branch's keypair. The
    sk-leak branch's setup keypair is at **L157**. Both branches were
    re-mapped to their actual line numbers. The reproducibility
    conclusion is unchanged — both branches still call OS-entropy
    `randombytes()` via PQClean.
  - **T6**: `dudect_runner.py:36/38/70-78/102-105` → `:43/45/90-100/102-106`.
  - **T8**: `config.py:268` → `:264-266` (all three fields cited together).
- No drift in F2/F8/F10/F11/T7/T9/T10/T11 — those `path:line` cites were
  already exact.
- Why the drift: `dudect_runner.py` lost ~20 lines of comments between
  v2 and v4 reviews; `config.py` lost ~5 lines around the dudect config
  block. Neither was tracked when v4 was written because the audits ran
  at slightly different commits.

### v4 — corrections after external review pass 4 (2026-05-26)

- Reviewer audited cross-stage interactions, not just individual
  stages.
- Net change: 26 → 35 issues (+9 new IDs, 2 issues expanded).
- New Tier 1 (verdict-reliability) issues — all confirmed by code
  cross-reference:
  - **F9** (compiler optimization asymmetry): ct stage uses `-O0`,
    dudect uses `-O2`. The two stages analyze **structurally
    different binaries**. verdict CLEAN doesn't mean "verified the
    code you'll ship." Biggest verdict-reliability gap missed by
    v1–v3 because those passes audited stages in isolation, not
    their compile-flag handshake.
  - **F10** (build stage exit-code only): `_do_build` returns
    `r.ok`, same fail-open pattern as F1. Bundle E's "fail-open
    closure" title doesn't fit unless this is closed too.
  - **F11** (`--continue-on-kat-fail` verdict leak): when the flag
    is set and KAT fails, the resulting verdict CSV doesn't
    include KAT status at all. KAT FAIL + ct PASS + dudect PASS →
    `CLEAN`, which is a lie.
- New Tier 3:
  - **S4** (partial dudect run discards prior data): mid-loop
    `raise typer.Exit(1)` on first failure drops 1..k–1 harnesses'
    measurements. Need to refactor to `continue` with ERROR status,
    landed after Bundle E-1 introduces ERROR.
- New Tier 4:
  - **U6** (`LOW_RISK` label undersells valgrind structural
    findings): user sees "LOW" and thinks dismissible; the actual
    semantics are "Valgrind confirmed a structural leak, dudect
    just couldn't measure it." Option A renames, Option B keeps
    label but documents.
- New Tier 5:
  - **T8** (no upper bound on `measurements`/`warmup`/`batches`):
    typo → 800MB BSS → OOM. Pydantic `Field(ge=…, le=…)` fix.
  - **T9** (`detect_qemu_emulation()` substring match false-pos):
    bare-metal hosts with QEMU strings in `/proc/cpuinfo` get
    `clock: auto → monotonic` even when rdtsc would be fine.
  - **T10** (no snapshot test pinning CSV column positions): the
    "1-14 stable" contract is in a comment only, no test enforces.
  - **T11** (`header_parser._DECL_RE` doesn't handle
    function-pointer params): silent skip on `int (*cb)(int)`-style
    declarations; user infers nothing and gets no warning.
- Existing-issue updates:
  - **T6 expanded** 🟢→🟡 (already in v3) → scope broadened. v3
    acceptance only covered `subprocess.TimeoutExpired`. v4
    reviewer pointed out the other three dudect-runner uncaught
    paths (RuntimeError from `rc!=0`, ValueError from empty
    stdout, ValueError from malformed CSV header). All four now
    in T6 acceptance.
  - **T7 expanded**: original scope was Jinja-context identifiers
    (`function`/`prefix`/`return_type`). v4 reviewer noted yaml
    `name` field → file path interpolation is a separate
    path-traversal vector (`harness_generator.py:93`). Now folded
    into T7 as a third acceptance criterion.
  - **Bundle E split**: v3 single-commit E at ~350 LoC was already
    at the upper edge. v4's F9/F10/F11/T6-expansion push it to
    ~500 LoC. Split is now strongly recommended into
    E-1 (verdict state + exit codes, ~250 LoC),
    E-2 (analysis-stage fail-open, ~150 LoC),
    E-3 (compiler-flag minimum, ~80 LoC).
  - **Bundle F LoC**: 170 → 220 with S4 absorbed.
