# CT-KAT — Known Issues & Improvement Plan

Working document. Catalogs problems found after Bundles A/B/C/D were
merged, with stable issue IDs so they can be referenced by future
commits and PRs.

## Status

- **Last updated**: 2026-05-27 (v8 — Bundle L hot-fixes landed)
- **Pipeline progress**: **40 fully closed** (Bundle 0~L), **1 deferred**
  (F9 #4, out of scope per spec), **12 still open** (F13, F14, T12, T13,
  T15, T16, T17, T18, T19, T20, T21, T22).
- **Resolved so far** (40/41 prior closed except deferred F9 #4):
  - R1 Option A — PQClean reproducibility caveat in README (Quick Docs commit).
  - F9 #1+#2 — cflags asymmetry banner + README warning (Bundle E-3).
  - F1, F3, F7, F8, F10, F11, T6 — Bundle E-1 (fail-open closure +
    INCONCLUSIVE verdict state + per-stage exit-code contract).
  - F2, F5 — Bundle E-2 (analysis-stage fail-open: valgrind crash → ERROR,
    manual-binary sentinel check).
  - F4, F6, S1, S2, S4 — Bundle F (per-class drop tracking, secret_regions
    coverage probe, raw-count CSV columns, graceful per-harness skip).
  - R2, S3 — Bundle G (multi-cutoff Type-I calibration + Bonferroni opt-in,
    Cohen's d in WelchResult + CSV col 21).
  - U1, U2 (interim), U3, U4, U5, U6 (Option B), R3 — Bundle H1 Docs Sweep
    (정직한 한계 + Windows/속도/노이즈/LOW_RISK caveat + tutorial.md).
  - T1, T4, T5, T7, T8, T9, T10, T11 — Bundle H2 Hardening (template
    dedup, shell=False argv 옵션, name regex, pydantic Field bounds,
    qemu multi-signal, CSV snapshot, header parser skip count).
  - F9 #3, U6 Option A, T2, T3 — Bundle I cleanup (shared_cflags
    propagation, LOW_RISK → STRUCTURAL_LEAK rename, lookup_patterns
    override, valgrind drop count).
  - **R1 Option B** — Bundle J (randombytes weak-symbol interpose,
    PQClean dudect deterministic opt-in).
  - **U2 #1** — Bundle K (`leak_target: fo` 모드, FO fallback path 검사).
  - **F12, F15, F16, F17, F18, T14** — Bundle L hot-fixes (parse 서브
    NameError, shared_cflags `model_fields_set`, seed=0 거부, CLI
    `model_validate` 재검증, KAT regex 앵커 + `re.MULTILINE`, yaml
    `-fno-lto` 추가 + examples lint).
  - F9 #4 — deferred future work (multi-cflags matrix; out of scope per
    spec, requires new CSV schema + matrix-aware verdict computation).
- **Audit sources**:
  - Internal review by Bundle A–D author (focused on dudect pipeline)
  - External independent reviewer, pass 1 (whole-pipeline audit)
  - External independent reviewer, pass 2 (audited v1 of this doc)
  - External independent reviewer, pass 3 (audited v2 + whole repo)
  - External independent reviewer, pass 4 (audited v3 + cross-stage interactions)
  - Verification pass 5 (audited v4 line references against `main`)
- **Total findings**: 5 tiers, 53 issues (v1: 20 → v2: 23 → v3: 26 → v4: 35
  → v5: 35 → v6: 46 → v7: 53)
  - v5: no new issues — all 35 v4 findings re-verified against `main`;
    line-reference drift corrected in 7 places (F1, F4, F5, F7, F9, R1,
    T6, T8). R1's sk-leak branch line was a real mis-cite (L102 → L157),
    not just drift.
  - v6: external review pass 5 (post-Bundle-K audit). 11 new issues:
    F12 (parse NameError 광고 기능 사망), F13 (sk-leak이 정상 path 아닌
    FO만 측정), F14 (cache-balance step 잘못된 path로 warm), F15
    (shared_cflags silent override), F16 (seed=0 silent swap), T12
    (subprocess timeout 무방어 4곳), T13 (T11 plumbing 미완성), T14
    (pqc_mlkem768 yaml -fno-lto 누락), T15 (upper_crop sort 중복),
    T16 (FRAME_RE partial accuracy), T17 (coverage probe -D 누락).
    리뷰어가 던진 12 항목 중 1개(yaml=shell)는 이미 T4 mitigation 있음.
  - v7: internal LLM-typical bug hunt (post-impl audit). 7 new issues:
    F17 (model_copy(update=) 재검증 안 함 → T8 cap CLI 우회 🚨),
    F18 (KAT regex `re.search` anywhere match → false PASS 🚨),
    T18 (subprocess `text=True` errors=replace 7군데 누락),
    T19 (harness_{name}.c TOCTOU race),
    T20 (F6 probe C-source injection T7 follow-up surface),
    T21 (Path.read/write_text 인코딩 미지정 → Windows 깨짐),
    T22 (dudect summary table ERROR row가 진짜 측정처럼 보임).
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

**Status: RESOLVED in Bundle E-2.** `_do_ct` now returns per-harness
status; valgrind returncode∉{0, 99} OR missing log → status="ERROR" +
continue. ERROR flows through `_compute_verdicts` → verdict.combine()
→ `Verdict.INCONCLUSIVE` (matrix entries added in E-1). `ctkat ct`
subcommand also exits 2 on ct ERROR.

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

**Status: RESOLVED in Bundle E-2.** New `ct.require_sentinel: bool` +
`ct.sentinel_pattern: str` yaml fields. When `require_sentinel=true` on
manual-binary harnesses, `_do_ct` checks the binary's stdout for the
pattern (default `CTKAT-HARNESS-RAN:\s*(\S+)`); missing → status=ERROR
→ INCONCLUSIVE. Template-mode harnesses skip the check. Backward-compat:
default `false`, plus a per-run note when manual harnesses are present.
examples/toy_password updated with the sentinel convention.

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

**Status**: **Criteria #1+#2 RESOLVED in Bundle E-3, #3 RESOLVED in
Bundle I.** `ctkat run` now (1) prints both stages' cflags side-by-side
at the top of the run with a yellow `[CTKAT] WARNING: ... different
cflags` line when they differ, (2) supports yaml top-level
`shared_cflags: List[str]` that auto-propagates to both stages unless
per-stage `ct.cflags` / `dudect.compiler.cflags` are explicitly set.
README §"컴파일 옵션 비대칭 경고" documents the trap.
**Open**: #4 (multi-target matrix — yaml declares multiple cflag combos
and runs ct+dudect for each, producing a verdict-per-combo matrix).
Explicitly "out of scope for immediate fix" per spec — would require a
new CSV schema and matrix-aware verdict computation; deferred indefinitely.

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

### F12: `ctkat parse` subcommand dies with NameError (광고된 기능 사망) 🚨

**Status: RESOLVED in Bundle L.** `cli.py:1223` 호출자를
`parse_valgrind_log_with_stats(text)`로 교체 (T3 정신과 통일, dropped 카운트
>50일 때 dim note 출력). `tests/test_cli.py::test_parse_subcommand_runs_on_valid_log`
smoke test 박혀 회귀 방어.

- **Where**: `ctkat/cli.py:54` import (`parse_valgrind_log_with_stats`만),
  `:1223` 호출 (`parse_valgrind_log`).
- **Symptom**: `python -m ctkat parse /tmp/v.log` →
  `NameError: name 'parse_valgrind_log' is not defined`. README:511에
  "Valgrind 로그 단일 파일 파싱 (디버깅용)"으로 광고된 user-facing 기능
  완전 사망.
- **History**: Bundle I (T3) 작업 중 `parse_valgrind_log` 호출을
  `parse_valgrind_log_with_stats`로 교체했으나 cli.py:1223 (parse 서브
  커맨드 본체)는 갱신 빼먹음. import도 새 함수만 가져옴. 기존 함수는
  valgrind_parser.py에 여전히 존재하므로 import만 추가해도 fix됨.
- **Test coverage**: 0. `tests/test_cli.py`에 parse 서브커맨드 smoke
  test 없어서 pytest 228 통과해도 잡히지 않음.
- **Why solve**: 광고된 user-facing 기능. 이전 Bundle 작업의 회귀
  방어가 충분치 않았음을 드러냄.
- **Acceptance criteria**:
  1. cli.py:54 import에 `parse_valgrind_log` 추가 (1-line fix), 또는
     :1223 호출을 `parse_valgrind_log_with_stats`로 교체 후 unpacking.
  2. `tests/test_cli.py`에 `test_parse_subcommand_runs_on_valid_log`
     smoke test 추가.
- **Related**: T3 (parse_valgrind_log_with_stats 도입), T10 (CSV snapshot
  같은 회귀 방어 — 여기에도 서브커맨드 smoke test가 필요했음을 시사).
- **Suggested bundle**: 즉시 hot-fix.

### F13: sk-leak 모드가 정상 dec 경로 대신 FO rejection만 측정 🚨

**Status: OPEN (v6 external review pass 5).**

- **Where**: `ctkat/templates/timing_kem.c.j2:230-233` warmup,
  `:251-255` measurement (sk-leak brunch).
- **Symptom**: sk-leak brunch에서 양 class 모두 `rand_bytes(ct,
  sizeof(ct))`로 ct 채움 → 거의 확실히 invalid → `crypto_kem_dec()`이
  FO fallback path 진입. README §"KEM leak axes"는 "sk-content
  dependent timing"이라 광고하지만 실제 측정 path는 FO rejection.
- **Why solve**: 광고와 실측 불일치. PQClean ML-KEM-768 검증으로
  sk-leak 돌리는 README 자랑은 사실 rejection path만 두들겨본 결과.
  정상 dec path의 sk-leak은 이 도구로 못 잡음.
  - sk-leak (현재): invalid ct × (sk_fixed vs sk_random) → FO path × sk-varies
  - ct-leak: valid ct (enc로 생성) → 정상 path × ct-varies
  - fo-leak: valid (cls 0) vs invalid (cls 1) → 두 path 비교 × sk_fixed
  - 즉 현 sk-leak이 사실상 "fo with sk-varies"의 의미.
- **Acceptance criteria**:
  1. sk-leak brunch에서 양 class 모두 valid ct 사용:
     - cls=0: `crypto_kem_enc(ct, ss, pk_fixed)` per iter → 정상 path
     - cls=1: keypair → `enc(ct, ss, pk_random)` per iter → 정상 path
  2. README §"KEM leak axes"에 sk-leak 측정 path가 정상 dec임을
     명시. Bundle K가 fo 모드 추가했을 때 sk-leak의 의미를 재점검
     했어야 했다고 review log에 인정.
  3. test_timing_harness: sk-leak가 양 class에서 `crypto_kem_enc(`
     호출하는지 검증 (random ct가 아니라).
- **Related**: U2 #1 / Bundle K (fo-leak mode 도입 — 그때 sk-leak도
  재정렬했어야 함), F14 (cache balance step도 같은 문제).
- **Suggested bundle**: 별도 fix bundle. F14와 같은 호흡.

### F14: emit_kem_measurement cache-balance가 ct-leak/fo-leak에서 실제 balance 안 됨 🟡

**Status: OPEN (v6 external review pass 5).**

- **Where**: `ctkat/templates/timing_kem.c.j2:10-11`
  (`emit_kem_measurement` Bundle H2/T1 매크로).
- **Symptom**: 매크로의 warm step은 `rand_bytes(ct_warm, ...)` +
  `crypto_kem_dec(ss, ct_warm, sk_expr)` → ct_warm은 random → invalid →
  FO path로 warm.
  - sk-leak (F13 fix 전): warm/timed 둘 다 invalid ct (FO). 균형 OK
    이지만 측정 의미 자체가 정상 path 아님 (F13 본문 참조).
  - ct-leak: warm는 invalid (FO path)이지만 timed는 valid ct (정상
    path). cache state mismatch → 매크로 주석의 "cache state
    normalized to just-ran-dec"가 거짓말 (실제로는 just-ran-FO-dec).
  - fo-leak: warm는 invalid (FO), timed는 cls 0 valid (정상), cls 1
    invalid (FO). class 0의 정상 path 측정이 FO cache state에서 시작.
- **Why solve**: 매크로 주석 vs 실측 불일치. 양 class 모두 동일하게
  잘못된 거라 통계적 bias는 일부 상쇄되지만 "cache balanced" 광고는
  false.
- **Acceptance criteria**:
  1. warm dec도 mode별 valid/invalid 분기 — 또는 매크로 시그니처에
     `warm_ct_expr` 인자 추가해서 caller가 path 선택.
     - sk-leak (F13 fix 후): warm = valid (정상 path와 matching)
     - ct-leak: warm = valid
     - fo-leak: warm = mixed (class-aware) 또는 매크로 호출 두 번 분리
  2. README의 cache-balance 단락 갱신 — 실측과 일치.
  3. test_timing_harness: 매크로 호출 시 warm ct가 의도된 path인지
     검증.
- **Related**: F13 (sk-leak이 정상 vs FO 어디 측정하는지의 근본).
- **Suggested bundle**: F13과 같은 호흡.

### F15: `shared_cflags`가 사용자 명시 cflags를 값 동등성으로 silent override 🚨

**Status: RESOLVED in Bundle L.** `_apply_shared_cflags`가
`self.ct.cflags == _default_cflags()` (값 비교) → `"cflags" not in
self.ct.model_fields_set` (input-set 비교) 으로 교체. 주석도 거짓말이었던
"object identity" 표현 폐기. 사용자가 default와 동일 cflags 명시한 경우
의도 유지 회귀 테스트 `test_shared_cflags_yields_when_user_explicit_matches_default`
박힘.

- **Where**: `ctkat/config.py:415-428` `_apply_shared_cflags` validator.
- **Symptom**: 주석은 "Detect by comparing object identity to the
  default-factory result"라 적혀있지만 실제로는 `==` 값 비교. 사용자가
  우연히 default와 같은 cflags를 yaml에 명시하면 → shared_cflags가
  silent로 override.
  ```yaml
  shared_cflags: ['-O3']
  ct:
    cflags: ['-O0', '-g', '-fno-inline', '-fno-omit-frame-pointer']
    # ↑ 사용자가 명시했지만 default와 동일 → shared_cflags가 override함
  ```
  → 결과 `ct.cflags = ['-O3']` (사용자 의도 증발).
- **Why solve**: 디버깅 지옥. 사용자가 명시한 cflags가 왜 무시되는지
  추적 어려움. yaml 명시가 항상 wins라는 원칙 위반.
- **Acceptance criteria**:
  1. pydantic v2 `model_fields_set` 사용:
     ```python
     if self.ct is not None and "cflags" not in self.ct.model_fields_set:
         self.ct.cflags = list(self.shared_cflags)
     ```
     이러면 사용자가 명시한 경우 (값이 default와 같아도) override 안 됨.
  2. test_config: 사용자가 default와 동일한 cflags 명시 → shared_cflags
     무시 케이스 회귀 테스트.
- **Related**: F9 #3 (shared_cflags 도입 시 정확성 검증 부족).
- **Suggested bundle**: 1-line pydantic fix.

### F16: `dudect.seed: 0` → 로그는 0x0, C는 0xC0FFEE swap (재현성 거짓말) 🚨

**Status: RESOLVED in Bundle L.** `DudectConfig.seed`와 `CtConfig.seed`
둘 다 `Field(gt=0)` 적용 — yaml에 `seed: 0` 박으면 config 로드 단계에서
ValidationError. Optional[int] (None=랜덤 픽) 경로는 그대로 동작.
README §재현성에 "seed=0 금지 — xorshift stuck 회피용" 단락 추가.
회귀 테스트 `test_dudect_seed_zero_rejected` / `test_dudect_seed_null_still_allowed`
/ `test_ct_seed_zero_rejected` 박힘.

- **Where**:
  - `ctkat/cli.py:636` `effective_seed = dud.seed if dud.seed is not
    None else secrets.randbits(63)` — `None`만 random 처리.
  - `:637` `console.print(f"[dim]dudect seed = 0x{effective_seed:X}[/]")`
    → 0x0 출력.
  - `ctkat/templates/timing_kem.c.j2:75` `prng_state = seed ? seed
    : 0xC0FFEEULL` — C에서 0이면 fallback.
  - `ctkat/templates/timing_generic.c.j2:45` 동일 패턴.
- **Symptom**: 사용자가 `seed: 0` 박으면 Python은 0 그대로 받아 로그에
  `0x0` 출력, C 코드는 swap으로 `0xC0FFEE` 사용. 사용자는 seed=0으로
  돌렸다고 믿지만 실제로는 0xC0FFEE — 두 다른 yaml run의 결과가 똑같이
  나와도 (둘 다 swap되어 0xC0FFEE 사용) 사용자는 영문 모름.
- **Why solve**: README §"재현성 (seed)"의 광고와 실제 동작 불일치.
  xorshift는 seed=0이면 영구 stuck이라 swap 자체는 의미적으로 필요한
  방어 — 다만 invisible해서 거짓말 됨.
- **Acceptance criteria**:
  1. Python에서 seed=0 명시적 거부: `Field(default=0xC0FFEE)` +
     `model_validator`로 `seed=0` 거부 (또는 `gt=0` 제약).
  2. README §"재현성 (seed)"에 "seed=0 금지 — xorshift stuck 회피용"
     명시.
  3. test_config: seed=0 yaml → ValidationError.
- **Related**: R1, R3 (재현성 family).
- **Suggested bundle**: 1-line pydantic validator + README 갱신.

### F17: `dudect --measurements N` CLI override가 T8 cap 그대로 뚫음 (pydantic `model_copy` 재검증 안 함) 🚨

**Status: RESOLVED in Bundle L.** `cli.py:843`을
`dud.model_copy(update=updates)` → `DudectConfig.model_validate({**dud.model_dump(),
**updates})` 로 교체. full validation 거치므로 T8 `Field(le=10_000_000)` 와
F16 `gt=0` 모두 CLI 경로에서도 enforce됨. 회귀 테스트
`test_dudect_cli_measurements_override_rejects_above_cap` 박힘.

- **Where**: `ctkat/cli.py:835-843` (`dudect` subcommand override 로직),
  `ctkat/config.py:343-345` (T8 Field bounds).
- **뭐가 좆되냐**: T8에서 `measurements: int = Field(default=100_000, ge=100,
  le=10_000_000)` 박아놨는데, CLI 옵션으로 우회 가능:
  ```bash
  python -m ctkat dudect -c x.yaml --measurements 100000000  # → 800MB BSS, OOM
  ```
  cli.py L842는 `dud = dud.model_copy(update=updates)`로 갱신하는데
  pydantic v2의 `model_copy(update=...)`는 **재검증 안 함** (공식 문서대로).
  직접 검증:
  ```python
  >>> M(x=Field(default=10, ge=0, le=100)).model_copy(update={'x': 99999}).x
  99999  # ㅋㅋ pydantic이 아무 말도 안 함
  ```
  T8 acceptance criteria의 "config 로드 단계에서 거부"라는 약속이 CLI
  경로에서 전부 무력화. 동일 패턴으로 `--seed 0`도 F16 미래 validator
  (seed=0 거부) 도입돼도 뚫림.
- **LLM이 자주 싸는 패턴 사유**: pydantic v2의 `model_copy(update=)` 가
  `model_validate(update=)` 처럼 보이지만 둘은 완전히 다른 함수임.
  LLM이 "그냥 copy하고 필드 갈아끼우기"라는 의도로 짜는데, 검증
  contract가 사라지는 줄 모름. v1 대비 v2에서 이 동작이 미묘해진 것도
  요인.
- **Why solve**: T8/F16의 방어선이 yaml 입력에만 걸려있고 CLI 입력은
  free pass — known_issues 문서는 "config 로드 단계에서 거부"라 적었는데
  거짓말. CI에서 `--measurements` 박는 사용자가 의도치 않은 cap 우회.
- **Acceptance criteria**:
  1. cli.py L842를 `dud = DudectConfig.model_validate({**dud.model_dump(),
     **updates})` 로 교체. 또는 `DudectConfig(**{**dud.model_dump(),
     **updates})`. 둘 다 full validation 거침.
  2. test_cli: `dudect --measurements 100000000` → `ValidationError` 또는
     명확한 exit 메시지 (typer가 입력단에서 잡는 게 더 정직).
  3. typer 옵션 레벨에서도 `min=100, max=10_000_000` 추가하면 double-belt
     (typer가 먼저 잡음).
- **Related**: T8 (Field bounds 자체), F16 (seed validator도 같이 우회됨),
  F15 (`shared_cflags` validator 정확성 — 비슷한 family).
- **Suggested bundle**: 1-line 교체 fix.

### F18: KAT `expected_pattern` 이 `re.search` (anywhere match) → stdout 오류 메시지 한 줄에 "PASSED: N" 박혀있으면 false PASS 🚨

**Status: RESOLVED in Bundle L.** default pattern을
`r"PASSED:?\s*(\d+)"` → `r"^PASSED:?\s*(\d+)(?:\s|$)"`로 앵커링하고
cli `_do_kat`의 `re.search` 호출에 `re.MULTILINE` 플래그 전달. 라인
시작이 `PASSED`인 standalone 요약 라인만 매치 → 에러 메시지 중간에
`PASSED: 100` 박혀도 false PASS 안 됨. PQClean `PASSED: 100 tests`
형식은 그대로 매치 (trailing `(?:\s|$)`). 회귀 테스트
`test_kat_anchored_pattern_rejects_substring_in_error_line` /
`test_kat_anchored_pattern_still_matches_pqclean_style_line` 박힘.

- **Where**: `ctkat/cli.py:169` (`m = re.search(cfg.kat.expected_pattern,
  r.stdout or "")`), `ctkat/config.py:99` (default
  `r"PASSED:?\s*(\d+)"`).
- **뭐가 좆되냐**: KAT runner가 진짜로는 죽었는데 stderr가 stdout으로
  redirect돼서 다음 같은 한 줄 박힌 경우 — `re.search`는 stdout 어디든
  매치 잡음:
  ```
  ERROR: vector 50 differs from expected. Test summary: PASSED: 100, FAILED: 0
                                                       ^^^^^^^^^^^^^^^^^
                                                       이거 match → count=100 → KAT PASS
  ```
  exit code도 0이면 (KAT runner가 마지막에 cleanup하면서 rc=0 반환) F1
  acceptance가 "count >= expected_min" 통과 시켜 PASS. 광고된 F1 fix가
  허울뿐.
- **LLM이 자주 싸는 패턴 사유**: `re.search` vs `re.match` vs `re.fullmatch`
  헷갈리기. LLM이 "stdout에서 패턴 찾기"라고 생각하면 거의 항상
  `re.search` 박는데, 보안 컨텍스트에서는 anchored match가 default여야
  함. 게다가 default pattern이 `PASSED:?\s*(\d+)` 라 `^`/`$` 앵커 없어서
  더더욱 안전망 없음.
- **Why solve**: F1의 "no-op runner도 PASS 박는다"를 해결한다고
  Bundle E-1에서 fix했는데, runner가 *진짜로 fail하면서 동시에 PASSED
  단어 어딘가에 박는* 경우는 여전히 뚫림. ML-KEM 같은 PQClean 출력은
  `PASSED: 100` 형식인데, 같은 패턴이 진행률 로그나 에러 메시지에도
  쉽게 등장할 수 있음.
- **Acceptance criteria**:
  1. default `expected_pattern`을 `re.MULTILINE` 가정 + 라인 앵커 추가:
     `r"^PASSED:?\s*(\d+)\s*$"` (`re.MULTILINE` 플래그도 함께).
  2. 또는 KAT runner의 *마지막* 라인만 매치 (stdout splitlines 후 끝에서
     앞으로 search). PQClean도 보통 summary가 마지막에 옴.
  3. README §"KAT pattern" 에 anchor 권장.
  4. test_cli: stdout이 `"ERROR foo: PASSED: 100 baz\n"` 이고 exit 0인
     KAT runner → PASS가 *아니라* FAIL.
- **Related**: F1 (Bundle E-1에서 fix됐다고 주장한 베이스), T4 (사용자
  yaml regex injection).
- **Suggested bundle**: default pattern + multiline 플래그 갱신 — 2줄 fix.

### F4: dudect zero-cycle filter ignores class balance 🟡

**Status: RESOLVED in Bundle F (with S2).** `parse_timing_csv` now tracks
`dropped_zero_n0` / `dropped_zero_n1` separately and fires a dedicated
yellow warning when one class loses ≥5% AND the per-class gap is ≥5%
(symmetric drops stay quiet — that's noise, not bias). Per-class counts
also surface in `TimingSamples` and propagate to CSV columns 19-20 (S1).

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

**Status: RESOLVED in Bundle F.** New `ctkat/coverage_check.py` module
emits a sentinel C program that evaluates `sum(secret_regions.length)`
and `{prefix}CRYPTO_SECRETKEYBYTES` under the same compiler+headers the
real harness uses, parses the printed integers, and warns when coverage
< 50%. kem/sign template harnesses only (no canonical "sk" notion in
generic). Compile/exec/parse failures are non-blocking — F6 is a
diagnostic, not a gate.

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

**Status: FULLY RESOLVED.**
- Option A (docs caveat) in Quick Docs commit (pre-Bundle-E warmup).
- **Option B (`randombytes` weak-symbol interpose) in Bundle J.** timing_kem
  하네스가 자기 `randombytes(uint8_t *buf, size_t len)`을 weak symbol로
  emit (xorshift PRNG로 buf 채움). 사용자가 yaml sources에서 PQClean의
  `common/randombytes.c`를 빼면 우리 weak이 유일 정의 → deterministic.
  안 빼면 strong이 win (legacy 동작 보존) → backward-compat.
- GCC/Clang weak attribute 사용. Windows MSVC는 다른 시맨틱이라 현재
  미지원 (U3 caveat과 동일).
- T1 (template dedup) Bundle H2에서 이미 끝나 있어서 매크로 한 곳에
  영향 미치는 일 없이 RNG 블록 추가만으로 완료.

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

**Status: RESOLVED in Bundle G.** New `dudect.bonferroni_correct: bool`
yaml field. When true, `_do_dudect` scales both thresholds by
`sqrt(len(CROP_PERCENTILES))` ≈ 2.236 before passing them to
`welch_with_cropping` / `welch_t_test` / `batch_t_scores`. README adds
a multi-cutoff calibration guide. A `test_multi_cutoff_under_null_typeI_rate_pinned`
synthetic test on 200 IID-noise trials pins the rate so future cropping
changes are visible regressions.
Normality assumption side stays partially open — documented as a caveat
in README but no kurtosis-aware adjustment yet.

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

**Status: RESOLVED in Bundle H1.** README §"시스템 노이즈와 \|t\| 변동"
신설: 같은 yaml+seed라도 런마다 ±10-20% 변동, status와 order-of-magnitude
만 비교 권장. PQClean KEM 하니스는 R1 Option A의 추가적인 비재현성 cross-ref.

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

**Status: RESOLVED in Bundle F.** `dudect_summary.csv` now has columns
18 (`raw_n_total`), 19 (`dropped_zero_n0`), 20 (`dropped_zero_n1`). Users
can reconstruct the full filter pipeline from the CSV alone:
`n0 = raw_n0 - dropped_zero_n0 - cropping`. ERROR-status rows have all
three at 0 (default-constructed TimingSamples). awk `$11=status` position
unchanged.

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

**Status: RESOLVED in Bundle F (with F4).** Per-class warning fires when
per-class drop rate exceeds 5% AND the gap between classes is > 5%.
Message: "zero-cycle filter asymmetric — dropped X% of class-0 vs Y%
of class-1 samples. Surviving samples are likely a biased subset..."
See F4 for the logic-side write-up.

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

**Status: RESOLVED in Bundle G.** `WelchResult.cohens_d` field populated
by `welch_t_test` via `_cohens_d(n0, n1, m0, m1, v0, v1)` using the
pooled-SD formula `(m1-m0)/sqrt(((n0-1)*v0+(n1-1)*v1)/(n0+n1-2))`. Sign
preserved (+ means class 1 slower). Degenerate cases handled (0 when
pooled var=0 AND means equal, ±inf when pooled var=0 but means differ —
mirrors the t-score's inf convention). CSV col 21. README has Cohen 1988
interpretation guide.

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

**Status: RESOLVED across Bundle E-1 + Bundle F.** E-1 introduced
graceful per-harness skip (try/except → status=ERROR + continue instead
of raise) for all four uncaught dudect paths plus the "n0/n1 < 2" case.
Bundle F finalizes by verifying via tests that ERROR rows still appear
in `dudect_summary.csv` with their raw-count columns at 0 — previously-
completed harnesses' data is preserved end-to-end.

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

**Status: RESOLVED in Bundle H1.** README 상단에 "PASS ≠ constant-time"
박스 추가, §Limitations에 안 보는 layer 목록 (power side-channel, EM,
fault injection, formal verification, KyberSlash-style adversarial) 명시.

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

**Status: FULLY RESOLVED.**
- Interim doc note in Bundle H1 (FO-fallback 미커버 명시).
- **Primary fix (U2 #1) in Bundle K.** `leak_target: fo` 신규 모드 추가.
  timing_kem.c.j2의 세 번째 brunch — class 0 valid ct (enc per-iter),
  class 1 random/invalid ct (FO fallback 강제). 같은 sk_fixed 위에서
  dec timing 비교. T1 dedup된 `emit_kem_measurement` 매크로 재사용으로
  깔끔하게 추가. R1 Option B와 결합하면 결정론적 FO-leak 검출도 가능.
- 3 leak axes (sk/ct/fo)는 직교. 한 KEM 종합 검사 시 3 harness 정의.

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

**Status: RESOLVED in Bundle H1.** README clock 표에 footnote 추가:
"Windows MSVC 미지원, MinGW gcc 또는 WSL2 + Linux gcc 권장". 미검증
경로를 사용자에게 명시.

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

**Status: RESOLVED in Bundle H1.** README §"함수 속도 범위" 신설:
~100ns ~ ~1ms 권장, 너무 빠른 함수는 batch wrapping, 너무 느린 함수는
`dudect.timeout` 늘리기 가이드.

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

**Status: RESOLVED in Bundle H1.** `docs/tutorial.md` 신설 — 사용자가
함수 하나에 dudect 거는 yaml을 30라인으로 따라가는 워크스루. WARNING
대응 5단계와 자주 빠지는 함정 (secret_regions 부분 검사, PQClean 재현성,
manual binary sentinel) 정리.

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

**Status: Option A RESOLVED in Bundle I.** `Verdict.LOW_RISK` renamed to
`Verdict.STRUCTURAL_LEAK` — string value 그대로, enum 이름 + verdict CSV
값 둘 다 변경. README 매트릭스 + tutorial + 기존 caveat 단락 일괄 갱신.
External awk scripts using literal `"LOW_RISK"` need update (intentional
break — Option A의 본질). Option B (caveat docs) already done in H1.

**Status: Option B RESOLVED in Bundle H1.** README verdict 매트릭스 옆에
"LOW_RISK는 무시해도 되는 게 아니다" 단락 추가 — Valgrind가 구조적으로
confirmed한 leak이 있고 dudect만 못 본 상태임을 명시. Option A (라벨을
`STRUCTURAL_LEAK`으로 rename)은 verdict CSV consumers 깨질 수 있어 별도
follow-up으로 남김.

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

**Status: RESOLVED in Bundle H2.** `timing_kem.c.j2` 상단에
`emit_kem_measurement(sk_expr, ct_expr)` Jinja2 매크로 신설.
양쪽 brunch (sk-leak / ct-leak)의 "warm dec + timed region + cycles
저장" 7-line 블록이 매크로 호출 1라인으로 줄어듦. R1 Option B
(randombytes interpose) 적용 시 이 매크로 한 군데에 박으면 양쪽
brunch가 자동으로 받음.

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

**Status: RESOLVED in Bundle H2.** Pydantic `Field(ge=, le=)` 박힘:
`measurements: 100..10_000_000`, `warmup: 0..10_000_000`,
`batches: 1..1_000`. 사용자가 zero 추가 typo로 800MB BSS 만들고 OOM
당하는 경로를 config 로드 단계에서 거부.

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

**Status: RESOLVED in Bundle H2.** `_MIN_SIGNALS=2` 도입. 한 candidate
파일에서만 "QEMU" 발견된 경우는 false-positive로 보고 native 판정.
Docker-on-M1처럼 ≥3 candidates에 박혀있는 진짜 emulation은 그대로
검출. monkeypatch 기반 4개 단위 테스트 (0/1/2/no-match) 신설.

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

**Status: RESOLVED in Bundle H2.** `test_dudect_summary_csv_header_snapshot`
신설. 전체 헤더 한 줄 (`project,harness,n0,...cohens_d`)을 literal로
pin. 새 컬럼 추가는 이 테스트를 명시적으로 갱신해야 통과 — silent
reorder가 awk-by-position 컨슈머(`scripts/run_phase4.sh`)를 깨지 않음.

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

**Status: RESOLVED in Bundle H2.** 신규 `_DECL_LOOSE_RE` — nested paren
1단계 허용. `parse_functions_with_stats(text)` API가 추가되어
`(sigs, skipped_count)` 반환. function pointer 같은 케이스가 silent
미스 → 카운트 가능. 기존 `parse_functions()` API는 시그니처 그대로
유지 (backward-compat). 정규식 자체 보강은 안 했음 — false-positive
키워드 필터링 비용 더 큼.

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

**Status: RESOLVED (primary) in Bundle H2.** Most important slice —
`HarnessConfig.name` / `DudectHarnessConfig.name`이 `^[A-Za-z0-9_-]+$`
패턴으로 제한되어 `../../etc/passwd` 같은 path traversal 또는 shell
metacharacter 박힌 이름을 config 로드 단계에서 거부함. `harness_generator.py:93`의
`{generated_dir}/harness_{name}.c` 인터폴레이션이 이제 안전. function /
return_type / prefix / args 같은 Jinja-context 식별자 추가 패턴 제한은
follow-up (compile fail이 일종의 보호).

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

**Status: RESOLVED in Bundle I.** Option (2) (yaml override) 채택.
`parse_valgrind_log(text, lookup_patterns=...)` 시그니처 확장 + 신규
yaml 필드 `ct.lookup_function_patterns: Optional[List[str]]`. 사용자가
`verify_table_size` 같은 false-positive 함수명에 시달리면 빈 리스트나
타이트한 패턴으로 override 가능. Option (1) (더 정밀한 휴리스틱)은
별도 follow-up — 현 휴리스틱이 false-positive 선호 정책에 부합하니
포기하지 않음.

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

**Status: RESOLVED in Bundle I.** `parse_valgrind_log_with_stats(text)
→ (findings, dropped_count)` 신규 API. cli `_do_ct`가 dropped > 50일 때
dim note 출력 — Valgrind 버전 업그레이드 후 갑자기 dropped 폭증하면
parser whitelist 갱신 신호. 기존 `parse_valgrind_log()` API 시그니처는
보존 (backward-compat).

- **Where**: `ctkat/valgrind_parser.py` (the dispatch over message types).
- **Symptom**: Messages whose Valgrind error type isn't in the parser's
  recognized set return None and are dropped. Valgrind version upgrade
  or locale change can break the recognized set silently.
- **Why solve**: Future regressions.
- **Acceptance criteria**: Emit a debug-level log line (or summary
  count at end) listing how many messages were dropped as unrecognized.
- **Suggested bundle**: TBD.

### T4: shell=True in user-yaml commands 🟢

**Status: RESOLVED in Bundle H2.** `BuildConfig.argv: List[str]` +
`KatConfig.argv: List[str]` 옵션 추가. 둘 중 정확히 하나 (command 또는
argv) 박혀야 함 (validator로 강제). argv 박으면 `subprocess.run`이
shell=False로 실행되어 yaml의 metacharacter 노출 제거. command 경로는
backward-compat 그대로 유지. builder.py에 `run_argv` + `run_step` 헬퍼
신설.

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

**Status: RESOLVED in Bundle H2.** Bundle E-3 이후 각 Bundle 작업 동안
TaskCreate/Update를 적극 사용, 매 Bundle commit 끝에 모든 task가
`completed` 상태로 명시됨. 운영 정책 — 다음 작업 시작 전에 stale
completed task를 그대로 두지 말고 새 Bundle용 task를 새로 생성하는
패턴이 자리잡힘.

### T12: subprocess 호출 4곳에 timeout 무방어 (CI hang 위험) 🚨→🟡

**Status: OPEN (v6 external review pass 5).**

- **Where**: 5개 subprocess.run() call site 중 `dudect_runner.py`만 T6
  에서 timeout 받음. 나머지는 무방어:
  - `ctkat/builder.py:20` `run_shell`
  - `ctkat/builder.py:42` `run_argv`
  - `ctkat/valgrind_runner.py:28` `run_valgrind`
  - `ctkat/harness_generator.py:67` `compile_harness`
  - `ctkat/timing_harness_generator.py:72` `_compile`
- **Symptom**: 사용자 build 스크립트에 `sleep infinity` 박혀있거나
  gcc/valgrind가 무한 루프 들어가면 ctkat 그대로 멈춤. CI에서 hang이
  떠도 진단 없음.
- **Why solve**: T6가 timing harness만 막아놨는데 다른 subprocess도
  똑같이 필요. CI 환경 안전성.
- **Acceptance criteria**:
  1. `BuildConfig.timeout`, `KatConfig.timeout` yaml 필드 (default 600).
  2. `CtConfig.compile_timeout`, `CtConfig.valgrind_timeout` 필드 (default 600).
  3. 각 subprocess.run에 timeout 전달, `TimeoutExpired` catch → 명확한
     ERROR 메시지 (build/KAT은 Exit(1) 또는 ERROR status, ct/dudect은
     기존 INCONCLUSIVE 흐름).
- **Related**: T6 (dudect timing timeout만 처리).
- **Suggested bundle**: timeout coverage bundle.

### T13: `parse_functions_with_stats` skip count → CLI에서 안 씀 (T11 미완) 🟢

**Status: OPEN (v6 external review pass 5).**

- **Where**: `ctkat/header_parser.py:158 parse_functions_with_stats`,
  `cli.py:1195 parse_header_file(h)` 호출.
- **Symptom**: T11에서 함수 포인터 등 strict regex가 놓친 선언 개수
  추적하는 helper를 만들어놨는데, cli.py infer 서브커맨드는
  `parse_header_file(h)`만 호출 — list-only 반환, skip count 무시.
  사용자에게 "skipped N declarations" 알림 안 뜸.
- **Why solve**: T11의 가치가 plumbing 미완으로 누수. infer 결과를
  신뢰하는 사용자가 함수 포인터 누락 모름.
- **Acceptance criteria**:
  1. `parse_header_file_with_stats` 신규 wrapper 또는 `parse_functions_with_stats`
     direct 호출.
  2. cli infer 서브: skipped > 0이면 console에 dim note 출력.
- **Related**: T11 (parser stats 도입).
- **Suggested bundle**: 1-line plumbing fix.

### T14: `examples/pqc_mlkem768/ctkat.yaml`에서 `-fno-lto` 누락 🟢

**Status: RESOLVED in Bundle L.** 세 yaml (`examples/pqc_mlkem768/ctkat.yaml`,
`examples/toy_dudect/ctkat_dudect.yaml`, `examples/toy_dudect/ctkat_combined.yaml`)
의 dudect.compiler.cflags에 `-fno-lto` 추가. 추가로
`test_example_yamls_have_fno_lto_when_overriding_dudect_cflags` lint test
박혀 — 앞으로 example yaml이 dudect cflags override 하면서 `-fno-lto`
빠뜨리면 CI에서 잡힘.

- **Where**: `examples/pqc_mlkem768/ctkat.yaml` dudect.compiler.cflags.
- **Symptom**: yaml cflags가 `[-O2, -g, -fno-omit-frame-pointer]` —
  `-fno-lto` 빠짐. dudect 기본 cflags 정의(`config.py:_default_dudect_cflags`)는
  `-fno-lto` 포함. README §"dudect 측정 강화"는 "LTO 켜면 컴파일러가
  함수 elide" 경고. yaml에서 사용자 정의 cflags가 default override
  하면서 critical flag 빼먹음.
- **Why solve**: gcc default LTO off라 운 좋게 안 터지지만 사용자
  환경에 `CFLAGS=-flto` 박혀있으면 측정 silent하게 망함.
- **Acceptance criteria**:
  1. yaml dudect.compiler.cflags에 `-fno-lto` 추가.
  2. (선택) examples lint test — dudect cflags가 critical flags
     (-fno-lto, -fno-omit-frame-pointer) 포함하는지 검증.
- **Related**: F9 (cflags asymmetry / banner).
- **Suggested bundle**: 1-line yaml fix.

### T15: `upper_crop`이 cutoff마다 sort 다시 함 🟢

**Status: OPEN (v6 external review pass 5).**

- **Where**: `ctkat/statistics.py:190 sorted(samples)` inside
  `upper_crop`. `welch_with_cropping`이 5 cutoff × 2 class = 10번 호출.
- **Symptom**: 매 호출마다 O(N log N) sort. 100k 측정이면 매번 ~1.5M
  비교. 성능만 영향, 정확성 OK.
- **Why solve**: 한 번 sort하고 cutoff별 prefix 슬라이스가 자연스러움.
  `welch_with_cropping`을 redesign하면 O(N log N) → O(N) per cutoff.
- **Acceptance criteria**:
  1. `welch_with_cropping`이 c0/c1 한 번씩만 sort → cutoff별로 prefix
     슬라이스 후 `welch_t_test` 호출.
  2. test_statistics: cutoff별 결과가 변하지 않는지 회귀 (정확성 동등).
- **Related**: R2 (calibration).
- **Suggested bundle**: 성능 최적화 — 낮은 우선순위.

### T16: `_FRAME_RE`가 `(in /lib/...)` 형식 location의 file:line 분리 못 함 🟢

**Status: OPEN (v6 external review pass 5, partial accuracy).**

- **Where**: `ctkat/valgrind_parser.py:47-49 _FRAME_RE`, `:50 _FILE_LINE_RE`.
- **Symptom (실측)**: `_FRAME_RE` 자체는 `(in /lib/...)` 형식도 match —
  function name까지 추출. 다만 `_FILE_LINE_RE` (`^(.+):(\d+)$`)는 `:`
  없어서 fail → frame.file/line = None.
- **External reviewer 표현**: "frame 인식 실패 → finding의 stack이
  비어버림". 실제로는 그 정도까지는 아님 (frame은 인식됨). 단 file:line
  loss로 stack trace가 빈약. **부분 정확**.
- **Why solve**: PQClean처럼 source-mapped binary는 무관하지만 외부
  shared lib에서 leak이 surfacing하면 file:line None으로 디버깅 단서
  줄어듦.
- **Acceptance criteria**:
  1. `_FILE_LINE_RE`에 "in <path>" 패턴 보강: file=path, line=None
     (현재와 동일 효과지만 명시적).
  2. 또는 frame metadata에 `is_binary_only: bool` 추가.
- **Related**: T2/T3 (parser hardening), T11 (parser regex보강 정책).
- **Suggested bundle**: parser polish — 낮은 우선순위.

### T18: subprocess `text=True` 가 `errors='replace'` 없음 → 하네스가 garbage 뱉으면 UnicodeDecodeError raw traceback 🟡

**Status: OPEN (v7 internal post-impl audit).**

- **Where**: 7개 call site 전부 동일 패턴:
  - `ctkat/builder.py:25` (`run_shell`)
  - `ctkat/builder.py:47` (`run_argv`)
  - `ctkat/valgrind_runner.py` (`run_valgrind`)
  - `ctkat/harness_generator.py:71` (`compile_harness`)
  - `ctkat/timing_harness_generator.py:73` (`_compile`)
  - `ctkat/dudect_runner.py:145` (`run_timing_harness`)
  - `ctkat/coverage_check.py:117, 137` (probe compile+exec)
  전부 `subprocess.run(..., text=True)`만 박고 `errors='replace'` 없음.
- **뭐가 좆되냐**: `text=True`는 locale.getpreferredencoding(False)
  (보통 utf-8) 로 decode. 하네스가 죽으면서 stdout/stderr에 garbage
  bytes 뱉으면 (segfault stack dump, `\xff\xfe` BOM, 깨진 multibyte
  중간 자름) Python이 `UnicodeDecodeError` 던지고 raw traceback 분출.
  T6 try/except이 잡는 건 `TimeoutExpired/RuntimeError/ValueError`만 —
  `UnicodeDecodeError`는 못 잡음 → fail-open 으로 죽기 직전까지 가다가
  마지막에 LLM이 자주 까먹는 예외로 사용자 console에 raw stack trace.
- **LLM이 자주 싸는 패턴 사유**: subprocess 핸들링에서 `text=True`만
  넣고 끝나는 게 typical AI-generated code. `errors=` 인자는 Python 3.6+
  에서 추가됐는데 LLM이 학습한 옛 코드는 모름. 보안 도구에서 이게
  특히 골때리는 게 — 분석 대상이 정의상 "이상하게 행동하는 코드"라
  garbage output 확률이 일반 도구보다 훨씬 높음.
- **Why solve**: T6의 "raw traceback 노출 금지" 약속이 7군데 중 6군데에서
  새는 거. ERROR status로 graceful flow 해야 할 시점에 Python 내부
  exception이 leak.
- **Acceptance criteria**:
  1. `text=True` → `text=True, errors='replace'` 일괄 교체 (또는
     `encoding='utf-8', errors='replace'`).
  2. test: 합성 하네스가 `printf("\xff\xfe garbage\n")` 후 exit 0 →
     ERROR status로 잡혀야 하고 traceback 노출 X.
  3. 헬퍼 wrapper 하나 만들어서 (`_run_text(...)`) 한 곳에서 정책 강제 —
     drift 방지.
- **Related**: T6 (try/except 정책), T12 (timeout 정책 — 같은 패밀리),
  F2/F5/T6 (graceful ERROR 약속).
- **Suggested bundle**: T12와 함께 묶어서 "subprocess hardening bundle".

### T19: `harness_{name}.c` 파일이 동일 yaml 두 ctkat 프로세스 동시 실행 시 race (TOCTOU) 🟢

**Status: OPEN (v7 internal post-impl audit).**

- **Where**: `ctkat/harness_generator.py:93-97` (`source_path = output_dir /
  f"harness_{name}.c"; ...; source_path.write_text(code)`),
  `ctkat/timing_harness_generator.py:96-100` 동일 패턴.
- **뭐가 좆되냐**: 동일 yaml에 대해 `ctkat run` 두 번 동시 실행 (CI 매트릭스,
  matrix 빌드에서 parallel jobs)하면 두 프로세스가 같은 `_generated/
  harness_foo.c` 에 write_text → 마지막 writer wins. 그 사이에 첫
  프로세스의 compile_harness가 source_path를 read하면 두 번째 writer가
  덮어쓴 *다른* 코드를 컴파일할 수 있음. Race condition. seed 같은 build
  컨텍스트가 두 yaml run에서 다르면 (e.g. --seed random) 하네스 두 개의
  통계가 섞임.
- **LLM이 자주 싸는 패턴 사유**: 파일 I/O 직렬화 가정. LLM이 "하나의
  프로세스 모델" 안에서 코드를 짜기 때문에 concurrent execution은
  거의 안 고려. `tempfile.NamedTemporaryFile` + atomic rename 패턴은
  명시적으로 요청하지 않으면 안 나옴.
- **Why solve**: 보통은 사용자가 ctkat 한 번에 한 yaml만 돌리니까 안
  걸리지만, CI matrix 빌드 (e.g. 같은 yaml × 다른 OS × 다른 seed)에서
  공유 workspace 쓰면 silent corruption. 디버깅 ㅈㄴ 어려움.
- **Acceptance criteria**:
  1. write_text → tempfile에 write 후 `Path.replace()` 로 atomic rename
     (POSIX rename은 atomic, Windows도 PathLike replace).
  2. 또는 generated_dir에 PID/seed 박은 서브디렉토리 만들어서 충돌 회피
     (`_generated/{pid}_{seed}/harness_*.c`). 단 cleanup 부담.
  3. README §"동시 실행 / CI matrix" caveat — minimum.
- **Related**: T5 (operational hygiene), F5 (manual binary 경로와 별개).
- **Suggested bundle**: 낮은 우선순위. README caveat이 minimum.

### T20: F6 coverage probe의 C source가 사용자 yaml 값 (`header`, `extra_headers`, `prefix`) 무검증 interpolate — T7 follow-up 못 잡은 surface 🟢

**Status: OPEN (v7 internal post-impl audit).**

- **Where**: `ctkat/coverage_check.py:67-80` (`_render_sentinel_c` —
  f-string으로 `#include "{header}"` 와 `{prefix}CRYPTO_SECRETKEYBYTES`
  박음).
- **뭐가 좆되냐**: yaml 사용자가 다음 같이 박으면:
  ```yaml
  ct:
    harnesses:
      - name: pwn
        template: kem
        header: 'foo.h"\n#include "/etc/passwd"\nint x=1; /*'
        prefix: 'KYBER_'
        secret_regions: [{offset: '0', length: '32'}]
  ```
  generate된 probe C가:
  ```c
  #include "foo.h"
  #include "/etc/passwd"
  int x=1; /*"
  ```
  T7은 `name` 만 regex 박았고 `header`/`prefix`/`extra_headers`는 follow-up
  으로 남겨놨는데, T20은 그 same family의 *coverage probe* 쪽 surface.
  컴파일 보통 fail (probe는 yellow note만 출력하고 silent skip)이지만
  shell-level abuse는 아니어도 *imported file contents가 probe binary에
  컴파일됨* → probe가 어쩌다 run 되면 사용자 의도와 다른 매크로 값이
  CTKAT-COVERAGE 출력에 박힐 수 있음.
- **LLM이 자주 싸는 패턴 사유**: 코드 생성 (codegen) 에서 f-string으로
  user input interpolate. shell injection은 LLM도 학습됐지만 *C source
  injection* 은 자주 놓침 — "어차피 compile fail이면 OK"라는 false
  confidence.
- **Why solve**: F6는 *diagnostic*이라 silent skip이 정책이긴 하지만,
  광범위한 user input → generated C 흐름의 일관성 정책이 없음. T7
  acceptance criteria의 "function/return_type/prefix 추가 패턴 제한"
  follow-up이 coverage_check까지 커버해야 함.
- **Acceptance criteria**:
  1. `prefix` 에 `^[A-Za-z_][A-Za-z0-9_]*$` 또는 빈 문자열 pydantic
     validator (T7 acceptance criterion #1과 동일).
  2. `header` / `extra_headers` 에 `^[A-Za-z0-9_./-]+$` 정도 — path
     traversal과 quote 차단.
  3. coverage_check도 같은 validator path 거치게 — probe 진입 전에 이미
     검증된 값만 들어옴.
- **Related**: T7 (validator follow-up family), F6 (probe 자체), F15
  (사용자 입력 정확성).
- **Suggested bundle**: T7 follow-up과 묶어서.

### T21: `Path.write_text` / `read_text` 인코딩 미지정 → Windows에서 cp1252 로 시도 → 깨짐 🟢

**Status: OPEN (v7 internal post-impl audit).**

- **Where**: 인코딩 미지정 read/write 다수:
  - `ctkat/harness_generator.py:97` (`source_path.write_text(code)`)
  - `ctkat/timing_harness_generator.py:100` (`source_path.write_text(code)`)
  - `ctkat/coverage_check.py:110` (`src_path.write_text(src)`)
  - `ctkat/cli.py:414, 1222` (valgrind log `read_text()`)
  - `ctkat/qemu_detect.py:49` (`path.read_text()`)
  - `ctkat/header_parser.py:216` (`path.read_text()`)
- **뭐가 좆되냐**: `Path.write_text/read_text`는 인코딩 미지정 시
  `locale.getpreferredencoding(False)` 따름. Linux는 보통 utf-8이라
  안 걸리지만 native Windows (WSL2 아님) 는 cp1252 default → 한국어
  주석 박힌 C 소스나 valgrind 로그의 UTF-8 stack 심볼 디코딩 깨짐.
  U3가 "Windows MSVC 미지원" 으로 caveat 박았지만 *gcc-on-Windows*
  (MinGW) 사용자한테는 여전히 enroll됨.
- **LLM이 자주 싸는 패턴 사유**: Path API의 편의 메서드 (`.read_text()`/
  `.write_text()`) 가 인코딩 인자 optional 이라 LLM이 거의 항상 생략.
  Python docs도 "default uses locale" 이라 명시는 하지만 LLM이
  copy-paste한 옛 stackoverflow 답변은 인자 누락 상태.
- **Why solve**: U3 캐비엇이 "MSVC 안 됨"만 다루는데 actual encoding
  문제는 컴파일러 선택과 무관. PEP 597 (`encoding=`) 도 PythonWarning
  으로 권장.
- **Acceptance criteria**:
  1. 모든 `read_text()`/`write_text()` 에 `encoding="utf-8"` 명시.
  2. read 쪽은 valgrind 로그 처럼 외부 출력은 `errors="replace"` 추가
     (T18과 같은 정책).
  3. Lint rule (e.g. ruff `PLW1514`) 추가해서 회귀 방지.
- **Related**: T18 (subprocess decoding 정책 — 같은 family), U3 (Windows
  caveat).
- **Suggested bundle**: T18과 함께 — "encoding/decoding hygiene bundle".

### T22: dudect summary table이 ERROR row를 `n0=0, mean=0.0` 으로 표시 — 진짜 측정처럼 보임 🟢

**Status: OPEN (v7 internal post-impl audit).**

- **Where**: `ctkat/cli.py:785-805` (`_print_dudect_summary` loop),
  `ctkat/cli.py:519-524` (`_error_welch` — `n0=0, mean0=0.0, ...`).
- **뭐가 좆되냐**: 하네스 timeout/crash로 `_error_welch()` 반환된 ERROR
  row 가 dudect summary table 에 그대로 `mean0=0.0 mean1=0.0 |t|=0.00`
  으로 들어감. status cell 만 ERROR라 사용자가 빠르게 스캔하면 "측정은
  됐고 그냥 ERROR가 뜬 거구나" 로 오해. 실제로는 *측정 자체가 안 됨*.
  `crop@` 셀은 None 핸들링으로 `-` 떨어지지만 mean/n0/n1/abs_t 는 `0.0`/
  `0` 그대로 노출.
- **LLM이 자주 싸는 패턴 사유**: dataclass default 값을 sentinel 처럼
  쓰는 게 typical. ERROR row 만 별도 분기 처리하는 건 verbose해서
  LLM이 자주 생략 — "어차피 status가 ERROR면 사용자도 알겠지" false
  confidence. table rendering 에서 status 외 cell 들이 sentinel 값임을
  visual 로 표시 안 함.
- **Why solve**: U6 (LOW_RISK label → STRUCTURAL_LEAK rename) 와 같은
  family — "사용자가 빠르게 읽고 안전한 줄 오해" 방어. ERROR 인데
  `|t|=0.00` 은 "측정했더니 leak 없더라" 와 동일한 시각적 신호.
- **Acceptance criteria**:
  1. `_print_dudect_summary` 에서 `r.status == "ERROR"` 분기 — n0/n1/
     mean/abs_t cell 모두 `-` 로 출력.
  2. CSV 쪽은 그대로 (S1 raw 카운트 0이 "측정 안 됨" 의미라는 contract
     유지) — 단 인간이 보는 console table 만 시각적 구분.
- **Related**: U6 (라벨 정직성), F2/F5/T6 (ERROR status 도입).
- **Suggested bundle**: 5-line UX fix.

### T17: coverage_check probe가 사용자 cflags(-D 등) 안 받음 — silent skip 🟢

**Status: OPEN (v6 external review pass 5).**

- **Where**: `ctkat/coverage_check.py:111 cmd = [cc, "-O0", str(src_path),
  "-o", str(bin_path)]`. include_dirs는 받지만 `-D` 매크로, 사용자 custom
  flag 안 받음.
- **Symptom**: 사용자 헤더가 `#ifdef CONFIG_X` 뒤에 매크로 정의 →
  probe 컴파일이 사용자 헤더 환경 미복제 → 컴파일 실패 → "F6 coverage
  check skipped" yellow note만 출력. 사용자 입장에서 F6 검증이 도는 줄
  알지만 매번 silent skip.
- **Why solve**: F6의 가치가 환경 의존적으로 0이 될 수 있음. 실제로
  PQClean 같은 예제는 매크로 chain이 단순해서 잡히지만 복잡한 user
  코드는 trip하기 쉬움.
- **Acceptance criteria**:
  1. probe `cmd`에 사용자 cflags 중 `-D`, `-I`, `-isystem` 정도 propagate.
     또는 전체 cflags propagate (probe도 main harness와 동일 환경).
  2. README §"통계 layer / secret_regions coverage probe"에 "사용자
     cflags 일부만 받음" caveat — 또는 fix 시 caveat 제거.
- **Related**: F6 (coverage probe), F9 (cflags handling).
- **Suggested bundle**: cflag propagation fix.

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

### v8 — Bundle L hot-fixes (2026-05-27)

내가 직접 짠 Bundle L. v6/v7에서 새로 발견한 18개 OPEN 중 **6개 닫음**
(F12, F15, F16, F17, F18, T14). 다 1~3줄짜리 hot-fix family — 묶어서
한 commit, ~50 LoC.

**무엇이 닫혔나**:
- **F12**: `cli.py:1223` `parse_valgrind_log` → `parse_valgrind_log_with_stats`
  로 교체 (T3 정신과 통일) + smoke test.
- **F15**: shared_cflags validator를 `model_fields_set` 기반으로 교체.
  주석이 거짓말이었던 "object identity" 표현도 폐기.
- **F16**: `ct.seed`/`dudect.seed` 모두 `Field(gt=0)`. README §재현성
  단락 추가. ct 쪽 swap (`harness_generic.c.j2:42`) 도 같은 family라
  같이 막음 (F16 본문은 dudect만 언급했지만).
- **F17**: `model_copy(update=)` → `model_validate({**dump, **updates})`.
  pydantic v2 시맨틱 차이로 T8 cap이 CLI에서 뚫리던 거.
- **F18**: KAT default pattern 앵커링 + `re.MULTILINE`. PQClean
  `PASSED: 100 tests` 라인 형식 그대로 매치되도록 `(?:\s|$)` 트레일링.
- **T14**: 세 yaml에 `-fno-lto` 추가 + examples lint test 박음.

**테스트**: 228 → **237 passed** (9개 회귀 방어 신규).

**Bundle L에 안 들어간 거 (다음 차례)**:
- F13/F14 — sk-leak/cache-balance 의미적 leak detection 수정 (Bundle M).
  C 템플릿 + warm step 매크로 인자 + README KEM leak axes 갱신 필요.
- T12/T18/T21 — subprocess/encoding hygiene (Bundle N). 7곳 일괄 +
  `_run_text` 헬퍼.
- T20/T13/T22/T17/T16/T15/T19 — polish & follow-ups (Bundle O/P).

### v7 — internal post-impl audit, LLM-typical bug hunt (2026-05-27)

이번엔 외부 리뷰어 안 부르고 **LLM이 코드 짤 때 ㅈ같이 잘 싸는 패턴**
위주로 직접 코드 씹어봤음. 결과: **7개 confirmed**, 그 중 2개가 🚨
verdict-affecting (F17, F18). Total 46 → **53 issues** (46 prior + 7 new).

**ㅈㄴ 어이없는 1번 — F17: T8 cap이 CLI 한 줄로 뚫림.**
T8에서 `measurements: Field(ge=100, le=10_000_000)` 박아놓고
known_issues 문서에 "config 로드 단계에서 거부" 라고 적었는데, cli.py가
`dud.model_copy(update={'measurements': 99999999})` 패턴으로 override.
직접 검증:
```python
>>> M(x=Field(ge=0, le=100)).model_copy(update={'x': 99999}).x
99999  # 검증 안 함 ㅋㅋㅋ
```
pydantic v2 `model_copy(update=)` 는 재검증 안 하는 게 *공식 동작*.
LLM이 v1 시절 패턴 그대로 짜면서 v2 시맨틱 못 따라간 거. 결과적으로
T8 acceptance 약속이 yaml 입력에만 걸리고 CLI는 free pass. 같은 패턴으로
미래 F16 (seed=0 거부) validator도 `--seed 0` 으로 뚫림.

**다음 큰 거 — F18: KAT regex가 `re.search` (anywhere match).**
default pattern `r"PASSED:?\s*(\d+)"` + `re.search` 조합 = stdout 어디든
"PASSED: 100" 박혀 있으면 매치. 실제로 KAT runner가 progress log 에
"WARNING: vector 50 differs. PASSED: 100 prior" 같은 거 한 줄만 박고
exit 0 로 끝나도 false PASS. F1 (Bundle E-1) 에서 fix 했다고 자랑했던
"no-op runner도 PASS 박는 문제" 의 *다른 각도* 가 여전히 살아있음.
`^...$` 앵커 + `re.MULTILINE` 만 박았으면 됐는데, LLM이 `re.search` vs
`re.match` vs `re.fullmatch` 헷갈리는 typical 패턴.

**나머지 confirmed (전부 LLM-typical mistake)**:
- **T18**: `subprocess.run(..., text=True)` 7군데 모두 `errors='replace'`
  없음. 하네스가 garbage bytes 뱉으면 `UnicodeDecodeError` raw traceback.
  T6 try/except이 이 예외는 안 잡음 → fail-open 다 채워놓고 마지막에
  새는 거. LLM이 `text=True` 까지만 박고 끝내는 게 typical.
- **T19**: `harness_{name}.c` 동시 write race. 같은 yaml 두 ctkat 프로세스
  parallel run 시 마지막 writer wins → silent corruption. tempfile +
  atomic rename 패턴은 LLM이 명시 요청 없으면 안 씀.
- **T20**: F6 coverage probe `_render_sentinel_c` 가 yaml `header`/
  `prefix` 무검증 interpolate. T7이 `name` 만 regex 박고 나머지 follow-up
  남겨놨던 surface의 *coverage probe* 버전. LLM이 codegen에서 f-string
  user input interpolate 자주 함.
- **T21**: 6군데 `Path.read_text()`/`write_text()` 에 encoding 미지정 →
  native Windows (MinGW) 에서 cp1252 fallback → 깨짐. U3 의 "MSVC 미지원"
  caveat 와는 *다른 차원* 문제.
- **T22**: dudect summary table ERROR row 가 `n0=0, mean=0.0, |t|=0.00`
  으로 표시 → 사용자가 "측정은 됐는데 ERROR 떴구나" 로 오해. status
  cell 외 cell들이 sentinel 인지 시각적 구분 없음. U6 (LOW_RISK rename)
  과 같은 family — "라벨/표시가 정직해야" 정책 위반.

**Note**: 외부 리뷰 v5 (post-Bundle-K) 가 11개 잡고, 이번 internal v6
post-impl audit 이 추가 7개. 6번이나 review 돌렸는데도 LLM-typical 한
구멍 (특히 F17/F18) 이 안 잡혔던 게 ㅈㄴ 의미심장. 다음 audit은
*보안 분석 도구의 fail-modes* 외에 *AI 코드의 fail-modes* 도 별도
체크리스트로 두고 돌려야 함.

### v6 — external review pass 5: post-implementation audit (2026-05-26)

옆집(외부) 리뷰어가 Bundle E ~ K 머지 후 새로 발견한 12개 항목을 받았음.
내가 코드 대조 검증 결과 **11개 confirmed**, 1개 partial (정확하지만 표현이
과장됨). Total 35 → **46 issues** (35 prior + 11 new).

**가장 큰 충격: F12 — `ctkat parse` 서브커맨드가 NameError로 죽어있음.**
Bundle I (T3)에서 `parse_valgrind_log` → `parse_valgrind_log_with_stats`로
교체할 때 import만 갱신, 1223라인 호출자는 누락. 광고된 user-facing
기능 사망 + test 0개라 pytest 228 통과해도 잡히지 않음. Bundle E 이래
모든 검증 passes가 이걸 놓침 — test_cli에 parse 서브커맨드 smoke test
부재가 근본 원인.

**다음 큰 발견: F13/F14 — sk-leak 모드와 cache-balance step이 실제로는
FO rejection path만 측정한다.** 양 class 모두 `rand_bytes(ct, ...)`로 ct를
random bytes로 채워서 `crypto_kem_dec()`이 FO fallback에 진입. README의
"sk-content dependent timing" 광고와 실측이 불일치 — 정상 dec path의
sk-leak은 이 도구로 못 잡고 있다. ct-leak 모드도 warm step이 invalid
ct여서 cache "balanced"가 사실 false. fo 모드(U2 #1)를 Bundle K에서
추가했을 때 sk-leak의 의미를 재점검했어야 했는데 놓침.

**나머지 confirmed**:
- F15: `shared_cflags`가 사용자 명시 cflags를 값 동등성으로 silent override
- F16: `dudect.seed: 0` → 로그는 0x0, C는 0xC0FFEE swap (xorshift fallback)
- T12: `builder.run_shell` / `run_argv` / `valgrind_runner` / 두 compile
  helper 다 timeout 인자 없음 (T6는 dudect timing만)
- T13: `parse_functions_with_stats` skip count → CLI에서 안 씀 (T11 plumbing 미완성)
- T14: `examples/pqc_mlkem768/ctkat.yaml` dudect cflags에서 `-fno-lto` 빠짐
- T15: `upper_crop`이 cutoff마다 sort 다시 함 (5×2 sort/call)
- T17: F6 probe가 사용자 `-D` 매크로 안 받아 silent skip 가능

**Partial accuracy**:
- T16: `_FRAME_RE` `(in /lib/...)` 형식. 리뷰어는 "frame 인식 실패"라 표현
  했지만 실제로는 frame 자체는 인식됨 (function name 잡힘). 단 file:line
  파싱은 None으로 떨어짐 → stack trace 빈약.

**Not a new issue**: 리뷰어 #9 (yaml = shell 실행권한). T4의 argv 옵션
opt-in으로 이미 mitigation 제공함 — 더 강한 보안 모드는 별도 follow-up
이지만 새 known_issues entry 가치는 낮음.

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
