# CT-KAT — Known Issues & Improvement Plan

Working document. Catalogs problems found after Bundles A/B/C/D were
merged, with stable issue IDs so they can be referenced by future
commits and PRs.

## Status

- **Last updated**: 2026-06-01 (v18 — R-1~R-5 fix 24개 + **R-6 재감사: 내 R-1/R-2
  fix에서 큰 구멍 3개 발견·재fix** (CLAUDE.md §9.1 "내가 내 fix를 믿는 anchor" 실증))
- **Pipeline progress (광고 / 실제)**:
  - **광고**: 52 closed (Bundle 0~P) + 1 deferred + 25 reopened
    (v13: 9, v14: 3, v15: 4, v16: 2, v17: 6, v18: 1)
  - **실제 코드 fix**: 52 + **27** (R-1~R-5 24개 + R-6 3개). 남은 reopened 1개(T25)는
    reviewed → won't-fix(전제 오류).
  - **남은 OPEN finding: 0** (T25 제외).

### v18 R-6 — 재감사 (R-1/R-2 fix 자체의 구멍 3개, 2026-06-01)

R-1~R-5 push 후 anchor-free 멀티에이전트 재감사. **내가 "닫았다"고 push한
R-1(fail-open)·R-2(injection) 각각에 구멍이 남아 있었다** — 정확히 CLAUDE.md §9.1
("광고≠검증, 내 fix를 믿는 anchor")의 실증. cross-check이 잡음. 전체 pytest 307
passed, 회귀 테스트 20개, 우회 시도 13종 차단 확인.

- **RA-1** 🚨 (HIGH, R-2 결함): `_C_EXPR_PATTERN`이 `sizeof()` 허용하려 `( ) , &`를
  열어둬서 **comma operator** (`length: '32, 0'` → `(32, 0)` == 0 → 비밀 0바이트
  taint → 누수 코드 CLEAN 오판, verdict 거짓-음성) + **함수 호출** (`size: 'abort()'`,
  `(&abort)()` 포인터 호출) 우회 가능. → fix: charset에서 `,` 제거 + 괄호/대괄호
  balance + `sizeof(` 외 호출형(`ident(`, `)(`,  `](`) 거부.
- **RA-2** (MED, R-1 미완): R-1이 standalone `dudect` 서브만 빈-결과 가드 추가하고
  `run()`/`ct()`는 놓침 → `ct: {harnesses: []}` 로 `ctkat run`이 exit 0 + green PASS.
  → fix: run()/ct()에 빈-하니스 가드(exit 2). dudect enabled:false는 의도적 skip 허용.
- **RA-3** (MED, 기존+1차 audit 미발견): `report.csv`/`report.json`이 무검증 →
  `csv: '../../tmp/x.csv'` 로 output_dir 밖 임의 쓰기. → fix: 순수 파일명(`/`·`..`·
  절대경로 금지) validator.

### v18 R-1~R-5 — 실제 코드 fix (audit≠fix 깨짐, 2026-05-30)

아래 24개는 **코드+테스트로 실제 닫힘** (전체 pytest 299 passed, examples 8종
무회귀, gcc로 dudect/coverage e2e 검증). 각 항목 본문의 `Status: OPEN` 헤더는
이 로그가 supersede.

- **R-1** `7e4ebba` — **T41** (dudect 서브 ERROR/empty fail-open).
- **R-2** `209c15d` — **T23 · T35 · T34 · F22** (yaml→C source injection 전면
  봉쇄: BufferSpec.name/size, args, SecretRegion.offset/length/comment,
  header `..` traversal, `.fullmatch`, coverage probe).
- **R-3** `18fab50` — **T31 · T32 · T36** (attribute nested-paren 함수 증발,
  `**`/맨타입 오파싱, 멀티라인 주석 줄번호 드리프트).
- **R-4** `dc38549` — **T37 · T39 · T40 · S5 · T24** (harness name 유일성,
  `argv: []`, parse missing-file, invalid-class row, CSV/yaml encoding) +
  **T38** (ML-KEM example reproducibility, Option A; Docker compile-smoke 잔여).
- **R-5** (this commit) — **F19 · F20 · F21 · F23 · T26 · T27 · T28 · T29 · T30
  · T33** (cleanup 묶음):
  - F19 randbits=0 → 0xC0FFEE fallback. F20/F23 bonferroni를 cropping path에만
    적용(batch/uncropped는 unscaled). F21 coverage probe OOB/overlap 경고.
  - T26 bisect import top-level. T27 sink 주석 정정(address-escape). T28 KAT
    capture-group parse-fail loud warn + coverage parse-fail wording. T29
    `ctkat run` smoke test 2개. T30 cropping cutoffs[0]==1.0 가드. T33 `--seed`
    invalid → Exit(2).
  - **T25** = reviewed → **won't-fix**: 문서가 "dead code"라 한 cli.py `except
    IndexError`는 `kat.expected_pattern` user-override(capture group 없는 패턴)로
    실제 도달 가능 → 제거 시 오히려 crash. config.py `prefix is not None`는
    재사용 validator의 의도적 None-guard. 둘 다 유지가 정답. (CLAUDE.md §3 —
    문서 claim 불신, 코드로 검증.)
- **v17 핵심 발견**: 같은 모델 1회 anchor-free + 메타-grep 강제
  (`grep "{{ r\." templates/*.j2`, `grep "harnesses:" examples/*/`,
  `grep "Argument(" cli.py`) 가 v13~v16 5회 audit이 못 본 6개 추가
  발견. **핵심 사례 T35**: T23 본문의 acceptance criteria #3 list가
  4종 필드만 명시 → v14/v15/v16 audit이 그 list 따라가서 `r.comment`
  사이트를 통째로 못 봄. CLAUDE.md §9.1 (광고 anchor) 의 재귀적
  발현 — T23 광고가 자기 후속 audit의 anchor. §9.3 (메타-grep 의무)
  가 list-anchor 회피의 유일한 백업.
- **v16 핵심 발견**: 또 다른 모델로 한 번 더 cross-audit. v13/v14/v15가
  못 본 또 다른 layer 2개 — validator regex 자체의 무결성 (`.match()` vs
  `.fullmatch()` 기초 Python 함정) + bonferroni가 `batch_t_scores` 까지
  영향주는 F20 사각지대 + test docstring 광고와 실제 검증 범위 mismatch.
  §9.2 의 "가끔 다른 모델 cross-check이 새 layer 발견" 효과 재실증.
- **Resolved so far** (52/53; F9 #4만 deferred):
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
  - **F13, F14** — Bundle M (sk-leak 정상 dec path 측정 + cache-balance
    warm step이 측정 path와 일치하도록 매크로 재설계). README §"KEM
    leak axes" 갱신 — 광고와 실측이 비로소 정합.
  - **T12, T18, T21** — Bundle N (subprocess/encoding hygiene). `_proc.run_text`
    헬퍼 신설: timeout 필수 + encoding='utf-8' + errors='replace' 정책
    한 곳에 집중. 5개 subprocess call site (builder × 2, valgrind, compile
    × 2) + 6개 read/write_text 일괄 적용. yaml 필드 신규: `build.timeout`,
    `kat.timeout`, `ct.compile_timeout`, `ct.valgrind_timeout`,
    `dudect.compile_timeout` (default 모두 600초).
  - **T20** (+ T7 follow-up family) — Bundle O. `prefix`, `header`,
    `extra_headers`, `function`, `return_type` 모두 pydantic validator에서
    regex 검증. `_check_yaml_identifiers` 모듈 레벨 함수로 두 모델
    (Harness/DudectHarness) 공유. F6 coverage probe도 같은 validator 거친
    값만 받으므로 C-source injection surface 자동 차단.
  - **T13, T15, T16, T17, T19, T22** — Bundle P (polish, ~150 LoC):
    parse_header_file_with_stats plumbing + cli infer skip note,
    welch_with_cropping 한 번 sort + prefix slice 최적화, FRAME parser
    binary-only location 인식, coverage probe에 -D/-I/-isystem propagate,
    `_atomic_write_text` 헬퍼로 harness write race 차단, dudect summary
    ERROR row의 numeric cell을 `-`로 분리.
  - F9 #4 — deferred future work (multi-cflags matrix; out of scope per
    spec, requires new CSV schema + matrix-aware verdict computation).
- **Audit sources**:
  - Internal review by Bundle A–D author (focused on dudect pipeline)
  - External independent reviewer, pass 1 (whole-pipeline audit)
  - External independent reviewer, pass 2 (audited v1 of this doc)
  - External independent reviewer, pass 3 (audited v2 + whole repo)
  - External independent reviewer, pass 4 (audited v3 + cross-stage interactions)
  - Verification pass 5 (audited v4 line references against `main`)
- **Total findings**: 6 tiers (Tier 0 신설), 77 issues (v1: 20 → v2: 23
  → v3: 26 → v4: 35 → v5: 35 → v6: 46 → v7: 53 → v13: 62 → v14: 65 → v15: 69 → v16: 71 → v17: 77)
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
  - v13: post-Bundle-P anchor-free meta-audit. 9 new issues (Tier 0 신설):
    T23 (T20 미완 — 4종 yaml 필드 5개 template raw-interp 🚨),
    F19 (F16 우회 — `secrets.randbits(63)` 0 corner 🚨),
    T24 (T21 미완 — `open()` 6곳 encoding 미지정 🟡),
    F20 (bonferroni `--no-crop` 거짓말 🟡),
    F21 (F6 미완 — region overlap/OOB 미검사 🟡),
    T25 (dead code 2곳 🟢), T26 (bisect import hot loop 🟢),
    T27 (sink 주석 거짓 🟢), T28 (silent parse-fail 2곳 🟢).
    핵심 관찰: 5회 review + 7개 Bundle을 거쳐도 같은 패턴이 새 site에서
    나옴. CLAUDE.md §9 "LLM 협업 메타-룰" 신설.
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

## Tier 0: Post-Bundle-P Meta-Audit Findings (v13 + v14 + v15 + v16 + v17)

이 섹션은 v13/v14/v15/v16/v17 meta-audit에서 발견된 24개 finding (v13: 9 +
v14: 3 + v15: 4 + v16: 2 + v17: 6) 을 모아둠. **별도 Tier로 분리한 이유**: Bundle L-P가
"닫았다"고 광고한 issue들이 실제로는 일부만 닫혔거나 같은 패턴이 다른
site에 그대로 남아있던 사례들이라, 정상 tier (1-5)에 흩어 놓으면
"Bundle X에서 닫혔다"는 이전 status 광고가 사실로 보이게 됨. v13/v14
는 정직성을 위해 별도 시각화.

**⚠️ audit ≠ fix 경고**: 아래 24개 finding은 **모두 코드 fix 안 됨**.
v13/v14/v15/v16/v17 audit이 적기만 하고 코드 commit 안 함. v14가 v13
광고를 코드 grep으로 verify해서 finding 9개 다 살아있음을 확인 (+ 3개
새). v17이 v13 T23 본문의 acceptance criteria #3 list가 audit anchor가
되어 후속 4회 cross-audit이 같은 family 한 site (`r.comment`) 를
통째로 못 본 사례를 적음. 이게 정확히 CLAUDE.md §9.1 ("광고 ≠ 검증")
의 재귀적 발현 — audit 본문 자체가 광고가 되어 다음 audit의 anchor.
§9.6 신설.

심각도 표기는 동일 (🚨 verdict-affecting / 🟡 correctness / 🟢 hygiene).

### T23: T20 미완 — 4종 yaml 필드가 5개 template에서 raw-interpolation 🚨

**Status: OPEN.** Bundle O (T20)이 `prefix/header/extra_headers/function/
return_type` 5개 필드에 `_check_yaml_identifiers` 추가했지만 같은 surface
인 4종 yaml 필드가 validator 거치지 않고 그대로 C로 들어감.

- **Where**: 5개 template × 4종 필드
  - `BufferSpec.name` (config.py:189) → `harness_generic.c.j2:46,47,51,
    61,64,81,82`, `timing_generic.c.j2:90,91,96,102,117,123,125`
  - `BufferSpec.size` (config.py:190) → 위와 동일 site (배열 크기 자리)
  - `HarnessConfig.args` / `DudectHarnessConfig.args` (config.py:242, 397)
    → `harness_generic.c.j2:55,57`, `timing_generic.c.j2:104,131,134`
  - `SecretRegion.offset` / `.length` (config.py:205-206) →
    `harness_kem.c.j2:39,49`, `harness_sign.c.j2:37,47`
- **Symptom**: yaml에 `name: "x; system(\"rm -rf /\"); int dummy"` 박으면
  그대로 C 컴파일됨. `args: ["\`evil\`"]` 동상. `SecretRegion.offset`은
  "C 표현식 허용" 정책이라 그렇다 쳐도 newline/quote 무필터.
- **Why solve**: Bundle O가 광고한 "C-source injection surface 자동
  차단"이 사실이 아님. T20의 의도된 closure가 미완 — 같은 surface 5개
  template × 4종 필드 추가 차단 필요. T20의 광고를 정정하지 않으면
  다음 안전 audit이 anchor에 끌림 (정확히 CLAUDE.md §9.1).
- **Acceptance criteria**:
  1. `_check_yaml_identifiers` 에 `buffer_names`/`buffer_sizes`/
     `arg_exprs`/`region_offsets`/`region_lengths` 파라미터 추가.
  2. `BufferSpec.name`은 C identifier regex (`_C_IDENT_PATTERN`).
  3. `BufferSpec.size`, `args`, `SecretRegion.offset/length`는 "C
     expression-like" — `[A-Za-z0-9_+\-*/() ]+` 정도. quote/semicolon/
     backslash/newline 명시 거부.
  4. `BufferSpec` / `SecretRegion` / `HarnessConfig` / `DudectHarnessConfig`
     의 `_check_mode` 또는 model_validator에서 호출.
  5. evil-input 시연 테스트 (CLAUDE.md §9.4): `name: 'x; system'` yaml 박으면
     ValidationError 떨어지는 stdout 캡쳐 + 해당 메시지에 필드명 포함.
- **Related**: T20 (이게 닫혔다고 광고했던 issue), T7 (filename surface).
- **Suggested bundle**: Q-1 (validator family extension, ~80 LoC).

### F19: F16 우회 — `secrets.randbits(63)` 0 corner 🚨

**Status: OPEN.** Bundle L (F16)이 yaml seed에 `Field(gt=0)` 추가해서
0 거부했지만 CLI fallback path가 `secrets.randbits(63)`로 0 반환할 수
있음 (확률 2^-63). 0 나오면 Python은 `0x0` 로깅, C는 `seed ? seed :
0xC0FFEE` swap → F16이 막은 두 layer 불일치 시나리오 재현.

- **Where**: `ctkat/cli.py:663`
  ```python
  effective_seed = dud.seed if dud.seed is not None else secrets.randbits(63)
  ```
- **Symptom**: 매우 낮은 확률이지만 logical hole. F16이 "seed=0 거부"라
  광고했는데 fallback path가 그대로 우회.
- **Why solve**: 확률은 작지만 "두 layer가 같은 값이라 보장"이라는
  invariant가 무너지면 deterministic reproducibility claim도 무너짐.
  CLAUDE.md §4 layer contract 위반.
- **Acceptance criteria**:
  1. `effective_seed = ... or 0xC0FFEE` 한 줄 추가 (또는 `secrets.randbits(63)
     or 0xC0FFEE`).
  2. test로 `secrets.randbits` mock해서 0 반환시 effective_seed가
     0xC0FFEE인지 검증.
- **Related**: F16 (이게 닫혔다고 광고했던 issue).
- **Suggested bundle**: Q-1 (F19 + T23 묶음).

### T24: T21 미완 — `open()` 6곳 encoding 미지정 🟡

**Status: OPEN.** Bundle N (T21)이 `Path.read_text/write_text`에 encoding
지정 추가했지만 `open()` 직접 호출은 안 봄. Windows non-UTF-8 locale에서
깨질 수 있음.

- **Where**:
  - `config.py:561` — `with open(path) as f:` (yaml load, **가장 critical**)
  - `cli.py:564, 571, 982` — CSV write (`newline=""`만 있고 encoding 없음)
  - `report.py:62, 72` — CSV/JSON write
- **Symptom**: Windows cp1252 locale에서 yaml의 비-ASCII (한글 주석 등)
  깨지거나, CSV 출력이 cp1252로 박혀 다른 시스템에서 못 읽음.
- **Why solve**: T21의 광고("Windows 깨짐 차단")가 read/write_text만
  덮음. `open()` 직접 호출은 그대로 → 같은 user impact 잔존.
- **Acceptance criteria**:
  1. 6곳 모두 `encoding="utf-8"` 추가.
  2. yaml load는 `errors="strict"` (default) 유지하되 명시.
  3. CSV write는 `newline=""` 유지.
- **Related**: T21 (이게 닫혔다고 광고했던 issue), T18.
- **Suggested bundle**: Q-2 (housekeeping, ~10 LoC).

### F20: bonferroni_correct + --no-crop 거짓말 🟡

**Status: OPEN.** `config.py:496-504` docstring은 "multi-cutoff cropping
protocol takes max |t| over 5 correlated tests"라 명시해 cropping 한정
보정이라 주장. 근데 `cli.py:682-687`은 `crop` 플래그와 무관하게
sqrt(5) 곱함. `--no-crop` 키면 single Welch test 1번 도는데 거기에도
보정 들어감 → threshold가 이유 없이 빡빡해짐.

- **Where**: `ctkat/cli.py:682-687`, `ctkat/config.py:496-504`
- **Symptom**: `bonferroni_correct: true` + `--no-crop` 조합에서 single
  Welch에 sqrt(5) scaling 적용 (통계적 근거 0). 실제 leak에서 PASS,
  false PASS 가능성 발생.
- **Why solve**: 주석 ≠ 코드 (CLAUDE.md §3). docstring claim과 코드
  동작 불일치는 user를 혼란시키고 verdict 신뢰도 깎음.
- **Acceptance criteria**: 둘 중 하나
  1. (Option A) `if dud.bonferroni_correct and crop:` 로 가드 추가.
     docstring과 코드 정합.
  2. (Option B) docstring 수정해서 "scale both crop and no-crop for
     consistent threshold across whole report" 명시. user는 헷갈리지만
     의도된 design 유지.
  - 추천: Option A (docstring을 정답으로 두고 코드 정정).
- **Related**: R2 (Bundle G에서 도입).
- **Suggested bundle**: Q-2.

### F21: F6 미완 — secret_regions overlap / OOB 미검사 🟡

**Status: OPEN.** Bundle F (F6) coverage probe는 `sum(length) / total`
ratio만 검사. overlap (두 region 같은 byte 덮음) 미검사 → sum > total
→ ratio > 1.0 가능. out-of-bounds (`offset: 999999, length: 32`) 미검사
→ harness가 `sk + 999999` 위치 (스택 외부) taint.

- **Where**: `ctkat/coverage_check.py:189` (`ratio = covered / total`)
- **Symptom**:
  - Overlap case: 두 region이 같은 byte 덮으면 100% 넘어가도 경고 없음.
  - OOB case: `offset` 큰 값 박으면 sk 배열 밖 stack을 VALGRIND_MAKE_MEM_UNDEFINED.
    실제 secret 아닌 stack을 taint해서 false-positive findings 발생 가능.
- **Why solve**: F6이 광고한 "yaml typo로 인한 인 false PASS 차단"이
  shrunk-length typo만 잡고 expanded-length / OOB는 미커버. F6 자체가
  diagnostic이지만 "advertised vs actual coverage"가 일치해야 함.
- **Acceptance criteria**:
  1. coverage probe가 `max(offset + length)`도 emit (sentinel C에 추가).
  2. python side에서 `max_offset_plus_length > total`이면 OOB warn.
  3. region 쌍별 overlap check (offset_i + length_i > offset_j 등).
     overlap 있으면 warn (가능한 의도지만 user에게 surface).
- **Related**: F6.
- **Suggested bundle**: Q-3 (F6 expansion).

### T25: dead code 2곳 — cleanup 🟢

**Status: OPEN.** v13 audit이 발견한 도달 불가 분기 2곳.

- **Where**:
  - `ctkat/cli.py:189` — `except (IndexError, ValueError): count = None`
    의 `IndexError`. regex pattern에 `(\d+)` capture group이 강제되므로
    `m.group(1)` 절대 missing 안 됨. `IndexError` raise되지 않음.
  - `ctkat/config.py:44` — `if prefix is not None and prefix != "" and
    not _C_IDENT_PATTERN.match(prefix):` 의 `is not None` guard.
    `HarnessConfig.prefix: str = ""` (default `""`, Optional 아님)
    이라 prefix가 None일 일이 없음.
- **Symptom**: 둘 다 dead defensive code. 동작 영향 없지만 reader 혼란.
- **Acceptance criteria**:
  1. cli.py:189 — `except ValueError:` 로 좁힘.
  2. config.py:44 — `is not None` 제거, `prefix != ""` 만 유지.
- **Related**: 없음.
- **Suggested bundle**: Q-4 (cleanup).

### T26: bisect import hot loop 안 🟢

**Status: OPEN.** `ctkat/statistics.py:237` `from bisect import
bisect_right`가 `welch_with_cropping`의 for 루프 안에 있음. Python의
import cache 덕분에 실제 비용은 매우 낮지만 (5회 iter × cache lookup)
hot loop 안 import는 코드 위생 부적합.

- **Where**: `ctkat/statistics.py:237`
- **Symptom**: micro-perf. 측정 영향 없음.
- **Acceptance criteria**: `bisect_right` import를 module 최상단으로.
- **Related**: T15 (welch_with_cropping 최적화 작업).
- **Suggested bundle**: Q-4.

### T27: harness_generic sink 주석 거짓 🟢

**Status: OPEN.** `templates/harness_generic.c.j2:67-79` sink 주석:
"XOR-accumulate pattern is intentional: it consumes every byte without
depending on a particular type for the return value." 실제 코드는
`__ctkat_sink ^= (uint64_t)(uintptr_t)&__ctkat_ret;` + `^= sizeof(...)`
— 값이 아니라 주소+크기만 XOR. mechanism은 `-fno-lto` + 주소 escape로
작동하지만 주석은 거짓.

- **Where**: `ctkat/templates/harness_generic.c.j2:67-79`
- **Symptom**: code reading 시 혼란. mechanism이 실제로는 address-escape
  기반이라 user/maintainer가 "값 소비"라 오해하면 향후 변경에서
  실수할 위험.
- **Why solve**: CLAUDE.md §3 "주석 ≠ 코드" 위반. 비교: `harness_kem.c.j2:
  61-65`는 `ctkat_sink ^= ss_actual[i]` (실제로 값 소비) — 주석 정확.
- **Acceptance criteria**: 주석을 정확하게 — "force allocation of
  __ctkat_ret via address escape; combined with -fno-lto this prevents
  dead-store elimination of the function call".
- **Related**: 없음 (F15 family).
- **Suggested bundle**: Q-4.

### T28: silent parse-fail 2곳 🟢

**Status: OPEN.** edge case지만 KAT/coverage 두 곳에서 regex가 matched
는데 capture group 파싱 fail시 silent.

- **Where**:
  - `ctkat/cli.py:189-190` — `int(m.group(1))` ValueError 시 `count=None`.
    `expected_min` 미설정이면 `return True, count` (PASS) — note는 출력
    되지만 "regex matched but value unparseable" 시나리오는 logging 없이
    PASS. user override pattern에서 발생 가능 (예: `(\w+)`).
  - `ctkat/coverage_check.py:179` — sentinel regex parse fail시 yellow
    note + return None. probe 실행은 성공한 거라 명시적 ERROR가 더
    적절.
- **Symptom**: 두 곳 모두 edge case. KAT는 user override pattern시 false
  PASS 가능; coverage는 F6 자체가 diagnostic이라 영향 작음.
- **Acceptance criteria**:
  1. cli.py: regex matched + count parse fail시 명시적 warn (yellow note
     "expected_pattern matched but capture group is non-numeric").
  2. coverage_check.py: probe 실행 성공 + parse fail은 yellow note에
     "probe ran successfully but stdout format unexpected" 명시.
- **Related**: F1 (KAT validation), F6 (coverage diagnostic).
- **Suggested bundle**: Q-4.

### F22: coverage probe도 injection surface — T23/T20의 미발견 site 🚨 (v14)

**Status: OPEN.** v13 T23이 5개 template에서 raw-interpolation 잡았지만
**`coverage_check._render_sentinel_c`도 같은 surface**. F6 probe의 C
source가 yaml 값 raw embed.

- **Where**: `ctkat/coverage_check.py:69`
  ```python
  sum_expr = " + ".join(f"({length})" for length in secret_region_lengths) or "0"
  ```
  + line 75 `size_t covered = (size_t)({sum_expr})` — `SecretRegion.length`
  원소가 그대로 C로.
- **Symptom**: evil yaml의 `secret_regions: [{offset: 0, length: '32);
  system("evil"); /*'}]` 박으면 F6 probe의 C source에 박힘. probe는
  `-O0`이고 gcc로 compile → 실행 가능.
- **Why solve**: T23이 광고한 "C-source injection 차단" 의 또 다른
  미커버 surface. v13 T23 본문이 template만 다루고 coverage probe는
  안 적음. CLAUDE.md §9.3 메타-grep 위반의 재발 사례 — `grep '({{' .`
  대신 `grep -r "f.*\\\\(.*{.*}.*\\\\)" coverage_check.py` 같은
  string-interpolation까지 메타-grep해야 했음.
- **Acceptance criteria**:
  1. T23의 `BufferSpec`/`SecretRegion` validator extension에 합류 —
     `SecretRegion.length` regex validator가 추가되면 자동 차단.
  2. coverage_check 호출 site (`cli.py` 어딘가) 에서 secret_region_lengths
     를 SecretRegion 모델 거친 값만 받도록 type-narrow.
  3. evil-input 시연 테스트.
- **Related**: T23 (template injection), F6 (coverage probe).
- **Suggested bundle**: Q-1 (T23 + F22 묶음 — 같은 fix가 둘 다 닫음).

### T29: `ctkat run` smoke test 0개 — F12 패턴 재현 위험 🟢 (v14)

**Status: OPEN.** `tests/test_cli.py`에서 `runner.invoke(app, ["run", ...])`
호출 0개. infer/ct/kat/dudect/parse는 다 smoke test 있는데 `run`만 없음.
README/tutorial이 `run`을 entry point로 광고하는데 backend unit test가
커버한다고 가정한 상태.

- **Where**: `tests/test_cli.py` (run subcommand 호출 0개), `cli.py:1018`
  (`run` 정의)
- **Symptom**: F12 (parse NameError) 와 정확히 같은 패턴 재현 가능 —
  backend 함수 rename / 호출 chain 변경 시 `run` subcommand가 NameError
  로 죽어도 잡지 못함. F12 가 정확히 이 시나리오로 user에게 노출됨.
- **Why solve**: CLAUDE.md §1 "user-visible surface 각각에 smoke test
  최소 1개" 위반. `run`이 가장 큰 user-visible surface인데 cover 0.
  F12를 만든 root cause가 그대로 재현 가능.
- **Acceptance criteria**:
  1. `tests/test_cli.py` 에 `runner.invoke(app, ["run", "--config",
     str(tmp_yaml)])` smoke test 최소 1개.
  2. 다른 subcommand의 acceptance 항목 (예: stdout에 `KAT: PASS`,
     `Constant-Time Check: PASS`, `dudect: PASS` 모두 나옴) 동일하게
     검증.
  3. 추가 fixture: KAT + ct + dudect 다 통과하는 minimal yaml + dummy
     header / sources.
- **Related**: F12 (parse NameError, 같은 패턴 v6에서 발생).
- **Suggested bundle**: Q-3 (test 추가).

### T31: `_ATTRIBUTE` regex가 nested paren 못 처리 → 함수 silently disappear 🟡 (v15)

**Status: OPEN.** `header_parser.py:42`의 `_ATTRIBUTE` regex
`__attribute__\s*\(\([^)]*\)\)` 가 `[^)]*` 라서 첫 `)` 에서 멈춤.
`__attribute__((nonnull(1)))` 같은 nested paren 안에 있는 attribute
들어오면 regex match가 `__attribute__((nonnull(1))` (마지막 `)` 미아).
sub 결과로 미아 `)` 가 declaration에 박혀서 `_DECL_RE`/`_DECL_LOOSE_RE`
둘 다 못 매치 → 함수 silently drop.

T11이 함수 `_DECL_LOOSE_RE` + `skipped` 카운트로 "infer 누락 surfacing"
이라 광고했지만 이 케이스는 **카운트조차 안 됨**. T11 광고 우회.

- **Where**: `ctkat/header_parser.py:42` (`_ATTRIBUTE` regex)
- **Symptom**: 실측:
  ```
  # 입력
  int with_attr(uint8_t *bar) __attribute__((nonnull(1)));
  # parse_functions_with_stats 출력
  Parsed: []
  Skipped: 0   ← skipped 카운트에도 안 잡힘
  ```
- **Why solve**: T11이 "skipped count로 infer 완성도 보장"이라 광고했는데
  이 surface가 우회. `__attribute__((nonnull(N)))` `__attribute__((warn_unused_result))`
  `__attribute__((format(printf, 1, 2)))` 등 표준 libc/PQClean 외 헤더에
  흔함. `ctkat infer` 가 "skip 0"이라 보고해도 실제로는 누락 가능.
  CLAUDE.md §8 (test corpus가 reference set만은 아닌가) 위반 — PQClean
  헤더엔 안 쓰지만 다른 PQC 구현 / libc 헤더엔 흔함.
- **Acceptance criteria**:
  1. `_ATTRIBUTE` regex를 nested paren 1단계 허용으로 — `r"__attribute__\s*\((?:[^()]|\([^()]*\))*\)"`.
  2. test fixture에 `__attribute__((nonnull(1)))` 케이스 추가 → parsed
     list에 함수가 잡히는지 검증.
  3. T13이 광고한 skip-count surfacing도 영향 받음 — 함수가 silent
     disappear하면 skip count조차 0이라 user 혼란. T31 fix가 T11/T13
     광고를 truthful하게 만듦.
- **Related**: T11 (function-pointer params), T13 (skip count plumbing).
- **Suggested bundle**: Q-3 (parser hardening).

### T32: `_parse_param` 익명 다중포인터 (uint8_t **) 파싱 망가짐 🟡 (v15)

**Status: OPEN.** `header_parser.py:121` `if name == "*":` 가드가 단일
포인터만 처리. `uint8_t **` (이름 없는 이중포인터) 같은 케이스 → tokens
= `["uint8_t", "**"]` → `name = "**"` (C 식별자 아님) → `type = "uint8_t"`
(`**` 사라짐) → `is_pointer = False` (틀림).

bare type name (`size_t` 단독, 이름 없는 파라미터) 도 같은 패턴: tokens
= `["size_t"]` → `name = "size_t"` (이름이 타입으로) → `type = ""` (빔).

실측:
```
int weird(uint8_t **, size_t);
  → param: name='**', type='uint8_t', is_pointer=False   # 1번 깨짐
  → param: name='size_t', type='', is_pointer=False      # 2번도 깨짐
```

- **Where**: `ctkat/header_parser.py:121-128`
- **Symptom**:
  - `infer` 가 yaml에 `args: ["**"]` 출력 — user 복붙하면 C compile error.
  - `secret_infer._heuristic_role(param)` 가 `is_pointer=False`로 "scalar"
    분류 — 실제로는 buffer인데 "이건 buffer 아님" 잘못된 hint.
- **Why solve**: T11과 다른 surface (T11은 function pointer, T32는
  bare type / 익명 다중포인터). PQClean API는 파라미터에 이름 다 있어
  실측 안 터지지만, ctkat이 자기 광고를 "general PQC infer"로 잡으면
  바로 터짐. CLAUDE.md §7 (같은 일반 문제 다른 site) 위반 — `name == "*"`
  가드가 `*` 단일만 처리, multi-`*` / 익명 케이스 무관심.
- **Acceptance criteria**:
  1. `name` 이 C identifier regex (`^[A-Za-z_]\w*$`) 매치 안 하면 익명
     처리: `name = f"_arg{index}"`, `type_tokens = tokens`.
  2. test fixture에 `uint8_t **`, `size_t`, `const void *` 익명 케이스
     추가.
  3. `is_pointer` 가 `**` 케이스에도 True.
- **Related**: T11, T13.
- **Suggested bundle**: Q-3.

### T33: `--seed abc` 같은 invalid CLI 입력이 Python traceback으로 노출 🟢 (v15)

**Status: OPEN.** `cli.py:882` `updates["seed"] = int(seed, 0)` 가 예외
처리 없음. `--seed abc` 또는 `--seed 1e5` 같은 그럴듯해 보이는 비숫자
입력 → `ValueError: invalid literal for int() with base 0: 'abc'` →
typer가 안 잡고 Python traceback이 그대로 사용자에게 노출.

- **Where**: `ctkat/cli.py:882`
- **Symptom**: `ctkat dudect --config foo.yaml --seed abc` 에서 typer
  의 일반 user-friendly error 대신 Python stack trace. user는 "도구가
  깨졌나" 의심.
- **Why solve**: CLAUDE.md §1 (user-visible surface 각각 smoke test).
  CLI input validation이 yaml validation (pydantic) 만 있고 direct CLI
  `int()` call은 빈손. F17 (model_copy → model_validate) 이후 yaml
  path는 안전하지만 CLI path는 그대로.
- **Acceptance criteria**:
  1. `try: updates["seed"] = int(seed, 0) except ValueError: console.print(
     f"[red]Invalid --seed {seed!r}: use integer (0x prefix allowed) or
     'random'[/]"); raise typer.Exit(1)`.
  2. test: `runner.invoke(app, ["dudect", "--config", ..., "--seed",
     "abc"])` 가 exit_code=1 + stderr 메시지 확인.
- **Related**: F19 (seed random fallback).
- **Suggested bundle**: Q-4.

### S5: timing CSV에서 `cls ∉ {0, 1}` row가 silent하게 분석 제외 🟡 (v15)

**Status: OPEN.** `dudect_runner.py:95` `samples.classes.append(cls)` 가
cls 값 범위 검사 안 함. cls=2 같은 invalid row가 들어오면 `raw_n_total`
에는 카운트되지만 downstream `c0 = [c for cls,c in ... if cls == 0]` /
`c1` split에서 둘 다 빠짐 → gap. `_MALFORMED_WARN_THRESHOLD` 에도 안
잡힘 (parse는 성공한 거라).

실측:
```
parse_timing_csv("sample_id,class,cycles\n0,2,1000\n1,0,1001\n2,1,999\n")
  → raw_n_total=3, c0=[1001], c1=[999], gap=1, no warning
```

- **Where**: `ctkat/dudect_runner.py:95`
- **Symptom**: timing harness가 mid-run crash해서 garbage 출력하거나,
  외부 binary output을 재사용했을 때 cls 값이 2/3/-1 등 들어올 수 있음.
  CSV 의 raw_n_total과 (n0 + n1) 차이가 있는데 user에게 surface 안 됨.
  통계 왜곡 가능.
- **Why solve**: F4/S1 family ("per-class drop tracking, raw-count CSV
  columns") 가 zero-cycle / malformed row는 잡지만 cls range 위반은
  미커버. CLAUDE.md §2 (semantic invariant 검증) 위반 — "cls는 {0,1}
  중 하나"라는 invariant가 docstring/주석에도 명시 안 됨.
- **Acceptance criteria**:
  1. `parse_timing_csv` 에서 `cls not in (0, 1)` 이면 `skipped_malformed`
     로 분류 + counter 추가 (`samples.dropped_invalid_class`).
  2. CSV report 에 `dropped_invalid_class_n` column 추가 또는 기존
     malformed 카운트에 합산하되 warn 메시지에 "invalid class" 명시.
  3. test fixture에 cls=2 row 추가 → drop count 증가 확인.
- **Related**: F4 (per-class drop tracking), S1 (raw-count CSV columns),
  T6 (timing harness fail-open).
- **Suggested bundle**: Q-3.

### T34: `_check_yaml_identifiers` 의 `.match()` 가 trailing `\n` 통과 🟢 (v16)

**Status: OPEN.** `config.py:44, 50, 58, 64, 69` 의 `_C_IDENT_PATTERN`,
`_HEADER_PATTERN`, `_C_TYPE_PATTERN` 셋 다 `.match()` 사용. Python `re`
스펙: `$` 앵커는 "문자열 끝" 또는 "**문자열 마지막 `\n` 직전**"에서
매치됨. `.match()` 는 시작 위치만 고정 → trailing `\n` 있으면 통과.
T23/F22가 막으려 만든 validator 본인의 무결성에 구멍.

실측:
```python
>>> _check_yaml_identifiers('test', prefix='PQCLEAN_\n')
# 통과 (raise 안 함) — 'PQCLEAN_' 까지만 match, '\n' 묵인
```

- **Where**: `ctkat/config.py:44, 50, 58, 64, 69` (.match() 5개 site)
- **Symptom**: yaml `prefix: "PQCLEAN_MLKEM768_CLEAN_\n"` (YAML 더블쿼티
  `\n` 이스케이프) 가 validator 통과 → Jinja 렌더 시 C 소스에
  `PQCLEAN_MLKEM768_CLEAN_\ncrypto_kem_dec(...)` 박힘 → gcc 컴파일 에러.
  silent injection은 아니지만 validator가 막아야 할 값을 통과시키는 게 팩트.
- **Why solve**: 보안 도구의 validator는 "엄밀히 거부"가 contract. trailing
  `\n` 같은 기초 corner를 통과시키면 광고 ≠ 실제. 같은 family인 T23/F22
  의 fix가 어차피 `_check_yaml_identifiers` 확장이라 같이 막아야 truthful.
  CLAUDE.md §3 (주석 ≠ 코드) + §9.4 (test 광고 ≠ 실제) 둘 다 표본 —
  `test_config.py`에 trailing-newline 케이스 0건.
- **Acceptance criteria**:
  1. 5개 site 모두 `.match()` → `.fullmatch()` 교체.
  2. test 추가: `prefix='X\n'`, `header='api.h\n'`, `return_type='int\n'`
     셋 다 ValidationError 떨어지는지 확인.
- **Related**: T23 (template injection — 같은 validator), F22 (coverage
  probe — 같은 validator).
- **Suggested bundle**: Q-1 (T23 + F22 + T34 묶음 — 같은 validator family).

### F23: `bonferroni_correct` 가 `batch_t_scores` threshold도 올림 — F20 사각지대 🟡 (v16)

**Status: OPEN.** F20이 `bonferroni_correct` + `--no-crop` 조합의
거짓말을 짚었지만, F20 본문에 `batch_t_scores` 언급 없음. `cli.py:782-783`
이 corrected threshold를 batch_t_scores에도 그대로 전달 — 단일 검정에
다중비교 보정 적용 (통계적 근거 없음).

`cli.py:679-680` 본인 주석:
> "Only the cropping path needs this (batch_t_scores remains uncropped
> per its own docstring), but we scale both calls so a single yaml flag
> means 'be conservative across the whole report'."

= "필요 없다고 인정 + 그래도 줌". 주석이 코드 모순을 자기 자백.

추가 §9.4 위반: `test_cli.py:931-969` docstring 광고:
> "_do_dudect must pass scaled thresholds to welch_with_cropping /
> welch_t_test / **batch_t_scores**"

근데 실제 monkeypatch는 `welch_with_cropping` 하나뿐, `batch_t_scores`
는 캡처 0. test 통과해도 "광고된 일" 안 검증함.

- **Where**:
  - `ctkat/cli.py:782-783` (batch_t_scores 호출에 corrected threshold)
  - `ctkat/cli.py:679-680` (자기 모순 주석)
  - `tests/test_cli.py:931-969` (광고와 다른 검증 범위)
- **Symptom**: `bonferroni_correct=True` 면 batch별 단일 Welch에도
  sqrt(5)≈2.236배 inflated threshold 적용. 결과:
  - t=5.5 → 정상 WARNING이 PASS로
  - t=8.0 → 정상 FAIL이 WARNING으로
  배치별 환경 불안정 신호가 false PASS로 묻힘.
- **Why solve**: F20 fix Option A (`if bonferroni and crop` guard) 가
  main Welch만 고치고 batch_t_scores는 그대로. F20만 닫으면 이 사각지대
  잔존. test 광고도 거짓이라 §9.4 표본.
- **Acceptance criteria**: 둘 중 하나
  1. (Option A 권장) `batch_t_scores` 호출에는 보정 안 한 원본
     `dud.threshold_warning` / `dud.threshold_fail` 전달. 단일 검정이므로
     통계적으로 정합.
  2. (Option B) docstring/주석에 "batch에도 의도적으로 보수적 적용"
     명시하되 test_cli 검증 범위를 docstring과 맞춤.
  3. `test_bonferroni_correction_scales_thresholds` 가 실제로 batch_t_scores
     의 threshold도 monkeypatch 캡처 + assert.
- **Related**: F20 (bonferroni --no-crop), R2 (bonferroni 도입).
- **Suggested bundle**: Q-2 (F20 + F23 묶음 — 통계 정합성 한 번에).

### T30: welch_with_cropping `cutoffs[0]==1.0` honor-system 🟢 (v14)

**Status: OPEN.** `statistics.py:201-203` docstring 명시:
> "Caller must ensure cutoffs starts with 1.0 — otherwise the uncropped
> fields will be left as None and the all-cropping-fails fallback is lost."

근데 함수 본문에 `assert cutoffs[0] == 1.0` 같은 enforce 없음. caller
가 cutoffs override해서 1.0 안 넣으면 silent malfunction — `uncropped_t`
가 None으로 남아 verdict 계산에 영향.

- **Where**: `ctkat/statistics.py:194-203`
- **Symptom**: caller (현재는 cli.py 하나) 가 default `CROP_PERCENTILES`
  쓰면 OK. 그러나 향후 yaml에서 cutoffs override 옵션 추가 등이 일어
  나면 silent malfunction 가능. test 0.
- **Why solve**: CLAUDE.md §3 "주석 ≠ 코드" — docstring이 invariant
  claim하면 코드에서 enforce해야 함. T15 작업 (welch_with_cropping
  최적화) 때 손댄 함수인데도 honor-system 그대로.
- **Acceptance criteria**:
  1. 함수 진입 시 `if not cutoffs or cutoffs[0] != 1.0: raise
     ValueError("cutoffs must start with 1.0 — see docstring")`.
  2. test로 `cutoffs=[0.5, 1.0]` 등 invalid 던지면 raise 확인.
- **Related**: T15 (welch_with_cropping 최적화), R2.
- **Suggested bundle**: Q-4.

### T35: T23 본문 누락 — `SecretRegion.comment` 도 raw-interp surface 🚨 (v17)

**Status: OPEN.** v13 T23이 `BufferSpec.name/size`, `args`,
`SecretRegion.offset/length` 4종은 적었지만 **`SecretRegion.comment`
사이트는 통째로 누락**. v14 F22가 coverage probe까지 확장했지만 그
사이에도 comment는 미언급. v15/v16 cross-audit 도 못 잡음.

5회 audit이 같은 family를 한 site 미커버한 직접 사례 — CLAUDE.md §9.1
("광고 ≠ 검증") 의 재귀적 패턴: T23 본문 자체가 anchor가 되어 후속
audit이 그 acceptance criteria #3 list (`buffer_names`/`buffer_sizes`/
`arg_exprs`/`region_offsets`/`region_lengths`) 만 따라가서 comment를
못 봄.

- **Where**:
  - `ctkat/templates/harness_kem.c.j2:38` —
    `{% if r.comment %}/* {{ r.comment }} */{% endif %}`
  - `ctkat/templates/harness_sign.c.j2:36` — 동일
  - `ctkat/config.py:207` — `SecretRegion.comment: Optional[str] = None`
    (validator 0)
- **Symptom**: 실측 (v17 verify pass)
  ```python
  >>> from ctkat.config import HarnessConfig, SecretRegion
  >>> HarnessConfig(name='test', template='kem', header='api.h', prefix='X_',
  ...   secret_regions=[SecretRegion(offset='0', length='32',
  ...     comment='*/ #include "evil.h" /*')])
  # 통과. Jinja render시 C source에:
  # /* */ #include "evil.h" /* */
  # → C comment break-out + 임의 header include.
  ```
- **Why solve**: T23/F22 family와 정확히 같은 위협 모델. T23 fix가
  comment surface 빠진 채 merge되면 "C-source injection 차단" 광고가
  또 정확하지 않게 됨. CLAUDE.md §9.3 (메타-grep 의무) 위반의 직접
  사례 — `grep -n "{{ r\." templates/*.j2` 한 줄이면 즉시 잡힘.
- **Acceptance criteria**:
  1. T23 fix 시 `_check_yaml_identifiers` (또는 `SecretRegion` 자체
     validator) 에 `comment` 인자 추가. 정책: `[A-Za-z0-9_ .,;:()\-]*`
     같은 보수적 regex, 또는 `*/` substring 명시 거부.
  2. evil-input test (§9.4): `comment='*/ x /*'` yaml 박으면
     ValidationError 떨어지는 stdout 캡쳐.
  3. T23 acceptance criteria #3에 `region_comments` 추가 명시.
- **Related**: T23 (template injection family — comment site는 본문
  미언급), F22 (coverage probe surface).
- **Suggested bundle**: Q-1 (T23 + F22 + T34 + T35 묶음 — 같은
  validator family extension 한 commit).

### T36: `header_parser._line_of` 가 stripped text 기준 → `infer` 출력 line이 거짓 🟡 (v17)

**Status: OPEN.** `header_parser._parse_functions_impl` 가
`_strip_preprocessing(text)` 거친 **stripped text 안의 offset** 으로
`_line_of` 호출. stripped 과정의 `_BLOCK_COMMENT.sub(" ", text)` 가
multi-line block comment를 **단일 공백 한 칸**으로 치환 — comment
내부 newline 죄다 증발. 결과 stripped text의 line N과 raw header의
line N이 불일치.

사용자가 보는 `ctkat infer` 출력의 `Function: foo (api.h:25)` 가
api.h의 실제 line 25 아님. silent wrong attribution.

- **Where**: `ctkat/header_parser.py:88-95` (`_strip_preprocessing`,
  block comment 공백 치환), `:98-100` (`_line_of`), `:171-198`
  (`_parse_functions_impl` 가 stripped text 의 offset 으로 호출).
- **Symptom**: 실측 (v17 verify pass)
  ```python
  >>> src = '/* hello\n   world\n   foo */\nint bar(void);\n'
  >>> _parse_functions_impl(src, source_file='api.h')[0][0].source_line
  2     # raw header에서는 line 4 (int bar 줄)
  ```
- **Why solve**: CLAUDE.md §3 "주석 ≠ 코드" 위반 — `FunctionSig.
  source_line` docstring/사용 모두 "raw header line"으로 암시 (cli
  `_print_inferred` 가 `(file.h:25)` 형식으로 보임). pytest parser
  unit test 통과는 stripped text 안 line 검증만 — 사용자에게 노출
  되는 file:line semantics는 검증 안 됨. F15/T27 family (intent vs
  code mismatch).
- **Acceptance criteria**:
  1. `_strip_preprocessing`의 block comment 치환을 newline-preserving
     으로: 매치된 텍스트의 newline 개수만큼 `\n` 유지 + 나머지를 공백.
     `lambda m: "\n" * m.group(0).count("\n") + " "` 같은 형태.
  2. line directive 치환 (`_DIRECTIVE_LINE.sub("", text)`) 도 동일하게
     newline 유지하도록 점검 (현재는 `^...$` per-line이라 newline은
     보존됨 — `.sub("", text)` 라도 trailing `\n` 보존). 일단 확인만.
  3. test fixture에 multi-line block comment 박힌 header → parsed
     `source_line` 이 raw header line과 일치 검증.
- **Related**: F15 (intent vs code), T27 (sink 주석 거짓), T11/T13
  (parser plumbing).
- **Suggested bundle**: Q-3 (parser hardening, T31/T32와 묶음).

### T37: `CtConfig.harnesses` / `DudectConfig.harnesses` name uniqueness 미검증 → silent overwrite 🟡 (v17)

**Status: OPEN.** `HarnessConfig.name` / `DudectHarnessConfig.name`
각각 정규식 검증은 있지만 **list 단위 uniqueness validator 없음**.
사용자가 yaml에 같은 name 두 번 박으면 통과 → 후속 dict-keyed 자료
구조에서 silent overwrite.

F12 패턴 직접 재현 — backend 함수가 dict 생성 시 last-wins, user는
yaml에 박은 harness 중 하나가 verdict CSV 에서 사라진 걸 모름.

- **Where**: `ctkat/config.py:311-355` (`CtConfig.harnesses`,
  uniqueness validator 없음), `:484` (`DudectConfig.harnesses`,
  동일).
- **Silent overwrite 사이트**:
  - `ctkat/cli.py:298` `paths[h.name] = result.binary_path`
  - `ctkat/harness_generator.py:138-139` `output_dir / f"harness_{name}.c"`
    — 같은 path를 두 번 atomic-write
  - `ctkat/cli.py:927` `ct_map = {name: (status, findings) for ...}`
  - `ctkat/cli.py:928` `dud_map = {name: (r, batches) for ...}`
- **Symptom**: 실측 (v17 verify pass)
  ```python
  >>> CtConfig(harnesses=[
  ...   HarnessConfig(name='dup', template='generic', function='foo'),
  ...   HarnessConfig(name='dup', template='generic', function='bar'),
  ... ])
  # 통과. _do_generate → _do_ct 흐름에서 'foo' 호출 harness가 'bar'
  # 호출 harness 결과로 덮어쓰여 verdict CSV 에 1줄만 나옴.
  ```
- **Why solve**: F12와 정확히 같은 패턴 (user yaml은 valid해보이는데
  framework silently 잡아먹음). CLAUDE.md §1 (user-visible behavior
  검증) + §2 (semantic invariant — "harness name = primary key") 둘
  다 위반. T29 (`run` smoke test 0개) sibling — 다른 surface인 dup-
  name도 cover 0.
- **Acceptance criteria**:
  1. `CtConfig` 및 `DudectConfig` 에 `@model_validator(mode="after")`
     추가: `names = [h.name for h in self.harnesses]; if len(names) !=
     len(set(names)): raise ValueError(f"duplicate harness names: ...")`.
  2. evil-input test: 같은 name 두 번 박힌 yaml → ValidationError +
     중복 name 메시지 포함.
- **Related**: F12 (광고 기능 사망), T29 (`run` smoke test 부재).
- **Suggested bundle**: Q-3 (validator extension).

### T38: `examples/pqc_mlkem768/ctkat.yaml` 가 R1 Option B 본인을 우회 — 광고와 example drift 🟡 (v17)

**Status: OPEN.** Bundle J가 weak `randombytes` interpose로 PQClean
dudect 재현성 확보 (R1 Option B). README `§"재현성 (seed)"` 광고:
"PQClean common/randombytes.c를 sources에서 빼면 weak override가 적용
되어 bit-identical reproducible." 그런데 **example yaml 본인이 그
sources에 `common/randombytes.c` 박아둠** — 3개 harness 모두.

→ example 따라 만든 yaml에서 `dudect.seed: 0xC0FFEE` 박아도 keypair/
enc는 OS getrandom으로 entropy 가져옴. reproducibility 광고와 실제
동작 불일치.

- **Where**:
  ```
  $ grep -n randombytes examples/pqc_mlkem768/ctkat.yaml
  52:        - common/randombytes.c
  92:        - common/randombytes.c
  117:        - common/randombytes.c
  ```
  ct.harnesses[kem_dec] (line 52) + dudect.harnesses[kem_dec] (92) +
  dudect.harnesses[kem_dec_ct] (117) 셋 다. ct stage는 reproducibility
  무관 (Valgrind 결정론적) 이지만 dudect 둘은 R1 광고 적용 site.
- **Symptom**: example yaml로 `ctkat run`을 두 번 돌리면
  `dudect_raw_timings.csv` 가 매번 다름 (random keypair entropy
  변동). 광고는 "동일 seed → bit-identical".
- **Why solve**: CLAUDE.md §6 "example yaml과 default drift 방지"
  직접 위반. v17이 정확히 이 site를 적는 이유: T14 (yaml `-fno-lto`
  누락) 가 lint test로 한 번 잡혀야 함 광고했는데, 같은 family인
  randombytes 우회 site는 lint에 미커버. example이 광고를 정정하지
  않으면 사용자가 example 그대로 박고 reproducibility 가정 → CI
  flaky verdict.
- **Acceptance criteria**: 둘 중 하나
  1. (Option A 권장) `examples/pqc_mlkem768/ctkat.yaml` dudect 두
     harness의 `sources` 에서 `common/randombytes.c` 제거. 두 ct
     stage는 그대로 (Valgrind 무관).
  2. (Option B) README/tutorial에 "ML-KEM example은 reproducibility
     non-goal — Valgrind 분석 + 정성 timing 비교만" 명시. example
     주석에도 한 줄 추가.
  3. 어느 쪽이든 T14 yaml lint test 에 `examples/*/ctkat.yaml`
     reproducibility check 추가 — Option A는 randombytes.c 미포함
     검증, Option B는 README cross-link 검증.
- **Related**: R1 (PQClean reproducibility), T14 (yaml lint family).
- **Suggested bundle**: Q-2 (housekeeping + example sweep).

### T39: `BuildConfig.argv=[]` 통과 → `run_argv([])` IndexError raw 🟢 (v17)

**Status: OPEN.** `BuildConfig._check_mode` 가 `(command is None) ==
(argv is None)` 만 검사 — `argv: []` + `command: null` 박으면
(False == False) → 통과. `builder.run_step` 가 `if argv is not None`
분기에서 `run_argv([])` 호출 → `subprocess.run([])` → `IndexError:
list index out of range` raw Python traceback.

`KatConfig._check_mode` 도 동일 패턴 (line 176-183).

- **Where**: `ctkat/config.py:140-147` (`BuildConfig._check_mode`),
  `:176-183` (`KatConfig._check_mode`), `ctkat/builder.py:88-90`
  (`run_step` 분기).
- **Symptom**: 실측 (v17 verify pass)
  ```python
  >>> BuildConfig(argv=[], workdir='.', timeout=600)  # 통과
  >>> run_step(command=None, argv=[], workdir=Path('.'), timeout=10)
  IndexError: list index out of range
  ```
- **Why solve**: T33 (`--seed abc` traceback) sibling — user-facing
  surface에서 raw Python traceback. T4 (shell=False argv 옵션) 이
  광고한 "구조적 안전성" 이 본인의 빈-list corner 미커버.
- **Acceptance criteria**:
  1. `BuildConfig._check_mode` 및 `KatConfig._check_mode` 에 `if
     argv is not None and len(argv) == 0:` 케이스 추가, ValueError
     로 거부. 메시지: `"argv must be a non-empty list (got [])"`.
  2. test로 `argv: []` yaml ValidationError 확인.
- **Related**: T4 (shell=False argv 옵션), T33 (CLI input 미검증).
- **Suggested bundle**: Q-4 (cleanup).

### T40: `ctkat parse <missing.log>` raw FileNotFoundError traceback 🟢 (v17)

**Status: OPEN.** `cli.py:1280` `text = log.read_text(...)`. typer
`Argument(..., help=...)` 는 type 검증만, `exists=True` 옵션 없음.
미존재 path 박으면 `FileNotFoundError` raw traceback이 user 에게.

T33 family — CLI input validation 비대칭. parse 서브가 F12 (`ctkat
parse` 광고 기능 사망) fix의 직접 surface인데 missing-file path는
그대로 fragile.

- **Where**: `ctkat/cli.py:1275-1281` (parse 서브 정의 + read_text).
- **Symptom**: 실측 (v17 verify pass)
  ```
  $ python3 -m ctkat parse /nonexistent/foo.log
  ╭───── Traceback ─────╮
  │ cli.py:1280 in parse                 │
  │ FileNotFoundError: ...               │
  ```
- **Why solve**: F12 fix가 광고 기능 살린 직후 surface인데 정작
  user input validation은 빈손. CLAUDE.md §1 (user-visible surface
  smoke test) + §9.4 (evil-input 시연 의무).
- **Acceptance criteria**:
  1. typer 시그니처 `log: Path = typer.Argument(..., exists=True,
     file_okay=True, readable=True, help=...)` 로 교체. typer가
     "File '...' does not exist" 자동 메시지 + Exit(2) 처리.
  2. test로 `runner.invoke(app, ["parse", "/nonexistent.log"])` 의
     exit_code==2 + traceback 없음 확인.
- **Related**: F12 (parse 광고 기능 사망), T33 (CLI input 미검증).
- **Suggested bundle**: Q-4 (cleanup).

### T41: standalone `ctkat dudect` 서브커맨드가 ERROR/empty를 PASS exit 0으로 처리 🚨 (v18)

**Status: OPEN.** `cli.py:896-907` (dudect 서브 종결 로직). 오직
`status == "FAIL"` / `"WARNING"` 만 체크하고 `"ERROR"` (timeout / crash /
insufficient-samples = `_error_welch()` 센티넬, cli.py:540-551)를 아무도
안 봄. 모든 하니스가 ERROR면 `any_fail=any_warn=False` → 907줄로 굴러떨어져
초록불 `PASS` + **exit 0**. 빈 하니스(`harnesses: []`)도 `any(...)`가 빈
시퀀스에 False → 측정 0개인데 동일하게 PASS exit 0.

```python
# cli.py:896-907 — ERROR 분기가 없음
any_fail = any(r.status == "FAIL"    for _, _, r, _ in results)
any_warn = any(r.status == "WARNING" for _, _, r, _ in results)
if any_fail: ... Exit(2)
if any_warn: ... Exit(2)
console.print("[bold green][CTKAT] dudect Timing Check: PASS[/]")  # ← ERROR/empty 여기로
```

F2/F5/T6가 `run` 파이프라인에서 "ERROR → INCONCLUSIVE → exit 2"로 막은
fail-open이, **verdict 레이어를 안 거치는 standalone `dudect` 서브커맨드에
그대로 재현됨.** `_do_dudect` 주석(cli.py:728-729)은 "ERROR가
`_compute_verdicts` → INCONCLUSIVE로 흐른다"고 광고하지만 그건 `run()`에서만
참 — `dudect()`는 `_do_dudect` 결과를 verdict 레이어 없이 직접 소비함
(주석 claim ≠ 코드, CLAUDE.md §3).

- **Where**: `ctkat/cli.py:850-907` (`dudect` 서브), 종결 로직 896-907.
  ERROR 생산 site: cli.py:743 / 750 / 757 / 768 (timeout / crash / unparseable /
  insufficient-samples 전부 `_error_welch()` append).
- **비대칭 증거** (§7 scope 한정 함정 — 같은 fail-open이 다른 site에):
  - `run()` : `any_inconclusive` 체크 → Exit(2) (cli.py:1093, 1097) ✅
  - `ct()`  : `any_ct_error` 체크 → Exit(2) (cli.py:1127, 1138) ✅
  - `dudect()` : **ERROR/empty 무점검** → PASS exit 0 (cli.py:896-907) ❌
  - cf. F7/F8은 "섹션 없음(`cfg.dudect is None`)" 비대칭만 닫음(cli.py:870)
    — "ERROR-status" 비대칭은 통째로 놓침.
- **Symptom**: 실측 (v18 verify pass, `typer.testing.CliRunner` + `_do_dudect`
  를 ERROR/empty 리턴으로 mock):
  ```
  Case A (ERROR 하니스):  exit_code = 0,  stdout 에 "Timing Check: PASS"
  Case B (빈 results)  :  exit_code = 0,  stdout 에 "Timing Check: PASS"
  Control (FAIL 하니스) :  exit_code = 2   ← 러너 정상 동작 확인
  ```
  `ctkat dudect -c x.yaml && deploy` CI 게이트가 타이밍 측정이 통째로
  실패(또는 미정의)해도 배포함.
- **Why solve**: Tier-1 verdict-integrity 불변식("못 verify했으면 못
  했다고 말하라")을 정면 위반. 단일-stage 서브커맨드는 CI 게이트용으로
  명시 설계(F7/F8 본문) — 그 exit code는 contract. CLAUDE.md §9.4
  (evil/edge-input 시연 의무)로 잡힘.
- **Acceptance criteria**:
  1. `dudect()`에 `any_err = any(r.status == "ERROR" for _, _, r, _ in results)`
     추가, `if any_fail or any_err: Exit(2)` (ct() 패턴 미러). ERROR 행은
     INCONCLUSIVE/INCOMPLETE 메시지로 표기.
  2. 빈 `results` 가드 — 하니스 0개면 빨간 메시지 + Exit(2) (측정 안 했으면
     PASS 금지). dudect.harnesses 빈 list 거부 또는 명시 경고.
  3. `_do_dudect` 주석(cli.py:728-729)의 "ERROR → INCONCLUSIVE" 문구를
     "`run`에서만; `dudect` 서브는 별도 게이트 필요"로 정정.
  4. test: `runner.invoke(app, ["dudect", ...])` 가 ERROR/empty 결과에서
     `exit_code == 2` (위 실측을 회귀 테스트로 박제).
- **Related**: F2/F5/T6 (ERROR status 생산 — `run`에선 INCONCLUSIVE),
  F7/F8 (서브커맨드 "섹션없음" 비대칭 — 닫힘), F3 (INCONCLUSIVE 정책),
  CLAUDE.md §7 (메타-grep) / §9.4 (evil-input 시연).
- **부가 관찰 (미카탈로그, LOW)**: `_HEADER_PATTERN` (config.py:22) 주석은
  "provably contained"라 광고하나 `.`/`/`/`-` 허용으로 `header:
  ../../../etc/passwd` · `/etc/hosts` path traversal 통과 → 임의 파일이
  `#include` 대상이 됨. T20/T23 injection surface의 미커버 axis.
- **Suggested bundle**: R-1 (verdict-integrity hot-fix; T41 #1+#2 우선).

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

**Status: RESOLVED in Bundle M.** sk-leak brunch가 양 class 모두
`crypto_kem_enc()`로 valid ct 생성하도록 재설계:
- cls=0 → `crypto_kem_enc(ct, ss, pk_fixed)` (sk_fixed에 매칭된 valid ct)
- cls=1 → `crypto_kem_keypair(pk_random, sk_random)` + `crypto_kem_enc(ct,
  ss, pk_random)` (sk_random에 매칭된 valid ct)

양 class 모두 정상 dec path를 측정 — sk-content dependent timing이 광고
대로 측정됨. 의미적 invariant 회귀 테스트 3개 (`test_kem_sk_leak_uses_valid_ct_for_both_classes`,
`test_kem_sk_leak_warmup_uses_valid_ct`, `test_kem_macro_warm_and_timed_dec_use_identical_args`)
박힘. README §"KEM leak axes" 표 갱신 (측정 path 컬럼 추가) + Bundle M
audit fix 단락 인정.

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

**Status: RESOLVED in Bundle M.** 매크로 warm step을 `rand_bytes(ct_warm) +
dec(ct_warm)` → `dec(ct_expr, sk_expr)` 로 교체. warm dec와 timed dec가
완전히 동일한 (ct, sk) pair를 사용 → cache state가 실제로 "방금 이 path를
돌고 왔다" 상태. ct_warm 변수 삭제 (사용처 없음).

warmup loop도 mode-aware로 정정 (이건 F14의 logical extension):
- sk-leak: 단일 valid ct를 enc로 만든 뒤 dec loop (정상 path)
- ct-leak: ct_fixed로 dec loop (정상 path)
- fo-leak: random ct로 dec loop (FO path — measurement loop가 mixed라
  burn-in은 longer-running path로 잡는 게 유리)

회귀 테스트 `test_kem_macro_warm_and_timed_dec_use_identical_args` +
`test_kem_ct_leak_warmup_uses_fixed_valid_ct` + `test_kem_sk_leak_warmup_uses_valid_ct`
박힘. README §"KEM leak axes"에 cache-balance 정정 내용 명시.

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

**Status: RESOLVED in Bundle N.** 신규 `ctkat/_proc.py` 의 `run_text(argv,
*, timeout, ...)` 헬퍼가 timeout 인자를 keyword-only 필수로 강제 (default
없음 — type error로 거부됨). 5개 call site 일괄 교체: `builder.run_shell`,
`builder.run_argv`, `valgrind_runner.run_valgrind`, `harness_generator.compile_harness`,
`timing_harness_generator._compile`. coverage_check도 같은 헬퍼로 통일.
yaml 필드 신규: `BuildConfig.timeout`, `KatConfig.timeout`,
`CtConfig.compile_timeout`/`valgrind_timeout`, `DudectConfig.compile_timeout`
(`DudectConfig.timeout`은 T6에서 이미 도입됨). TimeoutExpired → 각 stage의
ERROR/INCONCLUSIVE 흐름으로 wrap. 회귀 테스트
`test_build_timeout_yields_fail_not_hang` + `test_run_text_requires_timeout_keyword`
+ `test_run_text_timeout_raises_timeoutexpired` 박힘.

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

**Status: RESOLVED in Bundle P.** `header_parser.parse_header_file_with_stats`
wrapper 신설, cli `infer` 서브가 `parse_header_file` → `parse_header_file_with_stats`
로 갈음. 헤더별 skip 합산 → 0보다 크면 dim note "N declaration(s) skipped
by the strict regex" 출력. 회귀 테스트 `test_infer_surfaces_skipped_declaration_count`.

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

**Status: RESOLVED in Bundle P.** `welch_with_cropping`을 redesign:
c0/c1 각자 한 번씩 sort 후 cutoff별로 `bisect_right`로 prefix 인덱스만
계산, 그 위치까지 슬라이스. 5×2=10번 호출되던 O(N log N) sort가 2번으로
줄어듦. 결과값은 bit-identical (회귀 테스트
`test_welch_with_cropping_bit_identical_after_T15_optimization`이 기존
"sort per cutoff" 로직 reimpl과 결과 일치 검증).

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

**Status: RESOLVED in Bundle P.** 신규 `_BINARY_LOCATION_RE = ^in\s+(.+)$`
패턴을 `_parse_frame_location`에 추가. `(in /lib/libc.so.6)` 형식 location은
file=`/lib/libc.so.6`, line=None으로 명시적 surface — 이전엔 file=`in /lib/...`
literal string으로 새서 stack trace render시 혼란. 회귀 테스트
`test_frame_with_binary_only_location_keeps_path_as_file`.

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

**Status: RESOLVED in Bundle N.** T12와 같은 헬퍼 (`_proc.run_text`) 에
`encoding='utf-8', errors='replace'` 정책 박혀 — 7곳 모두 한 번에 적용됨.
하네스가 invalid utf-8 bytes 뱉어도 Python parent는 raw traceback 안 던지고
U+FFFD replacement character로 surface. 회귀 테스트
`test_run_text_garbage_bytes_do_not_raise_unicodedecodeerror` 박힘.

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

**Status: RESOLVED in Bundle P.** `harness_generator._atomic_write_text`
헬퍼 신설 — `tempfile.mkstemp(dir=path.parent)` 로 같은 디렉토리에
임시 파일 만들고 `os.replace()` 로 atomic rename (POSIX rename(2) +
Windows ReplaceFile 모두 atomic). 동시 실행하는 두 ctkat 프로세스가
같은 `_generated/harness_foo.c`에 쓰더라도 reader는 항상 *어느 한 쪽의
완전한 내용* 만 보게 됨 (절반 쓴 파일 노출 없음). harness_generator와
timing_harness_generator 둘 다 사용. 회귀 테스트 두 개
(`test_atomic_write_text_replaces_full_content`,
`test_atomic_write_text_uses_utf8_encoding`).

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

**Status: RESOLVED in Bundle O.** T7 follow-up까지 함께 처리:
- `_check_yaml_identifiers` 모듈 레벨 helper 신설 (`config.py`).
  세 regex 정책 박힘:
  * `_HEADER_PATTERN = ^[A-Za-z0-9_./+-]+$` — `#include "..."` escape
    문자 (quote, backslash, newline) 차단. 실제 헤더명 (`api.h`,
    `pqclean/include/foo.h`, `libc++/v1/x.hpp`, `gmp-6.h`) 다 통과.
  * `_C_IDENT_PATTERN = ^[A-Za-z_][A-Za-z0-9_]*$` — `function`, `prefix`
    (빈 문자열 default 허용).
  * `_C_TYPE_PATTERN = ^[A-Za-z_][A-Za-z0-9_:* ]*$` — `return_type`
    (포인터/const/namespaced 허용, quote/semicolon/brace 차단).
- `HarnessConfig._check_mode` + `DudectHarnessConfig._check_mode` 둘
  다 호출. coverage probe(`_render_sentinel_c`)도 같은 validator 거친
  값만 받음 → T20에서 지목한 C-source injection surface 자동 차단.
- 회귀 테스트 8개 (`test_harness_header_with_quote_rejected`,
  `test_harness_extra_headers_with_newline_rejected`,
  `test_harness_prefix_must_be_valid_c_identifier`,
  `test_harness_prefix_empty_is_allowed`,
  `test_harness_pqclean_prefix_passes`,
  `test_harness_function_must_be_c_identifier`,
  `test_dudect_harness_header_with_quote_rejected`,
  `test_harness_subdir_header_allowed`).

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

**Status: RESOLVED in Bundle N.** 6개 read/write 사이트에 명시적 인코딩
박힘:
- write (생성하는 utf-8 source): `harness_generator`, `timing_harness_generator`,
  `coverage_check` — `encoding="utf-8"` (errors 불필요, 우리가 만든 utf-8).
- read (외부 출력 / 미지의 헤더): `cli` (valgrind log × 2), `qemu_detect`
  (/proc DMI), `header_parser` — `encoding="utf-8", errors="replace"`
  (외부 데이터는 garbage 가능성 있어 replace 정책).

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

**Status: RESOLVED in Bundle P.** `_print_dudect_summary`에 `r.status ==
"ERROR"` 분기 추가 — n0/n1/mean/|t|/batch_max cell 모두 `-` 출력, crop@과
status cell만 정상. ERROR status는 bold magenta 색상으로 시각적 구분.
회귀 테스트 `test_dudect_summary_error_row_hides_numeric_cells` (Rich
Console 출력을 StringIO로 capture해서 검증).

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

**Status: RESOLVED in Bundle P.** `check_secret_region_coverage`에
`extra_compile_args` 인자 추가. cli `_do_generate`가 해당 harness의 effective
cflags를 그대로 전달. probe 빌드 명령 형성 시 `_filter_probe_cflags` 헬퍼가
preprocessor-affecting flag (`-D`/`-U`/`-isystem`/`-iquote`/`-I`)만 골라
넣고, `-O*`/`-g`/`-fno-lto` 등은 dropping (probe는 의도적으로 `-O0`,
다른 flag와 충돌 가능). `#ifdef CONFIG_X` chain 박힌 사용자 헤더도 이제
probe가 동일 macro state로 컴파일 → F6 효과 환경 의존성 제거. 회귀 테스트
`test_filter_probe_cflags_keeps_define_and_include_only`.

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

### v17 — anchor-free + 메타-grep 재발견 (2026-05-28)

v16 직후 같은 모델 1회 더, 단 prompt 비대칭화 (CLAUDE.md §9.2): anchor
무시 + 메타-grep 명시 첫 step (`grep "{{ r\." templates/*.j2`,
`grep "harnesses:" examples/*/`, `grep "Argument(" cli.py`,
`grep "open(\|read_text\|write_text" ctkat/`). v13~v16 5회 audit 의
finding 24개 (v13:9 + v14:3 + v15:4 + v16:2 + v17:6, 보정 후) 중 v17
이 추가한 6개 모두 코드 grep + repro로 verify 완료.

**6 new findings (전부 실측 검증)**:
- **T35** 🚨: v13 T23 본문 누락 — `SecretRegion.comment` 가 5개
  template 중 2개 (`harness_kem`, `harness_sign`) 에서 raw-interp.
  T23 acceptance criteria #3 list (`buffer_names`/`buffer_sizes`/
  `arg_exprs`/`region_offsets`/`region_lengths`) 가 audit anchor 가
  되어 v14/v15/v16 4회 cross-audit 모두 `r.comment` 미발견. **v17의
  메타-grep `grep "{{ r\." templates/*.j2` 한 줄이 즉시 잡아냄**.
  CLAUDE.md §9.1 (광고 anchor) 의 재귀적 발현 직접 사례 — T23 본문
  자체가 자기 후속 audit의 anchor가 됨.
- **T36** 🟡: `header_parser._strip_preprocessing` 가 multi-line
  block comment를 단일 공백으로 치환 → `_line_of` 가 stripped text
  기준 line 반환 → `ctkat infer` 출력의 `(file.h:N)` 가 raw header
  의 실제 line과 불일치. user-visible behavior 깨짐. 파서 unit
  test 통과는 stripped 안 line만 검증 — §1 위반. F15/T27 family
  (intent vs code mismatch).
- **T37** 🟡: `CtConfig.harnesses` / `DudectConfig.harnesses` name
  uniqueness validator 부재. yaml 에 같은 name 두 번 박으면 통과 →
  `_do_generate` / `ct_map` / `dud_map` dict 생성 시 last-wins
  silent overwrite. F12 패턴 (광고 기능 사망) 직접 재현 — verdict
  CSV 에 사용자 yaml 의 harness 중 하나가 사라짐.
- **T38** 🟡: `examples/pqc_mlkem768/ctkat.yaml` 의 dudect harness
  3곳 (line 52, 92, 117) 가 sources 에 `common/randombytes.c` 박아둠
  → R1 Option B (weak randombytes interpose) 가 strong link 우선에
  무력화. README 광고 "동일 seed → bit-identical" 과 실제 동작
  drift. example yaml lint 미커버. T14 sibling.
- **T39** 🟢: `BuildConfig._check_mode` 가 `argv=[]` 통과 →
  `subprocess.run([])` IndexError raw traceback. KatConfig 도 같은
  패턴. T33 (`--seed abc`) sibling — CLI/yaml input 미검증 family.
- **T40** 🟢: `ctkat parse <missing.log>` 가 typer `Argument(...,
  exists=True)` 없어서 FileNotFoundError raw traceback. T33 sibling.

**메타 통찰**:

1. **list-anchor 함정 직접 입증**: T23 본문이 acceptance criteria
   #3 에 4종 필드 명시 → v14/v15/v16 cross-audit 이 그 list 따라가서
   같은 family 한 site (`r.comment`) 통째로 미커버. v15 의 "다른
   모델 cross-check" 도 list anchor 자체는 못 깸. §9.3 메타-grep 의무
   가 list-anchor 회피의 유일한 백업이라는 것 재확인.

2. **메타-grep 강제 prompt 효과**: v13 §9.3 적었지만 honor system
   이라 LLM 자주 어김 (v14, v15, v16 셋 다 메타-grep 단계 명시 안
   함). v17 prompt 에서 첫 step 으로 `grep "{{" templates/*.j2`,
   `grep "Argument(" cli.py`, `grep "harnesses:" examples/*/` 박은
   결과 T35 + T39 + T40 + T38 4개가 그 grep 직접 결과. 메타-grep을
   prompt 의 step #1 으로 명시하면 LLM 의 working memory 에 site
   list 가 들어와서 list-anchor 우회 효과.

3. **24개 OPEN 누적**: v13:9 + v14:3 + v15:4 + v16:2 + v17:6 = 24개.
   모두 코드 그대로. Bundle Q (제안) 가 validator family (Q-1) +
   통계 정합 (Q-2) + parser hardening / test smoke / example sweep
   (Q-3) + cleanup (Q-4) 로 묶으면 ~20개 닫음. 다만 Q-1 정의 시
   T35 (comment) 명시적으로 포함해야 또 anchor 재발 안 함.

4. **§9.6 audit ≠ fix lag 재확인**: v13 audit 후 v14/v15/v16/v17
   네 번 더 audit. fix 0. audit ritual 패턴 그대로. 사용자가 다음
   action 으로 Bundle Q 분기/시간 잡고 실제 fix commit 해야 lag 끊김.

5. **anchor-free + 메타-grep 조합 ROI**: 같은 모델 1회 + prompt
   비대칭화로 6개 새 finding. v15 가 다른 모델 1회로 4개, v16 이 또
   다른 모델 1회로 2개. **§9.2 가설 (cross-model 효과) 와 §9.3 가설
   (메타-grep 효과) 둘 다 실측 — cross-model 없이도 메타-grep prompt
   엔지니어링으로 비슷한 ROI 가능**. cross-model 은 매번 의무 아니라
   는 §9.2 결론 강화.

### v16 — 또 다른 모델 cross-audit (2026-05-28)

v15 직후 또 다른 모델로 한 번 더. v15 finding (header_parser, CSV row,
CLI input) 영역은 이미 다뤄졌고, **v16은 또 다른 angle에서 2개 layer
발견** — validator 자체의 regex 무결성 + bonferroni의 batch_t_scores
사각지대 + test docstring 광고와 실제 검증 범위 mismatch.

**2 new findings**:
- **T34** 🟢: `_check_yaml_identifiers` 의 `.match()` 가 trailing `\n`
  통과. Python `re` 의 `$` 는 "문자열 끝 또는 마지막 `\n` 직전" 매치라
  `.match()` 로는 trailing newline 검증 못 함. 5개 site 다 `.fullmatch()`
  필요. T23/F22 fix가 어차피 같은 validator family라 묶어서 닫기 좋음.
  보안 도구의 validator 자체에 구멍이라 🟢여도 시급.
- **F23** 🟡: F20 (bonferroni --no-crop) 의 사각지대 — corrected
  threshold가 `batch_t_scores` 까지 전달. 단일 검정에 다중비교 보정
  적용이라 통계적 근거 없음. cli.py 본인 주석이 "필요 없다고 인정 +
  그래도 줌" 으로 자기 모순. 추가로 `test_cli.py:931-969` docstring이
  "batch_t_scores 도 검증한다" 광고하지만 실제 monkeypatch는
  welch_with_cropping 하나뿐 — §9.4 (test 광고 ≠ 실제) 표본.

**메타 통찰**:

1. **다른 모델의 attention domain 효과 또 입증**: v15가 header_parser/
   CSV row 같은 deep layer 잡았다면, v16은 validator 자체의 regex 무결성
   같은 또 다른 layer. anchor 자체가 무한 layer로 재귀하니까 audit 한
   번에 다 잡는 건 불가능. 다만 정기 cross-check 가 ROI 좋다는 건 v15/v16
   에서 일관되게 보임.
2. **test가 광고를 backstop 못 함의 또 다른 사례**: F23의 test는
   batch_t_scores 검증한다고 docstring에 적었지만 monkeypatch 안 함.
   pytest 통과해도 "광고된 일"은 검증 안 됨. §9.4의 가장 명백한 표본.
3. **anchor 재귀의 실용적 의미**: §9.6의 "이게 마지막 audit인가" 질문이
   매번 No로 답 나옴 (v13→v14→v15→v16). 결론은 "한 번에 다 잡으려
   하지 말고 정기 audit 으로 누적된 layer 천천히 깎기" 가 현실적.
   매번 다른 모델 의무화는 과함, 큰 변경 끝나면 가끔 다른 모델 1pass
   정도면 충분 (CLAUDE.md §9.2 톤 다운 반영).

**v16의 의의**:
- 18개 OPEN finding (v13:9 + v14:3 + v15:4 + v16:2). 모두 코드 그대로.
- §9.2 "가끔 다른 모델 cross-check" 의 일관된 효과 입증.
- CLAUDE.md §9.2/§9.6 톤 다운 (강박 → 가벼운 권장) 반영.

### v15 — cross-model audit: 다른 layer 4 new (2026-05-27)

CLAUDE.md §9.2 ("같은 모델 N회 review ≠ 사람 N회 review") 의 첫 실험.
v13/v14 작성 모델과 **다른 모델 1pass** 로 anchor-free audit. v13/v14
가 자랑한 "anchor-free"가 실제로는 own attention domain (template/config/
CLI flag interaction) 에 anchor됨이 드러남. **4개 새 finding 다 깊은
layer** — header_parser regex, CSV row validation, CLI input handling
— v13/v14가 한 번도 안 본 영역.

**4 new findings**:
- **T31** 🟡: `_ATTRIBUTE` regex 가 `[^)]*` 라 nested paren 못 처리.
  `__attribute__((nonnull(1)))` 들어있는 함수가 **silently disappear**
  (skip count 에도 안 잡힘 — T11/T13 광고 우회).
- **T32** 🟡: `_parse_param` 의 `if name == "*":` 가드가 단일 포인터만
  처리. 익명 `uint8_t **` → `name='**', type='uint8_t', is_pointer=False`
  완전 깨짐. bare type (`size_t` 단독) 도 동상. `secret_infer` 가 buffer
  를 scalar로 분류해 wrong hint.
- **T33** 🟢: `cli.py:882` `int(seed, 0)` 예외 처리 없음. `--seed abc`
  → Python traceback. CLI input validation이 yaml validation에만 있고
  direct CLI path는 무방어.
- **S5** 🟡: `parse_timing_csv` 가 `cls ∉ {0, 1}` row 를 silent하게
  분석 제외. raw_n_total ≠ n0+n1 gap 생기는데 warn 0. F4/S1 family
  미커버 site.

**메타 통찰** (CLAUDE.md §9.2 표본):

1. **"anchor-free" 자랑의 함정**: v13/v14 가 anchor-free라 자랑했지만
   own attention domain에 anchor됨. anchor-free는 절대 개념이 아니라
   상대 개념 — "어느 anchor로부터 free인가" 가 항상 따라옴. v13/v14
   는 "Bundle commit message anchor"에서 free였지만 "본인의 audit
   scope anchor"에는 갇힘. v15는 다른 모델이라 다른 attention domain
   가져옴.
2. **§9.2 의 ROI 실증**: cross-model 1pass 가 같은 모델 N pass 보다
   확실히 새 layer 발견. v15 finding 4개가 다 **v13/v14가 한 번도 안
   본 file** 에서 나옴 (header_parser.py, dudect_runner.py CSV path,
   CLI input parse). same-model N pass였으면 또 template/config 만 봤을 것.
3. **anchor 무한 재귀**: v13 (Bundle anchor에서 free) → v14 (v13 anchor
   에서 free) → v15 (v13/v14 anchor에서 free). 다음 layer 가 또 있을
   것 (v15가 못 본 deep layer). 결론은 "anchor 완전 제거 불가, 가장
   가까운 anchor만 풀 수 있음" — 정기 audit + 모델 다양성이 필수.
4. **사용자 워크플로우 implication**: Bundle Q를 v13/v14/v15 작성 모델
   다 다른 모델로 짜야 §9.6 위반 회피. 또는 Q 끝나면 또 다른 모델로
   audit-of-Q 필수.

**v15의 의의**:
- §9.2의 첫 실증 — cross-model 효과 입증.
- 16개 OPEN finding으로 확장 (v13:9 + v14:3 + v15:4).
- "anchor-free 자랑은 또 다른 anchor" 라는 메타-메타 통찰.

### v14 — meta-meta-audit: v13 광고 vs 코드 verify + 3 new (2026-05-27)

v13가 9개 finding을 known_issues.md에 적은 직후, **다른 세션이** v13의
광고를 코드 grep으로 verify. 결과: v13 finding 9개 다 코드에 그대로
살아있음 + 3개 새 hole. v13가 적기만 하고 fix commit 안 한 게 드러남.

**3 new findings**:
- **F22** 🚨: coverage probe도 injection surface — `coverage_check._render_sentinel_c`
  의 `secret_region_lengths` raw embed. v13 T23이 template 5개는 잡았지만
  coverage probe site 누락. CLAUDE.md §9.3 메타-grep을 string-interpolation
  까지 확장해야 한다는 교훈.
- **T29** 🟢: `ctkat run` smoke test 0개. infer/ct/kat/dudect/parse는 있는데
  `run`만 없음. F12 (parse NameError) 와 정확히 같은 root cause 재현 가능.
  v13 audit이 backend 함수 / template / config 중심이라 test corpus 자체의
  gap을 못 봄.
- **T30** 🟢: `welch_with_cropping` docstring "cutoffs must start with 1.0"
  honor-system. assert 없음. T15 작업이 함수 만지면서도 enforce 안 넣음.

**메타 메타 통찰** (CLAUDE.md §9.6 신설):

1. **v13 itself가 §9.1 표본**: v13가 "anchor-free audit으로 9개 잡음"이라
   광고했지만 v14가 verify해보니 그 광고 자체가 또 광고만이고 코드는 그대로.
   **audit이 의식(ritual)이 되면 audit도 광고로 변함**. 즉 §9.1이 audit
   layer에도 재귀적으로 적용됨.
2. **audit ≠ fix lag**: 같은 모델이 audit과 fix 둘 다 하면 자기 finding
   scope에 anchor됨. T23이 args 광고에 포함했지만, fix bundle 단계에서
   anchor 강해지면 args 빼먹을 가능성. **audit과 fix는 다른 세션으로
   분리**가 안전.
3. **"이게 마지막 audit"이라는 가정 자체가 위험**: 보통 finding N개 적은
   직후가 anchor 가장 강한 시점이라 다음 audit이 또 같은 hole 본다는 게
   v14의 의의. 정기 audit (§9.5) 의 implication이 "한 번 했으니 OK" 가
   아니라 "한 번 했으니 다음에 또 해야 함" 인 이유.
4. **사용자 워크플로우 implication**: v13 finding 적은 LLM이 Bundle Q
   짜면 §9.6 위반 위험. Bundle Q는 **다른 모델 / 다른 세션** 으로
   짜거나, 사용자가 fix 시작 prompt에 "v13/v14 적은 모델 아님" 명시.

**v14의 의의**:
- v13 광고 verify로 12개 finding (v13:9 + v14:3) 모두 코드 그대로임을
  확인. known_issues.md status 의 "광고 / 실제" 분리 도입.
- CLAUDE.md §9.6 "audit ≠ fix" 신설. §9.5 (정기 audit) 와 짝.
- 후속 안전 절차: Bundle Q 작성 모델 ≠ v13/v14 작성 모델. cross-session
  enforcement. Q 끝나면 다시 audit-of-Q (다른 세션).

### v13 — post-Bundle-P anchor-free meta-audit (2026-05-27)

v12의 "0 still open. 🎉" claim 직후 진행된 메타 audit. 핵심 차이:
**기존 audit이 anchored ("Bundle X가 닫았다고 한 게 맞나" 검증)였다면,
v13은 anchor-free ("known_issues.md / Bundle commit message 무시하고
코드만 grep")**. 결과: 9개 new finding.

**9 new findings**:

- **T23** 🚨: T20 (Bundle O) 미완 — `BufferSpec.name`, `BufferSpec.size`,
  `args` 항목, `SecretRegion.offset/length` 4종 yaml 필드가 5개 template
  에서 raw-interpolation. Bundle O가 "C-source injection surface 자동
  차단" 광고했지만 검증된 surface는 5개 필드만, 나머지 4종은 그대로.
  v13에서 가장 큰 finding — 광고와 실제 차이가 명백.
- **F19** 🚨: F16 (Bundle L) 우회 — `cli.py:663` `secrets.randbits(63)`
  fallback이 0 반환 가능 (2^-63). 0 corner에서 Python/C layer 불일치
  재현. `or 0xC0FFEE` 한 줄로 닫음.
- **T24** 🟡: T21 (Bundle N) 미완 — `open()` 6곳 encoding 미지정.
  `Path.read/write_text`만 잡았고 `open()` 직접 호출은 미점검.
  `config.py:561` (yaml load) 가장 critical.
- **F20** 🟡: docstring ≠ 코드 — `bonferroni_correct: true` + `--no-crop`
  조합에서 single Welch에 sqrt(5) scaling 잘못 적용. docstring은
  cropping 한정이라 명시.
- **F21** 🟡: F6 (Bundle F) 미완 — coverage probe가 ratio만 검사.
  region overlap (sum > total) / OOB (offset 큰 값으로 stack taint)
  미검사.
- **T25** 🟢: dead code 2곳 — `cli.py:189` IndexError unreachable,
  `config.py:44` `prefix is not None` guard dead.
- **T26** 🟢: `statistics.py:237` `bisect_right` import가 for 루프
  안. micro-perf.
- **T27** 🟢: `harness_generic.c.j2:67-79` sink 주석 거짓 ("consumes
  every byte"라 했지만 실제론 주소+sizeof만 XOR).
- **T28** 🟢: silent parse-fail 2곳 (cli.py:189 KAT count, coverage_check.py:179
  sentinel).

**메타 통찰** (CLAUDE.md §9에 protocol화):

1. **광고 ≠ 검증**: review가 "X가 X인가"만 검증, "X 외 같은 패턴 다른
   site"는 검증 안 됨. T20 미완이 정확한 예 — 5개 필드 검증만 했고
   `grep '{{' templates/` 메타-grep 안 함.
2. **같은 모델 N회 review의 한계**: 5회 외부 review pass가 같은 LLM
   패밀리면 attention bias 공유. 사람 review가 ~5배 효과인데 LLM은
   ~1.5배. v13이 잡은 9개 finding은 prompt를 anchor-free로 비대칭화한
   덕분.
3. **anchor의 함정**: known_issues.md `"0 still open. 🎉"` 같은 정리된
   status가 다음 audit의 LLM context에 들어가면 "닫혔다"는 강한 bias
   생성. anchor 명시적으로 제거해야 새 hole 보임.
4. **CLAUDE.md self-check이 honor system**: §5/§7가 "신규 API grep" /
   "메타-grep" 적었지만 작업 prompt에 강제하지 않으면 LLM이 본인 룰
   어김. v13에서 발견된 T20 미완이 정확히 본인 §5 위반.

**의의**:
- v13의 9개 finding 자체보다 **"5회 review + 7개 Bundle을 거쳐도 같은
  패턴 회귀가 새 site에서 나온다"는 메타 사실이 더 중요**.
- CLAUDE.md §9 "LLM 협업 메타-룰" 신설 — prompt 비대칭화, anchor-free
  audit, 메타-grep 의무, cross-model review.
- 후속: Bundle Q (Q-1 ~ Q-4)로 9개 finding 닫음. 단 닫는 commit message
  자체가 또 anchor가 될 수 있으므로 Q 다음 분기 1회 anchor-free re-audit
  스케줄 (CLAUDE.md §9.5).

### v12 — Bundle P: 마지막 polish 6개, 모든 OPEN 닫힘 🎉 (2026-05-27)

Bundle O 후속, 마지막 OPEN 6개 한 commit (~250 LoC).

**무엇이 닫혔나**:
- **T22**: dudect summary table ERROR row가 `n0=0, mean=0.0, |t|=0.00`로
  찍히던 거 → ERROR row는 모든 numeric cell `-` + status cell bold magenta.
  status가 ERROR임이 시각적으로 명확.
- **T13**: `parse_header_file_with_stats` wrapper + cli `infer`가 skip
  count > 0이면 dim note 출력. T11 plumbing 미완 완료.
- **T16**: `_BINARY_LOCATION_RE` 추가 → `(in /lib/libc.so.6)` 형식
  location의 file/line 명시적 분리.
- **T17**: coverage probe가 ct cflags의 preprocessor-affecting flag
  (`-D`/`-U`/`-isystem`/`-iquote`/`-I`) 만 propagate. `_filter_probe_cflags`
  헬퍼가 `-O*`/`-g`/`-fno-lto` 같은 noise drop.
- **T15**: `welch_with_cropping`이 c0/c1 각자 한 번씩 sort + cutoff별
  `bisect_right`로 prefix slice. 10번 sort → 2번. 결과 bit-identical
  (회귀 테스트가 prior "sort per cutoff" 로직 reimpl과 결과 일치 검증).
- **T19**: `_atomic_write_text` 헬퍼 신설 — `tempfile + os.replace()`.
  CI matrix에서 같은 yaml 동시 실행해도 reader는 완전한 파일만 봄.

**테스트**: 254 → **261 passed** (7개 신규 회귀 방어).

**전체 상태**: 53 issue 중 52 closed (Bundle 0~P), 1 deferred (F9 #4 multi-cflags
matrix — out of scope per spec, CSV schema 재설계 필요). **OPEN 0개**.

### v11 — Bundle O: T20 + T7 follow-up validator family (2026-05-27)

Bundle N 후속. ~120 LoC (config.py validator + 8개 회귀 테스트).

**무엇이 닫혔나**:
- **T20**: F6 coverage probe `_render_sentinel_c`의 `header`/`extra_headers`/
  `prefix` 무검증 interpolate 차단. 단 probe 쪽 코드는 안 건드림 — pydantic
  validator가 입력 단계에서 거부하므로 probe는 자동으로 안전한 값만 받음.
  *upstream에서 막는 게 down-stream 손대는 것보다 robust*.
- **T7 follow-up** (acceptance criterion #1 마지막 부분 — H2에서 `name`만
  박았음): `function`, `return_type`, `prefix`, `header`, `extra_headers`
  regex 검증. `_check_yaml_identifiers` 모듈 함수로 추출해 두 모델
  (HarnessConfig + DudectHarnessConfig) 공유.

**정책**:
- `_HEADER_PATTERN`: 알파벳/숫자/`_./+-`. quote/backslash/newline 차단.
  실제 헤더명 다 통과.
- `_C_IDENT_PATTERN`: 표준 C identifier. function name, prefix.
- `_C_TYPE_PATTERN`: 느슨 (포인터/const/scoped 허용). return_type.

**테스트**: 246 → **254 passed** (8개 신규).

**남은 OPEN 6개** (Bundle P 후보):
- T13 (parse_functions_with_stats plumbing 미완)
- T15 (upper_crop sort 중복 — 성능)
- T16 (FRAME_RE binary-only location partial)
- T17 (coverage probe `-D` 매크로 안 받음)
- T19 (harness_*.c TOCTOU race)
- T22 (dudect summary ERROR row 시각적 분리)

### v10 — Bundle N: subprocess/encoding hygiene (2026-05-27)

Bundle M 후속. T12/T18/T21 한 commit, ~250 LoC. 헬퍼 하나로 정책 집중 →
다음 LLM이 같은 함정 빠질 표면을 없앰.

**무엇이 닫혔나**:
- **T12** (subprocess timeout 4곳 무방어): `ctkat/_proc.py` 신설.
  `run_text(argv, *, timeout, ...)` — timeout이 keyword-only, default
  없어서 호출자가 까먹으면 type error로 죽음 (T12가 막으려던 그 실수
  자체를 type system이 막음). 5개 sub site + coverage probe 2곳 일괄
  교체. yaml: `build/kat.timeout`, `ct.compile_timeout`/`valgrind_timeout`,
  `dudect.compile_timeout` (기존 `dudect.timeout`은 T6에서 도입됨).
- **T18** (text=True + errors='replace' 누락): 같은 헬퍼 안에 정책
  포함 — `encoding='utf-8', errors='replace'`. invalid utf-8 → U+FFFD,
  raw traceback 없음.
- **T21** (read/write_text 인코딩 미지정): 6곳 모두 명시적
  `encoding="utf-8"`. read 쪽 (외부 출력) 은 `errors="replace"` 추가.

**테스트**: 241 → **246 passed**. 신규 5개:
- `test_run_text_requires_timeout_keyword` — type-level invariant
- `test_run_text_garbage_bytes_do_not_raise_unicodedecodeerror` — T18 핵심
- `test_run_text_timeout_raises_timeoutexpired` — T12 핵심
- `test_run_text_shell_mode_works` — builder backward-compat
- `test_build_timeout_yields_fail_not_hang` — cli 흐름까지 end-to-end

**남은 OPEN 7개**:
- Bundle O (T7 follow-up validator family): T20
- Bundle P (polish): T13, T22, T17, T16, T15, T19

### v9 — Bundle M: sk-leak/cache-balance semantics (2026-05-27)

Bundle L 후속 — v6 audit이 가장 강하게 꼬집었던 광고-실측 불일치 처리.
F13/F14 묶음 한 commit, ~80 LoC (C 템플릿 + Python 테스트 + README).

**무엇이 닫혔나**:
- **F13**: sk-leak brunch가 양 class에서 `crypto_kem_enc()`로 valid ct를
  생성하도록 재설계. README의 "정상 dec path의 sk-dependent timing"
  주장과 실측이 비로소 정합. cls=0은 enc(pk_fixed), cls=1은 keypair +
  enc(pk_random) — 각자의 sk가 자기 pk로 만든 valid ct를 측정.
- **F14**: `emit_kem_measurement` 매크로의 warm step을 `dec(ct_expr,
  sk_expr)` 로 교체. measurement와 동일 path warm → cache state 정직.
  ct_warm 버퍼 폐기. ct-leak/sk-leak warmup loop도 valid ct 사용. fo-leak
  warmup은 random ct 유지 (mixed-path 측정의 burn-in 정책).

**테스트**: 237 → **241 passed**. 새 회귀 방어 4개:
- `test_kem_sk_leak_uses_valid_ct_for_both_classes` — F13 의미 핵심
- `test_kem_sk_leak_warmup_uses_valid_ct` — F14 sk-leak 적용
- `test_kem_macro_warm_and_timed_dec_use_identical_args` — F14 매크로 invariant
- `test_kem_ct_leak_warmup_uses_fixed_valid_ct` — F14 ct-leak 적용

**측정값 변동 가능성**: sk-leak 결과가 Bundle M 이전과 달라짐
(FO path → 정상 path). 기존 `dudect_summary.csv` baseline 비교 불가.
README §KEM leak axes에 caveat 명시. 별도 baselines/ 디렉토리는 R3
시스템 노이즈로 어차피 변동성 ±10-20%이라 일괄 갱신 불필요.

**남은 OPEN 10개**:
- 다음 Bundle N (subprocess/encoding hygiene): T12, T18, T21
- Bundle O (T7 follow-up validator): T20
- Bundle P (polish): T13, T22, T17, T16, T15, T19

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
