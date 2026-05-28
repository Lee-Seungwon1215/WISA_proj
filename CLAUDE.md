# CT-KAT — 코드 작성 / 리뷰 지침

이 파일은 known_issues.md v6 외부 리뷰 pass 5에서 발견된 11개 회귀
(F12-F16, T12-T17)의 재발 방지용 운영 가이드. AI/사람이 코드 작성 /
review 시 이 패턴들을 체크할 것.

5회의 외부 review pass와 Bundle 자체 검증을 다 통과한 코드에서 11개
회귀가 발견됨 — pytest 통과는 "이 코드가 의도한 일을 한다"를 증명하지
않는다. 아래 패턴은 그 사실을 인정하고 만든 self-check 목록.

## 0. 메타: 통과 ≠ 정확

`pytest 228/228 통과`는 "구현이 의도된 동작을 한다"를 증명하지 않는다.
실제 v6에서 잡힌 회귀들:

- 광고된 user-facing 서브커맨드가 NameError로 사망 (F12)
- 광고된 측정 path와 실제 측정 path 불일치 (F13/F14)
- 주석에 적힌 의도와 코드 동작 불일치 (F15)
- yaml/Python/C 사이 sentinel value 의미 불일치 (F16)

매 작업 시작 전 아래 8개 self-check.

## 1. Acceptance criteria는 user-visible behavior로 적기

❌ "함수 X 가 추가됨"
✅ "`ctkat <subcommand> --foo` 실행 시 stdout에 Y가 보이고 exit code Z"

**규칙**: user-facing surface (CLI 서브커맨드, yaml field, CSV column,
console 메시지) **각각에 smoke test 최소 1개**. backend unit test만으로
"기능 완성" 마킹 금지.

**위반 사례**: F12 — `ctkat parse` 서브커맨드에 test 0개. Bundle I (T3)
작업이 backend 함수 이름만 바꾸고 frontend 서브커맨드 호출자 갱신 빼먹음.
parse 서브 smoke test가 1개라도 있었으면 즉시 잡혔음.

## 2. 도메인 의미 검증 — 작동 ≠ 의도

특히 crypto/security tool에서는 **"이 코드가 무엇을 측정하는가"의 의미적
정확성**을 별도 acceptance test로 못 박는다.

- timing harness: 어떤 dec path / 어떤 함수가 timed region 안인지
  명시적 검증
- 매크로/dedup: 의미가 정합한지 검증 (output bytes equal이 아니라
  semantics equal)
- secret region: 진짜 secret이 taint되는지 검증

**규칙**: 의미적 invariant (어떤 path / 어떤 함수 / 어떤 데이터가
변화) 한 줄짜리 자기검증을 acceptance criteria에 넣기.

**위반 사례**: F13/F14 — sk-leak 모드가 `rand_bytes(ct)`로 invalid ct
만든 뒤 `dec()` 호출. test는 "C 렌더링이 valid"만 확인. 정작 "invalid ct
→ FO fallback path 진입 → 광고된 정상 path 측정 아님"이라는 의미적 불
일치는 5번의 review가 다 놓침.

## 3. 주석 ≠ 코드 — 정기 audit

주석에 "이렇게 동작한다"라 적혀있어도 코드와 일치하는지 grep 검증.
주석은 의도의 표시지 동작의 증거가 아니다.

**규칙**: 새 함수/매크로/validator 작성 시 본문 주석으로 의도 적되,
그 claim이 코드에서 실제로 enforce되는지 self-check. review pass에서
**"주석에 그렇게 적혀있으니까 맞겠지"는 금지**.

**위반 사례**: F15 — 주석 "Detect by comparing object identity"인데
실제 코드는 `==` 값 비교. 5회 review pass가 주석만 보고 패스.

## 4. layer 간 contract 명시

C / Python / yaml 같은 다중 layer가 동일 의미를 가진 값을 다르게
해석할 수 있다. sentinel value, default 처리는 모든 layer 동일하게.

**규칙**: 다중 layer 값 (seed, threshold, name, cflags, path 등) 도입
시 각 layer가 같은 의미 부여하는지 명시적 검증, 또는 yaml validator로
invalid value 거부.

**위반 사례**: F16 — yaml `seed: 0` → Python은 0 그대로 (log에 0x0
출력), C는 `seed ? seed : 0xC0FFEE`로 swap. xorshift seed=0 stuck
방어는 필요하지만 두 layer가 다르게 처리한다는 사실을 어디서도 명시
안 함. yaml validator에서 `seed > 0` 강제했어야 했음.

## 5. backend / frontend plumbing chain 의무

새 helper / API 추가 시 사용처를 grep으로 추적. backend만 만들고
frontend plumbing 미완 패턴 회피.

**규칙**: 신규 API 도입 시 acceptance criteria에 **"어디서 호출되는가"**
박기. `grep <new_function>` 결과가 호출자 0개면 plumbing 미완으로
reject.

**위반 사례**:
- T13 — `parse_functions_with_stats` 추가했는데 cli infer는 여전히
  `parse_header_file()` 호출. user에게 skip count 안 보임.
- F12 — 동일한 패턴. backend 함수명 바꾸고 frontend 서브커맨드 sync
  빼먹음.

## 6. config default ↔ example yaml drift 방지

config.py의 default 변경 → examples/*.yaml이 explicit override 하면
sync 안 됨. yaml override가 critical flag 누락하기 쉬움.

**규칙**: example yaml은 가능한 default 안 override. override 필요하면
lint test로 critical flag 누락 검증.

**위반 사례**: T14 — `examples/pqc_mlkem768/ctkat.yaml`의 dudect
compiler.cflags가 `[-O2, -g, -fno-omit-frame-pointer]`. config.py
default는 여기에 `-fno-lto` 포함. yaml override가 그걸 빠뜨림 →
사용자 환경에 `CFLAGS=-flto` 박혀있으면 측정 silent하게 망함.

## 7. scope 한정 함정 회피

"X 작업"의 scope이 좁아도 같은 general 문제 (timeout, validation,
error handling)가 다른 곳에 있는지 grep으로 점검.

**규칙**: general 문제 작업 시작 전 `grep subprocess.run` 같은
**메타-grep**으로 같은 패턴 다른 site 검색. acceptance criteria에
"모든 site 적용" 박기.

**위반 사례**: T12 — Bundle E-1 T6가 dudect timing harness timeout만
처리. 같은 timeout 문제가 build/Valgrind/compile 4곳에 동일하게 있음.
"timeout"이라는 일반 문제를 dudect scope으로만 한정 사고 → 다른 4곳
무방어.

## 8. test corpus 다양성

새 parser / probe / validator 추가 시 reference set (PQClean ML-KEM,
toy_password) 만 검증하지 말 것. 외부 환경 variation 한 개 이상 fixture
로 박기.

**규칙**: silent failure path가 있으면 loud warning으로 surface. 환경
의존적으로 효과가 0이 되는 검증은 사용자에게 명시.

**위반 사례**:
- T16 — valgrind 출력 형식은 source-mapped `(file.c:123)` vs binary-only
  `(in /lib/libc.so)` 다양. parser는 전자만 fully parse, 후자는 file/line
  None. test corpus가 전자만 있어서 잡히지 않음.
- T17 — coverage_check probe가 `-D` 매크로 안 받음. 사용자 헤더가
  `#ifdef CONFIG_X` chain이면 silent skip — F6 효과 0. test는 단순
  헤더만 검증.

## 9. LLM 협업 메타-룰 (v13 post-meta-audit에서 추가)

§1-8은 "코드 작성 시 점검". 이 §9는 "LLM에게 prompt 던질 때 점검".
v13 meta-audit에서 발견: 5회 외부 review pass + 7개 Bundle 거쳤는데도
같은 패턴 회귀 9개가 새 site에서 나옴. 원인은 코드 결함이라기보다
**LLM 워크플로우 자체의 구조적 한계**.

### 9.1 광고 ≠ 검증의 함정

Bundle commit message / known_issues.md status / CLAUDE.md self-check
같은 "정리된 표면"이 LLM context에 들어가면 **"이건 닫혔다"는 강한
anchoring**. LLM이 코드 grep 대신 정리된 claim을 신뢰함. v13에서 T20이
"C-source injection 차단했다" 광고했지만 5개 template × 4종 필드
hole 그대로였던 게 정확히 이 패턴.

**규칙**: review prompt 던질 때 anchor 명시적으로 무시 지시.

```
❌ "이 Bundle review해줘"
✅ "known_issues.md / Bundle commit message / §0-8 self-check 다 무시.
    코드만 grep해서 X 패턴이 다른 site에 있는지 봐."
```

### 9.2 같은 모델 N회 review ≠ 사람 N회 review

같은 LLM 패밀리면 attention bias가 같아서 5회 review = 1회 review의
~1.5배 정도밖에 효과 없음 (사람은 ~5배). compound effect 매우 낮음.

**규칙**:
- Review를 N회 돌릴거면 prompt를 매번 비대칭화 —
  pass 1: 광고된 X 검증 / pass 2: X와 같은 패턴 다른 site / pass 3:
  evil-input 시뮬 / pass 4: layer contract 검증 / pass 5: 회귀 hunt
- 큰 Bundle / verdict-affecting 변경 끝나면 가끔 다른 모델 1회
  돌려보면 새 layer 잡힘. 매번 의무는 아니고 분기에 한 번 정도면 충분.
  v15가 정확히 이 효과로 header_parser regex / CSV row validation 같은
  새 layer 4개 발견.

### 9.3 메타-grep 의무 (§7 강화)

§7이 "general 문제 작업 전 메타-grep"이라 했는데 honor system이라
LLM이 본인이 자주 어김. 사용자 prompt에 첫 step으로 박는 게 enforcement.

**규칙**: 작업 시작 prompt에 메타-grep을 **첫 step으로** 명시.

```
"T29 시작 — 작업 들어가기 전에 `grep '{{' templates/*.j2` 같은
메타-grep으로 모든 site 나열하고 그 list 출력해줘. 본 다음에
작업 계획."
```

LLM이 1번 step에서 list 만들면 그 list가 working memory에 들어와서
이후 step에서 누락 site 자동 점검됨. anchor를 self-generate.

### 9.4 user-visible 시연 의무 (§1 강화)

§1이 "acceptance는 user-visible"이라 적었지만 "test 228 통과" 보면 LLM
본능적으로 "OK" 한다. 사용자가 매 Bundle 끝에 능동적 stress test 압박
해야 함.

**규칙**: Bundle 끝나면 evil/edge input으로 실제 실행 시연 요구.

```
❌ "test 다 통과했는지 확인"
✅ "BufferSpec.name에 `'x; system(\"rm\")'` 박은 yaml 만들어서 ctkat
    run에 던져. ValidationError 떨어지는 stdout 보여줘."
```

pytest는 "이 코드가 코드 작성자가 의도한 일을 한다" 증거지 "이 코드가
user에게 광고된 일을 한다" 증거 아님. v13의 T20 미완이 정확히 그
사례 (228/228 pytest 통과 + injection surface 4종 그대로).

### 9.5 "anchor-free audit" 분기 1회

매 분기 (또는 Bundle 5개마다) 1번씩 anchor 무시 audit 의무.

**규칙**: 사용자가 분기마다 `"known_issues.md 무시하고 코드만 봐서
같은 패턴 hole N개 찾아"` prompt 던지기. v13이 정확히 이 방식으로
9개 finding 잡음. 정기 audit으로 박지 않으면 회귀가 누적됨.

### 9.6 audit ≠ fix — 광고와 닫음 사이의 lag

v14가 발견: v13 audit이 9개 finding 적었지만 코드는 그대로. v15도
audit 적기만 하고 fix 0. audit이 누적되면 의식(ritual)이 됨.

**가벼운 규칙** (강박 X):
- known_issues.md `Status` 에 "광고 vs 실제 fix" 정도는 분리 표시 —
  "v13 발견: 9, v13 fix: 0" 식. 어느 게 정말 닫혔는지 한눈에.
- audit과 fix를 같은 세션에서 다 하면 자기 finding scope에 anchor되기
  쉽다. **분리하면 좋지만 매번 강제할 필요는 없음** — 큰 Bundle 끝나고
  분기에 한 번 정도 다른 모델 / 다른 세션으로 cross-check 하는 게
  ROI 적당. 매 audit마다 다른 모델 의무화는 과함.
- "이게 마지막 audit"이라는 가정 자체가 위험 신호. finding 적은 직후가
  anchor 가장 강한 시점이라 다음 audit이 또 같은 hole 본다는 것 기억.

## 한 줄 self-check (작업 시작 전)

매 작업 / Bundle 시작 전:

1. acceptance가 user-visible인가, implementation detail인가?
2. 의미적 invariant 검증 있나?
3. 주석 claim 이 코드에서 enforce되나?
4. 다중 layer 값이면 contract 명시했나?
5. 신규 함수가 어디서 호출되나? plumbing chain 완성됐나?
6. 같은 일반 문제가 다른 site에도 있나? **메타-grep 결과 있나?** (§9.3)
7. example yaml과 config default 일관성 있나?
8. test corpus가 reference set만은 아닌가?
9. **review prompt가 anchor-free인가? cross-model 1회 했나?** (§9.1, §9.2)

## 관련 문서

- `docs/known_issues.md` v6 — 이 가이드를 만든 11개 회귀의 상세
- `docs/known_issues.md` v13 — §9 (LLM 협업 메타-룰)을 만든 9개
  post-Bundle-P meta-audit finding의 상세
- `docs/tutorial.md` — 사용자 onboarding (U5)
- `README.md` — capabilities & limitations
