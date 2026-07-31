# CT-KAT 리젝 복구 및 프로젝트 완성 로드맵

기준일: 2026-07-29

기준 커밋: `b1ccd4d`

입력 리뷰: `~/Downloads/WISA리젝리뷰종합.md` (2026-07-28)

대상: 현재 작업 트리의 프레임워크, corpus, 예제, 로컬 WISA 논문 소스

진행 상태:

- **M1 완료 (2026-07-29)** — `0.2.0a1` 패키징, release CI, 문서
  single-source, third-party provenance, shell opt-in 정책을 구현했다.
- **M2 / `EVID-001` 완료 (2026-07-30, `0.3.0a1`)** — evidence schema v2, 5상태
  `overall`, review artifact linkage, v1.2 결정론적 migration을 구현했다.
- **M2 / `STAT-001` 완료 (2026-07-30, `0.4.0a1`)** — exact-pinned official
  dudect 102-test backend, two-trace protocol, synthetic A/A·effect curve,
  same-trace parity, host manifest와 fail-closed timing validity를 구현했다.
- **M2 / `TIME-001` 구현 완료 (2026-07-30, `0.5.0a1`)** — KEM/sign 양 class
  pool, common work buffer, setup 대칭화, RDTSCP AUX migration filter,
  3-process target 반복, physical A/A·setup-placebo·3-point positive control,
  run별 MDE/power artifact를 구현했다. 실제 target의 native control 통과는
  아직 실행하지 않았고 다음 corpus v2 refresh에서만 승격한다.
- **M2 / native campaign 준비 완료 (2026-07-30, `0.6.0a1`)** — 현재 timing
  evidence가 있는 6 target/8 axis를 manifest로 동결하고, native/bare-metal
  preflight, CPU pinning, 실행 재개, artifact hash·protocol 검증,
  `corpus_timing_updates.csv` 승격 후보 생성을 한 명령으로 묶었다. 현재
  macOS/ARM 환경에서는 실측하지 않았으며 이 상태를 결과 완료로 쓰지 않는다.
- **M3-A / `KS-001`·`KS-002` 완료 (2026-07-31, `0.7.0a1`)** — stock,
  KS1-only, KS2-only, KS1+2와 vulnerable historical source를 분리하고 exact
  diff/provenance/KEM equivalence를 동결했다. IACR artifact의 patched
  Valgrind/TIMECOP을 pin해 full-KEM secret-key 경로와 direct site-operand
  attribution을 별도 증거로 만들었다. native timing과 key recovery는 여전히
  미실행이며 `KS-003`·`KS-004`에 남긴다.
- clean wheel/sdist 설치와 6개 entry template render hash + v2 shared support
  resource 포함을 확인했다.
- Ubuntu 24.04 컨테이너의 설치본으로 gcc/clang 4개 조합, Valgrind,
  `ctkat screen` toy end-to-end를 통과했다.
- 기존 ML-KEM timing `FAIL + robust` 행은
  `confounded / signal / inconclusive`로 migration되어 모순이 제거됐다.
- asm-scan 미실행 compiler/opt는 셀별 `NOT_RUN`으로 남고, legacy
  summary-only 축은 대응 cell이 없으면 structural/asm `not-run`으로 강등된다.
- native 장비를 기다리는 동안의 다음 작업은 **Falcon comparator의 비-timing
  기반·target/provenance 준비**다. native
  장비가 확보되면 동결된 campaign을 실행해 기존 corpus를 재분류한다.
  코드가 control을 만들 수 있다는 사실과 실제 ML-KEM/ML-DSA/Falcon
  target/host가 A/A budget과 power를 통과했다는 사실을 섞지 않는다.

## 0. 결론부터

CT-KAT은 갈아엎을 프로젝트가 아니다. 검사기를 새로 발명한 건 아니지만,
여러 불완전한 신호를 build provenance와 default-deny triage 아래 묶는 구조는
살릴 가치가 충분하다.

다만 리뷰 직후 상태를 냉정하게 부르면 다음과 같았다.

- 엔지니어링 프로토타입: 꽤 잘 만들었음
- 설치 가능한 공개 패키지: wheel이 템플릿을 빼먹어서 아직 아님
- 과학적으로 해석 가능한 timing 도구: 아직 아님
- 일반화된 PQC 평가: 아직 PQClean clean C 한 집안 잔치임
- 논문: “통합해서 편하다”는 주장은 있는데 “얼마나 더 낫나” 숫자가 부족함
- KyberSlash: 좋은 seeded positive control이지만 아직 historical reproduction은 아님
- Falcon: 미지의 괴물이 아니라, non-CT reference와 CT 구현을 비교해야 할 benchmark임

따라서 우선순위는 기능 추가가 아니다.

> 패키징과 결과 의미론을 고치고 → timing 실험을 유효하게 만들고 →
> KyberSlash/Falcon을 ground-truth benchmark로 완성하고 → baseline·독립
> codebase를 늘린 뒤 → 마지막에 논문을 다시 쓴다.

이 순서를 뒤집으면 결함 있는 하니스로 비싼 실험을 다시 돌리고, 나중에 schema가
바뀌어서 결과를 또 갈아엎는 개고생 확정이다.

---

## 1. 리뷰 직후 직접 확인한 기준 상태 (`b1ccd4d`)

### 1.1 확인된 강점

- `python3 -m pytest -q`: **492 passed, 3 skipped**
- 실패·불완전 분석을 조용히 PASS로 올리지 않으려는 코드 경로가 잘 깔려 있음
- compiler/optimization matrix, asm provenance, triage 분리가 실제 코드에 존재함
- KyberSlash의 stock/vulnerable assembly 차이를 corpus regression test가 고정함
- Falcon은 무지성 `accepted-variable-time`으로 세탁하지 않고 `needs-analysis`로 멈춤
- 논문도 CT-KAT을 proof system이나 새 detector로 포장하지 않으려는 방향은 잡혀 있음

### 1.2 직접 재현한 차단 결함

| 증거 | 현재 값 | 판정 |
|---|---:|---|
| wheel entry | 29개 | 자체로는 문제 없음 |
| wheel 안 `ctkat/templates/*.j2` | **0개** | 설치본 핵심 기능 고장 |
| corpus summary | 17행 / 11 target | 숫자보다 upstream 다양성이 문제 |
| corpus cell | 152개 | 전부 `x86_64` |
| compiler | gcc 13.3 / clang 18.1 | 버전 기록은 좋음 |
| 독립 real upstream codebase | 사실상 **PQClean 1개** | 일반화 주장 불가 |
| timing 결과가 있는 행 | 8개 | validity/power 상태 없음 |
| ML-KEM `sk` timing | `FAIL`, `|t|=145.316` | 하니스 confound |
| 같은 행 최종 class | `robust` | 표 의미론 충돌 |
| README ML-KEM timing | QEMU `|t|=5.47` | committed CSV와 drift |
| `ctkat --version` | 없음 | 배포 metadata 미완성 |
| CI workflow | 없음 | 공개 release gate 없음 |

### 1.3 리뷰 작성 뒤 이미 들어간 수정과 그 한계

리뷰 작성 당시 HEAD에는 `Refresh dudect evidence to native measurement; fix
KEM timing template` 커밋이 있었다. 이 수정은 invalid ciphertext 일변도였던
KEM `sk` 축을 valid ciphertext normal path로 바꾸고 warm call을 추가했다.
이건 필요한 수정이었다.

하지만 class 0은 기존 key를 쓰고 class 1만 매 iteration keypair를 생성한다.
주소도 `sk_fixed`와 `sk_random`으로 다르다. 즉 keygen이 timer 밖에 있다는 이유만으로
cache, predictor, frequency, 주소 효과가 사라지지 않는다. 실제 `|t|=145.316`이 그
confound를 그대로 보여준다.

따라서 당시 `TIME-001`은 **해결이 아니라 부분 수정**이었다. signature timing
template도 같은 fixed-vs-fresh setup을 썼으므로 A/A control과 pool 방식으로
같이 재검증해야 했다. 현재 구현 상태는 아래 M2 절에 따로 기록한다.

---

## 2. 다운로드 리뷰 판정표

판정 용어:

- **확정**: 현재 checkout에서 직접 재현했거나 코드로 확인함
- **부분 확정**: 방향은 맞지만 이미 일부 보완됐거나 표현이 과함
- **보정 필요**: 결론은 살리되 과제 정의를 바꿔야 함

| 리뷰 항목 | 판정 | 현재 증거 | 결정 |
|---|---|---|---|
| `REL-001` wheel template 누락 | **확정 / P0** | 실제 wheel에 Jinja template 0개 | 첫 번째 수정 묶음 |
| `DOC-001` README drift | **확정 / P0** | README `5.47` vs CSV `145.316`, Docker clang 설명도 틀림 | 결과 블록 자동 생성 |
| `TIME-001` KEM setup confound | **확정 / P0** | class 1만 keypair, 서로 다른 주소 | pool/common-buffer/A-A로 재설계 |
| `VERD-001` timing FAIL + robust | **확정 / P0** | `corpus_summary.csv`에서 직접 확인 | evidence schema v2 필요 |
| `STAT-001` 가짜 Bonferroni | **확정 / P0** | threshold에 `sqrt(5)` 곱함 | 이름만 바꾸지 말고 통계 backend 교체 |
| `LEGAL-001` provenance/license | **확정 / P0** | 루트 LICENSE는 ML-KEM-768만 기록, ML-DSA-65 LICENSE 누락, commit 표기 불균일 | 자동 inventory + notices |
| `EVAL-001` TIMECOP/MicroWalk 맞대결 없음 | **확정 / P1** | 관련연구에만 있고 실행 artifact 없음 | same-corpus adapter 작성 |
| `EVAL-002` corpus 다양성 부족 | **확정 / P1** | 실코드는 전부 PQClean clean 계열 | upstream 기준으로 codebase 계산 |
| `STAT-002` dudect protocol parity | **확정 / P0/P1** | 현재 5 cutoff, official dudect는 uncropped + 100 percentile + second-order | official backend 기본화 |
| `TRIAGE-001` declassification 근거 약함 | **부분 확정 / P1** | guardrail은 좋지만 manual parent-frame override와 1인 판단이 큼 | schema·2인 review·expiry 추가 |
| `TAX-001` 9개 taxonomy | **확정 / P1** | 외부 class가 layer 상태와 행동 지침을 뒤섞음 | 외부 5상태 + 내부 evidence 분리 |
| YAML 실행 보안 | **부분 확정 / P1** | 안전한 `argv`는 이미 있으나 모든 예제가 legacy `command`를 기본 사용 | `argv` 기본, shell 명시 opt-in |
| asm-scan이 단순 grep이라는 비판 | **보정 필요** | multi-build/provenance engineering은 실제로 있음 | detector가 아니라 candidate collector라는 결론은 유지 |
| “3 codebase/20 target” 최소선 | **보정 필요** | 학계의 절대 법칙은 아님 | 숫자 채우기보다 독립 upstream·variant·arch를 명시 |
| 신규 finding 없음 | **확정 / P1** | historical/seeded 결과와 known scheme behavior 중심 | 신규 CVE 강박 대신 baseline·cost·reproducibility를 강하게 증명 |

### 리뷰에서 특히 맞는 말

1. 테스트가 많아도 실험 질문이 잘못되면 정교하게 틀린 답을 낸다.
2. parameter set 세 개는 독립 구현 세 개가 아니다.
3. manual review가 많다는 사실을 숨기면 안 된다.
4. `robust`, `accepted`, `dudect`라는 이름이 실제 증거보다 세다.
5. baseline 없이 “기존 도구의 blind spot을 메운다”는 주장은 사례담이다.

### 리뷰를 그대로 복붙하면 안 되는 부분

1. 현재 KEM timing 수정은 리뷰 ZIP보다 앞서 있지만 confound를 다 없애지는 못했다.
2. `argv` 실행 경로는 이미 있으므로 shell 보안은 신규 기능보다 default 전환 문제다.
3. Falcon row는 그냥 “언젠가 분석”이 아니라 reference-vs-constant-time 비교 실험으로
   재정의해야 한다.
4. asm-scan은 보안 detector는 아니지만 cross-build artifact 수집기로서의 구현 가치는 있다.
5. 새 분석 알고리즘을 억지로 발명할 필요는 없다. 대신 orchestration의 비용·재현성·
   review burden 이득을 수치로 보여야 한다.

---

## 3. 프로젝트 포지셔닝 고정

### 3.1 앞으로 쓸 한 문장

> CT-KAT은 새 constant-time 검출기가 아니라, 서로 다른 위협 모델의 검사 결과를
> cross-build provenance와 명시적 human review 아래 결합하고, 증거가 불완전하면
> 결론을 거부하는 재현 가능한 screening orchestrator다.

### 3.2 핵심 기여 후보

1. 하나의 target specification에서 여러 backend용 harness·build artifact 생성
2. compiler/flag별 evidence provenance
3. layer failure와 분석 미완료를 보존하는 default-deny semantics
4. 자동 증거와 사람의 declassification을 분리한 감사 가능한 기록
5. raw artifact에서 표·그림·최종 disposition까지 재생성하는 workflow

### 3.3 명시적 non-goal

- formal constant-time proof
- 모든 microarchitecture의 instruction latency 모델
- power/EM/fault/masking 분석
- asm 후보의 자동 secret attribution을 이미 구현했다고 주장
- 한 번의 timing PASS로 안전 선언
- Falcon/FN-DSA 표준 적합성 인증

---

## 4. 실행 순서와 마일스톤

## M0 — 결과 동결과 작업 장부

목적: 앞으로 결과가 바뀔 때 “코드 수정 때문인지 환경 때문인지” 추적 가능하게 만든다.

작업:

- 현재 `b1ccd4d` corpus와 raw local reports의 SHA-256 manifest 생성
- 리뷰 항목을 아래 ID로 issue/checklist화
- `docs/corpus_schema.md` v1.2는 legacy frozen schema로 표시
- 새 결과는 v2 디렉터리에 쓰고 v1 CSV를 제자리에서 덮어쓰지 않음
- 논문 숫자는 M4 완료 전까지 “frozen rejected-paper snapshot”으로 취급

종료 조건:

- 현재 결과의 코드 commit, source commit, 환경, hash를 한 파일에서 찾을 수 있음
- 이후 migration이 v1 artifact를 파괴하지 않음

---

## M1 — 공개 alpha가 설치부터 안 깨지게 만들기

**상태: 완료 (2026-07-29, `0.2.0a1`)**

### `PKG-001` wheel/sdist 완성

- `[tool.setuptools.package-data]`에 `templates/*.j2` 포함
- template loader를 `importlib.resources` 기반으로 전환
- source checkout 밖 clean venv에서 generic/KEM/sign 및 timing template 전부 렌더
- 최소 toy harness 하나를 컴파일하고 `ctkat screen` smoke 실행
- wheel과 sdist 모두 검사

합격 기준:

- 설치본과 source checkout의 render 결과 hash가 같음
- `TemplateNotFound`가 regression test로 영구 차단됨

### `META-001` 패키지 metadata

- README, license expression/file, authors/maintainers
- repository/issues/documentation URL
- Python classifiers와 지원 버전
- `ctkat --version`
- `dev`, `test`, `docs`, 선택 backend dependency group
- `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CITATION.cff`

### `CI-001` 실제 release gate

최소 CI:

- Python 3.11 / 3.12 / 3.13
- unit test와 coverage floor
- wheel/sdist build 및 clean-install smoke
- template render + toy C compile
- Linux Valgrind toy end-to-end
- gcc/clang matrix smoke
- Docker build
- schema validation
- README generated block drift 검사
- license/provenance inventory 검사
- formatter, linter, type checker

### `DOC-001` 문서 single source

- README 결과표를 손으로 쓰지 않고 corpus v2에서 생성
- generated block에 source CSV hash와 생성 명령 삽입
- Dockerfile에 clang이 있는데 “gcc only”라고 쓰인 문장 수정
- C++ end-to-end test 전까지 `C/C/C++`을 `C`로 축소
- `dudect` 표현은 M2 전까지 `dudect-inspired first-order screen`으로 축소

### `LIC-001` third-party inventory

- `THIRD_PARTY_NOTICES.md`
- upstream URL, full commit, path, license, local patch, tree hash
- ML-DSA-65의 누락 LICENSE 복구
- `FETCH_INFO.md` 형식 통일
- vendored directory가 inventory에 없으면 CI 실패
- `master` 같은 floating provenance 금지

### `SEC-001` config 실행 정책

- 신규 문서는 `argv`를 기본으로 사용
- `command`는 `allow_shell: true`가 없으면 거부하거나 loud warning
- 외부 PR CI에서는 shell-enabled corpus를 실행하지 않음
- trusted/untrusted profile을 구분

M1 종료 조건:

- clean Linux machine에서 wheel만 설치해 toy end-to-end 성공
- 문서·패키지·license drift가 CI에서 자동 차단
- 이 시점에만 `0.2.0a1` 같은 public alpha tag 허용

---

## M2 — 결과가 거짓말하지 않게 evidence/timing 재설계

M2 전에 KyberSlash/Falcon paper-grade timing을 다시 따지 않는다.

### `EVID-001` schema v2

**상태: 완료 (2026-07-30, schema `2.0`)**

layer evidence와 최종 행동 상태를 분리한다.

권장 구조:

```text
correctness: pass | fail | error | not-run
structural: no-finding | finding | incomplete | error | not-run
asm: no-candidate | candidate | incomplete | error | not-run
asm_attribution: public | secret-risk | mixed | unresolved | not-applicable
timing_validity: valid | confounded | insufficient-power | environment-rejected | error | not-run
timing_signal: no-signal-observed | warning | signal | not-interpretable | not-run
review: not-needed | pending | reviewed | disputed | expired
overall: no-finding-observed | risk-detected | needs-review | inconclusive | tool-error
```

규칙:

- `timing_validity != valid`이면 timing signal은 최종 clean 근거가 될 수 없음
- layer 하나라도 error/incomplete면 `robust`류 외부 표현 금지
- `basis=review`를 note 한 칸으로 때우지 말고 reviewer artifact ID로 연결
- legacy 9-class taxonomy는 migration용으로만 보존

### `STAT-001` official dudect backend 기본화

**상태: 완료 (2026-07-30, `0.4.0a1`)**

가장 싸고 방어 가능한 선택:

- CT-KAT은 input generation, harness, build, execution, artifact orchestration 담당
- official dudect를 기본 statistical backend로 실행·parse
- 현재 Python 구현은 `experimental-first-order` backend로 격하
- 동일 raw trace를 두 backend에 넣는 parity test 제공

구현 결과:

- upstream `dc269651fb2567e46755cfb2a13d3875592968b5`의 `dudect.h`와
  license를 exact vendoring하고 SHA-256 drift를 fail-closed 검사
- 별도 C adapter process가 upstream 통계 함수를 직접 호출
- calibration 전용 첫 trace와 analysis trace를 독립 실행
- 같은 binary에 domain-separated runtime seed를 줘 두 trace의 deterministic
  input stream도 분리하고 두 seed를 artifact에 기록
- uncropped first-order 1 + crop 100 + second-order 1 = 102개 test 전체 저장
- upstream minimum, max `|t|`, `tau`, detection estimate를 lossless JSON으로 저장
- 기존 Python 구현은 `experimental-first-order` explicit opt-in으로 격하
- `bonferroni_correct`는 경고 migration만 남기고 실제 동작명
  `sqrt_m_threshold_scaling`으로 교체
- backend-only synthetic 20회 A/A false alarm `0/20`, `d=0.2` detection
  `20/20`, uncropped same-trace `|Δt| ≤ 1e-9`
- QEMU와 Linux multi-CPU affinity, 과도/비대칭 zero drop을
  `environment-rejected`로 보존

당시 경계도 같이 고정했다. 이 calibration은 statistical adapter 검증이지
target 하니스 검증이 아니므로 `0.4.0a1`의 KEM/sign은 `confounded`,
generic은 `insufficient-power`였다. `0.5.0a1`부터 KEM/sign은 TIME-001
physical control을 실제로 통과한 run만 `valid` 후보가 되고, generic은
계속 target-specific control 전까지 `insufficient-power`다.

official dudect와 맞출 항목:

- uncropped first-order
- 100 percentile crop tests
- second-order test
- 최소 measurement 전 결론 유보
- max `|t|`, `tau=t/sqrt(n)`, detection estimate

현재 `sqrt(m)` 옵션:

- 즉시 `bonferroni_correct`라는 이름과 FWER 주장을 제거
- legacy config migration warning 제공
- 정말 multiple-testing p-value를 낼 경우 Welch df, two-sided p, Holm/Bonferroni
  adjusted p를 별도 구현·simulation 검증

### `TIME-001` KEM/sign timing harness v2

**상태: 구현 완료 (2026-07-30, `0.5.0a1`)**

아래 1–9는 생성 C, process runner, raw protocol CSV와 backend report schema
v2에 구현됐다. 6 target/8 axis의 실행 계약과 승격 전 검증은
[`measurement/native_timing_v2_campaign.yaml`](measurement/native_timing_v2_campaign.yaml)과
[`run_native_timing_campaign.py`](../scripts/run_native_timing_campaign.py)에
동결했다. 단, target별 physical acceptance artifact는 native corpus
refresh에서 생성한다. control 코드 unit test를 실제 native ML-KEM A/A
통과로 둔갑시키지 않는다. 상세 하니스 계약은
[`TIMING_HARNESS_V2.md`](TIMING_HARNESS_V2.md)에 고정했다.

공통 설계:

1. class 0/1 input pool을 측정 전에 모두 생성
2. 매 iteration setup 작업량 대칭화
3. 같은 주소의 work buffer에 선택 input 복사
4. timed region에는 target call만 유지
5. RDTSCP AUX 전후를 기록해 CPU migration sample 폐기
6. process/seed 반복
7. class label만 다르고 데이터는 같은 A/A negative control
8. 작은·중간·큰 seeded timing effect A/B positive control
9. raw sample drop 이유와 개수 기록

KEM 축:

- `sk`: fixed-vs-random key content, valid ciphertext, common address
- `ct`: fixed-vs-random valid ciphertext, fixed key
- `fo`: valid-vs-invalid ciphertext, fixed key
- setup-only placebo 축을 추가해 keygen/cache 잔류 효과 확인

signature 축:

- fixed-vs-random key, fixed message
- fixed key, fixed-vs-random message
- randomness/nonce policy를 target별 manifest에 기록
- variable-length signature encoding cost와 core signing cost를 분리

### `POWER-001` PASS 대신 검출 한계 보고

- target/run별 minimum detectable effect와 목표 power 사전 계산
- 3,000회 SPHINCS+를 자동 PASS로 두지 않음
- 여러 seed/process의 consistency 필요
- A/A false-alarm budget과 A/B power curve 공개
- host가 조건을 만족하지 않으면 `environment-rejected`

M2 종료 조건:

- [x] `FAIL + robust` 같은 모순 row가 schema상 생성 불가능
- [x] 기존 ML-KEM `|t|=145.316`은 `confounded`로 migration됨
- [x] 미실행 asm cell과 근거 없는 summary-only layer가 clean으로 승격되지 않음
- [ ] A/A control이 사전 false-alarm budget을 만족
- [ ] seeded effect가 목표 power로 반복 검출
- [x] backend-only synthetic A/A false-alarm budget과 injected-effect curve 존재
- [x] official/custom uncropped same-trace parity report 존재

앞의 미완료 두 항목은 실제 target/physical host 기준이다.
`timing-harness-v2` 구현 완료만으로 슬쩍 체크 처리하지 않는다. 다음 단계에서
native single-CPU로 corpus를 재실행하고 A/A false alarm, setup-placebo,
positive power curve, MDE를 target별로 커밋한 뒤에만 체크한다.

### `TIME-002` native corpus campaign

**상태: 실행 준비 완료 / 실측 보류 (2026-07-30, `0.6.0a1`)**

- [x] 현재 corpus timing row와 정확히 일치하는 6 target/8 axis manifest
- [x] Linux/x86_64, emulation/VM/container, single-affinity, clean-git,
  official adapter preflight
- [x] target별 paper setting override와 중단 후 `--resume`
- [x] raw/calibration/protocol/summary/backend artifact hash·row-count 검증
- [x] runtime backend/sample/seed가 YAML 기본값보다 우선하도록 corpus 병합 수정
- [x] curated corpus를 자동 수정하지 않는 승격 후보 CSV
- [ ] bare-metal native x86_64에서 campaign 실행
- [ ] 8개 축 모두 artifact review 후 corpus 재분류

실행·검증 명령과 exit-code 계약은
[`measurement/README.md`](measurement/README.md)에 있다. macOS/ARM,
Docker/QEMU, cloud VM 결과는 engineering smoke로 보존할 수는 있어도 위 두
체크를 닫지 못한다.

---

## M3-A — KyberSlash를 진짜 benchmark로 완성

**상태: `KS-001`·`KS-002` 완료 / `KS-003`·`KS-004`·`KS-005` 미완료
(2026-07-31, `0.7.0a1`)**

현재 target은 최신 PQClean ML-KEM source에 옛 `/KYBER_Q` 식 두 개를 함께 심은
**reconstructed seeded control**이다. useful하지만 “historical vulnerable
implementation reproduction”이라고 부르면 과장이다.

### `KS-001` ground-truth corpus 분리

최소 네 target:

1. stock patched ML-KEM
2. KyberSlash1-only
3. KyberSlash2-only
4. KyberSlash1+2

추가로:

- 논문/artifact가 사용한 historical source commit을 별도 import
- 모든 target의 KAT equivalence 확인
- source patch를 machine-readable diff로 보존
- expected vulnerable function, source line, secret origin을 ground-truth YAML에 기록

완료 내용:

- stock / KS1-only / KS2-only / KS1+2와 `pq-crystals/kyber@a621b8d`
  historical snapshot을 독립 target으로 동결
- 4개 modern target의 8회 full-KEM transcript byte equivalence와 historical
  smoke를 CI에서 검증
- 세 exact unified diff, 모든 marker/hash, fix commit chronology, IACR artifact
  member hash를 machine-readable manifest에 기록

### `KS-002` detection layer 구분

- Valgrind branch/address layer가 PASS하는 것을 negative expectation으로 고정
- asm-scan이 build별 `div/idiv/sdiv/udiv` 후보를 찾는 것을 candidate expectation으로 고정
- manual string hint가 아니라 secret operand dataflow로 최종 risk를 귀속
- 가장 현실적인 1차 선택은 KyberSlash 연구의 patched-Valgrind/TIMECOP 계열 backend adapter
- IR/LLVM taint는 후속 연구로 두되, 구현하면 backend 이름과 soundness 범위를 명시

완료 내용:

- ordinary Memcheck의 무검출을 negative expectation으로 유지
- assembly candidate expectation을 target별 exact function set으로 분리
- IACR artifact의 Valgrind 3.22.0 patch를 archive/tarball hash까지 pin하고
  Docker/CI canary를 추가
- full `kem_dec` secret-key-path와 direct polynomial-site operand attribution을
  서로 다른 report scope로 저장. 전자는 KS1까지만 taint가 도달하고, 후자는
  KS1 및 두 KS2 site를 정확히 귀속한다.
- Docker/에뮬레이션 결과는 operand attribution일 뿐 physical timing evidence가
  아니라는 promotion boundary를 report와 문서 양쪽에 고정

### `KS-003` build/architecture matrix

- x86_64: gcc/clang과 배포형 flag
- AArch64: gcc/clang cross-build assembly scan
- 가능하면 Cortex-A7 또는 Cortex-M4 historical attack platform
- compiler version과 emitted instruction을 cell 단위로 저장
- “division이 소스에 있음”과 “target CPU에서 operand-dependent latency가 있음”을 분리

### `KS-004` timing/attack evidence

- patched/vulnerable paired microbenchmark
- operand bin별 latency 분포
- 최소 2개 native microarchitecture 반복
- full key recovery를 재현하지 못하면 솔직히 leakage reproduction까지만 주장
- attack artifact까지 재현한 경우에만 “exploit reproduced” 표현 사용

### `KS-005` baseline 표

같은 source/build/input에서:

- CT-KAT structural
- CT-KAT asm candidate
- CT-KAT operand-attribution backend
- official dudect
- TIMECOP/patched Valgrind
- 가능하면 MicroWalk

M3-A 종료 조건:

- KS1/KS2를 독립적으로 검출·귀속
- patched control에서 같은 secret-risk가 사라짐
- candidate, secret attribution, timing signal을 서로 다른 열로 보고
- 모든 결론이 raw disassembly/trace/source diff로 역추적 가능

---

## M3-B — Falcon을 “미해결 한 줄”에서 비교 연구로 승격

### 먼저 바로잡을 해석

현재 `examples/pqc_falcon512`는 PQClean의 Falcon reference 계열이다. Falcon
관련 1차 문헌은 reference 구현이 constant-time이 아니며, 별도의 constant-time
구현이 존재한다고 명시한다. 따라서 현재 structural FAIL은 이상한 결과가 아니라
상당 부분 예상 결과다.

또한 2026-07-29 기준 NIST 공개 FIPS 목록에는 FIPS 206이 아직 없고, NIST는
FN-DSA를 개발 중인 표준으로 설명한다. 그러므로 corpus row를 그냥 `FN-DSA`라고
부르거나 최종 표준 적합성을 암시하면 안 된다.

### `FAL-001` target 이름과 provenance 정리

- 현 target을 `pqclean_falcon512_reference`로 명시
- Falcon-512와 Falcon-1024를 구분
- source commit을 full hash로 고정
- “reference”, “constant-time implementation”, “prospective FN-DSA”를 별도 field로 기록
- FIPS 206 draft/final이 나오면 별도 migration target 생성

### `FAL-002` constant-time comparator 추가

우선 후보:

- Thomas Pornin의 `c-fn-dsa`
- 필요 시 2019 constant-time Falcon implementation snapshot

비교 variant:

- reference clean C
- `c-fn-dsa` portable native-FP path
- `c-fn-dsa` integer floating-point emulation path
- dynamic key decode vs expanded key signing
- compressed/variable-length encoding vs core sampler

중요:

- 최신 `c-fn-dsa`는 prospective FN-DSA이므로 exact commit 기준 결과라고만 주장
- 결과가 예상과 다르면 implementation을 화이트리스트하지 말고 finding을 보존

### `FAL-003` taint boundary 분해

현재 API 한 방 하니스 외에 아래를 독립 row로 만든다.

1. encoded key decode
2. private-key completion/expansion
3. sampler core
4. signing acceptance loop
5. signature compression/encoding
6. full sign API

각 row에서 taint source를 분리:

- encoded `f`
- encoded `g`
- encoded `F`
- expanded tree/basis
- signing randomness
- public message/hash state

목표는 “FAIL 개수 28개”가 아니라 각 finding이 어느 secret origin과 어느
observable에 연결되는지 설명하는 것이다.

### `FAL-004` floating-point/instruction audit

현재 asm-scan의 integer division 목록만으로 Falcon을 다뤘다고 하면 안 된다.

- native FP와 emulation build를 분리
- 사용한 FP opcode, library call, division/sqrt/rounding path를 수집
- CPU별 latency assumption을 manifest에 명시
- NaN/Inf/denormal이 reachable하지 않다는 구현 전제는 source/reference 근거와
  runtime assertion으로 따로 확인
- 단순 opcode 존재를 leak verdict로 올리지 않음

### `FAL-005` timing protocol

- M2의 pool/common-buffer/A-A protocol 적용
- core sampler와 full signing/encoding을 별도 측정
- fixed-key/randomness 반복과 fresh-key 축을 분리
- signature length와 time의 상관을 별도 보고
- 여러 seed/process/host 반복
- reference vs CT comparator를 같은 환경에서 paired comparison

### `FAL-006` 최종 판정 원칙

- reference implementation: expected structural risk를 정확히 재현했는가
- CT implementation: configured profile에서 unexpected finding이 없는가
- timing PASS 하나로 CT 구현을 “증명”하지 않음
- structural FAIL이 설계상 isochronous rejection이라는 주장은 논문 근거,
  정확한 build, 2인 review 없이는 `needs-review`

M3-B 종료 조건:

- reference-vs-CT implementation 대조표 존재
- wrapper/decode/sampler/encoding finding이 분리됨
- native FP와 emulation 결과가 분리됨
- 현재 `needs-analysis` 한 줄이 재현 가능한 disposition 여러 개로 교체됨
- 이동 중인 FN-DSA 표준과 특정 source snapshot을 혼동하지 않음

---

## M4 — baseline과 corpus 일반화

### `BASE-001` same-corpus adapters

최소:

- official dudect
- TIMECOP 또는 KyberSlash patched-Valgrind 계열
- MicroWalk

도구마다 위협 모델이 다르므로 “정확도 93%” 하나로 줄 세우지 않는다.

공통 측정:

- supported / unsupported / crash / timeout
- known issue별 detection
- candidate 수와 review 후 concern 수
- setup 시간과 config LOC
- runtime / peak memory / artifact size
- human triage minutes
- reviewer agreement
- seed/host/compiler 반복의 disposition 일치율

MicroWalk는 x86 Pin tracer 제약이 있으므로 x86 baseline으로 명시하고, AArch64
미지원은 실패가 아니라 capability 범위로 기록한다.

### `CORP-001` 독립 codebase

parameter set이 아니라 upstream lineage로 센다.

우선순위:

1. 현재 PQClean clean corpus
2. `mlkem-native` portable/AVX2/AArch64
3. `mldsa-native`
4. `c-fn-dsa`
5. OpenSSL 3.5+ native PQ API를 통한 production integration case

`liboqs`를 쓸 경우 wrapper 하나를 새 codebase로 세지 말고, 실제 primary
implementation upstream을 기록한다.

권장 최소 목표:

- 독립 upstream 3개 이상
- reference와 optimized variant 모두 포함
- x86_64와 AArch64 structural/build artifact
- native timing microarchitecture 2종 이상
- production integration 1개

### `ABL-001` CT-KAT 자체 ablation

- single build vs full matrix
- structural only vs +asm candidate
- +operand attribution
- custom timing vs official dudect
- 자동 evidence만 vs review gate

보고:

- 추가로 발견한 case
- 추가 runtime
- candidate/review burden
- error/incomplete 증가
- final disposition 변화

M4 종료 조건:

- “통합이 유용하다”는 문장마다 같은 corpus 수치가 연결됨
- codebase/variant/parameter set을 따로 집계
- baseline 실패나 unsupported case를 조용히 제외하지 않음

---

## M5 — artifact와 논문 재작성

### `ART-001` 한 명령 재현

예시:

```bash
./scripts/reproduce_artifact.sh --profile paper-2027
```

생성물:

- source/config/dependency hashes
- compiler, Valgrind, objdump, backend versions
- OS/kernel/CPU/microcode/affinity/governor/turbo/SMT
- generated harness source와 binary hash
- Valgrind logs, disassembly, timing raw traces
- review/declassification records
- v2 CSV/JSON/Markdown
- paper tables/figures
- 전체 SHA-256 manifest

Docker:

- base image digest 고정
- package version 또는 snapshot repository 고정
- structural container 결과와 native timing 결과를 분리

### `REVIEW-001` auditable declassification

registry v2 필드:

```yaml
family:
implementation:
source_commit:
function:
source_lines:
build_cells:
threat_model:
secret_origin:
observed_dependency:
declassification_predicate:
public_transcript:
security_argument:
known_limitations:
reviewer_1:
reviewer_2:
review_date:
expiry_conditions:
artifact_links:
```

- exact source/build 단위
- 두 명의 독립 reviewer
- agreement와 disagreement 공개
- source/compiler/standard 변경 시 자동 expiry
- `accepted-variable-time` 대신 `reviewed-declassification` 계열 용어 검토

### `PAPER-001` 결과 뒤 논문

권장 구조:

1. threat model / non-goal
2. orchestrator design
3. evidence schema와 default-deny semantics
4. methodology validation
5. KyberSlash ground-truth study
6. Falcon reference-vs-CT study
7. same-corpus baseline
8. diverse implementation evaluation
9. human triage cost/agreement
10. limitations / artifact reproduction

삭제하거나 낮출 표현:

- `robust implementation`
- `specification-permitted variable-time`의 무근거 일반화
- `dudect` protocol parity 없는 상태에서의 동일시
- baseline 없이 “기존 도구가 놓친다/더 실용적이다”
- seeded reconstruction을 historical exploit reproduction이라고 부르는 표현

### `BLIND-001` 비개발자 재실행

- clean machine에서 문서만 보고 실행
- 숨은 local file이나 Downloads 의존 금지
- 표·그림 hash 비교
- 실패 단계와 수동 개입 시간 기록

M5 종료 조건:

- raw artifact에서 논문 숫자를 한 명령으로 재생성
- 비개발자 blind rerun 성공
- 논문 claim과 표 사이 추적 링크 존재

---

## 5. 권장 PR/작업 묶음

한 PR에 세상을 다 넣지 말고 아래 순서로 자른다.

| 순서 | 작업 묶음 | 핵심 산출물 |
|---:|---|---|
| 1 | `release-plumbing` | wheel, metadata, CI, license, README drift |
| 2 | `evidence-schema-v2` | layer evidence + 5-state overall + migration |
| 3 | `timing-backend-v2` | official dudect, backend validity/calibration/parity |
| 4 | `timing-harness-pools` | KEM/sign pool, common buffer, AUX rejection |
| 5 | `native-timing-campaign` | frozen 8-axis plan + preflight/runner/validator |
| 6 | `kyberslash-ground-truth` | KS1/KS2/stock/historical + operand attribution |
| 7 | `falcon-comparators` | PQClean reference vs `c-fn-dsa` variants |
| 8 | `baseline-adapters` | TIMECOP/MicroWalk same-corpus |
| 9 | `diverse-corpus` | mlkem-native/mldsa-native/OpenSSL/AArch64 |
| 10 | `paper-artifact` | one-command reproduction + blind rerun + rewrite |

각 묶음은 코드, regression test, 문서, migration note, raw artifact schema를
같이 끝내야 한다. “코드만 먼저 넣고 문서는 나중에”는 지금 README drift가 왜
생겼는지 재연하는 짓이다.

---

## 6. Go/No-Go gate

### 공개 alpha

- [x] wheel/sdist에 template 포함
- [x] source tree 밖 clean-install smoke
- [x] CI Python matrix와 Linux Valgrind smoke
- [x] `ctkat --version`
- [x] README generated result drift 0
- [x] third-party inventory 100%
- [x] shell opt-in 정책

### timing 결과 공개

- [x] timing validity가 별도 field
- [ ] A/A control 통과
- [ ] positive-control power curve
- [x] backend-only synthetic A/A/effect curve/parity
- [x] official dudect backend 또는 명시적 experimental 명칭
- [x] confounded/underpowered row가 clean 근거로 사용되지 않음
- [ ] seed/process/host 반복 정책 충족

### 논문 제출

- [ ] same-corpus baseline
- [ ] 독립 upstream 3개 이상
- [ ] x86_64/AArch64 build evidence
- [ ] native timing microarchitecture 2종
- [x] KyberSlash KS1/KS2 non-timing ground truth
- [ ] KyberSlash native timing / architecture matrix / attack reproduction
- [ ] Falcon reference-vs-CT comparator
- [ ] matrix ablation과 human triage cost
- [ ] 2인 declassification review
- [ ] one-command table/figure regeneration
- [ ] blind rerun

하나라도 안 되면 해당 claim을 빼거나 제출을 미룬다. note 한 줄로 덮고
`robust` 박는 꼼수는 금지한다.

---

## 7. 당장 다음 작업

바로 착수할 순서는 이것이다.

1. ~~`PKG-001`, `DOC-001`, `LIC-001`, `CI-001`~~ — 완료
2. ~~schema v2와 legacy migration~~ — 완료
3. ~~official dudect backend와 timing validity~~ — 완료
4. ~~KEM/sign pool 하니스 + physical control/power 프로토콜 구현~~ — 완료
5. **기존 corpus native v2 캠페인 준비** — 실행기·검증기 완료,
   bare-metal 실측/재분류만 `blocked-by-native-host`
6. ~~**KyberSlash ground-truth의 non-timing target/provenance부터 확장**~~
   — 완료 (`0.7.0a1`); native timing/attack은 별도 미완료
7. **Falcon reference-vs-CT comparator의 build/structural 기반 확장** — 다음
8. native 장비 확보 즉시 5번 campaign 실행·artifact review·재분류

첫 구현 batch의 완료 기준:

- wheel 설치본 렌더 성공
- README/CSV drift 제거
- `FAIL + robust` 생성 불가
- `bonferroni_correct` 오명 제거
- ML-KEM `sk` row가 `confounded`로 보임

여기까지 끝나기 전에는 새 target 숫자 늘리기를 보류한다.

---

## 8. 주요 리스크

| 리스크 | 영향 | 대응 |
|---|---|---|
| native x86/AArch64 장비 부족 | timing·arch claim 차단 | structural과 native timing artifact 분리, 장비 확보 전 claim 제한 |
| Cortex-M historical 재현 비용 | KyberSlash exploit claim 지연 | leakage reproduction과 full exploit을 별도 milestone로 분리 |
| MicroWalk Pin/x86 제약 | 모든 arch baseline 불가 | x86 capability 표에 명시, unsupported를 결과로 기록 |
| FN-DSA 표준 변경 | Falcon target drift | exact commit/variant 명시, 표준 발표 시 migration |
| 2인 reviewer 부족 | declassification gate 차단 | `needs-review` 유지, 한 명 판단으로 clean 승격 금지 |
| 범위 폭발 | 논문보다 도구 공사만 계속됨 | M1/M2 gate 뒤 KS/Falcon/baseline 순서 고정 |

---

## 9. 1차 자료

- [official dudect source](https://github.com/oreparaz/dudect)
- [KyberSlash paper and artifact index](https://kyberslash.cr.yp.to/papers.html)
- [KyberSlash ePrint](https://eprint.iacr.org/2024/1049)
- [MicroWalk](https://github.com/microwalk-project/Microwalk)
- [Falcon project](https://falcon-sign.info/)
- [Constant-time Falcon implementation paper](https://eprint.iacr.org/2019/893)
- [`c-fn-dsa`](https://github.com/pornin/c-fn-dsa)
- [NIST FIPS 206 presentation](https://csrc.nist.gov/Presentations/2025/fips-206-fn-dsa-falcon)
- [NIST current FIPS publications](https://csrc.nist.gov/publications/fips)
- [PQClean](https://github.com/PQClean/PQClean)
- [liboqs implementation provenance](https://github.com/open-quantum-safe/liboqs)
