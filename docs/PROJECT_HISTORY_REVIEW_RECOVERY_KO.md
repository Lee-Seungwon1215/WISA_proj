# CT-KAT 프로젝트 연혁: 기원, WISA 리뷰, 리젝 복구, 현재 상태

- 기준일: 2026-08-11
- 기준 버전: `0.12.0a4`
- 기준 커밋: `df3f356`
- 주요 입력: 2026-07-28 `WISA리젝리뷰종합.md`,
  [리젝 복구 로드맵](ROADMAP_REJECTION_RECOVERY.md), 현재 코드와 동결된 산출물

## 0. 이 문서의 목적

이 문서는 논문 원고를 다시 쓰기 전에 프로젝트의 사실관계를 한 번 고정하기 위한
회고 문서다. 다음 질문에 한 파일로 답하는 것이 목적이다.

1. CT-KAT은 원래 어떤 문제를 해결하려고 만든 프로젝트인가?
2. 초기 버전은 어떤 구조로 만들어졌고 WISA 논문에서는 무엇을 주장했는가?
3. 리뷰는 무엇을 장점으로 봤고 무엇을 문제로 지적했는가?
4. 각 지적을 코드, 실험 설계, evidence, 문서에 어떻게 반영했는가?
5. 리뷰가 직접 요구하지 않았지만 후속 감사에서 추가로 고친 것은 무엇인가?
6. 현재 무엇이 완료됐고 무엇은 사람·장비·논문 작성 단계로 남아 있는가?

이 문서는 논문 결과를 대신하지 않는다. 특히 아직 실행하지 않은 두 호스트의 final
timing을 완료된 결과처럼 쓰지 않는다.

## 1. 한 줄 요약

CT-KAT은 처음에는 **KAT, Valgrind 구조 검사, Welch t-test timing을 한 번에 돌리는
PQC constant-time 검사 프레임워크**로 시작했다. 이후 compiler/optimization matrix,
assembly 후보 수집, 수동 triage, corpus와 논문 표까지 붙으면서 WISA 논문으로
확장됐다.

WISA 리뷰의 핵심 판정은 다음과 같았다.

> 엔지니어링은 제법 잘했지만, 설치·결과 의미론·timing 방법론·baseline·구현
> 다양성·사람 판정의 근거가 논문 주장보다 약하다.

리젝 이후에는 새 detector를 억지로 발명하지 않았다. 대신 프로젝트의 정체성을
**여러 불완전한 신호를 정확한 build provenance와 default-deny review 아래 묶는
감사 가능한 screening orchestrator**로 다시 잡고, 패키징부터 evidence schema,
official dudect, 물리 측정 protocol, KyberSlash/Falcon ground truth, 동일 corpus
baseline, 독립 upstream, blind artifact까지 순서대로 다시 만들었다.

현재 코드와 측정 준비는 거의 끝났다. 그러나 final 결과는 아직 없다. 남은 큰 외부
조건은 독립 2인 리뷰, 서로 다른 물리 x86_64 Linux 호스트 두 대의 실행, 측정 후
승격 리뷰다. 실제 논문 LaTeX 본문도 새 프로젝트 기준으로 다시 써야 한다.

## 2. 처음에는 어떤 프로젝트였나

### 2.1 출발점이 된 문제

PQC C 구현은 KAT(Known Answer Test)를 통과해도 constant-time이라고 말할 수 없다.
KAT은 암호 결과가 맞는지만 확인하며 다음 문제는 별도로 남는다.

- 비밀값에 따라 branch가 갈리는가?
- 비밀값으로 메모리 주소를 고르는가?
- 정수 나눗셈처럼 operand에 따라 지연이 달라질 수 있는 명령이 남는가?
- 실제 실행 시간 분포에 입력 class별 차이가 있는가?
- compiler와 optimization이 바뀌면 관찰 결과도 바뀌는가?
- 도구가 실패하거나 일부 경로만 검사했는데도 사용자가 PASS로 오해하지 않는가?

기존 도구들은 각자 다른 질문에 답한다. 문제는 한 도구의 PASS를 전체
constant-time 보증처럼 읽기 쉽고, 빌드·하니스·입력·환경이 달라진 증거를 한
결론으로 섞기 쉽다는 점이었다. CT-KAT은 이 운영 문제를 줄이기 위해 시작됐다.

### 2.2 초기 구조

첫 커밋 `20a20f7`부터 프로젝트는 단순 shell script 한 장은 아니었다. Python
패키지, CLI, Pydantic YAML schema, Jinja2 C harness generator, Valgrind parser,
timing harness, 통계, 리포트와 Docker 환경을 함께 넣었다.

초기 파이프라인은 다음과 같았다.

```text
YAML target specification
        |
        +--> build
        +--> KAT / round-trip correctness
        +--> generated C harness
        |       +--> Valgrind/Memcheck structural observation
        |       `--> timing measurement + Welch t-test
        `--> CSV/JSON report + combined verdict
```

각 층의 원래 역할은 다음과 같았다.

| 층 | 질문 | 잡을 수 있는 것 | 단독으로 못 하는 것 |
|---|---|---|---|
| KAT | 구현 결과가 맞는가? | 기능 오류 | 부채널 위험 |
| Valgrind/Memcheck | secret-tainted 값이 branch/address에 쓰였는가? | 동적 구조 의존성 | 실행하지 않은 경로, operand latency |
| timing | 두 입력 class의 시간 분포가 다른가? | 경험적 timing 신호 | 원인 위치, 모든 작은 효과의 부재 증명 |
| 종합 verdict | 증거를 어떻게 사용자 행동으로 바꿀까? | 일관된 보고 | 입력 증거가 잘못되면 올바른 결론 보장 불가 |

초기 버전은 header parser와 이름 기반 secret/public 추론, generic/KEM/signature
하니스, toy branch/lookup/timing control, PQClean ML-KEM 예제를 제공했다. macOS에서
Valgrind가 동작하지 않는 문제는 Linux/amd64 Docker로 우회했다.

### 2.3 초기 설계가 좋았던 부분

- 하나의 YAML에서 build, KAT, 구조 검사와 timing을 연결했다.
- 암호 API마다 반복되는 C harness 작성을 template으로 줄였다.
- 로그와 CSV/JSON을 남겨 사람이 결과를 다시 볼 수 있게 했다.
- 도구 오류와 finding을 구분하려는 fail-closed 방향이 일찍부터 있었다.
- 실제 PQC C 소스를 toy 예제와 함께 다루려 했다.

### 2.4 초기 설계의 약점

초기 README는 세 층을 통과하면 `CLEAN`, `LOW_RISK`, `SUSPECT`, `RISKY`,
`CRITICAL` 같은 종합 verdict를 주는 구조였다. 이것은 사용하기는 쉬웠지만 다음을
한 상태명에 너무 일찍 섞었다.

- correctness가 실제로 실행됐는지
- 구조 finding이 있었는지
- assembly scan이 완전했는지
- timing 실험이 유효했는지
- 사람이 어떤 근거로 finding을 해석했는지

또한 자체 Welch 통계를 `dudect`라고 부르고, QEMU나 불안정한 환경의 숫자를 실제
보안 결론 가까이 읽을 위험이 있었다. 이 약점은 뒤의 WISA 리뷰에서 그대로
공격받았다.

## 3. WISA 제출 전까지 어떻게 확장됐나

### 3.1 fail-open과 오류 처리 보강

초기 구현 뒤 여러 차례 외부·내부 감사를 거치며 다음을 보강했다.

- Valgrind 오류, log 누락, sentinel 누락을 0 finding으로 읽지 않게 수정
- compiler·tool 누락, timeout, malformed YAML과 parser 오류를 명시적 ERROR로 보존
- YAML 값이 생성 C source로 들어갈 때의 injection 방어
- subprocess, encoding, regex, header parsing과 CLI exit-code 회귀 수정
- timing class balance, zero-cycle sample, seed, batch 안정성과 effect size 보고

이 시기의 핵심 변화는 “에러가 났는데 우연히 clean으로 보이는 경로”를 계속
닫은 것이다.

### 3.2 build sensitivity와 KyberSlash 방향

Valgrind는 secret-dependent branch/address를 관찰하는 데 유용하지만,
KyberSlash처럼 secret-derived operand가 variable-latency division에 들어가는
문제는 직접 잡지 못한다. 그래서 다음 기능이 추가됐다.

- compiler × optimization `ct-matrix`
- 여러 build의 disassembly를 수집하는 `asm-scan`
- division/remainder 후보와 symbol/build provenance 기록
- compiler가 위험 명령을 없애거나 남기는 positive control
- stock ML-KEM과 KyberSlash seeded variant 비교

중요한 경계는 당시에도 있었다. `asm-scan`은 secret dataflow를 증명하는 detector가
아니라 **여러 빌드에서 검토할 명령 후보를 수집하는 층**이다. 최종 attribution은
source/disassembly와 사람의 검토가 필요하다.

### 3.3 corpus와 수동 triage

toy control만으로는 논문이 되기 어려워 PQClean 기반 corpus가 확장됐다.

- ML-KEM 512/768/1024
- ML-DSA 44/65/87
- SLH-DSA의 전신 구현인 SPHINCS+ profile
- Falcon-512 feasibility target
- KyberSlash seeded variant
- secret branch/address와 build-flip synthetic control

구조 finding을 무조건 결함으로 부르지 않기 위해 `accepted-variable-time` registry와
review/stop basis가 들어갔다. 방향은 보수적이었지만, 당시에는 한 사람의 note와
넓은 function attribution으로 clean에 가까운 결론을 줄 여지가 있었다.

### 3.4 WISA 논문의 당시 이야기

제출 당시 논문은 CT-KAT을 다음처럼 설명했다.

- KAT, Valgrind, compiler/optimization matrix, asm-scan과 timing을 통합한다.
- baseline ML-KEM은 `robust`로 분류한다.
- KyberSlash reproduction은 variable-latency secret risk로 분류한다.
- ML-DSA와 SPHINCS+의 일부 variable-time behavior는 review로 수용한다.
- Falcon-512는 근거 부족으로 `needs-analysis`에 남긴다.
- PASS를 constant-time proof라고 부르지 않는다.

이 스토리의 장점은 default-deny와 build sensitivity였다. 약점은 실제 corpus가 거의
PQClean 한 계열이었고, timing 유효성·baseline·독립 review·일반화 증거가 얇은데
`robust`와 `accepted` 같은 단어는 강했다는 점이다.

## 4. 리뷰는 어떻게 왔나

### 4.1 전체 판정

2026-07-28 종합 리뷰는 프로젝트를 장난감으로 보지는 않았다. YAML에서 하니스를
만들고 여러 분석을 provenance-bearing pipeline으로 묶은 엔지니어링, 실패를
PASS로 세탁하지 않으려는 철학, build matrix의 실용성은 명확한 장점으로 인정했다.

하지만 용도별 판정은 냉정했다.

| 용도 | 당시 판정 | 이유 |
|---|---|---|
| 내부 연구 프로토타입 | 사용 가능 | 코드와 테스트 기반은 강함 |
| 공개 alpha | 출시 보류 | 설치 wheel에서 template 누락 |
| tool/artifact track | major revision | 재현성, baseline, timing validity 부족 |
| 일반 논문 | weak reject 권고 | 비교 이득, 일반화, 통계, 독립 finding 근거 부족 |

이를 가장 짧게 줄이면 다음과 같다.

> 검사 운영체계는 잘 만들었지만, 기존 방식보다 연구적으로 무엇이 얼마나 좋아졌는지
> 보여주는 평가가 부족했다.

### 4.2 리뷰가 인정한 강점

- 자동 harness 생성과 통합 workflow
- compiler/optimization별 build sensitivity 보존
- tool error와 incomplete analysis를 숨기지 않으려는 설계
- asm 후보와 자동 verdict를 무작정 합치지 않는 태도
- Falcon을 근거 없이 안전하다고 통과시키지 않은 점
- 새 detector보다 screening artifact로 포지셔닝할 가능성

### 4.3 핵심 지적

| ID | 지적 | 왜 치명적이었나 |
|---|---|---|
| `REL-001` | wheel에 Jinja template 0개 | source checkout 밖에서는 핵심 기능이 깨짐 |
| `DOC-001` | README 수치와 corpus CSV 불일치 | 어느 숫자가 진짜인지 신뢰할 수 없음 |
| `TIME-001` | KEM key class별 setup과 주소가 다름 | `|t|=145`가 decapsulation이 아니라 harness confound일 수 있음 |
| `VERD-001` | 같은 행에 timing FAIL과 `robust` 공존 | note를 읽지 않으면 결과 의미가 반대로 보임 |
| `STAT-001` | `sqrt(m)` threshold scaling을 Bonferroni처럼 명명 | 수학적으로 Bonferroni/FWER 주장을 할 수 없음 |
| `STAT-002` | 자체 5-cutoff Welch를 `dudect`라고 부름 | official protocol과 다른데 같은 권위를 빌림 |
| `LEGAL-001` | vendored source/license/provenance 불완전 | 공개 배포와 artifact 신뢰성 차단 |
| `EVAL-001` | TIMECOP·MicroWalk 동일 corpus 비교 없음 | “기존 도구를 보완한다”가 사례담에 머묾 |
| `EVAL-002` | 사실상 PQClean 한 upstream 계열 | parameter set 수를 일반화 증거로 셀 수 없음 |
| `TRIAGE-001` | 수동 declassification 근거와 독립성 부족 | fresh/public이라는 이유만으로 secret 의존을 안전 처리할 위험 |
| `TAX-001` | 9개 verdict 중 일부만 실제 행사 | 상태 수는 많지만 다음 행동이 명확하지 않음 |
| 평가 전반 | sample/power/seed/host 정책 불균일 | timing PASS의 검출 한계를 설명할 수 없음 |
| 논문 전반 | 신규 finding 또는 강한 대체 평가가 없음 | novelty를 engineering 밖에서 입증하지 못함 |

리뷰는 “3 codebase, 20 target” 같은 숫자를 절대 법칙으로 제시한 것은 아니었다.
핵심은 파라미터셋을 부풀려 세지 말고, 독립 upstream·variant·architecture·실제
integration을 구분해 보고하라는 것이었다.

## 5. 리뷰를 받고 방향을 어떻게 다시 잡았나

### 5.1 프로젝트 정체성 수정

리젝 뒤 프로젝트의 중심 문장을 다음처럼 고정했다.

> CT-KAT은 새로운 constant-time detector가 아니라, correctness, 동적 구조 관찰,
> cross-build assembly 후보, operand attribution, empirical timing과 독립 review를
> 정확한 provenance 아래 결합하고 증거가 부족하면 결론을 거부하는 screening
> orchestrator다.

즉 “뭔가 새로운 알고리즘을 발명했다”가 아니라 다음을 기여로 삼았다.

1. evidence orchestration
2. compiler/flag별 build provenance
3. default-deny evidence semantics
4. 자동 증거와 사람 판단의 분리
5. raw artifact에서 표와 최종 disposition까지 재생성하는 workflow

### 5.2 수정 순서

비싼 측정을 먼저 돌리지 않았다. 하니스와 schema가 틀린 채 측정하면 나중에 전부
다시 해야 하기 때문이다. 순서는 다음처럼 고정했다.

```text
패키징/문서 신뢰성
    -> evidence 의미론
    -> timing backend와 physical harness
    -> KyberSlash/Falcon ground truth
    -> same-corpus baseline
    -> 독립 upstream/architecture
    -> paper artifact 동결
    -> 사람 리뷰와 두 호스트 final 측정
    -> 논문 재작성
```

## 6. 실제로 무엇을 고쳤나

### 6.1 M1: 공개 alpha의 기본기 복구 (`0.2.0a1`)

리뷰의 `REL-001`, `DOC-001`, `LEGAL-001`을 먼저 닫았다.

- wheel/sdist에 모든 Jinja2 template과 timing support resource 포함
- `importlib.resources` 기반 loader로 설치 위치 의존 제거
- source checkout 밖 clean install/render/compile smoke test
- Linux Valgrind와 gcc/clang CI
- `ctkat --version`, package metadata, `CHANGELOG`, `SECURITY`, `CITATION`
- `THIRD_PARTY_NOTICES.md`와 vendored source inventory
- README 결과 블록을 corpus에서 생성하고 drift를 CI에서 차단
- shell command는 명시적 opt-in이 필요한 정책으로 전환

결과적으로 “저장소 안에서는 되는데 설치하면 깨지는 프로젝트” 상태를 벗어났다.

### 6.2 M2-A: evidence schema v2와 외부 5상태 (`0.3.0a1`)

`FAIL + robust` 같은 모순을 구조적으로 막기 위해 결과를 층별로 분리했다.

```text
correctness
structural
asm / asm attribution
timing validity / timing signal
review state / review artifact
overall
```

외부 상태는 다음 다섯 개로 단순화했다.

- `no-finding-observed`
- `risk-detected`
- `needs-review`
- `inconclusive`
- `tool-error`

timing이 confounded거나 underpowered면 raw `PASS`/`FAIL`과 관계없이 clean 근거로
승격할 수 없다. review가 pending·expired·disputed이면 note 한 줄로 통과시킬 수도
없다. 이전 corpus는 파괴하지 않고 archive와 결정론적 migration을 남겼다.

### 6.3 M2-B: official dudect와 timing validity (`0.4.0a1`)

자체 통계를 official dudect와 동일시하던 문제를 고쳤다.

- exact revision의 official dudect backend pin
- uncropped, percentile과 higher-order를 포함한 official test set 사용
- 기존 자체 backend는 historical/experimental 의미로 분리
- synthetic A/A, injected-effect curve와 same-trace parity calibration
- timing result와 validity를 별도 필드로 보존
- seed, clock, host, exclusion과 effect 관련 metadata 기록

이후 논문의 timing 주장은 “PASS이므로 안전”이 아니라 “이 protocol과 power에서
관찰된 신호/무신호”로 제한됐다.

### 6.4 M2-C: timing-harness-v2와 물리 측정 계약 (`0.5.0a1`~`0.6.0a1`)

`TIME-001`을 해결하기 위해 KEM과 signature 하니스를 다시 설계했다.

- class별 입력 pool을 timed loop 전에 생성
- 양 class setup 작업량 대칭화
- 같은 주소의 common work buffer 사용
- timed region에는 대상 API만 남김
- seeded randomness interpose
- RDTSCP AUX로 CPU migration sample 제거
- A/A, setup placebo, 3단계 positive control
- 여러 process repeat, MDE/power artifact
- Linux bare-metal, CPU pinning, governor와 host manifest preflight
- resumable engineering run과 non-resumable final run 분리

“하니스를 만들 수 있다”와 “실제 target/host에서 control이 통과했다”는 계속
분리했다. 후자는 final 장비 실행 전까지 완료로 세지 않는다.

### 6.5 M3-A: KyberSlash를 ground-truth study로 확장 (`0.7.0a1` 이후)

초기 seeded variant 하나를 historical reproduction처럼 부르지 않도록 범위를
정리했다.

- stock, KS1-only, KS2-only, KS1+KS2 variant 분리
- vulnerable historical source와 exact patch/provenance 보존
- deterministic KEM equivalence와 KAT
- patched Valgrind/TIMECOP 기반 full-KEM 경로 증거
- direct operand-site attribution과 일반 full-API timing 분리
- compiler/optimization별 division 잔존 여부 보존

후속 engineering run에서는 v2 operand canary가 class별 heap source 주소와 잘못된
placebo 값 때문에 confounded인 사실을 발견했다. 이를 숨기지 않고 v2 trace의 final
재사용을 금지한 뒤 v3를 만들었다.

KyberSlash v3는 다음을 강제한다.

- 두 class 모두 같은 `ct_work` 주소와 고정 `sk_fixed` 사용
- branchless coefficient mask
- 실제 범위 안의 유효 placebo operand
- 모든 bin, warmup, measured call의 return-code witness
- generated source, linked inputs와 measured binary build seal

아직 **실제 key recovery나 full attack을 재현했다고 주장하지 않는다.** 현재 완성된
것은 source/operand ground truth와 final timing 실행 계약이다.

### 6.6 M3-B: Falcon을 comparator study로 재정의 (`0.8.0a1` 이후)

Falcon을 단순 `needs-analysis` 한 줄로 남기지 않고 비교 연구 대상으로 바꿨다.

- PQClean Falcon reference 512/1024
- prospective c-fn-dsa 512/1024
- native floating-point와 integer-FPR profile 분리
- encoded secret key, decode, sampler, signing core, encoding의 구조 관찰 분리
- deterministic KAT와 transcript 비교
- FP opcode, fenv와 linked-binary profile audit
- full-signature API와 variable output length 보존

engineering calibration에서 1024 integer-FPR positive control의 효과가 부족하다는
사실이 드러났다. target threshold나 결과를 유리하게 바꾸지 않고 해당 control
ladder만 올린 Falcon v2 campaign을 새로 동결했다. v1 trace는 calibration 전용이며
final 결과로 재사용할 수 없다.

c-fn-dsa는 prospective comparator다. **FIPS 206 적합성 구현이라고 주장하지 않는다.**

### 6.7 M4-A: 동일 corpus baseline (`0.9.0a1`)

`EVAL-001`에 대응해 같은 source/function/input contract에 세 도구를 연결했다.

- official dudect
- KyberSlash artifact의 patched TIMECOP
- MicroWalk PinTracer

도구마다 위협 모델이 다르므로 단일 정확도 숫자로 줄 세우지 않는다. 다음을 따로
기록하는 schema와 adapter를 만들었다.

- capability와 unsupported 상태
- finding/candidate/signal
- 실행 오류와 incomplete
- runtime과 artifact
- 사람 review 비용 자리

TIMECOP positive/negative structural control과 MicroWalk x86 CI gate가 있다. 하지만
official dudect physical result, 반복 안정성, 실제 사람 시간은 final 실행 전까지
pending이다.

### 6.8 M4-B: 독립 upstream과 architecture 확장 (`0.10.0a1` 이후)

`EVAL-002`에 대응해 PQClean parameter set만 늘리는 방식을 버렸다.

- exact-pinned `mlkem-native`
- exact-pinned beta `mldsa-native`
- OpenSSL 3.5.7 provider API integration
- x86_64/AArch64
- portable/native profile
- gcc/clang과 5개 optimization build cell
- upstream KAT와 profile 간 equivalence

동결된 source/build gate는 240 build/run cell, 24 upstream KAT, 120 equivalence
pair를 다룬다. 이 숫자는 timing 결과가 아니며, OpenSSL wrapper와 parameter set을
새 독립 lineage처럼 부풀려 세지 않는다. shared ancestry도 0이라고 가정하지 않는다.

후속 engineering run에서 mldsa-native native backend header와 public verifier
adapter 누락을 발견해 고쳤다. compile이 됐다는 사실만으로 signing correctness를
세지 않고, untimed sign-then-verify gate를 추가했다.

### 6.9 M5: paper premeasurement artifact 동결 (`0.11.0a1` 이후)

측정 전에 논문에 필요한 질문과 산출물을 machine-readable하게 고정했다.

- [실험 사전등록](measurement/EXPERIMENT_PREREGISTRATION.md)
- [최상위 paper campaign v5](measurement/paper_native_campaign_v5.yaml)
- [claim/evidence matrix](paper/CLAIM_EVIDENCE_MATRIX.yaml)
- [논문 골격](paper/PAPER_OUTLINE.md)
- corpus, ablation, campaign과 review readiness 생성 표
- exact source/config/dependency/compiler/artifact hash
- 독립 2인 review packet
- blinded analysis와 unblinding record
- one-command premeasurement/verification/paper-ready profile
- final evidence root와 blind rerun checklist

현재 최상위 timing 범위는 다음과 같다.

| component | target execution | timing axis | protocol row/host |
|---|---:|---:|---:|
| committed corpus refresh | 6 | 8 | 2,220,000 |
| KyberSlash contrast | 10 | 10 | 3,300,000 |
| Falcon contrast | 6 | 6 | 1,530,000 |
| diverse lineages | 4 | 4 | 1,170,000 |
| 합계 | 26 | 28 | 8,220,000 |

두 호스트 전체는 16,440,000 protocol row다. 이것은 입력 계획의 크기이지 26개
독립 구현이나 완료된 측정 결과를 뜻하지 않는다.

### 6.10 M6~M9: 실제로 돌려보기 전에 추가로 드러난 계약 오류 수정

engineering calibration과 네 관점의 자동 적대적 감사를 통해 리뷰 원문보다 더
깊은 문제를 발견했다.

1. **KEM `sk` 축의 의미 교정**
   secret key만 바뀌는 것처럼 보였지만 matching public ciphertext와 secret-key
   내부 public material도 같이 바뀌었다. machine axis를 `valid_tuple`로 바꾸고
   “secret-key leakage” attribution을 금지했다.

2. **signature correctness fail-closed**
   signing return code, output length, untimed public verification이 하나라도 실패하면
   timing row를 유효하게 만들 수 없도록 했다.

3. **variable signature length 분석**
   Falcon의 output-length distribution, duration/length association, repeat-level
   pairwise contrast와 family-local Holm adjustment를 구현했다.

4. **host disagreement 보존**
   서로 다른 두 host 결과를 평균내 깨끗한 결론으로 세탁하지 않는다. disagreement는
   그대로 최종 상태에 남는다.

5. **방향성 positive-control gate**
   절댓값 t-score만 보면 반대 방향 효과도 power 성공으로 오인할 수 있어, 주입한
   class 방향과 mean delta까지 확인하게 했다.

6. **모든 timing 축의 universal build seal**
   특별한 binary contract가 없는 축도 config, generated C, measured binary,
   linked inputs, compiler/flags와 replay argv를 첫 sample 전에 봉인한다.

7. **artifact와 blind analysis 무결성**
   host/component self-attestation만 믿지 않고 raw artifact hash, target identity,
   blinded/named output set과 canonical final evidence root를 연결했다.

8. **구버전 engineering trace 재사용 금지**
   v1/v2 calibration에서 드러난 confound를 수정한 뒤에는 campaign ID와 output root를
   바꾸고, 이전 trace를 resume·relabel·final promotion하지 못하게 했다.

이 수정의 중요한 태도는 “결과가 안 예쁘면 숨김”이 아니라 “하니스가 틀렸으면 그
결과를 폐기하고 계약 버전을 올림”이었다.

## 7. 리뷰 항목별 현재 대응표

| 리뷰 항목 | 반영 내용 | 현재 상태 |
|---|---|---|
| wheel template 누락 | package data, resource loader, clean install smoke | 완료 |
| README/CSV drift | generated block와 CI drift check | 완료 |
| KEM setup confound | pool/common buffer/control, 이후 `valid_tuple` 교정 | 구현 완료, final 재측정 대기 |
| timing FAIL + `robust` | evidence v2와 5상태 fail-closed fold | 완료 |
| 가짜 Bonferroni | 해당 명칭/의미 제거, official backend와 Holm secondary analysis | 완료 |
| dudect protocol 차이 | pinned official dudect, parity/calibration | 완료 |
| license/provenance | notices, exact revision/tree hash/inventory | 완료 |
| baseline 없음 | official dudect/TIMECOP/MicroWalk same-corpus adapter | 실행 계약 완료, physical result 대기 |
| PQClean 한 계열 | mlkem-native, mldsa-native, OpenSSL, x86/AArch64 build gate | source/build 완료, timing 대기 |
| 수동 triage 근거 약함 | exact source/build packet, expiry, 독립 2인 quorum | schema 완료, 사람 승인 대기 |
| 9개 taxonomy | 외부 5상태 + layer evidence 분리 | 완료 |
| sample/power 불균일 | 사전등록, A/A/placebo/power curve/repeat/two-host | 구현 완료, final 실행 대기 |
| KyberSlash가 seeded case뿐 | KS1/KS2/combined/historical provenance와 operand evidence | non-timing 완료, native timing 대기 |
| Falcon 한 줄 stop | 512/1024 reference vs 두 prospective profile comparator | non-timing 완료, paired timing 대기 |
| 한 명령 재현성 | premeasurement/verification/paper-ready profile와 hashes | 구현 완료, blind human rerun 대기 |
| 논문 비교 이득 약함 | ablation, baseline, diverse corpus와 claim matrix | premeasurement 표 완료, final 수치 대기 |

## 8. 리뷰보다 추가로 고친 부분

초기 WISA 리뷰는 큰 방향을 정확히 찔렀지만, 후속 자동 감사에서는 실행 계약의 더
세부적인 구멍이 발견됐다. 현재 저장소에는 네 관점의 감사 기록이 남아 있다.

| 감사 관점 | 추가로 확인한 대표 문제 | 처리 |
|---|---|---|
| artifact/blind integrity | host·component self-claim, resume 오염, post-review root 불일치 | artifact hash와 canonical root로 봉합 |
| ML-KEM/KyberSlash protocol | mixed tuple 과대귀속, 제거된 division, 잘못된 operand placebo | `valid_tuple`, linked-binary evidence, KyberSlash v3 |
| signature harness | return code/길이/verify 누락, ML-DSA rejection 과대 declassification | correctness gate와 review 경계 강화 |
| native statistics | host 평균 세탁, pairwise·heterogeneity 누락, 방향 반대 control | two-host analyzer와 directional gate 구현 |

자동 감사에서 `addressed`가 아닌 항목은 대부분 “코드로 사람이나 물리 세계를 증명할
수 없다”는 blocker다. 자동 에이전트 감사는 독립 사람 리뷰를 대신하지 않으며,
두 개의 실제 물리 장비가 존재한다는 사실도 소프트웨어만으로 증명하지 않는다.

## 9. 현재 CT-KAT은 어떤 프로젝트인가

현재 시스템의 개념적 흐름은 다음과 같다.

```text
exact source + YAML + dependency/compiler lock
                    |
                    v
          correctness / KAT gate
                    |
                    v
       generated structural/timing harness
          |         |          |
          v         v          v
   Valgrind/     build/asm    official dudect
   TIMECOP       evidence     + physical controls
          \         |          /
           \        |         /
            v       v        v
          layer-separated evidence v2
                    |
           exact review artifacts
                    |
         default-deny overall fold
                    |
       reproducible/blinded paper bundle
```

즉 현재의 CT-KAT은 다음 세 가지가 아니다.

- formal constant-time proof system
- asm opcode만 보고 secret leakage를 자동 확정하는 detector
- timing PASS 한 번으로 구현을 안전하다고 인증하는 도구

대신 다음을 목표로 한다.

- 서로 다른 위협 모델의 증거를 같은 target/build 단위로 모은다.
- 검사 실패와 미실행을 결과에서 지우지 않는다.
- 자동화가 판단할 수 없는 attribution은 review artifact로 분리한다.
- 증거가 부족하면 clean 대신 `needs-review`나 `inconclusive`에 멈춘다.
- 최종 논문 숫자가 raw artifact와 hash로 다시 추적되게 한다.

## 10. 현재 완료 상태

### 10.1 코드와 정적 준비

- 현재 패키지 버전: `0.12.0a4`
- 패키징, CI, template 배포와 clean-install smoke 준비 완료
- evidence schema v2와 legacy migration 완료
- pinned official dudect backend와 calibration 완료
- timing-harness-v2와 native runner/validator 완료
- KyberSlash v3, Falcon v2, diverse v2, corpus native v3 동결
- same-corpus 세 도구 adapter와 artifact schema 완료
- one-command engineering/paper artifact gate 완료
- 네 관점 자동 감사의 critical/high finding은 수정되었거나 명시적 외부 blocker로 남음

### 10.2 현재 committed corpus

생성 표 기준 현재 corpus는 25개 target/harness pair다.

- `risk-detected`: 6
- `needs-review`: 5
- `inconclusive`: 10
- `no-finding-observed`: 4

toy 네 행은 correctness 미실행을 숨기지 않아 clean으로 fold되지 않는다. 과거의
confounded/underpowered timing 숫자도 보존은 하지만 final clean evidence로 쓰지
않는다.

### 10.3 아직 완료가 아닌 것

다음은 코드가 없어서가 아니라 외부 증거가 아직 없어서 완료가 아니다.

1. 측정 전 review packet 7종의 독립 2인 승인
2. 서로 다른 CPU model의 physical Linux x86_64 host 두 대 final 실행
3. 네 개 timing component와 same-corpus 세 도구의 양 host artifact
4. blinded analysis, unblinding과 host disagreement 검토
5. final evidence root에 대한 측정 후 독립 2인 promotion review
6. 실제 사람 triage 시간과 agreement 수치
7. 비개발자 blind rerun
8. 새 결과를 corpus와 논문에 명시적으로 승격

pending은 실패가 아니다. 하지만 완료도 아니다.

## 11. 데스크톱과 임베디드 범위

현재 final campaign의 실험 정의는 **두 개의 physical Linux x86_64 desktop-class
host**다. 이 정의는 Cortex-M4를 포함하지 않는다.

Cortex-M4에서 Python CLI, Valgrind, x86 PinTracer와 전체 official dudect host
workflow를 그대로 실행할 수는 없다. 임베디드 지원은 다음처럼 분리해야 한다.

- 호스트에서 config와 bare-metal harness 생성
- UART/SWD 등 board transport 정의
- DWT cycle counter 또는 board timer 정의
- interrupt, clock, cache/flash wait-state와 반복 정책 사전등록
- 지원되는 구조 검사와 board timing 결과를 별도 evidence schema에 연결

따라서 현재 프로젝트가 “데스크톱과 임베디드에서 모든 backend가 동일하게
동작한다”고 주장하면 틀리다. 더 정확한 방향은 **공통 orchestration/evidence
모델을 두되, desktop backend와 embedded measurement adapter를 분리하는 것**이다.

이 임베디드 track은 유효한 후속 연구지만, 현재 x86_64 final을 갈아엎고 모든 측정을
처음부터 다시 하게 만드는 선행조건으로 섞지 않는다.

## 12. 논문을 다시 쓸 때 달라져야 할 이야기

기존 논문은 “통합 도구로 몇 개 구현을 분류했다”가 중심이었다. 새 논문은 다음
순서가 맞다.

1. KAT, 구조 검사와 timing 단독 결과의 한계
2. threat model과 강한 non-goal
3. evidence schema와 default-deny semantics
4. compiler/build-sensitive provenance
5. timing-harness-v2와 사전등록된 물리 실험
6. same-corpus baseline과 ablation
7. KyberSlash ground-truth study
8. Falcon reference/prospective comparator study
9. 독립 upstream과 production integration
10. 사람 review 비용·합의와 한계
11. reproducible/blinded artifact

측정 전에도 system, methodology, non-timing result, experimental design과 limitation은
쓸 수 있다. final 측정 뒤에만 확정할 내용은 abstract의 수치, timing 결과 표,
host 비교, 결과 기반 discussion과 conclusion이다.

## 13. 앞으로 금지할 과장 표현

| 피할 표현 | 사용할 표현 |
|---|---|
| constant-time을 증명했다 | configured profile에서 finding이 관찰되지 않았다 |
| asm-scan이 leakage를 검출한다 | 여러 build의 variable-latency 후보와 provenance를 수집한다 |
| `valid_tuple` 신호는 secret-key leakage다 | public과 secret이 함께 변한 mixed-input contrast다 |
| KyberSlash attack을 재현했다 | exact source/patch와 operand/timing ground-truth를 재현했다 |
| c-fn-dsa는 FIPS 206 구현이다 | prospective Falcon/FN-DSA comparator다 |
| 네 개 독립 구현 | 네 primary lineage이며 shared ancestry는 별도 한계다 |
| 두 host 평균은 clean이다 | host별 결과와 disagreement를 각각 보존한다 |
| 자동 감사가 사람 review를 끝냈다 | 자동 감사는 engineering gate이며 사람 승인을 대체하지 않는다 |
| 계획이 있으므로 측정 완료 | campaign은 prepared-not-measured다 |

## 14. 전체 타임라인

| 시기 | 단계 | 대표 결과 |
|---|---|---|
| 초기 | CT-KAT 프레임워크 생성 | YAML, KAT, Valgrind, timing, report, Docker |
| 초기 확장 | fail-open hardening | error/incomplete를 clean으로 읽는 경로 봉쇄 |
| WISA 준비 | matrix/asm/corpus/paper | build sensitivity, PQClean corpus, 12p 초안 |
| 2026-07-28 | 종합 리뷰 | engineering 강점 인정, scientific validation major revision |
| 2026-07-30 | M1/M2 | release, evidence v2, official dudect, harness-v2 |
| 2026-07-31 | M3/M4 | KyberSlash, Falcon, baseline, independent upstream |
| 2026-08-07 | M5 | paper premeasurement artifact freeze |
| 2026-08-08~10 | M6~M8 | blind/statistics/signature/KEM 계약 보강 |
| 2026-08-11 | M9 | KyberSlash v3와 universal build provenance 동결 |
| 다음 | 외부 gate | 2인 리뷰, 두 host final, post-review, 논문 재작성 |

## 15. 관련 source of truth

- 사용자·도구 개요: [루트 README](../README.md)
- 리뷰 판정과 전체 로드맵: [ROADMAP_REJECTION_RECOVERY.md](ROADMAP_REJECTION_RECOVERY.md)
- 현재 evidence 의미론: [corpus_schema.md](corpus_schema.md)
- 현재 corpus: [corpus_summary.csv](corpus/corpus_summary.csv)
- timing-harness-v2: [TIMING_HARNESS_V2.md](TIMING_HARNESS_V2.md)
- 최상위 측정 안내: [measurement/README.md](measurement/README.md)
- 사전등록: [EXPERIMENT_PREREGISTRATION.md](measurement/EXPERIMENT_PREREGISTRATION.md)
- KyberSlash v3: [KYBERSLASH_NATIVE_V3.md](measurement/KYBERSLASH_NATIVE_V3.md)
- paper claim 상태: [CLAIM_EVIDENCE_MATRIX.yaml](paper/CLAIM_EVIDENCE_MATRIX.yaml)
- 측정 전 논문 골격: [PAPER_OUTLINE.md](paper/PAPER_OUTLINE.md)
- 독립 review packet: [reviews/paper/manifest.yaml](reviews/paper/manifest.yaml)
- 자동 적대적 감사: [audits/manifest.yaml](audits/manifest.yaml)
- artifact 절차: [artifact/README.md](artifact/README.md)

## 16. 최종 판단

CT-KAT은 리젝 뒤에 원래 프로젝트와 상관없는 기능을 마구 붙인 것이 아니다. 리뷰가
지적한 “설치도 안 되는 패키지, 의미가 충돌하는 결과표, confounded timing,
PQClean 한 집안 평가, baseline 부재, 약한 수동 판정”을 dependency 순서대로
해결하면서 원래 아이디어를 더 정직하고 감사 가능하게 만든 것이다.

리뷰 직후에는 **좋은 엔지니어링 프로토타입 + 약한 과학적 평가**였다. 현재는
**실행 계약과 artifact가 강하게 동결된 premeasurement 연구 시스템**이다. 다음
단계에서 필요한 것은 기능 폭발이 아니라, 이미 동결한 질문을 사람 리뷰와 물리
장비에서 그대로 실행하고 그 결과에 맞춰 논문을 쓰는 일이다.
