# CT-KAT × KyberSlash — 방향 결정 메모 (corrected, 최신 v8 — §8.7/§8.8)

> **⚠️ 먼저 읽을 것 (v8 기준 현재 결론)**: 아래 §0의 옛 한 줄("ct `-O0` operand 체크로
> x86에서도 KyberSlash 나눗셈을 잡는다")은 **Phase 0 실측에서 반증됨**(§8.7) — gcc는 상수
> 나눗셈을 `-O0`에서도 역수곱으로 죽이므로 ct(-O0, gcc) 바이너리엔 div가 없다. 실제로
> "작동하게" 만든 것은 **멀티-opt `ctkat asm-scan`**(warn-only, §8.8)이고, patched-Valgrind
> fork(Phase 2)는 보류다. §0~§5는 *판단 당시의 사고 기록*으로 남겨두되, 사실관계는
> **§8.7(실측 매트릭스) → §8.8(구현)** 순으로 신뢰할 것.
>
> **용도**: 나중에 "이거 기능으로 만들까 말까 / 만들면 어떻게" 결정할 때 보는 메모.
> 사실관계는 **실측 + 코드 앵커로 검증**했고, 한 번 틀렸다가(아래 §1) 정정한
> 버전이니 기준 문서로 삼을 것. 단 compiler/codegen 주장은 새 target이 추가될 때마다
> 반드시 objdump로 다시 깰 것. (교육용 설명은 `kyberslash_research.html`도 v3 기준으로
> 핵심 표현을 맞춤.)
>
> **v2 (2026-06): multi-agent + 직접 objdump 재검증.** 코드 앵커 8/8·논문 인용은
> 전부 실재, 방향성도 유지. 단 §2.2 표에서 **2셀 정정**(arm64 `/3329`, `/8`는
> `-O0`/`-Oz`에서 div 살아있음 — 옛 "없음"은 오류), §7.1 **논문 2편 attribution 분리**,
> §4에 **`-O0` over-flag 함정** 추가. 상세 정정 로그는 §1 3차 항목.
>
> **v3 (2026-06): 사람이 다시 쪼갬.** `/8`는 signed/unsigned가 다르다. signed `int / 8`은
> Apple clang에서 `-O0`/`-Oz`에 DIV가 살아있지만, unsigned `uint32_t / 8`은 x86에선
> `-O0`부터 shift다(arm64는 `-O0`만 `udiv`, `-Oz`/`-O2` shift). 그래서 옛
> "`/2^n`도 전부 div" 문장은 과장. 또 현재 CT-KAT 런타임은 Docker `linux/amd64`이고,
> arm64는 로컬 cross-target 실측일 뿐이다. Docker daemon이 꺼져 있어 Ubuntu gcc
> objdump는 이번 pass에서 직접 못 찍었다.
>
> **v4 (2026-06): 구현 착수 판단 추가.** "일단 넣고 보자" 기준으로 재검토:
> MVP는 CT-KAT 내부 `asm_scan`을 직접 구현해 warn-only 후보를 만들고, 정밀 탐지는
> KyberSlash 공식 patched Valgrind를 재사용하는 2단계가 현실적이다. 단 integer `mul`을
> 무지성 탐지하면 현재 ML-KEM fix(`*80635 >> 28`)도 걸릴 수 있으니, 초기 정책은
> division/mod/fp-div/sqrt 중심으로 제한한다(§8).

---

## 0. 결론 (한 줄)

> **⚠️ v8 정정**: 아래 첫 문장은 **틀렸다**(§8.7에서 실측 반증). gcc `-O0`은 상수 나눗셈을
> 역수곱으로 죽여 ct 바이너리에 div가 안 남는다. 현재 동작하는 결론은 §8.8(멀티-opt asm-scan).
> 아래는 *판단 당시 기록*으로만 본다.

기술적으론 **된다** — CT-KAT의 ct(`-O0`) 단계에 Valgrind operand 체크를 더하면
**x86에서도 KyberSlash류 비밀 나눗셈을 잡는다.** 그러나 **학술 신규성은 매우 약함**
(기법 = KyberSlash 논문/기존 operand-timing 모델의 CT-KAT 통합) + **Kyber는 이미 fix됨**
→ **새 연구라기보다 "도구 3축 완성"용 기능.** 만들면 **방법 B**, 안 만들면 HTML
문서로 충분.

**그리고 "KyberSlash 넘어서는 발전 방향"도 더블체크해보니 매력적인 길(컴파일러×
플래그×ISA 누수표면, Falcon FP)이 전부 2024-2025에 이미 출판됨 — 새 연구는
어렵다 (§7).** 현실적 길은 ①도구화/교육 포지셔닝 or ②새 버그 헌팅(high-risk)뿐.

---

## 1. 정정 이력 (믿을 수 있게 남김)

- **1차 판단 (틀림)**: "x86은 `-O0`~`-O3` 전부 div 없음 → objdump/VEX는 x86에서
  항상 빈손 → 소스 파싱만 유일한 길."
- **옆집 지적 + 재실측 (맞음)**: 이 머신이 Apple Silicon이라 `gcc -c`가 **arm64로
  컴파일**됐는데 그걸 "x86_64"라 착각했음. 진짜 x86_64는 **`-O0`/`-Oz`에서
  `/상수`가 `divl`로 살아있다.** (Apple clang 17 실측, §2.2)
- → **"x86 못 잡음"은 철회.** 정확히는 *"dudect(`-O2`) 타이밍으론 못 잡지만,
  ct(`-O0`) operand 패치로는 잡힌다."*
- 옆집 평가의 나머지(FindingType·repo 패치본·README·크로스툴체인 없음)는 **전부
  맞음**으로 확인.
- **3차 재실측 (2026-06, Claude multi-agent + 직접 `objdump` 50개 .o 전수)**: §2.2
  표를 5함수×2아키×5opt 디스어셈으로 재검증. **x86_64 컬럼·핵심 thesis는 전부 맞음**
  (매직상수 `0x9D7DBB41`/`0x13AFB`까지 대조). 그러나 **두 셀이 틀려서 정정**:
  - (a) `/3329` **arm64**도 `-O0`/`-Oz`에서 **`sdiv` 살아있음** — 옛 "전부 없음(곱셈)"은
    오류. *1차 arm/x86 혼동의 잔재가 arm64 컬럼에 그대로 남아있었던 것*(§2.2가 자기
    `%3329` arm64 행과도 모순이었음).
  - (b) signed `/2^n`(`/8`)도 `-O0`/`-Oz`에선 **div** — strength-reduction은 `-O1`+에서만.
    옛 "없음(shift)" 무조건은 오류.
  - 두 정정 모두 **Apple clang 실측 범위에선 결론을 강화**한다: `-O0`에서 취약 div가
    x86뿐 아니라 **arm64 target에서도 살아있다** → "ct `-O0` operand 패치로 잡힌다"가
    더 단단해짐. 단 현재 CT-KAT 런타임은 Docker amd64라 arm64는 참고자료다(v3).
  - 교훈(§0 메타룰 자기적용): "이제 신뢰하라"고 박은 표에도 구멍이 남는다. 통과 ≠ 정확.
- **4차 재실측 (v3)**: 3차의 `/8` 정정이 또 너무 컸음. unsigned `uint32_t / 8`은
  x86 Apple clang에서 `-O0`/`-Oz`/`-O2` 전부 shift, arm64 Apple clang에선 `-O0`만 `udiv`,
  `-Oz`/`-O2`는 shift. 즉 `/2^n` false-positive 함정은 **signed 또는 일부 target/옵션**의
  이야기지 무조건이 아니다. KyberSlash 본체(`/3329`)와 `/변수` 결론은 그대로.

---

## 2. 검증된 사실

### 2.1 코드 앵커 (CT-KAT 현재 상태)

| 사실 | 위치 |
|---|---|
| FindingType에 div/mul operand 타입 **없음** (branch/value/memory만) | `ctkat/valgrind_parser.py:7` |
| ct 기본 cflags = **`-O0`** | `ctkat/config.py` `_default_cflags` |
| dudect 기본 cflags = **`-O2`** | `ctkat/config.py` `_default_dudect_cflags` |
| 런타임 = **x86_64 Docker** | `docker-compose.yml:6` (`platform: linux/amd64`) |
| div/mul latency 미검출 **한계 명시** | `README.md:679` |
| repo ML-KEM = **fix본**(취약 `/KYBER_Q`는 주석, 실코드 `*80635>>28`) | `examples/pqc_mlkem768/clean/poly.c:146,149`(tomsg) `:31,34`(compress) |

### 2.2 실측 매트릭스 — 정수 나눗셈 명령 존재 여부 (Apple clang 17)

| 케이스 | x86_64 | arm64 |
|---|---|---|
| **`/3329` (KyberSlash, 상수)** | **`-O0`·`-Oz`=DIV 계열**(`divl`/`idivl`), `-O1`/`-O2`/`-Os`=없음 | **`-O0`·`-Oz`=DIV 계열**(`udiv`/`sdiv`), `-O1`/`-O2`/`-Os`=없음(곱셈) |
| `secret / 변수` | **전부 DIV 계열** | **전부 DIV 계열** |
| `% 3329` (모듈로 상수) | `-O0`·`-Oz`=DIV 계열, `-O1`+=없음 | `-O0`·`-Oz`=DIV 계열, `-O1`+=없음 |
| signed `/ 8` (2의 거듭제곱) | **`-O0`·`-Oz`=DIV**(`idivl`), `-O1`+=없음(shift/bias) | **`-O0`·`-Oz`=DIV**(`sdiv`), `-O1`+=없음(shift/bias) |
| unsigned `/ 8` (2의 거듭제곱) | **실측 subset `-O0`·`-Oz`·`-O2`=shift** | `-O0`=`udiv`, `-Oz`·`-O2`=shift |
| fix `*80635 >> 28` | 없음 | 없음 |

> **(v3 재검증 표시)** `/3329` 핵심 thesis는 그대로. 단 `/8`은 signed/unsigned를
> 분리해야 한다. KyberSlash 본체는 비-2^n 상수 3329라 이 nuance에 안 묻힌다.
> 매직상수 `0x9D7DBB41`(signed /3329 reciprocal), `0x3AFB7681`(unsigned /3329
> reciprocal), `0x13AFB`(=80635) 대조 완료.

**해석:**
- `/상수`(KyberSlash 패턴): **x86·arm64 둘 다 `-O0`/`-Oz`에서 DIV 계열**(`divl`/`idivl`,
  `udiv`/`sdiv`).
  `-O1`+에서만 reciprocal-multiply로 사라짐. (← 옛 버전은 arm64를 "전부 없음"이라
  적었으나 재실측 결과 틀림.)
- `/변수`(런타임 제수): **모든 아키·모든 `-O`에서 항상 div** → 보편적으로 위험한
  케이스(strength-reduction 불가). **가장 단단한 셀.**
- `%상수` ≈ `/상수`. `/2^n`은 **signedness/target/옵션에 따라 다름** — "항상 shift"도
  틀리고, "항상 div"도 틀림. fix = div 전혀 없음(모든 아키·모든 `-O`).
- **CT-KAT 실제 런타임은 Docker `linux/amd64` + ct `-O0`.** Docker gcc objdump는 이번
  pass에서 데몬이 꺼져 직접 못 찍었지만, Apple clang x86 `-O0`와 KyberSlash 논문/FAQ의
  gcc `-Os` 사례상 `/3329` 취약본은 DIV 계열이 살아있는 구간이다. arm64 결과는 현재
  런타임이 아니라 cross-target 참고자료.

---

## 3. 지금 코드로 취약본 돌리면 → 못 잡음 (이유 정밀)

| 레이어 | -O | 취약 div? | 지금 잡나? | 이유 |
|---|---|:--:|:--:|---|
| dudect | `-O2` | ❌(대개 곱셈) | ❌ | 시간차 0 |
| ct (Valgrind) | `-O0` | ✅(DIV 계열, Docker gcc는 다음 pass에서 objdump 확인 권장) | ❌ | 아래 |

> **중요**: ct 단계엔 DIV 계열 명령 + 비밀 taint가 **둘 다 있어도** 못 잡는다. 이유는
> ① FindingType에 operand 타입이 없고, ② **vanilla Memcheck가 "비밀이 div에
> 들어감"을 에러로 안 냄**(분기/주소/syscall만 에러, 산술은 undefined 전파만).
> → **"div가 남아있다 ≠ 자동 탐지된다." 패치가 있어야 잡는다.**

---

## 4. 만들 거면 — 옵션

| 옵션 | 내용 | 공수 | 평가 |
|---|---|---|---|
| **★ B. Valgrind operand 패치** | 기존 `-O0` ct Valgrind에 "tainted 피연산자 → variable-latency op 경고" 추가(div/mod/fp-div/sqrt 중심) | 높음(커스텀 valgrind 빌드+Docker 반영) | **정밀 최종형 1순위.** 하네스·taint·valgrind run **전부 재활용**, 크로스툴체인 불필요. = KyberSlash 논문 기법 그대로 |
| A. objdump `-O0` 스캔 | ct 바이너리 디스어셈 → div 명령 + 비밀함수 교집합 → Finding | 중 | 됨, 크루드(정밀 taint 아님) |
| 소스 파싱(`/` `%`) | 소스에서 비-2^n 나눗셈 flag (+taint면 정밀) | 중 | 포터블 대안. 단 주석/문자열 처리 위해 clang AST 필요, B보다 덜 정밀 |
| **none (문서만)** | 기능 안 만들고 HTML 교육 문서 유지 | 0 | **현실적 디폴트** (§5 근거) |

**방법 B 진행 시 first step:**
1. **Positive control 제작**: `poly.c`의 주석 `/KYBER_Q` 되살리고 ct 기본 `-O0`
   유지 → objdump로 DIV 계열 명령 확인 → 새 탐지가 잡는지 시험. 고친 버전 = negative control.
2. FindingType에 `SECRET_DEPENDENT_VARIABLE_LATENCY`(또는 좁게 `SECRET_DEPENDENT_DIVISION`)
   추가 → report/verdict 파이프라인
   자동 합류 (`valgrind_parser.py`). *(코드 확인: 새 FindingType은 verdict 매트릭스
   변경 없이 자동 FAIL로 흐름. 단 `report.py`의 `_RECOMMENDATIONS`에 권고문 1줄,
   `_FINDING_CLASSIFIERS`에 prefix 추가는 직접 해야 함 — plumbing 자체는 작음.)*
3. 패치드 Valgrind를 Docker 이미지에 반영 + ct 실행이 그걸 쓰게. *(진짜 공수는 Docker가
   아니라 Valgrind VEX 패치 + fork 유지보수. 대략 엔지니어링 1~2주 + 영구 maintenance.)*

> **⚠️ 방법 B의 숨은 함정 (v3 기준):** ct는 `-O0`에서 도는데 shipped 바이너리는 대개
> `-O2`/`-Os`다. 그래서 "tainted operand가 div에 들어감"만 보고 경고하면, 실제 배포
> 플래그에선 reciprocal-multiply/shift로 사라지는 소스도 may-leak로 트립할 수 있다.
> 특히 signed `/2^n` 또는 일부 target의 unsigned `/2^n`은 `-O0`에서 DIV가 살아날 수 있다.
> 다만 unsigned x86 `/8`처럼 `-O0`부터 shift인 케이스도 있어, 옛 "전부 div"는 과장이다.
> 정밀하게 하려면 결국 **divisor 값(2의 거듭제곱인지, 변수인지, 비-2^n 상수인지)**과
> **실제 배포 cflags/target**을 같이 봐야 한다.
>
> 함의 3가지:
> - (a) 방법 B의 `-O0` 경고는 **배포 바이너리 기준보다 보수적** — 특히 비-2^n 상수나눗셈은
>   `-O2`에서 사라져도 `-O0`에선 트립할 수 있다.
> - (b) **"방법 B ≫ 소스파싱" 우열이 흔들림**: 안전/위험 상수 구분엔 소스/operand-value
>   검사가 오히려 적합. (방법 B의 우위는 "secret 여부" taint 정밀도지, 상수 판별이 아님.)
> - (c) 진짜 정밀하려면 KyberSlash 논문처럼 **최적화된 바이너리(여러 컴파일러)** 위에서
>   탐지해야 하나, CT-KAT의 고정 `-O0` ct는 그 자리로 살짝 애매 → **divisor 상수값 필터를
>   패치에 같이 넣는 게 현실적**(secret /비-2^n 상수 또는 /변수만 경고).

---

## 5. 냉정한 평가

| 항목 | 판정 |
|---|---|
| 기술 feasibility | ✅ **됨** (x86 `-O0` ct에서 DIV 계열이 잡히는 구간 — Docker gcc는 다음 pass에서 objdump 확인 권장) |
| 신규성 | ❌ **논문 novelty로는 약함** (방법 B = KyberSlash 논문 그대로에 가깝고, operand-timing 모델/도구도 선행 존재) |
| Kyber 한정 가치 | ❌ 이미 fix → 잡을 게 없음 (positive control 일부러 만들어야) |
| 일반 가치 | △ `secret/변수` 나눗셈은 모든 환경 div → **미감사 코드/회귀-린트**엔 의미 |
| 경고 성격 | "may-leak" — *소스/해당 빌드에 비밀 나눗셈 있음*(= `-Os`/임베디드/구버전컴파일러서 샐 수 있음). x86 `-O2` ship 바이너리는 실제 안전할 수 있어 **보수적 경고**(오탐처럼 보일 수 있음). divisor/target/cflags 필터 필요, §4 함정 참고 |

---

## 6. 결정 체크리스트 (진행 전 답할 질문)

- [ ] 목적이 **교육/포트폴리오**인가 vs **실제 CI 가드**인가? (논문 신규성 목표면 비추)
- [ ] **커스텀 Valgrind 빌드 + Docker 반영** 공수 감당 가능한가? (방법 B의 진짜 비용)
- [ ] "논문 novelty는 약함(이미 논문/도구 있음)"을 받아들이는가?
- [ ] Kyber 한정이 아니라 **일반 `secret/변수` division 탐지**로 확장할 의향이 있는가? (그쪽이 더 실질적)
- [ ] "may-leak" 보수적 경고(오탐 감수)를 받아들일 수 있는가?

---

## 7. 발전 방향 — "KyberSlash 넘어서기" (double-checked, 정직판)

> ⚠️ **더블체크 경고**: 아래 "매력적" 방향(B/D)을 웹 검증해보니 **2024-2025에 이미
> 출판된 핫한 영역**이었다. 처음엔 "B가 distinctive 신규"라 적었다가 정정함 —
> 이 문서를 보고 *novelty를 주장하기 전에 §7.1을 반드시 읽을 것*.

### 7.1 이미 점령된 영역 (novelty 주장 금지 구역)

- **컴파일러×플래그×ISA가 CT를 깬다 / 누수표면 매핑** → **이미 출판됨** (단 아래 두 논문은
  기여가 **다름** — v2 정정: 한 논문이 다 한 게 아니니 인용 시 분리할 것):
  - *Breaking Bad: How Compilers Break Constant-Time Implementations* (arXiv 2410.13489,
    2024, ETH Zurich, ASIA CCS '25) — **44,604개 타겟을 x86-64/i386/armv7/aarch64/RISC-V/
    MIPS 6개 아키로 스캔**(8 라이브러리×6아키×GCC/LLVM×opt = 6608 바이너리). **대규모 측정**이
    본체. *어느 패스가 깨는지는 특정 안 함.*
  - *Fun with flags: How Compilers Break and Fix Constant-Time Code* (arXiv 2507.06112,
    2025, Geimer & Maurice) — **GCC/LLVM 어느 패스가 CT를 깨는지 특정 + 패스 비활성화 플래그
    mitigation**(`-mllvm --x86-cmov-converter=false`, `-fno-vectorize` 등). 단 **x86-64 단일 아키**.
  - ⚠️ **옛 버전이 둘을 "2024-25 연구"로 뭉뚱그린 게 오류**: `44,604·6아키 스캔`(Breaking
    Bad)과 `패스 특정·플래그 완화`(Fun with Flags, x86 단독)는 **서로 다른 논문**. 각 sub-fact는
    둘 중 하나엔 참이나, 셋 다 한 논문은 없음.
  - Trail of Bits, **LLVM constant-time 지원**(`__builtin_ct_select`) — 블로그 2025-12-02.
    단 **아직 upstream review 중**(LLVM PR #166702, RFC 2025-08), 정식 릴리스 전이라 "제품화"는 과장.
  - → "(소스 × 컴파일러 × 플래그 × ISA) 누수표면" 리프레임 = **논문 novelty 거의 없음** (이 결론은 유지).
- **Falcon(FN-DSA) 부동소수점 부채널** → **실재하나 이미 붐빔**:
  - single-trace **파워분석**으로 Falcon-512 비밀계수 복구(임베디드 재현),
    FFT 부채널, *Do Not Disturb a Sleeping Falcon: FP Error Sensitivity*(eprint 2024/1709)
  - FP가 가우시안 샘플링에 쓰이는 건 맞지만, 타이밍보다 **파워 쪽이 빽빽** → 새거 찾기 어려움

### 7.2 그래서 남은 현실적 길 (셋 다 정직하게 약함)

1. **엔지니어링 / 교육 / 통합** — 알려진 기법들을 CT-KAT에 *쓸 수 있게 묶기*.
   WISA/석사/포트폴리오엔 OK. **단 "새 탐지 능력" novelty 주장 금지** (reviewer가
   Breaking Bad / Fun with Flags로 깐다).
2. **새 버그 헌팅 (유일한 진짜 novelty 경로, high-risk)** — round-2 on-ramp 서명
   후보 등 *가장 덜 감사된* 구현에 기존 도구(Binsec/Rel, 패치드 Valgrind)로 들이대
   새 operand-timing 누수 찾기. 찾으면 기여 = *발견*, 못 찾으면 0.
3. **좁은 교집합 소유 (틈은 있으나 좁음)** — "Breaking Bad"류는 주로 *컴파일러가
   introduce하는* CT 위반에 집중. KyberSlash류는 *소스에 이미 있는* operand 위반이
   어느 deploy config에서 살아남나 — 미묘하게 다른 축. operand-timing(div/mul/fp) ×
   최신 PQC 표준 × *통합 실행도구*는 아무도 정확히 안 했을 수 있음. 단 기법은 다
   존재 → 기여는 "체계 적용 + 도구화" 수준, 근본 신규 아님.

### 7.3 한 줄

**이 기법으로 새 *연구*를 만들기는 (2024-25 출판물 때문에) 어렵다.** 갈 거면
(a) **도구화/교육으로 정직하게 포지셔닝** 하거나 (b) **새 버그 헌팅(high-risk)**.
"compiler/arch가 CT 깬다"를 새로 발견했다 주장하면 안 됨 — 이미 됐음.

---

## 8. 구현 착수 판단 (v4 addendum)

### 8.1 결론 — 직접 구현 + 기존 패치 재사용의 2단계

**바로 기능을 넣을 거면 "glue는 직접, 정밀 taint 엔진은 재사용"이 맞다.**

1. **MVP / PoC: CT-KAT 내부 직접 구현**
   - 새 모듈 `ctkat/asm_scan.py`를 만들고, generated/manual binary를 디스어셈해
     `div/idiv`(x86), `udiv/sdiv`(ARM), `div/divu/rem/remu`(RISC-V 후보) 같은 명령을 찾는다.
   - 이 단계는 **비밀 taint를 증명하지 못하므로 warn-only**로 시작한다. 단순히 binary 안에
     `div`가 있다는 건 "비밀이 들어갔다"가 아니라 "위험 후보가 있다"는 뜻이다.
   - CT-KAT의 기존 verdict는 Valgrind status가 `FAIL`이면 바로
     `STRUCTURAL_LEAK/RISKY/CRITICAL`로 흐르므로, 조잡한 asm scan 결과를 바로 `FAIL`로
     넣으면 오탐이 CI를 망친다. 별도 report 섹션이나 `LOW/MEDIUM` finding으로 시작할 것.
2. **정밀판: KyberSlash 공식 patched Valgrind 재사용**
   - KyberSlash 공식 패치는 `--variable-latency-errors=yes`를 추가하고, Memcheck/VEX에서
     tainted operand가 variable-latency IR op에 들어가면
     `Variable-latency instruction operand ... is secret/uninitialised` 형태의 에러를 낸다.
   - CT-KAT는 이미 `VALGRIND_MAKE_MEM_UNDEFINED`로 secret taint를 주고, `valgrind_runner.py`
     → `valgrind_parser.py` → report/verdict 파이프라인이 있으므로, 이 출력 prefix를
     `SECRET_DEPENDENT_VARIABLE_LATENCY`로 분류하면 통합 비용은 작다.
   - 단 이건 stock Ubuntu `valgrind` 옵션 하나로 되는 게 아니다. 2025-08-05 공식 패치는
     **Valgrind git 2025-08-05 기준**이라 Docker에서 source build/fork 유지가 필요하다.

### 8.2 왜 기존 도구를 통째로 끌어오면 애매한가

| 후보 | 끌어오기 평가 |
|---|---|
| KyberSlash patched Valgrind | **정밀 taint 엔진으로 재사용 가치 높음.** CT-KAT 스택과 잘 맞는다. 단 Docker 빌드/패치 유지보수 비용이 큼. |
| Binsec/Rel | binary-level CT 검증 도구로 훨씬 강하지만, CT-KAT에 곧장 넣으면 "외부 formal tool wrapper"가 된다. optional integration이면 OK, MVP로는 과함. |
| saferewrite/FaCT/ct-verif | 근거/모델 인용용으로 충분. 이 프로젝트에 바로 흡수할 구현 기반으로는 부적합하거나 범위가 다르다. |
| from-scratch Valgrind/VEX patch | 비추. KyberSlash 패치가 이미 같은 문제를 푼다. 직접 재구현하면 새 기능이 아니라 유지보수 지옥을 다시 여는 꼴. |

### 8.3 구현 체크리스트

- [ ] `FindingType` 이름은 넓게 `SECRET_DEPENDENT_VARIABLE_LATENCY`를 권장.
  KyberSlash 패치가 integer division만 보는 게 아니라 mod/fp-div/sqrt류까지 본다.
  단 user-facing 설명은 "KyberSlash-style secret-dependent division"으로 좁게 써도 된다.
- [ ] **integer mul은 초기 탐지 대상에서 빼거나 별도 정책으로 둔다.**
  현재 fix본 ML-KEM도 `*80635 >> 28`을 쓰므로, secret-derived `mul`을 무지성 HIGH로 잡으면
  negative control이 깨진다.
- [ ] config는 `ct.variable_latency_errors: off|auto|require` 정도가 현실적.
  `auto`는 patched Valgrind 지원을 감지해서 켜고, stock Valgrind면 안내만 출력한다.
  `require`는 지원 안 되면 ERROR/INCONCLUSIVE로 보내 CI에서 fail-closed하게 한다.
- [ ] `valgrind_flags`에 직접 `--variable-latency-errors=yes`를 박으면 stock Valgrind에서
  unknown option으로 터진다. `valgrind --help` probing 또는 wrapper 감지가 필요하다.
- [ ] `asm_scan`은 `ct` 실행 뒤 report에 합치되, 첫 버전은 `FAIL` 판정에 바로 섞지 않는다.
  필요하면 `ctkat_varlat_candidates.csv/json` 같은 별도 artifact로 분리한다.
- [ ] positive/negative control을 만든다:
  - positive: secret-derived `/3329` 또는 `secret / variable`이 있는 toy harness.
  - negative: reciprocal-multiply fix(`*80635 >> 28`)와 unsigned `/8` 같은 safe/ambiguous 케이스.
  - 기대: patched Valgrind는 positive를 잡고 fix는 안 잡아야 한다.
- [ ] 결과 문구는 "constant-time violation proved"가 아니라
  **"secret-tainted operand reached a variable-latency instruction in this build/target"**로 쓴다.
  `-O0` ct build와 shipped `-O2/-Os` binary가 다를 수 있기 때문이다.
- [ ] Docker source-build를 넣는다면 이미지 태그를 분리한다:
  - 기본 `ctkat-dev`: stock Valgrind, 빠른 개발용.
  - `ctkat-dev-varlat`: patched Valgrind, varlat 정밀 검사.

### 8.4 권장 구현 순서

1. `FindingType.SECRET_DEPENDENT_VARIABLE_LATENCY` 추가.
2. `report.py` recommendation 추가.
3. `valgrind_parser.py`에
   `Variable-latency instruction operand` prefix → `SECRET_DEPENDENT_VARIABLE_LATENCY`
   classifier 추가.
4. config에 `ct.variable_latency_errors` 추가(`off|auto|require`).
5. patched Valgrind 감지 helper 추가(`valgrind --help` 또는 dry-run).
6. `asm_scan.py` PoC를 warn-only artifact로 추가.
7. toy positive/negative control + parser/config/CLI tests 추가.
8. Docker에 KyberSlash Valgrind 패치 적용 이미지를 별도 타겟으로 추가.

한 줄로 정리하면: **"일단 넣기"는 asm scan으로 빠르게, "맞게 잡기"는 KyberSlash patched
Valgrind를 끌어와서 한다.** 처음부터 VEX를 직접 짜는 건 공수 대비 의미가 없다.

---

## 8.5 착수 전 판단 (v5 addendum — 코드 앵커 재검증 후)

> **v5 (2026-06): 코드 앵커 8/8 재grep 검증 + "이대로 다 만들어도 되나" 판단.**
> §2.1·§5·§8의 코드 앵커를 anchor-free로 다시 grep(§9.1 메타룰 적용) — 8개 항목
> 전부 실제 코드와 일치 확인. 문서 자체는 정직하나, **"md대로 전부 구현"은 비추**.
> 단계별로 끊는다.

### 결론: 0번 검증 → 1·2번만, 3번(Valgrind fork)은 보류

| 단계 | 내용 | 판단 | 이유 |
|---|---|:--:|---|
| **0. Docker amd64 positive control objdump** | 취약 `/KYBER_Q` 되살려 실제 런타임(Docker gcc)에서 DIV 살아있는지 직접 확인 | 🟢 **필수 선행** | §2.2·§3 자인 — 핵심 thesis가 정작 **실제 타겟(Docker gcc)에선 미검증**. Apple clang cross-target 유추일 뿐. v1 아키 혼동 재발 방지 |
| 1. `asm_scan.py` warn-only PoC | ct 바이너리 디스어셈 → div + 비밀함수 교집합 → 별도 artifact | 🟢 ㄱㄱ | 싸고(며칠) verdict 안 건드려 오탐이 CI 안 망침. 3축 완성 그림 |
| 2. FindingType + report/parser plumbing | `SECRET_DEPENDENT_VARIABLE_LATENCY` 추가 | 🟢 ㄱㄱ | dict 한 줄씩이라 거의 공짜 (앵커 6 확인) |
| 3. patched Valgrind Docker fork | 정밀 taint 엔진 | 🔴 **보류** | §4-3 자인 — 진짜 비용은 **VEX 패치 + 영구 fork 유지보수(1~2주+∞)**. 졸업 후 방치 fork 됨 + novelty 0 (§7) |

### "주제 자체가 비추냐" — ❌ 아님 (구분 명확화)

비추는 **딱 하나**: *"KyberSlash를 CT-KAT에 붙인 게 새 기법"이라는 논문 novelty 주장.*
(기법은 KyberSlash 논문 + Breaking Bad + Fun with Flags가 이미 점령 — §7.1)

주제 영역(PQC operand-timing 툴)은 안 죽었음. §7.2 재확인:
- "이 **기법으로** 새 연구" → 어렵다 (출판됨)
- "이 **도구로** 새 버그 발견" (덜 감사된 round-2 서명 등) → 가능, 단 high-risk 도박
- "도구화/교육 포지셔닝" → 안전, novelty 없음 (포폴/WISA OK)
- "주제 **자체**가 망함" → **그건 아님**

### 목적별 가이드

- **포폴 / WISA / 석사 제출** → 0 → 1 → 2번까지. 거기서 멈추는 게 ROI 최고.
- **진짜 논문 novelty** → 이 통합 기법으론 비추. §7.2-① 새 버그 헌팅이 유일한 진짜 길(도박).

---

## 8.6 착수 계획 (v6 addendum — 7-agent recon + 결정 락)

> **v6 (2026-06): 서브시스템 7개 병렬 recon으로 편집 위치까지 라인 확정 + 사용자 결정 락.**
> 목적은 아직 미정("일단 작동은 하게"), 범위는 **Phase 0(전제 증명)부터**. fork(Phase 2)는 보류 유지.

### 결정 락
- **목적**: 미정. 단 "fork 없이도 단독 작동하는 결과물"이 우선 → **Phase 1 asm_scan(warn-only)이 진짜 MVP**, Phase 2 patched-Valgrind fork는 보류.
- **범위(지금)**: **Phase 0 — Docker amd64 objdump로 thesis 증명**부터. 전제 안 깨고 코드 짜는 건 CLAUDE.md §0 위반.

### recon이 뒤집은 메모 §8.4 순서 (중요)
- `verdict`는 **FindingType-agnostic** — `cli.py:473`이 *"finding 있으면 무조건 FAIL"*, 매트릭스(`verdict.py:65-91`)는 (ct_status, dudect_status)만 봄.
- ⇒ **asm_scan 결과를 Finding으로 넣으면 자동 FAIL → CI 박살.** 반드시 별도 artifact(`ctkat_varlat_candidates.csv`)로 분리.
- ⇒ `FindingType.SECRET_DEPENDENT_VARIABLE_LATENCY`는 **patched Valgrind 출력이 있어야만 입력이 생김.** 단독으로 먼저 배선하면 입력 0 = §5 "backend만/frontend 없음" 안티패턴.
- **결론**: 메모 §8.4의 "FindingType 먼저(1번)"는 죽은 코드. **asm_scan(§8.4-6)이 단독 유용한 MVP라 그게 Phase 1.** FindingType 배선(§8.4-1~5)은 patched Valgrind(§8.4-8)와 한 묶음으로 Phase 2.

### Phase 정의
- **Phase 0 (게이트)**: Docker amd64에서 취약 `/KYBER_Q` 되살려 ct(-O0) 빌드 → `poly_tomsg`에 `idivl` 살아있나 objdump 확인. fix본(`*80635>>28`) = negative control(div 없어야). 산출물 = 테스트 fixture 근거.
  - ⚠️ **현재 Docker daemon OFF** — 시작 전 `docker compose build`(ubuntu:24.04, amd64 에뮬) 필요. 호스트(arm64)는 `sdiv` 나와서 대체 불가.
- **Phase 1 (MVP)**: `ctkat/asm_scan.py` 신규 — objdump 셸아웃으로 div/idiv + 비밀함수 교집합 → 별도 CSV. Finding/verdict 안 건드림. `mul` 제외(fix본 오탐 방지). 새 의존성 X.
- **Phase 2 (보류)**: FindingType 배선 + config probing + patched Valgrind Docker fork. novelty 0 + 영구 fork 유지보수라 목적 확정 전엔 안 함.

### 검증된 편집 위치 (Phase 1·2 착수 시)
| 대상 | 위치 |
|---|---|
| FindingType enum | `ctkat/valgrind_parser.py:7-12` |
| classifier prefix (`'Variable-latency instruction operand'`) | `ctkat/valgrind_parser.py:63-72` |
| recommendation | `ctkat/report.py:27-38` |
| verdict (FAIL if findings) | `ctkat/cli.py:473` / 매트릭스 `ctkat/verdict.py:65-91` |
| config `variable_latency_errors: off\|auto\|require` | `ctkat/config.py:485-535` (~530) |
| valgrind flag 주입 (+`valgrind --help` probing 필수) | `ctkat/cli.py:413-415`, default `config.py:467-478` |
| asm_scan 호출 | `ctkat/cli.py` `_do_ct` 끝 |
| ct 빌드 산출물 | `compile_harness` `harness_generator.py:84` → `_generated/harness_kem_dec` |
| 취약/fix 토글 | `poly.c:146`(주석 div)/`147-150`(fix), `:31`(주석 div)/`32-36`(fix) |

---

## 8.7 Phase 0 실측 결과 (v7 — Docker amd64 objdump 드디어 직접 찍음) — ⚠️ 핵심 thesis 반증

> **v7 (2026-06): Docker 켜고 amd64에서 gcc·clang objdump 직접 전수.** v2~v6이 "다음 pass에서
> Docker gcc 확인 권장"이라고 미뤄둔 그 검증을 실제로 실행. **결과: §0·§2.2의 핵심 thesis가
> 실제 런타임(gcc -O0)에서 거짓.** 메모 데이터는 Apple **clang**이었고, Docker 런타임은 **gcc**다 —
> 1차의 arm/x86 혼동(§1)과 똑같은 패턴이 **컴파일러 축**에서 재발했다. 통과 ≠ 정확(§0).

### 실측 매트릭스 (Docker linux/amd64, Ubuntu gcc 13.3.0 / clang 18.1.3)

| 케이스 | **gcc -O0 (실제 ct 런타임)** | gcc -Os | gcc -O2 | clang -O0 (옛 메모 출처) | clang -Os/-O2 |
|---|---|---|---|---|---|
| `/3329` signed const | **imul (div 없음)** | idiv | imul | **idiv** | imul |
| `/3329` unsigned const | **imul (div 없음)** | div | imul | **div** | imul |
| `%3329` | imul (없음) | idiv | imul | idiv | imul |
| `secret/변수` | **idivl ✅** | idiv | idiv | idivl | idiv |
| signed `/8` | shift (없음) | idiv | 없음 | idiv | 없음 |
| unsigned `/8` | shift (없음) | 없음 | 없음 | 없음 | 없음 |
| fix `*80635>>28` | 없음 | 없음 | 없음 | 없음 | 없음 |
| **실 `poly_tomsg` `/KYBER_Q`(unsigned)** | **imul 없음** | **`div %r9d` ✅** | — | — | — |
| **실 `poly_compress` `/KYBER_Q`** | **imul 없음** | **`idiv %r9d` ✅** | — | — | — |

(toy + 실제 poly.c 둘 다 동일 결론. 역수곱 매직상수 `0x9D7DBB41`/`0x3AFB7681`, fix `0x13AFB`=80635 대조 완료.)

### 무엇이 반증됐나
- **메모 §2.2 핵심 셀 "x86_64 `/3329` -O0/-Oz = DIV 계열"은 gcc에서 거짓.** gcc는 상수 나눗셈을
  **expand 단계에서 -O0에도 역수곱으로 변환**한다(최적화 패스가 아니라 RTL 생성 시점). div는
  **-Os에서만** 살아남(코드 크기 때문에 작은 idiv 선택). clang -O0은 idiv 유지 → **옛 메모는 clang을
  재고 gcc 런타임도 같다고 추론한 것.**
- **→ §0 결론("ct -O0 operand 패치로 x86에서도 KyberSlash 나눗셈 잡힌다")은 실제 gcc 런타임에서 무효.**
  취약본을 되살려도 ct(-O0, gcc) 바이너리엔 div 명령이 **아예 없다.** asm_scan(Phase 1)도,
  patched Valgrind(Phase 2)도 **볼 명령이 없어서 0개 탐지.**

### 살아남은 사실 / 교정된 설계 방향
- **유일하게 모든 gcc opt에서 견고한 셀 = `secret / 변수`(idivl).** 단 KyberSlash 본체는 `/상수`라 이 셀 아님.
- KyberSlash 패턴(`/상수`)을 실제로 잡으려면 스캔 대상이 **-Os 빌드 또는 clang 빌드**여야 한다
  (ct의 고정 gcc -O0이 아니라). 이건 §4 함정 노트·§7(컴파일러×플래그×ISA)와 일치하지만, 메모가
  "-O0이 더 보수적(많이 잡음)"이라 본 가정을 **정반대로 뒤집는다** — gcc -O0은 상수 나눗셈에선 *덜* 잡는다.
- **함의**: "그래도 작동하게" 만들려면 Phase 1 asm_scan은 ct -O0 바이너리가 아니라 **별도 -Os(±clang)
  스캔 빌드**를 까야 의미가 있다. 안 그러면 광고만 하고 0개 잡는 F12/T20류 재현.

---

## 8.8 Phase 1 구현 완료 (v8 — 멀티-opt asm-scan, Docker 검증 통과)

> **v8 (2026-06): §8.7 교정 방향대로 멀티-opt asm-scan 구현 + Docker amd64 end-to-end 검증.**
> 사용자 결정 = "일단 작동하게"(목적 미정) + 멀티-opt 스캔. fork(Phase 2)는 보류 유지.

### 무엇을 만들었나
- **`ctkat/asm_scan.py`** (신규): crypto sources를 `-O0/-Os/-O2`로 각각 `-c` 컴파일 → objdump →
  div류 명령(`i?div`/`sdiv`/`udiv`/`divu?w?`/`remu?w?`) 찾고 함수에 매핑. **mul/imul·FP div(`divsd`)
  제외.** (source, function)별로 "어느 opt에서 div가 살아남나" 집계.
- **`ctkat asm-scan -c <yaml>`** 서브커맨드: ct.harnesses의 sources를 스캔, 별도 artifact
  `ctkat_varlat_candidates.csv/json` 출력. **verdict 절대 안 건드림.** exit 코드: candidate
  유무는 `0`(warn-only), 단 toolchain/config 문제(컴파일러·objdump 누락, 디스어셈 실패)는
  fail-closed로 `2`.
  `--opt` 반복 옵션으로 opt 레벨 커스터마이즈.
- **테스트 16개** (`tests/test_asm_scan.py`): parser whitelist(x86/ARM/RISC-V + FP/mul 제외),
  note 로직, artifact writer, CLI smoke(scan mock), guarded 실컴파일(variable divisor 잡힘 /
  reciprocal fix 안 잡힘) + toolchain 누락/디스어셈 실패 시 fail-closed exit 2. 전체
  **330+ passed** (Docker amd64; 옆집 리뷰 반영분 포함).

### Docker amd64 end-to-end 검증 (실제 작동 시연)
| | `poly_tomsg`/`poly_compress` | 비고 |
|---|---|---|
| **POSITIVE (취약 `/KYBER_Q` 복원)** | ✅ `div`/`idiv` @ **-Os** 잡힘. note: *"absent at -O0 — ct/Valgrind stage would miss this build"* | Phase 0 통찰 자동 설명 |
| **NEGATIVE (fix `*80635>>28`)** | ✅ **0개** | 취약/fix 정확히 구분 |

- `fips202.c`의 `shake128`/`shake256`에 `div @ -Os`가 positive·negative 양쪽에 뜸 — keccak rate
  계산이라 **비밀 무관 false-positive**. 이게 바로 warn-only로 둔 이유(§8.1): 오탐이 verdict 못 깬다.

### 설계 메모 (CLAUDE.md self-check 반영)
- **§1 user-visible**: 서브커맨드·CSV 컬럼·콘솔 메시지 각각 테스트 있음.
- **§2 의미적 invariant**: variable divisor는 잡고 reciprocal fix는 안 잡는다 (guarded test).
- **§8 corpus 다양성**: parser는 canned objdump 텍스트(x86/ARM/RISC-V)로 컴파일러 무관 검증.
  실컴파일 테스트는 `secret/변수`(모든 컴파일러서 idiv인 유일 셀)만 단언 — clang -Os는 `/3329`를
  역수곱하므로 poly 기반 단언은 비포터블이라 의도적으로 피함.
- **Phase 2(patched Valgrind fork)는 여전히 보류**: novelty 0 + 영구 fork 유지보수. 목적 확정 시 재검토.

---

## 9. 관련 문서 / 출처

- **교육용 설명**: `docs/kyberslash_research.html` — v3에서 핵심 표현을 동기화함. PoC는
  objdump 스캔(A), 정밀 최종형은 patched Valgrind(B)로 읽으면 된다.
- **논문 (BibTeX)**:
  ```bibtex
  @article{kyberslash2025,
    author  = {Daniel J. Bernstein and Karthikeyan Bhargavan and Shivam Bhasin and
               Anupam Chattopadhyay and Tee Kiah Chia and Matthias J. Kannwischer and
               Franziskus Kiefer and Thales B. Paiva and Prasanna Ravi and Goutam Tamvada},
    title   = {{KyberSlash}: Exploiting secret-dependent division timings in {Kyber} implementations},
    journal = {{IACR} Transactions on Cryptographic Hardware and Embedded Systems},
    volume  = {2025}, number = {2}, pages = {209--234}, year = {2025},
    doi     = {10.46586/tches.v2025.i2.209-234},
    url     = {https://doi.org/10.46586/tches.v2025.i2.209-234}
  }
  ```
- **PDF**: <https://eprint.iacr.org/2024/1049.pdf> · **FAQ**: <https://kyberslash.cr.yp.to/faq.html>
- **기존 operand-model 도구**(= 방법 B novelty 약함 근거): Binsec/Rel, FaCT,
  ct-verif, saferewrite, KyberSlash 논문의 patched TIMECOP/Valgrind.
  - *(v2 검증 주석)* Binsec/Rel·FaCT·ct-verif는 실재 + operand 누수 모델링 확인.
    `saferewrite`는 cr.yp.to/SUPERCOP 궤도에 있으나 1차 출처 corroboration이 약함 —
    근거를 댈 거면 앞 셋 + KyberSlash 패치 Valgrind로 충분.
  - *(novelty 뉘앙스)* "operand model = 완전 표준"은 살짝 셈: KyberSlash 논문 **본인**이
    그 operand-level 가변시간-명령 탐지를 ctgrind/TIMECOP(분기·메모리만) **넘는 자기 신규
    기여**로 내세웠음. 큰 그림("CT-KAT가 이걸 새 논문으로 못 판다")은 그대로 맞음.
- **발전 방향이 이미 점령됐다는 근거(§7.1)**:
  - *Breaking Bad: How Compilers Break Constant-Time Implementations* — <https://arxiv.org/abs/2410.13489>
  - *Fun with flags: How Compilers Break and Fix Constant-Time Code* — <https://arxiv.org/abs/2507.06112>
  - Falcon FP 민감도: *Do Not Disturb a Sleeping Falcon* — <https://eprint.iacr.org/2024/1709>
  - Trail of Bits, constant-time LLVM (2025) — <https://blog.trailofbits.com/2025/12/02/introducing-constant-time-support-for-llvm-to-protect-cryptographic-code/>
- **v4 구현 판단 근거**:
  - KyberSlash 공식 Valgrind patches page — <https://kyberslash.cr.yp.to/papers.html#patch>
  - KyberSlash 2025-08-05 option-handling patch — <https://kyberslash.cr.yp.to/valgrind-try-patch-20250805.txt>
  - KyberSlash 2025-08-05 division patch — <https://kyberslash.cr.yp.to/valgrind-varlat-patch-20250805.txt>
  - Binsec/Rel overview — <https://binsec.github.io/nutshells/sp-20.html>
