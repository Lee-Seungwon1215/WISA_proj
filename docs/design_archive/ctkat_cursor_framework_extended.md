# CT-KAT: KAT + Valgrind 기반 Constant-Time 검사 프레임워크 개발 계획

## 1. 목표

본 프레임워크의 목표는 사용자가 제공한 C/C++ 암호 구현 소스코드에 대해 다음 과정을 자동화하는 것이다.

1. 소스코드 빌드
2. KAT(Known Answer Test) 수행
3. Valgrind Memcheck 기반 constant-time 동적 검사 수행
4. secret-dependent branch / memory access 가능성 탐지
5. 결과를 CLI와 CSV로 출력
6. variable timing 가능성이 있는 함수, 파일, 라인, 원인을 요약

최종 결과물은 다음과 같은 CLI 도구 형태를 목표로 한다.

```bash
ctkat run --project ./target_impl \
          --kat ./tests/kat.json \
          --config ./ctkat.yaml \
          --out ./reports
```

출력 예시는 다음과 같다.

```bash
[CTKAT] Build: PASS
[CTKAT] KAT: PASS
[CTKAT] Constant-Time Check: FAIL

Potential variable-time findings:
1. crypto_kem_dec() - secret-dependent branch
   file: src/kem.c:142
   reason: Conditional jump depends on secret-tainted value

2. poly_reduce() - secret-dependent memory address
   file: src/poly.c:88
   reason: Memory access address depends on secret-tainted value

CSV report saved to: reports/ctkat_report.csv
```

---

## 2. 핵심 아이디어

Valgrind Memcheck는 원래 “정의되지 않은 값(undefined value)”이 조건문이나 메모리 주소 계산에 사용될 때 경고를 발생시킨다.

이를 constant-time 검사에 응용하면 다음과 같다.

| 일반 Memcheck 관점 | Constant-Time 검사 관점 |
|---|---|
| undefined value | secret-tainted value |
| conditional jump depends on uninitialised value | secret-dependent branch |
| use of uninitialised value in memory address | secret-dependent memory access |
| 오류 위치 | variable-time 가능 위치 |

즉, 실제 secret 값을 사용하되, Valgrind에게는 해당 메모리를 “undefined”로 표시한다.

```c
#include <valgrind/memcheck.h>

VALGRIND_MAKE_MEM_UNDEFINED(secret_key, secret_key_len);
crypto_kem_dec(shared_secret, ciphertext, secret_key);
VALGRIND_MAKE_MEM_DEFINED(secret_key, secret_key_len);
```

이후 Valgrind가 다음과 같은 메시지를 출력하면 constant-time 위반 후보로 분류한다.

```text
Conditional jump or move depends on uninitialised value(s)
Use of uninitialised value of size 8
```

---

## 3. 전체 아키텍처

```text
ctkat/
├── cli.py
├── config.py
├── project_loader.py
├── builder.py
├── kat_runner.py
├── harness_generator.py
├── valgrind_runner.py
├── valgrind_parser.py
├── secret_infer.py
├── report.py
├── templates/
│   ├── harness_kem.c.j2
│   ├── harness_sign.c.j2
│   └── harness_generic.c.j2
├── examples/
│   ├── simple_aes/
│   ├── simple_kem/
│   └── pqclean_style/
└── tests/
```

---

## 4. 처리 파이프라인

```text
Input source code
      |
      v
[1] Project scan
      |
      v
[2] Build command execution
      |
      v
[3] KAT execution
      |
      v
[4] Secret annotation plan generation
      |
      v
[5] Valgrind harness generation
      |
      v
[6] Valgrind Memcheck execution
      |
      v
[7] Log parsing
      |
      v
[8] Finding classification
      |
      v
[9] CLI + CSV report
```

---

## 5. 입력 설정 파일

`ctkat.yaml`

```yaml
project:
  name: sample_crypto
  language: c
  root: ./target_impl

build:
  command: "make clean && make CC='gcc' CFLAGS='-O0 -g -fno-inline'"
  binary: "./build/test_target"

kat:
  type: json
  file: "./tests/kat.json"
  command: "./build/test_kat ./tests/kat.json"

ct:
  mode: valgrind
  target_function: "crypto_kem_dec"
  harness_template: "kem"
  iterations: 10

  public_inputs:
    - name: ciphertext
      type: uint8_t*
      length: CRYPTO_CIPHERTEXTBYTES

  secret_inputs:
    - name: secret_key
      type: uint8_t*
      length: CRYPTO_SECRETKEYBYTES

  outputs:
    - name: shared_secret
      type: uint8_t*
      length: CRYPTO_BYTES

report:
  output_dir: "./reports"
  csv: "ctkat_report.csv"
  json: "ctkat_report.json"
```

---

## 6. Secret 지정 자동화 전략

완전 자동화는 어렵지만, 다음 3단계로 자동화 수준을 높일 수 있다.

### 6.1 1단계: 규칙 기반 자동 추론

함수명과 파라미터명에서 secret 후보를 추론한다.

Secret 후보 키워드:

```text
sk
secret
secret_key
private
private_key
seed
nonce_secret
key
s
r
noise
```

Public 후보 키워드:

```text
pk
public
public_key
ct
ciphertext
msg
message
m
input
buf
out
```

예시:

```c
int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
```

자동 추론 결과:

```yaml
secret_inputs:
  - sk

public_inputs:
  - ct

outputs:
  - ss
```

### 6.2 2단계: 알고리즘 API 프로파일 기반 추론

PQC 계열은 API 형태가 어느 정도 정형화되어 있으므로 프로파일을 둔다.

#### KEM 프로파일

```c
crypto_kem_keypair(pk, sk)
crypto_kem_enc(ct, ss, pk)
crypto_kem_dec(ss, ct, sk)
```

추론 규칙:

| 함수 | Secret | Public | Output |
|---|---|---|---|
| keypair | 내부 seed, sk 생성부 | 없음 또는 랜덤 seed | pk, sk |
| enc | coins, ephemeral secret | pk, message | ct, ss |
| dec | sk | ct | ss |

#### Signature 프로파일

```c
crypto_sign_keypair(pk, sk)
crypto_sign_signature(sig, siglen, msg, msglen, sk)
crypto_sign_verify(sig, siglen, msg, msglen, pk)
```

추론 규칙:

| 함수 | Secret | Public | Output |
|---|---|---|---|
| keypair | seed, sk 생성부 | 없음 | pk, sk |
| sign | sk, nonce/coins | msg | sig |
| verify | 없음 | pk, msg, sig | valid/invalid |

### 6.3 3단계: 사용자 확인 기반 보정

자동 추론 후 CLI에서 다음과 같이 확인한다.

```bash
[CTKAT] Inferred secret inputs:
  - sk in crypto_kem_dec()
  - coins in crypto_kem_enc()

[CTKAT] Inferred public inputs:
  - ct in crypto_kem_dec()
  - pk in crypto_kem_enc()

Proceed? [Y/n]
```

또는 설정 파일로 고정한다.

```yaml
ct:
  secret_inputs:
    - function: crypto_kem_dec
      name: sk
      length: CRYPTO_SECRETKEYBYTES
```

---

## 7. Harness 자동 생성

### 7.1 KEM decapsulation harness 예시

`templates/harness_kem.c.j2`

```c
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <valgrind/memcheck.h>

#include "{{ header_file }}"

int main(void) {
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss1[CRYPTO_BYTES];
    uint8_t ss2[CRYPTO_BYTES];

    crypto_kem_keypair(pk, sk);
    crypto_kem_enc(ct, ss1, pk);

    /*
     * Mark secret key as undefined.
     * Valgrind will report if this tainted value influences
     * control flow or memory addressing.
     */
    VALGRIND_MAKE_MEM_UNDEFINED(sk, sizeof(sk));

    crypto_kem_dec(ss2, ct, sk);

    VALGRIND_MAKE_MEM_DEFINED(sk, sizeof(sk));

    /*
     * ss2 is derived from secret-dependent computation.
     * Make it defined before comparison/output to avoid false positives.
     */
    VALGRIND_MAKE_MEM_DEFINED(ss2, sizeof(ss2));

    if (memcmp(ss1, ss2, sizeof(ss1)) != 0) {
        fprintf(stderr, "KAT/runtime check failed\n");
        return 1;
    }

    return 0;
}
```

### 7.2 AES encrypt harness 예시

```c
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <valgrind/memcheck.h>

#include "aes.h"

int main(void) {
    uint8_t key[16] = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f
    };

    uint8_t pt[16] = {
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff
    };

    uint8_t ct[16];

    VALGRIND_MAKE_MEM_UNDEFINED(key, sizeof(key));

    aes_encrypt(ct, pt, key);

    VALGRIND_MAKE_MEM_DEFINED(key, sizeof(key));
    VALGRIND_MAKE_MEM_DEFINED(ct, sizeof(ct));

    return 0;
}
```

---

## 8. Valgrind 실행 명령

기본 실행:

```bash
valgrind \
  --tool=memcheck \
  --track-origins=yes \
  --error-exitcode=99 \
  --log-file=reports/valgrind.log \
  ./build/ct_harness
```

권장 빌드 옵션:

```bash
gcc -O0 -g -fno-inline -fno-omit-frame-pointer
```

추가 실험용 빌드 옵션:

```bash
gcc -O2 -g -fno-omit-frame-pointer
```

운영 전략:

1. `-O0`에서 먼저 원인 추적
2. `-O2`에서 실제 최적화 후 재검사
3. 두 결과를 모두 CSV에 기록

---

## 9. Valgrind 로그 파싱

### 9.1 탐지 대상 메시지

중점적으로 파싱할 메시지:

```text
Conditional jump or move depends on uninitialised value(s)
Use of uninitialised value of size N
```

분류 기준:

| Valgrind 메시지 | 분류 |
|---|---|
| Conditional jump or move depends on uninitialised value(s) | SECRET_DEPENDENT_BRANCH |
| Use of uninitialised value of size N | SECRET_DEPENDENT_VALUE_USE |
| Invalid read/write | MEMORY_ERROR |
| Source and destination overlap | MEMORY_ERROR |
| Uninitialised value was created by a client request | SECRET_TAINT_SOURCE |

### 9.2 CSV 필드

`ctkat_report.csv`

```csv
project,function,file,line,severity,type,message,secret_source,recommendation
sample_crypto,crypto_kem_dec,src/kem.c,142,HIGH,SECRET_DEPENDENT_BRANCH,"Conditional jump depends on secret-tainted value",sk,"Replace branch with constant-time select/mask"
sample_crypto,poly_reduce,src/poly.c,88,HIGH,SECRET_DEPENDENT_MEMORY_ACCESS,"Address may depend on secret-tainted value",sk,"Avoid table lookup indexed by secret"
```

---

## 10. CLI 설계

### 10.1 기본 실행

```bash
ctkat run --config ctkat.yaml
```

### 10.2 KAT만 실행

```bash
ctkat kat --config ctkat.yaml
```

### 10.3 CT 검사만 실행

```bash
ctkat ct --config ctkat.yaml
```

### 10.4 Secret 추론 결과만 확인

```bash
ctkat infer --project ./target_impl
```

출력:

```bash
Function: crypto_kem_dec
  output: ss
  public: ct
  secret: sk

Function: crypto_sign_signature
  output: sig, siglen
  public: msg, msglen
  secret: sk
```

### 10.5 CSV 출력

```bash
ctkat run --config ctkat.yaml --csv reports/result.csv
```

---

## 11. Cursor 개발 프롬프트

아래 내용을 Cursor에 그대로 넣고 개발을 시작한다.

```text
You are building a Python-based CLI framework named CT-KAT.

Goal:
- Given a C/C++ cryptographic implementation, run KAT tests.
- Then generate a Valgrind Memcheck harness.
- Mark secret inputs with VALGRIND_MAKE_MEM_UNDEFINED.
- Run the target under Valgrind.
- Parse Valgrind logs.
- Detect potential secret-dependent branches and memory accesses.
- Print CLI summary.
- Export CSV and JSON reports.

Tech stack:
- Python 3.11+
- typer for CLI
- pydantic for config validation
- jinja2 for C harness generation
- pandas or csv module for CSV report
- subprocess for build/KAT/Valgrind execution
- pytest for tests

Project structure:
ctkat/
  cli.py
  config.py
  builder.py
  kat_runner.py
  secret_infer.py
  harness_generator.py
  valgrind_runner.py
  valgrind_parser.py
  report.py
  templates/
  examples/
  tests/

Implement the following commands:
1. ctkat run --config ctkat.yaml
2. ctkat kat --config ctkat.yaml
3. ctkat ct --config ctkat.yaml
4. ctkat infer --project ./target_impl

Config:
- Read ctkat.yaml.
- Validate project, build, kat, ct, report sections.

Build:
- Execute user-provided build command.
- Capture stdout/stderr.
- Return PASS/FAIL.

KAT:
- Execute user-provided KAT command.
- If command returns 0, mark KAT PASS.
- Otherwise mark KAT FAIL and stop unless --continue-on-kat-fail is set.

Secret inference:
- Parse function signatures from header files.
- Recognize common crypto APIs:
  crypto_kem_keypair
  crypto_kem_enc
  crypto_kem_dec
  crypto_sign_keypair
  crypto_sign_signature
  crypto_sign_verify
- Infer secret parameters using names:
  sk, secret, secret_key, private_key, private, key, seed, coins, nonce
- Infer public parameters using names:
  pk, public_key, ct, ciphertext, msg, message, input
- Allow user config to override inference.

Harness generation:
- Use Jinja2 templates.
- Include <valgrind/memcheck.h>.
- For each secret input, insert:
  VALGRIND_MAKE_MEM_UNDEFINED(ptr, len);
- After target function call, insert:
  VALGRIND_MAKE_MEM_DEFINED(ptr, len);
- Mark outputs as defined before printing/comparing.

Valgrind:
- Run:
  valgrind --tool=memcheck --track-origins=yes --error-exitcode=99 --log-file=<path> <harness_binary>
- Parse the log.

Parser:
- Detect:
  "Conditional jump or move depends on uninitialised value(s)"
  "Use of uninitialised value"
  "Uninitialised value was created by a client request"
- Extract stack frames with file and line when available.
- Classify findings:
  SECRET_DEPENDENT_BRANCH
  SECRET_DEPENDENT_VALUE_USE
  MEMORY_ERROR
  UNKNOWN
- Severity:
  HIGH for secret-dependent branch or memory address.
  MEDIUM for secret-dependent value use.
  LOW for unknown.

Report:
- Print concise terminal summary.
- Write CSV with:
  project,function,file,line,severity,type,message,secret_source,recommendation
- Write JSON with full findings.

Important:
- This tool does not prove constant-time security.
- It dynamically detects paths exercised by the harness.
- It should recommend adding dudect-style statistical timing tests as an optional second stage.
```

---

## 12. MVP 개발 순서

### Phase 1: 최소 동작 버전

목표: 설정 파일 기반으로 KAT와 Valgrind 실행 및 CSV 생성

구현 항목:

1. `ctkat.yaml` 로딩
2. build command 실행
3. KAT command 실행
4. 사용자가 작성한 harness 실행
5. Valgrind 로그 파싱
6. CSV 출력

이 단계에서는 harness 자동 생성은 하지 않는다.

```bash
ctkat run --config ctkat.yaml
```

### Phase 2: Harness 자동 생성

목표: KEM, Signature, AES 정도의 대표 템플릿 자동 생성

구현 항목:

1. `harness_template: kem`
2. `harness_template: sign`
3. `harness_template: generic`
4. secret/public/output config 기반 코드 생성
5. harness 컴파일 자동화

### Phase 3: Secret 자동 추론

목표: 사용자가 secret을 전부 지정하지 않아도 기본 추론 가능

구현 항목:

1. header file parser
2. parameter name heuristic
3. PQC API profile
4. 추론 결과 CLI 출력
5. 사용자 override 지원

### Phase 4: dudect 연계

목표: Valgrind 기반 구조적 CT 검사 + dudect 기반 통계적 timing 검사 결합

구현 항목:

1. fixed-vs-random input class 생성
2. cycle/time 측정
3. Welch t-test 결과 수집
4. CSV에 t-score 추가

CSV 확장:

```csv
project,function,ctgrind_status,dudect_t_score,dudect_status
sample_crypto,crypto_kem_dec,PASS,2.1,PASS
sample_crypto,aes_encrypt,FAIL,15.8,FAIL
```

---

## 13. 한계와 주의사항

### 13.1 Valgrind 기반 검사는 증명이 아니다

이 방식은 실행된 경로에서 secret-dependent branch나 secret-dependent memory access를 탐지하는 동적 분석이다. 실행되지 않은 경로의 문제는 탐지하지 못할 수 있다.

### 13.2 Division timing은 별도 고려 필요

기본 Memcheck 방식은 secret-dependent branch와 secret-dependent memory address 탐지에는 유용하지만, 일부 플랫폼에서 문제가 되는 secret-dependent division timing까지 완전히 잡지 못할 수 있다. 따라서 나눗셈, 모듈러 reduction, Barrett/Montgomery reduction 내부의 division 사용 여부는 별도 정적 스캔 또는 패치된 도구로 확인하는 것이 좋다.

### 13.3 Lookup table은 매우 중요

다음 형태는 HIGH 위험으로 분류한다.

```c
y = table[secret_index];
```

이 경우 branch가 없어도 cache timing leakage가 발생할 수 있다.

### 13.4 KAT 통과와 CT 안전성은 별개

KAT는 기능 정확성을 확인하고, CT 검사는 부채널 위험 가능성을 확인한다.

```text
KAT PASS + CT FAIL = 정답은 맞지만 secret-dependent timing 가능성 있음
KAT FAIL + CT PASS = 구현 자체가 잘못되었으므로 CT 결과 의미 약함
```

---

## 14. 추천 CSV 결과 예시

```csv
project,function,file,line,severity,type,message,secret_source,recommendation
aes_ttable,aes_encrypt,src/aes.c,77,HIGH,SECRET_DEPENDENT_MEMORY_ACCESS,"table index depends on secret-tainted key/state",key,"Replace T-table AES with bitsliced or AES-NI implementation"
toy_kem,crypto_kem_dec,src/kem.c,142,HIGH,SECRET_DEPENDENT_BRANCH,"conditional branch depends on secret-tainted sk",sk,"Use constant-time mask-based selection"
toy_kem,poly_reduce,src/reduce.c,51,MEDIUM,SECRET_DEPENDENT_VALUE_USE,"secret-tainted value used in arithmetic",sk,"Check whether operation has variable latency on target CPU"
```

---

## 15. 권장 최종 구조

최종적으로는 다음 3단계 검사 구조를 추천한다.

```text
[1] KAT
    - correctness check

[2] Valgrind/Memcheck CT check
    - secret-dependent branch
    - secret-dependent memory access

[3] dudect-style statistical timing test
    - actual timing distribution difference
    - fixed vs random input
    - Welch t-test
```

이렇게 구성하면 다음과 같은 장점이 있다.

1. KAT로 기능 정확성 확보
2. Valgrind로 구조적 constant-time 위반 후보 탐지
3. dudect로 실제 플랫폼 timing leakage 가능성 보완
4. CSV 기반으로 함수별 위험도 정리 가능
5. CI/CD에 연결 가능

---

## 16. 초기 구현 우선순위

가장 먼저 만들 기능은 다음 순서가 좋다.

1. `ctkat run --config ctkat.yaml`
2. build command 실행
3. KAT command 실행
4. 수동 harness 기반 Valgrind 실행
5. Valgrind 로그 파싱
6. CSV 리포트 생성
7. KEM decapsulation harness 자동 생성
8. secret parameter 자동 추론
9. dudect 연계

처음부터 완전 자동화를 목표로 하지 말고, “수동 secret 지정 + 자동 리포트 생성”에서 시작한 뒤, secret inference와 harness generation을 단계적으로 추가하는 것이 가장 현실적이다.

---

# 17. dudect-style Welch t-test 기반 Timing Leakage 검사 확장

## 17.1 추가 목적

Valgrind 기반 검사는 secret-dependent branch 또는 secret-dependent memory access를 구조적으로 탐지하는 데 유용하다. 그러나 모든 timing leakage를 포착하지는 못한다.

예를 들어 다음과 같은 경우는 Valgrind만으로 충분히 탐지되지 않을 수 있다.

1. secret-dependent division latency
2. secret-dependent multiplication latency
3. microarchitecture-dependent timing difference
4. compiler optimization으로 인한 timing 변화
5. branch는 없지만 연산 latency가 secret에 따라 달라지는 경우
6. target CPU에서만 드러나는 cache, pipeline, speculation 영향

따라서 2단계 검사로 dudect-style statistical timing test를 추가한다.

전체 구조는 다음과 같다.

```text
[1단계] Valgrind Memcheck 기반 CT 검사
  - secret-dependent branch 탐지
  - secret-dependent memory access 탐지
  - 구조적 위험 위치 추적

[2단계] dudect-style Welch t-test
  - fixed input group vs random input group 실행 시간 비교
  - 실제 timing distribution 차이 측정
  - 통계적으로 leakage 가능성 판정
```

---

## 17.2 dudect-style 검사의 핵심 개념

dudect 방식은 입력을 두 집단으로 나눈 뒤, 각 집단의 실행 시간 분포가 통계적으로 구분 가능한지를 Welch t-test로 평가한다.

대표적인 두 집단은 다음과 같다.

| Class | 의미 |
|---|---|
| class 0 | fixed secret 또는 fixed input |
| class 1 | random secret 또는 random input |

예를 들어 AES encryption을 검사한다면 다음과 같이 구성할 수 있다.

```text
class 0: 고정 key, 랜덤 plaintext
class 1: 랜덤 key, 랜덤 plaintext
```

또는 KEM decapsulation을 검사한다면 다음과 같이 구성할 수 있다.

```text
class 0: 고정 secret key, 랜덤 ciphertext
class 1: 랜덤 secret key, 랜덤 ciphertext
```

각 class에 대해 실행 시간을 많이 수집한 뒤, 두 분포의 평균 차이가 통계적으로 유의한지 확인한다.

---

## 17.3 Welch t-test 개념

두 class의 실행 시간 샘플을 다음과 같이 둔다.

```text
X0 = class 0 실행 시간 샘플
X1 = class 1 실행 시간 샘플
```

각각의 평균과 분산을 계산한다.

```text
mean0 = average(X0)
mean1 = average(X1)

var0 = variance(X0)
var1 = variance(X1)

n0 = len(X0)
n1 = len(X1)
```

Welch t-score는 다음과 같다.

```text
t = (mean0 - mean1) / sqrt(var0 / n0 + var1 / n1)
```

판정은 일반적으로 절댓값 기준으로 수행한다.

```text
|t| < 4.5      : PASS 가능성이 높음
|t| >= 4.5     : timing leakage 의심
|t| >= 10      : 강한 timing leakage 의심
|t| >= 100     : 매우 명확한 timing leakage
```

프레임워크에서는 기본 threshold를 다음과 같이 둔다.

```yaml
dudect:
  threshold_warning: 4.5
  threshold_fail: 10.0
```

---

## 17.4 dudect 모듈 추가 구조

프로젝트 구조를 다음과 같이 확장한다.

```text
ctkat/
├── dudect_runner.py
├── dudect_parser.py
├── timing_harness_generator.py
├── statistics.py
└── templates/
    ├── dudect_aes.c.j2
    ├── dudect_kem_dec.c.j2
    ├── dudect_sign.c.j2
    └── dudect_generic.c.j2
```

각 모듈 역할은 다음과 같다.

| 모듈 | 역할 |
|---|---|
| `timing_harness_generator.py` | dudect-style timing harness 생성 |
| `dudect_runner.py` | timing binary 빌드 및 반복 실행 |
| `dudect_parser.py` | timing 결과 파싱 |
| `statistics.py` | mean, variance, Welch t-score 계산 |
| `report.py` | Valgrind 결과와 dudect 결과 통합 |

---

## 17.5 설정 파일 확장

`ctkat.yaml`에 `dudect` 섹션을 추가한다.

```yaml
dudect:
  enabled: true
  mode: internal

  target_function: "crypto_kem_dec"
  harness_template: "kem_dec"

  measurements: 100000
  batch_size: 100
  warmup: 1000

  clock: "rdtsc"
  threshold_warning: 4.5
  threshold_fail: 10.0

  class_policy:
    class_0:
      secret: fixed
      public: random
    class_1:
      secret: random
      public: random

  compiler:
    cc: "gcc"
    cflags: "-O2 -g -fno-omit-frame-pointer"

  output:
    raw_csv: "dudect_raw_timings.csv"
    summary_csv: "dudect_summary.csv"
```

---

## 17.6 Timing Harness 설계

### 17.6.1 공통 구조

Timing harness는 다음 기능을 가져야 한다.

1. class 0 또는 class 1 입력 생성
2. target function 호출 직전 timestamp 측정
3. target function 호출 직후 timestamp 측정
4. 실행 cycle 또는 nanosecond 기록
5. class label과 timing을 CSV로 출력

출력 예시는 다음과 같다.

```csv
sample_id,class,cycles
0,0,1284
1,1,1291
2,0,1282
3,1,1302
```

---

## 17.7 KEM Decapsulation Timing Harness 예시

```c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>

#include "api.h"

static inline uint64_t read_cycles(void) {
    unsigned int aux;
    return __rdtscp(&aux);
}

static void random_bytes(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = rand() & 0xff;
    }
}

int main(void) {
    const size_t measurements = 100000;

    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk_fixed[CRYPTO_SECRETKEYBYTES];
    uint8_t sk_random[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss[CRYPTO_BYTES];

    crypto_kem_keypair(pk, sk_fixed);

    printf("sample_id,class,cycles\n");

    for (size_t i = 0; i < measurements; i++) {
        int cls = rand() & 1;

        random_bytes(ct, sizeof(ct));

        uint8_t *sk;

        if (cls == 0) {
            sk = sk_fixed;
        } else {
            crypto_kem_keypair(pk, sk_random);
            sk = sk_random;
        }

        uint64_t start = read_cycles();
        crypto_kem_dec(ss, ct, sk);
        uint64_t end = read_cycles();

        printf("%zu,%d,%llu\n", i, cls, (unsigned long long)(end - start));
    }

    return 0;
}
```

주의할 점은 위 코드는 개념 설명용이다. 실제 구현에서는 다음을 보완해야 한다.

1. `rand()` 대신 재현 가능한 PRNG 사용
2. class 순서 랜덤화
3. warmup 구간 제거
4. CPU affinity 고정
5. turbo boost 영향 최소화
6. 측정 대상 함수 외 입력 생성 비용 제외
7. outlier trimming 또는 median-of-batch 선택 가능
8. `rdtsc` 직렬화 처리

---

## 17.8 AES Timing Harness 예시

```c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>

#include "aes.h"

static inline uint64_t read_cycles(void) {
    unsigned int aux;
    return __rdtscp(&aux);
}

static void random_bytes(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = rand() & 0xff;
    }
}

int main(void) {
    const size_t measurements = 100000;

    uint8_t key_fixed[16] = {0};
    uint8_t key_random[16];
    uint8_t pt[16];
    uint8_t ct[16];

    printf("sample_id,class,cycles\n");

    for (size_t i = 0; i < measurements; i++) {
        int cls = rand() & 1;

        random_bytes(pt, sizeof(pt));

        uint8_t *key;

        if (cls == 0) {
            key = key_fixed;
        } else {
            random_bytes(key_random, sizeof(key_random));
            key = key_random;
        }

        uint64_t start = read_cycles();
        aes_encrypt(ct, pt, key);
        uint64_t end = read_cycles();

        printf("%zu,%d,%llu\n", i, cls, (unsigned long long)(end - start));
    }

    return 0;
}
```

---

## 17.9 Python Welch t-test 계산 코드

`statistics.py`

```python
from dataclasses import dataclass
from math import sqrt
from statistics import mean, variance


@dataclass
class WelchResult:
    mean0: float
    mean1: float
    var0: float
    var1: float
    n0: int
    n1: int
    t_score: float
    status: str


def welch_t_test(class0: list[float], class1: list[float],
                 warning_threshold: float = 4.5,
                 fail_threshold: float = 10.0) -> WelchResult:
    if len(class0) < 2 or len(class1) < 2:
        raise ValueError("Each class must have at least two samples.")

    mean0 = mean(class0)
    mean1 = mean(class1)
    var0 = variance(class0)
    var1 = variance(class1)

    denom = sqrt(var0 / len(class0) + var1 / len(class1))

    if denom == 0:
        t_score = 0.0 if mean0 == mean1 else float("inf")
    else:
        t_score = (mean0 - mean1) / denom

    abs_t = abs(t_score)

    if abs_t >= fail_threshold:
        status = "FAIL"
    elif abs_t >= warning_threshold:
        status = "WARNING"
    else:
        status = "PASS"

    return WelchResult(
        mean0=mean0,
        mean1=mean1,
        var0=var0,
        var1=var1,
        n0=len(class0),
        n1=len(class1),
        t_score=t_score,
        status=status,
    )
```

---

## 17.10 dudect CSV 결과 형식

### 17.10.1 Raw timing CSV

`dudect_raw_timings.csv`

```csv
project,function,sample_id,class,cycles
sample_crypto,crypto_kem_dec,0,0,1284
sample_crypto,crypto_kem_dec,1,1,1291
sample_crypto,crypto_kem_dec,2,0,1282
sample_crypto,crypto_kem_dec,3,1,1302
```

### 17.10.2 Summary CSV

`dudect_summary.csv`

```csv
project,function,n0,n1,mean0,mean1,var0,var1,t_score,abs_t_score,status,recommendation
sample_crypto,crypto_kem_dec,50000,50000,1284.2,1291.8,42.1,45.7,-38.2,38.2,FAIL,"Timing distribution differs between fixed and random secret classes"
```

### 17.10.3 통합 CSV

기존 `ctkat_report.csv`를 다음과 같이 확장한다.

```csv
project,function,file,line,valgrind_status,valgrind_type,dudect_status,t_score,abs_t_score,severity,message,recommendation
sample_crypto,crypto_kem_dec,src/kem.c,142,FAIL,SECRET_DEPENDENT_BRANCH,FAIL,-38.2,38.2,HIGH,"Valgrind and dudect both indicate timing leakage risk","Remove secret-dependent branch and retest"
sample_crypto,aes_encrypt,src/aes.c,77,FAIL,SECRET_DEPENDENT_MEMORY_ACCESS,FAIL,92.5,92.5,HIGH,"Secret-dependent table lookup with measurable timing difference","Replace T-table AES with bitsliced or AES-NI implementation"
sample_crypto,poly_reduce,src/reduce.c,51,PASS,NONE,WARNING,5.6,5.6,MEDIUM,"No Valgrind branch finding, but timing distribution differs","Inspect variable-latency arithmetic such as division or multiplication"
```

---

## 17.11 판정 로직

Valgrind 결과와 dudect 결과를 통합하여 최종 위험도를 산정한다.

| Valgrind | dudect | 최종 판정 | 의미 |
|---|---|---|---|
| PASS | PASS | PASS | 현재 harness 기준 특이사항 없음 |
| FAIL | PASS | WARNING | 구조적 위험은 있으나 현재 timing 차이는 작음 |
| PASS | WARNING | MEDIUM | 구조적으로는 안 잡히지만 통계적 차이 존재 |
| PASS | FAIL | HIGH | 실제 timing leakage 가능성 높음 |
| FAIL | WARNING | HIGH | 구조적 위험과 약한 timing 차이 |
| FAIL | FAIL | CRITICAL | 구조적 위험과 timing leakage 모두 확인 |

CLI 출력 예시는 다음과 같다.

```bash
[CTKAT] Build: PASS
[CTKAT] KAT: PASS
[CTKAT] Valgrind CT Check: FAIL
[CTKAT] dudect Timing Check: FAIL

Final verdict: CRITICAL

Findings:
1. crypto_kem_dec()
   Valgrind: SECRET_DEPENDENT_BRANCH at src/kem.c:142
   dudect: |t| = 38.2
   verdict: CRITICAL
   recommendation: Remove secret-dependent branch and retest.
```

---

## 17.12 Cursor 개발 프롬프트 추가

Cursor에 기존 프롬프트 다음 내용을 추가한다.

```text
Extend CT-KAT with dudect-style statistical timing testing.

Add modules:
- timing_harness_generator.py
- dudect_runner.py
- dudect_parser.py
- statistics.py

Add config section:
dudect:
  enabled: true
  measurements: 100000
  batch_size: 100
  warmup: 1000
  clock: rdtsc
  threshold_warning: 4.5
  threshold_fail: 10.0
  class_policy:
    class_0:
      secret: fixed
      public: random
    class_1:
      secret: random
      public: random

Implement:
1. Generate timing harness from Jinja2 template.
2. Compile timing harness with -O2 -g.
3. Run timing harness and collect CSV output.
4. Parse class labels and cycle counts.
5. Compute Welch t-score:
   t = (mean0 - mean1) / sqrt(var0/n0 + var1/n1)
6. Classify:
   abs(t) < 4.5 => PASS
   4.5 <= abs(t) < 10 => WARNING
   abs(t) >= 10 => FAIL
7. Export:
   - dudect_raw_timings.csv
   - dudect_summary.csv
8. Merge Valgrind and dudect results into ctkat_report.csv.
9. Print final verdict:
   PASS, WARNING, MEDIUM, HIGH, CRITICAL.

Important engineering details:
- Exclude input generation time from measurement.
- Randomize class order.
- Add warmup iterations.
- Support CPU affinity option if available.
- Support multiple independent runs.
- Report unstable measurements if t-score varies greatly across runs.
- Keep Valgrind and dudect as separate stages.
- KAT must pass before dudect timing test is trusted.
```

---

## 17.13 CLI 확장

### 전체 실행

```bash
ctkat run --config ctkat.yaml
```

### dudect만 실행

```bash
ctkat dudect --config ctkat.yaml
```

### 샘플 수 지정

```bash
ctkat dudect --config ctkat.yaml --measurements 200000
```

### threshold 지정

```bash
ctkat dudect --config ctkat.yaml --threshold-warning 4.5 --threshold-fail 10.0
```

---

## 17.14 최종 권장 프레임워크 구조

최종적으로 다음과 같은 3중 구조를 권장한다.

```text
CT-KAT Framework

1. Correctness Layer
   - KAT
   - test vector validation
   - deterministic output check

2. Structural CT Layer
   - Valgrind Memcheck
   - secret taint via VALGRIND_MAKE_MEM_UNDEFINED
   - secret-dependent branch
   - secret-dependent memory access

3. Statistical Timing Layer
   - dudect-style fixed-vs-random timing test
   - Welch t-test
   - t-score based leakage detection
```

이 구조의 장점은 다음과 같다.

1. KAT로 기능 정확성 확보
2. Valgrind로 코드 위치 기반 위험 후보 탐지
3. dudect로 실제 timing 분포 차이 확인
4. CSV로 자동 정리 가능
5. CI/CD 또는 DevSecOps 파이프라인에 연계 가능
6. PQC, AES, RSA, ECC 등 다양한 암호 구현에 확장 가능

---

## 17.15 수업/연구용 설명 문구

보고서 또는 발표에서는 다음과 같이 설명할 수 있다.

```text
본 프레임워크는 암호 구현의 기능 정확성과 부채널 안전성을 동시에 점검하기 위해 KAT, Valgrind 기반 secret-taint 분석, dudect-style 통계적 timing 검사를 순차적으로 수행한다. 먼저 KAT를 통해 구현의 정합성을 확인한 뒤, secret 데이터를 Valgrind의 undefined memory로 표시하여 secret-dependent branch 및 memory access를 탐지한다. 이후 fixed-vs-random 입력 집단에 대한 실행 시간 분포를 Welch t-test로 비교함으로써 실제 timing leakage 가능성을 통계적으로 평가한다. 이를 통해 단순 기능 테스트로는 확인할 수 없는 variable-time 구현 위험을 자동으로 식별하고, 함수·파일·라인 단위의 CSV 리포트로 제공할 수 있다.
```

---

## 17.16 개발 시 주의사항

dudect-style timing test를 구현할 때는 다음을 특히 주의해야 한다.

1. 입력 생성 시간을 측정 구간에 포함하지 않는다.
2. class 0과 class 1의 실행 순서를 랜덤화한다.
3. 충분한 warmup 이후 측정한다.
4. CPU frequency scaling 영향을 줄인다.
5. 가능하면 CPU affinity를 고정한다.
6. 여러 번 독립 실행하여 t-score 안정성을 확인한다.
7. threshold는 절대적인 보안 증명 기준이 아니라 heuristic으로 사용한다.
8. KAT 실패 시 dudect 결과를 신뢰하지 않는다.
9. I/O 출력은 측정 루프 밖에서 처리하거나 buffering한다.
10. 컴파일러 최적화에 따라 결과가 달라질 수 있으므로 `-O0`과 `-O2` 결과를 구분한다.

---

## 17.17 최종 개발 우선순위 업데이트

기존 MVP 순서를 다음과 같이 확장한다.

1. `ctkat run --config ctkat.yaml`
2. build command 실행
3. KAT command 실행
4. 수동 harness 기반 Valgrind 실행
5. Valgrind 로그 파싱
6. CSV 리포트 생성
7. KEM decapsulation Valgrind harness 자동 생성
8. secret parameter 자동 추론
9. dudect timing harness 자동 생성
10. raw timing CSV 생성
11. Welch t-score 계산
12. dudect summary CSV 생성
13. Valgrind + dudect 통합 리포트 생성
14. 최종 verdict 출력
15. CI/CD 연동


