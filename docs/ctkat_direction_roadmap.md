# CT-KAT 방향성 로드맵

> 작성일: 2026-06-03  
> 목적: `README.md`/`ctkat/`/`tests/` 기준의 현재 구현을 바탕으로, 앞으로 기능을
> 어떤 순서로 키울지와 논문/보고서 방향성이 실제로 성립하는지 판단하기 위한 메모.
>
> 이 문서는 `docs/design_archive/`의 원래 계획서를 대체하지 않는다. archive는 역사
> 기록이고, 현재 동작의 source of truth는 `README.md`, `ctkat/`, `tests/`다.

---

## 1. 현재 큰그림

CT-KAT은 이제 단순한 "Valgrind 로그 파서"가 아니라, C/C++ 암호 구현을 대상으로
다음 세 층을 자동화하는 동적 분석 프레임워크다.

| 층 | 목적 | 현재 구현 상태 |
|---|---|---|
| KAT | 기능 정확성 확인 | 구현됨. `kat_status`가 verdict에 반영됨. |
| Valgrind/Memcheck CT | secret-tainted 값이 분기/메모리 주소에 쓰이는지 확인 | 구현됨. branch/value/memory finding 분류. |
| dudect | fixed-vs-random timing 분포 차이 확인 | 구현됨. cropping, batch, Cohen's d, drop count 포함. |
| asm-scan | variable-latency instruction 후보 확인 | 구현됨. warn-only 별도 artifact. |

중요한 설계 원칙은 **"못 검증했으면 PASS가 아니다"**다. `INCONCLUSIVE`,
toolchain/config error exit 2, manual harness sentinel, KAT status propagation 등은 전부
이 원칙을 지키기 위한 장치다.

현재 프로젝트의 강점은 새로운 부채널 이론이 아니라, 여러 동적 검사를 한 YAML/CLI
아래에서 **CI 친화적으로 fail-closed 운용**하게 만든 점이다.

---

## 2. 방향성 판단

### 2.1 당장 유지해야 할 경계

- `run` verdict는 KAT/Valgrind/dudect의 CI gate다.
- `asm-scan`은 후보 보고서다. secret-taint 증명이 없으므로 verdict에 섞지 않는다.
- `CLEAN`은 "이 도구가 이 설정/입력/바이너리에서 못 찾았다"는 뜻이지 constant-time 증명이 아니다.
- 새 기능은 false positive보다 **false PASS/false CLEAN 방지**를 더 우선한다.

### 2.2 앞으로 제일 의미 있는 축

다음 큰 축은 **컴파일러/최적화/타깃 matrix**다.

KyberSlash 때문에 이 축이 눈에 띄었지만, 의미는 KyberSlash에만 갇히지 않는다.
CT-KAT은 대부분 소스가 아니라 **컴파일된 바이너리**를 검사한다. 그런데 컴파일 옵션과
컴파일러가 바뀌면 다음이 모두 바뀔 수 있다.

- secret-dependent branch가 `cmov`/select로 바뀜
- mask/select 코드가 branch로 바뀜
- table access/inlining/frame 정보가 바뀜
- constant division이 reciprocal multiply 또는 `div/idiv`로 바뀜
- `-O0` CT binary와 `-O2` 배포 binary가 서로 다른 구조를 가짐

따라서 matrix의 목적은 "KyberSlash 검출"이 아니라:

> **같은 소스가 build configuration에 따라 다른 CT 성질을 갖는지 보이게 만드는 것**

이다.

---

## 3. 추천 로드맵

### Phase A. 현 상태 릴리스 안정화

목표: 현재 기능을 "쓸 수 있는 도구"로 고정한다.

작업:

- README, tutorial, examples 기준으로 사용법 정리
- `ctkat asm-scan`의 artifact schema를 고정
- Docker/local 테스트를 계속 green으로 유지
- `docs/kyberslash_direction.md`는 사건 기록으로 두고, 일반 방향성은 이 문서로 분리

완료 기준:

- `python3 -m pytest -q` 통과
- Docker `python3 -m pytest -q` 통과
- `examples/toy_*`와 `examples/pqc_mlkem768`가 문서 설명과 일치
- `asm-scan`은 candidate 유무 exit 0, toolchain/config 문제 exit 2 유지

### Phase B. Matrix-lite: asm-scan 확장

목표: 가장 싼 비용으로 compiler/opt 차이를 관찰 가능하게 만든다.

현재 `asm-scan`은 `--cc` 하나와 `--opt` 여러 개를 받는다. 다음 단계는 컴파일러도
반복 가능하게 만드는 것이다.

예상 CLI:

```bash
python -m ctkat asm-scan -c examples/pqc_mlkem768/ctkat.yaml \
  --cc gcc --cc clang \
  --opt -O0 --opt -O2 --opt -Os
```

artifact 확장:

| 필드 | 의미 |
|---|---|
| `compiler` | gcc/clang 등 |
| `opt_level` | `-O0`, `-O2`, `-Os` |
| `source_file` | yaml source |
| `function` | symbol-resolved function |
| `mnemonic` | div/idiv/sdiv/udiv/... |
| `count` | occurrence 수 |
| `note` | ct stage에서 보이는지, 특정 opt에서만 보이는지 |

정책:

- 여전히 warn-only다.
- verdict에 합류시키지 않는다.
- compiler 누락은 해당 compiler만 skip할지, 전체 exit 2로 볼지 정책 결정 필요.
  보안 도구 관점에서는 사용자가 명시한 compiler가 없으면 exit 2가 더 정직하다.

완료 기준:

- gcc-only Docker에서 `--cc clang` 명시 시 exit 2 또는 명시적 per-compiler ERROR 기록
- fixed ML-KEM에서 `poly.c`는 안 뜨고, 취약 복원본에서는 `gcc -Os` 등에서 뜨는 fixture 확보
- JSON이 "어떤 compiler/opt에서만 div가 살아남았는지" 기계적으로 비교 가능

### Phase C. CT cflags matrix: Valgrind 구조 검사 확장

목표: `ct` stage 자체를 여러 cflags에서 돌려서, `-O0`만 본 결과의 한계를 줄인다.

주의: 이건 `asm-scan`보다 훨씬 큼. 기존 `ctkat_verdict.csv` schema와 verdict 정책에
영향이 있다.

권장 접근:

1. 처음에는 `run` verdict에 넣지 않는다.
2. 별도 서브커맨드 또는 별도 artifact로 시작한다.
3. 각 combo별 Valgrind status를 표로 낸다.

예상 artifact:

```text
ctkat_ct_matrix.csv
project,harness,combo,cc,cflags,valgrind_status,findings,error
```

예상 YAML:

```yaml
matrix:
  ct_cflags:
    debug: [-O0, -g, -fno-inline, -fno-omit-frame-pointer]
    release: [-O2, -g, -fno-omit-frame-pointer, -fno-lto]
    size: [-Os, -g, -fno-omit-frame-pointer, -fno-lto]
```

완료 기준:

- `-O0 PASS / -O2 FAIL`, `-O0 FAIL / -O2 PASS` synthetic fixtures 확보
- 기존 `ctkat run`의 exit code와 verdict CSV는 깨지지 않음
- matrix artifact가 CI에서 읽기 쉬움

### Phase D. Real-world corpus 확장

목표: 도구가 toy에서만 작동한다는 인상을 없애고, 실전 판단 자료를 만든다.

후보:

- PQClean ML-KEM 계열
- Dilithium/ML-DSA
- Falcon
- SPHINCS+
- table-based AES toy/legacy 구현
- constant-time compare / memcmp류
- 직접 만든 compiler-sensitive fixtures

수집할 것:

- KAT 결과
- Valgrind findings
- dudect status / effect size
- asm/matrix 결과
- compiler/opt/arch 환경
- false positive/false negative로 판단한 근거

완료 기준:

- 최소 3개 알고리즘군, 10개 이상 target/config 조합
- 한눈에 볼 수 있는 summary table
- 실패/경고 사례를 "도구 문제", "환경 노이즈", "실제 코드 이슈"로 분류

### Phase E. 정밀 taint: patched Valgrind 또는 use-def

목표: `asm-scan` 후보를 secret-derived operand finding으로 바꾼다.

이 단계는 늦게 들어가는 게 맞다. 이유는 다음과 같다.

- patched Valgrind fork 유지보수 비용이 큼
- 단순히 ct `-O0` binary에 붙이면 `/상수` division이 이미 사라져 빈손일 수 있음
- Finding으로 들어가면 verdict를 깨므로 오탐 비용이 커짐

들어갈 조건:

- matrix/corpus에서 "후보는 많은데 수동 triage 비용이 크다"는 문제가 실제로 확인됨
- 정밀 판정이 논문/보고서 핵심 기여로 필요함
- Docker patched toolchain 유지보수를 감당할 수 있음

구현 범위:

- `FindingType.SECRET_DEPENDENT_VARIABLE_LATENCY`
- patched Valgrind output parser
- `ct.variable_latency_errors: off|auto|require`
- `valgrind --help` probing
- patched Docker image
- gcc/clang/`-Os` 등 variable-latency 전용 build combo와 연결

---

## 4. 논문/보고서 방향성

### 4.1 약한 방향: "KyberSlash patched Valgrind를 CT-KAT에 붙였다"

이건 기술적으로 가능하지만 논문 신규성은 약하다.

문제:

- operand timing model은 이미 알려져 있다.
- KyberSlash 논문/도구가 이미 patched Valgrind/TIMECOP 계열을 보여줬다.
- 단순 통합은 artifact/engineering contribution에 가깝다.

포트폴리오/WISA 보고서로는 괜찮지만, 연구 논문으로 밀기엔 약하다.

### 4.2 더 나은 방향: Optimization-sensitive CT analysis

논문/보고서로 키우려면 주제를 다음처럼 잡는 편이 낫다.

> **암호 구현의 constant-time 분석 결과는 컴파일러/최적화/타깃 설정에 민감하다.  
> CT-KAT은 Valgrind, dudect, instruction survival scan을 결합해 이 민감도를
> matrix artifact로 드러낸다.**

가능한 제목:

- `Optimization-Sensitive Constant-Time Testing for C Cryptographic Implementations`
- `Build-Configuration-Aware Side-Channel Screening for PQC Implementations`
- `CT-KAT: A Fail-Closed Dynamic Testing Framework for Constant-Time Crypto`

핵심 research questions:

| RQ | 질문 |
|---|---|
| RQ1 | 같은 소스가 `-O0/-O2/-Os`, gcc/clang에 따라 Valgrind CT 결과가 달라지는가? |
| RQ2 | instruction-level 후보(`div`, table access 등)는 어떤 compiler/opt에서 생존하는가? |
| RQ3 | 구조적 finding과 dudect timing signal은 얼마나 자주 일치/불일치하는가? |
| RQ4 | fail-closed pipeline이 기존 "PASS처럼 보이는 실패"를 얼마나 줄이는가? |

가능한 contribution:

1. KAT/Valgrind/dudect/asm-scan을 한 config로 묶은 fail-closed framework
2. compiler/optimization-sensitive CT matrix artifact
3. PQC/crypto corpus에 대한 empirical study
4. false PASS 방지를 위한 engineering patterns 정리

### 4.3 실험 설계

필수 실험:

- synthetic fixtures
  - secret branch가 `-O0`에서만 보이는 케이스
  - `-O2`에서만 branch/table access가 생기는 케이스
  - constant division이 `-Os`에서만 `div`로 살아나는 케이스
  - safe reciprocal multiply negative control
- real-world examples
  - ML-KEM
  - sign scheme 1~2개
  - lookup-table implementation 1개
- environment
  - Docker linux/amd64 gcc
  - clang 가능하면 별도 image
  - native x86_64 Linux dudect 권장

측정값:

- Valgrind status
- dudect status, `abs_t_score`, Cohen's d, batch max
- asm/matrix candidate count
- toolchain/config error count
- manual triage 결과

### 4.4 Go / No-Go 기준

논문 방향으로 갈지 판단하는 기준:

**Go**:

- compiler/opt에 따라 CT result가 실제로 달라지는 nontrivial 사례가 여러 개 나온다.
- real-world corpus에서 단순 toy가 아닌 흥미로운 warning/finding이 나온다.
- matrix artifact가 기존 단일-run CT 도구보다 명확한 의사결정 가치를 준다.
- 실험이 재현 가능하다.

**No-Go**:

- 결과가 대부분 "toy에서는 됨, real-world는 전부 clean" 수준이다.
- 새로 보여주는 게 KyberSlash 재현뿐이다.
- patched Valgrind 통합 외 기여가 없다.
- dudect 결과가 환경 노이즈 때문에 설명 불가능하다.

No-Go여도 프로젝트 가치는 남는다. 이 경우 포지셔닝은 논문이 아니라
**도구화/교육/CI hardening artifact**다.

---

## 5. 권장 다음 작업 순서

1. 현재 Phase A 완료 상태를 유지한다.
   - 테스트 green 유지
   - README/tutorial/examples 정리

2. Phase B를 먼저 한다.
   - `asm-scan --cc` repeatable
   - JSON/CSV에 compiler dimension 추가
   - ML-KEM vulnerable/fixed fixture로 positive/negative control 유지

3. synthetic compiler-sensitive fixtures를 만든다.
   - matrix가 KyberSlash 외에도 의미 있다는 증거가 필요하다.

4. corpus를 넓힌다.
   - PQClean/crypto examples를 늘려서 empirical table을 만든다.

5. 그 다음에 Phase C 또는 E를 고른다.
   - 도구 완성도/논문 empirical study면 Phase C
   - secret-derived operand 정밀 판정이 필요하면 Phase E

---

## 6. 최종 판단

지금 CT-KAT의 가장 좋은 방향은 **"정밀 증명 도구"가 아니라 "build-aware,
fail-closed side-channel screening framework"**다.

KyberSlash/div는 이 방향성을 발견하게 만든 좋은 사례지만, 프로젝트 전체를 div에
묶으면 좁아진다. 다음 핵심은 `compiler × optimization × target` matrix를 통해
"검사한 바이너리와 배포 바이너리의 보안 성질이 다를 수 있다"는 문제를 체계적으로
드러내는 것이다.

논문으로 키우려면 새 이론보다 **empirical + artifact** 방향이 현실적이다. 단,
nontrivial corpus 결과가 없으면 논문성은 약하고, 포트폴리오/도구 보고서로 포지셔닝하는
게 더 정직하다.
