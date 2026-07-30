# CT-KAT

KAT, Valgrind/Memcheck, asm-scan, ct-matrix와 pinned upstream
**official dudect** 통계 백엔드를 묶어 쓰는 constant-time **스크리닝**
프레임워크. 기존 Python first-order 구현은 명시적 experimental 백엔드로만
남아 있다.

C 암호 구현을 던지면 설정된 하니스에 대해:

1. 빌드
2. KAT (Known Answer Test) — 정확성 확인
3. **Valgrind/Memcheck** — secret-tainted 값이 분기/메모리 주소 계산에 쓰였는지 (구조적 검사)
4. **ct-matrix** — compiler × cflags별로 구조적 CT 결과가 바뀌는지 확인
5. **asm-scan** — emitted assembly에서 `div/idiv` 같은 variable-latency 후보 수집
6. **timing screen (`dudect` 명령)** — CT-KAT이 측정한 fixed-vs-random raw trace를 official dudect의 102개 검정으로 분석
7. CSV/JSON/Markdown 리포트 + triage가 연결된 evidence schema v2 출력

`screen`의 5상태 `overall`이 현재 도구/코퍼스의 기준이다. raw layer,
timing validity, review 상태를 따로 보존하므로 raw timing `FAIL`과 clean
headline이 공존할 수 없다. 예전 `run` 명령은
Valgrind+dudect 결합 verdict(`CLEAN`, `STRUCTURAL_LEAK`, `SUSPECT`, `RISKY`,
`CRITICAL`)를 계속 제공하지만, asm-scan/ct-matrix/triage까지 포함한 최종
판정은 아닌 legacy compatibility artifact다.

> **⚠ PASS/CLEAN/no-finding-observed는 "constant-time 증명"이 아니다.** 이 도구가
> 실행한 하니스, 입력 분포, 컴파일러/cflags, checker 범위 안에서 새 finding을
> 못 봤다는 뜻이다. 보지 않는 것: power/EM/fault side-channel, formal absence
> proof, 희귀/adversarial input trigger, asm-scan 후보의 자동 secret-taint 판정.
> PASS를 받았다고 masking analysis, power trace, 정적/형식 검증, 알고리즘별
> adversarial test를 건너뛰지 말 것. 자세한 한계는 §"Limitations &
> recommended environment" 참고.

```
$ python -m ctkat run --config examples/toy_password/ctkat.yaml
[CTKAT] Build: PASS
[CTKAT] Constant-Time Check: FAIL
                  Potential variable-time findings
┃ harness ┃ function    ┃ file:line        ┃ severity ┃ type                    ┃
│ bad     │ bad_compare │ bad_compare.c:10 │ HIGH     │ SECRET_DEPENDENT_BRANCH │
       Combined verdict (Valgrind + dudect)
┃ harness ┃ valgrind ┃ dudect ┃ |t| ┃ verdict  ┃
│ bad     │ FAIL     │ NONE   │ -   │ STRUCTURAL_LEAK │
```

---

## Quick start

Python 패키지와 pure-Python 명령은 일반 환경에 설치할 수 있다:

```bash
python -m pip install .
ctkat --version
ctkat infer --header tests/fixtures/headers/kem.h
```

Valgrind 구조 검사는 Linux가 필요하다. macOS/Windows 개발 환경에서는
Docker Desktop을 실행한 뒤:

```bash
# 컨테이너에 진입
./scripts/dev.sh

# 컨테이너 안에서
ctkat run --config examples/toy_password/ctkat.yaml
PYTHONPATH=. pytest tests -v
```

또는 일회성 실행:

```bash
docker compose run --rm ctkat-dev bash -c \
    "ctkat run --config examples/toy_password/ctkat.yaml"
```

처음 한 번은 도커 이미지 빌드에 5~10분 (Apple Silicon은 x86_64 에뮬레이션). 두 번째부터는 캐시.

---

## Why Docker

- **Valgrind는 macOS에서 동작 안 함** (특히 ARM/최신 OS). 리눅스 컨테이너 필수.
- Apple Silicon 맥은 `platform: linux/amd64`로 강제해서 QEMU 에뮬레이션 —
  구조 분석과 official backend 회귀는 돌릴 수 있지만 target timing validity는
  `environment-rejected`다.
- 호스트 작업 디렉토리를 `/workspace`에 마운트하므로 호스트에서 편집해도 컨테이너가 즉시 봄.

---

## Project structure

```
WISA/
├── ctkat/                      # framework package
│   ├── cli.py                  # typer CLI (run / ct / kat / dudect / infer / parse)
│   ├── config.py               # pydantic yaml schema
│   ├── builder.py              # build/KAT argv + explicit-shell wrapper
│   ├── valgrind_runner.py
│   ├── valgrind_parser.py      # finding extraction + heuristic re-classification
│   ├── harness_generator.py    # Jinja2 → C harness (Valgrind side)
│   ├── timing_harness_generator.py   # Jinja2 → C harness (dudect side)
│   ├── dudect_runner.py
│   ├── official_dudect.py      # pinned upstream C backend adapter
│   ├── timing_environment.py   # host manifest + fail-closed validity
│   ├── statistics.py           # legacy experimental Welch backend
│   ├── verdict.py              # Valgrind × dudect → combined verdict
│   ├── header_parser.py        # C header → function signatures
│   ├── secret_infer.py         # PQC profile + name heuristic
│   ├── qemu_detect.py
│   ├── report.py
│   ├── native/                 # official dudect raw-trace C bridge
│   ├── _vendor/dudect/         # exact pinned upstream header + license
│   └── templates/
│       ├── harness_generic.c.j2 / harness_kem.c.j2 / harness_sign.c.j2
│       ├── timing_generic.c.j2 / timing_kem.c.j2 / timing_sign.c.j2
│       └── timing_v2_common.c.j2   # KEM/sign pool/control/AUX protocol
├── examples/
│   ├── toy_password/           # bad_compare vs safe_compare (Phase 0~2)
│   ├── toy_dudect/             # leaky_function vs safe_function (Phase 4)
│   ├── toy_lookup/             # secret-indexed S-box vs constant-index
│   ├── toy_release_smoke/      # wheel-only CI end-to-end target
│   ├── pqc_mlkem512/           # PQClean ML-KEM-512 + valid/invalid KEM paths
│   ├── pqc_mlkem768/           # PQClean ML-KEM-768 + valid/invalid KEM paths
│   ├── pqc_mlkem1024/          # PQClean ML-KEM-1024 + valid/invalid KEM paths
│   ├── pqc_mlkem768_kyberslash/# ML-KEM with KyberSlash /KYBER_Q positive control
│   ├── pqc_mldsa44/            # PQClean ML-DSA-44 attribution/registry case
│   ├── pqc_mldsa65/            # PQClean ML-DSA-65 attribution/registry case
│   ├── pqc_mldsa87/            # PQClean ML-DSA-87 attribution/registry case
│   ├── pqc_sphincs_sha2_128f_simple/ # SPHINCS+ public-output attribution case
│   └── pqc_falcon512/          # Falcon/FN-DSA needs-analysis boundary target
├── docs/measurement/           # frozen native timing campaign + execution gate
├── tests/                      # pytest regression suite
├── scripts/                    # runners + release/corpus/provenance gates
├── Dockerfile, docker-compose.yml
└── pyproject.toml
```

---

## Screening model

검사는 여러 후보 소스를 모은 뒤 triage로 줄이는 구조다. 각 층은 서로 다른
blind spot을 가진다:

```
[1] KAT — Correctness
    test vectors + roundtrip check
    "구현이 맞게 동작하나?"
         ↓
[2] Valgrind Memcheck — Structural CT
    VALGRIND_MAKE_MEM_UNDEFINED → secret-tainted value tracking
    "secret 값이 분기 또는 메모리 주소 계산에 쓰였나?"
         ↓
[3] ct-matrix — Build sensitivity
    compiler × cflags별로 같은 하니스 재컴파일
    "빌드가 바뀌면 structural verdict가 달라지나?"
         ↓
[4] asm-scan — Variable-latency instruction candidates
    emitted assembly에서 div/idiv/sdiv/udiv 후보 수집
    "KyberSlash류 operand-latency 후보가 빌드에 살아남나?"
         ↓
[5] Timing measurement + official dudect — Statistical Timing
    fixed-vs-random raw trace + raw/100 crop/second-order tests (max |t|)
    "설정한 두 class의 실행 시간 분포가 통계적으로 다른가?"
         ↓
[triage] asm attribution + review state / artifact ID
         ↓
[evidence v2] layer states + review artifact
         ↓
[overall] no-finding-observed / risk-detected / needs-review /
          inconclusive / tool-error
```

각 층의 역할:

| 층 | 잡는 것 | 못 잡는 것 |
|---|---|---|
| KAT | 기능 정확성 | 부채널 위험 |
| Valgrind | secret-tainted branch, secret-indexed memory access | 명령어 latency 차이, 실행 안 된 경로, power/EM |
| ct-matrix | 빌드별 structural verdict 변화 | 왜 변했는지의 보안 의미 |
| asm-scan | `div/idiv` 등 variable-latency 명령 후보 | operand가 secret인지 자동 증명하지 못함 |
| timing screen | 설정한 두 class 사이의 timing 차이 | 정확한 코드 위치, rare trigger, noisy/QEMU 환경, 하니스 confound |
| triage | public 후보와 secret-risk/accepted behavior 분리 | 사람이 쓴 근거가 틀리면 같이 틀림 |

모든 configured layer가 통과해도 결론은 “이 하니스와 환경에서 새 후보가
없었다”이지, 보편적 constant-time 보장이 아니다.

---

## YAML config schema

전체 필드:

```yaml
project:
  name: my_target              # 리포트에 박힐 이름
  language: c
  root: .                      # 다른 경로의 기준점

execution_profile: trusted     # untrusted면 모든 shell-backed command 거부

build:
  argv: ["make", "clean", "all"]  # 기본: shell=False
  workdir: .
  expected_artifacts:          # (E-1) 빌드가 생산해야 할 파일들. rc=0인데
    - build/harness_foo        # 빠진 게 있으면 build FAIL. unset 시 legacy
    - build/harness_bar        # exit-code-only 동작 + 1회 warning.

# Optional. 없으면 KAT 단계 스킵.
kat:
  argv: ["./test_kat"]
  workdir: .
  expected_min: 100            # (E-1) stdout에서 expected_pattern으로 추출한
                               # 테스트 개수가 이 값 이상이어야 PASS. unset 시
                               # legacy exit-code-only 동작 + 1회 warning.
  expected_pattern: 'PASSED:?\s*(\d+)'   # (E-1) capturing group 1개. 기본값은
                               # PQClean/NIST KAT 출력 'PASSED: N tests'와 호환.

# Optional. 없으면 ct 검사 스킵.
ct:
  workdir: .
  generated_dir: ./_generated  # 자동 생성된 하네스 .c/binary 위치
  seed: 0xC0FFEE               # 자동 생성 하네스의 xorshift PRNG 시드 (재현성)
  require_sentinel: true       # (E-2) manual-binary 하니스가 stdout에
                               # 'CTKAT-HARNESS-RAN: <name>' 를 emit해야 PASS.
                               # 없으면 status=ERROR → INCONCLUSIVE. template
                               # 모드 하니스는 검사 안 함.
  sentinel_pattern: 'CTKAT-HARNESS-RAN:\s*(\S+)'   # (E-2) capturing group 1개.
  cflags:                      # 자동 생성 하네스 컴파일 옵션 (기본 -O0 디버그 친화)
    - -O0
    - -g
    - -fno-inline
    - -fno-omit-frame-pointer
  valgrind_flags:              # valgrind 실행 옵션 (exit 99 = finding 있음)
    - --tool=memcheck
    - --track-origins=yes
    - --error-exitcode=99
  harnesses:
    - name: foo                # 수동 모드: 미리 빌드된 binary 지정
      binary: ./build/harness_foo

    - name: bar                # 자동 모드: 템플릿 기반 자동 생성
      template: generic        # generic | kem | sign
      extra_headers: [api.h]
      include_dirs: [include]
      sources: [src/foo.c]
      # generic 전용:
      function: bar_func
      return_type: int
      args: [secret, public, "sizeof(secret)"]
      buffers:
        - {name: secret, size: "16", role: secret}
        - {name: public, size: "16", role: public}
      # kem/sign 전용:
      header: api.h
      prefix: "PQCLEAN_FOO_CLEAN_"   # PQClean 네임스페이스
      secret_regions:               # sk 안 진짜 secret 영역만 taint
        - {offset: "0", length: "FOO_INDCPA_SECRETKEYBYTES",
           comment: "real secret"}

# Optional. 없거나 enabled=false면 dudect 스킵.
dudect:
  enabled: true
  backend: official-dudect     # 기본값. pinned upstream C engine; x86_64 only
  measurements: 100000
  warmup: 1000
  batches: 10                  # batch stability 분할 수
  clock: auto                  # auto (기본, 환경 감지) | monotonic | rdtsc (x86 only)
  seed: 0xC0FFEE               # null이면 매번 랜덤 시드 + 로그에 기록
                               # KEM/sign은 weak randombytes interpose 사용 여부를
                               # runtime manifest로 확인. strong OS-random symbol이
                               # 이기면 validity=confounded.
  timeout: 600                 # (E-1) per-harness wall-clock ceiling. 초과 시
                               # TimeoutExpired → status=ERROR → verdict
                               # INCONCLUSIVE. Python traceback이 나가지 않음.
  compile_timeout: 600         # timing harness / backend bridge compile ceiling
  backend_timeout: 120         # raw trace를 통계 backend가 분석하는 시간 제한
  timing_protocol:             # KEM/sign timing-harness-v2 physical controls
    process_repeats: 3         # valid 후보가 되기 위한 최소 독립 process/seed 수
    pool_size: 64              # class 0/1 pool을 측정 전에 각각 생성
    control_measurements: null # null이면 measurements 재사용
    positive_control_effects: [32, 128, 512] # cycles(rdtscp) 또는 ns(monotonic)
    aa_abs_t_limit: 4.5        # A/A·setup-placebo 사전 false-alarm limit
    positive_abs_t_threshold: 10.0
    aa_max_failures: 0
    target_power: 0.80
    power_alpha: 0.01
  workdir: .
  generated_dir: ./_generated_dudect
  compiler:
    cc: gcc                    # gcc | clang
    # -fno-lto는 측정 정밀도에 중요: LTO를 켜면 컴파일러가 외부 링크 함수의
    # body까지 보고 "return값 안 쓰니까 호출 elide"를 결정할 수 있음.
    cflags: [-O2, -g, -fno-omit-frame-pointer, -fno-lto]
  harnesses:
    - name: bar
      template: generic        # generic | kem | sign
      extra_headers: [api.h]
      include_dirs: [include]
      sources: [src/foo.c]
      # generic 전용:
      function: bar_func
      return_type: int
      args: [secret, "sizeof(secret)"]
      buffers:
        - {name: secret, size: "16", role: secret}
      # kem/sign 공통:
      header: api.h
      prefix: "PQCLEAN_FOO_CLEAN_"
      randombytes_header: randombytes.h # seeded weak interpose용; toy만 null
      # kem 전용:
      leak_target: sk          # sk | ct | fo
      # sign 전용:
      sign_leak_target: sk     # sk | msg

report:
  output_dir: ./reports
  csv: ctkat_report.csv
  json: ctkat_report.json
```

official backend의 판정 규칙(`|t| > 10`, class 0 retained sample 10,000개 초과)은
upstream에 고정돼 있다. 예전 5-cutoff Python screen이 필요한 호환 실험만
아래처럼 명시적으로 켠다:

```yaml
dudect:
  backend: experimental-first-order
  threshold_warning: 4.5
  threshold_fail: 10.0
  sqrt_m_threshold_scaling: false  # 경험적 sqrt(m) 배율; Bonferroni/FWER 아님
```

구형 `bonferroni_correct` 키는 경고와 함께 위 이름으로 한시 migration되지만,
official backend와는 함께 쓸 수 없다.

`ct.harnesses[*].binary` (수동) ↔ `template` (자동)은 **상호 배타**. 둘 중 하나만.

수동 모드는 사용자 책임 영역이라 프레임워크가 binary 안에서 무슨 일이 일어나는지 모름 — `binary: /bin/true`도 "0 findings → PASS"로 통과되어 버린다 (F5). E-2부터는 `ct.require_sentinel: true`를 박으면 binary가 stdout에
`CTKAT-HARNESS-RAN: <harness-name>`을 출력해야 PASS, 없으면 status=ERROR
→ verdict INCONCLUSIVE. examples의 `toy_password/harness/harness_*.c`가
이 컨벤션의 reference. 자동 모드(template)는 자체적으로 target 함수를
호출하므로 sentinel 검사 스킵.

---

## official dudect timing backend

`dudect` CLI/config 이름은 그대로지만 기본 통계 엔진은
[`oreparaz/dudect`](https://github.com/oreparaz/dudect)의
`dc269651fb2567e46755cfb2a13d3875592968b5` revision이다. CT-KAT은 input
generation, target build, timing measurement와 artifact orchestration을
담당하고, 별도 C process가 hash 검증된 upstream `dudect.h`의 통계 함수를
직접 실행한다.

official protocol의 target repeat 하나마다 하니스를 두 번 실행한다. 첫 trace는
100개 crop threshold를 정하는 calibration batch라 통계에서 버리고, 독립된
두 번째 trace만 분석한다. KEM/sign v2 기본은 이 쌍을 세 process/seed에서
반복한다. 결과는 uncropped first-order 1개 + cropped first-order 100개 +
second-order 1개, 총 102개 검정의 max `|t|`, `tau=t/sqrt(n)`, detection
estimate를 포함한다. upstream 규칙대로 각 repeat의 class 0 retained sample이
10,000개를 넘지 못하면 `INSUFFICIENT`이며 PASS가 아니다. A/A/placebo/effect
trace는 target의 102-test 판정과 섞지 않고 사전 선언한 raw first-order control
threshold로 validity/power만 검증한다.

모든 target/calibration/control process가 같은 deterministic input stream을
재사용하지 않도록 yaml seed에서 role/repeat/effect별 uint64 seed를
domain-separate한다. 모든 seed는 protocol CSV/JSON에 기록한다.

이 upstream revision은 x86 intrinsics를 사용하므로 official backend는
**x86_64 전용**이다. ARM/macOS에서는 native x86_64 Linux/macOS 장비를 쓰거나
`backend: experimental-first-order`를 명시해야 한다. QEMU로 x86_64를
에뮬레이션하면 raw 결과는 보존하지만 validity는
`environment-rejected`라서 verdict를 clear하지 못한다. 최신 Docker
Desktop의 `VirtualApple` x86 translation marker도 같은 정책으로 잡는다.

### clock 선택 (`clock: auto` default)

`auto`는 yaml load 시 환경을 보고 적합한 clock을 자동 선택:

| 환경 | resolved clock |
|---|---|
| Native x86_64 (Linux/macOS Intel/Windows AMD64¹) | `rdtsc` |
| Apple Silicon, Linux ARM | `monotonic` |
| Docker on Apple Silicon (QEMU x86_64 에뮬레이션) | `monotonic` |

¹ **Windows MSVC는 미지원** (U3). 생성된 harness가 `<x86intrin.h>` / `__rdtscp` / `_mm_lfence`를 GCC/Clang intrinsic 그대로 쓰기 때문에 MinGW gcc 빌드만 동작함. MSVC intrinsic 이름은 다르고, Windows 환경 전체가 CI에서 검증되지 않았다. Windows에서 돌릴 거면 WSL2 + Linux gcc를 권장.

명시적으로 `clock: rdtsc`를 박아 놓은 yaml이 x86_64 아닌 호스트에서
로드되면 yaml load 단계에서 `ValidationError` (compile 단의 cryptic
`<x86intrin.h>` not-found 에러 대신).

### 측정 primitives (생성된 C harness)

전체 gate/축/아티팩트 계약은
[`docs/TIMING_HARNESS_V2.md`](docs/TIMING_HARNESS_V2.md)에 고정돼 있다.

| 항목 | 내용 |
|---|---|
| input pool | KEM/sign class 0/1 입력을 warmup 전에 전부 생성. 측정 loop 안 keygen/enc 없음 |
| setup 대칭 | 두 class 모두 같은 길이 `memcpy`를 거쳐 동일 주소 `*_work` buffer 사용 |
| timed region | target API 호출만 포함. positive control에서만 요청한 class-1 delay 추가 |
| physical controls | 같은 binary/process 경계의 label-only A/A, common work buffer를 fixed data로 정규화하는 setup-placebo, 3단계 effect A/B |
| PRNG domain | class label, pool index, target randombytes를 서로 다른 seed domain으로 분리 |
| rdtsc 직렬화/AUX | `_mm_lfence` + `__rdtscp` + `_mm_lfence`; 전후 AUX가 다르면 `cpu-migration`으로 폐기 |
| compiler 배리어 | `CTKAT_USE(ret)` 매크로로 비-void 리턴값 materialize. `-fno-lto` 기본값과 함께 외부 링크 함수 호출 elide 방어 |
| signature scope | full `crypto_sign_signature` API. `output_length`를 행마다 기록하며 core sampler는 별도 generic harness/row |
| drop provenance | `clock-anomaly`, `cpu-migration`, malformed를 이유·class·실제 sample id와 함께 보존 |

### 컴파일 옵션 비대칭 경고 (Bundle E-3)

ct stage(Valgrind)와 dudect stage는 같은 소스를 **다른 cflags로 컴파일한다**.
verdict=CLEAN이 떠도 "내가 배포할 -O2 바이너리"의 안전성 보장이 아님.

| stage | 기본 cflags | 이유 |
|---|---|---|
| ct (Valgrind) | `-O0 -g -fno-inline -fno-omit-frame-pointer` | secret-dependent 분기를 cmov로 융합되기 전 단계에서 봐야 Valgrind가 정확히 보고 |
| dudect | `-O2 -g -fno-omit-frame-pointer -fno-lto` | 사용자가 실제 배포할 바이너리에 가까운 타이밍 |

구체적 함정:

- `-O0`에선 `if (secret_byte) { ... }`가 분기로 남아 Valgrind가
  secret-dependent branch FAIL을 보고.
- `-O2`에선 같은 코드가 `cmov`로 컴파일되어 분기가 사라짐 → dudect는 타이밍
  차이를 못 봐서 PASS.
- 결합 verdict=CLEAN인데도 "실제 -O2 배포 바이너리"에 cmov로 마스킹된
  leak이 있을 수 있고, 반대로 `-O2`가 keep한 분기가 `-O0` ct에선 안 보일
  수도 있다.

런 시작 시 두 stage의 cflags가 다르면 yellow banner로 경고가 뜸. 일치
시키려면 yaml `ct.cflags`와 `dudect.compiler.cflags`를 동일 값으로 박으면
됨 (Valgrind 측 디버그 정보 손실은 감수):

```yaml
ct:
  cflags: [-O2, -g, -fno-omit-frame-pointer, -fno-lto]   # dudect와 통일
dudect:
  compiler:
    cflags: [-O2, -g, -fno-omit-frame-pointer, -fno-lto]
```

### 통계·validity layer

| 항목 | official backend (기본) | experimental backend (opt-in) |
|---|---|---|
| first-order | uncropped 1개 + percentile crop 100개 | cutoff `[1.0, 0.99, 0.95, 0.90, 0.75]` 5개 |
| second-order | 1개 | 없음 |
| raw 판정 | upstream max `|t| > 10`이면 FAIL | `<4.5` PASS, `4.5–10` WARNING, `≥10` FAIL (설정 가능) |
| 최소 표본 | class 0 retained sample >10,000, 아니면 `INSUFFICIENT` | 별도 upstream minimum 없음 |
| 추가 통계 | max `tau`, detection estimate, 102개 test 전체 | batch t-score, uncropped score, Cohen's d |
| evidence validity | 환경·하니스·power control을 별도 검사 | 항상 non-decisional; `valid` 승격은 pinned official backend만 |

두 backend 모두 `clock-anomaly`와 RDTSCP AUX CPU migration sample을 버리고
class별 이유/개수를 기록한다. 전체 drop이 1%를 넘거나 한 class의 drop이 5%를
넘으면서 class 간 차이도 5%를 넘으면 `environment-rejected`다. official
engine에는 raw CSV에서 `drop_reason`이 빈 retained row만 넘기고, CSV 자체는
폐기 row도 원래 sample id로 보존한다. target, calibration, A/A,
setup-placebo, positive trace를 전부 expected row
수·malformed bookkeeping으로 검사하며 한 행이라도 설명되지 않으면
`timing_validity=error`다.

KEM/sign이 `valid` 후보가 되려면 다음을 **전부** 통과해야 한다.

1. native/non-emulated host와 Linux single-CPU affinity
2. 세 개 이상 독립 process/seed에서 같은 target raw status
3. label만 다른 physical A/A의 사전 false-alarm budget
4. class setup 뒤 fixed target을 재는 setup-placebo 무신호
5. 가장 큰 seeded effect가 설정한 `target_power`로 반복 검출
6. 모든 official target repeat의 minimum measurement 충족
7. runtime manifest가 seeded randombytes interpose 사용을 확인

A/A/setup-placebo가 깨지면 `confounded`, effect power나 repeat 수/일관성이
부족하면 `insufficient-power`다. 이 validity는 raw PASS/FAIL과 독립이라
`valid + FAIL`은 유효한 timing signal, `valid + PASS`는 해당 run의 검출
한계 안에서 no-signal이다. generic은 caller-defined setup을 자동 대칭화할
수 없으므로 계속 `insufficient-power`다.

`dudect_backend_report.json`에는 A/A별 t, false-alarm budget, 각 effect의
실측 mean delta/detection rate, A/A noise로 계산한 run별 minimum detectable
effect(MDE)가 들어간다. MDE는 `power_alpha`와 `target_power`를 쓴
two-sided normal approximation이며 “검출 못 했으니 0” 같은 개소리를
막기 위한 run 한계치다.

Linux에서는 process affinity가 CPU 하나가 아니면, 그리고 모든 OS에서 QEMU
emulation이면 `environment-rejected`다. system, machine, kernel, clock,
affinity, governor, SMT, turbo, microcode는
`dudect_backend_report.json`에 기록한다. CT-KAT이 host 설정을 몰래 바꾸지는
않는다.

기존 5-cutoff backend의 `sqrt_m_threshold_scaling`은 threshold에
`sqrt(m)`을 곱하는 경험적 호환 옵션일 뿐 Bonferroni correction이나 FWER
보장이 아니다. 이 옵션과 threshold 설정은
`backend: experimental-first-order`에서만 의미가 있다.

### backend synthetic calibration

[`docs/calibration/timing_backend_v2.json`](docs/calibration/timing_backend_v2.json)은
50,050-sample calibration/analysis trace, effect당 20회로 고정한 회귀
artifact다. 현재 acceptance 결과는 A/A false alarm `0/20`, injected
`d=0.1` 검출 `17/20`, `d=0.2` 검출 `20/20`, 같은 uncropped trace의 upstream
C와 Python Welch `|Δt| ≤ 1e-9`다.

이건 **통계 adapter 자체**의 synthetic calibration이다. 실제 암호 target의
하니스 대칭성, 물리 host A/A, process 반복이나 검출력을 검증한 게 아니다.
그래서 이 artifact만으로 target run을 `timing_validity=valid`로 올리지 않는다.

### Native corpus timing campaign

현재 corpus에서 timing evidence가 있는 6개 target/8개 axis를
timing-harness-v2로 다시 재기 위한 실행 계획은
[`docs/measurement/native_timing_v2_campaign.yaml`](docs/measurement/native_timing_v2_campaign.yaml)에
동결돼 있다. macOS/ARM이나 Docker/QEMU에서 가짜 결론을 만드는 대신, 지금
checkout에서 가능한 준비 상태는 다음 명령으로 계속 검사한다.

```bash
python scripts/run_native_timing_campaign.py --check
```

bare-metal x86_64 Linux가 생기면 clean checkout에서 한 명령으로 preflight,
CPU pinning, target별 3-process 측정, physical controls, artifact 검증과 corpus
승격 후보 생성까지 실행한다.

```bash
python scripts/run_native_timing_campaign.py \
  --execute \
  --cpu 2 \
  --output-root measurement_runs/corpus-native-timing-v2
```

중단한 run은 `--resume`, 일부 target은 반복 가능한 `--target`으로 이어간다.
결과의 다섯 artifact와 hash/protocol row 수를 다시 검사하려면
`--validate-run <output-root>`를 쓴다. exit `0`만 모든 선택 축이
promotion-ready라는 뜻이고, `2`는 artifact는 완전하지만 validity gate가
깨졌다는 뜻이다. runner는 `corpus_timing_updates.csv`만 만들며
`docs/corpus`를 자동 수정하지 않는다. 자세한 host gate와 산출물 계약은
[`docs/measurement/README.md`](docs/measurement/README.md)에 있다.

### 재현성 (seed)

`dudect.seed`에서 target/calibration/A/A/placebo/effect process seed를
domain-separate하고, 각 process 안에서도 class label/pool index/target
randomness PRNG를 분리한다.

| 부분 | seed로 재현됨? |
|---|---|
| `template: generic`의 `rand_bytes()`로 채우는 secret/public 버퍼 | ✅ 예 |
| KEM/sign pool의 PQClean keypair/enc/sign randomness (`common/randombytes.c` 제외 시) | ✅ 예 |
| class label sequence | ✅ 예; target random consumption과 별도 stream |
| pool index sequence | ✅ 예; label/randomness와 별도 stream |
| strong target `randombytes`를 함께 link한 경우 | ❌ OS/target 정책. runtime manifest가 `external-or-none`로 기록하고 validity를 `confounded`로 막음 |

cycle/ns 값 자체는 scheduler, cache, frequency 때문에 bit-identical하지 않다.
재현되는 것은 입력·label·effect protocol이다. 각 process의 seed와 실제
randomness policy는 `dudect_backend_report.json`과
`dudect_protocol_timings.csv`에 남는다.

**`seed: 0` 금지** (F16). `ct.seed`와 `dudect.seed` 둘 다 config 로드
단계에서 `0` 입력을 거부한다. 이유: 생성된 C 하네스의 xorshift64는
`state=0`이면 영구적으로 0만 뱉기 때문에 템플릿이 내부적으로
`seed ? seed : 0xC0FFEE` swap을 박아둠. swap 자체는 의미적으로 필요한
방어지만, 사용자가 `seed: 0`을 yaml에 박으면 Python 로그는 `0x0`을
출력하고 실제 실행 바이너리는 `0xC0FFEE`를 쓰게 되어 두 레이어가
silent로 어긋난다. validator가 그걸 막는다. 다른 값이 필요하면
`seed: 1` 이상을 박거나, `dudect.seed: null`(랜덤 + 로그 출력)을 쓰면 됨.

### 결정론적 PQClean dudect — `randombytes` interpose

KEM/sign v2 하네스는 자기 자신의 `randombytes(uint8_t *buf, size_t len)`을
**weak symbol**로 emit한다. target-randomness 전용 PRNG로 buf를 채운다.
사용자가 yaml `sources:`에서 PQClean의
`common/randombytes.c`를 **빼면** 우리 weak 정의가 유일 정의가 되어
`crypto_kem_keypair` / `crypto_kem_enc` / `crypto_sign_*` randomness가
기록된 seed로 결정된다.

opt-in 방법:

```yaml
dudect:
  harnesses:
    - name: ml_kem_768
      template: kem
      header: api.h
      include_dirs: [include]
      sources:
        - ml_kem_768/clean/kem.c
        - ml_kem_768/clean/indcpa.c
        # - common/randombytes.c   ← 빼기
        - common/fips202.c
```

PQClean common/randombytes.c가 sources에 그대로 박혀있으면 strong이 win
하므로 weak 정의는 무시된다. v2는 setup/measurement randombytes call count를
stderr manifest로 측정해 이 경우를 숨기지 않고 `confounded` 처리한다.
`randombytes_header` 기본값은 `randombytes.h`; 매크로 namespace가 없는
deterministic toy만 `null`을 쓸 수 있다. GCC/Clang 기준이며 Windows MSVC의
weak symbol 시맨틱은 현재 지원하지 않는다.

### `dudect_summary.csv` 컬럼 reference

| col | 이름 | 의미 |
|---|---|---|
| 1-2 | `project`, `harness` | 식별자 |
| 3-4 | `n0`, `n1` | max test에 포함된 클래스별 sample 수 |
| 5-6 | `mean0`, `mean1` | max test의 클래스별 평균 cycle / ns |
| 7-8 | `var0`, `var1` | max test의 클래스별 variance |
| 9-10 | `t_score`, `abs_t_score` | protocol family의 max t-score |
| 11 | `status` | PASS / WARNING / FAIL / INSUFFICIENT / ERROR |
| 12-14 | `batch_t_mean`, `batch_t_max_abs`, `batches` | 배치 안정성 |
| 15 | `cropped_at` | experimental backend에서 max \|t\|를 만든 cutoff |
| 16-17 | `t_score_uncropped`, `abs_t_score_uncropped` | cutoff=1.0의 raw t-score (diagnostic, cropping 부작용 확인용) |
| 18 | `raw_n_total` | Bundle F (S1): zero-filter 적용 전 C 하니스가 emit한 row 수. `measurements - raw_n_total`이 0 이상이면 하니스가 일부 측정을 누락. ERROR-status row는 0 |
| 19-20 | `dropped_zero_n0`, `dropped_zero_n1` | Bundle F (S1): zero-cycle filter가 클래스별로 떨어뜨린 수. `n0 = (raw_n0 - dropped_zero_n0)` 식. 두 값이 비대칭하면 sample bias 의심 (F4/S2 console warning과 같이 봄) |
| 21 | `cohens_d` | experimental backend의 표준화 효과 크기. official backend는 빈 칸 |
| 22-24 | `backend`, `timing_validity`, `validity_reasons` | 정확한 엔진 ID와 fail-closed 해석 상태/사유 |
| 25-27 | `test_kind`, `test_index`, `protocol_test_count` | max test 종류·index와 전체 검정 수 |
| 28-29 | `max_tau`, `detection_estimate` | upstream `tau=t/sqrt(n)`와 `(5/tau)^2` estimate |
| 30 | `enough_measurements` | official dudect minimum 충족 여부 |
| 31 | `upstream_revision` | pinned upstream commit |
| 32 | `calibration_raw_n_total` | 별도 calibration trace의 raw sample 수 |
| 33-34 | `analysis_seed`, `calibration_seed` | 두 trace의 domain-separated PRNG seed |
| 35-37 | `dropped_migration_n0`, `dropped_migration_n1`, `malformed_count` | AUX migration 및 parse drop bookkeeping |
| 38-42 | `harness_protocol`, `process_repeats`, `aa_failures`, `positive_power_passed`, `minimum_detectable_effect_max` | timing-harness-v2 control/power 요약 |

컬럼 1-14는 backward compatibility 보장 (외부 awk 스크립트 호환). 15-17은
Bundle B diagnostic 컬럼, 18-20은 Bundle F (S1) raw-count 컬럼, 21은
Bundle G (S3) 효과 크기, 22-34는 timing-backend-v2, 35-42는
timing-harness-v2 컬럼이다. 모두 끝에
append됐으므로 기존 awk-by-position 파서는 안 깨진다.

추가 timing artifact:

- `dudect_raw_timings.csv` — analysis trace
- `dudect_calibration_timings.csv` — official crop threshold 전용으로 버린 첫 trace
- `dudect_protocol_timings.csv` — 모든 target repeat/calibration/A/A/placebo/effect
  raw row, process index, seed, effect, AUX, drop reason
- `dudect_backend_report.json` — 102개 test 전체, host manifest, validity 사유,
  control/power/MDE manifest와 세 raw artifact SHA-256

### `ctkat_verdict.csv` 컬럼 reference (legacy `run` compatibility)

`run` 명령이 emit하는 Valgrind×timing 호환 CSV다. asm/matrix/review가
없으므로 신규 CI의 canonical gate가 아니다. 신규 게이트는
`ctkat screen`의 evidence-v2 `screen_summary.*`와 `overall`을 사용한다.

| col | 이름 | 의미 |
|---|---|---|
| 1-2 | `project`, `harness` | 식별자 |
| 3-4 | `valgrind_status`, `valgrind_findings` | PASS / FAIL / ERROR / NONE + finding 개수 |
| 5-6 | `dudect_status`, `dudect_abs_t` | PASS / WARNING / FAIL / INSUFFICIENT / ERROR / NONE + protocol max \|t\| |
| 7 | `verdict` | CLEAN / STRUCTURAL_LEAK / SUSPECT / RISKY / CRITICAL / INCONCLUSIVE |
| 8-9 | `kat_status`, `kat_count` | E-1: PASS / FAIL / NONE + (있다면) expected_pattern으로 추출한 테스트 개수 |
| 10 | `dudect_validity` | valid / confounded / insufficient-power / environment-rejected / error / not-run |

컬럼 1-7은 backward-compat 보장 (`scripts/run_phase4.sh`의 awk `$7=verdict`
호환). 8-9는 E-1, 10은 timing-backend-v2에서 끝에 append.

### KEM structural path — `valid` / `invalid`

`ct.harnesses[].template: kem`은 기본적으로 `kem_decapsulation: valid`다.
즉 `crypto_kem_enc()`가 만든 정상 ciphertext를 `crypto_kem_dec()`에 넣고
Valgrind/Memcheck로 구조 CT를 본다. 이 모드는 정상 decapsulation path를
검사하지만, ML-KEM의 implicit-rejection / Fujisaki-Okamoto fallback path는
안 탄다.

FO/rejection path도 구조적으로 보고 싶으면 별도 하니스에
`kem_decapsulation: invalid`를 박는다. 이 모드는 정상 encapsulation 결과의
ciphertext 한 바이트를 뒤집고 decapsulation을 실행한다. 이후 dec 결과가 원래
enc shared secret과 같으면 하네스가 실패해서, invalid-path 하네스가 조용히
정상 path만 분석하는 일을 막는다.

```yaml
ct:
  harnesses:
    - name: kem_dec
      template: kem
      kem_decapsulation: valid
      header: api.h

    - name: kem_dec_fo
      template: kem
      kem_decapsulation: invalid
      header: api.h
```

`valid`/`invalid`는 Valgrind 구조 분석 축이고, 아래 `dudect.leak_target:
fo`는 timing 비교 축이다. 둘은 서로 대체가 아니라 보완 관계다.

### KEM timing axes — `sk` / `ct` / `fo` (Bundle D, K, M)

`template: kem` 하니스에 `leak_target: sk` (default), `leak_target: ct`,
또는 `leak_target: fo` (Bundle K) 설정. 세 모드는 직교 axis라 한 KEM
구현을 더 넓게 스크리닝하려면 yaml에 하니스 3개를 둔다. 이것도
동적 timing screen이지 absence proof는 아니다.

| `leak_target` | 측정 path | 고정 | 변화 | 잡는 leak |
|---|---|---|---|---|
| `sk` (기본) | **정상 dec** | 각 pool entry의 ct는 해당 sk에 매칭된 valid ct | class-0 fixed tuple pool vs class-1 random valid tuple pool | 정상 dec 경로의 sk-content dependent timing |
| `ct` | **정상 dec** | sk fixed 양 class | class-0 fixed valid-ct pool vs class-1 random valid-ct pool | 정상 dec 경로의 ct-content dependent timing |
| `fo` | **정상 ↔ FO** 비교 | sk fixed 양 class | paired valid-ct pool vs byte-corrupted invalid-ct pool | 정상 path와 FO fallback/implicit-rejection timing 차이 |

**Bundle M (F13/F14 audit fix)**: 이전 버전의 sk-leak은 양 class 모두
`rand_bytes(ct, ...)`로 ct를 random bytes로 채워 dec()가 매번 FO
fallback 경로로 떨어졌음 — 즉 README가 광고했던 "정상 dec 경로의
sk-dependent timing"이 아니라 실제로는 "FO rejection 경로의 sk-dependent
timing"을 측정한 셈. Bundle K에서 `leak_target: fo`를 별도로 추가하면서
sk-leak의 의미를 재점검했어야 했는데 빠뜨렸음. Bundle M에서 양 class에
valid ct를 `enc()`로 생성하도록 수정 → sk-leak이 진짜 정상 path를 측정.
Bundle M 이전 결과 (`dudect_summary.csv`의 |t| 값) 와 비교하려면 측정
경로 자체가 달라졌음을 감안할 것.

`0.5.0a1`의 timing-harness-v2는 여기서 한 번 더 갈아엎었다. 양 class pool을
측정 전에 만들고, measurement loop는 같은 `sk_work`/`ct_work` 주소로 같은
길이 복사만 한 뒤 dec를 딱 한 번 잰다. class-1-only keygen/enc와
per-iteration warm dec는 없다. setup 잔류 효과는 fixed target을 재는 별도
setup-placebo trace가 검증한다.

### ⚠️ ct-leak 모드의 본질적 한계

`leak_target: ct`는 **random sampling 기반의 fixed-vs-random** 검사. 그래서:

**✅ 잘 잡는 leak**:
- `if (ct[i] == X) slow_path()` — 흔한 ct 비트 패턴에 dependent
- ct 일부를 인덱스로 lookup table 접근
- ct 처리 중 분기 ≥ ~1%의 입력에 영향

**❌ 못 잡는 leak (희귀/adversarial ct trigger)**:
- **희귀한 ct 값**에서만 slow path 트리거 (e.g., `~2^-40` 확률)
- 50k 랜덤 샘플 중 한 번도 안 걸릴 가능성 높음
- 검출하려면 알고리즘 지식으로 특정 ct/test vector를 합성해야 함 — 본
  random-sampling harness 범위 밖

**즉 `leak_target: ct` PASS = "이 random-sampling class에서는 timing 차이를
못 봤다"이지 "ct-CT-safe"가 아님.**
알고리즘별 adversarial test vector, masking analysis 같은 별도 검사가 필요.

**KyberSlash는 별도 축이다.** KyberSlash류 문제는 secret-derived 값이
division operand로 들어가고, 일부 컴파일러/옵션/CPU에서 그 division latency가
입력 의존이 되는 경우다. `leak_target: ct` 랜덤샘플 PASS로 부재를 말할 수
없다. CT-KAT의 직접 대응은 `asm-scan` 후보 수집 + 사람 triage다. 이 repo의
positive control은 `examples/pqc_mlkem768/clean_kyberslash/poly.c`에서
PQClean ML-KEM의 reciprocal-multiply fix(`* 80635 >> 28`)를 되돌려
`poly_compress`/`poly_tomsg`에 `/KYBER_Q`를 복원한 것이다. Valgrind는
분기/주소 의존이 없어 PASS하지만, asm-scan은 emitted assembly의 `div/idiv`
후보를 잡는다. 단, asm-scan 자체는 operand taint를 증명하지 않으므로
`varlat-secret-risk` 판정은 코드/알고리즘 review가 붙은 triage 결과다.
즉 KyberSlash 판정은 Memcheck taint를 asm `div/idiv` operand에 연결한
결과가 아니라, taint-free asm 후보에 source triage를 붙인 결과다.

**❌ FO-fallback path 미커버 → `leak_target: fo` 사용**:
`leak_target: ct`는 `enc()`로 valid ct만 생성하므로 FO fallback / implicit
rejection 경로는 안 들어감. 이 경로에 거주하는 leak (예: 정상 path 대비
시간 차이로 ct invalidity가 누설)을 검출하려면 **`leak_target: fo`** 박을 것.
class 0/1의 paired valid/invalid ct pool을 측정 전에 만든다. 같은 sk와
동일 work-buffer 주소에서 dec timing을 비교하므로 정상 vs rejection 경로의
차이를 보되 per-iteration enc confound는 넣지 않는다.

```yaml
dudect:
  harnesses:
    - name: ml_kem_768_fo
      template: kem
      header: api.h
      leak_target: fo      # ← FO fallback path 검사
```

sk-leak / ct-leak / fo-leak 세 모드는 직교 axis — 한 KEM 구현을 더 넓게
보려면 3개 하니스를 두되, 결과는 각 하니스/입력 분포 기준으로 읽을 것.

### Signature timing axes — `sk` / `msg`

`template: sign`도 v2 pool/common-buffer/control 프로토콜을 쓴다.

| `sign_leak_target` | 고정 | 변화 |
|---|---|---|
| `sk` (기본) | message | fixed-key pool vs random valid-key pool |
| `msg` | secret key | fixed-message pool vs random-message pool |

portable template가 재는 경계는 full `crypto_sign_signature` API다. Falcon처럼
signature 길이/압축 cost가 변할 수 있으므로 모든 sample의 `output_length`를
기록하고 JSON manifest에 min/max/unique/variable을 남긴다. sampler core,
acceptance loop, encoding을 분리하려면 구현마다 ABI가 다르므로 각각
`template: generic`의 별도 function boundary와 별도 evidence row를 만든다.
full API 결과를 멋대로 “core signing cost”라고 부르는 건 금지다.

---

## CLI commands

```bash
# 전체 파이프라인 (build → kat → ct → dudect → report → verdict)
python -m ctkat run --config <ctkat.yaml> [--continue-on-kat-fail] [--no-crop]

# 통합 스크리닝 한 방 (build→kat→ct→ct-matrix→asm-scan→timing→triage→evidence v2)
python -m ctkat screen --config <ctkat.yaml> [--triage triage.yaml] [--family ML-DSA] [--asm-cc gcc --asm-cc clang]

# 각 단계 단독 실행
python -m ctkat ct       --config <ctkat.yaml>
python -m ctkat kat      --config <ctkat.yaml>
python -m ctkat dudect   --config <ctkat.yaml>  [--measurements N] [--seed VALUE|random] [--no-crop]

# 헤더 파일에서 함수 시그니처 + secret/public 역할 자동 추론
python -m ctkat infer --header path/to/api.h
python -m ctkat infer --project examples/toy_password
python -m ctkat infer --header api.h --function crypto_kem_dec

# Valgrind 로그 단일 파일 파싱 (디버깅용)
python -m ctkat parse path/to/valgrind.log

# 가변시간 명령 후보 스캔 — 단독 실행은 warn-only, screen은 evidence로 소비
python -m ctkat asm-scan --config <ctkat.yaml> [--opt -O0 --opt -Os ...] [--cc gcc --cc clang ...]
```

`asm-scan`: `ct.harnesses[].sources`를 여러 최적화 레벨(`-O0/-O1/-O2/-O3/-Os` + ct의 실제
`-O`)과 **여러 컴파일러**(`--cc` 반복, 기본 `gcc`)로 컴파일해 `objdump`로
`div/idiv/sdiv/udiv/…` 위치를 모으고, **어느 컴파일러 × 어느 빌드에서 나눗셈이
살아남나**를 `reports/ctkat_varlat_candidates.csv/json`에 적는다(CSV엔 `compiler`
와 `triage_hint` 컬럼, JSON엔 `scanned_compilers`·기계비교용 `matrix`·`errors`).
`triage_hint`는 판정이 아니라 리뷰 힌트다. 예를 들어 이 corpus의 KyberSlash
positive control은 `gcc -Os`와 `clang -O0`에서 `poly_compress` /
`poly_tomsg`의 `div/idiv`가 살아나며 `kyberslash-poly-review-secret-risk`
힌트로 남는다. 반대로 FIPS202/Keccak `shake128`/`shake256` 후보는
`keccak-rate-review-likely-public` 힌트로 남아 public triage 후보임을 빠르게
보여준다. 단일 컴파일러·단일 빌드만 보면 놓칠 수 있다. **taint 분석이 아니라**
소스 안 모든 나눗셈을 후보로 내므로(공개 나눗셈도 포함) 후보만으로 risk를
확정하지 않는다. 다만 `screen`은 미귀속 후보를 `needs-review`, 누락된 빌드
coverage를 `inconclusive`로 보존한다.
note의 "ct 스테이지가 놓침" 판정은 ct 빌드가 **같은 컴파일러**를 쓸 때만 성립하도록 조건부로 적는다
(asm-scan은 ct 빌드의 컴파일러를 모름). **exit 코드**: candidate 유무와 무관하게
`0`(warn-only). 요청한 컴파일러 중 **일부**가 PATH에 없으면 그 컴파일러만 건너뛰고
ERROR로 기록한 뒤 나머지로 계속한다(부분 결과, exit 0). 단 `objdump`가 없거나 요청한
컴파일러가 **하나도** 없으면 조용히 빈 결과로 exit 0 하지 않고 **config 에러로 exit
2**(fail-closed). 기본 Docker 이미지에는 `gcc`와 `clang`이 모두 설치되어
있다.
정밀 taint는 패치드 Valgrind 필요(미구현). 현재 구현은 멀티 최적화
`asm-scan` 후보 보고에 머문다.

```bash
# 컴파일러 × cflags Valgrind 매트릭스 — 단독 실행은 관찰용, screen evidence 입력
python -m ctkat ct-matrix --config <ctkat.yaml>
```

`ct-matrix`: 각 template 하니스를 `matrix:` 의 모든 빌드 설정(compilers × 이름붙은
cflags 조합; 기본 `gcc × debug/opt1/release/opt3/size`)으로 **재컴파일**해서 *같은* 구조적
CT(Valgrind/Memcheck) 검사를 돌리고, cell별 PASS/FAIL/ERROR를
`reports/ctkat_ct_matrix.csv`/`.json`에 적는다. 단독 `ct-matrix`는
`ctkat_verdict.csv`나 legacy `run` 게이트를 건드리지 않지만, `screen`은 이
artifact를 structural evidence로 소비한다. 목적은 "같은 소스인데 빌드 설정을
바꾸면 CT 판정이 달라지는가"를 보이는 것. 한 하니스가 빌드별로 다른 status를 내면
그걸 loud하게 표시한다. **exit 코드**: PASS/FAIL 분포와 무관하게
`0`(관찰 전용 — 어떤 빌드의 FAIL은 *데이터 포인트*지 도구 실패가 아님). 단 `ct` 하니스
없음 / 재컴파일할 template 하니스 없음 / combo 0개 / 컴파일러·`valgrind` 누락 / 모든
cell ERROR 면 **config·toolchain 에러로 exit 2**(fail-closed). Valgrind 필요 →
Linux/Docker 전용.

`matrix:` 섹션 스키마(생략하면 아래가 기본값):

```yaml
matrix:
  # 스윕할 컴파일러 (중복 제거; PATH command 이름만, '/' 불가). 기본 [gcc]
  compilers: [gcc, clang]
  # 이름붙은 cflags 조합. artifact의 combo = "{cc}_{이름}", 이름은 [A-Za-z0-9_-]+
  ct_cflags:
    debug:   [-O0, -g, -fno-inline, -fno-omit-frame-pointer]
    opt1:    [-O1, -g, -fno-omit-frame-pointer, -fno-lto]
    release: [-O2, -g, -fno-omit-frame-pointer, -fno-lto]
    opt3:    [-O3, -g, -fno-omit-frame-pointer, -fno-lto]
    size:    [-Os, -g, -fno-omit-frame-pointer, -fno-lto]
```

위 예시 = `compilers(2) × ct_cflags(5)` = harness당 10 combo. CSV의 `cflags`
컬럼엔 실제 플래그가 그대로 들어간다.

`screen`: 위 단계들(build → KAT → ct → ct-matrix → asm-scan → timing)을 **한
프로세스에서** 돌린 뒤, triage를 적용해 harness별 evidence v2를 산출하고
`reports/screen_summary.{csv,json,md}` + `screen_cells.csv`로 emit한다.
**`overall`은 코퍼스 빌더·마이그레이션·검증기가 모두 동일한
`ctkat/evidence.py` fold로 계산**한다. 상태는 `no-finding-observed` /
`risk-detected` / `needs-review` / `inconclusive` / `tool-error`다. 예전
9개 `verdict_class`는 `legacy_verdict_class`로만 남아 migration provenance에
쓰인다(정의는 `docs/corpus_schema.md`).
**exit 코드는 default-deny**: 모든 harness의 `overall`이
`no-finding-observed`인 경우에만 `0`이다. 미triage·review artifact 누락·불완전
스캔·검증되지 않은 timing·toolchain 문제는 `2` — 즉 `screen && deploy`는
사람이 triage하기 전 새 타깃을
통과시키지 않는다. `ct` 섹션 필수, `valgrind`/컴파일러/`objdump` 누락 시
toolchain 에러로 `2`. Valgrind 필요 → Linux/Docker 전용, 단일 서브커맨드보다
무겁다.

triage는 **파이프라인 config(ctkat.yaml)와 분리된** `triage.yaml`(사람 판단
레이어)로 준다 — ctkat.yaml은 재현 위해 frozen 유지:

```yaml
# triage.yaml
registry: docs/accepted_variable_time.md   # 선택; accepted-variable-time 레지스트리 경로 override
harnesses:
  kem_dec:
    varlat: public          # public | secret-risk | mixed | none | untriaged
    review: reviewed
    review_id: rvw-mlkem-evidence-v1
    note: "fips202 shake 나눗셈은 공개"
  sign:
    verdict: accepted-variable-time   # legacy 분류 bridge; headline 직접 override 아님
    review: pending                    # artifact 없이는 clean 승격 불가
```

수동 `accepted-variable-time` override는 “화이트리스트에 대충 추가”가 아니라,
optimized build의 parent-frame 귀속이나 SPHINCS+ public-output data flow처럼
registry에 넣으면 과허용되는 케이스를 노트와 함께 명시적으로 리뷰했다는 뜻이다.
특히 SPHINCS+의 `treehashx1` / `wots_gen_leafx1`는 함수명 registry에 넣지
않고, `examples/pqc_sphincs_sha2_128f_simple/triage.yaml`의 `sign` harness
data-flow note로만 받아들인다.

`reviewed`/`disputed`/`expired`는 `review_id`가 필수다. 코퍼스에서는 이 ID가
`docs/reviews/<review_id>.yaml`에 실제로 존재하고 정확한 target/harness를
scope에 포함하는지 CI가 확인한다. note 한 줄만 써놓고 reviewed라 우기는
경로는 막혀 있다.

`--no-crop`: `backend: experimental-first-order`의 5개 percentile cropping을
끄고 raw uncropped t-score만 사용한다. official backend는 upstream 102-test
family를 임의로 줄이지 않으므로 이 옵션을 config error로 거부한다.

`screen` 종료 코드:

- `0` — 모든 harness가 `overall=no-finding-observed`
- `2` — `risk-detected|needs-review|inconclusive|tool-error`
- `1` — 빌드/KAT 실패 등 파이프라인 자체 에러

`ctkat ct`, `ctkat kat`, `ctkat dudect` 단일 stage 서브커맨드는 yaml에
해당 섹션이 없을 때 모두 **exit 2** — 이전엔 `ct`/`kat`가 PASS인 척
exit 0을 던졌음 (F7/F8). CI는 `ctkat <stage> --config ... && deploy`
패턴으로 안전하게 게이팅 가능.

---

## Examples / Case studies

### Committed corpus snapshot

<!-- BEGIN CTKAT CORPUS SNAPSHOT -->
<!-- source: docs/corpus/corpus_summary.csv sha256=98bde62aae9b52644dd41a696465d250c93bbae7c38540324ddb7e5bcab87365; regenerate: python scripts/render_readme_corpus.py --write -->

`docs/corpus/corpus_summary.csv`에서 자동 생성한 committed snapshot (`sha256:98bde62aae9b`).

| family | target / harness | structural | asm / attribution | timing validity / signal | review | overall |
|---|---|---|---|---|---|---|
| ML-KEM | pqclean_mlkem512 / kem_dec | no-finding | candidate / public | not-run / not-run | reviewed (rvw-mlkem-evidence-v1) | no-finding-observed |
| ML-KEM | pqclean_mlkem512 / kem_dec_fo | no-finding | candidate / public | not-run / not-run | reviewed (rvw-mlkem-evidence-v1) | no-finding-observed |
| ML-KEM | pqclean_mlkem768 / kem_dec | no-finding | candidate / public | confounded / signal (raw FAIL, \|t\|=145.316) | reviewed (rvw-mlkem-evidence-v1) | inconclusive |
| ML-KEM | pqclean_mlkem768 / kem_dec_ct | not-run | not-run / not-applicable | insufficient-power / no-signal-observed (raw PASS, \|t\|=2.304) | reviewed (rvw-mlkem-evidence-v1) | inconclusive |
| ML-KEM | pqclean_mlkem768 / kem_dec_fo | no-finding | candidate / public | insufficient-power / no-signal-observed (raw PASS, \|t\|=2.103) | reviewed (rvw-mlkem-evidence-v1) | inconclusive |
| ML-KEM | pqclean_mlkem1024 / kem_dec | no-finding | candidate / public | not-run / not-run | reviewed (rvw-mlkem-evidence-v1) | no-finding-observed |
| ML-KEM | pqclean_mlkem1024 / kem_dec_fo | no-finding | candidate / public | not-run / not-run | reviewed (rvw-mlkem-evidence-v1) | no-finding-observed |
| ML-KEM | pqclean_mlkem768_kyberslash / kem_dec | no-finding | candidate / secret-risk | not-run / not-run | reviewed (rvw-kyberslash-seeded-v1) | risk-detected |
| ML-DSA | pqclean_mldsa44 / sign | finding | candidate / public | insufficient-power / no-signal-observed (raw PASS, \|t\|=1.153) | reviewed (rvw-mldsa-rejection-v1) | inconclusive |
| ML-DSA | pqclean_mldsa65 / sign | finding | candidate / public | insufficient-power / no-signal-observed (raw PASS, \|t\|=1.661) | reviewed (rvw-mldsa-rejection-v1) | inconclusive |
| ML-DSA | pqclean_mldsa87 / sign | finding | candidate / public | insufficient-power / no-signal-observed (raw PASS, \|t\|=1.748) | reviewed (rvw-mldsa-rejection-v1) | inconclusive |
| SPHINCS+ | pqclean_sphincs_sha2_128f_simple / sign | finding | candidate / public | insufficient-power / no-signal-observed (raw PASS, \|t\|=1.523) | reviewed (rvw-sphincs-public-state-v1) | inconclusive |
| Falcon | pqclean_falcon512 / sign | finding | candidate / unresolved | insufficient-power / no-signal-observed (raw PASS, \|t\|=1.590) | pending | inconclusive |
| synthetic | toy_lookup / leaky | finding | no-candidate / not-applicable | not-run / not-run | reviewed (rvw-toy-lookup-ground-truth-v1) | risk-detected |
| synthetic | toy_lookup / safe | no-finding | no-candidate / not-applicable | not-run / not-run | not-needed | no-finding-observed |
| synthetic | ct_matrix_flip / leaky | finding | no-candidate / not-applicable | not-run / not-run | not-needed | risk-detected |
| synthetic | ct_matrix_flip / safe | no-finding | no-candidate / not-applicable | not-run / not-run | not-needed | no-finding-observed |

재생성: `python scripts/render_readme_corpus.py --write`
<!-- END CTKAT CORPUS SNAPSHOT -->

이 표는 committed evidence schema v2 결과다. 과거 `timing FAIL + robust`
행은 이제 `confounded / signal / inconclusive`이고, power calibration이 없는
raw timing PASS도 `insufficient-power`라서 clean 근거로 쓰이지 않는다.
v1.2 원본과 결정론적 v2 migration snapshot은
`docs/corpus/archive/{v1.2,v2.0-from-v1.2}/` 및
`scripts/migrate_evidence_v1_to_v2.py`에 보존했다.

### 1. `toy_password` — secret-dependent early return

```c
int bad_compare(const uint8_t *secret, const uint8_t *guess, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (secret[i] != guess[i]) return 1;   // early return = leak
    }
    return 0;
}
int safe_compare(const uint8_t *secret, const uint8_t *guess, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= secret[i] ^ guess[i];
    return diff != 0;
}
```

결과: `bad_compare` → `SECRET_DEPENDENT_BRANCH` at `bad_compare.c:10` (HIGH). `safe_compare` → 0 findings.

### 2. `toy_lookup` — secret-indexed table access

```c
out[i] = sbox[secret[i]];   // leaky — address depends on secret
out[i] = sbox[i & 0xff] ^ secret[i];   // safe — index is the loop counter
```

결과: leaky → `SECRET_DEPENDENT_MEMORY_ACCESS` (HIGH, 휴리스틱으로 `VALUE_USE`에서 승격됨 — 함수명에 "lookup" 포함). safe → 0 findings.

### 3. `toy_dudect` — secret-dependent branch (statistical detection)

```c
int leaky_function(const uint8_t *secret, size_t len) {
    if (secret[0] >= 0x80) {
        for (int i = 0; i < 10000; i++) x = x * 17 + 3;
    }
    return ...;
}
```

현재 committed **legacy raw timing appendix** 기준(QEMU/Docker 환경):
- `leaky`: `|t| = 181.5`, **FAIL**
- `safe`: `|t| = 1.65`, **PASS**

`leaky` run은 zero-cycle sample drop이 커서 논문/리포트가 caveat를 같이
남긴다. raw positive-control 관찰값일 뿐 evidence-v2 `valid` 판정은 아니며,
실제 PQC timing 결론은 native x86_64의 A/A·power calibration 뒤에만 낸다.

### 4. `pqc_mlkem{512,768,1024}` — 실전 PQClean ML-KEM parameter sets

```bash
# 한 번만:
./scripts/fetch_pqclean.sh    # sparse-checkout으로 ML-KEM-768 + common 받기

# 검사:
PYTHONPATH=. python -m ctkat run --config examples/pqc_mlkem768/ctkat.yaml
```

현재 값은 이 절 위의 자동 생성 corpus snapshot을 기준으로 한다. 예전
QEMU `|t|=5.47` 표는 제거했으며, native 측정과 그 confound note를 포함한
CSV가 source of truth다.

ML-KEM-512/1024는 ML-KEM-768과 같은 valid/invalid decapsulation 구조
하니스를 사용한다. SPHINCS+-SHA2-128f-simple은 hash-based signature breadth
case로 포함하되, `treehashx1` / `wots_gen_leafx1` 함수 전체를 registry에
등록하지 않는다. `triage.yaml`은 `R`, `mhash`, `tree`, `idx_leaf`, intermediate
root가 signature/public-verification state로 declassified되는 이 `sign`
harness data flow에 한정해 `accepted-variable-time` override를 둔다.

### 5. `pqc_falcon512` — Falcon/FN-DSA feasibility target

Falcon-512 is present as a first-pass PQClean clean signing target. Its legacy
classification is `needs-analysis`; evidence v2 records `review=pending` and
`overall=inconclusive`, not an accepted-variable-time or clean row. The harness
taints `sk[1..]` because `sk[0]` is the public
format header and full-sk taint would create an immediate false branch finding.
Current Docker structural screening fails across gcc/clang debug/release cells,
with findings in private-key decode, private-key completion, Gaussian sampling,
and signature compression. Follow-up core/split probes show the important
boundary: after wrapper/decode noise is removed, taint from long-term key
material still reaches the Gaussian sampler, Bernoulli-exp path, floating-point
rounding, and signing acceptance loop. That is a correct structural signal, but
not by itself a timing-leak proof; accepting it would require a Falcon-specific
isochrony argument across the exact build. Treat Falcon as a `needs-analysis`
stress target and future-work boundary case, not as an `accepted-variable-time`
row.

---

## Findings from real-world testing (옵션 A)

PQClean ML-KEM-768 검사 중 발견된 것들 — 도구 진화의 출발점:

### 1. ML-KEM `sk` 구조에 public 데이터 박혀있음

PQClean ML-KEM의 `sk` 구조 (FIPS 203 §7.1):

```
[ s (secret 1152) | ek (PUBLIC 1184) | H(ek) (PUBLIC 32) | z (secret 32) ]
```

2400 바이트 중 **1216 바이트(50.7%)가 public**. `sk` 통째로 taint하면 dec 내부의 `unpack_pk` → `gen_at` → `rej_uniform` 흐름이 모두 tainted된 것처럼 보여 false positive 2건 발생.

**해결**: `HarnessConfig.secret_regions`로 진짜 secret 영역만 명시:

```yaml
secret_regions:
  - {offset: "0", length: "KYBER_INDCPA_SECRETKEYBYTES"}
  - {offset: "KYBER_SECRETKEYBYTES - KYBER_SYMBYTES", length: "KYBER_SYMBYTES"}
```

→ 이 하니스 기준으로 알려진 public-sk false positive를 피하고 PASS.

**교훈**: 알고리즘마다 `sk` 내부 구조가 다름. `secret_regions`는 “sk 전체
taint”보다 덜 거칠지만, offset/length 근거를 계속 유지해야 하는 수동 계약이다.

### 2. dudect timing 차이는 cache/environment artifact일 수 있음

초기 ML-KEM dec dudect 실험에서는 class 0(fixed sk)이 class 1(random sk +
매번 새 keypair)보다 빠르게 보이는 run이 있었다.

가설 검증: timing harness 수정해서 **양 class 모두 측정 직전 dummy dec 1회 실행** (cache state 균일화):

| 시나리오 | mean diff | \|t\| | batch max |
|---|---|---|---|
| Baseline | 478 ns | 9.25 | 7.31 |
| Seed 변경 + 30k | 389 ns | 20.09 | 9.78 |
| **+ Cache balance** | **208 ns** | **10.04** | **5.58** |

Cache balance 후 effect가 줄어든 관찰은, setup 작업(keypair 호출 등)이 cache
상태를 다르게 만들어 t-score에 섞일 수 있음을 보여준다. 이 숫자는 원인분해
증명이 아니라 하니스 설계 경고로 읽어야 한다.

**교훈**: dudect는 measurement environment에 매우 민감. setup 작업(keypair 호출 같은)이 cache 상태에 시스템적 영향을 줘서, secret 값과 무관한 효과가 t-score에 나타날 수 있음. KEM 전용 timing 템플릿은 이 균일화 단계를 포함해야 함.

### 3. -O0 / -O2 일관성

PQClean ML-KEM-768은 현재 configured ct-matrix cells에서 Valgrind PASS다.
이건 “이 하니스/빌드 셀에서 structural finding이 없다”는 관찰이지,
모든 최적화/플랫폼에서 새 leak이 생기지 않는다는 보장은 아니다.

---

## Limitations & recommended environment

### Dynamic analysis의 본질적 한계

- **Valgrind / dudect 둘 다 dynamic analysis** — 하네스가 실제로 실행한 경로만 검사. 실행 안 된 분기는 미검출.
- **KAT/CT 분리 권장** — 정확성과 부채널 안전성은 독립. 두 binary 따로 만들어서 각자 검증.
- **division/multiplication latency — Memcheck만으로는 미검출 (부분 완화: `ctkat asm-scan`)** — Memcheck는 분기와 메모리 주소 의존만 잡고 KyberSlash류 secret-dependent division latency는 잡지 못한다. 보조 수단으로 `ctkat asm-scan`이 소스를 여러 `-O`로 컴파일해 나눗셈 명령이 어느 빌드에서 살아남나 후보로 보고한다. 단독 명령은 warn-only지만 `screen`은 review 전까지 후보를 gating evidence로 보존한다(주의: taint 증명이 아니라 소스 내 모든 나눗셈을 후보로 냄). 정밀한 secret-taint 판정은 여전히 패치드 Valgrind나 별도 정적/알고리즘 분석 필요.
- **하네스가 cover하는 입력 분포 한계** — `rej_uniform` 같은 데이터 의존 분기는 통계적으로만 노출됨.

### 측정 환경 권장

| 시나리오 | 권장 환경 |
|---|---|
| ct (Valgrind) 검사 | Linux/Docker 컨테이너. timing보다 재현성은 높지만, 컴파일러/flags/하니스 경로에 의존 |
| official timing backend | **Native x86_64 Linux + rdtsc + 단일 CPU affinity**. QEMU는 raw trace만 보존하고 `environment-rejected` |
| timing screen on ARM mac | official backend 미지원. `backend: experimental-first-order` + `clock: monotonic`으로 진단은 가능하지만 non-decisional |
| 결과의 통계적 안정성 | `seed`를 바꿔가며 여러 번 실행해서 t-score 분포 확인. `batches` 분할 결과(`batch_t_max_abs`)가 클수록 환경 노이즈 큼 |

### 시스템 노이즈와 \|t\| 변동 (R3)

같은 yaml + 같은 seed라도 docker compose run을 두 번 돌리면 \|t\| 값은
런마다 ±10–20% 흔들린다 (OS 스케줄링, 캐시 상태, thermal throttling). PASS/
WARNING/FAIL 같은 status는 toy 케이스에선 안정적이지만 borderline 신호는
런마다 status가 바뀔 수도 있다. **두 run의 결과를 비교할 땐 exact \|t\|
값이 아니라 status와 order-of-magnitude를 비교할 것**. PQClean-backed KEM
하니스는 추가로 `crypto_kem_keypair/enc`가 OS entropy를 쓰기 때문에 sk/ct
자체도 매번 달라진다 (§"재현성 (seed)" 참고).

### 함수 속도 범위 (U4)

이 프레임워크는 **함수 1회 호출이 ~100ns ~ ~1ms 범위**에 들어가는
타겟에 맞춰져 있다.

- **너무 빠른 함수 (<100ns)**: rdtsc/monotonic 해상도 이하 측정이 많아져
  zero-cycle filter가 대량 drop → per-class drop 비대칭 경고가 자주 뜸
  (Bundle F/S2). 여러 호출을 batch해서 한 측정에 묶거나, 더 큰 입력으로
  호출 비용을 키우는 wrapper를 만들 것.
- **너무 느린 함수 (>1ms)**: `dudect.measurements`가 100k면 100초 이상,
  600s timeout이 깎아낼 수 있음. `dudect.timeout: 1800` 같이 늘리거나
  `dudect.measurements`를 줄일 것 (`--measurements 10000` CLI override
  로도 가능).

### 알고리즘별 고려사항

- **`sk` 내부에 public 데이터 박힌 알고리즘**: `secret_regions`로 명시 (예: ML-KEM, 일부 sign 알고리즘)
- **PQClean 네임스페이스화된 빌드**: `prefix: "PQCLEAN_FOO_CLEAN_"`로 매크로/함수명 prefix 처리
- **`crypto_declassify` 매크로 쓰는 알고리즘** (예: Classic McEliece): wrapper로 `VALGRIND_MAKE_MEM_DEFINED`에 매핑 가능

### 보안 모델 (yaml 신뢰 가정)

`build.argv`와 `kat.argv`는 shell 없이 실행되는 기본 경로다.
`build.command`/`kat.command`는 shell 문법이 꼭 필요한 trusted workflow용
escape hatch이며 `allow_shell: true`로 명시적으로 opt-in해야 한다. 0.1.x
legacy config는 현재 alpha에서 loud warning과 함께 한 번 더 허용하지만
stable 전 후속 minor에서 거부할 예정이다.

다운로드/외부 PR config에는 `execution_profile: untrusted`를 사용한다. 이
profile은 `allow_shell: true`가 있어도 shell-backed step을 거부한다. 다만
`argv`가 지정한 프로그램, compiler와 입력 C 코드 자체도 실행 가능한
공격면이므로 완전한 sandbox는 아니다. 신뢰할 수 없는 artifact는 disposable
container/VM 안에서 실행할 것.

### 도구 자체 한계

- **Finding 유형 휴리스틱 의존**: `MEMORY_ACCESS` vs `VALUE_USE` 구분은 스택 프레임 함수명 패턴 매칭 기반 (`memcpy`/`memmove`/`memset`/`strcpy`/`strncpy`/`bcopy` 같은 메모리 primitive + `*sbox*`/`*ttable*`/`*lookup*`/`*_table*` 같은 lookup 패턴). 라이브러리/내부 함수가 알려진 패턴 밖이면 `VALUE_USE`로 fallback. `_table` 같은 generic 패턴은 일부러 넓게 잡았는데 **보안 도구는 false negative보다 false positive를 선호**한다는 정책 — `verify_table` 처럼 무관한 이름도 잡힐 수 있으니 finding 위치는 사용자가 직접 확인 권장.
- **헤더 파서**: 정규식 기반. 함수 포인터 인자, 매크로로 만든 시그니처, 중첩 괄호, 복잡한 typedef는 **미지원이며 silently 미스매치**될 수 있음. PQClean/OpenSSL 같은 표준적 헤더는 대부분 OK. 비표준 헤더는 `ctkat infer` 결과를 yaml로 옮길 때 수동 확인 필수.
- **Secret inference**: 보수적 정책으로 키워드 매칭 안 되면 `unknown` 표시. `key`/`s`/`r` 같은 generic 이름은 의도적으로 제외.

---

## Legacy `run` verdict matrix

`run` 명령은 ct + raw timing 결과를 결합해 harness당 호환 verdict 1개를
산출한다. timing validity는 col 10으로 보존하고 non-valid timing은
`INCONCLUSIVE`로 강등하지만, asm attribution과 review artifact는 없으므로
evidence-v2 `overall` 대신 신규 배포 게이트로 사용하지 않는다.

| Valgrind | dudect | Verdict | 의미 |
|---|---|---|---|
| PASS | PASS | **CLEAN** | `run`의 두 layer에서 finding 없음 |
| FAIL | PASS / NONE | **STRUCTURAL_LEAK** | 구조적 finding 있음 — 통계 layer는 이 환경/분포에서 못 봄. **"LOW"가 아니라 "구조적 finding"이라는 이름이 정직함** (Bundle I U6 Option A 이전 라벨: `LOW_RISK`) |
| PASS / NONE | WARNING | **SUSPECT** | 약한 통계적 차이 (microarch state 또는 환경 포함) |
| PASS / NONE | FAIL | **RISKY** | 통계적으로 큰 차이, 단 구조 layer는 finding 없음 (microarch leak 또는 환경) |
| FAIL | WARNING | **RISKY** | 구조 + 약한 통계 |
| FAIL | FAIL | **CRITICAL** | 구조 + timing 신호가 같이 있음 — 우선 검토 대상 |
| ERROR (어느 한쪽) | * | **INCONCLUSIVE** | 한 stage가 완료되지 못함 (valgrind crash F2, manual binary sentinel 미흡 F5, dudect harness timeout/crash T6) — verdict 신뢰 불가 |
| * | * + KAT FAIL | **INCONCLUSIVE** | KAT 자체가 실패했으므로 분석은 잘못된 코드 위에서 돌아간 셈. `--continue-on-kat-fail`로 강행했을 때도 verdict는 INCONCLUSIVE로 떨어짐 (F11) |

이 라벨은 finding의 per-row `Severity` (HIGH/MEDIUM/LOW)와 의도적으로 단어가 다름 — finding 위험도와 통합 verdict를 시각적으로 구분하기 위함.

INCONCLUSIVE는 "안전하지 않다"는 뜻이 아니라 **"이 도구로는 판단할 수 없다"**는 뜻 — 사용자는 원인 (timeout? sentinel 누락? KAT FAIL?) 을 console 출력에서 확인하고 yaml/build를 고친 뒤 재실행해야 한다. CI는 INCONCLUSIVE를 FAIL과 동일하게 (exit 2) 취급한다.

**⚠ STRUCTURAL_LEAK은 무시해도 되는 게 아니다 (U6).** Bundle I 이전엔
`LOW_RISK`라 불렀는데 "LOW"가 "위험도 낮음 = 넘어가도 됨"으로 읽히는
오해가 잦아 rename. 실제 의미:

- Valgrind가 **구조적으로 confirmed**한 secret-dependent branch/memory
  access finding이 있다 (= 코드 자체에 secret이 control flow/주소
  계산에 영향을 줌).
- dudect가 **이 환경, 이 입력 분포에서** 측정 가능한 timing 차이를
  발견 못했다 (다른 micro-arch, adversarial 입력, FO-fallback 경로에선
  나타날 수 있음).

즉 STRUCTURAL_LEAK = "이 도구의 측정 layer로는 안 보이지만 코드 자체에는
leak이 있다". CI 게이트로 자동 통과시키지 말고 finding 위치를 직접 검토할 것.

**⚠ Backward-incompatible 변경**: 이전 `LOW_RISK` 라벨이 박힌 awk
스크립트나 외부 도구는 새 `STRUCTURAL_LEAK` 값으로 갱신 필요. verdict
CSV col 7 값이 변경됨.

---

## Acknowledgments

- **PQClean** (<https://github.com/PQClean/PQClean>) — ML-KEM, ML-DSA, and SPHINCS+ clean reference implementations under `examples/pqc_*`.
- **ctgrind** (Adam Langley) — Valgrind/Memcheck를 constant-time 검사에 응용한 원래 아이디어.
- **dudect** (Reparaz, Balasch, Verbauwhede) — revision
  `dc269651fb2567e46755cfb2a13d3875592968b5`의 `dudect.h`를 hash 검증해
  official statistical backend로 실행한다. CT-KAT의 측정 하니스까지 upstream
  dudect와 동일하다는 뜻은 아니다.

> **Note on historical drafts**
>
> 초기 설계 문서와 긴 audit 로그는 repo source of truth가 아니어서
> `.local_archive/`로 분리했다. 현재 동작의 source of truth는 본 README,
> `ctkat/` 코드, `tests/`, 그리고 `docs/README.md`에 나열된 활성 문서다.

---

## License

CT-KAT 자체는 MIT — [LICENSE](LICENSE). Vendored/derived PQClean과 dudect
자료는 각 원래 라이선스를 유지하며
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)에 revision, local
modification, tree hash를 기록한다.
