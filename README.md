# CT-KAT

KAT, Valgrind/Memcheck, asm-scan, ct-matrix, dudect를 묶어 쓰는
constant-time **스크리닝** 프레임워크.

C/C/C++ 암호 구현을 던지면 설정된 하니스에 대해:

1. 빌드
2. KAT (Known Answer Test) — 정확성 확인
3. **Valgrind/Memcheck** — secret-tainted 값이 분기/메모리 주소 계산에 쓰였는지 (구조적 검사)
4. **ct-matrix** — compiler × cflags별로 구조적 CT 결과가 바뀌는지 확인
5. **asm-scan** — emitted assembly에서 `div/idiv` 같은 variable-latency 후보 수집
6. **dudect** — fixed-vs-random class의 실행 시간 분포를 Welch t-test로 비교
7. CSV/JSON/Markdown 리포트 + triage 기반 verdict 출력

`screen`의 `verdict_class`가 현재 논문/코퍼스의 기준이다. 예전 `run` 명령은
Valgrind+dudect 결합 verdict(`CLEAN`, `STRUCTURAL_LEAK`, `SUSPECT`, `RISKY`,
`CRITICAL`)를 계속 제공하지만, asm-scan/ct-matrix/triage까지 포함한 최종
판정은 아니다.

> **⚠ PASS/CLEAN/robust는 "constant-time 증명"이 아니다.** 이 도구가
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

전제: Docker Desktop이 깔려 있고 실행 중.

```bash
# 1. 컨테이너에 진입
./scripts/dev.sh

# 2. 컨테이너 안에서:
PYTHONPATH=. python -m ctkat run --config examples/toy_password/ctkat.yaml
PYTHONPATH=. pytest tests -v
```

또는 일회성 실행:

```bash
docker compose run --rm ctkat-dev bash -c \
    "PYTHONPATH=. python -m ctkat run --config examples/toy_password/ctkat.yaml"
```

처음 한 번은 도커 이미지 빌드에 5~10분 (Apple Silicon은 x86_64 에뮬레이션). 두 번째부터는 캐시.

---

## Why Docker

- **Valgrind는 macOS에서 동작 안 함** (특히 ARM/최신 OS). 리눅스 컨테이너 필수.
- Apple Silicon 맥은 `platform: linux/amd64`로 강제해서 QEMU 에뮬레이션 — 구조 분석은 돌릴 수 있지만, dudect timing 숫자는 native x86_64보다 약하다.
- 호스트 작업 디렉토리를 `/workspace`에 마운트하므로 호스트에서 편집해도 컨테이너가 즉시 봄.

---

## Project structure

```
WISA/
├── ctkat/                      # framework package
│   ├── cli.py                  # typer CLI (run / ct / kat / dudect / infer / parse)
│   ├── config.py               # pydantic yaml schema
│   ├── builder.py              # build/KAT shell wrapper
│   ├── valgrind_runner.py
│   ├── valgrind_parser.py      # finding extraction + heuristic re-classification
│   ├── harness_generator.py    # Jinja2 → C harness (Valgrind side)
│   ├── timing_harness_generator.py   # Jinja2 → C harness (dudect side)
│   ├── dudect_runner.py
│   ├── statistics.py           # Welch t-test + batch stability
│   ├── verdict.py              # Valgrind × dudect → combined verdict
│   ├── header_parser.py        # C header → function signatures
│   ├── secret_infer.py         # PQC profile + name heuristic
│   ├── qemu_detect.py
│   ├── report.py
│   └── templates/
│       ├── harness_generic.c.j2 / harness_kem.c.j2 / harness_sign.c.j2
│       └── timing_generic.c.j2 / timing_kem.c.j2
├── examples/
│   ├── toy_password/           # bad_compare vs safe_compare (Phase 0~2)
│   ├── toy_dudect/             # leaky_function vs safe_function (Phase 4)
│   ├── toy_lookup/             # secret-indexed S-box vs constant-index
│   ├── pqc_mlkem512/           # PQClean ML-KEM-512 + valid/invalid KEM paths
│   ├── pqc_mlkem768/           # PQClean ML-KEM-768 + valid/invalid KEM paths
│   ├── pqc_mlkem1024/          # PQClean ML-KEM-1024 + valid/invalid KEM paths
│   ├── pqc_mlkem768_kyberslash/# ML-KEM with KyberSlash /KYBER_Q positive control
│   ├── pqc_mldsa44/            # PQClean ML-DSA-44 attribution/registry case
│   ├── pqc_mldsa65/            # PQClean ML-DSA-65 attribution/registry case
│   ├── pqc_mldsa87/            # PQClean ML-DSA-87 attribution/registry case
│   ├── pqc_sphincs_sha2_128f_simple/ # SPHINCS+ public-output attribution case
│   └── pqc_falcon512/          # Falcon/FN-DSA needs-analysis boundary target
├── tests/                      # pytest regression suite
├── scripts/                    # dev.sh, run_check.sh, run_phaseN.sh, fetch_pqclean.sh
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
[5] dudect — Statistical Timing
    fixed-vs-random secret + Welch t-test + percentile cropping (max |t|)
    "설정한 두 class의 실행 시간 분포가 통계적으로 다른가?"
         ↓
[triage] public / secret-risk / accepted-variable-time / needs-analysis
         ↓
[verdict_class] robust / varlat-secret-risk / build-sensitive-ct / ...
```

각 층의 역할:

| 층 | 잡는 것 | 못 잡는 것 |
|---|---|---|
| KAT | 기능 정확성 | 부채널 위험 |
| Valgrind | secret-tainted branch, secret-indexed memory access | 명령어 latency 차이, 실행 안 된 경로, power/EM |
| ct-matrix | 빌드별 structural verdict 변화 | 왜 변했는지의 보안 의미 |
| asm-scan | `div/idiv` 등 variable-latency 명령 후보 | operand가 secret인지 자동 증명하지 못함 |
| dudect | 설정한 두 class 사이의 timing 차이 | 정확한 코드 위치, rare trigger, noisy/QEMU 환경 |
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

build:
  command: "make clean && make"
  workdir: .
  expected_artifacts:          # (E-1) 빌드가 생산해야 할 파일들. rc=0인데
    - build/harness_foo        # 빠진 게 있으면 build FAIL. unset 시 legacy
    - build/harness_bar        # exit-code-only 동작 + 1회 warning.

# Optional. 없으면 KAT 단계 스킵.
kat:
  command: "./test_kat"
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
  measurements: 100000
  warmup: 1000
  batches: 10                  # batch stability 분할 수
  clock: auto                  # auto (기본, 환경 감지) | monotonic | rdtsc (x86 only)
  seed: 0xC0FFEE               # null이면 매번 랜덤 시드 + 로그에 기록
                               # ⚠ PQClean-backed KEM 하네스(template: kem)는
                               # crypto_kem_keypair/enc가 OS entropy(getrandom)을
                               # 쓰기 때문에 이 seed로 재현되지 않음. 자세한 건
                               # "재현성 (seed)" 섹션 참고.
  threshold_warning: 4.5       # |t| 임계값
  threshold_fail: 10.0
  timeout: 600                 # (E-1) per-harness wall-clock ceiling. 초과 시
                               # TimeoutExpired → status=ERROR → verdict
                               # INCONCLUSIVE. Python traceback이 나가지 않음.
  bonferroni_correct: false    # (G/R2) true면 임계값을 sqrt(N_cutoffs)≈2.24
                               # 배 스케일 — multi-cutoff cropping의 Type-I
                               # inflation 상쇄. 보수적 calibration 원할 때만.
  workdir: .
  generated_dir: ./_generated_dudect
  compiler:
    cc: gcc                    # gcc | clang
    # -fno-lto는 측정 정밀도에 중요: LTO를 켜면 컴파일러가 외부 링크 함수의
    # body까지 보고 "return값 안 쓰니까 호출 elide"를 결정할 수 있음.
    cflags: [-O2, -g, -fno-omit-frame-pointer, -fno-lto]
  harnesses:
    - name: bar
      template: generic        # generic | kem
      extra_headers: [api.h]
      include_dirs: [include]
      sources: [src/foo.c]
      # generic 전용:
      function: bar_func
      return_type: int
      args: [secret, "sizeof(secret)"]
      buffers:
        - {name: secret, size: "16", role: secret}
      # kem 전용 (template: kem일 때):
      header: api.h
      prefix: "PQCLEAN_FOO_CLEAN_"
      kem_decapsulation: valid  # valid | invalid. invalid = FO/rejection 구조 경로

report:
  output_dir: ./reports
  csv: ctkat_report.csv
  json: ctkat_report.json
```

`ct.harnesses[*].binary` (수동) ↔ `template` (자동)은 **상호 배타**. 둘 중 하나만.

수동 모드는 사용자 책임 영역이라 프레임워크가 binary 안에서 무슨 일이 일어나는지 모름 — `binary: /bin/true`도 "0 findings → PASS"로 통과되어 버린다 (F5). E-2부터는 `ct.require_sentinel: true`를 박으면 binary가 stdout에
`CTKAT-HARNESS-RAN: <harness-name>`을 출력해야 PASS, 없으면 status=ERROR
→ verdict INCONCLUSIVE. examples의 `toy_password/harness/harness_*.c`가
이 컨벤션의 reference. 자동 모드(template)는 자체적으로 target 함수를
호출하므로 sentinel 검사 스킵.

---

## dudect 측정 강화 (Bundle A / B / C / D)

기본 동작이 dudect 원본 (Reparaz et al. 2017) 프로토콜에 정합되도록
measurement primitives + 통계 레이어 모두 보강. 사용자가 켜는 옵션 ㄴ —
기본 ON이 권장 동작.

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

| 항목 | 내용 |
|---|---|
| rdtsc 직렬화 | `clock=rdtsc` 모드에서 `_mm_lfence` + `__rdtscp` + `_mm_lfence`. OOO/speculation으로 측정 명령이 timed region 밖으로 새는 것 방지 |
| compiler 배리어 | `CTKAT_USE(ret)` 매크로로 비-void 리턴값 materialize. `-fno-lto` 기본값과 함께 외부 링크 함수 호출 elide 방어 |
| class 라벨 균형 | xorshift64의 상위 비트 (`>>32 & 1`) 사용 — LSB는 분포 약함 |
| 언더플로우 clamp | `(t1 < t0) ? 0 : t1-t0`. TSC skew/clock anomaly로 인한 uint64 wrap 방지 |

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

### 통계 layer (Python 측)

| 항목 | 내용 |
|---|---|
| zero-cycle filter | parse 단계에서 cycles=0 (언더플로우 sentinel + ns-해상도 floor) drop. 1% 초과 시 전체 warning |
| per-class drop 비대칭 warning (Bundle F, F4/S2) | class별 drop rate를 추적해서 어느 한쪽이 5% 초과 + 두 rate의 gap이 5% 초과면 별도 warning. 살아남은 샘플이 한 클래스의 slow tail로 편향되어 Welch t-score를 왜곡할 수 있음 |
| percentile cropping | cutoff `[1.0, 0.99, 0.95, 0.90, 0.75]`에서 각각 Welch t-test, **max \|t\|** 채택. dudect 원본의 multi-cutoff scan 정신 따름 |
| batch t-score는 비-cropping | 환경 안정성 측정용이라 raw 신호 유지 |
| secret_regions coverage probe (Bundle F, F6) | `template: kem/sign`이고 `secret_regions`가 설정된 하니스에 한해, 자동 생성 단계에서 별도 sentinel 프로그램을 잠시 컴파일·실행해 `sum(secret_regions.length)`와 `{prefix}CRYPTO_SECRETKEYBYTES`를 실제 컴파일러에서 평가. <50%면 yellow warning (sk 대부분을 public으로 취급 중 — yaml typo 의심). probe 컴파일/실행 실패는 yellow note만, blocking X |
| 효과 크기 (Bundle G, S3) | 모든 t-score 결과에 Cohen's d 동반 (CSV col 21). pooled-SD 정확 버전, sign 유지. 같은 \|t\|=5라도 d=0.2 (작은 leak + 큰 n)과 d=2.0 (큰 leak + 작은 n)이 구별됨 |
| multi-cutoff calibration (Bundle G, R2) | percentile cropping은 5개 cutoff에서 max \|t\|를 채택하므로 H0 하 Type-I 비율이 단일 Welch 대비 약간 inflate된다. `dudect.bonferroni_correct: true`를 박으면 threshold가 `sqrt(N_cutoffs)`≈2.24만큼 더 보수적으로 스케일됨. default False — 대부분의 문헌이 "단일-test 4.5/10.0" 기준이라 사용자가 혼란을 안 겪게 |

#### multi-cutoff calibration guide (R2)

cropping 5개 cutoff 중 max \|t\|를 채택하면 nominal보다 false-positive
비율이 inflate된다 (대략 1.5-2배 수준, IID 가우시안 noise 기준의 회귀
테스트로 추적 중). 실용 해석 가이드:

| \|t\| | 단일-test 의미 | multi-cutoff (default) 의미 |
|---|---|---|
| < 4.5 | PASS | PASS (noise 영역) |
| 4.5 ~ 5.5 | WARNING | 약한 신호 — seed/반복/native 재측정 권장 |
| 5.5 ~ 10 | WARNING | 강한 의심 — 환경 노이즈와 실제 timing 후보를 같이 검토 |
| ≥ 10 | FAIL | 큰 신호 — 그래도 원인 attribution과 native 확인 필요 |

엄격한 family-wise α 보존이 필요하면 `dudect.bonferroni_correct: true`
박기. 그러면 threshold 자체가 ≈2.24배 올라가서 4.5→10.06, 10.0→22.36이
되니까 "단일-test 4.5/10.0과 동등한 보수성"이 multi-cutoff에서도 유지됨.

### 재현성 (seed)

`dudect.seed`는 **자동 생성 하네스의 xorshift64 PRNG**만 제어함. 구체적으로:

| 부분 | seed로 재현됨? |
|---|---|
| `template: generic`의 `rand_bytes()`로 채우는 secret/public 버퍼 | ✅ 예 |
| `toy_kem_ct_leak` 등 합성 KEM 하네스의 PRNG-기반 ct 생성 | ✅ 예 |
| `template: kem`에서 PQClean `crypto_kem_keypair()` 호출 결과 (sk-leak 모드 setup + class 1 매 반복, ct-leak 모드 setup) | ❌ **아니오** |
| `template: kem`에서 PQClean `crypto_kem_enc()` 호출 결과 (ct-leak 모드 setup + class 1 매 반복) | ❌ **아니오** |

이유: PQClean의 `common/randombytes.c`는 `getrandom()` / `/dev/urandom`을
직접 호출함 (OS entropy). yaml `seed`는 그 레이어에 닿지 않음.

**실용적 함의**:
- `dudect_raw_timings.csv` 두 run 사이 bit-identical diff를 기대하지 말 것 —
  PQClean KEM 하네스에선 sk/ct 값 자체가 매번 달라짐 (legacy 동작).
- |t| 절대값이 run 간 ±10-20% 흔들리는 게 정상 (OS 스케줄링/캐시 효과 포함).
  PASS/WARNING/FAIL 상태와 자릿수만 비교.

합성 하네스(`toy_dudect`, `toy_kem_ct_leak`)는 위 영향 없음 — 그 쪽은 모두
xorshift PRNG로만 입력을 만든다.

**`seed: 0` 금지** (F16). `ct.seed`와 `dudect.seed` 둘 다 config 로드
단계에서 `0` 입력을 거부한다. 이유: 생성된 C 하네스의 xorshift64는
`state=0`이면 영구적으로 0만 뱉기 때문에 템플릿이 내부적으로
`seed ? seed : 0xC0FFEE` swap을 박아둠. swap 자체는 의미적으로 필요한
방어지만, 사용자가 `seed: 0`을 yaml에 박으면 Python 로그는 `0x0`을
출력하고 실제 실행 바이너리는 `0xC0FFEE`를 쓰게 되어 두 레이어가
silent로 어긋난다. validator가 그걸 막는다. 다른 값이 필요하면
`seed: 1` 이상을 박거나, `dudect.seed: null`(랜덤 + 로그 출력)을 쓰면 됨.

### 결정론적 PQClean dudect — `randombytes` interpose (Bundle J, R1 Option B)

Bundle J부터 timing_kem 하네스가 자기 자신의 `randombytes(uint8_t *buf,
size_t len)`을 **weak symbol**로 emit한다. xorshift PRNG (CTKAT_SEED 기반)
로 buf를 채우는 구현. 사용자가 yaml `sources:`에서 PQClean의
`common/randombytes.c`를 **빼면** 우리 weak 정의가 유일 정의가 되어
`crypto_kem_keypair` / `crypto_kem_enc`의 모든 randomness가 시드 결정론적
이 된다 — `dudect_raw_timings.csv`가 bit-identical (modulo R3 시스템 노이즈).

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
하니까 우리 weak 정의는 무시됨 (= legacy OS entropy 동작). backward-
compat 보장. GCC/Clang 기준 — Windows MSVC의 weak symbol 시맨틱은
다르므로 현재 지원하지 않음 (§Windows MSVC caveat 참고).

### `dudect_summary.csv` 컬럼 reference

| col | 이름 | 의미 |
|---|---|---|
| 1-2 | `project`, `harness` | 식별자 |
| 3-4 | `n0`, `n1` | 클래스별 sample 수 (cropping 후) |
| 5-6 | `mean0`, `mean1` | 클래스별 평균 cycle / ns |
| 7-8 | `var0`, `var1` | 클래스별 variance |
| 9-10 | `t_score`, `abs_t_score` | max-cropped t-score |
| 11 | `status` | PASS / WARNING / FAIL — **max-cropped 기준** |
| 12-14 | `batch_t_mean`, `batch_t_max_abs`, `batches` | 배치 안정성 |
| 15 | `cropped_at` | max \|t\|를 만든 cutoff (e.g., `0.95`). cropping 꺼짐이면 빈 칸 |
| 16-17 | `t_score_uncropped`, `abs_t_score_uncropped` | cutoff=1.0의 raw t-score (diagnostic, cropping 부작용 확인용) |
| 18 | `raw_n_total` | Bundle F (S1): zero-filter 적용 전 C 하니스가 emit한 row 수. `measurements - raw_n_total`이 0 이상이면 하니스가 일부 측정을 누락. ERROR-status row는 0 |
| 19-20 | `dropped_zero_n0`, `dropped_zero_n1` | Bundle F (S1): zero-cycle filter가 클래스별로 떨어뜨린 수. `n0 = (raw_n0 - dropped_zero_n0)` 식. 두 값이 비대칭하면 sample bias 의심 (F4/S2 console warning과 같이 봄) |
| 21 | `cohens_d` | Bundle G (S3): 표준화 효과 크기 = `(mean1 - mean0) / pooled_SD`. t-score는 sample 크기에 같이 비례하지만 Cohen's d는 표본수에 무관 — "leak 자체가 얼마나 큰가"를 답함. 부호 유지(양수 = class 1이 느림). Cohen 1988 기준: \|d\|<0.2 trivial, ~0.5 medium, ≥0.8 large. ERROR row는 0.0 |

컬럼 1-14는 backward compatibility 보장 (외부 awk 스크립트 호환). 15-17은
Bundle B diagnostic 컬럼, 18-20은 Bundle F (S1) raw-count 컬럼, 21은
Bundle G (S3) 효과 크기. 모두 항상 끝에 append되므로 awk-by-position
파서는 안 깨짐.

### `ctkat_verdict.csv` 컬럼 reference (Bundle E-1 갱신)

`run` 명령이 emit하는 통합 verdict CSV — CI의 canonical gate.

| col | 이름 | 의미 |
|---|---|---|
| 1-2 | `project`, `harness` | 식별자 |
| 3-4 | `valgrind_status`, `valgrind_findings` | PASS / FAIL / ERROR / NONE + finding 개수 |
| 5-6 | `dudect_status`, `dudect_abs_t` | PASS / WARNING / FAIL / ERROR / NONE + max-cropped \|t\| |
| 7 | `verdict` | CLEAN / STRUCTURAL_LEAK / SUSPECT / RISKY / CRITICAL / INCONCLUSIVE |
| 8-9 | `kat_status`, `kat_count` | E-1: PASS / FAIL / NONE + (있다면) expected_pattern으로 추출한 테스트 개수 |

컬럼 1-7은 backward-compat 보장 (`scripts/run_phase4.sh`의 awk `$7=verdict`
호환). 8-9는 E-1에서 끝에 append.

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
| `sk` (기본) | **정상 dec** (양 class 모두 valid ct를 `enc()`로 생성) | ct는 각 class의 sk에 매칭된 valid ct | class 0 sk_fixed vs class 1 fresh sk_random | 정상 dec 경로에서 sk-content dependent timing (sk-indexed branch/lookup) |
| `ct` | **정상 dec** (valid ct만 사용) | sk fixed 양 class | class 0 fixed ct vs class 1 fresh ct via `enc()` | 정상 dec 경로에서 ct-content dependent timing |
| `fo` | **정상 ↔ FO** 비교 | sk fixed 양 class | class 0 valid ct (`enc()`) vs class 1 random/invalid ct | 정상 path와 FO fallback path 사이의 timing 차이 (rejection-side leak) |

**Bundle M (F13/F14 audit fix)**: 이전 버전의 sk-leak은 양 class 모두
`rand_bytes(ct, ...)`로 ct를 random bytes로 채워 dec()가 매번 FO
fallback 경로로 떨어졌음 — 즉 README가 광고했던 "정상 dec 경로의
sk-dependent timing"이 아니라 실제로는 "FO rejection 경로의 sk-dependent
timing"을 측정한 셈. Bundle K에서 `leak_target: fo`를 별도로 추가하면서
sk-leak의 의미를 재점검했어야 했는데 빠뜨렸음. Bundle M에서 양 class에
valid ct를 `enc()`로 생성하도록 수정 → sk-leak이 진짜 정상 path를 측정.
Bundle M 이전 결과 (`dudect_summary.csv`의 |t| 값) 와 비교하려면 측정
경로 자체가 달라졌음을 감안할 것.

매크로의 cache-balance warm step도 같은 family로 수정 (F14): 이전엔
warm dec가 항상 random ct로 호출되어 FO path로 burn-in 됐는데, 측정 dec
와 동일 (ct, sk) pair로 warm해서 cache state가 실제로 "just-ran-the-
measured-path"가 되도록 정정.

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

**❌ FO-fallback path 미커버 → `leak_target: fo` 사용 (Bundle K, U2 #1)**:
`leak_target: ct`는 `enc()`로 valid ct만 생성하므로 FO fallback / implicit
rejection 경로는 안 들어감. 이 경로에 거주하는 leak (예: 정상 path 대비
시간 차이로 ct invalidity가 누설)을 검출하려면 **`leak_target: fo`** 박을 것.
class 0 = 매 iteration 새 valid ct (enc()로 생성), class 1 = random/invalid
ct (FO fallback 강제). 같은 sk_fixed 위에서 dec timing 비교 → 정상 vs
rejection 경로의 timing 차이가 검출됨.

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

---

## CLI commands

```bash
# 전체 파이프라인 (build → kat → ct → dudect → report → verdict)
python -m ctkat run --config <ctkat.yaml> [--continue-on-kat-fail] [--no-crop]

# 통합 스크리닝 한 방 (build→kat→ct→ct-matrix→asm-scan→dudect→triage→verdict_class)
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

# 가변시간 명령(정수 나눗셈 등) 후보 스캔 — warn-only, verdict 무관
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
소스 안 모든 나눗셈을 후보로 내므로(공개 나눗셈도 포함) verdict엔 절대 섞지 않는다.
note의 "ct 스테이지가 놓침" 판정은 ct 빌드가 **같은 컴파일러**를 쓸 때만 성립하도록 조건부로 적는다
(asm-scan은 ct 빌드의 컴파일러를 모름). **exit 코드**: candidate 유무와 무관하게
`0`(warn-only). 요청한 컴파일러 중 **일부**가 PATH에 없으면 그 컴파일러만 건너뛰고
ERROR로 기록한 뒤 나머지로 계속한다(부분 결과, exit 0). 단 `objdump`가 없거나 요청한
컴파일러가 **하나도** 없으면 조용히 빈 결과로 exit 0 하지 않고 **config 에러로 exit
2**(fail-closed). 기본 Docker 이미지엔 `gcc`만 있으므로 `--cc clang`은 clang 설치 후.
정밀 taint는 패치드 Valgrind 필요(미구현). 현재 구현은 멀티 최적화
`asm-scan` 후보 보고에 머문다.

```bash
# 컴파일러 × cflags Valgrind 매트릭스 — 관찰 전용, verdict 무관 (Phase C)
python -m ctkat ct-matrix --config <ctkat.yaml>
```

`ct-matrix`: 각 template 하니스를 `matrix:` 의 모든 빌드 설정(compilers × 이름붙은
cflags 조합; 기본 `gcc × debug/opt1/release/opt3/size`)으로 **재컴파일**해서 *같은* 구조적
CT(Valgrind/Memcheck) 검사를 돌리고, cell별 PASS/FAIL/ERROR를
`reports/ctkat_ct_matrix.csv`/`.json`에 적는다. **이건 별도 산출물이고
`ctkat_verdict.csv`나 `run` 게이트를 절대 건드리지 않는다(관찰 전용).** 목적은 "같은
소스인데 빌드 설정을 바꾸면 CT 판정이 달라지는가"를 보이는 것. 한 하니스가 빌드별로
다른 status를 내면 그걸 loud하게 표시한다. **exit 코드**: PASS/FAIL 분포와 무관하게
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

`screen`: 위 단계들(build → KAT → ct → ct-matrix → asm-scan → dudect)을 **한
프로세스에서** 돌린 뒤, triage를 적용해 harness별 `verdict_class`를 산출하고
`reports/screen_summary.{csv,json,md}` + `screen_cells.csv`로 emit한다.
**`verdict_class`는 코퍼스 빌더(`scripts/build_corpus_table.py`)와 동일한
classifier(`ctkat/verdict_class.py`)로 계산** — 도구 출력과 논문 코퍼스가 어긋날
수 없다. taxonomy: `robust` / `ct-clean-untriaged` / `ct-clean-asm-incomplete` /
`varlat-secret-risk` / `build-sensitive-ct` / `accepted-variable-time` /
`needs-analysis` / `ct-leak` / `tool-problem` (정의는 `docs/corpus_schema.md`).
**exit 코드는 default-deny**: `verdict_class`가 `robust` 또는
`accepted-variable-time`이고, dudect가 WARNING/FAIL/ERROR가 아니며, ct/KAT가
완료된 경우에만 `0`이다. 미triage·불완전 스캔·timing warning·toolchain
문제는 `2` — 즉 `screen && deploy`는 사람이 triage하기 전 새 타깃을
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
    varlat: public          # public | secret-risk | none | untriaged
    note: "fips202 shake 나눗셈은 공개"
  sign:
    verdict: accepted-variable-time   # 선택; verdict_class 수동 override (도메인 triage)
```

수동 `accepted-variable-time` override는 “화이트리스트에 대충 추가”가 아니라,
optimized build의 parent-frame 귀속이나 SPHINCS+ public-output data flow처럼
registry에 넣으면 과허용되는 케이스를 노트와 함께 명시적으로 리뷰했다는 뜻이다.
특히 SPHINCS+의 `treehashx1` / `wots_gen_leafx1`는 함수명 registry에 넣지
않고, `examples/pqc_sphincs_sha2_128f_simple/triage.yaml`의 `sign` harness
data-flow note로만 받아들인다.

`--no-crop`: dudect percentile cropping (기본 ON) 끄고 raw uncropped t-score만
사용. 외부 dudect 구현과 수치 비교 / cropping 부작용 디버깅용. 평상시엔 그대로 둠.

종료 코드:

- `0` — 모든 검사 PASS
- `2` — finding 발견, dudect FAIL/WARNING, 또는 verdict=INCONCLUSIVE (E-1)
- `1` — 빌드/KAT 실패 등 파이프라인 자체 에러

`ctkat ct`, `ctkat kat`, `ctkat dudect` 단일 stage 서브커맨드는 yaml에
해당 섹션이 없을 때 모두 **exit 2** — 이전엔 `ct`/`kat`가 PASS인 척
exit 0을 던졌음 (F7/F8). CI는 `ctkat <stage> --config ... && deploy`
패턴으로 안전하게 게이팅 가능.

---

## Examples / Case studies

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

현재 committed timing appendix 기준(QEMU/Docker 환경):
- `leaky`: `|t| = 181.5`, **FAIL**
- `safe`: `|t| = 1.65`, **PASS**

`leaky` run은 zero-cycle sample drop이 커서 논문/리포트가 caveat를 같이
남긴다. 큰 toy 신호를 보여주는 positive control로는 충분하지만, 실제 PQC
timing 결론은 native x86_64에서 재확인해야 한다.

### 4. `pqc_mlkem{512,768,1024}` — 실전 PQClean ML-KEM parameter sets

```bash
# 한 번만:
./scripts/fetch_pqclean.sh    # sparse-checkout으로 ML-KEM-768 + common 받기

# 검사:
PYTHONPATH=. python -m ctkat run --config examples/pqc_mlkem768/ctkat.yaml
```

현재 corpus에서 읽는 요약:

| 검사 | 결과 |
|---|---|
| ct-matrix | configured cells에서 PASS |
| asm-scan | FIPS202/Keccak division 후보는 public으로 triage |
| dudect | QEMU/Docker에서 WARNING (`|t|=5.47`) |
| screen/corpus | `robust`, 단 timing warning은 native 확인 권장 |

ML-KEM-512/1024는 ML-KEM-768과 같은 valid/invalid decapsulation 구조
하니스를 사용한다. SPHINCS+-SHA2-128f-simple은 hash-based signature breadth
case로 포함하되, `treehashx1` / `wots_gen_leafx1` 함수 전체를 registry에
등록하지 않는다. `triage.yaml`은 `R`, `mhash`, `tree`, `idx_leaf`, intermediate
root가 signature/public-verification state로 declassified되는 이 `sign`
harness data flow에 한정해 `accepted-variable-time` override를 둔다.

### 5. `pqc_falcon512` — Falcon/FN-DSA feasibility target

Falcon-512 is present as a first-pass PQClean clean signing target and corpus
`needs-analysis` boundary row, not as an accepted-variable-time row. The harness
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
- **division/multiplication latency — Memcheck verdict로는 미검출 (부분 완화: `ctkat asm-scan`)** — Memcheck는 분기와 메모리 주소 의존만 잡고 KyberSlash류 secret-dependent division latency는 verdict에 안 나타남. 보조 수단으로 `ctkat asm-scan`이 소스를 여러 `-O`로 컴파일해 나눗셈 명령이 어느 빌드에서 살아남나 **warn-only 후보**로 보고한다(주의: taint 증명이 아니라 소스 내 모든 나눗셈을 후보로 냄, verdict 무관). 정밀한 secret-taint 판정은 여전히 패치드 Valgrind나 별도 정적/알고리즘 분석 필요.
- **하네스가 cover하는 입력 분포 한계** — `rej_uniform` 같은 데이터 의존 분기는 통계적으로만 노출됨.

### 측정 환경 권장

| 시나리오 | 권장 환경 |
|---|---|
| ct (Valgrind) 검사 | Linux/Docker 컨테이너. timing보다 재현성은 높지만, 컴파일러/flags/하니스 경로에 의존 |
| dudect 검사 | **Native x86_64 Linux + rdtsc** 권장. Apple Silicon + Docker는 QEMU 에뮬레이션이라 timing 신뢰도 떨어짐 |
| dudect on ARM mac | `clock: monotonic` 사용 (yaml 기본값). 정성적 비교는 가능, 절대적 결론은 native에서 확인 |
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

ctkat은 `build.command`, `kat.command` 같은 **사용자가 직접 적은 셸 명령**을 `subprocess`에 `shell=True`로 그대로 넘김. 즉 yaml 파일은 **실행권한과 동등**으로 취급됨:

- 신뢰할 수 없는 출처의 yaml(외부 PR, 다운로드한 데모 등)을 자동 실행 X
- CI에서 외부 PR을 자동으로 `ctkat run` 시키지 X
- `; rm -rf /` 같은 명령이 박혀있어도 ctkat은 막지 않음 — yaml 작성자가 책임

이건 도구가 "사용자 빌드 시스템을 호출하는 wrapper" 본질상 어쩔 수 없는 trade-off임. 진짜로 untrusted yaml을 받아야 한다면 ctkat 호출을 sandbox(docker 격리, seccomp 등) 안에서 돌릴 것.

### 도구 자체 한계

- **Finding 유형 휴리스틱 의존**: `MEMORY_ACCESS` vs `VALUE_USE` 구분은 스택 프레임 함수명 패턴 매칭 기반 (`memcpy`/`memmove`/`memset`/`strcpy`/`strncpy`/`bcopy` 같은 메모리 primitive + `*sbox*`/`*ttable*`/`*lookup*`/`*_table*` 같은 lookup 패턴). 라이브러리/내부 함수가 알려진 패턴 밖이면 `VALUE_USE`로 fallback. `_table` 같은 generic 패턴은 일부러 넓게 잡았는데 **보안 도구는 false negative보다 false positive를 선호**한다는 정책 — `verify_table` 처럼 무관한 이름도 잡힐 수 있으니 finding 위치는 사용자가 직접 확인 권장.
- **헤더 파서**: 정규식 기반. 함수 포인터 인자, 매크로로 만든 시그니처, 중첩 괄호, 복잡한 typedef는 **미지원이며 silently 미스매치**될 수 있음. PQClean/OpenSSL 같은 표준적 헤더는 대부분 OK. 비표준 헤더는 `ctkat infer` 결과를 yaml로 옮길 때 수동 확인 필수.
- **Secret inference**: 보수적 정책으로 키워드 매칭 안 되면 `unknown` 표시. `key`/`s`/`r` 같은 generic 이름은 의도적으로 제외.

---

## Three-layer verdict matrix

`run` 명령은 ct + dudect 결과를 결합해 harness당 verdict 1개 산출:

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
- **dudect** (Reparaz, Balasch, Verbauwhede) — fixed-vs-random Welch t-test 기반 timing leak 검출.

> **Note on historical drafts**
>
> 초기 설계 문서와 긴 audit 로그는 repo source of truth가 아니어서
> `.local_archive/`로 분리했다. 현재 동작의 source of truth는 본 README,
> `ctkat/` 코드, `tests/`, 그리고 `docs/README.md`에 나열된 활성 문서다.

---

## License

MIT — see [LICENSE](LICENSE). PQClean 부분은 원래 CC0 라이센스 그대로 유지.
