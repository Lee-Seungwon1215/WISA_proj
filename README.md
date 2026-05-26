# CT-KAT

KAT + Valgrind + dudect 기반 constant-time 검사 프레임워크.

C/C++ 암호 구현을 던지면 자동으로:

1. 빌드
2. KAT (Known Answer Test) — 정확성 확인
3. **Valgrind/Memcheck** — secret-tainted 값이 분기/메모리 주소 계산에 쓰였는지 (구조적 검사)
4. **dudect** — fixed-vs-random secret으로 실행 시간 분포를 Welch t-test로 비교 (통계적 검사)
5. CSV/JSON 리포트 + 통합 verdict 출력

세 단계 다 통과하면 `CLEAN`, 부분 실패면 `LOW_RISK`/`SUSPECT`/`RISKY`, 양쪽 다 실패면 `CRITICAL`.

> **⚠ PASS는 "constant-time"이 아니다.** verdict CLEAN은 *"이 프레임워크가 돌린 3개 layer가 leak을 못 잡았다"*는 뜻이지 *"이 코드는 안전하다"*가 아니다. 우리가 안 보는 것: power side-channel, EM, fault injection, formal verification, KyberSlash 류 adversarial-input. PASS를 받았다고 다른 분석 도구(masking analysis, power-trace, 정적 검증, 알고리즘별 adversarial test)를 건너뛰지 말 것. 자세한 한계는 §"Limitations & recommended environment" 참고.

```
$ python -m ctkat run --config examples/toy_password/ctkat.yaml
[CTKAT] Build: PASS
[CTKAT] Constant-Time Check: FAIL
                  Potential variable-time findings
┃ harness ┃ function    ┃ file:line        ┃ severity ┃ type                    ┃
│ bad     │ bad_compare │ bad_compare.c:10 │ HIGH     │ SECRET_DEPENDENT_BRANCH │
       Combined verdict (Valgrind + dudect)
┃ harness ┃ valgrind ┃ dudect ┃ |t| ┃ verdict  ┃
│ bad     │ FAIL     │ NONE   │ -   │ LOW_RISK │
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
- Apple Silicon 맥은 `platform: linux/amd64`로 강제해서 QEMU 에뮬레이션 — Valgrind 정상 동작.
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
│   └── pqc_mlkem768/           # real-world: PQClean ML-KEM-768
├── tests/                      # pytest unit tests (95+)
├── scripts/                    # dev.sh, run_check.sh, run_phaseN.sh, fetch_pqclean.sh
├── Dockerfile, docker-compose.yml
└── pyproject.toml
```

---

## Three-layer model

검사는 독립적인 세 층으로 구성:

```
[1] KAT — Correctness
    test vectors + roundtrip check
    "구현이 맞게 동작하나?"
         ↓
[2] Valgrind Memcheck — Structural CT
    VALGRIND_MAKE_MEM_UNDEFINED → secret-tainted value tracking
    "secret 값이 분기 또는 메모리 주소 계산에 쓰였나?"
         ↓
[3] dudect — Statistical Timing
    fixed-vs-random secret + Welch t-test + percentile cropping (max |t|)
    "secret 값에 따라 실행 시간 분포가 통계적으로 다른가?"
         ↓
[verdict] CLEAN / LOW_RISK / SUSPECT / RISKY / CRITICAL
```

각 층의 강점:

| 층 | 잡는 것 | 못 잡는 것 |
|---|---|---|
| KAT | 기능 정확성 | 부채널 위험 |
| Valgrind | 명백한 secret-dep branch, secret-indexed memory access | 명령어 latency 차이, microarchitectural side channel |
| dudect | 통계적 실행 시간 차이 (cache, branch predictor 영향 포함) | 정확한 코드 위치는 모름 (binary 차원의 평균) |

세 층을 모두 통과해야 비로소 안전 후보.

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

향후 작업: top-level `shared_cflags` 옵션 + 멀티 cflags 매트릭스 실행
(known_issues.md F9 #3 / #4, follow-up).

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
| 4.5 ~ 5.5 | WARNING | soft WARNING — 실제 leak 가능성은 절반 정도 |
| 5.5 ~ 10 | WARNING | confident WARNING — 진짜 신호 의심 |
| ≥ 10 | FAIL | FAIL (자릿수 차이 — 거의 noise 아님) |

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
  PQClean KEM 하네스에선 sk/ct 값 자체가 매번 달라짐.
- |t| 절대값이 run 간 ±10-20% 흔들리는 게 정상 (OS 스케줄링/캐시 효과 포함).
  PASS/WARNING/FAIL 상태와 자릿수만 비교.
- bit-identical 재현이 필요하면 PQClean `randombytes`를 xorshift로 교체하는
  링크-타임 interpose가 필요 (follow-up: known_issues.md R1 Option B).

합성 하네스(`toy_dudect`, `toy_kem_ct_leak`)는 위 영향 없음 — 그 쪽은 모두
xorshift PRNG로만 입력을 만든다.

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
| 7 | `verdict` | CLEAN / LOW_RISK / SUSPECT / RISKY / CRITICAL / INCONCLUSIVE |
| 8-9 | `kat_status`, `kat_count` | E-1: PASS / FAIL / NONE + (있다면) expected_pattern으로 추출한 테스트 개수 |

컬럼 1-7은 backward-compat 보장 (`scripts/run_phase4.sh`의 awk `$7=verdict`
호환). 8-9는 E-1에서 끝에 append.

### KEM leak axes — `sk` vs `ct` (Bundle D)

`template: kem` 하니스에 `leak_target: sk` (default) 또는 `leak_target: ct` 설정.
한 KEM 구현을 양 축으로 검증하려면 yaml에 하니스 2개 박음.

| `leak_target` | 고정 | 변화 | 잡는 leak |
|---|---|---|---|
| `sk` (기본) | ct random 양 class | class 0 fixed sk vs class 1 fresh sk | sk-content dependent timing (sk-indexed branch/lookup) |
| `ct` | sk fixed 양 class | class 0 fixed ct vs class 1 fresh ct via `enc()` | ct-content dependent timing (ct-indexed branch/lookup) |

### ⚠️ ct-leak 모드의 본질적 한계

`leak_target: ct`는 **random sampling 기반의 fixed-vs-random** 검사. 그래서:

**✅ 잘 잡는 leak**:
- `if (ct[i] == X) slow_path()` — 흔한 ct 비트 패턴에 dependent
- ct 일부를 인덱스로 lookup table 접근
- ct 처리 중 분기 ≥ ~1%의 입력에 영향

**❌ 못 잡는 leak (KyberSlash 류)**:
- **희귀한 ct 값**에서만 slow path 트리거 (e.g., `~2^-40` 확률)
- 50k 랜덤 샘플 중 한 번도 안 걸릴 가능성 높음
- 실제 KyberSlash 검출은 **adversarial ct 생성** (특정 polynomial 형태 만족
  하는 ct를 알고리즘 지식으로 합성) 필요 — 본 framework 범위 밖

**즉 `leak_target: ct` PASS = "흔한 ct-leak 면역"이지 "ct-CT-safe"가 아님.**
KyberSlash 류 검출은 별도 도구 (예: 알고리즘별 adversarial test vector,
masking analysis) 필요.

**❌ FO-fallback path 미커버 (U2 interim)**: `leak_target: ct`는 `enc()`로
**valid** ct를 생성해 두 class에 모두 정상 dec path를 태운다. KEM의 FO
fallback (잘못된 ct가 들어왔을 때 implicit rejection을 수행하는 경로) 안의
timing leak은 검출하지 못한다 — 알려진 일부 KEM 취약점이 이 fallback 경로에
거주하므로, "PASS"의 의미를 정상 dec path 내 ct-leak에 한정해서 읽을 것.
별도 `leak_target: fo` 모드는 known_issues.md U2 #1 follow-up.

---

## CLI commands

```bash
# 전체 파이프라인 (build → kat → ct → dudect → report → verdict)
python -m ctkat run --config <ctkat.yaml> [--continue-on-kat-fail] [--no-crop]

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
```

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

결과 (Bundle A/B 적용 후, monotonic clock, QEMU/Docker 환경):
- post-Bundle-A: mean diff ~3400 ns, `|t| = 156.7`, **FAIL**
- post-Bundle-B: mean diff ~4530 ns, `|t| = 192.3`, `cropped_at = 1.000`, **FAIL**

Bundle A의 언더플로우 clamp가 sub-resolution 0-cycle 측정값을 정리하고
Bundle B의 cropping이 추가로 noise를 잘라내면서 leak 감도가 +23% 향상됨.
`safe_function` 은 `|t| ≈ 0.34` (uncropped) 로 PASS 유지.

### 4. `pqc_mlkem768` — 실전 PQClean ML-KEM-768

```bash
# 한 번만:
./scripts/fetch_pqclean.sh    # sparse-checkout으로 ML-KEM-768 + common 받기

# 검사:
PYTHONPATH=. python -m ctkat run --config examples/pqc_mlkem768/ctkat.yaml
```

결과 (옵션 A 종합):

| 검사 | 결과 |
|---|---|
| ct (-O0) | PASS / CLEAN |
| ct (-O2) | PASS / CLEAN |
| dudect (monotonic clock, cache-balanced) | WARNING/FAIL borderline (\|t\|≈10) |
| **종합** | **구조적으로 깨끗, 통계적 borderline (환경 영향 의심)** |

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

→ False positive 0건, PASS.

**교훈**: 알고리즘마다 `sk` 내부 구조가 다름. PQClean이 `crypto_declassify` 매크로 정의해놓고도 ML-KEM에서 안 쓰는 건 "사용자가 알아서 분리해라"는 정책. 우리 `secret_regions`가 그 정책에 정확히 부합.

### 2. dudect timing 차이의 절반은 cache state artifact

ML-KEM dec dudect 검사 결과: class 0(fixed sk)이 class 1(random sk + 매번 새 keypair)보다 평균 ~400 ns 빠름. `|t|=20`, FAIL.

가설 검증: timing harness 수정해서 **양 class 모두 측정 직전 dummy dec 1회 실행** (cache state 균일화):

| 시나리오 | mean diff | \|t\| | batch max |
|---|---|---|---|
| Baseline | 478 ns | 9.25 | 7.31 |
| Seed 변경 + 30k | 389 ns | 20.09 | 9.78 |
| **+ Cache balance** | **208 ns** | **10.04** | **5.58** |

Cache balance로 effect 약 50% 감소 → **timing 차이의 절반은 cache state artifact** (class 1의 keypair() 호출이 cache를 어지럽힘). 잔존 effect는 추가 cache balance 부족 또는 QEMU 영향 의심.

**교훈**: dudect는 measurement environment에 매우 민감. setup 작업(keypair 호출 같은)이 cache 상태에 시스템적 영향을 줘서, secret 값과 무관한 효과가 t-score에 나타날 수 있음. KEM 전용 timing 템플릿은 이 균일화 단계를 포함해야 함.

### 3. -O0 / -O2 일관성

PQClean ML-KEM-768은 `-O0` 빌드와 `-O2` 빌드 모두에서 Valgrind PASS. 컴파일러 최적화가 새 leak을 만들지도, 기존 finding을 마스킹하지도 않음. 도구가 양 환경에서 일관된 판단을 내림.

---

## Limitations & recommended environment

### Dynamic analysis의 본질적 한계

- **Valgrind / dudect 둘 다 dynamic analysis** — 하네스가 실제로 실행한 경로만 검사. 실행 안 된 분기는 미검출.
- **KAT/CT 분리 권장** — 정확성과 부채널 안전성은 독립. 두 binary 따로 만들어서 각자 검증.
- **division/multiplication latency 미검출** — Memcheck는 분기와 메모리 주소 의존만 잡음. 일부 CPU의 secret-dep division/multiplication latency는 별도 정적 분석 필요.
- **하네스가 cover하는 입력 분포 한계** — `rej_uniform` 같은 데이터 의존 분기는 통계적으로만 노출됨.

### 측정 환경 권장

| 시나리오 | 권장 환경 |
|---|---|
| ct (Valgrind) 검사 | Docker 컨테이너 (어디서든 OK) — 결과는 환경 무관 |
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
| PASS | PASS | **CLEAN** | 양쪽 다 깨끗 |
| FAIL | PASS / NONE | **LOW_RISK** | 구조적 finding만 — 통계는 안 잡힘 (false positive 가능성) |
| PASS / NONE | WARNING | **SUSPECT** | 약한 통계적 차이 (microarch state 의심) |
| PASS / NONE | FAIL | **RISKY** | 통계적으로 명확한 차이, 단 구조는 깨끗 (microarch leak 또는 환경) |
| FAIL | WARNING | **RISKY** | 구조 + 약한 통계 |
| FAIL | FAIL | **CRITICAL** | 양쪽 다 명확 — 우선 수정 대상 |
| ERROR (어느 한쪽) | * | **INCONCLUSIVE** | 한 stage가 완료되지 못함 (valgrind crash F2, manual binary sentinel 미흡 F5, dudect harness timeout/crash T6) — verdict 신뢰 불가 |
| * | * + KAT FAIL | **INCONCLUSIVE** | KAT 자체가 실패했으므로 분석은 잘못된 코드 위에서 돌아간 셈. `--continue-on-kat-fail`로 강행했을 때도 verdict는 INCONCLUSIVE로 떨어짐 (F11) |

이 라벨은 finding의 per-row `Severity` (HIGH/MEDIUM/LOW)와 의도적으로 단어가 다름 — finding 위험도와 통합 verdict를 시각적으로 구분하기 위함.

INCONCLUSIVE는 "안전하지 않다"는 뜻이 아니라 **"이 도구로는 판단할 수 없다"**는 뜻 — 사용자는 원인 (timeout? sentinel 누락? KAT FAIL?) 을 console 출력에서 확인하고 yaml/build를 고친 뒤 재실행해야 한다. CI는 INCONCLUSIVE를 FAIL과 동일하게 (exit 2) 취급한다.

**⚠ LOW_RISK는 무시해도 되는 게 아니다 (U6).** 라벨의 "LOW"가 "위험도
낮음 = 넘어가도 됨"으로 읽히기 쉽지만 실제 의미는 다음과 같다:

- Valgrind가 **구조적으로 confirmed**한 secret-dependent branch/memory
  access finding이 있다 (= 코드 자체에 secret이 control flow/주소
  계산에 영향을 줌).
- dudect가 **이 환경, 이 입력 분포에서** 측정 가능한 timing 차이를
  발견 못했다 (다른 micro-arch, adversarial 입력, FO-fallback 경로에선
  나타날 수 있음).

즉 LOW_RISK = "이 도구의 측정 layer로는 안 보이지만 코드 자체에는 leak이
있다". CI 게이트로 자동 통과시키지 말고 finding 위치를 직접 검토할 것.
라벨 이름 자체를 `STRUCTURAL_LEAK`으로 바꿀지 여부는 known_issues.md U6
Option A로 남아 있음.

---

## Acknowledgments

- **PQClean** (<https://github.com/PQClean/PQClean>) — ML-KEM-768 reference implementation. `examples/pqc_mlkem768/` 안 `clean/` / `common/` 디렉토리.
- **ctgrind** (Adam Langley) — Valgrind/Memcheck를 constant-time 검사에 응용한 원래 아이디어.
- **dudect** (Reparaz, Balasch, Verbauwhede) — fixed-vs-random Welch t-test 기반 timing leak 검출.

> **Note on the original design spec**
>
> `docs/design_archive/ctkat_cursor_framework_extended.md` 는 프로젝트가 처음 출발할 때 사용한 **원본 설계 문서**입니다. 구현이 그 spec을 그대로 따르지 않고 일부 변경되었습니다 (verdict 라벨, CSV 컬럼, `secret_regions` API, 분류기 whitelist 등). 이 문서는 **historical reference**로만 보존되며, **현재 동작의 source of truth는 본 README + `ctkat/` 코드 + `tests/`** 입니다. 자세한 운용 규칙은 `docs/design_archive/README.md` 참조.

---

## License

MIT — see [LICENSE](LICENSE). PQClean 부분은 원래 CC0 라이센스 그대로 유지.
