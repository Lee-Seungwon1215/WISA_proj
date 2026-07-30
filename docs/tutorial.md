# CT-KAT — "내 함수에 timing screen 걸어보기" 튜토리얼

`infer` 서브커맨드와 README의 yaml 참조만으로도 가능하지만, 처음 yaml을
쓰는 사용자가 한 번 따라가면 좋은 30-line 워크스루.

## 시나리오

내 라이브러리에 다음 함수가 있다고 가정:

```c
// include/secret_compare.h
int secret_compare(const uint8_t *secret, const uint8_t *guess, size_t len);
```

이 구현에서 fixed-vs-random timing 차이가 보이는지 1차 스크리닝하고 싶다.
기본 backend는 pinned official dudect C engine이고, CT-KAT은 raw timing
trace 생성과 validity 판단을 담당한다.

## 1. PRNG로 채우는 가장 단순한 yaml

```yaml
project:
  name: my_lib
  language: c
  root: .

build:
  argv: ["make"]
  workdir: .
  expected_artifacts:
    - lib/libmy.a            # build가 실제로 만들었는지 검증 (F10)

dudect:
  enabled: true
  backend: official-dudect  # 기본값; x86_64 only
  measurements: 50000
  warmup: 1000
  batches: 10
  clock: auto                # 환경에 맞게 rdtsc / monotonic 선택
  seed: 0xC0FFEE
  timeout: 600
  workdir: .

  harnesses:
    - name: secret_compare
      template: generic
      extra_headers: [secret_compare.h]
      include_dirs: [include]
      sources: [src/secret_compare.c]
      function: secret_compare
      return_type: int
      args: [secret, guess, "sizeof(secret)"]
      buffers:
        - {name: secret, size: "16", role: secret}
        - {name: guess,  size: "16", role: public}
```

**해설**:

- `args`는 C 호출 그대로의 식. 버퍼 이름과 sizeof 표현 그대로 들어감.
- `buffers[i].role` — `secret`은 class 0/1 분기에서 fixed 또는 random
  으로 채워짐. `public`은 매 호출 같은 값. `output`은 출력 버퍼 (호출 후
  Valgrind 관점에서 결과 보호용).
- `dudect.timeout` 미설정 시 600s default. 한 함수 호출이 비싼 경우 늘릴 것.
- generic official backend는 calibration/analysis 두 trace를 만든다.
  KEM/sign v2는 이 target pair를 기본 3 process/seed로 반복하고 physical
  control trace도 실행한다.
- upstream minimum은 zero filter 뒤 class 0 sample 10,000개 초과다.

## 2. 실행

```bash
$ python -m ctkat dudect --config ctkat.yaml
```

출력의 핵심:

```
==> Generate timing harness: secret_compare
==> Run timing calibration trace: secret_compare (discarded by protocol)
==> Run timing analysis trace: secret_compare
   backend=official-dudect-dc269651 max-test=crop[37] |t|=12.4 [FAIL]
   validity=insufficient-power
```

- `n0`/`n1`: clock/AUX filter 후 클래스별 sample 수. raw/drop count는
  summary와 protocol CSV에서 확인한다.
- official backend는 uncropped first-order 1개, crop 100개, second-order 1개
  중 max `|t|`를 고르고 `|t| > 10`이면 raw FAIL이다.
- `validity`는 raw signal과 별개다. generic target의 physical A/A와
  positive-control power artifact가 없으면 기본 `insufficient-power`다.

## 3. 결과 파일

- `reports/dudect_summary.csv` — 통계·validity 요약 (42개 컬럼)
- `reports/dudect_raw_timings.csv` — analysis raw trace
- `reports/dudect_calibration_timings.csv` — crop threshold용 discarded trace
- `reports/dudect_protocol_timings.csv` — KEM/sign 모든 target/control process,
  seed/effect/AUX/drop reason
- `reports/dudect_backend_report.json` — 102개 검정 전체, host manifest,
  validity 사유, A/A budget, power curve, MDE, trace hash/seed

여기서 PASS는 **raw timing threshold 결과**일 뿐 evidence-v2의
`timing_validity=valid`를 뜻하지 않는다. backend 자체의 synthetic A/A와
effect curve는 `docs/calibration/timing_backend_v2.json`에 있지만 target
하니스·물리 host control은 아니다. 따라서 `screen`에서는 기본적으로
`insufficient-power`가 되어 clean 근거로 쓰이지 않는다.

## 4. raw FAIL 또는 invalid timing이 떴을 때

**a) validity부터 확인**: `confounded`, `environment-rejected`,
`insufficient-power`라면 raw FAIL도 target leak 결론이 아니다.
`validity_reasons`에 적힌 affinity/QEMU/drop/harness control 문제를 먼저
해결한다.

**b) per-class drop 비대칭 경고 확인** (F4/S2): console에
"zero-cycle filter asymmetric" 또는 AUX migration 경고가 떴다면 한 클래스의 slow tail로
편향된 표본. 호스트가 너무 느리거나 함수가 너무 빠를 가능성.

**c) 102개 test와 tau 보기**: summary의 max row만 보지 말고
`dudect_backend_report.json`에서 uncropped/cropped/second-order 중 어디서
신호가 났는지 확인한다.

**d) native single-CPU process로 반복**: Linux에서는 예를 들어
`taskset -c 0 python -m ctkat dudect ...`로 실행한다. QEMU 결과는 자동
reject된다.

**e) experimental backend 비교가 필요하면 명시적 opt-in**:
`backend: experimental-first-order`에서만 Cohen's d와 `--no-crop`을 쓸 수
있다. 이 결과는 official protocol 결과로 부르면 안 된다.

**f) KEM/sign control manifest 보기**:
`harness_protocol.aa_controls`, `setup_placebo_controls`,
`positive_power_curve`, `minimum_detectable_effects` 중 어디서 gate가
깨졌는지 확인한다. A/A/placebo 실패는 setup confound, positive power 실패는
검출력 부족이다. 둘을 같은 “타이밍 애매함”으로 뭉개지 않는다.

## 5. 다음 단계 — legacy 결합 verdict

dudect만으로는 한쪽 측면 — Valgrind ct 검사도 yaml에 같이 넣으면
combined verdict (CLEAN / STRUCTURAL_LEAK / SUSPECT / RISKY / CRITICAL /
INCONCLUSIVE)가 나옴. 이 `run` verdict는 호환용이며 timing validity는
fail-closed로 반영하지만 asm-scan과 review를 포함하지 않는다. 신규 자동 게이트에는 다음 `screen`
evidence v2를 쓴다. CT 자동 모드의 보일러플레이트는
`examples/toy_dudect/ctkat_combined.yaml` 참고.

## 6. 한 방에 — `ctkat screen`

ct + ct-matrix + asm-scan + dudect를 **한 명령**으로 돌리고 harness별
layer evidence와 `overall`(`no-finding-observed` / `risk-detected` /
`needs-review` / `inconclusive` / `tool-error`)을
`reports/screen_summary.{csv,json,md}`로 뽑는다:

```bash
python -m ctkat screen --config examples/pqc_mlkem768/ctkat.yaml --triage triage.yaml
```

asm-scan 후보가 public인지 secret-risk인지 등 **사람 판단**은 파이프라인
config(ctkat.yaml)와 분리된 `triage.yaml`에 적는다(README §screen 참고).
최종 review에는 `review`와 `review_id`가 필요하며 note만으로는 clear되지
않는다. default-deny: `overall=no-finding-observed`만 exit 0, 나머지는 exit
2다. generic timing은 caller-defined setup을 자동 대칭화할 수 없어
`insufficient-power`다. KEM/sign v2도 native single-CPU 환경, 3-repeat
일관성, A/A/placebo, positive power, seeded randomness를 모두 통과하기
전에는 exit 2다. Valgrind 필요 → Linux/Docker.

## 자주 빠지는 함정

- **secret_regions 설정이 작으면 silent 부분 검사**: ML-KEM의 sk는 2400
  바이트지만 `length: 32`로 적으면 32바이트만 taint됨. Bundle F의 F6
  coverage probe가 <50% 발견 시 yellow warning, fix하지 않으면 결과가
  부정확.
- **PQClean randombytes strong symbol을 같이 link**: v2의 weak seeded
  interpose가 가려져 runtime manifest가 `external-or-none`이 되고
  `confounded`다. dudect harness sources에서는 `common/randombytes.c`를 빼고,
  구조/Valgrind harness에는 그대로 둔다.
- **manual binary mode 사용 시**: `ct.require_sentinel: true` + binary
  stdout에 `CTKAT-HARNESS-RAN: <name>` 박는 것 권장 (F5). /bin/true도
  silent PASS되는 fail-open 회피.
- **official backend를 ARM/QEMU에서 결론으로 사용**: ARM native에서는
  upstream engine이 build되지 않고, QEMU x86_64는 raw trace를 남겨도
  `environment-rejected`다. target 결론은 native x86_64에서 낸다.

## See also

- `README.md` — 모든 yaml 필드 + evidence v2 설명
- `docs/corpus_schema.md` — layer enum, overall fold, migration contract
- `docs/calibration/` — official backend synthetic A/A, effect curve, parity
- `examples/toy_dudect/ctkat_combined.yaml` — ct + dudect 같이 돌리는 예제
- `examples/pqc_mlkem768/` — PQClean ML-KEM-768 실전 yaml
