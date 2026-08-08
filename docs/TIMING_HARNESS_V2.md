# Timing harness v2 protocol

`TIME-001`의 구현 계약이다. 통계 backend가 아니라 **target을 어떻게 준비하고
물리적으로 재는지**를 고정한다. 적용 대상은 `template: kem`과
`template: sign`; caller-defined `generic` setup은 자동으로 이 계약을
만족한다고 가정하지 않는다.

## Target trace

모든 process는 독립된 role/repeat seed를 받는다. process 안에서도 class label,
pool selection, target `randombytes`는 서로 다른 PRNG state를 쓴다.

```text
generate class-0 pool
generate class-1 pool
warm both pools symmetrically

for each measurement:
    class <- label PRNG
    index <- selection PRNG
    copy selected inputs to the same-address work buffers
    barrier
    AUX0, t0 <- clock
    target(work buffers)
    t1, AUX1 <- clock
    sink outputs
    retain, or label clock-anomaly / cpu-migration
```

keygen, encapsulation, random-message construction은 measurement loop에 없다.
target mode의 timed region에는 target call만 있다.

## Axes

| template/axis | class 0 | class 1 | 공통 |
|---|---|---|---|
| KEM `sk` | fixed valid `(sk, ct)` tuple pool | random valid paired tuple pool | common `sk_work`, `ct_work` |
| KEM `ct` | fixed valid-ct pool | random valid-ct pool | fixed sk, common buffers |
| KEM `fo` | valid-ct pool | paired byte-corrupted ct pool with exact rejection-key witness | fixed sk, common buffers |
| sign `sk` | fixed valid-sk pool | random valid-sk pool | fixed message, common buffers |
| sign `msg` | fixed-message pool | random-message pool | fixed sk, common buffers |

sign template의 portable boundary는 full `crypto_sign_signature` API다. signature
길이를 sample마다 기록한다. sampler/acceptance loop/encoding core는
implementation-specific generic harness와 별도 evidence row로 분리한다.

## Physical controls

같은 generated binary, process boundary, clock, parser, target call을 쓴다.

| role | setup data | timed target data | 기대 |
|---|---|---|---|
| `aa` | label과 무관하게 class-0 pool | label과 무관하게 동일 분포 | `|t| < aa_abs_t_limit` |
| `setup-placebo` | 실제 target axis처럼 class-dependent copy 후 같은 work buffer를 fixed data로 정규화 | fixed data/common-work 주소 | setup/cache 잔류 무신호 |
| `positive` | label과 무관하게 class-0 pool | 동일 target + class 1 clock-tick delay | class 1이 느린 방향의 effect별 detection curve |

positive delay는 RDTSCP이면 cycle, monotonic이면 ns 단위의 요청값이다. 요청값을
효과 크기라고 가정하지 않고 실제 mean delta와 검출률을 artifact에 기록한다.
A/A variance와 `power_alpha`, `target_power`로 각 run의 normal-approximation
nominal sensitivity를 함께 계산한다. 기존 artifact 필드명은
`minimum_detectable_effects`지만 target trace 분산으로 계산한 정식 MDE나
achieved-power 추정치가 아니며, no-signal target을 그 값으로 bound하지 않는다.
별도의 `positive_detection_effects_at_target_power`는 실제 directional gate
`t <= -positive_abs_t_threshold`에 A/A standard error를 대입한
`(positive_abs_t_threshold + z(target_power)) * SE` 진단값이다. 이것도
host/A/A 기반 계획 보조값일 뿐 target trace의 MDE나 achieved power가 아니다.

## Validity gate

다음 순서로 fail closed 한다.

1. malformed/unaccounted row → `error`
2. QEMU, Linux multi-CPU affinity, 과도/비대칭 clock·migration drop →
   `environment-rejected`
3. official minimum 미달 → `insufficient-power`
4. process repeat 3회 미만 → `insufficient-power`
5. A/A false-alarm budget 실패 → `confounded`
6. setup-placebo 실패 → `confounded`
7. largest positive effect가 class 1 지연 방향으로 threshold를 넘긴 repeat
   비율이 `target_power` 미달 →
   `insufficient-power` (3 repeats와 0.8이면 3/3 요구)
8. target raw status repeat 불일치 → `insufficient-power`
9. seeded randombytes interpose 미확인 → `confounded`
10. 전부 통과 → `valid`

`valid`는 PASS 동의어가 아니다. `valid + FAIL`은 해석 가능한 signal이고
`valid + PASS`는 선택한 host와 입력 분포에서 관측된 no-signal이다. A/A 기반
nominal sensitivity 숫자는 보조 진단일 뿐 target 효과의 상한이 아니다.

## Artifacts

- `dudect_raw_timings.csv`: summary에 대응하는 target analysis trace. 실제
  sample id, AUX, output length와 dropped row 포함.
- `dudect_calibration_timings.csv`: 그 target repeat의 official calibration.
- `dudect_protocol_timings.csv`: 모든 repeat의 target/calibration/A/A/placebo/
  positive raw row.
- `dudect_backend_report.json` schema 2.0: official 102 tests, host, seeds,
  randomness policy, false-alarm budget, power curve, MDE, 세 CSV hash.

## 아직 증명하지 않는 것

- random input pool이 희귀/adversarial trigger를 커버한다는 주장
- 한 host/microarchitecture 결과의 다른 CPU 일반화
- full sign API 결과를 core sampler 결과로 해석
- `generic` caller setup의 자동 대칭성
- control 코드가 존재한다는 이유만으로 실제 corpus target이 control을
  통과했다는 주장

따라서 다음 단계는 native single-CPU에서 기존 corpus를 v2로 재실행하고,
target별 control artifact를 검토한 뒤 evidence v2를 재분류하는 것이다.
6 target/8 timing axis의 paper setting, host gate, 실행 재개, 무결성 검증
계약은 [`measurement/`](measurement/README.md)에 준비돼 있다. 현재 상태는
**campaign 준비 완료 / physical 실행 보류**이며, CI의 synthetic fixture나
Docker/QEMU smoke는 이 미완료 실측을 대신하지 않는다.
