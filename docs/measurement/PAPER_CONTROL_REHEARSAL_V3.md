# Paper control rehearsal v3

V3는 V10 final 직전의 **비승격 control qualification**이다. V2-A는 커밋
`39a1cde`에서 중단 없이 28축, 세 baseline, assembly와 closure를 모두 완주했지만
사전 고정 gate 세 건으로 FAIL했다. 원본과 정확한 수치는
`paper_control_rehearsal_v2_calibration.yaml`에 보존한다. V2의 target 통계와 raw
row는 이 수정이나 V10 결론에 사용하지 않는다.

## V2에서 확인된 두 설계 문제

첫째, V1과 V2는 같은 seed와 같은 process-domain schedule을 썼다. 따라서
ML-DSA-44 A/A repeat 0의 `|t|`가 `3.7793`에서 `3.7921`로 거의 그대로 반복된
것은 두 번째 실행이 독립적인 null draw가 아니었기 때문이다. 더 근본적으로 null
t 통계량은 표본 수나 실행 횟수에 따라 0으로 단조 수렴하는 headroom 지표가 아니다.
28축에서 A/A와 placebo를 각각 세 번 검사하면 한 rehearsal에 168개의 null
검사가 생긴다. 별도 근거 없이 최종 4.5보다 낮은 3.5를 모든 검사에 적용하면
정상 null 실행도 불필요하게 탈락시키고, 통과할 때까지 재실행하게 만드는 선택
편향을 유도한다.

V3는 A/A와 setup-placebo에 원 final 규칙인 `|t| < 4.5`, 허용 실패 0회를
그대로 적용한다. 이는 V2 관측값에 맞춰 최종 판정선을 완화한 것이 아니다. final
manifest의 수량, seed, repeat, 4.5 limit와 0-failure budget은 바뀌지 않는다.
두 clean rehearsal은 서로 다른 시간, run ID, output root를 갖는 운영 재현이며
독립적인 추론 표본으로 주장하지 않는다.

둘째, KyberSlash1 chosen-ciphertext의 4096-tick positive sentinel은 최종 검출선
`t <= -10`을 통과했지만 V3 전 단계의 운영 여유선 `t <= -15`에는 두 repeat가
미달했다. V10은 실패 target 하나만 고르는 대신, 첫 두 효과가 `[64, 512]`인
모든 fast KEM/operand target 13개에 같은 `[64, 512, 16384]` ladder를 적용한다.
낮은 두 sensitivity point, control 수량, seed, repeat, target threshold와 분석은
그대로다. 이 규칙은 control 결과만 사용하며 어떤 reduced target 통계도 보지 않는다.

## 호스트 위생

V10의 네 component manifest와 same-corpus official dudect 실행기는 다음을 실행 전
hard gate로 요구한다.

- 한 logical CPU affinity
- `performance` governor
- SMT disabled
- Intel turbo disabled
- native Linux x86_64, invariant TSC/RDTSCP
- 비가상화·비에뮬레이션·clean exact commit

설정이 하나라도 다르면 sample을 수집하기 전에 종료한다. 이 요구는 V2에서 보인
분산 확대를 줄이고 두 rehearsal과 final의 물리 조건을 같게 보존하기 위한 것이다.
현재 Intel Linux host에서는 매 부팅 뒤 다음처럼 설정하고 readback을 확인한다.
sysfs 항목이 없는 다른 CPU를 임의로 통과시키지 말고 새 host 프로필로 별도
사전등록한다.

```bash
echo off | sudo tee /sys/devices/system/cpu/smt/control
echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo
cat /sys/devices/system/cpu/smt/active
cat /sys/devices/system/cpu/intel_pstate/no_turbo
uv run --frozen python scripts/run_native_timing_campaign.py --preflight --cpu 2
```

두 readback은 각각 `0`, `1`이어야 한다. 설정은 재부팅 뒤 원복될 수 있으므로
V3-A, V3-B, V10 final을 시작할 때마다 runner가 다시 확인한다.
Rehearsal closure는 네 component와 세 baseline이 기록한 두 readback도 서로
비교하며, 중간에 값이 바뀌거나 누락되면 해당 run을 blocker로 끝낸다.

## 실행

각 run은 target/calibration만 process당 1,000회로 줄인다. A/A, placebo,
positive-control count/effect/seed/repeat는 V10 final과 동일하다. Target status,
t-score, direction, power는 해석하거나 gate에 쓰지 않는다.

```bash
uv run --frozen python scripts/run_paper_control_rehearsal.py --check

uv run --frozen python scripts/run_paper_control_rehearsal.py \
  --execute --phase smoke --cpu 2 \
  --timecop-prefix /home/test/.local/ctkat/timecop \
  --output-root measurement_runs/host-a/control-rehearsals/v3-a

uv run --frozen python scripts/run_paper_control_rehearsal.py \
  --execute --phase controls --resume --cpu 2 \
  --timecop-prefix /home/test/.local/ctkat/timecop \
  --output-root measurement_runs/host-a/control-rehearsals/v3-a
```

V3-A가 blocker 0이면 같은 physical host와 logical CPU의 새 root `v3-b`에서
같은 절차를 한 번 더 실행한다. Qualification은 두 보고서의 machine-id hash,
CPU model, architecture와 affinity가 같지 않으면 거부한다. 두 run이 모두
PASS한 뒤 qualification을 만든다.

```bash
uv run --frozen python scripts/run_paper_control_rehearsal.py \
  --qualify \
  --expected-commit COMMIT \
  --rehearsal-report measurement_runs/host-a/control-rehearsals/v3-a/rehearsal_report.json \
  --rehearsal-report measurement_runs/host-a/control-rehearsals/v3-b/rehearsal_report.json \
  --qualification-output measurement_runs/host-a/v10-control-qualification.json
```

Qualification은 두 보고서의 경로, SHA-256, run ID, candidate commit, profile과
calibration hash를 봉인한다. 모든 V10 native/baseline final 명령은 같은
qualification을 받으며, final gate가 qualification과 두 원본을 다시 연다.

V1/V2/V3 artifact는 전부 engineering-only다. V3가 두 번 PASS해도 raw row나
target 통계를 final로 복사하지 않는다. V10 final은 같은 commit의 완전히 빈
root에서 30,000 target 표본으로 새로 시작한다.
