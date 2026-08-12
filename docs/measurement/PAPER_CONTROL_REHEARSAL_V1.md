# Paper control rehearsal v1

이 프로필은 장시간 final을 한 컴포넌트씩 실패시키며 디버깅하던 흐름을
끝내기 위한 **비승격 engineering 리허설**이다. 논문 수치 생산 단계가 아니며,
여기서 나온 target 통계와 baseline 결과는 어떤 경우에도 final로 이름만 바꿔
재사용하지 않는다.

## 무엇을 줄이고 무엇을 그대로 두는가

28개 timing axis를 모두 빌드하고 실행한다. 다만 각 process의 target 및
official-dudect calibration trace만 30,000회에서 1,000회로 줄인다. 이 trace는
컴파일, setup, correctness, return-code, RNG, build seal, input/binary contract와
전체 실행 경로를 밟기 위한 smoke다. 표본 수가 부족하므로 raw PASS/FAIL,
target repeat consistency, official target power를 해석하거나 합격 기준으로 쓰지
않는다.

다음 항목은 final component manifest 값을 한 개도 줄이거나 바꾸지 않는다.

- A/A, setup-placebo, 세 단계 positive-control 표본 수
- 세 process repeat와 모든 seed/domain separation
- positive-control effect ladder와 최종 판정 threshold
- warmup, batch, pool, compiler/flag, timeout
- class setup, randomness, input, signature, build 및 linked-binary contract

same-corpus 세 도구와 ML-KEM assembly evidence도 전체 범위로 실행한다. 반면
paper bundle builder와 paper analysis는 `run_kind=final`만 받는 승격 경계이므로
리허설에서 일부러 실행하지 않는다. 대신 네 component, 세 baseline, assembly의
경로·commit·host·boot·개수 연결을 pipeline-closure 검사로 확인한다.

## Final 문턱보다 먼저 보는 안전 여유

Final의 사전등록 threshold 자체는 바꾸지 않는다. 리허설은 경계 바로 위를
간신히 통과한 control이 다음 장시간 실행에서 흔들리지 않도록 더 안쪽의 운영
여유를 요구한다.

- 모든 A/A와 setup-placebo repeat: `|t| < 3.5` (final 한계 `4.5`)
- 가장 큰 positive effect의 세 repeat 모두: class 1이 느리고 `t <= -15`
  (final 검출 문턱 `t <= -10`)
- 원래 final gate인 A/A budget, placebo, largest-effect 3/3 detection도 당연히 통과

이 안전 여유는 논문의 새 통계 threshold가 아니다. Final을 시작해도 될 정도로
control이 문턱에서 떨어져 있는지 보는 engineering headroom이다. 실패하면 해당
axis와 repeat를 한꺼번에 blocker matrix에 남기고, 효과 ladder나 하니스 문제를
engineering artifact로 고친 뒤 새 commit에서 다시 리허설한다.

## 실행 순서

먼저 정적 계약을 확인한다.

```bash
uv run --frozen python scripts/run_paper_control_rehearsal.py --check
```

native Linux x86_64에서 모든 28축을 서로 독립적으로 컴파일하고 binary/build
contract까지 확인한다. 한 축이 실패해도 나머지를 계속한다.

```bash
uv run --frozen python scripts/run_paper_control_rehearsal.py \
  --execute --phase smoke --cpu 2 \
  --timecop-prefix /home/test/.local/ctkat/timecop \
  --output-root measurement_runs/rehearsal-v1-a
```

smoke가 깨끗하면 같은 root에서 final-equivalent control 리허설을 잇는다.

```bash
uv run --frozen python scripts/run_paper_control_rehearsal.py \
  --execute --phase controls --resume --cpu 2 \
  --timecop-prefix /home/test/.local/ctkat/timecop \
  --output-root measurement_runs/rehearsal-v1-a
```

각 component runner에는 target 간 `continue-on-error`를 강제하며, 바깥
orchestrator도 component나 baseline 하나의 반환값 때문에 종료하지 않는다.
끝에서 `rehearsal_report.json`과 `rehearsal_report.md`에 모든 실패를 한 번에
집계한다. SSH가 끊겨도 계속 실행하려면 이 명령을 systemd transient service나
동등한 host-local supervisor 안에서 실행한다.

## Final 진입 조건

한 번 깨끗하다고 바로 final로 가지 않는다. 동일한 candidate commit에서 서로
다른 rehearsal run ID 두 개가 연속으로 다음 조건을 만족해야 한다.

1. compile/contract smoke 28/28 pass;
2. 네 native component의 26 target/28 axis artifact 구조 검증 pass;
3. 모든 final control gate와 위 safety margin pass;
4. official-dudect, TIMECOP, MicroWalk 두 case 결과 pass;
5. assembly 및 pipeline-closure pass;
6. blocker 0개.

그 뒤에만 engineering 보정 내용을 사전등록 amendment와 새 paper campaign
버전에 고정하고 자동 감사를 다시 묶는다. 이후의 fresh final은 빈 root에서
실행하며 어떤 rehearsal trace도 복사하거나 resume하지 않는다.
