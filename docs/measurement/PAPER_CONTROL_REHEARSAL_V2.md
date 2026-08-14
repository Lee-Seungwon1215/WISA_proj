# Paper control rehearsal v2

V2는 V9 final 직전의 **비승격 control qualification**이다. V1은 중단 없이
전 범위를 완주했고 실행 경로는 모두 닫혔지만, Falcon-1024 positive power 2/3과
안전여유 blocker를 발견했다. 상세 수치와 선택 규칙은
`paper_control_rehearsal_v1_calibration.yaml`에 고정했다.

V9은 V1 target 결과를 사용하지 않는다. 모든 manifest target에 같은 규칙을
적용해, 그 target의 어떤 축이라도 가장 큰 positive effect의 최악 repeat가
`t > -20`이면 첫 두 effect는 유지하고 마지막 effect만 두 배로 올렸다. 이 규칙은
9개 target을 선택한다. 표본 수, seed, repeat, threshold, setup, source, compiler,
binary contract, 가설과 분석은 바뀌지 않는다. ML-DSA-44 A/A `|t|=3.7793` 한 건은
final 한계 4.5 안의 null-tail이므로 어떤 파라미터도 바꾸지 않고 새 run에서 다시
검사한다.

각 V2 run은 target/calibration만 process당 1,000회로 줄인다. A/A, placebo,
positive-control count/effect/seed/repeat는 V9 final과 동일하다. Target status,
t-score, direction, power는 해석하거나 gate에 쓰지 않는다. 각 run은 새 root에서
smoke 28축, native 4컴포넌트, baseline 3종, assembly와 closure를 모두 실행한다.

```bash
uv run --frozen python scripts/run_paper_control_rehearsal.py --check

uv run --frozen python scripts/run_paper_control_rehearsal.py \
  --execute --phase smoke --cpu 2 \
  --timecop-prefix /home/test/.local/ctkat/timecop \
  --output-root measurement_runs/host-a/control-rehearsals/v2-a

uv run --frozen python scripts/run_paper_control_rehearsal.py \
  --execute --phase controls --resume --cpu 2 \
  --timecop-prefix /home/test/.local/ctkat/timecop \
  --output-root measurement_runs/host-a/control-rehearsals/v2-a
```

V2-a가 blocker 0이면 동일한 clean commit의 새 root
`measurement_runs/host-a/control-rehearsals/v2-b`에서 같은 절차를 한 번 더
실행한다. 두 run이 모두 PASS한 뒤 qualification을 만든다. 이 경로들은 최종
host artifact tree 안에 두어 bundle의 `SHA256SUMS`가 원본까지 보존하게 한다.

```bash
uv run --frozen python scripts/run_paper_control_rehearsal.py \
  --qualify \
  --expected-commit COMMIT \
  --rehearsal-report measurement_runs/host-a/control-rehearsals/v2-a/rehearsal_report.json \
  --rehearsal-report measurement_runs/host-a/control-rehearsals/v2-b/rehearsal_report.json \
  --qualification-output measurement_runs/host-a/v9-control-qualification.json
```

Qualification은 두 보고서의 경로, SHA-256, run ID, candidate commit, profile과
calibration hash를 봉인한다. 모든 V9 native/baseline final 명령은
`--control-qualification measurement_runs/host-a/v9-control-qualification.json`을 반드시
받으며, final gate가 qualification과 두 원본 보고서를 독립적으로 다시 연다.
하나라도 없거나 바뀌면 final은 첫 sample 전에 종료한다.

V1/V2 artifact는 전부 engineering-only다. 두 번 PASS해도 어느 raw row나 target
통계를 final로 복사하지 않는다. V9 final은 같은 commit의 완전히 빈 root에서
30,000 target 표본으로 새로 시작한다.
