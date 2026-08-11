# Same-corpus baseline v1

`same_corpus_v1.yaml`은 `toy_kem_ct_leak`의 같은 source snapshot, 같은
`crypto_kem_dec(ss, ct, sk)` 호출, 같은 ciphertext 입력 축을 다음 세 도구에
연결한다.

| tool | 보는 것 | v1 실행 경계 |
|---|---|---|
| official dudect | 두 실행시간 분포의 통계 차이 | bare-metal Linux/x86_64와 physical control 필요 |
| patched TIMECOP | taint가 분기·주소·variable-latency operand에 도달하는지 | Linux structural/operand evidence |
| MicroWalk PinTracer | 입력별 instruction/control-flow/memory trace 차이 | Linux/x86_64 Pin structural evidence |

양성 case는 `ct[0]`에 따라 slow path가 갈리고, 음성 case는 입력과 무관하게 같은
횟수의 work를 한다. 도구마다 관측치가 다르므로 결과를 하나의 “정확도” 숫자로
합치지 않는다. 비교 가능한 것은 known issue 검출 여부, capability, 실행 실패,
후보 수, 비용, review burden, 반복 안정성이다.

## 정적 검사와 현재 host probe

```bash
uv run python scripts/run_same_corpus_baselines.py --check
uv run python scripts/run_same_corpus_baselines.py \
  --probe \
  --output measurement_runs/same-corpus-capability.json
```

`--check`는 source hash, upstream/backend pin, 2 case × 3 tool의 완전한
Cartesian coverage, testcase hash, result schema, committed CSV와 독립-upstream
계획을 함께 검사한다. `--probe`는 현재 host에서 실행할 수 없는 조합도 삭제하지
않고 `unsupported + not-run` 행으로 기록한다.

결과 JSON은 `baseline-result-v1.schema.json`의 공통 필드를 모두 가진다. 아직
사람이 측정하지 않은 `human_triage_minutes`, `reviewer_agreement`,
`disposition_stability`는 `null`이다. `0`으로 날조하지 않는다.

## TIMECOP

exact-pinned patched Valgrind image에서:

```bash
docker build --target timecop --tag ctkat-timecop .
docker run --rm \
  -v "$PWD:/workspace" \
  -v "$PWD/measurement_runs:/results" \
  -w /workspace \
  ctkat-timecop \
  python scripts/run_same_corpus_baselines.py \
    --run-timecop \
    --run-kind engineering \
    --output-root /results/same-corpus
```

runner는 variable-latency canary를 먼저 통과시킨 뒤 두 하니스를 같은 compiler
profile로 만든다. 양성의 branch finding과 음성의 zero finding이 모두 manifest와
맞아야 engineering artifact가 완전하다. container 실행은 언제나
non-promotable이다. final TIMECOP은 exact-pinned patched Valgrind를 bare-metal
host에 설치하고 `--prefix /exact/pinned/prefix`로 실행해야 한다. 이 값은 TIMECOP
artifact가 자기 계약을 통과했다는 뜻이지 physical timing이나 constant-time
증명이 아니다.

TIMECOP 행은 생성된 harness source, 연결된 tracked source들의 SHA-256,
구조화된 compile argv/workdir, compiler의 요청명·실행 경로·resolved 경로·binary
SHA-256·전체 `--version` transcript, 그리고 ASLR 주소를 제거한 finding signature를
보존한다. engineering 결과는 이 원시 artifact를 완결해서 후속 점검에 넘길 수
있다. 다만 final 승격 검증은 보존 로그를 증언으로 믿지 않는다. 현재 checkout에서
harness를 다시 렌더링하고 tracked source hash를 맞춘 뒤, 기록된 정확한 compiler로
격리 임시 디렉터리에 canary와 양성/음성 harness를 모두 재빌드한다. 이어 현재의
exact-prefix patched Valgrind로 세 binary를 새로 실행해 stable finding signature,
return code, classifier status, finding/no-finding outcome이 보존 raw와 같은지
재확인한다. 어느 단계든 재현할 수 없거나 서로 다르면 final은 fail-closed다.

## MicroWalk PinTracer

Linux/x86_64 Docker host에서:

```bash
uv run python scripts/run_same_corpus_baselines.py \
  --run-microwalk \
  --run-kind engineering \
  --output-root measurement_runs/same-corpus
```

runner는 16개 ciphertext를 결정론적으로 만들고 wrapper와 target을 빌드한다.
그 뒤 `objdump` preflight로 네 `PinNotify*` marker의 직접 호출이 최적화 뒤에도
남았는지 확인하고, MAP을 생성한 뒤 exact digest의 official GHCR image로
PinTracer를 실행한다. `call-stacks.txt`의 leakage entry 수를 lossless
artifact와 함께 정규화한다.

선택한 baseline은 MicroWalk 전체를 대표하는 게 아니라 **PinTracer profile**이다.
AArch64에서 이 profile은 `unsupported`다. 이를 crash나 no-finding으로 바꾸지
않는다. upstream image에는 source revision label이 없어 v1 manifest는 실행
image digest와 v3.2.0 documentation revision을 각각 pin하고 그 build linkage가
검증되지 않았다는 caveat도 보존한다.

## official dudect

bare-metal Linux/x86_64에서 CPU affinity를 하나로 고정한 뒤:

```bash
taskset -c 2 uv run python scripts/run_same_corpus_baselines.py \
  --run-dudect \
  --run-kind engineering \
  --output-root measurement_runs/same-corpus
```

raw status가 기대와 맞더라도 A/A, setup placebo, positive-control power,
virtualization, affinity gate 중 하나라도 실패하면 공통 outcome은
`inconclusive`이고 timing evidence로 승격되지 않는다. 현재 macOS/ARM
개발 host에서는 실행 대신 명시적인 unsupported artifact만 생성한다.

V7 toy 기준선은 결정적 API라 `randombytes_header: null`과
`external-or-none`을 명시적으로 짝지으며, 입력독립 음성 대조군은 고정
10,000회 작업을 수행한다. class 준비는 두 pool을 모두 읽는
`dual-read-masked-select-v4`, 양성 대조군은 `[512, 2048, 8192]` ticks로
동결돼 있다. V6의 두 invalid dudect run은 calibration으로만 보존한다.

모든 artifact는 다시 검사할 수 있다.

```bash
uv run python scripts/run_same_corpus_baselines.py \
  --validate-result measurement_runs/.../baseline_report.json
```

## 아직 남은 숫자

CI structural run은 TIMECOP/MicroWalk adapter의 재현성을 확인한다. 논문 표에
필요한 setup/runtime/memory/artifact size의 host 반복, human triage 시간,
reviewer agreement, compiler/seed/host disposition stability는 아직 측정하지
않았다. 특히 official dudect의 최종 두 행은 native physical run 전까지
`blocked-by-native-physical-host`다.

독립 구현 확대 순서와 각 import gate는
`../corpus/independent_upstreams_v1.yaml`에 동결되어 있다. 그 파일의
`design-frozen-not-imported`는 계획을 만들었다는 뜻이지 target을 이미 corpus에
넣었다는 뜻이 아니다.
