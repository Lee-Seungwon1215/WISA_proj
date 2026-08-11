# Native timing campaign

논문용 최상위 동결본은 `paper_native_campaign_v7.yaml`이다. 기존 corpus refresh
외에 KyberSlash, Falcon, diverse-upstream 비교를 독립 component로 묶으며,
한 대의 physical x86_64 Linux host에서 같은 clean commit으로 전부 실행한다.
결과는 해당 host 범위에서만 승격하며 cross-host 재현성과 독립 사람 리뷰를
주장하지 않는다. 기존 v5 two-host 계획은 stronger historical profile로 보존한다.

```bash
uv run python scripts/check_paper_campaign.py

uv run python scripts/run_native_timing_campaign.py \
  --manifest docs/measurement/native_timing_v3_campaign.yaml --check
uv run python scripts/run_native_timing_campaign.py \
  --manifest docs/measurement/kyberslash_native_v3.yaml --check
uv run python scripts/run_native_timing_campaign.py \
  --manifest docs/measurement/falcon_native_v2.yaml --check
uv run python scripts/run_native_timing_campaign.py \
  --manifest docs/measurement/diverse_native_v2.yaml --check
```

현재 정적 범위는 4 component, 26 target execution, 28 timing axis다. 이 숫자는
독립 구현 수가 아니다. 같은 target이 비교/control 목적으로 여러 component에
나올 수 있고 portable/native profile도 하나의 lineage 안에 있다.

- `native_timing_v3_campaign.yaml`: committed timing row 8축의 replacement;
  corpus key용 `kem_dec` 하니스 ID는 유지하지만 KEM machine axis는
  mixed `valid_tuple`로 교정
- `kyberslash_native_v3.yaml`: 고정키 chosen-ct 4축 + 같은 주소/유효 placebo/
  전 bin 반환값 witness를 강제한 취약·패치 operand canary 6축. v2 operand
  engineering trace는 setup confound 때문에 재사용 금지
- `falcon_native_v2.yaml`: 512/1024 reference/native-FP/integer-FPR 6축;
  v1 engineering calibration에서 power가 부족했던 1024 integer-FPR positive
  control만 상향한 final 동결본
- `diverse_native_v2.yaml`: mlkem-native의 혼합 valid-tuple 축과 mldsa-native
  sign 축을 portable/x86_64로 비교하는 4축; v1 engineering 결과는 attribution
  calibration 전용이며 final 재사용 금지

가설, sample/control 수, 제외 기준, multiplicity, host disagreement,
promotion 문구는 `EXPERIMENT_PREREGISTRATION.md`에 측정 전에 고정했다. static
check 성공은 timing 결과가 아니라 “실행 정의가 준비됨”만 뜻한다.

모든 timing 하니스는 특수 `binary_contract` 유무와 관계없이 첫 sample 전에
config, generated C, measured binary, linked source, compiler와 replay argv를
`reports/build_provenance/timing_<harness>.build-seal.json`에 봉인한다. runner는
각 subprocess 전후로 이를 확인하고 native validator는 target attestation에
해시를 다시 묶는다.

`native_timing_v3_campaign.yaml`은 기존 corpus의 timing 8개 축을
timing-harness-v2로 다시 측정하기 위한 동결된 실행 계획이다. v2의
ML-KEM `sk` machine label은 secret key와 matching public ciphertext를 함께
바꾸는 혼합 입력을 잘못 요약했다. v3은 corpus row key용 하니스 ID
`kem_dec`은 유지하되 machine axis를 `valid_tuple`로 바꾸고 fail-closed
input contract를 적용한다. v2 engineering trace는 역사 calibration이며 v3
final에 재사용·resume·relabel할 수 없다. 자동화 검증을
마친 clean commit에서는 engineering/pilot을 실행할 수 있다. v7 논문 승격용
final은 `--final-gate single-host`를 명시한다. runner는 v7 plan,
preregistration, analysis contract, 네 component manifest, baseline manifest,
실행/분석 코드와 lock file의 SHA-256을 campaign report에 묶는다. 이 gate는
input integrity 검증이며 사람 리뷰라고 부르지 않는다.

V7은 모든 비-operand KEM/서명 하니스의 class 준비를
`dual-read-masked-select-v4`로 고정한다. 두 class pool을 모두 읽고 마스크로
같은 work buffer에 선택하므로 `t0` 직전 class-dependent pointer branch가 없다.
각 raw trace가 이 계약을 기록하지 않으면 validity가 실패한다. V6 final tree와
V7 동결 전 engineering 결과는 이 setup 교정의 calibration일 뿐 재사용하지 않는다.

## 지금 확인 가능한 것

```bash
uv run python scripts/run_native_timing_campaign.py --check
```

이 명령은 native host를 요구하지 않는다. manifest schema, corpus coverage,
config/harness/source 존재, official backend, seeded interpose, 측정 수와 control
curve, 기본 gcc `-O2 -fno-lto -fno-omit-frame-pointer` 계약을 검증한다.
KyberSlash/Falcon처럼 exact linked-binary 계약이 있는 축은 그 manifest에 고정된
compiler flags를 대신 사용한다. 실행 때는
manifest의 warmup 1,000회, batch 10개, compile/backend timeout도 YAML의
개발용 기본값보다 우선한다.

동결 범위:

| family | target | timing axis |
|---|---|---|
| ML-KEM | `pqclean_mlkem768` | `kem_dec/valid_tuple`, `kem_dec_ct/ct`, `kem_dec_fo/fo` |
| ML-DSA | 44/65/87 세 target | 각 `sign/sk` |
| SPHINCS+ | SHA2-128f-simple | `sign/sk` |
| Falcon | Falcon-512 | `sign/sk` |

총 6 target/8 axis다. 이 manifest와 committed corpus timing row가 하나라도
어긋나면 CI의 `--check`가 실패한다.

## native 장비에서 실행

bare-metal x86_64 Linux에서 repository를 clean checkout한 뒤:

```bash
uv run python scripts/run_native_timing_campaign.py --preflight --cpu 2

uv run python scripts/run_native_timing_campaign.py \
  --execute --run-kind final --final-gate single-host \
  --cpu 2 \
  --output-root measurement_runs/corpus-native-timing-v3
```

`--cpu`는 명시적으로 현재 campaign process와 그 자식만 해당 logical CPU에
pin한다. CT-KAT core가 affinity를 몰래 바꾸는 것은 아니다. 이미 `taskset`으로
pin했다면 `--cpu`를 생략해도 된다.

engineering/pilot에서 긴 target이 중단됐으면 같은 경로에 `--resume`을 붙인다.
final은 resume을 금지하고 빈 output root에서 다시 시작한다. 일부 target만 먼저
돌리려면 `--target pqclean_mlkem768`처럼 반복 지정할 수 있다. partial run을
검증할 때도 같은 `--target`을 넘긴다. 생략하면 manifest의 6 target 전체가
있어야 한다.

preflight hard gate:

- Linux + x86_64
- QEMU/VirtualApple이 아닌 native instruction execution
- VM/container가 아닌 bare-metal (engineering run은
  `--allow-virtualized`로 명시)
- affinity CPU 정확히 1개
- clean git worktree
- `gcc`와 official dudect adapter build 가능

governor, invariant TSC, RDTSCP, exact CPU/machine/boot identity도 기록한다. pilot과
final은 performance governor와 timing capability를 hard gate로 요구한다. 실제
timing-harness-v2의 environment/control gate도 별도로 적용된다.
`machine-id` hash와 VM/container probe는 artifact 내부 일관성 검사이지 TPM quote나
물리 장비 소유 증명이 아니다. 따라서 bundle의 `physical: true`는 host probe와
운영 환경 기록이지 TPM 기반 원격 attestation은 아니다. 소프트웨어 checker는
이 경계를 물리 소유 증명이나 독립 검증이라고 구라치지 않는다.
`--allow-dirty`와 `--allow-virtualized`는 engineering 디버깅용 실행만 허용한다.
그 override가 붙은 run은 control이 우연히 전부 통과해도
`paper_eligible=false`라서 promotion-ready가 될 수 없다.

## 산출물

output root 아래 target별로 다음 파일이 생긴다.

- `reports/dudect_raw_timings.csv`
- `reports/dudect_calibration_timings.csv`
- `reports/dudect_protocol_timings.csv`
- `reports/dudect_summary.csv`
- `reports/dudect_backend_report.json`
- `reports/build_provenance/timing_<harness>.build-seal.json`
- `generated/timing_<harness>`와 generated C source

binary contract가 있는 축은 다음 파일도 필수 산출물이다.

- `reports/binary_contract/timing_<harness>.binary-contract.json`
- `reports/binary_contract/timing_<harness>.objdump.txt`
- `reports/binary_contract/timing_<harness>.objdump-file-header.txt`

root에는 다음 세 파일이 생긴다.

- `campaign_report.json`: manifest/commit/host/compiler, target별 artifact hash,
  validity와 promotion blocker
- target별 `run_attestation.json`: run id/kind, host·boot 지문, 모든 artifact hash
- `corpus_timing_updates.csv`: corpus 재분류 입력 후보. 자동으로
  `docs/corpus`를 수정하지 않는다.

복사 후에는 다섯 timing artifact뿐 아니라 campaign identity와
`corpus_timing_updates.csv`가 검증 결과에서 드리프트하지 않았는지도 다시
검사한다.

```bash
uv run python scripts/run_native_timing_campaign.py \
  --validate-run measurement_runs/corpus-native-timing-v3 \
  --expected-run-kind engineering
```

engineering/pilot의 exit `0`은 실행 artifact가 완전하다는 뜻일 뿐 승격 가능하다는
뜻이 아니다. final에서만 `0=모든 선택 축 promotion-ready`, `2=artifact는
완전하지만 non-promotable`, `1=실행/무결성 오류`다. raw FAIL도
`timing_validity=valid`면 유효한 signal일 수 있고, raw PASS도 validity가 깨지면
corpus clean 근거가 아니다.

## corpus 반영 경계

`corpus_timing_updates.csv`를 사람이 검토한 뒤에만
`scripts/build_corpus_table.py`로 curated corpus를 갱신한다. cloud VM/QEMU
smoke나 중간 run을 숫자만 복사해 넣는 행위는 금지한다. `measurement_runs/`는
크고 host-specific이라 gitignore 대상이다. 승격 시에는 최소한
`campaign_report.json`, backend report, raw trace의 immutable 보관 위치와
기록된 SHA-256이 서로 맞는지 먼저 결정해야 한다.
