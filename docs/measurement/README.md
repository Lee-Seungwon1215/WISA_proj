# Native timing campaign

`native_timing_v2_campaign.yaml`은 기존 corpus의 timing 8개 축을
timing-harness-v2로 다시 측정하기 위한 동결된 실행 계획이다. 현재 repository는
**준비 완료, native 실행 보류** 상태다.

## 지금 확인 가능한 것

```bash
python scripts/run_native_timing_campaign.py --check
```

이 명령은 native host를 요구하지 않는다. manifest schema, corpus coverage,
config/harness/source 존재, official backend, seeded interpose, 측정 수와 control
curve, gcc `-O2 -fno-lto -fno-omit-frame-pointer` 계약을 검증한다. 실행 때는
manifest의 warmup 1,000회, batch 10개, compile/backend timeout도 YAML의
개발용 기본값보다 우선한다.

동결 범위:

| family | target | timing axis |
|---|---|---|
| ML-KEM | `pqclean_mlkem768` | `kem_dec/sk`, `kem_dec_ct/ct`, `kem_dec_fo/fo` |
| ML-DSA | 44/65/87 세 target | 각 `sign/sk` |
| SPHINCS+ | SHA2-128f-simple | `sign/sk` |
| Falcon | Falcon-512 | `sign/sk` |

총 6 target/8 axis다. 이 manifest와 committed corpus timing row가 하나라도
어긋나면 CI의 `--check`가 실패한다.

## native 장비에서 실행

bare-metal x86_64 Linux에서 repository를 clean checkout한 뒤:

```bash
python scripts/run_native_timing_campaign.py --preflight --cpu 2

python scripts/run_native_timing_campaign.py \
  --execute \
  --cpu 2 \
  --output-root measurement_runs/corpus-native-timing-v2
```

`--cpu`는 명시적으로 현재 campaign process와 그 자식만 해당 logical CPU에
pin한다. CT-KAT core가 affinity를 몰래 바꾸는 것은 아니다. 이미 `taskset`으로
pin했다면 `--cpu`를 생략해도 된다.

긴 target에서 중단됐으면 같은 경로에 `--resume`을 붙인다. 일부 target만 먼저
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

governor가 확인 가능하면서 `performance`가 아니면 warning과 manifest에 남는다.
이를 숨기지는 않으며 실제 timing-harness-v2의 environment/control gate도 별도로
적용된다. `--allow-dirty`와 `--allow-virtualized`는 디버깅용 실행만 허용한다.
그 override가 붙은 run은 control이 우연히 전부 통과해도
`paper_eligible=false`라서 promotion-ready가 될 수 없다.

## 산출물

output root 아래 target별로 다음 파일이 생긴다.

- `reports/dudect_raw_timings.csv`
- `reports/dudect_calibration_timings.csv`
- `reports/dudect_protocol_timings.csv`
- `reports/dudect_summary.csv`
- `reports/dudect_backend_report.json`

root에는 다음 두 파일이 생긴다.

- `campaign_report.json`: manifest/commit/host/compiler, target별 artifact hash,
  validity와 promotion blocker
- `corpus_timing_updates.csv`: corpus 재분류 입력 후보. 자동으로
  `docs/corpus`를 수정하지 않는다.

복사 후에는 다섯 timing artifact뿐 아니라 campaign identity와
`corpus_timing_updates.csv`가 검증 결과에서 드리프트하지 않았는지도 다시
검사한다.

```bash
python scripts/run_native_timing_campaign.py \
  --validate-run measurement_runs/corpus-native-timing-v2
```

exit code는 `0=모든 선택 축 valid`, `2=artifact는 완전하지만 non-valid 결과
존재`, `1=실행/무결성 오류`다. raw FAIL도 `timing_validity=valid`면 유효한
signal일 수 있고, raw PASS도 validity가 깨지면 corpus clean 근거가 아니다.

## corpus 반영 경계

`corpus_timing_updates.csv`를 사람이 검토한 뒤에만
`scripts/build_corpus_table.py`로 curated corpus를 갱신한다. cloud VM/QEMU
smoke나 중간 run을 숫자만 복사해 넣는 행위는 금지한다. `measurement_runs/`는
크고 host-specific이라 gitignore 대상이다. 승격 시에는 최소한
`campaign_report.json`, backend report, raw trace의 immutable 보관 위치와
기록된 SHA-256이 서로 맞는지 먼저 결정해야 한다.
