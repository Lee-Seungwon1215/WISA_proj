# Independent upstream expansion

이 corpus 확장의 집계 단위는 parameter set이 아니라 separately maintained
primary upstream lineage다. 기계 판독 가능한 source/build/result 계약은 각각
`independent_upstreams_v1.yaml`, `diverse_upstreams_v1.yaml`,
`diverse-build-result-v1.schema.json`에 있다.

## 구현된 범위

현재 사전측정 동결본에는 다음 source/build gate가 구현돼 있다. 최초
`0.10.0a1` import의 mlkem-native v1.2.0은 `0.11.0a1` 동결에서 v1.3.0으로
교체했고 KAT digest 불변을 확인했다.

1. `mlkem-native v1.3.0`
   (`398050c877ff4353c96305c6434b63528accfc37`)
2. `mldsa-native v1.0.0-beta2`
   (`9b0ee84f4cf399043eca59eca4e5f8531ca1d61b`)
3. `OpenSSL 3.5.7`
   (`8cf17aaeb4599f8af87fefd810b5b5fee90fe69e`) production-provider API
   integration

두 native package는 license, upstream README/META, monolithic source와 assembly,
upstream KAT generator/test RNG를 byte-identical subset으로 import했다. OpenSSL은
source를 vendor하지 않고 공식 release tarball SHA-256을 검증한 뒤 CI에서 exact
release를 빌드한다.

OpenSSL wrapper는 integration case이며 primary lineage 수를 늘리지 않는다.
ML-KEM/ML-DSA parameter, compiler, optimization, architecture, wrapper도 각각
독립 codebase로 세지 않는다. 현재 집계는 기존 PQClean/c-fn-dsa와 새
mlkem-native/mldsa-native를 합친 maintained upstream lineage 4개와 integration
case 1개다. 두 native package가 public-domain Kyber/Dilithium reference에서
유래했다는 ancestry도 보존하며 shared-code fraction은 아직 `unmeasured`다.

## 재현 가능한 build gate

각 x86_64/AArch64 native runner는 다음 120개 cell을 실행한다.

```text
6 parameter × 2 profile × 2 compiler × 5 optimization = 120 cells/arch
```

- profile: portable C, architecture-native backend
- compiler: gcc, clang
- optimization: debug, O1, O2, O3, Os
- correctness: 모든 cell의 deterministic smoke 실행
- equivalence: 같은 parameter/compiler/optimization의 portable/native transcript
  byte identity
- KAT: gcc/O2의 두 profile에서 imported upstream `gen_KAT.c` stdout와
  `META.yml` SHA-256 비교
- structure: ELF machine, native assembly symbol, architecture instruction
  marker 검증

두 architecture를 합치면 240 build/run cell, 24 upstream KAT check, 120
portable/native equivalence pair다. OpenSSL job은 exact release의 default provider로
ML-KEM 3종의 keygen/encap/decap과 ML-DSA 3종의 keygen/sign/verify를 실행하고,
gcc/clang adapter transcript가 같아야 한다.

로컬 static gate와 Linux quick gate는 다음과 같다.

```bash
python scripts/check_diverse_upstreams.py
python scripts/check_diverse_upstreams.py \
  --run-build-matrix --quick --output-root /tmp/ctkat-diverse-quick
python scripts/check_diverse_upstreams.py \
  --validate-result /tmp/ctkat-diverse-quick/native-upstreams-x86_64.json
```

full CI artifact에는 result JSON, deterministic/KAT executable, native assembly
object가 남는다. `--quick`은 로컬 smoke 전용이며 gcc/O2만 줄이되 두 profile,
여섯 parameter, 12 upstream KAT는 생략하지 않는다.

## 아직 주장하지 않는 것

- `mldsa-native v1.0.0-beta2`의 API 안정성이나 독립 FIPS validation
- 네 lineage가 서로 from-scratch라는 주장 또는 shared-code fraction 0
- CI/VM/QEMU에서 얻은 timing evidence
- build/KAT/structural 통과에 의한 constant-time 증명
- 한 명의 판단으로 `clean` 또는 declassified 승격

모든 생성 artifact는 `needs-review`이고 최소 두 명의 review가 필요하다. native
timing은 source/build corpus와 분리되어 있다. 물리 장비 두 microarchitecture에서
동결된 timing-v2 control을 통과하기 전에는 기존 native campaign, Falcon paired
timing, same-corpus dudect와 함께 미완료로 남는다.
