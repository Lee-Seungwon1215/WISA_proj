# Independent upstream expansion plan

다음 corpus 확장은 parameter set 숫자 늘리기가 아니라 primary implementation
lineage를 늘리는 작업이다. 기계 판독 가능한 계약은
`independent_upstreams_v1.yaml`에 있다.

현재 imported lineage는 PQClean과 prospective c-fn-dsa 두 개다. 다음 순서는:

1. `mlkem-native`의 portable/x86_64/AArch64 profile
2. `mldsa-native`의 portable/x86_64/AArch64 profile
3. OpenSSL 3.5 계열 PQ API를 통한 production integration

OpenSSL wrapper는 production integration case로 세되, 그 밑의 실제 암호 구현
lineage와 별개인 새 codebase로 뻥튀기하지 않는다. 마찬가지로 ML-KEM-512/768/1024
세 parameter set, gcc/clang 두 compiler, 여러 optimization cell도 각각 독립
codebase로 세지 않는다.

각 import는 provenance/license/tree hash, upstream KAT, reference-optimized
equivalence, gcc/clang build matrix, x86_64/AArch64 artifact, structural/asm
evidence, same-corpus mapping, review gate를 한 묶음으로 끝낸다. 지원하지 않는
profile은 행을 지우지 않고 unsupported로 남긴다.

native timing은 source import와 분리한다. QEMU build/functional smoke는 가능하지만
timing 승격은 최소 두 microarchitecture의 reviewed physical artifact만 허용한다.
따라서 9번 작업에서는 먼저 독립 source/build/structural coverage를 완성하고,
현재 대기 중인 native timing-v2, Falcon paired timing, same-corpus dudect campaign은
장비 확보 뒤 같은 promotion gate로 처리한다.
