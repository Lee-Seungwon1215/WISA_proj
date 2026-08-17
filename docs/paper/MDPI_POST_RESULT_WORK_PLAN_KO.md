# CT-KAT V10 결과 이후 MDPI 잔여 작업 계획

작성 기준: 2026-08-17
측정 커밋: `1aeadb97e0409227aa203ba825a6bfc1d90445bc`
현재 상태: **V10 결과 주입·해석·PDF 자동 검증 완료, 제출자 정보와 영구 artifact 식별자 대기**

## 0. 결론

논문에 필요한 single-host 물리 측정은 끝났다. complete marker, 네 campaign의
26/26 target, 세 same-corpus baseline, schema-v5 bundle, deterministic named
analysis와 SHA-256을 확인했다. 로컬 논문 브랜치에는 28개 primary axis와 secondary
분석이 자동 생성되어 들어갔다.

따라서 두 번째 host, 사람 2인의 review, Cortex-M4 backend는 현재 논문을 완성하기
위한 숨은 필수조건이 아니다. 추가 연구·보강 실험으로만 남긴다. 지금 제출을 막는
것은 측정 부족이 아니라 저널/저자 정보와 공개 artifact 보관 위치다.

## 1. 완료된 기계 작업

- 원격 완료 시각: `2026-08-17T19:02:32+09:00`
- 원격 checkout과 분석 commit 일치 및 clean 상태 확인
- 네 component: 6/6, 10/10, 6/6, 4/4 target complete/promotion-ready
- official dudect, TIMECOP, MicroWalk baseline 3/3 promotion-ready
- named analysis 최초 생성과 `--check-output` byte 재현성 검증
- 로컬 회수본 SHA-256 대조
  - `paper_native_analysis.json`: `0af7e1b760565cf3caef760385a8f45c728cee155ab3e9f1c2e4b52b4ed90426`
  - bundle: `67089b3efc0f43fd951ffc81f77c61d33e5bbec3c61990f0eb4394d14f425a39`
- 28축 결과: risk-detected 3, needs-review 0, inconclusive 0,
  no-finding-observed 25
- 17개 pairwise contrast와 13개 signature-length endpoint 주입
- claim/evidence matrix의 물리 측정 대기 gate를 `supported-single-host`로 닫고
  파생 readiness 원장을 재생성
- complete-result MDPI PDF 생성, undefined citation/reference 0,
  2 pt 초과 overfull box 0
- PDF 14쪽 전 페이지와 결과표 확대 육안 검사
- 제출 source ZIP의 clean-room 컴파일 경로 구현
- 내부 검토용 draft source ZIP 생성, clean-room 재빌드와 독립 2회 생성의
  byte-identical SHA-256 확인
  - SHA-256: `9b63eb2c9964baf564c11b696f2c70ea4d8fc2a3e5580ea7c0d6df5062edd898`

## 2. 결과 해석 경계

세 risk-detected 축은 모두 ML-KEM `valid_tuple`이다. 이 입력은 matching secret key,
public ciphertext, secret key 내부의 public material을 함께 바꾸므로 **secret-only
attribution이 아니다**. 큰 t-score를 키 누출이나 key recovery로 쓰면 안 된다.

KyberSlash chosen-ciphertext와 vulnerable/patched operand canary는 이 Intel host에서
no-finding-observed였다. 이는 알려진 division site와 직접 operand attribution을
취소하지 않는다. “정적 메커니즘은 있으나 이 host/protocol에서 물리 신호를
관측하지 못했다”가 정확한 결론이다.

17개 pairwise 중 Holm-significant한 것은 mlkem-native portable/native mixed
valid-tuple 비교 하나다. 두 profile 모두 primary risk-detected이므로 보안 순위가
아니라 관측된 signal magnitude 차이다. Falcon variable-length endpoint 세 개의
within-class correlation은 모두 매우 작았고 primary verdict를 바꾸지 않는다.

## 3. 지금 사용자가 확정해야 하는 제출 blocker

1. 목표 MDPI 저널, article type, special issue 여부
2. 최종 제목
3. 저자 순서, 영문 이름, ORCID, 소속, 이메일, 교신저자
4. CRediT 기여
5. funding/grant 또는 no external funding
6. conflict of interest와 acknowledgment
7. 공개 저장소 release/tag 및 raw/derived artifact의 DOI 또는 영구 URL
8. 해당 저널의 최신 AI-assistance disclosure 문구

이 값들은 코드나 측정에서 추론하지 않는다. 가짜 DOI와 가짜 연구비를 채우는
것보다 placeholder로 막아 두는 편이 맞다.

## 4. 정보가 들어오면 바로 할 최종 순서

1. `main.tex` front/back matter를 확정 정보로 교체한다.
2. 목표 저널 class option과 최신 author instruction을 다시 확인한다.
3. artifact archive를 업로드하고 DOI/URL과 SHA-256을 기록한다.
4. 전체 영어 교정과 공동저자 claim review를 수행한다.
5. strict 모드로 source package를 만든다.

```bash
bash scripts/package_mdpi_submission.sh \
  --analysis /path/to/paper_native_analysis.json \
  --output /path/to/CT-KAT_MDPI_submission.zip
```

placeholder가 하나라도 남으면 strict packaging은 실패한다. 내부 검토용으로만
`--draft`를 붙일 수 있으며, 그 ZIP은 제출 가능 판정이 아니다.

## 5. 선택적 후속 연구

- 두 번째 x86_64 microarchitecture에서 cross-host replication
- 독립 사람 2인의 post-measurement review
- Cortex-M4 cross-compiled ELF용 ARM disassembly/contract backend
- 보드 위 cycle counter 또는 trace 기반 별도 물리 campaign
- artifact DOI 공개 뒤 external reproducibility exercise

이 항목은 논문의 limitations/future work에 남기며 현재 V10 결과를 갈아엎는 이유로
쓰지 않는다.
