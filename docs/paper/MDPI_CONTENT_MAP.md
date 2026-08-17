# WISA 원고 → MDPI 원고 내용 이관표

기준일: 2026-08-17
측정 기준: V10 single-host, commit
`1aeadb97e0409227aa203ba825a6bfc1d90445bc`

## 한 줄 결론

예전 WISA 원고를 포맷만 바꾼 게 아니다. 살아 있는 문제 정의와 도구 설명은
가져오되, 낡은 timing 숫자와 과한 수동 면책 verdict는 폐기하고, 그 뒤에 구현한
fail-closed evidence model·build/assembly matrix·KyberSlash/Falcon·28축 V10·artifact
무결성을 중심으로 논문 논리를 다시 짰다.

## 섹션별 이관

| 옛 WISA/LNCS 위치 | 새 MDPI 위치 | 처리 |
|---|---|---|
| Abstract | Abstract | 문제·파이프라인 기여는 재작성. 정적 corpus 수치는 자동 입력, V10 요약은 결과 JSON이 있을 때만 입력 |
| Introduction | Introduction | KAT만으로 부족하다는 동기와 도구 결합 필요성 유지. 기여를 네 가지 검증 가능한 항목으로 재정의 |
| Background | Background and Related Work | threat model, dynamic structural observation, timing analysis, build sensitivity를 한 흐름으로 통합 |
| Related Work | Background and Related Work | ctgrind, dudect, MicroWalk, compiler 영향 문헌 유지·정리 |
| System Design and Implementation | Materials and Methods | correctness, harness, compiler×flag matrix, assembly attribution, evidence fold로 세분화 |
| Triage-Based Verdict Assignment | Fail-Closed Evidence Fold | 옛 `accepted-variable-time` 면책 모델을 폐기하고 4-state claim vocabulary로 교체 |
| Evaluation의 corpus 표 | Results: Committed Screening Corpus | machine-readable corpus에서 생성한 25 pair/206 cell 및 6/5/10/4 상태만 사용 |
| Evaluation의 예전 native timing | 삭제 후 V10 Results 자리로 교체 | 옛 수치·부분 실험은 본문에서 전부 배제. complete named analysis만 허용 |
| ML-KEM 설명 | KyberSlash Static and Ground-Truth Evidence | stock/KS1/KS2/combined/patched provenance와 operand-latency 경계를 추가 |
| ML-DSA·SLH-DSA·Falcon 설명 | Screening Corpus + Falcon Comparator | 만료된 수동 declassification은 철회. Falcon reference/native-FP/integer-FPR 비교 범위를 명시 |
| Conclusion | Discussion + Limitations + Conclusions | 결과 해석, 사용 범위, 못 하는 것, 결론을 분리 |
| 없음 | Artifact Integrity and Promotion | commit, build seal, SHA-256, validation, deterministic named output을 추가 |
| 없음 | MDPI back matter | data availability, funding, IRB, consent, AI assistance, conflicts, abbreviations를 추가 |

## 완전히 폐기한 것

다음은 새 원고에서 사실상 매장했다. 다시 복붙하면 검사기가 실패한다.

- `accepted-variable-time`를 안전 판정처럼 사용하던 옛 verdict.
- ML-DSA/SLH-DSA의 오래된 수동 declassification을 현재 증거처럼 쓰는 주장.
- WISA 평가에 하드코딩돼 있던 `2.30`, `2.10`, `1.15--1.75`, `1.59`, `1.52`
  등의 native timing 값.
- pilot, engineering, 실패한 v7/v8, legacy v1/v2 결과를 final evidence로 승격하는 것.
- candidate pair 증가를 detector accuracy나 false-positive rate로 읽는 것.
- timing `PASS`를 constant-time 증명으로 쓰는 것.
- process repeat 세 번을 세 개의 독립 host처럼 쓰는 것.
- chosen-ciphertext 차이를 secret attribution으로, operand-bin을 실제 key-recovery로
  부르는 것.
- c-fn-dsa를 FIPS 206 적합 구현으로, OpenSSL provider를 독립 구현 lineage로 세는 것.
- `llncs.cls`, WISA 12-page 맞춤 편집, 한글 패키지를 MDPI 원고로 운반하는 것.

## 새로 들어간 핵심 내용

- 네 상태: `risk-detected`, `needs-review`, `inconclusive`,
  `no-finding-observed`.
- correctness 실패, attribution 미완료, control 실패, artifact 누락을 깨끗한 판정으로
  바꾸지 않는 fail-closed fold.
- 한 release build 11 candidate pair → 전체 matrix 13 → assembly 포함 22의 ablation.
  이는 검토 부담 변화이지 정확도 지표가 아니다.
- 네 구성요소, 26 target execution, 28 timing axis, host당 8,220,000 protocol row인
  V10 single-host 설계.
- A/A, setup-placebo, positive control, 세 process repeat, SMT/turbo 조건, build seal,
  semantic randomness contract.
- KyberSlash의 코드/operand/timing 증거 분리와 Falcon full-signature comparator.
- 다양한 upstream의 provenance/build/integration과 실제 독립성 주장의 분리.
- named analysis의 byte-identical 재생성 및 최종 결과 자동 주입.
- x86_64 측정과 Cortex-M4 향후 backend를 섞지 않는 architecture boundary.
- 생성형 AI 사용 공개를 포함한 MDPI 후면 선언.

## 현재 숫자가 박혀 있는 곳

확정된 정적 숫자는
`docs/paper/generated/premeasurement_tables.json`에서
`scripts/render_mdpi_results.py`를 통해
`paper/mdpi_working/generated/static_results.tex`로 생성된다. Native 숫자는
`paper_native_analysis.json`이 complete 28-axis 계약을 통과할 때만
`generated/native_results.tex`에 들어간다. 손으로 표를 고치는 경로는 없다.

## 결과 전/후 경계

결과 전에도 Introduction, Background, Methods, 정적 Results, Discussion 골격,
Limitations, Conclusions 골격, 참고문헌, MDPI 선언, 빌드와 검증은 완성할 수 있다.
결과 뒤에 남는 자동 작업은 native 표·초록 한 문장·결과 요약·결론 조건문을 complete
analysis로 렌더링하는 것이다. 사람이 결정해야 할 것은 저널, 저자/소속, CRediT,
연구비, 이해상충, 데이터 DOI뿐이다.
