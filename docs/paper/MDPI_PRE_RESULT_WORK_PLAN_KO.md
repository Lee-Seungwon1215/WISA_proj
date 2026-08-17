# V10 결과 대기 중 MDPI 논문 준비 계획

작성 기준: 2026-08-17
측정 기준 커밋: `1aeadb97e0409227aa203ba825a6bfc1d90445bc`
상태: **결과 독립 작업 구현 완료, V10 complete named analysis 대기 중**

## 0. 결론부터

최종 timing 숫자가 없어도 논문의 **형식 이관, 연구 질문, 방법론, 정적 결과,
그림, 재현성 설명, 결과 표 골격, 후처리 절차**는 먼저 끝낼 수 있다. 실제로
결과를 기다려야 하는 부분은 native timing 수치와 그 수치에 의존하는
Results/Discussion/Abstract/Conclusion의 최종 문장뿐이다.

2026-08-17 구현 결과: `paper/mdpi-pre-results` 브랜치에서 공식 MDPI 작업본,
12쪽 pre-result PDF, 영문 본문, 정적 표, 28축 renderer와 tests, fail-closed paper
checker, one-command build, content map, 제출 checklist, 결과 ingestion runbook,
`nm` locale regression 명세까지 완료했다. 측정 checkout의 frozen source는 수정하지
않았다.

따라서 대기 시간에는 기존 LLNCS 원고를 계속 땜질하지 않고, 별도 MDPI 작업본을
만드는 것이 맞다. 권장 순서는 아래와 같다.

1. MDPI 공식 템플릿과 빌드 경로를 먼저 고정한다.
2. 결과와 무관한 본문을 영어 MDPI 구조로 이관한다.
3. 이미 확정된 정적·구조적 증거를 표와 그림으로 넣는다.
4. timing 결과가 들어갈 위치와 자동 생성 형식을 빈 골격으로 만든다.
5. V10이 끝나면 검증된 결과만 삽입하고 주장 범위를 확정한다.

## 1. MDPI 형식 기준

### 1.1 기준 소스

- [MDPI 공식 LaTeX 안내](https://www.mdpi.com/authors/latex)의 최신 템플릿을
  사용한다. 임의로 비슷하게 만든 클래스는 쓰지 않는다.
- [MDPI Author Layout Style Guide](https://www.mdpi.com/authors/layout)를
  제목, 초록, 표, 그림, 약어, 참고문헌, 후면 선언의 기준으로 삼는다.
- 실제 투고 저널이 정해지면 해당 저널의 `Instructions for Authors`를 마지막
  우선순위로 적용한다.
- 보안·컴퓨터공학 계열을 전제로 작업 중 기본 인용 묶음은 **MDPI ACS style**로
  둔다. 목표 저널이 APA 또는 Chicago를 요구하면 공식 묶음만 교체한다.

### 1.2 새 작업본 원칙

- 기존 `paper/wisa_working/current_12p/`는 과거 LLNCS/WISA 원문의 내용 참조본으로
  보존한다.
- 새 작업본은 `paper/mdpi_working/` 아래에 만든다.
- 공식 배포본의 `template.tex`, `Definitions/`, bibliography style과 logo 파일을
  함께 보존하고, 다운로드 URL·날짜·SHA-256을 기록한다.
- 개발 중에는 섹션 파일을 나눌 수 있지만, 제출 ZIP은 목표 저널 지침에 맞춰
  모든 필수 소스·그림·참고문헌을 포함하고 깨끗한 환경에서 재컴파일한다.
- 현재 한글 원고를 MDPI 클래스에 억지로 끼우지 않는다. 투고 작업본은 영어로
  다시 쓰며 `kotex`, `llncs.cls`, WISA page-limit용 조정은 가져오지 않는다.
- 저널명, 저널별 `\documentclass` 옵션, 저자 정보처럼 아직 모르는 값은 명시적
  `TBD`로 남기고 추측해서 채우지 않는다.

### 1.3 MDPI 논문 구조

목표 구조는 다음과 같이 잡는다.

1. Front matter: article type, title, authors, affiliations, corresponding author,
   abstract, keywords
2. Introduction
3. Related Work and Background
4. Materials and Methods
   - threat model and claim vocabulary
   - CT-KAT evidence pipeline
   - correctness and dynamic structural screening
   - assembly candidate analysis and attribution
   - frozen native timing protocol and controls
   - targets, compiler/build matrix, and analysis policy
5. Results
   - screening corpus and evidence-state coverage
   - ablation/build-sensitive findings
   - KyberSlash ground truth
   - Falcon comparator
   - diverse upstream/integration evidence
   - V10 single-host native timing
6. Discussion
7. Limitations
8. Conclusions
9. Supplementary Materials
10. Author Contributions, Funding, Institutional Review Board Statement,
    Informed Consent Statement, Data Availability Statement, Acknowledgments,
    Conflicts of Interest

사람 대상 연구가 아니므로 IRB와 informed consent는 실제 적용 여부를 확인한 뒤
MDPI가 요구하는 비적용 문구를 넣는다. 저자·기여·연구비 정보는 사용자가 확정할
영역이다.

## 2. 결과가 나오기 전에 바로 가능한 작업

### P0. 측정 커밋 보호와 논문 작업 분리

- native host의 측정 checkout과 결과 디렉터리는 건드리지 않는다.
- V10 결과는 반드시 `1aeadb97...`에서 나온 것으로 보존한다.
- 논문 이관은 별도 `paper/mdpi-migration` 브랜치 또는 별도 worktree에서 한다.
- 이후 검증기는 `1aeadb97...`의 clean detached worktree에서 실행한다.
- 논문 커밋과 측정 커밋을 같은 것처럼 쓰지 않고 두 값을 논문 artifact에 각각
  기록한다.

완료 기준: 원격 final 실행·threshold·manifest·source가 전혀 바뀌지 않은 상태에서
논문 파일만 독립적으로 수정할 수 있어야 한다.

### P1. 공식 MDPI 작업본 생성과 빌드 고정

- 최신 공식 MDPI ACS 템플릿을 내려받아 출처와 SHA-256을 기록한다.
- `paper/mdpi_working/`을 만들고 최소 문서가 로컬에서 컴파일되게 한다.
- `scripts/build_mdpi_paper.sh` 같은 단일 빌드 진입점을 만든다.
- clean build, bibliography, missing reference, overfull box를 검사한다.
- 기존 LLNCS PDF와 새 MDPI PDF를 혼동하지 않도록 출력 이름을 분리한다.

완료 기준: 결과 표가 비어 있어도 MDPI PDF가 오류 없이 만들어지고, 빌드 명령과
필요 파일이 README에 남아 있어야 한다.

### P2. 기존 원고의 내용 이관표 작성

| 기존 LLNCS 원고 | MDPI 작업본 | 지금 처리 가능 여부 |
|---|---|---|
| Abstract | Abstract | 구조·문제·기여는 가능, 결과 문장은 대기 |
| Introduction | Introduction | 가능 |
| Related Work | Related Work and Background | 가능 |
| Implementation | Materials and Methods | 대부분 가능 |
| Performance | Results + Discussion | 정적 결과만 가능, V10 timing은 대기 |
| Conclusion | Conclusions + Limitations | 골격 가능, 최종 결론은 대기 |

이관하면서 중복 설명, WISA 분량 맞추기용 축약, 오래된 v6/v8 표현, 예전 native
숫자를 제거한다. 현재 `section/4performance.tex`에 박힌 `2.30`, `2.10`,
`1.15--1.75`, `1.59`, `1.52` 등의 값은 V10 결과가 아니므로 새 원고로 복사하지
않는다.

### P3. 결과와 무관한 본문 영어 초안 완성

아래 내용은 V10 숫자 없이도 사실관계와 동결된 설계만으로 쓸 수 있다.

- CT-KAT이 해결하는 문제와 연구 질문
- “한 도구가 constant-time을 증명한다”가 아니라 여러 증거를 fail-closed하게
  결합한다는 핵심 기여
- `risk-detected`, `needs-review`, `inconclusive`,
  `no-finding-observed`의 제한된 주장 어휘
- correctness/KAT gate, Valgrind/TIMECOP 관찰, compiler × flag matrix,
  assembly candidate와 operand attribution의 역할
- branch/address 관찰만으로 variable-latency operand를 놓칠 수 있는 이유
- KyberSlash를 ground truth로, Falcon을 comparator로 둔 이유
- 네 component, 26 target execution, 28 timing axis의 범위
- A/A, setup-placebo, positive control, process repeat, build seal,
  frozen-input gate의 역할
- 한 physical x86_64 Linux host만 사용하며 cross-host 재현성이나 독립 사람 리뷰를
  주장하지 않는다는 한계
- mixed `valid_tuple`, chosen-ciphertext, operand-bin, full-signature Falcon의
  attribution 경계
- c-fn-dsa가 prospective comparator이며 FIPS 206 conformance 증거가 아니라는 점
- OpenSSL provider는 통합 사례이지 독립 implementation lineage가 아니라는 점

완료 기준: 숫자 하나 없어도 Methods와 연구 범위가 재현 가능하게 읽혀야 하고,
실험 결과를 보고 설계를 바꾼 것처럼 보이는 문장이 없어야 한다.

### P4. 이미 확정된 비-timing 결과 이관

다음은 최종 native timing과 분리된 기존 machine-readable 증거에서 생성할 수 있다.

- screening corpus의 family/target/build coverage
- correctness/KAT 통과 여부와 명시적 gap
- compiler/optimization matrix에서 늘어난 candidate coverage
- assembly 후보와 public/mixed/secret attribution 상태
- KyberSlash stock, KS1, KS2, combined, patched의 provenance와 equivalence
- Falcon reference/native-FP/integer-FPR 프로필의 구현 범위
- diverse upstream 및 OpenSSL provider integration 범위
- review readiness와 미완료 human-review 상태

단, 서로 다른 threat model의 결과를 하나의 “accuracy” 숫자로 합치거나 candidate
수를 false-positive rate라고 부르지 않는다.

완료 기준: 각 표의 원천 JSON/YAML/CSV와 생성 명령이 캡션 또는 artifact 문서에
추적 가능해야 한다.

### P5. 그림과 표의 골격 완성

- CT-KAT pipeline 그림을 영어 MDPI 스타일로 정리한다.
- evidence flow와 fail-closed fold를 한 장으로 설명한다.
- corpus/build coverage 표를 자동 생성한다.
- KyberSlash와 Falcon 비교표를 만든다.
- V10 timing용 28-axis 표는 열 이름과 정렬 규칙만 만들고 값은 비워 둔다.
- primary verdict, 최대 `|t|`, MDE/power, validity, control 상태를 서로 다른 열로
  유지한다.
- 단일 host의 세 process repeat를 세 대의 독립 장비처럼 표시하지 않는다.

완료 기준: 결과 JSON만 주어지면 손으로 숫자를 옮기지 않고 표가 생성될 구조여야
한다.

### P6. 결과 삽입 자동화 설계

최종 입력은 다음 named output으로 고정한다.

- `paper_native_analysis.json`
- `paper_native_axis_results.csv`
- `paper_native_pairwise_contrasts.csv`
- `paper_native_signature_length.csv`
- `paper_native_analysis.md`

준비할 것:

- 분석 JSON/CSV에서 MDPI용 LaTeX 표를 생성하는 renderer
- 28개 axis 누락, 중복, invalid 상태를 잡는 test
- old preliminary number가 새 MDPI source에 남았는지 검사하는 stale-value gate
- 표 값과 본문 요약값이 일치하는지 검사하는 assertion
- 동일 입력에서 byte-identical output을 요구하는 deterministic check

이 renderer 구현은 측정 checkout이 아닌 논문 브랜치에서 한다. V10 원자료가
동결된 뒤 실제 artifact를 넣어 최종 검증한다.

### P7. 결과 해석 문장 템플릿 준비

숫자를 예상해 문장을 미리 결론내리지 않고, 상태별 허용 문장만 준비한다.

| 분석 상태 | 허용 요약 | 금지 요약 |
|---|---|---|
| valid `FAIL` | risk detected under this host and protocol | key recovery proved / universally leaky |
| valid `WARNING` | needs further review | safe 또는 vulnerable 확정 |
| valid `PASS` | no finding observed under this host and protocol | constant-time proved |
| invalid/confounded | inconclusive; state the failed gate | PASS/FAIL로 재해석 |

secondary contrast나 signature-length association은 primary verdict를 뒤집지 않는다.
chosen-ciphertext는 public-input contrast이고 operand-bin은 hardware-latency canary다.

### P8. 재현성·제출용 후면 섹션 준비

- Code Availability: 저장소와 정확한 release/commit 자리
- Data Availability: final bundle/DOI 또는 archive URL 자리
- Supplementary Materials: manifests, raw/control/protocol CSV, validators,
  named analysis, SHA-256 목록
- Author Contributions: CRediT 역할 입력 자리
- Funding, Acknowledgments, Conflicts of Interest 입력 자리
- 한 host/no independent human review/no M4 execution을 명시할 limitation 문장
- 제출 ZIP에 포함할 파일 목록과 clean-room rebuild checklist

URL이나 DOI가 아직 없으면 가짜 값을 넣지 않고 `TBD`로 둔다.

### P9. 최종 결과 수거·검증 runbook 작성

측정이 끝난 뒤 우왕좌왕하지 않도록 다음 gate를 명령 단위로 미리 적어 둔다.

1. completion marker와 systemd service exit 확인
2. 네 component validator 실행
3. official dudect/TIMECOP/MicroWalk same-corpus baseline 확인
4. ML-KEM assembly evidence 확인
5. source/binary/compiler/config/build-seal과 host `SHA256SUMS` 확인
6. schema-v5 single-host bundle 생성 및 검증
7. named deterministic analysis 생성 후 `--check-output`
8. top-level SHA-256과 read-only archive 생성
9. 원격과 로컬 수신 manifest 비교
10. 그 뒤에만 논문 표 생성

partial 결과나 이전 v6/v7/v8/v9/engineering 결과는 빈칸 메우기에 사용하지 않는다.

### P10. 측정 외 코드 부채의 수정 설계

이번 실행에서 드러난 locale 의존 `nm -n` 동률 정렬 문제는 결과 동결 전에는
코드를 바꾸지 않는다. 지금 가능한 것은 다음 regression spec을 쓰는 것까지다.

- `C`와 `en_US.UTF-8`에서 같은 symbol set을 얻는지 검사
- 주소가 같은 text symbol 후보를 이름까지 포함해 canonical sort
- bundle validation 결과가 locale에 따라 바뀌지 않는지 검사
- 수정 커밋은 `measurement_commit` 뒤의 별도 maintenance commit으로 기록

이 수정은 현재 V10이 어느 커밋에서 측정됐는지를 소급해 바꾸지 않는다.

## 3. 최종 결과가 있어야만 가능한 작업

아래 항목은 기다리는 게 맞다.

- 28개 timing axis의 실제 통계와 validity 확정
- 각 axis의 `risk-detected`/`needs-review`/`inconclusive`/
  `no-finding-observed` 판정
- KyberSlash 취약/패치 canary의 최종 비교 문장
- Falcon-512/1024 reference/native-FP/integer-FPR의 최종 비교
- ML-KEM/ML-DSA portable 대 native 프로필 비교
- pairwise Holm-adjusted secondary contrast와 Falcon signature-length association
- Results의 timing 표·그림·본문
- Discussion에서 결과의 의미와 예상 밖 결과 분석
- Abstract와 Conclusions의 정량 문장
- final evidence root hash, Data Availability의 실제 archive 식별자
- 최종 paper-ready 판정, PDF, submission ZIP, release/tag

## 4. 사용자 결정이 필요한 항목

다음은 측정 결과와 별개지만 임의로 정하면 안 된다.

- 목표 MDPI 저널명과 article type
- 최종 제목
- 저자 순서, 소속, 이메일, corresponding author
- 연구비/과제번호
- code/data 공개 URL과 공개 시점
- acknowledgments와 conflict-of-interest 문구

목표 저널이 늦게 정해져도 Methods와 Results 골격까지는 generic MDPI ACS 기준으로
진행 가능하다. 저널 선택은 class option, scope 문구, 일부 back matter를 확정할 때
필요하다.

## 5. 권장 실행 순서와 예상 작업량

### 결과 대기 중

| 순서 | 작업 | 예상 소요 | 산출물 |
|---:|---|---:|---|
| 1 | 측정/논문 worktree 분리 | 15--30분 | 보호된 측정 checkout |
| 2 | 공식 MDPI ACS 템플릿 도입과 clean build | 30--60분 | MDPI 최소 PDF |
| 3 | 본문 이관표와 새 목차 확정 | 30--60분 | content map |
| 4 | Introduction/Related Work 영어 재작성 | 2--4시간 | 결과 독립 본문 |
| 5 | Materials and Methods 영어 재작성 | 3--5시간 | 재현 가능한 방법론 |
| 6 | 정적 결과 표와 그림 이관 | 2--4시간 | result-independent figures/tables |
| 7 | timing 표 renderer와 test 골격 | 1--3시간 | 결과 삽입 자동화 |
| 8 | back matter와 제출 checklist | 1--2시간 | MDPI 제출 골격 |

즉, 결과를 기다리는 동안 **집중 작업 약 1--2일치**는 충분히 있다. 이걸 먼저
끝내면 결과 도착 후 남는 일은 검증, 숫자 삽입, Discussion/Abstract/Conclusion
확정 위주로 줄어든다.

### 결과 도착 직후

| 순서 | 작업 | 예상 소요 |
|---:|---|---:|
| 1 | completion/hash/validator 확인과 로컬 보관 | 1--2시간 |
| 2 | schema-v5 bundle + named analysis 재생성 | 30--90분 |
| 3 | 자동 표 생성과 수치 교차검증 | 1--2시간 |
| 4 | Results/Discussion 작성 | 2--4시간 |
| 5 | Abstract/Conclusions/Limitations 동기화 | 1--2시간 |
| 6 | MDPI clean build, reference/claim/artifact audit | 2--4시간 |

## 6. 결과 대기 중 금지 사항

- native host repository pull, source 수정, threshold 수정, final resume/relabel
- partial 통계를 보고 실험 설계나 제외 기준 수정
- 예전 preliminary/native snapshot 숫자를 새 MDPI 논문에 재사용
- `PASS`를 constant-time proof로 표현
- 세 process repeat를 독립 host replication으로 표현
- 사람 리뷰 2명 또는 host 2대가 완료된 것처럼 표현
- M4 실행·검증이 이번 x86_64 V10에 포함된 것처럼 표현
- 논문용 표를 손으로 복붙하고 원천 artifact 연결을 끊는 행위

## 7. 결과 전 준비 완료의 판정 기준

아래가 전부 만족되면 “결과만 꽂으면 되는 상태”다.

- [x] 기존 LLNCS 원고는 보존되고 별도 MDPI 작업본이 존재한다.
- [x] 공식 MDPI 템플릿의 출처·버전·SHA-256이 기록돼 있다.
- [x] 새 원고가 공식 class를 포함한 독립 source tree에서 오류 없이 빌드된다.
- [x] Introduction, Related Work, Materials and Methods가 영어로 완성돼 있다.
- [x] 정적/구조적 결과 표는 machine-readable source에서 생성된다.
- [x] V10 timing 표는 28개 axis의 스키마와 누락 검사를 갖는다.
- [x] 새 원고에 과거 timing 숫자가 남아 있지 않다.
- [x] 상태별 주장 문구와 금지 문구가 test와 review checklist에 반영돼 있다.
- [x] 최종 수거·검증·분석·보관 runbook이 준비돼 있다.
- [x] author/funding/journal/data URL 외에는 불필요한 `TBD`가 없다.
- [x] 측정 checkout과 결과 디렉터리는 건드리지 않고 논문 작업선만 분리했다.

## 8. M4 범위의 위치

M4는 이번 V10 native x86_64 timing 표를 완성하기 위한 선행 조건이 아니다.
현재 논문에는 다음처럼 제한적으로 둘 수 있다.

- desktop CT-KAT이 M4용 cross-compiled artifact를 구조적으로 검사하는 확장 방향
- ARM binary/ISA용 disassembly와 attribution backend가 추가로 필요하다는 점
- board execution과 on-device timing은 별도 검증 캠페인이라는 점

실제 M4 결과가 없는데 지원 완료라고 쓰지 않는다. 우선 MDPI 본문에서는 future
work 또는 architecture portability limitation으로 분리하고, 현재 V10 결과를
갈아엎는 이유로 사용하지 않는다.

## 9. 바로 다음 권장 배치

다음 작업은 한 묶음으로 진행하는 것이 가장 효율적이다.

1. `paper/mdpi-pre-results` 작업선 분리
2. 최신 공식 MDPI ACS 템플릿 도입
3. 최소 PDF와 one-command build 완성
4. 기존 LLNCS → MDPI content map 작성
5. 결과와 무관한 Introduction/Methods 및 정적 Results 이관

이 배치는 완료됐다. 반대로 timing 표의 실제 값과 최종 정량 결론은 bundle 검증이
끝날 때까지 손대지 않는다.
