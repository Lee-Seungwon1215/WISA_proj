# CT-KAT MDPI 제출 체크리스트

이 문서는 “PDF가 뜬다”와 “투고해도 된다”를 구분하는 최종 게이트다.

## A. 지금 자동으로 끝난 항목

- [x] 공식 2026 MDPI ACS bundle 출처와 SHA-256 고정
- [x] 영문 MDPI 단일 원고 및 bibliography 이관
- [x] 필수 본문 7개 섹션과 MDPI 후면 선언 골격
- [x] 정적 corpus/ablation/V10 scope 표 자동 생성
- [x] native 결과 pending/complete 분리 및 28-axis fail-closed renderer
- [x] 옛 WISA 수치·verdict·클래스 유입 검사
- [x] citation/label/generated-byte/LaTeX-log 검사
- [x] 단일 빌드 명령과 결과 회수 런북
- [x] single-host, no independent review, M4 미지원 한계 명시

## B. V10 결과가 나온 직후

- [ ] 원격 marker가 성공이고 모든 component/baseline 디렉터리가 하나씩 존재
- [ ] schema-v5 bundle 생성 및 전체 SHA-256 검증
- [ ] frozen clean commit에서 named analyzer 최초 실행 성공
- [ ] 같은 checkout에서 `--check-output` byte-identical 재검증
- [ ] `paper_native_analysis.json` SHA-256 별도 기록
- [ ] 논문 브랜치에서 `build_mdpi_paper.sh --analysis ... --refresh` 성공
- [ ] native table이 정확히 28축이고 pending marker가 0개인지 확인
- [ ] 결과 문장에 host/protocol scope와 attribution boundary가 유지되는지 읽기 검토
- [ ] raw/derived artifact archive 생성 및 안정된 DOI/URL 확보

결과가 이상하거나 일부만 있으면 표를 채우지 않는다. `inconclusive`는 실패를 숨기는
표현이 아니라 유효성 조건이 충족되지 않았다는 정식 결과다.

## C. 사용자가 정해야 하는 항목

- [ ] 실제 MDPI 목표 저널 및 최신 journal class option
- [ ] article type과 special issue 여부
- [ ] 제목 최종안
- [ ] 저자 순서, 영문 이름, ORCID, 소속, 이메일, 교신저자
- [ ] CRediT author contributions
- [ ] funding/grant number 또는 “no external funding” 확정
- [ ] conflicts of interest 확정
- [ ] 기관/비저자 acknowledgment 확정
- [ ] AI assistance disclosure가 해당 저널 최신 정책과 맞는지 확인
- [ ] 코드 저장소 공개 범위와 artifact DOI/영구 URL
- [ ] supplementary archive 크기 및 업로드 방식

## D. 내용/주장 최종 점검

- [ ] `PASS`를 constant-time proof로 부른 문장이 없음
- [ ] single-host 결과를 architecture/general reproducibility로 확장하지 않음
- [ ] process repeat를 독립 host로 세지 않음
- [ ] chosen-ciphertext = public-input contrast로 유지
- [ ] valid-tuple = public+secret mixed axis로 유지
- [ ] operand-bin = hardware-latency canary로 유지
- [ ] Falcon full-signature의 variable-length encoding을 숨기지 않음
- [ ] c-fn-dsa prospective/FIPS 206 비적합성 경계 유지
- [ ] OpenSSL provider를 별도 lineage로 세지 않음
- [ ] M4를 구현·측정했다고 쓰지 않음
- [ ] candidate burden을 accuracy/FPR로 바꾸지 않음

## E. 제출 패키지 게이트

```bash
bash scripts/build_mdpi_paper.sh \
  --analysis /path/to/v10-named/paper_native_analysis.json
```

- [ ] 위 명령 성공
- [ ] undefined citation/reference 0개
- [ ] 2 pt 초과 overfull box 0개
- [ ] PDF 첫 페이지, 모든 표, 참고문헌, 마지막 페이지 육안 확인
- [ ] 제출 ZIP에 `main.tex`, `references.bib`, `generated/`, `Definitions/`, 필요한
  그림이 모두 포함
- [ ] clean 임시 디렉터리에서 ZIP 단독 재빌드
- [ ] PDF metadata/저자 익명화 정책이 실제 review mode와 일치
- [ ] 최종 Git commit, tag, source archive SHA-256 기록

## 제출 가능 판정

자동 게이트와 B~E가 모두 끝나야 `submission-ready`다. 지금 상태는
`MDPI pre-result manuscript ready`이며, 결과가 비어 있다는 사실을 숨기지 않는
정상적인 대기 상태다.
