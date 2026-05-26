# CT-KAT — "내 함수에 dudect 걸어보기" 튜토리얼

`infer` 서브커맨드와 README의 yaml 참조만으로도 가능하지만, 처음 yaml을
쓰는 사용자가 한 번 따라가면 좋은 30-line 워크스루.

## 시나리오

내 라이브러리에 다음 함수가 있다고 가정:

```c
// include/secret_compare.h
int secret_compare(const uint8_t *secret, const uint8_t *guess, size_t len);
```

이게 constant-time인지 dudect로 확인하고 싶다.

## 1. PRNG로 채우는 가장 단순한 yaml

```yaml
project:
  name: my_lib
  language: c
  root: .

build:
  command: "make"
  workdir: .
  expected_artifacts:
    - lib/libmy.a            # build가 실제로 만들었는지 검증 (F10)

dudect:
  enabled: true
  measurements: 50000
  warmup: 1000
  batches: 10
  clock: auto                # 환경에 맞게 rdtsc / monotonic 선택
  seed: 0xC0FFEE
  timeout: 600
  workdir: .

  harnesses:
    - name: secret_compare
      template: generic
      extra_headers: [secret_compare.h]
      include_dirs: [include]
      sources: [src/secret_compare.c]
      function: secret_compare
      return_type: int
      args: [secret, guess, "sizeof(secret)"]
      buffers:
        - {name: secret, size: "16", role: secret}
        - {name: guess,  size: "16", role: public}
```

**해설**:

- `args`는 C 호출 그대로의 식. 버퍼 이름과 sizeof 표현 그대로 들어감.
- `buffers[i].role` — `secret`은 class 0/1 분기에서 fixed 또는 random
  으로 채워짐. `public`은 매 호출 같은 값. `output`은 출력 버퍼 (호출 후
  Valgrind 관점에서 결과 보호용).
- `dudect.timeout` 미설정 시 600s default. 한 함수 호출이 비싼 경우 늘릴 것.

## 2. 실행

```bash
$ python -m ctkat dudect --config ctkat.yaml
```

출력의 핵심:

```
==> Generate timing harness: secret_compare
==> Run timing harness: secret_compare (this may take a while)
   n0=24910 n1=25030 mean0=120.3 mean1=124.7 t=+8.42 crop@0.95 [WARNING]
```

- `n0`/`n1`: zero-filter 후 클래스별 sample 수. raw count는 CSV col 18-20.
- `|t|`가 4.5 미만이면 PASS, 4.5–10이면 WARNING, ≥10이면 FAIL.
- `crop@0.95`: percentile cropping이 잡아낸 cutoff. 0.95면 상위 5% 떨어뜨림.

## 3. 결과 파일

- `reports/dudect_summary.csv` — 통계 요약 (21개 컬럼, README §"dudect_summary.csv 컬럼 reference" 참고)
- `reports/dudect_raw_timings.csv` — 원시 cycle 측정 (재현성 디버깅용)

PASS면 일단 통과. WARNING이면 다음 단계.

## 4. WARNING 이 떴을 때

**a) 환경 노이즈 확인** (R3): 같은 yaml을 두 번 더 돌려서 \|t\| 분포 확인.
±20% 정도 흔들리는 게 정상. status가 매번 WARNING이면 진짜 신호 의심.

**b) per-class drop 비대칭 경고 확인** (F4/S2): console에 
"zero-cycle filter asymmetric" 메시지가 떴다면 한 클래스의 slow tail로
편향된 표본. 호스트가 너무 느리거나 함수가 너무 빠를 가능성.

**c) Cohen's d 보기** (S3): `dudect_summary.csv` col 21. \|d\|>0.5면 효과가
실재로 큰 것이고 \|d\|<0.2면 sample size로 부풀려진 \|t\|.

**d) `--no-crop`으로 다시 돌려서 cropping 부작용 확인**: 외부 dudect와
숫자 비교하고 싶을 때 유용.

**e) 그래도 WARNING이면 실제 leak일 가능성**. ct 검사도 추가해서 구조적
확인 (README §"yaml 전체 필드" ct 섹션 참고).

## 5. 다음 단계 — 결합 verdict

dudect만으로는 한쪽 측면 — Valgrind ct 검사도 yaml에 같이 넣으면
combined verdict (CLEAN / LOW_RISK / SUSPECT / RISKY / CRITICAL /
INCONCLUSIVE)가 나옴. CT 자동 모드의 보일러플레이트는 `examples/toy_dudect/
ctkat_combined.yaml` 참고.

## 자주 빠지는 함정

- **secret_regions 설정이 작으면 silent 부분 검사**: ML-KEM의 sk는 2400
  바이트지만 `length: 32`로 적으면 32바이트만 taint됨. Bundle F의 F6
  coverage probe가 <50% 발견 시 yellow warning, fix하지 않으면 결과가
  부정확.
- **PQClean KEM 하니스의 reproducibility**: yaml `seed`는 자동 생성
  하니스 PRNG만 제어한다. PQClean `crypto_kem_keypair/enc`는 OS entropy
  (`getrandom`)를 쓰기 때문에 시드로 재현되지 않음 (R1 Option A docs caveat).
- **manual binary mode 사용 시**: `ct.require_sentinel: true` + binary
  stdout에 `CTKAT-HARNESS-RAN: <name>` 박는 것 권장 (F5). /bin/true도
  silent PASS되는 fail-open 회피.

## See also

- `README.md` — 모든 yaml 필드 + verdict matrix
- `docs/known_issues.md` — 해결된/잔여 이슈와 trade-off
- `examples/toy_dudect/ctkat_combined.yaml` — ct + dudect 같이 돌리는 예제
- `examples/pqc_mlkem768/` — PQClean ML-KEM-768 실전 yaml
