# `nm -n` 동일 주소 symbol의 locale 독립 canonicalization 명세

상태: **설계 완료, V10 artifact 동결 전 source 수정 금지**
영향 코드: `ctkat/asm_scan.py::parse_nm`
측정 commit: `1aeadb97e0409227aa203ba825a6bfc1d90445bc`

## 문제를 개쉽게 말하면

object 안에서 여러 symbol이 같은 주소를 가리킬 수 있다. 현재 parser는 global/local과
linker-temp 여부가 같으면 `nm -n` 출력에서 **먼저 나온 이름**을 채택한다. 그런데
`nm`의 같은-address 정렬 순서는 locale에 따라 달라질 수 있다. 그러면 binary는 완전히
같은데 `C` locale과 `en_US.UTF-8`에서 함수 이름 attribution 또는 artifact byte가
달라질 수 있다. 암호 수치가 변한 게 아니라, 이름표 고르는 규칙이 외부 정렬에
의존하는 재현성 버그다.

현재 V10 launcher가 `en_US.UTF-8`을 고정한 것은 해당 측정 내부 일관성을 확보하는
운영 조치다. 그러나 source parser 자체가 deterministic하다는 뜻은 아니다.

## 왜 지금 코드를 바로 안 고치는가

V10 final은 위 commit의 source, binary, manifest, control qualification에 묶여 있다.
측정 중 `parse_nm`을 고치면 commit과 assembly evidence seal이 달라져 이미 얻은
component를 섞어 쓸 수 없다. 따라서 순서는 다음으로 고정한다.

1. V10 final과 named analysis를 frozen commit에서 끝낸다.
2. 전체 artifact hash를 검증하고 원본을 보존한다.
3. 논문은 그 측정 commit을 그대로 기록한다.
4. 별도 유지보수 commit에서 canonical parser와 regression test를 적용한다.
5. 수정판은 “측정 결과를 만든 source”인 척하지 않고 post-freeze reproducibility
   fix로 CHANGELOG/artifact 문서에 남긴다.

이 버그는 최종 V10을 통째로 다시 측정하라는 뜻이 아니다. frozen run 내부가 한
locale로 수행되고 hash/validator가 맞으면 그 결과는 해당 환경에 대해 쓸 수 있다.

## 요구 동작

`parse_nm(text)`는 입력 line 순서가 어떻든 같은 `[(address, name)]`을 반환해야 한다.

1. `t`와 `T` text symbol만 취급한다.
2. Mach-O leading underscore 하나를 제거한 이름을 `normalized_name`으로 둔다.
3. 주소별 후보를 전부 모은 뒤 다음 canonical tuple을 오름차순으로 비교한다.

```text
(
  0 if type == "T" else 1,                 # global 우선: 기존 의미 보존
  0 if not linker_temp(normalized_name) else 1,
  normalized_name encoded/compared by Python code-point order,
  original_name encoded/compared by Python code-point order,
  type
)
```

4. 각 주소에서 최소 tuple 하나만 선택한다.
5. 최종 목록은 numeric address 순으로 정렬한다.
6. locale-aware collation API를 호출하지 않는다.

Python의 일반 문자열 비교는 process locale의 collation 순서를 사용하지 않으므로,
명시적인 문자열 key는 locale-independent하다. `LC_ALL=C` 강제도 방어층으로 둘 수
있지만 parser의 결정성을 대신해서는 안 된다.

## 권장 구현 형태

```python
by_addr: dict[int, list[tuple[str, str, str]]] = defaultdict(list)
# append (typ, original_name, normalized_name)

def canonical_key(item):
    typ, original, normalized = item
    return (
        0 if typ == "T" else 1,
        0 if not _is_temp_symbol(normalized) else 1,
        normalized,
        original,
        typ,
    )

return sorted((addr, min(candidates, key=canonical_key)[2]) ...)
```

실제 patch에서는 type annotation과 기존 함수 스타일을 맞추고, 중복 line도 동일한
결과가 되게 한다.

## 필수 regression test

### 1. 순열 불변성

같은 주소에 global real symbol 두 개, local real symbol, global/local temp symbol을
둔 fixture를 만든다. 모든 line permutation 또는 충분한 무작위 permutation에서
결과가 byte-identical이어야 한다. 기존 테스트처럼 global 대 local 하나만 두면 이
버그를 못 잡는다.

### 2. locale 출력 불변성

동일 후보 집합을 `C`, `C.UTF-8`, `en_US.UTF-8`, `ko_KR.UTF-8` 순서로 흉내 낸
fixture에 각각 넣고 같은 결과를 요구한다. 설치되지 않은 OS locale 때문에 단위
테스트가 skip되지 않도록 핵심 테스트는 subprocess가 아니라 line permutation으로
작성한다.

### 3. 실제 tool integration

지원되는 host에서는 equal-address alias가 있는 작은 C/assembly object를 만든 뒤
다음 출력을 parser에 넣는다.

```bash
LC_ALL=C nm -n object.o
LC_ALL=en_US.UTF-8 nm -n object.o
```

해당 locale 또는 toolchain이 없으면 integration test만 명시적으로 skip한다.

### 4. 기존 의미 보존

- global real + local temp → global real
- global temp + local real → 기존 global 우선 정책
- Mach-O `_function` → `function`
- undefined symbol 제외
- malformed address 제외
- address가 여러 개면 numeric ascending
- `resolve_functions`가 greatest-address-`<=` hit 규칙을 유지

## 완료 조건

- permutation test가 옛 구현에서는 실패하고 새 구현에서 통과한다.
- 지원되는 locale integration이 같은 symbol list와 assembly artifact를 낸다.
- 전체 `tests/test_asm_scan.py`와 artifact reproduction test가 통과한다.
- CHANGELOG에 post-V10 reproducibility fix로 기록한다.
- V10 raw/named artifact는 수정하거나 재생성하지 않는다.

## 논문에 미치는 영향

본문에는 V10이 고정 locale과 exact commit에서 실행됐다는 재현성 조건만 적는다.
이 maintenance fix를 새로운 leakage detector나 timing 결과로 과장하지 않는다.
향후 artifact release에서 측정 commit과 maintenance/source-release commit을 둘 다
표시하면 된다.
