from pathlib import Path

from ctkat.header_parser import (
    discover_headers,
    parse_functions,
    parse_header_file,
)

FIXTURES = Path(__file__).parent / "fixtures" / "headers"


def test_parses_single_line_declaration():
    text = "int foo(int a, const char *b);"
    sigs = parse_functions(text)
    assert len(sigs) == 1
    s = sigs[0]
    assert s.return_type == "int"
    assert s.name == "foo"
    assert [p.name for p in s.params] == ["a", "b"]
    assert [p.is_pointer for p in s.params] == [False, True]


def test_parses_multi_line_declaration():
    text = """
    int crypto_kem_keypair(
        uint8_t *pk,
        uint8_t *sk
    );
    """
    sigs = parse_functions(text)
    assert len(sigs) == 1
    s = sigs[0]
    assert s.name == "crypto_kem_keypair"
    assert [p.name for p in s.params] == ["pk", "sk"]
    assert all(p.is_pointer for p in s.params)


def test_strips_block_and_line_comments():
    text = """
    /* leading comment */
    int foo(int a); // trailing
    /*
     * multi
     * line
     */
    int bar(int b);
    """
    sigs = parse_functions(text)
    assert [s.name for s in sigs] == ["foo", "bar"]


def test_skips_preprocessor_directives():
    text = """
    #include <stdint.h>
    #define X 1
    #if defined(__cplusplus)
    extern "C" {
    #endif
    int foo(int a);
    #if defined(__cplusplus)
    }
    #endif
    """
    sigs = parse_functions(text)
    assert [s.name for s in sigs] == ["foo"]


def test_const_pointer_param():
    text = "int f(const uint8_t *p);"
    sigs = parse_functions(text)
    p = sigs[0].params[0]
    assert p.is_pointer
    assert p.is_const
    assert "const" in p.type
    assert "*" in p.type


def test_void_param_list_is_empty():
    text = "int f(void);"
    sigs = parse_functions(text)
    assert sigs[0].params == []


def test_toy_header_yields_two_functions():
    sigs = parse_header_file(FIXTURES / "toy.h")
    assert [s.name for s in sigs] == ["bad_compare", "safe_compare"]
    bc = sigs[0]
    assert [p.name for p in bc.params] == ["secret", "guess", "len"]


def test_kem_header_extracts_canonical_and_namespaced():
    sigs = parse_header_file(FIXTURES / "kem.h")
    names = [s.name for s in sigs]
    assert "crypto_kem_keypair" in names
    assert "crypto_kem_enc" in names
    assert "crypto_kem_dec" in names
    assert "PQCLEAN_TOY_CLEAN_crypto_kem_dec" in names


def test_sign_header_extracts_all_three():
    sigs = parse_header_file(FIXTURES / "sign.h")
    names = [s.name for s in sigs]
    assert set(names) == {
        "crypto_sign_keypair",
        "crypto_sign_signature",
        "crypto_sign_verify",
    }


def test_anonymous_pointer_param_gets_deterministic_index_name():
    # Regression: previously synthesized names used `hash(text) % 1000`,
    # which depends on PYTHONHASHSEED → different name across processes.
    # Now the index is used, so two parses give identical names.
    text = "int f(uint8_t *, const char *);"
    sigs1 = parse_functions(text)
    sigs2 = parse_functions(text)
    names1 = [p.name for p in sigs1[0].params]
    names2 = [p.name for p in sigs2[0].params]
    assert names1 == names2
    assert names1 == ["_arg0", "_arg1"]


def test_discover_headers_finds_all_three():
    found = discover_headers(FIXTURES)
    assert {p.name for p in found} == {"toy.h", "kem.h", "sign.h"}
