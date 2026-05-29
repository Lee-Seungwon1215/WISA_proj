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


# --- Bundle H2: T11 function-pointer / nested-paren skip count -----------


def test_parse_functions_with_stats_counts_function_pointer_skips():
    from ctkat.header_parser import parse_functions_with_stats
    text = (
        "int foo(int x);\n"
        "int register_cb(int (*cb)(int));\n"     # function pointer — strict miss
        "int bar(const uint8_t *p);\n"
    )
    sigs, skipped = parse_functions_with_stats(text)
    names = {s.name for s in sigs}
    assert "foo" in names
    assert "bar" in names
    # `register_cb` is silently skipped by the strict regex; loose match
    # picks it up so the count is 1.
    assert skipped == 1


def test_parse_functions_with_stats_zero_skips_on_clean_header():
    from ctkat.header_parser import parse_functions_with_stats
    text = "int foo(int x);\nvoid bar(void);\n"
    _, skipped = parse_functions_with_stats(text)
    assert skipped == 0


# --- R-3 (T31/T32/T36): header parser correctness regressions ---------------


def test_attribute_with_nested_parens_does_not_drop_function():
    """T31: `__attribute__((nonnull(1)))` has nested parens. The old strip
    regex stopped at the first inner `)`, leaving a stray `)` that broke the
    decl regex — the whole function vanished from `infer` and wasn't even
    counted in the skip total. It must now parse normally."""
    from ctkat.header_parser import parse_functions_with_stats
    text = (
        "int with_attr(unsigned char *bar) __attribute__((nonnull(1)));\n"
        "int plain(unsigned char *x);\n"
    )
    sigs, skipped = parse_functions_with_stats(text)
    names = [s.name for s in sigs]
    assert "with_attr" in names
    assert "plain" in names
    assert skipped == 0


def test_attribute_format_printf_nested_parens():
    """T31: a second nested-paren attribute shape."""
    text = 'int logf(const char *fmt) __attribute__((format(printf, 1, 2)));\n'
    sigs = parse_functions(text)
    assert [s.name for s in sigs] == ["logf"]


def test_anonymous_double_pointer_is_pointer():
    """T32: `uint8_t **` is an anonymous double pointer. The old code set
    name='**', is_pointer=False, so secret_infer treated a double-pointer
    buffer as a scalar (never tainted). It must be is_pointer=True with a
    synthesized name."""
    from ctkat.header_parser import _parse_param
    p = _parse_param("unsigned char **", 0)
    assert p is not None
    assert p.is_pointer is True
    assert p.name == "_arg0"
    assert "*" in p.type


def test_bare_type_param_keeps_type_not_name():
    """T32: a lone `size_t` is an unnamed param whose token is the TYPE. The
    old code stored name='size_t', type='' — losing the type entirely."""
    from ctkat.header_parser import _parse_param
    p = _parse_param("size_t", 1)
    assert p is not None
    assert p.type == "size_t"
    assert p.name == "_arg1"
    assert p.is_pointer is False


def test_source_line_accurate_after_multiline_comment():
    """T36: a multi-line `/* ... */` before a declaration used to collapse to
    a single space, shifting the reported source_line up by the comment
    height. The function below is on original line 4."""
    text = "/* line1\n   line2\n   line3 */\nint foo(void);\n"
    sigs = parse_functions(text)
    assert sigs[0].name == "foo"
    assert sigs[0].source_line == 4
