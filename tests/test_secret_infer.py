from pathlib import Path

from ctkat.header_parser import parse_header_file
from ctkat.secret_infer import infer_function, infer_functions


FIXTURES = Path(__file__).parent / "fixtures" / "headers"


def _by_name(funcs, name):
    for f in funcs:
        if f.signature.name == name:
            return f
    raise AssertionError(f"function {name!r} not found")


def test_kem_dec_profile_assigns_canonical_roles():
    sigs = parse_header_file(FIXTURES / "kem.h")
    inferred = infer_functions(sigs)
    dec = _by_name(inferred, "crypto_kem_dec")
    assert dec.profile == "kem_dec"
    roles = [a.role for a in dec.assignments]
    assert roles == ["output", "public", "secret"]
    # All assignments should cite the profile match in their reason.
    for a in dec.assignments:
        assert "profile=kem_dec" in a.reason


def test_pqclean_namespace_prefix_still_matches_profile():
    sigs = parse_header_file(FIXTURES / "kem.h")
    inferred = infer_functions(sigs)
    ns_dec = _by_name(inferred, "PQCLEAN_TOY_CLEAN_crypto_kem_dec")
    assert ns_dec.profile == "kem_dec"
    assert [a.role for a in ns_dec.assignments] == ["output", "public", "secret"]


def test_sign_signature_profile_includes_scalar_lengths():
    sigs = parse_header_file(FIXTURES / "sign.h")
    inferred = infer_functions(sigs)
    sign = _by_name(inferred, "crypto_sign_signature")
    assert sign.profile == "sign_signature"
    roles = [a.role for a in sign.assignments]
    # sig, siglen, msg, msglen, sk
    assert roles == ["output", "output", "public", "scalar", "secret"]


def test_toy_compare_keyword_heuristic():
    sigs = parse_header_file(FIXTURES / "toy.h")
    inferred = infer_functions(sigs)
    bc = _by_name(inferred, "bad_compare")
    assert bc.profile is None
    by_name = {a.param.name: a for a in bc.assignments}
    # 'secret' is a keyword match
    assert by_name["secret"].role == "secret"
    # 'guess' is NOT in any keyword set → unknown (conservative)
    assert by_name["guess"].role == "unknown"
    # 'len' is scalar (not a pointer)
    assert by_name["len"].role == "scalar"


def test_scalar_param_classified_even_without_keyword_match():
    from ctkat.header_parser import parse_functions
    sigs = parse_functions("int f(int n);")
    inferred = infer_function(sigs[0])
    assert inferred.profile is None
    assert inferred.assignments[0].role == "scalar"
