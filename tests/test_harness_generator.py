import pytest

from ctkat.harness_generator import (
    HarnessGenerationError,
    render_harness,
)


def _generic_ctx(**overrides):
    ctx = {
        "extra_headers": ["compare.h"],
        "function": "bad_compare",
        "args": ["secret", "guess", "sizeof(secret)"],
        "return_type": "int",
        "buffers": [
            {"name": "secret", "size": "16", "role": "secret"},
            {"name": "guess", "size": "16", "role": "public"},
        ],
        "seed": 0xC0FFEE,
    }
    ctx.update(overrides)
    return ctx


def test_generic_render_contains_taint_markers():
    out = render_harness("generic", _generic_ctx())
    # secret buffer is tainted before the call and restored after
    assert "VALGRIND_MAKE_MEM_UNDEFINED(secret" in out
    assert "VALGRIND_MAKE_MEM_DEFINED(secret" in out
    # public buffer is NOT tainted
    assert "VALGRIND_MAKE_MEM_UNDEFINED(guess" not in out


def test_generic_render_call_line_includes_args():
    out = render_harness("generic", _generic_ctx())
    assert "bad_compare(secret, guess, sizeof(secret))" in out


def test_generic_render_keeps_return_value():
    out = render_harness("generic", _generic_ctx(return_type="int"))
    assert "int __ctkat_ret = bad_compare(" in out


def test_generic_render_void_return_no_ret_variable():
    out = render_harness("generic", _generic_ctx(return_type="void"))
    assert "__ctkat_ret" not in out
    # bare call line still present
    assert "bad_compare(secret, guess, sizeof(secret));" in out


def test_generic_render_includes_extra_headers():
    out = render_harness("generic", _generic_ctx(extra_headers=["a.h", "b.h"]))
    assert '#include "a.h"' in out
    assert '#include "b.h"' in out


def test_generic_render_uses_deterministic_prng_not_libc_rand():
    # Regression: srand(time(NULL)) + rand() made CT runs non-reproducible,
    # inconsistent with dudect's xorshift+seed. Now both stages use the same
    # baked-seed xorshift. Match the *call* form so the explanation comment
    # (which mentions srand by name) doesn't trip the assertion.
    out = render_harness("generic", _generic_ctx(seed=0xDEADBEEF))
    assert "srand(" not in out
    assert "rand() &" not in out
    assert "ctkat_prng_next" in out
    assert f"CTKAT_SEED {0xDEADBEEF}ULL" in out


def test_generic_render_emits_volatile_sink_to_resist_O2_dce():
    # Regression: without a volatile sink the compiler may dead-code-eliminate
    # the entire target call at -O2, leaving Valgrind with nothing to analyze.
    out = render_harness("generic", _generic_ctx())
    assert "volatile uint64_t __ctkat_sink" in out
    # The (void) cast on its own isn't enough — sink must actually consume
    # at least one byte related to the call.
    assert "__ctkat_sink ^=" in out


def test_generic_render_marks_output_buffers_defined():
    ctx = _generic_ctx(buffers=[
        {"name": "secret", "size": "16", "role": "secret"},
        {"name": "result", "size": "16", "role": "output"},
    ])
    out = render_harness("generic", ctx)
    # output buffer should be marked DEFINED after the call (so subsequent reads
    # don't trigger false positives)
    assert "VALGRIND_MAKE_MEM_DEFINED(result" in out


def test_kem_render_contains_dec_taint():
    out = render_harness("kem", {"header": "api.h", "prefix": "", "extra_headers": [], "secret_regions": []})
    assert '#include "api.h"' in out
    assert "VALGRIND_MAKE_MEM_UNDEFINED(sk" in out
    assert "crypto_kem_dec(ss_actual, ct, sk);" in out


def test_kem_render_has_no_memcmp_kat_check():
    # Correctness (enc/dec roundtrip) is a KAT concern, not a CT one — it
    # lives in a separate binary now (see doc §7.1 vs §13.4 mismatch).
    out = render_harness("kem", {"header": "api.h", "prefix": "", "extra_headers": [], "secret_regions": []})
    assert "memcmp" not in out
    assert "KAT/runtime check" not in out


def test_kem_render_uses_volatile_sink_to_keep_dec_alive():
    # Without sinking the result, -O2 can DCE the dec call entirely.
    out = render_harness("kem", {"header": "api.h", "prefix": "", "extra_headers": [], "secret_regions": []})
    assert "volatile" in out
    assert "ctkat_sink" in out


def test_kem_render_applies_pqclean_prefix():
    out = render_harness("kem", {
        "header": "api.h",
        "prefix": "PQCLEAN_MLKEM768_CLEAN_",
        "extra_headers": [],
        "secret_regions": [],
    })
    assert "PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(" in out
    assert "PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES" in out


def test_kem_render_partial_taint_with_secret_regions():
    # When ML-KEM-style sk holds public material inside, we taint only the
    # listed byte ranges instead of the whole buffer.
    out = render_harness("kem", {
        "header": "api.h",
        "prefix": "PQCLEAN_MLKEM768_CLEAN_",
        "extra_headers": [],
        "secret_regions": [
            {"offset": "0", "length": "1152", "comment": "indcpa secret s"},
            {"offset": "2368", "length": "32", "comment": "FO rejection seed z"},
        ],
    })
    assert "VALGRIND_MAKE_MEM_UNDEFINED(sk + (0), (1152));" in out
    assert "VALGRIND_MAKE_MEM_UNDEFINED(sk + (2368), (32));" in out
    # Full-buffer taint must NOT be emitted when regions are given
    assert "VALGRIND_MAKE_MEM_UNDEFINED(sk, sizeof(sk))" not in out


def _sign_ctx(**overrides):
    ctx = {
        "header": "api.h",
        "extra_headers": [],
        "prefix": "",
        "secret_regions": [],
    }
    ctx.update(overrides)
    return ctx


def test_sign_render_basic_taint():
    out = render_harness("sign", _sign_ctx())
    assert "VALGRIND_MAKE_MEM_UNDEFINED(sk, sizeof(sk));" in out
    assert "crypto_sign_signature(sig, &siglen, msg, sizeof(msg), sk);" in out


def test_sign_render_emits_volatile_sink_to_resist_O2_dce():
    # Regression: previously sig/siglen were never consumed after the
    # signature call, so -O2 could DCE the entire call and leave Valgrind
    # to analyze a no-op. Matches the sink pattern in kem and generic.
    out = render_harness("sign", _sign_ctx())
    assert "volatile uint64_t ctkat_sink" in out
    assert "ctkat_sink ^=" in out


def test_sign_render_applies_pqclean_prefix():
    out = render_harness("sign", _sign_ctx(prefix="PQCLEAN_MLDSA65_CLEAN_"))
    assert "PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(" in out
    assert "PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES" in out


def test_sign_render_secret_regions_partial_taint():
    # Regression for the bug where sign template silently ignored
    # secret_regions. With this fixture set, only the listed ranges should
    # be tainted, NOT the whole sk buffer.
    out = render_harness("sign", _sign_ctx(
        prefix="PQCLEAN_MLDSA65_CLEAN_",
        secret_regions=[
            {"offset": "0", "length": "32", "comment": "rho seed"},
            {"offset": "1024", "length": "256", "comment": "s1 secret"},
        ],
    ))
    assert "VALGRIND_MAKE_MEM_UNDEFINED(sk + (0), (32));" in out
    assert "VALGRIND_MAKE_MEM_UNDEFINED(sk + (1024), (256));" in out
    # Full-buffer taint must NOT be emitted when regions are given
    assert "VALGRIND_MAKE_MEM_UNDEFINED(sk, sizeof(sk))" not in out


def test_unknown_template_raises():
    with pytest.raises(HarnessGenerationError):
        render_harness("nonsense", {})


# --- Bundle P (T19): atomic write helper -------------------------------


def test_atomic_write_text_replaces_full_content(tmp_path):
    """T19 regression: `_atomic_write_text` must produce the final file
    via rename, not via incremental append/truncate. Verified by writing
    twice and asserting only the second content survives intact."""
    from ctkat.harness_generator import _atomic_write_text
    target = tmp_path / "harness_foo.c"
    _atomic_write_text(target, "first contents\n")
    _atomic_write_text(target, "second contents\n")
    assert target.read_text(encoding="utf-8") == "second contents\n"
    # No leftover .tmp files from the rename pattern.
    leftover = [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")]
    assert not leftover, f"atomic_write left tmp files behind: {leftover}"


def test_atomic_write_text_uses_utf8_encoding(tmp_path):
    """`_atomic_write_text` opens the tempfile with encoding='utf-8'
    explicitly so a non-utf-8 locale (Windows cp1252) doesn't corrupt
    Korean comments / non-ASCII source. T19 + T21 family."""
    from ctkat.harness_generator import _atomic_write_text
    target = tmp_path / "harness.c"
    body = "/* 한글 주석 */\nint main(void){return 0;}\n"
    _atomic_write_text(target, body)
    assert target.read_bytes() == body.encode("utf-8")


# --- Phase C: compile_harness `cc` parameterization -------------------------

class _FakeProc:
    returncode = 0
    stdout = ""
    stderr = ""


def test_compile_harness_uses_given_cc(tmp_path, monkeypatch):
    # ct-matrix recompiles the same harness under several compilers; the cc
    # must reach argv[0] and the returned command string.
    from ctkat import harness_generator as hg
    captured = {}

    def fake_run_text(cmd, *a, **k):
        captured["cmd"] = cmd
        return _FakeProc()

    monkeypatch.setattr(hg, "run_text", fake_run_text)
    src = tmp_path / "h.c"
    src.write_text("int main(void){return 0;}\n")
    cmd_str = hg.compile_harness(
        source_path=src, binary_path=tmp_path / "h", sources=[],
        include_dirs=[], cflags=["-O2"], workdir=tmp_path, timeout=30, cc="clang",
    )
    assert captured["cmd"][0] == "clang"
    assert cmd_str.startswith("clang ")


def test_compile_harness_defaults_to_gcc(tmp_path, monkeypatch):
    # No cc => gcc, so the single-build ct stage is unchanged.
    from ctkat import harness_generator as hg
    captured = {}

    def fake_run_text(cmd, *a, **k):
        captured["cmd"] = cmd
        return _FakeProc()

    monkeypatch.setattr(hg, "run_text", fake_run_text)
    src = tmp_path / "h.c"
    src.write_text("int main(void){return 0;}\n")
    hg.compile_harness(
        source_path=src, binary_path=tmp_path / "h", sources=[],
        include_dirs=[], cflags=["-O0"], workdir=tmp_path, timeout=30,
    )
    assert captured["cmd"][0] == "gcc"
