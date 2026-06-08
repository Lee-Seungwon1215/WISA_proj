import pytest

from ctkat.timing_harness_generator import render_timing_harness
from ctkat.harness_generator import HarnessGenerationError


def _ctx(**overrides):
    ctx = {
        "extra_headers": ["leaky.h"],
        "function": "leaky_function",
        "args": ["secret", "sizeof(secret)"],
        "return_type": "int",
        "buffers": [
            {"name": "secret", "size": "16", "role": "secret"},
        ],
        "measurements": 1000,
        "warmup": 10,
        "seed": 0xC0FFEE,
        "clock": "monotonic",
    }
    ctx.update(overrides)
    return ctx


def test_monotonic_template_uses_clock_gettime():
    out = render_timing_harness("generic", _ctx(clock="monotonic"))
    assert "clock_gettime" in out
    assert "CLOCK_MONOTONIC_RAW" in out
    assert "__rdtscp" not in out
    assert "<time.h>" in out


def test_rdtsc_template_uses_x86intrin():
    out = render_timing_harness("generic", _ctx(clock="rdtsc"))
    assert "__rdtscp" in out
    assert "<x86intrin.h>" in out


def test_seed_is_baked_into_source():
    # Python `int` renders in decimal — we don't care about the literal form
    # in C, just that the numeric value lands in the CTKAT_SEED macro.
    out = render_timing_harness("generic", _ctx(seed=0xDEADBEEF))
    assert f"CTKAT_SEED         {0xDEADBEEF}ULL" in out


def test_measurements_and_warmup_baked_in():
    out = render_timing_harness("generic", _ctx(measurements=12345, warmup=678))
    assert "CTKAT_MEASUREMENTS 12345" in out
    assert "CTKAT_WARMUP       678" in out


def test_secret_buffer_has_fixed_variant():
    out = render_timing_harness("generic", _ctx())
    # class-0 fixed buffer
    assert "secret_fixed" in out
    # class-1 fresh random fill
    assert "rand_bytes(secret" in out


def test_function_call_appears_inside_timed_region():
    out = render_timing_harness("generic", _ctx())
    assert "leaky_function(secret, sizeof(secret))" in out
    # I/O after the timed loop, not inside
    timed_loop_start = out.find("for (size_t i = 0; i < CTKAT_MEASUREMENTS")
    printf_pos = out.find('printf("sample_id')
    assert timed_loop_start > 0
    assert printf_pos > 0
    assert printf_pos > timed_loop_start


def test_unknown_template_raises():
    with pytest.raises(HarnessGenerationError):
        render_timing_harness("nonsense", _ctx())


# --- Bundle A: measurement-quality hardening -----------------------------------


def test_rdtsc_clock_has_lfence_serialization():
    out = render_timing_harness("generic", _ctx(clock="rdtsc"))
    # lfence on both sides of __rdtscp drains in-flight insns and prevents
    # speculation past the cycle sample. At least two occurrences expected.
    assert out.count("_mm_lfence") >= 2


def test_monotonic_clock_does_not_use_lfence():
    out = render_timing_harness("generic", _ctx(clock="monotonic"))
    # clock_gettime is already a sync point; lfence is x86-only and would
    # break the ARM/portable path.
    assert "_mm_lfence" not in out


def test_class_label_uses_high_bits_of_prng():
    out = render_timing_harness("generic", _ctx())
    # xorshift64 LSB has weak diffusion; class assignment must shift right
    # to use the upper word.
    assert "prng_next() >> 32" in out
    # The old LSB pattern must be gone.
    assert "prng_next() & 1ULL" not in out


def test_nonvoid_return_uses_ctkat_use_macro():
    # default _ctx() has return_type="int" — the return must be materialized
    # by CTKAT_USE so the optimizer cannot prune the call as dead.
    out = render_timing_harness("generic", _ctx())
    assert "CTKAT_USE(__ctkat_ret)" in out


def test_void_return_does_not_capture():
    out = render_timing_harness("generic", _ctx(return_type="void"))
    # No return-value capture line for void.
    assert "__ctkat_ret" not in out
    # The function call itself is still present.
    assert "leaky_function(secret, sizeof(secret))" in out


def test_underflow_clamp_present():
    # Guards against uint64 wrap when t1 < t0 (TSC skew across cores etc.)
    out = render_timing_harness("generic", _ctx())
    assert "(t1 >= t0) ? (t1 - t0) : 0" in out


def test_void_output_buffer_is_sunk(tmp_path):
    # N3 (fail-open fix): a void function that only WRITES an output buffer must
    # have that buffer consumed by a volatile sink, else the optimizer can elide
    # the call (esp. inline/header impls) → false PASS. The Valgrind harness
    # already does this; the timing harness must too.
    ctx = _ctx(
        function="fill", return_type="void", args=["out", "in_"],
        buffers=[
            {"name": "out", "size": "32", "role": "output"},
            {"name": "in_", "size": "32", "role": "public"},
        ],
    )
    out = render_timing_harness("generic", ctx)
    assert "volatile uint64_t __ctkat_sink" in out
    assert "out[__ctkat_si]" in out          # output buffer actually consumed
    # the sink lives AFTER the timed window so it doesn't charge the measurement
    assert out.index("t1 = ctkat_now()") < out.index("__ctkat_sink")


def test_void_output_sink_compiles(tmp_path):
    # The rendered void+output harness must be valid C (catches sizeof-on-array,
    # missing decls, Jinja slips). Skips if no C compiler is available.
    import os
    import shutil
    import subprocess
    cc = shutil.which("gcc") or shutil.which("cc")
    if cc is None:
        pytest.skip("no C compiler available")
    ctx = _ctx(
        clock="monotonic", extra_headers=[], function="fill", return_type="void",
        args=["out", "in_"],
        buffers=[
            {"name": "out", "size": "32", "role": "output"},
            {"name": "in_", "size": "32", "role": "public"},
        ],
    )
    src = (
        "static void fill(unsigned char *o, unsigned char *i){"
        "for(int k=0;k<32;k++) o[k]=i[k];}\n"
        + render_timing_harness("generic", ctx)
    )
    c = tmp_path / "t.c"
    c.write_text(src)
    r = subprocess.run([cc, "-O2", "-c", str(c), "-o", str(tmp_path / "t.o")],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-1000:]


# --- Bundle A: KEM template parity --------------------------------------------


def _kem_ctx(**overrides):
    ctx = {
        "extra_headers": [],
        "header": "api.h",
        "prefix": "TEST_",
        "measurements": 1000,
        "warmup": 10,
        "seed": 0xC0FFEE,
        "clock": "monotonic",
    }
    ctx.update(overrides)
    return ctx


def test_kem_rdtsc_has_lfence_serialization():
    out = render_timing_harness("kem", _kem_ctx(clock="rdtsc"))
    assert out.count("_mm_lfence") >= 2


def test_kem_class_label_uses_high_bits():
    out = render_timing_harness("kem", _kem_ctx())
    assert "prng_next() >> 32" in out
    assert "prng_next() & 1ULL" not in out


def test_kem_captures_dec_return_with_ctkat_use():
    out = render_timing_harness("kem", _kem_ctx())
    # The timed dec's return value must be captured and CTKAT_USE'd to
    # block elision under LTO / aggressive opt.
    assert "__ctkat_dec_rc" in out
    assert "CTKAT_USE(__ctkat_dec_rc)" in out


def test_kem_sinks_output_shared_secret_after_timed_window():
    # N3: capturing only the dec RETURN code is not enough — a header/inline KEM
    # impl could elide the work that fills the output `ss` while keeping `rc`.
    # The output must be sunk too, AND after t1 so it doesn't charge the
    # measurement (mirrors timing_generic.c.j2).
    for lt in ("sk", "ct", "fo"):
        out = render_timing_harness("kem", _kem_ctx(leak_target=lt))
        assert "volatile uint64_t __ctkat_sink" in out, lt
        assert "ss[__ctkat_si]" in out, lt
        # sink lives after the timed window for this leak_target's measurement
        assert out.index("t1 = ctkat_now()") < out.index("__ctkat_sink"), lt


def test_kem_underflow_clamp_present():
    out = render_timing_harness("kem", _kem_ctx())
    assert "(t1 >= t0) ? (t1 - t0) : 0" in out


# --- Bundle D: KEM ct-leak mode ----------------------------------------------


def test_kem_default_emits_sk_leak_mode():
    # Backward compatibility: leak_target omitted (or "sk") emits the
    # original sk-axis fixed-vs-random template (with sk_random etc.).
    out = render_timing_harness("kem", _kem_ctx())
    assert "sk_random" in out
    assert "sk-leak mode" in out
    # ct-leak-only artifacts must NOT appear.
    assert "ct_fixed" not in out
    assert "ct-leak mode" not in out


def test_kem_ct_leak_mode_uses_fixed_ct():
    out = render_timing_harness("kem", _kem_ctx(leak_target="ct"))
    # ct-leak setup: a fixed ct generated by enc() at init.
    assert "ct_fixed" in out
    assert "crypto_kem_enc(ct_fixed" in out
    assert "ct-leak mode" in out
    # No sk_random in this mode — sk is held constant.
    assert "sk_random" not in out


def test_kem_ct_leak_class_branch_uses_ct_fixed_vs_random():
    out = render_timing_harness("kem", _kem_ctx(leak_target="ct"))
    # Class 0 aliases ct_fixed; class 1 generates fresh ct via enc().
    assert "ct = ct_fixed;" in out
    assert "crypto_kem_enc(ct_random" in out


def test_kem_ct_leak_measured_dec_uses_sk_fixed():
    # Critical for the methodology: in ct-leak mode, sk MUST be the same
    # across both classes so the timing difference is attributable to ct
    # content, not to sk-side caching.
    out = render_timing_harness("kem", _kem_ctx(leak_target="ct"))
    assert "crypto_kem_dec(ss, ct, sk_fixed)" in out


# --- Bundle J (R1 Option B): randombytes weak interpose ----------------


def test_kem_emits_weak_randombytes_override():
    # Bundle J: the harness must declare its own `randombytes` as a weak
    # symbol so user can opt into deterministic PQClean dudect by
    # excluding common/randombytes.c from sources.
    out = render_timing_harness("kem", _kem_ctx())
    assert "__attribute__((weak)) int randombytes(" in out


def test_kem_randombytes_uses_xorshift_prng():
    # The override must feed PQClean's randomness from our seeded PRNG,
    # otherwise enabling the interpose would just give nondeterministic
    # randomness from a different source.
    out = render_timing_harness("kem", _kem_ctx())
    # Find the randombytes definition and check it calls our rand_bytes.
    idx = out.find("int randombytes(")
    assert idx > 0
    body = out[idx:idx + 200]
    assert "rand_bytes(" in body  # delegates to seeded xorshift PRNG


def test_kem_randombytes_emitted_in_both_leak_modes():
    # Both sk-leak and ct-leak branches must see the override.
    sk_out = render_timing_harness("kem", _kem_ctx(leak_target="sk"))
    ct_out = render_timing_harness("kem", _kem_ctx(leak_target="ct"))
    assert "weak)) int randombytes(" in sk_out
    assert "weak)) int randombytes(" in ct_out


# --- Bundle K (U2 #1): leak_target=fo mode ----------------------------


def test_kem_fo_mode_uses_valid_ct_for_class_0():
    out = render_timing_harness("kem", _kem_ctx(leak_target="fo"))
    # Class 0 gets a fresh ENCryption — valid ct.
    assert "crypto_kem_enc(ct_valid" in out
    assert "ct = ct_valid;" in out


def test_kem_fo_mode_uses_random_ct_for_class_1():
    out = render_timing_harness("kem", _kem_ctx(leak_target="fo"))
    # Class 1 fills ct_invalid with random bytes — FO fallback path.
    assert "rand_bytes(ct_invalid" in out
    assert "ct = ct_invalid;" in out


def test_kem_fo_mode_measured_dec_uses_sk_fixed():
    # sk is held constant in fo mode — only ct validity varies.
    out = render_timing_harness("kem", _kem_ctx(leak_target="fo"))
    assert "crypto_kem_dec(ss, ct, sk_fixed)" in out


# --- Bundle M (F13/F14): sk-leak measures normal path, warm balances ----


def _strip_comments(src: str) -> str:
    """Return source with /*...*/ and // line comments removed, so a
    `substring not in code` assertion isn't confused by historical
    breadcrumbs left inside doc comments. Crude but enough for these tests
    — the harness template uses C99 comment styles only."""
    import re as _re
    src = _re.sub(r"/\*.*?\*/", "", src, flags=_re.DOTALL)
    src = _re.sub(r"//.*", "", src)
    return src


def test_kem_sk_leak_uses_valid_ct_for_both_classes(_kem_ctx=_kem_ctx):
    """F13 regression: sk-leak previously called `rand_bytes(ct, ...)` for
    both classes → invalid ct → dec() took the FO fallback path every
    iteration. The README advertises sk-leak as a *normal-path* secret-
    dependence probe; the fix is to generate a valid ct under each
    class's pk."""
    out = render_timing_harness("kem", _kem_ctx(leak_target="sk"))
    code = _strip_comments(out)
    # Both classes call enc() — class 0 with pk_fixed, class 1 with pk_random.
    assert "crypto_kem_enc(ct, ss, pk_fixed)" in code
    assert "crypto_kem_enc(ct, ss, pk_random)" in code
    # The old rand_bytes(ct, ...) measurement step must be gone.
    assert "rand_bytes(ct, sizeof(ct))" not in code


def _extract_warmup_block(code: str) -> str:
    """Return the C source spanning from the warmup `for(...CTKAT_WARMUP...)`
    line up to the start of the measurement `for(...CTKAT_MEASUREMENTS...)`
    loop. Used by warmup-assertion tests."""
    warmup_idx = code.find("i < CTKAT_WARMUP")
    measure_idx = code.find("i < CTKAT_MEASUREMENTS")
    assert 0 < warmup_idx < measure_idx, (
        f"could not locate distinct warmup/measurement loops: "
        f"warmup={warmup_idx}, measurement={measure_idx}"
    )
    return code[warmup_idx:measure_idx]


def test_kem_sk_leak_warmup_uses_valid_ct(_kem_ctx=_kem_ctx):
    """F14 regression: sk-leak warmup also burnt in with random ct (FO
    path) while the measured loop now exercises the normal path. The
    warmup must match — a valid ct under sk_fixed."""
    out = render_timing_harness("kem", _kem_ctx(leak_target="sk"))
    code = _strip_comments(out)
    warmup_block = _extract_warmup_block(code)
    # The warm loop body must NOT contain rand_bytes(ct, ...).
    assert "rand_bytes(ct," not in warmup_block


def test_kem_macro_warm_and_timed_dec_use_identical_args(_kem_ctx=_kem_ctx):
    """F14 regression: the macro's warm dec used a separate `ct_warm`
    buffer filled with random bytes, regardless of what the measured dec
    was about to do. Rewritten to call dec() on the SAME (ct, sk) pair
    twice — first for cache/branch warm, then timed — so the timed region
    actually starts in the microarch state of "just ran this exact path"."""
    for mode in ("sk", "ct", "fo"):
        out = render_timing_harness("kem", _kem_ctx(leak_target=mode))
        code = _strip_comments(out)
        # No live ct_warm declaration or use anywhere — it was renamed away.
        # We tolerate the substring in comments (already filtered).
        assert "ct_warm" not in code, f"{mode}: ct_warm survives as code, not just comment"
        # Macro now emits two identical dec calls back-to-back with the
        # same (ct, sk) args. Count occurrences of the timed-call shape
        # `crypto_kem_dec(ss, <ct_expr>, <sk_expr>)` inside the
        # measurement loop — must be ≥ 2 per iteration.
        assert code.count("crypto_kem_dec(ss,") >= 2


def test_kem_ct_leak_warmup_uses_fixed_valid_ct(_kem_ctx=_kem_ctx):
    """F14 regression: ct-leak warmup used to randomize ct_warm (FO path)
    even though the measured loop runs the normal path under valid ct.
    The fix uses ct_fixed for warmup so burn-in matches measurement."""
    out = render_timing_harness("kem", _kem_ctx(leak_target="ct"))
    code = _strip_comments(out)
    warmup_block = _extract_warmup_block(code)
    assert "ct_fixed" in warmup_block
    assert "rand_bytes(" not in warmup_block


def test_kem_fo_mode_keypair_called_once_at_setup():
    out = render_timing_harness("kem", _kem_ctx(leak_target="fo"))
    # Exactly one actual call (prefix filters out the comment reference
    # at the top of the rendered file).
    assert out.count("TEST_crypto_kem_keypair(") == 1


def test_kem_fo_mode_emits_weak_randombytes():
    # All three modes (sk/ct/fo) need R1 Option B path for determinism.
    out = render_timing_harness("kem", _kem_ctx(leak_target="fo"))
    assert "weak)) int randombytes(" in out


def test_kem_default_does_not_use_fo_mode():
    # Backward compatibility: default leak_target must remain sk, not fo.
    out = render_timing_harness("kem", _kem_ctx())
    assert "ct_invalid" not in out
    assert "fo-leak mode" not in out
