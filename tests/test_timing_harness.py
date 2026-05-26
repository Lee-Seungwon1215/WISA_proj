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
