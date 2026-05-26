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
