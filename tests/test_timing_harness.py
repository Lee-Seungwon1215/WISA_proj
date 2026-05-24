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
