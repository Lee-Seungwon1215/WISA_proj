import math
import platform
import shutil

import pytest

from ctkat.dudect_runner import TimingSamples
from ctkat.official_dudect import (
    OFFICIAL_DUDECT_ABS_T_THRESHOLD,
    OFFICIAL_DUDECT_HEADER_SHA256,
    OFFICIAL_DUDECT_MIN_CLASS0,
    OFFICIAL_DUDECT_PROTOCOL_TESTS,
    OFFICIAL_DUDECT_THRESHOLD_LABEL,
    OfficialDudectError,
    OfficialDudectUnavailable,
    analyze_with_official_dudect,
    assert_official_source_integrity,
    build_official_dudect_adapter,
)
from ctkat.official_dudect_verify import (
    TimingArtifactSample,
    recompute_pinned_official_dudect,
)
from ctkat.statistics import welch_t_test

IS_X86 = platform.machine().lower() in {"x86_64", "amd64"}
IS_X86_WITH_GCC = IS_X86 and bool(shutil.which("gcc"))


def _samples(count: int, *, leak: int = 0) -> TimingSamples:
    classes = [index & 1 for index in range(count)]
    cycles = [
        float(10_000 + ((index * 17) % 101) + (leak if clazz == 1 else 0))
        for index, clazz in enumerate(classes)
    ]
    return TimingSamples(classes=classes, cycles=cycles, raw_n_total=count)


def _artifact_samples(samples: TimingSamples) -> list[TimingArtifactSample]:
    return [
        TimingArtifactSample(
            sample_id=index,
            clazz=clazz,
            cycles=int(cycles),
            aux_start=0,
            aux_end=0,
            drop_reason="",
            output_length=0,
            signature_return_code=None,
            protocol="timing-harness-v2",
        )
        for index, (clazz, cycles) in enumerate(zip(samples.classes, samples.cycles))
    ]


def test_vendored_official_header_hash_is_pinned():
    assert len(OFFICIAL_DUDECT_HEADER_SHA256) == 64
    assert OFFICIAL_DUDECT_ABS_T_THRESHOLD == 10.0
    assert OFFICIAL_DUDECT_MIN_CLASS0 == 10_001
    assert OFFICIAL_DUDECT_THRESHOLD_LABEL == "|t|>10;n0>=10001"
    assert_official_source_integrity()


def test_official_adapter_rejects_non_x86(monkeypatch, tmp_path):
    monkeypatch.setattr("ctkat.official_dudect.platform.machine", lambda: "arm64")
    with pytest.raises(OfficialDudectUnavailable, match="x86_64-only"):
        build_official_dudect_adapter(cc="gcc", output_dir=tmp_path)


def test_official_trace_contract_rejects_fractional_cycles(tmp_path):
    samples = _samples(20)
    samples.cycles[3] = 1.5
    with pytest.raises(OfficialDudectError, match="finite integer"):
        analyze_with_official_dudect(
            samples,
            samples,
            adapter_binary=tmp_path / "not-needed",
            workdir=tmp_path,
        )


def test_official_adapter_malformed_schema_fails_closed(tmp_path):
    adapter = tmp_path / "fake-adapter"
    adapter.write_text("#!/bin/sh\nprintf '{}\\n'\n", encoding="utf-8")
    adapter.chmod(0o755)
    samples = _samples(20)
    with pytest.raises(OfficialDudectError, match="schema mismatch"):
        analyze_with_official_dudect(
            samples,
            samples,
            adapter_binary=adapter,
            workdir=tmp_path,
        )


@pytest.mark.parametrize("cc", ["gcc", "clang"])
def test_official_adapter_builds_with_supported_compilers(cc, tmp_path):
    if not IS_X86 or not shutil.which(cc):
        pytest.skip(f"{cc} x86_64 toolchain unavailable")
    adapter = build_official_dudect_adapter(cc=cc, output_dir=tmp_path / cc)
    assert adapter.is_file()


@pytest.mark.skipif(not IS_X86_WITH_GCC, reason="pinned official dudect C engine is x86_64-only")
def test_official_backend_executes_all_tests_and_matches_uncropped_welch(tmp_path):
    adapter = build_official_dudect_adapter(cc="gcc", output_dir=tmp_path / "adapter")
    calibration = _samples(20_050)
    analysis_trace = _samples(20_050, leak=50)
    result = analyze_with_official_dudect(
        calibration,
        analysis_trace,
        adapter_binary=adapter,
        workdir=tmp_path,
    )

    assert result.status == "FAIL"
    assert result.enough_measurements is True
    assert len(result.tests) == OFFICIAL_DUDECT_PROTOCOL_TESTS == 102
    assert result.tests[0].kind == "first-order-uncropped"
    assert result.tests[1].kind == "first-order-cropped"
    assert result.tests[-1].kind == "second-order"
    assert result.max_tau is not None
    assert result.detection_estimate is not None

    retained = list(zip(analysis_trace.classes[10:], analysis_trace.cycles[10:]))
    class0 = [cycles for clazz, cycles in retained if clazz == 0]
    class1 = [cycles for clazz, cycles in retained if clazz == 1]
    python_t = welch_t_test(class0, class1).t_score
    official_t = result.uncropped_test.t_score
    assert official_t is not None
    assert math.isclose(official_t, python_t, rel_tol=0.0, abs_tol=1e-9)

    independent = recompute_pinned_official_dudect(
        _artifact_samples(calibration),
        _artifact_samples(analysis_trace),
    )
    assert independent.status == result.status
    assert independent.max_test_index == result.max_test_index
    assert len(independent.tests) == len(result.tests)
    for expected, actual in zip(independent.tests, result.tests, strict=True):
        assert expected.index == actual.index
        assert expected.n0 == actual.n0
        assert expected.n1 == actual.n1
        assert expected.crop_threshold == actual.crop_threshold
        if expected.t_score is None:
            assert actual.t_score is None
        else:
            assert actual.t_score is not None
            assert math.isclose(expected.t_score, actual.t_score, rel_tol=1e-12, abs_tol=1e-12)


@pytest.mark.skipif(not IS_X86_WITH_GCC, reason="pinned official dudect C engine is x86_64-only")
def test_official_backend_withholds_conclusion_below_upstream_minimum(tmp_path):
    adapter = build_official_dudect_adapter(cc="gcc", output_dir=tmp_path / "adapter")
    samples = _samples(2_000, leak=100)
    result = analyze_with_official_dudect(
        samples,
        samples,
        adapter_binary=adapter,
        workdir=tmp_path,
    )
    assert result.status == "INSUFFICIENT"
    assert result.enough_measurements is False
    assert result.minimum_class0_measurements == 10_001
