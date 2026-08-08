import csv
from pathlib import Path

from ctkat.official_dudect import (
    OFFICIAL_DUDECT_BACKEND,
    OFFICIAL_DUDECT_PROTOCOL_TESTS,
    OFFICIAL_DUDECT_REVISION,
)
from ctkat.official_dudect_verify import (
    PROTOCOL_TIMING_HEADER,
    RAW_TIMING_HEADER,
    TimingArtifactSample,
    recompute_pinned_official_dudect,
    verify_official_dudect_artifacts,
)


def _samples(count: int = 20_050, *, offset: int = 0) -> list[TimingArtifactSample]:
    return [
        TimingArtifactSample(
            sample_id=index,
            clazz=index & 1,
            cycles=10_000 + ((index * 17) % 101) + (offset if index & 1 else 0),
            aux_start=2,
            aux_end=2,
            drop_reason="",
            output_length=32,
            signature_return_code=None,
            protocol="timing-harness-v2",
        )
        for index in range(count)
    ]


def _raw_row(project: str, harness: str, sample: TimingArtifactSample) -> list[object]:
    return [
        project,
        harness,
        sample.sample_id,
        sample.clazz,
        sample.cycles,
        sample.aux_start,
        sample.aux_end,
        sample.drop_reason,
        sample.output_length,
        "" if sample.signature_return_code is None else sample.signature_return_code,
        sample.protocol,
    ]


def _write_csv(path: Path, header: tuple[str, ...], rows: list[list[object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(header)
        writer.writerows(rows)


def _backend_item(
    harness: str,
    analysis,
    *,
    analysis_seed: int,
    calibration_seed: int,
    raw_count: int,
    calibration_count: int,
) -> dict:
    winning = analysis.winning_test
    uncropped = analysis.uncropped_test
    return {
        "harness": harness,
        "backend": OFFICIAL_DUDECT_BACKEND,
        "upstream_revision": OFFICIAL_DUDECT_REVISION,
        "raw_status": analysis.status,
        "test_kind": analysis.max_test_kind,
        "test_index": analysis.max_test_index,
        "protocol_test_count": OFFICIAL_DUDECT_PROTOCOL_TESTS,
        "n0": winning.n0,
        "n1": winning.n1,
        "t_score": winning.t_score,
        "abs_t_score": analysis.max_abs_t,
        "t_score_uncropped": uncropped.t_score,
        "abs_t_score_uncropped": uncropped.abs_t_score,
        "max_tau": analysis.max_tau,
        "detection_estimate": analysis.detection_estimate,
        "enough_measurements": analysis.enough_measurements,
        "analysis_seed": analysis_seed,
        "calibration_seed": calibration_seed,
        "analysis_raw_n_total": raw_count,
        "calibration_raw_n_total": calibration_count,
        "tests": [test.as_dict() for test in analysis.tests],
    }


def _bundle(tmp_path: Path):
    project = "unit-project"
    harness = "kem_dec"
    analysis_rows = _samples(offset=0)
    calibration_rows = _samples(offset=0)
    analysis_seed = 101
    calibration_seed = 202
    raw_path = tmp_path / "dudect_raw_timings.csv"
    calibration_path = tmp_path / "dudect_calibration_timings.csv"
    protocol_path = tmp_path / "dudect_protocol_timings.csv"
    _write_csv(
        raw_path,
        RAW_TIMING_HEADER,
        [_raw_row(project, harness, row) for row in analysis_rows],
    )
    _write_csv(
        calibration_path,
        RAW_TIMING_HEADER,
        [_raw_row(project, harness, row) for row in calibration_rows],
    )
    protocol_rows = [
        [project, harness, "target-calibration", 0, calibration_seed, 0, *raw[2:]]
        for raw in (_raw_row(project, harness, row) for row in calibration_rows)
    ]
    protocol_rows.extend(
        [project, harness, "target", 0, analysis_seed, 0, *raw[2:]]
        for raw in (_raw_row(project, harness, row) for row in analysis_rows)
    )
    _write_csv(protocol_path, PROTOCOL_TIMING_HEADER, protocol_rows)
    analysis = recompute_pinned_official_dudect(calibration_rows, analysis_rows)
    backend = {
        "harnesses": [
            _backend_item(
                harness,
                analysis,
                analysis_seed=analysis_seed,
                calibration_seed=calibration_seed,
                raw_count=len(analysis_rows),
                calibration_count=len(calibration_rows),
            )
        ]
    }
    return project, harness, raw_path, calibration_path, protocol_path, backend


def test_independent_verifier_accepts_exact_raw_backend_and_protocol(tmp_path):
    project, harness, raw, calibration, protocol, backend = _bundle(tmp_path)
    result = verify_official_dudect_artifacts(
        raw_path=raw,
        calibration_path=calibration,
        protocol_path=protocol,
        backend_report=backend,
        expected_project=project,
        expected_harnesses={harness},
    )

    assert result.errors == []
    assert result.analyses[harness].enough_measurements is True
    assert len(result.analyses[harness].tests) == 102


def test_independent_verifier_rejects_garbage_raw_even_with_updated_backend_hashes(
    tmp_path,
):
    project, harness, raw, calibration, protocol, backend = _bundle(tmp_path)
    text = raw.read_text(encoding="utf-8")
    raw.write_text(text.replace(",10017,", ",nan,", 1), encoding="utf-8")

    result = verify_official_dudect_artifacts(
        raw_path=raw,
        calibration_path=calibration,
        protocol_path=protocol,
        backend_report=backend,
        expected_project=project,
        expected_harnesses={harness},
    )

    assert any("cycle count" in error for error in result.errors)


def test_self_consistent_forged_raw_and_backend_cannot_escape_protocol_binding(tmp_path):
    project, harness, raw, calibration, protocol, backend = _bundle(tmp_path)
    rows = list(csv.reader(raw.open(newline="", encoding="utf-8")))
    rows[24][4] = str(int(rows[24][4]) + 5000)
    _write_csv(raw, RAW_TIMING_HEADER, rows[1:])
    forged_samples = _samples(offset=0)
    forged_samples[23] = TimingArtifactSample(
        **{**forged_samples[23].__dict__, "cycles": forged_samples[23].cycles + 5000}
    )
    recomputed = recompute_pinned_official_dudect(_samples(offset=0), forged_samples)
    backend["harnesses"] = [
        _backend_item(
            harness,
            recomputed,
            analysis_seed=101,
            calibration_seed=202,
            raw_count=len(forged_samples),
            calibration_count=len(forged_samples),
        )
    ]

    result = verify_official_dudect_artifacts(
        raw_path=raw,
        calibration_path=calibration,
        protocol_path=protocol,
        backend_report=backend,
        expected_project=project,
        expected_harnesses={harness},
    )

    assert any("analysis raw rows differ" in error for error in result.errors)


def test_backend_test_t_score_drift_is_independently_rejected(tmp_path):
    project, harness, raw, calibration, protocol, backend = _bundle(tmp_path)
    backend["harnesses"][0]["tests"][0]["t_score"] += 0.25

    result = verify_official_dudect_artifacts(
        raw_path=raw,
        calibration_path=calibration,
        protocol_path=protocol,
        backend_report=backend,
        expected_project=project,
        expected_harnesses={harness},
    )

    assert any("test[0].t_score" in error for error in result.errors)
