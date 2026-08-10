import csv
import hashlib
import json
import math
import shutil
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from ctkat.official_dudect import (
    OFFICIAL_DUDECT_BACKEND,
    OFFICIAL_DUDECT_REVISION,
)
from ctkat.official_dudect_verify import (
    RAW_TIMING_HEADER,
    TimingArtifactSample,
    _control_payload,
    _positive_control_detected,
    _timing_domain_seed,
    parse_official_protocol_csv,
    recompute_pinned_official_dudect,
)
from scripts import run_native_timing_campaign as campaign


def test_committed_campaign_covers_every_existing_timing_row():
    spec = campaign.load_campaign()
    assert spec.coverage_mode == "committed-timing-rows"
    assert campaign.static_check(spec) == []
    pairs = {(target.id, harness) for target in spec.targets for harness in target.harnesses}
    assert pairs == campaign._corpus_timing_pairs()
    axes = {
        (target.id, harness, target.axis_for(harness))
        for target in spec.targets
        for harness in target.harnesses
    }
    assert axes == {
        ("pqclean_mlkem768", "kem_dec", "valid_tuple")
        if (target, harness, axis) == ("pqclean_mlkem768", "kem_dec", "sk")
        else (target, harness, axis)
        for target, harness, axis in campaign._corpus_timing_axes()
    }
    assert spec.corpus_axis_replacements == (
        campaign.CorpusAxisReplacement(
            target="pqclean_mlkem768",
            harness="kem_dec",
            from_axis="sk",
            to_axis="valid_tuple",
            rationale=(
                "The legacy class construction changes the secret key, matching public "
                "ciphertext, and public key material embedded in the secret key together; "
                "it is a mixed valid-tuple contrast and cannot support secret attribution."
            ),
        ),
    )
    assert len(spec.targets) == 6
    assert len(pairs) == 8


def test_manifest_only_campaign_does_not_claim_committed_corpus_coverage(monkeypatch):
    spec = replace(
        campaign.load_campaign(),
        coverage_mode="manifest-only",
        corpus_axis_replacements=(),
    )
    monkeypatch.setattr(
        campaign,
        "_corpus_timing_axes",
        lambda: {("unrelated", "axis", "sk")},
    )
    assert campaign.static_check(spec) == []


def test_campaign_overrides_do_not_mutate_modest_example_defaults(tmp_path):
    spec = campaign.load_campaign()
    target = next(target for target in spec.targets if target.id == "pqclean_mldsa44")
    cfg = campaign.load_config(target.config)
    assert cfg.dudect is not None
    original_measurements = cfg.dudect.measurements
    original_clock = cfg.dudect.clock

    dudect = campaign.campaign_dudect(cfg, spec, target, tmp_path / "generated")
    assert dudect.measurements == 30_000
    assert dudect.warmup == 1_000
    assert dudect.batches == 10
    assert dudect.clock == "rdtsc"
    assert dudect.compiler.cc == "gcc"
    assert dudect.compile_timeout == 600
    assert dudect.backend_timeout == 300
    assert dudect.timing_protocol.control_measurements == 5_000
    assert dudect.timing_protocol.positive_control_effects == [65536, 262144, 1048576]
    assert dudect.generated_dir == (tmp_path / "generated").resolve()
    assert cfg.dudect.measurements == original_measurements == 2_000
    assert cfg.dudect.clock == original_clock == "auto"


def test_preflight_accepts_clean_pinned_native_host(monkeypatch):
    spec = campaign.load_campaign()
    monkeypatch.setattr(campaign.platform, "system", lambda: "Linux")
    monkeypatch.setattr(campaign.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(campaign, "detect_qemu_emulation", lambda: False)
    monkeypatch.setattr(
        campaign,
        "collect_timing_environment",
        lambda **kwargs: {
            "cpu_model": "Example CPU",
            "machine_id_sha256": "1" * 64,
            "boot_id_sha256": "2" * 64,
            "timing_cpu_flags": {
                "constant_tsc": True,
                "nonstop_tsc": True,
                "rdtscp": True,
            },
            "cpu_affinity": [2],
            "rejected": False,
            "rejection_reasons": [],
        },
    )
    monkeypatch.setattr(campaign, "_detect_virtualization", lambda: {"vm": "", "container": ""})
    monkeypatch.setattr(campaign, "_git_state", lambda: ("a" * 40, False))
    monkeypatch.setattr(campaign, "_command_version", lambda command: "gcc 14.2.0")
    monkeypatch.setattr(
        campaign,
        "_compiler_executable_identity",
        lambda command: {"resolved_path": "/usr/bin/gcc", "sha256": "7" * 64},
    )
    monkeypatch.setattr(campaign, "_read_text", lambda path: "performance")
    monkeypatch.setattr(campaign, "build_official_dudect_adapter", lambda **kwargs: Path("adapter"))

    result = campaign.preflight(
        spec,
        allow_dirty=False,
        allow_virtualized=False,
        build_adapter=True,
    )
    assert result["ok"] is True
    assert result["paper_eligible"] is True


def test_container_marker_is_not_misreported_as_a_physical_host(monkeypatch):
    monkeypatch.setattr(campaign, "_detect_container_marker", lambda: "docker")
    monkeypatch.setattr(campaign.shutil, "which", lambda _command: None)
    monkeypatch.setattr(campaign, "_read_text", lambda _path: "")

    assert campaign._detect_virtualization() == {"vm": "", "container": "docker"}


def test_cpuid_hypervisor_flag_is_rejected_when_systemd_detector_is_absent(monkeypatch):
    monkeypatch.setattr(campaign, "_detect_container_marker", lambda: "")
    monkeypatch.setattr(campaign.shutil, "which", lambda _command: None)
    monkeypatch.setattr(
        campaign,
        "_read_text",
        lambda path: "flags : fpu tsc hypervisor rdtscp" if path == Path("/proc/cpuinfo") else "",
    )

    assert campaign._detect_virtualization() == {
        "vm": "cpuid-hypervisor",
        "container": "",
    }


def test_preflight_override_never_promotes_virtualized_or_dirty_host(monkeypatch):
    spec = campaign.load_campaign()
    monkeypatch.setattr(campaign.platform, "system", lambda: "Linux")
    monkeypatch.setattr(campaign.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(campaign, "detect_qemu_emulation", lambda: False)
    monkeypatch.setattr(
        campaign,
        "collect_timing_environment",
        lambda **kwargs: {
            "cpu_model": "Example CPU",
            "machine_id_sha256": "3" * 64,
            "boot_id_sha256": "4" * 64,
            "timing_cpu_flags": {
                "constant_tsc": True,
                "nonstop_tsc": True,
                "rdtscp": True,
            },
            "cpu_affinity": [3],
            "rejected": False,
            "rejection_reasons": [],
        },
    )
    monkeypatch.setattr(
        campaign,
        "_detect_virtualization",
        lambda: {"vm": "kvm", "container": ""},
    )
    monkeypatch.setattr(campaign, "_git_state", lambda: ("b" * 40, True))
    monkeypatch.setattr(campaign, "_command_version", lambda command: "gcc 14.2.0")
    monkeypatch.setattr(
        campaign,
        "_compiler_executable_identity",
        lambda command: {"resolved_path": "/usr/bin/gcc", "sha256": "7" * 64},
    )
    monkeypatch.setattr(campaign, "_read_text", lambda path: "performance")
    monkeypatch.setattr(campaign, "build_official_dudect_adapter", lambda **kwargs: Path("adapter"))

    result = campaign.preflight(
        spec,
        allow_dirty=True,
        allow_virtualized=True,
        build_adapter=True,
    )
    assert result["ok"] is True
    assert result["paper_eligible"] is False
    assert any("engineering-only" in warning for warning in result["warnings"])


def _write_csv(path, fieldnames, rows):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _paper_eligible_preflight(commit):
    return {
        "checked_at": "2026-07-30T00:00:00Z",
        "ok": True,
        "paper_eligible": True,
        "errors": [],
        "warnings": [],
        "git_commit": commit,
        "git_dirty": False,
        "compiler": "gcc 14.2.0",
        "compiler_executable": {
            "resolved_path": "/usr/bin/gcc",
            "sha256": "7" * 64,
        },
        "official_adapter_built": True,
        "virtualization": {"vm": "", "container": ""},
        "environment": {
            "system": "Linux",
            "machine": "x86_64",
            "clock": "rdtsc",
            "emulated": False,
            "cpu_model": "Example CPU",
            "machine_id_sha256": "5" * 64,
            "boot_id_sha256": "6" * 64,
            "timing_cpu_flags": {
                "constant_tsc": True,
                "nonstop_tsc": True,
                "rdtscp": True,
            },
            "cpu_affinity": [2],
            "rejected": False,
            "rejection_reasons": [],
        },
        "governor_selected_cpu": "performance",
    }


def test_preflight_report_recomputes_paper_eligibility():
    spec = campaign.load_campaign()
    commit = "c" * 40
    native = _paper_eligible_preflight(commit)
    assert campaign.validate_preflight_report(
        spec,
        native,
        expected_commit=commit,
    ) == (True, [])

    engineering = dict(native)
    engineering["git_dirty"] = True
    engineering["paper_eligible"] = False
    engineering["warnings"] = ["git worktree changed (engineering-only override)"]
    assert campaign.validate_preflight_report(
        spec,
        engineering,
        expected_commit=commit,
    ) == (False, [])

    tampered = dict(engineering)
    tampered["paper_eligible"] = True
    eligible, errors = campaign.validate_preflight_report(
        spec,
        tampered,
        expected_commit=commit,
    )
    assert eligible is False
    assert any("paper_eligible" in error for error in errors)


def _small_artifact_fixture(tmp_path, *, target_measurements=20_050):
    base = campaign.load_campaign()
    protocol = replace(base.protocol, process_repeats=1, pool_size=4)
    target = replace(
        base.targets[1],
        target_measurements=target_measurements,
        control_measurements=4,
        positive_control_effects=(1, 2, 3),
    )
    spec = replace(base, protocol=protocol, targets=(target,))
    report_dir = tmp_path / target.id / "reports"
    report_dir.mkdir(parents=True)

    protocol_rows = []
    expected = campaign._expected_protocol_counts(spec, target)
    analysis_seed = None
    calibration_seed = None
    analysis_trace_rows = []
    calibration_trace_rows = []
    for (harness, role, process_index, effect), count in expected.items():
        if role == "target":
            trace_seed = protocol.seed
        elif role == "target-calibration":
            trace_seed = _timing_domain_seed(protocol.seed, "calibration", process_index)
        elif role == "aa":
            trace_seed = _timing_domain_seed(protocol.seed, "aa", process_index)
        elif role == "setup-placebo":
            trace_seed = _timing_domain_seed(protocol.seed, "placebo", process_index)
        else:
            effect_index = target.positive_control_effects.index(effect)
            trace_seed = _timing_domain_seed(
                protocol.seed,
                "positive",
                process_index,
                effect_index,
            )
        if role == "target":
            analysis_seed = trace_seed
        elif role == "target-calibration":
            calibration_seed = trace_seed
        for sample_id in range(count):
            row = {
                "project": target.id,
                "harness": harness,
                "role": role,
                "process_index": process_index,
                "seed": trace_seed,
                "effect_ticks": effect,
                "sample_id": sample_id,
                "class": sample_id % 2,
                "cycles": (
                    100
                    + ((sample_id // 2) % 101)
                    + (effect * 100 if role == "positive" and sample_id % 2 else 0)
                ),
                "aux_start": 2,
                "aux_end": 2,
                "drop_reason": "",
                "output_length": 32,
                "signature_return_code": 0,
                "protocol": "timing-harness-v2",
            }
            protocol_rows.append(row)
            raw_row = {key: row[key] for key in RAW_TIMING_HEADER}
            if role == "target":
                analysis_trace_rows.append(raw_row)
            elif role == "target-calibration":
                calibration_trace_rows.append(raw_row)
    _write_csv(
        report_dir / "dudect_raw_timings.csv",
        list(RAW_TIMING_HEADER),
        analysis_trace_rows,
    )
    _write_csv(
        report_dir / "dudect_calibration_timings.csv",
        list(RAW_TIMING_HEADER),
        calibration_trace_rows,
    )
    _write_csv(
        report_dir / "dudect_protocol_timings.csv",
        campaign.PROTOCOL_HEADER,
        protocol_rows,
    )

    def artifact_samples(rows):
        return [
            TimingArtifactSample(
                sample_id=row["sample_id"],
                clazz=row["class"],
                cycles=row["cycles"],
                aux_start=row["aux_start"],
                aux_end=row["aux_end"],
                drop_reason=row["drop_reason"],
                output_length=row["output_length"],
                signature_return_code=row["signature_return_code"],
                protocol=row["protocol"],
            )
            for row in rows
        ]

    independent = recompute_pinned_official_dudect(
        artifact_samples(calibration_trace_rows),
        artifact_samples(analysis_trace_rows),
    )
    winning = independent.winning_test
    uncropped = independent.uncropped_test
    timing_validity = "valid" if independent.enough_measurements else "insufficient-power"
    validity_reasons = (
        [] if independent.enough_measurements else ["official class-0 minimum was not met"]
    )
    _write_csv(
        report_dir / "dudect_summary.csv",
        sorted(campaign.SUMMARY_REQUIRED_COLUMNS),
        [
            {
                "project": target.id,
                "harness": "sign",
                "n0": str(winning.n0),
                "n1": str(winning.n1),
                "abs_t_score": str(independent.max_abs_t),
                "status": independent.status,
                "backend": OFFICIAL_DUDECT_BACKEND,
                "timing_validity": timing_validity,
                "raw_n_total": str(target.target_measurements),
                "analysis_seed": str(analysis_seed),
                "harness_protocol": "timing-harness-v2",
                "process_repeats": "1",
                "aa_failures": "0",
                "positive_power_passed": "true",
                "protocol_test_count": "102",
                "upstream_revision": OFFICIAL_DUDECT_REVISION,
            }
        ],
    )
    parsed_protocol = parse_official_protocol_csv(
        report_dir / "dudect_protocol_timings.csv",
        expected_project=target.id,
    )
    aa_payloads = [
        _control_payload(
            parsed_protocol[("sign", "aa", 0, 0)],
            warning_threshold=protocol.aa_abs_t_limit,
            fail_threshold=protocol.positive_abs_t_threshold,
            power_alpha=protocol.power_alpha,
            target_power=protocol.target_power,
        )
    ]
    placebo_payloads = [
        _control_payload(
            parsed_protocol[("sign", "setup-placebo", 0, 0)],
            warning_threshold=protocol.aa_abs_t_limit,
            fail_threshold=protocol.positive_abs_t_threshold,
        )
    ]
    positive_payloads = [
        _control_payload(
            parsed_protocol[("sign", "positive", 0, effect)],
            warning_threshold=protocol.aa_abs_t_limit,
            fail_threshold=protocol.positive_abs_t_threshold,
        )
        for effect in target.positive_control_effects
    ]
    positive_curve = []
    for item in positive_payloads:
        detected = (
            item["mean_delta"] > 0.0 and item["t_score"] <= -protocol.positive_abs_t_threshold
        )
        positive_curve.append(
            {
                "effect_ticks": item["effect_ticks"],
                "detections": int(detected),
                "runs": 1,
                "detection_rate": float(detected),
                "mean_observed_delta": item["mean_delta"],
            }
        )
    target_payload = {
        "process_index": 0,
        "analysis_seed": analysis_seed,
        "calibration_seed": calibration_seed,
        "status": independent.status,
        "abs_t_score": independent.max_abs_t,
        "test_kind": independent.max_test_kind,
        "test_index": independent.max_test_index,
        "n0": winning.n0,
        "n1": winning.n1,
        "enough_measurements": independent.enough_measurements,
    }
    harness_protocol = {
        "schema_version": "1.0",
        "protocol": "timing-harness-v2",
        "template": "sign",
        "axis": "sk",
        "common_work_buffer": True,
        "symmetric_setup": True,
        "timed_region_target_only": True,
        "rdtscp_aux_migration_filter": True,
        "pool_size": 4,
        "target_measurements": target.target_measurements,
        "control_measurements": 4,
        "process_repeats_required": 3,
        "process_repeats_observed": 1,
        "target_status_consistent": True,
        "aa_abs_t_limit": protocol.aa_abs_t_limit,
        "aa_max_failures": protocol.aa_max_failures,
        "positive_abs_t_threshold": protocol.positive_abs_t_threshold,
        "target_power": protocol.target_power,
        "power_alpha": protocol.power_alpha,
        "positive_power_curve": positive_curve,
        "target_repeats": [target_payload],
        "aa_controls": aa_payloads,
        "aa_failures": 0,
        "aa_budget_passed": True,
        "setup_placebo_controls": placebo_payloads,
        "setup_placebo_failures": 0,
        "setup_placebo_passed": True,
        "positive_controls": positive_payloads,
        "required_positive_detections": 1,
        "positive_power_passed": True,
        "minimum_detectable_effects": [aa_payloads[0]["minimum_detectable_effect"]],
        "positive_detection_effects_at_target_power": [
            aa_payloads[0]["positive_detection_effect_at_target_power"]
        ],
        "randomness_policies_observed": ["seeded-interpose"],
        "signature_call_contract": {
            "configured": "fixed",
            "return_code_column": "signature_return_code",
            "return_code_success": 0,
            "return_codes_recorded": True,
            "correctness_round_trip_gate": True,
            "measured_contract_failures": 0,
            "resolved_min": 32,
            "resolved_max": 32,
            "traces_validated": 7,
            "passed": True,
        },
    }
    hashes = {
        name: hashlib.sha256((report_dir / name).read_bytes()).hexdigest()
        for name in (
            "dudect_raw_timings.csv",
            "dudect_calibration_timings.csv",
            "dudect_protocol_timings.csv",
        )
    }
    backend = {
        "schema_version": "2.0",
        "kind": "timing-backend-report",
        "project": target.id,
        "official_dudect_revision": OFFICIAL_DUDECT_REVISION,
        "raw_trace_sha256": hashes["dudect_raw_timings.csv"],
        "calibration_trace_sha256": hashes["dudect_calibration_timings.csv"],
        "protocol_trace_sha256": hashes["dudect_protocol_timings.csv"],
        "harnesses": [
            {
                "harness": "sign",
                "backend": OFFICIAL_DUDECT_BACKEND,
                "upstream_revision": OFFICIAL_DUDECT_REVISION,
                "raw_status": independent.status,
                "timing_validity": timing_validity,
                "validity_reasons": validity_reasons,
                "test_kind": independent.max_test_kind,
                "test_index": independent.max_test_index,
                "t_score": winning.t_score,
                "abs_t_score": independent.max_abs_t,
                "t_score_uncropped": uncropped.t_score,
                "abs_t_score_uncropped": uncropped.abs_t_score,
                "max_tau": (
                    independent.max_tau
                    if independent.max_tau is not None and math.isfinite(independent.max_tau)
                    else None
                ),
                "detection_estimate": (
                    independent.detection_estimate
                    if independent.detection_estimate is not None
                    and math.isfinite(independent.detection_estimate)
                    else None
                ),
                "analysis_seed": analysis_seed,
                "calibration_seed": calibration_seed,
                "analysis_raw_n_total": target.target_measurements,
                "calibration_raw_n_total": target.target_measurements,
                "n0": winning.n0,
                "n1": winning.n1,
                "enough_measurements": independent.enough_measurements,
                "environment": {"rejected": False},
                "protocol_test_count": 102,
                "tests": [test.as_dict() for test in independent.tests],
                "harness_protocol": harness_protocol,
            }
        ],
    }
    (report_dir / "dudect_backend_report.json").write_text(json.dumps(backend), encoding="utf-8")
    return spec, target, report_dir


def test_artifact_validator_accepts_complete_promotion_ready_bundle(tmp_path):
    spec, target, report_dir = _small_artifact_fixture(tmp_path)
    result = campaign.validate_target_artifacts(
        spec,
        target,
        report_dir,
        host_paper_eligible=True,
    )
    assert result.errors == []
    assert result.blockers == []
    assert result.complete is True
    assert result.promotion_ready is True

    updates = tmp_path / "updates.csv"
    campaign.write_updates(updates, [result])
    row = next(csv.DictReader(updates.open()))
    assert row["report"] == f"{target.id}/reports/dudect_backend_report.json"
    assert row["promotion_ready"] == "true"
    assert row["timing_threshold"] == campaign.OFFICIAL_TIMING_THRESHOLD

    backend = json.loads((report_dir / "dudect_backend_report.json").read_text(encoding="utf-8"))
    protocol = backend["harnesses"][0]["harness_protocol"]
    assert (
        protocol["positive_detection_effects_at_target_power"][0]
        > protocol["minimum_detectable_effects"][0]
    )


def test_independent_positive_detection_rejects_reversed_or_small_effect():
    assert _positive_control_detected(
        {"mean_delta": 250.0, "t_score": -10.0},
        abs_t_threshold=10.0,
    )
    assert not _positive_control_detected(
        {"mean_delta": 250.0, "t_score": -9.99},
        abs_t_threshold=10.0,
    )
    assert not _positive_control_detected(
        {"mean_delta": -250.0, "t_score": 12.0},
        abs_t_threshold=10.0,
    )


def test_artifact_validator_accepts_integral_control_means_serialized_as_floats(tmp_path):
    spec, target, report_dir = _small_artifact_fixture(tmp_path)
    backend_path = report_dir / "dudect_backend_report.json"
    backend = json.loads(backend_path.read_text(encoding="utf-8"))
    protocol = backend["harnesses"][0]["harness_protocol"]
    for field_name in ("aa_controls", "setup_placebo_controls", "positive_controls"):
        for payload in protocol[field_name]:
            for statistic in ("mean0", "mean1", "mean_delta"):
                payload[statistic] = float(payload[statistic])
    for payload in protocol["positive_power_curve"]:
        payload["mean_observed_delta"] = float(payload["mean_observed_delta"])
    backend_path.write_text(json.dumps(backend), encoding="utf-8")

    result = campaign.validate_target_artifacts(
        spec,
        target,
        report_dir,
        host_paper_eligible=True,
    )

    assert result.errors == []


def test_artifact_validator_rejects_hash_and_trace_count_drift(tmp_path):
    spec, target, report_dir = _small_artifact_fixture(tmp_path)
    protocol = report_dir / "dudect_protocol_timings.csv"
    lines = protocol.read_text(encoding="utf-8").splitlines()
    protocol.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")

    result = campaign.validate_target_artifacts(
        spec,
        target,
        report_dir,
        host_paper_eligible=True,
    )
    assert result.complete is False
    assert any("protocol_trace_sha256" in error for error in result.errors)
    assert any("trace count drift" in error for error in result.errors)


def test_artifact_validator_recomputes_controls_instead_of_trusting_pass_flags(tmp_path):
    spec, target, report_dir = _small_artifact_fixture(tmp_path)
    protocol_path = report_dir / "dudect_protocol_timings.csv"
    with protocol_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fieldnames = list(reader.fieldnames or [])
        rows = list(reader)
    for row in rows:
        if row["role"] == "aa":
            row["cycles"] = "100" if row["class"] == "0" else "100000"
        elif row["role"] == "positive":
            row["cycles"] = "100"
    _write_csv(protocol_path, fieldnames, rows)
    backend_path = report_dir / "dudect_backend_report.json"
    backend = json.loads(backend_path.read_text(encoding="utf-8"))
    backend["protocol_trace_sha256"] = hashlib.sha256(protocol_path.read_bytes()).hexdigest()
    backend_path.write_text(json.dumps(backend), encoding="utf-8")

    result = campaign.validate_target_artifacts(
        spec,
        target,
        report_dir,
        host_paper_eligible=True,
    )

    assert result.complete is False
    assert result.promotion_ready is False
    assert any("raw protocol" in error for error in result.errors)


def test_artifact_validator_rejects_wrong_target_identity_and_axis(tmp_path):
    spec, target, report_dir = _small_artifact_fixture(tmp_path)
    backend_path = report_dir / "dudect_backend_report.json"
    backend = json.loads(backend_path.read_text(encoding="utf-8"))
    backend["project"] = "some-other-target"
    backend["harnesses"][0]["harness_protocol"]["axis"] = "msg"
    backend_path.write_text(json.dumps(backend), encoding="utf-8")

    result = campaign.validate_target_artifacts(
        spec,
        target,
        report_dir,
        host_paper_eligible=True,
    )
    assert result.complete is False
    assert any("backend report project" in error for error in result.errors)
    assert any("harness_protocol.axis" in error for error in result.errors)


def test_artifact_validator_rejects_incomplete_valid_tuple_report(tmp_path):
    spec, target, report_dir = _small_artifact_fixture(tmp_path)
    target = replace(target, axes=(("sign", "valid_tuple"),))
    spec = replace(spec, targets=(target,))
    backend_path = report_dir / "dudect_backend_report.json"
    backend = json.loads(backend_path.read_text(encoding="utf-8"))
    harness = backend["harnesses"][0]
    harness["harness_protocol"]["axis"] = "valid_tuple"
    harness["harness_protocol"]["input_contract"] = {"passed": True}
    backend_path.write_text(json.dumps(backend), encoding="utf-8")

    result = campaign.validate_target_artifacts(
        spec,
        target,
        report_dir,
        host_paper_eligible=True,
    )

    assert result.complete is False
    assert any("process_repeats_observed" in error for error in result.errors)
    assert any("input_contract" in error for error in result.errors)
    assert any(
        error.startswith("official dudect independent verification:")
        and "process_repeats_observed" in error
        for error in result.errors
    )


def test_complete_underpowered_bundle_is_nonpromotable_not_corrupt(tmp_path):
    spec, target, report_dir = _small_artifact_fixture(
        tmp_path,
        target_measurements=100,
    )

    result = campaign.validate_target_artifacts(
        spec,
        target,
        report_dir,
        host_paper_eligible=True,
    )
    assert result.errors == []
    assert result.complete is True
    assert result.promotion_ready is False
    assert any("timing_validity=insufficient-power" in value for value in result.blockers)


def test_execute_resume_and_validate_run_round_trip(tmp_path, monkeypatch):
    spec, target, fixture_reports = _small_artifact_fixture(tmp_path / "fixture")
    output_root = tmp_path / "run"
    calls = []

    def fake_dudect(_dudect, _config_dir, project, report_dir, **_kwargs):
        calls.append(project)
        report_dir.mkdir(parents=True)
        for source in fixture_reports.iterdir():
            shutil.copy2(source, report_dir / source.name)
        return []

    monkeypatch.setattr(campaign, "_do_dudect", fake_dudect)
    preflight = _paper_eligible_preflight("a" * 40)
    assert (
        campaign.execute_campaign(
            spec,
            output_root,
            (target,),
            preflight_report=preflight,
            run_kind="engineering",
            review_gate=None,
            resume=False,
            continue_on_error=False,
        )
        == 0
    )
    assert calls == [target.id]
    report = json.loads((output_root / "campaign_report.json").read_text(encoding="utf-8"))
    assert report["status"] == "complete"
    assert report["paper_promotion_ready"] is False
    assert report["targets"][target.id]["promotion_ready"] is False
    assert (
        campaign.validate_run(
            spec,
            output_root,
            (target,),
            expected_run_kind="engineering",
        )
        == 0
    )

    calls.clear()
    assert (
        campaign.execute_campaign(
            spec,
            output_root,
            (target,),
            preflight_report=preflight,
            run_kind="engineering",
            review_gate=None,
            resume=True,
            continue_on_error=False,
        )
        == 0
    )
    assert calls == []
    with (output_root / "corpus_timing_updates.csv").open(
        newline="",
        encoding="utf-8",
    ) as handle:
        update_rows = list(csv.DictReader(handle))
    assert [(row["target"], row["harness"]) for row in update_rows] == [(target.id, "sign")]

    update_rows[0]["report_sha256"] = "0" * 64
    _write_csv(
        output_root / "corpus_timing_updates.csv",
        campaign.UPDATE_FIELDS,
        update_rows,
    )
    assert (
        campaign.validate_run(
            spec,
            output_root,
            (target,),
            expected_run_kind="engineering",
        )
        == 1
    )


def test_final_run_cannot_resume_or_bypass_human_gate(tmp_path):
    spec, target, _report_dir = _small_artifact_fixture(tmp_path / "fixture")
    preflight = _paper_eligible_preflight("a" * 40)
    with pytest.raises(campaign.CampaignError, match="cannot use --resume"):
        campaign.execute_campaign(
            spec,
            tmp_path / "final-resume",
            (target,),
            preflight_report=preflight,
            run_kind="final",
            review_gate=None,
            resume=True,
            continue_on_error=False,
        )
    with pytest.raises(campaign.CampaignError, match="human premeasurement review gate"):
        campaign.execute_campaign(
            spec,
            tmp_path / "final-no-review",
            (target,),
            preflight_report=preflight,
            run_kind="final",
            review_gate=None,
            resume=False,
            continue_on_error=False,
        )


def test_human_gate_binds_exact_reviewed_commit_and_current_packet_hashes(monkeypatch):
    from scripts import check_paper_reviews

    reviewed_commit = "a" * 40
    execution_commit = "b" * 40
    postmeasurement_review_commit = "c" * 40

    def fake_review_manifest(_path):
        return (
            {
                "pre_measurement_ready": True,
                "reviewed_source_commits": [
                    reviewed_commit,
                    postmeasurement_review_commit,
                ],
                "pre_measurement_reviewed_source_commits": [reviewed_commit],
                "post_measurement_reviewed_source_commits": [postmeasurement_review_commit],
                "packets": [],
                "plan_id": "unit-review-plan",
                "minimum_reviewers": 2,
            },
            [],
        )

    monkeypatch.setattr(check_paper_reviews, "evaluate_manifest", fake_review_manifest)
    monkeypatch.setattr(campaign, "_git_state", lambda: (execution_commit, False))
    gate = campaign._human_premeasurement_gate(execution_commit)
    assert gate["ctkat_commit"] == execution_commit
    assert gate["reviewed_source_commit"] == reviewed_commit
    assert (
        campaign._validate_human_premeasurement_gate(
            gate,
            expected_commit=execution_commit,
        )
        == []
    )

    forged = dict(gate)
    forged["reviewed_source_commit"] = "b" * 40
    assert (
        "no longer matches"
        in campaign._validate_human_premeasurement_gate(
            forged,
            expected_commit=execution_commit,
        )[0]
    )

    with pytest.raises(campaign.CampaignError, match="differs from current git HEAD"):
        campaign._human_premeasurement_gate("c" * 40)

    monkeypatch.setattr(campaign, "_git_state", lambda: ("c" * 40, False))
    monkeypatch.setattr(
        campaign.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    assert (
        campaign._validate_human_premeasurement_gate(
            gate,
            expected_commit=execution_commit,
            allow_review_only_head=True,
        )
        == []
    )


def test_human_gate_rejects_split_premeasurement_review_commits(monkeypatch):
    from scripts import check_paper_reviews

    execution_commit = "c" * 40

    monkeypatch.setattr(
        check_paper_reviews,
        "evaluate_manifest",
        lambda _path: (
            {
                "pre_measurement_ready": True,
                "reviewed_source_commits": ["a" * 40, "b" * 40],
                "pre_measurement_reviewed_source_commits": ["a" * 40, "b" * 40],
                "post_measurement_reviewed_source_commits": [],
                "packets": [],
                "plan_id": "unit-review-plan",
                "minimum_reviewers": 2,
            },
            [],
        ),
    )
    monkeypatch.setattr(campaign, "_git_state", lambda: (execution_commit, False))

    with pytest.raises(
        campaign.CampaignError,
        match="premeasurement packets must bind one frozen source commit",
    ):
        campaign._human_premeasurement_gate(execution_commit)


def test_safe_output_root_rejects_repository_and_ancestors():
    with pytest.raises(campaign.CampaignError):
        campaign._safe_output_root(campaign.ROOT)
    with pytest.raises(campaign.CampaignError):
        campaign._safe_output_root(campaign.ROOT.parent)
    with pytest.raises(campaign.CampaignError):
        campaign._safe_output_root(campaign.ROOT / "ctkat" / "campaign-output")
    assert (
        campaign._safe_output_root(campaign.ROOT / "measurement_runs" / "campaign-output")
        == (campaign.ROOT / "measurement_runs" / "campaign-output").resolve()
    )


def test_nested_binary_contract_artifacts_are_reparsed_and_attested(tmp_path, monkeypatch):
    config = tmp_path / "ctkat.yaml"
    source = tmp_path / "site.c"
    contract = tmp_path / "contract.yaml"
    config.write_text("project: unit\n", encoding="utf-8")
    source.write_text("unsigned site(unsigned x) { return x / 3; }\n", encoding="utf-8")
    contract.write_text(
        """
schema_version: "1.0"
kind: ctkat-timing-binary-instruction-contract
contract_id: unit-contract
system: Linux
machines: [x86_64, AMD64]
disassembler: objdump
file_format_pattern: elf64
targets:
  vulnerable:
    compiler: gcc
    cflags: [-Os, -fno-lto, -fno-omit-frame-pointer]
    comparison_group: unit
    evidence_boundary: unit test
    symbols:
      site: {division_count: 1, forbid_division_helpers: true}
""".lstrip(),
        encoding="utf-8",
    )
    target_root = tmp_path / "target"
    report_dir = target_root / "reports"
    contract_dir = report_dir / "binary_contract"
    generated_dir = target_root / "generated"
    contract_dir.mkdir(parents=True)
    generated_dir.mkdir(parents=True)
    binary = generated_dir / "timing_operand_bin"
    generated = generated_dir / "timing_operand_bin.c"
    fake_gcc = tmp_path / "gcc"
    fake_objdump = tmp_path / "objdump"
    binary.write_bytes(b"ELF-unit")
    generated.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    fake_gcc.write_bytes(b"fake-gcc")
    fake_objdump.write_bytes(b"fake-objdump")
    disassembly = contract_dir / "timing_operand_bin.objdump.txt"
    header = contract_dir / "timing_operand_bin.objdump-file-header.txt"
    disassembly.write_text(
        "0000000000001000 <site>:\n 1000:\tf7 f1\tdiv %ecx\n",
        encoding="utf-8",
    )
    header.write_text("file format elf64-x86-64\n", encoding="utf-8")
    symbol_rules = {"site": {"division_count": 1, "forbid_division_helpers": True}}
    observations, errors = campaign.evaluate_disassembly(
        disassembly.read_text(encoding="utf-8"), symbol_rules
    )
    assert errors == []

    def record(path):
        return {
            "path": str(path.resolve()),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "bytes": path.stat().st_size,
        }

    gcc_path = str(fake_gcc.resolve())
    objdump_path = str(fake_objdump.resolve())
    binary_path = str(binary.resolve())
    monkeypatch.setattr(
        campaign.shutil,
        "which",
        lambda command: {"gcc": gcc_path, "objdump": objdump_path}.get(command),
    )

    def fake_run(command, **_kwargs):
        if command == [gcc_path, "--version"]:
            return SimpleNamespace(returncode=0, stdout="gcc 13.3.0\n", stderr="")
        if command == [objdump_path, "--version"]:
            return SimpleNamespace(returncode=0, stdout="GNU objdump 2.42\n", stderr="")
        if command == [objdump_path, "-f", binary_path]:
            fresh_header = (
                header.read_text()
                if binary.read_bytes() == b"ELF-unit"
                else "file format elf32-i386\n"
            )
            return SimpleNamespace(returncode=0, stdout=fresh_header, stderr="")
        if command == [objdump_path, "-d", binary_path]:
            fresh_text = (
                "0000000000001000 <site>:\n 1000:\tf7 f1\tdiv %ecx\n"
                if binary.read_bytes() == b"ELF-unit"
                else "0000000000001000 <site>:\n 1000:\t90\tnop\n"
            )
            return SimpleNamespace(returncode=0, stdout=fresh_text, stderr="")
        raise AssertionError(f"unexpected command: {command}")

    monkeypatch.setattr(campaign.subprocess, "run", fake_run)
    objdump_record = record(fake_objdump)
    objdump_record.update(
        {
            "version": "GNU objdump 2.42",
            "version_command": [objdump_path, "--version"],
        }
    )
    gcc_record = record(fake_gcc)
    gcc_record["version_command"] = [gcc_path, "--version"]
    report = contract_dir / "timing_operand_bin.binary-contract.json"
    payload = {
        "schema_version": "1.0",
        "kind": "ctkat-timing-binary-contract-report",
        "contract_id": "unit-contract",
        "contract_target": "vulnerable",
        "passed": True,
        "errors": [],
        "contract_manifest": record(contract),
        "binary": record(binary),
        "generated_source": record(generated),
        "config": record(config),
        "linked_sources": [record(source)],
        "compiler": {
            "requested_command": "gcc",
            "cflags": ["-Os", "-fno-lto", "-fno-omit-frame-pointer"],
            "version": "gcc 13.3.0",
            "compile_command": "gcc -Os site.c -o timing_operand_bin",
            "executable": gcc_record,
        },
        "disassembly": {
            "tool": objdump_record,
            "command": [objdump_path, "-d", binary_path],
            "full_artifact": disassembly.name,
            "full_sha256": hashlib.sha256(disassembly.read_bytes()).hexdigest(),
            "file_header_command": [objdump_path, "-f", binary_path],
            "file_header_artifact": header.name,
            "file_header_sha256": hashlib.sha256(header.read_bytes()).hexdigest(),
            "symbols": observations,
        },
    }
    report.write_text(json.dumps(payload), encoding="utf-8")
    metadata = {
        "passed": True,
        "contract_id": "unit-contract",
        "contract_target": "vulnerable",
        "report": "binary_contract/timing_operand_bin.binary-contract.json",
        "report_sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "full_disassembly_sha256": hashlib.sha256(disassembly.read_bytes()).hexdigest(),
    }
    target = campaign.TargetSpec(
        id="unit",
        family="unit",
        config=config,
        harnesses=("operand_bin",),
        axes=(("operand_bin", "operand_bin"),),
        target_measurements=30_000,
        control_measurements=10_000,
        positive_control_effects=(1, 2, 3),
        timeout=30,
    )
    harness = SimpleNamespace(
        name="operand_bin",
        sources=[Path("site.c")],
        binary_contract=SimpleNamespace(
            manifest=Path("contract.yaml"),
            target="vulnerable",
        ),
    )
    hashes = {}
    assert (
        campaign._validate_binary_contract_artifacts(
            target=target,
            harness=harness,
            protocol={"binary_contract": metadata},
            report_dir=report_dir,
            artifact_sha256=hashes,
        )
        == []
    )
    assert set(hashes) == {
        "binary_contract/timing_operand_bin.binary-contract.json",
        "binary_contract/timing_operand_bin.objdump.txt",
        "binary_contract/timing_operand_bin.objdump-file-header.txt",
        "generated/timing_operand_bin",
        "generated/timing_operand_bin.c",
    }

    disassembly.write_text(
        "0000000000001000 <site>:\n 1000:\t90\tnop\n",
        encoding="utf-8",
    )
    payload["disassembly"]["full_sha256"] = hashlib.sha256(disassembly.read_bytes()).hexdigest()
    report.write_text(json.dumps(payload), encoding="utf-8")
    metadata["full_disassembly_sha256"] = payload["disassembly"]["full_sha256"]
    metadata["report_sha256"] = hashlib.sha256(report.read_bytes()).hexdigest()
    rejected = campaign._validate_binary_contract_artifacts(
        target=target,
        harness=harness,
        protocol={"binary_contract": metadata},
        report_dir=report_dir,
        artifact_sha256={},
    )
    assert any("exact div/idiv count=0" in error for error in rejected)

    # A forged report can update every recorded hash around a swapped binary,
    # but it cannot make fresh objdump output satisfy the committed contract.
    disassembly.write_text(
        "0000000000001000 <site>:\n 1000:\tf7 f1\tdiv %ecx\n",
        encoding="utf-8",
    )
    binary.write_bytes(b"ELF-forged")
    payload["binary"] = record(binary)
    payload["disassembly"]["full_sha256"] = hashlib.sha256(disassembly.read_bytes()).hexdigest()
    report.write_text(json.dumps(payload), encoding="utf-8")
    metadata["binary_sha256"] = payload["binary"]["sha256"]
    metadata["full_disassembly_sha256"] = payload["disassembly"]["full_sha256"]
    metadata["report_sha256"] = hashlib.sha256(report.read_bytes()).hexdigest()
    forged = campaign._validate_binary_contract_artifacts(
        target=target,
        harness=harness,
        protocol={"binary_contract": metadata},
        report_dir=report_dir,
        artifact_sha256={},
    )
    assert any("fresh file header does not match" in error for error in forged)
    assert any("fresh file header differs" in error for error in forged)
    assert any("fresh disassembly differs" in error for error in forged)
    assert any("fresh reparse" in error and "exact div/idiv count=0" in error for error in forged)

    # The validator runs only the trusted PATH resolution and binds its exact
    # identity to the recorded version rather than executing report-supplied paths.
    binary.write_bytes(b"ELF-unit")
    payload["binary"] = record(binary)
    payload["disassembly"]["tool"]["version"] = "GNU objdump forged"
    report.write_text(json.dumps(payload), encoding="utf-8")
    metadata["binary_sha256"] = payload["binary"]["sha256"]
    metadata["report_sha256"] = hashlib.sha256(report.read_bytes()).hexdigest()
    wrong_tool = campaign._validate_binary_contract_artifacts(
        target=target,
        harness=harness,
        protocol={"binary_contract": metadata},
        report_dir=report_dir,
        artifact_sha256={},
    )
    assert any("objdump current version differs" in error for error in wrong_tool)

    payload["disassembly"]["tool"]["version"] = "GNU objdump 2.42"
    payload["disassembly"]["tool"]["path"] = "/tmp/report-controlled-objdump"
    payload["disassembly"]["tool"]["version_command"] = [
        "/tmp/report-controlled-objdump",
        "--version",
    ]
    payload["disassembly"]["command"][0] = "/tmp/report-controlled-objdump"
    payload["disassembly"]["file_header_command"][0] = "/tmp/report-controlled-objdump"
    report.write_text(json.dumps(payload), encoding="utf-8")
    metadata["report_sha256"] = hashlib.sha256(report.read_bytes()).hexdigest()
    wrong_path = campaign._validate_binary_contract_artifacts(
        target=target,
        harness=harness,
        protocol={"binary_contract": metadata},
        report_dir=report_dir,
        artifact_sha256={},
    )
    assert any("objdump current path differs" in error for error in wrong_path)
