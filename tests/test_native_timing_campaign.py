import csv
import hashlib
import json
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from ctkat.official_dudect import (
    OFFICIAL_DUDECT_BACKEND,
    OFFICIAL_DUDECT_REVISION,
)
from scripts import run_native_timing_campaign as campaign


def test_committed_campaign_covers_every_existing_timing_row():
    spec = campaign.load_campaign()
    assert campaign.static_check(spec) == []
    pairs = {(target.id, harness) for target in spec.targets for harness in target.harnesses}
    assert pairs == campaign._corpus_timing_pairs()
    axes = {
        (target.id, harness, target.axis_for(harness))
        for target in spec.targets
        for harness in target.harnesses
    }
    assert axes == campaign._corpus_timing_axes()
    assert len(spec.targets) == 6
    assert len(pairs) == 8


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
    assert dudect.timing_protocol.positive_control_effects == [512, 4096, 32768]
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
            "cpu_affinity": [2],
            "rejected": False,
            "rejection_reasons": [],
        },
    )
    monkeypatch.setattr(campaign, "_detect_virtualization", lambda: {"vm": "", "container": ""})
    monkeypatch.setattr(campaign, "_git_state", lambda: ("a" * 40, False))
    monkeypatch.setattr(campaign, "_command_version", lambda command: "gcc 14.2.0")
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
    assert result["official_adapter_built"] is True
    assert result["errors"] == []


def test_preflight_override_never_promotes_virtualized_or_dirty_host(monkeypatch):
    spec = campaign.load_campaign()
    monkeypatch.setattr(campaign.platform, "system", lambda: "Linux")
    monkeypatch.setattr(campaign.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(campaign, "detect_qemu_emulation", lambda: False)
    monkeypatch.setattr(
        campaign,
        "collect_timing_environment",
        lambda **kwargs: {
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
        "official_adapter_built": True,
        "virtualization": {"vm": "", "container": ""},
        "environment": {
            "system": "Linux",
            "machine": "x86_64",
            "clock": "rdtsc",
            "emulated": False,
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


def _small_artifact_fixture(tmp_path):
    base = campaign.load_campaign()
    protocol = replace(base.protocol, process_repeats=1, pool_size=4)
    target = replace(
        base.targets[1],
        target_measurements=4,
        control_measurements=2,
        positive_control_effects=(1, 2, 3),
    )
    spec = replace(base, protocol=protocol, targets=(target,))
    report_dir = tmp_path / target.id / "reports"
    report_dir.mkdir(parents=True)

    (report_dir / "dudect_raw_timings.csv").write_text("raw\n", encoding="utf-8")
    (report_dir / "dudect_calibration_timings.csv").write_text("calibration\n", encoding="utf-8")
    protocol_rows = []
    expected = campaign._expected_protocol_counts(spec, target)
    analysis_seed = None
    for trace_index, ((harness, role, process_index, effect), count) in enumerate(
        expected.items(),
        start=1,
    ):
        trace_seed = 100 + trace_index
        if role == "target":
            analysis_seed = trace_seed
        for sample_id in range(count):
            protocol_rows.append(
                {
                    "project": target.id,
                    "harness": harness,
                    "role": role,
                    "process_index": process_index,
                    "seed": trace_seed,
                    "effect_ticks": effect,
                    "sample_id": sample_id,
                    "class": sample_id % 2,
                    "cycles": 100 + sample_id,
                    "aux_start": 2,
                    "aux_end": 2,
                    "drop_reason": "",
                    "output_length": 32,
                    "protocol": "timing-harness-v2",
                }
            )
    _write_csv(
        report_dir / "dudect_protocol_timings.csv",
        campaign.PROTOCOL_HEADER,
        protocol_rows,
    )
    _write_csv(
        report_dir / "dudect_summary.csv",
        sorted(campaign.SUMMARY_REQUIRED_COLUMNS),
        [
            {
                "project": target.id,
                "harness": "sign",
                "n0": "2",
                "n1": "2",
                "abs_t_score": "1.0",
                "status": "PASS",
                "backend": OFFICIAL_DUDECT_BACKEND,
                "timing_validity": "valid",
                "raw_n_total": "4",
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
        "target_measurements": 4,
        "control_measurements": 2,
        "process_repeats_required": 3,
        "process_repeats_observed": 1,
        "target_status_consistent": True,
        "aa_abs_t_limit": protocol.aa_abs_t_limit,
        "aa_max_failures": protocol.aa_max_failures,
        "positive_abs_t_threshold": protocol.positive_abs_t_threshold,
        "target_power": protocol.target_power,
        "power_alpha": protocol.power_alpha,
        "positive_power_curve": [{"effect_ticks": effect} for effect in (1, 2, 3)],
        "target_repeats": [{"enough_measurements": True}],
        "aa_controls": [{}],
        "aa_failures": 0,
        "aa_budget_passed": True,
        "setup_placebo_controls": [{}],
        "setup_placebo_passed": True,
        "positive_controls": [{}, {}, {}],
        "positive_power_passed": True,
        "randomness_policies_observed": ["seeded-interpose"],
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
                "raw_status": "PASS",
                "timing_validity": "valid",
                "validity_reasons": [],
                "abs_t_score": 1.0,
                "analysis_seed": analysis_seed,
                "analysis_raw_n_total": 4,
                "n0": 2,
                "n1": 2,
                "enough_measurements": True,
                "environment": {"rejected": False},
                "protocol_test_count": 102,
                "tests": [{"index": index} for index in range(102)],
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


def test_complete_underpowered_bundle_is_nonpromotable_not_corrupt(tmp_path):
    spec, target, report_dir = _small_artifact_fixture(tmp_path)
    backend_path = report_dir / "dudect_backend_report.json"
    backend = json.loads(backend_path.read_text(encoding="utf-8"))
    item = backend["harnesses"][0]
    item["raw_status"] = "INSUFFICIENT"
    item["timing_validity"] = "insufficient-power"
    item["validity_reasons"] = ["official class-0 minimum was not met"]
    item["enough_measurements"] = False
    backend_path.write_text(json.dumps(backend), encoding="utf-8")

    summary_path = report_dir / "dudect_summary.csv"
    with summary_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        rows = list(reader)
    assert fieldnames is not None
    rows[0]["status"] = "INSUFFICIENT"
    rows[0]["timing_validity"] = "insufficient-power"
    _write_csv(summary_path, fieldnames, rows)

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

    def fake_dudect(_dudect, _config_dir, project, report_dir):
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
            resume=False,
            continue_on_error=False,
        )
        == 0
    )
    assert calls == [target.id]
    report = json.loads((output_root / "campaign_report.json").read_text(encoding="utf-8"))
    assert report["status"] == "complete"
    assert report["targets"][target.id]["promotion_ready"] is True
    assert campaign.validate_run(spec, output_root, (target,)) == 0

    calls.clear()
    assert (
        campaign.execute_campaign(
            spec,
            output_root,
            (target,),
            preflight_report=preflight,
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
    assert campaign.validate_run(spec, output_root, (target,)) == 1


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
