import json
from copy import deepcopy

from scripts import run_paper_control_rehearsal as rehearsal


def _passing_protocol():
    positives = []
    for process_index in range(3):
        for effect, t_score in ((64, -2.0), (512, -11.0), (4096, -20.0)):
            positives.append(
                {
                    "process_index": process_index,
                    "effect_ticks": effect,
                    "t_score": t_score,
                    "abs_t_score": abs(t_score),
                    "mean_delta": float(effect),
                }
            )
    return {
        "target_measurements": 1_000,
        "control_measurements": 10_000,
        "process_repeats_observed": 3,
        "positive_power_passed": True,
        "aa_budget_passed": True,
        "setup_placebo_passed": True,
        "randomness_policy_expected": "seeded-interpose",
        "randomness_policies_observed": ["seeded-interpose"],
        "positive_power_curve": [
            {"effect_ticks": 64},
            {"effect_ticks": 512},
            {"effect_ticks": 4096},
        ],
        "aa_controls": [{"abs_t_score": value} for value in (1.0, 2.0, 3.0)],
        "setup_placebo_controls": [{"abs_t_score": value} for value in (0.5, 1.5, 2.5)],
        "positive_controls": positives,
        "target_repeats": [{}, {}, {}],
        "target_status_consistent": False,
    }


def test_frozen_rehearsal_profile_covers_all_axes_and_baselines():
    errors, report = rehearsal.validate_profile(rehearsal.load_profile())
    assert errors == []
    assert report["status"] == "valid"
    assert report["targets"] == 26
    assert report["axes"] == 28
    assert report["baselines"] == 3
    assert report["target_measurements"] == 1_000
    assert report["required_clean_runs"] == 2
    assert report["profile_id"] == "ctkat-paper-control-rehearsal-v3"
    assert report["calibration"] == ("docs/measurement/paper_control_rehearsal_v2_calibration.yaml")


def test_reduced_target_status_is_ignored_but_control_headroom_is_required():
    profile = rehearsal.load_profile()
    summary, blockers = rehearsal._assess_control_protocol(
        _passing_protocol(),
        subject="component/target/harness",
        target_measurements=1_000,
        control_measurements=10_000,
        effects=(64, 512, 4096),
        process_repeats=3,
        randomness_policy="seeded-interpose",
        margins=profile["safety_margins"],
    )
    assert blockers == []
    assert summary["target_status_consistent_observed"] is False
    assert summary["target_statistics_interpretable"] is False
    assert summary["final_controls_passed"] is True
    assert summary["safety_margins_passed"] is True

    near_cliff = _passing_protocol()
    near_cliff["positive_controls"][-1]["t_score"] = -12.0
    near_cliff["positive_controls"][-1]["abs_t_score"] = 12.0
    _, blockers = rehearsal._assess_control_protocol(
        near_cliff,
        subject="component/target/harness",
        target_measurements=1_000,
        control_measurements=10_000,
        effects=(64, 512, 4096),
        process_repeats=3,
        randomness_policy="seeded-interpose",
        margins=profile["safety_margins"],
    )
    assert any(blocker["code"] == "control.positive-margin" for blocker in blockers)


def test_reversed_positive_direction_never_passes_rehearsal_margin():
    protocol = _passing_protocol()
    protocol["positive_controls"][-1]["mean_delta"] = -4096.0
    _, blockers = rehearsal._assess_control_protocol(
        protocol,
        subject="component/target/harness",
        target_measurements=1_000,
        control_measurements=10_000,
        effects=(64, 512, 4096),
        process_repeats=3,
        randomness_policy="seeded-interpose",
        margins=rehearsal.load_profile()["safety_margins"],
    )
    assert any(blocker["code"] == "control.positive-direction" for blocker in blockers)


def test_null_control_uses_unchanged_final_limit_not_arbitrary_headroom():
    protocol = _passing_protocol()
    protocol["aa_controls"][0]["abs_t_score"] = 3.7920758863707618
    summary, blockers = rehearsal._assess_control_protocol(
        protocol,
        subject="component/target/harness",
        target_measurements=1_000,
        control_measurements=10_000,
        effects=(64, 512, 4096),
        process_repeats=3,
        randomness_policy="seeded-interpose",
        margins=rehearsal.load_profile()["safety_margins"],
    )
    assert not any(blocker["code"] == "control.aa-margin" for blocker in blockers)
    assert summary["aa_max_abs_t"] == 3.7920758863707618


def _clean_report(run_id):
    profile = rehearsal.load_profile()
    report = rehearsal._new_report(
        profile,
        rehearsal.DEFAULT_PROFILE,
        phase="all",
        commit="a" * 40,
    )
    report["run_id"] = run_id
    report["finished_at"] = "2026-08-12T12:00:00Z"
    report["status"] = "pass"
    report["smoke"] = {
        "expected_axes": 28,
        "completed_axes": 28,
        "passed_axes": 28,
        "axes": {
            f"axis-{index}": {
                "component": "component",
                "target": "target",
                "harness": f"harness-{index}",
                "axis": "sk",
                "status": "pass",
                "errors": [],
                "artifacts": {},
            }
            for index in range(28)
        },
    }
    report["native_components"] = {
        component: {"status": "pass"} for component in rehearsal.COMPONENT_IDS
    }
    report["baselines"] = {baseline: {"status": "pass"} for baseline in rehearsal.BASELINE_IDS}
    report["assembly"] = {"status": "pass"}
    report["pipeline_closure"] = {
        "status": "pass",
        "shared_identity_values": {
            "machine_id_sha256": [json.dumps("1" * 64)],
            "boot_id_sha256": [json.dumps("2" * 64)],
            "cpu_model": [json.dumps("Unit Test CPU")],
            "smt_active": [json.dumps("0")],
            "intel_pstate_no_turbo": [json.dumps("1")],
            "system": [json.dumps("Linux")],
            "machine": [json.dumps("x86_64")],
        },
        "affinities": [json.dumps([2])],
    }
    report["summary"] = {
        "smoke_axes_passed": 28,
        "native_axes_assessed": 28,
        "native_components_passed": 4,
        "baselines_passed": 3,
        "assembly_passed": True,
        "pipeline_closure_passed": True,
        "blocker_count": 0,
        "target_statistics_interpretable": False,
        "promotion_allowed": False,
    }
    report["blockers"] = []
    return report


def test_qualification_requires_two_distinct_clean_runs_at_one_commit(tmp_path):
    paths = [tmp_path / "first.json", tmp_path / "second.json"]
    for path, run_id in zip(paths, ("1" * 32, "2" * 32), strict=True):
        rehearsal._write_json_atomic(path, _clean_report(run_id), validate=True)
    result, errors = rehearsal.qualify_reports(
        paths,
        output=tmp_path / "qualification.json",
        expected_commit="a" * 40,
    )
    assert errors == []
    assert result["schema_version"] == "3.0"
    assert result["kind"] == "ctkat-v10-final-control-qualification"
    assert result["candidate_commit"] == "a" * 40
    assert result["profile_id"] == "ctkat-paper-control-rehearsal-v3"
    assert result["final_launch_ready"] is True
    assert result["observed_clean_runs"] == 2
    assert len(result["rehearsals"]) == 2

    duplicate = deepcopy(_clean_report("1" * 32))
    paths[1].write_text(json.dumps(duplicate), encoding="utf-8")
    result, errors = rehearsal.qualify_reports(
        paths,
        output=None,
        expected_commit="a" * 40,
    )
    assert result["final_launch_ready"] is False
    assert any("distinct run IDs" in error for error in errors)


def test_qualification_rejects_rehearsals_from_different_physical_hosts(tmp_path):
    paths = [tmp_path / "first.json", tmp_path / "second.json"]
    reports = [_clean_report("1" * 32), _clean_report("2" * 32)]
    reports[1]["pipeline_closure"]["shared_identity_values"]["machine_id_sha256"] = [
        json.dumps("9" * 64)
    ]
    for path, report in zip(paths, reports, strict=True):
        rehearsal._write_json_atomic(path, report, validate=True)

    result, errors = rehearsal.qualify_reports(
        paths,
        output=None,
        expected_commit="a" * 40,
    )

    assert result["final_launch_ready"] is False
    assert any("one machine_id_sha256" in error for error in errors)
