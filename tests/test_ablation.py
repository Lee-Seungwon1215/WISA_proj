from copy import deepcopy

import pytest

from scripts.run_ablation import build_report, load_manifest, validate_manifest


def test_ablation_report_keeps_native_timing_explicitly_pending():
    report = build_report(load_manifest())
    assert [stage["stage"] for stage in report["stages"]][-1] == "official-versus-legacy-timing"
    assert report["stages"][-1]["status"] == "pending-physical-native-measurement"
    assert report["stages"][-1]["pairs"] == ""


def test_full_matrix_never_has_fewer_cells_than_single_build():
    stages = build_report(load_manifest())["stages"]
    assert stages[1]["cells"] > stages[0]["cells"]
    assert stages[2]["candidate_pairs"] >= stages[1]["candidate_pairs"]


def test_missing_as_zero_policy_fails_closed():
    data = deepcopy(load_manifest())
    data["deferred_stage"]["zero_must_not_mean_missing"] = False
    assert any("never be encoded as zero" in error for error in validate_manifest(data))
    with pytest.raises(ValueError):
        build_report(data)
