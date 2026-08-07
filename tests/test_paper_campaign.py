from copy import deepcopy

from scripts.check_paper_campaign import load_manifest, validate


def test_frozen_paper_campaign_is_static_ready():
    errors, report = validate(load_manifest())
    assert errors == []
    assert report["status"] == "static-plan-valid"
    assert report["component_count"] == 4
    assert report["timing_axes"] == 25
    assert report["physical_hosts_required"] == 2


def test_one_host_or_automatic_promotion_fails_closed():
    data = deepcopy(load_manifest())
    data["execution_policy"]["minimum_physical_hosts"] = 1
    data["promotion"]["automatic_corpus_mutation"] = True
    errors, _ = validate(data)
    assert any("minimum_physical_hosts" in error for error in errors)
    assert any("automatic_corpus_mutation" in error for error in errors)


def test_upstream_pin_drift_is_rejected():
    data = deepcopy(load_manifest())
    data["upstream_freeze"]["mlkem-native"]["revision"] = "0" * 40
    errors, _ = validate(data)
    assert any("upstream_freeze.mlkem-native.revision" in error for error in errors)
