from copy import deepcopy

from scripts.check_corpus_correctness import (
    load_manifest,
    load_snapshot,
    validate_manifest,
    validate_snapshot,
)


def test_correctness_manifest_and_snapshot_are_closed():
    data = load_manifest()
    assert validate_manifest(data) == []
    snapshot = load_snapshot(data)
    assert validate_snapshot(data, snapshot) == []
    assert len(snapshot["targets"]) == 9
    assert all(record["status"] == "pass" for record in snapshot["targets"])


def test_correctness_snapshot_hash_drift_fails_closed():
    data = load_manifest()
    snapshot = deepcopy(load_snapshot(data))
    snapshot["targets"][0]["transcript_sha256"] = "not-a-sha256"
    errors = validate_snapshot(data, snapshot)
    assert any("transcript" in error or "drift" in error for error in errors)
