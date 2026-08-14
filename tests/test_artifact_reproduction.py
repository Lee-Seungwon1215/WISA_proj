import json
import subprocess
from pathlib import Path

import pytest
import yaml

from scripts import reproduce_artifact as reproduction
from scripts.hash_artifacts import build_manifest
from scripts.reproduce_artifact import (
    BLINDED_ANALYSIS_FILES,
    COMPONENTS,
    FINAL_EVIDENCE_MANIFEST,
    NAMED_ANALYSIS_FILES,
    POST_VERIFICATION_ALLOWED_PATH,
    _require_review_only_descendant,
    build_final_evidence_manifest,
    engineering_ready_commands,
    final_evidence_root_sha256,
    measurement_ready_commands,
    native_engineering_ready_commands,
    premeasurement_commands,
    validate_bundle,
    verify_final_evidence_manifest,
    write_final_evidence_manifest,
)


def test_premeasurement_command_contract_covers_every_frozen_component():
    commands = [" ".join(command) for command in premeasurement_commands()]
    for manifest in COMPONENTS.values():
        assert any(manifest in command and "--check" in command for command in commands)
    assert any("check_paper_reviews.py" in command for command in commands)
    assert any("check_corpus_correctness.py" in command for command in commands)
    assert any("build_paper_artifacts.py" in command for command in commands)
    assert any("check_asm_evidence.py" in command and "--static" in command for command in commands)
    assert any("check_automated_audits.py" in command for command in commands)


def test_reproducer_routes_only_replacement_core_and_diverse_manifests():
    assert COMPONENTS["committed-corpus-refresh"] == (
        "docs/measurement/native_timing_v5_campaign.yaml"
    )
    assert COMPONENTS["kyberslash-contrast"] == "docs/measurement/kyberslash_native_v5.yaml"
    assert COMPONENTS["falcon-contrast"] == "docs/measurement/falcon_native_v4.yaml"
    assert COMPONENTS["diverse-lineages"] == "docs/measurement/diverse_native_v4.yaml"
    assert "native_timing_v2_campaign.yaml" not in COMPONENTS.values()
    assert "diverse_native_v1.yaml" not in COMPONENTS.values()


def test_engineering_ready_profile_requires_automated_audits_but_not_humans():
    commands = [" ".join(command) for command in engineering_ready_commands()]
    assert any(
        "check_automated_audits.py" in command and "--require-engineering-ready" in command
        for command in commands
    )
    assert not any("--require-pre-measurement" in command for command in commands)
    assert any("uv lock --check" in command for command in commands)
    assert any("-m ruff check ctkat scripts tests" in command for command in commands)
    assert any("-m ruff format --check ctkat scripts tests" in command for command in commands)
    assert any("-m mypy ctkat" in command for command in commands)


def test_native_engineering_ready_profile_adds_backend_calibration():
    commands = [" ".join(command) for command in native_engineering_ready_commands()]
    assert any("calibrate_timing_backend.py --check" in command for command in commands)
    assert not any("--require-pre-measurement" in command for command in commands)


def test_measurement_ready_profile_requires_human_review_quorum():
    commands = [" ".join(command) for command in measurement_ready_commands()]
    assert any(
        "check_paper_reviews.py" in command and "--require-pre-measurement" in command
        for command in commands
    )
    assert any("calibrate_timing_backend.py --check" in command for command in commands)


def test_bundle_review_descendant_allows_only_native_promotion_packet(monkeypatch):
    def allowed_git(*args):
        if args[:2] == ("diff", "--name-only"):
            return POST_VERIFICATION_ALLOWED_PATH
        return ""

    monkeypatch.setattr("scripts.reproduce_artifact._git", allowed_git)
    _require_review_only_descendant("a" * 40, "b" * 40)

    def drifted_git(*args):
        if args[:2] == ("diff", "--name-only"):
            return "docs/reviews/paper/manifest.yaml\n.github/workflows/ci.yml"
        return ""

    monkeypatch.setattr("scripts.reproduce_artifact._git", drifted_git)
    with pytest.raises(ValueError, match="outside the sole review packet"):
        _require_review_only_descendant("a" * 40, "b" * 40)


def test_hash_manifest_rejects_symlinks(tmp_path: Path):
    (tmp_path / "artifact.txt").write_text("ok\n")
    assert "artifact.txt" in build_manifest(tmp_path)
    (tmp_path / "link").symlink_to(tmp_path / "artifact.txt")
    with pytest.raises(ValueError, match="symlink"):
        build_manifest(tmp_path)


def test_source_manifest_rejects_tracked_nonregular_entries(tmp_path: Path, monkeypatch):
    target = tmp_path / "target.txt"
    target.write_text("payload\n", encoding="utf-8")
    (tmp_path / "tracked-link").symlink_to(target)
    monkeypatch.setattr(reproduction, "ROOT", tmp_path)
    monkeypatch.setattr(reproduction, "_git", lambda *_args: "tracked-link")

    with pytest.raises(ValueError, match="not a regular file"):
        reproduction._source_manifest()


def test_final_bundle_requires_two_distinct_physical_hosts(tmp_path: Path):
    data = yaml.safe_load(
        (Path(__file__).parents[1] / "docs/artifact/measurement_bundle_template.yaml").read_text()
    )
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=Path(__file__).parents[1],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    data["measurement_commit"] = head
    data["verification_commit"] = head
    data["hosts"][0]["cpu_model"] = "cpu-a"
    data["hosts"][1]["cpu_model"] = "cpu-a"
    path = tmp_path / "bundle.yaml"
    path.write_text(yaml.safe_dump(data))
    with pytest.raises(ValueError, match="CPU models"):
        validate_bundle(path, head)


def _final_evidence_fixture(tmp_path: Path):
    bundle = tmp_path / "measurement_bundle.yaml"
    bundle.write_text("schema_version: 4\nbundle_id: test-bundle\n", encoding="utf-8")
    host_manifests = []
    for index in range(2):
        path = tmp_path / f"host-{index}-SHA256SUMS"
        path.write_text(f"{'a' * 64}  artifact-{index}\n", encoding="utf-8")
        host_manifests.append(path)
    assembly = tmp_path / "asm_evidence_bundle.json"
    assembly.write_text('{"paper_eligible":true}\n', encoding="utf-8")
    unblinding = tmp_path / "unblinding.yaml"
    unblinding.write_text("kind: test-unblinding\n", encoding="utf-8")
    blinded = tmp_path / "blinded-analysis"
    named = tmp_path / "candidate" / "named-analysis"
    blinded.mkdir()
    named.mkdir(parents=True)
    for name in BLINDED_ANALYSIS_FILES:
        (blinded / name).write_text(f"blinded:{name}\n", encoding="utf-8")
    for name in NAMED_ANALYSIS_FILES:
        (named / name).write_text(f"named:{name}\n", encoding="utf-8")
    report = {
        "bundle_id": "test-bundle",
        "measurement_commit": "1" * 40,
        "verification_commit": "2" * 40,
        "hosts": [
            {"id": "host-b", "hash_manifest": str(host_manifests[1])},
            {"id": "host-a", "hash_manifest": str(host_manifests[0])},
        ],
        "assembly_evidence": {"mlkem_public_attribution": {"bundle": str(assembly)}},
        "blinded_analysis_root": str(blinded),
        "unblinding_record": str(unblinding),
    }
    return bundle, report, named.parent


def test_final_evidence_root_is_deterministic_and_self_verifying(tmp_path: Path):
    bundle, report, candidate = _final_evidence_fixture(tmp_path)
    manifest = build_final_evidence_manifest(bundle, report, candidate / "named-analysis")
    assert manifest == build_final_evidence_manifest(bundle, report, candidate / "named-analysis")
    assert manifest["final_evidence_root_sha256"] == final_evidence_root_sha256(manifest)

    write_final_evidence_manifest(candidate / FINAL_EVIDENCE_MANIFEST, manifest)
    assert verify_final_evidence_manifest(candidate, bundle, report) == manifest
    schema = json.loads(
        (Path(__file__).parents[1] / "docs/artifact/final-evidence-root-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    assert set(schema["required"]) == set(manifest)
    assert set(schema["properties"]) == set(manifest)


def test_final_evidence_verification_rejects_bound_output_tampering(tmp_path: Path):
    bundle, report, candidate = _final_evidence_fixture(tmp_path)
    manifest = build_final_evidence_manifest(bundle, report, candidate / "named-analysis")
    write_final_evidence_manifest(candidate / FINAL_EVIDENCE_MANIFEST, manifest)
    (candidate / "named-analysis" / "paper_native_analysis.md").write_text(
        "tampered\n", encoding="utf-8"
    )

    with pytest.raises(ValueError, match="bound artifact bytes drifted"):
        verify_final_evidence_manifest(candidate, bundle, report)


def test_final_evidence_rejects_analysis_file_set_drift(tmp_path: Path):
    bundle, report, candidate = _final_evidence_fixture(tmp_path)
    (candidate / "named-analysis" / "unreviewed-notes.txt").write_text("extra\n", encoding="utf-8")

    with pytest.raises(ValueError, match="file set drift"):
        build_final_evidence_manifest(bundle, report, candidate / "named-analysis")
