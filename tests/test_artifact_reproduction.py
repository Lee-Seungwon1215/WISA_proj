from pathlib import Path

import pytest
import yaml

from scripts.hash_artifacts import build_manifest
from scripts.reproduce_artifact import (
    COMPONENTS,
    measurement_ready_commands,
    premeasurement_commands,
    validate_bundle,
)


def test_premeasurement_command_contract_covers_every_frozen_component():
    commands = [" ".join(command) for command in premeasurement_commands()]
    for manifest in COMPONENTS.values():
        assert any(manifest in command and "--check" in command for command in commands)
    assert any("check_paper_reviews.py" in command for command in commands)
    assert any("check_corpus_correctness.py" in command for command in commands)
    assert any("build_paper_artifacts.py" in command for command in commands)


def test_measurement_ready_profile_requires_human_review_quorum():
    commands = [" ".join(command) for command in measurement_ready_commands()]
    assert any(
        "check_paper_reviews.py" in command and "--require-pre-measurement" in command
        for command in commands
    )


def test_hash_manifest_rejects_symlinks(tmp_path: Path):
    (tmp_path / "artifact.txt").write_text("ok\n")
    assert "artifact.txt" in build_manifest(tmp_path)
    (tmp_path / "link").symlink_to(tmp_path / "artifact.txt")
    with pytest.raises(ValueError, match="symlink"):
        build_manifest(tmp_path)


def test_final_bundle_requires_two_distinct_physical_hosts(tmp_path: Path):
    data = yaml.safe_load(
        (Path(__file__).parents[1] / "docs/artifact/measurement_bundle_template.yaml").read_text()
    )
    data["ctkat_commit"] = "a" * 40
    data["hosts"][0]["cpu_model"] = "cpu-a"
    data["hosts"][1]["cpu_model"] = "cpu-a"
    path = tmp_path / "bundle.yaml"
    path.write_text(yaml.safe_dump(data))
    with pytest.raises(ValueError, match="CPU models"):
        validate_bundle(path, "a" * 40)
