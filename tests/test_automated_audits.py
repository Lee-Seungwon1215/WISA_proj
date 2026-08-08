from __future__ import annotations

import subprocess
from copy import deepcopy
from pathlib import Path

import yaml

from scripts import check_automated_audits as audits
from scripts import check_paper_reviews as paper_reviews


def _load_committed_packet(perspective: str) -> tuple[Path, dict]:
    manifest = audits._load_yaml(audits.DEFAULT_MANIFEST)
    entry = next(item for item in manifest["audits"] if item["perspective"] == perspective)
    path = audits.ROOT / entry["path"]
    return path, audits._load_yaml(path)


def test_committed_automated_audits_are_engineering_ready_but_never_human_ready():
    report, errors = audits.evaluate_manifest()

    assert errors == []
    assert report["static_valid"] is True
    assert report["engineering_ready"] is True
    assert report["automated_audit_count"] == 4
    assert report["human_review_credit"] is False
    assert report["pre_measurement_human_gate_satisfied"] is False
    assert report["final_human_gate_satisfied"] is False
    assert report["accepted_blockers"]
    assert {item["perspective"] for item in report["audits"]} == audits.REQUIRED_PERSPECTIVES
    assert all(item["automated_agent"] is True for item in report["audits"])
    assert all(item["human_reviewer"] is False for item in report["audits"])


def test_open_critical_finding_blocks_engineering_readiness_without_becoming_human_review():
    path, packet = _load_committed_packet("artifact-blind-integrity")
    packet = deepcopy(packet)
    disposition = next(item for item in packet["dispositions"] if item["finding_id"] == "abi-001")
    disposition["status"] = "open"
    disposition["blocker"] = "host provenance remediation has not been completed"

    record, errors = audits.validate_audit(
        packet,
        root=audits.ROOT,
        path=path,
        expected_perspective="artifact-blind-integrity",
    )

    assert errors == []
    assert record["unresolved_high_or_critical"] == ["abi-001"]
    assert record["human_reviewer"] is False
    assert record["human_gate_effect"] == "none"


def test_addressed_and_accepted_with_blocker_dispositions_are_fail_closed():
    path, packet = _load_committed_packet("signature-harness-contracts")

    addressed_with_blocker = deepcopy(packet)
    addressed = next(
        item for item in addressed_with_blocker["dispositions"] if item["status"] == "addressed"
    )
    addressed["blocker"] = "quietly retained blocker"
    _, errors = audits.validate_audit(
        addressed_with_blocker,
        root=audits.ROOT,
        path=path,
        expected_perspective="signature-harness-contracts",
    )
    assert any("addressed disposition cannot retain blocker" in error for error in errors)

    accepted_without_blocker = deepcopy(packet)
    accepted = next(
        item
        for item in accepted_without_blocker["dispositions"]
        if item["status"] == "accepted-with-blocker"
    )
    accepted["blocker"] = ""
    _, errors = audits.validate_audit(
        accepted_without_blocker,
        root=audits.ROOT,
        path=path,
        expected_perspective="signature-harness-contracts",
    )
    assert any("accepted-with-blocker requires" in error for error in errors)


def test_evidence_hash_drift_and_human_promotion_attempt_are_rejected():
    path, packet = _load_committed_packet("native-analysis-statistics")
    packet = deepcopy(packet)
    packet["evidence"][0]["sha256"] = "0" * 64
    packet["human_reviewer"] = True
    packet["human_gate_effect"] = "pre-measurement"

    _, errors = audits.validate_audit(
        packet,
        root=audits.ROOT,
        path=path,
        expected_perspective="native-analysis-statistics",
    )

    assert any("sha256 mismatch" in error for error in errors)
    assert any("human_reviewer must be false" in error for error in errors)
    assert any("human_gate_effect must be none" in error for error in errors)


def test_automated_audit_manifest_cannot_point_into_paper_reviews(tmp_path: Path):
    manifest = deepcopy(audits._load_yaml(audits.DEFAULT_MANIFEST))
    manifest["audits"][0]["path"] = "docs/reviews/paper/mlkem-public-attribution-v2.yaml"
    path = tmp_path / "manifest.yaml"
    path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")

    report, errors = audits.evaluate_manifest(path, root=audits.ROOT)

    assert report["engineering_ready"] is False
    assert any("never docs/reviews" in error for error in errors)


def test_automated_agents_cannot_satisfy_paper_reviewer_schema():
    packet = deepcopy(
        paper_reviews._load_yaml(
            paper_reviews.ROOT / "docs/reviews/paper/mlkem-public-attribution-v2.yaml"
        )
    )
    packet["status"] = "reviewed"
    commit = paper_reviews._git(paper_reviews.ROOT, "rev-parse", "HEAD")
    evidence_digest = paper_reviews.evidence_manifest_sha256(packet, root=paper_reviews.ROOT)
    packet["reviewers"] = [
        {
            "id": f"automated-agent-{index}",
            "human_reviewer": False,
            "affiliation_or_role": "automated adversarial audit",
            "independent_from_artifact_author": True,
            "decision": "approve",
            "reviewed_at": f"2026-08-08T0{index}:00:00Z",
            "reviewed_commit": commit,
            "evidence_manifest_sha256": evidence_digest,
            "notes": "automated output; explicitly not a human sign-off",
        }
        for index in (1, 2)
    ]

    errors = paper_reviews.validate_packet(
        packet,
        root=paper_reviews.ROOT,
        path=paper_reviews.ROOT / "docs/reviews/paper/mlkem-public-attribution-v2.yaml",
        minimum_reviewers=2,
        required_before_measurement=True,
    )

    assert sum("is not declared human" in error for error in errors) == 2
    audit_report, audit_errors = audits.evaluate_manifest()
    assert audit_errors == []
    assert audit_report["human_review_credit"] is False


def test_audited_commit_rejects_later_unlisted_critical_drift(tmp_path: Path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "Audit Fixture"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "audit@example.invalid"],
        cwd=tmp_path,
        check=True,
    )
    critical = tmp_path / "ctkat" / "critical.py"
    critical.parent.mkdir()
    critical.write_text("SAFE = True\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "audited source"], cwd=tmp_path, check=True)
    audited_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        check=True,
        text=True,
        capture_output=True,
    ).stdout.strip()

    critical.write_text("SAFE = False\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "critical drift"], cwd=tmp_path, check=True)

    errors = audits._audit_provenance_errors(tmp_path, audited_commit, "fixture")
    assert any("ctkat/critical.py" in error for error in errors)
