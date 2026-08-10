from __future__ import annotations

from copy import deepcopy

import pytest

from scripts import check_paper_reviews as reviews


def test_committed_review_packets_are_static_valid_and_have_no_partial_signoffs():
    report, errors = reviews.evaluate_manifest()

    assert errors == []
    assert report["static_valid"] is True
    assert report["pre_measurement_reviewed_source_commits"] == []
    assert report["post_measurement_reviewed_source_commits"] == []
    assert sum(report["status_counts"].values()) == 8
    assert all(
        record["status"] != "pending" or record["reviewer_count"] == 0
        for record in report["packets"]
    )


def test_reviewed_packet_requires_two_unique_independent_approvals():
    packet = reviews._load_yaml(
        reviews.ROOT / "docs/reviews/paper/mlkem-public-attribution-v2.yaml"
    )
    packet = deepcopy(packet)
    packet["status"] = "reviewed"
    commit = reviews._git(reviews.ROOT, "rev-parse", "HEAD")
    evidence_digest = reviews.evidence_manifest_sha256(packet, root=reviews.ROOT)
    packet["reviewers"] = [
        {
            "id": "reviewer-one",
            "human_reviewer": True,
            "affiliation_or_role": "independent security reviewer",
            "independent_from_artifact_author": True,
            "decision": "approve",
            "reviewed_at": "2026-08-07T00:00:00Z",
            "reviewed_commit": commit,
            "evidence_manifest_sha256": evidence_digest,
            "notes": "source and artifacts checked",
        }
    ]
    errors = reviews.validate_packet(
        packet,
        root=reviews.ROOT,
        path=reviews.ROOT / "docs/reviews/paper/mlkem-public-attribution-v2.yaml",
        minimum_reviewers=2,
        required_before_measurement=True,
    )
    assert any("at least 2" in error for error in errors)

    packet["reviewers"].append(
        {
            "id": "reviewer-two",
            "human_reviewer": True,
            "affiliation_or_role": "independent cryptography reviewer",
            "independent_from_artifact_author": True,
            "decision": "approve",
            "reviewed_at": "2026-08-07T01:00:00Z",
            "reviewed_commit": commit,
            "evidence_manifest_sha256": evidence_digest,
            "notes": "independent source and artifacts checked",
        }
    )
    assert (
        reviews.validate_packet(
            packet,
            root=reviews.ROOT,
            path=reviews.ROOT / "docs/reviews/paper/mlkem-public-attribution-v2.yaml",
            minimum_reviewers=2,
            required_before_measurement=True,
        )
        == []
    )

    packet["security_argument"] = "materially changed after approval"
    errors = reviews.validate_packet(
        packet,
        root=reviews.ROOT,
        path=reviews.ROOT / "docs/reviews/paper/mlkem-public-attribution-v2.yaml",
        minimum_reviewers=2,
        required_before_measurement=True,
    )
    assert sum("evidence manifest hash mismatch" in error for error in errors) == 2


def test_pending_packet_cannot_hide_partial_signoff():
    packet = reviews._load_yaml(
        reviews.ROOT / "docs/reviews/paper/mlkem-public-attribution-v2.yaml"
    )
    packet = deepcopy(packet)
    commit = reviews._git(reviews.ROOT, "rev-parse", "HEAD")
    evidence_digest = reviews.evidence_manifest_sha256(packet, root=reviews.ROOT)
    packet["reviewers"] = [
        {
            "id": "reviewer-one",
            "human_reviewer": True,
            "affiliation_or_role": "independent security reviewer",
            "independent_from_artifact_author": True,
            "decision": "approve",
            "reviewed_at": "2026-08-07T00:00:00Z",
            "reviewed_commit": commit,
            "evidence_manifest_sha256": evidence_digest,
            "notes": "partial review",
        }
    ]
    errors = reviews.validate_packet(
        packet,
        root=reviews.ROOT,
        path=reviews.ROOT / "docs/reviews/paper/mlkem-public-attribution-v2.yaml",
        minimum_reviewers=2,
        required_before_measurement=True,
    )
    assert any("partial sign-offs" in error for error in errors)


def test_review_evidence_paths_reject_symlinks(tmp_path):
    evidence = tmp_path / "evidence.txt"
    evidence.write_text("review me", encoding="utf-8")
    link = tmp_path / "evidence-link.txt"
    link.symlink_to(evidence)

    with pytest.raises(ValueError, match="symlink"):
        reviews._repo_path(tmp_path, link.name, "review evidence")


def test_postmeasurement_review_approves_one_exact_final_evidence_root():
    path = reviews.ROOT / "docs/reviews/paper/native-promotion-v2.yaml"
    packet = deepcopy(reviews._load_yaml(path))
    packet["status"] = "reviewed"
    commit = reviews._git(reviews.ROOT, "rev-parse", "HEAD")

    def approvals(evidence_digest):
        return [
            {
                "id": f"reviewer-{index}",
                "human_reviewer": True,
                "affiliation_or_role": "independent measurement reviewer",
                "independent_from_artifact_author": True,
                "decision": "approve",
                "reviewed_at": f"2026-08-07T0{index}:00:00Z",
                "reviewed_commit": commit,
                "evidence_manifest_sha256": evidence_digest,
                "notes": "candidate root and bound artifacts checked",
            }
            for index in (1, 2)
        ]

    missing_root_digest = reviews.evidence_manifest_sha256(packet, root=reviews.ROOT)
    packet["reviewers"] = approvals(missing_root_digest)
    errors = reviews.validate_packet(
        packet,
        root=reviews.ROOT,
        path=path,
        minimum_reviewers=2,
        required_before_measurement=False,
    )
    assert any("must bind final evidence" in error for error in errors)

    packet["final_evidence_root_sha256"] = "a" * 64
    approved_contract = reviews.evidence_manifest_sha256(packet, root=reviews.ROOT)
    packet["reviewers"] = approvals(approved_contract)
    assert (
        reviews.validate_packet(
            packet,
            root=reviews.ROOT,
            path=path,
            minimum_reviewers=2,
            required_before_measurement=False,
        )
        == []
    )

    packet["final_evidence_root_sha256"] = "b" * 64
    errors = reviews.validate_packet(
        packet,
        root=reviews.ROOT,
        path=path,
        minimum_reviewers=2,
        required_before_measurement=False,
    )
    assert sum("evidence manifest hash mismatch" in error for error in errors) == 2


def test_premeasurement_packet_cannot_claim_a_final_evidence_root():
    path = reviews.ROOT / "docs/reviews/paper/mlkem-public-attribution-v2.yaml"
    packet = deepcopy(reviews._load_yaml(path))
    packet["final_evidence_root_sha256"] = "a" * 64

    errors = reviews.validate_packet(
        packet,
        root=reviews.ROOT,
        path=path,
        minimum_reviewers=2,
        required_before_measurement=True,
    )
    assert any("cannot bind final evidence" in error for error in errors)


def test_completion_cli_requires_the_reviewed_candidate_root(monkeypatch):
    report = {
        "static_valid": True,
        "pre_measurement_ready": True,
        "paper_ready": True,
        "approved_final_evidence_root_sha256": "a" * 64,
    }
    monkeypatch.setattr(reviews, "evaluate_manifest", lambda manifest: (dict(report), []))

    assert (
        reviews.main(
            [
                "--require-complete",
                "--expected-final-evidence-root-sha256",
                "a" * 64,
            ]
        )
        == 0
    )
    assert (
        reviews.main(
            [
                "--require-complete",
                "--expected-final-evidence-root-sha256",
                "b" * 64,
            ]
        )
        == 1
    )
