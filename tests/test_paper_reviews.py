from __future__ import annotations

from copy import deepcopy

from scripts import check_paper_reviews as reviews


def test_committed_review_packets_are_static_valid_and_honestly_pending():
    report, errors = reviews.evaluate_manifest()

    assert errors == []
    assert report["static_valid"] is True
    assert report["pre_measurement_ready"] is False
    assert report["paper_ready"] is False
    assert report["status_counts"] == {"pending": 7}


def test_reviewed_packet_requires_two_unique_independent_approvals():
    packet = reviews._load_yaml(
        reviews.ROOT / "docs/reviews/paper/mlkem-public-attribution-v2.yaml"
    )
    packet = deepcopy(packet)
    packet["status"] = "reviewed"
    packet["reviewers"] = [
        {
            "id": "reviewer-one",
            "independent_from_artifact_author": True,
            "decision": "approve",
            "reviewed_at": "2026-08-07",
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
            "independent_from_artifact_author": True,
            "decision": "approve",
            "reviewed_at": "2026-08-07",
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


def test_pending_packet_cannot_hide_partial_signoff():
    packet = reviews._load_yaml(
        reviews.ROOT / "docs/reviews/paper/mlkem-public-attribution-v2.yaml"
    )
    packet = deepcopy(packet)
    packet["reviewers"] = [
        {
            "id": "reviewer-one",
            "independent_from_artifact_author": True,
            "decision": "approve",
            "reviewed_at": "2026-08-07",
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
