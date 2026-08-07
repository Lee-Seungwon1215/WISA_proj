from scripts.build_paper_artifacts import build


def test_paper_artifacts_are_built_from_canonical_sources():
    outputs, report = build()
    assert len(outputs) == 6
    assert report["corpus_pairs"] == 25
    assert report["corpus_state_counts"]["risk-detected"] == 6
    assert report["measurement_campaign"]["timing_axes"] == 25


def test_paper_artifacts_do_not_claim_pending_reviews_are_complete():
    _, report = build()
    readiness = report["review_readiness"]
    assert readiness["pre_measurement_ready"] is False
    assert readiness["paper_ready"] is False
    assert readiness["status_counts"] == {"pending": 7}
