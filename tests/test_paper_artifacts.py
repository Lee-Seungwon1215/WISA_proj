from scripts.build_paper_artifacts import build


def test_paper_artifacts_are_built_from_canonical_sources():
    outputs, report = build()
    assert len(outputs) == 6
    assert report["corpus_pairs"] == 25
    assert report["corpus_state_counts"]["risk-detected"] == 6
    assert report["schema_version"] == 2
    assert report["measurement_campaign"]["target_executions"] == 26
    assert report["measurement_campaign"]["timing_axes"] == 28
    assert report["measurement_campaign"]["protocol_rows_all_hosts"] == 16_440_000


def test_paper_artifacts_do_not_claim_pending_reviews_are_complete():
    _, report = build()
    readiness = report["review_readiness"]
    assert readiness["pre_measurement_ready"] is False
    assert readiness["paper_ready"] is False
    assert readiness["status_counts"] == {"pending": 7}
