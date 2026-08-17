from scripts.build_paper_artifacts import build


def test_paper_artifacts_are_built_from_canonical_sources():
    outputs, report = build()
    assert len(outputs) == 6
    assert report["corpus_pairs"] == 25
    assert report["corpus_state_counts"]["risk-detected"] == 6
    assert report["schema_version"] == 2
    assert report["measurement_campaign"]["target_executions"] == 26
    assert report["measurement_campaign"]["timing_axes"] == 28
    assert report["measurement_campaign"]["protocol_rows_all_hosts"] == 8_220_000


def test_paper_artifacts_do_not_claim_pending_reviews_are_complete():
    _, report = build()
    readiness = report["review_readiness"]
    assert readiness["required_by_current_campaign"] is False
    assert readiness["pre_measurement_ready"] is False
    assert readiness["paper_ready"] is False
    assert readiness["status_counts"] == {"pending": 8}


def test_completed_native_claims_are_host_scoped_and_have_no_measurement_gates():
    _, report = build()
    claims = {item["claim_id"]: item for item in report["claims"]}
    for claim_id in ("kyberslash-attribution", "falcon-comparator", "native-timing-results"):
        assert claims[claim_id]["status"] == "supported-single-host"
        assert claims[claim_id]["open_gates"] == 0
