"""Evidence schema v2 combination rules.

These are security semantics, not presentation tests: every formerly
contradictory route to a clean headline is locked here.
"""

import pytest

from ctkat.evidence import (
    AsmAttribution,
    AsmEvidence,
    Correctness,
    EvidenceV2,
    Overall,
    ReviewStatus,
    Structural,
    TimingSignal,
    TimingValidity,
    asm_from_cells,
    build_evidence,
)


def _evidence(**updates):
    values = {
        "correctness": Correctness.PASS,
        "structural": Structural.NO_FINDING,
        "asm": AsmEvidence.NO_CANDIDATE,
        "asm_attribution": AsmAttribution.NOT_APPLICABLE,
        "timing_validity": TimingValidity.NOT_RUN,
        "timing_signal": TimingSignal.NOT_RUN,
        "review": ReviewStatus.NOT_NEEDED,
        "review_id": "",
        "legacy_verdict_class": "robust",
    }
    values.update(updates)
    return EvidenceV2(**values)


def test_clean_executed_layers_fold_to_no_finding_observed():
    assert _evidence().overall == Overall.NO_FINDING


def test_legacy_timing_pass_without_power_is_inconclusive():
    evidence = build_evidence(
        correctness="pass",
        ct_statuses={"PASS"},
        asm_candidate_count=0,
        asm_error_count=0,
        asm_cell_count=1,
        triage="untriaged",
        raw_timing_status="PASS",
        timing_validity="",
        legacy_verdict_class="robust",
        legacy_basis="auto",
        review_status="",
        review_id="",
    )
    assert evidence.timing_validity == TimingValidity.INSUFFICIENT_POWER
    assert evidence.timing_signal == TimingSignal.NO_SIGNAL
    assert evidence.overall == Overall.INCONCLUSIVE


def test_official_minimum_withholds_timing_conclusion():
    from ctkat.evidence import timing_from_raw

    validity, signal = timing_from_raw("INSUFFICIENT", "insufficient-power")
    assert validity == TimingValidity.INSUFFICIENT_POWER
    assert signal == TimingSignal.NOT_INTERPRETABLE


def test_official_minimum_can_also_preserve_environment_rejection():
    from ctkat.evidence import timing_from_raw

    validity, signal = timing_from_raw("INSUFFICIENT", "environment-rejected")
    assert validity == TimingValidity.ENVIRONMENT_REJECTED
    assert signal == TimingSignal.NOT_INTERPRETABLE


def test_corrupt_trace_overrides_official_minimum_as_tool_error():
    from ctkat.evidence import timing_from_raw

    validity, signal = timing_from_raw("INSUFFICIENT", "error")
    assert validity == TimingValidity.ERROR
    assert signal == TimingSignal.NOT_INTERPRETABLE


def test_confounded_raw_fail_cannot_be_clean_or_risk():
    evidence = _evidence(
        timing_validity=TimingValidity.CONFOUNDED,
        timing_signal=TimingSignal.SIGNAL,
    )
    assert evidence.overall == Overall.INCONCLUSIVE


def test_only_valid_timing_signal_is_decisive_risk():
    evidence = _evidence(
        timing_validity=TimingValidity.VALID,
        timing_signal=TimingSignal.SIGNAL,
    )
    assert evidence.overall == Overall.RISK


def test_public_candidate_without_review_artifact_needs_review():
    evidence = _evidence(
        asm=AsmEvidence.CANDIDATE,
        asm_attribution=AsmAttribution.PUBLIC,
        review=ReviewStatus.PENDING,
    )
    assert evidence.overall == Overall.NEEDS_REVIEW


def test_public_candidate_with_review_artifact_can_clear():
    evidence = _evidence(
        asm=AsmEvidence.CANDIDATE,
        asm_attribution=AsmAttribution.PUBLIC,
        review=ReviewStatus.REVIEWED,
        review_id="rvw-test-public-v1",
    )
    assert evidence.overall == Overall.NO_FINDING


def test_unresolved_candidate_cannot_clear_even_if_review_record_is_final():
    evidence = _evidence(
        asm=AsmEvidence.CANDIDATE,
        asm_attribution=AsmAttribution.UNRESOLVED,
        review=ReviewStatus.REVIEWED,
        review_id="rvw-test-unresolved-v1",
    )
    assert evidence.overall == Overall.NEEDS_REVIEW


def test_reviewed_state_without_artifact_id_is_invalid():
    with pytest.raises(ValueError, match="requires review_id"):
        _evidence(review=ReviewStatus.REVIEWED)


def test_reviewed_secret_risk_is_risk_detected():
    evidence = _evidence(
        asm=AsmEvidence.CANDIDATE,
        asm_attribution=AsmAttribution.SECRET_RISK,
        review=ReviewStatus.REVIEWED,
        review_id="rvw-test-secret-v1",
        legacy_verdict_class="varlat-secret-risk",
    )
    assert evidence.overall == Overall.RISK


def test_reviewed_structural_acceptance_is_not_raw_risk():
    evidence = _evidence(
        structural=Structural.FINDING,
        review=ReviewStatus.REVIEWED,
        review_id="rvw-test-accept-v1",
        legacy_verdict_class="accepted-variable-time",
    )
    assert evidence.overall == Overall.NO_FINDING


def test_unreviewed_structural_acceptance_stays_needs_review():
    evidence = _evidence(
        structural=Structural.FINDING,
        review=ReviewStatus.PENDING,
        legacy_verdict_class="accepted-variable-time",
    )
    assert evidence.overall == Overall.NEEDS_REVIEW


def test_review_artifact_cannot_rename_raw_structural_finding_to_robust():
    evidence = _evidence(
        structural=Structural.FINDING,
        review=ReviewStatus.REVIEWED,
        review_id="rvw-test-bad-override-v1",
        legacy_verdict_class="robust",
    )
    assert evidence.overall == Overall.NEEDS_REVIEW


def test_manual_legacy_judgment_cannot_claim_review_not_needed():
    with pytest.raises(ValueError, match="contradicts manual"):
        build_evidence(
            correctness="pass",
            ct_statuses={"PASS"},
            asm_candidate_count=0,
            asm_error_count=0,
            asm_cell_count=1,
            triage="untriaged",
            raw_timing_status="",
            timing_validity="",
            legacy_verdict_class="ct-leak",
            legacy_basis="review",
            review_status="not-needed",
            review_id="",
        )


def test_direct_unreviewed_manual_legacy_risk_cannot_fold_clean():
    evidence = _evidence(
        review=ReviewStatus.NOT_NEEDED,
        legacy_verdict_class="ct-leak",
    )
    assert evidence.overall == Overall.NEEDS_REVIEW


def test_tool_error_and_correctness_failure_are_not_clean():
    assert _evidence(structural=Structural.ERROR).overall == Overall.TOOL_ERROR
    assert _evidence(correctness=Correctness.FAIL).overall == Overall.INCONCLUSIVE


def test_explicit_contradictory_overall_is_rejected():
    with pytest.raises(ValueError, match="contradicts evidence fold"):
        _evidence(overall=Overall.NO_FINDING, structural=Structural.ERROR)


def test_not_run_layer_contracts_are_validated():
    with pytest.raises(ValueError, match="timing not-run"):
        _evidence(timing_signal=TimingSignal.SIGNAL)
    with pytest.raises(ValueError, match="asm=no-candidate"):
        _evidence(asm_attribution=AsmAttribution.PUBLIC)


def test_asm_coverage_distinguishes_partial_and_not_run():
    assert (
        asm_from_cells(
            candidate_count=0,
            error_count=0,
            not_run_count=1,
            cell_count=2,
        )
        == AsmEvidence.INCOMPLETE
    )
    assert (
        asm_from_cells(
            candidate_count=0,
            error_count=0,
            not_run_count=2,
            cell_count=2,
        )
        == AsmEvidence.NOT_RUN
    )
