from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from ctkat.timing_input_contract import (
    VALID_TUPLE_AXIS,
    VALID_TUPLE_RUNTIME_METADATA,
    build_valid_tuple_input_contract,
    extract_valid_tuple_trace_metadata,
    validate_valid_tuple_harness_report,
    validate_valid_tuple_protocol,
)

TARGET_SEEDS = (101, 102, 103)
CALIBRATION_SEEDS = (201, 202, 203)
AA_SEEDS = (301, 302, 303)
PLACEBO_SEEDS = (401, 402, 403)
POSITIVE_SEEDS = tuple(range(501, 510))


def _runtime_metadata(seed: int) -> dict[str, str]:
    return {
        **VALID_TUPLE_RUNTIME_METADATA,
        "corpus_seed": str(seed),
    }


def _canonical_protocol() -> dict[str, Any]:
    protocol: dict[str, Any] = {
        "axis": VALID_TUPLE_AXIS,
        "process_repeats_observed": 3,
        "target_repeats": [
            {
                "process_index": process_index,
                "analysis_seed": analysis_seed,
                "calibration_seed": calibration_seed,
                "runtime_metadata": _runtime_metadata(analysis_seed),
                "calibration_runtime_metadata": _runtime_metadata(calibration_seed),
            }
            for process_index, (analysis_seed, calibration_seed) in enumerate(
                zip(TARGET_SEEDS, CALIBRATION_SEEDS, strict=True)
            )
        ],
        "aa_controls": [
            {
                "process_index": process_index,
                "seed": seed,
                "runtime_metadata": _runtime_metadata(seed),
            }
            for process_index, seed in enumerate(AA_SEEDS)
        ],
        "setup_placebo_controls": [
            {
                "process_index": process_index,
                "seed": seed,
                "runtime_metadata": _runtime_metadata(seed),
            }
            for process_index, seed in enumerate(PLACEBO_SEEDS)
        ],
        "positive_controls": [
            {
                "process_index": process_index,
                "effect_ticks": effect_ticks,
                "seed": seed,
                "runtime_metadata": _runtime_metadata(seed),
            }
            for seed, (process_index, effect_ticks) in zip(
                POSITIVE_SEEDS,
                (
                    (process_index, effect_ticks)
                    for process_index in range(3)
                    for effect_ticks in (64, 128, 256)
                ),
                strict=True,
            )
        ],
    }
    traces, errors = extract_valid_tuple_trace_metadata(protocol, label="protocol")
    assert errors == []
    assert len(traces) == 21
    protocol["input_contract"] = build_valid_tuple_input_contract(traces)
    return protocol


def _canonical_report(*, selected_process_index: int = 1) -> dict[str, Any]:
    protocol = _canonical_protocol()
    selected = protocol["target_repeats"][selected_process_index]
    return {
        "analysis_seed": selected["analysis_seed"],
        "calibration_seed": selected["calibration_seed"],
        "analysis_runtime_metadata": deepcopy(selected["runtime_metadata"]),
        "harness_protocol": protocol,
    }


def _rebuild_claimed_contract(protocol: dict[str, Any]) -> None:
    traces, _ = extract_valid_tuple_trace_metadata(protocol, label="protocol")
    protocol["input_contract"] = build_valid_tuple_input_contract(traces)


def test_canonical_valid_tuple_contract_covers_all_21_protocol_traces():
    protocol = _canonical_protocol()

    traces, extraction_errors = extract_valid_tuple_trace_metadata(
        protocol,
        label="report.harness_protocol",
    )

    assert extraction_errors == []
    assert len(traces) == 21
    assert [seed for _, seed in traces] == [
        *TARGET_SEEDS,
        *CALIBRATION_SEEDS,
        *AA_SEEDS,
        *PLACEBO_SEEDS,
        *POSITIVE_SEEDS,
    ]
    assert protocol["input_contract"] == build_valid_tuple_input_contract(traces)
    assert protocol["input_contract"]["traces_validated"] == 21
    assert protocol["input_contract"]["passed"] is True
    assert validate_valid_tuple_protocol(protocol, label="report.harness_protocol") == []
    assert validate_valid_tuple_harness_report(_canonical_report(), label="report") == []


@pytest.mark.parametrize(
    "field",
    (
        "target_repeats",
        "aa_controls",
        "setup_placebo_controls",
        "positive_controls",
    ),
)
def test_self_consistent_incomplete_protocol_cannot_forge_passed_true(field: str):
    protocol = _canonical_protocol()
    protocol[field].pop()
    _rebuild_claimed_contract(protocol)

    assert protocol["input_contract"]["passed"] is True
    assert protocol["input_contract"]["traces_validated"] < 21
    assert validate_valid_tuple_protocol(protocol, label="protocol")


def test_missing_target_calibration_metadata_is_rejected_even_with_passed_true():
    protocol = _canonical_protocol()
    del protocol["target_repeats"][0]["calibration_runtime_metadata"]
    protocol["input_contract"]["passed"] = True

    errors = validate_valid_tuple_protocol(protocol, label="protocol")

    assert errors
    assert any("calibration_runtime_metadata" in error for error in errors)


def test_runtime_secret_attribution_claim_is_rejected():
    protocol = _canonical_protocol()
    protocol["target_repeats"][0]["runtime_metadata"]["secret_attribution_permitted"] = "true"

    errors = validate_valid_tuple_protocol(protocol, label="protocol")

    assert errors
    assert any("secret_attribution_permitted" in error for error in errors)


def test_aggregate_secret_attribution_claim_must_equal_reconstructed_contract():
    protocol = _canonical_protocol()
    protocol["input_contract"]["secret_attribution_permitted"] = True

    errors = validate_valid_tuple_protocol(protocol, label="protocol")

    assert errors
    assert any("input_contract" in error for error in errors)


def test_runtime_corpus_seed_must_match_its_trace_domain_seed():
    protocol = _canonical_protocol()
    protocol["positive_controls"][-1]["runtime_metadata"]["corpus_seed"] = "999"

    errors = validate_valid_tuple_protocol(protocol, label="protocol")

    assert errors
    assert any("corpus_seed" in error for error in errors)


def test_selected_analysis_metadata_must_exactly_match_selected_target_repeat():
    report = _canonical_report()
    report["analysis_runtime_metadata"]["untrusted_selected_only_field"] = "forged"

    errors = validate_valid_tuple_harness_report(report, label="report")

    assert errors
    assert any("not the selected target repeat" in error for error in errors)


@pytest.mark.parametrize(
    "field",
    ("target_repeats", "aa_controls", "setup_placebo_controls"),
)
def test_each_three_repeat_role_requires_process_indexes_zero_one_two(field: str):
    protocol = _canonical_protocol()
    protocol[field][-1]["process_index"] = 1
    _rebuild_claimed_contract(protocol)

    assert protocol["input_contract"]["passed"] is True
    assert validate_valid_tuple_protocol(protocol, label="protocol")


def test_positive_controls_require_a_complete_three_by_three_effect_matrix():
    protocol = _canonical_protocol()
    protocol["positive_controls"][-1]["effect_ticks"] = 128
    _rebuild_claimed_contract(protocol)

    assert protocol["input_contract"]["passed"] is True
    assert validate_valid_tuple_protocol(protocol, label="protocol")


def test_all_21_trace_domain_seeds_must_be_unique():
    protocol = _canonical_protocol()
    duplicate_seed = protocol["target_repeats"][0]["analysis_seed"]
    protocol["aa_controls"][0]["seed"] = duplicate_seed
    protocol["aa_controls"][0]["runtime_metadata"] = _runtime_metadata(duplicate_seed)
    _rebuild_claimed_contract(protocol)

    assert protocol["input_contract"]["passed"] is True
    assert len(protocol["input_contract"]["observed_corpus_seeds"]) == 20
    assert validate_valid_tuple_protocol(protocol, label="protocol")
