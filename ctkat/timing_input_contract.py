"""Fail-closed KEM timing input-attribution contracts.

The timing producer is not allowed to turn a mixed public/secret corpus into a
secret-key claim by setting one boolean in its own report.  This module builds
and independently reconstructs the exact ``valid_tuple`` contract from every
preserved process trace's runtime metadata and domain seed.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

VALID_TUPLE_AXIS = "valid_tuple"
VALID_TUPLE_RUNTIME_METADATA = {
    "axis": VALID_TUPLE_AXIS,
    "key_policy": "class0-fixed-class1-fresh",
    "class_contract": "fixed-valid-tuple-vs-fresh-valid-tuples",
    "secret_key_varies_between_classes": "true",
    "public_ciphertext_varies_between_classes": "true",
    "embedded_public_key_material_varies_between_classes": "true",
    "secret_attribution_permitted": "false",
    "setup_return_codes": "checked",
    "valid_tuple_round_trip_witness": "all-pool-members",
}
VALID_TUPLE_EVIDENCE_BOUNDARY = (
    "mixed fixed-versus-fresh valid-tuple contrast; secret key, public "
    "ciphertext, and embedded public-key material vary together; no secret attribution"
)

TraceMetadata = tuple[Mapping[str, Any], int]


def _runtime_metadata_errors(
    metadata: Mapping[str, Any],
    seed: int,
    *,
    label: str,
) -> list[str]:
    errors = [
        f"{label}.{key}={metadata.get(key)!r}, expected={expected!r}"
        for key, expected in VALID_TUPLE_RUNTIME_METADATA.items()
        if metadata.get(key) != expected
    ]
    if metadata.get("corpus_seed") != str(seed):
        errors.append(
            f"{label}.corpus_seed={metadata.get('corpus_seed')!r}, expected={str(seed)!r}"
        )
    return errors


def build_valid_tuple_input_contract(traces: Sequence[TraceMetadata]) -> dict[str, Any]:
    """Build the canonical report object from trace metadata and known seeds."""

    metadata_errors = [
        error
        for index, (metadata, seed) in enumerate(traces)
        for error in _runtime_metadata_errors(metadata, seed, label=f"trace[{index}]")
    ]
    return {
        "axis": VALID_TUPLE_AXIS,
        "key_policy": "class0-fixed-class1-fresh",
        "public_class_axis": False,
        "secret_key_varies_between_classes": True,
        "public_ciphertext_varies_between_classes": True,
        "embedded_public_key_material_varies_between_classes": True,
        "secret_attribution_permitted": False,
        "expected_metadata": {
            **VALID_TUPLE_RUNTIME_METADATA,
            "corpus_seed": "per-trace-domain-seed",
        },
        "observed_corpus_seeds": sorted(
            {str(metadata.get("corpus_seed", "")) for metadata, _ in traces}
        ),
        "corpus_seed_matches_trace_seed": not metadata_errors,
        "observed_digests": {},
        "traces_validated": len(traces),
        "passed": bool(traces) and not metadata_errors,
        "evidence_boundary": VALID_TUPLE_EVIDENCE_BOUNDARY,
    }


def _payload_metadata(
    payload: Any,
    *,
    seed_key: str,
    metadata_key: str,
    label: str,
) -> tuple[TraceMetadata | None, list[str]]:
    if not isinstance(payload, Mapping):
        return None, [f"{label} must be an object"]
    seed = payload.get(seed_key)
    metadata = payload.get(metadata_key)
    errors: list[str] = []
    if isinstance(seed, bool) or not isinstance(seed, int) or seed <= 0:
        errors.append(f"{label}.{seed_key} must be a positive integer")
    if not isinstance(metadata, Mapping):
        errors.append(f"{label}.{metadata_key} must be an object")
    if errors:
        return None, errors
    assert isinstance(seed, int) and isinstance(metadata, Mapping)
    return (metadata, seed), []


def extract_valid_tuple_trace_metadata(
    protocol: Mapping[str, Any],
    *,
    label: str,
) -> tuple[list[TraceMetadata], list[str]]:
    """Extract all target/calibration/control metadata from a harness report."""

    traces: list[TraceMetadata] = []
    errors: list[str] = []
    payload_specs = (
        ("target_repeats", "analysis_seed", "runtime_metadata"),
        ("target_repeats", "calibration_seed", "calibration_runtime_metadata"),
        ("aa_controls", "seed", "runtime_metadata"),
        ("setup_placebo_controls", "seed", "runtime_metadata"),
        ("positive_controls", "seed", "runtime_metadata"),
    )
    for field, seed_key, metadata_key in payload_specs:
        payloads = protocol.get(field)
        if not isinstance(payloads, list) or not payloads:
            errors.append(f"{label}.{field} must be a non-empty list")
            continue
        for index, payload in enumerate(payloads):
            item, item_errors = _payload_metadata(
                payload,
                seed_key=seed_key,
                metadata_key=metadata_key,
                label=f"{label}.{field}[{index}]",
            )
            errors.extend(item_errors)
            if item is not None:
                traces.append(item)
    return traces, errors


def _valid_tuple_trace_matrix_errors(
    protocol: Mapping[str, Any],
    *,
    label: str,
) -> list[str]:
    errors: list[str] = []
    repeats = protocol.get("process_repeats_observed")
    if isinstance(repeats, bool) or not isinstance(repeats, int) or repeats < 3:
        return [f"{label}.process_repeats_observed must be an integer >= 3"]

    expected_indices = list(range(repeats))
    for field in ("target_repeats", "aa_controls", "setup_placebo_controls"):
        payloads = protocol.get(field)
        if not isinstance(payloads, list):
            continue
        if len(payloads) != repeats:
            errors.append(f"{label}.{field} must contain exactly {repeats} entries")
            continue
        indices = [
            item.get("process_index") if isinstance(item, Mapping) else None for item in payloads
        ]
        if (
            sorted(
                index for index in indices if isinstance(index, int) and not isinstance(index, bool)
            )
            != expected_indices
        ):
            errors.append(f"{label}.{field} process_index matrix must equal {expected_indices}")

    positives = protocol.get("positive_controls")
    if isinstance(positives, list):
        if len(positives) != repeats * 3:
            errors.append(f"{label}.positive_controls must contain exactly {repeats * 3} entries")
        effects_by_process: dict[int, set[int]] = {}
        for item in positives:
            if not isinstance(item, Mapping):
                continue
            process_index = item.get("process_index")
            effect_ticks = item.get("effect_ticks")
            if (
                isinstance(process_index, int)
                and not isinstance(process_index, bool)
                and isinstance(effect_ticks, int)
                and not isinstance(effect_ticks, bool)
                and effect_ticks > 0
            ):
                effects_by_process.setdefault(process_index, set()).add(effect_ticks)
        effect_sets = [effects_by_process.get(index, set()) for index in expected_indices]
        if (
            any(len(effects) != 3 for effects in effect_sets)
            or len({tuple(sorted(effects)) for effects in effect_sets}) != 1
        ):
            errors.append(
                f"{label}.positive_controls must contain the same three positive effects "
                "for every process_index"
            )

    traces, _ = extract_valid_tuple_trace_metadata(protocol, label=label)
    expected_trace_count = repeats * 7
    if len(traces) != expected_trace_count:
        errors.append(
            f"{label} must authenticate exactly {expected_trace_count} target/calibration/"
            "control traces"
        )
    seeds = [seed for _metadata, seed in traces]
    if len(seeds) != len(set(seeds)):
        errors.append(f"{label} trace domain seeds must be unique")
    return errors


def validate_valid_tuple_protocol(
    protocol: Mapping[str, Any],
    *,
    label: str,
) -> list[str]:
    """Reconstruct and compare the exact mixed-input contract."""

    errors: list[str] = []
    if protocol.get("axis") != VALID_TUPLE_AXIS:
        errors.append(f"{label}.axis={protocol.get('axis')!r}, expected={VALID_TUPLE_AXIS!r}")
    traces, trace_errors = extract_valid_tuple_trace_metadata(protocol, label=label)
    errors.extend(trace_errors)
    errors.extend(_valid_tuple_trace_matrix_errors(protocol, label=label))
    for index, (metadata, seed) in enumerate(traces):
        errors.extend(
            _runtime_metadata_errors(
                metadata,
                seed,
                label=f"{label}.trace[{index}]",
            )
        )
    expected = build_valid_tuple_input_contract(traces)
    actual = protocol.get("input_contract")
    if actual != expected:
        errors.append(f"{label}.input_contract does not equal the reconstructed contract")
    return errors


def validate_valid_tuple_harness_report(
    report: Mapping[str, Any],
    *,
    label: str,
) -> list[str]:
    """Validate the protocol plus selected-analysis metadata in a backend row."""

    protocol = report.get("harness_protocol")
    if not isinstance(protocol, Mapping):
        return [f"{label}.harness_protocol must be an object"]
    errors = validate_valid_tuple_protocol(protocol, label=f"{label}.harness_protocol")
    selected, selected_errors = _payload_metadata(
        report,
        seed_key="analysis_seed",
        metadata_key="analysis_runtime_metadata",
        label=label,
    )
    errors.extend(selected_errors)
    if selected is not None:
        metadata, seed = selected
        errors.extend(
            _runtime_metadata_errors(
                metadata,
                seed,
                label=f"{label}.analysis_runtime_metadata",
            )
        )
        target_repeats = protocol.get("target_repeats")
        matching = (
            [
                item
                for item in target_repeats
                if isinstance(item, Mapping) and item.get("analysis_seed") == seed
            ]
            if isinstance(target_repeats, list)
            else []
        )
        if len(matching) != 1 or matching[0].get("runtime_metadata") != metadata:
            errors.append(f"{label}.analysis_runtime_metadata is not the selected target repeat")
    return errors
