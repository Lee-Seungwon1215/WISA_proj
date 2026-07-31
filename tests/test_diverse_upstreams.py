from __future__ import annotations

from copy import deepcopy
from typing import Any

from scripts.check_diverse_upstreams import load_manifest, validate_result, validate_static

SHA = "a" * 64
COMMIT = "b" * 40


def _quick_native_result() -> dict[str, Any]:
    manifest = load_manifest()
    cells = []
    equivalence = []
    for lineage, record in manifest["lineages"].items():
        for parameter, parameter_record in record["parameters"].items():
            for profile in ("portable", "architecture-native"):
                native = profile == "architecture-native"
                cells.append(
                    {
                        "id": f"{lineage}-{parameter}-x86_64-{profile}-gcc-O2",
                        "lineage": lineage,
                        "parameter": parameter,
                        "architecture": "x86_64",
                        "profile": profile,
                        "compiler": "gcc",
                        "compiler_version": "gcc synthetic",
                        "optimization": "O2",
                        "status": "passed",
                        "artifact_sha256": SHA,
                        "artifact_machine": "Advanced Micro Devices X86-64",
                        "transcript_sha256": SHA,
                        "native_asm_symbols": ["example_avx2_asm"] if native else [],
                        "instruction_markers": ["vpxor"] if native else [],
                        "kat_sha256": parameter_record["kat_sha256"],
                        "command": ["gcc", "-c"],
                    }
                )
            equivalence.append(
                {
                    "lineage": lineage,
                    "parameter": parameter,
                    "compiler": "gcc",
                    "optimization": "O2",
                    "portable_sha256": SHA,
                    "native_sha256": SHA,
                    "equal": True,
                }
            )
    return {
        "schema_version": 1,
        "kind": "native-upstream-build-matrix",
        "generated_at": "2026-07-31T00:00:00+00:00",
        "git_commit": COMMIT,
        "host": {
            "system": "Linux",
            "machine": "x86_64",
            "release": "synthetic",
            "cpu_features": ["avx2", "bmi2"],
        },
        "architecture": "x86_64",
        "timing_evidence": False,
        "review_status": "needs-review",
        "full_matrix": False,
        "summary": {
            "expected_cells": 12,
            "passed_cells": 12,
            "kat_checks": 12,
            "equivalence_checks": 6,
            "structural_checks": 24,
        },
        "cells": cells,
        "equivalence": equivalence,
    }


def _openssl_result() -> dict[str, Any]:
    manifest = load_manifest()
    record = manifest["integrations"]["openssl-3.5-pqc-api"]
    return {
        "schema_version": 1,
        "kind": "openssl-pqc-api-integration",
        "generated_at": "2026-07-31T00:00:00+00:00",
        "git_commit": COMMIT,
        "host": {
            "system": "Linux",
            "machine": "x86_64",
            "release": "synthetic",
            "cpu_features": [],
        },
        "release": record["release"],
        "revision": record["revision"],
        "source_artifact_sha256": record["artifact_sha256"],
        "openssl_version": "OpenSSL 3.5.7 9 Jun 2026",
        "counts_as_lineage": False,
        "timing_evidence": False,
        "review_status": "needs-review",
        "cells": [
            {
                "compiler": compiler,
                "compiler_version": f"{compiler} synthetic",
                "status": "passed",
                "artifact_sha256": SHA,
                "transcript_sha256": record["expected_transcript_sha256"],
            }
            for compiler in ("gcc", "clang")
        ],
    }


def test_diverse_upstream_static_contract_is_valid() -> None:
    manifest = load_manifest()

    assert validate_static(manifest) == []
    assert manifest["counting"]["newly_imported_lineages"] == [
        "mlkem-native",
        "mldsa-native",
    ]
    assert manifest["counting"]["total_primary_upstream_lineages"] == 4
    assert manifest["integrations"]["openssl-3.5-pqc-api"]["counts_as_lineage"] is False
    assert manifest["lineages"]["mldsa-native"]["release_status"] == "beta"


def test_quick_native_result_contract_is_valid() -> None:
    assert validate_result(_quick_native_result(), load_manifest()) == []


def test_native_result_rejects_timing_promotion_and_kat_drift() -> None:
    manifest = load_manifest()
    result = _quick_native_result()
    result["timing_evidence"] = True
    result["cells"][0]["kat_sha256"] = SHA

    errors = validate_result(result, manifest)

    assert any("cannot be timing evidence" in error for error in errors)
    assert any("upstream KAT digest mismatch" in error for error in errors)


def test_native_result_rejects_missing_matrix_cell() -> None:
    result = _quick_native_result()
    result["cells"].pop()
    result["summary"]["passed_cells"] -= 1

    errors = validate_result(result, load_manifest())

    assert any("matrix tuple mismatch" in error for error in errors)


def test_openssl_integration_result_contract_is_valid() -> None:
    assert validate_result(_openssl_result(), load_manifest()) == []


def test_openssl_wrapper_cannot_be_promoted_to_lineage() -> None:
    result = deepcopy(_openssl_result())
    result["counts_as_lineage"] = True

    errors = validate_result(result, load_manifest())

    assert any("counts_as_lineage" in error for error in errors)
