#!/usr/bin/env python3
"""Fail-closed validation for committed evidence-schema-v2 corpus artifacts."""

from __future__ import annotations

import csv
import importlib.util
import json
import re
import sys
from collections import Counter
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "docs" / "corpus"
BUILDER_PATH = ROOT / "scripts" / "build_corpus_table.py"
SPEC = importlib.util.spec_from_file_location("ctkat_build_corpus_table", BUILDER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot import {BUILDER_PATH}")
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)
sys.path.insert(0, str(ROOT))

from ctkat.evidence import (  # noqa: E402
    SCHEMA_VERSION,
    AsmAttribution,
    AsmEvidence,
    Correctness,
    EvidenceV2,
    Overall,
    ReviewStatus,
    Structural,
    TimingSignal,
    TimingValidity,
    asm_attribution_from_triage,
    asm_from_cells,
    structural_from_statuses,
)
from ctkat.verdict_class import VERDICT_CLASSES  # noqa: E402

REVIEWS = ROOT / "docs" / "reviews"
JSON_SCHEMA = ROOT / "ctkat" / "schemas" / "evidence-v2.schema.json"


def read_csv(path: Path, expected_fields: list[str]) -> tuple[list[dict[str, str]], list[str]]:
    errors: list[str] = []
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames != expected_fields:
                errors.append(
                    f"{path.relative_to(ROOT)} header drift: "
                    f"expected={expected_fields}, actual={reader.fieldnames}"
                )
            rows = list(reader)
    except OSError as exc:
        return [], [f"{path.relative_to(ROOT)} unreadable: {exc}"]
    if not rows:
        errors.append(f"{path.relative_to(ROOT)} has no data rows")
    return rows, errors


def load_review_artifacts() -> tuple[dict[str, dict], list[str]]:
    artifacts: dict[str, dict] = {}
    errors: list[str] = []
    for path in sorted(REVIEWS.glob("*.yaml")):
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            errors.append(f"{path.relative_to(ROOT)} unreadable: {exc}")
            continue
        if not isinstance(raw, dict):
            errors.append(f"{path.relative_to(ROOT)} root must be a mapping")
            continue
        review_id = str(raw.get("review_id", ""))
        if review_id != path.stem:
            errors.append(f"{path.relative_to(ROOT)} review_id={review_id!r} must match filename")
            continue
        if review_id in artifacts:
            errors.append(f"duplicate review_id={review_id!r}")
            continue
        if raw.get("schema_version") != "1.0":
            errors.append(f"{path.relative_to(ROOT)} schema_version must be '1.0'")
        if raw.get("status") not in {"pending", "reviewed", "disputed", "expired"}:
            errors.append(f"{path.relative_to(ROOT)} invalid status={raw.get('status')!r}")
        if not raw.get("reviewers"):
            errors.append(f"{path.relative_to(ROOT)} requires at least one reviewer")
        if not raw.get("decision") or not raw.get("evidence") or not raw.get("limitations"):
            errors.append(f"{path.relative_to(ROOT)} requires decision/evidence/limitations lists")
        scopes = raw.get("scope")
        if not isinstance(scopes, list) or not scopes:
            errors.append(f"{path.relative_to(ROOT)} requires non-empty scope")
        for evidence_path in raw.get("evidence") or []:
            candidate = (ROOT / str(evidence_path)).resolve()
            try:
                candidate.relative_to(ROOT)
            except ValueError:
                errors.append(
                    f"{path.relative_to(ROOT)} evidence escapes repository: {evidence_path!r}"
                )
                continue
            if not candidate.exists():
                errors.append(f"{path.relative_to(ROOT)} evidence path missing: {evidence_path!r}")
        artifacts[review_id] = raw
    return artifacts, errors


def check_json_schema_contract() -> list[str]:
    errors: list[str] = []
    try:
        schema = json.loads(JSON_SCHEMA.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{JSON_SCHEMA.relative_to(ROOT)} unreadable: {exc}"]
    properties = schema.get("properties", {})
    expected = {
        "correctness": [member.value for member in Correctness],
        "structural": [member.value for member in Structural],
        "asm": [member.value for member in AsmEvidence],
        "asm_attribution": [member.value for member in AsmAttribution],
        "timing_validity": [member.value for member in TimingValidity],
        "timing_signal": [member.value for member in TimingSignal],
        "review": [member.value for member in ReviewStatus],
        "overall": [member.value for member in Overall],
    }
    if properties.get("schema_version", {}).get("const") != SCHEMA_VERSION:
        errors.append(f"{JSON_SCHEMA.relative_to(ROOT)} schema_version const drift")
    for field, values in expected.items():
        if properties.get(field, {}).get("enum") != values:
            errors.append(
                f"{JSON_SCHEMA.relative_to(ROOT)} {field} enum drift: "
                f"expected={values}, actual={properties.get(field, {}).get('enum')}"
            )
    return errors


def main() -> int:
    cells, errors = read_csv(CORPUS / "corpus_cells.csv", BUILDER.CELLS_FIELDS)
    summary, summary_errors = read_csv(CORPUS / "corpus_summary.csv", BUILDER.SUMMARY_FIELDS)
    errors.extend(summary_errors)

    cell_keys: set[tuple[str, str, str]] = set()
    summary_pairs: set[tuple[str, str]] = set()
    cell_pairs: set[tuple[str, str]] = set()
    cells_by_pair: dict[tuple[str, str], list[dict[str, str]]] = {}
    allowed_ct = {"PASS", "FAIL", "ERROR", "NA"}
    allowed_asm_status = {"PASS", "ERROR", "NOT_RUN"}
    for number, row in enumerate(cells, start=2):
        key = (row["target"], row["harness"], row["combo"])
        if key in cell_keys:
            errors.append(f"corpus_cells.csv:{number}: duplicate key {key}")
        cell_keys.add(key)
        pair = (row["target"], row["harness"])
        cell_pairs.add(pair)
        cells_by_pair.setdefault(pair, []).append(row)
        if row["schema_version"] != SCHEMA_VERSION:
            errors.append(f"corpus_cells.csv:{number}: schema_version={row['schema_version']!r}")
        if row["ct_status"] not in allowed_ct:
            errors.append(f"corpus_cells.csv:{number}: invalid ct_status={row['ct_status']!r}")
        asm_status = row["asm_status"]
        if asm_status not in allowed_asm_status:
            errors.append(f"corpus_cells.csv:{number}: invalid asm_status={asm_status!r}")
        if asm_status == "ERROR" and not row["asm_error"]:
            errors.append(f"corpus_cells.csv:{number}: asm ERROR requires asm_error")
        if asm_status != "ERROR" and row["asm_error"]:
            errors.append(f"corpus_cells.csv:{number}: asm_error requires asm_status=ERROR")
        try:
            asm_count = int(row["asm_div_count"])
            if asm_count < 0:
                raise ValueError
        except ValueError:
            errors.append(
                f"corpus_cells.csv:{number}: invalid asm_div_count={row['asm_div_count']!r}"
            )
            asm_count = 0
        if asm_status == "NOT_RUN" and asm_count:
            errors.append(f"corpus_cells.csv:{number}: asm NOT_RUN cannot contain candidates")
        if not row["cc_version"] or not row["arch"] or not row["ctkat_commit"]:
            errors.append(f"corpus_cells.csv:{number}: cc_version/arch/ctkat_commit required")
        if row["ctkat_commit"] and not re.fullmatch(r"[0-9a-f]{7,40}", row["ctkat_commit"]):
            errors.append(
                f"corpus_cells.csv:{number}: malformed ctkat_commit {row['ctkat_commit']!r}"
            )

    allowed_timing = {
        "",
        "PASS",
        "WARNING",
        "FAIL",
        "INSUFFICIENT",
        "ERROR",
        "NONE",
    }
    artifacts, artifact_errors = load_review_artifacts()
    errors.extend(artifact_errors)
    errors.extend(check_json_schema_contract())
    used_review_ids: set[str] = set()
    for number, row in enumerate(summary, start=2):
        pair = (row["target"], row["harness"])
        if pair in summary_pairs:
            errors.append(f"corpus_summary.csv:{number}: duplicate key {pair}")
        summary_pairs.add(pair)
        if pair not in cell_pairs:
            # A timing-only axis (currently ML-KEM's `kem_dec_ct`) has no
            # structural build cell by design. It is valid only when timing
            # evidence is actually present; an entirely unbacked row is not.
            if not row["timing_raw_status"]:
                errors.append(
                    f"corpus_summary.csv:{number}: no build cell or timing evidence for {pair}"
                )
            if (
                row["structural"] != Structural.NOT_RUN.value
                or row["asm"] != AsmEvidence.NOT_RUN.value
                or row["asm_attribution"] != AsmAttribution.NOT_APPLICABLE.value
            ):
                errors.append(
                    f"corpus_summary.csv:{number}: summary-only timing axis must set "
                    "structural/asm to not-run"
                )
        else:
            pair_cells = cells_by_pair[pair]
            try:
                expected_structural = structural_from_statuses(
                    {cell["ct_status"] for cell in pair_cells}
                )
                expected_asm = asm_from_cells(
                    candidate_count=sum(int(cell["asm_div_count"]) for cell in pair_cells),
                    error_count=sum(cell["asm_status"] == "ERROR" for cell in pair_cells),
                    not_run_count=sum(cell["asm_status"] == "NOT_RUN" for cell in pair_cells),
                    cell_count=len(pair_cells),
                )
                expected_attribution = asm_attribution_from_triage(
                    expected_asm, row["varlat_triage"]
                )
                actual_layers = (
                    row["structural"],
                    row["asm"],
                    row["asm_attribution"],
                )
                expected_layers = (
                    expected_structural.value,
                    expected_asm.value,
                    expected_attribution.value,
                )
                if actual_layers != expected_layers:
                    errors.append(
                        f"corpus_summary.csv:{number}: normalized layer drift from cells: "
                        f"expected={expected_layers}, actual={actual_layers}"
                    )
                ct_statuses = {cell["ct_status"] for cell in pair_cells}
                ct_verdicts = ct_statuses.intersection({"PASS", "FAIL"})
                expected_raw = {
                    "ct_flips": "yes" if len(ct_verdicts) > 1 else "no",
                    "ct_status_set": "{" + ",".join(sorted(ct_statuses)) + "}",
                    "ct_finding_funcs": ";".join(
                        sorted(
                            {
                                function
                                for cell in pair_cells
                                for function in cell["ct_finding_funcs"].split(";")
                                if function
                            }
                        )
                    ),
                    "varlat_candidates": (
                        ";".join(
                            sorted(
                                {
                                    f"{cell['cc']}:{cell['opt']}"
                                    for cell in pair_cells
                                    if int(cell["asm_div_count"]) > 0
                                }
                            )
                        )
                        or "none"
                    ),
                }
                actual_raw = {field: row[field] for field in expected_raw}
                if actual_raw != expected_raw:
                    errors.append(
                        f"corpus_summary.csv:{number}: raw summary drift from cells: "
                        f"expected={expected_raw}, actual={actual_raw}"
                    )
            except (KeyError, ValueError) as exc:
                errors.append(
                    f"corpus_summary.csv:{number}: cannot derive layers from cells: {exc}"
                )
        if row["legacy_verdict_class"] not in VERDICT_CLASSES:
            errors.append(
                "corpus_summary.csv:"
                f"{number}: invalid legacy_verdict_class {row['legacy_verdict_class']!r}"
            )
        if row["legacy_basis"] not in {"auto", "review", "stop"}:
            errors.append(
                f"corpus_summary.csv:{number}: invalid legacy_basis={row['legacy_basis']!r}"
            )
        if row["timing_raw_status"] not in allowed_timing:
            errors.append(
                "corpus_summary.csv:"
                f"{number}: invalid raw timing status {row['timing_raw_status']!r}"
            )
        if row["timing_raw_status"] and not row["timing_backend"]:
            errors.append(f"corpus_summary.csv:{number}: timing_backend required for raw timing")
        try:
            EvidenceV2.from_mapping(row)
        except (KeyError, ValueError) as exc:
            errors.append(f"corpus_summary.csv:{number}: invalid evidence v2: {exc}")

        review_id = row["review_id"]
        if review_id:
            used_review_ids.add(review_id)
            artifact = artifacts.get(review_id)
            if artifact is None:
                errors.append(f"corpus_summary.csv:{number}: review_id={review_id!r} not found")
            else:
                if artifact.get("status") != row["review"]:
                    errors.append(
                        f"corpus_summary.csv:{number}: review={row['review']!r} "
                        f"does not match {review_id} status={artifact.get('status')!r}"
                    )
                scopes = {
                    (str(item.get("target", "")), str(item.get("harness", "")))
                    for item in artifact.get("scope", [])
                    if isinstance(item, dict)
                }
                if pair not in scopes:
                    errors.append(f"corpus_summary.csv:{number}: {review_id} does not cover {pair}")

    unused_artifacts = sorted(set(artifacts) - used_review_ids)
    if unused_artifacts:
        errors.append(f"unreferenced review artifact(s): {unused_artifacts}")

    if errors:
        for error in errors:
            print(f"[corpus] ERROR: {error}", file=sys.stderr)
        return 1
    counts = Counter(row["overall"] for row in summary)
    rendered_counts = ", ".join(f"{state}={counts[state]}" for state in Overall if counts[state])
    print(
        f"[corpus] OK v{SCHEMA_VERSION}: {len(cells)} cells, "
        f"{len(summary)} summary rows ({rendered_counts})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
