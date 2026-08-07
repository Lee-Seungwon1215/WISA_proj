#!/usr/bin/env python3
"""Build the deterministic premeasurement evidence ablation artifact."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "docs/ablation/ablation_v1.yaml"
EXPECTED_STAGES = (
    "single-release-build",
    "full-build-matrix",
    "full-matrix-plus-asm",
    "reviewed-evidence-fold",
)
CSV_FIELDS = (
    "stage",
    "status",
    "cells",
    "pairs",
    "ct_finding_pairs",
    "build_sensitive_pairs",
    "asm_candidate_pairs",
    "candidate_pairs",
    "risk_detected_pairs",
    "needs_review_pairs",
    "inconclusive_pairs",
    "no_finding_pairs",
    "note",
)


def _repo_path(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty repository path")
    path = (ROOT / value).resolve()
    try:
        path.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError(f"{label} escapes repository") from exc
    return path


def load_manifest(path: Path = MANIFEST) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("ablation manifest root must be a mapping")
    return data


def validate_manifest(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if data.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if data.get("status") != "committed-screening-complete-native-timing-pending":
        errors.append("status drift")
    stages = data.get("stages")
    if not isinstance(stages, list) or [s.get("id") for s in stages if isinstance(s, dict)] != list(
        EXPECTED_STAGES
    ):
        errors.append("stage order/scope drift")
    deferred = data.get("deferred_stage")
    if not isinstance(deferred, dict):
        errors.append("deferred_stage must be a mapping")
    else:
        if deferred.get("status") != "pending-physical-native-measurement":
            errors.append("native timing ablation must remain explicitly pending")
        if deferred.get("zero_must_not_mean_missing") is not True:
            errors.append("missing timing evidence must never be encoded as zero")
    try:
        for key in ("cells", "summary"):
            if not _repo_path(
                data.get("data_sources", {}).get(key), f"data_sources.{key}"
            ).is_file():
                errors.append(f"data_sources.{key} is missing")
        for key in ("csv", "json", "markdown"):
            _repo_path(data.get("outputs", {}).get(key), f"outputs.{key}")
    except ValueError as exc:
        errors.append(str(exc))
    return errors


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _cell_stage(stage: str, rows: list[dict[str, str]], *, asm: bool) -> dict[str, Any]:
    by_pair: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_pair[(row["target"], row["harness"])].append(row)
    ct_findings = {
        pair
        for pair, cells in by_pair.items()
        if any(cell["ct_status"] == "FAIL" for cell in cells)
    }
    flips = {
        pair
        for pair, cells in by_pair.items()
        if {cell["ct_status"] for cell in cells} >= {"PASS", "FAIL"}
    }
    asm_candidates = {
        pair
        for pair, cells in by_pair.items()
        if any(int(cell["asm_div_count"] or "0") > 0 for cell in cells)
    }
    candidates = ct_findings | (asm_candidates if asm else set())
    return {
        "stage": stage,
        "status": "complete",
        "cells": len(rows),
        "pairs": len(by_pair),
        "ct_finding_pairs": len(ct_findings),
        "build_sensitive_pairs": len(flips),
        "asm_candidate_pairs": len(asm_candidates) if asm else 0,
        "candidate_pairs": len(candidates),
        "risk_detected_pairs": "",
        "needs_review_pairs": "",
        "inconclusive_pairs": "",
        "no_finding_pairs": "",
        "note": "candidate generation only; not a final evidence verdict",
    }


def build_report(data: dict[str, Any]) -> dict[str, Any]:
    errors = validate_manifest(data)
    if errors:
        raise ValueError("; ".join(errors))
    cells_path = _repo_path(data["data_sources"]["cells"], "data_sources.cells")
    summary_path = _repo_path(data["data_sources"]["summary"], "data_sources.summary")
    cells = _read_csv(cells_path)
    summary = _read_csv(summary_path)
    release = [row for row in cells if row["combo"] == "gcc_release"]
    stages = [
        _cell_stage("single-release-build", release, asm=False),
        _cell_stage("full-build-matrix", cells, asm=False),
        _cell_stage("full-matrix-plus-asm", cells, asm=True),
    ]
    overall = Counter(row["overall"] for row in summary)
    review = Counter(row["review"] for row in summary)
    stages.append(
        {
            "stage": "reviewed-evidence-fold",
            "status": "complete",
            "cells": len(cells),
            "pairs": len(summary),
            "ct_finding_pairs": sum(row["structural"] == "finding" for row in summary),
            "build_sensitive_pairs": sum(row["ct_flips"] == "yes" for row in summary),
            "asm_candidate_pairs": sum(row["asm"] == "candidate" for row in summary),
            "candidate_pairs": "",
            "risk_detected_pairs": overall["risk-detected"],
            "needs_review_pairs": overall["needs-review"],
            "inconclusive_pairs": overall["inconclusive"],
            "no_finding_pairs": overall["no-finding-observed"],
            "note": f"reviewed={review['reviewed']}; pending={review['pending']}; fold is fail-closed",
        }
    )
    deferred = data["deferred_stage"]
    stages.append(
        {
            "stage": deferred["id"],
            "status": deferred["status"],
            "cells": "",
            "pairs": "",
            "ct_finding_pairs": "",
            "build_sensitive_pairs": "",
            "asm_candidate_pairs": "",
            "candidate_pairs": "",
            "risk_detected_pairs": "",
            "needs_review_pairs": "",
            "inconclusive_pairs": "",
            "no_finding_pairs": "",
            "note": deferred["reason"],
        }
    )
    return {
        "schema_version": 1,
        "ablation_id": data["ablation_id"],
        "source_sha256": {"cells": _sha256(cells_path), "summary": _sha256(summary_path)},
        "stages": stages,
        "interpretation": [
            "The first three stages quantify candidate-generation burden, not tool accuracy.",
            "The reviewed fold is the only stage that reports final evidence states.",
            "The native timing ablation is missing by design and is represented as pending, never zero.",
        ],
    }


def render_csv(report: dict[str, Any]) -> str:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(report["stages"])
    return output.getvalue()


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Evidence ablation (generated)",
        "",
        "Do not edit by hand; run `python3 scripts/run_ablation.py --write`.",
        "",
        "| Stage | Status | Cells | Pairs | CT findings | Build-sensitive | ASM candidates | Candidate pairs | Final risk | Needs review | Inconclusive |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in report["stages"]:
        lines.append(
            "| {stage} | {status} | {cells} | {pairs} | {ct_finding_pairs} | "
            "{build_sensitive_pairs} | {asm_candidate_pairs} | {candidate_pairs} | "
            "{risk_detected_pairs} | {needs_review_pairs} | {inconclusive_pairs} |".format(**row)
        )
    lines.extend(["", *[f"- {item}" for item in report["interpretation"]], ""])
    return "\n".join(lines)


def expected_outputs(data: dict[str, Any]) -> dict[Path, str]:
    report = build_report(data)
    return {
        _repo_path(data["outputs"]["csv"], "outputs.csv"): render_csv(report),
        _repo_path(data["outputs"]["json"], "outputs.json"): json.dumps(
            report, indent=2, sort_keys=True
        )
        + "\n",
        _repo_path(data["outputs"]["markdown"], "outputs.markdown"): render_markdown(report),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    args = parser.parse_args()
    try:
        data = load_manifest(args.manifest)
        outputs = expected_outputs(data)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"[ablation] ERROR: {exc}", file=sys.stderr)
        return 2
    if args.write:
        for path, content in outputs.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        print(f"[ablation] wrote {len(outputs)} deterministic artifacts")
        return 0
    stale = [
        path
        for path, content in outputs.items()
        if not path.is_file() or path.read_text(encoding="utf-8") != content
    ]
    if stale:
        for path in stale:
            print(f"[ablation] ERROR: stale or missing: {path.relative_to(ROOT)}", file=sys.stderr)
        return 2
    print(f"[ablation] OK: {len(outputs)} deterministic artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
