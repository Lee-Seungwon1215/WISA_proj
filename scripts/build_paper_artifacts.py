#!/usr/bin/env python3
"""Generate deterministic premeasurement paper tables from canonical data."""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.check_paper_campaign import load_manifest as load_campaign  # noqa: E402
from scripts.check_paper_campaign import validate as validate_campaign  # noqa: E402
from scripts.check_paper_reviews import evaluate_manifest  # noqa: E402
from scripts.run_ablation import build_report as build_ablation  # noqa: E402
from scripts.run_ablation import load_manifest as load_ablation  # noqa: E402

SUMMARY = ROOT / "docs/corpus/corpus_summary.csv"
CLAIMS = ROOT / "docs/paper/CLAIM_EVIDENCE_MATRIX.yaml"
OUTPUT = ROOT / "docs/paper/generated"


def _csv_text(fields: list[str], rows: list[dict[str, Any]]) -> str:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue()


def _load_summary() -> list[dict[str, str]]:
    with SUMMARY.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _load_claims() -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    try:
        data = yaml.safe_load(CLAIMS.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        return {}, [f"claim matrix unreadable: {exc}"]
    if not isinstance(data, dict) or data.get("schema_version") != 2:
        return {}, ["claim matrix must be a schema-v2 mapping"]
    claims = data.get("claims")
    if not isinstance(claims, list) or not claims:
        return data, ["claim matrix requires claims"]
    seen: set[str] = set()
    allowed = {
        "implemented-premeasurement",
        "pending-independent-review",
        "pending-physical-measurement",
    }
    for index, claim in enumerate(claims):
        if not isinstance(claim, dict):
            errors.append(f"claims[{index}] must be a mapping")
            continue
        expected = {
            "id",
            "statement",
            "status",
            "scope",
            "evidence",
            "open_gates",
            "prohibited_wording",
        }
        if set(claim) != expected:
            errors.append(f"claims[{index}] field drift")
            continue
        claim_id = claim["id"]
        if not isinstance(claim_id, str) or claim_id in seen:
            errors.append(f"claims[{index}] id is missing or duplicate")
        seen.add(str(claim_id))
        if claim["status"] not in allowed:
            errors.append(f"claims[{index}] invalid status")
        if not isinstance(claim["evidence"], list) or not claim["evidence"]:
            errors.append(f"claims[{index}] requires evidence")
        else:
            for value in claim["evidence"]:
                raw = Path(str(value))
                candidate = ROOT / raw
                if raw.is_absolute() or ".." in raw.parts or candidate.is_symlink():
                    errors.append(f"claims[{index}] evidence escapes or is a symlink")
                    continue
                path = candidate.resolve()
                try:
                    path.relative_to(ROOT)
                except ValueError:
                    errors.append(f"claims[{index}] evidence escapes repository")
                    continue
                if path.is_symlink() or not path.is_file():
                    errors.append(f"claims[{index}] evidence missing: {value}")
        if not isinstance(claim["open_gates"], list):
            errors.append(f"claims[{index}] open_gates must be a list")
    return data, errors


def build() -> tuple[dict[Path, str], dict[str, Any]]:
    errors: list[str] = []
    summary = _load_summary()
    corpus_rows: list[dict[str, Any]] = []
    for dimension, field in (
        ("overall", "overall"),
        ("correctness", "correctness"),
        ("review", "review"),
        ("family", "family"),
        ("timing_validity", "timing_validity"),
    ):
        for value, count in sorted(Counter(row[field] for row in summary).items()):
            corpus_rows.append({"dimension": dimension, "value": value, "count": count})

    campaign_errors, campaign = validate_campaign(load_campaign())
    errors.extend(campaign_errors)
    measurement_rows = [
        {
            "component": item["id"],
            "campaign_id": item["campaign_id"],
            "coverage_mode": item["coverage_mode"],
            "targets": item["targets"],
            "timing_axes": item["timing_axes"],
            "protocol_rows_per_host": item["protocol_rows"],
            "physical_hosts": campaign["physical_hosts_required"],
            "status": "prepared-not-measured",
        }
        for item in campaign["components"]
    ]

    review, review_errors = evaluate_manifest()
    errors.extend(review_errors)
    review_rows = [
        {
            "review_id": packet["review_id"],
            "phase": packet["review_phase"],
            "required_before_measurement": str(packet["required_before_measurement"]).lower(),
            "required_by_current_campaign": "false",
            "status": packet["status"],
            "reviewers": packet["reviewer_count"],
            "minimum_reviewers": review.get("minimum_reviewers", 2),
        }
        for packet in review.get("packets", [])
    ]

    ablation = build_ablation(load_ablation())
    claims, claim_errors = _load_claims()
    errors.extend(claim_errors)
    claim_rows = [
        {
            "claim_id": claim["id"],
            "status": claim["status"],
            "scope": claim["scope"],
            "evidence_items": len(claim["evidence"]),
            "open_gates": len(claim["open_gates"]),
            "prohibited_wording": claim["prohibited_wording"],
        }
        for claim in claims.get("claims", [])
        if isinstance(claim, dict)
    ]
    if errors:
        raise ValueError("; ".join(errors))

    overall = Counter(row["overall"] for row in summary)
    correctness = Counter(row["correctness"] for row in summary)
    markdown = [
        "# Premeasurement paper tables (generated)",
        "",
        "Do not edit by hand; run `python3 scripts/build_paper_artifacts.py --write`.",
        "",
        "## Corpus state",
        "",
        f"The committed screening corpus contains {len(summary)} target/harness pairs: "
        f"{overall['risk-detected']} risk-detected, {overall['needs-review']} needs-review, "
        f"{overall['inconclusive']} inconclusive, and "
        f"{overall['no-finding-observed']} no-finding-observed. "
        f"Correctness is not run for {correctness['not-run']} pairs; these cannot fold to clean.",
        "",
        "## Native campaign readiness",
        "",
        "| Component | Targets | Axes | Rows/host | Status |",
        "|---|---:|---:|---:|---|",
    ]
    for row in measurement_rows:
        markdown.append(
            f"| {row['component']} | {row['targets']} | {row['timing_axes']} | "
            f"{row['protocol_rows_per_host']} | {row['status']} |"
        )
    markdown.extend(
        [
            "",
            f"Final timing requires {campaign['physical_hosts_required']} physical hosts; "
            f"the frozen plan contains {campaign['timing_axes']} component-axis executions "
            f"and {campaign['protocol_rows_all_hosts']} protocol rows on the frozen host.",
            "",
            "## Optional independent review readiness",
            "",
            f"Packets: {len(review_rows)}; premeasurement ready: "
            f"{str(review['pre_measurement_ready']).lower()}; paper ready: "
            f"{str(review['paper_ready']).lower()}. Pending means v7 makes no independent-review "
            "claim; it is not a v7 execution gate.",
            "",
            "## Claim readiness",
            "",
            "| Claim | Status | Evidence items | Open gates |",
            "|---|---|---:|---:|",
        ]
    )
    for row in claim_rows:
        markdown.append(
            f"| {row['claim_id']} | {row['status']} | {row['evidence_items']} | {row['open_gates']} |"
        )
    markdown.append("")

    aggregate = {
        "schema_version": 2,
        "kind": "ctkat-premeasurement-paper-artifacts",
        "corpus_pairs": len(summary),
        "corpus_state_counts": dict(sorted(overall.items())),
        "measurement_campaign": campaign,
        "review_readiness": {
            "required_by_current_campaign": False,
            "minimum_reviewers": review["minimum_reviewers"],
            "pre_measurement_ready": review["pre_measurement_ready"],
            "paper_ready": review["paper_ready"],
            "status_counts": review["status_counts"],
            "packets": review_rows,
        },
        "ablation": ablation,
        "claims": claim_rows,
    }
    outputs = {
        OUTPUT / "corpus_state_counts.csv": _csv_text(["dimension", "value", "count"], corpus_rows),
        OUTPUT / "measurement_plan.csv": _csv_text(
            [
                "component",
                "campaign_id",
                "coverage_mode",
                "targets",
                "timing_axes",
                "protocol_rows_per_host",
                "physical_hosts",
                "status",
            ],
            measurement_rows,
        ),
        OUTPUT / "review_readiness.csv": _csv_text(
            [
                "review_id",
                "phase",
                "required_before_measurement",
                "required_by_current_campaign",
                "status",
                "reviewers",
                "minimum_reviewers",
            ],
            review_rows,
        ),
        OUTPUT / "claim_readiness.csv": _csv_text(
            ["claim_id", "status", "scope", "evidence_items", "open_gates", "prohibited_wording"],
            claim_rows,
        ),
        OUTPUT / "premeasurement_tables.json": json.dumps(aggregate, indent=2, sort_keys=True)
        + "\n",
        OUTPUT / "README.md": "\n".join(markdown),
    }
    return outputs, aggregate


def main() -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--write", action="store_true")
    group.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        outputs, aggregate = build()
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"[paper-artifacts] ERROR: {exc}", file=sys.stderr)
        return 2
    if args.write:
        OUTPUT.mkdir(parents=True, exist_ok=True)
        for path, content in outputs.items():
            path.write_text(content, encoding="utf-8")
        print(f"[paper-artifacts] wrote {len(outputs)} files")
        return 0
    stale = [
        path
        for path, content in outputs.items()
        if not path.is_file() or path.read_text(encoding="utf-8") != content
    ]
    if stale:
        for path in stale:
            print(
                f"[paper-artifacts] ERROR: stale or missing: {path.relative_to(ROOT)}",
                file=sys.stderr,
            )
        return 2
    print(
        f"[paper-artifacts] OK: {aggregate['corpus_pairs']} corpus pairs, "
        f"{aggregate['measurement_campaign']['timing_axes']} frozen axes"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
