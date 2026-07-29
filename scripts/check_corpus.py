#!/usr/bin/env python3
"""Fail-closed validation for the committed corpus v1 CSV artifacts."""

from __future__ import annotations

import csv
import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "docs" / "corpus"
BUILDER_PATH = ROOT / "scripts" / "build_corpus_table.py"
SPEC = importlib.util.spec_from_file_location("ctkat_build_corpus_table", BUILDER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot import {BUILDER_PATH}")
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)
sys.path.insert(0, str(ROOT))

from ctkat.verdict_class import VERDICT_CLASSES  # noqa: E402


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


def main() -> int:
    cells, errors = read_csv(CORPUS / "corpus_cells.csv", BUILDER.CELLS_FIELDS)
    summary, summary_errors = read_csv(CORPUS / "corpus_summary.csv", BUILDER.SUMMARY_FIELDS)
    errors.extend(summary_errors)

    cell_keys: set[tuple[str, str, str]] = set()
    summary_pairs: set[tuple[str, str]] = set()
    allowed_ct = {"PASS", "FAIL", "ERROR", "NA"}
    for number, row in enumerate(cells, start=2):
        key = (row["target"], row["harness"], row["combo"])
        if key in cell_keys:
            errors.append(f"corpus_cells.csv:{number}: duplicate key {key}")
        cell_keys.add(key)
        if row["ct_status"] not in allowed_ct:
            errors.append(f"corpus_cells.csv:{number}: invalid ct_status={row['ct_status']!r}")
        if not row["cc_version"] or not row["arch"] or not row["ctkat_commit"]:
            errors.append(f"corpus_cells.csv:{number}: cc_version/arch/ctkat_commit required")
        if row["ctkat_commit"] and not re.fullmatch(r"[0-9a-f]{7,40}", row["ctkat_commit"]):
            errors.append(
                f"corpus_cells.csv:{number}: malformed ctkat_commit {row['ctkat_commit']!r}"
            )

    allowed_timing = {"", "PASS", "WARNING", "FAIL", "ERROR", "NONE"}
    warnings: list[str] = []
    for number, row in enumerate(summary, start=2):
        pair = (row["target"], row["harness"])
        if pair in summary_pairs:
            errors.append(f"corpus_summary.csv:{number}: duplicate key {pair}")
        summary_pairs.add(pair)
        if pair not in {(target, harness) for target, harness, _ in cell_keys}:
            # A timing-only axis (currently ML-KEM's `kem_dec_ct`) has no
            # structural build cell by design. It is valid only when timing
            # evidence is actually present; an entirely unbacked row is not.
            if not row["dudect_status"]:
                errors.append(
                    f"corpus_summary.csv:{number}: no build cell or timing evidence for {pair}"
                )
        if row["verdict_class"] not in VERDICT_CLASSES:
            errors.append(
                f"corpus_summary.csv:{number}: invalid verdict_class {row['verdict_class']!r}"
            )
        if row["basis"] not in {"auto", "review", "stop"}:
            errors.append(f"corpus_summary.csv:{number}: invalid basis={row['basis']!r}")
        if row["dudect_status"] not in allowed_timing:
            errors.append(
                f"corpus_summary.csv:{number}: invalid timing status {row['dudect_status']!r}"
            )
        if row["dudect_status"] in {"WARNING", "FAIL", "ERROR"} and row["verdict_class"] in {
            "robust",
            "accepted-variable-time",
        }:
            warnings.append(
                f"{pair}: timing={row['dudect_status']} coexists with "
                f"verdict={row['verdict_class']} (M2 migration debt)"
            )

    if errors:
        for error in errors:
            print(f"[corpus] ERROR: {error}", file=sys.stderr)
        return 1
    for warning in warnings:
        print(f"[corpus] WARNING: {warning}")
    print(f"[corpus] OK: {len(cells)} cells, {len(summary)} summary rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
