#!/usr/bin/env python3
"""Deterministically migrate frozen corpus v1.2 CSVs to evidence schema v2.

The migration manifest is the only place where historical human-review state
or timing validity may be upgraded. A legacy ``basis=review`` or free-text note
never becomes ``review=reviewed`` by inference.
"""

from __future__ import annotations

import argparse
import csv
import difflib
import io
import sys
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ctkat.evidence import (  # noqa: E402
    LEGACY_TIMING_BACKEND,
    SCHEMA_VERSION,
    build_evidence,
)
from scripts.build_corpus_table import CELLS_FIELDS, SUMMARY_FIELDS  # noqa: E402

V1_CELLS_FIELDS = [field for field in CELLS_FIELDS if field not in {"schema_version", "asm_status"}]
V1_SUMMARY_FIELDS = [
    "family",
    "target",
    "harness",
    "ct_flips",
    "ct_status_set",
    "ct_finding_funcs",
    "varlat_candidates",
    "varlat_triage",
    "dudect_status",
    "dudect_abs_t",
    "dudect_measurements",
    "dudect_leak_target",
    "dudect_seed",
    "dudect_threshold",
    "verdict_class",
    "basis",
    "notes",
]

DEFAULT_ARCHIVE = ROOT / "docs" / "corpus" / "archive" / "v1.2"
DEFAULT_CORPUS = ROOT / "docs" / "corpus"
DEFAULT_MIGRATED = DEFAULT_CORPUS / "archive" / "v2.0-from-v1.2"
DEFAULT_MANIFEST = DEFAULT_CORPUS / "evidence_migration.toml"


def _read_csv(path: Path, expected: list[str]) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != expected:
            raise ValueError(
                f"{path}: v1 header mismatch\nexpected={expected}\nactual={reader.fieldnames}"
            )
        rows = list(reader)
    if not rows:
        raise ValueError(f"{path}: no data rows")
    return rows


def _load_manifest(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        manifest = tomllib.load(handle)
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(
            f"{path}: schema_version must be {SCHEMA_VERSION!r}, "
            f"got {manifest.get('schema_version')!r}"
        )
    if manifest.get("source_schema_version") != "1.2":
        raise ValueError(f"{path}: source_schema_version must be '1.2'")
    return manifest


def _manifest_rows(manifest: dict[str, Any]) -> dict[tuple[str, str], dict[str, str]]:
    indexed: dict[tuple[str, str], dict[str, str]] = {}
    for item in manifest.get("rows", []):
        key = (str(item.get("target", "")), str(item.get("harness", "")))
        if not all(key):
            raise ValueError(f"migration manifest row has empty target/harness: {item}")
        if key in indexed:
            raise ValueError(f"duplicate migration manifest key: {key}")
        indexed[key] = {str(k): str(v) for k, v in item.items()}
    return indexed


def _parse_status_set(value: str) -> set[str]:
    inner = value.strip()
    if inner.startswith("{") and inner.endswith("}"):
        inner = inner[1:-1]
    return {part.strip() for part in inner.split(",") if part.strip()}


def _append_note(notes: str, text: str) -> str:
    return f"{notes}; {text}" if notes else text


def migrate_cells(
    rows: list[dict[str, str]],
    *,
    legacy_asm_cell_policy: str,
) -> list[dict[str, str]]:
    if legacy_asm_cell_policy != "assume-scanned-unless-error":
        raise ValueError(
            "migration manifest legacy_asm_cell_policy must be 'assume-scanned-unless-error'"
        )
    return [
        {
            "schema_version": SCHEMA_VERSION,
            **row,
            "asm_status": "ERROR" if row["asm_error"] else "PASS",
        }
        for row in rows
    ]


def migrate_summary(
    rows: list[dict[str, str]],
    manifest: dict[str, Any],
    *,
    cell_pairs: set[tuple[str, str]] | None = None,
) -> list[dict[str, str]]:
    overrides = _manifest_rows(manifest)
    seen: set[tuple[str, str]] = set()
    migrated: list[dict[str, str]] = []

    for row in rows:
        key = (row["target"], row["harness"])
        override = overrides.get(key, {})
        seen.add(key)
        has_cell_artifact = cell_pairs is None or key in cell_pairs
        raw_timing = row["dudect_status"]
        validity = override.get(
            "timing_validity",
            (
                str(manifest.get("default_timing_validity", "insufficient-power"))
                if raw_timing
                else "not-run"
            ),
        )
        correctness = override.get(
            "correctness", str(manifest.get("default_correctness", "not-run"))
        )

        has_candidates = has_cell_artifact and row["varlat_candidates"] not in {"", "none"}
        legacy_class = row["verdict_class"]
        asm_incomplete = has_cell_artifact and legacy_class == "ct-clean-asm-incomplete"
        migrated_triage = row["varlat_triage"] if has_cell_artifact else "untriaged"
        evidence = build_evidence(
            correctness=correctness,
            ct_statuses=(_parse_status_set(row["ct_status_set"]) if has_cell_artifact else set()),
            asm_candidate_count=1 if has_candidates else 0,
            asm_error_count=1 if asm_incomplete else 0,
            asm_cell_count=(2 if asm_incomplete else 1) if has_cell_artifact else 0,
            triage=migrated_triage,
            raw_timing_status=raw_timing,
            timing_validity=validity,
            legacy_verdict_class=legacy_class,
            legacy_basis=row["basis"],
            review_status=override.get("review", ""),
            review_id=override.get("review_id", ""),
        )

        notes = row["notes"]
        if not has_cell_artifact:
            notes = _append_note(
                notes,
                (
                    "v1 summary structural/asm claim had no matching cell artifact "
                    f"(ct={row['ct_status_set']}, asm={row['varlat_candidates']}); "
                    "normalized layers set to not-run"
                ),
            )
        if raw_timing and evidence.timing_validity.value != "valid":
            notes = _append_note(
                notes,
                (
                    f"timing validity={evidence.timing_validity.value}; "
                    f"raw {raw_timing} is non-decisional"
                ),
            )
        if evidence.review.value == "pending" and row["basis"] in {"review", "stop"}:
            notes = _append_note(
                notes,
                "review artifact pending; v1 note/basis was not promoted to reviewed",
            )

        migrated.append(
            {
                **evidence.as_dict(),
                "family": row["family"],
                "target": row["target"],
                "harness": row["harness"],
                "ct_flips": row["ct_flips"] if has_cell_artifact else "no",
                "ct_status_set": row["ct_status_set"] if has_cell_artifact else "{}",
                "ct_finding_funcs": row["ct_finding_funcs"] if has_cell_artifact else "",
                "varlat_candidates": (row["varlat_candidates"] if has_cell_artifact else "none"),
                "varlat_triage": migrated_triage,
                "timing_backend": (
                    str(manifest.get("default_timing_backend", LEGACY_TIMING_BACKEND))
                    if raw_timing
                    else ""
                ),
                "timing_raw_status": raw_timing,
                "timing_abs_t": row["dudect_abs_t"],
                "timing_measurements": row["dudect_measurements"],
                "timing_leak_target": row["dudect_leak_target"],
                "timing_seed": row["dudect_seed"],
                "timing_threshold": row["dudect_threshold"],
                "legacy_basis": row["basis"],
                "notes": notes,
            }
        )

    stale = sorted(set(overrides) - seen)
    if stale:
        raise ValueError(f"migration manifest contains row(s) absent from v1 corpus: {stale}")
    return migrated


def render_csv(rows: list[dict[str, str]], fields: list[str]) -> str:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({field: row.get(field, "") for field in fields})
    return stream.getvalue()


def expected_outputs(
    *,
    cells_in: Path,
    summary_in: Path,
    manifest_path: Path,
) -> tuple[str, str]:
    manifest = _load_manifest(manifest_path)
    source_cells = _read_csv(cells_in, V1_CELLS_FIELDS)
    cells = migrate_cells(
        source_cells,
        legacy_asm_cell_policy=str(manifest.get("legacy_asm_cell_policy", "")),
    )
    cell_pairs = {(row["target"], row["harness"]) for row in source_cells}
    summary = migrate_summary(
        _read_csv(summary_in, V1_SUMMARY_FIELDS),
        manifest,
        cell_pairs=cell_pairs,
    )
    return render_csv(cells, CELLS_FIELDS), render_csv(summary, SUMMARY_FIELDS)


def _check(path: Path, expected: str) -> bool:
    try:
        actual = path.read_text(encoding="utf-8")
    except OSError:
        actual = ""
    if actual == expected:
        return True
    print(f"[evidence-migration] drift: {_display_path(path)}")
    print(
        "".join(
            difflib.unified_diff(
                actual.splitlines(keepends=True),
                expected.splitlines(keepends=True),
                fromfile=str(path),
                tofile=f"{path} (expected)",
            )
        ),
        end="",
    )
    return False


def _display_path(path: Path) -> Path:
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT)
    except ValueError:
        return resolved


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    parser.add_argument("--cells-in", type=Path, default=DEFAULT_ARCHIVE / "corpus_cells.csv")
    parser.add_argument("--summary-in", type=Path, default=DEFAULT_ARCHIVE / "corpus_summary.csv")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--cells-out", type=Path, default=DEFAULT_MIGRATED / "corpus_cells.csv")
    parser.add_argument("--summary-out", type=Path, default=DEFAULT_MIGRATED / "corpus_summary.csv")
    args = parser.parse_args()

    try:
        cells_text, summary_text = expected_outputs(
            cells_in=args.cells_in,
            summary_in=args.summary_in,
            manifest_path=args.manifest,
        )
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        print(f"[evidence-migration] ERROR: {exc}", file=sys.stderr)
        return 1

    if args.check:
        ok = _check(args.cells_out, cells_text) & _check(args.summary_out, summary_text)
        if ok:
            print("[evidence-migration] OK: committed v2 corpus matches v1.2 + manifest")
        return 0 if ok else 1

    args.cells_out.parent.mkdir(parents=True, exist_ok=True)
    args.summary_out.parent.mkdir(parents=True, exist_ok=True)
    args.cells_out.write_text(cells_text, encoding="utf-8")
    args.summary_out.write_text(summary_text, encoding="utf-8")
    print(
        f"[evidence-migration] wrote {_display_path(args.cells_out)} and "
        f"{_display_path(args.summary_out)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
