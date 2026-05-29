import csv
import json
from pathlib import Path
from typing import Dict, List

from .valgrind_parser import Finding, FindingType


CSV_FIELDS = [
    "project",
    "harness",
    "function",
    "file",
    "line",
    "severity",
    "type",
    "message",
    "origin_function",
    "origin_file",
    "origin_line",
    "recommendation",
]


# Short, actionable hint per finding type so a reader can scan the CSV
# without having to look up what each `SECRET_DEPENDENT_*` actually implies.
_RECOMMENDATIONS = {
    FindingType.SECRET_DEPENDENT_BRANCH:
        "Replace data-dependent branch with constant-time select/mask.",
    FindingType.SECRET_DEPENDENT_MEMORY_ACCESS:
        "Avoid table lookup indexed by secret; consider bitsliced or constant-time alternative.",
    FindingType.SECRET_DEPENDENT_VALUE_USE:
        "Verify the operation has data-independent latency on target CPU (esp. div/mul).",
    FindingType.MEMORY_ERROR:
        "Fix the underlying memory error before trusting CT analysis results.",
    FindingType.UNKNOWN:
        "Inspect manually — finding type not classified.",
}


def finding_to_row(project: str, harness: str, finding: Finding) -> Dict[str, str]:
    primary = finding.primary_frame
    origin = finding.origin_frame
    return {
        "project": project,
        "harness": harness,
        "function": primary.function if primary else "",
        "file": primary.file if primary and primary.file else "",
        "line": str(primary.line) if primary and primary.line is not None else "",
        "severity": finding.severity.value,
        "type": finding.type.value,
        "message": finding.message,
        "origin_function": origin.function if origin else "",
        "origin_file": origin.file if origin and origin.file else "",
        "origin_line": str(origin.line) if origin and origin.line is not None else "",
        "recommendation": _RECOMMENDATIONS.get(finding.type, ""),
    }


def write_csv(rows: List[Dict[str, str]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        # lineterminator="\n" to keep awk/grep-friendly LF endings; csv's
        # Excel-flavored CRLF default trips downstream Unix tooling.
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def write_json(payload: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)
