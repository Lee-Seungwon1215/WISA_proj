#!/usr/bin/env python3
"""Render or verify README's committed-corpus snapshot.

The CSV is the source of truth.  CI runs this command with ``--check`` so a
corpus refresh cannot leave a hand-maintained README table behind.
"""

from __future__ import annotations

import argparse
import csv
import difflib
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_README = ROOT / "README.md"
DEFAULT_CSV = ROOT / "docs" / "corpus" / "corpus_summary.csv"
BEGIN = "<!-- BEGIN CTKAT CORPUS SNAPSHOT -->"
END = "<!-- END CTKAT CORPUS SNAPSHOT -->"
GENERATE_COMMAND = "python scripts/render_readme_corpus.py --write"


def _cell(value: str) -> str:
    value = value.strip()
    return value.replace("|", r"\|") if value else "—"


def render_block(csv_path: Path = DEFAULT_CSV) -> str:
    raw = csv_path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    required = {
        "schema_version",
        "family",
        "target",
        "harness",
        "structural",
        "asm",
        "asm_attribution",
        "timing_validity",
        "timing_signal",
        "timing_raw_status",
        "timing_abs_t",
        "review",
        "review_id",
        "overall",
    }
    missing = required.difference(rows[0] if rows else {})
    if missing:
        raise ValueError(f"corpus summary missing columns: {sorted(missing)}")

    lines = [
        BEGIN,
        (
            "<!-- source: docs/corpus/corpus_summary.csv "
            f"sha256={digest}; regenerate: {GENERATE_COMMAND} -->"
        ),
        "",
        (
            "`docs/corpus/corpus_summary.csv`에서 자동 생성한 committed "
            f"snapshot (`sha256:{digest[:12]}`)."
        ),
        "",
        (
            "| family | target / harness | structural | asm / attribution "
            "| timing validity / signal | review | overall |"
        ),
        "|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        timing = f"{row['timing_validity']} / {row['timing_signal']}"
        raw = row["timing_raw_status"].strip()
        if raw:
            timing += f" (raw {raw}"
            if row["timing_abs_t"].strip():
                timing += f", |t|={row['timing_abs_t'].strip()}"
            timing += ")"
        review = row["review"]
        if row["review_id"]:
            review += f" ({row['review_id']})"
        lines.append(
            "| "
            + " | ".join(
                [
                    _cell(row["family"]),
                    _cell(f"{row['target']} / {row['harness']}"),
                    _cell(row["structural"]),
                    _cell(f"{row['asm']} / {row['asm_attribution']}"),
                    _cell(timing),
                    _cell(review),
                    _cell(row["overall"]),
                ]
            )
            + " |"
        )
    lines.extend(["", f"재생성: `{GENERATE_COMMAND}`", END])
    return "\n".join(lines)


def replace_block(readme: str, rendered: str) -> str:
    if readme.count(BEGIN) != 1 or readme.count(END) != 1:
        raise ValueError("README must contain exactly one corpus snapshot marker pair")
    start = readme.index(BEGIN)
    end = readme.index(END, start) + len(END)
    return readme[:start] + rendered + readme[end:]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="fail if README is stale")
    mode.add_argument("--write", action="store_true", help="rewrite the generated block")
    parser.add_argument("--readme", type=Path, default=DEFAULT_README)
    parser.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    args = parser.parse_args()

    current = args.readme.read_text(encoding="utf-8")
    expected = replace_block(current, render_block(args.csv))
    if args.check:
        if current == expected:
            print("[readme-corpus] OK")
            return 0
        print("[readme-corpus] README generated block is stale")
        print(
            "".join(
                difflib.unified_diff(
                    current.splitlines(keepends=True),
                    expected.splitlines(keepends=True),
                    fromfile=str(args.readme),
                    tofile=f"{args.readme} (expected)",
                )
            ),
            end="",
        )
        return 1

    args.readme.write_text(expected, encoding="utf-8")
    print(f"[readme-corpus] wrote {args.readme}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
