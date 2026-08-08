#!/usr/bin/env python3
"""Validate the frozen ML-KEM assembly campaign or an external raw bundle."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ctkat.asm_evidence import (  # noqa: E402
    load_campaign,
    validate_bundle,
    validate_campaign,
)

DEFAULT_CAMPAIGN = ROOT / "docs/measurement/mlkem_asm_evidence_v1.yaml"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, default=DEFAULT_CAMPAIGN)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument(
        "--static",
        action="store_true",
        help="validate only committed campaign/config/corpus/review scope",
    )
    parser.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="debug partial bundle integrity without accepting complete coverage",
    )
    parser.add_argument(
        "--no-current-commit",
        action="store_true",
        help="verify recorded files/raw data without requiring bundle commit == HEAD",
    )
    parser.add_argument(
        "--expected-commit",
        help="require the bundle source revision to equal this lowercase 40-hex commit",
    )
    args = parser.parse_args()

    if args.static:
        if args.bundle is not None:
            parser.error("--static and --bundle are mutually exclusive")
        try:
            campaign = load_campaign(args.campaign)
            errors = validate_campaign(
                campaign,
                campaign_path=args.campaign.resolve(),
                repo_root=ROOT,
            )
        except (OSError, ValueError) as exc:
            errors = [str(exc)]
        label = "campaign"
    else:
        if args.bundle is None:
            parser.error("--bundle is required unless --static is used")
        errors = validate_bundle(
            args.bundle,
            args.campaign,
            repo_root=ROOT,
            require_current_commit=not args.no_current_commit,
            require_complete=not args.allow_incomplete,
            expected_commit=args.expected_commit,
        )
        label = "bundle"

    if errors:
        print(f"[asm-evidence] INVALID {label}", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print(f"[asm-evidence] PASS {label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
