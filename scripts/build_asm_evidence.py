#!/usr/bin/env python3
"""Build the external, content-addressed ML-KEM assembly evidence bundle."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ctkat.asm_evidence import AsmEvidenceError, build_bundle  # noqa: E402

DEFAULT_CAMPAIGN = ROOT / "docs/measurement/mlkem_asm_evidence_v1.yaml"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, default=DEFAULT_CAMPAIGN)
    parser.add_argument(
        "--output-root",
        type=Path,
        default=ROOT / "artifact_runs/mlkem-asm-evidence-v1",
        help="external output directory (raw disassembly is intentionally gitignored)",
    )
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="engineering-only run; resulting bundle is not paper-eligible",
    )
    parser.add_argument(
        "--allow-nonpaper-host",
        action="store_true",
        help="engineering-only run outside native Linux x86_64",
    )
    args = parser.parse_args()

    try:
        manifest, bundle_path, indexes = build_bundle(
            args.campaign,
            args.output_root,
            repo_root=ROOT,
            timeout=args.timeout,
            allow_dirty=args.allow_dirty,
            allow_nonpaper_host=args.allow_nonpaper_host,
        )
    except (AsmEvidenceError, OSError, ValueError) as exc:
        print(f"[asm-evidence] ERROR: {exc}", file=sys.stderr)
        return 2

    coverage = manifest["coverage"]
    raw = manifest["raw_bundle"]
    print(
        "[asm-evidence] "
        f"coverage={coverage['status']} "
        f"passed={coverage['passed_cells']}/{coverage['expected_cells']} "
        f"failed={coverage['failed_cells']}"
    )
    print(f"[asm-evidence] manifest={bundle_path}")
    print(
        f"[asm-evidence] raw={args.output_root / raw['path']} "
        f"aggregate_sha256={raw['sha256']} artifacts={raw['artifact_count']}"
    )
    for path in indexes:
        print(f"[asm-evidence] target-index={path}")
    if manifest["paper_eligible"] is not True:
        print("[asm-evidence] bundle is NOT paper-eligible", file=sys.stderr)
        for error in manifest["errors"]:
            print(f"  - {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
