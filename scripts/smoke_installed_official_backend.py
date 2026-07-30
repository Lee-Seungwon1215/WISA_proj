#!/usr/bin/env python3
"""Compile and execute official dudect resources from an installed package."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ctkat.dudect_runner import TimingSamples
from ctkat.official_dudect import (
    OFFICIAL_DUDECT_BACKEND,
    analyze_with_official_dudect,
    build_official_dudect_adapter,
)


def _samples(count: int, leak: int) -> TimingSamples:
    classes = [index & 1 for index in range(count)]
    cycles = [
        float(20_000 + ((index * 29) % 127) + (leak if clazz else 0))
        for index, clazz in enumerate(classes)
    ]
    return TimingSamples(classes=classes, cycles=cycles, raw_n_total=count)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--cc", default="gcc")
    args = parser.parse_args()
    args.workdir.mkdir(parents=True, exist_ok=True)

    adapter = build_official_dudect_adapter(
        cc=args.cc,
        output_dir=args.workdir / "adapter",
    )
    result = analyze_with_official_dudect(
        _samples(20_050, 0),
        _samples(20_050, 80),
        adapter_binary=adapter,
        workdir=args.workdir,
    )
    if result.status != "FAIL" or len(result.tests) != 102:
        raise SystemExit(
            f"official backend smoke mismatch: status={result.status}, tests={len(result.tests)}"
        )
    print(
        json.dumps(
            {
                "backend": OFFICIAL_DUDECT_BACKEND,
                "status": result.status,
                "tests": len(result.tests),
                "enough_measurements": result.enough_measurements,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
