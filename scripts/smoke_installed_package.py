#!/usr/bin/env python3
"""Render every harness family and print deterministic output hashes."""

from __future__ import annotations

import argparse
import hashlib
import json

from ctkat import __version__
from ctkat.harness_generator import render_harness
from ctkat.timing_harness_generator import render_timing_harness


def render_hashes() -> dict[str, str]:
    generic = {
        "extra_headers": [],
        "function": "probe",
        "args": ["secret", "sizeof(secret)"],
        "return_type": "int",
        "buffers": [{"name": "secret", "size": "16", "role": "secret"}],
        "seed": 0xC0FFEE,
    }
    kem = {
        "header": "api.h",
        "prefix": "TEST_",
        "extra_headers": [],
        "secret_regions": [],
    }
    sign = {
        "header": "api.h",
        "prefix": "TEST_",
        "extra_headers": [],
        "secret_regions": [],
    }
    timing_base = {
        "measurements": 32,
        "warmup": 2,
        "seed": 0xC0FFEE,
        "clock": "monotonic",
    }
    rendered = {
        "harness_generic.c.j2": render_harness("generic", generic),
        "harness_kem.c.j2": render_harness("kem", kem),
        "harness_sign.c.j2": render_harness("sign", sign),
        "timing_generic.c.j2": render_timing_harness("generic", {**generic, **timing_base}),
        "timing_kem.c.j2": render_timing_harness(
            "kem", {**kem, **timing_base, "leak_target": "sk"}
        ),
        "timing_sign.c.j2": render_timing_harness("sign", {**sign, **timing_base}),
    }
    return {
        name: hashlib.sha256(source.encode("utf-8")).hexdigest()
        for name, source in sorted(rendered.items())
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expect-version", default="0.2.0a1")
    args = parser.parse_args()
    if __version__ != args.expect_version:
        raise SystemExit(f"installed version mismatch: {__version__!r} != {args.expect_version!r}")
    print(json.dumps(render_hashes(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
