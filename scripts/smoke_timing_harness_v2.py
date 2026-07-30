#!/usr/bin/env python3
"""Compile and execute the installed KEM timing-harness-v2 protocol."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ctkat.cli import (
    _dudect_context,
    _emit_dudect_report,
    _run_v2_harness_protocol,
    _set_timing_validity,
)
from ctkat.config import load_config
from ctkat.official_dudect import build_official_dudect_adapter
from ctkat.timing_harness_generator import generate_and_compile_timing


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--cc", default="gcc")
    args = parser.parse_args()

    config_path = args.repo.resolve() / "examples/toy_kem_ct_leak/ctkat.yaml"
    config = load_config(config_path)
    assert config.dudect is not None
    # The constant-work toy is fast and exercises every physical mode without
    # interpreting this short smoke as paper-grade evidence.
    harness = config.dudect.harnesses[1]
    protocol = config.dudect.timing_protocol.model_copy(
        update={
            "pool_size": 8,
            "process_repeats": 3,
            "control_measurements": 1_000,
            "positive_control_effects": [32, 128, 512],
        }
    )
    dudect = config.dudect.model_copy(
        update={
            "measurements": 1_000,
            "warmup": 10,
            "timeout": 120,
            "timing_protocol": protocol,
        }
    )
    project_dir = config_path.parent
    workdir = args.workdir.resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    generated = generate_and_compile_timing(
        name=harness.name,
        template=harness.template,
        context=_dudect_context(harness, dudect, 0xC0FFEE, "rdtsc"),
        output_dir=workdir / "generated",
        sources=[(project_dir / source).resolve() for source in harness.sources],
        include_dirs=[
            (project_dir / include_dir).resolve() for include_dir in harness.include_dirs
        ],
        cflags=dudect.compiler.cflags,
        cc=args.cc,
        workdir=workdir,
        timeout=60,
    )
    adapter = build_official_dudect_adapter(
        cc=args.cc,
        output_dir=workdir / "adapter",
    )
    samples, result, batches = _run_v2_harness_protocol(
        binary=generated.binary_path,
        workdir=workdir,
        dud=dudect,
        harness=harness,
        effective_seed=0xC0FFEE,
        official_adapter=adapter,
        crop=True,
        crop_warn_t=4.5,
        crop_fail_t=10.0,
        warn_t=4.5,
        fail_t=10.0,
    )
    _set_timing_validity(
        result,
        samples,
        harness,
        {"rejected": False, "rejection_reasons": []},
        expected_measurements=dudect.measurements,
    )
    report_dir = workdir / "reports"
    _emit_dudect_report(
        "installed-timing-harness-v2-smoke",
        report_dir,
        [(harness.name, samples, result, batches)],
    )

    expected_trace_count = protocol.process_repeats * 7
    if len(samples.protocol_traces) != expected_trace_count:
        raise SystemExit(
            f"protocol trace count mismatch: {len(samples.protocol_traces)} "
            f"!= {expected_trace_count}"
        )
    payload = json.loads((report_dir / "dudect_backend_report.json").read_text(encoding="utf-8"))
    if payload["schema_version"] != "2.0":
        raise SystemExit(f"backend report schema mismatch: {payload['schema_version']}")
    protocol_report = result.harness_protocol
    if protocol_report.get("protocol") != "timing-harness-v2":
        raise SystemExit(f"protocol manifest missing: {protocol_report!r}")
    if protocol_report.get("process_repeats_observed") != 3:
        raise SystemExit(f"process repeat mismatch: {protocol_report!r}")

    print(
        json.dumps(
            {
                "aa_runs": len(protocol_report["aa_controls"]),
                "positive_runs": len(protocol_report["positive_controls"]),
                "raw_status": result.status,
                "timing_validity": result.timing_validity,
                "traces": len(samples.protocol_traces),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
