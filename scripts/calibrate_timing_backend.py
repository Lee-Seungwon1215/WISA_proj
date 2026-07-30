#!/usr/bin/env python3
"""Deterministic synthetic calibration for the pinned timing backend.

This checks statistical-engine behavior only. It is not a substitute for the
physical A/A and positive-control runs required from each target harness.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import tempfile
from pathlib import Path
from statistics import median

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ctkat.dudect_runner import TimingSamples  # noqa: E402
from ctkat.official_dudect import (  # noqa: E402
    OFFICIAL_DUDECT_BACKEND,
    OFFICIAL_DUDECT_HEADER_SHA256,
    OFFICIAL_DUDECT_REVISION,
    OfficialDudectError,
    analyze_with_official_dudect,
    build_official_dudect_adapter,
)
from ctkat.statistics import welch_t_test  # noqa: E402

DEFAULT_REPORT = ROOT / "docs" / "calibration" / "timing_backend_v2.json"
BASE_SEED = 0x43544B4154
TRIALS = 20
SAMPLES_PER_TRACE = 50_050
BASE_CYCLES = 100_000
NOISE_SD = 100.0
EFFECT_SIZES = (0.0, 0.05, 0.10, 0.20)
AA_FALSE_ALARM_BUDGET = 0.05
STRONG_EFFECT_MIN_POWER = 0.90
PARITY_TOLERANCE = 1e-9


def _trace(seed: int, effect_size: float) -> TimingSamples:
    rng = random.Random(seed)
    classes = [index & 1 for index in range(SAMPLES_PER_TRACE)]
    rng.shuffle(classes)
    cycles = [
        float(
            round(
                BASE_CYCLES
                + rng.gauss(0.0, NOISE_SD)
                + (effect_size * NOISE_SD if clazz == 1 else 0.0)
            )
        )
        for clazz in classes
    ]
    return TimingSamples(
        classes=classes,
        cycles=cycles,
        raw_n_total=SAMPLES_PER_TRACE,
    )


def build_report(*, cc: str, workdir: Path) -> dict[str, object]:
    adapter = build_official_dudect_adapter(
        cc=cc,
        output_dir=workdir / "adapter",
        timeout=120,
    )
    curve = []
    parity_delta = None
    parity_official = None
    parity_python = None

    for effect_index, effect in enumerate(EFFECT_SIZES):
        detections = 0
        max_abs_values = []
        for trial in range(TRIALS):
            seed = BASE_SEED + effect_index * 1000 + trial
            calibration = _trace(seed ^ 0xA5A5A5A5, 0.0)
            analysis_trace = _trace(seed, effect)
            result = analyze_with_official_dudect(
                calibration,
                analysis_trace,
                adapter_binary=adapter,
                workdir=workdir,
                timeout=120,
            )
            if not result.enough_measurements:
                raise OfficialDudectError(
                    "calibration fixture unexpectedly missed upstream minimum"
                )
            detections += result.status == "FAIL"
            max_abs_values.append(result.max_abs_t)

            if effect == EFFECT_SIZES[-1] and trial == 0:
                official_uncropped = result.uncropped_test.t_score
                retained = [
                    (clazz, cycle)
                    for clazz, cycle in zip(
                        analysis_trace.classes[10:],
                        analysis_trace.cycles[10:],
                    )
                    if cycle >= 0
                ]
                class0 = [cycle for clazz, cycle in retained if clazz == 0]
                class1 = [cycle for clazz, cycle in retained if clazz == 1]
                python_uncropped = welch_t_test(class0, class1).t_score
                if official_uncropped is None:
                    raise OfficialDudectError("uncropped parity t-score was non-finite")
                parity_official = official_uncropped
                parity_python = python_uncropped
                parity_delta = abs(official_uncropped - python_uncropped)

        curve.append(
            {
                "cohens_d_injected": effect,
                "detections": detections,
                "trials": TRIALS,
                "detection_rate": detections / TRIALS,
                "max_abs_t_min": min(max_abs_values),
                "max_abs_t_median": median(max_abs_values),
                "max_abs_t_max": max(max_abs_values),
            }
        )

    assert parity_delta is not None
    aa_rate = float(curve[0]["detection_rate"])
    strong_rate = float(curve[-1]["detection_rate"])
    acceptance = {
        "aa_false_alarm_budget": AA_FALSE_ALARM_BUDGET,
        "aa_observed_rate": aa_rate,
        "aa_pass": aa_rate <= AA_FALSE_ALARM_BUDGET,
        "strong_effect_d": EFFECT_SIZES[-1],
        "strong_effect_min_power": STRONG_EFFECT_MIN_POWER,
        "strong_effect_observed_power": strong_rate,
        "strong_effect_pass": strong_rate >= STRONG_EFFECT_MIN_POWER,
        "uncropped_parity_tolerance": PARITY_TOLERANCE,
        "uncropped_parity_abs_delta": parity_delta,
        "uncropped_parity_pass": parity_delta <= PARITY_TOLERANCE,
    }
    acceptance["overall_pass"] = all(
        acceptance[key] for key in ("aa_pass", "strong_effect_pass", "uncropped_parity_pass")
    )
    return {
        "schema_version": "1.0",
        "kind": "timing-backend-synthetic-calibration",
        "scope": (
            "backend-only synthetic A/A and injected-effect calibration; "
            "does not validate a target harness, host, or measurement environment"
        ),
        "backend": OFFICIAL_DUDECT_BACKEND,
        "upstream_revision": OFFICIAL_DUDECT_REVISION,
        "upstream_header_sha256": OFFICIAL_DUDECT_HEADER_SHA256,
        "protocol": {
            "tests": 102,
            "uncropped_first_order": 1,
            "percentile_crops": 100,
            "second_order": 1,
            "minimum_class0_measurements": 10_001,
            "leak_threshold_abs_t": 10.0,
        },
        "design": {
            "base_seed": BASE_SEED,
            "trials_per_effect": TRIALS,
            "samples_per_calibration_trace": SAMPLES_PER_TRACE,
            "samples_per_analysis_trace": SAMPLES_PER_TRACE,
            "base_cycles": BASE_CYCLES,
            "noise_sd_cycles": NOISE_SD,
            "injected_cohens_d": list(EFFECT_SIZES),
        },
        "uncropped_same_trace_parity": {
            "official_t": parity_official,
            "experimental_python_t": parity_python,
            "abs_delta": parity_delta,
            "comparison_trace_rule": "analysis rows [10,N), excluding negative cycles",
        },
        "power_curve": curve,
        "acceptance": acceptance,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--output", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="ctkat-backend-calibration-") as temp:
        try:
            report = build_report(cc=args.cc, workdir=Path(temp))
        except OfficialDudectError as exc:
            print(f"[timing-calibration] ERROR: {exc}", file=sys.stderr)
            return 2
    rendered = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if args.check:
        if not args.output.is_file() or args.output.read_text(encoding="utf-8") != rendered:
            print(
                f"[timing-calibration] ERROR: {args.output} is stale; regenerate without --check",
                file=sys.stderr,
            )
            return 1
        print(
            "[timing-calibration] OK: "
            f"A/A={report['acceptance']['aa_observed_rate']:.1%}, "
            f"d={EFFECT_SIZES[-1]:.2f} "
            f"power={report['acceptance']['strong_effect_observed_power']:.1%}"
        )
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    print(f"[timing-calibration] wrote {args.output}")
    return 0 if report["acceptance"]["overall_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
