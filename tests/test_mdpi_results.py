import json
from pathlib import Path

import pytest

from scripts import render_mdpi_results as mdpi


def _analysis() -> dict[str, object]:
    host = {
        "id": "host-a",
        "cpu_model": "Synthetic Test CPU",
        "machine_id_sha256": "a" * 64,
    }
    axes: list[dict[str, object]] = []
    states = tuple(sorted(mdpi.ALLOWED_STATES))
    for component, count in mdpi.EXPECTED_COMPONENTS.items():
        for index in range(count):
            state = states[len(axes) % len(states)]
            raw_status, validity, signal = {
                "risk-detected": ("FAIL", "valid", "signal"),
                "needs-review": ("WARNING", "valid", "warning"),
                "inconclusive": ("PASS", "invalid", "no-signal-observed"),
                "no-finding-observed": ("PASS", "valid", "no-signal-observed"),
            }[state]
            axes.append(
                {
                    "component": component,
                    "target": f"target-{index:02d}",
                    "family": "synthetic",
                    "harness": "operation",
                    "axis": f"axis-{index:02d}",
                    "combined_status": state,
                    "host_results": [
                        {
                            "host_id": host["id"],
                            "cpu_model": host["cpu_model"],
                            "machine_id_sha256": host["machine_id_sha256"],
                            "raw_status": raw_status,
                            "timing_validity": validity,
                            "timing_signal": signal,
                            "t_score": 1.25,
                            "abs_t_score": 1.25,
                            "n0": 15_000,
                            "n1": 15_000,
                            "repeat_class_mean_deltas": [0.1, 0.2, 0.3],
                        }
                    ],
                    "host_heterogeneity": {
                        "applicability": "not-applicable-single-host",
                        "warning": False,
                    },
                }
            )
    counts = {
        state: sum(axis["combined_status"] == state for axis in axes)
        for state in mdpi.ALLOWED_STATES
    }
    return {
        "schema_version": "1.0",
        "kind": "paper-native-single-host-analysis",
        "bundle_id": "synthetic-single-host-bundle",
        "ctkat_commit": mdpi.FROZEN_MEASUREMENT_COMMIT,
        "measurement_commit": mdpi.FROZEN_MEASUREMENT_COMMIT,
        "verification_commit": mdpi.FROZEN_MEASUREMENT_COMMIT,
        "input_aggregate_sha256": "b" * 64,
        "hosts": [host],
        "summary": {
            "axis_count": len(axes),
            "combined_status_counts": counts,
        },
        "primary_axes": axes,
    }


def _values_by_name(outputs: dict[Path, str]) -> dict[str, str]:
    return {path.name: value for path, value in outputs.items()}


def test_pending_render_is_explicit_and_preserves_frozen_scope(tmp_path: Path):
    outputs = _values_by_name(mdpi.build_outputs(output_root=tmp_path))
    assert "NATIVE-RESULTS-PENDING" in outputs["native_results.tex"]
    assert r"\NativeResultsAvailablefalse" in outputs["native_summary.tex"]
    assert "Total & 26 & 28 & 8,220,000" in outputs["static_results.tex"]
    state = json.loads(outputs["render_state.json"])
    assert state["native_results"] == "pending"
    assert state["measurement_commit"] == mdpi.FROZEN_MEASUREMENT_COMMIT
    assert state["expected_axes"] == 28


def test_complete_render_accepts_only_full_named_analysis(tmp_path: Path):
    analysis_path = tmp_path / "paper_native_analysis.json"
    analysis_path.write_text(json.dumps(_analysis()), encoding="utf-8")
    outputs = _values_by_name(
        mdpi.build_outputs(analysis_path=analysis_path, output_root=tmp_path / "generated")
    )
    assert "NATIVE-RESULTS-PENDING" not in outputs["native_results.tex"]
    assert r"\NativeResultsAvailabletrue" in outputs["native_summary.tex"]
    assert "Synthetic Test CPU" in outputs["native_summary.tex"]
    assert outputs["native_results.tex"].count(r"\begin{table}[H]") == 4
    state = json.loads(outputs["render_state.json"])
    assert state["native_results"] == "complete"
    assert state["analysis_input"] == "paper_native_analysis.json"
    assert len(state["analysis_input_sha256"]) == 64


def test_complete_render_rejects_axis_count_drift(tmp_path: Path):
    data = _analysis()
    data["primary_axes"] = data["primary_axes"][:-1]  # type: ignore[index]
    data["summary"]["axis_count"] = 27  # type: ignore[index]
    path = tmp_path / "paper_native_analysis.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(mdpi.RenderError, match="28 axes"):
        mdpi.build_outputs(analysis_path=path, output_root=tmp_path / "generated")


def test_complete_render_does_not_embed_machine_specific_parent_path(tmp_path: Path):
    values = []
    payload = json.dumps(_analysis())
    for directory in (tmp_path / "one", tmp_path / "two"):
        directory.mkdir()
        analysis_path = directory / "paper_native_analysis.json"
        analysis_path.write_text(payload, encoding="utf-8")
        values.append(
            _values_by_name(
                mdpi.build_outputs(
                    analysis_path=analysis_path,
                    output_root=directory / "generated",
                )
            )
        )
    assert values[0] == values[1]
