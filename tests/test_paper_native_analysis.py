import csv
import hashlib
import json
from pathlib import Path

import pytest
import yaml

from scripts import analyze_paper_native_results as analysis
from scripts import reproduce_artifact

COMMIT = "a" * 40


def test_review_descendant_critical_path_policy_matches_bundle_gate():
    assert analysis.MEASUREMENT_CRITICAL_PATHS == reproduce_artifact.MEASUREMENT_CRITICAL_PATHS


def _host_axis(
    host_id: str,
    *,
    status: str = "PASS",
    deltas: tuple[float, ...] = (1.0, 2.0, 3.0),
    key: analysis.AxisKey | None = None,
) -> analysis.HostAxis:
    suffix = "1" if host_id == "host-a" else "2"
    return analysis.HostAxis(
        key=key or analysis.AxisKey("component", "target", "sign"),
        family="Synthetic",
        axis="sk",
        host_id=host_id,
        cpu_model=f"cpu-{suffix}",
        machine_id_sha256=suffix * 64,
        raw_status=status,
        timing_validity="valid",
        timing_signal=analysis._signal(status),
        t_score=1.0,
        abs_t_score=12.0 if status == "FAIL" else 1.0,
        n0=15_000,
        n1=15_000,
        repeat_deltas=deltas,
        signature=None,
    )


def test_either_host_finding_remains_combined_risk():
    observations = [
        _host_axis("host-a", status="PASS"),
        _host_axis("host-b", status="FAIL"),
    ]
    result = analysis.build_analysis(
        observations,
        expected_commit=COMMIT,
        bundle_id="bundle",
        input_records=[],
        input_aggregate_sha256="0" * 64,
        pairwise_families={},
    )
    axis = result["primary_axes"][0]
    assert axis["combined_status"] == "risk-detected"
    assert axis["risk_on_either_host"] is True
    assert result["analysis_policy"]["secondary_can_override_primary"] is False


def test_student_t_and_holm_match_known_values():
    assert analysis._student_t_two_sided_p(2.570582, 5) == pytest.approx(0.05, abs=2e-7)
    rows = [
        {"contrast_id": "a", "p_value_raw": 0.01},
        {"contrast_id": "b", "p_value_raw": 0.03},
        {"contrast_id": "c", "p_value_raw": 0.04},
    ]
    analysis._holm_adjust(rows)
    adjusted = {row["contrast_id"]: row["p_value_holm"] for row in rows}
    assert adjusted == pytest.approx({"a": 0.03, "b": 0.06, "c": 0.06})


def test_pairwise_contrast_uses_both_hosts_and_adjusts_within_family():
    left = analysis.AxisKey("component", "left", "kem_dec")
    middle = analysis.AxisKey("component", "middle", "kem_dec")
    right = analysis.AxisKey("component", "right", "kem_dec")
    by_key = {
        left: [
            _host_axis("host-a", key=left, deltas=(0.0, 0.2, -0.2)),
            _host_axis("host-b", key=left, deltas=(0.1, -0.1, 0.0)),
        ],
        middle: [
            _host_axis("host-a", key=middle, deltas=(2.0, 2.2, 1.8)),
            _host_axis("host-b", key=middle, deltas=(2.1, 1.9, 2.0)),
        ],
        right: [
            _host_axis("host-a", key=right, deltas=(5.0, 5.2, 4.8)),
            _host_axis("host-b", key=right, deltas=(5.1, 4.9, 5.0)),
        ],
    }
    rows = analysis._pairwise_contrasts(by_key, {"family": (left, middle, right)})
    assert len(rows) == 3
    assert all(row["n_left"] == row["n_right"] == 6 for row in rows)
    assert all(row["p_value_holm"] >= row["p_value_raw"] for row in rows)
    assert all(row["method"].startswith("welch-two-sided") for row in rows)


def test_signature_association_reports_constant_and_variable_lengths():
    constant = analysis.SignatureAssociation()
    variable = analysis.SignatureAssociation()
    for index in range(20):
        clazz = index % 2
        constant.add(64, 100.0 + index, clazz)
        length = 60 + index
        variable.add(length, 3.0 * length + 7.0 * clazz, clazz)
    constant_result = constant.result()
    variable_result = variable.result()
    assert constant_result["status"] == "constant-length"
    assert constant_result["pearson_r"] is None
    assert variable_result["status"] == "variable-length"
    assert variable_result["pearson_r"] > 0.95
    assert variable_result["within_class_pearson_r"] > 0.99
    assert variable_result["p_value"] < 1e-10


PROTOCOL_FIELDS = [
    "project",
    "harness",
    "role",
    "process_index",
    "seed",
    "effect_ticks",
    "sample_id",
    "class",
    "cycles",
    "aux_start",
    "aux_end",
    "drop_reason",
    "output_length",
    "signature_return_code",
    "protocol",
]


def _write_protocol(path: Path, *, failed_rc: bool = False) -> None:
    rows = []
    for process_index in range(3):
        for sample_id in range(4):
            rows.append(
                {
                    "project": "sig-a",
                    "harness": "sign",
                    "role": "target",
                    "process_index": process_index,
                    "seed": 10 + process_index,
                    "effect_ticks": 0,
                    "sample_id": sample_id,
                    "class": sample_id % 2,
                    "cycles": 100 + 2 * sample_id + process_index,
                    "aux_start": 2,
                    "aux_end": 2,
                    "drop_reason": "",
                    "output_length": 64 + sample_id % 2,
                    "signature_return_code": (
                        1 if failed_rc and process_index == 2 and sample_id == 3 else 0
                    ),
                    "protocol": "timing-harness-v2",
                }
            )
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=PROTOCOL_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def test_protocol_parser_rejects_any_failed_signature_call(tmp_path: Path):
    path = tmp_path / "protocol.csv"
    _write_protocol(path, failed_rc=True)
    with pytest.raises(analysis.AnalysisError, match="returned nonzero"):
        analysis._parse_protocol(
            path,
            project="sig-a",
            harnesses=["sign"],
            sign_harnesses={"sign"},
            process_repeats=3,
            target_measurements=4,
        )


def _runtime_metadata() -> dict[str, object]:
    return {
        "signature_return_code_recorded": True,
        "signature_length_contract": "bounded",
        "signature_length_min": 1,
        "signature_length_max": 128,
        "signature_correctness_gate": "passed",
        "measured_signature_contract_failures": 0,
    }


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _make_component(
    root: Path,
    manifest: Path,
    *,
    host_id: str,
    cpu_model: str,
    machine_id: str,
    commit: str = COMMIT,
) -> Path:
    component_root = root / host_id / "component"
    report_dir = component_root / "sig-a" / "reports"
    report_dir.mkdir(parents=True)
    protocol_path = report_dir / "dudect_protocol_timings.csv"
    _write_protocol(protocol_path)
    (report_dir / "dudect_raw_timings.csv").write_text("raw\n", encoding="utf-8")
    (report_dir / "dudect_calibration_timings.csv").write_text("calibration\n", encoding="utf-8")
    (report_dir / "dudect_summary.csv").write_text("summary\n", encoding="utf-8")
    metadata = _runtime_metadata()
    backend = {
        "schema_version": "2.0",
        "kind": "timing-backend-report",
        "project": "sig-a",
        "protocol_trace_sha256": _sha256(protocol_path),
        "harnesses": [
            {
                "harness": "sign",
                "raw_status": "PASS",
                "timing_validity": "valid",
                "t_score": 1.0,
                "abs_t_score": 1.0,
                "n0": 6,
                "n1": 6,
                "analysis_runtime_metadata": metadata,
                "environment": {
                    "cpu_model": cpu_model,
                    "machine_id_sha256": machine_id,
                    "rejected": False,
                },
                "harness_protocol": {
                    "template": "sign",
                    "axis": "sk",
                    "target_repeats": [
                        {"process_index": index, "runtime_metadata": metadata} for index in range(3)
                    ],
                    "signature_call_contract": {
                        "configured": "bounded",
                        "return_code_column": "signature_return_code",
                        "return_code_success": 0,
                        "return_codes_recorded": True,
                        "correctness_round_trip_gate": True,
                        "measured_contract_failures": 0,
                        "resolved_min": 1,
                        "resolved_max": 128,
                        "traces_validated": 3,
                        "passed": True,
                    },
                },
            }
        ],
    }
    backend_path = report_dir / "dudect_backend_report.json"
    backend_path.write_text(json.dumps(backend), encoding="utf-8")
    hashes = {path.name: _sha256(path) for path in sorted(report_dir.iterdir()) if path.is_file()}
    campaign_report = {
        "schema_version": "2.0",
        "kind": "native-timing-campaign-report",
        "campaign_id": "synthetic-native-v1",
        "manifest_sha256": _sha256(manifest),
        "ctkat_commit": commit,
        "run_kind": "final",
        "run_id": ("1" if host_id == "host-a" else "2") * 32,
        "status": "complete",
        "paper_promotion_ready": True,
        "human_review_gate": {
            "kind": "human-premeasurement-review-gate",
            "ready": True,
        },
        "selected_targets": ["sig-a"],
        "host_preflight": {
            "paper_eligible": True,
            "git_commit": commit,
            "git_dirty": False,
            "compiler": "gcc synthetic 1.0",
            "compiler_executable": {
                "resolved_path": "/usr/bin/gcc",
                "sha256": "4" * 64,
            },
            "environment": {
                "system": "Linux",
                "machine": "x86_64",
                "cpu_model": cpu_model,
                "machine_id_sha256": machine_id,
                "boot_id_sha256": "3" * 64,
                "cpu_affinity": [2],
                "emulated": False,
                "rejected": False,
            },
            "virtualization": {"vm": "", "container": ""},
        },
        "targets": {
            "sig-a": {
                "target": "sig-a",
                "family": "Synthetic",
                "report_dir": "sig-a/reports",
                "complete": True,
                "promotion_ready": True,
                "errors": [],
                "blockers": [],
                "harnesses": [
                    {
                        "harness": "sign",
                        "axis": "sk",
                        "raw_status": "PASS",
                        "timing_validity": "valid",
                        "timing_signal": "no-signal-observed",
                        "abs_t_score": 1.0,
                        "analysis_seed": 10,
                        "n0": 6,
                        "n1": 6,
                        "promotion_ready": True,
                        "blockers": [],
                    }
                ],
                "artifact_sha256": hashes,
            }
        },
    }
    (component_root / "campaign_report.json").write_text(
        json.dumps(campaign_report), encoding="utf-8"
    )
    return component_root


def test_two_host_provenance_loader_and_outputs_are_deterministic(tmp_path: Path):
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text(
        yaml.safe_dump(
            {
                "schema_version": "1.0",
                "campaign_id": "synthetic-native-v1",
                "protocol": {"process_repeats": 3},
                "targets": [
                    {
                        "id": "sig-a",
                        "family": "Synthetic",
                        "harnesses": ["sign"],
                        "axes": {"sign": "sk"},
                        "target_measurements": 4,
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    plan = {"synthetic": analysis.ComponentPlan("synthetic", manifest, "synthetic-native-v1")}
    host_records = []
    for host_id, cpu_model, machine_id in (
        ("host-a", "cpu-a", "1" * 64),
        ("host-b", "cpu-b", "2" * 64),
    ):
        component_root = _make_component(
            tmp_path,
            manifest,
            host_id=host_id,
            cpu_model=cpu_model,
            machine_id=machine_id,
        )
        host_records.append(
            {
                "id": host_id,
                "cpu_model": cpu_model,
                "machine_id_sha256": machine_id,
                "components": {"synthetic": str(component_root)},
            }
        )

    ledger = analysis.InputLedger()
    observations = []
    for host in host_records:
        observations.extend(analysis.load_host_axes(host, COMMIT, ledger, component_plans=plan))
    result = analysis.build_analysis(
        observations,
        expected_commit=COMMIT,
        bundle_id="synthetic-bundle",
        input_records=ledger.records(),
        input_aggregate_sha256=ledger.aggregate_sha256(),
        pairwise_families={},
    )
    assert result["summary"]["axis_count"] == 1
    assert result["summary"]["signature_host_axis_count"] == 2
    assert result["signature_length_associations"][0]["status"] == "variable-length"
    assert len({item["label"] for item in result["inputs"]}) == len(result["inputs"])

    output = tmp_path / "output"
    analysis.write_outputs(output, result, check=False)
    first = {path.name: path.read_bytes() for path in output.iterdir()}
    with pytest.raises(analysis.AnalysisError, match="absent or empty"):
        analysis.write_outputs(output, result, check=False)
    second = {path.name: path.read_bytes() for path in output.iterdir()}
    assert first == second
    analysis.write_outputs(output, result, check=True)

    with pytest.raises(analysis.AnalysisError, match="commit mismatch"):
        analysis.load_host_axes(
            host_records[0], "b" * 40, analysis.InputLedger(), component_plans=plan
        )


def test_zero_variance_heterogeneity_is_explicit_warning():
    result = analysis._host_heterogeneity(
        [
            _host_axis("host-a", deltas=(1.0, 1.0, 1.0)),
            _host_axis("host-b", deltas=(2.0, 2.0, 2.0)),
        ]
    )
    assert result["i2_percent"] is None
    assert result["warning"] is True
    assert "heterogeneity-unavailable-zero-within-host-variance" in result["warning_reasons"]


def test_blinded_outputs_hide_labels_and_unblinded_mode_checks_byte_parity(tmp_path: Path):
    key = analysis.AxisKey("secret-component", "secret-target", "sign")
    named = analysis.build_analysis(
        [
            _host_axis("host-a", key=key),
            _host_axis("host-b", key=key, deltas=(1.5, 2.5, 3.5)),
        ],
        expected_commit=COMMIT,
        verification_commit="b" * 40,
        bundle_id="bundle",
        input_records=[{"label": "secret-component/secret-target/raw", "sha256": "0" * 64}],
        input_aggregate_sha256="1" * 64,
        pairwise_families={},
    )
    mapping = analysis.BlindingMap(
        bundle_id="bundle",
        scope="result-analyst-label-blinding",
        labels=(("A001", "secret-component", "secret-target"),),
    )
    blinded = analysis.blind_analysis(named, mapping)
    serialized = json.dumps(blinded, sort_keys=True)
    assert "secret-component" not in serialized
    assert "secret-target" not in serialized
    assert blinded["primary_axes"][0]["target"] == "A001"
    assert blinded["inputs"] == []

    output = tmp_path / "blinded"
    manifest_hash = analysis.write_blinded_outputs(output, blinded, check=False)
    analysis.verify_blinded_outputs(
        output,
        blinded,
        expected_manifest_sha256=manifest_hash,
    )
    extra = output / "REAL_LABELS.txt"
    extra.write_text("secret-target\n", encoding="utf-8")
    with pytest.raises(analysis.AnalysisError, match="file set drift"):
        analysis.verify_blinded_outputs(
            output,
            blinded,
            expected_manifest_sha256=manifest_hash,
        )
    extra.unlink()
    unblinded = analysis.unblinded_analysis(
        named,
        mapping,
        {
            "blinded_analysis_manifest_sha256": manifest_hash,
            "blinded_analysis_completed_at": "2026-08-08T01:00:00Z",
            "unblinded_at": "2026-08-08T02:00:00Z",
        },
        unblinding_record_sha256="2" * 64,
    )
    assert unblinded["blinding"]["blinded_byte_parity_verified"] is True
    assert unblinded["primary_axes"][0]["target"] == "secret-target"

    axis_csv = output / "paper_native_axis_results.csv"
    axis_csv.write_bytes(axis_csv.read_bytes() + b"tampered\n")
    with pytest.raises(analysis.AnalysisError, match="output drift"):
        analysis.verify_blinded_outputs(
            output,
            blinded,
            expected_manifest_sha256=manifest_hash,
        )


def test_review_only_descendant_gate_allows_only_native_promotion_packet(monkeypatch):
    def clean_run(command, **kwargs):
        stdout = analysis.POST_VERIFICATION_ALLOWED_PATH + "\n" if command[1] == "diff" else ""
        return analysis.subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(analysis.subprocess, "run", clean_run)
    analysis._require_review_only_descendant("a" * 40, "b" * 40)

    def drifted_run(command, **kwargs):
        stdout = "docs/reviews/paper/manifest.yaml\n" if command[1] == "diff" else ""
        return analysis.subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(analysis.subprocess, "run", drifted_run)
    with pytest.raises(analysis.AnalysisError, match="outside the sole review packet"):
        analysis._require_review_only_descendant("a" * 40, "b" * 40)


def test_blinding_record_selection_allows_only_blinded_external_draft(tmp_path: Path):
    declared = tmp_path / "bundle" / "final-unblinding.yaml"
    external = tmp_path / "custodian" / "draft.yaml"
    external.parent.mkdir()
    external.write_text("draft: true\n", encoding="utf-8")

    assert (
        analysis._select_blinding_record(
            declared,
            external,
            allow_external_draft=True,
        )
        == external.resolve()
    )
    with pytest.raises(analysis.AnalysisError, match="exact record frozen"):
        analysis._select_blinding_record(
            declared,
            external,
            allow_external_draft=False,
        )

    declared.parent.mkdir()
    declared.write_text("final: true\n", encoding="utf-8")
    assert (
        analysis._select_blinding_record(
            declared,
            declared,
            allow_external_draft=False,
        )
        == declared.resolve()
    )
