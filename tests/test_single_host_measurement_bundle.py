import hashlib
import json
from pathlib import Path

import yaml

from scripts.build_single_host_measurement_bundle import COMPONENT_DIRS, build_bundle
from scripts.hash_artifacts import build_manifest

COMMIT = "a" * 40
CPU = "Synthetic CPU"
MACHINE = "b" * 64


def _gate(host_root: Path):
    rehearsal_records = []
    report_hashes = {}
    rehearsal_run_ids = ["8" * 32, "9" * 32]
    for label, run_id in zip(("v3-a", "v3-b"), rehearsal_run_ids, strict=True):
        report_path = host_root / "control-rehearsals" / label / "rehearsal_report.json"
        _write_json(report_path, {"run_id": run_id, "status": "pass"})
        report_sha = hashlib.sha256(report_path.read_bytes()).hexdigest()
        report_hashes[str(report_path.resolve())] = report_sha
        rehearsal_records.append(
            {
                "path": str(report_path.resolve()),
                "sha256": report_sha,
                "run_id": run_id,
                "started_at": "2026-08-14T00:00:00Z",
                "finished_at": "2026-08-14T01:00:00Z",
            }
        )
    qualification_path = host_root / "v10-control-qualification.json"
    _write_json(
        qualification_path,
        {
            "schema_version": "3.0",
            "kind": "ctkat-v10-final-control-qualification",
            "created_at": "2026-08-14T02:00:00Z",
            "candidate_commit": COMMIT,
            "profile_id": "ctkat-paper-control-rehearsal-v3",
            "profile_sha256": "d" * 64,
            "calibration_sha256": "e" * 64,
            "rehearsal_run_ids": rehearsal_run_ids,
            "rehearsals": rehearsal_records,
            "required_clean_runs": 2,
            "observed_clean_runs": 2,
            "final_launch_ready": True,
            "next_gate": "execute fresh V10 final roots",
            "errors": [],
        },
    )
    return {
        "kind": "automated-frozen-input-integrity-gate",
        "ready": True,
        "ctkat_commit": COMMIT,
        "plan_id": "ctkat-paper-native-v10-single-host",
        "physical_host_count": 1,
        "independent_human_review": False,
        "cross_host_reproducibility": False,
        "control_qualification": {
            "kind": "two-clean-control-rehearsal-qualification",
            "ready": True,
            "path": str(qualification_path.resolve()),
            "sha256": hashlib.sha256(qualification_path.read_bytes()).hexdigest(),
            "profile_id": "ctkat-paper-control-rehearsal-v3",
            "profile_sha256": "d" * 64,
            "calibration_sha256": "e" * 64,
            "rehearsal_run_ids": rehearsal_run_ids,
            "rehearsal_report_sha256": report_hashes,
        },
    }


def _write_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def test_build_single_host_bundle_discovers_fresh_results_and_hashes_tree(tmp_path):
    host_root = tmp_path / "host-a"
    gate = _gate(host_root)
    for index, dirname in enumerate(COMPONENT_DIRS.values(), start=1):
        _write_json(
            host_root / dirname / "campaign_report.json",
            {
                "schema_version": "2.0",
                "kind": "native-timing-campaign-report",
                "status": "complete",
                "paper_promotion_ready": True,
                "run_kind": "final",
                "run_id": f"{index:x}" * 32,
                "ctkat_commit": COMMIT,
                "human_review_gate": None,
                "automated_premeasurement_gate": gate,
                "host_preflight": {
                    "paper_eligible": True,
                    "environment": {
                        "cpu_model": CPU,
                        "machine_id_sha256": MACHINE,
                    },
                    "virtualization": {"vm": "", "container": ""},
                },
            },
        )
    for index, tool_id in enumerate(
        ("official_dudect", "timecop", "microwalk_pin"),
        start=5,
    ):
        _write_json(
            host_root
            / "same-corpus"
            / f"20260812T00000{index}.000000Z-{tool_id}"
            / "baseline_report.json",
            {
                "schema_version": "2.0",
                "kind": "ctkat-same-corpus-baseline",
                "tool_id": tool_id,
                "run_kind": "final",
                "run_id": f"{index:x}" * 32,
                "ctkat_commit": COMMIT,
                "git_dirty": False,
                "promotion_ready": True,
                "human_review_gate": None,
                "automated_premeasurement_gate": gate,
                "host": {"cpu_model": CPU, "machine_id_sha256": MACHINE},
            },
        )
    _write_json(
        host_root / "asm-evidence" / "asm_evidence_bundle.json",
        {
            "kind": "ctkat-asm-evidence-bundle",
            "paper_eligible": True,
            "source_revision": {"commit": COMMIT},
        },
    )

    output = tmp_path / "measurement_bundle.yaml"
    bundle = build_bundle(
        host_root,
        output,
        host_id="host-a",
        analysis_output=tmp_path / "analysis" / "named",
    )

    assert bundle["schema_version"] == 5
    assert bundle["measurement_commit"] == COMMIT
    assert bundle["hosts"][0]["cpu_model"] == CPU
    assert bundle["hosts"][0]["artifact_root"] == "host-a"
    assert bundle["analysis"]["output_root"] == "analysis/named"
    assert yaml.safe_load(output.read_text(encoding="utf-8")) == bundle
    hash_manifest = host_root / "SHA256SUMS"
    assert hash_manifest.read_text(encoding="utf-8") == build_manifest(
        host_root,
        exclude=hash_manifest,
    )
