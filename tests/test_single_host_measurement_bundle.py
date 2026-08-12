import json
from pathlib import Path

import yaml

from scripts.build_single_host_measurement_bundle import COMPONENT_DIRS, build_bundle
from scripts.hash_artifacts import build_manifest

COMMIT = "a" * 40
CPU = "Synthetic CPU"
MACHINE = "b" * 64


def _gate():
    return {
        "kind": "automated-frozen-input-integrity-gate",
        "ready": True,
        "physical_host_count": 1,
        "independent_human_review": False,
        "cross_host_reproducibility": False,
    }


def _write_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def test_build_single_host_bundle_discovers_fresh_results_and_hashes_tree(tmp_path):
    host_root = tmp_path / "host-a"
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
                "automated_premeasurement_gate": _gate(),
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
                "automated_premeasurement_gate": _gate(),
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
