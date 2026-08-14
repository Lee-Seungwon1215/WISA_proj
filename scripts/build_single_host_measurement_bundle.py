#!/usr/bin/env python3
"""Build a fail-closed schema-v5 bundle from one completed physical host tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.hash_artifacts import build_manifest  # noqa: E402

COMPONENT_DIRS = {
    "committed-corpus-refresh": "committed-corpus-v5",
    "kyberslash-contrast": "kyberslash-v5",
    "falcon-contrast": "falcon-v4",
    "diverse-lineages": "diverse-v4",
}
BASELINE_TOOLS = ("official_dudect", "timecop", "microwalk_pin")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class BundleError(RuntimeError):
    """The candidate host tree cannot support a schema-v5 paper bundle."""


def _read_json(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise BundleError(f"{label} is missing or not a regular file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BundleError(f"{label} is unreadable: {exc}") from exc
    if not isinstance(value, dict):
        raise BundleError(f"{label} must be a JSON object")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _relative(bundle_root: Path, path: Path, label: str) -> str:
    resolved = path.resolve()
    if path.is_symlink() or not resolved.is_relative_to(bundle_root):
        raise BundleError(f"{label} escapes the bundle root")
    return resolved.relative_to(bundle_root).as_posix()


def _one_report(root: Path, tool_id: str) -> Path:
    tool_root = root / "same-corpus"
    reports = sorted(tool_root.glob(f"*-{tool_id}/baseline_report.json"))
    if len(reports) != 1:
        raise BundleError(
            f"{tool_id}: expected exactly one fresh baseline report, found {len(reports)}"
        )
    return reports[0]


def _gate_ok(report: dict[str, Any], *, label: str) -> dict[str, Any]:
    gate = report.get("automated_premeasurement_gate")
    qualification = gate.get("control_qualification") if isinstance(gate, dict) else None
    run_ids = qualification.get("rehearsal_run_ids") if isinstance(qualification, dict) else None
    report_hashes = (
        qualification.get("rehearsal_report_sha256") if isinstance(qualification, dict) else None
    )
    if (
        report.get("run_kind") != "final"
        or report.get("human_review_gate") is not None
        or not isinstance(gate, dict)
        or gate.get("kind") != "automated-frozen-input-integrity-gate"
        or gate.get("ready") is not True
        or gate.get("ctkat_commit") != report.get("ctkat_commit")
        or gate.get("plan_id") != "ctkat-paper-native-v10-single-host"
        or gate.get("physical_host_count") != 1
        or gate.get("independent_human_review") is not False
        or gate.get("cross_host_reproducibility") is not False
        or not isinstance(qualification, dict)
        or qualification.get("kind") != "two-clean-control-rehearsal-qualification"
        or qualification.get("ready") is not True
        or qualification.get("profile_id") != "ctkat-paper-control-rehearsal-v3"
        or not isinstance(qualification.get("sha256"), str)
        or SHA256_RE.fullmatch(qualification["sha256"]) is None
        or not isinstance(qualification.get("profile_sha256"), str)
        or SHA256_RE.fullmatch(qualification["profile_sha256"]) is None
        or not isinstance(qualification.get("calibration_sha256"), str)
        or SHA256_RE.fullmatch(qualification["calibration_sha256"]) is None
        or not isinstance(run_ids, list)
        or len(run_ids) != 2
        or len(set(run_ids)) != 2
        or any(
            not isinstance(run_id, str) or not re.fullmatch(r"[0-9a-f]{32}", run_id)
            for run_id in run_ids
        )
        or not isinstance(report_hashes, dict)
        or len(report_hashes) != 2
        or any(
            not isinstance(value, str) or SHA256_RE.fullmatch(value) is None
            for value in report_hashes.values()
        )
    ):
        raise BundleError(f"{label}: single-host final gate is missing or malformed")
    return qualification


def _verify_preserved_qualification(
    host_root: Path,
    qualification: dict[str, Any],
    *,
    commit: str,
) -> None:
    path_value = qualification.get("path")
    if not isinstance(path_value, str):
        raise BundleError("control qualification path is missing")
    qualification_candidate = Path(path_value)
    if not qualification_candidate.is_absolute():
        qualification_candidate = ROOT / qualification_candidate
    qualification_path = qualification_candidate.resolve()
    if (
        qualification_candidate.is_symlink()
        or not qualification_path.is_file()
        or not qualification_path.is_relative_to(host_root)
        or _sha256(qualification_path) != qualification.get("sha256")
    ):
        raise BundleError("control qualification is not preserved inside the host tree")
    source = _read_json(qualification_path, "control qualification")
    records = source.get("rehearsals")
    if (
        source.get("schema_version") != "3.0"
        or source.get("kind") != "ctkat-v10-final-control-qualification"
        or source.get("candidate_commit") != commit
        or source.get("profile_id") != qualification.get("profile_id")
        or source.get("profile_sha256") != qualification.get("profile_sha256")
        or source.get("calibration_sha256") != qualification.get("calibration_sha256")
        or source.get("rehearsal_run_ids") != qualification.get("rehearsal_run_ids")
        or source.get("required_clean_runs") != 2
        or source.get("observed_clean_runs") != 2
        or source.get("final_launch_ready") is not True
        or source.get("errors") != []
        or not isinstance(records, list)
        or len(records) != 2
    ):
        raise BundleError("preserved control qualification content drift")
    expected_reports = qualification.get("rehearsal_report_sha256")
    assert isinstance(expected_reports, dict)
    observed_reports: dict[str, str] = {}
    observed_run_ids: set[str] = set()
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise BundleError(f"control qualification rehearsal[{index}] is malformed")
        report_value = record.get("path")
        if not isinstance(report_value, str) or not Path(report_value).is_absolute():
            raise BundleError(f"control qualification rehearsal[{index}] path is invalid")
        report_candidate = Path(report_value)
        report_path = report_candidate.resolve()
        report_sha = record.get("sha256")
        if (
            report_candidate.is_symlink()
            or not report_path.is_file()
            or not report_path.is_relative_to(host_root)
            or not isinstance(report_sha, str)
            or _sha256(report_path) != report_sha
        ):
            raise BundleError(
                f"control qualification rehearsal[{index}] is not preserved inside the host tree"
            )
        observed_reports[str(report_path)] = report_sha
        observed_run_ids.add(str(record.get("run_id")))
    if observed_reports != expected_reports or observed_run_ids != set(
        qualification["rehearsal_run_ids"]
    ):
        raise BundleError("control qualification rehearsal provenance drift")


def build_bundle(
    host_root: Path,
    output: Path,
    *,
    host_id: str,
    analysis_output: Path,
) -> dict[str, Any]:
    host_root = host_root.resolve()
    output = output.resolve()
    bundle_root = output.parent
    analysis_output = analysis_output.resolve()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", host_id):
        raise BundleError("host id contains unsafe characters")
    if host_root.is_symlink() or not host_root.is_dir():
        raise BundleError("host root must be a regular directory")
    if not host_root.is_relative_to(bundle_root) or host_root == bundle_root:
        raise BundleError("host root must be a proper child of the bundle directory")
    if not analysis_output.is_relative_to(bundle_root) or analysis_output.is_relative_to(host_root):
        raise BundleError("analysis output must stay in the bundle root and outside the host tree")
    if output.exists() and (output.is_symlink() or not output.is_file()):
        raise BundleError("bundle output path is not a regular file")

    component_paths: dict[str, Path] = {}
    commit: str | None = None
    cpu_model: str | None = None
    machine_id: str | None = None
    qualification_fingerprint: str | None = None
    control_qualification: dict[str, Any] | None = None
    run_ids: set[str] = set()
    for component, dirname in COMPONENT_DIRS.items():
        component_root = host_root / dirname
        report = _read_json(
            component_root / "campaign_report.json",
            f"{component} campaign report",
        )
        current_qualification = _gate_ok(report, label=component)
        current_fingerprint = json.dumps(
            current_qualification,
            sort_keys=True,
            separators=(",", ":"),
        )
        if qualification_fingerprint is None:
            qualification_fingerprint = current_fingerprint
            control_qualification = current_qualification
        elif current_fingerprint != qualification_fingerprint:
            raise BundleError(f"{component}: final control qualification differs between results")
        if (
            report.get("schema_version") != "2.0"
            or report.get("kind") != "native-timing-campaign-report"
            or report.get("status") != "complete"
            or report.get("paper_promotion_ready") is not True
        ):
            raise BundleError(f"{component}: campaign is not complete and promotion-ready")
        current_commit = report.get("ctkat_commit")
        run_id = report.get("run_id")
        preflight = report.get("host_preflight")
        environment = preflight.get("environment") if isinstance(preflight, dict) else None
        virtualization = preflight.get("virtualization") if isinstance(preflight, dict) else None
        if not isinstance(current_commit, str) or not COMMIT_RE.fullmatch(current_commit):
            raise BundleError(f"{component}: malformed measurement commit")
        if commit is None:
            commit = current_commit
        elif current_commit != commit:
            raise BundleError(f"{component}: measurement commit differs between components")
        if (
            not isinstance(run_id, str)
            or not re.fullmatch(r"[0-9a-f]{32}", run_id)
            or run_id in run_ids
        ):
            raise BundleError(f"{component}: run id is malformed or reused")
        run_ids.add(run_id)
        if (
            not isinstance(preflight, dict)
            or preflight.get("paper_eligible") is not True
            or not isinstance(environment, dict)
            or not isinstance(virtualization, dict)
            or virtualization.get("vm")
            or virtualization.get("container")
        ):
            raise BundleError(f"{component}: physical host preflight is invalid")
        current_cpu = environment.get("cpu_model")
        current_machine = environment.get("machine_id_sha256")
        if not isinstance(current_cpu, str) or not current_cpu:
            raise BundleError(f"{component}: CPU model is missing")
        if not isinstance(current_machine, str) or not SHA256_RE.fullmatch(current_machine):
            raise BundleError(f"{component}: machine identity is missing")
        if cpu_model is None:
            cpu_model = current_cpu
            machine_id = current_machine
        elif current_cpu != cpu_model or current_machine != machine_id:
            raise BundleError(f"{component}: host identity differs between components")
        component_paths[component] = component_root

    assert commit is not None and cpu_model is not None and machine_id is not None
    baseline_paths: dict[str, Path] = {}
    for tool_id in BASELINE_TOOLS:
        report_path = _one_report(host_root, tool_id)
        report = _read_json(report_path, f"{tool_id} baseline report")
        current_qualification = _gate_ok(report, label=tool_id)
        current_fingerprint = json.dumps(
            current_qualification,
            sort_keys=True,
            separators=(",", ":"),
        )
        if current_fingerprint != qualification_fingerprint:
            raise BundleError(f"{tool_id}: final control qualification differs between results")
        baseline_host = report.get("host")
        run_id = report.get("run_id")
        if (
            report.get("schema_version") != "2.0"
            or report.get("kind") != "ctkat-same-corpus-baseline"
            or report.get("tool_id") != tool_id
            or report.get("ctkat_commit") != commit
            or report.get("git_dirty") is not False
            or report.get("promotion_ready") is not True
            or not isinstance(baseline_host, dict)
            or baseline_host.get("cpu_model") != cpu_model
            or baseline_host.get("machine_id_sha256") != machine_id
            or not isinstance(run_id, str)
            or not re.fullmatch(r"[0-9a-f]{32}", run_id)
            or run_id in run_ids
        ):
            raise BundleError(f"{tool_id}: baseline is not a matching final result")
        run_ids.add(run_id)
        baseline_paths[tool_id] = report_path

    assert control_qualification is not None
    _verify_preserved_qualification(
        host_root,
        control_qualification,
        commit=commit,
    )

    asm_candidates = sorted((host_root / "asm-evidence").glob("**/asm_evidence_bundle.json"))
    if len(asm_candidates) != 1:
        raise BundleError(
            f"assembly evidence: expected exactly one bundle, found {len(asm_candidates)}"
        )
    asm_path = asm_candidates[0]
    asm = _read_json(asm_path, "ML-KEM assembly evidence")
    if (
        asm.get("kind") != "ctkat-asm-evidence-bundle"
        or asm.get("paper_eligible") is not True
        or (asm.get("source_revision") or {}).get("commit") != commit
    ):
        raise BundleError("ML-KEM assembly evidence is not eligible at the measurement commit")

    hash_manifest = host_root / "SHA256SUMS"
    hash_manifest.write_text(
        build_manifest(host_root, exclude=hash_manifest),
        encoding="utf-8",
    )
    manifest_sha = hashlib.sha256(hash_manifest.read_bytes()).hexdigest()
    bundle = {
        "schema_version": 5,
        "evidence_scope": "single-physical-host",
        "bundle_id": f"ctkat-v10-{commit[:12]}-{manifest_sha[:12]}",
        "measurement_commit": commit,
        "verification_commit": commit,
        "hosts": [
            {
                "id": host_id,
                "cpu_model": cpu_model,
                "physical": True,
                "virtualization_detected": False,
                "artifact_root": _relative(bundle_root, host_root, "host root"),
                "hash_manifest": _relative(bundle_root, hash_manifest, "host hash manifest"),
                "components": {
                    key: _relative(bundle_root, path, f"{key} root")
                    for key, path in sorted(component_paths.items())
                },
                "same_corpus_results": {
                    key: _relative(bundle_root, path, f"{key} baseline")
                    for key, path in sorted(baseline_paths.items())
                },
            }
        ],
        "assembly_evidence": {
            "mlkem_public_attribution": {
                "host_id": host_id,
                "bundle": _relative(bundle_root, asm_path, "assembly evidence"),
            }
        },
        "analysis": {
            "scope": "named-single-host",
            "output_root": _relative(bundle_root, analysis_output, "analysis output"),
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(yaml.safe_dump(bundle, sort_keys=False), encoding="utf-8")
    return bundle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--host-id", required=True)
    parser.add_argument("--analysis-output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        bundle = build_bundle(
            args.host_root,
            args.output,
            host_id=args.host_id,
            analysis_output=args.analysis_output,
        )
    except (BundleError, OSError, ValueError, yaml.YAMLError) as exc:
        print(f"[single-host-bundle] ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"[single-host-bundle] wrote {args.output.resolve()}")
    print(f"[single-host-bundle] bundle_id={bundle['bundle_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
