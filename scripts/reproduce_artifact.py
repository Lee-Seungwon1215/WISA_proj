#!/usr/bin/env python3
"""Reproduce premeasurement, verification-candidate, and paper-ready gates."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.hash_artifacts import build_manifest  # noqa: E402

COMPONENTS = {
    "committed-corpus-refresh": "docs/measurement/native_timing_v3_campaign.yaml",
    "kyberslash-contrast": "docs/measurement/kyberslash_native_v3.yaml",
    "falcon-contrast": "docs/measurement/falcon_native_v2.yaml",
    "diverse-lineages": "docs/measurement/diverse_native_v2.yaml",
}
SAME_CORPUS_TOOLS = ("official_dudect", "timecop", "microwalk_pin")
MEASUREMENT_CRITICAL_PATHS = (
    "ctkat",
    "scripts",
    "examples",
    "docs/measurement",
    "docs/baselines",
    "docs/ground_truth",
    "pyproject.toml",
    "uv.lock",
)
POST_VERIFICATION_ALLOWED_PATH = "docs/reviews/paper/native-promotion-v2.yaml"
FINAL_EVIDENCE_MANIFEST = "final_evidence_manifest.json"
NAMED_ANALYSIS_FILES = frozenset(
    {
        "paper_native_analysis.json",
        "paper_native_axis_results.csv",
        "paper_native_pairwise_contrasts.csv",
        "paper_native_signature_length.csv",
        "paper_native_analysis.md",
    }
)
BLINDED_ANALYSIS_FILES = frozenset({*NAMED_ANALYSIS_FILES, "analysis_manifest.json"})


def _python(script: str, *args: str) -> list[str]:
    return [sys.executable, str(ROOT / script), *args]


def premeasurement_commands() -> list[list[str]]:
    commands = [
        [sys.executable, "-m", "pytest", "-q"],
        _python("scripts/check_corpus.py"),
        _python("scripts/check_corpus_correctness.py", "--verify-snapshot"),
        _python("scripts/migrate_evidence_v1_to_v2.py", "--check"),
        _python("scripts/render_readme_corpus.py", "--check"),
        _python("scripts/check_third_party.py"),
        _python("scripts/check_example_configs.py"),
        _python("scripts/check_asm_evidence.py", "--static"),
        _python("scripts/check_kyberslash_ground_truth.py", "--static-only"),
        _python("scripts/check_falcon_comparators.py", "--static-only"),
        _python("scripts/check_diverse_upstreams.py"),
        _python("scripts/run_same_corpus_baselines.py", "--check"),
    ]
    for manifest in COMPONENTS.values():
        commands.append(
            _python(
                "scripts/run_native_timing_campaign.py",
                "--manifest",
                manifest,
                "--check",
            )
        )
    commands.extend(
        [
            _python("scripts/check_paper_campaign.py"),
            _python("scripts/check_automated_audits.py"),
            _python("scripts/check_paper_reviews.py"),
            _python("scripts/run_ablation.py", "--check"),
            _python("scripts/build_paper_artifacts.py", "--check"),
        ]
    )
    return commands


def engineering_ready_commands() -> list[list[str]]:
    """Run static preparation plus non-human automated audit dispositions."""
    return [
        *premeasurement_commands(),
        ["uv", "lock", "--check"],
        [sys.executable, "-m", "ruff", "check", "ctkat", "scripts", "tests"],
        [
            sys.executable,
            "-m",
            "ruff",
            "format",
            "--check",
            "ctkat",
            "scripts",
            "tests",
        ],
        [sys.executable, "-m", "mypy", "ctkat"],
        _python("scripts/check_automated_audits.py", "--require-engineering-ready"),
    ]


def native_engineering_ready_commands() -> list[list[str]]:
    """Add the native timing-backend calibration required on a Linux host."""
    return [
        *engineering_ready_commands(),
        _python("scripts/calibrate_timing_backend.py", "--check"),
    ]


def measurement_ready_commands() -> list[list[str]]:
    """Run static preparation plus the human premeasurement-review quorum gate."""
    return [
        *native_engineering_ready_commands(),
        _python("scripts/check_paper_reviews.py", "--require-pre-measurement"),
    ]


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout.strip()


def _require_review_only_descendant(verification_commit: str, current_commit: str) -> None:
    try:
        _git("cat-file", "-e", f"{verification_commit}^{{commit}}")
        _git("merge-base", "--is-ancestor", verification_commit, current_commit)
    except subprocess.CalledProcessError as exc:
        raise ValueError(
            "paper-ready HEAD must descend from the candidate verification commit"
        ) from exc
    changed_paths = _git(
        "diff",
        "--name-only",
        f"{verification_commit}..{current_commit}",
    )
    unexpected = sorted(
        path
        for path in changed_paths.splitlines()
        if path and path != POST_VERIFICATION_ALLOWED_PATH
    )
    if unexpected:
        raise ValueError(
            "paper-ready descendant changed files outside the sole review packet: "
            + ", ".join(unexpected)
        )


def _source_manifest() -> dict[str, Any]:
    listed = _git("ls-files").splitlines()
    files: list[dict[str, str]] = []
    for value in listed:
        path = ROOT / value
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"tracked source entry is not a regular file: {value}")
        files.append(
            {
                "path": value,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    return {"algorithm": "sha256", "tracked_files": files}


def _canonical_json(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def final_evidence_root_sha256(manifest: Mapping[str, Any]) -> str:
    """Return the canonical digest, excluding the digest field itself."""

    payload = {key: value for key, value in manifest.items() if key != "final_evidence_root_sha256"}
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _final_evidence_record(path: Path, *, role: str, logical_path: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"final evidence must be a regular file: {logical_path}")
    content = path.read_bytes()
    return {
        "logical_path": logical_path,
        "role": role,
        "bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def _analysis_evidence_records(
    root: Path,
    *,
    expected_names: frozenset[str],
    role: str,
    logical_prefix: str,
) -> list[dict[str, Any]]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"{role} root must be a regular directory")
    entries = list(root.iterdir())
    actual_names = {entry.name for entry in entries}
    if actual_names != expected_names or any(
        entry.is_symlink() or not entry.is_file() for entry in entries
    ):
        raise ValueError(
            f"{role} file set drift: expected={sorted(expected_names)}, "
            f"actual={sorted(actual_names)}"
        )
    return [
        _final_evidence_record(
            root / name,
            role=role,
            logical_path=f"{logical_prefix}/{name}",
        )
        for name in sorted(expected_names)
    ]


def build_final_evidence_manifest(
    bundle_path: Path,
    bundle_report: Mapping[str, Any],
    named_analysis_root: Path,
) -> dict[str, Any]:
    """Bind all reviewable final inputs/outputs without machine-local paths."""

    bundle_id = bundle_report.get("bundle_id")
    measurement_commit = bundle_report.get("measurement_commit")
    verification_commit = bundle_report.get("verification_commit")
    if not isinstance(bundle_id, str) or not bundle_id:
        raise ValueError("validated bundle has no bundle_id")
    for label, value in (
        ("measurement_commit", measurement_commit),
        ("verification_commit", verification_commit),
    ):
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
            raise ValueError(f"validated bundle has no valid {label}")

    records = [
        _final_evidence_record(
            bundle_path,
            role="measurement-bundle",
            logical_path="measurement_bundle.yaml",
        )
    ]
    hosts = bundle_report.get("hosts")
    if not isinstance(hosts, list) or len(hosts) != 2:
        raise ValueError("validated bundle report must contain exactly two hosts")
    if any(not isinstance(host, Mapping) for host in hosts):
        raise ValueError("validated host record is malformed")
    host_ids = [host.get("id") for host in hosts]
    if any(not isinstance(host_id, str) or not host_id for host_id in host_ids) or len(
        set(host_ids)
    ) != len(host_ids):
        raise ValueError("validated host ids are malformed or duplicated")
    for index, host in enumerate(sorted(hosts, key=lambda item: str(item["id"]))):
        host_manifest = host.get("hash_manifest")
        if not isinstance(host_manifest, str):
            raise ValueError("validated host record has no hash manifest")
        records.append(
            _final_evidence_record(
                Path(host_manifest),
                role="host-tree-hash-manifest",
                logical_path=f"host-manifests/{index:02d}/SHA256SUMS",
            )
        )

    assembly = bundle_report.get("assembly_evidence")
    mlkem_assembly = (
        assembly.get("mlkem_public_attribution") if isinstance(assembly, Mapping) else None
    )
    if not isinstance(mlkem_assembly, Mapping) or not isinstance(mlkem_assembly.get("bundle"), str):
        raise ValueError("validated bundle report has no ML-KEM assembly evidence")
    records.append(
        _final_evidence_record(
            Path(str(mlkem_assembly["bundle"])),
            role="assembly-evidence-bundle",
            logical_path="assembly/mlkem_public_attribution.json",
        )
    )

    unblinding_record = bundle_report.get("unblinding_record")
    blinded_analysis_root = bundle_report.get("blinded_analysis_root")
    if not isinstance(unblinding_record, str) or not isinstance(blinded_analysis_root, str):
        raise ValueError("validated bundle report has no frozen blinding evidence")
    records.append(
        _final_evidence_record(
            Path(unblinding_record),
            role="unblinding-record",
            logical_path="unblinding/record.yaml",
        )
    )
    records.extend(
        _analysis_evidence_records(
            Path(blinded_analysis_root),
            expected_names=BLINDED_ANALYSIS_FILES,
            role="blinded-analysis-output",
            logical_prefix="blinded-analysis",
        )
    )
    records.extend(
        _analysis_evidence_records(
            named_analysis_root,
            expected_names=NAMED_ANALYSIS_FILES,
            role="named-analysis-output",
            logical_prefix="named-analysis",
        )
    )
    records.sort(key=lambda item: (item["logical_path"], item["role"]))
    logical_paths = [str(item["logical_path"]) for item in records]
    if len(logical_paths) != len(set(logical_paths)):
        raise ValueError("final evidence logical paths are not unique")
    manifest: dict[str, Any] = {
        "schema_version": "1.0",
        "kind": "ctkat-final-evidence-root",
        "algorithm": "sha256",
        "bundle_id": bundle_id,
        "measurement_commit": measurement_commit,
        "verification_commit": verification_commit,
        "artifact_count": len(records),
        "artifacts": records,
    }
    manifest["final_evidence_root_sha256"] = final_evidence_root_sha256(manifest)
    return manifest


def _render_final_evidence_manifest(manifest: Mapping[str, Any]) -> bytes:
    return (json.dumps(manifest, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")


def write_final_evidence_manifest(path: Path, manifest: Mapping[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError(f"final evidence manifest already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(_render_final_evidence_manifest(manifest))
    temporary.replace(path)


def verify_final_evidence_manifest(
    candidate_root: Path,
    bundle_path: Path,
    bundle_report: Mapping[str, Any],
) -> dict[str, Any]:
    if candidate_root.is_symlink() or not candidate_root.is_dir():
        raise ValueError("candidate root must be a regular directory")
    path = candidate_root / FINAL_EVIDENCE_MANIFEST
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"candidate root has no {FINAL_EVIDENCE_MANIFEST}")
    try:
        recorded = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"final evidence manifest is not valid JSON: {exc}") from exc
    if not isinstance(recorded, dict):
        raise ValueError("final evidence manifest must be an object")
    expected = build_final_evidence_manifest(
        bundle_path,
        bundle_report,
        candidate_root / "named-analysis",
    )
    if recorded != expected or path.read_bytes() != _render_final_evidence_manifest(expected):
        raise ValueError("final evidence manifest or bound artifact bytes drifted")
    recorded_root = recorded.get("final_evidence_root_sha256")
    if (
        not isinstance(recorded_root, str)
        or not re.fullmatch(r"[0-9a-f]{64}", recorded_root)
        or recorded_root != final_evidence_root_sha256(recorded)
    ):
        raise ValueError("final evidence root digest mismatch")
    return expected


def _bundle_path(bundle_root: Path, value: Any, label: str, *, directory: bool) -> Path:
    if not isinstance(value, str) or not value or value.startswith("replace"):
        raise ValueError(f"{label} is still a template placeholder")
    raw = Path(value)
    if raw.is_absolute():
        raise ValueError(f"{label} must be relative to the bundle manifest")
    candidate = bundle_root / raw
    lexical_root = bundle_root.resolve()
    if candidate.is_symlink() or any(
        parent.is_symlink()
        for parent in candidate.parents
        if parent != lexical_root and parent.is_relative_to(lexical_root)
    ):
        raise ValueError(f"{label} path contains a symlink")
    path = candidate.resolve()
    try:
        path.relative_to(bundle_root.resolve())
    except ValueError as exc:
        raise ValueError(f"{label} escapes the bundle root") from exc
    if directory and not path.is_dir():
        raise ValueError(f"{label} directory is missing: {value}")
    if not directory and not path.is_file():
        raise ValueError(f"{label} file is missing: {value}")
    return path


def validate_bundle(
    bundle_path: Path, verification_commit: str
) -> tuple[dict[str, Any], list[list[str]]]:
    bundle_path = bundle_path.resolve()
    raw = yaml.safe_load(bundle_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("schema_version") != 4:
        raise ValueError("measurement bundle must be a schema-v4 mapping")
    measurement_commit = raw.get("measurement_commit")
    if not isinstance(measurement_commit, str) or not re.fullmatch(
        r"[0-9a-f]{40}", measurement_commit
    ):
        raise ValueError("measurement bundle has no valid measurement commit")
    if raw.get("verification_commit") != verification_commit or not re.fullmatch(
        r"[0-9a-f]{40}", verification_commit
    ):
        raise ValueError("measurement bundle verification commit differs from current HEAD")
    try:
        _git("cat-file", "-e", f"{measurement_commit}^{{commit}}")
    except subprocess.CalledProcessError as exc:
        raise ValueError("measurement commit is unavailable in this repository") from exc
    critical_drift = _git(
        "diff",
        "--name-only",
        f"{measurement_commit}..{verification_commit}",
        "--",
        *MEASUREMENT_CRITICAL_PATHS,
    )
    if critical_drift:
        raise ValueError(
            "measurement-critical source changed after measurement: "
            + ", ".join(critical_drift.splitlines())
        )
    expected_commit = measurement_commit
    hosts = raw.get("hosts")
    if not isinstance(hosts, list) or len(hosts) != 2:
        raise ValueError("measurement bundle requires exactly two hosts")
    ids: set[str] = set()
    cpu_models: set[str] = set()
    for index, host in enumerate(hosts):
        if not isinstance(host, dict):
            raise ValueError(f"hosts[{index}] must be a mapping")
        host_id = host.get("id")
        cpu = host.get("cpu_model")
        if not isinstance(host_id, str) or not host_id or host_id in ids:
            raise ValueError("host ids must be non-empty and unique")
        if not isinstance(cpu, str) or not cpu or cpu.startswith("replace") or cpu in cpu_models:
            raise ValueError("host CPU models must be exact, non-placeholder, and distinct")
        ids.add(host_id)
        cpu_models.add(cpu)
        if host.get("physical") is not True or host.get("virtualization_detected") is not False:
            raise ValueError(f"{host_id}: final evidence requires a physical non-virtualized host")

    commands: list[list[str]] = []
    bundle_root = bundle_path.parent
    records: list[dict[str, Any]] = []
    seen_host_roots: list[Path] = []
    seen_artifacts: set[Path] = set()
    seen_run_ids: set[str] = set()
    observed_cpu_models: set[str] = set()
    observed_machine_ids: set[str] = set()
    observed_compilers: set[tuple[str, str]] = set()
    expected_label_pairs: set[tuple[str, str]] = set()
    reference_label_pairs: set[tuple[str, str]] | None = None
    host_manifest_hashes: dict[str, str] = {}
    for host in hosts:
        assert isinstance(host, dict)
        host_id = host.get("id")
        cpu = host.get("cpu_model")
        assert isinstance(host_id, str)
        assert isinstance(cpu, str)
        host_label_pairs: set[tuple[str, str]] = set()
        host_root = _bundle_path(
            bundle_root,
            host.get("artifact_root"),
            f"{host_id}.artifact_root",
            directory=True,
        )
        if any(
            host_root == previous
            or host_root.is_relative_to(previous)
            or previous.is_relative_to(host_root)
            for previous in seen_host_roots
        ):
            raise ValueError(f"{host_id}: host artifact roots must be distinct and non-overlapping")
        seen_host_roots.append(host_root)
        hash_manifest = _bundle_path(
            bundle_root,
            host.get("hash_manifest"),
            f"{host_id}.hash_manifest",
            directory=False,
        )
        if not hash_manifest.is_relative_to(host_root):
            raise ValueError(f"{host_id}: hash manifest must live inside the host artifact root")
        expected_hashes = build_manifest(host_root, exclude=hash_manifest)
        if hash_manifest.read_text(encoding="utf-8") != expected_hashes:
            raise ValueError(f"{host_id}: host SHA-256 manifest mismatch")
        host_manifest_hashes[host_id] = hashlib.sha256(hash_manifest.read_bytes()).hexdigest()

        component_paths = host.get("components")
        if not isinstance(component_paths, dict) or set(component_paths) != set(COMPONENTS):
            raise ValueError(f"{host_id}: component set drift")
        resolved: dict[str, str] = {}
        for component, manifest in COMPONENTS.items():
            artifact_root = _bundle_path(
                bundle_root,
                component_paths[component],
                f"{host_id}.{component}",
                directory=True,
            )
            if not artifact_root.is_relative_to(host_root):
                raise ValueError(f"{host_id}.{component}: artifact escapes host root")
            if artifact_root in seen_artifacts:
                raise ValueError(f"{host_id}.{component}: artifact path is reused")
            seen_artifacts.add(artifact_root)
            report_path = artifact_root / "campaign_report.json"
            if report_path.is_symlink() or not report_path.is_file():
                raise ValueError(f"{host_id}.{component}: campaign report is missing")
            try:
                campaign_report = json.loads(report_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ValueError(
                    f"{host_id}.{component}: campaign report unreadable: {exc}"
                ) from exc
            if not isinstance(campaign_report, dict):
                raise ValueError(f"{host_id}.{component}: campaign report must be an object")
            if campaign_report.get("ctkat_commit") != expected_commit:
                raise ValueError(f"{host_id}.{component}: CT-KAT commit mismatch")
            if (
                campaign_report.get("schema_version") != "2.0"
                or campaign_report.get("run_kind") != "final"
                or campaign_report.get("status") != "complete"
                or campaign_report.get("paper_promotion_ready") is not True
            ):
                raise ValueError(f"{host_id}.{component}: campaign is not complete")
            selected_targets = campaign_report.get("selected_targets")
            if not isinstance(selected_targets, list) or any(
                not isinstance(value, str) or not value for value in selected_targets
            ):
                raise ValueError(f"{host_id}.{component}: selected target index is malformed")
            host_label_pairs.update((component, value) for value in selected_targets)
            run_id = campaign_report.get("run_id")
            if (
                not isinstance(run_id, str)
                or not re.fullmatch(r"[0-9a-f]{32}", run_id)
                or run_id in seen_run_ids
            ):
                raise ValueError(f"{host_id}.{component}: run id is missing or reused")
            seen_run_ids.add(run_id)
            human_gate = campaign_report.get("human_review_gate")
            if (
                not isinstance(human_gate, dict)
                or human_gate.get("kind") != "human-premeasurement-review-gate"
                or human_gate.get("ready") is not True
            ):
                raise ValueError(f"{host_id}.{component}: human review gate is missing")
            preflight = campaign_report.get("host_preflight")
            if not isinstance(preflight, dict) or preflight.get("paper_eligible") is not True:
                raise ValueError(f"{host_id}.{component}: paper-eligible preflight is missing")
            environment = preflight.get("environment")
            virtualization = preflight.get("virtualization")
            if not isinstance(environment, dict) or not isinstance(virtualization, dict):
                raise ValueError(f"{host_id}.{component}: host identity metadata is malformed")
            actual_cpu = environment.get("cpu_model")
            machine_id = environment.get("machine_id_sha256")
            boot_id = environment.get("boot_id_sha256")
            if actual_cpu != cpu:
                raise ValueError(
                    f"{host_id}.{component}: declared CPU model differs from preflight"
                )
            if not isinstance(machine_id, str) or not re.fullmatch(r"[0-9a-f]{64}", machine_id):
                raise ValueError(f"{host_id}.{component}: physical host identity is missing")
            if not isinstance(boot_id, str) or not re.fullmatch(r"[0-9a-f]{64}", boot_id):
                raise ValueError(f"{host_id}.{component}: boot identity is missing")
            if virtualization.get("vm") or virtualization.get("container"):
                raise ValueError(f"{host_id}.{component}: virtualization detected in preflight")
            compiler_version = preflight.get("compiler")
            compiler_executable = preflight.get("compiler_executable")
            if (
                not isinstance(compiler_version, str)
                or not compiler_version
                or not isinstance(compiler_executable, dict)
                or not isinstance(compiler_executable.get("sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", compiler_executable.get("sha256", ""))
            ):
                raise ValueError(
                    f"{host_id}.{component}: compiler executable provenance is missing"
                )
            observed_compilers.add((compiler_version, str(compiler_executable["sha256"])))
            observed_cpu_models.add(actual_cpu)
            observed_machine_ids.add(machine_id)
            resolved[component] = str(artifact_root)
            commands.append(
                _python(
                    "scripts/run_native_timing_campaign.py",
                    "--manifest",
                    manifest,
                    "--validate-run",
                    str(artifact_root),
                    "--expected-commit",
                    expected_commit,
                    "--expected-run-kind",
                    "final",
                )
            )
        if reference_label_pairs is None:
            reference_label_pairs = host_label_pairs
        elif host_label_pairs != reference_label_pairs:
            raise ValueError(f"{host_id}: measured target set differs between hosts")
        expected_label_pairs.update(host_label_pairs)
        baseline_paths = host.get("same_corpus_results")
        if not isinstance(baseline_paths, dict) or set(baseline_paths) != set(SAME_CORPUS_TOOLS):
            raise ValueError(f"{host_id}: same-corpus result set must cover all three tools")
        baseline_machine_ids: set[str] = set()
        resolved_baselines: dict[str, str] = {}
        for tool_id in SAME_CORPUS_TOOLS:
            baseline = _bundle_path(
                bundle_root,
                baseline_paths[tool_id],
                f"{host_id}.same_corpus_results.{tool_id}",
                directory=False,
            )
            if not baseline.is_relative_to(host_root):
                raise ValueError(f"{host_id}.{tool_id}: same-corpus result escapes host root")
            if baseline in seen_artifacts:
                raise ValueError(f"{host_id}.{tool_id}: same-corpus artifact path is reused")
            seen_artifacts.add(baseline)
            try:
                baseline_report = json.loads(baseline.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ValueError(f"{host_id}.{tool_id}: result unreadable: {exc}") from exc
            if not isinstance(baseline_report, dict):
                raise ValueError(f"{host_id}.{tool_id}: result must be an object")
            baseline_host = baseline_report.get("host")
            expected_timing = tool_id == "official_dudect"
            if (
                baseline_report.get("schema_version") != "2.0"
                or baseline_report.get("tool_id") != tool_id
                or baseline_report.get("run_kind") != "final"
                or baseline_report.get("promotion_ready") is not True
                or baseline_report.get("ctkat_commit") != expected_commit
                or baseline_report.get("git_dirty") is not False
                or not isinstance(baseline_host, dict)
                or baseline_host.get("timing_evidence") is not expected_timing
            ):
                raise ValueError(f"{host_id}.{tool_id}: result is not final eligible evidence")
            baseline_run_id = baseline_report.get("run_id")
            if (
                not isinstance(baseline_run_id, str)
                or not re.fullmatch(r"[0-9a-f]{32}", baseline_run_id)
                or baseline_run_id in seen_run_ids
            ):
                raise ValueError(f"{host_id}.{tool_id}: run id is missing or reused")
            seen_run_ids.add(baseline_run_id)
            baseline_gate = baseline_report.get("human_review_gate")
            if (
                not isinstance(baseline_gate, dict)
                or baseline_gate.get("kind") != "human-premeasurement-review-gate"
                or baseline_gate.get("ready") is not True
            ):
                raise ValueError(f"{host_id}.{tool_id}: human review gate is missing")
            if baseline_host.get("cpu_model") != cpu:
                raise ValueError(f"{host_id}.{tool_id}: CPU model mismatch")
            baseline_machine_id = baseline_host.get("machine_id_sha256")
            if not isinstance(baseline_machine_id, str) or not re.fullmatch(
                r"[0-9a-f]{64}", baseline_machine_id
            ):
                raise ValueError(f"{host_id}.{tool_id}: physical host identity is missing")
            baseline_machine_ids.add(baseline_machine_id)
            resolved_baselines[tool_id] = str(baseline)
            commands.append(
                _python(
                    "scripts/run_same_corpus_baselines.py",
                    "--validate-result",
                    str(baseline),
                    "--expected-commit",
                    expected_commit,
                    "--expected-run-kind",
                    "final",
                )
            )
        component_machine_ids = {
            json.loads((Path(path) / "campaign_report.json").read_text(encoding="utf-8"))[
                "host_preflight"
            ]["environment"]["machine_id_sha256"]
            for path in resolved.values()
        }
        if len(baseline_machine_ids) != 1 or component_machine_ids != baseline_machine_ids:
            raise ValueError(f"{host_id}: component and same-corpus host identities differ")
        baseline_machine_id = next(iter(baseline_machine_ids))
        records.append(
            {
                "id": host_id,
                "cpu_model": cpu,
                "machine_id_sha256": baseline_machine_id,
                "artifact_root": str(host_root),
                "hash_manifest": str(hash_manifest),
                "components": resolved,
                "same_corpus_results": resolved_baselines,
            }
        )
    if len(observed_cpu_models) != 2:
        raise ValueError("final evidence requires two observed distinct CPU models")
    if len(observed_machine_ids) != 2:
        raise ValueError("final evidence requires two observed distinct physical host identities")
    if len(observed_compilers) != 1:
        raise ValueError(
            "final evidence requires the exact same GCC version and executable hash "
            "on both hosts and every component"
        )
    assembly = raw.get("assembly_evidence")
    if not isinstance(assembly, dict) or set(assembly) != {"mlkem_public_attribution"}:
        raise ValueError("assembly_evidence must contain the frozen ML-KEM attribution bundle")
    mlkem_assembly = assembly["mlkem_public_attribution"]
    if not isinstance(mlkem_assembly, dict) or set(mlkem_assembly) != {"host_id", "bundle"}:
        raise ValueError("ML-KEM assembly evidence entry field set drift")
    assembly_host_id = mlkem_assembly.get("host_id")
    host_roots = {record["id"]: Path(record["artifact_root"]) for record in records}
    if assembly_host_id not in host_roots:
        raise ValueError("ML-KEM assembly evidence references an unknown host")
    assembly_bundle = _bundle_path(
        bundle_root,
        mlkem_assembly.get("bundle"),
        "assembly_evidence.mlkem_public_attribution.bundle",
        directory=False,
    )
    if not assembly_bundle.is_relative_to(host_roots[str(assembly_host_id)]):
        raise ValueError("ML-KEM assembly evidence must live inside its recorded host root")
    if assembly_bundle in seen_artifacts:
        raise ValueError("ML-KEM assembly evidence path is reused")
    seen_artifacts.add(assembly_bundle)
    try:
        assembly_payload = json.loads(assembly_bundle.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"ML-KEM assembly evidence is unreadable: {exc}") from exc
    if (
        not isinstance(assembly_payload, dict)
        or assembly_payload.get("kind") != "ctkat-asm-evidence-bundle"
        or assembly_payload.get("paper_eligible") is not True
        or (assembly_payload.get("source_revision") or {}).get("commit") != measurement_commit
    ):
        raise ValueError("ML-KEM assembly evidence identity/commit/eligibility mismatch")
    commands.append(
        _python(
            "scripts/check_asm_evidence.py",
            "--bundle",
            str(assembly_bundle),
            "--no-current-commit",
            "--expected-commit",
            measurement_commit,
        )
    )
    assembly_record = {
        "mlkem_public_attribution": {
            "host_id": assembly_host_id,
            "bundle": str(assembly_bundle),
            "sha256": hashlib.sha256(assembly_bundle.read_bytes()).hexdigest(),
        }
    }
    blind = raw.get("blind_rerun")
    if not isinstance(blind, dict) or set(blind) != {
        "scope",
        "operator_did_not_see_other_host_results",
        "analyst_did_not_access_raw_named_artifacts_before_unblinding",
        "blinded_analysis_root",
        "blinded_analysis_manifest",
        "unblinding_record",
    }:
        raise ValueError("blind_rerun must be a mapping")
    if blind.get("scope") != "result-analyst-label-blinding":
        raise ValueError("blind_rerun scope must honestly describe result-analyst blinding")
    for key in (
        "operator_did_not_see_other_host_results",
        "analyst_did_not_access_raw_named_artifacts_before_unblinding",
    ):
        if blind.get(key) is not True:
            raise ValueError(f"blind_rerun.{key} must be true")
    blinded_analysis_root = _bundle_path(
        bundle_root,
        blind.get("blinded_analysis_root"),
        "blind_rerun.blinded_analysis_root",
        directory=True,
    )
    blinded_analysis_manifest = _bundle_path(
        bundle_root,
        blind.get("blinded_analysis_manifest"),
        "blind_rerun.blinded_analysis_manifest",
        directory=False,
    )
    if not blinded_analysis_manifest.is_relative_to(blinded_analysis_root):
        raise ValueError("blinded analysis manifest must live inside its output root")
    unblinding_path = _bundle_path(
        bundle_root,
        blind.get("unblinding_record"),
        "blind_rerun.unblinding_record",
        directory=False,
    )
    try:
        unblinding = yaml.safe_load(unblinding_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"unblinding record is unreadable: {exc}") from exc
    required_unblinding = {
        "schema_version",
        "kind",
        "bundle_id",
        "scope",
        "custodian_id",
        "analyst_id",
        "blinded_at",
        "blinded_analysis_completed_at",
        "blinded_analysis_manifest_sha256",
        "unblinded_at",
        "label_map",
        "host_transfers",
        "attestations",
    }
    if not isinstance(unblinding, dict) or set(unblinding) != required_unblinding:
        raise ValueError("unblinding record field set drift")
    if (
        unblinding.get("schema_version") != "1.0"
        or unblinding.get("kind") != "ctkat-analysis-unblinding-record"
        or unblinding.get("bundle_id") != raw.get("bundle_id")
        or unblinding.get("scope") != blind.get("scope")
    ):
        raise ValueError("unblinding record identity mismatch")
    custodian_id = unblinding.get("custodian_id")
    analyst_id = unblinding.get("analyst_id")
    if (
        not isinstance(custodian_id, str)
        or not custodian_id.strip()
        or not isinstance(analyst_id, str)
        or not analyst_id.strip()
        or custodian_id == analyst_id
    ):
        raise ValueError("unblinding custodian and analyst must be distinct named identities")

    def parse_timestamp(value: Any, label: str) -> datetime:
        if not isinstance(value, str):
            raise ValueError(f"{label} must be an ISO-8601 timestamp")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
        if parsed.tzinfo is None:
            raise ValueError(f"{label} must include a timezone")
        return parsed

    blinded_at = parse_timestamp(unblinding.get("blinded_at"), "blinded_at")
    analysis_completed_at = parse_timestamp(
        unblinding.get("blinded_analysis_completed_at"),
        "blinded_analysis_completed_at",
    )
    unblinded_at = parse_timestamp(unblinding.get("unblinded_at"), "unblinded_at")
    if not blinded_at <= analysis_completed_at < unblinded_at:
        raise ValueError("blinded analysis must complete after blinding and before unblinding")
    blinded_analysis_manifest_sha256 = unblinding.get("blinded_analysis_manifest_sha256")
    if not isinstance(blinded_analysis_manifest_sha256, str) or not re.fullmatch(
        r"[0-9a-f]{64}", blinded_analysis_manifest_sha256
    ):
        raise ValueError("blinded analysis manifest hash is malformed")
    if hashlib.sha256(blinded_analysis_manifest.read_bytes()).hexdigest() != (
        blinded_analysis_manifest_sha256
    ):
        raise ValueError("blinded analysis manifest hash mismatch")
    label_map = unblinding.get("label_map")
    if not isinstance(label_map, list) or not label_map:
        raise ValueError("unblinding label_map must be non-empty")
    observed_pairs: set[tuple[str, str]] = set()
    opaque_labels: set[str] = set()
    for index, item in enumerate(label_map):
        if not isinstance(item, dict) or set(item) != {"opaque_label", "component", "target"}:
            raise ValueError(f"unblinding label_map[{index}] is malformed")
        opaque = item.get("opaque_label")
        pair = (item.get("component"), item.get("target"))
        if (
            not isinstance(opaque, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}", opaque)
            or opaque in opaque_labels
            or not all(isinstance(value, str) and value for value in pair)
        ):
            raise ValueError(f"unblinding label_map[{index}] has invalid/duplicate values")
        opaque_labels.add(opaque)
        observed_pairs.add((str(pair[0]), str(pair[1])))
    if observed_pairs != expected_label_pairs or len(label_map) != len(expected_label_pairs):
        raise ValueError("unblinding label_map does not exactly cover the measured targets")
    transfers = unblinding.get("host_transfers")
    if not isinstance(transfers, list) or len(transfers) != 2:
        raise ValueError("unblinding record requires exactly two host transfers")
    transfer_ids: set[str] = set()
    for index, transfer in enumerate(transfers):
        if not isinstance(transfer, dict) or set(transfer) != {
            "host_id",
            "hash_manifest_sha256",
            "received_at",
            "verified",
        }:
            raise ValueError(f"host_transfers[{index}] is malformed")
        transfer_id = transfer.get("host_id")
        received_at = parse_timestamp(transfer.get("received_at"), f"host_transfers[{index}]")
        if (
            transfer_id not in host_manifest_hashes
            or transfer_id in transfer_ids
            or transfer.get("hash_manifest_sha256") != host_manifest_hashes.get(transfer_id)
            or transfer.get("verified") is not True
            or not blinded_at <= received_at < unblinded_at
        ):
            raise ValueError(f"host_transfers[{index}] identity/hash/time verification failed")
        transfer_ids.add(str(transfer_id))
    attestations = unblinding.get("attestations")
    required_attestations = {
        "custodian_created_opaque_labels_before_analysis",
        "analyst_saw_only_opaque_labels_before_unblinding",
        "unblinding_happened_after_frozen_analysis_completed",
    }
    if (
        not isinstance(attestations, dict)
        or set(attestations) != required_attestations
        or any(attestations.get(key) is not True for key in required_attestations)
    ):
        raise ValueError("unblinding attestations are incomplete")
    return {
        "bundle_id": raw.get("bundle_id"),
        "measurement_commit": measurement_commit,
        "verification_commit": verification_commit,
        "hosts": records,
        "assembly_evidence": assembly_record,
        "blinded_analysis_root": str(blinded_analysis_root),
        "blinded_analysis_manifest": str(blinded_analysis_manifest),
        "unblinding_record": str(unblinding_path),
    }, commands


def _run_commands(commands: list[list[str]], report_path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for index, command in enumerate(commands, start=1):
        display = " ".join(command)
        print(f"[artifact] [{index}/{len(commands)}] {display}", flush=True)
        result = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        record = {
            "command": command,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
        records.append(record)
        report_path.write_text(
            json.dumps(records, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        if result.returncode != 0:
            print(result.stdout[-4000:], file=sys.stderr)
            print(result.stderr[-8000:], file=sys.stderr)
            raise RuntimeError(f"artifact command failed ({result.returncode}): {display}")
    return records


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--profile",
        choices=(
            "premeasurement",
            "engineering-ready",
            "native-engineering-ready",
            "measurement-ready",
            "verification",
            "paper-ready",
            "final",
        ),
        required=True,
    )
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument(
        "--candidate-root",
        type=Path,
        help="verification-profile output reviewed by the post-measurement packet",
    )
    args = parser.parse_args()
    output = (args.output_root or ROOT / "artifact_runs" / args.profile).resolve()
    try:
        if output.exists() and any(output.iterdir()):
            raise ValueError(f"output root must be absent or empty: {output}")
        output.mkdir(parents=True, exist_ok=True)
        commit = _git("rev-parse", "HEAD")
        dirty = bool(_git("status", "--porcelain"))
        if dirty:
            raise ValueError(f"--profile {args.profile} requires a clean committed worktree")
        bundle_report: dict[str, Any] | None = None
        final_evidence: dict[str, Any] | None = None
        candidate_root: Path | None = None
        if args.profile == "measurement-ready":
            commands = measurement_ready_commands()
        elif args.profile == "native-engineering-ready":
            commands = native_engineering_ready_commands()
        elif args.profile == "engineering-ready":
            commands = engineering_ready_commands()
        elif args.profile in {"verification", "paper-ready", "final"}:
            commands = measurement_ready_commands()
        else:
            commands = premeasurement_commands()
        if args.profile in {"verification", "paper-ready", "final"}:
            if args.bundle is None:
                raise ValueError(f"--profile {args.profile} requires --bundle")
            if args.bundle.is_symlink() or not args.bundle.is_file():
                raise ValueError("--bundle must be a regular file, not a symlink")
            bundle_path = args.bundle.resolve()
            candidate_verification_commit: str
            if args.profile == "verification":
                candidate_verification_commit = commit
            else:
                raw_bundle = yaml.safe_load(bundle_path.read_text(encoding="utf-8"))
                recorded_verification_commit = (
                    raw_bundle.get("verification_commit") if isinstance(raw_bundle, dict) else None
                )
                if not isinstance(recorded_verification_commit, str) or not re.fullmatch(
                    r"[0-9a-f]{40}", recorded_verification_commit
                ):
                    raise ValueError("bundle has no valid candidate verification commit")
                candidate_verification_commit = recorded_verification_commit
                _require_review_only_descendant(candidate_verification_commit, commit)
            bundle_report, final_commands = validate_bundle(
                bundle_path,
                candidate_verification_commit,
            )
            commands.extend(final_commands)
            if args.profile == "verification":
                if args.candidate_root is not None:
                    raise ValueError("--profile verification writes its own candidate root")
                commands.append(
                    _python(
                        "scripts/analyze_paper_native_results.py",
                        "--bundle",
                        str(bundle_path),
                        "--verification-commit",
                        candidate_verification_commit,
                        "--output-root",
                        str(output / "named-analysis"),
                        "--output-mode",
                        "unblinded",
                    )
                )
            else:
                if args.candidate_root is None:
                    raise ValueError(
                        f"--profile {args.profile} requires --candidate-root from verification"
                    )
                if args.candidate_root.is_symlink():
                    raise ValueError("--candidate-root cannot be a symlink")
                candidate_root = args.candidate_root.resolve()
                if (
                    output == candidate_root
                    or output.is_relative_to(candidate_root)
                    or candidate_root.is_relative_to(output)
                ):
                    raise ValueError("paper-ready output and candidate roots must not overlap")
                final_evidence = verify_final_evidence_manifest(
                    candidate_root,
                    bundle_path,
                    bundle_report,
                )
                commands.append(
                    _python(
                        "scripts/analyze_paper_native_results.py",
                        "--bundle",
                        str(bundle_path),
                        "--verification-commit",
                        candidate_verification_commit,
                        "--output-root",
                        str(candidate_root / "named-analysis"),
                        "--output-mode",
                        "unblinded",
                        "--check-output",
                        "--allow-review-only-descendant",
                    )
                )
                commands.append(
                    _python(
                        "scripts/check_paper_reviews.py",
                        "--require-complete",
                        "--expected-final-evidence-root-sha256",
                        str(final_evidence["final_evidence_root_sha256"]),
                    )
                )
        report_path = output / "command_report.json"
        records = _run_commands(commands, report_path)
        if args.profile == "verification":
            assert args.bundle is not None
            bundle_report, _ = validate_bundle(
                args.bundle.resolve(),
                candidate_verification_commit,
            )
            final_evidence = build_final_evidence_manifest(
                args.bundle.resolve(),
                bundle_report,
                output / "named-analysis",
            )
            write_final_evidence_manifest(
                output / FINAL_EVIDENCE_MANIFEST,
                final_evidence,
            )
        elif args.profile in {"paper-ready", "final"}:
            assert candidate_root is not None
            assert args.bundle is not None
            bundle_report, _ = validate_bundle(
                args.bundle.resolve(),
                candidate_verification_commit,
            )
            final_evidence = verify_final_evidence_manifest(
                candidate_root,
                args.bundle.resolve(),
                bundle_report,
            )
        source = _source_manifest()
        source.update(
            {
                "profile": args.profile,
                "ctkat_commit": commit,
                "worktree_dirty": dirty,
                "python": sys.version,
                "platform": sys.platform,
                "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "bundle": bundle_report,
                "candidate_root": str(candidate_root) if candidate_root is not None else None,
                "final_evidence_root_sha256": (
                    final_evidence.get("final_evidence_root_sha256")
                    if final_evidence is not None
                    else None
                ),
                "command_count": len(records),
            }
        )
        (output / "source_manifest.json").write_text(
            json.dumps(source, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        checksum_path = output / "SHA256SUMS"
        checksum_path.write_text(build_manifest(output, exclude=checksum_path), encoding="utf-8")
    except (
        OSError,
        ValueError,
        RuntimeError,
        subprocess.CalledProcessError,
        yaml.YAMLError,
    ) as exc:
        print(f"[artifact] ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"[artifact] OK: {args.profile} bundle at {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
