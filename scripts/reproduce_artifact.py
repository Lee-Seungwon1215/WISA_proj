#!/usr/bin/env python3
"""One-command premeasurement and final paper-artifact gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.hash_artifacts import build_manifest  # noqa: E402

COMPONENTS = {
    "committed-corpus-refresh": "docs/measurement/native_timing_v2_campaign.yaml",
    "kyberslash-contrast": "docs/measurement/kyberslash_native_v1.yaml",
    "falcon-contrast": "docs/measurement/falcon_native_v1.yaml",
    "diverse-lineages": "docs/measurement/diverse_native_v1.yaml",
}


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
            _python("scripts/check_paper_reviews.py"),
            _python("scripts/run_ablation.py", "--check"),
            _python("scripts/build_paper_artifacts.py", "--check"),
        ]
    )
    return commands


def measurement_ready_commands() -> list[list[str]]:
    """Run static preparation plus the human premeasurement-review quorum gate."""
    return [
        *premeasurement_commands(),
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


def _source_manifest() -> dict[str, Any]:
    listed = _git("ls-files").splitlines()
    files: list[dict[str, str]] = []
    for value in listed:
        path = ROOT / value
        if not path.is_file() or path.is_symlink():
            continue
        files.append(
            {
                "path": value,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    return {"algorithm": "sha256", "tracked_files": files}


def _bundle_path(bundle_root: Path, value: Any, label: str, *, directory: bool) -> Path:
    if not isinstance(value, str) or not value or value.startswith("replace"):
        raise ValueError(f"{label} is still a template placeholder")
    raw = Path(value)
    if raw.is_absolute():
        raise ValueError(f"{label} must be relative to the bundle manifest")
    path = (bundle_root / raw).resolve()
    try:
        path.relative_to(bundle_root.resolve())
    except ValueError as exc:
        raise ValueError(f"{label} escapes the bundle root") from exc
    if path.is_symlink():
        raise ValueError(f"{label} must not be a symlink")
    if directory and not path.is_dir():
        raise ValueError(f"{label} directory is missing: {value}")
    if not directory and not path.is_file():
        raise ValueError(f"{label} file is missing: {value}")
    return path


def validate_bundle(
    bundle_path: Path, expected_commit: str
) -> tuple[dict[str, Any], list[list[str]]]:
    bundle_path = bundle_path.resolve()
    raw = yaml.safe_load(bundle_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        raise ValueError("measurement bundle must be a schema-v1 mapping")
    if raw.get("ctkat_commit") != expected_commit or not re.fullmatch(
        r"[0-9a-f]{40}", expected_commit
    ):
        raise ValueError("measurement bundle commit does not match the current 40-hex HEAD")
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
    for host in hosts:
        assert isinstance(host, dict)
        host_id = host.get("id")
        cpu = host.get("cpu_model")
        assert isinstance(host_id, str)
        assert isinstance(cpu, str)
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
            resolved[component] = str(artifact_root)
            commands.append(
                _python(
                    "scripts/run_native_timing_campaign.py",
                    "--manifest",
                    manifest,
                    "--validate-run",
                    str(artifact_root),
                )
            )
        baseline = _bundle_path(
            bundle_root,
            host.get("same_corpus_result"),
            f"{host_id}.same_corpus_result",
            directory=False,
        )
        commands.append(
            _python("scripts/run_same_corpus_baselines.py", "--validate-result", str(baseline))
        )
        records.append(
            {
                "id": host_id,
                "cpu_model": cpu,
                "components": resolved,
                "same_corpus_result": str(baseline),
            }
        )
    blind = raw.get("blind_rerun")
    if not isinstance(blind, dict):
        raise ValueError("blind_rerun must be a mapping")
    for key in (
        "operator_did_not_see_other_host_results",
        "target_labels_blinded_during_execution",
    ):
        if blind.get(key) is not True:
            raise ValueError(f"blind_rerun.{key} must be true")
    _bundle_path(
        bundle_root,
        blind.get("unblinding_record"),
        "blind_rerun.unblinding_record",
        directory=False,
    )
    return {"bundle_id": raw.get("bundle_id"), "hosts": records}, commands


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
        choices=("premeasurement", "measurement-ready", "final"),
        required=True,
    )
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()
    output = (args.output_root or ROOT / "artifact_runs" / args.profile).resolve()
    try:
        if output.exists() and any(output.iterdir()):
            raise ValueError(f"output root must be absent or empty: {output}")
        output.mkdir(parents=True, exist_ok=True)
        commit = _git("rev-parse", "HEAD")
        dirty = bool(_git("status", "--porcelain"))
        if dirty and not args.allow_dirty:
            raise ValueError(
                "worktree is dirty; commit/freeze it or pass --allow-dirty for development only"
            )
        bundle_report: dict[str, Any] | None = None
        commands = (
            measurement_ready_commands()
            if args.profile == "measurement-ready"
            else premeasurement_commands()
        )
        if args.profile == "final":
            if args.bundle is None:
                raise ValueError("--profile final requires --bundle")
            bundle_report, final_commands = validate_bundle(args.bundle, commit)
            commands.extend(final_commands)
            commands.append(_python("scripts/check_paper_reviews.py", "--require-complete"))
        report_path = output / "command_report.json"
        records = _run_commands(commands, report_path)
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
