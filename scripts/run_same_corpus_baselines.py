#!/usr/bin/env python3
"""Validate, probe, and run the frozen same-corpus baseline adapters."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import platform
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ctkat.cli import _do_dudect, _emit_dudect_report, _template_context  # noqa: E402
from ctkat.config import load_config  # noqa: E402
from ctkat.ct_runner import classify_valgrind_run  # noqa: E402
from ctkat.harness_generator import compile_harness, render_harness  # noqa: E402
from ctkat.official_dudect import OFFICIAL_DUDECT_REVISION  # noqa: E402
from ctkat.official_dudect_verify import (  # noqa: E402
    OfficialDudectProtocolContract,
    verify_official_dudect_artifacts,
)
from ctkat.qemu_detect import detect_qemu_emulation  # noqa: E402
from ctkat.timing_environment import collect_timing_environment  # noqa: E402
from ctkat.valgrind_parser import Finding, FindingType, parse_valgrind_log_with_stats  # noqa: E402
from ctkat.valgrind_runner import ValgrindResult  # noqa: E402
from scripts.run_kyberslash_timecop import CANARY_SOURCE, _find_backend  # noqa: E402
from scripts.run_native_timing_campaign import (  # noqa: E402
    CampaignError,
    _detect_virtualization,
    _git_state,
    _human_premeasurement_gate,
    _single_host_premeasurement_gate,
    _validate_human_premeasurement_gate,
    _validate_single_host_premeasurement_gate,
    pin_current_process,
)

DEFAULT_MANIFEST = ROOT / "docs/baselines/same_corpus_v1.yaml"
DEFAULT_SCHEMA = ROOT / "docs/baselines/baseline-result-v1.schema.json"
DEFAULT_MATRIX = ROOT / "docs/baselines/same_corpus_v1_matrix.csv"
DEFAULT_EXPANSION_PLAN = ROOT / "docs/corpus/independent_upstreams_v1.yaml"
DEFAULT_OUTPUT_ROOT = ROOT / "measurement_runs/same_corpus_baselines"

CASE_ORDER = ("toy-kem-ct-leaky", "toy-kem-ct-safe")
TOOL_ORDER = ("official_dudect", "timecop", "microwalk_pin")
EXECUTION_STATUSES = {"not-run", "completed", "crash", "timeout", "error"}
OUTCOMES = {"finding", "no-finding", "inconclusive", "not-run"}
CAPABILITIES = {"supported", "unsupported"}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
IMAGE_RE = re.compile(r"^ghcr\.io/microwalk-project/microwalk@sha256:([0-9a-f]{64})$")
MICROWALK_PEAK_RE = re.compile(r"Maximum private memory size: ([0-9]+) bytes")
MICROWALK_MARKERS = (
    "PinNotifyTestcaseStart",
    "PinNotifyTestcaseEnd",
    "PinNotifyStackPointer",
    "PinNotifyAllocation",
)
RUN_KINDS = ("engineering", "pilot", "final")


class BaselineError(RuntimeError):
    """A fail-closed manifest, adapter, or result error."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _repo_path(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise BaselineError(f"{label} must be a non-empty repository-relative path")
    path = (ROOT / value).resolve()
    try:
        path.relative_to(ROOT)
    except ValueError as exc:
        raise BaselineError(f"{label} escapes the repository: {value!r}") from exc
    return path


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BaselineError(f"{label} must be a mapping")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise BaselineError(f"{label} must be a list")
    return value


def _logical_loc(path: Path) -> int:
    count = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith(("#", "/*", "*", "*/", "//")):
            count += 1
    return count


def _tree_bytes(path: Path) -> int:
    if not path.exists():
        return 0
    if path.is_file():
        return path.stat().st_size
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def _make_artifact_readable(path: Path) -> None:
    """Preserve executable bits while allowing a host-side artifact upload."""
    path.chmod(path.stat().st_mode | 0o444)


def _subprocess_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _peak_child_kib() -> int:
    # Linux reports KiB; every executable adapter is Linux-gated.
    return max(0, int(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss))


def _testcase_payloads() -> list[bytes]:
    payloads: list[bytes] = []
    for index in range(16):
        payload = bytearray((index * 29 + offset * 17) & 0xFF for offset in range(32))
        payload[0] = 0x20 + index // 2 if index % 2 == 0 else 0xA0 + index // 2
        payloads.append(bytes(payload))
    return payloads


def _ordered_payload_sha256() -> str:
    return hashlib.sha256(b"".join(_testcase_payloads())).hexdigest()


def _read_yaml(path: Path, label: str) -> dict[str, Any]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise BaselineError(f"{label} unreadable: {path}: {exc}") from exc
    return _mapping(value, label)


def load_manifest(path: Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    return _read_yaml(path.resolve(), "baseline manifest")


def _case_map(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(_list(manifest.get("cases"), "cases")):
        case = _mapping(value, f"cases[{index}]")
        case_id = case.get("id")
        if not isinstance(case_id, str) or case_id in result:
            raise BaselineError(f"cases[{index}].id is missing or duplicated")
        result[case_id] = case
    return result


def _coverage_map(manifest: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for index, value in enumerate(_list(manifest.get("coverage"), "coverage")):
        row = _mapping(value, f"coverage[{index}]")
        key = (str(row.get("case_id", "")), str(row.get("tool_id", "")))
        if key in result:
            raise BaselineError(f"duplicate coverage row: {key}")
        result[key] = row
    return result


def _tool_locs(manifest: dict[str, Any], tool_id: str) -> tuple[int, int]:
    tools = _mapping(manifest.get("tools"), "tools")
    tool = _mapping(tools.get(tool_id), f"tools.{tool_id}")
    adapter = _mapping(tool.get("adapter"), f"tools.{tool_id}.adapter")

    def total(field: str) -> int:
        paths = _list(adapter.get(field), f"tools.{tool_id}.adapter.{field}")
        return sum(_logical_loc(_repo_path(value, f"{tool_id}.{field}")) for value in paths)

    return total("configuration_files"), total("implementation_files")


def render_matrix(manifest: dict[str, Any]) -> str:
    tools = _mapping(manifest.get("tools"), "tools")
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(
        [
            "case_id",
            "tool_id",
            "support",
            "expected_outcome",
            "evidence_gate",
            "threat_model",
            "observable",
        ]
    )
    coverage = _coverage_map(manifest)
    for case_id in CASE_ORDER:
        for tool_id in TOOL_ORDER:
            row = coverage[(case_id, tool_id)]
            tool = _mapping(tools[tool_id], f"tools.{tool_id}")
            writer.writerow(
                [
                    case_id,
                    tool_id,
                    row["support"],
                    row["expected_outcome"],
                    row["evidence_gate"],
                    tool["threat_model"],
                    tool["observable"],
                ]
            )
    return output.getvalue()


def validate_static(
    manifest: dict[str, Any],
    *,
    manifest_path: Path = DEFAULT_MANIFEST,
) -> list[str]:
    errors: list[str] = []

    def check(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    check(manifest.get("schema_version") == "1.0", "schema_version must be '1.0'")
    check(
        manifest.get("suite_id") == "ctkat-same-corpus-baseline-v1",
        "suite_id mismatch",
    )
    contract = _mapping(manifest.get("comparison_contract"), "comparison_contract")
    check(contract.get("aggregate_accuracy") == "forbidden", "aggregate accuracy must be forbidden")

    snapshot = _mapping(manifest.get("source_snapshot"), "source_snapshot")
    for label in ("config", "header", "implementation"):
        entry = _mapping(snapshot.get(label), f"source_snapshot.{label}")
        path = _repo_path(entry.get("path"), f"source_snapshot.{label}.path")
        expected = entry.get("sha256")
        check(path.is_file(), f"{label} file missing: {path}")
        check(
            isinstance(expected, str) and SHA256_RE.fullmatch(expected) is not None,
            f"{label} sha256 malformed",
        )
        if path.is_file() and isinstance(expected, str):
            check(_sha256(path) == expected, f"{label} sha256 drift: {path.relative_to(ROOT)}")

    protocol = _mapping(manifest.get("testcase_protocol"), "testcase_protocol")
    check(protocol.get("count") == 16, "testcase count must be 16")
    check(protocol.get("bytes_per_testcase") == 32, "testcase width must be 32")
    check(
        protocol.get("ordered_payload_sha256") == _ordered_payload_sha256(),
        "testcase payload hash drift",
    )

    cases = _case_map(manifest)
    check(tuple(cases) == CASE_ORDER, f"case order/set must be {CASE_ORDER}")
    check(cases.get(CASE_ORDER[0], {}).get("harness") == "leaky", "leaky case mismatch")
    check(cases.get(CASE_ORDER[1], {}).get("harness") == "safe", "safe case mismatch")

    tools = _mapping(manifest.get("tools"), "tools")
    check(tuple(tools) == TOOL_ORDER, f"tool order/set must be {TOOL_ORDER}")
    dudect = _mapping(tools.get("official_dudect"), "tools.official_dudect")
    check(dudect.get("revision") == OFFICIAL_DUDECT_REVISION, "official dudect pin mismatch")
    timecop = _mapping(tools.get("timecop"), "tools.timecop")
    patch = _mapping(timecop.get("patch"), "tools.timecop.patch")
    check(
        patch.get("sha256") == _sha256(_repo_path(patch.get("path"), "timecop patch")),
        "TIMECOP patch hash mismatch",
    )
    microwalk = _mapping(tools.get("microwalk_pin"), "tools.microwalk_pin")
    check(
        isinstance(microwalk.get("documentation_revision"), str)
        and REVISION_RE.fullmatch(microwalk["documentation_revision"]) is not None,
        "MicroWalk documentation revision must be a full Git revision",
    )
    check(
        isinstance(microwalk.get("execution_image"), str)
        and IMAGE_RE.fullmatch(microwalk["execution_image"]) is not None,
        "MicroWalk execution image must use an exact sha256 digest",
    )
    check(
        microwalk.get("source_image_linkage") == "unverified-upstream-image-metadata",
        "MicroWalk source/image linkage caveat must remain explicit",
    )

    for tool_id in TOOL_ORDER:
        tool = _mapping(tools.get(tool_id), f"tools.{tool_id}")
        adapter = _mapping(tool.get("adapter"), f"tools.{tool_id}.adapter")
        adapter_paths: list[str] = []
        for field in ("configuration_files", "implementation_files"):
            for value in _list(adapter.get(field), f"{tool_id}.{field}"):
                path = _repo_path(value, f"{tool_id}.{field}")
                check(path.is_file(), f"adapter file missing: {value}")
                adapter_paths.append(value)
        hashes = _mapping(adapter.get("file_sha256"), f"tools.{tool_id}.adapter.file_sha256")
        check(set(hashes) == set(adapter_paths), f"{tool_id}: adapter hash coverage mismatch")
        for value in adapter_paths:
            expected_hash = hashes.get(value)
            check(
                isinstance(expected_hash, str) and SHA256_RE.fullmatch(expected_hash) is not None,
                f"{tool_id}: malformed adapter hash for {value}",
            )
            path = _repo_path(value, f"{tool_id}.file_sha256")
            if path.is_file() and isinstance(expected_hash, str):
                check(
                    _sha256(path) == expected_hash,
                    f"{tool_id}: adapter sha256 drift: {value}",
                )

    coverage = _coverage_map(manifest)
    expected_keys = {(case_id, tool_id) for case_id in CASE_ORDER for tool_id in TOOL_ORDER}
    check(set(coverage) == expected_keys, "coverage must be the complete case/tool product")
    for key, row in coverage.items():
        check(row.get("support") in CAPABILITIES, f"{key}: invalid support")
        check(
            row.get("expected_outcome") in {"finding", "no-finding"},
            f"{key}: invalid expected outcome",
        )
        check(bool(row.get("evidence_gate")), f"{key}: missing evidence gate")

    required_metrics = {
        "capability_status",
        "execution_status",
        "known_issue_match",
        "candidate_count",
        "reviewed_concern_count",
        "setup_seconds",
        "config_loc",
        "adapter_loc",
        "runtime_seconds",
        "peak_memory_kib",
        "artifact_bytes",
        "human_triage_minutes",
        "reviewer_agreement",
        "disposition_stability",
    }
    check(
        set(_list(manifest.get("common_metrics"), "common_metrics")) == required_metrics,
        "common metric set mismatch",
    )

    config_path = _repo_path(snapshot["config"]["path"], "source config")
    try:
        config = load_config(config_path)
    except Exception as exc:  # Pydantic provides the detailed reason.
        errors.append(f"source config does not load: {exc}")
    else:
        ct_names = [item.name for item in config.ct.harnesses] if config.ct else []
        dudect_names = [item.name for item in config.dudect.harnesses] if config.dudect else []
        check(ct_names == ["leaky", "safe"], "CT harnesses must be leaky/safe")
        check(dudect_names == ["leaky", "safe"], "dudect harnesses must be leaky/safe")
        if config.dudect:
            check(config.dudect.backend == "official-dudect", "dudect backend pin mismatch")
            check(
                all(item.leak_target == "ct" for item in config.dudect.harnesses),
                "dudect workload must vary ciphertext",
            )

    try:
        schema = json.loads(DEFAULT_SCHEMA.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"baseline result schema unreadable: {exc}")
    else:
        check(
            schema.get("properties", {}).get("schema_version", {}).get("const") == "2.0",
            "result schema version mismatch",
        )

    plan = _read_yaml(DEFAULT_EXPANSION_PLAN, "independent upstream plan")
    check(plan.get("schema_version") == "1.0", "expansion plan schema mismatch")
    rule = _mapping(plan.get("counting_rule"), "counting_rule")
    check(rule.get("unit") == "primary-upstream-lineage", "lineage counting rule mismatch")
    check(
        rule.get("parameter_sets_are_independent") is False,
        "parameter sets must not count as independent",
    )
    queue = _list(plan.get("integration_queue"), "integration_queue")
    check(
        [item.get("order") for item in queue if isinstance(item, dict)] == [1, 2, 3],
        "integration queue order mismatch",
    )
    check(
        any(
            isinstance(item, dict)
            and item.get("id") == "openssl-pqc-api"
            and item.get("counts_as_lineage") is False
            for item in queue
        ),
        "OpenSSL integration must not be counted as an implementation lineage",
    )

    try:
        committed_matrix = DEFAULT_MATRIX.read_text(encoding="utf-8")
    except OSError as exc:
        errors.append(f"committed coverage matrix unreadable: {exc}")
    else:
        check(committed_matrix == render_matrix(manifest), "committed coverage matrix drift")

    check(
        manifest_path.resolve() == DEFAULT_MANIFEST.resolve(), "only the frozen manifest is valid"
    )
    return errors


def _host(*, timing_evidence: bool) -> dict[str, Any]:
    try:
        emulated = detect_qemu_emulation()
    except OSError:
        emulated = False
    environment = collect_timing_environment(
        emulated=emulated,
        clock="rdtsc" if timing_evidence else "not-applicable",
    )
    return {
        "system": platform.system(),
        "machine": platform.machine(),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "emulated": emulated,
        "timing_evidence": timing_evidence,
        "cpu_model": environment.get("cpu_model"),
        "hostname": environment.get("hostname"),
        "machine_id_sha256": environment.get("machine_id_sha256"),
        "boot_id_sha256": environment.get("boot_id_sha256"),
        "timing_cpu_flags": environment.get("timing_cpu_flags"),
        "cpu_affinity": environment.get("cpu_affinity"),
        "governor": environment.get("governor"),
        "virtualization": _detect_virtualization(),
    }


def _capability(
    tool_id: str,
    *,
    valgrind: str = "valgrind",
    prefix: Path | None = None,
) -> tuple[str, str]:
    system = platform.system()
    machine = platform.machine()
    x86 = machine in {"x86_64", "AMD64"}
    if tool_id == "official_dudect":
        if system != "Linux" or not x86:
            return "unsupported", "selected official-dudect profile requires Linux/x86_64"
        if detect_qemu_emulation():
            return "unsupported", "emulated x86 is excluded from physical timing evidence"
        return (
            "supported",
            "Linux/x86_64 adapter available; physical controls still decide validity",
        )
    if tool_id == "timecop":
        if system != "Linux":
            return "unsupported", "patched Valgrind/TIMECOP requires Linux"
        try:
            _find_backend(valgrind, prefix)
        except (OSError, RuntimeError) as exc:
            return "unsupported", str(exc)
        return "supported", "pinned patched Valgrind executable and header found"
    if tool_id == "microwalk_pin":
        if system != "Linux" or not x86:
            return "unsupported", "selected MicroWalk PinTracer profile requires Linux/x86_64"
        if detect_qemu_emulation():
            return "unsupported", "PinTracer baseline rejects emulated x86 execution"
        if shutil.which("docker") is None:
            return "unsupported", "docker executable not found"
        return "supported", "Linux/x86_64 Docker host available for pinned PinTracer image"
    raise BaselineError(f"unknown tool: {tool_id}")


def _base_row(
    manifest: dict[str, Any],
    case_id: str,
    tool_id: str,
    capability: tuple[str, str],
) -> dict[str, Any]:
    config_loc, adapter_loc = _tool_locs(manifest, tool_id)
    return {
        "case_id": case_id,
        "tool_id": tool_id,
        "capability": {"status": capability[0], "reason": capability[1]},
        "execution_status": "not-run",
        "outcome": "not-run",
        "known_issue_match": None,
        "candidate_count": None,
        "reviewed_concern_count": None,
        "setup_seconds": None,
        "config_loc": config_loc,
        "adapter_loc": adapter_loc,
        "runtime_seconds": None,
        "peak_memory_kib": None,
        "artifact_bytes": None,
        "human_triage_minutes": None,
        "reviewer_agreement": None,
        "disposition_stability": None,
        "evidence": {},
    }


def _record(
    manifest: dict[str, Any],
    manifest_path: Path,
    tool_id: str,
    rows: list[dict[str, Any]],
    *,
    run_kind: str,
    review_gate: dict[str, Any] | None = None,
    automated_gate: dict[str, Any] | None = None,
    timing_evidence: bool,
    backend: dict[str, Any] | None = None,
    errors: list[str] | None = None,
) -> dict[str, Any]:
    actual_errors = errors or []
    commit, dirty = _git_state()
    expected = _coverage_map(manifest)
    complete = all(
        row["capability"]["status"] == "supported"
        and row["execution_status"] == "completed"
        and row["known_issue_match"] is True
        for row in rows
    )
    return {
        "schema_version": "2.0",
        "kind": "ctkat-same-corpus-baseline",
        "suite_id": manifest["suite_id"],
        "created_at": _utc_now(),
        "manifest": str(manifest_path.resolve().relative_to(ROOT)),
        "manifest_sha256": _sha256(manifest_path),
        "ctkat_commit": commit,
        "git_dirty": dirty,
        "run_id": uuid.uuid4().hex,
        "run_kind": run_kind,
        "human_review_gate": review_gate,
        "automated_premeasurement_gate": automated_gate,
        "tool_id": tool_id,
        "host": _host(timing_evidence=timing_evidence),
        "rows": rows,
        "promotion_ready": run_kind == "final"
        and complete
        and not actual_errors
        and not dirty
        and all(
            row["outcome"] == expected[(row["case_id"], row["tool_id"])]["expected_outcome"]
            for row in rows
        ),
        "errors": actual_errors,
        "backend": backend,
    }


def _checked_artifact(root: Path, relative: Path, errors: list[str]) -> Path | None:
    if relative.is_absolute() or ".." in relative.parts:
        errors.append(f"unsafe artifact path: {relative}")
        return None
    resolved_root = root.resolve()
    candidate = resolved_root / relative
    if candidate.is_symlink() or any(
        parent.is_symlink()
        for parent in candidate.parents
        if parent != resolved_root and parent.is_relative_to(resolved_root)
    ):
        errors.append(f"artifact path contains a symlink: {relative}")
        return None
    if not candidate.is_file():
        errors.append(f"artifact is missing: {relative}")
        return None
    return candidate


def _check_hash_field(
    root: Path,
    relative: Path,
    expected: Any,
    errors: list[str],
) -> Path | None:
    path = _checked_artifact(root, relative, errors)
    if path is not None and (
        not isinstance(expected, str)
        or SHA256_RE.fullmatch(expected) is None
        or _sha256(path) != expected
    ):
        errors.append(f"artifact hash mismatch: {relative}")
        return None
    return path


def _current_compiler_from_identity(
    value: Any,
    errors: list[str],
) -> tuple[Path, Path] | None:
    label = "TIMECOP compiler identity"
    required = {
        "schema_version",
        "requested",
        "invocation_path",
        "resolved_path",
        "sha256",
        "version_argv",
        "version_returncode",
        "version_stdout",
        "version_stderr",
    }
    if not isinstance(value, dict) or set(value) != required:
        errors.append(f"{label} field set is malformed")
        return None
    requested = value.get("requested")
    invocation_raw = value.get("invocation_path")
    resolved_raw = value.get("resolved_path")
    if (
        value.get("schema_version") != "1.0"
        or not isinstance(requested, str)
        or not requested
        or not isinstance(invocation_raw, str)
        or not Path(invocation_raw).is_absolute()
        or not isinstance(resolved_raw, str)
        or not Path(resolved_raw).is_absolute()
    ):
        errors.append(f"{label} paths/request are malformed")
        return None
    invocation = Path(invocation_raw).absolute()
    resolved = Path(resolved_raw).resolve()
    current = shutil.which(requested)
    if current is None or Path(current).absolute() != invocation:
        errors.append(f"{label} requested command no longer resolves to the recorded path")
    if not invocation.is_file() or invocation.resolve() != resolved or not resolved.is_file():
        errors.append(f"{label} executable path is missing or resolved differently")
        return None
    expected_hash = value.get("sha256")
    if (
        not isinstance(expected_hash, str)
        or SHA256_RE.fullmatch(expected_hash) is None
        or _sha256(resolved) != expected_hash
    ):
        errors.append(f"{label} executable hash drift")
    expected_argv = [str(resolved), "--version"]
    if value.get("version_argv") != expected_argv:
        errors.append(f"{label} version argv drift")
    try:
        version = subprocess.run(
            expected_argv,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        errors.append(f"{label} version probe failed: {exc}")
        return None
    if (
        value.get("version_returncode") != version.returncode
        or value.get("version_stdout") != version.stdout
        or value.get("version_stderr") != version.stderr
        or version.returncode != 0
    ):
        errors.append(f"{label} full version transcript drift")
    return invocation, resolved


def _fresh_timecop_reproduction_errors(
    *,
    root: Path,
    rows: list[Any],
    manifest: dict[str, Any],
    source_config: Any,
    backend: dict[str, Any],
    executable: Path,
    patched_include: Path,
) -> list[str]:
    """Rebuild and rerun final TIMECOP evidence instead of trusting its logs."""

    errors: list[str] = []
    compiler_paths = _current_compiler_from_identity(backend.get("compiler_identity"), errors)
    if compiler_paths is None:
        return errors
    compiler_invocation, compiler_resolved = compiler_paths
    if source_config.ct is None:
        return [*errors, "TIMECOP frozen config has no CT harnesses"]
    config_path = _repo_path(
        manifest["source_snapshot"]["config"]["path"],
        "source_snapshot.config",
    )
    config_dir = config_path.parent.resolve()
    configured = {harness.name: harness for harness in source_config.ct.harnesses}

    with tempfile.TemporaryDirectory(prefix="ctkat-timecop-final-") as temporary_raw:
        temporary = Path(temporary_raw)
        canary = backend.get("canary")
        if isinstance(canary, dict):
            canary_source = root / "backend_canary/canary.c"
            canary_binary = root / "backend_canary/canary"
            canary_flags = ["-std=c99", "-O2", "-g", "-fno-omit-frame-pointer", "-fno-lto"]
            expected_canary_argv = _compile_argv_contract(
                compiler=compiler_invocation,
                source=canary_source,
                binary=canary_binary,
                sources=[],
                include_dirs=[patched_include],
                cflags=canary_flags,
            )
            if canary.get("compile_argv") != expected_canary_argv:
                errors.append("TIMECOP canary compile argv differs from frozen inputs")
            fresh_canary_source = temporary / "canary.c"
            fresh_canary_binary = temporary / "canary"
            fresh_canary_log = temporary / "canary.valgrind.log"
            fresh_canary_source.write_text(CANARY_SOURCE, encoding="utf-8")
            try:
                compile_harness(
                    fresh_canary_source,
                    fresh_canary_binary,
                    [],
                    [patched_include],
                    canary_flags,
                    ROOT,
                    timeout=600,
                    cc=str(compiler_resolved),
                )
                fresh_canary, _argv, _seconds = _run_valgrind(
                    executable,
                    fresh_canary_binary,
                    fresh_canary_log,
                    timeout=600,
                )
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                errors.append(f"TIMECOP fresh canary rebuild/rerun failed: {exc}")
            else:
                fresh_classified = classify_valgrind_run(fresh_canary, fresh_canary_log)
                fresh_variable_latency = [
                    finding
                    for finding in fresh_classified.findings
                    if finding.type == FindingType.SECRET_DEPENDENT_VARIABLE_LATENCY
                ]
                fresh_passed = (
                    not fresh_canary.timed_out
                    and fresh_canary.returncode == 99
                    and fresh_classified.status == "FAIL"
                    and bool(fresh_variable_latency)
                    and "CTKAT-TIMECOP-CANARY:" in fresh_canary.stdout
                )
                if not fresh_passed:
                    errors.append("TIMECOP fresh canary did not reproduce the positive control")
                preserved_log = _checked_artifact(
                    root,
                    Path("backend_canary/canary.valgrind.log"),
                    errors,
                )
                preserved_stdout = _checked_artifact(
                    root,
                    Path("backend_canary/canary.stdout"),
                    errors,
                )
                preserved_stderr = _checked_artifact(
                    root,
                    Path("backend_canary/canary.stderr"),
                    errors,
                )
                if preserved_log is None or preserved_stdout is None or preserved_stderr is None:
                    errors.append("TIMECOP fresh canary lacks preserved raw process artifacts")
                else:
                    preserved_returncode = canary.get("returncode")
                    if isinstance(preserved_returncode, bool) or not isinstance(
                        preserved_returncode, int
                    ):
                        errors.append("TIMECOP canary returncode cannot be freshly reproduced")
                    else:
                        preserved_result = ValgrindResult(
                            returncode=preserved_returncode,
                            log_path=preserved_log,
                            stdout=preserved_stdout.read_text(encoding="utf-8", errors="replace"),
                            stderr=preserved_stderr.read_text(encoding="utf-8", errors="replace"),
                            timed_out=canary.get("timed_out") is True,
                        )
                        preserved_classified = classify_valgrind_run(
                            preserved_result,
                            preserved_log,
                        )
                        preserved_signatures = _stable_finding_signatures(
                            preserved_classified.findings
                        )
                        fresh_signatures = _stable_finding_signatures(fresh_classified.findings)
                        if canary.get("finding_signatures") != preserved_signatures:
                            errors.append(
                                "TIMECOP canary stable finding signatures mismatch raw log"
                            )
                        if fresh_signatures != preserved_signatures:
                            errors.append(
                                "TIMECOP fresh canary findings differ from preserved raw log"
                            )

        cases = _case_map(manifest)
        for row in rows:
            if not isinstance(row, dict):
                continue
            case_id = str(row.get("case_id", ""))
            case = cases.get(case_id)
            harness_name = case.get("harness") if isinstance(case, dict) else None
            harness = configured.get(str(harness_name))
            evidence = row.get("evidence")
            if harness is None or not isinstance(evidence, dict):
                errors.append(f"{case_id}: TIMECOP fresh reproduction lacks a frozen harness")
                continue
            case_root = root / case_id
            source_path = case_root / f"harness_{harness.name}.c"
            binary_path = case_root / f"harness_{harness.name}"
            expected_source = render_harness(
                harness.template or "",
                _template_context(harness, source_config.ct.seed, timecop_mode=True),
            )
            source_artifact = _check_hash_field(
                root,
                Path(case_id) / source_path.name,
                evidence.get("source_sha256"),
                errors,
            )
            if (
                source_artifact is not None
                and source_artifact.read_text(encoding="utf-8") != expected_source
            ):
                errors.append(f"{case_id}: TIMECOP preserved harness source is not reproducible")
            includes = [
                patched_include,
                *((config_dir / path).resolve() for path in harness.include_dirs),
            ]
            sources = [(config_dir / path).resolve() for path in harness.sources]
            cflags = list(harness.cflags if harness.cflags is not None else source_config.ct.cflags)
            if evidence.get("linked_sources") != _linked_source_records(sources):
                errors.append(f"{case_id}: TIMECOP tracked linked-source hashes drift")
            expected_compile_argv = _compile_argv_contract(
                compiler=compiler_invocation,
                source=source_path,
                binary=binary_path,
                sources=sources,
                include_dirs=includes,
                cflags=cflags,
            )
            if evidence.get("compile_argv") != expected_compile_argv:
                errors.append(f"{case_id}: TIMECOP compile argv differs from frozen inputs")
            if evidence.get("compile_workdir") != str(config_dir.relative_to(ROOT)):
                errors.append(f"{case_id}: TIMECOP compile workdir differs from frozen config")
            preserved_log = _checked_artifact(
                root,
                Path(case_id) / "timecop.valgrind.log",
                errors,
            )
            preserved_stdout = _checked_artifact(
                root,
                Path(case_id) / "timecop.stdout",
                errors,
            )
            preserved_stderr = _checked_artifact(
                root,
                Path(case_id) / "timecop.stderr",
                errors,
            )
            if preserved_log is None or preserved_stdout is None or preserved_stderr is None:
                errors.append(f"{case_id}: TIMECOP fresh reproduction lacks raw process files")
                continue
            preserved_returncode = evidence.get("returncode")
            if isinstance(preserved_returncode, bool) or not isinstance(preserved_returncode, int):
                errors.append(f"{case_id}: TIMECOP returncode cannot be freshly reproduced")
                continue
            preserved_result = ValgrindResult(
                returncode=preserved_returncode,
                log_path=preserved_log,
                stdout=preserved_stdout.read_text(encoding="utf-8", errors="replace"),
                stderr=preserved_stderr.read_text(encoding="utf-8", errors="replace"),
                timed_out=evidence.get("timed_out") is True,
            )
            preserved_classified = classify_valgrind_run(
                preserved_result,
                preserved_log,
                lookup_patterns=source_config.ct.lookup_function_patterns,
            )
            preserved_signatures = _stable_finding_signatures(preserved_classified.findings)
            if evidence.get("finding_signatures") != preserved_signatures:
                errors.append(f"{case_id}: TIMECOP stable finding signatures mismatch raw log")

            fresh_case = temporary / case_id
            fresh_case.mkdir()
            fresh_source = fresh_case / source_path.name
            fresh_binary = fresh_case / binary_path.name
            fresh_log = fresh_case / "timecop.valgrind.log"
            fresh_source.write_text(expected_source, encoding="utf-8")
            try:
                compile_harness(
                    fresh_source,
                    fresh_binary,
                    sources,
                    includes,
                    cflags,
                    config_dir,
                    timeout=source_config.ct.compile_timeout,
                    cc=str(compiler_resolved),
                )
                fresh_result, _argv, _seconds = _run_valgrind(
                    executable,
                    fresh_binary,
                    fresh_log,
                    timeout=source_config.ct.valgrind_timeout,
                )
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                errors.append(f"{case_id}: TIMECOP fresh rebuild/rerun failed: {exc}")
                continue
            fresh_classified = classify_valgrind_run(
                fresh_result,
                fresh_log,
                lookup_patterns=source_config.ct.lookup_function_patterns,
            )
            fresh_signatures = _stable_finding_signatures(fresh_classified.findings)
            if fresh_signatures != preserved_signatures:
                errors.append(f"{case_id}: TIMECOP fresh findings differ from preserved raw log")
            if (
                fresh_result.returncode != preserved_result.returncode
                or fresh_result.timed_out != preserved_result.timed_out
                or fresh_classified.status != preserved_classified.status
            ):
                errors.append(f"{case_id}: TIMECOP fresh process outcome differs from raw process")
            fresh_outcome = (
                "inconclusive"
                if fresh_result.timed_out or fresh_classified.status == "ERROR"
                else "finding"
                if fresh_classified.findings
                else "no-finding"
            )
            if fresh_outcome != row.get("outcome"):
                errors.append(f"{case_id}: TIMECOP fresh normalized outcome mismatch")
    return errors


def validate_result(
    value: dict[str, Any],
    manifest: dict[str, Any],
    *,
    manifest_path: Path = DEFAULT_MANIFEST,
    expected_commit: str | None = None,
    expected_run_kind: str | None = None,
    artifact_root: Path | None = None,
) -> list[str]:
    errors: list[str] = []

    def check(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    required = {
        "schema_version",
        "kind",
        "suite_id",
        "created_at",
        "manifest",
        "manifest_sha256",
        "ctkat_commit",
        "git_dirty",
        "run_id",
        "run_kind",
        "human_review_gate",
        "automated_premeasurement_gate",
        "tool_id",
        "host",
        "rows",
        "promotion_ready",
        "errors",
        "backend",
    }
    check(set(value) == required, "result top-level field set mismatch")
    check(value.get("schema_version") == "2.0", "result schema_version mismatch")
    check(value.get("kind") == "ctkat-same-corpus-baseline", "result kind mismatch")
    check(value.get("suite_id") == manifest.get("suite_id"), "result suite_id mismatch")
    created_at = value.get("created_at")
    check(isinstance(created_at, str), "created_at must be a string")
    if isinstance(created_at, str):
        try:
            parsed_created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        except ValueError:
            errors.append("created_at must be an ISO-8601 date-time")
        else:
            check(parsed_created_at.tzinfo is not None, "created_at must include a timezone")
    check(
        isinstance(value.get("manifest_sha256"), str)
        and SHA256_RE.fullmatch(value["manifest_sha256"]) is not None,
        "result manifest_sha256 malformed",
    )
    expected_manifest_path = manifest_path.resolve()
    check(
        value.get("manifest") == str(expected_manifest_path.relative_to(ROOT)),
        "result manifest path mismatch",
    )
    check(
        value.get("manifest_sha256") == _sha256(expected_manifest_path),
        "result was produced from a different manifest revision",
    )
    check(
        isinstance(value.get("ctkat_commit"), str)
        and REVISION_RE.fullmatch(value["ctkat_commit"]) is not None,
        "result ctkat_commit malformed",
    )
    if expected_commit is not None:
        check(
            value.get("ctkat_commit") == expected_commit,
            "result ctkat_commit differs from the expected frozen commit",
        )
    check(isinstance(value.get("git_dirty"), bool), "result git_dirty must be boolean")
    run_id = value.get("run_id")
    check(
        isinstance(run_id, str) and re.fullmatch(r"[0-9a-f]{32}", run_id) is not None,
        "result run_id malformed",
    )
    run_kind = value.get("run_kind")
    check(run_kind in RUN_KINDS, "result run_kind invalid")
    if expected_run_kind is not None:
        check(run_kind == expected_run_kind, "result run_kind differs from expected kind")
    review_gate = value.get("human_review_gate")
    automated_gate = value.get("automated_premeasurement_gate")
    if run_kind == "final":
        result_commit = value.get("ctkat_commit")
        if not isinstance(result_commit, str) or REVISION_RE.fullmatch(result_commit) is None:
            errors.append("final result cannot validate a malformed CT-KAT commit")
        else:
            try:
                if review_gate is not None and automated_gate is not None:
                    errors.append("final result cannot claim both human and automated gates")
                elif automated_gate is not None:
                    errors.extend(
                        _validate_single_host_premeasurement_gate(
                            automated_gate,
                            expected_commit=result_commit,
                            allow_governance_only_head=True,
                        )
                    )
                else:
                    errors.extend(
                        _validate_human_premeasurement_gate(
                            review_gate,
                            expected_commit=result_commit,
                            allow_review_only_head=True,
                        )
                    )
            except CampaignError as exc:
                errors.append(f"final result premeasurement gate is invalid: {exc}")
    else:
        check(review_gate is None, "non-final result must not claim a human review gate")
        check(
            automated_gate is None,
            "non-final result must not claim an automated premeasurement gate",
        )
    tool_id = value.get("tool_id")
    check(tool_id in {*TOOL_ORDER, "capability_probe"}, "result tool_id invalid")
    check(isinstance(value.get("promotion_ready"), bool), "promotion_ready must be boolean")
    check(
        isinstance(value.get("errors"), list)
        and all(isinstance(item, str) for item in value["errors"]),
        "errors must be strings",
    )
    check(
        value.get("backend") is None or isinstance(value.get("backend"), dict),
        "backend must be a mapping or null",
    )
    host = value.get("host")
    check(isinstance(host, dict), "host must be a mapping")
    if isinstance(host, dict):
        check(isinstance(host.get("system"), str), "host.system missing")
        check(isinstance(host.get("machine"), str), "host.machine missing")
        check(isinstance(host.get("timing_evidence"), bool), "host.timing_evidence missing")
        check(
            isinstance(host.get("cpu_model"), str) and bool(host.get("cpu_model", "").strip()),
            "host.cpu_model missing",
        )
        check(
            isinstance(host.get("machine_id_sha256"), str)
            and SHA256_RE.fullmatch(host.get("machine_id_sha256", "")) is not None,
            "host.machine_id_sha256 missing",
        )
        check(
            isinstance(host.get("boot_id_sha256"), str)
            and SHA256_RE.fullmatch(host.get("boot_id_sha256", "")) is not None,
            "host.boot_id_sha256 missing",
        )
        affinity = host.get("cpu_affinity")
        check(
            isinstance(affinity, list)
            and all(isinstance(item, int) and not isinstance(item, bool) for item in affinity),
            "host.cpu_affinity malformed",
        )
        virtualization = host.get("virtualization")
        check(
            isinstance(virtualization, dict)
            and set(virtualization) == {"vm", "container"}
            and all(isinstance(virtualization.get(key), str) for key in ("vm", "container")),
            "host.virtualization malformed",
        )

    rows = value.get("rows")
    check(isinstance(rows, list), "rows must be a list")
    if not isinstance(rows, list):
        return errors
    expected_pairs = (
        {(case_id, item) for case_id in CASE_ORDER for item in TOOL_ORDER}
        if tool_id == "capability_probe"
        else {(case_id, tool_id) for case_id in CASE_ORDER}
    )
    observed_pairs: set[tuple[Any, Any]] = set()
    expected_coverage = _coverage_map(manifest)
    row_fields = {
        "case_id",
        "tool_id",
        "capability",
        "execution_status",
        "outcome",
        "known_issue_match",
        "candidate_count",
        "reviewed_concern_count",
        "setup_seconds",
        "config_loc",
        "adapter_loc",
        "runtime_seconds",
        "peak_memory_kib",
        "artifact_bytes",
        "human_triage_minutes",
        "reviewer_agreement",
        "disposition_stability",
        "evidence",
    }
    nullable_numbers = {
        "setup_seconds",
        "runtime_seconds",
        "human_triage_minutes",
        "reviewer_agreement",
        "disposition_stability",
    }
    nullable_ints = {
        "candidate_count",
        "reviewed_concern_count",
        "peak_memory_kib",
        "artifact_bytes",
    }
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            errors.append(f"rows[{index}] must be a mapping")
            continue
        check(set(row) == row_fields, f"rows[{index}] field set mismatch")
        pair = (row.get("case_id"), row.get("tool_id"))
        observed_pairs.add(pair)
        check(pair in expected_coverage, f"rows[{index}] unknown case/tool pair")
        capability = row.get("capability")
        check(
            isinstance(capability, dict)
            and set(capability) == {"status", "reason"}
            and capability.get("status") in CAPABILITIES
            and isinstance(capability.get("reason"), str),
            f"rows[{index}] capability malformed",
        )
        check(
            row.get("execution_status") in EXECUTION_STATUSES,
            f"rows[{index}] execution_status invalid",
        )
        check(row.get("outcome") in OUTCOMES, f"rows[{index}] outcome invalid")
        known_issue_match = row.get("known_issue_match")
        check(
            known_issue_match is None or isinstance(known_issue_match, bool),
            f"rows[{index}] known_issue_match invalid",
        )
        for field in nullable_numbers:
            item = row.get(field)
            check(
                item is None
                or (isinstance(item, (int, float)) and not isinstance(item, bool) and item >= 0),
                f"rows[{index}].{field} invalid",
            )
            if field in {"reviewer_agreement", "disposition_stability"} and item is not None:
                check(item <= 1, f"rows[{index}].{field} must be in [0, 1]")
        for field in nullable_ints:
            item = row.get(field)
            check(
                item is None
                or (isinstance(item, int) and not isinstance(item, bool) and item >= 0),
                f"rows[{index}].{field} invalid",
            )
        for field in ("config_loc", "adapter_loc"):
            item = row.get(field)
            check(
                isinstance(item, int) and not isinstance(item, bool) and item >= 0,
                f"rows[{index}].{field} invalid",
            )
        check(isinstance(row.get("evidence"), dict), f"rows[{index}] evidence malformed")
        if isinstance(capability, dict) and capability.get("status") == "unsupported":
            check(
                row.get("execution_status") == "not-run",
                f"rows[{index}] unsupported execution must be not-run",
            )
            check(
                row.get("outcome") == "not-run",
                f"rows[{index}] unsupported outcome must be not-run",
            )
        if row.get("execution_status") == "completed":
            check(
                row.get("outcome") != "not-run",
                f"rows[{index}] completed row cannot have not-run outcome",
            )
        if pair in expected_coverage and known_issue_match is not None:
            check(
                known_issue_match
                == (row.get("outcome") == expected_coverage[pair]["expected_outcome"]),
                f"rows[{index}] known_issue_match disagrees with manifest expectation",
            )
    check(observed_pairs == expected_pairs, "result row coverage mismatch")
    recomputed_promotion = (
        bool(rows)
        and run_kind == "final"
        and not value.get("errors")
        and value.get("git_dirty") is False
        and all(
            isinstance(row, dict)
            and row.get("capability", {}).get("status") == "supported"
            and row.get("execution_status") == "completed"
            and row.get("known_issue_match") is True
            and (row.get("case_id"), row.get("tool_id")) in expected_coverage
            and row.get("outcome")
            == expected_coverage[(str(row.get("case_id")), str(row.get("tool_id")))][
                "expected_outcome"
            ]
            for row in rows
        )
    )
    check(
        value.get("promotion_ready") == recomputed_promotion,
        "promotion_ready disagrees with recomputed row/error state",
    )
    if tool_id == "official_dudect" and value.get("promotion_ready"):
        check(
            isinstance(host, dict) and host.get("timing_evidence") is True,
            "official dudect promotion requires physical timing evidence",
        )
        if isinstance(host, dict):
            check(
                host.get("cpu_affinity") is not None and len(host.get("cpu_affinity", [])) == 1,
                "official dudect promotion requires one pinned logical CPU",
            )
            check(
                host.get("governor") == "performance",
                "official dudect promotion requires the performance governor",
            )
            virtualization = host.get("virtualization")
            check(
                isinstance(virtualization, dict)
                and not virtualization.get("vm")
                and not virtualization.get("container"),
                "official dudect promotion requires a non-virtualized host",
            )
        if artifact_root is None:
            errors.append("official dudect promotion requires its raw artifact root")
        else:
            backend = value.get("backend")
            if not isinstance(backend, dict):
                errors.append("official dudect promotion requires backend metadata")
            else:
                raw_value = backend.get("raw_report")
                raw_sha256 = backend.get("raw_report_sha256")
                if (
                    not isinstance(raw_value, str)
                    or not raw_value
                    or Path(raw_value).is_absolute()
                    or ".." in Path(raw_value).parts
                ):
                    errors.append("official dudect raw_report path is unsafe")
                else:
                    root = artifact_root.resolve()
                    raw_path = root / raw_value
                    if raw_path.is_symlink() or any(
                        parent.is_symlink()
                        for parent in raw_path.parents
                        if parent != root and parent.is_relative_to(root)
                    ):
                        errors.append("official dudect raw_report path contains a symlink")
                    elif not raw_path.is_file():
                        errors.append("official dudect raw_report artifact is missing")
                    elif not isinstance(raw_sha256, str) or _sha256(raw_path) != raw_sha256:
                        errors.append("official dudect raw_report hash mismatch")
                    else:
                        try:
                            raw_report = json.loads(raw_path.read_text(encoding="utf-8"))
                        except (OSError, json.JSONDecodeError) as exc:
                            errors.append(f"official dudect raw_report is unreadable: {exc}")
                        else:
                            if (
                                not isinstance(raw_report, dict)
                                or raw_report.get("schema_version") != "2.0"
                                or raw_report.get("kind") != "timing-backend-report"
                            ):
                                errors.append("official dudect raw_report identity/schema mismatch")
                            if isinstance(raw_report, dict):
                                source_config = load_config(
                                    _repo_path(
                                        manifest["source_snapshot"]["config"]["path"],
                                        "source_snapshot.config",
                                    )
                                )
                                assert source_config.dudect is not None
                                frozen_dudect = source_config.dudect
                                seed_value = frozen_dudect.seed
                                if seed_value is None:
                                    raise BaselineError("frozen dudect seed is missing")
                                frozen_seed: int = seed_value
                                if raw_report.get("project") != source_config.project.name:
                                    errors.append("official dudect raw_report project mismatch")
                                if (
                                    raw_report.get("official_dudect_revision")
                                    != OFFICIAL_DUDECT_REVISION
                                ):
                                    errors.append("official dudect raw_report revision mismatch")
                                harness_index = {
                                    item.get("harness"): item
                                    for item in raw_report.get("harnesses", [])
                                    if isinstance(item, dict)
                                }
                                cases = _case_map(manifest)
                                for row in rows:
                                    if not isinstance(row, dict):
                                        continue
                                    case = cases.get(str(row.get("case_id")))
                                    harness_name = case.get("harness") if case else None
                                    raw_harness = harness_index.get(harness_name)
                                    evidence = row.get("evidence")
                                    if not isinstance(raw_harness, dict) or not isinstance(
                                        evidence, dict
                                    ):
                                        errors.append(
                                            f"official dudect raw harness missing for {row.get('case_id')}"
                                        )
                                        continue
                                    for result_field, raw_field in (
                                        ("raw_status", "raw_status"),
                                        ("timing_validity", "timing_validity"),
                                        ("abs_t_score", "abs_t_score"),
                                        ("n0", "n0"),
                                        ("n1", "n1"),
                                        ("analysis_seed", "analysis_seed"),
                                    ):
                                        if evidence.get(result_field) != raw_harness.get(raw_field):
                                            errors.append(
                                                "official dudect normalized row differs from raw "
                                                f"harness {harness_name} in {result_field}"
                                            )
                            verified_trace_paths: dict[str, Path] = {}
                            for filename, field in (
                                ("dudect_raw_timings.csv", "raw_trace_sha256"),
                                (
                                    "dudect_calibration_timings.csv",
                                    "calibration_trace_sha256",
                                ),
                                ("dudect_protocol_timings.csv", "protocol_trace_sha256"),
                            ):
                                trace_path = raw_path.parent / filename
                                expected_hash = (
                                    raw_report.get(field) if isinstance(raw_report, dict) else None
                                )
                                if trace_path.is_symlink() or not trace_path.is_file():
                                    errors.append(
                                        f"official dudect artifact is missing: {filename}"
                                    )
                                elif (
                                    not isinstance(expected_hash, str)
                                    or _sha256(trace_path) != expected_hash
                                ):
                                    errors.append(
                                        f"official dudect artifact hash mismatch: {filename}"
                                    )
                                else:
                                    verified_trace_paths[filename] = trace_path
                            required_trace_names = {
                                "dudect_raw_timings.csv",
                                "dudect_calibration_timings.csv",
                                "dudect_protocol_timings.csv",
                            }
                            if (
                                isinstance(raw_report, dict)
                                and set(verified_trace_paths) == required_trace_names
                            ):
                                expected_harnesses = {
                                    str(case["harness"]) for case in cases.values()
                                }
                                independent = verify_official_dudect_artifacts(
                                    raw_path=verified_trace_paths["dudect_raw_timings.csv"],
                                    calibration_path=verified_trace_paths[
                                        "dudect_calibration_timings.csv"
                                    ],
                                    protocol_path=verified_trace_paths[
                                        "dudect_protocol_timings.csv"
                                    ],
                                    backend_report=raw_report,
                                    expected_project=source_config.project.name,
                                    expected_harnesses=expected_harnesses,
                                    protocol_contract=OfficialDudectProtocolContract(
                                        base_seed=frozen_seed,
                                        process_repeats=(
                                            frozen_dudect.timing_protocol.process_repeats
                                        ),
                                        target_measurements=frozen_dudect.measurements,
                                        control_measurements=(
                                            frozen_dudect.timing_protocol.control_measurements
                                            or frozen_dudect.measurements
                                        ),
                                        positive_effects=tuple(
                                            frozen_dudect.timing_protocol.positive_control_effects
                                        ),
                                        aa_abs_t_limit=(
                                            frozen_dudect.timing_protocol.aa_abs_t_limit
                                        ),
                                        positive_abs_t_threshold=(
                                            frozen_dudect.timing_protocol.positive_abs_t_threshold
                                        ),
                                        aa_max_failures=(
                                            frozen_dudect.timing_protocol.aa_max_failures
                                        ),
                                        target_power=(frozen_dudect.timing_protocol.target_power),
                                        power_alpha=(frozen_dudect.timing_protocol.power_alpha),
                                        expected_randomness_policies=tuple(
                                            sorted(
                                                (harness.name, harness.randomness_policy)
                                                for harness in frozen_dudect.harnesses
                                                if harness.name in expected_harnesses
                                            )
                                        ),
                                    ),
                                )
                                errors.extend(
                                    "official dudect independent verification: " + error
                                    for error in independent.errors
                                )
                                for row in rows:
                                    if not isinstance(row, dict):
                                        continue
                                    case = cases.get(str(row.get("case_id")))
                                    harness_name = case.get("harness") if case else None
                                    analysis = independent.analyses.get(str(harness_name))
                                    trace = independent.analysis_traces.get(str(harness_name))
                                    if analysis is None or trace is None:
                                        continue
                                    if analysis.status not in {"PASS", "FAIL"}:
                                        errors.append(
                                            f"{row.get('case_id')}: independently recomputed "
                                            f"official dudect status is {analysis.status}"
                                        )
                                        continue
                                    derived_outcome = (
                                        "finding" if analysis.status == "FAIL" else "no-finding"
                                    )
                                    pair = (row.get("case_id"), "official_dudect")
                                    derived_match = (
                                        pair in expected_coverage
                                        and derived_outcome
                                        == expected_coverage[pair]["expected_outcome"]
                                    )
                                    if row.get("outcome") != derived_outcome:
                                        errors.append(
                                            f"{row.get('case_id')}: official dudect outcome "
                                            "differs from independently recomputed raw trace"
                                        )
                                    if row.get("known_issue_match") is not derived_match:
                                        errors.append(
                                            f"{row.get('case_id')}: official dudect "
                                            "known_issue_match differs from raw trace"
                                        )
                                    expected_candidates = 1 if analysis.status == "FAIL" else 0
                                    if row.get("candidate_count") != expected_candidates:
                                        errors.append(
                                            f"{row.get('case_id')}: official dudect candidate "
                                            "count differs from raw trace"
                                        )
                                    evidence = row.get("evidence")
                                    if not isinstance(evidence, dict) or evidence.get(
                                        "raw_sample_count"
                                    ) != len(trace.rows):
                                        errors.append(
                                            f"{row.get('case_id')}: official dudect raw sample "
                                            "count differs from parsed artifact"
                                        )
    if tool_id == "timecop" and value.get("promotion_ready"):
        if artifact_root is None:
            errors.append("TIMECOP promotion requires its raw artifact root")
        else:
            root = artifact_root.resolve()
            source_config = load_config(
                _repo_path(
                    manifest["source_snapshot"]["config"]["path"],
                    "source_snapshot.config",
                )
            )
            lookup_patterns = (
                source_config.ct.lookup_function_patterns if source_config.ct is not None else []
            )
            for row in rows:
                if not isinstance(row, dict):
                    continue
                case_id = str(row.get("case_id", ""))
                harness = "leaky" if case_id.endswith("leaky") else "safe"
                evidence = row.get("evidence")
                if not isinstance(evidence, dict):
                    errors.append(f"{case_id}: TIMECOP evidence is malformed")
                    continue
                case_root = Path(case_id)
                _check_hash_field(
                    root,
                    case_root / f"harness_{harness}",
                    evidence.get("binary_sha256"),
                    errors,
                )
                log_path = _check_hash_field(
                    root,
                    case_root / "timecop.valgrind.log",
                    evidence.get("log_sha256"),
                    errors,
                )
                stdout_path = _check_hash_field(
                    root,
                    case_root / "timecop.stdout",
                    evidence.get("stdout_sha256"),
                    errors,
                )
                stderr_path = _check_hash_field(
                    root,
                    case_root / "timecop.stderr",
                    evidence.get("stderr_sha256"),
                    errors,
                )
                returncode = evidence.get("returncode")
                timed_out = evidence.get("timed_out")
                if isinstance(returncode, bool) or not isinstance(returncode, int):
                    errors.append(f"{case_id}: TIMECOP returncode metadata is malformed")
                    continue
                if not isinstance(timed_out, bool):
                    errors.append(f"{case_id}: TIMECOP timeout metadata is malformed")
                    continue
                if timed_out != (returncode == 124):
                    errors.append(f"{case_id}: TIMECOP returncode/timeout metadata conflicts")
                argv = evidence.get("argv")
                if (
                    not isinstance(argv, list)
                    or not argv
                    or any(not isinstance(item, str) for item in argv)
                    or "--tool=memcheck" not in argv
                    or "--error-exitcode=99" not in argv
                    or Path(argv[-1]).name != f"harness_{harness}"
                ):
                    errors.append(f"{case_id}: TIMECOP argv metadata is malformed")
                if log_path is not None and stdout_path is not None and stderr_path is not None:
                    raw_result = ValgrindResult(
                        returncode=returncode,
                        log_path=log_path,
                        stdout=stdout_path.read_text(encoding="utf-8", errors="replace"),
                        stderr=stderr_path.read_text(encoding="utf-8", errors="replace"),
                        timed_out=timed_out,
                    )
                    classified = classify_valgrind_run(
                        raw_result,
                        log_path,
                        lookup_patterns=lookup_patterns,
                    )
                    serialized = [_serialize_finding(item) for item in classified.findings]
                    if evidence.get("findings") != serialized:
                        errors.append(f"{case_id}: TIMECOP normalized findings mismatch raw log")
                    if evidence.get("dropped_valgrind_messages") != classified.dropped:
                        errors.append(f"{case_id}: TIMECOP dropped-message count mismatch")
                    if timed_out:
                        derived_execution = "timeout"
                        derived_outcome = "inconclusive"
                        derived_count = None
                        derived_match = None
                    elif classified.status == "ERROR":
                        derived_execution = "error"
                        derived_outcome = "inconclusive"
                        derived_count = None
                        derived_match = None
                    else:
                        derived_execution = "completed"
                        derived_outcome = "finding" if classified.findings else "no-finding"
                        derived_count = len(classified.findings)
                        pair = (case_id, "timecop")
                        derived_match = (
                            pair in expected_coverage
                            and derived_outcome == expected_coverage[pair]["expected_outcome"]
                        )
                    if row.get("execution_status") != derived_execution:
                        errors.append(f"{case_id}: TIMECOP execution status mismatch raw process")
                    if row.get("outcome") != derived_outcome:
                        errors.append(f"{case_id}: TIMECOP outcome mismatch raw findings")
                    if row.get("known_issue_match") is not derived_match:
                        errors.append(f"{case_id}: TIMECOP known_issue_match mismatch raw findings")
                    if row.get("candidate_count") != derived_count:
                        errors.append(f"{case_id}: TIMECOP candidate count mismatch")
            backend = value.get("backend")
            backend_map = backend if isinstance(backend, dict) else {}
            canary = backend_map.get("canary")
            resolved_final_backend: tuple[Path, Path] | None = None
            if value.get("run_kind") == "final":
                prefix_value = backend_map.get("prefix")
                executable_value = backend_map.get("executable")
                include_value = backend_map.get("patched_include")
                if (
                    not isinstance(prefix_value, str)
                    or not Path(prefix_value).is_absolute()
                    or not isinstance(executable_value, str)
                    or not isinstance(include_value, str)
                    or not Path(executable_value)
                    .resolve()
                    .is_relative_to(Path(prefix_value).resolve())
                    or not Path(include_value)
                    .resolve()
                    .is_relative_to(Path(prefix_value).resolve())
                ):
                    errors.append(
                        "TIMECOP final result must bind executable/include to an "
                        "explicit exact-pinned prefix"
                    )
                else:
                    try:
                        current_executable, current_include = _find_backend(
                            Path(executable_value).name,
                            Path(prefix_value),
                        )
                    except (OSError, RuntimeError) as exc:
                        errors.append(f"TIMECOP final backend cannot be re-resolved: {exc}")
                    else:
                        resolved_final_backend = (current_executable, current_include)
                        if current_executable != Path(executable_value).resolve():
                            errors.append("TIMECOP final executable path drift")
                        if current_include != Path(include_value).resolve():
                            errors.append("TIMECOP final patched include path drift")
                        if backend_map.get("executable_sha256") != _sha256(current_executable):
                            errors.append("TIMECOP final executable hash drift")
                        header = current_include / "valgrind/memcheck.h"
                        if not header.is_file() or backend_map.get(
                            "patched_header_sha256"
                        ) != _sha256(header):
                            errors.append("TIMECOP final patched header hash drift")
                        version = subprocess.run(
                            [str(current_executable), "--version"],
                            text=True,
                            capture_output=True,
                            check=False,
                            timeout=30,
                        )
                        if version.returncode != 0 or version.stdout.strip() != backend_map.get(
                            "version"
                        ):
                            errors.append("TIMECOP final executable version drift")
            if not isinstance(canary, dict):
                errors.append("TIMECOP final result lacks backend canary metadata")
            else:
                canary_root = Path("backend_canary")
                canary_source = _check_hash_field(
                    root,
                    canary_root / "canary.c",
                    canary.get("source_sha256"),
                    errors,
                )
                canary_binary = _check_hash_field(
                    root,
                    canary_root / "canary",
                    canary.get("binary_sha256"),
                    errors,
                )
                canary_log = _check_hash_field(
                    root,
                    canary_root / "canary.valgrind.log",
                    canary.get("log_sha256"),
                    errors,
                )
                canary_stdout = _check_hash_field(
                    root,
                    canary_root / "canary.stdout",
                    canary.get("stdout_sha256"),
                    errors,
                )
                canary_stderr = _check_hash_field(
                    root,
                    canary_root / "canary.stderr",
                    canary.get("stderr_sha256"),
                    errors,
                )
                if (
                    canary_source is not None
                    and canary_source.read_text(encoding="utf-8") != CANARY_SOURCE
                ):
                    errors.append("TIMECOP canary source differs from the pinned canary")
                returncode = canary.get("returncode")
                timed_out = canary.get("timed_out")
                argv = canary.get("argv")
                if isinstance(returncode, bool) or not isinstance(returncode, int):
                    errors.append("TIMECOP canary returncode metadata is malformed")
                if not isinstance(timed_out, bool):
                    errors.append("TIMECOP canary timeout metadata is malformed")
                if (
                    not isinstance(argv, list)
                    or not argv
                    or any(not isinstance(item, str) for item in argv)
                    or "--tool=memcheck" not in argv
                    or "--error-exitcode=99" not in argv
                    or Path(argv[-1]).name != "canary"
                ):
                    errors.append("TIMECOP canary argv metadata is malformed")
                if (
                    isinstance(returncode, int)
                    and not isinstance(returncode, bool)
                    and isinstance(timed_out, bool)
                    and canary_log is not None
                    and canary_stdout is not None
                    and canary_stderr is not None
                    and canary_binary is not None
                ):
                    raw_canary = ValgrindResult(
                        returncode=returncode,
                        log_path=canary_log,
                        stdout=canary_stdout.read_text(encoding="utf-8", errors="replace"),
                        stderr=canary_stderr.read_text(encoding="utf-8", errors="replace"),
                        timed_out=timed_out,
                    )
                    classified_canary = classify_valgrind_run(raw_canary, canary_log)
                    variable_latency = [
                        finding
                        for finding in classified_canary.findings
                        if finding.type == FindingType.SECRET_DEPENDENT_VARIABLE_LATENCY
                    ]
                    derived_passed = (
                        not timed_out
                        and returncode == 99
                        and classified_canary.status == "FAIL"
                        and bool(variable_latency)
                        and "CTKAT-TIMECOP-CANARY:" in raw_canary.stdout
                    )
                    if canary.get("passed") is not derived_passed or not derived_passed:
                        errors.append("TIMECOP canary pass flag differs from raw process/findings")
                    if canary.get("finding_count") != len(variable_latency):
                        errors.append("TIMECOP canary finding count mismatch raw log")
                    if canary.get("dropped_valgrind_messages") != classified_canary.dropped:
                        errors.append("TIMECOP canary dropped-message count mismatch")
            if (
                value.get("run_kind") == "final"
                and isinstance(backend, dict)
                and resolved_final_backend is not None
            ):
                errors.extend(
                    _fresh_timecop_reproduction_errors(
                        root=root,
                        rows=rows,
                        manifest=manifest,
                        source_config=source_config,
                        backend=backend_map,
                        executable=resolved_final_backend[0],
                        patched_include=resolved_final_backend[1],
                    )
                )
    if tool_id == "microwalk_pin" and value.get("promotion_ready"):
        if artifact_root is None:
            errors.append("MicroWalk promotion requires its raw artifact root")
        else:
            root = artifact_root.resolve()
            expected_payloads = _testcase_payloads()
            for row in rows:
                if not isinstance(row, dict):
                    continue
                case_id = str(row.get("case_id", ""))
                harness = "leaky" if case_id.endswith("leaky") else "safe"
                target_name = f"target-toy-kem-{harness}"
                evidence = row.get("evidence")
                if not isinstance(evidence, dict):
                    errors.append(f"{case_id}: MicroWalk evidence is malformed")
                    continue
                case_root = Path(case_id)
                _check_hash_field(
                    root,
                    case_root / target_name,
                    evidence.get("binary_sha256"),
                    errors,
                )
                _check_hash_field(
                    root,
                    case_root / f"{target_name}.map",
                    evidence.get("map_sha256"),
                    errors,
                )
                result_path = _check_hash_field(
                    root,
                    case_root / "results" / "call-stacks.txt",
                    evidence.get("result_sha256"),
                    errors,
                )
                testcase_records = evidence.get("testcases")
                if not isinstance(testcase_records, list) or len(testcase_records) != len(
                    expected_payloads
                ):
                    errors.append(f"{case_id}: MicroWalk testcase index is malformed")
                else:
                    for index, (record, payload) in enumerate(
                        zip(testcase_records, expected_payloads, strict=True)
                    ):
                        relative = case_root / "testcases" / f"t{index:02d}.testcase"
                        path = _check_hash_field(
                            root,
                            relative,
                            record.get("sha256") if isinstance(record, dict) else None,
                            errors,
                        )
                        if (
                            not isinstance(record, dict)
                            or record.get("name") != f"t{index:02d}.testcase"
                            or record.get("ct0") != payload[0]
                            or path is None
                            or path.read_bytes() != payload
                        ):
                            errors.append(f"{case_id}: MicroWalk testcase {index} drift")
                for stem, hashes in (
                    ("build", evidence.get("build_streams")),
                    ("markers", evidence.get("marker_streams")),
                    ("map", evidence.get("map_streams")),
                    ("microwalk", evidence.get("run_streams")),
                ):
                    if not isinstance(hashes, dict):
                        errors.append(f"{case_id}: MicroWalk {stem} stream index is malformed")
                        continue
                    for suffix, field in (
                        ("stdout", "stdout_sha256"),
                        ("stderr", "stderr_sha256"),
                        ("timeout", "timeout_sha256"),
                    ):
                        _check_hash_field(
                            root,
                            case_root / f"{stem}.{suffix}",
                            hashes.get(field),
                            errors,
                        )
                if result_path is not None:
                    candidate_count = _microwalk_candidates(result_path)
                    if row.get("candidate_count") != candidate_count:
                        errors.append(f"{case_id}: MicroWalk candidate count mismatch")
                    derived_outcome = "finding" if candidate_count else "no-finding"
                    pair = (case_id, "microwalk_pin")
                    derived_match = (
                        pair in expected_coverage
                        and derived_outcome == expected_coverage[pair]["expected_outcome"]
                    )
                    if row.get("execution_status") != "completed":
                        errors.append(
                            f"{case_id}: MicroWalk completed raw result conflicts "
                            "with execution status"
                        )
                    if row.get("outcome") != derived_outcome:
                        errors.append(f"{case_id}: MicroWalk outcome mismatch raw result")
                    if row.get("known_issue_match") is not derived_match:
                        errors.append(f"{case_id}: MicroWalk known_issue_match mismatch raw result")
                    if evidence.get("returncode") != 0:
                        errors.append(
                            f"{case_id}: MicroWalk completed raw result lacks returncode 0"
                        )
    return errors


def _write_result(
    path: Path,
    record: dict[str, Any],
    manifest: dict[str, Any],
    *,
    manifest_path: Path = DEFAULT_MANIFEST,
) -> None:
    errors = validate_result(
        record,
        manifest,
        manifest_path=manifest_path,
        expected_commit=record.get("ctkat_commit"),
        artifact_root=path.parent,
    )
    if errors:
        raise BaselineError("result validation failed: " + "; ".join(errors))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _new_output_dir(output_root: Path, tool_id: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    output_dir = output_root.resolve() / f"{stamp}-{tool_id}"
    output_dir.mkdir(parents=True, exist_ok=False)
    return output_dir


def probe(
    manifest: dict[str, Any],
    manifest_path: Path,
    *,
    valgrind: str,
    prefix: Path | None,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for case_id in CASE_ORDER:
        for tool_id in TOOL_ORDER:
            rows.append(
                _base_row(
                    manifest,
                    case_id,
                    tool_id,
                    _capability(tool_id, valgrind=valgrind, prefix=prefix),
                )
            )
    return _record(
        manifest,
        manifest_path,
        "capability_probe",
        rows,
        run_kind="engineering",
        timing_evidence=False,
    )


def _serialize_finding(finding: Finding) -> dict[str, Any]:
    def frame(item: Any) -> dict[str, Any]:
        return {
            "address": item.address,
            "function": item.function,
            "file": item.file,
            "line": item.line,
        }

    return {
        "type": finding.type.value,
        "severity": finding.severity.value,
        "message": finding.message,
        "frames": [frame(item) for item in finding.frames],
        "origin_frames": [frame(item) for item in finding.origin_frames],
    }


def _stable_finding_signature(finding: Finding) -> dict[str, Any]:
    """Discard PID/ASLR/path-prefix noise while retaining semantic attribution."""

    def frame(item: Any) -> dict[str, Any]:
        return {
            "function": item.function,
            "file": Path(item.file).name if item.file else None,
            "line": item.line,
        }

    return {
        "type": finding.type.value,
        "severity": finding.severity.value,
        "message": finding.message,
        "frames": [frame(item) for item in finding.frames],
        "origin_frames": [frame(item) for item in finding.origin_frames],
    }


def _stable_finding_signatures(findings: list[Finding]) -> list[dict[str, Any]]:
    return [_stable_finding_signature(finding) for finding in findings]


def _compile_argv_contract(
    *,
    compiler: Path,
    source: Path,
    binary: Path,
    sources: list[Path],
    include_dirs: list[Path],
    cflags: list[str],
) -> list[str]:
    return [
        str(compiler),
        *cflags,
        *(f"-I{path}" for path in include_dirs),
        str(source),
        *(str(path) for path in sources),
        "-o",
        str(binary),
    ]


def _linked_source_records(sources: list[Path]) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for source in sources:
        resolved = source.resolve()
        records.append({"path": str(resolved.relative_to(ROOT)), "sha256": _sha256(resolved)})
    return records


def _compiler_identity(requested: str, executable: Path) -> dict[str, Any]:
    invocation_path = executable.absolute()
    resolved_path = invocation_path.resolve()
    version_argv = [str(resolved_path), "--version"]
    version = subprocess.run(
        version_argv,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if version.returncode != 0 or not version.stdout.strip():
        raise BaselineError(f"compiler version probe failed: {version.stderr.strip()}")
    return {
        "schema_version": "1.0",
        "requested": requested,
        "invocation_path": str(invocation_path),
        "resolved_path": str(resolved_path),
        "sha256": _sha256(resolved_path),
        "version_argv": version_argv,
        "version_returncode": version.returncode,
        "version_stdout": version.stdout,
        "version_stderr": version.stderr,
    }


def _run_valgrind(
    executable: Path,
    binary: Path,
    log_path: Path,
    *,
    timeout: int,
) -> tuple[ValgrindResult, list[str], float]:
    command = [
        str(executable),
        "--tool=memcheck",
        "--track-origins=yes",
        "--leak-check=no",
        "--error-exitcode=99",
        f"--log-file={log_path}",
        str(binary),
    ]
    started = time.monotonic()
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        elapsed = time.monotonic() - started
        return (
            ValgrindResult(
                returncode=result.returncode,
                log_path=log_path,
                stdout=result.stdout,
                stderr=result.stderr,
            ),
            command,
            elapsed,
        )
    except subprocess.TimeoutExpired as exc:
        elapsed = time.monotonic() - started
        return (
            ValgrindResult(
                returncode=124,
                log_path=log_path,
                stdout=_subprocess_text(exc.stdout),
                stderr=_subprocess_text(exc.stderr),
                timed_out=True,
            ),
            command,
            elapsed,
        )


def run_timecop(
    manifest: dict[str, Any],
    manifest_path: Path,
    *,
    valgrind_arg: str,
    prefix: Path | None,
    output_root: Path,
    run_kind: str = "engineering",
    review_gate: dict[str, Any] | None = None,
    automated_gate: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], Path]:
    capability = _capability("timecop", valgrind=valgrind_arg, prefix=prefix)
    output_dir = _new_output_dir(output_root, "timecop")
    if capability[0] == "unsupported":
        unsupported_rows = [
            _base_row(manifest, case_id, "timecop", capability) for case_id in CASE_ORDER
        ]
        record = _record(
            manifest,
            manifest_path,
            "timecop",
            unsupported_rows,
            run_kind=run_kind,
            review_gate=review_gate,
            automated_gate=automated_gate,
            timing_evidence=False,
        )
        report_path = output_dir / "baseline_report.json"
        _write_result(report_path, record, manifest, manifest_path=manifest_path)
        return record, report_path

    executable, patched_include = _find_backend(valgrind_arg, prefix)
    version_result = subprocess.run(
        [str(executable), "--version"],
        text=True,
        capture_output=True,
        timeout=30,
    )
    expected_version = f"valgrind-{manifest['tools']['timecop']['target_valgrind_version']}"
    if version_result.returncode != 0 or version_result.stdout.strip() != expected_version:
        raise BaselineError(
            f"TIMECOP backend version {version_result.stdout.strip()!r}, "
            f"expected {expected_version!r}"
        )
    compiler_name = os.environ.get("CC", "gcc")
    compiler = shutil.which(compiler_name)
    if compiler is None:
        raise BaselineError(f"C compiler not found: {compiler_name}")
    compiler_path = Path(compiler).absolute()
    compiler_identity = _compiler_identity(compiler_name, compiler_path)

    canary_dir = output_dir / "backend_canary"
    canary_dir.mkdir()
    canary_source = canary_dir / "canary.c"
    canary_binary = canary_dir / "canary"
    canary_log = canary_dir / "canary.valgrind.log"
    canary_source.write_text(CANARY_SOURCE, encoding="utf-8")
    canary_cflags = ["-std=c99", "-O2", "-g", "-fno-omit-frame-pointer", "-fno-lto"]
    canary_compile_command = compile_harness(
        canary_source,
        canary_binary,
        [],
        [patched_include],
        canary_cflags,
        ROOT,
        timeout=600,
        cc=str(compiler_path),
    )
    _make_artifact_readable(canary_binary)
    canary_result, canary_argv, canary_seconds = _run_valgrind(
        executable,
        canary_binary,
        canary_log,
        timeout=600,
    )
    canary_stdout = canary_dir / "canary.stdout"
    canary_stderr = canary_dir / "canary.stderr"
    canary_stdout.write_text(canary_result.stdout, encoding="utf-8")
    canary_stderr.write_text(canary_result.stderr, encoding="utf-8")
    if not canary_log.is_file():
        raise BaselineError("TIMECOP canary did not produce a Valgrind log")
    canary_findings, canary_dropped = parse_valgrind_log_with_stats(
        canary_log.read_text(encoding="utf-8", errors="replace")
    )
    variable_latency = [
        finding
        for finding in canary_findings
        if finding.type == FindingType.SECRET_DEPENDENT_VARIABLE_LATENCY
    ]
    canary_passed = (
        canary_result.returncode == 99
        and bool(variable_latency)
        and "CTKAT-TIMECOP-CANARY:" in canary_result.stdout
    )

    source_config = _repo_path(
        manifest["source_snapshot"]["config"]["path"],
        "source_snapshot.config",
    )
    config = load_config(source_config)
    if config.ct is None:
        raise BaselineError("same-corpus config has no ct section")
    config_dir = source_config.parent.resolve()
    cases = _case_map(manifest)
    coverage = _coverage_map(manifest)
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    for case_id in CASE_ORDER:
        case = cases[case_id]
        harnesses = [item for item in config.ct.harnesses if item.name == case["harness"]]
        if len(harnesses) != 1:
            raise BaselineError(f"{case_id}: expected exactly one CT harness")
        harness = harnesses[0]
        case_dir = output_dir / case_id
        case_dir.mkdir()
        source_path = case_dir / f"harness_{harness.name}.c"
        binary_path = case_dir / f"harness_{harness.name}"
        log_path = case_dir / "timecop.valgrind.log"
        source_path.write_text(
            render_harness(
                harness.template or "",
                _template_context(harness, config.ct.seed, timecop_mode=True),
            ),
            encoding="utf-8",
        )
        includes = [
            patched_include,
            *((config_dir / path).resolve() for path in harness.include_dirs),
        ]
        sources = [(config_dir / path).resolve() for path in harness.sources]
        cflags = harness.cflags if harness.cflags is not None else config.ct.cflags
        setup_started = time.monotonic()
        compile_command = compile_harness(
            source_path,
            binary_path,
            sources,
            includes,
            cflags,
            config_dir,
            timeout=config.ct.compile_timeout,
            cc=str(compiler_path),
        )
        _make_artifact_readable(binary_path)
        setup_seconds = time.monotonic() - setup_started
        run_result, argv, runtime_seconds = _run_valgrind(
            executable,
            binary_path,
            log_path,
            timeout=config.ct.valgrind_timeout,
        )
        stdout_path = case_dir / "timecop.stdout"
        stderr_path = case_dir / "timecop.stderr"
        stdout_path.write_text(run_result.stdout, encoding="utf-8")
        stderr_path.write_text(run_result.stderr, encoding="utf-8")
        classified = classify_valgrind_run(
            run_result,
            log_path,
            lookup_patterns=config.ct.lookup_function_patterns,
        )
        row = _base_row(manifest, case_id, "timecop", capability)
        if run_result.timed_out:
            row["execution_status"] = "timeout"
            row["outcome"] = "inconclusive"
            errors.append(f"{case_id}: TIMECOP timeout")
        elif classified.status == "ERROR":
            row["execution_status"] = "error"
            row["outcome"] = "inconclusive"
            errors.append(f"{case_id}: {classified.error}")
        else:
            row["execution_status"] = "completed"
            row["outcome"] = "finding" if classified.findings else "no-finding"
            row["known_issue_match"] = (
                row["outcome"] == coverage[(case_id, "timecop")]["expected_outcome"]
            )
            row["candidate_count"] = len(classified.findings)
        row["setup_seconds"] = setup_seconds
        row["runtime_seconds"] = runtime_seconds
        row["peak_memory_kib"] = _peak_child_kib()
        row["artifact_bytes"] = _tree_bytes(case_dir)
        row["evidence"] = {
            "compile_command": compile_command,
            "compile_argv": _compile_argv_contract(
                compiler=compiler_path,
                source=source_path,
                binary=binary_path,
                sources=sources,
                include_dirs=includes,
                cflags=list(cflags),
            ),
            "compile_workdir": str(config_dir.relative_to(ROOT)),
            "source_sha256": _sha256(source_path),
            "linked_sources": _linked_source_records(sources),
            "argv": argv,
            "returncode": run_result.returncode,
            "timed_out": run_result.timed_out,
            "binary_sha256": _sha256(binary_path),
            "log_sha256": _sha256(log_path) if log_path.is_file() else None,
            "stdout_sha256": _sha256(stdout_path),
            "stderr_sha256": _sha256(stderr_path),
            "dropped_valgrind_messages": classified.dropped,
            "findings": [_serialize_finding(item) for item in classified.findings],
            "finding_signatures": _stable_finding_signatures(classified.findings),
            "evidence_boundary": "dynamic taint/operand evidence; never physical timing",
            "peak_memory_scope": "runner child-process upper bound",
        }
        rows.append(row)
    if not canary_passed:
        errors.append("TIMECOP backend canary failed")

    compiler_version = str(compiler_identity["version_stdout"]).splitlines()[0]
    backend = {
        "prefix": str(prefix.resolve()) if prefix is not None else None,
        "executable": str(executable),
        "executable_sha256": _sha256(executable),
        "version": version_result.stdout.strip(),
        "patched_include": str(patched_include),
        "patched_header_sha256": _sha256(patched_include / "valgrind/memcheck.h"),
        "patch_sha256": manifest["tools"]["timecop"]["patch"]["sha256"],
        "compiler": str(compiler_path),
        "compiler_version": compiler_version,
        "compiler_identity": compiler_identity,
        "canary": {
            "passed": canary_passed,
            "compile_command": canary_compile_command,
            "compile_argv": _compile_argv_contract(
                compiler=compiler_path,
                source=canary_source,
                binary=canary_binary,
                sources=[],
                include_dirs=[patched_include],
                cflags=canary_cflags,
            ),
            "argv": canary_argv,
            "runtime_seconds": canary_seconds,
            "returncode": canary_result.returncode,
            "timed_out": canary_result.timed_out,
            "finding_count": len(variable_latency),
            "dropped_valgrind_messages": canary_dropped,
            "finding_signatures": _stable_finding_signatures(canary_findings),
            "source_sha256": _sha256(canary_source),
            "binary_sha256": _sha256(canary_binary),
            "log_sha256": _sha256(canary_log),
            "stdout_sha256": _sha256(canary_stdout),
            "stderr_sha256": _sha256(canary_stderr),
        },
    }
    record = _record(
        manifest,
        manifest_path,
        "timecop",
        rows,
        run_kind=run_kind,
        review_gate=review_gate,
        automated_gate=automated_gate,
        timing_evidence=False,
        backend=backend,
        errors=errors,
    )
    report_path = output_dir / "baseline_report.json"
    _write_result(report_path, record, manifest, manifest_path=manifest_path)
    return record, report_path


def run_dudect(
    manifest: dict[str, Any],
    manifest_path: Path,
    *,
    output_root: Path,
    run_kind: str = "engineering",
    review_gate: dict[str, Any] | None = None,
    automated_gate: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], Path]:
    capability = _capability("official_dudect")
    output_dir = _new_output_dir(output_root, "official_dudect")
    if capability[0] == "unsupported":
        unsupported_rows = [
            _base_row(manifest, case_id, "official_dudect", capability) for case_id in CASE_ORDER
        ]
        record = _record(
            manifest,
            manifest_path,
            "official_dudect",
            unsupported_rows,
            run_kind=run_kind,
            review_gate=review_gate,
            automated_gate=automated_gate,
            timing_evidence=False,
        )
        report_path = output_dir / "baseline_report.json"
        _write_result(report_path, record, manifest, manifest_path=manifest_path)
        return record, report_path

    source_config = _repo_path(
        manifest["source_snapshot"]["config"]["path"],
        "source_snapshot.config",
    )
    config = load_config(source_config)
    if config.dudect is None:
        raise BaselineError("same-corpus config has no dudect section")
    raw_dir = output_dir / "raw"
    generated_dir = output_dir / "generated"
    dudect_config = config.dudect.model_copy(update={"generated_dir": generated_dir})
    started = time.monotonic()
    results = _do_dudect(
        dudect_config,
        source_config.parent.resolve(),
        config.project.name,
        raw_dir,
        config_path=source_config.resolve(),
    )
    runtime_seconds = time.monotonic() - started
    _emit_dudect_report(config.project.name, raw_dir, results)

    emulated = detect_qemu_emulation()
    virtualization = _detect_virtualization()
    virtualized = bool(virtualization["vm"] or virtualization["container"])
    timing_environment = collect_timing_environment(emulated=emulated, clock="rdtsc")
    _commit, git_dirty = _git_state()
    affinity = timing_environment.get("cpu_affinity")
    cpu_model = timing_environment.get("cpu_model")
    governor = timing_environment.get("governor")
    host_reasons: list[str] = []
    if emulated:
        host_reasons.append("emulated x86 timing host")
    if virtualized:
        host_reasons.append("virtualized timing host")
    if not isinstance(affinity, list) or len(affinity) != 1:
        host_reasons.append("process is not pinned to exactly one logical CPU")
    if governor != "performance":
        host_reasons.append("selected CPU governor is not performance")
    if not isinstance(cpu_model, str) or not cpu_model.strip():
        host_reasons.append("exact CPU model metadata is unavailable")
    if not isinstance(timing_environment.get("machine_id_sha256"), str):
        host_reasons.append("hashed physical host identity is unavailable")
    if git_dirty:
        host_reasons.append("git worktree is dirty")
    physical_eligible = not host_reasons and all(
        result.timing_validity == "valid" for _, _, result, _ in results
    )
    result_map = {name: (samples, result) for name, samples, result, _ in results}
    cases = _case_map(manifest)
    coverage = _coverage_map(manifest)
    config_loc, adapter_loc = _tool_locs(manifest, "official_dudect")
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    for case_id in CASE_ORDER:
        harness = cases[case_id]["harness"]
        samples, result = result_map[harness]
        row = _base_row(manifest, case_id, "official_dudect", capability)
        row["runtime_seconds"] = runtime_seconds
        row["peak_memory_kib"] = _peak_child_kib()
        row["artifact_bytes"] = _tree_bytes(raw_dir) + _tree_bytes(generated_dir)
        row["config_loc"] = config_loc
        row["adapter_loc"] = adapter_loc
        # WelchResult currently exposes `status`; `getattr` keeps a future
        # adapter's explicitly named raw status backward compatible.
        raw_status = getattr(result, "raw_status", result.status)
        if raw_status == "ERROR":
            row["execution_status"] = "error"
            row["outcome"] = "inconclusive"
            errors.append(f"{case_id}: official dudect returned ERROR")
        else:
            row["execution_status"] = "completed"
            if physical_eligible:
                row["outcome"] = "finding" if raw_status == "FAIL" else "no-finding"
                row["known_issue_match"] = (
                    row["outcome"] == coverage[(case_id, "official_dudect")]["expected_outcome"]
                )
            else:
                row["outcome"] = "inconclusive"
            row["candidate_count"] = 1 if raw_status == "FAIL" else 0
        row["evidence"] = {
            "raw_status": raw_status,
            "timing_validity": result.timing_validity,
            "validity_reasons": list(result.validity_reasons),
            "abs_t_score": result.abs_t_score,
            "n0": result.n0,
            "n1": result.n1,
            "analysis_seed": result.analysis_seed,
            "raw_sample_count": samples.raw_n_total,
            "physical_eligible": physical_eligible,
            "virtualization": virtualization,
            "runtime_scope": "shared two-case campaign",
            "artifact_size_scope": "shared two-case campaign",
        }
        rows.append(row)
    if not physical_eligible:
        errors.append(
            "official dudect run did not clear the physical-host validity gate"
            + (f": {'; '.join(host_reasons)}" if host_reasons else "")
        )

    record = _record(
        manifest,
        manifest_path,
        "official_dudect",
        rows,
        run_kind=run_kind,
        review_gate=review_gate,
        automated_gate=automated_gate,
        timing_evidence=physical_eligible,
        backend={
            "official_dudect_revision": OFFICIAL_DUDECT_REVISION,
            "virtualization": virtualization,
            "timing_environment": timing_environment,
            "raw_report": str((raw_dir / "dudect_backend_report.json").relative_to(output_dir)),
            "raw_report_sha256": _sha256(raw_dir / "dudect_backend_report.json"),
        },
        errors=errors,
    )
    report_path = output_dir / "baseline_report.json"
    _write_result(report_path, record, manifest, manifest_path=manifest_path)
    return record, report_path


def _docker_run(
    command: list[str],
    *,
    timeout: int,
    cleanup_container: str | None = None,
) -> tuple[subprocess.CompletedProcess[str] | None, float, str | None]:
    started = time.monotonic()
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        return result, time.monotonic() - started, None
    except subprocess.TimeoutExpired as exc:
        output = _subprocess_text(exc.stdout) + _subprocess_text(exc.stderr)
        if cleanup_container is not None:
            try:
                cleanup = subprocess.run(
                    ["docker", "rm", "--force", cleanup_container],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    timeout=30,
                )
                output += _subprocess_text(cleanup.stdout) + _subprocess_text(cleanup.stderr)
            except (OSError, subprocess.SubprocessError) as cleanup_exc:
                output += f"\ncontainer cleanup failed: {cleanup_exc}\n"
        return None, time.monotonic() - started, output


def _write_process_streams(
    directory: Path,
    stem: str,
    result: subprocess.CompletedProcess[str] | None,
    timeout_output: str | None,
) -> dict[str, str]:
    stdout_path = directory / f"{stem}.stdout"
    stderr_path = directory / f"{stem}.stderr"
    timeout_path = directory / f"{stem}.timeout"
    stdout_path.write_text("" if result is None else result.stdout, encoding="utf-8")
    stderr_path.write_text("" if result is None else result.stderr, encoding="utf-8")
    timeout_path.write_text(timeout_output or "", encoding="utf-8")
    return {
        "stdout_sha256": _sha256(stdout_path),
        "stderr_sha256": _sha256(stderr_path),
        "timeout_sha256": _sha256(timeout_path),
    }


def _write_testcases(directory: Path, expected_sha256: str) -> list[dict[str, Any]]:
    directory.mkdir(parents=True, exist_ok=False)
    records: list[dict[str, Any]] = []
    payloads = _testcase_payloads()
    for index, payload in enumerate(payloads):
        path = directory / f"t{index:02d}.testcase"
        path.write_bytes(payload)
        records.append(
            {
                "name": path.name,
                "ct0": payload[0],
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    actual = hashlib.sha256(b"".join(path.read_bytes() for path in sorted(directory.iterdir())))
    if actual.hexdigest() != expected_sha256:
        raise BaselineError("generated MicroWalk testcase corpus hash mismatch")
    return records


def _microwalk_candidates(path: Path) -> int:
    if not path.is_file():
        raise BaselineError(f"MicroWalk result missing: {path}")
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if "[L]" in line)


def _microwalk_marker_calls(disassembly: str) -> dict[str, bool]:
    call_lines = [
        line for line in disassembly.splitlines() if re.search(r"\bcallq?\b", line) is not None
    ]
    return {
        marker: any(f"<{marker}>" in line for line in call_lines) for marker in MICROWALK_MARKERS
    }


def run_microwalk(
    manifest: dict[str, Any],
    manifest_path: Path,
    *,
    output_root: Path,
    timeout: int,
    run_kind: str = "engineering",
    review_gate: dict[str, Any] | None = None,
    automated_gate: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], Path]:
    capability = _capability("microwalk_pin")
    output_dir = _new_output_dir(output_root, "microwalk_pin")
    if capability[0] == "unsupported":
        unsupported_rows = [
            _base_row(manifest, case_id, "microwalk_pin", capability) for case_id in CASE_ORDER
        ]
        record = _record(
            manifest,
            manifest_path,
            "microwalk_pin",
            unsupported_rows,
            run_kind=run_kind,
            review_gate=review_gate,
            automated_gate=automated_gate,
            timing_evidence=False,
        )
        report_path = output_dir / "baseline_report.json"
        _write_result(report_path, record, manifest, manifest_path=manifest_path)
        return record, report_path

    tool = manifest["tools"]["microwalk_pin"]
    image = tool["execution_image"]
    coverage = _coverage_map(manifest)
    protocol = manifest["testcase_protocol"]
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    run_token = hashlib.sha256(str(output_dir).encode("utf-8")).hexdigest()[:12]
    docker_version = subprocess.run(
        ["docker", "version", "--format", "{{.Client.Version}}"],
        text=True,
        capture_output=True,
        timeout=30,
    )
    if docker_version.returncode != 0:
        raise BaselineError(f"docker daemon unavailable: {docker_version.stderr.strip()}")

    for case_id in CASE_ORDER:
        harness = "leaky" if case_id.endswith("leaky") else "safe"
        macro = "CTKAT_MICROWALK_LEAKY" if harness == "leaky" else "CTKAT_MICROWALK_SAFE"
        target_name = f"target-toy-kem-{harness}"
        case_dir = output_dir / case_id
        case_dir.mkdir()
        testcase_records = _write_testcases(
            case_dir / "testcases",
            protocol["ordered_payload_sha256"],
        )
        (case_dir / "work").mkdir()
        (case_dir / "results").mkdir()
        target_path = case_dir / target_name
        map_path = case_dir / f"{target_name}.map"

        mount_repo = f"{ROOT}:/repo:ro"
        mount_case = f"{case_dir}:/baseline"
        build_container = f"ctkat-mw-{run_token}-{harness}-build"
        build_command = [
            "docker",
            "run",
            "--rm",
            "--name",
            build_container,
            "--platform=linux/amd64",
            "-v",
            mount_repo,
            "-v",
            mount_case,
            image,
            "gcc",
            "-std=c11",
            "-O2",
            "-g",
            "-fno-inline",
            "-fno-omit-frame-pointer",
            "-fno-split-stack",
            f"-D{macro}",
            "-I/repo/examples/toy_kem_ct_leak/include",
            "/repo/examples/toy_kem_ct_leak/microwalk/main.c",
            "/repo/examples/toy_kem_ct_leak/microwalk/target.c",
            "/repo/examples/toy_kem_ct_leak/src/toy_kem.c",
            "-o",
            f"/baseline/{target_name}",
        ]
        setup_started = time.monotonic()
        build_result, _, build_timeout = _docker_run(
            build_command,
            timeout=600,
            cleanup_container=build_container,
        )
        build_streams = _write_process_streams(
            case_dir,
            "build",
            build_result,
            build_timeout,
        )
        setup_logs = []
        if build_result is not None:
            setup_logs.append(build_result.stdout + build_result.stderr)
        if build_timeout is not None:
            setup_logs.append(build_timeout)

        marker_container = f"ctkat-mw-{run_token}-{harness}-markers"
        marker_command = [
            "docker",
            "run",
            "--rm",
            "--name",
            marker_container,
            "--platform=linux/amd64",
            "-v",
            mount_case,
            image,
            "objdump",
            "-d",
            f"/baseline/{target_name}",
        ]
        marker_result: subprocess.CompletedProcess[str] | None = None
        marker_timeout: str | None = None
        marker_calls = {marker: False for marker in MICROWALK_MARKERS}
        if build_result is not None and build_result.returncode == 0:
            marker_result, _, marker_timeout = _docker_run(
                marker_command,
                timeout=60,
                cleanup_container=marker_container,
            )
            if marker_result is not None:
                setup_logs.append(marker_result.stdout + marker_result.stderr)
                if marker_result.returncode == 0:
                    marker_calls = _microwalk_marker_calls(marker_result.stdout)
            if marker_timeout is not None:
                setup_logs.append(marker_timeout)
        marker_streams = _write_process_streams(
            case_dir,
            "markers",
            marker_result,
            marker_timeout,
        )
        markers_ready = (
            marker_result is not None
            and marker_result.returncode == 0
            and all(marker_calls.values())
        )

        map_container = f"ctkat-mw-{run_token}-{harness}-map"
        map_command = [
            "docker",
            "run",
            "--rm",
            "--name",
            map_container,
            "--platform=linux/amd64",
            "-v",
            mount_case,
            image,
            "dotnet",
            "/mw/mapfilegenerator/MapFileGenerator.dll",
            f"/baseline/{target_name}",
            f"/baseline/{target_name}.map",
        ]
        map_result: subprocess.CompletedProcess[str] | None = None
        map_timeout: str | None = None
        if markers_ready:
            map_result, _, map_timeout = _docker_run(
                map_command,
                timeout=300,
                cleanup_container=map_container,
            )
            if map_result is not None:
                setup_logs.append(map_result.stdout + map_result.stderr)
            if map_timeout is not None:
                setup_logs.append(map_timeout)
        map_streams = _write_process_streams(
            case_dir,
            "map",
            map_result,
            map_timeout,
        )
        setup_seconds = time.monotonic() - setup_started
        (case_dir / "setup.log").write_text("".join(setup_logs), encoding="utf-8")

        row = _base_row(manifest, case_id, "microwalk_pin", capability)
        row["setup_seconds"] = setup_seconds
        setup_failed = (
            build_result is None
            or build_result.returncode != 0
            or not markers_ready
            or map_result is None
            or map_result.returncode != 0
        )
        if setup_failed:
            row["execution_status"] = (
                "timeout"
                if build_timeout is not None
                or marker_timeout is not None
                or map_timeout is not None
                else "error"
            )
            row["outcome"] = "inconclusive"
            row["artifact_bytes"] = _tree_bytes(case_dir)
            errors.append(f"{case_id}: MicroWalk build/marker/MAP setup failed")
            row["evidence"] = {
                "build_argv": build_command,
                "marker_argv": marker_command,
                "map_argv": map_command,
                "build_returncode": (None if build_result is None else build_result.returncode),
                "marker_returncode": (None if marker_result is None else marker_result.returncode),
                "map_returncode": None if map_result is None else map_result.returncode,
                "marker_calls": marker_calls,
                "build_streams": build_streams,
                "marker_streams": marker_streams,
                "map_streams": map_streams,
            }
            rows.append(row)
            continue

        analysis_container = f"ctkat-mw-{run_token}-{harness}-analysis"
        run_command = [
            "docker",
            "run",
            "--rm",
            "--name",
            analysis_container,
            "--platform=linux/amd64",
            "-v",
            mount_repo,
            "-v",
            mount_case,
            "-e",
            "CTKAT_MICROWALK_WORK_DIR=/baseline/work",
            "-e",
            f"CTKAT_MICROWALK_TARGET_PATH=/baseline/{target_name}",
            "-e",
            "CTKAT_MICROWALK_RESULT_DIR=/baseline/results",
            "-e",
            "CTKAT_MICROWALK_TESTCASE_DIR=/baseline/testcases",
            "-e",
            f"CTKAT_MICROWALK_TARGET_NAME={target_name}",
            "-e",
            f"CTKAT_MICROWALK_MAP_PATH=/baseline/{target_name}.map",
            image,
            "dotnet",
            "/mw/microwalk/Microwalk.dll",
            "/repo/examples/toy_kem_ct_leak/microwalk/config.yml",
        ]
        run_result, runtime_seconds, run_timeout = _docker_run(
            run_command,
            timeout=timeout,
            cleanup_container=analysis_container,
        )
        run_streams = _write_process_streams(
            case_dir,
            "microwalk",
            run_result,
            run_timeout,
        )
        run_output = run_timeout or ""
        if run_result is not None:
            run_output = run_result.stdout + run_result.stderr
        (case_dir / "microwalk.stdout.log").write_text(run_output, encoding="utf-8")
        row["runtime_seconds"] = runtime_seconds
        if run_result is None:
            row["execution_status"] = "timeout"
            row["outcome"] = "inconclusive"
            errors.append(f"{case_id}: MicroWalk timeout")
        elif run_result.returncode != 0:
            row["execution_status"] = "crash" if run_result.returncode < 0 else "error"
            row["outcome"] = "inconclusive"
            errors.append(f"{case_id}: MicroWalk exited {run_result.returncode}")
        else:
            candidate_count = _microwalk_candidates(case_dir / "results/call-stacks.txt")
            row["execution_status"] = "completed"
            row["outcome"] = "finding" if candidate_count else "no-finding"
            row["known_issue_match"] = (
                row["outcome"] == coverage[(case_id, "microwalk_pin")]["expected_outcome"]
            )
            row["candidate_count"] = candidate_count

        monitor_path = case_dir / "work/microwalk.log"
        if monitor_path.is_file():
            match = MICROWALK_PEAK_RE.search(
                monitor_path.read_text(encoding="utf-8", errors="replace")
            )
            if match:
                row["peak_memory_kib"] = (int(match.group(1)) + 1023) // 1024
        row["artifact_bytes"] = _tree_bytes(case_dir)
        row["evidence"] = {
            "build_argv": build_command,
            "marker_argv": marker_command,
            "map_argv": map_command,
            "run_argv": run_command,
            "build_streams": build_streams,
            "marker_streams": marker_streams,
            "map_streams": map_streams,
            "run_streams": run_streams,
            "marker_calls": marker_calls,
            "returncode": None if run_result is None else run_result.returncode,
            "binary_sha256": _sha256(target_path),
            "map_sha256": _sha256(map_path),
            "testcases": testcase_records,
            "result_sha256": (
                _sha256(case_dir / "results/call-stacks.txt")
                if (case_dir / "results/call-stacks.txt").is_file()
                else None
            ),
            "evidence_boundary": "Pin trace evidence; never physical timing",
        }
        rows.append(row)

    record = _record(
        manifest,
        manifest_path,
        "microwalk_pin",
        rows,
        run_kind=run_kind,
        review_gate=review_gate,
        automated_gate=automated_gate,
        timing_evidence=False,
        backend={
            "execution_image": image,
            "documentation_revision": tool["documentation_revision"],
            "source_image_linkage": tool["source_image_linkage"],
            "docker_client_version": docker_version.stdout.strip(),
        },
        errors=errors,
    )
    report_path = output_dir / "baseline_report.json"
    _write_result(report_path, record, manifest, manifest_path=manifest_path)
    return record, report_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true", help="validate frozen inputs")
    action.add_argument("--probe", action="store_true", help="record host capability rows")
    action.add_argument("--run-timecop", action="store_true")
    action.add_argument("--run-dudect", action="store_true")
    action.add_argument("--run-microwalk", action="store_true")
    action.add_argument("--validate-result", type=Path)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, help="probe output path")
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--valgrind", default="valgrind")
    parser.add_argument("--prefix", type=Path)
    parser.add_argument("--cpu", type=int, help="pin official-dudect and all children to this CPU")
    parser.add_argument(
        "--expected-commit",
        help="require a validated result to match this frozen 40-hex CT-KAT commit",
    )
    parser.add_argument(
        "--run-kind",
        choices=RUN_KINDS,
        help="required for executable adapters; only final results are promotable",
    )
    parser.add_argument(
        "--expected-run-kind",
        choices=RUN_KINDS,
        help="require a validated result to have this run kind",
    )
    parser.add_argument(
        "--final-gate",
        choices=("human", "single-host"),
        default="human",
        help="final promotion gate; single-host claims no independent review",
    )
    parser.add_argument("--microwalk-timeout", type=int, default=1800)
    args = parser.parse_args()

    try:
        manifest_path = args.manifest.resolve()
        manifest = load_manifest(manifest_path)
        static_errors = validate_static(manifest, manifest_path=manifest_path)
        if static_errors:
            raise BaselineError("static validation failed: " + "; ".join(static_errors))
        if args.check:
            print(
                "[same-corpus] OK: 2 cases x 3 tools; complete coverage; "
                "result schema and expansion plan valid"
            )
            return 0
        if args.validate_result is not None:
            value = json.loads(args.validate_result.read_text(encoding="utf-8"))
            result_errors = validate_result(
                _mapping(value, "result"),
                manifest,
                manifest_path=manifest_path,
                expected_commit=args.expected_commit,
                expected_run_kind=args.expected_run_kind,
                artifact_root=args.validate_result.resolve().parent,
            )
            if result_errors:
                raise BaselineError("result validation failed: " + "; ".join(result_errors))
            print(f"[same-corpus] valid result: {args.validate_result}")
            return 0
        if args.cpu is not None and not args.run_dudect:
            parser.error("--cpu is only valid with --run-dudect")
        executing = args.run_timecop or args.run_dudect or args.run_microwalk
        if executing and args.run_kind is None:
            parser.error("executable adapters require --run-kind")
        if args.run_timecop and args.run_kind == "final" and args.prefix is None:
            parser.error("final TIMECOP execution requires an explicit --prefix")
        review_gate = None
        automated_gate = None
        if executing and args.run_kind == "final":
            commit, _dirty = _git_state()
            if args.final_gate == "single-host":
                automated_gate = _single_host_premeasurement_gate(commit)
            else:
                review_gate = _human_premeasurement_gate(commit)
        if executing and args.run_kind in {"pilot", "final"}:
            environment = collect_timing_environment(
                emulated=detect_qemu_emulation(),
                clock="rdtsc" if args.run_dudect else "not-applicable",
            )
            virtualization = _detect_virtualization()
            _commit, dirty = _git_state()
            host_errors: list[str] = []
            if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
                host_errors.append("Linux/x86_64 host is required")
            if environment.get("emulated") is not False:
                host_errors.append("emulation detected")
            if virtualization["vm"] or virtualization["container"]:
                host_errors.append("virtualization detected")
            if not environment.get("cpu_model"):
                host_errors.append("exact CPU model metadata is required")
            if not environment.get("machine_id_sha256"):
                host_errors.append("hashed physical host identity is required")
            if not environment.get("boot_id_sha256"):
                host_errors.append("hashed boot identity is required")
            if dirty:
                host_errors.append("clean git worktree is required")
            if host_errors:
                raise BaselineError(
                    f"{args.run_kind} host preflight failed: " + "; ".join(host_errors)
                )
        if args.run_dudect:
            if args.cpu is not None:
                pin_current_process(args.cpu)
            environment = collect_timing_environment(
                emulated=detect_qemu_emulation(),
                clock="rdtsc",
            )
            virtualization = _detect_virtualization()
            _commit, dirty = _git_state()
            readiness_errors: list[str] = []
            if environment.get("emulated") is not False:
                readiness_errors.append("emulation detected")
            if virtualization["vm"] or virtualization["container"]:
                readiness_errors.append("virtualization detected")
            if len(environment.get("cpu_affinity") or []) != 1:
                readiness_errors.append("exactly one pinned logical CPU is required")
            if environment.get("governor") != "performance":
                readiness_errors.append("performance governor is required")
            if not environment.get("cpu_model"):
                readiness_errors.append("exact CPU model metadata is required")
            if not environment.get("machine_id_sha256"):
                readiness_errors.append("hashed physical host identity is required")
            if not environment.get("boot_id_sha256"):
                readiness_errors.append("hashed boot identity is required")
            timing_flags = environment.get("timing_cpu_flags")
            if not isinstance(timing_flags, dict) or any(
                timing_flags.get(flag) is not True
                for flag in ("constant_tsc", "nonstop_tsc", "rdtscp")
            ):
                readiness_errors.append("invariant-TSC/RDTSCP capability is required")
            if dirty:
                readiness_errors.append("clean git worktree is required")
            if readiness_errors and args.run_kind in {"pilot", "final"}:
                raise BaselineError(
                    "official dudect host preflight failed: " + "; ".join(readiness_errors)
                )
        if args.probe:
            record = probe(
                manifest,
                manifest_path,
                valgrind=args.valgrind,
                prefix=args.prefix,
            )
            if args.output is not None:
                _write_result(
                    args.output.resolve(),
                    record,
                    manifest,
                    manifest_path=manifest_path,
                )
                print(f"[same-corpus] capability report: {args.output.resolve()}")
            else:
                print(json.dumps(record, indent=2, sort_keys=True))
            return 0
        if args.run_timecop:
            record, report = run_timecop(
                manifest,
                manifest_path,
                valgrind_arg=args.valgrind,
                prefix=args.prefix,
                output_root=args.output_root,
                run_kind=str(args.run_kind),
                review_gate=review_gate,
                automated_gate=automated_gate,
            )
        elif args.run_dudect:
            record, report = run_dudect(
                manifest,
                manifest_path,
                output_root=args.output_root,
                run_kind=str(args.run_kind),
                review_gate=review_gate,
                automated_gate=automated_gate,
            )
        else:
            record, report = run_microwalk(
                manifest,
                manifest_path,
                output_root=args.output_root,
                timeout=args.microwalk_timeout,
                run_kind=str(args.run_kind),
                review_gate=review_gate,
                automated_gate=automated_gate,
            )
        print(f"[same-corpus] report: {report}")
        print(f"[same-corpus] promotion_ready={record['promotion_ready']}")
        for error in record["errors"]:
            print(f"[same-corpus] ERROR: {error}", file=sys.stderr)
        if args.run_kind != "final":
            complete = not record["errors"] and all(
                row.get("execution_status") == "completed" for row in record["rows"]
            )
            return 0 if complete else 1
        return 0 if record["promotion_ready"] else 1
    except (
        BaselineError,
        CampaignError,
        json.JSONDecodeError,
        OSError,
        subprocess.SubprocessError,
        ValueError,
    ) as exc:
        print(f"[same-corpus] ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
