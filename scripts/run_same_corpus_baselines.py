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
import time
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
from ctkat.qemu_detect import detect_qemu_emulation  # noqa: E402
from ctkat.valgrind_parser import Finding, FindingType, parse_valgrind_log_with_stats  # noqa: E402
from ctkat.valgrind_runner import ValgrindResult  # noqa: E402
from scripts.run_kyberslash_timecop import CANARY_SOURCE, _find_backend  # noqa: E402
from scripts.run_native_timing_campaign import _detect_virtualization  # noqa: E402

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
            schema.get("properties", {}).get("schema_version", {}).get("const") == "1.0",
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
    return {
        "system": platform.system(),
        "machine": platform.machine(),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "emulated": emulated,
        "timing_evidence": timing_evidence,
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
    timing_evidence: bool,
    backend: dict[str, Any] | None = None,
    errors: list[str] | None = None,
) -> dict[str, Any]:
    actual_errors = errors or []
    expected = _coverage_map(manifest)
    complete = all(
        row["capability"]["status"] == "supported"
        and row["execution_status"] == "completed"
        and row["known_issue_match"] is True
        for row in rows
    )
    return {
        "schema_version": "1.0",
        "kind": "ctkat-same-corpus-baseline",
        "suite_id": manifest["suite_id"],
        "created_at": _utc_now(),
        "manifest": str(manifest_path.resolve().relative_to(ROOT)),
        "manifest_sha256": _sha256(manifest_path),
        "tool_id": tool_id,
        "host": _host(timing_evidence=timing_evidence),
        "rows": rows,
        "promotion_ready": complete
        and not actual_errors
        and all(
            row["outcome"] == expected[(row["case_id"], row["tool_id"])]["expected_outcome"]
            for row in rows
        ),
        "errors": actual_errors,
        "backend": backend,
    }


def validate_result(
    value: dict[str, Any],
    manifest: dict[str, Any],
    *,
    manifest_path: Path = DEFAULT_MANIFEST,
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
        "tool_id",
        "host",
        "rows",
        "promotion_ready",
        "errors",
        "backend",
    }
    check(set(value) == required, "result top-level field set mismatch")
    check(value.get("schema_version") == "1.0", "result schema_version mismatch")
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
        and not value.get("errors")
        and all(
            isinstance(row, dict)
            and row.get("capability", {}).get("status") == "supported"
            and row.get("execution_status") == "completed"
            and row.get("known_issue_match") is True
            and (row.get("case_id"), row.get("tool_id")) in expected_coverage
            and row.get("outcome")
            == expected_coverage[(row.get("case_id"), row.get("tool_id"))]["expected_outcome"]
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
    return errors


def _write_result(
    path: Path,
    record: dict[str, Any],
    manifest: dict[str, Any],
    *,
    manifest_path: Path = DEFAULT_MANIFEST,
) -> None:
    errors = validate_result(record, manifest, manifest_path=manifest_path)
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
) -> tuple[dict[str, Any], Path]:
    capability = _capability("timecop", valgrind=valgrind_arg, prefix=prefix)
    output_dir = _new_output_dir(output_root, "timecop")
    if capability[0] == "unsupported":
        rows = [_base_row(manifest, case_id, "timecop", capability) for case_id in CASE_ORDER]
        record = _record(
            manifest,
            manifest_path,
            "timecop",
            rows,
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

    canary_dir = output_dir / "backend_canary"
    canary_dir.mkdir()
    canary_source = canary_dir / "canary.c"
    canary_binary = canary_dir / "canary"
    canary_log = canary_dir / "canary.valgrind.log"
    canary_source.write_text(CANARY_SOURCE, encoding="utf-8")
    compile_harness(
        canary_source,
        canary_binary,
        [],
        [patched_include],
        ["-std=c99", "-O2", "-g", "-fno-omit-frame-pointer", "-fno-lto"],
        ROOT,
        timeout=600,
        cc=compiler,
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
            cc=compiler,
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
            "argv": argv,
            "returncode": run_result.returncode,
            "binary_sha256": _sha256(binary_path),
            "log_sha256": _sha256(log_path) if log_path.is_file() else None,
            "stdout_sha256": _sha256(stdout_path),
            "stderr_sha256": _sha256(stderr_path),
            "dropped_valgrind_messages": classified.dropped,
            "findings": [_serialize_finding(item) for item in classified.findings],
            "evidence_boundary": "dynamic taint/operand evidence; never physical timing",
            "peak_memory_scope": "runner child-process upper bound",
        }
        rows.append(row)
    if not canary_passed:
        errors.append("TIMECOP backend canary failed")

    compiler_version = subprocess.run(
        [compiler, "--version"],
        text=True,
        capture_output=True,
        timeout=30,
    ).stdout.splitlines()[0]
    backend = {
        "executable": str(executable),
        "executable_sha256": _sha256(executable),
        "version": version_result.stdout.strip(),
        "patched_include": str(patched_include),
        "patch_sha256": manifest["tools"]["timecop"]["patch"]["sha256"],
        "compiler": compiler,
        "compiler_version": compiler_version,
        "canary": {
            "passed": canary_passed,
            "argv": canary_argv,
            "runtime_seconds": canary_seconds,
            "returncode": canary_result.returncode,
            "finding_count": len(variable_latency),
            "dropped_valgrind_messages": canary_dropped,
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
) -> tuple[dict[str, Any], Path]:
    capability = _capability("official_dudect")
    output_dir = _new_output_dir(output_root, "official_dudect")
    if capability[0] == "unsupported":
        rows = [
            _base_row(manifest, case_id, "official_dudect", capability) for case_id in CASE_ORDER
        ]
        record = _record(
            manifest,
            manifest_path,
            "official_dudect",
            rows,
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
    )
    runtime_seconds = time.monotonic() - started
    _emit_dudect_report(config.project.name, raw_dir, results)

    virtualization = _detect_virtualization()
    virtualized = bool(virtualization["vm"] or virtualization["container"])
    physical_eligible = (
        not detect_qemu_emulation()
        and not virtualized
        and all(result.timing_validity == "valid" for _, _, result, _ in results)
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
        errors.append("official dudect run did not clear the physical-host validity gate")

    record = _record(
        manifest,
        manifest_path,
        "official_dudect",
        rows,
        timing_evidence=physical_eligible,
        backend={
            "official_dudect_revision": OFFICIAL_DUDECT_REVISION,
            "virtualization": virtualization,
            "raw_report": str((raw_dir / "dudect_backend_report.json").relative_to(output_dir)),
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


def run_microwalk(
    manifest: dict[str, Any],
    manifest_path: Path,
    *,
    output_root: Path,
    timeout: int,
) -> tuple[dict[str, Any], Path]:
    capability = _capability("microwalk_pin")
    output_dir = _new_output_dir(output_root, "microwalk_pin")
    if capability[0] == "unsupported":
        rows = [_base_row(manifest, case_id, "microwalk_pin", capability) for case_id in CASE_ORDER]
        record = _record(
            manifest,
            manifest_path,
            "microwalk_pin",
            rows,
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
        if build_result is not None and build_result.returncode == 0:
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
            or map_result is None
            or map_result.returncode != 0
        )
        if setup_failed:
            row["execution_status"] = (
                "timeout" if build_timeout is not None or map_timeout is not None else "error"
            )
            row["outcome"] = "inconclusive"
            row["artifact_bytes"] = _tree_bytes(case_dir)
            errors.append(f"{case_id}: MicroWalk build/MAP setup failed")
            row["evidence"] = {
                "build_argv": build_command,
                "map_argv": map_command,
                "build_returncode": (None if build_result is None else build_result.returncode),
                "map_returncode": None if map_result is None else map_result.returncode,
                "build_streams": build_streams,
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
            "map_argv": map_command,
            "run_argv": run_command,
            "build_streams": build_streams,
            "map_streams": map_streams,
            "run_streams": run_streams,
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
            )
            if result_errors:
                raise BaselineError("result validation failed: " + "; ".join(result_errors))
            print(f"[same-corpus] valid result: {args.validate_result}")
            return 0
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
            )
        elif args.run_dudect:
            record, report = run_dudect(
                manifest,
                manifest_path,
                output_root=args.output_root,
            )
        else:
            record, report = run_microwalk(
                manifest,
                manifest_path,
                output_root=args.output_root,
                timeout=args.microwalk_timeout,
            )
        print(f"[same-corpus] report: {report}")
        print(f"[same-corpus] promotion_ready={record['promotion_ready']}")
        for error in record["errors"]:
            print(f"[same-corpus] ERROR: {error}", file=sys.stderr)
        return 0 if record["promotion_ready"] else 1
    except (
        BaselineError,
        json.JSONDecodeError,
        OSError,
        subprocess.SubprocessError,
        ValueError,
    ) as exc:
        print(f"[same-corpus] ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
