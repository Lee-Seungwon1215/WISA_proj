"""Fail-closed post-link instruction contracts for measured timing binaries.

Source text is not executable evidence: an optimizer may strength-reduce a
constant division, introduce a helper call, or clone a function.  This module
checks the exact linked timing binary before the first sample is collected and
preserves the complete disassembly and build provenance used for that check.
"""

from __future__ import annotations

import hashlib
import json
import platform
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml


class TimingBinaryContractError(RuntimeError):
    """The binary could not be proven to satisfy its frozen contract."""


_SYMBOL_HEADER = re.compile(r"^[0-9A-Fa-f]+ <([^>]+)>:$")
_DIVISION_INSTRUCTION = re.compile(r"\b(?:idiv|div)(?:[bwlq])?\b", re.IGNORECASE)
_DIVISION_HELPER = re.compile(r"\b(?:__u?div(?:di|si)3|__aeabi_[ul]?div)\b")
_CONTROL_FLOW_TARGET = re.compile(r"<([^>]+)>")
_X87_ARITHMETIC = re.compile(
    r"^f(?:add|sub|subr|mul|div|divr|sqrt|prem|prem1|scale|yl2x|yl2xp1|2xm1|sin|cos|ptan|patan)(?:p|l|s)?$"
)
_SIMD_FP_ARITHMETIC = re.compile(
    r"^v?(?:(?:add|sub|mul|div|sqrt|max|min|rcp|rsqrt|hadd|hsub|dpp|round)"
    r"(?:ps|pd|ss|sd)|(?:fmadd|fmsub|fnmadd|fnmsub)\w*|(?:u?comi)(?:ss|sd)|cvt\w+)$"
)
_HEX64 = re.compile(r"[0-9a-f]{64}")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _regular_file(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise TimingBinaryContractError(f"{label} must be a regular non-symlink file: {path}")


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TimingBinaryContractError(f"{label} must be a mapping")
    return value


def _only_keys(value: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise TimingBinaryContractError(f"{label} contains unknown keys: {unknown}")


def load_timing_binary_contract(
    manifest_path: Path,
    target: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load and strictly validate one rule set from a contract manifest."""

    _regular_file(manifest_path, "binary contract manifest")
    try:
        raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise TimingBinaryContractError(f"cannot load binary contract: {exc}") from exc
    root = _mapping(raw, "binary contract")
    _only_keys(
        root,
        {
            "schema_version",
            "kind",
            "contract_id",
            "system",
            "machines",
            "disassembler",
            "file_format_pattern",
            "targets",
        },
        "binary contract",
    )
    if root.get("schema_version") != "1.0":
        raise TimingBinaryContractError("binary contract schema_version must be '1.0'")
    if root.get("kind") != "ctkat-timing-binary-instruction-contract":
        raise TimingBinaryContractError("binary contract kind is invalid")
    if not isinstance(root.get("contract_id"), str) or not root["contract_id"]:
        raise TimingBinaryContractError("binary contract_id must be non-empty")
    if root.get("system") != "Linux":
        raise TimingBinaryContractError("binary contract system must be Linux")
    machines = root.get("machines")
    if (
        not isinstance(machines, list)
        or not machines
        or any(not isinstance(item, str) or not item for item in machines)
    ):
        raise TimingBinaryContractError("binary contract machines must be a string list")
    if root.get("disassembler") != "objdump":
        raise TimingBinaryContractError("binary contract disassembler must be objdump")
    try:
        re.compile(str(root.get("file_format_pattern", "")))
    except re.error as exc:
        raise TimingBinaryContractError(f"invalid file_format_pattern: {exc}") from exc

    targets = _mapping(root.get("targets"), "binary contract targets")
    if target not in targets:
        raise TimingBinaryContractError(f"binary contract target {target!r} is absent")
    rule = _mapping(targets[target], f"binary contract target {target}")
    _only_keys(
        rule,
        {"compiler", "cflags", "symbols", "evidence_boundary", "comparison_group"},
        f"binary contract target {target}",
    )
    if rule.get("compiler") != "gcc":
        raise TimingBinaryContractError(f"{target}: compiler must be gcc")
    cflags = rule.get("cflags")
    if not isinstance(cflags, list) or any(not isinstance(flag, str) for flag in cflags):
        raise TimingBinaryContractError(f"{target}: cflags must be a string list")
    symbols = _mapping(rule.get("symbols"), f"{target}.symbols")
    if not symbols:
        raise TimingBinaryContractError(f"{target}: at least one symbol rule is required")
    for symbol, value in symbols.items():
        if not isinstance(symbol, str) or not symbol:
            raise TimingBinaryContractError(f"{target}: symbol names must be non-empty")
        symbol_rule = _mapping(value, f"{target}.symbols[{symbol!r}]")
        _only_keys(
            symbol_rule,
            {
                "present",
                "division_count",
                "forbid_division_helpers",
                "floating_point",
                "required_call_targets",
                "required_tail_targets",
            },
            symbol,
        )
        present = symbol_rule.get("present", True)
        if not isinstance(present, bool):
            raise TimingBinaryContractError(f"{target}/{symbol}: present must be boolean")
        division_count = symbol_rule.get("division_count")
        floating_point = symbol_rule.get("floating_point")
        call_targets = symbol_rule.get("required_call_targets")
        tail_targets = symbol_rule.get("required_tail_targets")
        if not present:
            if set(symbol_rule) != {"present"}:
                raise TimingBinaryContractError(
                    f"{target}/{symbol}: present=false cannot carry instruction rules"
                )
            continue
        if (
            division_count is None
            and floating_point is None
            and call_targets is None
            and tail_targets is None
        ):
            raise TimingBinaryContractError(
                f"{target}/{symbol}: at least one instruction rule is required"
            )
        if division_count is not None and (
            isinstance(division_count, bool)
            or not isinstance(division_count, int)
            or division_count < 0
        ):
            raise TimingBinaryContractError(f"{target}/{symbol}: division_count is invalid")
        forbid_helpers = symbol_rule.get("forbid_division_helpers")
        if division_count is not None and forbid_helpers is not True:
            raise TimingBinaryContractError(
                f"{target}/{symbol}: forbid_division_helpers must be true"
            )
        if division_count is None and forbid_helpers is not None and forbid_helpers is not True:
            raise TimingBinaryContractError(
                f"{target}/{symbol}: forbid_division_helpers must be true when present"
            )
        if floating_point is not None:
            fp_rule = _mapping(floating_point, f"{target}/{symbol}.floating_point")
            _only_keys(fp_rule, {"min_count", "max_count"}, f"{symbol}.floating_point")
            min_count = fp_rule.get("min_count")
            max_count = fp_rule.get("max_count")
            for label, count in (("min_count", min_count), ("max_count", max_count)):
                if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                    raise TimingBinaryContractError(
                        f"{target}/{symbol}.floating_point.{label} is invalid"
                    )
            assert isinstance(min_count, int) and not isinstance(min_count, bool)
            assert isinstance(max_count, int) and not isinstance(max_count, bool)
            if min_count > max_count:
                raise TimingBinaryContractError(
                    f"{target}/{symbol}.floating_point min_count exceeds max_count"
                )
        for label, targets_value in (
            ("required_call_targets", call_targets),
            ("required_tail_targets", tail_targets),
        ):
            if targets_value is None:
                continue
            if (
                not isinstance(targets_value, list)
                or not targets_value
                or any(not isinstance(item, str) or not item for item in targets_value)
                or len(set(targets_value)) != len(targets_value)
            ):
                raise TimingBinaryContractError(
                    f"{target}/{symbol}.{label} must be a non-empty unique string list"
                )
    return root, rule


def split_disassembly_symbols(disassembly: str) -> dict[str, list[str]]:
    """Return exact objdump symbol blocks, excluding their heading lines."""

    blocks: dict[str, list[str]] = {}
    current: str | None = None
    for line in disassembly.splitlines():
        match = _SYMBOL_HEADER.match(line.strip())
        if match:
            current = match.group(1)
            blocks.setdefault(current, [])
            continue
        if current is not None:
            blocks[current].append(line)
    return blocks


def _instruction_mnemonic(line: str) -> str:
    """Extract a GNU-objdump mnemonic with or without raw instruction bytes."""

    if ":" not in line:
        return ""
    tail = line.split(":", 1)[1].strip()
    if not tail:
        return ""
    tab_fields = [field.strip() for field in tail.split("\t") if field.strip()]
    instruction = tab_fields[-1] if tab_fields else tail
    # A raw-byte field can collapse into the instruction field on unusual
    # objdump builds. Drop leading two-digit byte tokens conservatively.
    tokens = instruction.split()
    while tokens and re.fullmatch(r"[0-9A-Fa-f]{2}", tokens[0]):
        tokens.pop(0)
    return tokens[0].lower() if tokens else ""


def _is_floating_point_arithmetic(mnemonic: str) -> bool:
    return bool(_X87_ARITHMETIC.fullmatch(mnemonic) or _SIMD_FP_ARITHMETIC.fullmatch(mnemonic))


def _control_flow_targets(lines: list[str], mnemonics: set[str]) -> list[str]:
    """Return exact GNU-objdump targets for selected control-flow opcodes."""

    targets: list[str] = []
    for line in lines:
        if _instruction_mnemonic(line) not in mnemonics:
            continue
        match = _CONTROL_FLOW_TARGET.search(line)
        if match:
            targets.append(match.group(1))
    return targets


def evaluate_disassembly(
    disassembly: str,
    symbol_rules: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Evaluate exact symbol-local div/idiv counts and helper-call absence."""

    blocks = split_disassembly_symbols(disassembly)
    observations: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for symbol, rule_value in symbol_rules.items():
        rule = dict(rule_value)
        lines = blocks.get(symbol)
        expected_present = rule.get("present", True)
        if lines is None:
            observations[symbol] = {
                "present": False,
                "expected_present": expected_present,
                "division_count": None,
                "division_lines": [],
                "division_helper_lines": [],
                "floating_point_arithmetic_count": None,
                "floating_point_arithmetic_lines": [],
                "call_targets": [],
                "tail_targets": [],
            }
            if expected_present:
                errors.append(f"required symbol absent from linked binary: {symbol}")
            continue
        division_lines = [line.strip() for line in lines if _DIVISION_INSTRUCTION.search(line)]
        helper_lines = [line.strip() for line in lines if _DIVISION_HELPER.search(line)]
        floating_lines = [
            line.strip()
            for line in lines
            if _is_floating_point_arithmetic(_instruction_mnemonic(line))
        ]
        call_targets = _control_flow_targets(lines, {"call", "callq"})
        tail_targets = _control_flow_targets(lines, {"jmp", "jmpq"})
        actual = len(division_lines)
        expected_value = rule.get("division_count")
        observations[symbol] = {
            "present": True,
            "expected_present": expected_present,
            "division_count": actual,
            "expected_division_count": expected_value,
            "division_lines": division_lines,
            "division_helper_lines": helper_lines,
            "floating_point_arithmetic_count": len(floating_lines),
            "floating_point_arithmetic_lines": floating_lines,
            "call_targets": call_targets,
            "tail_targets": tail_targets,
        }
        if not expected_present:
            errors.append(f"forbidden symbol present in linked binary: {symbol}")
            continue
        if expected_value is not None and actual != int(expected_value):
            errors.append(f"{symbol}: exact div/idiv count={actual}, expected={expected_value}")
        if rule.get("forbid_division_helpers") and helper_lines:
            errors.append(f"{symbol}: compiler division helper call is forbidden")
        fp_rule = rule.get("floating_point")
        if isinstance(fp_rule, dict):
            fp_count = len(floating_lines)
            minimum = int(fp_rule["min_count"])
            maximum = int(fp_rule["max_count"])
            if not minimum <= fp_count <= maximum:
                errors.append(
                    f"{symbol}: floating-point arithmetic count={fp_count}, "
                    f"expected range=[{minimum},{maximum}]"
                )
        for label, actual_targets in (
            ("required_call_targets", call_targets),
            ("required_tail_targets", tail_targets),
        ):
            required_targets = rule.get(label, [])
            missing_targets = sorted(set(required_targets) - set(actual_targets))
            if missing_targets:
                errors.append(
                    f"{symbol}: missing {label}={missing_targets}; observed={actual_targets}"
                )
    return observations, errors


def _run(command: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise TimingBinaryContractError(f"command failed to execute: {command}: {exc}") from exc


def _file_record(path: Path) -> dict[str, Any]:
    _regular_file(path, "provenance input")
    return {"path": str(path.resolve()), "sha256": _sha256(path), "bytes": path.stat().st_size}


def verify_timing_binary_contract(
    *,
    manifest_path: Path,
    target: str,
    binary_path: Path,
    generated_source_path: Path,
    config_path: Path | None,
    source_paths: Iterable[Path],
    compiler: str,
    cflags: list[str],
    compile_command: str,
    output_dir: Path,
) -> Path:
    """Verify the exact linked binary and write immutable audit-side artifacts.

    The JSON report is written even on a contract mismatch.  The mismatch is
    then raised so callers cannot start timing and accidentally promote a
    binary whose division sites were optimized away.
    """

    root, rule = load_timing_binary_contract(manifest_path, target)
    for path, label in (
        (binary_path, "timing binary"),
        (generated_source_path, "generated timing source"),
    ):
        _regular_file(path, label)
    if config_path is not None:
        _regular_file(config_path, "CT-KAT config")
    resolved_sources = [path.resolve() for path in source_paths]
    if len(resolved_sources) != len(set(resolved_sources)):
        raise TimingBinaryContractError("linked source list contains duplicates")
    for path in resolved_sources:
        _regular_file(path, "linked source")

    errors: list[str] = []
    accepted_machines = {item.lower() for item in root["machines"]}
    if platform.system() != root["system"]:
        errors.append(f"host system={platform.system()!r}, expected={root['system']!r}")
    if platform.machine().lower() not in accepted_machines:
        errors.append(
            f"host machine={platform.machine()!r}, expected one of {sorted(accepted_machines)}"
        )
    if compiler != rule["compiler"]:
        errors.append(f"compiler command={compiler!r}, expected={rule['compiler']!r}")
    if cflags != rule["cflags"]:
        errors.append(f"compiler flags={cflags!r}, expected exact {rule['cflags']!r}")

    compiler_executable_value = shutil.which(compiler)
    if not compiler_executable_value:
        raise TimingBinaryContractError(f"compiler unavailable for provenance: {compiler}")
    compiler_executable = Path(compiler_executable_value).resolve()
    _regular_file(compiler_executable, "compiler executable")
    compiler_version_command = [str(compiler_executable), "--version"]
    compiler_version_proc = _run(compiler_version_command)
    if compiler_version_proc.returncode != 0 or not compiler_version_proc.stdout.strip():
        raise TimingBinaryContractError("compiler --version failed")

    objdump_value = shutil.which(root["disassembler"])
    if not objdump_value:
        raise TimingBinaryContractError("GNU objdump is unavailable")
    objdump = Path(objdump_value).resolve()
    _regular_file(objdump, "objdump executable")
    objdump_version_command = [str(objdump), "--version"]
    objdump_version_proc = _run(objdump_version_command)
    if objdump_version_proc.returncode != 0 or not objdump_version_proc.stdout.strip():
        raise TimingBinaryContractError("objdump --version failed")
    header_command = [str(objdump), "-f", str(binary_path.resolve())]
    header_proc = _run(header_command)
    if header_proc.returncode != 0:
        raise TimingBinaryContractError(f"objdump -f failed: {header_proc.stderr.strip()}")
    format_pattern = str(root["file_format_pattern"])
    if not re.search(format_pattern, header_proc.stdout):
        errors.append(
            f"linked binary format does not match /{format_pattern}/: {header_proc.stdout.strip()}"
        )

    disassembly_command = [str(objdump), "-d", str(binary_path.resolve())]
    disassembly_proc = _run(disassembly_command)
    if disassembly_proc.returncode != 0 or not disassembly_proc.stdout.strip():
        raise TimingBinaryContractError(
            f"objdump disassembly failed: {disassembly_proc.stderr.strip()}"
        )
    observations, instruction_errors = evaluate_disassembly(
        disassembly_proc.stdout,
        rule["symbols"],
    )
    errors.extend(instruction_errors)

    if output_dir.is_symlink():
        raise TimingBinaryContractError(f"binary contract output dir is a symlink: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    disassembly_path = output_dir / f"{binary_path.name}.objdump.txt"
    header_path = output_dir / f"{binary_path.name}.objdump-file-header.txt"
    report_path = output_dir / f"{binary_path.name}.binary-contract.json"
    disassembly_path.write_text(disassembly_proc.stdout, encoding="utf-8")
    header_path.write_text(header_proc.stdout, encoding="utf-8")

    source_records = [_file_record(path) for path in resolved_sources]
    compiler_record = _file_record(compiler_executable)
    compiler_record["version_command"] = compiler_version_command
    objdump_record = _file_record(objdump)
    objdump_record.update(
        {
            "version": objdump_version_proc.stdout.splitlines()[0],
            "version_command": objdump_version_command,
        }
    )
    payload = {
        "schema_version": "1.0",
        "kind": "ctkat-timing-binary-contract-report",
        "created_at": _utc_now(),
        "contract_id": root["contract_id"],
        "contract_target": target,
        "contract_manifest": _file_record(manifest_path.resolve()),
        "comparison_group": rule.get("comparison_group"),
        "evidence_boundary": rule.get("evidence_boundary"),
        "passed": not errors,
        "errors": errors,
        "binary": _file_record(binary_path.resolve()),
        "generated_source": _file_record(generated_source_path.resolve()),
        "config": _file_record(config_path.resolve()) if config_path is not None else None,
        "linked_sources": source_records,
        "compiler": {
            "requested_command": compiler,
            "executable": compiler_record,
            "version": compiler_version_proc.stdout.splitlines()[0],
            "cflags": cflags,
            "compile_command": compile_command,
        },
        "disassembly": {
            "tool": objdump_record,
            "command": disassembly_command,
            "full_path": str(disassembly_path.resolve()),
            "full_artifact": disassembly_path.name,
            "full_sha256": _sha256(disassembly_path),
            "file_header_command": header_command,
            "file_header_path": str(header_path.resolve()),
            "file_header_artifact": header_path.name,
            "file_header_sha256": _sha256(header_path),
            "symbols": observations,
        },
    }
    report_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    report_hash = _sha256(report_path)
    if not _HEX64.fullmatch(report_hash):  # defensive invariant
        raise TimingBinaryContractError("binary contract report hashing failed")
    if errors:
        raise TimingBinaryContractError(
            f"timing binary contract {target!r} rejected linked binary; "
            f"report={report_path}: {'; '.join(errors)}"
        )
    return report_path
