#!/usr/bin/env python3
"""Validate and execute the independent native-upstream build corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.check_third_party import tree_sha256  # noqa: E402

MANIFEST_PATH = ROOT / "docs/corpus/diverse_upstreams_v1.yaml"
PLAN_PATH = ROOT / "docs/corpus/independent_upstreams_v1.yaml"
RESULT_SCHEMA_PATH = ROOT / "docs/corpus/diverse-build-result-v1.schema.json"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
ARCH_ALIASES = {
    "amd64": "x86_64",
    "x86_64": "x86_64",
    "aarch64": "aarch64",
    "arm64": "aarch64",
}
MACHINE_MARKERS = {
    "x86_64": ("X86-64", "x86-64"),
    "aarch64": ("AArch64",),
}


def load_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("diverse-upstream manifest root must be a mapping")
    return data


def _repo_path(value: str) -> Path:
    path = (ROOT / value).resolve()
    try:
        path.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError(f"path escapes repository: {value}") from exc
    return path


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _command_text(command: list[str]) -> str:
    return " ".join(command)


def _run(
    command: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = 180,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    if result.returncode != 0:
        stdout = result.stdout.decode("utf-8", errors="replace")[-4000:]
        stderr = result.stderr.decode("utf-8", errors="replace")[-8000:]
        raise RuntimeError(
            f"command failed ({result.returncode}): {_command_text(command)}\n"
            f"stdout:\n{stdout}\nstderr:\n{stderr}"
        )
    return result


def _normal_arch(machine: str | None = None) -> str:
    raw = (machine or platform.machine()).lower()
    try:
        return ARCH_ALIASES[raw]
    except KeyError as exc:
        raise ValueError(f"unsupported architecture: {raw}") from exc


def _cpu_features() -> list[str]:
    cpuinfo = Path("/proc/cpuinfo")
    if not cpuinfo.is_file():
        return []
    features: set[str] = set()
    for line in cpuinfo.read_text(encoding="utf-8", errors="replace").splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip().lower() in {"flags", "features"}:
            features.update(value.strip().lower().split())
    return sorted(features)


def _host_record() -> dict[str, Any]:
    return {
        "system": platform.system(),
        "machine": platform.machine(),
        "release": platform.release(),
        "cpu_features": _cpu_features(),
    }


def _git_commit() -> str:
    return _run(["git", "rev-parse", "HEAD"], cwd=ROOT).stdout.decode().strip()


def _compiler_version(compiler: str) -> str:
    output = _run([compiler, "--version"]).stdout.decode("utf-8", errors="replace")
    return output.splitlines()[0]


def _readelf_machine(path: Path) -> str:
    output = _run(["readelf", "-h", str(path)]).stdout.decode("utf-8", errors="replace")
    match = re.search(r"^\s*Machine:\s*(.+?)\s*$", output, re.MULTILINE)
    if match is None:
        raise RuntimeError(f"readelf did not report a machine for {path}")
    return match.group(1)


def _defined_asm_symbols(path: Path, suffix: str) -> list[str]:
    output = _run(["nm", "-g", "--defined-only", str(path)]).stdout.decode(
        "utf-8", errors="replace"
    )
    symbols = []
    for line in output.splitlines():
        fields = line.split()
        if fields and suffix in fields[-1]:
            symbols.append(fields[-1])
    return sorted(set(symbols))


def _instruction_markers(path: Path, candidates: list[str]) -> list[str]:
    output = _run(["objdump", "-d", str(path)]).stdout.decode("utf-8", errors="replace")
    lowered = output.lower()
    return sorted(marker for marker in candidates if re.search(rf"\b{marker}\b", lowered))


def _load_meta_kats(source_root: Path) -> dict[str, str]:
    data = yaml.safe_load((source_root / "META.yml").read_text(encoding="utf-8"))
    implementations = data.get("implementations", []) if isinstance(data, dict) else []
    result: dict[str, str] = {}
    for item in implementations:
        if isinstance(item, dict):
            name = item.get("name")
            digest = item.get("kat-sha256")
            if isinstance(name, str) and isinstance(digest, str):
                result[name] = digest
    return result


def validate_static(manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if manifest.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if manifest.get("status") != "imported-build-gated-needs-review":
        errors.append("manifest status must remain imported-build-gated-needs-review")

    scope = manifest.get("claim_scope", {})
    if scope.get("timing_evidence") != "none":
        errors.append("source/build corpus must not claim timing evidence")
    if scope.get("conformance_claim") != "none":
        errors.append("source/build corpus must not claim conformance")

    counting = manifest.get("counting", {})
    if counting.get("newly_imported_lineages") != ["mlkem-native", "mldsa-native"]:
        errors.append("new lineage list must be mlkem-native then mldsa-native")
    if counting.get("total_primary_upstream_lineages") != 4:
        errors.append("total primary-upstream lineage count must remain 4")
    for dimension in ("parameters", "profiles", "compilers", "integrations"):
        if counting.get(f"{dimension}_count_as_lineages") is not False:
            errors.append(f"{dimension} must not count as primary lineages")
    if "unmeasured" not in str(counting.get("ancestry_limit", "")):
        errors.append("counting ancestry limit must preserve the unmeasured fraction")

    lineages = manifest.get("lineages", {})
    if set(lineages) != {"mlkem-native", "mldsa-native"}:
        errors.append("lineages must define exactly mlkem-native and mldsa-native")
        return errors

    for lineage_id, record in lineages.items():
        revision = str(record.get("revision", ""))
        digest = str(record.get("tree_sha256", ""))
        if not REVISION_RE.fullmatch(revision):
            errors.append(f"{lineage_id}: revision must be a full lowercase commit")
        if not SHA256_RE.fullmatch(digest):
            errors.append(f"{lineage_id}: tree_sha256 must be lowercase SHA-256")
        if record.get("patch_sha256") != []:
            errors.append(f"{lineage_id}: imported tree must have an explicit empty patch set")
        if record.get("shared_code_fraction") != "unmeasured":
            errors.append(f"{lineage_id}: shared-code fraction must remain unmeasured")

        try:
            source_root = _repo_path(record["import_path"])
        except (KeyError, ValueError) as exc:
            errors.append(f"{lineage_id}: bad import path: {exc}")
            continue
        if not source_root.is_dir():
            errors.append(f"{lineage_id}: missing import tree {source_root}")
            continue
        actual_tree = tree_sha256(source_root)
        if actual_tree != digest:
            errors.append(
                f"{lineage_id}: vendored tree drift (expected {digest}, got {actual_tree})"
            )

        for relative in record.get("upstream_paths", []):
            if not (source_root / str(relative)).exists():
                errors.append(f"{lineage_id}: missing imported upstream path {relative}")
        for field in (
            "license_file",
            "provenance_file",
            "smoke_adapter",
        ):
            try:
                path = _repo_path(record[field])
            except (KeyError, ValueError) as exc:
                errors.append(f"{lineage_id}: bad {field}: {exc}")
                continue
            if not path.is_file():
                errors.append(f"{lineage_id}: missing {field} {path}")

        provenance_path = _repo_path(record["provenance_file"])
        if provenance_path.is_file():
            provenance = provenance_path.read_text(encoding="utf-8")
            for expected in (revision, digest, record["import_path"]):
                if expected not in provenance:
                    errors.append(f"{lineage_id}: provenance file does not contain {expected}")

        meta_kats = _load_meta_kats(source_root)
        parameters = record.get("parameters", {})
        if len(parameters) != 3:
            errors.append(f"{lineage_id}: exactly three parameters are required")
        for parameter, parameter_record in parameters.items():
            identity = parameter_record.get("identity")
            expected_kat = parameter_record.get("kat_sha256")
            if not SHA256_RE.fullmatch(str(expected_kat)):
                errors.append(f"{lineage_id}/{parameter}: bad KAT SHA-256")
            if meta_kats.get(identity) != expected_kat:
                errors.append(
                    f"{lineage_id}/{parameter}: manifest KAT does not match imported META.yml"
                )

        prefix = record.get("config_prefix")
        smoke_text = _repo_path(record["smoke_adapter"]).read_text(encoding="utf-8")
        if f"{prefix}_CONFIG_PARAMETER_SET" in smoke_text:
            errors.append(
                f"{lineage_id}: adapter must consume the build parameter, not redefine it"
            )

    mldsa = lineages["mldsa-native"]
    if mldsa.get("release_status") != "beta" or "Beta" not in str(mldsa.get("claim_limit", "")):
        errors.append("mldsa-native beta status and claim limit must remain explicit")

    integrations = manifest.get("integrations", {})
    if set(integrations) != {"openssl-3.5-pqc-api"}:
        errors.append("exactly one OpenSSL integration case is required")
    else:
        openssl = integrations["openssl-3.5-pqc-api"]
        if openssl.get("counts_as_lineage") is not False:
            errors.append("OpenSSL integration must not count as a lineage")
        for field in ("artifact_sha256", "expected_transcript_sha256"):
            if not SHA256_RE.fullmatch(str(openssl.get(field, ""))):
                errors.append(f"OpenSSL {field} must be lowercase SHA-256")
        if (
            openssl.get("release") != "openssl-3.5.7"
            or openssl.get("revision") != "8cf17aaeb4599f8af87fefd810b5b5fee90fe69e"
        ):
            errors.append("OpenSSL integration must remain pinned to 3.5.7 exact commit")
        for field in ("provenance_file", "adapter"):
            path = _repo_path(openssl[field])
            if not path.is_file():
                errors.append(f"OpenSSL integration missing {field}: {path}")
        provenance_path = _repo_path(openssl["provenance_file"])
        if provenance_path.is_file():
            provenance = provenance_path.read_text(encoding="utf-8")
            for expected in (
                openssl["revision"],
                openssl["artifact_sha256"],
                openssl["artifact_url"],
            ):
                if expected not in provenance:
                    errors.append(f"OpenSSL provenance does not contain {expected}")

    contract = manifest.get("build_contract", {})
    profiles = contract.get("profiles", [])
    compilers = contract.get("compilers", [])
    optimizations = contract.get("optimizations", {})
    architectures = contract.get("architectures", {})
    if profiles != ["portable", "architecture-native"]:
        errors.append("build profiles must be portable and architecture-native")
    if compilers != ["gcc", "clang"]:
        errors.append("build compilers must be gcc and clang")
    if list(optimizations) != ["debug", "O1", "O2", "O3", "Os"]:
        errors.append("optimization matrix must preserve debug/O1/O2/O3/Os order")
    if set(architectures) != {"x86_64", "aarch64"}:
        errors.append("architecture matrix must define x86_64 and aarch64")
    parameter_count = sum(len(record["parameters"]) for record in lineages.values())
    expected_per_arch = parameter_count * len(profiles) * len(compilers) * len(optimizations)
    if contract.get("expected_cells_per_architecture") != expected_per_arch:
        errors.append("expected_cells_per_architecture does not match the declared dimensions")
    if contract.get("expected_cells_all_architectures") != expected_per_arch * len(architectures):
        errors.append("all-architecture build-cell count does not match dimensions")
    if contract.get("timing_evidence") is not False:
        errors.append("build contract must explicitly reject timing evidence")

    review = manifest.get("review_gate", {})
    if review.get("status") != "needs-review" or review.get("minimum_reviewers") != 2:
        errors.append("two-person needs-review gate must remain active")
    if review.get("automatic_clean_promotion") is not False:
        errors.append("automatic clean promotion must remain disabled")

    try:
        schema = json.loads(RESULT_SCHEMA_PATH.read_text(encoding="utf-8"))
        if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            errors.append("result schema must use JSON Schema draft 2020-12")
        if len(schema.get("oneOf", [])) != 2:
            errors.append("result schema must cover native matrix and OpenSSL integration")
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"cannot load result schema: {exc}")

    if PLAN_PATH.is_file():
        plan = yaml.safe_load(PLAN_PATH.read_text(encoding="utf-8"))
        if not isinstance(plan, dict):
            errors.append("independent upstream plan root must be a mapping")
        else:
            current_ids = {
                item.get("id")
                for item in plan.get("current_lineages", [])
                if isinstance(item, dict) and item.get("imported") is True
            }
            if current_ids != {"pqclean", "c-fn-dsa", "mlkem-native", "mldsa-native"}:
                errors.append("independent plan must list exactly four imported lineages")
            implemented = plan.get("implemented_contract", {})
            if implemented.get("build_cells_per_architecture") != 120:
                errors.append("independent plan build-cell count must remain 120 per arch")
            if implemented.get("timing_evidence") is not False:
                errors.append("independent plan cannot promote build artifacts to timing")
    else:
        errors.append("independent upstream plan is missing")
    return errors


def _cell_flags(
    record: dict[str, Any],
    parameter: str,
    profile: str,
    architecture: str,
    optimization_flags: list[str],
) -> list[str]:
    prefix = str(record["config_prefix"])
    flags = [
        "-std=c99",
        "-Wall",
        "-Wextra",
        "-Werror=unused-result",
        "-Wno-unused-command-line-argument",
        "-Wno-unknown-pragmas",
        *optimization_flags,
        f"-D{prefix}_CONFIG_PARAMETER_SET={parameter}",
    ]
    if profile == "architecture-native":
        flags.extend(
            [
                f"-D{prefix}_CONFIG_USE_NATIVE_BACKEND_ARITH",
                f"-D{prefix}_CONFIG_USE_NATIVE_BACKEND_FIPS202",
                f"-D{prefix}_FORCE_{architecture.upper()}",
            ]
        )
        if architecture == "x86_64":
            flags.extend(["-mavx2", "-mbmi2"])
    return flags


def _compile_object(
    compiler: str,
    flags: list[str],
    include_dir: Path,
    source: Path,
    destination: Path,
) -> list[str]:
    command = [
        compiler,
        *flags,
        f"-I{include_dir}",
        "-c",
        str(source),
        "-o",
        str(destination),
    ]
    _run(command, timeout=300)
    return command


def _compile_cell(
    manifest: dict[str, Any],
    lineage_id: str,
    record: dict[str, Any],
    parameter: str,
    profile: str,
    compiler: str,
    optimization: str,
    architecture: str,
    output_root: Path,
) -> dict[str, Any]:
    contract = manifest["build_contract"]
    arch_contract = contract["architectures"][architecture]
    source_root = _repo_path(record["import_path"])
    core_source = source_root / record["monolithic_c"]
    asm_source = source_root / record["monolithic_asm"]
    algorithm_dir = core_source.parent
    rng_source = source_root / "test/notrandombytes/notrandombytes.c"
    smoke_source = _repo_path(record["smoke_adapter"])
    kat_source = source_root / record["kat_adapter"]
    opt_flags = [str(item) for item in contract["optimizations"][optimization]]
    flags = _cell_flags(record, parameter, profile, architecture, opt_flags)
    cell_id = "-".join([lineage_id, parameter, architecture, profile, compiler, optimization])
    cell_dir = output_root / "artifacts" / cell_id
    cell_dir.mkdir(parents=True, exist_ok=False)

    core_object = cell_dir / "core.o"
    rng_object = cell_dir / "notrandombytes.o"
    smoke_object = cell_dir / "smoke.o"
    objects = [core_object]
    core_command = _compile_object(compiler, flags, algorithm_dir, core_source, core_object)
    if profile == "architecture-native":
        asm_object = cell_dir / "native.o"
        _compile_object(compiler, flags, algorithm_dir, asm_source, asm_object)
        objects.append(asm_object)
    else:
        asm_object = core_object
    _compile_object(compiler, flags, algorithm_dir, rng_source, rng_object)
    _compile_object(compiler, flags, algorithm_dir, smoke_source, smoke_object)
    objects.extend([rng_object, smoke_object])

    binary = cell_dir / "deterministic-smoke"
    _run([compiler, *(str(path) for path in objects), "-o", str(binary)], timeout=300)
    transcript = _run([str(binary)], timeout=300).stdout

    suffix = str(arch_contract["asm_symbol_suffix"])
    symbols = _defined_asm_symbols(asm_object, suffix)
    markers = (
        []
        if profile == "portable"
        else _instruction_markers(
            asm_object, [str(item) for item in arch_contract["instruction_markers"]]
        )
    )
    if profile == "portable":
        if symbols:
            raise RuntimeError(f"{cell_id}: portable object contains native symbols")
    else:
        if not symbols:
            raise RuntimeError(f"{cell_id}: optimized object lacks {suffix} symbols")
        if not markers:
            raise RuntimeError(f"{cell_id}: optimized object lacks instruction markers")

    machine = _readelf_machine(binary)
    if not any(marker in machine for marker in MACHINE_MARKERS[architecture]):
        raise RuntimeError(f"{cell_id}: artifact machine {machine!r} does not match {architecture}")

    kat_sha256: str | None = None
    if compiler == "gcc" and optimization == "O2":
        kat_object = cell_dir / "upstream-kat.o"
        _compile_object(compiler, flags, algorithm_dir, kat_source, kat_object)
        kat_binary = cell_dir / "upstream-kat"
        kat_objects = [core_object]
        if profile == "architecture-native":
            kat_objects.append(asm_object)
        kat_objects.extend([rng_object, kat_object])
        _run(
            [compiler, *(str(path) for path in kat_objects), "-o", str(kat_binary)],
            timeout=300,
        )
        kat_output = _run([str(kat_binary)], timeout=600).stdout
        kat_sha256 = _sha256_bytes(kat_output)
        expected_kat = str(record["parameters"][parameter]["kat_sha256"])
        if kat_sha256 != expected_kat:
            raise RuntimeError(f"{cell_id}: upstream KAT mismatch: {kat_sha256} != {expected_kat}")

    return {
        "id": cell_id,
        "lineage": lineage_id,
        "parameter": parameter,
        "architecture": architecture,
        "profile": profile,
        "compiler": compiler,
        "compiler_version": _compiler_version(compiler),
        "optimization": optimization,
        "status": "passed",
        "artifact_sha256": _sha256_file(binary),
        "artifact_machine": machine,
        "transcript_sha256": _sha256_bytes(transcript),
        "native_asm_symbols": symbols,
        "instruction_markers": markers,
        "kat_sha256": kat_sha256,
        "command": core_command,
    }


def run_build_matrix(manifest: dict[str, Any], output_root: Path, *, quick: bool) -> Path:
    if platform.system() != "Linux":
        raise RuntimeError("native build evidence must execute on Linux")
    architecture = _normal_arch()
    contract = manifest["build_contract"]
    if architecture not in contract["architectures"]:
        raise RuntimeError(f"architecture {architecture} is outside the frozen matrix")
    arch_contract = contract["architectures"][architecture]
    features = set(_cpu_features())
    missing_features = set(arch_contract["required_cpu_features"]) - features
    if missing_features:
        raise RuntimeError(
            f"{architecture} host lacks required native features: {sorted(missing_features)}"
        )
    required_tools = ["gcc", "clang", "nm", "objdump", "readelf"]
    missing_tools = [tool for tool in required_tools if shutil.which(tool) is None]
    if missing_tools:
        raise RuntimeError(f"missing build tools: {missing_tools}")

    if output_root.exists():
        if any(output_root.iterdir()):
            raise RuntimeError(f"output root must be empty: {output_root}")
    else:
        output_root.mkdir(parents=True)

    compilers = ["gcc"] if quick else list(contract["compilers"])
    optimizations = ["O2"] if quick else list(contract["optimizations"])
    cells: list[dict[str, Any]] = []
    for lineage_id, record in manifest["lineages"].items():
        for parameter in record["parameters"]:
            for profile in contract["profiles"]:
                for compiler in compilers:
                    for optimization in optimizations:
                        print(
                            f"build {lineage_id}/{parameter}/{profile}/{compiler}/{optimization}",
                            flush=True,
                        )
                        cells.append(
                            _compile_cell(
                                manifest,
                                lineage_id,
                                record,
                                str(parameter),
                                str(profile),
                                str(compiler),
                                str(optimization),
                                architecture,
                                output_root,
                            )
                        )

    transcript_groups: dict[tuple[str, str], set[str]] = {}
    for cell in cells:
        key = (cell["lineage"], cell["parameter"])
        transcript_groups.setdefault(key, set()).add(cell["transcript_sha256"])
    for key, digests in transcript_groups.items():
        if len(digests) != 1:
            raise RuntimeError(f"{key}: cross-matrix transcript drift: {sorted(digests)}")

    equivalence: list[dict[str, Any]] = []
    for lineage_id, record in manifest["lineages"].items():
        for parameter in record["parameters"]:
            for compiler in compilers:
                for optimization in optimizations:
                    matching = {
                        cell["profile"]: cell["transcript_sha256"]
                        for cell in cells
                        if cell["lineage"] == lineage_id
                        and cell["parameter"] == str(parameter)
                        and cell["compiler"] == compiler
                        and cell["optimization"] == optimization
                    }
                    if set(matching) != {"portable", "architecture-native"}:
                        raise RuntimeError(
                            f"missing profile pair for {lineage_id}/{parameter}/"
                            f"{compiler}/{optimization}"
                        )
                    equal = matching["portable"] == matching["architecture-native"]
                    if not equal:
                        raise RuntimeError(
                            f"portable/native mismatch for {lineage_id}/{parameter}/"
                            f"{compiler}/{optimization}"
                        )
                    equivalence.append(
                        {
                            "lineage": lineage_id,
                            "parameter": str(parameter),
                            "compiler": compiler,
                            "optimization": optimization,
                            "portable_sha256": matching["portable"],
                            "native_sha256": matching["architecture-native"],
                            "equal": True,
                        }
                    )

    kat_checks = sum(cell["kat_sha256"] is not None for cell in cells)
    structural_checks = sum(
        1 + (cell["profile"] == "architecture-native") + bool(cell["instruction_markers"])
        for cell in cells
    )
    report = {
        "schema_version": 1,
        "kind": "native-upstream-build-matrix",
        "generated_at": datetime.now(UTC).isoformat(),
        "git_commit": _git_commit(),
        "host": _host_record(),
        "architecture": architecture,
        "timing_evidence": False,
        "review_status": "needs-review",
        "full_matrix": not quick,
        "summary": {
            "expected_cells": len(cells),
            "passed_cells": len(cells),
            "kat_checks": kat_checks,
            "equivalence_checks": len(equivalence),
            "structural_checks": structural_checks,
        },
        "cells": cells,
        "equivalence": equivalence,
    }
    report_path = output_root / f"native-upstreams-{architecture}.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    errors = validate_result(report, manifest)
    if errors:
        raise RuntimeError("generated native report is invalid:\n" + "\n".join(errors))
    return report_path


def _safe_extract_tar(archive: Path, destination: Path) -> None:
    with tarfile.open(archive, "r:gz") as handle:
        destination_resolved = destination.resolve()
        for member in handle.getmembers():
            if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                raise RuntimeError(f"unsupported tar member type: {member.name}")
            member_path = (destination / member.name).resolve()
            try:
                member_path.relative_to(destination_resolved)
            except ValueError as exc:
                raise RuntimeError(f"unsafe tar member path: {member.name}") from exc
            if member.issym() or member.islnk():
                link_path = (member_path.parent / member.linkname).resolve()
                try:
                    link_path.relative_to(destination_resolved)
                except ValueError as exc:
                    raise RuntimeError(
                        f"unsafe tar member link: {member.name} -> {member.linkname}"
                    ) from exc
        try:
            handle.extractall(destination, filter="data")
        except TypeError:  # Python 3.11 implementations without extraction filters
            handle.extractall(destination)


def _download_exact(url: str, expected_sha256: str, destination: Path) -> None:
    if not destination.is_file():
        request = urllib.request.Request(url, headers={"User-Agent": "ctkat/0.10"})
        with urllib.request.urlopen(request, timeout=120) as response:
            with destination.open("wb") as handle:
                shutil.copyfileobj(response, handle)
    actual = _sha256_file(destination)
    if actual != expected_sha256:
        raise RuntimeError(
            f"downloaded artifact digest mismatch: expected {expected_sha256}, got {actual}"
        )


def run_openssl_integration(manifest: dict[str, Any], output_root: Path) -> Path:
    if platform.system() != "Linux" or _normal_arch() != "x86_64":
        raise RuntimeError("frozen OpenSSL integration job requires Linux/x86_64")
    for tool in ("gcc", "clang", "make", "perl"):
        if shutil.which(tool) is None:
            raise RuntimeError(f"OpenSSL integration requires {tool}")
    if output_root.exists():
        if any(output_root.iterdir()):
            raise RuntimeError(f"output root must be empty: {output_root}")
    else:
        output_root.mkdir(parents=True)

    record = manifest["integrations"]["openssl-3.5-pqc-api"]
    archive = output_root / "openssl-3.5.7.tar.gz"
    print("download and verify OpenSSL 3.5.7", flush=True)
    _download_exact(record["artifact_url"], record["artifact_sha256"], archive)
    source_parent = output_root / "source"
    source_parent.mkdir()
    _safe_extract_tar(archive, source_parent)
    source = source_parent / "openssl-3.5.7"
    if not source.is_dir():
        raise RuntimeError("OpenSSL release archive has an unexpected root directory")

    env = dict(os.environ)
    env["CC"] = "gcc"
    print("configure OpenSSL 3.5.7", flush=True)
    _run(
        [
            "perl",
            "./Configure",
            "no-shared",
            "no-tests",
            "no-docs",
            "no-zlib",
            "-O2",
        ],
        cwd=source,
        timeout=300,
        env=env,
    )
    jobs = min(os.cpu_count() or 2, 4)
    print(f"build OpenSSL 3.5.7 ({jobs} jobs)", flush=True)
    _run(["make", f"-j{jobs}", "build_sw"], cwd=source, timeout=2400, env=env)
    version = (
        _run([str(source / "apps/openssl"), "version"], cwd=source)
        .stdout.decode("utf-8", errors="replace")
        .strip()
    )
    if not version.startswith("OpenSSL 3.5.7 "):
        raise RuntimeError(f"unexpected built OpenSSL version: {version}")

    adapter = _repo_path(record["adapter"])
    cells: list[dict[str, Any]] = []
    transcript_digests: set[str] = set()
    for compiler in record["build_scope"]["adapter_compilers"]:
        compiler_dir = output_root / f"adapter-{compiler}"
        compiler_dir.mkdir()
        binary = compiler_dir / "openssl-pqc-smoke"
        command = [
            compiler,
            "-std=c99",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-O2",
            f"-I{source / 'include'}",
            str(adapter),
            str(source / "libcrypto.a"),
            "-ldl",
            "-pthread",
            "-o",
            str(binary),
        ]
        print(f"compile and run OpenSSL adapter with {compiler}", flush=True)
        _run(command, timeout=600)
        transcript = _run([str(binary)], cwd=source, timeout=300).stdout
        transcript_sha256 = _sha256_bytes(transcript)
        if transcript_sha256 != record["expected_transcript_sha256"]:
            rendered = transcript.decode("utf-8", errors="replace")
            raise RuntimeError(
                f"OpenSSL {compiler} transcript mismatch: {transcript_sha256}\n{rendered}"
            )
        transcript_digests.add(transcript_sha256)
        cells.append(
            {
                "compiler": compiler,
                "compiler_version": _compiler_version(compiler),
                "status": "passed",
                "artifact_sha256": _sha256_file(binary),
                "transcript_sha256": transcript_sha256,
            }
        )
    if len(transcript_digests) != 1:
        raise RuntimeError("OpenSSL gcc/clang adapter transcripts differ")

    report = {
        "schema_version": 1,
        "kind": "openssl-pqc-api-integration",
        "generated_at": datetime.now(UTC).isoformat(),
        "git_commit": _git_commit(),
        "host": _host_record(),
        "release": record["release"],
        "revision": record["revision"],
        "source_artifact_sha256": record["artifact_sha256"],
        "openssl_version": version,
        "counts_as_lineage": False,
        "timing_evidence": False,
        "review_status": "needs-review",
        "cells": cells,
    }
    report_path = output_root / "openssl-pqc-api.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    errors = validate_result(report, manifest)
    if errors:
        raise RuntimeError("generated OpenSSL report is invalid:\n" + "\n".join(errors))
    return report_path


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and SHA256_RE.fullmatch(value) is not None


def _validate_host(host: Any, errors: list[str]) -> None:
    if not isinstance(host, dict):
        errors.append("host must be an object")
        return
    if host.get("system") != "Linux":
        errors.append("build evidence host must be Linux")
    for field in ("machine", "release"):
        if not isinstance(host.get(field), str) or not host[field]:
            errors.append(f"host.{field} must be a non-empty string")
    if not isinstance(host.get("cpu_features"), list):
        errors.append("host.cpu_features must be an array")


def _expected_native_tuples(
    manifest: dict[str, Any], *, full_matrix: bool
) -> set[tuple[str, str, str, str, str]]:
    contract = manifest["build_contract"]
    compilers = contract["compilers"] if full_matrix else ["gcc"]
    optimizations = list(contract["optimizations"]) if full_matrix else ["O2"]
    return {
        (lineage, str(parameter), profile, compiler, optimization)
        for lineage, record in manifest["lineages"].items()
        for parameter in record["parameters"]
        for profile in contract["profiles"]
        for compiler in compilers
        for optimization in optimizations
    }


def _validate_native_result(result: dict[str, Any], manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if result.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if result.get("timing_evidence") is not False:
        errors.append("native build report cannot be timing evidence")
    if result.get("review_status") != "needs-review":
        errors.append("native build report must remain needs-review")
    if not REVISION_RE.fullmatch(str(result.get("git_commit", ""))):
        errors.append("git_commit must be a full lowercase commit")
    _validate_host(result.get("host"), errors)
    architecture = result.get("architecture")
    if architecture not in {"x86_64", "aarch64"}:
        errors.append("architecture must be x86_64 or aarch64")
        return errors
    host = result.get("host", {})
    try:
        host_arch = _normal_arch(str(host.get("machine", "")))
        if host_arch != architecture:
            errors.append("host machine and report architecture differ")
    except ValueError as exc:
        errors.append(str(exc))

    full_matrix = result.get("full_matrix")
    if not isinstance(full_matrix, bool):
        errors.append("full_matrix must be boolean")
        return errors
    expected = _expected_native_tuples(manifest, full_matrix=full_matrix)
    cells = result.get("cells")
    if not isinstance(cells, list):
        errors.append("cells must be an array")
        return errors
    actual: set[tuple[str, str, str, str, str]] = set()
    ids: set[str] = set()
    transcripts: dict[tuple[str, str], set[str]] = {}
    kat_checks = 0
    for index, cell in enumerate(cells):
        label = f"cell[{index}]"
        if not isinstance(cell, dict):
            errors.append(f"{label} must be an object")
            continue
        cell_id = cell.get("id")
        if not isinstance(cell_id, str) or cell_id in ids:
            errors.append(f"{label}: id must be a unique string")
        else:
            ids.add(cell_id)
        key = (
            str(cell.get("lineage")),
            str(cell.get("parameter")),
            str(cell.get("profile")),
            str(cell.get("compiler")),
            str(cell.get("optimization")),
        )
        if key in actual:
            errors.append(f"{label}: duplicate matrix tuple {key}")
        actual.add(key)
        if cell.get("architecture") != architecture:
            errors.append(f"{label}: architecture differs from report")
        if cell.get("status") != "passed":
            errors.append(f"{label}: status must be passed")
        for field in ("artifact_sha256", "transcript_sha256"):
            if not _is_sha256(cell.get(field)):
                errors.append(f"{label}: {field} must be SHA-256")
        machine = str(cell.get("artifact_machine", ""))
        if not any(marker in machine for marker in MACHINE_MARKERS[architecture]):
            errors.append(f"{label}: artifact machine does not match {architecture}")
        symbols = cell.get("native_asm_symbols")
        markers = cell.get("instruction_markers")
        if not isinstance(symbols, list) or not isinstance(markers, list):
            errors.append(f"{label}: structural evidence fields must be arrays")
        elif key[2] == "portable" and (symbols or markers):
            errors.append(f"{label}: portable cell carries native asm evidence")
        elif key[2] == "architecture-native" and (not symbols or not markers):
            errors.append(f"{label}: native cell lacks asm symbol/instruction evidence")
        transcript = cell.get("transcript_sha256")
        if _is_sha256(transcript):
            transcripts.setdefault((key[0], key[1]), set()).add(transcript)

        kat = cell.get("kat_sha256")
        should_have_kat = key[3] == "gcc" and key[4] == "O2"
        if should_have_kat:
            kat_checks += 1
            try:
                expected_kat = manifest["lineages"][key[0]]["parameters"][key[1]]["kat_sha256"]
            except KeyError:
                expected_kat = None
            if kat != expected_kat:
                errors.append(f"{label}: upstream KAT digest mismatch")
        elif kat is not None:
            errors.append(f"{label}: KAT digest present outside canonical cell")
    if actual != expected:
        errors.append(
            f"matrix tuple mismatch: missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )
    for key, digests in transcripts.items():
        if len(digests) != 1:
            errors.append(f"{key}: transcript differs across matrix cells")

    equivalence = result.get("equivalence")
    expected_equivalence_count = len(expected) // 2
    if not isinstance(equivalence, list) or len(equivalence) != expected_equivalence_count:
        errors.append(f"equivalence must contain {expected_equivalence_count} profile pairs")
    else:
        equivalence_keys: set[tuple[str, str, str, str]] = set()
        for index, item in enumerate(equivalence):
            if not isinstance(item, dict):
                errors.append(f"equivalence[{index}] must be an object")
                continue
            key = (
                str(item.get("lineage")),
                str(item.get("parameter")),
                str(item.get("compiler")),
                str(item.get("optimization")),
            )
            if key in equivalence_keys:
                errors.append(f"equivalence[{index}] duplicates {key}")
            equivalence_keys.add(key)
            if item.get("equal") is not True or item.get("portable_sha256") != item.get(
                "native_sha256"
            ):
                errors.append(f"equivalence[{index}] is not byte-identical")

    summary = result.get("summary")
    if not isinstance(summary, dict):
        errors.append("summary must be an object")
    else:
        if summary.get("expected_cells") != len(expected):
            errors.append("summary expected_cells mismatch")
        if summary.get("passed_cells") != len(cells):
            errors.append("summary passed_cells mismatch")
        if summary.get("kat_checks") != kat_checks or kat_checks != 12:
            errors.append("summary must record 12 canonical upstream KAT checks")
        if summary.get("equivalence_checks") != expected_equivalence_count:
            errors.append("summary equivalence_checks mismatch")
        if not isinstance(summary.get("structural_checks"), int) or summary[
            "structural_checks"
        ] < len(cells):
            errors.append("summary structural_checks is too small")
    return errors


def _validate_openssl_result(result: dict[str, Any], manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    record = manifest["integrations"]["openssl-3.5-pqc-api"]
    expected_fields = {
        "schema_version": 1,
        "release": record["release"],
        "revision": record["revision"],
        "source_artifact_sha256": record["artifact_sha256"],
        "counts_as_lineage": False,
        "timing_evidence": False,
        "review_status": "needs-review",
    }
    for field, expected in expected_fields.items():
        if result.get(field) != expected:
            errors.append(f"OpenSSL report {field} must be {expected!r}")
    if not str(result.get("openssl_version", "")).startswith("OpenSSL 3.5.7 "):
        errors.append("OpenSSL runtime version must be exact 3.5.7")
    if not REVISION_RE.fullmatch(str(result.get("git_commit", ""))):
        errors.append("OpenSSL report git_commit must be a full commit")
    _validate_host(result.get("host"), errors)
    cells = result.get("cells")
    if not isinstance(cells, list) or len(cells) != 2:
        errors.append("OpenSSL report must contain gcc and clang cells")
        return errors
    compilers = {cell.get("compiler") for cell in cells if isinstance(cell, dict)}
    if compilers != {"gcc", "clang"}:
        errors.append("OpenSSL cells must be gcc and clang")
    transcripts = set()
    for index, cell in enumerate(cells):
        if not isinstance(cell, dict):
            errors.append(f"OpenSSL cell[{index}] must be an object")
            continue
        if cell.get("status") != "passed":
            errors.append(f"OpenSSL cell[{index}] status must be passed")
        for field in ("artifact_sha256", "transcript_sha256"):
            if not _is_sha256(cell.get(field)):
                errors.append(f"OpenSSL cell[{index}] {field} must be SHA-256")
        transcript = cell.get("transcript_sha256")
        transcripts.add(transcript)
        if transcript != record["expected_transcript_sha256"]:
            errors.append(f"OpenSSL cell[{index}] deterministic transcript mismatch")
    if len(transcripts) != 1:
        errors.append("OpenSSL gcc/clang transcripts differ")
    return errors


def validate_result(result: dict[str, Any], manifest: dict[str, Any]) -> list[str]:
    kind = result.get("kind")
    if kind == "native-upstream-build-matrix":
        return _validate_native_result(result, manifest)
    if kind == "openssl-pqc-api-integration":
        return _validate_openssl_result(result, manifest)
    return [f"unknown result kind: {kind!r}"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument(
        "--run-build-matrix",
        action="store_true",
        help="compile and execute the current Linux architecture matrix",
    )
    actions.add_argument(
        "--run-openssl",
        action="store_true",
        help="build exact OpenSSL 3.5.7 and run the PQ provider API adapter",
    )
    actions.add_argument(
        "--validate-result",
        type=Path,
        help="validate one generated JSON evidence report",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path(".ctkat-diverse-build"),
        help="empty directory for generated artifacts",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="for local smoke only: run gcc/O2 while preserving both profiles and KATs",
    )
    args = parser.parse_args()

    try:
        manifest = load_manifest()
        errors = validate_static(manifest)
        if errors:
            for error in errors:
                print(f"ERROR: {error}", file=sys.stderr)
            return 1

        if args.validate_result is not None:
            result = json.loads(args.validate_result.read_text(encoding="utf-8"))
            if not isinstance(result, dict):
                raise ValueError("result root must be a JSON object")
            result_errors = validate_result(result, manifest)
            if result_errors:
                for error in result_errors:
                    print(f"ERROR: {error}", file=sys.stderr)
                return 1
            print(f"diverse upstream result valid: {args.validate_result}")
            return 0

        output_root = args.output_root.resolve()
        if args.run_build_matrix:
            report = run_build_matrix(manifest, output_root, quick=args.quick)
            print(f"diverse upstream build matrix passed: {report}")
        elif args.run_openssl:
            if args.quick:
                parser.error("--quick applies only to --run-build-matrix")
            report = run_openssl_integration(manifest, output_root)
            print(f"OpenSSL PQ API integration passed: {report}")
        else:
            if args.quick:
                parser.error("--quick requires --run-build-matrix")
            print("diverse upstream provenance and build contract valid")
        return 0
    except (
        OSError,
        RuntimeError,
        ValueError,
        KeyError,
        json.JSONDecodeError,
        yaml.YAMLError,
        subprocess.TimeoutExpired,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
