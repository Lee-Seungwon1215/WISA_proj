"""Fail-closed provenance for every generated timing harness.

Instruction-specific binary contracts remain responsible for semantic
disassembly checks.  This module supplies the common lower bound that every
timing run needs: the exact generated source, linked binary, repository
configuration, linked sources, compiler identity, flags, and a replayable
compile argv are captured before the first sample is collected.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterable


class TimingBuildProvenanceError(RuntimeError):
    """Build provenance could not be captured without ambiguity."""


def sha256_file(path: Path) -> str:
    """Hash one regular file without loading large binaries into memory."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _regular_file(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise TimingBuildProvenanceError(f"{label} must be a regular non-symlink file: {path}")
    return path.resolve()


def file_record(path: Path, label: str) -> dict[str, Any]:
    """Return an absolute, content-addressed record for one provenance input."""

    resolved = _regular_file(path, label)
    return {
        "path": str(resolved),
        "sha256": sha256_file(resolved),
        "bytes": resolved.stat().st_size,
    }


def _compiler_record(command: str) -> dict[str, Any]:
    executable_value = shutil.which(command)
    if executable_value is None:
        raise TimingBuildProvenanceError(
            f"compiler unavailable while capturing provenance: {command}"
        )
    executable = _regular_file(Path(executable_value).resolve(), "compiler executable")
    version_command = [str(executable), "--version"]
    try:
        result = subprocess.run(
            version_command,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise TimingBuildProvenanceError(
            f"compiler version probe failed: {version_command}: {exc}"
        ) from exc
    version = result.stdout.splitlines()[0].strip() if result.stdout else ""
    if result.returncode != 0 or not version:
        raise TimingBuildProvenanceError(
            f"compiler version probe returned {result.returncode}: {version_command}"
        )
    return {
        "requested_command": command,
        "executable": file_record(executable, "compiler executable"),
        "version": version,
        "version_command": version_command,
    }


def capture_timing_build_provenance(
    *,
    compiler: str,
    cflags: Iterable[str],
    include_dirs: Iterable[Path],
    linked_sources: Iterable[Path],
    generated_source: Path,
    binary: Path,
    config_path: Path | None,
    compile_command: str,
) -> dict[str, Any]:
    """Capture exact build inputs immediately before timing begins.

    ``compile_command`` preserves the command that actually ran (which may use
    atomic temporary paths).  ``reproduction_argv`` names the byte-identical
    published source and final output paths so an auditor can replay the build
    without depending on those removed temporary names.
    """

    flags = list(cflags)
    if any(not isinstance(flag, str) for flag in flags):
        raise TimingBuildProvenanceError("compiler flags must be strings")
    if not isinstance(compile_command, str) or not compile_command.strip():
        raise TimingBuildProvenanceError("actual compile command is missing")

    original_includes = list(include_dirs)
    for path in original_includes:
        if path.is_symlink() or not path.is_dir():
            raise TimingBuildProvenanceError(
                f"include directory must be a non-symlink directory: {path}"
            )
    resolved_includes = [path.resolve() for path in original_includes]
    if len(resolved_includes) != len(set(resolved_includes)):
        raise TimingBuildProvenanceError("include directory list contains duplicates")

    resolved_sources = [_regular_file(path, "linked source") for path in linked_sources]
    if len(resolved_sources) != len(set(resolved_sources)):
        raise TimingBuildProvenanceError("linked source list contains duplicates")

    generated_record = file_record(generated_source, "generated timing source")
    binary_record = file_record(binary, "generated timing binary")
    config_record = (
        file_record(config_path, "CT-KAT timing config") if config_path is not None else None
    )
    compiler_record = _compiler_record(compiler)
    compiler_record["cflags"] = flags
    compiler_record["compile_command"] = compile_command

    reproduction_argv = [
        compiler_record["executable"]["path"],
        *flags,
        *(f"-I{path}" for path in resolved_includes),
        generated_record["path"],
        *(str(path) for path in resolved_sources),
        "-o",
        binary_record["path"],
    ]
    return {
        "schema_version": "1.0",
        "kind": "ctkat-timing-build-provenance",
        "captured_before_measurement": True,
        "config": config_record,
        "generated_source": generated_record,
        "binary": binary_record,
        "linked_sources": [file_record(path, "linked source") for path in resolved_sources],
        "include_dirs": [str(path) for path in resolved_includes],
        "compiler": compiler_record,
        "reproduction_argv": reproduction_argv,
    }


def assert_timing_build_provenance_unchanged(payload: dict[str, Any]) -> None:
    """Fail if any sealed build input has changed since capture.

    Callers use this immediately before and after each measured subprocess.
    That closes the gap where a generated binary could be replaced after its
    pre-measurement seal was written but before (or during) a multi-process
    timing protocol.
    """

    if not isinstance(payload, dict):
        raise TimingBuildProvenanceError("build provenance must be a mapping")
    expected_keys = {
        "schema_version",
        "kind",
        "captured_before_measurement",
        "config",
        "generated_source",
        "binary",
        "linked_sources",
        "include_dirs",
        "compiler",
        "reproduction_argv",
    }
    if set(payload) != expected_keys:
        raise TimingBuildProvenanceError("build provenance field set drifted")
    if payload.get("schema_version") != "1.0":
        raise TimingBuildProvenanceError("build provenance schema_version drifted")
    if payload.get("kind") != "ctkat-timing-build-provenance":
        raise TimingBuildProvenanceError("build provenance kind drifted")
    if payload.get("captured_before_measurement") is not True:
        raise TimingBuildProvenanceError("build provenance was not captured before measurement")

    records: list[tuple[str, Any]] = [
        ("generated timing source", payload.get("generated_source")),
        ("generated timing binary", payload.get("binary")),
    ]
    config = payload.get("config")
    if config is not None:
        records.append(("CT-KAT timing config", config))
    linked_sources = payload.get("linked_sources")
    if not isinstance(linked_sources, list):
        raise TimingBuildProvenanceError("linked source provenance must be a list")
    records.extend(
        (f"linked source[{index}]", record) for index, record in enumerate(linked_sources)
    )
    compiler = payload.get("compiler")
    expected_compiler_keys = {
        "requested_command",
        "executable",
        "version",
        "version_command",
        "cflags",
        "compile_command",
    }
    if not isinstance(compiler, dict) or set(compiler) != expected_compiler_keys:
        raise TimingBuildProvenanceError("compiler provenance must be a mapping")
    requested_command = compiler.get("requested_command")
    version = compiler.get("version")
    version_command = compiler.get("version_command")
    cflags = compiler.get("cflags")
    compile_command = compiler.get("compile_command")
    if not isinstance(requested_command, str) or not requested_command:
        raise TimingBuildProvenanceError("requested compiler command is malformed")
    if not isinstance(version, str) or not version:
        raise TimingBuildProvenanceError("compiler version provenance is malformed")
    if (
        not isinstance(version_command, list)
        or len(version_command) != 2
        or version_command[1] != "--version"
        or version_command[0] != compiler.get("executable", {}).get("path")
    ):
        raise TimingBuildProvenanceError("compiler version command provenance is malformed")
    if not isinstance(cflags, list) or any(not isinstance(flag, str) for flag in cflags):
        raise TimingBuildProvenanceError("compiler flag provenance is malformed")
    if not isinstance(compile_command, str) or not compile_command.strip():
        raise TimingBuildProvenanceError("actual compile command provenance is malformed")
    records.append(("compiler executable", compiler.get("executable")))

    for label, record in records:
        if not isinstance(record, dict) or set(record) != {"path", "sha256", "bytes"}:
            raise TimingBuildProvenanceError(f"{label} provenance record is malformed")
        path_value = record.get("path")
        if not isinstance(path_value, str) or not Path(path_value).is_absolute():
            raise TimingBuildProvenanceError(f"{label} provenance path is not absolute")
        path = _regular_file(Path(path_value), label)
        if record.get("bytes") != path.stat().st_size:
            raise TimingBuildProvenanceError(f"{label} byte length changed after sealing")
        if record.get("sha256") != sha256_file(path):
            raise TimingBuildProvenanceError(f"{label} content changed after sealing")

    include_dirs = payload.get("include_dirs")
    if not isinstance(include_dirs, list) or any(
        not isinstance(value, str) or not Path(value).is_absolute() for value in include_dirs
    ):
        raise TimingBuildProvenanceError("include directory provenance is malformed")
    for value in include_dirs:
        directory = Path(value)
        if directory.is_symlink() or not directory.is_dir():
            raise TimingBuildProvenanceError(
                f"sealed include directory is unavailable or unsafe: {directory}"
            )
    if len(include_dirs) != len(set(include_dirs)):
        raise TimingBuildProvenanceError("sealed include directory list contains duplicates")

    source_paths = [record.get("path") for record in linked_sources]
    if len(source_paths) != len(set(source_paths)):
        raise TimingBuildProvenanceError("sealed linked source list contains duplicates")

    reproduction_argv = payload.get("reproduction_argv")
    if not isinstance(reproduction_argv, list) or any(
        not isinstance(value, str) for value in reproduction_argv
    ):
        raise TimingBuildProvenanceError("reproduction argv provenance is malformed")
    expected_reproduction_argv = [
        compiler["executable"]["path"],
        *compiler["cflags"],
        *(f"-I{path}" for path in include_dirs),
        payload["generated_source"]["path"],
        *source_paths,
        "-o",
        payload["binary"]["path"],
    ]
    if reproduction_argv != expected_reproduction_argv:
        raise TimingBuildProvenanceError("reproduction argv does not match sealed build inputs")


def assert_timing_build_seal_unchanged(
    payload: dict[str, Any],
    seal_path: Path,
    seal_sha256: str,
) -> None:
    """Validate both the sealed inputs and the immutable published JSON."""

    assert_timing_build_provenance_unchanged(payload)
    seal = _regular_file(seal_path, "timing build provenance seal")
    if not isinstance(seal_sha256, str) or len(seal_sha256) != 64:
        raise TimingBuildProvenanceError("timing build provenance seal hash is malformed")
    if sha256_file(seal) != seal_sha256:
        raise TimingBuildProvenanceError("timing build provenance seal changed after publishing")


def write_timing_build_provenance(
    path: Path,
    payload: dict[str, Any],
) -> str:
    """Atomically publish a pre-measurement seal and return its SHA-256."""

    assert_timing_build_provenance_unchanged(payload)
    if path.name in {"", ".", ".."} or Path(path.name).name != path.name:
        raise TimingBuildProvenanceError(f"unsafe build provenance filename: {path.name!r}")
    parent = path.parent
    if parent.is_symlink():
        raise TimingBuildProvenanceError(f"build provenance directory is a symlink: {parent}")
    parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)
    except (OSError, TypeError, ValueError) as exc:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise TimingBuildProvenanceError(
            f"could not publish build provenance seal {path}: {exc}"
        ) from exc
    return sha256_file(path)
