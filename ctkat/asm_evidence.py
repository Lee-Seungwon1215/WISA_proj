"""Content-addressed, fail-closed assembly evidence bundles.

The legacy asm candidate report is intentionally small and warn-only.  It is
useful for triage, but it cannot prove that candidate-free cells were actually
compiled and disassembled.  This module is the paper-evidence layer: every
configured target/harness/source/compiler/optimization cell has an explicit
compile and disassembly status, and every successful cell points at the full
``objdump -dSl`` text by SHA-256.

Raw disassemblies are host artifacts and remain outside Git.  The committed
campaign/schema plus this checker define how to create and independently
verify them without promoting a partial scan to complete coverage.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from ._proc import run_text
from .asm_scan import (
    _strip_opt,
    parse_nm,
    parse_objdump_details,
    resolve_disassembly_hits,
    triage_hint_for,
)
from .config import load_config

SCHEMA_VERSION = "1.0"
BUNDLE_KIND = "ctkat-asm-evidence-bundle"
CAMPAIGN_KIND = "ctkat-asm-evidence-campaign"
INDEX_KIND = "ctkat-asm-evidence-target-index"
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_DISASSEMBLY_BYTES = 64 * 1024 * 1024
COMPILE_OUTPUT_TOKEN = "<compiled-object>"
DEPENDENCY_OUTPUT_TOKEN = "<dependency-file>"


class AsmEvidenceError(RuntimeError):
    pass


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _repo_path(root: Path, value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty repository-relative path")
    candidate = (root / value).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"{label} escapes repository: {value!r}") from exc
    return candidate


def _lexical_absolute(path: Path) -> Path:
    """Return an absolute normalized path without following symbolic links."""

    return Path(os.path.abspath(os.fspath(path)))


def _reject_symlink_components(path: Path, label: str) -> None:
    """Reject a symlink at the path or in any existing lexical parent."""

    absolute = _lexical_absolute(path)
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink():
            raise ValueError(f"{label} contains a symlink: {current}")


def _lexical_repo_path(root: Path, path: Path, label: str) -> Path:
    root = root.resolve()
    candidate = _lexical_absolute(path if path.is_absolute() else root / path)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{label} escapes repository: {path!s}") from exc
    _reject_symlink_components(candidate, label)
    return candidate


def _git_tracked_paths(repo_root: Path) -> set[str]:
    try:
        proc = run_text(
            ["git", "ls-files", "-z", "--cached"],
            cwd=repo_root,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"cannot enumerate Git-tracked inputs: {exc}") from exc
    if proc.returncode != 0:
        raise ValueError("cannot enumerate Git-tracked inputs")
    return {value for value in proc.stdout.split("\0") if value}


def _tracked_regular_repo_file(
    repo_root: Path,
    path: Path,
    label: str,
    *,
    tracked_paths: set[str],
) -> Path:
    candidate = _lexical_repo_path(repo_root, path, label)
    try:
        mode = candidate.lstat().st_mode
    except OSError as exc:
        raise ValueError(f"{label} is unavailable: {candidate}: {exc}") from exc
    if not stat.S_ISREG(mode):
        raise ValueError(f"{label} must be a regular non-symlink file: {candidate}")
    relative = candidate.relative_to(repo_root.resolve()).as_posix()
    if relative not in tracked_paths:
        raise ValueError(f"{label} is not tracked by Git: {relative}")
    return candidate


def _safe_repo_directory(repo_root: Path, path: Path, label: str) -> Path:
    candidate = _lexical_repo_path(repo_root, path, label)
    try:
        mode = candidate.lstat().st_mode
    except OSError as exc:
        raise ValueError(f"{label} is unavailable: {candidate}: {exc}") from exc
    if not stat.S_ISDIR(mode):
        raise ValueError(f"{label} must be a real directory: {candidate}")
    return candidate


def _prepare_output_root(path: Path) -> Path:
    output_root = _lexical_absolute(path)
    try:
        _reject_symlink_components(output_root, "output root")
    except ValueError as exc:
        raise AsmEvidenceError(str(exc)) from exc
    if output_root.exists():
        if not stat.S_ISDIR(output_root.lstat().st_mode):
            raise AsmEvidenceError(f"output root is not a real directory: {output_root}")
        if any(output_root.iterdir()):
            raise AsmEvidenceError(f"output root must be absent or empty: {output_root}")
    output_root.mkdir(parents=True, exist_ok=True)
    try:
        _reject_symlink_components(output_root, "output root")
    except ValueError as exc:
        raise AsmEvidenceError(str(exc)) from exc
    return output_root


def _relative(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def _safe_bundle_path(bundle_root: Path, value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty bundle-relative path")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"{label} escapes bundle: {value!r}")
    unresolved = bundle_root / relative
    root = bundle_root.resolve()
    if unresolved.is_symlink() or any(
        parent.is_symlink()
        for parent in unresolved.parents
        if parent != root and parent.is_relative_to(root)
    ):
        raise ValueError(f"{label} contains a symlink: {value!r}")
    candidate = unresolved.resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{label} escapes bundle: {value!r}") from exc
    return candidate


def load_campaign(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("asm evidence campaign root must be a mapping")
    return data


def campaign_scope(campaign: dict[str, Any]) -> list[dict[str, str]]:
    scope: list[dict[str, str]] = []
    for target in campaign.get("targets", []):
        if not isinstance(target, dict):
            continue
        target_id = target.get("id")
        for harness in target.get("harnesses", []):
            if isinstance(target_id, str) and isinstance(harness, str):
                scope.append({"target": target_id, "harness": harness})
    return scope


def _scope_pairs(rows: Iterable[dict[str, Any]]) -> set[tuple[str, str]]:
    return {
        (str(row.get("target", "")), str(row.get("harness", "")))
        for row in rows
        if isinstance(row, dict)
    }


def _public_corpus_scope(path: Path, family: str, attribution: str) -> set[tuple[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        rows = csv.DictReader(handle)
        return {
            (row.get("target", ""), row.get("harness", ""))
            for row in rows
            if row.get("family") == family and row.get("asm_attribution") == attribution
        }


def validate_campaign(
    campaign: dict[str, Any],
    *,
    campaign_path: Path,
    repo_root: Path,
) -> list[str]:
    """Validate frozen scope against configs, active corpus, and review packet."""

    errors: list[str] = []
    if campaign.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")
    if campaign.get("kind") != CAMPAIGN_KIND:
        errors.append(f"kind must be {CAMPAIGN_KIND}")
    if campaign.get("status") != "premeasurement-frozen":
        errors.append("status must be premeasurement-frozen")
    if campaign.get("source_revision_policy") != "exact-clean-git-head":
        errors.append("source_revision_policy must be exact-clean-git-head")
    host = campaign.get("host")
    if not isinstance(host, dict) or host.get("system") != "Linux":
        errors.append("host.system must be Linux")
    if not isinstance(host, dict) or host.get("architecture") not in {"x86_64", "AMD64"}:
        errors.append("host.architecture must be x86_64")
    if campaign.get("compilers") != ["gcc", "clang"]:
        errors.append("compilers must be exactly [gcc, clang]")
    if campaign.get("optimization_levels") != ["-O0", "-O1", "-O2", "-O3", "-Os"]:
        errors.append("optimization_levels must be exactly -O0/-O1/-O2/-O3/-Os")
    tools = campaign.get("tools")
    if not isinstance(tools, dict) or tools.get("full_disassembly_argv") != ["-dSl"]:
        errors.append("tools.full_disassembly_argv must be exactly [-dSl]")

    try:
        tracked_paths = _git_tracked_paths(repo_root)
    except ValueError as exc:
        errors.append(str(exc))
        tracked_paths = set()
    try:
        _tracked_regular_repo_file(
            repo_root,
            campaign_path,
            "campaign manifest",
            tracked_paths=tracked_paths,
        )
    except ValueError as exc:
        errors.append(str(exc))

    targets = campaign.get("targets")
    if not isinstance(targets, list) or not targets:
        errors.append("targets must be a non-empty list")
        targets = []
    seen_targets: set[str] = set()
    for index, target in enumerate(targets):
        if not isinstance(target, dict):
            errors.append(f"targets[{index}] must be a mapping")
            continue
        target_id = target.get("id")
        if not isinstance(target_id, str) or not target_id:
            errors.append(f"targets[{index}].id must be non-empty")
            continue
        if target_id in seen_targets:
            errors.append(f"duplicate target id: {target_id}")
        seen_targets.add(target_id)
        harnesses = target.get("harnesses")
        if (
            not isinstance(harnesses, list)
            or not harnesses
            or len(set(harnesses)) != len(harnesses)
        ):
            errors.append(f"{target_id}: harnesses must be a non-empty unique list")
            continue
        try:
            config_value = target.get("config")
            if not isinstance(config_value, str) or not config_value:
                raise ValueError("config must be a non-empty repository-relative path")
            config_path = _tracked_regular_repo_file(
                repo_root,
                repo_root / config_value,
                f"targets[{index}].config",
                tracked_paths=tracked_paths,
            )
            config = load_config(config_path)
        except (OSError, ValueError) as exc:
            errors.append(f"{target_id}: cannot load config: {exc}")
            continue
        if config.project.name != target_id:
            errors.append(f"{target_id}: config project name is {config.project.name!r}")
        if config.ct is None:
            errors.append(f"{target_id}: config has no ct section")
            continue
        by_name = {harness.name: harness for harness in config.ct.harnesses}
        for harness_name in harnesses:
            harness = by_name.get(harness_name)
            if harness is None:
                errors.append(f"{target_id}/{harness_name}: harness missing from config")
                continue
            if harness.template != "kem" or not harness.sources:
                errors.append(
                    f"{target_id}/{harness_name}: evidence scope requires a sourced KEM harness"
                )
            displays = [str(source) for source in harness.sources]
            if len(displays) != len(set(displays)):
                errors.append(f"{target_id}/{harness_name}: duplicate source entries")
            try:
                _safe_repo_directory(
                    repo_root,
                    config_path.parent / config.ct.workdir,
                    f"{target_id}/{harness_name}.workdir",
                )
                for include_index, include_dir in enumerate(harness.include_dirs):
                    _safe_repo_directory(
                        repo_root,
                        config_path.parent / include_dir,
                        f"{target_id}/{harness_name}.include_dirs[{include_index}]",
                    )
                for source_index, source in enumerate(harness.sources):
                    _tracked_regular_repo_file(
                        repo_root,
                        config_path.parent / source,
                        f"{target_id}/{harness_name}.sources[{source_index}]",
                        tracked_paths=tracked_paths,
                    )
            except ValueError as exc:
                errors.append(str(exc))

    configured_scope = _scope_pairs(campaign_scope(campaign))
    if len(configured_scope) != len(campaign_scope(campaign)):
        errors.append("campaign public scope contains duplicate target/harness pairs")

    corpus = campaign.get("corpus")
    if not isinstance(corpus, dict):
        errors.append("corpus must be a mapping")
        corpus = {}
    try:
        corpus_value = corpus.get("path")
        if not isinstance(corpus_value, str) or not corpus_value:
            raise ValueError("corpus.path must be a non-empty repository-relative path")
        corpus_path = _tracked_regular_repo_file(
            repo_root,
            repo_root / corpus_value,
            "corpus.path",
            tracked_paths=tracked_paths,
        )
        actual_scope = _public_corpus_scope(
            corpus_path,
            str(corpus.get("family", "")),
            str(corpus.get("attribution", "")),
        )
        if configured_scope != actual_scope:
            errors.append(
                "public-attributed corpus scope mismatch: "
                f"campaign={sorted(configured_scope)!r}, corpus={sorted(actual_scope)!r}"
            )
    except (OSError, ValueError) as exc:
        errors.append(f"cannot validate public corpus scope: {exc}")

    try:
        review_value = corpus.get("review")
        if not isinstance(review_value, str) or not review_value:
            raise ValueError("corpus.review must be a non-empty repository-relative path")
        review_path = _tracked_regular_repo_file(
            repo_root,
            repo_root / review_value,
            "corpus.review",
            tracked_paths=tracked_paths,
        )
        review = yaml.safe_load(review_path.read_text(encoding="utf-8"))
        review_scope = _scope_pairs(review.get("scope", []) if isinstance(review, dict) else [])
        if review_scope != configured_scope:
            errors.append(
                "paper review scope does not cover every public-attributed row: "
                f"review={sorted(review_scope)!r}, campaign={sorted(configured_scope)!r}"
            )
    except (OSError, ValueError, yaml.YAMLError) as exc:
        errors.append(f"cannot validate paper review scope: {exc}")

    policy = campaign.get("attribution_policy")
    if not isinstance(policy, dict):
        errors.append("attribution_policy must be a mapping")
    else:
        for key in (
            "allowed_source_suffixes",
            "allowed_functions",
            "required_functions_per_harness",
        ):
            values = policy.get(key)
            if (
                not isinstance(values, list)
                or not values
                or not all(isinstance(value, str) and value for value in values)
            ):
                errors.append(f"attribution_policy.{key} must be a non-empty string list")

    artifact = campaign.get("artifact")
    if not isinstance(artifact, dict):
        errors.append("artifact must be a mapping")
    else:
        if artifact.get("raw_directory") != "raw/sha256":
            errors.append("artifact.raw_directory must be raw/sha256")
        if artifact.get("raw_content_addressed") is not True:
            errors.append("artifact.raw_content_addressed must be true")
        if artifact.get("commit_raw_to_git") is not False:
            errors.append("artifact.commit_raw_to_git must be false")
        try:
            schema_value = artifact.get("schema")
            if not isinstance(schema_value, str) or not schema_value:
                raise ValueError("artifact.schema must be a non-empty repository-relative path")
            schema_path = _tracked_regular_repo_file(
                repo_root,
                repo_root / schema_value,
                "artifact.schema",
                tracked_paths=tracked_paths,
            )
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            schema_sha256 = artifact.get("schema_sha256")
            if not HEX64_RE.fullmatch(str(schema_sha256 or "")):
                errors.append("artifact.schema_sha256 must be a lowercase SHA-256")
            elif schema_sha256 != _sha256_file(schema_path):
                errors.append("artifact schema hash drift")
            if schema.get("properties", {}).get("kind", {}).get("const") != BUNDLE_KIND:
                errors.append("artifact schema kind drift")
            try:
                Draft202012Validator.check_schema(schema)
            except SchemaError as exc:
                errors.append(f"artifact schema is invalid: {exc.message}")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"cannot load artifact schema: {exc}")

    try:
        campaign_path.resolve().relative_to(repo_root.resolve())
    except ValueError:
        errors.append("campaign manifest must live inside the repository")
    return errors


def _git_state(repo_root: Path) -> tuple[str, bool]:
    commit_proc = run_text(["git", "rev-parse", "HEAD"], cwd=repo_root, timeout=15)
    status_proc = run_text(
        ["git", "status", "--porcelain", "--untracked-files=normal"],
        cwd=repo_root,
        timeout=15,
    )
    if commit_proc.returncode != 0 or status_proc.returncode != 0:
        raise AsmEvidenceError("cannot determine git revision/cleanliness")
    commit = commit_proc.stdout.strip()
    if not HEX40_RE.fullmatch(commit):
        raise AsmEvidenceError(f"git HEAD is not a full commit hash: {commit!r}")
    return commit, not bool(status_proc.stdout.strip())


def _tool_identity(command: str) -> dict[str, Any]:
    found = shutil.which(command)
    if found is None:
        payload: dict[str, Any] = {
            "command": command,
            "available": False,
            "resolved_path": None,
            "version": None,
            "binary_sha256": None,
        }
    else:
        resolved = Path(found).resolve()
        try:
            version_proc = run_text([str(resolved), "--version"], timeout=15)
            version = (version_proc.stdout or version_proc.stderr).strip()
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            version = f"unavailable: {exc}"
        try:
            binary_sha = _sha256_file(resolved)
        except OSError:
            binary_sha = None
        payload = {
            "command": command,
            "available": True,
            "resolved_path": str(resolved),
            "version": version,
            "binary_sha256": binary_sha,
        }
    payload["identity_sha256"] = _sha256_bytes(_canonical_bytes(payload))
    return payload


def _identity_errors(
    identity: Any,
    *,
    command: str,
    label: str,
) -> list[str]:
    """Validate the self-hashed identity used to interpret an evidence cell."""

    if not isinstance(identity, dict):
        return [f"{label} identity missing"]
    errors: list[str] = []
    identity_copy = {key: value for key, value in identity.items() if key != "identity_sha256"}
    expected_hash = _sha256_bytes(_canonical_bytes(identity_copy))
    if identity.get("identity_sha256") != expected_hash:
        errors.append(f"{label} identity hash drift")
    if identity.get("command") != command:
        errors.append(f"{label} identity command drift")
    if identity.get("available") is not True:
        errors.append(f"{label} identity is unavailable")
    resolved = identity.get("resolved_path")
    if not isinstance(resolved, str) or not Path(resolved).is_absolute():
        errors.append(f"{label} resolved path must be absolute")
    if not isinstance(identity.get("version"), str) or not identity.get("version"):
        errors.append(f"{label} version is missing")
    if not HEX64_RE.fullmatch(str(identity.get("binary_sha256", ""))):
        errors.append(f"{label} binary hash is missing/invalid")
    return errors


def _expected_cells(campaign: dict[str, Any], repo_root: Path) -> list[dict[str, Any]]:
    descriptors: list[dict[str, Any]] = []
    tracked_paths = _git_tracked_paths(repo_root)
    compilers = [str(value) for value in campaign["compilers"]]
    opts = [str(value) for value in campaign["optimization_levels"]]
    for target in campaign["targets"]:
        config_path = _tracked_regular_repo_file(
            repo_root,
            repo_root / target["config"],
            f"{target['id']}.config",
            tracked_paths=tracked_paths,
        )
        config = load_config(config_path)
        assert config.ct is not None
        by_name = {harness.name: harness for harness in config.ct.harnesses}
        for harness_name in target["harnesses"]:
            harness = by_name[harness_name]
            base_flags = _strip_opt(
                list(harness.cflags if harness.cflags is not None else config.ct.cflags)
            )
            include_dirs = [
                _safe_repo_directory(
                    repo_root,
                    config_path.parent / path,
                    f"{target['id']}/{harness_name}.include_dirs[{index}]",
                )
                for index, path in enumerate(harness.include_dirs)
            ]
            include_flags = [f"-I{path}" for path in include_dirs]
            workdir = _safe_repo_directory(
                repo_root,
                config_path.parent / config.ct.workdir,
                f"{target['id']}/{harness_name}.workdir",
            )
            for source_index, source in enumerate(harness.sources):
                source_path = _tracked_regular_repo_file(
                    repo_root,
                    config_path.parent / source,
                    f"{target['id']}/{harness_name}.sources[{source_index}]",
                    tracked_paths=tracked_paths,
                )
                source_display = str(source)
                for compiler in compilers:
                    for opt in opts:
                        key = {
                            "target": target["id"],
                            "harness": harness_name,
                            "source_file": source_display,
                            "compiler": compiler,
                            "opt": opt,
                        }
                        descriptors.append(
                            {
                                **key,
                                "cell_id": _sha256_bytes(_canonical_bytes(key)),
                                "config": _relative(config_path, repo_root),
                                "config_sha256": _sha256_file(config_path),
                                "source_sha256": _sha256_file(source_path),
                                "_config_path": config_path,
                                "_source_path": source_path,
                                "_base_flags": base_flags,
                                "_include_flags": include_flags,
                                "_workdir": workdir,
                                "_tracked_paths": tracked_paths,
                            }
                        )
    return descriptors


def _compile_argv(
    descriptor: dict[str, Any],
    compiler_path: str,
    *,
    object_path: Path | str,
    dependency_path: Path | str,
) -> list[str]:
    return [
        compiler_path,
        descriptor["opt"],
        *descriptor["_base_flags"],
        *descriptor["_include_flags"],
        "-MMD",
        "-MF",
        str(dependency_path),
        "-MT",
        str(object_path),
        "-c",
        str(descriptor["_source_path"]),
        "-o",
        str(object_path),
    ]


def _canonical_compile_argv(descriptor: dict[str, Any], compiler_path: str) -> list[str]:
    return _compile_argv(
        descriptor,
        compiler_path,
        object_path=COMPILE_OUTPUT_TOKEN,
        dependency_path=DEPENDENCY_OUTPUT_TOKEN,
    )


def _dependency_records(
    dependency_path: Path,
    *,
    workdir: Path,
    repo_root: Path,
    tracked_paths: set[str],
) -> list[dict[str, Any]]:
    try:
        if not stat.S_ISREG(dependency_path.lstat().st_mode):
            raise ValueError("compiler dependency path is not a regular file")
        raw = dependency_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot read compiler dependency file: {exc}") from exc
    logical = re.sub(r"\\\r?\n", " ", raw)
    _, separator, dependency_text = logical.partition(":")
    if not separator:
        raise ValueError("compiler dependency file has no target separator")
    try:
        values = shlex.split(dependency_text, posix=True)
    except ValueError as exc:
        raise ValueError(f"cannot parse compiler dependency file: {exc}") from exc
    if not values:
        raise ValueError("compiler dependency file contains no dependencies")

    by_path: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(values):
        dependency = Path(value)
        if not dependency.is_absolute():
            dependency = workdir / dependency
        checked = _tracked_regular_repo_file(
            repo_root,
            dependency,
            f"compiler dependency[{index}]",
            tracked_paths=tracked_paths,
        )
        relative = checked.relative_to(repo_root.resolve()).as_posix()
        by_path[relative] = {
            "path": relative,
            "sha256": _sha256_file(checked),
            "size": checked.stat().st_size,
        }
    return [by_path[path] for path in sorted(by_path)]


def _validate_dependency_records(
    records: Any,
    *,
    descriptor: dict[str, Any],
    repo_root: Path,
    errors: list[str],
    cell_id: Any,
) -> list[dict[str, Any]]:
    if not isinstance(records, list):
        errors.append(f"{cell_id}: dependencies must be a list")
        return []
    recomputed: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, record in enumerate(records):
        if not isinstance(record, dict) or set(record) != {"path", "sha256", "size"}:
            errors.append(f"{cell_id}: dependency[{index}] is malformed")
            continue
        path_value = record.get("path")
        if not isinstance(path_value, str) or not path_value:
            errors.append(f"{cell_id}: dependency[{index}] path is malformed")
            continue
        try:
            checked = _tracked_regular_repo_file(
                repo_root,
                repo_root / path_value,
                f"{cell_id}.dependencies[{index}]",
                tracked_paths=descriptor["_tracked_paths"],
            )
        except ValueError as exc:
            errors.append(str(exc))
            continue
        relative = checked.relative_to(repo_root.resolve()).as_posix()
        if relative != path_value:
            errors.append(f"{cell_id}: dependency[{index}] path is not canonical")
        if relative in seen:
            errors.append(f"{cell_id}: duplicate dependency path {relative!r}")
        seen.add(relative)
        current = {
            "path": relative,
            "sha256": _sha256_file(checked),
            "size": checked.stat().st_size,
        }
        if record != current:
            errors.append(f"{cell_id}: dependency content drift for {relative}")
        recomputed.append(current)
    recomputed.sort(key=lambda row: row["path"])
    if records != recomputed:
        errors.append(f"{cell_id}: dependency closure order/content drift")
    source_relative = descriptor["_source_path"].relative_to(repo_root.resolve()).as_posix()
    if source_relative not in seen:
        errors.append(f"{cell_id}: dependency closure omits source {source_relative}")
    return recomputed


def _diagnostic(stdout: str, stderr: str, *, limit: int = 4000) -> str:
    text = (stderr or stdout or "").strip()
    return text[-limit:]


def _stage_from_process(proc: subprocess.CompletedProcess) -> dict[str, Any]:
    stage: dict[str, Any] = {
        "status": "pass" if proc.returncode == 0 else "error",
        "returncode": int(proc.returncode),
        "stdout_sha256": _sha256_text(proc.stdout or ""),
        "stderr_sha256": _sha256_text(proc.stderr or ""),
    }
    if proc.returncode != 0:
        stage["diagnostic"] = _diagnostic(proc.stdout or "", proc.stderr or "")
    return stage


def _stage_from_transcripts(
    proc: subprocess.CompletedProcess,
    *,
    stdout: str,
    stderr: str,
) -> dict[str, Any]:
    stage: dict[str, Any] = {
        "status": "pass" if proc.returncode == 0 else "error",
        "returncode": int(proc.returncode),
        "stdout_sha256": _sha256_text(stdout),
        "stderr_sha256": _sha256_text(stderr),
    }
    if proc.returncode != 0:
        stage["diagnostic"] = _diagnostic(stdout, stderr)
    return stage


def _canonical_compile_text(
    text: str,
    *,
    repo_root: Path,
    temporary_root: Path,
) -> str:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    for source, replacement in (
        (str(repo_root.resolve()), "<repo>"),
        (str(temporary_root.resolve()), "<temporary>"),
    ):
        normalized = normalized.replace(source, replacement)
    return normalized


def _validate_stage_transcript(
    stage: Any,
    *,
    label: str,
    cell_id: Any,
    errors: list[str],
) -> bool:
    if not isinstance(stage, dict):
        errors.append(f"{cell_id}: {label} stage must be an object")
        return False
    status = stage.get("status")
    if status not in {"pass", "error", "timeout", "tool-unavailable", "not-run"}:
        errors.append(f"{cell_id}: invalid {label} stage status {status!r}")
    passed = status == "pass"
    if passed:
        if stage.get("returncode") != 0:
            errors.append(f"{cell_id}: passing {label} stage must record returncode 0")
        for field in ("stdout_sha256", "stderr_sha256"):
            if not HEX64_RE.fullmatch(str(stage.get(field, ""))):
                errors.append(f"{cell_id}: passing {label} stage lacks {field}")
    return passed


def _candidate_rows(hits: Iterable[Any]) -> list[dict[str, str]]:
    rows = [
        {
            "function": hit.function,
            "addr": hit.addr,
            "mnemonic": hit.mnemonic,
            "operand_text": hit.operand_text,
            "instruction_text": hit.instruction_text,
        }
        for hit in hits
    ]
    rows.sort(
        key=lambda row: (
            row["function"],
            int(row["addr"], 16),
            row["mnemonic"],
            row["operand_text"],
        )
    )
    return rows


def _write_content_addressed_artifact(
    output_root: Path,
    raw: bytes,
    *,
    suffix: str,
    allow_empty: bool = False,
) -> dict[str, Any]:
    if not raw and not allow_empty:
        raise AsmEvidenceError(f"empty assembly evidence artifact: {suffix}")
    if len(raw) > MAX_DISASSEMBLY_BYTES:
        raise AsmEvidenceError(
            f"assembly evidence artifact exceeds {MAX_DISASSEMBLY_BYTES} bytes: {len(raw)}"
        )
    if suffix not in {
        ".object",
        ".objdump.txt",
        ".nm.txt",
        ".compile.stdout.txt",
        ".compile.stderr.txt",
    }:
        raise AsmEvidenceError(f"unsupported assembly evidence suffix: {suffix}")
    digest = _sha256_bytes(raw)
    relative = Path("raw") / "sha256" / f"{digest}{suffix}"
    path = output_root / relative
    try:
        _reject_symlink_components(path, "assembly evidence artifact path")
    except ValueError as exc:
        raise AsmEvidenceError(str(exc)) from exc
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if not stat.S_ISREG(path.lstat().st_mode):
            raise AsmEvidenceError(f"artifact path is not a regular file: {path}")
        if path.read_bytes() != raw:
            raise AsmEvidenceError(f"content-address collision/tamper at {path}")
    else:
        path.write_bytes(raw)
    return {"path": relative.as_posix(), "sha256": digest, "size": len(raw)}


def _write_content_addressed_disassembly(output_root: Path, text: str) -> dict[str, Any]:
    return _write_content_addressed_artifact(
        output_root,
        text.encode("utf-8"),
        suffix=".objdump.txt",
    )


def _read_content_addressed_artifact(
    bundle_root: Path,
    artifact: Any,
    *,
    suffix: str,
    label: str,
    referenced: dict[str, dict[str, Any]],
    errors: list[str],
    allow_empty: bool = False,
) -> Optional[bytes]:
    if not isinstance(artifact, dict) or set(artifact) != {"path", "sha256", "size"}:
        errors.append(f"{label}: artifact record is missing or malformed")
        return None
    digest = str(artifact.get("sha256", ""))
    expected_path = f"raw/sha256/{digest}{suffix}"
    if artifact.get("path") != expected_path or not HEX64_RE.fullmatch(digest):
        errors.append(f"{label}: content-addressed path/hash drift")
        return None
    try:
        path = _safe_bundle_path(bundle_root, expected_path, label)
        raw = path.read_bytes()
    except (OSError, ValueError) as exc:
        errors.append(f"{label} unavailable: {exc}")
        return None
    if _sha256_bytes(raw) != digest:
        errors.append(f"{label} hash mismatch")
    if artifact.get("size") != len(raw):
        errors.append(f"{label} size mismatch")
    if not raw and not allow_empty:
        errors.append(f"{label}: raw artifact is empty")
    if len(raw) > MAX_DISASSEMBLY_BYTES:
        errors.append(f"{label}: raw artifact exceeds size limit")
    referenced[expected_path] = artifact
    return raw


def _canonical_tool_text(
    text: str,
    *,
    repo_root: Path,
    bundle_root: Path,
    temporary_root: Path | None = None,
) -> str:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    replacements = [
        (str(repo_root.resolve()), "<repo>"),
        (str(bundle_root.resolve()), "<bundle>"),
    ]
    if temporary_root is not None:
        replacements.append((str(temporary_root.resolve()), "<bundle>"))
    for source, target in replacements:
        normalized = normalized.replace(source, target)
    lines = normalized.splitlines()
    for index, line in enumerate(lines):
        marker = re.search(r":\s+file format\s+", line)
        if marker is not None:
            lines[index] = "<object>" + line[marker.start() :]
            break
    return "\n".join(lines).rstrip()


def _attribution_errors(campaign: dict[str, Any], cells: list[dict[str, Any]]) -> list[str]:
    policy = campaign["attribution_policy"]
    allowed_sources = tuple(str(value) for value in policy["allowed_source_suffixes"])
    allowed_functions = {str(value) for value in policy["allowed_functions"]}
    required_functions = {str(value) for value in policy["required_functions_per_harness"]}
    errors: list[str] = []
    observed: dict[tuple[str, str], set[str]] = {
        pair: set() for pair in _scope_pairs(campaign_scope(campaign))
    }
    for cell in cells:
        cell_id = cell.get("cell_id", "unknown-cell")
        pair = (str(cell.get("target", "")), str(cell.get("harness", "")))
        candidates = cell.get("candidates", [])
        if not isinstance(candidates, list):
            errors.append(f"{cell_id}: candidates must be a list")
            continue
        for candidate in candidates:
            if not isinstance(candidate, dict):
                errors.append(f"{cell_id}: candidate entry must be an object")
                continue
            function = str(candidate.get("function", ""))
            source = str(cell.get("source_file", ""))
            observed.setdefault(pair, set()).add(function)
            if function not in allowed_functions:
                errors.append(
                    f"{cell_id}: candidate function {function!r} is outside public policy"
                )
            normalized = source.replace("\\", "/")
            if not any(normalized.endswith(suffix) for suffix in allowed_sources):
                errors.append(f"{cell_id}: candidate source {source!r} is outside public policy")
            if triage_hint_for(source, function) != "keccak-rate-review-likely-public":
                errors.append(f"{cell_id}: candidate lacks the Keccak public-review hint")
            if not candidate.get("instruction_text"):
                errors.append(f"{cell_id}: candidate instruction text is missing")
    for pair, functions in observed.items():
        if functions != required_functions:
            errors.append(
                f"{pair[0]}/{pair[1]} candidate scope drift: "
                f"observed={sorted(functions)!r}, required={sorted(required_functions)!r}"
            )
    return errors


def build_bundle(
    campaign_path: Path,
    output_root: Path,
    *,
    repo_root: Path,
    timeout: float = 300,
    allow_dirty: bool = False,
    allow_nonpaper_host: bool = False,
    git_state_override: Optional[tuple[str, bool]] = None,
    tool_identities_override: Optional[dict[str, dict[str, Any]]] = None,
    runner: Callable[..., subprocess.CompletedProcess] = run_text,
) -> tuple[dict[str, Any], Path, list[Path]]:
    """Compile all frozen cells and write the external raw bundle + indexes."""

    repo_root = repo_root.resolve()
    campaign_path = _lexical_absolute(campaign_path)
    campaign = load_campaign(campaign_path)
    static_errors = validate_campaign(campaign, campaign_path=campaign_path, repo_root=repo_root)
    if static_errors:
        raise AsmEvidenceError("invalid asm evidence campaign: " + "; ".join(static_errors))
    commit, clean = git_state_override or _git_state(repo_root)
    if not clean and not allow_dirty:
        raise AsmEvidenceError("repository is dirty; exact paper evidence requires a clean commit")
    host = {"system": platform.system(), "machine": platform.machine()}
    host_ok = host["system"] == "Linux" and host["machine"] in {"x86_64", "AMD64"}
    if not host_ok and not allow_nonpaper_host:
        raise AsmEvidenceError(f"paper asm evidence requires native Linux x86_64, got {host}")

    tools = campaign["tools"]
    commands = [*campaign["compilers"], tools["objdump"], tools["nm"]]
    identities = tool_identities_override or {
        str(command): _tool_identity(str(command)) for command in commands
    }
    compiler_identities = {compiler: identities[compiler] for compiler in campaign["compilers"]}
    objdump_identity = identities[tools["objdump"]]
    nm_identity = identities[tools["nm"]]

    descriptors = _expected_cells(campaign, repo_root)
    output_root = _prepare_output_root(output_root)
    cells: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="ctkat-asm-evidence-") as temp_name:
        temp = Path(temp_name)
        for descriptor in descriptors:
            compiler_identity = compiler_identities[descriptor["compiler"]]
            object_path = temp / f"{descriptor['cell_id']}.o"
            dependency_path = temp / f"{descriptor['cell_id']}.d"
            compiler_path = compiler_identity.get("resolved_path")
            compiler_command = str(compiler_path or descriptor["compiler"])
            compile_argv = _compile_argv(
                descriptor,
                compiler_command,
                object_path=object_path,
                dependency_path=dependency_path,
            )
            cell: dict[str, Any] = {
                key: descriptor[key]
                for key in (
                    "cell_id",
                    "target",
                    "harness",
                    "source_file",
                    "source_sha256",
                    "config",
                    "config_sha256",
                    "compiler",
                    "opt",
                )
            }
            cell["compiler_identity_sha256"] = compiler_identity["identity_sha256"]
            cell["compile_argv"] = _canonical_compile_argv(descriptor, compiler_command)
            cell["candidates"] = []
            if not compiler_identity.get("available"):
                cell["compile"] = {
                    "status": "tool-unavailable",
                    "diagnostic": f"compiler {descriptor['compiler']!r} unavailable",
                }
                cell["disassembly"] = {"status": "not-run"}
                cell["nm"] = {"status": "not-run"}
                cell["status"] = "compile-error"
                cells.append(cell)
                continue
            try:
                compile_proc = runner(
                    compile_argv,
                    cwd=descriptor["_workdir"],
                    timeout=timeout,
                )
                compile_stdout = _canonical_compile_text(
                    compile_proc.stdout or "",
                    repo_root=repo_root,
                    temporary_root=temp,
                )
                compile_stderr = _canonical_compile_text(
                    compile_proc.stderr or "",
                    repo_root=repo_root,
                    temporary_root=temp,
                )
                cell["compile"] = _stage_from_transcripts(
                    compile_proc,
                    stdout=compile_stdout,
                    stderr=compile_stderr,
                )
                stdout_artifact = _write_content_addressed_artifact(
                    output_root,
                    compile_stdout.encode("utf-8"),
                    suffix=".compile.stdout.txt",
                    allow_empty=True,
                )
                stderr_artifact = _write_content_addressed_artifact(
                    output_root,
                    compile_stderr.encode("utf-8"),
                    suffix=".compile.stderr.txt",
                    allow_empty=True,
                )
                cell["compile_stdout_artifact"] = stdout_artifact
                cell["compile_stderr_artifact"] = stderr_artifact
            except subprocess.TimeoutExpired:
                cell["compile"] = {
                    "status": "timeout",
                    "diagnostic": f"compile exceeded timeout={timeout}s",
                }
            except (AsmEvidenceError, OSError) as exc:
                cell["compile"] = {"status": "error", "diagnostic": str(exc)}
            if (
                cell["compile"]["status"] != "pass"
                or not object_path.is_file()
                or object_path.is_symlink()
            ):
                if cell["compile"]["status"] == "pass":
                    cell["compile"] = {
                        **cell["compile"],
                        "status": "error",
                        "diagnostic": "compiler returned success without an object file",
                    }
                cell["disassembly"] = {"status": "not-run"}
                cell["nm"] = {"status": "not-run"}
                cell["status"] = "compile-error"
                cells.append(cell)
                continue

            try:
                dependencies = _dependency_records(
                    dependency_path,
                    workdir=descriptor["_workdir"],
                    repo_root=repo_root,
                    tracked_paths=descriptor["_tracked_paths"],
                )
                source_relative = descriptor["_source_path"].relative_to(repo_root).as_posix()
                if source_relative not in {dependency["path"] for dependency in dependencies}:
                    raise AsmEvidenceError(
                        f"compiler dependency closure omits source {source_relative}"
                    )
                object_artifact = _write_content_addressed_artifact(
                    output_root,
                    object_path.read_bytes(),
                    suffix=".object",
                )
            except (AsmEvidenceError, OSError, ValueError) as exc:
                cell["compile"] = {
                    **cell["compile"],
                    "status": "error",
                    "diagnostic": f"cannot preserve compiled object: {exc}",
                }
                cell["disassembly"] = {"status": "not-run"}
                cell["nm"] = {"status": "not-run"}
                cell["status"] = "compile-error"
                cells.append(cell)
                continue
            cell["dependencies"] = dependencies
            cell["object_artifact"] = object_artifact
            cell["object_sha256"] = object_artifact["sha256"]
            cell["object_size"] = object_artifact["size"]
            objdump_path = objdump_identity.get("resolved_path")
            nm_path = nm_identity.get("resolved_path")
            object_argument = object_artifact["path"]
            objdump_argv = [
                str(objdump_path or tools["objdump"]),
                *tools["full_disassembly_argv"],
                object_argument,
            ]
            nm_argv = [str(nm_path or tools["nm"]), "-n", object_argument]
            cell["objdump_argv"] = objdump_argv
            cell["nm_argv"] = nm_argv
            if not objdump_identity.get("available") or not nm_identity.get("available"):
                cell["disassembly"] = {
                    "status": "tool-unavailable",
                    "diagnostic": "objdump and nm are both required for attributable evidence",
                }
                cell["nm"] = {"status": "tool-unavailable"}
                cell["status"] = "disasm-error"
                cells.append(cell)
                continue
            try:
                disasm_proc = runner(objdump_argv, cwd=output_root, timeout=timeout)
                nm_proc = runner(nm_argv, cwd=output_root, timeout=timeout)
            except subprocess.TimeoutExpired:
                cell["disassembly"] = {
                    "status": "timeout",
                    "diagnostic": f"objdump/nm exceeded timeout={timeout}s",
                }
                cell["nm"] = {"status": "timeout"}
                cell["status"] = "disasm-error"
                cells.append(cell)
                continue
            except (FileNotFoundError, PermissionError) as exc:
                cell["disassembly"] = {"status": "error", "diagnostic": str(exc)}
                cell["nm"] = {"status": "error", "diagnostic": str(exc)}
                cell["status"] = "disasm-error"
                cells.append(cell)
                continue
            if disasm_proc.returncode != 0 or nm_proc.returncode != 0:
                cell["disassembly"] = {
                    "status": "error",
                    "returncode": int(disasm_proc.returncode or nm_proc.returncode),
                    "stdout_sha256": _sha256_text(disasm_proc.stdout or ""),
                    "stderr_sha256": _sha256_text(
                        (disasm_proc.stderr or "") + (nm_proc.stderr or "")
                    ),
                    "diagnostic": _diagnostic(
                        disasm_proc.stdout or "",
                        (disasm_proc.stderr or "") + (nm_proc.stderr or ""),
                    ),
                }
                cell["nm"] = _stage_from_process(nm_proc)
                cell["status"] = "disasm-error"
                cells.append(cell)
                continue
            try:
                disassembly_artifact = _write_content_addressed_disassembly(
                    output_root, disasm_proc.stdout
                )
                nm_artifact = _write_content_addressed_artifact(
                    output_root,
                    (nm_proc.stdout or "").encode("utf-8"),
                    suffix=".nm.txt",
                )
                hits = parse_objdump_details(disasm_proc.stdout)
                hits = resolve_disassembly_hits(hits, parse_nm(nm_proc.stdout))
            except (AsmEvidenceError, ValueError) as exc:
                cell["disassembly"] = {"status": "error", "diagnostic": str(exc)}
                cell["status"] = "disasm-error"
                cells.append(cell)
                continue
            cell["disassembly"] = _stage_from_process(disasm_proc)
            cell["nm"] = _stage_from_process(nm_proc)
            cell["disassembly_artifact"] = disassembly_artifact
            cell["nm_artifact"] = nm_artifact
            cell["candidates"] = _candidate_rows(hits)
            cell["status"] = "pass"
            cells.append(cell)

    cells.sort(
        key=lambda cell: (
            cell["target"],
            cell["harness"],
            cell["source_file"],
            cell["compiler"],
            cell["opt"],
        )
    )
    artifacts_by_path: dict[str, dict[str, Any]] = {}
    for cell in cells:
        for field in (
            "compile_stdout_artifact",
            "compile_stderr_artifact",
            "object_artifact",
            "disassembly_artifact",
            "nm_artifact",
        ):
            artifact = cell.get(field)
            if isinstance(artifact, dict):
                artifacts_by_path[str(artifact["path"])] = artifact
    artifacts = [artifacts_by_path[path] for path in sorted(artifacts_by_path)]
    raw_hash = _sha256_bytes(_canonical_bytes(artifacts))
    failed = sum(cell["status"] != "pass" for cell in cells)
    coverage = {
        "status": "pass" if failed == 0 and len(cells) == len(descriptors) else "incomplete",
        "expected_cells": len(descriptors),
        "passed_cells": sum(cell["status"] == "pass" for cell in cells),
        "failed_cells": failed,
    }
    attribution_errors = _attribution_errors(campaign, cells)
    errors = [f"{cell['cell_id']} {cell['status']}" for cell in cells if cell["status"] != "pass"]
    errors.extend(attribution_errors)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": BUNDLE_KIND,
        "campaign_id": campaign["campaign_id"],
        "campaign_manifest": {
            "path": _relative(campaign_path, repo_root),
            "sha256": _sha256_file(campaign_path),
        },
        "source_revision": {"commit": commit, "clean": clean},
        "host": host,
        "toolchain": {
            "compilers": compiler_identities,
            "objdump": objdump_identity,
            "nm": nm_identity,
        },
        "public_scope": campaign_scope(campaign),
        "coverage": coverage,
        "raw_bundle": {
            "path": campaign["artifact"]["raw_directory"],
            "sha256": raw_hash,
            "artifact_count": len(artifacts),
            "artifacts": artifacts,
        },
        "paper_eligible": bool(clean and host_ok and coverage["status"] == "pass" and not errors),
        "errors": errors,
        "cells": cells,
    }
    manifest_name = str(campaign["artifact"]["manifest_name"])
    bundle_path = output_root / manifest_name
    try:
        _reject_symlink_components(bundle_path, "bundle manifest path")
    except ValueError as exc:
        raise AsmEvidenceError(str(exc)) from exc
    bundle_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if manifest["paper_eligible"]:
        validation_errors = validate_bundle(
            bundle_path,
            campaign_path,
            repo_root=repo_root,
            current_git_state_override=(commit, clean),
            tool_identities_override=identities,
            runner=runner,
            timeout=timeout,
        )
        if validation_errors:
            raise AsmEvidenceError(
                "newly built bundle failed self-validation: " + "; ".join(validation_errors)
            )
    index_paths = write_target_indexes(manifest, bundle_path, output_root)
    return manifest, bundle_path, index_paths


def _current_cell_key(cell: dict[str, Any]) -> tuple[str, str, str, str, str]:
    return (
        str(cell.get("target", "")),
        str(cell.get("harness", "")),
        str(cell.get("source_file", "")),
        str(cell.get("compiler", "")),
        str(cell.get("opt", "")),
    )


def _validate_candidate_policy(
    campaign: dict[str, Any], cells: list[dict[str, Any]], errors: list[str]
) -> None:
    errors.extend(_attribution_errors(campaign, cells))


def _manifest_schema_errors(
    manifest: dict[str, Any],
    campaign: dict[str, Any],
    *,
    repo_root: Path,
) -> list[str]:
    artifact = campaign.get("artifact")
    if not isinstance(artifact, dict):
        return ["cannot validate bundle schema: campaign artifact record is missing"]
    try:
        schema_path = _repo_path(repo_root, artifact.get("schema"), "artifact.schema")
        expected_hash = artifact.get("schema_sha256")
        actual_hash = _sha256_file(schema_path)
        if not HEX64_RE.fullmatch(str(expected_hash or "")):
            return ["cannot validate bundle schema: campaign schema hash is invalid"]
        if actual_hash != expected_hash:
            return ["cannot validate bundle schema: artifact schema hash drift"]
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
    except (OSError, ValueError, json.JSONDecodeError, SchemaError) as error:
        return [f"cannot validate bundle schema: {error}"]

    validator = Draft202012Validator(schema)
    validation_errors = sorted(
        validator.iter_errors(manifest),
        key=lambda validation_error: tuple(str(part) for part in validation_error.absolute_path),
    )
    errors: list[str] = []
    for validation_error in validation_errors:
        location = ".".join(str(part) for part in validation_error.absolute_path) or "<root>"
        errors.append(f"bundle schema violation at {location}: {validation_error.message}")
    return errors


def validate_bundle(
    bundle_path: Path,
    campaign_path: Path,
    *,
    repo_root: Path,
    require_current_commit: bool = True,
    require_complete: bool = True,
    expected_commit: Optional[str] = None,
    current_git_state_override: Optional[tuple[str, bool]] = None,
    tool_identities_override: Optional[dict[str, dict[str, Any]]] = None,
    runner: Callable[..., subprocess.CompletedProcess] = run_text,
    timeout: float = 300,
) -> list[str]:
    """Recompute provenance and rerun objdump/nm over every preserved object."""

    errors: list[str] = []
    repo_root = repo_root.resolve()
    campaign_path = _lexical_absolute(campaign_path)
    bundle_path = bundle_path.resolve()
    bundle_root = bundle_path.parent
    try:
        campaign = load_campaign(campaign_path)
        errors.extend(validate_campaign(campaign, campaign_path=campaign_path, repo_root=repo_root))
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return [f"cannot load campaign: {exc}"]
    try:
        manifest = json.loads(bundle_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"cannot load bundle manifest: {exc}"]
    if not isinstance(manifest, dict):
        return ["bundle manifest root must be an object"]
    schema_errors = _manifest_schema_errors(manifest, campaign, repo_root=repo_root)
    if schema_errors:
        return list(dict.fromkeys([*errors, *schema_errors]))
    if manifest.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"bundle schema_version must be {SCHEMA_VERSION}")
    if manifest.get("kind") != BUNDLE_KIND:
        errors.append(f"bundle kind must be {BUNDLE_KIND}")
    if manifest.get("campaign_id") != campaign.get("campaign_id"):
        errors.append("bundle campaign_id drift")
    campaign_record = manifest.get("campaign_manifest")
    expected_campaign_record = {
        "path": _relative(campaign_path.resolve(), repo_root),
        "sha256": _sha256_file(campaign_path.resolve()),
    }
    if campaign_record != expected_campaign_record:
        errors.append("campaign manifest path/hash drift")

    revision = manifest.get("source_revision")
    if not isinstance(revision, dict):
        errors.append("source_revision must be an object")
        revision = {}
    if not HEX40_RE.fullmatch(str(revision.get("commit", ""))):
        errors.append("source_revision.commit must be a full lowercase git hash")
    if expected_commit is not None:
        if not HEX40_RE.fullmatch(expected_commit):
            errors.append("expected_commit must be a full lowercase git hash")
        elif revision.get("commit") != expected_commit:
            errors.append(
                f"bundle commit {revision.get('commit')} != expected commit {expected_commit}"
            )
    if revision.get("clean") is not True:
        errors.append("source_revision.clean must be true")
    if require_current_commit:
        try:
            current_commit, current_clean = current_git_state_override or _git_state(repo_root)
            if revision.get("commit") != current_commit:
                errors.append(
                    f"bundle commit {revision.get('commit')} != current HEAD {current_commit}"
                )
            if not current_clean:
                errors.append("current repository is dirty")
        except AsmEvidenceError as exc:
            errors.append(str(exc))

    host = manifest.get("host")
    if (
        not isinstance(host, dict)
        or host.get("system") != "Linux"
        or host.get("machine") not in {"x86_64", "AMD64"}
    ):
        errors.append("bundle host must be Linux x86_64")
    if _scope_pairs(manifest.get("public_scope", [])) != _scope_pairs(campaign_scope(campaign)):
        errors.append("bundle public_scope drift")

    toolchain = manifest.get("toolchain")
    compiler_identities: dict[str, Any] = {}
    objdump_identity: dict[str, Any] = {}
    nm_identity: dict[str, Any] = {}
    if not isinstance(toolchain, dict):
        errors.append("toolchain must be an object")
    else:
        raw_compilers = toolchain.get("compilers")
        if isinstance(raw_compilers, dict):
            compiler_identities = raw_compilers
        else:
            errors.append("toolchain.compilers must be an object")
        for compiler in campaign["compilers"]:
            identity = compiler_identities.get(compiler)
            errors.extend(
                _identity_errors(
                    identity,
                    command=compiler,
                    label=f"compiler {compiler}",
                )
            )
        tools = campaign["tools"]
        raw_objdump = toolchain.get("objdump")
        raw_nm = toolchain.get("nm")
        if isinstance(raw_objdump, dict):
            objdump_identity = raw_objdump
        if isinstance(raw_nm, dict):
            nm_identity = raw_nm
        errors.extend(
            _identity_errors(
                raw_objdump,
                command=str(tools["objdump"]),
                label="objdump",
            )
        )
        errors.extend(
            _identity_errors(
                raw_nm,
                command=str(tools["nm"]),
                label="nm",
            )
        )

    validation_identities = tool_identities_override or {
        str(command): _tool_identity(str(command))
        for command in (
            *campaign["compilers"],
            campaign["tools"]["objdump"],
            campaign["tools"]["nm"],
        )
    }
    current_objdump = validation_identities.get(str(campaign["tools"]["objdump"]), {})
    current_nm = validation_identities.get(str(campaign["tools"]["nm"]), {})
    for label, recorded, current in (
        ("objdump", objdump_identity, current_objdump),
        ("nm", nm_identity, current_nm),
    ):
        if current.get("identity_sha256") != recorded.get("identity_sha256"):
            errors.append(f"current {label} identity differs from the bundle's recorded tool")
    for compiler in campaign["compilers"]:
        current = validation_identities.get(str(compiler), {})
        recorded = compiler_identities.get(str(compiler), {})
        if current.get("identity_sha256") != recorded.get("identity_sha256"):
            errors.append(
                f"current compiler {compiler} identity differs from the bundle's recorded tool"
            )

    try:
        descriptors = _expected_cells(campaign, repo_root)
    except (OSError, ValueError) as exc:
        errors.append(f"cannot reconstruct expected cells: {exc}")
        descriptors = []
    expected_by_key = {_current_cell_key(cell): cell for cell in descriptors}
    raw_cells = manifest.get("cells")
    if not isinstance(raw_cells, list):
        errors.append("cells must be a list")
        raw_cells = []
    cells = [cell for cell in raw_cells if isinstance(cell, dict)]
    if len(cells) != len(raw_cells):
        errors.append("every cells entry must be an object")
    actual_by_key: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    for cell in cells:
        key = _current_cell_key(cell)
        if key in actual_by_key:
            errors.append(f"duplicate evidence cell: {key!r}")
        actual_by_key[key] = cell
    missing = sorted(set(expected_by_key) - set(actual_by_key))
    extra = sorted(set(actual_by_key) - set(expected_by_key))
    if missing:
        errors.append(f"missing source/compiler/opt cells: {missing!r}")
    if extra:
        errors.append(f"unexpected source/compiler/opt cells: {extra!r}")

    referenced_artifacts: dict[str, dict[str, Any]] = {}
    passed = 0
    for key, cell in actual_by_key.items():
        descriptor = expected_by_key.get(key)
        if descriptor is None:
            continue
        if cell.get("cell_id") != descriptor["cell_id"]:
            errors.append(f"{key!r}: cell_id drift")
        for field in ("config", "config_sha256", "source_sha256"):
            if cell.get(field) != descriptor[field]:
                errors.append(f"{cell.get('cell_id', key)}: {field} drift")
        identity = compiler_identities.get(descriptor["compiler"], {})
        if cell.get("compiler_identity_sha256") != identity.get("identity_sha256"):
            errors.append(f"{cell.get('cell_id', key)}: compiler identity reference drift")
        cell_id = cell.get("cell_id", key)
        argv = cell.get("compile_argv")
        expected_argv = _canonical_compile_argv(
            descriptor,
            str(identity.get("resolved_path") or descriptor["compiler"]),
        )
        if argv != expected_argv:
            errors.append(f"{cell.get('cell_id', key)}: compile argv drift")
        compile_stage = cell.get("compile")
        disasm_stage = cell.get("disassembly")
        nm_stage = cell.get("nm")
        compile_pass = _validate_stage_transcript(
            compile_stage,
            label="compile",
            cell_id=cell_id,
            errors=errors,
        )
        disasm_pass = _validate_stage_transcript(
            disasm_stage,
            label="disassembly",
            cell_id=cell_id,
            errors=errors,
        )
        nm_pass = _validate_stage_transcript(
            nm_stage,
            label="nm",
            cell_id=cell_id,
            errors=errors,
        )
        recomputed_status = (
            "pass"
            if compile_pass and disasm_pass and nm_pass
            else ("compile-error" if not compile_pass else "disasm-error")
        )
        if cell.get("status") not in {"pass", "compile-error", "disasm-error"}:
            errors.append(f"{cell_id}: invalid cell status {cell.get('status')!r}")
        if cell.get("status") != recomputed_status:
            errors.append(f"{cell.get('cell_id', key)}: status contradicts stage statuses")
        object_raw: Optional[bytes] = None
        compile_stdout_raw: Optional[bytes] = None
        compile_stderr_raw: Optional[bytes] = None
        recorded_dependencies: list[dict[str, Any]] = []
        if compile_pass:
            compile_stdout_raw = _read_content_addressed_artifact(
                bundle_root,
                cell.get("compile_stdout_artifact"),
                suffix=".compile.stdout.txt",
                label=f"{cell_id}: compile stdout transcript",
                referenced=referenced_artifacts,
                errors=errors,
                allow_empty=True,
            )
            compile_stderr_raw = _read_content_addressed_artifact(
                bundle_root,
                cell.get("compile_stderr_artifact"),
                suffix=".compile.stderr.txt",
                label=f"{cell_id}: compile stderr transcript",
                referenced=referenced_artifacts,
                errors=errors,
                allow_empty=True,
            )
            if isinstance(compile_stage, dict):
                if compile_stdout_raw is not None and compile_stage.get(
                    "stdout_sha256"
                ) != _sha256_bytes(compile_stdout_raw):
                    errors.append(f"{cell_id}: compile stdout hash/artifact drift")
                if compile_stderr_raw is not None and compile_stage.get(
                    "stderr_sha256"
                ) != _sha256_bytes(compile_stderr_raw):
                    errors.append(f"{cell_id}: compile stderr hash/artifact drift")
            recorded_dependencies = _validate_dependency_records(
                cell.get("dependencies"),
                descriptor=descriptor,
                repo_root=repo_root,
                errors=errors,
                cell_id=cell_id,
            )
            object_artifact = cell.get("object_artifact")
            object_raw = _read_content_addressed_artifact(
                bundle_root,
                object_artifact,
                suffix=".object",
                label=f"{cell_id}: compiled object",
                referenced=referenced_artifacts,
                errors=errors,
            )
            object_arg = object_artifact.get("path") if isinstance(object_artifact, dict) else None
            expected_objdump_argv = [
                str(objdump_identity.get("resolved_path") or campaign["tools"]["objdump"]),
                *campaign["tools"]["full_disassembly_argv"],
                object_arg,
            ]
            expected_nm_argv = [
                str(nm_identity.get("resolved_path") or campaign["tools"]["nm"]),
                "-n",
                object_arg,
            ]
            if cell.get("objdump_argv") != expected_objdump_argv:
                errors.append(f"{cell_id}: objdump argv drift")
            if cell.get("nm_argv") != expected_nm_argv:
                errors.append(f"{cell_id}: nm argv drift")
            if not HEX64_RE.fullmatch(str(cell.get("object_sha256", ""))):
                errors.append(f"{cell_id}: object hash missing/invalid")
            if not isinstance(cell.get("object_size"), int) or cell.get("object_size", 0) < 1:
                errors.append(f"{cell_id}: object size missing/invalid")
            if object_raw is not None:
                if cell.get("object_sha256") != _sha256_bytes(object_raw):
                    errors.append(f"{cell_id}: preserved object hash drift")
                if cell.get("object_size") != len(object_raw):
                    errors.append(f"{cell_id}: preserved object size drift")
        if recomputed_status != "pass":
            if require_complete:
                errors.append(f"{cell.get('cell_id', key)}: incomplete cell {recomputed_status}")
            continue
        passed += 1
        disassembly_raw = _read_content_addressed_artifact(
            bundle_root,
            cell.get("disassembly_artifact"),
            suffix=".objdump.txt",
            label=f"{cell_id}: raw disassembly",
            referenced=referenced_artifacts,
            errors=errors,
        )
        nm_raw = _read_content_addressed_artifact(
            bundle_root,
            cell.get("nm_artifact"),
            suffix=".nm.txt",
            label=f"{cell_id}: raw nm transcript",
            referenced=referenced_artifacts,
            errors=errors,
        )
        if (
            disassembly_raw is not None
            and isinstance(disasm_stage, dict)
            and disasm_stage.get("stdout_sha256") != _sha256_bytes(disassembly_raw)
        ):
            errors.append(f"{cell.get('cell_id', key)}: disassembly stdout hash/artifact drift")
        if (
            nm_raw is not None
            and isinstance(nm_stage, dict)
            and nm_stage.get("stdout_sha256") != _sha256_bytes(nm_raw)
        ):
            errors.append(f"{cell_id}: nm stdout hash/artifact drift")
        if disassembly_raw is None or nm_raw is None or object_raw is None:
            continue
        text = disassembly_raw.decode("utf-8", errors="strict")
        nm_text = nm_raw.decode("utf-8", errors="strict")
        raw_candidates = _candidate_rows(
            resolve_disassembly_hits(parse_objdump_details(text), parse_nm(nm_text))
        )
        if raw_candidates != cell.get("candidates"):
            errors.append(f"{cell_id}: raw candidate/operand transcript drift")

        rerun_objdump = [
            str(current_objdump.get("resolved_path") or campaign["tools"]["objdump"]),
            *campaign["tools"]["full_disassembly_argv"],
            str(cell["object_artifact"]["path"]),
        ]
        rerun_nm = [
            str(current_nm.get("resolved_path") or campaign["tools"]["nm"]),
            "-n",
            str(cell["object_artifact"]["path"]),
        ]
        try:
            fresh_objdump = runner(rerun_objdump, cwd=bundle_root, timeout=timeout)
            fresh_nm = runner(rerun_nm, cwd=bundle_root, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"{cell_id}: cannot rerun objdump/nm: {exc}")
            continue
        if fresh_objdump.returncode != 0:
            errors.append(f"{cell_id}: fresh objdump failed rc={fresh_objdump.returncode}")
        elif (fresh_objdump.stdout or "").encode("utf-8") != disassembly_raw:
            errors.append(f"{cell_id}: fresh objdump output differs from preserved transcript")
        if fresh_nm.returncode != 0:
            errors.append(f"{cell_id}: fresh nm failed rc={fresh_nm.returncode}")
        elif (fresh_nm.stdout or "").encode("utf-8") != nm_raw:
            errors.append(f"{cell_id}: fresh nm output differs from preserved transcript")

        current_compiler = validation_identities.get(descriptor["compiler"], {})
        compiler_path = current_compiler.get("resolved_path")
        if not isinstance(compiler_path, str) or not compiler_path:
            errors.append(f"{cell_id}: current compiler path is unavailable")
            continue
        try:
            with tempfile.TemporaryDirectory(prefix="ctkat-asm-rebuild-") as temporary_name:
                temporary_root = Path(temporary_name)
                rebuilt_object = temporary_root / f"{cell_id}.o"
                rebuilt_dependency = temporary_root / f"{cell_id}.d"
                rebuild_argv = _compile_argv(
                    descriptor,
                    compiler_path,
                    object_path=rebuilt_object,
                    dependency_path=rebuilt_dependency,
                )
                rebuilt = runner(
                    rebuild_argv,
                    cwd=descriptor["_workdir"],
                    timeout=timeout,
                )
                rebuilt_stdout = _canonical_compile_text(
                    rebuilt.stdout or "",
                    repo_root=repo_root,
                    temporary_root=temporary_root,
                ).encode("utf-8")
                rebuilt_stderr = _canonical_compile_text(
                    rebuilt.stderr or "",
                    repo_root=repo_root,
                    temporary_root=temporary_root,
                ).encode("utf-8")
                if compile_stdout_raw is not None and rebuilt_stdout != compile_stdout_raw:
                    errors.append(
                        f"{cell_id}: independent compile stdout differs from preserved transcript"
                    )
                if compile_stderr_raw is not None and rebuilt_stderr != compile_stderr_raw:
                    errors.append(
                        f"{cell_id}: independent compile stderr differs from preserved transcript"
                    )
                if (
                    rebuilt.returncode != 0
                    or not rebuilt_object.is_file()
                    or rebuilt_object.is_symlink()
                ):
                    errors.append(
                        f"{cell_id}: independent source rebuild failed rc={rebuilt.returncode}"
                    )
                    continue
                rebuilt_dependencies = _dependency_records(
                    rebuilt_dependency,
                    workdir=descriptor["_workdir"],
                    repo_root=repo_root,
                    tracked_paths=descriptor["_tracked_paths"],
                )
                if rebuilt_dependencies != recorded_dependencies:
                    errors.append(
                        f"{cell_id}: independent dependency closure differs from manifest"
                    )
                rebuilt_objdump = runner(
                    [
                        str(current_objdump.get("resolved_path")),
                        *campaign["tools"]["full_disassembly_argv"],
                        str(rebuilt_object),
                    ],
                    timeout=timeout,
                )
                rebuilt_nm = runner(
                    [str(current_nm.get("resolved_path")), "-n", str(rebuilt_object)],
                    timeout=timeout,
                )
                if rebuilt_objdump.returncode != 0 or rebuilt_nm.returncode != 0:
                    errors.append(f"{cell_id}: independent rebuilt objdump/nm failed")
                    continue
                preserved_disassembly = _canonical_tool_text(
                    text,
                    repo_root=repo_root,
                    bundle_root=bundle_root,
                )
                rebuilt_disassembly = _canonical_tool_text(
                    rebuilt_objdump.stdout or "",
                    repo_root=repo_root,
                    bundle_root=bundle_root,
                    temporary_root=temporary_root,
                )
                if rebuilt_disassembly != preserved_disassembly:
                    errors.append(
                        f"{cell_id}: independent source rebuild disassembly differs "
                        "from the preserved object"
                    )
                if (rebuilt_nm.stdout or "").strip() != nm_text.strip():
                    errors.append(
                        f"{cell_id}: independent source rebuild nm symbols differ "
                        "from the preserved object"
                    )
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            errors.append(f"{cell_id}: independent source rebuild could not run: {exc}")

    coverage = manifest.get("coverage")
    # Missing cells count as failed coverage.  A malicious/truncated manifest
    # must never make ``failed_cells`` smaller by simply deleting a row.
    failed = max(len(descriptors) - passed, 0) + len(extra)
    expected_coverage = {
        "status": "pass" if len(cells) == len(descriptors) and failed == 0 else "incomplete",
        "expected_cells": len(descriptors),
        "passed_cells": passed,
        "failed_cells": failed,
    }
    if coverage != expected_coverage:
        errors.append(
            f"coverage summary drift: recorded={coverage!r}, recomputed={expected_coverage!r}"
        )
    if require_complete and expected_coverage["status"] != "pass":
        errors.append("complete coverage required but at least one cell failed or is missing")

    raw_bundle = manifest.get("raw_bundle")
    if not isinstance(raw_bundle, dict):
        errors.append("raw_bundle must be an object")
        raw_bundle = {}
    listed = raw_bundle.get("artifacts")
    if not isinstance(listed, list):
        errors.append("raw_bundle.artifacts must be a list")
        listed = []
    listed_by_path = {str(item.get("path", "")): item for item in listed if isinstance(item, dict)}
    if len(listed_by_path) != len(listed):
        errors.append("raw bundle artifact index has duplicate or malformed entries")
    if listed_by_path != referenced_artifacts:
        errors.append("raw bundle artifact index differs from cell references")
    expected_raw_hash = _sha256_bytes(
        _canonical_bytes([listed_by_path[path] for path in sorted(listed_by_path)])
    )
    if raw_bundle.get("path") != "raw/sha256":
        errors.append("raw_bundle.path drift")
    if raw_bundle.get("sha256") != expected_raw_hash:
        errors.append("aggregate raw bundle hash mismatch")
    if raw_bundle.get("artifact_count") != len(listed_by_path):
        errors.append("raw bundle artifact count mismatch")
    raw_dir = bundle_root / "raw" / "sha256"
    actual_files: set[str] = set()
    invalid_entries: list[str] = []
    try:
        if raw_dir.is_symlink() or not stat.S_ISDIR(raw_dir.lstat().st_mode):
            invalid_entries.append(raw_dir.relative_to(bundle_root).as_posix())
        else:
            with os.scandir(raw_dir) as entries:
                for entry in entries:
                    relative = Path(entry.path).relative_to(bundle_root).as_posix()
                    if not entry.is_file(follow_symlinks=False):
                        invalid_entries.append(relative)
                    else:
                        actual_files.add(relative)
    except OSError as exc:
        errors.append(f"raw directory is unavailable: {exc}")
    if invalid_entries:
        errors.append(f"raw directory contains non-regular entries: {sorted(invalid_entries)!r}")
    if actual_files != set(listed_by_path):
        errors.append(
            "raw directory is incomplete or contains unindexed artifacts: "
            f"listed={sorted(listed_by_path)!r}, actual={sorted(actual_files)!r}"
        )

    _validate_candidate_policy(campaign, cells, errors)
    recomputed_paper_eligible = bool(
        revision.get("clean") is True
        and isinstance(host, dict)
        and host.get("system") == "Linux"
        and host.get("machine") in {"x86_64", "AMD64"}
        and expected_coverage["status"] == "pass"
        and not _attribution_errors(campaign, cells)
    )
    if manifest.get("paper_eligible") != recomputed_paper_eligible:
        errors.append("paper_eligible contradicts revision/host/coverage/attribution facts")
    if require_complete and manifest.get("paper_eligible") is not True:
        errors.append("bundle is not paper-eligible")
    return list(dict.fromkeys(errors))


def write_target_indexes(
    manifest: dict[str, Any], bundle_path: Path, output_root: Path
) -> list[Path]:
    bundle_sha = _sha256_file(bundle_path)
    paths: list[Path] = []
    targets = sorted({cell["target"] for cell in manifest["cells"]})
    for target in targets:
        target_cells = [cell for cell in manifest["cells"] if cell["target"] == target]
        directory = output_root / "targets" / target
        directory.mkdir(parents=True, exist_ok=True)
        index_path = directory / "ctkat_asm_evidence.json"
        relative_bundle = Path(os.path.relpath(bundle_path, start=directory)).as_posix()
        payload = {
            "schema_version": SCHEMA_VERSION,
            "kind": INDEX_KIND,
            "target": target,
            "bundle_path": relative_bundle,
            "bundle_sha256": bundle_sha,
            "raw_bundle_path": manifest["raw_bundle"]["path"],
            "raw_bundle_sha256": manifest["raw_bundle"]["sha256"],
            "coverage": {
                "expected_cells": len(target_cells),
                "passed_cells": sum(cell["status"] == "pass" for cell in target_cells),
                "failed_cells": sum(cell["status"] != "pass" for cell in target_cells),
                "status": (
                    "pass"
                    if target_cells and all(cell["status"] == "pass" for cell in target_cells)
                    else "incomplete"
                ),
            },
            "cell_ids": [cell["cell_id"] for cell in target_cells],
        }
        index_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        paths.append(index_path)
    return paths


def load_target_index(
    index_path: Path,
    *,
    expected_target: str,
    campaign_path: Path,
    repo_root: Path,
    require_current_commit: bool = False,
    tool_identities_override: Optional[dict[str, dict[str, Any]]] = None,
    runner: Callable[..., subprocess.CompletedProcess] = run_text,
) -> dict[str, Any]:
    """Verify a small target index and return its authoritative bundle cells."""

    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load asm evidence target index: {exc}") from exc
    if not isinstance(index, dict) or index.get("kind") != INDEX_KIND:
        raise ValueError("asm evidence target index kind/schema drift")
    if index.get("schema_version") != SCHEMA_VERSION or index.get("target") != expected_target:
        raise ValueError("asm evidence target index identity drift")
    bundle_value = index.get("bundle_path")
    if not isinstance(bundle_value, str) or not bundle_value:
        raise ValueError("bundle_path must be a non-empty relative path")
    if Path(bundle_value).is_absolute():
        raise ValueError("bundle_path must be relative")
    # Indexes live at ``<bundle-root>/targets/<target>/...`` and legitimately
    # point two directories upward.  Permit that exact bundle root while still
    # rejecting traversal outside the evidence bundle.
    try:
        bundle_root = index_path.resolve().parents[2]
    except IndexError as exc:
        raise ValueError("asm evidence target index is not under a bundle root") from exc
    bundle_path = (index_path.parent / bundle_value).resolve()
    try:
        bundle_path.relative_to(bundle_root)
    except ValueError as exc:
        raise ValueError(f"bundle_path escapes evidence bundle: {bundle_value!r}") from exc
    if not bundle_path.is_file() or _sha256_file(bundle_path) != index.get("bundle_sha256"):
        raise ValueError("asm evidence bundle path/hash mismatch")
    errors = validate_bundle(
        bundle_path,
        campaign_path,
        repo_root=repo_root,
        require_current_commit=require_current_commit,
        require_complete=True,
        tool_identities_override=tool_identities_override,
        runner=runner,
    )
    if errors:
        raise ValueError("invalid asm evidence bundle: " + "; ".join(errors))
    manifest = json.loads(bundle_path.read_text(encoding="utf-8"))
    cells = [cell for cell in manifest["cells"] if cell["target"] == expected_target]
    if index.get("cell_ids") != [cell["cell_id"] for cell in cells]:
        raise ValueError("asm evidence target index cell list drift")
    expected_coverage = {
        "expected_cells": len(cells),
        "passed_cells": sum(cell["status"] == "pass" for cell in cells),
        "failed_cells": sum(cell["status"] != "pass" for cell in cells),
        "status": "pass"
        if cells and all(cell["status"] == "pass" for cell in cells)
        else "incomplete",
    }
    if index.get("coverage") != expected_coverage:
        raise ValueError("asm evidence target index coverage drift")
    if (
        index.get("raw_bundle_path") != manifest["raw_bundle"]["path"]
        or index.get("raw_bundle_sha256") != manifest["raw_bundle"]["sha256"]
    ):
        raise ValueError("asm evidence target index raw bundle provenance drift")
    return {"index": index, "manifest": manifest, "cells": cells, "bundle_path": bundle_path}
