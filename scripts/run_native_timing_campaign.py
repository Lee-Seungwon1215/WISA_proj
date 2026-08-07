#!/usr/bin/env python3
"""Plan, execute, and validate the deferred native timing-v2 corpus campaign.

This script is deliberately repository-specific.  It freezes the exact set of
legacy timing rows that need replacement, applies paper-grade measurement
overrides without editing the example configs, and writes promotion *candidates*
without mutating the curated corpus.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ctkat.cli import _do_dudect  # noqa: E402
from ctkat.config import CtkatConfig, DudectConfig, load_config  # noqa: E402
from ctkat.evidence import timing_from_raw  # noqa: E402
from ctkat.official_dudect import (  # noqa: E402
    OFFICIAL_DUDECT_BACKEND,
    OFFICIAL_DUDECT_MIN_CLASS0,
    OFFICIAL_DUDECT_PROTOCOL_TESTS,
    OFFICIAL_DUDECT_REVISION,
    OFFICIAL_DUDECT_THRESHOLD_LABEL,
    build_official_dudect_adapter,
)
from ctkat.qemu_detect import detect_qemu_emulation  # noqa: E402
from ctkat.timing_environment import collect_timing_environment  # noqa: E402

DEFAULT_MANIFEST = ROOT / "docs" / "measurement" / "native_timing_v2_campaign.yaml"
CORPUS_SUMMARY = ROOT / "docs" / "corpus" / "corpus_summary.csv"
OFFICIAL_TIMING_THRESHOLD = OFFICIAL_DUDECT_THRESHOLD_LABEL
REQUIRED_ARTIFACTS = (
    "dudect_raw_timings.csv",
    "dudect_calibration_timings.csv",
    "dudect_protocol_timings.csv",
    "dudect_summary.csv",
    "dudect_backend_report.json",
)
SUMMARY_REQUIRED_COLUMNS = {
    "project",
    "harness",
    "n0",
    "n1",
    "abs_t_score",
    "status",
    "backend",
    "timing_validity",
    "raw_n_total",
    "analysis_seed",
    "harness_protocol",
    "process_repeats",
    "aa_failures",
    "positive_power_passed",
    "protocol_test_count",
    "upstream_revision",
}
PROTOCOL_HEADER = [
    "project",
    "harness",
    "role",
    "process_index",
    "seed",
    "effect_ticks",
    "sample_id",
    "class",
    "cycles",
    "aux_start",
    "aux_end",
    "drop_reason",
    "output_length",
    "protocol",
]
UPDATE_FIELDS = [
    "target",
    "family",
    "harness",
    "timing_validity",
    "timing_signal",
    "timing_backend",
    "timing_raw_status",
    "timing_abs_t",
    "timing_measurements",
    "timing_leak_target",
    "timing_seed",
    "timing_threshold",
    "report",
    "report_sha256",
    "promotion_ready",
    "blockers",
]


class CampaignError(RuntimeError):
    """A static, host, execution, or artifact-contract failure."""


@dataclass(frozen=True)
class ProtocolSpec:
    backend: str
    clock: str
    seed: int
    warmup: int
    batches: int
    process_repeats: int
    pool_size: int
    aa_abs_t_limit: float
    positive_abs_t_threshold: float
    aa_max_failures: int
    target_power: float
    power_alpha: float
    compiler: str
    compile_timeout: int
    backend_timeout: int


@dataclass(frozen=True)
class TargetSpec:
    id: str
    family: str
    config: Path
    harnesses: tuple[str, ...]
    axes: tuple[tuple[str, str], ...]
    target_measurements: int
    control_measurements: int
    positive_control_effects: tuple[int, ...]
    timeout: int

    def axis_for(self, harness: str) -> str:
        for name, axis in self.axes:
            if name == harness:
                return axis
        raise CampaignError(f"{self.id}: no frozen timing axis for harness {harness!r}")


@dataclass(frozen=True)
class CampaignSpec:
    schema_version: str
    campaign_id: str
    description: str
    coverage_mode: str
    host: dict[str, Any]
    protocol: ProtocolSpec
    targets: tuple[TargetSpec, ...]
    manifest_path: Path
    manifest_sha256: str


@dataclass
class TargetValidation:
    target: TargetSpec
    report_dir: Path
    complete: bool = False
    promotion_ready: bool = False
    errors: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    harnesses: list[dict[str, Any]] = field(default_factory=list)
    artifact_sha256: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "target": self.target.id,
            "family": self.target.family,
            "report_dir": f"{self.target.id}/reports",
            "complete": self.complete,
            "promotion_ready": self.promotion_ready,
            "errors": self.errors,
            "blockers": self.blockers,
            "harnesses": self.harnesses,
            "artifact_sha256": self.artifact_sha256,
        }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path.resolve())


def _require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CampaignError(f"{label} must be a mapping")
    return value


def _require_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise CampaignError(f"{label} must be a list")
    return value


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise CampaignError(f"{label} must be a positive integer")
    return value


def _nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CampaignError(f"{label} must be a non-negative integer")
    return value


def _positive_float(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or float(value) <= 0:
        raise CampaignError(f"{label} must be a positive number")
    result = float(value)
    if result == float("inf") or result != result:
        raise CampaignError(f"{label} must be finite")
    return result


def _forbid_unknown(data: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise CampaignError(f"{label} contains unknown keys: {unknown}")


def _repo_path(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise CampaignError(f"{label} must be a non-empty repository-relative path")
    candidate = (ROOT / value).resolve()
    try:
        candidate.relative_to(ROOT)
    except ValueError as exc:
        raise CampaignError(f"{label} escapes the repository: {value!r}") from exc
    return candidate


def load_campaign(path: Path = DEFAULT_MANIFEST) -> CampaignSpec:
    manifest_path = path.resolve()
    try:
        raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise CampaignError(f"campaign manifest unreadable: {manifest_path}: {exc}") from exc
    root = _require_mapping(raw, "campaign manifest")
    _forbid_unknown(
        root,
        {
            "schema_version",
            "campaign_id",
            "description",
            "coverage_mode",
            "host",
            "protocol",
            "targets",
        },
        "campaign manifest",
    )
    if root.get("schema_version") != "1.0":
        raise CampaignError("campaign schema_version must be '1.0'")
    campaign_id = root.get("campaign_id")
    if not isinstance(campaign_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]+", campaign_id):
        raise CampaignError("campaign_id must match [a-z0-9][a-z0-9._-]+")
    coverage_mode = root.get("coverage_mode")
    if coverage_mode not in {"committed-timing-rows", "manifest-only"}:
        raise CampaignError("coverage_mode must be committed-timing-rows or manifest-only")

    host = _require_mapping(root.get("host"), "host")
    _forbid_unknown(
        host,
        {
            "system",
            "machines",
            "require_single_cpu_affinity",
            "reject_emulation",
            "reject_virtualization",
            "recommended_governor",
        },
        "host",
    )
    protocol_raw = _require_mapping(root.get("protocol"), "protocol")
    _forbid_unknown(
        protocol_raw,
        {
            "backend",
            "clock",
            "seed",
            "warmup",
            "batches",
            "process_repeats",
            "pool_size",
            "aa_abs_t_limit",
            "positive_abs_t_threshold",
            "aa_max_failures",
            "target_power",
            "power_alpha",
            "compiler",
            "compile_timeout",
            "backend_timeout",
        },
        "protocol",
    )
    protocol = ProtocolSpec(
        backend=str(protocol_raw.get("backend", "")),
        clock=str(protocol_raw.get("clock", "")),
        seed=_positive_int(protocol_raw.get("seed"), "protocol.seed"),
        warmup=_nonnegative_int(protocol_raw.get("warmup"), "protocol.warmup"),
        batches=_positive_int(protocol_raw.get("batches"), "protocol.batches"),
        process_repeats=_positive_int(
            protocol_raw.get("process_repeats"), "protocol.process_repeats"
        ),
        pool_size=_positive_int(protocol_raw.get("pool_size"), "protocol.pool_size"),
        aa_abs_t_limit=_positive_float(
            protocol_raw.get("aa_abs_t_limit"), "protocol.aa_abs_t_limit"
        ),
        positive_abs_t_threshold=_positive_float(
            protocol_raw.get("positive_abs_t_threshold"),
            "protocol.positive_abs_t_threshold",
        ),
        aa_max_failures=_nonnegative_int(
            protocol_raw.get("aa_max_failures"), "protocol.aa_max_failures"
        ),
        target_power=_positive_float(protocol_raw.get("target_power"), "protocol.target_power"),
        power_alpha=_positive_float(protocol_raw.get("power_alpha"), "protocol.power_alpha"),
        compiler=str(protocol_raw.get("compiler", "")),
        compile_timeout=_positive_int(
            protocol_raw.get("compile_timeout"), "protocol.compile_timeout"
        ),
        backend_timeout=_positive_int(
            protocol_raw.get("backend_timeout"), "protocol.backend_timeout"
        ),
    )

    targets: list[TargetSpec] = []
    for index, item in enumerate(_require_list(root.get("targets"), "targets")):
        data = _require_mapping(item, f"targets[{index}]")
        _forbid_unknown(
            data,
            {
                "id",
                "family",
                "config",
                "harnesses",
                "axes",
                "target_measurements",
                "control_measurements",
                "positive_control_effects",
                "timeout",
            },
            f"targets[{index}]",
        )
        target_id = data.get("id")
        if not isinstance(target_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]+", target_id):
            raise CampaignError(f"targets[{index}].id is invalid")
        family = data.get("family")
        if not isinstance(family, str) or not family:
            raise CampaignError(f"targets[{index}].family must be non-empty")
        harnesses_raw = _require_list(data.get("harnesses"), f"targets[{index}].harnesses")
        if not harnesses_raw or any(
            not isinstance(name, str) or not name for name in harnesses_raw
        ):
            raise CampaignError(f"targets[{index}].harnesses must contain names")
        axes_raw = _require_mapping(data.get("axes"), f"targets[{index}].axes")
        if set(axes_raw) != set(harnesses_raw):
            raise CampaignError(f"targets[{index}].axes keys must exactly match harnesses")
        if any(
            not isinstance(axis, str) or axis not in {"sk", "ct", "fo", "msg"}
            for axis in axes_raw.values()
        ):
            raise CampaignError(f"targets[{index}].axes values must be one of sk/ct/fo/msg")
        effects_raw = _require_list(
            data.get("positive_control_effects"),
            f"targets[{index}].positive_control_effects",
        )
        effects = tuple(
            _positive_int(value, f"targets[{index}].positive_control_effects")
            for value in effects_raw
        )
        targets.append(
            TargetSpec(
                id=target_id,
                family=family,
                config=_repo_path(data.get("config"), f"targets[{index}].config"),
                harnesses=tuple(harnesses_raw),
                axes=tuple((name, axes_raw[name]) for name in harnesses_raw),
                target_measurements=_positive_int(
                    data.get("target_measurements"),
                    f"targets[{index}].target_measurements",
                ),
                control_measurements=_positive_int(
                    data.get("control_measurements"),
                    f"targets[{index}].control_measurements",
                ),
                positive_control_effects=effects,
                timeout=_positive_int(data.get("timeout"), f"targets[{index}].timeout"),
            )
        )

    return CampaignSpec(
        schema_version="1.0",
        campaign_id=campaign_id,
        description=str(root.get("description", "")),
        coverage_mode=str(coverage_mode),
        host=dict(host),
        protocol=protocol,
        targets=tuple(targets),
        manifest_path=manifest_path,
        manifest_sha256=_sha256(manifest_path),
    )


def _corpus_timing_pairs() -> set[tuple[str, str]]:
    return {(target, harness) for target, harness, _axis in _corpus_timing_axes()}


def _corpus_timing_axes() -> set[tuple[str, str, str]]:
    with CORPUS_SUMMARY.open(newline="", encoding="utf-8") as handle:
        return {
            (row["target"], row["harness"], row["timing_leak_target"])
            for row in csv.DictReader(handle)
            if row.get("timing_raw_status")
        }


def _resolve_from_config(config_path: Path, value: Path) -> Path:
    return value if value.is_absolute() else (config_path.parent / value).resolve()


def static_check(campaign: CampaignSpec) -> list[str]:
    errors: list[str] = []
    protocol = campaign.protocol
    for flag in (
        "require_single_cpu_affinity",
        "reject_emulation",
        "reject_virtualization",
    ):
        if not isinstance(campaign.host.get(flag), bool):
            errors.append(f"host.{flag} must be a boolean")
        elif campaign.host[flag] is not True:
            errors.append(f"host.{flag} must be true for the corpus campaign")
    if campaign.host.get("system") != "Linux":
        errors.append("host.system must be Linux")
    machines = campaign.host.get("machines")
    if not isinstance(machines, list) or {str(machine).lower() for machine in machines} != {
        "x86_64",
        "amd64",
    }:
        errors.append("host.machines must contain x86_64 and AMD64")
    if campaign.host.get("recommended_governor") != "performance":
        errors.append("host.recommended_governor must be performance")
    if protocol.backend != "official-dudect":
        errors.append("protocol.backend must be official-dudect")
    if protocol.compiler != "gcc":
        errors.append("protocol.compiler must be gcc")
    if protocol.clock != "rdtsc":
        errors.append("native corpus campaign must use clock=rdtsc for AUX migration checks")
    if not 0 < protocol.seed <= 0xFFFFFFFFFFFFFFFF:
        errors.append("protocol.seed must fit nonzero uint64")
    if protocol.warmup < 1_000:
        errors.append("protocol.warmup must be at least 1000")
    if protocol.batches < 10:
        errors.append("protocol.batches must be at least 10")
    if protocol.process_repeats < 3:
        errors.append("protocol.process_repeats must be at least 3")
    if protocol.pool_size < 2:
        errors.append("protocol.pool_size must be at least 2")
    if protocol.aa_max_failures < 0 or protocol.aa_max_failures >= protocol.process_repeats:
        errors.append("protocol.aa_max_failures must be in [0, process_repeats)")
    if not 0.5 < protocol.target_power < 1:
        errors.append("protocol.target_power must be between 0.5 and 1")
    if not 0 < protocol.power_alpha < 0.5:
        errors.append("protocol.power_alpha must be between 0 and 0.5")
    if protocol.positive_abs_t_threshold <= protocol.aa_abs_t_limit:
        errors.append("positive_abs_t_threshold must exceed aa_abs_t_limit")
    if not campaign.targets:
        errors.append("campaign must contain at least one target")

    ids: set[str] = set()
    manifest_axes: set[tuple[str, str, str]] = set()
    for target in campaign.targets:
        if target.id in ids:
            errors.append(f"duplicate target id: {target.id}")
        ids.add(target.id)
        if len(set(target.harnesses)) != len(target.harnesses):
            errors.append(f"{target.id}: duplicate harness name")
        effects = target.positive_control_effects
        if len(effects) != 3 or tuple(sorted(set(effects))) != effects:
            errors.append(
                f"{target.id}: positive_control_effects must be three unique increasing values"
            )
        minimum_total = 2 * OFFICIAL_DUDECT_MIN_CLASS0 + 1_000
        if target.target_measurements < minimum_total:
            errors.append(
                f"{target.id}: target_measurements={target.target_measurements} lacks "
                f"margin above official class-0 minimum; require >= {minimum_total}"
            )
        if target.control_measurements < 1_000:
            errors.append(f"{target.id}: control_measurements must be >= 1000")
        if target.control_measurements > target.target_measurements:
            errors.append(f"{target.id}: control_measurements cannot exceed target_measurements")
        if not target.config.is_file():
            errors.append(f"{target.id}: config missing: {target.config.relative_to(ROOT)}")
            continue
        try:
            cfg = load_config(target.config)
        except Exception as exc:
            errors.append(f"{target.id}: config does not load: {exc}")
            continue
        if cfg.project.name != target.id:
            errors.append(
                f"{target.id}: config project.name={cfg.project.name!r} does not match id"
            )
        dudect = cfg.dudect
        if dudect is None or not dudect.enabled:
            errors.append(f"{target.id}: dudect must be enabled")
            continue
        if dudect.backend != "official-dudect":
            errors.append(f"{target.id}: config backend must be official-dudect")
        if dudect.compiler.cc != protocol.compiler:
            errors.append(
                f"{target.id}: compiler drift: manifest={protocol.compiler!r}, "
                f"config={dudect.compiler.cc!r}"
            )
        required_cflags = {"-O2", "-fno-lto", "-fno-omit-frame-pointer"}
        actual_cflags = set(dudect.compiler.cflags)
        if not required_cflags <= actual_cflags:
            errors.append(
                f"{target.id}: timing compiler cflags must include {sorted(required_cflags)}"
            )
        if any(
            flag == "-fomit-frame-pointer" or (flag.startswith("-flto") and flag != "-fno-lto")
            for flag in dudect.compiler.cflags
        ):
            errors.append(f"{target.id}: timing compiler cflags re-enable LTO/frame omission")
        optimization_flags = [
            flag for flag in dudect.compiler.cflags if re.fullmatch(r"-O\S*", flag)
        ]
        if optimization_flags != ["-O2"]:
            errors.append(
                f"{target.id}: timing compiler must have exactly one -O2 "
                f"optimization flag, got {optimization_flags}"
            )
        configured = tuple(harness.name for harness in dudect.harnesses)
        if configured != target.harnesses:
            errors.append(
                f"{target.id}: harness order/set drift: manifest={target.harnesses}, "
                f"config={configured}"
            )
        for harness in dudect.harnesses:
            configured_axis = (
                harness.leak_target
                if harness.template == "kem"
                else harness.sign_leak_target
                if harness.template == "sign"
                else ""
            )
            frozen_axis = target.axis_for(harness.name)
            manifest_axes.add((target.id, harness.name, frozen_axis))
            if harness.template not in {"kem", "sign"}:
                errors.append(f"{target.id}/{harness.name}: campaign supports only KEM/sign v2")
            if configured_axis != frozen_axis:
                errors.append(
                    f"{target.id}/{harness.name}: timing axis drift: "
                    f"manifest={frozen_axis!r}, config={configured_axis!r}"
                )
            if any(Path(source).name == "randombytes.c" for source in harness.sources):
                errors.append(
                    f"{target.id}/{harness.name}: strong randombytes.c would shadow "
                    "the seeded interpose"
                )
            for source in harness.sources:
                resolved = _resolve_from_config(target.config, source)
                if not resolved.is_file():
                    errors.append(
                        f"{target.id}/{harness.name}: source missing: {resolved.relative_to(ROOT)}"
                    )
            include_dirs = [
                _resolve_from_config(target.config, include_dir)
                for include_dir in harness.include_dirs
            ]
            for include_dir in include_dirs:
                if not include_dir.is_dir():
                    errors.append(
                        f"{target.id}/{harness.name}: include dir missing: "
                        f"{include_dir.relative_to(ROOT)}"
                    )
            if (
                harness.header
                and include_dirs
                and not any(
                    (include_dir / harness.header).is_file() for include_dir in include_dirs
                )
            ):
                errors.append(
                    f"{target.id}/{harness.name}: header {harness.header!r} not found "
                    "under configured include dirs"
                )

    if campaign.coverage_mode == "committed-timing-rows":
        corpus_axes = _corpus_timing_axes()
        if manifest_axes != corpus_axes:
            missing = sorted(corpus_axes - manifest_axes)
            extra = sorted(manifest_axes - corpus_axes)
            errors.append(
                f"campaign/corpus timing-axis drift: missing={missing or 'none'}, "
                f"extra={extra or 'none'}"
            )
    return errors


def _command_version(command: str) -> str:
    executable = shutil.which(command)
    if executable is None:
        return ""
    try:
        result = subprocess.run(
            [executable, "--version"],
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.splitlines()[0].strip() if result.stdout else ""


def _detect_virtualization() -> dict[str, str]:
    result = {"vm": "", "container": ""}
    detector = shutil.which("systemd-detect-virt")
    if detector:
        for kind, option in (("vm", "--vm"), ("container", "--container")):
            try:
                proc = subprocess.run(
                    [detector, option],
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=10,
                )
            except (OSError, subprocess.SubprocessError):
                continue
            value = proc.stdout.strip()
            if proc.returncode == 0 and value and value != "none":
                result[kind] = value
    if result["vm"]:
        return result
    dmi = " ".join(
        _read_text(path)
        for path in (
            Path("/sys/class/dmi/id/sys_vendor"),
            Path("/sys/class/dmi/id/product_name"),
            Path("/sys/class/dmi/id/board_vendor"),
        )
    ).lower()
    markers = {
        "amazon": "amazon-ec2",
        "google compute": "gce",
        "microsoft corporation": "microsoft-hyperv",
        "vmware": "vmware",
        "virtualbox": "virtualbox",
        "openstack": "openstack",
        "kvm": "kvm",
        "qemu": "qemu",
    }
    for needle, label in markers.items():
        if needle in dmi:
            result["vm"] = label
            break
    return result


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def _git_state() -> tuple[str, bool]:
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
            timeout=10,
        ).stdout.strip()
        dirty = bool(
            subprocess.run(
                ["git", "status", "--porcelain", "--untracked-files=normal"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=True,
                timeout=10,
            ).stdout.strip()
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CampaignError(f"cannot resolve git provenance: {exc}") from exc
    return commit, dirty


def pin_current_process(cpu: int) -> None:
    if platform.system() != "Linux" or not hasattr(os, "sched_setaffinity"):
        raise CampaignError("--cpu requires Linux sched_setaffinity")
    available = set(os.sched_getaffinity(0))
    if cpu not in available:
        raise CampaignError(f"--cpu {cpu} is not in current affinity {sorted(available)}")
    try:
        os.sched_setaffinity(0, {cpu})
    except OSError as exc:
        raise CampaignError(f"could not pin campaign to CPU {cpu}: {exc}") from exc


def preflight(
    campaign: CampaignSpec,
    *,
    allow_dirty: bool,
    allow_virtualized: bool,
    build_adapter: bool,
) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    emulated = detect_qemu_emulation()
    environment = collect_timing_environment(emulated=emulated, clock=campaign.protocol.clock)
    system = platform.system()
    machine = platform.machine()
    accepted_machines = {str(value).lower() for value in campaign.host.get("machines", [])}
    if system != campaign.host.get("system"):
        errors.append(f"requires {campaign.host.get('system')}, got {system}")
    if machine.lower() not in accepted_machines:
        errors.append(f"requires x86_64 machine, got {machine or 'unknown'}")
    if emulated and campaign.host.get("reject_emulation", True):
        errors.append("cross-architecture emulation detected")
    affinity = environment.get("cpu_affinity") or []
    if campaign.host.get("require_single_cpu_affinity", True) and len(affinity) != 1:
        errors.append(f"requires exactly one eligible CPU, got {affinity or 'unavailable'}")

    virtualization = _detect_virtualization()
    virtualized = bool(virtualization["vm"] or virtualization["container"])
    if virtualized and campaign.host.get("reject_virtualization", True):
        message = (
            f"virtualized host detected: vm={virtualization['vm'] or 'none'}, "
            f"container={virtualization['container'] or 'none'}"
        )
        if allow_virtualized:
            warnings.append(message + " (engineering-only override)")
        else:
            errors.append(message)

    commit, dirty = _git_state()
    if dirty:
        message = "git worktree has tracked or untracked changes"
        if allow_dirty:
            warnings.append(message + " (engineering-only override)")
        else:
            errors.append(message)

    compiler = _command_version("gcc")
    if not compiler:
        errors.append("gcc is unavailable")
    selected_cpu = affinity[0] if len(affinity) == 1 else None
    governor = ""
    if selected_cpu is not None:
        governor = _read_text(
            Path(f"/sys/devices/system/cpu/cpu{selected_cpu}/cpufreq/scaling_governor")
        )
    recommended = str(campaign.host.get("recommended_governor", ""))
    if governor and recommended and governor != recommended:
        warnings.append(f"CPU {selected_cpu} governor is {governor!r}, recommended {recommended!r}")
    if not governor:
        warnings.append("CPU governor metadata unavailable")

    adapter_ok = False
    if build_adapter and not any(
        reason.startswith(("requires ", "cross-architecture", "gcc is")) for reason in errors
    ):
        try:
            with tempfile.TemporaryDirectory(prefix="ctkat-native-preflight-") as temp_dir:
                build_official_dudect_adapter(
                    cc="gcc",
                    output_dir=Path(temp_dir),
                    timeout=120,
                )
            adapter_ok = True
        except Exception as exc:
            errors.append(f"official dudect adapter preflight failed: {exc}")

    paper_eligible = not errors and not emulated and not virtualized and not dirty
    return {
        "checked_at": _utc_now(),
        "ok": not errors,
        "paper_eligible": paper_eligible,
        "errors": errors,
        "warnings": warnings,
        "git_commit": commit,
        "git_dirty": dirty,
        "compiler": compiler or None,
        "official_adapter_built": adapter_ok,
        "virtualization": virtualization,
        "environment": environment,
        "governor_selected_cpu": governor or None,
    }


def validate_preflight_report(
    campaign: CampaignSpec,
    report: Any,
    *,
    expected_commit: str,
) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if not isinstance(report, dict):
        return False, ["host_preflight must be an object"]
    if report.get("ok") is not True or report.get("errors") != []:
        errors.append("host preflight was not a successful executable-host check")
    if report.get("git_commit") != expected_commit:
        errors.append("host preflight git commit differs from campaign report")
    dirty = report.get("git_dirty")
    if not isinstance(dirty, bool):
        errors.append("host preflight git_dirty must be boolean")
        dirty = True
    if not isinstance(report.get("compiler"), str) or not report.get("compiler"):
        errors.append("host preflight compiler identity is missing")
    if report.get("official_adapter_built") is not True:
        errors.append("host preflight did not build the official adapter")

    virtualization = report.get("virtualization")
    if not isinstance(virtualization, dict) or any(
        not isinstance(virtualization.get(field), str) for field in ("vm", "container")
    ):
        errors.append("host preflight virtualization metadata is malformed")
        virtualized = True
    else:
        virtualized = bool(virtualization["vm"] or virtualization["container"])

    environment = report.get("environment")
    if not isinstance(environment, dict):
        errors.append("host preflight environment metadata is malformed")
    else:
        accepted_machines = {str(value).lower() for value in campaign.host.get("machines", [])}
        if environment.get("system") != campaign.host.get("system"):
            errors.append("host preflight environment is not Linux")
        if str(environment.get("machine", "")).lower() not in accepted_machines:
            errors.append("host preflight environment is not x86_64")
        if environment.get("clock") != campaign.protocol.clock:
            errors.append("host preflight clock differs from the campaign")
        if environment.get("emulated") is not False:
            errors.append("host preflight reports emulation")
        affinity = environment.get("cpu_affinity")
        if (
            not isinstance(affinity, list)
            or len(affinity) != 1
            or isinstance(affinity[0], bool)
            or not isinstance(affinity[0], int)
            or affinity[0] < 0
        ):
            errors.append("host preflight does not record one pinned logical CPU")
        if environment.get("rejected") is not False:
            errors.append("host timing environment was rejected")

    warnings = report.get("warnings")
    if not isinstance(warnings, list) or any(not isinstance(value, str) for value in warnings):
        errors.append("host preflight warnings must be a string list")
        warnings = []
    if dirty and not any("git worktree" in warning for warning in warnings):
        errors.append("dirty-host override is not recorded in warnings")
    if virtualized and not any("engineering-only override" in warning for warning in warnings):
        errors.append("virtualized-host override is not recorded in warnings")

    recomputed_eligible = not errors and not dirty and not virtualized
    if report.get("paper_eligible") is not recomputed_eligible:
        errors.append("host preflight paper_eligible does not match recorded host facts")
        recomputed_eligible = False
    return recomputed_eligible, errors


def campaign_dudect(
    cfg: CtkatConfig,
    campaign: CampaignSpec,
    target: TargetSpec,
    generated_dir: Path,
) -> DudectConfig:
    if cfg.dudect is None:
        raise CampaignError(f"{target.id}: dudect config missing")
    protocol = cfg.dudect.timing_protocol.model_copy(
        update={
            "process_repeats": campaign.protocol.process_repeats,
            "pool_size": campaign.protocol.pool_size,
            "control_measurements": target.control_measurements,
            "positive_control_effects": list(target.positive_control_effects),
            "aa_abs_t_limit": campaign.protocol.aa_abs_t_limit,
            "positive_abs_t_threshold": campaign.protocol.positive_abs_t_threshold,
            "aa_max_failures": campaign.protocol.aa_max_failures,
            "target_power": campaign.protocol.target_power,
            "power_alpha": campaign.protocol.power_alpha,
        }
    )
    compiler = cfg.dudect.compiler.model_copy(update={"cc": campaign.protocol.compiler})
    return cfg.dudect.model_copy(
        update={
            "backend": campaign.protocol.backend,
            "clock": campaign.protocol.clock,
            "seed": campaign.protocol.seed,
            "measurements": target.target_measurements,
            "warmup": campaign.protocol.warmup,
            "batches": campaign.protocol.batches,
            "timeout": target.timeout,
            "compile_timeout": campaign.protocol.compile_timeout,
            "backend_timeout": campaign.protocol.backend_timeout,
            "compiler": compiler,
            "generated_dir": generated_dir.resolve(),
            "timing_protocol": protocol,
        }
    )


def _expected_protocol_counts(
    campaign: CampaignSpec,
    target: TargetSpec,
) -> dict[tuple[str, str, int, int], int]:
    counts: dict[tuple[str, str, int, int], int] = {}
    for harness in target.harnesses:
        for process_index in range(campaign.protocol.process_repeats):
            counts[(harness, "target-calibration", process_index, 0)] = target.target_measurements
            counts[(harness, "target", process_index, 0)] = target.target_measurements
            counts[(harness, "aa", process_index, 0)] = target.control_measurements
            counts[(harness, "setup-placebo", process_index, 0)] = target.control_measurements
            for effect in target.positive_control_effects:
                counts[(harness, "positive", process_index, effect)] = target.control_measurements
    return counts


def _validate_protocol_csv(
    path: Path,
    campaign: CampaignSpec,
    target: TargetSpec,
) -> list[str]:
    errors: list[str] = []
    reported: set[str] = set()
    actual: dict[tuple[str, str, int, int], int] = {}
    seeds: dict[tuple[str, str, int, int], int] = {}

    def report_once(category: str, message: str) -> None:
        if category not in reported:
            errors.append(message)
            reported.add(category)

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != PROTOCOL_HEADER:
            return [
                f"{path.name}: header drift: expected={PROTOCOL_HEADER}, actual={reader.fieldnames}"
            ]
        for number, row in enumerate(reader, start=2):
            try:
                process_index = int(row["process_index"])
                effect = int(row["effect_ticks"])
                seed = int(row["seed"])
                sample_id = int(row["sample_id"])
                clazz = int(row["class"])
                cycles = float(row["cycles"])
                aux_start = int(row["aux_start"])
                aux_end = int(row["aux_end"])
                output_length = int(row["output_length"])
            except (TypeError, ValueError):
                report_once(
                    "numeric",
                    f"{path.name}:{number}: invalid numeric protocol field",
                )
                continue
            if row["project"] != target.id:
                report_once(
                    "project",
                    f"{path.name}:{number}: project={row['project']!r}, expected={target.id!r}",
                )
            if row["protocol"] != "timing-harness-v2":
                report_once(
                    "protocol",
                    f"{path.name}:{number}: protocol is not timing-harness-v2",
                )
            key = (row["harness"], row["role"], process_index, effect)
            expected_sample_id = actual.get(key, 0)
            if sample_id != expected_sample_id:
                report_once(
                    "sample-id",
                    f"{path.name}:{number}: non-contiguous sample_id={sample_id} "
                    f"for {key}, expected={expected_sample_id}",
                )
            if clazz not in {0, 1}:
                report_once(
                    "class",
                    f"{path.name}:{number}: class must be 0 or 1",
                )
            if not 0 < seed <= 0xFFFFFFFFFFFFFFFF:
                report_once(
                    "seed-range",
                    f"{path.name}:{number}: seed must be a nonzero uint64",
                )
            previous_seed = seeds.setdefault(key, seed)
            if previous_seed != seed:
                report_once(
                    "seed-stability",
                    f"{path.name}:{number}: seed changed within trace {key}",
                )
            if (
                not math.isfinite(cycles)
                or cycles < 0
                or min(aux_start, aux_end, output_length) < 0
            ):
                report_once(
                    "numeric-range",
                    f"{path.name}:{number}: negative/non-finite trace value",
                )
            drop_reason = row["drop_reason"]
            if drop_reason not in {"", "clock-anomaly", "cpu-migration"}:
                report_once(
                    "drop-reason",
                    f"{path.name}:{number}: invalid drop_reason={drop_reason!r}",
                )
            if not drop_reason and (cycles == 0 or aux_start != aux_end):
                report_once(
                    "unmarked-drop",
                    f"{path.name}:{number}: retained row contains a clock/AUX anomaly",
                )
            if drop_reason == "cpu-migration" and aux_start == aux_end:
                report_once(
                    "migration",
                    f"{path.name}:{number}: cpu-migration row has unchanged AUX",
                )
            actual[key] = actual.get(key, 0) + 1
    expected = _expected_protocol_counts(campaign, target)
    for harness in target.harnesses:
        harness_seeds = [seed for key, seed in seeds.items() if key[0] == harness]
        if len(set(harness_seeds)) != len(harness_seeds):
            errors.append(
                f"{path.name}: {harness} trace seeds are not domain-separated "
                "across roles/repeats/effects"
            )
    if actual != expected:
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        wrong = sorted(
            (key, expected[key], actual[key])
            for key in set(expected).intersection(actual)
            if expected[key] != actual[key]
        )
        errors.append(
            f"{path.name}: trace count drift: missing={missing or 'none'}, "
            f"extra={extra or 'none'}, wrong={wrong or 'none'}"
        )
    return errors


def _load_summary(path: Path) -> tuple[dict[str, dict[str, str]], list[str]]:
    errors: list[str] = []
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fields = set(reader.fieldnames or [])
        missing = SUMMARY_REQUIRED_COLUMNS - fields
        if missing:
            errors.append(f"{path.name}: missing columns {sorted(missing)}")
        rows = list(reader)
    by_harness: dict[str, dict[str, str]] = {}
    for row in rows:
        harness = row.get("harness", "")
        if not harness or harness in by_harness:
            errors.append(f"{path.name}: empty/duplicate harness {harness!r}")
            continue
        by_harness[harness] = row
    return by_harness, errors


def validate_target_artifacts(
    campaign: CampaignSpec,
    target: TargetSpec,
    report_dir: Path,
    *,
    host_paper_eligible: bool,
) -> TargetValidation:
    result = TargetValidation(target=target, report_dir=report_dir)
    cfg = load_config(target.config)
    if cfg.dudect is None:
        result.errors.append(f"{target.id}: dudect config missing")
        return result
    configured_harnesses = {harness.name: harness for harness in cfg.dudect.harnesses}
    for name in REQUIRED_ARTIFACTS:
        path = report_dir / name
        if not path.is_file():
            result.errors.append(f"missing artifact: {path}")
        else:
            result.artifact_sha256[name] = _sha256(path)
    if result.errors:
        return result

    backend_path = report_dir / "dudect_backend_report.json"
    try:
        backend = json.loads(backend_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        result.errors.append(f"backend report unreadable: {exc}")
        return result
    if not isinstance(backend, dict):
        result.errors.append("backend report root must be an object")
        return result
    if backend.get("schema_version") != "2.0":
        result.errors.append("backend report schema_version must be 2.0")
    if backend.get("kind") != "timing-backend-report":
        result.errors.append("backend report kind must be timing-backend-report")
    if backend.get("project") != target.id:
        result.errors.append(
            f"backend report project={backend.get('project')!r}, expected={target.id!r}"
        )
    if backend.get("official_dudect_revision") != OFFICIAL_DUDECT_REVISION:
        result.errors.append("official dudect revision drift")
    hash_fields = {
        "raw_trace_sha256": "dudect_raw_timings.csv",
        "calibration_trace_sha256": "dudect_calibration_timings.csv",
        "protocol_trace_sha256": "dudect_protocol_timings.csv",
    }
    for field_name, artifact_name in hash_fields.items():
        if backend.get(field_name) != result.artifact_sha256[artifact_name]:
            result.errors.append(f"{field_name} does not match {artifact_name}")

    summary, summary_errors = _load_summary(report_dir / "dudect_summary.csv")
    result.errors.extend(summary_errors)
    backend_harnesses: dict[str, dict[str, Any]] = {}
    backend_items = backend.get("harnesses")
    if not isinstance(backend_items, list):
        result.errors.append("backend report harnesses must be a list")
        backend_items = []
    for item in backend_items:
        if not isinstance(item, dict):
            result.errors.append("backend report contains a non-object harness")
            continue
        name = str(item.get("harness", ""))
        if not name or name in backend_harnesses:
            result.errors.append(f"backend report contains empty/duplicate harness {name!r}")
            continue
        backend_harnesses[name] = item
    expected_harnesses = set(target.harnesses)
    if set(summary) != expected_harnesses:
        result.errors.append(
            f"summary harness drift: expected={sorted(expected_harnesses)}, "
            f"actual={sorted(summary)}"
        )
    if set(backend_harnesses) != expected_harnesses:
        result.errors.append(
            f"backend harness drift: expected={sorted(expected_harnesses)}, "
            f"actual={sorted(backend_harnesses)}"
        )

    result.errors.extend(
        _validate_protocol_csv(
            report_dir / "dudect_protocol_timings.csv",
            campaign,
            target,
        )
    )

    for harness_name in target.harnesses:
        row = summary.get(harness_name)
        item = backend_harnesses.get(harness_name)
        if row is None or item is None:
            continue
        protocol = item.get("harness_protocol") or {}
        harness_errors: list[str] = []
        if not isinstance(protocol, dict):
            result.errors.append(f"{harness_name}: harness_protocol must be an object")
            continue
        if row.get("project") != target.id:
            harness_errors.append(f"summary project={row.get('project')!r}, expected={target.id!r}")
        configured_harness = configured_harnesses.get(harness_name)
        if configured_harness is None:
            harness_errors.append("harness is absent from the target config")
            continue
        if item.get("backend") != OFFICIAL_DUDECT_BACKEND:
            harness_errors.append(f"backend={item.get('backend')!r}")
        if item.get("upstream_revision") != OFFICIAL_DUDECT_REVISION:
            harness_errors.append("backend harness upstream revision drift")
        if row.get("upstream_revision") != OFFICIAL_DUDECT_REVISION:
            harness_errors.append("summary upstream revision drift")
        tests = item.get("tests")
        if (
            not isinstance(tests, list)
            or len(tests) != OFFICIAL_DUDECT_PROTOCOL_TESTS
            or any(not isinstance(test, dict) for test in tests)
            or [test.get("index") for test in tests] != list(range(OFFICIAL_DUDECT_PROTOCOL_TESTS))
        ):
            harness_errors.append(
                f"backend must preserve all {OFFICIAL_DUDECT_PROTOCOL_TESTS} ordered official tests"
            )
        if item.get("protocol_test_count") != OFFICIAL_DUDECT_PROTOCOL_TESTS:
            harness_errors.append("backend official protocol test count mismatch")
        try:
            summary_protocol_tests = int(row.get("protocol_test_count", ""))
        except (TypeError, ValueError):
            summary_protocol_tests = -1
        if summary_protocol_tests != OFFICIAL_DUDECT_PROTOCOL_TESTS:
            harness_errors.append("summary official protocol test count mismatch")
        if protocol.get("protocol") != "timing-harness-v2":
            harness_errors.append("protocol manifest missing")
        expected_axis = target.axis_for(harness_name)
        if protocol.get("axis") != expected_axis:
            harness_errors.append(
                f"harness_protocol.axis={protocol.get('axis')!r}, expected={expected_axis!r}"
            )
        expected_protocol = {
            "schema_version": "1.0",
            "template": configured_harness.template,
            "common_work_buffer": True,
            "symmetric_setup": True,
            "timed_region_target_only": True,
            "rdtscp_aux_migration_filter": True,
            "pool_size": campaign.protocol.pool_size,
            "target_measurements": target.target_measurements,
            "control_measurements": target.control_measurements,
            "process_repeats_required": 3,
            "process_repeats_observed": campaign.protocol.process_repeats,
            "aa_abs_t_limit": campaign.protocol.aa_abs_t_limit,
            "aa_max_failures": campaign.protocol.aa_max_failures,
            "positive_abs_t_threshold": campaign.protocol.positive_abs_t_threshold,
            "target_power": campaign.protocol.target_power,
            "power_alpha": campaign.protocol.power_alpha,
        }
        for key, expected in expected_protocol.items():
            if protocol.get(key) != expected:
                harness_errors.append(
                    f"harness_protocol.{key}={protocol.get(key)!r}, expected={expected!r}"
                )
        curve = protocol.get("positive_power_curve")
        if not isinstance(curve, list) or any(not isinstance(item, dict) for item in curve):
            harness_errors.append("positive_power_curve must be a list of objects")
            curve = []
        observed_effects = [item.get("effect_ticks") for item in curve]
        if observed_effects != list(target.positive_control_effects):
            harness_errors.append(
                f"positive effect curve={observed_effects}, "
                f"expected={list(target.positive_control_effects)}"
            )
        expected_list_lengths = {
            "target_repeats": campaign.protocol.process_repeats,
            "aa_controls": campaign.protocol.process_repeats,
            "setup_placebo_controls": campaign.protocol.process_repeats,
            "positive_controls": (
                campaign.protocol.process_repeats * len(target.positive_control_effects)
            ),
        }
        for field_name, expected_length in expected_list_lengths.items():
            value = protocol.get(field_name)
            if (
                not isinstance(value, list)
                or len(value) != expected_length
                or any(not isinstance(entry, dict) for entry in value)
            ):
                harness_errors.append(
                    f"{field_name} count/type mismatch; expected {expected_length} objects"
                )
        for field_name in (
            "target_status_consistent",
            "aa_budget_passed",
            "setup_placebo_passed",
            "positive_power_passed",
        ):
            if not isinstance(protocol.get(field_name), bool):
                harness_errors.append(f"{field_name} must be boolean")
        if protocol.get("randomness_policies_observed") != ["seeded-interpose"]:
            harness_errors.append(
                f"randomness policy={protocol.get('randomness_policies_observed')!r}"
            )
        try:
            raw_total = int(row.get("raw_n_total", ""))
        except (TypeError, ValueError):
            raw_total = -1
        if raw_total != target.target_measurements:
            harness_errors.append(
                f"summary raw_n_total={raw_total}, expected={target.target_measurements}"
            )
        if row.get("backend") != OFFICIAL_DUDECT_BACKEND:
            harness_errors.append(f"summary backend={row.get('backend')!r}")
        if row.get("status") != item.get("raw_status"):
            harness_errors.append("summary/backend raw status mismatch")
        if row.get("timing_validity") != item.get("timing_validity"):
            harness_errors.append("summary/backend timing_validity mismatch")
        try:
            summary_n0 = int(row.get("n0", ""))
            summary_n1 = int(row.get("n1", ""))
            summary_seed = int(row.get("analysis_seed", ""))
            summary_repeats = int(row.get("process_repeats", ""))
            summary_aa_failures = int(row.get("aa_failures", ""))
            summary_abs_t = float(row.get("abs_t_score", ""))
            backend_abs_t = float(item.get("abs_t_score"))
        except (TypeError, ValueError):
            harness_errors.append("summary/backend contains invalid numeric metadata")
        else:
            if summary_n0 != item.get("n0") or summary_n1 != item.get("n1"):
                harness_errors.append("summary/backend retained sample count mismatch")
            if summary_seed != item.get("analysis_seed"):
                harness_errors.append("summary/backend analysis seed mismatch")
            if summary_repeats != campaign.protocol.process_repeats:
                harness_errors.append("summary process repeat count mismatch")
            if summary_aa_failures != protocol.get("aa_failures"):
                harness_errors.append("summary/backend A/A failure count mismatch")
            if (
                not math.isfinite(summary_abs_t)
                or not math.isfinite(backend_abs_t)
                or not math.isclose(
                    summary_abs_t,
                    backend_abs_t,
                    rel_tol=0,
                    abs_tol=0.000_501,
                )
            ):
                harness_errors.append("summary/backend absolute t-score mismatch")
        expected_power = str(protocol.get("positive_power_passed")).lower()
        if row.get("positive_power_passed") != expected_power:
            harness_errors.append("summary/backend positive-power result mismatch")
        if item.get("analysis_raw_n_total") != target.target_measurements:
            harness_errors.append("backend analysis raw count mismatch")
        enough_measurements = item.get("enough_measurements")
        if not isinstance(enough_measurements, bool):
            harness_errors.append("backend enough_measurements must be boolean")
        elif item.get("timing_validity") == "valid" and not enough_measurements:
            harness_errors.append("valid timing contradicts insufficient retained measurements")
        if harness_errors:
            result.errors.extend(f"{harness_name}: {error}" for error in harness_errors)

        raw_status = str(item.get("raw_status", ""))
        validity = str(item.get("timing_validity", ""))
        try:
            _, signal = timing_from_raw(raw_status, validity)
            signal_value = signal.value
        except ValueError as exc:
            result.errors.append(f"{harness_name}: invalid timing state: {exc}")
            signal_value = "not-interpretable"
        validity_reasons = item.get("validity_reasons")
        if not isinstance(validity_reasons, list) or any(
            not isinstance(value, str) for value in validity_reasons
        ):
            result.errors.append(f"{harness_name}: validity_reasons must be a string list")
            validity_reasons = ["malformed validity_reasons"]
        blockers = list(validity_reasons)
        if validity != "valid":
            blockers.insert(0, f"timing_validity={validity or 'missing'}")
        environment = item.get("environment")
        if not isinstance(environment, dict):
            result.errors.append(f"{harness_name}: environment must be an object")
            environment = {"rejected": True}
        if environment.get("rejected"):
            blockers.append("target timing environment rejected")
        if not host_paper_eligible:
            blockers.append("campaign host is engineering-only")
        blockers = list(dict.fromkeys(blockers))
        result.blockers.extend(f"{harness_name}: {blocker}" for blocker in blockers)
        result.harnesses.append(
            {
                "harness": harness_name,
                "axis": expected_axis,
                "raw_status": raw_status,
                "timing_validity": validity,
                "timing_signal": signal_value,
                "abs_t_score": item.get("abs_t_score"),
                "analysis_seed": item.get("analysis_seed"),
                "n0": item.get("n0"),
                "n1": item.get("n1"),
                "promotion_ready": validity == "valid" and not blockers,
                "blockers": blockers,
            }
        )

    result.blockers = list(dict.fromkeys(result.blockers))
    result.complete = not result.errors
    result.promotion_ready = result.complete and all(
        harness["promotion_ready"] for harness in result.harnesses
    )
    return result


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _updates(validations: Iterable[TargetValidation]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for validation in validations:
        report_rel = f"{validation.target.id}/reports/dudect_backend_report.json"
        report_hash = validation.artifact_sha256.get("dudect_backend_report.json", "")
        for harness in validation.harnesses:
            rows.append(
                {
                    "target": validation.target.id,
                    "family": validation.target.family,
                    "harness": harness["harness"],
                    "timing_validity": harness["timing_validity"],
                    "timing_signal": harness["timing_signal"],
                    "timing_backend": OFFICIAL_DUDECT_BACKEND,
                    "timing_raw_status": harness["raw_status"],
                    "timing_abs_t": harness["abs_t_score"],
                    "timing_measurements": validation.target.target_measurements,
                    "timing_leak_target": harness["axis"],
                    "timing_seed": harness["analysis_seed"],
                    "timing_threshold": OFFICIAL_TIMING_THRESHOLD,
                    "report": report_rel,
                    "report_sha256": report_hash,
                    "promotion_ready": str(harness["promotion_ready"]).lower(),
                    "blockers": "; ".join(harness["blockers"]),
                }
            )
    return rows


def write_updates(
    path: Path,
    validations: Iterable[TargetValidation],
    *,
    merge: bool = False,
) -> None:
    materialized = list(validations)
    rows = _updates(materialized)
    if merge and path.is_file():
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames != UPDATE_FIELDS:
                raise CampaignError(f"cannot merge update CSV with a drifted header: {path}")
            replaced_targets = {validation.target.id for validation in materialized}
            previous = [row for row in reader if row.get("target") not in replaced_targets]
        rows = [*previous, *rows]
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=UPDATE_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    os.replace(temporary, path)


def validate_updates(
    path: Path,
    validations: Iterable[TargetValidation],
) -> list[str]:
    materialized = list(validations)
    if not path.is_file():
        return [f"missing artifact: {path}"]
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != UPDATE_FIELDS:
            return [
                f"{path.name}: header drift: expected={UPDATE_FIELDS}, actual={reader.fieldnames}"
            ]
        rows = list(reader)

    selected_targets = {validation.target.id for validation in materialized}
    actual: dict[tuple[str, str], dict[str, str]] = {}
    errors: list[str] = []
    for row in rows:
        if row.get("target") not in selected_targets:
            continue
        key = (row.get("target", ""), row.get("harness", ""))
        if key in actual:
            errors.append(f"{path.name}: duplicate candidate row {key}")
        actual[key] = row
    expected = {
        (str(row["target"]), str(row["harness"])): {
            field: "" if row.get(field) is None else str(row.get(field, ""))
            for field in UPDATE_FIELDS
        }
        for row in _updates(materialized)
    }
    if set(actual) != set(expected):
        errors.append(
            f"{path.name}: selected candidate rows drift: "
            f"expected={sorted(expected)}, actual={sorted(actual)}"
        )
    for key in set(actual).intersection(expected):
        if actual[key] != expected[key]:
            mismatches = [
                field
                for field in UPDATE_FIELDS
                if actual[key].get(field, "") != expected[key].get(field, "")
            ]
            errors.append(
                f"{path.name}: candidate {key} differs from validated artifacts in {mismatches}"
            )
    return errors


def _safe_output_root(path: Path) -> Path:
    resolved = path.resolve()
    if resolved == ROOT or ROOT.is_relative_to(resolved):
        raise CampaignError(
            f"output root cannot be the repository or one of its ancestors: {resolved}"
        )
    local_campaign_root = (ROOT / "measurement_runs").resolve()
    if resolved.is_relative_to(ROOT) and not resolved.is_relative_to(local_campaign_root):
        raise CampaignError(
            "an in-repository output must live under the ignored measurement_runs/ "
            f"directory: {resolved}"
        )
    if resolved.exists() and not resolved.is_dir():
        raise CampaignError(f"output root exists but is not a directory: {resolved}")
    return resolved


def _select_targets(campaign: CampaignSpec, selected: list[str]) -> tuple[TargetSpec, ...]:
    if not selected:
        return campaign.targets
    known = {target.id: target for target in campaign.targets}
    unknown = sorted(set(selected) - set(known))
    if unknown:
        raise CampaignError(f"unknown --target value(s): {unknown}")
    return tuple(target for target in campaign.targets if target.id in set(selected))


def _print_static_plan(campaign: CampaignSpec) -> None:
    print(
        f"[native-timing] OK: {campaign.campaign_id}, "
        f"{len(campaign.targets)} targets, "
        f"{sum(len(target.harnesses) for target in campaign.targets)} timing axes"
    )
    print(
        f"  protocol: backend={campaign.protocol.backend} "
        f"compiler={campaign.protocol.compiler} clock={campaign.protocol.clock} "
        f"warmup={campaign.protocol.warmup} repeats={campaign.protocol.process_repeats}"
    )
    for target in campaign.targets:
        rows_per_harness = campaign.protocol.process_repeats * (
            2 * target.target_measurements + 5 * target.control_measurements
        )
        print(
            f"  {target.id}: harnesses={','.join(target.harnesses)} "
            f"target={target.target_measurements} control={target.control_measurements} "
            f"protocol_rows={rows_per_harness * len(target.harnesses)}"
        )


def execute_campaign(
    campaign: CampaignSpec,
    output_root: Path,
    targets: tuple[TargetSpec, ...],
    *,
    preflight_report: dict[str, Any],
    resume: bool,
    continue_on_error: bool,
) -> int:
    output_root = _safe_output_root(output_root)
    commit = preflight_report.get("git_commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise CampaignError("preflight report must contain a full git commit")
    host_paper_eligible, host_errors = validate_preflight_report(
        campaign,
        preflight_report,
        expected_commit=commit,
    )
    if host_errors:
        raise CampaignError("preflight report is invalid: " + "; ".join(host_errors))
    if output_root.exists() and any(output_root.iterdir()) and not resume:
        raise CampaignError(f"output root is non-empty; use --resume: {output_root}")
    output_root.mkdir(parents=True, exist_ok=True)
    report_path = output_root / "campaign_report.json"
    report: dict[str, Any] = {
        "schema_version": "1.0",
        "kind": "native-timing-campaign-report",
        "campaign_id": campaign.campaign_id,
        "manifest": _display_path(campaign.manifest_path),
        "manifest_sha256": campaign.manifest_sha256,
        "ctkat_commit": commit,
        "started_at": _utc_now(),
        "finished_at": None,
        "status": "running",
        "selected_targets": [target.id for target in targets],
        "host_preflight": preflight_report,
        "targets": {},
    }
    if resume and report_path.is_file():
        try:
            previous = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CampaignError(f"cannot resume: campaign report unreadable: {exc}") from exc
        if not isinstance(previous, dict):
            raise CampaignError("cannot resume: campaign report root must be an object")
        if previous.get("manifest_sha256") != campaign.manifest_sha256:
            raise CampaignError("cannot resume: campaign manifest hash changed")
        if previous.get("ctkat_commit") != preflight_report["git_commit"]:
            raise CampaignError("cannot resume: CT-KAT commit changed")
        report["started_at"] = previous.get("started_at") or report["started_at"]
        previous_selected = previous.get("selected_targets") or []
        if not isinstance(previous_selected, list) or any(
            not isinstance(value, str) for value in previous_selected
        ):
            raise CampaignError("cannot resume: selected target index is malformed")
        known_targets = {target.id for target in campaign.targets}
        if not set(previous_selected) <= known_targets:
            raise CampaignError("cannot resume: selected target index contains unknown targets")
        report["selected_targets"] = list(
            dict.fromkeys(
                [
                    *previous_selected,
                    *(target.id for target in targets),
                ]
            )
        )
        previous_targets = previous.get("targets") or {}
        if not isinstance(previous_targets, dict) or any(
            not isinstance(value, dict) for value in previous_targets.values()
        ):
            raise CampaignError("cannot resume: campaign target index is malformed")
        if not set(previous_targets) <= known_targets:
            raise CampaignError("cannot resume: campaign target index contains unknown targets")
        report["targets"] = previous_targets
    _write_json_atomic(report_path, report)

    validations: list[TargetValidation] = []
    execution_failed = False
    for target in targets:
        target_root = output_root / target.id
        report_dir = target_root / "reports"
        existing = None
        if resume and all((report_dir / name).is_file() for name in REQUIRED_ARTIFACTS):
            existing = validate_target_artifacts(
                campaign,
                target,
                report_dir,
                host_paper_eligible=host_paper_eligible,
            )
            if existing.complete:
                print(f"[native-timing] resume: {target.id} artifacts already complete")
                validations.append(existing)
                report["targets"][target.id] = existing.as_dict()
                _write_json_atomic(report_path, report)
                continue
            raise CampaignError(
                f"cannot resume {target.id}: existing artifacts are corrupt: {existing.errors}"
            )

        print(f"[native-timing] execute: {target.id} ({', '.join(target.harnesses)})")
        try:
            cfg = load_config(target.config)
            dudect = campaign_dudect(
                cfg,
                campaign,
                target,
                target_root / "generated",
            )
            _do_dudect(
                dudect,
                target.config.parent,
                cfg.project.name,
                report_dir,
            )
            validation = validate_target_artifacts(
                campaign,
                target,
                report_dir,
                host_paper_eligible=host_paper_eligible,
            )
        except BaseException as exc:
            if isinstance(exc, KeyboardInterrupt):
                report["status"] = "interrupted"
                report["finished_at"] = _utc_now()
                _write_json_atomic(report_path, report)
                raise
            validation = TargetValidation(target=target, report_dir=report_dir)
            validation.errors.append(f"execution failed: {exc}")
        validations.append(validation)
        report["targets"][target.id] = validation.as_dict()
        _write_json_atomic(report_path, report)
        write_updates(
            output_root / "corpus_timing_updates.csv",
            [validation],
            merge=True,
        )
        if validation.errors:
            execution_failed = True
            print(
                f"[native-timing] ERROR {target.id}: " + "; ".join(validation.errors),
                file=sys.stderr,
            )
            if not continue_on_error:
                break
        elif validation.promotion_ready:
            print(f"[native-timing] {target.id}: promotion-ready")
        else:
            print(
                f"[native-timing] {target.id}: complete but non-promotable — "
                + "; ".join(validation.blockers)
            )

    report["finished_at"] = _utc_now()
    if execution_failed:
        report["status"] = "failed"
    elif any(target_id not in report["targets"] for target_id in report["selected_targets"]):
        report["status"] = "partial"
    elif all(
        bool(report["targets"][target_id].get("promotion_ready"))
        for target_id in report["selected_targets"]
    ):
        report["status"] = "complete"
    else:
        report["status"] = "complete-nonpromotable"
    _write_json_atomic(report_path, report)
    write_updates(
        output_root / "corpus_timing_updates.csv",
        validations,
        merge=resume,
    )
    if execution_failed:
        return 1
    return 0 if all(validation.promotion_ready for validation in validations) else 2


def validate_run(
    campaign: CampaignSpec,
    output_root: Path,
    selected: tuple[TargetSpec, ...],
) -> int:
    output_root = _safe_output_root(output_root)
    report_path = output_root / "campaign_report.json"
    if not report_path.is_file():
        raise CampaignError(f"campaign report missing: {report_path}")
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CampaignError(f"campaign report unreadable: {exc}") from exc
    if not isinstance(report, dict):
        raise CampaignError("campaign report root must be an object")
    if report.get("schema_version") != "1.0" or report.get("campaign_id") != campaign.campaign_id:
        raise CampaignError("campaign report identity/schema mismatch")
    if report.get("kind") != "native-timing-campaign-report":
        raise CampaignError("campaign report kind mismatch")
    if report.get("manifest_sha256") != campaign.manifest_sha256:
        raise CampaignError("campaign report manifest hash does not match current manifest")
    recorded_selected = report.get("selected_targets")
    if not isinstance(recorded_selected, list) or any(
        not isinstance(value, str) for value in recorded_selected
    ):
        raise CampaignError("campaign report selected_targets must be a string list")
    requested_ids = {target.id for target in selected}
    if not requested_ids <= set(recorded_selected):
        raise CampaignError(
            "selected validation targets were not recorded as executed by this campaign"
        )
    target_index = report.get("targets")
    if not isinstance(target_index, dict):
        raise CampaignError("campaign report targets must be an object")
    host_preflight = report.get("host_preflight")
    report_commit = report.get("ctkat_commit")
    if not isinstance(report_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", report_commit):
        raise CampaignError("campaign report ctkat_commit must be a full git hash")
    host_eligible, host_errors = validate_preflight_report(
        campaign,
        host_preflight,
        expected_commit=report_commit,
    )
    if host_errors:
        raise CampaignError("campaign host preflight is invalid: " + "; ".join(host_errors))
    validations = [
        validate_target_artifacts(
            campaign,
            target,
            output_root / target.id / "reports",
            host_paper_eligible=host_eligible,
        )
        for target in selected
    ]
    update_errors = validate_updates(
        output_root / "corpus_timing_updates.csv",
        validations,
    )
    for validation in validations:
        if validation.errors:
            print(
                f"[native-timing] ERROR {validation.target.id}: " + "; ".join(validation.errors),
                file=sys.stderr,
            )
        elif validation.promotion_ready:
            print(f"[native-timing] {validation.target.id}: artifacts valid, promotion-ready")
        else:
            print(
                f"[native-timing] {validation.target.id}: artifacts valid, non-promotable — "
                + "; ".join(validation.blockers)
            )
    if any(validation.errors for validation in validations):
        return 1
    for error in update_errors:
        print(f"[native-timing] ERROR: {error}", file=sys.stderr)
    if update_errors:
        return 1
    return 0 if all(validation.promotion_ready for validation in validations) else 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true", help="static manifest/config/corpus check")
    action.add_argument("--preflight", action="store_true", help="native host gate only")
    action.add_argument("--execute", action="store_true", help="run the selected campaign targets")
    action.add_argument(
        "--validate-run",
        type=Path,
        metavar="OUTPUT_ROOT",
        help="validate an existing campaign without executing targets",
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--target", action="append", default=[])
    parser.add_argument("--cpu", type=int, help="explicitly pin this process and children")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--continue-on-error", action="store_true")
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--allow-virtualized", action="store_true")
    args = parser.parse_args(argv)

    try:
        campaign = load_campaign(args.manifest)
        errors = static_check(campaign)
        if errors:
            for error in errors:
                print(f"[native-timing] ERROR: {error}", file=sys.stderr)
            return 1
        selected = _select_targets(campaign, args.target)
        if args.check:
            _print_static_plan(campaign)
            return 0
        if args.cpu is not None:
            pin_current_process(args.cpu)
        if args.validate_run is not None:
            return validate_run(campaign, args.validate_run, selected)

        host = preflight(
            campaign,
            allow_dirty=args.allow_dirty,
            allow_virtualized=args.allow_virtualized,
            build_adapter=True,
        )
        print(json.dumps(host, indent=2, sort_keys=True))
        if not host["ok"]:
            return 1
        if args.preflight:
            return 0
        if args.output_root is None:
            parser.error("--execute requires --output-root")
        return execute_campaign(
            campaign,
            args.output_root,
            selected,
            preflight_report=host,
            resume=args.resume,
            continue_on_error=args.continue_on_error,
        )
    except CampaignError as exc:
        print(f"[native-timing] ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
