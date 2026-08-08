"""Timing-host manifest and fail-closed environment checks."""

from __future__ import annotations

import hashlib
import os
import platform
from pathlib import Path
from typing import Any


def _read_first(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def _linux_microcode() -> str:
    try:
        text = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    for line in text.splitlines():
        if line.lower().startswith("microcode") and ":" in line:
            return line.split(":", 1)[1].strip()
    return ""


def _linux_cpu_model() -> str:
    """Return the exact kernel-reported CPU model used for host identity checks."""

    try:
        text = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    for field in ("model name", "hardware", "processor"):
        for line in text.splitlines():
            if line.lower().startswith(field) and ":" in line:
                value = line.split(":", 1)[1].strip()
                if value and not value.isdigit():
                    return value
    return ""


def _linux_machine_id_sha256() -> str:
    value = _read_first("/etc/machine-id")
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _linux_boot_id_sha256() -> str:
    value = _read_first("/proc/sys/kernel/random/boot_id")
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _linux_timing_cpu_flags() -> dict[str, bool]:
    required = ("constant_tsc", "nonstop_tsc", "rdtscp")
    try:
        text = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {name: False for name in required}
    flags: set[str] = set()
    for line in text.splitlines():
        if line.lower().startswith(("flags", "features")) and ":" in line:
            flags.update(line.split(":", 1)[1].strip().split())
            break
    return {name: name in flags for name in required}


def collect_timing_environment(*, emulated: bool, clock: str) -> dict[str, Any]:
    """Capture what can be observed without privileged host mutation.

    CT-KAT never changes affinity, governor, turbo, or SMT on the user's
    behalf.  It records them and rejects known-bad conditions.  At present,
    emulation and a Linux process eligible to migrate across multiple CPUs are
    hard rejection reasons; unavailable metadata remains explicit ``null``/"".
    """

    affinity: list[int] = []
    if hasattr(os, "sched_getaffinity"):
        try:
            affinity = sorted(os.sched_getaffinity(0))
        except OSError:
            affinity = []

    system = platform.system()
    governor_cpu = affinity[0] if len(affinity) == 1 else 0
    governor = (
        _read_first(f"/sys/devices/system/cpu/cpu{governor_cpu}/cpufreq/scaling_governor")
        if system == "Linux"
        else ""
    )
    smt_active = _read_first("/sys/devices/system/cpu/smt/active") if system == "Linux" else ""
    no_turbo = (
        _read_first("/sys/devices/system/cpu/intel_pstate/no_turbo") if system == "Linux" else ""
    )

    rejection_reasons: list[str] = []
    if emulated:
        rejection_reasons.append("emulated host (QEMU/virtual CPU timing is non-native)")
    if system == "Linux" and len(affinity) > 1:
        rejection_reasons.append(
            "process is eligible on multiple CPUs; pin it to one CPU (for example taskset -c 0)"
        )

    return {
        "system": system,
        "machine": platform.machine(),
        "kernel": platform.release(),
        "processor": platform.processor(),
        "cpu_model": _linux_cpu_model() or platform.processor() or None,
        "hostname": platform.node() or None,
        "machine_id_sha256": _linux_machine_id_sha256() or None,
        "boot_id_sha256": _linux_boot_id_sha256() or None,
        "timing_cpu_flags": _linux_timing_cpu_flags() if system == "Linux" else None,
        "clock": clock,
        "emulated": emulated,
        "cpu_affinity": affinity,
        "cpu_affinity_count": len(affinity) if affinity else None,
        "governor": governor or None,
        "smt_active": smt_active or None,
        "intel_pstate_no_turbo": no_turbo or None,
        "microcode": _linux_microcode() or None,
        "rejected": bool(rejection_reasons),
        "rejection_reasons": rejection_reasons,
    }
