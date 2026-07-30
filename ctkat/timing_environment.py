"""Timing-host manifest and fail-closed environment checks."""

from __future__ import annotations

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
    governor = (
        _read_first("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
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
