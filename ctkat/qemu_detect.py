"""Best-effort detection of QEMU emulation.

When ctkat runs inside a Docker container on Apple Silicon, the container
is x86_64 but executes under QEMU. In that environment the x86 `rdtsc`
instruction yields cycle counts that don't reflect the host CPU's actual
timing distribution. We surface a warning so the user can opt for the
`clock_gettime`-based fallback instead.
"""

from __future__ import annotations

from pathlib import Path


_CANDIDATES = (
    (Path("/proc/cpuinfo"), "QEMU"),
    (Path("/sys/class/dmi/id/sys_vendor"), "QEMU"),
    (Path("/sys/class/dmi/id/product_name"), "QEMU"),
    (Path("/sys/devices/virtual/dmi/id/sys_vendor"), "QEMU"),
)


def detect_qemu_emulation() -> bool:
    for path, needle in _CANDIDATES:
        try:
            text = path.read_text()
        except (FileNotFoundError, PermissionError, OSError):
            continue
        if needle in text:
            return True
    return False
