"""Best-effort detection of QEMU emulation.

When ctkat runs inside a Docker container on Apple Silicon, the container
is x86_64 but executes under QEMU. In that environment the x86 `rdtsc`
instruction yields cycle counts that don't reflect the host CPU's actual
timing distribution. We surface a warning so the user can opt for the
`clock_gettime`-based fallback instead.

Bundle H2 (T9): the v1 single-substring match would false-positive on
bare-metal hosts that happen to load QEMU-related kernel modules or DMI
strings (e.g. a workstation that runs VMs occasionally → `/proc/cpuinfo`
or `sys_vendor` carries "QEMU"). We now require AT LEAST TWO signals so
"my workstation has KVM/QEMU installed but isn't *running* under
emulation" is correctly identified as native.
"""

from __future__ import annotations

from pathlib import Path


# Each entry: (path, needle). Reading "QEMU" from MULTIPLE of these paths
# at the same time is strong evidence we're inside an emulator — DMI
# product_name + sys_vendor + cpuinfo all aligning would be hard to
# coincidentally trigger on bare metal.
_CANDIDATES = (
    (Path("/proc/cpuinfo"), "QEMU"),
    (Path("/sys/class/dmi/id/sys_vendor"), "QEMU"),
    (Path("/sys/class/dmi/id/product_name"), "QEMU"),
    (Path("/sys/devices/virtual/dmi/id/sys_vendor"), "QEMU"),
)

# Number of independent signal sources that must all see the needle for
# us to claim emulation. 2 is permissive enough to detect Docker-on-M1
# (which lights up at least 3 of the four candidates) while rejecting
# bare-metal workstations that only carry the string in a single file.
_MIN_SIGNALS = 2


def detect_qemu_emulation() -> bool:
    """True iff at least `_MIN_SIGNALS` candidate paths carry the QEMU
    marker. Returns False on read errors (file missing / permission denied
    / OS-level error) — defaulting to "not emulated" keeps the rdtsc path
    on hosts where we can't introspect (better than incorrectly downgrading
    to monotonic on a real x86_64 box)."""
    signals = 0
    for path, needle in _CANDIDATES:
        try:
            text = path.read_text()
        except (FileNotFoundError, PermissionError, OSError):
            continue
        if needle in text:
            signals += 1
            if signals >= _MIN_SIGNALS:
                return True
    return False
