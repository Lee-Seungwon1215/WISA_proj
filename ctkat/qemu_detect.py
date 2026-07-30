"""Best-effort detection of cross-architecture CPU emulation.

When ctkat runs inside a Docker container on Apple Silicon, the container
is x86_64 but executes under QEMU or Docker's newer VirtualApple translation
path. In that environment the x86 `rdtsc` instruction yields cycle counts that
don't reflect a native x86 CPU's actual timing distribution. We surface a
warning and reject the experiment's timing validity.

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

# Modern Docker Desktop on Apple Silicon may expose neither QEMU DMI strings
# nor a "QEMU" model name. Its translated x86 CPU instead reports
# ``vendor_id/model name: VirtualApple`` in /proc/cpuinfo. That identifier
# cannot occur on a native x86 CPU, so one occurrence is already a strong
# cross-architecture signal and does not need the generic two-source rule.
_STRONG_CANDIDATES = ((Path("/proc/cpuinfo"), "VirtualApple"),)


def detect_qemu_emulation() -> bool:
    """Return whether the observable CPU is a translated/emulated target.

    A strong VirtualApple marker is sufficient. Otherwise at least
    ``_MIN_SIGNALS`` independent paths must carry the generic QEMU marker.
    Read errors are neutral so a native x86 host with restricted proc/sys
    access is not rejected merely because metadata is unavailable.
    """
    for path, needle in _STRONG_CANDIDATES:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except (FileNotFoundError, PermissionError, OSError):
            continue
        if needle in text:
            return True

    signals = 0
    for path, needle in _CANDIDATES:
        try:
            # T21: /proc and /sys/dmi entries are mostly ASCII but locale
            # quirks (or DMI strings with vendor garbage) can break utf-8 —
            # errors="replace" keeps detection from raising in the parent.
            text = path.read_text(encoding="utf-8", errors="replace")
        except (FileNotFoundError, PermissionError, OSError):
            continue
        if needle in text:
            signals += 1
            if signals >= _MIN_SIGNALS:
                return True
    return False
