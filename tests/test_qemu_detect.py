"""Bundle H2 (T9): qemu_detect multi-signal threshold tests.

The v1 single-substring match used to false-positive on bare-metal hosts
that happened to ship QEMU-related strings in one DMI/cpuinfo file (a
workstation with KVM tools installed, say). v2 requires ≥2 independent
signals.
"""

from __future__ import annotations

from pathlib import Path

import ctkat.qemu_detect as qd


def _mock_read_text(monkeypatch, hits: dict[str, str]) -> None:
    """Patch Path.read_text so configured paths return content; others
    raise FileNotFoundError (treated as "no signal" by detect_qemu_emulation).
    `hits` is `{path_str: file_contents}`."""
    real = Path.read_text

    def fake(self, *a, **kw):
        s = str(self)
        if s in hits:
            return hits[s]
        raise FileNotFoundError(s)
    monkeypatch.setattr(Path, "read_text", fake)


def test_zero_signals_returns_false(monkeypatch):
    _mock_read_text(monkeypatch, {})
    assert qd.detect_qemu_emulation() is False


def test_one_signal_returns_false(monkeypatch):
    # Bare-metal workstation that happens to mention "QEMU" once
    # somewhere — must NOT be classified as emulated.
    _mock_read_text(monkeypatch, {"/proc/cpuinfo": "model name : Intel ... QEMU helper module loaded\n"})
    assert qd.detect_qemu_emulation() is False


def test_two_signals_returns_true(monkeypatch):
    # Docker-on-M1 typically lights up at least 3 of the 4 candidates.
    _mock_read_text(monkeypatch, {
        "/proc/cpuinfo": "QEMU Virtual CPU version 2.5+\n",
        "/sys/class/dmi/id/sys_vendor": "QEMU\n",
    })
    assert qd.detect_qemu_emulation() is True


def test_signal_without_needle_doesnt_count(monkeypatch):
    # File exists but doesn't carry the marker — neutral.
    _mock_read_text(monkeypatch, {
        "/proc/cpuinfo": "model name : Intel Core i7\n",
        "/sys/class/dmi/id/sys_vendor": "Dell Inc.\n",
    })
    assert qd.detect_qemu_emulation() is False
