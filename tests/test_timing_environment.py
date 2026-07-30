from ctkat import timing_environment as te


def test_emulation_is_environment_rejected(monkeypatch):
    monkeypatch.setattr(te.platform, "system", lambda: "Darwin")
    environment = te.collect_timing_environment(emulated=True, clock="monotonic")
    assert environment["rejected"] is True
    assert "emulated" in environment["rejection_reasons"][0]


def test_unavailable_affinity_metadata_is_recorded_not_invented(monkeypatch):
    monkeypatch.setattr(te.platform, "system", lambda: "Darwin")
    monkeypatch.delattr(te.os, "sched_getaffinity", raising=False)
    environment = te.collect_timing_environment(emulated=False, clock="monotonic")
    assert environment["cpu_affinity_count"] is None
    assert environment["rejected"] is False


def test_linux_multi_cpu_affinity_is_rejected(monkeypatch):
    monkeypatch.setattr(te.platform, "system", lambda: "Linux")
    monkeypatch.setattr(te.os, "sched_getaffinity", lambda _pid: {2, 4}, raising=False)
    monkeypatch.setattr(te, "_read_first", lambda _path: "")
    monkeypatch.setattr(te, "_linux_microcode", lambda: "")
    environment = te.collect_timing_environment(emulated=False, clock="rdtsc")
    assert environment["cpu_affinity"] == [2, 4]
    assert environment["rejected"] is True
    assert "multiple CPUs" in environment["rejection_reasons"][0]


def test_linux_single_cpu_affinity_is_accepted_by_host_policy(monkeypatch):
    monkeypatch.setattr(te.platform, "system", lambda: "Linux")
    monkeypatch.setattr(te.os, "sched_getaffinity", lambda _pid: {3}, raising=False)
    monkeypatch.setattr(te, "_read_first", lambda _path: "")
    monkeypatch.setattr(te, "_linux_microcode", lambda: "")
    environment = te.collect_timing_environment(emulated=False, clock="rdtsc")
    assert environment["cpu_affinity"] == [3]
    assert environment["rejected"] is False
