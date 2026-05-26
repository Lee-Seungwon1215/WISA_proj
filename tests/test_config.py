from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from ctkat.config import CtkatConfig, load_config


MINIMAL_YAML = """
project:
  name: demo
build:
  command: "true"
ct:
  harnesses:
    - name: h1
      binary: ./bin/h1
"""


def test_minimal_config_validates(tmp_path: Path):
    p = tmp_path / "ctkat.yaml"
    p.write_text(MINIMAL_YAML)
    cfg = load_config(p)
    assert isinstance(cfg, CtkatConfig)
    assert cfg.project.name == "demo"
    assert cfg.kat is None
    assert cfg.ct.harnesses[0].name == "h1"
    # default valgrind flags present
    assert any(flag.startswith("--tool=") for flag in cfg.ct.valgrind_flags)


def test_unknown_field_rejected(tmp_path: Path):
    p = tmp_path / "ctkat.yaml"
    raw = yaml.safe_load(MINIMAL_YAML)
    raw["project"]["bogus"] = 1
    p.write_text(yaml.safe_dump(raw))
    with pytest.raises(ValidationError):
        load_config(p)


def test_missing_required_section_rejected(tmp_path: Path):
    # `project` is required; omitting it must fail validation.
    p = tmp_path / "ctkat.yaml"
    p.write_text("build:\n  command: 'true'\n")
    with pytest.raises(ValidationError):
        load_config(p)


def test_ct_and_dudect_both_optional(tmp_path: Path):
    # A config with only project+build is valid as of Phase 4 — both `ct`
    # and `dudect` sections are optional now.
    p = tmp_path / "ctkat.yaml"
    p.write_text("project:\n  name: demo\nbuild:\n  command: 'true'\n")
    cfg = load_config(p)
    assert cfg.ct is None
    assert cfg.dudect is None


# --- HarnessConfig mutex / required-field validation ------------------------


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "ctkat.yaml"
    p.write_text(body)
    return p


_HARNESS_BOTH_MODES = """
project: {name: demo}
build: {command: "true"}
ct:
  harnesses:
    - name: h1
      binary: ./bin/h1
      template: generic
      function: foo
"""

_HARNESS_NEITHER_MODE = """
project: {name: demo}
build: {command: "true"}
ct:
  harnesses:
    - name: h1
"""

_HARNESS_GENERIC_WITHOUT_FUNCTION = """
project: {name: demo}
build: {command: "true"}
ct:
  harnesses:
    - name: h1
      template: generic
"""

_HARNESS_KEM_WITHOUT_HEADER = """
project: {name: demo}
build: {command: "true"}
ct:
  harnesses:
    - name: h1
      template: kem
"""


def test_harness_binary_and_template_mutually_exclusive(tmp_path: Path):
    with pytest.raises(ValidationError, match="mutually exclusive"):
        load_config(_write(tmp_path, _HARNESS_BOTH_MODES))


def test_harness_requires_binary_or_template(tmp_path: Path):
    with pytest.raises(ValidationError, match="binary.*template"):
        load_config(_write(tmp_path, _HARNESS_NEITHER_MODE))


def test_harness_generic_requires_function(tmp_path: Path):
    with pytest.raises(ValidationError, match="requires 'function'"):
        load_config(_write(tmp_path, _HARNESS_GENERIC_WITHOUT_FUNCTION))


def test_harness_kem_requires_header(tmp_path: Path):
    with pytest.raises(ValidationError, match="requires 'header'"):
        load_config(_write(tmp_path, _HARNESS_KEM_WITHOUT_HEADER))


# --- DudectHarnessConfig validator ------------------------------------------


_DUDECT_KEM_WITHOUT_HEADER = """
project: {name: demo}
build: {command: "true"}
dudect:
  harnesses:
    - name: h1
      template: kem
"""

_DUDECT_GENERIC_WITHOUT_FUNCTION = """
project: {name: demo}
build: {command: "true"}
dudect:
  harnesses:
    - name: h1
      template: generic
"""


def test_dudect_kem_requires_header(tmp_path: Path):
    # Regression: previously the dudect validator was missing, so this
    # passed pydantic and exploded later inside the Jinja2 generator.
    with pytest.raises(ValidationError, match="requires 'header'"):
        load_config(_write(tmp_path, _DUDECT_KEM_WITHOUT_HEADER))


def test_dudect_generic_requires_function(tmp_path: Path):
    with pytest.raises(ValidationError, match="requires 'function'"):
        load_config(_write(tmp_path, _DUDECT_GENERIC_WITHOUT_FUNCTION))


def test_dudect_default_cflags_disable_lto():
    # `-fno-lto` is load-bearing: with LTO the optimizer can see across the
    # timed function's external linkage and elide it once it concludes the
    # return value is unused. Keep the flag in the default set so users who
    # don't override `dudect.compiler.cflags` are protected by default.
    from ctkat.config import DudectCompilerConfig
    flags = DudectCompilerConfig().cflags
    assert "-fno-lto" in flags


# --- Bundle C: clock=auto + ARM guard ----------------------------------------


def test_dudect_clock_default_is_auto():
    from ctkat.config import DudectConfig
    cfg = DudectConfig(harnesses=[])
    assert cfg.clock == "auto"


def test_resolve_clock_passes_through_explicit_values():
    from ctkat.config import resolve_clock
    assert resolve_clock("rdtsc") == "rdtsc"
    assert resolve_clock("monotonic") == "monotonic"


def test_resolve_clock_auto_picks_rdtsc_on_native_x86(monkeypatch):
    import ctkat.config as cfg_mod
    monkeypatch.setattr(cfg_mod.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(cfg_mod, "detect_qemu_emulation", lambda: False)
    assert cfg_mod.resolve_clock("auto") == "rdtsc"


def test_resolve_clock_auto_picks_monotonic_under_qemu(monkeypatch):
    # QEMU x86 (Docker on Apple Silicon) reports x86_64 but rdtsc is
    # unreliable — auto must downgrade to monotonic.
    import ctkat.config as cfg_mod
    monkeypatch.setattr(cfg_mod.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(cfg_mod, "detect_qemu_emulation", lambda: True)
    assert cfg_mod.resolve_clock("auto") == "monotonic"


def test_resolve_clock_auto_picks_monotonic_on_arm(monkeypatch):
    import ctkat.config as cfg_mod
    monkeypatch.setattr(cfg_mod.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(cfg_mod, "detect_qemu_emulation", lambda: False)
    assert cfg_mod.resolve_clock("auto") == "monotonic"


def test_resolve_clock_auto_handles_windows_amd64_casing(monkeypatch):
    # Regression guard: Windows reports "AMD64" (uppercase). Naive == check
    # against "amd64" would miss it and fall through to monotonic.
    import ctkat.config as cfg_mod
    monkeypatch.setattr(cfg_mod.platform, "machine", lambda: "AMD64")
    monkeypatch.setattr(cfg_mod, "detect_qemu_emulation", lambda: False)
    assert cfg_mod.resolve_clock("auto") == "rdtsc"


def test_explicit_rdtsc_on_arm_raises(monkeypatch, tmp_path: Path):
    import ctkat.config as cfg_mod
    monkeypatch.setattr(cfg_mod.platform, "machine", lambda: "arm64")
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "dudect:\n"
        "  clock: rdtsc\n"
        "  harnesses: []\n"
    )
    with pytest.raises(ValidationError, match="rdtsc.*requires.*x86_64"):
        load_config(_write(tmp_path, body))


def test_explicit_monotonic_on_arm_is_fine(monkeypatch, tmp_path: Path):
    import ctkat.config as cfg_mod
    monkeypatch.setattr(cfg_mod.platform, "machine", lambda: "arm64")
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "dudect:\n"
        "  clock: monotonic\n"
        "  harnesses: []\n"
    )
    cfg = load_config(_write(tmp_path, body))
    assert cfg.dudect.clock == "monotonic"


def test_auto_clock_on_arm_loads_cleanly(monkeypatch, tmp_path: Path):
    # The yaml stays "auto"; resolution happens lazily at runtime.
    import ctkat.config as cfg_mod
    monkeypatch.setattr(cfg_mod.platform, "machine", lambda: "arm64")
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "dudect:\n"
        "  clock: auto\n"
        "  harnesses: []\n"
    )
    cfg = load_config(_write(tmp_path, body))
    assert cfg.dudect.clock == "auto"


# --- Bundle D: leak_target field ---------------------------------------------


def test_dudect_harness_leak_target_default_is_sk():
    from ctkat.config import DudectHarnessConfig
    h = DudectHarnessConfig(name="h", template="kem", header="api.h")
    assert h.leak_target == "sk"


def test_dudect_kem_can_set_leak_target_ct():
    from ctkat.config import DudectHarnessConfig
    h = DudectHarnessConfig(
        name="h", template="kem", header="api.h", leak_target="ct",
    )
    assert h.leak_target == "ct"


def test_dudect_generic_with_ct_leak_target_raises(tmp_path: Path):
    # leak_target is KEM-specific. On the generic template there's no
    # canonical sk-vs-ct split, so accepting `ct` would be a silent no-op.
    body = (
        "project: {name: demo}\n"
        "build: {command: 'true'}\n"
        "dudect:\n"
        "  harnesses:\n"
        "    - name: h\n"
        "      template: generic\n"
        "      function: foo\n"
        "      leak_target: ct\n"
    )
    with pytest.raises(ValidationError, match="leak_target.*only valid for template=kem"):
        load_config(_write(tmp_path, body))
