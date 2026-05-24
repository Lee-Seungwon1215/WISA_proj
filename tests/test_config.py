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
