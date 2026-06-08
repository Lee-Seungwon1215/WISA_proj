"""Bundle R (Phase 1): triage.yaml loader + adapters."""

import textwrap
from pathlib import Path

import pytest
from pydantic import ValidationError

from ctkat.triage import TriageConfig, load_triage


def _write(tmp_path, body: str) -> Path:
    p = tmp_path / "triage.yaml"
    p.write_text(textwrap.dedent(body))
    return p


def test_load_triage_parses_fields(tmp_path):
    p = _write(tmp_path, """
        registry: docs/accepted_variable_time.md
        harnesses:
          kem_dec:
            varlat: public
            note: "fips202 divs are public"
          sign:
            verdict: accepted-variable-time
    """)
    t = load_triage(p)
    assert t.registry == Path("docs/accepted_variable_time.md")
    assert t.varlat_map() == {"kem_dec": "public", "sign": "untriaged"}
    assert t.verdict_overrides() == {"sign": "accepted-variable-time"}
    assert t.note_overrides() == {"kem_dec": "fips202 divs are public"}


def test_empty_triage_is_valid(tmp_path):
    p = tmp_path / "triage.yaml"
    p.write_text("")
    t = load_triage(p)
    assert t.harnesses == {} and t.registry is None


def test_unknown_top_key_rejected(tmp_path):
    p = _write(tmp_path, "harnesses: {}\nbogus: 1\n")
    with pytest.raises(ValidationError):
        load_triage(p)


def test_unknown_harness_key_rejected(tmp_path):
    p = _write(tmp_path, """
        harnesses:
          h:
            varlat: public
            typo_field: x
    """)
    with pytest.raises(ValidationError):
        load_triage(p)


def test_invalid_varlat_enum_rejected(tmp_path):
    p = _write(tmp_path, "harnesses:\n  h:\n    varlat: maybe-secret\n")
    with pytest.raises(ValidationError):
        load_triage(p)


def test_invalid_verdict_override_rejected(tmp_path):
    # `verdict` must be a known verdict_class.
    p = _write(tmp_path, "harnesses:\n  h:\n    verdict: totally-clean\n")
    with pytest.raises(ValidationError, match="unknown verdict_class"):
        load_triage(p)


def test_non_mapping_root_rejected(tmp_path):
    p = tmp_path / "triage.yaml"
    p.write_text("- a\n- b\n")
    with pytest.raises(ValueError):
        load_triage(p)


def test_default_triage_config_is_empty():
    t = TriageConfig()
    assert t.varlat_map() == {} and t.verdict_overrides() == {} and t.note_overrides() == {}
