"""Regression tests for the public-alpha release plumbing."""

import json
from importlib import resources
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from ctkat import __version__
from ctkat._template_resources import read_template
from ctkat.cli import app
from ctkat.config import BuildConfig, CtkatConfig, ProjectConfig

ROOT = Path(__file__).resolve().parent.parent


def test_cli_version_matches_package_version():
    result = CliRunner().invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == __version__ == "0.3.0a1"


def test_all_six_templates_are_package_resources():
    template_root = resources.files("ctkat").joinpath("templates")
    expected = {
        "harness_generic.c.j2",
        "harness_kem.c.j2",
        "harness_sign.c.j2",
        "timing_generic.c.j2",
        "timing_kem.c.j2",
        "timing_sign.c.j2",
    }
    assert {
        entry.name for entry in template_root.iterdir() if entry.name.endswith(".j2")
    } == expected
    assert all(read_template(name) for name in expected)


def test_evidence_v2_json_schema_is_a_package_resource():
    schema = json.loads(
        resources.files("ctkat")
        .joinpath("schemas", "evidence-v2.schema.json")
        .read_text(encoding="utf-8")
    )
    assert schema["properties"]["schema_version"]["const"] == "2.0"


def test_template_resource_rejects_path_traversal():
    with pytest.raises(ValueError, match="basename"):
        read_template("../README.md")


def test_explicit_allow_shell_false_rejects_command():
    with pytest.raises(ValidationError, match="requires allow_shell: true"):
        BuildConfig(command="make", allow_shell=False)


def test_explicit_shell_opt_in_remains_available_for_trusted_config():
    config = BuildConfig(command="make clean && make", allow_shell=True)
    assert config.command == "make clean && make"


def test_untrusted_profile_rejects_shell_even_when_opted_in():
    with pytest.raises(ValidationError, match="execution_profile=untrusted"):
        CtkatConfig(
            project=ProjectConfig(name="demo"),
            build=BuildConfig(command="make", allow_shell=True),
            execution_profile="untrusted",
        )


@pytest.mark.parametrize(
    "script,args",
    [
        ("render_readme_corpus.py", ["--check"]),
        ("check_third_party.py", []),
        ("check_example_configs.py", []),
        ("check_corpus.py", []),
        ("migrate_evidence_v1_to_v2.py", ["--check"]),
    ],
)
def test_committed_release_gate_scripts_pass(script, args):
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / script), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
