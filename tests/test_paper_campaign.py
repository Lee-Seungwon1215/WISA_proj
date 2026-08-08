from copy import deepcopy
from pathlib import Path

import pytest

from scripts.check_paper_campaign import (
    load_manifest,
    main,
    render_execution_commands,
    validate,
)


def test_frozen_paper_campaign_is_static_ready():
    errors, report = validate(load_manifest())
    assert errors == []
    assert report["status"] == "static-plan-valid"
    assert report["component_count"] == 4
    assert report["timing_axes"] == 28
    assert report["target_executions"] == 26
    assert report["physical_hosts_required"] == 2


def test_one_host_or_automatic_promotion_fails_closed():
    data = deepcopy(load_manifest())
    data["execution_policy"]["minimum_physical_hosts"] = 1
    data["promotion"]["automatic_corpus_mutation"] = True
    errors, _ = validate(data)
    assert any("minimum_physical_hosts" in error for error in errors)
    assert any("automatic_corpus_mutation" in error for error in errors)


def test_upstream_pin_drift_is_rejected():
    data = deepcopy(load_manifest())
    data["upstream_freeze"]["mlkem-native"]["revision"] = "0" * 40
    errors, _ = validate(data)
    assert any("upstream_freeze.mlkem-native.revision" in error for error in errors)


def test_final_timecop_command_requires_explicit_pinned_prefix():
    data = deepcopy(load_manifest())
    data["same_corpus_baseline"]["execute_commands"]["timecop"] = (
        "uv run --frozen python scripts/run_same_corpus_baselines.py "
        "--run-timecop --run-kind final "
        "--output-root measurement_runs/host-ID/same-corpus"
    )
    errors, _ = validate(data)
    assert "same-corpus execution command matrix drift" in errors


def test_frozen_execution_commands_require_hash_locked_uv():
    data = deepcopy(load_manifest())
    data["components"][0]["command"] = data["components"][0]["command"].replace(
        "uv run --frozen python", "python3", 1
    )
    errors, _ = validate(data)
    assert "committed-corpus-refresh: execution command drift" in errors

    data = deepcopy(load_manifest())
    data["analysis"]["blinded_command"] = data["analysis"]["blinded_command"].replace(
        "uv run --frozen python", "python3", 1
    )
    errors, _ = validate(data)
    assert "analysis/blinding contract drift" in errors


def test_rendered_execution_matrix_has_seven_placeholder_free_commands():
    commands = render_execution_commands(
        load_manifest(),
        host_id="host-a",
        cpu=2,
        timecop_prefix=Path("/opt/ctkat/timecop"),
    )
    assert len(commands) == 7
    assert all(command.startswith("uv run --frozen python ") for command in commands)
    assert all(
        placeholder not in command
        for command in commands
        for placeholder in ("host-ID", "CPU-ID", "TIMECOP-PREFIX")
    )
    assert sum("measurement_runs/host-a/" in command for command in commands) == 7
    assert sum("--cpu 2" in command for command in commands) == 5
    assert sum("--prefix /opt/ctkat/timecop" in command for command in commands) == 1
    assert sum("--run-dudect" in command for command in commands) == 1
    assert sum("--run-timecop" in command for command in commands) == 1
    assert sum("--run-microwalk" in command for command in commands) == 1


@pytest.mark.parametrize(
    ("host_id", "prefix", "message"),
    [
        ("host a", Path("/opt/ctkat/timecop"), "host id"),
        ("host-a", Path("relative/timecop"), "absolute path"),
    ],
)
def test_command_renderer_rejects_unsafe_or_ambiguous_substitutions(
    host_id: str,
    prefix: Path,
    message: str,
):
    with pytest.raises(ValueError, match=message):
        render_execution_commands(
            load_manifest(),
            host_id=host_id,
            cpu=2,
            timecop_prefix=prefix,
        )


def test_print_commands_cli_emits_only_the_seven_commands(capsys):
    assert (
        main(
            [
                "--print-commands",
                "--host-id",
                "host-b",
                "--cpu",
                "3",
                "--timecop-prefix",
                "/srv/timecop",
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    assert captured.err == ""
    lines = captured.out.splitlines()
    assert len(lines) == 7
    assert all("host-b" in line for line in lines)


def test_print_commands_cli_requires_all_substitutions():
    with pytest.raises(SystemExit) as exc:
        main(["--print-commands", "--host-id", "host-a", "--cpu", "2"])
    assert exc.value.code == 2
