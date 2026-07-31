"""Regression tests for the same-corpus baseline contract and adapters."""

from __future__ import annotations

import copy
import json
import subprocess
from pathlib import Path

from scripts import run_same_corpus_baselines as baseline


def test_frozen_same_corpus_manifest_and_expansion_plan_pass():
    manifest = baseline.load_manifest()
    assert baseline.validate_static(manifest) == []
    assert manifest["comparison_contract"]["aggregate_accuracy"] == "forbidden"
    assert {(row["case_id"], row["tool_id"]) for row in manifest["coverage"]} == {
        (case_id, tool_id) for case_id in baseline.CASE_ORDER for tool_id in baseline.TOOL_ORDER
    }


def test_testcase_generator_is_balanced_and_exactly_frozen():
    manifest = baseline.load_manifest()
    payloads = baseline._testcase_payloads()
    assert len(payloads) == 16
    assert {len(payload) for payload in payloads} == {32}
    assert sum(payload[0] < 0x80 for payload in payloads) == 8
    assert sum(payload[0] >= 0x80 for payload in payloads) == 8
    assert (
        baseline._ordered_payload_sha256()
        == manifest["testcase_protocol"]["ordered_payload_sha256"]
    )


def test_testcase_materialization_preserves_ordered_hash(tmp_path: Path):
    manifest = baseline.load_manifest()
    records = baseline._write_testcases(
        tmp_path / "testcases",
        manifest["testcase_protocol"]["ordered_payload_sha256"],
    )
    assert [item["name"] for item in records] == [f"t{index:02d}.testcase" for index in range(16)]
    assert all(len(bytes.fromhex(item["sha256"])) == 32 for item in records)


def test_probe_keeps_unsupported_rows_instead_of_omitting_them(monkeypatch):
    manifest = baseline.load_manifest()
    monkeypatch.setattr(baseline.platform, "system", lambda: "Linux")
    monkeypatch.setattr(baseline.platform, "machine", lambda: "aarch64")
    monkeypatch.setattr(baseline, "detect_qemu_emulation", lambda: False)
    monkeypatch.setattr(
        baseline,
        "_find_backend",
        lambda _valgrind, _prefix: (Path("/opt/timecop/valgrind"), Path("/opt/include")),
    )

    record = baseline.probe(
        manifest,
        baseline.DEFAULT_MANIFEST,
        valgrind="valgrind",
        prefix=None,
    )
    assert baseline.validate_result(record, manifest) == []
    assert len(record["rows"]) == 6
    by_tool = {
        tool_id: [row for row in record["rows"] if row["tool_id"] == tool_id]
        for tool_id in baseline.TOOL_ORDER
    }
    assert all(row["capability"]["status"] == "unsupported" for row in by_tool["official_dudect"])
    assert all(row["capability"]["status"] == "supported" for row in by_tool["timecop"])
    assert all(row["capability"]["status"] == "unsupported" for row in by_tool["microwalk_pin"])
    assert all(
        row["execution_status"] == "not-run"
        for rows in by_tool.values()
        for row in rows
        if row["capability"]["status"] == "unsupported"
    )


def test_result_validator_rejects_omission_and_fake_unsupported_execution():
    manifest = baseline.load_manifest()
    record = baseline.probe(
        manifest,
        baseline.DEFAULT_MANIFEST,
        valgrind="valgrind",
        prefix=None,
    )
    omitted = copy.deepcopy(record)
    omitted["rows"].pop()
    assert "result row coverage mismatch" in baseline.validate_result(omitted, manifest)

    forged = copy.deepcopy(record)
    unsupported = next(
        row for row in forged["rows"] if row["capability"]["status"] == "unsupported"
    )
    unsupported["execution_status"] = "completed"
    unsupported["outcome"] = "no-finding"
    errors = baseline.validate_result(forged, manifest)
    assert any("unsupported execution must be not-run" in error for error in errors)
    assert any("unsupported outcome must be not-run" in error for error in errors)


def test_microwalk_candidate_parser_counts_only_leakage_entries(tmp_path: Path):
    report = tmp_path / "call-stacks.txt"
    report.write_text(
        "target -> function\n"
        "  [L] target+0x10 (jump)\n"
        "    - Number of calls: 1\n"
        "  [L] target+0x20 (memory access)\n",
        encoding="utf-8",
    )
    assert baseline._microwalk_candidates(report) == 2


def test_process_streams_are_retained_separately(tmp_path: Path):
    result = subprocess.CompletedProcess(["tool"], 0, stdout="out\n", stderr="err\n")
    hashes = baseline._write_process_streams(tmp_path, "tool", result, None)
    assert (tmp_path / "tool.stdout").read_text(encoding="utf-8") == "out\n"
    assert (tmp_path / "tool.stderr").read_text(encoding="utf-8") == "err\n"
    assert (tmp_path / "tool.timeout").read_text(encoding="utf-8") == ""
    assert set(hashes) == {"stdout_sha256", "stderr_sha256", "timeout_sha256"}


def test_compiled_artifact_is_made_host_readable(tmp_path: Path):
    binary = tmp_path / "artifact"
    binary.write_bytes(b"binary")
    binary.chmod(0o711)

    baseline._make_artifact_readable(binary)

    assert binary.stat().st_mode & 0o777 == 0o755


def test_docker_timeout_decodes_streams_and_cleans_named_container(monkeypatch):
    calls: list[list[str]] = []

    def fake_run(command, **_kwargs):
        calls.append(command)
        if command[:2] == ["docker", "run"]:
            raise subprocess.TimeoutExpired(
                command,
                timeout=3,
                output=b"partial stdout\n",
                stderr=b"partial stderr\n",
            )
        return subprocess.CompletedProcess(command, 0, stdout="removed\n", stderr="")

    monkeypatch.setattr(baseline.subprocess, "run", fake_run)
    result, _elapsed, timeout_output = baseline._docker_run(
        ["docker", "run", "--name", "ctkat-microwalk-test", "image"],
        timeout=3,
        cleanup_container="ctkat-microwalk-test",
    )

    assert result is None
    assert timeout_output == "partial stdout\npartial stderr\nremoved\n"
    assert calls[-1] == ["docker", "rm", "--force", "ctkat-microwalk-test"]


def test_docker_timeout_reports_cleanup_failure_without_losing_evidence(monkeypatch):
    def fake_run(command, **_kwargs):
        if command[:2] == ["docker", "run"]:
            raise subprocess.TimeoutExpired(command, timeout=3, output=b"partial\n")
        raise OSError("daemon unavailable")

    monkeypatch.setattr(baseline.subprocess, "run", fake_run)
    result, _elapsed, timeout_output = baseline._docker_run(
        ["docker", "run", "--name", "ctkat-microwalk-test", "image"],
        timeout=3,
        cleanup_container="ctkat-microwalk-test",
    )

    assert result is None
    assert timeout_output is not None
    assert "partial\n" in timeout_output
    assert "container cleanup failed: daemon unavailable" in timeout_output


def test_result_schema_is_valid_json_and_matches_manual_contract():
    schema = json.loads(baseline.DEFAULT_SCHEMA.read_text(encoding="utf-8"))
    assert schema["properties"]["schema_version"]["const"] == "1.0"
    required = set(schema["$defs"]["row"]["required"])
    assert {
        "candidate_count",
        "reviewed_concern_count",
        "human_triage_minutes",
        "reviewer_agreement",
        "disposition_stability",
    } <= required


def test_manifest_hash_drift_fails_closed():
    manifest = baseline.load_manifest()
    tampered = copy.deepcopy(manifest)
    tampered["source_snapshot"]["implementation"]["sha256"] = "0" * 64
    errors = baseline.validate_static(tampered)
    assert any("implementation sha256 drift" in error for error in errors)
