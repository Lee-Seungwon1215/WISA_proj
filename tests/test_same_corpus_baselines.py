"""Regression tests for the same-corpus baseline contract and adapters."""

from __future__ import annotations

import copy
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

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
        "collect_timing_environment",
        lambda **_kwargs: {
            "cpu_model": "Example ARM CPU",
            "hostname": "example-host",
            "machine_id_sha256": "1" * 64,
            "boot_id_sha256": "2" * 64,
            "timing_cpu_flags": {
                "constant_tsc": True,
                "nonstop_tsc": True,
                "rdtscp": True,
            },
            "cpu_affinity": [2],
            "governor": "performance",
        },
    )
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


def test_microwalk_pin_notifications_survive_optimized_builds():
    wrapper = (baseline.ROOT / "examples/toy_kem_ct_leak/microwalk/main.c").read_text(
        encoding="utf-8"
    )
    assert '#define CTKAT_PIN_NOTIFY_BARRIER() __asm__ __volatile__("" ::: "memory")' in wrapper
    assert wrapper.count("CTKAT_PIN_NOTIFY_BARRIER();") == 4
    assert wrapper.count("__attribute__((noinline, used)) int PinNotify") == 4


def test_microwalk_marker_preflight_requires_direct_calls():
    disassembly = """
      1200: e8 00 00 00 00 call 1300 <PinNotifyTestcaseStart>
      1210: e8 00 00 00 00 callq 1400 <PinNotifyTestcaseEnd>
      1300 <PinNotifyStackPointer>:
      1410: e8 00 00 00 00 call 1500 <PinNotifyAllocation>
    """
    calls = baseline._microwalk_marker_calls(disassembly)
    assert calls == {
        "PinNotifyTestcaseStart": True,
        "PinNotifyTestcaseEnd": True,
        "PinNotifyStackPointer": False,
        "PinNotifyAllocation": True,
    }


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
    assert schema["properties"]["schema_version"]["const"] == "2.0"
    required = set(schema["$defs"]["row"]["required"])
    assert {
        "candidate_count",
        "reviewed_concern_count",
        "human_triage_minutes",
        "reviewer_agreement",
        "disposition_stability",
    } <= required
    timecop_required = set(schema["$defs"]["timecopEvidence"]["required"])
    assert {
        "compile_argv",
        "compile_workdir",
        "source_sha256",
        "linked_sources",
        "finding_signatures",
    } <= timecop_required
    assert schema["properties"]["backend"]["properties"]["compiler_identity"] == {
        "$ref": "#/$defs/compilerIdentity"
    }


def test_manifest_hash_drift_fails_closed():
    manifest = baseline.load_manifest()
    tampered = copy.deepcopy(manifest)
    tampered["source_snapshot"]["implementation"]["sha256"] = "0" * 64
    errors = baseline.validate_static(tampered)
    assert any("implementation sha256 drift" in error for error in errors)


def _promotable_record(manifest, tool_id):
    record = baseline.probe(
        manifest,
        baseline.DEFAULT_MANIFEST,
        valgrind="valgrind",
        prefix=None,
    )
    coverage = baseline._coverage_map(manifest)
    rows = []
    for case_id in baseline.CASE_ORDER:
        row = baseline._base_row(
            manifest,
            case_id,
            tool_id,
            ("supported", "unit fixture"),
        )
        expected = coverage[(case_id, tool_id)]["expected_outcome"]
        row.update(
            {
                "execution_status": "completed",
                "outcome": expected,
                "known_issue_match": True,
                "candidate_count": 1 if expected == "finding" else 0,
                "runtime_seconds": 0.1,
                "peak_memory_kib": 1,
                "artifact_bytes": 1,
            }
        )
        rows.append(row)
    record.update(
        {
            "run_kind": "final",
            "human_review_gate": {},
            "tool_id": tool_id,
            "git_dirty": False,
            "rows": rows,
            "promotion_ready": True,
            "errors": [],
            "host": {
                "system": "Linux",
                "machine": "x86_64",
                "timing_evidence": tool_id == "official_dudect",
                "cpu_model": "Unit Test CPU",
                "machine_id_sha256": "1" * 64,
                "boot_id_sha256": "2" * 64,
                "cpu_affinity": [2],
                "governor": "performance",
                "virtualization": {"vm": "", "container": ""},
            },
        }
    )
    return record


def test_same_corpus_official_final_applies_full_raw_protocol_contract(
    tmp_path,
    monkeypatch,
):
    manifest = baseline.load_manifest()
    record = _promotable_record(manifest, "official_dudect")
    monkeypatch.setattr(
        baseline,
        "_validate_human_premeasurement_gate",
        lambda *_args, **_kwargs: [],
    )
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    trace_hashes = {}
    for filename, field in (
        ("dudect_raw_timings.csv", "raw_trace_sha256"),
        ("dudect_calibration_timings.csv", "calibration_trace_sha256"),
        ("dudect_protocol_timings.csv", "protocol_trace_sha256"),
    ):
        path = raw_dir / filename
        path.write_text("unit fixture\n", encoding="utf-8")
        trace_hashes[field] = baseline._sha256(path)
    source_config = baseline.load_config(
        baseline._repo_path(
            manifest["source_snapshot"]["config"]["path"],
            "source_snapshot.config",
        )
    )
    harnesses = []
    for row, harness in zip(record["rows"], ("leaky", "safe"), strict=True):
        raw_status = "FAIL" if harness == "leaky" else "PASS"
        row["evidence"] = {
            "raw_status": raw_status,
            "timing_validity": "valid",
            "abs_t_score": 11.0 if harness == "leaky" else 1.0,
            "n0": 25000,
            "n1": 25000,
            "analysis_seed": 123 + len(harnesses),
            "raw_sample_count": 50000,
        }
        harnesses.append(
            {
                "harness": harness,
                **row["evidence"],
            }
        )
    raw_report = {
        "schema_version": "2.0",
        "kind": "timing-backend-report",
        "project": source_config.project.name,
        "official_dudect_revision": baseline.OFFICIAL_DUDECT_REVISION,
        **trace_hashes,
        "harnesses": harnesses,
    }
    raw_report_path = raw_dir / "dudect_backend_report.json"
    raw_report_path.write_text(json.dumps(raw_report), encoding="utf-8")
    record["backend"] = {
        "raw_report": "raw/dudect_backend_report.json",
        "raw_report_sha256": baseline._sha256(raw_report_path),
    }
    observed_contracts = []

    def reject_forged_controls(**kwargs):
        observed_contracts.append(kwargs["protocol_contract"])
        return SimpleNamespace(
            errors=["positive-control raw trace contradicts claimed pass"],
            analyses={},
            analysis_traces={},
        )

    monkeypatch.setattr(
        baseline,
        "verify_official_dudect_artifacts",
        reject_forged_controls,
    )

    errors = baseline.validate_result(record, manifest, artifact_root=tmp_path)

    assert any("positive-control raw trace" in error for error in errors)
    assert len(observed_contracts) == 1
    contract = observed_contracts[0]
    assert contract.base_seed == 0xC0FFEE
    assert contract.process_repeats == 3
    assert contract.target_measurements == 50000
    assert contract.control_measurements == 50000
    assert contract.positive_effects == (32, 128, 512)


_BRANCH_FINDING_LOG = (
    "==77== Conditional jump or move depends on uninitialised value(s)\n"
    "==77==    at 0x401234: LEAKY_crypto_kem_dec (toy_kem.c:41)\n"
    "==77==  Uninitialised value was created by a client request\n"
    "==77==    at 0x400100: main (harness.c:61)\n"
    "==77== \n"
)
_VARIABLE_LATENCY_LOG = (
    "==88== Variable-latency instruction operand of size 4 is secret/uninitialised\n"
    "==88==    at 0x401234: canary_division (canary.c:11)\n"
    "==88==  Uninitialised value was created by a client request\n"
    "==88==    at 0x400100: main (canary.c:8)\n"
    "==88== \n"
)


def _write_text(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")
    return baseline._sha256(path)


def _timecop_final_fixture(tmp_path, manifest):
    record = _promotable_record(manifest, "timecop")
    prefix = (tmp_path / "pinned-timecop").resolve()
    executable = prefix / "bin/valgrind"
    patched_include = prefix / "include"
    patched_header = patched_include / "valgrind/memcheck.h"
    executable.parent.mkdir(parents=True)
    executable.write_text(
        '#!/bin/sh\nif [ "$1" = "--version" ]; then echo valgrind-3.22.0; exit 0; fi\nexit 2\n',
        encoding="utf-8",
    )
    executable.chmod(0o755)
    _write_text(
        patched_header,
        "#ifndef CTKAT_FAKE_MEMCHECK_H\n"
        "#define CTKAT_FAKE_MEMCHECK_H\n"
        "#define VALGRIND_ENABLE_TIMECOP_MODE ((void)0)\n"
        "#define VALGRIND_MAKE_MEM_UNDEFINED(p,n) ((void)(p), (void)(n))\n"
        "#define VALGRIND_MAKE_MEM_DEFINED(p,n) ((void)(p), (void)(n))\n"
        "#endif\n",
    )
    compiler_name = baseline.os.environ.get("CC", "gcc")
    compiler_raw = baseline.shutil.which(compiler_name)
    assert compiler_raw is not None
    compiler = Path(compiler_raw).absolute()
    compiler_identity = baseline._compiler_identity(compiler_name, compiler)
    config_path = baseline._repo_path(
        manifest["source_snapshot"]["config"]["path"],
        "source_snapshot.config",
    )
    config = baseline.load_config(config_path)
    assert config.ct is not None
    config_dir = config_path.parent.resolve()
    configured = {item.name: item for item in config.ct.harnesses}
    for row in record["rows"]:
        case_id = row["case_id"]
        harness = "leaky" if case_id.endswith("leaky") else "safe"
        configured_harness = configured[harness]
        case_dir = tmp_path / case_id
        source = case_dir / f"harness_{harness}.c"
        binary = case_dir / f"harness_{harness}"
        case_dir.mkdir(parents=True)
        source.write_text(
            baseline.render_harness(
                configured_harness.template or "",
                baseline._template_context(
                    configured_harness,
                    config.ct.seed,
                    timecop_mode=True,
                ),
            ),
            encoding="utf-8",
        )
        includes = [
            patched_include,
            *((config_dir / path).resolve() for path in configured_harness.include_dirs),
        ]
        sources = [(config_dir / path).resolve() for path in configured_harness.sources]
        cflags = list(
            configured_harness.cflags if configured_harness.cflags is not None else config.ct.cflags
        )
        compile_command = baseline.compile_harness(
            source,
            binary,
            sources,
            includes,
            cflags,
            config_dir,
            timeout=60,
            cc=str(compiler),
        )
        log = case_dir / "timecop.valgrind.log"
        log_text = _BRANCH_FINDING_LOG if harness == "leaky" else ""
        log.write_text(log_text, encoding="utf-8")
        stdout = case_dir / "timecop.stdout"
        stderr = case_dir / "timecop.stderr"
        stdout.write_text("unit\n", encoding="utf-8")
        stderr.write_text("", encoding="utf-8")
        findings, dropped = baseline.parse_valgrind_log_with_stats(log_text)
        returncode = 99 if findings else 0
        row["candidate_count"] = len(findings)
        row["evidence"] = {
            "compile_command": compile_command,
            "compile_argv": baseline._compile_argv_contract(
                compiler=compiler,
                source=source,
                binary=binary,
                sources=sources,
                include_dirs=includes,
                cflags=cflags,
            ),
            "compile_workdir": str(config_dir.relative_to(baseline.ROOT)),
            "source_sha256": baseline._sha256(source),
            "linked_sources": baseline._linked_source_records(sources),
            "argv": [
                str(executable),
                "--tool=memcheck",
                "--error-exitcode=99",
                f"--log-file={log}",
                str(binary),
            ],
            "returncode": returncode,
            "timed_out": False,
            "binary_sha256": baseline._sha256(binary),
            "log_sha256": baseline._sha256(log),
            "stdout_sha256": baseline._sha256(stdout),
            "stderr_sha256": baseline._sha256(stderr),
            "dropped_valgrind_messages": dropped,
            "findings": [baseline._serialize_finding(item) for item in findings],
            "finding_signatures": baseline._stable_finding_signatures(findings),
            "evidence_boundary": "unit",
            "peak_memory_scope": "unit",
        }

    canary_dir = tmp_path / "backend_canary"
    canary_source = canary_dir / "canary.c"
    canary_binary = canary_dir / "canary"
    canary_log = canary_dir / "canary.valgrind.log"
    canary_stdout = canary_dir / "canary.stdout"
    canary_stderr = canary_dir / "canary.stderr"
    _write_text(canary_source, baseline.CANARY_SOURCE)
    canary_cflags = ["-std=c99", "-O2", "-g", "-fno-omit-frame-pointer", "-fno-lto"]
    canary_compile_command = baseline.compile_harness(
        canary_source,
        canary_binary,
        [],
        [patched_include],
        canary_cflags,
        baseline.ROOT,
        timeout=60,
        cc=str(compiler),
    )
    _write_text(canary_log, _VARIABLE_LATENCY_LOG)
    _write_text(canary_stdout, "CTKAT-TIMECOP-CANARY:123\n")
    _write_text(canary_stderr, "")
    canary_findings, canary_dropped = baseline.parse_valgrind_log_with_stats(_VARIABLE_LATENCY_LOG)
    variable_latency = [
        item
        for item in canary_findings
        if item.type == baseline.FindingType.SECRET_DEPENDENT_VARIABLE_LATENCY
    ]
    record["backend"] = {
        "prefix": str(prefix),
        "executable": str(executable),
        "patched_include": str(patched_include),
        "executable_sha256": baseline._sha256(executable),
        "patched_header_sha256": baseline._sha256(patched_header),
        "version": "valgrind-3.22.0",
        "compiler": str(compiler),
        "compiler_version": str(compiler_identity["version_stdout"]).splitlines()[0],
        "compiler_identity": compiler_identity,
        "canary": {
            "passed": True,
            "compile_command": canary_compile_command,
            "compile_argv": baseline._compile_argv_contract(
                compiler=compiler,
                source=canary_source,
                binary=canary_binary,
                sources=[],
                include_dirs=[patched_include],
                cflags=canary_cflags,
            ),
            "argv": [
                "/opt/timecop/valgrind",
                "--tool=memcheck",
                "--error-exitcode=99",
                f"--log-file={canary_log}",
                str(canary_binary),
            ],
            "runtime_seconds": 0.1,
            "returncode": 99,
            "timed_out": False,
            "finding_count": len(variable_latency),
            "dropped_valgrind_messages": canary_dropped,
            "finding_signatures": baseline._stable_finding_signatures(canary_findings),
            "source_sha256": baseline._sha256(canary_source),
            "binary_sha256": baseline._sha256(canary_binary),
            "log_sha256": baseline._sha256(canary_log),
            "stdout_sha256": baseline._sha256(canary_stdout),
            "stderr_sha256": baseline._sha256(canary_stderr),
        },
    }
    return record


def _allow_pinned_timecop_backend(record, monkeypatch):
    backend = record["backend"]
    executable = Path(backend["executable"])
    patched_include = Path(backend["patched_include"])
    monkeypatch.setattr(
        baseline,
        "_find_backend",
        lambda _valgrind, _prefix: (executable, patched_include),
    )

    def deterministic_run(_executable, binary, log_path, *, timeout):
        del timeout
        if binary.name == "canary":
            log_text = _VARIABLE_LATENCY_LOG
            stdout = "CTKAT-TIMECOP-CANARY:123\n"
            returncode = 99
        elif binary.name == "harness_leaky":
            log_text = _BRANCH_FINDING_LOG
            stdout = "unit\n"
            returncode = 99
        else:
            log_text = ""
            stdout = "unit\n"
            returncode = 0
        log_path.write_text(log_text, encoding="utf-8")
        result = baseline.ValgrindResult(
            returncode=returncode,
            log_path=log_path,
            stdout=stdout,
            stderr="",
        )
        argv = [
            str(executable),
            "--tool=memcheck",
            "--track-origins=yes",
            "--leak-check=no",
            "--error-exitcode=99",
            f"--log-file={log_path}",
            str(binary),
        ]
        return result, argv, 0.01

    monkeypatch.setattr(baseline, "_run_valgrind", deterministic_run)


def test_timecop_final_validation_derives_rows_and_canary_from_raw(
    tmp_path,
    monkeypatch,
):
    manifest = baseline.load_manifest()
    monkeypatch.setattr(
        baseline,
        "_validate_human_premeasurement_gate",
        lambda *_args, **_kwargs: [],
    )
    record = _timecop_final_fixture(tmp_path, manifest)
    _allow_pinned_timecop_backend(record, monkeypatch)

    assert baseline.validate_result(record, manifest, artifact_root=tmp_path) == []


def test_timecop_true_flag_and_rehashed_empty_canary_cannot_promote(
    tmp_path,
    monkeypatch,
):
    manifest = baseline.load_manifest()
    monkeypatch.setattr(
        baseline,
        "_validate_human_premeasurement_gate",
        lambda *_args, **_kwargs: [],
    )
    record = _timecop_final_fixture(tmp_path, manifest)
    _allow_pinned_timecop_backend(record, monkeypatch)
    canary_log = tmp_path / "backend_canary/canary.valgrind.log"
    canary_log.write_text("", encoding="utf-8")
    canary = record["backend"]["canary"]
    canary["log_sha256"] = baseline._sha256(canary_log)
    canary["finding_count"] = 0

    errors = baseline.validate_result(record, manifest, artifact_root=tmp_path)
    assert any("canary pass flag differs from raw" in error for error in errors)


def test_timecop_row_outcome_cannot_disagree_with_rehashed_raw_findings(
    tmp_path,
    monkeypatch,
):
    manifest = baseline.load_manifest()
    monkeypatch.setattr(
        baseline,
        "_validate_human_premeasurement_gate",
        lambda *_args, **_kwargs: [],
    )
    record = _timecop_final_fixture(tmp_path, manifest)
    _allow_pinned_timecop_backend(record, monkeypatch)
    row = next(item for item in record["rows"] if item["case_id"].endswith("leaky"))
    log = tmp_path / row["case_id"] / "timecop.valgrind.log"
    log.write_text("", encoding="utf-8")
    row["candidate_count"] = 0
    row["evidence"].update(
        {
            "returncode": 0,
            "log_sha256": baseline._sha256(log),
            "dropped_valgrind_messages": 0,
            "findings": [],
        }
    )

    errors = baseline.validate_result(record, manifest, artifact_root=tmp_path)
    assert any("TIMECOP outcome mismatch raw findings" in error for error in errors)


def test_timecop_rehashed_generated_source_cannot_replace_frozen_harness(
    tmp_path,
    monkeypatch,
):
    manifest = baseline.load_manifest()
    monkeypatch.setattr(
        baseline,
        "_validate_human_premeasurement_gate",
        lambda *_args, **_kwargs: [],
    )
    record = _timecop_final_fixture(tmp_path, manifest)
    _allow_pinned_timecop_backend(record, monkeypatch)
    row = next(item for item in record["rows"] if item["case_id"].endswith("leaky"))
    source = tmp_path / row["case_id"] / "harness_leaky.c"
    source.write_text(source.read_text(encoding="utf-8") + "\n/* forged */\n", encoding="utf-8")
    row["evidence"]["source_sha256"] = baseline._sha256(source)

    errors = baseline.validate_result(record, manifest, artifact_root=tmp_path)

    assert any("preserved harness source is not reproducible" in error for error in errors)


def test_timecop_self_consistent_forged_log_fails_fresh_rerun(
    tmp_path,
    monkeypatch,
):
    manifest = baseline.load_manifest()
    monkeypatch.setattr(
        baseline,
        "_validate_human_premeasurement_gate",
        lambda *_args, **_kwargs: [],
    )
    record = _timecop_final_fixture(tmp_path, manifest)
    _allow_pinned_timecop_backend(record, monkeypatch)
    row = next(item for item in record["rows"] if item["case_id"].endswith("leaky"))
    log = tmp_path / row["case_id"] / "timecop.valgrind.log"
    forged_log = _BRANCH_FINDING_LOG.replace("LEAKY_crypto_kem_dec", "FORGED_crypto_kem_dec")
    log.write_text(forged_log, encoding="utf-8")
    findings, dropped = baseline.parse_valgrind_log_with_stats(forged_log)
    row["evidence"].update(
        {
            "log_sha256": baseline._sha256(log),
            "dropped_valgrind_messages": dropped,
            "findings": [baseline._serialize_finding(item) for item in findings],
            "finding_signatures": baseline._stable_finding_signatures(findings),
        }
    )

    errors = baseline.validate_result(record, manifest, artifact_root=tmp_path)

    assert any("fresh findings differ from preserved raw log" in error for error in errors)


def test_timecop_compiler_identity_hash_tamper_fails_closed(tmp_path, monkeypatch):
    manifest = baseline.load_manifest()
    monkeypatch.setattr(
        baseline,
        "_validate_human_premeasurement_gate",
        lambda *_args, **_kwargs: [],
    )
    record = _timecop_final_fixture(tmp_path, manifest)
    _allow_pinned_timecop_backend(record, monkeypatch)
    record["backend"]["compiler_identity"]["sha256"] = "0" * 64

    errors = baseline.validate_result(record, manifest, artifact_root=tmp_path)

    assert any("compiler identity executable hash drift" in error for error in errors)


def _stream_hashes(case_dir, stem):
    return {
        f"{suffix}_sha256": _write_text(case_dir / f"{stem}.{suffix}", "")
        for suffix in ("stdout", "stderr", "timeout")
    }


def _microwalk_final_fixture(tmp_path, manifest):
    record = _promotable_record(manifest, "microwalk_pin")
    for row in record["rows"]:
        case_id = row["case_id"]
        harness = "leaky" if case_id.endswith("leaky") else "safe"
        target_name = f"target-toy-kem-{harness}"
        case_dir = tmp_path / case_id
        case_dir.mkdir(parents=True)
        binary = case_dir / target_name
        map_path = case_dir / f"{target_name}.map"
        binary.write_bytes(b"ELF-unit")
        map_path.write_text("map\n", encoding="utf-8")
        testcase_records = baseline._write_testcases(
            case_dir / "testcases",
            manifest["testcase_protocol"]["ordered_payload_sha256"],
        )
        result_path = case_dir / "results/call-stacks.txt"
        _write_text(
            result_path,
            "  [L] target+0x10 (jump)\n" if harness == "leaky" else "no leaks\n",
        )
        count = baseline._microwalk_candidates(result_path)
        row["candidate_count"] = count
        row["evidence"] = {
            "build_argv": ["docker", "build"],
            "marker_argv": ["docker", "markers"],
            "map_argv": ["docker", "map"],
            "run_argv": ["docker", "run"],
            "build_streams": _stream_hashes(case_dir, "build"),
            "marker_streams": _stream_hashes(case_dir, "markers"),
            "map_streams": _stream_hashes(case_dir, "map"),
            "run_streams": _stream_hashes(case_dir, "microwalk"),
            "marker_calls": {marker: True for marker in baseline.MICROWALK_MARKERS},
            "returncode": 0,
            "binary_sha256": baseline._sha256(binary),
            "map_sha256": baseline._sha256(map_path),
            "testcases": testcase_records,
            "result_sha256": baseline._sha256(result_path),
            "evidence_boundary": "unit",
        }
    record["backend"] = {"execution_image": "unit"}
    return record


def test_microwalk_outcome_is_rederived_from_rehashed_raw_result(
    tmp_path,
    monkeypatch,
):
    manifest = baseline.load_manifest()
    monkeypatch.setattr(
        baseline,
        "_validate_human_premeasurement_gate",
        lambda *_args, **_kwargs: [],
    )
    record = _microwalk_final_fixture(tmp_path, manifest)
    row = next(item for item in record["rows"] if item["case_id"].endswith("leaky"))
    result_path = tmp_path / row["case_id"] / "results/call-stacks.txt"
    result_path.write_text("no leaks\n", encoding="utf-8")
    row["candidate_count"] = 0
    row["evidence"]["result_sha256"] = baseline._sha256(result_path)

    errors = baseline.validate_result(record, manifest, artifact_root=tmp_path)
    assert any("MicroWalk outcome mismatch raw result" in error for error in errors)
