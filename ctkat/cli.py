import csv
import math
import platform
import re
import secrets
import shutil
import subprocess
from pathlib import Path
from statistics import NormalDist
from typing import Dict, List, Optional, Tuple

import typer
import yaml
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from . import __version__
from .asm_scan import (
    DEFAULT_OPT_LEVELS,
    AsmScanError,
    extract_opt_level,
    scan_harness,
    write_varlat_csv,
    write_varlat_json,
)
from .builder import run_step
from .config import (
    CtkatConfig,
    DudectConfig,
    DudectHarnessConfig,
    HarnessConfig,
    MatrixConfig,
    load_config,
    resolve_clock,
)
from .coverage_check import check_secret_region_coverage
from .ct_matrix import (
    HarnessInputs,
    expand_combos,
    preprocessor_cflags,
    scan_ct_matrix,
    write_ct_matrix_csv,
    write_ct_matrix_json,
)
from .ct_runner import MAX_VALGRIND_LOG_BYTES, classify_valgrind_run
from .dudect_runner import (
    TimingProtocolTrace,
    TimingSamples,
    run_timing_harness,
    signature_trace_contract_errors,
)
from .evidence import SCHEMA_VERSION, Overall
from .harness_generator import (
    CompilerNotFoundError,
    HarnessGenerationError,
    _atomic_write_text,
    generate_and_compile,
    render_harness,
)
from .header_parser import (
    discover_headers,
    parse_header_file_with_stats,
)
from .official_dudect import (
    OFFICIAL_DUDECT_BACKEND,
    OFFICIAL_DUDECT_REVISION,
    OfficialDudectAnalysis,
    OfficialDudectError,
    analyze_with_official_dudect,
    build_official_dudect_adapter,
)
from .qemu_detect import detect_qemu_emulation
from .report import finding_to_row, write_csv, write_json
from .secret_infer import InferredFunction, infer_functions
from .statistics import (
    CROP_PERCENTILES,
    EXPERIMENTAL_FIRST_ORDER_BACKEND,
    WelchResult,
    batch_t_scores,
    welch_t_test,
    welch_with_cropping,
)
from .timing_binary_contract import (
    TimingBinaryContractError,
    verify_timing_binary_contract,
)
from .timing_build_provenance import (
    TimingBuildProvenanceError,
    assert_timing_build_seal_unchanged,
    capture_timing_build_provenance,
    write_timing_build_provenance,
)
from .timing_environment import collect_timing_environment
from .timing_harness_generator import generate_and_compile_timing
from .timing_input_contract import (
    build_operand_v3_input_contract,
    build_valid_tuple_input_contract,
    validate_operand_v3_protocol,
    validate_valid_tuple_protocol,
)
from .triage import TriageConfig, load_triage
from .valgrind_parser import Finding, parse_valgrind_log_with_stats
from .valgrind_runner import run_valgrind
from .verdict import VERDICT_STYLES, HarnessVerdict, Verdict, combine
from .verdict_class import load_registry, opt_of, summarize

app = typer.Typer(help="CT-KAT: KAT + Valgrind based constant-time check framework")
console = Console()
_CALIBRATION_SEED_DOMAIN = 0x9E3779B97F4A7C15
_UINT64_MASK = 0xFFFFFFFFFFFFFFFF


def _fmt(x: Optional[float], digits: int = 3) -> str:
    """CSV-safe float formatting: None and non-finite values become empty so
    pandas/R don't have to special-case the literal strings 'None' / 'inf' /
    'nan'. The accompanying `status` column already carries the information
    that a measurement blew up (it'll be FAIL whenever t_score is infinite).

    `None` is accepted because diagnostic fields (e.g. cropping cutoff when
    cropping was disabled via --no-crop) can be absent."""
    if x is None or not math.isfinite(x):
        return ""
    return f"{x:.{digits}f}"


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def _main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the installed CT-KAT version and exit.",
    ),
) -> None:
    """CT-KAT command-line entry point."""


def _resolve(base: Path, p: Path) -> Path:
    return p if p.is_absolute() else (base / p).resolve()


def _load_config_or_exit(config: Path) -> CtkatConfig:
    """Load + validate the yaml, mapping every load-time failure to a clean
    exit-2 'config/toolchain error' instead of a raw Python traceback.

    Bundle Q (FN-2): every subcommand called `load_config(config)` bare, so the
    single most common user mistake — a typo'd `--config` path, or a yaml field
    out of bounds — escaped as a rich traceback + exit 1. That is inconsistent
    with this project's own convention (objdump-missing, no-`dudect`-section,
    empty-matrix all exit 2 with a red message) AND breaks CI gating that keys
    'exit 2 == config error'. We funnel the five things `load_config` can raise
    (missing/unreadable/dir path, malformed YAML, non-mapping root, pydantic
    ValidationError) into one clean exit 2.
    """
    try:
        cfg = load_config(config)
    except FileNotFoundError:
        console.print(
            f"[bold red][CTKAT] config file not found:[/] {config}. "
            "Check the --config path. (exit 2)"
        )
        raise typer.Exit(2)
    except (IsADirectoryError, PermissionError, NotADirectoryError) as e:
        console.print(f"[bold red][CTKAT] config file not readable:[/] {config} — {e}. (exit 2)")
        raise typer.Exit(2)
    except yaml.YAMLError as e:
        console.print(
            f"[bold red][CTKAT] config is not valid YAML:[/] {config}\n{e}\n"
            "Fix the YAML syntax. (exit 2)"
        )
        raise typer.Exit(2)
    except (ValidationError, ValueError) as e:
        console.print(
            f"[bold red][CTKAT] invalid config:[/] {config}\n{e}\n"
            "Fix the offending field(s). (exit 2)"
        )
        raise typer.Exit(2)
    shell_steps = []
    if cfg.build.command is not None:
        shell_steps.append(("build", cfg.build.allow_shell))
    if cfg.kat is not None and cfg.kat.command is not None:
        shell_steps.append(("kat", cfg.kat.allow_shell))
    for step, opted_in in shell_steps:
        if opted_in is True:
            console.print(
                f"[bold yellow][CTKAT] shell enabled:[/] {step}.command will "
                "run through the system shell because allow_shell=true."
            )
        else:
            console.print(
                f"[bold yellow][CTKAT] LEGACY SHELL CONFIG:[/] {step}.command "
                "runs through the system shell. Migrate to argv, or add "
                "allow_shell: true after reviewing the command. Legacy "
                "implicit shell execution will be rejected in 0.3."
            )
    return cfg


def _print_cflags_banner(cfg: CtkatConfig) -> None:
    """Print ct vs dudect cflags side-by-side; warn loudly when they differ.

    F9: ct stage defaults to `-O0` (Valgrind debug friendliness — analyzers
    need branches to stay branches) while dudect defaults to `-O2` (realistic
    production timing). That means a verdict CLEAN does NOT mean "this exact
    binary is constant-time" — the two stages compiled the same source with
    different optimization, so e.g. an `if (secret) ...` that becomes a
    branch at -O0 (and Valgrind FAILs it) may become a `cmov` at -O2 (and
    dudect PASSes it). The user has to know this to read the verdict
    correctly. Compared as sets so cflag reordering doesn't false-positive.
    """
    if cfg.ct is None or cfg.dudect is None or not cfg.dudect.enabled:
        return
    ct_flags = list(cfg.ct.cflags)
    dud_flags = list(cfg.dudect.compiler.cflags)
    console.print(f"[dim]ct stage cflags    : {' '.join(ct_flags)}[/]")
    console.print(f"[dim]dudect stage cflags: {' '.join(dud_flags)}[/]")
    if set(ct_flags) != set(dud_flags):
        console.print(
            "[bold yellow][CTKAT] WARNING:[/] ct and dudect stages compile "
            "with different cflags — the two stages may analyze "
            "structurally different binaries (e.g., `-O0` keeps a branch "
            "that `-O2` turns into `cmov`). A combined verdict=CLEAN means "
            "'both stages clean on their own builds', NOT 'the binary you "
            "will ship is clean'. See README §컴파일 옵션 비대칭 경고."
        )


def _do_build(cfg: CtkatConfig, cfg_dir: Path) -> bool:
    """Run the user-supplied build command; verify expected artifacts exist.

    Bundle E-1 (F10): exit-code 0 is not enough — `build.command: "true"`
    will rc=0 forever and produce nothing. If `expected_artifacts` is set,
    every listed path must exist after the command finishes. Unset →
    legacy exit-code-only behavior with a one-time warning.
    """
    desc = cfg.build.command if cfg.build.command is not None else " ".join(cfg.build.argv or [])
    console.print(f"[bold cyan]==> Build[/]: {desc}")
    workdir = _resolve(cfg_dir, cfg.build.workdir)
    r = run_step(
        command=cfg.build.command,
        argv=cfg.build.argv,
        workdir=workdir,
        timeout=cfg.build.timeout,
    )
    if not r.ok:
        console.print("[bold red][CTKAT] Build: FAIL[/]")
        if r.stdout:
            console.print(r.stdout)
        if r.stderr:
            console.print(r.stderr)
        return False
    if cfg.build.expected_artifacts:
        missing = [p for p in cfg.build.expected_artifacts if not _resolve(workdir, p).exists()]
        if missing:
            console.print(
                "[bold red][CTKAT] Build: FAIL[/] — expected_artifacts "
                f"missing: {[str(p) for p in missing]}"
            )
            return False
    else:
        console.print(
            "[dim][CTKAT] note:[/dim] build.expected_artifacts unset — "
            "build validated by exit code only. Set the field in yaml to "
            "verify produced files exist (see known_issues F10)."
        )
    console.print("[green][CTKAT] Build: PASS[/]")
    return True


def _do_kat(cfg: CtkatConfig, cfg_dir: Path) -> Tuple[bool, Optional[int]]:
    """Run the user-supplied KAT command; verify reported test count.

    Returns `(success, count)`. `count` is the integer captured by
    `expected_pattern` (when the field was set and matched), else None.
    `run()` consumes both — the count is propagated into the verdict CSV
    as `kat_count` so a CI consumer can audit "how many vectors ran".

    Bundle E-1 (F1): exit-code 0 is not enough — a no-op runner can rc=0
    with zero tests executed and the framework would call that PASS. If
    `expected_min` is set, the regex `expected_pattern` must match in
    stdout and the captured count must be >= expected_min. Unset →
    legacy exit-code-only behavior with a one-time warning. KAT stdout
    is always echoed now (previously hidden on PASS) so the user sees
    the count their `expected_min` is checking against.
    """
    # Use raise rather than assert — `python -O` strips asserts and we don't
    # want a security tool's invariants disappearing in optimized builds.
    if cfg.kat is None:
        raise ValueError("_do_kat called with no `kat` section in config")
    desc = cfg.kat.command if cfg.kat.command is not None else " ".join(cfg.kat.argv or [])
    console.print(f"[bold cyan]==> KAT[/]: {desc}")
    workdir = _resolve(cfg_dir, cfg.kat.workdir)
    r = run_step(
        command=cfg.kat.command,
        argv=cfg.kat.argv,
        workdir=workdir,
        timeout=cfg.kat.timeout,
    )
    if r.stdout:
        console.print(r.stdout)
    if not r.ok:
        console.print("[bold red][CTKAT] KAT: FAIL[/]")
        if r.stderr:
            console.print(r.stderr)
        return False, None
    # Best-effort count extraction even when expected_min is unset, so the
    # verdict CSV's `kat_count` column carries useful diagnostic info
    # whenever the pattern happens to match.
    count: Optional[int] = None
    # F18: match with re.MULTILINE so the default anchored pattern
    # `^PASSED:?\s*(\d+)\s*$` only fires on a *standalone summary line*,
    # not on substring occurrences like "ERROR vector 50 differs. PASSED:
    # 100 prior". Anchored matching is the safe default in a security
    # tool; users who deliberately want anywhere-match can still set
    # `kat.expected_pattern` to an unanchored regex.
    m = re.search(cfg.kat.expected_pattern, r.stdout or "", re.MULTILINE)
    if m is not None:
        try:
            count = int(m.group(1))
        except (IndexError, ValueError):
            # T28: the pattern matched but the capture group is missing
            # (user override with no group → IndexError) or non-numeric
            # (`(\w+)` matched "abc" → ValueError). Previously this silently
            # left count=None; with expected_min unset that returns PASS with
            # no count, hiding a misconfigured pattern. Surface it loudly.
            # (IndexError is genuinely reachable here — the DEFAULT pattern
            # has a group, but `kat.expected_pattern` is user-overridable.)
            count = None
            console.print(
                "[bold yellow][CTKAT] note:[/] kat.expected_pattern "
                f"{cfg.kat.expected_pattern!r} matched, but its capture group "
                "is missing or non-numeric — no test count could be read. "
                "Use a pattern with a single numeric group like "
                r"'^PASSED:?\s*(\d+)'. (T28)"
            )
    if cfg.kat.expected_min is not None:
        if count is None:
            console.print(
                "[bold red][CTKAT] KAT: FAIL[/] — expected_pattern "
                f"{cfg.kat.expected_pattern!r} did not match stdout. "
                "Either the runner output format differs or KAT didn't "
                "actually report any test count."
            )
            return False, None
        if count < cfg.kat.expected_min:
            console.print(
                f"[bold red][CTKAT] KAT: FAIL[/] — ran {count} tests but "
                f"expected_min={cfg.kat.expected_min}."
            )
            return False, count
        console.print(
            f"[green][CTKAT] KAT: PASS[/] ({count} tests, expected >= {cfg.kat.expected_min})"
        )
        return True, count
    console.print(
        "[dim][CTKAT] note:[/dim] kat.expected_min unset — KAT validated by "
        "exit code only (a no-op runner passes). Set the field in yaml to "
        "require a minimum test count (see known_issues F1)."
    )
    console.print("[green][CTKAT] KAT: PASS[/]")
    return True, count


def _build_generic_context(h: HarnessConfig, seed: int, *, timecop_mode: bool = False) -> dict:
    return {
        "extra_headers": list(h.extra_headers),
        "function": h.function,
        "args": list(h.args),
        "return_type": h.return_type,
        "buffers": [b.model_dump() for b in h.buffers],
        "seed": seed,
        "timecop_mode": timecop_mode,
    }


def _build_kem_context(h: HarnessConfig, *, timecop_mode: bool = False) -> dict:
    return {
        "header": h.header,
        "extra_headers": list(h.extra_headers),
        "prefix": h.prefix,
        "secret_regions": [r.model_dump() for r in h.secret_regions],
        "kem_decapsulation": h.kem_decapsulation,
        "rejection_oracle_function": h.rejection_oracle_function,
        "rejection_seed_offset": h.rejection_seed_offset,
        "timecop_mode": timecop_mode,
    }


def _build_sign_context(h: HarnessConfig, *, timecop_mode: bool = False) -> dict:
    return {
        "header": h.header,
        "extra_headers": list(h.extra_headers),
        "prefix": h.prefix,
        "secret_regions": [r.model_dump() for r in h.secret_regions],
        "timecop_mode": timecop_mode,
    }


def _template_context(h: HarnessConfig, seed: int, *, timecop_mode: bool = False) -> dict:
    if h.template == "generic":
        return _build_generic_context(h, seed, timecop_mode=timecop_mode)
    if h.template == "kem":
        return _build_kem_context(h, timecop_mode=timecop_mode)
    if h.template == "sign":
        return _build_sign_context(h, timecop_mode=timecop_mode)
    raise ValueError(f"unknown template: {h.template!r}")


def _do_generate(cfg: CtkatConfig, cfg_dir: Path) -> Dict[str, Path]:
    """Render and compile any auto-mode harnesses. Returns name -> binary_path."""
    if cfg.ct is None:
        return {}
    ct_cwd = _resolve(cfg_dir, cfg.ct.workdir)
    generated_dir = _resolve(cfg_dir, cfg.ct.generated_dir)
    paths: Dict[str, Path] = {}

    auto_harnesses = [h for h in cfg.ct.harnesses if h.template is not None]
    if not auto_harnesses:
        return paths

    for h in auto_harnesses:
        template = h.template
        if template is None:
            # Kept fail-closed even though auto_harnesses filters this case.
            raise ValueError(f"auto harness {h.name!r} has no template")
        console.print(f"[bold cyan]==> Generate[/]: harness=[bold]{h.name}[/] template={template}")
        include_dirs = [_resolve(cfg_dir, d) for d in h.include_dirs]
        sources = [_resolve(cfg_dir, s) for s in h.sources]
        cflags = h.cflags if h.cflags is not None else cfg.ct.cflags
        try:
            result = generate_and_compile(
                name=h.name,
                template=template,
                context=_template_context(
                    h,
                    cfg.ct.seed,
                    timecop_mode=cfg.ct.timecop_mode,
                ),
                output_dir=generated_dir,
                sources=sources,
                include_dirs=include_dirs,
                cflags=cflags,
                workdir=ct_cwd,
                timeout=cfg.ct.compile_timeout,
            )
        except CompilerNotFoundError as e:
            # FN-5(exit-code): a missing/non-exec compiler is a toolchain error
            # → exit 2, matching asm-scan / ct-matrix, not exit 1 (real compile
            # failure) below.
            console.print(
                f"[bold red][CTKAT] Harness generation FAIL ({h.name})[/] — toolchain error"
            )
            console.print(str(e))
            raise typer.Exit(2)
        except HarnessGenerationError as e:
            console.print(f"[bold red][CTKAT] Harness generation FAIL ({h.name})[/]")
            console.print(str(e))
            raise typer.Exit(1)
        console.print(
            f"   [dim]source: {result.source_path}[/]\n   [dim]binary: {result.binary_path}[/]"
        )
        paths[h.name] = result.binary_path

        # F6: cross-check secret_regions coverage against the framework's
        # expected total (CRYPTO_SECRETKEYBYTES). Only meaningful when the
        # user actually specified secret_regions (otherwise full-sk taint is
        # applied and there's nothing to verify). kem/sign templates only —
        # generic has no canonical "sk" notion.
        if h.template in ("kem", "sign") and h.secret_regions and h.header is not None:
            check_secret_region_coverage(
                harness_name=h.name,
                header=h.header,
                extra_headers=list(h.extra_headers),
                prefix=h.prefix,
                secret_region_lengths=[r.length for r in h.secret_regions],
                # F21: pass offsets too so the probe can flag out-of-bounds
                # regions (offset+length past CRYPTO_SECRETKEYBYTES).
                secret_region_offsets=[r.offset for r in h.secret_regions],
                include_dirs=include_dirs,
                workdir=ct_cwd,
                # T17: forward `-D`/`-U`/`-isystem`/`-iquote` from the
                # harness's effective cflags so the probe sees the same
                # preprocessor state the real harness will.
                extra_compile_args=cflags,
            )
    return paths


def _do_ct(
    cfg: CtkatConfig,
    cfg_dir: Path,
    generated: Dict[str, Path],
) -> List[Tuple[str, str, List[Finding]]]:
    """Run Valgrind on each ct harness; return per-harness (name, status,
    findings).

    `status` ∈ {"PASS", "FAIL", "ERROR"}:
      - PASS  — valgrind ran cleanly, no findings
      - FAIL  — valgrind reported one or more findings
      - ERROR — analysis didn't complete (Bundle E-2):
          F2: returncode not in {0, 99} (harness crash / valgrind itself
              failed), or the log file is missing — previously these
              silently parsed as zero findings → PASS → CLEAN verdict.
          F5: manual-binary harness whose stdout doesn't contain
              `ct.sentinel_pattern` and `ct.require_sentinel=True` — a
              binary that pointed at /bin/true would otherwise PASS
              without ever calling the target function.

    ERROR flows through `_compute_verdicts` → verdict.combine() →
    Verdict.INCONCLUSIVE so the verdict CSV never claims CLEAN for an
    incomplete analysis.
    """
    if cfg.ct is None:
        return []
    ct_cwd = _resolve(cfg_dir, cfg.ct.workdir)
    out_dir = _resolve(cfg_dir, cfg.report.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # F5: per-run one-time note when require_sentinel=False and at least
    # one manual harness exists — the user is implicitly opting into the
    # legacy fail-open. Mirror's F1/F10's note pattern.
    has_manual = any(h.binary is not None for h in cfg.ct.harnesses)
    if has_manual and not cfg.ct.require_sentinel:
        console.print(
            "[dim][CTKAT] note:[/dim] ct.require_sentinel is False — "
            "manual-binary harnesses are accepted even if they never invoke "
            "the target function (the binary could be /bin/true). Set the "
            "field to true and have your harness emit "
            "'CTKAT-HARNESS-RAN: <name>' on stdout (see known_issues F5)."
        )

    # B5: KEM structural coverage caveat. A valid-ciphertext KEM harness only
    # exercises the normal decapsulation path. An invalid-ciphertext KEM harness
    # is needed to structurally exercise FO/implicit rejection under Valgrind.
    kem_ct = [h for h in cfg.ct.harnesses if h.template == "kem"]
    if kem_ct:
        valid_structural = [h.name for h in kem_ct if h.kem_decapsulation == "valid"]
        invalid_structural = [h.name for h in kem_ct if h.kem_decapsulation == "invalid"]
        if invalid_structural:
            valid_tail = (
                f" Valid-ct normal-path harness(es): {', '.join(valid_structural)}."
                if valid_structural
                else " Add a valid-ct harness too if normal-path structural coverage is needed."
            )
            console.print(
                "[dim][CTKAT] note:[/dim] KEM structural CT includes invalid-ct "
                f"FO/implicit-rejection harness(es): {', '.join(invalid_structural)}. "
                "Invalid-ct harnesses cover the rejection path under Valgrind."
                f"{valid_tail} (B5)"
            )
        else:
            fo_harnesses = [
                h.name
                for h in (cfg.dudect.harnesses if cfg.dudect is not None else [])
                if getattr(h, "leak_target", None) == "fo"
            ]
            if fo_harnesses:
                tail = (
                    f"that path is timing-covered by your dudect leak_target=fo "
                    f"harness(es): {', '.join(fo_harnesses)}."
                )
            else:
                tail = (
                    "that path is NOT covered by this run — add a dudect harness "
                    "with [bold]leak_target: fo[/] (see examples/pqc_mlkem768)."
                )
            console.print(
                "[dim][CTKAT] note:[/dim] KEM structural CT covers the valid-ct "
                f"(normal) decapsulation path only; the implicit-rejection / FO "
                f"fallback path is NOT analyzed by Valgrind here — {tail} "
                "A PASS says nothing about that path. (B5)"
            )

    results: List[Tuple[str, str, List[Finding]]] = []
    for h in cfg.ct.harnesses:
        is_manual = h.template is None
        if not is_manual:
            # In practice _do_generate fills `generated` for every template
            # harness before we get here, but guard explicitly — a KeyError
            # traceback is hostile to the user, especially when they're
            # debugging a yaml typo.
            if h.name not in generated:
                raise ValueError(
                    f"harness {h.name!r}: template-mode harness missing from "
                    f"generated set. This usually means generate failed silently "
                    f"or the harness was added after _do_generate ran."
                )
            binary = generated[h.name]
        else:
            if h.binary is None:
                # Should be caught by HarnessConfig._check_mode validator,
                # but defend explicitly — `python -O` strips asserts.
                raise ValueError(f"harness {h.name!r}: neither `binary` nor `template` set")
            binary = _resolve(cfg_dir, h.binary)
        log_path = out_dir / f"valgrind_{h.name}.log"
        console.print(f"[bold cyan]==> Valgrind[/]: harness=[bold]{h.name}[/] bin={binary}")
        result = run_valgrind(
            binary,
            log_path,
            cfg.ct.valgrind_flags,
            ct_cwd,
            timeout=cfg.ct.valgrind_timeout,
        )
        # F2: expected Valgrind exit codes are 0 (clean) and 99 (findings, via
        # --error-exitcode). Anything else = harness crashed / Valgrind failed /
        # timeout, or a missing log — all ERROR (not zero-findings → CLEAN). The
        # rc/log/parse classification lives in ct_runner so the ct-matrix sweep
        # maps identically (T21: utf-8+replace decoding is inside the parser).
        outcome = classify_valgrind_run(
            result,
            log_path,
            lookup_patterns=cfg.ct.lookup_function_patterns,
        )
        if outcome.status == "ERROR":
            stderr_tail = (result.stderr or "").strip().splitlines()[-3:]
            console.print(
                f"[bold red][CTKAT] ct: ERROR[/] — {outcome.error} on harness "
                f"[bold]{h.name}[/]. Analysis incomplete; verdict will be "
                f"INCONCLUSIVE. (F2)\n"
                f"[dim]valgrind stderr tail: {stderr_tail or '(empty)'}[/]"
            )
            results.append((h.name, "ERROR", []))
            continue
        # F5: manual-binary sentinel check — orthogonal to Valgrind's own status,
        # so it stays here (ct_runner is shared with the matrix, which only ever
        # drives template harnesses). Only enforced on manual mode;
        # `require_sentinel=False` keeps legacy behavior (note printed above).
        if is_manual and cfg.ct.require_sentinel:
            # F5 + Q(N1): the sentinel must not only be PRESENT — its captured
            # group must NAME this harness. Before, `re.search(...) is not None`
            # accepted ANY sentinel, so a binary that ran a DIFFERENT harness
            # (emitting `CTKAT-HARNESS-RAN: other`) passed for `h` — defeating
            # F5's "did THIS harness actually run" guarantee (the config doc
            # already says the capture group holds the harness name). One binary
            # may legitimately wrap several harnesses, so accept if ANY match
            # names this harness.
            pat = re.compile(cfg.ct.sentinel_pattern)
            stdout = result.stdout or ""
            if pat.groups >= 1:
                # .strip() tolerates a custom pattern whose group incidentally
                # captures surrounding whitespace (no-op for the default `\S+`);
                # skip matches where the optional group didn't participate.
                names = [m.group(1).strip() for m in pat.finditer(stdout) if m.group(1) is not None]
                ok = h.name in names
                why = (
                    f"emitted sentinel(s) naming {names!r}, not {h.name!r}"
                    if names
                    else "did not emit the sentinel"
                )
            else:
                # Group-less custom pattern: the user opted out of name
                # matching, so fall back to presence-only (legacy F5).
                ok = pat.search(stdout) is not None
                why = "did not emit the sentinel"
            if not ok:
                console.print(
                    f"[bold red][CTKAT] ct: ERROR[/] — manual harness "
                    f"[bold]{h.name}[/] {why} (pattern "
                    f"{cfg.ct.sentinel_pattern!r}) on stdout. The binary may not "
                    f"have invoked THIS harness's target. Verdict will be "
                    f"INCONCLUSIVE. (F5/N1)"
                )
                results.append((h.name, "ERROR", []))
                continue
        # T3: if the parser ignored a lot of lines, surface it as a dim note.
        # Banner/footer normally account for ~20 lines — much higher on a "no
        # findings" log suggests Valgrind changed format and our whitelist needs
        # an update.
        if outcome.dropped > 50:
            console.print(
                f"[dim][CTKAT] note:[/dim] valgrind parser ignored {outcome.dropped} "
                f"unrecognized lines for harness [bold]{h.name}[/]. If this "
                f"jumps across versions, our whitelist may need an update "
                f"(known_issues T3)."
            )
        results.append((h.name, outcome.status, outcome.findings))
    return results


def _emit_report(
    cfg: CtkatConfig,
    cfg_dir: Path,
    ct_results: List[Tuple[str, str, List[Finding]]],
) -> Path:
    out_dir = _resolve(cfg_dir, cfg.report.output_dir)
    rows = []
    for harness_name, _status, findings in ct_results:
        for f in findings:
            rows.append(finding_to_row(cfg.project.name, harness_name, f))

    csv_path = out_dir / cfg.report.csv_file
    json_path = out_dir / cfg.report.json_file
    write_csv(rows, csv_path)
    write_json(
        {
            "project": cfg.project.name,
            "harnesses": [
                {
                    "name": name,
                    "findings": [finding_to_row(cfg.project.name, name, f) for f in fs],
                }
                for name, _status, fs in ct_results
            ],
        },
        json_path,
    )

    if rows:
        table = Table(title="Potential variable-time findings")
        for col in ("harness", "function", "file:line", "severity", "type"):
            table.add_column(col)
        for r in rows:
            loc = f"{r['file']}:{r['line']}" if r["file"] else ""
            table.add_row(r["harness"], r["function"], loc, r["severity"], r["type"])
        console.print(table)

    console.print(f"[dim]CSV : {csv_path}[/]")
    console.print(f"[dim]JSON: {json_path}[/]")
    return csv_path


# --- dudect (Phase 4) -----------------------------------------------------


def _dudect_context(
    h: DudectHarnessConfig,
    dud: DudectConfig,
    effective_seed: int,
    effective_clock: str,
) -> dict:
    # `effective_clock` is the resolved concrete value ("rdtsc"/"monotonic"),
    # never the literal "auto" — the Jinja2 template branches on this and
    # would emit broken C if handed an unresolved sentinel.
    base = {
        "extra_headers": list(h.extra_headers),
        "measurements": dud.measurements,
        "warmup": dud.warmup,
        "seed": effective_seed,
        "clock": effective_clock,
        "pool_size": dud.timing_protocol.pool_size,
    }
    if h.template == "kem":
        # v2 accepts a runtime measurement count.  Allocate once for the
        # larger of target/control traces; each process receives its exact
        # requested count on argv.
        base["measurements"] = max(
            dud.measurements,
            dud.timing_protocol.control_measurements or dud.measurements,
        )
        base.update(
            {
                "header": h.header,
                "prefix": h.prefix,
                "leak_target": h.leak_target,
                "operand_setup_contract": h.operand_setup_contract,
                "rejection_oracle_function": h.rejection_oracle_function,
                "rejection_seed_offset": h.rejection_seed_offset,
                "randombytes_header": h.randombytes_header,
                "randombytes_return": h.randombytes_return,
            }
        )
    elif h.template == "sign":
        base["measurements"] = max(
            dud.measurements,
            dud.timing_protocol.control_measurements or dud.measurements,
        )
        # API-level signing axes are portable; implementation-specific sampler
        # cores are deliberately separate generic harnesses.
        base.update(
            {
                "header": h.header,
                "prefix": h.prefix,
                "sign_leak_target": h.sign_leak_target,
                "signature_length_contract": h.signature_length_contract,
                "randombytes_header": h.randombytes_header,
                "randombytes_return": h.randombytes_return,
            }
        )
    else:  # generic
        base.update(
            {
                "function": h.function,
                "args": list(h.args),
                "return_type": h.return_type,
                "buffers": [b.model_dump() for b in h.buffers],
            }
        )
    return base


def _error_welch(
    *,
    backend: str = "",
    reason: str = "timing stage did not complete",
    analysis_seed: Optional[int] = None,
    calibration_seed: Optional[int] = None,
) -> WelchResult:
    """Sentinel WelchResult for a harness whose dudect stage couldn't
    complete (timeout / crash / unparseable output / insufficient samples).
    `status="ERROR"` flows through `_compute_verdicts` → verdict.combine()
    → Verdict.INCONCLUSIVE so verdict CSV never silently downgrades a
    broken run to CLEAN. Used by Bundle E-1 (T6) and Bundle F (S4)."""
    return WelchResult(
        n0=0,
        n1=0,
        mean0=0.0,
        mean1=0.0,
        var0=0.0,
        var1=0.0,
        t_score=0.0,
        abs_t_score=0.0,
        status="ERROR",
        backend=backend,
        timing_validity="error",
        validity_reasons=(reason,),
        enough_measurements=False,
        analysis_seed=analysis_seed,
        calibration_seed=calibration_seed,
    )


def _official_t_value(test) -> float:
    if test.t_score is not None:
        return test.t_score
    if test.t_nonfinite and test.mean0 is not None and test.mean1 is not None:
        difference = test.mean0 - test.mean1
        if difference != 0:
            return math.copysign(math.inf, difference)
    return math.nan


def _official_to_welch(analysis: OfficialDudectAnalysis) -> WelchResult:
    winning = analysis.winning_test
    uncropped = analysis.uncropped_test
    t_score = _official_t_value(winning)
    return WelchResult(
        n0=winning.n0,
        n1=winning.n1,
        mean0=winning.mean0 or 0.0,
        mean1=winning.mean1 or 0.0,
        var0=winning.var0 or 0.0,
        var1=winning.var1 or 0.0,
        t_score=t_score,
        abs_t_score=analysis.max_abs_t,
        status=analysis.status,
        t_score_uncropped=_official_t_value(uncropped),
        abs_t_score_uncropped=uncropped.abs_t_score,
        backend=OFFICIAL_DUDECT_BACKEND,
        test_kind=analysis.max_test_kind,
        test_index=analysis.max_test_index,
        protocol_test_count=len(analysis.tests),
        max_tau=analysis.max_tau,
        detection_estimate=analysis.detection_estimate,
        enough_measurements=analysis.enough_measurements,
        upstream_revision=analysis.upstream_revision,
        protocol_results=[test.as_dict() for test in analysis.tests],
    )


_TIMING_SEED_DOMAINS = {
    "target": 0x5441524745545632,
    "calibration": 0x43414C4942525632,
    "aa": 0x41415F434E54525632,
    "placebo": 0x504C414345425632,
    "positive": 0x504F534954495632,
}


def _timing_domain_seed(base: int, role: str, process_index: int, subindex: int = 0) -> int:
    """Deterministic nonzero splitmix64 seed for one physical process."""

    x = (
        base
        ^ _TIMING_SEED_DOMAINS[role]
        ^ ((process_index + 1) * _CALIBRATION_SEED_DOMAIN)
        ^ ((subindex + 1) * 0xD1B54A32D192ED03)
    ) & _UINT64_MASK
    x = (x + _CALIBRATION_SEED_DOMAIN) & _UINT64_MASK
    x = ((x ^ (x >> 30)) * 0xBF58476D1CE4E5B9) & _UINT64_MASK
    x = ((x ^ (x >> 27)) * 0x94D049BB133111EB) & _UINT64_MASK
    x ^= x >> 31
    return x or _TIMING_SEED_DOMAINS[role]


def _trace_class_values(samples: TimingSamples) -> tuple[list[float], list[float]]:
    return (
        [cycle for clazz, cycle in zip(samples.classes, samples.cycles) if clazz == 0],
        [cycle for clazz, cycle in zip(samples.classes, samples.cycles) if clazz == 1],
    )


def _physical_control_result(
    samples: TimingSamples,
    *,
    warning_threshold: float,
    fail_threshold: float,
) -> WelchResult:
    class0, class1 = _trace_class_values(samples)
    if len(class0) < 2 or len(class1) < 2:
        raise RuntimeError(
            "physical control retained insufficient samples per class: "
            f"n0={len(class0)} n1={len(class1)}"
        )
    return welch_t_test(
        class0,
        class1,
        warning_threshold=warning_threshold,
        fail_threshold=fail_threshold,
    )


def _minimum_detectable_effect(
    result: WelchResult,
    *,
    alpha: float,
    target_power: float,
) -> float:
    """A/A-noise-derived nominal sensitivity in the harness clock domain.

    The legacy artifact key calls this an MDE.  It is not computed from the
    target-trace variance and therefore must not be interpreted as a bound on
    an unobserved target effect.
    """

    z_alpha = NormalDist().inv_cdf(1.0 - alpha / 2.0)
    z_power = NormalDist().inv_cdf(target_power)
    standard_error = math.sqrt(result.var0 / result.n0 + result.var1 / result.n1)
    return (z_alpha + z_power) * standard_error


def _positive_detection_effect(
    result: WelchResult,
    *,
    abs_t_threshold: float,
    target_power: float,
) -> float:
    """A/A-noise-derived effect for the directional positive-control rule.

    Unlike the legacy nominal MDE above, this diagnostic uses the actual
    positive-control threshold.  The injected delay has a known direction
    (class 1 must be slower), so the normal approximation is
    ``(threshold + z_power) * standard_error``.
    """

    z_power = NormalDist().inv_cdf(target_power)
    standard_error = math.sqrt(result.var0 / result.n0 + result.var1 / result.n1)
    return (abs_t_threshold + z_power) * standard_error


def _positive_control_detected(payload: dict, *, abs_t_threshold: float) -> bool:
    """Return whether a seeded class-1 delay was detected in its known direction."""

    return payload["mean_delta"] > 0.0 and payload["t_score"] <= -abs_t_threshold


def _control_result_payload(
    role: str,
    process_index: int,
    seed: int,
    samples: TimingSamples,
    result: WelchResult,
    *,
    effect_ticks: int = 0,
    alpha: Optional[float] = None,
    target_power: Optional[float] = None,
    positive_abs_t_threshold: Optional[float] = None,
) -> dict:
    payload = {
        "role": role,
        "process_index": process_index,
        "seed": seed,
        "effect_ticks": effect_ticks,
        "raw_n_total": samples.raw_n_total,
        "n0": result.n0,
        "n1": result.n1,
        "mean0": result.mean0,
        "mean1": result.mean1,
        "mean_delta": result.mean1 - result.mean0,
        "t_score": result.t_score,
        "abs_t_score": result.abs_t_score,
        "status": result.status,
        "dropped_clock_n0": samples.dropped_zero_n0,
        "dropped_clock_n1": samples.dropped_zero_n1,
        "dropped_migration_n0": samples.dropped_migration_n0,
        "dropped_migration_n1": samples.dropped_migration_n1,
        "malformed_count": samples.malformed_count,
        "runtime_metadata": dict(samples.runtime_metadata),
    }
    if alpha is not None and target_power is not None:
        payload["minimum_detectable_effect"] = _minimum_detectable_effect(
            result,
            alpha=alpha,
            target_power=target_power,
        )
    if positive_abs_t_threshold is not None and target_power is not None:
        payload["positive_detection_effect_at_target_power"] = _positive_detection_effect(
            result,
            abs_t_threshold=positive_abs_t_threshold,
            target_power=target_power,
        )
    return payload


def _run_timing_harness_with_build_seal(
    binary: Path,
    workdir: Path,
    *,
    build_provenance: Optional[dict] = None,
    build_provenance_path: Optional[Path] = None,
    build_provenance_sha256: Optional[str] = None,
    **kwargs,
) -> TimingSamples:
    """Run one measured subprocess between two immutable-build checks."""

    seal_values = (
        build_provenance,
        build_provenance_path,
        build_provenance_sha256,
    )
    if any(value is not None for value in seal_values) and not all(
        value is not None for value in seal_values
    ):
        raise TimingBuildProvenanceError("incomplete timing build seal was supplied")
    if build_provenance is not None:
        assert build_provenance_path is not None
        assert build_provenance_sha256 is not None
        assert_timing_build_seal_unchanged(
            build_provenance,
            build_provenance_path,
            build_provenance_sha256,
        )
    try:
        return run_timing_harness(binary, workdir, **kwargs)
    finally:
        if build_provenance is not None:
            assert build_provenance_path is not None
            assert build_provenance_sha256 is not None
            assert_timing_build_seal_unchanged(
                build_provenance,
                build_provenance_path,
                build_provenance_sha256,
            )


def _timing_build_protocol_record(
    payload: dict,
    seal_path: Path,
    seal_sha256: str,
    out_dir: Path,
) -> dict:
    """Return the stable report-facing subset of a timing build seal."""

    try:
        report = seal_path.resolve().relative_to(out_dir.resolve())
    except ValueError as exc:
        raise TimingBuildProvenanceError(
            f"timing build seal escaped report directory: {seal_path}"
        ) from exc
    return {
        "passed": True,
        "captured_before_measurement": payload.get("captured_before_measurement") is True,
        "report": str(report),
        "report_sha256": seal_sha256,
        "generated_source_sha256": payload["generated_source"]["sha256"],
        "binary_sha256": payload["binary"]["sha256"],
        "config_sha256": (
            payload["config"]["sha256"] if payload.get("config") is not None else None
        ),
    }


def _run_v2_harness_protocol(
    *,
    binary: Path,
    workdir: Path,
    dud: DudectConfig,
    harness: DudectHarnessConfig,
    effective_seed: int,
    official_adapter: Optional[Path],
    crop: bool,
    crop_warn_t: float,
    crop_fail_t: float,
    warn_t: float,
    fail_t: float,
    build_provenance: Optional[dict] = None,
    build_provenance_path: Optional[Path] = None,
    build_provenance_sha256: Optional[str] = None,
) -> tuple[TimingSamples, WelchResult, list[WelchResult]]:
    """Run target repetitions plus physical A/A/placebo/effect controls."""

    protocol = dud.timing_protocol
    control_measurements = protocol.control_measurements or dud.measurements
    traces: list[TimingProtocolTrace] = []
    target_runs: list[tuple[TimingSamples, WelchResult, list[WelchResult]]] = []
    target_payloads: list[dict] = []
    aa_payloads: list[dict] = []
    placebo_payloads: list[dict] = []
    positive_payloads: list[dict] = []
    signature_contract = harness.signature_length_contract if harness.template == "sign" else None

    for process_index in range(protocol.process_repeats):
        target_seed = (
            effective_seed
            if process_index == 0
            else _timing_domain_seed(effective_seed, "target", process_index)
        )
        calibration: Optional[TimingSamples] = None
        calibration_seed: Optional[int] = None
        if dud.backend == "official-dudect":
            if official_adapter is None:
                raise RuntimeError("official dudect adapter missing for timing-harness-v2")
            calibration_seed = _timing_domain_seed(effective_seed, "calibration", process_index)
            calibration = _run_timing_harness_with_build_seal(
                binary,
                workdir,
                timeout=dud.timeout,
                seed_override=calibration_seed,
                mode="target",
                measurements_override=dud.measurements,
                signature_length_contract=signature_contract,
                build_provenance=build_provenance,
                build_provenance_path=build_provenance_path,
                build_provenance_sha256=build_provenance_sha256,
            )
            traces.append(
                TimingProtocolTrace(
                    "target-calibration",
                    process_index,
                    calibration_seed,
                    calibration,
                )
            )

        samples = _run_timing_harness_with_build_seal(
            binary,
            workdir,
            timeout=dud.timeout,
            seed_override=target_seed,
            mode="target",
            measurements_override=dud.measurements,
            signature_length_contract=signature_contract,
            build_provenance=build_provenance,
            build_provenance_path=build_provenance_path,
            build_provenance_sha256=build_provenance_sha256,
        )
        samples.calibration = calibration
        traces.append(TimingProtocolTrace("target", process_index, target_seed, samples))
        class0, class1 = _trace_class_values(samples)
        if len(class0) < 2 or len(class1) < 2:
            raise RuntimeError(
                "target trace retained insufficient samples per class: "
                f"process={process_index} n0={len(class0)} n1={len(class1)}"
            )

        if dud.backend == "official-dudect":
            assert official_adapter is not None and calibration is not None
            analysis = analyze_with_official_dudect(
                calibration,
                samples,
                adapter_binary=official_adapter,
                workdir=workdir,
                timeout=dud.backend_timeout,
            )
            target_result = _official_to_welch(analysis)
        elif crop:
            target_result = welch_with_cropping(
                class0,
                class1,
                warning_threshold=crop_warn_t,
                fail_threshold=crop_fail_t,
            )
            target_result.backend = EXPERIMENTAL_FIRST_ORDER_BACKEND
            target_result.test_kind = "experimental-first-order-cropped"
            target_result.test_index = (
                CROP_PERCENTILES.index(target_result.cropped_at)
                if target_result.cropped_at in CROP_PERCENTILES
                else None
            )
            target_result.protocol_test_count = len(CROP_PERCENTILES)
        else:
            target_result = welch_t_test(class0, class1, warn_t, fail_t)
            target_result.backend = EXPERIMENTAL_FIRST_ORDER_BACKEND
            target_result.test_kind = "experimental-first-order-uncropped"
            target_result.test_index = 0
            target_result.protocol_test_count = 1

        target_result.analysis_seed = target_seed
        target_result.calibration_seed = calibration_seed
        batches = batch_t_scores(
            samples.classes,
            samples.cycles,
            batches=dud.batches,
            warning_threshold=warn_t,
            fail_threshold=fail_t,
        )
        target_runs.append((samples, target_result, batches))
        target_payload = {
            "process_index": process_index,
            "analysis_seed": target_seed,
            "calibration_seed": calibration_seed,
            "status": target_result.status,
            "abs_t_score": target_result.abs_t_score,
            "test_kind": target_result.test_kind,
            "test_index": target_result.test_index,
            "n0": target_result.n0,
            "n1": target_result.n1,
            "enough_measurements": target_result.enough_measurements,
            "runtime_metadata": dict(samples.runtime_metadata),
        }
        if calibration is not None:
            target_payload["calibration_runtime_metadata"] = dict(calibration.runtime_metadata)
        target_payloads.append(target_payload)

        aa_seed = _timing_domain_seed(effective_seed, "aa", process_index)
        aa_samples = _run_timing_harness_with_build_seal(
            binary,
            workdir,
            timeout=dud.timeout,
            seed_override=aa_seed,
            mode="aa",
            measurements_override=control_measurements,
            signature_length_contract=signature_contract,
            build_provenance=build_provenance,
            build_provenance_path=build_provenance_path,
            build_provenance_sha256=build_provenance_sha256,
        )
        traces.append(TimingProtocolTrace("aa", process_index, aa_seed, aa_samples))
        aa_result = _physical_control_result(
            aa_samples,
            warning_threshold=protocol.aa_abs_t_limit,
            fail_threshold=protocol.positive_abs_t_threshold,
        )
        aa_payloads.append(
            _control_result_payload(
                "aa",
                process_index,
                aa_seed,
                aa_samples,
                aa_result,
                alpha=protocol.power_alpha,
                target_power=protocol.target_power,
                positive_abs_t_threshold=protocol.positive_abs_t_threshold,
            )
        )

        placebo_seed = _timing_domain_seed(effective_seed, "placebo", process_index)
        placebo_samples = _run_timing_harness_with_build_seal(
            binary,
            workdir,
            timeout=dud.timeout,
            seed_override=placebo_seed,
            mode="placebo",
            measurements_override=control_measurements,
            signature_length_contract=signature_contract,
            build_provenance=build_provenance,
            build_provenance_path=build_provenance_path,
            build_provenance_sha256=build_provenance_sha256,
        )
        traces.append(
            TimingProtocolTrace("setup-placebo", process_index, placebo_seed, placebo_samples)
        )
        placebo_result = _physical_control_result(
            placebo_samples,
            warning_threshold=protocol.aa_abs_t_limit,
            fail_threshold=protocol.positive_abs_t_threshold,
        )
        placebo_payloads.append(
            _control_result_payload(
                "setup-placebo",
                process_index,
                placebo_seed,
                placebo_samples,
                placebo_result,
            )
        )

        for effect_index, effect_ticks in enumerate(protocol.positive_control_effects):
            effect_seed = _timing_domain_seed(
                effective_seed, "positive", process_index, effect_index
            )
            positive_samples = _run_timing_harness_with_build_seal(
                binary,
                workdir,
                timeout=dud.timeout,
                seed_override=effect_seed,
                mode="positive",
                effect_ticks=effect_ticks,
                measurements_override=control_measurements,
                signature_length_contract=signature_contract,
                build_provenance=build_provenance,
                build_provenance_path=build_provenance_path,
                build_provenance_sha256=build_provenance_sha256,
            )
            traces.append(
                TimingProtocolTrace(
                    "positive",
                    process_index,
                    effect_seed,
                    positive_samples,
                    effect_ticks,
                )
            )
            positive_result = _physical_control_result(
                positive_samples,
                warning_threshold=protocol.aa_abs_t_limit,
                fail_threshold=protocol.positive_abs_t_threshold,
            )
            positive_payloads.append(
                _control_result_payload(
                    "positive",
                    process_index,
                    effect_seed,
                    positive_samples,
                    positive_result,
                    effect_ticks=effect_ticks,
                )
            )

    # Report the most conservative target run while retaining every process.
    winning_index = max(
        range(len(target_runs)),
        key=lambda index: target_runs[index][1].abs_t_score,
    )
    samples, overall, batches = target_runs[winning_index]
    samples.protocol_traces = traces

    target_statuses = [payload["status"] for payload in target_payloads]
    aa_failures = sum(payload["abs_t_score"] >= protocol.aa_abs_t_limit for payload in aa_payloads)
    placebo_failures = sum(
        payload["abs_t_score"] >= protocol.aa_abs_t_limit for payload in placebo_payloads
    )
    power_curve: list[dict] = []
    for effect_ticks in protocol.positive_control_effects:
        effect_runs = [
            payload for payload in positive_payloads if payload["effect_ticks"] == effect_ticks
        ]
        detections = sum(
            _positive_control_detected(
                payload,
                abs_t_threshold=protocol.positive_abs_t_threshold,
            )
            for payload in effect_runs
        )
        power_curve.append(
            {
                "effect_ticks": effect_ticks,
                "detections": detections,
                "runs": len(effect_runs),
                "detection_rate": detections / len(effect_runs),
                "mean_observed_delta": (
                    sum(payload["mean_delta"] for payload in effect_runs) / len(effect_runs)
                ),
            }
        )
    largest_effect = power_curve[-1]
    required_detections = math.ceil(protocol.target_power * protocol.process_repeats)

    output_lengths = [
        length
        for trace in traces
        if trace.role == "target"
        for length in trace.samples.output_lengths
        if length is not None
    ]
    randomness = sorted(
        {
            trace.samples.runtime_metadata.get("randomness", "unreported")
            for trace in traces
            if trace.role == "target"
        }
    )
    overall.harness_protocol = {
        "schema_version": "1.0",
        "protocol": "timing-harness-v2",
        "template": harness.template,
        "axis": (harness.leak_target if harness.template == "kem" else harness.sign_leak_target),
        "measurement_scope": (
            "kem-decapsulation"
            if harness.template == "kem"
            else "full-signature-api-including-encoding"
        ),
        "pool_size": protocol.pool_size,
        "target_measurements": dud.measurements,
        "control_measurements": control_measurements,
        "common_work_buffer": True,
        "symmetric_setup": True,
        "timed_region_target_only": True,
        "rdtscp_aux_migration_filter": True,
        "process_repeats_required": 3,
        "process_repeats_observed": protocol.process_repeats,
        "target_repeats": target_payloads,
        "target_status_consistent": len(set(target_statuses)) == 1,
        "aa_controls": aa_payloads,
        "aa_abs_t_limit": protocol.aa_abs_t_limit,
        "aa_max_failures": protocol.aa_max_failures,
        "aa_failures": aa_failures,
        "aa_budget_passed": aa_failures <= protocol.aa_max_failures,
        "setup_placebo_controls": placebo_payloads,
        "setup_placebo_failures": placebo_failures,
        "setup_placebo_passed": placebo_failures == 0,
        "positive_controls": positive_payloads,
        "positive_abs_t_threshold": protocol.positive_abs_t_threshold,
        "positive_power_curve": power_curve,
        "target_power": protocol.target_power,
        "required_positive_detections": required_detections,
        "positive_power_passed": largest_effect["detections"] >= required_detections,
        "power_alpha": protocol.power_alpha,
        "minimum_detectable_effects": [
            payload["minimum_detectable_effect"] for payload in aa_payloads
        ],
        "positive_detection_effects_at_target_power": [
            payload["positive_detection_effect_at_target_power"] for payload in aa_payloads
        ],
        "randomness_policies_observed": randomness,
        "output_length": {
            "observed": bool(output_lengths),
            "min": min(output_lengths) if output_lengths else None,
            "max": max(output_lengths) if output_lengths else None,
            "unique_count": len(set(output_lengths)),
            "variable": len(set(output_lengths)) > 1,
        },
    }
    if harness.template == "kem" and harness.leak_target == "valid_tuple":
        overall.harness_protocol["input_contract"] = build_valid_tuple_input_contract(
            [(trace.samples.runtime_metadata, trace.seed) for trace in traces]
        )
    elif harness.template == "kem" and harness.leak_target in {
        "chosen_ct",
        "operand_bin",
    }:
        input_metadata = [trace.samples.runtime_metadata for trace in traces]
        expected_common = {
            "axis": harness.leak_target,
            "key_policy": "fixed",
            "corpus_seed": str(effective_seed),
        }
        if harness.leak_target == "chosen_ct":
            expected_common["class_contract"] = "paired-invalid-public-chosen-ciphertexts"
            expected_common["rejection_witness"] = "exact-rkprf-output"
            digest_names: tuple[str, ...] = (
                "fixed_sk_sha3_256",
                "class0_ct_sha3_256",
                "class1_ct_sha3_256",
            )
        elif harness.leak_target == "operand_bin":
            expected_common.update(
                {
                    "class_contract": "frozen-public-coefficient-bins",
                    "class0_coefficients": "0-63",
                    "class1_coefficients": "3265-3328",
                }
            )
            operand_v3 = harness.operand_setup_contract == "same-address-branchless-v3"
            if operand_v3:
                expected_common.update(
                    {
                        "setup_contract": "same-address-branchless-v3",
                        "class_address_policy": "fixed-sk-and-shared-ct-work",
                        "placebo_coefficient": "1664",
                        "placebo_target_path": "valid-decapsulation",
                        "setup_return_codes": "checked",
                        "coefficient_witness": "all-bin-members",
                        "measured_dec_contract_failures": "0",
                    }
                )
            digest_names = ()
        metadata_matches = all(
            all(item.get(key) == value for key, value in expected_common.items())
            for item in input_metadata
        )
        digest_values = {
            name: sorted({item.get(name, "") for item in input_metadata}) for name in digest_names
        }
        digests_valid = all(
            len(values) == 1 and re.fullmatch(r"[0-9a-f]{64}", values[0])
            for values in digest_values.values()
        )
        input_contract = {
            "axis": harness.leak_target,
            "key_policy": expected_common["key_policy"],
            "public_class_axis": True,
            "secret_key_varies_between_classes": False,
            "expected_metadata": expected_common,
            "observed_digests": digest_values,
            "traces_validated": len(input_metadata),
            "passed": metadata_matches and digests_valid,
            "evidence_boundary": (
                "fixed-key public chosen-ciphertext contrast; secret attribution "
                "requires separate operand evidence"
                if harness.leak_target == "chosen_ct"
                else "direct public numerator-bin latency canary; not full-KEM leakage"
            ),
        }
        if harness.leak_target == "operand_bin" and (
            harness.operand_setup_contract == "same-address-branchless-v3"
        ):
            # The official timing-harness-v2 matrix is exactly seven traces
            # (calibration, target, A/A, placebo, and three positive effects)
            # for each of three independent process seeds.  Do not accept a
            # partial/non-official matrix merely because every trace that did
            # happen to run emitted internally consistent metadata.
            input_contract = build_operand_v3_input_contract(
                input_metadata,
                base_seed=effective_seed,
                traces_required=7 * protocol.process_repeats,
                backend_is_official=dud.backend == "official-dudect",
            )
        overall.harness_protocol["input_contract"] = input_contract
    if harness.template == "sign":
        signature_metadata = [trace.samples.runtime_metadata for trace in traces]

        def one_metadata_uint(name: str) -> Optional[int]:
            values = {item.get(name) for item in signature_metadata}
            if len(values) != 1:
                return None
            value = next(iter(values))
            return int(value) if isinstance(value, str) and value.isdigit() else None

        overall.harness_protocol["signature_call_contract"] = {
            "configured": harness.signature_length_contract,
            "return_code_column": "signature_return_code",
            "return_code_success": 0,
            "return_codes_recorded": all(
                item.get("signature_return_code_recorded") == "true" for item in signature_metadata
            ),
            "correctness_round_trip_gate": all(
                item.get("signature_correctness_gate") == "passed" for item in signature_metadata
            ),
            "measured_contract_failures": sum(
                int(item["measured_signature_contract_failures"]) for item in signature_metadata
            ),
            "resolved_min": one_metadata_uint("signature_length_min"),
            "resolved_max": one_metadata_uint("signature_length_max"),
            "traces_validated": len(signature_metadata),
            "passed": all(
                not signature_trace_contract_errors(
                    trace.samples, harness.signature_length_contract
                )
                for trace in traces
            ),
        }
    return samples, overall, batches


def _set_timing_validity(
    result: WelchResult,
    samples: TimingSamples,
    harness: DudectHarnessConfig,
    environment: dict,
    *,
    expected_measurements: Optional[int] = None,
) -> None:
    """Attach fail-closed target-level timing validity."""

    result.environment = dict(environment)
    environment_reasons = list(environment.get("rejection_reasons", []))
    corruption_reasons: list[str] = []
    interpretation_reasons: list[str] = []

    def inspect_trace(trace: TimingSamples, label: str) -> None:
        raw_total = trace.raw_n_total
        dropped_zero = trace.dropped_zero_n0 + trace.dropped_zero_n1
        dropped_migration = trace.dropped_migration_n0 + trace.dropped_migration_n1
        malformed = trace.malformed_count
        accounted = len(trace.classes) + dropped_zero + dropped_migration + malformed
        trace_expected = expected_measurements
        metadata_expected = trace.runtime_metadata.get("measurements")
        if metadata_expected and metadata_expected.isdigit():
            trace_expected = int(metadata_expected)
        if trace_expected is not None and raw_total != trace_expected:
            corruption_reasons.append(
                f"{label} trace emitted {raw_total}/{trace_expected} expected rows"
            )
        if malformed != 0:
            corruption_reasons.append(f"{label} trace parser dropped {malformed} malformed rows")
        if raw_total != accounted:
            corruption_reasons.append(
                f"{label} trace bookkeeping found "
                f"{raw_total - accounted} malformed/unaccounted rows"
            )
        if harness.template == "sign":
            corruption_reasons.extend(
                f"{label} {reason}"
                for reason in signature_trace_contract_errors(
                    trace, harness.signature_length_contract
                )
            )
        dropped_total = dropped_zero + dropped_migration
        if raw_total and dropped_total / raw_total > 0.01:
            drop_label = "zero-cycle" if dropped_migration == 0 else "clock/migration"
            environment_reasons.append(
                f"{label} {drop_label} drop rate {dropped_total / raw_total:.2%} "
                "exceeds 1% environment limit"
            )

        surviving_n0 = sum(clazz == 0 for clazz in trace.classes)
        surviving_n1 = sum(clazz == 1 for clazz in trace.classes)
        dropped_n0 = trace.dropped_zero_n0 + trace.dropped_migration_n0
        dropped_n1 = trace.dropped_zero_n1 + trace.dropped_migration_n1
        raw_n0 = surviving_n0 + dropped_n0
        raw_n1 = surviving_n1 + dropped_n1
        if raw_n0 and raw_n1:
            drop_rate0 = dropped_n0 / raw_n0
            drop_rate1 = dropped_n1 / raw_n1
            if max(drop_rate0, drop_rate1) > 0.05 and abs(drop_rate0 - drop_rate1) > 0.05:
                environment_reasons.append(
                    f"{label} class-asymmetric sample filtering exceeds 5% environment limit"
                )

    if samples.protocol_traces:
        for trace in samples.protocol_traces:
            suffix = f"-effect-{trace.effect_ticks}" if trace.effect_ticks else ""
            inspect_trace(
                trace.samples,
                f"{trace.role}[{trace.process_index}]{suffix}",
            )
    else:
        inspect_trace(samples, "analysis")
        if samples.calibration is not None:
            inspect_trace(samples.calibration, "calibration")
    environment_reasons = list(dict.fromkeys(environment_reasons))
    result.environment["rejected"] = bool(environment_reasons)
    result.environment["rejection_reasons"] = environment_reasons

    if result.status == "ERROR":
        result.timing_validity = "error"
    elif corruption_reasons:
        result.timing_validity = "error"
    elif environment_reasons:
        result.timing_validity = "environment-rejected"
    elif result.status == "INSUFFICIENT":
        result.timing_validity = "insufficient-power"
        interpretation_reasons.append(
            "official dudect minimum was not met "
            "(more than 10,000 retained class-0 samples required)"
        )
    elif result.backend != OFFICIAL_DUDECT_BACKEND:
        result.timing_validity = "insufficient-power"
        interpretation_reasons.append(
            "experimental timing backend is non-decisional; "
            "target validity requires the pinned official dudect backend"
        )
    elif harness.template in {"kem", "sign"}:
        protocol = result.harness_protocol
        valid_tuple_errors = (
            validate_valid_tuple_protocol(protocol, label="harness_protocol")
            if harness.template == "kem" and harness.leak_target == "valid_tuple"
            else []
        )
        operand_v3_errors: list[str] = []
        if (
            harness.template == "kem"
            and harness.leak_target == "operand_bin"
            and harness.operand_setup_contract == "same-address-branchless-v3"
        ):
            expected_metadata = protocol.get("input_contract", {}).get("expected_metadata", {})
            base_seed = expected_metadata.get("corpus_seed")
            if isinstance(base_seed, str) and base_seed.isdigit():
                operand_v3_errors = validate_operand_v3_protocol(
                    protocol,
                    base_seed=int(base_seed),
                    label="harness_protocol",
                )
            else:
                operand_v3_errors = ["harness_protocol operand-v3 corpus seed is missing"]
        if protocol.get("protocol") != "timing-harness-v2":
            result.timing_validity = "confounded"
            interpretation_reasons.append(
                f"{harness.template} trace lacks timing-harness-v2 protocol evidence"
            )
        elif not protocol.get("build_provenance", {}).get("passed", False):
            result.timing_validity = "error"
            interpretation_reasons.append(
                "pre-measurement source/binary/compiler/config build seal is missing or failed"
            )
        elif protocol.get("process_repeats_observed", 0) < protocol.get(
            "process_repeats_required", 3
        ):
            result.timing_validity = "insufficient-power"
            interpretation_reasons.append(
                "fewer than three independent target/control process seeds were measured"
            )
        elif not protocol.get("aa_budget_passed", False):
            result.timing_validity = "confounded"
            interpretation_reasons.append(
                "physical A/A false-alarm budget failed; class labels alone changed timing"
            )
        elif not protocol.get("setup_placebo_passed", False):
            result.timing_validity = "confounded"
            interpretation_reasons.append(
                "setup-only placebo detected residual class-dependent setup/cache effects"
            )
        elif not protocol.get("positive_power_passed", False):
            result.timing_validity = "insufficient-power"
            interpretation_reasons.append(
                "largest seeded positive-control effect did not reach the required "
                "repeat detection fraction"
            )
        elif not protocol.get("target_status_consistent", False):
            result.timing_validity = "insufficient-power"
            interpretation_reasons.append(
                "target raw status was inconsistent across independent process/seed repeats"
            )
        elif any(
            item.get("enough_measurements") is False for item in protocol.get("target_repeats", [])
        ):
            result.timing_validity = "insufficient-power"
            interpretation_reasons.append(
                "at least one target repeat did not meet the backend measurement minimum"
            )
        elif protocol.get("randomness_policies_observed") != ["seeded-interpose"]:
            result.timing_validity = "confounded"
            interpretation_reasons.append(
                "target key/sign randomness was not confirmed to use the seeded interpose; "
                "the runtime manifest is not reproducible from the recorded seed"
            )
        elif valid_tuple_errors:
            result.timing_validity = "error"
            interpretation_reasons.extend(valid_tuple_errors)
        elif operand_v3_errors:
            result.timing_validity = "error"
            interpretation_reasons.extend(operand_v3_errors)
        elif harness.binary_contract is not None and not protocol.get("binary_contract", {}).get(
            "passed", False
        ):
            result.timing_validity = "error"
            interpretation_reasons.append(
                "configured exact linked-binary instruction contract is missing or failed"
            )
        elif (
            harness.template == "kem"
            and harness.leak_target in {"chosen_ct", "operand_bin"}
            and not protocol.get("input_contract", {}).get("passed", False)
        ):
            result.timing_validity = "error"
            interpretation_reasons.append(
                f"{harness.leak_target} input metadata contract did not pass"
            )
        elif harness.template == "sign" and not protocol.get("signature_call_contract", {}).get(
            "passed", False
        ):
            result.timing_validity = "error"
            interpretation_reasons.append(
                "signature return-code/length/correctness-gate contract did not pass"
            )
        else:
            result.timing_validity = "valid"
    else:
        result.timing_validity = "insufficient-power"
        interpretation_reasons.append(
            "target-level physical A/A and seeded positive-control power "
            "calibration are not attached to caller-defined generic setup"
        )
    result.validity_reasons = tuple(
        dict.fromkeys([*corruption_reasons, *environment_reasons, *interpretation_reasons])
    )


def _emit_dudect_report(
    project: str,
    out_dir: Path,
    results: List[Tuple[str, TimingSamples, WelchResult, List[WelchResult]]],
) -> Tuple[Path, Path]:
    """Write raw, summary, calibration, and backend-protocol artifacts.

    The return pair remains ``(raw_path, summary_path)`` for compatibility.
    Backend-v2 details live in appended summary columns and the lossless
    ``dudect_backend_report.json`` sidecar.
    """
    import hashlib as _hashlib
    import json as _json

    out_dir.mkdir(parents=True, exist_ok=True)
    raw_path = out_dir / "dudect_raw_timings.csv"
    calibration_path = out_dir / "dudect_calibration_timings.csv"
    protocol_path = out_dir / "dudect_protocol_timings.csv"
    summary_path = out_dir / "dudect_summary.csv"
    backend_path = out_dir / "dudect_backend_report.json"

    def trace_rows(trace: TimingSamples):
        retained = []
        for index, (clazz, cycles) in enumerate(zip(trace.classes, trace.cycles)):
            sample_id = trace.sample_ids[index] if index < len(trace.sample_ids) else index
            aux_start = trace.aux_start[index] if index < len(trace.aux_start) else None
            aux_end = trace.aux_end[index] if index < len(trace.aux_end) else None
            output_length = (
                trace.output_lengths[index] if index < len(trace.output_lengths) else None
            )
            signature_return_code = (
                trace.signature_return_codes[index]
                if index < len(trace.signature_return_codes)
                else None
            )
            retained.append(
                (
                    sample_id,
                    clazz,
                    cycles,
                    aux_start,
                    aux_end,
                    "",
                    output_length,
                    signature_return_code,
                )
            )
        dropped = [
            (
                item.sample_id,
                item.clazz,
                item.cycles,
                item.aux_start,
                item.aux_end,
                item.reason,
                item.output_length,
                item.signature_return_code,
            )
            for item in trace.dropped_samples
        ]
        return sorted([*retained, *dropped], key=lambda row: row[0])

    raw_header = [
        "project",
        "harness",
        "sample_id",
        "class",
        "cycles",
        "aux_start",
        "aux_end",
        "drop_reason",
        "output_length",
        "signature_return_code",
        "protocol",
    ]
    with open(raw_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(raw_header)
        for harness_name, samples, _, _ in results:
            for row in trace_rows(samples):
                w.writerow(
                    [
                        project,
                        harness_name,
                        *row,
                        samples.protocol_version,
                    ]
                )

    with open(calibration_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(raw_header)
        for harness_name, samples, _, _ in results:
            if samples.calibration is None:
                continue
            for row in trace_rows(samples.calibration):
                w.writerow(
                    [
                        project,
                        harness_name,
                        *row,
                        samples.calibration.protocol_version,
                    ]
                )

    with open(protocol_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(
            [
                "project",
                "harness",
                "role",
                "process_index",
                "seed",
                "effect_ticks",
                "sample_id",
                "class",
                "cycles",
                "aux_start",
                "aux_end",
                "drop_reason",
                "output_length",
                "signature_return_code",
                "protocol",
            ]
        )
        for harness_name, samples, _, _ in results:
            for trace in samples.protocol_traces:
                for row in trace_rows(trace.samples):
                    w.writerow(
                        [
                            project,
                            harness_name,
                            trace.role,
                            trace.process_index,
                            trace.seed,
                            trace.effect_ticks,
                            *row,
                            trace.samples.protocol_version,
                        ]
                    )

    with open(summary_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        # IMPORTANT: columns 1-14 are stable for backward compatibility —
        # scripts/run_phase4.sh parses $11 (status) via awk and we don't
        # want to break that contract. Diagnostic columns 15-17 added in
        # Bundle B (cropping), 18-20 added in Bundle F (S1 raw-count
        # bookkeeping). All new columns go at the END so awk-by-position
        # consumers keep working.
        w.writerow(
            [
                "project",
                "harness",
                "n0",
                "n1",
                "mean0",
                "mean1",
                "var0",
                "var1",
                "t_score",
                "abs_t_score",
                "status",
                "batch_t_mean",
                "batch_t_max_abs",
                "batches",
                "cropped_at",
                "t_score_uncropped",
                "abs_t_score_uncropped",
                "raw_n_total",
                "dropped_zero_n0",
                "dropped_zero_n1",
                "cohens_d",
                "backend",
                "timing_validity",
                "validity_reasons",
                "test_kind",
                "test_index",
                "protocol_test_count",
                "max_tau",
                "detection_estimate",
                "enough_measurements",
                "upstream_revision",
                "calibration_raw_n_total",
                "analysis_seed",
                "calibration_seed",
                "dropped_migration_n0",
                "dropped_migration_n1",
                "malformed_count",
                "harness_protocol",
                "process_repeats",
                "aa_failures",
                "positive_power_passed",
                "minimum_detectable_effect_max",
            ]
        )
        for harness_name, samples, r, batches in results:
            # Empty string when no batches — matches _print_dudect_summary's
            # on-screen "-" semantics and keeps pandas/R from reading the
            # literal string "nan" as a float NaN downstream.
            if batches:
                batch_mean_str = _fmt(sum(b.t_score for b in batches) / len(batches))
                batch_max_str = _fmt(max(b.abs_t_score for b in batches))
            else:
                batch_mean_str = ""
                batch_max_str = ""
            w.writerow(
                [
                    project,
                    harness_name,
                    r.n0,
                    r.n1,
                    _fmt(r.mean0),
                    _fmt(r.mean1),
                    _fmt(r.var0),
                    _fmt(r.var1),
                    _fmt(r.t_score),
                    _fmt(r.abs_t_score),
                    r.status,
                    batch_mean_str,
                    batch_max_str,
                    len(batches),
                    _fmt(r.cropped_at),
                    _fmt(r.t_score_uncropped),
                    _fmt(r.abs_t_score_uncropped),
                    # S1: raw bookkeeping straight from the parser. ERROR-status
                    # rows (T6/S4) have a default-constructed TimingSamples so
                    # these columns are all 0 — that's the correct semantic
                    # ("the run didn't produce any samples").
                    samples.raw_n_total,
                    samples.dropped_zero_n0,
                    samples.dropped_zero_n1,
                    # S3: standardized effect size. _fmt handles inf/NaN by
                    # emitting empty string — matches what we do with t_score
                    # so pandas/R get a consistent reading of "blew up".
                    _fmt(r.cohens_d),
                    r.backend,
                    r.timing_validity,
                    "; ".join(r.validity_reasons),
                    r.test_kind,
                    "" if r.test_index is None else r.test_index,
                    r.protocol_test_count,
                    _fmt(r.max_tau, digits=9),
                    _fmt(r.detection_estimate),
                    ("" if r.enough_measurements is None else str(r.enough_measurements).lower()),
                    r.upstream_revision,
                    (samples.calibration.raw_n_total if samples.calibration is not None else 0),
                    "" if r.analysis_seed is None else r.analysis_seed,
                    "" if r.calibration_seed is None else r.calibration_seed,
                    samples.dropped_migration_n0,
                    samples.dropped_migration_n1,
                    samples.malformed_count,
                    r.harness_protocol.get("protocol", ""),
                    r.harness_protocol.get("process_repeats_observed", ""),
                    r.harness_protocol.get("aa_failures", ""),
                    (
                        ""
                        if "positive_power_passed" not in r.harness_protocol
                        else str(r.harness_protocol["positive_power_passed"]).lower()
                    ),
                    _fmt(
                        max(r.harness_protocol.get("minimum_detectable_effects", [None]))
                        if r.harness_protocol.get("minimum_detectable_effects")
                        else None
                    ),
                ]
            )

    def json_number(value):
        return value if value is not None and math.isfinite(value) else None

    harness_reports = []
    for harness_name, samples, result, batches in results:
        harness_reports.append(
            {
                "harness": harness_name,
                "backend": result.backend,
                "upstream_revision": result.upstream_revision or None,
                "raw_status": result.status,
                "timing_validity": result.timing_validity,
                "validity_reasons": list(result.validity_reasons),
                "test_kind": result.test_kind,
                "test_index": result.test_index,
                "protocol_test_count": result.protocol_test_count,
                "n0": result.n0,
                "n1": result.n1,
                "t_score": json_number(result.t_score),
                "abs_t_score": json_number(result.abs_t_score),
                "t_score_uncropped": json_number(result.t_score_uncropped),
                "abs_t_score_uncropped": json_number(result.abs_t_score_uncropped),
                "max_tau": json_number(result.max_tau),
                "detection_estimate": json_number(result.detection_estimate),
                "enough_measurements": result.enough_measurements,
                "analysis_seed": result.analysis_seed,
                "calibration_seed": result.calibration_seed,
                "analysis_raw_n_total": samples.raw_n_total,
                "calibration_raw_n_total": (
                    samples.calibration.raw_n_total if samples.calibration is not None else 0
                ),
                "batch_t_scores": [json_number(batch.t_score) for batch in batches],
                "environment": result.environment,
                "tests": result.protocol_results,
                "harness_protocol": result.harness_protocol,
                "analysis_runtime_metadata": dict(samples.runtime_metadata),
                "drop_counts": {
                    "clock_n0": samples.dropped_zero_n0,
                    "clock_n1": samples.dropped_zero_n1,
                    "cpu_migration_n0": samples.dropped_migration_n0,
                    "cpu_migration_n1": samples.dropped_migration_n1,
                    "malformed": samples.malformed_count,
                },
            }
        )

    def json_safe(value):
        if isinstance(value, float):
            return value if math.isfinite(value) else None
        if isinstance(value, dict):
            return {key: json_safe(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [json_safe(item) for item in value]
        return value

    backend_payload = {
        "schema_version": "2.0",
        "kind": "timing-backend-report",
        "project": project,
        "official_dudect_revision": OFFICIAL_DUDECT_REVISION,
        "raw_trace_sha256": _hashlib.sha256(raw_path.read_bytes()).hexdigest(),
        "calibration_trace_sha256": _hashlib.sha256(calibration_path.read_bytes()).hexdigest(),
        "protocol_trace_sha256": _hashlib.sha256(protocol_path.read_bytes()).hexdigest(),
        "harnesses": harness_reports,
    }
    with backend_path.open("w", encoding="utf-8") as f:
        _json.dump(json_safe(backend_payload), f, indent=2, sort_keys=True, allow_nan=False)
        f.write("\n")
    return raw_path, summary_path


def _do_dudect(
    dud: DudectConfig,
    cfg_dir: Path,
    project_name: str,
    out_dir: Path,
    crop: bool = True,
    config_path: Optional[Path] = None,
) -> List[Tuple[str, TimingSamples, WelchResult, List[WelchResult]]]:
    qemu = detect_qemu_emulation()
    # Resolve clock=auto once up front so every downstream consumer (Jinja2
    # template, QEMU-warning logic, CLI banner) sees the same concrete value.
    effective_clock = resolve_clock(dud.clock)
    if qemu and effective_clock == "rdtsc":
        # Only reachable when the user explicitly set clock: rdtsc inside
        # QEMU — `auto` would have downgraded to monotonic already.
        console.print(
            "[bold yellow]WARNING:[/] QEMU emulation detected — rdtsc cycle "
            "counts here are NOT a reliable signal for timing analysis. "
            "Consider [bold]clock: auto[/] (or 'monotonic') in your "
            "ctkat.yaml, or run on a native x86_64 Linux host."
        )
    elif qemu and effective_clock == "monotonic":
        console.print(
            "[bold yellow]WARNING:[/] QEMU emulation detected. The raw trace "
            "will be retained, but backend-v2 marks its timing validity "
            "`environment-rejected`; it cannot clear a verdict."
        )

    # CPU pin hint — Linux only (taskset isn't a thing on macOS/Windows) and
    # only when not in QEMU (taskset inside QEMU pins the QEMU thread, not
    # the emulated CPU, so the hint would mislead). We don't enforce pinning
    # from Python because the user may already have wrapped us in taskset
    # or have a reason not to.
    if platform.system() == "Linux" and not qemu:
        console.print(
            "[dim][Tip] pin to one CPU for cleaner measurements: "
            "`taskset -c 0 python -m ctkat dudect ...`[/]"
        )

    # F19: `or 0xC0FFEE` guards the ~2^-63 case where randbits returns 0 —
    # the C harness swaps seed 0 to 0xC0FFEE (xorshift stuck-at-zero), so
    # without this Python would log `seed = 0x0` while the binary ran with
    # 0xC0FFEE. Astronomically unlikely, but the layers must not disagree
    # (same invariant F16 enforced for yaml seed).
    effective_seed = dud.seed if dud.seed is not None else (secrets.randbits(63) or 0xC0FFEE)
    calibration_seed = (
        (effective_seed + _CALIBRATION_SEED_DOMAIN) & _UINT64_MASK
    ) or _CALIBRATION_SEED_DOMAIN
    console.print(f"[dim]dudect seed = 0x{effective_seed:X}[/]")
    clock_display = f"{dud.clock}→{effective_clock}" if dud.clock == "auto" else effective_clock
    console.print(
        f"[dim]measurements={dud.measurements} warmup={dud.warmup} "
        f"batches={dud.batches} clock={clock_display} "
        f"backend={dud.backend}[/]"
    )

    if dud.backend == "official-dudect" and not crop:
        console.print(
            "[bold red][CTKAT] config error:[/] `--no-crop` is only available "
            "for `backend: experimental-first-order`. The official backend "
            "always executes upstream's uncropped + 100 crop + second-order "
            "family."
        )
        raise typer.Exit(2)

    warn_t = dud.threshold_warning
    fail_t = dud.threshold_fail
    crop_warn_t = warn_t
    crop_fail_t = fail_t
    if dud.sqrt_m_threshold_scaling:
        if crop:
            scale = math.sqrt(len(CROP_PERCENTILES))
            crop_warn_t = warn_t * scale
            crop_fail_t = fail_t * scale
            console.print(
                f"[dim]experimental sqrt(m) threshold scaling: "
                f"by sqrt({len(CROP_PERCENTILES)})={scale:.3f} → "
                f"warning={crop_warn_t:.2f} fail={crop_fail_t:.2f} "
                f"(not Bonferroni/FWER control; batch + uncropped keep "
                f"{warn_t}/{fail_t})[/]"
            )
        else:
            console.print(
                "[yellow]Note:[/] sqrt_m_threshold_scaling is set but "
                "cropping is off; the heuristic is ignored."
            )

    workdir = _resolve(cfg_dir, dud.workdir)
    gen_dir = _resolve(cfg_dir, dud.generated_dir)
    environment = collect_timing_environment(emulated=qemu, clock=effective_clock)

    official_adapter: Optional[Path] = None
    if dud.backend == "official-dudect":
        try:
            official_adapter = build_official_dudect_adapter(
                cc=dud.compiler.cc,
                output_dir=gen_dir / "_backend",
                timeout=dud.compile_timeout,
            )
        except OfficialDudectError as e:
            console.print(f"[bold red][CTKAT] official dudect backend unavailable:[/] {e}")
            raise typer.Exit(2)
        console.print(
            f"[dim]official dudect revision={OFFICIAL_DUDECT_REVISION} "
            "tests=102 (raw + 100 crop + second-order); first trace batch "
            "is calibration-only[/]"
        )

    results: List[Tuple[str, TimingSamples, WelchResult, List[WelchResult]]] = []
    for h in dud.harnesses:
        console.print(f"[bold cyan]==> Generate timing harness[/]: [bold]{h.name}[/]")
        source_paths = [_resolve(cfg_dir, source) for source in h.sources]
        include_dir_paths = [_resolve(cfg_dir, directory) for directory in h.include_dirs]
        try:
            gen = generate_and_compile_timing(
                name=h.name,
                template=h.template,
                context=_dudect_context(h, dud, effective_seed, effective_clock),
                output_dir=gen_dir,
                sources=source_paths,
                include_dirs=include_dir_paths,
                cflags=dud.compiler.cflags,
                cc=dud.compiler.cc,
                workdir=workdir,
                timeout=dud.compile_timeout,
            )
        except CompilerNotFoundError as e:
            # FN-5(exit-code): toolchain error → exit 2, consistent with the ct
            # path and the asm-scan / ct-matrix preflights.
            console.print(
                f"[bold red][CTKAT] Timing harness gen FAIL ({h.name})[/] — toolchain error"
            )
            console.print(str(e))
            raise typer.Exit(2)
        except HarnessGenerationError as e:
            console.print(f"[bold red][CTKAT] Timing harness gen FAIL ({h.name})[/]")
            console.print(str(e))
            raise typer.Exit(1)
        console.print(f"   [dim]source: {gen.source_path}[/]")
        console.print(f"   [dim]binary: {gen.binary_path}[/]")

        contract_report: Optional[Path] = None
        if h.binary_contract is not None:
            try:
                contract_report = verify_timing_binary_contract(
                    manifest_path=_resolve(cfg_dir, h.binary_contract.manifest),
                    target=h.binary_contract.target,
                    binary_path=gen.binary_path,
                    generated_source_path=gen.source_path,
                    config_path=config_path,
                    source_paths=source_paths,
                    compiler=dud.compiler.cc,
                    cflags=list(dud.compiler.cflags),
                    compile_command=gen.compile_command,
                    output_dir=out_dir / "binary_contract",
                )
            except TimingBinaryContractError as e:
                console.print(f"[bold red][CTKAT] timing binary contract FAIL ({h.name})[/]")
                console.print(str(e))
                raise typer.Exit(1)
            console.print(f"   [dim]binary contract: {contract_report}[/]")

        try:
            build_provenance = capture_timing_build_provenance(
                compiler=dud.compiler.cc,
                cflags=dud.compiler.cflags,
                include_dirs=include_dir_paths,
                linked_sources=source_paths,
                generated_source=gen.source_path,
                binary=gen.binary_path,
                config_path=config_path.resolve() if config_path is not None else None,
                compile_command=gen.compile_command,
            )
            build_provenance_path = (
                out_dir / "build_provenance" / f"timing_{h.name}.build-seal.json"
            )
            build_provenance_sha256 = write_timing_build_provenance(
                build_provenance_path,
                build_provenance,
            )
            build_provenance_record = _timing_build_protocol_record(
                build_provenance,
                build_provenance_path,
                build_provenance_sha256,
                out_dir,
            )
        except TimingBuildProvenanceError as e:
            console.print(f"[bold red][CTKAT] timing build seal FAIL ({h.name})[/]")
            console.print(str(e))
            raise typer.Exit(1)
        console.print(f"   [dim]build seal: {build_provenance_path}[/]")

        console.print(
            f"[bold cyan]==> Run timing harness[/]: [bold]{h.name}[/] (this may take a while)"
        )
        # Bundle E-1 (T6): wrap every uncaught failure mode of the timing
        # harness (timeout, crash rc!=0, empty stdout, malformed CSV header)
        # into a status=ERROR result instead of a raw Python traceback.
        # In the `run` pipeline the ERROR flows through _compute_verdicts →
        # INCONCLUSIVE so the verdict CSV reflects "couldn't verify". The
        # standalone `dudect` subcommand does NOT go through the verdict
        # matrix, so it gates on this status directly via its own `any_err`
        # check (T41) — keep both paths in sync when changing the sentinel.
        # Bundle F (S4) will preserve already-completed harnesses' data the
        # same way; the `continue` here is the foundation.
        backend_id = (
            OFFICIAL_DUDECT_BACKEND
            if dud.backend == "official-dudect"
            else EXPERIMENTAL_FIRST_ORDER_BACKEND
        )
        if h.template in {"kem", "sign"}:
            protocol = dud.timing_protocol
            console.print(
                "   [dim]timing-harness-v2: "
                f"pool={protocol.pool_size}, processes={protocol.process_repeats}, "
                f"control_measurements={protocol.control_measurements or dud.measurements}, "
                "modes=target/A-A/setup-placebo/positive"
                f"{protocol.positive_control_effects}[/]"
            )
            try:
                samples, overall, batches = _run_v2_harness_protocol(
                    binary=gen.binary_path,
                    workdir=workdir,
                    dud=dud,
                    harness=h,
                    effective_seed=effective_seed,
                    official_adapter=official_adapter,
                    crop=crop,
                    crop_warn_t=crop_warn_t,
                    crop_fail_t=crop_fail_t,
                    warn_t=warn_t,
                    fail_t=fail_t,
                    build_provenance=build_provenance,
                    build_provenance_path=build_provenance_path,
                    build_provenance_sha256=build_provenance_sha256,
                )
            except subprocess.TimeoutExpired:
                console.print(
                    f"[bold red][CTKAT] dudect: ERROR[/] — harness "
                    f"[bold]{h.name}[/] timing-harness-v2 process exceeded "
                    f"timeout={dud.timeout}s"
                )
                results.append(
                    (
                        h.name,
                        TimingSamples(),
                        _error_welch(
                            backend=backend_id,
                            reason=f"timing-harness-v2 process timed out after {dud.timeout}s",
                            analysis_seed=effective_seed,
                        ),
                        [],
                    )
                )
                continue
            except (RuntimeError, ValueError, OfficialDudectError) as e:
                console.print(
                    f"[bold red][CTKAT] dudect: ERROR[/] — harness "
                    f"[bold]{h.name}[/] timing-harness-v2 failed: {e}"
                )
                results.append(
                    (
                        h.name,
                        TimingSamples(),
                        _error_welch(
                            backend=backend_id,
                            reason=f"timing-harness-v2 failed: {e}",
                            analysis_seed=effective_seed,
                        ),
                        [],
                    )
                )
                continue

            if contract_report is not None:
                import hashlib as _hashlib
                import json as _json

                contract_payload = _json.loads(contract_report.read_text(encoding="utf-8"))
                overall.harness_protocol["binary_contract"] = {
                    "passed": contract_payload.get("passed") is True,
                    "contract_id": contract_payload.get("contract_id"),
                    "contract_target": contract_payload.get("contract_target"),
                    "report": str(contract_report.relative_to(out_dir)),
                    "report_sha256": _hashlib.sha256(contract_report.read_bytes()).hexdigest(),
                    "binary_sha256": contract_payload.get("binary", {}).get("sha256"),
                    "full_disassembly_sha256": contract_payload.get("disassembly", {}).get(
                        "full_sha256"
                    ),
                }
            overall.harness_protocol["build_provenance"] = build_provenance_record
            _set_timing_validity(
                overall,
                samples,
                h,
                environment,
                expected_measurements=dud.measurements,
            )
            results.append((h.name, samples, overall, batches))
            console.print(
                f"   n0={overall.n0} n1={overall.n1} "
                f"mean0={overall.mean0:.1f} mean1={overall.mean1:.1f} "
                f"t={overall.t_score:+.2f} [bold]{overall.status}[/] "
                f"validity={overall.timing_validity}; "
                f"A/A failures={overall.harness_protocol['aa_failures']}, "
                "positive power="
                f"{overall.harness_protocol['positive_power_passed']}"
            )
            continue

        calibration: Optional[TimingSamples] = None
        phase = "analysis"
        try:
            if dud.backend == "official-dudect":
                phase = "percentile calibration"
                console.print(
                    "   [dim]batch 1/2: percentile calibration "
                    f"(discarded, seed=0x{calibration_seed:X})[/]"
                )
                calibration = _run_timing_harness_with_build_seal(
                    gen.binary_path,
                    workdir,
                    timeout=dud.timeout,
                    seed_override=calibration_seed,
                    build_provenance=build_provenance,
                    build_provenance_path=build_provenance_path,
                    build_provenance_sha256=build_provenance_sha256,
                )
                phase = "analysis"
                console.print("   [dim]batch 2/2: independent analysis trace[/]")
            samples = _run_timing_harness_with_build_seal(
                gen.binary_path,
                workdir,
                timeout=dud.timeout,
                build_provenance=build_provenance,
                build_provenance_path=build_provenance_path,
                build_provenance_sha256=build_provenance_sha256,
            )
            samples.calibration = calibration
        except subprocess.TimeoutExpired:
            console.print(
                f"[bold red][CTKAT] dudect: ERROR[/] — harness "
                f"[bold]{h.name}[/] {phase} exceeded timeout={dud.timeout}s. "
                f"Bump dudect.timeout or reduce measurements. (T6)"
            )
            failed_samples = TimingSamples(calibration=calibration)
            results.append(
                (
                    h.name,
                    failed_samples,
                    _error_welch(
                        backend=backend_id,
                        reason=f"{phase} timed out after {dud.timeout}s",
                        analysis_seed=effective_seed,
                        calibration_seed=(
                            calibration_seed if dud.backend == "official-dudect" else None
                        ),
                    ),
                    [],
                )
            )
            continue
        except RuntimeError as e:
            console.print(
                f"[bold red][CTKAT] dudect: ERROR[/] — harness "
                f"[bold]{h.name}[/] {phase} crashed: {e} (T6)"
            )
            failed_samples = TimingSamples(calibration=calibration)
            results.append(
                (
                    h.name,
                    failed_samples,
                    _error_welch(
                        backend=backend_id,
                        reason=f"{phase} crashed: {e}",
                        analysis_seed=effective_seed,
                        calibration_seed=(
                            calibration_seed if dud.backend == "official-dudect" else None
                        ),
                    ),
                    [],
                )
            )
            continue
        except ValueError as e:
            console.print(
                f"[bold red][CTKAT] dudect: ERROR[/] — harness "
                f"[bold]{h.name}[/] {phase} output unparseable: {e} (T6)"
            )
            failed_samples = TimingSamples(calibration=calibration)
            results.append(
                (
                    h.name,
                    failed_samples,
                    _error_welch(
                        backend=backend_id,
                        reason=f"{phase} output unparseable: {e}",
                        analysis_seed=effective_seed,
                        calibration_seed=(
                            calibration_seed if dud.backend == "official-dudect" else None
                        ),
                    ),
                    [],
                )
            )
            continue

        c0 = [c for cls, c in zip(samples.classes, samples.cycles) if cls == 0]
        c1 = [c for cls, c in zip(samples.classes, samples.cycles) if cls == 1]
        if len(c0) < 2 or len(c1) < 2:
            console.print(
                f"[bold red][CTKAT] dudect: ERROR[/] — harness "
                f"[bold]{h.name}[/] insufficient samples per class: "
                f"n0={len(c0)} n1={len(c1)} (T6)"
            )
            results.append(
                (
                    h.name,
                    samples,
                    _error_welch(
                        backend=backend_id,
                        reason=f"insufficient samples per class: n0={len(c0)} n1={len(c1)}",
                        analysis_seed=effective_seed,
                        calibration_seed=(
                            calibration_seed if dud.backend == "official-dudect" else None
                        ),
                    ),
                    [],
                )
            )
            continue

        if dud.backend == "official-dudect":
            assert official_adapter is not None
            assert calibration is not None
            try:
                official_analysis = analyze_with_official_dudect(
                    calibration,
                    samples,
                    adapter_binary=official_adapter,
                    workdir=workdir,
                    timeout=dud.backend_timeout,
                )
            except OfficialDudectError as e:
                console.print(
                    f"[bold red][CTKAT] dudect: ERROR[/] — official backend "
                    f"failed for [bold]{h.name}[/]: {e}"
                )
                results.append(
                    (
                        h.name,
                        samples,
                        _error_welch(
                            backend=backend_id,
                            reason=f"official backend failed: {e}",
                            analysis_seed=effective_seed,
                            calibration_seed=calibration_seed,
                        ),
                        [],
                    )
                )
                continue
            overall = _official_to_welch(official_analysis)
        else:
            if crop:
                overall = welch_with_cropping(
                    c0,
                    c1,
                    warning_threshold=crop_warn_t,
                    fail_threshold=crop_fail_t,
                )
                overall.test_kind = "experimental-first-order-cropped"
                overall.test_index = (
                    CROP_PERCENTILES.index(overall.cropped_at)
                    if overall.cropped_at in CROP_PERCENTILES
                    else None
                )
                overall.protocol_test_count = len(CROP_PERCENTILES)
            else:
                overall = welch_t_test(c0, c1, warn_t, fail_t)
                overall.test_kind = "experimental-first-order-uncropped"
                overall.test_index = 0
                overall.protocol_test_count = 1
            overall.backend = EXPERIMENTAL_FIRST_ORDER_BACKEND

        overall.analysis_seed = effective_seed
        overall.calibration_seed = calibration_seed if dud.backend == "official-dudect" else None
        batches = batch_t_scores(
            samples.classes,
            samples.cycles,
            batches=dud.batches,
            warning_threshold=warn_t,
            fail_threshold=fail_t,
        )
        overall.harness_protocol["build_provenance"] = build_provenance_record
        _set_timing_validity(
            overall,
            samples,
            h,
            environment,
            expected_measurements=dud.measurements,
        )
        results.append((h.name, samples, overall, batches))

        if overall.test_kind == "first-order-cropped":
            test_tag = f" test=crop[{overall.test_index}]"
        elif overall.test_kind == "second-order":
            test_tag = " test=second-order"
        else:
            test_tag = f" crop@{overall.cropped_at:.2f}" if overall.cropped_at is not None else ""
        console.print(
            f"   n0={overall.n0} n1={overall.n1} "
            f"mean0={overall.mean0:.1f} mean1={overall.mean1:.1f} "
            f"t={overall.t_score:+.2f}{test_tag} [bold]{overall.status}[/] "
            f"validity={overall.timing_validity}"
        )

    _emit_dudect_report(project_name, out_dir, results)
    return results


def _print_dudect_summary(
    results: List[Tuple[str, TimingSamples, WelchResult, List[WelchResult]]],
) -> None:
    if not results:
        return
    table = Table(title="dudect timing summary")
    for col in (
        "harness",
        "backend",
        "n0",
        "n1",
        "mean0",
        "mean1",
        "|t|",
        "max test",
        "tau",
        "status",
        "validity",
        "batch max|t|",
    ):
        table.add_column(col)
    for name, _, r, batches in results:
        batch_max = f"{max(b.abs_t_score for b in batches):.2f}" if batches else "-"
        style = {
            "PASS": "green",
            "WARNING": "yellow",
            "FAIL": "bold red",
            "ERROR": "bold magenta",
            "INSUFFICIENT": "bold yellow",
        }.get(r.status, "")
        status_cell = f"[{style}]{r.status}[/]" if style else r.status
        if r.test_kind == "first-order-cropped":
            test_cell = f"crop[{r.test_index}]"
        elif r.cropped_at is not None:
            test_cell = f"crop@{r.cropped_at:.2f}"
        else:
            test_cell = r.test_kind or "-"
        backend_cell = r.backend or "-"
        tau_cell = _fmt(r.max_tau, digits=3) or "-"
        # T22: an ERROR row means measurement never completed — the
        # underlying WelchResult is _error_welch's all-zeros sentinel.
        # Rendering `n0=0 mean=0.00 |t|=0.00` makes the row visually
        # indistinguishable from a real successful measurement that
        # happened to score 0, so we collapse the numeric cells to `-`
        # and let the magenta status cell carry the signal.
        if r.status == "ERROR":
            table.add_row(
                name,
                backend_cell,
                "-",
                "-",
                "-",
                "-",
                "-",
                test_cell,
                tau_cell,
                status_cell,
                r.timing_validity or "error",
                "-",
            )
            continue
        table.add_row(
            name,
            backend_cell,
            str(r.n0),
            str(r.n1),
            f"{r.mean0:.1f}",
            f"{r.mean1:.1f}",
            f"{r.abs_t_score:.2f}",
            test_cell,
            tau_cell,
            status_cell,
            r.timing_validity or "-",
            batch_max,
        )
    console.print(table)


@app.command()
def dudect(
    config: Path = typer.Option(..., "--config", "-c", help="Path to ctkat.yaml"),
    measurements: Optional[int] = typer.Option(
        None, "--measurements", help="Override yaml measurement count."
    ),
    seed: Optional[str] = typer.Option(
        None,
        "--seed",
        help="Override yaml seed. Integer (decimal or 0x-prefixed hex) or 'random'.",
    ),
    crop: bool = typer.Option(
        True,
        "--crop/--no-crop",
        help="Legacy experimental backend only: toggle its five-cutoff "
        "cropping. The official backend always runs all 102 upstream tests.",
    ),
):
    """Run only the configured timing measurement/statistical backend."""
    cfg = _load_config_or_exit(config)
    cfg_dir = config.parent.resolve()
    if cfg.dudect is None:
        console.print("[red]No `dudect` section in config.[/]")
        raise typer.Exit(2)

    dud = cfg.dudect
    if not dud.enabled:
        console.print(
            "[bold red][CTKAT] dudect Timing Check: ERROR[/] — "
            "`dudect.enabled: false` in config, so no timing harness was run. "
            "Set it to true or use `ctkat run` to intentionally skip the stage."
        )
        raise typer.Exit(2)

    updates: Dict[str, object] = {}
    if measurements is not None:
        updates["measurements"] = measurements
    if seed is not None:
        if seed.lower() == "random":
            updates["seed"] = None
        else:
            # T33: `int(seed, 0)` on "abc" / "1e5" / "" raised a raw
            # ValueError traceback. Catch it and exit cleanly (mirrors typer's
            # own invalid-option handling and the T40 parse fix).
            try:
                updates["seed"] = int(seed, 0)
            except ValueError:
                console.print(
                    f"[red]Invalid --seed {seed!r}:[/] use an integer "
                    "(decimal, or 0x-prefixed hex) or 'random'."
                )
                raise typer.Exit(2)
    if updates:
        # F17: `model_copy(update=...)` does NOT re-run validators in
        # pydantic v2, so `--measurements 100000000` would bypass the T8
        # Field(le=10_000_000) bound and silently allocate ~800MB BSS.
        # Round-tripping through `model_validate` forces full validation
        # of the merged dict so CLI overrides are constrained identically
        # to yaml input.
        #
        # FN-6: but `model_validate` raises pydantic's ValidationError on a
        # bound violation (`--seed 0`, `--measurements 99`), and only the
        # int()-parse branch above was guarded — so a value that parses as an
        # int yet violates a Field bound fell through to a raw traceback,
        # re-opening the very crash T33 had closed. Catch it and exit cleanly.
        try:
            dud = DudectConfig.model_validate({**dud.model_dump(), **updates})
        except ValidationError as e:
            console.print(
                f"[red]Invalid dudect override:[/] {e}\n"
                "Check --measurements / --seed are within the allowed bounds."
            )
            raise typer.Exit(2)

    out_dir = _resolve(cfg_dir, cfg.report.output_dir)
    results = _do_dudect(
        dud,
        cfg_dir,
        cfg.project.name,
        out_dir,
        crop=crop,
        config_path=config.resolve(),
    )
    _print_dudect_summary(results)

    # T41: an empty result set means no harness actually ran — nothing was
    # measured, so reporting PASS would be a fail-open (same shape as F8 for
    # the `ct` subcommand). Refuse it with a gating exit code.
    if not results:
        console.print(
            "[bold red][CTKAT] dudect Timing Check: ERROR[/] — no dudect "
            "harnesses ran (empty `dudect.harnesses`?). Nothing was measured; "
            "refusing to report PASS."
        )
        raise typer.Exit(2)

    any_fail = any(r.status == "FAIL" for _, _, r, _ in results)
    any_warn = any(r.status == "WARNING" for _, _, r, _ in results)
    # T41: an ERROR status (timeout / crash / insufficient samples = the
    # `_error_welch` sentinel) must gate exactly like the `ct` subcommand's
    # `any_ct_error` and the `run` pipeline's INCONCLUSIVE. The standalone
    # `dudect` subcommand never goes through the verdict matrix, so without
    # this check an ERROR harness fell through to the bold-green PASS below
    # and exited 0 — `ctkat dudect -c x.yaml && deploy` would green-light a
    # run whose timing analysis never completed.
    any_err = any(r.status == "ERROR" for _, _, r, _ in results)
    if any_err:
        console.print(
            "[bold yellow][CTKAT] dudect Timing Check: INCOMPLETE[/] "
            "(see ERROR lines above) — analysis did not complete for at "
            "least one harness; this is NOT a PASS."
        )
        raise typer.Exit(2)
    invalid = [
        (name, r.status, r.timing_validity)
        for name, _, r, _ in results
        if r.timing_validity != "valid"
    ]
    if invalid:
        details = "; ".join(
            f"{name}=raw:{status}/validity:{validity}" for name, status, validity in invalid
        )
        console.print(
            "[bold yellow][CTKAT] dudect Timing Check: INCONCLUSIVE[/] — "
            f"{details}. Raw signal is retained but cannot clear or convict "
            "the target."
        )
        raise typer.Exit(2)
    if any_fail:
        console.print("[bold red][CTKAT] dudect Timing Check: FAIL[/]")
        raise typer.Exit(2)
    if any_warn:
        # WARNING must NOT exit 0 — that would be indistinguishable from
        # PASS in a CI script, defeating the whole point of having a
        # warning tier. Exit 2 so the shell can branch on it.
        console.print("[bold yellow][CTKAT] dudect Timing Check: WARNING[/]")
        raise typer.Exit(2)
    console.print("[bold green][CTKAT] dudect Timing Check: PASS[/]")


def _compute_verdicts(
    ct_results: List[Tuple[str, str, List[Finding]]],
    dudect_results: List[Tuple[str, TimingSamples, WelchResult, List[WelchResult]]],
    kat_status: str = "NONE",
) -> List[HarnessVerdict]:
    """Merge ct + dudect outcomes per harness name; missing side becomes NONE.

    Bundle E-1 (F11): `kat_status` is now part of every harness verdict —
    a KAT FAIL flips the verdict to INCONCLUSIVE for every harness
    regardless of ct/dudect outcomes, because the analyses ran on
    functionally broken code. Defaults to NONE so callers that don't have
    a KAT stage keep their existing behavior.

    Bundle E-2 (F2/F5): `ct_results` now carries a per-harness status —
    valgrind crash, missing log, and missing sentinel all flow in as
    "ERROR" and the matrix maps any ERROR pair to INCONCLUSIVE.
    """
    ct_map = {name: (status, findings) for name, status, findings in ct_results}
    dud_map = {name: (r, batches) for name, _, r, batches in dudect_results}

    names: List[str] = []
    for name in ct_map:
        names.append(name)
    for name in dud_map:
        if name not in ct_map:
            names.append(name)

    verdicts: List[HarnessVerdict] = []
    for name in names:
        ct_entry = ct_map.get(name)
        dud_pair = dud_map.get(name)
        if ct_entry is None:
            v_status = "NONE"
            findings: Optional[List[Finding]] = None
        else:
            v_status, findings = ct_entry
        if dud_pair is None:
            d_status = "NONE"
            abs_t: Optional[float] = None
            d_validity = ""
            decision_status = d_status
        else:
            d_status = dud_pair[0].status
            abs_t = dud_pair[0].abs_t_score
            d_validity = dud_pair[0].timing_validity
            decision_status = d_status if d_validity in {"", "valid"} else "ERROR"
        verdicts.append(
            HarnessVerdict(
                name=name,
                valgrind_status=v_status,
                dudect_status=d_status,
                verdict=combine(v_status, decision_status, kat_status=kat_status),
                valgrind_finding_count=(len(findings) if findings else 0),
                dudect_abs_t=abs_t,
                dudect_validity=d_validity,
            )
        )
    return verdicts


def _emit_verdicts(
    out_dir: Path,
    project: str,
    verdicts: List[HarnessVerdict],
    kat_status: str = "NONE",
    kat_count: Optional[int] = None,
) -> Path:
    """Write the per-harness verdict CSV.

    Bundle E-1 (F11): columns 8-9 (`kat_status`, `kat_count`) appended at
    the end so the column positions 1-7 stay backward-compatible with
    `scripts/run_phase4.sh` awk (which keys on `$7=verdict`). `kat_status`
    is a pipeline-wide signal (every row gets the same value), but we
    write it per-row so a single-file consumer can read it without
    cross-referencing a separate manifest.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "ctkat_verdict.csv"
    kat_count_str = "" if kat_count is None else str(kat_count)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(
            [
                "project",
                "harness",
                "valgrind_status",
                "valgrind_findings",
                "dudect_status",
                "dudect_abs_t",
                "verdict",
                "kat_status",
                "kat_count",
                "dudect_validity",
            ]
        )
        for v in verdicts:
            w.writerow(
                [
                    project,
                    v.name,
                    v.valgrind_status,
                    v.valgrind_finding_count,
                    v.dudect_status,
                    _fmt(v.dudect_abs_t) if v.dudect_abs_t is not None else "",
                    v.verdict.value,
                    kat_status,
                    kat_count_str,
                    v.dudect_validity,
                ]
            )
    return path


def _print_verdicts(verdicts: List[HarnessVerdict]) -> None:
    if not verdicts:
        return
    table = Table(title="Combined verdict (Valgrind + dudect)")
    for col in ("harness", "valgrind", "dudect", "validity", "|t|", "verdict"):
        table.add_column(col)
    for v in verdicts:
        abs_t = (_fmt(v.dudect_abs_t, digits=2) or "inf") if v.dudect_abs_t is not None else "-"
        style = VERDICT_STYLES.get(v.verdict, "")
        verdict_cell = f"[{style}]{v.verdict.value}[/]" if style else v.verdict.value
        table.add_row(
            v.name,
            v.valgrind_status,
            v.dudect_status,
            v.dudect_validity or "-",
            abs_t,
            verdict_cell,
        )
    console.print(table)


@app.command()
def run(
    config: Path = typer.Option(..., "--config", "-c", help="Path to ctkat.yaml"),
    continue_on_kat_fail: bool = typer.Option(False, "--continue-on-kat-fail"),
    crop: bool = typer.Option(
        True,
        "--crop/--no-crop",
        help="Apply dudect percentile cropping (default on). Use --no-crop "
        "for raw uncropped t-scores.",
    ),
):
    """Run the full pipeline: build -> kat -> ct -> dudect -> report."""
    cfg = _load_config_or_exit(config)
    cfg_dir = config.parent.resolve()

    _print_cflags_banner(cfg)

    if not _do_build(cfg, cfg_dir):
        raise typer.Exit(1)

    # KAT outcome feeds into the combined verdict: a KAT FAIL means the
    # build artifact didn't pass functional correctness, so ct/dudect ran
    # on incorrect code — their PASS is meaningless (F11). We track
    # (status, count) here and forward both into _compute_verdicts /
    # _emit_verdicts so verdict CSV reflects the full pipeline state even
    # when --continue-on-kat-fail keeps the pipeline running.
    kat_status = "NONE"
    kat_count: Optional[int] = None
    if cfg.kat is not None:
        ok, kat_count = _do_kat(cfg, cfg_dir)
        kat_status = "PASS" if ok else "FAIL"
        if not ok and not continue_on_kat_fail:
            raise typer.Exit(1)

    ct_results: List[Tuple[str, str, List[Finding]]] = []
    any_finding = False
    any_ct_error = False
    if cfg.ct is not None:
        # R-6: an empty `ct.harnesses` analyzes nothing but used to fall
        # through to a green PASS / exit 0 (same fail-open class R-1 closed
        # for the standalone dudect subcommand). Refuse it.
        if not cfg.ct.harnesses:
            console.print(
                "[bold red][CTKAT] config error:[/] `ct` section has no "
                "harnesses — nothing to analyze. Add at least one harness or "
                "remove the `ct` section."
            )
            raise typer.Exit(2)
        generated = _do_generate(cfg, cfg_dir)
        ct_results = _do_ct(cfg, cfg_dir, generated)
        any_finding = any(s == "FAIL" for _, s, _ in ct_results)
        any_ct_error = any(s == "ERROR" for _, s, _ in ct_results)
        if any_finding:
            console.print("[bold red][CTKAT] Constant-Time Check: FAIL[/]")
        elif any_ct_error:
            console.print(
                "[bold yellow][CTKAT] Constant-Time Check: INCOMPLETE[/] (see ERROR lines above)"
            )
        else:
            console.print("[bold green][CTKAT] Constant-Time Check: PASS[/]")
        _emit_report(cfg, cfg_dir, ct_results)

    dud_results: List[Tuple[str, TimingSamples, WelchResult, List[WelchResult]]] = []
    any_dudect_fail = False
    any_dudect_warn = False
    if cfg.dudect is not None and cfg.dudect.enabled:
        # R-6: dudect enabled but no harnesses measures nothing — same
        # fail-open. (Set dudect.enabled=false to intentionally skip the stage.)
        if not cfg.dudect.harnesses:
            console.print(
                "[bold red][CTKAT] config error:[/] `dudect` is enabled but "
                "has no harnesses — nothing to measure. Add a harness or set "
                "`dudect.enabled: false`."
            )
            raise typer.Exit(2)
        out_dir = _resolve(cfg_dir, cfg.report.output_dir)
        dud_results = _do_dudect(
            cfg.dudect,
            cfg_dir,
            cfg.project.name,
            out_dir,
            crop=crop,
            config_path=config.resolve(),
        )
        _print_dudect_summary(dud_results)
        any_dudect_fail = any(r.status == "FAIL" for _, _, r, _ in dud_results)
        any_dudect_warn = any(r.status == "WARNING" for _, _, r, _ in dud_results)

    # Combined verdict — only meaningful when at least one stage ran.
    any_inconclusive = False
    if cfg.ct is not None or (cfg.dudect is not None and cfg.dudect.enabled):
        verdicts = _compute_verdicts(ct_results, dud_results, kat_status=kat_status)
        if verdicts:
            _print_verdicts(verdicts)
            out_dir = _resolve(cfg_dir, cfg.report.output_dir)
            verdict_csv = _emit_verdicts(
                out_dir,
                cfg.project.name,
                verdicts,
                kat_status=kat_status,
                kat_count=kat_count,
            )
            console.print(f"[dim]Verdict CSV: {verdict_csv}[/]")
            any_inconclusive = any(v.verdict == Verdict.INCONCLUSIVE for v in verdicts)

    if any_finding or any_dudect_fail:
        raise typer.Exit(2)
    if any_inconclusive:
        # F11/F2/F5/T6: INCONCLUSIVE must be shell-distinguishable from
        # PASS — a CI script gating on `verdict=CLEAN` should NOT merge
        # code whose analysis couldn't complete. Same exit code as FAIL
        # (decision documented in known_issues F3) so existing CI
        # patterns (`run && deploy`) keep behaving sensibly.
        raise typer.Exit(2)
    if any_dudect_warn:
        # Same reasoning as the `dudect` subcommand: WARNING must be shell-
        # distinguishable from PASS so CI can branch on it.
        raise typer.Exit(2)


# --- `screen` — one-command pipeline + evidence schema v2 ---------------------

SCREEN_SUMMARY_FIELDS = [
    # Evidence-v2 core plus raw provenance. The corpus adapter adds
    # family/target/cc_version/arch/commit.
    "schema_version",
    "harness",
    "correctness",
    "structural",
    "asm",
    "asm_attribution",
    "timing_validity",
    "timing_signal",
    "review",
    "review_id",
    "overall",
    "ct_flips",
    "ct_status_set",
    "ct_finding_funcs",
    "varlat_candidates",
    "varlat_triage",
    "timing_backend",
    "timing_raw_status",
    "timing_abs_t",
    "timing_measurements",
    "timing_leak_target",
    "timing_seed",
    "timing_threshold",
    "legacy_verdict_class",
    "legacy_basis",
    "notes",
]
SCREEN_CELLS_FIELDS = [
    "schema_version",
    "harness",
    "combo",
    "cc",
    "opt",
    "cflags",
    "ct_status",
    "ct_findings",
    "ct_finding_funcs",
    "ct_error",
    "asm_status",
    "asm_div_count",
    "asm_div_funcs",
    "asm_error",
]


def _load_triage_or_exit(path: Path) -> TriageConfig:
    """Load triage.yaml, mapping any load failure to a clean exit 2 (mirrors
    _load_config_or_exit)."""
    try:
        return load_triage(path)
    except FileNotFoundError:
        console.print(f"[bold red][CTKAT] triage file not found:[/] {path}. (exit 2)")
        raise typer.Exit(2)
    except yaml.YAMLError as e:
        console.print(f"[bold red][CTKAT] triage is not valid YAML:[/] {path}\n{e} (exit 2)")
        raise typer.Exit(2)
    except (ValidationError, ValueError) as e:
        console.print(f"[bold red][CTKAT] invalid triage file:[/] {path}\n{e} (exit 2)")
        raise typer.Exit(2)


def _run_screen_matrix(cfg, cfg_dir, auto, matrix_cfg, out_dir):
    """ct-matrix sweep for screen (reuses the ct-matrix handler logic). Returns
    List[CtMatrixRow]. Preflight already done by the caller."""
    combos = expand_combos(matrix_cfg.compilers, matrix_cfg.ct_cflags)
    if not combos:
        return []
    ct_cwd = _resolve(cfg_dir, cfg.ct.workdir)
    generated_dir = _resolve(cfg_dir, cfg.ct.generated_dir)
    harness_inputs: List[HarnessInputs] = []
    for h in auto:
        include_dirs = [_resolve(cfg_dir, d) for d in h.include_dirs]
        sources = [_resolve(cfg_dir, s) for s in h.sources]
        base_cflags = h.cflags if h.cflags is not None else cfg.ct.cflags
        source_path = generated_dir / f"harness_{h.name}.c"
        try:
            code = render_harness(h.template, _template_context(h, cfg.ct.seed))
        except HarnessGenerationError as e:
            console.print(f"[bold red][CTKAT] screen: ct-matrix render FAIL ({h.name})[/]\n{e}")
            raise typer.Exit(1)
        _atomic_write_text(source_path, code)
        harness_inputs.append(
            HarnessInputs(
                name=h.name,
                source_path=source_path,
                sources=sources,
                include_dirs=include_dirs,
                # carry preprocessor defines into every cell or the matrix builds a
                # different program than ct (and the cell join becomes meaningless).
                extra_cflags=preprocessor_cflags(base_cflags),
            )
        )
    console.print(
        f"[bold cyan]==> screen: ct-matrix[/] combos = {', '.join(c.label for c in combos)}"
    )
    rows = scan_ct_matrix(
        harness_inputs,
        combos,
        workdir=ct_cwd,
        binaries_dir=generated_dir / "matrix",
        valgrind_flags=cfg.ct.valgrind_flags,
        compile_timeout=cfg.ct.compile_timeout,
        valgrind_timeout=cfg.ct.valgrind_timeout,
        lookup_patterns=cfg.ct.lookup_function_patterns,
        on_progress=lambda s: console.print(f"[dim][CTKAT] ct-matrix:[/dim] {s}"),
    )
    write_ct_matrix_csv(cfg.project.name, rows, out_dir / "ctkat_ct_matrix.csv")
    write_ct_matrix_json(
        cfg.project.name,
        rows,
        out_dir / "ctkat_ct_matrix.json",
        combos=combos,
        compilers=list(dict.fromkeys(matrix_cfg.compilers)),
    )
    return rows


def _run_screen_asmscan(cfg, cfg_dir, auto, asm_ccs, out_dir, extra_opts=()):
    """asm-scan for screen (reuses the asm-scan handler loop). Returns
    (candidates, cc_errors, scanned_compilers). A never-compiling source under a
    cc raises AsmScanError → that cc is recorded as ERROR, others continue.

    `extra_opts` adds the ct-matrix's configured opt levels to the scan so EVERY
    matrix cell has a matching asm scan (else a division surviving only at a
    project-specific custom opt, e.g. `-Oz`, would read as 0 divisions for that
    cell)."""
    ct_cwd = _resolve(cfg_dir, cfg.ct.workdir)
    candidates: list = []
    cc_errors: list = []
    scanned: set = set()
    scanned_ok: list = []
    for cc_name in asm_ccs:
        cc_cands: list = []
        try:
            for h in auto:
                include_dirs = [_resolve(cfg_dir, d) for d in h.include_dirs]
                sources = [_resolve(cfg_dir, s) for s in h.sources]
                source_display = [str(s) for s in h.sources]
                base_cflags = h.cflags if h.cflags is not None else cfg.ct.cflags
                ct_opt = extract_opt_level(base_cflags)
                harness_opts = tuple(dict.fromkeys((ct_opt, *DEFAULT_OPT_LEVELS, *extra_opts)))
                scanned.update(harness_opts)
                cc_cands.extend(
                    scan_harness(
                        harness=h.name,
                        sources=sources,
                        source_display=source_display,
                        include_dirs=include_dirs,
                        base_cflags=base_cflags,
                        workdir=ct_cwd,
                        opt_levels=harness_opts,
                        timeout=cfg.ct.compile_timeout,
                        cc=cc_name,
                        on_warn=lambda m, _cc=cc_name: console.print(
                            f"[dim][CTKAT] asm-scan note ({_cc}):[/dim] {m}"
                        ),
                    )
                )
        except AsmScanError as e:
            cc_errors.append({"compiler": cc_name, "error": f"disassembly failed: {e}"})
            console.print(
                f"[bold yellow][CTKAT] screen: asm-scan compiler '{cc_name}' failed[/] "
                f"— {e} (recorded as PARTIAL; continuing)."
            )
            continue
        candidates.extend(cc_cands)
        scanned_ok.append(cc_name)
    write_varlat_csv(candidates, out_dir / "ctkat_varlat_candidates.csv")
    write_varlat_json(
        cfg.project.name,
        candidates,
        out_dir / "ctkat_varlat_candidates.json",
        opt_levels=tuple(sorted(scanned)),
        compilers=tuple(scanned_ok),
        errors=cc_errors,
    )
    return candidates, cc_errors, scanned_ok


def _emit_screen_report(out_dir: Path, project: str, summary: list, cells: list):
    """Write screen_summary.{csv,json,md} + screen_cells.csv."""
    import json as _json

    out_dir.mkdir(parents=True, exist_ok=True)
    sp = out_dir / "screen_summary.csv"
    with open(sp, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=SCREEN_SUMMARY_FIELDS, lineterminator="\n")
        w.writeheader()
        for r in summary:
            w.writerow({k: r.get(k, "") for k in SCREEN_SUMMARY_FIELDS})
    cp = out_dir / "screen_cells.csv"
    with open(cp, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=SCREEN_CELLS_FIELDS, lineterminator="\n")
        w.writeheader()
        for r in cells:
            w.writerow({k: r.get(k, "") for k in SCREEN_CELLS_FIELDS})
    jp = out_dir / "screen_summary.json"
    with open(jp, "w", encoding="utf-8") as f:
        _json.dump(
            {
                "schema_version": SCHEMA_VERSION,
                "project": project,
                "kind": "screen_summary",
                "summary": summary,
                "cells": cells,
            },
            f,
            indent=2,
        )
    mp = out_dir / "screen_summary.md"
    md = [
        f"# CT-KAT screen — {project}",
        "",
        (
            "| harness | structural | asm / attribution | timing validity / signal "
            "| review | overall | legacy | notes |"
        ),
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in summary:
        md.append(
            f"| {r['harness']} | {r['structural']} | "
            f"{r['asm']} / {r['asm_attribution']} | "
            f"{r['timing_validity']} / {r['timing_signal']} | "
            f"{r['review']} ({r.get('review_id') or '-'}) | "
            f"**{r['overall']}** | {r['legacy_verdict_class']} | "
            f"{r.get('notes', '')} |"
        )
    mp.write_text("\n".join(md) + "\n", encoding="utf-8")
    return sp, jp, mp


@app.command()
def screen(
    config: Path = typer.Option(..., "--config", "-c", help="Path to ctkat.yaml"),
    triage: Optional[Path] = typer.Option(
        None, "--triage", help="Path to triage.yaml (human-judgment layer)."
    ),
    family: Optional[str] = typer.Option(
        None,
        "--family",
        help="Registry family for accepted-variable-time (e.g. ML-DSA). "
        "Default = project name; if it doesn't match a registry family, a "
        "ct FAIL stays needs-analysis (default-deny).",
    ),
    asm_cc: Optional[List[str]] = typer.Option(
        None, "--asm-cc", help="Compiler(s) for asm-scan. Default = matrix compilers."
    ),
    continue_on_kat_fail: bool = typer.Option(False, "--continue-on-kat-fail"),
    crop: bool = typer.Option(True, "--crop/--no-crop"),
):
    """One-command screening pipeline: build -> KAT -> ct -> ct-matrix -> asm-scan
    -> timing -> triage -> evidence v2, emitting a unified screen_summary
    artifact (CSV/JSON/Markdown).

    Layer states and the five-state overall fold are computed by the SAME
    implementation (`ctkat.evidence`) used by the corpus builder and migration
    gate. The legacy verdict class remains only as migration provenance.

    Exit codes (default-deny): 0 only when every harness is
    `no-finding-observed`; 2 for risk, review, inconclusive, or tool-error; 1 on
    a build/KAT hard failure.
    """
    cfg = _load_config_or_exit(config)
    cfg_dir = config.parent.resolve()
    triage_cfg = _load_triage_or_exit(triage) if triage else TriageConfig()
    reg_path = None
    if triage is not None and triage_cfg.registry is not None:
        reg_path = _resolve(triage.parent.resolve(), triage_cfg.registry)
        if not reg_path.exists():
            # An EXPLICIT registry override that doesn't exist would silently
            # yield an empty registry (accepted-variable-time then impossible) —
            # say so loudly. (The default-None case stays silent.)
            console.print(
                f"[bold yellow][CTKAT] screen: triage registry not found: {reg_path} "
                f"— accepted-variable-time classification disabled.[/]"
            )
    registry = load_registry(reg_path)
    fam = family or cfg.project.name

    if cfg.ct is None or not cfg.ct.harnesses:
        console.print(
            "[bold red][CTKAT] screen: needs a `ct` section with harnesses[/] — the "
            "structural evidence layer cannot be empty. (exit 2)"
        )
        raise typer.Exit(2)

    _print_cflags_banner(cfg)
    out_dir = _resolve(cfg_dir, cfg.report.output_dir)
    matrix_cfg = cfg.matrix or MatrixConfig()
    auto = [h for h in cfg.ct.harnesses if h.template is not None and h.sources]
    asm_ccs = list(dict.fromkeys(asm_cc)) if asm_cc else list(dict.fromkeys(matrix_cfg.compilers))

    # Fail-closed toolchain preflight for the stages that will actually run.
    needed = ["valgrind", *matrix_cfg.compilers]
    if any(h.template is not None for h in cfg.ct.harnesses):
        needed.append("gcc")  # _do_generate compiles template harnesses with gcc
    if auto:
        needed += ["objdump", *asm_ccs]
    if cfg.dudect is not None and cfg.dudect.enabled and cfg.dudect.harnesses:
        needed.append(cfg.dudect.compiler.cc)
    missing = [t for t in dict.fromkeys(needed) if shutil.which(t) is None]
    if missing:
        console.print(
            f"[bold red][CTKAT] screen: required tool(s) not found on PATH: "
            f"{', '.join(missing)}.[/] valgrind needs a Linux/Docker environment; "
            f"install the missing compiler(s) (e.g. add to the Docker image). "
            f"This is a config/toolchain error, so exit code is 2."
        )
        raise typer.Exit(2)

    # 1. build
    if not _do_build(cfg, cfg_dir):
        raise typer.Exit(1)
    # 2. kat
    kat_status = "NONE"
    if cfg.kat is not None:
        ok, _kat_count = _do_kat(cfg, cfg_dir)
        kat_status = "PASS" if ok else "FAIL"
        if not ok and not continue_on_kat_fail:
            raise typer.Exit(1)
    # 3. ct (primary structural check + report + sentinel; covers manual harnesses)
    generated = _do_generate(cfg, cfg_dir)
    ct_results = _do_ct(cfg, cfg_dir, generated)
    _emit_report(cfg, cfg_dir, ct_results)
    # 4. ct-matrix (template harnesses -> build-sensitivity)
    matrix_rows = _run_screen_matrix(cfg, cfg_dir, auto, matrix_cfg, out_dir) if auto else []
    # 5. asm-scan (template harnesses with sources). Scan the matrix's opt levels
    #    too so every matrix cell has matching asm coverage (FN/#18).
    matrix_opts = {opt_of(" ".join(fl)) for fl in matrix_cfg.ct_cflags.values()}
    candidates, cc_errors, asm_scanned_ccs = (
        _run_screen_asmscan(cfg, cfg_dir, auto, asm_ccs, out_dir, extra_opts=matrix_opts)
        if auto
        else ([], [], [])
    )
    # 6. dudect
    dud_results = []
    if cfg.dudect is not None and cfg.dudect.enabled and cfg.dudect.harnesses:
        dud_results = _do_dudect(
            cfg.dudect,
            cfg_dir,
            cfg.project.name,
            out_dir,
            crop=crop,
            config_path=config.resolve(),
        )
        _emit_dudect_report(cfg.project.name, out_dir, dud_results)

    # 7. build per-cell records (the shape verdict_class.summarize expects).
    asm_err_by_cc = {e["compiler"]: e["error"] for e in cc_errors}
    asm_scanned_ccs = set(asm_scanned_ccs)
    vindex: dict = {}
    for c in candidates:
        for o in c.opt_levels:
            vindex.setdefault((c.harness, c.compiler, o), []).append((c.function, c.count))
    cells: list = []
    template_names = {h.name for h in auto}
    for r in matrix_rows:
        o = opt_of(" ".join(r.cflags))
        hits = vindex.get((r.harness, r.cc, o), [])
        cells.append(
            {
                "schema_version": SCHEMA_VERSION,
                "target": cfg.project.name,
                "harness": r.harness,
                "combo": r.combo,
                "cc": r.cc,
                "opt": o,
                "cflags": " ".join(r.cflags),
                "ct_status": r.valgrind_status,
                "ct_findings": str(r.findings),
                "ct_finding_funcs": r.finding_funcs,
                "ct_error": r.error,
                "asm_status": (
                    "ERROR"
                    if r.cc in asm_err_by_cc
                    else "PASS"
                    if r.cc in asm_scanned_ccs
                    else "NOT_RUN"
                ),
                "asm_div_count": str(sum(n for _f, n in hits)),
                "asm_div_funcs": ";".join(sorted({f for f, _n in hits})),
                "asm_error": asm_err_by_cc.get(r.cc, ""),
            }
        )

    # Preserve asm-only compiler/opt coverage too. An explicit --asm-cc may be
    # wider than the structural matrix; dropping those candidates/errors would
    # let a requested scan disappear from the overall fold. NA means this cell
    # contributes no structural claim.
    represented_asm = {(c["harness"], c["cc"], c["opt"]) for c in cells}
    for harness in auto:
        base_cflags = harness.cflags if harness.cflags is not None else cfg.ct.cflags
        asm_opts = tuple(
            dict.fromkeys(
                (
                    extract_opt_level(base_cflags),
                    *DEFAULT_OPT_LEVELS,
                    *matrix_opts,
                )
            )
        )
        for cc_name in asm_ccs:
            for asm_opt in asm_opts:
                key = (harness.name, cc_name, asm_opt)
                if key in represented_asm:
                    continue
                hits = vindex.get(key, [])
                asm_status = (
                    "ERROR"
                    if cc_name in asm_err_by_cc
                    else "PASS"
                    if cc_name in asm_scanned_ccs
                    else "NOT_RUN"
                )
                cells.append(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "target": cfg.project.name,
                        "harness": harness.name,
                        "combo": f"asm_only_{cc_name}_{asm_opt.lstrip('-')}",
                        "cc": cc_name,
                        "opt": asm_opt,
                        "cflags": asm_opt,
                        "ct_status": "NA",
                        "ct_findings": "0",
                        "ct_finding_funcs": "",
                        "ct_error": "",
                        "asm_status": asm_status,
                        "asm_div_count": str(sum(n for _f, n in hits)),
                        "asm_div_funcs": ";".join(sorted({f for f, _n in hits})),
                        "asm_error": asm_err_by_cc.get(cc_name, ""),
                    }
                )
                represented_asm.add(key)

    # Harnesses ct-matrix didn't cover (manual binaries, or no matrix) get a cell
    # from the plain ct run. A manual binary has NO sources, so asm-scan never ran
    # for it — we genuinely can't claim it division-free. Mark asm_error (a real
    # blind spot, not "scanned 0") so it classifies ct-clean-asm-incomplete and
    # gates, instead of falsely reading as `robust` (a div-free claim with no
    # scan). A reviewer who accepts the manual binary can override via triage.yaml
    # (`verdict: robust`). (N2 at the screen layer.)
    ct_opt = opt_of(" ".join(cfg.ct.cflags))
    for name, status, findings in ct_results:
        # A successful primary run is redundant with its matrix cells. A primary
        # FAIL/ERROR is not: append it so evidence v2 cannot hide that outcome
        # behind clean matrix rows.
        if name in template_names and matrix_rows and status == "PASS":
            continue
        funcs = ";".join(sorted({f.primary_frame.function for f in findings if f.primary_frame}))
        is_manual = name not in template_names
        primary_asm_status = (
            "NOT_RUN"
            if is_manual
            else "ERROR"
            if "gcc" in asm_err_by_cc
            else "PASS"
            if "gcc" in asm_scanned_ccs
            else "NOT_RUN"
        )
        cells.append(
            {
                "schema_version": SCHEMA_VERSION,
                "target": cfg.project.name,
                "harness": name,
                "combo": "ct-primary" if name in template_names else "ct",
                "cc": "gcc",
                "opt": ct_opt,
                "cflags": " ".join(cfg.ct.cflags),
                "ct_status": status,
                "ct_findings": str(len(findings)),
                "ct_finding_funcs": funcs,
                "ct_error": "",
                "asm_status": primary_asm_status,
                "asm_div_count": "0",
                "asm_div_funcs": "",
                "asm_error": asm_err_by_cc.get("gcc", "") if not is_manual else "",
            }
        )

    # 8. dudect lookups + classify (shared classifier).
    dud_by = {
        name: {
            "status": w.status,
            "abs_t_score": _fmt(w.abs_t_score),
            "n0": w.n0,
            "n1": w.n1,
            "timing_validity": w.timing_validity,
            "backend": w.backend,
        }
        for name, _samples, w, _batches in dud_results
    }
    timing_result_by = {name: result for name, _, result, _ in dud_results}
    dcfg: dict = {}
    if cfg.dudect is not None:
        tw, tf = cfg.dudect.threshold_warning, cfg.dudect.threshold_fail
        for h in cfg.dudect.harnesses:
            timing_result = timing_result_by.get(h.name)
            dcfg[h.name] = {
                "leak_target": h.leak_target,
                "seed": str(cfg.dudect.seed),
                "threshold": (
                    "upstream>10" if cfg.dudect.backend == "official-dudect" else f"{tw}/{tf}"
                ),
                "measurements": str(cfg.dudect.measurements),
                "backend": (
                    timing_result.backend
                    if timing_result is not None
                    else (
                        OFFICIAL_DUDECT_BACKEND
                        if cfg.dudect.backend == "official-dudect"
                        else EXPERIMENTAL_FIRST_ORDER_BACKEND
                    )
                ),
                "timing_validity": (
                    timing_result.timing_validity if timing_result is not None else ""
                ),
            }
    summary = summarize(
        cells,
        family=fam,
        triage=triage_cfg.varlat_map(),
        dud_by=dud_by,
        dcfg=dcfg,
        registry=registry,
        verdict_override=triage_cfg.verdict_overrides(),
        note_override=triage_cfg.note_overrides(),
        correctness={"PASS": "pass", "FAIL": "fail", "NONE": "not-run"}[kat_status],
        review_status=triage_cfg.review_statuses(),
        review_id=triage_cfg.review_ids(),
        target=cfg.project.name,
    )

    # Preserve raw timing and incomplete-cell details as notes alongside the
    # normalized evidence states.
    def _add_note(s, text):
        s["notes"] = (s["notes"] + "; " + text) if s.get("notes") else text

    for s in summary:
        ds = dud_by.get(s["harness"], {}).get("status", "")
        if ds in ("FAIL", "ERROR", "INSUFFICIENT"):
            at = dud_by[s["harness"]].get("abs_t_score", "")
            _add_note(
                s,
                f"timing backend {ds}" + (f" (|t|={at})" if at else "") + " — gated",
            )
        # Name partial build cells in the note as well as the normalized
        # structural=incomplete state. Evidence v2 gates that state as
        # inconclusive, even though the legacy classifier still folds ERROR out
        # of its provenance-only verdict class.
        err_combos = sorted(
            {
                c["combo"]
                for c in cells
                if c["harness"] == s["harness"] and c["ct_status"] == "ERROR"
            }
        )
        if err_combos:
            _add_note(
                s,
                f"{len(err_combos)} build cell(s) couldn't be measured "
                f"(ct ERROR): {', '.join(err_combos)}",
            )

    # 9. emit + render + exit.
    sp, _jp, _mp = _emit_screen_report(out_dir, cfg.project.name, summary, cells)
    table = Table(title="CT-KAT screen — evidence schema v2")
    for col in ("harness", "structural", "asm", "timing", "review", "overall"):
        table.add_column(col)
    overall_style = {
        Overall.NO_FINDING.value: "green",
        Overall.RISK.value: "bold red",
        Overall.NEEDS_REVIEW.value: "yellow",
        Overall.INCONCLUSIVE.value: "bold yellow",
        Overall.TOOL_ERROR.value: "bold red on white",
    }
    for s in summary:
        overall = s["overall"]
        table.add_row(
            s["harness"],
            s["structural"],
            f"{s['asm']} / {s['asm_attribution']}",
            f"{s['timing_validity']} / {s['timing_signal']}",
            f"{s['review']} ({s.get('review_id') or '-'})",
            f"[{overall_style[overall]}]{overall}[/]",
        )
    console.print(table)
    for s in summary:
        if s.get("notes"):
            console.print(f"[dim]{s['harness']}: {s['notes']}[/]")
    console.print(f"[dim]screen summary: {sp}[/]")

    gated = [s for s in summary if s["overall"] != Overall.NO_FINDING.value]
    reasons = []
    if kat_status == "FAIL":
        reasons.append("KAT FAIL (downstream evidence is inconclusive)")
    reasons.extend(f"{s['harness']}={s['overall']}" for s in gated)
    if reasons:
        console.print(
            "[bold yellow][CTKAT] screen: NOT cleared (exit 2) — " + "; ".join(reasons) + ".[/]"
        )
        raise typer.Exit(2)
    console.print(
        "[bold green][CTKAT] screen: all harnesses cleared (overall=no-finding-observed).[/]"
    )


@app.command()
def ct(
    config: Path = typer.Option(..., "--config", "-c", help="Path to ctkat.yaml"),
):
    """Run only the constant-time check stage (skip build/KAT)."""
    cfg = _load_config_or_exit(config)
    cfg_dir = config.parent.resolve()
    # F8: previously fell through `_do_generate({}) → _do_ct([]) → any_finding=False`
    # and printed bold-green "PASS" with exit 0 when `ct:` section was absent.
    # That actively misleads CI consumers. Match the dudect subcommand's
    # Exit(2) and the new F7 fix for the kat subcommand.
    if cfg.ct is None:
        console.print("[red]No `ct` section in config.[/]")
        raise typer.Exit(2)
    # R-6: empty harness list = nothing analyzed; don't report a green PASS.
    if not cfg.ct.harnesses:
        console.print(
            "[bold red][CTKAT] config error:[/] `ct` section has no harnesses — nothing to analyze."
        )
        raise typer.Exit(2)
    generated = _do_generate(cfg, cfg_dir)
    ct_results = _do_ct(cfg, cfg_dir, generated)
    any_finding = any(s == "FAIL" for _, s, _ in ct_results)
    any_ct_error = any(s == "ERROR" for _, s, _ in ct_results)
    if any_finding:
        console.print("[bold red][CTKAT] Constant-Time Check: FAIL[/]")
    elif any_ct_error:
        console.print(
            "[bold yellow][CTKAT] Constant-Time Check: INCOMPLETE[/] (see ERROR lines above)"
        )
    else:
        console.print("[bold green][CTKAT] Constant-Time Check: PASS[/]")
    _emit_report(cfg, cfg_dir, ct_results)
    if any_finding or any_ct_error:
        # E-2: ct ERROR (F2/F5) also exits 2 — verdict CSV consumers and
        # `ctkat ct --config ... && deploy` patterns must see "couldn't
        # verify" as a gating failure, not green-light.
        raise typer.Exit(2)


@app.command(name="asm-scan")
def asm_scan(
    config: Path = typer.Option(..., "--config", "-c", help="Path to ctkat.yaml"),
    opt: Optional[List[str]] = typer.Option(
        None,
        "--opt",
        help="Optimization level to scan (repeatable). Default: -O0 -O1 -O2 -O3 -Os. "
        "The ct stage's own -O level is always added on top.",
    ),
    cc: Optional[List[str]] = typer.Option(
        None,
        "--cc",
        help="Compiler(s) for the scan builds (repeatable: --cc gcc --cc clang). "
        "Different compilers strength-reduce constant division differently, "
        "so scanning several widens the leak surface. Default: gcc. A "
        "requested compiler that is missing is skipped with an ERROR record "
        "and the scan continues with the rest; if NONE are available, exit 2.",
    ),
):
    """Warn-only scan for variable-latency instruction *candidates* (integer
    division etc.) in the harness sources, across optimization levels.

    WHY multi-opt: a constant divisor (KyberSlash's `/KYBER_Q`) is
    strength-reduced away at the ct stage's gcc -O0 and only re-appears as a
    real `div` at another optimization cell, so a single-build scan would find
    nothing. This compiles each source at several opt levels and reports which
    build a division survives in.

    NOT a taint analysis: it reports every division-family instruction in the
    sources, secret or not (so public divisions, e.g. Keccak rate math, also
    show up). The standalone command remains warn-only because candidates are
    not proven secret-dependent; `ctkat screen` consumes the artifact and keeps
    unresolved candidates or missing coverage as gating evidence.

    Exit codes: 0 whether or not candidates are found (warn-only), even if SOME
    requested compilers were missing — those are skipped and recorded as ERRORs
    in the artifact while the scan continues with the rest. Exit 2 on a hard
    config/toolchain error: no `ct` harnesses, `objdump` missing, or NONE of the
    requested compilers are available / produced a usable scan. A security tool
    must not silently exit 0 with an empty result just because its toolchain
    wasn't installed (fail-closed, like F2/F8).
    """
    cfg = _load_config_or_exit(config)
    cfg_dir = config.parent.resolve()
    if cfg.ct is None or not cfg.ct.harnesses:
        console.print("[red]No `ct` harnesses to scan.[/]")
        raise typer.Exit(2)
    base_opts = tuple(opt) if opt else DEFAULT_OPT_LEVELS
    ct_cwd = _resolve(cfg_dir, cfg.ct.workdir)
    out_dir = _resolve(cfg_dir, cfg.report.output_dir)

    auto = [h for h in cfg.ct.harnesses if h.template is not None and h.sources]
    if not auto:
        console.print(
            "[yellow]asm-scan: no template harnesses with `sources` to scan "
            "(manual-binary harnesses are skipped).[/]"
        )
        raise typer.Exit(0)

    # `objdump` is non-negotiable — without it NO build can be disassembled, so
    # its absence is a hard exit 2 (an absent disassembler must not look like a
    # clean "no candidates"). `nm` is optional (Mach-O symbol recovery only).
    if shutil.which("objdump") is None:
        console.print(
            "[bold red][CTKAT] asm-scan: 'objdump' not found on PATH.[/] Install it "
            "(e.g. add to the Docker image). This is a config/toolchain error, not a "
            "clean 'no candidates' result, so exit code is 2."
        )
        raise typer.Exit(2)

    # Compilers are repeatable and de-duped (default: gcc). A requested compiler
    # that is missing is SKIPPED with an explicit ERROR record and the scan
    # continues with the rest; but if NONE are available there is nothing to
    # scan, which is a hard exit 2 (a green empty result would be a lie).
    requested = list(dict.fromkeys(cc)) if cc else ["gcc"]
    available = [c for c in requested if shutil.which(c) is not None]
    missing_cc = [c for c in requested if shutil.which(c) is None]
    cc_errors = [{"compiler": c, "error": "compiler not found on PATH"} for c in missing_cc]
    if not available:
        console.print(
            f"[bold red][CTKAT] asm-scan: requested compiler(s) not found on PATH: "
            f"{', '.join(requested)}.[/] None are available — install one (e.g. add to "
            f"the Docker image) or pick a different [bold]--cc[/]. Nothing to scan — "
            f"exit code is 2."
        )
        raise typer.Exit(2)
    for c in missing_cc:
        console.print(
            f"[yellow][CTKAT] asm-scan: compiler '{c}' not found — skipped and "
            f"recorded as ERROR; continuing with: {', '.join(available)}.[/]"
        )

    console.print(
        f"[bold cyan]==> asm-scan[/]: compilers={','.join(available)} "
        f"base opt levels = {' '.join(base_opts)} "
        "[dim](standalone warn-only; screen consumes this artifact)[/]"
    )
    candidates = []
    scanned: set = set()
    scanned_ok = []
    for cc_name in available:
        # Accumulate this compiler's candidates in a LOCAL list and merge into the
        # global result only if its whole scan completes. A mid-scan AsmScanError
        # then discards this compiler's partial output entirely, keeping the CSV
        # rows and JSON `scanned_compilers` consistent (§4 artifact contract).
        cc_cands = []
        try:
            for h in auto:
                include_dirs = [_resolve(cfg_dir, d) for d in h.include_dirs]
                sources = [_resolve(cfg_dir, s) for s in h.sources]
                source_display = [str(s) for s in h.sources]
                base_cflags = h.cflags if h.cflags is not None else cfg.ct.cflags
                # Always scan the ct stage's own -O level so the "absent at <ct
                # opt>" note is grounded in an actual build, not a hardcoded
                # "-O0" (which would lie for a yaml whose ct.cflags is -O2).
                ct_opt = extract_opt_level(base_cflags)
                harness_opts = tuple(dict.fromkeys((ct_opt, *base_opts)))
                scanned.update(harness_opts)
                cc_cands.extend(
                    scan_harness(
                        harness=h.name,
                        sources=sources,
                        source_display=source_display,
                        include_dirs=include_dirs,
                        base_cflags=base_cflags,
                        workdir=ct_cwd,
                        opt_levels=harness_opts,
                        timeout=cfg.ct.compile_timeout,
                        cc=cc_name,
                        # default-arg binds cc_name per iteration (avoid late-binding)
                        on_warn=lambda m, _cc=cc_name: console.print(
                            f"[dim][CTKAT] asm-scan note ({_cc}):[/dim] {m}"
                        ),
                    )
                )
        except AsmScanError as e:
            # `--cc` ran but produced no object / objdump couldn't read it (a stub
            # or wrong wrapper that passed the which() preflight). Per the
            # skip-and-continue policy this is recorded as a per-compiler ERROR and
            # the remaining compilers still run. Any PARTIAL candidates produced
            # before the failure are DISCARDED, not merged — an incomplete disasm
            # can't back a trustworthy "scanned <cc>" claim, and keeping them would
            # contradict `scanned_compilers` (CSV rows for a compiler the JSON says
            # it never finished).
            cc_errors.append({"compiler": cc_name, "error": f"disassembly failed: {e}"})
            console.print(
                f"[bold yellow][CTKAT] asm-scan: compiler '{cc_name}' disassembly "
                f"failed[/] — {e}\n[dim]It ran but emitted no usable object (not a real "
                f"compiler?) — skipped, recorded as ERROR, partial results discarded; "
                f"continuing.[/]"
            )
            continue
        candidates.extend(cc_cands)
        scanned_ok.append(cc_name)

    if not scanned_ok:
        # Every available compiler failed disassembly — no usable scan ran, so an
        # empty artifact would be a lie. Fail-closed (exit 2), same spirit as the
        # missing-objdump / no-compiler cases.
        console.print(
            "[bold red][CTKAT] asm-scan: no compiler produced a usable scan[/] "
            "(all failed disassembly). Treating as a config/toolchain error (exit 2)."
        )
        raise typer.Exit(2)

    csv_path = out_dir / "ctkat_varlat_candidates.csv"
    json_path = out_dir / "ctkat_varlat_candidates.json"
    write_varlat_csv(candidates, csv_path)
    write_varlat_json(
        cfg.project.name,
        candidates,
        json_path,
        opt_levels=tuple(sorted(scanned)),
        compilers=tuple(scanned_ok),
        errors=cc_errors,
    )

    if candidates:
        table = Table(title="Variable-latency candidates in harness sources (warn-only)")
        for col in ("compiler", "harness", "source", "function", "hint", "mnem", "opt levels", "n"):
            table.add_column(col)
        for candidate in candidates:
            table.add_row(
                candidate.compiler,
                candidate.harness,
                candidate.source_file,
                candidate.function,
                candidate.triage_hint,
                ";".join(candidate.mnemonics),
                ";".join(candidate.opt_levels),
                str(candidate.count),
            )
        console.print(table)
        console.print(
            f"[yellow]{len(candidates)} variable-latency candidate(s)[/] across "
            f"{len(scanned_ok)} compiler(s) — review manually; these are NOT proven "
            "secret-dependent."
        )
    else:
        console.print("[green]asm-scan: no division-family instructions found.[/]")
    if cc_errors:
        # The result is PARTIAL — loudly so a green CSV is not mistaken for a
        # complete clean scan (the cost the skip-and-continue policy trades for).
        console.print(
            f"[bold yellow]asm-scan: {len(cc_errors)} compiler ERROR(s) recorded — "
            "result is PARTIAL, not complete:[/] "
            + "; ".join(f"{e['compiler']} ({e['error']})" for e in cc_errors)
        )
    console.print(f"[dim]varlat CSV : {csv_path}[/]")
    console.print(f"[dim]varlat JSON: {json_path}[/]")


@app.command(name="ct-matrix")
def ct_matrix(
    config: Path = typer.Option(..., "--config", "-c", help="Path to ctkat.yaml"),
):
    """Compiler × cflags Valgrind matrix — OBSERVATIONAL, verdict-independent.

    Recompiles each template harness under every `matrix:` build configuration
    (compilers × named cflags combos; default gcc ×
    debug/opt1/release/opt3/size) and runs
    the SAME structural-CT (Valgrind/Memcheck) check on each, recording PASS /
    FAIL / ERROR per cell. The product is a SEPARATE artifact
    (reports/ctkat_ct_matrix.csv/.json) — it NEVER touches ctkat_verdict.csv or
    the `run` gate. Use it to see whether "same source, different build" changes
    the CT conclusion.

    Exit codes: 0 regardless of the PASS/FAIL distribution (observational — a
    FAIL in some build is the interesting data point, not a tool failure). Exit 2
    only on a hard config/toolchain error: no `ct` harnesses, no *template*
    harness to recompile, no combos, a missing compiler / valgrind, or every
    build cell ERRORing (no usable result). Valgrind is required, so this is a
    Docker/Linux command.
    """
    cfg = _load_config_or_exit(config)
    cfg_dir = config.parent.resolve()

    if cfg.ct is None or not cfg.ct.harnesses:
        console.print("[red]No `ct` harnesses to sweep.[/]")
        raise typer.Exit(2)
    # Only template harnesses can be recompiled per combo; a prebuilt manual
    # binary is fixed, so it can't participate in a build-configuration sweep.
    auto = [h for h in cfg.ct.harnesses if h.template is not None]
    if not auto:
        console.print(
            "[bold red][CTKAT] ct-matrix: no template harnesses to sweep[/] — "
            "manual prebuilt binaries can't be recompiled per build config. "
            "This is a config error (exit 2)."
        )
        raise typer.Exit(2)

    # Loud about partial coverage (§8): manual harnesses can't be recompiled per
    # combo, so they're dropped — say so, else a green matrix reads as full.
    skipped_manual = [h.name for h in cfg.ct.harnesses if h.template is None]
    if skipped_manual:
        console.print(
            f"[yellow][CTKAT] ct-matrix: {len(skipped_manual)} manual-binary "
            f"harness(es) skipped (can't be recompiled per build config): "
            f"{', '.join(skipped_manual)}.[/]"
        )

    matrix_cfg = cfg.matrix or MatrixConfig()
    combos = expand_combos(matrix_cfg.compilers, matrix_cfg.ct_cflags)
    if not combos:
        console.print("[bold red][CTKAT] ct-matrix: empty matrix (no combos).[/] exit 2")
        raise typer.Exit(2)

    # Fail-closed preflight: valgrind + every requested compiler must exist, else
    # the sweep would silently skip cells and a green-looking matrix would lie
    # about coverage (the fail-open this project has spent its life closing).
    requested_compilers = list(dict.fromkeys(matrix_cfg.compilers))
    missing = [t for t in (["valgrind", *requested_compilers]) if shutil.which(t) is None]
    if missing:
        console.print(
            f"[bold red][CTKAT] ct-matrix: required tool(s) not found on PATH: "
            f"{', '.join(missing)}.[/] Valgrind needs a Linux/Docker environment; "
            f"install the missing compiler(s) (e.g. add to the Docker image). "
            f"This is a config/toolchain error, so exit code is 2."
        )
        raise typer.Exit(2)

    ct_cwd = _resolve(cfg_dir, cfg.ct.workdir)
    generated_dir = _resolve(cfg_dir, cfg.ct.generated_dir)
    out_dir = _resolve(cfg_dir, cfg.report.output_dir)

    # Render each harness's C source ONCE (combo-independent); the matrix then
    # compiles that same source under every (cc, cflags) cell.
    harness_inputs: List[HarnessInputs] = []
    for h in auto:
        template = h.template
        if template is None:
            raise ValueError(f"ct-matrix auto harness {h.name!r} has no template")
        include_dirs = [_resolve(cfg_dir, d) for d in h.include_dirs]
        sources = [_resolve(cfg_dir, s) for s in h.sources]
        # The harness's effective cflags carry build-selection flags (e.g.
        # `-DPQCLEAN_NO_GLIBC_RANDOMBYTES`). The matrix swaps only the -O/codegen
        # flags per combo, so these preprocessor defines must ride along into
        # every cell — else the matrix builds a different program than `ct`.
        base_cflags = h.cflags if h.cflags is not None else cfg.ct.cflags
        source_path = generated_dir / f"harness_{h.name}.c"
        try:
            code = render_harness(template, _template_context(h, cfg.ct.seed))
        except HarnessGenerationError as e:
            console.print(f"[bold red][CTKAT] ct-matrix: harness render FAIL ({h.name})[/]\n{e}")
            raise typer.Exit(1)
        _atomic_write_text(source_path, code)
        harness_inputs.append(
            HarnessInputs(
                name=h.name,
                source_path=source_path,
                sources=sources,
                include_dirs=include_dirs,
                extra_cflags=preprocessor_cflags(base_cflags),
            )
        )

    console.print(
        f"[bold cyan]==> ct-matrix[/]: combos = {', '.join(c.label for c in combos)} "
        "[dim](observational; NOT a verdict gate)[/]"
    )
    rows = scan_ct_matrix(
        harness_inputs,
        combos,
        workdir=ct_cwd,
        binaries_dir=generated_dir / "matrix",
        valgrind_flags=cfg.ct.valgrind_flags,
        compile_timeout=cfg.ct.compile_timeout,
        valgrind_timeout=cfg.ct.valgrind_timeout,
        lookup_patterns=cfg.ct.lookup_function_patterns,
        on_progress=lambda s: console.print(f"[dim][CTKAT] ct-matrix:[/dim] {s}"),
    )

    csv_path = out_dir / "ctkat_ct_matrix.csv"
    json_path = out_dir / "ctkat_ct_matrix.json"
    write_ct_matrix_csv(cfg.project.name, rows, csv_path)
    write_ct_matrix_json(
        cfg.project.name,
        rows,
        json_path,
        combos=combos,
        compilers=requested_compilers,
    )

    table = Table(title="CT matrix — Valgrind per build config (observational, NOT a verdict)")
    for col in ("harness", "combo", "cc", "status", "findings", "error"):
        table.add_column(col)
    _status_style = {"PASS": "green", "FAIL": "red", "ERROR": "yellow"}
    for r in rows:
        style = _status_style.get(r.valgrind_status, "")
        cell = f"[{style}]{r.valgrind_status}[/]" if style else r.valgrind_status
        err = (r.error[:40] + "…") if len(r.error) > 41 else r.error
        table.add_row(r.harness, r.combo, r.cc, cell, str(r.findings), err)
    console.print(table)

    # Surface the headline finding: a harness whose CT CONCLUSION differs across
    # builds is exactly "same source, different build → different verdict". The
    # diff is computed over actual verdicts {PASS, FAIL} ONLY — an ERROR cell
    # means "couldn't measure", not a different conclusion, so mixing it in
    # ({PASS, ERROR}) must NOT be reported as a CT disagreement. ERROR cells get
    # their own "some cells couldn't be measured" note.
    for harness_input in harness_inputs:
        h_rows = [r for r in rows if r.harness == harness_input.name]
        verdicts = {r.valgrind_status for r in h_rows if r.valgrind_status in ("PASS", "FAIL")}
        errored = [r for r in h_rows if r.valgrind_status == "ERROR"]
        if len(verdicts) > 1:
            console.print(
                f"[bold yellow]ct-matrix: harness '{harness_input.name}' has DIFFERENT CT "
                f"results across builds[/] ({', '.join(sorted(verdicts))}) — the "
                "tested binary and a differently-built binary disagree."
            )
        if errored:
            console.print(
                f"[yellow]ct-matrix: harness '{harness_input.name}': {len(errored)} build "
                f"cell(s) ERRORed (couldn't measure — not a CT result): "
                f"{', '.join(r.combo for r in errored)}.[/]"
            )

    # Stale-parser canary (mirror _do_ct's T3 note): a high parser-dropped-line
    # count means the Valgrind log format may have drifted and finding lines are
    # being silently ignored (a real leak could then read as PASS).
    worst_dropped = max((r.dropped for r in rows), default=0)
    if worst_dropped > 50:
        console.print(
            f"[dim][CTKAT] note:[/dim] valgrind parser ignored up to {worst_dropped} "
            "unrecognized lines in some cell — if this jumps across versions the "
            "parser whitelist may need an update (known_issues T3)."
        )

    console.print(f"[dim]ct matrix CSV : {csv_path}[/]")
    console.print(f"[dim]ct matrix JSON: {json_path}[/]")

    # Observational => exit 0 whatever the PASS/FAIL mix. The one fail-closed
    # case: if EVERY cell ERRORed, nothing was actually measured, so a green
    # exit 0 would be a lie.
    if rows and all(r.valgrind_status == "ERROR" for r in rows):
        console.print(
            "[bold red][CTKAT] ct-matrix: every build cell ERRORed[/] — no usable "
            "CT result was produced. Treating as a config/toolchain error (exit 2)."
        )
        raise typer.Exit(2)


@app.command()
def kat(
    config: Path = typer.Option(..., "--config", "-c", help="Path to ctkat.yaml"),
):
    """Run only the KAT stage."""
    cfg = _load_config_or_exit(config)
    cfg_dir = config.parent.resolve()
    # F7: previously printed a yellow note and exited 0 when `kat:` was
    # absent — asymmetric with the dudect subcommand (which exits 2 in
    # the same case) and a real fail-open in CI gating (`ctkat kat && deploy`
    # would deploy even when KAT was never wired up).
    if cfg.kat is None:
        console.print("[red]No `kat` section in config.[/]")
        raise typer.Exit(2)
    ok, _ = _do_kat(cfg, cfg_dir)
    if not ok:
        raise typer.Exit(1)


_ROLE_STYLES = {
    "secret": "bold red",
    "public": "bold green",
    "output": "bold yellow",
    "scalar": "dim",
    "unknown": "bold magenta",
}


def _print_inferred(funcs: List[InferredFunction]) -> int:
    """Print inference results, return count of params still 'unknown'."""
    unknown_total = 0
    for inf in funcs:
        sig = inf.signature
        src = ""
        if sig.source_file:
            src = f" [dim]({sig.source_file}"
            if sig.source_line:
                src += f":{sig.source_line}"
            src += ")[/]"
        profile = inf.profile or "[dim]none[/]"
        console.print()
        console.print(f"[bold]Function:[/] {sig.name}{src}")
        console.print(f"  Signature: {sig.render()}")
        console.print(f"  Profile:   {profile}")
        if not inf.assignments:
            console.print("  [dim](no parameters)[/]")
            continue
        table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
        table.add_column("role")
        table.add_column("type")
        table.add_column("name")
        table.add_column("reason", overflow="fold")
        for a in inf.assignments:
            style = _ROLE_STYLES.get(a.role, "")
            role_cell = f"[{style}]{a.role}[/]" if style else a.role
            table.add_row(role_cell, a.param.type, a.param.name, a.reason)
            if a.role == "unknown":
                unknown_total += 1
        console.print(table)
    return unknown_total


@app.command()
def infer(
    header: Optional[Path] = typer.Option(
        None, "--header", "-H", help="A single C header file to parse."
    ),
    project: Optional[Path] = typer.Option(
        None, "--project", "-p", help="Directory to scan recursively for *.h files."
    ),
    function: Optional[str] = typer.Option(
        None, "--function", "-f", help="Only show inference for this function name."
    ),
):
    """Parse C headers and infer secret/public/output roles for parameters."""
    if header is None and project is None:
        console.print("[red]Must specify --header or --project.[/]")
        raise typer.Exit(2)

    headers: List[Path] = []
    if header is not None:
        if not header.is_file():
            console.print(f"[red]Header not found: {header}[/]")
            raise typer.Exit(2)
        headers.append(header)
    if project is not None:
        if not project.is_dir():
            console.print(f"[red]Project dir not found: {project}[/]")
            raise typer.Exit(2)
        headers.extend(discover_headers(project))

    if not headers:
        console.print("[yellow]No headers found.[/]")
        raise typer.Exit(0)

    all_funcs: List[InferredFunction] = []
    total_skipped = 0
    for h in headers:
        sigs, skipped = parse_header_file_with_stats(h)
        total_skipped += skipped
        if function:
            sigs = [s for s in sigs if s.name == function]
        if not sigs:
            continue
        console.print(f"[cyan]==> {h}[/] [dim]({len(sigs)} function(s))[/]")
        all_funcs.extend(infer_functions(sigs))
    # T13: surface what the strict regex couldn't parse so the user knows
    # the inferred list is incomplete (function-pointer params, variadic,
    # nested-paren signatures).
    if total_skipped > 0:
        console.print(
            f"[dim]note: {total_skipped} declaration(s) skipped by the "
            f"strict regex (function pointers / variadic / nested-paren "
            f"signatures). Inferred list may be incomplete.[/]"
        )

    if not all_funcs:
        console.print("[yellow]No matching functions found.[/]")
        raise typer.Exit(0)

    unknown_count = _print_inferred(all_funcs)
    console.print()
    if unknown_count > 0:
        console.print(f"[bold magenta]{unknown_count} parameter(s) need manual role assignment.[/]")
    else:
        console.print("[bold green]All parameters inferred.[/]")


@app.command()
def parse(
    log: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Path to a valgrind log file",
    ),
):
    """Parse a single Valgrind log and print findings (debugging helper)."""
    log_size = log.stat().st_size
    if log_size > MAX_VALGRIND_LOG_BYTES:
        console.print(
            f"[bold red][CTKAT] parse: ERROR[/] — log is {log_size} bytes, "
            f"exceeding the {MAX_VALGRIND_LOG_BYTES}-byte parser limit."
        )
        raise typer.Exit(2)
    text = log.read_text(encoding="utf-8", errors="replace")
    findings, dropped = parse_valgrind_log_with_stats(text)
    if dropped > 50:
        console.print(
            f"[dim]Note: {dropped} unrecognized Valgrind messages dropped — "
            "parser whitelist may need updating.[/]"
        )
    if not findings:
        console.print("[green]No findings.[/]")
        return
    for i, f in enumerate(findings, 1):
        console.print(f"[bold]{i}.[/] [{f.severity.value}] [bold]{f.type.value}[/] — {f.message}")
        for fr in f.frames[:3]:
            loc = f"{fr.file}:{fr.line}" if fr.file else "?"
            console.print(f"   at {fr.function} ({loc})")
        if f.origin_frames:
            console.print("   [dim]origin:[/]")
            for fr in f.origin_frames[:2]:
                loc = f"{fr.file}:{fr.line}" if fr.file else "?"
                console.print(f"   [dim]    {fr.function} ({loc})[/]")


if __name__ == "__main__":
    app()
