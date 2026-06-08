import csv
import math
import platform
import re
import secrets
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple


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

import typer
import yaml
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

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
    expand_combos,
    preprocessor_cflags,
    scan_ct_matrix,
    write_ct_matrix_csv,
    write_ct_matrix_json,
    HarnessInputs,
)
from .ct_runner import classify_valgrind_run
from .dudect_runner import TimingSamples, run_timing_harness
from .harness_generator import (
    CompilerNotFoundError,
    HarnessGenerationError,
    generate_and_compile,
    render_harness,
    _atomic_write_text,
)
from .header_parser import (
    discover_headers,
    parse_header_file,
    parse_header_file_with_stats,
)
from .qemu_detect import detect_qemu_emulation
from .report import finding_to_row, write_csv, write_json
from .secret_infer import InferredFunction, infer_functions
from .statistics import (
    CROP_PERCENTILES,
    WelchResult,
    batch_t_scores,
    welch_t_test,
    welch_with_cropping,
)
from .timing_harness_generator import generate_and_compile_timing
from .valgrind_parser import Finding, parse_valgrind_log_with_stats
from .valgrind_runner import run_valgrind
from .verdict import VERDICT_STYLES, HarnessVerdict, Verdict, combine


app = typer.Typer(help="CT-KAT: KAT + Valgrind based constant-time check framework")
console = Console()


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
        return load_config(config)
    except FileNotFoundError:
        console.print(
            f"[bold red][CTKAT] config file not found:[/] {config}. "
            "Check the --config path. (exit 2)"
        )
        raise typer.Exit(2)
    except (IsADirectoryError, PermissionError, NotADirectoryError) as e:
        console.print(
            f"[bold red][CTKAT] config file not readable:[/] {config} — {e}. "
            "(exit 2)"
        )
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
        command=cfg.build.command, argv=cfg.build.argv,
        workdir=workdir, timeout=cfg.build.timeout,
    )
    if not r.ok:
        console.print("[bold red][CTKAT] Build: FAIL[/]")
        if r.stdout:
            console.print(r.stdout)
        if r.stderr:
            console.print(r.stderr)
        return False
    if cfg.build.expected_artifacts:
        missing = [p for p in cfg.build.expected_artifacts
                   if not _resolve(workdir, p).exists()]
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
        command=cfg.kat.command, argv=cfg.kat.argv,
        workdir=workdir, timeout=cfg.kat.timeout,
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
            f"[green][CTKAT] KAT: PASS[/] ({count} tests, expected >= "
            f"{cfg.kat.expected_min})"
        )
        return True, count
    console.print(
        "[dim][CTKAT] note:[/dim] kat.expected_min unset — KAT validated by "
        "exit code only (a no-op runner passes). Set the field in yaml to "
        "require a minimum test count (see known_issues F1)."
    )
    console.print("[green][CTKAT] KAT: PASS[/]")
    return True, count


def _build_generic_context(h: HarnessConfig, seed: int) -> dict:
    return {
        "extra_headers": list(h.extra_headers),
        "function": h.function,
        "args": list(h.args),
        "return_type": h.return_type,
        "buffers": [b.model_dump() for b in h.buffers],
        "seed": seed,
    }


def _build_kem_context(h: HarnessConfig) -> dict:
    return {
        "header": h.header,
        "extra_headers": list(h.extra_headers),
        "prefix": h.prefix,
        "secret_regions": [r.model_dump() for r in h.secret_regions],
    }


def _build_sign_context(h: HarnessConfig) -> dict:
    return {
        "header": h.header,
        "extra_headers": list(h.extra_headers),
        "prefix": h.prefix,
        "secret_regions": [r.model_dump() for r in h.secret_regions],
    }


def _template_context(h: HarnessConfig, seed: int) -> dict:
    if h.template == "generic":
        return _build_generic_context(h, seed)
    if h.template == "kem":
        return _build_kem_context(h)
    if h.template == "sign":
        return _build_sign_context(h)
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
        console.print(
            f"[bold cyan]==> Generate[/]: harness=[bold]{h.name}[/] template={h.template}"
        )
        include_dirs = [_resolve(cfg_dir, d) for d in h.include_dirs]
        sources = [_resolve(cfg_dir, s) for s in h.sources]
        cflags = h.cflags if h.cflags is not None else cfg.ct.cflags
        try:
            result = generate_and_compile(
                name=h.name,
                template=h.template,
                context=_template_context(h, cfg.ct.seed),
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
            console.print(f"[bold red][CTKAT] Harness generation FAIL ({h.name})[/] — toolchain error")
            console.print(str(e))
            raise typer.Exit(2)
        except HarnessGenerationError as e:
            console.print(f"[bold red][CTKAT] Harness generation FAIL ({h.name})[/]")
            console.print(str(e))
            raise typer.Exit(1)
        console.print(
            f"   [dim]source: {result.source_path}[/]\n"
            f"   [dim]binary: {result.binary_path}[/]"
        )
        paths[h.name] = result.binary_path

        # F6: cross-check secret_regions coverage against the framework's
        # expected total (CRYPTO_SECRETKEYBYTES). Only meaningful when the
        # user actually specified secret_regions (otherwise full-sk taint is
        # applied and there's nothing to verify). kem/sign templates only —
        # generic has no canonical "sk" notion.
        if (
            h.template in ("kem", "sign")
            and h.secret_regions
            and h.header is not None
        ):
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
                raise ValueError(
                    f"harness {h.name!r}: neither `binary` nor `template` set"
                )
            binary = _resolve(cfg_dir, h.binary)
        log_path = out_dir / f"valgrind_{h.name}.log"
        console.print(
            f"[bold cyan]==> Valgrind[/]: harness=[bold]{h.name}[/] bin={binary}"
        )
        result = run_valgrind(
            binary, log_path, cfg.ct.valgrind_flags, ct_cwd,
            timeout=cfg.ct.valgrind_timeout,
        )
        # F2: expected Valgrind exit codes are 0 (clean) and 99 (findings, via
        # --error-exitcode). Anything else = harness crashed / Valgrind failed /
        # timeout, or a missing log — all ERROR (not zero-findings → CLEAN). The
        # rc/log/parse classification lives in ct_runner so the ct-matrix sweep
        # maps identically (T21: utf-8+replace decoding is inside the parser).
        outcome = classify_valgrind_run(
            result, log_path, lookup_patterns=cfg.ct.lookup_function_patterns,
        )
        if outcome.status == "ERROR":
            tail = (result.stderr or "").strip().splitlines()[-3:]
            console.print(
                f"[bold red][CTKAT] ct: ERROR[/] — {outcome.error} on harness "
                f"[bold]{h.name}[/]. Analysis incomplete; verdict will be "
                f"INCONCLUSIVE. (F2)\n"
                f"[dim]valgrind stderr tail: {tail or '(empty)'}[/]"
            )
            results.append((h.name, "ERROR", []))
            continue
        # F5: manual-binary sentinel check — orthogonal to Valgrind's own status,
        # so it stays here (ct_runner is shared with the matrix, which only ever
        # drives template harnesses). Only enforced on manual mode;
        # `require_sentinel=False` keeps legacy behavior (note printed above).
        if is_manual and cfg.ct.require_sentinel:
            m = re.search(cfg.ct.sentinel_pattern, result.stdout or "")
            if m is None:
                console.print(
                    f"[bold red][CTKAT] ct: ERROR[/] — manual harness "
                    f"[bold]{h.name}[/] did not emit sentinel "
                    f"{cfg.ct.sentinel_pattern!r} on stdout. The binary may "
                    f"not have invoked the target function. Verdict will be "
                    f"INCONCLUSIVE. (F5)"
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
            table.add_row(
                r["harness"], r["function"], loc, r["severity"], r["type"]
            )
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
    }
    if h.template == "kem":
        base.update({
            "header": h.header,
            "prefix": h.prefix,
            "leak_target": h.leak_target,
        })
    else:  # generic
        base.update({
            "function": h.function,
            "args": list(h.args),
            "return_type": h.return_type,
            "buffers": [b.model_dump() for b in h.buffers],
        })
    return base


def _error_welch() -> WelchResult:
    """Sentinel WelchResult for a harness whose dudect stage couldn't
    complete (timeout / crash / unparseable output / insufficient samples).
    `status="ERROR"` flows through `_compute_verdicts` → verdict.combine()
    → Verdict.INCONCLUSIVE so verdict CSV never silently downgrades a
    broken run to CLEAN. Used by Bundle E-1 (T6) and Bundle F (S4)."""
    return WelchResult(
        n0=0, n1=0,
        mean0=0.0, mean1=0.0, var0=0.0, var1=0.0,
        t_score=0.0, abs_t_score=0.0,
        status="ERROR",
    )


def _emit_dudect_report(
    project: str,
    out_dir: Path,
    results: List[Tuple[str, TimingSamples, WelchResult, List[WelchResult]]],
) -> Tuple[Path, Path]:
    """Write dudect raw + summary CSVs. Returns (raw_path, summary_path)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_path = out_dir / "dudect_raw_timings.csv"
    summary_path = out_dir / "dudect_summary.csv"

    with open(raw_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["project", "harness", "sample_id", "class", "cycles"])
        for harness_name, samples, _, _ in results:
            for i, (cls, cyc) in enumerate(zip(samples.classes, samples.cycles)):
                w.writerow([project, harness_name, i, cls, cyc])

    with open(summary_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        # IMPORTANT: columns 1-14 are stable for backward compatibility —
        # scripts/run_phase4.sh parses $11 (status) via awk and we don't
        # want to break that contract. Diagnostic columns 15-17 added in
        # Bundle B (cropping), 18-20 added in Bundle F (S1 raw-count
        # bookkeeping). All new columns go at the END so awk-by-position
        # consumers keep working.
        w.writerow([
            "project", "harness",
            "n0", "n1",
            "mean0", "mean1", "var0", "var1",
            "t_score", "abs_t_score", "status",
            "batch_t_mean", "batch_t_max_abs", "batches",
            "cropped_at", "t_score_uncropped", "abs_t_score_uncropped",
            "raw_n_total", "dropped_zero_n0", "dropped_zero_n1",
            "cohens_d",
        ])
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
            w.writerow([
                project, harness_name,
                r.n0, r.n1,
                _fmt(r.mean0), _fmt(r.mean1),
                _fmt(r.var0), _fmt(r.var1),
                _fmt(r.t_score), _fmt(r.abs_t_score), r.status,
                batch_mean_str, batch_max_str, len(batches),
                _fmt(r.cropped_at), _fmt(r.t_score_uncropped),
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
            ])
    return raw_path, summary_path


def _do_dudect(
    dud: DudectConfig,
    cfg_dir: Path,
    project_name: str,
    out_dir: Path,
    crop: bool = True,
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
            "[yellow]Note:[/] QEMU emulation detected. clock=monotonic is "
            "safe for [italic]qualitative[/] comparison (effect "
            "presence/direction), but absolute timing conclusions and "
            "borderline verdicts should be re-verified on a native x86_64 "
            "Linux host."
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
    effective_seed = (
        dud.seed if dud.seed is not None else (secrets.randbits(63) or 0xC0FFEE)
    )
    console.print(f"[dim]dudect seed = 0x{effective_seed:X}[/]")
    clock_display = (
        f"{dud.clock}→{effective_clock}" if dud.clock == "auto"
        else effective_clock
    )
    console.print(
        f"[dim]measurements={dud.measurements} warmup={dud.warmup} "
        f"batches={dud.batches} clock={clock_display} "
        f"cropping={'on' if crop else 'off'}[/]"
    )

    # Bundle G (R2): bonferroni-like correction for multi-cutoff cropping.
    # The correction only makes sense for the cropping protocol — it accounts
    # for taking max |t| over N cropping cutoffs, which inflates the per-test
    # Type-I rate. It does NOT apply to:
    #   - F20: the uncropped (--no-crop) path — a single test, no family to
    #     correct, so scaling there would just be wrongly conservative.
    #   - F23: batch_t_scores — those never crop (they measure raw stability),
    #     so they keep the unscaled thresholds. (Batch status doesn't feed the
    #     verdict, but keeping it honest avoids a misleading display column.)
    # So we keep `warn_t`/`fail_t` as the unscaled thresholds for batch + the
    # uncropped path, and compute a separate scaled pair used ONLY for the
    # cropping welch call below.
    warn_t = dud.threshold_warning
    fail_t = dud.threshold_fail
    crop_warn_t = warn_t
    crop_fail_t = fail_t
    if dud.bonferroni_correct:
        if crop:
            scale = math.sqrt(len(CROP_PERCENTILES))
            crop_warn_t = warn_t * scale
            crop_fail_t = fail_t * scale
            console.print(
                f"[dim]bonferroni correction: scaling the cropping thresholds "
                f"by sqrt({len(CROP_PERCENTILES)})={scale:.3f} → "
                f"warning={crop_warn_t:.2f} fail={crop_fail_t:.2f} "
                f"(batch + uncropped keep {warn_t}/{fail_t})[/]"
            )
        else:
            console.print(
                "[yellow]Note:[/] bonferroni_correct is set but cropping is "
                "off (--no-crop) — there is no multi-cutoff family to correct, "
                "so the correction is ignored this run (F20)."
            )

    workdir = _resolve(cfg_dir, dud.workdir)
    gen_dir = _resolve(cfg_dir, dud.generated_dir)

    results: List[Tuple[str, TimingSamples, WelchResult, List[WelchResult]]] = []
    for h in dud.harnesses:
        console.print(
            f"[bold cyan]==> Generate timing harness[/]: [bold]{h.name}[/]"
        )
        try:
            gen = generate_and_compile_timing(
                name=h.name,
                template=h.template,
                context=_dudect_context(h, dud, effective_seed, effective_clock),
                output_dir=gen_dir,
                sources=[_resolve(cfg_dir, s) for s in h.sources],
                include_dirs=[_resolve(cfg_dir, d) for d in h.include_dirs],
                cflags=dud.compiler.cflags,
                cc=dud.compiler.cc,
                workdir=workdir,
                timeout=dud.compile_timeout,
            )
        except CompilerNotFoundError as e:
            # FN-5(exit-code): toolchain error → exit 2, consistent with the ct
            # path and the asm-scan / ct-matrix preflights.
            console.print(f"[bold red][CTKAT] Timing harness gen FAIL ({h.name})[/] — toolchain error")
            console.print(str(e))
            raise typer.Exit(2)
        except HarnessGenerationError as e:
            console.print(f"[bold red][CTKAT] Timing harness gen FAIL ({h.name})[/]")
            console.print(str(e))
            raise typer.Exit(1)
        console.print(f"   [dim]source: {gen.source_path}[/]")
        console.print(f"   [dim]binary: {gen.binary_path}[/]")

        console.print(
            f"[bold cyan]==> Run timing harness[/]: [bold]{h.name}[/] "
            f"(this may take a while)"
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
        try:
            samples = run_timing_harness(
                gen.binary_path, workdir, timeout=dud.timeout
            )
        except subprocess.TimeoutExpired:
            console.print(
                f"[bold red][CTKAT] dudect: ERROR[/] — harness "
                f"[bold]{h.name}[/] exceeded timeout={dud.timeout}s. "
                f"Bump dudect.timeout or reduce measurements. (T6)"
            )
            results.append((h.name, TimingSamples(), _error_welch(), []))
            continue
        except RuntimeError as e:
            console.print(
                f"[bold red][CTKAT] dudect: ERROR[/] — harness "
                f"[bold]{h.name}[/] crashed: {e} (T6)"
            )
            results.append((h.name, TimingSamples(), _error_welch(), []))
            continue
        except ValueError as e:
            console.print(
                f"[bold red][CTKAT] dudect: ERROR[/] — harness "
                f"[bold]{h.name}[/] output unparseable: {e} (T6)"
            )
            results.append((h.name, TimingSamples(), _error_welch(), []))
            continue

        c0 = [c for cls, c in zip(samples.classes, samples.cycles) if cls == 0]
        c1 = [c for cls, c in zip(samples.classes, samples.cycles) if cls == 1]
        if len(c0) < 2 or len(c1) < 2:
            console.print(
                f"[bold red][CTKAT] dudect: ERROR[/] — harness "
                f"[bold]{h.name}[/] insufficient samples per class: "
                f"n0={len(c0)} n1={len(c1)} (T6)"
            )
            results.append((h.name, samples, _error_welch(), []))
            continue

        if crop:
            # Cropping path: the only place the bonferroni-scaled thresholds
            # (crop_warn_t/crop_fail_t) apply — see F20/F23 note above.
            overall = welch_with_cropping(
                c0, c1,
                warning_threshold=crop_warn_t,
                fail_threshold=crop_fail_t,
            )
        else:
            # Uncropped single test: unscaled thresholds (F20).
            overall = welch_t_test(c0, c1, warn_t, fail_t)
        batches = batch_t_scores(
            samples.classes, samples.cycles,
            batches=dud.batches,
            warning_threshold=warn_t,
            fail_threshold=fail_t,
        )
        results.append((h.name, samples, overall, batches))

        crop_tag = (
            f" crop@{overall.cropped_at:.2f}"
            if overall.cropped_at is not None
            else ""
        )
        console.print(
            f"   n0={overall.n0} n1={overall.n1} "
            f"mean0={overall.mean0:.1f} mean1={overall.mean1:.1f} "
            f"t={overall.t_score:+.2f}{crop_tag} [bold]{overall.status}[/]"
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
        "harness", "n0", "n1", "mean0", "mean1", "|t|", "crop@",
        "status", "batch max|t|",
    ):
        table.add_column(col)
    for name, _, r, batches in results:
        batch_max = (
            f"{max(b.abs_t_score for b in batches):.2f}" if batches else "-"
        )
        style = {
            "PASS": "green",
            "WARNING": "yellow",
            "FAIL": "bold red",
            "ERROR": "bold magenta",
        }.get(r.status, "")
        status_cell = f"[{style}]{r.status}[/]" if style else r.status
        crop_cell = (
            f"{r.cropped_at:.2f}" if r.cropped_at is not None else "-"
        )
        # T22: an ERROR row means measurement never completed — the
        # underlying WelchResult is _error_welch's all-zeros sentinel.
        # Rendering `n0=0 mean=0.00 |t|=0.00` makes the row visually
        # indistinguishable from a real successful measurement that
        # happened to score 0, so we collapse the numeric cells to `-`
        # and let the magenta status cell carry the signal.
        if r.status == "ERROR":
            table.add_row(
                name, "-", "-", "-", "-", "-",
                crop_cell, status_cell, "-",
            )
            continue
        table.add_row(
            name, str(r.n0), str(r.n1),
            f"{r.mean0:.1f}", f"{r.mean1:.1f}",
            f"{r.abs_t_score:.2f}",
            crop_cell,
            status_cell,
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
        None, "--seed",
        help="Override yaml seed. Integer (decimal or 0x-prefixed hex) or 'random'.",
    ),
    crop: bool = typer.Option(
        True, "--crop/--no-crop",
        help="Apply dudect percentile cropping (default on). Use --no-crop "
             "to report raw uncropped t-scores, e.g. for comparison against "
             "external dudect runs.",
    ),
):
    """Run only the dudect-style statistical timing check."""
    cfg = _load_config_or_exit(config)
    cfg_dir = config.parent.resolve()
    if cfg.dudect is None:
        console.print("[red]No `dudect` section in config.[/]")
        raise typer.Exit(2)

    dud = cfg.dudect
    updates = {}
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
    results = _do_dudect(dud, cfg_dir, cfg.project.name, out_dir, crop=crop)
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
    if any_fail:
        console.print("[bold red][CTKAT] dudect Timing Check: FAIL[/]")
        raise typer.Exit(2)
    if any_err:
        console.print(
            "[bold yellow][CTKAT] dudect Timing Check: INCOMPLETE[/] "
            "(see ERROR lines above) — analysis did not complete for at "
            "least one harness; this is NOT a PASS."
        )
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
        else:
            d_status = dud_pair[0].status
            abs_t = dud_pair[0].abs_t_score
        verdicts.append(HarnessVerdict(
            name=name,
            valgrind_status=v_status,
            dudect_status=d_status,
            verdict=combine(v_status, d_status, kat_status=kat_status),
            valgrind_finding_count=(len(findings) if findings else 0),
            dudect_abs_t=abs_t,
        ))
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
        w.writerow([
            "project", "harness",
            "valgrind_status", "valgrind_findings",
            "dudect_status", "dudect_abs_t",
            "verdict",
            "kat_status", "kat_count",
        ])
        for v in verdicts:
            w.writerow([
                project, v.name,
                v.valgrind_status, v.valgrind_finding_count,
                v.dudect_status,
                _fmt(v.dudect_abs_t) if v.dudect_abs_t is not None else "",
                v.verdict.value,
                kat_status, kat_count_str,
            ])
    return path


def _print_verdicts(verdicts: List[HarnessVerdict]) -> None:
    if not verdicts:
        return
    table = Table(title="Combined verdict (Valgrind + dudect)")
    for col in ("harness", "valgrind", "dudect", "|t|", "verdict"):
        table.add_column(col)
    for v in verdicts:
        abs_t = (_fmt(v.dudect_abs_t, digits=2) or "inf") if v.dudect_abs_t is not None else "-"
        style = VERDICT_STYLES.get(v.verdict, "")
        verdict_cell = f"[{style}]{v.verdict.value}[/]" if style else v.verdict.value
        table.add_row(v.name, v.valgrind_status, v.dudect_status, abs_t, verdict_cell)
    console.print(table)


@app.command()
def run(
    config: Path = typer.Option(..., "--config", "-c", help="Path to ctkat.yaml"),
    continue_on_kat_fail: bool = typer.Option(False, "--continue-on-kat-fail"),
    crop: bool = typer.Option(
        True, "--crop/--no-crop",
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
                "[bold yellow][CTKAT] Constant-Time Check: INCOMPLETE[/] "
                "(see ERROR lines above)"
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
            cfg.dudect, cfg_dir, cfg.project.name, out_dir, crop=crop,
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
                out_dir, cfg.project.name, verdicts,
                kat_status=kat_status, kat_count=kat_count,
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
            "[bold red][CTKAT] config error:[/] `ct` section has no harnesses "
            "— nothing to analyze."
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
            "[bold yellow][CTKAT] Constant-Time Check: INCOMPLETE[/] "
            "(see ERROR lines above)"
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
        None, "--opt",
        help="Optimization level to scan (repeatable). Default: -O0 -Os -O2. "
             "The ct stage's own -O level is always added on top.",
    ),
    cc: Optional[List[str]] = typer.Option(
        None, "--cc",
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
    real `div` at -Os, so a single-build scan would find nothing (see
    docs/kyberslash_direction.md §8.7/§8.8). This compiles each source at
    several opt levels and reports which build a division survives in.

    NOT a taint analysis: it reports every division-family instruction in the
    sources, secret or not (so public divisions, e.g. Keccak rate math, also
    show up). Output is a SEPARATE artifact (ctkat_varlat_candidates.csv/json)
    and never affects the FAIL verdict — these are candidates, not proven
    secret-dependent.

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
    cc_errors = [
        {"compiler": c, "error": "compiler not found on PATH"} for c in missing_cc
    ]
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
        "[dim](warn-only; does not affect verdict)[/]"
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
                cc_cands.extend(scan_harness(
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
                ))
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
        cfg.project.name, candidates, json_path,
        opt_levels=tuple(sorted(scanned)),
        compilers=tuple(scanned_ok),
        errors=cc_errors,
    )

    if candidates:
        table = Table(title="Variable-latency candidates in harness sources (warn-only)")
        for col in ("compiler", "harness", "source", "function", "mnem", "opt levels", "n"):
            table.add_column(col)
        for c in candidates:
            table.add_row(
                c.compiler, c.harness, c.source_file, c.function,
                ";".join(c.mnemonics), ";".join(c.opt_levels), str(c.count),
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
    (compilers × named cflags combos; default gcc × debug/release/size) and runs
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
        include_dirs = [_resolve(cfg_dir, d) for d in h.include_dirs]
        sources = [_resolve(cfg_dir, s) for s in h.sources]
        # The harness's effective cflags carry build-selection flags (e.g.
        # `-DPQCLEAN_NO_GLIBC_RANDOMBYTES`). The matrix swaps only the -O/codegen
        # flags per combo, so these preprocessor defines must ride along into
        # every cell — else the matrix builds a different program than `ct`.
        base_cflags = h.cflags if h.cflags is not None else cfg.ct.cflags
        source_path = generated_dir / f"harness_{h.name}.c"
        try:
            code = render_harness(h.template, _template_context(h, cfg.ct.seed))
        except HarnessGenerationError as e:
            console.print(f"[bold red][CTKAT] ct-matrix: harness render FAIL ({h.name})[/]\n{e}")
            raise typer.Exit(1)
        _atomic_write_text(source_path, code)
        harness_inputs.append(HarnessInputs(
            name=h.name, source_path=source_path,
            sources=sources, include_dirs=include_dirs,
            extra_cflags=preprocessor_cflags(base_cflags),
        ))

    console.print(
        f"[bold cyan]==> ct-matrix[/]: combos = {', '.join(c.label for c in combos)} "
        "[dim](observational; NOT a verdict gate)[/]"
    )
    rows = scan_ct_matrix(
        harness_inputs, combos,
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
        cfg.project.name, rows, json_path,
        combos=combos, compilers=requested_compilers,
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
    for h in harness_inputs:
        h_rows = [r for r in rows if r.harness == h.name]
        verdicts = {r.valgrind_status for r in h_rows if r.valgrind_status in ("PASS", "FAIL")}
        errored = [r for r in h_rows if r.valgrind_status == "ERROR"]
        if len(verdicts) > 1:
            console.print(
                f"[bold yellow]ct-matrix: harness '{h.name}' has DIFFERENT CT "
                f"results across builds[/] ({', '.join(sorted(verdicts))}) — the "
                "tested binary and a differently-built binary disagree."
            )
        if errored:
            console.print(
                f"[yellow]ct-matrix: harness '{h.name}': {len(errored)} build "
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
        console.print(
            f"[bold magenta]{unknown_count} parameter(s) need manual role assignment.[/]"
        )
    else:
        console.print("[bold green]All parameters inferred.[/]")


@app.command()
def parse(
    log: Path = typer.Argument(
        ..., exists=True, file_okay=True, dir_okay=False, readable=True,
        help="Path to a valgrind log file",
    ),
):
    """Parse a single Valgrind log and print findings (debugging helper)."""
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
        console.print(
            f"[bold]{i}.[/] [{f.severity.value}] [bold]{f.type.value}[/] — {f.message}"
        )
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
