import csv
import math
import platform
import re
import secrets
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
from rich.console import Console
from rich.table import Table

from .builder import run_shell
from .config import (
    CtkatConfig,
    DudectConfig,
    DudectHarnessConfig,
    HarnessConfig,
    load_config,
    resolve_clock,
)
from .dudect_runner import TimingSamples, run_timing_harness
from .harness_generator import (
    HarnessGenerationError,
    generate_and_compile,
)
from .header_parser import discover_headers, parse_header_file
from .qemu_detect import detect_qemu_emulation
from .report import finding_to_row, write_csv, write_json
from .secret_infer import InferredFunction, infer_functions
from .statistics import (
    WelchResult,
    batch_t_scores,
    welch_t_test,
    welch_with_cropping,
)
from .timing_harness_generator import generate_and_compile_timing
from .valgrind_parser import Finding, parse_valgrind_log
from .valgrind_runner import run_valgrind
from .verdict import VERDICT_STYLES, HarnessVerdict, Verdict, combine


app = typer.Typer(help="CT-KAT: KAT + Valgrind based constant-time check framework")
console = Console()


def _resolve(base: Path, p: Path) -> Path:
    return p if p.is_absolute() else (base / p).resolve()


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
    console.print(f"[bold cyan]==> Build[/]: {cfg.build.command}")
    workdir = _resolve(cfg_dir, cfg.build.workdir)
    r = run_shell(cfg.build.command, workdir)
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
    console.print(f"[bold cyan]==> KAT[/]: {cfg.kat.command}")
    workdir = _resolve(cfg_dir, cfg.kat.workdir)
    r = run_shell(cfg.kat.command, workdir)
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
    m = re.search(cfg.kat.expected_pattern, r.stdout or "")
    if m is not None:
        try:
            count = int(m.group(1))
        except (IndexError, ValueError):
            count = None
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
            )
        except HarnessGenerationError as e:
            console.print(f"[bold red][CTKAT] Harness generation FAIL ({h.name})[/]")
            console.print(str(e))
            raise typer.Exit(1)
        console.print(
            f"   [dim]source: {result.source_path}[/]\n"
            f"   [dim]binary: {result.binary_path}[/]"
        )
        paths[h.name] = result.binary_path
    return paths


def _do_ct(
    cfg: CtkatConfig,
    cfg_dir: Path,
    generated: Dict[str, Path],
) -> List[Tuple[str, List[Finding]]]:
    if cfg.ct is None:
        return []
    ct_cwd = _resolve(cfg_dir, cfg.ct.workdir)
    out_dir = _resolve(cfg_dir, cfg.report.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    results: List[Tuple[str, List[Finding]]] = []
    for h in cfg.ct.harnesses:
        if h.template is not None:
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
        result = run_valgrind(binary, log_path, cfg.ct.valgrind_flags, ct_cwd)
        # Expected Valgrind exit codes:
        #   0  — harness ran cleanly, no findings
        #   99 — findings detected (our --error-exitcode flag)
        # Anything else means the harness crashed (segfault, abort) or
        # Valgrind itself failed (bad flags, OOM, missing binary). Treating
        # a missing/empty log as "no findings" in those cases would silently
        # mark a broken run as PASS — exactly the fail-open pattern we
        # otherwise avoid (see verdict.combine() which raises on unknowns).
        if result.returncode not in (0, 99):
            tail = (result.stderr or "").strip().splitlines()[-3:]
            console.print(
                f"[bold red]WARNING:[/] valgrind exited with code "
                f"{result.returncode} on harness [bold]{h.name}[/] — analysis "
                f"may be incomplete or the harness binary itself failed. "
                f"Treat any subsequent PASS verdict for this harness as "
                f"inconclusive.\n"
                f"[dim]valgrind stderr tail: {tail or '(empty)'}[/]"
            )
        if not log_path.exists():
            console.print(
                f"[bold red]WARNING:[/] valgrind produced no log file at "
                f"{log_path} for harness [bold]{h.name}[/] — nothing to parse."
            )
        text = log_path.read_text() if log_path.exists() else ""
        findings = parse_valgrind_log(text)
        results.append((h.name, findings))
    return results


def _emit_report(
    cfg: CtkatConfig,
    cfg_dir: Path,
    ct_results: List[Tuple[str, List[Finding]]],
) -> Path:
    out_dir = _resolve(cfg_dir, cfg.report.output_dir)
    rows = []
    for harness_name, findings in ct_results:
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
                for name, fs in ct_results
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

    with open(raw_path, "w", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["project", "harness", "sample_id", "class", "cycles"])
        for harness_name, samples, _, _ in results:
            for i, (cls, cyc) in enumerate(zip(samples.classes, samples.cycles)):
                w.writerow([project, harness_name, i, cls, cyc])

    with open(summary_path, "w", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        # IMPORTANT: columns 1-14 are stable for backward compatibility —
        # scripts/run_phase4.sh parses $11 (status) via awk and we don't
        # want to break that contract. New diagnostic columns (cropped_at,
        # uncropped t-scores) go at the END.
        w.writerow([
            "project", "harness",
            "n0", "n1",
            "mean0", "mean1", "var0", "var1",
            "t_score", "abs_t_score", "status",
            "batch_t_mean", "batch_t_max_abs", "batches",
            "cropped_at", "t_score_uncropped", "abs_t_score_uncropped",
        ])
        for harness_name, _, r, batches in results:
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

    effective_seed = dud.seed if dud.seed is not None else secrets.randbits(63)
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
            )
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
        # into a status=ERROR result instead of a raw Python traceback. The
        # ERROR flows through _compute_verdicts → INCONCLUSIVE so the verdict
        # CSV reflects "couldn't verify" rather than silently dropping the
        # harness. Bundle F (S4) will preserve already-completed harnesses'
        # data the same way; the `continue` here is the foundation.
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
            overall = welch_with_cropping(
                c0, c1,
                warning_threshold=dud.threshold_warning,
                fail_threshold=dud.threshold_fail,
            )
        else:
            overall = welch_t_test(
                c0, c1, dud.threshold_warning, dud.threshold_fail
            )
        batches = batch_t_scores(
            samples.classes, samples.cycles,
            batches=dud.batches,
            warning_threshold=dud.threshold_warning,
            fail_threshold=dud.threshold_fail,
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
        }.get(r.status, "")
        status_cell = f"[{style}]{r.status}[/]" if style else r.status
        crop_cell = (
            f"{r.cropped_at:.2f}" if r.cropped_at is not None else "-"
        )
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
    cfg = load_config(config)
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
            updates["seed"] = int(seed, 0)
    if updates:
        dud = dud.model_copy(update=updates)

    out_dir = _resolve(cfg_dir, cfg.report.output_dir)
    results = _do_dudect(dud, cfg_dir, cfg.project.name, out_dir, crop=crop)
    _print_dudect_summary(results)

    any_fail = any(r.status == "FAIL" for _, _, r, _ in results)
    any_warn = any(r.status == "WARNING" for _, _, r, _ in results)
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
    ct_results: List[Tuple[str, List[Finding]]],
    dudect_results: List[Tuple[str, TimingSamples, WelchResult, List[WelchResult]]],
    kat_status: str = "NONE",
) -> List[HarnessVerdict]:
    """Merge ct + dudect outcomes per harness name; missing side becomes NONE.

    Bundle E-1 (F11): `kat_status` is now part of every harness verdict —
    a KAT FAIL flips the verdict to INCONCLUSIVE for every harness
    regardless of ct/dudect outcomes, because the analyses ran on
    functionally broken code. Defaults to NONE so callers that don't have
    a KAT stage keep their existing behavior.
    """
    ct_map = {name: findings for name, findings in ct_results}
    dud_map = {name: (r, batches) for name, _, r, batches in dudect_results}

    names: List[str] = []
    for name in ct_map:
        names.append(name)
    for name in dud_map:
        if name not in ct_map:
            names.append(name)

    verdicts: List[HarnessVerdict] = []
    for name in names:
        findings = ct_map.get(name)
        dud_pair = dud_map.get(name)
        v_status = "NONE" if findings is None else ("FAIL" if findings else "PASS")
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
    with open(path, "w", newline="") as f:
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
    cfg = load_config(config)
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

    ct_results: List[Tuple[str, List[Finding]]] = []
    any_finding = False
    if cfg.ct is not None:
        generated = _do_generate(cfg, cfg_dir)
        ct_results = _do_ct(cfg, cfg_dir, generated)
        any_finding = any(fs for _, fs in ct_results)
        if any_finding:
            console.print("[bold red][CTKAT] Constant-Time Check: FAIL[/]")
        else:
            console.print("[bold green][CTKAT] Constant-Time Check: PASS[/]")
        _emit_report(cfg, cfg_dir, ct_results)

    dud_results: List[Tuple[str, TimingSamples, WelchResult, List[WelchResult]]] = []
    any_dudect_fail = False
    any_dudect_warn = False
    if cfg.dudect is not None and cfg.dudect.enabled:
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
    cfg = load_config(config)
    cfg_dir = config.parent.resolve()
    # F8: previously fell through `_do_generate({}) → _do_ct([]) → any_finding=False`
    # and printed bold-green "PASS" with exit 0 when `ct:` section was absent.
    # That actively misleads CI consumers. Match the dudect subcommand's
    # Exit(2) and the new F7 fix for the kat subcommand.
    if cfg.ct is None:
        console.print("[red]No `ct` section in config.[/]")
        raise typer.Exit(2)
    generated = _do_generate(cfg, cfg_dir)
    ct_results = _do_ct(cfg, cfg_dir, generated)
    any_finding = any(fs for _, fs in ct_results)
    if any_finding:
        console.print("[bold red][CTKAT] Constant-Time Check: FAIL[/]")
    else:
        console.print("[bold green][CTKAT] Constant-Time Check: PASS[/]")
    _emit_report(cfg, cfg_dir, ct_results)
    if any_finding:
        raise typer.Exit(2)


@app.command()
def kat(
    config: Path = typer.Option(..., "--config", "-c", help="Path to ctkat.yaml"),
):
    """Run only the KAT stage."""
    cfg = load_config(config)
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
    for h in headers:
        sigs = parse_header_file(h)
        if function:
            sigs = [s for s in sigs if s.name == function]
        if not sigs:
            continue
        console.print(f"[cyan]==> {h}[/] [dim]({len(sigs)} function(s))[/]")
        all_funcs.extend(infer_functions(sigs))

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
    log: Path = typer.Argument(..., help="Path to a valgrind log file"),
):
    """Parse a single Valgrind log and print findings (debugging helper)."""
    text = log.read_text()
    findings = parse_valgrind_log(text)
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
