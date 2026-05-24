import csv
import math
import secrets
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def _fmt(x: float, digits: int = 3) -> str:
    """CSV-safe float formatting: non-finite values become empty so pandas/R
    don't have to special-case the literal strings 'inf' / 'nan'. The
    accompanying `status` column already carries the information that a
    measurement blew up (it'll be FAIL whenever t_score is infinite)."""
    if not math.isfinite(x):
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
from .statistics import WelchResult, batch_t_scores, welch_t_test
from .timing_harness_generator import generate_and_compile_timing
from .valgrind_parser import Finding, parse_valgrind_log
from .valgrind_runner import run_valgrind
from .verdict import VERDICT_STYLES, HarnessVerdict, Verdict, combine


app = typer.Typer(help="CT-KAT: KAT + Valgrind based constant-time check framework")
console = Console()


def _resolve(base: Path, p: Path) -> Path:
    return p if p.is_absolute() else (base / p).resolve()


def _do_build(cfg: CtkatConfig, cfg_dir: Path) -> bool:
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
    console.print("[green][CTKAT] Build: PASS[/]")
    return True


def _do_kat(cfg: CtkatConfig, cfg_dir: Path) -> bool:
    # Use raise rather than assert — `python -O` strips asserts and we don't
    # want a security tool's invariants disappearing in optimized builds.
    if cfg.kat is None:
        raise ValueError("_do_kat called with no `kat` section in config")
    console.print(f"[bold cyan]==> KAT[/]: {cfg.kat.command}")
    workdir = _resolve(cfg_dir, cfg.kat.workdir)
    r = run_shell(cfg.kat.command, workdir)
    if not r.ok:
        console.print("[bold red][CTKAT] KAT: FAIL[/]")
        if r.stdout:
            console.print(r.stdout)
        if r.stderr:
            console.print(r.stderr)
        return False
    console.print("[green][CTKAT] KAT: PASS[/]")
    return True


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
) -> dict:
    base = {
        "extra_headers": list(h.extra_headers),
        "measurements": dud.measurements,
        "warmup": dud.warmup,
        "seed": effective_seed,
        "clock": dud.clock,
    }
    if h.template == "kem":
        base.update({
            "header": h.header,
            "prefix": h.prefix,
        })
    else:  # generic
        base.update({
            "function": h.function,
            "args": list(h.args),
            "return_type": h.return_type,
            "buffers": [b.model_dump() for b in h.buffers],
        })
    return base


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
        w.writerow([
            "project", "harness",
            "n0", "n1",
            "mean0", "mean1", "var0", "var1",
            "t_score", "abs_t_score", "status",
            "batch_t_mean", "batch_t_max_abs", "batches",
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
            ])
    return raw_path, summary_path


def _do_dudect(
    dud: DudectConfig,
    cfg_dir: Path,
    project_name: str,
    out_dir: Path,
) -> List[Tuple[str, TimingSamples, WelchResult, List[WelchResult]]]:
    qemu = detect_qemu_emulation()
    if qemu and dud.clock == "rdtsc":
        console.print(
            "[bold yellow]WARNING:[/] QEMU emulation detected — rdtsc cycle "
            "counts here are NOT a reliable signal for timing analysis. "
            "Consider [bold]clock: monotonic[/] in your ctkat.yaml, or run on "
            "a native x86_64 Linux host."
        )
    elif qemu and dud.clock == "monotonic":
        console.print(
            "[yellow]Note:[/] QEMU emulation detected. clock=monotonic is "
            "safe for [italic]qualitative[/] comparison (effect "
            "presence/direction), but absolute timing conclusions and "
            "borderline verdicts should be re-verified on a native x86_64 "
            "Linux host."
        )

    effective_seed = dud.seed if dud.seed is not None else secrets.randbits(63)
    console.print(f"[dim]dudect seed = 0x{effective_seed:X}[/]")
    console.print(
        f"[dim]measurements={dud.measurements} warmup={dud.warmup} "
        f"batches={dud.batches} clock={dud.clock}[/]"
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
                context=_dudect_context(h, dud, effective_seed),
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
        samples = run_timing_harness(gen.binary_path, workdir)

        c0 = [c for cls, c in zip(samples.classes, samples.cycles) if cls == 0]
        c1 = [c for cls, c in zip(samples.classes, samples.cycles) if cls == 1]
        if len(c0) < 2 or len(c1) < 2:
            console.print(
                f"[red]Not enough samples per class for {h.name}: "
                f"n0={len(c0)} n1={len(c1)}[/]"
            )
            raise typer.Exit(1)

        overall = welch_t_test(c0, c1, dud.threshold_warning, dud.threshold_fail)
        batches = batch_t_scores(
            samples.classes, samples.cycles,
            batches=dud.batches,
            warning_threshold=dud.threshold_warning,
            fail_threshold=dud.threshold_fail,
        )
        results.append((h.name, samples, overall, batches))

        console.print(
            f"   n0={overall.n0} n1={overall.n1} "
            f"mean0={overall.mean0:.1f} mean1={overall.mean1:.1f} "
            f"t={overall.t_score:+.2f} [bold]{overall.status}[/]"
        )

    _emit_dudect_report(project_name, out_dir, results)
    return results


def _print_dudect_summary(
    results: List[Tuple[str, TimingSamples, WelchResult, List[WelchResult]]],
) -> None:
    if not results:
        return
    table = Table(title="dudect timing summary")
    for col in ("harness", "n0", "n1", "mean0", "mean1", "|t|", "status", "batch max|t|"):
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
        table.add_row(
            name, str(r.n0), str(r.n1),
            f"{r.mean0:.1f}", f"{r.mean1:.1f}",
            f"{r.abs_t_score:.2f}",
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
    results = _do_dudect(dud, cfg_dir, cfg.project.name, out_dir)
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
) -> List[HarnessVerdict]:
    """Merge ct + dudect outcomes per harness name; missing side becomes NONE."""
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
            verdict=combine(v_status, d_status),
            valgrind_finding_count=(len(findings) if findings else 0),
            dudect_abs_t=abs_t,
        ))
    return verdicts


def _emit_verdicts(out_dir: Path, project: str, verdicts: List[HarnessVerdict]) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "ctkat_verdict.csv"
    with open(path, "w", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow([
            "project", "harness",
            "valgrind_status", "valgrind_findings",
            "dudect_status", "dudect_abs_t",
            "verdict",
        ])
        for v in verdicts:
            w.writerow([
                project, v.name,
                v.valgrind_status, v.valgrind_finding_count,
                v.dudect_status,
                _fmt(v.dudect_abs_t) if v.dudect_abs_t is not None else "",
                v.verdict.value,
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
):
    """Run the full pipeline: build -> kat -> ct -> dudect -> report."""
    cfg = load_config(config)
    cfg_dir = config.parent.resolve()

    if not _do_build(cfg, cfg_dir):
        raise typer.Exit(1)

    if cfg.kat is not None:
        if not _do_kat(cfg, cfg_dir) and not continue_on_kat_fail:
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
        dud_results = _do_dudect(cfg.dudect, cfg_dir, cfg.project.name, out_dir)
        _print_dudect_summary(dud_results)
        any_dudect_fail = any(r.status == "FAIL" for _, _, r, _ in dud_results)
        any_dudect_warn = any(r.status == "WARNING" for _, _, r, _ in dud_results)

    # Combined verdict — only meaningful when at least one stage ran.
    if cfg.ct is not None or (cfg.dudect is not None and cfg.dudect.enabled):
        verdicts = _compute_verdicts(ct_results, dud_results)
        if verdicts:
            _print_verdicts(verdicts)
            out_dir = _resolve(cfg_dir, cfg.report.output_dir)
            verdict_csv = _emit_verdicts(out_dir, cfg.project.name, verdicts)
            console.print(f"[dim]Verdict CSV: {verdict_csv}[/]")

    if any_finding or any_dudect_fail:
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
    if cfg.kat is None:
        console.print("[yellow]No `kat` section in config.[/]")
        raise typer.Exit(0)
    if not _do_kat(cfg, cfg_dir):
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
