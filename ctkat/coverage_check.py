"""Bundle F (F6): cross-check `sum(secret_regions.length)` vs
`{prefix}CRYPTO_SECRETKEYBYTES` for ct kem/sign template harnesses.

Why this exists
---------------
The README ML-KEM walkthrough teaches users to write `secret_regions` to
taint only the actual secret bytes inside a composite `sk` blob — but a
typo (`length: 32` instead of `KYBER_INDCPA_SECRETKEYBYTES`) silently
shrinks taint coverage so secret-dependent code paths operating on the
untainted bytes produce no Valgrind findings → false PASS. We can't catch
that with a Python-side integer check because the length is usually a C
macro (`PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES` etc.) only the C
preprocessor knows about.

How it works
------------
Emit a tiny sentinel program that includes the user's header(s),
evaluates both `sum(secret_regions.length)` and the expected total
macro under the same compiler+headers the real harness uses, and prints
both as integers. Parse the output, divide, warn if the covered fraction
falls below `threshold`.

Failure handling
----------------
F6 is a *diagnostic*, never a gate — compile/exec/parse failures emit a
yellow note and return None so the real ct pipeline continues. A wrong
F6 (e.g. headers behind an ifdef our probe doesn't define) must not
prevent the user from getting a verdict.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from ._proc import run_text

from rich.console import Console


_console = Console()

# Single line, locale-independent. Anything else and we treat parsing as
# failed and bail.
# Third group (max_end = max(offset+length)) is optional — only emitted when
# offsets are supplied (F21). Old two-field callers still parse.
_SENTINEL_RE = re.compile(
    r"^CTKAT-COVERAGE\s+(\d+)\s+(\d+)(?:\s+(\d+))?\s*$", re.MULTILINE
)

# Default warn threshold. Anything below this and the user almost
# certainly mis-numbered a length field.
DEFAULT_COVERAGE_WARN_THRESHOLD = 0.5


@dataclass
class CoverageResult:
    covered: int
    total: int
    ratio: float


def _render_sentinel_c(
    header: str,
    extra_headers: List[str],
    prefix: str,
    secret_region_lengths: List[str],
    secret_region_offsets: Optional[List[str]] = None,
) -> str:
    # F22/T23: `header`, `extra_headers`, `prefix` and each offset/length flow
    # in from an already-validated HarnessConfig / SecretRegion (config.py
    # `_check_header` / `_check_c_expr` / `_C_IDENT_PATTERN`), so the values
    # interpolated below are injection-safe by construction. The config-load
    # validators are the single chokepoint; don't re-derive these from
    # unvalidated input without re-validating.
    sum_expr = " + ".join(f"({length})" for length in secret_region_lengths) or "0"
    total_macro = f"{prefix}CRYPTO_SECRETKEYBYTES"
    includes = [f'#include "{header}"'] + [f'#include "{h}"' for h in extra_headers]
    head = (
        "#include <stddef.h>\n"
        "#include <stdio.h>\n"
        + "\n".join(includes) + "\n"
        "int main(void) {\n"
        f"    size_t covered = (size_t)({sum_expr});\n"
        f"    size_t total = (size_t)({total_macro});\n"
    )
    if secret_region_offsets is not None:
        # F21: also compute max(offset + length) so the caller can detect an
        # out-of-bounds region (offset+length > CRYPTO_SECRETKEYBYTES), which
        # would taint stack memory past `sk`. The macros are only known to the
        # C preprocessor, so the arithmetic has to happen here, not in Python.
        ends = ", ".join(
            f"({o}) + ({l})"
            for o, l in zip(secret_region_offsets, secret_region_lengths)
        ) or "0"
        return (
            head
            + f"    size_t ends[] = {{ {ends} }};\n"
            + "    size_t max_end = 0;\n"
            + "    for (size_t i = 0; i < sizeof(ends)/sizeof(ends[0]); i++)\n"
            + "        if (ends[i] > max_end) max_end = ends[i];\n"
            + '    printf("CTKAT-COVERAGE %zu %zu %zu\\n", covered, total, max_end);\n'
            + "    return 0;\n"
            + "}\n"
        )
    return (
        head
        + '    printf("CTKAT-COVERAGE %zu %zu\\n", covered, total);\n'
        + "    return 0;\n"
        + "}\n"
    )


def _filter_probe_cflags(cflags: List[str]) -> List[str]:
    """Bundle P (T17): keep only the user cflags that affect *which* macros
    / headers the preprocessor sees. We don't want to inherit `-O*`,
    `-fno-lto`, `-g`, etc. — those don't influence which `#ifdef CONFIG_X`
    branches the probe takes, and propagating them blindly could break
    the probe in unrelated ways (probe is intentionally `-O0`).
    """
    keep: List[str] = []
    skip_next = False
    for flag in cflags:
        if skip_next:
            keep.append(flag)
            skip_next = False
            continue
        if flag.startswith(("-D", "-U", "-isystem", "-iquote", "-I")):
            keep.append(flag)
            # `-isystem path` / `-iquote path` / `-I path` use a separate
            # argv slot for the value. `-Dx`, `-Dx=1`, `-Ipath` (no space)
            # are single-arg and don't need this.
            if flag in ("-isystem", "-iquote", "-I", "-D", "-U"):
                skip_next = True
    return keep


def check_secret_region_coverage(
    *,
    harness_name: str,
    header: str,
    extra_headers: List[str],
    prefix: str,
    secret_region_lengths: List[str],
    include_dirs: List[Path],
    workdir: Path,
    cc: str = "gcc",
    extra_compile_args: Optional[List[str]] = None,
    threshold: float = DEFAULT_COVERAGE_WARN_THRESHOLD,
    secret_region_offsets: Optional[List[str]] = None,
) -> Optional[CoverageResult]:
    """Compile + run the sentinel probe.

    Returns the (covered, total, ratio) result on success (even when the
    ratio triggered a warning). Returns None on any failure mode and
    emits a yellow note explaining why so the user can fix it manually.
    Never raises — F6 is diagnostic.
    """
    if not secret_region_lengths:
        # No secret_regions = full-sk taint policy, nothing to cross-check.
        return None
    src = _render_sentinel_c(
        header, extra_headers, prefix, secret_region_lengths,
        secret_region_offsets=secret_region_offsets,
    )
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        src_path = td_path / "ctkat_coverage_probe.c"
        bin_path = td_path / "ctkat_coverage_probe"
        src_path.write_text(src, encoding="utf-8")
        cmd = [cc, "-O0", str(src_path), "-o", str(bin_path)]
        for d in include_dirs:
            cmd.extend(["-I", str(d)])
        # T17: propagate `-D`/`-U`/`-isystem` so user headers gated on
        # `#ifdef CONFIG_X` reach the probe with the same preprocessor
        # state the real harness will see. Without this, complex header
        # chains silently fail to compile the probe → "F6 coverage check
        # skipped" yellow note → F6 effectively a no-op.
        if extra_compile_args:
            cmd.extend(_filter_probe_cflags(extra_compile_args))
        try:
            proc = run_text(cmd, cwd=workdir, timeout=30)
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            _console.print(
                f"[yellow][CTKAT] F6 coverage check skipped for "
                f"[bold]{harness_name}[/]: probe compile invocation failed "
                f"({e}).[/]"
            )
            return None
        if proc.returncode != 0:
            tail = (proc.stderr or "").strip().splitlines()[-3:]
            _console.print(
                f"[yellow][CTKAT] F6 coverage check skipped for "
                f"[bold]{harness_name}[/]: probe compile rc="
                f"{proc.returncode}. Stderr tail: {tail or '(empty)'}.[/]"
            )
            return None
        try:
            run = run_text([str(bin_path)], timeout=10)
        except subprocess.TimeoutExpired:
            _console.print(
                f"[yellow][CTKAT] F6 coverage check skipped for "
                f"[bold]{harness_name}[/]: probe timed out.[/]"
            )
            return None
        if run.returncode != 0:
            _console.print(
                f"[yellow][CTKAT] F6 coverage check skipped for "
                f"[bold]{harness_name}[/]: probe rc={run.returncode}.[/]"
            )
            return None
        m = _SENTINEL_RE.search(run.stdout)
        if m is None:
            # T28: the probe compiled AND ran (rc=0) — reaching here means its
            # stdout didn't match the sentinel format, not that the probe
            # failed. Say so explicitly rather than the ambiguous "skipped".
            _console.print(
                f"[yellow][CTKAT] F6 coverage check for "
                f"[bold]{harness_name}[/]: probe ran successfully but its "
                f"stdout format was unexpected (no CTKAT-COVERAGE line): "
                f"{run.stdout!r}. Skipping comparison.[/]"
            )
            return None
        covered = int(m.group(1))
        total = int(m.group(2))
        # F21: max(offset+length) over all regions, when offsets were supplied.
        max_end = int(m.group(3)) if m.group(3) is not None else None
        ratio = covered / total if total > 0 else 0.0
        result = CoverageResult(covered=covered, total=total, ratio=ratio)
        if total <= 0:
            _console.print(
                f"[yellow][CTKAT] F6 coverage check for "
                f"[bold]{harness_name}[/]: total=0 ({prefix}CRYPTO_"
                f"SECRETKEYBYTES mis-defined?). Skipping comparison.[/]"
            )
            return result
        # F21: out-of-bounds — a region extends past CRYPTO_SECRETKEYBYTES, so
        # the harness would VALGRIND_MAKE_MEM_UNDEFINED stack memory beyond
        # `sk` and surface false-positive findings. Diagnostic, never gates.
        if max_end is not None and max_end > total:
            _console.print(
                f"[bold yellow][CTKAT] WARNING:[/] harness [bold]"
                f"{harness_name}[/] has a secret_region ending at byte "
                f"{max_end} but {prefix}CRYPTO_SECRETKEYBYTES is only {total} "
                f"— an out-of-bounds offset/length taints memory past `sk` "
                f"(likely a yaml typo). (F21)"
            )
        # F21: covered (sum of lengths) exceeding total means the regions
        # overlap or double-count — ratio would read >100%.
        if covered > total:
            _console.print(
                f"[bold yellow][CTKAT] WARNING:[/] harness [bold]"
                f"{harness_name}[/] secret_regions sum to {covered} bytes but "
                f"{prefix}CRYPTO_SECRETKEYBYTES is only {total} — regions "
                f"overlap or double-count (sum > total). (F21)"
            )
            return result
        if ratio < threshold:
            _console.print(
                f"[bold yellow][CTKAT] WARNING:[/] harness [bold]"
                f"{harness_name}[/] secret_regions cover only "
                f"{covered}/{total} bytes ({ratio:.1%}) of "
                f"{prefix}CRYPTO_SECRETKEYBYTES. Most of `sk` is being "
                f"treated as public — almost certainly a yaml typo "
                f"(F6, threshold {threshold:.0%})."
            )
        else:
            _console.print(
                f"[dim][CTKAT] F6 coverage [bold]{harness_name}[/]: "
                f"{covered}/{total} bytes ({ratio:.1%}).[/]"
            )
        return result
