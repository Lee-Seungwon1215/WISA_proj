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
_SENTINEL_RE = re.compile(r"^CTKAT-COVERAGE\s+(\d+)\s+(\d+)\s*$", re.MULTILINE)

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
) -> str:
    sum_expr = " + ".join(f"({length})" for length in secret_region_lengths) or "0"
    total_macro = f"{prefix}CRYPTO_SECRETKEYBYTES"
    includes = [f'#include "{header}"'] + [f'#include "{h}"' for h in extra_headers]
    return (
        "#include <stddef.h>\n"
        "#include <stdio.h>\n"
        + "\n".join(includes) + "\n"
        "int main(void) {\n"
        f"    size_t covered = (size_t)({sum_expr});\n"
        f"    size_t total = (size_t)({total_macro});\n"
        '    printf("CTKAT-COVERAGE %zu %zu\\n", covered, total);\n'
        "    return 0;\n"
        "}\n"
    )


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
    threshold: float = DEFAULT_COVERAGE_WARN_THRESHOLD,
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
    src = _render_sentinel_c(header, extra_headers, prefix, secret_region_lengths)
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        src_path = td_path / "ctkat_coverage_probe.c"
        bin_path = td_path / "ctkat_coverage_probe"
        src_path.write_text(src, encoding="utf-8")
        cmd = [cc, "-O0", str(src_path), "-o", str(bin_path)]
        for d in include_dirs:
            cmd.extend(["-I", str(d)])
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
            _console.print(
                f"[yellow][CTKAT] F6 coverage check skipped for "
                f"[bold]{harness_name}[/]: probe output unparseable "
                f"({run.stdout!r}).[/]"
            )
            return None
        covered = int(m.group(1))
        total = int(m.group(2))
        ratio = covered / total if total > 0 else 0.0
        result = CoverageResult(covered=covered, total=total, ratio=ratio)
        if total <= 0:
            _console.print(
                f"[yellow][CTKAT] F6 coverage check for "
                f"[bold]{harness_name}[/]: total=0 ({prefix}CRYPTO_"
                f"SECRETKEYBYTES mis-defined?). Skipping comparison.[/]"
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
