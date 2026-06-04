"""Phase C: the compiler × cflags Valgrind matrix behind the `ct-matrix`
subcommand.

Observational ONLY — these rows NEVER feed `ctkat_verdict.csv` or the `run`
gate. The product is a separate `ctkat_ct_matrix.csv` / `.json` showing how the
SAME source's structural-CT conclusion (PASS / FAIL / ERROR) moves across build
configurations (gcc/clang × debug/release/size). Where asm-scan is the "which
instruction survives" table, this is the "what the Valgrind check concludes per
build" table — the direct evidence for "same source, different build → different
CT verdict".

Reuses the single-build pieces unchanged, so the matrix can never disagree with
the `ct` stage on an identical (cc, cflags) cell:
    render once per harness  ->  compile_harness(cc=...)  ->  run_valgrind
    ->  classify_valgrind_run   (the shared ct_runner mapping)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from .ct_runner import classify_valgrind_run
from .harness_generator import HarnessGenerationError, compile_harness
from .valgrind_runner import run_valgrind


# Flags whose VALUE is the NEXT token when they appear bare ("-D FOO", "-I dir",
# "-isystem path"). The glued forms ("-DFOO", "-I/inc") are kept by the
# startswith branch below. `-D`/`-U`/`-I` are valid in BOTH forms (e.g. flags
# copied from a make/pkg-config line), so they must be here too — dropping the
# value token of a spaced `-D FOO` would build a different/broken program than
# the ct stage (the exact divergence this function exists to prevent).
_PP_BARE_VALUE = (
    "-D", "-U", "-I",
    "-isystem", "-iquote", "-include", "-imacros", "-idirafter", "-isysroot",
)


def preprocessor_cflags(cflags: List[str]) -> List[str]:
    """Extract the preprocessor / build-selection flags (`-D`, `-U`, `-I` and the
    `-isystem`/`-iquote`/`-include` family) from a cflags list — both glued
    (`-DFOO`) and spaced (`-D FOO`) forms.

    These are INVARIANT across the optimization combos and must appear in EVERY
    matrix build: dropping a project's `-DPQCLEAN_NO_GLIBC_RANDOMBYTES`-style
    define (or an `-isystem` path) would make the matrix compile a *different*
    program than the `ct` stage, silently invalidating the comparison. The combo
    owns the `-O`/`-g`/codegen flags, so those are deliberately NOT kept here.
    Same intent as asm-scan's T17 forwarding and coverage_check's probe-flag
    filter, but selective (only preprocessor flags)."""
    out: List[str] = []
    i = 0
    while i < len(cflags):
        f = cflags[i]
        if f in _PP_BARE_VALUE:                 # spaced form: consume the value token
            if i + 1 < len(cflags):
                out.extend([f, cflags[i + 1]])
            i += 2
            continue
        if f.startswith(("-D", "-U", "-I")):    # glued form: -DFOO / -I/inc
            out.append(f)
        i += 1
    return out


@dataclass(frozen=True)
class Combo:
    """One (compiler, named-cflags) build configuration."""

    cc: str
    cflags_name: str
    cflags: Tuple[str, ...]

    @property
    def label(self) -> str:
        # artifact `combo` value + per-cell binary/log filename suffix. Both
        # `cc` and `cflags_name` are constrained upstream (MatrixConfig combo
        # name regex; cc is argv[0], not shell) so this is filesystem-safe.
        return f"{self.cc}_{self.cflags_name}"


def expand_combos(compilers: List[str], ct_cflags: Dict[str, List[str]]) -> List[Combo]:
    """Cartesian product compilers × named cflags combos. Compilers are de-duped
    (first-seen order kept); cflags-combo order follows dict insertion (i.e. the
    order the combos appear in the yaml)."""
    out: List[Combo] = []
    for cc in dict.fromkeys(compilers):
        for name, flags in ct_cflags.items():
            out.append(Combo(cc=cc, cflags_name=name, cflags=tuple(flags)))
    return out


@dataclass
class CtMatrixRow:
    harness: str
    combo: str                 # label, e.g. "gcc_release"
    cc: str
    cflags: Tuple[str, ...]
    valgrind_status: str       # PASS | FAIL | ERROR
    findings: int = 0
    error: str = ""            # reason when status == ERROR (compile/valgrind)
    dropped: int = 0           # parser-ignored lines (stale-parser canary; not in CSV)


@dataclass
class HarnessInputs:
    """One template harness already rendered to `source_path`. The matrix
    compiles this same source under every combo (render once, build many).

    `extra_cflags` are the harness's preprocessor/build-selection flags (defines,
    -isystem paths) that must be carried into EVERY combo so the matrix builds
    the same program the ct stage does (see `preprocessor_cflags`)."""

    name: str
    source_path: Path
    sources: List[Path]
    include_dirs: List[Path]
    extra_cflags: List[str] = field(default_factory=list)


def _first_line(s: str) -> str:
    body = s.strip()
    return (body.splitlines()[0] if body else "")[:200]


def scan_ct_matrix(
    harnesses: List[HarnessInputs],
    combos: List[Combo],
    *,
    workdir: Path,
    binaries_dir: Path,
    valgrind_flags: List[str],
    compile_timeout: float,
    valgrind_timeout: float,
    lookup_patterns: Optional[List[str]] = None,
    on_progress: Optional[Callable[[str], None]] = None,
) -> List[CtMatrixRow]:
    """Compile + Valgrind each (harness × combo) and classify the result.

    A compile failure/timeout for one cell becomes a status=ERROR row carrying
    the reason and the sweep CONTINUES — one bad build configuration must not
    abort the whole matrix (that observation, "this combo doesn't even build",
    is itself a data point). A Valgrind crash/timeout lands as ERROR via the
    shared `classify_valgrind_run` (rc=124 → ERROR), identical to the `ct` stage.
    """
    binaries_dir.mkdir(parents=True, exist_ok=True)
    rows: List[CtMatrixRow] = []
    for h in harnesses:
        for combo in combos:
            if on_progress:
                on_progress(f"{h.name} / {combo.label}")
            binary = binaries_dir / f"harness_{h.name}__{combo.label}"
            log = binaries_dir / f"valgrind_{h.name}__{combo.label}.log"
            try:
                compile_harness(
                    source_path=h.source_path,
                    binary_path=binary,
                    sources=h.sources,
                    include_dirs=h.include_dirs,
                    # combo owns -O/codegen; the harness's defines/includes are
                    # carried into every cell so we build the SAME program the
                    # ct stage builds, just at a different opt level.
                    cflags=list(combo.cflags) + list(h.extra_cflags),
                    workdir=workdir,
                    timeout=compile_timeout,
                    cc=combo.cc,
                )
            except HarnessGenerationError as e:
                rows.append(CtMatrixRow(
                    harness=h.name, combo=combo.label, cc=combo.cc,
                    cflags=combo.cflags, valgrind_status="ERROR", findings=0,
                    error=f"compile failed: {_first_line(str(e))}",
                ))
                continue
            result = run_valgrind(
                binary, log, valgrind_flags, workdir, timeout=valgrind_timeout,
            )
            outcome = classify_valgrind_run(
                result, log, lookup_patterns=lookup_patterns,
            )
            rows.append(CtMatrixRow(
                harness=h.name, combo=combo.label, cc=combo.cc,
                cflags=combo.cflags, valgrind_status=outcome.status,
                findings=len(outcome.findings), error=outcome.error,
                dropped=outcome.dropped,
            ))
    return rows


# --- artifact writers (separate file from ctkat_verdict.csv ON PURPOSE) ------

CT_MATRIX_CSV_FIELDS = [
    "project", "harness", "combo", "cc", "cflags",
    "valgrind_status", "findings", "error",
]


def row_to_dict(project: str, r: CtMatrixRow) -> Dict[str, str]:
    return {
        "project": project,
        "harness": r.harness,
        "combo": r.combo,
        "cc": r.cc,
        "cflags": " ".join(r.cflags),
        "valgrind_status": r.valgrind_status,
        "findings": str(r.findings),
        "error": r.error,
    }


def write_ct_matrix_csv(project: str, rows: List[CtMatrixRow], path: Path) -> None:
    import csv

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CT_MATRIX_CSV_FIELDS, lineterminator="\n")
        w.writeheader()
        for r in rows:
            w.writerow(row_to_dict(project, r))


def write_ct_matrix_json(
    project: str,
    rows: List[CtMatrixRow],
    path: Path,
    *,
    combos: List[Combo],
    compilers: List[str],
) -> None:
    import json

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "project": project,
        "kind": "ct_matrix",
        # explicit so no downstream tooling mistakes this for a verdict gate.
        "verdict_independent": True,
        "scanned_compilers": list(dict.fromkeys(compilers)),
        "combos": [c.label for c in combos],
        "rows": [row_to_dict(project, r) for r in rows],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
