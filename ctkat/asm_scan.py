"""Phase 1 (KyberSlash direction §8.8): warn-only multi-opt scan for
variable-latency instruction candidates (integer division & friends) in a
harness's *own* crypto sources.

WHY multi-opt — the whole point, learned the hard way in Phase 0 (§8.7):
on CT-KAT's actual ct runtime (Docker amd64, gcc -O0) a *constant* divisor
like KyberSlash's `/KYBER_Q` is strength-reduced to a reciprocal multiply and
emits NO division instruction at all. The hardware division only survives at
some other optimization cells, notably `-Os` (and on clang -O0). So scanning a
single build would advertise KyberSlash detection while finding nothing. We
compile each source at several optimization levels and report *which build* a
division survives in. The "div
survives at -Os but not at the ct stage's -O0" asymmetry is the finding.

Scope honesty (no overclaiming): there is NO taint here. We
report *every* division-family instruction in the configured sources, secret
or not. That is why a real run also surfaces public divisions (e.g. Keccak
rate math in fips202.c). These are *candidates in harness sources*, NOT proven
secret-dependent — proving that is the patched-Valgrind path (Phase 2). Hence:
  - WARN-ONLY: output goes to a SEPARATE artifact
    (`ctkat_varlat_candidates.csv/json`) and never feeds the FAIL verdict; a
    crude false positive cannot break CI (§8.1).
  - `triage_hint` is also warn-only: it labels common review buckets such as
    KyberSlash poly helpers and public Keccak rate arithmetic, but it is NOT
    the harness-level `varlat_triage` verdict input.
  - `mul`/`imul` is EXCLUDED: the ML-KEM fix is itself `*80635 >> 28` (a
    reciprocal multiply), so flagging multiply would trip the negative
    control (§8.3).

Multi-arch on purpose (x86 `idiv`/`div`, ARM `sdiv`/`udiv`, RISC-V
`div`/`divu`/`rem`/`remu`) so the same scan is meaningful on the amd64 Docker
image and on a developer's arm64 host. Function names are resolved from the
symbol table (`nm`) rather than objdump's disassembly labels, because LLVM
objdump on Mach-O labels code with linker-temp symbols (`ltmp0`) instead of
the real `_func` — the symbol table has the real name at the same address.
"""

from __future__ import annotations

import bisect
import re
import subprocess as _sp
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ._proc import run_text


# Optimization levels scanned by default. The ct stage's own opt level is added
# on top of these per-harness by the caller so the "absent at <ct opt>" note is
# always backed by an actual scan.
DEFAULT_OPT_LEVELS: Tuple[str, ...] = ("-O0", "-O1", "-O2", "-O3", "-Os")

# A disassembled instruction is a variable-latency *division candidate* if its
# mnemonic fully matches one of these. x86 size suffixes (idivl/divq/…), ARM
# sdiv/udiv, RISC-V div/divu/rem/remu and their `*w` word variants. The anchors
# matter: without `$`, `div` would also swallow SSE/x87 FP divides
# (`divss`/`divsd`) — those are excluded on purpose, as is mul/imul.
_DIV_RE = re.compile(r"^(?:i?div[bwlq]?|[su]div|divu?w?|remu?w?)$")

# objdump function label, e.g. `0000000000000050 <PQCLEAN_..._poly_tomsg>:`
_FUNC_RE = re.compile(r"^[0-9a-fA-F]+ <(?P<name>.+)>:$")
# An instruction line, e.g. `  62:\tidivl  -0x8(%rbp)` (with --no-show-raw-insn
# the mnemonic is the first token after the address). Leading whitespace
# distinguishes it from the column-0 function label line above.
_INSN_RE = re.compile(r"^\s+[0-9a-fA-F]+:\s+(?P<rest>\S.*)$")


class AsmScanError(RuntimeError):
    pass


@dataclass(frozen=True)
class Occurrence:
    """One division-family instruction at a concrete (opt level, address)."""

    opt: str
    addr: str          # objdump hex, e.g. "222"
    mnemonic: str


@dataclass
class VarLatCandidate:
    """A (compiler, harness, source, function) that contains at least one
    division instruction in at least one scanned optimization level. The
    interesting case is when `ct_opt` is NOT among `opt_levels` — the division
    only appears once optimized, so the ct/Valgrind stage at `ct_opt` would have
    missed it *if* the ct build uses the same compiler (see `_note_for`)."""

    harness: str
    source_file: str          # as written in the yaml (for readability)
    function: str
    compiler: str = "gcc"     # the scan compiler (`--cc`) this candidate came from
    ct_opt: str = "-O0"       # the ct stage's effective opt level for this harness
    occurrences: List[Occurrence] = field(default_factory=list)

    @property
    def opt_levels(self) -> List[str]:
        return sorted({o.opt for o in self.occurrences})

    @property
    def mnemonics(self) -> List[str]:
        return sorted({o.mnemonic for o in self.occurrences})

    @property
    def count(self) -> int:
        return len(self.occurrences)

    @property
    def addresses_display(self) -> str:
        # one entry per unique (opt, addr), sorted, e.g. "-O2@0x47;-Os@0x222"
        uniq = sorted({(o.opt, o.addr) for o in self.occurrences})
        return ";".join(f"{opt}@0x{addr}" for opt, addr in uniq)

    @property
    def triage_hint(self) -> str:
        """Non-authoritative review hint for the candidate queue.

        This is deliberately weaker than `varlat_triage`: it is derived only
        from source/function names, not operand taint. It exists so the artifact
        carries the same provenance reviewers use by hand (e.g. KyberSlash
        poly helpers versus public Keccak rate arithmetic) without turning that
        heuristic into an automatic verdict.
        """
        return triage_hint_for(self.source_file, self.function)


def triage_hint_for(source_file: str, function: str) -> str:
    """Heuristic-only label for common variable-latency candidate families."""
    src = source_file.lower()
    fn = function.lower()
    if "kyberslash" in src and (
        fn.endswith("poly_compress") or fn.endswith("poly_tomsg")
    ):
        return "kyberslash-poly-review-secret-risk"
    if any(part in src for part in ("fips202", "keccak", "sp800-185")) or fn.startswith(
        ("shake", "sha3", "keccak")
    ):
        return "keccak-rate-review-likely-public"
    return "unclassified-review-required"


def extract_opt_level(cflags: List[str]) -> str:
    """The effective `-O` level of a cflags list (gcc honours the last one).
    Absent any `-O` flag, gcc defaults to `-O0`."""
    found = [f for f in cflags if re.fullmatch(r"-O\S*", f)]
    return found[-1] if found else "-O0"


def _strip_opt(cflags: List[str]) -> List[str]:
    """Drop any `-O*` token so we can substitute our own. Everything else
    (`-g`, `-fno-inline`, `-D…` defines, `-isystem …`) is preserved verbatim so
    the scanned object sees the same preprocessor/codegen state the real ct
    harness would — same rationale as coverage_check forwarding cflags (T17)."""
    return [f for f in cflags if not re.fullmatch(r"-O\S*", f)]


def parse_objdump(text: str) -> List[Tuple[str, str, str]]:
    """Pure text -> [(label, address, mnemonic)] for every division-family
    instruction in `objdump -d --no-show-raw-insn` output. `label` is whatever
    symbol objdump attributed the code to (often correct on ELF, a linker-temp
    on Mach-O — callers remap it via the symbol table). Split out from the
    subprocess wrapper so the mnemonic whitelist can be unit-tested against
    canned GNU/LLVM objdump text without a compiler in the loop."""
    hits: List[Tuple[str, str, str]] = []
    current = "?"
    for line in text.splitlines():
        fm = _FUNC_RE.match(line)
        if fm:
            current = fm.group("name")
            continue
        im = _INSN_RE.match(line)
        if not im:
            continue
        mnem = im.group("rest").split()[0]
        if _DIV_RE.match(mnem):
            addr = line.strip().split(":", 1)[0].strip()
            hits.append((current, addr, mnem))
    return hits


def _is_temp_symbol(name: str) -> bool:
    # Mach-O / linker temporary labels we never want to surface as a function.
    return name.startswith(("ltmp", "l_", "L"))


def parse_nm(text: str) -> List[Tuple[int, str]]:
    """Pure `nm -n` text -> sorted [(address, function_name)] for text/function
    symbols, preferring a global symbol (and a real name over a linker temp)
    when several share an address. A leading underscore (Mach-O convention) is
    stripped so names match the ELF spelling. Pure for unit-testing."""
    by_addr: Dict[int, Tuple[bool, str]] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue  # undefined symbols ("    U foo") have no address
        addr_s, typ, name = parts[0], parts[1], parts[2]
        if typ not in ("t", "T"):  # text/function symbols only
            continue
        try:
            addr = int(addr_s, 16)
        except ValueError:
            continue
        if name.startswith("_"):
            name = name[1:]
        is_global = typ == "T"
        cur = by_addr.get(addr)
        if cur is None:
            by_addr[addr] = (is_global, name)
        elif is_global and not cur[0]:
            by_addr[addr] = (is_global, name)
        elif is_global == cur[0] and _is_temp_symbol(cur[1]) and not _is_temp_symbol(name):
            by_addr[addr] = (is_global, name)
    return sorted((a, n) for a, (_g, n) in by_addr.items())


def _label_needs_resolution(label: str) -> bool:
    """objdump's own label is trustworthy on ELF (real function names) but a
    linker temp on Mach-O (`ltmp0`). Only remap the latter — that keeps ELF's
    correct names untouched, so a genuine ELF function literally named `_foo`
    is never rewritten by the (Mach-O-oriented) underscore-stripping in
    `parse_nm`."""
    return label == "?" or _is_temp_symbol(label)


def resolve_functions(
    hits: List[Tuple[str, str, str]],
    symbols: List[Tuple[int, str]],
) -> List[Tuple[str, str, str]]:
    """Remap a hit's function label to the enclosing symbol-table function
    (greatest symbol address <= instruction address) ONLY when objdump's label
    is unhelpful (a Mach-O linker temp or missing). ELF labels are kept as-is.
    Falls back to the original label when there is no symbol table."""
    if not symbols:
        return list(hits)
    addrs = [a for a, _ in symbols]
    out: List[Tuple[str, str, str]] = []
    for label, addr_hex, mnem in hits:
        if not _label_needs_resolution(label):
            out.append((label, addr_hex, mnem))
            continue
        try:
            a = int(addr_hex, 16)
        except ValueError:
            out.append((label, addr_hex, mnem))
            continue
        i = bisect.bisect_right(addrs, a) - 1
        out.append((symbols[i][1] if i >= 0 else label, addr_hex, mnem))
    return out


def _function_symbols(obj_path: Path, nm: str, *, timeout: float) -> List[Tuple[int, str]]:
    """Best-effort symbol table via `nm -n`. Returns [] (caller falls back to
    objdump labels) if nm is missing or fails — this is a warn-only probe."""
    try:
        proc = run_text([nm, "-n", str(obj_path)], timeout=timeout)
    except (_sp.TimeoutExpired, FileNotFoundError):
        return []
    if proc.returncode != 0:
        return []
    return parse_nm(proc.stdout)


def _disasm_divisions(
    obj_path: Path, objdump: str, nm: str, *, timeout: float
) -> List[Tuple[str, str, str]]:
    """objdump the object, find division-family instructions, and resolve their
    function names via the symbol table. Raises AsmScanError if objdump fails."""
    cmd = [objdump, "-d", "--no-show-raw-insn", str(obj_path)]
    try:
        proc = run_text(cmd, timeout=timeout)
    except _sp.TimeoutExpired as e:
        raise AsmScanError(f"objdump exceeded timeout={timeout}s ({' '.join(cmd)})") from e
    except (FileNotFoundError, PermissionError) as e:
        # Bundle Q (FN-1): the CLI shutil.which()-preflights objdump, but which()
        # is a PATH lookup, not an exec test — a TOCTOU removal or a non-exec
        # file on PATH still reaches here. Raise AsmScanError (the cli records
        # it as a per-compiler skip) instead of a raw traceback. Matches the
        # `nm` site's existing FileNotFoundError tolerance.
        raise AsmScanError(f"objdump could not run ({' '.join(cmd)}): {e}") from e
    if proc.returncode != 0:
        raise AsmScanError(
            f"objdump failed ({' '.join(cmd)}):\n{proc.stderr or proc.stdout}"
        )
    hits = parse_objdump(proc.stdout)
    if not hits:
        return []
    # Only pay for the `nm` call when objdump gave us an unhelpful label
    # (Mach-O linker temps); on ELF the disassembly labels are already correct.
    if not any(_label_needs_resolution(label) for label, _a, _m in hits):
        return hits
    return resolve_functions(hits, _function_symbols(obj_path, nm, timeout=timeout))


def scan_harness(
    harness: str,
    sources: List[Path],
    source_display: List[str],
    include_dirs: List[Path],
    base_cflags: List[str],
    workdir: Path,
    *,
    opt_levels: Tuple[str, ...] = DEFAULT_OPT_LEVELS,
    timeout: float,
    cc: str = "gcc",
    objdump: str = "objdump",
    nm: str = "nm",
    on_warn=None,
) -> List[VarLatCandidate]:
    """Compile each source at each opt level (`-c`, no link) and aggregate the
    division-family instructions found, keyed by (source, function).

    `source_display[i]` is the yaml-relative string used purely for display;
    `sources[i]` is the resolved path actually compiled. `base_cflags` is the
    harness's effective cflags — its own `-O` is stripped for scanning but read
    back via `extract_opt_level` to label each candidate's `ct_opt`. A compile
    that fails for one (source, opt) is reported via `on_warn` and skipped
    rather than aborting — this is a best-effort warn-only probe."""
    if len(sources) != len(source_display):
        raise AsmScanError("sources / source_display length mismatch")
    ct_opt = extract_opt_level(base_cflags)
    base = _strip_opt(base_cflags)
    inc_flags = [f"-I{d}" for d in include_dirs]
    # key: (source_display, function) -> list[Occurrence]
    agg: Dict[Tuple[str, str], List[Occurrence]] = {}
    attempted = 0   # (source, opt) compile attempts
    compiled = 0    # ...that produced an object we could disassemble
    scanned_sources: set = set()  # source displays that compiled at >=1 opt

    with tempfile.TemporaryDirectory(prefix="ctkat_asm_") as td:
        tmp = Path(td)
        for src, disp in zip(sources, source_display):
            for opt in opt_levels:
                obj = tmp / f"{src.stem}_{opt.lstrip('-')}.o"
                cmd = [cc, opt, *base, *inc_flags, "-c", str(src), "-o", str(obj)]
                attempted += 1
                try:
                    proc = run_text(cmd, cwd=workdir, timeout=timeout)
                except _sp.TimeoutExpired:
                    if on_warn:
                        on_warn(f"compile timeout: {disp} {opt}")
                    continue
                except (FileNotFoundError, PermissionError) as e:
                    # Bundle Q (FN-1): the compiler vanished between which()
                    # preflight and use, or is a non-exec stub. Warn-and-skip
                    # this (source, opt) like a failed compile rather than
                    # crashing the whole warn-only scan with a raw traceback.
                    if on_warn:
                        on_warn(f"compiler could not run: {disp} {opt} — {e}")
                    continue
                if proc.returncode != 0:
                    if on_warn:
                        tail = (proc.stderr or "").strip().splitlines()[-2:]
                        on_warn(f"compile failed: {disp} {opt} — {tail or '(no stderr)'}")
                    continue
                compiled += 1
                scanned_sources.add(disp)
                for func, addr, mnem in _disasm_divisions(obj, objdump, nm, timeout=timeout):
                    agg.setdefault((disp, func), []).append(Occurrence(opt, addr, mnem))

    # Q(N2): a source we were told to scan that compiled at ZERO opt levels is a
    # BLIND SPOT — we never disassembled it, so we cannot honestly claim it is
    # division-free. The dangerous case (the neighbor's finding): a leaky source
    # fails to compile while an unrelated helper compiles → returning [] reads as
    # a clean "no divisions found" scan (false-clean). Fail closed: name the
    # unscanned source(s) so the caller records THIS compiler as ERROR / PARTIAL
    # rather than green. (A source that compiled at *some* opt levels is fine —
    # we have visibility there, and the per-(source,opt) warn covers the gaps.)
    # This subsumes the old "every compile failed" guard: if all sources failed,
    # all of them are unscanned.
    unscanned = [d for d in source_display if d not in scanned_sources]
    if attempted and unscanned:
        raise AsmScanError(
            f"source(s) never compiled under cc={cc!r} on harness {harness!r}: "
            f"{', '.join(unscanned)} — cannot claim division-free for them "
            f"(toolchain/header/-D/-isystem mismatch?). See warnings; this "
            f"compiler is recorded as a PARTIAL/ERROR scan, not clean."
        )

    out = [
        VarLatCandidate(
            harness=harness,
            source_file=disp,
            function=func,
            compiler=cc,
            ct_opt=ct_opt,
            occurrences=occ,
        )
        for (disp, func), occ in agg.items()
    ]
    out.sort(key=lambda c: (c.source_file, c.function))
    return out


# --- artifact writers (separate file from the verdict CSV on purpose) -------

VARLAT_CSV_FIELDS = [
    "compiler",
    "harness",
    "source_file",
    "function",
    "triage_hint",
    "mnemonics",
    "opt_levels",
    "count",
    "addresses",
    "note",
]


def _note_for(c: VarLatCandidate) -> str:
    """Human-facing one-liner keyed off the ct stage's own opt level AND the
    scan compiler. The "ct/Valgrind stage would miss this build" claim only
    holds when the ct build uses the *same* compiler we scanned with — asm-scan
    does not know the ct build's compiler (it runs `make`), so the claim is
    stated conditionally on `c.compiler` rather than asserted (compiler
    cross-layer contract — a clang-only `div` says nothing about a gcc ct
    stage)."""
    opts = c.opt_levels
    cc = c.compiler
    if c.ct_opt in opts and len(opts) == 1:
        return f"division present even at the ct stage's {c.ct_opt} under {cc} (variable divisor, or {cc} kept it)"
    if c.ct_opt not in opts:
        return (
            f"division survives only when optimized under {cc} ({';'.join(opts)}); "
            f"absent at the ct stage's {c.ct_opt} — if the ct build also uses {cc}, "
            f"the ct/Valgrind stage would miss this build"
        )
    return f"division present across {';'.join(opts)} under {cc} (incl. the ct stage's {c.ct_opt})"


def candidate_to_row(c: VarLatCandidate) -> Dict[str, str]:
    return {
        "compiler": c.compiler,
        "harness": c.harness,
        "source_file": c.source_file,
        "function": c.function,
        "triage_hint": c.triage_hint,
        "mnemonics": ";".join(c.mnemonics),
        "opt_levels": ";".join(c.opt_levels),
        "count": str(c.count),
        "addresses": c.addresses_display,
        "note": _note_for(c),
    }


def write_varlat_csv(candidates: List[VarLatCandidate], path: Path) -> None:
    import csv

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=VARLAT_CSV_FIELDS, lineterminator="\n")
        writer.writeheader()
        for c in candidates:
            writer.writerow(candidate_to_row(c))


def build_matrix(candidates: List[VarLatCandidate]) -> List[Dict[str, object]]:
    """Normalized one-row-per-(compiler, opt, source, function, mnemonic) view
    of the candidates, so a script can mechanically compare *which compiler ×
    opt level kept a division alive* without parsing the `;`-joined CSV columns.
    The human-readable cross-opt `note` lives only on the aggregated CSV rows /
    `candidates`; this matrix is the machine-diff surface."""
    agg: Dict[Tuple[str, str, str, str, str], int] = {}
    for c in candidates:
        for o in c.occurrences:
            key = (c.compiler, o.opt, c.source_file, c.function, o.mnemonic)
            agg[key] = agg.get(key, 0) + 1
    rows = [
        {
            "compiler": comp,
            "opt": opt,
            "source_file": sf,
            "function": fn,
            "triage_hint": triage_hint_for(sf, fn),
            "mnemonic": mn,
            "count": n,
        }
        for (comp, opt, sf, fn, mn), n in agg.items()
    ]
    rows.sort(key=lambda r: (r["compiler"], r["opt"], r["source_file"], r["function"], r["mnemonic"]))
    return rows


def write_varlat_json(
    project: str,
    candidates: List[VarLatCandidate],
    path: Path,
    *,
    opt_levels: Tuple[str, ...],
    compilers: Tuple[str, ...] = ("gcc",),
    errors: Optional[List[Dict[str, str]]] = None,
) -> None:
    import json

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "project": project,
        "kind": "varlat_candidates",
        "warn_only": True,
        "scanned_opt_levels": list(opt_levels),
        "scanned_compilers": list(compilers),
        # per-compiler problems (missing compiler skipped, or a disasm failure)
        # recorded explicitly so a green CSV is never mistaken for "complete".
        "errors": list(errors or []),
        "candidates": [candidate_to_row(c) for c in candidates],
        "matrix": build_matrix(candidates),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
