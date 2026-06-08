"""verdict_class taxonomy — the single source of truth shared by the `ctkat
screen` command and the post-hoc corpus builder (`scripts/build_corpus_table.py`).

Phase 1 (Bundle R): this logic used to live ONLY inside build_corpus_table.py, so
the headline artifact (`verdict_class`) was "an experiment post-processing script"
rather than something the tool emits. Extracting it here lets `ctkat screen`
compute the SAME classification in-process — the script and the command can no
longer drift (CLAUDE.md §3/§5).

Everything here is PURE (no file/console I/O) except `load_registry`, which reads
the accepted-variable-time markdown table. The classification is a faithful port
of build_corpus_table.build()'s per-harness loop; the decision ORDER and the exact
note phrasings are load-bearing (tests assert on them) and must be preserved.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# The full taxonomy. Exposed so tests/docs/CLI can assert against it and so the
# screen command can derive its default-deny gating set.
VERDICT_CLASSES: Tuple[str, ...] = (
    "robust",
    "ct-clean-untriaged",
    "ct-clean-asm-incomplete",
    "varlat-secret-risk",
    "build-sensitive-ct",
    "accepted-variable-time",
    "needs-analysis",
    "ct-leak",
    "tool-problem",
)

# Default-deny gate: only these read as "cleared". Everything else (incl. the
# not-yet-triaged / incomplete-scan classes) is a gating result.
CLEAN_CLASSES: Tuple[str, ...] = ("robust", "accepted-variable-time")


def opt_of(cflags: str) -> str:
    """The effective -O level of a cflags string (gcc honours the last)."""
    found = [t for t in cflags.split() if re.fullmatch(r"-O\S*", t)]
    return found[-1] if found else "-O0"


def load_registry(path: Optional[Path] = None) -> Dict[str, Set[str]]:
    """Parse docs/accepted_variable_time.md -> {family: set(function suffixes)}.

    Reads the markdown table rows `| family | function | ... |`. The default-deny
    classifier consults this: a ct-FAIL harness is `accepted-variable-time` only
    if EVERY leak-site function suffix-matches a registered one for its family.
    """
    if path is None:
        path = Path(__file__).resolve().parent.parent / "docs" / "accepted_variable_time.md"
    reg: Dict[str, Set[str]] = {}
    p = Path(path)
    if not p.exists():
        return reg
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.lstrip().startswith("|"):
            continue
        cols = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cols) < 2:
            continue
        fam, fn = cols[0], cols[1]
        if fam in ("family", "") or set(fn) <= set("-: "):  # skip header/separator
            continue
        reg.setdefault(fam, set()).add(fn)
    return reg


@dataclass
class _Agg:
    """Per-harness aggregate over its build cells — computed ONCE and shared by
    the classifier and the summary builder so they can't disagree."""
    statuses: Set[str]
    ct_flips: str            # "yes" | "no"
    only: Set[str]           # statuses minus ERROR
    vcells: List[str]        # ["gcc:-Os", ...] where asm_div_count > 0
    asm_err_ccs: List[str]   # compilers whose asm-scan ERRORED for this harness
    asm_errors: List[str]    # distinct asm error strings (for the note)
    ct_funcs: List[str]      # union of ct leak-site functions (sorted)


def _aggregate(harness_cells: List[dict]) -> _Agg:
    hc = harness_cells
    statuses = {c.get("ct_status", "") for c in hc}
    verdicts = {s for s in statuses if s in ("PASS", "FAIL")}
    return _Agg(
        statuses=statuses,
        ct_flips="yes" if len(verdicts) > 1 else "no",
        only=statuses - {"ERROR"},
        vcells=sorted({f"{c['cc']}:{c['opt']}" for c in hc
                       if int(c.get("asm_div_count") or 0) > 0}),
        asm_err_ccs=sorted({c["cc"] for c in hc if c.get("asm_error")}),
        asm_errors=sorted({c["asm_error"] for c in hc if c.get("asm_error")}),
        ct_funcs=sorted({ff for c in hc
                         for ff in c.get("ct_finding_funcs", "").split(";") if ff}),
    )


def classify_harness(
    harness_cells: List[dict],
    *,
    family: str,
    triage: str = "untriaged",          # public | secret-risk | none | untriaged
    dudect_status: str = "",            # "" | PASS | WARNING | FAIL | ERROR
    registry: Optional[Dict[str, Set[str]]] = None,
    verdict_override: Optional[str] = None,
    note_override: Optional[str] = None,
) -> Tuple[str, str]:
    """Classify ONE harness from its build cells. Returns (verdict_class, notes).

    `harness_cells` is a list of per-build-cell dicts (the shape build() makes and
    `ctkat screen` mirrors), each with: ct_status, cc, opt, asm_div_count,
    asm_error, ct_finding_funcs. Pure — no I/O.

    Decision ORDER is load-bearing (verbatim from build_corpus_table.build):
    ct_flips -> only=={FAIL}+registry -> secret-risk -> PASS+asm_err ->
    PASS+(no vcells | public/none) -> PASS -> tool-problem, then override, then notes.
    """
    registry = registry or {}
    agg = _aggregate(harness_cells)
    accepted = registry.get(family, set())
    tri = triage

    if agg.ct_flips == "yes":
        vclass = "build-sensitive-ct"
    elif agg.only == {"FAIL"}:
        # default-deny: ANY unregistered function -> needs-analysis (never
        # auto-accepted). All registered (suffix-match) -> accepted-variable-time.
        if agg.ct_funcs and all(any(ff.endswith(rf) for rf in accepted) for ff in agg.ct_funcs):
            vclass = "accepted-variable-time"
        else:
            vclass = "needs-analysis"
    elif tri == "secret-risk":
        vclass = "varlat-secret-risk"
    elif agg.only == {"PASS"} and agg.asm_err_ccs:
        # N2: ct PASS but asm-scan ERRORED for some build(s) — blind spot, NOT robust.
        vclass = "ct-clean-asm-incomplete"
    elif agg.only == {"PASS"} and (not agg.vcells or tri in ("none", "public")):
        vclass = "robust"
    elif agg.only == {"PASS"}:
        vclass = "ct-clean-untriaged"
    else:
        vclass = "tool-problem"
    # Domain triage can't be auto-derived (e.g. a ct FAIL that is a scheme's
    # analyzed-safe rejection sampling) — allow a manual override. An empty/None
    # override is ignored (keeps the computed class); the original build_corpus_table
    # only applied the override when the harness key was present, so a blank value
    # never meant "blank the verdict" — this preserves that intent.
    if verdict_override:
        vclass = verdict_override

    notes: List[str] = []
    if vclass == "accepted-variable-time":
        notes.append("ct FAIL functions all in accepted-variable-time registry "
                     "(see docs/accepted_variable_time.md)")
    elif vclass == "needs-analysis":
        unreg = [ff for ff in agg.ct_funcs if not any(ff.endswith(rf) for rf in accepted)]
        notes.append("ct FAIL with unregistered leak-site function(s) — triage required: "
                     + ";".join(unreg))
    if dudect_status == "WARNING":
        notes.append("dudect WARNING — likely QEMU env-noise; confirm natively")
    if agg.asm_err_ccs:
        notes.append(
            "asm-scan incomplete/errored for " + ",".join(agg.asm_err_ccs)
            + " — division-free claim does NOT cover those build(s): "
            + "; ".join(agg.asm_errors)
        )
    if not agg.vcells:
        pass
    elif tri == "untriaged":
        notes.append("asm-scan candidates present but not yet triaged (public vs secret-derived)")
    if note_override:
        notes.append(note_override)

    return vclass, "; ".join(notes)


def summarize(
    cells: List[dict],
    *,
    family: str,
    triage: Dict[str, str],
    dud_by: Dict[str, dict],
    dcfg: Dict[str, dict],
    registry: Optional[Dict[str, Set[str]]] = None,
    verdict_override: Optional[Dict[str, str]] = None,
    note_override: Optional[Dict[str, str]] = None,
) -> List[dict]:
    """Per-harness summary rows (SUMMARY_FIELDS shape) from the per-cell `cells`.

    Faithful port of build_corpus_table.build()'s harness loop (minus the cell
    construction and CSV writing). `dud_by` maps harness -> dudect summary row
    dict (n0/n1/status/abs_t_score); `dcfg` maps harness -> dudect config dict
    (leak_target/seed/threshold/measurements). Both consumers build these.
    """
    registry = registry or {}
    verdict_override = verdict_override or {}
    note_override = note_override or {}

    harnesses: List[str] = []
    for c in cells:
        if c["harness"] not in harnesses:
            harnesses.append(c["harness"])

    summary: List[dict] = []
    for h in harnesses:
        hc = [c for c in cells if c["harness"] == h]
        agg = _aggregate(hc)
        d = dud_by.get(h, {})
        cf = dcfg.get(h, {})
        tri = triage.get(h, "untriaged")

        vclass, notes = classify_harness(
            hc, family=family, triage=tri, dudect_status=d.get("status", ""),
            registry=registry, verdict_override=verdict_override.get(h),
            note_override=note_override.get(h),
        )

        meas = cf.get("measurements", "")
        if not meas and d:
            try:
                meas = str(int(d.get("n0", 0)) + int(d.get("n1", 0)))
            except (ValueError, TypeError):
                meas = ""

        summary.append({
            "family": family,
            "target": hc[0].get("target", "") if hc else "",
            "harness": h,
            "ct_flips": agg.ct_flips,
            "ct_status_set": "{" + ",".join(sorted(agg.statuses)) + "}",
            "ct_finding_funcs": ";".join(agg.ct_funcs),
            "varlat_candidates": ";".join(agg.vcells) or "none",
            "varlat_triage": tri,
            "dudect_status": d.get("status", ""),
            "dudect_abs_t": d.get("abs_t_score", ""),
            "dudect_measurements": meas,
            "dudect_leak_target": cf.get("leak_target", ""),
            "dudect_seed": cf.get("seed", ""),
            "dudect_threshold": cf.get("threshold", ""),
            "verdict_class": vclass,
            "notes": notes,
        })
    return summary
