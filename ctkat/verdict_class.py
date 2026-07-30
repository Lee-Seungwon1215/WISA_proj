"""Legacy verdict-class adapter shared by screen and the corpus migration.

Evidence schema v2 no longer exposes this nine-class taxonomy as the headline
result.  It is retained as ``legacy_verdict_class`` so old artifacts can be
migrated reproducibly and reviewed acceptance rules keep working while the
individual evidence layers feed :mod:`ctkat.evidence`.

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

from .evidence import LEGACY_TIMING_BACKEND, build_evidence
from .official_dudect import (
    OFFICIAL_DUDECT_BACKEND,
    OFFICIAL_DUDECT_THRESHOLD_LABEL,
)

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

STOP_CLASSES: Tuple[str, ...] = (
    "ct-clean-untriaged",
    "ct-clean-asm-incomplete",
    "needs-analysis",
    "tool-problem",
)


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
    ct_flips: str  # "yes" | "no"
    only: Set[str]  # statuses minus ERROR
    vcells: List[str]  # ["gcc:-Os", ...] where asm_div_count > 0
    asm_err_ccs: List[str]  # compilers whose asm-scan ERRORED for this harness
    asm_errors: List[str]  # distinct asm error strings (for the note)
    asm_not_run_cells: List[str]  # build cells outside the recorded asm coverage
    ct_funcs: List[str]  # union of ct leak-site functions (sorted)


def _asm_cell_status(cell: dict) -> str:
    """Read v2 coverage, with a narrow adapter for pre-v2 in-memory fixtures."""
    status = cell.get("asm_status", "")
    if status:
        return status.upper()
    return "ERROR" if cell.get("asm_error") else "PASS"


def _aggregate(harness_cells: List[dict]) -> _Agg:
    hc = harness_cells
    statuses = {c.get("ct_status", "") for c in hc}
    verdicts = {s for s in statuses if s in ("PASS", "FAIL")}
    return _Agg(
        statuses=statuses,
        ct_flips="yes" if len(verdicts) > 1 else "no",
        only=statuses - {"ERROR", "NA", "NONE", ""},
        vcells=sorted(
            {f"{c['cc']}:{c['opt']}" for c in hc if int(c.get("asm_div_count") or 0) > 0}
        ),
        asm_err_ccs=sorted({c["cc"] for c in hc if c.get("asm_error")}),
        asm_errors=sorted({c["asm_error"] for c in hc if c.get("asm_error")}),
        asm_not_run_cells=sorted(
            {f"{c['cc']}:{c['opt']}" for c in hc if _asm_cell_status(c) == "NOT_RUN"}
        ),
        ct_funcs=sorted({ff for c in hc for ff in c.get("ct_finding_funcs", "").split(";") if ff}),
    )


def classify_harness(
    harness_cells: List[dict],
    *,
    family: str,
    triage: str = "untriaged",  # public | secret-risk | mixed | none | untriaged
    dudect_status: str = "",  # "" | PASS | WARNING | FAIL | ERROR
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
    elif agg.only == {"PASS"} and "ERROR" in agg.statuses:
        # A matrix ERROR means at least one build cell was not analyzed. The
        # old `only = statuses - {"ERROR"}` rule made PASS+ERROR look robust;
        # that is a false-green because the clean claim does not cover every
        # configured build.
        vclass = "tool-problem"
    elif agg.only == {"PASS"} and (agg.asm_err_ccs or agg.asm_not_run_cells):
        # ct PASS but asm coverage is missing/errored for some build(s) — blind
        # spot, NOT robust.
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
    auto_vclass = vclass
    if verdict_override:
        vclass = verdict_override

    notes: List[str] = []
    unreg = [ff for ff in agg.ct_funcs if not any(ff.endswith(rf) for rf in accepted)]
    if auto_vclass == "accepted-variable-time":
        notes.append(
            "ct FAIL functions all in accepted-variable-time registry "
            "(see docs/accepted_variable_time.md)"
        )
    elif auto_vclass == "needs-analysis" and verdict_override and verdict_override != auto_vclass:
        msg = f"manual verdict override: {auto_vclass} -> {vclass}"
        if unreg:
            msg += "; reviewed unregistered leak-site function(s): " + ";".join(unreg)
        notes.append(msg)
    elif auto_vclass == "needs-analysis":
        notes.append(
            "ct FAIL with unregistered leak-site function(s) — triage required: " + ";".join(unreg)
        )
    elif verdict_override and verdict_override != auto_vclass:
        notes.append(f"manual verdict override: {auto_vclass} -> {vclass}")
    if dudect_status == "WARNING":
        notes.append("dudect WARNING — likely QEMU env-noise; confirm natively")
    if agg.asm_err_ccs:
        notes.append(
            "asm-scan incomplete/errored for "
            + ",".join(agg.asm_err_ccs)
            + " — division-free claim does NOT cover those build(s): "
            + "; ".join(agg.asm_errors)
        )
    if agg.asm_not_run_cells:
        notes.append(
            "asm-scan not run for build cell(s): "
            + ",".join(agg.asm_not_run_cells)
            + " — no-candidate claim does NOT cover those build(s)"
        )
    if "ERROR" in agg.statuses and agg.only == {"PASS"}:
        notes.append("ct-matrix ERROR cell(s) present — clean claim does NOT cover every build")
    if not agg.vcells:
        pass
    elif tri == "untriaged":
        notes.append("asm-scan candidates present but not yet triaged (public vs secret-derived)")
    if note_override:
        notes.append(note_override)

    return vclass, "; ".join(notes)


def verdict_basis(
    vclass: str,
    *,
    varlat_candidates: bool,
    triage: str = "untriaged",
    verdict_override: Optional[str] = None,
    note_override: Optional[str] = None,
) -> str:
    """Compact provenance for a final verdict row.

    `auto` means the shared classifier reached the final row without a manual
    attribution. `review` means a reviewer supplied either a verdict/note
    override or a public/secret varlat attribution for emitted candidates.
    `stop` means the row is deliberately unresolved/incomplete and remains at a
    default-deny stopping class.
    """
    if vclass in STOP_CLASSES:
        return "stop"
    if verdict_override or note_override:
        return "review"
    if varlat_candidates and triage in ("public", "secret-risk"):
        return "review"
    return "auto"


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
    correctness: str = "not-run",
    timing_validity: Optional[Dict[str, str]] = None,
    review_status: Optional[Dict[str, str]] = None,
    review_id: Optional[Dict[str, str]] = None,
    target: str = "",
) -> List[dict]:
    """Per-harness evidence-v2 rows from per-build cells.

    ``dud_by`` and ``dcfg`` retain their historical names because they read
    legacy artifacts. Their values are emitted under neutral ``timing_*`` raw
    provenance columns. Completed legacy timing defaults to
    ``insufficient-power`` unless a validity map explicitly says otherwise.
    """
    registry = registry or {}
    verdict_override = verdict_override or {}
    note_override = note_override or {}
    timing_validity = timing_validity or {}
    review_status = review_status or {}
    review_id = review_id or {}

    harnesses: List[str] = []
    for c in cells:
        if c["harness"] not in harnesses:
            harnesses.append(c["harness"])
    for h in [*dud_by, *dcfg]:
        if h not in harnesses:
            harnesses.append(h)

    summary: List[dict] = []
    for h in harnesses:
        hc = [c for c in cells if c["harness"] == h]
        agg = _aggregate(hc)
        d = dud_by.get(h, {})
        cf = dcfg.get(h, {})
        tri = triage.get(h, "untriaged")

        vclass, notes = classify_harness(
            hc,
            family=family,
            triage=tri,
            dudect_status=d.get("status", ""),
            registry=registry,
            verdict_override=verdict_override.get(h),
            note_override=note_override.get(h),
        )
        basis = verdict_basis(
            vclass,
            varlat_candidates=bool(agg.vcells),
            triage=tri,
            verdict_override=verdict_override.get(h),
            note_override=note_override.get(h),
        )
        evidence = build_evidence(
            correctness=correctness,
            ct_statuses=agg.statuses,
            asm_candidate_count=sum(int(c.get("asm_div_count") or 0) for c in hc),
            asm_error_count=sum(_asm_cell_status(c) == "ERROR" for c in hc),
            asm_cell_count=len(hc),
            asm_not_run_count=sum(_asm_cell_status(c) == "NOT_RUN" for c in hc),
            triage=tri,
            raw_timing_status=d.get("status", ""),
            timing_validity=timing_validity.get(
                h, d.get("timing_validity", cf.get("timing_validity", ""))
            ),
            legacy_verdict_class=vclass,
            legacy_basis=basis,
            review_status=review_status.get(h, ""),
            review_id=review_id.get(h, ""),
        )

        # The runtime report wins over the YAML. Campaigns deliberately apply
        # measurement/seed overrides without editing the modest example
        # defaults; reading config first would publish the wrong sample count
        # and base seed after a native refresh.
        meas = ""
        if d:
            raw_total = d.get("raw_n_total", "")
            try:
                if int(raw_total) > 0:
                    meas = str(int(raw_total))
            except (ValueError, TypeError):
                pass
        if not meas and d:
            try:
                meas = str(int(d.get("n0", 0)) + int(d.get("n1", 0)))
            except (ValueError, TypeError):
                meas = ""
        if not meas:
            meas = cf.get("measurements", "")

        if d.get("status") and evidence.timing_validity.value != "valid":
            timing_note = (
                f"timing validity={evidence.timing_validity.value}; raw "
                f"{d.get('status')} is non-decisional"
            )
            notes = f"{notes}; {timing_note}" if notes else timing_note
        if evidence.review.value == "pending" and basis in {"review", "stop"}:
            review_note = "review artifact pending; note text alone cannot clear evidence v2"
            notes = f"{notes}; {review_note}" if notes else review_note

        timing_backend = d.get("backend") or cf.get("backend", LEGACY_TIMING_BACKEND if d else "")
        timing_threshold = (
            OFFICIAL_DUDECT_THRESHOLD_LABEL
            if timing_backend == OFFICIAL_DUDECT_BACKEND
            else cf.get("threshold", "")
        )

        summary.append(
            {
                **evidence.as_dict(),
                "family": family,
                "target": hc[0].get("target", target) if hc else target,
                "harness": h,
                "ct_flips": agg.ct_flips,
                "ct_status_set": "{" + ",".join(sorted(agg.statuses)) + "}",
                "ct_finding_funcs": ";".join(agg.ct_funcs),
                "varlat_candidates": ";".join(agg.vcells) or "none",
                "varlat_triage": tri,
                "timing_backend": timing_backend,
                "timing_raw_status": d.get("status", ""),
                "timing_abs_t": d.get("abs_t_score", ""),
                "timing_measurements": meas,
                "timing_leak_target": cf.get("leak_target", ""),
                "timing_seed": d.get("analysis_seed") or cf.get("seed", ""),
                "timing_threshold": timing_threshold,
                "legacy_basis": basis,
                "notes": notes,
            }
        )
    return summary
