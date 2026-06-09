#!/usr/bin/env python3
"""Phase 2: render the paper's data tables + macros from the corpus CSVs, so the
camera-ready numbers are single-sourced (no more hand-copying) and a drift test
(tests/test_paper_corpus_sync.py) can enforce paper == corpus.

DETERMINISTIC, pure stdlib + csv — no valgrind/Docker. Reads the committed
docs/corpus/*.csv (Stage-B output) and emits, into a fenced generated region:

  paper/generated/tab_corpus.tex    - verdict-class corpus rows
  paper/generated/tab_dudect.tex    - dudect appendix rows
  paper/generated/tab_ablation.tex  - supporting ablation/miss evidence rows
  paper/generated/tab_mldsa.tex     - ML-DSA per-build triage evidence
  paper/generated/corpus_macros.tex - \\newcommand for every duplicated/derived
                                       number used in main.tex + 04_results.tex

It NEVER writes docs/corpus/*.csv (Stage-B owns those) and NEVER regenerates
dudect_appendix.csv (a frozen non-reproducible Docker snapshot — it only READS it).

The transform + rounding helpers are module-level so the sync test imports them —
the generator and the test share one definition of every transform (CLAUDE.md §3/§5).
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "docs" / "corpus"
GENERATED = ROOT / "paper" / "generated"

# Reuse the package taxonomy rather than hardcoding the class list.
sys.path.insert(0, str(ROOT))
from ctkat.verdict_class import VERDICT_CLASSES, load_registry  # noqa: E402


# --- shared transforms (imported by the sync test) --------------------------

def target_display(target: str) -> str:
    """Paper shortens corpus targets by dropping the pqclean_ prefix."""
    return target[len("pqclean_"):] if target.startswith("pqclean_") else target


def varlat_cell(row: dict) -> str:
    """Table varlat column. 'none' iff the harness has NO asm-scan candidates
    (varlat_candidates column), else its triage label. Keying off candidate
    PRESENCE (not triage=='untriaged') avoids mislabeling a future
    candidates-present-but-untriaged row as 'none'."""
    if row.get("varlat_candidates", "none") in ("", "none"):
        return "none"
    return row["varlat_triage"]


def ct_display(ct_status_set: str) -> str:
    """'{PASS}'->PASS, '{FAIL}'->FAIL, '{FAIL,PASS}'->FAIL/PASS."""
    inner = ct_status_set.strip().lstrip("{").rstrip("}")
    parts = [p.strip() for p in inner.split(",") if p.strip()]
    return "/".join(parts)


def round_mean(x: float) -> str:
    """Cycle means: 1 decimal place."""
    return f"{round(float(x), 1):.1f}"


def round_t(x: float) -> str:
    """Welch |t|: 1 dp when >=10, else 2 dp. Reproduces the paper's per-magnitude
    rounding exactly (181.498->181.5, 1.646->1.65, 5.470->5.47)."""
    v = abs(float(x))
    return f"{round(v, 1):.1f}" if v >= 10 else f"{round(v, 2):.2f}"


def round_pct(x: float) -> str:
    return f"{round(float(x), 1):.1f}"


def latex_tt(s: str) -> str:
    r"""Wrap in \texttt{} with underscores escaped (\_)."""
    return r"\texttt{" + s.replace("_", r"\_") + "}"


def join_tt(items: list[str]) -> str:
    return "; ".join(latex_tt(i) for i in items)


def thousands(n: int) -> str:
    """LaTeX thousands separator: 13250 -> 13{,}250 (math-mode safe)."""
    return f"{int(n):,}".replace(",", "{,}")


# --- readers ----------------------------------------------------------------

def _read(name: str) -> list[dict]:
    with open(CORPUS / name, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def load_corpus():
    summary = _read("corpus_summary.csv")
    cells = _read("corpus_cells.csv")
    appendix = {r["harness"]: r for r in _read("dudect_appendix.csv")}
    return summary, cells, appendix


# --- derived values (also used by the test) ---------------------------------

def cardinality(summary: list[dict]) -> dict:
    return {
        "rows": len(summary),
        "families": len(sorted({r["family"] for r in summary})),
        "verdict_classes": len(sorted({r["verdict_class"] for r in summary})),
    }


def max_build_cells(cells: list[dict]) -> int:
    from collections import Counter
    c = Counter((r["target"], r["harness"]) for r in cells)
    return max(c.values()) if c else 0


def drop_rates(appendix: dict) -> dict:
    """Per-class zero-cycle drop %: the load-bearing two-denominator formula.
    class-k denominator = kept n_k + dropped_zero_k (NOT raw_n_total/2)."""
    leaky = appendix["leaky"]
    n0, n1 = int(leaky["n0"]), int(leaky["n1"])
    d0, d1 = int(leaky["dropped_zero_n0"]), int(leaky["dropped_zero_n1"])
    raw = int(leaky["raw_n_total"])
    return {
        "total": (d0 + d1) / raw * 100.0,
        "class0": d0 / (n0 + d0) * 100.0,
        "class1": d1 / (n1 + d1) * 100.0,
    }


def mlkem_dudect_t(summary: list[dict]) -> str:
    for r in summary:
        if r["target"] == "pqclean_mlkem768" and r["dudect_abs_t"]:
            return round_t(r["dudect_abs_t"])
    return ""


# --- renderers --------------------------------------------------------------

def render_tab_corpus(summary: list[dict]) -> str:
    lines = []
    for r in summary:
        lines.append(
            f"{r['family']} & {latex_tt(target_display(r['target']))} & "
            f"{latex_tt(r['harness'])} & {ct_display(r['ct_status_set'])} & "
            f"{varlat_cell(r)} & {latex_tt(r['verdict_class'])}\\tabularnewline"
        )
    return "\n".join(lines) + "\n\\bottomrule\n"


def render_tab_dudect(appendix: dict) -> str:
    lines = []
    for h in ("leaky", "safe"):
        r = appendix[h]
        lines.append(
            f"{latex_tt(r['project'])} & {latex_tt(h)} & {int(r['n0'])} & "
            f"{int(r['n1'])} & {round_mean(r['mean0'])} & {round_mean(r['mean1'])} & "
            f"{round_t(r['abs_t_score'])} & {r['status']}\\tabularnewline"
        )
    return "\n".join(lines) + "\n\\bottomrule\n"


def render_tab_ablation(summary: list[dict], appendix: dict) -> str:
    """A compact "what breaks if a layer is removed" table.

    The row choices are intentional and mirror Table 1's single-coverage logic,
    but the concrete target/verdict strings are checked against the committed
    corpus so the paper cannot cite a stale or missing example.
    """
    by_key = {(r["target"], r["harness"]): r for r in summary}

    def require(target: str, harness: str, verdict: str) -> dict:
        row = by_key[(target, harness)]
        if row["verdict_class"] != verdict:
            raise SystemExit(
                f"ablation row {target}/{harness} expected {verdict}, "
                f"got {row['verdict_class']}"
            )
        return row

    require("toy_lookup", "leaky", "ct-leak")
    require("pqclean_mlkem768_kyberslash", "kem_dec", "varlat-secret-risk")
    require("ct_matrix_flip", "leaky", "build-sensitive-ct")
    require("pqclean_mldsa65", "sign", "needs-analysis")
    if appendix["leaky"]["status"] != "FAIL":
        raise SystemExit("ablation row toy_dudect/leaky expected dudect FAIL")

    rows = [
        ("Valgrind taint", "secret-indexed memory leak",
         f"{latex_tt('toy_lookup/leaky')} ({latex_tt('ct-leak')})"),
        ("asm-scan", "KyberSlash secret-derived division",
         f"{latex_tt('mlkem768_kyberslash/kem_dec')} ({latex_tt('varlat-secret-risk')})"),
        ("ct-matrix", "build-dependent verdict flip",
         f"{latex_tt('ct_matrix_flip/leaky')} ({latex_tt('build-sensitive-ct')})"),
        ("dudect", "black-box timing leak",
         f"{latex_tt('toy_dudect/leaky')} (FAIL $|t|={round_t(appendix['leaky']['abs_t_score'])}$)"),
        ("default-deny", "ML-DSA over-claim",
         f"{latex_tt('mldsa65/sign')} ({latex_tt('needs-analysis')})"),
    ]
    return "\n".join(
        f"{latex_tt(layer)} & {miss} & {evidence}\\tabularnewline"
        for layer, miss, evidence in rows
    ) + "\n\\bottomrule\n"


def render_tab_mldsa(cells: list[dict]) -> str:
    mldsa = [
        r for r in cells
        if r["target"] == "pqclean_mldsa65" and r["harness"] == "sign"
    ]
    if not mldsa:
        raise SystemExit("no ML-DSA sign cells found")
    reg = load_registry().get("ML-DSA", set())

    def short_funcs(rows: list[dict]) -> list[str]:
        funcs = {
            f.split("_CLEAN_")[-1]
            for r in rows
            for f in r["ct_finding_funcs"].split(";")
            if f
        }
        return sorted(funcs)

    debug = [r for r in mldsa if r["opt"] == "-O0"]
    opt = [r for r in mldsa if r["opt"] != "-O0"]
    debug_funcs = short_funcs(debug)
    opt_funcs = short_funcs(opt)
    unregistered = [
        f for f in opt_funcs
        if not any(f.endswith(rf) for rf in reg)
    ]
    if len(debug_funcs) != 3 or len(unregistered) != 2:
        raise SystemExit(
            f"unexpected ML-DSA split debug={debug_funcs}, unregistered={unregistered}"
        )

    rows = [
        (r"\texttt{-O0 -fno-inline}", join_tt(debug_funcs),
         "registered rejection-sampling behavior"),
        (r"\texttt{-O2/-Os}", "adds " + join_tt(unregistered),
         r"held at \texttt{needs-analysis}"),
    ]
    return "\n".join(
        f"{builds} & {funcs} & {meaning}\\tabularnewline"
        for builds, funcs, meaning in rows
    ) + "\n\\bottomrule\n"


def render_macros(summary, cells, appendix) -> str:
    card = cardinality(summary)
    dr = drop_rates(appendix)
    leaky, safe = appendix["leaky"], appendix["safe"]
    defs = [
        (r"\corpusRows", str(card["rows"])),
        (r"\corpusFamilies", str(card["families"])),
        (r"\corpusVerdictClasses", str(card["verdict_classes"])),
        (r"\maxBuildCells", str(max_build_cells(cells))),
        (r"\dudectLeakyNzero", thousands(leaky["n0"])),
        (r"\dudectLeakyNone", thousands(leaky["n1"])),
        (r"\dudectLeakyMeanZero", round_mean(leaky["mean0"])),
        (r"\dudectLeakyMeanOne", round_mean(leaky["mean1"])),
        (r"\dudectLeakyT", round_t(leaky["abs_t_score"])),
        # integer-truncated leaky |t| for the "so large (|t|=181)" caveat prose,
        # single-sourced so it can't drift from \dudectLeakyT.
        (r"\dudectLeakyTrunc", str(int(abs(float(leaky["abs_t_score"]))))),
        (r"\dudectSafeT", round_t(safe["abs_t_score"])),
        (r"\dropTotalPct", round_pct(dr["total"])),
        (r"\dropClassZeroPct", round_pct(dr["class0"])),
        (r"\dropClassOnePct", round_pct(dr["class1"])),
        (r"\mlkemDudectT", mlkem_dudect_t(summary)),
    ]
    head = ("% AUTO-GENERATED by scripts/render_paper_tables.py from "
            "docs/corpus/*.csv. DO NOT EDIT; edit the CSV + re-run.\n")
    body = "\n".join(f"\\newcommand{{{name}}}{{{val}}}" for name, val in defs)
    return head + body + "\n"


_GEN_HEAD = ("% AUTO-GENERATED by scripts/render_paper_tables.py from "
             "docs/corpus/*.csv. DO NOT EDIT; edit the CSV + re-run.\n")


def main() -> None:
    summary, cells, appendix = load_corpus()
    # sanity: every verdict_class in the corpus is a known taxonomy class.
    unknown = sorted({r["verdict_class"] for r in summary} - set(VERDICT_CLASSES))
    if unknown:
        raise SystemExit(f"corpus has unknown verdict_class(es): {unknown}")

    GENERATED.mkdir(parents=True, exist_ok=True)
    (GENERATED / "tab_corpus.tex").write_text(_GEN_HEAD + render_tab_corpus(summary), encoding="utf-8")
    (GENERATED / "tab_dudect.tex").write_text(_GEN_HEAD + render_tab_dudect(appendix), encoding="utf-8")
    (GENERATED / "tab_ablation.tex").write_text(_GEN_HEAD + render_tab_ablation(summary, appendix), encoding="utf-8")
    (GENERATED / "tab_mldsa.tex").write_text(_GEN_HEAD + render_tab_mldsa(cells), encoding="utf-8")
    (GENERATED / "corpus_macros.tex").write_text(render_macros(summary, cells, appendix), encoding="utf-8")
    print(f"[render] wrote generated paper tables in {GENERATED}")


if __name__ == "__main__":
    main()
