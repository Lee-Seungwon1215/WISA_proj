#!/usr/bin/env python3
"""Merge one ctkat project's per-tool reports into the LOCKED corpus schema
(docs/corpus_schema.md): `corpus_cells.csv` (per build cell) and
`corpus_summary.csv` (per harness). Idempotent per target — re-running replaces
that target's rows, so the corpus tables grow as targets are added.

Reads `<project-dir>/reports/`:
  - ctkat_ct_matrix.csv          (ct/Valgrind per build cell)
  - ctkat_varlat_candidates.csv  (asm-scan division candidates)
  - dudect_summary.csv           (timing, per harness)
and `<project-dir>/ctkat.yaml`   (dudect config: leak_target/seed/threshold).

The in-tool artifact schemas stay frozen; only THIS script knows the corpus
layout. `varlat_triage` is a MANUAL judgement (public vs secret-derived) — pass
`--triage <harness>=public|secret-risk|none`, else it defaults to `untriaged`
and the verdict lands as `ct-clean-untriaged` (the honest default).

Example:
  scripts/build_corpus_table.py --project-dir examples/pqc_mlkem768 \\
      --family ML-KEM --target pqclean_mlkem768 \\
      --arch x86_64 --ctkat-commit 8046018 \\
      --cc-version gcc=13.3.0 --cc-version clang=18.1.3 \\
      --triage kem_dec=public --triage kem_dec_ct=public \\
      --out-dir docs/corpus
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

# Running this as a standalone script (`python scripts/build_corpus_table.py`)
# puts scripts/ on sys.path, not the repo root — bootstrap the root so we can
# import the shared classifier (the single source of truth for verdict_class,
# also used by `ctkat screen`). Mirrors the lazy path-insert in _dudect_cfg.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ctkat.verdict_class import load_registry, opt_of, summarize  # noqa: E402

CELLS_FIELDS = [
    "family", "target", "harness", "combo", "cc", "cc_version", "opt", "cflags",
    "arch", "ctkat_commit", "ct_status", "ct_findings", "ct_finding_funcs", "ct_error",
    "asm_div_count", "asm_div_funcs", "asm_error",
]
SUMMARY_FIELDS = [
    "family", "target", "harness", "ct_flips", "ct_status_set", "ct_finding_funcs",
    "varlat_candidates", "varlat_triage",
    "dudect_status", "dudect_abs_t", "dudect_measurements", "dudect_leak_target",
    "dudect_seed", "dudect_threshold",
    "verdict_class", "notes",
]


# `load_registry` and `opt_of` now live in ctkat/verdict_class.py (imported above)
# so this script and `ctkat screen` share one implementation. Re-exported here via
# the import so existing callers/tests (`bct.load_registry`, `bct.opt_of`) still work.


def _read_csv(path: Path) -> list:
    if not path.exists():
        return []
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _dudect_cfg(project_dir: Path) -> dict:
    """Best-effort dudect config (leak_target per harness + seed/threshold/
    measurements) from the project's yaml. Degrades to {} on any error so a
    missing/odd config never breaks the merge."""
    try:
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from ctkat.config import load_config
        cfg = load_config(project_dir / "ctkat.yaml")
        d = cfg.dudect
        if d is None:
            return {}
        seed = getattr(d, "seed", "")
        tw = getattr(d, "threshold_warning", "")
        tf = getattr(d, "threshold_fail", "")
        meas = getattr(d, "measurements", "")
        per = {}
        for h in getattr(d, "harnesses", []) or []:
            per[h.name] = {
                "leak_target": getattr(h, "leak_target", ""),
                "seed": str(seed),
                "threshold": f"{tw}/{tf}" if tw != "" or tf != "" else "",
                "measurements": str(meas),
            }
        return per
    except Exception:
        return {}


def build(project_dir, family, target, cc_versions, arch, commit, triage,
          verdict_override=None, note_override=None, registry=None):
    if registry is None:
        registry = load_registry()
    reports = project_dir / "reports"
    ctm = _read_csv(reports / "ctkat_ct_matrix.csv")
    varlat = _read_csv(reports / "ctkat_varlat_candidates.csv")
    varlat_json = _read_json(reports / "ctkat_varlat_candidates.json")
    dud = _read_csv(reports / "dudect_summary.csv")
    dcfg = _dudect_cfg(project_dir)

    # N2: surface asm-scan compiler ERRORS so a cell whose asm scan was
    # incomplete is NOT printed as a clean "0 divisions". The varlat JSON records
    # per-compiler errors (missing/non-exec cc, disasm failure, or a source that
    # never compiled); the CSV (candidates only) has no error column, which is
    # why asm_error was previously hardcoded "". Per corpus_schema.md, asm_error
    # means an asm-scan ERROR — NOT a compiler that simply wasn't in asm-scan's
    # --cc set (the common matrix={gcc,clang} / asm-scan=gcc-only flow), which is
    # a coverage choice, not an error; conflating them would false-flag and (via
    # the verdict fold below) false-downgrade those builds.
    asm_err_by_cc = {
        e.get("compiler", ""): e.get("error", "")
        for e in (varlat_json.get("errors") or [])
    }

    def _asm_error_for(cc: str) -> str:
        return asm_err_by_cc.get(cc, "")

    # asm-scan candidates indexed by (compiler, opt) -> [(function, count), ...]
    vindex: dict = {}
    for r in varlat:
        for opt in r.get("opt_levels", "").split(";"):
            if opt:
                vindex.setdefault((r["compiler"], opt), []).append(
                    (r["function"], int(r.get("count", "1") or 1))
                )

    cells = []
    for r in ctm:
        opt = opt_of(r.get("cflags", ""))
        hits = vindex.get((r["cc"], opt), [])
        cells.append({
            "family": family, "target": target, "harness": r["harness"],
            "combo": r.get("combo", ""), "cc": r["cc"],
            "cc_version": cc_versions.get(r["cc"], ""), "opt": opt,
            "cflags": r.get("cflags", ""), "arch": arch, "ctkat_commit": commit,
            "ct_status": r.get("valgrind_status", ""), "ct_findings": r.get("findings", ""),
            "ct_finding_funcs": r.get("finding_funcs", ""), "ct_error": r.get("error", ""),
            "asm_div_count": str(sum(c for _f, c in hits)),
            "asm_div_funcs": ";".join(sorted({f for f, _c in hits})),
            "asm_error": _asm_error_for(r["cc"]),
        })

    # The per-harness classification + summary rows are produced by the shared
    # classifier (ctkat/verdict_class.py) so this script and `ctkat screen` can't
    # drift. CSV/JSON reading + the corpus-cell join (with curation metadata
    # family/target/cc_version/arch/commit) stay here; only the taxonomy moved.
    dud_by = {d["harness"]: d for d in dud}
    summary = summarize(
        cells, family=family, triage=triage, dud_by=dud_by, dcfg=dcfg,
        registry=registry, verdict_override=verdict_override, note_override=note_override,
    )
    return cells, summary


def merge_write(out_dir: Path, target: str, new_rows: list, fields: list, fname: str) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / fname
    kept = [r for r in _read_csv(path) if r.get("target") != target]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
        w.writeheader()
        for r in kept + new_rows:
            w.writerow({k: r.get(k, "") for k in fields})
    return path


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project-dir", required=True, type=Path)
    ap.add_argument("--family", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--arch", default="")
    ap.add_argument("--ctkat-commit", default="")
    ap.add_argument("--cc-version", action="append", default=[], metavar="cc=version")
    ap.add_argument("--triage", action="append", default=[], metavar="harness=public|secret-risk|none")
    ap.add_argument("--verdict", action="append", default=[], metavar="harness=verdict_class",
                    help="manual verdict_class override (domain triage, e.g. accepted-variable-time)")
    ap.add_argument("--note", action="append", default=[], metavar="harness=text",
                    help="append a manual note to a harness row")
    ap.add_argument("--out-dir", type=Path, default=Path("docs/corpus"))
    a = ap.parse_args()

    cc_versions = dict(x.split("=", 1) for x in a.cc_version)
    triage = dict(x.split("=", 1) for x in a.triage)
    verdict_override = dict(x.split("=", 1) for x in a.verdict)
    note_override = dict(x.split("=", 1) for x in a.note)

    # Validate --verdict against the known taxonomy, symmetric with triage.yaml's
    # verdict field (ctkat/triage.py). A typo'd override would otherwise write a
    # bogus verdict_class straight into the corpus.
    from ctkat.verdict_class import VERDICT_CLASSES
    bad = {h: v for h, v in verdict_override.items() if v not in VERDICT_CLASSES}
    if bad:
        ap.error(f"--verdict: unknown verdict_class(es) {bad}; "
                 f"expected one of {list(VERDICT_CLASSES)}")

    cells, summary = build(
        a.project_dir, a.family, a.target, cc_versions, a.arch, a.ctkat_commit, triage,
        verdict_override, note_override,
    )
    cp = merge_write(a.out_dir, a.target, cells, CELLS_FIELDS, "corpus_cells.csv")
    sp = merge_write(a.out_dir, a.target, summary, SUMMARY_FIELDS, "corpus_summary.csv")
    print(f"[corpus] {a.target}: {len(cells)} cells -> {cp}")
    print(f"[corpus] {a.target}: {len(summary)} summary rows -> {sp}")
    for s in summary:
        print(f"    {s['harness']:12} verdict={s['verdict_class']:20} "
              f"ct={s['ct_status_set']} dudect={s['dudect_status'] or '-'} "
              f"varlat={s['varlat_candidates']} triage={s['varlat_triage']}")


if __name__ == "__main__":
    main()
