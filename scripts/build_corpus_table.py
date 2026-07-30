#!/usr/bin/env python3
"""Merge one ctkat project's per-tool reports into evidence schema v2
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
from ctkat.evidence import SCHEMA_VERSION  # noqa: E402
from ctkat.verdict_class import load_registry, opt_of, summarize  # noqa: E402

CELLS_FIELDS = [
    "schema_version",
    "family",
    "target",
    "harness",
    "combo",
    "cc",
    "cc_version",
    "opt",
    "cflags",
    "arch",
    "ctkat_commit",
    "ct_status",
    "ct_findings",
    "ct_finding_funcs",
    "ct_error",
    "asm_status",
    "asm_div_count",
    "asm_div_funcs",
    "asm_error",
]
SUMMARY_FIELDS = [
    "schema_version",
    "family",
    "target",
    "harness",
    "correctness",
    "structural",
    "asm",
    "asm_attribution",
    "timing_validity",
    "timing_signal",
    "review",
    "review_id",
    "overall",
    "ct_flips",
    "ct_status_set",
    "ct_finding_funcs",
    "varlat_candidates",
    "varlat_triage",
    "timing_backend",
    "timing_raw_status",
    "timing_abs_t",
    "timing_measurements",
    "timing_leak_target",
    "timing_seed",
    "timing_threshold",
    "legacy_verdict_class",
    "legacy_basis",
    "notes",
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


def build(
    project_dir,
    family,
    target,
    cc_versions,
    arch,
    commit,
    triage,
    verdict_override=None,
    note_override=None,
    registry=None,
    correctness="not-run",
    timing_validity=None,
    review_status=None,
    review_id=None,
):
    if registry is None:
        registry = load_registry()
    reports = project_dir / "reports"
    ctm = _read_csv(reports / "ctkat_ct_matrix.csv")
    varlat = _read_csv(reports / "ctkat_varlat_candidates.csv")
    varlat_json = _read_json(reports / "ctkat_varlat_candidates.json")
    dud = _read_csv(reports / "dudect_summary.csv")
    dcfg = _dudect_cfg(project_dir)

    ctm_projects = {row.get("project", "") for row in ctm if row.get("project")}
    if varlat_json:
        if varlat_json.get("kind") != "varlat_candidates":
            raise ValueError("asm coverage JSON kind must be 'varlat_candidates'")
        manifest_project = str(varlat_json.get("project", ""))
        if ctm_projects and manifest_project not in ctm_projects:
            raise ValueError(
                "asm coverage JSON project does not match ct-matrix report: "
                f"{manifest_project!r} not in {sorted(ctm_projects)!r}"
            )

    # Surface both asm-scan errors and explicit coverage. A compiler/opt absent
    # from the JSON coverage manifest is NOT_RUN, never a clean zero-candidate
    # cell. Candidate CSV rows alone can prove that their own legacy cell ran,
    # but cannot prove coverage for candidate-free cells.
    asm_err_by_cc = {
        e.get("compiler", ""): e.get("error", "") for e in (varlat_json.get("errors") or [])
    }
    scanned_ccs = {str(value) for value in (varlat_json.get("scanned_compilers") or [])}
    scanned_opts = {str(value) for value in (varlat_json.get("scanned_opt_levels") or [])}

    # asm-scan candidates indexed by (harness, compiler, opt). Dropping the
    # harness key would copy one target path's candidates into sibling harnesses.
    vindex: dict = {}
    for r in varlat:
        for opt in r.get("opt_levels", "").split(";"):
            if opt:
                vindex.setdefault((r["harness"], r["compiler"], opt), []).append(
                    (r["function"], int(r.get("count", "1") or 1))
                )

    observed_candidate_cells = {(compiler, opt) for _harness, compiler, opt in vindex}
    if varlat_json:
        declared_coverage = {(cc, opt) for cc in scanned_ccs for opt in scanned_opts}
        undeclared_candidates = sorted(observed_candidate_cells - declared_coverage)
        if undeclared_candidates:
            raise ValueError(
                "candidate CSV contains compiler/opt cells absent from asm coverage JSON: "
                f"{undeclared_candidates}"
            )

    def _asm_status_for(cc: str, opt: str) -> str:
        if cc in asm_err_by_cc:
            return "ERROR"
        if (cc in scanned_ccs and opt in scanned_opts) or (
            not varlat_json and (cc, opt) in observed_candidate_cells
        ):
            return "PASS"
        return "NOT_RUN"

    cells = []
    for r in ctm:
        opt = opt_of(r.get("cflags", ""))
        hits = vindex.get((r["harness"], r["cc"], opt), [])
        cells.append(
            {
                "schema_version": SCHEMA_VERSION,
                "family": family,
                "target": target,
                "harness": r["harness"],
                "combo": r.get("combo", ""),
                "cc": r["cc"],
                "cc_version": cc_versions.get(r["cc"], ""),
                "opt": opt,
                "cflags": r.get("cflags", ""),
                "arch": arch,
                "ctkat_commit": commit,
                "ct_status": r.get("valgrind_status", ""),
                "ct_findings": r.get("findings", ""),
                "ct_finding_funcs": r.get("finding_funcs", ""),
                "ct_error": r.get("error", ""),
                "asm_status": _asm_status_for(r["cc"], opt),
                "asm_div_count": str(sum(c for _f, c in hits)),
                "asm_div_funcs": ";".join(sorted({f for f, _c in hits})),
                "asm_error": asm_err_by_cc.get(r["cc"], ""),
            }
        )

    # Preserve asm-only coverage outside the structural compiler/opt matrix.
    # These cells use ct_status=NA so candidates or errors from an explicitly
    # wider asm scan still reach evidence v2 without inventing structural data.
    represented_asm = {(cell["harness"], cell["cc"], cell["opt"]) for cell in cells}
    harnesses = list(dict.fromkeys(row["harness"] for row in ctm))
    coverage_pairs = {(cc, opt) for cc in scanned_ccs for opt in scanned_opts}
    if not varlat_json:
        coverage_pairs.update(observed_candidate_cells)
    for cc in asm_err_by_cc:
        coverage_pairs.update((cc, opt) for opt in scanned_opts)
    for harness in harnesses:
        for cc, opt in sorted(coverage_pairs):
            key = (harness, cc, opt)
            if key in represented_asm:
                continue
            hits = vindex.get((harness, cc, opt), [])
            cells.append(
                {
                    "schema_version": SCHEMA_VERSION,
                    "family": family,
                    "target": target,
                    "harness": harness,
                    "combo": f"asm_only_{cc}_{opt.lstrip('-')}",
                    "cc": cc,
                    "cc_version": cc_versions.get(cc, ""),
                    "opt": opt,
                    "cflags": opt,
                    "arch": arch,
                    "ctkat_commit": commit,
                    "ct_status": "NA",
                    "ct_findings": "0",
                    "ct_finding_funcs": "",
                    "ct_error": "",
                    "asm_status": _asm_status_for(cc, opt),
                    "asm_div_count": str(sum(count for _function, count in hits)),
                    "asm_div_funcs": ";".join(sorted({function for function, _count in hits})),
                    "asm_error": asm_err_by_cc.get(cc, ""),
                }
            )
            represented_asm.add(key)

    # The per-harness classification + summary rows are produced by the shared
    # classifier (ctkat/verdict_class.py) so this script and `ctkat screen` can't
    # drift. CSV/JSON reading + the corpus-cell join (with curation metadata
    # family/target/cc_version/arch/commit) stay here; only the taxonomy moved.
    dud_by = {d["harness"]: d for d in dud}
    summary = summarize(
        cells,
        family=family,
        triage=triage,
        dud_by=dud_by,
        dcfg=dcfg,
        registry=registry,
        verdict_override=verdict_override,
        note_override=note_override,
        correctness=correctness,
        timing_validity=timing_validity,
        review_status=review_status,
        review_id=review_id,
        target=target,
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
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--project-dir", required=True, type=Path)
    ap.add_argument("--family", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--arch", default="")
    ap.add_argument("--ctkat-commit", default="")
    ap.add_argument("--cc-version", action="append", default=[], metavar="cc=version")
    ap.add_argument(
        "--triage",
        action="append",
        default=[],
        metavar="harness=public|secret-risk|mixed|none|untriaged",
    )
    ap.add_argument(
        "--verdict",
        action="append",
        default=[],
        metavar="harness=verdict_class",
        help="manual verdict_class override (domain triage, e.g. accepted-variable-time)",
    )
    ap.add_argument(
        "--note",
        action="append",
        default=[],
        metavar="harness=text",
        help="append a manual note to a harness row",
    )
    ap.add_argument(
        "--correctness",
        choices=["pass", "fail", "error", "not-run"],
        default="not-run",
        help="KAT/correctness state attached to every emitted harness row",
    )
    ap.add_argument(
        "--timing-validity",
        action="append",
        default=[],
        metavar="harness=valid|confounded|insufficient-power|environment-rejected|error|not-run",
    )
    ap.add_argument(
        "--review",
        action="append",
        default=[],
        metavar="harness=not-needed|pending|reviewed|disputed|expired",
    )
    ap.add_argument(
        "--review-id",
        action="append",
        default=[],
        metavar="harness=artifact-id",
    )
    ap.add_argument("--out-dir", type=Path, default=Path("docs/corpus"))
    a = ap.parse_args()

    cc_versions = dict(x.split("=", 1) for x in a.cc_version)
    triage = dict(x.split("=", 1) for x in a.triage)
    verdict_override = dict(x.split("=", 1) for x in a.verdict)
    note_override = dict(x.split("=", 1) for x in a.note)
    timing_validity = dict(x.split("=", 1) for x in a.timing_validity)
    review_status = dict(x.split("=", 1) for x in a.review)
    review_id = dict(x.split("=", 1) for x in a.review_id)

    # Validate --verdict against the known taxonomy, symmetric with triage.yaml's
    # verdict field (ctkat/triage.py). A typo'd override would otherwise write a
    # bogus verdict_class straight into the corpus.
    from ctkat.verdict_class import VERDICT_CLASSES

    bad = {h: v for h, v in verdict_override.items() if v not in VERDICT_CLASSES}
    if bad:
        ap.error(
            f"--verdict: unknown verdict_class(es) {bad}; expected one of {list(VERDICT_CLASSES)}"
        )

    cells, summary = build(
        a.project_dir,
        a.family,
        a.target,
        cc_versions,
        a.arch,
        a.ctkat_commit,
        triage,
        verdict_override,
        note_override,
        correctness=a.correctness,
        timing_validity=timing_validity,
        review_status=review_status,
        review_id=review_id,
    )
    cp = merge_write(a.out_dir, a.target, cells, CELLS_FIELDS, "corpus_cells.csv")
    sp = merge_write(a.out_dir, a.target, summary, SUMMARY_FIELDS, "corpus_summary.csv")
    print(f"[corpus] {a.target}: {len(cells)} cells -> {cp}")
    print(f"[corpus] {a.target}: {len(summary)} summary rows -> {sp}")
    for s in summary:
        print(
            f"    {s['harness']:12} overall={s['overall']:20} "
            f"ct={s['structural']} timing={s['timing_validity']}/{s['timing_signal']} "
            f"varlat={s['varlat_candidates']} triage={s['varlat_triage']}"
        )


if __name__ == "__main__":
    main()
