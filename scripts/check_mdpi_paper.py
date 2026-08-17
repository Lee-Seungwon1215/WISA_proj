#!/usr/bin/env python3
"""Fail-closed checks for the MDPI working manuscript.

The checker deliberately distinguishes a compileable pre-result draft from a
submission candidate.  Pending native tables are accepted only when the caller
passes ``--allow-pending``; the default is the stricter final-paper gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import render_mdpi_results  # noqa: E402

PAPER = ROOT / "paper/mdpi_working"
MAIN = PAPER / "main.tex"
BIB = PAPER / "references.bib"
GENERATED = PAPER / "generated"

UPSTREAM_HASHES = {
    "Definitions/journalnames.tex": "18bcc6796b8e0460faabf3ae5a1e7ac3f3ca1e411107fd37853b3412e5a63e43",
    "Definitions/logo-mdpi-eps-converted-to.pdf": "e7fe39ea976c17c19484beb29d3a98d64ec26a498c6eb16104c3ebb7b8d37d6c",
    "Definitions/logo-mdpi.eps": "f02d31469c6b2666c9de2da8d8731773bce3751d2fa99a27ff4bcf61a106cdcf",
    "Definitions/logo-orcid.pdf": "0558a0097dc4d1ffe3f4a1b3c9b4b98c6e568eac7d7439d447ca56ed1a8ec759",
    "Definitions/logo-updates.eps": "71ad8b00bcca718b62f3286af02ea56678e8199b5843d7ed4fdc86bd969c2809",
    "Definitions/mdpi.bst": "3b747eee144173c46a43562ead905c26322c7cb394e350a925d36dcf63884680",
    "Definitions/mdpi.cls": "5ca561720cb31ddd52436334b54d442ed03cf921571b39ddfcba95c1ac8047d4",
    "Definitions/mdpi_apacite.bst": "c7fffe0231922e5521dc360889fafe941ee26d154c1ce4e167e4ec9f2d13498f",
    "Definitions/mdpi_apacite.sty": "a77a994f978c1860ff14dbcae74631f3ed835b418adbdcf84de2f06d98c34599",
    "Definitions/mdpi_chicago.bst": "4a73faf6e0cf1a225d1b9a41a6955d3cc29a55c5fdce662177d00eee3946ce36",
    "upstream/template.tex": "d10768ded633452ced9c07c918a1ab996681ea0ccd010e4b83cc5313897cbb62",
}

REQUIRED_SECTIONS = (
    "Introduction",
    "Background and Related Work",
    "Materials and Methods",
    "Results",
    "Discussion",
    "Limitations",
    "Conclusions",
)
REQUIRED_BACK_MATTER = (
    r"\supplementary{",
    r"\authorcontributions{",
    r"\funding{",
    r"\institutionalreview{",
    r"\informedconsent{",
    r"\dataavailability{",
    r"\acknowledgments{",
    r"\conflictsofinterest{",
    r"\abbreviations{",
    r"\bibliography{references}",
)
FORBIDDEN_MANUSCRIPT_PATTERNS = {
    r"accepted-variable-time": "retired declassification vocabulary",
    r"\\usepackage(?:\[[^]]*\])?\{kotex\}": "WISA-only Korean package",
    r"llncs(?:\.cls)?": "WISA/LNCS class reference",
}

# These values came from the superseded WISA draft and must not be copied into
# hand-written prose.  A complete named analysis may legitimately produce the
# same decimal text (for example, the measured host model contains 2.30 GHz and
# one V10 t-score rounds to 2.3), so generated files are protected by their
# analysis-byte reconstruction instead of this lexical denylist.
FORBIDDEN_SOURCE_PATTERNS = {
    r"(?<![0-9])2\.30(?![0-9])": "legacy native timing value 2.30",
    r"(?<![0-9])2\.10(?![0-9])": "legacy native timing value 2.10",
    r"(?<![0-9])1\.15(?:--|–|-)1\.75(?![0-9])": "legacy native timing range",
    r"(?<![0-9])1\.59(?![0-9])": "legacy native timing value 1.59",
    r"(?<![0-9])1\.52(?![0-9])": "legacy native timing value 1.52",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read(path: Path, errors: list[str]) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        errors.append(f"missing or unreadable {path.relative_to(ROOT)}: {exc}")
        return ""


def _check_upstream(errors: list[str]) -> None:
    for relative, expected in UPSTREAM_HASHES.items():
        path = PAPER / relative
        if not path.is_file():
            errors.append(f"official MDPI asset missing: paper/mdpi_working/{relative}")
        elif _sha256(path) != expected:
            errors.append(f"official MDPI asset changed: paper/mdpi_working/{relative}")


def _check_structure(main: str, generated: str, bib: str, errors: list[str]) -> None:
    if r"\documentclass[cryptography,article,submit,moreauthors]{Definitions/mdpi}" not in main:
        errors.append("working manuscript is not pinned to the provisional MDPI ACS profile")
    for section in REQUIRED_SECTIONS:
        if rf"\section{{{section}}}" not in main:
            errors.append(f"required manuscript section missing: {section}")
    for marker in REQUIRED_BACK_MATTER:
        if marker not in main:
            errors.append(f"required MDPI back-matter command missing: {marker}")
    for include in (
        "generated/native_summary.tex",
        "generated/static_results.tex",
        "generated/native_results.tex",
    ):
        if rf"\input{{{include}}}" not in main:
            errors.append(f"generated result include missing: {include}")
    summary_include = r"\input{generated/native_summary.tex}"
    abstract = r"\abstract{"
    if (
        summary_include in main
        and abstract in main
        and main.index(summary_include) > main.index(abstract)
    ):
        errors.append("native summary must be loaded before the MDPI abstract is defined")

    manuscript = main + "\n" + generated
    for pattern, explanation in FORBIDDEN_MANUSCRIPT_PATTERNS.items():
        if re.search(pattern, manuscript, flags=re.IGNORECASE):
            errors.append(f"forbidden stale content found: {explanation}")
    for pattern, explanation in FORBIDDEN_SOURCE_PATTERNS.items():
        if re.search(pattern, main, flags=re.IGNORECASE):
            errors.append(f"forbidden stale source content found: {explanation}")

    labels = re.findall(r"\\label\{([^}]+)\}", manuscript)
    duplicates = sorted({label for label in labels if labels.count(label) > 1})
    if duplicates:
        errors.append("duplicate LaTeX labels: " + ", ".join(duplicates))
    known_labels = set(labels)
    references = set(re.findall(r"\\(?:auto|page)?ref\{([^}]+)\}", manuscript))
    missing_labels = sorted(references - known_labels)
    if missing_labels:
        errors.append("references to missing labels: " + ", ".join(missing_labels))

    bib_keys = set(re.findall(r"^\s*@\w+\s*\{\s*([^,\s]+)", bib, flags=re.MULTILINE))
    cited: set[str] = set()
    for group in re.findall(r"\\cite\w*\s*(?:\[[^]]*\]\s*)*\{([^}]+)\}", manuscript):
        cited.update(key.strip() for key in group.split(",") if key.strip())
    missing_citations = sorted(cited - bib_keys)
    if missing_citations:
        errors.append("citations missing from references.bib: " + ", ".join(missing_citations))


def _check_generated(*, analysis_path: Path | None, allow_pending: bool, errors: list[str]) -> str:
    state_path = GENERATED / "render_state.json"
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"generated render state is unreadable: {exc}")
        return "unknown"
    status = state.get("native_results")
    if status not in {"pending", "complete"}:
        errors.append(f"generated native result state is invalid: {status!r}")
        return "unknown"
    if status == "pending":
        if not allow_pending:
            errors.append(
                "native results are pending; use --allow-pending only for a pre-result draft"
            )
        if analysis_path is not None:
            errors.append("an analysis file was supplied but generated results are still pending")
        expected_analysis = None
    else:
        if analysis_path is None:
            errors.append("complete generated results require --analysis for byte verification")
            return status
        expected_analysis = analysis_path

    try:
        outputs = render_mdpi_results.build_outputs(
            analysis_path=expected_analysis,
            output_root=GENERATED,
        )
    except (OSError, render_mdpi_results.RenderError, KeyError) as exc:
        errors.append(f"cannot reconstruct generated result inputs: {exc}")
        return status
    for path, expected in outputs.items():
        actual = _read(path, errors)
        if actual and actual != expected:
            errors.append(f"generated paper input is stale: {path.relative_to(ROOT)}")
    return status


def _check_log(path: Path, errors: list[str]) -> None:
    log = _read(path, errors)
    if not log:
        return
    undefined_patterns = (
        r"LaTeX Warning: Citation .+ undefined",
        r"LaTeX Warning: Reference .+ undefined",
        r"There were undefined (?:references|citations)",
        r"No file .+\.bbl",
    )
    for pattern in undefined_patterns:
        if re.search(pattern, log):
            errors.append(f"LaTeX log contains unresolved material matching: {pattern}")
    widths = [
        float(value) for value in re.findall(r"Overfull \\hbox \(([0-9.]+)pt too wide\)", log)
    ]
    material = [value for value in widths if value > 2.0]
    if material:
        errors.append(
            "LaTeX log contains material overfull boxes: "
            + ", ".join(f"{value:g}pt" for value in material)
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analysis", type=Path)
    parser.add_argument("--allow-pending", action="store_true")
    parser.add_argument("--log", type=Path)
    args = parser.parse_args()

    errors: list[str] = []
    _check_upstream(errors)
    main_text = _read(MAIN, errors)
    bib_text = _read(BIB, errors)
    generated_text = "\n".join(
        _read(GENERATED / name, errors)
        for name in ("native_summary.tex", "static_results.tex", "native_results.tex")
    )
    _check_structure(main_text, generated_text, bib_text, errors)
    status = _check_generated(
        analysis_path=args.analysis,
        allow_pending=args.allow_pending,
        errors=errors,
    )
    if args.log is not None:
        _check_log(args.log, errors)

    if errors:
        for error in errors:
            print(f"[mdpi-paper] ERROR: {error}", file=sys.stderr)
        return 1
    mode = "pre-result" if status == "pending" else "complete-result"
    print(f"[mdpi-paper] OK: {mode} manuscript passes fail-closed checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
