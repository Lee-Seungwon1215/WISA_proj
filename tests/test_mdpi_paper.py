from pathlib import Path

from scripts import check_mdpi_paper as checker
from scripts import render_mdpi_results


def test_repository_mdpi_assets_and_manuscript_structure_are_current():
    errors: list[str] = []
    checker._check_upstream(errors)
    main = checker.MAIN.read_text(encoding="utf-8")
    bib = checker.BIB.read_text(encoding="utf-8")
    generated = "\n".join(
        (checker.GENERATED / name).read_text(encoding="utf-8")
        for name in ("native_summary.tex", "static_results.tex", "native_results.tex")
    )
    checker._check_structure(main, generated, bib, errors)
    assert errors == []


def test_pending_result_requires_explicit_pre_result_mode(tmp_path: Path, monkeypatch):
    generated = tmp_path / "generated"
    outputs = render_mdpi_results.build_outputs(output_root=generated)
    generated.mkdir()
    for path, content in outputs.items():
        path.write_text(content, encoding="utf-8")
    monkeypatch.setattr(checker, "GENERATED", generated)

    strict_errors: list[str] = []
    status = checker._check_generated(
        analysis_path=None,
        allow_pending=False,
        errors=strict_errors,
    )
    assert status == "pending"
    assert any("--allow-pending" in error for error in strict_errors)

    draft_errors: list[str] = []
    checker._check_generated(
        analysis_path=None,
        allow_pending=True,
        errors=draft_errors,
    )
    assert draft_errors == []


def test_latex_log_gate_rejects_only_material_overfull_boxes(tmp_path: Path):
    harmless = tmp_path / "harmless.log"
    harmless.write_text(
        "Overfull \\hbox (0.21176pt too wide) in paragraph\n",
        encoding="utf-8",
    )
    errors: list[str] = []
    checker._check_log(harmless, errors)
    assert errors == []

    broken = tmp_path / "broken.log"
    broken.write_text(
        "Overfull \\hbox (9.5pt too wide) in paragraph\n"
        "LaTeX Warning: Reference `missing' on page 1 undefined\n",
        encoding="utf-8",
    )
    checker._check_log(broken, errors)
    assert any("overfull" in error for error in errors)
    assert any("unresolved" in error for error in errors)


def test_legacy_numeric_denylist_applies_only_to_hand_written_source():
    errors: list[str] = []
    checker._check_structure(
        checker.MAIN.read_text(encoding="utf-8"),
        r"Validated generated value: 2.30",
        checker.BIB.read_text(encoding="utf-8"),
        errors,
    )
    assert not any("legacy native timing value 2.30" in error for error in errors)

    errors = []
    checker._check_structure(
        checker.MAIN.read_text(encoding="utf-8") + "\nLegacy copied result: 2.30",
        "",
        checker.BIB.read_text(encoding="utf-8"),
        errors,
    )
    assert any("legacy native timing value 2.30" in error for error in errors)


def test_submission_packager_normalizes_and_sorts_archive_inputs():
    script = (checker.ROOT / "scripts/package_mdpi_submission.sh").read_text(encoding="utf-8")
    assert "LC_ALL=C sort" in script
    assert "touch -t 200001010000.00" in script
    assert 'zip -X -q "$output_abs" -@' in script
