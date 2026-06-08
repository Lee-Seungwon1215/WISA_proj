"""Phase 2: enforce paper == corpus. The paper's numbers used to be hand-copied
from docs/corpus/*.csv (honor-system, paper/README.md). This test fails if any
corpus-derived number/string in the paper / generated snippets / report_tables.md
drifts from the CSVs — so `pytest` catches what a human would otherwise miss.

CI-safe: pure committed-file reads (no valgrind/Docker). Shares the transform +
rounding helpers with the generator (scripts/render_paper_tables.py), so the test
and generator can't disagree about what "correct" is (CLAUDE.md §3/§5). Every
corpus-derived SURFACE gets ≥1 assertion (§1): the generated snippets, the macro
file, the paper prose (all sections), and docs/report_tables.md.
"""
import importlib.util
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
GEN_SCRIPT = ROOT / "scripts" / "render_paper_tables.py"
GENERATED = ROOT / "paper" / "generated"
PAPER = ROOT / "paper"
RESULTS_TEX = PAPER / "sections" / "04_results.tex"
DISCUSSION_TEX = PAPER / "sections" / "05_discussion.tex"
REPORT_MD = ROOT / "docs" / "report_tables.md"
REFRESH_SCRIPT = ROOT / "scripts" / "refresh_corpus_docker.sh"

_spec = importlib.util.spec_from_file_location("render_paper_tables", GEN_SCRIPT)
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)

NUM2WORD = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six",
            7: "seven", 8: "eight", 9: "nine", 10: "ten"}
WORD2NUM = {w: n for n, w in NUM2WORD.items()}


def num2word(n: int) -> str:
    if n not in NUM2WORD:
        pytest.fail(f"corpus dimension {n} exceeds NUM2WORD table — extend it")
    return NUM2WORD[n]


def _unescape(s: str) -> str:
    return s.replace("\\_", "_")


def _all_paper_tex() -> str:
    """main.tex + every section, underscores un-escaped, for substring checks."""
    parts = [(PAPER / "main.tex").read_text(encoding="utf-8")]
    parts += [p.read_text(encoding="utf-8") for p in sorted((PAPER / "sections").glob("*.tex"))]
    return _unescape("\n".join(parts))


def _macro_values() -> dict:
    """name -> value parsed from the committed generated macro file."""
    txt = (GENERATED / "corpus_macros.tex").read_text(encoding="utf-8")
    return dict(re.findall(r"\\newcommand\{\\(\w+)\}\{(.*)\}", txt))


@pytest.fixture(scope="module")
def corpus():
    return gen.load_corpus()  # (summary, cells, appendix)


# --- THE drift guard: committed generated files == fresh render from CSV -----

def test_tab_corpus_matches_fresh_render(corpus):
    summary, _cells, _appendix = corpus
    assert (GENERATED / "tab_corpus.tex").read_text(encoding="utf-8") == \
        gen._GEN_HEAD + gen.render_tab_corpus(summary), \
        "tab_corpus.tex stale — re-run scripts/render_paper_tables.py"


def test_tab_dudect_matches_fresh_render(corpus):
    _s, _c, appendix = corpus
    assert (GENERATED / "tab_dudect.tex").read_text(encoding="utf-8") == \
        gen._GEN_HEAD + gen.render_tab_dudect(appendix), \
        "tab_dudect.tex stale — re-run scripts/render_paper_tables.py"


def test_corpus_macros_match_fresh_render(corpus):
    summary, cells, appendix = corpus
    assert (GENERATED / "corpus_macros.tex").read_text(encoding="utf-8") == \
        gen.render_macros(summary, cells, appendix), \
        "corpus_macros.tex stale — re-run scripts/render_paper_tables.py"


# --- the paper must USE the generated artifacts (no hardcoded bypass) --------

def test_main_tex_inputs_generated_tables():
    t = (PAPER / "main.tex").read_text(encoding="utf-8")
    for snip in ("generated/tab_corpus", "generated/tab_dudect", "generated/corpus_macros"):
        assert f"\\input{{{snip}}}" in t
    for macro in (r"\corpusRows", r"\corpusFamilies", r"\corpusVerdictClasses"):
        assert macro in t


def test_main_tex_has_no_stale_generated_rows(corpus):
    # every generated data row must live ONLY in the snippet, not back in main.tex
    summary, _c, appendix = corpus
    t = (PAPER / "main.tex").read_text(encoding="utf-8")
    rows = (gen.render_tab_corpus(summary) + gen.render_tab_dudect(appendix)).splitlines()
    for row in rows:
        row = row.strip()
        if row and not row.startswith("%") and row != r"\bottomrule":
            assert row not in t, f"stale generated row hardcoded in main.tex: {row[:50]}"


def test_results_prose_uses_macros_not_hardcoded_numbers():
    r = RESULTS_TEX.read_text(encoding="utf-8")
    for macro in (r"\dudectLeakyT", r"\dudectLeakyTrunc", r"\dudectSafeT",
                  r"\dudectLeakyNzero", r"\dudectLeakyNone", r"\dudectLeakyMeanZero",
                  r"\dudectLeakyMeanOne", r"\dropTotalPct", r"\dropClassZeroPct",
                  r"\dropClassOnePct", r"\mlkemDudectT"):
        assert macro in r, f"04_results.tex should use {macro}"
    # programmatic forbidden list: every prose-duplicated macro VALUE must not be
    # re-hardcoded as a literal (would bypass single-sourcing). Built from the
    # macro file so it can never drift from what the generator emits.
    prose_macros = {
        "dudectLeakyT", "dudectLeakyTrunc", "dudectSafeT", "dudectLeakyNzero",
        "dudectLeakyNone", "dudectLeakyMeanZero", "dudectLeakyMeanOne",
        "dropTotalPct", "dropClassZeroPct", "dropClassOnePct", "mlkemDudectT",
    }
    vals = _macro_values()
    for name in prose_macros:
        lit = vals[name]
        # \dudectLeakyTrunc = "181" is a 3-digit substring of "181.5"; only flag a
        # standalone occurrence (word-boundaried) to avoid matching inside 181.5.
        pat = re.escape(lit)
        assert not re.search(rf"(?<![\d.]){pat}(?![\d.])", r), \
            f"value {lit!r} (macro \\{name}) hardcoded in 04_results.tex — use the macro"


# --- hand-typed prose across ALL sections still matches the corpus -----------

def test_cardinality_words_match_corpus_in_every_section(corpus):
    summary, cells, _appendix = corpus
    card = gen.cardinality(summary)
    mc = gen.max_build_cells(cells)
    all_tex = _all_paper_tex()

    def _check(noun_regex, expected, label):
        # every "<number-word> <noun>" in the paper must equal the corpus count.
        for m in re.finditer(rf"(\b[a-z]+)\s+{noun_regex}", all_tex, re.IGNORECASE):
            w = m.group(1).lower()
            if w in WORD2NUM:
                assert WORD2NUM[w] == expected, \
                    f"'{w} {label}' in paper != corpus {label}={expected}"

    _check(r"verdict class(?:es)?", card["verdict_classes"], "verdict classes")
    _check(r"families", card["families"], "families")
    _check(r"(?:harness\s+)?rows", card["rows"], "rows")
    _check(r"(?:build\s+)?(?:builds|cells)", mc, "build cells")
    # and the correct count-word must actually appear (catches "nobody says 7")
    assert f"{num2word(card['rows'])}" in all_tex
    assert f"{num2word(card['verdict_classes'])} verdict class" in all_tex


def test_every_verdict_class_named_in_paper(corpus):
    summary, _c, _a = corpus
    all_tex = _all_paper_tex()
    for vc in sorted({r["verdict_class"] for r in summary}):
        assert vc in all_tex, f"verdict_class {vc} (in corpus) never named in the paper"


def test_mldsa_leak_funcs_and_registry_split(corpus):
    summary, _c, _a = corpus
    from ctkat.verdict_class import load_registry
    reg = load_registry().get("ML-DSA", set())
    row = next(r for r in summary if r["target"] == "pqclean_mldsa65")
    short = [f.split("_CLEAN_")[-1] for f in row["ct_finding_funcs"].split(";") if f]
    registered = [s for s in short if any(s.endswith(rf) for rf in reg)]
    unregistered = [s for s in short if not any(s.endswith(rf) for rf in reg)]
    results = _unescape(RESULTS_TEX.read_text(encoding="utf-8"))
    discussion = _unescape(DISCUSSION_TEX.read_text(encoding="utf-8"))
    both = results + "\n" + discussion
    # every corpus leak-site function is named somewhere in the results/discussion
    for s in short:
        assert s in both, f"ML-DSA leak func {s} (in corpus) missing from paper prose"
    # the 3-registered / 2-unregistered split the prose claims matches the registry
    assert len(registered) == 3 and len(unregistered) == 2, (registered, unregistered)
    assert f"{num2word(len(registered)).capitalize()} ---" in results
    for s in unregistered:
        assert s in results
    # any unregistered func mentioned in the discussion must really be unregistered
    for s in short:
        if s in discussion:
            assert s in (unregistered + registered)  # i.e. it is a real corpus func


def test_compiler_versions_match_corpus(corpus):
    _s, cells, _a = corpus
    versions = sorted({r["cc_version"] for r in cells if r["cc_version"]})
    all_tex = _all_paper_tex()
    for v in versions:
        assert v in all_tex, f"compiler version {v} (corpus cc_version) missing from paper"
    # no OTHER x.y.z version string masquerading as a compiler version
    for m in re.finditer(r"(?:gcc|clang|GCC|Clang)~?(\d+\.\d+\.\d+)", all_tex):
        assert m.group(1) in versions, f"paper cites compiler version {m.group(1)} not in corpus {versions}"


# --- docs/report_tables.md (curated, NOT regenerated — test-guarded in full) --

def test_report_tables_md_matches_corpus(corpus):
    summary, _c, appendix = corpus
    md = REPORT_MD.read_text(encoding="utf-8")
    # A1 appendix: BOTH rows, every numeric field + status
    for h in ("leaky", "safe"):
        r = appendix[h]
        for v in (str(int(r["n0"])), str(int(r["n1"])), gen.round_mean(r["mean0"]),
                  gen.round_mean(r["mean1"]), gen.round_t(r["abs_t_score"]), r["status"]):
            assert v in md, f"report_tables.md A1 missing {h} value {v}"
    # the bare truncated |t| in the caveat sentence
    trunc = str(int(abs(float(appendix["leaky"]["abs_t_score"]))))
    assert f"|t|={trunc})" in md or f"({trunc}" in md
    # asymmetric-drop percentages
    dr = gen.drop_rates(appendix)
    for v in (gen.round_pct(dr["total"]), gen.round_pct(dr["class0"]), gen.round_pct(dr["class1"])):
        assert f"{v}%" in md
    # T2: every corpus row's target, verdict_class, and varlat display
    for row in summary:
        assert row["target"] in md
        assert row["verdict_class"] in md
        assert gen.varlat_cell(row) in md


def test_paper_does_not_hardcode_pytest_result_counts():
    # Pytest pass/skip counts change whenever the suite grows. They are an artifact
    # output, not a corpus fact, so the paper must not freeze "381 passed" again.
    all_tex = _all_paper_tex()
    assert not re.search(r"\b\d+\s*~?\s*passed\b", all_tex)
    assert not re.search(r"\b\d+\s*~?\s*skipped\b", all_tex)


def test_paper_surfaces_do_not_overclaim_universal_docker_provenance():
    # Some committed corpus cells still lack cc_version/arch/commit provenance.
    # Until Stage-A refresh fills those, prose must not say EVERY number/row is
    # from real Docker amd64 gcc/clang runs.
    surfaces = [
        _all_paper_tex(),
        REPORT_MD.read_text(encoding="utf-8"),
        (PAPER / "README.md").read_text(encoding="utf-8"),
    ]
    combined = "\n".join(surfaces).lower()
    forbidden = (
        "all from real docker",
        "all numbers are from real docker",
        "every figure in the paper comes from real docker",
        "each from a real docker run",
    )
    for phrase in forbidden:
        assert phrase not in combined


def test_refresh_script_does_not_swallow_structural_analysis_failures():
    # If ct-matrix/asm-scan fails, rebuilding corpus CSVs from stale reports is worse
    # than stopping. The Docker refresh path must fail closed for structural layers.
    sh = REFRESH_SCRIPT.read_text(encoding="utf-8")
    assert "ct-matrix  --config \"$dir/ctkat.yaml\" || true" not in sh
    assert "asm-scan   --config \"$dir/ctkat.yaml\" --cc gcc --cc clang || true" not in sh
