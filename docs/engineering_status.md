# CT-KAT engineering status & forward plan

> Engineering-hardening arc layered on top of the empirical corpus (see
> `go_forward.md` for the paper/report angle and `known_issues.md` for the older
> regression catalogue). This doc tracks **what was hardened**, the **review
> methodology** that drove it, and **what is still open** — so nothing deferred
> gets lost.

## Where we are

The tool went through five hardening passes. Each was: **audit/critique → fix →
adversarial multi-agent review (anchor-free, distinct lenses) → fix the review's
findings → verify (pytest + live repro + negative checks) → commit/push.** The
reviews repeatedly caught half-fixes and wrong justifications in the first cut —
that loop is the reason these landed clean, and it is worth keeping.

| pass | commit | what | headline outcome |
|---|---|---|---|
| Bundle Q | `ece94cf` | error-handling + fail-opens + load-time validation | missing/non-exec executable → clean ERROR/exit-2 (not a raw traceback); NaN/inf timing → never PASS; valgrind rc=99+0-findings → ERROR (not false-clean); regex/seed validated at load |
| Phase 0 | `fa13662` | 3 neighbour-found correctness bugs + adversarial 5 | sentinel must match the harness **name** (F5); asm-scan partial compile → surfaced not false-clean; timing harness sinks output (no optimizer-elided false PASS); `_proc` now catches the whole exec-failure family (incl. PermissionError) |
| Phase 1 | `6f16275` | `ctkat screen` + `verdict_class` as a tool artifact | one command runs build→KAT→ct→ct-matrix→asm-scan→dudect→triage→`verdict_class`; taxonomy extracted to `ctkat/verdict_class.py` (shared with the corpus script, can't drift); `triage.yaml` machine-readable triage; default-deny exit codes |
| Phase 2 | `4ed349a`, `13af63e` | paper tables auto-generated from the corpus + drift-failing test | `scripts/render_paper_tables.py` → `paper/generated/*.tex` + macros; `tests/test_paper_corpus_sync.py` fails CI if any paper number ≠ corpus CSV; `build_paper_pdf.sh` (tectonic-verified compile); pytest-count + Docker-provenance overclaims removed |
| B4 / B5 | `8706e38` | measurement-semantics: pooled dudect cropping + KEM FO caption | `welch_with_cropping` now crops at a single **pooled** threshold (dudect/Reparaz protocol fidelity — honest caveat: NOT a sensitivity gain, but never loses a strong leak); KEM ct verdict + paper now state Valgrind covers only the valid-ct path, FO/rejection is dudect `leak_target: fo` |

State: **466 pytest pass / 3 skipped**, paper compiles (tectonic), 12 example
yamls load, corpus 7 rows / 5 verdict classes unchanged (frozen artifacts intact).

## Recurring failure modes (what the reviews kept catching)

These are the anti-patterns that bit repeatedly — check them on every change:

1. **Fail-open / false-clean** — an internal failure reading as PASS/CLEAN/exit-0
   (NaN→PASS, rc=99→PASS, partial asm→clean, screen exit-0 on dudect FAIL). A
   security tool must fail **closed**.
2. **Illusory coverage** — adding a check you can't validate (B5 structural FO
   coverage with no valgrind here) is worse than an honest caption.
3. **Comment ≠ code / wrong justification** — the B4 first cut claimed pooled was
   *more* sensitive; it is the opposite. Keep the code if right for another
   reason, but never ship a false rationale.
4. **Fix-at-some-sites-not-others (§7)** — `_proc` caught FileNotFoundError but
   not PermissionError; the sync test guarded one section not all.
5. **Drift between layers** — paper ↔ CSV, generator ↔ corpus script, tool ↔ docs.
   Single-source it and add a test that fails on drift.

## What's still open (prioritised)

### Phase 3 — triage-quality, paper-aligned (recommended next)
- **asm-scan provenance** — link a varlat division candidate to its source
  function and known secret-tainted-region/context, emitting evidence
  (`function`, `source`, `triage hint`, `default: untriaged`) so a human triages
  faster. Framed as *triage-quality*, not a new detector — fits the paper's
  "honest integration" message. (`ctkat/asm_scan.py`, the varlat artifact.)
- **Stale report / artifact cleanup** — sweep `examples/*/reports/` gitignore
  consistency and any leftover non-regenerated docs.
- **Corpus → paper promotion adapter** (optional) — a thin script turning
  `screen_summary.csv` into corpus rows (add family/target/arch/commit), so
  `ctkat screen` output can feed the curated corpus directly.

### C-tier robustness (deferred from the audits; do when touched)
- **header_parser** — parses functions inside `#if 0` / `#ifdef UNDEF` blocks and
  multi-line `\`-continued `#define` bodies as live decls (phantom signatures).
- **valgrind_parser** — ignores `==PID==` (interleaved/threaded output
  misattributes frames); a location-less top frame is dropped → CSV mislocates
  the finding to the 2nd frame.
- **harness_generator** — compiled binary written non-atomically at a fixed path
  (concurrent/CI runs can race); seed not in the binary filename.
- **dudect_runner / valgrind log** — full log/stdout read into memory unbounded
  (10M-measurement run can OOM the parent).
- **config validation gaps** — `sources`/`include_dirs` not `..`/abs-path guarded
  (header is); `DudectCompilerConfig.cc` unvalidated (MatrixConfig.compilers is);
  `BufferSpec.size` accepts `' '`/`'0'`/`'-1'`.
- **`ctkat dudect` standalone** ignores `dudect.enabled: false` (product call).

### Deferred review findings (acknowledged, low/medium, errs-safe)
- **Phase 1**: screen asm vindex keyed by `(cc,opt)` (cross-harness attribution —
  over-flags, safe); a matrix-cell-only ERROR still classifies `robust` (it's the
  shared classifier's `only-minus-ERROR` rule — changing it changes the corpus).
- **B4**: optionally keep the per-class max-|t| as a diagnostic field so the
  fidelity-vs-sensitivity tradeoff is visible, not just documented.
- **B5**: real **structural** FO-path coverage (a tainted dec on an invalid ct
  under Valgrind) — only do this in a Docker/valgrind session where it can be
  *validated* (else it's illusory coverage). The caption + dudect `fo` mode cover
  it honestly for now.

### Paper / methodology (from `go_forward.md`, not blocking)
- Resolve ML-DSA `needs-analysis` rigorously (`-fno-inline` attribution + triage
  `pack_sig`); see `accepted_variable_time.md` Limitations.
- Corpus breadth (another ML-DSA size, Falcon, SPHINCS+, table-AES, ct-memcmp) —
  diminishing return for the report's argument.
- Phase E (patched Valgrind) — only if div-candidate triage volume becomes
  unmanageable (it has not).

## How to verify the current state

```bash
python3 -m pytest -q                          # full suite (466 pass / 3 skip)
bash scripts/reproduce_paper_tables.sh        # CSV → paper tables + drift test
bash scripts/build_paper_pdf.sh               # compile the 12p PDF (pdflatex/tectonic)
python3 -m ctkat screen --config examples/pqc_mlkem768/ctkat.yaml   # needs Linux/Docker (valgrind)
```

## Related docs
- `go_forward.md` — paper/report angle + per-feature single-coverage lens.
- `corpus_schema.md` — corpus CSV schema + `verdict_class` taxonomy.
- `known_issues.md` — the older 11-regression catalogue that produced `CLAUDE.md`.
- `accepted_variable_time.md` — the cited registry behind `accepted-variable-time`.
