# WISA paper outline (12-page LNCS, poster track)

> Companion to `docs/report_tables.md` (the two headline tables) and
> `docs/go_forward.md` §4.4 framing. This doc fixes the **structure, page budget,
> and argument spine** so the write-up is a fill-in, not a blank page.

## Positioning — the honest one-liner

> **Build-Configuration-Aware, Triage-Aware Constant-Time Screening for PQC** — a
> fail-closed framework binding Valgrind / asm-scan / dudect under one config,
> indexed by compiler × optimization, with a default-deny triage taxonomy and a
> cited accepted-variable-time registry; validated on a real PQC corpus.

**Novelty is modest and we say so.** The individual phenomena are known
(KyberSlash = variable-time division; build-sensitivity of CT; dudect timing).
The contribution is the **integration + methodology + its self-validation**:
the tool's default-deny taxonomy *caught an over-claim on real ML-DSA-65* and
surfaced that finding-attribution is build-dependent (inlining). The spine of the
paper is **"the tool kept the human honest"** — a stronger, more honest story than
"everything passed clean."

This framing fits WISA (applied security, real systems) and survives reviewer
scrutiny precisely because it does not over-claim novelty.

## Argument spine (one sentence per beat)

1. Structural CT checking (Valgrind/Memcheck) alone is **insufficient for PQC** —
   KyberSlash passes it clean yet leaks (T1 row 2).
2. The verdict is **not stable** — it flips with build config (T1 row 3).
3. So you need **multiple layers under one config, indexed by compiler×opt** —
   that's the framework.
4. But more checks → more FAILs → temptation to **over-claim leaks**. A real
   ML-DSA ct-FAIL is *not* obviously a key-recovery leak.
5. So the framework is **fail-closed / default-deny**: it never auto-declares a
   leak; it triages against a cited registry and otherwise says `needs-analysis`.
6. Evidence: a real PQC corpus where **every layer pulls its weight (T1)** and
   **every verdict class is grounded (T2)** — including the over-claim it refused
   to make.

## Page budget (12 pp LNCS)

| § | section | pp | content |
|---|---|---|---|
| 1 | Introduction | 1.5 | PQC deployment + CT side-channels; KyberSlash as the hook; the over-claim risk; contributions list (3 bullets). |
| 2 | Background & related | 1.5 | CT verification landscape (dudect, ctgrind/Valgrind-Memcheck, ct-verif/binsec); KyberSlash; what's missing = **integration + triage discipline**. Keep tight, cite generously. |
| 3 | Framework design | 2.5 | The 3 layers (Valgrind / asm-scan / dudect) under one yaml config; compiler×cflags **matrix**; the **triage-aware taxonomy** + **default-deny**; the cited `accepted_variable_time.md` registry. **Fig 1 = pipeline diagram.** |
| 4 | Corpus & method | 1.0 | Committed corpus CSVs, per-cell compiler/version provenance, PQClean targets + synthetic controls; reproducibility workflow. |
| 5 | Results | 3.0 | **T1 (single-coverage) and T2 (verdict-class) — the two headline tables.** Walk each T1 row; foreground KyberSlash (ct PASS/asm FAIL) and ML-DSA (default-deny). **A1 dudect** as inset. |
| 6 | Discussion: self-validation | 1.0 | The ML-DSA over-claim story; build-dependent attribution (inlining); honest limitations (QEMU TSC noise → confirm native; synthetic controls; corpus breadth). |
| 7 | Conclusion | 0.5 | Restate: layer-justified in this corpus (T1) + validated on concrete targets (T2) + honest (default-deny). |
| — | References | 0.5 | LNCS bib. |

Poster track ⇒ **the two tables + Fig 1 pipeline are the visual payload.** If
space is tight, §2 and §4 compress first; never compress §5/§6 (the contribution).

## Figures (camera-ready list)

- **Fig 1** — pipeline diagram: yaml config → {build matrix → Valgrind, asm-scan,
  dudect} → triage taxonomy (default-deny) → verdict_class. *(needs drawing.)*
- **Table 1 (T1)** — per-feature single-coverage. ✅ ready (`report_tables.md`).
- **Table 2 (T2)** — verdict-class corpus, 7 rows. ✅ ready.
- **Table 3 (A1)** — dudect appendix, 2 rows. ✅ ready.

## What's done vs what's left

**Done (evidence is airtight):** all 5 feature single-coverage cases captured;
corpus 7 rows / 5 classes; dudect appendix; pytest count comes from the current
artifact run, not a copied paper number.

**Left (write-up only, no new experiments needed):**
1. Draw **Fig 1** (pipeline).
2. Prose for §1–§7 (tables drop in as-is).
3. Bib (LNCS `splncs04.bst`): cite KyberSlash, dudect, ctgrind/Memcheck-CT,
   ct-verif/Binsec, FIPS 203/204, PQClean.

**Optional, do NOT block submission:** ML-DSA `-fno-inline` precise attribution;
native dudect confirmation; dudect (b) one-table merge; corpus breadth
(Falcon/SPHINCS+); structural FO-path Valgrind only if it can be validated. All
are secondary to clearing the 12-page / author / reference blockers.

## Recommended next action

Start prose at **§5 Results** (tables already exist, lowest friction, anchors the
rest), then §3 Design, then §1/§2/§6/§7. Draw Fig 1 in parallel. The paper is a
**fill-in around finished evidence**, not new research.
