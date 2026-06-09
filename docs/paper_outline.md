# WISA paper outline (12-page LNCS, poster track)

> Companion to `docs/report_tables.md` (the headline/support tables) and
> `docs/go_forward.md` §4.4 framing. This doc fixes the **structure, page budget,
> and argument structure** so the write-up is a fill-in, not a blank page.

## Positioning — the honest one-liner

> **Build-Configuration-Aware, Triage-Aware Constant-Time Screening for PQC** — a
> fail-closed framework binding Valgrind / asm-scan / dudect under one config,
> indexed by compiler × optimization, with a registry-backed triage policy and a
> cited accepted-variable-time registry; grounded in real PQC cases plus synthetic
> positive controls.

**Novelty is modest and we say so.** The individual phenomena are known
(KyberSlash = variable-time division; build-sensitivity of CT; dudect timing).
The contribution is the **workflow + methodology**: one configuration drives
multiple candidate sources, records compiler/optimization provenance, and uses a
registry-backed triage policy to stop at `needs-analysis` when attribution is too
coarse. ML-DSA is best framed as this conservative stop condition, not as a leak
claim.

This framing fits WISA (applied security, real systems) and survives reviewer
scrutiny precisely because it does not over-claim novelty.

## Argument structure (one sentence per beat)

1. Structural CT checking (Valgrind/Memcheck) alone is **insufficient for PQC** —
   KyberSlash passes it clean yet leaks (coverage table row 2).
2. The verdict is **not stable** — it flips with build config (coverage table row 3).
3. So you need **multiple layers under one config, indexed by compiler×opt** —
   that's the framework.
4. But more checks → more FAILs → temptation to **over-claim leaks**. A real
   ML-DSA ct-FAIL is *not* obviously a key-recovery leak.
5. So the framework is **fail-closed / default-deny**: it never auto-declares a
   leak; it triages against a cited registry and otherwise says `needs-analysis`.
6. Evidence: real PQC cases plus synthetic positive controls where each layer
   contributes evidence, every verdict class is grounded, and ML-DSA shows the
   `needs-analysis` stop condition.

## Page budget (12 pp LNCS)

| § | section | pp | content |
|---|---|---|---|
| 1 | Introduction | 1.5 | PQC deployment + CT side-channels; KyberSlash as the hook; the over-claim risk; contributions list (3 bullets). |
| 2 | Background & related | 1.5 | CT verification landscape (dudect, ctgrind/Valgrind-Memcheck, ct-verif/binsec); KyberSlash; what's missing = **integration + triage discipline**. Keep tight, cite generously. |
| 3 | Framework design | 2.5 | The 3 candidate sources (Valgrind / asm-scan / dudect) under one yaml config; compiler×cflags **matrix**; the **registry-backed triage policy** + **default-deny**; the cited `accepted_variable_time.md` registry. **Fig 1 = pipeline diagram.** |
| 4 | Corpus & method | 1.0 | Committed corpus CSVs, per-cell compiler/version provenance, PQClean targets + synthetic controls; reproducibility workflow. |
| 5 | Results | 3.0 | **Coverage + verdict corpus are the headline tables.** Walk coverage rows; foreground KyberSlash (ct PASS/asm candidate) and ML-DSA (`needs-analysis`). Use ML-DSA attribution and dudect as support. |
| 6 | Discussion: triage stress test | 1.0 | ML-DSA attribution ambiguity; build-dependent attribution (inlining); honest limitations (QEMU TSC noise → confirm native; synthetic controls; corpus breadth). |
| 7 | Conclusion | 0.5 | Restate: reproducible build-indexed screening + conservative triage + concrete corpus grounding. |
| — | References | 0.5 | LNCS bib. |

Poster track ⇒ **the tables + Fig 1 pipeline are the visual payload.** If
space is tight, §2 and §4 compress first; never compress §5/§6 (the contribution).

## Figures (camera-ready list)

- **Fig 1** — pipeline diagram: yaml config -> {build matrix -> Valgrind,
  asm-scan, dudect} -> triage policy (default-deny) -> verdict_class. ✅ present;
  polish only if print output looks cramped.
- **Table 1** — per-feature evidence map. ✅ ready.
- **Table 2** — verdict-class corpus, 7 rows. ✅ ready.
- **Table 3** — generated ML-DSA attribution split. ✅ ready.
- **Table 4** — dudect appendix, 2 rows. ✅ ready.
- **Support artifact** — generated ablation/miss rows. ✅ drift-tested, not a
  main-paper float.

## What's done vs what's left

**Done:** all 5 feature evidence cases captured; corpus 7 rows / 5 classes;
ablation support; ML-DSA attribution split; dudect
appendix; pytest count comes from the current artifact run, not a copied paper
number.

**Left before camera-ready:**
1. Replace placeholder author / ORCID / affiliation.
2. Do the final human eyeball pass over the source-checked bibliography.
3. Keep the PDF under 12 pages after author metadata edits.

**Optional, do NOT block submission:** ML-DSA `-fno-inline` precise attribution;
native dudect confirmation; dudect (b) one-table merge; corpus breadth
(Falcon/SPHINCS+); structural FO-path Valgrind only if it can be validated. All
are secondary to clearing the author metadata blocker and keeping the PDF under
12 pages.

## Recommended next action

Handle author metadata, rebuild, then do one final PDF glance. The paper is now a
**polish around finished evidence**, not new research.
