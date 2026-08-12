# CT-KAT docs map

This directory keeps project-facing documentation for running, extending, and
reproducing CT-KAT. Superseded scratchpads remain local-only.

## Current source of truth

- `../README.md` — user-facing overview, CLI usage, examples, limitations.
- `accepted_variable_time.md` — legacy-class bridge for reviewed CT findings.
- `corpus_schema.md` — evidence schema v2, overall fold, and corpus CSV contract.
- `reviews/` — stable human-review artifacts referenced by `review_id`.
- `tutorial.md` — quick usage guide.
- `calibration/` — pinned official-dudect backend synthetic A/A, injected
  effect curve, and same-trace parity artifact.
- `measurement/` — frozen paper-native-v8 single-host campaign, bare-metal preflight,
  resumable execution, artifact validation, and corpus-promotion boundary.
- `paper/` — premeasurement outline, claim/evidence matrix, and generated
  corpus/ablation/campaign/review readiness tables.
- `artifact/` — current single-host bundle/template plus preserved two-host
  profiles, hashes, and blind-rerun checklist.
- `baselines/` — same-source/input official dudect, patched TIMECOP, and
  MicroWalk PinTracer adapters, complete capability matrix, and common result
  schema.
- `ground_truth/kyberslash/` — frozen KS1/KS2/combined/historical sources,
  exact diffs, provenance, deterministic KEM equivalence, and TIMECOP evidence
  boundaries.
- `corpus/` — committed v2 corpus, deterministic correctness snapshot,
  migration manifest, frozen v1.2 archive, and independent-upstream expansion
  contract.
- `ROADMAP_REJECTION_RECOVERY.md` — rejection-review adjudication and the
  dependency-ordered completion plan, including the KyberSlash and Falcon
  workstreams.

## Local-only archive

Old audit ledgers, original design prompts, KyberSlash brainstorming notes,
agent prompting guides, and superseded drafts are intentionally excluded from
git under `.local_archive/` or the repository-root `/paper/`. They are useful
history, but not source of truth for current behavior. The tracked `docs/paper/`
tree is the current premeasurement paper source of truth.
