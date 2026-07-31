# CT-KAT docs map

This directory keeps project-facing documentation for running and extending
CT-KAT. Planning notes, paper drafts, and review scratchpads are local-only.

## Current source of truth

- `../README.md` — user-facing overview, CLI usage, examples, limitations.
- `accepted_variable_time.md` — legacy-class bridge for reviewed CT findings.
- `corpus_schema.md` — evidence schema v2, overall fold, and corpus CSV contract.
- `reviews/` — stable human-review artifacts referenced by `review_id`.
- `tutorial.md` — quick usage guide.
- `calibration/` — pinned official-dudect backend synthetic A/A, injected
  effect curve, and same-trace parity artifact.
- `measurement/` — frozen native timing-v2 campaign, bare-metal preflight,
  resumable execution, artifact validation, and corpus-promotion boundary.
- `baselines/` — same-source/input official dudect, patched TIMECOP, and
  MicroWalk PinTracer adapters, complete capability matrix, and common result
  schema.
- `ground_truth/kyberslash/` — frozen KS1/KS2/combined/historical sources,
  exact diffs, provenance, deterministic KEM equivalence, and TIMECOP evidence
  boundaries.
- `corpus/` — committed v2 corpus, migration manifest, frozen v1.2 archive,
  and independent-upstream expansion contract.
- `ROADMAP_REJECTION_RECOVERY.md` — rejection-review adjudication and the
  dependency-ordered completion plan, including the KyberSlash and Falcon
  workstreams.

## Local-only archive

Old audit ledgers, original design prompts, KyberSlash brainstorming notes,
agent prompting guides, forward plans, and paper material are intentionally
excluded from git under `.local_archive/` or `paper/`. They are useful history,
but not source of truth for current behavior.
