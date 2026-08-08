# Blind two-host rerun checklist

Use this after the premeasurement commit is frozen and before either final host
result is interpreted. A checked box is an operational record, not a substitute
for the machine-readable host report.

## Before execution

- [ ] Freeze one 40-character CT-KAT commit and verify a clean worktree.
- [ ] Complete all six premeasurement review packets with two independent
      reviewers; do not enter partial sign-offs into committed packets.
- [ ] Assign neutral labels to target directories and keep the label key from
      both host operators.
- [ ] Choose two physical Linux x86_64 machines with different exact CPU model
      strings; record firmware, kernel, compiler, governor, SMT, and affinity.
- [ ] Run `uv run --frozen ./scripts/reproduce_artifact.sh --profile
      measurement-ready` on the frozen commit on both machines.
- [ ] Run the pilot in a separate directory. Do not copy pilot traces into the
      final bundle.

## Final execution

- [ ] Host A operator has not seen Host B results; Host B operator has not seen
      Host A results.
- [ ] On each host, render all four component and three same-corpus commands with
      `uv run --frozen python scripts/check_paper_campaign.py --print-commands
      --host-id HOST-LABEL --cpu LOGICAL-CPU --timecop-prefix
      /absolute/exact-patched-valgrind-prefix`. Verify that the output contains
      exactly seven commands and no `host-ID`, `CPU-ID`, or `TIMECOP-PREFIX`, then
      execute every printed command from the same frozen commit.
- [ ] Use a dedicated output root and never `--resume` a pilot as a final run.
- [ ] Preserve stderr/stdout, preflight JSON, raw/control/protocol CSVs, backend
      report, corpus update candidate, and hashes even when a target fails.
- [ ] Confirm the printed same-corpus commands completed official dudect,
      exact-prefix TIMECOP, and MicroWalk on each host; all three reports are
      mandatory even though only official dudect is physical timing evidence.
- [ ] Do not rerun or exclude an unexpected result except for a preregistered,
      machine-recorded invalidation reason.

## Transfer and unblinding

- [ ] Transfer bundles read-only and compute SHA-256 manifests on both sending
      and receiving sides with `scripts/hash_artifacts.py`.
- [ ] Fill a copy of `measurement_bundle_template.yaml` with paths relative to
      its own directory; do not use symlinks or absolute paths.
- [ ] Validate every native component artifact before unblinding.
- [ ] Record the label key, time, people present, blinded-analysis manifest
      hash, and both pre-transfer hash manifests in the structured unblinding
      record.
- [ ] Run `uv run --frozen ./scripts/reproduce_artifact.sh --profile verification --bundle
      BUNDLE.yaml --output-root CANDIDATE_ROOT`.
- [ ] Copy the candidate's `final_evidence_root_sha256` into
      `native-promotion-v2.yaml`, keep reviewers empty, and commit that sole
      file as clean review-contract commit R0.
- [ ] Have two independent humans review that exact root and R0 packet, record
      `reviewed_commit: R0`, then commit the complete packet as R1; after
      candidate verification,
      `docs/reviews/paper/native-promotion-v2.yaml` must be the sole changed
      file.
- [ ] Run `uv run --frozen ./scripts/reproduce_artifact.sh --profile paper-ready --bundle
      BUNDLE.yaml --candidate-root CANDIDATE_ROOT`. Only a later, separately
      authorized change may update the curated corpus.

Any unchecked item remains an explicit limitation in the paper artifact.
