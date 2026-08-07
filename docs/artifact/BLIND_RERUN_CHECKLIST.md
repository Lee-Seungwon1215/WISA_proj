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
- [ ] Run `./scripts/reproduce_artifact.sh --profile measurement-ready` on the
      frozen commit on both machines.
- [ ] Run the pilot in a separate directory. Do not copy pilot traces into the
      final bundle.

## Final execution

- [ ] Host A operator has not seen Host B results; Host B operator has not seen
      Host A results.
- [ ] Execute every component command printed by
      `python3 scripts/check_paper_campaign.py` with the same frozen commit.
- [ ] Use a dedicated output root and never `--resume` a pilot as a final run.
- [ ] Preserve stderr/stdout, preflight JSON, raw/control/protocol CSVs, backend
      report, corpus update candidate, and hashes even when a target fails.
- [ ] Run the same-corpus official-dudect baseline on each host.
- [ ] Do not rerun or exclude an unexpected result except for a preregistered,
      machine-recorded invalidation reason.

## Transfer and unblinding

- [ ] Transfer bundles read-only and compute SHA-256 manifests on both sending
      and receiving sides with `scripts/hash_artifacts.py`.
- [ ] Fill a copy of `measurement_bundle_template.yaml` with paths relative to
      its own directory; do not use symlinks or absolute paths.
- [ ] Validate every native component artifact before unblinding.
- [ ] Record the label key, time, people present, and both pre-transfer hash
      manifests in `UNBLINDING.md`.
- [ ] Run `./scripts/reproduce_artifact.sh --profile final --bundle BUNDLE.yaml`.
- [ ] Complete the two-person postmeasurement promotion packet. Only a separate
      reviewed commit may update the curated corpus.

Any unchecked item remains an explicit limitation in the paper artifact.
