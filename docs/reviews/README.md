# Review artifacts

Evidence schema v2 does not treat a free-text note as proof that a human
judgment was completed. A corpus row with `review=reviewed|disputed|expired`
must name `review_id`, and that ID must resolve to a YAML file in this
directory whose `scope` includes the row's `(target, harness)`.

These records preserve the existing source-review decisions during the v1.2 to
v2.0 migration. They do **not** claim two independent reviewers. The
superseded v5 paper gate required a later two-person declassification pass.

Those optional/legacy review packets remain explicit under `paper/`. Run
`python scripts/check_paper_reviews.py` for schema/static validation. The
committed packets honestly remain `pending`; `--require-pre-measurement` and
`--require-complete` exit non-zero until at least two unique reviewers,
independent from the artifact author, record a quorum decision. Partial
sign-offs are not committed as if they were complete.

The post-measurement `native-promotion-v2` packet additionally binds
`final_evidence_root_sha256`. Generate that value with the artifact
`verification` profile before review. The value is part of the canonical review
contract, so changing it invalidates every reviewer's
`evidence_manifest_sha256`. The `paper-ready` profile supplies the candidate
root back to this checker and fails unless the completed human packet approved
the exact same digest. Automated agents cannot populate reviewer entries.

The current v7 single-host profile does not use these packets as a measurement
execution or host-scoped result-table gate. Their pending state means that v6
makes no independent-review, declassification, or inter-rater-agreement claim.
They may be completed later as follow-up validation; they must never be forged
merely to turn the old v5 checker green.

Superseded records retained only to explain frozen archive rows live under
`archive/`; the current corpus validator intentionally loads only top-level
review files.
