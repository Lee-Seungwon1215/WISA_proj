# Review artifacts

Evidence schema v2 does not treat a free-text note as proof that a human
judgment was completed. A corpus row with `review=reviewed|disputed|expired`
must name `review_id`, and that ID must resolve to a YAML file in this
directory whose `scope` includes the row's `(target, harness)`.

These records preserve the existing source-review decisions during the v1.2 to
v2.0 migration. They do **not** claim two independent reviewers. The
paper-submission gate still requires a later two-person declassification pass.

That paper gate is now explicit under `paper/`. Run
`python scripts/check_paper_reviews.py` for schema/static validation. The
committed packets honestly remain `pending`; `--require-pre-measurement` and
`--require-complete` exit non-zero until at least two unique reviewers,
independent from the artifact author, record a quorum decision. Partial
sign-offs are not committed as if they were complete.

Superseded records retained only to explain frozen archive rows live under
`archive/`; the current corpus validator intentionally loads only top-level
review files.
