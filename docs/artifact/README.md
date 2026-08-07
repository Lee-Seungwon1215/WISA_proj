# Reproducible artifact profiles

The dependency graph is locked in `uv.lock`. `requirements/runtime.lock` and
`requirements/artifact.lock` are hash-locked exports for environments that use
pip. Regenerate all three with the exact commands recorded in the generated
`requirements/README.md` and verify them in CI with uv 0.11.17.

For a fresh paper-artifact environment:

```bash
uv sync --frozen --extra dev
uv run ./scripts/reproduce_artifact.sh \
  --profile premeasurement \
  --output-root artifact_runs/premeasurement
```

The command runs the full tests, recompiles and verifies all nine deterministic
API-roundtrip correctness snapshots, and executes every corpus, provenance,
campaign, review, ablation, and generated-table static gate. It writes the
complete command stdout/stderr, tracked-file hashes, commit/worktree metadata,
and `SHA256SUMS`. It requires a clean worktree; `--allow-dirty` exists only for
development and is recorded in the output.

This preparation profile deliberately succeeds when well-formed review packets
are still pending, while recording `pre_measurement_ready=false`. After six
packets have real two-person sign-off, the execution gate must pass before any
physical run:

```bash
uv run ./scripts/reproduce_artifact.sh \
  --profile measurement-ready \
  --output-root artifact_runs/measurement-ready
```

`measurement-ready` reruns the preparation profile and then fails closed unless
all premeasurement packets have the required independent-review quorum.

Final two-host evidence uses a filled copy of
`measurement_bundle_template.yaml`:

```bash
uv run ./scripts/reproduce_artifact.sh \
  --profile final \
  --bundle /path/to/bundle/measurement_bundle.yaml \
  --output-root artifact_runs/final
```

The final profile reruns all premeasurement gates, verifies two distinct
physical non-virtualized CPU models, validates every component campaign and
same-corpus result, requires the blind-unblinding record, and finally requires
all two-person review packets. It does not promote results into the curated
corpus.

Before and after transfer, hash a raw evidence tree without following symlinks:

```bash
python scripts/hash_artifacts.py /path/to/tree \
  --write /path/to/tree/SHA256SUMS
python scripts/hash_artifacts.py /path/to/tree \
  --check /path/to/tree/SHA256SUMS
```

Follow `BLIND_RERUN_CHECKLIST.md`; retain unchecked items as limitations rather
than silently treating them as satisfied.

The Docker base filesystem is digest-pinned, but Ubuntu apt repository metadata
and package versions are not an archival snapshot. Preserve the successfully
built image digest (or an OCI archive) with a final paper artifact instead of
claiming that a future network rebuild is bit-for-bit reproducible.
