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
and `SHA256SUMS`. Every profile requires a clean committed worktree so the
source manifest and automated-audit provenance cannot diverge.

## Current v10 single-host result profile

The current paper campaign is `paper_native_campaign_v10.yaml`. It supersedes
the two-host/reviewer execution gate below without deleting that stronger
historical workflow. First obtain two blocker-free V3 operational control rehearsals from
the exact candidate commit and create
`measurement_runs/host-a/v10-control-qualification.json` as documented in
`../measurement/PAPER_CONTROL_REHEARSAL_V3.md`. The qualification does not turn
the two same-seed rehearsals into independent inferential replicates. Then render the seven commands
for the one available host:

```bash
uv run --frozen python scripts/check_paper_campaign.py \
  --print-commands \
  --host-id host-a \
  --cpu 2 \
  --timecop-prefix /home/test/.local/ctkat/timecop \
  --control-qualification /home/test/ctkat-native/measurement_runs/host-a/v10-control-qualification.json
```

Every rendered final command carries `--final-gate single-host` and the same
qualification path. The runner reopens the qualification and both hashed source
reports before sampling. After all four components, three baseline tools, and
ML-KEM assembly evidence complete, hash the one host tree and build the
schema-v5 bundle without hand-editing paths:

```bash
uv run --frozen python scripts/build_single_host_measurement_bundle.py \
  --host-root measurement_runs/host-a \
  --host-id host-a \
  --output measurement_runs/measurement_bundle.yaml \
  --analysis-output measurement_runs/analysis/named
```

The layout contract is also documented in
`measurement_bundle_single_host_template.yaml`. Run the deterministic named
analysis fixed in `PAPER_NATIVE_ANALYSIS_V2.md`:

```bash
uv run --frozen python scripts/analyze_paper_native_results.py \
  --bundle /path/to/measurement_bundle.yaml \
  --verification-commit MEASUREMENT-COMMIT \
  --output-mode named \
  --output-root /path/to/analysis/named
```

The v10 bundle and output are paper-usable only as single-host evidence. They do
not claim host replication, analyst blinding, independent human review, or
automatic curated-corpus declassification.

## Superseded v5 two-host/reviewer profile

This preparation profile deliberately succeeds when well-formed review packets
are still pending, while recording `pre_measurement_ready=false`. After six
packets have real two-person sign-off, the execution gate must pass before any
physical run:

```bash
uv run ./scripts/reproduce_artifact.sh \
  --profile measurement-ready \
  --output-root artifact_runs/measurement-ready
```

`measurement-ready` reruns the engineering checks and timing-backend
calibration, then fails closed unless all premeasurement packets have the
required independent-review quorum.

On each final host, render the complete frozen execution matrix only after
choosing the host label, pinned logical CPU, and absolute exact-patched TIMECOP
prefix:

```bash
uv run --frozen python scripts/check_paper_campaign.py \
  --print-commands \
  --host-id host-a \
  --cpu 2 \
  --timecop-prefix /opt/ctkat/valgrind-3.22.0-timecop
```

The command validates the campaign first and then prints exactly seven
placeholder-free, hash-locked commands: four native components followed by
official dudect, TIMECOP, and MicroWalk. Repeat with the other host label and
CPU. Execute every printed line; none of the three same-corpus tools is optional.

Final two-host evidence uses a filled copy of
`measurement_bundle_template.yaml`. First create a review candidate; this stage
does not require or fabricate the post-measurement approval:

```bash
uv run ./scripts/reproduce_artifact.sh \
  --profile verification \
  --bundle /path/to/bundle/measurement_bundle.yaml \
  --output-root artifact_runs/verification-candidate
```

`verification` reruns the measurement-ready gates, verifies two distinct
physical non-virtualized CPU models, validates every component, same-corpus,
assembly, and blind/unblinding artifact, and emits deterministic named results.
It then writes `final_evidence_manifest.json`. Its canonical root binds the
measurement bundle, both host `SHA256SUMS` files, the unblinding record, the
assembly bundle, and the exact blinded and named output file sets. Machine-local
paths and wall-clock time are not inputs to that root. The output contract is
documented by `final-evidence-root-v1.schema.json`.

Copy `final_evidence_root_sha256` from that manifest into only
`docs/reviews/paper/native-promotion-v2.yaml` and commit that pending packet as
review-contract commit R0. Two independent humans review the candidate and the
exact clean R0 packet, then record approval hashes calculated over that
contract. The packet keeps an empty reviewer list until the full quorum is
available. Each `reviewed_commit` names R0; the later R1 commit contains only
the completed packet and avoids a self-referential signature. Then run:

```bash
uv run ./scripts/reproduce_artifact.sh \
  --profile paper-ready \
  --bundle /path/to/bundle/measurement_bundle.yaml \
  --candidate-root artifact_runs/verification-candidate \
  --output-root artifact_runs/paper-ready
```

`paper-ready` recomputes the canonical root, regenerates both blinded and named
analysis in check mode, and requires the post-measurement reviewers to have
approved that same root. The review commit may descend from the candidate's
verification commit only when `docs/reviews/paper/native-promotion-v2.yaml` is
the sole changed file. The legacy
`final` profile name is an alias for `paper-ready`. Neither stage promotes
results into the curated corpus.

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
