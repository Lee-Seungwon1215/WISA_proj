# Premeasurement paper tables (generated)

Do not edit by hand; run `python3 scripts/build_paper_artifacts.py --write`.

## Corpus state

The committed screening corpus contains 25 target/harness pairs: 6 risk-detected, 5 needs-review, 10 inconclusive, and 4 no-finding-observed. Correctness is not run for 4 pairs; these cannot fold to clean.

## Native campaign readiness

| Component | Targets | Axes | Rows/host | Status |
|---|---:|---:|---:|---|
| committed-corpus-refresh | 6 | 8 | 2220000 | prepared-not-measured |
| kyberslash-contrast | 10 | 10 | 3300000 | prepared-not-measured |
| falcon-contrast | 6 | 6 | 1530000 | prepared-not-measured |
| diverse-lineages | 4 | 4 | 1170000 | prepared-not-measured |

Final timing requires 2 physical hosts; the frozen plan contains 28 component-axis executions and 16440000 protocol rows across both hosts.

## Independent review readiness

Packets: 8; premeasurement ready: false; paper ready: false. Pending is an honest blocker, not a failed test.

## Claim readiness

| Claim | Status | Evidence items | Open gates |
|---|---|---:|---:|
| fail-closed-evidence-fold | implemented-premeasurement | 4 | 0 |
| build-matrix-sensitivity | implemented-premeasurement | 2 | 0 |
| kyberslash-attribution | pending-independent-review | 4 | 2 |
| falcon-comparator | pending-independent-review | 4 | 3 |
| diverse-upstream-builds | implemented-premeasurement | 3 | 2 |
| native-timing-results | pending-physical-measurement | 9 | 4 |
