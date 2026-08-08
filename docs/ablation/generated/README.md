# Evidence ablation (generated)

Do not edit by hand; run `python3 scripts/run_ablation.py --write`.

| Stage | Status | Cells | Pairs | CT findings | Build-sensitive | ASM candidates | Candidate pairs | Final risk | Needs review | Inconclusive |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| single-release-build | complete | 24 | 24 | 11 | 0 | 0 | 11 |  |  |  |
| full-build-matrix | complete | 206 | 24 | 13 | 2 | 0 | 13 |  |  |  |
| full-matrix-plus-asm | complete | 206 | 24 | 13 | 2 | 16 | 22 |  |  |  |
| reviewed-evidence-fold | complete | 206 | 25 | 13 | 2 | 16 |  | 6 | 5 | 10 |
| official-versus-legacy-timing | pending-physical-native-measurement |  |  |  |  |  |  |  |  |  |

- The first three stages quantify candidate-generation burden, not tool accuracy.
- The reviewed fold is the only stage that reports final evidence states.
- The native timing ablation is missing by design and is represented as pending, never zero.
