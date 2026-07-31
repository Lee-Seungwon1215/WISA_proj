# Changelog

All notable user-facing changes are recorded here. CT-KAT follows semantic
versioning while the public API is stabilizing.

## [0.7.0a1] - 2026-07-31

### Added

- Four exact-patch ML-KEM-768 KyberSlash ground-truth targets: stock,
  KyberSlash1-only, KyberSlash2-only, and KyberSlash1+2.
- A byte-identical historical `pq-crystals/kyber` reference snapshot from
  `a621b8d`, with fix-commit chronology, source hashes, license, and provenance.
- A deterministic full-KEM transcript test that requires all four modern
  variants to be byte-identical, plus a historical KEM smoke test.
- The IACR artifact's pinned Valgrind 3.22.0 TIMECOP patch, an opt-in Docker
  target, a backend canary, a lossless two-scope attribution report, and a CI
  artifact job.
- A distinct high-severity
  `SECRET_DEPENDENT_VARIABLE_LATENCY` finding type and harness support for the
  patched backend's client request.

### Changed

- The KyberSlash corpus now separates candidate assembly evidence, full-KEM
  secret-key-path dynamic taint, direct site-operand attribution, and physical
  timing instead of collapsing them into one risk label.
- Vendored-source inventory entries may now use an immutable artifact SHA-256
  instead of pretending every external artifact has a Git revision.
- The combined seeded control now restores all three KyberSlash sites,
  including the previously omitted KyberSlash2 `polyvec_compress` division.

### Fixed

- KS2 is no longer falsely required to appear in the full decapsulation
  undefinedness trace. The report records that taint is lost across the
  recovered-message/hash boundary and verifies KS2 with a separately labeled
  direct-operand scope.
- A normal Memcheck PASS can no longer be described as evidence against
  operand-dependent division latency.
- The historical snapshot's clang `-O1`/`-Os` compiler-induced
  `poly_frommsg` branch is preserved as separate structural evidence instead
  of being forced into the modern controls' negative expectation.

## [0.6.0a1] - 2026-07-30

### Added

- A frozen native-x86_64 timing campaign manifest covering all six corpus
  targets and all eight existing timing axes.
- A repository-specific campaign runner with static corpus/config checks,
  bare-metal preflight, explicit CPU pinning, resumable target execution, and
  engineering-only dirty/virtualized overrides that can never become
  promotion-ready.
- Independent validation of the five timing-harness-v2 artifacts, their
  hashes, official dudect revision, protocol roles/counts, seeded randomness,
  physical controls, and target validity.
- `campaign_report.json` and `corpus_timing_updates.csv` promotion candidates;
  the runner deliberately does not mutate the curated corpus.
- Unit-sized synthetic campaign fixtures so execution/validation logic is
  covered without pretending CI or emulation is physical timing evidence.

### Changed

- Paper-grade campaign settings now override modest example defaults at
  runtime: 30,000 target samples, 1,000 warmups, three process seeds,
  target-specific control counts/effect curves, gcc/RDTSCP, and extended
  expensive-target timeouts.
- The corpus builder now takes sample count, backend, and analysis seed from
  the runtime timing report before falling back to YAML defaults, and records
  `sign_leak_target` for signature axes. Official rows use the upstream
  `|t|>10; n0>=10001` contract instead of legacy warning/fail thresholds.
- Native campaign output is ignored by default until a human reviews a
  promotion candidate and its immutable artifacts.

### Fixed

- A native campaign run can no longer be published as the YAML's old 500–2,000
  sample default or legacy timing backend.
- A future signature `msg` timing row can no longer be mislabeled with the KEM
  `leak_target` default.
- Corpus timing coverage drift, a changed manifest, corrupt trace hash, wrong
  protocol row count, non-native host, unpinned process, or dirty checkout now
  fails before evidence promotion.

## [0.5.0a1] - 2026-07-30

### Added

- KEM/sign `timing-harness-v2` with pre-generated class pools, symmetric
  per-iteration copies, and same-address key/ciphertext/message work buffers.
- Three independent target process/seed repetitions plus physical A/A,
  setup-placebo, and three-point seeded positive-control traces from the same
  generated target binary.
- RDTSCP AUX capture and CPU-migration filtering, lossless drop reasons, real
  sample identifiers, and signature output lengths in raw artifacts.
- Target/run minimum-detectable-effect estimates, A/A false-alarm budget,
  observed positive-control power curve, and fail-closed control gates.
- Signature fixed-key/fixed-vs-random-message axis and an explicit full-API
  scope manifest that distinguishes variable-length encoding from a separate
  implementation-specific core harness.
- `dudect_protocol_timings.csv` and timing backend report schema v2 containing
  every target/control process trace, seed, effect, runtime randomness policy,
  and trace hash.

### Changed

- KEM/sign timing can now become `timing_validity=valid`, but only when the
  native host, trace integrity, three-repeat consistency, A/A budget,
  setup-placebo, positive-control power, and seeded randomness gates all pass.
- KEM `sk`, `ct`, and `fo` axes no longer keygen/encapsulate only one class
  inside the measurement loop; all cryptographic input generation happens
  before warmup.
- Signature timing no longer generates a fresh class-1 key in the measurement
  loop. Signing randomness, label generation, and pool selection use
  domain-separated deterministic PRNG streams.
- Physical control sample counts default to the target measurement count and
  can be raised independently with `dudect.timing_protocol.control_measurements`.

### Fixed

- On RDTSCP hosts, a sample whose AUX value changes across the target call can
  no longer enter a Welch/official dudect trace unnoticed.
- Monotonic-clock harnesses now expose the POSIX clock API before any system
  header and fall back cleanly where `CLOCK_MONOTONIC_RAW` is unavailable,
  including strict C99 Linux builds.
- Dropped timing rows are no longer renumbered away or omitted from the raw
  artifact.
- A class-dependent setup/cache artifact, label-only false alarm, or powerless
  host can no longer be promoted to a valid target timing conclusion.
- Falcon/other variable-length signature timing can no longer be silently
  described as core signing cost; per-sample output length and scope are
  explicit.

## [0.4.0a1] - 2026-07-30

### Added

- Exact-pinned official dudect C backend with all 102 upstream tests,
  minimum-measurement semantics, tau, and detection estimates.
- Independent calibration/analysis traces, a lossless backend JSON report,
  environment manifest, and appended summary/verdict validity fields.
- Domain-separated runtime seeds for calibration and analysis without
  recompiling the measured target.
- Deterministic backend-only synthetic A/A, injected-effect power curve, and
  same-trace uncropped parity calibration.
- Installed wheel/sdist smoke coverage for the vendored header and native adapter.

### Changed

- `official-dudect` is now the default timing backend; the previous Python
  five-cutoff implementation requires explicit `experimental-first-order`
  opt-in.
- KEM/sign timing remains fail-closed as `confounded`, generic timing remains
  `insufficient-power`, and QEMU or unpinned Linux timing is
  `environment-rejected` pending target-level controls.
- The misleading `bonferroni_correct` setting is migrated with a warning to
  `sqrt_m_threshold_scaling` and is rejected by the official backend.

### Fixed

- A backend raw PASS can no longer imply target-level timing validity.
- Official protocol parity can no longer be claimed by a name-only Python
  approximation; upstream source identity and adapter output are validated.
- Modern Docker Desktop `VirtualApple` x86 translation is rejected even when
  legacy QEMU DMI strings are absent.
- Missing or malformed rows and noisy discarded calibration traces now
  invalidate timing just as strictly as analysis-trace corruption.

## [0.3.0a1] - 2026-07-30

### Added

- Evidence schema v2 with typed correctness, structural, assembly, timing
  validity/signal, review, and five-state overall fields.
- Machine-readable JSON Schema and fail-closed overall recomputation.
- Stable review artifacts linked by `review_id`.
- Deterministic v1.2-to-v2.0 corpus migration with an immutable source archive.

### Changed

- `ctkat screen` and corpus summaries now gate on `overall`; the nine-class
  taxonomy is retained only as `legacy_verdict_class`.
- Completed legacy timing runs default to `insufficient-power` until A/A and
  positive-control calibration exists.
- The known ML-KEM-768 raw timing failure is migrated to
  `confounded / signal / inconclusive`.
- Public/manual attribution no longer clears a result without a completed
  review artifact.

### Fixed

- A raw timing FAIL can no longer coexist with a clean machine-readable
  headline.
- Primary CT FAIL/ERROR results can no longer be hidden by clean matrix cells.
- An unscanned assembly compiler/optimization cell can no longer masquerade as
  a completed zero-candidate scan.
- The legacy ML-KEM timing-only axis no longer inherits structural/assembly
  claims that lack a matching cell artifact.

## [0.2.0a1] - 2026-07-29

### Added

- Installable wheel/sdist release gate with bundled Jinja templates.
- `ctkat --version`.
- Python 3.11–3.13 CI, coverage, package smoke, Linux Valgrind, gcc/clang,
  Docker, corpus drift, and third-party provenance checks.
- Trusted/untrusted config execution profiles and explicit shell opt-in.
- Machine-checkable third-party inventory and human-readable notices.
- Rejection-review recovery roadmap.

### Changed

- Example and documentation build/KAT steps now use shell-free `argv`.
- README corpus results are generated from the committed summary CSV.
- Timing claims now say `dudect-inspired first-order screen`; official dudect
  protocol parity is not claimed.
- Package version advanced from `0.1.0` to the first `0.2.0` alpha.

### Fixed

- Wheels now contain every `ctkat/templates/*.j2` resource.
- Template loading works independently of a source checkout.
- Missing ML-DSA-65 CC0 notice and incomplete PQClean attribution were restored.

## [0.1.0] - 2026-05-24

- Initial research prototype.

[0.7.0a1]: https://github.com/Lee-Seungwon1215/WISA_proj/compare/b44340d...main
[0.6.0a1]: https://github.com/Lee-Seungwon1215/WISA_proj/compare/186f8ef...b44340d
[0.5.0a1]: https://github.com/Lee-Seungwon1215/WISA_proj/compare/9768d83...186f8ef
[0.4.0a1]: https://github.com/Lee-Seungwon1215/WISA_proj/compare/abaf92f...9768d83
[0.3.0a1]: https://github.com/Lee-Seungwon1215/WISA_proj/compare/619d73c...abaf92f
[0.2.0a1]: https://github.com/Lee-Seungwon1215/WISA_proj/compare/b1ccd4d...619d73c
[0.1.0]: https://github.com/Lee-Seungwon1215/WISA_proj/commits/20a20f72a65216bb2e4edafc0b054789281f3455
