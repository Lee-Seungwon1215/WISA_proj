# Committed-corpus native timing v3

The v2 engineering campaign used the historical KEM machine label `sk` for a
corpus that changed a secret key and its matching valid ciphertext together.
That evidence remains useful as a mixed-input calibration, but it cannot be
causally attributed to secret material.

V3 retains the `kem_dec` harness name solely because committed-corpus coverage
is keyed by `(target, harness)`. Its machine axis is now `valid_tuple`, backed
by the same fail-closed metadata and untimed setup/round-trip witnesses as the
diverse v2 comparison. The `kem_dec_ct` and `kem_dec_fo` axes and every
non-ML-KEM target keep their v2 inputs, sample counts, controls, thresholds,
flags, and hypotheses.

No v2 engineering trace may be relabeled or promoted into a v3 final result.
Final collection starts from a fresh root at one reviewed commit on each of two
distinct physical CPU models.
