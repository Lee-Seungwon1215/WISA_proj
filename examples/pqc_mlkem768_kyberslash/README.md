# ML-KEM-768 KyberSlash positive control

This target is a positive control for CT-KAT's variable-latency instruction
layer. It is intentionally not a stock PQClean target: the source is PQClean
ML-KEM-768 with the historical KyberSlash-style divisions restored in two
compression helpers.

## What changed

The vulnerable copy lives at:

- `../pqc_mlkem768/clean_kyberslash/poly.c`
- `PQCLEAN_MLKEM768_CLEAN_poly_compress`, line 50:
  `((((uint16_t)u << 4) + KYBER_Q/2)/KYBER_Q) & 15`
- `PQCLEAN_MLKEM768_CLEAN_poly_tomsg`, line 162:
  `(((t << 1) + KYBER_Q/2)/KYBER_Q) & 1`

The stock fixed copy lives at:

- `../pqc_mlkem768/clean/poly.c`
- `PQCLEAN_MLKEM768_CLEAN_poly_compress`, lines 32-35:
  reciprocal multiply by `80635`, then shift by 28
- `PQCLEAN_MLKEM768_CLEAN_poly_tomsg`, lines 147-150:
  reciprocal multiply by `80635`, then shift by 28

## What the artifact is meant to show

The `kem_dec` harness passes the structural Memcheck/ctgrind-style check across
the committed gcc/clang matrix. That is expected: KyberSlash is not a
secret-dependent branch or secret-dependent address pattern.

The asm-scan layer is intentionally taint-free. It scans emitted assembly for
candidate variable-latency instructions and records source provenance, but it
does not prove whether a division operand is public or secret. The
`varlat-secret-risk` label for this target is therefore a human/source-triage
judgment over the restored `/KYBER_Q` helpers, not a Memcheck-taint-to-assembly
link.

The same report may also contain Keccak rate divisions from `common/fips202.c`.
Those are triaged as likely public and must not be collapsed with the
KyberSlash poly helpers.

## Expected committed reports

- `reports/ctkat_ct_matrix.csv`: every build cell is `PASS` with zero structural
  findings.
- `reports/ctkat_varlat_candidates.csv`: `poly_compress` and `poly_tomsg` are
  tagged `kyberslash-poly-review-secret-risk`; `shake128` and `shake256` are
  tagged `keccak-rate-review-likely-public`.
