# ML-KEM-768 KyberSlash1+2 differential target

This target is a positive control for CT-KAT's variable-latency instruction
layer. It is intentionally not a stock PQClean target: the source is PQClean
ML-KEM-768 with KyberSlash1 restored in `poly_tomsg` and KyberSlash2 restored
in both `poly_compress` and `polyvec_compress`.

## What changed

The vulnerable copy lives at:

- `../pqc_mlkem768/clean_kyberslash/poly.c`
- `PQCLEAN_MLKEM768_CLEAN_poly_compress`, line 50:
  `((((uint16_t)u << 4) + KYBER_Q/2)/KYBER_Q) & 15`
- `PQCLEAN_MLKEM768_CLEAN_poly_tomsg`, line 162:
  `(((t << 1) + KYBER_Q/2)/KYBER_Q) & 1`
- `../pqc_mlkem768/clean_kyberslash/polyvec.c`
- `PQCLEAN_MLKEM768_CLEAN_polyvec_compress`:
  `((((uint32_t)t[k] << 10) + KYBER_Q/2)/KYBER_Q) & 0x3ff`

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

The asm-scan layer remains intentionally taint-free: it reports emitted
variable-latency candidates. Secret-operand attribution is a separate column
produced by the pinned TIMECOP-patched Valgrind backend, so function-name
triage is no longer presented as the final proof.

The same report may also contain Keccak rate divisions from `common/fips202.c`.
Those are triaged as likely public and must not be collapsed with the
KyberSlash poly helpers.

## Expected committed reports

- `reports/ctkat_ct_matrix.csv`: every build cell is `PASS` with zero structural
  findings.
- `reports/ctkat_varlat_candidates.csv`: the three KyberSlash helper functions
  remain distinct from public Keccak rate arithmetic.
