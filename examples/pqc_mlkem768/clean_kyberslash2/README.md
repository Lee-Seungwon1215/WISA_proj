# `clean_kyberslash2`

Derived overlay for the pinned PQClean ML-KEM-768 clean implementation. It
restores both KyberSlash2 compression sites used by Kyber-768:

- `PQCLEAN_MLKEM768_CLEAN_poly_compress`
- `PQCLEAN_MLKEM768_CLEAN_polyvec_compress`

The values being compressed during the re-encryption check in ML-KEM
decapsulation are derived from the secret-dependent decrypted message. The
divisor `KYBER_Q` (`3329`) is public, but the numerator is not.

`poly_tomsg` retains the reciprocal-multiplication fix, so KyberSlash1 is
absent. The exact stock-to-overlay patch is frozen under
`docs/ground_truth/kyberslash/patches/ks2.patch`.

This is a reconstructed differential control on the current PQClean baseline,
not a claim that the whole directory is a verbatim historical release.
