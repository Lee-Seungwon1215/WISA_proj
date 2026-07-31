# `clean_kyberslash1`

Derived overlay for the pinned PQClean ML-KEM-768 clean implementation. It
restores only KyberSlash1:

- vulnerable function: `PQCLEAN_MLKEM768_CLEAN_poly_tomsg`
- data path: K-PKE decryption inside ML-KEM decapsulation
- secret numerator: the coefficient recovered from the secret-key-dependent
  decryption result
- public divisor: `KYBER_Q` (`3329`)

`poly_compress` and the stock `clean/polyvec.c` retain their reciprocal
multiplication fixes, so KyberSlash2 is absent. The exact stock-to-overlay patch
is frozen under `docs/ground_truth/kyberslash/patches/ks1.patch`.

This is a reconstructed differential control on the current PQClean baseline,
not a claim that the whole directory is a verbatim historical release.
