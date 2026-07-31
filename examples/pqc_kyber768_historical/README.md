# Historical Kyber-768 reference anchor

`ref/` is a byte-for-byte snapshot of `pq-crystals/kyber` commit
`a621b8dde405cc507cbcfc5f794570a4f98d69cc`, the parent of the KyberSlash1
fix. At that point the official reference implementation still contained:

- KyberSlash1 in `ref/poly.c::poly_tomsg`
- KyberSlash2 in `ref/poly.c::poly_compress`
- KyberSlash2 in `ref/polyvec.c::polyvec_compress`

The next relevant commits are:

- `dda29cc63af721981ee2c831cf00822e69be3220`: fixes KS1, leaving KS2
- `272125f6acc8e8b6850fd68ceb901a660ff48196`: fixes KS2

This directory is the historical source/provenance anchor. The four differential
benchmark targets use the newer pinned PQClean ML-KEM baseline so stock, KS1,
KS2, and KS1+2 differ only at the intended expressions. Do not equate a
successful source/build reproduction with reproducing the paper's Raspberry
Pi 2 or Cortex-M4 key-recovery attacks.

`ctkat_api.h` and `ctkat.yaml` are local adapters outside the immutable `ref/`
tree. Detailed hashes and the IACR artifact identity are in `FETCH_INFO.md` and
`docs/ground_truth/kyberslash/ground_truth.yaml`.
