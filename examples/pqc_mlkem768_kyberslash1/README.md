# ML-KEM-768 KyberSlash1-only target

This target swaps only `poly_tomsg` for the reconstructed KyberSlash1 overlay.
It exists to distinguish a decryption-side KS1 finding from the encryption-side
KS2 compression findings.

Expected layers:

- deterministic KEM transcript: byte-identical to stock
- ordinary Memcheck branch/address check: `PASS`
- assembly candidate: `poly_tomsg` only, apart from separately triaged public
  library arithmetic
- patched-Valgrind TIMECOP attribution: `poly_tomsg`
- physical timing/attack reproduction: not claimed by this target

The authoritative site and provenance contract lives in
`docs/ground_truth/kyberslash/ground_truth.yaml`.
