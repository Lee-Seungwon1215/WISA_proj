# Diverse native timing v2

The first engineering execution of `diverse_native_v1.yaml` completed only the
portable mlkem-native target.  The other three targets exposed premeasurement
compile-contract defects.  The completed target produced a large, repeatable
timing difference, but the legacy machine label `sk` described a corpus that
changed a secret key and its matching public ciphertext together.

V2 makes two corrections before any final trace exists:

1. The ML-KEM harness and manifest use `valid_tuple`, not `sk`. Class 0 repeats
   one fixed valid `(sk, ct)` tuple, while class 1 selects fresh valid tuples.
   The generated binary emits a fail-closed input contract recording that the
   secret key, public ciphertext, and public-key material embedded in the
   secret key all vary. Every setup API return code and every fixed/fresh
   tuple's untimed encapsulation-to-decapsulation round trip must pass before
   timing begins. A signal is therefore a mixed valid-tuple timing contrast
   and cannot establish secret attribution.
2. The x86_64 ML-KEM and ML-DSA profiles explicitly select the pinned upstream
   native arithmetic and FIPS-202 metadata headers. The ML-DSA adapter also
   exposes the upstream public verifier so every generated signature must pass
   the untimed sign-to-verify correctness gate before samples are accepted.

Sample counts, controls, thresholds, process repeats, compiler optimization,
upstream snapshots, parameter sets, and the portable/native comparison remain
unchanged. V1 engineering artifacts are calibration evidence only. They cannot
be resumed, relabeled, or promoted into a v2 final campaign.
