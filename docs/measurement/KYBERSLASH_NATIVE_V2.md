# KyberSlash native timing v2

The v1 full-KEM timing axis varied a fresh secret key and its matching
ciphertext together. A class effect therefore could not be attributed to the
secret key, the public ciphertext, or their interaction. It also compiled the
timing binary with GCC `-O2`, where the frozen corpus shows that the relevant
constant divisions are strength-reduced away. Those rows are exploratory and
must not support a KyberSlash leakage claim.

V2 separates three evidence layers:

1. `kem_dec_chosen_ct` holds one secret key byte-for-byte fixed and compares
   two deterministic pools of publicly mutated ciphertexts. Both members of a
   pair start from the same encapsulation and receive a nonzero mutation in
   opposite ciphertext halves. Before timing, an untimed scheme-specific
   `rkprf(z, ct)` oracle must match the decapsulation output for every member;
   the harness therefore proves implicit rejection instead of inferring it
   merely from an original-shared-secret mismatch. Key and pool SHA3-256
   digests are emitted in every trace, and all process repeats must agree. This
   is a public chosen-input contrast; it does not by itself attribute a signal
   to a secret.
2. `operand_bin` measures the three arithmetic sites directly. Class 0 freezes
   coefficients 0–63 and class 1 freezes 3265–3328; each site converts the
   coefficient to its exact KyberSlash numerator. Vulnerable and
   reciprocal-multiply binaries have identical base compiler flags and input
   pools. These are hardware-latency canaries, not full-KEM or key-recovery
   experiments.
3. The linked-binary contract runs GNU `objdump` on the exact timing binary
   before the first sample. GCC `-Os` is required. Stock/patched symbols must
   contain zero `div/idiv`; each vulnerable site must contain exactly one.
   Missing symbols, helper calls, wrong flags, wrong architecture, or a wrong
   instruction count abort the run. The full disassembly, compiler executable
   and version, compile command, binary/source hashes, and contract report are
   preserved under
   `reports/binary_contract/timing_<harness>.{binary-contract.json,objdump.txt,objdump-file-header.txt}`
   and referenced (with hashes) from the timing backend report. The generated
   source and measured binary remain under the target's `generated/` directory
   and are hash-bound by the contract report.

The campaign is frozen in `docs/measurement/kyberslash_native_v2.yaml`. It may
support “operand-dependent latency reproduced” only when both native hosts pass
their controls and the vulnerable/patched paired analysis agrees. “Full attack”
or “key recovery reproduced” remains forbidden without a separate attack
artifact.
