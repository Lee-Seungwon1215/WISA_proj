# KyberSlash TIMECOP Valgrind patch

This directory vendors the full Memcheck patch from the IACR CHES artifact for
“KyberSlash: Exploiting secret-dependent division timings in Kyber
implementations”:

- artifact: `https://artifacts.iacr.org/tches/2025/a9`
- archive:
  `https://artifacts.iacr.org/files/tches/2025/tches-2025-a9.zip`
- archive SHA-256:
  `403af6cb4ff8d7a6a4057e280cd22e27c842fec97963645b66f9138e8b69a4b8`
- member: `kyberslash-demo/valgrind/valgrind-3.22.0-varlat.patch`
- member SHA-256:
  `4b684f1b4a3456dcebea91d6daeb0eebe1e35492753b9412d74385a22c1bc612`
- target source: Valgrind `3.22.0`
- license: GPL-2.0-or-later, with the artifact's `COPYING.GPL2` retained

The patch adds `VALGRIND_ENABLE_TIMECOP_MODE` and reports tainted operands of
variable-latency instructions. It is intentionally a separate backend from
ordinary Memcheck: a normal structural `PASS` does not imply a TIMECOP `PASS`.

Use the dedicated Docker target and KyberSlash ground-truth runner documented
under `docs/ground_truth/kyberslash/README.md`. CT-KAT's MIT license does not
relicense this vendored patch.
