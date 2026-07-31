/* Deterministic adapter transcript and round-trip check. */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if CTKAT_FNDSA_FENV_CHECK
#include <fenv.h>
#endif

#include "api.h"

static int
emit(const uint8_t *buf, size_t len)
{
    return fwrite(buf, 1, len, stdout) == len ? 0 : -1;
}

int
main(void)
{
    uint8_t pk[CTKAT_FNDSA_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CTKAT_FNDSA_CRYPTO_SECRETKEYBYTES];
    uint8_t sig[CTKAT_FNDSA_CRYPTO_BYTES];
    uint8_t message[64];
    size_t sig_len = 0;

    for (size_t i = 0; i < sizeof message; i++) {
        message[i] = (uint8_t)(0xa5u ^ (uint8_t)(i * 29u));
    }
    if (CTKAT_FNDSA_crypto_sign_keypair(pk, sk) != 0) {
        return 10;
    }
#if CTKAT_FNDSA_FENV_CHECK
    if (feclearexcept(FE_ALL_EXCEPT) != 0) {
        return 16;
    }
#endif
    if (CTKAT_FNDSA_crypto_sign_signature(
            sig, &sig_len, message, sizeof message, sk)
        != 0) {
        return 11;
    }
#if CTKAT_FNDSA_FENV_CHECK
    if (fetestexcept(FE_INVALID | FE_DIVBYZERO | FE_OVERFLOW | FE_UNDERFLOW)
        != 0) {
        return 17;
    }
#endif
    if (sig_len != sizeof sig) {
        return 12;
    }
    if (CTKAT_FNDSA_crypto_sign_verify(
            sig, sig_len, message, sizeof message, pk)
        != 0) {
        return 13;
    }
    message[0] ^= 1;
    if (CTKAT_FNDSA_crypto_sign_verify(
            sig, sig_len, message, sizeof message, pk)
        == 0) {
        return 14;
    }
    if (emit(pk, sizeof pk) != 0
        || emit(sk, sizeof sk) != 0
        || emit(sig, sizeof sig) != 0) {
        return 15;
    }
    return 0;
}
