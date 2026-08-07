/* PQClean-shaped timing adapter for mldsa-native beta2; not production glue. */
#include <stddef.h>
#include <stdint.h>

#include "timing_api.h"

extern int randombytes(uint8_t *out, size_t outlen);

#define ctkat_keypair_internal MLD_API_NAMESPACE(keypair_internal)
#define ctkat_signature_internal MLD_API_NAMESPACE(signature_internal)

int
CTKAT_MLDSA_crypto_sign_keypair(uint8_t *pk, uint8_t *sk)
{
    uint8_t seed[MLDSA_SEEDBYTES];
    if (randombytes(seed, sizeof seed) != 0) {
        return -1;
    }
    return ctkat_keypair_internal(pk, sk, seed);
}

int
CTKAT_MLDSA_crypto_sign_signature(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *sk)
{
    static const uint8_t pre[] = {0x00, 0x00};
    uint8_t rnd[MLDSA_RNDBYTES];
    if (randombytes(rnd, sizeof rnd) != 0) {
        return -1;
    }
    return ctkat_signature_internal(
        sig,
        siglen,
        message,
        message_len,
        pre,
        sizeof pre,
        rnd,
        sk,
        0);
}
