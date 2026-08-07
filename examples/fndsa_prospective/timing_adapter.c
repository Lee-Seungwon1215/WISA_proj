/*
 * Timing-only PQClean-shaped adapter for the pinned c-fn-dsa snapshot.
 *
 * Unlike adapter.c, this glue deliberately obtains a fresh deterministic seed
 * through CT-KAT's weak seeded randombytes interpose for every key generation
 * and signature.  That is required for timing-harness-v2's fixed-vs-random
 * secret-key pools to contain genuinely distinct keys.  This is measurement
 * glue, not a production randomness recommendation.
 */

#include <stddef.h>
#include <stdint.h>

#include "api.h"
#include "fndsa.h"

#if CTKAT_FNDSA_LOGN != 9 && CTKAT_FNDSA_LOGN != 10
#error CTKAT_FNDSA_LOGN must be 9 or 10
#endif

extern int randombytes(uint8_t *out, size_t outlen);

int
CTKAT_FNDSA_crypto_sign_keypair(uint8_t *pk, uint8_t *sk)
{
    uint8_t seed[32];
    if (randombytes(seed, sizeof seed) != 0) {
        return -1;
    }
    fndsa_keygen_seeded(CTKAT_FNDSA_LOGN, seed, sizeof seed, sk, pk);
    return 0;
}

int
CTKAT_FNDSA_crypto_sign_signature(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *sk)
{
    uint8_t seed[40];
    if (randombytes(seed, sizeof seed) != 0) {
        return -1;
    }
    *siglen = fndsa_sign_seeded(
        sk,
        CTKAT_FNDSA_CRYPTO_SECRETKEYBYTES,
        NULL,
        0,
        FNDSA_HASH_ID_RAW,
        message,
        message_len,
        seed,
        sizeof seed,
        sig,
        CTKAT_FNDSA_CRYPTO_BYTES);
    return *siglen == CTKAT_FNDSA_CRYPTO_BYTES ? 0 : -1;
}

int
CTKAT_FNDSA_crypto_sign_verify(
    const uint8_t *sig,
    size_t siglen,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *pk)
{
    return fndsa_verify(
               sig,
               siglen,
               pk,
               CTKAT_FNDSA_CRYPTO_PUBLICKEYBYTES,
               NULL,
               0,
               FNDSA_HASH_ID_RAW,
               message,
               message_len)
        ? 0
        : -1;
}
