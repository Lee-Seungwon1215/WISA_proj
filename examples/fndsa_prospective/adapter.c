/*
 * CT-KAT's PQClean-shaped adapter for the pinned c-fn-dsa snapshot.
 *
 * This file is local glue, not upstream c-fn-dsa.  The caller must define
 * CTKAT_FNDSA_LOGN to 9 or 10.  Seeded entry points make structural runs and
 * KAT transcripts reproducible; they are not production randomness policy.
 */

#include <stddef.h>
#include <stdint.h>

#include "api.h"
#include "fndsa.h"

#if CTKAT_FNDSA_LOGN != 9 && CTKAT_FNDSA_LOGN != 10
#error CTKAT_FNDSA_LOGN must be 9 or 10
#endif

static const uint8_t ctkat_keygen_seed[32] = {
    0x43, 0x54, 0x4b, 0x41, 0x54, 0x2d, 0x46, 0x4e,
    0x44, 0x53, 0x41, 0x2d, 0x4b, 0x45, 0x59, 0x47,
    0x45, 0x4e, 0x2d, 0x56, 0x31, 0x00, 0x01, 0x02,
    0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
};

static const uint8_t ctkat_sign_seed[40] = {
    0x43, 0x54, 0x4b, 0x41, 0x54, 0x2d, 0x46, 0x4e,
    0x44, 0x53, 0x41, 0x2d, 0x53, 0x49, 0x47, 0x4e,
    0x2d, 0x56, 0x31, 0x00, 0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
};

int
CTKAT_FNDSA_crypto_sign_keypair(uint8_t *pk, uint8_t *sk)
{
    fndsa_keygen_seeded(
        CTKAT_FNDSA_LOGN,
        ctkat_keygen_seed,
        sizeof ctkat_keygen_seed,
        sk,
        pk);
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
    *siglen = fndsa_sign_seeded(
        sk,
        CTKAT_FNDSA_CRYPTO_SECRETKEYBYTES,
        NULL,
        0,
        FNDSA_HASH_ID_RAW,
        message,
        message_len,
        ctkat_sign_seed,
        sizeof ctkat_sign_seed,
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
