#ifndef CTKAT_FNDSA_API_H
#define CTKAT_FNDSA_API_H

#include <stddef.h>
#include <stdint.h>

#include "fndsa.h"

#define CTKAT_FNDSA_CRYPTO_SECRETKEYBYTES FNDSA_SIGN_KEY_SIZE(10)
#define CTKAT_FNDSA_CRYPTO_PUBLICKEYBYTES FNDSA_VRFY_KEY_SIZE(10)
#define CTKAT_FNDSA_CRYPTO_BYTES FNDSA_SIGNATURE_SIZE(10)

int CTKAT_FNDSA_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int CTKAT_FNDSA_crypto_sign_signature(
    uint8_t *sig,
    size_t *siglen,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *sk);
int CTKAT_FNDSA_crypto_sign_verify(
    const uint8_t *sig,
    size_t siglen,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *pk);

#endif
