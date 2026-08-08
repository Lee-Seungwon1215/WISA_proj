#ifndef CTKAT_KYBERSLASH_OPERAND_API_H
#define CTKAT_KYBERSLASH_OPERAND_API_H

#include <stdint.h>

#define CTKAT_KS_CRYPTO_PUBLICKEYBYTES 32
#define CTKAT_KS_CRYPTO_SECRETKEYBYTES 32
#define CTKAT_KS_CRYPTO_CIPHERTEXTBYTES 8
#define CTKAT_KS_CRYPTO_BYTES 32

int CTKAT_KS_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int CTKAT_KS_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int CTKAT_KS_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif
