/* Deterministic build/equivalence adapter; not a production RNG example. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "mlkem_native.h"

static int write_all(const uint8_t *data, size_t length)
{
  return fwrite(data, 1, length, stdout) == length ? 0 : -1;
}

int main(void)
{
  uint8_t key_coins[2 * MLKEM_SYMBYTES];
  uint8_t enc_coins[MLKEM_SYMBYTES];
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t ss_enc[CRYPTO_BYTES];
  uint8_t ss_dec[CRYPTO_BYTES];
  size_t i;

  for (i = 0; i < sizeof(key_coins); i++)
  {
    key_coins[i] = (uint8_t)(0x31U + (uint8_t)(17U * i));
  }
  for (i = 0; i < sizeof(enc_coins); i++)
  {
    enc_coins[i] = (uint8_t)(0xa7U ^ (uint8_t)(29U * i));
  }

  if (crypto_kem_keypair_derand(pk, sk, key_coins) != 0 ||
      crypto_kem_enc_derand(ct, ss_enc, pk, enc_coins) != 0 ||
      crypto_kem_dec(ss_dec, ct, sk) != 0 ||
      memcmp(ss_enc, ss_dec, sizeof(ss_enc)) != 0)
  {
    return 1;
  }

  if (write_all(pk, sizeof(pk)) != 0 || write_all(sk, sizeof(sk)) != 0 ||
      write_all(ct, sizeof(ct)) != 0 || write_all(ss_enc, sizeof(ss_enc)) != 0)
  {
    return 2;
  }
  return 0;
}
