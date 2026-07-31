/* Deterministic build/equivalence adapter; not a production RNG example. */
#include <stdint.h>
#include <stdio.h>

#include "mldsa_native.h"

#define ctkat_keypair_internal MLD_API_NAMESPACE(keypair_internal)
#define ctkat_signature_internal MLD_API_NAMESPACE(signature_internal)

static int write_all(const uint8_t *data, size_t length)
{
  return fwrite(data, 1, length, stdout) == length ? 0 : -1;
}

int main(void)
{
  static const uint8_t message[] = "ctkat/mldsa-native/deterministic-smoke/v1";
  static const uint8_t pre[] = {0x00, 0x00};
  uint8_t seed[MLDSA_SEEDBYTES];
  uint8_t rnd[MLDSA_RNDBYTES];
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t sig[CRYPTO_BYTES];
  size_t siglen = 0;
  size_t i;

  for (i = 0; i < sizeof(seed); i++)
  {
    seed[i] = (uint8_t)(0x53U ^ (uint8_t)(11U * i));
  }
  for (i = 0; i < sizeof(rnd); i++)
  {
    rnd[i] = (uint8_t)(0xc1U + (uint8_t)(7U * i));
  }

  if (ctkat_keypair_internal(pk, sk, seed) != 0 ||
      ctkat_signature_internal(sig, &siglen, message, sizeof(message) - 1,
                               pre, sizeof(pre), rnd, sk, 0) != 0 ||
      siglen != sizeof(sig) ||
      crypto_sign_verify(sig, siglen, message, sizeof(message) - 1, NULL, 0,
                         pk) != 0)
  {
    return 1;
  }

  if (write_all(pk, sizeof(pk)) != 0 || write_all(sk, sizeof(sk)) != 0 ||
      write_all(sig, siglen) != 0)
  {
    return 2;
  }
  return 0;
}
