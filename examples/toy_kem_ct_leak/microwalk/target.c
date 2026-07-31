/* Same-source MicroWalk adapter for the toy KEM ct-input benchmark. */

#include <stdint.h>
#include <stdio.h>

#include "toy_kem.h"

#if defined(CTKAT_MICROWALK_LEAKY)
#define CTKAT_DEC LEAKY_crypto_kem_dec
#elif defined(CTKAT_MICROWALK_SAFE)
#define CTKAT_DEC SAFE_crypto_kem_dec
#else
#error "select CTKAT_MICROWALK_LEAKY or CTKAT_MICROWALK_SAFE"
#endif

static uint8_t fixed_secret_key[_TOY_KEM_BYTES];
static volatile uint8_t output_sink;

void InitTarget(FILE *input) {
    (void)input;
    for (size_t i = 0; i < sizeof(fixed_secret_key); i++) {
        fixed_secret_key[i] = (uint8_t)i;
    }
}

void RunTarget(FILE *input) {
    uint8_t ciphertext[_TOY_KEM_BYTES];
    uint8_t shared_secret[_TOY_KEM_BYTES];
    if (fread(ciphertext, 1, sizeof(ciphertext), input) != sizeof(ciphertext)) {
        return;
    }
    (void)CTKAT_DEC(shared_secret, ciphertext, fixed_secret_key);
    output_sink ^= shared_secret[0];
}
