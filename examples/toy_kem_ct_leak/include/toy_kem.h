/* Toy "KEM" used to validate the dudect ct-leak detection mode.
 *
 * NOT a real cryptosystem. The keypair/enc functions exist only to give
 * the dudect KEM template the PQClean-style API it expects to call. The
 * actual differentiator between LEAKY_ and SAFE_ is the dec() body —
 * leaky's runtime depends on ct[0], safe's does not.
 *
 * Two prefixed copies (LEAKY_, SAFE_) live in the same translation unit
 * because the dudect KEM template namespaces every function and macro
 * with the yaml `prefix` field. Each harness picks its prefix and gets
 * its own binary; the unused prefix's symbols are linked but never called.
 */

#ifndef TOY_KEM_H
#define TOY_KEM_H

#include <stddef.h>
#include <stdint.h>

/* Same sizes for both variants — keeps the binary layout identical so
 * any timing difference is attributable to dec() logic, not buffer size. */
#define _TOY_KEM_BYTES 32

#define LEAKY_CRYPTO_PUBLICKEYBYTES   _TOY_KEM_BYTES
#define LEAKY_CRYPTO_SECRETKEYBYTES   _TOY_KEM_BYTES
#define LEAKY_CRYPTO_CIPHERTEXTBYTES  _TOY_KEM_BYTES
#define LEAKY_CRYPTO_BYTES            _TOY_KEM_BYTES

#define SAFE_CRYPTO_PUBLICKEYBYTES    _TOY_KEM_BYTES
#define SAFE_CRYPTO_SECRETKEYBYTES    _TOY_KEM_BYTES
#define SAFE_CRYPTO_CIPHERTEXTBYTES   _TOY_KEM_BYTES
#define SAFE_CRYPTO_BYTES             _TOY_KEM_BYTES

int LEAKY_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int LEAKY_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int LEAKY_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

int SAFE_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int SAFE_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int SAFE_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif
