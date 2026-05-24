#include "compare.h"

/*
 * Returns 0 on match, non-zero on mismatch.
 * No data-dependent branches: accumulate XOR diff across all bytes.
 */
int safe_compare(const uint8_t *secret, const uint8_t *guess, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(secret[i] ^ guess[i]);
    }
    return diff != 0;
}
