#include "compare.h"

/*
 * Returns 0 on match, non-zero on mismatch.
 * Early-returns on the first differing byte — execution time leaks
 * how many leading bytes of `secret` matched `guess`.
 */
int bad_compare(const uint8_t *secret, const uint8_t *guess, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (secret[i] != guess[i]) {
            return 1;
        }
    }
    return 0;
}
