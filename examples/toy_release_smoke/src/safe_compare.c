#include "safe_compare.h"

int safe_compare(const uint8_t *secret, const uint8_t *guess, size_t length) {
    uint8_t difference = 0;
    for (size_t i = 0; i < length; i++) {
        difference |= secret[i] ^ guess[i];
    }
    return difference != 0;
}
