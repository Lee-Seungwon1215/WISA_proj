#include <stdint.h>

__attribute__((noinline, used))
uint32_t ctkat_kyberslash_site_operation(uint16_t coefficient) {
    uint32_t numerator = ((uint32_t)coefficient << 1) + 1665U;
    numerator *= 80635U;
    return (numerator >> 28) & 1U;
}
