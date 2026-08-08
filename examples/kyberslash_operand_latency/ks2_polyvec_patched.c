#include <stdint.h>

__attribute__((noinline, used))
uint32_t ctkat_kyberslash_site_operation(uint16_t coefficient) {
    uint64_t numerator = ((uint64_t)coefficient << 10) + 1665U;
    numerator *= UINT64_C(1290167);
    return (uint32_t)(numerator >> 32) & 0x3ffU;
}
