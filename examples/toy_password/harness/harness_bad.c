#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <valgrind/memcheck.h>

#include "compare.h"

int main(void) {
    /* Bundle E-2 (F5): sentinel proving the harness actually ran the
     * target function. `ctkat run` with `ct.require_sentinel=true`
     * looks for this exact format on stdout. */
    puts("CTKAT-HARNESS-RAN: bad");

    uint8_t secret[16] = {
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    uint8_t guess[16] = {
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    VALGRIND_MAKE_MEM_UNDEFINED(secret, sizeof(secret));

    int result = bad_compare(secret, guess, sizeof(secret));

    VALGRIND_MAKE_MEM_DEFINED(secret, sizeof(secret));
    VALGRIND_MAKE_MEM_DEFINED(&result, sizeof(result));

    printf("bad_compare result: %d\n", result);
    return 0;
}
