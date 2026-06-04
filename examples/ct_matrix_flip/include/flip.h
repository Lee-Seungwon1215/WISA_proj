#ifndef CTKAT_FLIP_H
#define CTKAT_FLIP_H

#include <stdint.h>
#include <stddef.h>

/*
 * leaky_select: out[i] is chosen by a SECRET-DEPENDENT conditional branch.
 * At -O0 gcc emits a real conditional jump on the tainted byte, so Valgrind
 * reports "Conditional jump or move depends on uninitialised value(s)" (FAIL).
 * At -O2/-Os gcc lowers the select to branch-free code, so Valgrind no longer
 * sees it (PASS) — even though the source is unchanged. That FAIL->PASS flip
 * across build configs is the whole point of `ctkat ct-matrix`.
 */
void leaky_select(const uint8_t *secret, uint8_t *out, size_t n);

/*
 * safe_select: same input/output shape, written branch-free with arithmetic so
 * there is no secret-dependent control flow at ANY optimization level
 * (PASS everywhere). The contrast with leaky_select is the lesson.
 */
void safe_select(const uint8_t *secret, uint8_t *out, size_t n);

#endif /* CTKAT_FLIP_H */
