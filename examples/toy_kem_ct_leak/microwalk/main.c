/*
 * CT-KAT's minimal MicroWalk Pin wrapper.
 *
 * The protocol is compatible with MicroWalk v3.2.0's C template: the tracer
 * writes `t <id>` and a testcase path on stdin, or `e 0` to terminate.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

extern void InitTarget(FILE *input);
extern void RunTarget(FILE *input);

#if !defined(__x86_64__)
#error "The frozen MicroWalk Pin profile requires x86_64"
#endif

__attribute__((noinline, used)) int PinNotifyTestcaseStart(int testcase_id) {
    return testcase_id + 42;
}

__attribute__((noinline, used)) int PinNotifyTestcaseEnd(void) {
    return 42;
}

__attribute__((noinline, used)) int PinNotifyStackPointer(
    uint64_t minimum,
    uint64_t maximum
) {
    return (int)(minimum + maximum + 42);
}

__attribute__((noinline, used)) int PinNotifyAllocation(
    uint64_t address,
    uint64_t size
) {
    return (int)(address + 23 * size);
}

static void notify_stack_bounds(void) {
    uintptr_t stack_base;
    struct rlimit limit;
    __asm__ __volatile__("mov %%rsp, %0" : "=r"(stack_base));

    uint64_t stack_size = UINT64_C(8) * 1024 * 1024;
    if (getrlimit(RLIMIT_STACK, &limit) == 0 && limit.rlim_cur != RLIM_INFINITY) {
        stack_size = (uint64_t)limit.rlim_cur;
    }
    uint64_t minimum = (uint64_t)stack_base - stack_size;
    uint64_t maximum = ((uint64_t)stack_base + UINT64_C(0xffff)) & ~UINT64_C(0xffff);
    (void)PinNotifyStackPointer(minimum, maximum);
}

int main(void) {
    char command_line[64];
    char testcase_path[4096];
    int initialized = 0;

    notify_stack_bounds();
    (void)PinNotifyAllocation((uint64_t)(uintptr_t)&errno, sizeof(errno));

    while (fgets(command_line, sizeof(command_line), stdin) != NULL) {
        char command = '\0';
        int testcase_id = 0;
        if (sscanf(command_line, "%c %d", &command, &testcase_id) != 2) {
            fprintf(stderr, "invalid MicroWalk command: %s", command_line);
            return 2;
        }
        if (command == 'e') {
            return 0;
        }
        if (command != 't' || fgets(testcase_path, sizeof(testcase_path), stdin) == NULL) {
            fprintf(stderr, "invalid MicroWalk testcase command\n");
            return 2;
        }

        testcase_path[strcspn(testcase_path, "\r\n")] = '\0';
        FILE *input = fopen(testcase_path, "rb");
        if (input == NULL) {
            fprintf(stderr, "cannot open testcase %s: %s\n", testcase_path, strerror(errno));
            return 2;
        }
        if (!initialized) {
            InitTarget(input);
            if (fseek(input, 0, SEEK_SET) != 0) {
                fclose(input);
                return 2;
            }
            initialized = 1;
        }

        (void)PinNotifyTestcaseStart(testcase_id);
        RunTarget(input);
        (void)PinNotifyTestcaseEnd();
        fclose(input);
    }
    return 0;
}
