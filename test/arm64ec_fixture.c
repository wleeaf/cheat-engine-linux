/* ARM64EC console fixture for test/arm64ec_target_gate.py.
 *
 * Built with llvm-mingw's arm64ec-w64-mingw32-clang and run under a Wine with
 * ARM64EC support (Hangover) on an ARM64 Linux host. It prints
 * "CE_ARM64EC VALUE POINTER WRITER" (hex), then on stdin 'b' calls the writer
 * and prints the new value, and 'r' prints the current value.
 */
#include <stdio.h>

static volatile int value = 24681357;
volatile int *volatile pointer = &value;   /* a static path for the pointer scan */

__declspec(noinline) int ce_writer(void) { return ++*pointer; }

int main(void) {
    printf("CE_ARM64EC %p %p %p\n", (void *)&value, (void *)&pointer, (void *)ce_writer);
    fflush(stdout);
    int c;
    while ((c = getchar()) != EOF) {
        if (c == 'b') printf("%d\n", ce_writer());
        else if (c == 'r') printf("%d\n", value);
        else continue;
        fflush(stdout);
    }
    return 0;
}
