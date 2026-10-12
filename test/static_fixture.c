/* Ordinary libc program for the static-libc and musl targets.
 *
 * Unlike compatibility_fixture.c (freestanding, no libc), this links a real C
 * library, so it is built as glibc -static, musl -static or dynamic musl. It
 * exposes a static value, a static pointer to it and a non-inlined writer, and
 * answers stdin commands: 'b' runs the writer, 'r' reads the value, 'q' exits.
 */
#include <stdint.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <unistd.h>

#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER 0x59616d61
#endif

volatile int32_t ce_value = 1234567;
volatile int32_t* volatile ce_pointer = &ce_value;

__attribute__((noinline)) int32_t ce_writer(void) {
    ce_value = ce_value + 1;
    return ce_value;
}

int main(void) {
    /* Let a sibling tool attach under Yama ptrace_scope=1, as a game would
     * be attached from a separately launched cheat engine. */
    prctl(PR_SET_PTRACER, (unsigned long)-1, 0, 0, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("CE_STATIC %d %p %p %p\n", (int)getpid(), (void*)&ce_value, (void*)&ce_pointer, (void*)ce_writer);
    for (int command; (command = getchar()) != EOF;) {
        if (command == 'b') printf("%d\n", (int)ce_writer());
        else if (command == 'r') printf("%d\n", (int)ce_value);
        else if (command == 'q') break;
    }
    return 0;
}
