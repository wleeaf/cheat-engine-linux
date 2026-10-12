/* Ordinary libc program for the real-libc frontend targets.
 *
 * Unlike compatibility_fixture.c (freestanding, no libc), this links a real C
 * library: glibc or musl, static or dynamic. It exposes a static value, a
 * static pointer to it and a non-inlined writer, and answers stdin commands:
 * 'b' runs the writer, 'r' reads the value, 's'/'x' start/stop a busy worker
 * thread (like a game loop, it is executing user code when stopped), 'q' exits.
 */
#include <pthread.h>
#include <stdatomic.h>
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

static atomic_int ce_spinning;

static void* ce_spin(void* unused) {
    (void)unused;
    while (atomic_load(&ce_spinning))
        for (volatile int i = 0; i < 1000; ++i) {}
    return NULL;
}

int main(void) {
    pthread_t spinner;
    int spinning = 0;
    /* Let a sibling tool attach under Yama ptrace_scope=1, as a game would
     * be attached from a separately launched cheat engine. */
    prctl(PR_SET_PTRACER, (unsigned long)-1, 0, 0, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("CE_STATIC %d %p %p %p\n", (int)getpid(), (void*)&ce_value, (void*)&ce_pointer, (void*)ce_writer);
    for (int command; (command = getchar()) != EOF;) {
        if (command == 'b') printf("%d\n", (int)ce_writer());
        else if (command == 'r') printf("%d\n", (int)ce_value);
        else if (command == 's') {
            if (!spinning) { atomic_store(&ce_spinning, 1); spinning = pthread_create(&spinner, NULL, ce_spin, NULL) == 0; }
            printf("%d\n", spinning);
        } else if (command == 'x') {
            if (spinning) { atomic_store(&ce_spinning, 0); pthread_join(spinner, NULL); spinning = 0; }
            printf("0\n");
        }
        else if (command == 'q') break;
    }
    return 0;
}
