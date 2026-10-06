#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#if defined(__x86_64__) && defined(__ILP32__)
#include <sys/mman.h>
#include <fcntl.h>
int ce_call_file_fd=-1;
uint64_t ce_call_sum64(uint64_t a,uint64_t b,uint64_t c,uint64_t d,
                       uint64_t e,uint64_t f,uint64_t g,uint64_t h) {
    return a+3*b+5*c+7*d+11*e+13*f+17*g+19*h;
}
#endif

// Exported to the injected library and observed through the process API.
_Atomic unsigned ce_call_loaded, ce_call_completed, ce_call_running;
_Atomic unsigned ce_call_release = 1, ce_call_stop;
_Atomic unsigned ce_call_heartbeat;
static pthread_t consoleThread;

void* ce_call_entry(void* argument) {
    (void)argument;
    atomic_fetch_add(&ce_call_running, 1);
    while (!atomic_load(&ce_call_release)) {}
    atomic_fetch_add(&ce_call_completed, 1);
    atomic_fetch_sub(&ce_call_running, 1);
    return 0;
}
void* ce_call_detach_entry(void* argument) {
    pthread_detach(pthread_self());
    return ce_call_entry(argument);
}
void* ce_call_exit_entry(void* argument) {
    ce_call_entry(argument);
    pthread_exit(0);
}
int ce_call_create_delayed(pthread_t* thread,const pthread_attr_t* attributes,
                           void* (*entry)(void*),void* argument) {
    while (!atomic_load(&ce_call_release)) {}
    return pthread_create(thread,attributes,entry,argument);
}

static void* console(void* argument) {
    (void)argument;
    char command;
    while (read(0, &command, 1) == 1) {
        if (command == 'x') break;
    }
    atomic_store(&ce_call_stop, 1);
    return 0;
}

static void* heartbeatLoop(void* argument) {
    (void)argument;
    while (!atomic_load(&ce_call_stop)) atomic_fetch_add(&ce_call_heartbeat,1);
    if (pthread_join(consoleThread,0)) return (void*)1;
    puts("CE_NATIVE_CALL_DONE"); fflush(stdout);
    return 0;
}

int main(int argc,char** argv) {
    if (prctl(PR_SET_PTRACER, -1L, 0, 0, 0)) return 1;
#if defined(__x86_64__) && defined(__ILP32__)
    const off_t offset=UINT64_C(0x100002000);
    const uint64_t sentinel=UINT64_C(0x7461726765747832);
    ce_call_file_fd=memfd_create("x32-wide-offset",MFD_CLOEXEC);
    if (ce_call_file_fd<0 || ftruncate(ce_call_file_fd,offset+4096) ||
        pwrite(ce_call_file_fd,&sentinel,sizeof(sentinel),offset)!=sizeof(sentinel)) return 8;
#endif
    int parked=argc==2 && !strcmp(argv[1],"--parked");
    int leaderExit=argc==2 && !strcmp(argv[1],"--leader-exit");
    if (!parked && pthread_create(&consoleThread,0,console,0)) return 2;
    printf("CE_NATIVE_CALL %u %lx %lx %lx %lx %lx %lx %lx %lx\n", (unsigned)sizeof(void*),
           (unsigned long)(uintptr_t)&ce_call_loaded, (unsigned long)(uintptr_t)&ce_call_completed,
           (unsigned long)(uintptr_t)&ce_call_running, (unsigned long)(uintptr_t)&ce_call_release,
           (unsigned long)(uintptr_t)&ce_call_heartbeat, (unsigned long)(uintptr_t)ce_call_entry,
           (unsigned long)(uintptr_t)ce_call_detach_entry,(unsigned long)(uintptr_t)ce_call_exit_entry);
    fflush(stdout);
    if (parked) {
        char begin;
        if (read(0,&begin,1)!=1 || begin!='p') return 6;
        puts("CE_NATIVE_CALL_PARKED_WAIT");
        fflush(stdout);
        // Full-system emulation can spend hundreds of milliseconds resolving
        // and rejecting a call. Keep the real relative wait alive until both
        // operations and their final memory inspection have completed.
        struct timespec delay={2,0};
        if (nanosleep(&delay,&delay)) return 5;
        puts("CE_NATIVE_CALL_PARKED_DONE");
        return 0;
    }
    if (leaderExit) {
        pthread_t worker;
        if (pthread_create(&worker,0,heartbeatLoop,0)) return 7;
        pthread_exit(0);
    }
    return heartbeatLoop(0) ? 3 : 0;
}
