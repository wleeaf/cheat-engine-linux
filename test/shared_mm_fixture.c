#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

struct peer_config { pid_t parent; int owner_fd; };
static int keep_memory(void* argument) {
    const struct peer_config config = *(struct peer_config*)argument;
    if (config.owner_fd < 0) {
        syscall(SYS_prctl, PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
        if (syscall(SYS_getppid) != config.parent) syscall(SYS_exit, 0);
    }
    syscall(SYS_close, STDIN_FILENO);
    syscall(SYS_close, STDOUT_FILENO);
    // AArch64's generic syscall table has ppoll rather than legacy pause.
    // A keepalive peer survives its original parent's death, but never the
    // test controller's death. The pidfd pins that actual controller lifetime.
    struct pollfd owner = {config.owner_fd, POLLIN, 0};
    for (;;) {
        const long ready = syscall(SYS_ppoll, config.owner_fd < 0 ? NULL : &owner,
                                   config.owner_fd < 0 ? 0 : 1, NULL, NULL, 8);
        if (ready > 0 && config.owner_fd >= 0) syscall(SYS_exit, 0);
    }
    return 0;
}

int main(int argc, char** argv) {
    const int replacement = argc == 4 && !strcmp(argv[1], "--replacement");
    const int identical = replacement ? atoi(argv[3]) : argc == 2 && !strcmp(argv[1], "--identical");
    const size_t page = (size_t)sysconf(_SC_PAGESIZE);
    unsigned char* code = mmap((void*)0x30000000, page, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    unsigned char* data = mmap((void*)0x31000000, page, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (code == MAP_FAILED || data == MAP_FAILED) return 2;
    const unsigned value = replacement && !identical ? 55 : 42;
#if defined(__aarch64__)
    const uint32_t instructions[] = {0x52800000u | (value << 5), 0xd65f03c0u};
    memcpy(code, instructions, sizeof(instructions));
#else
    const unsigned char instructions[] = {0xb8, (unsigned char)value, 0, 0, 0, 0xc3};
    memcpy(code, instructions, sizeof(instructions));
#endif
    __builtin___clear_cache((char*)code, (char*)code + page);
    if (mprotect(code, page, PROT_READ | PROT_EXEC)) return 3;
    memset(data, value, page);
    pid_t peer = replacement ? (pid_t)strtol(argv[2], NULL, 10) : -1;
    if (!replacement) {
        void* stack = mmap(NULL, page * 16, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (stack == MAP_FAILED) return 4;
        static struct peer_config config;
        config.parent = getpid(); config.owner_fd = -1;
        if (argc == 3 && !strcmp(argv[1], "--keepalive")) {
            config.owner_fd = syscall(SYS_pidfd_open, (pid_t)strtol(argv[2], NULL, 10), 0);
            if (config.owner_fd < 0) return 7;
        }
        peer = clone(keep_memory, (char*)stack + page * 16, CLONE_VM | SIGCHLD, &config);
        if (config.owner_fd >= 0) close(config.owner_fd);
        if (peer < 0) return 5;
    }
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
    printf("SHARED_READY pid=%ld peer=%ld value=%d\n", (long)getpid(), (long)peer, ((int(*)(void))code)());
    fflush(stdout);
    char command;
    while (read(STDIN_FILENO, &command, 1) == 1) {
        if (command == 'Q') break;
        if (command == 'X') {
            char id[32]; snprintf(id, sizeof(id), "%ld", (long)peer);
            execl("/proc/self/exe", "shared_mm_fixture", "--replacement", id, identical ? "1" : "0", NULL);
            return 6;
        }
        if (command == 'E') {
            printf("SHARED_VALUE=%d\n", ((int(*)(void))code)());
            fflush(stdout);
        }
        if (command == 'B') {
            data[8] = 1;
            puts("SHARED_BUSY"); fflush(stdout);
            while (*(volatile unsigned char*)(data + 8)) __asm__ volatile("" ::: "memory");
            puts("SHARED_RESUMED"); fflush(stdout);
        }
    }
    kill(peer, SIGKILL);
    while (waitpid(peer, NULL, 0) < 0 && errno == EINTR) {}
    return 0;
}
