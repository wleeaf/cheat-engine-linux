/* inprocess_veh.c — in-process exception handler shim, the Linux equivalent
 * of CE's VEHDebugger.
 *
 * Loaded into the target process via LD_PRELOAD (or via the loadlibrary()
 * AA directive). The shim installs sigaction handlers for the common CPU
 * trap signals — SIGSEGV, SIGTRAP, SIGILL, SIGFPE, SIGBUS — and writes a
 * record of every event to /tmp/cecore_veh_<pid>.log (one line per event:
 * `signo addr rip pid_tid` in hex).
 *
 * After logging, the previous handler (if any) is invoked so the target
 * keeps its own crash semantics. When no previous handler exists the
 * default disposition (usually terminate) takes over.
 *
 * Use case: when ptrace can't be used against a target (anti-debug,
 * container without CAP_SYS_PTRACE, sandboxed Wine session) but
 * LD_PRELOAD can — drop this in and read the log alongside.
 *
 * Build target: libcecore_inprocess_veh.so. Use:
 *   LD_PRELOAD=$PWD/build/libcecore_inprocess_veh.so ./target
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>

static FILE* g_log = NULL;
static int g_log_fd = -1;   // raw fd for async-signal-safe writes from the handler
static struct sigaction g_prev[NSIG];
static int g_installed = 0;

static pid_t cecore_gettid(void) {
    return (pid_t)syscall(SYS_gettid);
}

// ── async-signal-safe formatting helpers ──
// fprintf/fflush are NOT async-signal-safe (they take stdio locks), so the
// signal handler must not use them. These build a line into a stack buffer and
// emit it with a single write(2), which is async-signal-safe.

// Append a NUL-terminated string; returns new length. Never overflows cap.
static size_t as_append(char* buf, size_t len, size_t cap, const char* s) {
    while (*s && len + 1 < cap) buf[len++] = *s++;
    return len;
}

// Append an unsigned long as decimal.
static size_t as_append_dec(char* buf, size_t len, size_t cap, unsigned long v) {
    char tmp[20];
    int n = 0;
    if (v == 0) tmp[n++] = '0';
    while (v && n < (int)sizeof(tmp)) { tmp[n++] = (char)('0' + (v % 10)); v /= 10; }
    while (n > 0 && len + 1 < cap) buf[len++] = tmp[--n];
    return len;
}

// Append an unsigned long as 0x-prefixed hex.
static size_t as_append_hex(char* buf, size_t len, size_t cap, unsigned long v) {
    static const char hexd[] = "0123456789abcdef";
    char tmp[16];
    int n = 0;
    len = as_append(buf, len, cap, "0x");
    if (v == 0) tmp[n++] = '0';
    while (v && n < (int)sizeof(tmp)) { tmp[n++] = hexd[v & 0xf]; v >>= 4; }
    while (n > 0 && len + 1 < cap) buf[len++] = tmp[--n];
    return len;
}

static const char* cecore_signal_name(int sig) {
    switch (sig) {
        case SIGSEGV: return "SIGSEGV";
        case SIGTRAP: return "SIGTRAP";
        case SIGILL:  return "SIGILL";
        case SIGFPE:  return "SIGFPE";
        case SIGBUS:  return "SIGBUS";
        default: return "SIG?";
    }
}

static void cecore_log_event(int signo, siginfo_t* info, void* ucontext) {
    if (g_log_fd < 0) return;
    ucontext_t* uc = (ucontext_t*)ucontext;
#if defined(__x86_64__)
    unsigned long rip = (unsigned long)uc->uc_mcontext.gregs[REG_RIP];
#elif defined(__i386__)
    unsigned long rip = (unsigned long)uc->uc_mcontext.gregs[REG_EIP];
#elif defined(__aarch64__)
    unsigned long rip = (unsigned long)uc->uc_mcontext.pc;
#else
    unsigned long rip = 0;
    (void)uc;
#endif
    unsigned long addr = info ? (unsigned long)info->si_addr : 0;

    // Build the line into a stack buffer and emit it with a single
    // async-signal-safe write(2) — no stdio, no locks.
    char line[256];
    size_t n = 0;
    n = as_append(line, n, sizeof(line), cecore_signal_name(signo));
    n = as_append(line, n, sizeof(line), " signo=");
    n = as_append_dec(line, n, sizeof(line), (unsigned long)signo);
    n = as_append(line, n, sizeof(line), " addr=");
    n = as_append_hex(line, n, sizeof(line), addr);
    n = as_append(line, n, sizeof(line), " rip=");
    n = as_append_hex(line, n, sizeof(line), rip);
    n = as_append(line, n, sizeof(line), " code=");
    n = as_append_dec(line, n, sizeof(line), (unsigned long)(info ? info->si_code : 0));
    n = as_append(line, n, sizeof(line), " tid=");
    n = as_append_dec(line, n, sizeof(line), (unsigned long)cecore_gettid());
    n = as_append(line, n, sizeof(line), " pid=");
    n = as_append_dec(line, n, sizeof(line), (unsigned long)getpid());
    n = as_append(line, n, sizeof(line), "\n");
    ssize_t w = write(g_log_fd, line, n);
    (void)w;
}

static void cecore_handler(int signo, siginfo_t* info, void* ucontext) {
    if (signo < 0 || signo >= NSIG) return;  // defensive: never index OOB
    cecore_log_event(signo, info, ucontext);

    // TODO(security): a genuine SIGSEGV chained to a handler that resumes the
    // faulting instruction re-enters this handler in a tight loop; restore
    // SIG_DFL for fatal CPU traps and install a sigaltstack so a stack-overflow
    // fault can still be handled. Left as a follow-up to avoid changing the
    // best-effort chaining semantics here.

    // Chain to the previous handler so the target's behaviour is preserved.
    struct sigaction* prev = &g_prev[signo];
    if (prev->sa_flags & SA_SIGINFO) {
        if (prev->sa_sigaction && prev->sa_sigaction != (void*)SIG_DFL &&
            prev->sa_sigaction != (void*)SIG_IGN) {
            prev->sa_sigaction(signo, info, ucontext);
            return;
        }
    } else {
        if (prev->sa_handler && prev->sa_handler != SIG_DFL && prev->sa_handler != SIG_IGN) {
            prev->sa_handler(signo);
            return;
        }
    }

    // Restore default disposition + re-raise so the kernel can do its thing
    // (core dump, terminate, …).
    signal(signo, SIG_DFL);
    raise(signo);
}

static void cecore_install_one(int signo) {
    if (signo < 0 || signo >= NSIG) return;  // defensive: never index OOB
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = cecore_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    sigaction(signo, &sa, &g_prev[signo]);
}

__attribute__((constructor))
static void cecore_veh_init(void) {
    if (g_installed) return;
    g_installed = 1;

    char path[256];
    snprintf(path, sizeof(path), "/tmp/cecore_veh_%d.log", (int)getpid());
    g_log = fopen(path, "a");
    if (g_log) setvbuf(g_log, NULL, _IOLBF, 0);

    // Raw append-only fd for the signal handler's async-signal-safe write(2).
    // O_CLOEXEC keeps it out of any child the target execs.
    g_log_fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);

    int sigs[] = { SIGSEGV, SIGTRAP, SIGILL, SIGFPE, SIGBUS };
    for (size_t i = 0; i < sizeof(sigs)/sizeof(sigs[0]); ++i)
        cecore_install_one(sigs[i]);

    if (g_log) {
        fprintf(g_log, "cecore VEH attached: pid=%d\n", (int)getpid());
        fflush(g_log);
    }
}

__attribute__((destructor))
static void cecore_veh_shutdown(void) {
    if (g_log) {
        fprintf(g_log, "cecore VEH detached: pid=%d\n", (int)getpid());
        fclose(g_log);
        g_log = NULL;
    }
    if (g_log_fd >= 0) {
        close(g_log_fd);
        g_log_fd = -1;
    }
}
