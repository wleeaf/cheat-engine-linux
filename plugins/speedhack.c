/// Speedhack — LD_PRELOAD library that intercepts time functions.
/// Usage: CE_SPEED=2.0 LD_PRELOAD=./libspeedhack.so ./game
/// Speed > 1.0 = faster, < 1.0 = slower

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <locale.h>
#include <time.h>
#include <sys/time.h>
#include <sys/select.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <link.h>    // dl_iterate_phdr, struct dl_phdr_info
#include <elf.h>

static double speed_factor = 1.0;
static int initialized = 0;

// Real clock_gettime, resolved once before init so init never re-enters the
// interposer (see clock_gettime override below).
typedef int (*clock_gettime_t)(clockid_t, struct timespec*);
static clock_gettime_t real_clock_gettime = NULL;

// Shared memory for runtime speed control
static double* shared_speed = NULL;
static const char* SHM_NAME = "/ce_speedhack";

// Sane bounds for the speed multiplier. Anything outside this range (or NaN/
// inf, or a poisoned shared-memory value) is treated as 1.0 so neither the
// fake-time math nor the sleep-scaling math can overflow or go non-finite.
#define CE_SPEED_MIN 0.01
#define CE_SPEED_MAX 1000.0

static double clamp_speed(double v) {
    if (!isfinite(v) || v < CE_SPEED_MIN || v > CE_SPEED_MAX) return 1.0;
    return v;
}

// Parse CE_SPEED with a forced C locale so "1.5" is read with a '.' decimal even
// when we are injected (dlopen) into a running game that already activated a
// comma-decimal locale — plain atof() would otherwise read "1.5" as 1.0.
static double parse_ce_speed(const char* s) {
    locale_t c = newlocale(LC_NUMERIC_MASK, "C", (locale_t)0);
    if (c == (locale_t)0) return atof(s);   // fallback: better than nothing
    locale_t prev = uselocale(c);
    double v = strtod(s, NULL);
    uselocale(prev);
    freelocale(c);
    return v;
}

static void init_speedhack() {
    if (initialized) return;
    initialized = 1;

    // Resolve the real clock_gettime first; never call the interposed name
    // from here or adjust_time would corrupt the (not yet set) baseline.
    if (!real_clock_gettime)
        real_clock_gettime = (clock_gettime_t)dlsym(RTLD_NEXT, "clock_gettime");

    // Get speed from environment
    const char* env = getenv("CE_SPEED");
    if (env) speed_factor = clamp_speed(parse_ce_speed(env));
    if (speed_factor <= 0) speed_factor = 1.0;

    // Try to open shared memory for runtime control. O_NOFOLLOW refuses a
    // symlink-swapped /dev/shm entry; 0600 keeps the channel same-user only.
    // NOTE: the name is fixed by contract with gui/mainwindow.cpp (the writer)
    // and audiohack.cpp; per-pid namespacing must be coordinated across all
    // three (see followup).
    int fd = shm_open(SHM_NAME, O_CREAT | O_RDWR | O_NOFOLLOW, 0600);
    // Only a channel this user owns and nobody else can write: a file another
    // user created could be truncated under the mapping (SIGBUS in the game).
    struct stat st;
    if (fd >= 0 && (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 077))) {
        close(fd);
        fd = -1;
    }
    if (fd >= 0) {
        // The channel is shared by every process the plugin is loaded in: a
        // second game starting must not reset the speed the first runs at.
        // Seed it only when it is new, or when CE_SPEED asks for a speed.
        const int seed = env != NULL || st.st_size < (off_t)sizeof(double);
        if (ftruncate(fd, sizeof(double)) != 0) {
            close(fd);
        } else {
            shared_speed = mmap(NULL, sizeof(double), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            if (shared_speed != MAP_FAILED) {
                if (seed) *shared_speed = speed_factor;
            } else {
                shared_speed = NULL;
            }
            close(fd);
        }
    }

    fprintf(stderr, "[speedhack] initialized, speed=%.2f\n", speed_factor);
}

// Repoint every loaded module's GOT slots for the time functions at our
// wrappers, so we also take effect when injected via dlopen (defined below).
static void speedhack_install_got_hooks(void);
static void sh_atfork_child(void);

// Capture the baseline race-free before any game thread runs, matching the
// constructor approach used by audiohack/inprocess_veh.
__attribute__((constructor))
static void speedhack_ctor(void) {
    init_speedhack();
    pthread_atfork(NULL, NULL, sh_atfork_child);
    // Symbol interposition (the wrappers) only fires under LD_PRELOAD; when we
    // are dlopen-injected into a running process the GOT is already bound to
    // libc, so also patch it directly.
    speedhack_install_got_hooks();
}

static double get_speed() {
    double v = shared_speed ? *shared_speed : speed_factor;
    return clamp_speed(v);
}

// A clock seen at the game's speed. Each clock keeps its own base, and is
// rebased whenever the speed changes, so the fake time stays continuous: a
// change from 2x back to 1x must not send a monotonic clock backwards, and
// the wall clock must not be scaled against the monotonic clock's origin.
// Clocks are read from any thread (and from signal handlers), so the base
// sits behind a seqlock instead of a mutex.
typedef struct {
    clockid_t id;
    unsigned long seq;         // odd while a rebase is being written
    int64_t base_real_ns;
    int64_t base_fake_ns;
    uint64_t speed_bits;       // the double the base was taken at; 0 = not started
} sh_clock_t;

static sh_clock_t sh_monotonic = {.id = CLOCK_MONOTONIC};
static sh_clock_t sh_monotonic_raw = {.id = CLOCK_MONOTONIC_RAW};
static sh_clock_t sh_realtime = {.id = CLOCK_REALTIME};

static int64_t sh_scale_elapsed(int64_t elapsed_ns, double speed) {
    if (elapsed_ns <= 0) return 0;   // read before another thread's rebase
    double scaled = (double)elapsed_ns * speed;
    if (!isfinite(scaled) || scaled > (double)(INT64_MAX / 4)) scaled = (double)(INT64_MAX / 4);
    return (int64_t)scaled;
}

// The fake time for a real reading `now_ns` of clock c.
static int64_t sh_fake_time(sh_clock_t* c, int64_t now_ns) {
    const double speed = get_speed();
    uint64_t want_bits;
    memcpy(&want_bits, &speed, sizeof want_bits);
    for (;;) {
        unsigned long seq = __atomic_load_n(&c->seq, __ATOMIC_ACQUIRE);
        if (seq & 1) continue;
        const int64_t base_real = __atomic_load_n(&c->base_real_ns, __ATOMIC_RELAXED);
        const int64_t base_fake = __atomic_load_n(&c->base_fake_ns, __ATOMIC_RELAXED);
        const uint64_t bits = __atomic_load_n(&c->speed_bits, __ATOMIC_RELAXED);
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        if (__atomic_load_n(&c->seq, __ATOMIC_RELAXED) != seq) continue;
        double base_speed;
        memcpy(&base_speed, &bits, sizeof base_speed);
        if (bits == want_bits)
            return base_fake + sh_scale_elapsed(now_ns - base_real, base_speed);
        // Not started, or the speed changed: rebase at now, continuing from
        // where the old speed had taken the clock. Signals stay blocked while
        // seq is odd: a handler on this thread reading the clock would
        // otherwise wait for a rebase that cannot finish.
        sigset_t all, previous;
        sigfillset(&all);
        pthread_sigmask(SIG_BLOCK, &all, &previous);
        if (!__atomic_compare_exchange_n(&c->seq, &seq, seq + 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            pthread_sigmask(SIG_SETMASK, &previous, NULL);
            continue;
        }
        // Rebase at the current time, not at the caller's reading: another
        // thread may have read the clock later and returned a time from the
        // old base, and the new base must not start behind that.
        int64_t at = now_ns;
        struct timespec fresh;
        if (real_clock_gettime && real_clock_gettime(c->id, &fresh) == 0) {
            const int64_t f = (int64_t)fresh.tv_sec * 1000000000LL + fresh.tv_nsec;
            if (f > at) at = f;
        }
        if (bits && at < base_real) at = base_real;
        const int64_t fake_now = bits ? base_fake + sh_scale_elapsed(at - base_real, base_speed) : at;
        // Fake base first: a fork that copies a half-written rebase (see
        // sh_atfork_child) then sees the clock jump forward, never back.
        __atomic_store_n(&c->base_fake_ns, fake_now, __ATOMIC_RELEASE);
        __atomic_store_n(&c->base_real_ns, at, __ATOMIC_RELEASE);
        __atomic_store_n(&c->speed_bits, want_bits, __ATOMIC_RELEASE);
        __atomic_store_n(&c->seq, seq + 2, __ATOMIC_RELEASE);
        pthread_sigmask(SIG_SETMASK, &previous, NULL);
        return fake_now;
    }
}

// A fork while another thread was mid-rebase copies an odd seq that nothing
// in the child will ever make even again: every clock read would spin.
static void sh_atfork_child(void) {
    sh_clock_t* clocks[] = {&sh_monotonic, &sh_monotonic_raw, &sh_realtime};
    for (size_t i = 0; i < sizeof clocks / sizeof clocks[0]; i++) {
        unsigned long seq = __atomic_load_n(&clocks[i]->seq, __ATOMIC_RELAXED);
        if (seq & 1) __atomic_store_n(&clocks[i]->seq, seq + 1, __ATOMIC_RELEASE);
    }
}

static void adjust_time(sh_clock_t* c, struct timespec* ts) {
    if (!initialized) init_speedhack();
    const int64_t now = (int64_t)ts->tv_sec * 1000000000LL + ts->tv_nsec;
    const int64_t fake = sh_fake_time(c, now);
    ts->tv_sec = (time_t)(fake / 1000000000LL);
    ts->tv_nsec = (long)(fake % 1000000000LL);
}

// ── Intercepted functions ──
// TODO(security): the per-wrapper lazy dlsym(RTLD_NEXT) statics below are not
// resolved under call_once; the race is benign (idempotent pointer write) but
// should eventually move to a single constructor-time resolution.

typedef int (*gettimeofday_t)(struct timeval*, void*);
typedef int (*nanosleep_t)(const struct timespec*, struct timespec*);

int clock_gettime(clockid_t clk_id, struct timespec* tp) {
    if (!real_clock_gettime) real_clock_gettime = (clock_gettime_t)dlsym(RTLD_NEXT, "clock_gettime");
    if (!real_clock_gettime) { errno = ENOSYS; return -1; }
    int ret = real_clock_gettime(clk_id, tp);
    if (ret == 0 && clk_id == CLOCK_MONOTONIC) adjust_time(&sh_monotonic, tp);
    else if (ret == 0 && clk_id == CLOCK_MONOTONIC_RAW) adjust_time(&sh_monotonic_raw, tp);
    return ret;
}

int gettimeofday(struct timeval* tv, void* tz) {
    static gettimeofday_t real_fn = NULL;
    if (!real_fn) real_fn = (gettimeofday_t)dlsym(RTLD_NEXT, "gettimeofday");
    if (!real_fn) { errno = ENOSYS; return -1; }
    int ret = real_fn(tv, tz);
    if (ret == 0 && tv) {   // tv may be NULL (only the time zone wanted)
        struct timespec ts = { tv->tv_sec, tv->tv_usec * 1000 };
        adjust_time(&sh_realtime, &ts);
        tv->tv_sec = ts.tv_sec;
        tv->tv_usec = ts.tv_nsec / 1000;
    }
    return ret;
}

// An interrupted sleep reports what is left in real time; the caller will
// sleep that again through us, so report it in game time.
static void sh_remaining_to_game_time(struct timespec* rem, double spd) {
    if (!rem) return;
    double ns = ((double)rem->tv_sec * 1e9 + (double)rem->tv_nsec) * spd;
    if (!isfinite(ns) || ns < 0) ns = 0;
    if (ns > (double)LONG_MAX * 1e9) ns = (double)LONG_MAX * 1e9;
    rem->tv_sec = (time_t)(ns / 1e9);
    rem->tv_nsec = (long)(ns - (double)rem->tv_sec * 1e9);
    if (rem->tv_nsec < 0) rem->tv_nsec = 0;
    if (rem->tv_nsec >= 1000000000L) rem->tv_nsec = 999999999L;
}

// The real-time span of a game-time span, saturating instead of overflowing.
// Returns 0 when the request should go through unchanged: speed 1, or a
// malformed timespec the kernel has to reject with EINVAL.
static int sh_real_span(const struct timespec* req, double spd, struct timespec* out) {
    if (!req || spd == 1.0 || req->tv_sec < 0 || req->tv_nsec < 0 || req->tv_nsec >= 1000000000L) return 0;
    double secs = ((double)req->tv_sec + (double)req->tv_nsec / 1e9) / spd;
    if (!isfinite(secs) || secs < 0) secs = 0;
    if (secs >= (double)LONG_MAX) {
        out->tv_sec = (time_t)LONG_MAX;
        out->tv_nsec = 999999999L;
        return 1;
    }
    out->tv_sec = (time_t)secs;
    long ns = (long)((secs - (double)out->tv_sec) * 1e9);
    if (ns < 0) ns = 0;
    if (ns > 999999999L) ns = 999999999L;
    out->tv_nsec = ns;
    return 1;
}

int nanosleep(const struct timespec* req, struct timespec* rem) {
    static nanosleep_t real_fn = NULL;
    if (!real_fn) real_fn = (nanosleep_t)dlsym(RTLD_NEXT, "nanosleep");
    if (!real_fn) { errno = ENOSYS; return -1; }
    if (!initialized) init_speedhack();

    double spd = get_speed();
    struct timespec adjusted;
    if (!sh_real_span(req, spd, &adjusted)) return real_fn(req, rem);
    int ret = real_fn(&adjusted, rem);
    if (ret != 0 && errno == EINTR) sh_remaining_to_game_time(rem, spd);
    return ret;
}

// clock_nanosleep — same semantics, called by many newer codebases. Only
// scale the relative form (TIMER_ABSTIME is honoured by the kernel against
// the OS clock; rescaling it would break alarm-style waits).
int clock_nanosleep(clockid_t clk, int flags, const struct timespec* req, struct timespec* rem) {
    typedef int (*fn_t)(clockid_t, int, const struct timespec*, struct timespec*);
    static fn_t real_fn = NULL;
    if (!real_fn) real_fn = (fn_t)dlsym(RTLD_NEXT, "clock_nanosleep");
    if (!real_fn) { errno = ENOSYS; return ENOSYS; }
    if (!initialized) init_speedhack();
    double spd = get_speed();
    struct timespec adjusted;
    if ((flags & TIMER_ABSTIME) || !sh_real_span(req, spd, &adjusted)) return real_fn(clk, flags, req, rem);
    int ret = real_fn(clk, flags, &adjusted, rem);
    if (ret == EINTR) sh_remaining_to_game_time(rem, spd);
    return ret;
}

// usleep — legacy POSIX microsecond sleep, still used by many games.
int usleep(useconds_t usec) {
    typedef int (*fn_t)(useconds_t);
    static fn_t real_fn = NULL;
    if (!real_fn) real_fn = (fn_t)dlsym(RTLD_NEXT, "usleep");
    if (!real_fn) { errno = ENOSYS; return -1; }
    if (!initialized) init_speedhack();
    double spd = get_speed();
    if (spd == 1.0) return real_fn(usec);
    // At a slow speed the scaled span can pass useconds_t's range; sleep it
    // as a timespec instead of wrapping it.
    double us = (double)usec / spd;
    if (us < 4294967295.0) return real_fn((useconds_t)us);
    struct timespec req = { .tv_sec = (time_t)usec / 1000000, .tv_nsec = (long)(usec % 1000000) * 1000 };
    struct timespec adjusted;
    sh_real_span(&req, spd, &adjusted);
    static nanosleep_t real_nanosleep = NULL;
    if (!real_nanosleep) real_nanosleep = (nanosleep_t)dlsym(RTLD_NEXT, "nanosleep");
    if (!real_nanosleep) { errno = ENOSYS; return -1; }
    return real_nanosleep(&adjusted, NULL);
}

// sleep — coarse second-granularity. CE-style: integer divide by speed.
unsigned int sleep(unsigned int seconds) {
    typedef unsigned int (*fn_t)(unsigned int);
    static fn_t real_fn = NULL;
    if (!real_fn) real_fn = (fn_t)dlsym(RTLD_NEXT, "sleep");
    if (!real_fn) return seconds;
    if (!initialized) init_speedhack();
    double spd = get_speed();
    if (spd == 1.0 || seconds == 0) return real_fn(seconds);
    // Sleep the exact scaled span (sleep(1) at 2x is half a second, not one
    // or none), and report an interruption's remainder in game seconds.
    static nanosleep_t real_nanosleep = NULL;
    if (!real_nanosleep) real_nanosleep = (nanosleep_t)dlsym(RTLD_NEXT, "nanosleep");
    if (!real_nanosleep) return real_fn(seconds);
    struct timespec req = { .tv_sec = (time_t)seconds, .tv_nsec = 0 }, adjusted, rem = {0, 0};
    sh_real_span(&req, spd, &adjusted);
    if (real_nanosleep(&adjusted, &rem) == 0) return 0;
    // Round up by hand: the plugin does not link libm, and a game that does
    // not either would fail to load it.
    double left = ((double)rem.tv_sec + (double)rem.tv_nsec / 1e9) * spd;
    if (!isfinite(left) || left < 0 || left >= (double)seconds) return seconds;
    unsigned int whole = (unsigned int)left;
    return whole < left ? whole + 1 : whole;
}

// select / pselect timeout scaling. Returning fd-readiness verbatim, but
// scaling the timeout so a 100ms select at speed=2.0 becomes a 50ms select.
int select(int nfds, fd_set* r, fd_set* w, fd_set* e, struct timeval* timeout) {
    typedef int (*fn_t)(int, fd_set*, fd_set*, fd_set*, struct timeval*);
    static fn_t real_fn = NULL;
    if (!real_fn) real_fn = (fn_t)dlsym(RTLD_NEXT, "select");
    if (!real_fn) { errno = ENOSYS; return -1; }
    if (!initialized) init_speedhack();
    double spd = get_speed();
    struct timespec req, span;
    if (timeout) {
        req.tv_sec = timeout->tv_sec;
        req.tv_nsec = timeout->tv_usec >= 0 && timeout->tv_usec < 1000000 ? (long)timeout->tv_usec * 1000 : -1;
    }
    if (!timeout || !sh_real_span(&req, spd, &span)) return real_fn(nfds, r, w, e, timeout);
    struct timeval adj = { .tv_sec = span.tv_sec, .tv_usec = (suseconds_t)(span.tv_nsec / 1000) };
    int ret = real_fn(nfds, r, w, e, &adj);
    // Linux reports the time left in *timeout; report it in game time.
    struct timespec left = { adj.tv_sec, (long)adj.tv_usec * 1000 };
    sh_remaining_to_game_time(&left, spd);
    timeout->tv_sec = left.tv_sec;
    timeout->tv_usec = (suseconds_t)(left.tv_nsec / 1000);
    return ret;
}

int poll(struct pollfd* fds, nfds_t nfds, int timeout) {
    typedef int (*fn_t)(struct pollfd*, nfds_t, int);
    static fn_t real_fn = NULL;
    if (!real_fn) real_fn = (fn_t)dlsym(RTLD_NEXT, "poll");
    if (!real_fn) { errno = ENOSYS; return -1; }
    if (!initialized) init_speedhack();
    double spd = get_speed();
    int adjusted = timeout;
    if (timeout > 0 && spd != 1.0) {
        double ms = timeout / spd;
        adjusted = ms >= (double)INT_MAX ? INT_MAX : (int)ms;
        if (adjusted == 0) adjusted = 1;
    }
    return real_fn(fds, nfds, adjusted);
}

// No SDL_GetTicks/SDL_Delay hooks: SDL takes its ticks from clock_gettime and
// sleeps with nanosleep, which are scaled already; hooking both scaled SDL
// games twice (2x became 4x).

// ── In-process GOT patching (covers dlopen injection) ──
// The wrappers above interpose by name, which only works when we load first
// (LD_PRELOAD). When cecore injects libspeedhack.so into an already-running
// process, every module's GOT is already bound to the real libc functions, so
// the wrappers never run. We walk each loaded module's relocations and repoint
// the GOT slots for the time functions at our wrappers. Only modules that
// *import* these functions carry such slots, so libc's own definitions are
// untouched and our wrappers (which call the real function via dlsym(RTLD_NEXT))
// don't recurse.

typedef struct { const char* name; void* fn; } sh_hook_t;

static const sh_hook_t sh_hooks[] = {
    {"clock_gettime",   (void*)clock_gettime},
    {"gettimeofday",    (void*)gettimeofday},
    {"nanosleep",       (void*)nanosleep},
    {"clock_nanosleep", (void*)clock_nanosleep},
    {"usleep",          (void*)usleep},
    {"sleep",           (void*)sleep},
    {"select",          (void*)select},
    {"poll",            (void*)poll},
};
static const int sh_nhooks = (int)(sizeof(sh_hooks) / sizeof(sh_hooks[0]));
static void* sh_self_base = NULL;

// DT_* pointers are absolute on some libcs and load-base-relative on others;
// normalise to an absolute runtime address. Relocation r_offsets are always
// base-relative and handled separately.
static uintptr_t sh_fix(struct dl_phdr_info* info, uintptr_t v) {
    return (v < info->dlpi_addr) ? v + info->dlpi_addr : v;
}

// Whether page lies in the module's RELRO range, which the loader made
// read-only after relocation (it protects whole pages from the range's
// rounded-down start to its rounded-down end).
static int sh_page_in_relro(struct dl_phdr_info* info, uintptr_t page, uintptr_t ps) {
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type != PT_GNU_RELRO) continue;
        uintptr_t lo = (info->dlpi_addr + info->dlpi_phdr[i].p_vaddr) & ~(ps - 1);
        uintptr_t hi = (info->dlpi_addr + info->dlpi_phdr[i].p_vaddr + info->dlpi_phdr[i].p_memsz) & ~(ps - 1);
        if (page >= lo && page < hi) return 1;
    }
    return 0;
}

static void sh_patch_slot(struct dl_phdr_info* info, void** slot, void* newval) {
    if (*slot == newval) return;
    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0) ps = 4096;
    uintptr_t page = (uintptr_t)slot & ~(uintptr_t)(ps - 1);
    // Make the containing page(s) writable (GOT is read-only under RELRO/BIND_NOW).
    size_t span = ((uintptr_t)slot + sizeof(void*) > page + (uintptr_t)ps)
                      ? (size_t)(2 * ps) : (size_t)ps;
    if (mprotect((void*)page, span, PROT_READ | PROT_WRITE) != 0) return;
    *slot = newval;
    // Hand RELRO pages back read-only, or the game is left with a writable
    // GOT for anything else to redirect.
    for (uintptr_t p = page; p < page + span; p += (uintptr_t)ps)
        if (sh_page_in_relro(info, p, (uintptr_t)ps)) mprotect((void*)p, (size_t)ps, PROT_READ);
}

static void sh_scan_rela(struct dl_phdr_info* info, const Elf64_Rela* rela,
                         size_t sz, const Elf64_Sym* symtab, const char* strtab) {
    if (!rela || !sz) return;
    size_t n = sz / sizeof(Elf64_Rela);
    for (size_t i = 0; i < n; i++) {
        uint32_t type = ELF64_R_TYPE(rela[i].r_info);
        if (type != R_X86_64_JUMP_SLOT && type != R_X86_64_GLOB_DAT) continue;
        uint32_t si = ELF64_R_SYM(rela[i].r_info);
        const char* name = strtab + symtab[si].st_name;
        if (!name || !name[0]) continue;
        for (int h = 0; h < sh_nhooks; h++) {
            if (strcmp(name, sh_hooks[h].name) == 0) {
                void** slot = (void**)(info->dlpi_addr + rela[i].r_offset);
                sh_patch_slot(info, slot, sh_hooks[h].fn);
                break;
            }
        }
    }
}

static int sh_phdr_cb(struct dl_phdr_info* info, size_t size, void* data) {
    (void)size; (void)data;
    if (sh_self_base && (void*)info->dlpi_addr == sh_self_base) return 0;  // skip self

    const Elf64_Dyn* dyn = NULL;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            dyn = (const Elf64_Dyn*)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return 0;

    const Elf64_Sym* symtab = NULL; const char* strtab = NULL;
    const Elf64_Rela* jmprel = NULL; size_t pltrelsz = 0;
    const Elf64_Rela* rela = NULL;   size_t relasz = 0;
    for (const Elf64_Dyn* d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
            case DT_SYMTAB:   symtab = (const Elf64_Sym*)sh_fix(info, d->d_un.d_ptr); break;
            case DT_STRTAB:   strtab = (const char*)sh_fix(info, d->d_un.d_ptr); break;
            case DT_JMPREL:   jmprel = (const Elf64_Rela*)sh_fix(info, d->d_un.d_ptr); break;
            case DT_PLTRELSZ: pltrelsz = d->d_un.d_val; break;
            case DT_RELA:     rela = (const Elf64_Rela*)sh_fix(info, d->d_un.d_ptr); break;
            case DT_RELASZ:   relasz = d->d_un.d_val; break;
        }
    }
    if (!symtab || !strtab) return 0;
    sh_scan_rela(info, jmprel, pltrelsz, symtab, strtab);   // .rela.plt (JUMP_SLOT)
    sh_scan_rela(info, rela, relasz, symtab, strtab);       // .rela.dyn (GLOB_DAT, -fno-plt)
    return 0;
}

static void speedhack_install_got_hooks(void) {
    static int done = 0;
    if (done) return;
    done = 1;
    Dl_info di;
    if (dladdr((void*)speedhack_install_got_hooks, &di))
        sh_self_base = di.dli_fbase;   // don't repoint our own GOT
    dl_iterate_phdr(sh_phdr_cb, NULL);
}
