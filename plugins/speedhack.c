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
#include <fcntl.h>
#include <unistd.h>
#include <link.h>    // dl_iterate_phdr, struct dl_phdr_info
#include <elf.h>

static double speed_factor = 1.0;
static struct timespec base_real_time;
static struct timespec base_fake_time;
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

    // Record base time via the REAL libc clock_gettime (not the interposer).
    if (real_clock_gettime)
        real_clock_gettime(CLOCK_MONOTONIC, &base_real_time);
    base_fake_time = base_real_time;

    // Try to open shared memory for runtime control. O_NOFOLLOW refuses a
    // symlink-swapped /dev/shm entry; 0600 keeps the channel same-user only.
    // NOTE: the name is fixed by contract with gui/mainwindow.cpp (the writer)
    // and audiohack.cpp; per-pid namespacing must be coordinated across all
    // three (see followup).
    int fd = shm_open(SHM_NAME, O_CREAT | O_RDWR | O_NOFOLLOW, 0600);
    if (fd >= 0) {
        if (ftruncate(fd, sizeof(double)) != 0) {
            close(fd);
        } else {
            shared_speed = mmap(NULL, sizeof(double), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            if (shared_speed != MAP_FAILED) {
                *shared_speed = speed_factor;
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

// Capture the baseline race-free before any game thread runs, matching the
// constructor approach used by audiohack/inprocess_veh.
__attribute__((constructor))
static void speedhack_ctor(void) {
    init_speedhack();
    // Symbol interposition (the wrappers) only fires under LD_PRELOAD; when we
    // are dlopen-injected into a running process the GOT is already bound to
    // libc, so also patch it directly.
    speedhack_install_got_hooks();
}

static double get_speed() {
    double v = shared_speed ? *shared_speed : speed_factor;
    return clamp_speed(v);
}

static void adjust_time(struct timespec* ts) {
    if (!initialized) init_speedhack();
    double spd = get_speed();

    // Calculate elapsed real time since init
    double real_elapsed = (ts->tv_sec - base_real_time.tv_sec) +
                          (ts->tv_nsec - base_real_time.tv_nsec) / 1e9;

    // Scale it
    double fake_elapsed = real_elapsed * spd;

    // Clamp to the representable tv_sec range before the double->long cast;
    // an out-of-range cast is UB and would produce a garbage clock.
    double max_secs = (double)(LONG_MAX - base_fake_time.tv_sec - 1);
    if (!isfinite(fake_elapsed) || fake_elapsed < 0) fake_elapsed = 0;
    if (fake_elapsed > max_secs) fake_elapsed = max_secs;

    // Add to base fake time
    ts->tv_sec = base_fake_time.tv_sec + (long)fake_elapsed;
    ts->tv_nsec = base_fake_time.tv_nsec + (long)((fake_elapsed - (long)fake_elapsed) * 1e9);
    if (ts->tv_nsec >= 1000000000L) { ts->tv_sec++; ts->tv_nsec -= 1000000000L; }
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
    if (ret == 0 && (clk_id == CLOCK_MONOTONIC || clk_id == CLOCK_MONOTONIC_RAW))
        adjust_time(tp);
    return ret;
}

int gettimeofday(struct timeval* tv, void* tz) {
    static gettimeofday_t real_fn = NULL;
    if (!real_fn) real_fn = (gettimeofday_t)dlsym(RTLD_NEXT, "gettimeofday");
    if (!real_fn) { errno = ENOSYS; return -1; }
    int ret = real_fn(tv, tz);
    if (ret == 0) {
        struct timespec ts = { tv->tv_sec, tv->tv_usec * 1000 };
        adjust_time(&ts);
        tv->tv_sec = ts.tv_sec;
        tv->tv_usec = ts.tv_nsec / 1000;
    }
    return ret;
}

int nanosleep(const struct timespec* req, struct timespec* rem) {
    static nanosleep_t real_fn = NULL;
    if (!real_fn) real_fn = (nanosleep_t)dlsym(RTLD_NEXT, "nanosleep");
    if (!real_fn) { errno = ENOSYS; return -1; }
    if (!initialized) init_speedhack();

    double spd = get_speed();
    if (spd <= 0) spd = 1.0;

    // Divide sleep duration by speed
    double sleep_ns = (req->tv_sec * 1e9 + req->tv_nsec) / spd;
    // Guard the tv_sec cast: a tiny speed can push sleep_ns past time_t range.
    double sleep_secs = sleep_ns / 1e9;
    if (!isfinite(sleep_secs) || sleep_secs < 0) sleep_secs = 0;
    if (sleep_secs > (double)LONG_MAX) sleep_secs = (double)LONG_MAX;
    struct timespec adjusted = {
        .tv_sec = (time_t)sleep_secs,
        .tv_nsec = (long)((long long)sleep_ns % 1000000000LL)
    };
    return real_fn(&adjusted, rem);
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
    if (spd <= 0 || (flags & TIMER_ABSTIME)) return real_fn(clk, flags, req, rem);

    double sleep_ns = (req->tv_sec * 1e9 + req->tv_nsec) / spd;
    // Guard the tv_sec cast: a tiny speed can push sleep_ns past time_t range.
    double sleep_secs = sleep_ns / 1e9;
    if (!isfinite(sleep_secs) || sleep_secs < 0) sleep_secs = 0;
    if (sleep_secs > (double)LONG_MAX) sleep_secs = (double)LONG_MAX;
    struct timespec adjusted = {
        .tv_sec = (time_t)sleep_secs,
        .tv_nsec = (long)((long long)sleep_ns % 1000000000LL)
    };
    return real_fn(clk, flags, &adjusted, rem);
}

// usleep — legacy POSIX microsecond sleep, still used by many games.
int usleep(useconds_t usec) {
    typedef int (*fn_t)(useconds_t);
    static fn_t real_fn = NULL;
    if (!real_fn) real_fn = (fn_t)dlsym(RTLD_NEXT, "usleep");
    if (!real_fn) { errno = ENOSYS; return -1; }
    if (!initialized) init_speedhack();
    double spd = get_speed();
    if (spd <= 0) spd = 1.0;
    useconds_t adjusted = (useconds_t)(usec / spd);
    return real_fn(adjusted);
}

// sleep — coarse second-granularity. CE-style: integer divide by speed.
unsigned int sleep(unsigned int seconds) {
    typedef unsigned int (*fn_t)(unsigned int);
    static fn_t real_fn = NULL;
    if (!real_fn) real_fn = (fn_t)dlsym(RTLD_NEXT, "sleep");
    if (!real_fn) return seconds;
    if (!initialized) init_speedhack();
    double spd = get_speed();
    if (spd <= 0) spd = 1.0;
    unsigned int adjusted = (unsigned int)(seconds / spd);
    if (adjusted == 0 && seconds > 0) adjusted = 1;  // don't completely starve
    return real_fn(adjusted);
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
    struct timeval adj;
    struct timeval* adjp = timeout;
    if (timeout && spd > 0 && spd != 1.0) {
        double us = timeout->tv_sec * 1e6 + timeout->tv_usec;
        us /= spd;
        adj.tv_sec  = (time_t)(us / 1e6);
        adj.tv_usec = (suseconds_t)((long long)us % 1000000LL);
        adjp = &adj;
    }
    return real_fn(nfds, r, w, e, adjp);
}

int poll(struct pollfd* fds, nfds_t nfds, int timeout) {
    typedef int (*fn_t)(struct pollfd*, nfds_t, int);
    static fn_t real_fn = NULL;
    if (!real_fn) real_fn = (fn_t)dlsym(RTLD_NEXT, "poll");
    if (!real_fn) { errno = ENOSYS; return -1; }
    if (!initialized) init_speedhack();
    double spd = get_speed();
    int adjusted = timeout;
    if (timeout > 0 && spd > 0 && spd != 1.0) {
        adjusted = (int)(timeout / spd);
        if (adjusted == 0) adjusted = 1;
    }
    return real_fn(fds, nfds, adjusted);
}

// SDL convenience symbols some games rely on directly (statically resolved
// builds skip this preload, but dynamically-linked SDL games pick it up).
unsigned int SDL_GetTicks(void) {
    typedef unsigned int (*fn_t)(void);
    static fn_t real_fn = NULL;
    if (!real_fn) real_fn = (fn_t)dlsym(RTLD_NEXT, "SDL_GetTicks");
    if (!real_fn) return 0;
    unsigned int raw = real_fn();
    if (!initialized) init_speedhack();
    double spd = get_speed();  // already finite/positive-clamped
    // Compute in 64-bit and clamp to the 32-bit ms range so a large raw or
    // speed can't wrap and send SDL frame pacing backwards.
    double scaled = (double)raw * spd;
    if (scaled < 0) scaled = 0;
    if (scaled > (double)UINT32_MAX) scaled = (double)UINT32_MAX;
    return (unsigned int)scaled;
}

void SDL_Delay(unsigned int ms) {
    typedef void (*fn_t)(unsigned int);
    static fn_t real_fn = NULL;
    if (!real_fn) real_fn = (fn_t)dlsym(RTLD_NEXT, "SDL_Delay");
    if (!real_fn) return;
    if (!initialized) init_speedhack();
    double spd = get_speed();
    if (spd <= 0) spd = 1.0;
    real_fn((unsigned int)(ms / spd));
}

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
    {"SDL_GetTicks",    (void*)SDL_GetTicks},
    {"SDL_Delay",       (void*)SDL_Delay},
};
static const int sh_nhooks = (int)(sizeof(sh_hooks) / sizeof(sh_hooks[0]));
static void* sh_self_base = NULL;

// DT_* pointers are absolute on some libcs and load-base-relative on others;
// normalise to an absolute runtime address. Relocation r_offsets are always
// base-relative and handled separately.
static uintptr_t sh_fix(struct dl_phdr_info* info, uintptr_t v) {
    return (v < info->dlpi_addr) ? v + info->dlpi_addr : v;
}

static void sh_patch_slot(void** slot, void* newval) {
    if (*slot == newval) return;
    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0) ps = 4096;
    uintptr_t page = (uintptr_t)slot & ~(uintptr_t)(ps - 1);
    // Make the containing page(s) writable (GOT is read-only under RELRO/BIND_NOW).
    size_t span = ((uintptr_t)slot + sizeof(void*) > page + (uintptr_t)ps)
                      ? (size_t)(2 * ps) : (size_t)ps;
    if (mprotect((void*)page, span, PROT_READ | PROT_WRITE) != 0) return;
    *slot = newval;
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
                sh_patch_slot(slot, sh_hooks[h].fn);
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
