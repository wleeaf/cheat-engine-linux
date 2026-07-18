#include <fstream>
#include <dirent.h>
#include "platform/linux/injector.hpp"

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <signal.h>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <cerrno>
#include <thread>

namespace ce::os {

// Stop a thread for hijacking via PTRACE_SEIZE + PTRACE_INTERRUPT rather than
// PTRACE_ATTACH's SIGSTOP. SEIZE gives a clean ptrace-stop that preserves an
// interrupted syscall's restart state, so hijacking a thread parked in a syscall
// resumes it cleanly. On Wine/Proton the threads sit in esync/fsync/wineserver
// syscalls almost all the time, and the old ATTACH path corrupted the wineserver
// RPC and froze the game. Returns true when the thread is stopped.
static bool seizeStop(pid_t tid) {
    if (ptrace(PTRACE_SEIZE, tid, nullptr, nullptr) < 0) return false;
    if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) < 0) {
        ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
        return false;
    }
    int st = 0;
    if (waitpid(tid, &st, __WALL) != tid || !WIFSTOPPED(st)) {
        ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
        return false;
    }
    return true;
}

// Syscall numbers for x86_64
static constexpr uint64_t NR_MMAP = 9;
static constexpr uint64_t NR_MUNMAP = 11;

// Execute a syscall in the target process via ptrace
static int64_t remoteSyscall(pid_t pid, uint64_t nr,
    uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6)
{
    struct user_regs_struct oldRegs, regs;

    if (ptrace(PTRACE_GETREGS, pid, nullptr, &oldRegs) < 0)
        return -1;

    regs = oldRegs;
    regs.rax = nr;
    regs.rdi = a1;
    regs.rsi = a2;
    regs.rdx = a3;
    regs.r10 = a4;
    regs.r8  = a5;
    regs.r9  = a6;

    // Save original instruction and write syscall. Clear errno so a genuine
    // 0xFFFF...FFFF code word is distinguishable from a PEEKTEXT failure; if
    // the read fails, bail without poking a garbage opcode (and never restore
    // a bogus origInstr over the target's real code).
    uint64_t syscallInstr = 0x050f; // syscall
    errno = 0;
    uint64_t origInstr = ptrace(PTRACE_PEEKTEXT, pid, (void*)oldRegs.rip, nullptr);
    if (origInstr == (uint64_t)-1 && errno != 0)
        return -1;
    if (ptrace(PTRACE_POKETEXT, pid, (void*)oldRegs.rip,
               (void*)((origInstr & ~0xFFFF) | syscallInstr)) < 0)
        return -1;

    int64_t result = -1;
    // From here on the original instruction has been overwritten; always
    // restore it (and the saved registers) before returning.
    if (ptrace(PTRACE_SETREGS, pid, nullptr, &regs) == 0 &&
        ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr) == 0) {
        int status;
        if (waitpid(pid, &status, 0) == pid &&
            WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
            // Trust the result only when the single-step actually completed.
            if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == 0)
                result = regs.rax;
        }
    }

    // Restore original instruction and registers.
    ptrace(PTRACE_POKETEXT, pid, (void*)oldRegs.rip, (void*)origInstr);
    ptrace(PTRACE_SETREGS, pid, nullptr, &oldRegs);

    return result;
}

// Call a function in the target process
static uint64_t remoteCall(pid_t pid, uintptr_t funcAddr,
    uintptr_t arg1 = 0, uintptr_t arg2 = 0, uintptr_t arg3 = 0,
    uintptr_t arg4 = 0, uintptr_t arg5 = 0, uintptr_t arg6 = 0) {
    struct user_regs_struct oldRegs, regs;

    if (ptrace(PTRACE_GETREGS, pid, nullptr, &oldRegs) < 0)
        return (uint64_t)-1;

    regs = oldRegs;
    // If we hijacked a thread that was stopped inside a blocking syscall, the
    // kernel would otherwise run its syscall-restart machinery on CONT (rewind
    // RIP / reissue the call), corrupting our injected call. orig_rax = -1 tells
    // the kernel there is no syscall to restart, so it just runs from our RIP.
    regs.orig_rax = (unsigned long long)-1;
    regs.rip = funcAddr;
    regs.rdi = arg1;
    regs.rsi = arg2;
    regs.rdx = arg3;
    regs.rcx = arg4;
    regs.r8 = arg5;
    regs.r9 = arg6;
    regs.rsp -= 128; // Red zone
    regs.rsp &= ~0xFULL; // Align

    // Push a poison return address. When the called function executes `ret`
    // it pops this value into RIP and jumps to the non-canonical address
    // 0xCCCCCCCCCCCCCCCC, which faults with SIGSEGV — that stop is how we know
    // the call finished (its result is already in rax at that point).
    static constexpr uint64_t kPoisonReturn = 0xCCCCCCCCCCCCCCCCULL;
    regs.rsp -= 8;
    uintptr_t returnAddrSlot = regs.rsp;
    if (ptrace(PTRACE_POKETEXT, pid, (void*)returnAddrSlot, (void*)kPoisonReturn) < 0)
        return (uint64_t)-1;

    if (ptrace(PTRACE_SETREGS, pid, nullptr, &regs) < 0)
        return (uint64_t)-1;
    if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) < 0) {
        ptrace(PTRACE_SETREGS, pid, nullptr, &oldRegs);
        return (uint64_t)-1;
    }

    int status;
    uint64_t result = (uint64_t)-1;
    // The called function returns by popping the poison address into RIP and
    // jumping there, which faults. We only require a signal-delivery stop of a
    // still-live tracee (WIFSTOPPED, not WIFEXITED/WIFSIGNALED) before reading
    // rax — at that point the call's result is already in rax. We deliberately
    // do NOT gate on WSTOPSIG==SIGTRAP or rip==poison: a `ret` into the
    // non-canonical poison address raises SIGSEGV (verified: the kernel reports
    // RIP at the faulting `ret`, not the poison value), so either of those
    // gates would reject every successful call.
    // TODO(security): distinguish a genuine return through the poison sentinel
    //   from a SIGSEGV raised inside the callee (e.g. via PTRACE_GETSIGINFO),
    //   and re-deliver pending signals instead of treating every stop as
    //   completion.
    if (waitpid(pid, &status, 0) == pid &&
        WIFSTOPPED(status) &&
        ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == 0) {
        result = regs.rax;
    }

    // Restore original registers regardless (moves rsp back, discards the
    // abandoned return word) so the target is left in a consistent state.
    ptrace(PTRACE_SETREGS, pid, nullptr, &oldRegs);

    return result;
}

// ── i386 (32-bit / compat) remote execution ──
// A 32-bit tracee on a 64-bit kernel is driven through the same
// `struct user_regs_struct`: for a compat task the kernel aliases the i386
// registers into the low 32 bits of the 64-bit fields (eax=rax, ebx=rbx,
// ecx=rcx, edx=rdx, esi=rsi, edi=rdi, ebp=rbp, eip=rip, esp=rsp), and CS still
// selects the 32-bit code segment so execution stays in 32-bit mode.
static constexpr uint32_t NR32_MMAP2  = 192;   // i386 __NR_mmap2 (offset in pages)
static constexpr uint32_t NR32_MUNMAP = 91;    // i386 __NR_munmap

static int64_t remoteSyscall32(pid_t pid, uint32_t nr,
    uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5, uint32_t a6)
{
    struct user_regs_struct oldRegs, regs;
    if (ptrace(PTRACE_GETREGS, pid, nullptr, &oldRegs) < 0) return -1;

    regs = oldRegs;
    regs.rax = nr;   // eax = syscall number
    regs.rbx = a1;   // i386 syscall args: ebx, ecx, edx, esi, edi, ebp
    regs.rcx = a2;
    regs.rdx = a3;
    regs.rsi = a4;
    regs.rdi = a5;
    regs.rbp = a6;

    // int 0x80 = CD 80 (little-endian 0x80CD in the low 16 bits of the word).
    uint64_t syscallInstr = 0x80CD;
    errno = 0;
    uint64_t origInstr = ptrace(PTRACE_PEEKTEXT, pid, (void*)oldRegs.rip, nullptr);
    if (origInstr == (uint64_t)-1 && errno != 0) return -1;
    if (ptrace(PTRACE_POKETEXT, pid, (void*)oldRegs.rip,
               (void*)((origInstr & ~0xFFFF) | syscallInstr)) < 0)
        return -1;

    int64_t result = -1;
    if (ptrace(PTRACE_SETREGS, pid, nullptr, &regs) == 0 &&
        ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr) == 0) {
        int status;
        if (waitpid(pid, &status, 0) == pid &&
            WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
            if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == 0)
                result = (int64_t)(uint32_t)regs.rax;   // eax, zero-extended
        }
    }

    ptrace(PTRACE_POKETEXT, pid, (void*)oldRegs.rip, (void*)origInstr);
    ptrace(PTRACE_SETREGS, pid, nullptr, &oldRegs);
    return result;
}

// Call a 32-bit cdecl function: arguments go on the stack (right-to-left), then
// the return address on top, and the callee returns its result in eax.
static uint64_t remoteCall32(pid_t pid, uint32_t funcAddr, uint32_t arg1, uint32_t arg2) {
    struct user_regs_struct oldRegs, regs;
    if (ptrace(PTRACE_GETREGS, pid, nullptr, &oldRegs) < 0) return (uint64_t)-1;

    regs = oldRegs;
    regs.orig_rax = (unsigned long long)-1;   // orig_eax = -1: no syscall restart

    // Build the frame a normal CALL would leave: [esp]=retaddr, [esp+4]=arg1,
    // [esp+8]=arg2, with esp % 16 == 12 so the callee sees a 16-aligned frame
    // (glibc uses SSE and would fault on a misaligned movaps otherwise).
    uint32_t esp = (uint32_t)oldRegs.rsp;
    esp -= 256;          // move well clear of the live stack
    esp &= ~0xFu;        // 16-align, then...
    esp -= 4;            // ...back up 4 so (esp % 16) == 12 as after a CALL push

    // Poison return address: an unmapped high address, so the callee's `ret`
    // faults (SIGSEGV) and that stop is how we learn the call finished.
    static constexpr uint32_t kPoisonReturn = 0xDEAD0000u;
    uint32_t frame[4] = { kPoisonReturn, arg1, arg2, 0 };
    for (int i = 0; i < 4; i += 2) {
        uint64_t word = (uint64_t)frame[i] | ((uint64_t)frame[i + 1] << 32);
        if (ptrace(PTRACE_POKETEXT, pid, (void*)(uintptr_t)(esp + i * 4), (void*)word) < 0)
            return (uint64_t)-1;
    }

    regs.rip = funcAddr;
    regs.rsp = esp;
    if (ptrace(PTRACE_SETREGS, pid, nullptr, &regs) < 0) return (uint64_t)-1;
    if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) < 0) {
        ptrace(PTRACE_SETREGS, pid, nullptr, &oldRegs);
        return (uint64_t)-1;
    }

    int status;
    uint64_t result = (uint64_t)-1;
    if (waitpid(pid, &status, 0) == pid && WIFSTOPPED(status) &&
        ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == 0) {
        result = (uint32_t)regs.rax;   // eax
    }

    ptrace(PTRACE_SETREGS, pid, nullptr, &oldRegs);
    return result;
}

// 32-bit sibling of injectLibrary. Kept separate so the hard-won x86_64 path is
// untouched; the attach / sibling-quiesce / userspace-pick / maps-verify shape
// mirrors it, only the mmap2/write/dlopen use the i386 ABI.
static std::expected<uintptr_t, std::string>
injectLibrary32(ProcessHandle& proc, SymbolResolver& resolver, const std::string& soPath) {
    pid_t pid = proc.pid();

    if (soPath.empty() || soPath.size() >= 4096)
        return std::unexpected("invalid shared library path");

    bool usingLibcDlopen = false;
    uintptr_t dlopenAddr = resolver.lookup("dlopen");
    if (!dlopenAddr) {
        dlopenAddr = resolver.lookup("__libc_dlopen_mode");
        usingLibcDlopen = dlopenAddr != 0;
    }
    if (!dlopenAddr)
        return std::unexpected("dlopen not found in target process symbols");

    if (!seizeStop(pid))
        return std::unexpected(std::string("ptrace seize failed: ") + strerror(errno));

    struct SiblingGuard {
        std::vector<pid_t> tids;
        ~SiblingGuard() { for (pid_t t : tids) ptrace(PTRACE_DETACH, t, nullptr, nullptr); }
    } siblings;
    if (DIR* d = ::opendir(("/proc/" + std::to_string(pid) + "/task").c_str())) {
        while (struct dirent* e = ::readdir(d)) {
            pid_t tid = (pid_t)atoi(e->d_name);
            if (tid <= 0 || tid == pid) continue;
            if (seizeStop(tid))
                siblings.tids.push_back(tid);
        }
        ::closedir(d);
    }

    // Prefer a thread not parked on a 32-bit syscall gadget (int 0x80 / sysenter),
    // for the same reason as the x86_64 path.
    auto inUserspace = [](pid_t tid) -> bool {
        struct user_regs_struct r;
        if (ptrace(PTRACE_GETREGS, tid, nullptr, &r) < 0) return false;
        errno = 0;
        long w = ptrace(PTRACE_PEEKTEXT, tid, (void*)r.rip, nullptr);
        if (w == -1 && errno != 0) return false;
        uint16_t op = (uint16_t)(w & 0xFFFF);
        return op != 0x80CD /*int 0x80*/ && op != 0x340F /*sysenter*/;
    };
    pid_t injPid = pid;
    if (!inUserspace(pid))
        for (pid_t t : siblings.tids)
            if (inUserspace(t)) { injPid = t; break; }

    size_t pathLen = soPath.size() + 1;
    size_t allocSize = (pathLen + 4095) & ~static_cast<size_t>(4095);

    int64_t raw = remoteSyscall32(injPid, NR32_MMAP2,
        0, (uint32_t)allocSize, 3 /*R|W*/, 0x22 /*PRIVATE|ANON*/, (uint32_t)-1, 0);
    uint32_t remoteMem = (uint32_t)raw;
    // mmap2 reports errors as -errno in eax (0xFFFFF001..0xFFFFFFFF once masked).
    if ((uint32_t)raw >= 0xFFFFF001u || remoteMem == 0) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return std::unexpected("Failed to allocate memory in target (32-bit)");
    }

    const char* pathStr = soPath.c_str();
    for (size_t i = 0; i < pathLen; i += sizeof(long)) {
        long word = 0;
        memcpy(&word, pathStr + i, std::min(sizeof(long), pathLen - i));
        if (ptrace(PTRACE_POKETEXT, injPid, (void*)(uintptr_t)(remoteMem + i), (void*)word) < 0) {
            remoteSyscall32(injPid, NR32_MUNMAP, remoteMem, (uint32_t)allocSize, 0, 0, 0, 0);
            ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
            return std::unexpected("Failed to write library path into target");
        }
    }

    constexpr uint32_t RTLD_NOW = 0x2;
    constexpr uint32_t RTLD_DLOPEN = 0x80000000u;
    uint32_t flags = usingLibcDlopen ? (RTLD_NOW | RTLD_DLOPEN) : RTLD_NOW;
    uint64_t handle = remoteCall32(injPid, (uint32_t)dlopenAddr, remoteMem, flags);

    remoteSyscall32(injPid, NR32_MUNMAP, remoteMem, (uint32_t)allocSize, 0, 0, 0, 0);
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);

    if ((uint32_t)handle == 0 || handle == (uint64_t)-1)
        return std::unexpected("dlopen returned NULL in target process");

    {
        std::string base = soPath.substr(soPath.find_last_of('/') + 1);
        std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
        std::string line;
        bool mapped = false;
        while (std::getline(maps, line))
            if (line.find(base) != std::string::npos) { mapped = true; break; }
        if (!mapped)
            return std::unexpected("dlopen returned " + std::to_string((uint32_t)handle) +
                                   " but " + base + " is not mapped in the target");
    }

    return (uintptr_t)(uint32_t)handle;
}

std::expected<uintptr_t, std::string>
injectLibrary(ProcessHandle& proc, SymbolResolver& resolver, const std::string& soPath) {
    pid_t pid = proc.pid();

    // A 32-bit/compat tracee needs the i386 ABI (int 0x80, mmap2, cdecl dlopen),
    // handled by the dedicated path; remoteSyscall/remoteCall below are x86_64.
    if (!proc.is64bit())
        return injectLibrary32(proc, resolver, soPath);

    // Bound the path length before we attach/allocate. A real .so path is
    // bounded by PATH_MAX; reject anything larger so a bogus oversized string
    // can't drive a huge remote allocation / write loop.
    if (soPath.empty() || soPath.size() >= 4096)
        return std::unexpected("invalid shared library path");

    // Find dlopen in target's libc. Prefer the public dlopen; fall back to the
    // internal __libc_dlopen_mode (present even when libdl isn't linked), which
    // requires the private __RTLD_DLOPEN flag bit OR'd into the mode.
    bool usingLibcDlopen = false;
    uintptr_t dlopenAddr = resolver.lookup("dlopen");
    if (!dlopenAddr) {
        dlopenAddr = resolver.lookup("__libc_dlopen_mode");
        usingLibcDlopen = dlopenAddr != 0;
    }
    if (!dlopenAddr)
        return std::unexpected("dlopen not found in target process symbols");

    // Attach
    if (!seizeStop(pid))
        return std::unexpected(std::string("ptrace seize failed: ") + strerror(errno));

    // Stop every sibling thread too. We hijack the main thread to call dlopen;
    // if the other threads keep running they can enter the dynamic linker (which
    // dlopen locks), corrupt the loader state, and crash the injected call. Attach
    // each /proc/<pid>/task/<tid> and hold it stopped for the duration; the guard
    // detaches them all on every return path.
    struct SiblingGuard {
        std::vector<pid_t> tids;
        ~SiblingGuard() { for (pid_t t : tids) ptrace(PTRACE_DETACH, t, nullptr, nullptr); }
    } siblings;
    if (DIR* d = ::opendir(("/proc/" + std::to_string(pid) + "/task").c_str())) {
        while (struct dirent* e = ::readdir(d)) {
            pid_t tid = (pid_t)atoi(e->d_name);
            if (tid <= 0 || tid == pid) continue;
            if (seizeStop(tid))
                siblings.tids.push_back(tid);
        }
        ::closedir(d);
    }

    // Pick a thread to hijack that is running in userspace. A thread parked in a
    // blocking syscall (nanosleep/futex) is rewound to sit ON its `syscall`
    // instruction (0f 05) for restart; hijacking it to call dlopen corrupts the
    // in-kernel syscall state and the injected call faults. Prefer a thread whose
    // RIP is NOT a syscall instruction (verified: userspace-thread injection maps
    // the library and returns a real handle). Fall back to the main thread.
    auto inUserspace = [](pid_t tid) -> bool {
        struct user_regs_struct r;
        if (ptrace(PTRACE_GETREGS, tid, nullptr, &r) < 0) return false;
        errno = 0;
        long w = ptrace(PTRACE_PEEKTEXT, tid, (void*)r.rip, nullptr);
        if (w == -1 && errno != 0) return false;
        return (uint16_t)(w & 0xFFFF) != 0x050f;  // 0f 05 = syscall
    };
    pid_t injPid = pid;
    if (!inUserspace(pid)) {
        for (pid_t t : siblings.tids) {
            if (inUserspace(t)) { injPid = t; break; }
        }
    }

    // Allocate memory in target for the path string
    size_t pathLen = soPath.size() + 1;
    size_t allocSize = (pathLen + 4095) & ~4095; // Page-aligned

    int64_t remoteMem = remoteSyscall(injPid, NR_MMAP,
        0, allocSize, 3 /*PROT_READ|PROT_WRITE*/, 0x22 /*MAP_PRIVATE|MAP_ANONYMOUS*/, -1, 0);

    if (remoteMem <= 0 || remoteMem == -1) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return std::unexpected("Failed to allocate memory in target");
    }

    // Write the path string
    const char* pathStr = soPath.c_str();
    for (size_t i = 0; i < pathLen; i += sizeof(long)) {
        long word = 0;
        memcpy(&word, pathStr + i, std::min(sizeof(long), pathLen - i));
        if (ptrace(PTRACE_POKETEXT, injPid, (void*)(remoteMem + i), (void*)word) < 0) {
            // Don't call dlopen on a partially-written path; free and bail.
            remoteSyscall(injPid, NR_MUNMAP, remoteMem, allocSize, 0, 0, 0, 0);
            ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
            return std::unexpected("Failed to write library path into target");
        }
    }

    // Call dlopen(path, flags). RTLD_NOW=2; __libc_dlopen_mode additionally needs
    // the private __RTLD_DLOPEN bit (0x80000000) or it does not behave as a real
    // dlopen (and returns a bogus handle without mapping the library).
    constexpr uint64_t RTLD_NOW = 0x2;
    constexpr uint64_t RTLD_DLOPEN = 0x80000000UL;
    uint64_t flags = usingLibcDlopen ? (RTLD_NOW | RTLD_DLOPEN) : RTLD_NOW;
    uint64_t handle = remoteCall(injPid, dlopenAddr, remoteMem, flags);

    // Free the path memory
    remoteSyscall(injPid, NR_MUNMAP, remoteMem, allocSize, 0, 0, 0, 0);

    // Detach
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);

    if (handle == 0 || handle == (uint64_t)-1)
        return std::unexpected("dlopen returned NULL in target process");

    // Verify the library is actually mapped now — a non-NULL return alone is not
    // proof (a mis-flagged call can hand back a bogus small value). Confirm the
    // basename appears in the target's /proc/<pid>/maps.
    {
        std::string base = soPath.substr(soPath.find_last_of('/') + 1);
        std::string mapsPath = "/proc/" + std::to_string(pid) + "/maps";
        std::ifstream maps(mapsPath);
        std::string line;
        bool mapped = false;
        while (std::getline(maps, line)) {
            if (line.find(base) != std::string::npos) { mapped = true; break; }
        }
        if (!mapped)
            return std::unexpected("dlopen returned " + std::to_string(handle) +
                                   " but " + base + " is not mapped in the target");
    }

    return (uintptr_t)handle;
}

std::expected<RemoteThreadInfo, std::string>
createRemoteThread(ProcessHandle& proc, SymbolResolver& resolver, uintptr_t entryPoint,
                   bool waitForCompletion, int timeoutMs) {
    if (!entryPoint)
        return std::unexpected("remote thread entry point is null");

    // See injectLibrary: the ptrace helpers below are x86_64-ABI only.
    if (!proc.is64bit())
        return std::unexpected("32-bit target remote thread is not supported");

    uintptr_t pthreadCreate = resolver.lookup("pthread_create");
    if (!pthreadCreate) pthreadCreate = resolver.lookup("__pthread_create");
    if (!pthreadCreate)
        return std::unexpected("pthread_create not found in target process symbols");

    uintptr_t pthreadJoin = resolver.lookup("pthread_join");
    uintptr_t pthreadTryJoin = resolver.lookup("pthread_tryjoin_np");
    uintptr_t pthreadDetach = resolver.lookup("pthread_detach");

    auto handleStorage = proc.allocate(sizeof(uintptr_t), MemProt::ReadWrite);
    if (!handleStorage)
        return std::unexpected("failed to allocate remote pthread handle storage: " +
            handleStorage.error().message());

    pid_t pid = proc.pid();

    if (!seizeStop(pid)) {
        proc.free(*handleStorage, sizeof(uintptr_t));
        return std::unexpected(std::string("ptrace seize failed: ") + strerror(errno));
    }

    // Quiesce sibling threads (mirrors injectLibrary): if another thread is inside
    // the dynamic linker or holding a glibc lock (malloc/TLS/stack-cache), the
    // injected pthread_create — which takes those same locks — deadlocks and the
    // waitpid in remoteCall never returns, hanging the tool with the target stopped.
    // Stop every sibling for the duration and hijack a thread that is in userspace
    // (not rewound onto a `syscall` instruction), falling back to the main thread.
    struct SiblingGuard {
        std::vector<pid_t> tids;
        ~SiblingGuard() { for (pid_t t : tids) ptrace(PTRACE_DETACH, t, nullptr, nullptr); }
    } siblings;
    if (DIR* d = ::opendir(("/proc/" + std::to_string(pid) + "/task").c_str())) {
        while (struct dirent* e = ::readdir(d)) {
            pid_t tid = (pid_t)atoi(e->d_name);
            if (tid <= 0 || tid == pid) continue;
            if (seizeStop(tid))
                siblings.tids.push_back(tid);
        }
        ::closedir(d);
    }
    auto inUserspace = [](pid_t tid) -> bool {
        struct user_regs_struct r;
        if (ptrace(PTRACE_GETREGS, tid, nullptr, &r) < 0) return false;
        errno = 0;
        long w = ptrace(PTRACE_PEEKTEXT, tid, (void*)r.rip, nullptr);
        if (w == -1 && errno != 0) return false;
        return (uint16_t)(w & 0xFFFF) != 0x050f;  // 0f 05 = syscall
    };
    pid_t injPid = pid;
    if (!inUserspace(pid)) {
        for (pid_t t : siblings.tids)
            if (inUserspace(t)) { injPid = t; break; }
    }

    uint64_t createResult = remoteCall(injPid, pthreadCreate, *handleStorage, 0, entryPoint, 0);
    if (createResult != 0) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        proc.free(*handleStorage, sizeof(uintptr_t));
        return std::unexpected("pthread_create failed with code " + std::to_string(createResult));
    }

    uintptr_t threadHandle = 0;
    proc.read(*handleStorage, &threadHandle, sizeof(threadHandle));
    if (!threadHandle) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        proc.free(*handleStorage, sizeof(uintptr_t));
        return std::unexpected("pthread_create returned an empty thread handle");
    }

    RemoteThreadInfo info;
    info.handle = threadHandle;

    if (waitForCompletion) {
        bool completed = false;
        auto deadline = std::chrono::steady_clock::now() +
            std::chrono::milliseconds(std::max(timeoutMs, 0));

        if (pthreadTryJoin) {
            do {
                uint64_t joinResult = remoteCall(injPid, pthreadTryJoin, threadHandle, 0);
                if (joinResult == 0) {
                    completed = true;
                    break;
                }
                if (joinResult != EBUSY)
                    break;
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            } while (std::chrono::steady_clock::now() < deadline);
        } else if (pthreadJoin) {
            completed = remoteCall(injPid, pthreadJoin, threadHandle, 0) == 0;
        }

        info.completed = completed;
    } else if (pthreadDetach) {
        remoteCall(injPid, pthreadDetach, threadHandle);
    }

    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    proc.free(*handleStorage, sizeof(uintptr_t));
    return info;
}

} // namespace ce::os
