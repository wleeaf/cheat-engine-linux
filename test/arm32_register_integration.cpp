#include "platform/linux/target_debug.hpp"
#include "core/cpu_registers.hpp"
#include "platform/linux/register_image.hpp"
#include "platform/linux/target_syscall.hpp"
#include <fstream>
#include <thread>
#include <sys/mman.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <poll.h>
#include <sstream>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include <elf.h>

using namespace ce;
static unsigned totalFailures;
static pid_t faultTarget;
static unsigned faultStage;
static unsigned faultNote = NT_PRSTATUS, extendedWrites;
static pid_t extendedTarget;
static bool rejectExtendedWrite;
static pid_t captureFaultTarget;
static unsigned captureFaultHits;
static bool spoofLegacyRead;
static pid_t memoryFaultTarget;
static bool memoryRan,refuseMemoryRestore,dropMemoryPatch,sendMemorySignal;
static unsigned droppedMemoryPatches;
static bool memorySignalSent;
static bool failRestore, forwardedMutation;
extern "C" long __real_ptrace(enum __ptrace_request, ...);
extern "C" long __wrap_ptrace(enum __ptrace_request request, ...) {
    va_list args; va_start(args, request);
    const pid_t tid = va_arg(args, pid_t);
    void* address = va_arg(args, void*); void* data = va_arg(args, void*);
    va_end(args);
    if (tid==memoryFaultTarget && request==PTRACE_POKETEXT && dropMemoryPatch) {
        ++droppedMemoryPatches; dropMemoryPatch=false; return 0;
    }
    if (tid==memoryFaultTarget && (request==PTRACE_CONT || request==PTRACE_SINGLESTEP)) {
        memoryRan=true;
        if (sendMemorySignal) { memorySignalSent=kill(tid,SIGUSR2)==0; sendMemorySignal=false; }
    }
    if (tid==memoryFaultTarget && memoryRan && refuseMemoryRestore && request==PTRACE_SETREGSET && address==reinterpret_cast<void*>(NT_PRSTATUS)) {
        errno=EIO; return -1;
    }
    if (tid==captureFaultTarget && request==PTRACE_GETREGSET && address==reinterpret_cast<void*>(0x400u)) {
        ++captureFaultHits; errno=EIO; return -1;
    }
    if (tid==extendedTarget && spoofLegacyRead && request==PTRACE_GETREGSET && address==reinterpret_cast<void*>(NT_PRFPREG)) {
        const auto result=__real_ptrace(request,tid,address,data);
        auto* io=static_cast<iovec*>(data);
        if (result==0 && io->iov_len) static_cast<uint8_t*>(io->iov_base)[0]^=1;
        return result;
    }
    if (tid == extendedTarget && request == PTRACE_SETREGSET) {
        ++extendedWrites;
        if (rejectExtendedWrite && address == reinterpret_cast<void*>(0x400u)) { errno = EIO; return -1; }
    }
    if (tid == faultTarget && request == PTRACE_SETREGSET && address == reinterpret_cast<void*>(uintptr_t(faultNote))) {
        if (faultStage == 1) {
            faultStage = 2;
            const auto result = __real_ptrace(request, tid, address, data);
            forwardedMutation = result == 0;
            if (forwardedMutation) { errno = EIO; return -1; }
            return result;
        }
        if (faultStage == 2 && failRestore) { errno = EIO; return -1; }
    }
    return __real_ptrace(request, tid, address, data);
}
static void armFault(pid_t target, bool restoration, unsigned note = NT_PRSTATUS) {
    faultNote = note;
    faultTarget = target; faultStage = 1; failRestore = restoration; forwardedMutation = false;
}
static void clearArmFault() { faultTarget = 0; faultStage = 0; }
struct Checks {
    const char* mode;
    unsigned count = 0, failed = 0;
    void operator()(bool ok, const char* name) {
        ++count; failed += !ok; totalFailures += !ok;
        std::printf("ARM32_REG %s %s: %s\n", mode, ok ? "OK" : "FAILED", name);
    }
};
struct Child {
    pid_t pid = -1; int output = -1; bool traced = false;
    Child() = default;
    explicit Child(const char* fixture, const char* mode) {
        int pipefd[2]; if (pipe(pipefd)) return;
        pid = fork();
        if (pid == 0) {
            close(pipefd[0]); dup2(pipefd[1], 1); close(pipefd[1]);
            execl(fixture, fixture, mode, nullptr); _exit(127);
        }
        close(pipefd[1]); output = pipefd[0];
    }
    bool waitStop(int* observed = nullptr) {
        int status = 0; pid_t result;
        do { result = waitpid(pid, &status, __WALL); } while (result < 0 && errno == EINTR);
        if (observed) *observed = status;
        return result == pid && WIFSTOPPED(status);
    }
    std::string line() {
        std::string value;
        while (value.size() < 4096) {
            pollfd fd{output, POLLIN, 0}; if (poll(&fd, 1, 3000) <= 0) return {};
            char c; if (read(output, &c, 1) != 1) return {};
            if (c == '\n') return value;
            value += c;
        }
        return {};
    }
    ~Child() {
        if (pid > 0) {
            kill(pid, SIGKILL);
            if (traced) ptrace(PTRACE_CONT, pid, nullptr, nullptr);
            int status; while (waitpid(pid, &status, __WALL) < 0 && errno == EINTR) {}
        }
        if (output >= 0) close(output);
    }
};
using Bank = std::array<uint32_t,18>;
static bool rawBank(pid_t pid, Bank& bank) {
    std::array<uint64_t,34> maximum{}; iovec io{maximum.data(), sizeof(maximum)};
    if (ptrace(PTRACE_GETREGSET, pid, reinterpret_cast<void*>(NT_PRSTATUS), &io) < 0 || io.iov_len != sizeof(bank)) return false;
    std::memcpy(bank.data(), maximum.data(), sizeof(bank)); return true;
}
static void timeout(int) {
    const char text[] = "ARM32_REGISTER_TIMEOUT\n"; write(1, text, sizeof(text)-1);
    if (getpid() == 1) reboot(RB_POWER_OFF);
    _exit(124);
}
#include "test/arm32_extended_checks.inc"
#include "test/arm32_memory_checks.inc"
#include "test/thumb_return_boundary_checks.inc"

static void profile(const char* fixture, bool thumb) {
    Checks check{thumb ? "THUMB" : "ARM"};
    Child child(fixture, thumb ? "thumb" : "arm");
    uintptr_t start = 0, end = 0, site = 0, scratch=0, applicationSignal=0; int file=-1; pid_t reported = 0; std::string magic, mode;
    std::istringstream ready(child.line()); ready >> magic >> mode >> reported >> std::hex >> start >> end >> site >> scratch >> std::dec >> file >> std::hex >> applicationSignal;
    check(ready && magic == "ARM32_FIXTURE" && mode == check.mode && reported == child.pid && start && end > start && site >= start && site < end,
          "actual ARM32 executable starts in the requested code mode");
    if (!ready || !start) return;
    bool stopped = ptrace(PTRACE_SEIZE, child.pid, nullptr, nullptr) == 0;
    child.traced = stopped;
    stopped = stopped && ptrace(PTRACE_INTERRUPT, child.pid, nullptr, nullptr) == 0 && child.waitStop();
    Bank before{};
    for (unsigned attempt = 0; stopped && attempt < 20; ++attempt) {
        if (!rawBank(child.pid, before)) break;
        if (before[15] >= start && before[15] < end && bool(before[16] & 0x20) == thumb && before[8] == 0x89abcdef) break;
        stopped = ptrace(PTRACE_CONT, child.pid, nullptr, nullptr) == 0;
        usleep(1000);
        stopped = stopped && ptrace(PTRACE_INTERRUPT, child.pid, nullptr, nullptr) == 0 && child.waitStop();
    }
    check(stopped, "the caller owns a real kernel ptrace stop"); if (!stopped) return;
    const bool raw = rawBank(child.pid, before);
    check(raw && before[15] >= start && before[15] < end && bool(before[16] & 0x20) == thumb,
          "the kernel supplies the complete 72-byte ARM register ABI and actual ARM/Thumb CPSR mode");
    if (!raw) return;
    auto context = os::readNativeContext(child.pid);
    check(context && context->architecture == CpuArchitecture::Arm32 && context->x[8] == 0x89abcdef && context->x[9] == 0xf1234567,
          "native register reads preserve high 32-bit values without sign extension");
    // The raw fallback permits the preserved unsupported backend to finish its
    // negative comparison and the child to exit normally; it cannot pass a
    // product register read, edit or patch assertion.
    CpuContext current{};
    if (context) current = *context;
    else {
        current.architecture = CpuArchitecture::Arm32;
        for (unsigned i = 0; i < 13; ++i) current.x[i] = before[i];
        current.x[14] = before[14]; current.sp = before[13]; current.pc = before[15]; current.pstate = before[16];
    }
    check(current.instructionPointer() == before[15] && current.stackPointer() == before[13] && current.framePointer() == 0x11223344,
          "generic PC SP and frame-pointer accessors use the ARM register bank");
    auto registers = cpuRegisterValues(current);
    check(registers.size() == 17 && registers[0].name == "PC" && registers[1].name == "SP" && registers[2].name == "R11" &&
          registers[3].name == "LR" && registers[16].name == "CPSR" &&
          std::all_of(registers.begin(), registers.end(), [](const auto& r) { return r.bits == 32 && r.value <= UINT32_MAX; }),
          "register consumers expose all real R0-R15 and CPSR fields at their actual width");
    check(describeCpuStatusFlags(current).find(thumb ? "T=1" : "T=0") != std::string::npos,
          "status flags report the actual instruction mode");
    const auto r8 = std::find_if(registers.begin(), registers.end(), [](const auto& r) { return r.name == "R8"; });
    const auto row = size_t(r8 - registers.begin());
    const bool edited = r8 != registers.end() && setCpuRegisterValue(current, row, 0x10203040);
    check(edited && os::writeNativeContext(child.pid, current).has_value(),
          "a real ARM register edit commits through the product backend");
    Bank after{}; bool changed = rawBank(child.pid, after);
    Bank expected = before; expected[8] = 0x10203040;
    check(changed && after == expected,
          "kernel readback verifies the edit while preserving every other register and ORIG_R0");
    CpuContext bad = current; bad.x[8] = UINT64_C(0x100000000);
    check(!os::writeNativeContext(child.pid, bad) && rawBank(child.pid, expected) && expected == after,
          "overflowing register values are rejected before any kernel mutation");
    bad = current; bad.pc |= 1;
    check(!os::writeNativeContext(child.pid, bad) && rawBank(child.pid, expected) && expected == after,
          "misaligned ARM and Thumb PCs cannot corrupt the stopped thread");
    bad = current; bad.architecture = CpuArchitecture::X86_64;
    check(!os::writeNativeContext(child.pid, bad) && rawBank(child.pid, expected) && expected == after,
          "an unrelated register ABI is rejected without writing");
    bad = current; bad.pstate = (bad.pstate & ~UINT64_C(31)) | 0x13;
    check(!os::writeNativeContext(child.pid, bad) && rawBank(child.pid, expected) && expected == after,
          "kernel-rejected privileged CPSR edits restore and verify the complete original bank");
    bad = current; bad.x[9] ^= 0x1234;
    armFault(child.pid, false);
    auto failedWrite = os::writeNativeContext(child.pid, bad);
    clearArmFault();
    check(!failedWrite && forwardedMutation && rawBank(child.pid, expected) && expected == after,
          "an injected error after an actual kernel write rolls back every original register");
    armFault(child.pid, true);
    auto failedRestore = os::writeNativeContext(child.pid, bad);
    clearArmFault();
    const bool retained = !failedRestore && failedRestore.error() == std::errc::state_not_recoverable && forwardedMutation &&
        rawBank(child.pid, expected) && expected[9] == bad.x[9];
    const bool retry = os::writeNativeContext(child.pid, current).has_value() && rawBank(child.pid, expected) && expected == after;
    check(retained && retry, "failed rollback reports the retained stop and permits verified recovery from the caller's original snapshot");
    std::vector<uint64_t> values; for (const auto& r : registers) values.push_back(r.value);
    CpuContext moved = current; moved.pstate ^= 0x20;
    check(!mergeCpuRegisterEdits(moved, current, values),
          "stale ARM versus Thumb snapshots cannot overwrite the current instruction mode");
    const auto oldR8 = current.x[8];
    check(!setCpuRegisterValue(current, row, UINT64_C(0x100000000)) && current.x[8] == oldR8,
          "register consumers reject overflow without changing their snapshot");

    Checks extendedCheck{thumb ? "VFP_THUMB" : "VFP_ARM"};
    arm32Extended(child.pid, extendedCheck);
    Checks memoryCheck{thumb ? "MEM_THUMB" : "MEM_ARM"};
    arm32Memory(child.pid,scratch,file,applicationSignal,fixture,memoryCheck);
    std::printf("ARM32_MEM_RESULT mode=%s checks=%u failures=%u\n", check.mode,memoryCheck.count,memoryCheck.failed);

    const auto address = site - site % sizeof(long);
    errno = 0; const long originalWord = ptrace(PTRACE_PEEKTEXT, child.pid, reinterpret_cast<void*>(address), nullptr);
    auto breakpoint = os::installNativeSoftwareBreakpoint(child.pid, site, thumb ? InstructionMode::Thumb : InstructionMode::Arm);
    check(breakpoint && breakpoint->installed && breakpoint->size == (thumb ? 2u : 4u),
          "a mode-specific software breakpoint installs through kernel code and cache handling");
    auto duplicate = os::installNativeSoftwareBreakpoint(child.pid, site, thumb ? InstructionMode::Thumb : InstructionMode::Arm);
    check(!duplicate && duplicate.error().error == std::errc::file_exists,
          "an existing trap cannot be adopted as another owner's original code");
    bool trapped = false; long trapWord = originalWord;
    if (breakpoint) {
        trapWord = ptrace(PTRACE_PEEKTEXT, child.pid, reinterpret_cast<void*>(address), nullptr);
        int status = 0;
        trapped = ptrace(PTRACE_CONT, child.pid, nullptr, nullptr) == 0 && child.waitStop(&status) && WSTOPSIG(status) == SIGTRAP;
    }
    auto hit = os::readNativeContext(child.pid);
    check(trapped && hit && hit->instructionPointer() == site && os::nativeSoftwareBreakpointAddress(*hit) == site,
          "actual ARM/Thumb execution hits the trap and reports its exact instruction address");
    bool refused = false, repaired = false, idempotent = false;
    if (breakpoint) {
        long conflict = trapWord;
        reinterpret_cast<unsigned char*>(&conflict)[site-address] ^= 1;
        ptrace(PTRACE_POKETEXT, child.pid, reinterpret_cast<void*>(address), reinterpret_cast<void*>(conflict));
        auto remove = os::removeNativeSoftwareBreakpoint(child.pid, *breakpoint);
        refused = !remove && breakpoint->installed && ptrace(PTRACE_PEEKTEXT, child.pid, reinterpret_cast<void*>(address), nullptr) == conflict;
        ptrace(PTRACE_POKETEXT, child.pid, reinterpret_cast<void*>(address), reinterpret_cast<void*>(trapWord));
        repaired = os::removeNativeSoftwareBreakpoint(child.pid, *breakpoint).has_value() && !breakpoint->installed &&
            ptrace(PTRACE_PEEKTEXT, child.pid, reinterpret_cast<void*>(address), nullptr) == originalWord;
        idempotent = os::removeNativeSoftwareBreakpoint(child.pid, *breakpoint).has_value();
    }
    check(refused, "replaced-code conflicts preserve the live breakpoint and recovery owner");
    check(repaired, "repairing the conflict restores the exact instruction and adjacent bytes");
    check(idempotent, "repeated successful breakpoint cleanup is harmless");
    check(!breakpoint || !breakpoint->installed, "the original executable instruction remains available before resuming");
    if (thumb) {
        Checks itCheck{"MEM_IT_THUMB"};
        thumbMemoryIt(child.pid,scratch,fixture,itCheck);
        std::printf("ARM32_IT_MEM_RESULT checks=%u failures=%u\n",itCheck.count,itCheck.failed);
        Checks boundaryCheck{"MEM_BOUNDARY_THUMB"};
        thumbReturnBoundary(child.pid,scratch,fixture,boundaryCheck);
        std::printf("THUMB_RETURN_BOUNDARY_RESULT checks=%u failures=%u\n",boundaryCheck.count,boundaryCheck.failed);
    }
    const bool detached = ptrace(PTRACE_DETACH, child.pid, nullptr, nullptr) == 0;
    child.traced = !detached;
    check(detached, "the target detaches with no injected application stop signal");
    kill(child.pid, SIGUSR1);
    const auto observed = child.line(); int status = 0;
    const auto vfpObserved = child.line();
    pid_t waited; do { waited = waitpid(child.pid, &status, 0); } while (waited < 0 && errno == EINTR);
    if (waited == child.pid) child.pid = -1;
    std::printf("ARM32_REG_OBSERVATION mode=%s value=%s\n", check.mode, observed.c_str());
    check(observed == "ARM32_CHILD 270544960" && waited > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "the actual application observes its edited register and exits normally after code restoration");
    std::printf("ARM32_VFP_OBSERVATION mode=%s value=%s\n", check.mode, vfpObserved.c_str());
    extendedCheck(vfpObserved == "ARM32_VFP_CHILD 11150031900141442680 18364758544493064720 4194304" && waited > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0,
                  "the actual application observes its original VFP state and exits normally");
    std::printf("ARM32_EXT_RESULT mode=%s checks=%u failures=%u\n", check.mode, extendedCheck.count, extendedCheck.failed);
    std::printf("ARM32_REG_RESULT mode=%s checks=%u failures=%u\n", check.mode, check.count, check.failed);
}
#if defined(__aarch64__)
static volatile sig_atomic_t nativeResume;
static void nativeResumeHandler(int) { nativeResume = 1; }
static void native64Regression() {
    Checks check{"AARCH64"}; Child child; int pipefd[2];
    if (pipe(pipefd)) { check(false, "native ARM64 child pipe available"); return; }
    child.pid = fork();
    if (child.pid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL); signal(SIGUSR1, nativeResumeHandler);
        close(pipefd[0]); dup2(pipefd[1], 1); close(pipefd[1]);
        void* scratch=mmap(nullptr,4096,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        if (scratch==MAP_FAILED) _exit(2);
        std::memset(scratch,0x57,4096);
        std::printf("AARCH64_READY %lx\n",static_cast<unsigned long>(reinterpret_cast<uintptr_t>(scratch))); fflush(stdout);
        while (!nativeResume) __asm__ volatile("nop");
        puts("AARCH64_CHILD_DONE"); fflush(stdout); _exit(0);
    }
    close(pipefd[1]); child.output = pipefd[0];
    std::istringstream greeting(child.line());std::string magic;uintptr_t scratch=0;
    greeting>>magic>>std::hex>>scratch;
    bool ready=greeting && magic=="AARCH64_READY" && scratch;
    usleep(1000);
    child.traced = ready && ptrace(PTRACE_SEIZE, child.pid, nullptr, nullptr) == 0;
    ready = child.traced && ptrace(PTRACE_INTERRUPT, child.pid, nullptr, nullptr) == 0 && child.waitStop();
    check(ready, "a separate actual AArch64 application is stopped by its owner"); if (!ready) return;
    using WideBank = std::array<uint64_t,34>;
    const auto raw = [&](WideBank& bank) {
        iovec io{bank.data(), sizeof(bank)};
        return ptrace(PTRACE_GETREGSET, child.pid, reinterpret_cast<void*>(NT_PRSTATUS), &io) == 0 && io.iov_len == sizeof(bank);
    };
    WideBank before{}, after{};
    check(raw(before), "the native ARM64 register ABI remains the actual 272-byte bank");
    auto context = os::readNativeContext(child.pid);
    check(context && context->architecture == CpuArchitecture::Arm64 &&
          std::equal(context->x.begin(), context->x.end(), before.begin()) && context->sp == before[31] && context->pc == before[32] && context->pstate == before[33],
          "the shared reader preserves every native ARM64 general register");
    if (!context) return;
    check(context->instructionPointer() == before[32] && context->stackPointer() == before[31] && context->framePointer() == before[29] && cpuRegisterValues(*context).size() == 34,
          "native ARM64 register consumers retain their original names and accessors");
    CpuContext changed = *context; changed.x[19] = UINT64_C(0xabcdef0012345678);
    auto expected = before; expected[19] = changed.x[19];
    check(os::writeNativeContext(child.pid, changed).has_value() && raw(after) && after == expected,
          "native ARM64 edits verify the complete actual kernel bank");
    CpuContext bad = changed; bad.architecture = CpuArchitecture::Arm32;
    check(!os::writeNativeContext(child.pid, bad) && raw(after) && after == expected,
          "an ARM32 context cannot truncate or replace a native ARM64 bank");
    bad = changed; bad.pc |= 2;
    check(!os::writeNativeContext(child.pid, bad) && raw(after) && after == expected,
          "misaligned native ARM64 PCs leave every register intact");
    bad = changed; bad.x[20] ^= 0x1234; bad.pstate = (bad.pstate & ~UINT64_C(31)) | 5;
    check(!os::writeNativeContext(child.pid, bad) && raw(after) && after == expected,
          "kernel-rejected ARM64 PSTATE edits roll back every requested general register");
    bad = changed; bad.x[20] ^= 0x1234;
    armFault(child.pid, false);
    auto failedWrite = os::writeNativeContext(child.pid, bad);
    clearArmFault();
    check(!failedWrite && forwardedMutation && raw(after) && after == expected,
          "an error after a real native ARM64 kernel write restores every register");
    armFault(child.pid, true);
    auto failedRestore = os::writeNativeContext(child.pid, bad);
    clearArmFault();
    const bool retained = !failedRestore && failedRestore.error() == std::errc::state_not_recoverable && forwardedMutation && raw(after) && after[20] == bad.x[20];
    const bool retry = os::writeNativeContext(child.pid, changed).has_value() && raw(after) && after == expected;
    check(retained && retry, "native ARM64 failed restoration retains its stop for verified caller recovery");
    check(os::writeNativeContext(child.pid, *context).has_value() && raw(after) && after == before,
          "restoration returns the exact original native ARM64 bank");
    Checks memoryGuard{"MEM_AARCH64"};
    native64ReturnGuard(child.pid,scratch,memoryGuard);
    std::printf("AARCH64_MEM_GUARD_RESULT checks=%u failures=%u\n",memoryGuard.count,memoryGuard.failed);
    Checks extendedCheck{"VFP_AARCH64"};
    native64Extended(child.pid,extendedCheck);
    std::printf("AARCH64_EXT_RESULT checks=%u failures=%u\n", extendedCheck.count, extendedCheck.failed);
    auto breakpoint = os::installNativeSoftwareBreakpoint(child.pid, context->pc, InstructionMode::Aarch64);
    int status = 0; bool trapped = breakpoint && ptrace(PTRACE_CONT, child.pid, nullptr, nullptr) == 0 && child.waitStop(&status) && WSTOPSIG(status) == SIGTRAP;
    auto hit = os::readNativeContext(child.pid);
    check(trapped && hit && os::nativeSoftwareBreakpointAddress(*hit) == context->pc,
          "native ARM64 BRK execution retains its exact instruction address");
    const bool restored = breakpoint && os::removeNativeSoftwareBreakpoint(child.pid, *breakpoint).has_value();
    const bool detached = restored && ptrace(PTRACE_DETACH, child.pid, nullptr, nullptr) == 0;
    child.traced = !detached;
    if (detached) kill(child.pid, SIGUSR1);
    const auto done = detached ? child.line() : std::string{};
    pid_t waited = -1;
    if (detached) { do { waited = waitpid(child.pid, &status, 0); } while (waited < 0 && errno == EINTR); }
    if (waited == child.pid) child.pid = -1;
    check(detached && done == "AARCH64_CHILD_DONE" && waited > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "the original ARM64 application finishes normally after register and code restoration");
    std::printf("AARCH64_REG_RESULT checks=%u failures=%u\n", check.count, check.failed);
}
#endif
int main(int argc, char** argv) {
    signal(SIGALRM, timeout); alarm(45);
    if (getpid() == 1) { mount("proc", "/proc", "proc", 0, nullptr); mount("devtmpfs", "/dev", "devtmpfs", 0, nullptr); }
    utsname kernel{}; uname(&kernel);
    std::printf("ARM32_REG_GUEST kernel=%s machine=%s page=%ld engine=%s\n", kernel.release, kernel.machine, sysconf(_SC_PAGESIZE),
#if defined(__aarch64__)
                "ARM64"
#else
                "ARM32"
#endif
    );
    const char* fixture = argc == 2 ? argv[1] : "/fixture";
    profile(fixture, false); profile(fixture, true);
#if defined(__aarch64__)
    native64Regression();
#endif
    std::printf("ARM32_REG_VM_RESULT=%s failures=%u\n", totalFailures ? "FAILED" : "PASSED", totalFailures); fflush(stdout);
    if (getpid() == 1) reboot(RB_POWER_OFF);
    return totalFailures ? 1 : 0;
}
