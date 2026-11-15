#include "core/target_capabilities.hpp"
#include "platform/linux/linux_process.hpp"
#include "platform/linux/ptrace_wrapper.hpp"
#include "platform/linux/target_debug.hpp"

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <signal.h>
#include <cerrno>
#include <cstring>
#include <unistd.h>

namespace ce::os {

Error LinuxDebugger::errFromErrno() {
    return std::error_code(errno, std::system_category());
}

LinuxDebugger::~LinuxDebugger() {
    if (attached_) (void)detach();
}

Result<void> LinuxDebugger::attach(pid_t pid) {
    LinuxProcessHandle target(pid);
    auto description = target.targetDescription();
    // The low-level register backend can be exercised independently of the
    // full DebugSession event loop, whose capability gate remains stricter.
    bool armRegisters = nativeTargetMachine().architecture == CpuArchitecture::Arm64 &&
        description.live && !description.pendingRecovery && description.runtime == TargetRuntime::Native &&
        description.host.architecture == CpuArchitecture::Arm64 && description.host.abi == TargetAbi::LinuxAarch64;
    if (!armRegisters && unsupportedTargetOperation(target, TargetFeature::Debugger))
        return std::unexpected(std::make_error_code(std::errc::not_supported));
    // SEIZE + INTERRUPT, never ATTACH: ATTACH's injected SIGSTOP deadlocks a
    // syscall-parked Wine/Proton thread, whereas SEIZE stops it without
    // delivering a signal (preserving syscall restart). Matches the rule used by
    // CodeFinder/DebugSession and the injector.
    if (ce::seizeIfOwned(pid, 0) < 0)
        return std::unexpected(errFromErrno());
    if (ptrace(PTRACE_INTERRUPT, pid, nullptr, nullptr) < 0) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return std::unexpected(errFromErrno());
    }

    int status;
    // Confirm the seize-stop actually landed before programming options/regs on
    // a tracee that may not be stopped yet.
    pid_t w;
    do { w = waitpid(pid, &status, __WALL); } while (w < 0 && errno == EINTR);
    if (w != pid || !WIFSTOPPED(status)) {
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return std::unexpected(std::make_error_code(std::errc::no_such_process));
    }

    // Opt-in to follow fork/vfork/clone so we get child stops as
    // PTRACE_EVENT_FORK / VFORK / CLONE — lets the consumer track every
    // process the target spawns. We also enable EXEC so we can re-baseline
    // mapped modules after execve, and EXIT so we know when a tracee dies.
    constexpr unsigned long opts =
        PTRACE_O_TRACEFORK  |
        PTRACE_O_TRACEVFORK |
        PTRACE_O_TRACECLONE |
        PTRACE_O_TRACEEXEC  |
        PTRACE_O_TRACEEXIT;
    // PTRACE_SETOPTIONS may fail on older kernels — that's not fatal, we
    // just don't get child notifications.
    ptrace(PTRACE_SETOPTIONS, pid, nullptr, (void*)opts);

    pid_ = pid;
    attached_ = true;
    tracees_ = {pid};
    awaitingStart_.clear();
    return {};
}

Result<std::vector<pid_t>> LinuxDebugger::pollChildren() {
    std::vector<pid_t> kids;
    if (!attached_) return kids;
    constexpr unsigned long opts =
        PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
        PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT;
    // Wait on each tracee by pid, never on -1: that would also reap the
    // calling program's own children and take their exit statuses.
    for (bool progress = true; progress;) {
        progress = false;
        for (pid_t who : std::vector<pid_t>(tracees_.begin(), tracees_.end())) {
            int status = 0;
            const pid_t waited = waitpid(who, &status, WNOHANG | __WALL);
            if (waited < 0 && errno == ECHILD) { tracees_.erase(who); awaitingStart_.erase(who); continue; }
            if (waited != who) continue;
            progress = true;
            if (WIFEXITED(status) || WIFSIGNALED(status)) {   // gone: forget it
                tracees_.erase(who);
                awaitingStart_.erase(who);
                continue;
            }
            if (!WIFSTOPPED(status)) continue;
            const int signal = WSTOPSIG(status);
            const unsigned event = static_cast<unsigned>(status >> 16) & 0xffff;
            if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK || event == PTRACE_EVENT_CLONE) {
                unsigned long childPid = 0;
                if (ptrace(PTRACE_GETEVENTMSG, who, nullptr, &childPid) == 0 && childPid != 0) {
                    const auto child = static_cast<pid_t>(childPid);
                    kids.push_back(child);
                    // Re-arm the new child with the same options so we keep
                    // following its fork tree. It starts in a stop of its own.
                    ptrace(PTRACE_SETOPTIONS, child, nullptr, (void*)opts);
                    tracees_.insert(child);
                    awaitingStart_.insert(child);
                }
            }
            if (event == PTRACE_EVENT_STOP) {
                const bool firstStop = awaitingStart_.erase(who) > 0;
                const bool jobControl = signal == SIGSTOP || signal == SIGTSTP || signal == SIGTTIN || signal == SIGTTOU;
                // A job-control stop (SIGSTOP, Ctrl+Z) keeps the process
                // stopped until SIGCONT, as without a debugger; LISTEN does
                // that while still reporting the SIGCONT.
                if (!firstStop && jobControl) {
                    ptrace(PTRACE_LISTEN, who, nullptr, nullptr);
                    continue;
                }
                ptrace(PTRACE_CONT, who, nullptr, nullptr);
                continue;
            }
            // Event stops (fork, clone, exec, exit) and the trace machinery's
            // own SIGTRAP resume without a signal. A signal the program took
            // (SIGSEGV, SIGINT, ...) is delivered, or it would never reach
            // it. After an exec the caller re-reads the modules it needs; an
            // exit stop resumes so the process can finish exiting and be
            // reaped above.
            const int deliver = event == 0 && signal != SIGTRAP ? signal : 0;
            ptrace(PTRACE_CONT, who, nullptr, (void*)(uintptr_t)deliver);
        }
    }
    return kids;
}

Result<void> LinuxDebugger::detach() {
    if (!attached_) return {};

    if (ptrace(PTRACE_DETACH, pid_, nullptr, nullptr) < 0)
        return std::unexpected(errFromErrno());
    // Children followed through pollChildren are tracees too: left attached
    // they would stop with no one to resume them. A tracee can only be
    // detached in a stop, so interrupt one that runs (briefly, by pid).
    for (pid_t child : tracees_) {
        if (child == pid_) continue;
        if (ptrace(PTRACE_DETACH, child, nullptr, nullptr) == 0) continue;
        if (ptrace(PTRACE_INTERRUPT, child, nullptr, nullptr) != 0) continue;
        for (int wait = 0; wait < 100; ++wait) {
            int status = 0;
            const pid_t waited = waitpid(child, &status, WNOHANG | __WALL);
            if (waited == child) {
                if (WIFSTOPPED(status)) ptrace(PTRACE_DETACH, child, nullptr, nullptr);
                break;
            }
            if (waited < 0) break;
            usleep(1000);
        }
    }

    attached_ = false;
    pid_ = 0;
    tracees_.clear();
    awaitingStart_.clear();
    breakpointExecution_.clear();
    return {};
}

Result<CpuContext> LinuxDebugger::getContext(pid_t tid) {
    return readNativeContext(tid);
}

Result<void> LinuxDebugger::setContext(pid_t tid, const CpuContext& ctx) {
    return writeNativeContext(tid, ctx);
}

Result<void> LinuxDebugger::suspend(pid_t tid) {
    // tkill sends signal to specific thread
    if (syscall(SYS_tkill, tid, SIGSTOP) < 0)
        return std::unexpected(errFromErrno());
    return {};
}

Result<void> LinuxDebugger::resume(pid_t tid) {
    if (syscall(SYS_tkill, tid, SIGCONT) < 0)
        return std::unexpected(errFromErrno());
    return {};
}

Result<void> LinuxDebugger::singleStep(pid_t tid) {
    if (ptrace(PTRACE_SINGLESTEP, tid, nullptr, nullptr) < 0)
        return std::unexpected(errFromErrno());

    int status;
    // Report failure if the step didn't produce a clean stop (tracee exited or
    // the wait was interrupted) so callers don't read stale registers.
    pid_t waited;
    do { waited = waitpid(tid, &status, __WALL | __WNOTHREAD); } while (waited < 0 && errno == EINTR);
    if (waited != tid || !WIFSTOPPED(status))
        return std::unexpected(std::make_error_code(std::errc::no_such_process));
    return {};
}

Result<void> LinuxDebugger::setBreakpoint(pid_t tid, int reg, uintptr_t address, int type, int size) {
    if (reg < 0 || size < 0 || size > 3 || (type != 0 && type != 1 && type != 3))
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    constexpr unsigned lengths[] = {1, 2, 8, 4};
    auto access = type == 0 ? HardwareBreakpointAccess::Execute :
        type == 1 ? HardwareBreakpointAccess::Write : HardwareBreakpointAccess::ReadWrite;
    // Preserve the public interface's historic x86 length encoding; the native
    // backend consumes byte lengths and selects its architecture's bank.
    unsigned length = lengths[size];
    if (type == 0 && nativeTargetMachine().architecture == CpuArchitecture::Arm64) length = 4;
    auto key = std::pair{tid, reg};
    auto it = breakpointExecution_.find(key);
    if (it != breakpointExecution_.end() && it->second != (type == 0) &&
        nativeTargetMachine().architecture == CpuArchitecture::Arm64)
        return std::unexpected(std::make_error_code(std::errc::device_or_resource_busy));
    bool inserted = false;
    if (it == breakpointExecution_.end()) {
        try { breakpointExecution_.emplace(key, type == 0); inserted = true; }
        catch (const std::bad_alloc&) {
            return std::unexpected(std::make_error_code(std::errc::not_enough_memory));
        }
    }
    auto result = setNativeHardwareBreakpoint(tid, unsigned(reg), address, access, length);
    if (!result && inserted && result.error() != std::make_error_code(std::errc::state_not_recoverable))
        breakpointExecution_.erase(key);
    else if (result) breakpointExecution_.find(key)->second = type == 0;
    return result;
}

Result<void> LinuxDebugger::removeBreakpoint(pid_t tid, int reg) {
    if (reg < 0) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    auto key = std::pair{tid, reg};
    auto it = breakpointExecution_.find(key);
    if (it == breakpointExecution_.end() && nativeTargetMachine().architecture == CpuArchitecture::Arm64)
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    bool execution = it != breakpointExecution_.end() && it->second;
    auto result = removeNativeHardwareBreakpoint(tid, unsigned(reg), execution);
    if (result) breakpointExecution_.erase(key);
    return result;
}

} // namespace ce::os
