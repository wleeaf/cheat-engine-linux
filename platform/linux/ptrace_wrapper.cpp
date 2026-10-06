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

namespace ce::os {

Error LinuxDebugger::errFromErrno() {
    return std::error_code(errno, std::system_category());
}

LinuxDebugger::~LinuxDebugger() {
    if (attached_) detach();
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
    if (ptrace(PTRACE_SEIZE, pid, nullptr, nullptr) < 0)
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
    return {};
}

Result<std::vector<pid_t>> LinuxDebugger::pollChildren() {
    std::vector<pid_t> kids;
    if (!attached_) return kids;
    // Non-blocking scan for any tracee that's ready with a fork-style event.
    while (true) {
        int status = 0;
        pid_t who = waitpid(-1, &status, WNOHANG | __WALL | __WNOTHREAD);
        if (who <= 0) break;
        if (WIFSTOPPED(status)) {
            int signal = WSTOPSIG(status);
            unsigned long event = (status >> 16) & 0xffff;
            if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK ||
                event == PTRACE_EVENT_CLONE) {
                unsigned long childPid = 0;
                if (ptrace(PTRACE_GETEVENTMSG, who, nullptr, &childPid) == 0 && childPid != 0) {
                    kids.push_back((pid_t)childPid);
                    // Re-arm the new child with the same options so we keep
                    // following its fork tree.
                    constexpr unsigned long opts =
                        PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                        PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC |
                        PTRACE_O_TRACEEXIT;
                    ptrace(PTRACE_SETOPTIONS, childPid, nullptr, (void*)opts);
                }
            }
            // Re-deliver genuine application signal-delivery stops instead of
            // swallowing them: a ptrace event stop (event != 0) and the
            // SIGTRAP from the trace machinery itself must NOT be re-injected,
            // but a real signal the application took (SIGSEGV, SIGINT, ...)
            // would otherwise be silently eaten and never reach the target,
            // changing its behavior.
            int contSig = 0;
            if (event == 0 && signal != SIGTRAP)
                contSig = signal;
            // TODO(security): also handle PTRACE_EVENT_EXEC/EXIT (re-baseline
            //   modules on exec, reap and surface exited tracees) and detect
            //   group-stops via PTRACE_GETSIGINFO before re-delivering.
            ptrace(PTRACE_CONT, who, nullptr, (void*)(uintptr_t)contSig);
        }
    }
    return kids;
}

Result<void> LinuxDebugger::detach() {
    if (!attached_) return {};

    if (ptrace(PTRACE_DETACH, pid_, nullptr, nullptr) < 0)
        return std::unexpected(errFromErrno());

    attached_ = false;
    pid_ = 0;
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
