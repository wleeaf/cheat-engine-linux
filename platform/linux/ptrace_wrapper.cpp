#include "platform/linux/ptrace_wrapper.hpp"

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
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
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) < 0)
        return std::unexpected(errFromErrno());

    int status;
    // Confirm the attach-stop actually landed before programming options/regs on
    // a tracee that may not be stopped yet.
    if (waitpid(pid, &status, 0) != pid || !WIFSTOPPED(status)) {
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
        pid_t who = waitpid(-1, &status, WNOHANG | __WALL);
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
    return {};
}

Result<CpuContext> LinuxDebugger::getContext(pid_t tid) {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, tid, nullptr, &regs) < 0)
        return std::unexpected(errFromErrno());

    CpuContext ctx{};
    ctx.rax = regs.rax; ctx.rbx = regs.rbx;
    ctx.rcx = regs.rcx; ctx.rdx = regs.rdx;
    ctx.rsi = regs.rsi; ctx.rdi = regs.rdi;
    ctx.rbp = regs.rbp; ctx.rsp = regs.rsp;
    ctx.r8  = regs.r8;  ctx.r9  = regs.r9;
    ctx.r10 = regs.r10; ctx.r11 = regs.r11;
    ctx.r12 = regs.r12; ctx.r13 = regs.r13;
    ctx.r14 = regs.r14; ctx.r15 = regs.r15;
    ctx.rip = regs.rip;
    ctx.rflags = regs.eflags;
    ctx.cs = regs.cs; ctx.ss = regs.ss;
    ctx.ds = regs.ds; ctx.es = regs.es;
    ctx.fs = regs.fs; ctx.gs = regs.gs;

    // Read the hardware debug registers via PTRACE_PEEKUSER so the GUI sees
    // real DR values (these were previously left zero even when hardware
    // breakpoints were active via setBreakpoint, and a setContext round-trip
    // then silently cleared them). PEEKUSER returns -1 on error; we leave the
    // field zero in that case rather than failing the whole context read.
    auto peekDr = [&](int idx) -> uint64_t {
        errno = 0;
        long v = ptrace(PTRACE_PEEKUSER, tid,
                        offsetof(struct user, u_debugreg) + idx * sizeof(long), nullptr);
        if (v == -1 && errno != 0) return 0;
        return static_cast<uint64_t>(static_cast<unsigned long>(v));
    };
    ctx.dr0 = peekDr(0); ctx.dr1 = peekDr(1);
    ctx.dr2 = peekDr(2); ctx.dr3 = peekDr(3);
    ctx.dr6 = peekDr(6); ctx.dr7 = peekDr(7);
    return ctx;
}

Result<void> LinuxDebugger::setContext(pid_t tid, const CpuContext& ctx) {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, tid, nullptr, &regs) < 0)
        return std::unexpected(errFromErrno());

    regs.rax = ctx.rax; regs.rbx = ctx.rbx;
    regs.rcx = ctx.rcx; regs.rdx = ctx.rdx;
    regs.rsi = ctx.rsi; regs.rdi = ctx.rdi;
    regs.rbp = ctx.rbp; regs.rsp = ctx.rsp;
    regs.r8  = ctx.r8;  regs.r9  = ctx.r9;
    regs.r10 = ctx.r10; regs.r11 = ctx.r11;
    regs.r12 = ctx.r12; regs.r13 = ctx.r13;
    regs.r14 = ctx.r14; regs.r15 = ctx.r15;
    regs.rip = ctx.rip;
    regs.eflags = ctx.rflags;
    regs.cs = ctx.cs; regs.ss = ctx.ss;
    regs.ds = ctx.ds; regs.es = ctx.es;
    regs.fs = ctx.fs; regs.gs = ctx.gs;

    if (ptrace(PTRACE_SETREGS, tid, nullptr, &regs) < 0)
        return std::unexpected(errFromErrno());

    // Write the hardware debug registers back so a getContext->edit->setContext
    // round-trip preserves them instead of silently dropping DR edits (and so
    // it no longer zeroes DRs that setBreakpoint set). The kernel rejects
    // illegal DR7/address values with an error, which we treat as best-effort
    // here (the GP/SETREGS path above already succeeded). DR6/DR7 reserved
    // bits are enforced by the kernel on POKEUSER.
    // TODO(security): mask DR7 reserved/control bits in userspace before the
    //   poke rather than relying solely on kernel validation, and reconcile
    //   the two DR-management paths (setContext vs setBreakpoint).
    auto pokeDr = [&](int idx, uint64_t value) {
        ptrace(PTRACE_POKEUSER, tid,
               offsetof(struct user, u_debugreg) + idx * sizeof(long),
               reinterpret_cast<void*>(static_cast<uintptr_t>(value)));
    };
    pokeDr(0, ctx.dr0); pokeDr(1, ctx.dr1);
    pokeDr(2, ctx.dr2); pokeDr(3, ctx.dr3);
    pokeDr(6, ctx.dr6); pokeDr(7, ctx.dr7);
    return {};
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
    if (waitpid(tid, &status, 0) != tid || !WIFSTOPPED(status))
        return std::unexpected(std::make_error_code(std::errc::no_such_process));
    return {};
}

Result<void> LinuxDebugger::setBreakpoint(pid_t tid, int reg, uintptr_t address, int type, int size) {
    if (reg < 0 || reg > 3)
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));

    // Set DR[reg] address
    size_t dr_offset = offsetof(struct user, u_debugreg) + reg * sizeof(long);
    if (ptrace(PTRACE_POKEUSER, tid, dr_offset, address) < 0)
        return std::unexpected(errFromErrno());

    // Read current DR7. PEEKUSER returns -1 on both a legitimate all-ones value
    // and an error, so clear errno first and treat -1-with-errno as failure —
    // otherwise a transient read error pokes a corrupted control register back.
    size_t dr7_offset = offsetof(struct user, u_debugreg) + 7 * sizeof(long);
    errno = 0;
    long dr7 = ptrace(PTRACE_PEEKUSER, tid, dr7_offset, nullptr);
    if (dr7 == -1 && errno != 0)
        return std::unexpected(errFromErrno());

    // Enable breakpoint in DR7
    // Bits: local enable at bit (reg*2), condition at bits (16 + reg*4), length at bits (18 + reg*4)
    dr7 |= (1L << (reg * 2));                 // Local enable
    dr7 &= ~(0xFL << (16 + reg * 4));         // Clear condition+length bits
    dr7 |= ((long)(type & 0x3) << (16 + reg * 4));   // Condition (0=exec, 1=write, 3=rw)
    dr7 |= ((long)(size & 0x3) << (18 + reg * 4));   // Length (0=1byte, 1=2byte, 3=4byte)

    if (ptrace(PTRACE_POKEUSER, tid, dr7_offset, dr7) < 0)
        return std::unexpected(errFromErrno());

    return {};
}

Result<void> LinuxDebugger::removeBreakpoint(pid_t tid, int reg) {
    if (reg < 0 || reg > 3)
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));

    // Clear DR[reg] address
    size_t dr_offset = offsetof(struct user, u_debugreg) + reg * sizeof(long);
    if (ptrace(PTRACE_POKEUSER, tid, dr_offset, 0) < 0)
        return std::unexpected(errFromErrno());

    // Disable in DR7 (clear+check errno around PEEKUSER; see setBreakpoint).
    size_t dr7_offset = offsetof(struct user, u_debugreg) + 7 * sizeof(long);
    errno = 0;
    long dr7 = ptrace(PTRACE_PEEKUSER, tid, dr7_offset, nullptr);
    if (dr7 == -1 && errno != 0)
        return std::unexpected(errFromErrno());
    dr7 &= ~(1L << (reg * 2));           // Disable local enable
    dr7 &= ~(0xFL << (16 + reg * 4));    // Clear condition+length

    if (ptrace(PTRACE_POKEUSER, tid, dr7_offset, dr7) < 0)
        return std::unexpected(errFromErrno());

    return {};
}

} // namespace ce::os
