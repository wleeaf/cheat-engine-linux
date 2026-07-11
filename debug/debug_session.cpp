#include "debug/debug_session.hpp"
#include "arch/disassembler.hpp"

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <signal.h>
#include <cstring>
#include <chrono>
#include <cerrno>
#include <unistd.h>

namespace ce {

// Patch a single byte in the tracee's text via ptrace. process_vm_writev (what
// ProcessHandle::write uses) cannot write read-only code pages, so int3 planting
// must go through PTRACE_POKETEXT, which bypasses page protection. Read-modify-
// write of the containing word. MUST be called on the tracer thread.
static bool pokeByte(pid_t pid, uintptr_t addr, uint8_t val, uint8_t* oldOut) {
    errno = 0;
    long word = ptrace(PTRACE_PEEKTEXT, pid, reinterpret_cast<void*>(addr), nullptr);
    if (word == -1 && errno != 0) return false;
    if (oldOut) *oldOut = static_cast<uint8_t>(word & 0xff);
    word = (word & ~0xffL) | static_cast<long>(val);
    return ptrace(PTRACE_POKETEXT, pid, reinterpret_cast<void*>(addr),
                  reinterpret_cast<void*>(word)) == 0;
}

DebugSession::~DebugSession() {
    if (attached_) detach();
    // detach() from within a callback cannot join the tracer thread; join the
    // still-joinable thread here so its cleanup completes before we destruct.
    if (eventThread_.joinable())
        eventThread_.join();
}

bool DebugSession::attach(pid_t pid, ProcessHandle* proc) {
    if (attached_) return false;
    pid_ = pid;
    proc_ = proc;

    // The tracer thread performs PTRACE_ATTACH itself so it (and only it) owns
    // every subsequent ptrace/waitpid. attach() blocks until the thread reports
    // whether the attach succeeded.
    attachPromise_ = std::promise<bool>{};
    auto fut = attachPromise_.get_future();
    eventThread_ = std::thread(&DebugSession::tracerThread, this);
    bool ok = fut.get();
    if (!ok && eventThread_.joinable())
        eventThread_.join();
    return ok;
}

void DebugSession::captureRegs() {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid_, nullptr, &regs) < 0) return;
    std::lock_guard lock(contextMutex_);
    stopContext_.rip = regs.rip;
    stopContext_.rsp = regs.rsp;
    stopContext_.rax = regs.rax;
    stopContext_.rbx = regs.rbx;
    stopContext_.rcx = regs.rcx;
    stopContext_.rdx = regs.rdx;
    stopContext_.rsi = regs.rsi;
    stopContext_.rdi = regs.rdi;
    stopContext_.rbp = regs.rbp;
    stopContext_.rflags = regs.eflags;
}

void DebugSession::detach() {
    if (!attached_.exchange(false)) return;
    // Wake the tracer loop so it observes attached_==false, runs cleanup at the
    // bottom of the loop, and exits.
    cmdCv_.notify_all();

    if (eventThread_.joinable()) {
        // If detach() is called from inside eventCb_ (which runs on the tracer
        // thread) we cannot join ourselves; the loop will finish cleanup on its
        // own and ~DebugSession joins the still-joinable thread. Callers must
        // not destroy the session from within its own callback.
        if (eventThread_.get_id() != std::this_thread::get_id())
            eventThread_.join();
    }
}

// Runs on the tracer thread once the loop exits: restore breakpoints and detach.
void DebugSession::tracerCleanup() {
    {
        std::lock_guard lock(bpMutex_);
        for (auto& [addr, bp] : softBreakpoints_) {
            if (bp.active)
                pokeByte(pid_, addr, bp.originalByte, nullptr);
        }
        softBreakpoints_.clear();
    }
    ptrace(PTRACE_DETACH, pid_, nullptr, nullptr);
    stopped_ = false;
    // Fail any commands still queued so their futures don't block forever.
    std::lock_guard lk(cmdMutex_);
    for (auto& c : commands_)
        if (c.done) c.done->set_value(-1);
    commands_.clear();
}

long DebugSession::postCommand(Command cmd) {
    if (!attached_.load()) return -1;
    // Re-entrant call from within a callback on the tracer thread: run inline to
    // avoid deadlocking on ourselves.
    if (std::this_thread::get_id() == tracerId_)
        return performCommand(cmd);

    auto done = std::make_shared<std::promise<long>>();
    cmd.done = done;
    auto fut = done->get_future();
    {
        std::lock_guard lk(cmdMutex_);
        if (!attached_.load()) return -1;
        commands_.push_back(std::move(cmd));
    }
    cmdCv_.notify_all();
    return fut.get();
}

long DebugSession::performCommand(const Command& cmd) {
    switch (cmd.type) {
        case CmdType::Continue:     doContinue(); return 0;
        case CmdType::Step:         doStep(cmd.stepMode, cmd.addr); return 0;
        case CmdType::SetSoftBp:    return doSetSoftBp(cmd.addr);
        case CmdType::RemoveSoftBp: doRemoveSoftBp(cmd.id); return 0;
    }
    return 0;
}

int DebugSession::setSoftwareBreakpoint(uintptr_t address) {
    if (!attached_.load()) return -1;
    return static_cast<int>(postCommand({CmdType::SetSoftBp, StepMode::Into, address, 0, nullptr}));
}

long DebugSession::doSetSoftBp(uintptr_t address) {
    std::lock_guard lock(bpMutex_);
    auto it = softBreakpoints_.find(address);
    if (it != softBreakpoints_.end()) return it->second.id;

    uint8_t origByte = 0;
    if (!pokeByte(pid_, address, 0xCC, &origByte)) return -1;

    int id = nextSoftBpId_++;
    softBreakpoints_[address] = {id, address, origByte, true};
    return id;
}

void DebugSession::removeSoftwareBreakpoint(int id) {
    if (!attached_.load()) return;
    postCommand({CmdType::RemoveSoftBp, StepMode::Into, 0, id, nullptr});
}

void DebugSession::doRemoveSoftBp(int id) {
    std::lock_guard lock(bpMutex_);
    for (auto it = softBreakpoints_.begin(); it != softBreakpoints_.end(); ++it) {
        if (it->second.id == id) {
            if (it->second.active)
                pokeByte(pid_, it->first, it->second.originalByte, nullptr);
            softBreakpoints_.erase(it);
            return;
        }
    }
}

void DebugSession::continueExecution() {
    if (!attached_.load()) return;
    postCommand({CmdType::Continue, StepMode::Into, 0, 0, nullptr});
}

void DebugSession::doContinue() {
    if (!stopped_.load()) return;
    stopped_ = false;
    if (ptrace(PTRACE_CONT, pid_, nullptr, nullptr) < 0)
        stopped_ = true;
}

void DebugSession::addExceptionBreakpoint(int signal) {
    std::lock_guard lock(exceptionMutex_);
    exceptionBreakSignals_.insert(signal);
}

void DebugSession::removeExceptionBreakpoint(int signal) {
    std::lock_guard lock(exceptionMutex_);
    exceptionBreakSignals_.erase(signal);
}

bool DebugSession::hasExceptionBreakpoint(int signal) const {
    std::lock_guard lock(exceptionMutex_);
    return exceptionBreakSignals_.contains(signal);
}

void DebugSession::tracerThread() {
    tracerId_ = std::this_thread::get_id();

    // Become the tracer on this thread so all later ptrace/waitpid are valid.
    if (ptrace(PTRACE_ATTACH, pid_, nullptr, nullptr) < 0) {
        attachPromise_.set_value(false);
        return;
    }
    int status;
    if (waitpid(pid_, &status, 0) != pid_ || !WIFSTOPPED(status)) {
        ptrace(PTRACE_DETACH, pid_, nullptr, nullptr);
        attachPromise_.set_value(false);
        return;
    }
    attached_ = true;
    stopped_ = true;
    captureRegs();
    attachPromise_.set_value(true);

    while (attached_.load()) {
        // 1) Drain any queued commands (valid because the tracee is stopped).
        Command cmd;
        bool haveCmd = false;
        {
            std::lock_guard lk(cmdMutex_);
            if (!commands_.empty()) {
                cmd = std::move(commands_.front());
                commands_.pop_front();
                haveCmd = true;
            }
        }
        if (haveCmd) {
            long r = performCommand(cmd);
            if (cmd.done) cmd.done->set_value(r);
            continue;
        }

        // 2) If the tracee is running, poll for its next stop event.
        if (!stopped_.load()) {
            int st = 0;
            pid_t waited = waitpid(pid_, &st, WNOHANG);
            if (waited == 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
                continue;
            }
            if (waited < 0) {
                if (errno == ECHILD) { attached_ = false; break; }
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
                continue;
            }
            handleStop(st);
            continue;
        }

        // 3) Stopped with nothing to do: sleep until a command arrives or detach.
        std::unique_lock lk(cmdMutex_);
        cmdCv_.wait_for(lk, std::chrono::milliseconds(50),
                        [&] { return !commands_.empty() || !attached_.load(); });
    }

    tracerCleanup();
}

void DebugSession::handleStop(int status) {
    {
        stopped_ = true;

        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);

            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, pid_, nullptr, &regs);

            {
                std::lock_guard lock(contextMutex_);
                stopContext_.rip = regs.rip;
                stopContext_.rsp = regs.rsp;
                stopContext_.rax = regs.rax;
                stopContext_.rbx = regs.rbx;
                stopContext_.rcx = regs.rcx;
                stopContext_.rdx = regs.rdx;
                stopContext_.rsi = regs.rsi;
                stopContext_.rdi = regs.rdi;
                stopContext_.rbp = regs.rbp;
                stopContext_.rflags = regs.eflags;
            }

            if (sig == SIGTRAP) {
                // Check if we hit a software breakpoint (RIP is one past the int3)
                uintptr_t bpAddr = regs.rip - 1;

                // Snapshot the breakpoint under the lock, then RELEASE it before
                // firing the user callback / single-stepping. Holding bpMutex_
                // across eventCb_ deadlocks any callback that adds/removes a
                // breakpoint (both take bpMutex_) and stalls all breakpoint
                // mutation across the blocking waitpid below.
                uint8_t origByte = 0;
                bool hitSoftBp = false;
                {
                    std::lock_guard lock(bpMutex_);
                    auto it = softBreakpoints_.find(bpAddr);
                    if (it != softBreakpoints_.end()) {
                        origByte = it->second.originalByte;
                        hitSoftBp = true;
                    }
                }

                if (hitSoftBp) {
                    // Restore original byte
                    pokeByte(pid_, bpAddr, origByte, nullptr);
                    // Back up RIP to the breakpoint address
                    regs.rip = bpAddr;
                    ptrace(PTRACE_SETREGS, pid_, nullptr, &regs);

                    DebugEvent evt;
                    evt.type = DebugEventType::BreakpointHit;
                    evt.tid = pid_;
                    evt.address = bpAddr;
                    evt.signal = sig;
                    {
                        std::lock_guard lock(contextMutex_);
                        evt.context = stopContext_;
                    }
                    if (eventCb_) eventCb_(evt);

                    // Re-set the breakpoint after single-stepping past it — but
                    // only if the callback did not remove it (and the tracee is
                    // still alive). Re-acquire the lock and re-check.
                    ptrace(PTRACE_SINGLESTEP, pid_, nullptr, nullptr);
                    waitpid(pid_, &status, 0);
                    if (WIFSTOPPED(status)) {
                        std::lock_guard lock(bpMutex_);
                        auto it = softBreakpoints_.find(bpAddr);
                        if (it != softBreakpoints_.end() && it->second.active)
                            pokeByte(pid_, bpAddr, 0xCC, nullptr);
                    }
                    return;
                }
            }

            DebugEvent evt;
            evt.type = (sig == SIGTRAP)
                ? DebugEventType::SingleStep
                : (hasExceptionBreakpoint(sig)
                    ? DebugEventType::ExceptionBreakpointHit
                    : DebugEventType::SignalReceived);
            evt.tid = pid_;
            evt.address = regs.rip;
            evt.signal = sig;
            evt.context = stopContext_;
            if (eventCb_) eventCb_(evt);
        } else if (WIFEXITED(status) || WIFSIGNALED(status)) {
            DebugEvent evt;
            evt.type = DebugEventType::ProcessExited;
            evt.tid = pid_;
            if (eventCb_) eventCb_(evt);
            attached_ = false;
            stopped_ = false;
        }
    }
}

// After a temporary software breakpoint (0xCC) traps, RIP points one byte past
// the breakpoint. Rewind it to the breakpoint address so the subsequent resume
// re-executes the original (now-restored) instruction instead of landing mid-
// instruction. Mirrors the eventLoop software-breakpoint handling.
void DebugSession::rewindOverBreakpoint(int status, uintptr_t bpAddr) {
    if (!WIFSTOPPED(status)) return;
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid_, nullptr, &regs) < 0) return;
    if (regs.rip == bpAddr + 1) {
        regs.rip = bpAddr;
        ptrace(PTRACE_SETREGS, pid_, nullptr, &regs);
    }
}

void DebugSession::step(StepMode mode, uintptr_t targetAddress) {
    if (!attached_.load()) return;
    postCommand({CmdType::Step, mode, targetAddress, 0, nullptr});
}

// Runs on the tracer thread. Every mode blocks until the tracee is stopped
// again, so on return stopped_ is true and stopContext_ holds fresh registers.
void DebugSession::doStep(StepMode mode, uintptr_t targetAddress) {
    if (!stopped_.load()) return;

    switch (mode) {
        case StepMode::Into: {
            ptrace(PTRACE_SINGLESTEP, pid_, nullptr, nullptr);
            int status;
            waitpid(pid_, &status, 0);
            break;
        }

        case StepMode::Over: {
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, pid_, nullptr, &regs);
            uint8_t buf[16];
            auto rr = proc_->read(regs.rip, buf, sizeof(buf));
            size_t n = (rr && *rr > 0) ? *rr : 0;
            Disassembler dis(Arch::X86_64);
            auto insns = dis.disassemble(regs.rip, {buf, n}, 1);
            if (!insns.empty() && insns[0].mnemonic == "call") {
                uintptr_t nextAddr = regs.rip + insns[0].size;
                long tmpBp = doSetSoftBp(nextAddr);
                ptrace(PTRACE_CONT, pid_, nullptr, nullptr);
                int status;
                waitpid(pid_, &status, 0);
                rewindOverBreakpoint(status, nextAddr);
                doRemoveSoftBp(static_cast<int>(tmpBp));
            } else {
                ptrace(PTRACE_SINGLESTEP, pid_, nullptr, nullptr);
                int status;
                waitpid(pid_, &status, 0);
            }
            break;
        }

        case StepMode::Out: {
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, pid_, nullptr, &regs);
            uintptr_t retAddr = 0;
            proc_->read(regs.rsp, &retAddr, sizeof(retAddr));
            if (retAddr) {
                long tmpBp = doSetSoftBp(retAddr);
                ptrace(PTRACE_CONT, pid_, nullptr, nullptr);
                int status;
                waitpid(pid_, &status, 0);
                rewindOverBreakpoint(status, retAddr);
                doRemoveSoftBp(static_cast<int>(tmpBp));
            }
            break;
        }

        case StepMode::RunToCursor:
            if (targetAddress) {
                long tmpBp = doSetSoftBp(targetAddress);
                ptrace(PTRACE_CONT, pid_, nullptr, nullptr);
                int status;
                waitpid(pid_, &status, 0);
                rewindOverBreakpoint(status, targetAddress);
                doRemoveSoftBp(static_cast<int>(tmpBp));
            }
            break;
    }

    stopped_ = true;
    captureRegs();
}

CpuContext DebugSession::getStopContext() const {
    std::lock_guard lock(contextMutex_);
    return stopContext_;
}

} // namespace ce
