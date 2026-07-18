#include "debug/code_finder.hpp"

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <signal.h>
#include <unistd.h>
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <set>

#ifndef __WALL
#define __WALL 0x40000000
#endif

namespace ce {

bool CodeFinder::start(ProcessHandle& proc, Debugger& dbg, uintptr_t address, bool writesOnly, int watchSize) {
    if (running_) return false;

    proc_ = &proc;
    dbg_ = &dbg;
    targetAddress_ = address;
    writesOnly_ = writesOnly;
    watchSize_ = (watchSize == 1 || watchSize == 2 || watchSize == 8) ? watchSize : 4;
    stopRequested_ = false;
    running_ = true;

    monitorThread_ = std::thread(&CodeFinder::monitorLoop, this);
    return true;
}

void CodeFinder::stop() {
    stopRequested_ = true;
    if (monitorThread_.joinable())
        monitorThread_.join();
    running_ = false;
}

std::vector<CodeFinderResult> CodeFinder::results() const {
    std::lock_guard lock(resultsMutex_);
    std::vector<CodeFinderResult> res;
    res.reserve(resultsMap_.size());
    for (auto& [_, r] : resultsMap_)
        res.push_back(r);
    std::sort(res.begin(), res.end(),
        [](const CodeFinderResult& a, const CodeFinderResult& b) { return a.hitCount > b.hitCount; });
    return res;
}

void CodeFinder::clearResults() {
    std::lock_guard lock(resultsMutex_);
    resultsMap_.clear();
}

void CodeFinder::monitorLoop() {
    pid_t pid = proc_->pid();

    // DR0-3 are per-thread CPU state, so the watchpoint must be armed on EVERY
    // thread of the target — a single-thread attach never sees sibling threads'
    // accesses. SEIZE each thread with PTRACE_O_TRACECLONE so threads created
    // later are auto-traced and can be armed too, then wait with __WALL.
    int bpType = writesOnly_ ? 1 : 3;
    // x86 DR7 length encoding: 1 byte->0, 2->1, 8->2, 4->3.
    int bpSize = (watchSize_ == 1) ? 0 : (watchSize_ == 2) ? 1 : (watchSize_ == 8) ? 2 : 3;

    auto armThread = [&](pid_t tid) {
        dbg_->setBreakpoint(tid, 0, targetAddress_, bpType, bpSize);
    };

    std::set<pid_t> attached;
    std::vector<pid_t> tids;
    for (auto& t : proc_->threads()) tids.push_back(t.tid);
    if (tids.empty()) tids.push_back(pid);

    for (pid_t tid : tids) {
        if (ptrace(PTRACE_SEIZE, tid, nullptr,
                   reinterpret_cast<void*>(PTRACE_O_TRACECLONE)) < 0)
            continue;
        // Stop the thread so its debug registers can be programmed.
        if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) == 0) {
            int st;
            waitpid(tid, &st, __WALL);
        }
        armThread(tid);
        attached.insert(tid);
        ptrace(PTRACE_CONT, tid, nullptr, nullptr);
    }

    if (attached.empty()) {
        running_ = false;
        return;
    }

    auto recordHit = [&](pid_t tid) {
        auto ctxResult = dbg_->getContext(tid);
        if (!ctxResult) return;
        auto& ctx = *ctxResult;
        // A data watchpoint (DR0-3 read/write) traps AFTER the accessing
        // instruction retires, so ctx.rip points at the NEXT instruction. Back up
        // to the instruction that actually touched the address (the one ending at
        // rip); otherwise we'd report a following register-only op like "add eax,1".
        uintptr_t rip = ctx.rip;
        uintptr_t instrAddr = disasm_.previousInstruction(rip, [&](uintptr_t a, uint8_t* b, size_t n) {
            auto r = proc_->read(a, b, n);
            return r && *r >= n;
        });
        if (instrAddr == 0 || instrAddr >= rip) instrAddr = rip;   // fallback
        uint8_t instrBuf[16];
        auto readResult = proc_->read(instrAddr, instrBuf, sizeof(instrBuf));
        std::string instrText;
        std::vector<uint8_t> instrBytes;
        if (readResult && *readResult > 0) {
            auto insns = disasm_.disassemble(instrAddr, {instrBuf, *readResult}, 1);
            if (!insns.empty()) {
                instrText = insns[0].mnemonic + " " + insns[0].operands;
                instrBytes = insns[0].bytes;
            }
        }
        std::lock_guard lock(resultsMutex_);
        auto& entry = resultsMap_[instrAddr];
        if (entry.hitCount == 0) {
            entry.instructionAddress = instrAddr;
            entry.instructionText = instrText;
            entry.instructionBytes = instrBytes;
            entry.firstContext = ctx;
        }
        entry.lastContext = ctx;
        entry.hitCount++;
    };

    while (!stopRequested_) {
        int status;
        pid_t w = waitpid(-1, &status, __WALL | WNOHANG);
        if (w <= 0) {
            usleep(1000); // 1ms poll
            continue;
        }

        // A newly created thread: it is auto-seized and stopped; arm and resume.
        if (WIFSTOPPED(status) &&
            (status >> 8) == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) {
            unsigned long newTid = 0;
            if (ptrace(PTRACE_GETEVENTMSG, w, nullptr, &newTid) == 0 && newTid) {
                int st;
                waitpid(static_cast<pid_t>(newTid), &st, __WALL);
                armThread(static_cast<pid_t>(newTid));
                attached.insert(static_cast<pid_t>(newTid));
                ptrace(PTRACE_CONT, static_cast<pid_t>(newTid), nullptr, nullptr);
            }
            ptrace(PTRACE_CONT, w, nullptr, nullptr);
            continue;
        }

        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);

            // Only treat this SIGTRAP as a watchpoint hit if siginfo confirms a
            // hardware-breakpoint trap. Report the hit against the tid (w) that
            // actually trapped, so sibling-thread accesses are attributed right.
            siginfo_t si{};
            bool isWatchpoint = (sig == SIGTRAP &&
                ptrace(PTRACE_GETSIGINFO, w, nullptr, &si) == 0 &&
                si.si_code == TRAP_HWBKPT);

            if (isWatchpoint) {
                recordHit(w);
                // Clear DR6's status bits before resuming. The CPU sets the B0-B3
                // bit for the debug register that fired and never auto-clears it;
                // if we leave it set, the tracee reads a stale "a hardware
                // breakpoint hit" flag back through its own context (Wine/Proton
                // exposes DR6 via GetThreadContext and re-raises it into the game's
                // SEH as a Windows debug exception, which shows the game's crash
                // dialog). The main debugger path already does this; CodeFinder did
                // not, so its watchpoints were the ones crashing Wine targets.
                size_t dr6Off = offsetof(struct user, u_debugreg) + 6 * sizeof(long);
                ptrace(PTRACE_POKEUSER, w, dr6Off, 0L);
                ptrace(PTRACE_CONT, w, nullptr, nullptr);
            } else if (sig == SIGTRAP) {
                // A trap that is not our watchpoint (int3, syscall-stop, an
                // event-stop). Resume without re-injecting SIGTRAP.
                ptrace(PTRACE_CONT, w, nullptr, nullptr);
            } else if (sig == SIGSTOP || sig == SIGTSTP ||
                       sig == SIGTTIN || sig == SIGTTOU) {
                // Group-stop / PTRACE_INTERRUPT stop: resume with no signal.
                ptrace(PTRACE_CONT, w, nullptr, nullptr);
            } else {
                // A genuine signal destined for the tracee — forward it.
                ptrace(PTRACE_CONT, w, nullptr, reinterpret_cast<void*>(static_cast<uintptr_t>(sig)));
            }
        } else if (WIFEXITED(status) || WIFSIGNALED(status)) {
            attached.erase(w);
            if (w == pid || attached.empty())
                break; // main thread / whole process gone
        }
    }

    // Clean up — remove the watchpoint and detach from every armed thread.
    // At loop exit every thread is running (each handled stop is CONT'd before
    // the next iteration). PTRACE_POKEUSER (clearing DR7) and PTRACE_DETACH both
    // require the tracee to be in a ptrace-stop, so we must INTERRUPT each thread
    // and wait for the stop first. Skipping this leaves the hardware watchpoint
    // armed after the kernel auto-detaches on tracer exit; the tracee then takes
    // a debug-exception SIGTRAP with no tracer installed and is killed.
    for (pid_t tid : attached) {
        if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) != 0)
            continue; // thread already gone / not seized
        int st = 0;
        pid_t r = waitpid(tid, &st, __WALL);
        if (r != tid || WIFEXITED(st) || WIFSIGNALED(st))
            continue; // exited before we could disarm it
        dbg_->removeBreakpoint(tid, 0);       // clears DR7 while stopped
        ptrace(PTRACE_DETACH, tid, nullptr, nullptr); // signal 0 = drop pending
    }
    running_ = false;
}

} // namespace ce
