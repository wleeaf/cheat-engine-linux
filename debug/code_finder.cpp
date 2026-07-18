#include "debug/code_finder.hpp"

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <signal.h>
#include <unistd.h>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cerrno>
#include <cstring>
#include <set>

#ifndef __WALL
#define __WALL 0x40000000
#endif

namespace ce {

bool CodeFinder::start(ProcessHandle& proc, Debugger& dbg, uintptr_t address, bool writesOnly, int watchSize, bool software) {
    if (running_) return false;

    proc_ = &proc;
    dbg_ = &dbg;
    targetAddress_ = address;
    writesOnly_ = writesOnly;
    watchSize_ = (watchSize == 1 || watchSize == 2 || watchSize == 8) ? watchSize : 4;
    software_ = software;
    stopRequested_ = false;
    running_ = true;

    monitorThread_ = std::thread(software_ ? &CodeFinder::monitorLoopSoftware
                                           : &CodeFinder::monitorLoop, this);
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
                recordHit(w, /*afterInstruction=*/true);
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

void CodeFinder::recordHit(pid_t tid, bool afterInstruction) {
    auto ctxResult = dbg_->getContext(tid);
    if (!ctxResult) return;
    auto& ctx = *ctxResult;
    uintptr_t rip = ctx.rip;
    uintptr_t instrAddr = rip;
    if (afterInstruction) {
        // Hardware watchpoint: the trap fires once the store has retired, so rip is
        // at the NEXT instruction — back up to the one that actually touched the
        // address (a software page fault, by contrast, stops on the store itself).
        uintptr_t prev = disasm_.previousInstruction(rip, [&](uintptr_t a, uint8_t* b, size_t n) {
            auto r = proc_->read(a, b, n);
            return r && *r >= n;
        });
        if (prev != 0 && prev < rip) instrAddr = prev;
    }
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
}

// Run a syscall in an already ptrace-stopped, traced thread by pointing its RIP at
// a pre-placed syscall GADGET (a `syscall` / `int 0x80` instruction in a scratch
// page we own), NOT by overwriting the instruction at the thread's own RIP. That
// matters in a multithreaded target: sibling threads run the same code, so poking
// a syscall over a shared instruction makes them execute it too and corrupts the
// process (observed as a SIGSEGV / game crash). The gadget page is private, so no
// running thread ever executes it. WoW64 / 32-bit compat threads (CS 0x23) use the
// int 0x80 gadget with the i386 syscall number. Returns the syscall result, or -1.
static long injectSyscallGadget(pid_t tid, uintptr_t gadget64, uintptr_t gadget32,
                                long nr64, uint64_t a1, uint64_t a2, uint64_t a3) {
    struct user_regs_struct oldRegs, regs;
    if (ptrace(PTRACE_GETREGS, tid, nullptr, &oldRegs) < 0) return -1;
    regs = oldRegs;
    regs.orig_rax = (unsigned long long)-1;   // no syscall-restart on resume

    const bool mode32 = ((oldRegs.cs & 0xFFu) == 0x23u);
    if (mode32) {
        uint32_t nr32 = (nr64 == 10) ? 125u : (uint32_t)nr64;  // mprotect -> i386 125
        regs.rax = nr32;
        regs.rbx = a1; regs.rcx = a2; regs.rdx = a3;
        regs.rip = gadget32;
    } else {
        regs.rax = (unsigned long long)nr64;
        regs.rdi = a1; regs.rsi = a2; regs.rdx = a3;
        regs.rip = gadget64;
    }

    long result = -1;
    int status;
    if (ptrace(PTRACE_SETREGS, tid, nullptr, &regs) == 0 &&
        ptrace(PTRACE_SINGLESTEP, tid, nullptr, nullptr) == 0 &&
        waitpid(tid, &status, __WALL) == tid && WIFSTOPPED(status)) {
        struct user_regs_struct after;
        if (ptrace(PTRACE_GETREGS, tid, nullptr, &after) == 0)
            result = mode32 ? (long)(int32_t)(after.rax & 0xFFFFFFFFu)
                            : (long)after.rax;
    }
    // Restore the saved registers (RIP goes back to the faulting store); no shared
    // instruction was ever modified, so nothing else to undo.
    ptrace(PTRACE_SETREGS, tid, nullptr, &oldRegs);
    return result;
}

void CodeFinder::monitorLoopSoftware() {
    pid_t pid = proc_->pid();
    const uintptr_t watchLo = targetAddress_;
    const uintptr_t watchHi = targetAddress_ + (uintptr_t)watchSize_;
    const uintptr_t pageStart = watchLo & ~uintptr_t(4095);
    const uintptr_t pageEnd = (watchHi + 4095) & ~uintptr_t(4095);
    const size_t pageLen = pageEnd - pageStart;

    // Original protection of the region (so we can restore it, and keep READ/EXEC
    // while dropping WRITE). Linux PROT_*: R=1, W=2, X=4.
    int origProt = 1;
    for (auto& r : proc_->queryRegions()) {
        if (targetAddress_ >= r.base && targetAddress_ < r.base + r.size) {
            origProt = 0;
            if (r.protection & MemProt::Read)  origProt |= 1;
            if (r.protection & MemProt::Write) origProt |= 2;
            if (r.protection & MemProt::Exec)  origProt |= 4;
            break;
        }
    }
    // Guard: writes-only drops WRITE (reads/exec still allowed); access mode drops
    // read too (PROT_NONE) so reads fault as well — heavier, but that is inherent.
    const int guardProt = writesOnly_ ? (origProt & ~2) : 0;

    // Allocate a scratch syscall-gadget page BEFORE seizing (allocate() attaches on
    // its own, so it must not run while we hold the seize). Place it near the target
    // so a WoW64 32-bit thread — whose RIP must be < 4 GB — can jump to it. Write a
    // `syscall` gadget for 64-bit threads and an `int 0x80` gadget for 32-bit ones.
    auto scratchRes = proc_->allocate(4096, MemProt::All, targetAddress_);
    if (!scratchRes) { running_ = false; return; }
    const uintptr_t scratch = *scratchRes;
    const uintptr_t gadget64 = scratch;
    const uintptr_t gadget32 = scratch + 16;
    { const uint8_t g64[2] = {0x0f, 0x05}; proc_->write(gadget64, g64, sizeof(g64)); }   // syscall
    { const uint8_t g32[2] = {0xcd, 0x80}; proc_->write(gadget32, g32, sizeof(g32)); }   // int 0x80

    std::set<pid_t> attached;
    std::vector<pid_t> tids;
    for (auto& t : proc_->threads()) tids.push_back(t.tid);
    if (tids.empty()) tids.push_back(pid);

    pid_t anyStopped = -1;
    for (pid_t tid : tids) {
        if (ptrace(PTRACE_SEIZE, tid, nullptr,
                   reinterpret_cast<void*>(PTRACE_O_TRACECLONE)) < 0)
            continue;
        if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) == 0) {
            int st; waitpid(tid, &st, __WALL);
            anyStopped = tid;
        }
        attached.insert(tid);
    }
    if (attached.empty() || anyStopped < 0) {
        proc_->free(scratch, 4096);
        running_ = false;
        return;
    }

    // Arm the guard from inside the target (via the gadget), then resume all threads.
    injectSyscallGadget(anyStopped, gadget64, gadget32, 10 /*mprotect*/,
                        pageStart, pageLen, guardProt);
    for (pid_t tid : attached) ptrace(PTRACE_CONT, tid, nullptr, nullptr);

    while (!stopRequested_) {
        int status;
        pid_t w = waitpid(-1, &status, __WALL | WNOHANG);
        if (w <= 0) { usleep(1000); continue; }

        // Newly cloned thread: trace + resume (the guard is process-wide, so it will
        // fault on the protected page too).
        if (WIFSTOPPED(status) &&
            (status >> 8) == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) {
            unsigned long newTid = 0;
            if (ptrace(PTRACE_GETEVENTMSG, w, nullptr, &newTid) == 0 && newTid) {
                int st; waitpid(static_cast<pid_t>(newTid), &st, __WALL);
                attached.insert(static_cast<pid_t>(newTid));
                ptrace(PTRACE_CONT, static_cast<pid_t>(newTid), nullptr, nullptr);
            }
            ptrace(PTRACE_CONT, w, nullptr, nullptr);
            continue;
        }

        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            if (sig == SIGSEGV) {
                siginfo_t si{};
                bool haveSi = (ptrace(PTRACE_GETSIGINFO, w, nullptr, &si) == 0);
                uintptr_t fault = haveSi ? reinterpret_cast<uintptr_t>(si.si_addr) : 0;
                bool ourPage = haveSi && fault >= pageStart && fault < pageEnd;
                if (ourPage) {
                    // A guarded access. Record it only if it lands on the watched
                    // bytes (other bytes on the same page fault too, but aren't ours).
                    if (fault >= watchLo && fault < watchHi)
                        recordHit(w, /*afterInstruction=*/false);
                    // Let the faulting instruction complete: briefly restore the real
                    // protection, single-step over the store, then re-arm the guard.
                    injectSyscallGadget(w, gadget64, gadget32, 10, pageStart, pageLen, origProt);
                    if (ptrace(PTRACE_SINGLESTEP, w, nullptr, nullptr) == 0) {
                        int st; waitpid(w, &st, __WALL);
                    }
                    injectSyscallGadget(w, gadget64, gadget32, 10, pageStart, pageLen, guardProt);
                    ptrace(PTRACE_CONT, w, nullptr, nullptr);
                } else {
                    // A genuine segfault elsewhere — forward it so the game / Wine
                    // handles its own fault instead of us swallowing a real crash.
                    ptrace(PTRACE_CONT, w, nullptr,
                           reinterpret_cast<void*>(static_cast<uintptr_t>(SIGSEGV)));
                }
            } else if (sig == SIGTRAP) {
                ptrace(PTRACE_CONT, w, nullptr, nullptr);
            } else if (sig == SIGSTOP || sig == SIGTSTP ||
                       sig == SIGTTIN || sig == SIGTTOU) {
                ptrace(PTRACE_CONT, w, nullptr, nullptr);
            } else {
                ptrace(PTRACE_CONT, w, nullptr,
                       reinterpret_cast<void*>(static_cast<uintptr_t>(sig)));
            }
        } else if (WIFEXITED(status) || WIFSIGNALED(status)) {
            attached.erase(w);
            if (w == pid || attached.empty())
                break;
        }
    }

    // Cleanup: restore the page's original protection once, detach every thread,
    // then release the scratch gadget page.
    bool restored = false;
    for (pid_t tid : attached) {
        if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) != 0)
            continue;
        int st = 0;
        pid_t r = waitpid(tid, &st, __WALL);
        if (r != tid || WIFEXITED(st) || WIFSIGNALED(st))
            continue;
        if (!restored) {
            injectSyscallGadget(tid, gadget64, gadget32, 10, pageStart, pageLen, origProt);
            restored = true;
        }
        ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
    }
    proc_->free(scratch, 4096);
    running_ = false;
}

} // namespace ce
