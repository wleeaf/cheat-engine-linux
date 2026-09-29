#include "debug/tracer.hpp"

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>
#include <cerrno>
#include <cstring>
#include <set>
#include <vector>

namespace ce {

std::vector<TraceEntry> Tracer::trace(ProcessHandle& proc, Debugger& dbg, const TraceConfig& config) {
    cancelled_.store(false);
    progress_.store(0);
    disasm_.setArch(proc.runs32BitCode() ? Arch::X86_32 : Arch::X86_64);   // WoW64-aware

    std::vector<TraceEntry> entries;
    entries.reserve(config.maxSteps);

    pid_t pid = proc.pid();

    // SEIZE every thread with PTRACE_O_TRACECLONE so a start breakpoint hit on a
    // CHILD thread is caught and that thread is traced — not just the main one.
    // Fall back to a single-thread attach if seizing isn't available.
    std::vector<pid_t> tids;
    for (auto& t : proc.threads()) tids.push_back(t.tid);
    if (tids.empty()) tids.push_back(pid);

    std::set<pid_t> seized;
    for (pid_t tid : tids) {
        if (ptrace(PTRACE_SEIZE, tid, nullptr,
                   reinterpret_cast<void*>(PTRACE_O_TRACECLONE)) < 0)
            continue;
        if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) == 0) {
            int st = 0;
            if (waitpid(tid, &st, __WALL) == tid) seized.insert(tid);
        }
    }
    if (seized.empty()) {
        if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) < 0) return entries;
        int status = 0;
        waitpid(pid, &status, 0);
        seized.insert(pid);
    }

    auto detachAll = [&]() {
        for (pid_t tid : seized) ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
    };

    pid_t traceTid = pid;   // the thread we single-step

    // Run to the start address on whichever thread reaches it first.
    if (config.startAddress) {
        for (pid_t tid : seized) dbg.setBreakpoint(tid, 0, config.startAddress, 0 /*execute*/, 0 /*1 byte*/);
        for (pid_t tid : seized) ptrace(PTRACE_CONT, tid, nullptr, nullptr);

        bool hit = false;
        while (!hit && !cancelled_.load()) {
            int status = 0;
            pid_t w = waitpid(-1, &status, __WALL);
            if (w < 0) { detachAll(); return entries; }
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                seized.erase(w);
                if (w == pid || seized.empty()) { progress_.store(1.0f); detachAll(); return entries; }
                continue;
            }
            if (!WIFSTOPPED(status)) continue;
            // A newly cloned thread: it is auto-seized+stopped. Arm the start
            // breakpoint on it and resume both it and the parent, or a start
            // address first reached on the new thread is missed (and its
            // SIGSTOP would otherwise be re-delivered by the generic path).
            if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) {
                unsigned long newTid = 0;
                if (ptrace(PTRACE_GETEVENTMSG, w, nullptr, &newTid) == 0 && newTid != 0) {
                    pid_t child = static_cast<pid_t>(newTid);
                    int cst = 0;
                    pid_t cw;
                    do { cw = waitpid(child, &cst, __WALL); } while (cw < 0 && errno == EINTR);
                    if (cw == child && WIFSTOPPED(cst)) {
                        seized.insert(child);
                        if (config.startAddress)
                            dbg.setBreakpoint(child, 0, config.startAddress, 0 /*execute*/, 0 /*1 byte*/);
                        ptrace(PTRACE_CONT, child, nullptr, nullptr);
                    } else {
                        // Could not consume its initial stop; release it so it is
                        // not left seized/stopped forever (detachAll only knows
                        // about `seized`).
                        ptrace(PTRACE_DETACH, child, nullptr, nullptr);
                    }
                }
                ptrace(PTRACE_CONT, w, nullptr, nullptr);
                continue;
            }
            int sig = WSTOPSIG(status);
            if (sig == SIGTRAP) {
                // Only accept a genuine hardware (execute) breakpoint at the start.
                siginfo_t si{};
                bool isHw = (ptrace(PTRACE_GETSIGINFO, w, nullptr, &si) == 0 &&
                             si.si_code == TRAP_HWBKPT);
                auto ctx = dbg.getContext(w);
                if (isHw && ctx && ctx->rip == config.startAddress) {
                    traceTid = w;
                    hit = true;
                } else {
                    ptrace(PTRACE_CONT, w, nullptr, nullptr);   // not our breakpoint
                }
            } else {
                ptrace(PTRACE_CONT, w, nullptr, reinterpret_cast<void*>(static_cast<long>(sig)));
            }
        }
        if (!hit) { detachAll(); return entries; }

        // Disarm the start breakpoint everywhere and freeze the other threads
        // (all-stop) so only the traced thread advances.
        for (pid_t tid : seized) dbg.removeBreakpoint(tid, 0);
        for (pid_t tid : seized) {
            if (tid == traceTid) continue;
            if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) == 0) {
                int st = 0;
                waitpid(tid, &st, __WALL);
            }
        }
    }

    // Single-step the traced thread; every other thread stays frozen.
    for (int step = 0; step < config.maxSteps && !cancelled_.load(); ++step) {
        progress_.store(static_cast<float>(step) / config.maxSteps);

        auto ctxResult = dbg.getContext(traceTid);
        if (!ctxResult) break;
        auto& ctx = *ctxResult;

        uint8_t instrBuf[16];
        auto readResult = proc.read(ctx.rip, instrBuf, sizeof(instrBuf));
        size_t n = (readResult && *readResult > 0) ? *readResult : 0;
        std::string instrText = "??";
        if (n) {
            auto insns = disasm_.disassemble(ctx.rip, {instrBuf, n}, 1);
            if (!insns.empty())
                instrText = insns[0].mnemonic + " " + insns[0].operands;
        }

        entries.push_back({ctx.rip, instrText, ctx});

        if (config.stopAddress && ctx.rip == config.stopAddress)
            break;
        if (config.stayInModule && config.moduleBase &&
            (ctx.rip < config.moduleBase || ctx.rip >= config.moduleEnd))
            break;

        if (config.stepOverCalls && instrText.starts_with("call") && n) {
            auto insns = disasm_.disassemble(ctx.rip, {instrBuf, n}, 1);
            if (!insns.empty()) {
                uintptr_t nextAddr = ctx.rip + insns[0].size;
                dbg.setBreakpoint(traceTid, 0, nextAddr, 0, 0);
                ptrace(PTRACE_CONT, traceTid, nullptr, nullptr);
                int status = 0;
                waitpid(traceTid, &status, __WALL);
                if (WIFEXITED(status) || WIFSIGNALED(status)) {
                    progress_.store(1.0f);
                    detachAll();
                    return entries;
                }
                dbg.removeBreakpoint(traceTid, 0);
                continue;
            }
        }

        auto stepResult = dbg.singleStep(traceTid);
        if (!stepResult) break;
    }

    progress_.store(1.0f);
    detachAll();
    return entries;
}

} // namespace ce
