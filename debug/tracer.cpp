#include "debug/tracer.hpp"
#include "platform/linux/ceserver_process.hpp"

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <signal.h>
#include <unistd.h>
#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <functional>
#include <map>

namespace ce {

std::vector<TraceEntry> Tracer::trace(ProcessHandle& proc, Debugger& dbg, const TraceConfig& config) {
    cancelled_.store(false);
    progress_.store(0);
    std::vector<TraceEntry> entries;
    // A remote PID is meaningful only on its server. Local ptrace must never
    // attach an unrelated local task that happens to have the same PID.
    if (dynamic_cast<os::RemoteProcessHandle*>(&proc)) { progress_.store(1); return entries; }
    if (config.maxSteps <= 0) { progress_.store(1); return entries; }
    entries.reserve(std::min(config.maxSteps, 10000));
    disasm_.setArch(proc.runs32BitCode() ? Arch::X86_32 : Arch::X86_64);

    struct ThreadState {
        bool stopped = false;
        bool alive = true;
        int signal = 0;
        int event = 0;
        bool released = false;
        bool savedDebug = false;
        uint64_t dr0 = 0, dr6 = 0, dr7 = 0;
    };
    std::map<pid_t, ThreadState> threads;
    auto consume = [&](pid_t tid, int status) {
        auto& state = threads.at(tid);
        if (WIFEXITED(status) || WIFSIGNALED(status)) state.alive = false;
        else if (WIFSTOPPED(status)) {
            state.stopped = true;
            state.signal = WSTOPSIG(status);
            state.event = status >> 16;
            if (state.event != 0) state.signal = 0;
            else if (state.signal == SIGTRAP) {
                siginfo_t si{};
                if (ptrace(PTRACE_GETSIGINFO, tid, nullptr, &si) == 0 &&
                    (si.si_code == TRAP_HWBKPT || si.si_code == TRAP_TRACE)) state.signal = 0;
            }
        }
    };
    auto waitThread = [&](pid_t tid, int& status, bool cancellable = true) {
        for (;;) {
            if (cancellable && cancelled_.load()) return false;
            pid_t result = waitpid(tid, &status, __WALL | WNOHANG);
            if (result == tid) {
                consume(tid, status);
                return threads.at(tid).alive && threads.at(tid).stopped;
            }
            if (result < 0 && errno != EINTR) {
                if (errno == ECHILD || errno == ESRCH) threads.at(tid).alive = false;
                return false;
            }
            usleep(1000);
        }
    };
    auto resume = [&](pid_t tid, enum __ptrace_request request) {
        auto& state = threads.at(tid);
        if (ptrace(request, tid, nullptr,
                   reinterpret_cast<void*>(static_cast<intptr_t>(state.signal))) < 0) return false;
        state.stopped = false;
        state.signal = 0;
        state.event = 0;
        return true;
    };
    auto restoreDebug = [&](pid_t tid) {
        auto& state = threads.at(tid);
        if (!state.savedDebug) return;
        const size_t offset = offsetof(struct user, u_debugreg);
        ptrace(PTRACE_POKEUSER, tid, offset + 7 * sizeof(long), 0L);
        ptrace(PTRACE_POKEUSER, tid, offset, static_cast<long>(state.dr0));
        ptrace(PTRACE_POKEUSER, tid, offset + 6 * sizeof(long), static_cast<long>(state.dr6));
        ptrace(PTRACE_POKEUSER, tid, offset + 7 * sizeof(long), static_cast<long>(state.dr7));
    };
    auto arm = [&](pid_t tid, uintptr_t address) {
        auto& state = threads.at(tid);
        if (!state.savedDebug) {
            auto context = dbg.getContext(tid);
            if (!context) return false;
            state.dr0 = context->dr0; state.dr6 = context->dr6; state.dr7 = context->dr7;
            state.savedDebug = true;
        }
        return static_cast<bool>(dbg.setBreakpoint(tid, 0, address, 0, 0));
    };
    auto addClone = [&](pid_t parent) {
        unsigned long child = 0;
        if (ptrace(PTRACE_GETEVENTMSG, parent, nullptr, &child) < 0 || !child) return pid_t{0};
        pid_t tid = static_cast<pid_t>(child);
        ThreadState state = threads.at(parent);
        state.stopped = false;
        state.signal = 0;
        state.event = 0;
        state.released = false;
        threads.emplace(tid, state);
        int status = 0;
        if (!waitThread(tid, status)) return pid_t{0};
        threads.at(tid).signal = 0; // The initial auto-attach stop belongs to ptrace.
        return tid;
    };
    struct Cleanup {
        std::function<void()> action;
        ~Cleanup() { action(); }
    } cleanup{[&] {
        // Register writes and DETACH require a stopped tracee. Cancellation while
        // waiting for a breakpoint must disarm before releasing the target.
        for (;;) {
            auto it = std::find_if(threads.begin(), threads.end(), [](const auto& entry) {
                return entry.second.alive && !entry.second.released;
            });
            if (it == threads.end()) break;
            auto& [tid, state] = *it;
            state.released = true;
            int status = 0;
            if (!state.stopped) {
                ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr);
                if (!waitThread(tid, status, false)) continue;
            }
            if (state.event == PTRACE_EVENT_CLONE) {
                unsigned long child = 0;
                if (ptrace(PTRACE_GETEVENTMSG, tid, nullptr, &child) == 0 && child) {
                    ThreadState inherited = state;
                    inherited.stopped = false; inherited.signal = 0;
                    inherited.event = 0; inherited.released = false;
                    threads.emplace(static_cast<pid_t>(child), inherited);
                }
            }
            restoreDebug(tid);
            ptrace(PTRACE_DETACH, tid, nullptr,
                   reinterpret_cast<void*>(static_cast<intptr_t>(state.signal)));
        }
        progress_.store(1);
    }};

    std::vector<pid_t> tids;
    for (const auto& thread : proc.threads()) tids.push_back(thread.tid);
    if (tids.empty()) tids.push_back(proc.pid());
    for (pid_t tid : tids) {
        if (cancelled_.load()) return entries;
        if (ptrace(PTRACE_SEIZE, tid, nullptr, reinterpret_cast<void*>(PTRACE_O_TRACECLONE)) < 0) continue;
        threads.emplace(tid, ThreadState{});
        if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) < 0) return entries;
        int status = 0;
        if (!waitThread(tid, status)) return entries;
    }
    if (threads.empty()) return entries;
    pid_t traceTid = threads.contains(proc.pid()) ? proc.pid() : threads.begin()->first;

    if (config.startAddress) {
        for (auto& [tid, state] : threads) {
            if (!state.alive || !arm(tid, config.startAddress) || !resume(tid, PTRACE_CONT)) return entries;
        }
        bool hit = false;
        while (!hit && !cancelled_.load()) {
            bool alive = false;
            for (auto& [tid, state] : threads) {
                if (!state.alive || state.stopped) continue;
                alive = true;
                int status = 0;
                pid_t result = waitpid(tid, &status, __WALL | WNOHANG);
                if (result < 0 && errno != EINTR) { state.alive = false; continue; }
                if (result != tid) continue;
                consume(tid, status);
                if (!state.alive || !state.stopped) continue;
                if ((status >> 16) == PTRACE_EVENT_CLONE) {
                    pid_t child = addClone(tid);
                    if (!child || !arm(child, config.startAddress) || !resume(child, PTRACE_CONT)) return entries;
                } else if (WSTOPSIG(status) == SIGTRAP && (status >> 16) == 0) {
                    siginfo_t si{};
                    auto ctx = dbg.getContext(tid);
                    if (ptrace(PTRACE_GETSIGINFO, tid, nullptr, &si) == 0 &&
                        si.si_code == TRAP_HWBKPT && ctx && ctx->rip == config.startAddress) {
                        traceTid = tid; hit = true; break;
                    }
                }
                if (!resume(tid, PTRACE_CONT)) return entries;
            }
            if (!alive) return entries;
            if (!hit) usleep(1000);
        }
        if (!hit) return entries;
        for (auto& [tid, state] : threads) {
            if (!state.alive) continue;
            if (!state.stopped) {
                if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) < 0) return entries;
                int status = 0;
                if (!waitThread(tid, status)) return entries;
                if ((status >> 16) == PTRACE_EVENT_CLONE && !addClone(tid)) return entries;
            }
            restoreDebug(tid);
        }
    }

    for (int step = 0; step < config.maxSteps && !cancelled_.load(); ++step) {
        progress_.store(static_cast<float>(step) / config.maxSteps);
        auto ctx = dbg.getContext(traceTid);
        if (!ctx) break;
        uint8_t bytes[16];
        auto read = proc.read(ctx->rip, bytes, sizeof(bytes));
        size_t count = read ? std::min(*read, sizeof(bytes)) : 0;
        auto instructions = disasm_.disassemble(ctx->rip, {bytes, count}, 1);
        std::string text = instructions.empty() ? "??" : instructions[0].mnemonic + " " + instructions[0].operands;
        entries.push_back({ctx->rip, text, *ctx});
        if ((config.stopAddress && ctx->rip == config.stopAddress) ||
            (config.stayInModule && config.moduleBase &&
             (ctx->rip < config.moduleBase || ctx->rip >= config.moduleEnd))) break;

        bool overCall = config.stepOverCalls && !instructions.empty() && instructions[0].mnemonic == "call";
        uintptr_t next = overCall ? ctx->rip + instructions[0].size : 0;
        if (overCall && !arm(traceTid, next)) break;
        if (!resume(traceTid, overCall ? PTRACE_CONT : PTRACE_SINGLESTEP)) break;
        for (;;) {
            int status = 0;
            if (!waitThread(traceTid, status)) return entries;
            if ((status >> 16) == PTRACE_EVENT_CLONE) {
                if (!addClone(traceTid) || !resume(traceTid, overCall ? PTRACE_CONT : PTRACE_SINGLESTEP)) return entries;
                continue;
            }
            siginfo_t si{};
            if (WSTOPSIG(status) != SIGTRAP || (status >> 16) != 0 ||
                ptrace(PTRACE_GETSIGINFO, traceTid, nullptr, &si) < 0) return entries;
            if (!overCall && si.si_code == TRAP_TRACE) break;
            auto context = dbg.getContext(traceTid);
            if (overCall && si.si_code == TRAP_HWBKPT && context && context->rip == next) {
                restoreDebug(traceTid);
                break;
            }
            // Preserve genuine signals and unrelated traps for the target.
            if (!overCall || !resume(traceTid, PTRACE_CONT)) return entries;
        }
    }
    return entries;
}

} // namespace ce
