#include "core/target_capabilities.hpp"
#include "arch/target_arch.hpp"
#include "debug/tracer.hpp"
#include "platform/linux/target_debug.hpp"

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <functional>
#include <map>
#include <stdexcept>

namespace ce {

std::vector<TraceEntry> Tracer::trace(ProcessHandle& proc, Debugger& dbg, const TraceConfig& config) {
    std::unique_lock traceLock(traceMutex_,std::try_to_lock);
    if (!traceLock.owns_lock()) {
        std::lock_guard lock(errorMutex_);
        error_=std::make_error_code(std::errc::device_or_resource_busy);
        return {};
    }
    cancelled_.store(false);
    progress_.store(0);
    ready_=false;
    auto error=[&](Error value) { std::lock_guard lock(errorMutex_); error_=value; };
    error({});
    std::vector<TraceEntry> entries;
    std::optional<Disassembler> disassembler;
    // A remote PID is meaningful only on its server. Local ptrace must never
    // attach an unrelated local task that happens to have the same PID.
    if (proc.targetDescription().transport!=TargetTransport::Local || unsupportedTargetOperation(proc, TargetFeature::Trace)) {
        error(std::make_error_code(std::errc::not_supported)); progress_.store(1); return entries;
    }
    if (config.maxSteps<=0 || (config.stayInModule && config.moduleEnd<=config.moduleBase)) {
        error(std::make_error_code(std::errc::invalid_argument)); progress_.store(1); return entries;
    }
    entries.reserve(std::min(config.maxSteps, 10000));

    struct ThreadState {
        bool stopped = false;
        bool alive = true;
        int signal = 0;
        int event = 0;
        bool released = false;
        bool savedDebug = false;
        bool stepping = false;
        uintptr_t armedAddress = 0;
        os::NativeHardwareBank originalDebug;
        unsigned slot=0;
    };
    std::map<pid_t, ThreadState> threads;
    auto consume = [&](pid_t tid, int status) {
        auto& state = threads.at(tid);
        if (WIFEXITED(status) || WIFSIGNALED(status)) state.alive = false;
        else if (WIFSTOPPED(status)) {
            state.stopped = true;
            state.signal = WSTOPSIG(status);
            state.event = status >> 16;
            if (state.event==PTRACE_EVENT_EXEC) {
                // Exec retires the old instruction addresses and debug banks.
                for (auto& [otherTid,other] : threads) {
                    other.savedDebug=false;
                    if (otherTid!=tid) other.alive=false;
                }
                proc.targetDescription();
            }
            if (state.event != 0) state.signal = 0;
            else if (state.signal == SIGTRAP) {
                siginfo_t si{};
                if (ptrace(PTRACE_GETSIGINFO, tid, nullptr, &si) == 0) {
                    auto context=dbg.getContext(tid);
                    bool ownBreakpoint=si.si_code==TRAP_HWBKPT && state.armedAddress && context &&
                        context->instructionPointer()==state.armedAddress;
                    bool ownStep=state.stepping && (si.si_code==TRAP_TRACE || os::isNativeSyscallStepTrap(tid,si));
                    if (ownBreakpoint || ownStep) state.signal=0;
                }
            }
        }
    };
    auto waitThread = [&](pid_t tid, int& status, bool cancellable = true) {
        for (;;) {
            if (cancellable && cancelled_.load()) return false;
            pid_t result = waitpid(tid, &status, __WALL | __WNOTHREAD | WNOHANG);
            if (result == tid) {
                consume(tid, status);
                return threads.at(tid).alive && threads.at(tid).stopped;
            }
            if (result < 0 && errno != EINTR) {
                if (errno == ECHILD || errno == ESRCH) threads.at(tid).alive = false;
                else error({errno,std::system_category()});
                return false;
            }
            usleep(1000);
        }
    };
    auto resume = [&](pid_t tid, enum __ptrace_request request) {
        auto& state = threads.at(tid);
        if (ptrace(request, tid, nullptr,
                   reinterpret_cast<void*>(static_cast<intptr_t>(state.signal))) < 0) {
            error({errno,std::system_category()}); return false;
        }
        state.stopped = false;
        state.signal = 0;
        state.event = 0;
        state.stepping=request==PTRACE_SINGLESTEP;
        return true;
    };
    auto restoreDebug = [&](pid_t tid) {
        auto& state = threads.at(tid);
        if (!state.savedDebug) return true;
        auto restored=os::restoreNativeHardwareBank(tid,true,state.originalDebug);
        if (!restored) error(restored.error());
        else state.armedAddress=0;
        return restored.has_value();
    };
    auto arm = [&](pid_t tid, uintptr_t address) {
        auto& state = threads.at(tid);
        if (!state.savedDebug) {
            auto bank=os::readNativeHardwareBank(tid,true);
            if (!bank) { error(bank.error()); return false; }
            state.originalDebug=*bank;
            while (state.slot<bank->count && (bank->entries[state.slot].control&
                (nativeTargetMachine().architecture==CpuArchitecture::Arm64 ? 1u : 3u))) ++state.slot;
            if (state.slot==bank->count) { error(std::make_error_code(std::errc::no_space_on_device)); return false; }
            state.savedDebug = true;
        }
        auto armed=os::setNativeHardwareBreakpoint(tid,state.slot,address,os::HardwareBreakpointAccess::Execute,
            nativeTargetMachine().architecture==CpuArchitecture::Arm64 ? 4 : 1);
        if (!armed) error(armed.error());
        else state.armedAddress=address;
        return armed.has_value();
    };
    auto addClone = [&](pid_t parent) {
        unsigned long child = 0;
        if (ptrace(PTRACE_GETEVENTMSG, parent, nullptr, &child) < 0 || !child) {
            error({errno ? errno : EIO,std::system_category()}); return pid_t{0};
        }
        pid_t tid = static_cast<pid_t>(child);
        threads.emplace(tid,ThreadState{});
        int status = 0;
        if (!threads.at(tid).stopped && !waitThread(tid, status)) return pid_t{0};
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
            int status = 0;
            pid_t pending=waitpid(tid,&status,__WALL|__WNOTHREAD|WNOHANG);
            if (pending==tid) consume(tid,status);
            else if (pending<0 && (errno==ECHILD || errno==ESRCH)) state.alive=false;
            if (!state.alive) continue;
            if (!state.stopped) {
                ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr);
                if (!waitThread(tid, status, false)) { usleep(20000); continue; }
            }
            if (state.event == PTRACE_EVENT_CLONE) {
                unsigned long child = 0;
                if (ptrace(PTRACE_GETEVENTMSG, tid, nullptr, &child) == 0 && child) {
                    threads.emplace(static_cast<pid_t>(child),ThreadState{});
                }
            }
            if (!restoreDebug(tid)) { usleep(20000); continue; }
            if (ptrace(PTRACE_DETACH,tid,nullptr,reinterpret_cast<void*>(static_cast<intptr_t>(state.signal)))<0 &&
                errno!=ESRCH && errno!=ECHILD) {
                error({errno,std::system_category()}); usleep(20000); continue;
            }
            state.released=true;
        }
        progress_.store(1);
        ready_=false;
    }};

    std::vector<pid_t> tids;
    for (const auto& thread : proc.threads()) tids.push_back(thread.tid);
    if (tids.empty()) tids.push_back(proc.pid());
    for (pid_t tid : tids) {
        if (cancelled_.load()) return entries;
        // A clone event from an earlier parent can already own a listed child.
        // Seizing it again would fail and lose the retained ownership record.
        if (threads.contains(tid)) continue;
        threads.emplace(tid, ThreadState{});
        if (ptrace(PTRACE_SEIZE,tid,nullptr,reinterpret_cast<void*>(PTRACE_O_TRACECLONE|PTRACE_O_TRACEEXEC))<0) {
            int failure=errno;
            threads.erase(tid);
            if (failure==ESRCH) continue;
            error({failure,std::system_category()}); return entries;
        }
        if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) < 0) {
            error({errno,std::system_category()}); return entries;
        }
        int status = 0;
        if (!waitThread(tid, status)) return entries;
        if (threads.at(tid).event==PTRACE_EVENT_CLONE && !addClone(tid)) return entries;
        if (threads.at(tid).event==PTRACE_EVENT_EXEC) return entries;
    }
    if (threads.empty()) return entries;
    pid_t traceTid = threads.contains(proc.pid()) ? proc.pid() : threads.begin()->first;

    if (config.startAddress) {
        for (auto& [tid, state] : threads) {
            if (!state.alive || !arm(tid, config.startAddress) || !resume(tid, PTRACE_CONT)) return entries;
        }
        ready_=true;
        bool hit = false;
        while (!hit && !cancelled_.load()) {
            bool alive = false;
            for (auto& [tid, state] : threads) {
                if (!state.alive || state.stopped) continue;
                alive = true;
                int status = 0;
                pid_t result = waitpid(tid, &status, __WALL | __WNOTHREAD | WNOHANG);
                if (result<0 && errno!=EINTR) {
                    if (errno==ECHILD || errno==ESRCH) { state.alive=false; continue; }
                    error({errno,std::system_category()}); return entries;
                }
                if (result != tid) continue;
                consume(tid, status);
                if (!state.alive || !state.stopped) continue;
                if (state.event==PTRACE_EVENT_EXEC) return entries;
                if ((status >> 16) == PTRACE_EVENT_CLONE) {
                    pid_t child = addClone(tid);
                    if (!child || !arm(child, config.startAddress) || !resume(child, PTRACE_CONT)) return entries;
                } else if (WSTOPSIG(status) == SIGTRAP && (status >> 16) == 0) {
                    siginfo_t si{};
                    auto ctx = dbg.getContext(tid);
                    if (ptrace(PTRACE_GETSIGINFO, tid, nullptr, &si) == 0 &&
                        si.si_code == TRAP_HWBKPT && ctx && ctx->instructionPointer() == config.startAddress) {
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
                if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) < 0) {
                    error({errno,std::system_category()}); return entries;
                }
                int status = 0;
                if (!waitThread(tid, status)) return entries;
                if ((status >> 16) == PTRACE_EVENT_CLONE && !addClone(tid)) return entries;
            }
            if (!restoreDebug(tid)) return entries;
        }
    }

    for (int step = 0; step < config.maxSteps && !cancelled_.load(); ++step) {
        progress_.store(static_cast<float>(step) / config.maxSteps);
        auto ctx = dbg.getContext(traceTid);
        if (!ctx) { error(ctx.error()); break; }
        uintptr_t pc=ctx->instructionPointer();
        auto architecture=disassemblerArchFor(proc,pc);
        if (!architecture) { error(std::make_error_code(std::errc::not_supported)); break; }
        try {
            if (!disassembler) disassembler.emplace(*architecture);
            else disassembler->setArch(*architecture);
        } catch (const std::runtime_error&) {
            error(std::make_error_code(std::errc::not_supported));
            break;
        }
        uint8_t bytes[16];
        auto read = proc.read(pc, bytes, sizeof(bytes));
        if (!read) { error(read.error()); break; }
        size_t count = read ? std::min(*read, sizeof(bytes)) : 0;
        auto instructions = disassembler->disassemble(pc, {bytes, count}, 1);
        if (instructions.empty()) { error(std::make_error_code(std::errc::illegal_byte_sequence)); break; }
        std::string text = instructions[0].mnemonic + " " + instructions[0].operands;
        entries.push_back({pc, text, *ctx});
        if ((config.stopAddress && pc == config.stopAddress) ||
            (config.stayInModule &&
             (pc < config.moduleBase || pc >= config.moduleEnd))) break;

        bool overCall = config.stepOverCalls && !instructions.empty() && instructions[0].isCall;
        uintptr_t next = overCall ? pc + instructions[0].size : 0;
        if (overCall && !arm(traceTid, next)) break;
        if (!resume(traceTid, overCall ? PTRACE_CONT : PTRACE_SINGLESTEP)) break;
        for (;;) {
            int status = 0;
            if (!waitThread(traceTid, status)) return entries;
            if ((status >> 16) == PTRACE_EVENT_CLONE) {
                if (!addClone(traceTid) || !resume(traceTid, overCall ? PTRACE_CONT : PTRACE_SINGLESTEP)) return entries;
                continue;
            }
            if ((status>>16)==PTRACE_EVENT_EXEC) return entries;
            if ((status>>8)==(SIGTRAP|(PTRACE_EVENT_STOP<<8))) {
                if (!resume(traceTid,overCall ? PTRACE_CONT : PTRACE_SINGLESTEP)) return entries;
                continue;
            }
            siginfo_t si{};
            if (WSTOPSIG(status) != SIGTRAP || (status >> 16) != 0 ||
                ptrace(PTRACE_GETSIGINFO, traceTid, nullptr, &si) < 0) return entries;
            if (!overCall && (si.si_code==TRAP_TRACE || os::isNativeSyscallStepTrap(traceTid,si))) {
                threads.at(traceTid).signal=0;
                break;
            }
            auto context = dbg.getContext(traceTid);
            if (overCall && si.si_code == TRAP_HWBKPT && context && context->instructionPointer() == next) {
                if (!restoreDebug(traceTid)) return entries;
                break;
            }
            // Preserve genuine signals and unrelated traps for the target.
            if (!overCall || !resume(traceTid, PTRACE_CONT)) return entries;
        }
    }
    return entries;
}

} // namespace ce
