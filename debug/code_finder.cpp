#include "core/target_capabilities.hpp"
#include "arch/target_arch.hpp"
#include "debug/code_finder.hpp"
#include "core/log.hpp"
#include "symbols/elf_symbols.hpp"
#include "platform/linux/target_debug.hpp"
#include "platform/linux/target_syscall.hpp"

#include <cstdlib>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cerrno>
#include <cstring>
#include <set>
#include <map>
#include <functional>
#include <stdexcept>
#include <array>

#ifndef __WALL
#define __WALL 0x40000000
#endif

namespace ce {

bool CodeFinder::start(ProcessHandle& proc, Debugger& dbg, uintptr_t address, bool writesOnly, int watchSize, bool software, bool singleThread) {
    std::lock_guard lifecycle(lifecycleMutex_);
    if (running_) { setError(std::make_error_code(std::errc::device_or_resource_busy)); return false; }
    if (proc.targetDescription().transport!=TargetTransport::Local ||
        unsupportedTargetOperation(proc,software ? TargetFeature::SoftwareWatchpoint : TargetFeature::HardwareWatchpoint)) {
        setError(std::make_error_code(std::errc::not_supported)); return false;
    }
    if (!address || (watchSize!=1 && watchSize!=2 && watchSize!=4 && watchSize!=8) ||
        address>UINTPTR_MAX-static_cast<unsigned>(watchSize)) {
        setError(std::make_error_code(std::errc::invalid_argument)); return false;
    }
    setError({});
    recoveryPending_=false;
    if (monitorThread_.joinable()) monitorThread_.join();

    proc_ = &proc;
    dbg_ = &dbg;
    host_=proc.targetDescription().host;
    disasm_.reset();
    symbols_.loadProcess(proc);
    targetAddress_ = address;
    writesOnly_ = writesOnly;
    watchSize_ = watchSize;
    software_ = software;
    singleThread_ = singleThread || proc.targetDescription().runtime == TargetRuntime::Wine;
    stopRequested_ = false;
    running_ = true;
    startup_ = std::promise<bool>{};
    auto ready = startup_.get_future();

    try {
        monitorThread_=std::thread([this] {
            try { monitorLoop(); }
            catch (const std::bad_alloc&) { setError(std::make_error_code(std::errc::not_enough_memory)); }
            catch (const std::exception&) { setError(std::make_error_code(std::errc::io_error)); }
            running_=false;
            try { startup_.set_value(false); } catch (const std::future_error&) {}
        });
    } catch (...) {
        running_ = false;
        throw;
    }
    bool armed = ready.get();
    if (!armed) { stopRequested_=true; if (monitorThread_.joinable()) monitorThread_.join(); }
    return armed;
}

void CodeFinder::stop() {
    stopRequested_ = true;
    std::lock_guard lifecycle(lifecycleMutex_);
    // A concurrent startup may clear the flag while holding this mutex.
    // Request cancellation again once its startup transaction has finished.
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
        [](const CodeFinderResult& a, const CodeFinderResult& b) {
            return a.hitCount!=b.hitCount ? a.hitCount>b.hitCount : a.instructionAddress<b.instructionAddress;
        });
    return res;
}

void CodeFinder::clearResults() {
    std::lock_guard lock(resultsMutex_);
    resultsMap_.clear();
}

void CodeFinder::monitorLoop() {
    struct Thread {
        bool alive=true,stopped=false,saved=false,armed=false,stepping=false,groupStop=false,guardStop=false;
        std::optional<siginfo_t> signalInfo;
        std::optional<siginfo_t> deferredInfo;
        int deferredSignal=0;
        int signal=0,event=0;
        unsigned slot=0;
        os::NativeHardwareBank original;
    };
    std::map<pid_t,Thread> threads;
    uintptr_t scratch=0,pageStart=0,pageEnd=0;
    size_t pageLength=0,pageSize=0;
    int originalProtection=0,guardProtection=0;
    bool guardChanged=false,guardActive=false,imageRetired=false;
    bool startupReported=false;
    auto reportStartup=[&](bool success) { if (!startupReported) { startup_.set_value(success); startupReported=true; } };
    auto consume=[&](pid_t tid,int status) {
        auto& state=threads.try_emplace(tid).first->second;
        if (WIFEXITED(status) || WIFSIGNALED(status)) { state.alive=false; return; }
        if (!WIFSTOPPED(status)) return;
        state.stopped=true; state.event=status>>16;
        state.signal=state.event ? 0 : WSTOPSIG(status);
        state.signalInfo.reset(); state.guardStop=false;
        if (state.signal) {
            siginfo_t info{};
            if (ptrace(PTRACE_GETSIGINFO,tid,nullptr,&info)==0) {
                state.signalInfo=info;
                state.guardStop=software_ && guardActive && state.signal==SIGSEGV && info.si_code==SEGV_ACCERR &&
                    reinterpret_cast<uintptr_t>(info.si_addr)>=pageStart && reinterpret_cast<uintptr_t>(info.si_addr)<pageEnd;
            }
        }
        state.groupStop=state.event==PTRACE_EVENT_STOP && WSTOPSIG(status)!=SIGTRAP;
        if (state.event==PTRACE_EVENT_EXEC) {
            for (auto& [otherTid,other] : threads) {
                other.saved=false; other.armed=false;
                if (otherTid!=tid) other.alive=false;
            }
            state.alive=true; imageRetired=true;
            setError(std::make_error_code(std::errc::operation_canceled)); stopRequested_=true;
        }
        if (state.stepping && !state.event && state.signal==SIGTRAP) {
            siginfo_t info{};
            if (ptrace(PTRACE_GETSIGINFO,tid,nullptr,&info)==0 &&
                (info.si_code==TRAP_TRACE || (nativeTargetMachine().architecture==CpuArchitecture::Arm64 &&
                 info.si_code==SI_USER && !info.si_pid && !info.si_uid))) state.signal=0;
        }
    };
    auto waitForStop=[&](pid_t tid) {
        for (;;) {
            int status=0;
            pid_t waited=waitpid(tid,&status,__WALL|__WNOTHREAD|WNOHANG);
            if (waited==tid) { consume(tid,status); return threads.at(tid).alive && threads.at(tid).stopped; }
            if (waited<0 && errno!=EINTR) {
                if (errno==ECHILD || errno==ESRCH) threads.at(tid).alive=false;
                else setError({errno,std::system_category()});
                return false;
            }
            usleep(1000);
        }
    };
    auto restore=[&](pid_t tid) {
        auto& state=threads.at(tid);
        if (!state.saved) return true;
        auto result=os::restoreNativeHardwareBank(tid,false,state.original);
        if (!result) { setError(result.error()); recoveryPending_=true; return false; }
        state.armed=false; return true;
    };
    auto arm=[&](pid_t tid) {
        auto& state=threads.at(tid);
        if (software_) return true;
        if (!state.saved) {
            auto bank=os::readNativeHardwareBank(tid,false);
            if (!bank) { setError(bank.error()); return false; }
            state.original=*bank;
            bool arm64=nativeTargetMachine().architecture==CpuArchitecture::Arm64;
            while (state.slot<bank->count && (bank->entries[state.slot].control&(arm64 ? 1u : 3u))) ++state.slot;
            if (state.slot==bank->count) { setError(std::make_error_code(std::errc::no_space_on_device)); return false; }
            state.saved=true;
        }
        auto result=os::setNativeHardwareBreakpoint(tid,state.slot,targetAddress_,
            writesOnly_ ? os::HardwareBreakpointAccess::Write : os::HardwareBreakpointAccess::ReadWrite,watchSize_);
        if (!result) { setError(result.error()); recoveryPending_=true; return false; }
        state.armed=true; return true;
    };
    auto resume=[&](pid_t tid,bool step=false,bool forceContinue=false) {
        auto& state=threads.at(tid);
        auto request=step ? PTRACE_SINGLESTEP : state.groupStop && !forceContinue ? PTRACE_LISTEN : PTRACE_CONT;
        if (state.signal && state.signalInfo && ptrace(PTRACE_SETSIGINFO,tid,nullptr,&*state.signalInfo)<0) {
            setError({errno,std::system_category()}); return false;
        }
        if (ptrace(request,tid,nullptr,reinterpret_cast<void*>(intptr_t(state.signal)))<0) {
            setError({errno,std::system_category()}); return false;
        }
        state.stopped=false; state.signal=0; state.signalInfo.reset(); state.guardStop=false; state.event=0; state.stepping=step; return true;
    };
    auto ownsHardwareTrap=[&](pid_t tid,const siginfo_t& info) -> Result<bool> {
        auto& state=threads.at(tid);
        if (software_ || !state.armed || info.si_signo!=SIGTRAP || info.si_code!=TRAP_HWBKPT) return false;
        if (host_.architecture==CpuArchitecture::Arm64) {
            auto address=reinterpret_cast<uintptr_t>(info.si_addr);
            return address>=targetAddress_ && address<targetAddress_+watchSize_;
        }
        auto bank=os::readNativeHardwareBank(tid,false);
        if (!bank) return std::unexpected(bank.error());
        return (bank->status&(uint64_t{1}<<state.slot))!=0;
    };
    auto clearHardwareStop=[&](pid_t tid) {
        auto& state=threads.at(tid);
        if (state.event || state.signal!=SIGTRAP) return true;
        siginfo_t info{};
        if (ptrace(PTRACE_GETSIGINFO,tid,nullptr,&info)<0) {setError({errno,std::system_category()});return false;}
        auto owned=ownsHardwareTrap(tid,info);
        if (!owned) {setError(owned.error());return false;}
        if (*owned) {state.signal=0;state.signalInfo.reset();}
        return true;
    };
    auto queuedHardwareTrap=[&](pid_t tid) -> Result<bool> {
        struct {uint64_t offset;uint32_t flags;int32_t count;} peek{0,0,32};
        std::array<siginfo_t,32> pending{};
        for (;;) {
            auto count=ptrace(PTRACE_PEEKSIGINFO,tid,&peek,pending.data());
            if (count<0) return std::unexpected(Error(errno,std::system_category()));
            for (long i=0;i<count;++i) {
                auto owned=ownsHardwareTrap(tid,pending[i]);
                if (!owned || *owned) return owned;
            }
            if (!count) return false;
            peek.offset+=static_cast<uint64_t>(count);
        }
    };
    auto drainHardwareTraps=[&](pid_t tid) {
        auto& state=threads.at(tid);
        if (software_ || !state.armed) return true;
        while (state.alive && state.armed) {
            if (!clearHardwareStop(tid)) return false;
            auto queued=queuedHardwareTrap(tid);
            if (!queued) {setError(queued.error());return false;}
            if (!*queued) break;
            // INTERRUPT can win before a synchronous watchpoint signal reaches
            // its delivery stop. Drain that signal before clearing DR6/slots.
            // Keep an already observed application signal for final detach.
            if (state.signal) {
                if (state.deferredSignal) {setError(std::make_error_code(std::errc::resource_unavailable_try_again));return false;}
                state.deferredSignal=state.signal;state.deferredInfo=state.signalInfo;
                state.signal=0;state.signalInfo.reset();
            }
            // A pending synchronous trap stops before another user instruction.
            // CONT also releases a group-stop to its delivery stop; DETACH
            // reinstates the kernel's group-stop state without adding SIGSTOP.
            if (!resume(tid,false,true) || !waitForStop(tid)) return !state.alive;
        }
        if (state.deferredSignal) {
            state.signal=state.deferredSignal;state.signalInfo=state.deferredInfo;
            state.deferredSignal=0;state.deferredInfo.reset();
        }
        return true;
    };
    auto adopt=[&](pid_t parent) {
        unsigned long child=0;
        if (ptrace(PTRACE_GETEVENTMSG,parent,nullptr,&child)<0 || !child) {
            setError({errno ? errno : EIO,std::system_category()}); return pid_t{0};
        }
        pid_t tid=static_cast<pid_t>(child);
        threads.try_emplace(tid);
        // An automatic child stop may have arrived before its parent's event.
        if (!threads.at(tid).stopped && !waitForStop(tid)) return pid_t{0};
        threads.at(tid).signal=0;
        return tid;
    };
    auto stopAll=[&] {
        for (;;) {
            bool pending=false;
            for (auto& [tid,state] : threads) {
                if (!state.alive) continue;
                if (!state.stopped) {
                    pending=true;
                    ptrace(PTRACE_INTERRUPT,tid,nullptr,nullptr);
                    if (!waitForStop(tid)) continue;
                }
                if (state.event==PTRACE_EVENT_CLONE && !adopt(tid)) return false;
            }
            bool running=std::any_of(threads.begin(),threads.end(),[](const auto& entry) {
                return entry.second.alive && !entry.second.stopped;
            });
            if (!running) return true;
            if (pending) usleep(20000);
        }
    };
    auto guardFault=[&](pid_t tid,siginfo_t* details=nullptr) {
        auto& state=threads.at(tid);
        if (state.event || state.signal!=SIGSEGV || !state.guardStop) return false;
        siginfo_t info{};
        if (ptrace(PTRACE_GETSIGINFO,tid,nullptr,&info)<0 || info.si_code!=SEGV_ACCERR) return false;
        uintptr_t fault=reinterpret_cast<uintptr_t>(info.si_addr);
        if (details) *details=info;
        return fault>=pageStart && fault<pageEnd;
    };
    auto releaseScratch=[&] {
        if (!scratch || imageRetired) { scratch=0; return true; }
        auto owner=std::find_if(threads.begin(),threads.end(),[](const auto& entry) { return entry.second.alive && entry.second.stopped; });
        if (owner!=threads.end()) {
            if (runStoppedSyscall(owner->first,os::MemorySyscall::Unmap,{scratch,pageSize,0,0,0,0},0,owner->second.signal,&owner->second.signalInfo)!=0) return false;
        } else {
            if (!proc_->targetDescription().live) { scratch=0; return true; }
            auto freed=proc_->free(scratch,pageSize);
            if (!freed) { setError(freed.error()); recoveryPending_=true; return false; }
        }
        scratch=0; return true;
    };
    struct Cleanup { std::function<void()> action; ~Cleanup() { action(); } } cleanup{[&] {
        reportStartup(false);
        if (software_) {
            for (;;) {
                if (!stopAll()) { recoveryPending_=true; usleep(20000); continue; }
                if (imageRetired) { guardChanged=false; guardActive=false; scratch=0; break; }
                for (auto& [tid,state] : threads) if (state.alive && guardFault(tid)) {
                    state.signal=0; state.signalInfo.reset(); state.guardStop=false;
                }
                auto owner=std::find_if(threads.begin(),threads.end(),[](const auto& entry) { return entry.second.alive && entry.second.stopped; });
                if (guardChanged && owner!=threads.end()) {
                    if (setStoppedProtection(owner->first,scratch,pageStart,pageLength,originalProtection,owner->second.signal,&owner->second.signalInfo)!=0) {
                        recoveryPending_=true; usleep(20000); continue;
                    }
                }
                guardChanged=false; guardActive=false;
                if (!releaseScratch()) { usleep(20000); continue; }
                break;
            }
        }
        for (;;) {
            auto it=std::find_if(threads.begin(),threads.end(),[](const auto& entry) { return entry.second.alive; });
            if (it==threads.end()) break;
            auto& [tid,state]=*it;
            int status=0;
            pid_t pending=waitpid(tid,&status,__WALL|__WNOTHREAD|WNOHANG);
            if (pending==tid) consume(tid,status);
            else if (pending<0 && (errno==ECHILD || errno==ESRCH)) state.alive=false;
            if (!state.alive) continue;
            if (!state.stopped) {
                ptrace(PTRACE_INTERRUPT,tid,nullptr,nullptr);
                if (!waitForStop(tid)) { usleep(20000); continue; }
            }
            if (state.event==PTRACE_EVENT_CLONE && !adopt(tid)) { usleep(20000); continue; }
            if (!drainHardwareTraps(tid)) {recoveryPending_=true;usleep(20000);continue;}
            if (!state.alive) continue;
            if (software_ && guardFault(tid)) state.signal=0;
            if (!restore(tid)) { usleep(20000); continue; }
            if (state.signal && state.signalInfo && ptrace(PTRACE_SETSIGINFO,tid,nullptr,&*state.signalInfo)<0) {
                setError({errno,std::system_category()}); recoveryPending_=true; usleep(20000); continue;
            }
            if (ptrace(PTRACE_DETACH,tid,nullptr,reinterpret_cast<void*>(intptr_t(state.signal)))<0 &&
                errno!=ESRCH && errno!=ECHILD) {
                setError({errno,std::system_category()}); recoveryPending_=true; usleep(20000); continue;
            }
            state.alive=false;
        }
        recoveryPending_=false; running_=false;
    }};

    if (software_) {
        long nativePageSize=sysconf(_SC_PAGESIZE);
        if (nativePageSize<=0) { setError(std::make_error_code(std::errc::invalid_argument)); return; }
        pageSize=static_cast<size_t>(nativePageSize);
        pageStart=targetAddress_-targetAddress_%pageSize;
        uintptr_t last=targetAddress_+watchSize_-1;
        if (last>UINTPTR_MAX-pageSize) { setError(std::make_error_code(std::errc::value_too_large)); return; }
        pageEnd=last-last%pageSize+pageSize; pageLength=pageEnd-pageStart;
        bool found=false;
        for (const auto& region : proc_->queryRegions()) {
            if (pageStart<region.base || region.size>UINTPTR_MAX-region.base || pageEnd>region.base+region.size) continue;
            if (region.protection&MemProt::Read) originalProtection|=1;
            if (region.protection&MemProt::Write) originalProtection|=2;
            if (region.protection&MemProt::Exec) originalProtection|=4;
            found=true; break;
        }
        if (!found) { setError(std::make_error_code(std::errc::bad_address)); return; }
        if (writesOnly_ && !(originalProtection&2)) { setError(std::make_error_code(std::errc::permission_denied)); return; }
        guardProtection=writesOnly_ ? originalProtection&~2 : 0;
        auto allocation=proc_->allocate(pageSize,MemProt::All,targetAddress_);
        if (!allocation) { setError(allocation.error()); return; }
        scratch=*allocation;
    }
    std::vector<pid_t> tids;
    if (singleThread_ && !software_) {
        if (proc_->targetDescription().runtime==TargetRuntime::Wine) tids.push_back(proc_->pid());
        else {
            auto task=os::processMemoryTask(proc_->pid());
            if (!task) { setError(task.error()); return; }
            tids.push_back(*task);
        }
    }
    else for (const auto& thread : proc_->threads()) tids.push_back(thread.tid);
    if (tids.empty()) tids.push_back(proc_->pid());
    unsigned options=PTRACE_O_TRACEEXEC|(singleThread_ && !software_ ? 0 : PTRACE_O_TRACECLONE);
    for (pid_t tid : tids) {
        if (stopRequested_) return;
        if (threads.contains(tid)) continue;
        threads.try_emplace(tid);
        if (ptrace(PTRACE_SEIZE,tid,nullptr,reinterpret_cast<void*>(uintptr_t(options)))<0) {
            int failure=errno; threads.erase(tid);
            if (failure==ESRCH) continue;
            setError({failure,std::system_category()}); return;
        }
        if (ptrace(PTRACE_INTERRUPT,tid,nullptr,nullptr)<0) { setError({errno,std::system_category()}); return; }
        if (!waitForStop(tid)) return;
        if (threads.at(tid).event==PTRACE_EVENT_CLONE && !adopt(tid)) return;
        if (stopRequested_) return;
    }
    if (threads.empty()) { setError(std::make_error_code(std::errc::no_such_process)); return; }
    for (auto& [tid,state] : threads) if (state.alive && !arm(tid)) return;
    if (software_) {
        auto owner=std::find_if(threads.begin(),threads.end(),[](const auto& entry) { return entry.second.alive; });
        if (owner==threads.end()) return;
        guardChanged=true;
        if (setStoppedProtection(owner->first,scratch,pageStart,pageLength,guardProtection,owner->second.signal,&owner->second.signalInfo)!=0) return;
        guardActive=true;
    }
    for (auto& [tid,state] : threads) if (state.alive && !resume(tid)) return;
    reportStartup(true);

    while (!stopRequested_) {
        int status=0;
        pid_t tid=waitpid(-1,&status,__WALL|__WNOTHREAD|WNOHANG);
        if (tid<0 && errno==ECHILD) break;
        if (tid<0 && errno!=EINTR) { setError({errno,std::system_category()}); return; }
        if (tid<=0) { usleep(1000); continue; }
        bool unknown=!threads.contains(tid);
        consume(tid,status);
        auto& state=threads.at(tid);
        if (!state.alive) continue;
        if (stopRequested_) return;
        // Do not release an early child until its parent's clone event arms it.
        if (unknown) continue;
        if (state.event==PTRACE_EVENT_CLONE) {
            pid_t child=adopt(tid);
            if (!child || !arm(child) || !resume(child) || !resume(tid)) return;
            continue;
        }
        if (software_ && guardFault(tid)) {
            if (!stopAll() || imageRetired) return;
            siginfo_t info{};
            if (!guardFault(tid,&info)) return;
            uintptr_t fault=reinterpret_cast<uintptr_t>(info.si_addr);
            if (fault>=targetAddress_ && fault<targetAddress_+watchSize_ && !recordHit(tid,false)) return;
            state.signal=0; state.signalInfo.reset(); state.guardStop=false;
            if (setStoppedProtection(tid,scratch,pageStart,pageLength,originalProtection,state.signal,&state.signalInfo)!=0) return;
            guardActive=false;
            do {
                if (!resume(tid,true) || !waitForStop(tid)) return;
            } while (state.event==PTRACE_EVENT_STOP && !state.groupStop && !stopRequested_);
            if (state.event==PTRACE_EVENT_CLONE && !adopt(tid)) return;
            if (imageRetired || stopRequested_) return;
            if (setStoppedProtection(tid,scratch,pageStart,pageLength,guardProtection,state.signal,&state.signalInfo)!=0) return;
            guardActive=true;
            for (auto& [otherTid,other] : threads) {
                if (!other.alive) continue;
                if (guardFault(otherTid)) other.signal=0;
                if (!resume(otherTid)) return;
            }
            continue;
        }
        if (!software_ && !state.event && state.signal==SIGTRAP && state.armed) {
            siginfo_t info{};
            if (ptrace(PTRACE_GETSIGINFO,tid,nullptr,&info)<0) { setError({errno,std::system_category()}); return; }
            auto context=os::readNativeContext(tid);
            if (!context) { setError(context.error()); return; }
            bool arm64=context->architecture==CpuArchitecture::Arm64;
            if (info.si_code==TRAP_HWBKPT && !arm64 && !context->debugRegistersValid) {
                setError(std::make_error_code(std::errc::io_error));
                return;
            }
            bool own=info.si_code==TRAP_HWBKPT && (arm64 ?
                reinterpret_cast<uintptr_t>(info.si_addr)>=targetAddress_ &&
                reinterpret_cast<uintptr_t>(info.si_addr)<targetAddress_+watchSize_ :
                context->debugRegistersValid && (context->dr6&(uint64_t{1}<<state.slot)));
            if (own) {
                state.signal=0;
                if (!recordHit(tid,!arm64)) return;
                auto cleared=os::clearNativeHardwareStatus(tid);
                if (!cleared) { setError(cleared.error()); return; }
                if (arm64) {
                    // ARM64 stops before the access. Lift only our slot, step
                    // the original instruction, and rearm before continuing.
                    auto removed=os::removeNativeHardwareBreakpoint(tid,state.slot,false);
                    if (!removed) { setError(removed.error()); recoveryPending_=true; return; }
                    state.armed=false;
                    do {
                        if (!resume(tid,true) || !waitForStop(tid)) return;
                    } while (state.event==PTRACE_EVENT_STOP && !state.groupStop && !stopRequested_);
                    if (state.event==PTRACE_EVENT_CLONE && !adopt(tid)) return;
                    if (stopRequested_ || !state.alive || !arm(tid)) return;
                }
            }
        }
        if (!resume(tid)) return;
    }
}

RecoveredInstruction recoverStoreInstruction(ProcessHandle& proc, SymbolResolver& resolver,
                                             uintptr_t trapRip, bool is64) {
    RecoveredInstruction out;
    if (trapRip == 0) return out;
    // Anchor the forward decode at the enclosing function so instruction boundaries are
    // unambiguous; fall back to a bounded lookback when the address is unsymbolized.
    uintptr_t anchor = (trapRip > 48) ? trapRip - 48 : 0;
    std::string sym = resolver.resolve(trapRip - 1);
    if (auto plus = sym.rfind("+0x"); plus != std::string::npos) {
        uintptr_t off = std::strtoull(sym.c_str() + plus + 3, nullptr, 16);
        uintptr_t fstart = (trapRip - 1) - off;
        if (fstart < trapRip && trapRip - fstart <= 4096) anchor = fstart;
    }
    const size_t span = trapRip - anchor;
    std::vector<uint8_t> buf(span + 16);
    auto r = proc.read(anchor, buf.data(), buf.size());
    if (!r || *r < span) return out;
    Disassembler dis(is64 ? Arch::X86_64 : Arch::X86_32);
    auto insns = dis.disassemble(anchor, {buf.data(), *r}, span + 4);
    for (auto& in : insns) {
        if (in.address >= trapRip) break;
        if (in.address + in.size == trapRip) {
            out.address = in.address;
            out.text = in.operands.empty() ? in.mnemonic : in.mnemonic + " " + in.operands;
            out.ok = true;
            return out;
        }
    }
    return out;
}

bool CodeFinder::recordHit(pid_t tid, bool afterInstruction) {
    auto ctxResult = dbg_->getContext(tid);
    if (!ctxResult) { setError(ctxResult.error()); return false; }
    auto& ctx = *ctxResult;
    uintptr_t rip = ctx.instructionPointer();
    auto architecture=disassemblerArchFor(*proc_,rip);
    if (!architecture) { setError(std::make_error_code(std::errc::not_supported)); return false; }
    if (!disasm_) disasm_.emplace(*architecture);
    else disasm_->setArch(*architecture);
    uintptr_t instrAddr = rip;
    if (afterInstruction) {
        // Hardware watchpoint: the trap fires once the store has retired, so rip is
        // at the NEXT instruction — back up to the one that actually touched the
        // address (a software page fault, by contrast, stops on the store itself).
        uintptr_t prev = disasm_->previousInstruction(rip, [&](uintptr_t a, uint8_t* b, size_t n) {
            auto r = proc_->read(a, b, n);
            return r && *r >= n;
        });
        if (prev != 0 && prev < rip) instrAddr = prev;
        auto exact=recoverStoreInstruction(*proc_,symbols_,rip,ctx.architecture==CpuArchitecture::X86_64);
        if (exact.ok) instrAddr=exact.address;
    }
    uint8_t instrBuf[16];
    auto readResult = proc_->read(instrAddr, instrBuf, sizeof(instrBuf));
    std::string instrText;
    std::vector<uint8_t> instrBytes;
    if (!readResult || !*readResult) {
        setError(readResult ? std::make_error_code(std::errc::bad_address) : readResult.error()); return false;
    }
    auto insns=disasm_->disassemble(instrAddr,{instrBuf,std::min(*readResult,sizeof(instrBuf))},1);
    if (insns.empty()) { setError(std::make_error_code(std::errc::illegal_byte_sequence)); return false; }
    instrText=insns[0].mnemonic+" "+insns[0].operands;
    instrBytes=insns[0].bytes;
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
    return true;
}

long CodeFinder::setStoppedProtection(pid_t tid,uintptr_t scratch,uintptr_t address,size_t length,int protection,int& signal,std::optional<siginfo_t>* signalInfo) {
    return runStoppedSyscall(tid,os::MemorySyscall::Protect,{address,length,static_cast<uint64_t>(protection),0,0,0},scratch,signal,signalInfo);
}

long CodeFinder::runStoppedSyscall(pid_t tid,os::MemorySyscall operation,std::array<uint64_t,6> arguments,uintptr_t scratch,int& signal,std::optional<siginfo_t>* signalInfo) {
    auto result=scratch ? os::executeStoppedMemorySyscall(tid,host_,operation,arguments,scratch) :
        os::executeQuiescedMemorySyscall(tid,host_,operation,arguments);
    if (result) return static_cast<long>(*result);
    auto failure=result.error();
    setError(failure.code); stopRequested_=true;
    if (failure.pendingSignal) {
        signal=failure.pendingSignal;
        siginfo_t info{};
        if (signalInfo && ptrace(PTRACE_GETSIGINFO,tid,nullptr,&info)==0) *signalInfo=info;
    }
    if (failure.recovery) {
        recoveryPending_=true;
        for (;;) {
            auto restored=failure.recovery->retry();
            if (restored || restored.error()==std::errc::no_such_process || restored.error()==std::errc::operation_canceled) break;
            usleep(20000);
        }
        recoveryPending_=false;
    }
    return -1;
}


} // namespace ce
