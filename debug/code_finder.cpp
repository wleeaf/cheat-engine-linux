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
#include <optional>
#include <string_view>
#include <functional>
#include <stdexcept>
#include <array>

#ifndef __WALL
#define __WALL 0x40000000
#endif

namespace ce {

Error softwareWatchOnStackError() {
    struct Category : std::error_category {
        const char* name() const noexcept override { return "code finder"; }
        std::string message(int) const override {
            return "the page holds a thread stack, where a software watch would crash the target; use a hardware watchpoint";
        }
    };
    static const Category category;
    return {1, category};
}

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
    uintptr_t scratch=0,pageStart=0,pageEnd=0,mappingStart=0,mappingEnd=0;
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
    // ARM64 reports the accessed address, which for a wider access covering
    // the watched bytes (str x1,[x0] over an int at x0+4, stp, a q-register
    // pair, dc zva) lies below them. Accept it within the widest access when
    // no other watchpoint of the thread could explain the trap.
    auto arm64WatchHit=[&](const Thread& state,uintptr_t address) {
        const uintptr_t end=targetAddress_+watchSize_;
        if (address>=targetAddress_ && address<end) return true;
        constexpr uintptr_t widestAccess=2048;   // dc zva's largest block
        const uintptr_t aligned=targetAddress_&~uintptr_t{7};
        if (address>=end || address<(aligned>widestAccess ? aligned-widestAccess : 0)) return false;
        for (unsigned i=0;i<state.original.count;++i)
            if (i!=state.slot && (state.original.entries[i].control&1)) return false;
        return true;
    };
    auto ownsHardwareTrap=[&](pid_t tid,const siginfo_t& info) -> Result<bool> {
        auto& state=threads.at(tid);
        if (software_ || !state.armed || info.si_signo!=SIGTRAP || info.si_code!=TRAP_HWBKPT) return false;
        if (host_.architecture==CpuArchitecture::Arm64)
            return arm64WatchHit(state,reinterpret_cast<uintptr_t>(info.si_addr));
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
        // A child that already exited is adopted as gone, not as a failure.
        if (!threads.at(tid).stopped && !waitForStop(tid)) return threads.at(tid).alive ? pid_t{0} : tid;
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
            // Detaching while the guard is still on would let the target's next
            // touch of the page kill it, so the threads stay held (recovery
            // pending) until it is restored. Only giving back the scratch page
            // is given up on: a leaked page is harmless.
            for (int releaseAttempts=0;;) {
                // A target killed meanwhile leaves threads we consider stopped:
                // reap them, or the restore below retries a dead thread forever.
                for (auto& [tid,state] : threads) {
                    if (!state.alive) continue;
                    int status=0;
                    pid_t reaped=waitpid(tid,&status,__WALL|__WNOTHREAD|WNOHANG);
                    if (reaped==tid) consume(tid,status);
                    else if (reaped<0 && (errno==ECHILD || errno==ESRCH)) state.alive=false;
                }
                if (std::none_of(threads.begin(),threads.end(),[](const auto& entry) { return entry.second.alive; })) {
                    // Nothing to restore through; a live target still gets its
                    // scratch page back (a failed seize leaves it allocated).
                    guardChanged=false; guardActive=false;
                    if (!releaseScratch()) scratch=0;
                    break;
                }
                if (!guardChanged && releaseAttempts++==500) {
                    setError(std::make_error_code(std::errc::timed_out)); scratch=0; break;
                }
                if (!stopAll()) { recoveryPending_=true; usleep(20000); continue; }
                if (imageRetired) { guardChanged=false; guardActive=false; scratch=0; break; }
                for (auto& [tid,state] : threads) if (state.alive && guardFault(tid)) {
                    state.signal=0; state.signalInfo.reset(); state.guardStop=false;
                }
                if (guardChanged) {
                    // Any stopped thread can run the mprotect; one parked where
                    // the syscall cannot be injected should not block the rest.
                    bool restored=false;
                    for (auto& [tid,state] : threads) {
                        if (!state.alive || !state.stopped) continue;
                        if (setStoppedProtection(tid,scratch,pageStart,pageLength,originalProtection,state.signal,&state.signalInfo)==0) {
                            restored=true; break;
                        }
                    }
                    if (!restored) { recoveryPending_=true; usleep(20000); continue; }
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
            if (region.path.starts_with("[stack")) { setError(softwareWatchOnStackError()); return; }
            mappingStart=region.base; mappingEnd=region.base+region.size;
            found=true; break;
        }
        if (!found) { setError(std::make_error_code(std::errc::bad_address)); return; }
        if (writesOnly_ && !(originalProtection&2)) { setError(std::make_error_code(std::errc::permission_denied)); return; }
        guardProtection=writesOnly_ ? originalProtection&~2 : 0;
        auto allocation=proc_->allocate(pageSize,MemProt::All,targetAddress_);
        if (!allocation) { setError(allocation.error()); return; }
        scratch=*allocation;
    }
    std::vector<pid_t> single;
    if (singleThread_ && !software_) {
        if (proc_->targetDescription().runtime==TargetRuntime::Wine) single.push_back(proc_->pid());
        else {
            auto task=os::processMemoryTask(proc_->pid());
            if (!task) { setError(task.error()); return; }
            single.push_back(*task);
        }
    }
    unsigned options=PTRACE_O_TRACEEXEC|(singleThread_ && !software_ ? 0 : PTRACE_O_TRACECLONE);
    // A thread not yet seized can clone while we work through the list, and
    // its child would run untraced (a missed write, or a fatal guard fault).
    // List again until a pass finds nothing new, as
    // DebugSession::seizeAllThreads does.
    std::set<pid_t> attempted;
    for (int pass=0;pass<16;++pass) {
        std::vector<pid_t> tids;
        if (!single.empty()) { if (!pass) tids=single; }
        else for (const auto& thread : proc_->threads()) if (attempted.insert(thread.tid).second) tids.push_back(thread.tid);
        if (!pass && tids.empty() && attempted.insert(proc_->pid()).second) tids.push_back(proc_->pid());
        if (tids.empty()) break;
        for (pid_t tid : tids) {
            if (stopRequested_) return;
            if (threads.contains(tid)) continue;
            threads.try_emplace(tid);
            if (ce::seizeIfOwned(tid,static_cast<unsigned long>(options))<0) {
                int failure=errno; threads.erase(tid);
                if (failure==ESRCH) continue;
                setError({failure,std::system_category()}); return;
            }
            if (ptrace(PTRACE_INTERRUPT,tid,nullptr,nullptr)<0) { setError({errno,std::system_category()}); return; }
            if (!waitForStop(tid)) return;
            if (threads.at(tid).event==PTRACE_EVENT_CLONE && !adopt(tid)) return;
            if (stopRequested_) return;
        }
    }
    if (threads.empty()) { setError(std::make_error_code(std::errc::no_such_process)); return; }
    for (auto& [tid,state] : threads) if (state.alive && !arm(tid)) return;
    if (software_) {
        // A signal frame is written below the stack pointer; with that page
        // guarded the kernel cannot write it and kills the target.
        for (auto& [tid,state] : threads) {
            if (!state.alive) continue;
            auto context=os::readNativeContext(tid);
            if (!context) continue;
            const uintptr_t sp=context->stackPointer();
            if (sp>=mappingStart && sp<mappingEnd) { setError(softwareWatchOnStackError()); return; }
        }
    }
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
            if (!child || (threads.at(child).alive && (!arm(child) || !resume(child))) || !resume(tid)) return;
            continue;
        }
        if (software_ && guardFault(tid)) {
            if (!stopAll() || imageRetired) return;
            siginfo_t info{};
            if (!guardFault(tid,&info)) return;
            uintptr_t fault=reinterpret_cast<uintptr_t>(info.si_addr);
            if (accessTouchesTarget(tid,fault) && !recordHit(tid,false)) return;
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
                arm64WatchHit(state,reinterpret_cast<uintptr_t>(info.si_addr)) :
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

namespace {

// The x86 instruction that ends exactly at `end`, decoded forward from the
// enclosing function so instruction boundaries are unambiguous; a bounded
// lookback when the address is unsymbolized.
std::optional<Instruction> instructionEndingAt(ProcessHandle& proc, SymbolResolver& resolver,
                                               uintptr_t end, bool is64) {
    if (end == 0) return std::nullopt;
    uintptr_t anchor = (end > 48) ? end - 48 : 0;
    std::string sym = resolver.resolve(end - 1);
    if (auto plus = sym.rfind("+0x"); plus != std::string::npos) {
        uintptr_t off = std::strtoull(sym.c_str() + plus + 3, nullptr, 16);
        uintptr_t fstart = (end - 1) - off;
        if (fstart < end && end - fstart <= 4096) anchor = fstart;
    }
    const size_t span = end - anchor;
    std::vector<uint8_t> buf(span + 16);
    auto r = proc.read(anchor, buf.data(), buf.size());
    if (!r || *r < span) return std::nullopt;
    Disassembler dis(is64 ? Arch::X86_64 : Arch::X86_32);
    auto insns = dis.disassemble(anchor, {buf.data(), *r}, span + 4);
    for (auto& in : insns) {
        if (in.address >= end) break;
        if (in.address + in.size == end) return std::move(in);
    }
    return std::nullopt;
}

// The operation without prefixes: "rep stosd" -> "stosd", "bnd jmp" -> "jmp".
std::string_view operation(const Instruction& in) {
    std::string_view m = in.mnemonic;
    auto space = m.rfind(' ');
    return space == std::string_view::npos ? m : m.substr(space + 1);
}

// A direct branch's target ("call 0x401000"), 0 for an indirect one.
uintptr_t directTarget(const Instruction& in) {
    if (!in.operands.starts_with("0x")) return 0;
    char* stop = nullptr;
    const unsigned long long target = std::strtoull(in.operands.c_str() + 2, &stop, 16);
    return stop && !*stop ? static_cast<uintptr_t>(target) : 0;
}

// Could `in`, which ends at `rip`, have accessed memory and then fallen
// through to `rip`? A branch stops at its target instead, and a register-only
// instruction, lea or a nop touches no memory.
bool accessFallsThrough(const Instruction& in, uintptr_t rip) {
    const auto op = operation(in);
    if (in.isCall) return directTarget(in) == rip;   // call $+5 pushes and falls through
    if (op.starts_with('j') || op.starts_with("ret") || op.starts_with("iret") || op.starts_with("loop") ||
        op == "int3" || op == "ud2" || op == "hlt")
        return false;
    if (in.memory.present) return op != "lea" && !op.starts_with("nop");
    // Stack and string instructions access memory without a decoded operand.
    return op.starts_with("push") || op.starts_with("pop") || op == "enter" || op == "leave" ||
           op.starts_with("xlat") || op.starts_with("maskmov") || op.starts_with("movs") || op.starts_with("stos") ||
           op.starts_with("lods") || op.starts_with("scas") || op.starts_with("cmps");
}

RecoveredInstruction recovered(const Instruction& in) {
    RecoveredInstruction out;
    out.address = in.address;
    out.text = in.operands.empty() ? in.mnemonic : in.mnemonic + " " + in.operands;
    out.ok = true;
    return out;
}

} // namespace

RecoveredInstruction recoverStoreInstruction(ProcessHandle& proc, SymbolResolver& resolver,
                                             uintptr_t trapRip, bool is64) {
    auto in = instructionEndingAt(proc, resolver, trapRip, is64);
    if (!in || !accessFallsThrough(*in, trapRip)) return {};
    return recovered(*in);
}

RecoveredInstruction recoverHardwareAccess(ProcessHandle& proc, SymbolResolver& resolver, const CpuContext& ctx) {
    const bool is64 = ctx.architecture == CpuArchitecture::X86_64;
    const uintptr_t rip = ctx.instructionPointer();
    auto before = instructionEndingAt(proc, resolver, rip, is64);
    if (!before) {
        // Unsymbolized dense code: the longest decode that ends at rip.
        Disassembler dis(is64 ? Arch::X86_64 : Arch::X86_32);
        const uintptr_t prev = dis.previousInstruction(rip, [&](uintptr_t a, uint8_t* b, size_t n) {
            auto r = proc.read(a, b, n);
            return r && *r >= n;
        });
        uint8_t bytes[16];
        auto r = prev && prev < rip ? proc.read(prev, bytes, sizeof(bytes)) : Result<size_t>(0);
        auto insns = r && *r ? dis.disassemble(prev, {bytes, std::min(*r, sizeof(bytes))}, 1) : std::vector<Instruction>{};
        // Undecodable: keep the caller's own choice.
        if (insns.empty() || insns[0].address + insns[0].size != rip) return {};
        before = std::move(insns[0]);
    }
    if (accessFallsThrough(*before, rip)) return recovered(*before);

    // The trap followed a branch. After a call, its return address is on top
    // of the stack: the call itself pushed onto the watched slot or read the
    // watched pointer. Accept a direct call only to rip, and an indirect one
    // only when rip does not follow a call (where a ret would have landed).
    RecoveredInstruction branched;
    branched.branched = true;
    uint64_t returnAddress = 0;
    const size_t width = is64 ? 8 : 4;
    auto read = proc.read(ctx.stackPointer(), &returnAddress, width);
    if (!read || *read != width || !returnAddress) return branched;
    auto call = instructionEndingAt(proc, resolver, returnAddress, is64);
    if (!call || !call->isCall) return branched;
    const uintptr_t target = directTarget(*call);
    if (target ? target != rip : before->isCall) return branched;
    return recovered(*call);
}

// A page fault reports where the access starts: a 16-byte copy at obj+8
// covering a dword watched at obj+12 faults at obj+8. Decode the faulting
// instruction for its operand size before discarding such a fault.
bool CodeFinder::accessTouchesTarget(pid_t tid, uintptr_t fault) {
    const uintptr_t end = targetAddress_ + watchSize_;
    if (fault >= targetAddress_ && fault < end) return true;
    if (fault > targetAddress_ || targetAddress_ - fault >= 64) return false;   // no access is wider
    auto ctx = dbg_->getContext(tid);
    if (!ctx) return false;
    auto architecture = disassemblerArchFor(*proc_, ctx->instructionPointer());
    if (!architecture) return false;
    if (!disasm_) disasm_.emplace(*architecture);
    else disasm_->setArch(*architecture);
    uint8_t bytes[16];
    auto read = proc_->read(ctx->instructionPointer(), bytes, sizeof(bytes));
    if (!read || !*read) return false;
    auto insns = disasm_->disassemble(ctx->instructionPointer(), {bytes, std::min(*read, sizeof(bytes))}, 1);
    if (insns.empty() || !insns[0].memory.present || !insns[0].memory.size) return false;
    return fault + insns[0].memory.size > targetAddress_;
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
    bool afterBranch = false;   // x86: trapped at a branch target, accessor unknown
    // A REP string instruction traps between iterations with the instruction
    // pointer still on it: it is the writer, not the instruction before it.
    bool repAtRip = false;
    if (afterInstruction && (ctx.architecture == CpuArchitecture::X86_64 || ctx.architecture == CpuArchitecture::X86_32)) {
        uint8_t bytes[16];
        auto read = proc_->read(rip, bytes, sizeof(bytes));
        auto insns = read && *read ? disasm_->disassemble(rip, {bytes, std::min(*read, sizeof(bytes))}, 1)
                                   : std::vector<Instruction>{};
        if (!insns.empty() && insns[0].mnemonic.starts_with("rep")) {
            const auto& m = insns[0].mnemonic;
            const bool stringOp = m.find("movs") != std::string::npos || m.find("stos") != std::string::npos ||
                                  m.find("lods") != std::string::npos || m.find("scas") != std::string::npos ||
                                  m.find("cmps") != std::string::npos;
            // Mid-copy, RDI/RSI sit right next to the watched bytes.
            auto near = [&](uint64_t reg) { return (reg > targetAddress_ ? reg - targetAddress_ : targetAddress_ - reg) <= 64; };
            repAtRip = stringOp && (near(ctx.rdi) || near(ctx.rsi));
        }
    }
    if (afterInstruction && !repAtRip) {
        // Hardware watchpoint: the trap fires once the store has retired, so rip is
        // at the NEXT instruction — back up to the one that actually touched the
        // address (a software page fault, by contrast, stops on the store itself).
        uintptr_t prev = disasm_->previousInstruction(rip, [&](uintptr_t a, uint8_t* b, size_t n) {
            auto r = proc_->read(a, b, n);
            return r && *r >= n;
        });
        if (prev != 0 && prev < rip) instrAddr = prev;
        // The forward recovery decodes x86 only.
        if (ctx.architecture == CpuArchitecture::X86_64 || ctx.architecture == CpuArchitecture::X86_32) {
            auto exact=recoverHardwareAccess(*proc_,symbols_,ctx);
            if (exact.ok) instrAddr=exact.address;
            else if (exact.branched) { instrAddr=rip; afterBranch=true; }
        }
    }
    uint8_t instrBuf[16];
    auto readResult = proc_->read(instrAddr, instrBuf, sizeof(instrBuf));
    std::string instrText;
    std::vector<uint8_t> instrBytes;
    // An instruction that cannot be read or decoded (unmapped since, or bytes
    // the disassembler does not know) is still a hit: record it as "??"
    // rather than ending the whole monitoring session.
    if (afterBranch) {
        // Keyed at the branch target: decoding there would name an instruction
        // that has not run yet.
        instrText = "?? (accessed by the branch or return to here)";
    } else if (readResult && *readResult) {
        auto insns=disasm_->disassemble(instrAddr,{instrBuf,std::min(*readResult,sizeof(instrBuf))},1);
        if (!insns.empty()) {
            instrText=insns[0].mnemonic+" "+insns[0].operands;
            instrBytes=insns[0].bytes;
        }
    }
    if (instrText.empty()) instrText="??";
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
