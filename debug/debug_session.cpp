#include "core/target_capabilities.hpp"
#include "debug/debug_session.hpp"
#include "arch/disassembler.hpp"
#include "arch/target_arch.hpp"
#include "core/log.hpp"
#include "platform/linux/target_debug.hpp"

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>
#include <cstring>
#include <chrono>
#include <cerrno>
#include <unistd.h>
#include <vector>
#include <algorithm>
#include <optional>

namespace ce {

static bool isEventStop(int status, int event) {
    return WIFSTOPPED(status) && (status >> 8) == (SIGTRAP | (event << 8));
}

static std::optional<int> unreportedStopStatus(pid_t tid) {
    // A launcher thread can consume this owner's wait report without releasing
    // the ptrace stop. GETSIGINFO proves a real stop; ESRCH is also normal for
    // a running task and must never be interpreted as task death here.
    siginfo_t info{};
    if (ptrace(PTRACE_GETSIGINFO,tid,nullptr,&info)<0 || info.si_signo<=0 || info.si_signo>=NSIG)
        return std::nullopt;
    // The first wait may have preceded this stop by a few instructions. Drain
    // its now-available report before reconstructing one, so an owned stop is
    // never published twice. Prefer the kernel status if death raced the probe.
    int reported=0; pid_t waited=-1;
    do { waited=waitpid(tid,&reported,__WALL|__WNOTHREAD|WNOHANG); } while (waited<0 && errno==EINTR);
    if (waited==tid) return reported;
    if (waited<0) return std::nullopt;
    int status=(info.si_signo<<8)|0x7f;
    if (info.si_signo==SIGTRAP && info.si_code>0xff && (info.si_code&0xff)==SIGTRAP) {
        const unsigned event=static_cast<unsigned>(info.si_code)>>8;
        if ((event<PTRACE_EVENT_FORK || event>PTRACE_EVENT_SECCOMP) && event!=PTRACE_EVENT_STOP)
            return std::nullopt;
        status|=static_cast<int>(event<<16);
    }
    return status;
}

DebugSession::~DebugSession() {
    if (attached_) detach();
    // detach() from within a callback cannot join the tracer thread; join the
    // still-joinable thread here so its cleanup completes before we destruct.
    if (eventThread_.joinable())
        eventThread_.join();
}

bool DebugSession::attach(pid_t pid, ProcessHandle* proc) {
    if (proc && unsupportedTargetOperation(*proc, TargetFeature::Debugger)) return false;
    if (attached_ || !proc || proc->targetDescription().transport != TargetTransport::Local) return false;
    // Target exit and detach from a callback leave a finished, joinable tracer.
    // Complete its cleanup before replacing the thread or its process handle.
    if (eventThread_.joinable()) {
        if (eventThread_.get_id() == std::this_thread::get_id()) return false;
        eventThread_.join();
    }
    pid_ = pid;
    proc_ = proc;

    // The tracer thread performs the SEIZE itself so it (and only it) owns every
    // subsequent ptrace/waitpid. attach() blocks until the thread reports whether
    // the attach succeeded.
    attachPromise_ = std::promise<bool>{};
    auto fut = attachPromise_.get_future();
    eventThread_ = std::thread(&DebugSession::tracerThread, this);
    bool ok = fut.get();
    if (!ok && eventThread_.joinable())
        eventThread_.join();
    return ok;
}

bool DebugSession::captureRegs(pid_t tid) {
    auto registers=os::readNativeContext(tid);
    if (!registers) { setError(registers.error()); return false; }
    auto vectors=os::readNativeVectors(tid);
    std::lock_guard lock(contextMutex_);
    stopContext_=*registers;
    vectorRegisters_ = vectors ? *vectors : os::NativeVectorContext{};
    xmmRegs_ = {};
    if (vectors) std::copy_n(vectors->registers.begin(), std::min(size_t(vectors->count),xmmRegs_.size()),xmmRegs_.begin());
    return true;
}

std::array<std::array<uint8_t, 16>, 16> DebugSession::getXmmRegisters() const {
    std::lock_guard lock(contextMutex_);
    return xmmRegs_;
}

void DebugSession::detach() {
    if (!attached_.exchange(false)) return;
    // Wake the tracer loop so it observes attached_==false, runs cleanup at the
    // bottom of the loop, and exits.
    cmdCv_.notify_all();

    if (eventThread_.joinable()) {
        // If detach() is called from inside eventCb_ (which runs on the tracer
        // thread) we cannot join ourselves; the loop will finish cleanup on its
        // own and ~DebugSession joins the still-joinable thread.
        if (eventThread_.get_id() != std::this_thread::get_id())
            eventThread_.join();
    }
}

// ── All-stop multi-thread helpers (tracer thread only) ──

bool DebugSession::seizeAllThreads() {
    traced_.clear(); stoppedTids_.clear(); pendingSignals_.clear(); pendingRewinds_.clear(); pendingHardwareSteps_.clear();
    pendingExitStops_.clear(); exitedDuringStop_.clear();
    std::vector<pid_t> tids;
    for (auto& t : proc_->threads()) tids.push_back(t.tid);
    if (tids.empty()) tids.push_back(pid_);
    for (pid_t tid : tids) {
        pendingSignals_.emplace(tid,0);
        pendingRewinds_.emplace(tid,0);
        pendingHardwareSteps_.emplace(tid,0);
        traced_.insert(tid);
        if (ptrace(PTRACE_SEIZE,tid,nullptr,reinterpret_cast<void*>(PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT))<0) {
            traced_.erase(tid);
            pendingSignals_.erase(tid); pendingRewinds_.erase(tid); pendingHardwareSteps_.erase(tid); continue;
        }
        if (ptrace(PTRACE_INTERRUPT,tid,nullptr,nullptr)<0) continue;
        int status=0;
        if (waitForStop(tid,status,false)) {
            stoppedTids_.insert(tid);
            if (isEventStop(status,PTRACE_EVENT_CLONE) && !adoptClonedThread(tid)) {
                tracerCleanup(); return false;
            }
            if (isEventStop(status,PTRACE_EVENT_EXEC)) handleExec(tid);
        }
    }
    // The group leader can already be a zombie while live members still own
    // the process. Require an actual stopped group, not a stopped leader.
    if (stoppedTids_.empty()) {
        tracerCleanup(); return false;
    }
    stopOtherThreads(0);
    if (traced_.empty() || traced_.size()!=stoppedTids_.size()) {
        tracerCleanup(); return false;
    }
    return true;
}

pid_t DebugSession::stoppedMemoryThread() const {
    return stoppedTids_.empty() ? 0 : *stoppedTids_.begin();
}

bool DebugSession::isSoftwareStop(pid_t tid,int status) const {
    if (!WIFSTOPPED(status) || WSTOPSIG(status)!=SIGTRAP || (status>>16)!=0) return false;
    siginfo_t info{};
    return ptrace(PTRACE_GETSIGINFO,tid,nullptr,&info)==0 &&
        (info.si_code==TRAP_BRKPT || (nativeTargetMachine().architecture==CpuArchitecture::X86_64 && info.si_code==SI_KERNEL));
}

bool DebugSession::rewindSoftwareStop(pid_t tid,uintptr_t address) {
    pendingRewinds_.at(tid)=address;
    auto context=os::readNativeContext(tid);
    if (!context) { setError(context.error()); recoveryPending_=true; return false; }
    context->setInstructionPointer(address);
    context->debugRegistersValid=false;
    auto write=os::writeNativeContext(tid,*context);
    if (!write) { setError(write.error()); recoveryPending_=true; return false; }
    pendingRewinds_.at(tid)=0;
    return true;
}

void DebugSession::stopOtherThreads(pid_t active) {
    std::vector<pid_t> tids(traced_.begin(),traced_.end());
    for (pid_t tid : tids) {
        if (!traced_.contains(tid) || tid==active || stoppedTids_.contains(tid)) continue;
        if (ptrace(PTRACE_INTERRUPT,tid,nullptr,nullptr)<0) {
            if (errno!=ESRCH) { setError({errno,std::system_category()}); continue; }
            // A dead thread may still have an unconsumed exit notification.
            // Drain it so cleanup does not wait forever for an impossible stop.
        }
        int status=0;
        if (!waitForStop(tid,status,false)) continue;
        stoppedTids_.insert(tid);
        if (isEventStop(status,PTRACE_EVENT_EXEC)) { handleExec(tid); break; }
        if (isEventStop(status,PTRACE_EVENT_CLONE)) {
            if (!adoptClonedThread(tid)) { hardwareRecovery_=true; recoveryPending_=true; }
            continue;
        }
        if (isSoftwareStop(tid,status)) {
            auto context=os::readNativeContext(tid);
            if (!context) { setError(context.error()); recoveryPending_=true; continue; }
            uintptr_t address=os::nativeSoftwareBreakpointAddress(*context);
            std::lock_guard lock(bpMutex_);
            auto bp=softBreakpoints_.find(address);
            if (bp!=softBreakpoints_.end() && bp->second.patch.installed) rewindSoftwareStop(tid,address);
        } else if ((status>>16)==0) {
            siginfo_t info{};
            if (ptrace(PTRACE_GETSIGINFO,tid,nullptr,&info)==0) {
                if (info.si_signo==SIGTRAP && info.si_code==TRAP_HWBKPT &&
                    nativeTargetMachine().architecture==CpuArchitecture::Arm64 && !hwBreakpoints_.empty()) {
                    auto context=os::readNativeContext(tid);
                    if (context) pendingHardwareSteps_.at(tid)=context->instructionPointer();
                    else { setError(context.error()); recoveryPending_=true; }
                } else if (!(info.si_signo==SIGTRAP && (info.si_code==TRAP_TRACE || info.si_code==TRAP_HWBKPT)))
                    pendingSignals_.at(tid)=WSTOPSIG(status);
            }
        }
    }
    publishStoppedThreads();
}

// Snapshot the currently-stopped tids under contextMutex_ so stoppedThreads()
// (called from any thread) can read them without racing the tracer thread.
void DebugSession::publishStoppedThreads() {
    std::lock_guard lk(contextMutex_);
    stoppedSnapshot_.assign(stoppedTids_.begin(), stoppedTids_.end());
}

std::vector<pid_t> DebugSession::stoppedThreads() const {
    std::lock_guard lk(contextMutex_);
    return stoppedSnapshot_;
}

bool DebugSession::selectThread(pid_t tid) {
    if (!attached_.load() || !stopped_.load()) return false;
    Command cmd;
    cmd.type = CmdType::SelectThread;
    cmd.id = static_cast<int>(tid);
    return postCommand(std::move(cmd)) == 1;
}

// Tracer thread only (via performCommand): switch the active thread and refresh
// the cached context so register read/write/step target it.
bool DebugSession::doSelectThread(pid_t tid) {
    if (stoppedTids_.count(tid) == 0) return false;
    if (!captureRegs(tid)) return false;
    activeTid_ = tid;
    return true;
}

void DebugSession::setError(Error error) {
    std::lock_guard lock(contextMutex_);
    lastError_=error;
}
Error DebugSession::lastError() const {
    std::lock_guard lock(contextMutex_);
    return lastError_;
}
os::NativeVectorContext DebugSession::getVectorRegisters() const {
    std::lock_guard lock(contextMutex_);
    return vectorRegisters_;
}

bool DebugSession::waitForStop(pid_t tid,int& status,bool cancellable) {
    bool interrupted=false;
    for (;;) {
        if (!traced_.contains(tid)) return false;
        // Exec can make a sibling exit, or rename the requested nonleader to
        // the group PID. Drain this owner's events instead of blocking on one
        // old TID while an EXIT event holds up the operation in the kernel.
        pid_t waited=waitpid(-1,&status,__WALL|__WNOTHREAD|WNOHANG);
        if (waited==0) {
            if (auto actual=unreportedStopStatus(tid)) { status=*actual; waited=tid; }
            else if (recoverRenamedExec()) return false;
        }
        if (waited>0 && waited!=tid) {
            if (WIFEXITED(status) || WIFSIGNALED(status)) retireThread(waited,status);
            else if (isEventStop(status,PTRACE_EVENT_EXIT)) {
                stoppedTids_.insert(waited);
                if (!finishExitStop(waited)) return false;
            } else if (isEventStop(status,PTRACE_EVENT_EXEC)) { handleExec(waited); return false; }
            else if (isEventStop(status,PTRACE_EVENT_STOP)) {
                if (!traced_.contains(waited)) handleStop(waited,status);
                else stoppedTids_.insert(waited);
            } else { handleStop(waited,status,true); return false; }
            if (!traced_.contains(tid)) return false;
            continue;
        }
        if (waited==tid) {
            if (WIFSTOPPED(status)) {
                stoppedTids_.insert(tid);
                if (isEventStop(status,PTRACE_EVENT_EXIT)) { finishExitStop(tid); return false; }
                return true;
            }
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                retireThread(tid,status);
                return false;
            }
        } else if (waited<0 && errno!=EINTR) {
            if (errno==ECHILD || errno==ESRCH) {
                retireThread(tid,0);
            }
            setError({errno,std::system_category()}); return false;
        }
        if (cancellable && !attached_.load() && !interrupted) {
            if (ptrace(PTRACE_INTERRUPT,tid,nullptr,nullptr)<0 && errno!=ESRCH) {
                setError({errno,std::system_category()}); return false;
            }
            interrupted=true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

bool DebugSession::singleStepThread(pid_t tid) {
    for (;;) {
        int signal=pendingSignals_.at(tid);
        if (ptrace(PTRACE_SINGLESTEP,tid,nullptr,reinterpret_cast<void*>(intptr_t(signal)))<0) {
            setError({errno,std::system_category()}); return false;
        }
        pendingSignals_.at(tid)=0;
        stoppedTids_.erase(tid);
        int status=0;
        if (!waitForStop(tid,status) || !attached_) return false;
        if (isEventStop(status,PTRACE_EVENT_EXEC)) { handleExec(tid); return false; }
        // An all-stop interrupt can race an already-pending breakpoint trap.
        // Its synthetic stop then precedes our requested single-step trap.
        if (isEventStop(status,PTRACE_EVENT_STOP)) continue;
        siginfo_t info{};
        bool stepTrap=WSTOPSIG(status)==SIGTRAP && (status>>16)==0 &&
            ptrace(PTRACE_GETSIGINFO,tid,nullptr,&info)==0 &&
            (info.si_code==TRAP_TRACE || os::isNativeSyscallStepTrap(tid,info));
        log::trace(log::Cat::Debugger,"step stop: tid={}, status={:#x}, code={}, sender={}",tid,status,info.si_code,info.si_pid);
        if (!stepTrap) { handleStop(tid,status,true); return false; }
        return true;
    }
}

bool DebugSession::liftSoftBreakpoint(uintptr_t address) {
    std::lock_guard lock(bpMutex_);
    auto bp=softBreakpoints_.find(address);
    if (bp==softBreakpoints_.end() || !bp->second.active) return true;
    auto restore=os::removeNativeSoftwareBreakpoint(stoppedMemoryThread(),bp->second.patch);
    if (!restore) { setError(restore.error()); recoveryPending_=true; return false; }
    return true;
}

bool DebugSession::rearmSoftBreakpoint(uintptr_t address) {
    std::lock_guard lock(bpMutex_);
    auto bp=softBreakpoints_.find(address);
    if (bp==softBreakpoints_.end() || !bp->second.active || bp->second.patch.installed) return true;
    auto installed=os::installNativeSoftwareBreakpoint(stoppedMemoryThread(),address,proc_->machineAt(address).instructionMode);
    if (!installed) {
        if (installed.error().recovery) bp->second.patch=*installed.error().recovery;
        setError(installed.error().error); recoveryPending_=true; return false;
    }
    bp->second.patch=*installed;
    return true;
}

bool DebugSession::stepThreadOverBp(pid_t tid) {
    auto context=os::readNativeContext(tid);
    if (!context) { setError(context.error()); return false; }
    uintptr_t address=context->instructionPointer();
    {
        std::lock_guard lock(bpMutex_);
        auto bp=softBreakpoints_.find(address);
        if (bp==softBreakpoints_.end() || !bp->second.active) return false;
    }
    if (!liftSoftBreakpoint(address)) return false;
    uint64_t generation=imageGeneration_;
    bool stepped=singleStepThread(tid);
    if (imageGeneration_==generation && !rearmSoftBreakpoint(address)) return false;
    return stepped;
}

bool DebugSession::resumeAllThreads() {
    log::trace(log::Cat::Debugger,"resume session: {} traced, {} stopped, recovery={}",traced_.size(),stoppedTids_.size(),recoveryPending_.load());
    if (recoveryPending_ || traced_.size()!=stoppedTids_.size()) return false;
    std::vector<pid_t> tids(traced_.begin(),traced_.end());
    for (pid_t tid : tids) {
        if (!traced_.contains(tid)) continue;
        if (pendingHardwareSteps_.at(tid) && !stepThreadOverWatchpoint(tid)) return false;
        auto context=os::readNativeContext(tid);
        if (!context) { setError(context.error()); return false; }
        bool atBreakpoint=false;
        {
            std::lock_guard lock(bpMutex_);
            auto bp=softBreakpoints_.find(context->instructionPointer());
            atBreakpoint=bp!=softBreakpoints_.end() && bp->second.active;
        }
        if (atBreakpoint && !stepThreadOverBp(tid)) return false;
    }
    for (pid_t tid : tids) {
        if (!traced_.contains(tid)) continue;
        int signal=pendingSignals_.at(tid);
        if (ptrace(PTRACE_CONT,tid,nullptr,reinterpret_cast<void*>(intptr_t(signal)))<0) {
            setError({errno,std::system_category()}); stopOtherThreads(0); return false;
        }
        pendingSignals_.at(tid)=0;
        stoppedTids_.erase(tid);
    }
    return true;
}

bool DebugSession::stepThreadOverWatchpoint(pid_t tid) {
    uintptr_t pc=pendingHardwareSteps_.at(tid);
    if (!pc) return false;
    auto context=os::readNativeContext(tid);
    if (!context) { setError(context.error()); return false; }
    if (context->instructionPointer()!=pc || hwBreakpoints_.empty()) {
        pendingHardwareSteps_.at(tid)=0;
        return true;
    }
    // ARM64 watchpoints stop before the memory access. Execute that one
    // instruction with our watchpoints lifted while sibling threads stay frozen.
    for (const auto& bp : hwBreakpoints_) {
        auto removed=os::removeNativeHardwareBreakpoint(tid,bp.reg,false);
        if (!removed) {
            setError(removed.error()); hardwareRecovery_=true; recoveryPending_=true;
            return false;
        }
    }
    uint64_t generation=imageGeneration_;
    auto bp=softBreakpoints_.find(pc);
    bool stepped=bp!=softBreakpoints_.end() && bp->second.active ? stepThreadOverBp(tid) : singleStepThread(tid);
    if (stepped && pendingHardwareSteps_.contains(tid)) pendingHardwareSteps_.at(tid)=0;
    if (imageGeneration_==generation && traced_.contains(tid) && !initializeThreadHardware(tid)) return false;
    return stepped;
}

bool DebugSession::adoptClonedThread(pid_t parent) {
    unsigned long child=0;
    if (ptrace(PTRACE_GETEVENTMSG,parent,nullptr,&child)<0 || !child) {
        setError({errno ? errno : EIO,std::system_category()}); return false;
    }
    pid_t tid=static_cast<pid_t>(child);
    pendingSignals_.emplace(tid,0); pendingRewinds_.emplace(tid,0); pendingHardwareSteps_.emplace(tid,0);
    traced_.insert(tid);
    int status=0;
    // waitpid(-1) may report the child's automatic stop before the parent's
    // clone event. Keep that child frozen until its watchpoint bank is ready.
    if (!stoppedTids_.contains(tid) && !waitForStop(tid,status,false)) return !traced_.contains(tid);
    return initializeThreadHardware(tid);
}

bool DebugSession::recoverBreakpoints() {
    if (!pendingExitStops_.empty()) {
        if (traced_.size()!=stoppedTids_.size()) return false;
        const auto exits=pendingExitStops_;
        for (pid_t tid : exits) if (!finishExitStop(tid)) return false;
    }
    if (traced_.empty()) {
        softBreakpoints_.clear(); savedHardware_.clear(); registerRecovery_.reset();
        hardwareRecovery_=false; recoveryPending_=false; return true;
    }
    if (traced_.size()!=stoppedTids_.size()) return false;
    if (registerRecovery_) {
        if (!traced_.contains(registerRecovery_->first)) registerRecovery_.reset();
    }
    if (registerRecovery_) {
        auto restore=os::writeNativeContext(registerRecovery_->first,registerRecovery_->second);
        if (!restore) { setError(restore.error()); return false; }
        registerRecovery_.reset();
    }
    for (auto& [tid,address] : pendingRewinds_)
        if (address && !rewindSoftwareStop(tid,address)) return false;
    {
        std::lock_guard lock(bpMutex_);
        for (auto it=softBreakpoints_.begin();it!=softBreakpoints_.end();) {
            if (!it->second.active) {
                auto restore=os::removeNativeSoftwareBreakpoint(stoppedMemoryThread(),it->second.patch);
                if (!restore) { setError(restore.error()); return false; }
                it=softBreakpoints_.erase(it);
            } else ++it;
        }
    }
    std::vector<uintptr_t> rearm;
    for (const auto& [address,bp] : softBreakpoints_) if (bp.active && !bp.patch.installed) rearm.push_back(address);
    for (uintptr_t address : rearm) if (!rearmSoftBreakpoint(address)) return false;
    if (hardwareRecovery_ && !restoreHardwareState()) return false;
    hardwareRecovery_=false; recoveryPending_=false;
    return true;
}

bool DebugSession::retryPendingOperations() {
    Command command;
    command.type=CmdType::RetryRecovery;
    return postCommand(std::move(command))==1;
}

void DebugSession::tracerCleanup() {
    stopOtherThreads(0);
    for (auto& [address,bp] : softBreakpoints_) bp.active=false;
    hwBreakpoints_.clear(); hardwareRecovery_=!savedHardware_.empty(); recoveryPending_=true;
    while (!recoverBreakpoints()) {
        stopOtherThreads(0);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    std::vector<pid_t> tids(traced_.begin(),traced_.end());
    for (pid_t tid : tids) {
        int signal=pendingSignals_.at(tid);
        while (ptrace(PTRACE_DETACH,tid,nullptr,reinterpret_cast<void*>(intptr_t(signal)))<0) {
            if (errno==ESRCH || errno==ECHILD) break;
            setError({errno,std::system_category()});
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }
    traced_.clear(); stoppedTids_.clear(); savedHardware_.clear(); pendingSignals_.clear(); pendingRewinds_.clear(); pendingHardwareSteps_.clear();
    pendingExitStops_.clear(); exitedDuringStop_.clear(); activeTid_=0;
    publishStoppedThreads();
    stopped_=false; recoveryPending_=false;
    std::lock_guard lock(cmdMutex_);
    for (auto& command : commands_) if (command.done) command.done->set_value(-1);
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
    if (recoveryPending_ && cmd.type!=CmdType::RetryRecovery && !recoverBreakpoints()) return -1;
    // Breakpoint writes require stopped tracees. Lua and GUI callers can add
    // or remove breakpoints while running; stop every thread and rewind any
    // pending int3 hits before restoring a byte or forgetting its address.
    // Otherwise POKETEXT fails and a later untracked int3 skips the original
    // instruction, potentially corrupting a function's stack frame.
    const bool mutation = cmd.type == CmdType::SetSoftBp || cmd.type == CmdType::RemoveSoftBp ||
                          cmd.type == CmdType::SetHwBp || cmd.type == CmdType::RemoveHwBp;
    const bool resume = mutation && !stopped_.load();
    if (resume) {
        stopOtherThreads(0);
        stopped_ = true;
    }
    long result = 0;
    switch (cmd.type) {
        case CmdType::Continue:     doContinue(); break;
        case CmdType::Step:         doStep(cmd.stepMode, cmd.addr); break;
        case CmdType::SetSoftBp:    result = doSetSoftBp(cmd.addr); break;
        case CmdType::RemoveSoftBp: result = doRemoveSoftBp(cmd.id) ? 1 : 0; break;
        case CmdType::SetRegs:      result = doSetRegs(cmd.regs) ? 1 : 0; break;
        case CmdType::SelectThread: result = doSelectThread(static_cast<pid_t>(cmd.id)) ? 1 : 0; break;
        case CmdType::SetHwBp:      result = doSetHwBp(cmd.addr, cmd.hwType, cmd.hwSize); break;
        case CmdType::RemoveHwBp:   result = doRemoveHwBp(cmd.id) ? 1 : 0; break;
        case CmdType::RetryRecovery: result = recoverBreakpoints() ? 1 : 0; break;
    }
    if (resume && !recoveryPending_) doContinue();
    publishThreadExits();
    return result;
}

bool DebugSession::setStopContext(const CpuContext& ctx) {
    if (!attached_.load() || !stopped_.load()) return false;
    Command cmd;
    cmd.type = CmdType::SetRegs;
    cmd.regs = ctx;
    return postCommand(std::move(cmd)) == 1;
}

// Runs ONLY on the tracer thread (via performCommand). Read the live registers,
// overwrite the managed integer/flags fields from ctx, and write them back — so
// registers we do not model (segment bases, orig_rax, etc.) are left intact.
bool DebugSession::doSetRegs(const CpuContext& ctx) {
    if (!stopped_.load() || activeTid_ == 0) return false;
    auto current=os::readNativeContext(activeTid_);
    if (!current) { setError(current.error()); return false; }
    auto edited=ctx;
    // This command edits integer/flags registers. Preserve segment selectors
    // and the separately managed breakpoint bank, as before.
    edited.cs=current->cs; edited.ss=current->ss;
    edited.ds=current->ds; edited.es=current->es; edited.fs=current->fs; edited.gs=current->gs;
    edited.debugRegistersValid=false;
    auto write=os::writeNativeContext(activeTid_,edited);
    if (!write) {
        setError(write.error());
        if (write.error()==std::make_error_code(std::errc::state_not_recoverable)) {
            current->debugRegistersValid=false;
            registerRecovery_=std::pair{activeTid_.load(),*current}; recoveryPending_=true;
        }
        return false;
    }
    return captureRegs(activeTid_);
}

int DebugSession::setSoftwareBreakpoint(uintptr_t address) {
    if (!attached_.load()) return -1;
    return static_cast<int>(postCommand({CmdType::SetSoftBp, StepMode::Into, address, 0, nullptr}));
}

long DebugSession::doSetSoftBp(uintptr_t address) {
    std::lock_guard lock(bpMutex_);
    auto existing=softBreakpoints_.find(address);
    if (existing!=softBreakpoints_.end()) return existing->second.active ? existing->second.id : -1;
    // Reserve recovery ownership before modifying the target, including an
    // installation which fails after the trap was actually written.
    auto [it,inserted]=softBreakpoints_.emplace(address,SoftBp{nextSoftBpId_++,address,{},false});
    auto installed=os::installNativeSoftwareBreakpoint(stoppedMemoryThread(),address,proc_->machineAt(address).instructionMode);
    if (!installed) {
        setError(installed.error().error);
        if (installed.error().recovery) { it->second.patch=*installed.error().recovery; recoveryPending_=true; }
        else softBreakpoints_.erase(it);
        return -1;
    }
    it->second.patch=*installed; it->second.active=true;
    return it->second.id;
}

bool DebugSession::removeSoftwareBreakpoint(int id) {
    return attached_.load() && postCommand({CmdType::RemoveSoftBp,StepMode::Into,0,id,nullptr})==1;
}

bool DebugSession::doRemoveSoftBp(int id) {
    std::lock_guard lock(bpMutex_);
    for (auto it=softBreakpoints_.begin();it!=softBreakpoints_.end();++it) {
        if (it->second.id!=id) continue;
        it->second.active=false;
        auto restore=os::removeNativeSoftwareBreakpoint(stoppedMemoryThread(),it->second.patch);
        if (!restore) { setError(restore.error()); recoveryPending_=true; return false; }
        softBreakpoints_.erase(it); return true;
    }
    // A pending removal can complete in the automatic recovery loop before
    // the caller retries it. Already-issued, retired IDs remove idempotently.
    return id>0 && id<nextSoftBpId_;
}

int DebugSession::setHardwareBreakpoint(uintptr_t address,int type,int size) {
    if (!attached_) return -1;
    Command command; command.type=CmdType::SetHwBp; command.addr=address; command.hwType=type; command.hwSize=size;
    return static_cast<int>(postCommand(std::move(command)));
}
bool DebugSession::removeHardwareBreakpoint(int id) {
    return attached_.load() && postCommand({CmdType::RemoveHwBp,StepMode::Into,0,id,nullptr})==1;
}

bool DebugSession::initializeThreadHardware(pid_t tid) {
    if (hwBreakpoints_.empty()) return true;
    if (!savedHardware_.contains(tid)) {
        auto bank=os::readNativeHardwareBank(tid,false);
        if (!bank) { setError(bank.error()); return false; }
        savedHardware_.emplace(tid,*bank);
    }
    for (const auto& bp : hwBreakpoints_) {
        auto access=bp.type==1 ? os::HardwareBreakpointAccess::Write : os::HardwareBreakpointAccess::ReadWrite;
        auto result=os::setNativeHardwareBreakpoint(tid,bp.reg,bp.address,access,bp.size);
        if (!result) { setError(result.error()); hardwareRecovery_=true; recoveryPending_=true; return false; }
    }
    return true;
}

bool DebugSession::restoreHardwareState() {
    for (const auto& [tid,saved] : savedHardware_) {
        if (!traced_.contains(tid)) continue;
        auto restore=os::restoreNativeHardwareBank(tid,false,saved);
        if (!restore) { setError(restore.error()); return false; }
        for (const auto& bp : hwBreakpoints_) {
            auto access=bp.type==1 ? os::HardwareBreakpointAccess::Write : os::HardwareBreakpointAccess::ReadWrite;
            auto arm=os::setNativeHardwareBreakpoint(tid,bp.reg,bp.address,access,bp.size);
            if (!arm) { setError(arm.error()); return false; }
        }
    }
    return true;
}

long DebugSession::doSetHwBp(uintptr_t address,int type,int size) {
    if ((type!=1 && type!=3) || (size!=1 && size!=2 && size!=4 && size!=8) || traced_.empty()) {
        setError(std::make_error_code(std::errc::invalid_argument)); return -1;
    }
    unsigned count=16;
    std::array<bool,16> used{};
    for (const auto& bp : hwBreakpoints_) used.at(bp.reg)=true;
    for (pid_t tid : traced_) {
        auto bank=os::readNativeHardwareBank(tid,false);
        if (!bank) { setError(bank.error()); return -1; }
        count=std::min(count,bank->count);
        for (unsigned i=0;i<count;++i) {
            bool enabled=nativeTargetMachine().architecture==CpuArchitecture::Arm64 ?
                (bank->entries[i].control&1)!=0 : (bank->entries[i].control&3)!=0;
            used[i]=used[i] || enabled;
        }
        if (!savedHardware_.contains(tid)) savedHardware_.emplace(tid,*bank);
    }
    unsigned slot=0;
    while (slot<count && used[slot]) ++slot;
    if (slot==count) { setError(std::make_error_code(std::errc::no_space_on_device)); return -1; }
    hwBreakpoints_.reserve(hwBreakpoints_.size()+1);
    for (pid_t tid : traced_) {
        auto access=type==1 ? os::HardwareBreakpointAccess::Write : os::HardwareBreakpointAccess::ReadWrite;
        auto arm=os::setNativeHardwareBreakpoint(tid,slot,address,access,size);
        if (!arm) {
            setError(arm.error()); hardwareRecovery_=true; recoveryPending_=true;
            recoverBreakpoints(); return -1;
        }
    }
    int id=nextHwBpId_++;
    hwBreakpoints_.push_back({id,address,static_cast<int>(slot),type,size});
    return id;
}

bool DebugSession::doRemoveHwBp(int id) {
    auto bp=std::find_if(hwBreakpoints_.begin(),hwBreakpoints_.end(),[&](const auto& item){return item.id==id;});
    if (bp==hwBreakpoints_.end()) return id>0 && id<nextHwBpId_;
    hwBreakpoints_.erase(bp);
    hardwareRecovery_=true; recoveryPending_=true;
    return recoverBreakpoints();
}

bool DebugSession::disarmAllHwBreakpoints() {
    hwBreakpoints_.clear();
    return restoreHardwareState();
}

void DebugSession::continueExecution() {
    if (!attached_.load()) return;
    postCommand({CmdType::Continue, StepMode::Into, 0, 0, nullptr});
}

void DebugSession::doContinue() {
    if (!stopped_.load()) return;
    if (resumeAllThreads()) stopped_ = false;
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

    if (!seizeAllThreads()) {
        attachPromise_.set_value(false);
        return;
    }
    attached_ = true;
    stopped_ = true;              // every thread is stopped after the seize
    activeTid_ = stoppedTids_.contains(pid_) ? pid_ : *stoppedTids_.begin();
    if (!captureRegs(activeTid_)) {
        attached_=false; tracerCleanup(); attachPromise_.set_value(false); return;
    }
    attachPromise_.set_value(true);

    pid_t lastStopProbe=0;
    while (attached_.load()) {
        if (recoveryPending_) { recoverBreakpoints(); publishThreadExits(); }
        // 1) Drain queued commands (safe: the target is all-stopped).
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
            long result=-1;
            try { result=performCommand(cmd); }
            catch (const std::bad_alloc&) { setError(std::make_error_code(std::errc::not_enough_memory)); }
            catch (const std::exception&) { setError(std::make_error_code(std::errc::io_error)); }
            if (cmd.done) cmd.done->set_value(result);
            continue;
        }

        // 2) Poll even while paused: SIGKILL can turn an existing stop into an
        // EXIT stop, and death must remain observable without another command.
        {
            int st = 0;
            pid_t w = waitpid(-1, &st, __WALL | __WNOTHREAD | WNOHANG);
            if (w == 0) {
                if (recoverRenamedExec()) { publishThreadExits(); continue; }
                // Another launcher thread can consume this owner's wait
                // notification. Probe one owned task per idle poll, rotating
                // through the group so cost does not grow with thread count.
                auto candidate=traced_.upper_bound(lastStopProbe);
                if (candidate==traced_.end()) candidate=traced_.begin();
                if (candidate!=traced_.end()) {
                    lastStopProbe=*candidate;
                    if (auto actual=unreportedStopStatus(lastStopProbe);
                        actual && (!stoppedTids_.contains(lastStopProbe) || isEventStop(*actual,PTRACE_EVENT_EXIT) ||
                                   WIFEXITED(*actual) || WIFSIGNALED(*actual))) {
                        handleStop(lastStopProbe,*actual,stopped_.load());
                        publishThreadExits();
                        continue;
                    }
                }
                if (!stopped_.load()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(2));
                    continue;
                }
            } else if (w < 0) {
                if (errno == ECHILD) {   // the whole process is gone
                    while (!traced_.empty()) retireThread(*traced_.begin(),0);
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
                continue;
            } else {
                handleStop(w, st,stopped_.load());
                publishThreadExits();
                continue;
            }
        }

        // 3) All-stopped with nothing queued: wait for a command or detach.
        std::unique_lock lk(cmdMutex_);
        cmdCv_.wait_for(lk, std::chrono::milliseconds(50),
                        [&] { return !commands_.empty() || !attached_.load(); });
    }

    tracerCleanup();
}

bool DebugSession::recoverRenamedExec() {
    // A nonleader exec replaces its TID with the process PID. Once the old
    // leader is retired, probing only recorded TIDs cannot find that stop.
    // Require both the real kernel EXEC siginfo and a recorded former TID;
    // a missing old task alone never proves an exec or authorizes adoption.
    if (pid_<=0 || traced_.contains(pid_)) return false;
    siginfo_t info{}; unsigned long former=0;
    if (ptrace(PTRACE_GETSIGINFO,pid_,nullptr,&info)<0 || info.si_signo!=SIGTRAP ||
        info.si_code!=(SIGTRAP|(PTRACE_EVENT_EXEC<<8)) ||
        ptrace(PTRACE_GETEVENTMSG,pid_,nullptr,&former)<0 ||
        !traced_.contains(static_cast<pid_t>(former))) return false;
    int status=0; pid_t waited=-1;
    do { waited=waitpid(pid_,&status,__WALL|__WNOTHREAD|WNOHANG); } while (waited<0 && errno==EINTR);
    if (waited<0 && errno!=ECHILD) { setError({errno,std::system_category()}); return false; }
    const bool execStop=waited==0 || (waited==pid_ && isEventStop(status,PTRACE_EVENT_EXEC));
    // SIGKILL may replace the proven exec stop before the second wait. Adopt
    // the renamed identity and retire the old image before handling that real
    // terminal status, without publishing an invented usable exec context.
    handleExec(pid_,execStop);
    if (waited<0) retireThread(pid_,0);
    else if (!execStop) handleStop(pid_,status,true);
    return true;
}

void DebugSession::handleExec(pid_t tid,bool notify) {
    ++imageGeneration_;
    // EXEC destroys the old memory image and sibling threads. Its breakpoint
    // recovery records must never be replayed into the replacement program.
    softBreakpoints_.clear(); hwBreakpoints_.clear(); savedHardware_.clear(); registerRecovery_.reset();
    hardwareRecovery_=false; recoveryPending_=false;
    pendingExitStops_.clear(); exitedDuringStop_.clear();
    traced_={tid}; stoppedTids_={tid}; pendingSignals_.clear(); pendingRewinds_.clear(); pendingHardwareSteps_.clear();
    pendingSignals_.emplace(tid,0); pendingRewinds_.emplace(tid,0); pendingHardwareSteps_.emplace(tid,0);
    activeTid_=tid; stopped_=true;
    { std::lock_guard lock(contextMutex_); stopContext_={}; vectorRegisters_={}; xmmRegs_={}; }
    proc_->targetDescription();
    captureRegs(tid); publishStoppedThreads();
    // The image changed even if its context read failed. Notify consumers so
    // they retire old breakpoints and displays; the cleared context stays
    // explicitly unavailable until a successful read on this existing owner.
    if (!notify) return;
    DebugEvent event{DebugEventType::ProcessExecuted,tid,0,0,{}};
    event.generation=imageGeneration_;
    event.context=getStopContext(); event.address=event.context.instructionPointer();
    if (eventCb_) eventCb_(event);
}

void DebugSession::retireThread(pid_t tid,int status) {
    if (!traced_.contains(tid)) return;
    if (stopped_ && traced_.size()>1) exitedDuringStop_.push_back(tid);
    traced_.erase(tid); stoppedTids_.erase(tid); savedHardware_.erase(tid); pendingExitStops_.erase(tid);
    pendingSignals_.erase(tid); pendingRewinds_.erase(tid); pendingHardwareSteps_.erase(tid);
    if (registerRecovery_ && registerRecovery_->first==tid) registerRecovery_.reset();
    if (activeTid_==tid) {
        activeTid_=0;
        { std::lock_guard lock(contextMutex_); stopContext_={}; vectorRegisters_={}; xmmRegs_={}; }
        if (!stoppedTids_.empty()) doSelectThread(*stoppedTids_.begin());
    }
    publishStoppedThreads();
    if (traced_.empty()) {
        softBreakpoints_.clear(); hwBreakpoints_.clear(); registerRecovery_.reset();
        hardwareRecovery_=false; recoveryPending_=false; ++imageGeneration_;
        DebugEvent event{DebugEventType::ProcessExited,tid,0,0,{}};
        event.signal=WIFSIGNALED(status) ? WTERMSIG(status) : 0;
        event.generation=imageGeneration_;
        const bool notify=attached_.exchange(false); stopped_=false; exitedDuringStop_.clear();
        if (notify && eventCb_) eventCb_(event);
    }
}

bool DebugSession::finishExitStop(pid_t tid) {
    pendingExitStops_.insert(tid);
    unsigned long status=0;
    if (ptrace(PTRACE_GETEVENTMSG,tid,nullptr,&status)<0) {
        const int failure=errno;
        if (failure==ESRCH || failure==ECHILD) {
            int terminal=0;
            const pid_t waited=waitpid(tid,&terminal,__WALL|__WNOTHREAD|WNOHANG);
            if ((waited==tid && (WIFEXITED(terminal) || WIFSIGNALED(terminal))) ||
                (waited<0 && errno==ECHILD)) {
                retireThread(tid,terminal); return true;
            }
        }
        setError({failure,std::system_category()}); recoveryPending_=true; return false;
    }
    // The leader's final wait notification can depend on its frozen siblings
    // exiting. Detach at the irreversible EXIT stop instead of waiting for it.
    if (ptrace(PTRACE_DETACH,tid,nullptr,nullptr)<0 && errno!=ESRCH && errno!=ECHILD) {
        setError({errno,std::system_category()}); recoveryPending_=true; return false;
    }
    retireThread(tid,static_cast<int>(status));
    return true;
}

void DebugSession::publishThreadExits() {
    if (recoveryPending_ || exitedDuringStop_.empty()) return;
    auto exits=std::move(exitedDuringStop_); exitedDuringStop_.clear();
    for (pid_t tid : exits) {
        if (!attached_ || !stopped_ || !activeTid_) break;
        DebugEvent event{DebugEventType::ThreadExiting,activeTid_,0,0,getStopContext()};
        event.exitingTid=tid; event.address=event.context.instructionPointer(); event.generation=imageGeneration_;
        if (eventCb_) eventCb_(event);
    }
}

void DebugSession::handleStop(pid_t tid,int status,bool holdStop) {
    log::trace(log::Cat::Debugger,"session stop: tid={}, status={:#x}",tid,status);
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        retireThread(tid,status);
        return;
    }
    if (!WIFSTOPPED(status)) return;
    if (isEventStop(status,PTRACE_EVENT_EXEC)) { handleExec(tid); return; }
    if (!traced_.contains(tid)) {
        pendingSignals_.emplace(tid,0); pendingRewinds_.emplace(tid,0); pendingHardwareSteps_.emplace(tid,0);
        traced_.insert(tid); stoppedTids_.insert(tid);
        return;
    }
    stoppedTids_.insert(tid);
    if (isEventStop(status,PTRACE_EVENT_EXIT)) {
        if (!finishExitStop(tid)) { stopOtherThreads(tid); stopped_=true; }
        return;
    }
    if (isEventStop(status,PTRACE_EVENT_CLONE)) {
        unsigned long child=0;
        if (adoptClonedThread(tid) && ptrace(PTRACE_GETEVENTMSG,tid,nullptr,&child)==0 && child) {
            pid_t newTid=static_cast<pid_t>(child);
            if (!holdStop && stoppedTids_.contains(newTid)) {
                if (ptrace(PTRACE_CONT,newTid,nullptr,nullptr)==0) stoppedTids_.erase(newTid);
                else { setError({errno,std::system_category()}); recoveryPending_=true; }
            }
        } else { hardwareRecovery_=true; recoveryPending_=true; }
        if (recoveryPending_) { stopOtherThreads(tid); stopped_=true; return; }
        if (holdStop) {
            stopOtherThreads(tid); stopped_=true; activeTid_=tid;
            captureRegs(tid); publishStoppedThreads();
            DebugEvent event{DebugEventType::SignalReceived,tid,0,0,getStopContext()};
            event.address=event.context.instructionPointer(); event.generation=imageGeneration_;
            if (eventCb_) eventCb_(event);
            return;
        }
        if (ptrace(PTRACE_CONT,tid,nullptr,nullptr)==0) stoppedTids_.erase(tid);
        return;
    }
    int signal=WSTOPSIG(status);
    siginfo_t info{};
    bool haveInfo=ptrace(PTRACE_GETSIGINFO,tid,nullptr,&info)==0;
    auto context=os::readNativeContext(tid);
    if (!context) { setError(context.error()); stopOtherThreads(tid); stopped_=true; return; }
    uintptr_t address=context->instructionPointer();
    bool breakpointHit=false;
    if (signal==SIGTRAP && (status>>16)==0 && haveInfo && info.si_code==TRAP_HWBKPT && !hwBreakpoints_.empty()) {
        if (context->architecture==CpuArchitecture::Arm64) {
            uintptr_t access=reinterpret_cast<uintptr_t>(info.si_addr);
            uintptr_t closest=UINTPTR_MAX;
            for (const auto& bp : hwBreakpoints_) {
                uintptr_t distance=access<bp.address ? bp.address-access :
                    access-bp.address<static_cast<unsigned>(bp.size) ? 0 : access-bp.address-bp.size+1;
                if (distance<closest) { address=bp.address; closest=distance; }
            }
            breakpointHit=closest!=UINTPTR_MAX;
            if (breakpointHit) pendingHardwareSteps_.at(tid)=context->instructionPointer();
        } else {
            auto bank=os::readNativeHardwareBank(tid,false);
            if (bank) {
                for (const auto& bp : hwBreakpoints_)
                    if (bank->status & (UINT64_C(1)<<bp.reg)) { address=bp.address; breakpointHit=true; break; }
            } else setError(bank.error());
        }
        if (breakpointHit) {
            auto cleared=os::clearNativeHardwareStatus(tid);
            if (!cleared) { setError(cleared.error()); hardwareRecovery_=true; recoveryPending_=true; }
        }
    }
    if (!breakpointHit && isSoftwareStop(tid,status)) {
        uintptr_t bpAddress=os::nativeSoftwareBreakpointAddress(*context);
        auto bp=softBreakpoints_.find(bpAddress);
        if (bp!=softBreakpoints_.end() && bp->second.active && bp->second.patch.installed) {
            address=bpAddress;
            rewindSoftwareStop(tid,address);
            breakpointHit=true;
        }
    }
    if (breakpointHit || hasExceptionBreakpoint(signal)) {
        if (!breakpointHit && (status>>16)==0) pendingSignals_.at(tid)=signal;
        activeTid_=tid; stopOtherThreads(tid); stopped_=true;
        captureRegs(tid); publishStoppedThreads();
        DebugEvent event{breakpointHit ? DebugEventType::BreakpointHit : DebugEventType::ExceptionBreakpointHit,
                         tid,address,signal,getStopContext()};
        event.generation=imageGeneration_;
        if (eventCb_) eventCb_(event);
        return;
    }
    // Only ptrace events and trace traps belong to us. Preserve genuine user
    // SIGTRAP, original program BRK/INT3, and ordinary signal-delivery stops.
    int deliver=(status>>16)!=0 || (signal==SIGTRAP && haveInfo && info.si_code==TRAP_TRACE) ? 0 : signal;
    if (holdStop) {
        pendingSignals_.at(tid)=deliver;
        activeTid_=tid; stopOtherThreads(tid); stopped_=true;
        captureRegs(tid); publishStoppedThreads();
        DebugEvent event{DebugEventType::SignalReceived,tid,address,deliver,getStopContext()};
        event.generation=imageGeneration_;
        if (eventCb_) eventCb_(event);
        return;
    }
    if (ptrace(PTRACE_CONT,tid,nullptr,reinterpret_cast<void*>(intptr_t(deliver)))==0) stoppedTids_.erase(tid);
    else { setError({errno,std::system_category()}); stopOtherThreads(tid); stopped_=true; }
}

bool DebugSession::runToTempBreakpoint(pid_t tid,uintptr_t expected) {
    for (;;) {
        if (ptrace(PTRACE_CONT,tid,nullptr,reinterpret_cast<void*>(intptr_t(pendingSignals_.at(tid))))<0) {
            setError({errno,std::system_category()}); return false;
        }
        pendingSignals_.at(tid)=0; stoppedTids_.erase(tid);
        int status=0;
        if (!waitForStop(tid,status) || !attached_) return false;
        if (isEventStop(status,PTRACE_EVENT_EXEC)) { handleExec(tid); return false; }
        bool softwareStop=isSoftwareStop(tid,status);
        if (softwareStop) {
            auto context=os::readNativeContext(tid);
            if (!context) { setError(context.error()); return false; }
            uintptr_t address=os::nativeSoftwareBreakpointAddress(*context);
            if (address==expected) return rewindSoftwareStop(tid,address);
            auto bp=softBreakpoints_.find(address);
            if (bp!=softBreakpoints_.end() && bp->second.active) { handleStop(tid,status); return false; }
        }
        if (isEventStop(status,PTRACE_EVENT_CLONE)) {
            if (!adoptClonedThread(tid)) return false;
            continue;
        }
        siginfo_t info{};
        bool haveInfo=ptrace(PTRACE_GETSIGINFO,tid,nullptr,&info)==0;
        int signal=WSTOPSIG(status);
        if (hasExceptionBreakpoint(signal) ||
            (signal==SIGTRAP && haveInfo && info.si_code==TRAP_HWBKPT && !hwBreakpoints_.empty())) {
            handleStop(tid,status); return false;
        }
        pendingSignals_.at(tid)=(status>>16)!=0 ||
            (signal==SIGTRAP && haveInfo && info.si_code==TRAP_TRACE) ? 0 : signal;
    }
}

void DebugSession::step(StepMode mode, uintptr_t targetAddress) {
    if (!attached_.load()) return;
    postCommand({CmdType::Step, mode, targetAddress, 0, nullptr});
}

// Runs on the tracer thread. All-stop stepping: only the active thread runs;
// every other thread stays frozen. On return stopped_ is true and stopContext_
// holds fresh registers.
void DebugSession::doStep(StepMode mode,uintptr_t targetAddress) {
    if (!stopped_ || recoveryPending_) return;
    pid_t tid=activeTid_.load() ? activeTid_.load() : pid_;
    auto registers=os::readNativeContext(tid);
    if (!registers) { setError(registers.error()); return; }
    uintptr_t pc=registers->instructionPointer();
    bool atBreakpoint=false;
    {
        auto bp=softBreakpoints_.find(pc);
        atBreakpoint=bp!=softBreakpoints_.end() && bp->second.active;
    }
    auto stepOne=[&] {
        if (pendingHardwareSteps_.at(tid)) return stepThreadOverWatchpoint(tid);
        return atBreakpoint ? stepThreadOverBp(tid) : singleStepThread(tid);
    };
    auto runTo=[&](uintptr_t address) {
        if (pendingHardwareSteps_.at(tid) && !stepThreadOverWatchpoint(tid)) return false;
        uint64_t generation=imageGeneration_;
        auto existing=softBreakpoints_.find(address);
        bool created=existing==softBreakpoints_.end();
        int id=created ? static_cast<int>(doSetSoftBp(address)) : existing->second.id;
        if (id<0) return false;
        if (atBreakpoint && !liftSoftBreakpoint(pc)) {
            if (created) doRemoveSoftBp(id);
            return false;
        }
        bool completed=runToTempBreakpoint(tid,address);
        if (imageGeneration_==generation && !traced_.empty()) {
            if (created && !doRemoveSoftBp(id)) completed=false;
            if (atBreakpoint && !rearmSoftBreakpoint(pc)) completed=false;
        }
        return completed;
    };
    bool completed=false;
    switch (mode) {
        case StepMode::Into: completed=stepOne(); break;
        case StepMode::Over: {
            uint8_t bytes[16]{};
            auto read=proc_->read(pc,bytes,sizeof(bytes));
            size_t count=read ? std::min(*read,sizeof(bytes)) : 0;
            auto bp=softBreakpoints_.find(pc);
            if (bp!=softBreakpoints_.end() && bp->second.active && count>=bp->second.patch.size)
                std::copy_n(bp->second.patch.original.begin(),bp->second.patch.size,bytes);
            auto architecture=disassemblerArchFor(*proc_,pc);
            if (!architecture) { setError(std::make_error_code(std::errc::not_supported)); return; }
            Disassembler decoder(*architecture);
            auto instruction=decoder.disassembleOne(pc,{bytes,count});
            if (instruction && instruction->isCall) completed=runTo(pc+instruction->size);
            else completed=stepOne();
            break;
        }
        case StepMode::Out: {
            uintptr_t returnAddress=0;
            if (registers->architecture==CpuArchitecture::Arm64) returnAddress=registers->x[30];
            else {
                size_t width=registers->architecture==CpuArchitecture::X86_32 ? 4 : 8;
                std::array<uint8_t,8> bytes{};
                auto read=proc_->read(registers->stackPointer(),bytes.data(),width);
                auto decoded=read && *read==width ? decodeTargetUnsigned({bytes.data(),width},
                    proc_->machineAt(pc).byteOrder) : std::expected<uint64_t,std::string>(std::unexpected("Unreadable return address"));
                if (decoded && *decoded<=UINTPTR_MAX) returnAddress=*decoded;
            }
            if (returnAddress) completed=runTo(returnAddress);
            else setError(std::make_error_code(std::errc::bad_address));
            break;
        }
        case StepMode::RunToCursor:
            if (targetAddress && pc!=targetAddress) completed=runTo(targetAddress);
            break;
    }
    if (!completed || !attached_ || recoveryPending_) return;
    activeTid_=tid; stopped_=true;
    captureRegs(tid); publishStoppedThreads();
    DebugEvent event{DebugEventType::SingleStep,tid,0,0,getStopContext()};
    event.generation=imageGeneration_;
    event.address=event.context.instructionPointer();
    if (eventCb_) eventCb_(event);
}

CpuContext DebugSession::getStopContext() const {
    std::lock_guard lock(contextMutex_);
    return stopContext_;
}

} // namespace ce
