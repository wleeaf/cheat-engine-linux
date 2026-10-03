#include "debug/debug_session.hpp"
#include "arch/disassembler.hpp"
#include "platform/linux/ceserver_process.hpp"

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <signal.h>
#include <cstring>
#include <chrono>
#include <cerrno>
#include <unistd.h>
#include <vector>
#include <algorithm>

namespace ce {

// Patch a single byte in the tracee's text via ptrace. process_vm_writev (what
// ProcessHandle::write uses) cannot write read-only code pages, so int3 planting
// must go through PTRACE_POKETEXT, which bypasses page protection. Read-modify-
// write of the containing word. The text is process-wide, so any stopped traced
// thread works; we always use the main tid (pid_), which is traced+stopped
// whenever a poke is issued (breakpoint mutation only happens under all-stop).
// MUST be called on the tracer thread.
static bool pokeByte(pid_t pid, uintptr_t addr, uint8_t val, uint8_t* oldOut) {
    errno = 0;
    long word = ptrace(PTRACE_PEEKTEXT, pid, reinterpret_cast<void*>(addr), nullptr);
    if (word == -1 && errno != 0) return false;
    if (oldOut) *oldOut = static_cast<uint8_t>(word & 0xff);
    word = (word & ~0xffL) | static_cast<long>(val);
    return ptrace(PTRACE_POKETEXT, pid, reinterpret_cast<void*>(addr),
                  reinterpret_cast<void*>(word)) == 0;
}

static bool isEventStop(int status, int event) {
    return WIFSTOPPED(status) && (status >> 8) == (SIGTRAP | (event << 8));
}

DebugSession::~DebugSession() {
    if (attached_) detach();
    // detach() from within a callback cannot join the tracer thread; join the
    // still-joinable thread here so its cleanup completes before we destruct.
    if (eventThread_.joinable())
        eventThread_.join();
}

bool DebugSession::attach(pid_t pid, ProcessHandle* proc) {
    if (attached_ || !proc || dynamic_cast<os::RemoteProcessHandle*>(proc)) return false;
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

void DebugSession::captureRegs(pid_t tid) {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, tid, nullptr, &regs) < 0) return;
    struct user_fpregs_struct fp;
    bool haveFp = (ptrace(PTRACE_GETFPREGS, tid, nullptr, &fp) == 0);
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
    stopContext_.r8  = regs.r8;
    stopContext_.r9  = regs.r9;
    stopContext_.r10 = regs.r10;
    stopContext_.r11 = regs.r11;
    stopContext_.r12 = regs.r12;
    stopContext_.r13 = regs.r13;
    stopContext_.r14 = regs.r14;
    stopContext_.r15 = regs.r15;
    stopContext_.rflags = regs.eflags;
    // xmm_space is 64 x uint32 = 16 XMM registers of 16 bytes each.
    if (haveFp) std::memcpy(xmmRegs_.data(), fp.xmm_space, sizeof(xmmRegs_));
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
    traced_.clear();
    stoppedTids_.clear();
    std::vector<pid_t> tids;
    for (auto& t : proc_->threads()) tids.push_back(t.tid);
    if (tids.empty()) tids.push_back(pid_);

    for (pid_t tid : tids) {
        // SEIZE (not ATTACH) so PTRACE_O_TRACECLONE auto-traces future threads
        // and we control the stop explicitly via INTERRUPT.
        if (ptrace(PTRACE_SEIZE, tid, nullptr,
                   reinterpret_cast<void*>(PTRACE_O_TRACECLONE)) < 0)
            continue;
        if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) != 0) {
            ptrace(PTRACE_DETACH, tid, nullptr, nullptr);   // don't leave it seized
            continue;
        }
        int st = 0;
        pid_t w;
        do { w = waitpid(tid, &st, __WALL); } while (w < 0 && errno == EINTR);
        if (w == tid) {
            traced_.insert(tid);
            stoppedTids_.insert(tid);
        } else {
            // Seized but never stopped: detach so the thread is not left frozen
            // (traced_ is what resume/cleanup iterate, so an untracked tid leaks).
            ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
        }
    }
    return !traced_.empty();
}

void DebugSession::stopOtherThreads(pid_t active) {
    // Freeze every thread except `active` so the whole target is stopped while
    // the user inspects. A thread interrupted exactly on one of our int3s reports
    // a SIGTRAP with rip one past the byte; back its rip up so a later resume
    // re-executes the real instruction.
    for (pid_t tid : traced_) {
        if (tid == active || stoppedTids_.count(tid)) continue;
        if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) != 0) continue;
        int st = 0;
        pid_t w;
        do { w = waitpid(tid, &st, __WALL); } while (w < 0 && errno == EINTR);
        if (w != tid || !WIFSTOPPED(st)) continue;
        stoppedTids_.insert(tid);
        if (WIFSTOPPED(st) && WSTOPSIG(st) == SIGTRAP) {
            struct user_regs_struct r;
            if (ptrace(PTRACE_GETREGS, tid, nullptr, &r) == 0) {
                uintptr_t bpAddr = r.rip - 1;
                std::lock_guard lk(bpMutex_);
                auto it = softBreakpoints_.find(bpAddr);
                if (it != softBreakpoints_.end() && it->second.active) {
                    r.rip = bpAddr;
                    ptrace(PTRACE_SETREGS, tid, nullptr, &r);
                }
            }
        }
    }
    publishStoppedThreads();   // record the frozen set for stoppedThreads()
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
    activeTid_ = tid;
    captureRegs(tid);
    return true;
}

bool DebugSession::stepThreadOverBp(pid_t tid) {
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, tid, nullptr, &r) < 0) return false;
    uint8_t orig = 0;
    bool atBp = false;
    {
        std::lock_guard lk(bpMutex_);
        auto it = softBreakpoints_.find(r.rip);
        if (it != softBreakpoints_.end() && it->second.active) {
            orig = it->second.originalByte;
            atBp = true;
        }
    }
    if (!atBp) return false;
    // Lift the int3, single-step the real instruction (all other threads are
    // stopped, so no sibling can execute the un-patched byte), then re-arm.
    pokeByte(pid_, r.rip, orig, nullptr);
    ptrace(PTRACE_SINGLESTEP, tid, nullptr, nullptr);
    int st = 0;
    waitpid(tid, &st, __WALL);
    std::lock_guard lk(bpMutex_);
    auto it = softBreakpoints_.find(r.rip);
    if (it != softBreakpoints_.end() && it->second.active)
        pokeByte(pid_, r.rip, 0xCC, nullptr);
    return true;
}

void DebugSession::resumeAllThreads() {
    // Phase 1 (everyone still stopped): step any thread that sits on an armed
    // int3 past it and re-arm. Doing this before resuming ANY thread is what
    // makes it race-free — no running sibling can slip over a lifted byte.
    for (pid_t tid : traced_) stepThreadOverBp(tid);
    // Phase 2: all breakpoints armed, no thread on one — resume the world.
    for (pid_t tid : traced_) ptrace(PTRACE_CONT, tid, nullptr, nullptr);
    stoppedTids_.clear();
}

// Runs on the tracer thread once the loop exits: stop the world, restore
// breakpoints, and detach every thread.
void DebugSession::tracerCleanup() {
    stopOtherThreads(0);
    {
        std::lock_guard lock(bpMutex_);
        for (auto& [addr, bp] : softBreakpoints_)
            if (bp.active) pokeByte(pid_, addr, bp.originalByte, nullptr);
        softBreakpoints_.clear();
    }
    disarmAllHwBreakpoints();   // clear DR before detach, or the tracee is killed
    for (pid_t tid : traced_)
        ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
    traced_.clear();
    stoppedTids_.clear();
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
        case CmdType::RemoveSoftBp: doRemoveSoftBp(cmd.id); break;
        case CmdType::SetRegs:      result = doSetRegs(cmd.regs) ? 1 : 0; break;
        case CmdType::SelectThread: result = doSelectThread(static_cast<pid_t>(cmd.id)) ? 1 : 0; break;
        case CmdType::SetHwBp:      result = doSetHwBp(cmd.addr, cmd.hwType, cmd.hwSize); break;
        case CmdType::RemoveHwBp:   doRemoveHwBp(cmd.id); break;
    }
    if (resume) doContinue();
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
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, activeTid_, nullptr, &regs) < 0) return false;
    regs.rip = ctx.rip; regs.rsp = ctx.rsp;
    regs.rax = ctx.rax; regs.rbx = ctx.rbx; regs.rcx = ctx.rcx; regs.rdx = ctx.rdx;
    regs.rsi = ctx.rsi; regs.rdi = ctx.rdi; regs.rbp = ctx.rbp;
    regs.r8  = ctx.r8;  regs.r9  = ctx.r9;  regs.r10 = ctx.r10; regs.r11 = ctx.r11;
    regs.r12 = ctx.r12; regs.r13 = ctx.r13; regs.r14 = ctx.r14; regs.r15 = ctx.r15;
    regs.eflags = ctx.rflags;
    if (ptrace(PTRACE_SETREGS, activeTid_, nullptr, &regs) < 0) return false;
    captureRegs(activeTid_);   // refresh the cached stop context
    return true;
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
                if (!pokeByte(pid_, it->first, it->second.originalByte, nullptr)) return;
            softBreakpoints_.erase(it);
            return;
        }
    }
}

// ── Hardware data watchpoints (DR0-3) ──
namespace {
bool armHwBp(pid_t tid, int reg, uintptr_t addr, int cond, int len) {
    size_t drOff = offsetof(struct user, u_debugreg) + reg * sizeof(long);
    if (ptrace(PTRACE_POKEUSER, tid, drOff, addr) < 0) return false;
    size_t dr7Off = offsetof(struct user, u_debugreg) + 7 * sizeof(long);
    errno = 0;
    long dr7 = ptrace(PTRACE_PEEKUSER, tid, dr7Off, nullptr);
    if (dr7 == -1 && errno != 0) return false;
    dr7 |= (1L << (reg * 2));                        // local enable
    dr7 &= ~(0xFL << (16 + reg * 4));                // clear condition+length
    dr7 |= ((long)(cond & 0x3) << (16 + reg * 4));   // 1=write, 3=access
    dr7 |= ((long)(len & 0x3) << (18 + reg * 4));    // length (0=1,1=2,2=8,3=4)
    return ptrace(PTRACE_POKEUSER, tid, dr7Off, dr7) >= 0;
}
void disarmHwBpReg(pid_t tid, int reg) {
    size_t dr7Off = offsetof(struct user, u_debugreg) + 7 * sizeof(long);
    errno = 0;
    long dr7 = ptrace(PTRACE_PEEKUSER, tid, dr7Off, nullptr);
    if (!(dr7 == -1 && errno != 0)) {
        dr7 &= ~(1L << (reg * 2));
        dr7 &= ~(0xFL << (16 + reg * 4));
        ptrace(PTRACE_POKEUSER, tid, dr7Off, dr7);
    }
    size_t drOff = offsetof(struct user, u_debugreg) + reg * sizeof(long);
    ptrace(PTRACE_POKEUSER, tid, drOff, 0L);
}
} // namespace

int DebugSession::setHardwareBreakpoint(uintptr_t address, int type, int size) {
    if (!attached_.load()) return -1;
    Command cmd;
    cmd.type = CmdType::SetHwBp;
    cmd.addr = address;
    cmd.hwType = type;
    cmd.hwSize = size;
    return static_cast<int>(postCommand(std::move(cmd)));
}

void DebugSession::removeHardwareBreakpoint(int id) {
    if (!attached_.load()) return;
    Command cmd; cmd.type = CmdType::RemoveHwBp; cmd.id = id;
    postCommand(std::move(cmd));
}

// Tracer thread only. Arm a DR on every traced thread (they are stopped when a
// breakpoint is set during setup, right after attach).
long DebugSession::doSetHwBp(uintptr_t address, int type, int size) {
    bool used[4] = {false, false, false, false};
    for (auto& b : hwBreakpoints_) if (b.reg >= 0 && b.reg < 4) used[b.reg] = true;
    int reg = -1;
    for (int i = 0; i < 4; ++i) if (!used[i]) { reg = i; break; }
    if (reg < 0) return -1;                                   // no free debug register
    int len  = (size == 1) ? 0 : (size == 2) ? 1 : (size == 8) ? 2 : 3;
    int cond = (type == 1) ? 1 : 3;                           // 1=write, else access
    int armed = 0;
    for (pid_t tid : traced_)
        if (armHwBp(tid, reg, address, cond, len)) ++armed;
    // Don't report success if the DR was armed on no thread (e.g. the command
    // ran while the target was running, so PTRACE_POKEUSER failed).
    if (!traced_.empty() && armed == 0) return -1;
    int id = nextHwBpId_++;
    hwBreakpoints_.push_back({id, address, reg, cond, len});
    return id;
}

void DebugSession::doRemoveHwBp(int id) {
    for (auto it = hwBreakpoints_.begin(); it != hwBreakpoints_.end(); ++it) {
        if (it->id == id) {
            for (pid_t tid : traced_) disarmHwBpReg(tid, it->reg);
            hwBreakpoints_.erase(it);
            return;
        }
    }
}

// Clear every hardware watchpoint on every thread. MUST run before PTRACE_DETACH
// (which leaves debug registers armed) or the tracee takes a debug exception with
// no tracer and is killed.
void DebugSession::disarmAllHwBreakpoints() {
    for (auto& b : hwBreakpoints_)
        for (pid_t tid : traced_) disarmHwBpReg(tid, b.reg);
    hwBreakpoints_.clear();
}

void DebugSession::continueExecution() {
    if (!attached_.load()) return;
    postCommand({CmdType::Continue, StepMode::Into, 0, 0, nullptr});
}

void DebugSession::doContinue() {
    if (!stopped_.load()) return;
    resumeAllThreads();
    stopped_ = false;
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
    activeTid_ = pid_;
    captureRegs(activeTid_);
    attachPromise_.set_value(true);

    while (attached_.load()) {
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
            long r = performCommand(cmd);
            if (cmd.done) cmd.done->set_value(r);
            continue;
        }

        // 2) Running: poll for the next event from ANY thread (__WALL).
        if (!stopped_.load()) {
            int st = 0;
            pid_t w = waitpid(-1, &st, __WALL | __WNOTHREAD | WNOHANG);
            if (w == 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
                continue;
            }
            if (w < 0) {
                if (errno == ECHILD) {   // the whole process is gone
                    DebugEvent evt{};
                    evt.type = DebugEventType::ProcessExited;
                    evt.tid = pid_;
                    if (eventCb_) eventCb_(evt);
                    attached_ = false;
                    stopped_ = false;
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
                continue;
            }
            handleStop(w, st);
            continue;
        }

        // 3) All-stopped with nothing queued: wait for a command or detach.
        std::unique_lock lk(cmdMutex_);
        cmdCv_.wait_for(lk, std::chrono::milliseconds(50),
                        [&] { return !commands_.empty() || !attached_.load(); });
    }

    tracerCleanup();
}

void DebugSession::handleStop(pid_t w, int status) {
    // A thread (or the whole process) exited.
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        traced_.erase(w);
        stoppedTids_.erase(w);
        if (w == pid_ || traced_.empty()) {
            DebugEvent evt{};
            evt.type = DebugEventType::ProcessExited;
            evt.tid = w;
            if (eventCb_) eventCb_(evt);
            attached_ = false;
            stopped_ = false;
        }
        return;
    }
    if (!WIFSTOPPED(status)) return;

    // A newly created thread: auto-seized + stopped by PTRACE_O_TRACECLONE.
    // Track it and (since we're running) resume both it and its parent.
    if (isEventStop(status, PTRACE_EVENT_CLONE)) {
        unsigned long newTid = 0;
        if (ptrace(PTRACE_GETEVENTMSG, w, nullptr, &newTid) == 0 && newTid) {
            int cst = 0;
            waitpid(static_cast<pid_t>(newTid), &cst, __WALL);   // consume initial stop
            traced_.insert(static_cast<pid_t>(newTid));
            ptrace(PTRACE_CONT, static_cast<pid_t>(newTid), nullptr, nullptr);
        }
        ptrace(PTRACE_CONT, w, nullptr, nullptr);
        return;
    }

    int sig = WSTOPSIG(status);

    if (sig == SIGTRAP) {
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, w, nullptr, &regs) < 0) {
            ptrace(PTRACE_CONT, w, nullptr, nullptr);
            return;
        }
        // A hardware DATA watchpoint fires with siginfo TRAP_HWBKPT (distinct from
        // a software int3). Identify which DR triggered via DR6 and report the
        // watched address. rip points past the accessing instruction.
        if (!hwBreakpoints_.empty()) {
            siginfo_t si{};
            if (ptrace(PTRACE_GETSIGINFO, w, nullptr, &si) == 0 && si.si_code == TRAP_HWBKPT) {
                size_t dr6Off = offsetof(struct user, u_debugreg) + 6 * sizeof(long);
                long dr6 = ptrace(PTRACE_PEEKUSER, w, dr6Off, nullptr);
                uintptr_t hitAddr = regs.rip;
                for (auto& b : hwBreakpoints_)
                    if (b.reg >= 0 && b.reg < 4 && (dr6 & (1L << b.reg))) { hitAddr = b.address; break; }
                ptrace(PTRACE_POKEUSER, w, dr6Off, 0L);   // clear DR6 status bits
                activeTid_ = w;
                stoppedTids_.insert(w);
                stopOtherThreads(w);
                stopped_ = true;
                captureRegs(w);
                DebugEvent evt{};
                evt.type = DebugEventType::BreakpointHit;
                evt.tid = w;
                evt.address = hitAddr;
                evt.signal = sig;
                { std::lock_guard lock(contextMutex_); evt.context = stopContext_; }
                if (eventCb_) eventCb_(evt);
                return;
            }
        }
        uintptr_t bpAddr = regs.rip - 1;
        bool hitSoftBp = false;
        {
            std::lock_guard lock(bpMutex_);
            auto it = softBreakpoints_.find(bpAddr);
            hitSoftBp = (it != softBreakpoints_.end() && it->second.active);
        }
        if (hitSoftBp) {
            regs.rip = bpAddr;                       // rewind past the int3
            ptrace(PTRACE_SETREGS, w, nullptr, &regs);
            activeTid_ = w;
            stoppedTids_.insert(w);
            stopOtherThreads(w);                     // freeze the world (all-stop)
            stopped_ = true;
            captureRegs(w);

            DebugEvent evt{};
            evt.type = DebugEventType::BreakpointHit;
            evt.tid = w;
            evt.address = bpAddr;
            evt.signal = sig;
            {
                std::lock_guard lock(contextMutex_);
                evt.context = stopContext_;
            }
            if (eventCb_) eventCb_(evt);
            return;                                  // stay all-stopped
        }
        // A SIGTRAP that is not one of our breakpoints (leftover single-step,
        // group-stop). Resume the thread without re-injecting SIGTRAP.
        ptrace(PTRACE_CONT, w, nullptr, nullptr);
        return;
    }

    // A signal we were asked to break on (exception breakpoint).
    if (hasExceptionBreakpoint(sig)) {
        struct user_regs_struct regs{};
        ptrace(PTRACE_GETREGS, w, nullptr, &regs);
        activeTid_ = w;
        stoppedTids_.insert(w);
        stopOtherThreads(w);
        stopped_ = true;
        captureRegs(w);

        DebugEvent evt{};
        evt.type = DebugEventType::ExceptionBreakpointHit;
        evt.tid = w;
        evt.address = regs.rip;
        evt.signal = sig;
        {
            std::lock_guard lock(contextMutex_);
            evt.context = stopContext_;
        }
        if (eventCb_) eventCb_(evt);
        return;
    }

    // Any other signal: deliver it to the target and keep running.
    ptrace(PTRACE_CONT, w, nullptr, reinterpret_cast<void*>(static_cast<long>(sig)));
}

// Resume `tid` until the temporary int3 at `expected` traps. A single waitpid
// used to be assumed to be that temp breakpoint, so a user breakpoint hit during
// a step-over/out/run-to-cursor was mistaken for step completion (the temp was
// cleared and a bogus SingleStep reported). Handle each stop: our temp completes
// the step (RIP rewound), a user int3 is surfaced as a BreakpointHit and the
// step is abandoned there, other signals are re-delivered.
bool DebugSession::runToTempBreakpoint(pid_t tid, uintptr_t expected) {
    long contSig = 0;
    for (int guard = 0; guard < 1000000; ++guard) {
        if (ptrace(PTRACE_CONT, tid, nullptr, reinterpret_cast<void*>(contSig)) < 0)
            return false;
        contSig = 0;
        int status = 0;
        pid_t w;
        do { w = waitpid(tid, &status, __WALL); } while (w < 0 && errno == EINTR);
        if (w != tid) return false;
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            DebugEvent evt{};
            evt.type = DebugEventType::ProcessExited;
            evt.tid = w;
            if (eventCb_) eventCb_(evt);
            attached_ = false;
            stopped_ = false;
            return false;
        }
        if (!WIFSTOPPED(status)) continue;
        int sig = WSTOPSIG(status);
        if (sig != SIGTRAP) { contSig = sig; continue; }   // re-deliver real signal
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, tid, nullptr, &regs) < 0) continue;
        if (regs.rip == expected + 1) {                    // our temp int3
            regs.rip = expected;                           // re-execute the instruction
            ptrace(PTRACE_SETREGS, tid, nullptr, &regs);
            return true;
        }
        uintptr_t bpAddr = regs.rip - 1;
        bool hitSoftBp = false;
        {
            std::lock_guard lk(bpMutex_);
            auto it = softBreakpoints_.find(bpAddr);
            hitSoftBp = (it != softBreakpoints_.end() && it->second.active);
        }
        if (hitSoftBp) {                                   // user breakpoint: surface it
            regs.rip = bpAddr;
            ptrace(PTRACE_SETREGS, tid, nullptr, &regs);
            activeTid_ = tid;
            stoppedTids_.insert(tid);
            stopOtherThreads(tid);
            stopped_ = true;
            captureRegs(tid);
            DebugEvent evt{};
            evt.type = DebugEventType::BreakpointHit;
            evt.tid = tid;
            evt.address = bpAddr;
            evt.signal = sig;
            { std::lock_guard lk(contextMutex_); evt.context = stopContext_; }
            if (eventCb_) eventCb_(evt);
            return false;
        }
        // Stray SIGTRAP (leftover single-step/group-stop): swallow and continue.
    }
    // Safety net (pathological signal storm): stop where we are and let doStep
    // report the stop rather than leaving the thread running with stopped_ true.
    if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) == 0) {
        int st = 0;
        pid_t w;
        do { w = waitpid(tid, &st, __WALL); } while (w < 0 && errno == EINTR);
        return true;
    }
    return false;
}

void DebugSession::step(StepMode mode, uintptr_t targetAddress) {
    if (!attached_.load()) return;
    postCommand({CmdType::Step, mode, targetAddress, 0, nullptr});
}

// Runs on the tracer thread. All-stop stepping: only the active thread runs;
// every other thread stays frozen. On return stopped_ is true and stopContext_
// holds fresh registers.
void DebugSession::doStep(StepMode mode, uintptr_t targetAddress) {
    if (!stopped_.load()) return;
    pid_t tid = activeTid_ ? activeTid_ : pid_;

    // Plant a temporary int3 only if the address isn't already an armed user
    // breakpoint; report whether we created it so we can cleanly remove it.
    struct Temp { uintptr_t addr; uint8_t orig; bool created; bool valid; };
    auto setTemp = [&](uintptr_t addr) -> Temp {
        {
            std::lock_guard lk(bpMutex_);
            auto it = softBreakpoints_.find(addr);
            if (it != softBreakpoints_.end() && it->second.active)
                return {addr, 0, false, true};
        }
        uint8_t orig = 0;
        bool ok = pokeByte(pid_, addr, 0xCC, &orig);
        return {addr, orig, ok, ok};
    };
    auto clearTemp = [&](const Temp& t) {
        if (t.created) pokeByte(pid_, t.addr, t.orig, nullptr);
    };
    // Lift an armed user int3 the active thread may be sitting on, so CONT does
    // not immediately re-trap; returns the byte to re-arm afterwards.
    auto liftCurrentBp = [&](uintptr_t rip) -> bool {
        std::lock_guard lk(bpMutex_);
        auto it = softBreakpoints_.find(rip);
        if (it != softBreakpoints_.end() && it->second.active) {
            pokeByte(pid_, rip, it->second.originalByte, nullptr);
            return true;
        }
        return false;
    };
    auto rearmCurrentBp = [&](uintptr_t rip) {
        std::lock_guard lk(bpMutex_);
        auto it = softBreakpoints_.find(rip);
        if (it != softBreakpoints_.end() && it->second.active)
            pokeByte(pid_, rip, 0xCC, nullptr);
    };

    // False when a step was abandoned because a user breakpoint was hit en route
    // (runToTempBreakpoint already surfaced it), so we must not also report a
    // SingleStep at that stop.
    bool stepCompleted = true;
    switch (mode) {
        case StepMode::Into: {
            // stepThreadOverBp single-steps if sitting on a bp; otherwise plain step.
            if (!stepThreadOverBp(tid)) {
                ptrace(PTRACE_SINGLESTEP, tid, nullptr, nullptr);
                int status = 0;
                waitpid(tid, &status, __WALL);
            }
            break;
        }

        case StepMode::Over: {
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, tid, nullptr, &regs);
            uint8_t buf[16];
            auto rr = proc_->read(regs.rip, buf, sizeof(buf));
            size_t n = rr ? std::min(*rr, sizeof(buf)) : 0;
            if (n) {
                std::lock_guard lk(bpMutex_);
                auto it = softBreakpoints_.find(regs.rip);
                if (it != softBreakpoints_.end() && it->second.active)
                    buf[0] = it->second.originalByte;
            }
            Disassembler dis(proc_->runs32BitCode() ? Arch::X86_32 : Arch::X86_64);
            auto insns = dis.disassemble(regs.rip, {buf, n}, 1);
            if (!insns.empty() && insns[0].mnemonic == "call") {
                uintptr_t nextAddr = regs.rip + insns[0].size;
                Temp t = setTemp(nextAddr);
                if (!t.valid) return;
                bool lifted = liftCurrentBp(regs.rip);
                stepCompleted = runToTempBreakpoint(tid, nextAddr);
                clearTemp(t);
                if (lifted) rearmCurrentBp(regs.rip);
            } else {
                if (!stepThreadOverBp(tid)) {
                    ptrace(PTRACE_SINGLESTEP, tid, nullptr, nullptr);
                    int status = 0;
                    waitpid(tid, &status, __WALL);
                }
            }
            break;
        }

        case StepMode::Out: {
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, tid, nullptr, &regs);
            uintptr_t retAddr = 0;
            size_t ptrSize = proc_->is64bit() ? 8 : 4;
            auto read = proc_->read(regs.rsp, &retAddr, ptrSize);
            if (read && *read == ptrSize && retAddr) {
                Temp t = setTemp(retAddr);
                if (!t.valid) return;
                bool lifted = liftCurrentBp(regs.rip);
                stepCompleted = runToTempBreakpoint(tid, retAddr);
                clearTemp(t);
                if (lifted) rearmCurrentBp(regs.rip);
            }
            break;
        }

        case StepMode::RunToCursor:
            if (targetAddress) {
                struct user_regs_struct regs;
                ptrace(PTRACE_GETREGS, tid, nullptr, &regs);
                if (regs.rip == targetAddress) return;
                Temp t = setTemp(targetAddress);
                if (!t.valid) return;
                bool lifted = liftCurrentBp(regs.rip);
                stepCompleted = runToTempBreakpoint(tid, targetAddress);
                clearTemp(t);
                if (lifted) rearmCurrentBp(regs.rip);
            }
            break;
    }

    if (!stepCompleted) return;   // a BreakpointHit/exit was already surfaced

    stopped_ = true;
    captureRegs(tid);

    DebugEvent evt{};
    evt.type = DebugEventType::SingleStep;
    evt.tid = tid;
    {
        std::lock_guard lock(contextMutex_);
        evt.address = stopContext_.rip;
        evt.context = stopContext_;
    }
    if (eventCb_) eventCb_(evt);
}

CpuContext DebugSession::getStopContext() const {
    std::lock_guard lock(contextMutex_);
    return stopContext_;
}

} // namespace ce
