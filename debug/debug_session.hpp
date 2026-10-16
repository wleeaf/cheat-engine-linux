#pragma once
/// Persistent ptrace attachment with native register/breakpoint backends and stepping.

#include "debug/breakpoint_manager.hpp"
#include "platform/process_api.hpp"
#include "platform/linux/target_debug.hpp"
#include <thread>
#include <atomic>
#include <functional>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <vector>
#include <array>
#include <mutex>
#include <condition_variable>
#include <deque>
#include <future>
#include <memory>
#include <optional>

namespace ce {

enum class StepMode { Into, Over, Out, RunToCursor };

enum class DebugEventType {
    BreakpointHit,
    ExceptionBreakpointHit,
    SingleStep,
    ProcessExited,
    ProcessExecuted,
    SignalReceived,
    ThreadExiting,
};

struct DebugEvent {
    DebugEventType type;
    pid_t tid;
    uintptr_t address;
    int signal;
    CpuContext context;
    uint64_t generation=0;
    // ThreadExiting carries the surviving selected thread's context in tid;
    // this separate ID identifies the task irreversibly leaving the group.
    pid_t exitingTid=0;
};

class DebugSession {
public:
    DebugSession() = default;
    ~DebugSession();

    /// Attach to a process and start the debug event loop.
    bool attach(pid_t pid, ProcessHandle* proc);

    /// Detach and stop the event loop.
    void detach();

    bool isAttached() const { return attached_.load(); }
    pid_t pid() const { return pid_; }

    /// Set an architecture-specific software trap. Returns breakpoint ID.
    int setSoftwareBreakpoint(uintptr_t address);

    /// Remove a software breakpoint.
    bool removeSoftwareBreakpoint(int id);

    /// Plant a native hardware data watchpoint. type: 1=write, 3=access;
    /// size: 1/2/4/8 bytes. Returns an id, or -1 if no kernel slot is free.
    int setHardwareBreakpoint(uintptr_t address, int type, int size);
    /// Remove a hardware watchpoint by id.
    bool removeHardwareBreakpoint(int id);

    /// Continue execution after a break. Returns false when the target could
    /// not be resumed and no stop was reported instead (lastError() says why).
    /// A hit another thread took while the target was stopping is reported
    /// by this call rather than lost; the target then stays stopped.
    bool continueExecution();

    /// Step (into, over, out, run to cursor).
    void step(StepMode mode, uintptr_t targetAddress = 0);

    /// Break when the target receives this signal (for example SIGSEGV).
    void addExceptionBreakpoint(int signal);
    void removeExceptionBreakpoint(int signal);
    bool hasExceptionBreakpoint(int signal) const;

    /// Is the process currently stopped?
    bool isStopped() const { return stopped_.load(); }
    bool hasPendingRecovery() const { return recoveryPending_.load(); }
    uint64_t imageGeneration() const { return imageGeneration_.load(); }
    bool retryPendingOperations();
    Error lastError() const;
    os::NativeVectorContext getVectorRegisters() const;

    /// Get the current stop context.
    CpuContext getStopContext() const;

    /// Overwrite the stopped thread's general-purpose registers and flags
    /// (register editing in the debugger). Only the managed integer registers
    /// and native flags are written; everything else the thread had is preserved.
    /// Returns false if the target is not currently stopped.
    bool setStopContext(const CpuContext& ctx);

    /// The thread ids frozen at the current all-stop (for a thread switcher).
    /// Snapshot from the last break; meaningful while isStopped().
    std::vector<pid_t> stoppedThreads() const;

    /// Make `tid` the active thread: getStopContext / setStopContext / step now
    /// operate on it. Returns false if it isn't currently stopped.
    bool selectThread(pid_t tid);

    /// The active (currently-selected) thread.
    pid_t activeThread() const { return activeTid_; }

    /// The 16 XMM registers (XMM0-15, 16 bytes each) of the active thread,
    /// captured at the last stop. Meaningful while isStopped().
    std::array<std::array<uint8_t, 16>, 16> getXmmRegisters() const;

    /// Callback for debug events.
    using EventCallback = std::function<void(const DebugEvent&)>;
    void setEventCallback(EventCallback cb) { eventCb_ = std::move(cb); }

    /// Access breakpoint manager.
    BreakpointManager& breakpoints() { return bpManager_; }

private:
    // ptrace is per-tracer-thread: every ptrace()/waitpid() for the tracee must
    // be issued by the one thread that attached. So the event-loop thread is the
    // sole tracer; public mutators (continue/step/set-bp/remove-bp) post a
    // command that the tracer thread executes while the tracee is stopped.
    enum class CmdType { Continue, Step, SetSoftBp, RemoveSoftBp, SetRegs, SelectThread,
                         SetHwBp, RemoveHwBp, RetryRecovery };
    struct Command {
        CmdType type;
        StepMode stepMode{StepMode::Into};
        uintptr_t addr = 0;   // step target / breakpoint address
        int id = 0;           // RemoveSoftBp/RemoveHwBp target
        std::shared_ptr<std::promise<long>> done; // result (bp id, else 0)
        CpuContext regs{};    // SetRegs payload
        int hwType = 0;       // SetHwBp: watch condition (1=write, 3=access)
        int hwSize = 0;       // SetHwBp: watch length in bytes
    };

    void tracerThread();
    long postCommand(Command cmd);
    long performCommand(const Command& cmd);
    void handleStop(pid_t tid, int status, bool holdStop=false);
    bool captureRegs(pid_t tid);  // native register banks on the tracer thread
    void tracerCleanup();
    // These run ONLY on the tracer thread.
    bool doContinue();
    void doStep(StepMode mode, uintptr_t targetAddress);
    long doSetSoftBp(uintptr_t address);
    bool doRemoveSoftBp(int id);
    long doSetHwBp(uintptr_t address, int type, int size);
    bool doRemoveHwBp(int id);
    bool disarmAllHwBreakpoints();   // restore native banks before detach
    bool doSetRegs(const CpuContext& ctx);
    bool doSelectThread(pid_t tid);
    void publishStoppedThreads();   // snapshot stoppedTids_ for stoppedThreads()
    // Run `tid` until the temporary trap at `expected` fires (restoring PC so
    // the original instruction re-executes). If a user software breakpoint is
    // hit en route it is surfaced as a BreakpointHit and the step is abandoned
    // there; returns false in that case and on tracee exit, true on success.
    // A frame check accepts the trap only in the starting frame or an outer
    // one, so a recursive call reaching the same address does not end it.
    // `reentry`, when set, holds a second temporary trap at the stepped call
    // (or the entry of the function stepped out of): deeper frames passing it
    // are counted, so a call that returns with a lower stack pointer is told
    // apart from a deeper frame on x86.
    enum class FrameCheck { None, Over, Out };
    bool runToTempBreakpoint(pid_t tid, uintptr_t expected, FrameCheck frame = FrameCheck::None,
                             uintptr_t startSp = 0, uintptr_t reentry = 0);
    // True when an x86 `ret` (or a pop) just took `address` off the stack.
    bool poppedReturnTo(const CpuContext& context, uintptr_t address) const;
    // ── All-stop multi-thread helpers (tracer thread only) ──
    // Seize every thread of the target with PTRACE_O_TRACECLONE and leave them
    // stopped. Populates traced_/stoppedTids_. Returns false if none seized.
    bool seizeAllThreads();
    // Interrupt every traced thread except `active` and drain it to a stop, so
    // the whole target is frozen (all-stop) while the user inspects `active`.
    void stopOtherThreads(pid_t active);
    // Resume every stopped thread, stepping any thread that sits on an armed
    // software breakpoint over it first (restore byte, single-step, re-arm).
    bool resumeAllThreads();
    // If `tid` is stopped exactly on an armed trap, step it past the original
    // instruction with the breakpoint temporarily lifted. Returns true if it did.
    bool stepThreadOverBp(pid_t tid);
    bool stepThreadOverWatchpoint(pid_t tid);
    // Record why a thread frozen for an all-stop stopped, without reporting
    // it. Returns false when an exec replaced the image.
    bool absorbStop(pid_t tid, int status);
    void absorbForeignStops();
    // Freeze every other thread for a stop of `tid`. False when an exec or
    // the process's exit happened meanwhile (its own event already went out).
    bool holdAll(pid_t tid);
    // Emit a stop event for a stopped thread and make it the active one. No
    // address means the thread's PC.
    void reportStop(pid_t tid, DebugEventType type, int signal, std::optional<uintptr_t> address = std::nullopt,
                    bool softwareHit = false);
    // All-stopped after a failure with no stop of our own to show: report one.
    void reportHeldStop(pid_t preferred);
    bool reportDeferredStop(pid_t tid, int status);
    bool resumeThread(pid_t tid);
    void trackGroupStop(pid_t tid, int status);
    std::optional<uintptr_t> takeX86WatchpointHit(pid_t tid);
    bool adoptClonedThread(pid_t parent);
    bool singleStepThread(pid_t tid);
    bool waitForStop(pid_t tid, int& status, bool cancellable = true);
    bool liftSoftBreakpoint(uintptr_t address);
    bool rearmSoftBreakpoint(uintptr_t address);
    bool recoverBreakpoints();
    bool restoreHardwareState();
    bool initializeThreadHardware(pid_t tid);
    bool rewindSoftwareStop(pid_t tid, uintptr_t address);
    bool isSoftwareStop(pid_t tid, int status) const;
    pid_t stoppedMemoryThread() const;
    void setError(Error error);
    void handleExec(pid_t tid, bool notify = true);
    bool recoverRenamedExec();
    bool finishExitStop(pid_t tid);
    void retireThread(pid_t tid, int status);
    void publishThreadExits();

    pid_t pid_ = 0;
    std::atomic<pid_t> activeTid_{0};               // thread currently stopped/reported
    std::set<pid_t> traced_;            // all seized tids (tracer thread only)
    std::set<pid_t> stoppedTids_;       // currently ptrace-stopped tids
    std::set<pid_t> pendingExitStops_;  // EXIT stops retained until detach succeeds
    std::vector<pid_t> exitedDuringStop_;
    std::vector<pid_t> stoppedSnapshot_; // published stopped tids (contextMutex_)
    std::array<std::array<uint8_t, 16>, 16> xmmRegs_{}; // XMM0-15 (contextMutex_)
    ProcessHandle* proc_ = nullptr;
    std::atomic<bool> attached_{false};
    std::atomic<bool> stopped_{false};
    std::atomic<bool> recoveryPending_{false};
    bool hardwareRecovery_ = false;
    std::unordered_map<pid_t, os::NativeHardwareBank> savedHardware_;
    std::unordered_map<pid_t, int> pendingSignals_;
    std::unordered_map<pid_t, uintptr_t> pendingRewinds_;
    std::unordered_map<pid_t, uintptr_t> pendingHardwareSteps_;
    // Stops of other threads seen while waiting for one thread. They are
    // classified by the all-stop, never reported from inside the wait.
    std::deque<std::pair<pid_t, int>> foreignStops_;
    // Hits that cannot recur when resumed (an x86 watchpoint, an exception
    // breakpoint signal) taken by another thread during an all-stop. Continue
    // reports them before it resumes anything.
    std::deque<std::pair<pid_t, int>> deferredStops_;
    // The PC each thread's last stop was reported at. Only such a thread is
    // stepped over a breakpoint on resume; others re-trap and are reported.
    std::unordered_map<pid_t, uintptr_t> reportedPc_;
    std::set<pid_t> groupStopped_;      // last stop was a job-control group-stop
    uint64_t reportCount_ = 0;          // stop events emitted (tracer thread only)
    std::optional<std::pair<pid_t, CpuContext>> registerRecovery_;
    std::atomic<uint64_t> imageGeneration_{0};
    os::NativeVectorContext vectorRegisters_{};
    Error lastError_;
    std::thread eventThread_;
    std::thread::id tracerId_;
    std::promise<bool> attachPromise_;
    std::mutex cmdMutex_;
    std::condition_variable cmdCv_;
    std::deque<Command> commands_;
    BreakpointManager bpManager_;
    EventCallback eventCb_;

    // Software breakpoint tracking
    struct SoftBp {
        int id;
        uintptr_t address;
        os::NativeSoftwareBreakpoint patch;
        bool active;
    };
    std::mutex bpMutex_;
    std::unordered_map<uintptr_t, SoftBp> softBreakpoints_;
    int nextSoftBpId_ = 1;
    // Native hardware data watchpoints, tracer thread only.
    struct HwBp { int id; uintptr_t address; int reg; int type; int size; };
    std::vector<HwBp> hwBreakpoints_;
    int nextHwBpId_ = 1;
    mutable std::mutex exceptionMutex_;
    std::unordered_set<int> exceptionBreakSignals_;

    CpuContext stopContext_{};
    mutable std::mutex contextMutex_;
};

} // namespace ce
