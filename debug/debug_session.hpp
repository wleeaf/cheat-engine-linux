#pragma once
/// Debug session — persistent ptrace attachment with event loop, software breakpoints, stepping.

#include "debug/breakpoint_manager.hpp"
#include "platform/process_api.hpp"
#include <thread>
#include <atomic>
#include <functional>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <mutex>
#include <condition_variable>
#include <deque>
#include <future>
#include <memory>

namespace ce {

enum class StepMode { Into, Over, Out, RunToCursor };

enum class DebugEventType {
    BreakpointHit,
    ExceptionBreakpointHit,
    SingleStep,
    ProcessExited,
    SignalReceived,
};

struct DebugEvent {
    DebugEventType type;
    pid_t tid;
    uintptr_t address;
    int signal;
    CpuContext context;
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

    /// Set a software breakpoint (int3). Returns breakpoint ID.
    int setSoftwareBreakpoint(uintptr_t address);

    /// Remove a software breakpoint.
    void removeSoftwareBreakpoint(int id);

    /// Continue execution after a break.
    void continueExecution();

    /// Step (into, over, out, run to cursor).
    void step(StepMode mode, uintptr_t targetAddress = 0);

    /// Break when the target receives this signal (for example SIGSEGV).
    void addExceptionBreakpoint(int signal);
    void removeExceptionBreakpoint(int signal);
    bool hasExceptionBreakpoint(int signal) const;

    /// Is the process currently stopped?
    bool isStopped() const { return stopped_.load(); }

    /// Get the current stop context.
    CpuContext getStopContext() const;

    /// Overwrite the stopped thread's general-purpose registers and flags
    /// (register editing in the debugger). Only the managed integer registers
    /// and RFLAGS are written; everything else the thread had is preserved.
    /// Returns false if the target is not currently stopped.
    bool setStopContext(const CpuContext& ctx);

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
    enum class CmdType { Continue, Step, SetSoftBp, RemoveSoftBp, SetRegs };
    struct Command {
        CmdType type;
        StepMode stepMode{StepMode::Into};
        uintptr_t addr = 0;   // step target / breakpoint address
        int id = 0;           // RemoveSoftBp target
        std::shared_ptr<std::promise<long>> done; // result (bp id, else 0)
        CpuContext regs{};    // SetRegs payload
    };

    void tracerThread();
    long postCommand(Command cmd);
    long performCommand(const Command& cmd);
    void handleStop(pid_t tid, int status);
    void captureRegs(pid_t tid);  // GETREGS on the tracer thread → stopContext_
    void tracerCleanup();
    // These run ONLY on the tracer thread.
    void doContinue();
    void doStep(StepMode mode, uintptr_t targetAddress);
    long doSetSoftBp(uintptr_t address);
    void doRemoveSoftBp(int id);
    bool doSetRegs(const CpuContext& ctx);
    void rewindOverBreakpoint(pid_t tid, int status, uintptr_t bpAddr);
    // ── All-stop multi-thread helpers (tracer thread only) ──
    // Seize every thread of the target with PTRACE_O_TRACECLONE and leave them
    // stopped. Populates traced_/stoppedTids_. Returns false if none seized.
    bool seizeAllThreads();
    // Interrupt every traced thread except `active` and drain it to a stop, so
    // the whole target is frozen (all-stop) while the user inspects `active`.
    void stopOtherThreads(pid_t active);
    // Resume every stopped thread, stepping any thread that sits on an armed
    // software breakpoint over it first (restore byte, single-step, re-arm).
    void resumeAllThreads();
    // If `tid` is stopped exactly on an armed int3, step it past the original
    // instruction with the breakpoint temporarily lifted. Returns true if it did.
    bool stepThreadOverBp(pid_t tid);

    pid_t pid_ = 0;
    pid_t activeTid_ = 0;               // thread currently stopped/reported
    std::set<pid_t> traced_;            // all seized tids (tracer thread only)
    std::set<pid_t> stoppedTids_;       // currently ptrace-stopped tids
    ProcessHandle* proc_ = nullptr;
    std::atomic<bool> attached_{false};
    std::atomic<bool> stopped_{false};
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
        uint8_t originalByte;
        bool active;
    };
    std::mutex bpMutex_;
    std::unordered_map<uintptr_t, SoftBp> softBreakpoints_;
    int nextSoftBpId_ = 1;
    mutable std::mutex exceptionMutex_;
    std::unordered_set<int> exceptionBreakSignals_;

    CpuContext stopContext_{};
    mutable std::mutex contextMutex_;
};

} // namespace ce
