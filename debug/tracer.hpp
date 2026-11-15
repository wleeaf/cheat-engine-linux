#pragma once
/// Break and Trace — single-step N instructions from a breakpoint, logging each.

#include "core/types.hpp"
#include "platform/process_api.hpp"
#include "arch/disassembler.hpp"
#include <vector>
#include <string>
#include <atomic>
#include <functional>
#include <mutex>

namespace ce {

struct TraceEntry {
    uintptr_t address;
    std::string instruction;
    CpuContext context;
    // With dereferenceAddresses: "[address]=value" of the memory operand.
    std::string memoryNote;
    // With stackBytes: that many bytes from the stack pointer before the step.
    std::vector<uint8_t> stack;
};

struct TraceConfig {
    uintptr_t startAddress = 0;
    int maxSteps = 1000;
    bool stepOverCalls = false;
    bool stayInModule = false;
    uintptr_t moduleBase = 0;
    uintptr_t moduleEnd = 0;
    uintptr_t stopAddress = 0;    // Stop when this address is reached (0 = disabled)
    // Conditions on the registers (Cheat Engine's start and stop conditions).
    // startCondition is checked each time the start address is reached; a false
    // result lets the program run on to the next hit. It needs x86 code, where
    // the kernel resumes past an execute breakpoint. stopCondition is checked
    // before every step and ends the trace (that step included) when true.
    std::function<bool(const CpuContext&)> startCondition;
    std::function<bool(const CpuContext&)> stopCondition;
    bool stepOverRep = false;          // run a rep-prefixed string instruction as one step
    bool skipSystemModules = false;    // step over calls into system libraries
    bool dereferenceAddresses = false; // note each memory operand's address and value
    size_t stackBytes = 0;             // copy this many bytes at the stack pointer per step
};

/// Whether a module path is a system library (the C library, Wine's own DLLs),
/// which skipSystemModules steps over.
bool isSystemModulePath(const std::string& path);

class Tracer {
public:
    /// Execute a trace. Blocks until trace completes or is cancelled.
    std::vector<TraceEntry> trace(ProcessHandle& proc, Debugger& dbg, const TraceConfig& config);

    /// Cancel a running trace.
    void cancel() { cancelled_.store(true); }
    /// Clear a previous cancel before starting trace() on another thread, so a
    /// cancel() issued before that thread reaches trace() is not lost.
    void prepare() { cancelled_.store(false); prepared_.store(true); }

    float progress() const { return progress_.load(); }
    /// True once every selected thread is armed and waiting for the start address.
    bool ready() const { return ready_.load(); }
    Error lastError() const { std::lock_guard lock(errorMutex_); return error_; }

private:
    // A ceserver target: traced through the server's debug events and single
    // steps (see trace()).
    std::vector<TraceEntry> traceRemote(ProcessHandle& proc, Debugger& dbg, const TraceConfig& config);
    void setError(Error value) { std::lock_guard lock(errorMutex_); error_ = value; }
    struct LocalTrace;   // the local (ptrace) trace (see tracer.cpp)

    std::mutex traceMutex_;
    std::atomic<bool> cancelled_{false};
    std::atomic<bool> prepared_{false};
    std::atomic<float> progress_{0};
    std::atomic<bool> ready_{false};
    mutable std::mutex errorMutex_;
    Error error_;
};

} // namespace ce
