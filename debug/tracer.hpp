#pragma once
/// Break and Trace — single-step N instructions from a breakpoint, logging each.

#include "core/types.hpp"
#include "platform/process_api.hpp"
#include "arch/disassembler.hpp"
#include <vector>
#include <string>
#include <atomic>
#include <mutex>

namespace ce {

struct TraceEntry {
    uintptr_t address;
    std::string instruction;
    CpuContext context;
};

struct TraceConfig {
    uintptr_t startAddress = 0;
    int maxSteps = 1000;
    bool stepOverCalls = false;
    bool stayInModule = false;
    uintptr_t moduleBase = 0;
    uintptr_t moduleEnd = 0;
    uintptr_t stopAddress = 0;    // Stop when this address is reached (0 = disabled)
};

class Tracer {
public:
    /// Execute a trace. Blocks until trace completes or is cancelled.
    std::vector<TraceEntry> trace(ProcessHandle& proc, Debugger& dbg, const TraceConfig& config);

    /// Cancel a running trace.
    void cancel() { cancelled_.store(true); }

    float progress() const { return progress_.load(); }
    /// True once every selected thread is armed and waiting for the start address.
    bool ready() const { return ready_.load(); }
    Error lastError() const { std::lock_guard lock(errorMutex_); return error_; }

private:
    std::mutex traceMutex_;
    std::atomic<bool> cancelled_{false};
    std::atomic<float> progress_{0};
    std::atomic<bool> ready_{false};
    mutable std::mutex errorMutex_;
    Error error_;
};

} // namespace ce
