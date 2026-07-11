#pragma once
/// "Find what accesses/writes this address" — logs all instructions that touch an address.

#include "debug/breakpoint_manager.hpp"
#include "platform/process_api.hpp"
#include "arch/disassembler.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <thread>

namespace ce {

struct CodeFinderResult {
    uintptr_t instructionAddress;
    std::string instructionText;
    std::vector<uint8_t> instructionBytes;
    int hitCount = 0;
    CpuContext firstContext{}; // Register state at the first time this instruction hit
    CpuContext lastContext{};  // Register state at the most recent hit
};

class CodeFinder {
public:
    CodeFinder() = default;
    ~CodeFinder() { stop(); }

    /// Start monitoring an address for reads (access) or writes only.
    /// Runs in a background thread. Call stop() to finish.
    bool start(ProcessHandle& proc, Debugger& dbg, uintptr_t address, bool writesOnly = false);

    /// Stop monitoring.
    void stop();

    /// Is monitoring active?
    bool running() const { return running_.load(); }

    /// Get accumulated results (grouped by instruction address, sorted by hit count).
    std::vector<CodeFinderResult> results() const;

    /// Clear results.
    void clearResults();

private:
    void monitorLoop();

    ProcessHandle* proc_ = nullptr;
    Debugger* dbg_ = nullptr;
    uintptr_t targetAddress_ = 0;
    bool writesOnly_ = false;
    std::atomic<bool> running_{false};
    std::atomic<bool> stopRequested_{false};
    std::thread monitorThread_;
    Disassembler disasm_{Arch::X86_64};

    mutable std::mutex resultsMutex_;
    std::unordered_map<uintptr_t, CodeFinderResult> resultsMap_;
};

} // namespace ce
