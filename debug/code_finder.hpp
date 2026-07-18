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
    // watchSize: bytes to watch (1/2/4/8) — must be watchSize-aligned like any
    // x86 hardware data breakpoint. Default 4 (a dword).
    // software: use a page-protection watchpoint (mprotect + SIGSEGV) instead of a
    // CPU hardware debug register. Never viable on Wine/Proton (its mprotect fights
    // Proton's kernel write-watch/userfaultfd and deadlocks the game); kept for
    // native Linux only.
    // singleThread: arm the hardware watchpoint on ONLY the process's main thread,
    // and do not trace any sibling thread. Seizing/stopping the whole Wine/Proton
    // thread group deadlocks the game (it collides with wineserver, esync/fsync and
    // GPU/driver threads), so on Wine we watch just the main game-logic thread,
    // which is where gameplay values (money, HP, …) are written.
    bool start(ProcessHandle& proc, Debugger& dbg, uintptr_t address,
               bool writesOnly = false, int watchSize = 4, bool software = false,
               bool singleThread = false);

    /// Stop monitoring.
    void stop();

    /// Is monitoring active?
    bool running() const { return running_.load(); }

    /// The address being watched (for pointer-path hints in the UI).
    uintptr_t targetAddress() const { return targetAddress_; }

    /// Get accumulated results (grouped by instruction address, sorted by hit count).
    std::vector<CodeFinderResult> results() const;

    /// Clear results.
    void clearResults();

private:
    void monitorLoop();          // hardware debug-register watchpoint
    void monitorLoopSoftware();  // page-protection (mprotect + SIGSEGV) watchpoint
    // Record the instruction that touched the address. afterInstruction=true (a
    // hardware watchpoint traps once the store has retired, so rip is past it) backs
    // up to the previous instruction; false (a software page fault stops on the
    // faulting store itself) uses rip directly.
    void recordHit(pid_t tid, bool afterInstruction);

    ProcessHandle* proc_ = nullptr;
    Debugger* dbg_ = nullptr;
    uintptr_t targetAddress_ = 0;
    bool writesOnly_ = false;
    int  watchSize_ = 4;
    bool software_ = false;
    bool singleThread_ = false;
    std::atomic<bool> running_{false};
    std::atomic<bool> stopRequested_{false};
    std::thread monitorThread_;
    Disassembler disasm_{Arch::X86_64};

    mutable std::mutex resultsMutex_;
    std::unordered_map<uintptr_t, CodeFinderResult> resultsMap_;
};

} // namespace ce
