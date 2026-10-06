#pragma once
/// "Find what accesses/writes this address" — logs all instructions that touch an address.

#include "debug/breakpoint_manager.hpp"
#include "platform/process_api.hpp"
#include "arch/disassembler.hpp"
#include "symbols/elf_symbols.hpp"
#include "platform/linux/target_syscall.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <thread>
#include <future>
#include <signal.h>

namespace ce {

class SymbolResolver;

struct CodeFinderResult {
    uintptr_t instructionAddress;
    std::string instructionText;
    std::vector<uint8_t> instructionBytes;
    uint64_t hitCount = 0;
    CpuContext firstContext{}; // Register state at the first time this instruction hit
    CpuContext lastContext{};  // Register state at the most recent hit
};

struct RecoveredInstruction {
    uintptr_t address = 0;
    std::string text;   // "mnemonic operands"
    bool ok = false;
};

/// An x86 hardware watchpoint traps AFTER the store retires, so `trapRip` (a hit's
/// firstContext.rip) points at the instruction FOLLOWING the writer. CodeFinder's
/// backward disassembly picks the longest decode ending at rip, which can land a few
/// bytes early on dense code and mis-decode. This recovers the exact store by
/// disassembling FORWARD from the enclosing function (located via the symbol resolver)
/// up to `trapRip` and returning the instruction that ends exactly there. It is not
/// needed for software page-guard hits (those already stop on the store). Returns
/// ok=false if it cannot be recovered (caller should keep the original instruction).
RecoveredInstruction recoverStoreInstruction(ProcessHandle& proc, SymbolResolver& resolver,
                                             uintptr_t trapRip, bool is64);

class CodeFinder {
public:
    CodeFinder() = default;
    ~CodeFinder() { stop(); }

    /// Start monitoring an address for reads (access) or writes only.
    /// Runs in a background thread. Call stop() to finish.
    // watchSize: bytes to watch (1/2/4/8), with native hardware alignment/range
    // validation. Default 4 (a dword).
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
    Error lastError() const { std::lock_guard lock(errorMutex_); return error_; }
    bool hasPendingRecovery() const { return recoveryPending_.load(); }

    /// The address being watched (for pointer-path hints in the UI).
    uintptr_t targetAddress() const { return targetAddress_; }

    /// True if the software page-guard backend is in use (its hits stop on the store,
    /// so exact-store recovery is unnecessary); false for a hardware watchpoint.
    bool softwareWatch() const { return software_; }

    /// Get accumulated results (grouped by instruction address, sorted by hit count).
    std::vector<CodeFinderResult> results() const;

    /// Clear results.
    void clearResults();

private:
    void monitorLoop();          // native hardware and page-guard event loop
    // x86 hardware stops after the instruction. ARM64 hardware and software page
    // faults stop before it. Decode using the instruction address's native ISA.
    bool recordHit(pid_t tid, bool afterInstruction);
    void setError(Error error) { std::lock_guard lock(errorMutex_); error_=error; }
    long setStoppedProtection(pid_t tid,uintptr_t scratch,uintptr_t address,size_t length,int protection,int& signal,
                              std::optional<siginfo_t>* signalInfo=nullptr);
    long runStoppedSyscall(pid_t tid,os::MemorySyscall operation,std::array<uint64_t,6> arguments,uintptr_t scratch,int& signal,
                           std::optional<siginfo_t>* signalInfo=nullptr);

    ProcessHandle* proc_ = nullptr;
    Debugger* dbg_ = nullptr;
    TargetMachine host_;
    uintptr_t targetAddress_ = 0;
    bool writesOnly_ = false;
    int  watchSize_ = 4;
    bool software_ = false;
    bool singleThread_ = false;
    std::atomic<bool> running_{false};
    std::atomic<bool> stopRequested_{false};
    std::thread monitorThread_;
    std::promise<bool> startup_;
    std::optional<Disassembler> disasm_;
    SymbolResolver symbols_;
    std::mutex lifecycleMutex_;
    mutable std::mutex errorMutex_;
    Error error_;
    std::atomic<bool> recoveryPending_{false};

    mutable std::mutex resultsMutex_;
    std::unordered_map<uintptr_t, CodeFinderResult> resultsMap_;
};

} // namespace ce
