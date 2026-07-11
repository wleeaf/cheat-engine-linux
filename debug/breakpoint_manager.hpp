#pragma once
/// Breakpoint manager — central tracking of all breakpoints with actions and conditions.

#include "core/types.hpp"
#include "platform/process_api.hpp"
#include <string>
#include <vector>
#include <functional>
#include <mutex>
#include <atomic>
#include <unordered_map>

namespace ce {

enum class BpType { Execute, Write, Read, Access };
enum class BpAction { Break, FindCode, FindAccess, Trace, OnBreakpoint };
enum class BpMethod { Hardware, Software };

struct Breakpoint {
    int id = 0;
    uintptr_t address = 0;
    BpType type = BpType::Execute;
    BpAction action = BpAction::Break;
    BpMethod method = BpMethod::Hardware;
    int hwRegister = -1;        // DR0-DR3 (-1 = auto-assign)
    int size = 1;               // 1, 2, 4, 8 bytes (for data breakpoints)
    bool enabled = true;
    bool oneShot = false;       // Auto-remove after first hit
    pid_t threadFilter = 0;     // 0 = all threads
    std::string condition;      // Lua expression (empty = unconditional)
    std::string description;
    int hitCount = 0;
};

struct BreakpointHit {
    int bpId;
    uintptr_t address;          // Breakpoint address
    uintptr_t rip;              // Instruction that triggered it
    pid_t tid;
    CpuContext context;
    std::vector<uint8_t> instructionBytes;
    std::string instructionText;
};

class BreakpointManager {
public:
    BreakpointManager() = default;

    /// Add a breakpoint. Returns its ID.
    int add(const Breakpoint& bp);

    /// Remove a breakpoint by ID.
    void remove(int id);

    /// Enable/disable.
    void setEnabled(int id, bool enabled);

    /// Get all breakpoints.
    std::vector<Breakpoint> list() const;

    /// Get a specific breakpoint.
    const Breakpoint* get(int id) const;

    /// Find the next available hardware register (0-3).
    int findFreeHwRegister() const;

    /// Apply all enabled hardware breakpoints to a thread.
    bool applyToThread(Debugger& dbg, pid_t tid);

    /// Remove all hardware breakpoints from a thread.
    bool removeFromThread(Debugger& dbg, pid_t tid);

    /// Record a hit. Returns true when the hit should be delivered to the user.
    bool recordHit(int id, const BreakpointHit& hit);

    /// Get hit log for a breakpoint.
    std::vector<BreakpointHit> getHits(int id) const;

    /// Clear hit log.
    void clearHits(int id);

    /// Set callback for when a breakpoint is hit.
    using HitCallback = std::function<void(const Breakpoint&, const BreakpointHit&)>;
    void setHitCallback(HitCallback cb) { hitCallback_ = std::move(cb); }

private:
    mutable std::mutex mutex_;
    std::vector<Breakpoint> breakpoints_;
    std::unordered_map<int, std::vector<BreakpointHit>> hitLog_;
    int nextId_ = 1;
    HitCallback hitCallback_;
};

} // namespace ce
