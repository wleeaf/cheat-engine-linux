#pragma once
/// Pointer scanner — finds stable pointer chains to dynamic addresses.

#include "platform/process_api.hpp"
#include <vector>
#include <string>
#include <atomic>
#include <cstddef>
#include <optional>

namespace ce {

/// A pointer path: module+baseOffset → [offset1] → [offset2] → ... → target
struct PointerPath {
    std::string module;         // Module name (e.g., "game")
    uintptr_t   moduleBase;     // Module base address (for display)
    uintptr_t   baseOffset;     // Offset from module base
    std::vector<int32_t> offsets; // Dereference offsets at each level

    /// Human-readable string: [[game.exe+0x100]+0x20]+0x8
    std::string toString() const;
};

struct PointerScanConfig {
    uintptr_t targetAddress = 0;
    int       maxDepth = 4;         // Max levels of indirection (2-7)
    int       maxOffset = 2048;     // Max offset from pointer to target
    bool      negativeOffsets = false;
    bool      alignedOnly = true;   // 8-byte aligned pointers only
    bool      staticOnly = true;    // Only save paths ending at static (module) addresses
    size_t    shardIndex = 0;       // Worker shard for distributed scans
    size_t    shardCount = 1;       // Total distributed workers
    bool      useGpu = false;       // Offload per-region candidate filter to CUDA when available
    size_t    gpuMinRegionBytes = 1u << 20;  // Skip GPU for regions below this size (transfer overhead)
    // Stop after this many paths. Paths come shortest first, so a scan that stops
    // early misses the deeper ones; truncated() says so, and a smaller maxOffset
    // usually brings them back.
    size_t    maxResults = 100000;
    // Stop the path search after examining this many candidate pointers in all.
    // Their number grows as fanout^depth in a dense heap, so a large maxOffset
    // and depth would otherwise run for hours. truncated() reports it.
    uint64_t  maxVisits = uint64_t(1) << 32;
    // Stop reading memory once the map holds this many pointer-like values
    // (16 bytes each, plus a 4-byte index). truncated() reports it.
    size_t    maxMapEntries = size_t(1) << 28;
};

/// The largest depth and offset the front ends (cescan, Lua) accept. The work
/// grows as fanout^depth, so deeper scans rarely finish.
inline constexpr int kPointerScanMaxDepth = 7;
inline constexpr int kPointerScanMaxOffset = 1 << 20;

/// Which limit cut a pointer scan short.
enum class PointerScanLimit {
    None,
    Results,      // config.maxResults paths were found
    Work,         // config.maxVisits candidates were examined
    MapEntries,   // memory held more than config.maxMapEntries pointer-like values
};

/// Build one config per worker. Merged results are equivalent to a full scan.
std::vector<PointerScanConfig> makePointerScanShards(const PointerScanConfig& base, size_t shardCount);

/// A reusable snapshot of a process's pointer graph: every pointer-shaped value
/// found in readable memory, indexed both by target (for a scan's reverse search)
/// and by location (for resolving a saved path without touching the process).
/// Building it is the expensive half of a pointer scan; reuse lets you scan
/// several targets, or re-resolve a whole saved path set after a game restart,
/// without re-reading memory.
class PointerMap {
public:
    struct Entry {
        uintptr_t pointsTo;    // pointer value (target)
        uintptr_t locatedAt;   // address that holds it
    };

    bool   empty() const { return byTarget_.empty(); }
    size_t size()  const { return byTarget_.size(); }
    /// buildPointerMap stopped at config.maxMapEntries, so some pointers are
    /// missing. Not saved with the map.
    bool   truncated() const { return truncated_; }
    void   setTruncated(bool truncated) { truncated_ = truncated; }
    const std::vector<Entry>&      entriesByTarget() const { return byTarget_; }  // sorted by pointsTo
    const std::vector<ModuleInfo>& modules() const { return modules_; }

    /// The pointer value stored at `addr` in the snapshot, or nullopt if `addr`
    /// held no recorded pointer-shaped value.
    std::optional<uintptr_t> valueAt(uintptr_t addr) const;

    /// Resolve a path to its final target address using ONLY the snapshot (no
    /// process reads). Returns 0 if the module is missing or a link is absent
    /// from the map. For scanner-produced paths every intermediate address is a
    /// recorded aligned slot, so this equals PointerScanner::dereference against
    /// the same process state; a manually-entered path whose intermediate lands
    /// off a recorded slot resolves to 0 (use dereference for those).
    uintptr_t resolve(const PointerPath& path) const;

    /// Persist / restore the snapshot ("PMAP0001" + entries + modules). load()
    /// sets *error and returns an empty map on failure.
    bool save(const std::string& path) const;
    static PointerMap load(const std::string& path, std::string* error = nullptr);

    /// Populate the map (used by buildPointerMap and load). setEntries sorts the
    /// entries by target and rebuilds the by-location index.
    void setEntries(std::vector<Entry> entries);
    void setModules(std::vector<ModuleInfo> modules) { modules_ = std::move(modules); }

private:
    std::vector<Entry>       byTarget_;    // sorted by pointsTo
    std::vector<uint32_t>    byLocated_;   // indices into byTarget_, sorted by locatedAt
    std::vector<ModuleInfo>  modules_;
    bool                     truncated_ = false;
    uintptr_t moduleBase(const std::string& name) const;
};

/// Build a PointerMap from a live process (the expensive read phase). Honors
/// alignedOnly / useGpu / gpuMinRegionBytes / maxMapEntries from `config`. A
/// value counts as a pointer when it points into readable memory. Each region
/// is read with the pointer width and byte order that dereference() uses at its
/// address. `cancel`, if set and flipped true, aborts and yields an empty map.
/// `progress`, if set, is driven from 0.0 to `progressSpan` across the read.
PointerMap buildPointerMap(ProcessHandle& proc, const PointerScanConfig& config,
                           std::atomic<bool>* cancel = nullptr,
                           std::atomic<float>* progress = nullptr,
                           float progressSpan = 0.5f);

class PointerScanner {
public:
    PointerScanner() = default;

    /// Run a pointer scan. Returns all found paths, shortest first. A module
    /// whose name an earlier module already has (WoW64's two ntdll.dll, a library
    /// loaded twice) is not used as a static base: a path names its module, and
    /// the name resolves to the first one. Its slots count as plain memory.
    std::vector<PointerPath> scan(ProcessHandle& proc, const PointerScanConfig& config);

    /// Scan using a prebuilt PointerMap, skipping the memory-read phase. Lets you
    /// scan several targets against one map. Equivalent to scan() for the same
    /// process state (same config target/depth/offset/shard settings).
    std::vector<PointerPath> scanWithMap(const PointerMap& map, const PointerScanConfig& config);

    /// Dereference a pointer path in the target process.
    /// Returns the final address, or 0 if any dereference fails.
    static uintptr_t dereference(ProcessHandle& proc, const PointerPath& path);

    /// Dereference using a pre-fetched module list (avoids re-reading /proc maps
    /// per call). Used by the rescan loops so a large path set parses modules once.
    static uintptr_t dereference(ProcessHandle& proc, const std::vector<ModuleInfo>& modules,
                                 const PointerPath& path);

    /// Progress (0.0 - 1.0)
    float progress() const { return progress_.load(std::memory_order_relaxed); }

    /// Stop the scan in progress, or the next one if it has not started yet.
    /// A cancel stays in effect; use a new scanner for another scan.
    void cancel() { cancelled_.store(true); }
    bool wasCancelled() const { return cancelled_.load(); }

    /// The last scan stopped at a limit (see limitReached()), so paths may be
    /// missing.
    bool truncated() const { return limit_.load() != 0; }
    /// Whether the last scan hit this limit. A scan can hit two: the map
    /// entry limit while reading memory, then a path or work limit.
    bool limitHit(PointerScanLimit limit) const { return (limit_.load() & limitBit(limit)) != 0; }
    /// The limit that stopped the search (Results or Work), else MapEntries
    /// when only the map was cut, else None. mapTruncated() tells whether the
    /// map was also cut when a search limit is returned.
    PointerScanLimit limitReached() const {
        for (auto limit : {PointerScanLimit::Results, PointerScanLimit::Work, PointerScanLimit::MapEntries})
            if (limitHit(limit)) return limit;
        return PointerScanLimit::None;
    }
    bool mapTruncated() const { return limitHit(PointerScanLimit::MapEntries); }

private:
    static int limitBit(PointerScanLimit limit) { return limit == PointerScanLimit::None ? 0 : 1 << static_cast<int>(limit); }
    void reachLimit(PointerScanLimit limit) { limit_.fetch_or(limitBit(limit)); }
    std::atomic<float> progress_{0};
    std::atomic<bool> cancelled_{false};
    std::atomic<int> limit_{0};   // limitBit() of each limit hit
};

// ── Result-set persistence and post-processing ──

/// Save a path list to a binary file. File format:
///   magic[8] "PSCAN001" + uint32 version=1 + uint32 count + records.
/// Each record: { uint64 moduleBase, uint64 baseOffset, uint32 offsetCount,
///                uint32 moduleNameLen, moduleName bytes, offsetCount * int32 offsets }.
bool savePointerPaths(const std::string& path, const std::vector<PointerPath>& paths);

/// Load a saved path list. Returns empty vector + sets `error` on failure.
std::vector<PointerPath> loadPointerPaths(const std::string& path, std::string* error = nullptr);

/// Walk every path against a (possibly different) target address; keep only
/// those whose dereference resolves to `newTarget`. Useful when a game restarts
/// and the target's runtime address changes — same module-relative chain may
/// still work, others won't. `cancel`, if set and flipped true, stops the walk
/// and returns an empty list; `progress`, if set, goes from 0.0 to 1.0.
std::vector<PointerPath>
rescanPointerPaths(ProcessHandle& proc, const std::vector<PointerPath>& paths, uintptr_t newTarget,
                   std::atomic<bool>* cancel = nullptr, std::atomic<float>* progress = nullptr);

/// Like rescanPointerPaths, but filter by the VALUE the chain points to rather
/// than a known new address. Keeps paths whose final dereferenced address holds
/// `expectedValue` (`valueSize` bytes, 1-8). This is the canonical game-restart
/// workflow: after a restart the target's address changes, but you still know
/// its value, so re-narrow the saved paths by value.
std::vector<PointerPath>
rescanPointerPathsByValue(ProcessHandle& proc, const std::vector<PointerPath>& paths,
                          uint64_t expectedValue, size_t valueSize);

/// Rescan against a prebuilt PointerMap of the CURRENT process state: keep paths
/// whose in-map resolution equals `newTarget`. No process reads, so re-narrowing
/// a large saved set across a game restart is instant once the map is built (one
/// linear memory pass) instead of a dereference syscall chain per path.
std::vector<PointerPath>
rescanPointerPathsWithMap(const PointerMap& map, const std::vector<PointerPath>& paths,
                          uintptr_t newTarget);

/// Map-based rescan by value: resolve each path via the map, then read the value
/// at the surviving target addresses in one batched pass (readMany) and keep the
/// ones equal to `expectedValue`. The value itself is not in the map, so this
/// still reads the target bytes, but skips the per-level chain syscalls.
std::vector<PointerPath>
rescanPointerPathsByValueWithMap(ProcessHandle& proc, const PointerMap& map,
                                 const std::vector<PointerPath>& paths,
                                 uint64_t expectedValue, size_t valueSize);

enum class PointerSortKey {
    Depth,        // shorter chains first
    BaseOffset,   // smaller module-relative base first
    OffsetSum,    // smallest sum of dereference offsets first
    Module,       // grouped by module name (lex)
};

/// In-place sort.
void sortPointerPaths(std::vector<PointerPath>& paths, PointerSortKey key);

/// Concatenate two result sets. With `deduplicate`, paths that share the same
/// module/baseOffset/offsets are kept only once (preserving order from `a`).
std::vector<PointerPath>
mergePointerPaths(const std::vector<PointerPath>& a, const std::vector<PointerPath>& b,
                  bool deduplicate = true);

} // namespace ce
