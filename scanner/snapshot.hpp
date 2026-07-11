#pragma once
/// Process memory snapshot — capture every writable region's bytes, diff
/// against a later capture, optionally restore the original bytes.
///
/// Useful for "set a checkpoint, mess with the game, find every address that
/// changed" workflows and for one-shot bulk reverts. Region selection is
/// limited to writable user-space regions to keep snapshot size sane.

#include "platform/process_api.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ce {

struct SnapshotRegion {
    uint64_t base = 0;
    uint64_t size = 0;
    uint32_t protection = 0;   // bitfield of ce::MemProt
    std::vector<uint8_t> bytes;
};

class Snapshot {
public:
    /// Capture every writable region of `proc`. Optional `maxBytes` caps the
    /// total snapshot size by skipping regions once the budget runs out
    /// (returned in the order /proc/PID/maps lists them).
    static Snapshot capture(ProcessHandle& proc, uint64_t maxBytes = ~0ULL);

    /// Number of regions captured.
    size_t regionCount() const { return regions_.size(); }

    /// Total captured bytes.
    uint64_t byteCount() const;

    /// Walk regions; useful for inspection or custom diff.
    const std::vector<SnapshotRegion>& regions() const { return regions_; }

    /// Compare against another snapshot; produces a sorted list of
    /// (address, oldByte, newByte) tuples for every differing byte. Only
    /// regions present in both snapshots at the same base+size are compared.
    struct ByteDiff { uint64_t address; uint8_t before; uint8_t after; };
    std::vector<ByteDiff> diff(const Snapshot& later) const;

    /// Write the snapshot's bytes back into the process. Returns the number
    /// of bytes actually written (some pages may be unmapped / read-only).
    uint64_t restore(ProcessHandle& proc) const;

    /// Serialise to a binary file. Format: magic "CESNAP01" + uint32 region
    /// count + per-region {uint64 base, uint64 size, uint32 protection,
    /// bytes...}.
    bool save(const std::string& path) const;
    bool load(const std::string& path, std::string* error = nullptr);

private:
    std::vector<SnapshotRegion> regions_;
};

} // namespace ce
