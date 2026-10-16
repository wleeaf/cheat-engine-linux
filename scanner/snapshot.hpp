#pragma once
/// Process memory snapshot — capture every writable region's bytes, diff
/// against a later capture, optionally restore the original bytes.
///
/// Useful for "set a checkpoint, mess with the game, find every address that
/// changed" workflows and for one-shot bulk reverts. Region selection is
/// limited to writable user-space regions to keep snapshot size sane.

#include "platform/process_api.hpp"

#include <cstddef>
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
    /// (returned in the order /proc/PID/maps lists them); truncated() then
    /// reports that writable memory was left out.
    static Snapshot capture(ProcessHandle& proc, uint64_t maxBytes = ~0ULL);

    /// The current bytes of the ranges this snapshot holds, limited to what is
    /// still mapped writable. Its size never exceeds this snapshot's, so a diff
    /// against the live process costs no more memory than the baseline.
    Snapshot recapture(ProcessHandle& proc) const;

    /// Whether capture() stopped at its byte budget.
    bool truncated() const { return truncated_; }

    /// Number of regions captured.
    size_t regionCount() const { return regions_.size(); }

    /// Total captured bytes.
    uint64_t byteCount() const;

    /// Walk regions; useful for inspection or custom diff.
    const std::vector<SnapshotRegion>& regions() const { return regions_; }

    /// Compare against another snapshot; produces a sorted list of
    /// (address, oldByte, newByte) tuples for differing bytes. Regions are
    /// matched by address overlap, so a region that grew, shrank or merged
    /// with a neighbour is still compared over the range both hold. At most
    /// `maxDiffs` entries are returned (the lowest addresses); `changedBytes`,
    /// when given, receives the count of every differing byte.
    struct ByteDiff { uint64_t address; uint8_t before; uint8_t after; };
    std::vector<ByteDiff> diff(const Snapshot& later, size_t maxDiffs = SIZE_MAX,
                               uint64_t* changedBytes = nullptr) const;

    /// Write the snapshot's bytes back into the process, but only where the
    /// process currently has a writable, non-executable mapping: a loaded or
    /// stale snapshot may name ranges that were since unmapped, remapped or
    /// turned into code, and those are skipped. Returns the bytes written.
    uint64_t restore(ProcessHandle& proc) const;

    /// Serialise to a binary file. Format: magic "CESNAP01" + uint32 region
    /// count + per-region {uint64 base, uint64 size, uint32 protection,
    /// bytes...}.
    bool save(const std::string& path) const;
    bool load(const std::string& path, std::string* error = nullptr);

private:
    std::vector<SnapshotRegion> regions_;
    bool truncated_ = false;
};

} // namespace ce
