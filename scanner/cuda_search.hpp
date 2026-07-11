#pragma once
/// GPU-accelerated byte-buffer scan for 64-bit pointer values.
///
/// One of the pointer-scan inner loops: given a flat dump of every
/// writable memory region in the target, find every 8-byte-aligned
/// position whose value falls in a target range. On a big game (4+ GB
/// committed) this is the hottest part of pointer-scan; GPU offload
/// helps when the data fits in VRAM.
///
/// Gated behind CECORE_HAVE_CUDA. When the CUDA toolkit isn't found at
/// configure time, every call cleanly reports `available() == false` and
/// search() returns an empty result — callers should fall back to the
/// CPU path (PointerScanner::scan).

#include <cstdint>
#include <cstddef>
#include <vector>

namespace ce {

class CudaSearch {
public:
    CudaSearch() = default;
    ~CudaSearch();

    /// Cheap probe — is the build's CUDA path compiled in AND is a CUDA-
    /// capable device usable from the current process?
    static bool available();

    /// Scan `data` (size bytes) for every 8-byte-aligned uint64 that
    /// satisfies `target_low <= value <= target_high`. Returns the byte
    /// offsets of the matching slots. `data` doesn't need to be 8-aligned.
    std::vector<size_t> searchU64Range(
        const uint8_t* data, size_t size,
        uint64_t targetLow, uint64_t targetHigh);
};

} // namespace ce
