#pragma once
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace ce {
struct Aarch64RelocationOptions {
    // The caller explicitly permits this X register to be clobbered by far
    // vector/zero-register literal loads, prefetches and branch veneers.
    std::optional<unsigned> scratchRegister;
    // Indirect veneers require compatible BTI landing sites. Leave disabled
    // when the caller cannot establish the target's branch-protection policy.
    bool allowIndirectBranches=false;
};
struct Aarch64RelocatedCode {
    std::vector<uint8_t> bytes;
    std::vector<size_t> instructionOffsets;
};

// Relocate whole LE-encoded A64 instructions. Static branches into the source
// block follow the corresponding relocated instruction; ADR/ADRP and literal
// addresses retain their original absolute values. Literal memory is not copied
// or cached. The caller owns code writes, cache synchronization and continuation.
// PC-relative slots reserve their maximum size so layout is deterministic even
// when a branch/literal can retain a shorter encoding. Call return PCs therefore
// refer to the relocated block. Other copied instructions retain their bytes.
std::expected<Aarch64RelocatedCode,std::string> relocateAarch64(
    std::span<const uint8_t> code,uint64_t source,uint64_t destination,
    const Aarch64RelocationOptions& options={});
}
