#pragma once
/// createSimpleHook / removeSimpleHook: a jmp-detour code hook, the safe way.
///
/// installSimpleHook redirects execution at `address` to `target`. The displaced
/// original instructions are relocated into an allocated codecave followed by a
/// jmp back, so the target's code can run the original and continue (via the
/// returned `trampoline`). It REFUSES (returns nullopt, patches nothing) when the
/// displaced region contains position-dependent instructions we don't relocate
/// (relative branches, RIP-relative operands) — a wrong hook crashes the target,
/// so we'd rather not hook than hook incorrectly.

#include "platform/process_api.hpp"
#include <cstdint>
#include <optional>
#include <vector>

namespace ce {

struct SimpleHook {
    uintptr_t address = 0;              // hooked address
    uintptr_t trampoline = 0;           // relocated original + jmp back (jump here to resume)
    uintptr_t codecave = 0;             // base of the allocated gate+trampoline block
    std::vector<uint8_t> original;      // original bytes at `address` (for removal)
    size_t patchLen = 0;
};

/// Install a detour at `address` -> `target`. Returns the hook (for removal) or
/// nullopt on refusal/failure (nothing is patched on failure).
std::optional<SimpleHook> installSimpleHook(ProcessHandle& proc, uintptr_t address,
                                            uintptr_t target);

/// Restore the original bytes at the hooked address. The codecave is intentionally
/// NOT freed (the target may still be mid-trampoline). Returns false if the write
/// fails.
bool removeSimpleHook(ProcessHandle& proc, const SimpleHook& hook);

} // namespace ce
