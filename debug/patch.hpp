#pragma once
/// Small code-patch helpers for the debugger ("replace with code that does
/// nothing" and its undo), decoupled from any UI.

#include "platform/process_api.hpp"
#include <cstdint>
#include <vector>

namespace ce {

/// Overwrite the single instruction at `address` with NOPs (0x90), preserving
/// its exact byte length, and return the original bytes so the patch can be
/// reverted with restoreBytes. Returns empty if the instruction can't be read,
/// decoded, or written. Decodes as x86-64 (matches the debug layer).
std::vector<uint8_t> nopInstruction(ProcessHandle& proc, uintptr_t address);

/// Write `original` back at `address` (revert a nopInstruction). Returns false
/// on empty input or a failed write.
bool restoreBytes(ProcessHandle& proc, uintptr_t address,
                  const std::vector<uint8_t>& original);

} // namespace ce
