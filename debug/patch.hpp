#pragma once
/// Small code-patch helpers for the debugger ("replace with code that does
/// nothing" and its undo), decoupled from any UI.

#include "platform/process_api.hpp"
#include <cstdint>
#include <vector>
#include <span>

namespace ce {

std::expected<std::vector<uint8_t>,std::string> nopBytesFor(
    ProcessHandle& proc,uintptr_t address,size_t size);
// Preserve/verify the original bytes and use the adapter's code-cache path.
std::expected<std::vector<uint8_t>,std::string> patchInstructionBytes(
    ProcessHandle& proc,uintptr_t address,std::span<const uint8_t> bytes);

/// Overwrite the single instruction at `address` with target NOPs, preserving
/// its exact byte length, and return the original bytes so the patch can be
/// reverted with restoreBytes. Returns empty if the instruction can't be read,
/// decoded, or written. Uses the instruction architecture at that address.
std::vector<uint8_t> nopInstruction(ProcessHandle& proc, uintptr_t address);

/// Write `original` back at `address` (revert a nopInstruction). Returns false
/// on empty input or a failed write.
bool restoreBytes(ProcessHandle& proc, uintptr_t address,
                  const std::vector<uint8_t>& original);

} // namespace ce
