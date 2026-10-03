#pragma once
/// Generate a ready-to-edit auto-assembler injection script by reading and
/// disassembling a target's code at an address. Shared by the memory browser
/// (right-click an instruction) and the script editor.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include "core/aa_templates.hpp"

namespace ce {
class ProcessHandle;
struct ModuleInfo;

/// Build a code-injection (aob=false) or AOB-injection (aob=true) AA script for
/// `address`: reads a window of code, steals whole instructions covering at least
/// the 5-byte jmp, relocates them into the cave, and captures the original bytes
/// for the [DISABLE] restore. Returns the script, or "" with `error` set.
std::string generateInjectionScript(ProcessHandle& proc, uintptr_t address,
                                    bool aob, std::string& error, size_t minimumOverwrite = 5);

std::string generateInjectionScript(ProcessHandle& proc, uintptr_t address,
                                    InjectionKind kind, std::string& error,
                                    const std::string& pointerRegister = "", size_t minimumOverwrite = 5);

/// Shortest signature length (bytes starting at `targetOffset`) whose byte pattern
/// occurs exactly once in `mod`, searched in [minLen, maxLen]. This is the core of
/// CE's "make the AOB unique" step: a signature that matches only the hook site
/// survives module rebases. Returns 0 if no unique signature exists.
std::size_t shortestUniqueAobLen(const std::vector<std::uint8_t>& mod,
                                 std::size_t targetOffset,
                                 std::size_t minLen, std::size_t maxLen);

/// Read module `m` and return a space-separated hex AOB for `address` that is unique
/// within the module (at least `minLen` bytes, extended up to `maxLen`). Returns ""
/// if no unique signature can be verified in readable module memory.
std::string uniqueAobSignature(ProcessHandle& proc, const ModuleInfo& m,
                               uintptr_t address, std::size_t minLen, std::size_t maxLen);

} // namespace ce
