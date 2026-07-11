#pragma once
/// Generate a ready-to-edit auto-assembler injection script by reading and
/// disassembling a target's code at an address. Shared by the memory browser
/// (right-click an instruction) and the script editor.

#include <cstdint>
#include <string>

namespace ce {
class ProcessHandle;

/// Build a code-injection (aob=false) or AOB-injection (aob=true) AA script for
/// `address`: reads a window of code, steals whole instructions covering at least
/// the 5-byte jmp, relocates them into the cave, and captures the original bytes
/// for the [DISABLE] restore. Returns the script, or "" with `error` set.
std::string generateInjectionScript(ProcessHandle& proc, uintptr_t address,
                                    bool aob, std::string& error);

} // namespace ce
