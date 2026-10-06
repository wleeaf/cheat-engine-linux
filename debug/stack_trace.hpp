#pragma once
/// Frame-chain stack traces for stopped x86/i386/x32 and AArch64 threads.

#include "platform/process_api.hpp"
#include "symbols/elf_symbols.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace ce {

struct StackFrame {
    size_t index = 0;
    uintptr_t instructionPointer = 0;
    uintptr_t stackPointer = 0;
    uintptr_t framePointer = 0;
    uintptr_t returnAddress = 0;
    std::string symbol;
};

std::vector<StackFrame> buildStackTrace(ProcessHandle& proc,
    const CpuContext& context,
    size_t maxFrames = 64,
    const SymbolResolver* symbols = nullptr);

} // namespace ce
