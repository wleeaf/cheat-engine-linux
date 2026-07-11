#pragma once
/// Stack trace helpers for stopped x86_64 Linux threads.

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
