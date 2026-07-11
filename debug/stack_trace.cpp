#include "debug/stack_trace.hpp"

#include <limits>

namespace ce {

namespace {

constexpr uintptr_t kMaxFrameSpan = 1024 * 1024;

bool addWouldOverflow(uintptr_t value, size_t amount) {
    return value > std::numeric_limits<uintptr_t>::max() - amount;
}

bool isReadable(ProcessHandle& proc, uintptr_t address, size_t size) {
    if (size == 0 || addWouldOverflow(address, size - 1)) return false;

    auto region = proc.queryRegion(address);
    if (!region || !(region->protection & MemProt::Read)) return false;
    if (addWouldOverflow(region->base, region->size)) return false;

    const uintptr_t end = address + size;
    if (end < address) return false;
    return end <= region->base + region->size;
}

bool readPointer(ProcessHandle& proc, uintptr_t address, uintptr_t& value) {
    auto read = proc.read(address, &value, sizeof(value));
    return read && *read == sizeof(value);
}

bool isPlausibleNextFrame(uintptr_t currentRbp, uintptr_t nextRbp) {
    if (nextRbp == 0) return false;
    if (nextRbp <= currentRbp) return false;
    if ((nextRbp % sizeof(uintptr_t)) != 0) return false;
    return nextRbp - currentRbp <= kMaxFrameSpan;
}

std::string resolveSymbol(const SymbolResolver* symbols, uintptr_t address) {
    if (!symbols || address == 0) return {};
    return symbols->resolve(address);
}

} // namespace

std::vector<StackFrame> buildStackTrace(ProcessHandle& proc,
    const CpuContext& context,
    size_t maxFrames,
    const SymbolResolver* symbols)
{
    std::vector<StackFrame> frames;
    if (maxFrames == 0) return frames;

    frames.push_back(StackFrame{
        .index = 0,
        .instructionPointer = context.rip,
        .stackPointer = context.rsp,
        .framePointer = context.rbp,
        .returnAddress = 0,
        .symbol = resolveSymbol(symbols, context.rip),
    });

    uintptr_t rbp = context.rbp;
    for (size_t index = 1; index < maxFrames; ++index) {
        if (rbp == 0 || addWouldOverflow(rbp, sizeof(uintptr_t) * 2)) break;
        if (!isReadable(proc, rbp, sizeof(uintptr_t) * 2)) break;

        uintptr_t nextRbp = 0;
        uintptr_t returnAddress = 0;
        if (!readPointer(proc, rbp, nextRbp)) break;
        if (!readPointer(proc, rbp + sizeof(uintptr_t), returnAddress)) break;
        if (returnAddress == 0) break;

        frames.push_back(StackFrame{
            .index = index,
            .instructionPointer = returnAddress,
            .stackPointer = rbp + sizeof(uintptr_t) * 2,
            .framePointer = rbp,
            .returnAddress = returnAddress,
            .symbol = resolveSymbol(symbols, returnAddress),
        });

        if (!isPlausibleNextFrame(rbp, nextRbp)) break;
        rbp = nextRbp;
    }

    return frames;
}

} // namespace ce
