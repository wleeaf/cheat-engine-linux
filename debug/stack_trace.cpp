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

bool readPointer(ProcessHandle& proc, uintptr_t address, uintptr_t& value, size_t width, ByteOrder order) {
    std::array<uint8_t,8> bytes{};
    auto read = proc.read(address, bytes.data(), width);
    if (!read || *read != width) return false;
    auto decoded = decodeTargetUnsigned({bytes.data(),width},order);
    if (!decoded || *decoded > std::numeric_limits<uintptr_t>::max()) return false;
    value = static_cast<uintptr_t>(*decoded);
    return true;
}

bool isPlausibleNextFrame(uintptr_t currentRbp, uintptr_t nextRbp, size_t width) {
    if (nextRbp == 0) return false;
    if (nextRbp <= currentRbp) return false;
    if ((nextRbp % width) != 0) return false;
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
        .instructionPointer = context.instructionPointer(),
        .stackPointer = context.stackPointer(),
        .framePointer = context.framePointer(),
        .returnAddress = 0,
        .symbol = resolveSymbol(symbols, context.instructionPointer()),
    });

    uintptr_t rbp = context.framePointer();
    auto machine=proc.machineAt(context.instructionPointer());
    auto architecture=context.architecture==CpuArchitecture::Unknown ? machine.architecture : context.architecture;
    // A frame record stores saved registers. x32 still pushes 64-bit RBP/RIP
    // even though its data pointers are 32-bit; AArch64 saves X29/LR as 64-bit.
    const size_t width=architecture==CpuArchitecture::X86_32 ? 4 :
        architecture==CpuArchitecture::X86_64 || architecture==CpuArchitecture::Arm64 ? 8 : 0;
    if (!width || machine.byteOrder==ByteOrder::Unknown) return frames;
    for (size_t index = 1; index < maxFrames; ++index) {
        if (rbp == 0 || addWouldOverflow(rbp, width * 2)) break;
        if (!isReadable(proc, rbp, width * 2)) break;

        uintptr_t nextRbp = 0;
        uintptr_t returnAddress = 0;
        if (!readPointer(proc, rbp, nextRbp, width, machine.byteOrder)) break;
        if (!readPointer(proc, rbp + width, returnAddress, width, machine.byteOrder)) break;
        if (returnAddress == 0) break;

        frames.push_back(StackFrame{
            .index = index,
            .instructionPointer = returnAddress,
            .stackPointer = rbp + width * 2,
            .framePointer = rbp,
            .returnAddress = returnAddress,
            .symbol = resolveSymbol(symbols, returnAddress),
        });

        if (!isPlausibleNextFrame(rbp, nextRbp, width)) break;
        rbp = nextRbp;
    }

    return frames;
}

} // namespace ce
