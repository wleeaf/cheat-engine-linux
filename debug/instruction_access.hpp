#pragma once
/// "Find out what addresses this instruction accesses" — monitor a single
/// instruction and tally the distinct data addresses its memory operand touches
/// (the complement of find-what-accesses-an-address). Built on DebugSession +
/// the disassembler's computeEffectiveAddress.

#include "platform/process_api.hpp"
#include "core/types.hpp"
#include <cstdint>
#include <vector>

namespace ce {

struct InstructionAccess {
    uintptr_t  address = 0;     // data address the instruction touched
    int        hitCount = 0;
    CpuContext firstContext{};  // registers the first time this address was seen
};

/// Plant an execute breakpoint at `instructionAddress` and, each time it is about
/// to run, resolve the effective address of its first memory operand from the
/// live registers and tally it. Runs until `maxHits` accesses are recorded or
/// `timeoutMs` elapses, then detaches. Results are sorted by hit count (desc).
/// Returns empty if the instruction has no memory operand or attach fails.
std::vector<InstructionAccess> findInstructionAccesses(
    ProcessHandle& proc, uintptr_t instructionAddress,
    int maxHits = 32, int timeoutMs = 4000);

} // namespace ce
