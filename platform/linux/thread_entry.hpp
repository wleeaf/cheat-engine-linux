#pragma once

#include "core/target_machine.hpp"
#include <expected>
#include <system_error>
#include <vector>

namespace ce::os {

// Each control field has the target's pointer width and data byte order.
enum class NativeThreadField : size_t {
    Tid, Start, Done, Exit, Function, Argument, Value, ReturnPc, Stack, PollNanoseconds, Count
};

struct NativeThreadEntry {
    std::vector<uint8_t> code;
    unsigned wordSize=0;
    size_t publishedOffset=0,returnOffset=0;
    size_t suspendedStackBytes=0;
    unsigned returnInstructions=0;
    size_t dataSize() const { return wordSize*static_cast<size_t>(NativeThreadField::Count); }
    size_t offset(NativeThreadField field) const { return wordSize*static_cast<size_t>(field); }
};

// Called by a real native pthread with its control pointer as the argument.
// Publishes its Linux TID and waits until its owner sets Start=1 (execute) or
// Start=2 (cancel before execution). After the function returns, publishes Done
// and waits for Exit before performing an ordinary, ABI-correct return.
// Done alone does not permit unmapping: the return path still uses this code.
// Its polling interval is provided in the control block, avoiding a busy loop.
std::expected<NativeThreadEntry,std::error_code> nativeThreadEntry(const TargetMachine&);
std::expected<std::vector<uint8_t>,std::error_code> nativeThreadControl(
    const TargetMachine&,uintptr_t function,uintptr_t argument=0,uint64_t pollNanoseconds=1000000);

} // namespace ce::os
