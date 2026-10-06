#pragma once
#include "core/target_machine.hpp"

namespace ce::test {

// The byte buffers in backend regression tests deliberately model x86 code.
inline TargetDescription x86Target(bool wide, bool code32) {
    TargetDescription d;
    d.host = wide
        ? TargetMachine{CpuArchitecture::X86_64, ByteOrder::Little, TargetAbi::LinuxX86_64, InstructionMode::X86_64, 8, ByteOrder::Little}
        : TargetMachine{CpuArchitecture::X86_32, ByteOrder::Little, TargetAbi::LinuxI386, InstructionMode::X86_32, 4, ByteOrder::Little};
    d.program = code32
        ? TargetMachine{CpuArchitecture::X86_32, ByteOrder::Little, TargetAbi::WindowsI386, InstructionMode::X86_32, 4, ByteOrder::Little}
        : d.host;
    d.transport = TargetTransport::Local;
    d.runtime = wide && code32 ? TargetRuntime::Wine : TargetRuntime::Native;
    d.mixedCode = d.host != d.program;
    return d;
}

} // namespace ce::test
