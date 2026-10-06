#include "platform/linux/thread_entry.hpp"

namespace ce::os {
std::expected<NativeThreadEntry,std::error_code> nativeThreadEntry(const TargetMachine& machine) {
    if (machine.byteOrder!=ByteOrder::Little || machine.instructionByteOrder!=ByteOrder::Little)
        return std::unexpected(std::make_error_code(std::errc::not_supported));
    if (machine.architecture==CpuArchitecture::X86_64 && machine.abi==TargetAbi::LinuxX86_64 && machine.pointerWidth==8)
        return
#include "platform/linux/thread_entry/x86_64.inc"
        ;
    if (machine.architecture==CpuArchitecture::X86_64 && machine.abi==TargetAbi::LinuxX32 && machine.pointerWidth==4)
        return
#include "platform/linux/thread_entry/x32.inc"
        ;
    if (machine.architecture==CpuArchitecture::X86_32 && machine.abi==TargetAbi::LinuxI386 && machine.pointerWidth==4)
        return
#include "platform/linux/thread_entry/i386.inc"
        ;
    if (machine.architecture==CpuArchitecture::Arm64 && machine.abi==TargetAbi::LinuxAarch64 && machine.pointerWidth==8)
        return
#include "platform/linux/thread_entry/arm64.inc"
        ;
    return std::unexpected(std::make_error_code(std::errc::not_supported));
}

std::expected<std::vector<uint8_t>,std::error_code> nativeThreadControl(
    const TargetMachine& machine,uintptr_t function,uintptr_t argument,uint64_t pollNanoseconds) {
    auto entry=nativeThreadEntry(machine);
    if (!entry) return std::unexpected(entry.error());
    if (!function || pollNanoseconds>999999999 ||
        (entry->wordSize==4 && (function>UINT32_MAX || argument>UINT32_MAX)))
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    std::vector<uint8_t> data(entry->dataSize());
    auto put=[&](NativeThreadField field,uint64_t value) {
        for (unsigned i=0;i<entry->wordSize;++i) data[entry->offset(field)+i]=static_cast<uint8_t>(value>>(i*8));
    };
    put(NativeThreadField::Function,function);
    put(NativeThreadField::Argument,argument);
    put(NativeThreadField::PollNanoseconds,pollNanoseconds);
    return data;
}
} // namespace ce::os
