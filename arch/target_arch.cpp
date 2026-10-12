#include "arch/target_arch.hpp"
#include <stdexcept>

namespace ce {

std::expected<Arch, std::string> disassemblerArchFor(const TargetMachine& m) {
    switch (m.architecture) {
        case CpuArchitecture::X86_32: return Arch::X86_32;
        case CpuArchitecture::X86_64: return Arch::X86_64;
        case CpuArchitecture::Arm64: return Arch::ARM64;
        case CpuArchitecture::RiscV32:
        case CpuArchitecture::RiscV64: {
            const auto arch = m.architecture == CpuArchitecture::RiscV32 ? Arch::RISCV32 : Arch::RISCV64;
            if (!Disassembler::supports(arch))
                return std::unexpected("No RISC-V decoder in this Capstone build (Capstone 5 or newer is required)");
            return arch;
        }
        case CpuArchitecture::Arm32: {
            if (m.instructionByteOrder == ByteOrder::Unknown)
                return std::unexpected("ARM instruction byte order is unknown");
            bool big = m.instructionByteOrder == ByteOrder::Big;
            if (m.instructionMode == InstructionMode::Thumb) return big ? Arch::ARMThumb_BE : Arch::ARMThumb;
            if (m.instructionMode == InstructionMode::Arm) return big ? Arch::ARM32_BE : Arch::ARM32;
            return std::unexpected("ARM instruction mode is unknown");
        }
        default: return std::unexpected("No instruction backend for " + std::string(cpuArchitectureName(m.architecture)));
    }
}

std::expected<Arch, std::string> disassemblerArchFor(ProcessHandle& process, uintptr_t address) {
    return disassemblerArchFor(address ? process.machineAt(address) : process.targetDescription().program);
}

std::expected<AsmArch, std::string> assemblerArchFor(Arch arch) {
    switch (arch) {
        case Arch::X86_32: return AsmArch::X86_32;
        case Arch::X86_64: return AsmArch::X86_64;
        case Arch::ARM32: return AsmArch::ARM32;
        case Arch::ARM64: return AsmArch::ARM64;
        case Arch::ARMThumb: return AsmArch::ARMThumb;
        case Arch::ARM32_BE: return AsmArch::ARM32_BE;
        case Arch::ARMThumb_BE: return AsmArch::ARMThumb_BE;
        case Arch::RISCV32: case Arch::RISCV64:
            return std::unexpected("No assembler backend for RISC-V (Keystone has none); disassembly is available");
    }
    return std::unexpected("Unknown instruction architecture");
}

} // namespace ce
