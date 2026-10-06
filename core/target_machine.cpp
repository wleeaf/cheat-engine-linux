#include "core/target_machine.hpp"

#include <elf.h>

namespace ce {

const char* cpuArchitectureName(CpuArchitecture arch) {
    switch (arch) {
        case CpuArchitecture::Unknown: return "unknown";
        case CpuArchitecture::X86_32: return "x86-32";
        case CpuArchitecture::X86_64: return "x86-64";
        case CpuArchitecture::Arm32: return "ARM32";
        case CpuArchitecture::Arm64: return "ARM64";
        case CpuArchitecture::RiscV32: return "RISC-V32";
        case CpuArchitecture::RiscV64: return "RISC-V64";
        case CpuArchitecture::Mips32: return "MIPS32";
        case CpuArchitecture::Mips64: return "MIPS64";
        case CpuArchitecture::PowerPC32: return "PowerPC32";
        case CpuArchitecture::PowerPC64: return "PowerPC64";
        case CpuArchitecture::S390X: return "s390x";
        case CpuArchitecture::Arm64EC: return "ARM64EC";
        case CpuArchitecture::Arm64X: return "ARM64X";
        case CpuArchitecture::Other: return "other";
    }
    return "unknown";
}

const char* byteOrderName(ByteOrder order) {
    switch (order) {
        case ByteOrder::Little: return "little-endian";
        case ByteOrder::Big: return "big-endian";
        case ByteOrder::Unknown: return "unknown";
    }
    return "unknown";
}

const char* targetAbiName(TargetAbi abi) {
    switch (abi) {
        case TargetAbi::Unknown: return "unknown";
        case TargetAbi::LinuxI386: return "Linux i386";
        case TargetAbi::LinuxX86_64: return "Linux x86-64";
        case TargetAbi::LinuxX32: return "Linux x32";
        case TargetAbi::LinuxArmEabi: return "Linux ARM EABI";
        case TargetAbi::LinuxAarch64: return "Linux AArch64";
        case TargetAbi::LinuxRiscV: return "Linux RISC-V";
        case TargetAbi::LinuxOther: return "Linux other";
        case TargetAbi::WindowsI386: return "Windows i386";
        case TargetAbi::WindowsX64: return "Windows x64";
        case TargetAbi::WindowsArm: return "Windows ARM";
        case TargetAbi::WindowsArm64: return "Windows ARM64";
        case TargetAbi::WindowsArm64EC: return "Windows ARM64EC";
        case TargetAbi::WindowsArm64X: return "Windows ARM64X";
    }
    return "unknown";
}

TargetMachine nativeTargetMachine() {
    TargetMachine machine;
    machine.pointerWidth = sizeof(uintptr_t);
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    machine.byteOrder = ByteOrder::Big;
#else
    machine.byteOrder = ByteOrder::Little;
#endif
#if defined(__x86_64__)
    machine.architecture = CpuArchitecture::X86_64;
    machine.instructionMode = InstructionMode::X86_64;
    machine.abi = sizeof(uintptr_t) == 4 ? TargetAbi::LinuxX32 : TargetAbi::LinuxX86_64;
#elif defined(__i386__)
    machine.architecture = CpuArchitecture::X86_32;
    machine.instructionMode = InstructionMode::X86_32;
    machine.abi = TargetAbi::LinuxI386;
#elif defined(__aarch64__)
    machine.architecture = CpuArchitecture::Arm64;
    machine.instructionMode = InstructionMode::Aarch64;
    machine.abi = TargetAbi::LinuxAarch64;
#elif defined(__arm__)
    machine.architecture = CpuArchitecture::Arm32;
    machine.instructionMode = InstructionMode::Arm;
    machine.abi = TargetAbi::LinuxArmEabi;
#elif defined(__riscv)
    machine.architecture = __riscv_xlen == 64 ? CpuArchitecture::RiscV64 : CpuArchitecture::RiscV32;
    machine.instructionMode = InstructionMode::Other;
    machine.abi = TargetAbi::LinuxRiscV;
#else
    machine.architecture = CpuArchitecture::Other;
    machine.instructionMode = InstructionMode::Other;
    machine.abi = TargetAbi::LinuxOther;
#endif
    machine.instructionByteOrder = machine.byteOrder;
    if (machine.architecture == CpuArchitecture::Arm64) machine.instructionByteOrder = ByteOrder::Little;
    return machine;
}

std::expected<uint64_t, std::string> decodeTargetUnsigned(std::span<const uint8_t> bytes, ByteOrder order) {
    if (bytes.empty() || bytes.size() > 8 || order == ByteOrder::Unknown)
        return std::unexpected("Invalid integer width or unknown target byte order");
    uint64_t value = 0;
    for (size_t i = 0; i < bytes.size(); ++i) {
        size_t index = order == ByteOrder::Little ? bytes.size() - 1 - i : i;
        value = (value << 8) | bytes[index];
    }
    return value;
}

std::expected<TargetMachine, std::string> parseElfTarget(std::span<const uint8_t> h) {
    if (h.size() < EI_NIDENT || h[0] != 0x7f || h[1] != 'E' || h[2] != 'L' || h[3] != 'F')
        return std::unexpected("Missing ELF identification");
    if ((h[EI_CLASS] != ELFCLASS32 && h[EI_CLASS] != ELFCLASS64) ||
        (h[EI_DATA] != ELFDATA2LSB && h[EI_DATA] != ELFDATA2MSB) || h[EI_VERSION] != EV_CURRENT)
        return std::unexpected("Invalid ELF class, byte order, or version");
    bool wide = h[EI_CLASS] == ELFCLASS64;
    if (h.size() < (wide ? sizeof(Elf64_Ehdr) : sizeof(Elf32_Ehdr)))
        return std::unexpected("Truncated ELF header");
    TargetMachine m;
    m.pointerWidth = wide ? 8 : 4;
    m.byteOrder = h[EI_DATA] == ELFDATA2MSB ? ByteOrder::Big : ByteOrder::Little;
    m.instructionByteOrder = m.byteOrder;
    auto machine = *decodeTargetUnsigned(h.subspan(18, 2), m.byteOrder);
    m.instructionMode = InstructionMode::Other;
    m.abi = TargetAbi::LinuxOther;
    switch (machine) {
        case EM_386:
            if (wide) return std::unexpected("ELF i386 has a 64-bit class");
            m.architecture = CpuArchitecture::X86_32; m.instructionMode = InstructionMode::X86_32;
            m.abi = TargetAbi::LinuxI386; break;
        case EM_X86_64:
            m.architecture = CpuArchitecture::X86_64; m.instructionMode = InstructionMode::X86_64;
            m.abi = wide ? TargetAbi::LinuxX86_64 : TargetAbi::LinuxX32; break;
        case EM_ARM:
            if (wide) return std::unexpected("ELF ARM32 has a 64-bit class");
            m.architecture = CpuArchitecture::Arm32; m.instructionMode = InstructionMode::Arm;
            m.abi = TargetAbi::LinuxArmEabi; break;
        case EM_AARCH64:
            m.architecture = CpuArchitecture::Arm64; m.instructionMode = InstructionMode::Aarch64;
            // AArch64 ILP32 needs its own syscall backend; do not identify it as LP64.
            m.abi = wide ? TargetAbi::LinuxAarch64 : TargetAbi::Unknown; break;
        case EM_RISCV:
            m.architecture = wide ? CpuArchitecture::RiscV64 : CpuArchitecture::RiscV32;
            m.abi = TargetAbi::LinuxRiscV; break;
        case EM_MIPS: m.architecture = wide ? CpuArchitecture::Mips64 : CpuArchitecture::Mips32; break;
        case EM_PPC: m.architecture = CpuArchitecture::PowerPC32; break;
        case EM_PPC64: m.architecture = CpuArchitecture::PowerPC64; break;
        case EM_S390: m.architecture = wide ? CpuArchitecture::S390X : CpuArchitecture::Other; break;
        default: m.architecture = CpuArchitecture::Other; break;
    }
    if (m.isX86() && m.byteOrder != ByteOrder::Little)
        return std::unexpected("x86 ELF declares an invalid big-endian encoding");
    if (m.architecture == CpuArchitecture::Arm32) {
        auto flags = *decodeTargetUnsigned(h.subspan(36, 4), m.byteOrder);
        if (flags & EF_ARM_BE8) m.instructionByteOrder = ByteOrder::Little;
    }
    if (m.architecture == CpuArchitecture::Arm64 || m.architecture == CpuArchitecture::RiscV32 ||
        m.architecture == CpuArchitecture::RiscV64) m.instructionByteOrder = ByteOrder::Little;
    return m;
}

std::expected<TargetMachine, std::string> parsePeTarget(std::span<const uint8_t> h) {
    if (h.size() < 0x40 || h[0] != 'M' || h[1] != 'Z') return std::unexpected("Missing DOS header");
    size_t pe = *decodeTargetUnsigned(h.subspan(0x3c, 4), ByteOrder::Little);
    if (pe < 0x40 || pe > h.size() || h.size() - pe < 26 ||
        h[pe] != 'P' || h[pe + 1] != 'E' || h[pe + 2] || h[pe + 3])
        return std::unexpected("Truncated or invalid PE header");
    auto machine = *decodeTargetUnsigned(h.subspan(pe + 4, 2), ByteOrder::Little);
    auto optionalSize = *decodeTargetUnsigned(h.subspan(pe + 20, 2), ByteOrder::Little);
    if (optionalSize < 60 || optionalSize > h.size() - pe - 24)
        return std::unexpected("Truncated PE optional header");
    auto magic = *decodeTargetUnsigned(h.subspan(pe + 24, 2), ByteOrder::Little);
    if (magic != 0x10b && magic != 0x20b) return std::unexpected("Unknown PE optional header");
    TargetMachine m;
    m.pointerWidth = magic == 0x20b ? 8 : 4;
    m.byteOrder = ByteOrder::Little;
    m.instructionByteOrder = ByteOrder::Little;
    switch (machine) {
        case 0x14c: m.architecture = CpuArchitecture::X86_32; m.abi = TargetAbi::WindowsI386;
            m.instructionMode = InstructionMode::X86_32; break;
        case 0x8664: m.architecture = CpuArchitecture::X86_64; m.abi = TargetAbi::WindowsX64;
            m.instructionMode = InstructionMode::X86_64; break;
        case 0x1c0: case 0x1c2: case 0x1c4:
            m.architecture = CpuArchitecture::Arm32; m.abi = TargetAbi::WindowsArm;
            m.instructionMode = machine == 0x1c0 ? InstructionMode::Arm : InstructionMode::Thumb; break;
        case 0xaa64: m.architecture = CpuArchitecture::Arm64; m.abi = TargetAbi::WindowsArm64;
            m.instructionMode = InstructionMode::Aarch64; break;
        case 0xa641: m.architecture = CpuArchitecture::Arm64EC; m.abi = TargetAbi::WindowsArm64EC; break;
        case 0xa64e: m.architecture = CpuArchitecture::Arm64X; m.abi = TargetAbi::WindowsArm64X; break;
        default: m.architecture = CpuArchitecture::Other; break;
    }
    bool requires32 = m.architecture == CpuArchitecture::X86_32 || m.architecture == CpuArchitecture::Arm32;
    bool requires64 = m.architecture == CpuArchitecture::X86_64 || m.architecture == CpuArchitecture::Arm64 ||
                      m.architecture == CpuArchitecture::Arm64EC || m.architecture == CpuArchitecture::Arm64X;
    if ((requires32 && m.pointerWidth != 4) || (requires64 && m.pointerWidth != 8))
        return std::unexpected("PE machine and optional-header width disagree");
    return m;
}

} // namespace ce
