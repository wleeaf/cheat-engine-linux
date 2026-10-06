#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>

namespace ce {

enum class CpuArchitecture {
    Unknown, X86_32, X86_64, Arm32, Arm64, RiscV32, RiscV64,
    Mips32, Mips64, PowerPC32, PowerPC64, S390X, Arm64EC, Arm64X, Other
};
enum class ByteOrder { Unknown, Little, Big };
enum class TargetAbi {
    Unknown, LinuxI386, LinuxX86_64, LinuxX32, LinuxArmEabi, LinuxAarch64,
    LinuxRiscV, LinuxOther, WindowsI386, WindowsX64, WindowsArm,
    WindowsArm64, WindowsArm64EC, WindowsArm64X
};
enum class InstructionMode { Unknown, X86_32, X86_64, Arm, Thumb, Aarch64, Other };
enum class TargetTransport { Local, CEServer, Gdb, Unknown };
enum class TargetRuntime { Native, Wine, Emulated, Unknown };

struct TargetMachine {
    CpuArchitecture architecture = CpuArchitecture::Unknown;
    ByteOrder byteOrder = ByteOrder::Unknown;
    TargetAbi abi = TargetAbi::Unknown;
    InstructionMode instructionMode = InstructionMode::Unknown;
    uint8_t pointerWidth = 0;
    ByteOrder instructionByteOrder = ByteOrder::Unknown;

    bool hasPointers() const { return pointerWidth == 4 || pointerWidth == 8; }
    bool isX86() const {
        return architecture == CpuArchitecture::X86_32 || architecture == CpuArchitecture::X86_64;
    }
    bool operator==(const TargetMachine&) const = default;
};

struct TargetDescription {
    // The Unix loader and the selected program can have different ABIs (WoW64).
    TargetMachine host;
    TargetMachine program;
    TargetTransport transport = TargetTransport::Unknown;
    TargetRuntime runtime = TargetRuntime::Unknown;
    bool mixedCode = false;
    bool live = true;
    int tracerPid = 0;
    bool pendingRecovery = false;
};

const char* cpuArchitectureName(CpuArchitecture architecture);
const char* byteOrderName(ByteOrder order);
const char* targetAbiName(TargetAbi abi);
TargetMachine nativeTargetMachine();
std::expected<TargetMachine, std::string> parseElfTarget(std::span<const uint8_t> header);
std::expected<TargetMachine, std::string> parsePeTarget(std::span<const uint8_t> header);
std::expected<uint64_t, std::string> decodeTargetUnsigned(std::span<const uint8_t> bytes, ByteOrder order);

} // namespace ce
