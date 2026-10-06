#pragma once
/// Core types for cecore — Linux-native replacements for Windows API types.

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <optional>
#include <array>
#include <sys/types.h>
#include "core/target_machine.hpp"

namespace ce {

// ── Memory protection flags (match /proc/maps rwxp) ──
enum class MemProt : uint32_t {
    None       = 0,
    Read       = 1,
    Write      = 2,
    Exec       = 4,
    ReadWrite  = Read | Write,
    ReadExec   = Read | Exec,
    All        = Read | Write | Exec,
};
inline MemProt operator|(MemProt a, MemProt b) { return MemProt(uint32_t(a) | uint32_t(b)); }
inline bool operator&(MemProt a, MemProt b) { return (uint32_t(a) & uint32_t(b)) != 0; }

// ── Memory region state ──
enum class MemState : uint32_t {
    Free     = 0,
    Committed = 1,
};

// ── Memory region type ──
enum class MemType : uint32_t {
    Private  = 0,
    Mapped   = 1,
    Image    = 2,  // File-backed (ELF binary, .so)
};

// ── Memory region info (from /proc/pid/maps) ──
struct MemoryRegion {
    uintptr_t base = 0;
    size_t    size = 0;
    MemProt   protection = MemProt::None;
    MemType   type = MemType::Private;
    MemState  state = MemState::Free;
    std::string path;  // Mapped file path (empty for anonymous)
};

// ── Process info ──
struct ProcessInfo {
    pid_t       pid = 0;
    std::string name;
    std::string path;
    bool        sandboxed = false;   // in a nested PID namespace (Flatpak/Snap/container)
};

// ── Module info ──
struct ModuleInfo {
    uintptr_t   base = 0;
    size_t      size = 0;
    std::string name;
    std::string path;
    bool        is64bit = true;
    TargetMachine machine{};
};

/// If `addr` lies within one of `modules`, returns "basename+0xOFFSET" (the
/// module-relative address Cheat Engine shows, which stays meaningful across
/// restarts / ASLR); otherwise an empty string. When mappings nest, the smallest
/// containing module wins.
std::string moduleOffsetString(const std::vector<ModuleInfo>& modules, uintptr_t addr);

// ── Thread info ──
struct ThreadInfo {
    pid_t tid = 0;
};

// Register banks retain their own names; consumers must select the target ISA.
struct CpuContext {
    uint64_t rax = 0, rbx = 0, rcx = 0, rdx = 0;
    uint64_t rsi = 0, rdi = 0, rbp = 0, rsp = 0;
    uint64_t r8 = 0, r9 = 0, r10 = 0, r11 = 0, r12 = 0, r13 = 0, r14 = 0, r15 = 0;
    uint64_t rip = 0;
    uint64_t rflags = 0;
    uint64_t cs = 0, ss = 0, ds = 0, es = 0, fs = 0, gs = 0;

    // Debug registers
    uint64_t dr0 = 0, dr1 = 0, dr2 = 0, dr3 = 0, dr6 = 0, dr7 = 0;

    CpuArchitecture architecture = CpuArchitecture::Unknown;
    // ARM64: X0-X30. ARM32: R0-R12 and LR at index 14; SP, PC and CPSR
    // use the common fields below. No x86 aliases or duplicated PC/SP storage.
    std::array<uint64_t, 31> x{};
    uint64_t sp = 0, pc = 0, pstate = 0;
    bool debugRegistersValid = false;

    bool hasArmRegisters() const { return architecture == CpuArchitecture::Arm64 || architecture == CpuArchitecture::Arm32; }
    uint64_t instructionPointer() const { return hasArmRegisters() ? pc : rip; }
    uint64_t stackPointer() const { return hasArmRegisters() ? sp : rsp; }
    uint64_t framePointer() const { return architecture == CpuArchitecture::Arm32 ? x[11] : architecture == CpuArchitecture::Arm64 ? x[29] : rbp; }
    void setInstructionPointer(uint64_t value) {
        if (hasArmRegisters()) pc = value;
        else rip = value;
    }
};

// ── Scan value types ──
enum class ValueType {
    Byte,
    Int16,
    Int32,
    Int64,
    Float,
    Double,
    String,
    UnicodeString,
    ByteArray,
    Binary,      // Binary/bitmask scan
    All,         // Scan all numeric types simultaneously
    Grouped,     // Multiple values at offsets in one pass
    Custom,      // Lua-defined type
    Pointer,     // Native pointer-sized integer
};

/// Canonical display name for a value type, matching Cheat Engine's wording (and the
/// Change-address dialog), so the cheat-table Type column, the dialog, and any other
/// surface all agree. Shared to avoid drift ("String" vs "Text", "Array of byte").
inline const char* valueTypeName(ValueType t) {
    switch (t) {
        case ValueType::Byte:          return "Byte";
        case ValueType::Int16:         return "2 Bytes";
        case ValueType::Int32:         return "4 Bytes";
        case ValueType::Int64:         return "8 Bytes";
        case ValueType::Float:         return "Float";
        case ValueType::Double:        return "Double";
        case ValueType::String:        return "String";
        case ValueType::UnicodeString: return "Unicode String";
        case ValueType::ByteArray:     return "Array of byte";
        case ValueType::Binary:        return "Binary";
        case ValueType::All:           return "All";
        case ValueType::Grouped:       return "Grouped";
        case ValueType::Custom:        return "Custom";
        case ValueType::Pointer:       return "Pointer";
    }
    return "4 Bytes";
}

// ── Scan comparison ──
enum class ScanCompare {
    Exact,
    Greater,
    Less,
    Between,
    Unknown,
    Changed,
    Unchanged,
    Increased,
    Decreased,
    IncreasedBy,   // current - old == value
    DecreasedBy,   // old - current == value
    SameAsFirst,
};

// ── Freeze modes ──
enum class FreezeMode {
    Normal,         // Always write frozen value
    IncreaseOnly,   // Only write if current < frozen (allow increase)
    DecreaseOnly,   // Only write if current > frozen (allow decrease)
    NeverIncrease,  // Write if current > frozen (prevent increase)
    NeverDecrease,  // Write if current < frozen (prevent decrease)
};

/// Whether a directional freeze should re-write the frozen value given the value
/// currently in memory. Normal always writes; the directional pairs are
/// equivalent (allow-increase ≡ never-decrease = floor at frozen; allow-decrease ≡
/// never-increase = ceiling at frozen).
inline bool freezeShouldWrite(FreezeMode mode, double current, double frozen) {
    switch (mode) {
        case FreezeMode::IncreaseOnly:
        case FreezeMode::NeverDecrease: return current < frozen;  // floor
        case FreezeMode::DecreaseOnly:
        case FreezeMode::NeverIncrease: return current > frozen;  // ceiling
        case FreezeMode::Normal:
        default:                        return true;
    }
}

} // namespace ce
