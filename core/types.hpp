#pragma once
/// Core types for cecore — Linux-native replacements for Windows API types.

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <optional>

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

// ── CPU register context (x86_64) ──
struct CpuContext {
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsi, rdi, rbp, rsp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rip;
    uint64_t rflags;
    uint64_t cs, ss, ds, es, fs, gs;

    // Debug registers
    uint64_t dr0, dr1, dr2, dr3, dr6, dr7;
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
