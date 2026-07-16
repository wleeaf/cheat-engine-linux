#pragma once
/// DWARF line-table reader.
///
/// Resolves an instruction address to a (source file, line number) pair when the
/// target ELF binary has DWARF debug information (.debug_line).
///
/// Backed by libdw (elfutils) — only compiled in when CECORE_HAVE_DWARF is defined,
/// which the CMake configure step sets after locating elfutils/libdw.h. Without
/// libdw-dev installed the API is still present; every call cleanly reports
/// `available() == false` and `lookup()` returns std::nullopt.
///
/// Usage:
///   DwarfInfo info;
///   if (info.load("/usr/bin/sleep", base)) {
///       if (auto src = info.lookup(rip)) printf("%s:%d\n", src->file.c_str(), src->line);
///   }

#include <cstdint>
#include <optional>
#include <string>
#include <memory>
#include <vector>

namespace ce {

struct DwarfSourceLocation {
    std::string file;       // Absolute path or compile-unit-relative
    int32_t line = 0;
    int32_t column = 0;
    bool isStatement = true;
};

/// One member of a DWARF struct/union/class type.
struct DwarfMember {
    std::string name;
    uint64_t    offset = 0;    // DW_AT_data_member_location (bytes from struct start)
    std::string typeName;      // resolved, e.g. "int", "float", "Foo*", "char[16]"
    uint64_t    size = 0;      // byte size of the member's type (0 if unknown)
    bool        isFloat = false;
    bool        isPointer = false;
};

/// A DWARF-described aggregate type (struct / union / class) and its members.
struct DwarfStruct {
    std::string name;
    uint64_t    size = 0;      // DW_AT_byte_size
    std::vector<DwarfMember> members;
};

class DwarfInfo {
public:
    DwarfInfo();
    ~DwarfInfo();

    DwarfInfo(const DwarfInfo&) = delete;
    DwarfInfo& operator=(const DwarfInfo&) = delete;
    DwarfInfo(DwarfInfo&&) noexcept;
    DwarfInfo& operator=(DwarfInfo&&) noexcept;

    /// Was this build compiled with libdw support? When false every method below
    /// returns its "no info" value.
    static bool available();

    /// Open `elfPath` and prepare its DWARF line tables. `loadBase` is the
    /// process-time load address of the module; addresses passed to lookup()
    /// are translated relative to this. Returns false if no debug info exists.
    bool load(const std::string& elfPath, uintptr_t loadBase);

    /// Returns std::nullopt if no DWARF row maps the given runtime address.
    std::optional<DwarfSourceLocation> lookup(uintptr_t runtimeAddress) const;

    /// Return the function (DW_TAG_subprogram) name covering the given
    /// runtime address, if any. Inline functions get the innermost name.
    std::optional<std::string> functionName(uintptr_t runtimeAddress) const;

    /// Names of every named struct/union/class type in the debug info (deduped).
    std::vector<std::string> structNames() const;

    /// Resolve a struct/union/class type by name to its members (name, offset,
    /// resolved type name + size). Returns nullopt if no such type is described.
    std::optional<DwarfStruct> structByName(const std::string& name) const;

    /// Drop loaded debug info.
    void close();

    bool isLoaded() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/// Per-process DWARF registry: maintains one DwarfInfo per loaded module
/// and routes lookups to the right module by address range.
class DwarfRegistry {
public:
    DwarfRegistry();
    ~DwarfRegistry();

    DwarfRegistry(const DwarfRegistry&) = delete;
    DwarfRegistry& operator=(const DwarfRegistry&) = delete;

    /// Load every readable module of `proc` that has DWARF info.
    /// Returns the count successfully loaded. No-op when DWARF is disabled.
    int loadFromProcess(class ProcessHandle& proc);

    std::optional<DwarfSourceLocation> lookup(uintptr_t runtimeAddress) const;
    std::optional<std::string> functionName(uintptr_t runtimeAddress) const;

    /// Struct/union/class type names across all loaded modules (deduped).
    std::vector<std::string> structNames() const;
    /// Resolve a struct by name across all loaded modules (first match).
    std::optional<DwarfStruct> structByName(const std::string& name) const;

    void clear();

private:
    struct Module {
        uintptr_t base = 0;
        size_t    size = 0;
        std::unique_ptr<DwarfInfo> info;
    };
    std::vector<Module> modules_;
};

} // namespace ce
