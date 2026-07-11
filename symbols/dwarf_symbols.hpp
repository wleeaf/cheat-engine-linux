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
