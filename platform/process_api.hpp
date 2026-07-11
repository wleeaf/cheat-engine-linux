#pragma once
/// Abstract process API interface.
/// Linux implementation wraps ceserver's C functions directly.

#include "core/types.hpp"
#include <memory>
#include <expected>
#include <system_error>

namespace ce {

// Error type for process operations
using Error = std::error_code;

template<typename T>
using Result = std::expected<T, Error>;

/// Handle to an opened process.
class ProcessHandle {
public:
    virtual ~ProcessHandle() = default;

    virtual pid_t pid() const = 0;
    virtual bool is64bit() const = 0;
    // Whether the process EXECUTES 32-bit code. Differs from is64bit() for WoW64
    // (a 64-bit Wine process running a 32-bit Windows game): the ELF is 64-bit but
    // the code is 32-bit. Default: the inverse of is64bit(); LinuxProcessHandle
    // refines it with a read-only CPU-mode probe.
    virtual bool runs32BitCode() { return !is64bit(); }

    // ── Memory access ──
    virtual Result<size_t> read(uintptr_t address, void* buffer, size_t size) = 0;
    virtual Result<size_t> write(uintptr_t address, const void* buffer, size_t size) = 0;

    // ── Memory info ──
    virtual std::vector<MemoryRegion> queryRegions() = 0;
    virtual std::optional<MemoryRegion> queryRegion(uintptr_t address) = 0;

    // ── Memory management ──
    virtual Result<uintptr_t> allocate(size_t size, MemProt protection, uintptr_t preferredBase = 0) = 0;
    virtual Result<void> free(uintptr_t address, size_t size) = 0;
    virtual Result<void> protect(uintptr_t address, size_t size, MemProt newProtection) = 0;

    // ── Module enumeration ──
    virtual std::vector<ModuleInfo> modules() = 0;

    // ── Thread enumeration ──
    virtual std::vector<ThreadInfo> threads() = 0;

    // ── Convenience templates ──
    template<typename T>
    Result<T> read(uintptr_t address) {
        T value{};
        auto r = read(address, &value, sizeof(T));
        if (!r) return std::unexpected(r.error());
        // A short read (e.g. the address straddles a region boundary) would
        // otherwise masquerade as a complete, zero-extended value. Treat any
        // transfer that didn't cover the whole T as an I/O error.
        if (*r != sizeof(T))
            return std::unexpected(std::make_error_code(std::errc::io_error));
        return value;
    }

    template<typename T>
    Result<size_t> write(uintptr_t address, const T& value) {
        auto r = write(address, &value, sizeof(T));
        if (!r) return std::unexpected(r.error());
        // Treat a short write as a failure rather than reporting success.
        if (*r != sizeof(T))
            return std::unexpected(std::make_error_code(std::errc::io_error));
        return r;
    }
};

/// Process enumeration — list all running processes.
class ProcessEnumerator {
public:
    virtual ~ProcessEnumerator() = default;
    virtual std::vector<ProcessInfo> list() = 0;
    virtual std::unique_ptr<ProcessHandle> open(pid_t pid) = 0;
};

/// Debugger interface for a process.
class Debugger {
public:
    virtual ~Debugger() = default;

    virtual Result<void> attach(pid_t pid) = 0;
    virtual Result<void> detach() = 0;

    virtual Result<CpuContext> getContext(pid_t tid) = 0;
    virtual Result<void> setContext(pid_t tid, const CpuContext& ctx) = 0;

    virtual Result<void> suspend(pid_t tid) = 0;
    virtual Result<void> resume(pid_t tid) = 0;
    virtual Result<void> singleStep(pid_t tid) = 0;

    // Hardware breakpoints (DR0-DR3)
    virtual Result<void> setBreakpoint(pid_t tid, int reg, uintptr_t address, int type, int size) = 0;
    virtual Result<void> removeBreakpoint(pid_t tid, int reg) = 0;
};

} // namespace ce
