#pragma once

#include <span>
#include "platform/process_api.hpp"
#include <array>
#include <signal.h>

namespace ce::os {

// These operations require a ptrace stop owned by the calling thread. They do
// not attach, resume, or replace the target's original syscall restart state.
Result<CpuContext> readNativeContext(pid_t tid);
Result<void> writeNativeContext(pid_t tid, const CpuContext& context);
// Valid only after a requested single-step. Unlike an ordinary trace trap,
// syscall-return traps have architecture-specific siginfo and kernel GP state.
bool isNativeSyscallStepTrap(pid_t tid, const siginfo_t& info);

struct NativeVectorContext {
    std::array<std::array<uint8_t, 16>, 32> registers{};
    unsigned count = 0;
    uint32_t status = 0, control = 0;
};
Result<NativeVectorContext> readNativeVectors(pid_t tid);

enum class HardwareBreakpointAccess { Execute, Write, ReadWrite };
struct NativeHardwareBank {
    struct Slot { uint64_t address = 0; uint32_t control = 0; };
    std::array<Slot, 16> entries{};
    unsigned count = 0;
    uint64_t status = 0, control = 0;
};
Result<NativeHardwareBank> readNativeHardwareBank(pid_t tid, bool execution);
Result<void> restoreNativeHardwareBank(pid_t tid, bool execution, const NativeHardwareBank& saved);
Result<void> setNativeHardwareBreakpoint(pid_t tid, unsigned slot, uintptr_t address,
                                        HardwareBreakpointAccess access, unsigned length);
Result<void> removeNativeHardwareBreakpoint(pid_t tid, unsigned slot, bool execution);
Result<void> clearNativeHardwareStatus(pid_t tid);

struct NativeSoftwareBreakpoint {
    uintptr_t address = 0;
    std::array<uint8_t, 4> original{}, trap{};
    unsigned size = 0;
    bool installed = false;
};
struct NativeBreakpointFailure {
    Error error;
    std::optional<NativeSoftwareBreakpoint> recovery;
};
std::expected<NativeSoftwareBreakpoint, NativeBreakpointFailure> installNativeSoftwareBreakpoint(
    pid_t tid, uintptr_t address, InstructionMode mode);
Result<void> removeNativeSoftwareBreakpoint(pid_t tid, NativeSoftwareBreakpoint& breakpoint);

/// Write `bytes` at `address` through the file behind a shared mapping that
/// the target maps without write permission. W^X JITs (CoreCLR) map code as
/// an executable read-only view of a shared memfd, which the kernel's forced
/// remote writes (POKETEXT, /proc/pid/mem) refuse. The target keeps the
/// backing file open, so its descriptor is reopened through /proc/PID/fd
/// (same ptrace access check) and written at the mapping's file offset; both
/// views share the page. Fails if the range is not such a mapping, no view of
/// that file is executable, or no open descriptor of that file exists. On
/// ARM64 the instruction cache is made coherent for the written range.
Result<void> writeSharedMappingBacking(pid_t pid, uintptr_t address, std::span<const uint8_t> bytes);
/// The errors with which a forced code write reports that the page refused it
/// (EIO from /proc/PID/mem, EFAULT, EPERM, EACCES), the only ones after which
/// writeSharedMappingBacking may be tried. Busy or unrecoverable native-call
/// state is never one of them and must reach the caller.
bool sharedMappingWriteRefused(const Error& error);
uintptr_t nativeSoftwareBreakpointAddress(const CpuContext& context);

// A failed update restores and verifies the previous slot before returning the
// original error. state_not_recoverable means restoration failed: the caller
// must retain its ptrace stop and recovery state instead of resuming the target.

} // namespace ce::os
