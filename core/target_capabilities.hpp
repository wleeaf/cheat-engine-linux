#pragma once

#include "platform/process_api.hpp"
#include <optional>
#include <string>
#include <system_error>
#include <vector>

namespace ce {

enum class TargetFeature {
    ReadMemory, WriteMemory, NumericScan, PointerScan, Disassemble, Assemble,
    Allocate, Protect, LibraryInjection, CodeInjection, Debugger,
    HardwareWatchpoint, SoftwareWatchpoint, Trace, GuestDebugging, RemoteThread
};
enum class CapabilityState { Available, Partial, Unsupported, Blocked, Unknown };
struct TargetCapability {
    TargetFeature feature;
    CapabilityState state;
    std::string reason;
};

const char* targetFeatureName(TargetFeature feature);
const char* capabilityStateName(CapabilityState state);
// Availability describes the implemented backend, not permission or test coverage.
// Runtime syscall errors remain authoritative for permission and mapping changes.
std::vector<TargetCapability> targetCapabilities(const TargetDescription& description);
std::vector<TargetCapability> targetCapabilities(ProcessHandle& process);
std::optional<std::string> unsupportedTargetOperation(ProcessHandle& process, TargetFeature feature);
// User-facing reason for a failed operation: the capability reason when the
// backend refuses this target, otherwise the operation's own error. Frontends
// use this so an unsupported target never fails silently or with a bare errno.
std::string targetOperationError(ProcessHandle& process, TargetFeature feature, std::error_code error = {});
// Probes a few readable regions. When none can be read (typically EPERM from
// Yama ptrace_scope on a process that is not a descendant), returns the reason,
// so a scan of an unreadable target fails explicitly instead of finding nothing.
std::optional<std::string> memoryAccessProblem(ProcessHandle& process);

/// Whether this process may act on local process pid: the same real,
/// effective, saved and filesystem uid and gid as ours (the kernel's own
/// ptrace rule), or we run as root. The .deb gives the binaries cap_sys_ptrace
/// to get past Yama for the user's own games; without this check that would
/// reach every user's processes, root's included.
bool processOwnedByCaller(pid_t pid);
/// PTRACE_SEIZE of a thread, refused (-1, errno EPERM) for one that
/// processOwnedByCaller rejects. Every seize goes through here.
long seizeIfOwned(pid_t tid, unsigned long options);

} // namespace ce
