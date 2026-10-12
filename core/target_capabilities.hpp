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

} // namespace ce
