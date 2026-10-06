#pragma once

#include "platform/process_api.hpp"
#include <optional>
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

} // namespace ce
