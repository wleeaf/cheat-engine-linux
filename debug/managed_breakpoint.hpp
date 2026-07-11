#pragma once
/// Managed method breakpoint helpers.

#include "analysis/managed_runtime.hpp"
#include "debug/breakpoint_manager.hpp"

#include <cstdint>
#include <string>

namespace ce {

struct ManagedMethodInfo {
    ManagedTypeInfo type;
    std::string methodName;
    std::string signature;
    uint32_t metadataToken = 0;
    uintptr_t nativeAddress = 0;
    size_t nativeSize = 0;
};

struct ManagedMethodBreakpointOptions {
    BpAction action = BpAction::Break;
    bool oneShot = false;
    pid_t threadFilter = 0;
    std::string condition;
};

std::string formatManagedMethodName(const ManagedMethodInfo& method);
int addManagedMethodBreakpoint(
    BreakpointManager& manager,
    const ManagedMethodInfo& method,
    const ManagedMethodBreakpointOptions& options = {});

} // namespace ce
