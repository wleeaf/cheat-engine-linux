#include "debug/managed_breakpoint.hpp"

#include <sstream>

namespace ce {

std::string formatManagedMethodName(const ManagedMethodInfo& method) {
    std::ostringstream out;
    if (!method.type.namespaceName.empty())
        out << method.type.namespaceName << '.';
    if (!method.type.name.empty())
        out << method.type.name << "::";
    out << method.methodName;
    if (!method.signature.empty())
        out << method.signature;
    if (method.metadataToken != 0)
        out << " [token 0x" << std::hex << method.metadataToken << ']';
    return out.str();
}

int addManagedMethodBreakpoint(
    BreakpointManager& manager,
    const ManagedMethodInfo& method,
    const ManagedMethodBreakpointOptions& options) {
    if (method.nativeAddress == 0 || method.methodName.empty())
        return -1;

    Breakpoint bp;
    bp.address = method.nativeAddress;
    bp.type = BpType::Execute;
    bp.action = options.action;
    bp.method = BpMethod::Software;
    bp.hwRegister = -1;
    bp.size = 1;
    bp.oneShot = options.oneShot;
    bp.threadFilter = options.threadFilter;
    bp.condition = options.condition;
    bp.description = formatManagedMethodName(method);
    return manager.add(bp);
}

} // namespace ce
