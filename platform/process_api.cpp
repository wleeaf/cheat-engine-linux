#include "platform/process_api.hpp"

namespace ce {

TargetDescription ProcessHandle::targetDescription() {
    TargetDescription description;
    description.host.pointerWidth = is64bit() ? 8 : 4;
    description.program = description.host;
    return description;
}

TargetMachine ProcessHandle::machineAt(uintptr_t) {
    return targetDescription().program;
}

Result<size_t> ProcessHandle::writeCode(uintptr_t address,const void* buffer,size_t size) {
    if (!size) return size_t(0);
    if (!buffer || size-1>UINTPTR_MAX-address)
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    if (!machineAt(address).isX86())
        return std::unexpected(std::make_error_code(std::errc::operation_not_supported));
    return write(address,buffer,size);
}

} // namespace ce
