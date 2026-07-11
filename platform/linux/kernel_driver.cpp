#include "platform/linux/kernel_driver.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <system_error>
#include <unistd.h>

namespace ce::os {

KernelDriverClient::~KernelDriverClient() {
    close();
}

bool KernelDriverClient::open(const std::string& path) {
    close();
    fd_ = ::open(path.c_str(), O_RDWR | O_CLOEXEC);
    return fd_ >= 0;
}

void KernelDriverClient::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

Result<size_t> KernelDriverClient::readProcessMemory(
    pid_t pid,
    uintptr_t address,
    void* buffer,
    size_t size) {
    return accessProcessMemory(CECORE_KMOD_IOC_READ_PROCESS_VM, pid, address, buffer, size);
}

Result<size_t> KernelDriverClient::writeProcessMemory(
    pid_t pid,
    uintptr_t address,
    const void* buffer,
    size_t size) {
    return accessProcessMemory(
        CECORE_KMOD_IOC_WRITE_PROCESS_VM,
        pid,
        address,
        const_cast<void*>(buffer),
        size);
}

Result<size_t> KernelDriverClient::readPhysicalMemory(
    uintptr_t physicalAddress,
    void* buffer,
    size_t size) {
    return accessPhysicalMemory(CECORE_KMOD_IOC_READ_PHYSICAL, physicalAddress, buffer, size);
}

Result<size_t> KernelDriverClient::writePhysicalMemory(
    uintptr_t physicalAddress,
    const void* buffer,
    size_t size) {
    return accessPhysicalMemory(
        CECORE_KMOD_IOC_WRITE_PHYSICAL,
        physicalAddress,
        const_cast<void*>(buffer),
        size);
}

Result<VirtualAddressTranslation> KernelDriverClient::translateVirtualAddress(
    pid_t pid,
    uintptr_t virtualAddress) {
    if (fd_ < 0)
        return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
    if (virtualAddress == 0)
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));

    cecore_kmod_translate_request req{};
    req.pid = static_cast<__u32>(pid);
    req.virtual_address = virtualAddress;

    if (::ioctl(fd_, CECORE_KMOD_IOC_TRANSLATE_VA, &req) < 0)
        return std::unexpected(std::error_code(errno, std::generic_category()));

    return VirtualAddressTranslation{
        static_cast<uintptr_t>(req.virtual_address),
        static_cast<uintptr_t>(req.physical_address),
        static_cast<size_t>(req.page_size),
        static_cast<size_t>(req.page_offset),
    };
}

Result<void> KernelDriverClient::hidePid(pid_t pid) {
    if (fd_ < 0)
        return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
    cecore_kmod_hide_request req{};
    req.pid = static_cast<__u32>(pid);
    if (::ioctl(fd_, CECORE_KMOD_IOC_HIDE_PID, &req) < 0)
        return std::unexpected(std::error_code(errno, std::generic_category()));
    return {};
}

Result<void> KernelDriverClient::unhidePid(pid_t pid) {
    if (fd_ < 0)
        return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
    cecore_kmod_hide_request req{};
    req.pid = static_cast<__u32>(pid);
    if (::ioctl(fd_, CECORE_KMOD_IOC_UNHIDE_PID, &req) < 0)
        return std::unexpected(std::error_code(errno, std::generic_category()));
    return {};
}

Result<size_t> KernelDriverClient::accessProcessMemory(
    unsigned long request,
    pid_t pid,
    uintptr_t address,
    void* buffer,
    size_t size) {
    if (fd_ < 0)
        return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
    if (!buffer && size != 0)
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));

    cecore_kmod_mem_request mem{};
    mem.pid = static_cast<__u32>(pid);
    mem.remote_address = address;
    mem.user_buffer = reinterpret_cast<__u64>(buffer);
    mem.size = size;

    if (::ioctl(fd_, request, &mem) < 0)
        return std::unexpected(std::error_code(errno, std::generic_category()));
    // Defensively clamp: a buggy/spoofed kernel side reporting more bytes than
    // we requested must never let callers use the return value as a transfer
    // count beyond the user buffer.
    return std::min<size_t>(static_cast<size_t>(mem.bytes_transferred), size);
}

Result<size_t> KernelDriverClient::accessPhysicalMemory(
    unsigned long request,
    uintptr_t physicalAddress,
    void* buffer,
    size_t size) {
    if (fd_ < 0)
        return std::unexpected(std::make_error_code(std::errc::bad_file_descriptor));
    if (!buffer && size != 0)
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));

    cecore_kmod_phys_request mem{};
    mem.physical_address = physicalAddress;
    mem.user_buffer = reinterpret_cast<__u64>(buffer);
    mem.size = size;

    if (::ioctl(fd_, request, &mem) < 0)
        return std::unexpected(std::error_code(errno, std::generic_category()));
    // See accessProcessMemory: clamp the reported count to the requested size.
    return std::min<size_t>(static_cast<size_t>(mem.bytes_transferred), size);
}

} // namespace ce::os
