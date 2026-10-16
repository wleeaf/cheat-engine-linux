#pragma once
/// User-space client for the optional cecore kernel helper.
///
/// The module only reads physical System RAM. Process memory and the virtual
/// to physical translation go through /proc/<pid>/mem and /proc/<pid>/pagemap,
/// where the kernel applies its ptrace, Yama and LSM checks (a module cannot).
/// Every call still needs an open session so callers see one availability
/// state.

#include "kernel/cecore_kmod.h"
#include "platform/process_api.hpp"

#include <cstdint>
#include <string>

namespace ce::os {

struct VirtualAddressTranslation {
    uintptr_t virtualAddress = 0;
    uint64_t physicalAddress = 0;
    size_t pageSize = 0;
    size_t pageOffset = 0;
};

class KernelDriverClient {
public:
    KernelDriverClient() = default;
    ~KernelDriverClient();

    KernelDriverClient(const KernelDriverClient&) = delete;
    KernelDriverClient& operator=(const KernelDriverClient&) = delete;

    bool open(const std::string& path = CECORE_KMOD_PATH);
    void close();
    bool isOpen() const { return fd_ >= 0; }

    Result<size_t> readProcessMemory(pid_t pid, uintptr_t address, void* buffer, size_t size);
    Result<size_t> writeProcessMemory(pid_t pid, uintptr_t address, const void* buffer, size_t size);
    /// Reads online System RAM only (EINVAL for MMIO and holes). There is no
    /// physical write: a translated frame can be freed or shared by the time
    /// it is written, so writes go through writeProcessMemory.
    Result<size_t> readPhysicalMemory(uint64_t physicalAddress, void* buffer, size_t size);
    /// A snapshot: the page can move or be freed as soon as this returns.
    /// Needs CAP_SYS_ADMIN for the frame number (EPERM otherwise).
    Result<VirtualAddressTranslation> translateVirtualAddress(pid_t pid, uintptr_t virtualAddress);

private:
    Result<size_t> accessProcessMemory(
        bool write,
        pid_t pid,
        uintptr_t address,
        void* buffer,
        size_t size);

    int fd_ = -1;
};

} // namespace ce::os
