#pragma once
/// User-space client for the optional cecore kernel helper.

#include "kernel/cecore_kmod.h"
#include "platform/process_api.hpp"

#include <string>

namespace ce::os {

struct VirtualAddressTranslation {
    uintptr_t virtualAddress = 0;
    uintptr_t physicalAddress = 0;
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
    Result<size_t> readPhysicalMemory(uintptr_t physicalAddress, void* buffer, size_t size);
    Result<size_t> writePhysicalMemory(uintptr_t physicalAddress, const void* buffer, size_t size);
    Result<VirtualAddressTranslation> translateVirtualAddress(pid_t pid, uintptr_t virtualAddress);

private:
    Result<size_t> accessProcessMemory(
        unsigned long request,
        pid_t pid,
        uintptr_t address,
        void* buffer,
        size_t size);
    Result<size_t> accessPhysicalMemory(
        unsigned long request,
        uintptr_t physicalAddress,
        void* buffer,
        size_t size);

    int fd_ = -1;
};

} // namespace ce::os
