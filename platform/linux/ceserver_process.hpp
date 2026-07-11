#pragma once
/// ProcessHandle implementation backed by a remote ceserver. Lets the rest of
/// cecore (scanner, debugger UI, etc.) treat a remote target the same as a local
/// /proc-backed one.
///
/// Construction opens a process handle on the server. Destruction closes it.
/// The owning CEServerClient must outlive this handle.

#include "platform/process_api.hpp"
#include "platform/linux/ceserver_client.hpp"

#include <memory>

namespace ce::os {

class RemoteProcessHandle : public ProcessHandle {
public:
    /// Open `pid` on the supplied client. Returns nullptr if the OPENPROCESS
    /// command fails or the server returns a zero handle.
    static std::unique_ptr<RemoteProcessHandle> open(CEServerClient& client, pid_t pid);

    ~RemoteProcessHandle() override;

    pid_t pid() const override { return pid_; }
    bool is64bit() const override { return is64bit_; }

    Result<size_t> read(uintptr_t address, void* buffer, size_t size) override;
    Result<size_t> write(uintptr_t address, const void* buffer, size_t size) override;

    std::vector<MemoryRegion> queryRegions() override;
    std::optional<MemoryRegion> queryRegion(uintptr_t address) override;

    Result<uintptr_t> allocate(size_t size, MemProt protection, uintptr_t preferredBase = 0) override;
    Result<void> free(uintptr_t address, size_t size) override;
    Result<void> protect(uintptr_t address, size_t size, MemProt newProtection) override;

    std::vector<ModuleInfo> modules() override;
    std::vector<ThreadInfo> threads() override;

    int32_t serverHandle() const { return handle_; }

private:
    RemoteProcessHandle(CEServerClient& client, pid_t pid, int32_t handle, bool is64bit)
        : client_(&client), pid_(pid), handle_(handle), is64bit_(is64bit) {}

    CEServerClient* client_;
    pid_t pid_;
    int32_t handle_;
    bool is64bit_;
};

} // namespace ce::os
