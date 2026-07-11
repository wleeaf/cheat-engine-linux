#pragma once
/// Linux implementation of ProcessHandle, ProcessEnumerator, and Debugger.
/// Uses process_vm_readv/writev and /proc filesystem directly (no ceserver socket).

#include "platform/process_api.hpp"
#include <memory>

namespace ce::os {

class LinuxProcessHandle : public ProcessHandle {
public:
    explicit LinuxProcessHandle(pid_t pid);
    ~LinuxProcessHandle() override;

    pid_t pid() const override { return pid_; }
    bool is64bit() const override { return is64bit_; }
    bool runs32BitCode() override;

    Result<size_t> read(uintptr_t address, void* buffer, size_t size) override;
    Result<size_t> write(uintptr_t address, const void* buffer, size_t size) override;

    std::vector<MemoryRegion> queryRegions() override;
    std::optional<MemoryRegion> queryRegion(uintptr_t address) override;

    Result<uintptr_t> allocate(size_t size, MemProt protection, uintptr_t preferredBase = 0) override;
    Result<void> free(uintptr_t address, size_t size) override;
    Result<void> protect(uintptr_t address, size_t size, MemProt newProtection) override;

    std::vector<ModuleInfo> modules() override;
    std::vector<ThreadInfo> threads() override;

private:
    pid_t pid_;
    bool is64bit_;
    int runs32_ = -1;   // cache for runs32BitCode(): -1 unknown, 0 no, 1 yes

    MemProt parsePerms(const std::string& perms) const;
    bool detectIs64Bit() const;
    // Read Wine PE headers from memory to add real PE modules (base/size/name/
    // bitness) that /proc-maps collapsing would otherwise mis-attribute.
    void enumeratePeModules(std::vector<ModuleInfo>& mods,
                            const std::vector<MemoryRegion>& regions);
};

class LinuxProcessEnumerator : public ProcessEnumerator {
public:
    std::vector<ProcessInfo> list() override;
    std::unique_ptr<ProcessHandle> open(pid_t pid) override;
};

} // namespace ce::os
