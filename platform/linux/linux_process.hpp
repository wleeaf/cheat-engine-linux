#pragma once
/// Linux implementation of ProcessHandle, ProcessEnumerator, and Debugger.
/// Uses process_vm_readv/writev and /proc filesystem directly (no ceserver socket).

#include "platform/process_api.hpp"
#include <memory>
#include <atomic>
#include <mutex>

namespace ce::os {
class NativeMemoryImage;

class LinuxProcessHandle : public ProcessHandle {
public:
    explicit LinuxProcessHandle(pid_t pid);
    ~LinuxProcessHandle() override;

    pid_t pid() const override { return pid_; }
    bool is64bit() const override { return is64bit_; }
    bool runs32BitCode() override;
    TargetDescription targetDescription() override;
    TargetMachine machineAt(uintptr_t address) override;

    bool supportsConcurrentReads() const override { return true; }
    Result<size_t> read(uintptr_t address, void* buffer, size_t size) override;
    Result<size_t> write(uintptr_t address, const void* buffer, size_t size) override;
    Result<size_t> writeCode(uintptr_t address,const void* buffer,size_t size) override;
    void readMany(const uintptr_t* addrs, size_t count, size_t size,
                  uint8_t* out, uint8_t* ok) override;

    std::vector<MemoryRegion> queryRegions() override;
    std::optional<MemoryRegion> queryRegion(uintptr_t address) override;
    std::vector<std::pair<uintptr_t, uintptr_t>>
    residentRanges(uintptr_t base, size_t size) override;

    Result<uintptr_t> allocate(size_t size, MemProt protection, uintptr_t preferredBase = 0) override;
    Result<void> free(uintptr_t address, size_t size) override;
    Result<void> protect(uintptr_t address, size_t size, MemProt newProtection) override;
    Result<uintptr_t> allocateInImage(size_t,MemProt,uintptr_t,const NativeMemoryImage*);
    Result<void> freeInImage(uintptr_t,size_t,const NativeMemoryImage*);
    Result<void> protectInImage(uintptr_t,size_t,MemProt,const NativeMemoryImage*);
    Result<void> retryPendingOperations() override;
    Result<void> resumePendingCallSignal(bool deliverSignal) override;

    std::vector<ModuleInfo> modules() override;
    std::vector<ThreadInfo> threads() override;

private:
    pid_t pid_;
    std::atomic<bool> is64bit_{true};
    int pidfd_ = -1;
    uint64_t startTime_ = 0;
    uint64_t exeDevice_ = 0, exeInode_ = 0;
    TargetDescription description_;
    bool programKnown_ = false;
    bool wineHint_ = false;
    std::recursive_mutex metadataMutex_;

    MemProt parsePerms(const std::string& perms) const;
    bool sameProcess() const;
    void refreshMachine();
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
