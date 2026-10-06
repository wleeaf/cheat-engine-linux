#pragma once
#include "platform/linux/target_syscall.hpp"
#include "platform/linux/call_service.hpp"
#include <span>
#include <memory>

namespace ce::os {
class NativeMemoryImage;

// One owner thread executes and recovers memory syscalls for every frontend.
// Recovery survives callers and handles. Shutdown drains recovery before the
// owner exits, so ptrace cannot detach an unrestored target implicitly.
class TargetSyscallService {
public:
    explicit TargetSyscallService(bool processLifetime=false);
    ~TargetSyscallService();
    TargetSyscallService(const TargetSyscallService&) = delete;
    TargetSyscallService& operator=(const TargetSyscallService&) = delete;
    std::expected<uint64_t, std::error_code> execute(const TargetProcessIdentity& identity,
        const TargetMachine& host, MemorySyscall operation, std::array<uint64_t, 6> arguments,const NativeMemoryImage* image=nullptr);
    std::expected<void, std::error_code> recover(const TargetProcessIdentity& identity);
    std::expected<size_t,std::error_code> writeCode(const TargetProcessIdentity& identity,
        uintptr_t address,std::span<const uint8_t> bytes,const NativeMemoryImage* image=nullptr);
    std::expected<void,std::error_code> inspectThread(const TargetProcessIdentity& identity,
        const TargetProcessIdentity& processIdentity,const TargetMachine& host,bool registerWrites,
        const std::function<std::expected<void,std::error_code>()>& callback);
    bool pending(pid_t pid, uint64_t startTime);
    bool threadStorageBusy(pid_t pid,uintptr_t address,size_t size);
    std::expected<NativeCallResult,std::error_code> invoke(const TargetProcessIdentity& identity,
        const TargetMachine& host,NativeCallRequest request);
    std::expected<void,std::error_code> resumeCall(const TargetProcessIdentity& identity,bool deliverSignal);
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

TargetSyscallService& memorySyscallService();
bool hasPendingMemorySyscalls(pid_t pid, uint64_t startTime);

} // namespace ce::os
