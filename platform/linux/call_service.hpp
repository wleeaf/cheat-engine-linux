#pragma once

#include "platform/linux/target_syscall.hpp"
#include <atomic>

namespace ce::os {
class NativeMemoryImage;

struct NativeThreadRange { uintptr_t address=0; size_t size=0; };
struct NativeCallRequest {
    std::shared_ptr<NativeMemoryImage> image;
    uintptr_t function=0;
    std::array<uint64_t,8> arguments{};
    std::vector<uint8_t> data;
    // Selected arguments are offsets into data/output storage.
    uint8_t dataArguments=0;
    size_t outputSize=0;
    int timeoutMs=5000;
    bool forwardSignals=false;
    // pthread_create can complete after its caller has received an error.
    // Detach its successful, unreturned handle before releasing storage.
    uintptr_t orphanDetach=0;
    // A pthread entry wrapped by the owner, with storage pinned until kernel exit.
    uintptr_t workerEntry=0;
    std::vector<NativeThreadRange> workerRanges;
};
struct NativeCallResult {
    uint64_t value=0;
    std::vector<uint8_t> data;
    struct ThreadLease {
        std::shared_ptr<std::atomic<bool>> released=std::make_shared<std::atomic<bool>>(false);
        // Only after the target successfully joins or detaches this handle.
        void release() { released->store(true,std::memory_order_release); }
    };
    std::shared_ptr<ThreadLease> threadLease;
    struct WorkerState {
        pid_t tid=0;
        std::atomic<bool> exited{false};
    };
    std::shared_ptr<WorkerState> worker;
};

// Runs on TargetSyscallService's existing ptrace owner, with no second worker.
// Private frames and attachments survive frontend destruction and call errors.
class NativeCallOwner {
public:
    NativeCallOwner();
    ~NativeCallOwner();
    std::expected<NativeCallResult,std::error_code> invoke(
        const TargetProcessIdentity&,const TargetMachine&,NativeCallRequest);
    std::expected<void,std::error_code> recover(const TargetProcessIdentity&);
    std::expected<void,std::error_code> resume(const TargetProcessIdentity&,bool deliverSignal);
    void recoverAll();
    bool pending(pid_t,uint64_t) const;
    bool empty() const;
    bool busy(pid_t,uintptr_t,size_t) const;
    // Process exit can leave fully detached workers running in the target.
    // Their wrappers must already permit ordinary return without their owner.
    void releaseDetachedWorkersAtProcessExit();
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ce::os
