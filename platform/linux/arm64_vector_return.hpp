#pragma once

#include "platform/linux/register_image.hpp"
#include "platform/linux/target_syscall.hpp"
#if defined(__aarch64__)
#include <asm/ptrace.h>
#include <signal.h>

namespace ce::os {

// Memory syscalls do not change vector lengths or ZA/ZT. Return their live
// vector state through the signal ABI, which avoids the vector-length setter
// and therefore preserves deferred exec-time lengths. Only a user-mode stop
// on a kernel-labelled main stack with no pending syscall, active GCS or
// seccomp filter can use this path.
struct Arm64VectorReturn {
    uintptr_t address=0,syscallAddress=0;
    uint64_t signalMask=0;
    std::vector<uint8_t> frame,original,verification;
    bool frameChanged=false,contextRestored=false,memoryWritable=false;

    static Result<std::optional<Arm64VectorReturn>> prepare(
        pid_t tid,int memoryFd,uintptr_t syscallAddress,const user_pt_regs& registers,
        int originalSyscall,const NativeExtendedContext& saved,MemorySyscall operation,
        const std::array<uint64_t,6>& arguments);
    Result<void> restore(pid_t tid,int memoryFd,const user_pt_regs& registers,
        NativeExtendedContext& saved,int& pendingSignal,std::optional<siginfo_t>& pendingInfo,
        bool& pendingStepTrap,uintptr_t& stepEnd);
};

} // namespace ce::os
#endif
