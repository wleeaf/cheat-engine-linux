#pragma once
/// Linux ptrace wrapper for debugging operations.

#include "platform/process_api.hpp"

#include <vector>

namespace ce::os {

class LinuxDebugger : public Debugger {
public:
    LinuxDebugger() = default;
    ~LinuxDebugger() override;

    Result<void> attach(pid_t pid) override;
    Result<void> detach() override;

    Result<CpuContext> getContext(pid_t tid) override;
    Result<void> setContext(pid_t tid, const CpuContext& ctx) override;

    Result<void> suspend(pid_t tid) override;
    Result<void> resume(pid_t tid) override;
    Result<void> singleStep(pid_t tid) override;

    Result<void> setBreakpoint(pid_t tid, int reg, uintptr_t address, int type, int size) override;
    Result<void> removeBreakpoint(pid_t tid, int reg) override;

    bool isAttached() const { return attached_; }
    pid_t attachedPid() const { return pid_; }

    /// Drain any child PIDs that the kernel has reported via
    /// PTRACE_EVENT_FORK / VFORK / CLONE since the last call. Each returned
    /// pid is automatically re-armed with the same trace options so the
    /// follow-fork chain keeps going. Safe to call frequently; non-blocking.
    Result<std::vector<pid_t>> pollChildren();

private:
    pid_t pid_ = 0;
    bool attached_ = false;

    static Error errFromErrno();
};

} // namespace ce::os
