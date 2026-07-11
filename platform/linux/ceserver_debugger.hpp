#pragma once
/// Debugger interface backed by a remote ceserver. Lets the existing
/// breakpoint manager and code-finder UIs run against a remote target with
/// no API changes — pass a RemoteDebugger* anywhere the local LinuxDebugger
/// would have gone.
///
/// Construction does not start debugging; call attach() to issue
/// CMD_STARTDEBUG. detach() issues CMD_STOPDEBUG. The `pid` argument to
/// attach() is informational (the server already knows the target via the
/// handle that was passed to open()).
///
/// getContext / setContext require parsing the architecture-specific CONTEXT
/// blob that ceserver returns. The current implementation returns
/// std::errc::not_supported for these — workaround until the per-arch
/// marshalling is wired.

#include "platform/process_api.hpp"
#include "platform/linux/ceserver_client.hpp"

#include <memory>
#include <optional>
#include <array>

namespace ce::os {

/// ARM64 general register context as ceserver delivers it
/// (user_pt_regs: x0..x30, sp, pc, pstate).
struct Arm64Context {
    std::array<uint64_t, 31> x;   // x0..x30
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

/// ARM32 general register context (CE wires struct pt_regs ≈ uregs[18]).
struct Arm32Context {
    std::array<uint32_t, 18> regs;  // r0..r12, sp, lr, pc, cpsr, orig_r0
};


class RemoteDebugger : public Debugger {
public:
    /// `client` and `serverHandle` together identify the remote target.
    /// Caller retains ownership of the client; it must outlive the debugger.
    RemoteDebugger(CEServerClient& client, int32_t serverHandle);
    ~RemoteDebugger() override;

    Result<void> attach(pid_t pid) override;
    Result<void> detach() override;

    Result<CpuContext> getContext(pid_t tid) override;
    Result<void>       setContext(pid_t tid, const CpuContext& ctx) override;

    Result<void> suspend(pid_t tid) override;
    Result<void> resume(pid_t tid) override;
    Result<void> singleStep(pid_t tid) override;

    Result<void> setBreakpoint(pid_t tid, int reg, uintptr_t address, int type, int size) override;
    Result<void> removeBreakpoint(pid_t tid, int reg) override;

    /// Convenience wrappers around CMD_WAITFORDEBUGEVENT /
    /// CMD_CONTINUEFROMDEBUGEVENT — a debug-event loop wraps these.
    std::optional<CeDebugEvent> waitForEvent(int timeoutMs);
    Result<void> continueAfterEvent(pid_t tid, int signalToForward = 0);

    /// ARM64-specific decode of CMD_GETTHREADCONTEXT into x0..x30 + sp + pc
    /// + pstate. Returns nullopt on parse failure (wrong blob size for
    /// this arch). Use this against an aarch64 ceserver target instead of
    /// getContext(), which is x86_64-only.
    std::optional<Arm64Context> getArm64Context(pid_t tid);

    /// ARM32-specific decode covering 18 * uint32 pt_regs (r0..r12, sp, lr,
    /// pc, cpsr, orig_r0).
    std::optional<Arm32Context> getArm32Context(pid_t tid);

    int32_t serverHandle() const { return handle_; }

private:
    CEServerClient* client_;
    int32_t handle_;
    bool attached_ = false;
};

} // namespace ce::os
