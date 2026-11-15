/// RemoteDebugger — Debugger interface implementation forwarding through
/// CEServerClient.

#include "platform/linux/ceserver_debugger.hpp"
#include "platform/linux/ceserver_context.hpp"

#include <chrono>
#include <cstring>
#include <system_error>
#include <vector>

namespace ce::os {

namespace {
Error remoteIo() { return std::make_error_code(std::errc::io_error); }
Error remoteNotImpl() { return std::make_error_code(std::errc::not_supported); }

} // namespace

RemoteDebugger::RemoteDebugger(CEServerClient& client, int32_t serverHandle)
    : client_(&client), handle_(serverHandle), generation_(client.connectionGeneration()) {}

RemoteDebugger::~RemoteDebugger() {
    auto operation=client_->lockConnection();
    if (attached_ && connectionValid()) {
        // Best-effort detach so the remote target isn't left in a debug state.
        (void)client_->stopDebug(handle_);
    }
}

Result<void> RemoteDebugger::attach(pid_t /*pid*/) {
    auto operation=client_->lockConnection();
    if (!connectionValid()) return std::unexpected(std::make_error_code(std::errc::not_connected));
    auto r = client_->startDebug(handle_);
    if (!r || *r == 0) return std::unexpected(remoteIo());
    attached_ = true;
    return {};
}

Result<void> RemoteDebugger::detach() {
    auto operation=client_->lockConnection();
    if (!attached_) return {};
    if (!connectionValid()) {
        attached_=false;
        return std::unexpected(std::make_error_code(std::errc::not_connected));
    }
    auto r = client_->stopDebug(handle_);
    attached_ = false;
    if (!r || !*r) return std::unexpected(remoteIo());
    return {};
}

Result<CpuContext> RemoteDebugger::getContext(pid_t tid) {
    auto operation=client_->lockConnection();
    if (!connectionValid()) return std::unexpected(std::make_error_code(std::errc::not_connected));
    auto blob = client_->getThreadContext(handle_, static_cast<uint32_t>(tid));
    if (!blob || blob->empty()) return std::unexpected(remoteIo());
    CpuContext ctx{};
    if (!decodeCeserverX86_64Context(*blob, ctx)) return std::unexpected(remoteNotImpl());
    return ctx;
}

Result<void> RemoteDebugger::setContext(pid_t tid, const CpuContext& ctx) {
    auto operation=client_->lockConnection();
    if (!connectionValid()) return std::unexpected(std::make_error_code(std::errc::not_connected));
    auto blob = encodeCeserverX86_64Context(ctx);
    auto r = client_->setThreadContext(handle_, static_cast<uint32_t>(tid),
                                       blob.data(), static_cast<uint32_t>(blob.size()));
    if (!r || *r == 0) return std::unexpected(remoteIo());
    return {};
}

Result<void> RemoteDebugger::suspend(pid_t tid) {
    auto operation=client_->lockConnection();
    if (!connectionValid()) return std::unexpected(std::make_error_code(std::errc::not_connected));
    auto r = client_->suspendThread(handle_, static_cast<int32_t>(tid));
    if (!r || *r == 0) return std::unexpected(remoteIo());
    return {};
}

Result<void> RemoteDebugger::resume(pid_t tid) {
    auto operation=client_->lockConnection();
    if (!connectionValid()) return std::unexpected(std::make_error_code(std::errc::not_connected));
    auto r = client_->resumeThread(handle_, static_cast<int32_t>(tid));
    if (!r || *r == 0) return std::unexpected(remoteIo());
    return {};
}

// ceserver has no step command: upstream single-steps a thread stopped at a
// debug event when it is continued with option 2, and reports the step's end
// as a SIGTRAP event. Like a local single step, this waits for that stop, so
// the caller reads the new registers next. Another thread's stop meanwhile
// (an upstream server does not stop the other threads) is continued.
Result<void> RemoteDebugger::singleStep(pid_t tid) {
    {
        auto operation=client_->lockConnection();
        if (!connectionValid()) return std::unexpected(std::make_error_code(std::errc::not_connected));
        auto r = client_->continueFromDebugEvent(handle_, static_cast<int32_t>(tid), kContinueSingleStep);
        if (!r || *r == 0) return std::unexpected(remoteIo());
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (std::chrono::steady_clock::now() < deadline) {
        if (!connectionValid()) return std::unexpected(std::make_error_code(std::errc::not_connected));
        auto event = waitForEvent(200);
        if (!event) continue;
        if (event->threadId == tid) return {};
        (void)continueAfterEvent(static_cast<pid_t>(event->threadId));
    }
    return std::unexpected(std::make_error_code(std::errc::timed_out));
}

Result<void>
RemoteDebugger::setBreakpoint(pid_t tid, int reg, uintptr_t address, int type, int size) {
    auto operation=client_->lockConnection();
    if (!connectionValid()) return std::unexpected(std::make_error_code(std::errc::not_connected));
    // The interface takes the x86 DR7 length code (0=1, 1=2, 3=4, 2=8 bytes);
    // the wire carries the length in bytes.
    if (size < 0 || size > 3) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    constexpr int32_t lengths[] = {1, 2, 8, 4};
    auto r = client_->setRemoteBreakpoint(
        handle_, static_cast<int32_t>(tid), reg, address, type, lengths[size]);
    if (!r || *r == 0) return std::unexpected(remoteIo());
    return {};
}

Result<void> RemoteDebugger::removeBreakpoint(pid_t tid, int reg) {
    auto operation=client_->lockConnection();
    if (!connectionValid()) return std::unexpected(std::make_error_code(std::errc::not_connected));
    auto r = client_->removeRemoteBreakpoint(
        handle_,
        static_cast<uint32_t>(tid),
        static_cast<uint32_t>(reg),
        /*wasWatchpoint=*/0);
    if (!r || *r == 0) return std::unexpected(remoteIo());
    return {};
}

std::optional<CeDebugEvent> RemoteDebugger::waitForEvent(int timeoutMs) {
    auto operation=client_->lockConnection();
    if (!connectionValid()) return std::nullopt;
    auto r = client_->waitForDebugEvent(handle_, timeoutMs);
    if (!r) return std::nullopt;
    return *r;
}

std::optional<Debugger::Stop> RemoteDebugger::waitForStop(int timeoutMs) {
    auto event = waitForEvent(timeoutMs);
    if (!event) return std::nullopt;
    return Stop{static_cast<pid_t>(event->threadId), event->debugEvent, static_cast<uintptr_t>(event->address)};
}

Result<void> RemoteDebugger::continueAfterEvent(pid_t tid, int option) {
    auto operation=client_->lockConnection();
    if (!connectionValid()) return std::unexpected(std::make_error_code(std::errc::not_connected));
    auto r = client_->continueFromDebugEvent(handle_, static_cast<int32_t>(tid), option);
    if (!r || *r == 0) return std::unexpected(remoteIo());
    return {};
}

// ── ARM64 / ARM32 raw context decode ──
//
// CE's CONTEXT blob layout on aarch64 (#pragma pack(1)):
//   uint32 structsize
//   uint32 type
//   user_pt_regs: uint64 x[31], sp, pc, pstate          (272 bytes)
//   user_fpsimd_state: vregs[32]*16, fpsr, fpcr, pad    (528 bytes, optional)
//
// On 32-bit ARM:
//   uint32 structsize
//   uint32 type
//   uint32 uregs[18]                                    (72 bytes)
//   fp regs (CE struct, variable)
//
// We read just the general regs — FP/SIMD requires a separate decoder and
// no consumer uses it yet.
constexpr size_t kHeaderBytes        = 8;          // structsize + type
constexpr size_t kArm64GeneralBytes  = 34 * 8;     // 31 x + sp + pc + pstate
constexpr size_t kArm32GeneralBytes  = 18 * 4;     // uregs[18]

std::optional<Arm64Context> RemoteDebugger::getArm64Context(pid_t tid) {
    auto operation=client_->lockConnection();
    if (!connectionValid()) return std::nullopt;
    auto blob = client_->getThreadContext(handle_, static_cast<uint32_t>(tid));
    if (!blob || blob->size() < kHeaderBytes + kArm64GeneralBytes) return std::nullopt;
    Arm64Context out{};
    std::memcpy(out.x.data(), blob->data() + kHeaderBytes, 31 * 8);
    std::memcpy(&out.sp,     blob->data() + kHeaderBytes + 31 * 8,      8);
    std::memcpy(&out.pc,     blob->data() + kHeaderBytes + 32 * 8,      8);
    std::memcpy(&out.pstate, blob->data() + kHeaderBytes + 33 * 8,      8);
    return out;
}

std::optional<Arm32Context> RemoteDebugger::getArm32Context(pid_t tid) {
    auto operation=client_->lockConnection();
    if (!connectionValid()) return std::nullopt;
    auto blob = client_->getThreadContext(handle_, static_cast<uint32_t>(tid));
    if (!blob || blob->size() < kHeaderBytes + kArm32GeneralBytes) return std::nullopt;
    Arm32Context out{};
    std::memcpy(out.regs.data(), blob->data() + kHeaderBytes, kArm32GeneralBytes);
    return out;
}

} // namespace ce::os
