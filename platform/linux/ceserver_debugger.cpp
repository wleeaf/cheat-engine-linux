/// RemoteDebugger — Debugger interface implementation forwarding through
/// CEServerClient.

#include "platform/linux/ceserver_debugger.hpp"

#include <cstring>
#include <system_error>
#include <vector>

namespace ce::os {

namespace {
Error remoteIo() { return std::make_error_code(std::errc::io_error); }
Error remoteNotImpl() { return std::make_error_code(std::errc::not_supported); }

// Wire layout matches ceserver/context.h on Linux x86_64:
//   uint32  structsize
//   uint32  type
//   user_regs_struct regs (27 * uint64 — see below)
//   user_fpregs_struct fp (FP/SSE state, optional for our purposes)
// All fields are #pragma pack(1)-packed.
//
// user_regs_struct field order (kernel ABI):
//   r15, r14, r13, r12, rbp, rbx, r11, r10, r9, r8,
//   rax, rcx, rdx, rsi, rdi, orig_rax, rip, cs, eflags, rsp,
//   ss, fs_base, gs_base, ds, es, fs, gs
// 27 fields * 8 bytes = 216 bytes.
constexpr size_t kX86_64HeaderSize  = 4 + 4;        // structsize + type
constexpr size_t kX86_64RegsCount   = 27;
constexpr size_t kX86_64RegsSize    = kX86_64RegsCount * sizeof(uint64_t);
constexpr size_t kX86_64GeneralEnd  = kX86_64HeaderSize + kX86_64RegsSize;

bool decodeX86_64Context(const std::vector<uint8_t>& blob, CpuContext& out) {
    if (blob.size() < kX86_64GeneralEnd) return false;
    uint64_t r[kX86_64RegsCount] = {};
    std::memcpy(r, blob.data() + kX86_64HeaderSize, kX86_64RegsSize);
    out.r15  = r[0];  out.r14  = r[1];  out.r13  = r[2];  out.r12 = r[3];
    out.rbp  = r[4];  out.rbx  = r[5];  out.r11  = r[6];  out.r10 = r[7];
    out.r9   = r[8];  out.r8   = r[9];
    out.rax  = r[10]; out.rcx  = r[11]; out.rdx  = r[12]; out.rsi = r[13];
    out.rdi  = r[14]; /* r[15] = orig_rax — discard */
    out.rip  = r[16]; out.cs   = r[17]; out.rflags = r[18]; out.rsp = r[19];
    out.ss   = r[20]; /* r[21] = fs_base, r[22] = gs_base — not in CpuContext */
    out.ds   = r[23]; out.es   = r[24]; out.fs   = r[25]; out.gs   = r[26];
    // Debug registers don't ride along with CMD_GETTHREADCONTEXT; they're
    // managed separately via CMD_SETBREAKPOINT.
    out.dr0 = out.dr1 = out.dr2 = out.dr3 = out.dr6 = out.dr7 = 0;
    return true;
}

// Encode a CpuContext back into a fresh blob matching ceserver's wire format.
// We synthesize structsize as (header + 27*8) so the server only reads what it
// expects; FP regs are intentionally omitted (server tolerates short blobs).
std::vector<uint8_t> encodeX86_64Context(const CpuContext& ctx) {
    std::vector<uint8_t> blob(kX86_64GeneralEnd);
    uint32_t structSize = static_cast<uint32_t>(blob.size());
    uint32_t type = 0;
    std::memcpy(blob.data() + 0, &structSize, sizeof(structSize));
    std::memcpy(blob.data() + 4, &type,       sizeof(type));

    uint64_t r[kX86_64RegsCount] = {};
    r[0]  = ctx.r15; r[1]  = ctx.r14; r[2]  = ctx.r13; r[3]  = ctx.r12;
    r[4]  = ctx.rbp; r[5]  = ctx.rbx; r[6]  = ctx.r11; r[7]  = ctx.r10;
    r[8]  = ctx.r9;  r[9]  = ctx.r8;
    r[10] = ctx.rax; r[11] = ctx.rcx; r[12] = ctx.rdx; r[13] = ctx.rsi;
    r[14] = ctx.rdi; /* r[15] = orig_rax kept zero */
    r[16] = ctx.rip; r[17] = ctx.cs;  r[18] = ctx.rflags; r[19] = ctx.rsp;
    r[20] = ctx.ss;  /* r[21]/r[22] fs_base/gs_base kept zero */
    r[23] = ctx.ds;  r[24] = ctx.es;  r[25] = ctx.fs;  r[26] = ctx.gs;
    std::memcpy(blob.data() + kX86_64HeaderSize, r, kX86_64RegsSize);
    return blob;
}

} // namespace

RemoteDebugger::RemoteDebugger(CEServerClient& client, int32_t serverHandle)
    : client_(&client), handle_(serverHandle) {}

RemoteDebugger::~RemoteDebugger() {
    if (attached_) {
        // Best-effort detach so the remote target isn't left in a debug state.
        client_->stopDebug(handle_);
    }
}

Result<void> RemoteDebugger::attach(pid_t /*pid*/) {
    auto r = client_->startDebug(handle_);
    if (!r || *r == 0) return std::unexpected(remoteIo());
    attached_ = true;
    return {};
}

Result<void> RemoteDebugger::detach() {
    if (!attached_) return {};
    auto r = client_->stopDebug(handle_);
    attached_ = false;
    if (!r) return std::unexpected(remoteIo());
    return {};
}

Result<CpuContext> RemoteDebugger::getContext(pid_t tid) {
    auto blob = client_->getThreadContext(handle_, static_cast<uint32_t>(tid));
    if (!blob || blob->empty()) return std::unexpected(remoteIo());
    CpuContext ctx{};
    if (!decodeX86_64Context(*blob, ctx)) return std::unexpected(remoteNotImpl());
    return ctx;
}

Result<void> RemoteDebugger::setContext(pid_t tid, const CpuContext& ctx) {
    auto blob = encodeX86_64Context(ctx);
    auto r = client_->setThreadContext(handle_, static_cast<uint32_t>(tid),
                                       blob.data(), static_cast<uint32_t>(blob.size()));
    if (!r || *r == 0) return std::unexpected(remoteIo());
    return {};
}

Result<void> RemoteDebugger::suspend(pid_t tid) {
    auto r = client_->suspendThread(handle_, static_cast<int32_t>(tid));
    if (!r || *r == 0) return std::unexpected(remoteIo());
    return {};
}

Result<void> RemoteDebugger::resume(pid_t tid) {
    auto r = client_->resumeThread(handle_, static_cast<int32_t>(tid));
    if (!r || *r == 0) return std::unexpected(remoteIo());
    return {};
}

Result<void> RemoteDebugger::singleStep(pid_t /*tid*/) {
    // CE protocol has no dedicated single-step command. Implementations set
    // EFLAGS.TF=1 via CMD_SETTHREADCONTEXT, then call
    // CMD_CONTINUEFROMDEBUGEVENT. That requires the per-arch CONTEXT layout
    // — TODO once getContext/setContext are implemented.
    return std::unexpected(remoteNotImpl());
}

Result<void>
RemoteDebugger::setBreakpoint(pid_t tid, int reg, uintptr_t address, int type, int size) {
    auto r = client_->setRemoteBreakpoint(
        handle_, static_cast<int32_t>(tid), reg, address, type, size);
    if (!r || *r == 0) return std::unexpected(remoteIo());
    return {};
}

Result<void> RemoteDebugger::removeBreakpoint(pid_t tid, int reg) {
    auto r = client_->removeRemoteBreakpoint(
        handle_,
        static_cast<uint32_t>(tid),
        static_cast<uint32_t>(reg),
        /*wasWatchpoint=*/0);
    if (!r || *r == 0) return std::unexpected(remoteIo());
    return {};
}

std::optional<CeDebugEvent> RemoteDebugger::waitForEvent(int timeoutMs) {
    auto r = client_->waitForDebugEvent(handle_, timeoutMs);
    if (!r) return std::nullopt;
    return *r;
}

Result<void> RemoteDebugger::continueAfterEvent(pid_t tid, int signalToForward) {
    auto r = client_->continueFromDebugEvent(handle_, static_cast<int32_t>(tid), signalToForward);
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
    auto blob = client_->getThreadContext(handle_, static_cast<uint32_t>(tid));
    if (!blob || blob->size() < kHeaderBytes + kArm32GeneralBytes) return std::nullopt;
    Arm32Context out{};
    std::memcpy(out.regs.data(), blob->data() + kHeaderBytes, kArm32GeneralBytes);
    return out;
}

} // namespace ce::os
