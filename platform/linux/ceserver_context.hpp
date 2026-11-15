#pragma once
/// The x86-64 thread context as ceserver sends it (CMD_GETTHREADCONTEXT and
/// CMD_SETTHREADCONTEXT), shared by the client and this project's server.

#include "core/types.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace ce::os {

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
inline constexpr size_t kCeserverX86_64HeaderSize  = 4 + 4;        // structsize + type
inline constexpr size_t kCeserverX86_64RegsCount   = 27;
inline constexpr size_t kCeserverX86_64RegsSize    = kCeserverX86_64RegsCount * sizeof(uint64_t);
inline constexpr size_t kCeserverX86_64GeneralEnd  = kCeserverX86_64HeaderSize + kCeserverX86_64RegsSize;

inline bool decodeCeserverX86_64Context(const std::vector<uint8_t>& blob, CpuContext& out) {
    if (blob.size() < kCeserverX86_64GeneralEnd) return false;
    uint64_t r[kCeserverX86_64RegsCount] = {};
    std::memcpy(r, blob.data() + kCeserverX86_64HeaderSize, kCeserverX86_64RegsSize);
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
inline std::vector<uint8_t> encodeCeserverX86_64Context(const CpuContext& ctx) {
    std::vector<uint8_t> blob(kCeserverX86_64GeneralEnd);
    uint32_t structSize = static_cast<uint32_t>(blob.size());
    uint32_t type = 0;
    std::memcpy(blob.data() + 0, &structSize, sizeof(structSize));
    std::memcpy(blob.data() + 4, &type,       sizeof(type));

    uint64_t r[kCeserverX86_64RegsCount] = {};
    r[0]  = ctx.r15; r[1]  = ctx.r14; r[2]  = ctx.r13; r[3]  = ctx.r12;
    r[4]  = ctx.rbp; r[5]  = ctx.rbx; r[6]  = ctx.r11; r[7]  = ctx.r10;
    r[8]  = ctx.r9;  r[9]  = ctx.r8;
    r[10] = ctx.rax; r[11] = ctx.rcx; r[12] = ctx.rdx; r[13] = ctx.rsi;
    r[14] = ctx.rdi; /* r[15] = orig_rax kept zero */
    r[16] = ctx.rip; r[17] = ctx.cs;  r[18] = ctx.rflags; r[19] = ctx.rsp;
    r[20] = ctx.ss;  /* r[21]/r[22] fs_base/gs_base kept zero */
    r[23] = ctx.ds;  r[24] = ctx.es;  r[25] = ctx.fs;  r[26] = ctx.gs;
    std::memcpy(blob.data() + kCeserverX86_64HeaderSize, r, kCeserverX86_64RegsSize);
    return blob;
}

} // namespace ce::os
