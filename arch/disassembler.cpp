#include "arch/disassembler.hpp"
#include <capstone/capstone.h>
#include <stdexcept>
#include <format>
#include <cstdio>

namespace ce {

std::string Instruction::toString() const {
    std::string hex;
    for (auto b : bytes)
        hex += std::format("{:02x} ", b);
    return std::format("{:016x}  {:<24s} {} {}", address, hex, mnemonic, operands);
}

Disassembler::Disassembler(Arch arch) : arch_(arch) {
    cs_arch cs_a;
    cs_mode cs_m;

    switch (arch) {
        case Arch::X86_32: cs_a = CS_ARCH_X86; cs_m = CS_MODE_32; break;
        case Arch::X86_64: cs_a = CS_ARCH_X86; cs_m = CS_MODE_64; break;
        case Arch::ARM32:  cs_a = CS_ARCH_ARM; cs_m = CS_MODE_ARM; break;
        case Arch::ARM64:  cs_a = CS_ARCH_ARM64; cs_m = CS_MODE_ARM; break;
    }

    csh h;
    if (cs_open(cs_a, cs_m, &h) != CS_ERR_OK)
        throw std::runtime_error("Failed to initialize Capstone");

    cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
    handle_ = h;
}

Disassembler::~Disassembler() {
    if (handle_)
        cs_close(reinterpret_cast<csh*>(&handle_));
}

// Rewrite a RIP-relative memory operand ("[rip + 0x1234]") to its resolved
// absolute address ("[0x...]"), the way Cheat Engine displays it — much more
// useful than Capstone's raw rip-relative form. Requires CS_OPT_DETAIL (on).
static uintptr_t resolveRipRelative(const cs_insn& in, std::string& ops) {
    if (!in.detail) return 0;
    const cs_x86& x86 = in.detail->x86;
    for (int k = 0; k < x86.op_count; ++k) {
        const cs_x86_op& op = x86.operands[k];
        if (op.type != X86_OP_MEM || op.mem.base != X86_REG_RIP || op.mem.index != X86_REG_INVALID)
            continue;
        uintptr_t abs = in.address + in.size + static_cast<int64_t>(op.mem.disp);
        auto b = ops.find("[rip");
        if (b == std::string::npos) return abs;  // target known even if text unexpected
        auto e = ops.find(']', b);
        if (e == std::string::npos) return abs;
        char buf[32];
        std::snprintf(buf, sizeof(buf), "[0x%llx]", static_cast<unsigned long long>(abs));
        ops.replace(b, e - b + 1, buf);
        return abs;
    }
    return 0;
}

static Instruction buildInstruction(const cs_insn& in) {
    Instruction inst;
    inst.address = in.address;
    inst.size = in.size;
    inst.mnemonic = in.mnemonic;
    inst.operands = in.op_str;
    inst.bytes.assign(in.bytes, in.bytes + in.size);
    inst.ripTarget = resolveRipRelative(in, inst.operands);
    return inst;
}

std::vector<Instruction> Disassembler::disassemble(uintptr_t address, std::span<const uint8_t> code,
                                                   size_t count, bool emitDataBytes) {
    std::vector<Instruction> result;
    size_t offset = 0;

    // Ensure a Capstone-allocated insn array is freed on every exit path.
    struct InsnGuard {
        cs_insn* p = nullptr;
        size_t   n = 0;
        ~InsnGuard() { if (p) cs_free(p, n); }
    };

    while (offset < code.size()) {
        if (count != 0 && result.size() >= count) break;
        size_t want = (count == 0) ? 0 : (count - result.size());

        cs_insn* insn = nullptr;
        size_t n = cs_disasm(static_cast<csh>(handle_), code.data() + offset,
                             code.size() - offset, address + offset, want, &insn);
        InsnGuard guard{insn, n};

        for (size_t i = 0; i < n; ++i)
            result.push_back(buildInstruction(insn[i]));

        if (n > 0)
            offset = (result.back().address - address) + result.back().size;

        // Stop unless we should emit a "db" for the byte Capstone choked on.
        if (!emitDataBytes) break;
        if (count != 0 && result.size() >= count) break;
        if (offset >= code.size()) break;

        Instruction dbi;
        dbi.address = address + offset;
        dbi.size = 1;
        dbi.bytes = {code[offset]};
        dbi.mnemonic = "db";
        char hb[8];
        std::snprintf(hb, sizeof(hb), "0x%02x", code[offset]);
        dbi.operands = hb;
        result.push_back(std::move(dbi));
        offset += 1;
    }

    return result;
}

uintptr_t Disassembler::previousInstruction(uintptr_t addr,
    const std::function<bool(uintptr_t, uint8_t*, size_t)>& read) {
    uintptr_t best = addr ? addr - 1 : addr;
    for (int len = 15; len >= 1; --len) {
        if (static_cast<uintptr_t>(len) > addr) continue;
        uintptr_t cand = addr - len;
        uint8_t buf[16];
        if (!read(cand, buf, static_cast<size_t>(len))) continue;
        auto insns = disassemble(cand, {buf, static_cast<size_t>(len)}, 1);
        if (!insns.empty() && insns[0].size == static_cast<size_t>(len)) return cand;
    }
    return best;
}

std::optional<Instruction> Disassembler::disassembleOne(uintptr_t address, std::span<const uint8_t> code) {
    auto result = disassemble(address, code, 1);
    if (result.empty()) return std::nullopt;
    return std::move(result[0]);
}

} // namespace ce
