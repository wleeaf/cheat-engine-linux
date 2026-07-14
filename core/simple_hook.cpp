#include "core/simple_hook.hpp"
#include "arch/disassembler.hpp"
#include "core/log.hpp"

#include <cstring>
#include <span>

namespace ce {

namespace {

// A relative branch's encoded displacement is relative to its ORIGINAL address;
// copied into a codecave it would jump to the wrong place. Refuse those (and
// RIP-relative operands) rather than relocate them in this first version.
bool isPositionDependent(const Instruction& in) {
    if (in.memory.ripRelative || in.ripTarget != 0) return true;
    const std::string& m = in.mnemonic;
    if (m == "call" || m.rfind("loop", 0) == 0) return true;
    if (!m.empty() && m[0] == 'j') return true;   // jmp + all jcc
    return false;
}

void putAbsJmp(std::vector<uint8_t>& out, uint64_t target) {
    // jmp qword [rip+0]; <8-byte absolute target>
    const uint8_t stub[6] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
    out.insert(out.end(), stub, stub + 6);
    for (int i = 0; i < 8; ++i) out.push_back((uint8_t)((target >> (8 * i)) & 0xFF));
}

} // namespace

std::optional<SimpleHook> installSimpleHook(ProcessHandle& proc, uintptr_t address,
                                            uintptr_t target) {
    // 1. Decode enough whole instructions at `address` to hold a 5-byte E9 jmp.
    uint8_t code[32] = {0};
    auto rd = proc.read(address, code, sizeof(code));
    if (!rd || *rd < 5) {
        ce::log::warn(ce::log::Cat::General, "createSimpleHook: cannot read code @ {:#x}", address);
        return std::nullopt;
    }
    Disassembler dis(proc.runs32BitCode() ? Arch::X86_32 : Arch::X86_64);
    auto insns = dis.disassemble(address, std::span<const uint8_t>(code, *rd), 0);
    size_t patchLen = 0;
    for (const auto& in : insns) {
        if (isPositionDependent(in)) {
            ce::log::warn(ce::log::Cat::General,
                "createSimpleHook: refusing @ {:#x} — displaced '{} {}' is position-dependent",
                address, in.mnemonic, in.operands);
            return std::nullopt;
        }
        patchLen += in.size;
        if (patchLen >= 5) break;
    }
    if (patchLen < 5) {
        ce::log::warn(ce::log::Cat::General, "createSimpleHook: <5 decodable bytes @ {:#x}", address);
        return std::nullopt;
    }

    SimpleHook hook;
    hook.address = address;
    hook.patchLen = patchLen;
    hook.original.assign(code, code + patchLen);

    // 2. Allocate a codecave NEAR the hook (within ±2GB so the E9 rel32 reaches).
    //    Layout: [gate: abs-jmp -> target][trampoline: original bytes + abs-jmp back].
    auto cave = proc.allocate(64 + patchLen, MemProt::Read | MemProt::Write | MemProt::Exec, address);
    if (!cave) {
        ce::log::warn(ce::log::Cat::General, "createSimpleHook: codecave alloc failed");
        return std::nullopt;
    }
    hook.codecave = *cave;
    const uintptr_t gate = *cave;
    const uintptr_t trampoline = *cave + 16;   // gate is 14 bytes; pad to 16
    hook.trampoline = trampoline;

    // The E9 at `address` must reach the gate.
    int64_t rel = (int64_t)gate - (int64_t)(address + 5);
    if (rel > 0x7FFFFFFFLL || rel < -0x80000000LL) {
        ce::log::warn(ce::log::Cat::General, "createSimpleHook: codecave out of rel32 range");
        return std::nullopt;
    }

    // 3. Write the gate (abs jmp -> user target) and the trampoline (original bytes
    //    then abs jmp back to address+patchLen).
    std::vector<uint8_t> gateBytes;   putAbsJmp(gateBytes, target);
    std::vector<uint8_t> tramp(hook.original.begin(), hook.original.end());
    putAbsJmp(tramp, address + patchLen);
    if (!proc.write(gate, gateBytes.data(), gateBytes.size()) ||
        !proc.write(trampoline, tramp.data(), tramp.size())) {
        ce::log::warn(ce::log::Cat::General, "createSimpleHook: codecave write failed");
        return std::nullopt;
    }

    // 4. Patch `address`: E9 rel32 -> gate, NOP-padded to patchLen. Make the code
    //    page writable first (it is normally r-x).
    std::vector<uint8_t> patch(patchLen, 0x90);
    patch[0] = 0xE9;
    int32_t r32 = (int32_t)rel;
    std::memcpy(&patch[1], &r32, 4);
    proc.protect(address, patchLen, MemProt::Read | MemProt::Write | MemProt::Exec);
    if (!proc.write(address, patch.data(), patch.size())) {
        ce::log::warn(ce::log::Cat::General, "createSimpleHook: patch write failed @ {:#x}", address);
        return std::nullopt;
    }
    proc.protect(address, patchLen, MemProt::Read | MemProt::Exec);

    ce::log::info(ce::log::Cat::General,
        "createSimpleHook @ {:#x} -> {:#x} (patchLen={}, trampoline={:#x})",
        address, target, patchLen, trampoline);
    return hook;
}

bool removeSimpleHook(ProcessHandle& proc, const SimpleHook& hook) {
    if (hook.original.empty()) return false;
    proc.protect(hook.address, hook.original.size(), MemProt::Read | MemProt::Write | MemProt::Exec);
    bool ok = proc.write(hook.address, hook.original.data(), hook.original.size()).has_value();
    proc.protect(hook.address, hook.original.size(), MemProt::Read | MemProt::Exec);
    // Deliberately do not free the codecave: the target could still be executing
    // inside the trampoline.
    ce::log::info(ce::log::Cat::General, "removeSimpleHook @ {:#x}: {}", hook.address, ok ? "ok" : "FAILED");
    return ok;
}

} // namespace ce
