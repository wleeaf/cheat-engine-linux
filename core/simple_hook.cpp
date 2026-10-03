#include "core/simple_hook.hpp"
#include "arch/disassembler.hpp"
#include "core/log.hpp"

#include <cstring>
#include <span>
#include <limits>
#include <algorithm>

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

void putRelJmp(std::vector<uint8_t>& out, uintptr_t address, uintptr_t target) {
    out.push_back(0xE9);
    uint32_t rel = static_cast<uint32_t>(target - (address + 5));
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>(rel >> (8 * i)));
}

std::vector<SimpleHook::ProtectionRange> protectionsFor(ProcessHandle& proc, uintptr_t address, size_t size) {
    std::vector<SimpleHook::ProtectionRange> out;
    while (size) {
        auto region = proc.queryRegion(address);
        if (!region || address < region->base || address - region->base >= region->size) return {};
        size_t n = std::min(size, region->size - (address - region->base));
        out.push_back({address, n, region->protection});
        address += n;
        size -= n;
    }
    return out;
}

bool setProtections(ProcessHandle& proc, const std::vector<SimpleHook::ProtectionRange>& ranges, bool writable) {
    bool ok = true;
    for (const auto& range : ranges)
        if (!proc.protect(range.address, range.size, writable ? range.protection | MemProt::Write : range.protection))
            ok = false;
    return ok;
}

} // namespace

std::optional<SimpleHook> installSimpleHook(ProcessHandle& proc, uintptr_t address,
                                            uintptr_t target) {
    bool code32 = proc.runs32BitCode();
    if (code32 && (address > UINT32_MAX || target > UINT32_MAX)) return std::nullopt;
    // 1. Decode enough whole instructions at `address` to hold a 5-byte E9 jmp.
    uint8_t code[32] = {0};
    auto rd = proc.read(address, code, sizeof(code));
    if (!rd || *rd < 5) {
        ce::log::warn(ce::log::Cat::General, "createSimpleHook: cannot read code @ {:#x}", address);
        return std::nullopt;
    }
    Disassembler dis(code32 ? Arch::X86_32 : Arch::X86_64);
    auto insns = dis.disassemble(address, std::span<const uint8_t>(code, std::min(*rd, sizeof(code))), 0);
    size_t patchLen = 0;
    for (const auto& in : insns) {
        if (isPositionDependent(in)) {
            ce::log::warn(ce::log::Cat::General,
                "createSimpleHook: refusing @ {:#x}: displaced '{} {}' is position-dependent",
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
    if (patchLen > UINTPTR_MAX - address) return std::nullopt;
    hook.protections = protectionsFor(proc, address, patchLen);
    if (hook.protections.empty()) return std::nullopt;

    // 2. Allocate a codecave NEAR the hook (within ±2GB so the E9 rel32 reaches).
    //    Layout: [gate: abs-jmp -> target][trampoline: original bytes + abs-jmp back].
    auto cave = proc.allocate(64 + patchLen, MemProt::Read | MemProt::Write | MemProt::Exec, address);
    if (!cave) {
        ce::log::warn(ce::log::Cat::General, "createSimpleHook: codecave alloc failed");
        return std::nullopt;
    }
    hook.codecave = *cave;
    if (64 + patchLen > UINTPTR_MAX - *cave ||
        (code32 && *cave > UINT32_MAX - (64 + patchLen))) {
        proc.free(*cave, 64 + patchLen);
        return std::nullopt;
    }
    const uintptr_t gate = *cave;
    const uintptr_t trampoline = *cave + 16;   // gate is 14 bytes; pad to 16
    hook.trampoline = trampoline;

    // The E9 at `address` must reach the gate.
    uintptr_t rel = gate - (address + 5);
    if (!code32 && rel > INT32_MAX && rel < UINTPTR_MAX - INT32_MAX) {
        ce::log::warn(ce::log::Cat::General, "createSimpleHook: codecave out of rel32 range");
        proc.free(*cave, 64 + patchLen);
        return std::nullopt;
    }

    // 3. Write the gate (abs jmp -> user target) and the trampoline (original bytes
    //    then abs jmp back to address+patchLen).
    std::vector<uint8_t> gateBytes;
    if (code32) putRelJmp(gateBytes, gate, target);
    else putAbsJmp(gateBytes, target);
    std::vector<uint8_t> tramp(hook.original.begin(), hook.original.end());
    if (code32) putRelJmp(tramp, trampoline + patchLen, address + patchLen);
    else putAbsJmp(tramp, address + patchLen);
    auto gateWrite = proc.write(gate, gateBytes.data(), gateBytes.size());
    auto trampolineWrite = gateWrite && *gateWrite == gateBytes.size()
        ? proc.write(trampoline, tramp.data(), tramp.size())
        : Result<size_t>(std::unexpected(std::make_error_code(std::errc::io_error)));
    if (!gateWrite || *gateWrite != gateBytes.size() ||
        !trampolineWrite || *trampolineWrite != tramp.size()) {
        ce::log::warn(ce::log::Cat::General, "createSimpleHook: codecave write failed");
        proc.free(*cave, 64 + patchLen);
        return std::nullopt;
    }

    // 4. Patch `address`: E9 rel32 -> gate, NOP-padded to patchLen. Make the code
    //    page writable first (it is normally r-x).
    std::vector<uint8_t> patch(patchLen, 0x90);
    patch[0] = 0xE9;
    uint32_t r32 = static_cast<uint32_t>(rel);
    std::memcpy(&patch[1], &r32, 4);
    if (!setProtections(proc, hook.protections, true)) {
        setProtections(proc, hook.protections, false);
        proc.free(*cave, 64 + patchLen);
        return std::nullopt;
    }
    auto patchWrite = proc.write(address, patch.data(), patch.size());
    if (!patchWrite || *patchWrite != patch.size()) {
        ce::log::warn(ce::log::Cat::General, "createSimpleHook: patch write failed @ {:#x}", address);
        // A short write may already have installed the jump. Restore the code
        // before freeing its destination; retain the cave if recovery fails.
        auto restored = proc.write(address, hook.original.data(), hook.original.size());
        setProtections(proc, hook.protections, false);
        if (restored && *restored == hook.original.size()) proc.free(*cave, 64 + patchLen);
        return std::nullopt;
    }
    setProtections(proc, hook.protections, false);

    ce::log::info(ce::log::Cat::General,
        "createSimpleHook @ {:#x} -> {:#x} (patchLen={}, trampoline={:#x})",
        address, target, patchLen, trampoline);
    return hook;
}

bool removeSimpleHook(ProcessHandle& proc, const SimpleHook& hook) {
    if (hook.original.empty()) return false;
    auto ranges = hook.protections.empty() ? protectionsFor(proc, hook.address, hook.original.size()) : hook.protections;
    if (ranges.empty() || !setProtections(proc, ranges, true)) {
        setProtections(proc, ranges, false);
        return false;
    }
    auto restored = proc.write(hook.address, hook.original.data(), hook.original.size());
    bool ok = restored && *restored == hook.original.size();
    ok = setProtections(proc, ranges, false) && ok;
    // Deliberately do not free the codecave: the target could still be executing
    // inside the trampoline.
    ce::log::info(ce::log::Cat::General, "removeSimpleHook @ {:#x}: {}", hook.address, ok ? "ok" : "FAILED");
    return ok;
}

} // namespace ce
