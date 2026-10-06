#include "core/target_capabilities.hpp"
#include "arch/target_arch.hpp"
#include "core/simple_hook.hpp"
#include "arch/disassembler.hpp"
#include "core/log.hpp"
#include "platform/linux/memory_image.hpp"

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

bool matches(ProcessHandle& proc, const SimpleHook& hook, const std::vector<uint8_t>& wanted) {
    std::vector<uint8_t> actual(wanted.size());
    auto read = hook.image ? hook.image->read(hook.address, actual.data(), actual.size()) : proc.read(hook.address, actual.data(), actual.size());
    return read && *read == actual.size() && actual == wanted;
}

} // namespace

std::optional<SimpleHook> installSimpleHook(ProcessHandle& proc, uintptr_t address,
                                            uintptr_t target) {
    if (unsupportedTargetOperation(proc, TargetFeature::CodeInjection)) return std::nullopt;
    auto sourceMachine = proc.machineAt(address);
    auto destinationMachine = proc.machineAt(target);
    if (!sourceMachine.isX86() || sourceMachine.architecture != destinationMachine.architecture) return std::nullopt;
    bool code32 = sourceMachine.architecture == CpuArchitecture::X86_32;
    if (code32 && (address > UINT32_MAX || target > UINT32_MAX)) return std::nullopt;
    auto image = os::pinNativeMemoryImage(proc);
    if (!image) return std::nullopt;
    // 1. Decode enough whole instructions at `address` to hold a 5-byte E9 jmp.
    uint8_t code[32] = {0};
    auto rd = *image ? (*image)->read(address, code, sizeof(code)) : proc.read(address, code, sizeof(code));
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
    hook.image = std::move(*image);
    hook.removal = std::make_shared<SimpleHook::Removal>();
    hook.address = address;
    hook.patchLen = patchLen;
    hook.original.assign(code, code + patchLen);
    if (patchLen > UINTPTR_MAX - address) return std::nullopt;
    hook.protections = protectionsFor(proc, address, patchLen);
    if (hook.protections.empty()) return std::nullopt;
    std::vector<uint8_t> gateBytes;
    gateBytes.reserve(14);
    std::vector<uint8_t> tramp(hook.original.begin(),hook.original.end());
    tramp.reserve(patchLen+14);
    hook.installed.assign(patchLen,0x90);

    // 2. Allocate a codecave NEAR the hook (within ±2GB so the E9 rel32 reaches).
    //    Layout: [gate: abs-jmp -> target][trampoline: original bytes + abs-jmp back].
    auto cave = hook.image ? hook.image->allocate(64 + patchLen, MemProt::All, address) : proc.allocate(64 + patchLen, MemProt::All, address);
    if (!cave) {
        ce::log::warn(ce::log::Cat::General, "createSimpleHook: codecave alloc failed");
        return std::nullopt;
    }
    hook.codecave = *cave;
    auto freeCave = [&] {
        return hook.image ? hook.image->free(*cave,64+patchLen) : proc.free(*cave,64+patchLen);
    };
    if (64 + patchLen > UINTPTR_MAX - *cave ||
        (code32 && *cave > UINT32_MAX - (64 + patchLen))) {
        freeCave();
        return std::nullopt;
    }
    const uintptr_t gate = *cave;
    const uintptr_t trampoline = *cave + 16;   // gate is 14 bytes; pad to 16
    hook.trampoline = trampoline;

    // The E9 at `address` must reach the gate.
    uintptr_t rel = gate - (address + 5);
    if (!code32 && rel > INT32_MAX && rel < UINTPTR_MAX - INT32_MAX) {
        ce::log::warn(ce::log::Cat::General, "createSimpleHook: codecave out of rel32 range");
        freeCave();
        return std::nullopt;
    }

    // 3. Write the gate (abs jmp -> user target) and the trampoline (original bytes
    //    then abs jmp back to address+patchLen).
    if (code32) putRelJmp(gateBytes, gate, target);
    else putAbsJmp(gateBytes, target);
    if (code32) putRelJmp(tramp, trampoline + patchLen, address + patchLen);
    else putAbsJmp(tramp, address + patchLen);
    auto gateWrite = hook.image ? hook.image->write(gate,gateBytes,true) : proc.writeCode(gate, gateBytes.data(), gateBytes.size());
    auto trampolineWrite = gateWrite && *gateWrite == gateBytes.size()
        ? (hook.image ? hook.image->write(trampoline,tramp,true) : proc.writeCode(trampoline, tramp.data(), tramp.size()))
        : Result<size_t>(std::unexpected(std::make_error_code(std::errc::io_error)));
    if (!gateWrite || *gateWrite != gateBytes.size() ||
        !trampolineWrite || *trampolineWrite != tramp.size()) {
        ce::log::warn(ce::log::Cat::General, "createSimpleHook: codecave write failed");
        freeCave();
        return std::nullopt;
    }

    // 4. Patch `address`: E9 rel32 -> gate, NOP-padded to patchLen. The native
    //    pinned-mm code adapter preserves the original page permissions.
    auto& patch = hook.installed;
    patch[0] = 0xE9;
    uint32_t r32 = static_cast<uint32_t>(rel);
    std::memcpy(&patch[1], &r32, 4);
    if (!hook.image && !setProtections(proc, hook.protections, true)) {
        setProtections(proc, hook.protections, false);
        freeCave();
        return std::nullopt;
    }
    auto patchWrite = hook.image ? hook.image->write(address,patch,true) : proc.writeCode(address, patch.data(), patch.size());
    if (!patchWrite || *patchWrite != patch.size() || !matches(proc,hook,patch)) {
        ce::log::warn(ce::log::Cat::General, "createSimpleHook: patch write failed @ {:#x}", address);
        // A short write may already have installed the jump. Restore the code
        // before freeing its destination; retain the cave if recovery fails.
        if (hook.image) {
            // The native transaction already owns any failed restoration.
            // Never start a second undo into a retired image or free a gate
            // still referenced by an incompletely restored jump.
            if (matches(proc,hook,hook.original)) freeCave();
        } else {
            auto restored = proc.writeCode(address, hook.original.data(), hook.original.size());
            setProtections(proc, hook.protections, false);
            if (restored && *restored == hook.original.size() && matches(proc,hook,hook.original)) freeCave();
        }
        return std::nullopt;
    }
    if (!hook.image && !setProtections(proc, hook.protections, false)) {
        // Keep a reachable cave and a reviewable recovery record if restoring
        // the original permissions fails after a successful installation.
        ce::log::warn(ce::log::Cat::General, "createSimpleHook: original page protection still requires recovery");
    }

    ce::log::info(ce::log::Cat::General,
        "createSimpleHook @ {:#x} -> {:#x} (patchLen={}, trampoline={:#x})",
        address, target, patchLen, trampoline);
    return hook;
}

bool removeSimpleHook(ProcessHandle& proc, const SimpleHook& hook) {
    if (hook.original.empty()) return false;
    std::unique_lock<std::mutex> removal;
    if (hook.removal) {
        removal = std::unique_lock(hook.removal->mutex,std::try_to_lock);
        if (!removal.owns_lock()) return false;
        if (hook.removal->complete) return true;
    }
    if (hook.image) {
        if (hook.image->pid()!=proc.pid()) return false;
        auto live = hook.image->check();
        if (!live) {
            if (live.error()!=std::errc::operation_canceled) return false;
            if (hook.removal) hook.removal->complete=true;
            return true;
        }
    }
    if (!hook.installed.empty()) {
        std::vector<uint8_t> actual(hook.original.size());
        auto read = hook.image ? hook.image->read(hook.address,actual.data(),actual.size()) : proc.read(hook.address,actual.data(),actual.size());
        if (!read || *read!=actual.size() || hook.installed.size()!=actual.size()) return false;
        for (size_t i=0;i<actual.size();++i)
            if (actual[i]!=hook.original[i] && actual[i]!=hook.installed[i]) return false;
    }
    if (hook.image) {
        if (!matches(proc,hook,hook.original)) {
            auto restored = hook.image->write(hook.address,hook.original,true);
            if (!restored || *restored!=hook.original.size() || !matches(proc,hook,hook.original)) return false;
        }
        if (hook.removal) hook.removal->complete=true;
        return true;
    }
    auto ranges = hook.protections.empty() ? protectionsFor(proc, hook.address, hook.original.size()) : hook.protections;
    if (ranges.empty() || !setProtections(proc, ranges, true)) {
        setProtections(proc, ranges, false);
        return false;
    }
    auto restored = proc.writeCode(hook.address, hook.original.data(), hook.original.size());
    bool ok = restored && *restored == hook.original.size() && matches(proc,hook,hook.original);
    ok = setProtections(proc, ranges, false) && ok;
    if (ok && hook.removal) hook.removal->complete=true;
    // Deliberately do not free the codecave: the target could still be executing
    // inside the trampoline.
    ce::log::info(ce::log::Cat::General, "removeSimpleHook @ {:#x}: {}", hook.address, ok ? "ok" : "FAILED");
    return ok;
}

} // namespace ce
