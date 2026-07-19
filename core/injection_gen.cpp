#include "core/injection_gen.hpp"
#include "core/aa_templates.hpp"
#include "core/types.hpp"
#include "arch/disassembler.hpp"
#include "platform/process_api.hpp"

#include <cstdio>
#include <cstring>
#include <vector>

namespace ce {

std::size_t shortestUniqueAobLen(const std::vector<std::uint8_t>& mod,
                                 std::size_t targetOffset,
                                 std::size_t minLen, std::size_t maxLen) {
    if (targetOffset >= mod.size()) return minLen;
    std::size_t avail = mod.size() - targetOffset;
    if (minLen < 1) minLen = 1;
    if (maxLen > avail) maxLen = avail;
    if (minLen > maxLen) minLen = maxLen;
    const std::uint8_t* pat = mod.data() + targetOffset;
    for (std::size_t L = minLen; L <= maxLen; ++L) {
        // Count matches of pat[0..L); stop early once a second one appears. The
        // target's own position is one match, so "unique" means exactly one.
        std::size_t count = 0;
        for (std::size_t i = 0; i + L <= mod.size(); ++i) {
            if (std::memcmp(mod.data() + i, pat, L) == 0 && ++count > 1) break;
        }
        if (count <= 1) return L;
    }
    return maxLen;
}

std::string uniqueAobSignature(ProcessHandle& proc, const ModuleInfo& m,
                               uintptr_t address, std::size_t minLen, std::size_t maxLen) {
    // Only scan sanely-sized modules; huge ones fall back to the raw signature.
    constexpr std::size_t kMaxScan = 64u * 1024 * 1024;
    if (m.size == 0 || m.size > kMaxScan) return {};
    if (address < m.base || address >= m.base + m.size) return {};

    // Read the whole module in page-sized chunks; unreadable gaps stay 0 (a real
    // code signature effectively never matches a run of zeros).
    std::vector<std::uint8_t> mod(m.size, 0);
    for (std::size_t off = 0; off < m.size; off += 0x1000) {
        std::size_t n = std::min<std::size_t>(0x1000, m.size - off);
        proc.read(m.base + off, mod.data() + off, n);   // ignore per-chunk failures
    }

    std::size_t targetOffset = static_cast<std::size_t>(address - m.base);
    std::size_t len = shortestUniqueAobLen(mod, targetOffset, minLen, maxLen);
    if (targetOffset + len > mod.size()) return {};

    std::string sig;
    for (std::size_t i = 0; i < len; ++i) {
        char b[4];
        std::snprintf(b, sizeof(b), "%02X", mod[targetOffset + i]);
        if (i) sig += ' ';
        sig += b;
    }
    return sig;
}

std::string generateInjectionScript(ProcessHandle& proc, uintptr_t address,
                                    bool aob, std::string& error) {
    // Read a window of code and disassemble whole instructions until at least the
    // 5 bytes the jmp needs are covered. Stealing partial instructions would
    // corrupt the target, so we always take complete ones.
    uint8_t buf[64];
    auto r = proc.read(address, buf, sizeof(buf));
    if (!r || *r < 5) {
        error = "Could not read enough code at that address.";
        return {};
    }
    size_t avail = *r;

    // Decode in the target's bitness so a 32-bit process's stolen instructions
    // are read correctly (and the cave code the AA engine emits matches).
    Disassembler dis(proc.runs32BitCode() ? Arch::X86_32 : Arch::X86_64);
    auto insns = dis.disassemble(address, {buf, avail}, 0);

    std::vector<StolenInstruction> stolen;
    size_t covered = 0;
    for (const auto& insn : insns) {
        if (insn.size == 0) break;
        if (covered + insn.size > avail) break;
        stolen.push_back({insn.address,
                          insn.operands.empty() ? insn.mnemonic
                                                : insn.mnemonic + " " + insn.operands,
                          insn.size});
        covered += insn.size;
        if (covered >= 5) break;
    }
    if (covered < 5 || stolen.empty()) {
        error = "Could not disassemble at least 5 bytes of whole instructions here.";
        return {};
    }
    std::vector<uint8_t> originalBytes(buf, buf + covered);

    // Resolve the containing module for a readable header / AOB scan.
    std::string module;
    uintptr_t moduleOffset = 0;
    const ModuleInfo* mod = nullptr;
    for (const auto& m : proc.modules()) {
        if (address >= m.base && address < m.base + m.size) {
            module = m.name;
            moduleOffset = address - m.base;
            mod = &m;
            break;
        }
    }

    if (aob) {
        if (module.empty() || !mod) {
            error = "AOB injection needs the address to be inside a loaded module.";
            return {};
        }
        // Extend the signature past the stolen bytes until it is unique in the module
        // (CE parity), so the aobscanmodule matches only the hook site. Falls back to
        // the raw stolen bytes if the module can't be scanned.
        std::string sig = uniqueAobSignature(proc, *mod, address, covered, covered + 16);
        return buildAobInjectionScript(module, moduleOffset, stolen, originalBytes, sig);
    }
    return buildCodeInjectionScript(address, stolen, originalBytes, module);
}

} // namespace ce
