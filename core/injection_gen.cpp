#include "core/injection_gen.hpp"
#include "core/aa_templates.hpp"
#include "arch/disassembler.hpp"
#include "platform/process_api.hpp"

#include <vector>

namespace ce {

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
    for (const auto& m : proc.modules()) {
        if (address >= m.base && address < m.base + m.size) {
            module = m.name;
            moduleOffset = address - m.base;
            break;
        }
    }

    if (aob) {
        if (module.empty()) {
            error = "AOB injection needs the address to be inside a loaded module.";
            return {};
        }
        return buildAobInjectionScript(module, moduleOffset, stolen, originalBytes);
    }
    return buildCodeInjectionScript(address, stolen, originalBytes, module);
}

} // namespace ce
