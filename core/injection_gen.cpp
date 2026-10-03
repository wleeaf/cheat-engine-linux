#include "core/injection_gen.hpp"
#include "core/types.hpp"
#include "arch/disassembler.hpp"
#include "arch/assembler.hpp"
#include "platform/process_api.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <limits>
#include <set>
#include <sstream>

namespace ce {
namespace {
std::string hex(uintptr_t n) {
    std::ostringstream s;
    s << "0x" << std::hex << n;
    return s.str();
}
std::string bytesText(const std::vector<uint8_t>& bytes) {
    std::string result;
    for (auto b : bytes) {
        char text[4];
        std::snprintf(text, sizeof(text), "%02X", b);
        if (!result.empty()) result += ' ';
        result += text;
    }
    return result;
}
std::string siteOffset(uintptr_t target, uintptr_t site) {
    return target >= site ? "INJECT+" + hex(target - site)
                          : "INJECT-" + hex(site - target);
}
}

std::size_t shortestUniqueAobLen(const std::vector<uint8_t>& mod,
                                 std::size_t targetOffset,
                                 std::size_t minLen, std::size_t maxLen) {
    if (targetOffset >= mod.size() || minLen == 0 || maxLen < minLen) return 0;
    maxLen = std::min(maxLen, mod.size() - targetOffset);
    if (minLen > maxLen) return 0;
    size_t required = minLen;
    for (size_t i = 0; i <= mod.size() - minLen; ++i) {
        if (i == targetOffset || std::memcmp(mod.data() + i, mod.data() + targetOffset, minLen)) continue;
        size_t common = minLen;
        while (common < maxLen && common < mod.size() - i && mod[i + common] == mod[targetOffset + common]) ++common;
        required = std::max(required, common + 1);
        if (required > maxLen) return 0;
    }
    return required;
}

std::string uniqueAobSignature(ProcessHandle& proc, const ModuleInfo& m,
                               uintptr_t address, std::size_t minLen, std::size_t maxLen) {
    if (!m.size || address < m.base || address - m.base >= m.size ||
        m.size > UINTPTR_MAX - m.base || !minLen || maxLen < minLen) return {};
    maxLen = std::min(maxLen, m.size - (address - m.base));
    // Bound candidate storage; scan module memory in chunks rather than loading it all.
    maxLen = std::min<size_t>(maxLen, 4096);
    std::vector<uint8_t> candidate(maxLen);
    auto read = proc.read(address, candidate.data(), candidate.size());
    if (!read || *read < minLen || *read > candidate.size()) return {};
    candidate.resize(*read);
    size_t required = minLen;
    bool foundSite = false;
    auto regions = proc.queryRegions();
    std::sort(regions.begin(), regions.end(), [](const auto& a, const auto& b) { return a.base < b.base; });
    std::vector<uint8_t> window;
    uintptr_t previousEnd = 0;
    for (const auto& region : regions) {
        if (!(region.protection & MemProt::Read) || !region.size || region.size > UINTPTR_MAX - region.base) continue;
        uintptr_t start = std::max(m.base, region.base);
        uintptr_t end = std::min(m.base + m.size, region.base + region.size);
        for (uintptr_t cursor = start; cursor < end;) {
            size_t n = std::min<uintptr_t>(65536, end - cursor);
            std::vector<uint8_t> chunk(n);
            auto r = proc.read(cursor, chunk.data(), n);
            if (!r || !*r || *r > n) { window.clear(); previousEnd = 0; cursor += n; continue; }
            if (previousEnd != cursor) window.clear();
            uintptr_t windowBase = cursor - window.size();
            window.insert(window.end(), chunk.begin(), chunk.begin() + *r);
            if (window.size() >= minLen) {
                for (size_t i = 0; i <= window.size() - minLen; ++i) {
                    if (std::memcmp(window.data() + i, candidate.data(), minLen)) continue;
                    if (windowBase + i == address) { foundSite = true; continue; }
                    size_t common = minLen;
                    while (common < candidate.size() && common < window.size() - i && window[i + common] == candidate[common]) ++common;
                    // Defer candidates at a chunk boundary until their full suffix is read.
                    if (common == window.size() - i && common < candidate.size() && cursor + *r < end) continue;
                    required = std::max(required, common + 1);
                    if (required > candidate.size()) return {};
                }
            }
            size_t tail = std::min(window.size(), candidate.size() - 1);
            window.erase(window.begin(), window.end() - tail);
            previousEnd = cursor + *r;
            cursor += *r;
        }
    }
    if (!foundSite) return {};
    candidate.resize(required);
    return bytesText(candidate);
}

std::string generateInjectionScript(ProcessHandle& proc, uintptr_t address,
                                    bool aob, std::string& error, size_t minimumOverwrite) {
    return generateInjectionScript(proc, address, aob ? InjectionKind::Aob : InjectionKind::Code, error, "", minimumOverwrite);
}

std::string generateInjectionScript(ProcessHandle& proc, uintptr_t address,
                                    InjectionKind kind, std::string& error,
                                    const std::string& pointerRegister, size_t minimumOverwrite) {
    error.clear();
    if (kind == InjectionKind::None) { error = "Choose an injection template."; return {}; }
    minimumOverwrite = std::max<size_t>(5, minimumOverwrite);
    if (minimumOverwrite > 1024 * 1024) { error = "The selected injection range exceeds 1 MiB."; return {}; }
    std::vector<uint8_t> buf(std::max<size_t>(64, minimumOverwrite + 15));
    auto r = proc.read(address, buf.data(), buf.size());
    if (!r || *r < minimumOverwrite || *r > buf.size() || *r > UINTPTR_MAX - address) {
        error = "Could not read enough code at that address.";
        return {};
    }
    bool is32 = proc.runs32BitCode();
    Disassembler dis(is32 ? Arch::X86_32 : Arch::X86_64);
    Assembler assembler(is32 ? AsmArch::X86_32 : AsmArch::X86_64);
    auto insns = dis.disassemble(address, {buf.data(), *r});
    size_t covered = 0, count = 0;
    for (const auto& insn : insns) {
        if (!insn.size || insn.address != address + covered || insn.size > *r - covered) break;
        covered += insn.size;
        ++count;
        if (covered >= minimumOverwrite) break;
    }
    if (covered < minimumOverwrite) { error = "Could not disassemble enough whole instructions for this injection."; return {}; }
    insns.resize(count);
    std::vector<uint8_t> originalBytes(buf.begin(), buf.begin() + covered);
    std::vector<StolenInstruction> stolen;
    std::set<size_t> branchLabels;
    for (size_t i = 0; i < insns.size(); ++i) {
        const auto& insn = insns[i];
        std::string operands = insn.operands;
        auto operation = insn.mnemonic.substr(insn.mnemonic.find_last_of(' ') + 1);
        bool relativeBranch = (operation.starts_with('j') || operation.starts_with("loop") ||
                               operation == "call" || operation == "xbegin") &&
                               operands.starts_with("0x");
        if (relativeBranch) {
            uintptr_t target = 0;
            try { target = std::stoull(operands, nullptr, 16); } catch (...) {
                error = "Cannot resolve the original branch destination."; return {};
            }
            if (target >= address && target < address + covered) {
                auto it = std::find_if(insns.begin(), insns.end(), [&](const auto& item) { return item.address == target; });
                if (it == insns.end()) { error = "A branch enters the middle of a stolen instruction."; return {}; }
                size_t index = it - insns.begin();
                branchLabels.insert(index);
                operands = "original_" + std::to_string(index);
            } else if (target == address + covered) operands = "return";
            else operands = siteOffset(target, address);
        }
        if (insn.memory.ripRelative) {
            const auto begin = operands.find('['), end = operands.find(']', begin);
            if (begin == std::string::npos || end == std::string::npos) {
                error = "Cannot relocate this RIP-relative operand."; return {};
            }
            operands.replace(begin + 1, end - begin - 1, "rel " + siteOffset(insn.ripTarget, address));
        }
        std::string text = insn.mnemonic + (operands.empty() ? "" : " " + operands);
        // Unsupported position-independent instructions (e.g. CET endbr64) can
        // keep their encoding. Relative instructions must always be relocated.
        auto probe = assembler.assemble(insn.mnemonic + " " + insn.operands, insn.address);
        if (!probe && !relativeBranch && !insn.memory.ripRelative)
            text = "db " + bytesText(insn.bytes) + " // " + text;
        stolen.push_back({insn.address, text, insn.size, ""});
    }
    for (auto index : branchLabels) stolen[index].label = "original_" + std::to_string(index);
    const auto modules = proc.modules();
    const ModuleInfo* module = nullptr;
    for (const auto& m : modules) {
        if (address >= m.base && address - m.base < m.size) { module = &m; break; }
    }
    std::string script;
    if (kind == InjectionKind::Aob) {
        if (!module || module->name.empty()) { error = "AOB injection needs the address to be inside a loaded module."; return {}; }
        auto signature = uniqueAobSignature(proc, *module, address, 5, std::max<size_t>(64, covered));
        if (signature.empty()) {
            error = "No unique AOB signature could be verified here. Choose another instruction or use Code injection.";
            return {};
        }
        script = buildAobInjectionScript(module->name, address - module->base, stolen, originalBytes, signature);
    } else {
        script = buildCodeInjectionScript(address, stolen, originalBytes,
                                         module ? module->name : "", module ? address - module->base : 0);
    }
    if (kind == InjectionKind::Full) {
        size_t pos = script.find("label(code)"); script.replace(pos, 11, "label(originalcode)\nlabel(exit)");
        pos = script.find("\ncode:\n"); script.replace(pos, 7, "\noriginalcode:\n");
        pos = script.find("  jmp return"); script.insert(pos, "exit:\n");
    }
    if (kind == InjectionKind::Pointer) {
        std::string reg = pointerRegister;
        if (reg.empty()) {
            reg = insns.front().memory.baseReg;
            if (reg.empty() || reg == "rip") { error = "Choose the register holding the pointer to capture."; return {}; }
        }
        std::transform(reg.begin(), reg.end(), reg.begin(), [](unsigned char c) { return std::tolower(c); });
        const std::vector<std::string> regs32 = {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"};
        const std::vector<std::string> regs64 = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
        const auto& allowed = is32 ? regs32 : regs64;
        if (std::find(allowed.begin(), allowed.end(), reg) == allowed.end()) { error = "Choose a pointer-sized general purpose register for this target."; return {}; }
        size_t pos = script.find("label(code)");
        // Keep the pointer slot in the cave, within RIP-relative reach and zeroed
        // without changing flags or clobbering a scratch register.
        script.insert(pos, "label(pPlayerBase)\nregistersymbol(pPlayerBase)\n");
        pos = script.find("  // your code here");
        script.replace(pos, 19, "  mov [" + std::string(is32 ? "" : "rel ") + "pPlayerBase], " + reg);
        pos = script.find("\nINJECT:\n");
        script.insert(pos, std::string("\npPlayerBase:\n  ") + (is32 ? "dd" : "dq") + " 0\n");
        pos = script.find("dealloc(newmem)"); script.insert(pos, "unregistersymbol(pPlayerBase)\n");
    }
    // A snapshot ties the editable template to the exact instructions selected.
    script += "\n{ Original code at " + (module ? module->name + "+" + hex(address - module->base) : hex(address)) + "\n";
    for (const auto& insn : insns)
        script += "  " + hex(insn.address) + " : " + bytesText(insn.bytes) + " : " + insn.mnemonic + " " + insn.operands + "\n";
    script += "}\n";
    return script;
}
} // namespace ce
