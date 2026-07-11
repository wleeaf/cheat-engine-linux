#include "analysis/code_analysis.hpp"
#include <cstring>
#include <algorithm>
#include <charconv>
#include <cctype>
#include <map>
#include <optional>
#include <unordered_map>

namespace ce {

// Cap the per-region read so a hostile target with a multi-GB PROT_EXEC mapping
// inside the module range can't drive a std::bad_alloc via buf(r.size).
static constexpr size_t kMaxAnalysisRegion = 512u * 1024 * 1024; // 512 MB

namespace {

std::optional<int64_t> parseInteger(std::string_view text) {
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front()))) text.remove_prefix(1);
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back()))) text.remove_suffix(1);
    if (text.empty()) return std::nullopt;

    bool neg = false;
    if (text.front() == '+' || text.front() == '-') {
        neg = text.front() == '-';
        text.remove_prefix(1);
        while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front()))) text.remove_prefix(1);
    }

    int base = 10;
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        base = 16;
        text.remove_prefix(2);
    }

    uint64_t value = 0;
    auto* first = text.data();
    auto* last = text.data() + text.size();
    auto [ptr, ec] = std::from_chars(first, last, value, base);
    if (ec != std::errc{} || ptr != last) return std::nullopt;
    if (neg) return -static_cast<int64_t>(value);
    return static_cast<int64_t>(value);
}

std::optional<uintptr_t> parseDirectTarget(const std::string& operands) {
    auto comma = operands.rfind(',');
    std::string_view target(operands);
    if (comma != std::string::npos)
        target = std::string_view(operands).substr(comma + 1);
    if (target.find('[') != std::string_view::npos)
        return std::nullopt;
    auto parsed = parseInteger(target);
    if (!parsed || *parsed < 0) return std::nullopt;
    return static_cast<uintptr_t>(*parsed);
}

std::optional<uintptr_t> parseRipRelativeTarget(const Instruction& inst) {
    // The Disassembler resolves RIP-relative operands and stores the absolute
    // effective address on the instruction (the operand text is rewritten to
    // "[0x<abs>]", so parsing "rip + disp" no longer works). Use the field.
    if (inst.ripTarget == 0) return std::nullopt;
    return inst.ripTarget;
}

bool readPrintableString(ProcessHandle& proc, uintptr_t address, std::string& out) {
    char buf[256] = {};
    auto rr = proc.read(address, buf, sizeof(buf) - 1);
    if (!rr || *rr < 4) return false;

    size_t printable = 0;
    size_t len = 0;
    for (; len < *rr && buf[len]; ++len) {
        unsigned char ch = static_cast<unsigned char>(buf[len]);
        if (ch >= 32 && ch < 127) ++printable;
        else return false;
    }
    if (printable < 4) return false;
    out.assign(buf, len);
    return true;
}

} // namespace

std::vector<CodeRef> CodeAnalyzer::dissectModule(ProcessHandle& proc, const ModuleInfo& module) {
    std::vector<CodeRef> refs;

    // Read executable sections of the module
    auto regions = proc.queryRegions();
    for (auto& r : regions) {
        if (r.base < module.base || r.base >= module.base + module.size) continue;
        if (!(r.protection & MemProt::Exec)) continue;

        size_t readLen = std::min<size_t>(r.size, kMaxAnalysisRegion);
        std::vector<uint8_t> buf(readLen);
        auto rr = proc.read(r.base, buf.data(), readLen);
        if (!rr || *rr == 0) continue;

        auto insns = disasm_.disassemble(r.base, {buf.data(), *rr}, 0);
        for (auto& inst : insns) {
            // CALL instructions
            if (inst.mnemonic == "call") {
                CodeRef ref;
                ref.address = inst.address;
                ref.type = RefType::Call;
                ref.text = inst.mnemonic + " " + inst.operands;
                ref.target = parseDirectTarget(inst.operands).value_or(0);
                if (ref.target) {
                    refs.push_back(ref);
                }
                // Indirect PIC form: call qword ptr [rip + disp] (GOT/PLT stub).
                // The direct-target parse fails on the '['; recover the referenced
                // slot as a RIP-relative data ref so findStatics/findRipRelative*
                // do not silently drop it. Recorded as RipRelative (not Call) on
                // purpose: the target is a GOT data slot, not a function entry, so
                // the direct-only call graph must not treat it as a callee.
                else if (auto target = parseRipRelativeTarget(inst)) {
                    ref.type = RefType::RipRelative;
                    ref.target = *target;
                    refs.push_back(ref);
                }
            }
            // JMP instructions
            else if (inst.mnemonic == "jmp" || (!inst.mnemonic.empty() && inst.mnemonic[0] == 'j')) {
                CodeRef ref;
                ref.address = inst.address;
                ref.type = RefType::Jump;
                ref.text = inst.mnemonic + " " + inst.operands;
                ref.target = parseDirectTarget(inst.operands).value_or(0);
                if (ref.target) {
                    refs.push_back(ref);
                }
                // Indirect PIC form: jmp qword ptr [rip + disp] (PLT stub).
                // Recover the referenced slot as a RIP-relative data ref rather
                // than discarding it; not recorded as a Jump because the target
                // is a GOT data slot, not a code address.
                else if (auto target = parseRipRelativeTarget(inst)) {
                    ref.type = RefType::RipRelative;
                    ref.target = *target;
                    refs.push_back(ref);
                }
            }
            // RIP-relative memory operands often reference literals in nearby rodata.
            else if (auto target = parseRipRelativeTarget(inst)) {
                CodeRef ref;
                ref.address = inst.address;
                ref.type = RefType::RipRelative;
                ref.text = inst.mnemonic + " " + inst.operands;
                ref.target = *target;
                refs.push_back(ref);
            }
        }
    }

    return refs;
}

std::vector<CodeRef> CodeAnalyzer::findReferencedStrings(ProcessHandle& proc, const ModuleInfo& module) {
    auto allRefs = dissectModule(proc, module);
    std::vector<CodeRef> strings;
    for (auto& ref : allRefs) {
        if (ref.type != RefType::RipRelative || !ref.target) continue;
        std::string text;
        if (readPrintableString(proc, ref.target, text)) {
            ref.type = RefType::String;
            ref.text = std::move(text);
            strings.push_back(ref);
        }
    }
    return strings;
}

std::vector<CodeRef> CodeAnalyzer::findReferencedFunctions(ProcessHandle& proc, const ModuleInfo& module) {
    auto allRefs = dissectModule(proc, module);
    std::vector<CodeRef> functions;
    for (auto& ref : allRefs) {
        if (ref.type == RefType::Call && ref.target)
            functions.push_back(ref);
    }
    return functions;
}

std::vector<FunctionInfo> CodeAnalyzer::enumerateFunctions(ProcessHandle& proc, const ModuleInfo& module) {
    std::map<uintptr_t, size_t> references;
    for (const auto& ref : findReferencedFunctions(proc, module))
        ++references[ref.target];

    std::vector<FunctionInfo> functions;
    functions.reserve(references.size());
    for (const auto& [address, count] : references)
        functions.push_back({address, count});
    return functions;
}

std::vector<CallGraphEdge> CodeAnalyzer::buildCallGraph(ProcessHandle& proc, const ModuleInfo& module) {
    auto refs = findReferencedFunctions(proc, module);
    auto functions = enumerateFunctions(proc, module);

    std::vector<uintptr_t> starts;
    starts.push_back(module.base);
    for (const auto& fn : functions) {
        if (fn.address >= module.base && fn.address < module.base + module.size)
            starts.push_back(fn.address);
    }
    std::sort(starts.begin(), starts.end());
    starts.erase(std::unique(starts.begin(), starts.end()), starts.end());

    std::vector<CallGraphEdge> graph;
    graph.reserve(refs.size());
    for (const auto& ref : refs) {
        auto it = std::upper_bound(starts.begin(), starts.end(), ref.address);
        uintptr_t caller = it == starts.begin() ? module.base : *std::prev(it);
        graph.push_back({caller, ref.target, ref.address});
    }
    return graph;
}

std::vector<CodeRef> CodeAnalyzer::findJumps(ProcessHandle& proc, const ModuleInfo& module) {
    auto allRefs = dissectModule(proc, module);
    std::vector<CodeRef> jumps;
    for (auto& ref : allRefs) {
        if (ref.type == RefType::Jump && ref.target)
            jumps.push_back(ref);
    }
    return jumps;
}

std::vector<CodeRef> CodeAnalyzer::findRipRelativeInstructions(ProcessHandle& proc, const ModuleInfo& module) {
    auto allRefs = dissectModule(proc, module);
    std::vector<CodeRef> ripRefs;
    for (auto& ref : allRefs) {
        if (ref.type == RefType::RipRelative)
            ripRefs.push_back(ref);
    }
    return ripRefs;
}

std::vector<CodeRef> CodeAnalyzer::findAssemblyPattern(ProcessHandle& proc, const ModuleInfo& module,
                                                       const std::string& assembly) {
    auto assembled = assembler_.assemble(assembly, module.base);
    if (!assembled || assembled->empty()) return {};

    std::vector<CodeRef> matches;
    auto regions = proc.queryRegions();
    for (const auto& r : regions) {
        if (r.base < module.base || r.base >= module.base + module.size) continue;
        if (!(r.protection & MemProt::Exec)) continue;

        size_t readLen = std::min<size_t>(r.size, kMaxAnalysisRegion);
        std::vector<uint8_t> buf(readLen);
        auto rr = proc.read(r.base, buf.data(), readLen);
        if (!rr || *rr < assembled->size()) continue;

        for (size_t offset = 0; offset + assembled->size() <= *rr; ++offset) {
            if (std::memcmp(buf.data() + offset, assembled->data(), assembled->size()) != 0)
                continue;

            CodeRef ref;
            ref.address = r.base + offset;
            ref.target = 0;
            ref.type = RefType::AssemblyPattern;
            ref.text = assembly;
            matches.push_back(std::move(ref));
        }
    }

    return matches;
}

std::vector<CodeCave> CodeAnalyzer::findCodeCaves(ProcessHandle& proc, const ModuleInfo& module, size_t minSize) {
    std::vector<CodeCave> caves;
    auto regions = proc.queryRegions();

    for (auto& r : regions) {
        if (r.base < module.base || r.base >= module.base + module.size) continue;
        if (!(r.protection & MemProt::Exec)) continue;

        size_t readLen = std::min<size_t>(r.size, kMaxAnalysisRegion);
        std::vector<uint8_t> buf(readLen);
        auto rr = proc.read(r.base, buf.data(), readLen);
        if (!rr || *rr == 0) continue;

        size_t runStart = 0;
        bool inRun = false;

        for (size_t i = 0; i < *rr; ++i) {
            bool isEmpty = (buf[i] == 0x00 || buf[i] == 0xCC);
            if (isEmpty && !inRun) {
                runStart = i;
                inRun = true;
            } else if (!isEmpty && inRun) {
                size_t runLen = i - runStart;
                if (runLen >= minSize)
                    caves.push_back({r.base + runStart, runLen});
                inRun = false;
            }
        }
        if (inRun) {
            size_t runLen = *rr - runStart;
            if (runLen >= minSize)
                caves.push_back({r.base + runStart, runLen});
        }
    }

    return caves;
}

std::vector<StaticAccess> CodeAnalyzer::findStatics(ProcessHandle& proc, const ModuleInfo& module) {
    auto rip = findRipRelativeInstructions(proc, module);
    std::unordered_map<uintptr_t, size_t> counts;
    for (const auto& r : rip) counts[r.target] += 1;

    std::vector<StaticAccess> out;
    out.reserve(counts.size());
    for (const auto& [addr, n] : counts)
        out.push_back(StaticAccess{addr, n});
    std::sort(out.begin(), out.end(),
        [](const StaticAccess& a, const StaticAccess& b) { return a.references > b.references; });
    return out;
}

std::vector<CodeRef> CodeAnalyzer::findReferencesTo(ProcessHandle& proc,
                                                    const ModuleInfo& module, uintptr_t target) {
    std::vector<CodeRef> refs;
    auto collect = [&](const std::vector<CodeRef>& src) {
        for (const auto& r : src)
            if (r.target == target) refs.push_back(r);
    };
    collect(dissectModule(proc, module));            // call / jump / string refs
    collect(findRipRelativeInstructions(proc, module)); // data (RIP-relative) refs

    // Dedupe by the referencing instruction address.
    std::sort(refs.begin(), refs.end(),
        [](const CodeRef& a, const CodeRef& b) { return a.address < b.address; });
    refs.erase(std::unique(refs.begin(), refs.end(),
        [](const CodeRef& a, const CodeRef& b) { return a.address == b.address; }), refs.end());
    return refs;
}

} // namespace ce
