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
    // The data address an instruction refers to: RIP-relative on x86-64, or an
    // absolute [disp32] with no base or index register, which is how 32-bit
    // code addresses its globals (and call/jmp [IAT] slots). Only inside the
    // module: that also excludes segment-relative operands like fs:[0x28].
    auto dataTarget = [&](const Instruction& inst) -> std::optional<uintptr_t> {
        if (auto rip = parseRipRelativeTarget(inst)) return rip;
        const auto& m = inst.memory;
        if (!m.present || m.ripRelative || !m.baseReg.empty() || !m.indexReg.empty()) return std::nullopt;
        // Capstone sign-extends disp32: in 32-bit code [0x80001000] arrives as a
        // negative displacement, so take it as the unsigned 32-bit address.
        const auto target = disasm_.arch() == Arch::X86_32
            ? static_cast<uintptr_t>(static_cast<uint32_t>(m.disp))
            : m.disp > 0 ? static_cast<uintptr_t>(m.disp) : uintptr_t(0);
        if (!target) return std::nullopt;
        if (target < module.base || target - module.base >= module.size) return std::nullopt;
        return target;
    };

    // Read executable sections of the module
    auto regions = proc.queryRegions();
    for (auto& r : regions) {
        if (r.base < module.base || r.base >= module.base + module.size) continue;
        if (!(r.protection & MemProt::Exec)) continue;

        size_t readLen = std::min<size_t>(r.size, kMaxAnalysisRegion);
        std::vector<uint8_t> buf(readLen);
        auto rr = proc.read(r.base, buf.data(), readLen);
        if (!rr || *rr == 0) continue;

        // Decode in chunks: a whole region's instructions with details would
        // take ~100x the code size. Data inside code (headers, jump tables,
        // literal pools) is stepped over as "db" instead of ending the region,
        // and the last bytes of a chunk are decoded again with the next one so
        // no instruction is cut in two.
        constexpr size_t kChunk = size_t(1) << 20, kMaxInstruction = 16;
        for (size_t offset = 0; offset < *rr;) {
            const size_t length = std::min(kChunk, *rr - offset);
            const bool lastChunk = offset + length >= *rr;
            auto insns = disasm_.disassemble(r.base + offset, {buf.data() + offset, length}, 0, /*emitDataBytes=*/true);
            size_t next = offset + length;
            for (auto& inst : insns) {
                if (!lastChunk && inst.address + kMaxInstruction > r.base + offset + length) {
                    next = inst.address - r.base;
                    break;
                }
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
                    else if (auto target = dataTarget(inst)) {
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
                    else if (auto target = dataTarget(inst)) {
                        ref.type = RefType::RipRelative;
                        ref.target = *target;
                        refs.push_back(ref);
                    }
                }
                // RIP-relative memory operands often reference literals in nearby rodata.
                else if (auto target = dataTarget(inst)) {
                    CodeRef ref;
                    ref.address = inst.address;
                    ref.type = RefType::RipRelative;
                    ref.text = inst.mnemonic + " " + inst.operands;
                    ref.target = *target;
                    refs.push_back(ref);
                }
            }
            offset = next > offset ? next : offset + length;
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
    if (!assembler_) return {};
    auto assembled = assembler_->assemble(assembly, module.base);
    if (!assembled || assembled->empty()) return {};
    const std::vector<uint8_t>& pattern = *assembled;

    // The bytes were assembled at module.base, so a relative branch or a
    // rip-relative operand only has those exact bytes there. Such fields are
    // compared per candidate instead: the value that reaches the same target
    // from the candidate's address.
    struct RelField { size_t offset, size; int64_t valueAtBase; };
    std::vector<RelField> fields;
    std::vector<bool> wild(pattern.size(), false);
    const Arch arch = disasm_.arch();
    if (arch == Arch::X86_32 || arch == Arch::X86_64) {
        for (const auto& in : disasm_.disassemble(module.base, {pattern.data(), pattern.size()})) {
            const size_t at = in.address - module.base;
            const bool branch = !in.mnemonic.empty() &&
                (in.mnemonic[0] == 'j' || in.mnemonic == "call" || in.mnemonic.rfind("loop", 0) == 0 ||
                 in.mnemonic == "xbegin") &&
                parseDirectTarget(in.operands).has_value();
            size_t offset = 0, size = 0;
            if (in.ripTarget && in.dispSize) { offset = in.dispOffset; size = in.dispSize; }
            else if (branch && in.immSize) { offset = in.immOffset; size = in.immSize; }
            if (!size || size > 4 || at + offset + size > pattern.size()) continue;
            uint64_t raw = 0;
            for (size_t b = 0; b < size; ++b) raw |= uint64_t(pattern[at + offset + b]) << (8 * b);
            const int shift = int(64 - 8 * size);
            fields.push_back({at + offset, size, static_cast<int64_t>(raw << shift) >> shift});
            for (size_t b = 0; b < size; ++b) wild[at + offset + b] = true;
        }
    }
    // The relative value that reaches the same target from `candidate`; false
    // when it does not fit the field (the code there would use another form).
    auto fieldMatches = [&](const RelField& f, uintptr_t candidate, const uint8_t* bytes) {
        uint64_t raw = 0;
        for (size_t b = 0; b < f.size; ++b) raw |= uint64_t(bytes[f.offset + b]) << (8 * b);
        const int shift = int(64 - 8 * f.size);
        const int64_t value = static_cast<int64_t>(raw << shift) >> shift;
        const uint64_t delta = uint64_t(module.base) - uint64_t(candidate);
        if (arch == Arch::X86_32 && f.size == 4)   // 32-bit addresses wrap
            return uint32_t(value) == uint32_t(uint64_t(f.valueAtBase) + delta);
        const int64_t expected = static_cast<int64_t>(uint64_t(f.valueAtBase) + delta);
        return value == expected;
    };

    std::vector<CodeRef> matches;
    auto regions = proc.queryRegions();
    for (const auto& r : regions) {
        if (r.base < module.base || r.base >= module.base + module.size) continue;
        if (!(r.protection & MemProt::Exec)) continue;

        size_t readLen = std::min<size_t>(r.size, kMaxAnalysisRegion);
        std::vector<uint8_t> buf(readLen);
        auto rr = proc.read(r.base, buf.data(), readLen);
        if (!rr || *rr < pattern.size()) continue;

        for (size_t offset = 0; offset + pattern.size() <= *rr; ++offset) {
            const uint8_t* bytes = buf.data() + offset;
            bool match = true;
            for (size_t i = 0; i < pattern.size() && match; ++i)
                match = wild[i] || bytes[i] == pattern[i];
            for (size_t i = 0; i < fields.size() && match; ++i)
                match = fieldMatches(fields[i], r.base + offset, bytes);
            if (!match) continue;

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
