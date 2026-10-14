#include "arch/assembler.hpp"
#include <optional>
#include <cstring>
#include "arch/disassembler.hpp"
#include "core/expression.hpp"
#include <keystone/keystone.h>
#include <stdexcept>
#include <cctype>
#include <algorithm>
#include <cstdio>
#include <vector>

namespace {
// Capstone emits Intel size specifiers with the "ptr" keyword ("qword ptr [..]",
// "byte ptr [..]"), but Keystone (LLVM MC) rejects "ptr" and wants "qword [..]".
// Strip the standalone word "ptr" so disassembly text re-assembles. "ptr" is not
// a valid mnemonic/register/symbol, so removing it everywhere is safe.
std::string stripPtrKeyword(const std::string& in) {
    auto isWord = [](unsigned char c) { return std::isalnum(c) || c == '_'; };
    std::string out;
    out.reserve(in.size());
    size_t i = 0;
    while (i < in.size()) {
        bool boundaryL = (i == 0) || !isWord(static_cast<unsigned char>(in[i - 1]));
        if (boundaryL && i + 3 <= in.size() &&
            std::tolower(static_cast<unsigned char>(in[i]))     == 'p' &&
            std::tolower(static_cast<unsigned char>(in[i + 1])) == 't' &&
            std::tolower(static_cast<unsigned char>(in[i + 2])) == 'r' &&
            (i + 3 == in.size() || !isWord(static_cast<unsigned char>(in[i + 3])))) {
            i += 3;                                   // drop "ptr"
            if (i < in.size() && in[i] == ' ') ++i;   // and one trailing space
            continue;                                 // leaves "qword [" (single space)
        }
        out += in[i++];
    }
    return out;
}

// Cheat Engine operand numbers are hex, with `#` marking decimal and `$` an
// explicit hex prefix; tables write `[rsi+1C]`, `mov [rax+C8],ecx`,
// `mov al,FF` and `mov eax,#1000`. Keystone only accepts hex that starts with
// a digit, and neither prefix, so rewrite those operand tokens to 0x form.
// Mnemonics, quoted text and labels defined in the same block are left alone,
// as are all-decimal-digit tokens (their existing Keystone meaning is kept).
std::string normalizeCeNumbers(const std::string& in) {
    auto isIdent = [](unsigned char c) { return std::isalnum(c) || c == '_' || c == '.' || c == '@' || c == '?'; };
    auto lower = [](std::string s) { for (auto& c : s) c = std::tolower(static_cast<unsigned char>(c)); return s; };
    auto allHex = [](const std::string& s) {
        return !s.empty() && std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isxdigit(c); });
    };
    // Labels defined anywhere in the block may be referenced before definition.
    std::vector<std::string> labels;
    for (size_t pos = 0; pos < in.size();) {
        size_t end = in.find_first_of(";\n", pos);
        if (end == std::string::npos) end = in.size();
        size_t i = pos;
        for (;;) {
            while (i < end && std::isspace(static_cast<unsigned char>(in[i]))) ++i;
            size_t start = i;
            while (i < end && isIdent(static_cast<unsigned char>(in[i]))) ++i;
            if (i == start || i >= end || in[i] != ':') break;
            labels.push_back(lower(in.substr(start, i - start)));
            ++i;
        }
        pos = end + 1;
    }
    static const char* prefixes[] = {"lock", "rep", "repe", "repz", "repne", "repnz", "bnd", "notrack", "xacquire", "xrelease"};
    std::string out;
    out.reserve(in.size() + 16);
    for (size_t pos = 0; pos <= in.size();) {
        size_t end = in.find_first_of(";\n", pos);
        if (end == std::string::npos) end = in.size();
        std::string statement = in.substr(pos, end - pos);
        size_t i = 0;
        // Skip label definitions, prefixes and the mnemonic itself.
        for (bool mnemonic = false; !mnemonic;) {
            while (i < statement.size() && std::isspace(static_cast<unsigned char>(statement[i]))) ++i;
            size_t start = i;
            while (i < statement.size() && isIdent(static_cast<unsigned char>(statement[i]))) ++i;
            if (i == start) break;
            if (i < statement.size() && statement[i] == ':') { ++i; continue; }
            auto word = lower(statement.substr(start, i - start));
            mnemonic = std::none_of(std::begin(prefixes), std::end(prefixes), [&](const char* p) { return word == p; });
        }
        std::string rewritten = statement.substr(0, i);
        while (i < statement.size()) {
            unsigned char c = statement[i];
            if (c == '"' || c == '\'') {
                size_t close = statement.find(static_cast<char>(c), i + 1);
                close = close == std::string::npos ? statement.size() : close + 1;
                rewritten += statement.substr(i, close - i);
                i = close;
                continue;
            }
            bool boundary = i == 0 || !isIdent(static_cast<unsigned char>(statement[i - 1]));
            if (!boundary || !(isIdent(c) || c == '#' || c == '$')) { rewritten += static_cast<char>(c); ++i; continue; }
            size_t start = i++;
            while (i < statement.size() && isIdent(static_cast<unsigned char>(statement[i]))) ++i;
            std::string token = statement.substr(start, i - start);
            if (token.size() > 1 && token[0] == '#' &&
                std::all_of(token.begin() + 1, token.end(), [](unsigned char d) { return std::isdigit(d); })) {
                try {
                    char hex[24];
                    snprintf(hex, sizeof(hex), "0x%llx", std::stoull(token.substr(1), nullptr, 10));
                    token = hex;
                } catch (...) {}   // out of range: leave it for Keystone to reject
            } else if (token.size() > 1 && token[0] == '$' && allHex(token.substr(1))) {
                token = "0x" + token.substr(1);
            } else if (allHex(token) && std::any_of(token.begin(), token.end(), [](unsigned char d) { return std::isalpha(d); }) &&
                       std::find(labels.begin(), labels.end(), lower(token)) == labels.end()) {
                token = "0x" + token;
            }
            rewritten += token;
        }
        out += rewritten;
        if (end < in.size()) out += in[end];
        pos = end + 1;
        if (end >= in.size()) break;
    }
    return out;
}
} // namespace

namespace ce {

Assembler::Assembler(AsmArch arch) : arch_(arch) {
    ks_arch ka;
    ks_mode km;
    switch (arch) {
        case AsmArch::X86_32: ka = KS_ARCH_X86;   km = KS_MODE_32; break;
        case AsmArch::X86_64: ka = KS_ARCH_X86;   km = KS_MODE_64; break;
        case AsmArch::ARM32:  ka = KS_ARCH_ARM;   km = KS_MODE_ARM; break;
        case AsmArch::ARM64:  ka = KS_ARCH_ARM64; km = KS_MODE_LITTLE_ENDIAN; break;
        case AsmArch::ARMThumb: ka = KS_ARCH_ARM; km = KS_MODE_THUMB; break;
        case AsmArch::ARM32_BE: ka = KS_ARCH_ARM; km = static_cast<ks_mode>(KS_MODE_ARM | KS_MODE_BIG_ENDIAN); break;
        case AsmArch::ARMThumb_BE: ka = KS_ARCH_ARM; km = static_cast<ks_mode>(KS_MODE_THUMB | KS_MODE_BIG_ENDIAN); break;
        default: throw std::invalid_argument("Unknown assembler architecture");
    }

    ks_engine* ks;
    if (ks_open(ka, km, &ks) != KS_ERR_OK)
        throw std::runtime_error("Failed to initialize Keystone");

    // NASM syntax matches CE's assembler style; it applies to x86 only (ARM uses its
    // own syntax, and setting NASM on an ARM engine is rejected).
    if (arch == AsmArch::X86_32 || arch == AsmArch::X86_64)
        ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_NASM);
    handle_ = reinterpret_cast<size_t>(ks);
}

Assembler::~Assembler() {
    if (handle_)
        ks_close(reinterpret_cast<ks_engine*>(handle_));
}

std::expected<std::vector<uint8_t>, std::string>
Assembler::assemble(const std::string& code, uintptr_t address) {
    size_t stmts;
    return assembleEx(code, address, stmts);
}

std::expected<std::vector<uint8_t>, std::string>
Assembler::assembleEx(const std::string& code, uintptr_t address, size_t& statementsOut) {
    auto* ks = reinterpret_cast<ks_engine*>(handle_);
    unsigned char* encoded = nullptr;
    size_t size = 0;
    size_t count = 0;

    std::string normalized = stripPtrKeyword(code);
    if (arch_ == AsmArch::X86_32 || arch_ == AsmArch::X86_64) normalized = normalizeCeNumbers(normalized);
    auto prefix = normalized.substr(0, 9);
    for (auto& c : prefix) c = std::tolower(static_cast<unsigned char>(c));
    if ((arch_ == AsmArch::X86_32 || arch_ == AsmArch::X86_64) && prefix == "jmp near ") {
        auto target = ExpressionParser().parse(normalized.substr(9));
        if (!target || address > UINTPTR_MAX - 5)
            return std::unexpected("Unresolved near jump destination");
        uintptr_t next = address + 5;
        uint32_t bits;
        if (arch_ == AsmArch::X86_32) {
            if (*target > UINT32_MAX || next > uint64_t(UINT32_MAX) + 1)
                return std::unexpected("Near jump exceeds the 32-bit address space");
            bits = static_cast<uint32_t>(*target) - static_cast<uint32_t>(next);
        } else {
            uint64_t distance = *target >= next ? *target - next : next - *target;
            if (distance > (*target >= next ? uint64_t(INT32_MAX) : uint64_t(INT32_MAX) + 1))
                return std::unexpected("Near jump destination is outside the 2 GiB range");
            bits = static_cast<uint32_t>(*target >= next ? int64_t(distance) : -int64_t(distance));
        }
        statementsOut = 1;
        return std::vector<uint8_t>{0xe9, static_cast<uint8_t>(bits), static_cast<uint8_t>(bits >> 8),
                                   static_cast<uint8_t>(bits >> 16), static_cast<uint8_t>(bits >> 24)};
    }
    // Keystone's NASM parser inconsistently treats numeric memory destinations:
    // MOV can encode the number as a RIP displacement while other instructions
    // encode an absolute destination. Retain destinations and verify/fix each
    // emitted instruction, including blocks with labels and multiple operands.
    std::vector<std::optional<uintptr_t>> memoryTargets;
    bool hasMemoryTarget = false;
    if (arch_ == AsmArch::X86_64) {
        size_t statementStart = 0;
        while (statementStart < normalized.size()) {
            size_t statementEnd = normalized.find_first_of(";\n", statementStart);
            if (statementEnd == std::string::npos) statementEnd = normalized.size();
            auto statement = normalized.substr(statementStart, statementEnd - statementStart);
            auto first = statement.find_first_not_of(" \t\r");
            // A label does not consume an instruction in the decoded output.
            while (first != std::string::npos) {
                auto colon = statement.find(':', first);
                auto space = statement.find_first_of(" \t[", first);
                if (colon == std::string::npos || (space != std::string::npos && space < colon)) break;
                first = statement.find_first_not_of(" \t\r", colon + 1);
            }
            if (first != std::string::npos) {
                std::optional<uintptr_t> target;
                auto open = statement.find('[', first), close = statement.find(']', open);
                if (open != std::string::npos && close != std::string::npos) {
                    auto expression = statement.substr(open + 1, close - open - 1);
                    auto begin = expression.find_first_not_of(" \t");
                    auto end = expression.find_last_not_of(" \t");
                    expression = begin == std::string::npos ? "" : expression.substr(begin, end - begin + 1);
                    auto keyword = expression.substr(0, 3);
                    for (auto& c : keyword) c = std::tolower(static_cast<unsigned char>(c));
                    bool relative = keyword == "rel" && expression.size() > 3 && std::isspace(static_cast<unsigned char>(expression[3]));
                    bool absolute = keyword == "abs" && expression.size() > 3 && std::isspace(static_cast<unsigned char>(expression[3]));
                    if (relative || absolute) expression = expression.substr(4);
                    // Bare NASM decimal literals differ from CE expression numbers.
                    bool decimal = !expression.empty() && std::all_of(expression.begin(), expression.end(),
                        [](unsigned char c) { return std::isdigit(c); });
                    if (relative || absolute || decimal || expression.starts_with("0x") || expression.starts_with("0X"))
                        target = ExpressionParser().parse(decimal && !relative && !absolute ? "#" + expression : expression);
                    if ((relative || absolute) && !target)
                        return std::unexpected("Unresolved memory destination");
                    if (relative) statement.replace(open + 1, close - open - 1, "rip+0");
                }
                hasMemoryTarget |= target.has_value();
                memoryTargets.push_back(target);
            }
            normalized.replace(statementStart, statementEnd - statementStart, statement);
            statementEnd = statementStart + statement.size();
            statementStart = statementEnd + 1;
        }
    }
    int r = ks_asm(ks, normalized.c_str(), address, &encoded, &size, &count);
    if (r != 0) {
        auto err = ks_errno(ks);
        return std::unexpected(std::string("Assembly error: ") + ks_strerror(err));
    }

    // Free the Keystone-allocated buffer on every exit path, including if the
    // vector construction below throws (OOM).
    struct EncodedGuard {
        unsigned char* p;
        ~EncodedGuard() { if (p) ks_free(p); }
    } guard{encoded};

    // Keystone can return KS_ERR_OK yet emit zero bytes for input it silently
    // rejects (e.g. some Capstone-style "qword ptr [reg+disp], reg64" forms).
    // Treat "non-blank input assembled to nothing" as a failure — otherwise
    // callers see success with an empty buffer (the GUI would then NOP-pad over
    // the original instruction, corrupting code).
    if (size == 0) {
        bool hasContent = code.find_first_not_of(" \t\r\n") != std::string::npos;
        if (hasContent)
            return std::unexpected(std::string(
                "Assembly produced no output (unsupported or invalid syntax)"));
    }

    std::vector<uint8_t> result(encoded, encoded + size);
    if (hasMemoryTarget) {
        if (size > UINTPTR_MAX - address)
            return std::unexpected("Assembly range exceeds the address space");
        Disassembler dis(Arch::X86_64);
        auto instructions = dis.disassemble(address, result);
        if (instructions.size() != memoryTargets.size() || instructions.empty() ||
            instructions.back().address + instructions.back().size != address + size)
            return std::unexpected("Cannot verify memory destinations in this assembly block");
        for (size_t i = 0; i < instructions.size(); ++i) {
            if (!memoryTargets[i]) continue;
            const auto& inst = instructions[i];
            uintptr_t target = *memoryTargets[i];
            if (!inst.memory.ripRelative) {
                if (!inst.memory.present || inst.memory.disp != static_cast<int64_t>(target))
                    return std::unexpected("Absolute memory destination cannot be represented by this instruction");
                continue;
            }
            if (inst.dispSize != 4 || size_t(inst.dispOffset) + 4 > inst.bytes.size())
                return std::unexpected("Cannot encode this relative memory operand");
            uintptr_t next = inst.address + inst.size;
            uint64_t distance = target >= next ? target - next : next - target;
            if (distance > (target >= next ? uint64_t(INT32_MAX) : uint64_t(INT32_MAX) + 1))
                return std::unexpected("Relative memory destination is outside the 2 GiB range");
            int64_t displacement = target >= next ? int64_t(distance) : -int64_t(distance);
            uint32_t bits = static_cast<uint32_t>(displacement);
            size_t offset = inst.address - address + inst.dispOffset;
            for (size_t j = 0; j < 4; ++j) result[offset + j] = static_cast<uint8_t>(bits >> (8 * j));
        }
    }
    // A relative jmp/call/jcc to a numeric destination (labels are numbers by
    // now): Keystone wraps a displacement it cannot represent instead of
    // failing, and the branch lands somewhere else. Decode it and compare.
    if ((arch_ == AsmArch::X86_32 || arch_ == AsmArch::X86_64) && count == 1 && !result.empty()) {
        std::string statement = normalized;
        while (!statement.empty() && std::isspace(static_cast<unsigned char>(statement.front()))) statement.erase(0, 1);
        const auto space = statement.find_first_of(" \t");
        std::string mnemonic = statement.substr(0, space);
        for (auto& c : mnemonic) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        const bool branch = mnemonic == "jmp" || mnemonic == "call" || (mnemonic.size() >= 2 && mnemonic[0] == 'j');
        if (branch && space != std::string::npos) {
            if (auto target = ExpressionParser().parse(statement.substr(space + 1))) {
                const uint8_t* b = result.data();
                const size_t n = result.size();
                std::optional<int64_t> rel;
                size_t length = 0;
                if ((b[0] == 0xE8 || b[0] == 0xE9) && n >= 5) { int32_t v; std::memcpy(&v, b + 1, 4); rel = v; length = 5; }
                else if ((b[0] == 0xEB || (b[0] >= 0x70 && b[0] <= 0x7F)) && n >= 2) { rel = static_cast<int8_t>(b[1]); length = 2; }
                else if (b[0] == 0x0F && n >= 6 && b[1] >= 0x80 && b[1] <= 0x8F) { int32_t v; std::memcpy(&v, b + 2, 4); rel = v; length = 6; }
                if (rel && length == n) {
                    uint64_t landed = static_cast<uint64_t>(address) + length + static_cast<uint64_t>(*rel);
                    uint64_t wanted = *target;
                    if (arch_ == AsmArch::X86_32) { landed &= 0xFFFFFFFFu; wanted &= 0xFFFFFFFFu; }
                    if (landed != wanted)
                        return std::unexpected("Branch destination is out of reach of a relative " + mnemonic +
                                               " from this address (more than 2 GiB away)");
                }
            }
        }
    }
    statementsOut = count;
    return result;
}

} // namespace ce
