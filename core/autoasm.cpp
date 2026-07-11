#include "core/autoasm.hpp"
#include "arch/disassembler.hpp"
#include "platform/linux/injector.hpp"
#include "symbols/elf_symbols.hpp"
#include <set>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <cctype>
#include <unistd.h>
#include <cstring>
#include <charconv>
#include <filesystem>
#include <regex>
#include <string_view>
#include <utility>
#include <vector>

namespace ce {

// ── Helpers ──

static std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    auto end = s.find_last_not_of(" \t\r\n");
    return (start == std::string::npos) ? "" : s.substr(start, end - start + 1);
}

static std::string toUpper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::toupper);
    return s;
}

static std::string normalizeCommandName(const std::string& name) {
    return toUpper(trim(name));
}

static bool startsWith(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

static std::string stripOptionalQuotes(std::string s) {
    s = trim(s);
    if (s.size() >= 2 &&
        ((s.front() == '"' && s.back() == '"') || (s.front() == '\'' && s.back() == '\''))) {
        return s.substr(1, s.size() - 2);
    }
    return s;
}

static std::vector<std::string> splitArgs(const std::string& args, size_t maxParts) {
    std::vector<std::string> parts;
    std::string current;
    char quote = 0;

    for (char c : args) {
        if ((c == '"' || c == '\'') && (quote == 0 || quote == c)) {
            quote = quote == c ? 0 : c;
            current.push_back(c);
            continue;
        }
        if (c == ',' && quote == 0 && parts.size() + 1 < maxParts) {
            parts.push_back(trim(current));
            current.clear();
            continue;
        }
        current.push_back(c);
    }

    parts.push_back(trim(current));
    return parts;
}

static std::string formatHex(uintptr_t address) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%lx", address);
    return buf;
}

static std::string formatHexLiteral(uintptr_t address) {
    return "0x" + formatHex(address);
}

static std::string stripInlineComment(std::string line) {
    // Scan for "//" but skip occurrences inside single/double-quoted spans, so a
    // data directive like  db "http://x",0  keeps its literal instead of being
    // truncated to  db "http:  (which then fails to parse).
    bool inS = false, inD = false;
    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (c == '\'' && !inD) inS = !inS;
        else if (c == '"' && !inS) inD = !inD;
        else if (!inS && !inD && c == '/' && i + 1 < line.size() && line[i + 1] == '/') {
            line = line.substr(0, i);
            break;
        }
    }
    return trim(line);
}

static bool runScriptHooks(const std::vector<AutoAssembler::ScriptHook>& hooks,
    std::string& code, std::vector<std::string>& log, std::string& error, const char* phase) {
    for (size_t i = 0; i < hooks.size(); ++i) {
        if (!hooks[i](code, log, error)) {
            if (error.empty())
                error = std::string("Auto-assembler ") + phase + " hook failed at index " + std::to_string(i);
            return false;
        }
    }
    return true;
}

static bool parseWholeUnsigned(const std::string& text, int base, uint64_t& value) {
    auto s = trim(text);
    if (s.empty())
        return false;

    size_t parsed = 0;
    try {
        value = std::stoull(s, &parsed, base);
    } catch (...) {
        return false;
    }
    return parsed == s.size();
}

static bool moduleMatches(const ModuleInfo& module, const std::string& requested) {
    auto req = stripOptionalQuotes(requested);
    auto reqUpper = toUpper(req);
    return toUpper(module.name) == reqUpper || toUpper(module.path) == reqUpper;
}

static size_t findAobInRange(ProcessHandle& proc, uintptr_t start, uintptr_t stop,
                             const std::vector<uint8_t>& pattern,
                             const std::vector<uint8_t>& mask,
                             uintptr_t& firstMatch) {
    if (pattern.empty() || stop <= start)
        return 0;

    size_t matches = 0;
    auto regions = proc.queryRegions();
    for (const auto& region : regions) {
        if (region.state != MemState::Committed || !(region.protection & MemProt::Read))
            continue;

        uintptr_t regionStart = std::max(region.base, start);
        uintptr_t regionEnd = std::min(region.base + region.size, stop);
        if (regionEnd <= regionStart || regionEnd - regionStart < pattern.size())
            continue;

        std::vector<uint8_t> buffer(regionEnd - regionStart);
        auto readResult = proc.read(regionStart, buffer.data(), buffer.size());
        if (!readResult || *readResult < pattern.size())
            continue;

        size_t bytesRead = *readResult;
        size_t limit = bytesRead - pattern.size() + 1;
        for (size_t offset = 0; offset < limit; ++offset) {
            bool matched = true;
            for (size_t i = 0; i < pattern.size(); ++i) {
                uint8_t m = i < mask.size() ? mask[i] : 0xFF;
                if ((buffer[offset + i] & m) != (pattern[i] & m)) {
                    matched = false;
                    break;
                }
            }
            if (matched) {
                if (matches == 0)
                    firstMatch = regionStart + offset;
                ++matches;
            }
        }
    }

    return matches;
}

static std::vector<std::string> splitDataValues(const std::string& data) {
    std::vector<std::string> values;
    std::string current;
    char quote = 0;

    for (char c : data) {
        if ((c == '"' || c == '\'') && (quote == 0 || quote == c)) {
            quote = quote == c ? 0 : c;
            current.push_back(c);
            continue;
        }
        if (quote == 0 && (c == ',' || std::isspace(static_cast<unsigned char>(c)))) {
            if (!trim(current).empty()) {
                values.push_back(trim(current));
                current.clear();
            }
            continue;
        }
        current.push_back(c);
    }

    if (!trim(current).empty())
        values.push_back(trim(current));
    return values;
}

// Evaluate a data-directive value that may contain +/- arithmetic between terms,
// e.g. "0x1000+4" (a label+offset after symbol substitution, for indexed pointer
// tables). Each term is hex by default, or #decimal. No hex digit is '+' or '-',
// so splitting on those signs is unambiguous.
static bool evalDataToken(const std::string& tok, uint64_t& out) {
    if (tok.empty()) return false;
    uint64_t acc = 0;
    bool sub = false;
    size_t i = 0;
    if (tok[0] == '+' || tok[0] == '-') { sub = (tok[0] == '-'); i = 1; }
    while (i < tok.size()) {
        size_t j = i;
        while (j < tok.size() && tok[j] != '+' && tok[j] != '-') ++j;
        std::string term = trim(tok.substr(i, j - i));
        if (term.empty()) return false;
        uint64_t v;
        try {
            if (term[0] == '#') v = std::stoull(term.substr(1), nullptr, 10);
            else                v = std::stoull(term, nullptr, 16);
        } catch (...) { return false; }
        acc = sub ? (acc - v) : (acc + v);
        if (j < tok.size()) { sub = (tok[j] == '-'); i = j + 1; } else break;
    }
    out = acc;
    return true;
}

static bool parseDataDirective(const std::string& op, const std::string& data,
                               std::vector<uint8_t>& bytes, std::string& error) {
    size_t width = 1;
    if (op == "DW") width = 2;
    else if (op == "DD") width = 4;
    else if (op == "DQ") width = 8;

    auto values = splitDataValues(data);
    if (values.empty()) {
        error = op + " requires at least one value";
        return false;
    }

    uint64_t maxValue = width == 8 ? UINT64_MAX : ((uint64_t{1} << (width * 8)) - 1);
    for (auto token : values) {
        token = trim(token);
        if (token.size() >= 2 &&
            ((token.front() == '"' && token.back() == '"') || (token.front() == '\'' && token.back() == '\''))) {
            if (width != 1) {
                error = op + " string literal is only supported for DB";
                return false;
            }
            auto text = stripOptionalQuotes(token);
            bytes.insert(bytes.end(), text.begin(), text.end());
            continue;
        }

        // (float)N / (double)N cast: store the IEEE-754 bit pattern (patching
        // float/double constants — a very common AA use). Parse the number
        // locale-independently (from_chars, comma normalised to dot): this host's
        // LC_NUMERIC is comma-decimal, which would make strtod stop at the '.'.
        {
            std::string lower = token;
            std::transform(lower.begin(), lower.end(), lower.begin(),
                [](unsigned char c) { return std::tolower(c); });
            bool isFloat  = lower.rfind("(float)", 0) == 0;
            bool isDouble = lower.rfind("(double)", 0) == 0;
            if (isFloat || isDouble) {
                std::string num = trim(token.substr(isDouble ? 8 : 7));
                for (auto& c : num) if (c == ',') c = '.';
                const char* b = num.c_str();
                const char* e = b + num.size();
                if (isFloat) {
                    float f = 0;
                    if (std::from_chars(b, e, f).ec != std::errc()) {
                        error = "Invalid " + op + " float value: " + token; return false;
                    }
                    uint32_t bits; std::memcpy(&bits, &f, 4);
                    for (int i = 0; i < 4; ++i) bytes.push_back((uint8_t)((bits >> (i * 8)) & 0xFF));
                } else {
                    double d = 0;
                    if (std::from_chars(b, e, d).ec != std::errc()) {
                        error = "Invalid " + op + " double value: " + token; return false;
                    }
                    uint64_t bits; std::memcpy(&bits, &d, 8);
                    for (int i = 0; i < 8; ++i) bytes.push_back((uint8_t)((bits >> (i * 8)) & 0xFF));
                }
                continue;
            }
        }

        // CE data directives default to hex; a leading '#' means decimal. Values
        // may also contain +/- arithmetic (e.g. "label+8" after substitution).
        uint64_t value = 0;
        if (!evalDataToken(token, value)) {
            error = "Invalid " + op + " value: " + token;
            return false;
        }

        if (value > maxValue) {
            error = op + " value out of range: " + token;
            return false;
        }

        for (size_t i = 0; i < width; ++i)
            bytes.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
    }

    return true;
}

static bool parseStructDataSize(const std::string& line, size_t& size, std::string& error) {
    auto trimmed = trim(line);
    auto upper = toUpper(trimmed);
    size = 0;

    if (startsWith(upper, "DB ") || startsWith(upper, "DW ") ||
        startsWith(upper, "DD ") || startsWith(upper, "DQ ")) {
        size_t width = 1;
        auto op = upper.substr(0, 2);
        if (op == "DW") width = 2;
        else if (op == "DD") width = 4;
        else if (op == "DQ") width = 8;

        auto values = splitDataValues(trimmed.substr(3));
        if (values.empty()) {
            error = "STRUCT data directive requires at least one value";
            return false;
        }

        for (auto token : values) {
            token = trim(token);
            if (token.size() >= 2 &&
                ((token.front() == '"' && token.back() == '"') || (token.front() == '\'' && token.back() == '\''))) {
                if (width != 1) {
                    error = "STRUCT string literal is only supported for DB";
                    return false;
                }
                size += stripOptionalQuotes(token).size();
                continue;
            }
            size += width;
        }
        return true;
    }

    if (startsWith(upper, "DS ")) {
        auto text = stripOptionalQuotes(trimmed.substr(3));
        if (text.empty()) {
            error = "STRUCT DS requires a string";
            return false;
        }
        size = text.size();
        return true;
    }

    return false;
}

static bool isSimpleLabelDefinition(const std::string& line) {
    return !line.empty() && line.back() == ':' && line.find_first_of(" \t") == std::string::npos;
}

// Cheat Engine auto-registers any "name:" label defined anywhere in the script,
// so a forward "jmp skip ... skip:" works without an explicit label(skip). Our
// sizing pass aborts on the forward reference before it reaches the definition,
// so mirror the anonymous-label mechanism: emit label() for every named
// definition that is not already declared (via alloc/label/define/registersymbol/
// globalalloc). Prepending these declarations makes the label known on pass 1.
static void autoDeclareNamedLabels(std::string& code) {
    auto firstArg = [](const std::string& line, size_t open) -> std::string {
        size_t end = line.find_first_of(",)", open);
        return trim(line.substr(open, end == std::string::npos ? std::string::npos : end - open));
    };
    std::set<std::string> declared, defined;
    std::vector<std::string> order;   // preserve definition order for stable output
    std::istringstream ss(code);
    std::string raw;
    while (std::getline(ss, raw)) {
        std::string line = trim(raw);
        std::string upper = toUpper(line);
        if (startsWith(upper, "ALLOC("))               declared.insert(firstArg(line, 6));
        else if (startsWith(upper, "GLOBALALLOC("))     declared.insert(firstArg(line, 12));
        else if (startsWith(upper, "KALLOC("))          declared.insert(firstArg(line, 7));
        else if (startsWith(upper, "DEFINE("))          declared.insert(firstArg(line, 7));
        else if (startsWith(upper, "REGISTERSYMBOL("))  declared.insert(firstArg(line, 15));
        // AOB-scan results define a symbol at runtime; the injection point is
        // written as "name:" (e.g. aobscanmodule(INJECT,..) ... INJECT: jmp newmem).
        // That name must resolve to the scanned address, so it must NOT be
        // auto-declared as a fresh (address-0) forward label that would shadow it.
        else if (startsWith(upper, "AOBSCANMODULE("))    declared.insert(firstArg(line, 14));
        else if (startsWith(upper, "AOBSCANREGION("))    declared.insert(firstArg(line, 14));
        else if (startsWith(upper, "AOBSCANALL("))       declared.insert(firstArg(line, 11));
        else if (startsWith(upper, "AOBSCAN("))          declared.insert(firstArg(line, 8));
        else if (startsWith(upper, "LABEL(") && line.back() == ')') {
            std::istringstream a(line.substr(6, line.size() - 7));
            std::string n;
            while (std::getline(a, n, ',')) declared.insert(trim(n));
        } else if (isSimpleLabelDefinition(line)) {
            std::string name = line.substr(0, line.size() - 1);
            // Only genuine identifier labels — NOT address injection points like
            // "00401000:" or "module+off:" (which isSimpleLabelDefinition also
            // matches). A label name starts with a letter/underscore and is
            // alphanumeric/underscore throughout.
            bool ident = !name.empty() &&
                (std::isalpha((unsigned char)name[0]) || name[0] == '_') &&
                std::all_of(name.begin(), name.end(), [](unsigned char c) {
                    return std::isalnum(c) || c == '_';
                });
            if (ident && name.rfind("__anon_", 0) != 0 && defined.insert(name).second)
                order.push_back(name);
        }
    }
    std::string preamble;
    for (const auto& name : order)
        if (!declared.count(name)) preamble += "label(" + name + ")\n";
    if (!preamble.empty()) code = preamble + code;
}

static bool parseNopCount(const std::string& countExpr, size_t& count, std::string& error) {
    try {
        count = countExpr.empty() ? 1 : std::stoull(countExpr, nullptr, 0);
    } catch (...) {
        error = "Invalid NOP count: " + countExpr;
        return false;
    }
    if (count == 0) {
        error = "NOP count must be greater than zero";
        return false;
    }
    return true;
}

static bool expandStructDefinitions(const std::string& code, std::string& expanded,
                                    std::vector<std::string>& log, std::string& error) {
    std::istringstream ss(code);
    std::string rawLine;
    std::string generated;
    std::string body;
    bool inStruct = false;
    std::string structName;
    size_t offset = 0;

    while (std::getline(ss, rawLine)) {
        auto line = stripInlineComment(rawLine);
        auto upper = toUpper(line);

        if (!inStruct) {
            if (startsWith(upper, "STRUCT ")) {
                structName = trim(line.substr(7));
                if (structName.empty()) {
                    error = "STRUCT requires a name";
                    return false;
                }
                inStruct = true;
                offset = 0;
                log.push_back("STRUCT: " + structName);
                continue;
            }

            body += rawLine + "\n";
            continue;
        }

        if (line.empty() || line[0] == ';' || line[0] == '/')
            continue;

        if (upper == "ENDS" || upper == "ENDSTRUCT") {
            generated += "define(" + structName + "," + formatHexLiteral(offset) + ")\n";
            log.push_back("ENDSTRUCT: " + structName + " size=" + std::to_string(offset));
            inStruct = false;
            structName.clear();
            continue;
        }

        auto work = line;
        auto colon = work.find(':');
        if (colon != std::string::npos) {
            auto field = trim(work.substr(0, colon));
            if (field.empty()) {
                error = "STRUCT has an empty field name";
                return false;
            }

            auto value = formatHexLiteral(offset);
            generated += "define(" + structName + "." + field + "," + value + ")\n";
            generated += "define(" + field + "," + value + ")\n";
            log.push_back("STRUCT: " + structName + "." + field + " = " + value);
            work = trim(work.substr(colon + 1));
            if (work.empty())
                continue;
            upper = toUpper(work);
        }

        size_t dataSize = 0;
        std::string sizeError;
        if (parseStructDataSize(work, dataSize, sizeError)) {
            offset += dataSize;
            continue;
        }
        if (!sizeError.empty()) {
            error = sizeError;
            return false;
        }

        error = "Unsupported STRUCT line in " + structName + ": " + work;
        return false;
    }

    if (inStruct) {
        error = "STRUCT missing ENDSTRUCT/ENDS: " + structName;
        return false;
    }

    expanded = generated + body;
    return true;
}

// Parse "name, size [, preferred]" from inside ALLOC(...). The optional
// preferred (near) address is returned as a raw expression — it may be a symbol
// (e.g. an aobscanmodule result) that is only known later, so it is resolved at
// allocation time rather than here.
static bool parseAllocArgs(const std::string& args, std::string& name, size_t& size,
                           std::string& preferredExpr) {
    std::istringstream ss(args);
    std::string token;
    std::getline(ss, token, ','); name = trim(token);
    if (!std::getline(ss, token, ',')) return false;
    std::string sizeStr = trim(token);
    // CE-style $ hex prefix → 0x prefix so std::stoull(0) handles it.
    if (!sizeStr.empty() && sizeStr.front() == '$')
        sizeStr = "0x" + sizeStr.substr(1);
    try {
        size = std::stoull(sizeStr, nullptr, 0);
    } catch (...) {
        return false;
    }
    preferredExpr.clear();
    if (std::getline(ss, token, ','))
        preferredExpr = trim(token);
    return true;
}

// ── Section extraction ──

std::string AutoAssembler::extractSection(const std::string& script, const std::string& section) {
    auto tag = "[" + section + "]";
    auto tagUpper = toUpper(tag);
    std::istringstream ss(script);
    std::string line;
    std::string result;
    bool inSection = false;

    while (std::getline(ss, line)) {
        auto trimmed = toUpper(trim(line));
        if (trimmed == tagUpper) {
            inSection = true;
            continue;
        }
        if (inSection && trimmed.size() > 2 && trimmed[0] == '[' && trimmed.back() == ']') {
            break; // Next section
        }
        if (inSection)
            result += line + "\n";
    }
    return result;
}

// ── Line parsing ──

bool AutoAssembler::parseLine(const std::string& rawLine,
    std::vector<Alloc>& allocs, std::vector<Label>& labels,
    std::vector<Define>& defines, std::vector<std::string>& registeredSymbols,
    std::vector<std::string>& asmLines, std::vector<std::string>& log,
    ProcessHandle* proc, std::string& error, int includeDepth)
{
    auto line = trim(rawLine);
    if (line.empty() || line[0] == '/' || line[0] == ';') return true; // Comment

    // Strip inline comments (quote-aware, so db "http://x" survives)
    line = stripInlineComment(line);
    if (line.empty()) return true;

    auto upper = toUpper(line);

    if (upper == "{$TRY}") {
        asmLines.push_back("__TRY_BEGIN__");
        return true;
    }
    if (upper == "{$EXCEPT}") {
        asmLines.push_back("__TRY_EXCEPT__");
        return true;
    }
    if (upper == "{$ENDTRY}") {
        asmLines.push_back("__TRY_END__");
        return true;
    }

    // ALLOC(name, size [, preferred])
    if (startsWith(upper, "ALLOC(") && line.back() == ')') {
        auto args = line.substr(6, line.size() - 7);
        Alloc a;
        if (!parseAllocArgs(args, a.name, a.size, a.preferredExpr)) {
            error = "Invalid alloc() arguments: " + args;
            return false;
        }
        a.address = 0;
        allocs.push_back(a);
        log.push_back("ALLOC: " + a.name + " size=" + std::to_string(a.size));
        return true;
    }

    // GLOBALALLOC(name, size [, preferred]) — same as ALLOC but the symbol
    // is also exported to the cross-script symbol table so other AA scripts
    // can reference it after activation.
    if (startsWith(upper, "GLOBALALLOC(") && line.back() == ')') {
        auto args = line.substr(12, line.size() - 13);
        Alloc a;
        if (!parseAllocArgs(args, a.name, a.size, a.preferredExpr)) {
            error = "Invalid globalalloc() arguments: " + args;
            return false;
        }
        a.address = 0;
        allocs.push_back(a);
        registeredSymbols.push_back(a.name);  // export after resolution
        log.push_back("GLOBALALLOC: " + a.name + " size=" + std::to_string(a.size));
        return true;
    }

    // KALLOC(name, size [, preferred]) — same shape as ALLOC. On Linux the
    // kernel doesn't expose ring-0 executable allocations to user-space; we
    // fall back to the same mmap path as ALLOC and warn so scripts that
    // depend on kernel-side memory know the difference.
    if (startsWith(upper, "KALLOC(") && line.back() == ')') {
        auto args = line.substr(7, line.size() - 8);
        Alloc a;
        if (!parseAllocArgs(args, a.name, a.size, a.preferredExpr)) {
            error = "Invalid kalloc() arguments: " + args;
            return false;
        }
        a.address = 0;
        allocs.push_back(a);
        log.push_back("KALLOC (mapped as ALLOC on Linux): " + a.name +
                      " size=" + std::to_string(a.size));
        return true;
    }

    // UNLOCK / LOCK prefix shortcuts. CE's AA accepts `unlock` as a
    // standalone line that flips a flag for the next emitted instruction,
    // wrapping it with the `lock` x86 prefix where supported. Our backend
    // (Keystone) accepts `lock` as a regular prefix, so we just rewrite
    // `unlock<space><rest>` into `lock <rest>` here.
    if (startsWith(upper, "UNLOCK ")) {
        std::string rest = line.substr(7);
        asmLines.push_back("lock " + rest);
        return true;
    }

    // BREAK — diagnostic syntax error with optional message. Used in AA
    // scripts to fail fast when a precondition isn't met.
    if (upper == "BREAK" || startsWith(upper, "BREAK ") || startsWith(upper, "BREAK(")) {
        std::string msg = line.size() > 5 ? trim(line.substr(5)) : std::string{};
        if (!msg.empty() && msg.front() == '(' && msg.back() == ')')
            msg = msg.substr(1, msg.size() - 2);
        error = msg.empty() ? "BREAK encountered" : ("BREAK: " + msg);
        return false;
    }

    if (startsWith(upper, "DEALLOC(") && line.back() == ')') {
        auto args = line.substr(8, line.size() - 9);
        asmLines.push_back("__DEALLOC__:" + args);
        return true;
    }

    // LABEL(name1, name2, ...)
    if (startsWith(upper, "LABEL(") && line.back() == ')') {
        auto args = line.substr(6, line.size() - 7);
        std::istringstream ss(args);
        std::string name;
        while (std::getline(ss, name, ',')) {
            Label l;
            l.name = trim(name);
            l.address = 0;
            labels.push_back(l);
        }
        return true;
    }

    // DEFINE(name, value)
    if (startsWith(upper, "DEFINE(") && line.back() == ')') {
        auto args = line.substr(7, line.size() - 8);
        auto comma = args.find(',');
        if (comma != std::string::npos) {
            Define d;
            d.name = trim(args.substr(0, comma));
            d.value = trim(args.substr(comma + 1));
            defines.push_back(d);
        }
        return true;
    }

    // REGISTERSYMBOL(name)
    if (startsWith(upper, "REGISTERSYMBOL(") && line.back() == ')') {
        auto args = line.substr(15, line.size() - 16);
        std::istringstream ss(args);
        std::string name;
        while (std::getline(ss, name, ','))
            registeredSymbols.push_back(trim(name));
        return true;
    }

    if (startsWith(upper, "UNREGISTERSYMBOL(") && line.back() == ')') {
        constexpr std::string_view prefix = "UNREGISTERSYMBOL(";
        auto args = line.substr(prefix.size(), line.size() - prefix.size() - 1);
        asmLines.push_back("__UNREGISTERSYMBOL__:" + args);
        return true;
    }

    // FULLACCESS(address, size) — make memory writable
    if (startsWith(upper, "FULLACCESS(") && line.back() == ')') {
        auto args = line.substr(11, line.size() - 12);
        asmLines.push_back("__FULLACCESS__:" + args);
        return true;
    }

    // ASSERT(address, bytes) — verify bytes at address before proceeding
    if (startsWith(upper, "ASSERT(") && line.back() == ')') {
        auto args = line.substr(7, line.size() - 8);
        auto comma = args.find(',');
        if (comma != std::string::npos) {
            auto addrExpr = trim(args.substr(0, comma));
            auto bytesStr = trim(args.substr(comma + 1));
            log.push_back("ASSERT: " + addrExpr + " = " + bytesStr);
        }
        asmLines.push_back("__ASSERT__:" + args);
        return true;
    }

    // AOBSCANREGION(name, start, stop, pattern) — find pattern in an address range
    if (startsWith(upper, "AOBSCANREGION(") && line.back() == ')' && proc) {
        auto args = line.substr(14, line.size() - 15);
        auto parts = splitArgs(args, 4);
        if (parts.size() == 4) {
            auto name = trim(parts[0]);
            auto startExpr = trim(parts[1]);
            auto stopExpr = trim(parts[2]);
            auto pattern = stripOptionalQuotes(parts[3]);
            auto start = resolveAddress(startExpr, allocs, labels, defines);
            auto stop = resolveAddress(stopExpr, allocs, labels, defines);
            if (!start || !stop || stop <= start) {
                log.push_back("AOBSCANREGION: " + name + " invalid range");
                return true;
            }

            ScanConfig cfg;
            cfg.parseAOB(pattern);
            uintptr_t addr = 0;
            size_t matches = findAobInRange(*proc, start, stop, cfg.byteArray, cfg.byteArrayMask, addr);
            if (matches > 0) {
                Define d;
                d.name = name;
                d.value = formatHex(addr);
                defines.push_back(d);
                log.push_back("AOBSCANREGION: " + name + " = 0x" + d.value +
                    " (" + std::to_string(matches) + " matches)");
            } else {
                log.push_back("AOBSCANREGION: " + name + " NOT FOUND");
            }
        }
        return true;
    }

    // AOBSCANALL(name, pattern) — find pattern across all readable memory
    if (startsWith(upper, "AOBSCANALL(") && line.back() == ')' && proc) {
        auto args = line.substr(11, line.size() - 12);
        auto parts = splitArgs(args, 2);
        if (parts.size() == 2) {
            auto name = trim(parts[0]);
            auto pattern = stripOptionalQuotes(parts[1]);

            ScanConfig cfg;
            cfg.valueType = ValueType::ByteArray;
            cfg.parseAOB(pattern);
            cfg.alignment = 1;

            MemoryScanner scanner;
            auto result = scanner.firstScan(*proc, cfg);
            if (result.count() > 0) {
                Define d;
                d.name = name;
                d.value = formatHex(result.address(0));
                defines.push_back(d);
                log.push_back("AOBSCANALL: " + name + " = 0x" + d.value +
                    " (" + std::to_string(result.count()) + " matches)");
            } else {
                log.push_back("AOBSCANALL: " + name + " NOT FOUND");
            }
        }
        return true;
    }

    // AOBSCANMODULE(name, module, pattern) — find pattern inside one module
    if (startsWith(upper, "AOBSCANMODULE(") && line.back() == ')' && proc) {
        auto args = line.substr(14, line.size() - 15);
        auto parts = splitArgs(args, 3);
        if (parts.size() == 3) {
            auto name = trim(parts[0]);
            auto moduleName = stripOptionalQuotes(parts[1]);
            auto pattern = stripOptionalQuotes(parts[2]);

            auto modules = proc->modules();
            auto moduleIt = std::find_if(modules.begin(), modules.end(), [&](const ModuleInfo& module) {
                return moduleMatches(module, moduleName);
            });
            if (moduleIt == modules.end()) {
                log.push_back("AOBSCANMODULE: " + name + " module not found: " + moduleName);
                return true;
            }

            ScanConfig cfg;
            cfg.parseAOB(pattern);
            uintptr_t addr = 0;
            size_t matches = findAobInRange(*proc, moduleIt->base, moduleIt->base + moduleIt->size,
                cfg.byteArray, cfg.byteArrayMask, addr);
            if (matches > 0) {
                Define d;
                d.name = name;
                d.value = formatHex(addr);
                defines.push_back(d);
                log.push_back("AOBSCANMODULE: " + name + " = 0x" + d.value +
                    " in " + moduleIt->name + " (" + std::to_string(matches) + " matches)");
            } else {
                log.push_back("AOBSCANMODULE: " + name + " NOT FOUND in " + moduleIt->name);
            }
        }
        return true;
    }

    // AOBSCAN(name, pattern) — find pattern
    if (startsWith(upper, "AOBSCAN(") && line.back() == ')' && proc) {
        auto args = line.substr(8, line.size() - 9);
        auto parts = splitArgs(args, 2);
        if (parts.size() == 2) {
            auto name = trim(parts[0]);
            auto pattern = stripOptionalQuotes(parts[1]);

            // Use our scanner's AOB
            ScanConfig cfg;
            cfg.valueType = ValueType::ByteArray;
            cfg.parseAOB(pattern);
            cfg.alignment = 1;

            MemoryScanner scanner;
            auto result = scanner.firstScan(*proc, cfg);
            if (result.count() > 0) {
                uintptr_t addr = result.address(0);
                Define d;
                d.name = name;
                d.value = formatHex(addr);
                defines.push_back(d);
                log.push_back("AOBSCAN: " + name + " = 0x" + d.value +
                    " (" + std::to_string(result.count()) + " matches)");
            } else {
                log.push_back("AOBSCAN: " + name + " NOT FOUND");
            }
        }
        return true;
    }

    // CREATETHREAD(address) — create remote thread at address after injection
    if (startsWith(upper, "CREATETHREAD(") && line.back() == ')') {
        auto addr = trim(line.substr(13, line.size() - 14));
        log.push_back("CREATETHREAD: " + addr + " (deferred to post-injection)");
        // Store for execution after all writes complete
        asmLines.push_back("__CREATETHREAD__:" + addr);
        return true;
    }

    // CREATETHREADANDWAIT(address[, timeout])
    if (startsWith(upper, "CREATETHREADANDWAIT(") && line.back() == ')') {
        auto args = trim(line.substr(20, line.size() - 21));
        log.push_back("CREATETHREADANDWAIT: " + args);
        asmLines.push_back("__CREATETHREADANDWAIT__:" + args);
        return true;
    }

    // INCLUDE(filename) — include another .cea script
    if (startsWith(upper, "INCLUDE(") && line.back() == ')') {
        auto filename = trim(line.substr(8, line.size() - 9));
        // Remove quotes
        if (!filename.empty() && filename.front() == '"') filename = filename.substr(1);
        if (!filename.empty() && filename.back() == '"') filename.pop_back();

        // Bound recursion: a cap on include depth prevents stack exhaustion
        // from a self-including .cea or an A→B→A cycle.
        // TODO(security): also track a visited-set of std::filesystem::weakly_canonical
        // paths to detect and report true cycles rather than only capping depth.
        constexpr int kMaxIncludeDepth = 16;
        if (includeDepth >= kMaxIncludeDepth) {
            error = "INCLUDE nesting too deep (limit " +
                std::to_string(kMaxIncludeDepth) + "): " + filename;
            return false;
        }

        // Read the file and parse each line
        std::ifstream incFile(filename);
        if (incFile) {
            std::string incLine;
            while (std::getline(incFile, incLine)) {
                if (!parseLine(incLine, allocs, labels, defines, registeredSymbols, asmLines, log, proc, error, includeDepth + 1))
                    return false;
            }
            log.push_back("INCLUDE: " + filename + " (loaded)");
        } else {
            log.push_back("INCLUDE: " + filename + " (NOT FOUND)");
        }
        return true;
    }

    // REASSEMBLE(address) — disassemble instruction at address and re-emit it
    if (startsWith(upper, "REASSEMBLE(") && line.back() == ')' && proc) {
        auto addrExpr = trim(line.substr(11, line.size() - 12));
        asmLines.push_back("__REASSEMBLE__:" + addrExpr);
        return true;
    }

    // READMEM(address, size) — read bytes from process memory, emit as db
    if (startsWith(upper, "READMEM(") && line.back() == ')') {
        auto args = trim(line.substr(8, line.size() - 9));
        asmLines.push_back("__READMEM__:" + args);
        return true;
    }

    // LOADBINARY(address, filename)
    if (startsWith(upper, "LOADBINARY(") && line.back() == ')') {
        auto args = trim(line.substr(11, line.size() - 12));
        asmLines.push_back("__LOADBINARY__:" + args);
        return true;
    }

    // LOADLIBRARY(path) — dlopen a shared object inside the target process.
    if (startsWith(upper, "LOADLIBRARY(") && line.back() == ')') {
        auto args = trim(line.substr(12, line.size() - 13));
        asmLines.push_back("__LOADLIBRARY__:" + args);
        return true;
    }

    // FILLMEM(address, size, value)
    if (startsWith(upper, "FILLMEM(") && line.back() == ')') {
        auto args = trim(line.substr(8, line.size() - 9));
        asmLines.push_back("__FILLMEM__:" + args);
        return true;
    }

    // NOP [count] — emit one or more 0x90 bytes at the active address.
    if (upper == "NOP" || startsWith(upper, "NOP ")) {
        auto count = trim(line.size() > 3 ? line.substr(3) : "1");
        asmLines.push_back("__NOP__:" + count);
        return true;
    }

    // DS "text" — emit string bytes at the active address.
    if (startsWith(upper, "DS ")) {
        asmLines.push_back("__DS__:" + trim(line.substr(3)));
        return true;
    }

    std::string customName;
    std::string customArgs;
    auto openParen = line.find('(');
    if (openParen != std::string::npos && line.back() == ')') {
        customName = trim(line.substr(0, openParen));
        customArgs = line.substr(openParen + 1, line.size() - openParen - 2);
    } else {
        auto firstSpace = line.find_first_of(" \t");
        customName = firstSpace == std::string::npos ? line : trim(line.substr(0, firstSpace));
        customArgs = firstSpace == std::string::npos ? "" : trim(line.substr(firstSpace + 1));
    }

    auto customIt = customCommands_.find(normalizeCommandName(customName));
    if (customIt != customCommands_.end()) {
        std::vector<std::string> expandedLines;
        if (!customIt->second(customArgs, expandedLines, log, error)) {
            if (error.empty())
                error = "Custom command failed: " + customName;
            return false;
        }

        for (const auto& expandedLine : expandedLines) {
            if (!parseLine(expandedLine, allocs, labels, defines, registeredSymbols, asmLines, log, proc, error, includeDepth))
                return false;
        }
        return true;
    }

    // Everything else is an assembly line or label definition
    asmLines.push_back(line);
    return true;
}

// ── Symbol resolution ──

uintptr_t AutoAssembler::resolveAddress(const std::string& expr,
    const std::vector<Alloc>& allocs, const std::vector<Label>& labels,
    const std::vector<Define>& defines) const
{
    auto name = trim(expr);

    // Check allocs
    for (auto& a : allocs)
        if (a.name == name) return a.address;

    // Check labels
    for (auto& l : labels)
        if (l.name == name) return l.address;

    // Check defines
    for (auto& d : defines)
        if (d.name == name) {
            uint64_t parsed = 0;
            if (parseWholeUnsigned(d.value, 16, parsed))
                return static_cast<uintptr_t>(parsed);
        }

    // Check global symbols
    auto it = globalSymbols_.find(name);
    if (it != globalSymbols_.end()) return it->second;

    // Try module+offset format (module.exe+1234)
    auto plus = name.find('+');
    if (plus != std::string::npos) {
        auto base = name.substr(0, plus);
        auto offset = name.substr(plus + 1);
        auto baseAddr = resolveAddress(base, allocs, labels, defines);
        if (baseAddr) {
            uint64_t parsedOffset = 0;
            if (parseWholeUnsigned(offset, 16, parsedOffset))
                return baseAddr + static_cast<uintptr_t>(parsedOffset);
        }
    }

    // Try as hex address
    uint64_t parsed = 0;
    if (parseWholeUnsigned(name, 16, parsed))
        return static_cast<uintptr_t>(parsed);

    return 0;
}

std::string AutoAssembler::substituteSymbols(const std::string& line,
    const std::vector<Alloc>& allocs, const std::vector<Label>& labels,
    const std::vector<Define>& defines) const
{
    // Replace `name` with `value` only on identifier boundaries, so a symbol
    // named `ax` is not substituted inside `rax`/`eax` and a define name that
    // is a substring of a mnemonic or another symbol is not clobbered.
    auto isIdentChar = [](char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') || c == '_';
    };

    // Sort so longer names substitute first (avoids partial-name clobbering).
    auto sortedDefines = defines;
    std::sort(sortedDefines.begin(), sortedDefines.end(),
        [](const Define& a, const Define& b) { return a.name.size() > b.name.size(); });
    auto sortedAllocs = allocs;
    std::sort(sortedAllocs.begin(), sortedAllocs.end(),
        [](const Alloc& a, const Alloc& b) { return a.name.size() > b.name.size(); });
    auto sortedLabels = labels;
    std::sort(sortedLabels.begin(), sortedLabels.end(),
        [](const Label& a, const Label& b) { return a.name.size() > b.name.size(); });

    // Apply all substitutions to one span of text.
    auto substituteSpan = [&](std::string result) -> std::string {
        auto replaceWholeToken = [&](const std::string& name, const std::string& value) {
            if (name.empty()) return;
            size_t pos = 0;
            while ((pos = result.find(name, pos)) != std::string::npos) {
                bool leftOk  = (pos == 0) || !isIdentChar(result[pos - 1]);
                size_t after = pos + name.size();
                bool rightOk = (after >= result.size()) || !isIdentChar(result[after]);
                if (leftOk && rightOk) {
                    result.replace(pos, name.size(), value);
                    pos += value.size();
                } else {
                    pos += 1;
                }
            }
        };
        for (auto& d : sortedDefines) replaceWholeToken(d.name, d.value);
        for (auto& a : sortedAllocs) {
            if (a.address == 0) continue;
            char addr[32]; snprintf(addr, sizeof(addr), "0x%lx", a.address);
            replaceWholeToken(a.name, addr);
        }
        for (auto& l : sortedLabels) {
            if (l.address == 0) continue;
            char addr[32]; snprintf(addr, sizeof(addr), "0x%lx", l.address);
            replaceWholeToken(l.name, addr);
        }
        return result;
    };

    // Substitute only OUTSIDE quoted string literals, so a db "text" that happens
    // to contain a symbol name (e.g. db "mylabel") is written verbatim.
    std::string out;
    size_t i = 0;
    while (i < line.size()) {
        char c = line[i];
        if (c == '"' || c == '\'') {
            char q = c;
            size_t start = i++;
            while (i < line.size() && line[i] != q) ++i;
            if (i < line.size()) ++i;                 // include the closing quote
            out += line.substr(start, i - start);      // verbatim
        } else {
            size_t start = i;
            while (i < line.size() && line[i] != '"' && line[i] != '\'') ++i;
            out += substituteSpan(line.substr(start, i - start));
        }
    }
    return out;
}

bool AutoAssembler::resolveForwardLabels(const std::vector<std::string>& asmLines,
    const std::vector<Alloc>& allocs, std::vector<Label>& labels,
    const std::vector<Define>& defines, ProcessHandle& proc,
    std::string& error)
{
    auto isIdentChar = [](char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') || c == '_';
    };
    auto substituteForSizing = [&](const std::string& line, uintptr_t currentAddr) {
        auto result = substituteSymbols(line, allocs, labels, defines);
        auto placeholder = formatHexLiteral(currentAddr);

        // Replace unresolved forward-label names with a sizing placeholder, but
        // only outside quoted string literals, so db "labelname" keeps its length.
        auto replaceInSpan = [&](std::string span) -> std::string {
            for (const auto& l : labels) {
                if (l.address != 0 || l.name.empty()) continue;
                size_t pos = 0;
                while ((pos = span.find(l.name, pos)) != std::string::npos) {
                    bool leftOk  = (pos == 0) || !isIdentChar(span[pos - 1]);
                    size_t after = pos + l.name.size();
                    bool rightOk = (after >= span.size()) || !isIdentChar(span[after]);
                    if (leftOk && rightOk) { span.replace(pos, l.name.size(), placeholder); pos += placeholder.size(); }
                    else pos += 1;
                }
            }
            return span;
        };
        std::string out;
        size_t i = 0;
        while (i < result.size()) {
            char c = result[i];
            if (c == '"' || c == '\'') {
                char q = c;
                size_t start = i++;
                while (i < result.size() && result[i] != q) ++i;
                if (i < result.size()) ++i;
                out += result.substr(start, i - start);
            } else {
                size_t start = i;
                while (i < result.size() && result[i] != '"' && result[i] != '\'') ++i;
                out += replaceInSpan(result.substr(start, i - start));
            }
        }
        return out;
    };

    constexpr size_t maxPasses = 8;
    for (size_t pass = 0; pass < maxPasses; ++pass) {
        uintptr_t currentAddr = 0;
        bool changed = false;

        for (const auto& rawLine : asmLines) {
            auto trimmedLine = trim(rawLine);
            if (trimmedLine.empty())
                continue;

            if (isSimpleLabelDefinition(trimmedLine)) {
                auto labelName = trimmedLine.substr(0, trimmedLine.size() - 1);
                bool handledLabel = false;

                for (const auto& a : allocs) {
                    if (a.name == labelName) {
                        currentAddr = a.address;
                        handledLabel = true;
                        break;
                    }
                }
                if (handledLabel)
                    continue;

                for (auto& l : labels) {
                    if (l.name == labelName) {
                        if (currentAddr == 0) {
                            error = "Label has no active assembly address: " + labelName;
                            return false;
                        }
                        if (l.address != currentAddr) {
                            l.address = currentAddr;
                            changed = true;
                        }
                        handledLabel = true;
                        break;
                    }
                }
                if (handledLabel)
                    continue;

                auto targetAddr = resolveAddress(labelName, allocs, labels, defines);
                if (targetAddr == 0) {
                    error = "Unresolved auto-assembler target: " + labelName;
                    return false;
                }
                currentAddr = targetAddr;
                continue;
            }

            if (startsWith(trimmedLine, "__FULLACCESS__:") ||
                startsWith(trimmedLine, "__ASSERT__:") ||
                startsWith(trimmedLine, "__UNREGISTERSYMBOL__:") ||
                startsWith(trimmedLine, "__DEALLOC__:") ||
                startsWith(trimmedLine, "__CREATETHREAD__:") ||
                startsWith(trimmedLine, "__CREATETHREADANDWAIT__:") ||
                startsWith(trimmedLine, "__LOADBINARY__:") ||
                startsWith(trimmedLine, "__LOADLIBRARY__:")) {
                continue;
            }

            if (currentAddr == 0) {
                error = "No active assembly address for line: " + trimmedLine;
                return false;
            }

            if (startsWith(trimmedLine, "__REASSEMBLE__:")) {
                auto addrExpr = trimmedLine.substr(15);
                auto addr = resolveAddress(addrExpr, allocs, labels, defines);
                if (!addr) {
                    error = "Invalid REASSEMBLE target: " + addrExpr;
                    return false;
                }

                uint8_t instrBuf[16];
                auto rr = proc.read(addr, instrBuf, sizeof(instrBuf));
                if (!rr || *rr == 0) {
                    error = "REASSEMBLE read failed at " + addrExpr;
                    return false;
                }

                Disassembler dis(targetDisArch());
                auto insns = dis.disassemble(addr, {instrBuf, *rr}, 1);
                if (insns.empty()) {
                    error = "REASSEMBLE disassembly failed at " + addrExpr;
                    return false;
                }

                auto asmCode = insns[0].mnemonic + " " + insns[0].operands;
                auto asmResult = targetAsm().assemble(asmCode, currentAddr);
                if (!asmResult) {
                    error = "REASSEMBLE sizing failed at " + addrExpr + ": " + asmResult.error();
                    return false;
                }
                currentAddr += asmResult->size();
                continue;
            }

            if (startsWith(trimmedLine, "__READMEM__:")) {
                auto args = trimmedLine.substr(12);
                auto comma = args.find(',');
                if (comma == std::string::npos) {
                    error = "READMEM requires address and size";
                    return false;
                }

                auto sizeStr = trim(args.substr(comma + 1));
                try {
                    currentAddr += std::stoull(sizeStr, nullptr, 0);
                } catch (...) {
                    error = "Invalid READMEM size: " + sizeStr;
                    return false;
                }
                continue;
            }

            if (startsWith(trimmedLine, "__FILLMEM__:")) {
                continue;
            }

            if (startsWith(trimmedLine, "__NOP__:")) {
                auto countExpr = trim(trimmedLine.substr(8));
                size_t count = 1;
                if (!parseNopCount(countExpr, count, error))
                    return false;
                currentAddr += count;
                continue;
            }

            if (startsWith(trimmedLine, "__DS__:")) {
                auto text = stripOptionalQuotes(trimmedLine.substr(7));
                if (text.empty()) {
                    error = "DS requires a string";
                    return false;
                }
                currentAddr += text.size();
                continue;
            }

            auto upper = toUpper(trimmedLine);
            if (startsWith(upper, "DB ") || startsWith(upper, "DW ") ||
                startsWith(upper, "DD ") || startsWith(upper, "DQ ")) {
                auto op = upper.substr(0, 2);
                // Resolve symbol/label references in data values (e.g. "dq tgt"
                // for pointer/jump tables). Forward refs get the sizing placeholder
                // so the byte count is still correct.
                auto dataStr = substituteForSizing(trim(trimmedLine.substr(3)), currentAddr);
                std::vector<uint8_t> dataBytes;
                std::string parseError;
                if (!parseDataDirective(op, dataStr, dataBytes, parseError)) {
                    error = parseError;
                    return false;
                }
                currentAddr += dataBytes.size();
                continue;
            }

            auto substituted = substituteForSizing(trimmedLine, currentAddr);
            auto asmResult = targetAsm().assemble(substituted, currentAddr);
            if (!asmResult) {
                error = "Assembly sizing error at " + formatHexLiteral(currentAddr) +
                    ": " + asmResult.error() + "\n  Line: " + trimmedLine;
                return false;
            }
            currentAddr += asmResult->size();
        }

        if (!changed)
            return true;
    }

    error = "Forward label resolution did not converge";
    return false;
}

bool AutoAssembler::tryBranchCanExecute(const std::vector<std::string>& branchLines,
    const std::vector<Alloc>& allocs, const std::vector<Label>& labels,
    const std::vector<Define>& defines, ProcessHandle* proc,
    std::string& reason) const
{
    reason.clear();
    if (!proc)
        return true;

    for (const auto& rawLine : branchLines) {
        auto line = trim(rawLine);
        if (startsWith(line, "__ASSERT__:")) {
            auto args = line.substr(11);
            auto comma = args.find(',');
            if (comma == std::string::npos) {
                reason = "ASSERT requires address and bytes";
                return false;
            }

            auto addrExpr = trim(args.substr(0, comma));
            auto bytesStr = trim(args.substr(comma + 1));
            auto addr = resolveAddress(addrExpr, allocs, labels, defines);
            if (!addr) {
                reason = "Invalid ASSERT target: " + addrExpr;
                return false;
            }

            if (!bytesStr.empty() && bytesStr.front() == '"') bytesStr = bytesStr.substr(1);
            if (!bytesStr.empty() && bytesStr.back() == '"') bytesStr.pop_back();

            ScanConfig pattern;
            pattern.parseAOB(bytesStr);
            if (pattern.byteArray.empty()) {
                reason = "ASSERT has no bytes: " + bytesStr;
                return false;
            }

            std::vector<uint8_t> current(pattern.byteArray.size());
            auto readResult = proc->read(addr, current.data(), current.size());
            if (!readResult || *readResult < current.size()) {
                reason = "ASSERT read failed at " + addrExpr;
                return false;
            }

            for (size_t i = 0; i < pattern.byteArray.size(); ++i) {
                if (i < pattern.byteArrayMask.size() && !pattern.byteArrayMask[i])
                    continue;
                if (current[i] != pattern.byteArray[i]) {
                    reason = "ASSERT failed at " + addrExpr + "+" + std::to_string(i);
                    return false;
                }
            }
        }
    }

    return true;
}

bool AutoAssembler::selectTryExceptBranches(const std::vector<std::string>& asmLines,
    std::vector<std::string>& selectedLines,
    const std::vector<Alloc>& allocs, const std::vector<Label>& labels,
    const std::vector<Define>& defines, ProcessHandle* proc,
    std::vector<std::string>& log, std::string& error) const
{
    selectedLines.clear();

    for (size_t i = 0; i < asmLines.size(); ++i) {
        auto line = trim(asmLines[i]);
        if (line != "__TRY_BEGIN__") {
            if (line == "__TRY_EXCEPT__" || line == "__TRY_END__") {
                error = "Unexpected {$except}/{$endtry} without {$try}";
                return false;
            }
            selectedLines.push_back(asmLines[i]);
            continue;
        }

        size_t exceptIndex = asmLines.size();
        size_t endIndex = asmLines.size();
        int depth = 1;
        for (size_t j = i + 1; j < asmLines.size(); ++j) {
            auto marker = trim(asmLines[j]);
            if (marker == "__TRY_BEGIN__") {
                ++depth;
            } else if (marker == "__TRY_END__") {
                --depth;
                if (depth == 0) {
                    endIndex = j;
                    break;
                }
            } else if (marker == "__TRY_EXCEPT__" && depth == 1) {
                exceptIndex = j;
            }
        }

        if (endIndex == asmLines.size()) {
            error = "Missing {$endtry} for {$try} block";
            return false;
        }
        if (exceptIndex == asmLines.size() || exceptIndex > endIndex) {
            error = "Missing {$except} for {$try} block";
            return false;
        }

        std::vector<std::string> tryLines(asmLines.begin() + i + 1, asmLines.begin() + exceptIndex);
        std::vector<std::string> exceptLines(asmLines.begin() + exceptIndex + 1, asmLines.begin() + endIndex);
        std::vector<std::string> selectedBranch;

        std::string reason;
        if (tryBranchCanExecute(tryLines, allocs, labels, defines, proc, reason)) {
            if (!selectTryExceptBranches(tryLines, selectedBranch, allocs, labels, defines, proc, log, error))
                return false;
            log.push_back("TRY: selected guarded block");
        } else {
            if (!selectTryExceptBranches(exceptLines, selectedBranch, allocs, labels, defines, proc, log, error))
                return false;
            log.push_back("TRY: selected {$except} block (" + reason + ")");
        }

        selectedLines.insert(selectedLines.end(), selectedBranch.begin(), selectedBranch.end());
        i = endIndex;
    }

    return true;
}

// ── Symbol management ──

void AutoAssembler::registerSymbol(const std::string& name, uintptr_t address) {
    globalSymbols_[name] = address;
}

void AutoAssembler::unregisterSymbol(const std::string& name) {
    globalSymbols_.erase(name);
}

uintptr_t AutoAssembler::resolveSymbol(const std::string& name) const {
    auto it = globalSymbols_.find(name);
    return it != globalSymbols_.end() ? it->second : 0;
}

void AutoAssembler::registerCommand(const std::string& name, CustomCommandHandler handler) {
    auto key = normalizeCommandName(name);
    if (key.empty() || !handler)
        return;
    customCommands_[key] = std::move(handler);
}

void AutoAssembler::unregisterCommand(const std::string& name) {
    customCommands_.erase(normalizeCommandName(name));
}

void AutoAssembler::addPreprocessorHook(ScriptHook hook) {
    if (hook)
        preprocessorHooks_.push_back(std::move(hook));
}

void AutoAssembler::addPostprocessorHook(ScriptHook hook) {
    if (hook)
        postprocessorHooks_.push_back(std::move(hook));
}

void AutoAssembler::clearPreprocessorHooks() {
    preprocessorHooks_.clear();
}

void AutoAssembler::clearPostprocessorHooks() {
    postprocessorHooks_.clear();
}

// ── Shared preprocessing ──
//
// execute() and check() MUST transform the script identically, otherwise a
// script that passes check() ("Syntax OK") can preprocess differently at
// injection time and emit wrong/garbage code. Both call this single chain.
bool AutoAssembler::preprocessScript(std::string& code,
                                     std::vector<std::string>& log,
                                     std::string& error) {
    if (!expandLuaBlocks(code, log, error))
        return false;
    if (!expandConditionalBlocks(code, log, error))
        return false;
    if (!resolveAnonymousLabels(code, log, error))
        return false;
    // Auto-declare named labels so forward "jmp skip … skip:" works without an
    // explicit label(skip), matching CE. Runs after anonymous-label resolution so
    // the generated __anon_N labels are already declared and skipped.
    autoDeclareNamedLabels(code);

    if (!runScriptHooks(preprocessorHooks_, code, log, error, "preprocessor"))
        return false;

    std::string expanded;
    if (!expandStructDefinitions(code, expanded, log, error))
        return false;
    code = std::move(expanded);

    if (!runScriptHooks(postprocessorHooks_, code, log, error, "postprocessor"))
        return false;

    return true;
}

// ── Main execution ──

// Upper bound on a single READMEM/FILLMEM buffer sourced from an (untrusted)
// table's AA script, so a bogus size can't drive a multi-GB bad_alloc/terminate.
static constexpr uint64_t kMaxAaBufferBytes = 256u * 1024 * 1024; // 256 MB

AutoAsmResult AutoAssembler::execute(ProcessHandle& proc, const std::string& script) {
    AutoAsmResult result;
    result.success = false;

    // Assemble/disassemble the cave in the TARGET's bitness so a 32-bit process
    // gets 32-bit machine code (and its stolen instructions decode correctly).
    targetIs32_ = proc.runs32BitCode();

    // CE's cheat tables address memory as "module+offset" (e.g. game.exe+1C). Seed
    // every loaded module's base as a resolvable symbol so resolveAddress (and thus
    // module+offset) works for tables loaded from a .CT.
    for (const auto& m : proc.modules())
        if (!m.name.empty()) globalSymbols_[m.name] = m.base;

    // Extract ENABLE section
    auto enableCode = extractSection(script, "ENABLE");
    if (enableCode.empty()) {
        // No sections — treat entire script as enable
        enableCode = script;
    }

    if (!preprocessScript(enableCode, result.log, result.error))
        return result;

    // ── Phase 1: Parse directives ──
    std::vector<Alloc> allocs;
    std::vector<Label> labels;
    std::vector<Define> defines;
    std::vector<std::string> registeredSymbols;
    std::vector<std::string> asmLines;

    std::istringstream ss(enableCode);
    std::string line;
    while (std::getline(ss, line)) {
        if (!parseLine(line, allocs, labels, defines, registeredSymbols, asmLines, result.log, &proc, result.error))
            return result;
    }

    // ── Phase 2: Allocate memory ──
    for (auto& a : allocs) {
        // Resolve the optional "near" address now — it may be a symbol defined
        // by an earlier aobscanmodule/aobscan (e.g. alloc(newmem,$1000,INJECT)),
        // which is how AOB code injections keep the cave within jmp range.
        if (!a.preferredExpr.empty()) {
            std::string p = a.preferredExpr;
            if (p.front() == '$') p = "0x" + p.substr(1);
            a.preferred = resolveAddress(p, allocs, labels, defines);
        }
        auto r = proc.allocate(a.size, MemProt::All, a.preferred);
        if (r) {
            a.address = *r;
            result.disableInfo.allocs.push_back({a.name, a.address, a.size});
            // Tracked in the cross-script dealloc(name) namespace so a later script
            // can dealloc(name) it (an intended pattern). The namespace is by name
            // (like CE's global alloc names), so distinct scripts must use distinct
            // names; the address-matched erases below keep disable() from evicting a
            // different script's same-named entry.
            knownAllocations_[a.name] = {a.name, a.address, a.size};
            result.log.push_back("Allocated " + a.name + " at 0x" +
                ([&]{ char b[32]; snprintf(b, 32, "%lx", a.address); return std::string(b); })());
        } else {
            // The mmap runs via a ptrace attach, which fails if the target already
            // has a tracer. The common self-inflicted case is THIS program already
            // tracing it (an open "find what accesses" monitor or the debugger), so
            // detect and name that; otherwise point at the general causes.
            std::string hint;
            {
                std::ifstream st("/proc/" + std::to_string(proc.pid()) + "/status");
                std::string line;
                while (std::getline(st, line)) {
                    if (line.rfind("TracerPid:", 0) == 0) {
                        long tp = 0; try { tp = std::stol(line.substr(10)); } catch (...) {}
                        if (tp != 0)
                            hint = (tp == (long)getpid())
                                ? " The target is already being traced by THIS program — close any "
                                  "'find what accesses/writes' window and disable breakpoints, then retry."
                                : (" The target is already being traced by PID " + std::to_string(tp) +
                                   " — detach that debugger and retry.");
                        break;
                    }
                }
            }
            result.error = "Failed to allocate memory for " + a.name + ": " +
                           r.error().message() +
                           (hint.empty()
                              ? ". (Code injection allocates a cave via ptrace; this can fail if the "
                                "process denies ptrace or a cave can't be placed near the hook.)"
                              : "." + hint);
            return result;
        }
    }

    std::vector<std::string> selectedAsmLines;
    if (!selectTryExceptBranches(asmLines, selectedAsmLines, allocs, labels, defines, &proc, result.log, result.error))
        return result;
    asmLines = std::move(selectedAsmLines);

    if (!resolveForwardLabels(asmLines, allocs, labels, defines, proc, result.error))
        return result;

    // ── Phase 3: Assemble and inject ──
    uintptr_t currentAddr = 0;
    std::string currentLabel;
    struct DeferredThread {
        std::string addressExpr;
        bool wait = false;
        int timeoutMs = 5000;
    };
    std::vector<DeferredThread> deferredThreads;

    // Apply one patch: fully read+save the original bytes, then write the
    // new bytes, verifying every step. Saving an original buffer from a
    // failed/partial read would let disable() write a zero-filled buffer
    // back and corrupt the target, and a silently-dropped write would leave
    // execute() reporting success against a patch that never landed.
    // Undo a partial activation: restore patched bytes (reverse order) then free
    // the caves — same as disable(). Called on ANY hard failure during execute so
    // a failed script leaves the target unchanged instead of a half-written cave
    // with an already-live hook (and doesn't leak the allocated RWX pages).
    auto rollback = [&]() -> AutoAsmResult {
        for (auto it = result.disableInfo.originals.rbegin();
             it != result.disableInfo.originals.rend(); ++it)
            proc.write(it->address, it->bytes.data(), it->bytes.size());
        for (auto& a : result.disableInfo.allocs) {
            proc.free(a.address, a.size);
            auto it = knownAllocations_.find(a.name);
            if (it != knownAllocations_.end() && it->second.address == a.address)
                knownAllocations_.erase(it);
        }
        result.disableInfo = DisableInfo{};
        result.success = false;
        return result;
    };

    auto patchMemory = [&](uintptr_t addr, const std::vector<uint8_t>& bytes) -> bool {
        std::vector<uint8_t> orig(bytes.size());
        auto rr = proc.read(addr, orig.data(), orig.size());
        if (!rr || *rr < orig.size()) {
            result.error = "original-byte read failed at " + formatHexLiteral(addr);
            return false;
        }
        result.disableInfo.originals.push_back({addr, orig});

        auto wr = proc.write(addr, bytes.data(), bytes.size());
        if (!wr || *wr < bytes.size()) {
            // The target page may be non-writable (e.g. r-x code). Code
            // injection has to patch executable pages, so make the range
            // writable and retry — mirrors CE making the region writable
            // before applying a hook.
            proc.protect(addr, bytes.size(), MemProt::All);
            wr = proc.write(addr, bytes.data(), bytes.size());
            if (!wr || *wr < bytes.size()) {
                result.error = "memory write failed at " + formatHexLiteral(addr);
                return false;
            }
        }
        return true;
    };

    for (auto& rawLine : asmLines) {
        auto trimmedLine = trim(rawLine);

        // Check for label definition (name:)
        if (isSimpleLabelDefinition(trimmedLine)) {
            auto labelName = trimmedLine.substr(0, trimmedLine.size() - 1);

            bool handledLabel = false;

            // Is this an alloc name? Set currentAddr to that block.
            for (auto& a : allocs) {
                if (a.name == labelName) {
                    currentAddr = a.address;
                    handledLabel = true;
                    break;
                }
            }
            if (handledLabel) continue;

            // Is this a declared internal label? Bind it to the active block address.
            for (auto& l : labels) {
                if (l.name == labelName) {
                    if (currentAddr == 0) {
                        result.error = "Label has no active assembly address: " + labelName;
                        return result;
                    }
                    l.address = currentAddr;
                    handledLabel = true;
                    break;
                }
            }
            if (handledLabel) continue;

            // Otherwise this must be a target address expression (game.exe+1234:).
            auto targetAddr = resolveAddress(labelName, allocs, labels, defines);
            if (targetAddr == 0) {
                result.error = "Unresolved auto-assembler target: " + labelName;
                return result;
            }
            currentAddr = targetAddr;
            continue;
        }

        // Handle special deferred directives
        if (startsWith(trimmedLine, "__FULLACCESS__:")) {
            auto args = trimmedLine.substr(15);
            auto comma = args.find(',');
            if (comma == std::string::npos) {
                result.error = "FULLACCESS requires address and size";
                return result;
            }

            auto addrExpr = trim(args.substr(0, comma));
            auto sizeStr = trim(args.substr(comma + 1));
            auto addr = resolveAddress(addrExpr, allocs, labels, defines);
            size_t size = 0;
            try {
                size = std::stoull(sizeStr, nullptr, 0);
            } catch (...) {
                result.error = "Invalid FULLACCESS size: " + sizeStr;
                return result;
            }

            if (!addr || size == 0) {
                result.error = "Invalid FULLACCESS target: " + addrExpr;
                return result;
            }

            auto protectResult = proc.protect(addr, size, MemProt::All);
            if (!protectResult) {
                result.error = "FULLACCESS failed at " + addrExpr + ": " + protectResult.error().message();
                return result;
            }
            result.log.push_back("FULLACCESS: " + addrExpr + " size=" + std::to_string(size));
            continue;
        }
        if (startsWith(trimmedLine, "__ASSERT__:")) {
            auto args = trimmedLine.substr(11);
            auto comma = args.find(',');
            if (comma == std::string::npos) {
                result.error = "ASSERT requires address and bytes";
                return result;
            }

            auto addrExpr = trim(args.substr(0, comma));
            auto bytesStr = trim(args.substr(comma + 1));
            auto addr = resolveAddress(addrExpr, allocs, labels, defines);
            if (!addr) {
                result.error = "Invalid ASSERT target: " + addrExpr;
                return result;
            }

            if (!bytesStr.empty() && bytesStr.front() == '"') bytesStr = bytesStr.substr(1);
            if (!bytesStr.empty() && bytesStr.back() == '"') bytesStr.pop_back();

            ScanConfig pattern;
            pattern.parseAOB(bytesStr);
            if (pattern.byteArray.empty()) {
                result.error = "ASSERT has no bytes: " + bytesStr;
                return result;
            }

            std::vector<uint8_t> current(pattern.byteArray.size());
            auto readResult = proc.read(addr, current.data(), current.size());
            if (!readResult || *readResult < current.size()) {
                result.error = "ASSERT read failed at " + addrExpr;
                return result;
            }

            for (size_t i = 0; i < pattern.byteArray.size(); ++i) {
                if (i < pattern.byteArrayMask.size() && !pattern.byteArrayMask[i])
                    continue;
                if (current[i] != pattern.byteArray[i]) {
                    char expected[8];
                    char actual[8];
                    snprintf(expected, sizeof(expected), "%02x", pattern.byteArray[i]);
                    snprintf(actual, sizeof(actual), "%02x", current[i]);
                    result.error = "ASSERT failed at " + addrExpr + "+" + std::to_string(i) +
                        ": expected " + expected + ", got " + actual;
                    return result;
                }
            }

            result.log.push_back("ASSERT OK: " + addrExpr);
            continue;
        }
        if (startsWith(trimmedLine, "__UNREGISTERSYMBOL__:")) {
            auto args = trimmedLine.substr(21);
            std::istringstream symbolStream(args);
            std::string name;
            while (std::getline(symbolStream, name, ',')) {
                name = trim(name);
                if (name.empty()) continue;
                globalSymbols_.erase(name);
                result.disableInfo.symbols.erase(name);
                result.log.push_back("UNREGISTERSYMBOL: " + name);
            }
            continue;
        }
        if (startsWith(trimmedLine, "__DEALLOC__:")) {
            auto args = trimmedLine.substr(12);
            std::istringstream allocStream(args);
            std::string name;
            while (std::getline(allocStream, name, ',')) {
                name = trim(name);
                if (name.empty()) continue;

                auto it = knownAllocations_.find(name);
                if (it == knownAllocations_.end()) {
                    result.log.push_back("DEALLOC: " + name + " not tracked");
                    continue;
                }

                auto freeResult = proc.free(it->second.address, it->second.size);
                if (!freeResult) {
                    result.error = "DEALLOC failed for " + name + ": " + freeResult.error().message();
                    return result;
                }

                result.disableInfo.allocs.erase(
                    std::remove_if(result.disableInfo.allocs.begin(), result.disableInfo.allocs.end(),
                        [&](const DisableInfo::AllocEntry& alloc) { return alloc.name == name; }),
                    result.disableInfo.allocs.end());
                result.log.push_back("DEALLOC: " + name);
                knownAllocations_.erase(it);
            }
            continue;
        }

        if (startsWith(trimmedLine, "__CREATETHREAD__:")) {
            deferredThreads.push_back({trim(trimmedLine.substr(17)), false, 0});
            result.log.push_back("Deferred: " + trimmedLine);
            continue;
        }
        if (startsWith(trimmedLine, "__CREATETHREADANDWAIT__:")) {
            auto args = trimmedLine.substr(24);
            auto parts = splitArgs(args, 2);
            if (parts.empty() || parts[0].empty()) {
                result.error = "CREATETHREADANDWAIT requires an address";
                return result;
            }

            int timeoutMs = 5000;
            if (parts.size() > 1 && !parts[1].empty()) {
                try {
                    timeoutMs = std::stoi(parts[1], nullptr, 0);
                } catch (...) {
                    result.error = "Invalid CREATETHREADANDWAIT timeout: " + parts[1];
                    return result;
                }
            }
            deferredThreads.push_back({trim(parts[0]), true, timeoutMs});
            result.log.push_back("Deferred: " + trimmedLine);
            continue;
        }

        if (startsWith(trimmedLine, "__LOADBINARY__:")) {
            auto args = trimmedLine.substr(15);
            auto parts = splitArgs(args, 2);
            if (parts.size() != 2) {
                result.error = "LOADBINARY requires address and filename";
                return result;
            }

            auto addrExpr = trim(parts[0]);
            auto filename = stripOptionalQuotes(parts[1]);
            auto addr = resolveAddress(addrExpr, allocs, labels, defines);
            if (!addr) {
                result.error = "Invalid LOADBINARY target: " + addrExpr;
                return result;
            }

            std::ifstream binFile(filename, std::ios::binary);
            if (!binFile) {
                result.error = "LOADBINARY file not found: " + filename;
                return result;
            }

            std::vector<uint8_t> data((std::istreambuf_iterator<char>(binFile)), {});
            if (data.empty()) {
                result.error = "LOADBINARY file is empty: " + filename;
                return result;
            }

            std::vector<uint8_t> orig(data.size());
            auto readResult = proc.read(addr, orig.data(), orig.size());
            if (!readResult || *readResult < orig.size()) {
                result.error = "LOADBINARY original-byte read failed at " + addrExpr;
                return result;
            }

            result.disableInfo.originals.push_back({addr, orig});
            auto writeResult = proc.write(addr, data.data(), data.size());
            if (!writeResult || *writeResult < data.size()) {
                result.error = "LOADBINARY write failed at " + addrExpr;
                return result;
            }

            result.log.push_back("LOADBINARY: " + filename + " -> " + addrExpr);
            continue;
        }

        if (startsWith(trimmedLine, "__LOADLIBRARY__:")) {
            auto path = stripOptionalQuotes(trimmedLine.substr(16));
            if (path.empty()) {
                result.error = "LOADLIBRARY requires a shared library path";
                return result;
            }
            if (!std::filesystem::exists(path)) {
                result.error = "LOADLIBRARY file not found: " + path;
                return result;
            }

            SymbolResolver resolver;
            resolver.loadProcess(proc);
            auto injectResult = os::injectLibrary(proc, resolver, path);
            if (!injectResult) {
                result.error = "LOADLIBRARY failed for " + path + ": " + injectResult.error();
                return result;
            }

            result.log.push_back("LOADLIBRARY: " + path + " handle=0x" + formatHex(*injectResult));
            continue;
        }

        if (currentAddr == 0) {
            result.error = "No active assembly address for line: " + trimmedLine;
            return result;
        }
        if (startsWith(trimmedLine, "__REASSEMBLE__:")) {
            auto addrExpr = trimmedLine.substr(15);
            auto addr = resolveAddress(addrExpr, allocs, labels, defines);
            if (addr) {
                // Read and disassemble the instruction, then re-emit as bytes
                uint8_t instrBuf[16];
                auto rr = proc.read(addr, instrBuf, sizeof(instrBuf));
                if (rr && *rr > 0) {
                    Disassembler dis(targetDisArch());
                    auto insns = dis.disassemble(addr, {instrBuf, *rr}, 1);
                    if (!insns.empty()) {
                        // Assemble the instruction at the current address
                        auto asmCode = insns[0].mnemonic + " " + insns[0].operands;
                        auto asmResult = targetAsm().assemble(asmCode, currentAddr);
                        if (asmResult && !asmResult->empty()) {
                            if (!patchMemory(currentAddr, *asmResult))
                                return rollback();
                            currentAddr += asmResult->size();
                        }
                    }
                }
            }
            continue;
        }
        if (startsWith(trimmedLine, "__READMEM__:")) {
            auto args = trimmedLine.substr(12);
            auto comma = args.find(',');
            if (comma != std::string::npos) {
                auto addrExpr = trim(args.substr(0, comma));
                auto sizeStr = trim(args.substr(comma + 1));
                auto addr = resolveAddress(addrExpr, allocs, labels, defines);
                // Parse the size identically to the forward-label sizing pass
                // (base-0, so CE-style 0x.. hex sizes are honored); otherwise
                // the two passes disagree and later code lands at a wrong
                // address.
                uint64_t sz = 0;
                if (!parseWholeUnsigned(sizeStr, 0, sz)) {
                    result.error = "Invalid READMEM size: " + sizeStr;
                    return result;
                }
                if (sz > kMaxAaBufferBytes) {
                    result.error = "READMEM size too large: " + sizeStr;
                    return result;
                }
                if (addr && sz > 0) {
                    std::vector<uint8_t> mem(sz);
                    auto rr = proc.read(addr, mem.data(), sz);
                    if (!rr || *rr < sz) {
                        result.error = "READMEM source read failed at " + addrExpr;
                        return result;
                    }
                    if (!patchMemory(currentAddr, mem))
                        return rollback();
                    currentAddr += mem.size();
                }
            }
            continue;
        }
        if (startsWith(trimmedLine, "__FILLMEM__:")) {
            auto args = trimmedLine.substr(12);
            auto parts = splitArgs(args, 3);
            if (parts.size() != 3) {
                result.error = "FILLMEM requires address, size, and value";
                return result;
            }

            auto addr = resolveAddress(parts[0], allocs, labels, defines);
            size_t size = 0;
            uint64_t value = 0;
            try {
                size = std::stoull(trim(parts[1]), nullptr, 0);
                value = std::stoull(trim(parts[2]), nullptr, 16);
            } catch (...) {
                result.error = "Invalid FILLMEM argument";
                return result;
            }
            if (!addr || size == 0 || value > 0xff) {
                result.error = "Invalid FILLMEM target or value";
                return result;
            }
            if (size > kMaxAaBufferBytes) {
                result.error = "FILLMEM size too large";
                return result;
            }

            std::vector<uint8_t> data(size, static_cast<uint8_t>(value));
            if (!patchMemory(addr, data))
                return rollback();
            result.log.push_back("FILLMEM: " + parts[0] + " size=" + std::to_string(size));
            continue;
        }
        if (startsWith(trimmedLine, "__NOP__:")) {
            auto countExpr = trim(trimmedLine.substr(8));
            size_t count = 1;
            if (!parseNopCount(countExpr, count, result.error))
                return result;

            std::vector<uint8_t> data(count, 0x90);
            if (!patchMemory(currentAddr, data))
                return rollback();
            currentAddr += data.size();
            continue;
        }
        if (startsWith(trimmedLine, "__DS__:")) {
            auto text = stripOptionalQuotes(trimmedLine.substr(7));
            if (text.empty()) {
                result.error = "DS requires a string";
                return result;
            }

            std::vector<uint8_t> data(text.begin(), text.end());
            if (!patchMemory(currentAddr, data))
                return rollback();
            currentAddr += data.size();
            continue;
        }

        // Handle db/dw/dd/dq directives
        auto upper = toUpper(trimmedLine);
        if (startsWith(upper, "DB ") || startsWith(upper, "DW ") ||
            startsWith(upper, "DD ") || startsWith(upper, "DQ ")) {

            auto op = upper.substr(0, 2);
            // Resolve symbol/label references in data values (e.g. "dq tgt").
            auto dataStr = substituteSymbols(trim(trimmedLine.substr(3)), allocs, labels, defines);
            std::vector<uint8_t> dataBytes;
            std::string parseError;
            if (!parseDataDirective(op, dataStr, dataBytes, parseError)) {
                result.error = parseError;
                return result;
            }

            if (!dataBytes.empty()) {
                if (!patchMemory(currentAddr, dataBytes))
                    return rollback();
                currentAddr += dataBytes.size();
            }
            continue;
        }

        // Substitute symbols in assembly line
        auto substituted = substituteSymbols(trimmedLine, allocs, labels, defines);

        // Assemble
        auto asmResult = targetAsm().assemble(substituted, currentAddr);
        if (!asmResult) {
            result.error = "Assembly error at 0x" +
                ([&]{ char b[32]; snprintf(b, 32, "%lx", currentAddr); return std::string(b); })() +
                ": " + asmResult.error() + "\n  Line: " + trimmedLine;
            // A failed line can't be skipped: continuing would write the next
            // instruction over the failed slot and shift every later label. Abort
            // and roll back the partial activation (hooks may already be live).
            result.log.push_back("ERROR: " + result.error);
            return rollback();
        }

        auto& bytes = *asmResult;
        if (!bytes.empty()) {
            if (!patchMemory(currentAddr, bytes))
                return rollback();
            currentAddr += bytes.size();
        }
    }

    if (!deferredThreads.empty()) {
        SymbolResolver resolver;
        resolver.loadProcess(proc);

        for (const auto& thread : deferredThreads) {
            auto addr = resolveAddress(thread.addressExpr, allocs, labels, defines);
            if (!addr) {
                result.error = "Invalid CREATETHREAD target: " + thread.addressExpr;
                return result;
            }

            auto threadResult = os::createRemoteThread(proc, resolver, addr, thread.wait, thread.timeoutMs);
            if (!threadResult) {
                result.error = "CREATETHREAD failed for " + thread.addressExpr + ": " + threadResult.error();
                return result;
            }

            auto info = *threadResult;
            if (info.stackAddress)
                result.disableInfo.allocs.push_back({
                    "__threadstack_" + std::to_string(info.tid), info.stackAddress, info.stackSize});

            result.log.push_back(std::string(thread.wait ? "CREATETHREADANDWAIT" : "CREATETHREAD") +
                ": " + thread.addressExpr + " handle=0x" + formatHex(info.handle));

            if (thread.wait && !info.completed) {
                result.error = "CREATETHREADANDWAIT timed out for " + thread.addressExpr;
                return result;
            }
        }
    }

    // ── Phase 4: Register symbols ──
    for (auto& sym : registeredSymbols) {
        uintptr_t addr = resolveAddress(sym, allocs, labels, defines);
        if (addr) {
            globalSymbols_[sym] = addr;
            result.disableInfo.symbols[sym] = addr;
        }
    }

    result.success = result.error.empty();
    return result;
}

AutoAsmResult AutoAssembler::disable(ProcessHandle& proc, const std::string& script, const DisableInfo& info) {
    AutoAsmResult result;

    // Seed module bases so the [DISABLE] script's module+offset addresses resolve.
    for (const auto& m : proc.modules())
        if (!m.name.empty()) globalSymbols_[m.name] = m.base;

    // Restore original bytes (in reverse order)
    for (auto it = info.originals.rbegin(); it != info.originals.rend(); ++it) {
        proc.write(it->address, it->bytes.data(), it->bytes.size());
    }

    // Free allocated memory
    for (auto& a : info.allocs) {
        proc.free(a.address, a.size);
        // Drop the global-namespace entry only if it's THIS block: a local alloc
        // sharing a name with some globalalloc must not evict the global entry.
        auto it = knownAllocations_.find(a.name);
        if (it != knownAllocations_.end() && it->second.address == a.address)
            knownAllocations_.erase(it);
    }

    // Unregister symbols
    for (auto& [name, _] : info.symbols) {
        globalSymbols_.erase(name);
    }

    result.success = true;
    result.log.push_back("Disabled: restored " + std::to_string(info.originals.size()) +
        " patches, freed " + std::to_string(info.allocs.size()) + " allocations");
    return result;
}

AutoAsmResult AutoAssembler::check(const std::string& script) {
    AutoAsmResult result;
    // Parse without a process — syntax check only
    auto enableCode = extractSection(script, "ENABLE");
    if (enableCode.empty()) enableCode = script;

    if (!preprocessScript(enableCode, result.log, result.error))
        return result;

    std::vector<Alloc> allocs;
    std::vector<Label> labels;
    std::vector<Define> defines;
    std::vector<std::string> registeredSymbols;
    std::vector<std::string> asmLines;

    std::istringstream ss(enableCode);
    std::string line;
    while (std::getline(ss, line)) {
        if (!parseLine(line, allocs, labels, defines, registeredSymbols, asmLines, result.log, nullptr, result.error))
            return result;
    }

    std::vector<std::string> selectedAsmLines;
    if (!selectTryExceptBranches(asmLines, selectedAsmLines, allocs, labels, defines, nullptr, result.log, result.error))
        return result;
    asmLines = std::move(selectedAsmLines);

    // NOTE: check() validates preprocessing + structural parsing only. It does
    // NOT run the forward-label resolution or the Keystone assembly pass, and it
    // has no process, so it cannot resolve AOBSCAN(*)/module-relative symbols or
    // catch a bad mnemonic — those surface at execute() time. A full assemble
    // here would instead fail on every legitimate alloc/label reference (whose
    // address is unknown without a target), turning a lenient check into one
    // that rejects valid scripts, so we intentionally keep it structural.
    result.success = true;
    result.log.push_back("Structure OK (preprocess + parse validated; final assembly runs at inject time): " +
        std::to_string(allocs.size()) + " allocs, " +
        std::to_string(labels.size()) + " labels, " + std::to_string(asmLines.size()) + " asm lines");
    return result;
}

// ── {$ccode} block compilation via libtcc (when CECORE_HAVE_TINYCC) ──
#ifdef CECORE_HAVE_TINYCC
extern "C" {
#include <libtcc.h>
}
#include <cstdint>

bool AutoAssembler::compileCCodeBlock(const std::string& source,
                                      std::string& emittedAa,
                                      std::string& error) {
    TCCState* s = tcc_new();
    if (!s) { error = "tcc_new() failed"; return false; }
    tcc_set_output_type(s, TCC_OUTPUT_MEMORY);

    // Wrap user source: add a sentinel symbol after the user's _ce_inject
    // function so we can compute its size by symbol diff.
    std::string wrapped =
        source +
        "\n\n/* cecore sentinel */\nchar _ce_inject_end_marker;\n";

    // Redirect tcc's error output into a captured string.
    static thread_local std::string g_tccErr;
    g_tccErr.clear();
    tcc_set_error_func(s, &g_tccErr,
        [](void* opaque, const char* msg) {
            auto* dst = static_cast<std::string*>(opaque);
            if (msg) { if (!dst->empty()) *dst += "; "; *dst += msg; }
        });

    if (tcc_compile_string(s, wrapped.c_str()) < 0) {
        error = "compile: " + (g_tccErr.empty() ? std::string("unknown") : g_tccErr);
        tcc_delete(s);
        return false;
    }
    if (tcc_relocate(s) < 0) {
        error = "relocate: " + (g_tccErr.empty() ? std::string("unknown") : g_tccErr);
        tcc_delete(s);
        return false;
    }

    void* injectPtr = tcc_get_symbol(s, "_ce_inject");
    void* endPtr    = tcc_get_symbol(s, "_ce_inject_end_marker");
    if (!injectPtr) {
        error = "no _ce_inject function found in {$ccode} block";
        tcc_delete(s);
        return false;
    }
    if (!endPtr || endPtr <= injectPtr) {
        error = "could not determine size of _ce_inject (end marker missing or before symbol)";
        tcc_delete(s);
        return false;
    }
    size_t funcSize = (uint8_t*)endPtr - (uint8_t*)injectPtr;
    if (funcSize == 0 || funcSize > (64 * 1024)) {
        error = "implausible _ce_inject size " + std::to_string(funcSize);
        tcc_delete(s);
        return false;
    }

    // Build a db line with hex byte sequence.
    std::string out = "db ";
    out.reserve(funcSize * 3 + 8);
    auto* bytes = static_cast<const uint8_t*>(injectPtr);
    for (size_t i = 0; i < funcSize; ++i) {
        char buf[4];
        std::snprintf(buf, sizeof(buf), "%02x ", bytes[i]);
        out += buf;
    }
    if (!out.empty() && out.back() == ' ') out.pop_back();
    out += "\n";

    emittedAa = out;
    tcc_delete(s);
    return true;
}
#else
bool AutoAssembler::compileCCodeBlock(const std::string&, std::string&,
                                      std::string& error) {
    error = "TinyCC not enabled in this build";
    return false;
}
#endif

// ── {$lua} block expansion ──
//
// Walks `code` left-to-right looking for `{$lua}` tokens. For each, finds the
// matching `{$asm}` or `{$endlua}` terminator (case-insensitive). Runs the
// captured Lua source through luaEvaluator_; the returned string replaces
// the entire block, including the markers, in `code`. If no evaluator is
// installed, encountering `{$lua}` is a syntax error.
//
// Also handles `{$ccode} ... {$endccode}` by emitting a clear "C blocks
// require TinyCC bridge — not yet wired" error so scripts using those don't
// silently misbehave.
bool AutoAssembler::expandLuaBlocks(std::string& code, std::vector<std::string>& log,
                                    std::string& error) {
    auto findCaseInsensitive = [&](const std::string& needle, size_t from) {
        // ASCII-only case-insensitive search.
        if (needle.empty()) return std::string::npos;
        for (size_t i = from; i + needle.size() <= code.size(); ++i) {
            bool match = true;
            for (size_t j = 0; j < needle.size(); ++j) {
                char a = code[i + j];
                char b = needle[j];
                char la = (a >= 'A' && a <= 'Z') ? (char)(a + 32) : a;
                char lb = (b >= 'A' && b <= 'Z') ? (char)(b + 32) : b;
                if (la != lb) { match = false; break; }
            }
            if (match) return i;
        }
        return std::string::npos;
    };

    // {$ccode} ... {$endccode} — compile inline C via libtcc, emit the
    // resulting bytes as a `db` sequence at the same point in the AA
    // stream. Requires CECORE_HAVE_TINYCC at build time.
    while (true) {
        size_t open = findCaseInsensitive("{$ccode}", 0);
        if (open == std::string::npos) break;
        size_t bodyStart = open + std::string("{$ccode}").size();
        size_t closePos = findCaseInsensitive("{$endccode}", bodyStart);
        if (closePos == std::string::npos) {
            error = "{$ccode} block has no matching {$endccode} terminator";
            return false;
        }
        std::string source = code.substr(bodyStart, closePos - bodyStart);
        size_t blockEnd = closePos + std::string("{$endccode}").size();

#ifdef CECORE_HAVE_TINYCC
        std::string emitted;
        std::string compileErr;
        if (!compileCCodeBlock(source, emitted, compileErr)) {
            error = "{$ccode} compile error: " + compileErr;
            return false;
        }
        code.replace(open, blockEnd - open, emitted);
        log.push_back("{$ccode}: compiled " + std::to_string(source.size()) +
                      " bytes of C to " + std::to_string(emitted.size()) + " bytes of AA");
#else
        (void)source; (void)blockEnd;
        error = "{$ccode} blocks require the TinyCC bridge — rebuild with libtcc-dev installed";
        return false;
#endif
    }

    while (true) {
        size_t open = findCaseInsensitive("{$lua}", 0);
        if (open == std::string::npos) break;

        size_t bodyStart = open + std::string("{$lua}").size();

        size_t closeAsm = findCaseInsensitive("{$asm}", bodyStart);
        size_t closeEnd = findCaseInsensitive("{$endlua}", bodyStart);
        size_t closePos = std::string::npos;
        size_t closeLen = 0;
        if (closeAsm != std::string::npos &&
            (closeEnd == std::string::npos || closeAsm < closeEnd)) {
            closePos = closeAsm;
            closeLen = std::string("{$asm}").size();
        } else if (closeEnd != std::string::npos) {
            closePos = closeEnd;
            closeLen = std::string("{$endlua}").size();
        }
        if (closePos == std::string::npos) {
            error = "{$lua} block has no matching {$asm} or {$endlua} terminator";
            return false;
        }

        std::string luaCode = code.substr(bodyStart, closePos - bodyStart);

        if (!luaEvaluator_) {
            error = "{$lua} block encountered but no Lua evaluator is installed on this AutoAssembler";
            return false;
        }
        auto r = luaEvaluator_(luaCode);
        if (!r) {
            error = "{$lua} block error: " + r.error();
            return false;
        }

        // Splice the replacement in place of the entire block.
        std::string replacement = *r;
        size_t blockEnd = closePos + closeLen;
        code.replace(open, blockEnd - open, replacement);

        log.push_back("{$lua}: expanded " + std::to_string(luaCode.size()) +
                      "-byte block to " + std::to_string(replacement.size()) + " bytes");
    }
    return true;
}

// ── {$if} / {$else} / {$endif} preprocessor conditionals ──
//
// `{$if expression}` ... `{$else}` ... `{$endif}` — the expression is run
// through the Lua evaluator and one of the two branches survives based on
// the truthiness of its return value. Nested ifs aren't supported (CE
// itself doesn't either in this form); the outer level is the only one
// processed.
bool AutoAssembler::expandConditionalBlocks(std::string& code,
                                            std::vector<std::string>& log,
                                            std::string& error) {
    auto findCi = [&](const std::string& needle, size_t from) {
        if (needle.empty()) return std::string::npos;
        for (size_t i = from; i + needle.size() <= code.size(); ++i) {
            bool match = true;
            for (size_t j = 0; j < needle.size(); ++j) {
                char a = code[i + j];
                char b = needle[j];
                char la = (a >= 'A' && a <= 'Z') ? (char)(a + 32) : a;
                char lb = (b >= 'A' && b <= 'Z') ? (char)(b + 32) : b;
                if (la != lb) { match = false; break; }
            }
            if (match) return i;
        }
        return std::string::npos;
    };

    while (true) {
        size_t openPos = findCi("{$if", 0);
        if (openPos == std::string::npos) break;

        size_t exprStart = openPos + 4;  // past "{$if"
        // Require a full `{$if` token: the next char must be whitespace or the
        // closing brace, so a `{$ifdef}`-style token is not mistaken for it.
        if (exprStart < code.size()) {
            char nextCh = code[exprStart];
            if (nextCh != ' ' && nextCh != '\t' && nextCh != '}') {
                error = "Unrecognized preprocessor token starting at '{$if'";
                return false;
            }
        }
        size_t openEnd = code.find('}', exprStart);
        if (openEnd == std::string::npos) {
            error = "{$if has no closing brace";
            return false;
        }
        std::string conditionRaw = code.substr(exprStart, openEnd - exprStart);
        // Strip leading whitespace.
        size_t nonWs = conditionRaw.find_first_not_of(" \t");
        if (nonWs != std::string::npos) conditionRaw = conditionRaw.substr(nonWs);
        if (conditionRaw.empty()) {
            error = "{$if has no expression";
            return false;
        }

        size_t elsePos  = findCi("{$else}",  openEnd);
        size_t endifPos = findCi("{$endif}", openEnd);
        if (endifPos == std::string::npos) {
            error = "{$if has no matching {$endif}";
            return false;
        }
        // Nested ifs are unsupported. Detect a second `{$if` before this
        // block's `{$endif}` and report it explicitly rather than silently
        // mis-pairing the outer open with the inner endif.
        size_t innerIf = findCi("{$if", openEnd);
        if (innerIf != std::string::npos && innerIf < endifPos) {
            error = "nested {$if} not supported";
            return false;
        }
        if (elsePos != std::string::npos && elsePos > endifPos) elsePos = std::string::npos;

        if (!luaEvaluator_) {
            error = "{$if requires a Lua evaluator on this AutoAssembler";
            return false;
        }
        std::string luaChunk = "return (" + conditionRaw + ")";
        auto evalResult = luaEvaluator_(luaChunk);
        if (!evalResult) {
            error = "{$if condition error: " + evalResult.error();
            return false;
        }
        // Lua truthiness rules: only `false` and `nil` are false. evalToString
        // returns the chunk's first return value coerced to string; "false"
        // or empty (nil) → false branch.
        const std::string& s = *evalResult;
        bool truthy = !(s.empty() || s == "false" || s == "nil");

        size_t ifBranchStart = openEnd + 1;
        size_t ifBranchEnd, elseBranchStart, elseBranchEnd;
        if (elsePos != std::string::npos) {
            ifBranchEnd      = elsePos;
            elseBranchStart  = elsePos + std::string("{$else}").size();
            elseBranchEnd    = endifPos;
        } else {
            ifBranchEnd      = endifPos;
            elseBranchStart  = endifPos;  // empty else
            elseBranchEnd    = endifPos;
        }

        std::string kept = truthy
            ? code.substr(ifBranchStart, ifBranchEnd - ifBranchStart)
            : code.substr(elseBranchStart, elseBranchEnd - elseBranchStart);

        size_t blockEnd = endifPos + std::string("{$endif}").size();
        code.replace(openPos, blockEnd - openPos, kept);

        log.push_back(std::string("{$if}: ") + (truthy ? "true" : "false") +
                      " branch kept (" + std::to_string(kept.size()) + " bytes)");
    }
    return true;
}

// ── Anonymous labels: @@:, @F, @B ──
//
// `@@:` declares an anonymous label. `@F` (or `@f`) refers to the next
// anonymous label after the current line; `@B` (`@b`) the previous one.
// Resolved by rewriting `@@:` to `__anon_N:` and `@F`/`@B` to the
// generated name of the appropriate sibling.
bool AutoAssembler::resolveAnonymousLabels(std::string& code,
                                           std::vector<std::string>& log,
                                           std::string& error) {
    // Split into lines preserving original line endings.
    std::vector<std::string> lines;
    {
        size_t start = 0;
        for (size_t i = 0; i <= code.size(); ++i) {
            if (i == code.size() || code[i] == '\n') {
                lines.push_back(code.substr(start, i - start));
                start = i + 1;
            }
        }
    }

    // Pass 1: number every @@: declaration. Trim leading whitespace before
    // matching to support indented anonymous labels.
    std::vector<int> anonAt(lines.size(), -1);
    int anonCount = 0;
    auto leadingWs = [&](const std::string& l) {
        size_t i = 0;
        while (i < l.size() && (l[i] == ' ' || l[i] == '\t')) ++i;
        return i;
    };
    for (size_t i = 0; i < lines.size(); ++i) {
        size_t ws = leadingWs(lines[i]);
        if (lines[i].compare(ws, 3, "@@:") == 0) {
            anonAt[i] = anonCount++;
            lines[i] = lines[i].substr(0, ws) +
                       "__anon_" + std::to_string(anonAt[i]) + ":" +
                       lines[i].substr(ws + 3);
        }
    }
    // Pass 2: rewrite @F / @B references. Be careful not to touch substrings
    // that happen to contain "@F" inside other identifiers — match only when
    // the surrounding chars are non-identifier (i.e. whole-token).
    auto isIdent = [](char c) {
        return std::isalnum((unsigned char)c) || c == '_';
    };
    auto replaceRefs = [&](std::string& line, size_t lineIdx) -> bool {
        for (size_t pos = 0; pos + 1 < line.size(); ) {
            if (line[pos] != '@') { ++pos; continue; }
            char next = line[pos + 1];
            bool isF = (next == 'F' || next == 'f');
            bool isB = (next == 'B' || next == 'b');
            if (!isF && !isB) { ++pos; continue; }
            // Must be a token boundary on both sides.
            bool leftOk  = (pos == 0) || !isIdent(line[pos - 1]);
            bool rightOk = (pos + 2 >= line.size()) || !isIdent(line[pos + 2]);
            if (!(leftOk && rightOk)) { ++pos; continue; }

            int target = -1;
            if (isF) {
                for (size_t j = lineIdx + 1; j < anonAt.size(); ++j)
                    if (anonAt[j] >= 0) { target = anonAt[j]; break; }
            } else {
                for (size_t j = lineIdx; j-- > 0; )
                    if (anonAt[j] >= 0) { target = anonAt[j]; break; }
            }
            if (target < 0) {
                error = std::string("anonymous label reference @") +
                        (isF ? "F" : "B") + " has no matching @@:";
                return false;
            }
            std::string sub = "__anon_" + std::to_string(target);
            line.replace(pos, 2, sub);
            pos += sub.size();
        }
        return true;
    };

    for (size_t i = 0; i < lines.size(); ++i) {
        if (!replaceRefs(lines[i], i)) return false;
    }

    if (anonCount == 0) return true;  // no labels — no preamble or rewrite needed

    // Emit explicit `label()` declarations at the top so every __anon_N is
    // known to the AA symbol table before its first reference.
    std::string preamble;
    for (int i = 0; i < anonCount; ++i)
        preamble += "label(__anon_" + std::to_string(i) + ")\n";

    std::string body;
    for (size_t i = 0; i < lines.size(); ++i) {
        body += lines[i];
        if (i + 1 < lines.size()) body += '\n';
    }
    code = preamble + body;
    log.push_back("anonymous labels: resolved " + std::to_string(anonCount) +
                  " @@: declaration(s)");
    return true;
}

} // namespace ce
