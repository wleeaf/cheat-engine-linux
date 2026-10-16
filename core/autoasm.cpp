#include "core/autoasm.hpp"
#include "arch/disassembler.hpp"
#include "arch/aarch64_relocator.hpp"
#include "platform/linux/injector.hpp"
#include "platform/linux/syscall_service.hpp"
#include "platform/linux/memory_image.hpp"
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
#include <thread>
#include <chrono>
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
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
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

        // Read in chunks (a region can be gigabytes of emulator RAM), each
        // overlapping the next by the pattern length less one byte.
        constexpr size_t kChunk = size_t(16) << 20;
        std::vector<uint8_t> buffer;
        for (uintptr_t chunkStart = regionStart; chunkStart < regionEnd;) {
            const size_t want = std::min<uintptr_t>(kChunk + pattern.size() - 1, regionEnd - chunkStart);
            buffer.resize(want);
            auto readResult = proc.read(chunkStart, buffer.data(), buffer.size());
            if (!readResult || *readResult < pattern.size()) break;
            const size_t bytesRead = *readResult;
            const size_t limit = bytesRead - pattern.size() + 1;
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
                        firstMatch = chunkStart + offset;
                    ++matches;
                }
            }
            if (bytesRead < want) break;   // the rest of the region is unreadable
            chunkStart += limit;
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
static bool evalDataToken(std::string tok, uint64_t& out) {
    if (tok.empty()) return false;
    // "#-5" is a negative decimal: move the sign in front of the '#'.
    for (size_t at; (at = tok.find("#-")) != std::string::npos || (at = tok.find("#+")) != std::string::npos;)
        std::swap(tok[at], tok[at + 1]);
    uint64_t acc = 0;
    bool sub = false;
    size_t i = 0;
    if (tok[0] == '+' || tok[0] == '-') { sub = (tok[0] == '-'); i = 1; }
    while (i < tok.size()) {
        size_t j = i;
        while (j < tok.size() && tok[j] != '+' && tok[j] != '-') ++j;
        std::string term = trim(tok.substr(i, j - i));
        if (term.empty()) return false;
        // The whole term must be a number: "bad_target" is not 0xBAD.
        uint64_t v = 0;
        const bool decimal = term[0] == '#';
        const char* first = term.data() + (decimal ? 1 : 0);
        const char* last = term.data() + term.size();
        if (!decimal && term.size() > 2 && (term[1] == 'x' || term[1] == 'X') && term[0] == '0') first += 2;
        const auto [stop, failure] = std::from_chars(first, last, v, decimal ? 10 : 16);
        if (failure != std::errc() || stop != last || first == last) return false;
        acc = sub ? (acc - v) : (acc + v);
        if (j < tok.size()) { sub = (tok[j] == '-'); i = j + 1; } else break;
    }
    out = acc;
    return true;
}

static bool parseDataDirective(const std::string& op, const std::string& data,
                               std::vector<uint8_t>& bytes, std::string& error, ByteOrder order = ByteOrder::Little) {
    size_t width = 1;
    if (op == "DW") width = 2;
    else if (op == "DD") width = 4;
    else if (op == "DQ") width = 8;

    if (width > 1 && order == ByteOrder::Unknown) { error = "Target byte order is unknown"; return false; }
    auto appendValue = [&](uint64_t value, size_t count) {
        for (size_t i = 0; i < count; ++i) {
            size_t shift = order == ByteOrder::Big ? count - 1 - i : i;
            bytes.push_back(static_cast<uint8_t>(value >> (8 * shift)));
        }
    };
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
                    appendValue(bits, 4);
                } else {
                    double d = 0;
                    if (std::from_chars(b, e, d).ec != std::errc()) {
                        error = "Invalid " + op + " double value: " + token; return false;
                    }
                    uint64_t bits; std::memcpy(&bits, &d, 8);
                    appendValue(bits, 8);
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

        // A negative value ("dd -1", "dw #-5") is its two's complement in the
        // width, down to the type's smallest signed value.
        const bool negativeFits = width < 8 && static_cast<int64_t>(value) < 0 &&
            static_cast<int64_t>(value) >= -(int64_t(1) << (width * 8 - 1));
        if (value > maxValue && !negativeFits) {
            error = op + " value out of range: " + token;
            return false;
        }

        appendValue(value & maxValue, width);
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

// How a script uses an undeclared "name:" definition (see autoDeclareNamedLabels).
struct NamedLabelUse {
    // An instruction or data line uses the bare name ("jmp exit"), as code
    // uses a local label; a directive ("alloc(newmem,$1000,UpdateHealth)") or
    // an offset ("UpdateHealth+5") uses an address.
    bool jumpTarget = false;
    // The name is an alloc's near address ("alloc(newmem,$1000,UpdateHealth)"),
    // so the script itself treats it as an address outside the script.
    bool nearAddress = false;
    // No line before the definition sets an address ("exit:" then "db 90" at
    // the top of a section), so as a label it would have no address.
    bool firstAddress = false;
};

// Cheat Engine auto-registers any "name:" label defined anywhere in the script,
// so a forward "jmp skip ... skip:" works without an explicit label(skip). Our
// sizing pass aborts on the forward reference before it reaches the definition,
// so mirror the anonymous-label mechanism: emit label() for every named
// definition that is not already declared (via alloc/label/define/registersymbol/
// globalalloc). Prepending these declarations makes the label known on pass 1.
// known(name, use) says a name is an address from outside the script (a
// registered symbol, a module, a target function) rather than a label.
static void autoDeclareNamedLabels(std::string& code,
                                   const std::function<bool(const std::string&, const NamedLabelUse&)>& known) {
    auto firstArg = [](const std::string& line, size_t open) -> std::string {
        size_t end = line.find_first_of(",)", open);
        return trim(line.substr(open, end == std::string::npos ? std::string::npos : end - open));
    };
    // The third argument of alloc(name,size,near), without quotes.
    auto nearArg = [](const std::string& line, size_t open) -> std::string {
        const size_t close = line.rfind(')');
        if (close == std::string::npos || close < open) return {};
        std::istringstream args(line.substr(open, close - open));
        std::string part;
        for (int index = 0; std::getline(args, part, ','); ++index)
            if (index == 2) return stripOptionalQuotes(trim(part));
        return {};
    };
    std::vector<std::string> lines;
    {
        std::istringstream ss(code);
        for (std::string raw; std::getline(ss, raw);) lines.push_back(stripInlineComment(raw));
    }
    std::set<std::string> declared, defined, jumpTargets, nearNames, firstAddress;
    std::vector<std::string> order;   // preserve definition order for stable output
    bool addressSet = false;           // a line before this one ends in ':'
    for (size_t index = 0; index < lines.size(); ++index) {
        const std::string& line = lines[index];
        std::string upper = toUpper(line);
        auto identifierEnd = [&](size_t at) {
            while (at < line.size() && (std::isalnum(static_cast<unsigned char>(line[at])) || line[at] == '_')) ++at;
            return at;
        };
        const size_t head = identifierEnd(0);
        const bool directive = head && line.find_first_not_of(" \t", head) != std::string::npos &&
                               line[line.find_first_not_of(" \t", head)] == '(';
        const bool definition = isSimpleLabelDefinition(line) && head == line.size() - 1;
        for (size_t at = 0; !directive && !definition && at < line.size();) {
            if (!std::isalpha(static_cast<unsigned char>(line[at])) && line[at] != '_') { ++at; continue; }
            const size_t end = identifierEnd(at);
            const size_t next = line.find_first_not_of(" \t", end);
            const bool offset = (next != std::string::npos && (line[next] == '+' || line[next] == '-')) ||
                                (at && (line[at - 1] == '+' || line[at - 1] == '-'));
            if (!offset) jumpTargets.insert(line.substr(at, end - at));
            at = end;
        }
        if (startsWith(upper, "ALLOC(")) {
            declared.insert(firstArg(line, 6)); nearNames.insert(nearArg(line, 6));
        } else if (startsWith(upper, "GLOBALALLOC(")) {
            declared.insert(firstArg(line, 12)); nearNames.insert(nearArg(line, 12));
        } else if (startsWith(upper, "KALLOC(")) {
            declared.insert(firstArg(line, 7));
        }
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
            // Bare addresses can begin with A-F, especially high i386 mmap
            // addresses. Do not shadow a hexadecimal literal with an implicit
            // zero-address label. Explicit label()/alloc()/define() declarations
            // still give names such as "dead" their intended symbol meaning.
            const bool hexAddress = name.size() > 1 &&
                std::all_of(name.begin(), name.end(), [](unsigned char c) { return std::isxdigit(c); });
            if (ident && !hexAddress && name.rfind("__anon_", 0) != 0 && defined.insert(name).second) {
                order.push_back(name);
                if (!addressSet) firstAddress.insert(name);
            }
        }
        if (!line.empty() && line.back() == ':') addressSet = true;
    }
    std::string preamble;
    for (const auto& name : order)
        if (!declared.count(name) &&
            !known(name, {jumpTargets.contains(name), nearNames.contains(name), firstAddress.contains(name)}))
            preamble += "label(" + name + ")\n";
    if (!preamble.empty()) code = preamble + code;
}

// A NOP count: decimal digits, or hex with 0x or with hex letters ("nop A").
static bool parseNopCount(const std::string& countExpr, size_t& count, std::string& error) {
    unsigned long long parsed = 1;
    if (!countExpr.empty()) {
        const bool prefixed = countExpr.size() > 2 && countExpr[0] == '0' && (countExpr[1] == 'x' || countExpr[1] == 'X');
        const bool decimal = !prefixed && std::all_of(countExpr.begin(), countExpr.end(), [](unsigned char c) { return std::isdigit(c); });
        const char* first = countExpr.data() + (prefixed ? 2 : 0);
        const char* last = countExpr.data() + countExpr.size();
        const auto [stop, failure] = std::from_chars(first, last, parsed, decimal ? 10 : 16);
        if (failure != std::errc() || stop != last || first == last) {
            error = "Invalid NOP count: " + countExpr;
            return false;
        }
    }
    if (parsed > 256u * 1024 * 1024) { error = "NOP count exceeds the buffer limit"; return false; }
    count = static_cast<size_t>(parsed);
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

// Cheat Engine's { ... } comments, which may span lines. {$...} directives,
// the bodies of {$lua} blocks (Lua uses braces for tables), quoted text and
// // comments are kept; a comment's line breaks stay so line numbers do.
static std::string stripBraceComments(const std::string& script) {
    auto at = [&](size_t i, const char* word) {
        for (size_t k = 0; word[k]; ++k)
            if (i + k >= script.size() || std::toupper(static_cast<unsigned char>(script[i + k])) != word[k]) return false;
        return true;
    };
    std::string out;
    out.reserve(script.size());
    bool inLua = false;
    char quote = 0;
    for (size_t i = 0; i < script.size();) {
        const char c = script[i];
        if (inLua) {
            if (at(i, "{$ASM}") || at(i, "{$ENDLUA}")) inLua = false;
            else { out += c; ++i; continue; }
        }
        if (c == '\n') quote = 0;
        if (quote) {
            if (c == quote) quote = 0;
        } else if (c == '"' || c == '\'') {
            quote = c;
        } else if (c == '/' && i + 1 < script.size() && script[i + 1] == '/') {
            const size_t end = script.find('\n', i);
            const size_t stop = end == std::string::npos ? script.size() : end;
            out.append(script, i, stop - i);
            i = stop;
            continue;
        } else if (c == '{' && at(i, "{$LUA}")) {
            out.append(script, i, 6);
            i += 6;
            inLua = true;
            continue;
        } else if (c == '{' && i + 1 < script.size() && script[i + 1] == '$') {
            // A directive ({$if expr} may hold Lua braces): copy it whole, up to
            // its own closing brace.
            size_t depth = 0, k = i;
            for (; k < script.size(); ++k) {
                if (script[k] == '{') ++depth;
                else if (script[k] == '}' && --depth == 0) break;
                else if (script[k] == '\n') break;
            }
            const size_t stop = k < script.size() && script[k] == '}' ? k + 1 : k;
            out.append(script, i, stop - i);
            i = stop;
            continue;
        } else if (c == '{') {
            const size_t end = script.find('}', i);
            const size_t stop = end == std::string::npos ? script.size() : end + 1;
            for (size_t k = i; k < stop; ++k) if (script[k] == '\n') out += '\n';
            i = stop;
            continue;
        }
        out += c;
        ++i;
    }
    return out;
}

// The next "{$" at or after from that opens a directive. One in a // comment
// or a quoted string ("// {$lua} was here", db '{$if}') is text.
static size_t findDirective(const std::string& code, size_t from) {
    char quote = 0;
    for (size_t i = from; i + 1 < code.size(); ++i) {
        const char c = code[i];
        if (c == '\n') quote = 0;
        else if (quote) { if (c == quote) quote = 0; }
        else if (c == '"' || c == '\'') quote = c;
        else if (c == '/' && code[i + 1] == '/') {
            i = code.find('\n', i);
            if (i == std::string::npos) return i;
            --i;   // the loop steps onto the line break, which ends any quote
        } else if (c == '{' && code[i + 1] == '$') return i;
    }
    return std::string::npos;
}

// "[ENABLE]", "[DISABLE] // comment" and the like: the upper-case header, or
// empty when the line is not one. A trailing comment no longer hides it
// ("[DISABLE] // x" merged the disable body into the enable section).
static std::string sectionHeader(const std::string& line) {
    auto trimmed = toUpper(trim(stripInlineComment(trim(line))));
    const bool header = trimmed.size() > 2 && trimmed.front() == '[' && trimmed.back() == ']' &&
        std::all_of(trimmed.begin() + 1, trimmed.end() - 1, [](unsigned char ch) { return std::isalpha(ch); });
    return header ? trimmed : std::string();
}

// Whether a script has sections at all; one without runs whole on enable.
static bool hasSectionHeaders(const std::string& script) {
    std::istringstream ss(script);
    for (std::string line; std::getline(ss, line);)
        if (!sectionHeader(line).empty()) return true;
    return false;
}

std::string AutoAssembler::extractSection(const std::string& script, const std::string& section) {
    // As in Cheat Engine, lines outside every section (a define() above
    // [ENABLE] in the standard templates) belong to both sections.
    auto tagUpper = toUpper("[" + section + "]");
    std::istringstream ss(stripBraceComments(script));
    std::string line;
    std::string result;
    enum class Part { Shared, Wanted, Other } part = Part::Shared;

    while (std::getline(ss, line)) {
        const auto trimmed = sectionHeader(line);
        if (!trimmed.empty()) {
            part = trimmed == tagUpper ? Part::Wanted : Part::Other;
            continue;
        }
        if (part != Part::Other)
            result += line + "\n";
    }
    return result;
}

// ── Line parsing ──

static std::string restrictedError(const std::string& command) {
    return command + " is not allowed in this script: it would read a file from this computer or run code "
                     "in the target directly";
}

// The command a restricted script may not use, or empty. Also matches the
// internal "__LOADLIBRARY__:" form, which a script can write as a raw line.
static std::string restrictedCommand(const std::string& upperLine) {
    auto name = trim(upperLine.substr(0, upperLine.find_first_of("({ \t:")));
    if (name.size() > 4 && startsWith(name, "__") && name.ends_with("__")) name = name.substr(2, name.size() - 4);
    static const std::set<std::string> refused = {"LOADLIBRARY", "LOADBINARY", "INCLUDE", "CREATETHREAD",
                                                  "CREATETHREADANDWAIT"};
    return refused.count(name) ? name : std::string();
}

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

    // Checked after comment stripping: "loadlibrary{}(x)" is loadlibrary.
    if (restricted_) {
        if (auto command = restrictedCommand(upper); !command.empty()) {
            error = restrictedError(command);
            return false;
        }
    }

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

    // GLOBALALLOC(name, size [, preferred]) — as in Cheat Engine, memory shared
    // by name: a later globalalloc of the same name reuses it, the symbol is
    // exported for other scripts, and disabling a script never frees it (another
    // script's hook may still use it).
    if (startsWith(upper, "GLOBALALLOC(") && line.back() == ')') {
        auto args = line.substr(12, line.size() - 13);
        Alloc a;
        if (!parseAllocArgs(args, a.name, a.size, a.preferredExpr)) {
            error = "Invalid globalalloc() arguments: " + args;
            return false;
        }
        a.address = 0;
        a.global = true;
        allocs.push_back(a);
        // Exported in Phase 4 without an owner: as one of this script's undo
        // symbols, disabling the last script that declared it erased the name,
        // and the next globalalloc mapped a new block while others kept the old.
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
        // A missing argument used to skip the scan silently: the name then
        // resolved to a label another enabled script registered (templates
        // share INJECT), and the hook went to that script's address.
        if (parts.size() != 4) { error = "AOBSCANREGION(name, start, stop, pattern) takes 4 arguments"; return false; }
        if (parts.size() == 4) {
            auto name = trim(parts[0]);
            auto startExpr = trim(parts[1]);
            auto stopExpr = trim(parts[2]);
            auto pattern = stripOptionalQuotes(parts[3]);
            auto start = resolveAddress(startExpr, allocs, labels, defines);
            auto stop = resolveAddress(stopExpr, allocs, labels, defines);
            if (!start || !stop || stop <= start) {
                error = "AOBSCANREGION: invalid range for " + name;
                return false;
            }

            ScanConfig cfg;
            if (!cfg.parseAOB(pattern) || cfg.byteArray.empty()) { error = "Invalid AOB pattern: " + pattern; return false; }
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
                error = std::string("AOBSCANREGION could not find ") + name; return false;
            }
        }
        return true;
    }

    // AOBSCANALL(name, pattern) — find pattern across all readable memory
    if (startsWith(upper, "AOBSCANALL(") && line.back() == ')' && proc) {
        auto args = line.substr(11, line.size() - 12);
        auto parts = splitArgs(args, 2);
        // A missing argument used to skip the scan silently: the name then
        // resolved to a label another enabled script registered (templates
        // share INJECT), and the hook went to that script's address.
        if (parts.size() != 2) { error = "AOBSCANALL(name, pattern) takes 2 arguments"; return false; }
        if (parts.size() == 2) {
            auto name = trim(parts[0]);
            auto pattern = stripOptionalQuotes(parts[1]);

            ScanConfig cfg;
            cfg.valueType = ValueType::ByteArray;
            if (!cfg.parseAOB(pattern) || cfg.byteArray.empty()) { error = "Invalid AOB pattern: " + pattern; return false; }
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
                error = std::string("AOBSCANALL could not find ") + name; return false;
            }
        }
        return true;
    }

    // AOBSCANMODULE(name, module, pattern) — find pattern inside one module
    if (startsWith(upper, "AOBSCANMODULE(") && line.back() == ')' && proc) {
        auto args = line.substr(14, line.size() - 15);
        auto parts = splitArgs(args, 3);
        // A missing argument used to skip the scan silently: the name then
        // resolved to a label another enabled script registered (templates
        // share INJECT), and the hook went to that script's address.
        if (parts.size() != 3) { error = "AOBSCANMODULE(name, module, pattern) takes 3 arguments"; return false; }
        if (parts.size() == 3) {
            auto name = trim(parts[0]);
            auto moduleName = stripOptionalQuotes(parts[1]);
            auto pattern = stripOptionalQuotes(parts[2]);

            auto modules = proc->modules();
            auto moduleIt = std::find_if(modules.begin(), modules.end(), [&](const ModuleInfo& module) {
                return moduleMatches(module, moduleName);
            });
            if (moduleIt == modules.end()) {
                error = "AOBSCANMODULE: module not found: " + moduleName;
                return false;
            }

            ScanConfig cfg;
            if (!cfg.parseAOB(pattern) || cfg.byteArray.empty()) { error = "Invalid AOB pattern: " + pattern; return false; }
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
                error = "AOBSCANMODULE could not find " + name + " in " + moduleIt->name; return false;
            }
        }
        return true;
    }

    // AOBSCAN(name, pattern) — find pattern
    if (startsWith(upper, "AOBSCAN(") && line.back() == ')' && proc) {
        auto args = line.substr(8, line.size() - 9);
        auto parts = splitArgs(args, 2);
        // A missing argument used to skip the scan silently: the name then
        // resolved to a label another enabled script registered (templates
        // share INJECT), and the hook went to that script's address.
        if (parts.size() != 2) { error = "AOBSCAN(name, pattern) takes 2 arguments"; return false; }
        if (parts.size() == 2) {
            auto name = trim(parts[0]);
            auto pattern = stripOptionalQuotes(parts[1]);

            // Use our scanner's AOB
            ScanConfig cfg;
            cfg.valueType = ValueType::ByteArray;
            if (!cfg.parseAOB(pattern) || cfg.byteArray.empty()) { error = "Invalid AOB pattern: " + pattern; return false; }
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
                error = std::string("AOBSCAN could not find ") + name; return false;
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
        // A regular file of reasonable size only: a device such as /dev/zero
        // would be read without end (this also runs in a syntax check).
        std::error_code sizeError;
        const bool readable = std::filesystem::is_regular_file(filename, sizeError) &&
                              std::filesystem::file_size(filename, sizeError) <= (16u << 20) && !sizeError;
        std::ifstream incFile;
        if (readable) incFile.open(filename);
        if (readable && incFile) {
            std::string incLine;
            while (std::getline(incFile, incLine)) {
                if (!parseLine(incLine, allocs, labels, defines, registeredSymbols, asmLines, log, proc, error, includeDepth + 1))
                    return false;
            }
            log.push_back("INCLUDE: " + filename + " (loaded)");
        } else {
            // Carrying on without the file's allocs and defines "succeeded"
            // with a script that is not the one written.
            error = "INCLUDE: cannot read " + filename;
            return false;
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

    // NOP [count] emits this many target instructions at the active address. A
    // NOP with an operand ("nop dword ptr [rax+rax]", the multi-byte form
    // compilers pad with, as relocated by injection templates) is an
    // ordinary instruction.
    const auto nopOperand = upper.size() > 3 ? trim(upper.substr(3)) : std::string();
    // "nop eax" (0f 1f c0) is a register, though it reads like a hex count.
    static const std::set<std::string> nopRegisters = {"AX", "BX", "CX", "DX", "EAX", "EBX", "ECX", "EDX"};
    const bool nopCount = nopOperand.empty() ||
        (!nopRegisters.count(nopOperand) &&
         std::all_of(nopOperand.begin(), nopOperand.end(), [](unsigned char c) { return std::isxdigit(c) || c == 'X'; }));
    if ((upper == "NOP" || startsWith(upper, "NOP ")) && nopCount) {
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
    std::function<uintptr_t(const std::string&, size_t)> resolve;
    resolve = [&](const std::string& expression, size_t depth) -> uintptr_t {
        if (depth > 32) return 0;
        auto name = trim(expression);
        if (name.empty()) return 0;
        for (const auto& a : allocs) if (a.name == name) return a.address;
        for (const auto& l : labels) if (l.name == name) return l.address;
        for (const auto& d : defines) if (d.name == name) return resolve(d.value, depth + 1);
        auto it = globalSymbols_.find(stripOptionalQuotes(name));
        if (it != globalSymbols_.end()) return it->second;
        for (auto module = targetModules_.rbegin(); module != targetModules_.rend(); ++module)
            if (!module->name.empty() && module->name == stripOptionalQuotes(name)) return module->base;
        if (auto site = hookSites_.find(stripOptionalQuotes(name)); site != hookSites_.end()) return site->second;
        if (auto symbol = processSymbol(stripOptionalQuotes(name))) return symbol;
        // Quoted module names can contain '+' and '-'; split arithmetic only
        // outside quotes, from the right, to preserve left-to-right evaluation.
        char quote = 0;
        size_t op = std::string::npos;
        for (size_t i = 0; i < name.size(); ++i) {
            char c = name[i];
            if (quote) { if (c == quote) quote = 0; }
            else if (c == '\"' || c == '\'') quote = c;
            else if (i && (c == '+' || c == '-')) op = i;
        }
        if (op != std::string::npos) {
            auto base = resolve(name.substr(0, op), depth + 1);
            uint64_t offset = 0;
            if (!base || !parseWholeUnsigned(trim(name.substr(op + 1)), 16, offset) || offset > UINTPTR_MAX) return 0;
            if (name[op] == '+') return offset <= UINTPTR_MAX - base ? base + offset : 0;
            return offset <= base ? base - offset : 0;
        }
        uint64_t parsed = 0;
        return parseWholeUnsigned(name, 16, parsed) && parsed <= UINTPTR_MAX ? static_cast<uintptr_t>(parsed) : 0;
    };
    return resolve(expr, 0);
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
                // Defines that name other defines multiply a line's length
                // with each level: stop at 64 KiB (the line then fails to
                // assemble instead of using up memory).
                if (leftOk && rightOk && result.size() - name.size() + value.size() > (64u << 10)) return;
                if (leftOk && rightOk) {
                    result.replace(pos, name.size(), value);
                    pos += value.size();
                } else {
                    pos += 1;
                }
            }
        };
        for (const auto& d : sortedDefines) {
            auto address = resolveAddress(d.name, allocs, labels, defines);
            replaceWholeToken(d.name, address ? formatHexLiteral(address) : d.value);
        }
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
    std::vector<size_t>& reassemblySizes, std::string& error)
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
        reassemblySizes.assign(asmLines.size(),0);

        for (size_t lineIndex=0;lineIndex<asmLines.size();++lineIndex) {
            const auto& rawLine=asmLines[lineIndex];
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

            // fillmem names its own address; it needs no active one.
            if (currentAddr == 0 && !startsWith(trimmedLine, "__FILLMEM__:")) {
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

                auto asmResult = reassembleTarget(proc,addr,currentAddr);
                if (!asmResult) {
                    error = "REASSEMBLE sizing failed at " + addrExpr + ": " + asmResult.error();
                    return false;
                }
                reassemblySizes[lineIndex]=asmResult->size();
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
                auto plan=planNops(currentAddr,count);
                if (!plan) {error=plan.error();return false;}
                currentAddr += plan->size;
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
                if (!parseDataDirective(op, dataStr, dataBytes, parseError, machineForCode(currentAddr).byteOrder)) {
                    error = parseError;
                    return false;
                }
                currentAddr += dataBytes.size();
                continue;
            }

            auto substituted = substituteForSizing(trimmedLine, currentAddr);
            auto asmResult = assembleTarget(substituted, currentAddr);
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

            // CE's templates write assert(address,bytes) after define(bytes,...).
            for (int depth = 0; depth < 8; ++depth) {
                auto named = std::find_if(defines.begin(), defines.end(), [&](const Define& d) { return d.name == bytesStr; });
                if (named == defines.end()) break;
                bytesStr = trim(named->value);
            }
            if (!bytesStr.empty() && bytesStr.front() == '"') bytesStr = bytesStr.substr(1);
            if (!bytesStr.empty() && bytesStr.back() == '"') bytesStr.pop_back();

            ScanConfig pattern;
            if (!pattern.parseAOB(bytesStr) || pattern.byteArray.empty()) {
                reason = "ASSERT has no valid bytes: " + bytesStr;
                return false;
            }

            std::vector<uint8_t> current(pattern.byteArray.size());
            auto readResult = proc->read(addr, current.data(), current.size());
            if (!readResult || *readResult < current.size()) {
                reason = "ASSERT read failed at " + addrExpr;
                return false;
            }

            for (size_t i = 0; i < pattern.byteArray.size(); ++i) {
                // Wildcards and half wildcards ("4?") compare only their mask.
                const uint8_t mask = i < pattern.byteArrayMask.size() ? pattern.byteArrayMask[i] : 0xFF;
                if ((current[i] & mask) != (pattern.byteArray[i] & mask)) {
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
    symbolOwners_.erase(name);
}

void AutoAssembler::unregisterSymbol(const std::string& name) {
    globalSymbols_.erase(name);
    symbolOwners_.erase(name);
}

uintptr_t AutoAssembler::processSymbol(const std::string& name) const {
    // Only identifier-like names: numbers and arithmetic never need the
    // (lazily loaded, potentially large) process symbol table.
    if (!symbolProcess_ || name.empty() || !(std::isalpha(static_cast<unsigned char>(name[0])) || name[0] == '_') ||
        name.find_first_of("+-*[] ") != std::string::npos)
        return 0;
    if (!processSymbols_) {
        auto resolver = std::make_shared<SymbolResolver>();
        resolver->loadProcess(*symbolProcess_);
        processSymbols_ = std::move(resolver);
    }
    return processSymbols_->lookup(name);
}

// The C runtime and the dynamic loader: libc, ld-linux, musl, and glibc's
// split-out parts, and under Wine or Proton the Windows C runtimes (msvcrt,
// ucrtbase, the api-ms-win-crt forwarders, msvcr*, msvcp*, vcruntime*) and
// ntdll, which exports C functions too. Windows names in any case, with or
// without ".dll", and Wine's builtin ".so" or ".dll.so" forms. An undeclared
// "index:" or "exit:" never patches them.
static bool isCRuntimeModule(const std::string& module) {
    std::string name = module;
    for (auto& c : name) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    static const std::set<std::string> runtime = {"libc", "ld", "libm", "libpthread", "libdl", "librt", "libresolv"};
    if (runtime.contains(name.substr(0, name.find_first_of(".-")))) return true;
    for (const char* suffix : {".so", ".dll"})
        if (name.ends_with(suffix)) name.resize(name.size() - std::strlen(suffix));
    static const std::set<std::string> windows = {"msvcrt", "msvcrtd", "ucrtbase", "ucrtbased", "crtdll", "ntdll"};
    if (windows.contains(name) || name.starts_with("api-ms-win-crt-")) return true;
    // Versioned runtimes: msvcr100, msvcp140, msvcp140_1, msvcp_win, vcruntime140_1.
    for (const std::string prefix : {"msvcr", "msvcp", "vcruntime"})
        if (name.starts_with(prefix) && name.size() > prefix.size() &&
            (std::isdigit(static_cast<unsigned char>(name[prefix.size()])) || name[prefix.size()] == '_'))
            return true;
    return false;
}

AutoAssembler::HookSiteSymbol AutoAssembler::hookSiteSymbol(const std::string& name) {
    if (auto known = hookSites_.find(name); known != hookSites_.end()) return {known->second, false};
    if (!processSymbol(name)) return {};   // also loads the table
    // The main executable first, then any other module except the C runtime.
    // By the name as written: a mangled C++ name is listed demangled.
    const std::string main = targetModules_.empty() ? std::string() : targetModules_.front().name;
    uintptr_t best = 0;
    bool mainModule = false, runtimeOnly = false;
    for (const auto* found : processSymbols_->symbolsByRawName(name)) {
        const auto& symbol = *found;
        // Code a JIT runtime listed in its perf map is recompiled and moved;
        // a label never lands on it.
        if (!symbol.address || symbol.module == "[jit]") continue;
        if (isCRuntimeModule(symbol.module)) { runtimeOnly = true; continue; }
        const bool inMain = !main.empty() && symbol.module == main;
        if (!best || (inMain && !mainModule)) { best = symbol.address; mainModule = inMain; }
    }
    if (!best) return {0, runtimeOnly};
    hookSites_[name] = best;
    return {best, false};
}

uintptr_t AutoAssembler::resolveSymbol(const std::string& name) const {
    auto it = globalSymbols_.find(name);
    if (it != globalSymbols_.end()) return it->second;
    for (auto module = targetModules_.rbegin(); module != targetModules_.rend(); ++module)
        if (!module->name.empty() && module->name == name) return module->base;
    return 0;
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
                                     std::string& error, const std::set<std::string>& knownNames) {
    if (!expandConditionalBlocks(code, log, error))
        return false;
    if (!resolveAnonymousLabels(code, log, error))
        return false;
    // Auto-declare named labels so forward "jmp skip … skip:" works without an
    // explicit label(skip), matching CE. Runs after anonymous-label resolution so
    // the generated __anon_N labels are already declared and skipped.
    std::string refused;
    std::vector<std::string> undecided;
    autoDeclareNamedLabels(code, [&](const std::string& name, const NamedLabelUse& use) {
        if (globalSymbols_.contains(name) || knownNames.contains(name)) return true;
        for (const auto& module : targetModules_)
            if (module.name == name) return true;
        // Cheat Engine tries every "name:" as a symbol before making it a
        // label. Here a name the code jumps to ("jmp exit ... exit:") stays a
        // local label, and so does a name that only the C runtime or the
        // loader defines, so "index:" or "time:" in a cave never patches
        // libc. A function of the game or of its other libraries
        // ("UpdateHealth:") is that function, wherever the definition is.
        if (use.jumpTarget) return false;
        if (!symbolProcess_) {
            // A syntax check has no target to look in. It parses the name as
            // a label unless the script names it as an alloc's near address,
            // and says that the target decides.
            if (use.nearAddress) return true;
            undecided.push_back(name);
            return false;
        }
        const auto symbol = hookSiteSymbol(name);
        if (symbol.address) return true;
        // As a label this one has no address, or the alloc beside it is
        // placed near it: the script means the C runtime's function.
        if (symbol.runtimeOnly && (use.firstAddress || use.nearAddress) && refused.empty())
            refused = name + ": only the C library or the loader has this symbol; to patch it there, write define(hook," +
                      name + ") and hook:";
        return false;
    });
    if (!refused.empty()) { error = refused; return false; }
    if (!undecided.empty()) {
        std::string names;
        for (const auto& name : undecided) names += (names.empty() ? "" : ", ") + name;
        log.push_back("Decided at inject time: " + names + " (the target's function of that name unless only the "
                      "C library or the loader has one, otherwise a label in this script)");
    }

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

TargetMachine AutoAssembler::machineForCode(uintptr_t address) const {
    for (const auto& block : codeAllocations_)
        if (address >= block.address && address - block.address < block.size) return block.machine;
    const ModuleInfo* best = nullptr;
    for (const auto& m : targetModules_)
        if (address >= m.base && address - m.base < m.size && (!best || m.size < best->size)) best = &m;
    return best && best->machine.architecture != CpuArchitecture::Unknown &&
           best->machine.architecture != CpuArchitecture::Other ? best->machine : programMachine_;
}

std::expected<std::vector<uint8_t>, std::string> AutoAssembler::assembleTarget(const std::string& code, uintptr_t address) {
    auto architecture = disassemblerArchFor(machineForCode(address));
    if (!architecture) return std::unexpected(architecture.error());
    auto arch = assemblerArchFor(*architecture);
    if (!arch) return std::unexpected(arch.error());
    try {
        auto& assembler = targetAssemblers_[*arch];
        if (!assembler) assembler = std::make_unique<Assembler>(*arch);
        return assembler->assemble(code, address);
    } catch (const std::exception& error) { return std::unexpected(error.what()); }
}

std::expected<AutoAssembler::NopPlan,std::string> AutoAssembler::planNops(uintptr_t address,size_t count) {
    auto architecture=disassemblerArchFor(machineForCode(address));
    if (!architecture) return std::unexpected(architecture.error());
    const bool thumb=*architecture==Arch::ARMThumb || *architecture==Arch::ARMThumb_BE;
    const bool arm=*architecture==Arch::ARM32 || *architecture==Arch::ARM32_BE || *architecture==Arch::ARM64;
    if ((thumb && address%2) || (arm && address%4)) return std::unexpected("Unaligned NOP instruction address");
    auto encoding=assembleTarget("nop",address);
    if (!encoding || encoding->empty()) return std::unexpected(encoding ? "Empty NOP encoding" : encoding.error());
    if (!count || count>kMaxAaBufferBytes/encoding->size()) return std::unexpected("NOP range exceeds the buffer limit");
    const size_t size=count*encoding->size();
    if (size>UINTPTR_MAX-address) return std::unexpected("NOP range overflows the address space");
    return NopPlan{std::move(*encoding),size};
}

std::expected<std::vector<uint8_t>,std::string> AutoAssembler::reassembleTarget(
    ProcessHandle& proc,uintptr_t source,uintptr_t destination,const std::vector<DisableInfo::OriginalBytes>* before) {
    const auto machine=machineForCode(source);
    const bool a64=machine.architecture==CpuArchitecture::Arm64;
    uint8_t buffer[16];const size_t size=a64 ? 4 : sizeof(buffer);
    auto read=proc.read(source,buffer,size);
    if (!read || !*read || *read>size) return std::unexpected("REASSEMBLE source read failed");
    // As readmem and assert do: relocate the instruction the script found, not
    // its own hook written over it (the earliest write's original wins).
    if (before)
        for (auto patch=before->rbegin();patch!=before->rend();++patch) {
            if (patch->bytes.empty() || patch->bytes.size()-1>UINTPTR_MAX-patch->address) continue;
            const uintptr_t last=source+(*read-1),patchLast=patch->address+(patch->bytes.size()-1);
            const uintptr_t lo=std::max(source,patch->address),hi=std::min(last,patchLast);
            if (lo<=hi) std::copy_n(patch->bytes.data()+(lo-patch->address),hi-lo+1,buffer+(lo-source));
        }
    auto architecture=disassemblerArchFor(machine);
    if (!architecture) return std::unexpected(architecture.error());
    Disassembler decoder(*architecture);
    const auto decoded=decoder.disassemble(source,{buffer,*read},1);
    if (decoded.empty()) return std::unexpected("REASSEMBLE source instruction is invalid");
    if (a64) {
        if (machineForCode(destination).architecture!=CpuArchitecture::Arm64)
            return std::unexpected("REASSEMBLE source and destination instruction architectures differ");
        auto relocated=relocateAarch64(decoded[0].bytes,source,destination);
        if (!relocated) return std::unexpected(relocated.error());
        return std::move(relocated->bytes);
    }
    // A RIP-relative operand reaches its target from the original address:
    // re-encode it relative to the new one, as injection templates do.
    std::string operands=decoded[0].operands;
    if (decoded[0].memory.ripRelative) {
        const auto open=operands.find('['),close=operands.find(']',open);
        if (open==std::string::npos || close==std::string::npos)
            return std::unexpected("REASSEMBLE cannot relocate this RIP-relative operand");
        char target[32];std::snprintf(target,sizeof target,"rel 0x%llx",static_cast<unsigned long long>(decoded[0].ripTarget));
        operands.replace(open+1,close-open-1,target);
    }
    return assembleTarget(decoded[0].mnemonic+" "+operands,destination);
}

static bool recordReleased(const auto& record) {
    return record.allocationReleased && record.allocationReleased->load();
}

// Make bytes the value restored at address wherever saved originals cover it.
static void overrideOriginals(std::vector<DisableInfo::OriginalBytes>& originals, uintptr_t address,
                              const std::vector<uint8_t>& bytes) {
    if (bytes.empty() || bytes.size() - 1 > UINTPTR_MAX - address) return;
    const uintptr_t last = address + (bytes.size() - 1);
    for (auto& patch : originals) {
        if (patch.bytes.empty() || patch.bytes.size() - 1 > UINTPTR_MAX - patch.address) continue;
        const uintptr_t lo = std::max(address, patch.address);
        const uintptr_t hi = std::min(last, patch.address + (patch.bytes.size() - 1));
        if (lo <= hi) std::copy_n(bytes.data() + (lo - address), hi - lo + 1, patch.bytes.data() + (lo - patch.address));
    }
}

// Remove [first, last] from every saved range: nothing restores those bytes.
static void dropRange(std::vector<DisableInfo::OriginalBytes>& originals, uintptr_t first, uintptr_t last) {
    std::vector<DisableInfo::OriginalBytes> kept;
    kept.reserve(originals.size());
    for (auto& patch : originals) {
        const uintptr_t end = patch.bytes.empty() ? patch.address : patch.address + (patch.bytes.size() - 1);
        if (patch.bytes.empty() || last < patch.address || first > end) { kept.push_back(std::move(patch)); continue; }
        auto piece = [&](uintptr_t from, uintptr_t to) {
            const size_t offset = from - patch.address, count = to - from + 1;
            DisableInfo::OriginalBytes part{from, {patch.bytes.begin() + offset, patch.bytes.begin() + offset + count}, {},
                                            patch.executable, patch.allocationReleased, patch.verifyOwnership};
            if (patch.written.size() == patch.bytes.size())
                part.written.assign(patch.written.begin() + offset, patch.written.begin() + offset + count);
            kept.push_back(std::move(part));
        };
        if (first > patch.address) piece(patch.address, first - 1);
        if (last < end) piece(last + 1, end);
    }
    originals = std::move(kept);
}

// Code a saved patch can be gone (a library unloaded, a JIT method freed): its
// bytes cannot be checked or restored, and insisting on it left the record
// impossible to disable and its cave allocated for good. Patches and
// protections over unmapped ranges are dropped.
static DisableInfo withoutUnmapped(ProcessHandle& proc, const DisableInfo& saved, bool& dropped) {
    DisableInfo pruned = saved;
    dropped = false;
    // Gone only when nothing of it can be read and no region holds it: a
    // handle without a region map (a stub, a test double) reads fine.
    auto mapped = [&](uintptr_t address, size_t size) {
        uint8_t probe[64];
        auto read = proc.read(address, probe, std::min<size_t>(size, sizeof probe));
        if (read && *read) return true;
        auto region = proc.queryRegion(address);
        return region && address >= region->base && address - region->base < region->size;
    };
    if (!saved.image || saved.image->pid() == proc.pid()) {
        std::erase_if(pruned.originals, [&](const auto& patch) {
            return !patch.bytes.empty() && patch.bytes.size() - 1 <= UINTPTR_MAX - patch.address &&
                   !mapped(patch.address, patch.bytes.size());
        });
        std::erase_if(pruned.protections, [&](const auto& protection) { return !mapped(protection.address, protection.size); });
        dropped = pruned.originals.size() != saved.originals.size();
    }
    return pruned;
}

// Refuse to overwrite code replaced by the target or another patch owner.
// Partial writes/undo and overlapping script lines may leave any byte in one
// of this operation's saved states, so accept those states individually.
// Ordinary data can legitimately change while a script is enabled.
static std::string codeOwnershipConflict(ProcessHandle& proc, const DisableInfo& info) {
    for (const auto& patch : info.originals) {
        if (!patch.verifyOwnership || recordReleased(patch) || patch.written.size() != patch.bytes.size()) continue;
        for (size_t offset = 0; offset < patch.bytes.size();) {
            const size_t count = std::min<size_t>(65536, patch.bytes.size() - offset);
            const uintptr_t address = patch.address + offset;
            std::vector<uint8_t> actual(count), accepted(count);
            auto read = info.image ? info.image->read(address, actual.data(), count) : proc.read(address, actual.data(), count);
            if (!read || *read != count) return "Cannot inspect saved code ownership at " + formatHexLiteral(address);
            for (const auto& state : info.originals) {
                if (recordReleased(state) || state.bytes.empty()) continue;
                for (size_t i = 0; i < count; ++i) {
                    const uintptr_t at = address + i;
                    if (at < state.address || at - state.address >= state.bytes.size()) continue;
                    const size_t index = at - state.address;
                    if (actual[i] == state.bytes[index] ||
                        (index < state.written.size() && actual[i] == state.written[index])) accepted[i] = 1;
                }
            }
            const auto conflict = std::find(accepted.begin(), accepted.end(), uint8_t(0));
            if (conflict != accepted.end())
                return "Code ownership changed at " + formatHexLiteral(address + (conflict - accepted.begin())) + "; saved undo retained";
            offset += count;
        }
    }
    return {};
}

// Data this script wrote that a newer, still enabled script of this assembler
// wrote again: restoring it now would undo that script's write, and that
// script would later restore this one's value. The newer script restores this
// one's original instead; the ranges leave info. Code is not handed over: a
// hook over a hook relocated the older jump, so its overlap stays refused.
std::vector<AutoAssembler::Handover> AutoAssembler::planHandovers(DisableInfo& info, pid_t pid) {
    std::vector<Handover> handovers;
    std::erase_if(livePatches_, [](const LivePatch& live) { auto owner = live.owner.lock(); return !owner || owner->complete; });
    if (!info.ownership) return handovers;
    auto self = std::find_if(livePatches_.begin(), livePatches_.end(),
                             [&](const LivePatch& live) { return live.owner.lock() == info.ownership; });
    if (self == livePatches_.end()) return handovers;
    std::vector<std::pair<std::shared_ptr<DisableInfo::Ownership>, const LivePatch*>> newer;
    for (auto live = std::next(self); live != livePatches_.end(); ++live) {
        if (live->pid != pid) continue;
        if (auto image = live->image.lock(); image && !image->check()) continue;
        if (live->ranges.empty()) continue;   // holds no originals to restore
        if (auto owner = live->owner.lock()) newer.push_back({std::move(owner), &*live});
    }
    if (newer.empty()) return handovers;
    // What this script restores at [first, last]: the earliest write's original.
    auto originalAt = [&](uintptr_t first, uintptr_t last) {
        std::vector<uint8_t> bytes(last - first + 1);
        for (auto patch = info.originals.rbegin(); patch != info.originals.rend(); ++patch) {
            if (patch->bytes.empty() || recordReleased(*patch)) continue;
            const uintptr_t lo = std::max(first, patch->address);
            const uintptr_t hi = std::min(last, patch->address + (patch->bytes.size() - 1));
            if (lo <= hi) std::copy_n(patch->bytes.data() + (lo - patch->address), hi - lo + 1, bytes.data() + (lo - first));
        }
        return bytes;
    };
    std::vector<std::pair<uintptr_t, uintptr_t>> claimed;
    for (const auto& patch : info.originals) {
        // Writes inside allocations end with them; code keeps its ownership check.
        if (patch.verifyOwnership || patch.allocationReleased || patch.bytes.empty()) continue;
        std::vector<std::pair<uintptr_t, uintptr_t>> open{{patch.address, patch.address + (patch.bytes.size() - 1)}};
        // The next newer script over a byte holds the value this one wrote there.
        for (const auto& [owner, live] : newer) {
            for (const auto& [address, size] : live->ranges) {
                if (!size) continue;
                std::vector<std::pair<uintptr_t, uintptr_t>> rest;
                for (const auto& [first, last] : open) {
                    const uintptr_t lo = std::max(first, address), hi = std::min(last, address + (size - 1));
                    if (lo > hi) { rest.push_back({first, last}); continue; }
                    handovers.push_back({owner, lo, originalAt(lo, hi)});
                    claimed.push_back({lo, hi});
                    if (first < lo) rest.push_back({first, lo - 1});
                    if (hi < last) rest.push_back({hi + 1, last});
                }
                open = std::move(rest);
            }
        }
    }
    for (const auto& [first, last] : claimed) dropRange(info.originals, first, last);
    return handovers;
}

AutoAsmResult AutoAssembler::cleanup(ProcessHandle& proc, const DisableInfo& saved) {
    AutoAsmResult result;
    result.disableInfo = saved;
    // Patches and protections over unmapped ranges are dropped; the rest of
    // the cleanup (freeing allocations) goes on.
    bool dropped = false;
    DisableInfo pruned = withoutUnmapped(proc, saved, dropped);
    if (dropped) result.log.push_back("Patched code is no longer mapped; its original bytes were not restored");
    const DisableInfo& info = pruned;
    auto fail = [&](const std::string& error) {
        if (!result.error.empty()) result.error += "\n";
        result.error += error;
    };
    std::unique_lock<std::mutex> ownership;
    if(info.ownership) {
        ownership=std::unique_lock(info.ownership->mutex,std::try_to_lock);
        if(!ownership.owns_lock()) {fail("This undo is already in progress");return result;}
        if(info.ownership->complete) {result.disableInfo={};result.success=true;return result;}
        for (const auto& [address, bytes] : info.ownership->restoreOverrides) overrideOriginals(pruned.originals, address, bytes);
    }
    auto eraseSymbols=[&] {
        for(const auto& [name,address]:info.symbols) {
            auto sym=globalSymbols_.find(name);auto owner=symbolOwners_.find(name);
            const bool ours=!info.ownership || (owner!=symbolOwners_.end() && owner->second.lock()==info.ownership);
            if(ours && sym!=globalSymbols_.end() && sym->second==address) {globalSymbols_.erase(sym);symbolOwners_.erase(name);}
        }
    };
    if(info.image) {
        if(info.image->pid()!=proc.pid()) {fail("Saved undo belongs to another process");return result;}
        auto live=info.image->check();
        if(!live) {
            if(live.error()!=std::errc::operation_canceled) {fail(live.error().message());return result;}
            for(const auto& a:info.allocs) {
                if(a.released) a.released->store(true);
                auto tracked=knownAllocations_.find(a.name);
                if(tracked!=knownAllocations_.end() && tracked->second.address==a.address && (!a.owner || tracked->second.owner==a.owner)) knownAllocations_.erase(tracked);
            }
            eraseSymbols();if(info.ownership) info.ownership->complete=true;
            result.disableInfo={};result.success=true;
            result.log.push_back("Original address space retired; discarded undo without writing to its replacement");return result;
        }
    }
    auto busy=[&](uintptr_t address,size_t size) {
        return os::memorySyscallService().threadStorageBusy(proc.pid(),address,size);
    };
    for (const auto& allocation : info.allocs) if ((!allocation.released || !allocation.released->load()) && busy(allocation.address,allocation.size)) {
        fail("Injected thread is still running; retain allocations and retry cleanup after it exits"); return result;
    }
    for (const auto& patch : info.originals) if (!recordReleased(patch) && busy(patch.address,patch.bytes.size())) {
        fail("Injected thread is still running; retain original bytes and retry cleanup after it exits"); return result;
    }
    for (const auto& protection : info.protections) if (!recordReleased(protection) && busy(protection.address,protection.size)) {
        fail("Injected thread is still running; retain page protections and retry cleanup after it exits"); return result;
    }
    for (const auto& patch : info.originals)
        if (!patch.bytes.empty() && patch.bytes.size() - 1 > UINTPTR_MAX - patch.address) {
            fail("Restoration range overflows the address space"); return result;
        }
    if (auto conflict = codeOwnershipConflict(proc, info); !conflict.empty()) { fail(conflict); return result; }
    auto handovers = planHandovers(pruned, proc.pid());
    // Verify the final restored image; later saved ranges can overlap earlier ones.
    std::vector<std::pair<uintptr_t, uintptr_t>> ranges;
    for (const auto& patch : info.originals) {
        if (patch.bytes.empty() || recordReleased(patch)) continue;
        if (patch.bytes.size() - 1 > UINTPTR_MAX - patch.address) { fail("Restoration range overflows the address space"); return result; }
        ranges.push_back({patch.address, patch.address + patch.bytes.size() - 1});
    }
    std::sort(ranges.begin(), ranges.end());
    std::vector<std::pair<uintptr_t, uintptr_t>> merged;
    for (const auto& range : ranges) {
        if (!merged.empty() && (range.first <= merged.back().second ||
            (merged.back().second != UINTPTR_MAX && range.first == merged.back().second + 1)))
            merged.back().second = std::max(merged.back().second, range.second);
        else merged.push_back(range);
    }
    auto firstMismatch = [&]() -> std::optional<uintptr_t> {
        for (const auto& [first, last] : merged) {
            uintptr_t address = first;
            while (true) {
                size_t count = last - address >= 65535 ? 65536 : last - address + 1;
                std::vector<uint8_t> wanted(count), actual(count);
                uintptr_t end = address + count - 1;
                for (auto patch = info.originals.rbegin(); patch != info.originals.rend(); ++patch) {
                    if (patch->bytes.empty() || recordReleased(*patch)) continue;
                    uintptr_t patchEnd = patch->address + patch->bytes.size() - 1;
                    if (patchEnd < address || patch->address > end) continue;
                    uintptr_t from = std::max(address, patch->address), to = std::min(end, patchEnd);
                    std::copy_n(patch->bytes.data() + (from - patch->address), to - from + 1, wanted.data() + (from - address));
                }
                auto read = info.image ? info.image->read(address,actual.data(),actual.size()) : proc.read(address, actual.data(), actual.size());
                if (!read || *read != actual.size() || actual != wanted) return address;
                if (count - 1 == last - address) break;
                address += count;
            }
        }
        return std::nullopt;
    };
    // A retry may follow partial protection restoration. Avoid writing pages
    // whose final original bytes are already correct and possibly read-only.
    if (firstMismatch()) {
        for (auto it = info.originals.rbegin(); it != info.originals.rend(); ++it) {
            if(recordReleased(*it)) continue;
            const auto region=proc.queryRegion(it->address);
            auto written = info.image ? info.image->write(it->address,it->bytes,it->executable) : region && (region->protection & MemProt::Exec)
                ? proc.writeCode(it->address,it->bytes.data(),it->bytes.size())
                : proc.write(it->address, it->bytes.data(), it->bytes.size());
            if (!written || *written != it->bytes.size())
                fail("Cannot restore original bytes at " + formatHexLiteral(it->address));
        }
        if (auto mismatch = firstMismatch())
            fail("Original-byte verification failed at " + formatHexLiteral(*mismatch));
    }
    if (!result.error.empty()) return result; // Keep allocations and symbols alive for retry.
    for (auto it = info.protections.rbegin(); it != info.protections.rend(); ++it) {
        if(recordReleased(*it)) continue;
        auto restored = info.image ? info.image->protect(it->address,it->size,it->protection) : proc.protect(it->address, it->size, it->protection);
        if (!restored) fail("Cannot restore page protection at " + formatHexLiteral(it->address));
    }
    if (!result.error.empty()) return result;
    // Restored: the newer scripts now hold the originals under their writes.
    for (auto& handover : handovers) {
        std::lock_guard lock(handover.to->mutex);
        handover.to->restoreOverrides.emplace_back(handover.address, std::move(handover.bytes));
    }
    if (!handovers.empty()) result.log.push_back("Left bytes that a newer enabled script wrote over; it restores the originals");
    result.disableInfo.originals.clear(); result.disableInfo.protections.clear();
    // Its bytes are restored and no longer saved: an older script disabled
    // later must restore its own originals there, not hand them to this one
    // (whose retry after a failed free restores nothing).
    if (info.ownership)
        std::erase_if(livePatches_, [&](const LivePatch& live) { return live.owner.lock() == info.ownership; });
    std::vector<DisableInfo::AllocEntry> pending;
    for (const auto& a : info.allocs) {
        if(a.released ? a.released->load() : cleanedAllocations_.contains({a.address,a.size})) continue;
        auto freed = a.image ? a.image->free(a.address,a.size) : info.image ? info.image->free(a.address,a.size) : proc.free(a.address, a.size);
        if (!freed) { pending.push_back(a); fail("Cannot free allocation " + a.name + ": " + freed.error().message()); continue; }
        cleanedAllocations_.insert({a.address, a.size});
        if(a.released) a.released->store(true);
        auto tracked = knownAllocations_.find(a.name);
        if (tracked != knownAllocations_.end() && tracked->second.address == a.address && (!a.owner || tracked->second.owner==a.owner)) knownAllocations_.erase(tracked);
    }
    result.disableInfo.allocs = std::move(pending);
    if (!result.error.empty()) return result;
    eraseSymbols();if(info.ownership) info.ownership->complete=true;
    result.disableInfo = {};
    result.success = true;
    result.log.push_back("Disabled: restored original bytes and page protections; freed allocations");
    return result;
}

AutoAsmResult AutoAssembler::execute(ProcessHandle& proc, const std::string& script) {
    auto enableCode = extractSection(script, "ENABLE");
    // No sections: the entire script is the enable part. An empty [ENABLE]
    // (with a [DISABLE]) enables nothing; it must not run the whole script.
    if (!hasSectionHeaders(stripBraceComments(script))) enableCode = script;
    return run(proc, std::move(enableCode), nullptr);
}

AutoAsmResult AutoAssembler::run(ProcessHandle& proc, std::string enableCode, const DisableInfo* undo) {
    AutoAsmResult result;
    result.success = false;
    // A failed target capture must not leave the previous target's modules
    // visible to subsequent resolution or syntax checking.
    targetModules_.clear();
    result.disableInfo.ownership=std::make_shared<DisableInfo::Ownership>();
    if (undo && undo->image) result.disableInfo.image = undo->image;   // the address space it undoes
    else {
        auto image=os::pinNativeMemoryImage(proc);
        if(!image) {result.error="Cannot pin original address space: "+image.error().message();return result;}
        result.disableInfo.image=*image;
    }

    // A globalalloc block made in this address space. One assembler (the
    // GUI's) outlives a game run: a block from an earlier run or another
    // process is not shared, and a write at its addresses here is undone.
    // Handles without a pinned image (remote, test doubles) match as before.
    auto liveBlock = [&](const DisableInfo::AllocEntry& block) {
        if (!block.image || !result.disableInfo.image) return block.image == result.disableInfo.image;
        return block.image->identity() == result.disableInfo.image->identity();
    };
    // Blocks whose address space is gone (the game exited or ran exec) are
    // forgotten, with the symbol their globalalloc registered.
    for (auto name = globalAllocations_.begin(); name != globalAllocations_.end();) {
        auto known = knownAllocations_.find(*name);
        if (known == knownAllocations_.end() || !known->second.image || known->second.image->check()) { ++name; continue; }
        if (auto symbol = globalSymbols_.find(*name); symbol != globalSymbols_.end() && symbol->second == known->second.address) {
            globalSymbols_.erase(symbol);
            symbolOwners_.erase(*name);
        }
        knownAllocations_.erase(known);
        name = globalAllocations_.erase(name);
    }

    // globalalloc blocks this run maps. A rollback frees them (with the rest
    // of its allocations) and forgets the name; a success keeps them.
    struct NewGlobalBlock { std::string name; uintptr_t address; std::optional<DisableInfo::AllocEntry> previous; bool wasGlobal; };
    std::vector<NewGlobalBlock> newGlobalBlocks;
    auto rollback = [&]() -> AutoAsmResult {
        if (result.success) return result;
        auto restored = cleanup(proc, result.disableInfo);
        for (const auto& block : newGlobalBlocks) {
            // Not freed: the remaining undo still holds it and frees it later.
            if (std::any_of(restored.disableInfo.allocs.begin(), restored.disableInfo.allocs.end(),
                            [&](const auto& allocation) { return allocation.address == block.address; })) continue;
            if (block.previous && !knownAllocations_.contains(block.name)) knownAllocations_[block.name] = *block.previous;
            if (!block.wasGlobal) globalAllocations_.erase(block.name);
        }
        if (!restored.success) {
            result.error += "\nRollback incomplete: " + restored.error;
            result.disableInfo = std::move(restored.disableInfo);
        } else result.disableInfo = {};
        result.success = false;
        return result;
    };

    try {
    programMachine_ = proc.targetDescription().program;
    targetModules_ = proc.modules();
    codeAllocations_.clear();
    // Process symbols resolve only while this target is being assembled.
    struct SymbolScope {
        AutoAssembler& owner;
        ~SymbolScope() { owner.symbolProcess_ = nullptr; owner.processSymbols_.reset(); owner.hookSites_.clear(); }
    } symbolScope{*this};
    symbolProcess_ = &proc;
    processSymbols_.reset();
    hookSites_.clear();

    // CE tables address memory as "module+offset". Resolve modules from this
    // target snapshot, separate from explicitly registered symbols. Seeding the
    // persistent map kept unloaded/previous-image names and replaced symbol
    // ownership whenever a registered name happened to match a module.

    // A [DISABLE] section names what its [ENABLE] run allocated, labelled and
    // registered ("INJECT: db ...", "stop: dd 1"), as in Cheat Engine. The
    // activation's own values win over a same-named symbol another script
    // registered since.
    std::vector<std::pair<std::string, uintptr_t>> undoNames;
    std::set<std::string> knownNames;
    if (undo) {
        for (const auto& [name, address] : undo->symbols) undoNames.push_back({name, address});
        for (const auto& [name, address] : undo->scriptSymbols) undoNames.push_back({name, address});
        for (const auto& allocation : undo->allocs) undoNames.push_back({allocation.name, allocation.address});
        for (const auto& [name, address] : undoNames) knownNames.insert(name);
    }

    if (!preprocessScript(enableCode, result.log, result.error, knownNames))
        return rollback();

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
            return rollback();
    }
    // After parsing, so the section's own declarations of a name come first.
    for (const auto& undoName : undoNames) {
        const std::string& name = undoName.first;
        const uintptr_t address = undoName.second;
        const bool declared = address == 0 ||
            std::any_of(allocs.begin(), allocs.end(), [&](const Alloc& a) { return a.name == name; }) ||
            std::any_of(labels.begin(), labels.end(), [&](const Label& l) { return l.name == name; }) ||
            std::any_of(defines.begin(), defines.end(), [&](const Define& d) { return d.name == name; });
        if (!declared) defines.push_back({name, formatHexLiteral(address)});
    }

    // ── Phase 2: Allocate memory ──
    for (auto& a : allocs) {
        // alloc() in a [DISABLE] section names the activation's memory, which
        // its undo frees: nothing new is mapped while disabling.
        if (undo && !a.global) {
            auto prior = std::find_if(undo->allocs.begin(), undo->allocs.end(),
                                      [&](const auto& allocation) { return allocation.name == a.name; });
            auto named = undo->scriptSymbols.find(a.name);
            a.address = prior != undo->allocs.end() ? prior->address : named != undo->scriptSymbols.end() ? named->second : 0;
            if (!a.address) {
                result.error = "[DISABLE] can only name memory that [ENABLE] allocated: " + a.name;
                return rollback();
            }
            continue;
        }
        // A globalalloc whose memory already exists (an earlier globalalloc of
        // this name, still registered) shares it.
        if (a.global) {
            auto symbol = globalSymbols_.find(a.name);
            auto known = knownAllocations_.find(a.name);
            // Only memory made by a globalalloc: a plain alloc of the same name
            // (registered by another script) is freed when that script is disabled.
            if (globalAllocations_.contains(a.name) &&
                symbol != globalSymbols_.end() && known != knownAllocations_.end() && known->second.address == symbol->second &&
                known->second.size >= a.size && liveBlock(known->second)) {
                a.address = symbol->second;
                result.log.push_back("GLOBALALLOC: " + a.name + " reuses its existing memory");
                continue;
            }
        }
        // Resolve the optional "near" address now — it may be a symbol defined
        // by an earlier aobscanmodule/aobscan (e.g. alloc(newmem,$1000,INJECT)),
        // which is how AOB code injections keep the cave within jmp range.
        if (!a.preferredExpr.empty()) {
            std::string p = a.preferredExpr;
            if (p.front() == '$') p = "0x" + p.substr(1);
            a.preferred = resolveAddress(p, allocs, labels, defines);
            // A typo here made it "anywhere": a cave out of jump range of the
            // hook, which then fails to assemble or branches wrong.
            if (!a.preferred) {
                result.error = "ALLOC(" + a.name + "): cannot resolve the near address " + a.preferredExpr;
                return rollback();
            }
        }
        // Allocate ownership metadata before asking the target to map memory.
        auto released = std::make_shared<std::atomic<bool>>(false);
        DisableInfo::AllocEntry savedAllocation{a.name,0,a.size,std::move(released),result.disableInfo.ownership,result.disableInfo.image};
        result.disableInfo.allocs.reserve(result.disableInfo.allocs.size() + 1);
        codeAllocations_.reserve(codeAllocations_.size() + 1);
        auto r = result.disableInfo.image ? result.disableInfo.image->allocate(a.size,MemProt::All,a.preferred) : proc.allocate(a.size, MemProt::All, a.preferred);
        if (r) {
            a.address = *r;
            cleanedAllocations_.erase({a.address, a.size});
            codeAllocations_.push_back({a.address, a.size, a.preferred ? machineForCode(a.preferred) : programMachine_});
            size_t mappedSize = a.size;
            if (result.disableInfo.image) {
                const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
                mappedSize += (page - mappedSize % page) % page;
            }
            savedAllocation.address = a.address;
            savedAllocation.size = mappedSize;
            result.disableInfo.allocs.push_back(std::move(savedAllocation));
            // Tracked in the cross-script dealloc(name) namespace so a later script
            // can dealloc(name) it (an intended pattern). The namespace is by name
            // (like CE's global alloc names), so distinct scripts must use distinct
            // names; the address-matched erases below keep disable() from evicting a
            // different script's same-named entry.
            if (a.global) {
                std::optional<DisableInfo::AllocEntry> previous;
                if (auto known = knownAllocations_.find(a.name); known != knownAllocations_.end()) previous = known->second;
                newGlobalBlocks.push_back({a.name, a.address, std::move(previous), globalAllocations_.contains(a.name)});
                globalAllocations_.insert(a.name);
            }
            knownAllocations_[a.name] = result.disableInfo.allocs.back();
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
                                ? " The target is already being traced by THIS program; close any "
                                  "'find what accesses/writes' window and disable breakpoints, then retry."
                                : (" The target is already being traced by PID " + std::to_string(tp) +
                                   "; detach that debugger and retry.");
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
            return rollback();
        }
    }

    std::vector<std::string> selectedAsmLines;
    if (!selectTryExceptBranches(asmLines, selectedAsmLines, allocs, labels, defines, &proc, result.log, result.error))
        return rollback();
    asmLines = std::move(selectedAsmLines);

    std::vector<size_t> reassemblySizes;
    if (!resolveForwardLabels(asmLines, allocs, labels, defines, proc, reassemblySizes, result.error))
        return rollback();

    // ── Phase 3: Assemble and inject ──
    uintptr_t currentAddr = 0;
    std::string currentLabel;
    struct DeferredThread {
        std::string addressExpr;
        bool wait = false;
        int timeoutMs = 5000;
    };
    std::vector<DeferredThread> deferredThreads;
    std::vector<std::string> deferredDeallocs, deferredUnregisters;

    auto allocationRelease = [&](uintptr_t address, size_t size) -> std::shared_ptr<std::atomic<bool>> {
        auto contains = [&](const auto& allocation) {
            return allocation.released && !allocation.released->load() && address >= allocation.address &&
                address - allocation.address <= allocation.size && size <= allocation.size - (address - allocation.address);
        };
        for (const auto& allocation : result.disableInfo.allocs)
            if (contains(allocation)) return allocation.released;
        for (const auto& [name, allocation] : knownAllocations_)
            if (contains(allocation) && (!allocation.image ||
                (allocation.image->pid()==proc.pid() && allocation.image->check()))) return allocation.released;
        return {};
    };

    // Apply one patch: fully read+save the original bytes, then write the
    // new bytes, verifying every step. Saving an original buffer from a
    // failed/partial read would let disable() write a zero-filled buffer
    // back and corrupt the target, and a silently-dropped write would leave
    // execute() reporting success against a patch that never landed.
    // Undo a partial activation: restore patched bytes (reverse order) then free
    // the caves — same as disable(). Called on ANY hard failure during execute so
    // a failed script leaves the target unchanged instead of a half-written cave
    // with an already-live hook (and doesn't leak the allocated RWX pages).
    // What the script saw before it ran: live bytes with the originals of this
    // run's earlier writes laid back over them (the earliest write's original
    // wins). readmem and assert are about the unpatched code: read live after
    // "INJECT: jmp newmem", readmem(INJECT,5) copied the hook itself into the
    // cave and the game jumped to garbage.
    auto readBeforeScript = [&](uintptr_t addr, uint8_t* out, size_t size) -> bool {
        if (size && size - 1 > UINTPTR_MAX - addr) return false;
        auto rr = result.disableInfo.image ? result.disableInfo.image->read(addr, out, size) : proc.read(addr, out, size);
        if (!rr || *rr < size) return false;
        const auto& written = result.disableInfo.originals;
        for (auto it = written.rbegin(); it != written.rend(); ++it) {
            const uintptr_t lo = std::max(addr, it->address);
            const uintptr_t hi = std::min(addr + size, it->address + it->bytes.size());
            for (uintptr_t a = lo; a < hi; ++a) out[a - addr] = it->bytes[a - it->address];
        }
        return true;
    };
    // A globalalloc block is shared code and data that other enabled scripts
    // may use: writes into it are never undone (and a new block that a
    // rollback frees needs no restoring either).
    auto inGlobalBlock = [&](uintptr_t address, size_t size) {
        for (const auto& name : globalAllocations_) {
            auto known = knownAllocations_.find(name);
            if (known != knownAllocations_.end() && liveBlock(known->second) && address >= known->second.address &&
                address - known->second.address < known->second.size &&
                size <= known->second.size - (address - known->second.address)) return true;
        }
        return false;
    };
    auto patchMemory = [&](uintptr_t addr, const std::vector<uint8_t>& bytes, bool mutableData = false) -> bool {
        if (!bytes.empty() && bytes.size() - 1 > UINTPTR_MAX - addr) {
            result.error = "Patch range overflows the address space"; return false;
        }
        auto region = proc.queryRegion(addr);
        const bool executable=region && (region->protection & MemProt::Exec);
        if (!inGlobalBlock(addr, bytes.size())) {
            std::vector<uint8_t> orig(bytes.size());
            auto rr = result.disableInfo.image ? result.disableInfo.image->read(addr,orig.data(),orig.size()) : proc.read(addr, orig.data(), orig.size());
            if (!rr || *rr < orig.size()) {
                result.error = "original-byte read failed at " + formatHexLiteral(addr);
                return false;
            }
            result.disableInfo.originals.push_back({addr, std::move(orig),bytes,executable,allocationRelease(addr,bytes.size()),executable && !mutableData});
        }
        auto writeBytes=[&] {return result.disableInfo.image ? result.disableInfo.image->write(addr,bytes,executable) : executable ? proc.writeCode(addr,bytes.data(),bytes.size()) : proc.write(addr,bytes.data(),bytes.size());};
        auto wr = writeBytes();
        // A running injected thread owns its cave, so the pinned image refuses
        // writes there. A data value such as the stop flag it polls is written
        // directly, while that image is still the live address space.
        if (!wr && wr.error() == std::errc::device_or_resource_busy && mutableData && result.disableInfo.image &&
            result.disableInfo.image->check())
            wr = proc.write(addr, bytes.data(), bytes.size());
        if (!wr || *wr < bytes.size()) {
            if (executable && !machineForCode(addr).isX86()) {
                result.error="Code write failed: "+(wr ? std::string("short transfer") : wr.error().message());
                return false;
            }
            // The target page may be non-writable (e.g. r-x code). Code
            // injection has to patch executable pages, so make the range
            // writable and retry — mirrors CE making the region writable
            // before applying a hook.
            uintptr_t at = addr;
            size_t remaining = bytes.size();
            while (remaining) {
                auto region = proc.queryRegion(at);
                if (!region || at < region->base || at - region->base >= region->size) {
                    result.error = "Cannot inspect original page protection"; return false;
                }
                size_t count = std::min(remaining, region->size - (at - region->base));
                result.disableInfo.protections.push_back({at, count, region->protection,allocationRelease(at,count)});
                auto protectedRange = result.disableInfo.image ? result.disableInfo.image->protect(at,count,region->protection|MemProt::Write) : proc.protect(at, count, region->protection | MemProt::Write);
                if (!protectedRange) { result.error = protectedRange.error().message(); return false; }
                at += count; remaining -= count;
            }
            wr = writeBytes();
            if (!wr || *wr < bytes.size()) {
                result.error = "memory write failed at " + formatHexLiteral(addr);
                return false;
            }
        }
        return true;
    };

    for (size_t lineIndex=0;lineIndex<asmLines.size();++lineIndex) {
        const auto& rawLine=asmLines[lineIndex];
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
                        return rollback();
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
                return rollback();
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
                return rollback();
            }

            auto addrExpr = trim(args.substr(0, comma));
            auto sizeStr = trim(args.substr(comma + 1));
            auto addr = resolveAddress(addrExpr, allocs, labels, defines);
            size_t size = 0;
            try {
                size = std::stoull(sizeStr, nullptr, 0);
            } catch (...) {
                result.error = "Invalid FULLACCESS size: " + sizeStr;
                return rollback();
            }

            if (!addr || size == 0) {
                result.error = "Invalid FULLACCESS target: " + addrExpr;
                return rollback();
            }

            if (size - 1 > UINTPTR_MAX - addr) {
                result.error = "FULLACCESS range overflows the address space";
                return rollback();
            }
            uintptr_t at = addr;
            size_t remaining = size;
            while (remaining) {
                auto region = proc.queryRegion(at);
                if (!region || at < region->base || at - region->base >= region->size) {
                    result.error = "Cannot inspect FULLACCESS page protection";
                    return rollback();
                }
                size_t count = std::min(remaining, region->size - (at - region->base));
                result.disableInfo.protections.push_back({at, count, region->protection,allocationRelease(at,count)});
                auto protectResult = result.disableInfo.image ? result.disableInfo.image->protect(at,count,MemProt::All) : proc.protect(at, count, MemProt::All);
                if (!protectResult) {
                    result.error = "FULLACCESS failed at " + addrExpr + ": " + protectResult.error().message();
                    return rollback();
                }
                remaining -= count;
                if (remaining) at += count;
            }
            result.log.push_back("FULLACCESS: " + addrExpr + " size=" + std::to_string(size));
            continue;
        }
        if (startsWith(trimmedLine, "__ASSERT__:")) {
            auto args = trimmedLine.substr(11);
            auto comma = args.find(',');
            if (comma == std::string::npos) {
                result.error = "ASSERT requires address and bytes";
                return rollback();
            }

            auto addrExpr = trim(args.substr(0, comma));
            auto bytesStr = trim(args.substr(comma + 1));
            auto addr = resolveAddress(addrExpr, allocs, labels, defines);
            if (!addr) {
                result.error = "Invalid ASSERT target: " + addrExpr;
                return rollback();
            }

            // CE's templates write assert(address,bytes) after define(bytes,...).
            for (int depth = 0; depth < 8; ++depth) {
                auto named = std::find_if(defines.begin(), defines.end(), [&](const Define& d) { return d.name == bytesStr; });
                if (named == defines.end()) break;
                bytesStr = trim(named->value);
            }
            if (!bytesStr.empty() && bytesStr.front() == '"') bytesStr = bytesStr.substr(1);
            if (!bytesStr.empty() && bytesStr.back() == '"') bytesStr.pop_back();

            ScanConfig pattern;
            if (!pattern.parseAOB(bytesStr) || pattern.byteArray.empty()) {
                result.error = "ASSERT has no valid bytes: " + bytesStr;
                return rollback();
            }

            std::vector<uint8_t> current(pattern.byteArray.size());
            if (!readBeforeScript(addr, current.data(), current.size())) {   // the code before this script's writes
                result.error = "ASSERT read failed at " + addrExpr;
                return rollback();
            }

            for (size_t i = 0; i < pattern.byteArray.size(); ++i) {
                // Wildcards and half wildcards ("4?") compare only their mask.
                const uint8_t mask = i < pattern.byteArrayMask.size() ? pattern.byteArrayMask[i] : 0xFF;
                if ((current[i] & mask) != (pattern.byteArray[i] & mask)) {
                    char expected[8];
                    char actual[8];
                    snprintf(expected, sizeof(expected), "%02x", pattern.byteArray[i]);
                    snprintf(actual, sizeof(actual), "%02x", current[i]);
                    result.error = "ASSERT failed at " + addrExpr + "+" + std::to_string(i) +
                        ": expected " + expected + ", got " + actual;
                    return rollback();
                }
            }

            result.log.push_back("ASSERT OK: " + addrExpr);
            continue;
        }
        // unregistersymbol and dealloc take effect once every other line has
        // succeeded, as in Cheat Engine: a script that fails later rolls back
        // with its memory and symbols still in place.
        if (startsWith(trimmedLine, "__UNREGISTERSYMBOL__:")) {
            std::istringstream symbolStream(trimmedLine.substr(21));
            for (std::string name; std::getline(symbolStream, name, ',');)
                if (!trim(name).empty()) deferredUnregisters.push_back(trim(name));
            continue;
        }
        if (startsWith(trimmedLine, "__DEALLOC__:")) {
            std::istringstream allocStream(trimmedLine.substr(12));
            for (std::string name; std::getline(allocStream, name, ',');) {
                name = trim(name);
                if (name.empty()) continue;
                // While disabling, dealloc names only the activation's own
                // memory (Cheat Engine looks it up in the undo), which the
                // undo frees after restoring: another script's block of the
                // same name ("newmem" in every template) is left alone.
                if (!undo) deferredDeallocs.push_back(name);
                else if (std::any_of(undo->allocs.begin(), undo->allocs.end(), [&](const auto& a) { return a.name == name; }))
                    result.log.push_back("DEALLOC: " + name + " (freed with the script's undo)");
                else result.log.push_back("DEALLOC: " + name + " not tracked");
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
                return rollback();
            }

            int timeoutMs = 5000;
            if (parts.size() > 1 && !parts[1].empty()) {
                try {
                    timeoutMs = std::stoi(parts[1], nullptr, 0);
                } catch (...) {
                    result.error = "Invalid CREATETHREADANDWAIT timeout: " + parts[1];
                    return rollback();
                }
            }
            deferredThreads.push_back({trim(parts[0]), true, timeoutMs});
            result.log.push_back("Deferred: " + trimmedLine);
            continue;
        }

        if (startsWith(trimmedLine, "__LOADBINARY__:")) {
            // parseLine refuses it already; this keeps the step itself safe.
            if (restricted_) { result.error = restrictedError("LOADBINARY"); return rollback(); }
            auto args = trimmedLine.substr(15);
            auto parts = splitArgs(args, 2);
            if (parts.size() != 2) {
                result.error = "LOADBINARY requires address and filename";
                return rollback();
            }

            auto addrExpr = trim(parts[0]);
            auto filename = stripOptionalQuotes(parts[1]);
            auto addr = resolveAddress(addrExpr, allocs, labels, defines);
            if (!addr) {
                result.error = "Invalid LOADBINARY target: " + addrExpr;
                return rollback();
            }

            std::error_code sizeError;
            if (!std::filesystem::is_regular_file(filename, sizeError) ||
                std::filesystem::file_size(filename, sizeError) > kMaxAaBufferBytes || sizeError) {
                result.error = "LOADBINARY needs a regular file of at most 256 MB: " + filename;
                return rollback();
            }
            std::ifstream binFile(filename, std::ios::binary);
            if (!binFile) {
                result.error = "LOADBINARY file not found: " + filename;
                return rollback();
            }

            std::vector<uint8_t> data((std::istreambuf_iterator<char>(binFile)), {});
            if (data.empty()) {
                result.error = "LOADBINARY file is empty: " + filename;
                return rollback();
            }

            if (!patchMemory(addr,data)) return rollback();

            result.log.push_back("LOADBINARY: " + filename + " -> " + addrExpr);
            continue;
        }

        if (startsWith(trimmedLine, "__LOADLIBRARY__:")) {
            if (restricted_) { result.error = restrictedError("LOADLIBRARY"); return rollback(); }
            auto path = stripOptionalQuotes(trimmedLine.substr(16));
            if (path.empty()) {
                result.error = "LOADLIBRARY requires a shared library path";
                return rollback();
            }
            if (!std::filesystem::exists(path)) {
                result.error = "LOADLIBRARY file not found: " + path;
                return rollback();
            }
            // dlopen runs in the target, with its own working directory and
            // possibly another mount namespace: pass the name it sees this file by.
            std::error_code absoluteError;
            auto targetPath = std::filesystem::absolute(path, absoluteError).lexically_normal().string();
            if (absoluteError) targetPath = path;
            if (proc.targetDescription().transport == TargetTransport::Local)
                if (auto task = os::processMemoryTask(proc.pid())) targetPath = os::targetVisiblePath(*task, targetPath);

            SymbolResolver resolver;
            resolver.loadProcess(proc);
            auto injectResult = os::injectLibrary(proc, resolver, targetPath,result.disableInfo.image);
            if (!injectResult) {
                result.error = "LOADLIBRARY failed for " + path + ": " + injectResult.error();
                return rollback();
            }

            result.log.push_back("LOADLIBRARY: " + path + " handle=0x" + formatHex(*injectResult));
            continue;
        }

        if (currentAddr == 0 && !startsWith(trimmedLine, "__FILLMEM__:")) {   // fillmem names its own address
            result.error = "No active assembly address for line: " + trimmedLine;
            return rollback();
        }
        if (startsWith(trimmedLine, "__REASSEMBLE__:")) {
            auto addrExpr = trimmedLine.substr(15);
            auto addr = resolveAddress(addrExpr, allocs, labels, defines);
            if (!addr) {result.error="Invalid REASSEMBLE target: "+addrExpr;return rollback();}
            auto relocated=reassembleTarget(proc,addr,currentAddr,&result.disableInfo.originals);
            if (!relocated || relocated->empty()) {
                result.error="REASSEMBLE failed at "+addrExpr+": "+(relocated ? "empty instruction" : relocated.error());
                return rollback();
            }
            // A source instruction may change after sizing, including through
            // an earlier write in this script. Already emitted forward label
            // references would point at the wrong instruction if the size changes.
            if (relocated->size()!=reassemblySizes[lineIndex]) {
                result.error="REASSEMBLE output size changed after label sizing at "+addrExpr;
                return rollback();
            }
            if (!patchMemory(currentAddr,*relocated)) return rollback();
            currentAddr+=relocated->size();
            continue;
        }
        if (startsWith(trimmedLine, "__READMEM__:")) {
            auto args = trimmedLine.substr(12);
            auto comma = args.find(',');
            if (comma != std::string::npos) {
                auto addrExpr = trim(args.substr(0, comma));
                auto sizeStr = trim(args.substr(comma + 1));
                auto addr = resolveAddress(addrExpr, allocs, labels, defines);
                // The sizing pass always advances by the READMEM size, so an
                // unresolved source here would place every later instruction at
                // the wrong address. Fail loudly instead of silently skipping.
                if (!addr) {
                    result.error = "READMEM source address unresolved: " + addrExpr;
                    return rollback();
                }
                // Parse the size identically to the forward-label sizing pass
                // (base-0, so CE-style 0x.. hex sizes are honored); otherwise
                // the two passes disagree and later code lands at a wrong
                // address.
                uint64_t sz = 0;
                if (!parseWholeUnsigned(sizeStr, 0, sz)) {
                    result.error = "Invalid READMEM size: " + sizeStr;
                    return rollback();
                }
                if (sz > kMaxAaBufferBytes) {
                    result.error = "READMEM size too large: " + sizeStr;
                    return rollback();
                }
                if (sz > 0) {
                    std::vector<uint8_t> mem(sz);
                    if (!readBeforeScript(addr, mem.data(), sz)) {
                        result.error = "READMEM source read failed at " + addrExpr;
                        return rollback();
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
                return rollback();
            }

            auto addr = resolveAddress(parts[0], allocs, labels, defines);
            size_t size = 0;
            uint64_t value = 0;
            try {
                size = std::stoull(trim(parts[1]), nullptr, 0);
                value = std::stoull(trim(parts[2]), nullptr, 16);
            } catch (...) {
                result.error = "Invalid FILLMEM argument";
                return rollback();
            }
            if (!addr || size == 0 || value > 0xff) {
                result.error = "Invalid FILLMEM target or value";
                return rollback();
            }
            if (size > kMaxAaBufferBytes) {
                result.error = "FILLMEM size too large";
                return rollback();
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
                return rollback();

            auto plan=planNops(currentAddr,count);
            if (!plan) {result.error=plan.error();return rollback();}
            std::vector<uint8_t> data(plan->size);
            for (size_t at=0;at<data.size();at+=plan->encoding.size())
                std::copy(plan->encoding.begin(),plan->encoding.end(),data.begin()+at);
            if (!patchMemory(currentAddr, data))
                return rollback();
            currentAddr += data.size();
            continue;
        }
        if (startsWith(trimmedLine, "__DS__:")) {
            auto text = stripOptionalQuotes(trimmedLine.substr(7));
            if (text.empty()) {
                result.error = "DS requires a string";
                return rollback();
            }

            std::vector<uint8_t> data(text.begin(), text.end());
            if (!patchMemory(currentAddr, data,true))
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
            if (!parseDataDirective(op, dataStr, dataBytes, parseError, machineForCode(currentAddr).byteOrder)) {
                result.error = parseError;
                return rollback();
            }

            if (!dataBytes.empty()) {
                // Typed storage and byte buffers inside owned caves can change
                // at runtime (for example, a pointer-capture slot). Raw DB at
                // an external executable site also serves as machine code.
                const bool mutableData = op != "DB" || bool(allocationRelease(currentAddr,dataBytes.size()));
                if (!patchMemory(currentAddr, dataBytes,mutableData))
                    return rollback();
                currentAddr += dataBytes.size();
            }
            continue;
        }

        // Substitute symbols in assembly line
        auto substituted = substituteSymbols(trimmedLine, allocs, labels, defines);

        // Assemble
        auto asmResult = assembleTarget(substituted, currentAddr);
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

    if (!deferredThreads.empty() && restricted_) {
        result.error = restrictedError("CREATETHREAD");
        return rollback();
    }
    if (!deferredThreads.empty()) {
        SymbolResolver resolver;
        resolver.loadProcess(proc);

        for (const auto& thread : deferredThreads) {
            auto addr = resolveAddress(thread.addressExpr, allocs, labels, defines);
            if (!addr) {
                result.error = "Invalid CREATETHREAD target: " + thread.addressExpr;
                return rollback();
            }

            std::vector<os::NativeThreadRange> storage;
            for (const auto& allocation : result.disableInfo.allocs) storage.push_back({allocation.address,allocation.size});
            for (const auto& patch : result.disableInfo.originals) if (!patch.bytes.empty()) storage.push_back({patch.address,patch.bytes.size()});
            for (const auto& protection : result.disableInfo.protections) if (protection.size) storage.push_back({protection.address,protection.size});
            auto stackReleased = std::make_shared<std::atomic<bool>>(false);
            result.disableInfo.allocs.reserve(result.disableInfo.allocs.size()+1);
            auto threadResult = os::createRemoteThread(proc, resolver, addr, thread.wait, thread.timeoutMs,storage,result.disableInfo.image);
            if (!threadResult) {
                result.error = "CREATETHREAD failed for " + thread.addressExpr + ": " + threadResult.error();
                return rollback();
            }

            auto info = *threadResult;
            if (info.stackAddress)
                result.disableInfo.allocs.push_back({
                    "__threadstack_" + std::to_string(info.tid), info.stackAddress, info.stackSize,
                    std::move(stackReleased),result.disableInfo.ownership,result.disableInfo.image});

            result.log.push_back(std::string(thread.wait ? "CREATETHREADANDWAIT" : "CREATETHREAD") +
                ": " + thread.addressExpr + " handle=0x" + formatHex(info.handle));

            if (thread.wait && !info.completed) {
                result.error = "CREATETHREADANDWAIT timed out for " + thread.addressExpr;
                return rollback();
            }
        }
    }

    for (const auto& name : deferredDeallocs) {
        auto it = knownAllocations_.find(name);
        if (it == knownAllocations_.end()) {
            result.log.push_back("DEALLOC: " + name + " not tracked");
            continue;
        }
        if (it->second.image && it->second.image->pid()!=proc.pid()) {
            result.error="DEALLOC belongs to another process: "+name;
            return rollback();
        }

        std::unique_lock<std::mutex> allocationOwner;
        if(it->second.owner) {
            allocationOwner=std::unique_lock(it->second.owner->mutex,std::try_to_lock);
            if(!allocationOwner.owns_lock()) {result.error="Allocation cleanup is already in progress";return rollback();}
        }
        auto live = it->second.image ? it->second.image->check() : Result<void>{};
        auto freeResult = !live && live.error()==std::errc::operation_canceled ? Result<void>{}
            : !live ? live : it->second.image ? it->second.image->free(it->second.address,it->second.size) : proc.free(it->second.address,it->second.size);
        if (!freeResult) {
            result.error = "DEALLOC failed for " + name + ": " + freeResult.error().message();
            if (allocationOwner.owns_lock()) allocationOwner.unlock();
            return rollback();
        }

        // Keep the released lease in saved undo records. Its byte and
        // protection records must never follow address reuse.
        result.log.push_back("DEALLOC: " + name);
        if(it->second.released) it->second.released->store(true);
        knownAllocations_.erase(it);
        globalAllocations_.erase(name);   // a dealloc ends a globalalloc too
    }
    for (const auto& name : deferredUnregisters) {
        // While disabling, the activation's own symbols go with its undo,
        // which keeps a name another script registered since.
        if (undo && undo->symbols.contains(name)) continue;
        globalSymbols_.erase(name);
        symbolOwners_.erase(name);
        result.log.push_back("UNREGISTERSYMBOL: " + name);
    }

    // ── Phase 4: Register symbols ──
    // globalalloc names are shared and outlive any one script: no owner, and
    // not part of this script's undo.
    for (const auto& a : allocs)
        if (a.global && a.address) { globalSymbols_[a.name] = a.address; symbolOwners_.erase(a.name); }
    for (auto& sym : registeredSymbols) {
        uintptr_t addr = resolveAddress(sym, allocs, labels, defines);
        if (!addr) continue;
        globalSymbols_[sym] = addr;
        if (undo) { symbolOwners_.erase(sym); continue; }   // registered by a [DISABLE] section: no undo removes it
        symbolOwners_[sym]=result.disableInfo.ownership;
        result.disableInfo.symbols[sym] = addr;
    }

    // New globalalloc blocks stay mapped when this script is disabled.
    std::erase_if(result.disableInfo.allocs, [&](const auto& allocation) {
        return std::any_of(newGlobalBlocks.begin(), newGlobalBlocks.end(),
                           [&](const NewGlobalBlock& block) { return block.address == allocation.address; });
    });
    if (!undo) {
        result.disableInfo.runDisableSection = true;
        for (const auto& a : allocs) if (a.address) result.disableInfo.scriptSymbols[a.name] = a.address;
        for (const auto& l : labels)
            if (l.address && !startsWith(l.name, "__anon_")) result.disableInfo.scriptSymbols[l.name] = l.address;
        // [DISABLE] restores the function [ENABLE] hooked, by the same address.
        for (const auto& [name, address] : hookSites_) result.disableInfo.scriptSymbols.emplace(name, address);
        if (!result.disableInfo.originals.empty()) {
            LivePatch live{result.disableInfo.ownership, result.disableInfo.image, proc.pid(), {}};
            for (const auto& patch : result.disableInfo.originals)
                if (!patch.bytes.empty()) live.ranges.push_back({patch.address, patch.bytes.size()});
            std::erase_if(livePatches_, [](const LivePatch& entry) { auto owner = entry.owner.lock(); return !owner || owner->complete; });
            livePatches_.push_back(std::move(live));
        }
    }

    result.success = result.error.empty();
    return rollback();
    } catch (const std::exception& error) {
        result.success = false;
        result.error = std::string("AutoAssembler failed: ")+error.what();
        return rollback();
    }
}

// Whether the script has a [name] section header.
static bool hasSection(const std::string& script, const std::string& name) {
    const auto tag = toUpper("[" + name + "]");
    std::istringstream ss(stripBraceComments(script));
    for (std::string line; std::getline(ss, line);)
        if (sectionHeader(line) == tag) return true;
    return false;
}

std::expected<void, std::string> AutoAssembler::runDisableSection(ProcessHandle& proc, const std::string& script,
    const DisableInfo& info, DisableInfo& saved, std::vector<std::string>& log, std::string& sectionError) {
    // Nothing to run, or nothing it may touch: an undo already completed, or
    // an address space that is gone (cleanup discards that undo unwritten).
    if (script.empty() || !hasSection(script, "DISABLE")) return {};
    if (info.ownership && info.ownership->complete) return {};
    if (info.image && (info.image->pid() != proc.pid() || !info.image->check())) return {};
    // Code that another script hooked over since is refused before the section
    // writes the original bytes back over that hook, as the restore refuses it.
    {
        bool dropped = false;
        auto view = withoutUnmapped(proc, info, dropped);
        if (info.ownership) {
            std::lock_guard lock(info.ownership->mutex);
            for (const auto& [address, bytes] : info.ownership->restoreOverrides) overrideOriginals(view.originals, address, bytes);
        }
        if (auto conflict = codeOwnershipConflict(proc, view); !conflict.empty()) return std::unexpected(conflict);
    }
    auto section = run(proc, extractSection(script, "DISABLE"), &info);
    log.insert(log.end(), section.log.begin(), section.log.end());
    if (!section.success) {
        const auto& left = section.disableInfo;
        if (!left.originals.empty() || !left.allocs.empty() || !left.protections.empty())
            return std::unexpected("[DISABLE] failed and its own writes could not be undone: " + section.error);
        // Its writes are undone; the saved bytes still restore the script.
        log.push_back("[DISABLE] failed, restoring the saved bytes instead: " + section.error);
        sectionError = section.error;
        return {};
    }
    // What the section wrote is what the script leaves behind: the restore
    // keeps it where it overlaps saved originals ("INJECT: db <original
    // bytes>" restores exactly; "dd 0" over a patched value stays 0).
    for (const auto& write : section.disableInfo.originals) {
        if (!info.ownership) { overrideOriginals(saved.originals, write.address, write.written); continue; }
        std::lock_guard lock(info.ownership->mutex);
        info.ownership->restoreOverrides.emplace_back(write.address, write.written);
    }
    // A section that stops an injected thread ("stop: dd 1") gives it a moment
    // to leave the memory the undo frees.
    auto running = [&] {
        for (const auto& allocation : info.allocs)
            if ((!allocation.released || !allocation.released->load()) &&
                os::memorySyscallService().threadStorageBusy(proc.pid(), allocation.address, allocation.size)) return true;
        return false;
    };
    for (int wait = 0; wait < 100 && running(); ++wait) std::this_thread::sleep_for(std::chrono::milliseconds(20));
    return {};
}

AutoAsmResult AutoAssembler::disable(ProcessHandle& proc, const std::string& script, const DisableInfo& info) {
    // As in Cheat Engine, the [DISABLE] section runs as a script first, while
    // the script's allocations and symbols still exist: its conditionals, Lua
    // ({$lua} that stops a timer) and writes ("INJECT: db <original bytes>",
    // a stop flag for an injected thread). The saved undo then restores what
    // the section did not write, frees the allocations and drops the symbols.
    // It runs once: a retried cleanup only restores.
    std::vector<std::string> log;
    std::string sectionError;
    DisableInfo saved = info;
    saved.runDisableSection = false;
    if (info.runDisableSection) {
        if (auto ran = runDisableSection(proc, script, info, saved, log, sectionError); !ran) {
            AutoAsmResult failed;
            failed.error = ran.error();
            failed.disableInfo = info;
            failed.log = std::move(log);
            return failed;
        }
    }
    auto result = cleanup(proc, saved);
    result.log.insert(result.log.begin(), log.begin(), log.end());
    result.disableSectionError = std::move(sectionError);
    return result;
}

AutoAsmResult AutoAssembler::check(const std::string& script) {
    programMachine_ = nativeTargetMachine();
    targetModules_.clear(); codeAllocations_.clear();
    // A check never runs code: {$lua} blocks expand to nothing and {$if}
    // conditions are not evaluated (a script under review may be untrusted).
    struct RestoreEvaluator {
        LuaEvaluator& slot;
        LuaEvaluator saved;
        ~RestoreEvaluator() { slot = std::move(saved); }
    } restore{luaEvaluator_, std::move(luaEvaluator_)};
    if (restore.saved)
        luaEvaluator_ = [](const std::string&) -> std::expected<std::string, std::string> { return std::string(); };
    else
        luaEvaluator_ = nullptr;
    AutoAsmResult result;
    // An untrusted script runs nothing on this computer, in either section:
    // the [DISABLE] Lua of a saved record would run later, unrestricted.
    if (restricted_) {
        const auto stripped = stripBraceComments(script);
        for (size_t at = findDirective(stripped, 0); at != std::string::npos; at = findDirective(stripped, at + 2)) {
            size_t end = at + 2;
            while (end < stripped.size() && std::isalpha(static_cast<unsigned char>(stripped[end]))) ++end;
            const auto name = toUpper(stripped.substr(at + 2, end - at - 2));
            if (name == "LUA" || name == "CCODE" || name == "IF") {
                auto lower = name;
                for (auto& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                result.error = "{$" + lower + "} is not allowed in this script: it would run code on this computer";
                return result;
            }
        }
    }
    // Parse without a process — syntax check only
    std::vector<Alloc> allocs;
    std::vector<Label> labels;
    std::vector<Define> defines;
    std::vector<std::string> registeredSymbols;
    std::vector<std::string> asmLines;
    auto validate = [&](std::string code) {
        allocs.clear(); labels.clear(); defines.clear(); registeredSymbols.clear(); asmLines.clear();
        if (!preprocessScript(code, result.log, result.error))
            return false;
        std::istringstream ss(code);
        std::string line;
        while (std::getline(ss, line)) {
            if (!parseLine(line, allocs, labels, defines, registeredSymbols, asmLines, result.log, nullptr, result.error))
                return false;
        }
        std::vector<std::string> selectedAsmLines;
        if (!selectTryExceptBranches(asmLines, selectedAsmLines, allocs, labels, defines, nullptr, result.log, result.error))
            return false;
        asmLines = std::move(selectedAsmLines);
        return true;
    };
    // The [DISABLE] section of an untrusted script is held to the same
    // restrictions, since disabling runs it.
    if (restricted_ && hasSection(script, "DISABLE") && !validate(extractSection(script, "DISABLE"))) {
        result.error = "[DISABLE]: " + result.error;
        return result;
    }
    auto enableCode = extractSection(script, "ENABLE");
    if (!hasSectionHeaders(stripBraceComments(script))) enableCode = script;
    if (!validate(std::move(enableCode)))
        return result;

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
        // C source can #include any file here, and a compile error quotes it.
        if (restricted_) { error = restrictedError("{$ccode}"); return false; }
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
        error = "{$ccode} blocks require the TinyCC bridge; rebuild with libtcc-dev installed";
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
            // The end of the section closes a Lua block (see preprocessScript).
            closePos = code.size();
            closeLen = 0;
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
// `{$if expression}` selects one branch using Lua truthiness before converting
// the result to text. Blocks are processed in
// source order, so discarded branches never execute embedded Lua or C code.
bool AutoAssembler::expandConditionalBlocks(std::string& code,
                                            std::vector<std::string>& log,
                                            std::string& error) {
    struct Branch { bool parent; bool taken; bool seenElse = false; };
    std::vector<Branch> stack;
    bool active = true;
    std::string output;
    size_t position = 0;
    auto findCi = [&](const std::string& token, size_t start) {
        for (size_t i = start; i + token.size() <= code.size(); ++i) {
            if (toUpper(code.substr(i, token.size())) == token) return i;
        }
        return std::string::npos;
    };
    while (position < code.size()) {
        auto open = findDirective(code, position);
        if (open == std::string::npos) {
            if (active) output.append(code, position, std::string::npos);
            break;
        }
        if (active) output.append(code, position, open - position);
        // Skip Lua strings and comments when locating the directive's final brace.
        auto longStringEnd = [&](size_t start) -> std::optional<size_t> {
            if (start >= code.size() || code[start] != '[') return std::nullopt;
            size_t end = start + 1;
            while (end < code.size() && code[end] == '=') ++end;
            if (end >= code.size() || code[end] != '[') return std::nullopt;
            auto marker = "]" + std::string(end - start - 1, '=') + "]";
            auto finish = code.find(marker, end + 1);
            return finish == std::string::npos ? code.size() : finish + marker.size() - 1;
        };
        size_t close = open + 2;
        unsigned braces = 0;
        char quote = 0;
        for (; close < code.size(); ++close) {
            char c = code[close];
            if (quote) {
                if (c == '\\') { ++close; continue; }
                if (c == quote) quote = 0;
                continue;
            }
            if (c == '\'' || c == '"') { quote = c; continue; }
            if (c == '-' && close + 1 < code.size() && code[close + 1] == '-') {
                if (auto end = longStringEnd(close + 2)) close = *end;
                else close = code.find('\n', close + 2);
                if (close >= code.size()) break;
                continue;
            }
            if (auto end = longStringEnd(close)) { close = *end; if (close >= code.size()) break; continue; }
            if (c == '{') ++braces;
            else if (c == '}') {
                if (!braces) break;
                --braces;
            }
        }
        if (close >= code.size()) { error = "Preprocessor token has no closing brace"; return false; }
        auto directive = trim(code.substr(open + 2, close - open - 2));
        auto upper = toUpper(directive);
        if (upper == "LUA" || upper == "CCODE") {
            auto terminator = upper == "LUA" ? "{$ASM}" : "{$ENDCCODE}";
            size_t end = findCi(terminator, close + 1);
            size_t endLength = std::strlen(terminator);
            if (upper == "LUA") {
                auto alternate = findCi("{$ENDLUA}", close + 1);
                if (alternate < end) { end = alternate; endLength = 9; }
            }
            // A Lua block may run to the end of its section, as in the common
            // pure-Lua record ("[ENABLE] {$lua} ... [DISABLE] {$lua} ..."): the
            // section's end closes it.
            if (end == std::string::npos && upper == "LUA") { end = code.size(); endLength = 0; }
            if (end == std::string::npos) { error = "{$" + directive + "} block has no matching terminator"; return false; }
            if (active) {
                auto expanded = std::string(upper == "LUA" ? "{$lua}" : "{$ccode}") +
                    code.substr(close + 1, end - close - 1) + (upper == "LUA" ? "{$asm}" : "{$endccode}");
                if (!expandLuaBlocks(expanded, log, error)) return false;
                // Reprocess generated text so generated conditionals work too.
                code.replace(open, end + endLength - open, expanded);
                position = open;
            } else position = end + endLength;
            continue;
        }
        if (upper == "IF" || (upper.starts_with("IF") && upper.size() > 2 && std::isspace(static_cast<unsigned char>(upper[2])))) {
            auto expression = trim(directive.substr(2));
            if (expression.empty()) { error = "{$if has no expression"; return false; }
            bool taken = false;
            if (active) {
                if (!luaEvaluator_) { error = "{$if requires a Lua evaluator on this AutoAssembler"; return false; }
                auto result = luaEvaluator_("return (" + expression + ") and 'true' or 'false'");
                if (!result) { error = "{$if condition error: " + result.error(); return false; }
                taken = *result == "true";
                log.push_back(std::string("{$if}: ") + (taken ? "true" : "false") + " branch kept");
            }
            stack.push_back({active, taken});
            active = active && taken;
        } else if (upper == "ELSE") {
            if (stack.empty() || stack.back().seenElse) { error = "Unexpected or duplicate {$else}"; return false; }
            auto& branch = stack.back(); branch.seenElse = true;
            active = branch.parent && !branch.taken;
        } else if (upper == "ENDIF") {
            if (stack.empty()) { error = "Unexpected {$endif}"; return false; }
            active = stack.back().parent; stack.pop_back();
        } else if (upper.starts_with("IF")) {
            error = "Unrecognized preprocessor token starting at '{$if'"; return false;
        } else if (active) output.append(code, open, close + 1 - open);
        position = close + 1;
    }
    if (!stack.empty()) { error = "{$if has no matching {$endif}"; return false; }
    code = std::move(output);
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
