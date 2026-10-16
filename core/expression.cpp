#include "core/expression.hpp"
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <string_view>

namespace ce {

static std::string trim(const std::string& s) {
    auto a = s.find_first_not_of(" \t");
    auto b = s.find_last_not_of(" \t");
    return a == std::string::npos ? "" : s.substr(a, b - a + 1);
}

// Module names compare without case, as in Cheat Engine: a table made on
// Windows says "KERNEL32.DLL" where Wine maps kernel32.dll.
static bool sameNameIgnoringCase(std::string_view a, std::string_view b) {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](unsigned char x, unsigned char y) {
        return std::tolower(x) == std::tolower(y);
    });
}

const std::vector<ModuleInfo>& ExpressionParser::modules() const {
    if (!modules_) modules_ = proc_ ? proc_->modules() : std::vector<ModuleInfo>{};
    return *modules_;
}

// The base of the module named `name`: an exact match first, then one that
// differs only in case.
static std::optional<uintptr_t> moduleBase(const std::vector<ModuleInfo>& modules, const std::string& name) {
    for (const auto& m : modules) if (m.name == name) return m.base;
    for (const auto& m : modules) if (sameNameIgnoringCase(m.name, name)) return m.base;
    return std::nullopt;
}

std::optional<uintptr_t> ExpressionParser::resolveToken(const std::string& token) const {
    if (token.empty()) return std::nullopt;
    if (token.size() >= 2 && (token.front() == '"' || token.front() == '\'') && token.back() == token.front()) {
        auto name = token.substr(1, token.size() - 2);
        if (resolver_) {
            if (auto address = resolver_->lookup(name)) return address;
        }
        if (proc_) return moduleBase(modules(), name);
        return std::nullopt;
    }

    auto number = [](const std::string& text, int base) -> std::optional<uintptr_t> {
        if (text.empty()) return std::nullopt;
        const bool valid = std::all_of(text.begin(), text.end(), [base](unsigned char c) {
            return base == 16 ? std::isxdigit(c) : std::isdigit(c);
        });
        if (!valid) return std::nullopt;
        try {
            auto value = std::stoull(text, nullptr, base);
            if (value > UINTPTR_MAX) return std::nullopt;
            return static_cast<uintptr_t>(value);
        } catch (...) { return std::nullopt; }
    };

    if (token.size() >= 2 && token[0] == '0' && (token[1] == 'x' || token[1] == 'X'))
        return number(token.substr(2), 16);
    if (token[0] == '#') return number(token.substr(1), 10);

    const bool allHex = std::all_of(token.begin(), token.end(),
        [](unsigned char c) { return std::isxdigit(c); });
    const bool allDigit = std::all_of(token.begin(), token.end(),
        [](unsigned char c) { return std::isdigit(c); });
    if (allHex && (token.size() >= 2 || allDigit)) return number(token, 16);

    if (resolver_) {
        auto addr = resolver_->lookup(token);
        if (addr) return addr;
    }
    if (proc_) {
        if (auto base = moduleBase(modules(), token)) return base;
    }
    // A lone hex letter remains symbol-first for CE compatibility.
    if (allHex) return number(token, 16);
    return std::nullopt;
}

std::optional<uintptr_t> ExpressionParser::parse(const std::string& expr) const {
    return parseImpl(expr, 0);
}

std::optional<uintptr_t> ExpressionParser::parseImpl(const std::string& expr, int depth) const {
    // Cap recursion to defend against adversarial nesting (e.g. "[[[[...]]]]"
    // or long "+" chains) that would otherwise exhaust the stack.
    static constexpr int kMaxDepth = 64;
    if (depth > kMaxDepth) return std::nullopt;

    auto s = trim(expr);
    if (s.empty()) return std::nullopt;

    // Split only at top-level operators. '*' binds tighter than '+' and '-',
    // which are evaluated left to right, including offsets after a dereference
    // ("[base]-8-4"). A 32-bit target's addresses wrap at 32 bits: "[p]+FFFFFFFC"
    // is p-4 there, not an address above 4 GiB.
    if (!mask_) {
        const bool narrow = proc_ && proc_->pointerWidth() == 4;
        mixedWidth_ = narrow && proc_->is64bit();
        mask_ = narrow && !mixedWidth_ ? uintptr_t(0xFFFFFFFFu) : UINTPTR_MAX;
    }
    const uintptr_t mask = *mask_;
    // In a mixed-width process an address above 4 GiB is real (64-bit code and
    // stacks), so only arithmetic on two 32-bit values that carries or borrows
    // past 32 bits wraps.
    auto combine = [&](uintptr_t left, uintptr_t right, char op) -> uintptr_t {
        uintptr_t value = op == '-' ? left - right : op == '*' ? left * right : left + right;
        value &= mask;
        if (mixedWidth_ && left <= 0xFFFFFFFFu && right <= 0xFFFFFFFFu && value > 0xFFFFFFFFu)
            value &= 0xFFFFFFFFu;
        return value;
    };
    auto isSpace = [](char c) { return c == ' ' || c == '\t'; };
    auto skipSpaces = [&](size_t& pos) { while (pos < s.size() && isSpace(s[pos])) ++pos; };

    // One operand: a [dereference], a quoted name, or a number, symbol or
    // module name.
    auto factor = [&](size_t& pos) -> std::optional<uintptr_t> {
        skipSpaces(pos);
        if (pos == s.size() || s[pos] == '+' || s[pos] == '-' || s[pos] == '*') return std::nullopt;
        const size_t start = pos;
        if (s[pos] == '[') {
            int bracketDepth = 1;
            const size_t innerStart = ++pos;
            while (pos < s.size() && bracketDepth) {
                if (s[pos] == '[') ++bracketDepth;
                else if (s[pos] == ']') --bracketDepth;
                if (bracketDepth) ++pos;
            }
            if (bracketDepth || !proc_) return std::nullopt;
            auto inner = parseImpl(s.substr(innerStart, pos - innerStart), depth + 1);
            if (!inner) return std::nullopt;
            const size_t ptrSize = proc_->pointerWidth(*inner);
            if ((ptrSize != 4 && ptrSize != 8) || ptrSize > sizeof(uintptr_t)) return std::nullopt;
            uint8_t bytes[8]{};
            auto r = proc_->read(*inner, bytes, ptrSize);
            if (!r || *r != ptrSize) return std::nullopt;
            auto ptr = decodeTargetUnsigned({bytes, ptrSize}, proc_->byteOrder(*inner));
            if (!ptr || *ptr > UINTPTR_MAX) return std::nullopt;
            ++pos;
            return static_cast<uintptr_t>(*ptr);
        }
        if (s[pos] == '"' || s[pos] == '\'') {
            char quote = s[pos++];
            while (pos < s.size() && s[pos] != quote) ++pos;
            if (pos == s.size()) return std::nullopt;
            ++pos;
            return resolveToken(s.substr(start, pos - start));
        }
        // Preserve operators inside known module names, taking the longest match.
        // A plain number ("1C", "0x10", "#16") is no module name: skip the list.
        auto ends = [&](size_t at) { return at == s.size() || s[at] == '+' || s[at] == '-' || s[at] == '*' || isSpace(s[at]); };
        size_t tokenEnd = pos;
        while (!ends(tokenEnd)) ++tokenEnd;
        const std::string head = s.substr(pos, tokenEnd - pos);
        const bool plainNumber = !head.empty() &&
            (head[0] == '#' || std::all_of(head.begin() + (head.starts_with("0x") || head.starts_with("0X") ? 2 : 0),
                                           head.end(), [](unsigned char c) { return std::isxdigit(c); }));
        static const std::vector<ModuleInfo> none;
        size_t modLen = 0;
        for (const auto& m : plainNumber ? none : modules()) {
            if (m.name.empty() || m.name.size() <= modLen || pos + m.name.size() > s.size() ||
                !sameNameIgnoringCase(std::string_view(s).substr(pos, m.name.size()), m.name)) continue;
            if (ends(pos + m.name.size())) modLen = m.name.size();
        }
        if (modLen) {
            pos += modLen;
            return resolveToken(trim(s.substr(start, pos - start)));
        }
        // A demangled C++ name holds '*' ("Game::hit(Player*, int)"), so a
        // symbol may run to the next '+' or '-'. Try that whole span first,
        // then end it at each '*' from the right; a plain number ends at the
        // first '*' ("10*4").
        size_t spanEnd = pos;
        while (spanEnd < s.size() && s[spanEnd] != '+' && s[spanEnd] != '-') ++spanEnd;
        const size_t firstStar = s.find('*', pos);
        if (!plainNumber && firstStar < spanEnd) {
            for (size_t end = spanEnd; end > firstStar;) {
                if (auto value = resolveToken(trim(s.substr(start, end - start)))) { pos = end; return value; }
                end = s.rfind('*', end - 1);
                if (end == std::string::npos || end < firstStar) break;
            }
        }
        while (pos < s.size() && s[pos] != '+' && s[pos] != '-' && s[pos] != '*') ++pos;
        return resolveToken(trim(s.substr(start, pos - start)));
    };
    // A product of factors.
    auto term = [&](size_t& pos) -> std::optional<uintptr_t> {
        auto value = factor(pos);
        if (!value) return std::nullopt;
        for (;;) {
            size_t next = pos;
            skipSpaces(next);
            if (next == s.size() || s[next] != '*') return value;
            pos = next + 1;
            auto right = factor(pos);
            if (!right) return std::nullopt;
            value = combine(*value, *right, '*');
        }
    };

    uintptr_t result = 0;
    char op = '+';
    size_t pos = 0;
    if (s[pos] == '+' || s[pos] == '-') op = s[pos++];
    for (;;) {
        auto value = term(pos);
        if (!value) return std::nullopt;
        result = combine(result, *value, op);
        skipSpaces(pos);
        if (pos == s.size()) return result;
        if (s[pos] != '+' && s[pos] != '-') return std::nullopt;
        op = s[pos++];
        if (pos == s.size()) return std::nullopt;
    }
}

} // namespace ce
