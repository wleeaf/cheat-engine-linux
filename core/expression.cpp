#include "core/expression.hpp"
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstring>

namespace ce {

static std::string trim(const std::string& s) {
    auto a = s.find_first_not_of(" \t");
    auto b = s.find_last_not_of(" \t");
    return a == std::string::npos ? "" : s.substr(a, b - a + 1);
}

std::optional<uintptr_t> ExpressionParser::resolveToken(const std::string& token) const {
    if (token.empty()) return std::nullopt;
    if (token.size() >= 2 && (token.front() == '"' || token.front() == '\'') && token.back() == token.front()) {
        auto name = token.substr(1, token.size() - 2);
        if (resolver_) {
            if (auto address = resolver_->lookup(name)) return address;
        }
        if (proc_) {
            for (const auto& m : proc_->modules()) if (m.name == name) return m.base;
        }
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
        for (const auto& m : proc_->modules())
            if (m.name == token) return m.base;
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

    // Split only at top-level operators. All arithmetic is evaluated left to
    // right, including offsets after a dereference ("[base]-8-4").
    std::vector<ModuleInfo> mods;
    if (proc_) mods = proc_->modules();
    uintptr_t result = 0;
    bool subtract = false;
    size_t pos = 0;
    if (s[pos] == '+' || s[pos] == '-') {
        subtract = s[pos] == '-';
        ++pos;
    }

    while (pos < s.size()) {
        while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t')) ++pos;
        if (pos == s.size() || s[pos] == '+' || s[pos] == '-') return std::nullopt;
        const size_t start = pos;
        std::optional<uintptr_t> val;

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
            val = static_cast<uintptr_t>(*ptr);
            ++pos;
        } else if (s[pos] == '"' || s[pos] == '\'') {
            char quote = s[pos++];
            while (pos < s.size() && s[pos] != quote) ++pos;
            if (pos == s.size()) return std::nullopt;
            ++pos;
            val = resolveToken(s.substr(start, pos - start));
        } else {
            // Preserve operators inside known module names, taking the longest match.
            size_t modLen = 0;
            for (const auto& m : mods) {
                if (m.name.empty() || m.name.size() <= modLen ||
                    s.compare(pos, m.name.size(), m.name) != 0) continue;
                const size_t after = pos + m.name.size();
                if (after == s.size() || s[after] == '+' || s[after] == '-' ||
                    s[after] == ' ' || s[after] == '\t') modLen = m.name.size();
            }
            if (modLen) pos += modLen;
            else while (pos < s.size() && s[pos] != '+' && s[pos] != '-') ++pos;
            val = resolveToken(trim(s.substr(start, pos - start)));
        }
        if (!val) return std::nullopt;
        if (subtract) result -= *val;
        else result += *val;

        while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t')) ++pos;
        if (pos == s.size()) return result;
        if (s[pos] != '+' && s[pos] != '-') return std::nullopt;
        subtract = s[pos++] == '-';
        if (pos == s.size()) return std::nullopt;
    }
    return std::nullopt;
}

} // namespace ce
