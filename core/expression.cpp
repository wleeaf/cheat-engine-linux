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

uintptr_t ExpressionParser::resolveToken(const std::string& token) const {
    if (token.empty()) return 0;

    // Hex with prefix
    if (token.size() > 2 && token[0] == '0' && (token[1] == 'x' || token[1] == 'X')) {
        try { return std::stoull(token.substr(2), nullptr, 16); } catch (...) { return 0; }
    }

    // Decimal with # prefix
    if (token[0] == '#') {
        if (token.size() < 2) return 0;  // "#" alone has no digits
        try { return std::stoull(token.substr(1), nullptr, 10); } catch (...) { return 0; }
    }

    // Try as plain hex (CE convention: bare numbers are hexadecimal). The
    // size>=2 guard avoids treating a single-letter symbol ("a") as hex 0xa, but
    // it wrongly zeroed single-DIGIT tokens too — so "[base]+8" resolved as +0.
    // A single digit 0-9 is unambiguously a number (hex 0-9 == decimal), so parse
    // it; only a lone hex letter (a-f) stays symbol-first.
    bool allHex = std::all_of(token.begin(), token.end(),
        [](char c) { return std::isxdigit(static_cast<unsigned char>(c)); });
    bool allDigit = std::all_of(token.begin(), token.end(),
        [](char c) { return std::isdigit(static_cast<unsigned char>(c)); });
    if (allHex && (token.size() >= 2 || allDigit)) {
        try { return std::stoull(token, nullptr, 16); } catch (...) { return 0; }
    }

    // Try symbol resolver
    if (resolver_) {
        auto addr = resolver_->lookup(token);
        if (addr) return addr;
    }

    // Try module name → base address
    if (proc_) {
        auto mods = proc_->modules();
        for (auto& m : mods)
            if (m.name == token) return m.base;
    }

    // Last resort: a lone hex letter (e.g. an offset "+c") that is not a known
    // symbol or module is a hex number. We try this AFTER symbol/module lookup so
    // a single-letter symbol still wins if one is registered.
    if (allHex) {
        try { return std::stoull(token, nullptr, 16); } catch (...) {}
    }

    return 0;
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

    // Handle pointer dereference: [expr]+offset
    if (s[0] == '[') {
        // Find the ']' that MATCHES the opening '[' (by nesting depth), not the
        // first one — otherwise a multi-level pointer like "[[base]]" would split
        // its inner bracket ("[base") and fail to resolve.
        size_t closeB = std::string::npos;
        int bracketDepth = 0;
        for (size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '[') ++bracketDepth;
            else if (s[i] == ']') { if (--bracketDepth == 0) { closeB = i; break; } }
        }
        if (closeB == std::string::npos) return std::nullopt;

        auto inner = s.substr(1, closeB - 1);
        auto innerVal = parseImpl(inner, depth + 1);
        if (!innerVal || !proc_) return std::nullopt;

        // Dereference
        uintptr_t ptr = 0;
        auto r = proc_->read(*innerVal, &ptr, sizeof(ptr));
        if (!r || *r < sizeof(ptr)) return std::nullopt;

        // Apply remaining offset after ']'
        auto rest = trim(s.substr(closeB + 1));
        if (rest.empty()) return ptr;

        // Parse +/- offset
        if (rest[0] == '+') {
            auto offsetVal = parseImpl(rest.substr(1), depth + 1);
            return offsetVal ? std::optional(ptr + *offsetVal) : std::nullopt;
        } else if (rest[0] == '-') {
            auto offsetVal = parseImpl(rest.substr(1), depth + 1);
            return offsetVal ? std::optional(ptr - *offsetVal) : std::nullopt;
        }
        return ptr;
    }

    // Split by + and - for arithmetic
    uintptr_t result = 0;
    bool subtract = false;
    size_t pos = 0;

    // Module names can contain '-' (Linux libraries like "libssl-1.1.so"). Querying the
    // module list once lets a term that starts with a known module name be taken whole,
    // so the '-' inside the name is not mistaken for a subtraction operator.
    std::vector<ModuleInfo> mods;
    if (proc_) mods = proc_->modules();

    while (pos < s.size()) {
        // Find next + or - past the current term (not inside a 0x prefix, and not
        // inside a [pointer] sub-expression — otherwise "0x1000+[base+8]" would
        // split the inner "+8" and mangle the bracket).
        size_t nextOp = std::string::npos;

        // If the term begins with a known (possibly hyphenated) module name followed by
        // an operator or the end of the string, take the whole name as the token so its
        // internal '-' is not split. Longest match wins for overlapping names.
        size_t modLen = 0;
        for (const auto& m : mods) {
            if (m.name.empty() || m.name.size() <= modLen) continue;
            if (s.compare(pos, m.name.size(), m.name) != 0) continue;
            size_t after = pos + m.name.size();
            if (after >= s.size() || s[after] == '+' || s[after] == '-')
                modLen = m.name.size();
        }
        if (modLen > 0) {
            nextOp = (pos + modLen < s.size()) ? pos + modLen : std::string::npos;
        } else {
            // Count the term's own leading '[' — the scan starts at pos+1, so without
            // this the outer bracket wouldn't be tracked and an inner '+' would match.
            int bd = (pos < s.size() && s[pos] == '[') ? 1 : 0;
            for (size_t i = pos + 1; i < s.size(); ++i) {
                if (s[i] == '[') ++bd;
                else if (s[i] == ']') { if (bd > 0) --bd; }
                else if (bd == 0 && (s[i] == '+' || s[i] == '-') &&
                         !(i > 1 && (s[i-1] == 'x' || s[i-1] == 'X'))) {
                    nextOp = i;
                    break;
                }
            }
        }

        std::string token;
        if (nextOp == std::string::npos) {
            token = trim(s.substr(pos));
            pos = s.size();
        } else {
            token = trim(s.substr(pos, nextOp - pos));
            pos = nextOp;
        }

        if (!token.empty()) {
            // A term can itself be a [pointer] sub-expression; recurse through
            // parseImpl for those so the dereference happens (resolveToken handles
            // only simple hex/decimal/symbol/module+offset tokens and would 0 it).
            uintptr_t val = 0;
            if (token.find('[') != std::string::npos) {
                auto sub = parseImpl(token, depth + 1);
                val = sub ? *sub : 0;
            } else {
                val = resolveToken(token);
            }
            if (subtract)
                result -= val;
            else
                result += val;
        }

        if (pos < s.size()) {
            subtract = (s[pos] == '-');
            ++pos;
        }
    }

    return result;
}

} // namespace ce
