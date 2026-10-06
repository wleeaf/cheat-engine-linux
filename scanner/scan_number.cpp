#include "scanner/memory_scanner.hpp"
#include <algorithm>
#include <bit>
#include <charconv>
#include <cmath>
#include <limits>

namespace ce {
namespace {
struct Number {
    ScanConfig::AllIntegerValue integer;
    double floating = 0;
    int decimals = 0;
};

std::optional<Number> parseNumber(std::string_view input, bool hex) {
    if (input.size() > 4096) return {};
    const auto first = input.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) return {};
    input = input.substr(first, input.find_last_not_of(" \t\r\n") - first + 1);
    Number number;
    bool negative = false;
    std::string_view body = input;
    if (body.front() == '+' || body.front() == '-') {
        negative = body.front() == '-'; body.remove_prefix(1);
    }
    if (body.empty()) return {};
    const bool prefix = body.size() >= 2 && body[0] == '0' && (body[1] == 'x' || body[1] == 'X');
    if (hex || prefix) {
        if (prefix) body.remove_prefix(2);
        uint64_t bits = 0;
        const auto parsed = std::from_chars(body.data(), body.data() + body.size(), bits, 16);
        if (body.empty() || parsed.ec != std::errc{} || parsed.ptr != body.data() + body.size() ||
            (negative && bits > (uint64_t{1} << 63))) return {};
        if (negative) bits = uint64_t{0} - bits;
        // Preserve the existing integer editor's 64-bit two's-complement hex convention.
        const int64_t value = std::bit_cast<int64_t>(bits);
        number.integer.negative = value < 0;
        number.integer.magnitude = value < 0 ? uint64_t{0} - bits : bits;
        number.floating = static_cast<double>(value);
        return number;
    }
    std::string token(input);
    std::replace(token.begin(), token.end(), ',', '.');
    const auto start = token.data() + (token.front() == '+' ? 1 : 0);
    const auto parsed = std::from_chars(start, token.data() + token.size(), number.floating);
    if (parsed.ec != std::errc{} || parsed.ptr != token.data() + token.size()) return {};
    if (!std::isfinite(number.floating)) {
        std::string special(body);
        std::transform(special.begin(), special.end(), special.begin(), [](unsigned char c) {
            return static_cast<char>(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
        });
        if (special != "nan" && special != "inf" && special != "infinity") return {};
        number.integer.negative = negative;
        number.integer.unordered = std::isnan(number.floating);
        number.integer.outsideMagnitude = !number.integer.unordered;
        return number;
    }
    // Decode decimal digits and scale exactly, without going through double.
    // This also keeps 9223372036854775807 and nearby fractions distinguishable.
    std::string digits;
    size_t pos = 0;
    bool separator = false;
    int fractionalDigits = 0;
    while (pos < body.size()) {
        const char c = body[pos];
        if (c >= '0' && c <= '9') {
            digits.push_back(c); if (separator) ++fractionalDigits;
        } else if ((c == '.' || c == ',') && !separator) separator = true;
        else break;
        ++pos;
    }
    if (digits.empty()) return {};
    int exponent = 0;
    if (pos < body.size() && (body[pos] == 'e' || body[pos] == 'E')) {
        ++pos; bool exponentNegative = false;
        if (pos < body.size() && (body[pos] == '+' || body[pos] == '-')) {
            exponentNegative = body[pos] == '-'; ++pos;
        }
        const size_t begin = pos;
        while (pos < body.size() && body[pos] >= '0' && body[pos] <= '9') {
            exponent = std::min(8192, exponent * 10 + (body[pos++] - '0'));
        }
        if (begin == pos) return {};
        if (exponentNegative) exponent = -exponent;
    }
    if (pos != body.size()) return {};
    number.decimals = std::max(0, fractionalDigits - exponent);
    const auto significant = digits.find_first_not_of('0');
    if (significant == std::string::npos) return number;
    const int point = static_cast<int>(digits.size()) - fractionalDigits + exponent - static_cast<int>(significant);
    digits.erase(0, significant);
    number.integer.negative = negative;
    const size_t fractionStart = static_cast<size_t>(std::max(0, point));
    number.integer.fractional = fractionStart < digits.size() &&
        digits.find_first_not_of('0', fractionStart) != std::string::npos;
    if (point > 20) number.integer.outsideMagnitude = true;
    else for (int i = 0; i < point; ++i) {
        const auto digit = static_cast<uint64_t>(static_cast<size_t>(i) < digits.size() ? digits[i] - '0' : 0);
        if (number.integer.magnitude > (UINT64_MAX - digit) / 10) {
            number.integer.outsideMagnitude = true; break;
        }
        number.integer.magnitude = number.integer.magnitude * 10 + digit;
    }
    return number;
}

int64_t integerHint(const ScanConfig::AllIntegerValue& value) {
    if (value.unordered || value.outsideMagnitude || value.fractional ||
        value.magnitude > (value.negative ? uint64_t{1} << 63 : uint64_t{INT64_MAX})) return 0;
    return std::bit_cast<int64_t>(value.negative ? uint64_t{0} - value.magnitude : value.magnitude);
}

bool needsLiteral(const ScanConfig& config) {
    if (config.percentageScan && (config.compareType == ScanCompare::Greater || config.compareType == ScanCompare::Less ||
        config.compareType == ScanCompare::Between || config.compareType == ScanCompare::Increased || config.compareType == ScanCompare::Decreased)) return false;
    switch (config.compareType) {
        case ScanCompare::Exact: case ScanCompare::Greater: case ScanCompare::Less:
        case ScanCompare::Between: case ScanCompare::IncreasedBy: case ScanCompare::DecreasedBy: return true;
        default: return false;
    }
}
}

int ScanConfig::AllIntegerValue::compare(int64_t current) const {
    if (unordered) return 2;
    if (outsideMagnitude) return negative ? 1 : -1;
    const bool currentNegative = current < 0;
    if (currentNegative != negative) return currentNegative ? -1 : 1;
    const uint64_t bits = std::bit_cast<uint64_t>(current);
    const uint64_t absolute = currentNegative ? uint64_t{0} - bits : bits;
    int order = absolute < magnitude ? -1 : absolute > magnitude ? 1 : fractional ? -1 : 0;
    return negative ? -order : order;
}

bool ScanConfig::parseAllValues(std::string_view first, std::string_view second, bool hex) {
    if (!needsLiteral(*this)) {allIntegerValue.reset(); allIntegerValue2.reset(); return true;}
    const auto lower = parseNumber(first, hex);
    const auto upper = compareType == ScanCompare::Between ? parseNumber(second, hex) : std::optional<Number>{};
    if (!lower || (compareType == ScanCompare::Between && !upper)) return false;
    allIntegerValue = lower->integer; intValue = integerHint(lower->integer);
    floatValue = lower->floating; floatDecimals = lower->decimals;
    allIntegerValue2 = upper ? std::optional{upper->integer} : std::nullopt;
    if (upper) { intValue2 = integerHint(upper->integer); floatValue2 = upper->floating; }
    return true;
}

bool ScanConfig::parseFloatingValues(std::string_view first, std::string_view second) {
    if (!needsLiteral(*this)) return true;
    const auto lower = parseNumber(first, false);
    const auto upper = compareType == ScanCompare::Between ? parseNumber(second, false) : std::optional<Number>{};
    if (!lower || (compareType == ScanCompare::Between && !upper)) return false;
    floatValue = lower->floating; floatDecimals = lower->decimals;
    if (upper) floatValue2 = upper->floating;
    return true;
}
}
