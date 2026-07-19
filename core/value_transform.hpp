#pragma once
/// Qt-free scalar value transform shared by the GUI cheat table (and testable
/// headlessly). A stored scalar can be big-endian (emulated PS3/Wii/GameCube) and/or
/// obfuscated by a ValueCodec (xor/add/rol/ror). The logical value the user works with
/// is: reverse the byte order to host, then decode the codec; writing is the inverse.
/// Keeping this in cecore lets the codec+endianness composition be unit-tested instead
/// of living only inside a GUI translation unit.

#include "core/types.hpp"
#include "core/value_codec.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

namespace ce {

/// Byte width of a fixed-width scalar type, or 0 for non-scalar (string/aob/...).
inline int scalarWidth(ValueType t) {
    switch (t) {
        case ValueType::Byte:                        return 1;
        case ValueType::Int16:                       return 2;
        case ValueType::Int32: case ValueType::Float: return 4;
        case ValueType::Int64: case ValueType::Double:
        case ValueType::Pointer:                     return 8;
        default:                                     return 0;
    }
}

/// Codecs apply to integer types only (a float/pointer is never obfuscated this way).
inline bool isIntegerScalar(ValueType t) {
    return t == ValueType::Byte || t == ValueType::Int16 ||
           t == ValueType::Int32 || t == ValueType::Int64;
}

/// Decode `width(type)` stored bytes to the LOGICAL value's host-order bits: reverse
/// big-endian byte order first, then apply the codec (integer types only). The caller
/// reinterprets the returned bits as the typed value.
inline uint64_t decodeScalarBits(ValueType type, const uint8_t* stored,
                                 bool bigEndian, const ValueCodec& codec) {
    const int w = scalarWidth(type);
    if (w <= 0) return 0;
    uint8_t buf[8] = {};
    std::memcpy(buf, stored, static_cast<size_t>(w));
    if (bigEndian && w > 1) std::reverse(buf, buf + w);
    uint64_t raw = 0;
    std::memcpy(&raw, buf, static_cast<size_t>(w));
    if (codec.active() && isIntegerScalar(type)) raw = codec.decode(raw, w);
    return raw;
}

/// Format an integer scalar's decoded bits for display (CE ShowAsSigned + hex flags).
/// `width` is 1/2/4/8 bytes. Hex shows the width-masked unsigned value; decimal shows
/// it signed (sign-extended from `width`) or unsigned. Qt-free so it is unit-tested in
/// cecore and shared by the GUI's value formatter.
inline std::string formatIntegerScalar(uint64_t bits, int width, bool isSigned, bool hex) {
    if (width < 1) width = 1;
    if (width > 8) width = 8;
    uint64_t mask = (width >= 8) ? ~0ull : ((1ull << (width * 8)) - 1);
    uint64_t u = bits & mask;
    if (hex) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(u));
        return buf;
    }
    if (isSigned) {
        int64_t s;
        switch (width) {
            case 1:  s = static_cast<int8_t>(u);  break;
            case 2:  s = static_cast<int16_t>(u); break;
            case 4:  s = static_cast<int32_t>(u); break;
            default: s = static_cast<int64_t>(u); break;
        }
        return std::to_string(s);
    }
    return std::to_string(u);
}

/// Parse a user-typed integer value (the input counterpart of formatIntegerScalar).
/// When `hex` is true a bare token is read as hexadecimal (CE's "Show as hexadecimal"
/// edit mode); a leading "0x" is always hex; a leading '-'/'+' sets the sign. Returns
/// the signed value; sets ok=false (and returns 0) on an empty/malformed token. The
/// caller casts the result to the type width (two's complement handles negatives).
inline int64_t parseIntegerScalar(const std::string& s, bool hex, bool& ok) {
    ok = false;
    size_t a = s.find_first_not_of(" \t");
    if (a == std::string::npos) return 0;
    size_t b = s.find_last_not_of(" \t");
    std::string t = s.substr(a, b - a + 1);
    size_t i = 0;
    bool neg = false;
    if (t[i] == '-' || t[i] == '+') { neg = (t[i] == '-'); ++i; }
    int base = hex ? 16 : 10;
    if (i + 1 < t.size() && t[i] == '0' && (t[i + 1] == 'x' || t[i + 1] == 'X')) { base = 16; i += 2; }
    if (i >= t.size()) return 0;
    uint64_t val = 0;
    for (; i < t.size(); ++i) {
        char c = t[i];
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return 0;
        if (d >= base) return 0;   // e.g. a hex letter typed in a decimal field
        val = val * static_cast<uint64_t>(base) + static_cast<uint64_t>(d);
    }
    ok = true;
    return neg ? -static_cast<int64_t>(val) : static_cast<int64_t>(val);
}

/// Format a float/double for display the way Cheat Engine does: trimmed of trailing
/// zeros (100.0 -> "100", 99.5 -> "99.5") with precision matching the type's
/// significant digits (~7 for float, ~15 for double). Qt-free and shared, so the cheat
/// table and scan results render floats identically. NaN/Inf render as short tokens.
inline std::string formatFloatScalar(double v, bool isDouble) {
    if (std::isnan(v)) return "nan";
    if (std::isinf(v)) return v < 0 ? "-inf" : "inf";
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%.*g", isDouble ? 15 : 7, v);
    return buf;
}

/// Inverse: from a LOGICAL value's host-order bits, produce the `width(type)` stored
/// bytes to write (encode via codec for integer types, then reverse for big-endian).
inline void encodeScalarBits(ValueType type, uint64_t logicalBits,
                             bool bigEndian, const ValueCodec& codec, uint8_t* out) {
    const int w = scalarWidth(type);
    if (w <= 0) return;
    uint64_t raw = logicalBits;
    if (codec.active() && isIntegerScalar(type)) raw = codec.encode(raw, w);
    std::memcpy(out, &raw, static_cast<size_t>(w));
    if (bigEndian && w > 1) std::reverse(out, out + w);
}

} // namespace ce
