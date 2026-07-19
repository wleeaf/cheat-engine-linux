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
#include <cstdint>
#include <cstring>

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
