#include "analysis/il2cpp_metadata.hpp"

#include <cstring>

namespace ce {

namespace {

constexpr uint32_t kIl2CppMagic = 0xFAB11BAFu;

// global-metadata.dat is little-endian (every IL2CPP target is LE).
uint32_t rdU32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | static_cast<uint32_t>(p[1]) << 8 |
           static_cast<uint32_t>(p[2]) << 16 | static_cast<uint32_t>(p[3]) << 24;
}
int32_t rdI32(const uint8_t* p) { return static_cast<int32_t>(rdU32(p)); }

// Header field byte offsets. These leading fields keep the same layout across
// metadata versions ~16..31:
//   0  sanity (magic)          4  version
//   8  stringLiteralOffset     12 stringLiteralSize
//   16 stringLiteralDataOffset 20 stringLiteralDataSize
//   24 stringOffset            28 stringSize
constexpr size_t kOffSanity = 0;
constexpr size_t kOffVersion = 4;
constexpr size_t kOffStrLit = 8;
constexpr size_t kOffStrLitSize = 12;
constexpr size_t kOffStrLitData = 16;
constexpr size_t kOffStrLitDataSize = 20;
constexpr size_t kOffString = 24;
constexpr size_t kOffStringSize = 28;
constexpr size_t kMinHeader = 32;

// A declared [offset, offset+size) region must lie wholly inside the buffer.
bool regionValid(int32_t off, int32_t size, size_t total) {
    return off >= 0 && size >= 0 &&
        static_cast<uint64_t>(off) + static_cast<uint64_t>(size) <=
            static_cast<uint64_t>(total);
}

} // namespace

bool isIl2CppMetadata(const uint8_t* data, size_t size) {
    return data && size >= 4 && rdU32(data + kOffSanity) == kIl2CppMagic;
}

std::optional<Il2CppMetadata> parseIl2CppMetadata(const uint8_t* data, size_t size) {
    if (!data || size < kMinHeader) return std::nullopt;
    if (rdU32(data + kOffSanity) != kIl2CppMagic) return std::nullopt;

    Il2CppMetadata md;
    md.version = rdI32(data + kOffVersion);

    // Identifier pool: consecutive null-terminated UTF-8 strings.
    const int32_t strOff = rdI32(data + kOffString);
    const int32_t strSize = rdI32(data + kOffStringSize);
    if (!regionValid(strOff, strSize, size)) return std::nullopt;
    for (int32_t i = 0; i < strSize;) {
        const char* s = reinterpret_cast<const char*>(data + strOff + i);
        const size_t maxLen = static_cast<size_t>(strSize - i);
        const size_t len = ::strnlen(s, maxLen);
        md.strings.emplace_back(s, len);
        if (len == maxLen) break;      // unterminated tail: stop cleanly
        i += static_cast<int32_t>(len) + 1;  // step past the NUL
    }

    // String-literal pool: a table of { uint32 length; int32 dataIndex } whose
    // bytes live in the separate stringLiteralData region.
    const int32_t litOff = rdI32(data + kOffStrLit);
    const int32_t litSize = rdI32(data + kOffStrLitSize);
    const int32_t litDataOff = rdI32(data + kOffStrLitData);
    const int32_t litDataSize = rdI32(data + kOffStrLitDataSize);
    if (regionValid(litOff, litSize, size) &&
        regionValid(litDataOff, litDataSize, size)) {
        for (int32_t i = 0; i + 8 <= litSize; i += 8) {
            const uint32_t length = rdU32(data + litOff + i);
            const int32_t dataIndex = rdI32(data + litOff + i + 4);
            if (dataIndex < 0 ||
                static_cast<uint64_t>(dataIndex) + length >
                    static_cast<uint64_t>(litDataSize))
                continue;              // skip a malformed entry, keep the rest
            md.stringLiterals.emplace_back(
                reinterpret_cast<const char*>(data + litDataOff + dataIndex), length);
        }
    }

    return md;
}

} // namespace ce
