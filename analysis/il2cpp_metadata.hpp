#pragma once
/// Parser for Unity IL2CPP `global-metadata.dat` files.
///
/// Reads the version-stable part of the header (the 0xFAB11BAF magic + version)
/// and the two string pools: the identifier pool (type / method / field /
/// namespace names) and the user string-literal pool. Those leading header
/// fields have kept the same byte layout across metadata versions ~16..31, so
/// this parser is correct for real Unity files, not just synthetic ones.
///
/// The deeper metadata tables (type definitions, methods, fields with true
/// offsets) have per-Unity-version struct layouts and need a real target to
/// validate against, so they are intentionally out of scope here. This is the
/// foundation the rest of IL2CPP support (roadmap #10) builds on: it already
/// lets you detect an IL2CPP metadata blob and extract every managed name and
/// string literal offline, with no live process.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ce {

struct Il2CppMetadata {
    int32_t version = 0;
    std::vector<std::string> strings;         ///< identifier pool (names)
    std::vector<std::string> stringLiterals;  ///< user string literals
};

/// True if the buffer begins with the IL2CPP metadata magic (0xFAB11BAF).
bool isIl2CppMetadata(const uint8_t* data, size_t size);

/// Parse a global-metadata.dat image. Returns nullopt if the magic is wrong, the
/// buffer is shorter than the fixed header, or any declared string region falls
/// outside the buffer. Malformed individual string-literal entries are skipped
/// rather than aborting the whole parse.
std::optional<Il2CppMetadata> parseIl2CppMetadata(const uint8_t* data, size_t size);

} // namespace ce
