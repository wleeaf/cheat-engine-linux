#pragma once
/// zlib helpers for compressed remote/network payloads.

#include <cstdint>
#include <cstddef>
#include <expected>
#include <string>
#include <vector>

namespace ce::net {

std::expected<std::vector<uint8_t>, std::string>
compressPayload(const std::vector<uint8_t>& data, int level = 6);

std::expected<std::vector<uint8_t>, std::string>
decompressPayload(const std::vector<uint8_t>& compressed, size_t uncompressedSize);

} // namespace ce::net
