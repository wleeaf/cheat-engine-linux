#include "platform/network_compression.hpp"

#include <zlib.h>

namespace ce::net {

std::expected<std::vector<uint8_t>, std::string>
compressPayload(const std::vector<uint8_t>& data, int level) {
    if (level < Z_NO_COMPRESSION || level > Z_BEST_COMPRESSION)
        return std::unexpected("invalid zlib compression level");

    uLongf compressedSize = compressBound(static_cast<uLong>(data.size()));
    std::vector<uint8_t> compressed(compressedSize);
    int result = compress2(compressed.data(), &compressedSize,
        data.data(), static_cast<uLong>(data.size()), level);
    if (result != Z_OK)
        return std::unexpected("zlib compress failed: " + std::to_string(result));

    compressed.resize(compressedSize);
    return compressed;
}

std::expected<std::vector<uint8_t>, std::string>
decompressPayload(const std::vector<uint8_t>& compressed, size_t uncompressedSize) {
    std::vector<uint8_t> output(uncompressedSize);
    uLongf outputSize = static_cast<uLongf>(output.size());
    int result = uncompress(output.data(), &outputSize,
        compressed.data(), static_cast<uLong>(compressed.size()));
    if (result != Z_OK)
        return std::unexpected("zlib decompress failed: " + std::to_string(result));
    if (outputSize != uncompressedSize)
        return std::unexpected("zlib decompress size mismatch");

    return output;
}

} // namespace ce::net
