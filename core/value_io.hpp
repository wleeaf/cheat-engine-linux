#pragma once

#include "platform/process_api.hpp"
#include "core/value_codec.hpp"
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ce {

struct ValueIoOptions {
    bool hex = false;
    bool isSigned = true;
    bool bigEndian = false;
    // Explicit byte order overrides detection; the legacy bigEndian flag forces BE.
    std::optional<ByteOrder> byteOrder;
    bool terminate = false;
    size_t size = 64; // Maximum read length for strings; exact length for byte arrays.
    int pointerWidth = sizeof(uintptr_t); // Encoding without a process defaults to host width.
    std::optional<int> pointerWidthOverride; // Known encoded data, independent of the process ABI.
    std::string encoding = "UTF-8";
    ValueCodec codec;
};

std::optional<ValueType> parseValueType(std::string_view name);
std::expected<ValueIoOptions, std::string> valueOptionsForTarget(
    ProcessHandle& process, uintptr_t address, ValueType type, ValueIoOptions options = {});
std::expected<std::vector<uint8_t>, std::string> encodeTypedValue(
    ValueType type, std::string_view value, const ValueIoOptions& options = {});
std::expected<std::string, std::string> readTypedValue(
    ProcessHandle& process, uintptr_t address, ValueType type, ValueIoOptions options = {});
// Decode captured target bytes without rereading a live process. Scalar input
// must have exactly its described width; options carry the captured data format.
std::expected<std::string, std::string> decodeTypedValue(
    ValueType type, std::span<const uint8_t> bytes, ValueIoOptions options = {});
// Compare current memory with a logical value: -1, 0 or 1, without losing integer precision.
std::expected<int, std::string> compareTypedValue(
    ProcessHandle& process, uintptr_t address, ValueType type, std::string_view value,
    ValueIoOptions options = {});
std::expected<size_t, std::string> writeTypedValue(
    ProcessHandle& process, uintptr_t address, ValueType type, std::string_view value,
    ValueIoOptions options = {});

} // namespace ce
