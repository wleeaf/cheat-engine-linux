#include "core/value_io.hpp"
#include <bit>
#include "core/value_transform.hpp"
#include "scanner/memory_scanner.hpp"

#include <charconv>
#include <cctype>
#include <cmath>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace ce {
namespace {
std::string trim(std::string_view value) {
    auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) return {};
    return std::string(value.substr(first, value.find_last_not_of(" \t\r\n") - first + 1));
}
int width(ValueType type, const ValueIoOptions& options) {
    return type == ValueType::Pointer ? options.pointerWidthOverride.value_or(options.pointerWidth) : scalarWidth(type);
}
bool integer(ValueType type) { return isIntegerScalar(type) || type == ValueType::Pointer; }
}

std::optional<ValueType> parseValueType(std::string_view name) {
    auto token = trim(name);
    for (auto& c : token) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (token == "byte" || token == "i8" || token == "u8") return ValueType::Byte;
    if (token == "i16" || token == "u16" || token == "int16" || token == "2 bytes") return ValueType::Int16;
    if (token == "i32" || token == "u32" || token == "int32" || token == "4 bytes") return ValueType::Int32;
    if (token == "i64" || token == "u64" || token == "int64" || token == "8 bytes") return ValueType::Int64;
    if (token == "pointer" || token == "ptr") return ValueType::Pointer;
    if (token == "float" || token == "f32") return ValueType::Float;
    if (token == "double" || token == "f64") return ValueType::Double;
    if (token == "string" || token == "utf8" || token == "utf-8") return ValueType::String;
    if (token == "unicode" || token == "utf16" || token == "utf-16" || token == "unicodestring") return ValueType::UnicodeString;
    if (token == "aob" || token == "bytes" || token == "bytearray" || token == "array of byte") return ValueType::ByteArray;
    if (token == "binary") return ValueType::Binary;
    if (token == "all") return ValueType::All;
    if (token == "grouped" || token == "group") return ValueType::Grouped;
    if (token == "custom") return ValueType::Custom;
    return std::nullopt;
}

static bool bigEndianEncoding(const ValueIoOptions& options) {
    return options.byteOrder ? *options.byteOrder == ByteOrder::Big : options.bigEndian;
}
static std::optional<std::string> resolveTargetOptions(ProcessHandle& process, uintptr_t address,
                                                       ValueType type, ValueIoOptions& options) {
    auto machine = process.machineAt(address);
    options.pointerWidth = options.pointerWidthOverride.value_or(machine.pointerWidth);
    if (options.pointerWidthOverride && options.pointerWidth != 4 && options.pointerWidth != 8)
        return "Pointer width must be 4 or 8 bytes";
    if (type == ValueType::Pointer && options.pointerWidth != 4 && options.pointerWidth != 8)
        return "Target pointer width is unknown; select it explicitly";
    if (type != ValueType::ByteArray && type != ValueType::String) {
        if (!options.byteOrder) options.byteOrder = options.bigEndian ? ByteOrder::Big : machine.byteOrder;
        if (*options.byteOrder != ByteOrder::Little && *options.byteOrder != ByteOrder::Big)
            return "Target byte order is unknown or invalid; select it explicitly";
    }
    return std::nullopt;
}

std::expected<ValueIoOptions, std::string> valueOptionsForTarget(
    ProcessHandle& process, uintptr_t address, ValueType type, ValueIoOptions options) {
    if (auto error = resolveTargetOptions(process, address, type, options)) return std::unexpected(*error);
    return options;
}

std::expected<std::vector<uint8_t>, std::string> encodeTypedValue(
    ValueType type, std::string_view value, const ValueIoOptions& options) {
    if (type != ValueType::ByteArray && type != ValueType::String && options.byteOrder &&
        *options.byteOrder != ByteOrder::Little && *options.byteOrder != ByteOrder::Big)
        return std::unexpected("Invalid data byte order");
    if (type == ValueType::Pointer && width(type,options) != 4 && width(type,options) != 8)
        return std::unexpected("Pointer width must be 4 or 8 bytes");
    if (options.codec.active() && !integer(type))
        return std::unexpected("Value codecs require an integer or pointer type");
    if (type == ValueType::String || type == ValueType::UnicodeString) {
        try {
            auto encoding = type == ValueType::UnicodeString
                ? (bigEndianEncoding(options) ? "UTF-16BE" : "UTF-16LE") : options.encoding;
            std::string text(value);
            if (options.terminate) text.push_back('\0');
            // Convert text and terminator together so stateful encodings and BOMs
            // are emitted once for the complete value.
            auto bytes = encodeStringBytes(text, encoding);
            return bytes;
        } catch (const std::invalid_argument& error) { return std::unexpected(error.what()); }
    }
    if (type == ValueType::ByteArray) {
        std::vector<uint8_t> bytes;
        auto text = trim(value);
        size_t start = 0;
        while (start < text.size()) {
            size_t end = text.find_first_of(" ,\t\r\n", start);
            if (end == std::string::npos) end = text.size();
            auto token = std::string_view(text).substr(start, end - start);
            if (token.starts_with("0x") || token.starts_with("0X")) token.remove_prefix(2);
            unsigned byte = 0;
            auto parsed = std::from_chars(token.data(), token.data() + token.size(), byte, 16);
            if (token.empty() || parsed.ec != std::errc{} || parsed.ptr != token.data() + token.size() || byte > 255)
                return std::unexpected("Byte arrays need concrete hexadecimal bytes, for example '90 90 48 8B'");
            bytes.push_back(static_cast<uint8_t>(byte));
            start = text.find_first_not_of(" ,\t\r\n", end);
            if (start == std::string::npos) break;
        }
        if (bytes.empty()) return std::unexpected("Enter at least one byte");
        return bytes;
    }
    const int count = width(type, options);
    if (count != 1 && count != 2 && count != 4 && count != 8)
        return std::unexpected("This type describes a scan, not a single editable value");
    uint64_t bits = 0;
    auto text = trim(value);
    if (integer(type)) {
        bool ok = false;
        int64_t parsed = parseIntegerScalar(text, options.hex, ok);
        if (!ok) return std::unexpected("Enter a decimal integer or a hexadecimal value beginning with 0x");
        bits = static_cast<uint64_t>(parsed);
        bool negative = !text.empty() && text.front() == '-';
        if (count < 8 && ((negative && parsed < -(int64_t{1} << (count * 8 - 1))) ||
                         (!negative && bits > ValueCodec::maskFor(count))))
            return std::unexpected("The value does not fit in " + std::to_string(count) + " bytes");
        if (options.codec.active()) bits = options.codec.encode(bits, count);
    } else {
        for (auto& c : text) if (c == ',') c = '.';
        std::string_view token(text);
        if (token.starts_with('+')) token.remove_prefix(1);
        double number = 0;
        auto parsed = std::from_chars(token.data(), token.data() + token.size(), number);
        if (token.empty() || parsed.ec != std::errc{} || parsed.ptr != token.data() + token.size())
            return std::unexpected("Enter a floating-point value, for example 2.5 or 2,5");
        if (type == ValueType::Float) {
            if (std::isfinite(number) && std::abs(number) > std::numeric_limits<float>::max())
                return std::unexpected("The value exceeds the float range; use double instead");
            float converted = static_cast<float>(number); bits = std::bit_cast<uint32_t>(converted);
        } else bits = std::bit_cast<uint64_t>(number);
    }
    std::vector<uint8_t> bytes(count);
    for (int i = 0; i < count; ++i)
        bytes[bigEndianEncoding(options) ? count - 1 - i : i] = static_cast<uint8_t>(bits >> (8 * i));
    return bytes;
}

std::expected<std::string, std::string> readTypedValue(
    ProcessHandle& process, uintptr_t address, ValueType type, ValueIoOptions options) {
    if (auto error = resolveTargetOptions(process, address, type, options)) return std::unexpected(*error);
    int scalar = width(type, options);
    bool string = type == ValueType::String || type == ValueType::UnicodeString;
    if (!scalar && !string && type != ValueType::ByteArray)
        return std::unexpected("This type describes a scan, not a single readable value");
    if (options.codec.active() && !integer(type)) return std::unexpected("Value codecs require an integer or pointer type");
    size_t count = scalar ? static_cast<size_t>(scalar) : options.size;
    if (!count || count > 256 * 1024 * 1024) return std::unexpected("Read size must be between 1 byte and 256 MiB");
    if (count - 1 > UINTPTR_MAX - address) return std::unexpected("The read range overflows the address space");
    std::vector<uint8_t> bytes(count);
    auto result = process.read(address, bytes.data(), bytes.size());
    if (!result) return std::unexpected(result.error().message());
    if (*result > count || (!string && *result != count) || *result == 0)
        return std::unexpected("Incomplete memory read");
    bytes.resize(*result);
    return decodeTypedValue(type,bytes,options);
}

std::expected<std::string,std::string> decodeTypedValue(
    ValueType type,std::span<const uint8_t> bytes,ValueIoOptions options) {
    if (type != ValueType::ByteArray && type != ValueType::String && options.byteOrder &&
        *options.byteOrder != ByteOrder::Little && *options.byteOrder != ByteOrder::Big)
        return std::unexpected("Invalid captured data byte order");
    const int scalar=width(type,options);
    if (type==ValueType::Pointer && scalar!=4 && scalar!=8)
        return std::unexpected("Captured pointer width must be 4 or 8 bytes");
    const bool string=type==ValueType::String || type==ValueType::UnicodeString;
    if (!scalar && !string && type!=ValueType::ByteArray)
        return std::unexpected("This type describes a scan, not a single readable value");
    if (options.codec.active() && !integer(type)) return std::unexpected("Value codecs require an integer or pointer type");
    if (bytes.empty() || (scalar && bytes.size()!=static_cast<size_t>(scalar)))
        return std::unexpected("Captured value has an incomplete or incorrect width");
    if (options.byteOrder==ByteOrder::Unknown && (scalar>1 || type==ValueType::UnicodeString))
        return std::unexpected("Captured value byte order is unknown");
    if (string) {
        auto encoding = type == ValueType::UnicodeString
            ? (bigEndianEncoding(options) ? "UTF-16BE" : "UTF-16LE") : options.encoding;
        try { (void)encodeStringBytes("", encoding); }
        catch (const std::invalid_argument& error) { return std::unexpected(error.what()); }
        auto text = decodeStringBytes(bytes.data(), bytes.size(), encoding);
        if (auto end = text.find('\0'); end != std::string::npos) text.resize(end);
        return text;
    }
    if (type == ValueType::ByteArray) {
        std::string text;
        constexpr char digits[] = "0123456789ABCDEF";
        for (auto byte : bytes) {
            if (!text.empty()) text += ' ';
            text += digits[byte >> 4]; text += digits[byte & 15];
        }
        return text;
    }
    uint64_t bits = *decodeTargetUnsigned(bytes, bigEndianEncoding(options) ? ByteOrder::Big : ByteOrder::Little);
    if (options.codec.active()) bits = options.codec.decode(bits, scalar);
    if (integer(type)) return formatIntegerScalar(bits, scalar, options.isSigned && type != ValueType::Pointer,
                                                 options.hex || type == ValueType::Pointer);
    if (type == ValueType::Float) return formatFloatScalar(std::bit_cast<float>(static_cast<uint32_t>(bits)), false);
    return formatFloatScalar(std::bit_cast<double>(bits), true);
}

std::expected<int, std::string> compareTypedValue(
    ProcessHandle& process, uintptr_t address, ValueType type, std::string_view value, ValueIoOptions options) {
    if (auto error = resolveTargetOptions(process, address, type, options)) return std::unexpected(*error);
    int count = width(type, options);
    if (count <= 0) return std::unexpected("Directional freeze requires a numeric type");
    auto desired = encodeTypedValue(type, value, options);
    if (!desired) return std::unexpected(desired.error());
    if (static_cast<size_t>(count - 1) > UINTPTR_MAX - address) return std::unexpected("The read range overflows the address space");
    std::vector<uint8_t> current(count);
    auto result = process.read(address, current.data(), current.size());
    if (!result) return std::unexpected(result.error().message());
    if (*result != current.size()) return std::unexpected("Incomplete memory read");
    auto decode = [&](std::vector<uint8_t>& bytes) {
        uint64_t bits = *decodeTargetUnsigned(bytes, bigEndianEncoding(options) ? ByteOrder::Big : ByteOrder::Little);
        return options.codec.active() ? options.codec.decode(bits, count) : bits;
    };
    auto left = decode(current), right = decode(*desired);
    if (integer(type)) {
        if (options.isSigned && type != ValueType::Pointer) {
            // Flipping the sign bit maps signed order to unsigned order at this width.
            left ^= uint64_t{1} << (count * 8 - 1);
            right ^= uint64_t{1} << (count * 8 - 1);
        }
        return left < right ? -1 : (left > right ? 1 : 0);
    }
    double leftNumber, rightNumber;
    if (type == ValueType::Float) {
        float first = std::bit_cast<float>(static_cast<uint32_t>(left));
        float second = std::bit_cast<float>(static_cast<uint32_t>(right));
        leftNumber = first; rightNumber = second;
    } else {
        leftNumber = std::bit_cast<double>(left); rightNumber = std::bit_cast<double>(right);
    }
    return leftNumber < rightNumber ? -1 : (leftNumber > rightNumber ? 1 : 0);
}

std::expected<size_t, std::string> writeTypedValue(
    ProcessHandle& process, uintptr_t address, ValueType type, std::string_view value, ValueIoOptions options) {
    if (auto error = resolveTargetOptions(process, address, type, options)) return std::unexpected(*error);
    auto bytes = encodeTypedValue(type, value, options);
    if (!bytes) return std::unexpected(bytes.error());
    if (!bytes->empty() && bytes->size() - 1 > UINTPTR_MAX - address) return std::unexpected("The write range overflows the address space");
    if (bytes->empty()) return size_t{0};
    auto result = process.write(address, bytes->data(), bytes->size());
    if (!result) return std::unexpected(result.error().message());
    if (*result != bytes->size()) return std::unexpected("Incomplete memory write");
    return *result;
}

} // namespace ce
