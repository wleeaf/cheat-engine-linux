#include "analysis/structure_tools.hpp"

#include <algorithm>
#include <bit>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace ce {

namespace {

std::string sanitizeIdentifier(const std::string& input, const std::string& fallback) {
    std::string out;
    for (unsigned char c : input) {
        if (std::isalnum(c) || c == '_')
            out.push_back(static_cast<char>(c));
        else if (!out.empty() && out.back() != '_')
            out.push_back('_');
    }

    while (!out.empty() && out.back() == '_')
        out.pop_back();
    if (out.empty())
        out = fallback;
    if (std::isdigit(static_cast<unsigned char>(out.front())))
        out.insert(out.begin(), '_');
    return out;
}

// The C++ type for a field of `size` bytes. The type follows the size, so a
// 4-byte pointer of a 32-bit target is uint32_t, not the host's uintptr_t, and
// a size that does not fit the value type becomes a byte array.
std::string cppTypeFor(ValueType type, size_t size) {
    switch (type) {
        case ValueType::Byte:
            if (size == 1) return "uint8_t";
            break;
        case ValueType::Int16:
        case ValueType::Int32:
        case ValueType::Int64:
            if (size == 1) return "int8_t";
            if (size == 2) return "int16_t";
            if (size == 4) return "int32_t";
            if (size == 8) return "int64_t";
            break;
        case ValueType::Pointer:
            if (size == 4) return "uint32_t";
            if (size == 8) return "uint64_t";
            break;
        case ValueType::Float:
            if (size == 4) return "float";
            break;
        case ValueType::Double:
            if (size == 8) return "double";
            break;
        default:
            break;
    }
    return "uint8_t[" + std::to_string(std::max<size_t>(1, size)) + "]";
}

ByteOrder hostByteOrder() {
    return std::endian::native == std::endian::big ? ByteOrder::Big : ByteOrder::Little;
}

// A target pointer of `width` bytes in `order` at `address`.
std::optional<uintptr_t> readTargetPointer(ProcessHandle& proc, uintptr_t address,
                                           size_t width, ByteOrder order) {
    uint8_t bytes[8] = {};
    if (width != 4 && width != 8) return std::nullopt;
    auto read = proc.read(address, bytes, width);
    if (!read || *read != width) return std::nullopt;
    auto value = decodeTargetUnsigned({bytes, width}, order);
    if (!value) return std::nullopt;
    return static_cast<uintptr_t>(*value);
}

size_t defaultSizeFor(ValueType type, size_t explicitSize) {
    if (explicitSize != 0) return explicitSize;
    switch (type) {
        case ValueType::Byte: return 1;
        case ValueType::Int16: return 2;
        case ValueType::Int32:
        case ValueType::Float: return 4;
        case ValueType::Int64:
        case ValueType::Pointer:
        case ValueType::Double: return 8;
        default: return 1;
    }
}

ValueType suggestedTypeForRun(size_t size) {
    switch (size) {
        case 1: return ValueType::Byte;
        case 2: return ValueType::Int16;
        case 4: return ValueType::Int32;
        case 8: return ValueType::Int64;
        default: return ValueType::ByteArray;
    }
}

std::string lowerCopy(const std::string& value) {
    std::string out = value;
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

bool isReadablePointer(ProcessHandle& proc, uintptr_t address, size_t width) {
    auto region = proc.queryRegion(address);
    return region && (region->protection & MemProt::Read) &&
        address >= region->base &&
        region->size >= width &&
        address <= region->base + region->size - width;
}

template<typename T>
bool readSnapshotValue(const std::vector<uint8_t>& snapshot, size_t offset, T& out) {
    if (offset > snapshot.size() || snapshot.size() - offset < sizeof(T))
        return false;
    std::memcpy(&out, snapshot.data() + offset, sizeof(T));
    return true;
}

} // namespace

bool saveStructureTemplate(const StructureDefinition& structure, const std::string& path) {
    CheatTable table;
    table.structures.push_back(structure);
    return table.saveJson(path);
}

std::optional<StructureDefinition> loadStructureTemplate(const std::string& path) {
    CheatTable table;
    if (!table.loadJson(path) || table.structures.empty())
        return std::nullopt;
    return table.structures.front();
}

std::string generateCppStruct(const StructureDefinition& structure) {
    auto fields = structure.fields;
    std::stable_sort(fields.begin(), fields.end(), [](const StructureField& lhs, const StructureField& rhs) {
        return lhs.offset < rhs.offset;
    });

    const std::string structName = sanitizeIdentifier(structure.name, "GeneratedStruct");
    std::ostringstream out;
    // Packed with explicit padding, so each member sits at its dissected offset
    // whatever the compiler's alignment rules; the static_asserts check it.
    out << "#include <cstddef>\n#include <cstdint>\n\n";
    out << "#pragma pack(push, 1)\n";
    out << "struct " << structName << " {\n";
    std::vector<std::pair<std::string, size_t>> placed;

    size_t cursor = 0;
    size_t padIndex = 0;
    for (const auto& field : fields) {
        const size_t fieldSize = defaultSizeFor(field.type, field.size);
        if (field.offset < cursor) {
            // C++ cannot place a member at a lower offset than the running
            // cursor, so emitting this field back-to-back would silently put it
            // at the wrong offset. Flag and skip it to keep the generated layout
            // consistent with the offset comments (cursor stays unchanged so all
            // following fields and padding remain correct).
            const auto skippedName = sanitizeIdentifier(field.name,
                "field_" + std::to_string(field.offset));
            out << "    // " << skippedName << " at 0x" << std::hex << field.offset
                << " overlaps previous field (ends at 0x" << cursor << std::dec
                << "); omitted to preserve layout\n";
            continue;
        }
        if (field.offset > cursor) {
            out << "    uint8_t _pad" << padIndex++ << "[0x"
                << std::hex << (field.offset - cursor) << std::dec << "];\n";
            cursor = field.offset;
        }

        const auto type = field.nestedStructure.empty()
            ? cppTypeFor(field.type, fieldSize)
            : sanitizeIdentifier(field.nestedStructure, "NestedStruct");
        const auto name = sanitizeIdentifier(field.name, "field_" + std::to_string(field.offset));
        auto arrayStart = type.find('[');
        if (arrayStart == std::string::npos) {
            out << "    " << type << " " << name << "; // 0x"
                << std::hex << field.offset << std::dec << "\n";
        } else {
            out << "    " << type.substr(0, arrayStart) << " " << name
                << type.substr(arrayStart) << "; // 0x"
                << std::hex << field.offset << std::dec << "\n";
        }
        placed.emplace_back(name, field.offset);
        cursor = std::max(cursor, field.offset + fieldSize);
    }

    if (structure.size > cursor) {
        out << "    uint8_t _pad" << padIndex++ << "[0x"
            << std::hex << (structure.size - cursor) << std::dec << "];\n";
        cursor = structure.size;
    }

    out << "};\n";
    out << "#pragma pack(pop)\n\n";
    for (const auto& [name, offset] : placed)
        out << "static_assert(offsetof(" << structName << ", " << name << ") == 0x"
            << std::hex << offset << std::dec << ");\n";
    out << "static_assert(sizeof(" << structName << ") == 0x" << std::hex << cursor << std::dec << ");\n";
    return out.str();
}

std::vector<StructureFieldDiff> compareStructureSnapshots(const StructureDefinition& structure,
    const std::vector<uint8_t>& before,
    const std::vector<uint8_t>& after)
{
    std::vector<StructureFieldDiff> diffs;
    for (const auto& field : structure.fields) {
        const size_t fieldSize = defaultSizeFor(field.type, field.size);
        if (fieldSize == 0 || field.offset >= before.size() || field.offset >= after.size())
            continue;

        const size_t beforeSize = std::min(fieldSize, before.size() - field.offset);
        const size_t afterSize = std::min(fieldSize, after.size() - field.offset);
        const size_t compareSize = std::min(beforeSize, afterSize);
        if (compareSize == 0)
            continue;

        StructureFieldDiff diff;
        diff.name = field.name;
        diff.offset = field.offset;
        diff.size = compareSize;
        auto beforeStart = before.begin() + static_cast<std::vector<uint8_t>::difference_type>(field.offset);
        auto afterStart = after.begin() + static_cast<std::vector<uint8_t>::difference_type>(field.offset);
        diff.before.assign(beforeStart,
            beforeStart + static_cast<std::vector<uint8_t>::difference_type>(compareSize));
        diff.after.assign(afterStart,
            afterStart + static_cast<std::vector<uint8_t>::difference_type>(compareSize));
        diff.changed = std::memcmp(diff.before.data(), diff.after.data(), compareSize) != 0;
        diffs.push_back(std::move(diff));
    }
    return diffs;
}

std::vector<StructureDetectedField> autoDetectStructureFields(const std::vector<uint8_t>& before,
    const std::vector<uint8_t>& after)
{
    // The two-snapshot case is exactly N=2 of the multi-instance detector.
    return autoDetectStructureFieldsMulti({before, after});
}

std::vector<StructureDetectedField> autoDetectStructureFieldsMulti(
    const std::vector<std::vector<uint8_t>>& snapshots)
{
    std::vector<StructureDetectedField> fields;
    if (snapshots.empty())
        return fields;

    // Compare over the common prefix length so a short snapshot never drives an
    // out-of-bounds read; anything past the shortest instance is undetectable.
    size_t size = snapshots.front().size();
    for (const auto& snapshot : snapshots)
        size = std::min(size, snapshot.size());
    if (size == 0)
        return fields;

    const auto& base = snapshots.front();
    const auto byteVaries = [&](size_t index) {
        for (size_t s = 1; s < snapshots.size(); ++s)
            if (snapshots[s][index] != base[index])
                return true;
        return false;
    };

    size_t start = 0;
    bool currentChanged = byteVaries(0);
    for (size_t i = 1; i < size; ++i) {
        bool changed = byteVaries(i);
        if (changed == currentChanged)
            continue;

        const size_t runSize = i - start;
        fields.push_back(StructureDetectedField{
            .offset = start,
            .size = runSize,
            .changed = currentChanged,
            .suggestedType = suggestedTypeForRun(runSize),
        });
        start = i;
        currentChanged = changed;
    }

    const size_t runSize = size - start;
    fields.push_back(StructureDetectedField{
        .offset = start,
        .size = runSize,
        .changed = currentChanged,
        .suggestedType = suggestedTypeForRun(runSize),
    });
    return fields;
}

std::vector<StructurePointerChain> followStructurePointers(ProcessHandle& proc,
    uintptr_t baseAddress,
    const StructureDefinition& structure,
    size_t maxDepth)
{
    std::vector<StructurePointerChain> chains;
    if (maxDepth == 0)
        return chains;
    // Pointers are decoded as the target stores them; without a known width
    // and byte order there is nothing safe to follow.
    const size_t width = proc.pointerWidth();
    const ByteOrder order = proc.byteOrder();
    if ((width != 4 && width != 8) || width > sizeof(uintptr_t) || order == ByteOrder::Unknown)
        return chains;

    for (const auto& field : structure.fields) {
        if (field.type != ValueType::Pointer)
            continue;

        // The field's own width when it names one (a 32-bit offset field in a
        // 64-bit target), else the target's.
        const size_t fieldWidth = field.size == 4 || field.size == 8 ? field.size : width;
        auto first = readTargetPointer(proc, baseAddress + field.offset, fieldWidth, order);
        if (!first || *first == 0)
            continue;
        const uintptr_t pointer = *first;

        StructurePointerChain chain;
        chain.fieldName = field.name;
        chain.fieldOffset = field.offset;
        chain.addresses.push_back(pointer);

        uintptr_t current = pointer;
        for (size_t depth = 1; depth < maxDepth; ++depth) {
            if (!isReadablePointer(proc, current, width))
                break;

            auto next = readTargetPointer(proc, current, width, order);
            if (!next || *next == 0)
                break;

            chain.addresses.push_back(*next);
            current = *next;
        }

        chains.push_back(std::move(chain));
    }

    return chains;
}

std::string formatStructureFieldValue(const StructureField& field,
    const std::vector<uint8_t>& snapshot, ByteOrder order)
{
    if (order == ByteOrder::Unknown) order = hostByteOrder();
    const size_t fieldSize = defaultSizeFor(field.type, field.size);
    if (fieldSize == 0 || field.offset >= snapshot.size())
        return {};

    const size_t available = std::min(fieldSize, snapshot.size() - field.offset);
    auto method = lowerCopy(field.displayMethod);
    if (method.empty()) {
        switch (field.type) {
            case ValueType::Float:
            case ValueType::Double:
                method = "float";
                break;
            case ValueType::Pointer:
                method = "pointer";
                break;
            case ValueType::ByteArray:
            case ValueType::String:
            case ValueType::UnicodeString:
                method = "hex";
                break;
            default:
                method = "signed";
                break;
        }
    }

    std::ostringstream out;
    if (method == "hex" || method == "bytes") {
        out << std::hex << std::setfill('0');
        for (size_t i = 0; i < available; ++i) {
            if (i) out << ' ';
            out << std::setw(2) << static_cast<unsigned>(snapshot[field.offset + i]);
        }
        return out.str();
    }

    if (method == "pointer") {
        // The field's width (a 32-bit target's pointer is 4 bytes), not the host's.
        const size_t width = fieldSize == 4 ? 4 : 8;
        if (available < width)
            return {};
        auto value = decodeTargetUnsigned({snapshot.data() + field.offset, width}, order);
        if (!value)
            return {};
        out << "0x" << std::hex << *value;
        return out.str();
    }

    // The numeric formats below read host-order values: put the field's bytes
    // in host order first.
    std::vector<uint8_t> local(snapshot.begin() + static_cast<std::ptrdiff_t>(field.offset),
                               snapshot.begin() + static_cast<std::ptrdiff_t>(field.offset + available));
    if (order != hostByteOrder())
        std::reverse(local.begin(), local.end());

    if (method == "float") {
        if (field.type == ValueType::Double || fieldSize == sizeof(double)) {
            double value = 0;
            if (!readSnapshotValue(local, 0, value))
                return {};
            out << value;
            return out.str();
        }
        float value = 0;
        if (!readSnapshotValue(local, 0, value))
            return {};
        out << value;
        return out.str();
    }

    if (method == "unsigned") {
        uint64_t value = 0;
        const size_t copySize = std::min(available, sizeof(value));
        std::memcpy(&value, local.data(), copySize);
        out << value;
        return out.str();
    }

    int64_t value = 0;
    switch (std::min(available, sizeof(value))) {
        case 1: {
            int8_t v = 0;
            std::memcpy(&v, local.data(), sizeof(v));
            value = v;
            break;
        }
        case 2: {
            int16_t v = 0;
            std::memcpy(&v, local.data(), sizeof(v));
            value = v;
            break;
        }
        case 4: {
            int32_t v = 0;
            std::memcpy(&v, local.data(), sizeof(v));
            value = v;
            break;
        }
        default:
            std::memcpy(&value, local.data(), std::min(available, sizeof(value)));
            break;
    }
    out << value;
    return out.str();
}

StructureDefinition il2cppClassToStructure(const Il2CppClassLayout& cls) {
    StructureDefinition def;
    def.name = cls.fullName();

    struct F { std::string name; size_t offset; uint8_t typeEnum; };
    std::vector<F> insts;
    insts.reserve(cls.fields.size());
    for (const auto& f : cls.fields)
        if (!f.isStatic && !f.isConst)
            insts.push_back({f.name, static_cast<size_t>(f.offset < 0 ? 0 : f.offset), f.typeEnum});
    std::sort(insts.begin(), insts.end(), [](const F& a, const F& b) { return a.offset < b.offset; });

    for (size_t i = 0; i < insts.size(); ++i) {
        StructureField sf;
        sf.name = insts[i].name;
        sf.offset = insts[i].offset;
        sf.type = il2cppTypeEnumToValueType(insts[i].typeEnum);
        size_t sz = il2cppTypeEnumSize(insts[i].typeEnum);
        if (sz == 0) {
            // Embedded value type: width = gap to the next field (>= 4 as a floor).
            size_t next = (i + 1 < insts.size()) ? insts[i + 1].offset : sf.offset + 4;
            sz = next > sf.offset ? next - sf.offset : 4;
        }
        sf.size = sz;
        def.fields.push_back(std::move(sf));
    }
    if (!def.fields.empty()) {
        const auto& last = def.fields.back();
        def.size = last.offset + last.size;
    }
    return def;
}

StructureDefinition dwarfStructToStructure(const DwarfStruct& s) {
    StructureDefinition def;
    def.name = s.name;
    def.size = s.size;
    for (const auto& m : s.members) {
        StructureField sf;
        sf.name = m.name;
        sf.offset = static_cast<size_t>(m.offset);
        sf.size = static_cast<size_t>(m.size);
        if (m.isPointer) {
            sf.type = ValueType::Pointer;
            if (sf.size == 0) sf.size = 8;
        } else if (m.isFloat) {
            sf.type = (m.size == 8) ? ValueType::Double : ValueType::Float;
        } else {
            switch (m.size) {
                case 1: sf.type = ValueType::Byte; break;
                case 2: sf.type = ValueType::Int16; break;
                case 4: sf.type = ValueType::Int32; break;
                case 8: sf.type = ValueType::Int64; break;
                default: sf.type = ValueType::ByteArray; break;   // embedded struct/array
            }
        }
        def.fields.push_back(std::move(sf));
    }
    if (def.size == 0 && !def.fields.empty()) {
        const auto& last = def.fields.back();
        def.size = last.offset + (last.size ? last.size : 1);
    }
    return def;
}

} // namespace ce
