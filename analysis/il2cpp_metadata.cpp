#include "analysis/il2cpp_metadata.hpp"

#include <cstring>
#include <filesystem>

namespace ce {

namespace {

constexpr uint32_t kIl2CppMagic = 0xFAB11BAFu;

// global-metadata.dat is little-endian (every IL2CPP target is LE).
uint16_t rdU16(const uint8_t* p) {
    return static_cast<uint16_t>(static_cast<uint16_t>(p[0]) |
                                 static_cast<uint16_t>(p[1]) << 8);
}
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

// Deeper-table header field offsets. In the standard Il2CppGlobalMetadataHeader
// the fields/typeDefinitions/images (offset,size) pairs sit at these fixed byte
// positions; the version differences live in later sections (custom attributes),
// so these prefix positions are shared across the versions we decode (29..31).
//   0x60 fieldsOffset            0x64 fieldsSize
//   0xA0 typeDefinitionsOffset   0xA4 typeDefinitionsSize
//   0xA8 imagesOffset            0xAC imagesSize
constexpr size_t kOffFields = 0x60;
constexpr size_t kOffTypeDefs = 0xA0;
constexpr size_t kOffImages = 0xA8;
constexpr size_t kTableHeaderEnd = 0xB0;  // must be able to read through 0xAC+4

// Per-version record layout for the tables we decode. Only the fields that this
// parser actually reads are described; every offset is transcribed from public
// IL2CPP reversing references and validated synthetically (see the .hpp note).
struct TableLayout {
    size_t typeDefSize;        // sizeof(Il2CppTypeDefinition)
    size_t tdNameOff;          // StringIndex nameIndex
    size_t tdNamespaceOff;     // StringIndex namespaceIndex
    size_t tdFieldStartOff;    // FieldIndex fieldStart (int32)
    size_t tdFieldCountOff;    // uint16 field_count
    size_t tdTokenOff;         // uint32 token
    size_t imageSize;          // sizeof(Il2CppImageDefinition)
    size_t imgNameOff;         // StringIndex nameIndex
    size_t imgTypeStartOff;    // TypeDefinitionIndex typeStart (int32)
    size_t imgTypeCountOff;    // uint32 typeCount
};
constexpr size_t kFieldRecSize = 12;   // {int32 name; int32 type; uint32 token}
constexpr size_t kFieldNameOff = 0;
constexpr size_t kFieldTypeOff = 4;
constexpr size_t kFieldTokenOff = 8;

// v29..v31 (Unity 2021.2+): byrefTypeIndex was removed at metadata v27.2, so the
// Il2CppTypeDefinition here has no byref field and is 0x58 bytes. The v24/v27
// (byref present, 0x5C) layouts are deliberately not enabled yet: the integer
// version field can't distinguish v27.0 (byref) from v27.2 (no byref), so they
// need a real-file / binary cross-check before being trusted (roadmap follow-up).
constexpr TableLayout kLayoutV29{
    /*typeDefSize*/ 0x58,
    /*tdNameOff*/ 0x00, /*tdNamespaceOff*/ 0x04,
    /*tdFieldStartOff*/ 0x20, /*tdFieldCountOff*/ 0x44, /*tdTokenOff*/ 0x54,
    /*imageSize*/ 0x28,
    /*imgNameOff*/ 0x00, /*imgTypeStartOff*/ 0x08, /*imgTypeCountOff*/ 0x0C};

const TableLayout* layoutFor(int32_t version) {
    switch (version) {
        case 29:
        case 30:
        case 31:
            return &kLayoutV29;
        default:
            return nullptr;
    }
}

// A declared [offset, offset+size) region must lie wholly inside the buffer.
bool regionValid(int32_t off, int32_t size, size_t total) {
    return off >= 0 && size >= 0 &&
        static_cast<uint64_t>(off) + static_cast<uint64_t>(size) <=
            static_cast<uint64_t>(total);
}

// Read a NUL-terminated identifier at byte offset `idx` within the string region
// [strOff, strOff+strSize). StringIndex values in the tables are byte offsets
// into this region, not array indices. Returns "" for an out-of-range index.
std::string stringAt(const uint8_t* data, int32_t strOff, int32_t strSize, int32_t idx) {
    if (idx < 0 || idx >= strSize) return {};
    const char* s = reinterpret_cast<const char*>(data + strOff + idx);
    const size_t maxLen = static_cast<size_t>(strSize - idx);
    return std::string(s, ::strnlen(s, maxLen));
}

// Decode the type/field/image tables into `md`. Returns true (and sets
// md.tablesDecoded) only if the version is supported, the header is large enough,
// and every table region lies inside the buffer. Any malformed per-record index
// is clamped/skipped rather than aborting the whole decode.
bool decodeTables(const uint8_t* data, size_t size, Il2CppMetadata& md,
                  int32_t strOff, int32_t strSize) {
    const TableLayout* L = layoutFor(md.version);
    if (!L) return false;
    if (size < kTableHeaderEnd) return false;

    const int32_t fieldsOff = rdI32(data + kOffFields);
    const int32_t fieldsSize = rdI32(data + kOffFields + 4);
    const int32_t tdOff = rdI32(data + kOffTypeDefs);
    const int32_t tdSize = rdI32(data + kOffTypeDefs + 4);
    const int32_t imgOff = rdI32(data + kOffImages);
    const int32_t imgSize = rdI32(data + kOffImages + 4);

    if (!regionValid(fieldsOff, fieldsSize, size) ||
        !regionValid(tdOff, tdSize, size) ||
        !regionValid(imgOff, imgSize, size))
        return false;

    const size_t nFields = static_cast<size_t>(fieldsSize) / kFieldRecSize;
    const size_t nTypes = static_cast<size_t>(tdSize) / L->typeDefSize;
    const size_t nImages = static_cast<size_t>(imgSize) / L->imageSize;

    // Fields (a flat table; each type references a [start,count) slice of it).
    std::vector<Il2CppFieldDef> allFields;
    allFields.reserve(nFields);
    for (size_t k = 0; k < nFields; ++k) {
        const uint8_t* rec = data + fieldsOff + k * kFieldRecSize;
        Il2CppFieldDef f;
        f.name = stringAt(data, strOff, strSize, rdI32(rec + kFieldNameOff));
        f.typeIndex = rdI32(rec + kFieldTypeOff);
        f.token = rdU32(rec + kFieldTokenOff);
        allFields.push_back(std::move(f));
    }

    // Type definitions.
    md.types.reserve(nTypes);
    for (size_t k = 0; k < nTypes; ++k) {
        const uint8_t* rec = data + tdOff + k * L->typeDefSize;
        Il2CppTypeDef t;
        t.name = stringAt(data, strOff, strSize, rdI32(rec + L->tdNameOff));
        t.namespaceName = stringAt(data, strOff, strSize, rdI32(rec + L->tdNamespaceOff));
        t.token = rdU32(rec + L->tdTokenOff);
        const int32_t fieldStart = rdI32(rec + L->tdFieldStartOff);
        const uint16_t fieldCount = rdU16(rec + L->tdFieldCountOff);
        if (fieldStart >= 0 &&
            static_cast<uint64_t>(fieldStart) + fieldCount <= nFields) {
            t.fields.assign(allFields.begin() + fieldStart,
                            allFields.begin() + fieldStart + fieldCount);
        }
        md.types.push_back(std::move(t));
    }

    // Images (assemblies): name + the run of types each owns.
    md.images.reserve(nImages);
    for (size_t k = 0; k < nImages; ++k) {
        const uint8_t* rec = data + imgOff + k * L->imageSize;
        Il2CppImageDef img;
        img.name = stringAt(data, strOff, strSize, rdI32(rec + L->imgNameOff));
        const uint32_t typeStart = rdU32(rec + L->imgTypeStartOff);
        const uint32_t typeCount = rdU32(rec + L->imgTypeCountOff);
        if (static_cast<uint64_t>(typeStart) + typeCount <= nTypes) {
            img.typeStart = typeStart;
            img.typeCount = typeCount;
        }
        md.images.push_back(std::move(img));
    }

    md.tablesDecoded = true;
    return true;
}

} // namespace

namespace {

// A mapped file worth deriving game directories from: the Unity player
// executable, GameAssembly.so, UnityPlayer.so, libil2cpp.so, or anything already
// under a `*_Data` tree. Filters out libc and other system mappings so the
// directory scan below never trawls /usr/lib.
bool gameRelevantPath(const std::string& p) {
    namespace fs = std::filesystem;
    const std::string base = fs::path(p).filename().string();
    if (base == "GameAssembly.so" || base == "GameAssembly.dll" ||
        base == "UnityPlayer.so" || base == "libil2cpp.so")
        return true;
    if (p.find("_Data/") != std::string::npos) return true;
    auto endsWith = [&](const char* s) {
        const size_t n = std::strlen(s);
        return base.size() >= n && base.compare(base.size() - n, n, s) == 0;
    };
    return endsWith(".x86_64") || endsWith(".x86");
}

bool metadataUnder(const std::filesystem::path& dir, std::string& out) {
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::path cand = dir / "il2cpp_data" / "Metadata" / "global-metadata.dat";
    if (fs::is_regular_file(cand, ec)) { out = cand.string(); return true; }
    return false;
}

bool endsWithData(const std::string& name) {
    return name.size() > 5 && name.compare(name.size() - 5, 5, "_Data") == 0;
}

} // namespace

std::optional<std::string> findIl2CppMetadataPath(const std::vector<std::string>& mappedPaths) {
    namespace fs = std::filesystem;
    std::vector<fs::path> dirs;
    auto addDir = [&](const fs::path& d) {
        if (d.empty()) return;
        for (const auto& e : dirs) if (e == d) return;   // dedup
        dirs.push_back(d);
    };

    for (const auto& p : mappedPaths) {
        if (p.empty() || p[0] != '/' || !gameRelevantPath(p)) continue;
        fs::path path(p);
        addDir(path.parent_path());
        // If a path component IS a `*_Data` dir, that dir holds the metadata tree.
        fs::path prefix;
        for (const auto& comp : path) {
            prefix /= comp;
            if (endsWithData(comp.string())) addDir(prefix);
        }
    }

    std::string out;
    // 1) A candidate dir is itself the `*_Data` dir.
    for (const auto& d : dirs)
        if (metadataUnder(d, out)) return out;
    // 2) A `*_Data` dir living next to the executable (candidate dir's child).
    for (const auto& d : dirs) {
        std::error_code ec;
        fs::directory_iterator it(d, ec), end;
        if (ec) continue;
        for (size_t seen = 0; it != end && seen < 4096; it.increment(ec), ++seen) {
            if (ec) break;
            std::error_code ec2;
            if (!it->is_directory(ec2)) continue;
            if (endsWithData(it->path().filename().string()) &&
                metadataUnder(it->path(), out))
                return out;
        }
    }
    return std::nullopt;
}

bool isIl2CppMetadata(const uint8_t* data, size_t size) {
    return data && size >= 4 && rdU32(data + kOffSanity) == kIl2CppMagic;
}

bool il2cppTablesSupported(int32_t version) { return layoutFor(version) != nullptr; }

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

    // Deeper tables (optional; only for supported versions with valid regions).
    // A failure here is non-fatal: the string pools above are still returned.
    decodeTables(data, size, md, strOff, strSize);

    return md;
}

} // namespace ce
