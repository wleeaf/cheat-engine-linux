#include "analysis/il2cpp_binary.hpp"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>

namespace ce {

namespace {

// ── A loaded GameAssembly image (PE or ELF), providing VA/RVA -> file reads ──
//
// `imageBase` is the link-time base (PE OptionalHeader.ImageBase; 0 for a PIE
// ELF, where virtual addresses already equal RVAs). A "segment" is a loadable
// range mapping [rva, rva+vsize) to file bytes [fileOff, fileOff+fileSize).
struct Image {
    std::vector<uint8_t> buf;
    uint64_t imageBase = 0;
    struct Segment { uint64_t rva, vsize; uint64_t fileOff, fileSize; };
    std::vector<Segment> segs;

    bool inRange(size_t off, size_t n) const { return off + n <= buf.size() && off + n >= off; }
    uint16_t u16(size_t o) const { uint16_t v = 0; std::memcpy(&v, buf.data() + o, 2); return v; }
    uint32_t u32(size_t o) const { uint32_t v = 0; std::memcpy(&v, buf.data() + o, 4); return v; }
    uint64_t u64(size_t o) const { uint64_t v = 0; std::memcpy(&v, buf.data() + o, 8); return v; }

    // Virtual address (or RVA when imageBase==0) -> file offset.
    std::optional<size_t> rvaToOff(uint64_t rva) const {
        for (const auto& s : segs) {
            if (rva >= s.rva && rva < s.rva + s.vsize) {
                uint64_t d = rva - s.rva;
                if (d < s.fileSize) {
                    uint64_t off = s.fileOff + d;
                    if (off < buf.size()) return static_cast<size_t>(off);
                }
                return std::nullopt;  // in the bss tail (no file bytes)
            }
        }
        return std::nullopt;
    }
    std::optional<size_t> vaToOff(uint64_t va) const {
        if (va < imageBase) return std::nullopt;
        return rvaToOff(va - imageBase);
    }
    bool vaValid(uint64_t va) const { return va >= imageBase && rvaToOff(va - imageBase).has_value(); }

    std::optional<uint64_t> readPtrVA(uint64_t va) const {
        auto o = vaToOff(va); if (!o || !inRange(*o, 8)) return std::nullopt; return u64(*o);
    }
    std::optional<int32_t> readI32VA(uint64_t va) const {
        auto o = vaToOff(va); if (!o || !inRange(*o, 4)) return std::nullopt;
        return static_cast<int32_t>(u32(*o));
    }
    std::optional<uint32_t> readU32VA(uint64_t va) const {
        auto o = vaToOff(va); if (!o || !inRange(*o, 4)) return std::nullopt; return u32(*o);
    }
    std::string readCStrVA(uint64_t va, size_t maxLen = 256) const {
        auto o = vaToOff(va);
        if (!o) return {};
        std::string s;
        for (size_t i = 0; i < maxLen && *o + i < buf.size(); ++i) {
            char c = static_cast<char>(buf[*o + i]);
            if (c == '\0') break;
            s.push_back(c);
        }
        return s;
    }
};

bool loadPE(Image& img) {
    const auto& b = img.buf;
    if (b.size() < 0x40 || b[0] != 'M' || b[1] != 'Z') return false;
    uint32_t e = img.u32(0x3C);
    if (!img.inRange(e, 24) || std::memcmp(b.data() + e, "PE\0\0", 4) != 0) return false;
    size_t coff = e + 4;
    if (!img.inRange(coff, 20)) return false;
    uint16_t machine = img.u16(coff + 0);
    if (machine != 0x8664) return false;             // x86-64 only (IL2CPP targets)
    uint16_t nSec = img.u16(coff + 2);
    uint16_t optSize = img.u16(coff + 16);
    size_t opt = coff + 20;
    if (!img.inRange(opt, optSize)) return false;
    if (img.u16(opt) != 0x20B) return false;         // PE32+ (magic)
    img.imageBase = img.u64(opt + 24);
    size_t secTbl = opt + optSize;
    for (uint16_t k = 0; k < nSec; ++k) {
        size_t so = secTbl + static_cast<size_t>(k) * 40;
        if (!img.inRange(so, 40)) break;
        uint64_t vsize = img.u32(so + 8);
        uint64_t vaddr = img.u32(so + 12);
        uint64_t rawSize = img.u32(so + 16);
        uint64_t rawPtr = img.u32(so + 20);
        img.segs.push_back({vaddr, std::max(vsize, rawSize), rawPtr, rawSize});
    }
    return !img.segs.empty();
}

bool loadELF64(Image& img) {
    const auto& b = img.buf;
    if (b.size() < 0x40 || std::memcmp(b.data(), "\x7f""ELF", 4) != 0) return false;
    if (b[4] != 2) return false;                     // ELFCLASS64
    img.imageBase = 0;                               // PIE .so: VA == RVA
    uint64_t phoff = img.u64(0x20);
    uint16_t phentsize = img.u16(0x36);
    uint16_t phnum = img.u16(0x38);
    for (uint16_t k = 0; k < phnum; ++k) {
        size_t po = static_cast<size_t>(phoff) + static_cast<size_t>(k) * phentsize;
        if (!img.inRange(po, 56)) break;
        if (img.u32(po + 0) != 1) continue;          // PT_LOAD
        uint64_t off = img.u64(po + 8);
        uint64_t vaddr = img.u64(po + 16);
        uint64_t filesz = img.u64(po + 32);
        uint64_t memsz = img.u64(po + 40);
        img.segs.push_back({vaddr, std::max(memsz, filesz), off, filesz});
    }
    return !img.segs.empty();
}

// Il2CppMetadataRegistration field byte offsets (x64), shared by metadata v27-31
// (these fields precede the version-specific tail). Every pointer is 8 bytes.
constexpr size_t kMR_typesCount = 0x30;
constexpr size_t kMR_types = 0x38;
constexpr size_t kMR_fieldOffsetsCount = 0x50;
constexpr size_t kMR_fieldOffsets = 0x58;
constexpr size_t kMR_typeDefSizesCount = 0x60;

// Il2CppType is 0x10 bytes on x64; `attrs` is the low 16 bits of the u32 at +0x08.
constexpr size_t kType_attrs = 0x08;
constexpr uint16_t kFIELD_STATIC = 0x0010;
constexpr uint16_t kFIELD_LITERAL = 0x0040;

// Find Il2CppMetadataRegistration. Its fieldOffsetsCount and typeDefinitionsSizes
// Count both equal the metadata type count and sit 0x10 apart, an extremely
// specific signature; confirm by validating that the fieldOffsets array holds
// plausible per-type pointers. Returns the struct's file offset.
std::optional<size_t> findMetadataRegistration(const Image& img, size_t nTypes) {
    const int32_t want = static_cast<int32_t>(nTypes);
    for (const auto& s : img.segs) {
        if (s.fileSize < 0x70) continue;
        size_t begin = static_cast<size_t>(s.fileOff);
        size_t end = begin + static_cast<size_t>(s.fileSize);
        if (end > img.buf.size()) end = img.buf.size();
        for (size_t p = begin; p + 0x18 <= end; p += 8) {
            if (static_cast<int32_t>(img.u32(p)) != want) continue;
            if (static_cast<int32_t>(img.u32(p + 0x10)) != want) continue;
            uint64_t foVA = img.u64(p + 8);          // p is fieldOffsetsCount pos (+0x50)
            if (!img.vaValid(foVA)) continue;
            // Validate the fieldOffsets array: entries are 0 or valid VAs. (The
            // double count-match 0x10 apart is already near-unique on a real
            // binary; this and the typesCount/types confirmation below rule out
            // the rare coincidence.)
            size_t ok = 0, tot = 0;
            size_t probe = std::min<size_t>(nTypes, 256);
            for (size_t k = 0; k < probe; ++k) {
                auto e = img.readPtrVA(foVA + k * 8);
                if (!e) break;
                ++tot;
                if (*e == 0 || img.vaValid(*e)) ++ok;
            }
            if (tot == 0 || ok * 5 < tot * 4) continue;   // < 80% plausible
            if (p < kMR_fieldOffsetsCount) continue;
            size_t base = p - kMR_fieldOffsetsCount;      // struct base
            if (!img.inRange(base, 0x70)) continue;
            int32_t typesCount = static_cast<int32_t>(img.u32(base + kMR_typesCount));
            uint64_t typesVA = img.u64(base + kMR_types);
            if (typesCount < want || typesCount > 50'000'000) continue;  // types >= typeDefs
            if (!img.vaValid(typesVA)) continue;
            return base;
        }
    }
    return std::nullopt;
}

} // namespace

Il2CppBinaryLayout resolveIl2CppLayout(const Il2CppMetadata& md, const std::string& binaryPath) {
    Il2CppBinaryLayout out;
    if (!md.tablesDecoded) { out.error = "metadata tables not decoded (unsupported version)"; return out; }

    Image img;
    {
        std::ifstream in(binaryPath, std::ios::binary);
        if (!in) { out.error = "cannot open binary: " + binaryPath; return out; }
        img.buf.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }
    if (img.buf.size() < 0x40) { out.error = "binary too small"; return out; }
    if (!loadPE(img) && !loadELF64(img)) {
        out.error = "unrecognized binary (need x86-64 PE32+ or ELF64 GameAssembly)";
        return out;
    }

    const size_t nTypes = md.types.size();
    auto mr = findMetadataRegistration(img, nTypes);
    if (!mr) { out.error = "Il2CppMetadataRegistration not found (unsupported build?)"; return out; }

    if (!img.inRange(*mr + kMR_typeDefSizesCount + 4, 0)) { out.error = "registration truncated"; return out; }
    uint64_t fieldOffsetsVA = img.u64(*mr + kMR_fieldOffsets);
    uint64_t typesVA = img.u64(*mr + kMR_types);
    int32_t typesCount = static_cast<int32_t>(img.u32(*mr + kMR_typesCount));
    if (typesCount < 0) typesCount = 0;

    // Read a field's Il2CppType word: low16 = C# attrs, bits16-23 = type enum.
    auto fieldAttrs = [&](int32_t typeIndex) -> uint32_t {
        if (typeIndex < 0 || typeIndex >= typesCount) return 0u;
        auto tp = img.readPtrVA(typesVA + static_cast<uint64_t>(typeIndex) * 8);
        if (!tp) return 0u;
        auto a = img.readU32VA(*tp + kType_attrs);
        return a ? *a : 0u;   // low16 = C# field attrs; bits16-23 = Il2CppTypeEnum
    };

    // Map a global type index to its owning image name.
    auto imageNameForType = [&](size_t ti) -> std::string {
        for (const auto& im : md.images)
            if (ti >= im.typeStart && ti < static_cast<size_t>(im.typeStart) + im.typeCount)
                return im.name;
        return {};
    };

    out.classes.reserve(nTypes);
    for (size_t t = 0; t < nTypes; ++t) {
        const auto& mt = md.types[t];
        Il2CppClassLayout cl;
        cl.image = imageNameForType(t);
        cl.namespaceName = mt.namespaceName;
        cl.name = mt.name;

        // fieldOffsets[t] -> per-type int32 array (or 0 for generic defs).
        std::optional<uint64_t> entryVA = img.readPtrVA(fieldOffsetsVA + t * 8);
        for (size_t i = 0; i < mt.fields.size(); ++i) {
            Il2CppResolvedField rf;
            rf.name = mt.fields[i].name;
            uint32_t typeWord = fieldAttrs(mt.fields[i].typeIndex);
            uint16_t attrs = static_cast<uint16_t>(typeWord & 0xFFFF);
            rf.isStatic = (attrs & kFIELD_STATIC) != 0;
            rf.isConst = (attrs & kFIELD_LITERAL) != 0;
            rf.typeEnum = static_cast<uint8_t>((typeWord >> 16) & 0xFF);  // Il2CppTypeEnum
            if (entryVA && *entryVA != 0) {
                if (auto o = img.readI32VA(*entryVA + i * 4)) rf.offset = *o;
            }
            cl.fields.push_back(std::move(rf));
        }
        out.classes.push_back(std::move(cl));
    }

    out.ok = true;
    return out;
}

// Il2CppTypeEnum constants (subset we classify; the rest fall to Pointer).
namespace {
enum : uint8_t {
    IL2CPP_TYPE_BOOLEAN = 0x02, IL2CPP_TYPE_CHAR = 0x03,
    IL2CPP_TYPE_I1 = 0x04, IL2CPP_TYPE_U1 = 0x05,
    IL2CPP_TYPE_I2 = 0x06, IL2CPP_TYPE_U2 = 0x07,
    IL2CPP_TYPE_I4 = 0x08, IL2CPP_TYPE_U4 = 0x09,
    IL2CPP_TYPE_I8 = 0x0A, IL2CPP_TYPE_U8 = 0x0B,
    IL2CPP_TYPE_R4 = 0x0C, IL2CPP_TYPE_R8 = 0x0D,
    IL2CPP_TYPE_STRING = 0x0E, IL2CPP_TYPE_VALUETYPE = 0x11,
    IL2CPP_TYPE_I = 0x18, IL2CPP_TYPE_U = 0x19,
};
}

ValueType il2cppTypeEnumToValueType(uint8_t e) {
    switch (e) {
        case IL2CPP_TYPE_BOOLEAN: case IL2CPP_TYPE_I1: case IL2CPP_TYPE_U1: return ValueType::Byte;
        case IL2CPP_TYPE_CHAR: case IL2CPP_TYPE_I2: case IL2CPP_TYPE_U2:    return ValueType::Int16;
        case IL2CPP_TYPE_I4: case IL2CPP_TYPE_U4:                           return ValueType::Int32;
        case IL2CPP_TYPE_I8: case IL2CPP_TYPE_U8:                           return ValueType::Int64;
        case IL2CPP_TYPE_R4:                                               return ValueType::Float;
        case IL2CPP_TYPE_R8:                                               return ValueType::Double;
        case IL2CPP_TYPE_STRING:                                          return ValueType::Pointer;  // string ref
        case IL2CPP_TYPE_VALUETYPE:                                        return ValueType::ByteArray; // embedded
        case IL2CPP_TYPE_I: case IL2CPP_TYPE_U:                            return ValueType::Pointer;
        default:                                                          return ValueType::Pointer;  // CLASS/OBJECT/ARRAY/PTR/...
    }
}

size_t il2cppTypeEnumSize(uint8_t e) {
    switch (e) {
        case IL2CPP_TYPE_BOOLEAN: case IL2CPP_TYPE_I1: case IL2CPP_TYPE_U1: return 1;
        case IL2CPP_TYPE_CHAR: case IL2CPP_TYPE_I2: case IL2CPP_TYPE_U2:    return 2;
        case IL2CPP_TYPE_I4: case IL2CPP_TYPE_U4: case IL2CPP_TYPE_R4:      return 4;
        case IL2CPP_TYPE_I8: case IL2CPP_TYPE_U8: case IL2CPP_TYPE_R8:      return 8;
        case IL2CPP_TYPE_VALUETYPE:                                        return 0;  // infer from gap
        default:                                                          return 8;  // pointer-sized ref
    }
}

namespace {

// Il2CppCodeGenModule (x64): { const char* moduleName; uint64 methodPointerCount;
// Il2CppMethodPointer* methodPointers; ... }. One per assembly image.
constexpr size_t kCGM_moduleName = 0x00;
constexpr size_t kCGM_methodCount = 0x08;
constexpr size_t kCGM_methodPointers = 0x10;

// Find Il2CppCodeRegistration.codeGenModules: a count == the metadata image count
// followed by a pointer to an array of that many Il2CppCodeGenModule* whose
// moduleName fields are valid ".dll" strings. Returns the array VA.
std::optional<uint64_t> findCodeGenModules(const Image& img, size_t imageCount) {
    auto looksLikeModuleName = [](const std::string& s) {
        return s.size() > 4 && s.compare(s.size() - 4, 4, ".dll") == 0;
    };
    for (const auto& s : img.segs) {
        if (s.fileSize < 16) continue;
        size_t begin = static_cast<size_t>(s.fileOff);
        size_t end = std::min<size_t>(begin + s.fileSize, img.buf.size());
        for (size_t p = begin; p + 16 <= end; p += 8) {
            if (img.u64(p) != imageCount) continue;
            uint64_t arrVA = img.u64(p + 8);
            if (!img.vaValid(arrVA)) continue;
            size_t ok = 0, tot = 0, probe = std::min<size_t>(imageCount, 32);
            for (size_t i = 0; i < probe; ++i) {
                auto m = img.readPtrVA(arrVA + i * 8);
                if (!m) break;
                ++tot;
                if (*m == 0 || !img.vaValid(*m)) continue;
                auto nmp = img.readPtrVA(*m + kCGM_moduleName);
                if (nmp && img.vaValid(*nmp) && looksLikeModuleName(img.readCStrVA(*nmp))) ++ok;
            }
            if (tot >= 8 && ok * 5 >= tot * 4) return arrVA;
        }
    }
    return std::nullopt;
}

} // namespace

std::vector<Il2CppResolvedMethod>
resolveIl2CppMethods(const Il2CppMetadata& md, const std::string& binaryPath,
                     const std::string& className) {
    std::vector<Il2CppResolvedMethod> out;
    if (!md.tablesDecoded) return out;

    // Locate the class + its owning image name.
    const Il2CppTypeDef* cls = nullptr;
    size_t classIndex = 0;
    for (size_t i = 0; i < md.types.size(); ++i)
        if (md.types[i].fullName() == className) { cls = &md.types[i]; classIndex = i; break; }
    if (!cls)
        for (size_t i = 0; i < md.types.size(); ++i)
            if (md.types[i].name == className) { cls = &md.types[i]; classIndex = i; break; }
    if (!cls || cls->methods.empty()) return out;

    std::string imageName;
    for (const auto& im : md.images)
        if (classIndex >= im.typeStart && classIndex < static_cast<size_t>(im.typeStart) + im.typeCount) {
            imageName = im.name; break;
        }
    if (imageName.empty()) return out;

    Image img;
    {
        std::ifstream in(binaryPath, std::ios::binary);
        if (!in) return out;
        img.buf.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }
    if (!loadPE(img) && !loadELF64(img)) return out;

    auto arrVA = findCodeGenModules(img, md.images.size());
    if (!arrVA) return out;

    // Find the codeGenModule whose moduleName matches this class's image.
    uint64_t methodCount = 0, methodPointersVA = 0;
    for (size_t k = 0; k < md.images.size(); ++k) {
        auto m = img.readPtrVA(*arrVA + k * 8);
        if (!m || *m == 0) continue;
        auto nmp = img.readPtrVA(*m + kCGM_moduleName);
        if (!nmp || img.readCStrVA(*nmp) != imageName) continue;
        if (auto mc = img.readPtrVA(*m + kCGM_methodCount)) methodCount = *mc;
        if (auto mp = img.readPtrVA(*m + kCGM_methodPointers)) methodPointersVA = *mp;
        break;
    }
    if (methodPointersVA == 0) return out;

    // Each method: token RID -> methodPointers[RID-1] -> code VA -> RVA.
    for (const auto& m : cls->methods) {
        uint32_t rid = m.token & 0x00FFFFFF;
        if (rid == 0 || rid > methodCount) continue;
        auto fp = img.readPtrVA(methodPointersVA + static_cast<uint64_t>(rid - 1) * 8);
        if (!fp || *fp == 0 || !img.vaValid(*fp)) continue;   // no compiled body
        out.push_back({m.name, *fp - img.imageBase});
    }
    return out;
}

std::string findGameAssemblyPath(const std::vector<std::string>& mappedPaths) {
    namespace fs = std::filesystem;
    for (const auto& p : mappedPaths) {
        std::string base = fs::path(p).filename().string();
        if (base == "GameAssembly.so" || base == "GameAssembly.dll" || base == "libil2cpp.so")
            return p;
    }
    return {};
}

Il2CppBinaryLayout resolveIl2CppForProcess(ProcessHandle& proc) {
    namespace fs = std::filesystem;
    Il2CppBinaryLayout out;

    std::vector<std::string> paths;
    for (const auto& m : proc.modules()) if (!m.path.empty()) paths.push_back(m.path);
    for (const auto& r : proc.queryRegions()) if (!r.path.empty()) paths.push_back(r.path);

    auto metaPath = findIl2CppMetadataPath(paths);
    if (!metaPath) { out.error = "global-metadata.dat not found for this process"; return out; }

    std::ifstream in(*metaPath, std::ios::binary);
    if (!in) { out.error = "cannot open " + *metaPath; return out; }
    std::vector<uint8_t> buf((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    auto md = parseIl2CppMetadata(buf.data(), buf.size());
    if (!md) { out.error = "failed to parse " + *metaPath; return out; }
    if (!md->tablesDecoded) {
        out.error = "metadata version " + std::to_string(md->version) + " unsupported for offsets";
        return out;
    }

    // The GameAssembly is usually already mapped; else look next to the metadata.
    std::string ga = findGameAssemblyPath(paths);
    if (ga.empty()) {
        fs::path root = fs::path(*metaPath).parent_path().parent_path()
                            .parent_path().parent_path();
        std::error_code ec;
        for (const char* n : {"GameAssembly.so", "GameAssembly.dll", "libil2cpp.so"}) {
            fs::path c = root / n;
            if (fs::is_regular_file(c, ec)) { ga = c.string(); break; }
        }
    }
    if (ga.empty()) { out.error = "GameAssembly binary not found for this process"; return out; }

    return resolveIl2CppLayout(*md, ga);
}

} // namespace ce
