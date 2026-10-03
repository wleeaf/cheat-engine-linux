#include "analysis/pe_exports.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <optional>

namespace ce {

namespace {

// A minimal PE reader: enough to map RVAs to file offsets and reach the export
// directory. All reads are bounds-checked against the loaded buffer.
struct Pe {
    std::vector<uint8_t> buf;
    struct Sec { uint32_t rva, vsize, fileOff, fileSize; };
    std::vector<Sec> secs;
    uint32_t headerSize = 0;

    bool inRange(size_t o, size_t n) const { return o + n <= buf.size() && o + n >= o; }
    uint16_t u16(size_t o) const { uint16_t v = 0; std::memcpy(&v, buf.data() + o, 2); return v; }
    uint32_t u32(size_t o) const { uint32_t v = 0; std::memcpy(&v, buf.data() + o, 4); return v; }

    std::optional<size_t> rvaToOff(uint64_t rva, size_t n = 1) const {
        if (rva > UINT32_MAX || n > uint64_t(UINT32_MAX) + 1 - rva) return std::nullopt;
        if (rva < headerSize && n <= headerSize - rva && inRange(rva, n))
            return static_cast<size_t>(rva);
        for (const auto& s : secs)
            if (rva >= s.rva && rva - s.rva < std::max(s.vsize, s.fileSize)) {
                uint32_t d = rva - s.rva;
                if (d < s.fileSize && n <= s.fileSize - d) {
                    size_t off = static_cast<size_t>(s.fileOff) + d;
                    if (inRange(off, n)) return off;
                }
                return std::nullopt;
            }
        return std::nullopt;
    }
    std::optional<uint32_t> u32AtRva(uint64_t rva) const {
        auto o = rvaToOff(rva, 4); if (!o) return std::nullopt; return u32(*o);
    }
    std::optional<uint16_t> u16AtRva(uint64_t rva) const {
        auto o = rvaToOff(rva, 2); if (!o) return std::nullopt; return u16(*o);
    }
    std::string cstrAtRva(uint64_t rva, size_t maxLen = 512) const {
        std::string s;
        for (size_t i = 0; i < maxLen; ++i) {
            // Require the whole string to belong to one mapped raw extent.
            auto o = rvaToOff(rva, i + 1);
            if (!o) return {};
            char c = static_cast<char>(buf[*o + i]);
            if (c == '\0') return s;
            s.push_back(c);
        }
        return {};
    }
};

// Loaded PE headers: the DataDirectory entries we care about + whether it's PE32+.
struct PeDirs {
    bool     pe64 = false;
    uint32_t exportRva = 0, exportSize = 0;   // DataDirectory[0]
    uint32_t importRva = 0, importSize = 0;   // DataDirectory[1]
};

// Load headers + section table + `dirs`. Returns false if not a valid PE.
bool loadPe(Pe& pe, PeDirs& dirs) {
    const auto& b = pe.buf;
    if (b.size() < 0x40 || b[0] != 'M' || b[1] != 'Z') return false;
    uint32_t e = pe.u32(0x3C);
    if (!pe.inRange(e, 24) || std::memcmp(b.data() + e, "PE\0\0", 4) != 0) return false;
    size_t coff = e + 4;
    if (!pe.inRange(coff, 20)) return false;
    uint16_t nSec = pe.u16(coff + 2);
    uint16_t optSize = pe.u16(coff + 16);
    size_t opt = coff + 20;
    if (!pe.inRange(opt, optSize) || optSize < 0x18) return false;
    uint16_t magic = pe.u16(opt);
    size_t dataDir;
    if (magic == 0x20B) { dirs.pe64 = true; dataDir = opt + 0x70; }   // PE32+
    else if (magic == 0x10B) { dataDir = opt + 0x60; }               // PE32
    else return false;
    size_t directoryOffset = dataDir - opt;
    if (optSize < directoryOffset) return false;
    uint32_t directoryCount = pe.u32(dataDir - 4);
    if (directoryCount > (optSize - directoryOffset) / 8) return false;
    pe.headerSize = pe.u32(opt + 0x3c);
    if (pe.headerSize > b.size()) return false;
    if (directoryCount > 0) {
        dirs.exportRva = pe.u32(dataDir);
        dirs.exportSize = pe.u32(dataDir + 4);
    }
    if (directoryCount > 1) {
        dirs.importRva = pe.u32(dataDir + 8);
        dirs.importSize = pe.u32(dataDir + 12);
    }

    size_t secTbl = opt + optSize;
    if (!pe.inRange(secTbl, static_cast<size_t>(nSec) * 40)) return false;
    for (uint16_t k = 0; k < nSec; ++k) {
        size_t so = secTbl + static_cast<size_t>(k) * 40;
        Pe::Sec s;
        s.vsize = pe.u32(so + 8);
        s.rva = pe.u32(so + 12);
        s.fileSize = pe.u32(so + 16);
        s.fileOff = pe.u32(so + 20);
        if (!pe.inRange(s.fileOff, s.fileSize) ||
            uint64_t(s.rva) + std::max(s.vsize, s.fileSize) > uint64_t(UINT32_MAX) + 1)
            return false;
        pe.secs.push_back(s);
    }
    return !pe.secs.empty();
}

} // namespace

std::vector<PEExport> parsePEExports(const std::string& path) {
    std::vector<PEExport> out;
    Pe pe;
    {
        std::ifstream in(path, std::ios::binary);
        if (!in) return out;
        pe.buf.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }
    PeDirs dirs;
    if (!loadPe(pe, dirs) || dirs.exportRva == 0) return out;
    const uint32_t edRva = dirs.exportRva, edSize = dirs.exportSize;

    if (edSize < 40 || uint64_t(edRva) + edSize > uint64_t(UINT32_MAX) + 1) return out;
    auto o = pe.rvaToOff(edRva, 40);
    if (!o) return out;
    const size_t ed = *o;
    // IMAGE_EXPORT_DIRECTORY fields.
    const uint32_t base = pe.u32(ed + 0x10);
    const uint32_t nFuncs = pe.u32(ed + 0x14);
    const uint32_t nNames = pe.u32(ed + 0x18);
    const uint32_t addrFuncs = pe.u32(ed + 0x1C);
    const uint32_t addrNames = pe.u32(ed + 0x20);
    const uint32_t addrOrds = pe.u32(ed + 0x24);
    if (nFuncs > 1'000'000 || nNames > 1'000'000) return out;   // sanity

    out.reserve(nNames);
    for (uint32_t i = 0; i < nNames; ++i) {
        auto nameRva = pe.u32AtRva(uint64_t(addrNames) + i * 4);
        auto ord = pe.u16AtRva(uint64_t(addrOrds) + i * 2);
        if (!nameRva || !ord) break;
        if (*ord >= nFuncs) continue;
        auto funcRva = pe.u32AtRva(uint64_t(addrFuncs) + *ord * 4);
        if (!funcRva || !*funcRva || *ord > UINT32_MAX - base) continue;

        PEExport ex;
        ex.name = pe.cstrAtRva(*nameRva);
        if (ex.name.empty()) continue;
        ex.ordinal = base + *ord;
        // A function RVA inside the export directory region is a forwarder string.
        if (*funcRva >= edRva && *funcRva - edRva < edSize) {
            ex.forward = pe.cstrAtRva(*funcRva, std::min<size_t>(512, edSize - (*funcRva - edRva)));
            if (ex.forward.empty()) continue;
        } else
            ex.rva = *funcRva;
        out.push_back(std::move(ex));
    }
    return out;
}

uint64_t peExportRva(const std::string& path, const std::string& name) {
    for (const auto& e : parsePEExports(path))
        if (e.name == name) return e.rva;
    return 0;
}

std::vector<PEImport> parsePEImports(const std::string& path) {
    std::vector<PEImport> out;
    Pe pe;
    {
        std::ifstream in(path, std::ios::binary);
        if (!in) return out;
        pe.buf.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }
    PeDirs dirs;
    if (!loadPe(pe, dirs) || dirs.importRva == 0) return out;
    const uint64_t hiBit = dirs.pe64 ? 0x8000000000000000ull : 0x80000000ull;
    const uint32_t thunkSize = dirs.pe64 ? 8 : 4;

    // Import directory: a null-terminated array of IMAGE_IMPORT_DESCRIPTOR (20B).
    //   +0x00 OriginalFirstThunk (ILT rva)  +0x0C Name (dll name rva)  +0x10 FirstThunk (IAT rva)
    if (uint64_t(dirs.importRva) + dirs.importSize > uint64_t(UINT32_MAX) + 1) return out;
    for (uint32_t d = 0; d < std::min<uint32_t>(4096, dirs.importSize / 20); ++d) {
        uint64_t base = uint64_t(dirs.importRva) + d * 20;
        if (!pe.rvaToOff(base, 20)) break;
        auto oft = pe.u32AtRva(base + 0x00);
        auto nameRva = pe.u32AtRva(base + 0x0C);
        auto ft = pe.u32AtRva(base + 0x10);
        if (!oft || !nameRva || !ft) break;
        if (*oft == 0 && *nameRva == 0 && *ft == 0) break;   // terminator
        std::string dll = pe.cstrAtRva(*nameRva);
        if (dll.empty() || *ft == 0) continue;
        uint32_t iltRva = *oft ? *oft : *ft;                 // ILT preferred; else IAT
        for (uint32_t i = 0; i < 100000; ++i) {
            uint64_t thunk = 0;
            if (dirs.pe64) { auto t = pe.rvaToOff(uint64_t(iltRva) + i * 8, 8); if (!t) break;
                             std::memcpy(&thunk, pe.buf.data() + *t, 8); }
            else           { auto t = pe.u32AtRva(uint64_t(iltRva) + i * 4); if (!t) break; thunk = *t; }
            if (thunk == 0) break;                           // end of this DLL's thunks
            PEImport im;
            im.dll = dll;
            uint64_t iat = uint64_t(*ft) + i * thunkSize;
            if (iat > UINT32_MAX) break;
            im.iatRva = static_cast<uint32_t>(iat);
            if (thunk & hiBit) {
                im.ordinal = static_cast<uint32_t>(thunk & 0xFFFF);
            } else {
                if (thunk > UINT32_MAX - 2 || !pe.u16AtRva(thunk)) break;
                im.name = pe.cstrAtRva(thunk + 2);
                if (im.name.empty()) break;
            }
            out.push_back(std::move(im));
        }
    }
    return out;
}

} // namespace ce
