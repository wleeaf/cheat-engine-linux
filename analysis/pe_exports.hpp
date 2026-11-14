#pragma once
/// Parse a Windows PE module's export table.
///
/// Proton/Wine games map their real DLLs as PE images (GameAssembly.dll,
/// UnityPlayer.dll, ...), whose exported functions live in the PE export
/// directory rather than an ELF symbol table. This resolves those names to RVAs
/// so a script can, e.g., call the il2cpp_* runtime API GameAssembly.dll exports.
/// Runtime address = the module's mapped base + rva.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace ce {

struct PEExport {
    std::string name;      ///< exported name ("" for an ordinal-only export)
    uint32_t    ordinal = 0;   ///< export ordinal (Base-relative, as in the PE)
    uint64_t    rva = 0;   ///< function RVA (0 when forwarded)
    std::string forward;   ///< "OTHERDLL.func" if this export forwards, else empty
};

/// Parse the export directory of the PE at `path`. Returns [] if the file is not
/// a PE32/PE32+ image or exports nothing. Named exports come first, in name
/// order. Bounds-checked against the file (untrusted input).
std::vector<PEExport> parsePEExports(const std::string& path);

/// Convenience: the RVA of a single named export, or 0 if absent or forwarded.
uint64_t peExportRva(const std::string& path, const std::string& name);

struct PEImport {
    std::string dll;       ///< the DLL this function is imported from
    std::string name;      ///< imported name ("" for an ordinal import)
    uint32_t    ordinal = 0;   ///< ordinal (only when imported by ordinal)
    uint64_t    iatRva = 0;///< RVA of this import's IAT slot (an IAT-hook target)
};

/// Parse the import table of the PE at `path`: every function the module imports,
/// with the RVA of its IAT slot (module base + iatRva is a live IAT-hook point).
/// Bounds-checked; returns [] if not a PE or nothing is imported.
std::vector<PEImport> parsePEImports(const std::string& path);

struct PESection {
    std::string name;
    uint32_t rva = 0, virtualSize = 0, rawOffset = 0, rawSize = 0, characteristics = 0;
};

/// The headers Cheat Engine's PE Info window lists: the COFF and optional
/// header fields, the data directories (rva, size) and the section table.
struct PEHeaderInfo {
    bool pe32Plus = false;
    uint16_t machine = 0, characteristics = 0, subsystem = 0, dllCharacteristics = 0;
    uint32_t timestamp = 0, entryPoint = 0, sizeOfImage = 0, sizeOfHeaders = 0, checksum = 0;
    uint64_t imageBase = 0;
    std::vector<std::pair<uint32_t, uint32_t>> directories;
    std::vector<PESection> sections;
};

/// Parse the headers at the start of a PE image: a file's first bytes or a
/// loaded module's header page read from memory. Bounds-checked; nullopt when
/// `image` does not start with a PE32/PE32+ header.
std::optional<PEHeaderInfo> parsePEHeaderInfo(std::span<const uint8_t> image);

struct PERelocation {
    uint32_t rva = 0;   ///< the address the loader patches, relative to the image
    uint8_t type = 0;   ///< IMAGE_REL_BASED_* (3 HIGHLOW, 10 DIR64, ...)
};

/// The base relocations of the PE at `path` (DataDirectory[5]), at most
/// `limit` of them; ABSOLUTE padding entries are skipped.
std::vector<PERelocation> parsePERelocations(const std::string& path, size_t limit = 100000);

} // namespace ce
