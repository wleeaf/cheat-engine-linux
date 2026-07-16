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
#include <string>
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

} // namespace ce
