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

} // namespace ce
