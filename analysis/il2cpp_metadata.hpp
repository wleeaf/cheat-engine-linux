#pragma once
/// Parser for Unity IL2CPP `global-metadata.dat` files.
///
/// Reads the version-stable part of the header (the 0xFAB11BAF magic + version)
/// and the two string pools: the identifier pool (type / method / field /
/// namespace names) and the user string-literal pool. Those leading header
/// fields have kept the same byte layout across metadata versions ~16..31, so
/// this parser is correct for real Unity files, not just synthetic ones.
///
/// On top of that it optionally decodes the deeper type/field/image tables to
/// recover the class layout offline (assembly image -> class namespace.name ->
/// field names), which is the metadata half of a live IL2CPP dissector. Two
/// honesty notes on that deeper decode:
///
///   1. The table struct layouts are version-specific. The offsets here are
///      transcribed from public IL2CPP reversing references (Il2CppDumper /
///      Il2CppInspector) for the metadata versions in `il2cppTablesSupported`,
///      and are exercised by synthetic round-trip tests. They have NOT yet been
///      validated against a real Unity `global-metadata.dat`; on an unsupported
///      version, or if any region fails bounds-checking, table decode is skipped
///      (`tablesDecoded == false`) and the string pools are still returned.
///   2. Field byte OFFSETS and field TYPE names are NOT in global-metadata.dat
///      on modern IL2CPP; they live in the compiled binary (GameAssembly.so).
///      So this recovers field NAMES and their grouping into classes, not their
///      in-object offsets. Offset resolution is the separate live/binary track.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ce {

/// One field of a managed class. `name` is offline-recoverable; `typeIndex`
/// indexes the binary's Il2CppType[] (resolve to a type name with the binary),
/// and the in-object byte offset is not in the metadata (see header note 2).
struct Il2CppFieldDef {
    std::string name;
    int32_t     typeIndex = 0;
    uint32_t    token = 0;
};

/// One managed type (class/struct) with its declared fields.
struct Il2CppTypeDef {
    std::string name;
    std::string namespaceName;
    std::vector<Il2CppFieldDef> fields;
    uint32_t    token = 0;

    /// "Namespace.Name", or just "Name" when the namespace is empty.
    std::string fullName() const {
        return namespaceName.empty() ? name : namespaceName + "." + name;
    }
};

/// One assembly image (e.g. "Assembly-CSharp.dll") and the run of type
/// definitions it owns: types[typeStart .. typeStart+typeCount).
struct Il2CppImageDef {
    std::string name;
    uint32_t    typeStart = 0;
    uint32_t    typeCount = 0;
};

struct Il2CppMetadata {
    int32_t version = 0;
    std::vector<std::string> strings;         ///< identifier pool (names)
    std::vector<std::string> stringLiterals;  ///< user string literals

    /// Deeper tables. Populated only when `tablesDecoded` is true (a supported
    /// version whose regions all pass bounds-checks); empty otherwise. See the
    /// file header for what these do and do not contain.
    bool tablesDecoded = false;
    std::vector<Il2CppTypeDef>  types;
    std::vector<Il2CppImageDef> images;
};

/// True if the buffer begins with the IL2CPP metadata magic (0xFAB11BAF).
bool isIl2CppMetadata(const uint8_t* data, size_t size);

/// True if `version` has a known table layout, so the parser can decode the
/// deeper type/field/image tables. Unsupported versions still parse the string
/// pools.
bool il2cppTablesSupported(int32_t version);

/// Locate a live IL2CPP process's global-metadata.dat on disk, given the file
/// paths it has mapped (executable, GameAssembly.so, UnityPlayer.so, ...). Unity
/// stores it at `<X>_Data/il2cpp_data/Metadata/global-metadata.dat`, where the
/// `<X>_Data` folder sits next to the game executable / GameAssembly.so. Only
/// game-relevant paths are considered (system libraries are ignored), so this
/// never trawls /usr/lib. Returns the first existing candidate, or nullopt.
std::optional<std::string> findIl2CppMetadataPath(const std::vector<std::string>& mappedPaths);

/// Parse a global-metadata.dat image. Returns nullopt if the magic is wrong, the
/// buffer is shorter than the fixed header, or any declared string region falls
/// outside the buffer. Malformed individual string-literal entries are skipped
/// rather than aborting the whole parse. The deeper type/field/image tables are
/// decoded when the version is supported and every table region validates;
/// otherwise `tablesDecoded` is false and only the string pools are populated.
std::optional<Il2CppMetadata> parseIl2CppMetadata(const uint8_t* data, size_t size);

} // namespace ce
