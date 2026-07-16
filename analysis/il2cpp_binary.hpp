#pragma once
/// Resolve IL2CPP field byte offsets by matching parsed `global-metadata.dat`
/// against the game's compiled `GameAssembly` binary (Windows PE / native ELF).
///
/// The metadata (analysis/il2cpp_metadata) recovers class and field NAMES, but the
/// in-object byte offsets live in the binary's Il2CppMetadataRegistration.
/// fieldOffsets table. This finds that table (a count-match heuristic cross-checked
/// against the metadata's type count) and reads each type's per-field offsets,
/// plus each field's static/instance/const kind (from its Il2CppType.attrs).
///
/// Offset semantics (validated against real Unity builds, e.g. UnityEngine.Vector3
/// x@0x10, y@0x14, z@0x18):
///   - INSTANCE fields: object-relative. Add to the managed object's base pointer:
///     value address = objectPtr + offset. (For reference types the first field is
///     usually at 0x10, past the Il2CppObject header; for value types the offset is
///     also header-relative, so subtract 0x10 for the unboxed struct.)
///   - STATIC fields: offset into the type's static storage block (not object mem).
///   - CONST (literal) fields: no storage (offset is meaningless).

#include "analysis/il2cpp_metadata.hpp"
#include "platform/process_api.hpp"

#include <string>
#include <vector>

namespace ce {

struct Il2CppResolvedField {
    std::string name;
    int32_t     offset = 0;
    bool        isStatic = false;
    bool        isConst = false;   // literal; has no storage
    uint8_t     typeEnum = 0;      // Il2CppTypeEnum (I4=8, R4=0xC, CLASS=0x12, ...)
};

struct Il2CppClassLayout {
    std::string image;
    std::string namespaceName;
    std::string name;
    std::vector<Il2CppResolvedField> fields;

    std::string fullName() const {
        return namespaceName.empty() ? name : namespaceName + "." + name;
    }
};

struct Il2CppBinaryLayout {
    bool        ok = false;
    std::string error;
    /// One entry per metadata type, in the same order as `Il2CppMetadata::types`.
    std::vector<Il2CppClassLayout> classes;
};

/// Resolve field offsets for every type in `md` (which must have `tablesDecoded`)
/// using the GameAssembly binary at `binaryPath`. On failure returns `{ok=false,
/// error=...}`. Generic type definitions legitimately report all-zero offsets
/// (their real offsets are per-instantiation), so a class of all-zero instance
/// fields is expected for generics, not an error.
Il2CppBinaryLayout resolveIl2CppLayout(const Il2CppMetadata& md, const std::string& binaryPath);

/// The GameAssembly binary path among a process's mapped file paths (basename
/// GameAssembly.so/.dll or libil2cpp.so), or "" if none is mapped.
std::string findGameAssemblyPath(const std::vector<std::string>& mappedPaths);

/// Live convenience: locate a running IL2CPP process's global-metadata.dat and
/// GameAssembly from its mapped files, parse the metadata, and resolve the full
/// class layout with field offsets. Shared by the Lua binding and the GUI so both
/// go through one code path. On failure returns `{ok=false, error=...}`.
Il2CppBinaryLayout resolveIl2CppForProcess(ProcessHandle& proc);

/// Map an Il2CppTypeEnum (Il2CppResolvedField::typeEnum) to our ValueType for
/// display/scan: integers by width, R4/R8 to Float/Double, String to String, and
/// every reference/pointer kind (CLASS, OBJECT, STRING pointer, SZARRAY, PTR, I/U)
/// to Pointer. An embedded VALUETYPE (a struct field) maps to ByteArray.
ValueType il2cppTypeEnumToValueType(uint8_t typeEnum);

/// Byte width of a field of the given Il2CppTypeEnum (0 = unknown / caller should
/// infer from the offset gap, e.g. an embedded value type).
size_t il2cppTypeEnumSize(uint8_t typeEnum);

} // namespace ce
