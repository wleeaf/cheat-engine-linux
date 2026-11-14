#pragma once
/// Utilities for structure dissector templates and C/C++ export.

#include "core/ct_file.hpp"
#include "platform/process_api.hpp"
#include "analysis/il2cpp_binary.hpp"
#include "symbols/dwarf_symbols.hpp"

#include <optional>
#include <string>
#include <vector>

namespace ce {

struct StructureFieldDiff {
    std::string name;
    size_t offset = 0;
    size_t size = 0;
    bool changed = false;
    std::vector<uint8_t> before;
    std::vector<uint8_t> after;
};

struct StructureDetectedField {
    size_t offset = 0;
    size_t size = 0;
    bool changed = false;
    ValueType suggestedType = ValueType::ByteArray;
};

struct StructurePointerChain {
    std::string fieldName;
    size_t fieldOffset = 0;
    std::vector<uintptr_t> addresses;
};

/// Structure Compare (Cheat Engine's frmStructureCompare): a path of offsets
/// from each structure base, following pointers, whose element is the same in
/// every group 1 structure and different in every group 2 structure.
struct StructureCompareOptions {
    size_t structSize = 4096;   // bytes looked at in each structure, at every level
    size_t elementSize = 4;     // compared element: 1, 2, 4 or 8 bytes
    int maxLevel = 2;           // pointers followed below a structure
    bool sameOnly = true;       // group 1 must agree on one value (else: only differ from group 2)
    size_t maxResults = 10000;
    size_t maxBlocks = 20000;   // structure blocks read in all (the search stops there)
};
struct StructureCompareMatch {
    std::vector<int32_t> offsets;          // the last one is the element; the others are dereferenced
    std::vector<uint64_t> group1Values;    // the element in each group 1 structure
    std::vector<uint64_t> group2Values;
};
std::vector<StructureCompareMatch> compareStructureGroups(ProcessHandle& proc,
    const std::vector<uintptr_t>& group1, const std::vector<uintptr_t>& group2,
    const StructureCompareOptions& options);
/// "[[+10]+8]+4" for a match's offsets.
std::string formatStructureComparePath(const std::vector<int32_t>& offsets);

bool saveStructureTemplate(const StructureDefinition& structure, const std::string& path);
std::optional<StructureDefinition> loadStructureTemplate(const std::string& path);
std::string generateCppStruct(const StructureDefinition& structure);
std::vector<StructureFieldDiff> compareStructureSnapshots(const StructureDefinition& structure,
    const std::vector<uint8_t>& before,
    const std::vector<uint8_t>& after);
std::vector<StructureDetectedField> autoDetectStructureFields(const std::vector<uint8_t>& before,
    const std::vector<uint8_t>& after);
/// Multi-instance variant: given N snapshots of the same structure (one per
/// dissected instance), flags each byte-run that is not identical across every
/// snapshot. This is the discriminating-field detector for the N-instance
/// dissector: bytes constant across all instances stay `changed=false`; a run
/// that differs in any instance is flagged. The two-snapshot overload above is
/// the N=2 case and delegates here.
std::vector<StructureDetectedField> autoDetectStructureFieldsMulti(
    const std::vector<std::vector<uint8_t>>& snapshots);
/// Follow each pointer field, decoding pointers with the target's width and
/// byte order (nothing is followed when either is unknown).
std::vector<StructurePointerChain> followStructurePointers(ProcessHandle& proc,
    uintptr_t baseAddress,
    const StructureDefinition& structure,
    size_t maxDepth = 2);
/// Format a field from a snapshot of the structure. `order` is the target's
/// byte order (Unknown: host order); a pointer uses the field's width.
std::string formatStructureFieldValue(const StructureField& field,
    const std::vector<uint8_t>& snapshot, ByteOrder order = ByteOrder::Unknown);

/// Build a structure-dissector definition from a resolved IL2CPP class layout:
/// one field per INSTANCE field (statics/consts skipped), at its object offset,
/// typed from its Il2CppTypeEnum. This is the managed-typing path for the
/// dissector (roadmap #21): instead of guessing field boundaries from byte diffs,
/// a Unity target's real class layout labels the struct. Embedded value-type
/// fields (unknown fixed width) take their size from the gap to the next field;
/// the structure size is the end of the last field. Only the class's OWN declared
/// fields are included (IL2CPP metadata does not repeat inherited fields).
StructureDefinition il2cppClassToStructure(const Il2CppClassLayout& cls);

/// Build a structure-dissector definition from a DWARF-described struct/union
/// type (roadmap #20): one field per member at its `data_member_location`, typed
/// from the member's resolved type (float/double, integers by width, pointers,
/// and embedded aggregates/arrays as ByteArray sized from DWARF). This types a
/// native C/C++ target's structs from its debug info, the RTTI/DWARF analog of
/// il2cppClassToStructure.
StructureDefinition dwarfStructToStructure(const DwarfStruct& s);

} // namespace ce
