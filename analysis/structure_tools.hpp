#pragma once
/// Utilities for structure dissector templates and C/C++ export.

#include "core/ct_file.hpp"
#include "platform/process_api.hpp"

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

bool saveStructureTemplate(const StructureDefinition& structure, const std::string& path);
std::optional<StructureDefinition> loadStructureTemplate(const std::string& path);
std::string generateCppStruct(const StructureDefinition& structure);
std::vector<StructureFieldDiff> compareStructureSnapshots(const StructureDefinition& structure,
    const std::vector<uint8_t>& before,
    const std::vector<uint8_t>& after);
std::vector<StructureDetectedField> autoDetectStructureFields(const std::vector<uint8_t>& before,
    const std::vector<uint8_t>& after);
std::vector<StructurePointerChain> followStructurePointers(ProcessHandle& proc,
    uintptr_t baseAddress,
    const StructureDefinition& structure,
    size_t maxDepth = 2);
std::string formatStructureFieldValue(const StructureField& field,
    const std::vector<uint8_t>& snapshot);

} // namespace ce
