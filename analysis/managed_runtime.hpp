#pragma once
/// Managed runtime detection helpers for Mono and CoreCLR targets.

#include "platform/process_api.hpp"

#include <string>
#include <vector>
#include <optional>

namespace ce {

enum class ManagedRuntimeKind {
    Mono,
    CoreCLR,
};

struct ManagedRuntimeInfo {
    ManagedRuntimeKind kind;
    std::string name;
    std::string moduleName;
    std::string modulePath;
    uintptr_t base = 0;
    size_t size = 0;
};

struct ManagedObjectInfo {
    uintptr_t address = 0;
    uintptr_t typeHandle = 0;
    size_t size = 0;                  // 0 when the runtime-specific size is not known
    std::optional<ManagedRuntimeKind> runtimeKind;
    std::string regionPath;
};

struct ManagedTypeInfo {
    uintptr_t typeHandle = 0;
    std::string name;
    std::string namespaceName;
    std::optional<ManagedRuntimeKind> runtimeKind;
};

struct ManagedObjectEnumerationConfig {
    std::optional<ManagedRuntimeKind> runtimeKind;
    uintptr_t heapStart = 0;
    uintptr_t heapEnd = 0;            // 0 means no upper bound
    size_t pointerSize = 0;           // 0 means infer from ProcessHandle::is64bit()
    size_t maxObjects = 100000;
    bool writableRegionsOnly = true;
    std::vector<MemoryRegion> typeHandleRanges;
};

struct ManagedTypeExtractionConfig {
    std::optional<ManagedRuntimeKind> runtimeKind;
    size_t pointerSize = 0;           // 0 means infer from ProcessHandle::is64bit()
    size_t maxNameLength = 256;
    std::vector<size_t> namePointerOffsets;
    std::vector<size_t> namespacePointerOffsets;
};

std::vector<ManagedRuntimeInfo> detectManagedRuntimes(ProcessHandle& proc);
std::vector<ManagedObjectInfo> enumerateManagedObjects(
    ProcessHandle& proc,
    const ManagedObjectEnumerationConfig& config = {});
std::vector<ManagedTypeInfo> extractManagedTypes(
    ProcessHandle& proc,
    const std::vector<uintptr_t>& typeHandles,
    const ManagedTypeExtractionConfig& config = {});
std::vector<ManagedTypeInfo> extractManagedObjectTypes(
    ProcessHandle& proc,
    const std::vector<ManagedObjectInfo>& objects,
    const ManagedTypeExtractionConfig& config = {});

} // namespace ce
