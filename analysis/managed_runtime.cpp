#include "analysis/managed_runtime.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <initializer_list>
#include <set>

namespace ce {
namespace {

std::string lowerCopy(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return text;
}

bool containsAny(const std::string& text, std::initializer_list<const char*> needles) {
    for (const auto* needle : needles) {
        if (text.find(needle) != std::string::npos)
            return true;
    }
    return false;
}

bool isRuntimeModuleName(const std::string& text, ManagedRuntimeKind kind) {
    if (kind == ManagedRuntimeKind::Mono) {
        return containsAny(text, {
            "libmonosgen", "libmono-2.0", "libmono", "/mono/", "mono-sgen"
        });
    }
    return containsAny(text, {
        "libcoreclr.so", "coreclr.dll", "libclrjit.so", "clrjit.dll",
        "libhostpolicy.so", "system.private.corelib"
    });
}

bool rangeContains(const MemoryRegion& range, uintptr_t address) {
    auto end = range.base + range.size;
    return address >= range.base && address < end && end >= range.base;
}

uintptr_t readPointer(const uint8_t* data, size_t pointerSize) {
    if (pointerSize == 4) {
        uint32_t value = 0;
        std::memcpy(&value, data, sizeof(value));
        return value;
    }

    uint64_t value = 0;
    std::memcpy(&value, data, sizeof(value));
    return static_cast<uintptr_t>(value);
}

std::optional<uintptr_t> readProcessPointer(ProcessHandle& proc, uintptr_t address, size_t pointerSize) {
    uint8_t bytes[8] = {};
    auto read = proc.read(address, bytes, pointerSize);
    if (!read || *read != pointerSize)
        return std::nullopt;
    return readPointer(bytes, pointerSize);
}

bool isReasonableManagedName(const std::string& text) {
    if (text.empty())
        return false;
    for (unsigned char c : text) {
        if (!std::isprint(c))
            return false;
    }
    return true;
}

std::optional<std::string> readCString(ProcessHandle& proc, uintptr_t address, size_t maxLength) {
    auto region = proc.queryRegion(address);
    if (!region || !(region->protection & MemProt::Read))
        return std::nullopt;

    auto regionEnd = region->base + region->size;
    if (regionEnd <= address)
        return std::nullopt;
    auto bytesToRead = std::min(maxLength + 1, static_cast<size_t>(regionEnd - address));
    if (bytesToRead == 0)
        return std::nullopt;

    std::vector<char> buffer(bytesToRead);
    auto read = proc.read(address, buffer.data(), buffer.size());
    if (!read || *read == 0)
        return std::nullopt;

    auto nul = std::find(buffer.begin(), buffer.begin() + *read, '\0');
    if (nul == buffer.begin() + *read)
        return std::nullopt;

    std::string text(buffer.begin(), nul);
    if (!isReasonableManagedName(text))
        return std::nullopt;
    return text;
}

} // namespace

std::vector<ManagedRuntimeInfo> detectManagedRuntimes(ProcessHandle& proc) {
    std::vector<ManagedRuntimeInfo> runtimes;
    bool sawMono = false;
    bool sawCoreClr = false;

    for (const auto& module : proc.modules()) {
        auto name = lowerCopy(module.name);
        auto path = lowerCopy(module.path);
        auto haystack = name + "\n" + path;

        if (!sawMono && isRuntimeModuleName(haystack, ManagedRuntimeKind::Mono)) {
            runtimes.push_back({
                ManagedRuntimeKind::Mono,
                "Mono",
                module.name,
                module.path,
                module.base,
                module.size,
            });
            sawMono = true;
            continue;
        }

        if (!sawCoreClr && isRuntimeModuleName(haystack, ManagedRuntimeKind::CoreCLR)) {
            runtimes.push_back({
                ManagedRuntimeKind::CoreCLR,
                "CoreCLR",
                module.name,
                module.path,
                module.base,
                module.size,
            });
            sawCoreClr = true;
        }
    }

    return runtimes;
}

std::vector<ManagedObjectInfo> enumerateManagedObjects(
    ProcessHandle& proc,
    const ManagedObjectEnumerationConfig& config) {
    auto pointerSize = config.pointerSize != 0 ? config.pointerSize : (proc.is64bit() ? 8 : 4);
    if (pointerSize != 4 && pointerSize != 8)
        return {};

    std::vector<MemoryRegion> typeRanges = config.typeHandleRanges;
    if (typeRanges.empty()) {
        for (const auto& module : proc.modules()) {
            auto haystack = lowerCopy(module.name + "\n" + module.path);
            if ((config.runtimeKind && isRuntimeModuleName(haystack, *config.runtimeKind)) ||
                (!config.runtimeKind && (isRuntimeModuleName(haystack, ManagedRuntimeKind::Mono) ||
                    isRuntimeModuleName(haystack, ManagedRuntimeKind::CoreCLR)))) {
                typeRanges.push_back({
                    module.base,
                    module.size,
                    MemProt::Read,
                    MemType::Image,
                    MemState::Committed,
                    module.path,
                });
            }
        }
    }
    if (typeRanges.empty())
        return {};

    std::vector<ManagedObjectInfo> objects;
    std::vector<uint8_t> buffer;

    for (const auto& region : proc.queryRegions()) {
        if (objects.size() >= config.maxObjects)
            break;
        if (region.state != MemState::Committed || !(region.protection & MemProt::Read))
            continue;
        if (config.writableRegionsOnly && !(region.protection & MemProt::Write))
            continue;
        if (region.protection & MemProt::Exec)
            continue;
        if (config.heapEnd != 0 && region.base >= config.heapEnd)
            continue;
        auto regionEnd = region.base + region.size;
        if (config.heapStart != 0 && regionEnd <= config.heapStart)
            continue;

        auto scanStart = std::max(region.base, config.heapStart);
        auto scanEnd = config.heapEnd == 0 ? regionEnd : std::min(regionEnd, config.heapEnd);
        if (scanEnd <= scanStart || scanEnd - scanStart < pointerSize)
            continue;

        // Scan in fixed pointer-aligned chunks instead of resizing one buffer to
        // span the whole region: managed GC heaps run to several GB, and a single
        // region-sized allocation risks std::bad_alloc/OOM here. 4 MiB is a
        // multiple of both 4- and 8-byte pointers, so no pointer straddles a
        // chunk boundary given the pointer-step walk below.
        constexpr size_t kChunkSize = 4u * 1024u * 1024u;
        for (auto chunkStart = scanStart; chunkStart + pointerSize <= scanEnd; ) {
            if (objects.size() >= config.maxObjects)
                break;

            auto chunkLen = std::min<uintptr_t>(kChunkSize, scanEnd - chunkStart);
            buffer.resize(chunkLen);
            auto read = proc.read(chunkStart, buffer.data(), chunkLen);
            if (!read || *read < pointerSize) {
                // Unreadable hole: advance past this chunk and keep scanning.
                chunkStart += chunkLen;
                continue;
            }

            auto readable = *read;
            for (size_t offset = 0; offset + pointerSize <= readable; offset += pointerSize) {
                auto typeHandle = readPointer(buffer.data() + offset, pointerSize);
                if (typeHandle == 0)
                    continue;

                auto typeRange = std::find_if(typeRanges.begin(), typeRanges.end(), [&](const MemoryRegion& range) {
                    return rangeContains(range, typeHandle);
                });
                if (typeRange == typeRanges.end())
                    continue;

                objects.push_back({
                    chunkStart + offset,
                    typeHandle,
                    0,
                    config.runtimeKind,
                    region.path,
                });
                if (objects.size() >= config.maxObjects)
                    break;
            }

            chunkStart += chunkLen;
        }
    }

    return objects;
}

std::vector<ManagedTypeInfo> extractManagedTypes(
    ProcessHandle& proc,
    const std::vector<uintptr_t>& typeHandles,
    const ManagedTypeExtractionConfig& config) {
    auto pointerSize = config.pointerSize != 0 ? config.pointerSize : (proc.is64bit() ? 8 : 4);
    if (pointerSize != 4 && pointerSize != 8)
        return {};

    auto nameOffsets = config.namePointerOffsets;
    if (nameOffsets.empty()) {
        for (size_t i = 0; i < 8; ++i)
            nameOffsets.push_back(i * pointerSize);
    }
    auto namespaceOffsets = config.namespacePointerOffsets;
    if (namespaceOffsets.empty()) {
        for (size_t i = 1; i < 8; ++i)
            namespaceOffsets.push_back(i * pointerSize);
    }

    std::vector<ManagedTypeInfo> types;
    std::set<uintptr_t> seen;
    for (auto typeHandle : typeHandles) {
        if (typeHandle == 0 || !seen.insert(typeHandle).second)
            continue;

        std::string name;
        size_t selectedNameOffset = 0;
        for (auto offset : nameOffsets) {
            auto namePtr = readProcessPointer(proc, typeHandle + offset, pointerSize);
            if (!namePtr)
                continue;
            auto candidate = readCString(proc, *namePtr, config.maxNameLength);
            if (candidate) {
                name = *candidate;
                selectedNameOffset = offset;
                break;
            }
        }
        if (name.empty())
            continue;

        std::string namespaceName;
        for (auto offset : namespaceOffsets) {
            if (offset == selectedNameOffset)
                continue;
            auto namespacePtr = readProcessPointer(proc, typeHandle + offset, pointerSize);
            if (!namespacePtr)
                continue;
            auto candidate = readCString(proc, *namespacePtr, config.maxNameLength);
            if (candidate) {
                namespaceName = *candidate;
                break;
            }
        }

        types.push_back({
            typeHandle,
            name,
            namespaceName,
            config.runtimeKind,
        });
    }

    return types;
}

std::vector<ManagedTypeInfo> extractManagedObjectTypes(
    ProcessHandle& proc,
    const std::vector<ManagedObjectInfo>& objects,
    const ManagedTypeExtractionConfig& config) {
    std::vector<uintptr_t> typeHandles;
    typeHandles.reserve(objects.size());
    for (const auto& object : objects)
        typeHandles.push_back(object.typeHandle);
    return extractManagedTypes(proc, typeHandles, config);
}

} // namespace ce
