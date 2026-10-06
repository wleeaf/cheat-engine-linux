#pragma once
#include "debug/lbr_tracer.hpp"
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace ce::detail {
struct PerfMappingSize { size_t dataBytes; size_t mappingBytes; };
// Round a positive page count without signed shifts or overflowing byte sizes.
std::optional<PerfMappingSize> perfMappingSize(size_t pageSize,int pages);
// Callers serialize access to their mappings. These readers consume the Linux
// native perf ABI and publish tails only after completing payload reads.
std::vector<LbrEntry> drainPerfBranches(std::span<uint8_t> mapping,size_t pageSize);
std::vector<uint8_t> drainPerfAux(std::span<uint8_t> mapping,std::span<uint8_t> auxiliary,size_t pageSize);
} // namespace ce::detail
