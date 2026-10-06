#pragma once
#include "core/types.hpp"
#include <string>
#include <vector>
#include <expected>
#include <span>

namespace ce {

struct CpuRegisterValue {
    std::string name;
    uint64_t value = 0;
    unsigned bits = 0;
};

// Describes the actual stopped thread's register ABI, including compat mode.
// Unknown architectures produce no invented register bank.
std::vector<CpuRegisterValue> cpuRegisterValues(const CpuContext& context);
bool setCpuRegisterValue(CpuContext& context, size_t row, uint64_t value);
// Merge only values changed from the displayed snapshot into a fresh kernel
// context. Unedited PC/SP, segments, flags and registers retain their live values.
std::expected<CpuContext, std::string> mergeCpuRegisterEdits(
    const CpuContext& current, const CpuContext& displayed, std::span<const uint64_t> values);
std::string describeCpuStatusFlags(const CpuContext& context);

} // namespace ce
