#include "core/types.hpp"

#include <cstdio>

namespace ce {

std::string moduleOffsetString(const std::vector<ModuleInfo>& modules, uintptr_t addr) {
    const ModuleInfo* best = nullptr;
    for (const auto& m : modules) {
        if (m.size == 0) continue;
        if (addr >= m.base && addr < m.base + m.size) {
            // Nested mappings: prefer the smallest module that contains the address.
            if (!best || m.size < best->size) best = &m;
        }
    }
    if (!best) return {};
    std::string name = !best->name.empty() ? best->name : best->path;
    if (auto slash = name.find_last_of('/'); slash != std::string::npos)
        name = name.substr(slash + 1);
    char buf[24];
    std::snprintf(buf, sizeof(buf), "+0x%llX",
                  static_cast<unsigned long long>(addr - best->base));
    return name + buf;
}

} // namespace ce
