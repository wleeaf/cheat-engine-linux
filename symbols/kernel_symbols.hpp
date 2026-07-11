#pragma once
/// Linux kernel symbol resolver for /proc/kallsyms-style data.

#include <cstdint>
#include <istream>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

namespace ce {

struct KernelSymbol {
    uintptr_t address = 0;
    char type = '?';
    std::string name;
    std::string module; // Empty for built-in kernel symbols
};

class KernelSymbolResolver {
public:
    bool loadFile(const std::string& path = "/proc/kallsyms", bool includeZeroAddresses = false);
    bool load(std::istream& input, bool includeZeroAddresses = false);
    void clear();

    uintptr_t lookup(const std::string& name) const;
    std::string resolve(uintptr_t address) const;

    const std::vector<KernelSymbol>& symbols() const { return symbols_; }
    size_t count() const { return symbols_.size(); }

private:
    void indexSymbol(KernelSymbol symbol);

    std::vector<KernelSymbol> symbols_;
    std::map<uintptr_t, size_t> addrIndex_;
    std::unordered_map<std::string, uintptr_t> nameIndex_;
};

} // namespace ce
