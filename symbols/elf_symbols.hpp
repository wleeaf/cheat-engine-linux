#pragma once
/// ELF symbol resolver — parses .dynsym/.symtab from ELF files to resolve addresses to names.

#include "platform/process_api.hpp"
#include <string>
#include <vector>
#include <map>
#include <unordered_map>

namespace ce {

struct Symbol {
    std::string name;
    uintptr_t   address;    // Absolute address in process memory
    size_t      size;
    std::string module;     // Module short name (e.g., "libc.so.6")
};

class SymbolResolver {
public:
    SymbolResolver() = default;

    /// Load symbols for all modules of a process.
    void loadProcess(ProcessHandle& proc);

    /// Load symbols from a single ELF file mapped at baseAddr.
    void loadModule(const std::string& path, const std::string& moduleName, uintptr_t baseAddr);

    /// Clear all loaded symbols.
    void clear();

    /// Resolve an address to a symbol string like "libc.so!printf+0x12"
    std::string resolve(uintptr_t address) const;

    /// Resolve a symbol name to an address. Returns 0 if not found.
    uintptr_t lookup(const std::string& name) const;

    /// User-defined labels. These take priority over module symbols in
    /// resolve() (like Cheat Engine's user-defined symbols).
    void addUserSymbol(uintptr_t address, const std::string& name);
    void removeUserSymbol(uintptr_t address);
    /// All user-defined labels (address -> name), for persistence/enumeration.
    const std::map<uintptr_t, std::string>& userSymbols() const { return userSymbols_; }

    /// Get all symbols (for listing).
    const std::vector<Symbol>& symbols() const { return symbols_; }

    /// Number of loaded symbols.
    size_t count() const { return symbols_.size(); }

private:
    void parseElfSymbols(const std::string& path, const std::string& moduleName, uintptr_t baseAddr);

    std::vector<Symbol> symbols_;
    // Sorted by address for binary search in resolve()
    std::map<uintptr_t, size_t> addrIndex_; // address → index into symbols_
    std::unordered_map<std::string, uintptr_t> nameIndex_; // name → address
    std::map<uintptr_t, std::string> userSymbols_;         // user-defined labels
};

} // namespace ce
