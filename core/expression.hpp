#pragma once
#include <vector>
/// Expression parser for address expressions like "game.exe+0x100", "[rax+8]", "0x7f1234"

#include "platform/process_api.hpp"
#include "symbols/elf_symbols.hpp"
#include <string>
#include <optional>

namespace ce {

class ExpressionParser {
public:
    ExpressionParser(ProcessHandle* proc = nullptr, SymbolResolver* resolver = nullptr)
        : proc_(proc), resolver_(resolver) {}

    /// Parse an address expression. Supports:
    /// - Hex: "0x7f1234", "7f1234"
    /// - Decimal: "#100" (prefixed with #)
    /// - Module+offset: "libc.so.6+0x1234"
    /// - Symbol: "printf", "main"
    /// - Arithmetic: "libc.so.6+0x100+0x20"
    /// - Pointer deref: "[libc.so.6+0x100]+0x20" (requires proc)
    std::optional<uintptr_t> parse(const std::string& expr) const;

private:
    std::optional<uintptr_t> parseImpl(const std::string& expr, int depth) const;
    std::optional<uintptr_t> resolveToken(const std::string& token) const;
    // The module list, read once per parser and only when a token needs it:
    // the freezer re-resolves pointer records ten times a second, and every
    // read of it parses the target's whole memory map.
    const std::vector<ModuleInfo>& modules() const;
    ProcessHandle* proc_;
    SymbolResolver* resolver_;
    mutable std::optional<std::vector<ModuleInfo>> modules_;
    mutable std::optional<uintptr_t> mask_;   // address width of the target
    // A 64-bit process running 32-bit code (WoW64 under Wine): its 32-bit
    // code wraps at 4 GiB, but 64-bit modules and stacks live above it.
    mutable bool mixedWidth_ = false;
};

} // namespace ce
