#pragma once
/// Lua 5.3 scripting engine with CE API bindings.

#include "platform/process_api.hpp"
#include "scanner/memory_scanner.hpp"
#include "symbols/elf_symbols.hpp"
#include <string>
#include <expected>
#include <functional>
#include <memory>

struct lua_State;

namespace ce {

class IAddressList;

class LuaEngine {
public:
    LuaEngine();
    ~LuaEngine();

    LuaEngine(const LuaEngine&) = delete;

    /// Set the target process (enables memory functions in Lua).
    void setProcess(ProcessHandle* proc) { ownedProc_.reset(); proc_ = proc; }
    void setOwnedProcess(std::unique_ptr<ProcessHandle> proc);
    void setResolver(SymbolResolver* resolver) { resolver_ = resolver; }

    /// Set the live cheat-table address list. The MemoryRecord/AddressList Lua API
    /// becomes usable once a non-null pointer is set. Subscribes a single activation
    /// dispatcher that fans out to per-record OnActivate callbacks stored in the Lua
    /// registry.
    void setAddressList(IAddressList* list);
    IAddressList* addressList() const { return addressList_; }

    /// Execute a Lua string. Returns error message or empty on success.
    std::string execute(const std::string& code);

    /// Execute a Lua string and return its first return value coerced to a
    /// string. Used by AutoAssembler {$lua} blocks: the Lua chunk's return
    /// value is spliced back into the AA stream.
    /// On Lua error returns std::unexpected with the Lua error message.
    std::expected<std::string, std::string> evalToString(const std::string& code);

    /// Execute a Lua file.
    std::string executeFile(const std::string& path);

    /// Set a callback for Lua print output.
    void setOutputCallback(std::function<void(const std::string&)> cb) { outputCb_ = std::move(cb); }

    lua_State* state() { return L_; }

    static LuaEngine* instanceFromState(lua_State* L);

    std::function<void(const std::string&)> outputCb_;

private:
    void registerBindings();

    lua_State* L_ = nullptr;
    std::unique_ptr<ProcessHandle> ownedProc_;
    ProcessHandle* proc_ = nullptr;
    SymbolResolver* resolver_ = nullptr;
    IAddressList* addressList_ = nullptr;
};

/// Register extended CE API bindings (defined in lua_bindings.cpp)
void registerExtendedBindings(lua_State* L);

} // namespace ce
