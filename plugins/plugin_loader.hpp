#pragma once
/// Plugin system — loads .so plugins from a directory.
///
/// Two ABIs supported:
///  1. Structured (preferred): plugin exports `ce_plugin_entry` returning a
///     CePlugin* pointing to its info + init/shutdown function pointers,
///     wired through a CePluginHost vtable owned by this loader.
///     Defined in plugins/cecore_plugin.h.
///  2. Legacy symbol-based: plugin exports ce_plugin_name / ce_plugin_version /
///     ce_plugin_init / ce_plugin_cleanup. Maintained for backward compat.

#include <string>
#include <vector>
#include <filesystem>
#include <functional>

struct lua_State;

namespace ce {

class LuaEngine;
class ProcessHandle;

enum class PluginAbi {
    Legacy,      // ce_plugin_init/cleanup
    Structured,  // ce_plugin_entry returning CePlugin*
};

struct PluginInfo {
    std::string name;
    std::string path;
    std::string version;
    std::string author;
    std::string description;
    PluginAbi abi = PluginAbi::Legacy;
    void* handle = nullptr;          // dlopen handle
    void* descriptor = nullptr;      // CePlugin* for structured plugins (do not free)
};

class PluginLoader {
public:
    using LogSink = std::function<void(int level, const std::string& message)>;

    /// Wire the host services structured plugins can call back into.
    void setLuaEngine(LuaEngine* engine) { luaEngine_ = engine; }
    void setProcess(ProcessHandle* proc) { proc_ = proc; }
    void setLogSink(LogSink sink) { logSink_ = std::move(sink); }

    LuaEngine* luaEngine() const { return luaEngine_; }
    ProcessHandle* process() const { return proc_; }
    void log(int level, const std::string& message) const;

    /// Load all .so plugins from a directory.
    void loadDirectory(const std::filesystem::path& dir);

    /// Load a single plugin.
    bool loadPlugin(const std::filesystem::path& path);

    /// Unload all plugins.
    void unloadAll();

    const std::vector<PluginInfo>& plugins() const { return plugins_; }

    ~PluginLoader() { unloadAll(); }

private:
    bool loadStructured(void* handle, const std::filesystem::path& path);
    bool loadLegacy(void* handle, const std::filesystem::path& path);
    void initHostVtableOnce();

    std::vector<PluginInfo> plugins_;
    LuaEngine* luaEngine_ = nullptr;
    ProcessHandle* proc_ = nullptr;
    LogSink logSink_;
    void* hostVtable_ = nullptr;  // Heap-allocated CePluginHost; lifetime = loader.
};

} // namespace ce
