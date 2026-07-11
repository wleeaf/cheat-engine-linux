/// Plugin loader. Supports both the structured ABI (ce_plugin_entry +
/// CePluginHost vtable, defined in plugins/cecore_plugin.h) and the legacy
/// symbol-based ABI used by older plugins.

#include "plugins/plugin_loader.hpp"
#include "plugins/cecore_plugin.h"
#include "scripting/lua_engine.hpp"
#include "platform/process_api.hpp"

extern "C" {
#include <lua.h>
#include <lauxlib.h>
}

#include <dlfcn.h>
#include <cstdio>
#include <cstring>
#include <mutex>

namespace ce {

namespace {

// Host-side callbacks. Each takes the loader pointer as host_token and reads
// luaEngine_ / proc_ at call time so updates propagate naturally.
void hostLog(void* token, CePluginLogLevel level, const char* message) {
    auto* loader = static_cast<PluginLoader*>(token);
    if (!loader) return;
    loader->log(static_cast<int>(level), message ? message : "");
}

int hostRegisterLuaFunction(void* token, const char* name, int (*fn)(lua_State*)) {
    auto* loader = static_cast<PluginLoader*>(token);
    if (!loader || !name || !fn) return -1;
    auto* engine = loader->luaEngine();
    if (!engine || !engine->state()) return -2;
    lua_register(engine->state(), name, fn);
    return 0;
}

int hostGetAttachedPid(void* token) {
    auto* loader = static_cast<PluginLoader*>(token);
    if (!loader || !loader->process()) return 0;
    return loader->process()->pid();
}

long hostReadMemory(void* token, uintptr_t address, void* buffer, size_t size) {
    auto* loader = static_cast<PluginLoader*>(token);
    if (!loader || !loader->process() || !buffer || size == 0) return -1;
    auto r = loader->process()->read(address, buffer, size);
    return r ? static_cast<long>(*r) : -1;
}

long hostWriteMemory(void* token, uintptr_t address, const void* buffer, size_t size) {
    auto* loader = static_cast<PluginLoader*>(token);
    if (!loader || !loader->process() || !buffer || size == 0) return -1;
    auto r = loader->process()->write(address, buffer, size);
    return r ? static_cast<long>(*r) : -1;
}

} // namespace

void PluginLoader::initHostVtableOnce() {
    // Serialise the per-instance check-then-act so concurrent loadPlugin()
    // calls can't both see hostVtable_ == nullptr and leak a CePluginHost.
    // A plain mutex (not call_once) preserves the per-instance semantics: each
    // distinct loader still gets its own vtable.
    static std::mutex initMutex;
    std::lock_guard<std::mutex> lk(initMutex);
    if (hostVtable_) return;
    auto* h = new CePluginHost{};
    h->abi_version = CECORE_PLUGIN_ABI_VERSION;
    h->log = &hostLog;
    h->register_lua_function = &hostRegisterLuaFunction;
    h->get_attached_pid = &hostGetAttachedPid;
    h->read_memory = &hostReadMemory;
    h->write_memory = &hostWriteMemory;
    hostVtable_ = h;
}

void PluginLoader::log(int level, const std::string& message) const {
    if (logSink_) {
        logSink_(level, message);
        return;
    }
    const char* prefix = "PLUGIN";
    switch (level) {
        case CECORE_LOG_WARNING: prefix = "PLUGIN WARN"; break;
        case CECORE_LOG_ERROR:   prefix = "PLUGIN ERR"; break;
        default: prefix = "PLUGIN INFO"; break;
    }
    std::fprintf(stderr, "[%s] %s\n", prefix, message.c_str());
}

void PluginLoader::loadDirectory(const std::filesystem::path& dir) {
    if (!std::filesystem::exists(dir)) return;
    for (auto& entry : std::filesystem::directory_iterator(dir)) {
        if (entry.path().extension() == ".so")
            loadPlugin(entry.path());
    }
}

bool PluginLoader::loadPlugin(const std::filesystem::path& path) {
    void* handle = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        std::fprintf(stderr, "Plugin load failed: %s: %s\n", path.c_str(), dlerror());
        return false;
    }
    if (loadStructured(handle, path)) return true;
    if (loadLegacy(handle, path))     return true;

    std::fprintf(stderr, "Plugin %s exposes no recognised entry symbol\n", path.c_str());
    dlclose(handle);
    return false;
}

bool PluginLoader::loadStructured(void* handle, const std::filesystem::path& path) {
    auto entry = reinterpret_cast<CePluginEntryFn>(dlsym(handle, CECORE_PLUGIN_ENTRY_SYMBOL));
    if (!entry) return false;

    CePlugin* descriptor = entry();
    if (!descriptor) {
        std::fprintf(stderr, "Plugin %s entry returned NULL\n", path.c_str());
        return false;
    }
    if (descriptor->abi_version != CECORE_PLUGIN_ABI_VERSION) {
        std::fprintf(stderr, "Plugin %s ABI mismatch: plugin=%d host=%d\n",
            path.c_str(), descriptor->abi_version, CECORE_PLUGIN_ABI_VERSION);
        return false;
    }

    PluginInfo info;
    info.path = path.string();
    info.handle = handle;
    info.descriptor = descriptor;
    info.abi = PluginAbi::Structured;
    info.name        = descriptor->info.name        ? descriptor->info.name        : path.stem().string();
    info.version     = descriptor->info.version     ? descriptor->info.version     : "unknown";
    info.author      = descriptor->info.author      ? descriptor->info.author      : "";
    info.description = descriptor->info.description ? descriptor->info.description : "";

    if (descriptor->init) {
        initHostVtableOnce();
        int rc = descriptor->init(static_cast<const CePluginHost*>(hostVtable_), this);
        if (rc != 0) {
            std::fprintf(stderr, "Plugin %s init returned %d\n", info.name.c_str(), rc);
            return false;
        }
    }
    plugins_.push_back(std::move(info));
    return true;
}

bool PluginLoader::loadLegacy(void* handle, const std::filesystem::path& path) {
    auto getName    = reinterpret_cast<const char*(*)()>(dlsym(handle, "ce_plugin_name"));
    auto getVersion = reinterpret_cast<const char*(*)()>(dlsym(handle, "ce_plugin_version"));
    auto init       = reinterpret_cast<int(*)()>(dlsym(handle, "ce_plugin_init"));

    if (!getName && !init) return false;  // not a legacy plugin either

    PluginInfo info;
    info.path = path.string();
    info.handle = handle;
    info.abi = PluginAbi::Legacy;
    info.name    = getName    ? getName()    : path.stem().string();
    info.version = getVersion ? getVersion() : "unknown";

    if (init && init() != 0) {
        std::fprintf(stderr, "Plugin init failed: %s\n", info.name.c_str());
        return false;
    }
    plugins_.push_back(std::move(info));
    return true;
}

void PluginLoader::unloadAll() {
    for (auto& p : plugins_) {
        if (!p.handle) continue;
        if (p.abi == PluginAbi::Structured) {
            auto* desc = static_cast<CePlugin*>(p.descriptor);
            if (desc && desc->shutdown) desc->shutdown();
        } else {
            auto cleanup = reinterpret_cast<void(*)()>(dlsym(p.handle, "ce_plugin_cleanup"));
            if (cleanup) cleanup();
        }
        // NOTE: plugins must join any threads they spawned before shutdown()
        // returns; dlclose unmaps the code and a still-running plugin thread
        // would crash. That contract is the plugin's to honour.
        if (dlclose(p.handle) != 0)
            std::fprintf(stderr, "Plugin unload (dlclose) failed: %s: %s\n",
                         p.name.c_str(), dlerror());
    }
    plugins_.clear();
    if (hostVtable_) {
        delete static_cast<CePluginHost*>(hostVtable_);
        hostVtable_ = nullptr;
    }
}

} // namespace ce
