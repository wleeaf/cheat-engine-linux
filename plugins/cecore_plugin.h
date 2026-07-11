/* cecore_plugin.h — public C ABI for cecore plugins.
 *
 * Plugins are .so libraries the cecore host loads at startup (or via the
 * Plugins menu). Each plugin exports a single C symbol named
 * `ce_plugin_entry` returning a pointer to a static CePlugin descriptor:
 *
 *     CECORE_PLUGIN_EXPORT CePlugin* ce_plugin_entry(void) {
 *         static CePlugin plugin = { ... };
 *         return &plugin;
 *     }
 *
 * The host calls plugin->init(host, host_token). The plugin calls back into
 * the host through `host->*` function pointers. ABI is C, no C++ types
 * crossing the boundary.
 *
 * The legacy symbol-based ABI (ce_plugin_name / ce_plugin_init / etc.)
 * remains supported as a fallback for plugins that don't expose
 * ce_plugin_entry.
 */

#ifndef CECORE_PLUGIN_H
#define CECORE_PLUGIN_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CECORE_PLUGIN_ABI_VERSION 1

#if defined(_WIN32)
  #define CECORE_PLUGIN_EXPORT __declspec(dllexport)
#else
  #define CECORE_PLUGIN_EXPORT __attribute__((visibility("default")))
#endif

/* Forward-declare lua_State so plugins can opt into Lua bindings without
 * pulling in the full Lua headers transitively. */
struct lua_State;

typedef enum {
    CECORE_LOG_INFO    = 0,
    CECORE_LOG_WARNING = 1,
    CECORE_LOG_ERROR   = 2,
} CePluginLogLevel;

/* Host-provided vtable. Every callback takes the same `host_token` the host
 * passed to CePlugin::init so the plugin can be threaded through cleanly. */
typedef struct CePluginHost {
    int abi_version;  /* host's ABI version; plugins should refuse mismatched */

    /* Logging — routes to the host's preferred sink (stderr by default). */
    void (*log)(void* host_token, CePluginLogLevel level, const char* message);

    /* Register a Lua C function under `name`. The function is registered as
     * a global on the host's main Lua state. Returns 0 on success. */
    int (*register_lua_function)(void* host_token, const char* name,
                                 int (*fn)(struct lua_State* L));

    /* Currently attached target process. Returns 0 when no process is open. */
    int (*get_attached_pid)(void* host_token);

    /* Memory access against the currently attached target process. Returns
     * the byte count read/written, or -1 on error. */
    long (*read_memory)(void* host_token, uintptr_t address, void* buffer, size_t size);
    long (*write_memory)(void* host_token, uintptr_t address, const void* buffer, size_t size);

    /* Reserved for future expansion. Hosts may add callbacks at the bottom of
     * this struct in subsequent ABI versions; bumping abi_version signals
     * compatibility breaks. */
} CePluginHost;

typedef struct CePluginInfo {
    const char* name;
    const char* version;
    const char* author;
    const char* description;
} CePluginInfo;

typedef struct CePlugin {
    int abi_version;          /* must equal CECORE_PLUGIN_ABI_VERSION at compile time */
    CePluginInfo info;

    /* Called once, just after the host loads the plugin. Return 0 on success.
     * `host` and `host_token` together let the plugin call back into cecore. */
    int (*init)(const CePluginHost* host, void* host_token);

    /* Called once just before unload. May be NULL. */
    void (*shutdown)(void);
} CePlugin;

/* Each plugin must export this entry point. */
typedef CePlugin* (*CePluginEntryFn)(void);
#define CECORE_PLUGIN_ENTRY_SYMBOL "ce_plugin_entry"

#ifdef __cplusplus
}
#endif

#endif /* CECORE_PLUGIN_H */
