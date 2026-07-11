/* sample_plugin.c — exercises every callback in the structured plugin ABI.
 *
 * Built as cecore_sample_plugin.so by CMakeLists.txt and loaded by the
 * plugin loader regression test.
 */

#include "plugins/cecore_plugin.h"
#include <stdio.h>
#include <string.h>

/* The host's vtable + token, captured at init time. */
static const CePluginHost* g_host = NULL;
static void* g_token = NULL;

/* Stats updated as the host calls into us. Inspected from the test. */
volatile int g_sample_init_calls = 0;
volatile int g_sample_shutdown_calls = 0;
volatile int g_sample_lua_fn_calls = 0;
volatile int g_sample_attached_pid_seen = -1;

/* A Lua C function the plugin registers under the name `sample_plugin_ping`. */
static int sample_lua_ping(struct lua_State* L) {
    (void)L;
    ++g_sample_lua_fn_calls;
    return 0;
}

static int sample_init(const CePluginHost* host, void* token) {
    g_host = host;
    g_token = token;
    ++g_sample_init_calls;
    if (!host) return -1;

    if (host->log)
        host->log(token, CECORE_LOG_INFO, "sample plugin: init called");

    if (host->register_lua_function)
        host->register_lua_function(token, "sample_plugin_ping", sample_lua_ping);

    if (host->get_attached_pid)
        g_sample_attached_pid_seen = host->get_attached_pid(token);

    return 0;
}

static void sample_shutdown(void) {
    ++g_sample_shutdown_calls;
    if (g_host && g_host->log)
        g_host->log(g_token, CECORE_LOG_INFO, "sample plugin: shutdown called");
}

CECORE_PLUGIN_EXPORT CePlugin* ce_plugin_entry(void) {
    static CePlugin plugin;
    static int initialised = 0;
    if (!initialised) {
        plugin.abi_version = CECORE_PLUGIN_ABI_VERSION;
        plugin.info.name = "Sample Plugin";
        plugin.info.version = "1.0";
        plugin.info.author = "cecore";
        plugin.info.description = "Built-in regression sample exercising the plugin ABI";
        plugin.init = sample_init;
        plugin.shutdown = sample_shutdown;
        initialised = 1;
    }
    return &plugin;
}
