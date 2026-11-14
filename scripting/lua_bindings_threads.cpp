/// Lua bindings: hotkeys and Lua threads.
#include "core/target_capabilities.hpp"
#include "core/local_target.hpp"
#include "core/module_files.hpp"
#include "arch/target_arch.hpp"
/// Extended Lua API bindings — CE-compatible function set.
#include <charconv>
#include <bit>
#include <array>
#include <csignal>
#include "scripting/lua_engine.hpp"
#include "scripting/lua_safe.hpp"
#include "core/ct_file.hpp"
#include "core/trainer.hpp"
#include "core/address_list.hpp"
#include "analysis/managed_runtime.hpp"
#include "analysis/mono_dissector.hpp"
#include "analysis/il2cpp_metadata.hpp"
#include "analysis/il2cpp_binary.hpp"
#include "analysis/signature.hpp"
#include "analysis/pe_exports.hpp"
#include "symbols/dwarf_symbols.hpp"
#include "core/simple_hook.hpp"
#include "analysis/structure_tools.hpp"
#include "analysis/code_analysis.hpp"
#include "scripting/lua_memrec.hpp"
#include "scanner/memory_scanner.hpp"
#include "scanner/pointer_scanner.hpp"
#include "core/autoasm.hpp"
#include "core/value_io.hpp"
#include "core/value_transform.hpp"
#include "core/expression.hpp"
#include "core/injection_gen.hpp"
#include "arch/disassembler.hpp"
#include "arch/assembler.hpp"
#include "debug/patch.hpp"
#include "debug/debug_session.hpp"
#include "debug/code_finder.hpp"
#include "debug/tracer.hpp"
#include "debug/lbr_tracer.hpp"
#include "platform/linux/ptrace_wrapper.hpp"
#include "symbols/elf_symbols.hpp"
#include "platform/linux/linux_process.hpp"
#include "platform/linux/injector.hpp"
#include "platform/linux/target_syscall.hpp"
#include <climits>
#include "platform/linux/ceserver_client.hpp"
#include "platform/linux/ceserver_process.hpp"
#include "platform/gdb_process.hpp"

extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}

#include <cstring>
#include <sys/uio.h>
#include <cerrno>
#include <iconv.h>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <linux/input.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <filesystem>
#include <limits>
#include <cmath>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>
#include <algorithm>
#include <stdexcept>
#include <unordered_map>
#include <cctype>

#undef lua_pushcfunction
#define lua_pushcfunction(L, f) ce::pushSafeLuaFunction((L), (f))

#include "scripting/lua_bindings_internal.hpp"
namespace ce::lua_detail {

// ── Hotkeys ──

struct LuaHotkey {
    int callbackRef = LUA_NOREF;
    bool enabled = true;
    std::vector<int> keys;
};

struct LuaHotkeyRef { LuaHotkey* data; };

static LuaHotkey* checkHotkey(lua_State* L, int index) {
    auto* ref = static_cast<LuaHotkeyRef*>(luaL_checkudata(L, index, "CEHotkey"));
    if (!ref->data) luaL_error(L, "hotkey is destroyed");
    return ref->data;
}

int l_hotkey_gc(lua_State* L) {
    auto* ref = static_cast<LuaHotkeyRef*>(luaL_checkudata(L, 1, "CEHotkey"));
    auto* hotkey = ref->data;
    if (!hotkey) return 0;
    if (hotkey->callbackRef != LUA_NOREF) {
        luaL_unref(L, LUA_REGISTRYINDEX, hotkey->callbackRef);
        hotkey->callbackRef = LUA_NOREF;
    }
    delete hotkey;
    ref->data = nullptr;
    return 0;
}

int l_hotkey_trigger(lua_State* L) {
    auto* hotkey = checkHotkey(L, 1);
    if (!hotkey->enabled || hotkey->callbackRef == LUA_NOREF) {
        lua_pushboolean(L, 0);
        return 1;
    }

    lua_rawgeti(L, LUA_REGISTRYINDEX, hotkey->callbackRef);
    if (lua_pcall(L, 0, 0, 0) != LUA_OK) {
        // Copy the message before popping it: pushing a new string can run a GC
        // step that collects the now-unreferenced error string (use-after-free).
        const char* err = lua_tostring(L, -1);
        std::string msg = err ? err : "hotkey callback failed";
        lua_pop(L, 1);
        lua_pushnil(L);
        lua_pushlstring(L, msg.data(), msg.size());
        return 2;
    }
    lua_pushboolean(L, 1);
    return 1;
}

int l_hotkey_destroy(lua_State* L) {
    auto* hotkey = checkHotkey(L, 1);
    hotkey->enabled = false;
    if (hotkey->callbackRef != LUA_NOREF) {
        luaL_unref(L, LUA_REGISTRYINDEX, hotkey->callbackRef);
        hotkey->callbackRef = LUA_NOREF;
    }
    return 0;
}

int l_hotkey_getKeys(lua_State* L) {
    auto* hotkey = checkHotkey(L, 1);
    lua_newtable(L);
    for (size_t i = 0; i < hotkey->keys.size(); ++i) {
        lua_pushinteger(L, hotkey->keys[i]);
        lua_rawseti(L, -2, static_cast<int>(i + 1));
    }
    return 1;
}

int l_hotkey_index(lua_State* L) {
    auto* hotkey = checkHotkey(L, 1);
    const char* key = luaL_checkstring(L, 2);
    if (std::strcmp(key, "Enabled") == 0 || std::strcmp(key, "enabled") == 0) {
        lua_pushboolean(L, hotkey->enabled);
        return 1;
    }
    if (std::strcmp(key, "trigger") == 0 || std::strcmp(key, "doHotkey") == 0) {
        lua_pushcfunction(L, l_hotkey_trigger);
        return 1;
    }
    if (std::strcmp(key, "destroy") == 0 || std::strcmp(key, "Destroy") == 0) {
        lua_pushcfunction(L, l_hotkey_destroy);
        return 1;
    }
    if (std::strcmp(key, "getKeys") == 0 || std::strcmp(key, "GetKeys") == 0) {
        lua_pushcfunction(L, l_hotkey_getKeys);
        return 1;
    }
    lua_pushnil(L);
    return 1;
}

int l_hotkey_newindex(lua_State* L) {
    auto* hotkey = checkHotkey(L, 1);
    const char* key = luaL_checkstring(L, 2);
    if (std::strcmp(key, "Enabled") == 0 || std::strcmp(key, "enabled") == 0)
        hotkey->enabled = lua_toboolean(L, 3) != 0;
    return 0;
}

static void ensureHotkeyMetatable(lua_State* L) {
    if (luaL_newmetatable(L, "CEHotkey")) {
        lua_pushcfunction(L, l_hotkey_gc);
        lua_setfield(L, -2, "__gc");
        lua_pushcfunction(L, l_hotkey_index);
        lua_setfield(L, -2, "__index");
        lua_pushcfunction(L, l_hotkey_newindex);
        lua_setfield(L, -2, "__newindex");
    }
    lua_pop(L, 1);
}

int l_createHotkey(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    ensureHotkeyMetatable(L);

    auto* ref = static_cast<LuaHotkeyRef*>(lua_newuserdata(L, sizeof(LuaHotkeyRef)));
    ref->data = nullptr;
    luaL_setmetatable(L, "CEHotkey");
    auto* hotkey = new LuaHotkey();
    ref->data = hotkey;
    lua_pushvalue(L, 1);
    hotkey->callbackRef = luaL_ref(L, LUA_REGISTRYINDEX);

    int top = lua_gettop(L);
    for (int i = 2; i < top; ++i) {
        if (lua_isinteger(L, i))
            hotkey->keys.push_back(static_cast<int>(lua_tointeger(L, i)));
    }

    luaL_getmetatable(L, "CEHotkey");
    lua_setmetatable(L, -2);
    return 1;
}

int l_setHotkeyAction(lua_State* L) {
    auto* hotkey = checkHotkey(L, 1);
    luaL_checktype(L, 2, LUA_TFUNCTION);
    if (hotkey->callbackRef != LUA_NOREF)
        luaL_unref(L, LUA_REGISTRYINDEX, hotkey->callbackRef);
    lua_pushvalue(L, 2);
    hotkey->callbackRef = luaL_ref(L, LUA_REGISTRYINDEX);
    return 0;
}

// ── Thread helpers ──

struct LuaThread {
    int callbackRef = LUA_NOREF;
    bool finished = false;
    bool terminated = false;
    bool suspended = false;
    bool running = false;
    std::string name;
    std::string lastError;
};

struct LuaThreadRef { std::shared_ptr<LuaThread>* data; };

static LuaThread* checkThread(lua_State* L, int index) {
    auto* ref = static_cast<LuaThreadRef*>(luaL_checkudata(L, index, "CEThread"));
    if (!ref->data) luaL_error(L, "thread is destroyed");
    return ref->data->get();
}

static bool runThreadCallback(lua_State* L, LuaThread* thread) {
    if (thread->running) {
        thread->lastError = "thread callback is already running";
        return false;
    }
    if (thread->terminated || thread->finished || thread->callbackRef == LUA_NOREF)
        return true;

    thread->suspended = false;
    thread->running = true;
    lua_rawgeti(L, LUA_REGISTRYINDEX, thread->callbackRef);
    if (lua_pcall(L, 0, 0, 0) != LUA_OK) {
        thread->running = false;
        const char* err = lua_tostring(L, -1);
        thread->lastError = err ? err : "thread callback failed";
        lua_pop(L, 1);
        thread->finished = true;
        return false;
    }
    thread->running = false;
    thread->finished = true;
    return true;
}

int l_thread_gc(lua_State* L) {
    auto* ref = static_cast<LuaThreadRef*>(luaL_checkudata(L, 1, "CEThread"));
    if (!ref->data) return 0;
    auto* thread = ref->data->get();
    if (thread->callbackRef != LUA_NOREF) {
        luaL_unref(L, LUA_REGISTRYINDEX, thread->callbackRef);
        thread->callbackRef = LUA_NOREF;
    }
    delete ref->data;
    ref->data = nullptr;
    return 0;
}

int l_thread_waitfor(lua_State* L) {
    auto* thread = checkThread(L, 1);
    lua_pushboolean(L, thread->finished);
    return 1;
}

int l_thread_terminate(lua_State* L) {
    auto* thread = checkThread(L, 1);
    thread->terminated = true;
    thread->finished = true;
    lua_pushboolean(L, 1);
    return 1;
}

int l_thread_suspend(lua_State* L) {
    auto* thread = checkThread(L, 1);
    if (!thread->finished)
        thread->suspended = true;
    lua_pushboolean(L, 1);
    return 1;
}

int l_thread_resume(lua_State* L) {
    auto* thread = checkThread(L, 1);
    // A callback may explicitly collect its userdata. Keep its state alive
    // until the callback and this method have both finished using it.
    auto* ref = static_cast<LuaThreadRef*>(luaL_checkudata(L, 1, "CEThread"));
    auto held = *ref->data;
    bool ok = runThreadCallback(L, thread);
    lua_pushboolean(L, ok);
    if (!ok) {
        lua_pushstring(L, thread->lastError.c_str());
        return 2;
    }
    return 1;
}

int l_thread_index(lua_State* L) {
    auto* thread = checkThread(L, 1);
    const char* key = luaL_checkstring(L, 2);
    if (std::strcmp(key, "Finished") == 0 || std::strcmp(key, "finished") == 0) {
        lua_pushboolean(L, thread->finished);
        return 1;
    }
    if (std::strcmp(key, "Terminated") == 0 || std::strcmp(key, "terminated") == 0) {
        lua_pushboolean(L, thread->terminated);
        return 1;
    }
    if (std::strcmp(key, "Suspended") == 0 || std::strcmp(key, "suspended") == 0) {
        lua_pushboolean(L, thread->suspended);
        return 1;
    }
    if (std::strcmp(key, "Name") == 0 || std::strcmp(key, "name") == 0) {
        lua_pushstring(L, thread->name.c_str());
        return 1;
    }
    if (std::strcmp(key, "LastError") == 0 || std::strcmp(key, "lastError") == 0) {
        lua_pushstring(L, thread->lastError.c_str());
        return 1;
    }
    if (std::strcmp(key, "waitfor") == 0 || std::strcmp(key, "waitFor") == 0) {
        lua_pushcfunction(L, l_thread_waitfor);
        return 1;
    }
    if (std::strcmp(key, "terminate") == 0 || std::strcmp(key, "Terminate") == 0) {
        lua_pushcfunction(L, l_thread_terminate);
        return 1;
    }
    if (std::strcmp(key, "suspend") == 0 || std::strcmp(key, "Suspend") == 0) {
        lua_pushcfunction(L, l_thread_suspend);
        return 1;
    }
    if (std::strcmp(key, "resume") == 0 || std::strcmp(key, "Resume") == 0) {
        lua_pushcfunction(L, l_thread_resume);
        return 1;
    }
    lua_pushnil(L);
    return 1;
}

int l_thread_newindex(lua_State* L) {
    auto* thread = checkThread(L, 1);
    const char* key = luaL_checkstring(L, 2);
    if (std::strcmp(key, "Name") == 0 || std::strcmp(key, "name") == 0)
        thread->name = luaL_checkstring(L, 3);
    return 0;
}

static void ensureThreadMetatable(lua_State* L) {
    if (luaL_newmetatable(L, "CEThread")) {
        lua_pushcfunction(L, l_thread_gc);
        lua_setfield(L, -2, "__gc");
        lua_pushcfunction(L, l_thread_index);
        lua_setfield(L, -2, "__index");
        lua_pushcfunction(L, l_thread_newindex);
        lua_setfield(L, -2, "__newindex");
    }
    lua_pop(L, 1);
}

int l_createThread(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    ensureThreadMetatable(L);

    bool suspended = lua_toboolean(L, 2) != 0;
    auto* ref = static_cast<LuaThreadRef*>(lua_newuserdata(L, sizeof(LuaThreadRef)));
    ref->data = nullptr;
    luaL_setmetatable(L, "CEThread");
    auto held = std::make_shared<LuaThread>();
    ref->data = new std::shared_ptr<LuaThread>(held);
    auto* thread = held.get();
    thread->suspended = suspended;
    lua_pushvalue(L, 1);
    thread->callbackRef = luaL_ref(L, LUA_REGISTRYINDEX);

    luaL_getmetatable(L, "CEThread");
    lua_setmetatable(L, -2);

    if (!suspended)
        runThreadCallback(L, thread);
    return 1;
}

int l_synchronize(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    int base = lua_gettop(L);
    lua_pushvalue(L, 1);
    if (lua_pcall(L, 0, LUA_MULTRET, 0) != LUA_OK)
        return lua_error(L);
    return lua_gettop(L) - base;
}

int l_queue(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    lua_pushvalue(L, 1);
    if (lua_pcall(L, 0, 0, 0) != LUA_OK)
        return lua_error(L);
    lua_pushboolean(L, 1);
    return 1;
}
} // namespace ce::lua_detail
