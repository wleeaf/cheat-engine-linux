#pragma once

extern "C" {
#include <lua.h>
#include <lauxlib.h>
}

#include <cstdio>
#include <cstdlib>
#include <exception>

#include "core/secure_exec.hpp"

namespace ce {

// Default-deny: shell commands, native code, writing files on this computer
// and cecore's own memory need CECORE_LUA_ALLOW_UNSAFE=1 in the environment
// Cheat Engine was started with. A script cannot set it: each Lua state reads
// it once, when the engine creates the state (markLuaUnsafeAllowed), so a
// script that later changes cecore's environment gains nothing.
inline constexpr const char* kLuaUnsafeKey = "ce_unsafe_allowed";
// A secure-exec process (started with the ptrace capability) never honours it:
// whoever starts the program is not trusted with native code in it.
inline void markLuaUnsafeAllowed(lua_State* L) {
    lua_pushboolean(L, std::getenv("CECORE_LUA_ALLOW_UNSAFE") != nullptr && !secureExecution());
    lua_setfield(L, LUA_REGISTRYINDEX, kLuaUnsafeKey);
}
inline bool luaUnsafeAllowed(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, kLuaUnsafeKey);
    const bool allowed = lua_toboolean(L, -1);
    lua_pop(L, 1);
    return allowed;
}

template <lua_CFunction Fn>
int guardFileWrite(lua_State* L) {
    if (!luaUnsafeAllowed(L))
        return luaL_error(L, "writing files is blocked: a table could overwrite any of your files. Enable it only "
                             "for tables you trust by launching with CECORE_LUA_ALLOW_UNSAFE=1 (see SECURITY.md).");
    return Fn(L);
}

// Leave the catch scope before raising a Lua error: luaL_error uses longjmp,
// so raising it while a C++ exception is alive would skip its destruction.
inline int safeLuaCall(lua_State* L) {
    auto function = reinterpret_cast<lua_CFunction>(lua_touserdata(L, lua_upvalueindex(1)));
    char error[512];
    try { return function(L); }
    catch (const std::exception& e) { std::snprintf(error, sizeof(error), "%s", e.what()); }
    catch (...) { std::snprintf(error, sizeof(error), "unhandled C++ exception in a native Lua binding"); }
    return luaL_error(L, "%s", error);
}

inline void pushSafeLuaFunction(lua_State* L, lua_CFunction function) {
    lua_pushlightuserdata(L, reinterpret_cast<void*>(function));
    lua_pushcclosure(L, safeLuaCall, 1);
}

inline void registerSafeLuaFunction(lua_State* L, const char* name, lua_CFunction function) {
    pushSafeLuaFunction(L, function);
    lua_setglobal(L, name);
}

inline void setSafeLuaFunctions(lua_State* L, const luaL_Reg* functions, int upvalues) {
    // These bindings have no upvalues. Keep the check explicit so a future
    // registration cannot silently change a function's upvalue indexes.
    if (upvalues != 0) luaL_error(L, "guarded method registration requires zero upvalues");
    for (const auto* f = functions; f->name; ++f) {
        pushSafeLuaFunction(L, f->func);
        lua_setfield(L, -2, f->name);
    }
}

// Methods fetched through __index come back bound to their object, so both
// obj:method(x) and obj.method(x) work, as in CE. A call whose first argument
// is the object itself is a ':' call and passes through unchanged.
inline int boundMethodCall(lua_State* L) {
    if (lua_gettop(L) == 0 || !lua_rawequal(L, 1, lua_upvalueindex(2))) {
        lua_pushvalue(L, lua_upvalueindex(2));
        lua_insert(L, 1);
    }
    lua_pushvalue(L, lua_upvalueindex(1));
    lua_insert(L, 1);
    lua_call(L, lua_gettop(L) - 1, LUA_MULTRET);
    return lua_gettop(L);
}

// Replace the method on top of the stack with one bound to the object at `object`.
inline void bindMethod(lua_State* L, int object) {
    object = lua_absindex(L, object);
    lua_pushvalue(L, object);
    lua_pushcclosure(L, boundMethodCall, 2);
}

} // namespace ce
