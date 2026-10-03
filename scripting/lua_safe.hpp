#pragma once

extern "C" {
#include <lua.h>
#include <lauxlib.h>
}

#include <cstdio>
#include <exception>

namespace ce {

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

} // namespace ce
