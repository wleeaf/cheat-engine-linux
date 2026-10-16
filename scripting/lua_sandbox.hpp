#pragma once
/// Limits for the small Lua states that run untrusted one-line code from a
/// table: breakpoint conditions and custom scan formulas. These states get no
/// engine bindings, only base, string, table and math.

extern "C" {
#include <lua.h>
#include <lauxlib.h>
}

#include <cstddef>
#include <cstdlib>

namespace ce::lua_sandbox {

// Memory cap: lua_newstate(budgetAlloc, &budget) refuses any growth past
// `limit`, which Lua reports as a memory error. The budget must outlive the
// state.
struct MemoryBudget {
    size_t used = 0;
    size_t limit = 0;
};

inline void* budgetAlloc(void* ud, void* ptr, size_t osize, size_t nsize) {
    auto* budget = static_cast<MemoryBudget*>(ud);
    const size_t old = ptr ? osize : 0;   // osize is a type tag when ptr is null
    if (nsize == 0) {
        std::free(ptr);
        budget->used -= old;
        return nullptr;
    }
    // Lua expects shrinking to succeed, so only growth is refused.
    if (nsize > old && nsize - old > budget->limit - budget->used) return nullptr;
    void* grown = std::realloc(ptr, nsize);
    if (grown) budget->used = budget->used - old + nsize;
    return grown;
}

// Instruction budget. Once it trips, the hook re-arms itself with a count of
// one, so every later instruction fails as well: catching the first error
// cannot buy more time.
inline void budgetHook(lua_State* L, lua_Debug*) {
    lua_sethook(L, budgetHook, LUA_MASKCOUNT, 1);
    luaL_error(L, "instruction limit exceeded");
}

inline void armInstructionBudget(lua_State* L, int count) {
    lua_sethook(L, budgetHook, LUA_MASKCOUNT, count);
}

// string.rep with a bounded result and count: string.rep('', 1e15) would
// otherwise loop in C, out of reach of the instruction hook.
inline constexpr lua_Integer kMaxRepBytes = lua_Integer(1) << 20;

inline int cappedStringRep(lua_State* L) {
    size_t length = 0, separator = 0;
    luaL_checklstring(L, 1, &length);
    const lua_Integer count = luaL_checkinteger(L, 2);
    luaL_optlstring(L, 3, "", &separator);
    if (count > 0 && (count > kMaxRepBytes ||
                      static_cast<lua_Integer>(length + separator) > kMaxRepBytes / count))
        return luaL_error(L, "string.rep result is too large");
    lua_pushvalue(L, lua_upvalueindex(1));
    lua_insert(L, 1);
    lua_call(L, lua_gettop(L) - 1, 1);
    return 1;
}

// Call after the libraries are open. Removes what lets code escape the
// limits: pcall and xpcall catch the budget error, setmetatable can attach a
// __gc finalizer (finalizers run with hooks off, even in lua_close), and the
// pattern functions can backtrack for hours in C. string.rep is capped.
inline void restrictLibraries(lua_State* L) {
    for (const char* name : {"pcall", "xpcall", "setmetatable", "collectgarbage", "load", "loadstring",
                             "dofile", "loadfile", "require"}) {
        lua_pushnil(L);
        lua_setglobal(L, name);
    }
    lua_getglobal(L, "string");
    if (lua_istable(L, -1)) {
        for (const char* name : {"find", "match", "gmatch", "gsub"}) {
            lua_pushnil(L);
            lua_setfield(L, -2, name);
        }
        lua_getfield(L, -1, "rep");
        lua_pushcclosure(L, cappedStringRep, 1);
        lua_setfield(L, -2, "rep");
    }
    lua_pop(L, 1);
}

} // namespace ce::lua_sandbox
