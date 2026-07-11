/// Lua bindings for ce::Snapshot — capture / diff / restore / save / load
/// from script. Tables that want bulk memory checkpoints (e.g. "snapshot
/// before fight, restore on death") use these.

#include "scanner/snapshot.hpp"
#include "platform/process_api.hpp"

extern "C" {
#include <lua.h>
#include <lauxlib.h>
}

#include <string>
#include <new>
#include <memory>

namespace ce {

namespace {

constexpr const char* SNAPSHOT_MT = "ce.Snapshot";

struct LuaSnapshotHolder {
    std::shared_ptr<Snapshot> snap;
};

LuaSnapshotHolder* checkSnap(lua_State* L, int idx) {
    return static_cast<LuaSnapshotHolder*>(luaL_checkudata(L, idx, SNAPSHOT_MT));
}

ProcessHandle* getProcFromRegistry(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_proc");
    auto* p = (ProcessHandle*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    return p;
}

void pushSnapshot(lua_State* L, std::shared_ptr<Snapshot> snap) {
    auto* h = static_cast<LuaSnapshotHolder*>(
        lua_newuserdata(L, sizeof(LuaSnapshotHolder)));
    new (h) LuaSnapshotHolder{std::move(snap)};
    luaL_setmetatable(L, SNAPSHOT_MT);
}

int l_snap__gc(lua_State* L) {
    auto* h = checkSnap(L, 1);
    h->~LuaSnapshotHolder();
    return 0;
}

int l_captureSnapshot(lua_State* L) {
    auto* proc = getProcFromRegistry(L);
    if (!proc) { lua_pushnil(L); return 1; }
    uint64_t maxBytes = ~0ULL;
    if (lua_gettop(L) >= 1 && lua_isnumber(L, 1)) {
        lua_Integer arg = lua_tointeger(L, 1);
        // A negative budget would wrap to a huge unsigned cap and silently
        // defeat the intended byte limit; reject it instead.
        if (arg < 0)
            return luaL_argerror(L, 1, "byte budget must be non-negative");
        maxBytes = (uint64_t)arg;
    }
    auto snap = std::make_shared<Snapshot>(Snapshot::capture(*proc, maxBytes));
    pushSnapshot(L, std::move(snap));
    return 1;
}

int l_loadSnapshot(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    auto snap = std::make_shared<Snapshot>();
    std::string err;
    if (!snap->load(path, &err)) {
        lua_pushnil(L);
        lua_pushstring(L, err.c_str());
        return 2;
    }
    pushSnapshot(L, std::move(snap));
    return 1;
}

int l_snap_save(lua_State* L) {
    auto* h = checkSnap(L, 1);
    const char* path = luaL_checkstring(L, 2);
    lua_pushboolean(L, h->snap && h->snap->save(path));
    return 1;
}

int l_snap_regionCount(lua_State* L) {
    auto* h = checkSnap(L, 1);
    lua_pushinteger(L, h->snap ? (lua_Integer)h->snap->regionCount() : 0);
    return 1;
}

int l_snap_byteCount(lua_State* L) {
    auto* h = checkSnap(L, 1);
    lua_pushinteger(L, h->snap ? (lua_Integer)h->snap->byteCount() : 0);
    return 1;
}

int l_snap_restore(lua_State* L) {
    auto* h = checkSnap(L, 1);
    auto* proc = getProcFromRegistry(L);
    if (!proc || !h->snap) { lua_pushinteger(L, 0); return 1; }
    lua_pushinteger(L, (lua_Integer)h->snap->restore(*proc));
    return 1;
}

int l_snap_diff(lua_State* L) {
    auto* a = checkSnap(L, 1);
    auto* b = checkSnap(L, 2);
    if (!a->snap || !b->snap) { lua_newtable(L); return 1; }
    auto diffs = a->snap->diff(*b->snap);
    lua_newtable(L);
    for (size_t i = 0; i < diffs.size(); ++i) {
        lua_newtable(L);
        lua_pushinteger(L, (lua_Integer)diffs[i].address); lua_setfield(L, -2, "address");
        lua_pushinteger(L, diffs[i].before); lua_setfield(L, -2, "before");
        lua_pushinteger(L, diffs[i].after);  lua_setfield(L, -2, "after");
        lua_rawseti(L, -2, (lua_Integer)i + 1);
    }
    return 1;
}

void buildSnapshotMetatable(lua_State* L) {
    luaL_newmetatable(L, SNAPSHOT_MT);
    static const luaL_Reg methods[] = {
        {"save",        l_snap_save},
        {"regionCount", l_snap_regionCount},
        {"byteCount",   l_snap_byteCount},
        {"restore",     l_snap_restore},
        {"diff",        l_snap_diff},
        {nullptr, nullptr},
    };
    luaL_setfuncs(L, methods, 0);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, l_snap__gc);
    lua_setfield(L, -2, "__gc");
    lua_pop(L, 1);
}

} // anonymous namespace

void registerSnapshotBindings(lua_State* L) {
    buildSnapshotMetatable(L);
    lua_register(L, "captureSnapshot", l_captureSnapshot);
    lua_register(L, "loadSnapshot",    l_loadSnapshot);
}

} // namespace ce
