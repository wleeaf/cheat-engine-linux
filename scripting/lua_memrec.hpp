#pragma once
/// Lua bindings for the MemoryRecord and AddressList objects.
/// Registered by registerMemoryRecordBindings() during LuaEngine setup.
/// Operates against ce::IAddressList stored in LUA_REGISTRYINDEX["ce_addresslist"].

struct lua_State;

namespace ce {

void registerMemoryRecordBindings(lua_State* L);

// Push the per-record OnActivate table for the current list, starting a fresh
// one if the list was replaced since the callbacks were stored.
void pushMemRecCallbacks(lua_State* L);

} // namespace ce
