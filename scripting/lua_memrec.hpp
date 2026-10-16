#pragma once
/// Lua bindings for the MemoryRecord and AddressList objects.
/// Registered by registerMemoryRecordBindings() during LuaEngine setup.
/// Operates against ce::IAddressList stored in LUA_REGISTRYINDEX["ce_addresslist"].

struct lua_State;

namespace ce {

void registerMemoryRecordBindings(lua_State* L);

// Push the per-record OnActivate/OnDeactivate table for the current list,
// starting a fresh one if the list was replaced since the callbacks were stored.
void pushMemRecCallbacks(lua_State* L);

// lua_CFunction(id, active): call the record's OnActivate or OnDeactivate as
// CE does, handler(sender, before, currentstate). The list reports a change
// after it happened, so `before` is false. Run it under lua_pcall.
int dispatchMemoryRecordActivation(lua_State* L);

} // namespace ce
