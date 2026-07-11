#pragma once
/// Lua bindings for the MemoryRecord and AddressList objects.
/// Registered by registerMemoryRecordBindings() during LuaEngine setup.
/// Operates against ce::IAddressList stored in LUA_REGISTRYINDEX["ce_addresslist"].

struct lua_State;

namespace ce {

void registerMemoryRecordBindings(lua_State* L);

} // namespace ce
