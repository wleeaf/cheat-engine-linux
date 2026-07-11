#pragma once
/// Lua GUI bindings — create Qt widgets from Lua scripts.

struct lua_State;
class QMainWindow;

namespace ce {
void registerLuaGuiBindings(lua_State* L);
/// Set the QMainWindow that getMainForm() returns from Lua scripts.
void setLuaMainForm(QMainWindow* w);
/// Drop all Lua GUI callback bindings and forget the lua_State. MUST be called
/// before the owning LuaEngine's lua_State is closed, otherwise a Qt widget/timer
/// callback firing afterwards dereferences a freed lua_State (use-after-free).
void shutdownLuaGuiBindings();
} // namespace ce
