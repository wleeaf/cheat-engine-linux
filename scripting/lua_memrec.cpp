/// MemoryRecord and AddressList Lua bindings — the live cheat-table surface.
///
/// MemoryRecord userdata stores only the entry's stable int id. The IAddressList* is
/// fetched from LUA_REGISTRYINDEX["ce_addresslist"] on every call; if the list has been
/// torn down the calls fail gracefully with nil.
///
/// Property syntax (mr.Active = true, mr.Description = "x", mr.OnActivate = function(active) end)
/// is handled through __index/__newindex metamethods, mapping CE property names to method calls.
/// OnActivate is stored in LUA_REGISTRYINDEX["ce_memrec_callbacks"][id] and dispatched by the
/// activation callback registered in LuaEngine::setAddressList.

#include <charconv>
#include "scripting/lua_memrec.hpp"
#include "core/address_list.hpp"
#include "core/types.hpp"

extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}

#include <cstring>
#include <string>

namespace ce {

namespace {

constexpr const char* MEMREC_MT = "ce.MemoryRecord";
constexpr const char* ADDRLIST_MT = "ce.AddressList";
constexpr const char* ADDRESSLIST_KEY = "ce_addresslist";
constexpr const char* MEMREC_CALLBACKS_KEY = "ce_memrec_callbacks";

struct MemRecRef {
    int id;
};

struct AddrListRef {
    char _placeholder;  // userdata needs nonzero size
};

IAddressList* currentList(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, ADDRESSLIST_KEY);
    auto* list = static_cast<IAddressList*>(lua_touserdata(L, -1));
    lua_pop(L, 1);
    return list;
}

MemRecRef* checkMemRec(lua_State* L, int idx) {
    return static_cast<MemRecRef*>(luaL_checkudata(L, idx, MEMREC_MT));
}

[[maybe_unused]] AddrListRef* checkAddrList(lua_State* L, int idx) {
    return static_cast<AddrListRef*>(luaL_checkudata(L, idx, ADDRLIST_MT));
}

void pushMemRec(lua_State* L, int id) {
    auto* ref = static_cast<MemRecRef*>(lua_newuserdata(L, sizeof(MemRecRef)));
    ref->id = id;
    luaL_getmetatable(L, MEMREC_MT);
    lua_setmetatable(L, -2);
}

void pushAddressListSingleton(lua_State* L) {
    auto* ref = static_cast<AddrListRef*>(lua_newuserdata(L, sizeof(AddrListRef)));
    (void)ref;
    luaL_getmetatable(L, ADDRLIST_MT);
    lua_setmetatable(L, -2);
}

ValueType parseTypeName(const char* s) {
    if (!s) return ValueType::Int32;
    std::string n = s;
    for (auto& c : n) c = (char)tolower((unsigned char)c);
    if (n == "byte" || n == "1 byte") return ValueType::Byte;
    if (n == "i16" || n == "2 bytes" || n == "word") return ValueType::Int16;
    if (n == "i32" || n == "4 bytes" || n == "dword") return ValueType::Int32;
    if (n == "i64" || n == "8 bytes" || n == "qword") return ValueType::Int64;
    if (n == "float") return ValueType::Float;
    if (n == "double") return ValueType::Double;
    if (n == "string") return ValueType::String;
    if (n == "unicode" || n == "unicodestring") return ValueType::UnicodeString;
    if (n == "aob" || n == "array of byte" || n == "bytearray") return ValueType::ByteArray;
    if (n == "binary") return ValueType::Binary;
    if (n == "pointer") return ValueType::Pointer;
    if (n == "all") return ValueType::All;
    if (n == "grouped") return ValueType::Grouped;
    if (n == "custom") return ValueType::Custom;
    return ValueType::Int32;
}

const char* typeName(ValueType t) {
    switch (t) {
        case ValueType::Byte:   return "Byte";
        case ValueType::Int16:  return "2 Bytes";
        case ValueType::Int32:  return "4 Bytes";
        case ValueType::Int64:  return "8 Bytes";
        case ValueType::Float:  return "Float";
        case ValueType::Double: return "Double";
        case ValueType::String: return "String";
        case ValueType::UnicodeString: return "Unicode";
        case ValueType::ByteArray: return "Array of byte";
        case ValueType::Binary: return "Binary";
        case ValueType::Pointer: return "Pointer";
        case ValueType::All: return "All";
        case ValueType::Grouped: return "Grouped";
        case ValueType::Custom: return "Custom";
    }
    return "4 Bytes";
}

// ── MemoryRecord methods ──

int l_mr_getID(lua_State* L) {
    auto* ref = checkMemRec(L, 1);
    lua_pushinteger(L, ref->id);
    return 1;
}

int l_mr_getDescription(lua_State* L) {
    auto* ref = checkMemRec(L, 1);
    auto* list = currentList(L);
    if (!list) { lua_pushnil(L); return 1; }
    auto snap = list->byId(ref->id);
    if (!snap) { lua_pushnil(L); return 1; }
    lua_pushstring(L, snap->description.c_str());
    return 1;
}

int l_mr_setDescription(lua_State* L) {
    auto* ref = checkMemRec(L, 1);
    const char* v = luaL_checkstring(L, 2);
    auto* list = currentList(L);
    if (list) list->setDescription(ref->id, v);
    return 0;
}

int l_mr_getAddress(lua_State* L) {
    auto* ref = checkMemRec(L, 1);
    auto* list = currentList(L);
    if (!list) { lua_pushnil(L); return 1; }
    auto snap = list->byId(ref->id);
    if (!snap) { lua_pushnil(L); return 1; }
    lua_pushinteger(L, (lua_Integer)snap->address);
    return 1;
}

int l_mr_setAddress(lua_State* L) {
    auto* ref = checkMemRec(L, 1);
    auto* list = currentList(L);
    if (!list) return 0;
    if (lua_type(L, 2) == LUA_TSTRING) {
        const char* s = lua_tostring(L, 2);
        char* endp = nullptr;
        uintptr_t v = (uintptr_t)strtoull(s, &endp, 0);
        // A fully-numeric string is a plain address; anything else (pointer deref
        // "[base]+off", module+offset, arithmetic) is a live-resolved expression.
        if (endp && *endp == '\0' && endp != s)
            list->setAddress(ref->id, v);
        else
            list->setAddressExpression(ref->id, s);
    } else {
        list->setAddress(ref->id, (uintptr_t)luaL_checkinteger(L, 2));
    }
    return 0;
}

int l_mr_getCurrentAddress(lua_State* L) {
    // For simple records (no offset chain) this is the same as Address.
    return l_mr_getAddress(L);
}

int l_mr_getType(lua_State* L) {
    auto* ref = checkMemRec(L, 1);
    auto* list = currentList(L);
    if (!list) { lua_pushnil(L); return 1; }
    auto snap = list->byId(ref->id);
    if (!snap) { lua_pushnil(L); return 1; }
    lua_pushinteger(L, (lua_Integer)snap->type);
    return 1;
}

int l_mr_setType(lua_State* L) {
    auto* ref = checkMemRec(L, 1);
    ValueType t;
    if (lua_type(L, 2) == LUA_TSTRING)
        t = parseTypeName(lua_tostring(L, 2));
    else
        t = (ValueType)luaL_checkinteger(L, 2);
    auto* list = currentList(L);
    if (list) list->setType(ref->id, t);
    return 0;
}

int l_mr_getValue(lua_State* L) {
    auto* ref = checkMemRec(L, 1);
    auto* list = currentList(L);
    if (!list) { lua_pushnil(L); return 1; }
    // CE's mr.Value does a live read on access; prefer that so a synchronous
    // mr.Address=...; x=mr.Value works without waiting for the refresh timer.
    std::string live = list->liveValue(ref->id);
    if (!live.empty()) { lua_pushstring(L, live.c_str()); return 1; }
    auto snap = list->byId(ref->id);
    if (!snap) { lua_pushnil(L); return 1; }
    lua_pushstring(L, snap->value.c_str());
    return 1;
}

int l_mr_setValue(lua_State* L) {
    auto* ref = checkMemRec(L, 1);
    std::string v;
    if (lua_type(L, 2) == LUA_TNUMBER) {
        // Format locale-independently with '.': std::to_string honours the C
        // locale, which Qt sets to comma-decimal, and QString::toFloat (C locale,
        // '.') then rejects "2,5" and writes 0. std::to_chars always uses '.'.
        // Integers must format without a fractional part or the int parser rejects.
        char buf[64];
        char* end = lua_isinteger(L, 2)
            ? std::to_chars(buf, buf + sizeof(buf), (long long)lua_tointeger(L, 2)).ptr
            : std::to_chars(buf, buf + sizeof(buf), lua_tonumber(L, 2)).ptr;
        v.assign(buf, end);
    } else {
        v = luaL_checkstring(L, 2);
    }
    auto* list = currentList(L);
    if (list) list->setValue(ref->id, v);
    return 0;
}

int l_mr_getActive(lua_State* L) {
    auto* ref = checkMemRec(L, 1);
    auto* list = currentList(L);
    if (!list) { lua_pushboolean(L, 0); return 1; }
    auto snap = list->byId(ref->id);
    lua_pushboolean(L, snap && snap->active);
    return 1;
}

int l_mr_setActive(lua_State* L) {
    auto* ref = checkMemRec(L, 1);
    bool active = lua_toboolean(L, 2);
    auto* list = currentList(L);
    if (list) {
        bool ok = list->setActive(ref->id, active);
        lua_pushboolean(L, ok);
        return 1;
    }
    lua_pushboolean(L, 0);
    return 1;
}

int l_mr_disableWithoutExecute(lua_State* L) {
    auto* ref = checkMemRec(L, 1);
    auto* list = currentList(L);
    if (!list) return 0;
    // Bypass setActive so no enable/disable script runs — call setValue("") would be wrong;
    // best we can do without a dedicated API is set active false through the model. Real CE
    // skips the [DISABLE] script, but our model only fires the script on toggle paths through
    // setEntryActive. For now this is equivalent to setActive(false); upgrade later when we
    // expose a "raw" deactivation hook.
    list->setActive(ref->id, false);
    return 0;
}

int l_mr_getColor(lua_State* L) {
    auto* ref = checkMemRec(L, 1);
    auto* list = currentList(L);
    if (!list) { lua_pushnil(L); return 1; }
    auto snap = list->byId(ref->id);
    if (!snap) { lua_pushnil(L); return 1; }
    lua_pushstring(L, snap->color.c_str());
    return 1;
}

int l_mr_setColor(lua_State* L) {
    auto* ref = checkMemRec(L, 1);
    const char* v = luaL_checkstring(L, 2);
    auto* list = currentList(L);
    if (list) list->setColor(ref->id, v);
    return 0;
}

int l_mr_getScript(lua_State* L) {
    auto* ref = checkMemRec(L, 1);
    auto* list = currentList(L);
    if (!list) { lua_pushnil(L); return 1; }
    auto snap = list->byId(ref->id);
    if (!snap) { lua_pushnil(L); return 1; }
    lua_pushstring(L, snap->script.c_str());
    return 1;
}

int l_mr_setScript(lua_State* L) {
    auto* ref = checkMemRec(L, 1);
    const char* v = luaL_checkstring(L, 2);
    auto* list = currentList(L);
    if (list) list->setScript(ref->id, v);
    return 0;
}

int l_mr_isGroup(lua_State* L) {
    auto* ref = checkMemRec(L, 1);
    auto* list = currentList(L);
    if (!list) { lua_pushboolean(L, 0); return 1; }
    auto snap = list->byId(ref->id);
    lua_pushboolean(L, snap && snap->isGroup);
    return 1;
}

int l_mr_getShowAsHex(lua_State* L) {
    auto* ref = checkMemRec(L, 1);
    auto* list = currentList(L);
    if (!list) { lua_pushboolean(L, 0); return 1; }
    auto snap = list->byId(ref->id);
    lua_pushboolean(L, snap && snap->showAsHex);
    return 1;
}

int l_mr_delete(lua_State* L) {
    auto* ref = checkMemRec(L, 1);
    auto* list = currentList(L);
    if (list) list->deleteById(ref->id);
    // Clear any registered OnActivate callback for this id.
    lua_getfield(L, LUA_REGISTRYINDEX, MEMREC_CALLBACKS_KEY);
    if (lua_istable(L, -1)) {
        lua_pushnil(L);
        lua_rawseti(L, -2, ref->id);
    }
    lua_pop(L, 1);
    return 0;
}

// MemoryRecord __index: method first, then property getter.
int l_mr__index(lua_State* L) {
    luaL_checkudata(L, 1, MEMREC_MT);
    const char* key = luaL_checkstring(L, 2);

    // Look up methods table (stored as uvalue 1 of the metatable, but easier via fields_table)
    luaL_getmetatable(L, MEMREC_MT);
    lua_getfield(L, -1, "__methods");
    lua_getfield(L, -1, key);
    if (!lua_isnil(L, -1)) {
        // Stack: ud, key, mt, methods, fn — return fn
        return 1;
    }
    lua_pop(L, 3);  // pop nil, methods, mt — back to ud, key

    // Property getters
    if (strcmp(key, "ID") == 0) return l_mr_getID(L);
    if (strcmp(key, "Description") == 0) return l_mr_getDescription(L);
    if (strcmp(key, "Address") == 0) return l_mr_getAddress(L);
    if (strcmp(key, "CurrentAddress") == 0) return l_mr_getCurrentAddress(L);
    if (strcmp(key, "Type") == 0) return l_mr_getType(L);
    if (strcmp(key, "Value") == 0) return l_mr_getValue(L);
    if (strcmp(key, "Active") == 0) return l_mr_getActive(L);
    if (strcmp(key, "Color") == 0) return l_mr_getColor(L);
    if (strcmp(key, "Script") == 0) return l_mr_getScript(L);
    if (strcmp(key, "IsGroupHeader") == 0) return l_mr_isGroup(L);
    if (strcmp(key, "ShowAsHex") == 0) return l_mr_getShowAsHex(L);

    lua_pushnil(L);
    return 1;
}

int l_mr__newindex(lua_State* L) {
    auto* ref = static_cast<MemRecRef*>(luaL_checkudata(L, 1, MEMREC_MT));
    const char* key = luaL_checkstring(L, 2);

    // OnActivate handler — store function in registry callbacks table keyed by id.
    if (strcmp(key, "OnActivate") == 0 || strcmp(key, "OnDeactivate") == 0) {
        // Both share the same dispatch slot for now (real CE distinguishes — TODO).
        lua_getfield(L, LUA_REGISTRYINDEX, MEMREC_CALLBACKS_KEY);
        if (!lua_istable(L, -1)) {
            lua_pop(L, 1);
            lua_newtable(L);
            lua_pushvalue(L, -1);
            lua_setfield(L, LUA_REGISTRYINDEX, MEMREC_CALLBACKS_KEY);
        }
        lua_pushvalue(L, 3);
        lua_rawseti(L, -2, ref->id);
        lua_pop(L, 1);
        return 0;
    }

    // Property setters expect stack [self, value]. __newindex hands us [self, key, value],
    // so drop the key, then dispatch by name.
    lua_remove(L, 2);
    if (strcmp(key, "Description") == 0) { l_mr_setDescription(L); return 0; }
    if (strcmp(key, "Address") == 0)     { l_mr_setAddress(L);     return 0; }
    if (strcmp(key, "Type") == 0)        { l_mr_setType(L);        return 0; }
    if (strcmp(key, "Value") == 0)       { l_mr_setValue(L);       return 0; }
    if (strcmp(key, "Active") == 0)      { l_mr_setActive(L);      return 0; }
    if (strcmp(key, "Color") == 0)       { l_mr_setColor(L);       return 0; }
    if (strcmp(key, "Script") == 0)      { l_mr_setScript(L);      return 0; }
    // Freeze direction (CE-style): FreezeDirection is the raw mode (0=locked,
    // 1=IncreaseOnly, 2=DecreaseOnly, 3=NeverIncrease, 4=NeverDecrease);
    // AllowIncrease=false blocks increases, AllowDecrease=false blocks decreases.
    // NOTE: the key was removed above, so the assigned value is now at index 2.
    if (strcmp(key, "FreezeDirection") == 0) {
        if (auto* list = currentList(L)) list->setFreezeMode(ref->id, (int)luaL_checkinteger(L, 2));
        return 0;
    }
    if (strcmp(key, "ShowAsHex") == 0) {
        if (auto* list = currentList(L)) list->setHexView(ref->id, lua_toboolean(L, 2));
        return 0;
    }
    if (strcmp(key, "AllowDecrease") == 0) {
        if (auto* list = currentList(L)) list->setFreezeMode(ref->id, lua_toboolean(L, 2) ? 0 : 1);
        return 0;
    }
    if (strcmp(key, "AllowIncrease") == 0) {
        if (auto* list = currentList(L)) list->setFreezeMode(ref->id, lua_toboolean(L, 2) ? 0 : 3);
        return 0;
    }

    return luaL_error(L, "unknown MemoryRecord property '%s'", key);
}

int l_mr__tostring(lua_State* L) {
    auto* ref = checkMemRec(L, 1);
    auto* list = currentList(L);
    if (!list) { lua_pushfstring(L, "MemoryRecord(id=%d, detached)", ref->id); return 1; }
    auto snap = list->byId(ref->id);
    if (!snap) { lua_pushfstring(L, "MemoryRecord(id=%d, deleted)", ref->id); return 1; }
    lua_pushfstring(L, "MemoryRecord(id=%d, addr=0x%llx, type=%s, desc=%s)",
        ref->id, (long long)snap->address, typeName(snap->type), snap->description.c_str());
    return 1;
}

// ── AddressList methods ──

int l_al_getCount(lua_State* L) {
    (void)checkAddrList(L, 1);
    auto* list = currentList(L);
    lua_pushinteger(L, list ? list->count() : 0);
    return 1;
}

int l_al_getMemoryRecord(lua_State* L) {
    (void)checkAddrList(L, 1);
    int idx = (int)luaL_checkinteger(L, 2);
    auto* list = currentList(L);
    if (!list) { lua_pushnil(L); return 1; }
    auto snap = list->at(idx);
    if (!snap) { lua_pushnil(L); return 1; }
    pushMemRec(L, snap->id);
    return 1;
}

int l_al_getMemoryRecordByID(lua_State* L) {
    (void)checkAddrList(L, 1);
    int id = (int)luaL_checkinteger(L, 2);
    auto* list = currentList(L);
    if (!list) { lua_pushnil(L); return 1; }
    auto snap = list->byId(id);
    if (!snap) { lua_pushnil(L); return 1; }
    pushMemRec(L, snap->id);
    return 1;
}

int l_al_getMemoryRecordByDescription(lua_State* L) {
    (void)checkAddrList(L, 1);
    const char* desc = luaL_checkstring(L, 2);
    auto* list = currentList(L);
    if (!list) { lua_pushnil(L); return 1; }
    int id = list->findIdByDescription(desc);
    if (id < 0) { lua_pushnil(L); return 1; }
    pushMemRec(L, id);
    return 1;
}

int l_al_createMemoryRecord(lua_State* L) {
    (void)checkAddrList(L, 1);
    auto* list = currentList(L);
    if (!list) { lua_pushnil(L); return 1; }
    int id = list->createEntry(0, ValueType::Int32, "No description");
    if (id < 0) { lua_pushnil(L); return 1; }
    pushMemRec(L, id);
    return 1;
}

int l_al_disableAllWithoutExecute(lua_State* L) {
    (void)checkAddrList(L, 1);
    auto* list = currentList(L);
    if (list) list->disableAllWithoutExecute();
    return 0;
}

int l_al_getSelectedRecords(lua_State* L) {
    (void)checkAddrList(L, 1);
    // Selection model is a UI concept not yet plumbed through IAddressList.
    // Return an empty table so scripts that iterate over the result don't crash.
    lua_newtable(L);
    return 1;
}

int l_al__index(lua_State* L) {
    luaL_checkudata(L, 1, ADDRLIST_MT);
    if (lua_type(L, 2) == LUA_TNUMBER) {
        int idx = (int)lua_tointeger(L, 2);
        auto* list = currentList(L);
        if (!list) { lua_pushnil(L); return 1; }
        auto snap = list->at(idx);
        if (!snap) { lua_pushnil(L); return 1; }
        pushMemRec(L, snap->id);
        return 1;
    }
    const char* key = luaL_checkstring(L, 2);

    luaL_getmetatable(L, ADDRLIST_MT);
    lua_getfield(L, -1, "__methods");
    lua_getfield(L, -1, key);
    if (!lua_isnil(L, -1)) return 1;
    lua_pop(L, 3);

    if (strcmp(key, "Count") == 0) return l_al_getCount(L);

    lua_pushnil(L);
    return 1;
}

// ── Globals ──

int l_getAddressList(lua_State* L) {
    pushAddressListSingleton(L);
    return 1;
}

int l_createMemoryRecord(lua_State* L) {
    auto* list = currentList(L);
    if (!list) { lua_pushnil(L); return 1; }
    int id = list->createEntry(0, ValueType::Int32, "No description");
    if (id < 0) { lua_pushnil(L); return 1; }
    pushMemRec(L, id);
    return 1;
}

int l_getMemoryRecord(lua_State* L) {
    auto* list = currentList(L);
    if (!list) { lua_pushnil(L); return 1; }
    int idx = (int)luaL_checkinteger(L, 1);
    auto snap = list->at(idx);
    if (!snap) { lua_pushnil(L); return 1; }
    pushMemRec(L, snap->id);
    return 1;
}

// Global form of the address-list method: CE exposes both
// getMemoryRecordByDescription(desc) and addresslist:getMemoryRecordByDescription.
int l_getMemoryRecordByDescription(lua_State* L) {
    auto* list = currentList(L);
    if (!list) { lua_pushnil(L); return 1; }
    const char* desc = luaL_checkstring(L, 1);
    int id = list->findIdByDescription(desc);
    if (id < 0) { lua_pushnil(L); return 1; }
    pushMemRec(L, id);
    return 1;
}

void buildMemRecMetatable(lua_State* L) {
    luaL_newmetatable(L, MEMREC_MT);

    // __methods sub-table (looked up by __index for `mr:method()` syntax)
    lua_newtable(L);
    static const luaL_Reg methods[] = {
        {"getID",                 l_mr_getID},
        {"getDescription",        l_mr_getDescription},
        {"setDescription",        l_mr_setDescription},
        {"getAddress",            l_mr_getAddress},
        {"setAddress",            l_mr_setAddress},
        {"getCurrentAddress",     l_mr_getCurrentAddress},
        {"getType",               l_mr_getType},
        {"setType",               l_mr_setType},
        {"getValue",              l_mr_getValue},
        {"setValue",              l_mr_setValue},
        {"getActive",             l_mr_getActive},
        {"setActive",             l_mr_setActive},
        {"isActive",              l_mr_getActive},
        {"disableWithoutExecute", l_mr_disableWithoutExecute},
        {"getColor",              l_mr_getColor},
        {"setColor",              l_mr_setColor},
        {"getScript",             l_mr_getScript},
        {"setScript",             l_mr_setScript},
        {"isGroupHeader",         l_mr_isGroup},
        {"delete",                l_mr_delete},
        {nullptr, nullptr},
    };
    luaL_setfuncs(L, methods, 0);
    lua_setfield(L, -2, "__methods");

    lua_pushcfunction(L, l_mr__index);
    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, l_mr__newindex);
    lua_setfield(L, -2, "__newindex");
    lua_pushcfunction(L, l_mr__tostring);
    lua_setfield(L, -2, "__tostring");

    lua_pop(L, 1);  // pop metatable
}

void buildAddrListMetatable(lua_State* L) {
    luaL_newmetatable(L, ADDRLIST_MT);

    lua_newtable(L);
    static const luaL_Reg methods[] = {
        {"getCount",                       l_al_getCount},
        {"getMemoryRecord",                l_al_getMemoryRecord},
        {"getMemoryRecordByID",            l_al_getMemoryRecordByID},
        {"getMemoryRecordByDescription",   l_al_getMemoryRecordByDescription},
        {"createMemoryRecord",             l_al_createMemoryRecord},
        {"disableAllWithoutExecute",       l_al_disableAllWithoutExecute},
        {"getSelectedRecords",             l_al_getSelectedRecords},
        {nullptr, nullptr},
    };
    luaL_setfuncs(L, methods, 0);
    lua_setfield(L, -2, "__methods");

    lua_pushcfunction(L, l_al__index);
    lua_setfield(L, -2, "__index");

    lua_pop(L, 1);
}

} // anonymous namespace

void registerMemoryRecordBindings(lua_State* L) {
    buildMemRecMetatable(L);
    buildAddrListMetatable(L);

    lua_register(L, "getAddressList",   l_getAddressList);
    lua_register(L, "createMemoryRecord", l_createMemoryRecord);
    lua_register(L, "getMemoryRecord",  l_getMemoryRecord);
    lua_register(L, "getMemoryRecordByDescription", l_getMemoryRecordByDescription);

    // CE convention: `addresslist` / `AddressList` are also globals returning the singleton.
    pushAddressListSingleton(L);
    lua_setglobal(L, "addresslist");
    pushAddressListSingleton(L);
    lua_setglobal(L, "AddressList");
}

} // namespace ce
