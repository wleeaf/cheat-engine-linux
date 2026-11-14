/// Lua bindings: the address list and trainer generation.
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

// ── Address list manipulation ──

static void ensureLuaAddressList(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_lua_addresslist");
    if (lua_istable(L, -1))
        return;

    lua_pop(L, 1);
    lua_newtable(L);
    lua_pushvalue(L, -1);
    lua_setfield(L, LUA_REGISTRYINDEX, "ce_lua_addresslist");
}

static int luaAddressListIndex(lua_State* L, int arg) {
    lua_Integer raw = luaL_checkinteger(L, arg);
    if (raw < 0)
        luaL_argerror(L, arg, "address list index must be non-negative");
    return static_cast<int>(raw + 1); // CE-style zero-based index at API boundary.
}

int l_addressList_getCount(lua_State* L) {
    // Stored as registry value by MainWindow
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_addresslist_count");
    if (lua_isfunction(L, -1)) {
        lua_call(L, 0, 1);
        return 1;
    }
    lua_pop(L, 1);
    ensureLuaAddressList(L);
    lua_pushinteger(L, static_cast<lua_Integer>(lua_rawlen(L, -1)));
    lua_remove(L, -2);
    return 1;
}

int l_getTableEntry(lua_State* L) {
    int index = luaAddressListIndex(L, 1);
    ensureLuaAddressList(L);
    lua_rawgeti(L, -1, index);
    lua_remove(L, -2);
    return 1;
}

int l_setTableEntry(lua_State* L) {
    int index = luaAddressListIndex(L, 1);
    luaL_checktype(L, 2, LUA_TTABLE);
    ensureLuaAddressList(L);
    lua_pushvalue(L, 2);
    lua_rawseti(L, -2, index);
    lua_pop(L, 1);
    lua_pushboolean(L, 1);
    return 1;
}

int l_addressList_addEntry(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE);
    ensureLuaAddressList(L);
    auto index = static_cast<lua_Integer>(lua_rawlen(L, -1) + 1);
    lua_pushvalue(L, 1);
    lua_rawseti(L, -2, index);
    lua_pop(L, 1);
    lua_pushinteger(L, index - 1);
    return 1;
}

int l_addressList_removeEntry(lua_State* L) {
    int index = luaAddressListIndex(L, 1);
    ensureLuaAddressList(L);
    auto count = static_cast<int>(lua_rawlen(L, -1));
    if (index > count) {
        lua_pop(L, 1);
        lua_pushboolean(L, 0);
        return 1;
    }

    for (int i = index; i < count; ++i) {
        lua_rawgeti(L, -1, i + 1);
        lua_rawseti(L, -2, i);
    }
    lua_pushnil(L);
    lua_rawseti(L, -2, count);
    lua_pop(L, 1);
    lua_pushboolean(L, 1);
    return 1;
}

int l_addressList_clear(lua_State* L) {
    lua_newtable(L);
    lua_setfield(L, LUA_REGISTRYINDEX, "ce_lua_addresslist");
    return 0;
}

// saveTable(path) -> bool. Serialize the live cheat table (the C++ address list)
// to a .CT/.json, the same format the GUI's Save Table writes.
// Snapshot the live IAddressList into a CheatTable (shared by save/trainer paths).
static ce::CheatTable buildCheatTableFromList(ce::IAddressList* list) {
    ce::CheatTable table;
    if (!list) return table;
    // The list is flat with an indent per row; a table nests by parent ID.
    std::vector<std::pair<int, int>> parents;   // (indent, id) of open groups
    for (int id : list->ids()) {
        auto snap = list->byId(id);
        if (!snap) continue;
        ce::CheatEntry e;
        while (!parents.empty() && parents.back().first >= snap->indent) parents.pop_back();
        e.parentId = parents.empty() ? -1 : parents.back().second;
        if (snap->isGroup) parents.push_back({snap->indent, snap->id});
        // A pointer path or module+offset must be saved as such: `address` is
        // only where it resolved now, and a trainer would write there forever.
        e.addressString = snap->addressExpression;
        e.showAsSigned = snap->showAsSigned;
        e.length = static_cast<int>(std::min<std::size_t>(snap->byteCount, INT_MAX));
        e.dataByteOrder = snap->dataByteOrder;
        e.pointerWidth = snap->pointerWidth;
        e.freezeMode = static_cast<ce::FreezeMode>(snap->freezeMode);
        e.id = snap->id;
        e.description = snap->description;
        e.address = snap->address;
        e.type = snap->type;
        e.value = snap->value;
        e.active = snap->active;
        e.showAsHex = snap->showAsHex;
        e.isGroup = snap->isGroup;
        e.color = snap->color;
        e.autoAsmScript = snap->script;
        e.hotkeyKeys = snap->hotkeyKeys;
        table.entries.push_back(std::move(e));
    }
    return table;
}

int l_saveTable(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    auto* eng = ce::LuaEngine::instanceFromState(L);
    auto* list = eng ? eng->addressList() : nullptr;
    if (!list) { lua_pushboolean(L, 0); return 1; }
    ce::CheatTable table = buildCheatTableFromList(list);
    // The format follows the name, as in the GUI: a .ct (any case) is Cheat
    // Engine XML, anything else our JSON.
    const std::string name = path;
    const bool ct = name.size() >= 3 && name[name.size() - 3] == '.' &&
        (name[name.size() - 2] | 0x20) == 'c' && (name[name.size() - 1] | 0x20) == 't';
    lua_pushboolean(L, (ct ? table.save(path) : table.saveJson(path)) ? 1 : 0);
    return 1;
}

// loadTable(path) -> bool. Load a .CT/.json into the live cheat table (address
// list), like the GUI's Load Table.
int l_loadTable(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    auto* eng = ce::LuaEngine::instanceFromState(L);
    auto* list = eng ? eng->addressList() : nullptr;
    if (!list) { lua_pushboolean(L, 0); return 1; }

    ce::CheatTable table;
    // Auto-detect CE XML .CT vs our JSON from the file contents (not extension),
    // so `.CT`/`.ct`/extensionless downloaded tables all load.
    if (!table.loadAuto(path)) { lua_pushboolean(L, 0); return 1; }
    // Compute each entry's indent from the parentId tree (entries are in document
    // order, parents before children) so the imported hierarchy matches the GUI's
    // Load Table, and preserve CE symbolic bases + pointer offset chains as address
    // expressions re-evaluated each refresh.
    std::unordered_map<int, int> indentByCeId;
    for (const auto& e : table.entries) {
        int indent = 0;
        if (e.parentId != -1) {
            auto it = indentByCeId.find(e.parentId);
            if (it != indentByCeId.end()) indent = it->second + 1;
        }
        indentByCeId[e.id] = indent;

        if (e.isGroup) {
            int gid = list->createGroup(e.description);
            list->setIndent(gid, indent);
            continue;
        }
        int id = list->createEntry(e.address, e.type, e.description);
        if (!e.addressString.empty() || !e.offsets.empty()) {
            char hexbuf[32];
            std::snprintf(hexbuf, sizeof(hexbuf), "0x%llx",
                          (unsigned long long)e.address);
            std::string base = e.addressString.empty() ? hexbuf : e.addressString;
            list->setAddressExpression(id, ce::buildPointerExpression(base, e.offsets));
        }
        // The stored value is the last one seen, not something to write:
        // setValue writes into the game. And like the GUI's Load Table,
        // records load inactive: activating would run the loaded table's
        // scripts (and freeze writes) without the user choosing to.
        if (!e.color.empty()) list->setColor(id, e.color);
        if (!e.autoAsmScript.empty()) list->setScript(id, e.autoAsmScript);
        if (e.showAsHex) list->setHexView(id, true);
        if (!e.showAsSigned) list->setSigned(id, false);
        if (e.length > 0) list->setByteCount(id, static_cast<std::size_t>(e.length));
        if (e.dataByteOrder != ce::ByteOrder::Unknown || e.pointerWidth)
            list->setDataFormat(id, e.dataByteOrder, e.pointerWidth);
        list->setFreezeMode(id, (int)e.freezeMode);
        list->setIndent(id, indent);
    }
    lua_pushboolean(L, 1);
    return 1;
}

// ── Trainer generation (standalone executable from the cheat table) ──
// generateTrainerSource() -> C source string for the current address list (nil
// if there is no list). Mirrors the GUI's "Create Trainer" source step.
int l_generateTrainerSource(lua_State* L) {
    auto* eng = ce::LuaEngine::instanceFromState(L);
    auto* list = eng ? eng->addressList() : nullptr;
    if (!list) { lua_pushnil(L); return 1; }
    ce::CheatTable table = buildCheatTableFromList(list);
    ce::TrainerGenerator gen;
    std::string src = gen.generateSource(table);
    lua_pushlstring(L, src.data(), src.size());
    return 1;
}

// generateTrainer(outputPath) -> true, or (nil, errmsg). Compiles a standalone
// trainer binary from the current address list, like the GUI's Create Trainer.
int l_generateTrainer(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    auto* eng = ce::LuaEngine::instanceFromState(L);
    auto* list = eng ? eng->addressList() : nullptr;
    if (!list) { lua_pushnil(L); lua_pushstring(L, "no address list"); return 2; }
    ce::CheatTable table = buildCheatTableFromList(list);
    ce::TrainerGenerator gen;
    std::string err = gen.generateBinary(table, path);
    if (err.empty()) { lua_pushboolean(L, 1); return 1; }
    lua_pushnil(L);
    lua_pushstring(L, err.c_str());
    return 2;
}
} // namespace ce::lua_detail
