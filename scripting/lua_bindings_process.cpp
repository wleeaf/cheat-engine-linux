/// Lua bindings: processes, modules and symbol resolution.
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

// ── Process info ──

pid_t parseProcessId(std::string_view text) {
    std::string value(text);
    char* end = nullptr;
    long pid = std::strtol(value.c_str(), &end, 10);
    if (end == value.c_str() || *end != '\0' || pid <= 0 ||
        pid > std::numeric_limits<pid_t>::max()) {
        return 0;
    }
    return static_cast<pid_t>(pid);
}

static std::string readProcessName(const std::filesystem::path& procDir) {
    std::ifstream comm(procDir / "comm");
    std::string name;
    if (comm)
        std::getline(comm, name);
    return name;
}

static bool processNameMatches(const std::filesystem::path& procDir, std::string_view target) {
    if (readProcessName(procDir) == target)
        return true;

    std::error_code ec;
    auto exe = std::filesystem::read_symlink(procDir / "exe", ec);
    return !ec && exe.filename().string() == target;
}

pid_t findProcessIdByName(std::string_view target) {
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(
             "/proc", std::filesystem::directory_options::skip_permission_denied, ec)) {
        if (ec)
            break;
        auto pid = parseProcessId(entry.path().filename().string());
        if (pid > 0 && processNameMatches(entry.path(), target))
            return pid;
    }
    return 0;
}

int l_getProcessList(lua_State* L) {
    // Return a table keyed by pid, each value a {pid, name} subtable (the
    // Cheat-Engine-compatible contract). Uses skip_permission_denied so a
    // /proc entry we cannot stat does not abort enumeration.
    lua_newtable(L);
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(
             "/proc", std::filesystem::directory_options::skip_permission_denied, ec)) {
        if (ec)
            break;
        auto pid = parseProcessId(entry.path().filename().string());
        if (pid <= 0)
            continue;

        auto pname = readProcessName(entry.path());
        lua_newtable(L);
        lua_pushinteger(L, pid);
        lua_setfield(L, -2, "pid");
        lua_pushstring(L, pname.c_str());
        lua_setfield(L, -2, "name");
        lua_rawseti(L, -2, pid);
    }
    return 1;
}

int l_getProcessIDFromProcessName(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    auto pid = findProcessIdByName(name);
    if (pid > 0)
        lua_pushinteger(L, pid);
    else
        lua_pushnil(L);
    return 1;
}

// Case-insensitive match of a module by its short name or the basename of its
// path — mirrors how CE's getModuleBase("libc.so.6") / getAddress("game+0x10")
// resolve modules.
const ce::ModuleInfo* findModuleByName(ProcessHandle* p, const std::string& want) {
    if (!p) return nullptr;
    auto lc = [](std::string s) { for (char& c : s) c = (char)tolower((unsigned char)c); return s; };
    std::string w = lc(want);
    static std::vector<ce::ModuleInfo> mods;   // keep storage alive for the returned pointer
    mods = p->modules();
    for (const auto& m : mods) {
        if (lc(m.name) == w) return &m;
        auto slash = m.path.find_last_of('/');
        std::string base = slash == std::string::npos ? m.path : m.path.substr(slash + 1);
        if (!base.empty() && lc(base) == w) return &m;
    }
    return nullptr;
}

int l_getModuleBase(lua_State* L) {
    auto* m = findModuleByName(getProc(L), luaL_checkstring(L, 1));
    if (m) lua_pushinteger(L, (lua_Integer)m->base);
    else   lua_pushnil(L);
    return 1;
}

// pause()/unpause(): freeze/resume the whole target (SIGSTOP/SIGCONT), like CE's
// "pause the game" toggle. Returns true on success.
int l_pauseSignal(lua_State* L, int sig) {
    auto pid=localTargetPid(getProc(L));
    if (!pid) { lua_pushboolean(L, 0); return 1; }
    lua_pushboolean(L, kill(*pid, sig) == 0 ? 1 : 0);
    return 1;
}
int l_pause(lua_State* L)   { return l_pauseSignal(L, SIGSTOP); }
int l_unpause(lua_State* L) { return l_pauseSignal(L, SIGCONT); }

// inModule(address) -> module name containing the address, or nil.
int l_inModule(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    for (auto& m : p->modules()) {
        if (addr >= m.base && addr < m.base + m.size) {
            lua_pushstring(L, m.name.c_str());
            return 1;
        }
    }
    lua_pushnil(L);
    return 1;
}
// isAddress(address) -> true if a byte is readable there (valid mapped address).
int l_isAddress(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushboolean(L, 0); return 1; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    uint8_t b;
    lua_pushboolean(L, (bool)p->read(addr, &b, 1) ? 1 : 0);
    return 1;
}

// copyMemory(source, destination, size) -> bool. Copies within the target.
int l_copyMemory(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushboolean(L, 0); return 1; }
    uintptr_t src = (uintptr_t)luaL_checkinteger(L, 1);
    uintptr_t dst = (uintptr_t)luaL_checkinteger(L, 2);
    const lua_Integer requested = luaL_checkinteger(L, 3);
    luaL_argcheck(L, requested >= 0 && requested <= (lua_Integer(1) << 28), 3, "size must be 0..256MB");
    const size_t n = static_cast<size_t>(requested);
    // A Lua-owned buffer: nothing leaks if a later call raises. The whole range
    // must be read: a short read would copy zeros over the destination's tail.
    auto* buf = static_cast<uint8_t*>(lua_newuserdata(L, n ? n : 1));
    if (!readExact(p, src, buf, n)) { lua_pushboolean(L, 0); return 1; }
    auto written = p->write(dst, buf, n);
    lua_pushboolean(L, written && *written == n ? 1 : 0);
    return 1;
}

// enumMemoryRegions() -> { {BaseAddress, MemorySize, Protect, State, Path}, ... }
// CE-style region list (0..N-1 not needed; scripts iterate with ipairs).
int l_enumMemoryRegions(lua_State* L) {
    auto* p = getProc(L);
    lua_newtable(L);
    if (!p) return 1;
    auto regions = p->queryRegions();
    int idx = 0;
    for (auto& r : regions) {
        lua_newtable(L);
        lua_pushinteger(L, (lua_Integer)r.base);          lua_setfield(L, -2, "BaseAddress");
        lua_pushinteger(L, (lua_Integer)r.size);          lua_setfield(L, -2, "MemorySize");
        lua_pushinteger(L, (lua_Integer)(uint32_t)r.protection); lua_setfield(L, -2, "Protect");
        if (!r.path.empty()) { lua_pushstring(L, r.path.c_str()); lua_setfield(L, -2, "Path"); }
        lua_rawseti(L, -2, ++idx);
    }
    return 1;
}

// allocateMemory(size [, preferredBase]) -> address (RWX, for code caves).
int l_allocateMemory(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    size_t size = (size_t)luaL_checkinteger(L, 1);
    uintptr_t base = lua_isnoneornil(L, 2) ? 0 : (uintptr_t)luaL_checkinteger(L, 2);
    auto r = p->allocate(size, MemProt::All, base);
    if (!r) {
        lua_pushnil(L);
        lua_pushstring(L, ce::targetOperationError(*p, ce::TargetFeature::Allocate, r.error()).c_str());
        return 2;
    }
    lua_pushinteger(L, (lua_Integer)*r);
    return 1;
}
int l_deAlloc(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushboolean(L, 0); return 1; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    size_t size = lua_isnoneornil(L, 2) ? 0 : (size_t)luaL_checkinteger(L, 2);
    lua_pushboolean(L, (bool)p->free(addr, size) ? 1 : 0);
    return 1;
}

int l_getModuleSize(lua_State* L) {
    auto* m = findModuleByName(getProc(L), luaL_checkstring(L, 1));
    if (m) lua_pushinteger(L, (lua_Integer)m->size);
    else   lua_pushnil(L);
    return 1;
}

int l_getModuleList(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_newtable(L); return 1; }
    auto mods = p->modules();
    lua_newtable(L);
    for (size_t i = 0; i < mods.size(); ++i) {
        lua_newtable(L);
        lua_pushstring(L, mods[i].name.c_str());
        lua_setfield(L, -2, "name");
        lua_pushinteger(L, (lua_Integer)mods[i].base);
        lua_setfield(L, -2, "base");
        lua_pushinteger(L, (lua_Integer)mods[i].size);
        lua_setfield(L, -2, "size");
        lua_rawseti(L, -2, i + 1);
    }
    return 1;
}

// enumModules([processid]) -> table of {Name, Address, Size} per loaded module, using
// CE's exact field names (companion to our lowercase getModuleList, for .CT scripts).
// The optional processid is accepted for compatibility; the current target's modules
// are returned.
int l_enumModules(lua_State* L) {
    auto* p = getProc(L);
    lua_newtable(L);
    if (!p) return 1;
    auto mods = p->modules();
    for (size_t i = 0; i < mods.size(); ++i) {
        lua_newtable(L);
        lua_pushstring(L, mods[i].name.c_str());       lua_setfield(L, -2, "Name");
        lua_pushinteger(L, (lua_Integer)mods[i].base); lua_setfield(L, -2, "Address");
        lua_pushinteger(L, (lua_Integer)mods[i].size); lua_setfield(L, -2, "Size");
        lua_rawseti(L, -2, (int)i + 1);
    }
    return 1;
}

// getPointerSize() -> 8 for a 64-bit target, 4 for 32-bit (8 when no target is open).
int l_getPointerSize(lua_State* L) {
    auto* p = getProc(L);
    lua_pushinteger(L, p ? p->pointerWidth() : sizeof(uintptr_t));
    return 1;
}

// getMemoryRegionInfo(address) -> table of the region containing `address` with CE's
// Windows-style field names/values (BaseAddress, AllocationBase, AllocationProtect,
// RegionSize, State, Protect, Type), so .CT scripts that compare against PAGE_*/MEM_*
// constants work. Linux r/w/x and Private/Image/Mapped map onto those constants.
int l_getMemoryRegionInfo(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    auto reg = p->queryRegion(addr);
    if (!reg) { lua_pushnil(L); return 1; }
    const bool r = reg->protection & ce::MemProt::Read;
    const bool w = reg->protection & ce::MemProt::Write;
    const bool x = reg->protection & ce::MemProt::Exec;
    const uint32_t page = x ? (w ? 0x40u : (r ? 0x20u : 0x10u))   // EXECUTE_READWRITE/READ/EXECUTE
                            : (w ? 0x04u : (r ? 0x02u : 0x01u));  // READWRITE/READONLY/NOACCESS
    const uint32_t type = reg->type == ce::MemType::Image  ? 0x1000000u   // MEM_IMAGE
                        : reg->type == ce::MemType::Mapped ? 0x40000u     // MEM_MAPPED
                                                           : 0x20000u;    // MEM_PRIVATE
    lua_newtable(L);
    lua_pushinteger(L, (lua_Integer)reg->base); lua_setfield(L, -2, "BaseAddress");
    lua_pushinteger(L, (lua_Integer)reg->base); lua_setfield(L, -2, "AllocationBase");
    lua_pushinteger(L, page);                   lua_setfield(L, -2, "AllocationProtect");
    lua_pushinteger(L, (lua_Integer)reg->size); lua_setfield(L, -2, "RegionSize");
    lua_pushinteger(L, 0x1000);                 lua_setfield(L, -2, "State");   // MEM_COMMIT
    lua_pushinteger(L, page);                   lua_setfield(L, -2, "Protect");
    lua_pushinteger(L, type);                   lua_setfield(L, -2, "Type");
    return 1;
}

// ── Symbol resolution ──

int l_getNameFromAddress(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    auto* r = getResolver(L);
    std::string name;
    if (r) name = r->resolve(addr);
    if (name.empty()) {
        // CE-compat: getNameFromAddress always returns a string, falling back to
        // the hex address when nothing resolves (callers routinely concatenate
        // the result, so a nil return would error).
        char buf[24];
        snprintf(buf, sizeof(buf), "%lX", static_cast<unsigned long>(addr));
        name = buf;
    }
    lua_pushstring(L, name.c_str());
    return 1;
}

int l_getAddressFromName(lua_State* L) {
    auto* r = getResolver(L);
    if (!r) { lua_pushnil(L); return 1; }
    const char* name = luaL_checkstring(L, 1);
    auto addr = r->lookup(name);
    // Like getAddress (and Cheat Engine), also accept module+offset and [pointer] paths.
    if (!addr)
        if (auto parsed = ExpressionParser(getProc(L), r).parse(name)) addr = *parsed;
    if (addr) lua_pushinteger(L, (lua_Integer)addr);
    else lua_pushnil(L);
    return 1;
}
} // namespace ce::lua_detail
