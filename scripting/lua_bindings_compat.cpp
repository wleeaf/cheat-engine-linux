/// Lua bindings: the remaining Cheat Engine compatible functions.
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
#include "scripting/lua_files.hpp"
namespace ce::lua_detail {

// ── Additional CE-compatible functions ──

// True for cecore itself or one of its threads (/proc/<tid> also opens the
// thread group's memory).
static bool isOwnProcess(pid_t pid) {
    if (pid == getpid()) return true;
    std::ifstream status("/proc/" + std::to_string(pid) + "/status");
    std::string line;
    while (std::getline(status, line))
        if (line.rfind("Tgid:", 0) == 0) return std::strtol(line.c_str() + 5, nullptr, 10) == getpid();
    return false;
}

int l_openProcess(lua_State* L) {
    const char* nameOrPid = luaL_checkstring(L, 1);
    auto pid = parseProcessId(nameOrPid);
    if (pid <= 0)
        pid = findProcessIdByName(nameOrPid);
    // A table that opens Cheat Engine itself could rewrite its own memory,
    // environment included, and lift the default-deny rules.
    if (pid > 0 && isOwnProcess(pid)) {
        lua_pushnil(L);
        lua_pushliteral(L, "openProcess: Cheat Engine cannot open itself from Lua");
        return 2;
    }

    if (pid > 0) {
        auto* engine = LuaEngine::instanceFromState(L);
        if (engine) {
            os::LinuxProcessEnumerator enumerator;
            auto proc = enumerator.open(pid);
            if (proc) {
                engine->setOwnedProcess(std::move(proc));
                lua_pushinteger(L, pid);
                return 1;
            }
        }
    }

    lua_pushnil(L);
    return 1;
}

// connectToCeserver(host, port, pid [, timeoutMs]) -> pid or (nil, errmsg). Opens a
// remote process over a ceserver TCP connection and makes it the engine's target,
// so the same read/write/scan API works against a networked target (like the GUI's
// File -> Connect). The engine owns the client so it outlives the remote handle.
int l_connectToCeserver(lua_State* L) {
    const char* host = luaL_checkstring(L, 1);
    lua_Integer port = luaL_checkinteger(L, 2);
    lua_Integer pid = luaL_checkinteger(L, 3);
    lua_Integer timeout = luaL_optinteger(L, 4, 5000);
    const char* invalid = port<1 || port>UINT16_MAX ? "ceserver port must be between 1 and 65535" :
        pid<1 || pid>INT32_MAX ? "ceserver pid must be a positive 32-bit process ID" :
        timeout<1 || timeout>INT32_MAX ? "ceserver timeout must be a positive 32-bit millisecond count" : nullptr;
    if (invalid) { lua_pushnil(L);lua_pushstring(L,invalid);return 2; }
    auto* eng = ce::LuaEngine::instanceFromState(L);
    if (!eng) { lua_pushnil(L); lua_pushstring(L, "no engine"); return 2; }

    auto client = std::make_unique<ce::os::CEServerClient>();
    client->setTimeoutMs(static_cast<int>(timeout));
    std::string err;
    if (!client->connectTcp(host, (uint16_t)port, err)) {
        lua_pushnil(L);
        lua_pushstring(L, err.empty() ? "connect failed" : err.c_str());
        return 2;
    }
    // open() stores &*client; moving the unique_ptr into the engine keeps the
    // CEServerClient object at the same address, so the stored pointer stays valid.
    auto handle = ce::os::RemoteProcessHandle::open(*client, static_cast<pid_t>(pid));
    if (!handle) {
        lua_pushnil(L);
        lua_pushstring(L, "openProcess on ceserver failed");
        return 2;
    }
    eng->setOwnedCeserverClient(std::move(client));   // own the client first (outlives handle)
    eng->setOwnedProcess(std::move(handle));
    lua_pushinteger(L, pid);
    return 1;
}

// Evaluate an option getter under pcall so Lua errors cannot skip C++ destructors.
std::expected<void,std::string> gdbOptionField(lua_State* L,int index,const char* name) {
    index=lua_absindex(L,index);
    lua_pushcfunction(L,+[](lua_State* state){lua_pushvalue(state,2);lua_gettable(state,1);return 1;});
    lua_pushvalue(L,index);lua_pushstring(L,name);
    if (lua_pcall(L,2,1,0)==LUA_OK) return {};
    size_t size=0;const char* error=lua_tolstring(L,-1,&size);
    std::string message=error ? std::string(error,size) : "GDB option lookup failed";
    lua_pop(L,1);return std::unexpected(std::move(message));
}
static std::expected<GdbProcessOptions,std::string> gdbOptions(lua_State* L,int index) {
    GdbProcessOptions options;
    if (lua_isnoneornil(L,index)) return options;
    if (!lua_istable(L,index)) return std::unexpected("GDB options must be a table");
    index=lua_absindex(L,index);
    auto field=[&](const char* name){return gdbOptionField(L,index,name);};
    auto result=field("byteOrder");if (!result) return std::unexpected(result.error());
    if (!lua_isnil(L,-1)) {
        size_t count=0;const char* value=lua_tolstring(L,-1,&count);
        std::string_view order=value ? std::string_view(value,count) : std::string_view{};
        if (order=="little" || order=="le") options.byteOrder=ByteOrder::Little;
        else if (order=="big" || order=="be") options.byteOrder=ByteOrder::Big;
        else if (order!="unknown") {lua_pop(L,1);return std::unexpected("byteOrder must be little, big or unknown");}
    }
    lua_pop(L,1);
    for (const char* name:{"pointerWidth","timeoutMs"}) {
        result=field(name);if (!result) return std::unexpected(result.error());
        if (!lua_isnil(L,-1)) {
            const bool valid=lua_isinteger(L,-1);const auto value=lua_tointeger(L,-1);lua_pop(L,1);
            if (!valid) return std::unexpected(std::string(name)+" must be an integer");
            if (!std::strcmp(name,"pointerWidth")) {
                if (value!=4 && value!=8) return std::unexpected("pointerWidth must be 4 or 8");
                options.pointerWidth=static_cast<uint8_t>(value);
            } else {
                if (value<1 || value>60000) return std::unexpected("timeoutMs must be between 1 and 60000");
                options.timeout=std::chrono::milliseconds(value);
            }
        } else lua_pop(L,1);
    }
    result=field("regions");if (!result) return std::unexpected(result.error());
    if (!lua_isnil(L,-1)) {
        if (!lua_istable(L,-1)) {lua_pop(L,1);return std::unexpected("regions must be an array of {base, size} tables");}
        const int regions=lua_absindex(L,-1);const size_t count=lua_rawlen(L,regions);
        if (count>4096) {lua_pop(L,1);return std::unexpected("Too many GDB regions");}
        for (size_t i=1;i<=count;++i) {
            lua_rawgeti(L,regions,static_cast<lua_Integer>(i));
            if (!lua_istable(L,-1)) {lua_pop(L,2);return std::unexpected("Each GDB region must be a table");}
            const int entry=lua_absindex(L,-1);
            result=gdbOptionField(L,entry,"base");
            if (!result) {lua_pop(L,2);return std::unexpected(result.error());}
            const bool validBase=lua_isinteger(L,-1);const auto base=static_cast<uint64_t>(lua_tointeger(L,-1));lua_pop(L,1);
            result=gdbOptionField(L,entry,"size");
            if (!result) {lua_pop(L,2);return std::unexpected(result.error());}
            const bool validSize=lua_isinteger(L,-1);const auto size=lua_tointeger(L,-1);lua_pop(L,1);
            if (!validBase || base>UINTPTR_MAX || !validSize || size<=0 || static_cast<uint64_t>(size)>UINTPTR_MAX-base) {
                lua_pop(L,2);return std::unexpected("Invalid GDB region base or size");
            }
            options.regions.push_back({static_cast<uintptr_t>(base),static_cast<size_t>(size),MemProt::ReadWrite,MemType::Private,MemState::Committed,{}});
            lua_pop(L,1);
        }
    }
    lua_pop(L,1);return options;
}
int l_connectToGdb(lua_State* L) {
    auto fail=[&](const std::string& error){lua_pushnil(L);lua_pushlstring(L,error.data(),error.size());return 2;};
    size_t size=0;const char* host=lua_tolstring(L,1,&size);
    if (!host || !size || std::memchr(host,0,size)) return fail("GDB host must be a nonempty string");
    if (!lua_isinteger(L,2) || lua_tointeger(L,2)<1 || lua_tointeger(L,2)>65535) return fail("GDB port must be between 1 and 65535");
    auto* engine=LuaEngine::instanceFromState(L);if (!engine) return fail("No Lua engine");
    auto options=gdbOptions(L,3);if (!options) return fail(options.error());
    auto process=GdbProcessHandle::connect(std::string(host,size),static_cast<uint16_t>(lua_tointeger(L,2)),*options);
    if (!process) return fail(process.error());
    engine->setOwnedCeserverClient(nullptr);
    engine->setOwnedProcess(std::move(*process));lua_pushboolean(L,true);return 1;
}
int l_disconnectProcess(lua_State* L) {
    auto* engine=LuaEngine::instanceFromState(L);
    if (!engine) {lua_pushboolean(L,false);return 1;}
    auto* guest=dynamic_cast<GdbProcessHandle*>(engine->process());
    std::expected<void,std::string> detached;
    if (guest) detached=guest->detach();
    engine->setProcess(nullptr);
    engine->setOwnedCeserverClient(nullptr);
    if (!detached) {lua_pushnil(L);lua_pushlstring(L,detached.error().data(),detached.error().size());return 2;}
    lua_pushboolean(L,true);return 1;
}
int l_getGdbRegisterInfo(lua_State* L) {
    auto* process=dynamic_cast<GdbProcessHandle*>(getProc(L));
    if (!process) {lua_pushnil(L);lua_pushstring(L,"No GDB target");return 2;}
    lua_newtable(L);size_t i=0;
    for (const auto& reg:process->registerDescription().registers) {
        lua_newtable(L);
        lua_pushlstring(L,reg.name.data(),reg.name.size());lua_setfield(L,-2,"name");
        lua_pushinteger(L,reg.bits);lua_setfield(L,-2,"bits");
        lua_pushinteger(L,reg.number);lua_setfield(L,-2,"number");
        lua_pushlstring(L,reg.type.data(),reg.type.size());lua_setfield(L,-2,"type");
        lua_rawseti(L,-2,static_cast<lua_Integer>(++i));
    }
    return 1;
}
int l_gdbRegister(lua_State* L,bool write) {
    auto fail=[&](const std::string& error){lua_pushnil(L);lua_pushlstring(L,error.data(),error.size());return 2;};
    auto* process=dynamic_cast<GdbProcessHandle*>(getProc(L));if (!process) return fail("No GDB target");
    size_t size=0;const char* name=lua_tolstring(L,1,&size);
    if (!name || !size || size>256 || std::memchr(name,0,size)) return fail("Invalid GDB register name");
    const std::string registerName(name,size);
    if (write) {
        const char* bytes=lua_tolstring(L,2,&size);if (!bytes || lua_type(L,2)!=LUA_TSTRING) return fail("Register data must be a byte string");
        auto result=process->writeRegister(registerName,{reinterpret_cast<const uint8_t*>(bytes),size});
        if (!result) return fail(result.error());
        lua_pushboolean(L,true);return 1;
    }
    auto result=process->readRegister(registerName);if (!result) return fail(result.error());
    lua_pushlstring(L,reinterpret_cast<const char*>(result->data()),result->size());return 1;
}
int l_readGdbRegister(lua_State* L) {return l_gdbRegister(L,false);}
int l_writeGdbRegister(lua_State* L) {return l_gdbRegister(L,true);}

int l_getOpenedProcessID(lua_State* L) {
    auto* p = getProc(L);
    lua_pushinteger(L, p ? p->pid() : 0);
    return 1;
}

int l_writePointer(lua_State* L) {
    auto* p = getProc(L);
    if (!p) return 0;
    uintptr_t addr = 0;
    if (!checkAddress(L, 1, p, addr)) { lua_pushboolean(L, 0); return 1; }
    uintptr_t val = (uintptr_t)luaL_checkinteger(L, 2);
    size_t size = p->pointerWidth(addr);
    ByteOrder order = p->byteOrder(addr);
    if ((size != 4 && size != 8) || order == ByteOrder::Unknown || (size == 4 && val > UINT32_MAX)) {
        lua_pushboolean(L, 0); return 1;
    }
    uint8_t bytes[8]{};
    for (size_t i = 0; i < size; ++i)
        bytes[order == ByteOrder::Big ? size - 1 - i : i] = static_cast<uint8_t>(uint64_t(val) >> (8 * i));
    lua_pushboolean(L, writeExact(p, addr, bytes, size));
    return 1;
}

// getOpenedProcesses() -> table {[pid] = name} of running processes (CE-style).
int l_getOpenedProcesses(lua_State* L) {
    ce::os::LinuxProcessEnumerator en;
    auto procs = en.list();
    lua_newtable(L);
    for (const auto& p : procs) {
        lua_pushinteger(L, (lua_Integer)p.pid);
        lua_pushstring(L, p.name.c_str());
        lua_settable(L, -3);   // t[pid] = name
    }
    return 1;
}

// getUserDefinedSymbolByName(name) -> address, or nil. Reads back a symbol
// registered with registerSymbol (CE-compatible; user symbols only).
int l_getUserDefinedSymbolByName(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_user_symbols");
    if (!lua_istable(L, -1)) { lua_pop(L, 1); lua_pushnil(L); return 1; }
    lua_getfield(L, -1, name);
    if (lua_isnil(L, -1)) { lua_pop(L, 2); lua_pushnil(L); return 1; }
    lua_Integer addr = lua_tointeger(L, -1);
    lua_pop(L, 2);
    lua_pushinteger(L, addr);
    return 1;
}

// getUserDefinedSymbolByAddress(address) -> name, or nil (reverse of the above).
int l_getUserDefinedSymbolByAddress(lua_State* L) {
    lua_Integer addr = luaL_checkinteger(L, 1);
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_user_symbols");
    if (!lua_istable(L, -1)) { lua_pop(L, 1); lua_pushnil(L); return 1; }
    lua_pushnil(L);
    while (lua_next(L, -2)) {              // key(name) at -2, value(addr) at -1
        if (lua_tointeger(L, -1) == addr) {
            lua_pushvalue(L, -2);          // copy the name to the top
            return 1;                      // Lua returns the top value
        }
        lua_pop(L, 1);                     // drop value, keep key for next
    }
    lua_pushnil(L);
    return 1;
}

int l_registerSymbol(lua_State* L) {
    auto* r = getResolver(L);
    const char* name = luaL_checkstring(L, 1);
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 2);
    // Register with the resolver so getAddressFromName() and the expression
    // parser can resolve it, not just Lua's own bookkeeping table.
    if (r) r->addUserSymbol(addr, name);
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_user_symbols");
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        lua_newtable(L);
        lua_pushvalue(L, -1);
        lua_setfield(L, LUA_REGISTRYINDEX, "ce_user_symbols");
    }
    lua_pushinteger(L, (lua_Integer)addr);
    lua_setfield(L, -2, name);
    lua_pop(L, 1);
    return 0;
}

int l_unregisterSymbol(lua_State* L) {
    auto* r = getResolver(L);
    const char* name = luaL_checkstring(L, 1);
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_user_symbols");
    if (!lua_isnil(L, -1)) {
        // Recover the address so we can drop it from the resolver too.
        lua_getfield(L, -1, name);
        if (r && lua_isinteger(L, -1)) r->removeUserSymbol((uintptr_t)lua_tointeger(L, -1));
        lua_pop(L, 1);
        lua_pushnil(L);
        lua_setfield(L, -2, name);
    }
    lua_pop(L, 1);
    return 0;
}

int l_inputQuery(lua_State* L) {
    const char* title = luaL_checkstring(L, 1);
    const char* prompt = luaL_checkstring(L, 2);
    const char* defval = luaL_optstring(L, 3, "");
    // In GUI mode, would use QInputDialog; for now, stderr prompt
    fprintf(stderr, "[CE Lua] %s: %s [%s]: ", title, prompt, defval);
    char buf[256];
    if (fgets(buf, sizeof(buf), stdin)) {
        buf[strcspn(buf, "\n")] = 0;
        if (buf[0] == 0) lua_pushstring(L, defval);
        else lua_pushstring(L, buf);
    } else {
        lua_pushstring(L, defval);
    }
    return 1;
}

// SECURITY: shellExecute runs an arbitrary command line via /bin/sh as the
// cecore user (commonly root). This is intentional CE-compatible surface, but
// it means loading a Lua script (or an AutoAssembler {$lua} block, or a cheat
// table's OnActivate) is equivalent to granting native command execution as the
// cecore user. Treat scripts as trusted code. luaL_checkstring guarantees a
// non-NULL, NUL-terminated argument so the system() call itself is well-formed.
// Default-DENY: shellExecute is arbitrary command execution, so loading a
// malicious table would grant native RCE (usually as root). It now requires an
// explicit, out-of-band opt-in the script itself cannot set: the process env
// var CECORE_LUA_ALLOW_UNSAFE, read once when the Lua state is created (see
// luaUnsafeAllowed), so changing the environment later does not enable it.
int l_shellExecute(lua_State* L) {
    if (!luaUnsafeAllowed(L))
        return luaL_error(L,
            "shellExecute blocked: it runs arbitrary shell commands. Only enable for "
            "tables you trust by launching with CECORE_LUA_ALLOW_UNSAFE=1 (see SECURITY.md).");
    const char* cmd = luaL_checkstring(L, 1);
    int ret = system(cmd);
    lua_pushinteger(L, ret);
    return 1;
}

int l_getScreenWidth(lua_State* L) {
    // Basic X11 screen size
    lua_pushinteger(L, 1920); // Default; would query X11
    return 1;
}

int l_getScreenHeight(lua_State* L) {
    lua_pushinteger(L, 1080);
    return 1;
}

int l_inMainThread(lua_State* L) {
    lua_pushboolean(L, 1); // Simplified
    return 1;
}

int l_getProcessName(lua_State* L) {
    char buf[16] = {0};
    if (prctl(PR_GET_NAME, (unsigned long)buf, 0, 0, 0) == 0) {
        lua_pushstring(L, buf);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

int l_getThreadList(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_newtable(L); return 1; }
    auto threads = p->threads();
    lua_newtable(L);
    for (size_t i = 0; i < threads.size(); ++i) {
        lua_pushinteger(L, threads[i].tid);
        lua_rawseti(L, -2, i + 1);
    }
    return 1;
}

int l_readRegionFromFile(lua_State* L) {
    auto* p = getProc(L);
    if (!p) return 0;
    const char* filename = luaL_checkstring(L, 1);
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 2);
    std::ifstream f(filename, std::ios::binary);
    if (!f) { lua_pushboolean(L, 0); return 1; }
    // Bound + guard the read (see l_readFromFile): an unbounded "/dev/zero" / huge
    // file would OOM and throw bad_alloc through this C function into liblua.
    constexpr size_t kMax = 64u * 1024 * 1024;  // 64 MB
    try {
        std::vector<uint8_t> data;
        char buf[65536];
        while (f && data.size() < kMax) {
            f.read(buf, (std::streamsize)std::min(sizeof(buf), kMax - data.size()));
            std::streamsize got = f.gcount();
            if (got <= 0) break;
            data.insert(data.end(), buf, buf + got);
        }
        auto r = p->write(addr, data.data(), data.size());
        lua_pushboolean(L, r.has_value());
        return 1;
    } catch (const std::exception& ex) {
        throw std::runtime_error(std::string("readRegionFromFile: ") + ex.what());   // the firewall reports it
    }
}

int l_writeRegionToFile(lua_State* L) {
    auto* p = getProc(L);
    if (!p) return 0;
    const char* filename = luaL_checkstring(L, 1);
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 2);
    lua_Integer rawSize = luaL_checkinteger(L, 3);
    luaL_argcheck(L, rawSize >= 0, 3, "size must be non-negative");
    // Cap the allocation so a hostile/typo'd huge size cannot throw bad_alloc
    // (std::vector ctor) out of this C function into C-compiled Lua frames.
    constexpr lua_Integer kMaxRegion = 256 * 1024 * 1024; // 256 MiB
    luaL_argcheck(L, rawSize <= kMaxRegion, 3, "size too large");
    size_t size = (size_t)rawSize;
    std::vector<uint8_t> buf(size);
    auto r = p->read(addr, buf.data(), size);
    if (!r) { lua_pushboolean(L, 0); return 1; }
    std::ofstream f;
    if (openNoFollow(f, filename, std::ios::out | std::ios::binary | std::ios::trunc)) { f.write((char*)buf.data(), *r); lua_pushboolean(L, f.good()); }
    else lua_pushboolean(L, 0);
    return 1;
}

int l_AOBScan(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    const char* pattern = luaL_checkstring(L, 1);
    try {
        ScanConfig cfg;
        cfg.valueType = ValueType::ByteArray;
        if (!cfg.parseAOB(pattern))
            throw std::invalid_argument(std::string("AOBScan: invalid AOB pattern '") + pattern + "'");
        cfg.alignment = 1;
        MemoryScanner scanner;
        auto result = scanner.firstScan(*p, cfg);
        // CE returns a StringList of ALL matches (0-indexed hex strings, .Count,
        // .destroy()); our previous impl returned only the first address as an
        // integer, silently dropping the rest and breaking result iteration.
        // No match is nil, as in CE.
        size_t n = result.count();
        if (n == 0) { lua_pushnil(L); return 1; }
        lua_newtable(L);
        for (size_t i = 0; i < n; ++i) {
            char hex[24];
            snprintf(hex, sizeof(hex), "%llX", (unsigned long long)result.address(i));
            lua_pushstring(L, hex);
            lua_rawseti(L, -2, (int)i);          // CE result lists are 0-indexed
        }
        lua_pushinteger(L, (lua_Integer)n);
        lua_setfield(L, -2, "Count");
        lua_pushcfunction(L, [](lua_State*) { return 0; });  // .destroy() no-op
        lua_setfield(L, -2, "destroy");
    } catch (const std::exception& ex) {
        throw;   // the firewall reports it outside this catch
    } catch (...) {
        throw std::runtime_error("AOBScan failed");
    }
    return 1;
}

int l_AOBScanEx(lua_State* L) {
    // Returns all results as a table
    auto* p = getProc(L);
    if (!p) { lua_newtable(L); return 1; }
    const char* pattern = luaL_checkstring(L, 1);
    try {
        ScanConfig cfg;
        cfg.valueType = ValueType::ByteArray;
        if (!cfg.parseAOB(pattern))
            throw std::invalid_argument(std::string("AOBScan: invalid AOB pattern '") + pattern + "'");
        cfg.alignment = 1;
        MemoryScanner scanner;
        auto result = scanner.firstScan(*p, cfg);
        lua_newtable(L);
        // Return ALL matches (like AOBScan and CE), not a silent first-1000 slice.
        size_t count = result.count();
        luaL_checkstack(L, 2, "AOBScanEx result table");
        for (size_t i = 0; i < count; ++i) {
            lua_pushinteger(L, (lua_Integer)result.address(i));
            lua_rawseti(L, -2, i + 1);
        }
    } catch (const std::exception& ex) {
        throw;   // the firewall reports it outside this catch
    } catch (...) {
        throw std::runtime_error("AOBScan failed");
    }
    return 1;
}

// AOBScanModule(moduleName, pattern) -> result list restricted to that module's
// address range (CE convention). Same 0-indexed .Count/.destroy() shape as AOBScan.
// getUniqueAOB(address) -> aobString, offset. Returns a byte pattern that uniquely
// identifies `address` within its module (extended until unique), plus the offset from
// the pattern's start to `address`. Our pattern starts at `address`, so offset is 0.
// Returns nil if the address is not inside a loaded module.
int l_getUniqueAOB(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    for (auto& m : p->modules()) {
        if (addr < m.base || addr >= m.base + m.size) continue;
        std::string sig = ce::uniqueAobSignature(*p, m, addr, /*minLen=*/1, /*maxLen=*/128);
        if (sig.empty()) break;
        lua_pushstring(L, sig.c_str());
        lua_pushinteger(L, 0);   // pattern starts at `address`
        return 2;
    }
    lua_pushnil(L);
    return 1;
}

int l_AOBScanModule(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    const char* modName = luaL_checkstring(L, 1);
    const char* pattern = luaL_checkstring(L, 2);
    const auto* mod = findModuleByName(p, modName);
    if (!mod) { lua_pushnil(L); return 1; }
    try {
        ScanConfig cfg;
        cfg.valueType = ValueType::ByteArray;
        if (!cfg.parseAOB(pattern))
            throw std::invalid_argument(std::string("AOBScan: invalid AOB pattern '") + pattern + "'");
        cfg.alignment = 1;
        cfg.startAddress = mod->base;
        cfg.stopAddress = mod->base + mod->size;
        MemoryScanner scanner;
        auto result = scanner.firstScan(*p, cfg);
        size_t n = result.count();
        if (n == 0) { lua_pushnil(L); return 1; }   // like AOBScan
        lua_newtable(L);
        for (size_t i = 0; i < n; ++i) {
            char hex[24];
            snprintf(hex, sizeof(hex), "%llX", (unsigned long long)result.address(i));
            lua_pushstring(L, hex);
            lua_rawseti(L, -2, (int)i);
        }
        lua_pushinteger(L, (lua_Integer)n);
        lua_setfield(L, -2, "Count");
        lua_pushcfunction(L, [](lua_State*) { return 0; });
        lua_setfield(L, -2, "destroy");
    } catch (const std::exception& ex) {
        throw;   // the firewall reports it outside this catch
    } catch (...) {
        throw std::runtime_error("AOBScanModule failed");
    }
    return 1;
}

// AOBScanUnique(aobstring) -> first matching address (integer) or nil. CE convenience
// over AOBScan that returns a single address instead of a result list. Like CE, the
// "Unique" is the caller's responsibility: it returns the first match found and does not
// verify the pattern is unique.
int l_AOBScanUnique(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    const char* pattern = luaL_checkstring(L, 1);
    try {
        ScanConfig cfg;
        cfg.valueType = ValueType::ByteArray;
        if (!cfg.parseAOB(pattern))
            throw std::invalid_argument(std::string("AOBScanUnique: invalid AOB pattern '") + pattern + "'");
        cfg.alignment = 1;
        MemoryScanner scanner;
        auto result = scanner.firstScan(*p, cfg);
        if (result.count() == 0) { lua_pushnil(L); return 1; }
        lua_pushinteger(L, (lua_Integer)result.address(0));
    } catch (const std::exception& ex) {
        throw;   // the firewall reports it outside this catch
    } catch (...) {
        throw std::runtime_error("AOBScanUnique failed");
    }
    return 1;
}

// AOBScanModuleUnique(modulename, aobstring) -> the sole match within the module, or nil.
int l_AOBScanModuleUnique(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    const char* modName = luaL_checkstring(L, 1);
    const char* pattern = luaL_checkstring(L, 2);
    const auto* mod = findModuleByName(p, modName);
    if (!mod) { lua_pushnil(L); return 1; }
    try {
        ScanConfig cfg;
        cfg.valueType = ValueType::ByteArray;
        if (!cfg.parseAOB(pattern))
            throw std::invalid_argument(std::string("AOBScanModuleUnique: invalid AOB pattern '") + pattern + "'");
        cfg.alignment = 1;
        cfg.startAddress = mod->base;
        cfg.stopAddress = mod->base + mod->size;
        MemoryScanner scanner;
        auto result = scanner.firstScan(*p, cfg);
        if (result.hasWriteError() || result.count() != 1) { lua_pushnil(L); return 1; }
        lua_pushinteger(L, (lua_Integer)result.address(0));
    } catch (const std::exception& ex) {
        throw;   // the firewall reports it outside this catch
    } catch (...) {
        throw std::runtime_error("AOBScanModuleUnique failed");
    }
    return 1;
}

int l_fullAccess(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); lua_pushstring(L, "no process attached"); return 2; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    size_t size = (size_t)luaL_checkinteger(L, 2);
    if (auto r = p->protect(addr, size, MemProt::All); !r) {
        lua_pushnil(L);
        lua_pushstring(L, ce::targetOperationError(*p, ce::TargetFeature::Protect, r.error()).c_str());
        return 2;
    }
    lua_pushboolean(L, 1);
    return 1;
}
} // namespace ce::lua_detail
