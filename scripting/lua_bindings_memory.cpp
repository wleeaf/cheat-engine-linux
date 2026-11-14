/// Lua bindings: reading and writing target memory (every width, strings,
/// byte tables, local process memory).
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

// ── Memory read functions (all widths) ──

bool readExact(ProcessHandle* proc, uintptr_t address, void* data, size_t size) {
    auto result = proc->read(address, data, size);
    return result && *result == size;
}

bool writeExact(ProcessHandle* proc, uintptr_t address, const void* data, size_t size) {
    auto result = proc->write(address, data, size);
    return result && *result == size;
}

// The address argument at `index`: an integer, or a string such as
// "game.exe+1234" or "[[base]+10]" resolved like readValue does (CE's
// lua_toaddress). Raises for other types; false when a string does not
// resolve, which the callers report as nil (reads) or false (writes).
bool checkAddress(lua_State* L, int index, ProcessHandle* process, uintptr_t& address) {
    if (lua_type(L, index) != LUA_TSTRING) {
        address = static_cast<uintptr_t>(luaL_checkinteger(L, index));
        return true;
    }
    if (!process) return false;
    auto parsed = ExpressionParser(process, getResolver(L)).parse(lua_tostring(L, index));
    if (!parsed) return false;
    address = *parsed;
    return true;
}

template <typename T>
static bool readTargetScalar(ProcessHandle* process, uintptr_t address, T& value) {
    std::array<uint8_t, sizeof(T)> bytes{};
    if (!readExact(process, address, bytes.data(), bytes.size())) return false;
    ByteOrder order = sizeof(T) == 1 ? ByteOrder::Little : process->byteOrder(address);
    if (order == ByteOrder::Unknown) return false;
    bool hostBig = std::endian::native == std::endian::big;
    if ((order == ByteOrder::Big) != hostBig) std::reverse(bytes.begin(), bytes.end());
    value = std::bit_cast<T>(bytes);
    return true;
}
template <typename T>
static bool writeTargetScalar(ProcessHandle* process, uintptr_t address, T value) {
    auto bytes = std::bit_cast<std::array<uint8_t, sizeof(T)>>(value);
    ByteOrder order = sizeof(T) == 1 ? ByteOrder::Little : process->byteOrder(address);
    if (order == ByteOrder::Unknown) return false;
    bool hostBig = std::endian::native == std::endian::big;
    if ((order == ByteOrder::Big) != hostBig) std::reverse(bytes.begin(), bytes.end());
    return writeExact(process, address, bytes.data(), bytes.size());
}

static void pushTargetMachine(lua_State* L, const TargetMachine& machine) {
    lua_newtable(L);
    lua_pushstring(L, cpuArchitectureName(machine.architecture)); lua_setfield(L, -2, "architecture");
    lua_pushinteger(L, machine.pointerWidth); lua_setfield(L, -2, "pointerWidth");
    lua_pushstring(L, byteOrderName(machine.byteOrder)); lua_setfield(L, -2, "byteOrder");
    lua_pushstring(L, byteOrderName(machine.instructionByteOrder)); lua_setfield(L, -2, "instructionByteOrder");
    lua_pushstring(L, targetAbiName(machine.abi)); lua_setfield(L, -2, "abi");
}
int l_getTargetInfo(lua_State* L) {
    auto* process = getProc(L);
    if (!process) { lua_pushnil(L); lua_pushstring(L, "no process attached"); return 2; }
    auto description = process->targetDescription();
    if (auto* engine=LuaEngine::instanceFromState(L); engine && engine->debugAttached())
        description.pendingRecovery=description.pendingRecovery || engine->debugSession()->hasPendingRecovery();
    lua_newtable(L);
    pushTargetMachine(L, description.host); lua_setfield(L, -2, "host");
    pushTargetMachine(L, description.program); lua_setfield(L, -2, "program");
    lua_pushboolean(L, description.mixedCode); lua_setfield(L, -2, "mixedCode");
    lua_pushboolean(L, description.live); lua_setfield(L, -2, "live");
    lua_pushboolean(L, description.pendingRecovery); lua_setfield(L, -2, "pendingRecovery");
    lua_pushinteger(L, description.tracerPid); lua_setfield(L, -2, "tracerPid");
    const char* transport = description.transport == TargetTransport::Local ? "local" :
        description.transport == TargetTransport::CEServer ? "ceserver" : description.transport == TargetTransport::Gdb ? "gdb" : "unknown";
    lua_pushstring(L, transport); lua_setfield(L, -2, "transport");
    return 1;
}
int l_getTargetCapabilities(lua_State* L) {
    auto* process = getProc(L);
    if (!process) { lua_pushnil(L); lua_pushstring(L, "no process attached"); return 2; }
    lua_newtable(L);
    auto description=process->targetDescription();
    if (auto* engine=LuaEngine::instanceFromState(L); engine && engine->debugAttached())
        description.pendingRecovery=description.pendingRecovery || engine->debugSession()->hasPendingRecovery();
    for (const auto& capability : targetCapabilities(description)) {
        lua_newtable(L);
        lua_pushstring(L, capabilityStateName(capability.state)); lua_setfield(L, -2, "state");
        lua_pushstring(L, capability.reason.c_str()); lua_setfield(L, -2, "reason");
        lua_setfield(L, -2, targetFeatureName(capability.feature));
    }
    return 1;
}
int l_retryPendingOperations(lua_State* L) {
    auto* process = getProc(L);
    if (!process) { lua_pushnil(L); lua_pushstring(L, "no process attached"); return 2; }
    if (auto* engine=LuaEngine::instanceFromState(L); engine && engine->debugAttached()) {
        auto* session=engine->debugSession();
        if (session->hasPendingRecovery() && !session->retryPendingOperations()) {
            lua_pushnil(L); lua_pushstring(L,session->lastError().message().c_str()); return 2;
        }
    }
    auto result = process->retryPendingOperations();
    if (!result) { lua_pushnil(L); lua_pushstring(L, result.error().message().c_str()); return 2; }
    lua_pushboolean(L, true);
    return 1;
}

int l_resumePendingCallSignal(lua_State* L) {
    auto* process=getProc(L);
    if (!process) { lua_pushnil(L); lua_pushstring(L,"no process attached"); return 2; }
    luaL_checktype(L,1,LUA_TBOOLEAN);
    auto result=process->resumePendingCallSignal(lua_toboolean(L,1));
    if (!result) { lua_pushnil(L); lua_pushstring(L,result.error().message().c_str()); return 2; }
    lua_pushboolean(L,true); return 1;
}

int l_readByte(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    uintptr_t addr = 0;
    if (!checkAddress(L, 1, p, addr)) { lua_pushnil(L); return 1; }
    uint8_t v = 0;
    if (readTargetScalar(p, addr, v)) lua_pushinteger(L, lua_toboolean(L, 2) ? lua_Integer(int8_t(v)) : lua_Integer(v));
    else lua_pushnil(L);
    return 1;
}

// readByte, readSmallInteger and readInteger take an optional `signed` flag
// and are unsigned without it, as in CE.
int l_readSmallInteger(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    uintptr_t addr = 0;
    if (!checkAddress(L, 1, p, addr)) { lua_pushnil(L); return 1; }
    uint16_t v = 0;
    if (readTargetScalar(p, addr, v)) lua_pushinteger(L, lua_toboolean(L, 2) ? lua_Integer(int16_t(v)) : lua_Integer(v));
    else lua_pushnil(L);
    return 1;
}

int l_readQword(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    uintptr_t addr = 0;
    if (!checkAddress(L, 1, p, addr)) { lua_pushnil(L); return 1; }
    int64_t v = 0;
    if (readTargetScalar(p, addr, v)) lua_pushinteger(L, v);
    else lua_pushnil(L);
    return 1;
}

int l_readPointer(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    uintptr_t addr = 0;
    if (!checkAddress(L, 1, p, addr)) { lua_pushnil(L); return 1; }
    size_t size = p->pointerWidth(addr);
    if (size != 4 && size != 8) { lua_pushnil(L); return 1; }
    uint8_t bytes[8]{};
    if (!readExact(p, addr, bytes, size)) { lua_pushnil(L); return 1; }
    auto value = decodeTargetUnsigned({bytes, size}, p->byteOrder(addr));
    if (value) lua_pushinteger(L, static_cast<lua_Integer>(*value)); else lua_pushnil(L);
    return 1;
}

int l_readDouble(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    uintptr_t addr = 0;
    if (!checkAddress(L, 1, p, addr)) { lua_pushnil(L); return 1; }
    double v = 0;
    if (readTargetScalar(p, addr, v)) lua_pushnumber(L, v);
    else lua_pushnil(L);
    return 1;
}

int l_readString(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    uintptr_t addr = 0;
    if (!checkAddress(L, 1, p, addr)) { lua_pushnil(L); return 1; }
    // Clamp as a lua_Integer: narrowing first turned 0x100000000 into 0 and
    // 0x80000000 into a negative length.
    const lua_Integer requested = luaL_optinteger(L, 2, 256);
    luaL_argcheck(L, requested >= 0, 2, "max length must be non-negative");
    // readString(address, maxLength, widechar): maxLength counts bytes in
    // both forms, as in CE. Cap like readBytes: an unbounded maxLen could OOM.
    const bool wide = lua_toboolean(L, 3);
    constexpr lua_Integer kMaxReadString = 1 << 24;  // 16 MB
    const size_t maxLen = static_cast<size_t>(std::min(requested, kMaxReadString));
    // Lua owns the buffer, so a raise below leaks nothing.
    auto* buf = static_cast<unsigned char*>(lua_newuserdata(L, maxLen ? maxLen : 1));
    auto r = p->read(addr, buf, maxLen);
    if (!r) { lua_pushnil(L); return 1; }
    const size_t got = std::min(*r, maxLen);
    if (!wide) {
        lua_pushlstring(L, reinterpret_cast<const char*>(buf), strnlen(reinterpret_cast<const char*>(buf), got));
        return 1;
    }
    // UTF-16 in the target's byte order, to UTF-8, up to a zero code unit.
    const bool big = p->byteOrder(addr) == ByteOrder::Big;
    auto unit = [&](size_t i) -> uint32_t {
        return big ? (buf[2 * i] << 8) | buf[2 * i + 1] : buf[2 * i] | (buf[2 * i + 1] << 8);
    };
    luaL_Buffer out;
    luaL_buffinit(L, &out);
    const size_t units = got / 2;
    for (size_t i = 0; i < units; ++i) {
        uint32_t cp = unit(i);
        if (cp == 0) break;
        if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < units && unit(i + 1) >= 0xDC00 && unit(i + 1) <= 0xDFFF)
            cp = 0x10000 + ((cp - 0xD800) << 10) + (unit(++i) - 0xDC00);
        else if (cp >= 0xD800 && cp <= 0xDFFF)
            cp = 0xFFFD;   // an unpaired surrogate
        char utf8[4];
        int n = 0;
        if (cp < 0x80) utf8[n++] = char(cp);
        else if (cp < 0x800) { utf8[n++] = char(0xC0 | (cp >> 6)); utf8[n++] = char(0x80 | (cp & 0x3F)); }
        else if (cp < 0x10000) {
            utf8[n++] = char(0xE0 | (cp >> 12)); utf8[n++] = char(0x80 | ((cp >> 6) & 0x3F));
            utf8[n++] = char(0x80 | (cp & 0x3F));
        } else {
            utf8[n++] = char(0xF0 | (cp >> 18)); utf8[n++] = char(0x80 | ((cp >> 12) & 0x3F));
            utf8[n++] = char(0x80 | ((cp >> 6) & 0x3F)); utf8[n++] = char(0x80 | (cp & 0x3F));
        }
        luaL_addlstring(&out, utf8, n);
    }
    luaL_pushresult(&out);
    return 1;
}

// ── Memory write functions ──

int l_writeByte(lua_State* L) {
    auto* p = getProc(L);
    if (!p) return 0;
    uintptr_t addr = 0;
    if (!checkAddress(L, 1, p, addr)) { lua_pushboolean(L, 0); return 1; }
    uint8_t v = (uint8_t)luaL_checkinteger(L, 2);
    lua_pushboolean(L, writeTargetScalar(p, addr, v));
    return 1;
}

int l_writeSmallInteger(lua_State* L) {
    auto* p = getProc(L);
    if (!p) return 0;
    uintptr_t addr = 0;
    if (!checkAddress(L, 1, p, addr)) { lua_pushboolean(L, 0); return 1; }
    int16_t v = (int16_t)luaL_checkinteger(L, 2);
    lua_pushboolean(L, writeTargetScalar(p, addr, v));
    return 1;
}

int l_writeQword(lua_State* L) {
    auto* p = getProc(L);
    if (!p) return 0;
    uintptr_t addr = 0;
    if (!checkAddress(L, 1, p, addr)) { lua_pushboolean(L, 0); return 1; }
    int64_t v = luaL_checkinteger(L, 2);
    lua_pushboolean(L, writeTargetScalar(p, addr, v));
    return 1;
}

int l_writeDouble(lua_State* L) {
    auto* p = getProc(L);
    if (!p) return 0;
    uintptr_t addr = 0;
    if (!checkAddress(L, 1, p, addr)) { lua_pushboolean(L, 0); return 1; }
    double v = luaL_checknumber(L, 2);
    lua_pushboolean(L, writeTargetScalar(p, addr, v));
    return 1;
}

int l_writeString(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushboolean(L, 0); return 1; }
    uintptr_t addr = 0;
    if (!checkAddress(L, 1, p, addr)) { lua_pushboolean(L, 0); return 1; }
    const char* s = luaL_checkstring(L, 2);
    // Return success like CE (and the other write* bindings).
    lua_pushboolean(L, writeExact(p, addr, s, strlen(s) + 1));
    return 1;
}

// Raise for a non-integer (or, when strict, out of 0..255) element of the
// table at `idx`, positions first..last, before the caller builds any C++
// container: a Lua error longjmps past destructors and would leak it.
void checkByteTable(lua_State* L, int idx, lua_Integer first, lua_Integer last, bool strict) {
    for (lua_Integer i = first; i <= last; ++i) {
        lua_rawgeti(L, idx, i);
        const lua_Integer value = luaL_checkinteger(L, -1);
        if (strict) luaL_argcheck(L, value >= 0 && value <= 255, idx, "byte values must be 0..255");
        lua_pop(L, 1);
    }
}

int l_writeBytes(lua_State* L) {
    auto* p = getProc(L);
    if (!p) return 0;
    uintptr_t addr = 0;
    if (!checkAddress(L, 1, p, addr)) { lua_pushboolean(L, 0); return 1; }
    // CE accepts writeBytes(addr, {b1,b2,...}) or writeBytes(addr, b1, b2, ...).
    const bool table = lua_istable(L, 2);
    const int top = lua_gettop(L);
    if (table) checkByteTable(L, 2, 1, (lua_Integer)lua_rawlen(L, 2), true);
    else
        for (int i = 2; i <= top; ++i) {
            lua_Integer value = luaL_checkinteger(L, i);
            luaL_argcheck(L, value >= 0 && value <= 255, i, "byte values must be 0..255");
        }
    std::vector<uint8_t> bytes;   // every element is valid: nothing below raises
    if (table) {
        const int n = (int)lua_rawlen(L, 2);
        bytes.resize(n);
        for (int i = 1; i <= n; ++i) {
            lua_rawgeti(L, 2, i);
            bytes[i-1] = (uint8_t)lua_tointeger(L, -1);
            lua_pop(L, 1);
        }
    } else {
        for (int i = 2; i <= top; ++i) bytes.push_back((uint8_t)lua_tointeger(L, i));
    }
    (void)p->write(addr, bytes.data(), bytes.size());
    return 0;
}

// ── The four workhorse CE reads/writes for the opened process ──
// readInteger(address[, signed]): 4-byte int, unsigned unless `signed` is true (CE).
int l_readInteger(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    uintptr_t addr = 0;
    if (!checkAddress(L, 1, p, addr)) { lua_pushnil(L); return 1; }
    bool isSigned = lua_toboolean(L, 2);
    int32_t v = 0;
    if (readTargetScalar(p, addr, v)) {
        if (isSigned) lua_pushinteger(L, v);
        else          lua_pushinteger(L, (lua_Integer)(uint32_t)v);
    } else lua_pushnil(L);
    return 1;
}

int l_writeInteger(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushboolean(L, 0); return 1; }
    uintptr_t addr = 0;
    if (!checkAddress(L, 1, p, addr)) { lua_pushboolean(L, 0); return 1; }
    int32_t v = (int32_t)luaL_checkinteger(L, 2);
    lua_pushboolean(L, writeTargetScalar(p, addr, v));
    return 1;
}

int l_readFloat(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    uintptr_t addr = 0;
    if (!checkAddress(L, 1, p, addr)) { lua_pushnil(L); return 1; }
    float v = 0;
    if (readTargetScalar(p, addr, v)) lua_pushnumber(L, v);
    else lua_pushnil(L);
    return 1;
}

int l_writeFloat(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushboolean(L, 0); return 1; }
    uintptr_t addr = 0;
    if (!checkAddress(L, 1, p, addr)) { lua_pushboolean(L, 0); return 1; }
    float v = (float)luaL_checknumber(L, 2);
    lua_pushboolean(L, writeTargetScalar(p, addr, v));
    return 1;
}

// readBytes(address, count[, returnAsTable]) — table when the flag is true,
// otherwise the bytes as multiple return values (CE semantics). nil on failure.
// byteTableToString({b1,b2,...}) -> string; stringToByteTable("str") -> {bytes}.
// Pure data helpers CE scripts use for AOB/byte munging.
int l_byteTableToString(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE);
    int n = (int)lua_rawlen(L, 1);
    // luaL_Buffer lives on the Lua stack, so a non-integer element's error
    // leaks nothing.
    luaL_Buffer b;
    luaL_buffinit(L, &b);
    for (int i = 1; i <= n; ++i) {
        lua_rawgeti(L, 1, i);
        const char c = (char)(uint8_t)(luaL_checkinteger(L, -1) & 0xff);
        lua_pop(L, 1);
        luaL_addchar(&b, c);
    }
    luaL_pushresult(&b);
    return 1;
}

int l_stringToByteTable(lua_State* L) {
    size_t len = 0;
    const char* s = luaL_checklstring(L, 1, &len);
    lua_newtable(L);
    for (size_t i = 0; i < len; ++i) {
        lua_pushinteger(L, (uint8_t)s[i]);
        lua_rawseti(L, -2, (int)i + 1);
    }
    return 1;
}

// UTF-8 (Lua string) <-> UTF-16LE (CE "widestring") byte tables. Game strings are
// usually BMP, but surrogate pairs are handled so astral code points round-trip.
static void appendUtf8(std::string& out, uint32_t cp) {
    if (cp <= 0x7F) out.push_back((char)cp);
    else if (cp <= 0x7FF) {
        out.push_back((char)(0xC0 | (cp >> 6)));
        out.push_back((char)(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
        out.push_back((char)(0xE0 | (cp >> 12)));
        out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back((char)(0x80 | (cp & 0x3F)));
    } else {
        out.push_back((char)(0xF0 | (cp >> 18)));
        out.push_back((char)(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back((char)(0x80 | (cp & 0x3F)));
    }
}

int l_wideStringToByteTable(lua_State* L) {
    size_t len = 0;
    const char* s = luaL_checklstring(L, 1, &len);
    lua_newtable(L);
    int outIdx = 1;
    auto emit16 = [&](uint16_t u) {
        lua_pushinteger(L, u & 0xFF);        lua_rawseti(L, -2, outIdx++);
        lua_pushinteger(L, (u >> 8) & 0xFF); lua_rawseti(L, -2, outIdx++);
    };
    size_t i = 0;
    while (i < len) {
        uint8_t c = (uint8_t)s[i];
        uint32_t cp; int extra;
        if (c < 0x80)            { cp = c;        extra = 0; }
        else if ((c >> 5) == 0x6){ cp = c & 0x1F; extra = 1; }
        else if ((c >> 4) == 0xE){ cp = c & 0x0F; extra = 2; }
        else if ((c >> 3) == 0x1E){ cp = c & 0x07; extra = 3; }
        else                     { cp = 0xFFFD;   extra = 0; }
        ++i;
        int consumed = 0;
        for (; consumed < extra && i < len; ++consumed, ++i) {
            if (((uint8_t)s[i] & 0xC0) != 0x80) break;   // that byte starts the next character
            cp = (cp << 6) | ((uint8_t)s[i] & 0x3F);
        }
        // A cut-off sequence, a surrogate or a value past U+10FFFF is not a
        // character: replace it rather than emit a fragment of one.
        if (consumed < extra || (cp >= 0xD800 && cp <= 0xDFFF) || cp > 0x10FFFF) cp = 0xFFFD;
        if (cp <= 0xFFFF) emit16((uint16_t)cp);
        else { cp -= 0x10000; emit16((uint16_t)(0xD800 + (cp >> 10)));
                               emit16((uint16_t)(0xDC00 + (cp & 0x3FF))); }
    }
    return 1;
}

int l_byteTableToWideString(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE);
    int start = (int)luaL_optinteger(L, 2, 1);
    int n = (int)lua_rawlen(L, 1);
    checkByteTable(L, 1, start, n, false);   // before the containers below exist
    std::vector<uint8_t> bytes;
    for (int i = start; i <= n; ++i) {
        lua_rawgeti(L, 1, i);
        bytes.push_back((uint8_t)(lua_tointeger(L, -1) & 0xFF));
        lua_pop(L, 1);
    }
    std::string out;
    size_t count = bytes.size() / 2;
    for (size_t i = 0; i < count; ++i) {
        uint16_t u = (uint16_t)(bytes[2 * i] | (bytes[2 * i + 1] << 8));
        uint32_t cp = u;
        if (u >= 0xD800 && u <= 0xDBFF && i + 1 < count) {   // high surrogate
            uint16_t lo = (uint16_t)(bytes[2 * (i + 1)] | (bytes[2 * (i + 1) + 1] << 8));
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                cp = 0x10000 + (((u - 0xD800) << 10) | (lo - 0xDC00));
                ++i;
            }
        }
        appendUtf8(out, cp);
    }
    lua_pushlstring(L, out.data(), out.size());
    return 1;
}

// signExtend(value, mostSignificantBit): treat bit `msb` as the sign bit and extend.
int l_signExtend(lua_State* L) {
    int64_t v = (int64_t)luaL_checkinteger(L, 1);
    int msb = (int)luaL_checkinteger(L, 2);
    if (msb < 0 || msb >= 63) { lua_pushinteger(L, v); return 1; }   // already full width
    uint64_t mask = (1ULL << (msb + 1)) - 1;
    uint64_t uv = (uint64_t)v & mask;
    if (uv & (1ULL << msb)) uv |= ~mask;   // sign bit set -> fill the high bits
    lua_pushinteger(L, (lua_Integer)(int64_t)uv);
    return 1;
}

int l_getCPUCount(lua_State* L) {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    lua_pushinteger(L, n > 0 ? (lua_Integer)n : 1);
    return 1;
}

// N-wide integer -> little-endian byte table (CE's wordToByteTable etc.).
static int pushLeBytes(lua_State* L, uint64_t v, int nbytes) {
    lua_newtable(L);
    for (int i = 0; i < nbytes; ++i) {
        lua_pushinteger(L, (uint8_t)((v >> (8 * i)) & 0xff));
        lua_rawseti(L, -2, i + 1);
    }
    return 1;
}
int l_wordToByteTable(lua_State* L)  { return pushLeBytes(L, (uint64_t)luaL_checkinteger(L, 1), 2); }
int l_dwordToByteTable(lua_State* L) { return pushLeBytes(L, (uint64_t)luaL_checkinteger(L, 1), 4); }
int l_qwordToByteTable(lua_State* L) { return pushLeBytes(L, (uint64_t)luaL_checkinteger(L, 1), 8); }

// byteTableToDwordTable({bytes}) -> {dwords} (little-endian, 4 bytes each).
int l_byteTableToDwordTable(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE);
    int n = (int)lua_rawlen(L, 1);
    lua_newtable(L);
    int out = 0;
    for (int i = 0; i + 4 <= n; i += 4) {
        uint32_t v = 0;
        for (int b = 0; b < 4; ++b) {
            lua_rawgeti(L, 1, i + b + 1);
            v |= (uint32_t)((uint8_t)(luaL_checkinteger(L, -1) & 0xff)) << (8 * b);
            lua_pop(L, 1);
        }
        lua_pushinteger(L, (lua_Integer)v);
        lua_rawseti(L, -2, ++out);
    }
    return 1;
}

// Path string helpers (CE's extractFileName/Path/Ext). Pure string ops.
// Map a CE code-page number to an iconv charset name. 65001 = UTF-8; 0 = the Windows
// "Ansi" default, treated as CP1252 (the usual western game encoding under Proton).
static std::string codepageToCharset(int cp) {
    if (cp == 65001) return "UTF-8";
    if (cp == 0 || cp == 1252) return "CP1252";
    return "CP" + std::to_string(cp);
}

// iconv `in` from charset `from` to `to`. Returns `in` unchanged if the pairing is
// unavailable; skips bytes that don't map so malformed game data can't throw.
static std::string iconvString(const std::string& in, const char* from, const char* to) {
    iconv_t cd = iconv_open(to, from);
    if (cd == reinterpret_cast<iconv_t>(-1)) return in;
    std::string out(in.size() * 4 + 8, '\0');
    char* inPtr = const_cast<char*>(in.data());
    size_t inLeft = in.size();
    char* outPtr = out.data();
    size_t outLeft = out.size();
    while (inLeft) {
        size_t r = iconv(cd, &inPtr, &inLeft, &outPtr, &outLeft);
        if (r != static_cast<size_t>(-1)) continue;
        if (errno == E2BIG) {
            size_t used = out.size() - outLeft;
            out.resize(out.size() * 2);
            outPtr = out.data() + used;
            outLeft = out.size() - used;
        } else {                    // EILSEQ / EINVAL: drop the offending byte
            ++inPtr; --inLeft;
        }
    }
    out.resize(out.size() - outLeft);
    iconv_close(cd);
    return out;
}

// convertToUTF8(string, codepage=1252) -> UTF-8. Decodes a code-page string (e.g. bytes
// read from a Windows/Proton game) into UTF-8. Bytes preserved via length.
int l_convertToUTF8(lua_State* L) {
    size_t len = 0; const char* p = luaL_checklstring(L, 1, &len);
    int cp = static_cast<int>(luaL_optinteger(L, 2, 1252));
    std::string out = iconvString(std::string(p, len), codepageToCharset(cp).c_str(), "UTF-8");
    lua_pushlstring(L, out.data(), out.size());
    return 1;
}
// convertFromUTF8(utf8string, codepage) -> code-page-encoded string (inverse).
int l_convertFromUTF8(lua_State* L) {
    size_t len = 0; const char* p = luaL_checklstring(L, 1, &len);
    int cp = static_cast<int>(luaL_checkinteger(L, 2));
    std::string out = iconvString(std::string(p, len), "UTF-8", codepageToCharset(cp).c_str());
    lua_pushlstring(L, out.data(), out.size());
    return 1;
}
// ansiToUTF8(string) -> UTF-8, assuming the CP1252 "Ansi" code page.
int l_ansiToUTF8(lua_State* L) {
    size_t len = 0; const char* p = luaL_checklstring(L, 1, &len);
    std::string out = iconvString(std::string(p, len), "CP1252", "UTF-8");
    lua_pushlstring(L, out.data(), out.size());
    return 1;
}

int l_extractFileName(lua_State* L) {
    std::string s = luaL_checkstring(L, 1);
    auto slash = s.find_last_of("/\\");
    lua_pushstring(L, (slash == std::string::npos ? s : s.substr(slash + 1)).c_str());
    return 1;
}
int l_extractFilePath(lua_State* L) {
    std::string s = luaL_checkstring(L, 1);
    auto slash = s.find_last_of("/\\");
    lua_pushstring(L, (slash == std::string::npos ? std::string() : s.substr(0, slash)).c_str());
    return 1;
}
int l_extractFileExt(lua_State* L) {
    std::string s = luaL_checkstring(L, 1);
    auto slash = s.find_last_of("/\\");
    auto dot = s.find_last_of('.');
    // Only count a dot that comes after the last path separator.
    if (dot == std::string::npos || (slash != std::string::npos && dot < slash))
        lua_pushstring(L, "");
    else
        lua_pushstring(L, s.substr(dot).c_str());
    return 1;
}
int l_extractFileNameWithoutExt(lua_State* L) {
    std::string s = luaL_checkstring(L, 1);
    auto slash = s.find_last_of("/\\");
    std::string name = (slash == std::string::npos) ? s : s.substr(slash + 1);
    auto dot = name.find_last_of('.');
    if (dot != std::string::npos && dot != 0)   // keep a leading-dot dotfile ("~/.bashrc") intact
        name = name.substr(0, dot);
    lua_pushstring(L, name.c_str());
    return 1;
}

// Case-sensitive glob: '*' matches any run (incl. empty), '?' matches one char.
static bool luaGlobMatch(const char* pat, const char* str) {
    const char* star = nullptr;
    const char* ss = nullptr;
    while (*str) {
        if (*pat == '?' || *pat == *str) { ++pat; ++str; }
        else if (*pat == '*') { star = pat++; ss = str; }
        else if (star) { pat = star + 1; str = ++ss; }
        else return false;
    }
    while (*pat == '*') ++pat;
    return *pat == '\0';
}

// getFileList(path[, mask[, recursive]]) -> 1-indexed table of file basenames in `path`
// matching the glob `mask` (default "*"). Read-only directory enumeration; an unreadable
// or missing path yields an empty table.
int l_getFileList(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    const char* mask = luaL_optstring(L, 2, "*");
    bool recursive = lua_toboolean(L, 3);
    lua_newtable(L);
    int idx = 1;
    namespace fs = std::filesystem;
    std::error_code ec;
    auto emit = [&](const fs::directory_entry& e) {
        if (!e.is_regular_file(ec)) return;
        std::string name = e.path().filename().string();
        if (luaGlobMatch(mask, name.c_str())) {
            lua_pushstring(L, name.c_str());
            lua_rawseti(L, -2, idx++);
        }
    };
    if (recursive) {
        for (fs::recursive_directory_iterator it(path, fs::directory_options::skip_permission_denied, ec), end;
             !ec && it != end; it.increment(ec))
            emit(*it);
    } else {
        for (fs::directory_iterator it(path, fs::directory_options::skip_permission_denied, ec), end;
             !ec && it != end; it.increment(ec))
            emit(*it);
    }
    return 1;
}
int l_getCEVersion(lua_State* L) {
    // cecore reports a CE-compatible version float so scripts that gate on it run.
    lua_pushnumber(L, 7.5);
    return 1;
}

int l_readBytes(lua_State* L) {
    auto* p = getProc(L);
    uintptr_t addr = 0;
    if (!checkAddress(L, 1, p, addr)) { lua_pushnil(L); return 1; }
    lua_Integer requested = luaL_checkinteger(L, 2);
    // Cap the count so an accidental huge value (readBytes(addr, 1e9)) can't OOM
    // the process on the buf allocation below. 16 MB is far above any real read.
    luaL_argcheck(L, requested >= 0 && requested <= (1 << 24), 2, "count must be 0..16MB");
    int count = static_cast<int>(requested);
    bool asTable = lua_toboolean(L, 3);
    // Multi-value return pushes `count` values; guard the Lua stack so a large
    // count raises a clean error instead of overflowing (use the table form).
    // Checked before the buffer exists, and the buffer is Lua-owned, so a
    // raise here or below cannot leak it.
    if (!asTable) luaL_checkstack(L, count + 2, "readBytes: too many values, pass returnAsTable=true");
    auto* buf = static_cast<uint8_t*>(lua_newuserdata(L, count ? count : 1));
    if (!p || !readExact(p, addr, buf, count)) { lua_pushnil(L); return 1; }
    if (asTable) {
        lua_createtable(L, count, 0);
        for (int i = 0; i < count; ++i) {
            lua_pushinteger(L, buf[i]);
            lua_rawseti(L, -2, i + 1);
        }
        return 1;
    }
    for (int i = 0; i < count; ++i) lua_pushinteger(L, buf[i]);
    return count;   // the values above the buffer
}

// readRegionToFile(fileName, address, size) -> bytes written, or nil (CE-compat:
// dump a memory region to a file).
int l_readRegionToFile(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 2);
    size_t size = (size_t)luaL_checkinteger(L, 3);
    luaL_argcheck(L, size <= (1u << 28), 3, "size too large");
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    std::vector<uint8_t> buf(size);
    auto r = p->read(addr, buf.data(), size);
    size_t n = (r && *r > 0) ? *r : 0;
    if (n == 0) { lua_pushnil(L); return 1; }
    std::ofstream f(path, std::ios::binary);
    if (!f) { lua_pushnil(L); return 1; }
    f.write(reinterpret_cast<const char*>(buf.data()), (std::streamsize)n);
    lua_pushinteger(L, (lua_Integer)n);
    return 1;
}

// writeRegionFromFile(fileName, address) -> bytes written, or nil (CE-compat:
// load a previously-dumped region back into memory).
int l_writeRegionFromFile(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 2);
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    // A regular file of at most 256 MiB (a device has no real size).
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec)) { lua_pushnil(L); return 1; }
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) { lua_pushnil(L); return 1; }
    const std::streamoff end = f.tellg();
    if (end < 0 || end > (std::streamoff(1) << 28)) { lua_pushnil(L); return 1; }
    size_t size = (size_t)end;
    f.seekg(0);
    std::vector<uint8_t> buf(size);
    if (size && !f.read(reinterpret_cast<char*>(buf.data()), (std::streamsize)size)) {
        lua_pushnil(L); return 1;
    }
    auto w = p->write(addr, buf.data(), size);
    size_t n = (w && *w > 0) ? *w : 0;
    if (n == 0) { lua_pushnil(L); return 1; }
    lua_pushinteger(L, (lua_Integer)n);
    return 1;
}

// getModuleAddress(name) -> base address of the named module, or nil.
int l_getModuleAddress(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    for (auto& m : p->modules())
        if (m.name == name || m.path == name || m.path.find(name) != std::string::npos) {
            lua_pushinteger(L, (lua_Integer)m.base);
            return 1;
        }
    lua_pushnil(L);
    return 1;
}

// compareMemory(address1, address2, size) -> true if the two regions are equal.
int l_compareMemory(lua_State* L) {
    uintptr_t a1 = (uintptr_t)luaL_checkinteger(L, 1);
    uintptr_t a2 = (uintptr_t)luaL_checkinteger(L, 2);
    size_t size = (size_t)luaL_checkinteger(L, 3);
    luaL_argcheck(L, size <= (1u << 24), 3, "size too large");
    auto* p = getProc(L);
    if (!p) { lua_pushboolean(L, 0); return 1; }
    std::vector<uint8_t> b1(size), b2(size);
    auto r1 = p->read(a1, b1.data(), size);
    auto r2 = p->read(a2, b2.data(), size);
    bool equal = r1 && r2 && *r1 == size && *r2 == size &&
                 std::memcmp(b1.data(), b2.data(), size) == 0;
    lua_pushboolean(L, equal ? 1 : 0);
    return 1;
}

// floatToByteTable(value) -> {b1,b2,b3,b4} (little-endian IEEE-754).
int l_floatToByteTable(lua_State* L) {
    float f = (float)luaL_checknumber(L, 1);
    uint8_t bytes[4];
    std::memcpy(bytes, &f, 4);
    lua_newtable(L);
    for (int i = 0; i < 4; ++i) { lua_pushinteger(L, bytes[i]); lua_rawseti(L, -2, i + 1); }
    return 1;
}
int l_doubleToByteTable(lua_State* L) {
    double d = luaL_checknumber(L, 1);
    uint8_t b[8]; std::memcpy(b, &d, 8);
    lua_newtable(L);
    for (int i = 0; i < 8; ++i) { lua_pushinteger(L, b[i]); lua_rawseti(L, -2, i + 1); }
    return 1;
}
// Read the first n bytes of a Lua array into `out` (missing entries pad to 0).
static void luaTableToBytes(lua_State* L, int idx, uint8_t* out, int n) {
    for (int i = 0; i < n; ++i) {
        lua_rawgeti(L, idx, i + 1);
        out[i] = (uint8_t)lua_tointeger(L, -1);
        lua_pop(L, 1);
    }
}
// byteTableTo{Float,Double,Word,Dword,Qword}(t) -> value (little-endian).
int l_byteTableToFloat(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE); uint8_t b[4]; luaTableToBytes(L, 1, b, 4);
    float f; std::memcpy(&f, b, 4); lua_pushnumber(L, f); return 1;
}
int l_byteTableToDouble(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE); uint8_t b[8]; luaTableToBytes(L, 1, b, 8);
    double d; std::memcpy(&d, b, 8); lua_pushnumber(L, d); return 1;
}
int l_byteTableToWord(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE); uint8_t b[2]; luaTableToBytes(L, 1, b, 2);
    uint16_t v; std::memcpy(&v, b, 2); lua_pushinteger(L, v); return 1;
}
int l_byteTableToDword(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE); uint8_t b[4]; luaTableToBytes(L, 1, b, 4);
    uint32_t v; std::memcpy(&v, b, 4); lua_pushinteger(L, v); return 1;
}
int l_byteTableToQword(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE); uint8_t b[8]; luaTableToBytes(L, 1, b, 8);
    uint64_t v; std::memcpy(&v, b, 8); lua_pushinteger(L, (lua_Integer)v); return 1;
}

// ── Local memory read/write functions ──
//
// SECURITY (by design): the *Local family reinterpret_casts a script-supplied
// integer to a pointer and reads/writes cecore's OWN address space with no
// bounds check. This is intentional CE-compatible API, but under an untrusted-
// script threat model it is unrestricted host-memory access (full compromise of
// the cecore process, and via root the host). Loading a Lua script therefore
// equals granting native code execution as the cecore user; treat scripts as
// trusted. Element values are range-checked where applicable, but the raw
// destination address cannot be validated without changing the documented API.
// TODO(security): gate the *Local family behind an explicit opt-in/sandbox flag
// if cecore is ever exposed to untrusted scripts.

// Copies cecore's own memory through the kernel, so a bad address is an error
// (EFAULT) instead of a crash of the whole program.
static bool copyLocal(void* destination, uintptr_t addr, size_t size) {
    if (!size) return true;
    iovec local{destination, size}, remote{reinterpret_cast<void*>(addr), size};
    return process_vm_readv(getpid(), &local, 1, &remote, 1, 0) == static_cast<ssize_t>(size);
}

template <typename T>
static std::optional<T> readLocalValue(uintptr_t addr) {
    T value{};
    if (!copyLocal(&value, addr, sizeof(T))) return std::nullopt;
    return value;
}

template <typename T>
static void writeLocalValue(uintptr_t addr, T value) {
    std::memcpy(reinterpret_cast<void*>(addr), &value, sizeof(T));
}

int l_readByteLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    auto value = readLocalValue<uint8_t>(addr);
    if (!value) { lua_pushnil(L); return 1; }
    lua_pushinteger(L, *value);
    return 1;
}

int l_readSmallIntegerLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    auto value = readLocalValue<int16_t>(addr);
    if (!value) { lua_pushnil(L); return 1; }
    lua_pushinteger(L, *value);
    return 1;
}

int l_readIntegerLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    auto value = readLocalValue<int32_t>(addr);
    if (!value) { lua_pushnil(L); return 1; }
    lua_pushinteger(L, *value);
    return 1;
}

int l_readQwordLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    auto value = readLocalValue<int64_t>(addr);
    if (!value) { lua_pushnil(L); return 1; }
    lua_pushinteger(L, *value);
    return 1;
}

int l_readPointerLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    auto value = readLocalValue<uintptr_t>(addr);
    if (!value) { lua_pushnil(L); return 1; }
    lua_pushinteger(L, (lua_Integer)*value);
    return 1;
}

int l_readFloatLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    auto value = readLocalValue<float>(addr);
    if (!value) { lua_pushnil(L); return 1; }
    lua_pushnumber(L, *value);
    return 1;
}

int l_readDoubleLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    auto value = readLocalValue<double>(addr);
    if (!value) { lua_pushnil(L); return 1; }
    lua_pushnumber(L, *value);
    return 1;
}

int l_readBytesLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    const lua_Integer requested = luaL_checkinteger(L, 2);
    // Cap the size: this walks cecore's own memory from a raw address, so an
    // accidental huge size would read far past `addr` into unmapped pages (SIGSEGV).
    luaL_argcheck(L, requested >= 0 && requested <= (1 << 24), 2, "size must be 0..16MB");
    const int size = static_cast<int>(requested);

    std::vector<uint8_t> bytes(static_cast<size_t>(size));
    if (!copyLocal(bytes.data(), addr, bytes.size())) { lua_pushnil(L); return 1; }
    lua_createtable(L, size, 0);
    for (int i = 0; i < size; ++i) {
        lua_pushinteger(L, bytes[static_cast<size_t>(i)]);
        lua_rawseti(L, -2, i + 1);
    }
    return 1;
}

int l_readStringLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    int maxLen = luaL_optinteger(L, 2, 256);
    luaL_argcheck(L, maxLen >= 0, 2, "max length must be non-negative");
    // Cap the scan so a huge maxLen cannot walk far past the string into
    // unmapped memory (strnlen faults) or stall.
    constexpr int kMaxReadString = 1 << 24;  // 16 MB
    if (maxLen > kMaxReadString) maxLen = kMaxReadString;

    // Read in pages, so a string near the end of a mapping is still found.
    std::string text;
    char chunk[4096];
    while ((int)text.size() < maxLen) {
        const uintptr_t at = addr + text.size();
        const size_t want = std::min<size_t>(maxLen - text.size(), sizeof chunk - at % sizeof chunk);
        if (!copyLocal(chunk, at, want)) {
            if (text.empty()) { lua_pushnil(L); return 1; }
            break;
        }
        const size_t length = strnlen(chunk, want);
        text.append(chunk, length);
        if (length < want) break;
    }
    lua_pushlstring(L, text.data(), text.size());
    return 1;
}

int l_writeByteLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    writeLocalValue<uint8_t>(addr, (uint8_t)luaL_checkinteger(L, 2));
    return 0;
}

int l_writeSmallIntegerLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    writeLocalValue<int16_t>(addr, (int16_t)luaL_checkinteger(L, 2));
    return 0;
}

int l_writeIntegerLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    writeLocalValue<int32_t>(addr, (int32_t)luaL_checkinteger(L, 2));
    return 0;
}

int l_writeQwordLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    writeLocalValue<int64_t>(addr, (int64_t)luaL_checkinteger(L, 2));
    return 0;
}

int l_writePointerLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    writeLocalValue<uintptr_t>(addr, (uintptr_t)luaL_checkinteger(L, 2));
    return 0;
}

int l_writeFloatLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    writeLocalValue<float>(addr, (float)luaL_checknumber(L, 2));
    return 0;
}

int l_writeDoubleLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    writeLocalValue<double>(addr, luaL_checknumber(L, 2));
    return 0;
}

int l_writeBytesLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    luaL_checktype(L, 2, LUA_TTABLE);
    int n = (int)lua_rawlen(L, 2);
    auto* bytes = reinterpret_cast<uint8_t*>(addr);
    for (int i = 1; i <= n; ++i) {
        lua_rawgeti(L, 2, i);
        lua_Integer value = luaL_checkinteger(L, -1);
        lua_pop(L, 1);
        luaL_argcheck(L, value >= 0 && value <= 255, 2, "byte values must be 0..255");
        bytes[i - 1] = (uint8_t)value;
    }
    return 0;
}

int l_writeStringLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    size_t len = 0;
    const char* str = luaL_checklstring(L, 2, &len);
    std::memcpy(reinterpret_cast<void*>(addr), str, len);
    reinterpret_cast<char*>(addr)[len] = '\0';
    return 0;
}
} // namespace ce::lua_detail
