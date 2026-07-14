/// Extended Lua API bindings — CE-compatible function set.
#include <charconv>
#include <csignal>
#include "scripting/lua_engine.hpp"
#include "core/ct_file.hpp"
#include "core/trainer.hpp"
#include "core/address_list.hpp"
#include "analysis/managed_runtime.hpp"
#include "analysis/mono_dissector.hpp"
#include "analysis/structure_tools.hpp"
#include "analysis/code_analysis.hpp"
#include "scripting/lua_memrec.hpp"
#include "scanner/memory_scanner.hpp"
#include "scanner/pointer_scanner.hpp"
#include "core/autoasm.hpp"
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
#include "platform/linux/ceserver_client.hpp"
#include "platform/linux/ceserver_process.hpp"

extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}

#include <cstring>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <linux/input.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <filesystem>
#include <limits>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>
#include <algorithm>
#include <stdexcept>
#include <unordered_map>
#include <cctype>

namespace ce {

// Helper: get process handle from registry
// Locale-independent double parse (atof/strtod honour Qt's comma-decimal C
// locale); accept both ',' and '.'.
static double parseLocaleDouble(const char* s) {
    if (!s) return 0.0;
    std::string t(s);
    for (auto& c : t) if (c == ',') c = '.';
    double v = 0;
    auto [ptr, ec] = std::from_chars(t.data(), t.data() + t.size(), v);
    (void)ptr;
    return ec == std::errc() ? v : 0.0;
}

static ProcessHandle* getProc(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_proc");
    auto* p = (ProcessHandle*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    return p;
}

static SymbolResolver* getResolver(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_resolver");
    auto* r = (SymbolResolver*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    return r;
}

// ── Memory read functions (all widths) ──

static int l_readByte(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    uint8_t v = 0;
    if (p->read(addr, &v, 1)) lua_pushinteger(L, v);
    else lua_pushnil(L);
    return 1;
}

static int l_readSmallInteger(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    int16_t v = 0;
    if (p->read(addr, &v, 2)) lua_pushinteger(L, v);
    else lua_pushnil(L);
    return 1;
}

static int l_readQword(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    int64_t v = 0;
    if (p->read(addr, &v, 8)) lua_pushinteger(L, v);
    else lua_pushnil(L);
    return 1;
}

static int l_readPointer(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    // Use the TARGET's pointer width: reading 8 bytes at a 4-byte pointer on a
    // 32-bit target leaves garbage in the upper dword. v is zero-initialized, so
    // a 4-byte little-endian read zero-extends correctly.
    uintptr_t v = 0;
    size_t ptrSize = p->is64bit() ? 8 : 4;
    if (p->read(addr, &v, ptrSize)) lua_pushinteger(L, (lua_Integer)v);
    else lua_pushnil(L);
    return 1;
}

static int l_readDouble(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    double v = 0;
    if (p->read(addr, &v, 8)) lua_pushnumber(L, v);
    else lua_pushnil(L);
    return 1;
}

static int l_readString(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    int maxLen = luaL_optinteger(L, 2, 256);
    luaL_argcheck(L, maxLen >= 0, 2, "max length must be non-negative");
    // Allocate under try/catch: a large maxLen can throw bad_alloc, which must
    // not escape this C function into C-compiled Lua frames (UB).
    try {
        std::vector<char> buf(maxLen + 1, 0);
        auto r = p->read(addr, buf.data(), maxLen);
        if (r) {
            buf[*r] = 0;
            lua_pushstring(L, buf.data());
        } else lua_pushnil(L);
    } catch (const std::exception& ex) {
        return luaL_error(L, "%s", ex.what());
    }
    return 1;
}

// ── Memory write functions ──

static int l_writeByte(lua_State* L) {
    auto* p = getProc(L);
    if (!p) return 0;
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    uint8_t v = (uint8_t)luaL_checkinteger(L, 2);
    p->write(addr, &v, 1);
    return 0;
}

static int l_writeSmallInteger(lua_State* L) {
    auto* p = getProc(L);
    if (!p) return 0;
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    int16_t v = (int16_t)luaL_checkinteger(L, 2);
    p->write(addr, &v, 2);
    return 0;
}

static int l_writeQword(lua_State* L) {
    auto* p = getProc(L);
    if (!p) return 0;
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    int64_t v = luaL_checkinteger(L, 2);
    p->write(addr, &v, 8);
    return 0;
}

static int l_writeDouble(lua_State* L) {
    auto* p = getProc(L);
    if (!p) return 0;
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    double v = luaL_checknumber(L, 2);
    p->write(addr, &v, 8);
    return 0;
}

static int l_writeString(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushboolean(L, 0); return 1; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    const char* s = luaL_checkstring(L, 2);
    // Return success like CE (and the other write* bindings).
    lua_pushboolean(L, (bool)p->write(addr, s, strlen(s) + 1));
    return 1;
}

static int l_writeBytes(lua_State* L) {
    auto* p = getProc(L);
    if (!p) return 0;
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    // CE accepts writeBytes(addr, {b1,b2,...}) or writeBytes(addr, b1, b2, ...).
    std::vector<uint8_t> bytes;
    if (lua_istable(L, 2)) {
        int n = (int)lua_rawlen(L, 2);
        bytes.resize(n);
        for (int i = 1; i <= n; ++i) {
            lua_rawgeti(L, 2, i);
            lua_Integer value = luaL_checkinteger(L, -1);
            lua_pop(L, 1);
            luaL_argcheck(L, value >= 0 && value <= 255, 2, "byte values must be 0..255");
            bytes[i-1] = (uint8_t)value;
        }
    } else {
        int top = lua_gettop(L);
        for (int i = 2; i <= top; ++i) {
            lua_Integer value = luaL_checkinteger(L, i);
            luaL_argcheck(L, value >= 0 && value <= 255, i, "byte values must be 0..255");
            bytes.push_back((uint8_t)value);
        }
    }
    p->write(addr, bytes.data(), bytes.size());
    return 0;
}

// ── The four workhorse CE reads/writes for the opened process ──
// readInteger(address[, signed])  — 4-byte int, signed by default.
static int l_readInteger(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    bool isSigned = lua_isnoneornil(L, 2) ? true : lua_toboolean(L, 2);
    int32_t v = 0;
    if (p->read(addr, &v, 4)) {
        if (isSigned) lua_pushinteger(L, v);
        else          lua_pushinteger(L, (lua_Integer)(uint32_t)v);
    } else lua_pushnil(L);
    return 1;
}

static int l_writeInteger(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushboolean(L, 0); return 1; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    int32_t v = (int32_t)luaL_checkinteger(L, 2);
    lua_pushboolean(L, (bool)p->write(addr, &v, 4));
    return 1;
}

static int l_readFloat(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    float v = 0;
    if (p->read(addr, &v, 4)) lua_pushnumber(L, v);
    else lua_pushnil(L);
    return 1;
}

static int l_writeFloat(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushboolean(L, 0); return 1; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    float v = (float)luaL_checknumber(L, 2);
    lua_pushboolean(L, (bool)p->write(addr, &v, 4));
    return 1;
}

// readBytes(address, count[, returnAsTable]) — table when the flag is true,
// otherwise the bytes as multiple return values (CE semantics). nil on failure.
// byteTableToString({b1,b2,...}) -> string; stringToByteTable("str") -> {bytes}.
// Pure data helpers CE scripts use for AOB/byte munging.
static int l_byteTableToString(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE);
    int n = (int)lua_rawlen(L, 1);
    std::string s;
    s.reserve(n);
    for (int i = 1; i <= n; ++i) {
        lua_rawgeti(L, 1, i);
        s.push_back((char)(uint8_t)(luaL_checkinteger(L, -1) & 0xff));
        lua_pop(L, 1);
    }
    lua_pushlstring(L, s.data(), s.size());
    return 1;
}

static int l_stringToByteTable(lua_State* L) {
    size_t len = 0;
    const char* s = luaL_checklstring(L, 1, &len);
    lua_newtable(L);
    for (size_t i = 0; i < len; ++i) {
        lua_pushinteger(L, (uint8_t)s[i]);
        lua_rawseti(L, -2, (int)i + 1);
    }
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
static int l_wordToByteTable(lua_State* L)  { return pushLeBytes(L, (uint64_t)luaL_checkinteger(L, 1), 2); }
static int l_dwordToByteTable(lua_State* L) { return pushLeBytes(L, (uint64_t)luaL_checkinteger(L, 1), 4); }
static int l_qwordToByteTable(lua_State* L) { return pushLeBytes(L, (uint64_t)luaL_checkinteger(L, 1), 8); }

// byteTableToDwordTable({bytes}) -> {dwords} (little-endian, 4 bytes each).
static int l_byteTableToDwordTable(lua_State* L) {
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
static int l_extractFileName(lua_State* L) {
    std::string s = luaL_checkstring(L, 1);
    auto slash = s.find_last_of("/\\");
    lua_pushstring(L, (slash == std::string::npos ? s : s.substr(slash + 1)).c_str());
    return 1;
}
static int l_extractFilePath(lua_State* L) {
    std::string s = luaL_checkstring(L, 1);
    auto slash = s.find_last_of("/\\");
    lua_pushstring(L, (slash == std::string::npos ? std::string() : s.substr(0, slash)).c_str());
    return 1;
}
static int l_extractFileExt(lua_State* L) {
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
static int l_getCEVersion(lua_State* L) {
    // cecore reports a CE-compatible version float so scripts that gate on it run.
    lua_pushnumber(L, 7.5);
    return 1;
}

static int l_readBytes(lua_State* L) {
    auto* p = getProc(L);
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    int count = (int)luaL_checkinteger(L, 2);
    // Cap the count so an accidental huge value (readBytes(addr, 1e9)) can't OOM
    // the process on the buf allocation below. 16 MB is far above any real read.
    luaL_argcheck(L, count >= 0 && count <= (1 << 24), 2, "count must be 0..16MB");
    bool asTable = lua_toboolean(L, 3);
    std::vector<uint8_t> buf(count);
    if (!p || !p->read(addr, buf.data(), count)) { lua_pushnil(L); return 1; }
    if (asTable) {
        lua_newtable(L);
        for (int i = 0; i < count; ++i) {
            lua_pushinteger(L, buf[i]);
            lua_rawseti(L, -2, i + 1);
        }
        return 1;
    }
    // Multi-value return pushes `count` values; guard the Lua stack so a large
    // count raises a clean error instead of overflowing (use the table form).
    luaL_checkstack(L, count + 1, "readBytes: too many values, pass returnAsTable=true");
    for (int i = 0; i < count; ++i) lua_pushinteger(L, buf[i]);
    return count;
}

// readRegionToFile(fileName, address, size) -> bytes written, or nil (CE-compat:
// dump a memory region to a file).
static int l_readRegionToFile(lua_State* L) {
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
static int l_writeRegionFromFile(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 2);
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) { lua_pushnil(L); return 1; }
    size_t size = (size_t)f.tellg();
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
static int l_getModuleAddress(lua_State* L) {
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
static int l_compareMemory(lua_State* L) {
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
static int l_floatToByteTable(lua_State* L) {
    float f = (float)luaL_checknumber(L, 1);
    uint8_t bytes[4];
    std::memcpy(bytes, &f, 4);
    lua_newtable(L);
    for (int i = 0; i < 4; ++i) { lua_pushinteger(L, bytes[i]); lua_rawseti(L, -2, i + 1); }
    return 1;
}
static int l_doubleToByteTable(lua_State* L) {
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
static int l_byteTableToFloat(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE); uint8_t b[4]; luaTableToBytes(L, 1, b, 4);
    float f; std::memcpy(&f, b, 4); lua_pushnumber(L, f); return 1;
}
static int l_byteTableToDouble(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE); uint8_t b[8]; luaTableToBytes(L, 1, b, 8);
    double d; std::memcpy(&d, b, 8); lua_pushnumber(L, d); return 1;
}
static int l_byteTableToWord(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE); uint8_t b[2]; luaTableToBytes(L, 1, b, 2);
    uint16_t v; std::memcpy(&v, b, 2); lua_pushinteger(L, v); return 1;
}
static int l_byteTableToDword(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE); uint8_t b[4]; luaTableToBytes(L, 1, b, 4);
    uint32_t v; std::memcpy(&v, b, 4); lua_pushinteger(L, v); return 1;
}
static int l_byteTableToQword(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE); uint8_t b[8]; luaTableToBytes(L, 1, b, 8);
    uint64_t v; std::memcpy(&v, b, 8); lua_pushinteger(L, (lua_Integer)v); return 1;
}

// ── MD5 (RFC 1321) ──
// CE trainers use stringToMD5String() for integrity/anti-tamper checksums. This
// is a self-contained implementation (no external crypto dependency); its output
// is pinned to the standard MD5 test vectors in the test suite.
static inline uint32_t md5Rotl(uint32_t x, uint32_t c) {
    return (x << c) | (x >> (32 - c));
}
static std::string md5Hex(const uint8_t* msg, size_t len) {
    static const uint32_t K[64] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    };
    static const uint32_t S[64] = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    };

    uint32_t a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;

    // Pad: original bytes, then 0x80, then zeros to 56 mod 64, then the 64-bit
    // little-endian bit length. Result is a whole number of 512-bit blocks.
    std::vector<uint8_t> data(msg, msg + len);
    const uint64_t bitLen = static_cast<uint64_t>(len) * 8;
    data.push_back(0x80);
    while (data.size() % 64 != 56) data.push_back(0x00);
    for (int i = 0; i < 8; ++i) data.push_back(static_cast<uint8_t>(bitLen >> (i * 8)));

    for (size_t off = 0; off < data.size(); off += 64) {
        uint32_t M[16];
        for (int i = 0; i < 16; ++i)
            M[i] = static_cast<uint32_t>(data[off + i * 4]) |
                   static_cast<uint32_t>(data[off + i * 4 + 1]) << 8 |
                   static_cast<uint32_t>(data[off + i * 4 + 2]) << 16 |
                   static_cast<uint32_t>(data[off + i * 4 + 3]) << 24;

        uint32_t A = a0, B = b0, C = c0, D = d0;
        for (int i = 0; i < 64; ++i) {
            uint32_t F;
            int g;
            if (i < 16)      { F = (B & C) | (~B & D);  g = i; }
            else if (i < 32) { F = (D & B) | (~D & C);  g = (5 * i + 1) & 15; }
            else if (i < 48) { F = B ^ C ^ D;           g = (3 * i + 5) & 15; }
            else             { F = C ^ (B | ~D);        g = (7 * i) & 15; }
            F += A + K[i] + M[g];
            A = D;
            D = C;
            C = B;
            B += md5Rotl(F, S[i]);
        }
        a0 += A; b0 += B; c0 += C; d0 += D;
    }

    const uint32_t words[4] = { a0, b0, c0, d0 };
    static const char* hex = "0123456789abcdef";
    std::string out(32, '0');
    for (int w = 0; w < 4; ++w)
        for (int j = 0; j < 4; ++j) {
            const uint8_t byte = static_cast<uint8_t>(words[w] >> (j * 8));
            out[(w * 4 + j) * 2]     = hex[byte >> 4];
            out[(w * 4 + j) * 2 + 1] = hex[byte & 0xf];
        }
    return out;
}
// stringToMD5String(str) -> lowercase 32-char hex digest (CE-compatible).
static int l_stringToMD5String(lua_State* L) {
    size_t len = 0;
    const char* s = luaL_checklstring(L, 1, &len);
    lua_pushstring(L, md5Hex(reinterpret_cast<const uint8_t*>(s), len).c_str());
    return 1;
}

// ── Bitwise-op compat family ──
// CE predates Lua 5.3's native &|~<<>> operators, so its scripts call bAnd/bOr/
// bXor/bNot/bShl/bShr. Provide them as 64-bit integer ops (matching modern CE and
// the vendored Lua 5.3 integer semantics). Shift counts are masked to [0,63] so a
// script-supplied count can never trigger undefined shift behaviour.
static int l_bAnd(lua_State* L) {
    lua_pushinteger(L, luaL_checkinteger(L, 1) & luaL_checkinteger(L, 2));
    return 1;
}
static int l_bOr(lua_State* L) {
    lua_pushinteger(L, luaL_checkinteger(L, 1) | luaL_checkinteger(L, 2));
    return 1;
}
static int l_bXor(lua_State* L) {
    lua_pushinteger(L, luaL_checkinteger(L, 1) ^ luaL_checkinteger(L, 2));
    return 1;
}
static int l_bNot(lua_State* L) {
    lua_pushinteger(L, ~luaL_checkinteger(L, 1));
    return 1;
}
static int l_bShl(lua_State* L) {
    const uint64_t v = static_cast<uint64_t>(luaL_checkinteger(L, 1));
    const int n = static_cast<int>(luaL_checkinteger(L, 2)) & 63;
    lua_pushinteger(L, static_cast<lua_Integer>(v << n));
    return 1;
}
static int l_bShr(lua_State* L) {
    // Logical (unsigned) shift, so high bits fill with zero regardless of sign.
    const uint64_t v = static_cast<uint64_t>(luaL_checkinteger(L, 1));
    const int n = static_cast<int>(luaL_checkinteger(L, 2)) & 63;
    lua_pushinteger(L, static_cast<lua_Integer>(v >> n));
    return 1;
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

template <typename T>
static T readLocalValue(uintptr_t addr) {
    T value{};
    std::memcpy(&value, reinterpret_cast<const void*>(addr), sizeof(T));
    return value;
}

template <typename T>
static void writeLocalValue(uintptr_t addr, T value) {
    std::memcpy(reinterpret_cast<void*>(addr), &value, sizeof(T));
}

static int l_readByteLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    lua_pushinteger(L, readLocalValue<uint8_t>(addr));
    return 1;
}

static int l_readSmallIntegerLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    lua_pushinteger(L, readLocalValue<int16_t>(addr));
    return 1;
}

static int l_readIntegerLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    lua_pushinteger(L, readLocalValue<int32_t>(addr));
    return 1;
}

static int l_readQwordLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    lua_pushinteger(L, readLocalValue<int64_t>(addr));
    return 1;
}

static int l_readPointerLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    lua_pushinteger(L, (lua_Integer)readLocalValue<uintptr_t>(addr));
    return 1;
}

static int l_readFloatLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    lua_pushnumber(L, readLocalValue<float>(addr));
    return 1;
}

static int l_readDoubleLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    lua_pushnumber(L, readLocalValue<double>(addr));
    return 1;
}

static int l_readBytesLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    int size = luaL_checkinteger(L, 2);
    // Cap the size: this walks cecore's own memory from a raw address, so an
    // accidental huge size would read far past `addr` into unmapped pages (SIGSEGV).
    luaL_argcheck(L, size >= 0 && size <= (1 << 24), 2, "size must be 0..16MB");

    auto* bytes = reinterpret_cast<const uint8_t*>(addr);
    lua_newtable(L);
    for (int i = 0; i < size; ++i) {
        lua_pushinteger(L, bytes[i]);
        lua_rawseti(L, -2, i + 1);
    }
    return 1;
}

static int l_readStringLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    int maxLen = luaL_optinteger(L, 2, 256);
    luaL_argcheck(L, maxLen >= 0, 2, "max length must be non-negative");

    auto* str = reinterpret_cast<const char*>(addr);
    lua_pushlstring(L, str, strnlen(str, maxLen));
    return 1;
}

static int l_writeByteLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    writeLocalValue<uint8_t>(addr, (uint8_t)luaL_checkinteger(L, 2));
    return 0;
}

static int l_writeSmallIntegerLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    writeLocalValue<int16_t>(addr, (int16_t)luaL_checkinteger(L, 2));
    return 0;
}

static int l_writeIntegerLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    writeLocalValue<int32_t>(addr, (int32_t)luaL_checkinteger(L, 2));
    return 0;
}

static int l_writeQwordLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    writeLocalValue<int64_t>(addr, (int64_t)luaL_checkinteger(L, 2));
    return 0;
}

static int l_writePointerLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    writeLocalValue<uintptr_t>(addr, (uintptr_t)luaL_checkinteger(L, 2));
    return 0;
}

static int l_writeFloatLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    writeLocalValue<float>(addr, (float)luaL_checknumber(L, 2));
    return 0;
}

static int l_writeDoubleLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    writeLocalValue<double>(addr, luaL_checknumber(L, 2));
    return 0;
}

static int l_writeBytesLocal(lua_State* L) {
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

static int l_writeStringLocal(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    size_t len = 0;
    const char* str = luaL_checklstring(L, 2, &len);
    std::memcpy(reinterpret_cast<void*>(addr), str, len);
    reinterpret_cast<char*>(addr)[len] = '\0';
    return 0;
}

// The write*Local family stores to an ARBITRARY address inside cecore's OWN
// address space (reinterpret_cast<T*>(addr)), so an untrusted .CT could patch
// cecore's code/GOT/vtables to hijack the process (cecore is often run as root).
// Gate every write*Local behind the same out-of-band opt-in as shellExecute: an
// env var a Lua table cannot set. read*Local only leaks memory, so it stays open.
template <lua_CFunction Fn>
static int guardLocalWrite(lua_State* L) {
    if (!getenv("CECORE_LUA_ALLOW_UNSAFE"))
        return luaL_error(L,
            "write*Local blocked: it writes cecore's own memory, which an untrusted "
            ".CT could use to hijack cecore. Enable only for scripts you trust by "
            "launching with CECORE_LUA_ALLOW_UNSAFE=1 (see SECURITY.md).");
    return Fn(L);
}

// ── Process info ──

static pid_t parseProcessId(std::string_view text) {
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

static pid_t findProcessIdByName(std::string_view target) {
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

static int l_getProcessList(lua_State* L) {
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

static int l_getProcessIDFromProcessName(lua_State* L) {
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
static const ce::ModuleInfo* findModuleByName(ProcessHandle* p, const std::string& want) {
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

static int l_getModuleBase(lua_State* L) {
    auto* m = findModuleByName(getProc(L), luaL_checkstring(L, 1));
    if (m) lua_pushinteger(L, (lua_Integer)m->base);
    else   lua_pushnil(L);
    return 1;
}

// pause()/unpause(): freeze/resume the whole target (SIGSTOP/SIGCONT), like CE's
// "pause the game" toggle. Returns true on success.
static int l_pauseSignal(lua_State* L, int sig) {
    auto* p = getProc(L);
    if (!p || p->pid() <= 0) { lua_pushboolean(L, 0); return 1; }
    lua_pushboolean(L, kill(p->pid(), sig) == 0 ? 1 : 0);
    return 1;
}
static int l_pause(lua_State* L)   { return l_pauseSignal(L, SIGSTOP); }
static int l_unpause(lua_State* L) { return l_pauseSignal(L, SIGCONT); }

// inModule(address) -> module name containing the address, or nil.
static int l_inModule(lua_State* L) {
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
static int l_isAddress(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushboolean(L, 0); return 1; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    uint8_t b;
    lua_pushboolean(L, (bool)p->read(addr, &b, 1) ? 1 : 0);
    return 1;
}

// copyMemory(source, destination, size) -> bool. Copies within the target.
static int l_copyMemory(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushboolean(L, 0); return 1; }
    uintptr_t src = (uintptr_t)luaL_checkinteger(L, 1);
    uintptr_t dst = (uintptr_t)luaL_checkinteger(L, 2);
    size_t n = (size_t)luaL_checkinteger(L, 3);
    try {
        std::vector<uint8_t> buf(n);
        if (!p->read(src, buf.data(), n)) { lua_pushboolean(L, 0); return 1; }
        lua_pushboolean(L, (bool)p->write(dst, buf.data(), n) ? 1 : 0);
    } catch (const std::exception& ex) {
        return luaL_error(L, "%s", ex.what());
    }
    return 1;
}

// enumMemoryRegions() -> { {BaseAddress, MemorySize, Protect, State, Path}, ... }
// CE-style region list (0..N-1 not needed; scripts iterate with ipairs).
static int l_enumMemoryRegions(lua_State* L) {
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
static int l_allocateMemory(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    size_t size = (size_t)luaL_checkinteger(L, 1);
    uintptr_t base = lua_isnoneornil(L, 2) ? 0 : (uintptr_t)luaL_checkinteger(L, 2);
    auto r = p->allocate(size, MemProt::All, base);
    if (r) lua_pushinteger(L, (lua_Integer)*r);
    else   lua_pushnil(L);
    return 1;
}
static int l_deAlloc(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushboolean(L, 0); return 1; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    size_t size = lua_isnoneornil(L, 2) ? 0 : (size_t)luaL_checkinteger(L, 2);
    lua_pushboolean(L, (bool)p->free(addr, size) ? 1 : 0);
    return 1;
}

static int l_getModuleSize(lua_State* L) {
    auto* m = findModuleByName(getProc(L), luaL_checkstring(L, 1));
    if (m) lua_pushinteger(L, (lua_Integer)m->size);
    else   lua_pushnil(L);
    return 1;
}

static int l_getModuleList(lua_State* L) {
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

// ── Symbol resolution ──

static int l_getNameFromAddress(lua_State* L) {
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

static int l_getAddressFromName(lua_State* L) {
    auto* r = getResolver(L);
    if (!r) { lua_pushnil(L); return 1; }
    const char* name = luaL_checkstring(L, 1);
    auto addr = r->lookup(name);
    if (addr) lua_pushinteger(L, (lua_Integer)addr);
    else lua_pushnil(L);
    return 1;
}

// ── Disassembly / Assembly ──

// speedhack_setSpeed(factor) — write the speed multiplier to the shared-memory
// channel the injected speedhack plugin (plugins/speedhack.c) reads. Matches the
// GUI "Speedhack…" dialog: a double at /dev/shm/ce_speedhack, opened O_NOFOLLOW,
// mode 0600, and confirmed to be a regular file before mapping. The target must
// have been started with LD_PRELOAD=libspeedhack.so for this to take effect.
static int l_speedhack_setSpeed(lua_State* L) {
    double speed = luaL_checknumber(L, 1);
    if (!(speed >= 0.01 && speed <= 1000.0)) { lua_pushboolean(L, 0); return 1; }
    int fd = ::open("/dev/shm/ce_speedhack", O_CREAT | O_RDWR | O_NOFOLLOW, 0600);
    if (fd < 0) { lua_pushboolean(L, 0); return 1; }
    bool ok = false;
    struct stat st{};
    if (::fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && ::ftruncate(fd, sizeof(double)) == 0) {
        void* mem = ::mmap(nullptr, sizeof(double), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (mem != MAP_FAILED) { *reinterpret_cast<double*>(mem) = speed; ::munmap(mem, sizeof(double)); ok = true; }
    }
    ::close(fd);
    lua_pushboolean(L, ok);
    return 1;
}

// injectLibrary(soPath) — load a shared library into the attached process via
// ptrace + remote dlopen (this is how CE injects e.g. the speedhack lib into a
// running game, instead of relaunching it with LD_PRELOAD). Returns the remote
// dlopen handle on success, or (nil, errorString).
static int l_injectLibrary(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); lua_pushstring(L, "no process attached"); return 2; }
    const char* path = luaL_checkstring(L, 1);
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_resolver");
    auto* resolver = static_cast<ce::SymbolResolver*>(lua_touserdata(L, -1));
    lua_pop(L, 1);
    if (!resolver) { lua_pushnil(L); lua_pushstring(L, "no symbol resolver"); return 2; }
    auto r = ce::os::injectLibrary(*p, *resolver, path);
    if (!r) { lua_pushnil(L); lua_pushstring(L, r.error().c_str()); return 2; }
    lua_pushinteger(L, static_cast<lua_Integer>(*r));
    return 1;
}

static int l_disassemble(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    uint8_t buf[16];
    auto r = p->read(addr, buf, sizeof(buf));
    if (!r) { lua_pushnil(L); return 1; }

    Disassembler dis(Arch::X86_64);
    auto insns = dis.disassemble(addr, {buf, *r}, 1);
    if (insns.empty()) { lua_pushnil(L); return 1; }

    lua_pushstring(L, (insns[0].mnemonic + " " + insns[0].operands).c_str());
    lua_pushinteger(L, insns[0].size);
    lua_pushinteger(L, (lua_Integer)insns[0].ripTarget);
    return 3; // returns instruction_text, size, ripTarget (0 if not RIP-relative)
}

// getInstructionSize(address) -> byte length of the instruction at address.
static int l_getInstructionSize(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    uint8_t buf[16];
    auto r = p->read(addr, buf, sizeof(buf));
    if (!r) { lua_pushnil(L); return 1; }
    Disassembler dis(Arch::X86_64);
    auto insns = dis.disassemble(addr, {buf, *r}, 1);
    if (insns.empty()) { lua_pushnil(L); return 1; }
    lua_pushinteger(L, insns[0].size);
    return 1;
}
// nopInstruction(address) -> table of the instruction's original bytes (for undo),
// or nil. Overwrites the instruction at `address` with length-preserving NOPs
// (CE's "replace with code that does nothing"). Restore by writeBytes(address, t).
static int l_nopInstruction(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    auto orig = ce::nopInstruction(*p, addr);
    if (orig.empty()) { lua_pushnil(L); return 1; }
    lua_newtable(L);
    for (size_t i = 0; i < orig.size(); ++i) {
        lua_pushinteger(L, orig[i]);
        lua_rawseti(L, -2, static_cast<int>(i) + 1);
    }
    return 1;
}
// getPreviousOpcode(address) -> start of the instruction preceding `address`.
// x86 is variable-length, so this decodes a stream forward from ~20 bytes back and
// re-syncs: the instruction stream naturally realigns, and we return the last
// instruction that starts before `address` (CE uses the same heuristic).
static int l_getPreviousOpcode(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    // Back-disassembly is ambiguous on x86. Find the LARGEST length L (max x86
    // instruction is 15 bytes) such that a single instruction decoded at addr-L
    // is exactly L bytes — i.e. it ends precisely at addr. That is the preceding
    // instruction. Read only the candidate's own bytes so a page-aligned region
    // start doesn't make us read unmapped memory (the old fixed 20-byte lookback
    // failed there and fell back to addr-1, mis-reporting a multi-byte previous
    // instruction as ending one byte before addr).
    Disassembler dis(Arch::X86_64);
    uintptr_t prev = dis.previousInstruction(addr, [&](uintptr_t a, uint8_t* buf, size_t n) {
        auto r = p->read(a, buf, n);
        return r && *r >= n;
    });
    lua_pushinteger(L, (lua_Integer)prev);
    return 1;
}

static int l_assemble(lua_State* L) {
    const char* code = luaL_checkstring(L, 1);
    uintptr_t addr = (uintptr_t)luaL_optinteger(L, 2, 0);

    Assembler asm64(AsmArch::X86_64);
    auto result = asm64.assemble(code, addr);
    if (!result) {
        lua_pushnil(L);
        lua_pushstring(L, result.error().c_str());
        return 2;
    }

    lua_newtable(L);
    for (size_t i = 0; i < result->size(); ++i) {
        lua_pushinteger(L, (*result)[i]);
        lua_rawseti(L, -2, i + 1);
    }
    return 1;
}

static int l_autoAssemble(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushboolean(L, 0); lua_pushstring(L, "no process"); return 2; }
    const char* script = luaL_checkstring(L, 1);

    AutoAssembler aa;
    auto result = aa.execute(*p, script);
    // registersymbol'd names live on the (local) AutoAssembler; export them to the
    // Lua resolver so getAddress("name")/expressions can resolve them afterwards.
    if (result.success) {
        if (auto* r = getResolver(L))
            for (auto& [name, addr] : result.disableInfo.symbols)
                r->addUserSymbol(addr, name);
    }
    lua_pushboolean(L, result.success);
    if (!result.success)
        lua_pushstring(L, result.error.c_str());
    else
        lua_pushnil(L);
    return 2;
}

static int l_autoAssembleCheck(lua_State* L) {
    const char* script = luaL_checkstring(L, 1);

    AutoAssembler aa;
    auto result = aa.check(script);
    lua_pushboolean(L, result.success);
    if (!result.success)
        lua_pushstring(L, result.error.c_str());
    else
        lua_pushnil(L);
    return 2;
}

// ── Utility ──

static int l_showMessage(lua_State* L) {
    const char* msg = luaL_checkstring(L, 1);
    fprintf(stderr, "[CE Lua] %s\n", msg); // GUI integration would use QMessageBox
    return 0;
}

static int modalResultForButton(lua_Integer button) {
    switch (button) {
        case 2: return 2;  // cancel
        case 3: return 3;  // abort
        case 4: return 4;  // retry
        case 5: return 5;  // ignore
        case 6: return 6;  // yes
        case 7: return 7;  // no
        case 8: return 8;  // all
        case 9: return 9;  // no to all
        case 10: return 10; // yes to all
        case 11: return 11; // close
        default: return 1;  // ok
    }
}

static int l_messageDialog(lua_State* L) {
    const char* msg = luaL_checkstring(L, 1);
    int dialogType = (int)luaL_optinteger(L, 2, 0);
    (void)dialogType;

    int result = 1; // mrOK
    if (lua_gettop(L) >= 3 && lua_isinteger(L, 3))
        result = modalResultForButton(lua_tointeger(L, 3));

    fprintf(stderr, "[CE Lua] %s\n", msg);
    lua_pushinteger(L, result);
    return 1;
}

static void appendCanvasCommand(lua_State* L, const char* command) {
    lua_getfield(L, 1, "commands");
    if (!lua_istable(L, -1)) {
        lua_pop(L, 1);
        lua_newtable(L);
        lua_pushvalue(L, -1);
        lua_setfield(L, 1, "commands");
    }

    lua_Integer nextIndex = (lua_Integer)lua_rawlen(L, -1) + 1;
    lua_pushstring(L, command);
    lua_rawseti(L, -2, nextIndex);
    lua_pop(L, 1);
}

static int l_canvas_noop(lua_State* L) {
    const char* command = lua_tostring(L, lua_upvalueindex(1));
    appendCanvasCommand(L, command ? command : "draw");
    lua_pushboolean(L, 1);
    return 1;
}

static int l_canvas_getTextWidth(lua_State* L) {
    size_t len = 0;
    luaL_checklstring(L, 2, &len);
    lua_pushinteger(L, (lua_Integer)len * 8);
    return 1;
}

static int l_canvas_getTextHeight(lua_State* L) {
    lua_pushinteger(L, 16);
    return 1;
}

static int l_canvas_getPixel(lua_State* L) {
    lua_pushinteger(L, 0);
    return 1;
}

static void setCanvasMethod(lua_State* L, const char* name, lua_CFunction fn) {
    lua_pushstring(L, name);
    lua_pushcclosure(L, fn, 1);
    lua_setfield(L, -2, name);
}

static void setCanvasFunction(lua_State* L, const char* name, lua_CFunction fn) {
    lua_pushcfunction(L, fn);
    lua_setfield(L, -2, name);
}

static int l_getScreenCanvas(lua_State* L) {
    lua_newtable(L);
    lua_pushinteger(L, 1920); lua_setfield(L, -2, "Width");
    lua_pushinteger(L, 1080); lua_setfield(L, -2, "Height");

    lua_newtable(L);
    lua_setfield(L, -2, "commands");

    lua_newtable(L);
    lua_pushinteger(L, 0xffffff); lua_setfield(L, -2, "Color");
    lua_setfield(L, -2, "Pen");

    lua_newtable(L);
    lua_pushinteger(L, 0x000000); lua_setfield(L, -2, "Color");
    lua_setfield(L, -2, "Brush");

    lua_newtable(L);
    lua_pushstring(L, "Sans"); lua_setfield(L, -2, "Name");
    lua_pushinteger(L, 10); lua_setfield(L, -2, "Size");
    lua_setfield(L, -2, "Font");

    setCanvasMethod(L, "clear", l_canvas_noop);
    setCanvasMethod(L, "Clear", l_canvas_noop);
    setCanvasMethod(L, "line", l_canvas_noop);
    setCanvasMethod(L, "Line", l_canvas_noop);
    setCanvasMethod(L, "rectangle", l_canvas_noop);
    setCanvasMethod(L, "Rectangle", l_canvas_noop);
    setCanvasMethod(L, "fillRect", l_canvas_noop);
    setCanvasMethod(L, "FillRect", l_canvas_noop);
    setCanvasMethod(L, "textOut", l_canvas_noop);
    setCanvasMethod(L, "TextOut", l_canvas_noop);
    setCanvasMethod(L, "setPixel", l_canvas_noop);
    setCanvasMethod(L, "SetPixel", l_canvas_noop);
    setCanvasFunction(L, "getTextWidth", l_canvas_getTextWidth);
    setCanvasFunction(L, "GetTextWidth", l_canvas_getTextWidth);
    setCanvasFunction(L, "getTextHeight", l_canvas_getTextHeight);
    setCanvasFunction(L, "GetTextHeight", l_canvas_getTextHeight);
    setCanvasFunction(L, "getPixel", l_canvas_getPixel);
    setCanvasFunction(L, "GetPixel", l_canvas_getPixel);

    return 1;
}

static int l_sleep(lua_State* L) {
    lua_Integer ms = luaL_checkinteger(L, 1);
    if (ms < 0) ms = 0;
    struct timespec ts{ (time_t)(ms / 1000), (long)((ms % 1000) * 1000000) };
    nanosleep(&ts, nullptr);
    return 0;
}

// Milliseconds from a monotonic clock — CE scripts use this for timing/deltas.
static int l_getTickCount(lua_State* L) {
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    lua_pushinteger(L, (lua_Integer)(ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL));
    return 1;
}

static int l_outputDebugString(lua_State* L) {
    const char* s = luaL_checkstring(L, 1);
    fprintf(stderr, "%s\n", s);
    return 0;
}

static int l_getCheatEngineDir(lua_State* L) {
    char buf[1024];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len > 0) {
        buf[len] = 0;
        auto dir = std::filesystem::path(buf).parent_path().string();
        lua_pushstring(L, dir.c_str());
    } else {
        lua_pushstring(L, ".");
    }
    return 1;
}

// CE alias — tables use both names; same return value on Linux.
static int l_getApplicationDir(lua_State* L) {
    return l_getCheatEngineDir(L);
}

static int l_getTempPath(lua_State* L) {
    if (auto* env = std::getenv("TMPDIR")) lua_pushstring(L, env);
    else lua_pushstring(L, "/tmp");
    return 1;
}

static int l_getOperatingSystem(lua_State* L) {
    // CE returns 0 for Windows, 1 for macOS, 2 for Linux, 3 for Android.
    lua_pushinteger(L, 2);
    return 1;
}

static int l_cheatEngineIs64Bit(lua_State* L) {
    lua_pushboolean(L, sizeof(void*) == 8);
    return 1;
}

static int l_targetIs64Bit(lua_State* L) {
    auto* proc = getProc(L);
    lua_pushboolean(L, proc && proc->is64bit());
    return 1;
}

// Forward-declared so l_inputBox can delegate to it; the body lives later
// in the file alongside the other dialog helpers.
static int l_inputQuery(lua_State* L);

// Tables sometimes call inputBox(title, prompt, default) directly. Forward
// to inputQuery's prompt-only form so the result matches CE's behaviour.
static int l_inputBox(lua_State* L) {
    return l_inputQuery(L);
}

// ── File I/O ──

static int l_readFromFile(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    std::ifstream f(path, std::ios::binary);
    if (!f) { lua_pushnil(L); return 1; }
    // Bound the read: readFromFile("/dev/zero") never hits EOF and a huge file
    // would OOM, and the resulting bad_alloc would unwind out of this C function
    // into liblua's C frames (UB). Read in a capped loop, wrapped in try/catch.
    constexpr size_t kMax = 64u * 1024 * 1024;  // 64 MB
    try {
        std::string content;
        char buf[65536];
        while (f && content.size() < kMax) {
            f.read(buf, (std::streamsize)std::min(sizeof(buf), kMax - content.size()));
            std::streamsize got = f.gcount();
            if (got <= 0) break;
            content.append(buf, (size_t)got);
        }
        lua_pushlstring(L, content.data(), content.size());
        return 1;
    } catch (const std::exception& ex) {
        return luaL_error(L, "readFile: %s", ex.what());
    }
}

static int l_writeToFile(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    size_t len;
    const char* data = luaL_checklstring(L, 2, &len);
    std::ofstream f(path, std::ios::binary);
    if (f) { f.write(data, len); lua_pushboolean(L, 1); }
    else lua_pushboolean(L, 0);
    return 1;
}

static int l_fileExists(lua_State* L) {
    // std::error_code overload: the throwing one can raise filesystem_error out
    // of this C function into liblua (UB) on e.g. a permission-denied component.
    std::error_code ec;
    lua_pushboolean(L, std::filesystem::exists(luaL_checkstring(L, 1), ec) && !ec);
    return 1;
}

static int l_getTempDir(lua_State* L) {
    std::error_code ec;
    auto dir = std::filesystem::temp_directory_path(ec);
    lua_pushstring(L, ec ? "/tmp" : dir.c_str());
    return 1;
}

static int l_getProcessDir(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushstring(L, ""); return 1; }
    try {
        auto exe = std::filesystem::read_symlink("/proc/" + std::to_string(p->pid()) + "/exe");
        lua_pushstring(L, exe.parent_path().c_str());
    } catch (...) { lua_pushstring(L, ""); }
    return 1;
}

// ── Scanning from Lua ──

struct LuaScanData {
    MemoryScanner scanner;
    std::unique_ptr<ScanResult> result;
};

static ValueType mapLuaValueType(int raw) {
    switch (raw) {
        case 0: return ValueType::Byte;
        case 1: return ValueType::Int16;
        case 2: return ValueType::Int32;
        case 3: return ValueType::Int64;
        case 4: return ValueType::Float;
        case 5: return ValueType::Double;
        case 6: return ValueType::String;
        case 7: return ValueType::UnicodeString;
        case 8: return ValueType::ByteArray;
        case 9: return ValueType::Binary;
        case 10: return ValueType::All;
        case 11: return ValueType::Grouped;
        case 12: return ValueType::Custom;
        case 13: return ValueType::Pointer;
        default:
            return static_cast<ValueType>(raw);
    }
}

static size_t luaValueTypeSize(ValueType vt) {
    switch (vt) {
        case ValueType::Byte: return 1;
        case ValueType::Int16: return 2;
        case ValueType::Int32:
        case ValueType::Float: return 4;
        case ValueType::Int64:
        case ValueType::Pointer:
        case ValueType::Double: return 8;
        default: return 4;
    }
}

static ScanCompare mapLuaScanType(int raw, bool& customFormula) {
    customFormula = false;
    switch (raw) {
        case 0: return ScanCompare::Exact;
        case 1: return ScanCompare::Between;
        case 2: return ScanCompare::Greater;
        case 3: return ScanCompare::Less;
        case 4: return ScanCompare::Unknown;
        case 5: return ScanCompare::Increased;
        case 6: return ScanCompare::Decreased;
        case 7: return ScanCompare::Changed;
        case 8: return ScanCompare::Unchanged;
        case 9: return ScanCompare::SameAsFirst;
        case 10:
            customFormula = true;
            return ScanCompare::Exact;
        default:
            return static_cast<ScanCompare>(raw);
    }
}

static ScanConfig luaScanConfig(lua_State* L, int scanTypeIndex, int valueTypeIndex, int valueIndex) {
    int scanType = (int)luaL_checkinteger(L, scanTypeIndex);
    int valueTypeRaw = (int)luaL_checkinteger(L, valueTypeIndex);
    const char* value = luaL_checkstring(L, valueIndex);

    ScanConfig cfg;
    bool customFormula = false;
    cfg.compareType = mapLuaScanType(scanType, customFormula);
    cfg.valueType = mapLuaValueType(valueTypeRaw);
    cfg.alignment = (size_t)std::max<lua_Integer>(1, luaL_optinteger(L, valueIndex + 3, 4));
    cfg.startAddress = (uintptr_t)luaL_optinteger(L, valueIndex + 1, cfg.startAddress);
    cfg.stopAddress = (uintptr_t)luaL_optinteger(L, valueIndex + 2, cfg.stopAddress);
    if (lua_isstring(L, valueIndex + 4))
        cfg.stringEncoding = lua_tostring(L, valueIndex + 4);

    if (customFormula)
        cfg.valueType = ValueType::Custom;

    switch (cfg.valueType) {
        case ValueType::String:
        case ValueType::UnicodeString:
            cfg.stringValue = value;
            cfg.alignment = 1;
            break;
        case ValueType::ByteArray:
            cfg.parseAOB(value);
            cfg.alignment = 1;
            break;
        case ValueType::Binary:
            cfg.parseBinary(value);
            cfg.alignment = 1;
            break;
        case ValueType::Float:
        case ValueType::Double:
            cfg.floatValue = parseLocaleDouble(value);
            break;
        case ValueType::Pointer:
            cfg.intValue = static_cast<int64_t>(strtoull(value, nullptr, 0));
            break;
        case ValueType::All:
            cfg.intValue = atoll(value);
            cfg.floatValue = parseLocaleDouble(value);
            break;
        case ValueType::Grouped: {
            std::string error;
            if (!cfg.parseGrouped(value, &error))
                throw std::invalid_argument("Invalid grouped scan expression: " + error);
            cfg.alignment = 1;
            break;
        }
        case ValueType::Custom:
            cfg.customFormula = value;
            cfg.customValueSize = luaValueTypeSize(mapLuaValueType(valueTypeRaw));
            cfg.alignment = 1;
            break;
        default:
            cfg.intValue = atoll(value);
            break;
    }

    return cfg;
}

static int l_createMemScan(lua_State* L) {
    auto* sd = (LuaScanData*)lua_newuserdata(L, sizeof(LuaScanData));
    new (sd) LuaScanData();
    luaL_getmetatable(L, "MemScan");
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        luaL_newmetatable(L, "MemScan");
        lua_pushvalue(L, -1); lua_setfield(L, -2, "__index");

        lua_pushcfunction(L, [](lua_State* L) -> int {
            auto* sd = (LuaScanData*)luaL_checkudata(L, 1, "MemScan");
            sd->~LuaScanData();
            return 0;
        });
        lua_setfield(L, -2, "__gc");

        lua_pushcfunction(L, [](lua_State* L) -> int {
            auto* sd = (LuaScanData*)luaL_checkudata(L, 1, "MemScan");
            auto* p = getProc(L);
            if (!p) { lua_pushboolean(L, 0); return 1; }
            try {
                auto cfg = luaScanConfig(L, 2, 3, 4);
                sd->result = std::make_unique<ScanResult>(sd->scanner.firstScan(*p, cfg));
                lua_pushboolean(L, 1);
                lua_pushnil(L);
            } catch (const std::exception& ex) {
                lua_pushboolean(L, 0);
                lua_pushstring(L, ex.what());
            } catch (...) {
                lua_pushboolean(L, 0);
                lua_pushstring(L, "scan failed");
            }
            return 2;
        });
        lua_setfield(L, -2, "firstScan");

        lua_pushcfunction(L, [](lua_State* L) -> int {
            auto* sd = (LuaScanData*)luaL_checkudata(L, 1, "MemScan");
            auto* p = getProc(L);
            if (!p || !sd->result) { lua_pushboolean(L, 0); return 1; }
            try {
                auto cfg = luaScanConfig(L, 2, 3, 4);
                sd->result = std::make_unique<ScanResult>(sd->scanner.nextScan(*p, cfg, *sd->result));
                lua_pushboolean(L, 1);
                lua_pushnil(L);
            } catch (const std::exception& ex) {
                lua_pushboolean(L, 0);
                lua_pushstring(L, ex.what());
            } catch (...) {
                lua_pushboolean(L, 0);
                lua_pushstring(L, "scan failed");
            }
            return 2;
        });
        lua_setfield(L, -2, "nextScan");

        lua_pushcfunction(L, [](lua_State* L) -> int {
            auto* sd = (LuaScanData*)luaL_checkudata(L, 1, "MemScan");
            lua_pushinteger(L, sd->result ? sd->result->count() : 0);
            return 1;
        });
        lua_setfield(L, -2, "getFoundCount");

        lua_pushcfunction(L, [](lua_State* L) -> int {
            auto* sd = (LuaScanData*)luaL_checkudata(L, 1, "MemScan");
            int idx = (int)luaL_checkinteger(L, 2);
            if (!sd->result || idx < 0 || idx >= (int)sd->result->count()) { lua_pushnil(L); return 1; }
            lua_pushinteger(L, (lua_Integer)sd->result->address(idx));
            return 1;
        });
        lua_setfield(L, -2, "getAddress");
    }
    lua_setmetatable(L, -2);
    return 1;
}

// ── Debug control ──

static int l_debug_getThreadList(lua_State* L) {
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

static void ensureLuaBreakpointList(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_lua_breakpoints");
    if (lua_istable(L, -1))
        return;

    lua_pop(L, 1);
    lua_newtable(L);
    lua_pushvalue(L, -1);
    lua_setfield(L, LUA_REGISTRYINDEX, "ce_lua_breakpoints");
    lua_pushinteger(L, 1);
    lua_setfield(L, LUA_REGISTRYINDEX, "ce_lua_next_breakpoint_id");
    lua_pushboolean(L, 0);
    lua_setfield(L, LUA_REGISTRYINDEX, "ce_lua_debug_broken");
}

static int nextLuaBreakpointId(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_lua_next_breakpoint_id");
    int id = static_cast<int>(lua_tointeger(L, -1));
    lua_pop(L, 1);
    if (id <= 0) id = 1;
    lua_pushinteger(L, id + 1);
    lua_setfield(L, LUA_REGISTRYINDEX, "ce_lua_next_breakpoint_id");
    return id;
}

static int l_debug_setBreakpoint(lua_State* L) {
    uintptr_t address = static_cast<uintptr_t>(luaL_checkinteger(L, 1));
    int type = static_cast<int>(luaL_optinteger(L, 2, 0));
    int size = static_cast<int>(luaL_optinteger(L, 3, 1));

    // Plant a REAL software breakpoint via the engine's DebugSession (P2 #15), then
    // let the target run toward it. Hits are queued on the tracer thread and drained
    // by debug_pumpEvents on the Lua thread. Falls back to bookkeeping-only if no
    // process is attached.
    // type 0 = execute (software int3); non-zero = hardware DATA watchpoint
    // (1=write, else access), size bytes wide.
    int realId = -1;
    if (auto* eng = ce::LuaEngine::instanceFromState(L)) {
        if (auto* sess = eng->debugSession()) {
            realId = (type == 0) ? sess->setSoftwareBreakpoint(address)
                                 : sess->setHardwareBreakpoint(address, type, size);
            sess->continueExecution();
        }
    }

    ensureLuaBreakpointList(L);
    int id = nextLuaBreakpointId(L);

    lua_newtable(L);
    lua_pushinteger(L, id); lua_setfield(L, -2, "id");
    lua_pushinteger(L, realId); lua_setfield(L, -2, "realId");
    lua_pushinteger(L, static_cast<lua_Integer>(address)); lua_setfield(L, -2, "address");
    lua_pushinteger(L, type); lua_setfield(L, -2, "type");
    lua_pushinteger(L, size); lua_setfield(L, -2, "size");
    lua_pushboolean(L, 1); lua_setfield(L, -2, "enabled");
    lua_pushinteger(L, 0); lua_setfield(L, -2, "hitCount");
    lua_rawseti(L, -2, id);
    lua_pop(L, 1);

    lua_pushinteger(L, id);
    return 1;
}

// Canonical general-purpose register list (global name -> CpuContext field),
// used consistently everywhere registers cross the Lua boundary: the breakpoint
// globals, the register write-back on resume, and debug_getRegisters.
#define CE_GP_REGS(X) \
    X("RAX", rax) X("RBX", rbx) X("RCX", rcx) X("RDX", rdx) \
    X("RSI", rsi) X("RDI", rdi) X("RBP", rbp) X("RSP", rsp) \
    X("R8", r8)   X("R9", r9)   X("R10", r10) X("R11", r11) \
    X("R12", r12) X("R13", r13) X("R14", r14) X("R15", r15) \
    X("RIP", rip) X("RFLAGS", rflags)

// Resolve a register name (case-insensitive; E-prefixed 32-bit aliases map to
// the same 64-bit field, matching CE's register editor) to its CpuContext field.
static uint64_t* regFieldByName(ce::CpuContext& c, std::string n) {
    for (auto& ch : n) ch = (char)std::toupper((unsigned char)ch);
    if (n.size() == 3 && n[0] == 'E') n[0] = 'R';   // EAX->RAX, ESP->RSP, ...
    static const std::unordered_map<std::string, uint64_t ce::CpuContext::*> m = {
        {"RAX", &ce::CpuContext::rax}, {"RBX", &ce::CpuContext::rbx},
        {"RCX", &ce::CpuContext::rcx}, {"RDX", &ce::CpuContext::rdx},
        {"RSI", &ce::CpuContext::rsi}, {"RDI", &ce::CpuContext::rdi},
        {"RBP", &ce::CpuContext::rbp}, {"RSP", &ce::CpuContext::rsp},
        {"RIP", &ce::CpuContext::rip},
        {"R8", &ce::CpuContext::r8},   {"R9", &ce::CpuContext::r9},
        {"R10", &ce::CpuContext::r10}, {"R11", &ce::CpuContext::r11},
        {"R12", &ce::CpuContext::r12}, {"R13", &ce::CpuContext::r13},
        {"R14", &ce::CpuContext::r14}, {"R15", &ce::CpuContext::r15},
        {"RFLAGS", &ce::CpuContext::rflags}, {"EFLAGS", &ce::CpuContext::rflags},
        {"CS", &ce::CpuContext::cs}, {"SS", &ce::CpuContext::ss},
        {"DS", &ce::CpuContext::ds}, {"ES", &ce::CpuContext::es},
        {"FS", &ce::CpuContext::fs}, {"GS", &ce::CpuContext::gs},
        {"DR0", &ce::CpuContext::dr0}, {"DR1", &ce::CpuContext::dr1},
        {"DR2", &ce::CpuContext::dr2}, {"DR3", &ce::CpuContext::dr3},
        {"DR6", &ce::CpuContext::dr6}, {"DR7", &ce::CpuContext::dr7},
    };
    auto it = m.find(n);
    return it == m.end() ? nullptr : &(c.*(it->second));
}

// debug_pumpEvents([timeoutMs]) -> number of breakpoint hits processed. For each
// queued hit it publishes the full register context as globals (RIP/RSP/RAX..R15/
// RFLAGS and BPAddress), calls the global debugger_onBreakpoint (CE convention) if
// defined, then applies any register edits and resumes the target. The first hit
// waits up to timeoutMs; already-queued hits are then drained without blocking.
static int l_debug_pumpEvents(lua_State* L) {
    int timeoutMs = static_cast<int>(luaL_optinteger(L, 1, 0));
    auto* eng = ce::LuaEngine::instanceFromState(L);
    if (!eng || !eng->debugAttached()) { lua_pushinteger(L, 0); return 1; }

    int processed = 0;
    ce::LuaEngine::DebugHit hit;
    while (eng->nextDebugHit(hit, processed == 0 ? timeoutMs : 0)) {
        ++processed;
#define X(name, field) lua_pushinteger(L, (lua_Integer)hit.context.field); lua_setglobal(L, name);
        CE_GP_REGS(X)
#undef X
        lua_pushinteger(L, (lua_Integer)hit.address);     lua_setglobal(L, "BPAddress");

        lua_getglobal(L, "debugger_onBreakpoint");
        if (lua_isfunction(L, -1)) {
            if (lua_pcall(L, 0, 0, 0) != LUA_OK) return lua_error(L);
        } else {
            lua_pop(L, 1);
        }
        // Apply any register edits the handler made via the RIP/RSP/RAX.. globals
        // (CE lets debugger_onBreakpoint rewrite registers), then resume. Target
        // the thread that actually hit, then write it.
        if (auto* sess = eng->debugSession()) {
            if (sess->selectThread(hit.tid)) {
                ce::CpuContext ctx = hit.context;
                auto applyReg = [&](const char* name, uint64_t& field) {
                    lua_getglobal(L, name);
                    if (lua_isinteger(L, -1))     field = (uint64_t)lua_tointeger(L, -1);
                    else if (lua_isnumber(L, -1))  field = (uint64_t)lua_tonumber(L, -1);
                    lua_pop(L, 1);
                };
#define X(name, field) applyReg(name, ctx.field);
                CE_GP_REGS(X)
#undef X
                sess->setStopContext(ctx);
            }
            sess->continueExecution();
        }
    }
    lua_pushinteger(L, processed);
    return 1;
}

static int l_debug_removeBreakpoint(lua_State* L) {
    int id = static_cast<int>(luaL_checkinteger(L, 1));
    ensureLuaBreakpointList(L);            // pushes the breakpoint table
    // Remove the REAL software breakpoint recorded under this id, then the entry.
    lua_rawgeti(L, -1, id);
    if (lua_istable(L, -1)) {
        lua_getfield(L, -1, "realId");
        int realId = static_cast<int>(lua_tointeger(L, -1));
        lua_pop(L, 1);
        lua_getfield(L, -1, "type");
        int bpType = static_cast<int>(lua_tointeger(L, -1));
        lua_pop(L, 1);
        if (realId >= 0)
            if (auto* eng = ce::LuaEngine::instanceFromState(L))
                if (eng->debugAttached())
                    if (auto* sess = eng->debugSession()) {
                        if (bpType == 0) sess->removeSoftwareBreakpoint(realId);
                        else             sess->removeHardwareBreakpoint(realId);
                    }
    }
    lua_pop(L, 1);                          // pop the entry
    lua_pushnil(L);
    lua_rawseti(L, -2, id);                 // clear the bookkeeping entry
    lua_pop(L, 1);                          // pop the table
    lua_pushboolean(L, 1);
    return 1;
}

static int l_debug_continueFromBreakpoint(lua_State* L) {
    if (auto* eng = ce::LuaEngine::instanceFromState(L))
        if (eng->debugAttached())
            if (auto* sess = eng->debugSession()) sess->continueExecution();
    lua_pushboolean(L, 0);
    lua_setfield(L, LUA_REGISTRYINDEX, "ce_lua_debug_broken");
    lua_pushboolean(L, 1);
    return 1;
}

static int l_debug_getBreakpointList(lua_State* L) {
    ensureLuaBreakpointList(L);
    lua_newtable(L);
    int outIndex = 1;
    lua_pushnil(L);
    while (lua_next(L, -3) != 0) {
        if (lua_istable(L, -1)) {
            lua_pushvalue(L, -1);
            lua_rawseti(L, -4, outIndex++);
        }
        lua_pop(L, 1);
    }
    lua_remove(L, -2);
    return 1;
}

static int l_debug_isDebugging(lua_State* L) {
    ensureLuaBreakpointList(L);
    bool hasBreakpoint = false;
    lua_pushnil(L);
    while (lua_next(L, -2) != 0) {
        hasBreakpoint = true;
        lua_pop(L, 2);
        break;
    }
    lua_pop(L, 1);
    lua_pushboolean(L, hasBreakpoint);
    return 1;
}

static int l_debug_isBroken(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_lua_debug_broken");
    bool broken = lua_toboolean(L, -1) != 0;
    lua_pop(L, 1);
    lua_pushboolean(L, broken);
    return 1;
}

// debug_getRegisters([tid]) -> table of every register at the current stop
// (RAX..R15, RIP, RSP, RBP, RSI, RDI, RFLAGS, segment + debug regs). Meaningful
// only while broken at a breakpoint; returns nil if there is no debug session.
static int l_debug_getRegisters(lua_State* L) {
    auto* eng  = ce::LuaEngine::instanceFromState(L);
    auto* sess = eng ? eng->debugSession() : nullptr;
    if (!sess) { lua_pushnil(L); return 1; }
    if (lua_gettop(L) >= 1 && lua_isinteger(L, 1))
        sess->selectThread((pid_t)lua_tointeger(L, 1));
    ce::CpuContext c = sess->getStopContext();
    lua_newtable(L);
#define X(name, field) lua_pushinteger(L, (lua_Integer)c.field); lua_setfield(L, -2, name);
    CE_GP_REGS(X)
    X("CS", cs) X("SS", ss) X("DS", ds) X("ES", es) X("FS", fs) X("GS", gs)
    X("DR0", dr0) X("DR1", dr1) X("DR2", dr2) X("DR3", dr3) X("DR6", dr6) X("DR7", dr7)
#undef X
    return 1;
}

// debug_setRegister(name, value [, tid]) -> bool. Writes one register into the
// stop context (name is case-insensitive; EAX-style 32-bit aliases accepted) and
// pushes it back to the target so the change takes effect on resume.
static int l_debug_setRegister(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    uint64_t val = (uint64_t)luaL_checkinteger(L, 2);
    auto* eng  = ce::LuaEngine::instanceFromState(L);
    auto* sess = eng ? eng->debugSession() : nullptr;
    if (!sess) { lua_pushboolean(L, 0); return 1; }
    if (lua_gettop(L) >= 3 && lua_isinteger(L, 3))
        sess->selectThread((pid_t)lua_tointeger(L, 3));
    ce::CpuContext c = sess->getStopContext();
    uint64_t* field = regFieldByName(c, name);
    if (!field) { lua_pushboolean(L, 0); return 1; }
    *field = val;
    lua_pushboolean(L, sess->setStopContext(c));
    return 1;
}

// debug_getStack([count]) -> array of { address, value } for `count` (default 16)
// pointer-sized slots starting at RSP. Reads through the process, so word size
// tracks the target's bitness.
static int l_debug_getStack(lua_State* L) {
    int count = (int)luaL_optinteger(L, 1, 16);
    auto* eng  = ce::LuaEngine::instanceFromState(L);
    auto* sess = eng ? eng->debugSession() : nullptr;
    auto* p    = getProc(L);
    if (!sess || !p) { lua_pushnil(L); return 1; }
    uint64_t rsp = sess->getStopContext().rsp;
    size_t ps = p->is64bit() ? 8 : 4;
    lua_newtable(L);
    for (int i = 0; i < count; ++i) {
        uint64_t v = 0;
        uintptr_t at = (uintptr_t)(rsp + (uint64_t)i * ps);
        if (!p->read(at, &v, ps)) break;
        lua_newtable(L);
        lua_pushinteger(L, (lua_Integer)at); lua_setfield(L, -2, "address");
        lua_pushinteger(L, (lua_Integer)v);  lua_setfield(L, -2, "value");
        lua_rawseti(L, -2, i + 1);
    }
    return 1;
}

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

static int l_addressList_getCount(lua_State* L) {
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

static int l_getTableEntry(lua_State* L) {
    int index = luaAddressListIndex(L, 1);
    ensureLuaAddressList(L);
    lua_rawgeti(L, -1, index);
    lua_remove(L, -2);
    return 1;
}

static int l_setTableEntry(lua_State* L) {
    int index = luaAddressListIndex(L, 1);
    luaL_checktype(L, 2, LUA_TTABLE);
    ensureLuaAddressList(L);
    lua_pushvalue(L, 2);
    lua_rawseti(L, -2, index);
    lua_pop(L, 1);
    lua_pushboolean(L, 1);
    return 1;
}

static int l_addressList_addEntry(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE);
    ensureLuaAddressList(L);
    auto index = static_cast<lua_Integer>(lua_rawlen(L, -1) + 1);
    lua_pushvalue(L, 1);
    lua_rawseti(L, -2, index);
    lua_pop(L, 1);
    lua_pushinteger(L, index - 1);
    return 1;
}

static int l_addressList_removeEntry(lua_State* L) {
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

static int l_addressList_clear(lua_State* L) {
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
    for (int id : list->ids()) {
        auto snap = list->byId(id);
        if (!snap) continue;
        ce::CheatEntry e;
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

static int l_saveTable(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    auto* eng = ce::LuaEngine::instanceFromState(L);
    auto* list = eng ? eng->addressList() : nullptr;
    if (!list) { lua_pushboolean(L, 0); return 1; }
    ce::CheatTable table = buildCheatTableFromList(list);
    lua_pushboolean(L, table.saveJson(path) ? 1 : 0);
    return 1;
}

// loadTable(path) -> bool. Load a .CT/.json into the live cheat table (address
// list), like the GUI's Load Table.
static int l_loadTable(lua_State* L) {
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
        if (!e.value.empty()) list->setValue(id, e.value);
        if (!e.color.empty()) list->setColor(id, e.color);
        if (!e.autoAsmScript.empty()) list->setScript(id, e.autoAsmScript);
        if (e.showAsHex) list->setHexView(id, true);
        list->setFreezeMode(id, (int)e.freezeMode);
        list->setIndent(id, indent);
        if (e.active) list->setActive(id, true);
    }
    lua_pushboolean(L, 1);
    return 1;
}

// ── Trainer generation (standalone executable from the cheat table) ──
// generateTrainerSource() -> C source string for the current address list (nil
// if there is no list). Mirrors the GUI's "Create Trainer" source step.
static int l_generateTrainerSource(lua_State* L) {
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
static int l_generateTrainer(lua_State* L) {
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

// ── Managed runtime detection (Mono / .NET / CoreCLR) ──
// getManagedRuntimes() -> array of { kind, name, module, modulePath, base, size }
// ── isKeyPressed(vk [, vk2, …]) — global key state, no window focus needed ──
// CE tables poll this for hotkeys. We map Windows virtual-key codes (what tables
// pass) to Linux evdev KEY_* codes and read the live pressed-key bitmap via
// EVIOCGKEY across all /dev/input/event* devices — works headless and under the
// GUI, needs read access to /dev/input (root, which this tool usually has).
static int linuxKeyForVk(int vk) {
    static const std::unordered_map<int, int> kMap = {
        {0x08, KEY_BACKSPACE}, {0x09, KEY_TAB}, {0x0D, KEY_ENTER}, {0x1B, KEY_ESC},
        {0x20, KEY_SPACE}, {0x10, KEY_LEFTSHIFT}, {0x11, KEY_LEFTCTRL}, {0x12, KEY_LEFTALT},
        {0xA0, KEY_LEFTSHIFT}, {0xA1, KEY_RIGHTSHIFT}, {0xA2, KEY_LEFTCTRL}, {0xA3, KEY_RIGHTCTRL},
        {0xA4, KEY_LEFTALT}, {0xA5, KEY_RIGHTALT},
        {0x25, KEY_LEFT}, {0x26, KEY_UP}, {0x27, KEY_RIGHT}, {0x28, KEY_DOWN},
        {0x2D, KEY_INSERT}, {0x2E, KEY_DELETE}, {0x24, KEY_HOME}, {0x23, KEY_END},
        {0x21, KEY_PAGEUP}, {0x22, KEY_PAGEDOWN}, {0x14, KEY_CAPSLOCK},
        // digits 0-9
        {0x30, KEY_0}, {0x31, KEY_1}, {0x32, KEY_2}, {0x33, KEY_3}, {0x34, KEY_4},
        {0x35, KEY_5}, {0x36, KEY_6}, {0x37, KEY_7}, {0x38, KEY_8}, {0x39, KEY_9},
        // letters A-Z (Windows VK 0x41-0x5A)
        {0x41, KEY_A}, {0x42, KEY_B}, {0x43, KEY_C}, {0x44, KEY_D}, {0x45, KEY_E},
        {0x46, KEY_F}, {0x47, KEY_G}, {0x48, KEY_H}, {0x49, KEY_I}, {0x4A, KEY_J},
        {0x4B, KEY_K}, {0x4C, KEY_L}, {0x4D, KEY_M}, {0x4E, KEY_N}, {0x4F, KEY_O},
        {0x50, KEY_P}, {0x51, KEY_Q}, {0x52, KEY_R}, {0x53, KEY_S}, {0x54, KEY_T},
        {0x55, KEY_U}, {0x56, KEY_V}, {0x57, KEY_W}, {0x58, KEY_X}, {0x59, KEY_Y}, {0x5A, KEY_Z},
        // numpad 0-9
        {0x60, KEY_KP0}, {0x61, KEY_KP1}, {0x62, KEY_KP2}, {0x63, KEY_KP3}, {0x64, KEY_KP4},
        {0x65, KEY_KP5}, {0x66, KEY_KP6}, {0x67, KEY_KP7}, {0x68, KEY_KP8}, {0x69, KEY_KP9},
        {0x6A, KEY_KPASTERISK}, {0x6B, KEY_KPPLUS}, {0x6D, KEY_KPMINUS}, {0x6E, KEY_KPDOT},
        {0x6F, KEY_KPSLASH},
        // F1-F12
        {0x70, KEY_F1}, {0x71, KEY_F2}, {0x72, KEY_F3}, {0x73, KEY_F4}, {0x74, KEY_F5},
        {0x75, KEY_F6}, {0x76, KEY_F7}, {0x77, KEY_F8}, {0x78, KEY_F9}, {0x79, KEY_F10},
        {0x7A, KEY_F11}, {0x7B, KEY_F12},
    };
    auto it = kMap.find(vk);
    return it == kMap.end() ? -1 : it->second;
}

static bool linuxKeyDown(int keycode) {
    if (keycode < 0 || keycode > KEY_MAX) return false;
    DIR* d = ::opendir("/dev/input");
    if (!d) return false;
    bool down = false;
    struct dirent* e;
    const size_t wordBits = 8 * sizeof(unsigned long);
    while ((e = ::readdir(d)) && !down) {
        if (std::strncmp(e->d_name, "event", 5) != 0) continue;
        std::string path = std::string("/dev/input/") + e->d_name;
        int fd = ::open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0) continue;
        unsigned long keys[(KEY_MAX / wordBits) + 1] = {0};
        if (::ioctl(fd, EVIOCGKEY(sizeof(keys)), keys) >= 0)
            down = (keys[keycode / wordBits] >> (keycode % wordBits)) & 1UL;
        ::close(fd);
    }
    ::closedir(d);
    return down;
}

static int l_isKeyPressed(lua_State* L) {
    // All supplied keys must be down (CE allows a small combo).
    int n = lua_gettop(L);
    if (n < 1) { lua_pushboolean(L, 0); return 1; }
    for (int i = 1; i <= n; ++i) {
        int vk = (int)luaL_checkinteger(L, i);
        int kc = linuxKeyForVk(vk);
        if (kc < 0 || !linuxKeyDown(kc)) { lua_pushboolean(L, 0); return 1; }
    }
    lua_pushboolean(L, 1);
    return 1;
}

static int l_getManagedRuntimes(lua_State* L) {
    auto* p = getProc(L);
    lua_newtable(L);
    if (!p) return 1;
    auto runtimes = ce::detectManagedRuntimes(*p);
    for (size_t i = 0; i < runtimes.size(); ++i) {
        const auto& r = runtimes[i];
        lua_newtable(L);
        lua_pushstring(L, r.kind == ce::ManagedRuntimeKind::Mono ? "Mono" : "CoreCLR");
        lua_setfield(L, -2, "kind");
        lua_pushstring(L, r.name.c_str());        lua_setfield(L, -2, "name");
        lua_pushstring(L, r.moduleName.c_str());  lua_setfield(L, -2, "module");
        lua_pushstring(L, r.modulePath.c_str());  lua_setfield(L, -2, "modulePath");
        lua_pushinteger(L, (lua_Integer)r.base);  lua_setfield(L, -2, "base");
        lua_pushinteger(L, (lua_Integer)r.size);  lua_setfield(L, -2, "size");
        lua_rawseti(L, -2, (int)i + 1);
    }
    return 1;
}

// monoDissect() -> { ready, error, images = { {name, classes = { {namespace,
//   name, fullName, fields = { {name, type, offset, static}, ... } } } } } }
// Injects the in-process Mono agent, waits for it, and returns the ground-truth
// class/field layout. Returns nil + message if there's no target, the agent .so
// can't be found, or injection fails.
static int l_monoDissect(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); lua_pushstring(L, "no target process"); return 2; }
    switch (ce::detectManagedKind(*p)) {
        case ce::ManagedKind::Il2Cpp:
            lua_pushnil(L);
            lua_pushstring(L, "IL2CPP target: live dissection is Mono-only (IL2CPP is a separate track)");
            return 2;
        case ce::ManagedKind::None:
            lua_pushnil(L); lua_pushstring(L, "no Mono runtime detected"); return 2;
        case ce::ManagedKind::Mono: break;
    }
    std::string agent = ce::findMonoAgentPath();
    if (agent.empty()) {
        lua_pushnil(L); lua_pushstring(L, "libcecore_mono_agent.so not found"); return 2;
    }
    int timeoutMs = (lua_gettop(L) >= 1 && !lua_isnil(L, 1)) ? (int)luaL_checkinteger(L, 1) : 10000;
    // Injection needs the target's symbols (to find dlopen); load a resolver for
    // this process rather than depend on the engine's (openProcess doesn't load one).
    ce::SymbolResolver resolver;
    resolver.loadProcess(*p);
    auto d = ce::dissectMono(*p, resolver, agent, timeoutMs);
    if (!d) { lua_pushnil(L); lua_pushstring(L, "agent injection failed"); return 2; }

    lua_newtable(L);
    lua_pushboolean(L, d->ready);        lua_setfield(L, -2, "ready");
    lua_pushstring(L, d->error.c_str()); lua_setfield(L, -2, "error");
    lua_newtable(L);   // images
    int ii = 1;
    for (const auto& img : d->images) {
        lua_newtable(L);
        lua_pushstring(L, img.name.c_str()); lua_setfield(L, -2, "name");
        lua_newtable(L);   // classes
        int ci = 1;
        for (const auto& c : img.classes) {
            lua_newtable(L);
            lua_pushstring(L, c.namespaceName.c_str()); lua_setfield(L, -2, "namespace");
            lua_pushstring(L, c.name.c_str());          lua_setfield(L, -2, "name");
            lua_pushstring(L, c.fullName().c_str());    lua_setfield(L, -2, "fullName");
            lua_newtable(L);   // fields
            int fi = 1;
            for (const auto& f : c.fields) {
                lua_newtable(L);
                lua_pushstring(L, f.name.c_str());     lua_setfield(L, -2, "name");
                lua_pushstring(L, f.typeName.c_str()); lua_setfield(L, -2, "type");
                lua_pushinteger(L, (lua_Integer)f.offset); lua_setfield(L, -2, "offset");
                lua_pushboolean(L, f.isStatic);        lua_setfield(L, -2, "static");
                lua_rawseti(L, -2, fi++);
            }
            lua_setfield(L, -2, "fields");
            lua_rawseti(L, -2, ci++);
        }
        lua_setfield(L, -2, "classes");
        lua_rawseti(L, -2, ii++);
    }
    lua_setfield(L, -2, "images");
    return 1;
}

// ── Pointer scanner ──
// pointerScan(target [, maxDepth [, maxOffset [, {negativeOffsets,staticOnly,alignedOnly}]]])
//   -> array of { path, module, baseOffset, moduleBase, offsets={...} }
static int l_pointerScan(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    ce::PointerScanConfig cfg;
    cfg.targetAddress = (uintptr_t)luaL_checkinteger(L, 1);
    if (lua_gettop(L) >= 2 && !lua_isnil(L, 2)) cfg.maxDepth  = (int)luaL_checkinteger(L, 2);
    if (lua_gettop(L) >= 3 && !lua_isnil(L, 3)) cfg.maxOffset = (int)luaL_checkinteger(L, 3);
    if (lua_istable(L, 4)) {
        lua_getfield(L, 4, "negativeOffsets"); if (lua_isboolean(L, -1)) cfg.negativeOffsets = lua_toboolean(L, -1); lua_pop(L, 1);
        lua_getfield(L, 4, "staticOnly");      if (lua_isboolean(L, -1)) cfg.staticOnly      = lua_toboolean(L, -1); lua_pop(L, 1);
        lua_getfield(L, 4, "alignedOnly");     if (lua_isboolean(L, -1)) cfg.alignedOnly     = lua_toboolean(L, -1); lua_pop(L, 1);
    }
    ce::PointerScanner scanner;
    auto paths = scanner.scan(*p, cfg);
    lua_newtable(L);
    for (size_t i = 0; i < paths.size(); ++i) {
        const auto& pp = paths[i];
        lua_newtable(L);
        lua_pushstring(L, pp.toString().c_str());       lua_setfield(L, -2, "path");
        lua_pushstring(L, pp.module.c_str());           lua_setfield(L, -2, "module");
        lua_pushinteger(L, (lua_Integer)pp.baseOffset); lua_setfield(L, -2, "baseOffset");
        lua_pushinteger(L, (lua_Integer)pp.moduleBase); lua_setfield(L, -2, "moduleBase");
        lua_newtable(L);
        for (size_t j = 0; j < pp.offsets.size(); ++j) {
            lua_pushinteger(L, pp.offsets[j]);
            lua_rawseti(L, -2, (int)j + 1);
        }
        lua_setfield(L, -2, "offsets");
        lua_rawseti(L, -2, (int)i + 1);
    }
    return 1;
}

// ── Structure dissect (discriminating-field detector across N instances) ──
static const char* structFieldTypeName(ce::ValueType t) {
    switch (t) {
        case ce::ValueType::Byte:          return "Byte";
        case ce::ValueType::Int16:         return "2 Bytes";
        case ce::ValueType::Int32:         return "4 Bytes";
        case ce::ValueType::Int64:         return "8 Bytes";
        case ce::ValueType::Float:         return "Float";
        case ce::ValueType::Double:        return "Double";
        case ce::ValueType::String:        return "String";
        case ce::ValueType::UnicodeString: return "Unicode String";
        case ce::ValueType::Pointer:       return "Pointer";
        default:                           return "Array of byte";
    }
}
// dissectStructure(address | {addresses...}, size)
//   -> array of { offset, size, changed, type }
// One address: shows the layout. N addresses: flags fields that differ across
// instances (the discriminating-field detector).
static int l_dissectStructure(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    std::vector<uintptr_t> addrs;
    if (lua_istable(L, 1)) {
        int n = (int)lua_rawlen(L, 1);
        for (int i = 1; i <= n; ++i) {
            lua_rawgeti(L, 1, i);
            addrs.push_back((uintptr_t)lua_tointeger(L, -1));
            lua_pop(L, 1);
        }
    } else {
        addrs.push_back((uintptr_t)luaL_checkinteger(L, 1));
    }
    size_t size = (size_t)luaL_checkinteger(L, 2);
    if (addrs.empty() || size == 0) { lua_pushnil(L); return 1; }
    std::vector<std::vector<uint8_t>> snapshots;
    for (auto a : addrs) {
        std::vector<uint8_t> buf(size);
        if (!p->read(a, buf.data(), size)) { lua_pushnil(L); lua_pushstring(L, "read failed"); return 2; }
        snapshots.push_back(std::move(buf));
    }
    auto fields = ce::autoDetectStructureFieldsMulti(snapshots);
    lua_newtable(L);
    for (size_t i = 0; i < fields.size(); ++i) {
        const auto& f = fields[i];
        lua_newtable(L);
        lua_pushinteger(L, (lua_Integer)f.offset);         lua_setfield(L, -2, "offset");
        lua_pushinteger(L, (lua_Integer)f.size);           lua_setfield(L, -2, "size");
        lua_pushboolean(L, f.changed);                     lua_setfield(L, -2, "changed");
        lua_pushstring(L, structFieldTypeName(f.suggestedType)); lua_setfield(L, -2, "type");
        lua_rawseti(L, -2, (int)i + 1);
    }
    return 1;
}

// Busy-free sleep in small chunks (keeps the tool loops collecting over `seconds`).
static void sleepSeconds(double seconds) {
    long us = (long)(seconds * 1e6);
    while (us > 0) { long chunk = us > 200000 ? 200000 : us; usleep((useconds_t)chunk); us -= chunk; }
}

// ── Find what accesses / writes (code finder over a HW data watchpoint) ──
// findWhatWrites(address [, seconds=2 [, watchSize=4]])
// findWhatAccesses(address [, seconds=2 [, watchSize=4]])
//   -> array of { address, instruction, hitCount } sorted by hitCount.
// Runs the CodeFinder for `seconds`, which SEIZEs the target's threads and arms a
// DR watchpoint, so it needs exclusive ptrace (do not hold a debug session).
static int codeFinderImpl(lua_State* L, bool writesOnly) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    double seconds = luaL_optnumber(L, 2, 2.0);
    int watchSize  = (int)luaL_optinteger(L, 3, 4);
    ce::os::LinuxDebugger dbg;
    ce::CodeFinder finder;
    if (!finder.start(*p, dbg, addr, writesOnly, watchSize)) {
        lua_pushnil(L);
        lua_pushstring(L, "code finder failed to attach (need exclusive ptrace / privileges)");
        return 2;
    }
    sleepSeconds(seconds);
    finder.stop();
    auto results = finder.results();
    lua_newtable(L);
    for (size_t i = 0; i < results.size(); ++i) {
        const auto& r = results[i];
        lua_newtable(L);
        lua_pushinteger(L, (lua_Integer)r.instructionAddress); lua_setfield(L, -2, "address");
        lua_pushstring(L, r.instructionText.c_str());          lua_setfield(L, -2, "instruction");
        lua_pushinteger(L, r.hitCount);                        lua_setfield(L, -2, "hitCount");
        lua_rawseti(L, -2, (int)i + 1);
    }
    return 1;
}
static int l_findWhatWrites(lua_State* L)   { return codeFinderImpl(L, true); }
static int l_findWhatAccesses(lua_State* L) { return codeFinderImpl(L, false); }

// ── Break and Trace (single-step from a start address) ──
// breakAndTrace(startAddress [, maxSteps=100 [, {stepOverCalls,stayInModule,
//   stopAddress,moduleBase,moduleEnd} ]]) -> array of { address, instruction, rip }.
static int l_breakAndTrace(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    ce::TraceConfig cfg;
    cfg.startAddress = (uintptr_t)luaL_checkinteger(L, 1);
    cfg.maxSteps = (int)luaL_optinteger(L, 2, 100);
    if (lua_istable(L, 3)) {
        lua_getfield(L, 3, "stepOverCalls"); if (lua_isboolean(L, -1)) cfg.stepOverCalls = lua_toboolean(L, -1); lua_pop(L, 1);
        lua_getfield(L, 3, "stayInModule");  if (lua_isboolean(L, -1)) cfg.stayInModule  = lua_toboolean(L, -1); lua_pop(L, 1);
        lua_getfield(L, 3, "stopAddress");   if (lua_isinteger(L, -1)) cfg.stopAddress = (uintptr_t)lua_tointeger(L, -1); lua_pop(L, 1);
        lua_getfield(L, 3, "moduleBase");    if (lua_isinteger(L, -1)) cfg.moduleBase  = (uintptr_t)lua_tointeger(L, -1); lua_pop(L, 1);
        lua_getfield(L, 3, "moduleEnd");     if (lua_isinteger(L, -1)) cfg.moduleEnd    = (uintptr_t)lua_tointeger(L, -1); lua_pop(L, 1);
    }
    ce::os::LinuxDebugger dbg;
    ce::Tracer tracer;
    auto entries = tracer.trace(*p, dbg, cfg);
    lua_newtable(L);
    for (size_t i = 0; i < entries.size(); ++i) {
        const auto& e = entries[i];
        lua_newtable(L);
        lua_pushinteger(L, (lua_Integer)e.address);     lua_setfield(L, -2, "address");
        lua_pushstring(L, e.instruction.c_str());       lua_setfield(L, -2, "instruction");
        lua_pushinteger(L, (lua_Integer)e.context.rip); lua_setfield(L, -2, "rip");
        lua_rawseti(L, -2, (int)i + 1);
    }
    return 1;
}

// ── Find Statics (module-relative addresses referenced by code) ──
// findStatics([moduleName]) -> array of { address, references }, sorted by the
// analyzer. Defaults to the main/executable module (first in the module list).
static int l_findStatics(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    const char* modName = (lua_gettop(L) >= 1 && lua_isstring(L, 1)) ? lua_tostring(L, 1) : nullptr;
    auto mods = p->modules();
    if (mods.empty()) { lua_pushnil(L); lua_pushstring(L, "no modules"); return 2; }
    const ce::ModuleInfo* mod = nullptr;
    if (modName) {
        for (auto& m : mods) if (m.name == modName) { mod = &m; break; }
        if (!mod) { lua_pushnil(L); lua_pushstring(L, "module not found"); return 2; }
    } else {
        mod = &mods.front();   // main executable is enumerated first
    }
    ce::CodeAnalyzer analyzer;
    auto statics = analyzer.findStatics(*p, *mod);
    lua_newtable(L);
    for (size_t i = 0; i < statics.size(); ++i) {
        lua_newtable(L);
        lua_pushinteger(L, (lua_Integer)statics[i].address);    lua_setfield(L, -2, "address");
        lua_pushinteger(L, (lua_Integer)statics[i].references); lua_setfield(L, -2, "references");
        lua_rawseti(L, -2, (int)i + 1);
    }
    return 1;
}

// ── Branch mapper (hardware LBR via perf_event_open) ──
// branchMapAvailable() -> bool (Intel LBR + perf_event_paranoid<=1)
static int l_branchMapAvailable(lua_State* L) {
    lua_pushboolean(L, ce::LbrTracer::available());
    return 1;
}
// branchMap([seconds=1 [, tid]]) -> array of { from, to, mispred, predicted }.
// Samples the CPU branch buffer for `seconds` on `tid` (default main thread).
static int l_branchMap(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    double seconds = luaL_optnumber(L, 1, 1.0);
    pid_t tid = (lua_gettop(L) >= 2 && lua_isinteger(L, 2)) ? (pid_t)lua_tointeger(L, 2)
                                                            : (pid_t)p->pid();
    if (!ce::LbrTracer::available()) {
        lua_pushnil(L);
        lua_pushstring(L, "LBR unavailable (needs Intel LBR + kernel.perf_event_paranoid<=1)");
        return 2;
    }
    ce::LbrTracer lbr;
    if (!lbr.start(tid)) {
        lua_pushnil(L);
        lua_pushstring(L, "perf_event_open failed");
        return 2;
    }
    sleepSeconds(seconds);
    auto entries = lbr.drain();
    lbr.stop();
    lua_newtable(L);
    for (size_t i = 0; i < entries.size(); ++i) {
        const auto& e = entries[i];
        lua_newtable(L);
        lua_pushinteger(L, (lua_Integer)e.from);  lua_setfield(L, -2, "from");
        lua_pushinteger(L, (lua_Integer)e.to);    lua_setfield(L, -2, "to");
        lua_pushboolean(L, e.mispred);            lua_setfield(L, -2, "mispred");
        lua_pushboolean(L, e.predicted);          lua_setfield(L, -2, "predicted");
        lua_rawseti(L, -2, (int)i + 1);
    }
    return 1;
}

// ── Additional CE-compatible functions ──

static int l_openProcess(lua_State* L) {
    const char* nameOrPid = luaL_checkstring(L, 1);
    auto pid = parseProcessId(nameOrPid);
    if (pid <= 0)
        pid = findProcessIdByName(nameOrPid);

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

// connectToCeserver(host, port, pid) -> pid on success, or (nil, errmsg). Opens a
// remote process over a ceserver TCP connection and makes it the engine's target,
// so the same read/write/scan API works against a networked target (like the GUI's
// File -> Connect). The engine owns the client so it outlives the remote handle.
static int l_connectToCeserver(lua_State* L) {
    const char* host = luaL_checkstring(L, 1);
    int port = (int)luaL_checkinteger(L, 2);
    int pid  = (int)luaL_checkinteger(L, 3);
    auto* eng = ce::LuaEngine::instanceFromState(L);
    if (!eng) { lua_pushnil(L); lua_pushstring(L, "no engine"); return 2; }

    auto client = std::make_unique<ce::os::CEServerClient>();
    std::string err;
    if (!client->connectTcp(host, (uint16_t)port, err)) {
        lua_pushnil(L);
        lua_pushstring(L, err.empty() ? "connect failed" : err.c_str());
        return 2;
    }
    // open() stores &*client; moving the unique_ptr into the engine keeps the
    // CEServerClient object at the same address, so the stored pointer stays valid.
    auto handle = ce::os::RemoteProcessHandle::open(*client, pid);
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

static int l_getOpenedProcessID(lua_State* L) {
    auto* p = getProc(L);
    lua_pushinteger(L, p ? p->pid() : 0);
    return 1;
}

static int l_writePointer(lua_State* L) {
    auto* p = getProc(L);
    if (!p) return 0;
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    uintptr_t val = (uintptr_t)luaL_checkinteger(L, 2);
    // Write only the target's pointer width (4 bytes on a 32-bit target), else
    // an 8-byte write clobbers the following dword.
    size_t ptrSize = p->is64bit() ? 8 : 4;
    p->write(addr, &val, ptrSize);
    return 0;
}

// getOpenedProcesses() -> table {[pid] = name} of running processes (CE-style).
static int l_getOpenedProcesses(lua_State* L) {
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
static int l_getUserDefinedSymbolByName(lua_State* L) {
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
static int l_getUserDefinedSymbolByAddress(lua_State* L) {
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

static int l_registerSymbol(lua_State* L) {
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

static int l_unregisterSymbol(lua_State* L) {
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

static int l_inputQuery(lua_State* L) {
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
// explicit, out-of-band opt-in the script itself cannot set — the process env
// var CECORE_LUA_ALLOW_UNSAFE, read live (Lua's os library cannot change the
// process environment, so an untrusted table cannot flip this).
static int l_shellExecute(lua_State* L) {
    if (!getenv("CECORE_LUA_ALLOW_UNSAFE"))
        return luaL_error(L,
            "shellExecute blocked: it runs arbitrary shell commands. Only enable for "
            "tables you trust by launching with CECORE_LUA_ALLOW_UNSAFE=1 (see SECURITY.md).");
    const char* cmd = luaL_checkstring(L, 1);
    int ret = system(cmd);
    lua_pushinteger(L, ret);
    return 1;
}

static int l_getScreenWidth(lua_State* L) {
    // Basic X11 screen size
    lua_pushinteger(L, 1920); // Default; would query X11
    return 1;
}

static int l_getScreenHeight(lua_State* L) {
    lua_pushinteger(L, 1080);
    return 1;
}

static int l_inMainThread(lua_State* L) {
    lua_pushboolean(L, 1); // Simplified
    return 1;
}

// Process-name camouflage. Mostly relevant for hiding cecore from single-
// player anti-tamper string scans (/proc/<pid>/comm, ps output, etc.).
// Does not defeat dedicated anti-cheat — see project policy notes.
static int l_setProcessName(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    if (!name || !*name) return 0;
    // prctl PR_SET_NAME truncates to 15 chars; copy explicitly to keep
    // behaviour predictable.
    char buf[16] = {0};
    std::strncpy(buf, name, sizeof(buf) - 1);
    int rc = prctl(PR_SET_NAME, (unsigned long)buf, 0, 0, 0);
    lua_pushboolean(L, rc == 0);
    return 1;
}

static int l_getProcessName(lua_State* L) {
    char buf[16] = {0};
    if (prctl(PR_GET_NAME, (unsigned long)buf, 0, 0, 0) == 0) {
        lua_pushstring(L, buf);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

static int l_getThreadList(lua_State* L) {
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

static int l_readRegionFromFile(lua_State* L) {
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
        return luaL_error(L, "readRegionFromFile: %s", ex.what());
    }
}

static int l_writeRegionToFile(lua_State* L) {
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
    std::ofstream f(filename, std::ios::binary);
    if (f) { f.write((char*)buf.data(), *r); lua_pushboolean(L, 1); }
    else lua_pushboolean(L, 0);
    return 1;
}

static int l_AOBScan(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    const char* pattern = luaL_checkstring(L, 1);
    try {
        ScanConfig cfg;
        cfg.valueType = ValueType::ByteArray;
        if (!cfg.parseAOB(pattern))
            return luaL_error(L, "AOBScan: invalid AOB pattern '%s'", pattern);
        cfg.alignment = 1;
        MemoryScanner scanner;
        auto result = scanner.firstScan(*p, cfg);
        // CE returns a StringList of ALL matches (0-indexed hex strings, .Count,
        // .destroy()); our previous impl returned only the first address as an
        // integer, silently dropping the rest and breaking result iteration.
        size_t n = result.count();
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
        return luaL_error(L, "%s", ex.what());
    } catch (...) {
        return luaL_error(L, "AOBScan failed");
    }
    return 1;
}

static int l_AOBScanEx(lua_State* L) {
    // Returns all results as a table
    auto* p = getProc(L);
    if (!p) { lua_newtable(L); return 1; }
    const char* pattern = luaL_checkstring(L, 1);
    try {
        ScanConfig cfg;
        cfg.valueType = ValueType::ByteArray;
        if (!cfg.parseAOB(pattern))
            return luaL_error(L, "AOBScan: invalid AOB pattern '%s'", pattern);
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
        return luaL_error(L, "%s", ex.what());
    } catch (...) {
        return luaL_error(L, "AOBScan failed");
    }
    return 1;
}

// AOBScanModule(moduleName, pattern) -> result list restricted to that module's
// address range (CE convention). Same 0-indexed .Count/.destroy() shape as AOBScan.
static int l_AOBScanModule(lua_State* L) {
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
            return luaL_error(L, "AOBScan: invalid AOB pattern '%s'", pattern);
        cfg.alignment = 1;
        cfg.startAddress = mod->base;
        cfg.stopAddress = mod->base + mod->size;
        MemoryScanner scanner;
        auto result = scanner.firstScan(*p, cfg);
        size_t n = result.count();
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
        return luaL_error(L, "%s", ex.what());
    } catch (...) {
        return luaL_error(L, "AOBScanModule failed");
    }
    return 1;
}

static int l_fullAccess(lua_State* L) {
    auto* p = getProc(L);
    if (!p) return 0;
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    size_t size = (size_t)luaL_checkinteger(L, 2);
    p->protect(addr, size, MemProt::All);
    return 0;
}

// ── Hotkeys ──

struct LuaHotkey {
    int callbackRef = LUA_NOREF;
    bool enabled = true;
    std::vector<int> keys;
};

static LuaHotkey* checkHotkey(lua_State* L, int index) {
    return static_cast<LuaHotkey*>(luaL_checkudata(L, index, "CEHotkey"));
}

static int l_hotkey_gc(lua_State* L) {
    auto* hotkey = checkHotkey(L, 1);
    if (hotkey->callbackRef != LUA_NOREF) {
        luaL_unref(L, LUA_REGISTRYINDEX, hotkey->callbackRef);
        hotkey->callbackRef = LUA_NOREF;
    }
    hotkey->~LuaHotkey();
    return 0;
}

static int l_hotkey_trigger(lua_State* L) {
    auto* hotkey = checkHotkey(L, 1);
    if (!hotkey->enabled || hotkey->callbackRef == LUA_NOREF) {
        lua_pushboolean(L, 0);
        return 1;
    }

    lua_rawgeti(L, LUA_REGISTRYINDEX, hotkey->callbackRef);
    if (lua_pcall(L, 0, 0, 0) != LUA_OK) {
        const char* err = lua_tostring(L, -1);
        lua_pop(L, 1);
        lua_pushnil(L);
        lua_pushstring(L, err ? err : "hotkey callback failed");
        return 2;
    }
    lua_pushboolean(L, 1);
    return 1;
}

static int l_hotkey_destroy(lua_State* L) {
    auto* hotkey = checkHotkey(L, 1);
    hotkey->enabled = false;
    if (hotkey->callbackRef != LUA_NOREF) {
        luaL_unref(L, LUA_REGISTRYINDEX, hotkey->callbackRef);
        hotkey->callbackRef = LUA_NOREF;
    }
    return 0;
}

static int l_hotkey_getKeys(lua_State* L) {
    auto* hotkey = checkHotkey(L, 1);
    lua_newtable(L);
    for (size_t i = 0; i < hotkey->keys.size(); ++i) {
        lua_pushinteger(L, hotkey->keys[i]);
        lua_rawseti(L, -2, static_cast<int>(i + 1));
    }
    return 1;
}

static int l_hotkey_index(lua_State* L) {
    auto* hotkey = checkHotkey(L, 1);
    const char* key = luaL_checkstring(L, 2);
    if (std::strcmp(key, "Enabled") == 0 || std::strcmp(key, "enabled") == 0) {
        lua_pushboolean(L, hotkey->enabled);
        return 1;
    }
    if (std::strcmp(key, "trigger") == 0 || std::strcmp(key, "doHotkey") == 0) {
        lua_pushcfunction(L, l_hotkey_trigger);
        return 1;
    }
    if (std::strcmp(key, "destroy") == 0 || std::strcmp(key, "Destroy") == 0) {
        lua_pushcfunction(L, l_hotkey_destroy);
        return 1;
    }
    if (std::strcmp(key, "getKeys") == 0 || std::strcmp(key, "GetKeys") == 0) {
        lua_pushcfunction(L, l_hotkey_getKeys);
        return 1;
    }
    lua_pushnil(L);
    return 1;
}

static int l_hotkey_newindex(lua_State* L) {
    auto* hotkey = checkHotkey(L, 1);
    const char* key = luaL_checkstring(L, 2);
    if (std::strcmp(key, "Enabled") == 0 || std::strcmp(key, "enabled") == 0)
        hotkey->enabled = lua_toboolean(L, 3) != 0;
    return 0;
}

static void ensureHotkeyMetatable(lua_State* L) {
    if (luaL_newmetatable(L, "CEHotkey")) {
        lua_pushcfunction(L, l_hotkey_gc);
        lua_setfield(L, -2, "__gc");
        lua_pushcfunction(L, l_hotkey_index);
        lua_setfield(L, -2, "__index");
        lua_pushcfunction(L, l_hotkey_newindex);
        lua_setfield(L, -2, "__newindex");
    }
    lua_pop(L, 1);
}

static int l_createHotkey(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    ensureHotkeyMetatable(L);

    auto* hotkey = static_cast<LuaHotkey*>(lua_newuserdata(L, sizeof(LuaHotkey)));
    new (hotkey) LuaHotkey();
    lua_pushvalue(L, 1);
    hotkey->callbackRef = luaL_ref(L, LUA_REGISTRYINDEX);

    int top = lua_gettop(L);
    for (int i = 2; i < top; ++i) {
        if (lua_isinteger(L, i))
            hotkey->keys.push_back(static_cast<int>(lua_tointeger(L, i)));
    }

    luaL_getmetatable(L, "CEHotkey");
    lua_setmetatable(L, -2);
    return 1;
}

static int l_setHotkeyAction(lua_State* L) {
    auto* hotkey = checkHotkey(L, 1);
    luaL_checktype(L, 2, LUA_TFUNCTION);
    if (hotkey->callbackRef != LUA_NOREF)
        luaL_unref(L, LUA_REGISTRYINDEX, hotkey->callbackRef);
    lua_pushvalue(L, 2);
    hotkey->callbackRef = luaL_ref(L, LUA_REGISTRYINDEX);
    return 0;
}

// ── Thread helpers ──

struct LuaThread {
    int callbackRef = LUA_NOREF;
    bool finished = false;
    bool terminated = false;
    bool suspended = false;
    std::string name;
    std::string lastError;
};

static LuaThread* checkThread(lua_State* L, int index) {
    return static_cast<LuaThread*>(luaL_checkudata(L, index, "CEThread"));
}

static bool runThreadCallback(lua_State* L, LuaThread* thread) {
    if (thread->terminated || thread->finished || thread->callbackRef == LUA_NOREF)
        return true;

    thread->suspended = false;
    lua_rawgeti(L, LUA_REGISTRYINDEX, thread->callbackRef);
    if (lua_pcall(L, 0, 0, 0) != LUA_OK) {
        const char* err = lua_tostring(L, -1);
        thread->lastError = err ? err : "thread callback failed";
        lua_pop(L, 1);
        thread->finished = true;
        return false;
    }
    thread->finished = true;
    return true;
}

static int l_thread_gc(lua_State* L) {
    auto* thread = checkThread(L, 1);
    if (thread->callbackRef != LUA_NOREF) {
        luaL_unref(L, LUA_REGISTRYINDEX, thread->callbackRef);
        thread->callbackRef = LUA_NOREF;
    }
    thread->~LuaThread();
    return 0;
}

static int l_thread_waitfor(lua_State* L) {
    auto* thread = checkThread(L, 1);
    lua_pushboolean(L, thread->finished);
    return 1;
}

static int l_thread_terminate(lua_State* L) {
    auto* thread = checkThread(L, 1);
    thread->terminated = true;
    thread->finished = true;
    lua_pushboolean(L, 1);
    return 1;
}

static int l_thread_suspend(lua_State* L) {
    auto* thread = checkThread(L, 1);
    if (!thread->finished)
        thread->suspended = true;
    lua_pushboolean(L, 1);
    return 1;
}

static int l_thread_resume(lua_State* L) {
    auto* thread = checkThread(L, 1);
    bool ok = runThreadCallback(L, thread);
    lua_pushboolean(L, ok);
    if (!ok) {
        lua_pushstring(L, thread->lastError.c_str());
        return 2;
    }
    return 1;
}

static int l_thread_index(lua_State* L) {
    auto* thread = checkThread(L, 1);
    const char* key = luaL_checkstring(L, 2);
    if (std::strcmp(key, "Finished") == 0 || std::strcmp(key, "finished") == 0) {
        lua_pushboolean(L, thread->finished);
        return 1;
    }
    if (std::strcmp(key, "Terminated") == 0 || std::strcmp(key, "terminated") == 0) {
        lua_pushboolean(L, thread->terminated);
        return 1;
    }
    if (std::strcmp(key, "Suspended") == 0 || std::strcmp(key, "suspended") == 0) {
        lua_pushboolean(L, thread->suspended);
        return 1;
    }
    if (std::strcmp(key, "Name") == 0 || std::strcmp(key, "name") == 0) {
        lua_pushstring(L, thread->name.c_str());
        return 1;
    }
    if (std::strcmp(key, "LastError") == 0 || std::strcmp(key, "lastError") == 0) {
        lua_pushstring(L, thread->lastError.c_str());
        return 1;
    }
    if (std::strcmp(key, "waitfor") == 0 || std::strcmp(key, "waitFor") == 0) {
        lua_pushcfunction(L, l_thread_waitfor);
        return 1;
    }
    if (std::strcmp(key, "terminate") == 0 || std::strcmp(key, "Terminate") == 0) {
        lua_pushcfunction(L, l_thread_terminate);
        return 1;
    }
    if (std::strcmp(key, "suspend") == 0 || std::strcmp(key, "Suspend") == 0) {
        lua_pushcfunction(L, l_thread_suspend);
        return 1;
    }
    if (std::strcmp(key, "resume") == 0 || std::strcmp(key, "Resume") == 0) {
        lua_pushcfunction(L, l_thread_resume);
        return 1;
    }
    lua_pushnil(L);
    return 1;
}

static int l_thread_newindex(lua_State* L) {
    auto* thread = checkThread(L, 1);
    const char* key = luaL_checkstring(L, 2);
    if (std::strcmp(key, "Name") == 0 || std::strcmp(key, "name") == 0)
        thread->name = luaL_checkstring(L, 3);
    return 0;
}

static void ensureThreadMetatable(lua_State* L) {
    if (luaL_newmetatable(L, "CEThread")) {
        lua_pushcfunction(L, l_thread_gc);
        lua_setfield(L, -2, "__gc");
        lua_pushcfunction(L, l_thread_index);
        lua_setfield(L, -2, "__index");
        lua_pushcfunction(L, l_thread_newindex);
        lua_setfield(L, -2, "__newindex");
    }
    lua_pop(L, 1);
}

static int l_createThread(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    ensureThreadMetatable(L);

    bool suspended = lua_toboolean(L, 2) != 0;
    auto* thread = static_cast<LuaThread*>(lua_newuserdata(L, sizeof(LuaThread)));
    new (thread) LuaThread();
    thread->suspended = suspended;
    lua_pushvalue(L, 1);
    thread->callbackRef = luaL_ref(L, LUA_REGISTRYINDEX);

    luaL_getmetatable(L, "CEThread");
    lua_setmetatable(L, -2);

    if (!suspended)
        runThreadCallback(L, thread);
    return 1;
}

static int l_synchronize(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    int base = lua_gettop(L);
    lua_pushvalue(L, 1);
    if (lua_pcall(L, 0, LUA_MULTRET, 0) != LUA_OK)
        return lua_error(L);
    return lua_gettop(L) - base;
}

static int l_queue(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    lua_pushvalue(L, 1);
    if (lua_pcall(L, 0, 0, 0) != LUA_OK)
        return lua_error(L);
    lua_pushboolean(L, 1);
    return 1;
}

// ── Lua-defined custom types ──

static void ensureCustomTypeRegistry(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_custom_types");
    if (lua_istable(L, -1))
        return;

    lua_pop(L, 1);
    lua_newtable(L);
    lua_pushvalue(L, -1);
    lua_setfield(L, LUA_REGISTRYINDEX, "ce_custom_types");
}

static bool pushCustomType(lua_State* L, const char* name) {
    ensureCustomTypeRegistry(L);
    lua_getfield(L, -1, name);
    lua_remove(L, -2);
    return lua_istable(L, -1);
}

static std::string customBytesArg(lua_State* L, int index) {
    if (lua_isstring(L, index)) {
        size_t len = 0;
        const char* bytes = lua_tolstring(L, index, &len);
        return std::string(bytes, len);
    }

    luaL_checktype(L, index, LUA_TTABLE);
    std::string bytes;
    auto count = lua_rawlen(L, index);
    bytes.reserve(count);
    for (size_t i = 1; i <= count; ++i) {
        lua_rawgeti(L, index, static_cast<int>(i));
        int value = static_cast<int>(luaL_checkinteger(L, -1));
        lua_pop(L, 1);
        luaL_argcheck(L, value >= 0 && value <= 255, index, "byte values must be 0..255");
        bytes.push_back(static_cast<char>(value));
    }
    return bytes;
}

static int pushByteTableFromString(lua_State* L, const std::string& bytes) {
    lua_newtable(L);
    for (size_t i = 0; i < bytes.size(); ++i) {
        lua_pushinteger(L, static_cast<unsigned char>(bytes[i]));
        lua_rawseti(L, -2, static_cast<int>(i + 1));
    }
    return 1;
}

static int l_registerCustomTypeLua(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    int byteSize = static_cast<int>(luaL_checkinteger(L, 2));
    luaL_argcheck(L, byteSize > 0, 2, "byte size must be greater than zero");
    luaL_checktype(L, 3, LUA_TFUNCTION);
    luaL_checktype(L, 4, LUA_TFUNCTION);

    ensureCustomTypeRegistry(L);
    lua_newtable(L);
    lua_pushstring(L, name);
    lua_setfield(L, -2, "Name");
    lua_pushinteger(L, byteSize);
    lua_setfield(L, -2, "ByteSize");
    lua_pushvalue(L, 3);
    lua_setfield(L, -2, "BytesToValue");
    lua_pushvalue(L, 4);
    lua_setfield(L, -2, "ValueToBytes");
    lua_setfield(L, -2, name);
    lua_pop(L, 1);
    lua_pushboolean(L, 1);
    return 1;
}

static int l_unregisterCustomType(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    ensureCustomTypeRegistry(L);
    lua_pushnil(L);
    lua_setfield(L, -2, name);
    lua_pop(L, 1);
    lua_pushboolean(L, 1);
    return 1;
}

static int l_getCustomType(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    if (!pushCustomType(L, name)) {
        lua_pop(L, 1);
        lua_pushnil(L);
    }
    return 1;
}

static int l_getCustomTypeSize(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    if (!pushCustomType(L, name)) {
        lua_pop(L, 1);
        lua_pushnil(L);
        return 1;
    }
    lua_getfield(L, -1, "ByteSize");
    lua_remove(L, -2);
    return 1;
}

static int l_customTypeToValue(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    auto bytes = customBytesArg(L, 2);
    if (!pushCustomType(L, name)) {
        lua_pop(L, 1);
        lua_pushnil(L);
        lua_pushstring(L, "unknown custom type");
        return 2;
    }

    lua_getfield(L, -1, "BytesToValue");
    lua_remove(L, -2);
    lua_pushlstring(L, bytes.data(), bytes.size());
    if (lua_pcall(L, 1, 1, 0) != LUA_OK)
        return lua_error(L);
    return 1;
}

static int l_customTypeToBytes(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    if (!pushCustomType(L, name)) {
        lua_pop(L, 1);
        lua_pushnil(L);
        lua_pushstring(L, "unknown custom type");
        return 2;
    }

    lua_getfield(L, -1, "ValueToBytes");
    lua_remove(L, -2);
    lua_pushvalue(L, 2);
    if (lua_pcall(L, 1, 1, 0) != LUA_OK)
        return lua_error(L);

    if (lua_isstring(L, -1)) {
        size_t len = 0;
        const char* bytes = lua_tolstring(L, -1, &len);
        std::string copy(bytes, len);
        lua_pop(L, 1);
        return pushByteTableFromString(L, copy);
    }

    luaL_checktype(L, -1, LUA_TTABLE);
    return 1;
}

// ── Constants registration ──

static void registerConstants(lua_State* L) {
    // Scan types (CE compatible)
    lua_pushinteger(L, 0); lua_setglobal(L, "soExactValue");
    lua_pushinteger(L, 1); lua_setglobal(L, "soValueBetween");
    lua_pushinteger(L, 2); lua_setglobal(L, "soBiggerThan");
    lua_pushinteger(L, 3); lua_setglobal(L, "soSmallerThan");
    lua_pushinteger(L, 4); lua_setglobal(L, "soUnknownValue");
    lua_pushinteger(L, 5); lua_setglobal(L, "soIncreasedValue");
    lua_pushinteger(L, 6); lua_setglobal(L, "soDecreasedValue");
    lua_pushinteger(L, 7); lua_setglobal(L, "soChanged");
    lua_pushinteger(L, 8); lua_setglobal(L, "soUnchanged");
    lua_pushinteger(L, static_cast<int>(ScanCompare::SameAsFirst)); lua_setglobal(L, "soSameAsFirst");
    lua_pushinteger(L, 10); lua_setglobal(L, "soCustom");

    // Value types (CE compatible)
    lua_pushinteger(L, 0); lua_setglobal(L, "vtByte");
    lua_pushinteger(L, 1); lua_setglobal(L, "vtWord");
    lua_pushinteger(L, 2); lua_setglobal(L, "vtDword");
    lua_pushinteger(L, 3); lua_setglobal(L, "vtQword");
    lua_pushinteger(L, 4); lua_setglobal(L, "vtSingle");
    lua_pushinteger(L, 5); lua_setglobal(L, "vtDouble");
    lua_pushinteger(L, 6); lua_setglobal(L, "vtString");
    lua_pushinteger(L, 8); lua_setglobal(L, "vtByteArray");
    lua_pushinteger(L, 9); lua_setglobal(L, "vtBinary");
    lua_pushinteger(L, 10); lua_setglobal(L, "vtAll");
    lua_pushinteger(L, static_cast<int>(ValueType::Grouped)); lua_setglobal(L, "vtGrouped");
    lua_pushinteger(L, static_cast<int>(ValueType::Custom)); lua_setglobal(L, "vtCustom");
    lua_pushinteger(L, static_cast<int>(ValueType::Pointer)); lua_setglobal(L, "vtPointer");

    // Breakpoint types
    lua_pushinteger(L, 0); lua_setglobal(L, "bptExecute");
    lua_pushinteger(L, 1); lua_setglobal(L, "bptWrite");
    lua_pushinteger(L, 3); lua_setglobal(L, "bptAccess");

    // Message dialog types and modal results
    lua_pushinteger(L, 0); lua_setglobal(L, "mtWarning");
    lua_pushinteger(L, 1); lua_setglobal(L, "mtError");
    lua_pushinteger(L, 2); lua_setglobal(L, "mtInformation");
    lua_pushinteger(L, 3); lua_setglobal(L, "mtConfirmation");
    lua_pushinteger(L, 1); lua_setglobal(L, "mbOK");
    lua_pushinteger(L, 2); lua_setglobal(L, "mbCancel");
    lua_pushinteger(L, 6); lua_setglobal(L, "mbYes");
    lua_pushinteger(L, 7); lua_setglobal(L, "mbNo");
    lua_pushinteger(L, 1); lua_setglobal(L, "mrOK");
    lua_pushinteger(L, 2); lua_setglobal(L, "mrCancel");
    lua_pushinteger(L, 6); lua_setglobal(L, "mrYes");
    lua_pushinteger(L, 7); lua_setglobal(L, "mrNo");

    // Virtual key codes (common ones)
    lua_pushinteger(L, 0x70); lua_setglobal(L, "VK_F1");
    lua_pushinteger(L, 0x71); lua_setglobal(L, "VK_F2");
    lua_pushinteger(L, 0x72); lua_setglobal(L, "VK_F3");
    lua_pushinteger(L, 0x73); lua_setglobal(L, "VK_F4");
    lua_pushinteger(L, 0x74); lua_setglobal(L, "VK_F5");
    lua_pushinteger(L, 0x75); lua_setglobal(L, "VK_F6");
    lua_pushinteger(L, 0x76); lua_setglobal(L, "VK_F7");
    lua_pushinteger(L, 0x77); lua_setglobal(L, "VK_F8");
    lua_pushinteger(L, 0x78); lua_setglobal(L, "VK_F9");
    lua_pushinteger(L, 0x79); lua_setglobal(L, "VK_F10");
    lua_pushinteger(L, 0x7A); lua_setglobal(L, "VK_F11");
    lua_pushinteger(L, 0x7B); lua_setglobal(L, "VK_F12");
    lua_pushinteger(L, 0x13); lua_setglobal(L, "VK_PAUSE");
    lua_pushinteger(L, 0x0D); lua_setglobal(L, "VK_RETURN");
    lua_pushinteger(L, 0x20); lua_setglobal(L, "VK_SPACE");
    lua_pushinteger(L, 0x1B); lua_setglobal(L, "VK_ESCAPE");
}

// ── Registration function called from LuaEngine ──

// getSymbolInfo(name) -> {address=..., searchkey=name} or nil (CE-compatible).
static int l_getSymbolInfo(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    auto* resolver = getResolver(L);
    if (!resolver) { lua_pushnil(L); return 1; }
    uintptr_t addr = resolver->lookup(name);
    if (addr == 0) { lua_pushnil(L); return 1; }
    lua_newtable(L);
    lua_pushstring(L, "address");   lua_pushinteger(L, static_cast<lua_Integer>(addr)); lua_settable(L, -3);
    lua_pushstring(L, "searchkey"); lua_pushstring(L, name);                            lua_settable(L, -3);
    return 1;
}

// reinitializeSymbolhandler() -> reload symbols from the attached process (CE-compat).
static int l_reinitializeSymbolhandler(lua_State* L) {
    auto* resolver = getResolver(L);
    auto* proc = getProc(L);
    if (resolver && proc) {
        resolver->clear();
        resolver->loadProcess(*proc);
    }
    return 0;
}

// getRegionInfo(address) -> {BaseAddress, MemorySize, Protect [, Path]} for the
// mapped region that contains address, or nil if unmapped (CE-compat: CE returns
// a MEMORY_BASIC_INFORMATION-like table; field names mirror enumMemoryRegions).
static int l_getRegionInfo(lua_State* L) {
    uintptr_t addr = static_cast<uintptr_t>(luaL_checkinteger(L, 1));
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    for (auto& r : p->queryRegions()) {
        if (addr >= r.base && addr < r.base + r.size) {
            lua_newtable(L);
            lua_pushinteger(L, (lua_Integer)r.base);                 lua_setfield(L, -2, "BaseAddress");
            lua_pushinteger(L, (lua_Integer)r.size);                 lua_setfield(L, -2, "MemorySize");
            lua_pushinteger(L, (lua_Integer)(uint32_t)r.protection); lua_setfield(L, -2, "Protect");
            if (!r.path.empty()) { lua_pushstring(L, r.path.c_str()); lua_setfield(L, -2, "Path"); }
            return 1;
        }
    }
    lua_pushnil(L);
    return 1;
}

// Central exception firewall. liblua is C-compiled, so a C++ exception that
// escapes a lua_CFunction would unwind through non-exception-aware C frames
// (undefined behavior). This trampoline wraps every cecore binding and converts
// any escaping exception into a Lua error. The real function pointer travels as
// a light-userdata upvalue (function-pointer <-> void* is POSIX-guaranteed, and
// cecore is Linux-only). luaL_error longjmps out; the trampoline holds no
// non-trivial locals across that jump, so it is the standard Lua/C++ pattern.
static int ce_lua_firewall(lua_State* L) {
    auto fn = reinterpret_cast<lua_CFunction>(lua_touserdata(L, lua_upvalueindex(1)));
    try {
        return fn(L);
    } catch (const std::exception& e) {
        return luaL_error(L, "%s", e.what());
    } catch (...) {
        return luaL_error(L, "unhandled C++ exception in a cecore native binding");
    }
}
static inline void ce_register_guarded(lua_State* L, const char* name, lua_CFunction fn) {
    lua_pushlightuserdata(L, reinterpret_cast<void*>(fn));
    lua_pushcclosure(L, ce_lua_firewall, 1);
    lua_setglobal(L, name);
}
// Route every lua_register in registerExtendedBindings through the firewall
// (all 142 registrations funnel through this one macro; write*Local stays
// double-wrapped by its own gate, which is harmless).
#undef lua_register
#define lua_register(L, n, f) ce_register_guarded((L), (n), (f))

void registerExtendedBindings(lua_State* L) {
    // Memory read
    lua_register(L, "readByte", l_readByte);
    lua_register(L, "readSmallInteger", l_readSmallInteger);
    lua_register(L, "readShortInteger", l_readSmallInteger);   // CE alias (2-byte)
    lua_register(L, "readInteger", l_readInteger);
    lua_register(L, "readQword", l_readQword);
    lua_register(L, "readPointer", l_readPointer);
    lua_register(L, "readFloat", l_readFloat);
    lua_register(L, "readDouble", l_readDouble);
    lua_register(L, "readString", l_readString);
    lua_register(L, "readBytes", l_readBytes);
    lua_register(L, "readRegionToFile", l_readRegionToFile);
    lua_register(L, "writeRegionFromFile", l_writeRegionFromFile);
    lua_register(L, "getModuleAddress", l_getModuleAddress);
    lua_register(L, "compareMemory", l_compareMemory);
    lua_register(L, "floatToByteTable", l_floatToByteTable);
    lua_register(L, "doubleToByteTable", l_doubleToByteTable);
    lua_register(L, "byteTableToFloat", l_byteTableToFloat);
    lua_register(L, "byteTableToDouble", l_byteTableToDouble);
    lua_register(L, "byteTableToWord", l_byteTableToWord);
    lua_register(L, "byteTableToDword", l_byteTableToDword);
    lua_register(L, "byteTableToQword", l_byteTableToQword);
    lua_register(L, "byteTableToString", l_byteTableToString);
    lua_register(L, "stringToByteTable", l_stringToByteTable);
    lua_register(L, "stringToMD5String", l_stringToMD5String);
    lua_register(L, "bAnd", l_bAnd);
    lua_register(L, "bOr", l_bOr);
    lua_register(L, "bXor", l_bXor);
    lua_register(L, "bNot", l_bNot);
    lua_register(L, "bShl", l_bShl);
    lua_register(L, "bShr", l_bShr);
    lua_register(L, "wordToByteTable", l_wordToByteTable);
    lua_register(L, "dwordToByteTable", l_dwordToByteTable);
    lua_register(L, "qwordToByteTable", l_qwordToByteTable);
    lua_register(L, "byteTableToDwordTable", l_byteTableToDwordTable);
    lua_register(L, "extractFileName", l_extractFileName);
    lua_register(L, "extractFilePath", l_extractFilePath);
    lua_register(L, "extractFileExt", l_extractFileExt);
    lua_register(L, "getCEVersion", l_getCEVersion);

    // Memory write
    lua_register(L, "writeByte", l_writeByte);
    lua_register(L, "writeSmallInteger", l_writeSmallInteger);
    lua_register(L, "writeShortInteger", l_writeSmallInteger);  // CE alias (2-byte)
    lua_register(L, "writeInteger", l_writeInteger);
    lua_register(L, "writeQword", l_writeQword);
    lua_register(L, "writeFloat", l_writeFloat);
    lua_register(L, "writeDouble", l_writeDouble);
    lua_register(L, "writeString", l_writeString);
    lua_register(L, "writeBytes", l_writeBytes);

    // Local memory
    lua_register(L, "readByteLocal", l_readByteLocal);
    lua_register(L, "readSmallIntegerLocal", l_readSmallIntegerLocal);
    lua_register(L, "readIntegerLocal", l_readIntegerLocal);
    lua_register(L, "readQwordLocal", l_readQwordLocal);
    lua_register(L, "readPointerLocal", l_readPointerLocal);
    lua_register(L, "readFloatLocal", l_readFloatLocal);
    lua_register(L, "readDoubleLocal", l_readDoubleLocal);
    lua_register(L, "readBytesLocal", l_readBytesLocal);
    lua_register(L, "readStringLocal", l_readStringLocal);
    lua_register(L, "writeByteLocal", guardLocalWrite<l_writeByteLocal>);
    lua_register(L, "writeSmallIntegerLocal", guardLocalWrite<l_writeSmallIntegerLocal>);
    lua_register(L, "writeIntegerLocal", guardLocalWrite<l_writeIntegerLocal>);
    lua_register(L, "writeQwordLocal", guardLocalWrite<l_writeQwordLocal>);
    lua_register(L, "writePointerLocal", guardLocalWrite<l_writePointerLocal>);
    lua_register(L, "writeFloatLocal", guardLocalWrite<l_writeFloatLocal>);
    lua_register(L, "writeDoubleLocal", guardLocalWrite<l_writeDoubleLocal>);
    lua_register(L, "writeBytesLocal", guardLocalWrite<l_writeBytesLocal>);
    lua_register(L, "writeStringLocal", guardLocalWrite<l_writeStringLocal>);

    // Process info
    lua_register(L, "getProcessList", l_getProcessList);
    lua_register(L, "getProcessIDFromProcessName", l_getProcessIDFromProcessName);
    lua_register(L, "getModuleList", l_getModuleList);
    lua_register(L, "getModuleBase", l_getModuleBase);
    lua_register(L, "getModuleSize", l_getModuleSize);
    lua_register(L, "inModule", l_inModule);
    lua_register(L, "isAddress", l_isAddress);
    lua_register(L, "pause", l_pause);
    lua_register(L, "unpause", l_unpause);
    lua_register(L, "copyMemory", l_copyMemory);
    lua_register(L, "enumMemoryRegions", l_enumMemoryRegions);
    lua_register(L, "allocateMemory", l_allocateMemory);
    lua_register(L, "deAlloc", l_deAlloc);

    // Symbols
    lua_register(L, "getNameFromAddress", l_getNameFromAddress);
    lua_register(L, "getAddressFromName", l_getAddressFromName);

    // Disassembly / Assembly
    lua_register(L, "disassemble", l_disassemble);
    lua_register(L, "speedhack_setSpeed", l_speedhack_setSpeed);
    lua_register(L, "setSpeed", l_speedhack_setSpeed);   // convenience alias
    lua_register(L, "injectLibrary", l_injectLibrary);
    lua_register(L, "getInstructionSize", l_getInstructionSize);
    lua_register(L, "nopInstruction", l_nopInstruction);
    lua_register(L, "getPreviousOpcode", l_getPreviousOpcode);
    lua_register(L, "assemble", l_assemble);
    lua_register(L, "autoAssemble", l_autoAssemble);
    lua_register(L, "autoAssembleCheck", l_autoAssembleCheck);

    // Utility
    lua_register(L, "showMessage", l_showMessage);
    lua_register(L, "messageDialog", l_messageDialog);
    lua_register(L, "getScreenCanvas", l_getScreenCanvas);
    lua_register(L, "sleep", l_sleep);
    lua_register(L, "getTickCount", l_getTickCount);
    lua_register(L, "outputDebugString", l_outputDebugString);
    lua_register(L, "getCheatEngineDir",    l_getCheatEngineDir);
    lua_register(L, "getApplicationDir",    l_getApplicationDir);
    lua_register(L, "getTempPath",          l_getTempPath);
    lua_register(L, "getOperatingSystem",   l_getOperatingSystem);
    lua_register(L, "cheatEngineIs64Bit",   l_cheatEngineIs64Bit);
    lua_register(L, "targetIs64Bit",        l_targetIs64Bit);
    lua_register(L, "inputBox",             l_inputBox);

    // File I/O
    lua_register(L, "readFile", l_readFromFile);
    lua_register(L, "writeFile", l_writeToFile);
    lua_register(L, "readFromFile", l_readFromFile);
    lua_register(L, "writeToFile", l_writeToFile);
    lua_register(L, "fileExists", l_fileExists);
    lua_register(L, "getTempDir", l_getTempDir);
    lua_register(L, "getProcessDir", l_getProcessDir);

    // Scanning
    lua_register(L, "createMemScan", l_createMemScan);

    // Debug
    lua_register(L, "debug_getThreadList", l_debug_getThreadList);
    lua_register(L, "debug_setBreakpoint", l_debug_setBreakpoint);
    lua_register(L, "debug_pumpEvents", l_debug_pumpEvents);
    lua_register(L, "debug_removeBreakpoint", l_debug_removeBreakpoint);
    lua_register(L, "debug_continueFromBreakpoint", l_debug_continueFromBreakpoint);
    lua_register(L, "debug_getBreakpointList", l_debug_getBreakpointList);
    lua_register(L, "debug_isDebugging", l_debug_isDebugging);
    lua_register(L, "debug_isBroken", l_debug_isBroken);
    lua_register(L, "debug_getRegisters", l_debug_getRegisters);
    lua_register(L, "debug_setRegister", l_debug_setRegister);
    lua_register(L, "debug_getStack", l_debug_getStack);

    // Address list
    lua_register(L, "addressList_getCount", l_addressList_getCount);
    lua_register(L, "addressList_addEntry", l_addressList_addEntry);
    lua_register(L, "addressList_removeEntry", l_addressList_removeEntry);
    lua_register(L, "addressList_clear", l_addressList_clear);
    lua_register(L, "saveTable", l_saveTable);
    lua_register(L, "loadTable", l_loadTable);
    lua_register(L, "generateTrainer", l_generateTrainer);
    lua_register(L, "generateTrainerSource", l_generateTrainerSource);
    lua_register(L, "isKeyPressed", l_isKeyPressed);
    lua_register(L, "getManagedRuntimes", l_getManagedRuntimes);
    lua_register(L, "monoDissect", l_monoDissect);
    lua_register(L, "pointerScan", l_pointerScan);
    lua_register(L, "dissectStructure", l_dissectStructure);
    lua_register(L, "findWhatWrites", l_findWhatWrites);
    lua_register(L, "findWhatAccesses", l_findWhatAccesses);
    lua_register(L, "breakAndTrace", l_breakAndTrace);
    lua_register(L, "findStatics", l_findStatics);
    lua_register(L, "branchMap", l_branchMap);
    lua_register(L, "branchMapAvailable", l_branchMapAvailable);
    lua_register(L, "getTableEntry", l_getTableEntry);
    lua_register(L, "setTableEntry", l_setTableEntry);

    // Process
    lua_register(L, "openProcess", l_openProcess);
    lua_register(L, "connectToCeserver", l_connectToCeserver);
    lua_register(L, "getOpenedProcessID", l_getOpenedProcessID);
    lua_register(L, "getThreadList", l_getThreadList);

    // Extended memory
    lua_register(L, "writePointer", l_writePointer);

    // Symbols
    lua_register(L, "registerSymbol", l_registerSymbol);
    lua_register(L, "unregisterSymbol", l_unregisterSymbol);
    lua_register(L, "getSymbolInfo", l_getSymbolInfo);
    lua_register(L, "reinitializeSymbolhandler", l_reinitializeSymbolhandler);
    lua_register(L, "getRegionInfo", l_getRegionInfo);
    lua_register(L, "getUserDefinedSymbolByName", l_getUserDefinedSymbolByName);
    lua_register(L, "getUserDefinedSymbolByAddress", l_getUserDefinedSymbolByAddress);
    lua_register(L, "getOpenedProcesses", l_getOpenedProcesses);

    // AOB
    lua_register(L, "AOBScan", l_AOBScan);
    lua_register(L, "AOBScanModule", l_AOBScanModule);
    lua_register(L, "AOBScanEx", l_AOBScanEx);

    // Memory protection
    lua_register(L, "fullAccess", l_fullAccess);

    // Hotkeys
    lua_register(L, "createHotkey", l_createHotkey);
    lua_register(L, "setHotkeyAction", l_setHotkeyAction);

    // Thread helpers
    lua_register(L, "createThread", l_createThread);
    lua_register(L, "synchronize", l_synchronize);
    lua_register(L, "queue", l_queue);

    // Custom value types
    lua_register(L, "registerCustomTypeLua", l_registerCustomTypeLua);
    lua_register(L, "registerCustomType", l_registerCustomTypeLua);
    lua_register(L, "unregisterCustomType", l_unregisterCustomType);
    lua_register(L, "getCustomType", l_getCustomType);
    lua_register(L, "getCustomTypeSize", l_getCustomTypeSize);
    lua_register(L, "customTypeToValue", l_customTypeToValue);
    lua_register(L, "customTypeToBytes", l_customTypeToBytes);

    // File regions
    lua_register(L, "readRegionFromFile", l_readRegionFromFile);
    lua_register(L, "writeRegionToFile", l_writeRegionToFile);

    // UI
    lua_register(L, "inputQuery", l_inputQuery);
    lua_register(L, "shellExecute", l_shellExecute);
    lua_register(L, "getScreenWidth", l_getScreenWidth);
    lua_register(L, "getScreenHeight", l_getScreenHeight);

    // Misc
    lua_register(L, "inMainThread", l_inMainThread);
    lua_register(L, "setProcessName", l_setProcessName);
    lua_register(L, "getProcessName", l_getProcessName);

    // Constants
    registerConstants(L);

    // MemoryRecord / AddressList object surface
    registerMemoryRecordBindings(L);

    // Stream / StringList userdata (createMemoryStream, createFileStream,
    // createStringList)
    extern void registerStreamBindings(lua_State* L);
    registerStreamBindings(L);

    // captureSnapshot / loadSnapshot + Snapshot userdata methods.
    extern void registerSnapshotBindings(lua_State* L);
    registerSnapshotBindings(L);
}

} // namespace ce
