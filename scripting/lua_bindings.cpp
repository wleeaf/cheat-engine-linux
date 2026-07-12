/// Extended Lua API bindings — CE-compatible function set.
#include <charconv>
#include <csignal>
#include "scripting/lua_engine.hpp"
#include "scripting/lua_memrec.hpp"
#include "scanner/memory_scanner.hpp"
#include "scanner/pointer_scanner.hpp"
#include "core/autoasm.hpp"
#include "arch/disassembler.hpp"
#include "arch/assembler.hpp"
#include "symbols/elf_symbols.hpp"
#include "platform/linux/linux_process.hpp"
#include "platform/linux/injector.hpp"

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

    ensureLuaBreakpointList(L);
    int id = nextLuaBreakpointId(L);

    lua_newtable(L);
    lua_pushinteger(L, id); lua_setfield(L, -2, "id");
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

static int l_debug_removeBreakpoint(lua_State* L) {
    int id = static_cast<int>(luaL_checkinteger(L, 1));
    ensureLuaBreakpointList(L);
    lua_pushnil(L);
    lua_rawseti(L, -2, id);
    lua_pop(L, 1);
    lua_pushboolean(L, 1);
    return 1;
}

static int l_debug_continueFromBreakpoint(lua_State* L) {
    (void)L;
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
    lua_register(L, "byteTableToString", l_byteTableToString);
    lua_register(L, "stringToByteTable", l_stringToByteTable);
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
    lua_register(L, "debug_removeBreakpoint", l_debug_removeBreakpoint);
    lua_register(L, "debug_continueFromBreakpoint", l_debug_continueFromBreakpoint);
    lua_register(L, "debug_getBreakpointList", l_debug_getBreakpointList);
    lua_register(L, "debug_isDebugging", l_debug_isDebugging);
    lua_register(L, "debug_isBroken", l_debug_isBroken);

    // Address list
    lua_register(L, "addressList_getCount", l_addressList_getCount);
    lua_register(L, "addressList_addEntry", l_addressList_addEntry);
    lua_register(L, "addressList_removeEntry", l_addressList_removeEntry);
    lua_register(L, "addressList_clear", l_addressList_clear);
    lua_register(L, "getTableEntry", l_getTableEntry);
    lua_register(L, "setTableEntry", l_setTableEntry);

    // Process
    lua_register(L, "openProcess", l_openProcess);
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
