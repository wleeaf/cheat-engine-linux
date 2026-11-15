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
#include "scripting/lua_bindings_internal.hpp"

#undef lua_pushcfunction
#define lua_pushcfunction(L, f) ce::pushSafeLuaFunction((L), (f))

namespace ce {
using namespace lua_detail;

// Helper: get process handle from registry

namespace lua_detail {
ProcessHandle* getProc(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_proc");
    auto* p = (ProcessHandle*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    return p;
}
} // namespace lua_detail

SymbolResolver* luaSymbolResolver(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_resolver");
    auto* r = (SymbolResolver*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    // Like CE's symbol handler, symbols are available as soon as a process is
    // open: load the attached process on first use (a host such as the GUI
    // may already have filled it).
    if (r && r->count() == 0) {
        lua_getfield(L, LUA_REGISTRYINDEX, "ce_resolver_loaded");
        bool loaded = lua_toboolean(L, -1);
        lua_pop(L, 1);
        if (!loaded) {
            lua_getfield(L, LUA_REGISTRYINDEX, "ce_proc");
            auto* p = (ProcessHandle*)lua_touserdata(L, -1);
            lua_pop(L, 1);
            if (p) {
                r->loadProcess(*p);
                lua_pushboolean(L, 1);
                lua_setfield(L, LUA_REGISTRYINDEX, "ce_resolver_loaded");
            }
        }
    }
    return r;
}
namespace lua_detail {
SymbolResolver* getResolver(lua_State* L) { return luaSymbolResolver(L); }
} // namespace lua_detail

// Typed values use strings so 64-bit unsigned values remain exact in Lua.
static std::expected<ValueIoOptions, std::string> typedOptions(lua_State* L, int index, bool isSigned) {
    ValueIoOptions options; options.isSigned = isSigned;
    if (lua_isnoneornil(L, index)) return options;
    if (!lua_istable(L, index)) return std::unexpected("Options must be a table");
    std::string error;
    // Protect option lookups: __index may be a Lua function that raises an error.
    // A pcall keeps that error from longjmping across C++ option strings.
    auto field = [&](const char* name) {
        lua_pushcfunction(L, +[](lua_State* state) {
            lua_pushvalue(state, 2); lua_gettable(state, 1); return 1;
        });
        lua_pushvalue(L, index); lua_pushstring(L, name);
        if (lua_pcall(L, 2, 1, 0) == LUA_OK) return true;
        size_t length = 0; const char* message = lua_tolstring(L, -1, &length);
        error = message ? std::string(message, length) : "Option lookup failed";
        lua_pop(L, 1); return false;
    };
    auto boolean = [&](const char* name, bool& value) {
        if (!field(name)) return false;
        if (!lua_isnil(L, -1)) value = lua_toboolean(L, -1);
        lua_pop(L, 1); return true;
    };
    if (!boolean("hex", options.hex) || !boolean("signed", options.isSigned) ||
        !boolean("terminate", options.terminate)) return std::unexpected(error);
    if (!field("bigEndian")) return std::unexpected(error);
    if (!lua_isnil(L, -1)) {
        options.bigEndian = lua_toboolean(L, -1);
        options.byteOrder = options.bigEndian ? ByteOrder::Big : ByteOrder::Little;
    }
    lua_pop(L, 1);
    if (!field("size")) return std::unexpected(error);
    if (!lua_isnil(L, -1)) {
        int valid = 0; auto size = lua_tointegerx(L, -1, &valid);
        lua_pop(L, 1);
        if (!valid || size <= 0 || size > 256 * 1024 * 1024) return std::unexpected("Size must be between 1 byte and 256 MiB");
        options.size = static_cast<size_t>(size);
    } else lua_pop(L, 1);
    if (!field("encoding")) return std::unexpected(error);
    if (!lua_isnil(L, -1)) {
        const char* encoding = lua_tostring(L, -1);
        if (!encoding) { lua_pop(L, 1); return std::unexpected("Encoding must be a string"); }
        options.encoding = encoding;
    }
    lua_pop(L, 1);
    if (!field("codec")) return std::unexpected(error);
    if (!lua_isnil(L, -1)) {
        const char* text = lua_tostring(L, -1);
        auto codec = text ? ValueCodec::parse(text) : std::nullopt;
        lua_pop(L, 1);
        if (!codec) return std::unexpected("Invalid codec; use xor:0xKEY, add:N, rol:N or ror:N");
        options.codec = *codec;
    } else lua_pop(L, 1);
    return options;
}

static int typedValue(lua_State* L, bool write) {
    auto fail = [&](const std::string& error) {
        if (write) lua_pushboolean(L, false); else lua_pushnil(L);
        lua_pushlstring(L, error.data(), error.size());
        return 2;
    };
    const char* name = lua_tostring(L, 2);
    auto type = name ? parseValueType(name) : std::nullopt;
    if (!type) return fail("Unknown value type; use i32, u64, pointer, float, string, unicode or aob");
    bool isSigned = !(std::tolower(static_cast<unsigned char>(name[0])) == 'u' &&
                      std::isdigit(static_cast<unsigned char>(name[1])));
    // The options can run Lua (metatables) that closes or replaces the
    // process: read them before taking the process pointer.
    auto options = typedOptions(L, write ? 4 : 3, isSigned);
    if (!options) return fail(options.error());
    auto* process = getProc(L);
    if (!process) return fail("Open a process first");
    uintptr_t address = 0;
    if (lua_isinteger(L, 1)) address = static_cast<uintptr_t>(lua_tointeger(L, 1));
    else {
        const char* expression = lua_tostring(L, 1);
        auto parsed = expression ? ExpressionParser(process, getResolver(L)).parse(expression) : std::nullopt;
        if (!parsed) return fail("Cannot resolve the address expression");
        address = *parsed;
    }
    if (write) {
        size_t length = 0;
        const char* value = lua_tolstring(L, 3, &length);
        if (!value) return fail("Value must be a string or number");
        auto result = writeTypedValue(*process, address, *type, std::string_view(value, length), *options);
        if (!result) return fail(result.error());
        lua_pushboolean(L, true); lua_pushinteger(L, *result); return 2;
    }
    auto result = readTypedValue(*process, address, *type, *options);
    if (!result) return fail(result.error());
    lua_pushlstring(L, result->data(), result->size()); return 1;
}
static int l_readValue(lua_State* L) { return typedValue(L, false); }
static int l_writeValue(lua_State* L) { return typedValue(L, true); }

// The write*Local family stores to an ARBITRARY address inside cecore's OWN
// address space (reinterpret_cast<T*>(addr)), so an untrusted .CT could patch
// cecore's code/GOT/vtables to hijack the process (cecore is often run as root).
// Gate every write*Local behind the same out-of-band opt-in as shellExecute: an
// env var a Lua table cannot set. read*Local only leaks memory, so it stays open.
template <lua_CFunction Fn>
static int guardLocalWrite(lua_State* L) {
    if (!luaUnsafeAllowed(L))
        return luaL_error(L,
            "write*Local blocked: it writes cecore's own memory, which an untrusted "
            ".CT could use to hijack cecore. Enable only for scripts you trust by "
            "launching with CECORE_LUA_ALLOW_UNSAFE=1 (see SECURITY.md).");
    return Fn(L);
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
static int ce_lua_firewall(lua_State* L) { return ce::safeLuaCall(L); }
// ── CE Lua string extensions ────────────────────────────────────────────────
// printf(...) is print(string.format(...)); startsWith/endsWith/split are added to
// the `string` table so trainer scripts can call them as methods on a string
// (s:startsWith(p), s:endsWith(p), s:split(sep)). Pure string ops, no side effects.
static int l_printf(lua_State* L) {
    int n = lua_gettop(L);
    lua_getglobal(L, "string");
    lua_getfield(L, -1, "format");   // string.format
    lua_replace(L, -2);              // drop the string table, keep format
    lua_insert(L, 1);                // [format, args...]
    lua_call(L, n, 1);               // [formatted]
    lua_getglobal(L, "print");       // [formatted, print]
    lua_insert(L, 1);                // [print, formatted]
    lua_call(L, 1, 0);
    return 0;
}

static int l_string_startsWith(lua_State* L) {
    size_t sl = 0, pl = 0;
    const char* s = luaL_checklstring(L, 1, &sl);
    const char* p = luaL_checklstring(L, 2, &pl);
    lua_pushboolean(L, pl <= sl && std::memcmp(s, p, pl) == 0);
    return 1;
}

static int l_string_endsWith(lua_State* L) {
    size_t sl = 0, pl = 0;
    const char* s = luaL_checklstring(L, 1, &sl);
    const char* p = luaL_checklstring(L, 2, &pl);
    lua_pushboolean(L, pl <= sl && std::memcmp(s + (sl - pl), p, pl) == 0);
    return 1;
}

static int l_string_split(lua_State* L) {
    size_t sl = 0, sepl = 0;
    const char* s = luaL_checklstring(L, 1, &sl);
    const char* sep = luaL_checklstring(L, 2, &sepl);
    lua_newtable(L);
    int idx = 1;
    if (sepl == 0) {   // no separator: the whole string is the only element
        lua_pushlstring(L, s, sl);
        lua_rawseti(L, -2, idx++);
        return 1;
    }
    // Split on any character in `sep` (CE treats the argument as a separator set),
    // skipping empty segments so runs of separators don't produce "" entries.
    auto isSep = [&](char c) {
        for (size_t k = 0; k < sepl; ++k) if (sep[k] == c) return true;
        return false;
    };
    size_t start = 0;
    for (size_t i = 0; i <= sl; ++i) {
        if (i == sl || isSep(s[i])) {
            if (i > start) {
                lua_pushlstring(L, s + start, i - start);
                lua_rawseti(L, -2, idx++);
            }
            start = i + 1;
        }
    }
    return 1;
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

// Target information, typed values and memory reads and writes, here and local.
static void registerMemoryAccessBindings(lua_State* L) {
    lua_register(L, "getTargetInfo", l_getTargetInfo);
    lua_register(L, "getTargetCapabilities", l_getTargetCapabilities);
    lua_register(L, "retryPendingOperations", l_retryPendingOperations);
    lua_register(L, "resumePendingCallSignal", l_resumePendingCallSignal);
    lua_register(L, "readValue", l_readValue);
    lua_register(L, "writeValue", l_writeValue);
    // Memory read
    lua_register(L, "readByte", l_readByte);
    lua_register(L, "readSmallInteger", l_readSmallInteger);
    lua_register(L, "readShortInteger", l_readByte);   // CE alias: one byte, like readByte
    lua_register(L, "readInteger", l_readInteger);
    lua_register(L, "readQword", l_readQword);
    lua_register(L, "readPointer", l_readPointer);
    lua_register(L, "readFloat", l_readFloat);
    lua_register(L, "readDouble", l_readDouble);
    lua_register(L, "readString", l_readString);
    lua_register(L, "readBytes", l_readBytes);
    lua_register(L, "readRegionToFile", ce::guardFileWrite<l_readRegionToFile>);
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
    lua_register(L, "byteTableToWideString", l_byteTableToWideString);
    lua_register(L, "wideStringToByteTable", l_wideStringToByteTable);
    lua_register(L, "signExtend", l_signExtend);
    lua_register(L, "getCPUCount", l_getCPUCount);
    lua_register(L, "stringToMD5String", l_stringToMD5String);
    lua_register(L, "md5memory", l_md5memory);
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
    lua_register(L, "convertToUTF8", l_convertToUTF8);
    lua_register(L, "convertFromUTF8", l_convertFromUTF8);
    lua_register(L, "ansiToUTF8", l_ansiToUTF8);
    lua_register(L, "extractFileName", l_extractFileName);
    lua_register(L, "extractFilePath", l_extractFilePath);
    lua_register(L, "extractFileExt", l_extractFileExt);
    lua_register(L, "extractFileNameWithoutExt", l_extractFileNameWithoutExt);
    lua_register(L, "getFileList", l_getFileList);
    lua_register(L, "getCEVersion", l_getCEVersion);

    // Memory write
    lua_register(L, "writeByte", l_writeByte);
    lua_register(L, "writeSmallInteger", l_writeSmallInteger);
    lua_register(L, "writeShortInteger", l_writeByte);  // CE alias: one byte, like writeByte
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

}

// Process information, symbols, disassembly, utilities, files, scans and the debugger.
static void registerProcessCodeBindings(lua_State* L) {
    // Process info
    lua_register(L, "getProcessList", l_getProcessList);
    lua_register(L, "getProcessIDFromProcessName", l_getProcessIDFromProcessName);
    lua_register(L, "getModuleList", l_getModuleList);
    lua_register(L, "getModuleBase", l_getModuleBase);
    lua_register(L, "getModuleSize", l_getModuleSize);
    lua_register(L, "enumModules", l_enumModules);
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
    lua_register(L, "disassembleRange", l_disassembleRange);
    lua_register(L, "disassembleBytes", l_disassembleBytes);
    lua_register(L, "speedhack_setSpeed", l_speedhack_setSpeed);
    lua_register(L, "setSpeed", l_speedhack_setSpeed);   // convenience alias
    lua_register(L, "injectLibrary", l_injectLibrary);
    lua_register(L, "getInstructionSize", l_getInstructionSize);
    lua_register(L, "nopInstruction", l_nopInstruction);
    lua_register(L, "getPreviousOpcode", l_getPreviousOpcode);
    lua_register(L, "assemble", l_assemble);
    lua_register(L, "autoAssemble", l_autoAssemble);
    lua_register(L, "autoAssembleCheck", l_autoAssembleCheck);
    lua_register(L, "generateCodeInjectionScript", l_generateCodeInjectionScript);
    lua_register(L, "generateAOBInjectionScript", l_generateAOBInjectionScript);
    lua_register(L, "generateFullInjectionScript", l_generateFullInjectionScript);

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
    lua_register(L, "getPointerSize",        l_getPointerSize);
    lua_register(L, "getMemoryRegionInfo",   l_getMemoryRegionInfo);
    lua_register(L, "inputBox",             l_inputBox);

    // File I/O
    lua_register(L, "readFile", l_readFromFile);
    lua_register(L, "writeFile", ce::guardFileWrite<l_writeToFile>);   // an alias must not skip the opt-in
    lua_register(L, "readFromFile", l_readFromFile);
    lua_register(L, "writeToFile", ce::guardFileWrite<l_writeToFile>);
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

}

// The address list, processes, AOB scans, hotkeys, threads, custom types, UI and the userdata types.
static void registerTableToolBindings(lua_State* L) {
    // Address list
    lua_register(L, "addressList_getCount", l_addressList_getCount);
    lua_register(L, "addressList_addEntry", l_addressList_addEntry);
    lua_register(L, "addressList_removeEntry", l_addressList_removeEntry);
    lua_register(L, "addressList_clear", l_addressList_clear);
    lua_register(L, "saveTable", ce::guardFileWrite<l_saveTable>);
    lua_register(L, "loadTable", l_loadTable);
    lua_register(L, "generateTrainer", ce::guardFileWrite<l_generateTrainer>);
    lua_register(L, "generateTrainerSource", l_generateTrainerSource);
    lua_register(L, "isKeyPressed", l_isKeyPressed);
    lua_register(L, "createTimer", l_createTimer);
    lua_register(L, "timer_setInterval", l_timer_setInterval);
    lua_register(L, "timer_onTimer", l_timer_onTimer);
    lua_register(L, "timer_setEnabled", l_timer_setEnabled);
    lua_register(L, "object_destroy", l_object_destroy);
    lua_register(L, "createStringlist", l_createStringlist);
    lua_register(L, "stringlist_add", l_stringlist_add);
    lua_register(L, "stringlist_getCount", l_stringlist_getCount);
    lua_register(L, "stringlist_getString", l_stringlist_getString);
    lua_register(L, "stringlist_setString", l_stringlist_setString);
    lua_register(L, "stringlist_remove", l_stringlist_remove);
    lua_register(L, "stringlist_clear", l_stringlist_clear);
    lua_register(L, "selectFilePath", l_selectFilePath);
    lua_register(L, "playSound", l_playSound);
    lua_register(L, "getManagedRuntimes", l_getManagedRuntimes);
    lua_register(L, "monoDissect", l_monoDissect);
    lua_register(L, "findMonoFunction", l_findMonoFunction);
    lua_register(L, "findMonoInstances", l_findMonoInstances);
    lua_register(L, "executeCode", l_executeCode);
    lua_register(L, "createSignature", l_createSignature);
    lua_register(L, "getIl2CppMetadataPath", l_getIl2CppMetadataPath);
    lua_register(L, "getIl2CppClasses", l_getIl2CppClasses);
    lua_register(L, "getIl2CppClassLayout", l_getIl2CppClassLayout);
    lua_register(L, "getIl2CppObjectLayout", l_getIl2CppObjectLayout);
    lua_register(L, "getIl2CppStructure", l_getIl2CppStructure);
    lua_register(L, "getDwarfStructure", l_getDwarfStructure);
    lua_register(L, "listDwarfStructs", l_listDwarfStructs);
    lua_register(L, "getIl2CppMethods", l_getIl2CppMethods);
    lua_register(L, "findIl2CppMethod", l_findIl2CppMethod);
    lua_register(L, "createSimpleHook", l_createSimpleHook);
    lua_register(L, "removeSimpleHook", l_removeSimpleHook);
    lua_register(L, "pointerScan", l_pointerScan);
    lua_register(L, "dissectStructure", l_dissectStructure);
    lua_register(L, "findWhatWrites", l_findWhatWrites);
    lua_register(L, "findWhatAccesses", l_findWhatAccesses);
    lua_register(L, "findReferences", l_findReferences);
    lua_register(L, "enumerateFunctions", l_enumerateFunctions);
    lua_register(L, "buildCallGraph", l_buildCallGraph);
    lua_register(L, "findReferencedStrings", l_findReferencedStrings);
    lua_register(L, "findCodeCaves", l_findCodeCaves);
    lua_register(L, "findAssemblyPattern", l_findAssemblyPattern);
    lua_register(L, "getModuleExports", l_getModuleExports);
    lua_register(L, "getModuleImports", l_getModuleImports);
    lua_register(L, "breakAndTrace", l_breakAndTrace);
    lua_register(L, "findStatics", l_findStatics);
    lua_register(L, "branchMap", l_branchMap);
    lua_register(L, "branchMapAvailable", l_branchMapAvailable);
    lua_register(L, "getTableEntry", l_getTableEntry);
    lua_register(L, "setTableEntry", l_setTableEntry);

    // Process
    lua_register(L, "openProcess", l_openProcess);
    lua_register(L, "connectToCeserver", l_connectToCeserver);
    lua_register(L, "connectToGdb", l_connectToGdb);
    lua_register(L, "disconnectProcess", l_disconnectProcess);
    lua_register(L, "getGdbRegisterInfo", l_getGdbRegisterInfo);
    lua_register(L, "readGdbRegister", l_readGdbRegister);
    lua_register(L, "writeGdbRegister", l_writeGdbRegister);
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
    lua_register(L, "AOBScanUnique", l_AOBScanUnique);
    lua_register(L, "AOBScanModuleUnique", l_AOBScanModuleUnique);
    lua_register(L, "getUniqueAOB", l_getUniqueAOB);
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
    lua_register(L, "writeRegionToFile", ce::guardFileWrite<l_writeRegionToFile>);

    // UI
    lua_register(L, "inputQuery", l_inputQuery);
    lua_register(L, "shellExecute", l_shellExecute);
    lua_register(L, "getScreenWidth", l_getScreenWidth);
    lua_register(L, "getScreenHeight", l_getScreenHeight);

    // Misc
    lua_register(L, "inMainThread", l_inMainThread);
    lua_register(L, "getProcessName", l_getProcessName);

    // CE Lua string extensions: printf global + startsWith/endsWith/split string methods.
    lua_register(L, "printf", l_printf);
    lua_getglobal(L, "string");
    if (lua_istable(L, -1)) {
        lua_pushcfunction(L, l_string_startsWith); lua_setfield(L, -2, "startsWith");
        lua_pushcfunction(L, l_string_endsWith);   lua_setfield(L, -2, "endsWith");
        lua_pushcfunction(L, l_string_split);      lua_setfield(L, -2, "split");
    }
    lua_pop(L, 1);

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

void registerExtendedBindings(lua_State* L) {
    registerMemoryAccessBindings(L);
    registerProcessCodeBindings(L);
    registerTableToolBindings(L);
}

} // namespace ce
