/// Lua bindings: utilities (MD5, bit operations, dialogs, file I/O, keys,
/// timers, string lists, sounds) and Lua-defined custom types.
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
int l_stringToMD5String(lua_State* L) {
    size_t len = 0;
    const char* s = luaL_checklstring(L, 1, &len);
    lua_pushstring(L, md5Hex(reinterpret_cast<const uint8_t*>(s), len).c_str());
    return 1;
}

// md5memory(address, size) -> MD5 hex of `size` bytes read from the target (nil on a
// failed read). Handy for tamper/change detection. No new capability: the script can
// already readBytes the same memory.
int l_md5memory(lua_State* L) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    lua_Integer size = luaL_checkinteger(L, 2);
    luaL_argcheck(L, size >= 0 && size <= (1 << 26), 2, "size out of range (0..64MB)");
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    std::vector<uint8_t> buf(static_cast<size_t>(size));
    auto r = p->read(addr, buf.data(), buf.size());
    if (!r) { lua_pushnil(L); return 1; }
    lua_pushstring(L, md5Hex(buf.data(), *r).c_str());   // hash the bytes actually read
    return 1;
}

// ── Bitwise-op compat family ──
// CE predates Lua 5.3's native &|~<<>> operators, so its scripts call bAnd/bOr/
// bXor/bNot/bShl/bShr. Provide them as 64-bit integer ops (matching modern CE and
// the vendored Lua 5.3 integer semantics). Shift counts are masked to [0,63] so a
// script-supplied count can never trigger undefined shift behaviour.
int l_bAnd(lua_State* L) {
    lua_pushinteger(L, luaL_checkinteger(L, 1) & luaL_checkinteger(L, 2));
    return 1;
}
int l_bOr(lua_State* L) {
    lua_pushinteger(L, luaL_checkinteger(L, 1) | luaL_checkinteger(L, 2));
    return 1;
}
int l_bXor(lua_State* L) {
    lua_pushinteger(L, luaL_checkinteger(L, 1) ^ luaL_checkinteger(L, 2));
    return 1;
}
int l_bNot(lua_State* L) {
    lua_pushinteger(L, ~luaL_checkinteger(L, 1));
    return 1;
}
int l_bShl(lua_State* L) {
    const uint64_t v = static_cast<uint64_t>(luaL_checkinteger(L, 1));
    const int n = static_cast<int>(luaL_checkinteger(L, 2)) & 63;
    lua_pushinteger(L, static_cast<lua_Integer>(v << n));
    return 1;
}
int l_bShr(lua_State* L) {
    // Logical (unsigned) shift, so high bits fill with zero regardless of sign.
    const uint64_t v = static_cast<uint64_t>(luaL_checkinteger(L, 1));
    const int n = static_cast<int>(luaL_checkinteger(L, 2)) & 63;
    lua_pushinteger(L, static_cast<lua_Integer>(v >> n));
    return 1;
}

// ── Utility ──

int l_showMessage(lua_State* L) {
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

int l_messageDialog(lua_State* L) {
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

int l_canvas_noop(lua_State* L) {
    const char* command = lua_tostring(L, lua_upvalueindex(1));
    appendCanvasCommand(L, command ? command : "draw");
    lua_pushboolean(L, 1);
    return 1;
}

int l_canvas_getTextWidth(lua_State* L) {
    size_t len = 0;
    luaL_checklstring(L, 2, &len);
    lua_pushinteger(L, (lua_Integer)len * 8);
    return 1;
}

int l_canvas_getTextHeight(lua_State* L) {
    lua_pushinteger(L, 16);
    return 1;
}

int l_canvas_getPixel(lua_State* L) {
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

int l_getScreenCanvas(lua_State* L) {
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

int l_sleep(lua_State* L) {
    lua_Integer ms = luaL_checkinteger(L, 1);
    if (ms < 0) ms = 0;
    struct timespec ts{ (time_t)(ms / 1000), (long)((ms % 1000) * 1000000) };
    nanosleep(&ts, nullptr);
    return 0;
}

// Milliseconds from a monotonic clock — CE scripts use this for timing/deltas.
int l_getTickCount(lua_State* L) {
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    lua_pushinteger(L, (lua_Integer)(ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL));
    return 1;
}

int l_outputDebugString(lua_State* L) {
    const char* s = luaL_checkstring(L, 1);
    fprintf(stderr, "%s\n", s);
    return 0;
}

int l_getCheatEngineDir(lua_State* L) {
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
int l_getApplicationDir(lua_State* L) {
    return l_getCheatEngineDir(L);
}

int l_getTempPath(lua_State* L) {
    if (auto* env = std::getenv("TMPDIR")) lua_pushstring(L, env);
    else lua_pushstring(L, "/tmp");
    return 1;
}

int l_getOperatingSystem(lua_State* L) {
    // CE returns 0 for Windows, 1 for macOS, 2 for Linux, 3 for Android.
    lua_pushinteger(L, 2);
    return 1;
}

int l_cheatEngineIs64Bit(lua_State* L) {
    lua_pushboolean(L, sizeof(void*) == 8);
    return 1;
}

int l_targetIs64Bit(lua_State* L) {
    auto* proc = getProc(L);
    lua_pushboolean(L, proc && proc->is64bit());
    return 1;
}

// Forward-declared so l_inputBox can delegate to it; the body lives later
// in the file alongside the other dialog helpers.
int l_inputQuery(lua_State* L);

// Tables sometimes call inputBox(title, prompt, default) directly. Forward
// to inputQuery's prompt-only form so the result matches CE's behaviour.
int l_inputBox(lua_State* L) {
    return l_inputQuery(L);
}

// ── File I/O ──

int l_readFromFile(lua_State* L) {
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
        throw std::runtime_error(std::string("readFile: ") + ex.what());   // the firewall reports it
    }
}

int l_writeToFile(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    size_t len;
    const char* data = luaL_checklstring(L, 2, &len);
    std::ofstream f;
    if (openNoFollow(f, path, std::ios::out | std::ios::binary | std::ios::trunc)) { f.write(data, len); lua_pushboolean(L, f.good()); }
    else lua_pushboolean(L, 0);
    return 1;
}

int l_fileExists(lua_State* L) {
    // std::error_code overload: the throwing one can raise filesystem_error out
    // of this C function into liblua (UB) on e.g. a permission-denied component.
    std::error_code ec;
    lua_pushboolean(L, std::filesystem::exists(luaL_checkstring(L, 1), ec) && !ec);
    return 1;
}

int l_getTempDir(lua_State* L) {
    std::error_code ec;
    auto dir = std::filesystem::temp_directory_path(ec);
    lua_pushstring(L, ec ? "/tmp" : dir.c_str());
    return 1;
}

int l_getProcessDir(lua_State* L) {
    auto pid=localTargetPid(getProc(L));
    if (!pid) { lua_pushstring(L, ""); return 1; }
    try {
        auto exe = std::filesystem::read_symlink("/proc/" + std::to_string(*pid) + "/exe");
        lua_pushstring(L, exe.parent_path().c_str());
    } catch (...) { lua_pushstring(L, ""); }
    return 1;
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

int l_isKeyPressed(lua_State* L) {
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

// ── CE timer API: createTimer([interval]) -> id; timer_setInterval(id, ms);
//    timer_onTimer(id, fn); timer_setEnabled(id, bool). Callbacks fire from the
//    engine's pumpTimers() (driven by the GUI). object_destroy(id) frees a timer.
int l_createTimer(lua_State* L) {
    auto* eng = ce::LuaEngine::instanceFromState(L);
    if (!eng) { lua_pushnil(L); return 1; }
    double interval = (lua_gettop(L) >= 1 && lua_isnumber(L, 1)) ? lua_tonumber(L, 1) : 1000;
    int id = eng->createTimer(interval);
    // CE also accepts createTimer(owner, enabled); if a function is passed, treat
    // it as the OnTimer callback for convenience.
    if (lua_gettop(L) >= 1 && lua_isfunction(L, 1)) {
        lua_pushvalue(L, 1);
        eng->setTimerCallback(id, luaL_ref(L, LUA_REGISTRYINDEX));
    }
    lua_pushinteger(L, id);
    return 1;
}
int l_timer_setInterval(lua_State* L) {
    auto* eng = ce::LuaEngine::instanceFromState(L);
    if (eng) eng->setTimerInterval((int)luaL_checkinteger(L, 1), luaL_checknumber(L, 2));
    return 0;
}
int l_timer_onTimer(lua_State* L) {
    auto* eng = ce::LuaEngine::instanceFromState(L);
    if (!eng) return 0;
    int id = (int)luaL_checkinteger(L, 1);
    if (lua_isnil(L, 2)) { eng->setTimerCallback(id, -1 /*clear*/); return 0; }
    luaL_checktype(L, 2, LUA_TFUNCTION);
    lua_pushvalue(L, 2);
    eng->setTimerCallback(id, luaL_ref(L, LUA_REGISTRYINDEX));
    return 0;
}
int l_timer_setEnabled(lua_State* L) {
    auto* eng = ce::LuaEngine::instanceFromState(L);
    if (eng) eng->setTimerEnabled((int)luaL_checkinteger(L, 1), lua_toboolean(L, 2));
    return 0;
}
int l_object_destroy(lua_State* L) {
    auto* eng = ce::LuaEngine::instanceFromState(L);
    if (eng && lua_isnumber(L, 1)) {
        int id = (int)lua_tointeger(L, 1);
        if (eng->isTimer(id)) eng->destroyTimer(id);
        else if (eng->isStringlist(id)) eng->destroyStringlist(id);
    }
    return 0;
}

// ── CE stringlist: createStringlist() -> id; stringlist_add(id, s);
//    stringlist_getCount(id); stringlist_getString(id, index) [0-based]; … ──
int l_createStringlist(lua_State* L) {
    auto* eng = ce::LuaEngine::instanceFromState(L);
    if (!eng) { lua_pushnil(L); return 1; }
    lua_pushinteger(L, eng->createStringlist());
    return 1;
}
int l_stringlist_add(lua_State* L) {
    auto* eng = ce::LuaEngine::instanceFromState(L);
    if (eng) eng->stringlistAdd((int)luaL_checkinteger(L, 1), luaL_checkstring(L, 2));
    return 0;
}
int l_stringlist_getCount(lua_State* L) {
    auto* eng = ce::LuaEngine::instanceFromState(L);
    lua_pushinteger(L, eng ? eng->stringlistCount((int)luaL_checkinteger(L, 1)) : 0);
    return 1;
}
int l_stringlist_getString(lua_State* L) {
    auto* eng = ce::LuaEngine::instanceFromState(L);
    if (!eng) { lua_pushnil(L); return 1; }
    std::string s = eng->stringlistGet((int)luaL_checkinteger(L, 1), (int)luaL_checkinteger(L, 2));
    lua_pushstring(L, s.c_str());
    return 1;
}
int l_stringlist_setString(lua_State* L) {
    auto* eng = ce::LuaEngine::instanceFromState(L);
    if (eng) eng->stringlistSet((int)luaL_checkinteger(L, 1), (int)luaL_checkinteger(L, 2), luaL_checkstring(L, 3));
    return 0;
}
int l_stringlist_remove(lua_State* L) {
    auto* eng = ce::LuaEngine::instanceFromState(L);
    if (eng) eng->stringlistRemove((int)luaL_checkinteger(L, 1), (int)luaL_checkinteger(L, 2));
    return 0;
}
int l_stringlist_clear(lua_State* L) {
    auto* eng = ce::LuaEngine::instanceFromState(L);
    if (eng) eng->stringlistClear((int)luaL_checkinteger(L, 1));
    return 0;
}

// selectFilePath(sender, settingName) -> path (or nil if cancelled/headless).
// Uses the host file-picker hook (the GUI opens a QFileDialog); nil when unset.
int l_selectFilePath(lua_State* L) {
    auto* eng = ce::LuaEngine::instanceFromState(L);
    const char* setting = lua_isstring(L, 2) ? lua_tostring(L, 2)
                        : (lua_isstring(L, 1) ? lua_tostring(L, 1) : "");
    std::string path = eng ? eng->pickFilePath(setting ? setting : "") : std::string();
    if (path.empty()) lua_pushnil(L); else lua_pushstring(L, path.c_str());
    return 1;
}

// playSound(path) — best-effort: play a WAV via paplay, then aplay, forked (no
// shell, so no injection). No-op if neither player exists.
int l_playSound(lua_State* L) {
    const char* path = lua_tostring(L, 1);
    if (!path || !*path) return 0;
    // Double fork: the player is re-parented to init, and the intermediate
    // child is reaped here, so repeated sounds leave no zombies behind.
    pid_t pid = fork();
    if (pid == 0) {
        if (fork() != 0) _exit(0);
        // Grandchild: detach from stdio, try paplay then aplay. "--" keeps a
        // path that starts with '-' from being read as an option.
        int devnull = ::open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, 1); dup2(devnull, 2); }
        execlp("paplay", "paplay", "--", path, (char*)nullptr);
        execlp("aplay", "aplay", "-q", "--", path, (char*)nullptr);
        _exit(127);
    }
    if (pid > 0) while (::waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {}
    return 0;
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

// Push the bytes argument (a string or a table of byte values) as a Lua
// string. Lua owns every intermediate value, so the checks below may raise.
static void pushCustomBytesArg(lua_State* L, int index) {
    // lua_isstring() is true for numbers; require a real string so a numeric arg
    // is rejected rather than silently converted to its decimal text ("5" -> 0x35).
    if (lua_type(L, index) == LUA_TSTRING) {
        lua_pushvalue(L, index);
        return;
    }
    luaL_checktype(L, index, LUA_TTABLE);
    const auto count = (lua_Integer)lua_rawlen(L, index);
    checkByteTable(L, index, 1, count, true);
    luaL_Buffer bytes;
    luaL_buffinit(L, &bytes);
    for (lua_Integer i = 1; i <= count; ++i) {
        lua_rawgeti(L, index, i);
        const char value = static_cast<char>(lua_tointeger(L, -1));
        lua_pop(L, 1);
        luaL_addchar(&bytes, value);
    }
    luaL_pushresult(&bytes);
}

static int pushByteTable(lua_State* L, const char* bytes, size_t length) {
    lua_createtable(L, static_cast<int>(std::min<size_t>(length, INT_MAX)), 0);
    for (size_t i = 0; i < length; ++i) {
        lua_pushinteger(L, static_cast<unsigned char>(bytes[i]));
        lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
    }
    return 1;
}

int l_registerCustomTypeLua(lua_State* L) {
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

int l_unregisterCustomType(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    ensureCustomTypeRegistry(L);
    lua_pushnil(L);
    lua_setfield(L, -2, name);
    lua_pop(L, 1);
    lua_pushboolean(L, 1);
    return 1;
}

int l_getCustomType(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    if (!pushCustomType(L, name)) {
        lua_pop(L, 1);
        lua_pushnil(L);
    }
    return 1;
}

int l_getCustomTypeSize(lua_State* L) {
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

int l_customTypeToValue(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    pushCustomBytesArg(L, 2);
    if (!pushCustomType(L, name)) {
        lua_pop(L, 1);
        lua_pushnil(L);
        lua_pushstring(L, "unknown custom type");
        return 2;
    }

    lua_getfield(L, -1, "BytesToValue");
    lua_remove(L, -2);
    lua_insert(L, -2);   // BytesToValue(bytes)
    if (lua_pcall(L, 1, 1, 0) != LUA_OK)
        return lua_error(L);
    return 1;
}

int l_customTypeToBytes(lua_State* L) {
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
        const char* bytes = lua_tolstring(L, -1, &len);   // stays on the stack below the table
        return pushByteTable(L, bytes, len);
    }

    luaL_checktype(L, -1, LUA_TTABLE);
    return 1;
}
} // namespace ce::lua_detail
