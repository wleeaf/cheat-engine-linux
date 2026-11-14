/// Lua bindings: disassembling, assembling and Auto Assembler scripts.
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

// ── Disassembly / Assembly ──

// speedhack_setSpeed(factor) — write the speed multiplier to the shared-memory
// channel the injected speedhack plugin (plugins/speedhack.c) reads. Matches the
// GUI "Speedhack…" dialog: a double at /dev/shm/ce_speedhack, opened O_NOFOLLOW,
// mode 0600, and confirmed to be a regular file before mapping. The target must
// have been started with LD_PRELOAD=libspeedhack.so for this to take effect.
int l_speedhack_setSpeed(lua_State* L) {
    double speed = luaL_checknumber(L, 1);
    if (!(speed >= 0.01 && speed <= 1000.0)) { lua_pushboolean(L, 0); return 1; }
    int fd = ::open("/dev/shm/ce_speedhack", O_CREAT | O_RDWR | O_NOFOLLOW, 0600);
    if (fd < 0) { lua_pushboolean(L, 0); return 1; }
    bool ok = false;
    struct stat st{};
    if (::fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == ::geteuid() && !(st.st_mode & 077) && ::ftruncate(fd, sizeof(double)) == 0) {
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
int l_injectLibrary(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); lua_pushstring(L, "no process attached"); return 2; }
    size_t pathLength=0;
    const char* path = luaL_checklstring(L, 1, &pathLength);
    auto* resolver = getResolver(L);
    ce::SymbolResolver localResolver;
    if (!resolver) {
        localResolver.loadProcess(*p);
        resolver=&localResolver;
    }
    // dlopen runs in the target: a relative path would resolve against its
    // working directory, and a sandboxed target sees its own filesystem.
    std::string target(path,pathLength);
    std::error_code pathError;
    if (target.find('\0')==std::string::npos && std::filesystem::exists(target,pathError)) {
        auto absolute=std::filesystem::absolute(target,pathError);
        if (!pathError) target=absolute.lexically_normal().string();
        if (p->targetDescription().transport==ce::TargetTransport::Local)
            if (auto task=ce::os::processMemoryTask(p->pid())) target=ce::os::targetVisiblePath(*task,target);
    }
    auto r = ce::os::injectLibrary(*p, *resolver, target);
    if (!r) { lua_pushnil(L); lua_pushstring(L, r.error().c_str()); return 2; }
    lua_pushinteger(L, static_cast<lua_Integer>(*r));
    return 1;
}

int l_disassemble(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    uint8_t buf[16];
    auto r = p->read(addr, buf, sizeof(buf));
    if (!r) { lua_pushnil(L); return 1; }

    auto architecture = disassemblerArchFor(*p, addr);
    if (!architecture) { lua_pushnil(L); lua_pushstring(L, architecture.error().c_str()); return 2; }
    Disassembler dis(*architecture);
    auto insns = dis.disassemble(addr, {buf, *r}, 1);
    if (insns.empty()) { lua_pushnil(L); return 1; }

    lua_pushstring(L, (insns[0].mnemonic + " " + insns[0].operands).c_str());
    lua_pushinteger(L, insns[0].size);
    lua_pushinteger(L, (lua_Integer)insns[0].ripTarget);
    return 3; // returns instruction_text, size, ripTarget (0 if not RIP-relative)
}

// disassembleRange(address [, count=16]) -> { {address, size, text, ripTarget}, ...}
// Decodes `count` instructions from `address` in the target. Handy for dumping a
// function or feeding a decoded stream to analysis; disassemble() returns only one.
int l_disassembleRange(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); lua_pushstring(L, "no target process"); return 2; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    int count = (lua_gettop(L) >= 2 && !lua_isnil(L, 2)) ? (int)luaL_checkinteger(L, 2) : 16;
    if (count < 1) count = 1;
    if (count > 4096) count = 4096;
    std::vector<uint8_t> buf(static_cast<size_t>(count) * 15 + 16);
    auto r = p->read(addr, buf.data(), buf.size());
    if (!r || *r == 0) { lua_pushnil(L); lua_pushstring(L, "read failed"); return 2; }

    auto architecture = disassemblerArchFor(*p, addr);
    if (!architecture) { lua_pushnil(L); lua_pushstring(L, architecture.error().c_str()); return 2; }
    Disassembler dis(*architecture);
    auto insns = dis.disassemble(addr, {buf.data(), *r}, (size_t)count);
    lua_newtable(L);
    int i = 1;
    for (const auto& in : insns) {
        lua_newtable(L);
        lua_pushinteger(L, (lua_Integer)in.address);  lua_setfield(L, -2, "address");
        lua_pushinteger(L, in.size);                  lua_setfield(L, -2, "size");
        lua_pushstring(L, (in.mnemonic + " " + in.operands).c_str()); lua_setfield(L, -2, "text");
        if (in.ripTarget) { lua_pushinteger(L, (lua_Integer)in.ripTarget); lua_setfield(L, -2, "ripTarget"); }
        lua_rawseti(L, -2, i++);
    }
    return 1;
}

// disassembleBytes(hexstring | {bytetable}[, address]) -> text, size, ripTarget.
// CE parity: disassemble raw bytes with no process attached. Accepts a hex string
// ("48 89 5C" or "48895C", separators ignored) or a byte table. `address` (default 0)
// only affects RIP-relative operand math. Returns the first instruction's text, its
// byte length, and the absolute RIP target (0 if not RIP-relative), or nil if the bytes
// don't decode.
int l_disassembleBytes(lua_State* L) {
    // Every argument check before the vector exists (a raise would leak it).
    if (lua_istable(L, 1)) checkByteTable(L, 1, 1, (lua_Integer)lua_rawlen(L, 1), true);
    else luaL_checkstring(L, 1);
    const uintptr_t addr = (uintptr_t)luaL_optinteger(L, 2, 0);
    std::vector<uint8_t> bytes;
    if (lua_istable(L, 1)) {
        int n = (int)lua_rawlen(L, 1);
        bytes.reserve(n);
        for (int i = 1; i <= n; ++i) {
            lua_rawgeti(L, 1, i);
            bytes.push_back((uint8_t)lua_tointeger(L, -1));
            lua_pop(L, 1);
        }
    } else {
        const char* s = luaL_checkstring(L, 1);
        int hi = -1;
        for (const char* c = s; *c; ++c) {
            int nib;
            if (*c >= '0' && *c <= '9')      nib = *c - '0';
            else if (*c >= 'a' && *c <= 'f') nib = *c - 'a' + 10;
            else if (*c >= 'A' && *c <= 'F') nib = *c - 'A' + 10;
            else continue;   // ignore spaces, commas, and other separators
            if (hi < 0) hi = nib;
            else { bytes.push_back((uint8_t)((hi << 4) | nib)); hi = -1; }
        }
    }
    if (bytes.empty()) { lua_pushnil(L); return 1; }

    // Use the target's bitness if attached, else CE's default 64-bit mode.
    auto* p = getProc(L);
    auto architecture = p ? disassemblerArchFor(*p, addr) : std::expected<Arch, std::string>(Arch::X86_64);
    if (!architecture) { lua_pushnil(L); lua_pushstring(L, architecture.error().c_str()); return 2; }
    Disassembler dis(*architecture);
    auto insns = dis.disassemble(addr, {bytes.data(), bytes.size()}, 1);
    if (insns.empty()) { lua_pushnil(L); return 1; }
    lua_pushstring(L, (insns[0].mnemonic + " " + insns[0].operands).c_str());
    lua_pushinteger(L, insns[0].size);
    lua_pushinteger(L, (lua_Integer)insns[0].ripTarget);
    return 3;
}

// getInstructionSize(address) -> byte length of the instruction at address.
int l_getInstructionSize(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    uint8_t buf[16];
    auto r = p->read(addr, buf, sizeof(buf));
    if (!r) { lua_pushnil(L); return 1; }
    auto architecture = disassemblerArchFor(*p, addr);
    if (!architecture) { lua_pushnil(L); lua_pushstring(L, architecture.error().c_str()); return 2; }
    Disassembler dis(*architecture);
    auto insns = dis.disassemble(addr, {buf, *r}, 1);
    if (insns.empty()) { lua_pushnil(L); return 1; }
    lua_pushinteger(L, insns[0].size);
    return 1;
}
// nopInstruction(address) -> table of the instruction's original bytes (for undo),
// or nil. Overwrites the instruction at `address` with length-preserving NOPs
// (CE's "replace with code that does nothing"). Restore by writeBytes(address, t).
int l_nopInstruction(lua_State* L) {
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
int l_getPreviousOpcode(lua_State* L) {
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
    auto architecture = disassemblerArchFor(*p, addr);
    if (!architecture) { lua_pushnil(L); lua_pushstring(L, architecture.error().c_str()); return 2; }
    Disassembler dis(*architecture);
    uintptr_t prev = dis.previousInstruction(addr, [&](uintptr_t a, uint8_t* buf, size_t n) {
        auto r = p->read(a, buf, n);
        return r && *r >= n;
    });
    lua_pushinteger(L, (lua_Integer)prev);
    return 1;
}

int l_assemble(lua_State* L) {
    const char* code = luaL_checkstring(L, 1);
    uintptr_t addr = (uintptr_t)luaL_optinteger(L, 2, 0);

    auto* p = getProc(L);   // match the attached target's bitness when one is open
    auto architecture = p ? disassemblerArchFor(*p, addr) : std::expected<Arch, std::string>(Arch::X86_64);
    if (!architecture) { lua_pushnil(L); lua_pushstring(L, architecture.error().c_str()); return 2; }
    auto assemblerArch = assemblerArchFor(*architecture);
    if (!assemblerArch) { lua_pushnil(L); lua_pushstring(L, assemblerArch.error().c_str()); return 2; }
    Assembler asm64(*assemblerArch);
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

// CE parity: autoAssemble(script) -> true, disableInfo | false, error, and
// autoAssemble(script, disableInfo) undoes that activation (the [DISABLE]
// semantics: original bytes, protections and allocations are restored).
static const char* kAADisableInfo = "ce.AADisableInfo";
int l_aaDisableInfoGc(lua_State* L) {
    static_cast<DisableInfo*>(luaL_checkudata(L, 1, kAADisableInfo))->~DisableInfo();
    return 0;
}
int l_autoAssemble(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushboolean(L, 0); lua_pushstring(L, "no process"); return 2; }
    const char* script = luaL_checkstring(L, 1);
    if (auto* info = static_cast<DisableInfo*>(luaL_testudata(L, 2, kAADisableInfo))) {
        AutoAssembler aa;
        auto result = aa.disable(*p, script, *info);
        lua_pushboolean(L, result.success);
        if (result.success) { *info = {}; lua_pushnil(L); }   // a second disable is a no-op
        else lua_pushstring(L, result.error.c_str());
        return 2;
    }
    if (lua_toboolean(L, 2) && !lua_isuserdata(L, 2)) {
        lua_pushboolean(L, 0); lua_pushstring(L, "assembling into Cheat Engine itself (targetself) is not supported");
        return 2;
    }

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
    if (!result.success) {
        lua_pushstring(L, result.error.c_str());
        return 2;
    }
    auto* info = static_cast<DisableInfo*>(lua_newuserdata(L, sizeof(DisableInfo)));
    new (info) DisableInfo(std::move(result.disableInfo));
    if (luaL_newmetatable(L, kAADisableInfo)) {
        lua_pushcfunction(L, l_aaDisableInfoGc);
        lua_setfield(L, -2, "__gc");
        // Out of reach of scripts: calling __gc by hand would destroy it twice.
        lua_pushliteral(L, "locked");
        lua_setfield(L, -2, "__metatable");
    }
    lua_setmetatable(L, -2);
    return 2;
}

// generateCodeInjectionScript(address) / generateAOBInjectionScript(address) /
// generateFullInjectionScript(address) -> script text, or nil plus error.
// The address may be a number or an expression ("game+1234", a symbol). CE
// appends to a TStrings; here the generated script is returned as a string.
static int injectionScript(lua_State* L, InjectionKind kind) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); lua_pushstring(L, "no process attached"); return 2; }
    uintptr_t address = 0;
    if (lua_isinteger(L, 1)) address = static_cast<uintptr_t>(lua_tointeger(L, 1));
    else if (auto parsed = ExpressionParser(p, getResolver(L)).parse(luaL_checkstring(L, 1))) address = *parsed;
    if (!address) { lua_pushnil(L); lua_pushstring(L, "cannot resolve the injection address"); return 2; }
    std::string error;
    auto script = generateInjectionScript(*p, address, kind, error);
    if (script.empty()) { lua_pushnil(L); lua_pushstring(L, error.empty() ? "injection script generation failed" : error.c_str()); return 2; }
    lua_pushstring(L, script.c_str());
    return 1;
}
int l_generateCodeInjectionScript(lua_State* L) { return injectionScript(L, InjectionKind::Code); }
int l_generateAOBInjectionScript(lua_State* L) { return injectionScript(L, InjectionKind::Aob); }
int l_generateFullInjectionScript(lua_State* L) { return injectionScript(L, InjectionKind::Full); }

int l_autoAssembleCheck(lua_State* L) {
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
} // namespace ce::lua_detail
