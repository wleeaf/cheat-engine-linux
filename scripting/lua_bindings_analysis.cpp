/// Lua bindings: code analysis (statics, references, exports, imports, call
/// graph, strings, code caves, assembly patterns).
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

// ── Find Statics (module-relative addresses referenced by code) ──
// findStatics([moduleName]) -> array of { address, references }, sorted by the
// analyzer. Defaults to the main/executable module (first in the module list).
int l_findStatics(lua_State* L) {
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
    ce::CodeAnalyzer analyzer(ce::analyzerArchFor(*p));
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

static const char* refTypeName(ce::RefType t) {
    switch (t) {
        case ce::RefType::Call:            return "call";
        case ce::RefType::Jump:            return "jump";
        case ce::RefType::String:          return "string";
        case ce::RefType::Function:        return "function";
        case ce::RefType::RipRelative:     return "riprel";
        case ce::RefType::AssemblyPattern: return "pattern";
    }
    return "?";
}

// findReferences(target [, moduleName]) -> { {address, target, type, text}, ... }
// Static "find what references this address": disassembles a module and lists
// every call/jump/rip-relative instruction whose target is `target`. Unlike
// findWhatAccesses (which watches at runtime), this finds ALL references without
// executing. Defaults to the module containing `target`; pass a module name to
// scan a different one.
int l_findReferences(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); lua_pushstring(L, "no target process"); return 2; }
    uintptr_t target = (uintptr_t)luaL_checkinteger(L, 1);
    std::string modName = (lua_gettop(L) >= 2 && !lua_isnil(L, 2)) ? luaL_checkstring(L, 2) : "";

    auto modules = p->modules();
    const ce::ModuleInfo* mod = nullptr;
    for (const auto& m : modules) {
        if (!modName.empty()) { if (m.name == modName) { mod = &m; break; } }
        else if (target >= m.base && target < m.base + m.size) { mod = &m; break; }
    }

    ce::CodeAnalyzer an(ce::analyzerArchFor(*p));
    std::vector<ce::CodeRef> refs;
    if (mod) {
        refs = an.findReferencesTo(*p, *mod, target);
    } else {
        for (const auto& m : modules) {
            auto r = an.findReferencesTo(*p, m, target);
            refs.insert(refs.end(), r.begin(), r.end());
        }
    }

    lua_newtable(L);
    int i = 1;
    for (const auto& r : refs) {
        lua_newtable(L);
        lua_pushinteger(L, (lua_Integer)r.address); lua_setfield(L, -2, "address");
        lua_pushinteger(L, (lua_Integer)r.target);  lua_setfield(L, -2, "target");
        lua_pushstring(L, refTypeName(r.type));     lua_setfield(L, -2, "type");
        lua_pushstring(L, r.text.c_str());          lua_setfield(L, -2, "text");
        lua_rawseti(L, -2, i++);
    }
    return 1;
}

// Pick a module by name, or the first module (the main executable) when unnamed.
static bool pickModule(ce::ProcessHandle& p, const std::string& modName, ce::ModuleInfo& out) {
    auto modules = p.modules();
    if (modules.empty()) return false;
    if (modName.empty()) { out = modules.front(); return true; }
    for (const auto& m : modules) if (m.name == modName) { out = m; return true; }
    return false;
}

// getModuleExports(nameOrPath) -> { {name, ordinal, rva, address, forward}, ... }
//   | nil, err. Exported functions of a PE module (Wine/Proton DLLs). Pass a file
// path to parse it directly (address == rva), or a mapped module's name to get
// live addresses (module base + rva). Handy for the il2cpp_* API GameAssembly.dll
// exports. Forwarded exports carry `forward = "OTHERDLL.func"` and rva 0.
// Resolve a getModule* argument (a PE file path, or a mapped module's name) to a
// file path + module base. Returns "" on success, else an error string.
static std::string resolvePEModuleArg(lua_State* L, const std::string& arg,
                                      std::string& path, uint64_t& base) {
    std::error_code ec;
    if (!arg.empty() && std::filesystem::is_regular_file(arg, ec)) { path = arg; base = 0; return {}; }
    auto* p = getProc(L);
    if (!p) return "no target process; pass a PE file path";
    // A remote module's path names a file on the remote system.
    if (!ce::moduleFilesAreLocal(*p)) return ce::kRemoteModuleFilesError;
    auto modules = p->modules();
    const ce::ModuleInfo* mod = nullptr;
    if (arg.empty()) { if (!modules.empty()) mod = &modules.front(); }
    else for (const auto& m : modules) if (m.name == arg || m.path == arg) { mod = &m; break; }
    if (!mod) return "module not found";
    path = mod->path;
    base = mod->base;
    return {};
}

int l_getModuleExports(lua_State* L) {
    std::string arg = (lua_gettop(L) >= 1 && !lua_isnil(L, 1)) ? luaL_checkstring(L, 1) : "";
    std::string path;
    uint64_t base = 0;
    if (std::string e = resolvePEModuleArg(L, arg, path, base); !e.empty()) {
        lua_pushnil(L); lua_pushstring(L, e.c_str()); return 2;
    }

    auto exps = ce::parsePEExports(path);
    if (exps.empty()) { lua_pushnil(L); lua_pushstring(L, "not a PE image or no exports"); return 2; }
    lua_newtable(L);
    int i = 1;
    for (const auto& e : exps) {
        lua_newtable(L);
        lua_pushstring(L, e.name.c_str());              lua_setfield(L, -2, "name");
        lua_pushinteger(L, (lua_Integer)e.ordinal);     lua_setfield(L, -2, "ordinal");
        lua_pushinteger(L, (lua_Integer)e.rva);         lua_setfield(L, -2, "rva");
        lua_pushinteger(L, (lua_Integer)(e.rva ? base + e.rva : 0)); lua_setfield(L, -2, "address");
        if (!e.forward.empty()) { lua_pushstring(L, e.forward.c_str()); lua_setfield(L, -2, "forward"); }
        lua_rawseti(L, -2, i++);
    }
    return 1;
}

// getModuleImports(nameOrPath) -> { {dll, name, ordinal, iatRva, iatAddress}, ...}
//   | nil, err. Functions a PE module imports, with the RVA of each IAT slot
// (iatAddress = module base + iatRva is a live IAT-hook target). Same argument
// forms as getModuleExports.
int l_getModuleImports(lua_State* L) {
    std::string arg = (lua_gettop(L) >= 1 && !lua_isnil(L, 1)) ? luaL_checkstring(L, 1) : "";
    std::string path;
    uint64_t base = 0;
    if (std::string e = resolvePEModuleArg(L, arg, path, base); !e.empty()) {
        lua_pushnil(L); lua_pushstring(L, e.c_str()); return 2;
    }

    auto imps = ce::parsePEImports(path);
    if (imps.empty()) { lua_pushnil(L); lua_pushstring(L, "not a PE image or no imports"); return 2; }
    lua_newtable(L);
    int i = 1;
    for (const auto& im : imps) {
        lua_newtable(L);
        lua_pushstring(L, im.dll.c_str());          lua_setfield(L, -2, "dll");
        lua_pushstring(L, im.name.c_str());         lua_setfield(L, -2, "name");
        lua_pushinteger(L, (lua_Integer)im.ordinal);lua_setfield(L, -2, "ordinal");
        lua_pushinteger(L, (lua_Integer)im.iatRva); lua_setfield(L, -2, "iatRva");
        lua_pushinteger(L, (lua_Integer)(base + im.iatRva)); lua_setfield(L, -2, "iatAddress");
        lua_rawseti(L, -2, i++);
    }
    return 1;
}

// enumerateFunctions([moduleName]) -> { {address, references}, ... } | nil, err
// Candidate function entry points in a module (call targets + prologues), with
// how many places reference each. Defaults to the main module.
int l_enumerateFunctions(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); lua_pushstring(L, "no target process"); return 2; }
    std::string modName = (lua_gettop(L) >= 1 && !lua_isnil(L, 1)) ? luaL_checkstring(L, 1) : "";
    ce::ModuleInfo mod;
    if (!pickModule(*p, modName, mod)) { lua_pushnil(L); lua_pushstring(L, "module not found"); return 2; }
    ce::CodeAnalyzer an(ce::analyzerArchFor(*p));
    auto fns = an.enumerateFunctions(*p, mod);
    lua_newtable(L);
    int i = 1;
    for (const auto& f : fns) {
        lua_newtable(L);
        lua_pushinteger(L, (lua_Integer)f.address);    lua_setfield(L, -2, "address");
        lua_pushinteger(L, (lua_Integer)f.references); lua_setfield(L, -2, "references");
        lua_rawseti(L, -2, i++);
    }
    return 1;
}

// buildCallGraph([moduleName]) -> { {caller, callee, callSite}, ... } | nil, err
// Static call edges within a module (who calls what, and from where).
int l_buildCallGraph(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); lua_pushstring(L, "no target process"); return 2; }
    std::string modName = (lua_gettop(L) >= 1 && !lua_isnil(L, 1)) ? luaL_checkstring(L, 1) : "";
    ce::ModuleInfo mod;
    if (!pickModule(*p, modName, mod)) { lua_pushnil(L); lua_pushstring(L, "module not found"); return 2; }
    ce::CodeAnalyzer an(ce::analyzerArchFor(*p));
    auto edges = an.buildCallGraph(*p, mod);
    lua_newtable(L);
    int i = 1;
    for (const auto& e : edges) {
        lua_newtable(L);
        lua_pushinteger(L, (lua_Integer)e.caller);   lua_setfield(L, -2, "caller");
        lua_pushinteger(L, (lua_Integer)e.callee);   lua_setfield(L, -2, "callee");
        lua_pushinteger(L, (lua_Integer)e.callSite); lua_setfield(L, -2, "callSite");
        lua_rawseti(L, -2, i++);
    }
    return 1;
}

// findReferencedStrings([moduleName]) -> { {address, target, text}, ... } | nil, err
// String literals the module's code points at (lea/mov rip-rel into readable
// data holding a printable C string), with the referencing instruction address,
// the string's address, and its text. Great for locating feature code by its
// UI text ("God Mode", "Game Over"). Defaults to the main module.
int l_findReferencedStrings(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); lua_pushstring(L, "no target process"); return 2; }
    std::string modName = (lua_gettop(L) >= 1 && !lua_isnil(L, 1)) ? luaL_checkstring(L, 1) : "";
    ce::ModuleInfo mod;
    if (!pickModule(*p, modName, mod)) { lua_pushnil(L); lua_pushstring(L, "module not found"); return 2; }
    ce::CodeAnalyzer an(ce::analyzerArchFor(*p));
    auto refs = an.findReferencedStrings(*p, mod);
    lua_newtable(L);
    int i = 1;
    for (const auto& r : refs) {
        lua_newtable(L);
        lua_pushinteger(L, (lua_Integer)r.address); lua_setfield(L, -2, "address");
        lua_pushinteger(L, (lua_Integer)r.target);  lua_setfield(L, -2, "target");
        lua_pushstring(L, r.text.c_str());          lua_setfield(L, -2, "text");
        lua_rawseti(L, -2, i++);
    }
    return 1;
}

// findCodeCaves([moduleName [, minSize]]) -> { {address, size}, ... } | nil, err
// Runs of padding (0x00 / 0xCC) at least minSize bytes long (default 16) inside a
// module, usable to host injected code without a separate allocation. Defaults to
// the main module.
int l_findCodeCaves(lua_State* L) {
    checkOptionalStrings(L, 1, 1); if (!lua_isnoneornil(L, 2)) luaL_checkinteger(L, 2);
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); lua_pushstring(L, "no target process"); return 2; }
    std::string modName = (lua_gettop(L) >= 1 && !lua_isnil(L, 1)) ? luaL_checkstring(L, 1) : "";
    size_t minSize = (lua_gettop(L) >= 2 && !lua_isnil(L, 2)) ? (size_t)luaL_checkinteger(L, 2) : 16;
    ce::ModuleInfo mod;
    if (!pickModule(*p, modName, mod)) { lua_pushnil(L); lua_pushstring(L, "module not found"); return 2; }
    ce::CodeAnalyzer an(ce::analyzerArchFor(*p));
    auto caves = an.findCodeCaves(*p, mod, minSize);
    lua_newtable(L);
    int i = 1;
    for (const auto& c : caves) {
        lua_newtable(L);
        lua_pushinteger(L, (lua_Integer)c.address); lua_setfield(L, -2, "address");
        lua_pushinteger(L, (lua_Integer)c.size);    lua_setfield(L, -2, "size");
        lua_rawseti(L, -2, i++);
    }
    return 1;
}

// findAssemblyPattern(assembly [, moduleName]) -> { {address, text}, ... } | nil, err
// Assemble an instruction (or short sequence), then find every place in the
// module's code where those exact bytes occur. The instruction-level analog of an
// AOB scan: e.g. "mov [rax+0x10], 999" or "call rax". Defaults to the main module.
int l_findAssemblyPattern(lua_State* L) {
    luaL_checkstring(L, 1); checkOptionalStrings(L, 2, 2);
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); lua_pushstring(L, "no target process"); return 2; }
    std::string assembly = luaL_checkstring(L, 1);
    std::string modName = (lua_gettop(L) >= 2 && !lua_isnil(L, 2)) ? luaL_checkstring(L, 2) : "";
    ce::ModuleInfo mod;
    if (!pickModule(*p, modName, mod)) { lua_pushnil(L); lua_pushstring(L, "module not found"); return 2; }
    ce::CodeAnalyzer an(ce::analyzerArchFor(*p));
    auto hits = an.findAssemblyPattern(*p, mod, assembly);
    lua_newtable(L);
    int i = 1;
    for (const auto& h : hits) {
        lua_newtable(L);
        lua_pushinteger(L, (lua_Integer)h.address); lua_setfield(L, -2, "address");
        lua_pushstring(L, h.text.c_str());          lua_setfield(L, -2, "text");
        lua_rawseti(L, -2, i++);
    }
    return 1;
}
} // namespace ce::lua_detail
