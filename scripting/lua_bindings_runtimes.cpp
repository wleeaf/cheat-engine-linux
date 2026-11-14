/// Lua bindings: managed runtimes (Mono, IL2CPP), DWARF structures, simple
/// hooks, signatures and code execution.
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

int l_getManagedRuntimes(lua_State* L) {
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
// class/field layout. Missing targets/agents return nil + message. Request,
// runtime and injection errors are reported in the result's ready/error fields.
int l_monoDissect(lua_State* L) {
    // Arguments first: a raise after a std::string exists would leak it.
    const int timeoutMs = (lua_gettop(L) >= 1 && !lua_isnil(L, 1)) ? (int)luaL_checkinteger(L, 1) : 10000;
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

// createSimpleHook(address, target) -> hookInfo { id, address, trampoline } or nil.
// Redirects `address` to `target`; the returned `trampoline` runs the displaced
// original code then resumes, so target code can `jmp trampoline` to continue.
// Refuses (nil) if the displaced instructions are position-dependent.
int l_createSimpleHook(lua_State* L) {
    auto* p = getProc(L);
    auto* eng = ce::LuaEngine::instanceFromState(L);
    if (!p || !eng) { lua_pushnil(L); return 1; }
    uintptr_t addr   = (uintptr_t)luaL_checkinteger(L, 1);
    uintptr_t target = (uintptr_t)luaL_checkinteger(L, 2);
    auto h = ce::installSimpleHook(*p, addr, target);
    if (!h) {
        lua_pushnil(L);
        lua_pushstring(L, ce::targetOperationError(*p, ce::TargetFeature::CodeInjection).c_str());
        return 2;
    }
    int id = eng->addHook(*h);
    lua_newtable(L);
    lua_pushinteger(L, id);                        lua_setfield(L, -2, "id");
    lua_pushinteger(L, (lua_Integer)addr);         lua_setfield(L, -2, "address");
    lua_pushinteger(L, (lua_Integer)h->trampoline); lua_setfield(L, -2, "trampoline");
    return 1;
}
// removeSimpleHook(hookInfo) — restores the original bytes. Accepts the table from
// createSimpleHook or a bare id.
int l_removeSimpleHook(lua_State* L) {
    auto* p = getProc(L);
    auto* eng = ce::LuaEngine::instanceFromState(L);
    if (!p || !eng) return 0;
    int id = -1;
    if (lua_istable(L, 1)) { lua_getfield(L, 1, "id"); id = (int)lua_tointeger(L, -1); lua_pop(L, 1); }
    else if (lua_isnumber(L, 1)) id = (int)lua_tointeger(L, 1);
    bool removed = false;
    if (const auto* h = eng->hook(id)) {
        removed = ce::removeSimpleHook(*p, *h);
        if (removed) eng->eraseHook(id);
    }
    lua_pushboolean(L, removed);
    return 1;
}

// findMonoFunction(namespace, class, method [, params]) -> address (or nil).
// Resolves + JIT-compiles the one named method via the resident Mono agent.
// `params` is a comma-separated type list ("Entity,int") used only for its count
// to disambiguate overloads; omit or "" to match any overload.
int l_findMonoFunction(lua_State* L) {
    // Arguments first: a raise after a std::string exists would leak it.
    const char* ns   = luaL_optstring(L, 1, "");
    const char* cls  = luaL_checkstring(L, 2);
    const char* meth = luaL_checkstring(L, 3);
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    if (ce::detectManagedKind(*p) != ce::ManagedKind::Mono) { lua_pushnil(L); return 1; }
    std::string agent = ce::findMonoAgentPath();
    if (agent.empty()) { lua_pushnil(L); return 1; }
    int paramCount = -1;
    // lua_isstring() is true for numbers too, so check the concrete type: a
    // numeric arg is the param count, not a comma-separated type list.
    if (lua_type(L, 4) == LUA_TNUMBER) {
        paramCount = (int)lua_tointeger(L, 4);
    } else if (lua_type(L, 4) == LUA_TSTRING) {
        std::string params = lua_tostring(L, 4);
        if (params.empty()) paramCount = 0;
        else paramCount = 1 + (int)std::count(params.begin(), params.end(), ',');
    }
    ce::SymbolResolver resolver;
    resolver.loadProcess(*p);
    uintptr_t addr = ce::findMonoFunction(*p, resolver, agent, ns, cls, meth, paramCount);
    if (addr) lua_pushinteger(L, (lua_Integer)addr); else lua_pushnil(L);
    return 1;
}

// findMonoInstances(namespace, class [, limit]) -> {addresses}, vtable | nil, error
// The class's live objects: pointer-aligned words in private writable memory
// that hold its MonoVTable (the first word of every object of the class).
int l_findMonoInstances(lua_State* L) {
    const char* ns  = luaL_optstring(L, 1, "");
    const char* cls = luaL_checkstring(L, 2);
    const lua_Integer limit = luaL_optinteger(L, 3, 10000);
    if (limit <= 0) return luaL_argerror(L, 3, "limit must be positive");
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); lua_pushliteral(L, "no process is open"); return 2; }
    if (ce::detectManagedKind(*p) != ce::ManagedKind::Mono) {
        lua_pushnil(L); lua_pushliteral(L, "the target has no Mono runtime"); return 2;
    }
    std::string agent = ce::findMonoAgentPath();
    if (agent.empty()) { lua_pushnil(L); lua_pushliteral(L, "libcecore_mono_agent.so not found"); return 2; }
    ce::SymbolResolver resolver;
    resolver.loadProcess(*p);
    const uintptr_t vtable = ce::findMonoClassVTable(*p, resolver, agent, ns, cls);
    if (!vtable) {
        lua_pushnil(L);
        lua_pushliteral(L, "no vtable: class not found, an interface, abstract or static class or generic definition, "
                           "or the runtime refused the lookup");
        return 2;
    }
    auto instances = ce::findMonoInstances(*p, vtable, static_cast<size_t>(limit));
    lua_createtable(L, static_cast<int>(std::min<size_t>(instances.size(), INT_MAX)), 0);
    for (size_t i = 0; i < instances.size(); ++i) {
        lua_pushinteger(L, static_cast<lua_Integer>(instances[i]));
        lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
    }
    lua_pushinteger(L, static_cast<lua_Integer>(vtable));
    return 2;
}

// createSignature(address [, maxBytes]) -> pattern, unique | nil, error
// An array-of-bytes signature for the code at `address`; rip-relative
// displacements and address-sized immediates are wildcarded so it survives
// ASLR / minor rebuilds. `pattern` is CE AOB format. `unique` says it matched
// exactly once across the readable mappings of its module (or its anonymous
// mapping), as AOBScanModule searches; it is not checked process-wide, and is
// false when part of the module could not be read.
int l_createSignature(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); lua_pushstring(L, "no target process"); return 2; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    size_t maxBytes = (lua_gettop(L) >= 2 && !lua_isnil(L, 2)) ? (size_t)luaL_checkinteger(L, 2) : 64;
    auto sig = ce::makeSignature(*p, addr, maxBytes);
    if (sig.pattern.empty()) {
        lua_pushnil(L);
        lua_pushstring(L, "could not build signature (unreadable or out of range)");
        return 2;
    }
    lua_pushstring(L, sig.pattern.c_str());
    lua_pushboolean(L, sig.unique);
    return 2;
}

// executeCode(address [, timeoutMs]) -> true | nil, error
// Runs the target's code at `address` on a fresh native pthread and waits up
// to timeoutMs (default 5000) for it to return. CE's executeCodeEx / createThread
// with wait; the function must use the native pthread entry ABI. The return value is
// not captured. Runs on the open process (no active debugger; ptrace-exclusive).
int l_executeCode(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); lua_pushstring(L, "no target process"); return 2; }
    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    lua_Integer timeout = (lua_gettop(L) >= 2 && !lua_isnil(L, 2)) ? luaL_checkinteger(L, 2) : 5000;
    if (timeout < 0 || timeout > INT_MAX) {
        lua_pushnil(L); lua_pushstring(L, "timeout must be between 0 and INT_MAX milliseconds"); return 2;
    }
    int timeoutMs = static_cast<int>(timeout);
    ce::SymbolResolver resolver;
    resolver.loadProcess(*p);
    auto r = ce::os::createRemoteThread(*p, resolver, addr, /*waitForCompletion=*/true, timeoutMs);
    if (!r) { lua_pushnil(L); lua_pushstring(L, r.error().c_str()); return 2; }
    if (!r->completed) {
        lua_pushnil(L); lua_pushstring(L,"remote thread timed out and continues detached; keep its code and data mapped until it exits"); return 2;
    }
    lua_pushboolean(L, 1);
    return 1;
}

// Gather the file paths the open process has mapped (modules + region paths).
static std::vector<std::string> mappedFilePaths(ce::ProcessHandle& p) {
    std::vector<std::string> paths;
    for (const auto& m : p.modules()) if (!m.path.empty()) paths.push_back(m.path);
    for (const auto& r : p.queryRegions()) if (!r.path.empty()) paths.push_back(r.path);
    return paths;
}

// getIl2CppMetadataPath() -> path string, or nil + message.
// Locates the open IL2CPP process's global-metadata.dat on disk (see
// findIl2CppMetadataPath). A convenience so scripts don't hunt for the file.
int l_getIl2CppMetadataPath(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); lua_pushstring(L, "no target process"); return 2; }
    if (!ce::moduleFilesAreLocal(*p)) { lua_pushnil(L); lua_pushstring(L, ce::kRemoteModuleFilesError); return 2; }
    auto found = ce::findIl2CppMetadataPath(mappedFilePaths(*p));
    if (!found) {
        lua_pushnil(L);
        lua_pushstring(L, "global-metadata.dat not found for this process");
        return 2;
    }
    lua_pushstring(L, found->c_str());
    return 1;
}

// Metadata files are tens of MB at most; cap well above that. The path can come
// from a table's Lua, and an unbounded istreambuf_iterator read of /dev/zero
// never hits EOF (grows until OOM) and a huge file OOMs, so read in a capped
// loop like readFromFile does.
constexpr size_t kMaxMetadataBytes = 256u * 1024 * 1024;  // 256 MB
static bool readFileCapped(const std::string& path, size_t maxBytes,
                           std::vector<uint8_t>& out, std::string& err) {
    std::ifstream in(path, std::ios::binary);
    if (!in) { err = "cannot open metadata file"; return false; }
    out.clear();
    try {
        char buf[65536];
        while (in && out.size() < maxBytes) {
            in.read(buf, (std::streamsize)std::min(sizeof(buf), maxBytes - out.size()));
            std::streamsize got = in.gcount();
            if (got <= 0) break;
            out.insert(out.end(), buf, buf + got);
        }
    } catch (const std::exception& ex) {
        err = ex.what();
        return false;
    }
    return true;
}

// getIl2CppClasses([path]) -> { version, decoded, classes = { {image, namespace,
//   name, fullName, fields = { "name", ... } }, ... } }, or nil + message.
// With no path, auto-locates global-metadata.dat for the open process. This is
// the OFFLINE metadata view: field NAMES and their grouping into classes only.
// Field byte offsets and field TYPE names are not in the metadata (they live in
// GameAssembly.so), and the deeper tables decode only for metadata versions
// 27-31 (other versions return decoded=false with an empty class list).
int l_getIl2CppClasses(lua_State* L) {
    std::string path;
    if (lua_gettop(L) >= 1 && !lua_isnil(L, 1)) {
        path = luaL_checkstring(L, 1);
    } else {
        auto* p = getProc(L);
        if (!p) { lua_pushnil(L); lua_pushstring(L, "no target process and no path given"); return 2; }
        if (!ce::moduleFilesAreLocal(*p)) { lua_pushnil(L); lua_pushstring(L, ce::kRemoteModuleFilesError); return 2; }
        auto found = ce::findIl2CppMetadataPath(mappedFilePaths(*p));
        if (!found) {
            lua_pushnil(L);
            lua_pushstring(L, "global-metadata.dat not found; pass a path explicitly");
            return 2;
        }
        path = *found;
    }

    std::vector<uint8_t> buf;
    std::string err;
    if (!readFileCapped(path, kMaxMetadataBytes, buf, err)) {
        lua_pushnil(L); lua_pushstring(L, err.c_str()); return 2;
    }
    auto md = ce::parseIl2CppMetadata(buf.data(), buf.size());
    if (!md) { lua_pushnil(L); lua_pushstring(L, "not a valid global-metadata.dat"); return 2; }

    // Resolve a type index to its owning image name (each image owns the
    // contiguous run types[typeStart, typeStart+typeCount)).
    auto imageNameForType = [&](size_t ti) -> const char* {
        for (const auto& img : md->images)
            if (ti >= img.typeStart && ti < static_cast<size_t>(img.typeStart) + img.typeCount)
                return img.name.c_str();
        return "";
    };

    lua_newtable(L);
    lua_pushinteger(L, md->version);       lua_setfield(L, -2, "version");
    lua_pushboolean(L, md->tablesDecoded); lua_setfield(L, -2, "decoded");
    lua_newtable(L);   // classes
    int ci = 1;
    for (size_t ti = 0; ti < md->types.size(); ++ti) {
        const auto& t = md->types[ti];
        lua_newtable(L);
        lua_pushstring(L, imageNameForType(ti));     lua_setfield(L, -2, "image");
        lua_pushstring(L, t.namespaceName.c_str());  lua_setfield(L, -2, "namespace");
        lua_pushstring(L, t.name.c_str());           lua_setfield(L, -2, "name");
        lua_pushstring(L, t.fullName().c_str());     lua_setfield(L, -2, "fullName");
        lua_newtable(L);   // fields (names)
        int fi = 1;
        for (const auto& f : t.fields) {
            lua_pushstring(L, f.name.c_str());
            lua_rawseti(L, -2, fi++);
        }
        lua_setfield(L, -2, "fields");
        lua_rawseti(L, -2, ci++);
    }
    lua_setfield(L, -2, "classes");
    return 1;
}

// getIl2CppClassLayout([className [, metadataPath [, binaryPath]]]) -> table|nil,err
// Like getIl2CppClasses but resolves each field's in-object byte OFFSET from the
// GameAssembly binary. Returns an array of matching classes:
// Build an Il2CppBinaryLayout from an explicit (metaPath[, binPath]) or, when
// metaPath is empty, from the open process (auto-locating both). On failure
// pushes nil + message and returns false, so the caller does `return 2`.
static bool luaBuildIl2CppLayout(lua_State* L, const std::string& metaPath,
                                 const std::string& binPath, ce::Il2CppBinaryLayout& layout) {
    if (!metaPath.empty()) {
        std::vector<uint8_t> buf;
        std::string err;
        if (!readFileCapped(metaPath, kMaxMetadataBytes, buf, err)) {
            lua_pushnil(L); lua_pushstring(L, err.c_str()); return false;
        }
        auto md = ce::parseIl2CppMetadata(buf.data(), buf.size());
        if (!md) { lua_pushnil(L); lua_pushstring(L, "not a valid global-metadata.dat"); return false; }
        std::string ga = binPath;
        if (ga.empty()) {
            std::error_code ec;
            std::filesystem::path root = std::filesystem::path(metaPath)
                .parent_path().parent_path().parent_path().parent_path();
            for (const char* n : {"GameAssembly.so", "GameAssembly.dll", "libil2cpp.so"}) {
                std::filesystem::path c = root / n;
                if (std::filesystem::is_regular_file(c, ec)) { ga = c.string(); break; }
            }
        }
        if (ga.empty()) {
            lua_pushnil(L); lua_pushstring(L, "GameAssembly binary not found; pass one explicitly");
            return false;
        }
        layout = ce::resolveIl2CppLayout(*md, ga);
    } else {
        auto* p = getProc(L);
        if (!p) { lua_pushnil(L); lua_pushstring(L, "no target process and no metadata path"); return false; }
        layout = ce::resolveIl2CppForProcess(*p);
    }
    if (!layout.ok) { lua_pushnil(L); lua_pushstring(L, layout.error.c_str()); return false; }
    return true;
}

//   { {image, namespace, name, fullName, fields = { {name, offset, static, const} }} }
// With no metadataPath it uses the open process (auto-locating both metadata and
// GameAssembly from its mapped files). `className` filters by full-name substring
// (nil/"" = all). Instance-field offsets are object-relative: value address =
// objectPtr + offset. Static-field offsets are into the static block; const
// fields have no storage.
// Raise for a present (non-nil) argument in first..last that is not a string,
// before the caller copies any of them into C++ strings: a raise after that
// longjmps past their destructors.
void checkOptionalStrings(lua_State* L, int first, int last) {
    for (int i = first; i <= last; ++i)
        if (!lua_isnoneornil(L, i)) luaL_checkstring(L, i);
}

int l_getIl2CppClassLayout(lua_State* L) {
    checkOptionalStrings(L, 1, 3);
    std::string className, metaPath, binPath;
    if (lua_gettop(L) >= 1 && !lua_isnil(L, 1)) className = luaL_checkstring(L, 1);
    if (lua_gettop(L) >= 2 && !lua_isnil(L, 2)) metaPath = luaL_checkstring(L, 2);
    if (lua_gettop(L) >= 3 && !lua_isnil(L, 3)) binPath = luaL_checkstring(L, 3);

    ce::Il2CppBinaryLayout layout;
    if (!luaBuildIl2CppLayout(L, metaPath, binPath, layout)) return 2;

    lua_newtable(L);
    int ci = 1;
    for (const auto& c : layout.classes) {
        std::string full = c.fullName();
        if (!className.empty() && full.find(className) == std::string::npos) continue;
        lua_newtable(L);
        lua_pushstring(L, c.image.c_str());         lua_setfield(L, -2, "image");
        lua_pushstring(L, c.namespaceName.c_str()); lua_setfield(L, -2, "namespace");
        lua_pushstring(L, c.name.c_str());          lua_setfield(L, -2, "name");
        lua_pushstring(L, full.c_str());            lua_setfield(L, -2, "fullName");
        lua_pushstring(L, c.parentName.c_str());    lua_setfield(L, -2, "parent");   // base class
        lua_newtable(L);   // fields
        int fi = 1;
        for (const auto& f : c.fields) {
            lua_newtable(L);
            lua_pushstring(L, f.name.c_str());     lua_setfield(L, -2, "name");
            lua_pushinteger(L, (lua_Integer)f.offset); lua_setfield(L, -2, "offset");
            lua_pushboolean(L, f.isStatic);        lua_setfield(L, -2, "static");
            lua_pushboolean(L, f.isConst);         lua_setfield(L, -2, "const");
            lua_pushstring(L, f.typeName.c_str()); lua_setfield(L, -2, "typeName");  // "UnityEngine.Vector3", …
            lua_rawseti(L, -2, fi++);
        }
        lua_setfield(L, -2, "fields");
        lua_newtable(L);   // methods (name + rva; resolved in the same binary pass)
        int mi = 1;
        for (const auto& m : c.methods) {
            lua_newtable(L);
            lua_pushstring(L, m.name.c_str());      lua_setfield(L, -2, "name");
            lua_pushinteger(L, (lua_Integer)m.rva); lua_setfield(L, -2, "rva");
            lua_rawseti(L, -2, mi++);
        }
        lua_setfield(L, -2, "methods");
        lua_rawseti(L, -2, ci++);
    }
    return 1;
}

// getIl2CppObjectLayout(class [, metadataPath [, binaryPath]]) ->
//   { class=<fullName>, fields = { {name, offset, typeName, static=false,
//   const=false, declaringType}, ... } } | nil, err
// The COMPLETE instance layout of one object: this class's own instance fields
// plus every inherited one (walking the base-class chain), each at its
// object-relative offset and tagged with `declaringType`. `class` is matched
// exactly by full name, else by short name, else as a full-name substring.
int l_getIl2CppObjectLayout(lua_State* L) {
    checkOptionalStrings(L, 1, 3);
    std::string className, metaPath, binPath;
    if (lua_gettop(L) >= 1 && !lua_isnil(L, 1)) className = luaL_checkstring(L, 1);
    if (lua_gettop(L) >= 2 && !lua_isnil(L, 2)) metaPath = luaL_checkstring(L, 2);
    if (lua_gettop(L) >= 3 && !lua_isnil(L, 3)) binPath = luaL_checkstring(L, 3);
    if (className.empty()) { lua_pushnil(L); lua_pushstring(L, "need a class name"); return 2; }

    ce::Il2CppBinaryLayout layout;
    if (!luaBuildIl2CppLayout(L, metaPath, binPath, layout)) return 2;

    // Resolve the class name: exact fullName, else exact short name, else substring.
    std::string full;
    for (const auto& c : layout.classes) if (c.fullName() == className) { full = className; break; }
    if (full.empty())
        for (const auto& c : layout.classes) if (c.name == className) { full = c.fullName(); break; }
    if (full.empty())
        for (const auto& c : layout.classes)
            if (c.fullName().find(className) != std::string::npos) { full = c.fullName(); break; }
    if (full.empty()) { lua_pushnil(L); lua_pushstring(L, "class not found"); return 2; }

    auto fields = ce::il2cppObjectFieldLayout(layout, full);
    lua_newtable(L);
    lua_pushstring(L, full.c_str()); lua_setfield(L, -2, "class");
    lua_newtable(L);   // fields
    int fi = 1;
    for (const auto& f : fields) {
        lua_newtable(L);
        lua_pushstring(L, f.name.c_str());          lua_setfield(L, -2, "name");
        lua_pushinteger(L, (lua_Integer)f.offset);  lua_setfield(L, -2, "offset");
        lua_pushstring(L, f.typeName.c_str());      lua_setfield(L, -2, "typeName");
        lua_pushstring(L, f.declaringType.c_str()); lua_setfield(L, -2, "declaringType");
        lua_rawseti(L, -2, fi++);
    }
    lua_setfield(L, -2, "fields");
    return 1;
}

static const char* valueTypeShortName(ce::ValueType t) {
    switch (t) {
        case ce::ValueType::Byte:    return "byte";
        case ce::ValueType::Int16:   return "int16";
        case ce::ValueType::Int32:   return "int32";
        case ce::ValueType::Int64:   return "int64";
        case ce::ValueType::Float:   return "float";
        case ce::ValueType::Double:  return "double";
        case ce::ValueType::String:  return "string";
        case ce::ValueType::Pointer: return "pointer";
        case ce::ValueType::ByteArray: return "aob";
        default: return "int32";
    }
}

// getIl2CppStructure(className [, metadataPath [, binaryPath]]) -> table|nil,err
// The managed-typed structure layout for one class: { name, size, fields = {
//   {name, offset, size, type=<ValueType int>, typeName=<"int32"/"float"/...>} } }.
// Instance fields only, each typed from its Il2CppTypeEnum, so a script can lay a
// Unity class over an object address (base+offset) with real names + types. Uses
// the open process (auto-locate) or explicit metadata/binary paths.
int l_getIl2CppStructure(lua_State* L) {
    checkOptionalStrings(L, 1, 3);
    std::string className, metaPath, binPath;
    if (lua_gettop(L) >= 1 && !lua_isnil(L, 1)) className = luaL_checkstring(L, 1);
    if (lua_gettop(L) >= 2 && !lua_isnil(L, 2)) metaPath = luaL_checkstring(L, 2);
    if (lua_gettop(L) >= 3 && !lua_isnil(L, 3)) binPath = luaL_checkstring(L, 3);
    if (className.empty()) { lua_pushnil(L); lua_pushstring(L, "class name required"); return 2; }

    ce::Il2CppBinaryLayout layout;
    if (!metaPath.empty()) {
        std::vector<uint8_t> buf;
        std::string err;
        if (!readFileCapped(metaPath, kMaxMetadataBytes, buf, err)) {
            lua_pushnil(L); lua_pushstring(L, err.c_str()); return 2;
        }
        auto md = ce::parseIl2CppMetadata(buf.data(), buf.size());
        if (!md) { lua_pushnil(L); lua_pushstring(L, "not a valid global-metadata.dat"); return 2; }
        std::string ga = binPath;
        if (ga.empty()) {
            std::error_code ec;
            std::filesystem::path root = std::filesystem::path(metaPath)
                .parent_path().parent_path().parent_path().parent_path();
            for (const char* n : {"GameAssembly.so", "GameAssembly.dll", "libil2cpp.so"}) {
                std::filesystem::path c = root / n;
                if (std::filesystem::is_regular_file(c, ec)) { ga = c.string(); break; }
            }
        }
        if (ga.empty()) { lua_pushnil(L); lua_pushstring(L, "GameAssembly binary not found; pass one explicitly"); return 2; }
        layout = ce::resolveIl2CppLayout(*md, ga);
    } else {
        auto* p = getProc(L);
        if (!p) { lua_pushnil(L); lua_pushstring(L, "no target process and no metadata path"); return 2; }
        layout = ce::resolveIl2CppForProcess(*p);
    }
    if (!layout.ok) { lua_pushnil(L); lua_pushstring(L, layout.error.c_str()); return 2; }

    // Prefer an exact full-name match; fall back to a bare class-name match.
    const ce::Il2CppClassLayout* found = nullptr;
    for (const auto& c : layout.classes)
        if (c.fullName() == className) { found = &c; break; }
    if (!found)
        for (const auto& c : layout.classes)
            if (c.name == className) { found = &c; break; }
    if (!found) { lua_pushnil(L); lua_pushstring(L, "class not found"); return 2; }

    ce::StructureDefinition def = ce::il2cppClassToStructure(*found);
    lua_newtable(L);
    lua_pushstring(L, def.name.c_str());          lua_setfield(L, -2, "name");
    lua_pushinteger(L, (lua_Integer)def.size);    lua_setfield(L, -2, "size");
    lua_newtable(L);   // fields
    int fi = 1;
    for (const auto& f : def.fields) {
        lua_newtable(L);
        lua_pushstring(L, f.name.c_str());              lua_setfield(L, -2, "name");
        lua_pushinteger(L, (lua_Integer)f.offset);      lua_setfield(L, -2, "offset");
        lua_pushinteger(L, (lua_Integer)f.size);        lua_setfield(L, -2, "size");
        lua_pushinteger(L, (lua_Integer)f.type);        lua_setfield(L, -2, "type");
        lua_pushstring(L, valueTypeShortName(f.type));  lua_setfield(L, -2, "typeName");
        lua_rawseti(L, -2, fi++);
    }
    lua_setfield(L, -2, "fields");
    return 1;
}

// getDwarfStructure(name [, elfPath]) -> { name, size, fields = { {name, offset,
//   size, type=<ValueType int>, typeName} } } | nil, err
// A native struct's layout from DWARF debug info: with an elfPath, reads that
// binary; otherwise resolves against the open process's modules. The DWARF analog
// of getIl2CppStructure.
int l_getDwarfStructure(lua_State* L) {
    luaL_checkstring(L, 1); checkOptionalStrings(L, 2, 2);
    if (!ce::DwarfInfo::available()) { lua_pushnil(L); lua_pushstring(L, "built without libdw"); return 2; }
    std::string name = luaL_checkstring(L, 1);
    std::optional<ce::DwarfStruct> st;
    if (lua_gettop(L) >= 2 && !lua_isnil(L, 2)) {
        ce::DwarfInfo di;
        if (!di.load(luaL_checkstring(L, 2), 0)) { lua_pushnil(L); lua_pushstring(L, "no DWARF in file"); return 2; }
        st = di.structByName(name);
    } else {
        auto* p = getProc(L);
        if (!p) { lua_pushnil(L); lua_pushstring(L, "no target process and no elf path"); return 2; }
        ce::DwarfRegistry reg; reg.loadFromProcess(*p);
        st = reg.structByName(name);
    }
    if (!st) { lua_pushnil(L); lua_pushstring(L, "struct not found"); return 2; }

    ce::StructureDefinition def = ce::dwarfStructToStructure(*st);
    lua_newtable(L);
    lua_pushstring(L, def.name.c_str());       lua_setfield(L, -2, "name");
    lua_pushinteger(L, (lua_Integer)def.size); lua_setfield(L, -2, "size");
    lua_newtable(L);
    int fi = 1;
    for (const auto& f : def.fields) {
        lua_newtable(L);
        lua_pushstring(L, f.name.c_str());              lua_setfield(L, -2, "name");
        lua_pushinteger(L, (lua_Integer)f.offset);      lua_setfield(L, -2, "offset");
        lua_pushinteger(L, (lua_Integer)f.size);        lua_setfield(L, -2, "size");
        lua_pushinteger(L, (lua_Integer)f.type);        lua_setfield(L, -2, "type");
        lua_pushstring(L, valueTypeShortName(f.type));  lua_setfield(L, -2, "typeName");
        lua_rawseti(L, -2, fi++);
    }
    lua_setfield(L, -2, "fields");
    return 1;
}

// listDwarfStructs([elfPath]) -> { "Name", ... } | nil, err
int l_listDwarfStructs(lua_State* L) {
    if (!ce::DwarfInfo::available()) { lua_pushnil(L); lua_pushstring(L, "built without libdw"); return 2; }
    std::vector<std::string> names;
    if (lua_gettop(L) >= 1 && !lua_isnil(L, 1)) {
        ce::DwarfInfo di;
        if (di.load(luaL_checkstring(L, 1), 0)) names = di.structNames();
    } else {
        auto* p = getProc(L);
        if (!p) { lua_pushnil(L); lua_pushstring(L, "no target process and no elf path"); return 2; }
        ce::DwarfRegistry reg; reg.loadFromProcess(*p); names = reg.structNames();
    }
    lua_newtable(L);
    for (size_t i = 0; i < names.size(); ++i) {
        lua_pushstring(L, names[i].c_str());
        lua_rawseti(L, -2, (int)i + 1);
    }
    return 1;
}

// Locate metadata + GameAssembly + the module's runtime base for the IL2CPP method
// bindings. Returns "" on success (fills md/binary/moduleBase) or an error string.
// With metaPath set: file mode (moduleBase = 0, so address == the link-time rva).
// Else: the open process (moduleBase = the mapped GameAssembly base, so address ==
// the live runtime address).
static std::string luaIl2CppMethodContext(lua_State* L, const std::string& metaPath,
                                          const std::string& binPath,
                                          std::optional<ce::Il2CppMetadata>& md,
                                          std::string& binary, uint64_t& moduleBase) {
    if (!metaPath.empty()) {
        std::vector<uint8_t> buf;
        std::string err;
        if (!readFileCapped(metaPath, kMaxMetadataBytes, buf, err)) return err;
        md = ce::parseIl2CppMetadata(buf.data(), buf.size());
        if (!md) return "not a valid global-metadata.dat";
        binary = binPath;
        if (binary.empty()) {
            std::error_code ec;
            std::filesystem::path root = std::filesystem::path(metaPath)
                .parent_path().parent_path().parent_path().parent_path();
            for (const char* n : {"GameAssembly.so", "GameAssembly.dll", "libil2cpp.so"}) {
                std::filesystem::path c = root / n;
                if (std::filesystem::is_regular_file(c, ec)) { binary = c.string(); break; }
            }
        }
        if (binary.empty()) return "GameAssembly binary not found; pass one explicitly";
        moduleBase = 0;
        return {};
    }
    auto* p = getProc(L);
    if (!p) return "no target process and no metadata path";
    if (!ce::moduleFilesAreLocal(*p)) return ce::kRemoteModuleFilesError;
    auto paths = mappedFilePaths(*p);
    auto mp = ce::findIl2CppMetadataPath(paths);
    if (!mp) return "global-metadata.dat not found for this process";
    std::vector<uint8_t> buf;
    std::string err;
    if (!readFileCapped(*mp, kMaxMetadataBytes, buf, err)) return err;
    md = ce::parseIl2CppMetadata(buf.data(), buf.size());
    if (!md) return "failed to parse metadata";
    binary = ce::findGameAssemblyPath(paths);
    if (binary.empty()) return "GameAssembly binary not mapped in this process";
    for (const auto& m : p->modules())
        if (m.path == binary) { moduleBase = m.base; break; }
    return {};
}

// getIl2CppMethods(className [, metadataPath [, binaryPath]]) -> { {name, rva,
//   address}, ... } | nil, err. Resolves a class's method code addresses. In the
// open-process case `address` is the live runtime address (module base + rva); in
// file mode it equals the rva.
int l_getIl2CppMethods(lua_State* L) {
    checkOptionalStrings(L, 1, 3);
    std::string className, metaPath, binPath;
    if (lua_gettop(L) >= 1 && !lua_isnil(L, 1)) className = luaL_checkstring(L, 1);
    if (lua_gettop(L) >= 2 && !lua_isnil(L, 2)) metaPath = luaL_checkstring(L, 2);
    if (lua_gettop(L) >= 3 && !lua_isnil(L, 3)) binPath = luaL_checkstring(L, 3);
    if (className.empty()) { lua_pushnil(L); lua_pushstring(L, "class name required"); return 2; }

    std::optional<ce::Il2CppMetadata> md;
    std::string binary;
    uint64_t moduleBase = 0;
    std::string err = luaIl2CppMethodContext(L, metaPath, binPath, md, binary, moduleBase);
    if (!err.empty()) { lua_pushnil(L); lua_pushstring(L, err.c_str()); return 2; }

    auto methods = ce::resolveIl2CppMethods(*md, binary, className);
    lua_newtable(L);
    int mi = 1;
    for (const auto& m : methods) {
        lua_newtable(L);
        lua_pushstring(L, m.name.c_str());                       lua_setfield(L, -2, "name");
        lua_pushinteger(L, (lua_Integer)m.rva);                  lua_setfield(L, -2, "rva");
        lua_pushinteger(L, (lua_Integer)(moduleBase + m.rva));   lua_setfield(L, -2, "address");
        lua_rawseti(L, -2, mi++);
    }
    return 1;
}

// findIl2CppMethod(className, methodName [, metadataPath [, binaryPath]]) ->
//   address | nil, err. The code address of one method (module base + rva live,
//   or the rva in file mode). Useful for hooking a game function.
int l_findIl2CppMethod(lua_State* L) {
    luaL_checkstring(L, 1); luaL_checkstring(L, 2); checkOptionalStrings(L, 3, 4);
    std::string className = luaL_checkstring(L, 1);
    std::string methodName = luaL_checkstring(L, 2);
    std::string metaPath, binPath;
    if (lua_gettop(L) >= 3 && !lua_isnil(L, 3)) metaPath = luaL_checkstring(L, 3);
    if (lua_gettop(L) >= 4 && !lua_isnil(L, 4)) binPath = luaL_checkstring(L, 4);

    std::optional<ce::Il2CppMetadata> md;
    std::string binary;
    uint64_t moduleBase = 0;
    std::string err = luaIl2CppMethodContext(L, metaPath, binPath, md, binary, moduleBase);
    if (!err.empty()) { lua_pushnil(L); lua_pushstring(L, err.c_str()); return 2; }

    for (const auto& m : ce::resolveIl2CppMethods(*md, binary, className))
        if (m.name == methodName) { lua_pushinteger(L, (lua_Integer)(moduleBase + m.rva)); return 1; }
    lua_pushnil(L);
    lua_pushstring(L, "method not found (or has no compiled body)");
    return 2;
}
} // namespace ce::lua_detail
