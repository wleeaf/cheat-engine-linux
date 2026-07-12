#include "core/expression.hpp"
#include "scripting/lua_engine.hpp"
#include "core/address_list.hpp"
#include "debug/debug_session.hpp"

extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}

#include <cstring>
#include <chrono>
#include <exception>
#include <utility>

namespace ce {

// Store engine pointer in Lua registry
static const char* ENGINE_KEY = "ce_engine";
static const char* ADDRESSLIST_KEY = "ce_addresslist";
static const char* MEMREC_CALLBACKS_KEY = "ce_memrec_callbacks";

LuaEngine* LuaEngine::instanceFromState(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, ENGINE_KEY);
    auto* eng = (LuaEngine*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    return eng;
}

void LuaEngine::setOwnedProcess(std::unique_ptr<ProcessHandle> proc) {
    ownedProc_ = std::move(proc);
    proc_ = ownedProc_.get();

    if (L_) {
        lua_pushlightuserdata(L_, proc_);
        lua_setfield(L_, LUA_REGISTRYINDEX, "ce_proc");
    }
}

DebugSession* LuaEngine::debugSession() {
    if (debugSession_) return debugSession_.get();
    if (!proc_) return nullptr;
    auto sess = std::make_unique<DebugSession>();
    // Runs on the tracer thread — it MUST NOT touch Lua. It only queues the hit;
    // the Lua thread drains the queue in the debug_pumpEvents binding.
    sess->setEventCallback([this](const DebugEvent& e) {
        if (e.type != DebugEventType::BreakpointHit &&
            e.type != DebugEventType::ExceptionBreakpointHit) return;
        {
            std::lock_guard<std::mutex> lk(debugMutex_);
            debugQueue_.push_back({e.tid, e.address, e.context});
        }
        debugCv_.notify_all();
    });
    if (!sess->attach(proc_->pid(), proc_)) return nullptr;
    debugSession_ = std::move(sess);
    return debugSession_.get();
}

bool LuaEngine::debugAttached() const {
    return debugSession_ && debugSession_->isAttached();
}

bool LuaEngine::nextDebugHit(DebugHit& out, int timeoutMs) {
    std::unique_lock<std::mutex> lk(debugMutex_);
    if (!debugCv_.wait_for(lk, std::chrono::milliseconds(timeoutMs),
                           [this] { return !debugQueue_.empty(); }))
        return false;
    out = debugQueue_.front();
    debugQueue_.pop_front();
    return true;
}

void LuaEngine::setAddressList(IAddressList* list) {
    addressList_ = list;
    if (!L_) return;

    lua_pushlightuserdata(L_, list);
    lua_setfield(L_, LUA_REGISTRYINDEX, ADDRESSLIST_KEY);

    if (!list) return;

    // Subscribe a single C++ callback that fans out to the per-record Lua callbacks
    // stored in LUA_REGISTRYINDEX[MEMREC_CALLBACKS_KEY] keyed by record id.
    list->setActivationCallback([this](int id, bool active) {
        if (!L_) return;
        lua_getfield(L_, LUA_REGISTRYINDEX, MEMREC_CALLBACKS_KEY);
        if (!lua_istable(L_, -1)) { lua_pop(L_, 1); return; }
        lua_rawgeti(L_, -1, id);
        if (lua_isfunction(L_, -1)) {
            lua_pushboolean(L_, active);
            if (lua_pcall(L_, 1, 0, 0) != LUA_OK) {
                const char* msg = lua_tostring(L_, -1);
                std::string err = msg ? msg : "lua error";
                lua_pop(L_, 1);
                if (outputCb_) outputCb_("OnActivate error: " + err);
            }
        } else {
            lua_pop(L_, 1);
        }
        lua_pop(L_, 1); // pop callbacks table
    });
}

// ── Lua bindings ──

static int l_readInteger(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_proc");
    auto* proc = (ProcessHandle*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    if (!proc) { lua_pushnil(L); return 1; }

    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    int32_t val = 0;
    auto r = proc->read(addr, &val, sizeof(val));
    if (r) lua_pushinteger(L, val);
    else lua_pushnil(L);
    return 1;
}

static int l_writeInteger(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_proc");
    auto* proc = (ProcessHandle*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    if (!proc) return 0;

    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    int32_t val = (int32_t)luaL_checkinteger(L, 2);
    proc->write(addr, &val, sizeof(val));
    return 0;
}

static int l_readFloat(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_proc");
    auto* proc = (ProcessHandle*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    if (!proc) { lua_pushnil(L); return 1; }

    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    float val = 0;
    auto r = proc->read(addr, &val, sizeof(val));
    if (r) lua_pushnumber(L, val);
    else lua_pushnil(L);
    return 1;
}

static int l_writeFloat(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_proc");
    auto* proc = (ProcessHandle*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    if (!proc) return 0;

    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    float val = (float)luaL_checknumber(L, 2);
    proc->write(addr, &val, sizeof(val));
    return 0;
}

static int l_readBytes(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_proc");
    auto* proc = (ProcessHandle*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    if (!proc) { lua_pushnil(L); return 1; }

    uintptr_t addr = (uintptr_t)luaL_checkinteger(L, 1);
    int size = (int)luaL_checkinteger(L, 2);
    luaL_argcheck(L, size >= 0, 2, "size must be non-negative");
    // Allocate under try/catch: a large positive size can throw bad_alloc, which
    // must not escape this C function into C-compiled Lua frames (UB).
    try {
        std::vector<uint8_t> buf(size);
        auto r = proc->read(addr, buf.data(), size);
        if (r) {
            lua_newtable(L);
            for (int i = 0; i < (int)*r; ++i) {
                lua_pushinteger(L, buf[i]);
                lua_rawseti(L, -2, i + 1);
            }
        } else {
            lua_pushnil(L);
        }
    } catch (const std::exception& ex) {
        return luaL_error(L, "%s", ex.what());
    }
    return 1;
}

static int l_getAddress(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_resolver");
    auto* resolver = (SymbolResolver*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_proc");
    auto* proc = (ProcessHandle*)lua_touserdata(L, -1);
    lua_pop(L, 1);

    const char* name = luaL_checkstring(L, 1);
    uintptr_t addr = resolver ? resolver->lookup(name) : 0;
    // Fall back to the full expression parser so getAddress also accepts hex,
    // "module+offset", arithmetic and [pointer] derefs — as CE's getAddress does.
    if (!addr) {
        ExpressionParser parser(proc, resolver);
        if (auto v = parser.parse(name)) addr = *v;
    }
    if (addr) lua_pushinteger(L, (lua_Integer)addr);
    else      lua_pushnil(L);
    return 1;
}

static int l_getModuleBase(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_proc");
    auto* proc = (ProcessHandle*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    if (!proc) { lua_pushnil(L); return 1; }

    const char* name = luaL_checkstring(L, 1);
    auto mods = proc->modules();
    for (auto& m : mods) {
        if (m.name == name) {
            lua_pushinteger(L, (lua_Integer)m.base);
            return 1;
        }
    }
    lua_pushnil(L);
    return 1;
}

static int l_getProcessId(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_proc");
    auto* proc = (ProcessHandle*)lua_touserdata(L, -1);
    lua_pop(L, 1);
    if (!proc) { lua_pushinteger(L, 0); return 1; }
    lua_pushinteger(L, proc->pid());
    return 1;
}

// ── Engine implementation ──

LuaEngine::LuaEngine() {
    L_ = luaL_newstate();
    luaL_openlibs(L_);

    // Store engine pointer
    lua_pushlightuserdata(L_, this);
    lua_setfield(L_, LUA_REGISTRYINDEX, ENGINE_KEY);

    registerBindings();
}

LuaEngine::~LuaEngine() {
    if (L_) lua_close(L_);
}

void LuaEngine::registerBindings() {
    // Override print
    lua_pushcfunction(L_, [](lua_State* L) -> int {
        auto* eng = LuaEngine::instanceFromState(L);
        int n = lua_gettop(L);
        std::string out;
        for (int i = 1; i <= n; ++i) {
            if (i > 1) out += "\t";
            out += luaL_tolstring(L, i, nullptr);
            lua_pop(L, 1);
        }
        if (eng && eng->outputCb_)
            eng->outputCb_(out);
        else
            fprintf(stdout, "%s\n", out.c_str());
        return 0;
    });
    lua_setglobal(L_, "print");

    // Core memory functions
    lua_register(L_, "readInteger", l_readInteger);
    lua_register(L_, "writeInteger", l_writeInteger);
    lua_register(L_, "readFloat", l_readFloat);
    lua_register(L_, "writeFloat", l_writeFloat);
    lua_register(L_, "readBytes", l_readBytes);
    lua_register(L_, "getAddress", l_getAddress);
    // CE's getAddressSafe returns nil on failure (getAddress throws). Our
    // getAddress already returns nil, so alias it — cheat-table scripts that call
    // getAddressSafe(...) then work unchanged.
    lua_register(L_, "getAddressSafe", l_getAddress);
    lua_register(L_, "getModuleBase", l_getModuleBase);
    lua_register(L_, "getProcessID", l_getProcessId);

    // Store process and resolver pointers (updated when setProcess/setResolver called)
    lua_pushlightuserdata(L_, nullptr);
    lua_setfield(L_, LUA_REGISTRYINDEX, "ce_proc");
    lua_pushlightuserdata(L_, nullptr);
    lua_setfield(L_, LUA_REGISTRYINDEX, "ce_resolver");
    lua_pushlightuserdata(L_, nullptr);
    lua_setfield(L_, LUA_REGISTRYINDEX, ADDRESSLIST_KEY);

    // OnActivate callback dispatch table
    lua_newtable(L_);
    lua_setfield(L_, LUA_REGISTRYINDEX, MEMREC_CALLBACKS_KEY);

    // Register extended bindings (readByte, readString, disassemble, autoAssemble, etc.)
    registerExtendedBindings(L_);
}

std::string LuaEngine::execute(const std::string& code) {
    // Update process/resolver pointers
    lua_pushlightuserdata(L_, proc_);
    lua_setfield(L_, LUA_REGISTRYINDEX, "ce_proc");
    lua_pushlightuserdata(L_, resolver_);
    lua_setfield(L_, LUA_REGISTRYINDEX, "ce_resolver");

    if (luaL_dostring(L_, code.c_str()) != LUA_OK) {
        const char* msg = lua_tostring(L_, -1);
        std::string err = msg ? msg : "lua error";
        lua_pop(L_, 1);
        return err;
    }
    return {};
}

std::expected<std::string, std::string>
LuaEngine::evalToString(const std::string& code) {
    if (!L_) return std::unexpected("lua state not initialised");
    lua_pushlightuserdata(L_, proc_);
    lua_setfield(L_, LUA_REGISTRYINDEX, "ce_proc");
    lua_pushlightuserdata(L_, resolver_);
    lua_setfield(L_, LUA_REGISTRYINDEX, "ce_resolver");

    int top = lua_gettop(L_);
    if (luaL_dostring(L_, code.c_str()) != LUA_OK) {
        std::string err = lua_tostring(L_, -1) ? lua_tostring(L_, -1) : "lua error";
        lua_pop(L_, 1);
        return std::unexpected(err);
    }
    int returned = lua_gettop(L_) - top;
    std::string result;
    if (returned > 0) {
        const char* s = lua_tostring(L_, -returned);
        if (s) result = s;
        lua_pop(L_, returned);
    }
    return result;
}

std::string LuaEngine::executeFile(const std::string& path) {
    lua_pushlightuserdata(L_, proc_);
    lua_setfield(L_, LUA_REGISTRYINDEX, "ce_proc");
    lua_pushlightuserdata(L_, resolver_);
    lua_setfield(L_, LUA_REGISTRYINDEX, "ce_resolver");

    if (luaL_dofile(L_, path.c_str()) != LUA_OK) {
        const char* msg = lua_tostring(L_, -1);
        std::string err = msg ? msg : "lua error";
        lua_pop(L_, 1);
        return err;
    }
    return {};
}

} // namespace ce
