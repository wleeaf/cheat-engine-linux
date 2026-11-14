/// Lua bindings: the debugger (breakpoints, registers, find what
/// accesses/writes, break and trace, branch mapper).
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

// ── Debug control ──

int l_debug_getThreadList(lua_State* L) {
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

int l_debug_setBreakpoint(lua_State* L) {
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
    std::string failure;
    if (auto* eng = ce::LuaEngine::instanceFromState(L)) {
        if (auto* sess = eng->debugSession()) {
            realId = (type == 0) ? sess->setSoftwareBreakpoint(address)
                                 : sess->setHardwareBreakpoint(address, type, size);
            // Say why (bad address, no free debug register) instead of
            // returning an id for a breakpoint that will never stop.
            if (realId < 0) {
                const auto error = sess->lastError();
                failure = error ? "breakpoint not set: " + error.message() : "breakpoint not set";
            }
            sess->continueExecution();
        } else if (auto* p = getProc(L)) {
            failure = ce::targetOperationError(*p, ce::TargetFeature::Debugger);
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
    // CE scripts ignore extra results; ours can read why no real breakpoint exists.
    if (!failure.empty()) { lua_pushstring(L, failure.c_str()); return 2; }
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
int l_debug_pumpEvents(lua_State* L) {
    int timeoutMs = static_cast<int>(luaL_optinteger(L, 1, 0));
    auto* eng = ce::LuaEngine::instanceFromState(L);
    if (!eng || !eng->debugAttached()) { lua_pushinteger(L, 0); return 1; }

    int processed = 0;
    ce::LuaEngine::DebugHit hit;
    while (eng->nextDebugHit(hit, processed == 0 ? timeoutMs : 0)) {
        auto* currentSession=eng->debugSession();
        if (!currentSession || currentSession->imageGeneration()!=hit.generation) continue;
        ++processed;
#define X(name, field) lua_pushinteger(L, (lua_Integer)hit.context.field); lua_setglobal(L, name);
        CE_GP_REGS(X)
#undef X
        if (hit.context.hasArmRegisters()) {
            // ARM stops publish their own register names (read-only here; the
            // write-back below covers the x86 names).
            const bool arm64 = hit.context.architecture == ce::CpuArchitecture::Arm64;
            for (int index = 0; index < (arm64 ? 31 : 13); ++index) {
                char name[8];
                std::snprintf(name, sizeof(name), arm64 ? "X%d" : "R%d", index);
                lua_pushinteger(L, (lua_Integer)hit.context.x[index]); lua_setglobal(L, name);
            }
            lua_pushinteger(L, (lua_Integer)hit.context.sp); lua_setglobal(L, "SP");
            lua_pushinteger(L, (lua_Integer)hit.context.pc); lua_setglobal(L, "PC");
            lua_pushinteger(L, (lua_Integer)hit.context.pstate); lua_setglobal(L, "PSTATE");
        }
        lua_pushinteger(L, (lua_Integer)hit.address);     lua_setglobal(L, "BPAddress");
        lua_pushinteger(L,hit.signal); lua_setglobal(L,"DebugSignal");
        lua_pushinteger(L,hit.exitingTid); lua_setglobal(L,"DebugExitingThread");

        if (hit.type==DebugEventType::ProcessExecuted) {
            lua_newtable(L);
            lua_setfield(L,LUA_REGISTRYINDEX,"ce_lua_breakpoints");
        }
        const char* callback=hit.type==DebugEventType::ProcessExecuted ? "debugger_onProcessExecuted" :
            hit.type==DebugEventType::ThreadExiting ? "debugger_onThreadExiting" :
            hit.type==DebugEventType::SignalReceived ? "debugger_onSignalReceived" : "debugger_onBreakpoint";
        lua_getglobal(L,callback);
        if (lua_isfunction(L, -1)) {
            if (lua_pcall(L, 0, 0, 0) != LUA_OK) {
                // A failing handler must not leave the game frozen at the
                // breakpoint: resume (without its half-made register edits),
                // then report the error.
                if (auto* sess = eng->debugSession(); sess && sess->imageGeneration() == hit.generation)
                    sess->continueExecution();
                return lua_error(L);
            }
        } else {
            lua_pop(L, 1);
        }
        // Apply any register edits the handler made via the RIP/RSP/RAX.. globals
        // (CE lets debugger_onBreakpoint rewrite registers), then resume. Target
        // the thread that actually hit, then write it.
        if (auto* sess = eng->debugSession()) {
            if (sess->imageGeneration()!=hit.generation) continue;
            if (hit.type!=DebugEventType::ThreadExiting && sess->selectThread(hit.tid)) {
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

int l_debug_removeBreakpoint(lua_State* L) {
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
                        bool removed=bpType==0 ? sess->removeSoftwareBreakpoint(realId) : sess->removeHardwareBreakpoint(realId);
                        if (!removed) {
                            lua_pop(L,2);
                            lua_pushnil(L); lua_pushstring(L,sess->lastError().message().c_str()); return 2;
                        }
                    }
    }
    lua_pop(L, 1);                          // pop the entry
    lua_pushnil(L);
    lua_rawseti(L, -2, id);                 // clear the bookkeeping entry
    lua_pop(L, 1);                          // pop the table
    lua_pushboolean(L, 1);
    return 1;
}

int l_debug_continueFromBreakpoint(lua_State* L) {
    if (auto* eng = ce::LuaEngine::instanceFromState(L))
        if (eng->debugAttached())
            if (auto* sess = eng->debugSession()) sess->continueExecution();
    lua_pushboolean(L, 0);
    lua_setfield(L, LUA_REGISTRYINDEX, "ce_lua_debug_broken");
    lua_pushboolean(L, 1);
    return 1;
}

int l_debug_getBreakpointList(lua_State* L) {
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

int l_debug_isDebugging(lua_State* L) {
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

int l_debug_isBroken(lua_State* L) {
    lua_getfield(L, LUA_REGISTRYINDEX, "ce_lua_debug_broken");
    bool broken = lua_toboolean(L, -1) != 0;
    lua_pop(L, 1);
    lua_pushboolean(L, broken);
    return 1;
}

// The engine's debug session when one is already attached. Reading or setting
// registers must not attach the debugger as a side effect.
static ce::DebugSession* attachedDebugSession(lua_State* L) {
    auto* eng = ce::LuaEngine::instanceFromState(L);
    return eng && eng->debugAttached() ? eng->debugSession() : nullptr;
}

// debug_getRegisters([tid]) -> table of every register at the current stop
// (RAX..R15, RIP, RSP, RBP, RSI, RDI, RFLAGS, segment + debug regs). Meaningful
// only while broken at a breakpoint; returns nil unless the debugger is attached.
int l_debug_getRegisters(lua_State* L) {
    auto* sess = attachedDebugSession(L);
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
int l_debug_setRegister(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    uint64_t val = (uint64_t)luaL_checkinteger(L, 2);
    auto* sess = attachedDebugSession(L);
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
int l_debug_getStack(lua_State* L) {
    int count = (int)luaL_optinteger(L, 1, 16);
    auto* sess = attachedDebugSession(L);
    auto* p    = getProc(L);
    if (!sess || !p) { lua_pushnil(L); return 1; }
    uint64_t rsp = sess->getStopContext().rsp;
    size_t ps = p->pointerWidth();
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

// Busy-free sleep in small chunks (keeps the tool loops collecting over `seconds`).
static bool validSampleDuration(double seconds) {
    return std::isfinite(seconds) && seconds>=0 && static_cast<long double>(seconds)*1e6L<=std::numeric_limits<long>::max();
}
static void sleepSeconds(double seconds) {
    long us=static_cast<long>(static_cast<long double>(seconds)*1e6L);
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
    if (!validSampleDuration(seconds)) {lua_pushnil(L);lua_pushliteral(L,"Sampling duration must be finite, nonnegative and representable");return 2;}
    int watchSize  = (int)luaL_optinteger(L, 3, 4);
    ce::os::LinuxDebugger dbg;
    ce::CodeFinder finder;
    if (!finder.start(*p, dbg, addr, writesOnly, watchSize)) {
        lua_pushnil(L);
        lua_pushstring(L, ce::targetOperationError(*p, ce::TargetFeature::HardwareWatchpoint, finder.lastError()).c_str());
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
int l_findWhatWrites(lua_State* L)   { return codeFinderImpl(L, true); }
int l_findWhatAccesses(lua_State* L) { return codeFinderImpl(L, false); }

// ── Break and Trace (single-step from a start address) ──
// breakAndTrace(startAddress [, maxSteps=100 [, {stepOverCalls,stayInModule,
//   stopAddress,moduleBase,moduleEnd} ]]) -> array of { address, instruction, rip }.
int l_breakAndTrace(lua_State* L) {
    // Options first, as in pointerScan: their __index may close the process.
    const auto start = (uintptr_t)luaL_checkinteger(L, 1);
    const int maxSteps = (int)luaL_optinteger(L, 2, 100);
    std::optional<bool> stepOverCalls, stayInModule;
    std::optional<uintptr_t> stopAddress, moduleBase, moduleEnd;
    if (lua_istable(L, 3)) {
        lua_getfield(L, 3, "stepOverCalls"); if (lua_isboolean(L, -1)) stepOverCalls = lua_toboolean(L, -1); lua_pop(L, 1);
        lua_getfield(L, 3, "stayInModule");  if (lua_isboolean(L, -1)) stayInModule  = lua_toboolean(L, -1); lua_pop(L, 1);
        lua_getfield(L, 3, "stopAddress");   if (lua_isinteger(L, -1)) stopAddress = (uintptr_t)lua_tointeger(L, -1); lua_pop(L, 1);
        lua_getfield(L, 3, "moduleBase");    if (lua_isinteger(L, -1)) moduleBase  = (uintptr_t)lua_tointeger(L, -1); lua_pop(L, 1);
        lua_getfield(L, 3, "moduleEnd");     if (lua_isinteger(L, -1)) moduleEnd   = (uintptr_t)lua_tointeger(L, -1); lua_pop(L, 1);
    }
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    ce::TraceConfig cfg;
    cfg.startAddress = start;
    cfg.maxSteps = maxSteps;
    if (stepOverCalls) cfg.stepOverCalls = *stepOverCalls;
    if (stayInModule) cfg.stayInModule = *stayInModule;
    if (stopAddress) cfg.stopAddress = *stopAddress;
    if (moduleBase) cfg.moduleBase = *moduleBase;
    if (moduleEnd) cfg.moduleEnd = *moduleEnd;
    ce::os::LinuxDebugger dbg;
    ce::Tracer tracer;
    auto entries = tracer.trace(*p, dbg, cfg);
    if (entries.empty() && tracer.lastError()) {
        lua_pushnil(L);
        lua_pushstring(L, ce::targetOperationError(*p, ce::TargetFeature::Trace, tracer.lastError()).c_str());
        return 2;
    }
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

// ── Branch mapper (hardware LBR via perf_event_open) ──
// branchMapAvailable() -> bool (branch-stack perf probe on the calling thread)
int l_branchMapAvailable(lua_State* L) {
    lua_pushboolean(L, ce::LbrTracer::available());
    return 1;
}
// branchMap([seconds=1 [, tid]]) -> array of { from, to, mispred, predicted }.
// Samples the CPU branch buffer for `seconds` on `tid` (default main thread).
int l_branchMap(lua_State* L) {
    auto* p = getProc(L);
    if (!p) { lua_pushnil(L); return 1; }
    if (!localTargetPid(p)) {
        lua_pushnil(L);lua_pushstring(L,"Branch sampling requires a live local process target");return 2;
    }
    double seconds = luaL_optnumber(L, 1, 1.0);
    if (!validSampleDuration(seconds)) {lua_pushnil(L);lua_pushliteral(L,"Sampling duration must be finite, nonnegative and representable");return 2;}
    const lua_Integer requested=luaL_optinteger(L,2,p->pid());
    if (requested<=0 || requested>std::numeric_limits<pid_t>::max()) {
        lua_pushnil(L);lua_pushliteral(L,"Choose a positive target thread ID within the kernel PID range");return 2;
    }
    const pid_t tid=static_cast<pid_t>(requested);
    ce::LbrTracer lbr;
    if (!lbr.start(tid)) {
        lua_pushnil(L);
        lua_pushstring(L,lbr.lastError().c_str());
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
} // namespace ce::lua_detail
