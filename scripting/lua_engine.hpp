#pragma once
/// Lua 5.3 scripting engine with CE API bindings.

#include "platform/process_api.hpp"
#include "scanner/memory_scanner.hpp"
#include "symbols/elf_symbols.hpp"
#include "core/types.hpp"          // CpuContext
#include <string>
#include <expected>
#include <functional>
#include <memory>
#include <deque>
#include <map>
#include <vector>
#include <mutex>
#include <condition_variable>

struct lua_State;

namespace ce {

class IAddressList;
class DebugSession;
namespace os { class CEServerClient; }

class LuaEngine {
public:
    LuaEngine();
    ~LuaEngine();

    LuaEngine(const LuaEngine&) = delete;

    /// Set the target process (enables memory functions in Lua).
    void setProcess(ProcessHandle* proc) { ownedProc_.reset(); proc_ = proc; }
    void setOwnedProcess(std::unique_ptr<ProcessHandle> proc);

    /// Take ownership of the ceserver client backing a remote process handle. The
    /// client must outlive the RemoteProcessHandle that references it, so the engine
    /// holds it here (destroyed after ownedProc_). Set it BEFORE setOwnedProcess.
    void setOwnedCeserverClient(std::unique_ptr<os::CEServerClient> client);
    void setResolver(SymbolResolver* resolver) { resolver_ = resolver; }

    /// Set the live cheat-table address list. The MemoryRecord/AddressList Lua API
    /// becomes usable once a non-null pointer is set. Subscribes a single activation
    /// dispatcher that fans out to per-record OnActivate callbacks stored in the Lua
    /// registry.
    void setAddressList(IAddressList* list);
    IAddressList* addressList() const { return addressList_; }

    /// Execute a Lua string. Returns error message or empty on success.
    std::string execute(const std::string& code);

    /// Execute a Lua string and return its first return value coerced to a
    /// string. Used by AutoAssembler {$lua} blocks: the Lua chunk's return
    /// value is spliced back into the AA stream.
    /// On Lua error returns std::unexpected with the Lua error message.
    std::expected<std::string, std::string> evalToString(const std::string& code);

    /// Execute a Lua file.
    std::string executeFile(const std::string& path);

    /// Set a callback for Lua print output.
    void setOutputCallback(std::function<void(const std::string&)> cb) { outputCb_ = std::move(cb); }

    lua_State* state() { return L_; }

    // ── Interactive debugger backing the Lua debug_* API (P2 #15) ──
    struct DebugHit { pid_t tid = 0; uintptr_t address = 0; CpuContext context{}; };
    ProcessHandle* process() const { return proc_; }
    /// Lazily create + attach a DebugSession to the current process, wiring a
    /// tracer-thread callback that queues each breakpoint hit for the Lua thread.
    /// Returns null if no process is set or the attach fails.
    DebugSession* debugSession();
    /// True if a debug session is attached.
    bool debugAttached() const;
    /// Pop the next queued breakpoint hit, waiting up to timeoutMs. False on timeout.
    bool nextDebugHit(DebugHit& out, int timeoutMs);

    static LuaEngine* instanceFromState(lua_State* L);

    // ── CE timer API backing (createTimer / timer_setInterval / timer_onTimer) ──
    // Timers fire their Lua callback from pumpTimers(), which the host calls on the
    // Lua thread (the GUI drives it with a QTimer). cbRef is a luaL_ref into the
    // registry. Returns the new timer id.
    int  createTimer(double intervalMs);
    void setTimerInterval(int id, double intervalMs);
    void setTimerCallback(int id, int cbRef);   // luaL_ref value; replaces+frees any prior
    void setTimerEnabled(int id, bool enabled);
    void destroyTimer(int id);
    bool isTimer(int id) const { return timers_.count(id) != 0; }
    /// Fire every enabled timer whose interval has elapsed. Safe to call often.
    void pumpTimers();

    // ── CE stringlist object (createStringlist / stringlist_* ) ──
    // A named list of strings; indices are 0-based (CE convention).
    int  createStringlist();
    void stringlistAdd(int id, const std::string& s);
    int  stringlistCount(int id) const;
    std::string stringlistGet(int id, int index) const;
    void stringlistSet(int id, int index, const std::string& s);
    void stringlistRemove(int id, int index);
    void stringlistClear(int id);
    bool isStringlist(int id) const { return stringlists_.count(id) != 0; }
    void destroyStringlist(int id) { stringlists_.erase(id); }

    /// Host hook for selectFilePath(sender, settingName): opens a file chooser and
    /// returns the chosen path (empty = cancelled). Unset (headless) => returns "".
    void setFilePicker(std::function<std::string(const std::string& settingName)> cb) {
        filePicker_ = std::move(cb);
    }
    std::string pickFilePath(const std::string& settingName) {
        return filePicker_ ? filePicker_(settingName) : std::string();
    }

    std::function<void(const std::string&)> outputCb_;

private:
    void registerBindings();

    lua_State* L_ = nullptr;
    // Declared before ownedProc_ so it is destroyed AFTER the remote handle that
    // points into it (members destroy in reverse declaration order).
    std::unique_ptr<os::CEServerClient> ownedCeserverClient_;
    std::unique_ptr<ProcessHandle> ownedProc_;
    ProcessHandle* proc_ = nullptr;
    SymbolResolver* resolver_ = nullptr;
    IAddressList* addressList_ = nullptr;

    // Order matters: debugSession_ is declared LAST so it is destroyed FIRST —
    // its destructor joins the tracer thread, whose callback touches the members
    // below, so they must still be alive during that join.
    std::mutex debugMutex_;
    std::condition_variable debugCv_;
    std::deque<DebugHit> debugQueue_;
    std::unique_ptr<DebugSession> debugSession_;

    struct LuaTimer { double intervalMs = 1000; double lastMs = 0; int cbRef = -2 /*LUA_NOREF*/; bool enabled = true; };
    std::map<int, LuaTimer> timers_;
    std::map<int, std::vector<std::string>> stringlists_;
    int nextObjectId_ = 1;   // shared id space for timers + stringlists (object_destroy)
    std::function<std::string(const std::string&)> filePicker_;
};

/// Register extended CE API bindings (defined in lua_bindings.cpp)
void registerExtendedBindings(lua_State* L);

} // namespace ce
