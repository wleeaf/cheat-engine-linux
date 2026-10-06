#include "test_target.hpp"
#include "core/simple_address_list.hpp"
#include "core/simple_hook.hpp"
#include "debug/breakpoint_manager.hpp"
#include "debug/code_finder.hpp"
#include "debug/debug_session.hpp"
#include "debug/tracer.hpp"
#include "debug/patch.hpp"
#include "debug/stack_trace.hpp"
#include "platform/linux/linux_process.hpp"
#include "platform/linux/process_watcher.hpp"
#include "platform/linux/ptrace_wrapper.hpp"
#include "platform/linux/ceserver_server.hpp"
#include "platform/linux/ceserver_process.hpp"
#include "scripting/lua_engine.hpp"

extern "C" {
#include <lua.h>
#include <lauxlib.h>
}

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <cstdio>
#include <fstream>
#include <thread>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <elf.h>
#include <limits>

using namespace ce;
namespace fs = std::filesystem;
namespace {
int failures = 0;
int tracePipe = -1;
__attribute__((noinline)) void traceAfterCancel() { asm volatile("nop" ::: "memory"); }
__attribute__((noinline)) void traceBlockingCall() {
    char token = 0;
    (void)::read(tracePipe, &token, 1);
    asm volatile("nop" ::: "memory");
}
__attribute__((noinline)) void traceCaller() {
    traceBlockingCall();
    asm volatile("nop" ::: "memory");
}
void check(bool ok, const char* name) {
    std::printf("%s: %s\n", ok ? "OK" : "FAILED", name);
    if (!ok) ++failures;
}

class ModelProcess : public ProcessHandle {
public:
    std::vector<uint8_t> bytes = std::vector<uint8_t>(8192, 0x90);
    bool wide = true;
    bool shortReads = false;
    bool shortWrites = false;
    bool partialOnce = false;
    MemProt protection = MemProt::All;
    pid_t pid() const override { return getpid(); }
    bool is64bit() const override { return wide; }
    TargetDescription targetDescription() override { return ce::test::x86Target(is64bit(), runs32BitCode()); }
    Result<size_t> read(uintptr_t at, void* out, size_t n) override {
        if (at > bytes.size() || n > bytes.size() - at) return std::unexpected(std::make_error_code(std::errc::bad_address));
        size_t got = shortReads && n ? n - 1 : n;
        std::memcpy(out, bytes.data() + at, got);
        return got;
    }
    Result<size_t> write(uintptr_t at, const void* in, size_t n) override {
        if (at > bytes.size() || n > bytes.size() - at) return std::unexpected(std::make_error_code(std::errc::bad_address));
        size_t got = (shortWrites || partialOnce) && n ? n - 1 : n;
        partialOnce = false;
        std::memcpy(bytes.data() + at, in, got);
        return got;
    }
    std::vector<MemoryRegion> queryRegions() override { return {{0, bytes.size(), protection, MemType::Private, MemState::Committed, ""}}; }
    std::optional<MemoryRegion> queryRegion(uintptr_t at) override { return at < bytes.size() ? std::optional(queryRegions()[0]) : std::nullopt; }
    Result<uintptr_t> allocate(size_t, MemProt, uintptr_t) override { return 4096; }
    Result<void> free(uintptr_t, size_t) override { return {}; }
    Result<void> protect(uintptr_t, size_t, MemProt value) override { protection = value; return {}; }
    std::vector<ModuleInfo> modules() override { return {{256, 64, "fixture", "", wide}}; }
    std::vector<ThreadInfo> threads() override { return {}; }
};

bool isolated(const std::function<bool()>& body) {
    std::fflush(nullptr);
    pid_t child = fork();
    if (!child) _exit(body() ? 0 : 1);
    if (child < 0) return false;
    int status = 0;
    if (waitpid(child, &status, 0) != child) return false;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

bool waitUntil(const std::function<bool()>& ready) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (!ready() && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    return ready();
}

void engineTests(const fs::path& root) {
    ModelProcess proc;
    LuaEngine engine;
    engine.setProcess(&proc);
    lua_pushliteral(engine.state(), "sentinel");
    int top = lua_gettop(engine.state());
    for (int i = 0; i < 20; ++i) engine.execute("return nil, 1, nil");
    check(lua_gettop(engine.state()) == top, "executing scripts discards their return values without growing the Lua stack");
    lua_settop(engine.state(), top);
    auto file = root / "returns.lua";
    { std::ofstream out(file); out << "return 1,2,3"; }
    engine.executeFile(file.string());
    check(lua_gettop(engine.state()) == top, "executing script files preserves the caller's stack");
    lua_settop(engine.state(), top);
    auto value = engine.evalToString("return 'a'..string.char(0)..'b'");
    check(value && *value == std::string("a\0b", 3), "Lua evaluation preserves embedded NUL bytes");
    engine.execute("calls=0; ta=createTimer(1); tb=createTimer(1); timer_onTimer(ta,function() timer_setEnabled(tb,false) end); timer_onTimer(tb,function() calls=calls+1 end)");
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    engine.pumpTimers();
    check(engine.execute("assert(calls==0); object_destroy(ta); object_destroy(tb)").empty(),
          "timers disabled by an earlier callback do not fire in the same batch");
    engine.execute("calls=0; ta=createTimer(1); tb=createTimer(1); timer_onTimer(ta,function() timer_setInterval(tb,1000000) end); timer_onTimer(tb,function() calls=calls+1 end)");
    std::this_thread::sleep_for(std::chrono::milliseconds(10)); engine.pumpTimers();
    check(engine.execute("assert(calls==0); object_destroy(ta); object_destroy(tb)").empty(),
          "timer interval changes invalidate an already collected due event");
    proc.shortReads = true;
    check(engine.execute("assert(readInteger(256)==nil and readFloat(256)==nil and readQword(256)==nil and readPointer(256)==nil and readByte(256)==nil)").empty(),
          "Lua scalar reads reject incomplete transfers");
    check(engine.execute("assert(readBytes(256,4,true)==nil)").empty(), "Lua byte reads cannot pad short transfers with fabricated zero bytes");
    proc.shortReads = false; proc.shortWrites = true;
    check(engine.execute("assert(writeInteger(256,1)==false and writeFloat(256,1)==false and writeString(256,'a')==false)").empty(),
          "Lua writes report partial transfers as failures");
    proc.shortWrites = false;
    check(engine.execute("assert(not pcall(readBytes,256,4294967297,true))").empty(), "Lua read counts cannot wrap through a narrower integer type");
    SymbolResolver resolver;
    resolver.addUserSymbol(512, "immediate");
    engine.setResolver(&resolver);
    check(luaL_dostring(engine.state(), "assert(getAddress('immediate')==512)") == LUA_OK,
          "resolver setters immediately update native Lua callbacks");
    engine.setResolver(nullptr);
    proc.bytes[256] = 0x12; proc.bytes[257] = 0x34; proc.bytes[270] = 0x12; proc.bytes[271] = 0x34;
    check(engine.execute("assert(AOBScanModuleUnique('fixture','12 34')==nil)").empty(),
          "module-unique AOB searches reject ambiguous matches");

    SimpleAddressList first, second;
    int a = first.createEntry(256, ValueType::Int32, "first");
    int b = second.createEntry(256, ValueType::Int32, "second");
    engine.setAddressList(&first);
    engine.execute("activationCount=0; oldRecord=getAddressList():getMemoryRecord(0); oldRecord.OnActivate=function() activationCount=activationCount+1 end");
    engine.setAddressList(&second);
    second.setActive(b, true);
    check(engine.execute("assert(activationCount==0)").empty(), "switching address lists does not reuse old activation callbacks");
    engine.execute("oldRecord.Description='stale'");
    check(second.byId(b)->description == "second" && first.byId(a)->description == "first",
          "stale Lua memory records cannot edit a replacement address list");
    engine.setAddressList(nullptr);

    ModelProcess next;
    SimpleHook h; h.address = 256; h.patchLen = 5; h.original.assign(5, 0x90);
    int hook = engine.addHook(h);
    proc.shortWrites = true;
    engine.execute("removeSimpleHook(" + std::to_string(hook) + ")");
    check(engine.isHook(hook), "failed hook removal keeps the original bytes available for retry");
    proc.shortWrites = false;
    proc.bytes[256] = 0xe9;
    engine.setProcess(&next);
    check(!engine.isHook(hook) && proc.bytes[256] == 0x90 && next.bytes[256] == 0x90,
          "process switches restore old hooks and invalidate their registry entries");
    engine.setProcess(nullptr);
}

void debuggerLifecycleTests() {
    check(isolated([] {
        pid_t child = fork();
        if (!child) { prctl(PR_SET_PDEATHSIG, SIGKILL); for (;;) pause(); }
        if (child < 0) return false;
        os::LinuxProcessHandle proc(child);
        ModelProcess next;
        LuaEngine engine;
        engine.setProcess(&proc);
        bool attached = engine.debugSession() != nullptr;
        engine.setProcess(&next);
        bool detached = !engine.debugAttached();
        engine.setProcess(nullptr);
        kill(child, SIGKILL); waitpid(child, nullptr, 0);
        return attached && detached;
    }), "changing a Lua target detaches the previous target's debugger");
    check(isolated([] {
        struct Tracked : ModelProcess { bool* dead; explicit Tracked(bool& flag) : dead(&flag) {} ~Tracked() override { *dead = true; } };
        bool destroyed = false;
        LuaEngine engine;
        engine.setOwnedProcess(std::make_unique<Tracked>(destroyed));
        engine.setProcess(engine.process());
        bool alive = !destroyed;
        engine.setProcess(nullptr);
        return alive;
    }), "setting an owned process to itself does not destroy the handle");
    check(isolated([] {
        os::CeserverServer server;
        uint16_t port = server.start(0);
        if (!port) return false;
        auto client = std::make_unique<os::CEServerClient>();
        std::string error;
        if (!client->connectTcp("127.0.0.1", port, error)) return false;
        auto proc = os::RemoteProcessHandle::open(*client, getpid());
        if (!proc) return false;
        LuaEngine engine;
        engine.setOwnedCeserverClient(std::move(client));
        engine.setOwnedProcess(std::move(proc));
        engine.setOwnedCeserverClient(std::make_unique<os::CEServerClient>());
        bool reset = engine.process() == nullptr;
        server.stop();
        return reset;
    }), "replacing a remote client releases its old process handle before the connection");
    check(isolated([] {
        alarm(5);
        pid_t child = fork();
        if (!child) { prctl(PR_SET_PDEATHSIG, SIGKILL); for (;;) pause(); }
        if (child < 0) return false;
        os::CeserverServer server;
        auto port = server.start(0);
        os::CEServerClient client; std::string error;
        if (!port || !client.connectTcp("127.0.0.1", port, error)) return false;
        auto remote = os::RemoteProcessHandle::open(client, child);
        if (!remote) return false;
        os::LinuxDebugger debugger; DebugSession session; CodeFinder finder; Tracer tracer;
        bool rejected = !session.attach(child, remote.get()) &&
            !finder.start(*remote, debugger, 256) && tracer.trace(*remote, debugger, TraceConfig{.maxSteps=1}).empty();
        finder.stop(); session.detach();
        kill(child, SIGKILL); waitpid(child, nullptr, 0);
        alarm(0);
        return rejected;
    }), "local ptrace backends cannot attach local tasks using remote process IDs");
    check(isolated([] {
        pid_t child = fork();
        if (!child) { prctl(PR_SET_PDEATHSIG, SIGKILL); for (;;) pause(); }
        if (child < 0) return false;
        os::LinuxProcessHandle proc(child);
        os::LinuxDebugger debugger;
        CodeFinder finder;
        bool started = finder.start(proc, debugger, reinterpret_cast<uintptr_t>(&failures), true);
        std::this_thread::sleep_for(std::chrono::milliseconds(40));
        kill(child, SIGKILL);
        bool ended = waitUntil([&] { return !finder.running(); });
        bool rejectedDead = !finder.start(proc, debugger, reinterpret_cast<uintptr_t>(&failures), true);
        finder.stop();
        waitpid(child, nullptr, 0);
        pid_t replacement = fork();
        if (!replacement) { prctl(PR_SET_PDEATHSIG, SIGKILL); for (;;) pause(); }
        if (replacement < 0) return false;
        os::LinuxProcessHandle next(replacement);
        bool restarted = started && ended && rejectedDead && finder.start(next, debugger, reinterpret_cast<uintptr_t>(&failures), true);
        finder.stop();
        kill(replacement, SIGKILL); waitpid(replacement, nullptr, 0);
        return restarted;
    }), "code-finder monitors can restart after their target exits");
    check(isolated([] {
        alarm(3);
        pid_t child = fork();
        if (!child) { prctl(PR_SET_PDEATHSIG, SIGKILL); for (;;) pause(); }
        if (child < 0) return false;
        os::LinuxProcessHandle proc(child);
        os::LinuxDebugger debugger;
        Tracer tracer;
        std::thread cancel([&] { usleep(100000); tracer.cancel(); });
        auto entries = tracer.trace(proc, debugger, TraceConfig{.startAddress=1, .maxSteps=10});
        cancel.join();
        bool alive = kill(child, 0) == 0;
        kill(child, SIGKILL); waitpid(child, nullptr, 0);
        alarm(0);
        return entries.empty() && alive;
    }), "traces waiting for an unreachable start address can be cancelled safely");
    check(isolated([] {
        alarm(5);
        int fds[2]; if (pipe(fds)) return false;
        pid_t child = fork();
        if (!child) {
            prctl(PR_SET_PDEATHSIG, SIGKILL); close(fds[1]);
            char token; (void)::read(fds[0], &token, 1);
            traceAfterCancel(); _exit(0);
        }
        if (child < 0) return false;
        close(fds[0]);
        pid_t unrelated = fork();
        if (!unrelated) _exit(37);
        os::LinuxProcessHandle proc(child); os::LinuxDebugger debugger; Tracer tracer;
        std::thread cancel([&] { usleep(100000); tracer.cancel(); });
        auto entries = tracer.trace(proc, debugger, TraceConfig{.startAddress=reinterpret_cast<uintptr_t>(&traceAfterCancel), .maxSteps=10});
        cancel.join();
        char token = 'x'; (void)::write(fds[1], &token, 1); close(fds[1]);
        int targetStatus = 0, otherStatus = 0;
        bool target = waitpid(child, &targetStatus, 0) == child && WIFEXITED(targetStatus) && WEXITSTATUS(targetStatus) == 0;
        bool other = waitpid(unrelated, &otherStatus, 0) == unrelated && WIFEXITED(otherStatus) && WEXITSTATUS(otherStatus) == 37;
        alarm(0);
        return entries.empty() && target && other;
    }), "trace cancellation disarms its start breakpoint and preserves unrelated child statuses");
    check(isolated([] {
        alarm(5);
        int fds[2]; if (pipe(fds)) return false;
        tracePipe = fds[0];
        pid_t child = fork();
        if (!child) {
            prctl(PR_SET_PDEATHSIG, SIGKILL); close(fds[1]);
            usleep(100000); traceCaller(); _exit(0);
        }
        if (child < 0) return false;
        close(fds[0]);
        os::LinuxProcessHandle proc(child); os::LinuxDebugger debugger; Tracer tracer;
        std::thread cancel([&] { usleep(300000); tracer.cancel(); });
        auto entries = tracer.trace(proc, debugger, TraceConfig{.startAddress=reinterpret_cast<uintptr_t>(&traceCaller), .maxSteps=1000, .stepOverCalls=true});
        cancel.join();
        char token = 'x'; (void)::write(fds[1], &token, 1); close(fds[1]);
        int status = 0;
        bool resumed = waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
        alarm(0);
        return !entries.empty() && resumed;
    }), "cancelling a trace inside a blocked call removes its temporary breakpoint and resumes safely");
    ModelProcess proc; os::LinuxDebugger debugger; Tracer tracer;
    check(tracer.trace(proc, debugger, TraceConfig{.maxSteps=-1}).empty(), "negative trace lengths return without allocating or attaching");
}

void breakpointTests() {
    BreakpointManager manager;
    Breakpoint bp; bp.address = 0x1234; bp.method = BpMethod::Software;
    int id = manager.add(bp);
    auto saved = manager.get(id);
    bp.address = 0x5678;
    for (int i = 0; i < 200; ++i) manager.add(bp);
    check(saved && saved->address == 0x1234, "breakpoint lookups return stable snapshots across later mutations");
    BreakpointManager slots;
    bp.method = BpMethod::Hardware;
    for (int i = 0; i < 4; ++i) slots.add(bp);
    check(slots.add(bp) == -1, "hardware breakpoint exhaustion is reported instead of silently skipping a breakpoint");
    auto initial = slots.list();
    slots.setEnabled(initial[0].id, false);
    int replacement = slots.add(bp);
    slots.setEnabled(initial[0].id, true);
    bool staysDisabled = !slots.get(initial[0].id)->enabled;
    slots.remove(replacement);
    slots.setEnabled(initial[0].id, true);
    check(staysDisabled && slots.get(initial[0].id)->enabled, "reenabling breakpoints never reuses an occupied hardware register");
}

void objectTests() {
    const std::pair<const char*, const char*> cases[] = {
        {"local s=captureSnapshot(0); local gc=getmetatable(s).__gc; gc(s); gc(s); assert(not pcall(function() s:regionCount() end))", "snapshot collection is idempotent and destroyed snapshots reject methods"},
        {"local s=createMemScan(); local gc=getmetatable(s).__gc; gc(s); gc(s); assert(not pcall(function() s:getFoundCount() end))", "scan collection is idempotent and destroyed scans reject methods"},
        {"local s=createHotkey(function() end,1,2,3); local gc=getmetatable(s).__gc; gc(s); gc(s); assert(not pcall(function() s:getKeys() end))", "hotkey collection is idempotent and destroyed hotkeys reject methods"},
        {"local s=createThread(function() end,true); s.Name=string.rep('x',100); local gc=getmetatable(s).__gc; gc(s); gc(s); assert(not pcall(function() s:resume() end))", "thread collection is idempotent and destroyed threads reject methods"},
        {"local s; s=createThread(function() getmetatable(s).__gc(s) end,true); assert(s:resume()); assert(not pcall(function() return s.Finished end))", "collecting a thread in its callback does not invalidate its executing state"},
    };
    for (const auto& [script, name] : cases)
        check(isolated([&] { ModelProcess proc; LuaEngine engine; engine.setProcess(&proc); return engine.execute(script).empty(); }), name);
}

template<class Header, class Section, class Sym>
void elfSymbolTests(const fs::path& root, int elfClass) {
    std::vector<uint8_t> bytes(512);
    Header header{};
    std::memcpy(header.e_ident, ELFMAG, SELFMAG);
    header.e_ident[EI_CLASS] = elfClass; header.e_ident[EI_DATA] = ELFDATA2LSB;
    header.e_ident[EI_VERSION] = EV_CURRENT; header.e_version = EV_CURRENT;
    header.e_type = ET_DYN; header.e_ehsize = sizeof(Header);
    header.e_shoff = 128; header.e_shnum = 3; header.e_shentsize = sizeof(Section);
    Section sections[3]{};
    sections[1].sh_type = SHT_SYMTAB; sections[1].sh_offset = 384;
    sections[1].sh_size = 2 * sizeof(Sym); sections[1].sh_entsize = sizeof(Sym); sections[1].sh_link = 2;
    sections[2].sh_type = SHT_STRTAB; sections[2].sh_offset = 480; sections[2].sh_size = 7;
    Sym symbol{}; symbol.st_name = 1; symbol.st_value = 0x123; symbol.st_shndx = 1; symbol.st_info = STT_FUNC;
    std::memcpy(bytes.data() + 480, "\0probe\0", 7);
    auto file = root / (elfClass == ELFCLASS64 ? "symbols64.elf" : "symbols32.elf");
    auto save = [&] {
        std::memcpy(bytes.data(), &header, sizeof(header));
        std::memcpy(bytes.data() + 128, sections, sizeof(sections));
        std::memcpy(bytes.data() + 384 + sizeof(Sym), &symbol, sizeof(symbol));
        std::ofstream out(file, std::ios::binary); out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    };
    auto load = [&](uintptr_t base=0x1000) { SymbolResolver r; r.loadModule(file.string(), "fixture", base); return r; };
    save(); check(load().lookup("probe") == 0x1123, "valid ELF symbol tables still resolve");
    header.e_ident[EI_DATA] = ELFDATA2MSB; save();
    check(load().count() == 0, "ELF symbol parsers reject unsupported byte order");
    header.e_ident[EI_DATA] = ELFDATA2LSB; header.e_shentsize = 0; save();
    check(load().count() == 0, "ELF section headers cannot ignore their declared stride");
    header.e_shentsize = sizeof(Section); symbol.st_shndx = SHN_ABS; save();
    check(load().lookup("probe") == 0x123, "absolute ELF symbols are not rebased in shared libraries");
    symbol.st_shndx = 1; save();
    check(load(UINTPTR_MAX - 3).count() == 0, "ELF symbol relocation rejects address overflow");
    sections[2].sh_size = 6; save();
    check(load().count() == 0, "unterminated ELF symbol names are rejected without inventing a terminator");
}

void symbolTests(const fs::path& root) {
    elfSymbolTests<Elf64_Ehdr, Elf64_Shdr, Elf64_Sym>(root, ELFCLASS64);
    elfSymbolTests<Elf32_Ehdr, Elf32_Shdr, Elf32_Sym>(root, ELFCLASS32);
    SymbolResolver resolver;
    resolver.addUserSymbol(0x1000, "old"); resolver.addUserSymbol(0x1000, "new");
    check(resolver.lookup("old") == 0 && resolver.lookup("new") == 0x1000, "renaming user symbols removes obsolete name lookups");
    resolver.clear();
    check(resolver.lookup("new") == 0x1000 && resolver.resolve(0x1000) == "new", "reloading module symbols preserves consistent user-symbol lookups");
    check(isolated([&] {
        std::vector<uint8_t> bytes(512);
        Elf64_Ehdr header{}; std::memcpy(header.e_ident, ELFMAG, SELFMAG);
        header.e_ident[EI_CLASS] = ELFCLASS64; header.e_ident[EI_DATA] = ELFDATA2LSB;
        header.e_ident[EI_VERSION] = EV_CURRENT; header.e_version = EV_CURRENT;
        header.e_ehsize = sizeof(header); header.e_shoff = 128; header.e_shnum = 1; header.e_shentsize = sizeof(Elf64_Shdr);
        Elf64_Shdr section{}; section.sh_type = SHT_NOTE; section.sh_offset = 384; section.sh_size = sizeof(Elf64_Nhdr) + 2;
        Elf64_Nhdr note{UINT32_MAX, 2, NT_GNU_BUILD_ID};
        std::memcpy(bytes.data(), &header, sizeof(header)); std::memcpy(bytes.data() + 128, &section, sizeof(section));
        std::memcpy(bytes.data() + 384, &note, sizeof(note)); bytes[396] = 'G'; bytes[397] = 'N';
        auto file = root / "wrapped-note.elf";
        { std::ofstream out(file, std::ios::binary); out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size()); }
        SymbolResolver r; r.loadModule(file.string(), "fixture", 0);
        return r.count() == 0;
    }), "ELF build-id notes reject wrapped name lengths before reading their contents");
}

void memoryTests() {
    ModelProcess proc; proc.wide = false;
    auto put32 = [&](size_t at, uint32_t value) { std::memcpy(proc.bytes.data() + at, &value, 4); };
    put32(256, 272); put32(260, 0x123456); put32(272, 0); put32(276, 0x654321);
    CpuContext context{}; context.rbp = 256; context.rsp = 240; context.rip = 0x102030;
    auto frames = buildStackTrace(proc, context, 8);
    check(frames.size() == 3 && frames[1].instructionPointer == 0x123456 && frames[1].stackPointer == 264 && frames[2].instructionPointer == 0x654321,
          "32-bit stack traces read target-width frame links and return addresses");
    std::fill(proc.bytes.begin(), proc.bytes.end(), 0x90);
    auto hook = installSimpleHook(proc, 256, 512);
    bool valid = hook && proc.bytes[hook->codecave] == 0xe9;
    if (valid) {
        uint32_t displacement = 0;
        std::memcpy(&displacement, proc.bytes.data() + hook->codecave + 1, 4);
        valid = uint32_t(hook->codecave + 5 + displacement) == 512;
    }
    check(valid, "32-bit hooks use a 32-bit branch gate instead of a RIP-relative 64-bit gate");
    if (hook) removeSimpleHook(proc, *hook);
    check(proc.protection == MemProt::All, "installing and removing hooks preserve the original memory protection");
    proc.wide = true;
    proc.bytes[256] = 0xb8; put32(257, 0x12345678);
    auto original = std::vector<uint8_t>(proc.bytes.begin() + 256, proc.bytes.begin() + 261);
    proc.partialOnce = true;
    check(nopInstruction(proc, 256).empty() && std::equal(original.begin(), original.end(), proc.bytes.begin() + 256),
          "failed partial NOP patches restore the original instruction");
}

void watcherTests() {
    check(isolated([] {
        os::ProcessWatcher watcher;
        std::atomic<bool> matched{false};
        watcher.start("ce-late-name", [&](pid_t, const std::string&) { matched = true; }, 1);
        pid_t child = fork();
        if (!child) { prctl(PR_SET_PDEATHSIG, SIGKILL); prctl(PR_SET_NAME, "ce-early-name"); usleep(100000); prctl(PR_SET_NAME, "ce-late-name"); for (;;) pause(); }
        bool found = child > 0 && waitUntil([&] { return matched.load(); });
        watcher.stop();
        if (child > 0) { kill(child, SIGKILL); waitpid(child, nullptr, 0); }
        return found;
    }), "process watchers keep checking new processes until their final names match");
    check(isolated([] {
        os::ProcessWatcher watcher;
        std::atomic<bool> matched{false};
        watcher.start("ce-self-stop", [&](pid_t, const std::string&) { watcher.stop(); matched = true; }, 1);
        pid_t child = fork();
        if (!child) { prctl(PR_SET_PDEATHSIG, SIGKILL); prctl(PR_SET_NAME, "ce-self-stop"); for (;;) pause(); }
        bool found = child > 0 && waitUntil([&] { return matched.load(); });
        watcher.stop();
        if (child > 0) { kill(child, SIGKILL); waitpid(child, nullptr, 0); }
        return found;
    }), "watcher callbacks can stop their own watcher without joining themselves");
}
}

int runUnderlyingReviewTests(const fs::path& root) {
    engineTests(root);
    objectTests();
    memoryTests();
    watcherTests();
    debuggerLifecycleTests();
    breakpointTests();
    symbolTests(root);
    return failures;
}
