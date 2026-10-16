#include "test_target.hpp"
#include "core/simple_address_list.hpp"
#include "core/simple_hook.hpp"
#include "core/json.hpp"
#include "core/value_io.hpp"
#include "core/expression.hpp"
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
#include "scanner/memory_scanner.hpp"

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
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
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
#ifdef __x86_64__
    check(isolated([] {
        // A 16-byte store that starts 4 bytes before the watched dword faults
        // at its start address; the page-guard finder must still count it.
        alarm(10);
        alignas(64) static uint8_t object[64];
        int fds[2]; if (pipe(fds)) return false;
        pid_t child = fork();
        if (!child) {
            prctl(PR_SET_PDEATHSIG, SIGKILL); close(fds[1]);
            char token; (void)::read(fds[0], &token, 1);
            for (int i = 0; i < 200; ++i) {
                asm volatile("pxor %%xmm0, %%xmm0\n\tmovdqu %%xmm0, (%0)" :: "r"(object) : "xmm0", "memory");
                usleep(2000);
            }
            _exit(0);
        }
        if (child < 0) return false;
        close(fds[0]);
        os::LinuxProcessHandle proc(child);
        os::LinuxDebugger debugger;
        CodeFinder finder;
        bool started = finder.start(proc, debugger, reinterpret_cast<uintptr_t>(object) + 4, true, 4, /*software=*/true);
        (void)!::write(fds[1], "x", 1);
        bool hit = started && waitUntil([&] { return !finder.results().empty(); });
        finder.stop();
        kill(child, SIGKILL); waitpid(child, nullptr, 0);
        alarm(0);
        return hit;
    }), "page-guard code finder counts a wide store that starts before the watched value");
#endif
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

// A small 64-bit ELF built piece by piece: sections and program headers are
// placed at fixed offsets, the payload is whatever the test writes.
struct ElfImage {
    std::vector<uint8_t> bytes = std::vector<uint8_t>(0x3000);
    Elf64_Ehdr header{};
    std::vector<Elf64_Shdr> sections{Elf64_Shdr{}};
    std::vector<Elf64_Phdr> programs;
    ElfImage() {
        std::memcpy(header.e_ident, ELFMAG, SELFMAG);
        header.e_ident[EI_CLASS] = ELFCLASS64; header.e_ident[EI_DATA] = ELFDATA2LSB;
        header.e_ident[EI_VERSION] = EV_CURRENT; header.e_version = EV_CURRENT;
        header.e_type = ET_DYN; header.e_ehsize = sizeof(header);
    }
    void put(size_t at, const void* data, size_t size) {
        if (at + size > bytes.size()) bytes.resize(at + size);
        std::memcpy(bytes.data() + at, data, size);
    }
    size_t addSection(uint32_t type, size_t offset, size_t size, uint32_t link = 0, size_t entsize = 0) {
        Elf64_Shdr s{}; s.sh_type = type; s.sh_offset = offset; s.sh_size = size; s.sh_link = link; s.sh_entsize = entsize;
        sections.push_back(s);
        return sections.size() - 1;
    }
    void save(const fs::path& file) {
        header.e_shoff = 0x100; header.e_shnum = sections.size(); header.e_shentsize = sizeof(Elf64_Shdr);
        if (!programs.empty()) { header.e_phoff = 0x40; header.e_phnum = programs.size(); header.e_phentsize = sizeof(Elf64_Phdr); }
        put(0, &header, sizeof(header));
        if (!programs.empty()) put(0x40, programs.data(), programs.size() * sizeof(Elf64_Phdr));
        put(0x100, sections.data(), sections.size() * sizeof(Elf64_Shdr));
        std::ofstream out(file, std::ios::binary);
        out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    }
};

Elf64_Sym elfSymbol(uint32_t name, uint64_t value) {
    Elf64_Sym s{}; s.st_name = name; s.st_value = value; s.st_shndx = 1; s.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    return s;
}

void elfLoaderLimitTests(const fs::path& root) {
    const auto file = root / "limits.elf";
    auto load = [&](uintptr_t base) { SymbolResolver r; r.loadModule(file.string(), "fixture", base); return r; };
    {   // Overlapping symbol table headers: only one .symtab is read.
        ElfImage elf;
        elf.put(0x1000, "\0probe\0", 7);
        const auto strtab = elf.addSection(SHT_STRTAB, 0x1000, 7);
        Elf64_Sym syms[2] = {Elf64_Sym{}, elfSymbol(1, 0x10)};
        elf.put(0x1100, syms, sizeof(syms));
        elf.addSection(SHT_SYMTAB, 0x1100, sizeof(syms), strtab, sizeof(Elf64_Sym));
        elf.addSection(SHT_SYMTAB, 0x1100 + sizeof(Elf64_Sym), sizeof(Elf64_Sym), strtab, sizeof(Elf64_Sym));
        elf.save(file);
        check(load(0x1000).count() == 1, "overlapping symbol table headers do not multiply the symbols");
    }
    {   // A name past the length cap is not copied per symbol.
        ElfImage elf;
        std::string longName(5000, 'n');
        elf.put(0x1001, longName.c_str(), longName.size() + 1);
        const auto strtab = elf.addSection(SHT_STRTAB, 0x1000, longName.size() + 2);
        Elf64_Sym syms[2] = {Elf64_Sym{}, elfSymbol(1, 0x10)};
        elf.put(0x3000, syms, sizeof(syms));
        elf.addSection(SHT_SYMTAB, 0x3000, sizeof(syms), strtab, sizeof(Elf64_Sym));
        elf.save(file);
        check(load(0x1000).count() == 0, "symbol names longer than 4 KiB are skipped");
    }
    {   // glibc keeps compat versions under the same name: the default wins.
        ElfImage elf;
        elf.put(0x1000, "\0probe\0", 7);
        const auto strtab = elf.addSection(SHT_STRTAB, 0x1000, 7);
        Elf64_Sym syms[3] = {Elf64_Sym{}, elfSymbol(1, 0x100), elfSymbol(1, 0x200)};
        elf.put(0x1100, syms, sizeof(syms));
        const auto dynsym = elf.addSection(SHT_DYNSYM, 0x1100, sizeof(syms), strtab, sizeof(Elf64_Sym));
        const uint16_t versions[3] = {0, 0x8002, 3};
        elf.put(0x1200, versions, sizeof(versions));
        elf.addSection(SHT_GNU_versym, 0x1200, sizeof(versions), dynsym, sizeof(uint16_t));
        elf.save(file);
        check(load(0x1000).lookup("probe") == 0x1200, "a symbol's default version wins over a hidden compat version");
    }
    {   // A library linked at a non-zero base: the lowest mapping is that base plus the bias.
        ElfImage elf;
        elf.put(0x1000, "\0probe\0", 7);
        const auto strtab = elf.addSection(SHT_STRTAB, 0x1000, 7);
        Elf64_Sym syms[2] = {Elf64_Sym{}, elfSymbol(1, 0x400123)};
        elf.put(0x1100, syms, sizeof(syms));
        elf.addSection(SHT_SYMTAB, 0x1100, sizeof(syms), strtab, sizeof(Elf64_Sym));
        Elf64_Phdr segment{}; segment.p_type = PT_LOAD; segment.p_vaddr = 0x400000; segment.p_memsz = 0x2000;
        elf.programs.push_back(segment);
        elf.save(file);
        check(load(0x7000000).lookup("probe") == 0x7000123, "symbols of an image linked at a non-zero base are rebased by the load bias");
    }
    check(isolated([&] {
        const auto fifo = root / "module.fifo";
        if (::mkfifo(fifo.c_str(), 0600) != 0) return false;
        alarm(10);   // a blocking open would hang here
        SymbolResolver r; r.loadModule(fifo.string(), "fifo", 0x1000);
        return r.count() == 0;
    }), "a FIFO named as a module is never opened for a blocking read");
}

void symbolTests(const fs::path& root) {
    elfLoaderLimitTests(root);
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

void scannerTests(const fs::path& root) {
    ModelProcess proc;
    auto put = [&](size_t at, auto value) { std::memcpy(proc.bytes.data() + at, &value, sizeof(value)); };
    // Results go where CE_SCAN_DIR says, in a directory named for this process.
    const auto scanRootDir = root / "scans";
    fs::create_directories(scanRootDir);
    setenv("CE_SCAN_DIR", scanRootDir.c_str(), 1);
    MemoryScanner scanner(1);
    auto throws = [&](auto&& body) { try { body(); } catch (const std::invalid_argument&) { return true; } return false; };

    ScanConfig changed; changed.valueType = ValueType::Int32; changed.compareType = ScanCompare::Changed;
    check(throws([&] { scanner.firstScan(proc, changed); }), "a first scan refuses compares that need a previous scan");

    put(0x400, int32_t(100));
    ScanConfig exact; exact.valueType = ValueType::Int32; exact.intValue = 100;
    auto first = scanner.firstScan(proc, exact);
    char host[256] = {};
    gethostname(host, sizeof(host) - 1);
    const std::string scanDirName = first.directory().lexically_relative(scanRootDir).begin()->string();
    bool named = first.count() == 1 && first.directory().string().starts_with(scanRootDir.string()) &&
                 scanDirName.starts_with("ce-scan-") && scanDirName.find("-" + std::to_string(getpid()) + "-") != std::string::npos &&
                 (!*host || std::strchr(host, '-') || scanDirName.starts_with(std::string("ce-scan-") + host + "-"));
    check(named, "scan results go to CE_SCAN_DIR in a directory named for the scanning host and process");
    put(0x400, int32_t(95));
    ScanConfig by; by.valueType = ValueType::Int32; by.compareType = ScanCompare::IncreasedBy; by.intValue = -5;
    check(scanner.nextScan(proc, by, first).count() == 1, "increased by a negative amount finds the decreased value");

    ScanConfig pointer; pointer.valueType = ValueType::Pointer; pointer.pointerWidth = 4; pointer.intValue = 0x100001234;
    check(throws([&] { scanner.firstScan(proc, pointer); }), "a 4-byte pointer scan refuses a value wider than 32 bits");

    ScanConfig text; text.valueType = ValueType::String; text.stringValue = "abc"; text.alignment = 1;
    std::memcpy(proc.bytes.data() + 0x800, "abc", 3);
    auto texts = scanner.firstScan(proc, text);
    ScanConfig greater = text; greater.compareType = ScanCompare::Greater;
    check(throws([&] { scanner.nextScan(proc, greater, texts); }), "text next scans refuse ordered compares");

    put(0xC00, uint64_t(UINT64_MAX));
    ScanConfig all; all.valueType = ValueType::All; all.alignment = 8;
    bool parsed = all.parseAllValues("18446744073709551615");
    auto alls = scanner.firstScan(proc, all);
    bool found = false;
    for (size_t i = 0; i < alls.count(); ++i) found |= alls.address(i) == 0xC00;
    check(parsed && found, "an All-type exact scan finds an 8-byte value above INT64_MAX");

    {
        // Each candidate keeps 256 KiB in a global, so the 16 MiB formula
        // state runs out of memory every ~60 candidates. That must neither
        // abort the scan nor leave the state full for the candidates after it.
        ModelProcess custom;
        custom.bytes[0x1F00] = 0x42;
        ScanConfig formula; formula.valueType = ValueType::Custom; formula.customValueSize = 4; formula.alignment = 4;
        formula.customFormula = "keep = keep or {}\n"
                                "keep[#keep + 1] = string.rep(current, 65536) .. #keep\n"
                                "return string.byte(current, 1) == 0x42";
        bool survived = isolated([&] {
            auto hits = scanner.firstScan(custom, formula);
            return hits.count() == 1 && hits.address(0) == 0x1F00;
        });
        check(survived, "a custom formula that runs out of memory fails its candidate and the state is rebuilt");
    }

    {
        // Only this host's directories are judged by pid; another host's live
        // scan on a shared home is left alone, and so is an old-style name.
        const auto pruneRoot = root / "prune";
        fs::create_directories(pruneRoot);
        pid_t gone = fork();
        if (gone == 0) _exit(0);
        if (gone > 0) waitpid(gone, nullptr, 0);
        const std::string tag = *host && !std::strchr(host, '-') ? host : "";
        const auto mine = pruneRoot / ("ce-scan-" + tag + "-" + std::to_string(gone) + "-abcdef");
        const auto live = pruneRoot / ("ce-scan-" + tag + "-" + std::to_string(getpid()) + "-abcdef");
        const auto other = pruneRoot / ("ce-scan-elsewhere.example-" + std::to_string(gone) + "-abcdef");
        const auto oldStyle = pruneRoot / ("ce-scan-" + std::to_string(gone) + "-abcdef");
        for (const auto& dir : {mine, live, other, oldStyle}) fs::create_directories(dir);
        // Another host's directory a week old (this machine's own from before
        // a hostname change) goes, unless it is kept; a recent one stays.
        const auto renamed = pruneRoot / ("ce-scan-oldname.example-" + std::to_string(getpid()) + "-abcdef");
        const auto renamedKept = pruneRoot / ("ce-scan-oldname.example-" + std::to_string(gone) + "-ghijkl");
        const auto oldStyleStale = pruneRoot / ("ce-scan-" + std::to_string(gone) + "-mnopqr");
        for (const auto& dir : {renamed, renamedKept, oldStyleStale}) fs::create_directories(dir);
        { std::ofstream marker(renamedKept / ".kept"); }
        const auto eightDaysAgo = fs::file_time_type::clock::now() - std::chrono::hours(24 * 8);
        std::error_code aged;
        for (const auto& dir : {renamed, renamedKept, oldStyleStale}) fs::last_write_time(dir, eightDaysAgo, aged);
        pruneStaleScanDirectories(pruneRoot);
        check(tag.empty() || (gone > 0 && !fs::exists(mine) && fs::exists(live) && fs::exists(other) && fs::exists(oldStyle)),
              "stale scan directories are pruned by pid only for this host");
        check(!aged && !fs::exists(renamed) && !fs::exists(oldStyleStale) && fs::exists(renamedKept),
              "another host's scan directories are pruned a week old unless kept");
        // A file written inside keeps another host's directory, and so does a
        // live scan's lock however old everything in it is.
        const auto busy = pruneRoot / ("ce-scan-busy.example-" + std::to_string(gone) + "-stuvwx");
        const auto held = pruneRoot / ("ce-scan-held.example-" + std::to_string(gone) + "-yzabcd");
        const auto owned = pruneRoot / ("ce-scan-owned.example-" + std::to_string(gone) + "-efghij");
        for (const auto& dir : {busy, held, owned}) fs::create_directories(dir / "results");
        { std::ofstream recent(busy / "results" / "values.bin"); recent << "x"; }
        { std::ofstream lockFile(held / ".lock"); }
        ScanResult holder;
        holder.adoptDirectory(owned);
        const int lockFd = ::open((held / ".lock").c_str(), O_RDWR | O_CLOEXEC);
        const bool locked = lockFd >= 0 && ::flock(lockFd, LOCK_SH | LOCK_NB) == 0;
        auto age = [&](const fs::path& dir) {
            for (fs::recursive_directory_iterator it(dir, aged), end; !aged && it != end; it.increment(aged))
                fs::last_write_time(it->path(), eightDaysAgo, aged);
            fs::last_write_time(dir / "results", eightDaysAgo, aged);
            fs::last_write_time(dir, eightDaysAgo, aged);
        };
        age(held);
        age(owned);
        fs::last_write_time(busy / "results", eightDaysAgo, aged);
        fs::last_write_time(busy, eightDaysAgo, aged);
        pruneStaleScanDirectories(pruneRoot);
        check(!aged && locked && fs::exists(busy) && fs::exists(held) && fs::exists(owned),
              "another host's scan directory stays while a file in it is recent or a live scan holds its lock");
        if (lockFd >= 0) ::close(lockFd);
        pruneStaleScanDirectories(pruneRoot);
        check(!fs::exists(held) && fs::exists(owned), "a released lock lets the week-old directory go");
        std::error_code ignored;
        fs::remove_all(pruneRoot, ignored);
    }

    {
        // CP932 and ISO-8859-16 are byte encodings: a bad byte is skipped alone.
        const uint8_t bad[] = {0xFF, 'A', 'B', 'C'};
        check(decodeStringBytes(bad, sizeof(bad), "CP932") == "\xEF\xBF\xBD" "ABC",
              "a code page whose name holds 32 is decoded one byte at a time");
    }
    unsetenv("CE_SCAN_DIR");
}

void expressionTests() {
    ModelProcess proc;   // module "fixture" at 256
    ExpressionParser parser(&proc);
    check(parser.parse("FIXTURE+4") == 260u, "module names in expressions match without regard to case");
    check(parser.parse("fixture+2*4") == 264u && parser.parse("2*3+1") == 7u && parser.parse("[fixture]*0+1") == 1u,
          "expressions multiply, with '*' binding tighter than '+'");
    struct Mixed : ModelProcess { bool runs32BitCode() override { return true; } } mixed;   // 64-bit process, 32-bit code
    ExpressionParser wide(&mixed);
    check(wide.parse("7f0012345678") == uintptr_t(0x7f0012345678) && wide.parse("FFFFFFFC+8") == 4u,
          "a WoW64 process keeps addresses above 4 GiB and still wraps 32-bit arithmetic");
    SymbolResolver symbols;
    symbols.addUserSymbol(0x1000, "Game::hit(Player*, int)");
    symbols.addUserSymbol(0x2000, "Game::swap(Player*, Player*)");
    ExpressionParser named(&proc, &symbols);
    check(named.parse("Game::hit(Player*, int)+0x12") == 0x1012u && named.parse("Game::hit(Player*, int)*2") == 0x2000u &&
          named.parse("Game::swap(Player*, Player*)-10") == 0x1FF0u && named.parse("Game::swap(Player*, Player*)*2+1") == 0x4001u,
          "a demangled C++ name with '*' resolves as one symbol");
    check(named.parse("fixture+10*4") == 320u && named.parse("10*4+fixture") == 320u && named.parse("0x10*2") == 32u &&
          !named.parse("Game::hit(Player*, long)+4").has_value(),
          "'*' still multiplies numbers and module offsets beside symbol names");

    check(!encodeTypedValue(ValueType::Float, "+-5").has_value(), "a float value with two signs is rejected");
    check(json::Value::number(1.5).stringValue == "1.5", "JSON numbers do not depend on the locale");
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
    scannerTests(root);
    expressionTests();
    watcherTests();
    debuggerLifecycleTests();
    breakpointTests();
    symbolTests(root);
    return failures;
}
