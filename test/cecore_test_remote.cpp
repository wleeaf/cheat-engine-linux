// cecore_test: the ceserver and GDB remote protocols, pointer scan
// persistence, DWARF and ELF symbols, early Auto Assembler blocks.
#include "test_target.hpp"
#include "platform/linux/linux_process.hpp"
#include "platform/linux/ptrace_wrapper.hpp"
#include "platform/linux/ceserver_client.hpp"
#include "platform/linux/ceserver_server.hpp"
#include "platform/linux/mono_debugger_client.hpp"
#include "platform/linux/process_watcher.hpp"
#include "platform/linux/ceserver_process.hpp"
#include "platform/linux/ceserver_debugger.hpp"
#include "platform/linux/kernel_driver.hpp"
#include "platform/network_compression.hpp"
#include "platform/vulkan_overlay_injector.hpp"
#include "platform/linux/injector.hpp"
#include "platform/linux/wine_memory.hpp"
#include "platform/linux/memory_image.hpp"
#ifdef CE_HAVE_VULKAN
#include <vulkan/vulkan.h>
#include <vulkan/vk_layer.h>
#include <dlfcn.h>
#endif
#include "scanner/pointer_scanner.hpp"
#include "scanner/snapshot.hpp"
#include "core/target_capabilities.hpp"
#include "core/value_io.hpp"
#include "core/autoasm.hpp"
#include "core/aa_templates.hpp"
#include "core/injection_gen.hpp"
#include "core/ct_file.hpp"
#include "analysis/mono_dissector.hpp"
#include "core/simple_hook.hpp"
#include "core/log.hpp"
#include "core/target_profile.hpp"
#include "core/guest_view.hpp"
#include "core/ns_attach.hpp"
#include "core/value_codec.hpp"
#include "core/value_transform.hpp"
#include "arch/disassembler.hpp"
#include "arch/cpu_flags.hpp"
#include "core/expression.hpp"
#include "core/memview_nav.hpp"
#include "core/trainer.hpp"
#include "analysis/code_analysis.hpp"
#include "analysis/managed_runtime.hpp"
#include "analysis/il2cpp_metadata.hpp"
#include "analysis/il2cpp_binary.hpp"
#include "analysis/signature.hpp"
#include "analysis/pe_exports.hpp"
#include "analysis/structure_tools.hpp"
#include "debug/breakpoint_manager.hpp"
#include "debug/stack_trace.hpp"
#include "debug/tracer.hpp"
#include "debug/debug_session.hpp"
#include "debug/gdb_remote.hpp"
#include "debug/managed_breakpoint.hpp"
#include "debug/code_finder.hpp"
#include "debug/instruction_access.hpp"
#include "debug/patch.hpp"
#include "symbols/kernel_symbols.hpp"
#include "symbols/dwarf_symbols.hpp"
#include "scripting/lua_engine.hpp"
#include "core/address_list.hpp"
#include "core/simple_address_list.hpp"
#include "plugins/plugin_loader.hpp"

#include <cstdio>
#include <cstdlib>
#include "symbols/elf_symbols.hpp"
#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <csignal>
#include <thread>
#include <chrono>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <future>
#include <sys/stat.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <cstdarg>
#include <stdexcept>
#include "core/mcp_server.hpp"
#include "core/agent_chat.hpp"
#include "arch/target_arch.hpp"
#include "core/json.hpp"
#include <unistd.h>
#include <sys/wait.h>
#include <csignal>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/select.h>
#include <poll.h>

#include "test/cecore_test.hpp"

void test_ceserver_memory_ops() {
    printf("\n── Test: ceserver memory ops ──\n");

    int server = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (server < 0 ||
        ::bind(server, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
        ::listen(server, 1) != 0) {
        if (server >= 0) ::close(server);
        printf("  setup: FAILED\n");
        return;
    }
    socklen_t addrLen = sizeof(addr);
    if (::getsockname(server, reinterpret_cast<sockaddr*>(&addr), &addrLen) != 0) {
        ::close(server);
        printf("  setup: FAILED\n");
        return;
    }

    constexpr int32_t kHandle = 0x1234;
    constexpr int32_t kPid = 4242;
    constexpr uint64_t kRegionBase = 0x7f0000000000ull;
    constexpr uint64_t kRegionSize = 0x10000;
    constexpr uint32_t kRegionProt = 0x40; // PAGE_EXECUTE_READWRITE
    constexpr uint32_t kRegionType = 0x20000; // MEM_PRIVATE
    const std::string kReadBlob = "DEADBEEFCAFEBABE";
    std::string capturedWrite;
    bool sawClose = false;

    std::thread stub([&]() {
        int client = ::accept(server, nullptr, nullptr);
        if (client < 0) return;

        for (;;) {
            uint8_t cmd = 0xff;
            ssize_t n = ::recv(client, &cmd, 1, MSG_WAITALL);
            if (n <= 0) break;

            if (cmd == 3) { // CMD_OPENPROCESS
                int32_t pid = 0;
                ::recv(client, &pid, 4, MSG_WAITALL);
                int32_t h = (pid == kPid) ? kHandle : 0;
                ::send(client, &h, 4, 0);
            } else if (cmd == 7) { // CMD_CLOSEHANDLE
                int32_t h = 0;
                ::recv(client, &h, 4, MSG_WAITALL);
                int32_t r = (h == kHandle) ? 1 : 0;
                if (h == kHandle) sawClose = true;
                ::send(client, &r, 4, 0);
            } else if (cmd == 8) { // CMD_VIRTUALQUERYEX
                int32_t h = 0;
                uint64_t base = 0;
                ::recv(client, &h, 4, MSG_WAITALL);
                ::recv(client, &base, 8, MSG_WAITALL);
                uint8_t result = (h == kHandle && base == kRegionBase) ? 1 : 0;
                uint32_t prot = kRegionProt;
                uint32_t type = kRegionType;
                ::send(client, &result, 1, 0);
                ::send(client, &prot, 4, 0);
                ::send(client, &type, 4, 0);
                ::send(client, &kRegionBase, 8, 0);
                ::send(client, &kRegionSize, 8, 0);
            } else if (cmd == 31) { // CMD_VIRTUALQUERYEXFULL
                int32_t h = 0;
                uint8_t flags = 0;
                ::recv(client, &h, 4, MSG_WAITALL);
                ::recv(client, &flags, 1, MSG_WAITALL);
                int32_t count = 2;
                ::send(client, &count, 4, 0);
                for (int i = 0; i < 2; ++i) {
                    uint32_t prot = kRegionProt;
                    uint32_t type = kRegionType;
                    uint64_t base = kRegionBase + i * kRegionSize;
                    uint64_t size = kRegionSize;
                    // Upstream RegionInfo order: base, size, protection, type.
                    ::send(client, &base, 8, 0);
                    ::send(client, &size, 8, 0);
                    ::send(client, &prot, 4, 0);
                    ::send(client, &type, 4, 0);
                }
            } else if (cmd == 9) { // CMD_READPROCESSMEMORY
                uint32_t h = 0, size = 0;
                uint64_t address = 0;
                uint8_t compress = 0xff;
                ::recv(client, &h, 4, MSG_WAITALL);
                ::recv(client, &address, 8, MSG_WAITALL);
                ::recv(client, &size, 4, MSG_WAITALL);
                ::recv(client, &compress, 1, MSG_WAITALL);
                int32_t served = (int32_t)std::min<uint32_t>(size, kReadBlob.size());
                ::send(client, &served, 4, 0);
                if (served > 0)
                    ::send(client, kReadBlob.data(), served, 0);
            } else if (cmd == 10) { // CMD_WRITEPROCESSMEMORY
                int32_t h = 0, size = 0;
                int64_t address = 0;
                ::recv(client, &h, 4, MSG_WAITALL);
                ::recv(client, &address, 8, MSG_WAITALL);
                ::recv(client, &size, 4, MSG_WAITALL);
                std::string buf(size, '\0');
                if (size > 0) ::recv(client, buf.data(), size, MSG_WAITALL);
                capturedWrite = buf;
                int32_t written = size;
                ::send(client, &written, 4, 0);
            } else {
                break;
            }
        }
        ::close(client);
    });

    CEServerClient client;
    std::string error;
    bool connected = client.connectTcp("127.0.0.1", ntohs(addr.sin_port), error);
    bool allOk = connected;

    if (allOk) {
        auto h = client.openProcess(kPid);
        allOk = h && *h == kHandle;
        printf("  openProcess: %s\n", allOk ? "OK" : "FAILED");
    }

    if (allOk) {
        auto region = client.virtualQueryEx(kHandle, kRegionBase);
        bool ok = region && region->has_value() &&
                  (*region)->baseAddress == kRegionBase &&
                  (*region)->size == kRegionSize &&
                  (*region)->protection == kRegionProt;
        printf("  virtualQueryEx: %s\n", ok ? "OK" : "FAILED");
        allOk = ok;
    }

    if (allOk) {
        auto regions = client.virtualQueryExFull(kHandle, 0);
        bool ok = regions && regions->size() == 2 &&
                  (*regions)[0].baseAddress == kRegionBase &&
                  (*regions)[1].baseAddress == kRegionBase + kRegionSize;
        printf("  virtualQueryExFull: %s\n", ok ? "OK" : "FAILED");
        allOk = ok;
    }

    if (allOk) {
        char buf[32] = {};
        auto r = client.readProcessMemory(kHandle, kRegionBase, buf, sizeof(buf));
        bool ok = r && *r == (int32_t)kReadBlob.size() &&
                  std::string(buf, *r) == kReadBlob;
        printf("  readProcessMemory: %s\n", ok ? "OK" : "FAILED");
        allOk = ok;
    }

    if (allOk) {
        std::string payload = "WRITE_TEST_42";
        auto w = client.writeProcessMemory(kHandle, kRegionBase, payload.data(), (int32_t)payload.size());
        bool ok = w && *w == (int32_t)payload.size() && capturedWrite == payload;
        printf("  writeProcessMemory: %s\n", ok ? "OK" : "FAILED");
        allOk = ok;
    }

    if (allOk) {
        auto c = client.closeHandle(kHandle);
        bool ok = c.has_value() && sawClose;
        printf("  closeHandle: %s\n", ok ? "OK" : "FAILED");
    }

    client.close();
    stub.join();
    ::close(server);
}

void test_ceserver_extended_ops() {
    printf("\n── Test: ceserver extended ops ──\n");

    StubFixture fx;
    if (!startStub(fx)) { printf("  setup: FAILED\n"); return; }

    CEServerClient client;
    std::string error;
    if (!client.connectTcp("127.0.0.1", fx.port, error)) {
        printf("  connect: FAILED (%s)\n", error.c_str());
        stopStub(fx); return;
    }

    auto h = client.openProcess(kStubPid);
    bool ok = h && *h == kStubHandle;
    printf("  openProcess: %s\n", ok ? "OK" : "FAILED");

    if (ok) {
        auto arch = client.getArchitecture(kStubHandle);
        ok = arch && *arch == CeArchitecture::X86_64;
        printf("  getArchitecture: %s\n", ok ? "OK" : "FAILED");
    }

    if (ok) {
        auto addr = client.allocateMemory(kStubHandle, 0, 4096, 0x40);
        ok = addr && *addr == kStubAlloc;
        printf("  allocateMemory: %s\n", ok ? "OK" : "FAILED");
    }

    if (ok) {
        auto r = client.freeMemory(kStubHandle, kStubAlloc, 4096);
        ok = r && *r == 1;
        printf("  freeMemory: %s\n", ok ? "OK" : "FAILED");
    }

    if (ok) {
        auto p = client.changeMemoryProtection(kStubHandle, kStubAlloc, 4096, 0x40);
        ok = p && p->result == 1 && p->oldProtection == 0x40;
        printf("  changeMemoryProtection: %s\n", ok ? "OK" : "FAILED");
    }

    if (ok) {
        auto mods = client.enumModules(kStubPid);
        ok = mods && mods->size() == 2 &&
             (*mods)[0].name == "/usr/lib/libc.so.6" &&
             (*mods)[1].baseAddress == 0x500000;
        printf("  enumModules: %s\n", ok ? "OK" : "FAILED");
    }

    if (ok) {
        auto tids = client.enumThreads(kStubPid);
        ok = tids && tids->size() == 3 && (*tids)[0] == 1001 && (*tids)[2] == 1003;
        printf("  enumThreads: %s\n", ok ? "OK" : "FAILED");
    }

    client.close();
    stopStub(fx);
}

void test_ceserver_debug_ops() {
    printf("\n── Test: ceserver debug ops ──\n");

    StubFixture fx;
    if (!startStub(fx)) { printf("  setup: FAILED\n"); return; }

    CEServerClient client;
    std::string error;
    if (!client.connectTcp("127.0.0.1", fx.port, error)) {
        printf("  connect: FAILED (%s)\n", error.c_str());
        stopStub(fx); return;
    }

    bool ok = true;
    if (ok) {
        auto h = client.openProcess(kStubPid);
        ok = h && *h == kStubHandle;
        printf("  openProcess: %s\n", ok ? "OK" : "FAILED");
    }
    if (ok) {
        auto r = client.startDebug(kStubHandle);
        ok = r && *r == 1;
        printf("  startDebug: %s\n", ok ? "OK" : "FAILED");
    }
    if (ok) {
        auto evt = client.waitForDebugEvent(kStubHandle, 100);
        ok = evt && evt->has_value() && (*evt)->threadId == 4242 && (*evt)->address == 0xCAFEBABE;
        printf("  waitForDebugEvent: %s\n", ok ? "OK" : "FAILED");
    }
    if (ok) {
        auto r = client.continueFromDebugEvent(kStubHandle, 4242, 0);
        ok = r && *r == 1;
        printf("  continueFromDebugEvent: %s\n", ok ? "OK" : "FAILED");
    }
    if (ok) {
        auto r = client.setRemoteBreakpoint(kStubHandle, 4242, 0, 0x401234, 0, 1);
        ok = r && *r == 1;
        printf("  setRemoteBreakpoint: %s\n", ok ? "OK" : "FAILED");
    }
    if (ok) {
        auto r = client.removeRemoteBreakpoint(kStubHandle, 4242, 0, 0);
        ok = r && *r == 1;
        printf("  removeRemoteBreakpoint: %s\n", ok ? "OK" : "FAILED");
    }
    if (ok) {
        auto r = client.suspendThread(kStubHandle, 4242);
        ok = r && *r == 1;
        printf("  suspendThread: %s\n", ok ? "OK" : "FAILED");
    }
    if (ok) {
        auto r = client.resumeThread(kStubHandle, 4242);
        ok = r && *r == 1;
        printf("  resumeThread: %s\n", ok ? "OK" : "FAILED");
    }
    if (ok) {
        auto r = client.getThreadContext(kStubHandle, 4242);
        // Stub now sends a real-looking blob: header(8) + 27*uint64 regs.
        constexpr size_t expectedBytes = 8 + 27 * 8;
        ok = r && r->size() == expectedBytes;
        if (ok) {
            uint64_t rax = 0;
            std::memcpy(&rax, r->data() + 8 + 10 * 8, 8);
            ok = rax == 0xAAAA'BBBB'CCCC'DDDDULL;
        }
        printf("  getThreadContext: %s (got %zu bytes)\n",
            ok ? "OK" : "FAILED", r ? r->size() : 0);
    }
    if (ok) {
        std::vector<uint8_t> blob(32, 0xAB);
        auto r = client.setThreadContext(kStubHandle, 4242, blob.data(), (uint32_t)blob.size());
        ok = r && *r == 1;
        printf("  setThreadContext: %s\n", ok ? "OK" : "FAILED");
    }
    if (ok) {
        auto r = client.speedhackSetSpeed(kStubHandle, 2.0f);
        ok = r && *r == 1;
        printf("  speedhackSetSpeed: %s\n", ok ? "OK" : "FAILED");
    }
    if (ok) {
        auto r = client.stopDebug(kStubHandle);
        ok = r && *r == 1;
        printf("  stopDebug: %s\n", ok ? "OK" : "FAILED");
    }
    if (ok) {
        auto syms = client.getSymbolListFromFile("/usr/lib/libgame.so", 0);
        bool gotPayload = syms && syms->has_value() && (*syms)->size() == 16 &&
                          (**syms)[8] == 0xCA;
        printf("  getSymbolListFromFile (hit): %s\n", gotPayload ? "OK" : "FAILED");
        auto miss = client.getSymbolListFromFile("/tmp/nope", 0);
        bool gotMiss = miss && !miss->has_value();
        printf("  getSymbolListFromFile (miss): %s\n", gotMiss ? "OK" : "FAILED");
    }

    client.close();
    stopStub(fx);
}

void test_remote_process_adapter() {
    printf("\n── Test: RemoteProcessHandle adapter ──\n");

    StubFixture fx;
    if (!startStub(fx)) { printf("  setup: FAILED\n"); return; }

    CEServerClient client;
    std::string error;
    if (!client.connectTcp("127.0.0.1", fx.port, error)) {
        printf("  connect: FAILED (%s)\n", error.c_str());
        stopStub(fx); return;
    }

    auto handle = RemoteProcessHandle::open(client, kStubPid);
    bool ok = handle != nullptr;
    printf("  open: %s\n", ok ? "OK" : "FAILED");

    if (ok) {
        ok = handle->is64bit() && handle->pid() == kStubPid;
        printf("  pid + is64bit: %s\n", ok ? "OK" : "FAILED");
    }

    if (ok) {
        auto regions = handle->queryRegions();
        ok = regions.size() == 1 && regions[0].base == 0x400000 &&
             regions[0].type == MemType::Image;
        printf("  queryRegions: %s\n", ok ? "OK" : "FAILED");
    }

    if (ok) {
        auto region = handle->queryRegion(0x12340000);
        ok = region && region->base == 0x12340000 && region->size == 0x1000;
        printf("  queryRegion: %s\n", ok ? "OK" : "FAILED");
    }

    if (ok) {
        auto mods = handle->modules();
        ok = mods.size() == 2 && mods[0].name == "libc.so.6" && mods[1].name == "target";
        printf("  modules: %s\n", ok ? "OK" : "FAILED");
    }

    if (ok) {
        auto threads = handle->threads();
        ok = threads.size() == 3 && threads[1].tid == 1002;
        printf("  threads: %s\n", ok ? "OK" : "FAILED");
    }

    if (ok) {
        auto alloc = handle->allocate(4096, MemProt::All);
        ok = alloc && *alloc == kStubAlloc;
        printf("  allocate: %s\n", ok ? "OK" : "FAILED");
    }

    if (ok) {
        auto freed = handle->free(kStubAlloc, 4096);
        ok = freed.has_value();
        printf("  free: %s\n", ok ? "OK" : "FAILED");
    }

    if (ok) {
        auto p = handle->protect(kStubAlloc, 4096, MemProt::ReadWrite);
        ok = p.has_value();
        printf("  protect: %s\n", ok ? "OK" : "FAILED");
    }

    handle.reset();
    client.close();
    stopStub(fx);
}

void test_remote_debugger() {
    printf("\n── Test: RemoteDebugger ──\n");

    StubFixture fx;
    if (!startStub(fx)) { printf("  setup: FAILED\n"); return; }

    CEServerClient client;
    std::string error;
    if (!client.connectTcp("127.0.0.1", fx.port, error)) {
        printf("  connect: FAILED (%s)\n", error.c_str());
        stopStub(fx); return;
    }
    auto h = client.openProcess(kStubPid);
    if (!h || *h != kStubHandle) { printf("  openProcess: FAILED\n"); stopStub(fx); return; }

    RemoteDebugger debugger(client, kStubHandle);

    bool ok = true;
    if (ok) {
        auto r = debugger.attach(kStubPid);
        ok = r.has_value();
        printf("  attach: %s\n", ok ? "OK" : "FAILED");
    }
    if (ok) {
        auto r = debugger.suspend(4242);
        ok = r.has_value();
        printf("  suspend: %s\n", ok ? "OK" : "FAILED");
    }
    if (ok) {
        auto r = debugger.resume(4242);
        ok = r.has_value();
        printf("  resume: %s\n", ok ? "OK" : "FAILED");
    }
    if (ok) {
        auto r = debugger.setBreakpoint(4242, /*reg=*/0, 0x401234, /*type=*/0, /*size=*/1);
        ok = r.has_value();
        printf("  setBreakpoint: %s\n", ok ? "OK" : "FAILED");
    }
    if (ok) {
        auto r = debugger.removeBreakpoint(4242, /*reg=*/0);
        ok = r.has_value();
        printf("  removeBreakpoint: %s\n", ok ? "OK" : "FAILED");
    }
    if (ok) {
        auto evt = debugger.waitForEvent(50);
        ok = evt.has_value() && evt->threadId == 4242;
        printf("  waitForEvent: %s\n", ok ? "OK" : "FAILED");
    }
    if (ok) {
        auto r = debugger.continueAfterEvent(4242, 0);
        ok = r.has_value();
        printf("  continueAfterEvent: %s\n", ok ? "OK" : "FAILED");
    }
    if (ok) {
        auto ctx = debugger.getContext(4242);
        bool gctxOk = ctx.has_value() &&
            ctx->rax == 0xAAAA'BBBB'CCCC'DDDDULL &&
            ctx->rbx == 0x1111'2222'3333'4444ULL &&
            ctx->rip == 0x0000'0000'0040'1234ULL &&
            ctx->rflags == 0x0000'0000'0000'0246ULL &&
            ctx->rsp == 0x0000'7FFF'FFFF'1000ULL;
        printf("  getContext decodes regs: %s\n", gctxOk ? "OK" : "FAILED");
        ok = gctxOk;
    }
    if (ok) {
        // Round-trip: encode a known CpuContext, send via setContext, ensure
        // the bytes we sent decode back to the same values.
        CpuContext sent{};
        sent.rax = 0xDEAD'BEEF'1234'5678ULL;
        sent.rbx = 0xCAFE'BABE'2222'3333ULL;
        sent.rip = 0x4055'66ULL;
        sent.rflags = 0x202;
        sent.rsp = 0x7000'0000ULL;
        auto sr = debugger.setContext(4242, sent);
        bool sctxOk = sr.has_value() && g_lastSetContextBlob.size() >= 8 + 27 * 8;
        if (sctxOk) {
            uint64_t r[27] = {};
            std::memcpy(r, g_lastSetContextBlob.data() + 8, sizeof(r));
            sctxOk = r[10] == sent.rax && r[5] == sent.rbx &&
                     r[16] == sent.rip && r[18] == sent.rflags && r[19] == sent.rsp;
        }
        printf("  setContext encodes regs: %s\n", sctxOk ? "OK" : "FAILED");
        ok = sctxOk;
    }
    if (ok) {
        auto r = debugger.detach();
        ok = r.has_value();
        printf("  detach: %s\n", ok ? "OK" : "FAILED");
    }

    client.close();
    stopStub(fx);
}

void test_network_compression() {
    printf("\n── Test: Network compression ──\n");

    std::vector<uint8_t> payload;
    payload.reserve(4096);
    for (int i = 0; i < 4096; ++i)
        payload.push_back(static_cast<uint8_t>((i * 17) & 0xff));

    auto compressed = ce::net::compressPayload(payload, 9);
    std::expected<std::vector<uint8_t>, std::string> decompressed =
        std::unexpected(compressed ? "" : compressed.error());
    if (compressed)
        decompressed = ce::net::decompressPayload(*compressed, payload.size());

    auto badLevel = ce::net::compressPayload(payload, 99);
    std::expected<std::vector<uint8_t>, std::string> wrongSize =
        std::unexpected(compressed ? "" : compressed.error());
    if (compressed)
        wrongSize = ce::net::decompressPayload(*compressed, payload.size() + 1);

    bool ok = compressed &&
        decompressed &&
        *decompressed == payload &&
        !badLevel &&
        !wrongSize;
    printf("  zlib round trip: %s\n", ok ? "OK" : "FAILED");
}

void test_distributed_pointer_scan() {
    printf("\n── Test: Distributed pointer scan ──\n");

    constexpr uintptr_t moduleBase = 0x400000;
    constexpr uintptr_t heapBase = 0x700000;
    constexpr uintptr_t target = heapBase + 0x80;
    std::vector<uint8_t> module(0x100, 0);
    std::vector<uint8_t> heap(0x100, 0);

    uintptr_t heapPointer = target - 0x20;
    uintptr_t staticPointer = heapBase + 0x20;
    std::memcpy(heap.data() + 0x20, &heapPointer, sizeof(heapPointer));
    std::memcpy(module.data() + 0x10, &staticPointer, sizeof(staticPointer));

    FakeProcessHandle proc({
        {{moduleBase, module.size(), MemProt::Read, MemType::Image, MemState::Committed, "/tmp/game"}, module},
        {{heapBase, heap.size(), MemProt::ReadWrite, MemType::Private, MemState::Committed, "[heap]"}, heap},
    }, {
        {moduleBase, module.size(), "game", "/tmp/game", true},
    });

    PointerScanConfig config;
    config.targetAddress = target;
    config.maxDepth = 3;
    config.maxOffset = 0x100;

    PointerScanner fullScanner;
    auto full = fullScanner.scan(proc, config);

    std::vector<PointerPath> merged;
    for (auto shardConfig : makePointerScanShards(config, 2)) {
        PointerScanner shardScanner;
        auto shard = shardScanner.scan(proc, shardConfig);
        merged.insert(merged.end(), shard.begin(), shard.end());
    }

    auto hasExpectedPath = [&](const std::vector<PointerPath>& paths) {
        return std::any_of(paths.begin(), paths.end(), [](const PointerPath& path) {
            return path.module == "game" &&
                path.baseOffset == 0x10 &&
                path.offsets == std::vector<int32_t>({0, 0x20});
        });
    };

    bool ok = hasExpectedPath(full) &&
        hasExpectedPath(merged) &&
        merged.size() == full.size();
    printf("  shard merge: %s\n", ok ? "OK" : "FAILED");

    // Roundtrip: every found path must dereference back to the target, and a
    // rescan against the same target must keep them all (nothing spuriously
    // dropped or kept).
    bool derefOk = !full.empty() && std::all_of(full.begin(), full.end(),
        [&](const PointerPath& p) { return PointerScanner::dereference(proc, p) == target; });
    auto rescanned = rescanPointerPaths(proc, full, target);
    bool rescanOk = rescanned.size() == full.size() && hasExpectedPath(rescanned);
    printf("  dereference resolves to target: %s\n", derefOk ? "OK" : "FAILED");
    printf("  rescan (same target) keeps all valid paths: %s\n", rescanOk ? "OK" : "FAILED");

    // Rescanning against a DIFFERENT target must keep NONE of these paths — they
    // dereference to `target`, not target+0x10000. This is the discard half of the
    // rescan: after a restart, dereference re-resolves the module base by name and
    // paths that no longer reach the value's new address are dropped.
    auto rescanWrong = rescanPointerPaths(proc, full, target + 0x10000);
    printf("  rescan against a different target keeps none: %s\n",
           rescanWrong.empty() ? "OK" : "FAILED");

    // No two returned paths should be identical (module, baseOffset, offsets) —
    // the BFS's visited-set must not emit exact-duplicate paths.
    bool noDupes = true;
    for (size_t i = 0; i < full.size() && noDupes; ++i)
        for (size_t j = i + 1; j < full.size(); ++j)
            if (full[i].module == full[j].module &&
                full[i].baseOffset == full[j].baseOffset &&
                full[i].offsets == full[j].offsets) { noDupes = false; break; }
    printf("  pointer scan yields no duplicate paths: %s\n", noDupes ? "OK" : "FAILED");

    // staticOnly=false also records module-less (heap) bases as absolute
    // addresses; they dereference without a module and shard by page.
    PointerScanConfig loose = config;
    loose.staticOnly = false;
    PointerScanner looseScanner;
    auto all = looseScanner.scan(proc, loose);
    auto heapPath = std::find_if(all.begin(), all.end(), [&](const PointerPath& path) {
        return path.module.empty() && path.baseOffset == heapBase + 0x20 && path.offsets == std::vector<int32_t>({0x20});
    });
    std::vector<PointerPath> looseMerged;
    for (auto shardConfig : makePointerScanShards(loose, 2)) {
        PointerScanner shardScanner;
        auto shard = shardScanner.scan(proc, shardConfig);
        looseMerged.insert(looseMerged.end(), shard.begin(), shard.end());
    }
    bool nonStatic = heapPath != all.end() && PointerScanner::dereference(proc, *heapPath) == target &&
        heapPath->toString().find("700020") != std::string::npos && hasExpectedPath(all) &&
        std::none_of(full.begin(), full.end(), [](const PointerPath& path) { return path.module.empty(); }) &&
        looseMerged.size() == all.size();
    printf("  staticOnly=false adds absolute heap bases that resolve and shard: %s\n", nonStatic ? "OK" : "FAILED");
}

void test_pointer_scan_shard_through_static() {
    printf("\n── Test: Sharded scan keeps paths through a static intermediate ──\n");

    // Chain: gameA+0x10 -> gameB+0x20 -> heap+0x40 -> target. gameA and gameB are
    // DIFFERENT modules, so under 2-way sharding they land in different shards.
    // The gameA-ending path can only be discovered if BOTH module regions are read
    // (to walk THROUGH gameB). Regression for the sharded-scan traversal bug where
    // a shard skipped other shards' module regions and lost this path entirely.
    constexpr uintptr_t aBase = 0x400000, bBase = 0x500000, heapBase = 0x700000;
    constexpr uintptr_t target = heapBase + 0x80;
    std::vector<uint8_t> a(0x100, 0), b(0x100, 0), heap(0x100, 0);
    uintptr_t aPtr = bBase + 0x20;      // [gameA+0x10] -> gameB+0x20
    uintptr_t bPtr = heapBase + 0x40;   // [gameB+0x20] -> heap+0x40
    uintptr_t hPtr = target;            // [heap+0x40]   -> target
    std::memcpy(a.data() + 0x10, &aPtr, sizeof(aPtr));
    std::memcpy(b.data() + 0x20, &bPtr, sizeof(bPtr));
    std::memcpy(heap.data() + 0x40, &hPtr, sizeof(hPtr));

    FakeProcessHandle proc({
        {{aBase, a.size(), MemProt::Read, MemType::Image, MemState::Committed, "/tmp/gameA"}, a},
        {{bBase, b.size(), MemProt::Read, MemType::Image, MemState::Committed, "/tmp/gameB"}, b},
        {{heapBase, heap.size(), MemProt::ReadWrite, MemType::Private, MemState::Committed, "[heap]"}, heap},
    }, {
        {aBase, a.size(), "gameA", "/tmp/gameA", true},
        {bBase, b.size(), "gameB", "/tmp/gameB", true},
    });

    PointerScanConfig config;
    config.targetAddress = target;
    config.maxDepth = 4;
    config.maxOffset = 0x100;

    PointerScanner fullScanner;
    auto full = fullScanner.scan(proc, config);

    std::vector<PointerPath> merged;
    for (auto shardConfig : makePointerScanShards(config, 2)) {
        PointerScanner s;
        auto shard = s.scan(proc, shardConfig);
        merged.insert(merged.end(), shard.begin(), shard.end());
    }

    auto hasModule = [](const std::vector<PointerPath>& v, const std::string& m) {
        return std::any_of(v.begin(), v.end(),
            [&](const PointerPath& p) { return p.module == m; });
    };
    // The through-static gameA path must appear in BOTH the full scan and the
    // merged shards, and the shard union must equal the full result set.
    bool ok = hasModule(full, "gameA") && hasModule(full, "gameB") &&
              hasModule(merged, "gameA") && hasModule(merged, "gameB") &&
              merged.size() == full.size();
    printf("  sharded scan keeps through-static path: %s\n", ok ? "OK" : "FAILED");
}

void test_pointer_scan_persistence() {
    printf("\n── Test: Pointer scan persistence ──\n");

    std::vector<PointerPath> paths;
    PointerPath p1; p1.module = "libgame.so"; p1.moduleBase = 0x400000;
        p1.baseOffset = 0x1000; p1.offsets = {0, 0x20};
    PointerPath p2; p2.module = "libgame.so"; p2.moduleBase = 0x400000;
        p2.baseOffset = 0x2000; p2.offsets = {0x40, 0x10, -8};
    PointerPath p3; p3.module = "loader";    p3.moduleBase = 0x500000;
        p3.baseOffset = 0x100;  p3.offsets = {};
    paths = {p1, p2, p3};

    auto tmp = std::filesystem::temp_directory_path() / "cecore_pscan.bin";
    bool saved = savePointerPaths(tmp.string(), paths);
    printf("  save: %s\n", saved ? "OK" : "FAILED");
    if (!saved) return;

    std::string err;
    auto loaded = loadPointerPaths(tmp.string(), &err);
    bool loadOk = loaded.size() == 3 &&
        loaded[0].module == "libgame.so" &&
        loaded[0].offsets == std::vector<int32_t>({0, 0x20}) &&
        loaded[1].offsets == std::vector<int32_t>({0x40, 0x10, -8}) &&
        loaded[2].offsets.empty();
    printf("  load round-trip: %s\n", loadOk ? "OK" : ("FAILED (" + err + ")").c_str());
    if (!loadOk) { std::filesystem::remove(tmp); return; }

    std::vector<PointerPath> sorted = loaded;
    sortPointerPaths(sorted, PointerSortKey::Depth);
    bool sortDepthOk = sorted[0].offsets.size() <= sorted[1].offsets.size() &&
                       sorted[1].offsets.size() <= sorted[2].offsets.size();
    printf("  sort by depth: %s\n", sortDepthOk ? "OK" : "FAILED");

    sortPointerPaths(sorted, PointerSortKey::BaseOffset);
    bool sortBaseOk = sorted[0].baseOffset <= sorted[1].baseOffset &&
                      sorted[1].baseOffset <= sorted[2].baseOffset;
    printf("  sort by baseOffset: %s\n", sortBaseOk ? "OK" : "FAILED");

    PointerPath duplicate = p1;
    PointerPath unique;    unique.module = "libgame.so"; unique.moduleBase = 0x400000;
                           unique.baseOffset = 0x9000; unique.offsets = {0x50};
    auto merged = mergePointerPaths(paths, {duplicate, unique}, /*dedup=*/true);
    bool mergeDedupOk = merged.size() == 4;
    printf("  merge with dedup: %s (got %zu, expected 4)\n", mergeDedupOk ? "OK" : "FAILED", merged.size());

    auto mergedNoDedup = mergePointerPaths(paths, {duplicate, unique}, /*dedup=*/false);
    bool mergePlainOk = mergedNoDedup.size() == 5;
    printf("  merge without dedup: %s\n", mergePlainOk ? "OK" : "FAILED");

    std::filesystem::remove(tmp);
}

void test_ct_table_luascript_after_entries() {
    printf("\n── Test: table LuaScript placed after </CheatEntries> ──\n");
    // CE writes the table-level <LuaScript> AFTER the entries block; the loader
    // must still pick it up (it used to search only before <CheatEntries>).
    const char* xml =
        "<?xml version=\"1.0\"?>\n<CheatTable>\n"
        "<CheatEntries><CheatEntry><ID>1</ID><Description>x</Description>"
        "<VariableType>4 Bytes</VariableType><Address>400000</Address></CheatEntry></CheatEntries>\n"
        "<LuaScript>return 1+1</LuaScript>\n</CheatTable>\n";
    auto dir = std::filesystem::temp_directory_path();
    auto path = (dir / "ce_luascript_pos.ct").string();
    { std::ofstream o(path); o << xml; }
    ce::CheatTable t;
    bool ok = t.load(path) && t.luaScript == "return 1+1";
    std::filesystem::remove(path);
    printf("  table LuaScript after entries is parsed: %s\n", ok ? "OK" : "FAILED");

    // A group nests its own <CheatEntries>, so the FIRST "</CheatEntries>" is the
    // child's. Searching "outside the first entries block" then left the sibling
    // entry after the group in scope, and its per-record <LuaScript> shadowed the
    // real table-level one. Must use the MATCHING outer close.
    const char* nested =
        "<?xml version=\"1.0\"?>\n<CheatTable>\n<CheatEntries>\n"
        "<CheatEntry><ID>1</ID><Description>grp</Description><GroupHeader>1</GroupHeader>"
        "<CheatEntries><CheatEntry><ID>2</ID><Description>c</Description>"
        "<VariableType>4 Bytes</VariableType><Address>400000</Address></CheatEntry></CheatEntries>"
        "</CheatEntry>\n"
        "<CheatEntry><ID>3</ID><Description>sib</Description>"
        "<VariableType>4 Bytes</VariableType><Address>400010</Address>"
        "<LuaScript>return 'entry'</LuaScript></CheatEntry>\n"
        "</CheatEntries>\n<LuaScript>return 'table'</LuaScript>\n</CheatTable>\n";
    auto path2 = (dir / "ce_luascript_nested.ct").string();
    { std::ofstream o(path2); o << nested; }
    ce::CheatTable t2;
    bool nestedOk = t2.load(path2) && t2.luaScript == "return 'table'" && t2.entries.size() == 3;
    std::filesystem::remove(path2);
    printf("  table LuaScript not shadowed by a sibling record: %s (got '%s')\n",
           nestedOk ? "OK" : "FAILED", t2.luaScript.c_str());
}
void test_ct_json_pointer_roundtrip() {
    printf("\n── Test: JSON round-trip preserves pointer chain / length ──\n");
    // saveJson/loadJson (also the .CETRAINER path) used to drop these, so a
    // protected table lost pointer chains, symbolic bases and String/AoB length.
    CheatTable t;
    CheatEntry e;
    e.id = 1;
    e.description = "ptr";
    e.type = ValueType::String;
    e.addressString = "\"game.exe\"+1C";
    e.offsets = {0x10, 0x8};
    e.length = 12;
    e.optionsXml = "<Options moActivateChildrenAsWell=\"1\" moDeactivateChildrenAsWell=\"0\"/>";
    t.entries.push_back(e);

    auto path = std::filesystem::temp_directory_path() /
        ("cecore-json-ptr-" + std::to_string(getpid()) + ".json");
    bool saved = t.saveJson(path.string());
    CheatTable l;
    bool loaded = saved && l.loadJson(path.string()) && l.entries.size() == 1;
    std::filesystem::remove(path);
    bool ok = loaded &&
        l.entries[0].addressString == e.addressString &&
        l.entries[0].offsets == e.offsets &&
        l.entries[0].length == e.length &&
        l.entries[0].optionsXml == e.optionsXml;
    printf("  addressString/offsets/length/optionsXml survive: %s\n", ok ? "OK" : "FAILED");
}

void test_il2cpp_pe_header_bounds() {
    printf("\n── Test: IL2CPP PE optional-header bounds ──\n");
    // A PE32+ whose SizeOfOptionalHeader does not cover the fields loadPE reads
    // (magic at +0, ImageBase at +24). With opt at/near EOF this was an OOB read
    // (caught under the CI ASan job); it must be rejected outright.
    std::vector<uint8_t> pe(128, 0);
    pe[0] = 'M'; pe[1] = 'Z';
    uint32_t e = 0x67;                        // PE header near EOF
    std::memcpy(&pe[0x3C], &e, 4);
    std::memcpy(&pe[e], "PE\0\0", 4);
    size_t coff = e + 4;
    uint16_t machine = 0x8664; std::memcpy(&pe[coff], &machine, 2);
    uint16_t nsec = 0;         std::memcpy(&pe[coff + 2], &nsec, 2);
    uint16_t optSize = 0;      std::memcpy(&pe[coff + 16], &optSize, 2);

    auto path = std::filesystem::temp_directory_path() /
        ("cecore-il2cpp-pe-" + std::to_string(getpid()) + ".bin");
    { std::ofstream o(path, std::ios::binary);
      o.write(reinterpret_cast<const char*>(pe.data()), (std::streamsize)pe.size()); }
    ce::Il2CppMetadata md;
    md.tablesDecoded = true;
    ce::Il2CppBinaryLayout layout = ce::resolveIl2CppLayout(md, path.string());
    std::filesystem::remove(path);
    bool ok = !layout.error.empty();   // rejected instead of reading past EOF
    printf("  undersized optional header rejected: %s\n", ok ? "OK" : "FAILED");
}

void test_dwarf_symbols() {
    printf("\n── Test: DWARF symbols ──\n");

    DwarfInfo info;
    bool available = DwarfInfo::available();
    printf("  libdw available at build time: %s\n", available ? "yes" : "no (stub mode)");

    if (!available) {
        // Stub path: every method must report nothing.
        bool ok = !info.load("/usr/bin/sleep", 0) &&
                  !info.isLoaded() &&
                  !info.lookup(0x1234).has_value();
        printf("  stub returns no info: %s\n", ok ? "OK" : "FAILED");
        info.close();
        return;
    }

    // libdw path: try to load /usr/bin/sleep (or the test binary itself).
    bool loaded = info.load("/usr/bin/sleep", 0);
    if (!loaded) loaded = info.load("/proc/self/exe", 0);
    printf("  load: %s\n", loaded ? "OK" : "no DWARF in tested binary (skipped)");

    if (loaded) {
        printf("  isLoaded after load: %s\n", info.isLoaded() ? "OK" : "FAILED");
        info.close();
        printf("  isLoaded after close: %s\n", !info.isLoaded() ? "OK" : "FAILED");
    }

    // Lookup path: compile a tiny -g .so, resolve a function's address from its
    // symtab, and verify DWARF maps that address back to a source file + line.
    // The struct + global exercise DWARF type extraction (roadmap #20).
    const char* src =
        "struct CeProbe { int a; float b; char c; long d; int* p; };\n"
        "struct CeProbe ceProbeGlobal;\n"
        "int ceDwarfProbe(int x){\n  ceProbeGlobal.a = x;\n  int y = x + 1;\n  return y;\n}\n"
        "static inline __attribute__((always_inline)) int ceDwarfInner(int v){ return v * 3; }\n"
        "int ceDwarfOuter(int x){\n  { int z = x + 2;\n    return ceDwarfInner(z); }\n}\n";
    auto dir = std::filesystem::temp_directory_path();
    auto c  = dir / "ce_dwarf_test.c";
    auto so = dir / "libce_dwarf_test.so";
    { std::ofstream o(c); o << src; }
    std::string cmd = "gcc -shared -fPIC -g -O0 -o '" + so.string() + "' '" + c.string() + "' 2>/dev/null";
    if (std::system(cmd.c_str()) == 0) {
        ce::SymbolResolver res;
        res.loadModule(so.string(), "d", 0);
        uintptr_t addr = res.lookup("ceDwarfProbe");
        DwarfInfo di;
        bool lok = false;
        if (addr && di.load(so.string(), 0)) {
            auto loc = di.lookup(addr);
            lok = loc.has_value() && loc->line >= 1 &&
                  loc->file.find("ce_dwarf_test") != std::string::npos;
        }
        printf("  DWARF address->source line lookup: %s\n", lok ? "OK" : "FAILED");

        // Function names: a plain function, and one whose code sits in a
        // nested block with an inlined call (the walk descends into both).
        const uintptr_t outer = res.lookup("ceDwarfOuter");
        bool named = addr && outer && di.isLoaded() && di.functionName(addr) == std::optional<std::string>("ceDwarfProbe") &&
                     di.functionName(outer) == std::optional<std::string>("ceDwarfOuter");
        // Somewhere inside ceDwarfOuter, the inlined ceDwarfInner is named.
        bool inlined = false;
        for (uintptr_t at = outer; outer && at < outer + 96 && !inlined; ++at)
            inlined = di.functionName(at) == std::optional<std::string>("ceDwarfInner");
        printf("  DWARF address->function name, nested and inlined: %s\n", named && inlined ? "OK" : "FAILED");

        // DWARF struct type extraction + typed structure build (#20).
        DwarfInfo dt;
        if (dt.load(so.string(), 0)) {
            auto names = dt.structNames();
            bool listed = std::find(names.begin(), names.end(), "CeProbe") != names.end();
            auto st = dt.structByName("CeProbe");
            bool membersOk = false;
            if (st) {
                auto find = [&](const char* n) -> const ce::DwarfMember* {
                    for (const auto& m : st->members) if (m.name == n) return &m;
                    return nullptr;
                };
                const auto* a = find("a"); const auto* b = find("b"); const auto* p = find("p");
                membersOk = st->size >= 24 &&
                    a && a->typeName == "int" && a->size == 4 && !a->isFloat && !a->isPointer && a->offset == 0 &&
                    b && b->isFloat && b->size == 4 && b->offset == 4 &&
                    p && p->isPointer && p->typeName == "int*";
            }
            auto def = st ? ce::dwarfStructToStructure(*st) : ce::StructureDefinition{};
            auto ftype = [&](const char* n, ce::ValueType t) {
                for (const auto& f : def.fields) if (f.name == n) return f.type == t;
                return false;
            };
            bool typedOk = st && def.name == "CeProbe" &&
                ftype("a", ce::ValueType::Int32) && ftype("b", ce::ValueType::Float) &&
                ftype("p", ce::ValueType::Pointer);
            printf("  DWARF struct listed + members resolved: %s\n",
                   (listed && membersOk) ? "OK" : "FAILED");
            printf("  DWARF struct -> typed structure: %s\n", typedOk ? "OK" : "FAILED");
        }
    }
    std::filesystem::remove(c); std::filesystem::remove(so);
}

// Symbol resolution for 32-bit (ELFCLASS32) ELFs, the prerequisite for 32-bit
// library injection (resolving e.g. __libc_dlopen_mode in a 32-bit libc). Skips
// gracefully when the host lacks a 32-bit toolchain.
void test_elf32_symbols() {
    printf("\n── Test: 32-bit ELF symbol resolution ──\n");
    const char* src = "int ce32Probe(int x){ return x + 7; }\n";
    auto dir = std::filesystem::temp_directory_path();
    auto c  = dir / "ce_elf32_test.c";
    auto so = dir / "libce_elf32_test.so";
    { std::ofstream o(c); o << src; }
    std::string cmd = "gcc -m32 -shared -fPIC -O0 -o '" + so.string() +
                      "' '" + c.string() + "' 2>/dev/null";
    if (std::system(cmd.c_str()) == 0) {
        ce::SymbolResolver res;
        res.loadModule(so.string(), "e32", 0);
        uintptr_t addr = res.lookup("ce32Probe");
        printf("  resolve exported symbol in a 32-bit .so: %s\n",
               addr != 0 ? "OK" : "FAILED");
    } else {
        printf("  resolve exported symbol in a 32-bit .so: SKIPPED (no gcc -m32)\n");
    }
    std::filesystem::remove(c); std::filesystem::remove(so);
}

// End-to-end 32-bit library injection: compile a real 32-bit target + .so, exec
// the target so it is a genuine i386 process, then inject the .so via the i386
// ptrace path (int 0x80 / mmap2 / cdecl __libc_dlopen_mode) and confirm it maps.
// Skips gracefully without a 32-bit toolchain.
void test_inject_library_32bit() {
    printf("\n── Test: 32-bit library injection ──\n");

    auto dir = std::filesystem::temp_directory_path();
    auto tgtC   = dir / "ce_inj32_target.c";
    auto tgtBin = dir / "ce_inj32_target";
    auto libC   = dir / "ce_inj32_lib.c";
    auto libSo  = dir / "libce_inj32.so";

    // Target: allow any tracer (YAMA), report readiness, then spin in USERSPACE
    // so the injector can hijack a userspace thread (a thread parked in a
    // syscall, or one still inside libc or the loader, can't be used).
    {
        std::ofstream o(tgtC);
        o << "#include <sys/prctl.h>\n#include <unistd.h>\n"
             "int main(){ prctl(PR_SET_PTRACER, -1L, 0, 0, 0);\n"
             "  if (write(1, \"R\", 1) != 1) return 1;\n"
             "  for(volatile unsigned long i=0;;++i){} return 0; }\n";
    }
    { std::ofstream o(libC); o << "int ceInjected32(){ return 1; }\n"; }

    auto sh = [](const std::string& c){ return std::system(c.c_str()) == 0; };
    bool built =
        sh("gcc -m32 -O0 -o '" + tgtBin.string() + "' '" + tgtC.string() + "' 2>/dev/null") &&
        sh("gcc -m32 -shared -fPIC -O0 -o '" + libSo.string() + "' '" + libC.string() + "' 2>/dev/null");
    if (!built) {
        printf("  32-bit .so injected + mapped: SKIPPED (no gcc -m32 toolchain)\n");
        for (auto* p : {&tgtC, &libC, &tgtBin, &libSo}) std::filesystem::remove(*p);
        return;
    }

    int ready[2] = {-1, -1};
    pid_t child = pipe(ready) == 0 ? fork() : -1;
    if (child == 0) {
        dup2(ready[1], 1);
        close(ready[0]); close(ready[1]);
        execl(tgtBin.c_str(), tgtBin.c_str(), (char*)nullptr);
        _exit(127);
    }
    if (ready[1] >= 0) close(ready[1]);

    bool ok = false;
    std::string detail;
    if (child > 0) {
        // Wait until it has exec'd, set the ptracer and left libc for its spin;
        // a fixed delay is not enough on a busy runner.
        pollfd fd{ready[0], POLLIN, 0};
        char marker = 0;
        bool reached = poll(&fd, 1, 10000) == 1 && read(ready[0], &marker, 1) == 1 && marker == 'R';
        if (!reached) detail = "target did not reach its spin loop";
        LinuxProcessHandle proc(child);
        ce::SymbolResolver resolver;
        resolver.loadProcess(proc);
        auto res = reached ? ce::os::injectLibrary(proc, resolver, libSo.string()) :
            std::expected<uintptr_t, std::string>(std::unexpected(detail));
        ok = res.has_value();
        if (!res) detail = res.error();
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
    }
    if (ready[0] >= 0) close(ready[0]);

    if (ok) printf("  32-bit .so injected + mapped: OK\n");
    else     printf("  32-bit .so injected + mapped: FAILED (%s)\n", detail.c_str());

    for (auto* p : {&tgtC, &libC, &tgtBin, &libSo}) std::filesystem::remove(*p);
}

void test_autoasm_lua_blocks() {
    printf("\n── Test: AutoAssembler {$lua} blocks ──\n");

    LuaEngine engine;
    AutoAssembler aa;
    aa.setLuaEvaluator([&](const std::string& code) -> std::expected<std::string, std::string> {
        return engine.evalToString(code);
    });

    // Substitution: {$lua} block returns a string that becomes part of the AA stream.
    {
        std::string script =
            "[ENABLE]\n"
            "{$lua}return \"alloc(newmem,1024)\\nlabel(myLabel)\"{$asm}\n"
            "[DISABLE]\n";
        auto r = aa.check(script);
        bool ok = r.success;
        printf("  block returns AA text: %s%s\n",
            ok ? "OK" : "FAILED ", ok ? "" : ("(" + r.error + ")").c_str());
        if (!ok) return;
    }

    // {$endlua} alternative terminator.
    {
        std::string script =
            "[ENABLE]\n"
            "{$lua}return \"\"{$endlua}\n"
            "alloc(here, 64)\n"
            "[DISABLE]\n";
        auto r = aa.check(script);
        printf("  {$endlua} terminator: %s\n", r.success ? "OK" : ("FAILED: " + r.error).c_str());
    }

    // Conditional code generation pattern — produces or skips lines based on a flag.
    {
        engine.execute("CE_VERSION = 7.5");
        std::string script =
            "[ENABLE]\n"
            "{$lua}\n"
            "  if CE_VERSION >= 7.0 then\n"
            "    return \"label(modern)\\n\"\n"
            "  else\n"
            "    return \"label(legacy)\\n\"\n"
            "  end\n"
            "{$asm}\n"
            "modern:\n"
            "[DISABLE]\n";
        auto r = aa.check(script);
        printf("  conditional codegen: %s\n", r.success ? "OK" : ("FAILED: " + r.error).c_str());
    }

    // A {$lua} block runs to the end of its section, as in Cheat Engine's
    // pure-Lua records ([ENABLE] {$lua} ... [DISABLE] {$lua} ...).
    {
        std::string script =
            "[ENABLE]\n"
            "{$lua}return \"\"\n"
            "[DISABLE]\n";
        auto r = aa.check(script);
        printf("  a Lua block may end with its section: %s\n", r.success ? "OK" : ("FAILED: " + r.error).c_str());
    }

    // A check never runs the block: a script under review may be untrusted.
    {
        std::string script =
            "[ENABLE]\n"
            "{$lua}error(\"boom\"){$asm}\n"
            "[DISABLE]\n";
        auto r = aa.check(script);
        bool notRun = r.success && r.error.find("boom") == std::string::npos;
        printf("  check does not run {$lua} blocks: %s\n", notRun ? "OK" : ("FAILED: " + r.error).c_str());
    }

    // {$ccode} block — explicit reject.
    {
        std::string script =
            "[ENABLE]\n"
            "{$ccode}int main() { return 0; }{$endccode}\n"
            "[DISABLE]\n";
        auto r = aa.check(script);
        bool detected = !r.success && r.error.find("TinyCC") != std::string::npos;
        printf("  {$ccode} reject: %s\n", detected ? "OK" : ("FAILED: " + r.error).c_str());
    }

    // Without an evaluator, {$lua} is a syntax error.
    {
        AutoAssembler bare;
        std::string script = "[ENABLE]\n{$lua}return \"\"{$asm}\n[DISABLE]\n";
        auto r = bare.check(script);
        bool detected = !r.success && r.error.find("evaluator") != std::string::npos;
        printf("  no-evaluator detected: %s\n", detected ? "OK" : ("FAILED: " + r.error).c_str());
    }
}

void test_autoasm_conditional_blocks() {
    printf("\n── Test: AutoAssembler {$if}/{$else}/{$endif} ──\n");

    LuaEngine engine;
    AutoAssembler aa;
    aa.setLuaEvaluator([&](const std::string& code) -> std::expected<std::string, std::string> {
        return engine.evalToString(code);
    });
    engine.execute("FLAG = true");

    {
        std::string script =
            "[ENABLE]\n"
            "{$if FLAG}\n"
            "alloc(taken, 16)\n"
            "{$else}\n"
            "alloc(skipped, 16)\n"
            "{$endif}\n"
            "[DISABLE]\n";
        auto r = aa.check(script);
        printf("  truthy branch kept: %s\n", r.success ? "OK" : ("FAILED: " + r.error).c_str());
    }

    engine.execute("FLAG = false");
    {
        std::string script =
            "[ENABLE]\n"
            "{$if FLAG}\n"
            "alloc(taken, 16)\n"
            "{$else}\n"
            "alloc(elseBranch, 16)\n"
            "{$endif}\n"
            "[DISABLE]\n";
        auto r = aa.check(script);
        printf("  falsy branch kept: %s\n", r.success ? "OK" : ("FAILED: " + r.error).c_str());
    }

    {
        std::string script = "[ENABLE]\n{$if FLAG}\nalloc(x, 16)\n[DISABLE]\n";  // no {$endif}
        auto r = aa.check(script);
        bool detected = !r.success && r.error.find("{$endif}") != std::string::npos;
        printf("  missing endif flagged: %s\n", detected ? "OK" : ("FAILED: " + r.error).c_str());
    }
}
