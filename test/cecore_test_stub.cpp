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

// Loopback ceserver stub that handles every command exercised by the extended
// ops + adapter tests. Returns deterministic blobs keyed off the chosen handle/pid.
std::vector<uint8_t> g_lastSetContextBlob;

void runStubServer(StubFixture* fx) {
    int client = ::accept(fx->server, nullptr, nullptr);
    if (client < 0) return;

    auto recvN = [&](void* buf, size_t n) { return ::recv(client, buf, n, MSG_WAITALL) == (ssize_t)n; };
    auto sendN = [&](const void* buf, size_t n) { ::send(client, buf, n, 0); };

    while (!fx->stop) {
        uint8_t cmd = 0xff;
        ssize_t n = ::recv(client, &cmd, 1, MSG_WAITALL);
        if (n <= 0) break;

        if (cmd == 3) { // OPENPROCESS
            int32_t pid = 0; recvN(&pid, 4);
            int32_t h = (pid == kStubPid) ? kStubHandle : 0;
            sendN(&h, 4);
        } else if (cmd == 7) { // CLOSEHANDLE
            int32_t h = 0; recvN(&h, 4);
            int32_t r = 1; sendN(&r, 4);
        } else if (cmd == 21) { // GETARCHITECTURE
            int32_t h = 0; recvN(&h, 4);
            uint8_t arch = 1; sendN(&arch, 1); // x86_64
        } else if (cmd == 26) { // ALLOC
            int32_t h = 0; uint64_t base = 0; uint32_t size = 0, prot = 0;
            recvN(&h, 4); recvN(&base, 8); recvN(&size, 4); recvN(&prot, 4);
            uint64_t addr = (h == kStubHandle && size > 0) ? kStubAlloc : 0;
            sendN(&addr, 8);
        } else if (cmd == 27) { // FREE
            int32_t h = 0; uint64_t addr = 0; uint32_t size = 0;
            recvN(&h, 4); recvN(&addr, 8); recvN(&size, 4);
            uint32_t r = 1; sendN(&r, 4);
        } else if (cmd == 36) { // CHANGEMEMORYPROTECTION
            int32_t h = 0; uint64_t addr = 0; uint32_t size = 0, prot = 0;
            recvN(&h, 4); recvN(&addr, 8); recvN(&size, 4); recvN(&prot, 4);
            uint32_t result = 1, oldProt = 0x40; sendN(&result, 4); sendN(&oldProt, 4);
        } else if (cmd == 35) { // CREATETOOLHELP32SNAPSHOTEX
            uint32_t flags = 0, pid = 0;
            recvN(&flags, 4); recvN(&pid, 4);
            if (flags & 0x4) { // SNAPTHREAD
                int32_t count = 3;
                int32_t tids[3] = { 1001, 1002, 1003 };
                sendN(&count, 4);
                sendN(tids, sizeof(tids));
            } else if (flags & 0x8) { // SNAPMODULE
                auto sendModule = [&](int32_t result, uint64_t base, int32_t modSize, const char* name) {
                    int32_t part = 0;
                    uint32_t fileOff = 0;
                    int32_t nameSize = (int32_t)std::strlen(name);
                    sendN(&result, 4);
                    sendN(&base, 8);
                    sendN(&part, 4);
                    sendN(&modSize, 4);
                    sendN(&fileOff, 4);
                    sendN(&nameSize, 4);
                    if (nameSize > 0) sendN(name, nameSize);
                };
                sendModule(1, 0x400000, 0x10000, "/usr/lib/libc.so.6");
                sendModule(1, 0x500000, 0x4000,  "/usr/bin/target");
                sendModule(0, 0, 0, "");
            }
        } else if (cmd == 8) { // VIRTUALQUERYEX (used by adapter to test queryRegion)
            int32_t h = 0; uint64_t base = 0;
            recvN(&h, 4); recvN(&base, 8);
            uint8_t result = 1;
            uint32_t prot = 0x4;
            uint32_t type = 0x20000;
            uint64_t b = base;
            uint64_t s = 0x1000;
            sendN(&result, 1); sendN(&prot, 4); sendN(&type, 4); sendN(&b, 8); sendN(&s, 8);
        } else if (cmd == 31) { // VIRTUALQUERYEXFULL
            int32_t h = 0; uint8_t flags = 0;
            recvN(&h, 4); recvN(&flags, 1);
            int32_t count = 1; sendN(&count, 4);
            uint32_t prot = 0x40, type = 0x1000000;
            uint64_t base = 0x400000, size = 0x10000;
            sendN(&base, 8); sendN(&size, 8); sendN(&prot, 4); sendN(&type, 4);   // upstream RegionInfo order
        } else if (cmd == 11) { // STARTDEBUG
            int32_t h = 0; recvN(&h, 4);
            int32_t r = (h == kStubHandle) ? 1 : 0; sendN(&r, 4);
        } else if (cmd == 12) { // STOPDEBUG
            int32_t h = 0; recvN(&h, 4);
            int32_t r = 1; sendN(&r, 4);
        } else if (cmd == 13) { // WAITFORDEBUGEVENT
            int32_t h = 0, timeout = 0; recvN(&h, 4); recvN(&timeout, 4);
            // Always return one event for the test.
            int32_t result = 1;
            int32_t debugEvt = 5; // SIGTRAP
            int64_t tid = 4242;
            uint64_t addr = 0xCAFEBABE;
            sendN(&result, 4);
            sendN(&debugEvt, 4);
            sendN(&tid, 8);
            sendN(&addr, 8);
        } else if (cmd == 14) { // CONTINUEFROMDEBUGEVENT
            int32_t h = 0, tid = 0, ignore = 0;
            recvN(&h, 4); recvN(&tid, 4); recvN(&ignore, 4);
            int32_t r = 1; sendN(&r, 4);
        } else if (cmd == 15) { // SETBREAKPOINT
            int32_t h = 0, tid = 0, debugReg = 0, bptype = 0, bpsize = 0;
            uint64_t address = 0;
            recvN(&h, 4); recvN(&tid, 4); recvN(&debugReg, 4);
            recvN(&address, 8); recvN(&bptype, 4); recvN(&bpsize, 4);
            int32_t r = 1; sendN(&r, 4);
        } else if (cmd == 16) { // REMOVEBREAKPOINT
            int32_t h = 0; uint32_t tid = 0, debugReg = 0, wasWatch = 0;
            recvN(&h, 4); recvN(&tid, 4); recvN(&debugReg, 4); recvN(&wasWatch, 4);
            int32_t r = 1; sendN(&r, 4);
        } else if (cmd == 17 || cmd == 18) { // SUSPEND / RESUME THREAD
            int32_t h = 0, tid = 0; recvN(&h, 4); recvN(&tid, 4);
            int32_t r = 1; sendN(&r, 4);
        } else if (cmd == 19) { // GETTHREADCONTEXT
            int32_t h = 0; uint32_t tid = 0; recvN(&h, 4); recvN(&tid, 4);
            uint32_t result = 1;
            // Wire format: header(8) + 27 * uint64 user_regs_struct.
            constexpr uint32_t kHdr = 8;
            constexpr uint32_t kRegBytes = 27 * 8;
            uint32_t structSize = kHdr + kRegBytes;
            std::vector<uint8_t> ctx(structSize, 0);
            std::memcpy(ctx.data(), &structSize, 4);
            // Stash recognisable values in the user_regs_struct fields the
            // marshaller will read back as rax/rbx/rip/rflags/rsp.
            uint64_t r[27] = {};
            r[5]  = 0x1111'2222'3333'4444ULL;  // rbx
            r[10] = 0xAAAA'BBBB'CCCC'DDDDULL;  // rax
            r[16] = 0x0000'0000'0040'1234ULL;  // rip
            r[18] = 0x0000'0000'0000'0246ULL;  // rflags (IF + ZF + PF)
            r[19] = 0x0000'7FFF'FFFF'1000ULL;  // rsp
            std::memcpy(ctx.data() + kHdr, r, kRegBytes);
            sendN(&result, 4);
            sendN(&structSize, 4);
            sendN(ctx.data(), structSize);
        } else if (cmd == 20) { // SETTHREADCONTEXT
            int32_t h = 0; uint32_t tid = 0, structSize = 0;
            recvN(&h, 4); recvN(&tid, 4); recvN(&structSize, 4);
            std::vector<uint8_t> blob(structSize);
            if (structSize > 0) recvN(blob.data(), structSize);
            // Capture so the test can verify round-trip bytes.
            ::g_lastSetContextBlob = blob;
            uint32_t r = 1; sendN(&r, 4);
        } else if (cmd == 30) { // SPEEDHACK_SETSPEED
            int32_t h = 0; float speed = 0.0f;
            recvN(&h, 4); recvN(&speed, 4);
            uint32_t r = 1; sendN(&r, 4);
        } else if (cmd == 24) { // GETSYMBOLLISTFROMFILE
            uint32_t off = 0, pathSize = 0;
            recvN(&off, 4); recvN(&pathSize, 4);
            std::string path(pathSize, '\0');
            if (pathSize > 0) recvN(path.data(), pathSize);
            // Return a synthetic 16-byte payload when the path looks valid;
            // 8 zero bytes (no-symbols sentinel) otherwise.
            if (path.find("libgame") != std::string::npos) {
                uint8_t blob[16] = {};
                uint32_t totalSize = 16;
                std::memcpy(blob + 4, &totalSize, 4);
                blob[8] = 0xCA; blob[9] = 0xFE; blob[10] = 0xBA; blob[11] = 0xBE;
                sendN(blob, 16);
            } else {
                uint8_t zeros[8] = {};
                sendN(zeros, 8);
            }
        } else {
            break;
        }
    }
    ::close(client);
}

bool startStub(StubFixture& fx) {
    fx.server = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fx.server < 0 ||
        ::bind(fx.server, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
        ::listen(fx.server, 1) != 0) return false;
    socklen_t len = sizeof(addr);
    if (::getsockname(fx.server, reinterpret_cast<sockaddr*>(&addr), &len) != 0) return false;
    fx.port = ntohs(addr.sin_port);
    fx.thread = std::thread([&fx]() { runStubServer(&fx); });
    return true;
}

void stopStub(StubFixture& fx) {
    fx.stop = true;
    if (fx.thread.joinable()) fx.thread.join();
    if (fx.server >= 0) ::close(fx.server);
}
