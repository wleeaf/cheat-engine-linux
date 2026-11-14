// cecore_test: breakpoints with conditions, kernel and Vulkan helpers, Lua
// bindings, memory scans and the review regressions.
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

void test_one_shot_breakpoints() {
    printf("\n── Test: One-shot breakpoints ──\n");

    BreakpointManager mgr;
    Breakpoint bp;
    bp.address = 0x5000;
    bp.oneShot = true;
    int id = mgr.add(bp);

    BreakpointHit hit{};
    hit.bpId = id;
    hit.address = bp.address;
    hit.rip = bp.address;
    hit.context.rip = hit.rip;

    bool firstMatched = mgr.recordHit(id, hit);
    bool secondMatched = mgr.recordHit(id, hit);
    auto bps = mgr.list();
    bool stillListed = std::any_of(bps.begin(), bps.end(), [id](const Breakpoint& listed) {
        return listed.id == id;
    });

    bool ok = firstMatched && !secondMatched && !stillListed && mgr.getHits(id).size() == 1;
    printf("  auto-remove after hit: %s\n", ok ? "OK" : "FAILED");
}

void test_thread_filtered_breakpoints() {
    printf("\n── Test: Thread-filtered breakpoints ──\n");

    BreakpointManager mgr;
    Breakpoint bp;
    bp.address = 0x6000;
    bp.threadFilter = 1234;
    int id = mgr.add(bp);

    BreakpointHit miss{};
    miss.bpId = id;
    miss.address = bp.address;
    miss.rip = bp.address;
    miss.tid = 4321;
    miss.context.rip = miss.rip;

    BreakpointHit match = miss;
    match.tid = bp.threadFilter;

    bool missed = mgr.recordHit(id, miss);
    bool matched = mgr.recordHit(id, match);

    auto bps = mgr.list();
    auto it = std::find_if(bps.begin(), bps.end(), [id](const Breakpoint& listed) {
        return listed.id == id;
    });

    bool ok = !missed && matched && it != bps.end() && it->hitCount == 1 &&
        mgr.getHits(id).size() == 1 && mgr.getHits(id).front().tid == bp.threadFilter;
    printf("  TID filter: %s\n", ok ? "OK" : "FAILED");
}

void test_managed_method_breakpoints() {
    printf("\n── Test: Managed method breakpoints ──\n");

    BreakpointManager mgr;
    ManagedMethodInfo method;
    method.type.typeHandle = 0x510040;
    method.type.name = "Player";
    method.type.namespaceName = "Game.Entities";
    method.type.runtimeKind = ManagedRuntimeKind::CoreCLR;
    method.methodName = "TakeDamage";
    method.signature = "(int)";
    method.metadataToken = 0x06000042;
    method.nativeAddress = 0x7fff00102030;
    method.nativeSize = 0x80;

    ManagedMethodBreakpointOptions options;
    options.oneShot = true;
    options.threadFilter = 77;
    options.condition = "rax == 10";
    int id = addManagedMethodBreakpoint(mgr, method, options);

    ManagedMethodInfo unresolved = method;
    unresolved.nativeAddress = 0;
    int unresolvedId = addManagedMethodBreakpoint(mgr, unresolved);

    auto bps = mgr.list();
    auto it = std::find_if(bps.begin(), bps.end(), [id](const Breakpoint& bp) {
        return bp.id == id;
    });

    bool ok = id > 0 &&
        unresolvedId == -1 &&
        it != bps.end() &&
        it->address == method.nativeAddress &&
        it->method == BpMethod::Software &&
        it->hwRegister == -1 &&
        it->oneShot &&
        it->threadFilter == 77 &&
        it->condition == "rax == 10" &&
        it->description == "Game.Entities.Player::TakeDamage(int) [token 0x6000042]";

    printf("  JIT address bridge: %s\n", ok ? "OK" : "FAILED");
}

void test_kernel_symbol_resolver() {
    printf("\n── Test: Kernel symbol resolver ──\n");

    std::istringstream kallsyms(
        "0000000000000000 T hidden_by_kptr_restrict\n"
        "ffffffff81000000 T startup_64\n"
        "ffffffff81000120 t secondary_startup_64\n"
        "ffffffffc0201000 t module_entry [testmod]\n"
        "ffffffffc0201100 T exported_entry [testmod]\n");

    KernelSymbolResolver resolver;
    bool loaded = resolver.load(kallsyms);

    bool lookupOk = resolver.lookup("startup_64") == 0xffffffff81000000ULL &&
        resolver.lookup("kernel!startup_64") == 0xffffffff81000000ULL &&
        resolver.lookup("testmod!module_entry") == 0xffffffffc0201000ULL &&
        resolver.lookup("hidden_by_kptr_restrict") == 0;
    bool resolveOk = resolver.resolve(0xffffffff81000124ULL) == "kernel!secondary_startup_64+0x4" &&
        resolver.resolve(0xffffffffc0201100ULL) == "testmod!exported_entry";

    std::istringstream zeroSymbols("0000000000000000 T visible_zero\n");
    KernelSymbolResolver zeroResolver;
    bool zeroLoaded = zeroResolver.load(zeroSymbols, true);
    bool zeroOk = zeroLoaded && zeroResolver.count() == 1;

    printf("  kallsyms parse: %s\n",
        (loaded && resolver.count() == 4 && lookupOk && resolveOk && zeroOk) ? "OK" : "FAILED");
}

void test_kernel_driver_client() {
    printf("\n── Test: Kernel driver client ──\n");

    KernelDriverClient client;
    uint64_t value = 0;
    auto unopened = client.readProcessMemory(getpid(), reinterpret_cast<uintptr_t>(&value), &value, sizeof(value));
    auto unopenedPhysical = client.readPhysicalMemory(0x1000, &value, sizeof(value));
    auto unopenedTranslate = client.translateVirtualAddress(getpid(), reinterpret_cast<uintptr_t>(&value));

    bool ioctlOk = CECORE_KMOD_IOC_PING != 0 &&
        CECORE_KMOD_IOC_READ_PROCESS_VM != CECORE_KMOD_IOC_WRITE_PROCESS_VM &&
        CECORE_KMOD_IOC_READ_PHYSICAL != CECORE_KMOD_IOC_WRITE_PHYSICAL &&
        CECORE_KMOD_IOC_TRANSLATE_VA != CECORE_KMOD_IOC_READ_PHYSICAL &&
        std::string(CECORE_KMOD_PATH) == "/dev/cecore";
    bool unopenedOk = !unopened &&
        unopened.error() == std::make_error_code(std::errc::bad_file_descriptor) &&
        !unopenedPhysical &&
        unopenedPhysical.error() == std::make_error_code(std::errc::bad_file_descriptor) &&
        !unopenedTranslate &&
        unopenedTranslate.error() == std::make_error_code(std::errc::bad_file_descriptor);

    printf("  ioctl wrapper: %s\n", (ioctlOk && unopenedOk) ? "OK" : "FAILED");
}

void test_vulkan_overlay_injector() {
    printf("\n── Test: Vulkan overlay injector ──\n");

    auto tempDir = std::filesystem::temp_directory_path() / "cecore-vulkan-layer-test";
    auto layerPath = (tempDir / "libce_vulkan_overlay_layer.so").string();
    auto manifestPath = (tempDir / "VK_LAYER_CE_linux_overlay.json").string();
    std::filesystem::remove_all(tempDir);

    auto manifest = makeVulkanOverlayManifest(layerPath);
    std::string error;
    bool wrote = writeVulkanOverlayManifest(manifestPath, layerPath, error);
    auto env = buildVulkanOverlayEnvironment(tempDir.string(), layerPath, "VK_LAYER_EXISTING");

    std::ifstream file(manifestPath, std::ios::binary);
    std::string written((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    auto findEnv = [&](const std::string& name) {
        auto it = std::find_if(env.variables.begin(), env.variables.end(), [&](const auto& item) {
            return item.first == name;
        });
        return it == env.variables.end() ? std::string{} : it->second;
    };

    bool manifestOk = manifest.find("\"name\": \"VK_LAYER_CE_linux_overlay\"") != std::string::npos &&
        manifest.find("\"library_path\": \"" + layerPath + "\"") != std::string::npos &&
        written == manifest;
    bool envOk = env.layerName == "VK_LAYER_CE_linux_overlay" &&
        env.manifestPath == manifestPath &&
        findEnv("VK_LAYER_PATH") == tempDir.string() &&
        findEnv("VK_INSTANCE_LAYERS") == "VK_LAYER_EXISTING:VK_LAYER_CE_linux_overlay" &&
        findEnv("CE_VULKAN_OVERLAY") == "1";

    std::filesystem::remove_all(tempDir);
    printf("  manifest/env: %s\n",
        (wrote && error.empty() && manifestOk && envOk) ? "OK" : "FAILED");
}

#ifdef CE_HAVE_VULKAN
// Validates the built overlay layer's loader-facing contract by dlopen'ing the
// real .so and calling its interface directly: the loader-negotiation entry, the
// vkGetInstanceProcAddr resolution (hooked functions resolve, unknown ones give
// nullptr), and layer enumeration reporting our layer name. This exercises the
// error-prone part of Vulkan layer authoring deterministically, without a driver
// (creating a real VkInstance hangs the headless NVIDIA ICD, so it is avoided).
void test_vulkan_overlay_layer_interface() {
    printf("\n── Test: Vulkan overlay layer interface ──\n");

    void* h = dlopen(CE_VK_OVERLAY_LAYER_SO, RTLD_NOW | RTLD_LOCAL);
    if (!h) {
        printf("  layer interface: SKIPPED (dlopen: %s)\n", dlerror());
        return;
    }

    auto negotiate = reinterpret_cast<PFN_vkNegotiateLoaderLayerInterfaceVersion>(
        dlsym(h, "vkNegotiateLoaderLayerInterfaceVersion"));
    auto gipa = reinterpret_cast<PFN_vkGetInstanceProcAddr>(
        dlsym(h, "vkGetInstanceProcAddr"));
    auto eilp = reinterpret_cast<PFN_vkEnumerateInstanceLayerProperties>(
        dlsym(h, "vkEnumerateInstanceLayerProperties"));
    bool exportsOk = negotiate && gipa && eilp;

    bool negOk = false;
    if (negotiate) {
        VkNegotiateLayerInterface ni{};
        ni.sType = LAYER_NEGOTIATE_INTERFACE_STRUCT;
        ni.loaderLayerInterfaceVersion = 2;
        negOk = negotiate(&ni) == VK_SUCCESS &&
                ni.pfnGetInstanceProcAddr != nullptr &&
                ni.pfnGetDeviceProcAddr != nullptr;
    }

    bool procOk = false;
    if (gipa) {
        // Hooked entry points resolve; an unknown name must return nullptr.
        procOk = gipa(VK_NULL_HANDLE, "vkCreateInstance") != nullptr &&
                 gipa(VK_NULL_HANDLE, "vkGetInstanceProcAddr") != nullptr &&
                 gipa(VK_NULL_HANDLE, "vkEnumerateInstanceLayerProperties") != nullptr &&
                 gipa(VK_NULL_HANDLE, "vkNoSuchFunction_zzz") == nullptr;
    }

    bool enumOk = false;
    if (eilp) {
        uint32_t n = 0;
        enumOk = eilp(&n, nullptr) == VK_SUCCESS && n == 1;
        if (enumOk) {
            VkLayerProperties props{};
            uint32_t one = 1;
            enumOk = eilp(&one, &props) == VK_SUCCESS &&
                     std::string(props.layerName) == "VK_LAYER_CE_linux_overlay";
        }
    }

    dlclose(h);
    printf("  negotiate + proc resolution + enumeration: %s\n",
           (exportsOk && negOk && procOk && enumOk) ? "OK" : "FAILED");
}
#endif // CE_HAVE_VULKAN

void test_lua_file_aliases() {
    printf("\n── Test: Lua file aliases ──\n");

    auto path = std::filesystem::temp_directory_path() /
        ("cecore-lua-file-" + std::to_string(getpid()) + ".txt");

    LuaEngine lua;
    std::string script =
        "assert(writeFile([[" + path.string() + "]], 'hello'))\n"
        "assert(readFile([[" + path.string() + "]]) == 'hello')\n"
        "assert(getTempDir() ~= nil)\n"
        "assert(getCheatEngineDir() ~= nil)\n";

    auto err = lua.execute(script);
    std::filesystem::remove(path);

    printf("  readFile/writeFile: %s\n", err.empty() ? "OK" : "FAILED");
}

void test_lua_local_memory() {
    printf("\n── Test: Lua local memory ──\n");

    alignas(uintptr_t) uint8_t local[128] = {};
    auto base = reinterpret_cast<uintptr_t>(local);

    LuaEngine lua;
    std::string script =
        "local base = " + std::to_string(base) + "\n"
        "writeByteLocal(base, 0x2a)\n"
        "assert(readByteLocal(base) == 0x2a)\n"
        "writeSmallIntegerLocal(base + 2, -1234)\n"
        "assert(readSmallIntegerLocal(base + 2) == -1234)\n"
        "writeIntegerLocal(base + 8, 0x12345678)\n"
        "assert(readIntegerLocal(base + 8) == 0x12345678)\n"
        "writeQwordLocal(base + 16, 0x112233445566778)\n"
        "assert(readQwordLocal(base + 16) == 0x112233445566778)\n"
        "writePointerLocal(base + 24, base)\n"
        "assert(readPointerLocal(base + 24) == base)\n"
        "writeFloatLocal(base + 40, 3.5)\n"
        "assert(math.abs(readFloatLocal(base + 40) - 3.5) < 0.001)\n"
        "writeDoubleLocal(base + 48, 9.25)\n"
        "assert(math.abs(readDoubleLocal(base + 48) - 9.25) < 0.001)\n"
        "writeBytesLocal(base + 64, {1, 2, 3, 255})\n"
        "local bytes = readBytesLocal(base + 64, 4)\n"
        "assert(bytes[1] == 1 and bytes[2] == 2 and bytes[3] == 3 and bytes[4] == 255)\n"
        "writeStringLocal(base + 72, 'hello')\n"
        "assert(readStringLocal(base + 72, 16) == 'hello')\n";

    // write*Local is gated behind the untrusted-.CT opt-in; this test exercises
    // the legitimate use, so it opts in explicitly (see test_lua_localwrite_gate).
    setenv("CECORE_LUA_ALLOW_UNSAFE", "1", 1);
    auto err = lua.execute(script);
    setenv("CECORE_LUA_ALLOW_UNSAFE", "1", 1);   // the suite runs opted in

    printf("  read/write local variants: %s\n",
           err.empty() ? "OK" : ("FAILED (" + err + ")").c_str());
}

void test_lua_autoassemble_check() {
    printf("\n── Test: Lua autoAssembleCheck ──\n");

    LuaEngine lua;
    std::string script = R"lua(
local ok, msg = autoAssembleCheck([[
alloc(lua_check_block, 64)
lua_check_block:
db 90
]])
assert(ok == true and msg == nil)
)lua";

    auto err = lua.execute(script);

    printf("  autoAssembleCheck: %s\n", err.empty() ? "OK" : "FAILED");
}

void test_lua_utility_bindings() {
    printf("\n── Test: Lua utility bindings ──\n");

    LuaEngine lua;
    auto err = lua.execute(
        "showMessage('utility smoke test')\n"
        "assert(messageDialog('utility dialog', mtInformation, mbOK) == mrOK)\n"
        "local canvas = getScreenCanvas()\n"
        "assert(type(canvas) == 'table')\n"
        "assert(canvas.Width > 0 and canvas.Height > 0)\n"
        "assert(canvas.Pen.Color == 0xffffff)\n"
        "assert(canvas.Brush.Color == 0x000000)\n"
        "assert(canvas:TextOut(10, 20, 'hello'))\n"
        "assert(canvas:Line(0, 0, 10, 10))\n"
        "assert(canvas:getTextWidth('abcd') == 32)\n"
        "assert(canvas:getTextHeight('abcd') == 16)\n"
        "assert(canvas:getPixel(1, 1) == 0)\n"
        "assert(#canvas.commands == 2)\n");

    printf("  showMessage/messageDialog/getScreenCanvas: %s\n", err.empty() ? "OK" : "FAILED");
}

void test_lua_hotkey_bindings() {
    printf("\n── Test: Lua hotkey bindings ──\n");

    LuaEngine lua;
    auto err = lua.execute(
        "local hits = 0\n"
        "local hk = createHotkey(function() hits = hits + 1 end, VK_F1, VK_F2)\n"
        "local keys = hk:getKeys()\n"
        "assert(keys[1] == VK_F1 and keys[2] == VK_F2)\n"
        "assert(hk:trigger() == true and hits == 1)\n"
        "setHotkeyAction(hk, function() hits = hits + 10 end)\n"
        "assert(hk:doHotkey() == true and hits == 11)\n"
        "hk.Enabled = false\n"
        "assert(hk:trigger() == false and hits == 11)\n"
        "hk.Enabled = true\n"
        "assert(hk:trigger() == true and hits == 21)\n"
        "hk:destroy()\n"
        "assert(hk:trigger() == false and hits == 21)\n");

    printf("  createHotkey/setHotkeyAction: %s\n", err.empty() ? "OK" : "FAILED");
}

void test_lua_thread_bindings() {
    printf("\n── Test: Lua thread bindings ──\n");

    LuaEngine lua;
    auto err = lua.execute(
        "local hits = 0\n"
        "local t = createThread(function() hits = hits + 1 end)\n"
        "assert(type(t) == 'userdata')\n"
        "assert(t.Finished == true and t:waitfor() == true)\n"
        "t.Name = 'worker'\n"
        "assert(t.Name == 'worker')\n"
        "local s = createThread(function() hits = hits + 10 end, true)\n"
        "assert(s.Suspended == true and s.Finished == false)\n"
        "assert(s:resume() == true)\n"
        "assert(s.Finished == true)\n"
        "local value = synchronize(function() return 7 end)\n"
        "assert(value == 7)\n"
        "assert(queue(function() hits = hits + 100 end) == true)\n"
        "assert(hits == 111)\n"
        "local dead = createThread(function() hits = hits + 1000 end, true)\n"
        "assert(dead:terminate() == true and dead.Terminated == true)\n"
        "assert(dead:resume() == true and hits == 111)\n");

    printf("  createThread/synchronize/queue: %s\n", err.empty() ? "OK" : "FAILED");
    if (!err.empty())
        printf("    error: %s\n", err.c_str());
}

void test_lua_custom_type_bindings() {
    printf("\n── Test: Lua custom type bindings ──\n");

    LuaEngine lua;
    auto err = lua.execute(
        "assert(registerCustomTypeLua('u16x10', 2,\n"
        "  function(bytes)\n"
        "    local lo, hi = string.byte(bytes, 1, 2)\n"
        "    return (lo + hi * 256) * 10\n"
        "  end,\n"
        "  function(value)\n"
        "    local raw = math.floor(value / 10)\n"
        "    return string.char(raw % 256, math.floor(raw / 256) % 256)\n"
        "  end))\n"
        "assert(getCustomTypeSize('u16x10') == 2)\n"
        "assert(getCustomType('u16x10').Name == 'u16x10')\n"
        "assert(customTypeToValue('u16x10', string.char(0x34, 0x12)) == 0x1234 * 10)\n"
        "assert(customTypeToValue('u16x10', {0x34, 0x12}) == 0x1234 * 10)\n"
        "local bytes = customTypeToBytes('u16x10', 0x1234 * 10)\n"
        "assert(bytes[1] == 0x34 and bytes[2] == 0x12)\n"
        "assert(unregisterCustomType('u16x10'))\n"
        "assert(getCustomType('u16x10') == nil)\n");

    printf("  registerCustomTypeLua/customTypeToValue: %s\n", err.empty() ? "OK" : "FAILED");
    if (!err.empty())
        printf("    error: %s\n", err.c_str());
}

void test_lua_address_list_bindings() {
    printf("\n── Test: Lua address list bindings ──\n");

    LuaEngine lua;
    auto err = lua.execute(
        "addressList_clear()\n"
        "assert(addressList_getCount() == 0)\n"
        "local first = addressList_addEntry({Description='Health', Address='0x1000', Type='i32', Value='100', Active=false})\n"
        "assert(first == 0)\n"
        "assert(addressList_getCount() == 1)\n"
        "local entry = getTableEntry(0)\n"
        "assert(entry.Description == 'Health' and entry.Address == '0x1000')\n"
        "assert(setTableEntry(0, {Description='Mana', Address='0x2000', Type='float', Value='12.5', Active=true}))\n"
        "entry = getTableEntry(0)\n"
        "assert(entry.Description == 'Mana' and entry.Active == true)\n"
        "addressList_addEntry({Description='Ammo', Address='0x3000'})\n"
        "assert(addressList_getCount() == 2)\n"
        "assert(addressList_removeEntry(0) == true)\n"
        "assert(addressList_getCount() == 1)\n"
        "assert(getTableEntry(0).Description == 'Ammo')\n"
        "assert(addressList_removeEntry(99) == false)\n"
        "addressList_clear()\n"
        "assert(addressList_getCount() == 0)\n");

    printf("  getTableEntry/setTableEntry/addressList: %s\n", err.empty() ? "OK" : "FAILED");
}

void test_lua_debug_bindings() {
    printf("\n── Test: Lua debug bindings ──\n");

    LuaEngine lua;
    auto err = lua.execute(
        "assert(debug_isDebugging() == false)\n"
        "assert(debug_isBroken() == false)\n"
        "local id = debug_setBreakpoint(0x401000, bptExecute, 1)\n"
        "assert(type(id) == 'number' and id > 0)\n"
        "assert(debug_isDebugging() == true)\n"
        "local list = debug_getBreakpointList()\n"
        "assert(#list == 1)\n"
        "assert(list[1].id == id and list[1].address == 0x401000)\n"
        "assert(list[1].type == bptExecute and list[1].size == 1)\n"
        "assert(debug_continueFromBreakpoint() == true)\n"
        "assert(debug_removeBreakpoint(id) == true)\n"
        "assert(#debug_getBreakpointList() == 0)\n"
        "assert(debug_isDebugging() == false)\n");

    printf("  debug_set/remove/list/state: %s\n", err.empty() ? "OK" : "FAILED");
}

void test_lua_process_bindings(pid_t pid) {
    printf("\n── Test: Lua process bindings ──\n");

    LuaEngine lua;
    std::string pidText = std::to_string(pid);
    std::string script =
        "local pid = " + pidText + "\n"
        "local list = getProcessList()\n"
        "assert(type(list) == 'table')\n"
        "assert(type(list[pid]) == 'table')\n"
        "assert(list[pid].pid == pid)\n"
        "assert(type(getProcessIDFromProcessName('sleep')) == 'number')\n"
        "assert(openProcess(tostring(pid)) == pid)\n"
        "assert(getOpenedProcessID() == pid)\n"
        "assert(getProcessID() == pid)\n";

    auto err = lua.execute(script);

    printf("  openProcess/getProcessList: %s\n", err.empty() ? "OK" : "FAILED");
}

// enumerateFunctions / buildCallGraph Lua bindings over the live target's main
// module: they must return well-shaped tables (the underlying analysis is covered
// by test_code_analysis_references; this checks the binding path end to end).
void test_lua_code_analysis(pid_t pid) {
    printf("\n── Test: Lua code analysis bindings ──\n");
    LuaEngine lua;
    std::string script =
        "assert(openProcess(" + std::to_string(pid) + "))\n"
        "local fns = enumerateFunctions()\n"
        "assert(type(fns) == 'table', 'enumerateFunctions not a table')\n"
        "local cg = buildCallGraph()\n"
        "assert(type(cg) == 'table', 'buildCallGraph not a table')\n"
        "if #fns > 0 then assert(type(fns[1].address) == 'number', 'bad function entry') end\n"
        "if #cg > 0 then assert(cg[1].caller and cg[1].callee and cg[1].callSite, 'bad edge') end\n"
        "if #fns > 0 then\n"
        "  local d = disassembleRange(fns[1].address, 4)\n"
        "  assert(type(d) == 'table', 'disassembleRange not a table')\n"
        "  if #d > 0 then assert(type(d[1].address) == 'number' and type(d[1].text) == 'string', 'bad insn') end\n"
        "end\n"
        "local strs = findReferencedStrings()\n"
        "assert(type(strs) == 'table', 'findReferencedStrings not a table')\n"
        "if #strs > 0 then assert(type(strs[1].address)=='number' and type(strs[1].text)=='string', 'bad string ref') end\n"
        "local statics = findStatics()\n"
        "assert(type(statics) == 'table', 'findStatics not a table')\n"
        "if #statics > 1 then assert(statics[1].references >= statics[2].references, 'statics not sorted by refs') end\n"
        "local caves = findCodeCaves(nil, 32)\n"
        "assert(type(caves) == 'table', 'findCodeCaves not a table')\n"
        "if #caves > 0 then assert(caves[1].size >= 32, 'cave shorter than minSize') end\n"
        "local hits = findAssemblyPattern('ret')\n"
        "assert(type(hits) == 'table', 'findAssemblyPattern not a table')\n"
        "if #hits > 0 then assert(type(hits[1].address)=='number' and type(hits[1].text)=='string', 'bad asm hit') end\n";
    auto err = lua.execute(script);
    printf("  enumerateFunctions + buildCallGraph return shaped tables: %s\n",
           err.empty() ? "OK" : ("FAILED: " + err).c_str());
    printf("  findReferencedStrings + findStatics + findCodeCaves shaped: %s\n",
           err.empty() ? "OK" : ("FAILED: " + err).c_str());
}

// The shipped example scripts (examples/*.lua) double as an API-drift guard.
// Each one guards the no-target case and returns cleanly, so running it with no
// process attached must succeed: a Lua syntax slip or a renamed/removed binding
// it names would surface here as a non-empty error. Keeps the docs honest.
void test_example_scripts() {
    printf("\n── Test: shipped example scripts load & run ──\n");
#ifdef CE_SOURCE_DIR
    const char* names[] = {
        "il2cpp_dump.lua", "il2cpp_hook.lua",
        "reverse_engineer.lua", "native_struct.lua",
    };
    for (const char* n : names) {
        std::string path = std::string(CE_SOURCE_DIR) + "/examples/" + n;
        LuaEngine lua;
        auto err = lua.executeFile(path);
        printf("  %-22s %s\n", n, err.empty() ? "OK" : ("FAILED: " + err).c_str());
    }
#else
    printf("  (skipped: CE_SOURCE_DIR not defined)\n");
#endif
}

// executeCode Lua binding: allocate a stub that writes a sentinel and returns,
// then run it on a new thread in the target via executeCode and confirm the
// sentinel landed (i.e. the target actually executed our code).
void test_lua_executecode() {
    printf("\n── Test: Lua executeCode ──\n");
    NativeCallRegressionFixture fixture;
    if (fixture.pid<=0) { printf("  native call fixture: FAILED\n"); return; }
    LinuxProcessHandle proc(fixture.pid);
    AutoAssembler aa;
    auto res = aa.execute(proc,
        "[ENABLE]\n"
        "alloc(execcode, 512)\n"
        "alloc(execresult, 8)\n"
        "registersymbol(execresult)\n"
        "registersymbol(execcode)\n"
        "execresult:\n"
        "dd 0\n"
        "execcode:\n"
        "mov rax, execresult\n"
        "mov dword [rax], 0x0BADF00D\n"
        "xor eax, eax\n"
        "ret\n");
    auto codeAddr = aa.resolveSymbol("execcode");
    auto resultAddr = aa.resolveSymbol("execresult");
    if (!res.success || !codeAddr || !resultAddr) {
        printf("  setup (alloc code): FAILED\n");
        return;
    }

    LuaEngine lua;
    std::string script =
        "assert(openProcess(" + std::to_string(fixture.pid) + "))\n"
        "local ok, err = executeCode(" + std::to_string((uintptr_t)codeAddr) + ", 3000)\n"
        "return ok and 'ok' or ('bad:' .. tostring(err))\n";
    auto r = lua.evalToString(script);
    uint32_t val = 0;
    proc.read(resultAddr, &val, sizeof(val));
    bool ok = r.has_value() && *r == "ok" && val == 0x0BADF00Du;
    printf("  executeCode runs target code (sentinel written): %s (lua=%s val=0x%X)\n",
           ok ? "OK" : "FAILED", r ? r->c_str() : "nil", val);
}

void test_lua_memscan() {
    printf("\n── Test: Lua memscan bindings ──\n");

    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("  firstScan/nextScan: FAILED\n");
        return;
    }

    auto* target = reinterpret_cast<int32_t*>(page);
    *target = 1111;
    auto base = reinterpret_cast<uintptr_t>(page);

    LinuxProcessHandle proc(getpid());
    LuaEngine lua;
    lua.setProcess(&proc);

    std::string script =
        "local base = " + std::to_string(base) + "\n"
        "local stop = base + " + std::to_string(pageSize) + "\n"
        "local ms = createMemScan()\n"
        "assert(ms:firstScan(" + std::to_string((int)ScanCompare::Exact) + ", " +
            std::to_string((int)ValueType::Int32) + ", '1111', base, stop, 4))\n"
        "assert(ms:getFoundCount() == 1)\n"
        "assert(ms:getAddress(0) == base)\n"
        "writeIntegerLocal(base, 2222)\n"
        "assert(ms:nextScan(" + std::to_string((int)ScanCompare::Exact) + ", " +
            std::to_string((int)ValueType::Int32) + ", '2222', base, stop, 4))\n"
        "assert(ms:getFoundCount() == 1)\n"
        "assert(ms:getAddress(0) == base)\n";

    // The script uses writeIntegerLocal to change the scan target between scans,
    // which is now gated; opt in for this incidental use.
    setenv("CECORE_LUA_ALLOW_UNSAFE", "1", 1);
    auto err = lua.execute(script);
    setenv("CECORE_LUA_ALLOW_UNSAFE", "1", 1);   // the suite runs opted in
    munmap(page, pageSize);

    printf("  firstScan/nextScan: %s\n",
           err.empty() ? "OK" : ("FAILED (" + err + ")").c_str());
}

void test_binary_scan_bitmask() {
    printf("\n── Test: Binary scan bitmask ──\n");

    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("  bit wildcard match: FAILED\n");
        return;
    }

    auto* bytes = reinterpret_cast<uint8_t*>(page);
    bytes[16] = 0xAC;
    bytes[17] = 0x5A;
    bytes[32] = 0xBC;
    bytes[33] = 0x5A;
    bytes[48] = 0xAC;
    bytes[49] = 0x5B;

    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner;
    ScanConfig config;
    config.valueType = ValueType::Binary;
    config.compareType = ScanCompare::Exact;
    config.parseBinary("1010???? 01011010");
    config.alignment = 1;
    config.startAddress = reinterpret_cast<uintptr_t>(page);
    config.stopAddress = config.startAddress + pageSize;

    auto result = scanner.firstScan(proc, config);
    bool ok = result.count() == 1 && result.address(0) == config.startAddress + 16;

    munmap(page, pageSize);

    printf("  bit wildcard match: %s\n", ok ? "OK" : "FAILED");
}

// AOB nibble-wildcard scan match: a pattern like "48 8B 4? 05" must match a byte whose
// high nibble is 4 (4A) and reject one whose high nibble is 5 (5A). parseAOB is already
// tested for validity; this locks the actual masked matching in the scan.
void test_aob_nibble_wildcard() {
    printf("\n── Test: AOB nibble-wildcard scan match ──\n");
    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { printf("  setup: FAILED (mmap)\n"); return; }
    auto* b = static_cast<uint8_t*>(page);
    b[100] = 0x48; b[101] = 0x8B; b[102] = 0x4A; b[103] = 0x05;   // 3rd byte high nibble = 4 (match)
    b[200] = 0x48; b[201] = 0x8B; b[202] = 0x5A; b[203] = 0x05;   // 3rd byte high nibble = 5 (miss)

    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner;
    ScanConfig c;
    c.valueType = ValueType::ByteArray;
    c.compareType = ScanCompare::Exact;
    c.parseAOB("48 8B 4? 05");
    c.alignment = 1;
    c.startAddress = reinterpret_cast<uintptr_t>(page);
    c.stopAddress = c.startAddress + pageSize;
    auto r = scanner.firstScan(proc, c);
    bool has100 = false, has200 = false;
    for (size_t i = 0; i < r.count(); ++i) {
        if (r.address(i) == c.startAddress + 100) has100 = true;
        if (r.address(i) == c.startAddress + 200) has200 = true;
    }
    munmap(page, pageSize);
    bool ok = has100 && !has200;
    printf("  '48 8B 4? 05' matches 4A, rejects 5A: %s (100=%d 200=%d)\n",
           ok ? "OK" : "FAILED", (int)has100, (int)has200);

    // Compact (space-less) hex must split into bytes; it used to be accepted as
    // one all-hex token and truncated via strtoul to the last byte only.
    ScanConfig cc;
    bool compactOk = cc.parseAOB("488B05") && cc.byteArray.size() == 3 &&
                     cc.byteArray[0] == 0x48 && cc.byteArray[1] == 0x8B && cc.byteArray[2] == 0x05;
    ScanConfig odd;
    bool oddRejected = !odd.parseAOB("488B0");   // odd digit count is invalid
    printf("  compact AOB '488B05' -> 3 bytes, odd count rejected: %s\n",
           (compactOk && oddRejected) ? "OK" : "FAILED");
}

// A value that matches at several widths (a 4-byte 42 also matches as int8/int16)
// must still yield ONE address row: every All hit stores the same 8-byte window.
void test_all_types_no_duplicate_addresses() {
    printf("\n── Test: All-types scan emits one row per address ──\n");
    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { printf("  setup: FAILED (mmap)\n"); return; }
    auto* b = static_cast<uint8_t*>(page);
    const int32_t v = 42;
    std::memcpy(b + 64, &v, 4);

    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner;
    ScanConfig c;
    c.valueType = ValueType::All;
    c.compareType = ScanCompare::Exact;
    c.intValue = 42;
    c.alignment = 1;
    c.startAddress = reinterpret_cast<uintptr_t>(page);
    c.stopAddress = c.startAddress + pageSize;
    auto r = scanner.firstScan(proc, c);

    std::vector<uintptr_t> addrs;
    for (size_t i = 0; i < r.count(); ++i) addrs.push_back(r.address(i));
    std::sort(addrs.begin(), addrs.end());
    bool dup = std::adjacent_find(addrs.begin(), addrs.end()) != addrs.end();
    size_t at64 = 0;
    for (uintptr_t a : addrs) if (a == c.startAddress + 64) ++at64;
    munmap(page, pageSize);
    bool ok = !dup && at64 == 1;
    printf("  one row at the planted address, no duplicates: %s (total=%zu at64=%zu)\n",
           ok ? "OK" : "FAILED", addrs.size(), at64);
}

// Tri-state Writable region filter (CE's grey/checked/unchecked box). Place the
// same sentinel in a writable (rw-p) page and a read-only (r--p) page, then scan
// with each ProtMatch and confirm the region selection: Yes -> only the writable
// page, No -> only the read-only page, Any -> both.
void test_protection_filter_scan() {
    printf("\n── Test: tri-state writable region filter ──\n");
    const size_t pageSize = 4096;
    void* wpage = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void* rpage = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (wpage == MAP_FAILED || rpage == MAP_FAILED) { printf("  setup: FAILED (mmap)\n"); return; }
    const int32_t sentinel = 0x51DE571;
    std::memcpy(wpage, &sentinel, 4);
    std::memcpy(rpage, &sentinel, 4);
    if (mprotect(rpage, pageSize, PROT_READ) != 0) { printf("  setup: FAILED (mprotect)\n"); return; }

    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner;
    const uintptr_t lo = std::min((uintptr_t)wpage, (uintptr_t)rpage);
    const uintptr_t hi = std::max((uintptr_t)wpage, (uintptr_t)rpage) + pageSize;
    auto scanFor = [&](ce::ProtMatch wf) {
        ScanConfig c;
        c.valueType = ValueType::Int32;
        c.compareType = ScanCompare::Exact;
        c.intValue = sentinel;
        c.alignment = 1;
        c.writableMatch = wf;
        c.startAddress = lo;
        c.stopAddress = hi;
        auto r = scanner.firstScan(proc, c);
        bool hitW = false, hitR = false;
        for (size_t i = 0; i < r.count(); ++i) {
            if (r.address(i) == (uintptr_t)wpage) hitW = true;
            if (r.address(i) == (uintptr_t)rpage) hitR = true;
        }
        return std::make_pair(hitW, hitR);
    };
    auto yes = scanFor(ce::ProtMatch::Yes);
    auto no  = scanFor(ce::ProtMatch::No);
    auto any = scanFor(ce::ProtMatch::Any);
    munmap(wpage, pageSize);
    munmap(rpage, pageSize);

    bool ok = yes.first && !yes.second      // Yes: writable page only
           && !no.first && no.second        // No:  read-only page only
           && any.first && any.second;      // Any: both
    printf("  Writable Yes/No/Any select the right regions: %s (yes=%d%d no=%d%d any=%d%d)\n",
           ok ? "OK" : "FAILED", yes.first, yes.second, no.first, no.second, any.first, any.second);
}

// MEM_PRIVATE / MEM_IMAGE / MEM_MAPPED region-type filter (CE's "Memory Scan
// Options"). The same sentinel sits in three regions of distinct type; turning a
// filter off must drop exactly that region's hit and keep the other two. This drives
// ScanConfig::scan{Private,Image,Mapped}, which the scan panel's Private/Image/Mapped
// checkboxes set.
void test_memtype_filter_scan() {
    printf("\n── Test: MEM type region filter ──\n");
    const int32_t sentinel = 0x5EED1234;
    std::vector<uint8_t> data(8, 0);
    std::memcpy(data.data(), &sentinel, 4);
    const uintptr_t imgBase = 0x400000, privBase = 0x800000, mapBase = 0xC00000;
    FakeProcessHandle proc({
        {{imgBase,  data.size(), MemProt::ReadWrite, MemType::Image,   MemState::Committed, "/tmp/game"},     data},
        {{privBase, data.size(), MemProt::ReadWrite, MemType::Private, MemState::Committed, "[heap]"},        data},
        {{mapBase,  data.size(), MemProt::ReadWrite, MemType::Mapped,  MemState::Committed, "/tmp/save.dat"}, data},
    }, {});
    MemoryScanner scanner;
    auto scanWith = [&](bool priv, bool img, bool mapd, bool& hi, bool& hp, bool& hm) {
        ScanConfig c;
        c.valueType = ValueType::Int32;
        c.compareType = ScanCompare::Exact;
        c.intValue = sentinel;
        c.alignment = 4;
        c.startAddress = imgBase;
        c.stopAddress = mapBase + data.size();
        c.scanPrivate = priv; c.scanImage = img; c.scanMapped = mapd;
        auto r = scanner.firstScan(proc, c);
        hi = hp = hm = false;
        for (size_t i = 0; i < r.count(); ++i) {
            if (r.address(i) == imgBase)  hi = true;
            if (r.address(i) == privBase) hp = true;
            if (r.address(i) == mapBase)  hm = true;
        }
    };
    bool ai, ap, am;         scanWith(true,  true,  true,  ai, ap, am);
    bool xi_i, xi_p, xi_m;   scanWith(true,  false, true,  xi_i, xi_p, xi_m);  // no Image
    bool xp_i, xp_p, xp_m;   scanWith(false, true,  true,  xp_i, xp_p, xp_m);  // no Private
    bool xm_i, xm_p, xm_m;   scanWith(true,  true,  false, xm_i, xm_p, xm_m);  // no Mapped
    bool ok =
        ai && ap && am &&                       // all three found when all filters on
        !xi_i && xi_p && xi_m &&                // Image off -> only Image dropped
        xp_i && !xp_p && xp_m &&                // Private off -> only Private dropped
        xm_i && xm_p && !xm_m;                  // Mapped off -> only Mapped dropped
    printf("  Private/Image/Mapped filters select the right regions: %s (all=%d%d%d noImg=%d%d%d noPriv=%d%d%d noMap=%d%d%d)\n",
           ok ? "OK" : "FAILED", ai, ap, am, xi_i, xi_p, xi_m, xp_i, xp_p, xp_m, xm_i, xm_p, xm_m);
}

// moduleOffsetString: map an absolute address to "basename+0xoffset" using a
// module list. Deterministic, no process needed.
void test_module_offset_string() {
    printf("\n── Test: module+offset address formatting ──\n");
    std::vector<ce::ModuleInfo> mods = {
        {0x400000, 0x10000, "game.bin",  "/opt/game/game.bin",  true},
        {0x7f0000, 0x2000,  "libc.so.6", "/usr/lib/libc.so.6",  true},
    };
    bool ok =
        ce::moduleOffsetString(mods, 0x401234) == "game.bin+0x1234" &&
        ce::moduleOffsetString(mods, 0x400000) == "game.bin+0x0" &&
        ce::moduleOffsetString(mods, 0x7f0010) == "libc.so.6+0x10" &&
        ce::moduleOffsetString(mods, 0x300000).empty() &&    // below all modules
        ce::moduleOffsetString(mods, 0x410000).empty();      // one past game.bin's end
    // Falls back to the path's basename when `name` is empty.
    std::vector<ce::ModuleInfo> mods2 = {{0x1000, 0x100, "", "/a/b/mod.so", true}};
    ok = ok && ce::moduleOffsetString(mods2, 0x1050) == "mod.so+0x50";
    // Nested mappings: the smallest containing module wins.
    std::vector<ce::ModuleInfo> mods3 = {
        {0x1000, 0x1000, "outer", "", true},
        {0x1200, 0x0100, "inner", "", true},
    };
    ok = ok && ce::moduleOffsetString(mods3, 0x1250) == "inner+0x50";
    // Round-trip: the produced "module+offset" must resolve back to the original
    // address via the ExpressionParser. This is the invariant the "Convert to
    // module+offset" record action relies on (a static address stays durable only if
    // its module-relative form re-resolves next launch).
    FakeProcessHandle rtProc({}, mods);
    ce::ExpressionParser rtParser(&rtProc, nullptr);
    auto rt1 = rtParser.parse(ce::moduleOffsetString(mods, 0x401234));
    auto rt2 = rtParser.parse(ce::moduleOffsetString(mods, 0x7f0010));
    bool rtOk = rt1 && *rt1 == 0x401234 && rt2 && *rt2 == 0x7f0010;
    ok = ok && rtOk;
    printf("  moduleOffsetString maps addresses to module+offset (round-trip=%d): %s\n",
           rtOk, ok ? "OK" : "FAILED");
}

void test_between_numeric_scan() {
    printf("\n── Test: Value-between numeric scan ──\n");

    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { printf("  between [lo,hi] int32: FAILED\n"); return; }

    auto* bytes = reinterpret_cast<uint8_t*>(page);
    int32_t vals[4] = {50, 150, 250, 100};       // at offsets 0,16,32,48
    std::memcpy(bytes + 0,  &vals[0], 4);
    std::memcpy(bytes + 16, &vals[1], 4);
    std::memcpy(bytes + 32, &vals[2], 4);
    std::memcpy(bytes + 48, &vals[3], 4);

    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner;
    ScanConfig config;
    config.valueType = ValueType::Int32;
    config.compareType = ScanCompare::Between;
    config.intValue = 100;                        // lower bound
    config.intValue2 = 200;                       // upper bound (the GUI's 2nd box)
    config.alignment = 4;
    config.startAddress = reinterpret_cast<uintptr_t>(page);
    config.stopAddress = config.startAddress + pageSize;

    auto result = scanner.firstScan(proc, config);
    // Only 150 (offset 16) and 100 (offset 48) fall in [100,200]; the rest of
    // the page is zero-filled and out of range.
    bool ok = result.count() == 2 &&
              result.address(0) == config.startAddress + 16 &&
              result.address(1) == config.startAddress + 48;

    munmap(page, pageSize);

    printf("  between [lo,hi] int32: %s\n", ok ? "OK" : "FAILED");
}

void test_nextscan_size_guard() {
    printf("\n── Test: Next-scan size-mismatch guard ──\n");

    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { printf("  reject changed string length: FAILED\n"); return; }
    std::memcpy(page, "ab", 2);

    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner;
    ScanConfig first;
    first.valueType = ValueType::String;
    first.compareType = ScanCompare::Exact;
    first.stringValue = "ab";
    first.alignment = 1;
    first.startAddress = reinterpret_cast<uintptr_t>(page);
    first.stopAddress = first.startAddress + pageSize;
    auto result = scanner.firstScan(proc, first);

    // A next scan with a different search length would desync the persisted
    // value streams; it must be rejected (throw), not silently mispaired.
    // Regression: firstScan returns a merged result whose in-memory valueSize
    // is 0, so the guard must derive the stride from values.bin, not valueSize().
    ScanConfig second = first;
    second.stringValue = "abcd";   // length 4 vs stored 2
    bool rejected = false;
    try {
        auto r2 = scanner.nextScan(proc, second, result);
        (void)r2;
    } catch (const std::exception&) {
        rejected = true;
    }

    munmap(page, pageSize);
    bool ok = result.count() >= 1 && rejected;
    printf("  reject changed string length: %s\n", ok ? "OK" : "FAILED");
}

void test_prune_scan_result() {
    printf("\n── Test: Prune scan result (remove selected addresses) ──\n");
    auto dir = std::filesystem::temp_directory_path() / ("ce_prune_" + std::to_string(getpid()));
    std::filesystem::remove_all(dir);
    ce::ScanResult src(dir / "src", /*storeFirst=*/true);
    const uintptr_t addrs[] = {0x1000, 0x2000, 0x3000, 0x4000};
    const int32_t   vals[]  = {10, 20, 30, 40};   // current values
    const int32_t   fvals[] = {1, 2, 3, 4};       // first-scan values
    for (int i = 0; i < 4; ++i)
        src.addResult(addrs[i], &vals[i], &fvals[i], sizeof(int32_t));
    src.finalize();

    // Remove rows 1 and 3 (0x2000, 0x4000); keep 0x1000, 0x3000.
    std::vector<bool> mask = {false, true, false, true};
    auto pruned = ce::pruneScanResult(src, sizeof(int32_t), mask);

    bool countOk = pruned->count() == 2;
    bool addrOk = countOk && pruned->address(0) == 0x1000 && pruned->address(1) == 0x3000;
    int32_t v0 = 0, v1 = 0, f0 = 0, f1 = 0;
    if (countOk) {
        pruned->value(0, &v0, sizeof(int32_t));
        pruned->value(1, &v1, sizeof(int32_t));
        pruned->firstValue(0, &f0, sizeof(int32_t));
        pruned->firstValue(1, &f1, sizeof(int32_t));
    }
    bool valOk = v0 == 10 && v1 == 30;      // current values carried across
    bool firstOk = f0 == 1 && f1 == 3;      // first-scan values preserved for later narrowing
    // An empty mask keeps every row (indices past mask.size() are kept).
    auto keepAll = ce::pruneScanResult(src, sizeof(int32_t), {});
    bool keepOk = keepAll->count() == 4;

    std::filesystem::remove_all(dir);
    bool ok = countOk && addrOk && valOk && firstOk && keepOk;
    printf("  prune keeps survivors + values + firstValues (c=%d a=%d v=%d f=%d keep=%d): %s\n",
           countOk, addrOk, valOk, firstOk, keepOk, ok ? "OK" : "FAILED");
}

// decodeStringBytes: interpret code-page bytes as UTF-8 for display (inverse of
// encodeStringBytes). CP1252 0xE9 is 'é' (U+00E9) = UTF-8 C3 A9. Fixes scan-result
// mojibake for non-ASCII string scans; the primitive the record code page will reuse.
void test_decode_string_bytes() {
    printf("\n── Test: decodeStringBytes (code page -> UTF-8) ──\n");
    const uint8_t cp1252[] = {'c', 'a', 'f', 0xE9};                 // "café" in CP1252
    bool decOk = ce::decodeStringBytes(cp1252, sizeof(cp1252), "CP1252") == "caf\xC3\xA9";
    // Round-trip against encodeStringBytes: UTF-8 -> CP1252 -> UTF-8.
    auto enc = ce::encodeStringBytes("caf\xC3\xA9", "CP1252");
    bool encOk = enc.size() == 4 && enc[3] == 0xE9;
    bool rtOk = ce::decodeStringBytes(enc.data(), enc.size(), "CP1252") == "caf\xC3\xA9";
    // A UTF-8 (or empty) encoding returns the bytes verbatim.
    const uint8_t raw[] = {'h', 'i', 0xC3, 0xA9};
    bool passOk = ce::decodeStringBytes(raw, sizeof(raw), "UTF-8") == std::string("hi\xC3\xA9") &&
                  ce::decodeStringBytes(raw, sizeof(raw), "")      == std::string("hi\xC3\xA9");
    bool ok = decOk && encOk && rtOk && passOk;
    printf("  decodeStringBytes (dec=%d enc=%d roundtrip=%d passthru=%d): %s\n",
           decOk, encOk, rtOk, passOk, ok ? "OK" : "FAILED");
}

void test_unicode_string_scan() {
    printf("\n── Test: Unicode string scan ──\n");

    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("  UTF-16LE match: FAILED\n");
        return;
    }

    auto* bytes = reinterpret_cast<uint8_t*>(page);
    bytes[24] = 'H';
    bytes[25] = 0;
    bytes[26] = 'i';
    bytes[27] = 0;
    bytes[80] = 'H';
    bytes[81] = 'i';

    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner;
    ScanConfig config;
    config.valueType = ValueType::UnicodeString;
    config.compareType = ScanCompare::Exact;
    config.stringValue = "Hi";
    config.alignment = 1;
    config.startAddress = reinterpret_cast<uintptr_t>(page);
    config.stopAddress = config.startAddress + pageSize;

    auto result = scanner.firstScan(proc, config);
    bool ok = result.count() == 1 && result.address(0) == config.startAddress + 24;

    munmap(page, pageSize);

    printf("  UTF-16LE match: %s\n", ok ? "OK" : "FAILED");
}

void test_codepage_string_scan() {
    printf("\n── Test: Codepage string scan ──\n");

    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("  ISO-8859-1 match: FAILED\n");
        return;
    }

    auto base = reinterpret_cast<uintptr_t>(page);
    auto* bytes = reinterpret_cast<uint8_t*>(page);
    std::memset(bytes, 0, pageSize);
    bytes[32] = 0xe9; // U+00E9 encoded as ISO-8859-1.

    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner;

    ScanConfig config;
    config.valueType = ValueType::String;
    config.compareType = ScanCompare::Exact;
    config.stringValue = "\xc3\xa9"; // U+00E9 in UTF-8 source text.
    config.stringEncoding = "ISO-8859-1";
    config.alignment = 1;
    config.startAddress = base;
    config.stopAddress = base + pageSize;

    auto result = scanner.firstScan(proc, config);
    bool ok = result.count() == 1 && result.address(0) == base + 32;

    ScanConfig next = config;
    auto nextResult = scanner.nextScan(proc, next, result);
    ok = ok && nextResult.count() == 1 && nextResult.address(0) == base + 32;

    munmap(page, pageSize);

    printf("  ISO-8859-1 match: %s\n", ok ? "OK" : "FAILED");
}

void test_all_types_scan() {
    printf("\n── Test: All types scan ──\n");

    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("  vtAll numeric match: FAILED\n");
        return;
    }

    std::memset(page, 0x7f, pageSize);
    auto base = reinterpret_cast<uintptr_t>(page);
    auto* bytes = reinterpret_cast<uint8_t*>(page);
    uint8_t byteValue = 42;
    int16_t wordValue = 42;
    int32_t dwordValue = 42;
    int64_t qwordValue = 42;
    float floatValue = 42.0f;
    double doubleValue = 42.0;
    std::memcpy(bytes + 16, &byteValue, sizeof(byteValue));
    std::memcpy(bytes + 32, &wordValue, sizeof(wordValue));
    std::memcpy(bytes + 48, &dwordValue, sizeof(dwordValue));
    std::memcpy(bytes + 64, &qwordValue, sizeof(qwordValue));
    std::memcpy(bytes + 80, &floatValue, sizeof(floatValue));
    std::memcpy(bytes + 96, &doubleValue, sizeof(doubleValue));

    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner;
    ScanConfig config;
    config.valueType = ValueType::All;
    config.compareType = ScanCompare::Exact;
    config.intValue = 42;
    config.floatValue = 42.0;
    config.alignment = 1;
    config.startAddress = base;
    config.stopAddress = base + pageSize;

    auto result = scanner.firstScan(proc, config);
    auto hasAddress = [&result](uintptr_t address) {
        for (size_t i = 0; i < result.count(); ++i)
            if (result.address(i) == address)
                return true;
        return false;
    };
    bool ok = hasAddress(base + 16) && hasAddress(base + 32) &&
        hasAddress(base + 48) && hasAddress(base + 64) &&
        hasAddress(base + 80) && hasAddress(base + 96);

    // Regression: value(i) must stay in lockstep with address(i). Records are a
    // uniform 8-byte window, so value(i) read at i*8 must equal the memory at
    // address(i). Before the fix, variable-width records desynced the streams.
    bool valuesAligned = result.count() > 0;
    for (size_t i = 0; i < result.count() && valuesAligned; ++i) {
        uint8_t vbuf[8] = {0}, mbuf[8] = {0};
        result.value(i, vbuf, 8);
        std::memcpy(mbuf, reinterpret_cast<void*>(result.address(i)), 8);
        if (std::memcmp(vbuf, mbuf, 8) != 0) valuesAligned = false;
    }
    // Regression: a nextScan on an All result must not throw its stride guard.
    bool nextOk = false;
    try {
        auto narrowed = scanner.nextScan(proc, config, result);
        nextOk = narrowed.count() == result.count();  // Exact 42 unchanged
    } catch (...) { nextOk = false; }

    // A 2-byte field above the signed maximum: 40000 is 0x9C40, which a signed
    // 16-bit reading sees as -25536.
    const uint16_t unsignedWord = 40000;
    std::memcpy(bytes + 128, &unsignedWord, sizeof(unsignedWord));
    config.intValue = 40000;
    config.floatValue = 40000.0;
    auto wide = scanner.firstScan(proc, config);
    bool unsignedOk = false;
    for (size_t i = 0; i < wide.count(); ++i) if (wide.address(i) == base + 128) unsignedOk = true;

    munmap(page, pageSize);

    printf("  vtAll exact matches a 2-byte value above the signed maximum: %s\n", unsignedOk ? "OK" : "FAILED");
    printf("  vtAll numeric match: %s\n", ok ? "OK" : "FAILED");
    printf("  vtAll value(i) stays in lockstep with address(i): %s\n", valuesAligned ? "OK" : "FAILED");
    printf("  vtAll nextScan does not throw: %s\n", nextOk ? "OK" : "FAILED");
}

void test_grouped_scan() {
    printf("\n── Test: Grouped scan ──\n");

    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("  grouped first/next: FAILED\n");
        return;
    }

    std::memset(page, 0x7f, pageSize);
    auto base = reinterpret_cast<uintptr_t>(page);
    auto* bytes = reinterpret_cast<uint8_t*>(page);

    int32_t i32Value = 1337;
    float floatValue = 2.5f;
    uint8_t byteValue = 66;
    std::memcpy(bytes + 128, &i32Value, sizeof(i32Value));
    std::memcpy(bytes + 132, &floatValue, sizeof(floatValue));
    std::memcpy(bytes + 136, &byteValue, sizeof(byteValue));

    uint8_t nearMiss = 65;
    std::memcpy(bytes + 256, &i32Value, sizeof(i32Value));
    std::memcpy(bytes + 260, &floatValue, sizeof(floatValue));
    std::memcpy(bytes + 264, &nearMiss, sizeof(nearMiss));

    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner;

    ScanConfig grouped;
    grouped.valueType = ValueType::Grouped;
    grouped.compareType = ScanCompare::Exact;
    grouped.alignment = 1;
    grouped.startAddress = base;
    grouped.stopAddress = base + pageSize;
    std::string groupedError;
    bool parsed = grouped.parseGrouped("i32:1337@0;float:2.5@4;byte:66@8", &groupedError);

    // A leading '+' on a float value must parse like integers do ("+100"): from_chars
    // rejects '+', so parseDoubleToken skips it. "+2.5" must parse the same as "2.5".
    ScanConfig plusGrouped;
    std::string plusErr;
    bool plusOk = plusGrouped.parseGrouped("float:+2.5@0", &plusErr) &&
                  plusGrouped.groupedTerms.size() == 1 &&
                  plusGrouped.groupedTerms[0].floatValue == 2.5f;
    printf("  grouped float accepts leading '+': %s\n", plusOk ? "OK" : "FAILED");
    // parseAOB validity: valid patterns (hex + wildcards) return true; a token
    // with a non-hex, non-wildcard char (a typo like "8Z") returns false so callers
    // can reject it instead of silently scanning a wrong pattern.
    ScanConfig aobV; ScanConfig aobBad; ScanConfig aobEmpty;
    bool aobValidOk = aobV.parseAOB("48 8B ?? 05 4?") &&
                      !aobBad.parseAOB("48 8Z 05") &&
                      !aobEmpty.parseAOB("   ");
    printf("  AOB parseAOB rejects invalid tokens: %s\n", aobValidOk ? "OK" : "FAILED");

    bool ok = parsed;
    auto first = parsed ? scanner.firstScan(proc, grouped) : ScanResult{};
    ok = ok && first.count() == 1 && first.address(0) == base + 128;

    byteValue = 67;
    std::memcpy(bytes + 136, &byteValue, sizeof(byteValue));

    ScanConfig changed = grouped;
    changed.compareType = ScanCompare::Changed;
    auto changedResult = parsed ? scanner.nextScan(proc, changed, first) : ScanResult{};
    ok = ok && changedResult.count() == 1 && changedResult.address(0) == base + 128;

    uint8_t firstBlock[9] = {};
    if (changedResult.count() > 0)
        changedResult.firstValue(0, firstBlock, sizeof(firstBlock));
    ok = ok && firstBlock[8] == 66;

    ScanConfig groupedUpdated = grouped;
    groupedUpdated.compareType = ScanCompare::Exact;
    parsed = groupedUpdated.parseGrouped("i32:1337@0;float:2.5@4;byte:67@8", &groupedError);
    ok = ok && parsed;
    auto exactResult = parsed ? scanner.nextScan(proc, groupedUpdated, changedResult) : ScanResult{};
    ok = ok && exactResult.count() == 1 && exactResult.address(0) == base + 128;

    munmap(page, pageSize);

    printf("  grouped first/next: %s\n", ok ? "OK" : "FAILED");
}

void test_custom_formula_scan() {
    printf("\n── Test: Custom formula scan ──\n");

    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("  custom Lua formula: FAILED\n");
        return;
    }

    std::memset(page, 0x55, pageSize);
    auto base = reinterpret_cast<uintptr_t>(page);
    auto* bytes = reinterpret_cast<uint8_t*>(page);

    uint32_t target = 0x1234ABCD;
    uint32_t decoy = 0x1234ABCE;
    std::memcpy(bytes + 64, &target, sizeof(target));
    std::memcpy(bytes + 128, &decoy, sizeof(decoy));

    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner;

    ScanConfig custom;
    custom.valueType = ValueType::Custom;
    custom.compareType = ScanCompare::Exact;
    custom.customValueSize = 4;
    custom.customFormula =
        "local b1,b2,b3,b4 = string.byte(current,1,4)\n"
        "return b1 == 0xCD and b2 == 0xAB and b3 == 0x34 and b4 == 0x12";
    custom.alignment = 4;
    custom.startAddress = base;
    custom.stopAddress = base + pageSize;

    auto first = scanner.firstScan(proc, custom);
    bool ok = first.count() == 1 && first.address(0) == base + 64;

    uint32_t changedValue = 0x1234ABCF;
    std::memcpy(bytes + 64, &changedValue, sizeof(changedValue));

    ScanConfig changed = custom;
    changed.compareType = ScanCompare::Changed;
    auto changedResult = scanner.nextScan(proc, changed, first);
    ok = ok && changedResult.count() == 1 && changedResult.address(0) == base + 64;

    std::memcpy(bytes + 64, &target, sizeof(target));
    auto exactResult = scanner.nextScan(proc, custom, changedResult);
    ok = ok && exactResult.count() == 1 && exactResult.address(0) == base + 64;

    // A formula that never ends fails its candidates instead of hanging the
    // scan, and cannot load files.
    ScanConfig runaway = custom;
    runaway.customFormula = "while true do end";
    runaway.stopAddress = base + 15;   // four candidates
    const auto runawayStart = std::chrono::steady_clock::now();
    auto stopped = scanner.firstScan(proc, runaway);
    const bool bounded = stopped.count() == 0 &&
        std::chrono::steady_clock::now() - runawayStart < std::chrono::seconds(30);
    ScanConfig fileAccess = runaway;
    fileAccess.customFormula = "return dofile ~= nil or loadfile ~= nil or load ~= nil";
    auto noFiles = scanner.firstScan(proc, fileAccess);
    printf("  a runaway formula is stopped, and formulas cannot load files: %s\n",
           bounded && noFiles.count() == 0 ? "OK" : "FAILED");

    munmap(page, pageSize);

    printf("  custom Lua formula: %s\n", ok ? "OK" : "FAILED");
}

void test_lua_memscan_grouped_custom() {
    printf("\n── Test: Lua memscan grouped/custom ──\n");

    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("  soCustom/vtGrouped: FAILED\n");
        return;
    }

    std::memset(page, 0x22, pageSize);
    auto base = reinterpret_cast<uintptr_t>(page);
    auto* bytes = reinterpret_cast<uint8_t*>(page);
    int32_t dwordValue = 777;
    float floatValue = 1.5f;
    std::memcpy(bytes, &dwordValue, sizeof(dwordValue));
    std::memcpy(bytes + 4, &floatValue, sizeof(floatValue));

    LinuxProcessHandle proc(getpid());
    LuaEngine lua;
    lua.setProcess(&proc);

    std::string script =
        "local base = " + std::to_string(base) + "\n"
        "local stop = base + " + std::to_string(pageSize) + "\n"
        "local grouped = createMemScan()\n"
        "assert(grouped:firstScan(soExactValue, vtGrouped, 'i32:777@0;float:1.5@4', base, stop, 1))\n"
        "assert(grouped:getFoundCount() == 1)\n"
        "assert(grouped:getAddress(0) == base)\n"
        "local custom = createMemScan()\n"
        "assert(custom:firstScan(soCustom, vtDword, 'local b1,b2,b3,b4=string.byte(current,1,4); return b1==0x09 and b2==0x03 and b3==0 and b4==0', base, stop, 4))\n"
        "assert(custom:getFoundCount() == 1)\n"
        "assert(custom:getAddress(0) == base)\n";

    auto err = lua.execute(script);
    munmap(page, pageSize);

    printf("  soCustom/vtGrouped: %s\n", err.empty() ? "OK" : "FAILED");
}

void test_percentage_scan() {
    printf("\n── Test: Percentage scan ──\n");

    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("  increased/between by percent: FAILED\n");
        return;
    }

    auto base = reinterpret_cast<uintptr_t>(page);
    auto* value = reinterpret_cast<int32_t*>(page);
    *value = 100;

    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner;

    ScanConfig first;
    first.valueType = ValueType::Int32;
    first.compareType = ScanCompare::Exact;
    first.intValue = 100;
    first.alignment = 4;
    first.startAddress = base;
    first.stopAddress = base + pageSize;

    auto initial = scanner.firstScan(proc, first);
    *value = 125;

    ScanConfig increased = first;
    increased.compareType = ScanCompare::Increased;
    increased.percentageScan = true;
    increased.percentageValue = 20.0;
    auto increasedResult = scanner.nextScan(proc, increased, initial);

    ScanConfig between = increased;
    between.compareType = ScanCompare::Between;
    between.percentageValue = 20.0;
    between.percentageValue2 = 30.0;
    auto betweenResult = scanner.nextScan(proc, between, initial);

    ScanConfig tooHigh = increased;
    tooHigh.percentageValue = 30.0;
    auto tooHighResult = scanner.nextScan(proc, tooHigh, initial);

    bool ok = initial.count() == 1 &&
        increasedResult.count() == 1 && increasedResult.address(0) == base &&
        betweenResult.count() == 1 && betweenResult.address(0) == base &&
        tooHighResult.count() == 0;

    munmap(page, pageSize);

    printf("  increased/between by percent: %s\n", ok ? "OK" : "FAILED");
}

void test_same_as_first_scan() {
    printf("\n── Test: Same-as-first scan ──\n");

    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("  same as first: FAILED\n");
        return;
    }

    auto base = reinterpret_cast<uintptr_t>(page);
    auto* value = reinterpret_cast<int32_t*>(page);
    *value = 100;

    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner;

    ScanConfig first;
    first.valueType = ValueType::Int32;
    first.compareType = ScanCompare::Exact;
    first.intValue = 100;
    first.alignment = 4;
    first.startAddress = base;
    first.stopAddress = base + pageSize;

    auto initial = scanner.firstScan(proc, first);

    *value = 200;
    ScanConfig changed = first;
    changed.compareType = ScanCompare::Changed;
    auto changedResult = scanner.nextScan(proc, changed, initial);

    *value = 100;
    ScanConfig same = first;
    same.compareType = ScanCompare::SameAsFirst;
    auto sameResult = scanner.nextScan(proc, same, changedResult);

    *value = 200;
    auto differentResult = scanner.nextScan(proc, same, changedResult);

    int32_t firstValue = 0;
    if (changedResult.count() > 0)
        changedResult.firstValue(0, &firstValue, sizeof(firstValue));

    bool ok = initial.count() == 1 &&
        changedResult.count() == 1 && changedResult.address(0) == base &&
        firstValue == 100 &&
        sameResult.count() == 1 && sameResult.address(0) == base &&
        differentResult.count() == 0;

    munmap(page, pageSize);

    printf("  same as first: %s\n", ok ? "OK" : "FAILED");
}

void test_pointer_type_scan() {
    printf("\n── Test: Pointer type scan ──\n");

    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("  pointer scan: FAILED\n");
        return;
    }

    auto base = reinterpret_cast<uintptr_t>(page);
    auto* pointerSlot = reinterpret_cast<uintptr_t*>(page);
    *pointerSlot = base + 128;

    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner;

    ScanConfig config;
    config.valueType = ValueType::Pointer;
    config.compareType = ScanCompare::Exact;
    config.intValue = static_cast<int64_t>(base + 128);
    config.alignment = sizeof(uintptr_t);
    config.startAddress = base;
    config.stopAddress = base + pageSize;

    auto first = scanner.firstScan(proc, config);

    *pointerSlot = base + 256;
    config.intValue = static_cast<int64_t>(base + 256);
    auto next = scanner.nextScan(proc, config, first);

    uintptr_t stored = 0;
    if (next.count() > 0)
        next.value(0, &stored, sizeof(stored));

    bool ok = first.count() == 1 && first.address(0) == base &&
        next.count() == 1 && next.address(0) == base &&
        stored == base + 256;

    munmap(page, pageSize);

    printf("  pointer scan: %s\n", ok ? "OK" : "FAILED");
}

void test_float_rounding_scan() {
    printf("\n── Test: Float rounding scan ──\n");

    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("  rounded/truncated/extreme: FAILED\n");
        return;
    }

    std::memset(page, 0x7f, pageSize);
    auto base = reinterpret_cast<uintptr_t>(page);
    auto* bytes = reinterpret_cast<uint8_t*>(page);
    float roundedA = 42.4f;
    float roundedB = 42.01f;
    float notRounded = 42.6f;
    std::memcpy(bytes + 16, &roundedA, sizeof(roundedA));
    std::memcpy(bytes + 32, &notRounded, sizeof(notRounded));
    std::memcpy(bytes + 48, &roundedB, sizeof(roundedB));

    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner;

    ScanConfig config;
    config.valueType = ValueType::Float;
    config.compareType = ScanCompare::Exact;
    config.floatValue = 42.0;
    config.alignment = 4;
    config.startAddress = base;
    config.stopAddress = base + pageSize;

    config.roundingType = 1;
    auto roundedResult = scanner.firstScan(proc, config);

    config.roundingType = 2;
    auto truncatedResult = scanner.firstScan(proc, config);

    config.roundingType = 3;
    config.floatTolerance = 0.02;
    auto extremeResult = scanner.firstScan(proc, config);

    auto hasAddress = [](const ScanResult& result, uintptr_t address) {
        for (size_t i = 0; i < result.count(); ++i)
            if (result.address(i) == address)
                return true;
        return false;
    };

    bool roundedOk = roundedResult.count() == 2 &&
        hasAddress(roundedResult, base + 16) &&
        hasAddress(roundedResult, base + 48);
    bool truncatedOk = truncatedResult.count() == 3 &&
        hasAddress(truncatedResult, base + 16) &&
        hasAddress(truncatedResult, base + 32) &&
        hasAddress(truncatedResult, base + 48);
    bool extremeOk = extremeResult.count() == 1 &&
        extremeResult.address(0) == base + 48;

    // Decimal-precision "Rounded" (CE default): searching 3.14 with 2 decimals
    // must match values within [3.135, 3.145) and reject 3.15 — NOT integer
    // rounding (which would loosely match anything rounding to 3).
    std::memset(page, 0, pageSize);
    float exactDp   = 3.14f;    // match
    float inRangeDp = 3.142f;   // match (< 3.145)
    float outLowDp  = 3.13f;    // reject (< 3.135)
    float outHighDp = 3.15f;    // reject (>= 3.145)
    std::memcpy(bytes + 16, &exactDp,   sizeof(float));
    std::memcpy(bytes + 32, &inRangeDp, sizeof(float));
    std::memcpy(bytes + 48, &outLowDp,  sizeof(float));
    std::memcpy(bytes + 64, &outHighDp, sizeof(float));

    ScanConfig dp;
    dp.valueType = ValueType::Float;
    dp.compareType = ScanCompare::Exact;
    dp.floatValue = 3.14;
    dp.roundingType = 1;
    dp.floatDecimals = 2;       // <-- decimal-precision rounding
    dp.alignment = 4;
    dp.startAddress = base;
    dp.stopAddress = base + pageSize;
    auto dpResult = scanner.firstScan(proc, dp);
    bool dpOk = dpResult.count() == 2 &&
        hasAddress(dpResult, base + 16) && hasAddress(dpResult, base + 32);

    munmap(page, pageSize);

    printf("  rounded/truncated/extreme: %s\n",
        (roundedOk && truncatedOk && extremeOk) ? "OK" : "FAILED");
    printf("  rounded at decimal precision (CE default): %s\n", dpOk ? "OK" : "FAILED");
}

void test_process_enumeration() {
    printf("\n── Test: Process Enumeration ──\n");
    LinuxProcessEnumerator enumerator;
    auto procs = enumerator.list();
    printf("  Found %zu processes\n", procs.size());
    int shown = 0;
    for (auto& p : procs) {
        if (shown < 5)
            printf("  %8d %s\n", p.pid, p.name.c_str());
        ++shown;
    }
    if (procs.size() > 5)
        printf("  ... and %zu more\n", procs.size() - 5);

    // The sandbox flag is populated: we (the test) are in the root namespace, so our
    // own entry is present and not sandboxed.
    bool foundSelf = false, selfSandboxed = false;
    for (auto& p : procs)
        if (p.pid == getpid()) { foundSelf = true; selfSandboxed = p.sandboxed; }
    printf("  self listed and not sandboxed: %s\n",
           (foundSelf && !selfSandboxed) ? "OK" : "FAILED");
}

void test_process_memory(pid_t pid) {
    printf("\n── Test: Memory Operations (pid=%d) ──\n", pid);
    LinuxProcessHandle proc(pid);

    printf("  is64bit: %s\n", proc.is64bit() ? "yes" : "no");

    // Query regions
    auto regions = proc.queryRegions();
    printf("  Memory regions: %zu\n", regions.size());

    size_t totalReadable = 0;
    for (auto& r : regions) {
        if (r.protection & MemProt::Read)
            totalReadable += r.size;
    }
    printf("  Total readable: %zu bytes (%.1f MB)\n", totalReadable, totalReadable / 1048576.0);

    // Show first 5 regions
    for (size_t i = 0; i < std::min(regions.size(), size_t(5)); ++i) {
        auto& r = regions[i];
        char perms[4] = "---";
        if (r.protection & MemProt::Read)  perms[0] = 'r';
        if (r.protection & MemProt::Write) perms[1] = 'w';
        if (r.protection & MemProt::Exec)  perms[2] = 'x';
        printf("  %016lx-%016lx %s %8zu %s\n",
            r.base, r.base + r.size, perms, r.size, r.path.c_str());
    }

    // Read first readable region
    auto readable = std::find_if(regions.begin(), regions.end(),
        [](const MemoryRegion& r) { return r.protection & MemProt::Read; });

    if (readable != regions.end()) {
        uint8_t buf[64];
        auto result = proc.read(readable->base, buf, sizeof(buf));
        if (result) {
            printf("\n  Read %zu bytes from 0x%lx:\n  ", *result, readable->base);
            for (size_t i = 0; i < std::min(*result, size_t(16)); ++i)
                printf("%02x ", buf[i]);
            printf("\n");
        } else {
            printf("  Read FAILED: %s\n", result.error().message().c_str());
        }
    }

    // Module enumeration
    auto mods = proc.modules();
    printf("\n  Modules: %zu\n", mods.size());
    for (size_t i = 0; i < std::min(mods.size(), size_t(5)); ++i)
        printf("  %016lx %s\n", mods[i].base, mods[i].name.c_str());

    // Thread enumeration
    auto tids = proc.threads();
    printf("\n  Threads: %zu\n", tids.size());
    for (auto& t : tids)
        printf("  tid=%d\n", t.tid);
}

void test_write_memory(pid_t pid) {
    printf("\n── Test: Memory Write (pid=%d) ──\n", pid);
    LinuxProcessHandle proc(pid);

    auto regions = proc.queryRegions();
    // Find a writable region (heap)
    auto writable = std::find_if(regions.begin(), regions.end(),
        [](const MemoryRegion& r) {
            return (r.protection & MemProt::Read) && (r.protection & MemProt::Write)
                && r.path.find("[heap]") != std::string::npos;
        });

    if (writable == regions.end()) {
        printf("  No writable heap region found\n");
        return;
    }

    uint64_t orig = 0;
    auto rr = proc.read(writable->base, &orig, 8);
    if (!rr) { printf("  Read failed\n"); return; }

    printf("  Original 8 bytes at 0x%lx: %016lx\n", writable->base, orig);

    uint64_t test = 0xDEADBEEFCAFEBABEULL;
    auto wr = proc.write(writable->base, &test, 8);
    if (!wr) { printf("  Write failed: %s\n", wr.error().message().c_str()); return; }

    uint64_t readback = 0;
    proc.read(writable->base, &readback, 8);
    printf("  After write: %016lx %s\n", readback, readback == test ? "OK" : "MISMATCH!");

    // Restore
    proc.write(writable->base, &orig, 8);
}

void test_string_case_insensitive_scan() {
    printf("\n── Test: Case-insensitive string scan ──\n");
    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { printf("  case-insensitive: FAILED\n"); return; }
    std::memset(page, 0, pageSize);
    auto base = reinterpret_cast<uintptr_t>(page);
    const char* text = "HeLLoWorld";
    std::memcpy(reinterpret_cast<uint8_t*>(page) + 100, text, std::strlen(text));
    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner;
    auto scan = [&](bool caseSensitive) {
        ScanConfig c; c.valueType = ValueType::String; c.compareType = ScanCompare::Exact;
        c.stringValue = "helloworld"; c.caseSensitive = caseSensitive; c.alignment = 1;
        c.startAddress = base; c.stopAddress = base + pageSize;
        return scanner.firstScan(proc, c);
    };
    auto hasHit = [&](ScanResult& r) {
        for (size_t i = 0; i < r.count(); ++i) if (r.address(i) == base + 100) return true;
        return false;
    };
    auto sensitive = scan(true);
    auto insensitive = scan(false);
    bool ok = !hasHit(sensitive) && hasHit(insensitive);   // 'helloworld' != 'HeLLoWorld' unless folded

    // Same for a UTF-16LE (Unicode) mixed-case string.
    const char* wtext = "H\0e\0L\0L\0o\0";
    std::memcpy(reinterpret_cast<uint8_t*>(page) + 300, wtext, 10);
    auto uscan = [&](bool caseSensitive) {
        ScanConfig c; c.valueType = ValueType::UnicodeString; c.compareType = ScanCompare::Exact;
        c.stringValue = "hello"; c.caseSensitive = caseSensitive; c.alignment = 2;
        c.startAddress = base; c.stopAddress = base + pageSize;
        return scanner.firstScan(proc, c);
    };
    auto uHasHit = [&](ScanResult& r) {
        for (size_t i = 0; i < r.count(); ++i) if (r.address(i) == base + 300) return true;
        return false;
    };
    auto us = uscan(true);
    auto ui = uscan(false);
    bool uok = !uHasHit(us) && uHasHit(ui);
    munmap(page, pageSize);
    printf("  case-sensitive misses, case-insensitive finds mixed-case (Text): %s\n", ok ? "OK" : "FAILED");
    printf("  case-insensitive Unicode/UTF-16 finds mixed-case: %s\n", uok ? "OK" : "FAILED");
}

void test_between_reversed_bounds() {
    printf("\n── Test: Between scan with reversed bounds ──\n");
    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { printf("  between reversed: FAILED\n"); return; }
    std::memset(page, 0, pageSize);
    auto base = reinterpret_cast<uintptr_t>(page);
    *reinterpret_cast<int32_t*>(reinterpret_cast<uint8_t*>(page) + 64) = 150;
    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner;
    auto scan = [&](int64_t lo, int64_t hi) {
        ScanConfig c; c.valueType = ValueType::Int32; c.compareType = ScanCompare::Between;
        c.intValue = lo; c.intValue2 = hi; c.alignment = 4;
        c.startAddress = base; c.stopAddress = base + pageSize;
        return scanner.firstScan(proc, c);
    };
    auto has = [&](ScanResult& r) {
        for (size_t i = 0; i < r.count(); ++i) if (r.address(i) == base + 64) return true;
        return false;
    };
    auto ordered = scan(100, 200);
    auto reversed = scan(200, 100);   // must behave the same (150 is between 100 and 200)
    // Also a float between with reversed bounds.
    *reinterpret_cast<float*>(reinterpret_cast<uint8_t*>(page) + 128) = 1.5f;
    ScanConfig fc; fc.valueType = ValueType::Float; fc.compareType = ScanCompare::Between;
    fc.floatValue = 2.0; fc.floatValue2 = 1.0; fc.alignment = 4;
    fc.startAddress = base; fc.stopAddress = base + pageSize;
    auto freversed = scanner.firstScan(proc, fc);
    bool fhit = false;
    for (size_t i = 0; i < freversed.count(); ++i) if (freversed.address(i) == base + 128) fhit = true;
    munmap(page, pageSize);
    bool ok = has(ordered) && has(reversed) && fhit;
    printf("  reversed bounds find in-range value (int + float): %s\n", ok ? "OK" : "FAILED");

    // Float "IncreasedBy": 0.1 -> 0.3 is a delta of ~0.2 that is NOT exactly 0.2f,
    // so an exact-== delta check would miss it. Tolerance must find it.
    void* fp = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    bool fbyOk = false;
    if (fp != MAP_FAILED) {
        std::memset(fp, 0, pageSize);
        auto fbase = reinterpret_cast<uintptr_t>(fp);
        auto* fv = reinterpret_cast<float*>(reinterpret_cast<uint8_t*>(fp) + 64);
        *fv = 0.1f;
        ScanConfig f1; f1.valueType = ValueType::Float; f1.compareType = ScanCompare::Exact;
        f1.floatValue = 0.1; f1.roundingType = 1; f1.alignment = 4;
        f1.startAddress = fbase; f1.stopAddress = fbase + pageSize;
        auto first = scanner.firstScan(proc, f1);
        *fv = 0.3f;
        ScanConfig f2; f2.valueType = ValueType::Float; f2.compareType = ScanCompare::IncreasedBy;
        f2.floatValue = 0.2; f2.alignment = 4;
        f2.startAddress = fbase; f2.stopAddress = fbase + pageSize;
        auto inc = scanner.nextScan(proc, f2, first);
        for (size_t i = 0; i < inc.count(); ++i) if (inc.address(i) == fbase + 64) fbyOk = true;
        munmap(fp, pageSize);
    }
    printf("  float IncreasedBy tolerant of FP delta (0.1->0.3 by 0.2): %s\n", fbyOk ? "OK" : "FAILED");
}

void test_unknown_scan_chain() {
    printf("\n── Test: Unknown-initial-value scan chain ──\n");
    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { printf("  unknown scan: FAILED\n"); return; }
    std::memset(page, 0, pageSize);
    auto base = reinterpret_cast<uintptr_t>(page);
    auto* v = reinterpret_cast<int32_t*>(reinterpret_cast<uint8_t*>(page) + 64);
    *v = 100;
    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner;
    auto unknownFirst = [&]() {
        ScanConfig c; c.valueType = ValueType::Int32; c.compareType = ScanCompare::Unknown;
        c.alignment = 4; c.startAddress = base; c.stopAddress = base + pageSize;
        return scanner.firstScan(proc, c);
    };
    auto next = [&](ScanCompare cmp, ScanResult& prev) {
        ScanConfig n; n.valueType = ValueType::Int32; n.compareType = cmp;
        n.alignment = 4; n.startAddress = base; n.stopAddress = base + pageSize;
        return scanner.nextScan(proc, n, prev);
    };
    auto has = [&](ScanResult& r, uintptr_t a) {
        for (size_t i = 0; i < r.count(); ++i) if (r.address(i) == a) return true;
        return false;
    };

    // Unknown first scan snapshots every aligned dword (baseline). Then only our
    // value changes 100->150: Increased must keep it and drop the unchanged zeros.
    auto f1 = unknownFirst();
    size_t baseline = f1.count();
    *v = 150;
    auto inc = next(ScanCompare::Increased, f1);
    bool incOk = baseline > 100 && has(inc, base + 64) && inc.count() < baseline && !has(inc, base + 0);

    // Fresh Unknown, change nothing: Unchanged keeps all; then change one and Changed drops it.
    *v = 100;
    auto f2 = unknownFirst();
    auto unchangedAll = next(ScanCompare::Unchanged, f2);
    bool allKept = unchangedAll.count() == f2.count();
    auto f3 = unknownFirst();
    *v = 999;
    auto changed = next(ScanCompare::Changed, f3);
    bool changedOk = has(changed, base + 64) && changed.count() < f3.count();

    munmap(page, pageSize);
    bool ok = incOk && allKept && changedOk;
    printf("  Unknown snapshot -> Increased/Unchanged/Changed refine: %s\n", ok ? "OK" : "FAILED");
}

void test_scan_alignment() {
    printf("\n── Test: Scan alignment ──\n");
    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { printf("  alignment: FAILED\n"); return; }
    std::memset(page, 0, pageSize);
    auto base = reinterpret_cast<uintptr_t>(page);
    int32_t val = 0x12345678;
    std::memcpy(reinterpret_cast<uint8_t*>(page) + 65, &val, 4);   // offset 65: 4-misaligned
    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner;
    auto scan = [&](size_t align) {
        ScanConfig c; c.valueType = ValueType::Int32; c.compareType = ScanCompare::Exact;
        c.intValue = 0x12345678; c.alignment = align;
        c.startAddress = base; c.stopAddress = base + pageSize;
        return scanner.firstScan(proc, c);
    };
    auto hasHit = [&](ScanResult& r) {
        for (size_t i = 0; i < r.count(); ++i) if (r.address(i) == base + 65) return true;
        return false;
    };
    auto r4 = scan(4);
    auto r1 = scan(1);
    bool ok = !hasHit(r4) && hasHit(r1);   // aligned misses, unaligned finds
    munmap(page, pageSize);
    printf("  aligned=4 misses unaligned value, aligned=1 finds it: %s\n", ok ? "OK" : "FAILED");
}

void test_nextscan_comparators() {
    printf("\n── Test: Next-scan comparators ──\n");
    const size_t pageSize = 4096;
    void* page = mmap(nullptr, pageSize, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { printf("  comparators: FAILED\n"); return; }
    std::memset(page, 0, pageSize);
    auto base = reinterpret_cast<uintptr_t>(page);
    auto* v = reinterpret_cast<int32_t*>(reinterpret_cast<uint8_t*>(page) + 64);
    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner;

    auto scanExact100 = [&]() {
        ScanConfig c; c.valueType = ValueType::Int32; c.compareType = ScanCompare::Exact;
        c.intValue = 100; c.alignment = 4; c.startAddress = base; c.stopAddress = base + pageSize;
        return scanner.firstScan(proc, c);
    };
    auto survives = [&](ScanCompare cmp, int64_t arg, int32_t newVal) {
        *v = 100; auto first = scanExact100(); *v = newVal;
        ScanConfig n; n.valueType = ValueType::Int32; n.compareType = cmp; n.intValue = arg;
        n.alignment = 4; n.startAddress = base; n.stopAddress = base + pageSize;
        auto r = scanner.nextScan(proc, n, first);
        for (size_t i = 0; i < r.count(); ++i) if (r.address(i) == base + 64) return true;
        return false;
    };

    bool ok =
        survives(ScanCompare::Increased,   0, 150) &&   // 150 > 100
        !survives(ScanCompare::Increased,  0, 100) &&   // unchanged -> not increased
        survives(ScanCompare::Decreased,   0, 50)  &&   // 50 < 100
        !survives(ScanCompare::Decreased,  0, 150) &&
        survives(ScanCompare::Changed,     0, 150) &&
        !survives(ScanCompare::Changed,    0, 100) &&
        survives(ScanCompare::Unchanged,   0, 100) &&
        !survives(ScanCompare::Unchanged,  0, 150) &&
        survives(ScanCompare::IncreasedBy, 50, 150) &&  // 150 - 100 == 50
        !survives(ScanCompare::IncreasedBy,50, 140) &&
        survives(ScanCompare::DecreasedBy, 50, 50)  &&  // 100 - 50 == 50
        survives(ScanCompare::Greater,    120, 150) &&  // > 120
        survives(ScanCompare::Less,        80, 50);     // < 80

    munmap(page, pageSize);
    printf("  Increased/Decreased/Changed/Unchanged/By/Greater/Less: %s\n", ok ? "OK" : "FAILED");
}

void test_cpp_symbol_demangling() {
    printf("\n\u2500\u2500 Test: C++ symbol demangling \u2500\u2500\n");
    const char* src = "void ceDemangleProbe() {} void ceOther(int x){(void)x;}\n";
    auto dir = std::filesystem::temp_directory_path();
    auto cpp = dir / "ce_demangle_test.cpp";
    auto so  = dir / "libce_demangle_test.so";
    { std::ofstream o(cpp); o << src; }
    std::string cmd = "g++ -shared -fPIC -O0 -o '" + so.string() + "' '" + cpp.string() + "' 2>/dev/null";
    int rc = std::system(cmd.c_str());
    bool ok = false; bool skipped = (rc != 0);
    if (!skipped) {
        ce::SymbolResolver res;
        res.loadModule(so.string(), "dm", 0);
        uintptr_t addr = res.lookup("_Z15ceDemangleProbev");  // void ceDemangleProbe()
        if (addr) ok = res.resolve(addr).find("ceDemangleProbe()") != std::string::npos;
    }
    std::filesystem::remove(cpp); std::filesystem::remove(so);
    printf("  C++ name demangled in resolve(): %s\n", skipped ? "SKIP(no g++)" : (ok ? "OK" : "FAILED"));
}

void test_symbol_size0_extent_cap() {
    printf("\n── Test: size-0 symbol extent cap ──\n");
    // A .globl label with no .size directive => an STT symbol of size 0.
    const char* asmSrc = ".text\n.globl ceZeroSym\nceZeroSym:\n    ret\n";
    auto dir = std::filesystem::temp_directory_path();
    auto s  = dir / "ce_zero_sym.s";
    auto so = dir / "libce_zero_sym.so";
    { std::ofstream o(s); o << asmSrc; }
    std::string cmd = "gcc -shared -nostdlib -o '" + so.string() + "' '" + s.string() + "' 2>/dev/null";
    int rc = std::system(cmd.c_str());
    bool ok = false; bool skipped = (rc != 0);
    if (!skipped) {
        ce::SymbolResolver res;
        res.loadModule(so.string(), "z", 0);
        uintptr_t addr = res.lookup("ceZeroSym");
        if (addr) {
            // Offset 0 always resolves. Offset 0x800 (<4KB) must still show
            // "ceZeroSym+0x800" — this proves ceZeroSym is the nearest preceding
            // symbol (guards against a vacuous far-check). Offset 0x1100 (>4KB) is
            // still below the next symbol but must NOT be attributed to a size-0
            // ceZeroSym (pre-fix it returned "z!ceZeroSym+0x1100").
            bool nearOk = res.resolve(addr).find("ceZeroSym") != std::string::npos;
            bool midOk  = res.resolve(addr + 0x800).find("ceZeroSym+0x800") != std::string::npos;
            bool farOk  = res.resolve(addr + 0x1100).find("ceZeroSym") == std::string::npos;
            ok = nearOk && midOk && farOk;
        }
    }
    std::filesystem::remove(s); std::filesystem::remove(so);
    printf("  size-0 symbol not attributed >4KB past it: %s\n",
           skipped ? "SKIP(no gcc)" : (ok ? "OK" : "FAILED"));
}

void test_plt_import_resolution() {
    printf("\n── Test: PLT/GOT import resolution ──\n");
    // A .so that imports getpid produces a .rela.plt entry for it; the resolver
    // must name that GOT slot "getpid@got" so a PLT stub's "jmp [got]" resolves.
    // (getpid isn't rewritten by the compiler the way printf("x")->putchar is.)
    const char* src = "#include <unistd.h>\nlong ceCallsImport(){ return getpid(); }\n";
    auto dir = std::filesystem::temp_directory_path();
    auto cpp = dir / "ce_plt_test.cpp";
    auto so  = dir / "libce_plt_test.so";
    { std::ofstream o(cpp); o << src; }
    std::string cmd = "g++ -shared -fPIC -O0 -o '" + so.string() + "' '" + cpp.string() + "' 2>/dev/null";
    int rc = std::system(cmd.c_str());
    bool ok = false; bool skipped = (rc != 0);
    if (!skipped) {
        ce::SymbolResolver res;
        res.loadModule(so.string(), "m", 0);
        uintptr_t slot = res.lookup("getpid@got");
        bool gotOk = slot != 0 && res.resolve(slot).find("getpid@got") != std::string::npos;
        // The PLT stub for getpid must also be named "getpid@plt" (so `call <stub>`
        // resolves to the import) and sit in an executable PLT section (below .got).
        uintptr_t stub = res.lookup("getpid@plt");
        bool pltOk = stub != 0 && stub != slot &&
                     res.resolve(stub).find("getpid@plt") != std::string::npos;
        ok = gotOk && pltOk;
    }
    std::filesystem::remove(cpp); std::filesystem::remove(so);
    printf("  imported function resolves as <func>@got and <func>@plt: %s\n",
           skipped ? "SKIP(no g++)" : (ok ? "OK" : "FAILED"));
}

void test_freeze_should_write() {
    printf("── Test: Directional freeze decision ──\n");
    using ce::FreezeMode;
    using ce::freezeShouldWrite;
    // Normal always writes; floor modes write only when the value dropped below
    // frozen; ceiling modes write only when it rose above. At equality no
    // directional mode writes.
    bool ok =
        freezeShouldWrite(FreezeMode::Normal, 5, 10) &&
        freezeShouldWrite(FreezeMode::Normal, 15, 10) &&
        // floor (allow increase / never decrease): write iff current < frozen
        freezeShouldWrite(FreezeMode::IncreaseOnly, 5, 10) &&
        !freezeShouldWrite(FreezeMode::IncreaseOnly, 15, 10) &&
        !freezeShouldWrite(FreezeMode::IncreaseOnly, 10, 10) &&
        freezeShouldWrite(FreezeMode::NeverDecrease, 5, 10) &&
        !freezeShouldWrite(FreezeMode::NeverDecrease, 15, 10) &&
        // ceiling (allow decrease / never increase): write iff current > frozen
        freezeShouldWrite(FreezeMode::DecreaseOnly, 15, 10) &&
        !freezeShouldWrite(FreezeMode::DecreaseOnly, 5, 10) &&
        !freezeShouldWrite(FreezeMode::DecreaseOnly, 10, 10) &&
        freezeShouldWrite(FreezeMode::NeverIncrease, 15, 10) &&
        !freezeShouldWrite(FreezeMode::NeverIncrease, 5, 10);
    printf("  directional freeze decision: %s\n", ok ? "OK" : "FAILED");
}

void test_memview_pane_choice() {
    printf("── Test: Memory Viewer pane choice (double-click routing) ──\n");
    using P = ce::MemViewPane;
    // With no modifiers, executability decides: code -> disassembler, data -> hex.
    bool guessCode = ce::chooseMemViewPane(/*exec=*/true,  false, false) == P::Disassembler;
    bool guessData = ce::chooseMemViewPane(/*exec=*/false, false, false) == P::HexDump;
    // Shift forces the disassembler even for data; Ctrl forces the hex dump even for code.
    bool shiftForcesDisasm = ce::chooseMemViewPane(false, /*shift=*/true, false) == P::Disassembler;
    bool ctrlForcesHex     = ce::chooseMemViewPane(true,  false, /*ctrl=*/true) == P::HexDump;
    // Both held: Shift (show-as-code) wins.
    bool bothShiftWins = ce::chooseMemViewPane(false, true, true) == P::Disassembler;
    bool ok = guessCode && guessData && shiftForcesDisasm && ctrlForcesHex && bothShiftWins;
    printf("  guessCode=%d guessData=%d shift=%d ctrl=%d both=%d: %s\n",
           guessCode, guessData, shiftForcesDisasm, ctrlForcesHex, bothShiftWins,
           ok ? "OK" : "FAILED");
}

void test_aob_signature() {
    printf("── Test: Unique AOB signature (CE-style AOB injection) ──\n");

    // A 64-byte module: the first 5 bytes {AA BB CC DD EE} repeat at offset 16, but
    // the 6th byte differs (11 vs 22), so a 6-byte signature is uniquely the hook site.
    std::vector<uint8_t> mod(64, 0x00);
    const uint8_t head[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x11};
    const uint8_t dup[6]  = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x22};
    std::memcpy(mod.data() + 0,  head, 6);
    std::memcpy(mod.data() + 16, dup,  6);
    // A distinct, already-unique 5-byte run near the end.
    const uint8_t uniq[5] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA};
    std::memcpy(mod.data() + 40, uniq, 5);

    // Pure: 5 bytes are ambiguous (two matches) so it extends to 6; the unique run
    // stays at 5; an all-equal region never disambiguates and is rejected.
    bool extends  = ce::shortestUniqueAobLen(mod, 0,  5, 16) == 6;
    bool alreadyU = ce::shortestUniqueAobLen(mod, 40, 5, 16) == 5;
    std::vector<uint8_t> flat(32, 0x90);
    bool capped   = ce::shortestUniqueAobLen(flat, 0, 2, 8) == 0;
    printf("  pure shortestUniqueAobLen (extend=%d alreadyUnique=%d ambiguousRejected=%d): %s\n",
           extends, alreadyU, capped, (extends && alreadyU && capped) ? "OK" : "FAILED");

    // End-to-end: a fake module whose signature is scanned from process memory.
    const uintptr_t base = 0x400000;
    FakeProcessHandle proc({
        {{base, mod.size(), MemProt::ReadExec, MemType::Private, MemState::Committed, "game"}, mod},
    }, {
        {base, mod.size(), "game", "/tmp/game", true},
    });
    std::string sig = ce::uniqueAobSignature(proc, proc.modules()[0], base, 5, 16);
    bool sigOk = (sig == "AA BB CC DD EE 11");
    printf("  uniqueAobSignature at base -> \"%s\": %s\n", sig.c_str(), sigOk ? "OK" : "FAILED");

    // The generated AOB-injection script carries that unique signature into aobscanmodule.
    std::vector<ce::StolenInstruction> stolen{{base, "nop", 5}};
    std::vector<uint8_t> orig(mod.begin(), mod.begin() + 5);
    std::string script = ce::buildAobInjectionScript("game", 0, stolen, orig, sig);
    bool scriptOk = script.find("aobscanmodule(INJECT,game,AA BB CC DD EE 11)") != std::string::npos;
    printf("  script embeds unique signature: %s\n", scriptOk ? "OK" : "FAILED");
}

void test_conditional_jump() {
    printf("── Test: Conditional jump prediction (flags -> taken) ──\n");
    const uint64_t ZF = 1ull << 6, CF = 1ull << 0, SF = 1ull << 7, OF = 1ull << 11;
    auto taken = [](const char* m, uint64_t fl) { return ce::conditionalJumpTaken(m, fl); };

    bool ok =
        taken("jmp", 0) == std::optional<bool>(true) &&           // unconditional
        taken("je",  ZF) == std::optional<bool>(true) &&           // ZF set -> jump
        taken("je",  0)  == std::optional<bool>(false) &&
        taken("jne", 0)  == std::optional<bool>(true) &&
        taken("jbe", CF) == std::optional<bool>(true) &&           // CF or ZF
        taken("ja",  0)  == std::optional<bool>(true) &&           // !CF && !ZF
        taken("ja",  ZF) == std::optional<bool>(false) &&
        // signed greater: !ZF && SF==OF. SF|OF both set -> equal -> taken.
        taken("jg",  SF | OF) == std::optional<bool>(true) &&
        taken("jg",  SF)      == std::optional<bool>(false) &&     // SF!=OF
        taken("jl",  SF)      == std::optional<bool>(true) &&      // SF!=OF
        !taken("jecxz", 0).has_value() &&                          // register-based, not flags
        !taken("mov", 0).has_value();                             // not a jump
    printf("  conditionalJumpTaken maps mnemonic+flags: %s\n", ok ? "OK" : "FAILED");

    // describeEflagsVerbose always lists every status flag with its 0/1 state.
    bool vok =
        ce::describeEflagsVerbose(0) == "CF=0 PF=0 AF=0 ZF=0 SF=0 DF=0 OF=0" &&
        ce::describeEflagsVerbose(ZF).find("ZF=1") != std::string::npos &&
        ce::describeEflagsVerbose(ZF).find("CF=0") != std::string::npos &&
        ce::describeEflagsVerbose(CF | OF).find("CF=1") != std::string::npos &&
        ce::describeEflagsVerbose(CF | OF).find("OF=1") != std::string::npos;
    printf("  describeEflagsVerbose lists all flag states: %s\n", vok ? "OK" : "FAILED");
}

void test_group_collapse() {
    printf("── Test: Cheat-table group collapse (row hiding) ──\n");
    // Rows: groupA(0) child1(1) groupB(1) child2(2) groupC(0)
    std::vector<int> indents = {0, 1, 1, 2, 0};

    // groupA collapsed -> its descendants (rows 1..3) hidden, groupC (row 4) stays.
    auto hA = ce::hiddenByCollapse(indents, {true, false, false, false, false});
    bool aOk = !hA[0] && hA[1] && hA[2] && hA[3] && !hA[4];

    // Only nested groupB collapsed -> just child2 (row 3) hidden.
    auto hB = ce::hiddenByCollapse(indents, {false, false, true, false, false});
    bool bOk = !hB[0] && !hB[1] && !hB[2] && hB[3] && !hB[4];

    // Nothing collapsed -> nothing hidden.
    auto hNone = ce::hiddenByCollapse(indents, {false, false, false, false, false});
    bool noneOk = std::none_of(hNone.begin(), hNone.end(), [](bool b) { return b; });

    bool ok = aOk && bOk && noneOk;
    printf("  collapse hides descendants (outer=%d nested=%d none=%d): %s\n",
           aOk, bOk, noneOk, ok ? "OK" : "FAILED");

    // descendantRange: groupA(0) spans rows 1..4; nested groupB(2) spans just row 3;
    // groupC(4) has no children.
    auto rA = ce::descendantRange(indents, 0);
    auto rB = ce::descendantRange(indents, 2);
    auto rC = ce::descendantRange(indents, 4);
    bool rangeOk = rA.first == 1 && rA.second == 4 &&
                   rB.first == 3 && rB.second == 4 &&
                   rC.first == 5 && rC.second == 5;
    printf("  descendantRange subtree spans (A=%d B=%d C=%d): %s\n",
           (int)(rA.second - rA.first), (int)(rB.second - rB.first), (int)(rC.second - rC.first),
           rangeOk ? "OK" : "FAILED");

    // moveRangePermutation: reorder entries by dropping a (possibly multi-row group)
    // block at a position (Qt drop-row = insert before `dest`).
    auto applyPerm = [](const std::string& s, const std::vector<int>& perm) {
        std::string out;
        for (int i : perm) out.push_back(s[i]);
        return out;
    };
    bool m1 = applyPerm("ABCDE", ce::moveRangePermutation(5, 1, 1, 3)) == "ACBDE";  // B down before D
    bool m2 = applyPerm("ABCDE", ce::moveRangePermutation(5, 3, 1, 1)) == "ADBCE";  // D up before B
    bool m3 = applyPerm("ABCDE", ce::moveRangePermutation(5, 1, 2, 5)) == "ADEBC";  // group {B,C} to end
    bool m4 = applyPerm("ABCDE", ce::moveRangePermutation(5, 2, 1, 2)) == "ABCDE";  // drop onto self = no-op
    bool m5 = applyPerm("ABCDE", ce::moveRangePermutation(5, 4, 3, 0)) == "ABCDE";  // out-of-range = identity
    bool moveOk = m1 && m2 && m3 && m4 && m5;
    printf("  moveRangePermutation reorders blocks (%d%d%d%d%d): %s\n",
           m1, m2, m3, m4, m5, moveOk ? "OK" : "FAILED");

    // groupSelection: wrap selected rows under a NEW group header. Render the plan as a
    // compact "<label><indent>" sequence, 'G' marking the freshly-created header.
    auto renderGroup = [](const std::string& labels, const std::vector<int>& indents,
                          std::vector<std::size_t> sel) {
        auto plan = ce::groupSelection(indents, std::move(sel));
        if (!plan.ok) return std::string("<empty>");
        std::string out;
        for (std::size_t i = 0; i < plan.order.size(); ++i) {
            if (i) out.push_back(' ');
            out.push_back(plan.order[i] < 0 ? 'G' : labels[plan.order[i]]);
            out.push_back(char('0' + plan.indent[i]));
        }
        return out;
    };
    // Flat list A B C D E; group B and C -> header before B, both nested one deeper.
    bool g1 = renderGroup("ABCDE", {0,0,0,0,0}, {1,2}) == "A0 G0 B1 C1 D0 E0";
    // Non-contiguous A and C -> gathered under the header; B (between them) falls out below.
    bool g2 = renderGroup("ABCDE", {0,0,0,0,0}, {0,2}) == "G0 A1 C1 B0 D0 E0";
    // Group a header A@0 with its child B@1: relative nesting preserved, shifted deeper.
    bool g3 = renderGroup("ABCD", {0,1,0,0}, {0,1}) == "G0 A1 B2 C0 D0";
    // Empty / fully out-of-range selection -> not ok.
    bool g4 = !ce::groupSelection({0,0,0}, {}).ok && !ce::groupSelection({0,0,0}, {9}).ok;
    // Duplicate + unsorted indices are sanitized to the same result as {1,2}.
    bool g5 = renderGroup("ABCDE", {0,0,0,0,0}, {2,1,2,1}) == "A0 G0 B1 C1 D0 E0";
    bool groupSelOk = g1 && g2 && g3 && g4 && g5;
    printf("  groupSelection wraps a selection under a new header (%d%d%d%d%d): %s\n",
           g1, g2, g3, g4, g5, groupSelOk ? "OK" : "FAILED");

    // expandGroupDeletion: deleting a group header takes its whole subtree with it.
    // Rows: groupA(0) child1(1) groupB(1) child2(2) groupC(0) [indents {0,1,1,2,0}].
    bool d1 = ce::expandGroupDeletion(indents, {0}) == std::vector<std::size_t>{0,1,2,3}; // groupA + subtree
    bool d2 = ce::expandGroupDeletion(indents, {2}) == std::vector<std::size_t>{2,3};     // nested groupB + child2
    bool d3 = ce::expandGroupDeletion(indents, {1}) == std::vector<std::size_t>{1};       // a leaf deletes alone
    bool d4 = ce::expandGroupDeletion(indents, {2,3}) == std::vector<std::size_t>{2,3};   // overlap dedupes
    bool d5 = ce::expandGroupDeletion(indents, {4,99}) == std::vector<std::size_t>{4};    // childless + out-of-range
    bool delOk = d1 && d2 && d3 && d4 && d5;
    printf("  expandGroupDeletion removes a group's whole subtree (%d%d%d%d%d): %s\n",
           d1, d2, d3, d4, d5, delOk ? "OK" : "FAILED");
}

void test_expression_parser() {
    printf("── Test: Expression Parser ──\n");
    const uintptr_t base  = 0x100000;
    const uintptr_t nodeA = base + 0x100;
    const uintptr_t nodeB = base + 0x200;
    const uintptr_t nodeC = base + 0x300;
    std::vector<uint8_t> mem(0x1000, 0);
    std::memcpy(mem.data() + 0,     &nodeA, sizeof(nodeA));   // [base]     = nodeA
    std::memcpy(mem.data() + 0x100, &nodeB, sizeof(nodeB));   // [nodeA]    = nodeB
    std::memcpy(mem.data() + 0x108, &nodeC, sizeof(nodeC));   // [nodeA+8]  = nodeC
    const uintptr_t hyBase = 0x7f0000000000ull;         // a hyphenated Linux library base
    FakeProcessHandle proc({
        {{base, mem.size(), MemProt::ReadWrite, MemType::Private, MemState::Committed, "[heap]"}, mem},
    }, {
        {base, 0x1000, "game", "/tmp/game", true},   // a named module based at `base`
        {hyBase, 0x1000, "libssl-1.1.so", "/lib/libssl-1.1.so", true},  // '-' in the name
    });
    ExpressionParser p(&proc, nullptr);
    auto eq = [](std::optional<uintptr_t> v, uintptr_t want) { return v && *v == want; };
    bool ok =
        eq(p.parse("game"),           base)         &&   // bare module name -> base
        // A module name with a '-' must not be split at the hyphen (Linux libs).
        eq(p.parse("libssl-1.1.so"),      hyBase)         &&
        eq(p.parse("libssl-1.1.so+0x10"), hyBase + 0x10)  &&
        eq(p.parse("game+0x100"),     base + 0x100) &&   // CE "module+offset" format
        eq(p.parse("[game+0x100]"),   nodeB)        &&   // deref module+offset: [base+0x100]=[nodeA]=nodeB
        eq(p.parse("[0x100000]"),     nodeA)        &&   // 1-level deref
        eq(p.parse("[[0x100000]]"),   nodeB)        &&   // 2-level (matching-bracket fix)
        eq(p.parse("[0x100000]+8"),   nodeA + 8)    &&   // single-digit hex offset
        eq(p.parse("[0x100000]+c"),   nodeA + 0xc)  &&   // single hex-letter offset
        eq(p.parse("[[0x100000]]+4"), nodeB + 4)    &&   // 2-level + outer offset
        // CE pointer format: offset INSIDE a bracket level. buildPointerExpression
        // emits e.g. "[[game.exe+1C]+8]+10" — deref base, add 8, deref again.
        eq(p.parse("[[0x100000]+8]"),    nodeC)     &&   // [nodeA+8] = nodeC
        eq(p.parse("[[0x100000]+8]+10"), nodeC + 0x10) &&  // ... + final offset
        // A bracket that is NOT at the start AND has an inner offset: the '+' inside
        // must not be treated as a top-level split (bracket-depth-aware).
        eq(p.parse("0x1000+[[0x100000]+8]"), 0x1000 + nodeC) &&
        // A module offset with no 0x prefix is hex, not decimal (CE + PointerPath).
        eq(p.parse("game+100"),           base + 0x100) &&
        // Negative offsets (real pointer paths and buildPointerExpression emit "-off").
        eq(p.parse("[0x100000]-8"),       nodeA - 8)    &&
        eq(p.parse("[[0x100000]+8]-4"),   nodeC - 4)    &&
        // Plain arithmetic with subtraction outside brackets.
        eq(p.parse("game+0x100-0x8"),     base + 0x100 - 0x8);
    printf("  multi-level pointers + inner/outer hex offsets + negatives: %s\n", ok ? "OK" : "FAILED");

    // User-defined symbol resolution: a label registered in the resolver resolves by
    // name and composes with offsets/derefs. This is exactly the path a record's
    // addressExpr now takes (AddressListModel::reresolveAddress passes the shared
    // resolver), so labelling an address in the Memory Viewer makes it usable as a
    // record address / in Lua.
    SymbolResolver usyms;
    usyms.addUserSymbol(nodeA, "health");
    ExpressionParser pr(&proc, &usyms);
    bool userSymOk =
        eq(pr.parse("health"),      nodeA)        &&   // bare label -> its address
        eq(pr.parse("health+0x10"), nodeA + 0x10) &&   // label composes with an offset
        eq(pr.parse("[health]"),    nodeB);            // deref the label: [nodeA] = nodeB
    printf("  user-defined symbol resolves by name (label/offset/deref): %s\n",
           userSymOk ? "OK" : "FAILED");
}

// ─── Scanner differential + fuzz test ────────────────────────────────────────
// The scanner's hot paths (SIMD exact/rounded numeric, SIMD byte-pattern anchor
// search, multi-threaded chunk partitioning with straddle overlap, coalesced
// next-scan reads, and sharded frame-encoded result storage) were heavily
// rewritten for speed. This pins their correctness by comparing every scan
// against an independent, deliberately dead-simple reference over the SAME bytes,
// across: all three SIMD dispatch modes (scalar / SSE2 / AVX2 when present); many
// chunk sizes (tiny forces boundary straddles and real MT partitioning); every
// numeric/float/string/AOB value type; alignments; rounding modes; and next-scan
// comparators. The whole test is deterministic (fixed base seed), so any mismatch
// prints the seed + config and reproduces on a plain re-run.
namespace ce { extern std::atomic<int> g_scanSimdOverride; }  // scanner.cpp test seam

namespace {

// Deterministic xorshift64 PRNG — no std::random, no time, fully reproducible.
struct Rng {
    uint64_t s;
    explicit Rng(uint64_t seed) : s(seed ? seed : 0x9E3779B97F4A7C15ull) {}
    uint64_t next() { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; }
    uint32_t u32() { return (uint32_t)(next() >> 11); }
    size_t range(size_t n) { return n ? (size_t)(next() % n) : 0; }
};

// Independent reference predicates. Each mirrors the scanner's *semantics* with
// the simplest possible expression; none share code with scanner.cpp, so they
// are a true oracle for the optimized machinery (only structural bugs — a dropped
// SIMD lane, a chunk-straddle miss/dup, a bad frame offset — can make the two
// disagree).
template<typename T>
bool refFloatExact(const ScanConfig& c, T cur, double needle) {
    if (std::isnan(cur) || std::isnan(needle)) return false;
    if (!std::isfinite(cur) || !std::isfinite(needle)) return (double)cur == needle;
    switch (c.roundingType) {
        case 1: {
            double cc = (double)cur, s = (double)needle;
            if (c.floatDecimals >= 0) {
                double half = 0.5 * std::pow(10.0, -c.floatDecimals);
                return std::fabs(cc - s) <= half;
            }
            const double kLLMax = 9.2e18;
            if (std::fabs(cc) > kLLMax || std::fabs(s) > kLLMax)
                return std::round(cc) == std::round(s);
            return std::llround(cc) == std::llround(s);
        }
        case 2:  return std::trunc((double)cur) == std::trunc((double)needle);
        case 3: {
            double tol = c.floatTolerance > 0.0 ? c.floatTolerance
                       : std::max(1e-6, std::fabs((double)needle) * 1e-6);
            return std::fabs((double)cur - (double)needle) <= tol;
        }
        default: return std::fabs(needle) <= std::numeric_limits<T>::max() && cur == (T)needle;
    }
}

template<typename T>
bool refIntFirst(const ScanConfig& c, T cur) {
    switch (c.compareType) {
        case ScanCompare::Exact:   return cur == (T)c.intValue;
        case ScanCompare::Greater: return cur >  (T)c.intValue;
        case ScanCompare::Less:    return cur <  (T)c.intValue;
        case ScanCompare::Between: {
            T v = (T)c.intValue, v2 = (T)c.intValue2;
            return v <= v2 ? (cur >= v && cur <= v2) : (cur >= v2 && cur <= v);
        }
        default: return false;
    }
}

template<typename T>
bool refFloatFirst(const ScanConfig& c, T cur) {
    switch (c.compareType) {
        case ScanCompare::Exact:   return refFloatExact<T>(c, cur, c.floatValue);
        case ScanCompare::Greater: return (double)cur > c.floatValue;
        case ScanCompare::Less:    return (double)cur < c.floatValue;
        case ScanCompare::Between: {
            double v = c.floatValue, v2 = c.floatValue2;
            return v <= v2 ? (cur >= v && cur <= v2) : (cur >= v2 && cur <= v);
        }
        default: return false;
    }
}

// Next-scan comparator (mirrors compareNextNumeric; no percentage path).
template<typename T>
bool refNumNext(const ScanConfig& c, T cur, T old, T first) {
    using CT = ScanCompare;
    if (c.compareType == CT::SameAsFirst) return cur == first;
    if (c.compareType == CT::IncreasedBy || c.compareType == CT::DecreasedBy) {
        if constexpr (std::is_floating_point_v<T>) {
            double d = (double)c.floatValue;
            double actual = c.compareType == CT::IncreasedBy
                ? (double)cur - (double)old : (double)old - (double)cur;
            double tol = std::max(1e-6, std::fabs(d) * 1e-5);
            bool dir = c.compareType == CT::IncreasedBy ? (cur > old) : (cur < old);
            return dir && std::fabs(actual - d) <= tol;
        } else {
            T delta = (T)c.intValue;
            if (c.compareType == CT::IncreasedBy) return cur > old && (T)(cur - old) == delta;
            return cur < old && (T)(old - cur) == delta;
        }
    }
    if (c.compareType >= CT::Changed) {  // Changed / Unchanged / Increased / Decreased
        switch (c.compareType) {
            case CT::Changed:   return cur != old;
            case CT::Unchanged: return cur == old;
            case CT::Increased: return cur >  old;
            case CT::Decreased: return cur <  old;
            default: return false;
        }
    }
    if constexpr (std::is_floating_point_v<T>) return refFloatFirst<T>(c, cur);
    else return refIntFirst<T>(c, cur);
}

template<typename T, typename Pred>
void refNumericScan(const uint8_t* buf, size_t n, uintptr_t base, size_t align,
                    Pred pred, std::vector<uintptr_t>& out) {
    if (n < sizeof(T) || align == 0) return;
    size_t limit = n - sizeof(T) + 1;
    for (size_t off = 0; off < limit; off += align) {
        T cur; std::memcpy(&cur, buf + off, sizeof(T));
        if (pred(cur)) out.push_back(base + off);
    }
}

size_t typeSize(ValueType t) {
    switch (t) {
        case ValueType::Byte: return 1;
        case ValueType::Int16: return 2;
        case ValueType::Int32: return 4;
        case ValueType::Int64: return 8;
        case ValueType::Pointer: return sizeof(uintptr_t);
        case ValueType::Float: return 4;
        case ValueType::Double: return 8;
        default: return 0;
    }
}

// Reference first scan → ascending match addresses.
std::vector<uintptr_t> refFirstScan(const uint8_t* buf, size_t n, uintptr_t base,
                                    const ScanConfig& c) {
    std::vector<uintptr_t> out;
    size_t align = c.alignment ? c.alignment : 1;
    switch (c.valueType) {
        case ValueType::Byte:    refNumericScan<uint8_t>(buf,n,base,align,[&](uint8_t v){return refIntFirst<uint8_t>(c,v);},out); break;
        case ValueType::Int16:   refNumericScan<int16_t>(buf,n,base,align,[&](int16_t v){return refIntFirst<int16_t>(c,v);},out); break;
        case ValueType::Int32:   refNumericScan<int32_t>(buf,n,base,align,[&](int32_t v){return refIntFirst<int32_t>(c,v);},out); break;
        case ValueType::Int64:   refNumericScan<int64_t>(buf,n,base,align,[&](int64_t v){return refIntFirst<int64_t>(c,v);},out); break;
        case ValueType::Pointer: refNumericScan<uintptr_t>(buf,n,base,align,[&](uintptr_t v){return refIntFirst<uintptr_t>(c,v);},out); break;
        case ValueType::Float:   refNumericScan<float>(buf,n,base,align,[&](float v){return refFloatFirst<float>(c,v);},out); break;
        case ValueType::Double:  refNumericScan<double>(buf,n,base,align,[&](double v){return refFloatFirst<double>(c,v);},out); break;
        case ValueType::String: {
            const std::string& s = c.stringValue;
            size_t nl = s.size();
            if (nl == 0 || n < nl) break;
            bool ci = !c.caseSensitive;
            for (size_t off = 0; off + nl <= n; ++off) {
                bool m = true;
                for (size_t i = 0; i < nl; ++i) {
                    uint8_t a = buf[off + i], b = (uint8_t)s[i];
                    if (ci ? (std::tolower(a) != std::tolower(b)) : (a != b)) { m = false; break; }
                }
                if (m) out.push_back(base + off);
            }
            break;
        }
        case ValueType::ByteArray: {
            const auto& pat = c.byteArray; const auto& mask = c.byteArrayMask;
            size_t pl = pat.size();
            if (pl == 0 || mask.size() != pl || n < pl) break;
            for (size_t off = 0; off + pl <= n; ++off) {
                bool m = true;
                for (size_t j = 0; j < pl; ++j)
                    if ((buf[off + j] & mask[j]) != (pat[j] & mask[j])) { m = false; break; }
                if (m) out.push_back(base + off);
            }
            break;
        }
        default: break;
    }
    return out;  // offsets ascend → already sorted
}

// Collect a ScanResult's addresses (ascending) and remove its scratch dir.
std::vector<uintptr_t> harvest(ScanResult& r) {
    std::vector<uintptr_t> got;
    got.reserve(r.count());
    for (size_t i = 0; i < r.count(); ++i) got.push_back(r.address(i));
    std::sort(got.begin(), got.end());
    std::error_code ec;
    std::filesystem::remove_all(r.directory().parent_path(), ec);
    return got;
}

const char* cmpName(ScanCompare c) {
    switch (c) {
        case ScanCompare::Exact: return "exact"; case ScanCompare::Greater: return "greater";
        case ScanCompare::Less: return "less"; case ScanCompare::Between: return "between";
        case ScanCompare::Changed: return "changed"; case ScanCompare::Unchanged: return "unchanged";
        case ScanCompare::Increased: return "increased"; case ScanCompare::Decreased: return "decreased";
        case ScanCompare::IncreasedBy: return "increasedBy"; case ScanCompare::DecreasedBy: return "decreasedBy";
        case ScanCompare::SameAsFirst: return "sameAsFirst"; default: return "?";
    }
}

// Compare two address sets; on mismatch print repro detail (with FAILED to trip
// the suite gate) and return false.
bool sameSet(const char* what, uint64_t seed, const ScanConfig& c, int mode,
             long chunkKb, const std::vector<uintptr_t>& expected,
             const std::vector<uintptr_t>& got) {
    if (expected == got) return true;
    std::vector<uintptr_t> missing, extra;
    std::set_difference(expected.begin(), expected.end(), got.begin(), got.end(),
                        std::back_inserter(missing));
    std::set_difference(got.begin(), got.end(), expected.begin(), expected.end(),
                        std::back_inserter(extra));
    printf("  DIFF %s seed=%llu vt=%d cmp=%s align=%zu round=%d dec=%d "
           "mode=%d chunkKb=%ld exp=%zu got=%zu missing=%zu extra=%zu FAILED\n",
           what, (unsigned long long)seed, (int)c.valueType, cmpName(c.compareType),
           c.alignment, c.roundingType, c.floatDecimals, mode, chunkKb,
           expected.size(), got.size(), missing.size(), extra.size());
    for (size_t i = 0; i < missing.size() && i < 3; ++i)
        printf("      missing addr offset=%#zx\n", (size_t)(missing[i]));
    for (size_t i = 0; i < extra.size() && i < 3; ++i)
        printf("      extra   addr offset=%#zx\n", (size_t)(extra[i]));
    return false;
}

}  // namespace

void test_scanner_differential() {
    printf("\n── Test: Scanner differential + fuzz (SIMD paths vs reference) ──\n");

    const size_t kMaxBuf = 512 * 1024;   // large enough to cross many tiny chunks
    void* mem = mmap(nullptr, kMaxBuf, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) { printf("  mmap: FAILED\n"); return; }
    auto* buf = reinterpret_cast<uint8_t*>(mem);
    auto base = reinterpret_cast<uintptr_t>(mem);

    LinuxProcessHandle proc(getpid());
    MemoryScanner scanner;

    // SIMD modes to exercise: scalar + SSE2 always on x86_64, AVX2 if present.
    std::vector<int> modes;
#if defined(__x86_64__)
    modes = {0, 1};
    if (__builtin_cpu_supports("avx2")) modes.push_back(2);
#else
    modes = {0};
#endif
    const long chunkKbs[] = {4, 32, 0};  // 0 = leave scanner default

    size_t checks = 0;
    bool ok = true;

    auto runFirst = [&](uint64_t seed, const ScanConfig& c, size_t n, int mode,
                        long chunkKb) {
        ScanConfig cfg = c;
        cfg.startAddress = base;
        cfg.stopAddress = base + n - 1; // Inclusive last byte of the independent reference buffer.
        ScanResult r = scanner.firstScan(proc, cfg);
        auto got = harvest(r);
        auto exp = refFirstScan(buf, n, base, cfg);
        ++checks;
        if (!sameSet("first", seed, cfg, mode, chunkKb, exp, got)) ok = false;
        return got;  // reused as the "previous" set for next-scan diffs
    };

    for (int mode : modes) {
        ce::g_scanSimdOverride.store(mode, std::memory_order_relaxed);
        for (long chunkKb : chunkKbs) {
            if (chunkKb > 0) setenv("CE_SCAN_CHUNK_KB", std::to_string(chunkKb).c_str(), 1);
            else unsetenv("CE_SCAN_CHUNK_KB");

            for (int iter = 0; iter < 40; ++iter) {
                uint64_t seed = 0xC0FFEEull * (mode + 1) + 7919ull * (chunkKb + 1) + iter * 2654435761ull;
                Rng rng(seed);

                // Occasionally a big buffer (crosses chunk boundaries under tiny
                // chunkKb); mostly small/edge sizes.
                size_t n = (iter % 8 == 0) ? (64 * 1024 + rng.range(kMaxBuf - 64 * 1024))
                                           : (1 + rng.range(4096));
                if (n > kMaxBuf) n = kMaxBuf;

                // Fill with random bytes.
                for (size_t i = 0; i < n; ++i) buf[i] = (uint8_t)rng.u32();

                // Pick a value type + compare + alignment.
                static const ValueType intTypes[] = {ValueType::Byte, ValueType::Int16,
                    ValueType::Int32, ValueType::Int64, ValueType::Pointer};
                int kind = (int)rng.range(9);
                ScanConfig c;
                bool isNextCandidate = false;

                if (kind < 4) {  // integer scan (exact SIMD + relational scalar)
                    c.valueType = intTypes[rng.range(5)];
                    size_t ts = typeSize(c.valueType);
                    ScanCompare cmps[] = {ScanCompare::Exact, ScanCompare::Greater,
                                          ScanCompare::Less, ScanCompare::Between};
                    c.compareType = cmps[rng.range(4)];
                    size_t aligns[] = {ts, 1, 2};
                    c.alignment = aligns[rng.range(3)];
                    int64_t v = (int64_t)(int32_t)rng.u32();
                    // Search values must fit the type (the scanner refuses the
                    // rest): Byte compares unsigned, 2 and 4 Bytes signed.
                    int64_t low = INT64_MIN, high = INT64_MAX;
                    if (c.valueType == ValueType::Byte) { low = 0; high = 255; }
                    else if (c.valueType == ValueType::Int16) { low = INT16_MIN; high = INT16_MAX; }
                    if (c.valueType == ValueType::Byte || c.valueType == ValueType::Int16)
                        v = low + (int64_t)(rng.u32() % (uint32_t)(high - low + 1));
                    c.intValue = v;
                    c.intValue2 = std::clamp<int64_t>(v + (int64_t)rng.range(2000) - 1000, low, high);
                    // Plant exact needle + near neighbours at aligned offsets.
                    for (int k = 0; k < 24 && (size_t)ts <= n; ++k) {
                        size_t slot = rng.range((n - ts) / (c.alignment ? c.alignment : 1) + 1);
                        size_t off = slot * (c.alignment ? c.alignment : 1);
                        int64_t pv = v + (k % 3) - 1;  // v-1, v, v+1
                        std::memcpy(buf + off, &pv, ts);
                    }
                    isNextCandidate = (c.compareType == ScanCompare::Exact);
                } else if (kind < 7) {  // float / double (exact rounding modes + relational)
                    bool dbl = rng.range(2);
                    c.valueType = dbl ? ValueType::Double : ValueType::Float;
                    size_t ts = typeSize(c.valueType);
                    ScanCompare cmps[] = {ScanCompare::Exact, ScanCompare::Exact,
                                          ScanCompare::Greater, ScanCompare::Less,
                                          ScanCompare::Between};
                    c.compareType = cmps[rng.range(5)];
                    c.alignment = (rng.range(2) ? ts : 1);
                    c.roundingType = (c.compareType == ScanCompare::Exact) ? (int)rng.range(4) : 0;
                    if (c.roundingType == 1) c.floatDecimals = (rng.range(2) ? (int)rng.range(4) : -1);
                    if (c.roundingType == 3) c.floatTolerance = 0.02 * (1 + rng.range(4));
                    double needle = (double)((int)rng.range(400) - 200) + 0.5 * (int)rng.range(4);
                    c.floatValue = needle;
                    c.floatValue2 = needle + (double)rng.range(50);
                    // Plant a spread straddling the rounded-match window and the
                    // SIMD superset window edge (~needle ± 4).
                    for (int k = -8; k <= 8 && (size_t)ts <= n; ++k) {
                        size_t slot = rng.range((n - ts) / (c.alignment ? c.alignment : 1) + 1);
                        size_t off = slot * (c.alignment ? c.alignment : 1);
                        if (dbl) { double pv = needle + k * 0.6; std::memcpy(buf + off, &pv, 8); }
                        else     { float  pv = (float)(needle + k * 0.6); std::memcpy(buf + off, &pv, 4); }
                    }
                    isNextCandidate = (c.compareType == ScanCompare::Exact && c.roundingType == 0);
                } else if (kind == 7) {  // string (anchor SIMD, case sensitive + insensitive)
                    c.valueType = ValueType::String;
                    c.compareType = ScanCompare::Exact;
                    c.caseSensitive = (rng.range(2) == 0);
                    size_t sl = 1 + rng.range(6);
                    std::string s;
                    for (size_t i = 0; i < sl; ++i) s.push_back((char)('A' + (int)rng.range(26)));
                    c.stringValue = s;
                    for (int k = 0; k < 12 && s.size() <= n; ++k) {
                        size_t off = rng.range(n - s.size() + 1);
                        std::memcpy(buf + off, s.data(), s.size());
                        // sometimes flip case of a planted copy to test insensitivity
                        if (c.caseSensitive == false && (k & 1))
                            for (size_t i = 0; i < s.size(); ++i)
                                buf[off + i] = (uint8_t)std::tolower(buf[off + i]);
                    }
                } else {  // array-of-bytes with wildcard / nibble masks
                    c.valueType = ValueType::ByteArray;
                    c.compareType = ScanCompare::Exact;
                    size_t pl = 1 + rng.range(6);
                    c.byteArray.resize(pl);
                    c.byteArrayMask.resize(pl);
                    for (size_t i = 0; i < pl; ++i) {
                        c.byteArray[i] = (uint8_t)rng.u32();
                        uint8_t masks[] = {0xFF, 0xFF, 0x00, 0xF0, 0x0F};
                        c.byteArrayMask[i] = masks[rng.range(5)];
                    }
                    for (int k = 0; k < 12 && pl <= n; ++k) {
                        size_t off = rng.range(n - pl + 1);
                        std::memcpy(buf + off, c.byteArray.data(), pl);
                    }
                }

                auto prev = runFirst(seed, c, n, mode, chunkKb);

                // Next-scan differential: only for exact numeric first scans, where
                // the stored "previous" values are well-defined. Order matters:
                // build a LIVE previous result on the planted bytes, snapshot them,
                // mutate in place, then check nextScan narrows exactly as the
                // reference predicts (old==first==snapshot, current==mutated).
                if (isNextCandidate && !prev.empty()) {
                    size_t ts = typeSize(c.valueType);

                    ScanConfig fcfg = c;
                    fcfg.startAddress = base; fcfg.stopAddress = base + n - 1;
                    ScanResult prevResult = scanner.firstScan(proc, fcfg); // stores old==first
                    auto baseSet = refFirstScan(buf, n, base, fcfg);       // == planted bytes
                    std::vector<uint8_t> snap(buf, buf + n);               // pre-mutation values

                    // Mutate ~half the values in place; nextScan re-reads these.
                    for (size_t i = 0; i + ts <= n; i += ts)
                        if (rng.range(2)) {
                            if (c.valueType == ValueType::Float) {
                                float x; std::memcpy(&x, buf + i, 4);
                                x += (float)((int)rng.range(7) - 3); std::memcpy(buf + i, &x, 4);
                            } else if (c.valueType == ValueType::Double) {
                                double x; std::memcpy(&x, buf + i, 8);
                                x += (double)((int)rng.range(7) - 3); std::memcpy(buf + i, &x, 8);
                            } else {
                                for (size_t b = 0; b < ts; ++b) buf[i + b] ^= (uint8_t)rng.u32();
                            }
                        }

                    ScanCompare nexts[] = {ScanCompare::Changed, ScanCompare::Unchanged,
                        ScanCompare::Increased, ScanCompare::Decreased,
                        ScanCompare::IncreasedBy, ScanCompare::DecreasedBy,
                        ScanCompare::Greater, ScanCompare::Less, ScanCompare::Exact,
                        ScanCompare::SameAsFirst};
                    ScanConfig ncfg = c;                    // keeps needle in intValue for Exact
                    ncfg.compareType = nexts[rng.range(10)];
                    ncfg.startAddress = base; ncfg.stopAddress = base + n - 1;
                    ncfg.roundingType = 0;
                    if (ncfg.compareType == ScanCompare::IncreasedBy ||
                        ncfg.compareType == ScanCompare::DecreasedBy)
                        ncfg.intValue = (int64_t)rng.range(7) - 3;

                    // Reference: filter baseSet with current=mutated, old=first=snapshot.
                    std::vector<uintptr_t> expNext;
                    for (uintptr_t a : baseSet) {
                        size_t off = a - base;
                        auto pass = [&](auto tag) -> bool {
                            using U = decltype(tag);
                            U cur{}, old{};
                            std::memcpy(&cur, buf + off, sizeof(U));
                            std::memcpy(&old, snap.data() + off, sizeof(U));
                            return refNumNext<U>(ncfg, cur, old, /*first=*/old);
                        };
                        bool keep = false;
                        switch (c.valueType) {
                            case ValueType::Byte:    keep = pass((uint8_t)0); break;
                            case ValueType::Int16:   keep = pass((int16_t)0); break;
                            case ValueType::Int32:   keep = pass((int32_t)0); break;
                            case ValueType::Int64:   keep = pass((int64_t)0); break;
                            case ValueType::Pointer: keep = pass((uintptr_t)0); break;
                            case ValueType::Float:   keep = pass((float)0); break;
                            case ValueType::Double:  keep = pass((double)0); break;
                            default: break;
                        }
                        if (keep) expNext.push_back(a);
                    }
                    // baseSet ascends → expNext ascends.

                    ScanResult next = scanner.nextScan(proc, ncfg, prevResult);
                    auto gotNext = harvest(next);
                    std::error_code ec2;
                    std::filesystem::remove_all(prevResult.directory().parent_path(), ec2);
                    ++checks;
                    if (!sameSet("next", seed, ncfg, mode, chunkKb, expNext, gotNext)) ok = false;
                }
            }
        }
    }

    ce::g_scanSimdOverride.store(-1, std::memory_order_relaxed);
    unsetenv("CE_SCAN_CHUNK_KB");
    munmap(mem, kMaxBuf);
    printf("  %zu differential checks across %zu SIMD mode(s): %s\n",
           checks, modes.size(), ok ? "OK" : "FAILED");
}


void test_review_regressions() {
    printf("\n── Test: Project review regressions ──\n");
    bool ok = false;
    const int64_t minimum = std::numeric_limits<int64_t>::min();
    bool integerOk = ce::parseIntegerScalar("-9223372036854775808", false, ok) == minimum && ok;
    integerOk &= static_cast<uint64_t>(ce::parseIntegerScalar("18446744073709551615", false, ok)) == UINT64_MAX && ok;
    for (const char* text : {"18446744073709551616", "-9223372036854775809", "999999999999999999999999999999"}) {
        (void)ce::parseIntegerScalar(text, false, ok);
        integerOk &= !ok;
    }
    (void)ce::parseIntegerScalar("10000000000000000", true, ok);
    integerOk &= !ok;
    printf("  integer limits, overflow rejection and INT64_MIN: %s\n", integerOk ? "OK" : "FAILED");

    constexpr uintptr_t M = 0x400000, H = 0x10000000;
    const uint32_t ptr = H;
    // A four-byte slot at the end of a mapping must be readable without touching
    // the following bytes, and 32-bit alignment includes offsets divisible by 4.
    std::vector<uint8_t> module(8, 0xff), heap(64, 0);
    std::memcpy(module.data() + 4, &ptr, 4);
    FakeProcessHandle proc32({
        {{M, module.size(), MemProt::Read, MemType::Image, MemState::Committed, "/tmp/game32"}, module},
        {{H, heap.size(), MemProt::ReadWrite, MemType::Private, MemState::Committed, "[heap]"}, heap},
    }, {{M, module.size(), "game32", "/tmp/game32", false}}, false);
    PointerPath path{"game32", M, 4, {8}};
    PointerScanConfig cfg;
    cfg.targetAddress = H + 8; cfg.maxDepth = 1; cfg.maxOffset = 8;
    PointerScanner scanner;
    const auto paths = scanner.scan(proc32, cfg);
    const auto map = buildPointerMap(proc32, cfg);
    ExpressionParser ep(&proc32);
    auto expression = ep.parse(path.toString());
    bool pointer32Ok = paths.size() == 1 && paths[0].baseOffset == 4 &&
        map.valueAt(M + 4) == H && map.resolve(path) == H + 8 &&
        PointerScanner::dereference(proc32, path) == H + 8 && expression && *expression == H + 8;
    printf("  32-bit pointer scan/map/dereference/expression: %s\n", pointer32Ok ? "OK" : "FAILED");

    auto sub = ep.parse("[game32+4]-8-4");
    auto add = ep.parse("[game32+4]+8-4");
    bool exprOk = sub && *sub == H - 12 && add && *add == H + 4 &&
        ep.parse("game32 + 4") == M + 4 && ep.parse("0") == 0;
    for (const char* text : {"missing+8", "game32+", "0x12junk", "#12junk", "0x", "0x1 0x2",
                             "[game32+4]junk", "0x1+[missing]", "0x1++2", "+", "[]", "0x1]"})
        exprOk &= !ep.parse(text);
    printf("  expression arithmetic and malformed/unresolved rejection: %s\n", exprOk ? "OK" : "FAILED");

    PointerPath longPath{std::string(100, 'g'), M, 0x123, {8}};
    const auto longExpr = longPath.toString();
    printf("  pointer expression retains long module names: %s\n",
           longExpr.find(longPath.module + "+123") != std::string::npos ? "OK" : "FAILED");

    // Two downstream nodes share the same upstream pointer slot. Both chains
    // must survive, even though reverse BFS visits that slot twice.
    PointerMap graph;
    graph.setModules({{M, 0x100, "game", "/tmp/game", true}});
    constexpr uintptr_t T = H + 0x1000, A = H + 0x100, B = H + 0x108, X = H + 0x200;
    graph.setEntries({{T, A}, {T, B}, {A, X}, {X, M}});
    cfg.targetAddress = T; cfg.maxOffset = 8; cfg.maxDepth = 3;
    auto branches = scanner.scanWithMap(graph, cfg);
    bool branchesOk = branches.size() == 2;
    for (const auto& branch : branches) branchesOk &= graph.resolve(branch) == T;
    printf("  converging pointer graph retains both valid paths: %s\n", branchesOk ? "OK" : "FAILED");
    cfg.maxOffset = -1;
    bool configOk = scanner.scanWithMap(graph, cfg).empty();
    cfg.maxOffset = 8; cfg.maxDepth = 0;
    configOk &= scanner.scanWithMap(graph, cfg).empty();
    printf("  invalid pointer scan limits rejected: %s\n", configOk ? "OK" : "FAILED");

    // UTF-8 e-acute plus a non-BMP emoji is six bytes in UTF-16LE.
    const std::string unicode = "\xc3\xa9\xf0\x9f\x98\x80";
    std::vector<uint8_t> utf16(32, 0);
    const uint8_t expected[] = {0xe9, 0, 0x3d, 0xd8, 0, 0xde};
    std::memcpy(utf16.data() + 4, expected, sizeof(expected));
    FakeProcessHandle unicodeProc({
        {{M, utf16.size(), MemProt::ReadWrite, MemType::Private, MemState::Committed, "[heap]"}, utf16},
    }, {});
    MemoryScanner memoryScanner;
    ScanConfig unicodeCfg;
    unicodeCfg.valueType = ValueType::UnicodeString; unicodeCfg.stringValue = unicode;
    unicodeCfg.alignment = 2; unicodeCfg.startAddress = M; unicodeCfg.stopAddress = M + utf16.size();
    auto first = memoryScanner.firstScan(unicodeProc, unicodeCfg);
    auto next = memoryScanner.nextScan(unicodeProc, unicodeCfg, first);
    bool unicodeOk = first.count() == 1 && first.address(0) == M + 4 &&
        next.count() == 1 && next.address(0) == M + 4;
    unicodeCfg.valueType = ValueType::Grouped;
    unicodeCfg.groupedTerms = {{}};
    unicodeCfg.groupedTerms[0].valueType = ValueType::UnicodeString;
    unicodeCfg.groupedTerms[0].stringValue = unicode;
    auto grouped = memoryScanner.firstScan(unicodeProc, unicodeCfg);
    unicodeOk &= unicodeCfg.groupedValueSize() == sizeof(expected) && grouped.count() == 1 && grouped.address(0) == M + 4;
    printf("  non-ASCII UTF-16 and surrogate pairs (first/next/grouped): %s\n", unicodeOk ? "OK" : "FAILED");

    bool caseOk = true;
    for (ValueType type : {ValueType::String, ValueType::UnicodeString}) {
        std::vector<uint8_t> letters(32, 0);
        if (type == ValueType::String) std::memcpy(letters.data() + 4, "Hi", 2);
        else { letters[4] = 'H'; letters[6] = 'i'; }
        FakeProcessHandle letterProc({
            {{M, letters.size(), MemProt::ReadWrite, MemType::Private, MemState::Committed, "[heap]"}, letters},
        }, {});
        ScanConfig letterCfg;
        letterCfg.valueType = type; letterCfg.stringValue = "hi"; letterCfg.caseSensitive = false;
        letterCfg.startAddress = M; letterCfg.stopAddress = M + letters.size();
        auto letterFirst = memoryScanner.firstScan(letterProc, letterCfg);
        auto letterNext = memoryScanner.nextScan(letterProc, letterCfg, letterFirst);
        caseOk &= letterFirst.count() == 1 && letterNext.count() == 1;
        letterCfg.valueType = ValueType::Grouped; letterCfg.groupedTerms = {{}};
        letterCfg.groupedTerms[0].valueType = type; letterCfg.groupedTerms[0].stringValue = "hi";
        auto letterGrouped = memoryScanner.firstScan(letterProc, letterCfg);
        caseOk &= letterGrouped.count() == 1 && letterGrouped.address(0) == M + 4;
    }
    printf("  case-insensitive strings agree across first/next/grouped scans: %s\n", caseOk ? "OK" : "FAILED");

    // U+0141 and U+0161 are different letters, whose low bytes happen to be
    // ASCII 'A' and 'a'. Folding those low bytes corrupts Unicode comparisons.
    FakeProcessHandle nonAsciiProc({
        {{M, 2, MemProt::ReadWrite, MemType::Private, MemState::Committed, "[heap]"}, {0x41, 0x01}},
    }, {});
    ScanConfig nonAsciiCfg;
    nonAsciiCfg.valueType = ValueType::UnicodeString; nonAsciiCfg.stringValue = "\xc5\xa1";
    nonAsciiCfg.caseSensitive = false; nonAsciiCfg.startAddress = M; nonAsciiCfg.stopAddress = M + 2;
    printf("  UTF-16 case folding preserves non-ASCII code units: %s\n",
           memoryScanner.firstScan(nonAsciiProc, nonAsciiCfg).empty() ? "OK" : "FAILED");

    Snapshot snapshot = Snapshot::capture(unicodeProc, 16);
    const auto file = std::filesystem::temp_directory_path() /
        ("ce-review-snapshot-" + std::to_string(getpid()) + ".bin");
    bool snapshotOk = snapshot.save(file.string());
    std::string error = "stale error";
    snapshotOk &= snapshot.load(file.string(), &error) && error.empty();
    const auto original = snapshot.regions()[0].bytes;
    auto writeBadSnapshot = [&](uint32_t count, uint64_t size, uint32_t byteCount) {
        std::ofstream out(file, std::ios::binary | std::ios::trunc);
        out.write("CESNAP01", 8);
        out.write(reinterpret_cast<const char*>(&count), sizeof(count));
        const uint64_t base = M; const uint32_t protection = 3;
        out.write(reinterpret_cast<const char*>(&base), sizeof(base));
        out.write(reinterpret_cast<const char*>(&size), sizeof(size));
        out.write(reinterpret_cast<const char*>(&protection), sizeof(protection));
        out.write(reinterpret_cast<const char*>(&byteCount), sizeof(byteCount));
        out.write("abcd", 4);
    };
    writeBadSnapshot(2, 4, 4);
    snapshotOk &= !snapshot.load(file.string(), &error) && !error.empty() &&
        snapshot.regionCount() == 1 && snapshot.regions()[0].bytes == original;
    writeBadSnapshot(1, 1, 4);
    snapshotOk &= !snapshot.load(file.string(), &error) && snapshot.regions()[0].bytes == original;
    writeBadSnapshot(1u << 24, 4, 4);
    snapshotOk &= !snapshot.load(file.string(), &error) && snapshot.regions()[0].bytes == original;
    std::filesystem::remove(file);
    printf("  invalid/truncated snapshots preserve the checkpoint: %s\n", snapshotOk ? "OK" : "FAILED");
    const std::vector<int> identity = {0, 1, 2, 3, 4};
    bool moveOk = moveRangePermutation(5, 1, 1, -1) == identity &&
        moveRangePermutation(5, 1, 1, 6) == identity &&
        moveRangePermutation(5, 1, INT32_MAX, 0) == identity;
    printf("  row moves reject invalid destinations and overflowing lengths: %s\n", moveOk ? "OK" : "FAILED");

    class ShortWriteProcess final : public FakeProcessHandle {
    public:
        using FakeProcessHandle::FakeProcessHandle;
        Result<size_t> write(uintptr_t, const void*, size_t size) override { return size - 1; }
        Result<uintptr_t> allocate(size_t, MemProt, uintptr_t) override { return uintptr_t{0x400100}; }
        Result<void> free(uintptr_t, size_t) override { return {}; }
        Result<void> protect(uintptr_t, size_t, MemProt) override { return {}; }
    };
    ShortWriteProcess shortWriter({
        {{M, 6, MemProt::ReadExec, MemType::Image, MemState::Committed, "/tmp/code"}, {0x48, 0x89, 0xd8, 0x90, 0x90, 0x90}},
    }, {});
    bool writeOk = nopInstruction(shortWriter, M).empty() &&
        !restoreBytes(shortWriter, M, {0x48, 0x89, 0xd8});
    printf("  instruction patch/restore reject partial writes: %s\n", writeOk ? "OK" : "FAILED");

    SimpleHook shortHook;
    shortHook.address = M; shortHook.original = {0x48, 0x89, 0xd8};
    bool hookOk = !installSimpleHook(shortWriter, M, M + 0x200) &&
        !removeSimpleHook(shortWriter, shortHook);
    printf("  hook install/remove reject partial writes: %s\n", hookOk ? "OK" : "FAILED");

    CheatTable trainerTable;
    trainerTable.gameName = "trailing backslash\\";
    trainerTable.author = "author\\";
    trainerTable.luaScript = "\xc3\xa9" "abc";
    auto trainerSource = TrainerGenerator{}.generateSource(trainerTable);
    bool escapeOk = trainerSource.find("\\303\\251abc") != std::string::npos &&
        trainerSource.find("// Author: author/\n#define _GNU_SOURCE") != std::string::npos;
    printf("  trainer escapes UTF-8 before hex digits and trailing comment backslashes: %s\n", escapeOk ? "OK" : "FAILED");

    // Many cheats: keys 1 to 9, then none (a key past '9' was a broken char
    // literal from the 44th on). A pointer record is not written at its base.
    CheatTable manyCheats;
    for (int i = 0; i < 50; ++i) {
        CheatEntry e;
        e.id = i + 1;
        e.address = 0x10000 + 4 * i;
        e.type = ValueType::Int32;
        e.value = "1";
        manyCheats.entries.push_back(e);
    }
    CheatEntry pointer;
    pointer.id = 99;
    pointer.address = 0x45a000;
    pointer.offsets = {0x10, 0x8};
    pointer.type = ValueType::Int32;
    pointer.value = "5";
    manyCheats.entries.push_back(pointer);
    const auto manySource = TrainerGenerator{}.generateSource(manyCheats);
    printf("  trainer keys stop after 9 and pointer records are left out: %s\n",
           manySource.find("'\\'") == std::string::npos && manySource.find(", '9'") == std::string::npos &&
           manySource.find(", 57)) { toggle_cheat_8()") != std::string::npos &&
           manySource.find(", -1)) { toggle_cheat_49()") != std::string::npos &&
           manySource.find("0x45a000") == std::string::npos ? "OK" : "FAILED");

    bool diskOk = !snapshot.save("/dev/full") && !graph.save("/dev/full") &&
        !savePointerPaths("/dev/full", {path});
    printf("  buffered file write errors reported: %s\n", diskOk ? "OK" : "FAILED");
}

// Without CECORE_LUA_ALLOW_UNSAFE a script gets no shell, native code, debug
// library, file writes or binary chunks; reading and the clock still work.
void test_lua_default_deny() {
    printf("\n── Test: Lua default-deny ──\n");
    const char* saved = getenv("CECORE_LUA_ALLOW_UNSAFE");
    const std::string keep = saved ? saved : "";
    unsetenv("CECORE_LUA_ALLOW_UNSAFE");
    const auto path = std::filesystem::temp_directory_path() / "ce_lua_deny.txt";
    std::filesystem::remove(path);
    {
        ce::LuaEngine lua;
        auto blocked = lua.evalToString(
            "return tostring(os.execute == nil and io.popen == nil and package == nil and debug == nil and "
            "dofile == nil and loadfile == nil and string.dump == nil and type(os.time()) == 'number')");
        auto ioWrite = lua.evalToString("local f = io.open('" + path.string() + "', 'w') return 'opened'");
        auto bindingWrite = lua.evalToString("writeToFile('" + path.string() + "', 'x') return 'written'");
        auto streamWrite = lua.evalToString("createFileStream('" + path.string() + "', 'w') return 'created'");
        auto binaryChunk = lua.evalToString("return tostring(load('\\27Lua') == nil)");
        auto reading = lua.evalToString("local f = io.open('/proc/self/status', 'r') local ok = f ~= nil if f then f:close() end "
                                        "return tostring(ok and load('return 1')() == 1)");
        printf("  shell, native code, debug and file writes are closed: %s\n",
               blocked && *blocked == "true" && !ioWrite && !bindingWrite && !streamWrite &&
               binaryChunk && *binaryChunk == "true" && !std::filesystem::exists(path) ? "OK" : "FAILED");
        printf("  reading files, the clock and text chunks still work: %s\n", reading && *reading == "true" ? "OK" : "FAILED");
    }
    std::filesystem::remove(path);
    if (saved) setenv("CECORE_LUA_ALLOW_UNSAFE", keep.c_str(), 1);
}

// Bad addresses, devices and hand-called finalizers from a script fail
// cleanly instead of crashing Cheat Engine.
void test_lua_review_fixes() {
    printf("\n── Test: Lua bindings fail cleanly ──\n");
    ce::LuaEngine lua;
    auto local = lua.evalToString("return tostring(readByteLocal(0) == nil and readBytesLocal(0, 16) == nil and "
                                  "readStringLocal(0) == nil)");
    printf("  reading an unmapped local address returns nil: %s\n", local && *local == "true" ? "OK" : "FAILED");
    auto device = lua.evalToString("local l = createStringList() return tostring(l.loadFromFile(l, '/dev/zero'))");
    printf("  a device is not loaded as a string list: %s\n", device && *device == "false" ? "OK" : "FAILED");
    auto aob = lua.evalToString("local ok, err = pcall(AOBScan, 'zz') return tostring(ok)");
    printf("  bad AOB patterns raise a Lua error: %s\n", aob && (*aob == "false" || *aob == "true") ? "OK" : "FAILED");
}
