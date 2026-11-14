// cecore_test: the Auto Assembler.
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

void test_autoassembler_data_directive_widths(pid_t pid) {
    printf("\n── Test: AutoAssembler db/dw/dd/dq widths ──\n");

    LinuxProcessHandle proc(pid);
    AutoAssembler aa;

    auto allocResult = proc.allocate(4096, MemProt::All);
    if (!allocResult) {
        printf("  db/dw/dd/dq widths: FAILED\n");
        return;
    }
    uintptr_t addr = *allocResult;

    char script[512];
    snprintf(script, sizeof(script),
        "[ENABLE]\n"
        "%lx:\n"
        "db 01, \"A\"\n"
        "dw 0203\n"
        "dd 04050607\n"
        "dq 08090A0B0C0D0E0F\n",
        addr);

    auto result = aa.execute(proc, script);
    const uint8_t expected[] = {
        0x01, 0x41,
        0x03, 0x02,
        0x07, 0x06, 0x05, 0x04,
        0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08
    };
    uint8_t actual[sizeof(expected)] = {};
    proc.read(addr, actual, sizeof(actual));

    auto badResult = aa.execute(proc,
        "[ENABLE]\n"
        "alloc(widthbad, 16)\n"
        "widthbad:\n"
        "dw 10000\n");

    bool ok = result.success &&
        std::memcmp(actual, expected, sizeof(actual)) == 0 &&
        !badResult.success &&
        badResult.error.find("out of range") != std::string::npos;

    proc.free(addr, 4096);
    printf("  db/dw/dd/dq widths: %s\n", ok ? "OK" : "FAILED");
}

void test_autoassembler_comment_in_string(pid_t pid) {
    printf("\n── Test: AutoAssembler // inside db string ──\n");

    LinuxProcessHandle proc(pid);
    AutoAssembler aa;
    auto allocResult = proc.allocate(4096, MemProt::All);
    if (!allocResult) { printf("  // inside db string: FAILED\n"); return; }
    uintptr_t addr = *allocResult;

    // The "//" here is DATA, not a comment: quote-aware stripping must keep it,
    // else the line truncates to  db "ab  and mis-assembles.
    char script[256];
    snprintf(script, sizeof(script),
        "[ENABLE]\n%lx:\ndb \"ab//cd\",0\n", addr);
    auto result = aa.execute(proc, script);

    const uint8_t expected[] = {'a','b','/','/','c','d',0};
    uint8_t actual[sizeof(expected)] = {};
    proc.read(addr, actual, sizeof(actual));
    bool ok = result.success &&
              std::memcmp(actual, expected, sizeof(expected)) == 0;

    proc.free(addr, 4096);
    printf("  // inside db string: %s\n", ok ? "OK" : "FAILED");
}

// globalalloc is shared by name and outlives the script that made it: another
// script's hook may still use it.
void test_autoassembler_globalalloc_shared(pid_t pid) {
    printf("\n── Test: Auto Assembler globalalloc is shared ──\n");
    LinuxProcessHandle proc(pid);
    AutoAssembler aa;
    // The name is a shared symbol owned by no script (not in either script's
    // undo symbols), so read it from the assembler.
    auto first = aa.execute(proc, "[ENABLE]\nglobalalloc(ce_shared_block,64)\nce_shared_block:\ndd #4242\n[DISABLE]\n");
    const uintptr_t firstAddress = first.success ? aa.resolveSymbol("ce_shared_block") : 0;
    auto second = aa.execute(proc, "[ENABLE]\nglobalalloc(ce_shared_block,64)\n[DISABLE]\n");
    const uintptr_t secondAddress = second.success ? aa.resolveSymbol("ce_shared_block") : 0;
    printf("  a second globalalloc of the name reuses the memory: %s\n",
           firstAddress && firstAddress == secondAddress ? "OK" : ("FAILED: " + first.error + second.error).c_str());
    if (first.success) aa.disable(proc, "[ENABLE]\nglobalalloc(ce_shared_block,64)\n[DISABLE]\n", first.disableInfo);
    // Toggling one script leaves the shared name in place: the next
    // globalalloc still reuses the same block.
    auto third = second.success ? aa.execute(proc, "[ENABLE]\nglobalalloc(ce_shared_block,64)\n[DISABLE]\n") : second;
    printf("  the shared name survives a script's disable: %s\n",
           third.success && aa.resolveSymbol("ce_shared_block") == firstAddress ? "OK" : "FAILED");
    int32_t value = 0;
    auto read = firstAddress ? proc.read(firstAddress, &value, sizeof value) : ce::Result<size_t>(std::unexpected(std::make_error_code(std::errc::invalid_argument)));
    // Mapped (its bytes are restored like any the script wrote, but the
    // memory stays for the other script's hook).
    printf("  disabling the script that made it keeps it mapped: %s\n", read && *read == 4 ? "OK" : "FAILED");
}

// Cheat Engine script conventions and malformed values, against this process.
alignas(16) static uint8_t g_aaScratch[64];
void test_autoassembler_review_fixes() {
    printf("\n── Test: Auto Assembler script conventions ──\n");
    LinuxProcessHandle proc(getpid());
    const auto base = reinterpret_cast<uintptr_t>(g_aaScratch);
    auto run = [&](const std::string& script) { AutoAssembler aa; return aa.execute(proc, script); };
    auto hex = [](uintptr_t value) { char text[32]; snprintf(text, sizeof text, "%lx", static_cast<unsigned long>(value)); return std::string(text); };
    std::memset(g_aaScratch, 0, sizeof g_aaScratch);
    g_aaScratch[0] = 0x48; g_aaScratch[1] = 0x8B;

    // The standard template: defines above [ENABLE], assert(address,bytes),
    // a { } comment, and a nibble wildcard.
    auto shared = run("define(address," + hex(base) + ")\ndefine(bytes,4? 8B)\n{ Cheat Engine template\n  header }\n"
                      "[ENABLE]\nassert(address,bytes)\naddress+10:\ndb 11 { inline note }\n[DISABLE]\n");
    printf("  defines above [ENABLE], assert(address,bytes), { } comments: %s\n",
           shared.success && g_aaScratch[0x10] == 0x11 ? "OK" : ("FAILED: " + shared.error).c_str());
    auto mismatch = run("[ENABLE]\nassert(" + hex(base) + ",4? 8C)\n");
    auto badBytes = run("[ENABLE]\nassert(" + hex(base) + ",48 GG)\n");
    printf("  assert compares nibbles and rejects bad bytes: %s\n", !mismatch.success && !badBytes.success ? "OK" : "FAILED");
    auto missing = run("[ENABLE]\naobscanregion(hook," + hex(base) + "," + hex(base + 32) + ",DE AD BE EF CA FE)\nhook:\ndb 90\n");
    printf("  an aobscan that finds nothing stops the script: %s\n", !missing.success ? "OK" : "FAILED");
    // Disabling runs the [DISABLE] section's Lua (it stops what [ENABLE] started).
    {
        AutoAssembler aa;
        std::vector<std::string> ran;
        aa.setLuaEvaluator([&](const std::string& code) -> std::expected<std::string, std::string> {
            ran.push_back(code); return std::string();
        });
        const std::string script = "[ENABLE]\n{$lua}\nstart()\n{$asm}\n[DISABLE]\n{$lua}\nstop()\n";
        auto enabled = aa.execute(proc, script);
        auto disabled = enabled.success ? aa.disable(proc, script, enabled.disableInfo) : enabled;
        const bool stopped = disabled.success &&
            std::any_of(ran.begin(), ran.end(), [](const std::string& code) { return code.find("stop()") != std::string::npos; });
        printf("  disabling runs the [DISABLE] section's Lua: %s\n", stopped ? "OK" : ("FAILED: " + enabled.error + disabled.error).c_str());
    }
    // readmem copies the code as it was before this script's own writes: the
    // usual hook-then-copy-the-original order.
    g_aaScratch[0x30] = 0xAA; g_aaScratch[0x31] = 0xBB; g_aaScratch[0x32] = 0xCC;
    auto copied = run("[ENABLE]\n" + hex(base + 0x30) + ":\ndb 90 90 90\n" + hex(base + 0x38) + ":\nreadmem(" +
                      hex(base + 0x30) + ",3)\n");
    printf("  readmem copies the bytes from before the script's writes: %s\n",
           copied.success && g_aaScratch[0x38] == 0xAA && g_aaScratch[0x39] == 0xBB && g_aaScratch[0x3A] == 0xCC
               ? "OK" : ("FAILED: " + copied.error).c_str());
    auto negative = run("[ENABLE]\n" + hex(base + 0x20) + ":\ndd -1\ndw #-5\n");
    uint32_t minusOne = 0; uint16_t minusFive = 0;
    std::memcpy(&minusOne, g_aaScratch + 0x20, 4); std::memcpy(&minusFive, g_aaScratch + 0x24, 2);
    printf("  negative data values: %s\n", negative.success && minusOne == 0xFFFFFFFFu && minusFive == 0xFFFB ? "OK" : ("FAILED: " + negative.error).c_str());
    auto garbage = run("[ENABLE]\n" + hex(base + 0x28) + ":\ndq bad_target\n");
    printf("  a data token that is not a number is refused: %s\n", !garbage.success ? "OK" : "FAILED");
    auto fill = run("[ENABLE]\nfillmem(" + hex(base + 0x30) + ",4,CC)\n");
    printf("  fillmem needs no active address: %s\n", fill.success && g_aaScratch[0x33] == 0xCC ? "OK" : ("FAILED: " + fill.error).c_str());

    // The largest float, as the address list shows it, can be written back.
    {
        ce::ValueIoOptions floatOptions;
        auto written = ce::writeTypedValue(proc, base + 0x38, ValueType::Float, "3.4028235e+38", floatOptions);
        float back = 0;
        std::memcpy(&back, g_aaScratch + 0x38, 4);
        auto tooBig = ce::writeTypedValue(proc, base + 0x38, ValueType::Float, "1e39", floatOptions);
        printf("  the largest float round-trips through its text: %s\n",
               written && back == std::numeric_limits<float>::max() && !tooBig ? "OK" : "FAILED");
    }

    // reassemble() of a RIP-relative instruction still reaches the same data.
    static const uint8_t source[8] = {0x8B, 0x05, 0x10, 0x00, 0x00, 0x00, 0x90, 0x90};   // mov eax,[rip+0x10]
    alignas(16) static uint8_t copy[16];
    const auto sourceAddress = reinterpret_cast<uintptr_t>(source);
    auto relocated = run("[ENABLE]\n" + hex(reinterpret_cast<uintptr_t>(copy)) + ":\nreassemble(" + hex(sourceAddress) + ")\n");
    Disassembler decoder(Arch::X86_64);
    auto decoded = decoder.disassemble(reinterpret_cast<uintptr_t>(copy), {copy, sizeof copy}, 1);
    printf("  reassemble keeps a RIP-relative target: %s\n",
           relocated.success && !decoded.empty() && decoded[0].ripTarget == sourceAddress + 6 + 0x10 ? "OK"
           : ("FAILED: " + relocated.error).c_str());
}

// The [DISABLE] section runs as a script before the saved undo restores, and
// the undo keeps what other enabled scripts wrote. Writes to this process's
// own data; allocations in the child.
alignas(16) static uint8_t g_aaDisable[64];
extern "C" { __attribute__((used)) uint8_t cecore_aa_symbol_probe[16]; }
extern "C" { __attribute__((used)) uint8_t cecore_aa_symbol_probe2[16]; }
// A C++ name: the script writes it mangled, the symbol table lists it demangled.
namespace cecore_aa { __attribute__((used)) uint8_t mangled_probe[16]; }
void test_autoassembler_disable_section(pid_t pid) {
    printf("\n── Test: Auto Assembler [DISABLE] section and undo ──\n");
    LinuxProcessHandle proc(getpid()), child(pid);
    const auto base = reinterpret_cast<uintptr_t>(g_aaDisable);
    auto hex = [](uintptr_t value) { char text[32]; snprintf(text, sizeof text, "%lx", static_cast<unsigned long>(value)); return std::string(text); };
    auto value32 = [](size_t offset) { uint32_t value; std::memcpy(&value, g_aaDisable + offset, 4); return value; };
    auto logged = [](const AutoAsmResult& result, const std::string& text) {
        return std::any_of(result.log.begin(), result.log.end(), [&](const std::string& line) { return line.find(text) != std::string::npos; });
    };
    std::memset(g_aaDisable, 0, sizeof g_aaDisable);
    std::vector<std::string> chunks;
    AutoAssembler aa;
    aa.setLuaEvaluator([&](const std::string& code) -> std::expected<std::string, std::string> {
        chunks.push_back(code);
        if (code.find("probe()") != std::string::npos)
            chunks.push_back(aa.resolveSymbol("ce_disable_mem") ? "symbol live" : "symbol gone");
        return std::string(code.starts_with("return (") ? "false" : "");   // every {$if} is false
    });
    auto ran = [&](const std::string& text) {
        return std::any_of(chunks.begin(), chunks.end(), [&](const std::string& chunk) { return chunk.find(text) != std::string::npos; });
    };

    const std::string data = "[ENABLE]\n" + hex(base) + ":\ndd 5\n[DISABLE]\n" + hex(base) + ":\ndd 7\n";
    auto enabled = aa.execute(proc, data);
    const bool patched = enabled.success && value32(0) == 5;
    auto disabled = enabled.success ? aa.disable(proc, data, enabled.disableInfo) : enabled;
    printf("  the [DISABLE] section's writes are applied and kept: %s\n",
           patched && disabled.success && value32(0) == 7 ? "OK" : ("FAILED: " + enabled.error + disabled.error).c_str());

    chunks.clear();
    const std::string named = "[ENABLE]\nalloc(ce_disable_mem,32)\nregistersymbol(ce_disable_mem)\nlabel(ce_stop)\n"
        "ce_disable_mem:\ndd 0\nce_stop:\ndd 0\n"
        "[DISABLE]\n{$lua}\nprobe()\n{$asm}\nce_stop:\ndd 1\ndealloc(ce_disable_mem)\nunregistersymbol(ce_disable_mem)\n";
    enabled = aa.execute(child, named);
    disabled = enabled.success ? aa.disable(child, named, enabled.disableInfo) : enabled;
    printf("  [DISABLE] runs first: its Lua sees the symbols, its code names [ENABLE] labels: %s\n",
           disabled.success && ran("symbol live") && !logged(disabled, "[DISABLE] failed") &&
           aa.resolveSymbol("ce_disable_mem") == 0 ? "OK" : ("FAILED: " + enabled.error + disabled.error).c_str());

    chunks.clear();
    const std::string sectionless = "{$lua}\nonce()\n{$asm}\n" + hex(base + 12) + ":\ndd 3\n";
    enabled = aa.execute(proc, sectionless);
    const bool once = enabled.success && chunks.size() == 1 && value32(12) == 3;
    disabled = enabled.success ? aa.disable(proc, sectionless, enabled.disableInfo) : enabled;
    printf("  a script without sections runs nothing again when disabled: %s\n",
           once && disabled.success && chunks.size() == 1 && value32(12) == 0 ? "OK" : ("FAILED: " + enabled.error + disabled.error).c_str());

    chunks.clear();
    const std::string conditional = "[ENABLE]\n[DISABLE]\n{$if FLAG}\n{$lua}\nskipped()\n{$asm}\n{$endif}\n";
    enabled = aa.execute(proc, conditional);
    disabled = enabled.success ? aa.disable(proc, conditional, enabled.disableInfo) : enabled;
    printf("  {$if} selects what the [DISABLE] section runs: %s\n",
           disabled.success && ran("FLAG") && !ran("skipped()") ? "OK" : ("FAILED: " + enabled.error + disabled.error).c_str());

    chunks.clear();
    const std::string commented = "[ENABLE]\n// {$lua} commented() {$asm}\n" + hex(base + 16) + ":\ndb '{$lua}'\n[DISABLE]\n";
    enabled = aa.execute(proc, commented);
    const bool asText = enabled.success && chunks.empty() && std::memcmp(g_aaDisable + 16, "{$lua}", 6) == 0;
    if (enabled.success) aa.disable(proc, commented, enabled.disableInfo);
    printf("  directives in // comments and strings are text: %s\n",
           asText && aa.check("[ENABLE]\n// {$endif}\n[DISABLE]\n").success ? "OK" : ("FAILED: " + enabled.error).c_str());

    // Two scripts writing the same value: disabling the older one keeps the
    // newer one's value, and the newer one then restores the first original.
    const std::string older = "[ENABLE]\n" + hex(base + 24) + ":\ndd 1\n", newer = "[ENABLE]\n" + hex(base + 24) + ":\ndd 2\n";
    auto first = aa.execute(proc, older);
    auto second = aa.execute(proc, newer);
    auto firstUndo = first.success ? aa.disable(proc, older, first.disableInfo) : first;
    const bool newerKept = firstUndo.success && value32(24) == 2;
    auto secondUndo = second.success ? aa.disable(proc, newer, second.disableInfo) : second;
    printf("  overlapping data patches undo in any order: %s\n",
           newerKept && secondUndo.success && value32(24) == 0 ? "OK" : ("FAILED: " + first.error + second.error + firstUndo.error + secondUndo.error).c_str());

    const std::string global = "[ENABLE]\nglobalalloc(ce_disable_global,64)\nce_disable_global:\ndd #4242\n[DISABLE]\n";
    auto shared = aa.execute(child, global);
    const uintptr_t block = shared.success ? aa.resolveSymbol("ce_disable_global") : 0;
    auto sharedUndo = shared.success ? aa.disable(child, global, shared.disableInfo) : shared;
    uint32_t sharedValue = 0;
    auto sharedRead = block ? child.read(block, &sharedValue, sizeof sharedValue) : ce::Result<size_t>(0);
    printf("  writes into a globalalloc block are not undone: %s\n",
           sharedUndo.success && sharedRead && *sharedRead == 4 && sharedValue == 4242 ? "OK" : ("FAILED: " + shared.error + sharedUndo.error).c_str());

    // A failing script frees the globalalloc block it made and has not yet
    // run its dealloc or unregistersymbol.
    auto owner = aa.execute(child, "[ENABLE]\nalloc(ce_keep_mem,16)\nregistersymbol(ce_keep_mem)\n");
    const uintptr_t keep = owner.success ? aa.resolveSymbol("ce_keep_mem") : 0;
    auto failing = aa.execute(child, "[ENABLE]\nglobalalloc(ce_failed_global,4096)\nunregistersymbol(ce_keep_mem)\n"
                                    "dealloc(ce_keep_mem)\nce_failed_global:\nnot_an_instruction\n");
    uintptr_t failedBlock = 0;
    for (const auto& line : failing.log)
        if (line.starts_with("Allocated ce_failed_global at 0x")) failedBlock = std::stoull(line.substr(32), nullptr, 16);
    uint32_t probe = 0;
    auto kept = keep ? child.read(keep, &probe, sizeof probe) : ce::Result<size_t>(0);
    auto freed = failedBlock ? child.read(failedBlock, &probe, sizeof probe) : ce::Result<size_t>(4);
    printf("  a failed script keeps its dealloc targets and frees its new globalalloc: %s\n",
           !failing.success && kept && *kept == 4 && aa.resolveSymbol("ce_keep_mem") == keep && failedBlock &&
           (!freed || *freed == 0) && aa.resolveSymbol("ce_failed_global") == 0 ? "OK" : "FAILED");
    if (owner.success) aa.disable(child, "", owner.disableInfo);

    // A target symbol written as "name:" is that address, not a new label.
    std::memset(cecore_aa_symbol_probe, 0, sizeof cecore_aa_symbol_probe);
    auto symbolTarget = aa.execute(proc, "[ENABLE]\ncecore_aa_symbol_probe:\ndb 5A\n");
    printf("  \"symbol:\" addresses a target symbol: %s\n",
           symbolTarget.success && cecore_aa_symbol_probe[0] == 0x5A ? "OK" : ("FAILED: " + symbolTarget.error).c_str());
    if (symbolTarget.success) aa.disable(proc, "", symbolTarget.disableInfo);
    auto localLabel = aa.execute(proc, "[ENABLE]\n" + hex(base + 40) + ":\njmp cecore_aa_symbol_probe\n"
                                       "cecore_aa_symbol_probe:\ndb 90\n");
    printf("  a name the code jumps to stays a local label: %s\n",
           localLabel.success && cecore_aa_symbol_probe[0] == 0 && g_aaDisable[40] == 0xEB && g_aaDisable[42] == 0x90
               ? "OK" : ("FAILED: " + localLabel.error).c_str());
    if (localLabel.success) aa.disable(proc, "", localLabel.disableInfo);

    // Two target symbols patched in a row: the second is its own address, not
    // a label after the first patch. A syntax check cannot know and says so.
    std::memset(cecore_aa_symbol_probe, 0, sizeof cecore_aa_symbol_probe);
    std::memset(cecore_aa_symbol_probe2, 0, sizeof cecore_aa_symbol_probe2);
    const std::string inRow = "[ENABLE]\ncecore_aa_symbol_probe:\ndb 5A\ncecore_aa_symbol_probe2:\ndb 6B\n";
    auto rowPatched = aa.execute(proc, inRow);
    const auto rowChecked = aa.check(inRow);
    printf("  target symbols patched one after another are each their own address: %s\n",
           rowPatched.success && cecore_aa_symbol_probe[0] == 0x5A && cecore_aa_symbol_probe[1] == 0 &&
           cecore_aa_symbol_probe2[0] == 0x6B && rowChecked.success && logged(rowChecked, "Decided at inject time")
               ? "OK" : ("FAILED: " + rowPatched.error + rowChecked.error).c_str());
    if (rowPatched.success) aa.disable(proc, "", rowPatched.disableInfo);
    std::memset(cecore_aa::mangled_probe, 0, sizeof cecore_aa::mangled_probe);
    auto mangled = aa.execute(proc, "[ENABLE]\n" + hex(base + 48) + ":\ndb 01\n_ZN9cecore_aa13mangled_probeE:\ndb 5A\n");
    printf("  a mangled C++ name is the target's symbol: %s\n",
           mangled.success && cecore_aa::mangled_probe[0] == 0x5A && g_aaDisable[49] == 0
               ? "OK" : ("FAILED: " + mangled.error).c_str());
    if (mangled.success) aa.disable(proc, "", mangled.disableInfo);

    // A name only the C runtime defines stays a label. Data labels in a cave
    // that share a libc name ("index:" used as index+4, "time:") stay there.
    const std::string cave = "[ENABLE]\nalloc(ce_label_mem,64)\nce_label_mem:\ndq index+4\n"
                             "index:\ndq 0\ntime:\ndd 0\n[DISABLE]\ndealloc(ce_label_mem)\n";
    auto caveLabels = aa.execute(child, cave);
    auto inCave = [&](const char* name) {
        const auto& info = caveLabels.disableInfo;
        auto found = info.scriptSymbols.find(name);
        return found != info.scriptSymbols.end() && !info.allocs.empty() && found->second > info.allocs[0].address &&
               found->second < info.allocs[0].address + info.allocs[0].size;
    };
    printf("  a data label with a libc name stays in the cave: %s\n",
           caveLabels.success && inCave("index") && inCave("time") && aa.check(cave).success
               ? "OK" : ("FAILED: " + caveLabels.error).c_str());
    if (caveLabels.success) aa.disable(child, cave, caveLabels.disableInfo);
    auto libcSite = aa.execute(child, "[ENABLE]\nexit:\ndb 90\n");
    printf("  an undeclared hook site never patches the C library: %s\n",
           !libcSite.success && libcSite.error.find("C library") != std::string::npos ? "OK" : ("FAILED: " + libcSite.error).c_str());
    if (libcSite.success) aa.disable(child, "", libcSite.disableInfo);

    // A hook site named as the alloc's near address, or written after the
    // cave's code, is the target's function; [DISABLE] names the same
    // address. The target is a copy of this program, whose main module has
    // cecore_aa_symbol_probe.
    auto spawn = [] {
        const pid_t copy = fork();
        if (copy == 0) {
            prctl(PR_SET_PDEATHSIG, SIGKILL);
            for (;;) pause();
        }
        return copy;
    };
    std::memset(cecore_aa_symbol_probe, 0, sizeof cecore_aa_symbol_probe);
    const pid_t copyPid = spawn();
    LinuxProcessHandle copy(copyPid);
    const auto probeAddress = reinterpret_cast<uintptr_t>(cecore_aa_symbol_probe);
    auto probeByte = [&] { uint8_t value = 0xAA; (void)copy.read(probeAddress, &value, 1); return value; };
    const std::string nearHook = "[ENABLE]\nalloc(ce_hook_mem,64,cecore_aa_symbol_probe)\nce_hook_mem:\nret\n"
        "cecore_aa_symbol_probe:\njmp ce_hook_mem\n[DISABLE]\ncecore_aa_symbol_probe:\ndb 11\ndealloc(ce_hook_mem)\n";
    auto hooked = aa.execute(copy, nearHook);
    const uint8_t hookByte = probeByte();
    auto unhooked = hooked.success ? aa.disable(copy, nearHook, hooked.disableInfo) : hooked;
    printf("  alloc's near address names a hook site, also in [DISABLE]: %s\n",
           hooked.success && (hookByte == 0xE9 || hookByte == 0xFF) && unhooked.success &&
           !logged(unhooked, "[DISABLE] failed") && probeByte() == 0x11
               ? "OK" : ("FAILED: " + hooked.error + unhooked.error).c_str());
    const uint8_t zero = 0;
    (void)copy.write(probeAddress, &zero, 1);
    const std::string jumpHook = "[ENABLE]\nalloc(ce_hook_jmp,64," + hex(base) + ")\nce_hook_jmp:\nret\n"
        "cecore_aa_symbol_probe:\njmp ce_hook_jmp\n";
    auto jumped = aa.execute(copy, jumpHook);
    const uint8_t jumpByte = probeByte();
    if (jumped.success) aa.disable(copy, "", jumped.disableInfo);
    printf("  a hook site after the cave's code is the target's function: %s\n",
           jumped.success && (jumpByte == 0xE9 || jumpByte == 0xFF) && probeByte() == 0
               ? "OK" : ("FAILED: " + jumped.error).c_str());
    // Two hooks around one cave: the second jumps to a label inside it.
    const auto probe2Address = reinterpret_cast<uintptr_t>(cecore_aa_symbol_probe2);
    auto probe2Byte = [&] { uint8_t value = 0xAA; (void)copy.read(probe2Address, &value, 1); return value; };
    (void)copy.write(probe2Address, &zero, 1);
    const std::string twoHooks = "[ENABLE]\nalloc(ce_shared_cave,64,cecore_aa_symbol_probe)\nce_shared_cave:\nret\n"
        "ce_second_entry:\nret\ncecore_aa_symbol_probe:\njmp ce_shared_cave\n"
        "cecore_aa_symbol_probe2:\njmp ce_second_entry\n";
    auto both = aa.execute(copy, twoHooks);
    const uint8_t firstHook = probeByte(), secondHook = probe2Byte();
    if (both.success) aa.disable(copy, "", both.disableInfo);
    const auto entry = both.disableInfo.scriptSymbols.find("ce_second_entry");
    printf("  a second hook that jumps into a shared cave patches its own function: %s\n",
           both.success && (firstHook == 0xE9 || firstHook == 0xFF) && (secondHook == 0xE9 || secondHook == 0xFF) &&
           entry != both.disableInfo.scriptSymbols.end() && !both.disableInfo.allocs.empty() &&
           entry->second == both.disableInfo.allocs[0].address + 1 && probeByte() == 0 && probe2Byte() == 0
               ? "OK" : ("FAILED: " + both.error).c_str());

    // A globalalloc block of another process (a game run that ended) does not
    // keep this process's writes at the same address from being undone. Two
    // fresh copies of this program have the same layout, so the same mapping
    // lands at the same address in both.
    {
        const pid_t otherPid = spawn(), twinPid = spawn();
        LinuxProcessHandle other(otherPid), twin(twinPid);
        bool reaped = false;
        AutoAssembler longLived;
        auto made = longLived.execute(other, "[ENABLE]\nglobalalloc(ce_stale_global,4096)\n");
        const uintptr_t stale = made.success ? longLived.resolveSymbol("ce_stale_global") : 0;
        auto mapped = stale ? twin.allocate(4096, MemProt::All) : ce::Result<uintptr_t>(0);
        if (mapped && *mapped && *mapped != stale) {
            (void)twin.free(*mapped, 4096);
            mapped = twin.allocate(4096, MemProt::All, stale);
        }
        if (!stale || !mapped || *mapped != stale) {
            printf("  a globalalloc block of another process is not shared: SKIPPED (block %lx, twin %lx)\n",
                   static_cast<unsigned long>(stale), static_cast<unsigned long>(mapped ? *mapped : 0));
        } else {
            auto value = [&] { uint32_t v = 1; (void)twin.read(stale, &v, sizeof v); return v; };
            const std::string write = "[ENABLE]\n" + hex(stale) + ":\ndd 5\n";
            auto live = longLived.execute(twin, write);
            const bool written = live.success && value() == 5;
            if (live.success) longLived.disable(twin, "", live.disableInfo);
            const bool restored = written && value() == 0;
            kill(otherPid, SIGKILL);
            waitpid(otherPid, nullptr, 0);
            reaped = true;
            live = longLived.execute(twin, write);   // the block's process is gone: it is forgotten
            const bool forgotten = live.success && longLived.resolveSymbol("ce_stale_global") == 0;
            if (live.success) longLived.disable(twin, "", live.disableInfo);
            printf("  a globalalloc block of another process is not shared: %s\n",
                   restored && forgotten && value() == 0 ? "OK" : ("FAILED: " + made.error + live.error).c_str());
        }
        if (!reaped) { kill(otherPid, SIGKILL); waitpid(otherPid, nullptr, 0); }
        kill(twinPid, SIGKILL);
        waitpid(twinPid, nullptr, 0);
    }
    kill(copyPid, SIGKILL);
    waitpid(copyPid, nullptr, 0);

    // A newer script that restored its bytes but could not free its memory
    // takes no originals from an older script disabled after it.
    {
        struct NoFree final : ProcessHandle {
            std::vector<uint8_t> bytes = std::vector<uint8_t>(0x10000);
            bool refuse = false;
            pid_t pid() const override { return getpid(); }
            bool is64bit() const override { return true; }
            TargetDescription targetDescription() override { return ce::test::x86Target(true, false); }
            Result<size_t> read(uintptr_t at, void* out, size_t n) override {
                if (at > bytes.size() || n > bytes.size() - at) return std::unexpected(std::make_error_code(std::errc::bad_address));
                std::memcpy(out, bytes.data() + at, n); return n;
            }
            Result<size_t> write(uintptr_t at, const void* in, size_t n) override {
                if (at > bytes.size() || n > bytes.size() - at) return std::unexpected(std::make_error_code(std::errc::bad_address));
                std::memcpy(bytes.data() + at, in, n); return n;
            }
            std::vector<MemoryRegion> queryRegions() override {
                return {{0, bytes.size(), MemProt::ReadWrite, MemType::Private, MemState::Committed, ""}};
            }
            std::optional<MemoryRegion> queryRegion(uintptr_t at) override {
                return at < bytes.size() ? std::optional<MemoryRegion>(queryRegions()[0]) : std::nullopt;
            }
            Result<uintptr_t> allocate(size_t, MemProt, uintptr_t) override { return uintptr_t(0x8000); }
            Result<void> free(uintptr_t, size_t) override {
                if (refuse) return std::unexpected(std::make_error_code(std::errc::device_or_resource_busy));
                return {};
            }
            Result<void> protect(uintptr_t, size_t, MemProt) override { return {}; }
            std::vector<ModuleInfo> modules() override { return {}; }
            std::vector<ThreadInfo> threads() override { return {}; }
        } stubborn;
        auto at = [&] { uint32_t value; std::memcpy(&value, stubborn.bytes.data() + 0x100, 4); return value; };
        const std::string olderData = "[ENABLE]\n100:\ndd 1\n";
        const std::string newerData = "[ENABLE]\nalloc(ce_newer_mem,16)\n100:\ndd 2\n";
        AutoAssembler pair;
        auto olderOn = pair.execute(stubborn, olderData);
        auto newerOn = pair.execute(stubborn, newerData);
        stubborn.refuse = true;
        auto newerOff = newerOn.success ? pair.disable(stubborn, "", newerOn.disableInfo) : newerOn;
        const bool newerRestored = olderOn.success && newerOn.success && !newerOff.success && at() == 1;
        stubborn.refuse = false;
        auto olderOff = olderOn.success ? pair.disable(stubborn, "", olderOn.disableInfo) : olderOn;
        printf("  a script with restored bytes takes no handover: %s (%u)\n",
               newerRestored && olderOff.success && at() == 0 ? "OK" : ("FAILED: " + olderOn.error + newerOn.error + olderOff.error).c_str(),
               at());
        if (!newerOff.success) pair.disable(stubborn, "", newerOff.disableInfo);
    }

    // reassemble() relocates the instruction from before the script's writes.
    g_aaDisable[32] = 0x90;
    auto moved = aa.execute(proc, "[ENABLE]\n" + hex(base + 32) + ":\ndb C3\n" + hex(base + 48) + ":\nreassemble(" + hex(base + 32) + ")\n");
    printf("  reassemble copies the instruction from before the script's writes: %s\n",
           moved.success && g_aaDisable[32] == 0xC3 && g_aaDisable[48] == 0x90 ? "OK" : ("FAILED: " + moved.error).c_str());
    if (moved.success) aa.disable(proc, "", moved.disableInfo);

    // An untrusted script carries no Lua or C, nor a refused command, in
    // either section: disabling a saved record runs its [DISABLE] section.
    AutoAssembler restricted;
    restricted.setRestricted(true);
    const bool refused = !restricted.check("[ENABLE]\nnop\n[DISABLE]\n{$lua}\nos.exit()\n").success &&
        !restricted.check("[ENABLE]\nnop\n[DISABLE]\n{$ccode}int x;{$endccode}\n").success &&
        !restricted.check("[ENABLE]\nnop\n[DISABLE]\n{$if os.exit()}\n{$endif}\n").success &&
        !restricted.check("[ENABLE]\nnop\n[DISABLE]\nloadlibrary(/tmp/x.so)\n").success;
    printf("  a restricted check covers the [DISABLE] section: %s\n",
           refused && restricted.check("[ENABLE]\nnop\n[DISABLE]\nnop\n").success ? "OK" : "FAILED");
}

// A PE image whose export table names one function, for a fake Wine module.
static void writeSingleExportPe(const std::filesystem::path& path, const char* name, uint32_t rva) {
    std::vector<uint8_t> f(0x1400, 0);
    auto pU16 = [&](size_t o, uint16_t v) { f[o] = (uint8_t)v; f[o + 1] = (uint8_t)(v >> 8); };
    auto pU32 = [&](size_t o, uint32_t v) { for (int i = 0; i < 4; ++i) f[o + i] = (uint8_t)(v >> (8 * i)); };
    f[0] = 'M'; f[1] = 'Z'; pU32(0x3C, 0x80);
    f[0x80] = 'P'; f[0x81] = 'E';
    pU16(0x84, 0x8664); pU16(0x86, 1); pU16(0x94, 0xF0);
    pU16(0x98, 0x20B);
    pU32(0x104, 2);
    pU32(0x108, 0x1000); pU32(0x10C, 0x100);
    const char* section = ".rdata"; for (int i = 0; i < 6; ++i) f[0x188 + i] = section[i];
    pU32(0x190, 0x1000); pU32(0x194, 0x1000); pU32(0x198, 0x1000); pU32(0x19C, 0x400);
    pU32(0x410, 1); pU32(0x414, 1); pU32(0x418, 1);
    pU32(0x41C, 0x1030); pU32(0x420, 0x1040); pU32(0x424, 0x1050);
    pU32(0x430, rva); pU32(0x440, 0x1060); pU16(0x450, 0);
    std::memcpy(f.data() + 0x460, name, std::min<size_t>(std::strlen(name), 32));
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<char*>(f.data()), (std::streamsize)f.size());
}

// Under Wine or Proton the C runtime is msvcrt.dll, ucrtbase.dll and friends:
// an undeclared cave label "exit:" never lands on their export, and neither
// does a name from a JIT runtime's perf map.
void test_autoassembler_windows_runtime_labels() {
    printf("\n── Test: Auto Assembler labels never patch the Windows C runtime ──\n");
    namespace fs = std::filesystem;
    struct FakeWine final : ProcessHandle {
        std::vector<uint8_t> bytes = std::vector<uint8_t>(0x10000);
        std::vector<ModuleInfo> list;
        pid_t pid() const override { return getpid(); }
        bool is64bit() const override { return true; }
        TargetDescription targetDescription() override { return ce::test::x86Target(true, false); }
        Result<size_t> read(uintptr_t at, void* out, size_t n) override {
            if (at > bytes.size() || n > bytes.size() - at) return std::unexpected(std::make_error_code(std::errc::bad_address));
            std::memcpy(out, bytes.data() + at, n); return n;
        }
        Result<size_t> write(uintptr_t at, const void* in, size_t n) override {
            if (at > bytes.size() || n > bytes.size() - at) return std::unexpected(std::make_error_code(std::errc::bad_address));
            std::memcpy(bytes.data() + at, in, n); return n;
        }
        std::vector<MemoryRegion> queryRegions() override {
            return {{0, bytes.size(), MemProt::All, MemType::Private, MemState::Committed, ""}};
        }
        std::optional<MemoryRegion> queryRegion(uintptr_t at) override {
            return at < bytes.size() ? std::optional<MemoryRegion>(queryRegions()[0]) : std::nullopt;
        }
        Result<uintptr_t> allocate(size_t, MemProt, uintptr_t) override { return uintptr_t(0x8000); }
        Result<void> free(uintptr_t, size_t) override { return {}; }
        Result<void> protect(uintptr_t, size_t, MemProt) override { return {}; }
        std::vector<ModuleInfo> modules() override { return list; }
        std::vector<ThreadInfo> threads() override { return {}; }
    };
    const fs::path pe = fs::temp_directory_path() / ("ce-crt-" + std::to_string(getpid()) + ".dll");
    writeSingleExportPe(pe, "exit", 0x1234);   // the export lands at 0x4000 + 0x1234
    const uintptr_t exitAddress = 0x5234;
    auto withModule = [&](const std::string& name) {
        return std::vector<ModuleInfo>{{0x1000, 0x1000, "game.exe", "", true, {}}, {0x4000, 0x2000, name, pe.string(), true, {}}};
    };
    const std::string cave = "[ENABLE]\nalloc(ce_crt_cave,64)\nce_crt_cave:\ndd 0\nexit:\ndd 0\n";
    const std::string site = "[ENABLE]\nexit:\ndb 90\n";

    // Another DLL of the game that exports "exit" is that function.
    FakeWine helper;
    helper.list = withModule("helper.dll");
    AutoAssembler control;
    auto patched = control.execute(helper, site);
    printf("  a game DLL's export written as \"name:\" is that function: %s\n",
           patched.success && helper.bytes[exitAddress] == 0x90 ? "OK" : ("FAILED: " + patched.error).c_str());

    bool allKept = true;
    std::string failures;
    for (const char* name : {"msvcrt.dll", "MSVCRT.DLL", "msvcrt", "ucrtbase.dll", "api-ms-win-crt-runtime-l1-1-0.dll",
                             "msvcr120.dll", "msvcp140.dll", "vcruntime140_1.dll", "msvcrt.dll.so", "ntdll.dll", "ntdll.dll.so"}) {
        FakeWine wine;
        wine.list = withModule(name);
        AutoAssembler aa;
        auto labelled = aa.execute(wine, cave);
        const auto& info = labelled.disableInfo;
        auto label = info.scriptSymbols.find("exit");
        const bool inCave = labelled.success && label != info.scriptSymbols.end() && label->second > 0x8000 &&
                            label->second < 0x8040 && wine.bytes[exitAddress] == 0;
        auto refused = aa.execute(wine, site);
        const bool siteRefused = !refused.success && refused.error.find("C library") != std::string::npos &&
                                 wine.bytes[exitAddress] == 0;
        if (!inCave || !siteRefused) {
            allKept = false;
            failures += std::string(" ") + name + (inCave ? "" : " (cave: " + labelled.error + ")") +
                        (siteRefused ? "" : " (site: " + refused.error + ")");
        }
    }
    printf("  \"exit:\" stays a cave label beside msvcrt, ucrtbase, msvcp, vcruntime, api-ms-win-crt and ntdll's C exports: %s%s\n",
           allKept ? "OK" : "FAILED:", failures.c_str());

    // ntdll's native API (Nt*, Rtl*, Dbg*) is a hook site, unlike its C exports.
    const fs::path ntPe = fs::temp_directory_path() / ("ce-nt-" + std::to_string(getpid()) + ".dll");
    writeSingleExportPe(ntPe, "NtCeProbe", 0x1234);
    FakeWine native;
    native.list = {{0x1000, 0x1000, "game.exe", "", true, {}}, {0x4000, 0x2000, "ntdll.dll", ntPe.string(), true, {}}};
    AutoAssembler nativeAa;
    auto nativePatched = nativeAa.execute(native, "[ENABLE]\nNtCeProbe:\ndb 90\n");
    printf("  an ntdll native API export written as \"name:\" is that function: %s\n",
           nativePatched.success && native.bytes[exitAddress] == 0x90 ? "OK" : ("FAILED: " + nativePatched.error).c_str());
    // Wine's Unix-side ntdll.so holds no C library: even "exit" there is a hook site.
    FakeWine unixSide;
    unixSide.list = withModule("ntdll.so");
    AutoAssembler unixAa;
    auto unixPatched = unixAa.execute(unixSide, site);
    printf("  an export of Wine's Unix-side ntdll.so written as \"name:\" is that function: %s\n",
           unixPatched.success && unixSide.bytes[exitAddress] == 0x90 ? "OK" : ("FAILED: " + unixPatched.error).c_str());
    // A private Rtlp export is API too, not a C library name.
    writeSingleExportPe(ntPe, "RtlpCeProbe", 0x1234);
    FakeWine privateApi;
    privateApi.list = native.list;
    AutoAssembler privateAa;
    auto privatePatched = privateAa.execute(privateApi, "[ENABLE]\nRtlpCeProbe:\ndb 90\n");
    printf("  a private ntdll export (RtlpXxx) written as \"name:\" is that function: %s\n",
           privatePatched.success && privateApi.bytes[exitAddress] == 0x90 ? "OK" : ("FAILED: " + privatePatched.error).c_str());
    std::error_code ntRemoved;
    fs::remove(ntPe, ntRemoved);

    // A perf map entry of a JIT runtime is never a hook site for a label.
    const std::string map = "/tmp/perf-" + std::to_string(getpid()) + ".map";
    bool jitKept = false;
    std::string jitError;
    if (std::ofstream perf(map); perf) {
        perf << "6000 10 ce_jit_probe\n";
        perf.close();
        FakeWine wine;
        wine.list = withModule("helper.dll");
        AutoAssembler aa;
        auto labelled = aa.execute(wine, "[ENABLE]\nalloc(ce_jit_cave,64)\nce_jit_cave:\ndd 0\nce_jit_probe:\ndd 0\n");
        auto label = labelled.disableInfo.scriptSymbols.find("ce_jit_probe");
        jitKept = labelled.success && label != labelled.disableInfo.scriptSymbols.end() && label->second > 0x8000 &&
                  label->second < 0x8040;
        jitError = labelled.error;
        std::error_code ec;
        fs::remove(map, ec);
    }
    printf("  a JIT perf-map name stays a cave label: %s\n", jitKept ? "OK" : ("FAILED: " + jitError).c_str());
    std::error_code ec;
    fs::remove(pe, ec);
}

void test_autoassembler_nop_fillmem(pid_t pid) {
    printf("\n── Test: AutoAssembler nop/fillmem ──\n");

    LinuxProcessHandle proc(pid);
    auto allocResult = proc.allocate(4096, MemProt::All);
    if (!allocResult) {
        printf("  nop/fillmem: FAILED\n");
        return;
    }
    uintptr_t addr = *allocResult;

    char script[256];
    snprintf(script, sizeof(script),
        "[ENABLE]\n"
        "%lx:\n"
        "nop 3\n"
        "fillmem(%lx+3, 4, CC)\n",
        addr, addr);

    AutoAssembler aa;
    auto result = aa.execute(proc, script);
    uint8_t actual[7] = {};
    proc.read(addr, actual, sizeof(actual));
    const uint8_t expected[] = {0x90, 0x90, 0x90, 0xcc, 0xcc, 0xcc, 0xcc};

    bool ok = result.success && std::memcmp(actual, expected, sizeof(actual)) == 0;
    printf("  nop/fillmem: %s\n", ok ? "OK" : "FAILED");

    // A NOP with an operand is the multi-byte instruction compilers pad with
    // (injection templates relocate it), not a count.
    snprintf(script, sizeof(script), "[ENABLE]\n%lx:\nnop dword ptr [rax+rax]\nnop 2\n", addr);
    auto multiByte = aa.execute(proc, script);
    uint8_t padded[7] = {};
    proc.read(addr, padded, sizeof(padded));
    // Keystone picks a 4-byte hint NOP (0f 18 /4); any 4-byte NOP is right.
    printf("  nop with an operand assembles as an instruction: %s\n",
           multiByte.success && padded[0] == 0x0f && padded[3] == 0x00 && padded[4] == 0x90 && padded[5] == 0x90 ? "OK" : "FAILED");
    // "nop eax" reads like a hex count but is a 3-byte register NOP (Keystone
    // picks 0f 18 e0; 0f 1f c0 is the same), not 0xEAX one-byte NOPs.
    padded[3] = 0xaa;
    (void)proc.write(addr + 3, &padded[3], 1);
    snprintf(script, sizeof(script), "[ENABLE]\n%lx:\nnop eax\n", addr);
    auto registerForm = aa.execute(proc, script);
    proc.read(addr, padded, sizeof(padded));
    printf("  nop with a register assembles as an instruction: %s\n",
           registerForm.success && padded[0] == 0x0f && padded[2] >= 0xc0 && padded[3] == 0xaa ? "OK" : "FAILED");
    proc.free(addr, 4096);
}

void test_autoassembler_try_except(pid_t pid) {
    printf("\n── Test: AutoAssembler try/except ──\n");

    LinuxProcessHandle proc(pid);
    auto allocResult = proc.allocate(4096, MemProt::All);
    if (!allocResult) {
        printf("  try/except regions: FAILED\n");
        return;
    }
    uintptr_t addr = *allocResult;
    uint8_t initial[] = {0xaa, 0xbb};
    proc.write(addr, initial, sizeof(initial));

    char script[512];
    snprintf(script, sizeof(script),
        "[ENABLE]\n"
        "%lx:\n"
        "{$try}\n"
        "assert(%lx, AA)\n"
        "db 11\n"
        "{$except}\n"
        "db 22\n"
        "{$endtry}\n"
        "%lx:\n"
        "{$try}\n"
        "assert(%lx, AA)\n"
        "db 33\n"
        "{$except}\n"
        "db 44\n"
        "{$endtry}\n",
        addr, addr, addr + 1, addr + 1);

    AutoAssembler aa;
    auto result = aa.execute(proc, script);
    uint8_t actual[] = {0, 0};
    proc.read(addr, actual, sizeof(actual));

    auto malformed = aa.check("[ENABLE]\n{$try}\nnop\n{$except}\nnop\n");
    bool sawExceptLog = std::any_of(result.log.begin(), result.log.end(), [](const std::string& line) {
        return line.find("selected {$except} block") != std::string::npos;
    });

    bool ok = result.success &&
        actual[0] == 0x11 &&
        actual[1] == 0x44 &&
        sawExceptLog &&
        !malformed.success &&
        malformed.error.find("Missing {$endtry}") != std::string::npos;

    proc.free(addr, 4096);
    printf("  try/except regions: %s\n", ok ? "OK" : "FAILED");
}

void test_autoassembler_forward_labels(pid_t pid) {
    printf("\n── Test: AutoAssembler forward labels ──\n");

    LinuxProcessHandle proc(pid);
    AutoAssembler aa;

    auto result = aa.execute(proc,
        "[ENABLE]\n"
        "alloc(forwardblock, 512)\n"
        "label(farreturn)\n"
        "registersymbol(forwardblock,farreturn)\n"
        "forwardblock:\n"
        "jmp farreturn\n"
        "nop 200\n"
        "farreturn:\n"
        "ret\n");

    uintptr_t block = aa.resolveSymbol("forwardblock");
    uintptr_t farreturn = aa.resolveSymbol("farreturn");
    uint8_t firstByte = 0;
    uint8_t returnByte = 0;
    if (block)
        proc.read(block, &firstByte, sizeof(firstByte));
    if (farreturn)
        proc.read(farreturn, &returnByte, sizeof(returnByte));

    bool ok = result.success &&
        block != 0 &&
        farreturn == block + 205 &&
        firstByte == 0xe9 &&
        returnByte == 0xc3;

    aa.disable(proc, "", result.disableInfo);
    printf("  forward label sizing: %s\n", ok ? "OK" : "FAILED");

    // CE auto-collects a "name:" label defined later, so a forward jump works
    // WITHOUT an explicit label(name). (Regression guard: this used to fail with
    // KS_ERR_ASM_SYMBOL_MISSING because the sizing pass aborted on the forward ref.)
    auto r2 = aa.execute(proc,
        "[ENABLE]\n"
        "alloc(fwd2, 512)\n"
        "registersymbol(fwd2)\n"
        "fwd2:\n"
        "jmp skiplbl\n"
        "nop 200\n"
        "skiplbl:\n"
        "ret\n");
    uintptr_t fwd2 = aa.resolveSymbol("fwd2");
    uint8_t b0 = 0, bret = 0;
    if (fwd2) { proc.read(fwd2, &b0, 1); proc.read(fwd2 + 205, &bret, 1); }
    bool ok2 = r2.success && fwd2 != 0 && b0 == 0xe9 && bret == 0xc3;
    aa.disable(proc, "", r2.disableInfo);
    printf("  forward named label without label() decl: %s\n", ok2 ? "OK" : "FAILED");

    // dq <label>: a data directive whose value is a label's address (pointer/jump
    // tables). dq tgt at dqmem should store the 64-bit address of tgt (= dqmem+8).
    auto r3 = aa.execute(proc,
        "[ENABLE]\n"
        "alloc(dqmem, 64)\n"
        "registersymbol(dqmem)\n"
        "label(tgt)\n"
        "dqmem:\n"
        "dq tgt\n"
        "tgt:\n"
        "db 90\n");
    uintptr_t dqmem = aa.resolveSymbol("dqmem");
    uint64_t stored = 0;
    if (dqmem) proc.read(dqmem, &stored, sizeof(stored));
    // tgt is a plain label() (not registersymbol'd), so it sits immediately after
    // the 8-byte dq at dqmem+8. dq tgt must have stored that address.
    bool ok3 = r3.success && dqmem != 0 && stored == dqmem + 8;
    aa.disable(proc, "", r3.disableInfo);
    printf("  dq <label> stores the label address: %s\n", ok3 ? "OK" : "FAILED");

    // dq <label>+offset: CE evaluates arithmetic in data values. dq tgt+4 with
    // tgt at dqmem2+8 must store dqmem2+12.
    auto r4 = aa.execute(proc,
        "[ENABLE]\n"
        "alloc(dqmem2, 64)\n"
        "registersymbol(dqmem2)\n"
        "label(tgt2)\n"
        "dqmem2:\n"
        "dq tgt2+4\n"
        "tgt2:\n"
        "db 90\n");
    uintptr_t dqmem2 = aa.resolveSymbol("dqmem2");
    uint64_t stored2 = 0;
    if (dqmem2) proc.read(dqmem2, &stored2, sizeof(stored2));
    bool ok4 = r4.success && dqmem2 != 0 && stored2 == dqmem2 + 12;
    aa.disable(proc, "", r4.disableInfo);
    printf("  dq <label>+offset evaluates arithmetic: %s\n", ok4 ? "OK" : "FAILED");

    // (float)/(double) casts store IEEE-754 bit patterns (patching float consts).
    auto r5 = aa.execute(proc,
        "[ENABLE]\n"
        "alloc(fmem, 32)\n"
        "registersymbol(fmem)\n"
        "fmem:\n"
        "dd (float)1.5\n"
        "dq (double)2.5\n");
    uintptr_t fmem = aa.resolveSymbol("fmem");
    uint32_t fb = 0; uint64_t db = 0;
    if (fmem) { proc.read(fmem, &fb, 4); proc.read(fmem + 4, &db, 8); }
    float fv; std::memcpy(&fv, &fb, 4);
    double dv; std::memcpy(&dv, &db, 8);
    bool ok5 = r5.success && fmem != 0 && fv == 1.5f && dv == 2.5;
    aa.disable(proc, "", r5.disableInfo);
    printf("  dd (float)/dq (double) store IEEE-754 bits: %s\n", ok5 ? "OK" : "FAILED");

    // db string literal containing a comma and a space must not be split on them
    // (splitDataValues is quote-aware): 'db "a, b"' writes the 5 bytes a , SP b.
    auto r6 = aa.execute(proc,
        "[ENABLE]\n"
        "alloc(smem, 16)\n"
        "registersymbol(smem)\n"
        "smem:\n"
        "db \"a, b\"\n");
    uintptr_t smem = aa.resolveSymbol("smem");
    uint8_t sb[8] = {};
    if (smem) proc.read(smem, sb, 5);
    bool ok6 = r6.success && smem != 0 && std::memcmp(sb, "a, b", 4) == 0 && sb[4] == 0;
    aa.disable(proc, "", r6.disableInfo);
    printf("  db string with comma/space not split: %s\n", ok6 ? "OK" : "FAILED");

    // A db string that happens to contain a symbol name must NOT be corrupted by
    // symbol substitution (data directives substitute symbols for dq label refs,
    // but that must not reach inside quoted string literals).
    auto r7 = aa.execute(proc,
        "[ENABLE]\n"
        "alloc(mylabel, 16)\n"       // 'mylabel' becomes a symbol
        "alloc(s2mem, 32)\n"
        "registersymbol(s2mem)\n"
        "s2mem:\n"
        "db \"mylabel\"\n");         // the literal text, not the address
    uintptr_t s2mem = aa.resolveSymbol("s2mem");
    uint8_t s2[16] = {};
    if (s2mem) proc.read(s2mem, s2, 8);
    bool ok7 = r7.success && s2mem != 0 && std::memcmp(s2, "mylabel", 7) == 0 && s2[7] == 0;
    aa.disable(proc, "", r7.disableInfo);
    printf("  db string containing a symbol name not corrupted: %s\n", ok7 ? "OK" : "FAILED");

    // Sizing pass must also be quote-aware: a db string whose text is an
    // UNRESOLVED forward-label name must keep its true length, so the label after
    // it lands at the right offset. db "fwd" is 3 bytes, so fwd: (db 90) is at +3.
    auto r8 = aa.execute(proc,
        "[ENABLE]\n"
        "alloc(s3mem, 64)\n"
        "registersymbol(s3mem)\n"
        "label(fwd)\n"
        "s3mem:\n"
        "db \"fwd\"\n"
        "fwd:\n"
        "db 90\n");
    uintptr_t s3mem = aa.resolveSymbol("s3mem");
    uint8_t s3[8] = {};
    if (s3mem) proc.read(s3mem, s3, 4);
    bool ok8 = r8.success && s3mem != 0 && std::memcmp(s3, "fwd", 3) == 0 && s3[3] == 0x90;
    aa.disable(proc, "", r8.disableInfo);
    printf("  sizing pass quote-aware (db \"fwd\" keeps length): %s\n", ok8 ? "OK" : "FAILED");
}

// File-scope so it lives in this executable's module (patched by module+offset below).
static volatile int aaModuleOffsetProbe = 1337;

void test_autoassembler_module_offset() {
    printf("\n── Test: AA module+offset resolution ──\n");
    // CE tables address memory as "module+offset" (game.exe+1C). Verify the AA
    // resolves a real loaded module's name to its base and patches through it.
    // Patch our OWN global (self-write works without ptrace).
    LinuxProcessHandle proc(getpid());
    uintptr_t gaddr = (uintptr_t)&aaModuleOffsetProbe;
    std::string modName; uintptr_t modBase = 0;
    for (auto& m : proc.modules())
        if (gaddr >= m.base && gaddr < m.base + m.size) { modName = m.name; modBase = m.base; break; }
    bool ok = false;
    if (!modName.empty()) {
        char script[256];
        snprintf(script, sizeof(script), "[ENABLE]\n%s+%lx:\n  dd #9999\n",
                 modName.c_str(), (unsigned long)(gaddr - modBase));
        AutoAssembler aa;
        auto r = aa.execute(proc, script);
        ok = r.success && aaModuleOffsetProbe == 9999;
    }
    aaModuleOffsetProbe = 1337;   // restore
    printf("  AA resolves <module>+offset and patches it: %s\n", ok ? "OK" : "FAILED");
}

void test_autoassembler_code_injection_template(pid_t pid) {
    printf("\n── Test: AA code-injection template pattern ──\n");
    LinuxProcessHandle proc(pid);
    AutoAssembler aa;
    // A 5-byte-plus target instruction to hook (mov eax,1 + padding nops).
    auto setup = aa.execute(proc,
        "[ENABLE]\n"
        "alloc(tgt, 64)\n"
        "registersymbol(tgt)\n"
        "tgt:\n"
        "mov eax, 1\n"
        "nop\nnop\nnop\n");
    uintptr_t tgt = aa.resolveSymbol("tgt");
    bool ok = false;
    if (setup.success && tgt) {
        // The "Code injection (at address)" template pattern, instantiated:
        // alloc a cave, run the stolen code, jmp back; hook the target with jmp cave.
        char script[512];
        snprintf(script, sizeof(script),
            "[ENABLE]\n"
            "alloc(newmem, 0x1000, %lx)\n"
            "label(return)\n"
            "newmem:\n"
            "  mov eax, 1\n"
            "  jmp return\n"
            "%lx:\n"
            "  jmp newmem\n"
            "return:\n",
            (unsigned long)tgt, (unsigned long)tgt);
        AutoAssembler aa2;
        auto rInj = aa2.execute(proc, script);
        uint8_t b = 0;
        if (tgt) proc.read(tgt, &b, 1);
        ok = rInj.success && b == 0xe9;   // target now starts with jmp (0xe9)
        aa2.disable(proc, "", rInj.disableInfo);
    }
    aa.disable(proc, "", setup.disableInfo);
    printf("  code-injection template hooks target with jmp: %s\n", ok ? "OK" : "FAILED");
}

void test_autoassembler_assert(pid_t pid) {
    printf("\n── Test: AutoAssembler assert ──\n");
    LinuxProcessHandle proc(pid);
    AutoAssembler aa;
    auto setup = aa.execute(proc,
        "[ENABLE]\n"
        "alloc(acave, 16)\n"
        "registersymbol(acave)\n"
        "acave:\n"
        "db 90 90 90\n");
    uintptr_t acave = aa.resolveSymbol("acave");
    bool ok = false;
    if (setup.success && acave) {
        char script[256];
        AutoAssembler aa2;
        snprintf(script, sizeof(script), "[ENABLE]\nassert(%lx, 90 90 90)\n", (unsigned long)acave);
        auto rMatch = aa2.execute(proc, script);          // bytes match -> proceed
        AutoAssembler aa3;
        snprintf(script, sizeof(script), "[ENABLE]\nassert(%lx, 11 22 33)\n", (unsigned long)acave);
        auto rMismatch = aa3.execute(proc, script);       // bytes differ -> abort
        ok = rMatch.success && !rMismatch.success &&
             rMismatch.error.find("ASSERT") != std::string::npos;
    }
    aa.disable(proc, "", setup.disableInfo);
    printf("  assert matches -> proceed, mismatch -> abort: %s\n", ok ? "OK" : "FAILED");
}

void test_autoassembler_create_thread() {
    printf("\n── Test: AutoAssembler createthread ──\n");
    NativeCallRegressionFixture fixture;
    if (fixture.pid<=0) { printf("  native call fixture: FAILED\n"); return; }
    LinuxProcessHandle proc(fixture.pid);

    AutoAssembler waitedAssembler;
    auto waited = waitedAssembler.execute(proc,
        "[ENABLE]\n"
        "alloc(waitcode, 512)\n"
        "alloc(waitresult, 8)\n"
        "registersymbol(waitresult)\n"
        "waitresult:\n"
        "dd 0\n"
        "waitcode:\n"
        "mov rax, waitresult\n"
        "mov dword [rax], 0x11223344\n"
        "xor eax, eax\n"
        "ret\n"
        "createthreadandwait(waitcode, 2000)\n");

    uint32_t waitedValue = 0;
    auto waitResultAddr = waitedAssembler.resolveSymbol("waitresult");
    if (waitResultAddr)
        proc.read(waitResultAddr, &waitedValue, sizeof(waitedValue));

    AutoAssembler asyncAssembler;
    auto async = asyncAssembler.execute(proc,
        "[ENABLE]\n"
        "alloc(asynccode, 512)\n"
        "alloc(asyncresult, 8)\n"
        "registersymbol(asyncresult)\n"
        "asyncresult:\n"
        "dd 0\n"
        "asynccode:\n"
        "mov rax, asyncresult\n"
        "mov dword [rax], 0x55667788\n"
        "xor eax, eax\n"
        "ret\n"
        "createthread(asynccode)\n");

    uint32_t asyncValue = 0;
    auto asyncResultAddr = asyncAssembler.resolveSymbol("asyncresult");
    for (int i = 0; i < 100 && asyncResultAddr; ++i) {
        proc.read(asyncResultAddr, &asyncValue, sizeof(asyncValue));
        if (asyncValue == 0x55667788 && proc.threads().size()==2)
            break;
        usleep(10000);
    }

    bool ok = waited.success && waitedValue == 0x11223344 &&
        async.success && asyncValue == 0x55667788 && proc.threads().size()==2;
    if (!waited.success) printf("  waited call error: %s\n",waited.error.c_str());
    if (!async.success) printf("  async call error: %s\n",async.error.c_str());

    waitedAssembler.disable(proc, "", waited.disableInfo);
    asyncAssembler.disable(proc, "", async.disableInfo);
    printf("  createthread/andwait: %s\n", ok ? "OK" : "FAILED");

    // A thread that runs until [DISABLE] sets its stop flag: the section runs
    // before the undo, which waits for the thread to leave the cave.
    AutoAssembler loopAssembler;
    const std::string loop =
        "[ENABLE]\n"
        "alloc(loopcode, 512)\n"
        "label(stop)\n"
        "loopcode:\n"
        "mov rax, stop\n"
        "@@:\n"
        "pause\n"
        "cmp dword [rax], 0\n"
        "je @B\n"
        "xor eax, eax\n"
        "ret\n"
        "stop:\n"
        "dd 0\n"
        "createthread(loopcode)\n"
        "[DISABLE]\n"
        "stop:\n"
        "dd 1\n";
    auto looping = loopAssembler.execute(proc, loop);
    auto stopped = looping.success ? loopAssembler.disable(proc, loop, looping.disableInfo) : looping;
    if (!stopped.success) {
        printf("  stop flag error: %s\n", stopped.error.c_str());
        if (looping.success) loopAssembler.disable(proc, "", stopped.disableInfo);
    }
    printf("  [DISABLE] stops an injected thread before the undo frees its cave: %s\n",
           looping.success && stopped.success ? "OK" : "FAILED");
}

void test_autoassembler_ds(pid_t pid) {
    printf("\n── Test: AutoAssembler ds ──\n");

    LinuxProcessHandle proc(pid);
    auto allocResult = proc.allocate(4096, MemProt::All);
    if (!allocResult) {
        printf("  ds: FAILED\n");
        return;
    }
    uintptr_t addr = *allocResult;

    char script[256];
    snprintf(script, sizeof(script),
        "[ENABLE]\n"
        "%lx:\n"
        "ds \"hello\"\n",
        addr);

    AutoAssembler aa;
    auto result = aa.execute(proc, script);
    char actual[5] = {};
    proc.read(addr, actual, sizeof(actual));

    bool ok = result.success && std::memcmp(actual, "hello", sizeof(actual)) == 0;
    proc.free(addr, 4096);
    printf("  ds: %s\n", ok ? "OK" : "FAILED");
}

void test_autoassembler_custom_commands(pid_t pid) {
    printf("\n── Test: AutoAssembler custom commands ──\n");

    LinuxProcessHandle proc(pid);
    auto allocResult = proc.allocate(4096, MemProt::All);
    if (!allocResult) {
        printf("  custom commands: FAILED\n");
        return;
    }
    uintptr_t addr = *allocResult;

    AutoAssembler aa;
    aa.registerCommand("emitbytes", [](const std::string& args,
        std::vector<std::string>& outputLines, std::vector<std::string>& log, std::string&) {
        outputLines.push_back("db " + args);
        log.push_back("custom emitbytes");
        return true;
    });
    aa.registerCommand("emitnops", [](const std::string& args,
        std::vector<std::string>& outputLines, std::vector<std::string>&, std::string&) {
        outputLines.push_back("nop " + args);
        return true;
    });

    char script[256];
    snprintf(script, sizeof(script),
        "[ENABLE]\n"
        "%lx:\n"
        "EMITBYTES(2A, 2B)\n"
        "emitnops 2\n",
        addr);

    auto result = aa.execute(proc, script);
    uint8_t actual[4] = {};
    proc.read(addr, actual, sizeof(actual));
    const uint8_t expected[] = {0x2a, 0x2b, 0x90, 0x90};

    AutoAssembler failing;
    failing.registerCommand("failcmd", [](const std::string&, std::vector<std::string>&,
        std::vector<std::string>&, std::string& error) {
        error = "failcmd parse error";
        return false;
    });
    auto failedCheck = failing.check("[ENABLE]\nfailcmd()\n");

    bool ok = result.success &&
        std::memcmp(actual, expected, sizeof(actual)) == 0 &&
        !failedCheck.success &&
        failedCheck.error == "failcmd parse error";

    proc.free(addr, 4096);
    printf("  custom commands: %s\n", ok ? "OK" : "FAILED");
}

void test_autoassembler_processing_hooks(pid_t pid) {
    printf("\n── Test: AutoAssembler processing hooks ──\n");

    LinuxProcessHandle proc(pid);
    auto allocResult = proc.allocate(4096, MemProt::All);
    if (!allocResult) {
        printf("  processing hooks: FAILED\n");
        return;
    }
    uintptr_t addr = *allocResult;

    AutoAssembler aa;
    aa.addPreprocessorHook([](std::string& code, std::vector<std::string>& log, std::string&) {
        code += "\nnop 1\n";
        log.push_back("pre-hook");
        return true;
    });
    aa.addPostprocessorHook([](std::string& code, std::vector<std::string>& log, std::string&) {
        code += "\ndb 2A\n";
        log.push_back("post-hook");
        return true;
    });

    char script[128];
    snprintf(script, sizeof(script),
        "[ENABLE]\n"
        "%lx:\n",
        addr);

    auto result = aa.execute(proc, script);
    uint8_t actual[2] = {};
    proc.read(addr, actual, sizeof(actual));
    const uint8_t expected[] = {0x90, 0x2a};

    auto checkResult = aa.check(script);

    AutoAssembler failing;
    failing.addPostprocessorHook([](std::string&, std::vector<std::string>&, std::string& error) {
        error = "post hook parse stop";
        return false;
    });
    auto failedCheck = failing.check("[ENABLE]\nnop 1\n");

    bool ok = result.success &&
        std::memcmp(actual, expected, sizeof(actual)) == 0 &&
        checkResult.success &&
        !failedCheck.success &&
        failedCheck.error == "post hook parse stop";

    proc.free(addr, 4096);
    printf("  processing hooks: %s\n", ok ? "OK" : "FAILED");
}

void test_autoassembler_loadbinary(pid_t pid) {
    printf("\n── Test: AutoAssembler loadbinary ──\n");

    LinuxProcessHandle proc(pid);
    auto allocResult = proc.allocate(4096, MemProt::All);
    if (!allocResult) {
        printf("  loadbinary: FAILED\n");
        return;
    }
    uintptr_t addr = *allocResult;

    auto path = std::filesystem::temp_directory_path() /
        ("cecore-loadbinary-" + std::to_string(getpid()) + ".bin");
    const uint8_t expected[] = {0xde, 0xad, 0xbe, 0xef, 0x42};
    {
        std::ofstream f(path, std::ios::binary);
        f.write(reinterpret_cast<const char*>(expected), sizeof(expected));
    }

    char script[512];
    snprintf(script, sizeof(script),
        "[ENABLE]\n"
        "loadbinary(%lx, \"%s\")\n",
        addr, path.c_str());

    AutoAssembler aa;
    auto result = aa.execute(proc, script);
    uint8_t actual[sizeof(expected)] = {};
    proc.read(addr, actual, sizeof(actual));

    bool ok = result.success && std::memcmp(actual, expected, sizeof(actual)) == 0;
    std::filesystem::remove(path);
    proc.free(addr, 4096);
    printf("  loadbinary: %s\n", ok ? "OK" : "FAILED");
}

void test_autoassembler_loadlibrary() {
    printf("\n── Test: AutoAssembler loadlibrary ──\n");

    auto exePath = std::filesystem::read_symlink("/proc/self/exe");
    auto libraryPath = exePath.parent_path() / "libspeedhack.so";
    if (!std::filesystem::exists(libraryPath)) {
        printf("  loadlibrary: SKIPPED (libspeedhack.so not found)\n");
        return;
    }

    char script[1024];
    snprintf(script, sizeof(script),
        "[ENABLE]\n"
        "loadlibrary(\"%s\")\n",
        libraryPath.c_str());

    NativeCallRegressionFixture fixture;
    if (fixture.pid<=0) { printf("  native call fixture: FAILED\n"); return; }
    LinuxProcessHandle proc(fixture.pid);
    AutoAssembler aa;
    auto result = aa.execute(proc, script);

    bool sawLog = false;
    for (const auto& line : result.log) {
        if (line.find("LOADLIBRARY: ") == 0) {
            sawLog = true;
            break;
        }
    }

    bool ok = result.success && sawLog;
    printf("  loadlibrary: %s\n", ok ? "OK" : "FAILED");
    if (!ok && !result.error.empty())
        printf("    error: %s\n", result.error.c_str());
}

void test_autoassembler_struct_definitions(pid_t pid) {
    printf("\n── Test: AutoAssembler struct definitions ──\n");

    LinuxProcessHandle proc(pid);
    AutoAssembler aa;
    auto result = aa.execute(proc,
        "[ENABLE]\n"
        "struct stackview\n"
        "returnaddress:\n"
        "  dd ?\n"
        "param1:\n"
        "  dq ?\n"
        "param2:\n"
        "  dd ?\n"
        "endstruct\n"
        "alloc(structblock, 4096)\n"
        "structblock:\n"
        "mov eax, stackview.returnaddress\n"
        "mov ebx, param1\n"
        "mov ecx, stackview\n");

    uint8_t actual[15] = {};
    if (result.success && !result.disableInfo.allocs.empty())
        proc.read(result.disableInfo.allocs[0].address, actual, sizeof(actual));

    const uint8_t expected[] = {
        0xb8, 0x00, 0x00, 0x00, 0x00,
        0xbb, 0x04, 0x00, 0x00, 0x00,
        0xb9, 0x10, 0x00, 0x00, 0x00
    };

    bool ok = result.success && std::memcmp(actual, expected, sizeof(expected)) == 0;
    if (result.success)
        aa.disable(proc, "", result.disableInfo);

    printf("  struct definitions: %s\n", ok ? "OK" : "FAILED");
    if (!ok && !result.error.empty())
        printf("    error: %s\n", result.error.c_str());
}

void test_autoassembler_aobscanmodule(pid_t pid) {
    printf("\n── Test: AutoAssembler aobscanmodule ──\n");

    LinuxProcessHandle proc(pid);
    AutoAssembler aa;

    auto result = aa.execute(proc,
        "[ENABLE]\n"
        "aobscanmodule(sleep_elf, sleep, 7F 45 4C 46)\n"
        "registersymbol(sleep_elf)\n");

    bool ok = result.success && aa.resolveSymbol("sleep_elf") != 0;
    printf("  aobscanmodule: %s\n", ok ? "OK" : "FAILED");

    // Wildcard pattern (?? matches the 0x45 'E') must find the same ELF header.
    uintptr_t fixed = aa.resolveSymbol("sleep_elf");
    auto rw = aa.execute(proc,
        "[ENABLE]\n"
        "aobscanmodule(sleep_wild, sleep, 7F ?? 4C 46)\n"
        "registersymbol(sleep_wild)\n");
    uintptr_t wild = aa.resolveSymbol("sleep_wild");
    bool wildOk = rw.success && wild != 0 && wild == fixed;
    printf("  aobscanmodule wildcard (7F ?? 4C 46) finds same addr: %s\n", wildOk ? "OK" : "FAILED");
}

void test_autoassembler_aobscanregion(pid_t pid) {
    printf("\n── Test: AutoAssembler aobscanregion ──\n");

    LinuxProcessHandle proc(pid);
    auto modules = proc.modules();
    auto sleepModule = std::find_if(modules.begin(), modules.end(), [](const ModuleInfo& module) {
        return module.name == "sleep";
    });
    if (sleepModule == modules.end()) {
        printf("  aobscanregion: FAILED\n");
        return;
    }

    char script[256];
    snprintf(script, sizeof(script),
        "[ENABLE]\n"
        "aobscanregion(sleep_elf_region, %lx, %lx, 7F 45 4C 46)\n"
        "registersymbol(sleep_elf_region)\n",
        sleepModule->base, sleepModule->base + sleepModule->size);

    AutoAssembler aa;
    auto result = aa.execute(proc, script);
    bool ok = result.success && aa.resolveSymbol("sleep_elf_region") != 0;
    printf("  aobscanregion: %s\n", ok ? "OK" : "FAILED");
}

void test_autoassembler_aobscanall(pid_t pid) {
    printf("\n── Test: AutoAssembler aobscanall ──\n");

    LinuxProcessHandle proc(pid);
    AutoAssembler aa;

    auto result = aa.execute(proc,
        "[ENABLE]\n"
        "aobscanall(sleep_elf_all, 7F 45 4C 46)\n"
        "registersymbol(sleep_elf_all)\n");

    bool ok = result.success && aa.resolveSymbol("sleep_elf_all") != 0;
    printf("  aobscanall: %s\n", ok ? "OK" : "FAILED");
}

// Regression: an aobscan/aobscanmodule result used as an injection LABEL.
// The classic CE idiom is:
//     aobscanmodule(INJECT, mod, <pattern>)
//     alloc(newmem, ...)
//     INJECT:
//       jmp newmem
// The auto-declare-labels preprocessor used to build its "already declared" set
// from alloc/define/registersymbol/label only — NOT the aobscan family — so it
// prepended a spurious label(INJECT) that shadowed the scanned address with an
// empty (address-0) forward label. Writes at INJECT: then landed in the code
// cave (or errored "Label has no active assembly address"), so every AOB
// injection script silently failed to patch its target. This test writes a
// unique marker into an allocated buffer, aobscans for it, and patches it
// through an INJECT: label, then verifies the bytes changed AT the scanned
// address (proving the label resolved to the scan result, not a fresh label).
void test_autoassembler_aobscan_inject_label(pid_t pid) {
    printf("\n── Test: AutoAssembler aobscan result as inject label ──\n");
    LinuxProcessHandle proc(pid);

    // 1) Allocate a buffer in the target and stamp a unique 16-byte marker.
    AutoAssembler seed;
    auto r1 = seed.execute(proc,
        "[ENABLE]\n"
        "alloc(rbuf, 64)\n"
        "registersymbol(rbuf)\n"
        "rbuf:\n"
        "db 5A A5 C3 3C 11 22 33 44 55 66 77 88 99 AA BB CC\n");
    uintptr_t buf = seed.resolveSymbol("rbuf");
    if (!r1.success || !buf) {
        printf("  seed buffer: FAILED (%s)\n", r1.error.c_str());
        return;
    }

    // 2) aobscan for that marker, then patch it via an INJECT: label.
    AutoAssembler aa;
    auto r2 = aa.execute(proc,
        "[ENABLE]\n"
        "aobscan(INJECT, 5A A5 C3 3C 11 22 33 44 55 66 77 88 99 AA BB CC)\n"
        "INJECT:\n"
        "db 90 90 90 90\n");

    uint8_t after[4] = {0,0,0,0};
    auto rd = proc.read(buf, after, sizeof(after));
    bool patched = rd && *rd == sizeof(after) &&
                   after[0]==0x90 && after[1]==0x90 && after[2]==0x90 && after[3]==0x90;

    printf("  execute succeeds (no phantom label): %s\n", r2.success ? "OK" : "FAILED");
    printf("  INJECT: label wrote at the scanned address: %s\n", patched ? "OK" : "FAILED");

    // 3) Full injection idiom: alloc + jmp cave hooked in at the scanned site.
    // Seed a fresh, unique 16-byte marker so the scan has exactly one match
    // (short/common patterns like a NOP run would collide with real code).
    AutoAssembler seed2;
    auto r2b = seed2.execute(proc,
        "[ENABLE]\n"
        "alloc(rbuf2, 64)\n"
        "registersymbol(rbuf2)\n"
        "rbuf2:\n"
        "db BE EF CA FE 0D F0 AD 8B 5A A5 C3 3C 12 34 56 78\n");
    uintptr_t buf2 = seed2.resolveSymbol("rbuf2");
    AutoAssembler aa2;
    auto r3 = aa2.execute(proc,
        "[ENABLE]\n"
        "aobscan(INJ2, BE EF CA FE 0D F0 AD 8B 5A A5 C3 3C 12 34 56 78)\n"
        "alloc(newmem, 128, INJ2)\n"
        "label(back)\n"
        "newmem:\n"
        "  nop\n"
        "  jmp back\n"
        "INJ2:\n"
        "  jmp newmem\n"
        "back:\n");
    bool hooked = false;
    if (r2b.success && buf2 && r3.success) {
        uint8_t hook = 0;
        auto rd2 = proc.read(buf2, &hook, 1);
        hooked = rd2 && *rd2 == 1 && hook == 0xE9; // jmp rel32 opcode
    }
    printf("  full alloc+jmp injection lands E9 at site: %s\n", hooked ? "OK" : "FAILED");
}

void test_autoassembler_requires_target(pid_t pid) {
    printf("\n── Test: AutoAssembler requires target ──\n");

    LinuxProcessHandle proc(pid);
    AutoAssembler aa;

    auto result = aa.execute(proc, "[ENABLE]\nmov eax, 1\n");
    bool ok = !result.success && result.error.find("No active assembly address") != std::string::npos;
    printf("  missing target: %s\n", ok ? "OK" : "FAILED");
}

void test_breakpoint_conditions() {
    printf("\n── Test: Breakpoint Lua Conditions ──\n");

    BreakpointManager mgr;

    Breakpoint falseBp;
    falseBp.address = 0x401000;
    falseBp.condition = "rax == 2";
    int falseId = mgr.add(falseBp);

    Breakpoint trueBp;
    trueBp.address = 0x401010;
    trueBp.condition = "RAX == 1 and bpId == 2 and hitCount == 1 and bp.id == 2 and ctx.rip == rip";
    int trueId = mgr.add(trueBp);

    BreakpointHit hit{};
    hit.bpId = falseId;
    hit.address = falseBp.address;
    hit.rip = 0x401000;
    hit.tid = 77;
    hit.context.rax = 1;
    hit.context.rip = hit.rip;

    bool falseMatched = mgr.recordHit(falseId, hit);

    hit.bpId = trueId;
    hit.address = trueBp.address;
    hit.rip = 0x401010;
    hit.context.rip = hit.rip;
    bool trueMatched = mgr.recordHit(trueId, hit);

    auto bps = mgr.list();
    auto falseIt = std::find_if(bps.begin(), bps.end(), [falseId](const Breakpoint& bp) {
        return bp.id == falseId;
    });
    auto trueIt = std::find_if(bps.begin(), bps.end(), [trueId](const Breakpoint& bp) {
        return bp.id == trueId;
    });

    bool ok = !falseMatched && trueMatched &&
        falseIt != bps.end() && falseIt->hitCount == 0 &&
        trueIt != bps.end() && trueIt->hitCount == 1 &&
        mgr.getHits(falseId).empty() && mgr.getHits(trueId).size() == 1;

    printf("  Lua condition gate: %s\n", ok ? "OK" : "FAILED");

    // A condition that loops forever must be aborted by the instruction-count hook
    // (so the debugger doesn't hang on every hit) and fall through to the fail-safe
    // break. The real assertion is simply that recordHit RETURNS here.
    Breakpoint loopBp;
    loopBp.address = 0x401020;
    loopBp.condition = "while true do end";
    int loopId = mgr.add(loopBp);
    hit.bpId = loopId;
    hit.address = loopBp.address;
    hit.rip = 0x401020;
    hit.context.rip = hit.rip;
    bool loopMatched = mgr.recordHit(loopId, hit);   // must return, not hang
    printf("  infinite-loop condition aborts (no hang): %s\n", loopMatched ? "OK" : "FAILED");
}
