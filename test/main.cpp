#include "platform/linux/linux_process.hpp"
#include "platform/linux/ptrace_wrapper.hpp"
#include "platform/linux/ceserver_client.hpp"
#include "platform/linux/ceserver_process.hpp"
#include "platform/linux/ceserver_debugger.hpp"
#include "platform/linux/kernel_driver.hpp"
#include "platform/network_compression.hpp"
#include "platform/vulkan_overlay_injector.hpp"
#include "scanner/pointer_scanner.hpp"
#include "scanner/snapshot.hpp"
#include "core/autoasm.hpp"
#include "core/aa_templates.hpp"
#include "core/ct_file.hpp"
#include "arch/disassembler.hpp"
#include "core/expression.hpp"
#include "core/trainer.hpp"
#include "analysis/code_analysis.hpp"
#include "analysis/managed_runtime.hpp"
#include "analysis/structure_tools.hpp"
#include "debug/breakpoint_manager.hpp"
#include "debug/stack_trace.hpp"
#include "debug/tracer.hpp"
#include "debug/debug_session.hpp"
#include "debug/gdb_remote.hpp"
#include "debug/managed_breakpoint.hpp"
#include "debug/code_finder.hpp"
#include "symbols/kernel_symbols.hpp"
#include "symbols/dwarf_symbols.hpp"
#include "scripting/lua_engine.hpp"
#include "core/address_list.hpp"
#include "plugins/plugin_loader.hpp"

#include <cstdio>
#include <cstdlib>
#include "symbols/elf_symbols.hpp"
#include <algorithm>
#include <atomic>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <csignal>
#include <thread>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <cstdarg>
#include <stdexcept>
#include <unistd.h>
#include <sys/wait.h>

using namespace ce;
using namespace ce::os;

// ── Test failure gate ──
// The suite prints "... FAILED" on a failed check but historically returned 0
// unconditionally, so CI only caught crashes. Wrap printf to count every line
// containing "FAILED" (the token appears ONLY in real failure results — there
// are no "N FAILED" summary lines and no stderr failures) and make main() exit
// non-zero if any fired. vasprintf avoids truncating long test output.
static int g_test_failures = 0;
static int ce_test_printf(const char* fmt, ...) {
    char* buf = nullptr;
    va_list ap;
    va_start(ap, fmt);
    int n = vasprintf(&buf, fmt, ap);
    va_end(ap);
    if (n >= 0 && buf) {
        if (std::strstr(buf, "FAILED")) g_test_failures++;
        std::fputs(buf, stdout);
        std::free(buf);
    }
    return n;
}
#define printf ce_test_printf

static uint64_t g_traceTargetCounter = 0;

extern "C" __attribute__((noinline)) void cecore_trace_target_tick() {
    ++g_traceTargetCounter;
    asm volatile("nop\nnop\nnop\n" ::: "memory");
}

class FakeProcessHandle final : public ProcessHandle {
public:
    struct Segment {
        MemoryRegion region;
        std::vector<uint8_t> data;
    };

    explicit FakeProcessHandle(std::vector<Segment> segments, std::vector<ModuleInfo> modules)
        : segments_(std::move(segments)), modules_(std::move(modules)) {}

    pid_t pid() const override { return getpid(); }
    bool is64bit() const override { return true; }

    Result<size_t> read(uintptr_t address, void* buffer, size_t size) override {
        for (const auto& segment : segments_) {
            auto start = segment.region.base;
            auto end = start + segment.data.size();
            if (address < start || address >= end) continue;
            auto offset = address - start;
            auto count = std::min<size_t>(size, segment.data.size() - offset);
            std::memcpy(buffer, segment.data.data() + offset, count);
            return count;
        }
        return std::unexpected(std::make_error_code(std::errc::bad_address));
    }

    Result<size_t> write(uintptr_t, const void*, size_t) override {
        return std::unexpected(std::make_error_code(std::errc::not_supported));
    }

    std::vector<MemoryRegion> queryRegions() override {
        std::vector<MemoryRegion> regions;
        for (const auto& segment : segments_) regions.push_back(segment.region);
        return regions;
    }

    std::optional<MemoryRegion> queryRegion(uintptr_t address) override {
        for (const auto& segment : segments_) {
            auto start = segment.region.base;
            auto end = start + segment.region.size;
            if (address >= start && address < end) return segment.region;
        }
        return std::nullopt;
    }

    Result<uintptr_t> allocate(size_t, MemProt, uintptr_t = 0) override {
        return std::unexpected(std::make_error_code(std::errc::not_supported));
    }
    Result<void> free(uintptr_t, size_t) override {
        return std::unexpected(std::make_error_code(std::errc::not_supported));
    }
    Result<void> protect(uintptr_t, size_t, MemProt) override {
        return std::unexpected(std::make_error_code(std::errc::not_supported));
    }
    std::vector<ModuleInfo> modules() override { return modules_; }
    std::vector<ThreadInfo> threads() override { return {}; }

private:
    std::vector<Segment> segments_;
    std::vector<ModuleInfo> modules_;
};

static void test_cheat_table_json() {
    printf("\n── Test: CheatTable Round Trip ──\n");

    CheatTable table;
    table.gameName = "Example Game";
    table.gameVersion = "1.2.3";
    table.author = "cecore";
    table.comment = "Lua table metadata";
    table.luaScript = "print('table lua')\nreturn 7\n";

    CheatEntry entry;
    entry.id = 7;
    entry.description = "Health \"current\"";
    entry.address = 0x1234;
    entry.type = ValueType::Int32;
    entry.value = "100\n200";
    entry.active = true;
    entry.autoAsmScript = "[ENABLE]\nassert(1234, 90)\n";
    entry.luaScript = "print('entry lua')\n";
    entry.color = "FF00AA";
    entry.dropdownList = "0:Off;1:On";
    entry.hotkeyKeys = "Ctrl+H";
    entry.increaseHotkeyKeys = "Ctrl+Up";
    entry.decreaseHotkeyKeys = "Ctrl+Down";
    entry.hotkeyStep = "5";
    table.entries.push_back(entry);

    StructureDefinition structure;
    structure.name = "Player";
    structure.size = 16;
    structure.fields.push_back({"health", 0, ValueType::Int32, 4});
    structure.fields.push_back({"mana", 4, ValueType::Float, 4});
    structure.fields[0].displayMethod = "unsigned";
    structure.fields.push_back({"position", 8, ValueType::ByteArray, 8});
    structure.fields[2].nestedStructure = "Vector2";
    table.structures.push_back(structure);

    table.disassemblerComments.push_back({"libgame.so+0x1234", "loop start \"here\"", ""});
    table.disassemblerComments.push_back({"0x400500", "", "InitPlayer"});

    auto jsonPath = std::filesystem::temp_directory_path() /
        ("cecore-table-" + std::to_string(getpid()) + ".json");
    auto xmlPath = std::filesystem::temp_directory_path() /
        ("cecore-table-" + std::to_string(getpid()) + ".CT");
    auto protectedPath = std::filesystem::temp_directory_path() /
        ("cecore-table-" + std::to_string(getpid()) + ".CETRAINER");

    if (!table.saveJson(jsonPath.string()) || !table.save(xmlPath.string()) ||
        !table.saveProtected(protectedPath.string(), "secret")) {
        printf("  Save FAILED\n");
        return;
    }

    auto matchesTable = [&table, &entry](const CheatTable& loaded) {
        return loaded.gameName == table.gameName &&
            loaded.gameVersion == table.gameVersion &&
            loaded.author == table.author &&
            loaded.comment == table.comment &&
            loaded.luaScript == table.luaScript &&
            loaded.structures.size() == 1 &&
            loaded.structures[0].name == "Player" &&
            loaded.structures[0].size == 16 &&
            loaded.structures[0].fields.size() == 3 &&
            loaded.structures[0].fields[0].name == "health" &&
            loaded.structures[0].fields[0].offset == 0 &&
            loaded.structures[0].fields[0].type == ValueType::Int32 &&
            loaded.structures[0].fields[0].displayMethod == "unsigned" &&
            loaded.structures[0].fields[1].name == "mana" &&
            loaded.structures[0].fields[1].offset == 4 &&
            loaded.structures[0].fields[1].type == ValueType::Float &&
            loaded.structures[0].fields[2].name == "position" &&
            loaded.structures[0].fields[2].nestedStructure == "Vector2" &&
            loaded.entries.size() == 1 &&
            loaded.entries[0].id == entry.id &&
            loaded.entries[0].description == entry.description &&
            loaded.entries[0].address == entry.address &&
            loaded.entries[0].type == entry.type &&
            loaded.entries[0].value == entry.value &&
            loaded.entries[0].active == entry.active &&
            loaded.entries[0].autoAsmScript == entry.autoAsmScript &&
            loaded.entries[0].luaScript == entry.luaScript &&
            loaded.entries[0].color == entry.color &&
            loaded.entries[0].dropdownList == entry.dropdownList &&
            loaded.entries[0].hotkeyKeys == entry.hotkeyKeys &&
            loaded.entries[0].increaseHotkeyKeys == entry.increaseHotkeyKeys &&
            loaded.entries[0].decreaseHotkeyKeys == entry.decreaseHotkeyKeys &&
            loaded.entries[0].hotkeyStep == entry.hotkeyStep &&
            loaded.disassemblerComments.size() == 2 &&
            loaded.disassemblerComments[0].address == "libgame.so+0x1234" &&
            loaded.disassemblerComments[0].comment == "loop start \"here\"" &&
            loaded.disassemblerComments[0].label.empty() &&
            loaded.disassemblerComments[1].address == "0x400500" &&
            loaded.disassemblerComments[1].comment.empty() &&
            loaded.disassemblerComments[1].label == "InitPlayer";
    };

    CheatTable jsonLoaded;
    bool jsonOk = jsonLoaded.loadJson(jsonPath.string()) && matchesTable(jsonLoaded);
    CheatTable xmlLoaded;
    bool xmlOk = xmlLoaded.load(xmlPath.string()) && matchesTable(xmlLoaded);
    std::ifstream xmlFile(xmlPath);
    std::string xmlText((std::istreambuf_iterator<char>(xmlFile)), {});
    bool xmlTypeNamesOk =
        xmlText.find("<VariableType>4 Bytes</VariableType>") != std::string::npos &&
        xmlText.find("<Type>4 Bytes</Type>") != std::string::npos &&
        xmlText.find("<Type>Float</Type>") != std::string::npos &&
        xmlText.find("<Type>Array of byte</Type>") != std::string::npos;
    CheatTable protectedLoaded;
    bool protectedOk = protectedLoaded.loadProtected(protectedPath.string(), "secret") &&
        matchesTable(protectedLoaded);
    CheatTable wrongPassword;
    bool wrongPasswordOk = !wrongPassword.loadProtected(protectedPath.string(), "wrong");
    std::filesystem::remove(jsonPath);
    std::filesystem::remove(xmlPath);
    std::filesystem::remove(protectedPath);

    printf("  JSON round trip: %s\n", jsonOk ? "OK" : "FAILED");
    printf("  CT XML round trip: %s\n", xmlOk ? "OK" : "FAILED");
    printf("  CT XML CE type names: %s\n", xmlTypeNamesOk ? "OK" : "FAILED");
    printf("  CETRAINER protected round trip: %s\n", (protectedOk && wrongPasswordOk) ? "OK" : "FAILED");
}

static void test_ce_table_import() {
    printf("\n── Test: Real CE .CT import ──\n");
    // Exactly as Cheat Engine itself writes an entry: the Description is wrapped
    // in double quotes, the type is a name ("4 Bytes"), the address is bare hex.
    const char* ct =
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        "<CheatTable>\n"
        "  <CheatEntries>\n"
        "    <CheatEntry>\n"
        "      <ID>1</ID>\n"
        "      <Description>\"Player Health\"</Description>\n"
        "      <VariableType>4 Bytes</VariableType>\n"
        "      <Address>00401000</Address>\n"
        "    </CheatEntry>\n"
        "    <CheatEntry>\n"
        "      <ID>2</ID>\n"
        "      <Description>\"Ammo (pointer)\"</Description>\n"
        "      <VariableType>4 Bytes</VariableType>\n"
        "      <Address>game.exe+1C</Address>\n"
        "      <Offsets>\n"
        "        <Offset>10</Offset>\n"
        "        <Offset>8</Offset>\n"
        "      </Offsets>\n"
        "    </CheatEntry>\n"
        "  </CheatEntries>\n"
        "</CheatTable>\n";
    auto path = std::filesystem::temp_directory_path() / "ce_import_test.CT";
    { std::ofstream o(path); o << ct; }
    CheatTable t;
    bool loaded = t.load(path.string());
    std::filesystem::remove(path);
    bool ok = loaded && t.entries.size() == 2 &&
        t.entries[0].description == "Player Health" &&      // CE's quotes stripped
        t.entries[0].type == ValueType::Int32 &&
        t.entries[0].address == 0x401000;
    // Pointer entry: symbolic base preserved, offsets parsed (hex).
    bool ptrOk = t.entries[1].description == "Ammo (pointer)" &&
        t.entries[1].addressString == "game.exe+1C" &&
        t.entries[1].offsets == std::vector<int64_t>({0x10, 0x8});
    printf("  loads CE-authored .CT (quoted desc, 4 Bytes, hex addr): %s\n", ok ? "OK" : "FAILED");
    printf("  loads CE pointer entry (symbolic base + offsets): %s\n", ptrOk ? "OK" : "FAILED");

    // Pointer expression built from base+offsets must match CE's resolution order.
    bool exprOk =
        ce::buildPointerExpression("game.exe+1C", {}) == "game.exe+1C" &&
        ce::buildPointerExpression("game.exe+1C", {0x10}) == "[game.exe+1C]+10" &&
        ce::buildPointerExpression("game.exe+1C", {0x10, 0x8}) == "[[game.exe+1C]+8]+10";
    printf("  pointer expression matches CE offset order: %s\n", exprOk ? "OK" : "FAILED");

    // CE nests child entries inside a group's <CheatEntries>. Loading a grouped
    // table must yield the group AND its child, with the child parented correctly.
    const char* grouped =
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        "<CheatTable>\n"
        "  <CheatEntries>\n"
        "    <CheatEntry>\n"
        "      <ID>10</ID>\n"
        "      <Description>\"Cheats\"</Description>\n"
        "      <GroupHeader>1</GroupHeader>\n"
        "      <CheatEntries>\n"
        "        <CheatEntry>\n"
        "          <ID>11</ID>\n"
        "          <Description>\"God Mode\"</Description>\n"
        "          <VariableType>4 Bytes</VariableType>\n"
        "          <Address>00500000</Address>\n"
        "        </CheatEntry>\n"
        "      </CheatEntries>\n"
        "    </CheatEntry>\n"
        "  </CheatEntries>\n"
        "</CheatTable>\n";
    auto gpath = std::filesystem::temp_directory_path() / "ce_group_test.CT";
    { std::ofstream o(gpath); o << grouped; }
    CheatTable gt;
    bool gloaded = gt.load(gpath.string());
    std::filesystem::remove(gpath);
    bool groupOk = gloaded && gt.entries.size() == 2;
    // find the group and child
    if (groupOk) {
        const CheatEntry* grp = nullptr; const CheatEntry* child = nullptr;
        for (auto& e : gt.entries) {
            if (e.description == "Cheats") grp = &e;
            if (e.description == "God Mode") child = &e;
        }
        groupOk = grp && child && grp->isGroup && !child->isGroup &&
                  child->address == 0x500000 && child->parentId == grp->id;
    }
    printf("  loads nested CE group (parent+child hierarchy): %s\n", groupOk ? "OK" : "FAILED");

    // Save a grouped table and reload it: the parent/child hierarchy must survive
    // (saver must nest children, not write a flat list).
    CheatTable st;
    CheatEntry sg; sg.id = 1; sg.description = "Folder"; sg.isGroup = true; sg.parentId = -1;
    CheatEntry sc; sc.id = 2; sc.description = "Coins"; sc.parentId = 1;
    sc.address = 0x1000; sc.type = ValueType::Int32;
    st.entries = {sg, sc};
    auto spath = std::filesystem::temp_directory_path() / "ce_group_save.CT";
    bool saved = st.save(spath.string());
    CheatTable rt;
    bool reloaded = rt.load(spath.string());
    std::filesystem::remove(spath);
    bool saveHierOk = saved && reloaded && rt.entries.size() == 2;
    if (saveHierOk) {
        const CheatEntry* g = nullptr; const CheatEntry* c = nullptr;
        for (auto& e : rt.entries) { if (e.description == "Folder") g = &e; if (e.description == "Coins") c = &e; }
        saveHierOk = g && c && g->isGroup && c->parentId == g->id && c->address == 0x1000;
    }
    printf("  save/reload preserves group hierarchy: %s\n", saveHierOk ? "OK" : "FAILED");

    // Save an entry with a symbolic base + pointer offsets, reload: both must
    // survive (verifies the SAVE side emits <Address>text and <Offsets>).
    CheatTable pt;
    CheatEntry pe; pe.id = 1; pe.description = "Ptr"; pe.type = ValueType::Int32;
    pe.addressString = "game.exe+1C"; pe.offsets = {0x10, 0x8};
    pe.freezeMode = ce::FreezeMode::DecreaseOnly;  // directional freeze must persist
    pe.showAsHex = true;                          // show-as-hex flag must persist too
    pe.setValueHotkeyKeys = "Ctrl+H"; pe.setValueHotkeyValue = "999";  // set-value hotkey persists
    pt.entries = {pe};
    auto ppath = std::filesystem::temp_directory_path() / "ce_ptr_save.CT";
    bool psaved = pt.save(ppath.string());
    CheatTable pr;
    bool preloaded = pr.load(ppath.string());
    std::filesystem::remove(ppath);
    bool ptrSaveOk = psaved && preloaded && pr.entries.size() == 1 &&
        pr.entries[0].addressString == "game.exe+1C" &&
        pr.entries[0].freezeMode == ce::FreezeMode::DecreaseOnly &&  // freezeMode round-trips
        pr.entries[0].showAsHex == true &&  // showAsHex round-trips
        pr.entries[0].setValueHotkeyKeys == "Ctrl+H" && pr.entries[0].setValueHotkeyValue == "999" &&
        pr.entries[0].offsets == std::vector<int64_t>({0x10, 0x8});
    printf("  save/reload preserves symbolic base + offsets: %s\n", ptrSaveOk ? "OK" : "FAILED");
}

static void test_trainer_generation() {
    printf("\n── Test: Trainer Generation ──\n");

    CheatTable table;
    table.gameName = "Trainer \"Smoke\"\nGame";
    table.author = "cecore";
    table.luaScript = "print('table trainer lua')\n";

    CheatEntry entry;
    entry.description = "Health \"current\"\nline";
    entry.address = 0x12345678;
    entry.type = ValueType::Int32;
    entry.value = "1337";
    entry.hotkeyKeys = "Ctrl+H";
    entry.luaScript = "print('entry trainer lua')\n";
    entry.autoAsmScript = "[ENABLE]\nnop\n";
    table.entries.push_back(entry);

    // Float/Double entries with COMMA-decimal input (as typed under tr_TR): the
    // generator must normalize ','->'.' and emit valid C literals ("2.5f", "1.25"),
    // never "2,5f" (which would fail to compile in generateBinary below).
    CheatEntry fe;
    fe.description = "Speed";
    fe.address = 0x2000;
    fe.type = ValueType::Float;
    fe.value = "2,5";
    table.entries.push_back(fe);

    CheatEntry de;
    de.description = "Gravity";
    de.address = 0x2008;
    de.type = ValueType::Double;
    de.value = "1,25";
    table.entries.push_back(de);

    TrainerGenerator generator;
    auto source = generator.generateSource(table);
    bool floatOk = source.find("2.5f") != std::string::npos &&
                   source.find("1.25") != std::string::npos &&
                   source.find("2,5") == std::string::npos;   // comma never leaks into C
    bool sourceOk =
        source.find("Trainer \\\"Smoke\\\"\\nGame") != std::string::npos &&
        source.find("Health \\\"current\\\"\\nline") != std::string::npos &&
        source.find("#include <sys/select.h>") != std::string::npos &&
        source.find("find_process_by_name") != std::string::npos &&
        source.find("else target_pid = find_process_by_name") != std::string::npos &&
        source.find("hotkey_matches") != std::string::npos &&
        source.find("\"Ctrl+H\"") != std::string::npos &&
        source.find("print_trainer_ui") != std::string::npos &&
        source.find("[%c]") != std::string::npos &&
        source.find("embedded_table_lua") != std::string::npos &&
        source.find("entry trainer lua") != std::string::npos &&
        source.find("[ENABLE]\\nnop\\n") != std::string::npos;

    auto outputPath = std::filesystem::temp_directory_path() /
        ("cecore-trainer-" + std::to_string(getpid()));
    auto error = generator.generateBinary(table, outputPath.string());
    bool binaryOk = error.empty() && std::filesystem::exists(outputPath);

    std::filesystem::remove(outputPath);
    std::filesystem::remove(outputPath.string() + ".c");

    printf("  source escaping: %s\n", sourceOk ? "OK" : "FAILED");
    printf("  float/double comma-decimal emits valid C: %s\n", floatOk ? "OK" : "FAILED");
    printf("  binary compile: %s\n", binaryOk ? "OK" : "FAILED");
    if (!error.empty())
        printf("    error: %s\n", error.c_str());
}

static void test_code_analysis_references() {
    printf("\n── Test: Code Analysis References ──\n");

    const uintptr_t codeBase = 0x1000;
    const uintptr_t stringBase = 0x2000;
    const uintptr_t callTarget = 0x3000;

    std::vector<uint8_t> code = {
        0x48, 0x8d, 0x05, 0xf9, 0x0f, 0x00, 0x00, // lea rax, [rip + 0xff9] -> 0x2000
        0xe8, 0xf4, 0x1f, 0x00, 0x00,             // call 0x3000
        0xeb, 0x01,                                     // jmp 0x100f
        0xc3                                            // ret
    };
    code.insert(code.end(), 20, 0x00);
    std::vector<uint8_t> text = {'h', 'e', 'l', 'l', 'o', ' ', 'c', 'e', 0};

    ModuleInfo module{codeBase, 0x1000, "fake.so", "/tmp/fake.so", true};
    FakeProcessHandle proc({
        {{codeBase, code.size(), MemProt::ReadExec, MemType::Image, MemState::Committed, module.path}, code},
        {{stringBase, text.size(), MemProt::Read, MemType::Image, MemState::Committed, module.path}, text},
    }, {module});

    CodeAnalyzer analyzer;
    auto strings = analyzer.findReferencedStrings(proc, module);
    auto functions = analyzer.findReferencedFunctions(proc, module);
    auto functionSummary = analyzer.enumerateFunctions(proc, module);
    auto callGraph = analyzer.buildCallGraph(proc, module);
    auto jumps = analyzer.findJumps(proc, module);
    auto ripRelative = analyzer.findRipRelativeInstructions(proc, module);
    auto statics = analyzer.findStatics(proc, module);
    auto assembly = analyzer.findAssemblyPattern(proc, module, "ret");
    auto caves = analyzer.findCodeCaves(proc, module, 16);

    bool stringOk = strings.size() == 1 && strings[0].address == codeBase &&
        strings[0].target == stringBase && strings[0].text == "hello ce";
    bool functionOk = functions.size() == 1 && functions[0].address == codeBase + 7 &&
        functions[0].target == callTarget;
    bool functionSummaryOk = functionSummary.size() == 1 &&
        functionSummary[0].address == callTarget &&
        functionSummary[0].references == 1;
    bool callGraphOk = callGraph.size() == 1 &&
        callGraph[0].caller == codeBase &&
        callGraph[0].callee == callTarget &&
        callGraph[0].callSite == codeBase + 7;
    bool jumpsOk = jumps.size() == 1 && jumps[0].address == codeBase + 12 &&
        jumps[0].target == codeBase + 15;
    bool ripOk = ripRelative.size() == 1 && ripRelative[0].address == codeBase &&
        ripRelative[0].target == stringBase;
    bool assemblyOk = assembly.size() == 1 && assembly[0].address == codeBase + 14;
    bool cavesOk = caves.size() == 1 && caves[0].address == codeBase + 15 && caves[0].size == 20;

    // Disassembler resolves the RIP-relative operand to its absolute address and
    // records it in Instruction::ripTarget (the lea at codeBase points to stringBase).
    ce::Disassembler dis(ce::Arch::X86_64);
    auto insns = dis.disassemble(codeBase, {code.data(), code.size()}, 1);
    bool ripResolveOk = insns.size() == 1 &&
        insns[0].ripTarget == stringBase &&
        insns[0].operands.find("0x2000") != std::string::npos &&
        insns[0].operands.find("rip") == std::string::npos;

    printf("  Disassembler RIP resolution: %s\n", ripResolveOk ? "OK" : "FAILED");

    // An indirect branch through a RIP-relative pointer slot (a PLT stub) must
    // resolve ripTarget too, and its operand is a memory reference ('['). The
    // memory browser's "Follow operand" relies on both: parseImmediate bails on the
    // '[' (so it doesn't mistake the displacement 0x2ede for a target) and follows
    // ripTarget (the pointer slot) instead. ff 25 de 2e 00 00 = jmp qword [rip+0x2ede].
    uint8_t pltJmp[] = {0xff, 0x25, 0xde, 0x2e, 0x00, 0x00};
    uintptr_t pltAt = 0x555555000000;
    auto pj = dis.disassemble(pltAt, {pltJmp, sizeof(pltJmp)}, 1);
    bool pltOk = pj.size() == 1 && pj[0].mnemonic == "jmp" &&
        pj[0].ripTarget == pltAt + 6 + 0x2ede &&
        pj[0].operands.find('[') != std::string::npos;
    printf("  Disassembler resolves indirect jmp ripTarget (PLT follow): %s\n", pltOk ? "OK" : "FAILED");

    // Back-disassembly (previousInstruction): nop; nop; mov eax,1 (5B); ret.
    // Layout: c+0 nop, c+1 nop, c+2..c+6 mov, c+7 ret. The read callback refuses
    // out-of-buffer reads, emulating a region boundary (the old fixed-lookback
    // code read unmapped memory there and mis-reported the previous instruction).
    std::vector<uint8_t> backCode = {0x90, 0x90, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3};
    const uintptr_t bc = 0x400000;
    auto backRead = [&](uintptr_t a, uint8_t* buf, size_t n) {
        if (a < bc || a + n > bc + backCode.size()) return false;
        std::memcpy(buf, backCode.data() + (a - bc), n);
        return true;
    };
    bool backOk =
        dis.previousInstruction(bc + 7, backRead) == bc + 2 &&   // before ret -> mov start
        dis.previousInstruction(bc + 2, backRead) == bc + 1 &&   // before mov -> 2nd nop
        dis.previousInstruction(bc + 1, backRead) == bc + 0;     // before 2nd nop -> 1st nop
    printf("  Disassembler previousInstruction: %s\n", backOk ? "OK" : "FAILED");

    // emitDataBytes: an undecodable byte (0xFF at a spot Capstone can't start an
    // instruction) becomes "db" and disassembly continues instead of stopping.
    // nop(90); <bad>; nop(90). Without emitDataBytes it stops at the bad byte.
    // 0x0f without a following modrm is an incomplete/undecodable opcode here.
    std::vector<uint8_t> gapCode = {0x90, 0x0f, 0x90};
    auto strict = dis.disassemble(0x1000, {gapCode.data(), gapCode.size()}, 0, /*emitDataBytes=*/false);
    auto filled = dis.disassemble(0x1000, {gapCode.data(), gapCode.size()}, 0, /*emitDataBytes=*/true);
    // strict stops early (fewer than 3 entries, never reaches the trailing nop);
    // filled emits a db for the 0x0f and continues to the final nop at 0x1002.
    bool gapOk = filled.size() > strict.size() &&
                 std::any_of(filled.begin(), filled.end(),
                     [](const ce::Instruction& i){ return i.mnemonic == "db"; }) &&
                 filled.back().address == 0x1002 && filled.back().mnemonic == "nop";
    printf("  Disassembler emitDataBytes (db fallback): %s\n", gapOk ? "OK" : "FAILED");

    // Round-trip: a RIP-relative instruction is displayed with its operand
    // rewritten to [0x<abs>]. Re-assembling that resolved text at the same address
    // should reproduce the original bytes (so "Assemble" on such an insn is safe).
    {
        ce::Assembler rtAsm(ce::AsmArch::X86_64);
        const uintptr_t A = 0x401000;
        auto orig = rtAsm.assemble("lea rax, [rip+0x100]", A);
        bool rtOk = false;
        if (orig) {
            auto di = dis.disassemble(A, {orig->data(), orig->size()}, 1);
            if (!di.empty() && di[0].ripTarget != 0) {
                std::string text = di[0].mnemonic + " " + di[0].operands;  // lea rax, [0x401107]
                auto re = rtAsm.assemble(text, A);
                rtOk = re && *re == *orig;
            }
        }
        printf("  RIP-resolved operand re-assembles to same bytes: %s\n", rtOk ? "OK" : "FAILED");
    }

    // Relocation invariant — the crux of RIP-relative code injection. Because the
    // disassembler rewrites [rip+disp] to its absolute [0x<abs>], a stolen
    // RIP-relative instruction re-assembled at a DIFFERENT address (the cave)
    // still points at the SAME absolute target (Keystone recomputes the disp for
    // the new site). Without the absolute rewrite it would silently retarget.
    {
        ce::Assembler rtAsm(ce::AsmArch::X86_64);
        const uintptr_t A = 0x401000, B = 0x410000;  // cave within ±2GB of target
        auto orig = rtAsm.assemble("mov eax, dword ptr [rip+0x1234]", A);
        bool relocOk = false;
        if (orig) {
            auto dA = dis.disassemble(A, {orig->data(), orig->size()}, 1);
            if (!dA.empty() && dA[0].ripTarget != 0) {
                std::string text = dA[0].mnemonic + " " + dA[0].operands;  // [0x<abs>]
                auto atB = rtAsm.assemble(text, B);
                if (atB) {
                    auto dB = dis.disassemble(B, {atB->data(), atB->size()}, 1);
                    // The relocated insn must reference the SAME absolute target.
                    // Compare by the resolved address in the operand text, not
                    // ripTarget: Keystone may pick the moffs (absolute) encoding at
                    // the new site, which has no RIP base but still hits 0x<abs>.
                    char tgt[32];
                    std::snprintf(tgt, sizeof(tgt), "0x%llx",
                                  (unsigned long long)dA[0].ripTarget);
                    relocOk = !dB.empty() &&
                              dB[0].operands.find(tgt) != std::string::npos;
                }
            }
        }
        printf("  RIP-relative stolen insn keeps target when relocated to cave: %s\n",
               relocOk ? "OK" : "FAILED");
    }

    // Assemble<->disassemble round-trip idempotency for instructions common in
    // code injection. assemble(text) -> bytes -> disassemble -> text2 ->
    // assemble(text2) -> bytes2; bytes2 must equal bytes (the canonical
    // disassembly must re-assemble to the same encoding). Catches asm/disasm
    // encoding drift without depending on exact textual equality of the original.
    {
        ce::Assembler rt(ce::AsmArch::X86_64);
        ce::Disassembler rd(ce::Arch::X86_64);
        const uintptr_t A = 0x401000;
        const char* insns[] = {
            "push rbp", "pop rbp", "mov eax, 1", "xor eax, eax", "add rax, rbx",
            "sub rsp, 0x20", "ret", "nop", "lea rax, [rbx+rcx*4+0x10]",
            "mov [rax+8], rbx", "cmp rax, 0x10", "test eax, eax", "call 0x401234",
            "jmp 0x401500", "jne 0x401050", "movzx eax, byte ptr [rdx]",
            // SSE / float math (common in game code injection)
            "movss xmm0, dword ptr [rax]", "addss xmm0, xmm1", "mulss xmm0, dword ptr [rbx]",
            "movsd xmm0, qword ptr [rax]", "cvtsi2ss xmm0, eax", "comiss xmm0, xmm1",
            "subps xmm0, xmm1", "movaps xmm2, xmm3",
            // Prefixed instructions (appear throughout real code / injection sites)
            "lock inc dword ptr [rax]", "lock xadd qword ptr [rbx], rcx",
            "rep movsb", "rep stosd", "pause", "lock cmpxchg dword ptr [rdi], esi",
            // x64-specific: 64-bit immediates, bit ops, shifts, misc
            "movabs rax, 0x123456789abcdef0", "cqo", "cdqe", "rdtsc", "bswap eax",
            "bt rax, 5", "shld rax, rbx, 4", "imul rax, rbx, 0x10", "shl rax, cl",
            // Segment override + size specifier (stripPtrKeyword must not corrupt these)
            "mov qword ptr fs:[0x28], rax", "mov eax, dword ptr gs:[0x10]",
            // AVX / VEX-encoded (modern game code — 256-bit ymm and 3-operand forms)
            "vmovups ymm0, ymmword ptr [rax]", "vaddps ymm0, ymm1, ymm2",
            "vxorps xmm0, xmm0, xmm0", "vmovaps ymm5, ymm6", "vmulsd xmm0, xmm1, xmm2",
        };
        // Safety property: re-assembling the canonical disassembly must EITHER
        // reproduce the original bytes OR cleanly fail — never silently succeed
        // with wrong/empty bytes (which would let the GUI NOP-pad over real code).
        int match = 0, safeErr = 0, unsafe = 0;
        for (const char* ins : insns) {
            auto b1 = rt.assemble(ins, A);
            if (!b1) continue;                 // Keystone can't encode it -> skip
            auto d = rd.disassemble(A, {b1->data(), b1->size()}, 1);
            if (d.empty()) continue;
            std::string text = d[0].operands.empty() ? d[0].mnemonic
                                                      : d[0].mnemonic + " " + d[0].operands;
            auto b2 = rt.assemble(text, A);
            if (b2 && *b2 == *b1) ++match;
            else if (!b2)         ++safeErr;   // clean error -> GUI shows a message
            else                  ++unsafe;    // BAD: success with different/empty bytes
        }
        printf("  asm<->disasm round-trip safe (match=%d safeErr=%d unsafe=%d): %s\n",
               match, safeErr, unsafe, (unsafe == 0 && safeErr == 0) ? "OK" : "FAILED");

        // Direct exact-encoding check that the assembler uses the target address for
        // the rel32 (the memory-view "Assemble" path passes the instruction address):
        // jmp 0x401500 @ 0x401000 -> e9 <0x401500-(0x401000+5)=0x4fb> = e9 fb 04 00 00.
        auto jrel = rt.assemble("jmp 0x401500", 0x401000);
        bool jrelOk = jrel && jrel->size() == 5 &&
            (*jrel)[0] == 0xe9 && (*jrel)[1] == 0xfb && (*jrel)[2] == 0x04 &&
            (*jrel)[3] == 0x00 && (*jrel)[4] == 0x00;
        // Same instruction one page higher must encode a different rel32 (address is
        // actually consumed, not ignored): jmp 0x401500 @ 0x402000 -> negative rel.
        auto jrel2 = rt.assemble("jmp 0x401500", 0x402000);
        bool addrUsed = jrel2 && jrel2->size() == 5 && (*jrel2) != (*jrel);
        printf("  assembler uses branch address for rel32: %s\n",
               (jrelOk && addrUsed) ? "OK" : "FAILED");
    }
    printf("  Referenced strings: %s\n", stringOk ? "OK" : "FAILED");
    printf("  Referenced functions: %s\n", functionOk ? "OK" : "FAILED");
    printf("  Function enumeration: %s\n", functionSummaryOk ? "OK" : "FAILED");
    printf("  Call graph: %s\n", callGraphOk ? "OK" : "FAILED");
    printf("  Jump detection: %s\n", jumpsOk ? "OK" : "FAILED");
    printf("  RIP-relative instructions: %s\n", ripOk ? "OK" : "FAILED");

    // findStatics aggregates RIP-relative targets by reference count. Here the one
    // rip-relative insn (the lea) points at stringBase, referenced once.
    bool staticsOk = statics.size() == 1 && statics[0].address == stringBase &&
                     statics[0].references == 1;
    printf("  Find statics (referenced static addresses): %s\n", staticsOk ? "OK" : "FAILED");
    printf("  Assembly pattern scan: %s\n", assemblyOk ? "OK" : "FAILED");
    printf("  Code caves: %s\n", cavesOk ? "OK" : "FAILED");
}

static void test_managed_runtime_detection() {
    printf("\n── Test: Managed runtime detection ──\n");

    FakeProcessHandle proc({}, {
        {0x100000, 0x20000, "libmonosgen-2.0.so", "/usr/lib/libmonosgen-2.0.so", true},
        {0x200000, 0x30000, "libclrjit.so", "/opt/dotnet/shared/Microsoft.NETCore.App/libclrjit.so", true},
        {0x300000, 0x10000, "libnative.so", "/tmp/libnative.so", true},
    });
    auto runtimes = detectManagedRuntimes(proc);

    FakeProcessHandle nativeOnly({}, {
        {0x400000, 0x10000, "libc.so.6", "/usr/lib/libc.so.6", true},
    });
    auto none = detectManagedRuntimes(nativeOnly);

    bool monoOk = std::any_of(runtimes.begin(), runtimes.end(), [](const ManagedRuntimeInfo& info) {
        return info.kind == ManagedRuntimeKind::Mono &&
            info.name == "Mono" &&
            info.moduleName == "libmonosgen-2.0.so";
    });
    bool coreClrOk = std::any_of(runtimes.begin(), runtimes.end(), [](const ManagedRuntimeInfo& info) {
        return info.kind == ManagedRuntimeKind::CoreCLR &&
            info.name == "CoreCLR" &&
            info.moduleName == "libclrjit.so";
    });

    printf("  Mono/CoreCLR modules: %s\n",
        (monoOk && coreClrOk && none.empty()) ? "OK" : "FAILED");
}

static void test_managed_object_enumeration() {
    printf("\n── Test: Managed object enumeration ──\n");

    constexpr uintptr_t metadataBase = 0x500000;
    constexpr uintptr_t heapBase = 0x800000;
    std::vector<uint8_t> metadata(0x200, 0);
    std::vector<uint8_t> heap(0x200, 0);

    uintptr_t playerType = metadataBase + 0x40;
    uintptr_t inventoryType = metadataBase + 0x90;
    uintptr_t nativePointer = 0x12345678;
    std::memcpy(heap.data() + 0x20, &playerType, sizeof(playerType));
    std::memcpy(heap.data() + 0x80, &inventoryType, sizeof(inventoryType));
    std::memcpy(heap.data() + 0xc0, &nativePointer, sizeof(nativePointer));

    FakeProcessHandle proc({
        {{metadataBase, metadata.size(), MemProt::Read, MemType::Image, MemState::Committed, "/opt/dotnet/System.Private.CoreLib.dll"}, metadata},
        {{heapBase, heap.size(), MemProt::ReadWrite, MemType::Private, MemState::Committed, "[managed heap]"}, heap},
    }, {
        {metadataBase, metadata.size(), "System.Private.CoreLib.dll", "/opt/dotnet/System.Private.CoreLib.dll", true},
    });

    ManagedObjectEnumerationConfig config;
    config.runtimeKind = ManagedRuntimeKind::CoreCLR;
    auto objects = enumerateManagedObjects(proc, config);

    config.heapStart = heapBase + 0x70;
    config.heapEnd = heapBase + 0x100;
    config.maxObjects = 1;
    auto bounded = enumerateManagedObjects(proc, config);

    bool playerOk = std::any_of(objects.begin(), objects.end(), [&](const ManagedObjectInfo& object) {
        return object.address == heapBase + 0x20 &&
            object.typeHandle == playerType &&
            object.runtimeKind == ManagedRuntimeKind::CoreCLR &&
            object.regionPath == "[managed heap]";
    });
    bool inventoryOk = std::any_of(objects.begin(), objects.end(), [&](const ManagedObjectInfo& object) {
        return object.address == heapBase + 0x80 && object.typeHandle == inventoryType;
    });
    bool boundedOk = bounded.size() == 1 &&
        bounded.front().address == heapBase + 0x80 &&
        bounded.front().typeHandle == inventoryType;

    printf("  object headers: %s\n",
        (objects.size() == 2 && playerOk && inventoryOk && boundedOk) ? "OK" : "FAILED");
}

static void test_managed_type_extraction() {
    printf("\n── Test: Managed type extraction ──\n");

    constexpr uintptr_t metadataBase = 0x510000;
    constexpr uintptr_t heapBase = 0x810000;
    std::vector<uint8_t> metadata(0x300, 0);
    std::vector<uint8_t> heap(0x200, 0);

    uintptr_t playerType = metadataBase + 0x40;
    uintptr_t inventoryType = metadataBase + 0x80;
    uintptr_t playerName = metadataBase + 0x140;
    uintptr_t playerNamespace = metadataBase + 0x180;
    uintptr_t inventoryName = metadataBase + 0x1c0;
    uintptr_t inventoryNamespace = metadataBase + 0x200;

    std::memcpy(metadata.data() + 0x40, &playerName, sizeof(playerName));
    std::memcpy(metadata.data() + 0x48, &playerNamespace, sizeof(playerNamespace));
    std::memcpy(metadata.data() + 0x80, &inventoryName, sizeof(inventoryName));
    std::memcpy(metadata.data() + 0x88, &inventoryNamespace, sizeof(inventoryNamespace));
    std::memcpy(metadata.data() + 0x140, "Player", sizeof("Player"));
    std::memcpy(metadata.data() + 0x180, "Game.Entities", sizeof("Game.Entities"));
    std::memcpy(metadata.data() + 0x1c0, "Inventory", sizeof("Inventory"));
    std::memcpy(metadata.data() + 0x200, "Game.Items", sizeof("Game.Items"));

    std::memcpy(heap.data() + 0x20, &playerType, sizeof(playerType));
    std::memcpy(heap.data() + 0x80, &inventoryType, sizeof(inventoryType));
    std::memcpy(heap.data() + 0xa0, &playerType, sizeof(playerType));

    FakeProcessHandle proc({
        {{metadataBase, metadata.size(), MemProt::Read, MemType::Image, MemState::Committed, "/opt/dotnet/System.Private.CoreLib.dll"}, metadata},
        {{heapBase, heap.size(), MemProt::ReadWrite, MemType::Private, MemState::Committed, "[managed heap]"}, heap},
    }, {
        {metadataBase, metadata.size(), "System.Private.CoreLib.dll", "/opt/dotnet/System.Private.CoreLib.dll", true},
    });

    ManagedObjectEnumerationConfig objectConfig;
    objectConfig.runtimeKind = ManagedRuntimeKind::CoreCLR;
    auto objects = enumerateManagedObjects(proc, objectConfig);

    ManagedTypeExtractionConfig typeConfig;
    typeConfig.runtimeKind = ManagedRuntimeKind::CoreCLR;
    auto types = extractManagedObjectTypes(proc, objects, typeConfig);

    bool playerOk = std::any_of(types.begin(), types.end(), [&](const ManagedTypeInfo& type) {
        return type.typeHandle == playerType &&
            type.name == "Player" &&
            type.namespaceName == "Game.Entities" &&
            type.runtimeKind == ManagedRuntimeKind::CoreCLR;
    });
    bool inventoryOk = std::any_of(types.begin(), types.end(), [&](const ManagedTypeInfo& type) {
        return type.typeHandle == inventoryType &&
            type.name == "Inventory" &&
            type.namespaceName == "Game.Items";
    });

    printf("  type names: %s\n",
        (objects.size() == 3 && types.size() == 2 && playerOk && inventoryOk) ? "OK" : "FAILED");
}

static void test_gdb_remote_client() {
    printf("\n── Test: GDB remote client ──\n");

    auto checksum = [](const std::string& payload) {
        uint8_t sum = 0;
        for (unsigned char c : payload)
            sum = static_cast<uint8_t>(sum + c);
        return sum;
    };
    auto sendPacket = [&](int fd, const std::string& payload) {
        char suffix[4];
        std::snprintf(suffix, sizeof(suffix), "#%02x", checksum(payload));
        std::string packet = "$" + payload + suffix;
        ::send(fd, packet.data(), packet.size(), 0);
        char ack = 0;
        ::recv(fd, &ack, 1, MSG_WAITALL);
    };
    auto readPacket = [](int fd) {
        char c = 0;
        do {
            if (::recv(fd, &c, 1, MSG_WAITALL) != 1)
                return std::string{};
        } while (c != '$');

        std::string payload;
        while (::recv(fd, &c, 1, MSG_WAITALL) == 1 && c != '#')
            payload.push_back(c);
        char ignored[2] = {};
        ::recv(fd, ignored, 2, MSG_WAITALL);
        ::send(fd, "+", 1, 0);
        return payload;
    };

    int server = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    bool setupOk = server >= 0 &&
        ::bind(server, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0 &&
        ::listen(server, 1) == 0;
    socklen_t addrLen = sizeof(addr);
    if (setupOk)
        setupOk = ::getsockname(server, reinterpret_cast<sockaddr*>(&addr), &addrLen) == 0;

    if (!setupOk) {
        if (server >= 0) ::close(server);
        printf("  packet exchange: FAILED\n");
        return;
    }

    bool serverOk = false;
    std::thread stub([&]() {
        int client = ::accept(server, nullptr, nullptr);
        if (client < 0)
            return;

        auto first = readPacket(client);
        sendPacket(client, "01020304");
        auto second = readPacket(client);
        sendPacket(client, "11223344");

        serverOk = first == "g" && second == "m1000,4";
        ::close(client);
    });

    GdbRemoteClient client;
    std::string error;
    bool connected = client.connectTcp("127.0.0.1", ntohs(addr.sin_port), error);
    std::expected<std::string, std::string> regs = std::unexpected(error);
    std::expected<std::vector<uint8_t>, std::string> mem = std::unexpected(error);
    if (connected) {
        regs = client.readRegisters();
        mem = client.readMemory(0x1000, 4);
    }
    client.close();
    stub.join();
    ::close(server);

    bool ok = connected &&
        regs && *regs == "01020304" &&
        mem && *mem == std::vector<uint8_t>({0x11, 0x22, 0x33, 0x44}) &&
        serverOk;
    printf("  packet exchange: %s\n", ok ? "OK" : "FAILED");
}

static void test_ceserver_client() {
    printf("\n── Test: ceserver TCP client ──\n");

    int server = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    bool setupOk = server >= 0 &&
        ::bind(server, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0 &&
        ::listen(server, 1) == 0;
    socklen_t addrLen = sizeof(addr);
    if (setupOk)
        setupOk = ::getsockname(server, reinterpret_cast<sockaddr*>(&addr), &addrLen) == 0;

    if (!setupOk) {
        if (server >= 0) ::close(server);
        printf("  version handshake: FAILED\n");
        return;
    }

    bool serverOk = false;
    std::thread stub([&]() {
        int client = ::accept(server, nullptr, nullptr);
        if (client < 0)
            return;

        uint8_t command = 0xff;
        ::recv(client, &command, sizeof(command), MSG_WAITALL);
        int32_t protocol = 6;
        const std::string version = "CHEATENGINE Network 2.3";
        uint8_t size = static_cast<uint8_t>(version.size());
        ::send(client, &protocol, sizeof(protocol), 0);
        ::send(client, &size, sizeof(size), 0);
        ::send(client, version.data(), version.size(), 0);
        serverOk = command == 0;
        ::close(client);
    });

    CEServerClient client;
    std::string error;
    bool connected = client.connectTcp("127.0.0.1", ntohs(addr.sin_port), error);
    std::expected<CEServerVersionInfo, std::string> version = std::unexpected(error);
    if (connected)
        version = client.getVersion();
    client.close();
    stub.join();
    ::close(server);

    bool ok = connected &&
        version &&
        version->protocolVersion == 6 &&
        version->versionString == "CHEATENGINE Network 2.3" &&
        serverOk;
    printf("  version handshake: %s\n", ok ? "OK" : "FAILED");
}

static void test_ceserver_memory_ops() {
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
                    ::send(client, &prot, 4, 0);
                    ::send(client, &type, 4, 0);
                    ::send(client, &base, 8, 0);
                    ::send(client, &size, 8, 0);
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

// Loopback ceserver stub that handles every command exercised by the extended
// ops + adapter tests. Returns deterministic blobs keyed off the chosen handle/pid.
namespace {
struct StubFixture {
    int server = -1;
    uint16_t port = 0;
    std::thread thread;
    std::atomic<bool> stop{false};
    bool ok() const { return server >= 0 && port != 0; }
};

constexpr int32_t kStubHandle = 0xCAFE;
constexpr int32_t kStubPid = 99999;
constexpr uint64_t kStubAlloc = 0x77777000ull;
} // namespace
std::vector<uint8_t> g_lastSetContextBlob;
namespace {

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
            sendN(&prot, 4); sendN(&type, 4); sendN(&base, 8); sendN(&size, 8);
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
} // namespace

static void test_ceserver_extended_ops() {
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

static void test_ceserver_debug_ops() {
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

static void test_remote_process_adapter() {
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

static void test_remote_debugger() {
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

static void test_network_compression() {
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

static void test_distributed_pointer_scan() {
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
}

static void test_pointer_scan_shard_through_static() {
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

static void test_pointer_scan_persistence() {
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

static void test_ct_table_luascript_after_entries() {
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
}
static void test_dwarf_symbols() {
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
    const char* src = "int ceDwarfProbe(int x){\n  int y = x + 1;\n  return y;\n}\n";
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
    }
    std::filesystem::remove(c); std::filesystem::remove(so);
}

static void test_autoasm_lua_blocks() {
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

    // Unmatched {$lua}.
    {
        std::string script =
            "[ENABLE]\n"
            "{$lua}return \"\"\n"
            "[DISABLE]\n";
        auto r = aa.check(script);
        bool detected = !r.success && r.error.find("matching") != std::string::npos;
        printf("  unterminated block flagged: %s\n", detected ? "OK" : ("FAILED: " + r.error).c_str());
    }

    // Lua error inside the block.
    {
        std::string script =
            "[ENABLE]\n"
            "{$lua}error(\"boom\"){$asm}\n"
            "[DISABLE]\n";
        auto r = aa.check(script);
        bool detected = !r.success && r.error.find("boom") != std::string::npos;
        printf("  lua error surfaced: %s\n", detected ? "OK" : ("FAILED: " + r.error).c_str());
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

static void test_autoasm_conditional_blocks() {
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

static void test_autoasm_anonymous_labels() {
    printf("\n── Test: AutoAssembler @@: / @F / @B ──\n");

    AutoAssembler aa;
    {
        std::string script =
            "[ENABLE]\n"
            "alloc(newmem, $100)\n"
            "label(modern)\n"
            "newmem:\n"
            "@@:\n"
            "  jmp @F\n"
            "  nop\n"
            "@@:\n"
            "  jmp @B\n"
            "modern:\n"
            "[DISABLE]\n"
            "dealloc(newmem)\n";
        auto r = aa.check(script);
        printf("  @@: + @F + @B parses cleanly: %s\n", r.success ? "OK" : ("FAILED: " + r.error).c_str());
    }

    {
        std::string script =
            "[ENABLE]\n"
            "jmp @F\n"  // no @@: anywhere
            "[DISABLE]\n";
        auto r = aa.check(script);
        bool detected = !r.success && r.error.find("@F") != std::string::npos;
        printf("  dangling @F flagged: %s\n", detected ? "OK" : ("FAILED: " + r.error).c_str());
    }
}

static void test_autoasm_globalalloc_break() {
    printf("\n── Test: AutoAssembler globalalloc + break ──\n");

    AutoAssembler aa;
    {
        std::string script =
            "[ENABLE]\n"
            "globalalloc(sharedMem, 256)\n"
            "[DISABLE]\n";
        auto r = aa.check(script);
        printf("  globalalloc parses: %s\n", r.success ? "OK" : ("FAILED: " + r.error).c_str());
    }
    {
        std::string script =
            "[ENABLE]\n"
            "alloc(x, 16)\n"
            "break\n"
            "[DISABLE]\n";
        auto r = aa.check(script);
        bool detected = !r.success && r.error.find("BREAK") != std::string::npos;
        printf("  break aborts: %s\n", detected ? "OK" : ("FAILED: " + r.error).c_str());
    }
    {
        std::string script =
            "[ENABLE]\n"
            "break(precondition not met)\n"
            "[DISABLE]\n";
        auto r = aa.check(script);
        bool detected = !r.success && r.error.find("precondition") != std::string::npos;
        printf("  break with message: %s\n", detected ? "OK" : ("FAILED: " + r.error).c_str());
    }
    {
        // AOB injections use alloc(newmem,$1000,INJECT) where the 3rd (near)
        // arg is a symbol from aobscanmodule. This must parse (previously the
        // preferred address was parsed only as a hex number and threw).
        std::string script =
            "[ENABLE]\n"
            "define(INJECT, 400000)\n"
            "alloc(newmem, $1000, INJECT)\n"
            "[DISABLE]\n"
            "dealloc(newmem)\n";
        auto r = aa.check(script);
        bool ok = r.success && r.error.find("Invalid alloc") == std::string::npos;
        printf("  alloc with symbol near-address: %s\n", ok ? "OK" : ("FAILED: " + r.error).c_str());
    }
}

static void test_code_injection_builder() {
    printf("\n── Test: Code-injection auto-generator ──\n");

    // Two stolen instructions totalling 7 bytes; the 5-byte jmp leaves 2 nops.
    std::vector<ce::StolenInstruction> stolen = {
        {0x400000, "mov [rax+8], ecx", 3},
        {0x400003, "add ecx, 1", 4},
    };
    std::vector<uint8_t> orig = {0x89, 0x48, 0x08, 0x83, 0xC1, 0x01, 0x90};

    std::string s = ce::buildCodeInjectionScript(0x400000, stolen, orig);

    auto has = [&](const std::string& sub) { return s.find(sub) != std::string::npos; };
    size_t nops = 0;
    for (size_t p = s.find("nop"); p != std::string::npos; p = s.find("nop", p + 1)) ++nops;

    bool ok = has("alloc(newmem,$1000,0x400000)")    // cave near the hook
           && has("mov [rax+8], ecx")                // original code relocated
           && has("add ecx, 1")
           && has("jmp newmem")                       // hook
           && has("jmp return")                       // cave returns
           && has("db 89 48 08 83 C1 01 90")          // original bytes array
           && has("dealloc(newmem)")
           && nops == 2;                              // 7 - 5 = 2 padding nops

    printf("  generate injection with byte array: %s%s\n",
           ok ? "OK" : "FAILED", ok ? "" : ("\n---\n" + s + "\n---").c_str());

    // AOB variant: aobscanmodule signature, the same relocated code/bytes, and
    // register/unregister of the INJECT symbol.
    std::string a = ce::buildAobInjectionScript("game.exe", 0x1234, stolen, orig);
    auto hasA = [&](const std::string& sub) { return a.find(sub) != std::string::npos; };
    bool aobOk = hasA("aobscanmodule(INJECT,game.exe,89 48 08 83 C1 01 90)")
              && hasA("alloc(newmem,$1000,INJECT)")
              && hasA("mov [rax+8], ecx")
              && hasA("jmp newmem")
              && hasA("registersymbol(INJECT)")
              && hasA("db 89 48 08 83 C1 01 90")
              && hasA("unregistersymbol(INJECT)")
              && hasA("dealloc(newmem)");
    printf("  generate AOB injection: %s%s\n",
           aobOk ? "OK" : "FAILED", aobOk ? "" : ("\n---\n" + a + "\n---").c_str());
}

static void test_lua_streams() {
    printf("\n── Test: Lua Stream + StringList ──\n");
    LuaEngine eng;

    auto run = [&](const char* label, const char* code) {
        std::string err = eng.execute(code);
        printf("  %s: %s\n", label, err.empty() ? "OK" : err.c_str());
        if (!err.empty()) std::abort();
    };

    run("MemoryStream round-trip", R"(
        local s = createMemoryStream()
        assert(s:getSize() == 0)
        s:write("hello world")
        assert(s:getSize() == 11)
        s:seek(0)
        assert(s:read(5) == "hello")
        assert(s:read(6) == " world")
    )");

    run("MemoryStream property accessors", R"(
        local s = createMemoryStream()
        s:write("abc")
        assert(s.Size == 3)
        s:seek(1)
        assert(s.Position == 1)
    )");

    run("StringList add/get/count/text", R"(
        local sl = createStringList()
        sl:add("alpha")
        sl:add("beta")
        sl:add("gamma")
        assert(sl:getCount() == 3)
        assert(sl:getString(0) == "alpha")
        assert(sl:getString(2) == "gamma")
        assert(sl.Count == 3)
        assert(sl.Text == "alpha\nbeta\ngamma")
        assert(sl:indexOf("beta") == 1)
        assert(sl:indexOf("missing") == -1)
    )");

    run("StringList setText splits on newlines", R"(
        local sl = createStringList()
        sl:setText("one\ntwo\nthree")
        assert(sl:getCount() == 3)
        assert(sl:getString(1) == "two")
    )");

    // saveToFile / loadFromFile.
    auto tmp = std::filesystem::temp_directory_path() / "cecore_streams_test.txt";
    std::string s = "_TMP_PATH = '" + tmp.string() + "'\n";
    eng.execute(s);
    run("StringList file round-trip", R"(
        local a = createStringList()
        a:add("one")
        a:add("two")
        assert(a:saveToFile(_TMP_PATH))
        local b = createStringList()
        assert(b:loadFromFile(_TMP_PATH))
        assert(b:getCount() == 2)
        assert(b:getString(0) == "one")
    )");
    std::filesystem::remove(tmp);
}

static void test_snapshot_engine() {
    printf("\n── Test: Snapshot engine (save/load/diff) ──\n");

    // Synthetic snapshots — we don't need a real process to exercise the
    // file format and diff logic.
    Snapshot before;
    {
        SnapshotRegion r;
        r.base = 0x10000; r.size = 8;
        r.bytes = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
        // Field-by-field assignment because Snapshot::regions_ is private —
        // round-trip via save+load to materialise the same shape.
        Snapshot tmp;
        // We can't poke regions_ directly; use the save/load round-trip
        // by writing a tiny payload by hand below.
        (void)r; (void)tmp; (void)before;
    }

    // Build a synthetic on-disk snapshot file, then load it.
    auto tmpA = std::filesystem::temp_directory_path() / "cecore_snapA.bin";
    auto tmpB = std::filesystem::temp_directory_path() / "cecore_snapB.bin";
    {
        FILE* f = std::fopen(tmpA.string().c_str(), "wb");
        constexpr char magic[8] = {'C','E','S','N','A','P','0','1'};
        std::fwrite(magic, 1, 8, f);
        uint32_t count = 1; std::fwrite(&count, 1, 4, f);
        uint64_t base = 0x10000; uint64_t size = 4;
        uint32_t prot = 4 /* Write */; uint32_t byteCount = 4;
        std::fwrite(&base, 1, 8, f);
        std::fwrite(&size, 1, 8, f);
        std::fwrite(&prot, 1, 4, f);
        std::fwrite(&byteCount, 1, 4, f);
        uint8_t bytes[4] = {0xAA, 0xBB, 0xCC, 0xDD};
        std::fwrite(bytes, 1, 4, f);
        std::fclose(f);
    }
    {
        FILE* f = std::fopen(tmpB.string().c_str(), "wb");
        constexpr char magic[8] = {'C','E','S','N','A','P','0','1'};
        std::fwrite(magic, 1, 8, f);
        uint32_t count = 1; std::fwrite(&count, 1, 4, f);
        uint64_t base = 0x10000; uint64_t size = 4;
        uint32_t prot = 4 /* Write */; uint32_t byteCount = 4;
        std::fwrite(&base, 1, 8, f);
        std::fwrite(&size, 1, 8, f);
        std::fwrite(&prot, 1, 4, f);
        std::fwrite(&byteCount, 1, 4, f);
        // Two bytes changed.
        uint8_t bytes[4] = {0xAA, 0x99, 0xCC, 0xEE};
        std::fwrite(bytes, 1, 4, f);
        std::fclose(f);
    }

    Snapshot snapA, snapB;
    std::string errA, errB;
    bool loadAOk = snapA.load(tmpA.string(), &errA);
    bool loadBOk = snapB.load(tmpB.string(), &errB);
    printf("  load A: %s\n", loadAOk ? "OK" : ("FAILED " + errA).c_str());
    printf("  load B: %s\n", loadBOk ? "OK" : ("FAILED " + errB).c_str());
    if (!loadAOk || !loadBOk) {
        std::filesystem::remove(tmpA); std::filesystem::remove(tmpB);
        return;
    }

    bool metaOk = snapA.regionCount() == 1 && snapA.byteCount() == 4 &&
                  snapB.regionCount() == 1 && snapB.byteCount() == 4;
    printf("  metadata: %s\n", metaOk ? "OK" : "FAILED");

    auto diffs = snapA.diff(snapB);
    bool diffOk = diffs.size() == 2 &&
                  diffs[0].address == 0x10001 && diffs[0].before == 0xBB && diffs[0].after == 0x99 &&
                  diffs[1].address == 0x10003 && diffs[1].before == 0xDD && diffs[1].after == 0xEE;
    printf("  diff (2 changes): %s\n", diffOk ? "OK" : "FAILED");

    // Round-trip A through save -> load.
    auto tmpC = std::filesystem::temp_directory_path() / "cecore_snapC.bin";
    bool saveOk = snapA.save(tmpC.string());
    Snapshot snapC;
    bool reload = saveOk && snapC.load(tmpC.string(), nullptr);
    bool roundtrip = reload && snapC.regionCount() == 1 && snapC.byteCount() == 4;
    printf("  round-trip save/load: %s\n", roundtrip ? "OK" : "FAILED");

    std::filesystem::remove(tmpA);
    std::filesystem::remove(tmpB);
    std::filesystem::remove(tmpC);
}

static void test_plugin_abi() {
    printf("\n── Test: Plugin ABI ──\n");

    // The sample plugin lives next to the test binary in build/.
    namespace fs = std::filesystem;
    fs::path soPath;
    char exe[4096] = {};
    ssize_t n = ::readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n > 0) {
        fs::path bin{std::string(exe, n)};
        soPath = bin.parent_path() / "libcecore_sample_plugin.so";
    }
    if (!fs::exists(soPath)) {
        printf("  sample plugin missing at %s — SKIPPED\n", soPath.string().c_str());
        return;
    }

    LuaEngine engine;
    PluginLoader loader;
    loader.setLuaEngine(&engine);
    int loggedCount = 0;
    std::string lastMessage;
    loader.setLogSink([&](int level, const std::string& msg) {
        ++loggedCount;
        (void)level;
        lastMessage = msg;
    });

    bool loaded = loader.loadPlugin(soPath);
    printf("  loadPlugin: %s\n", loaded ? "OK" : "FAILED");
    if (!loaded) return;

    bool meta = loader.plugins().size() == 1 &&
                loader.plugins()[0].name == "Sample Plugin" &&
                loader.plugins()[0].abi == PluginAbi::Structured;
    printf("  metadata + ABI: %s\n", meta ? "OK" : "FAILED");

    bool sawLog = loggedCount >= 1 && lastMessage.find("init") != std::string::npos;
    printf("  log callback: %s (%d messages, last=\"%s\")\n",
           sawLog ? "OK" : "FAILED", loggedCount, lastMessage.c_str());

    // The plugin should have registered `sample_plugin_ping` on the Lua state.
    auto err = engine.execute("sample_plugin_ping(); _G._plugin_test_ran = true");
    bool luaOk = err.empty();
    printf("  registered Lua function: %s\n", luaOk ? "OK" : ("FAILED: " + err).c_str());

    loader.unloadAll();
    bool unloaded = loader.plugins().empty();
    printf("  unload: %s\n", unloaded ? "OK" : "FAILED");
}

static void test_stack_trace_frame_walk() {
    printf("\n── Test: Stack trace frame walk ──\n");

    const uintptr_t stackBase = 0x70000000;
    const uintptr_t rbp0 = stackBase + 0x100;
    const uintptr_t rbp1 = stackBase + 0x140;
    std::vector<uint8_t> stack(0x1000, 0);

    auto writePtr = [&](uintptr_t address, uintptr_t value) {
        std::memcpy(stack.data() + (address - stackBase), &value, sizeof(value));
    };
    writePtr(rbp0, rbp1);
    writePtr(rbp0 + sizeof(uintptr_t), 0x401100);
    writePtr(rbp1, 0);
    writePtr(rbp1 + sizeof(uintptr_t), 0x401200);

    FakeProcessHandle proc({
        {{stackBase, stack.size(), MemProt::ReadWrite, MemType::Private, MemState::Committed, "[stack]"}, stack},
    }, {});

    CpuContext context{};
    context.rip = 0x401000;
    context.rsp = stackBase + 0x80;
    context.rbp = rbp0;

    auto frames = buildStackTrace(proc, context);
    bool ok = frames.size() == 3 &&
        frames[0].instructionPointer == 0x401000 &&
        frames[1].instructionPointer == 0x401100 &&
        frames[1].framePointer == rbp0 &&
        frames[2].instructionPointer == 0x401200 &&
        frames[2].framePointer == rbp1;

    printf("  frame pointer walk: %s\n", ok ? "OK" : "FAILED");
}

static void test_break_and_trace() {
    printf("\n── Test: Break and trace ──\n");

    pid_t child = fork();
    if (child == 0) {
        while (true)
            cecore_trace_target_tick();
        _exit(0);
    }
    if (child < 0) {
        printf("  break and trace: FAILED\n");
        return;
    }

    usleep(50000);

    LinuxProcessHandle proc(child);
    LinuxDebugger dbg;
    Tracer tracer;
    TraceConfig config;
    config.startAddress = reinterpret_cast<uintptr_t>(&cecore_trace_target_tick);
    config.maxSteps = 8;

    auto entries = tracer.trace(proc, dbg, config);
    kill(child, SIGKILL);
    waitpid(child, nullptr, 0);

    bool hitStart = !entries.empty() && entries[0].address == config.startAddress;
    bool countOk = entries.size() == static_cast<size_t>(config.maxSteps);
    bool decoded = std::any_of(entries.begin(), entries.end(), [](const TraceEntry& entry) {
        return entry.instruction != "??";
    });

    printf("  break and trace: %s\n", (hitStart && countOk && decoded) ? "OK" : "FAILED");
}

// A probe called ONLY by a sibling worker thread, so tracing from its address
// proves the tracer follows the thread that hit the start breakpoint, not main.
static volatile int g_trace_mt_sink = 0;
__attribute__((noinline)) static void mt_trace_probe() {
    g_trace_mt_sink = g_trace_mt_sink + 1;
    asm volatile("nop");
}
static void mt_trace_worker() {
    for (;;) { mt_trace_probe(); usleep(200); }
}
static void test_break_and_trace_multithread() {
    printf("\n── Test: Break and trace (child thread) ──\n");
    pid_t child = fork();
    if (child == 0) {
        std::thread(mt_trace_worker).detach();   // only the worker calls the probe
        for (;;) usleep(100000);                 // main never calls it
        _exit(0);
    }
    if (child < 0) { printf("  mt break and trace: FAILED\n"); return; }
    usleep(80000);

    LinuxProcessHandle proc(child);
    LinuxDebugger dbg;
    Tracer tracer;
    TraceConfig config;
    config.startAddress = reinterpret_cast<uintptr_t>(&mt_trace_probe);
    config.maxSteps = 6;
    auto entries = tracer.trace(proc, dbg, config);
    kill(child, SIGKILL);
    waitpid(child, nullptr, 0);

    bool hitStart = !entries.empty() && entries[0].address == config.startAddress;
    bool countOk = entries.size() == static_cast<size_t>(config.maxSteps);
    printf("  break and trace on a child thread: %s (%zu entries, first=%s)\n",
           (hitStart && countOk) ? "OK" : "FAILED", entries.size(), hitStart ? "startAddr" : "no");
}

static void test_exception_breakpoint() {
    printf("\n── Test: Exception breakpoints ──\n");

    int fds[2];
    if (pipe(fds) != 0) {
        printf("  SIGSEGV exception breakpoint: FAILED\n");
        return;
    }

    pid_t child = fork();
    if (child == 0) {
        close(fds[1]);
        char token = 0;
        (void)read(fds[0], &token, 1);
        close(fds[0]);
        volatile int* bad = reinterpret_cast<volatile int*>(uintptr_t{0x1});
        (void)*bad;
        _exit(0);
    }

    close(fds[0]);
    if (child < 0) {
        close(fds[1]);
        printf("  SIGSEGV exception breakpoint: FAILED\n");
        return;
    }

    LinuxProcessHandle proc(child);
    DebugSession session;
    std::atomic<bool> hit{false};
    std::atomic<int> signal{0};
    session.setEventCallback([&](const DebugEvent& event) {
        if (event.type == DebugEventType::ExceptionBreakpointHit) {
            hit.store(true);
            signal.store(event.signal);
        }
    });
    session.addExceptionBreakpoint(SIGSEGV);

    bool attached = session.attach(child, &proc);
    write(fds[1], "x", 1);
    close(fds[1]);
    if (attached)
        session.continueExecution();

    for (int i = 0; i < 100 && !hit.load(); ++i)
        usleep(10000);

    if (session.isAttached())
        session.detach();
    kill(child, SIGKILL);
    waitpid(child, nullptr, 0);

    printf("  SIGSEGV exception breakpoint: %s\n",
        (attached && hit.load() && signal.load() == SIGSEGV) ? "OK" : "FAILED");
}

// A distinct, non-inlined function the child will call so the parent can plant a
// software breakpoint at its entry. volatile work prevents the optimizer from
// eliding the call. After fork the address matches in parent and child.
__attribute__((noinline)) static void bp_marker() {
    static volatile int sink = 0;
    sink = sink + 1;
}

static void test_software_breakpoint() {
    printf("\n── Test: Software breakpoints ──\n");

    int fds[2];
    if (pipe(fds) != 0) { printf("  soft breakpoint hit: FAILED\n"); return; }

    pid_t child = fork();
    if (child == 0) {
        close(fds[1]);
        char token = 0;
        (void)read(fds[0], &token, 1);
        close(fds[0]);
        for (int i = 0; i < 5; ++i) bp_marker();
        _exit(0);
    }
    close(fds[0]);
    if (child < 0) { close(fds[1]); printf("  soft breakpoint hit: FAILED\n"); return; }

    LinuxProcessHandle proc(child);
    DebugSession session;
    std::atomic<bool> hit{false};
    std::atomic<uintptr_t> hitAddr{0};
    auto marker = reinterpret_cast<uintptr_t>(&bp_marker);
    session.setEventCallback([&](const DebugEvent& event) {
        if (event.type == DebugEventType::BreakpointHit) {
            hitAddr.store(event.address);
            hit.store(true);
        }
    });

    bool attached = session.attach(child, &proc);
    int bpId = attached ? session.setSoftwareBreakpoint(marker) : -1;
    write(fds[1], "x", 1);            // release the child now the bp is armed
    close(fds[1]);
    if (attached) session.continueExecution();

    for (int i = 0; i < 200 && !hit.load(); ++i)
        usleep(10000);

    if (session.isAttached()) session.detach();
    kill(child, SIGKILL);
    waitpid(child, nullptr, 0);

    bool ok = attached && bpId > 0 && hit.load() && hitAddr.load() == marker;
    printf("  soft breakpoint hit at marker: %s\n", ok ? "OK" : "FAILED");
}

// A shared address written ONLY by non-main (sibling) threads of the child, so
// the watchpoint must cover every thread — not just the main one — to see it.
static volatile uint32_t g_cf_watched = 0;
static void cf_writer() {
    for (int i = 0; i < 200000; ++i) {
        g_cf_watched = g_cf_watched + 1;
        usleep(100);
    }
}

static void test_multithread_watchpoint() {
    printf("\n── Test: Multithread watchpoint ──\n");

    int fds[2];
    if (pipe(fds) != 0) { printf("  sibling-thread watchpoint: FAILED\n"); return; }

    pid_t child = fork();
    if (child == 0) {
        close(fds[0]);
        // Only sibling threads touch g_cf_watched; the main thread never does.
        std::thread t1(cf_writer), t2(cf_writer);
        t1.detach();
        t2.detach();
        write(fds[1], "x", 1);            // signal that the workers exist
        for (;;) usleep(100000);          // keep the process alive
        _exit(0);
    }
    close(fds[1]);
    if (child < 0) { close(fds[0]); printf("  sibling-thread watchpoint: FAILED\n"); return; }

    char tok = 0;
    (void)read(fds[0], &tok, 1);          // wait until the worker threads are up
    close(fds[0]);

    LinuxProcessHandle proc(child);
    LinuxDebugger dbg;
    CodeFinder finder;
    bool started = finder.start(proc, dbg, reinterpret_cast<uintptr_t>(&g_cf_watched), true);

    for (int i = 0; i < 100 && finder.results().empty(); ++i)
        usleep(10000);                    // up to ~1s to accumulate hits

    auto results = finder.results();
    finder.stop();

    // The target must survive detach: if the hardware watchpoint is left armed
    // on any thread, that thread takes a SIGTRAP with no tracer and dies. Give
    // it a moment to run past the watched write, then confirm it's still alive.
    usleep(50000);
    bool survived = (kill(child, 0) == 0);

    kill(child, SIGKILL);
    waitpid(child, nullptr, 0);

    bool ok = started && !results.empty() && survived;
    printf("  sibling-thread watchpoint: %s (%zu instr sites, target %s)\n",
           ok ? "OK" : "FAILED", results.size(), survived ? "survived" : "KILLED");
}

// Interactive-debugger multithread verification. bp_child_hot is called ONLY by
// sibling worker threads (never the main thread), so catching it proves the
// debugger traces every thread. g_free_counter is bumped by a SEPARATE thread
// that never touches bp_child_hot — freezing it at a breakpoint hit proves
// all-stop reaches the whole target, not just the thread that trapped.
static volatile long g_free_counter = 0;
__attribute__((noinline)) static void bp_child_hot() {
    static volatile int sink = 0;
    sink = sink + 1;
}
static void bp_hot_worker() {
    for (;;) { bp_child_hot(); usleep(200); }
}
static void free_counter_worker() {
    for (;;) { g_free_counter = g_free_counter + 1; usleep(50); }
}

static void test_multithread_software_breakpoint() {
    printf("\n── Test: Multithread software breakpoint (all-stop) ──\n");

    int fds[2];
    if (pipe(fds) != 0) { printf("  mt soft bp: FAILED\n"); return; }

    pid_t child = fork();
    if (child == 0) {
        close(fds[0]);
        std::thread(bp_hot_worker).detach();       // two workers hit the bp
        std::thread(bp_hot_worker).detach();
        std::thread(free_counter_worker).detach();  // a third only bumps the counter
        write(fds[1], "x", 1);
        for (;;) usleep(100000);
        _exit(0);
    }
    close(fds[1]);
    if (child < 0) { close(fds[0]); printf("  mt soft bp: FAILED\n"); return; }
    char tok = 0; (void)read(fds[0], &tok, 1); close(fds[0]);
    usleep(80000);   // let all four threads spin up before attaching

    LinuxProcessHandle proc(child);
    DebugSession session;
    std::atomic<bool> hit{false};
    std::atomic<uintptr_t> hitAddr{0};
    std::atomic<pid_t> hitTid{0};
    std::atomic<int> stepEvents{0};
    std::atomic<uintptr_t> stepRip{0};
    session.setEventCallback([&](const DebugEvent& e) {
        if (e.type == DebugEventType::BreakpointHit) {
            hitAddr.store(e.address); hitTid.store(e.tid); hit.store(true);
        } else if (e.type == DebugEventType::SingleStep) {
            stepRip.store(e.address); stepEvents.fetch_add(1);
        }
    });
    auto hotAddr = reinterpret_cast<uintptr_t>(&bp_child_hot);
    auto counterAddr = reinterpret_cast<uintptr_t>(&g_free_counter);

    bool attached = session.attach(child, &proc);
    int bpId = attached ? session.setSoftwareBreakpoint(hotAddr) : -1;
    if (attached) session.continueExecution();

    for (int i = 0; i < 300 && !hit.load(); ++i) usleep(10000);   // up to ~3s

    // All-stop: the free counter (a thread that never calls bp_child_hot) must be
    // frozen while we sit at the breakpoint.
    long c1 = 0, c2 = 0;
    proc.read(counterAddr, &c1, sizeof(c1));
    usleep(60000);
    proc.read(counterAddr, &c2, sizeof(c2));
    bool allStop = hit.load() && (c1 == c2);

    bool alive = (kill(child, 0) == 0);   // child-thread bp must not kill the target

    // Step the trapped sibling thread one instruction; expect a moved RIP.
    uintptr_t beforeStep = session.getStopContext().rip;
    session.step(StepMode::Into);
    bool stepped = stepEvents.load() >= 1 && stepRip.load() != 0 &&
                   stepRip.load() != beforeStep;

    // Resume the world; the free counter must advance again. Poll up to ~2s so
    // this stays reliable under heavy slowdown (e.g. instrumented ASan/CI runs).
    long c3 = 0;
    proc.read(counterAddr, &c3, sizeof(c3));
    session.continueExecution();
    bool resumed = false;
    for (int i = 0; i < 200 && !resumed; ++i) {
        usleep(10000);
        long c4 = 0;
        proc.read(counterAddr, &c4, sizeof(c4));
        if (c4 > c3) resumed = true;
    }

    if (session.isAttached()) session.detach();
    kill(child, SIGKILL);
    waitpid(child, nullptr, 0);

    bool ok = attached && bpId > 0 && hit.load() && hitAddr.load() == hotAddr &&
              allStop && alive && stepped && resumed;
    printf("  mt soft bp: %s (hit tid=%d, all-stop=%s, alive=%s, stepped=%s, resumed=%s)\n",
           ok ? "OK" : "FAILED", (int)hitTid.load(),
           allStop ? "yes" : "no", alive ? "yes" : "no",
           stepped ? "yes" : "no", resumed ? "yes" : "no");
}

// Real monotonic time via a raw syscall, so it stays real even after the GOT
// patch redirects the clock_gettime symbol.
static double sh_raw_monotonic() {
    struct timespec ts{};
    syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + ts.tv_nsec / 1e9;
}
static double sh_time_8_sleeps() {
    double t0 = sh_raw_monotonic();
    for (int i = 0; i < 8; i++) {
        struct timespec req{0, 20 * 1000 * 1000};   // 20 ms each -> ~160 ms total
        nanosleep(&req, nullptr);
    }
    return sh_raw_monotonic() - t0;
}

// Verifies the GOT-patch path: a process that has ALREADY bound nanosleep to
// libc (the injected scenario) gets its time scaled after libspeedhack.so is
// dlopen'd, which only works because the constructor repoints the GOT.
static void test_speedhack_got_injection() {
    printf("\n── Test: Speedhack GOT injection (dlopen) ──\n");

    char exe[4096];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    std::string libpath;
    if (n > 0) {
        exe[n] = 0;
        std::string d(exe);
        libpath = d.substr(0, d.find_last_of('/')) + "/libspeedhack.so";
    }

    int fds[2];
    if (pipe(fds) != 0) { printf("  speedhack GOT inject: FAILED (pipe)\n"); return; }
    pid_t child = fork();
    if (child == 0) {
        close(fds[0]);
        double base = sh_time_8_sleeps();          // GOT bound to real libc here
        setenv("CE_SPEED", "10", 1);
        void* h = dlopen(libpath.c_str(), RTLD_NOW);   // ctor GOT-patches this process
        double scaled = h ? sh_time_8_sleeps() : -1.0;
        double out[2] = {base, scaled};
        ssize_t wr = write(fds[1], out, sizeof(out)); (void)wr;
        _exit(h ? 0 : 3);
    }
    close(fds[1]);
    double out[2] = {0, 0};
    ssize_t got = read(fds[0], out, sizeof(out));
    close(fds[0]);
    waitpid(child, nullptr, 0);
    shm_unlink("/ce_speedhack");

    double base = out[0], scaled = out[1];
    // 8x20ms (~160 ms real) at speed=10 should collapse to ~16 ms.
    bool ok = got == (ssize_t)sizeof(out) && base > 0.05 && scaled > 0 &&
              scaled < base * 0.5;
    printf("  speedhack GOT inject: %s (baseline %.0f ms -> injected %.0f ms, %.1fx)\n",
           ok ? "OK" : "FAILED", base * 1000, scaled * 1000,
           scaled > 0 ? base / scaled : 0.0);
}

// Adversarial / malformed input for the parsers that the README says treat
// their input as untrusted. Each must fail gracefully — return empty/false, not
// throw an uncaught exception or crash. A throw is reported FAILED so we fix the
// parser (segfaults kill the suite, which CI now catches).
static void test_parser_fuzz_negatives() {
    printf("\n── Test: Parser adversarial input ──\n");
    namespace fs = std::filesystem;
    auto tmp = fs::temp_directory_path();

    // 1) ExpressionParser
    {
        ExpressionParser ep;
        std::vector<std::string> inputs = {
            "", " ", "\t", "[", "]", "[]", "[[]]", "[[[[[[[[[[", "]]]]]]]]]]",
            "0x", "0X", "0xffffffffffffffffffffffffffffffffff",
            "999999999999999999999999999999999", "-99999999999999999999",
            "+++", "---", "+", "0x[rax", "[rax+", "game.exe+", "+0x", "0x1+",
            "[0x1]+[0x2]+[0x3]", "0x1 0x2", "0xZZZZ", "[0xg]",
            std::string(8192, '['), std::string(2000, 'A'),
            std::string(500, '[') + "0x1" + std::string(500, ']'),
        };
        int fails = 0;
        for (auto& in : inputs) {
            try { (void)ep.parse(in); }
            catch (const std::exception& e) {
                printf("    expr threw (\"%.16s\"...): %s -> FAILED\n", in.c_str(), e.what());
                fails++;
            }
        }
        printf("  ExpressionParser (%zu adversarial inputs): %s\n",
               inputs.size(), fails == 0 ? "OK" : "FAILED");
    }

    // 2) CheatTable::load on malformed .CT XML
    {
        std::vector<std::string> blobs = {
            "", "<>", "<CheatTable>", "<CheatTable><CheatEntries>",
            "<CheatTable><CheatEntries><CheatEntry><Offsets><Offset>x",
            "<CheatTable>" + std::string(20000, '<'),
            std::string(50000, '>'),
            "<CheatTable><CheatEntry><VariableType>Nonsense</VariableType>"
            "<Address>notahexaddr</Address></CheatEntry></CheatTable>",
            "<CheatTable><CheatEntry><Offsets>" + std::string(5000, ' ') + "</Offsets>",
            "\xff\xfe not xml at all \x01\x02\x03",
        };
        int fails = 0;
        for (size_t i = 0; i < blobs.size(); ++i) {
            auto p = tmp / ("cecore-fuzz-ct-" + std::to_string(getpid()) + "-" + std::to_string(i));
            { std::ofstream f(p, std::ios::binary); f.write(blobs[i].data(), (std::streamsize)blobs[i].size()); }
            CheatTable t;
            try { (void)t.load(p.string()); }
            catch (const std::exception& e) { printf("    .CT load threw: %s -> FAILED\n", e.what()); fails++; }
            fs::remove(p);
        }
        printf("  CheatTable malformed .CT (%zu blobs): %s\n",
               blobs.size(), fails == 0 ? "OK" : "FAILED");
    }

    // 3) SymbolResolver::loadModule on malformed ELF
    {
        std::vector<std::string> elfs = {
            "", std::string("\x7f", 1), std::string("\x7f""ELF", 4),
            std::string("\x7f""ELF", 4) + std::string(60, '\xff'),
            std::string(64, '\x00'),
            std::string("\x7f""ELF\x02\x01\x01\x00", 8) + std::string(512, '\x41'),
            std::string("\x7f""ELF\x02\x01\x01\x00", 8) + std::string(4096, '\xff'),
        };
        int fails = 0;
        for (size_t i = 0; i < elfs.size(); ++i) {
            auto p = tmp / ("cecore-fuzz-elf-" + std::to_string(getpid()) + "-" + std::to_string(i));
            { std::ofstream f(p, std::ios::binary); f.write(elfs[i].data(), (std::streamsize)elfs[i].size()); }
            SymbolResolver sr;
            try { sr.loadModule(p.string(), "fuzz", 0x400000); }
            catch (const std::exception& e) { printf("    ELF parse threw: %s -> FAILED\n", e.what()); fails++; }
            fs::remove(p);
        }
        printf("  ELF malformed parse (%zu blobs): %s\n",
               elfs.size(), fails == 0 ? "OK" : "FAILED");
    }
}

// The shellExecute RCE gate: blocked by default, allowed only via the
// out-of-band CECORE_LUA_ALLOW_UNSAFE env var (a malicious table can't set it).
static void test_lua_shellexecute_gate() {
    printf("\n── Test: Lua shellExecute RCE gate ──\n");
    unsetenv("CECORE_LUA_ALLOW_UNSAFE");
    LuaEngine eng1;
    std::string blocked = eng1.execute("return shellExecute('true')");
    bool isBlocked = blocked.find("blocked") != std::string::npos;

    setenv("CECORE_LUA_ALLOW_UNSAFE", "1", 1);
    LuaEngine eng2;
    std::string allowed = eng2.execute("return shellExecute('true')");
    bool isAllowed = allowed.empty();   // opted in: runs, no error
    unsetenv("CECORE_LUA_ALLOW_UNSAFE");

    bool ok = isBlocked && isAllowed;
    printf("  shellExecute default-blocked + env opt-in: %s (blocked=%d allowed=%d)\n",
           ok ? "OK" : "FAILED", (int)isBlocked, (int)isAllowed);
}

static void test_lua_localwrite_gate() {
    printf("\n── Test: Lua write*Local self-memory gate ──\n");
    volatile int target = 0x1111;
    uintptr_t addr = reinterpret_cast<uintptr_t>(&target);
    std::string a = std::to_string(addr);

    // Default: write*Local is blocked and must NOT touch our memory.
    unsetenv("CECORE_LUA_ALLOW_UNSAFE");
    LuaEngine eng1;
    std::string blocked = eng1.execute("writeIntegerLocal(" + a + ", 0x2222)");
    bool isBlocked = blocked.find("blocked") != std::string::npos && target == 0x1111;

    // read*Local only leaks memory (info), so it stays ungated even by default.
    std::string readRes = eng1.execute("assert(readIntegerLocal(" + a + ") == 0x1111, 'read mismatch')");
    bool readUngated = readRes.empty();

    // Opted in: the write goes through and mutates the target.
    setenv("CECORE_LUA_ALLOW_UNSAFE", "1", 1);
    LuaEngine eng2;
    std::string allowed = eng2.execute("writeIntegerLocal(" + a + ", 0x2222)");
    bool isAllowed = allowed.empty() && target == 0x2222;
    unsetenv("CECORE_LUA_ALLOW_UNSAFE");

    bool ok = isBlocked && readUngated && isAllowed;
    printf("  write*Local default-blocked + read ungated + env opt-in: %s (blocked=%d read=%d allowed=%d)\n",
           ok ? "OK" : "FAILED", (int)isBlocked, (int)readUngated, (int)isAllowed);
}

static void test_lua_exception_firewall() {
    printf("\n── Test: Lua native exception firewall ──\n");
    SymbolResolver resolver;
    LuaEngine eng;
    eng.setResolver(&resolver);
    // Every cecore binding is registered through the firewall trampoline, which
    // is a C closure carrying the real function pointer as its single upvalue.
    // A plain (unwrapped) C function has zero upvalues, so getupvalue(f,1)==nil;
    // a wrapped one returns a non-nil name (""), proving the trampoline is in
    // place to translate any escaping C++ exception into a Lua error. The full
    // suite (every Lua test now calls through the trampoline) covers regression;
    // here we also confirm a wrapped binding still behaves normally.
    std::string err = eng.execute(R"lua(
        assert(type(readByte) == 'function', 'readByte missing')
        assert(debug.getupvalue(readByte, 1) ~= nil, 'readByte not firewall-wrapped')
        assert(debug.getupvalue(getRegionInfo, 1) ~= nil, 'getRegionInfo not firewall-wrapped')
        assert(debug.getupvalue(writeIntegerLocal, 1) ~= nil, 'writeIntegerLocal not firewall-wrapped')
        registerSymbol('fw_probe', 0x1234)
        assert(getSymbolInfo('fw_probe').address == 0x1234, 'wrapped binding misbehaves')
    )lua");
    bool ok = err.empty();
    printf("  firewall wraps every binding + calls still work: %s\n",
           ok ? "OK" : ("FAILED (" + err + ")").c_str());
}

// Stripped binaries keep their real symbols in a separate debug file. Build a
// .so with a used static function (only in .symtab), split the debug info into a
// sidecar, strip the .so, link them with .gnu_debuglink, and verify the static
// symbol resolves only when the debug file is reachable.
static void test_symbol_build_id_debuglink() {
    printf("\n── Test: separate-debug-file symbols (.gnu_debuglink) ──\n");
    namespace fs = std::filesystem;
    auto dir = fs::temp_directory_path();
    std::string tag = std::to_string(getpid());
    fs::path src = dir / ("cecore-dl-" + tag + ".c");
    fs::path so  = dir / ("libcecore-dl-" + tag + ".so");
    fs::path dbg = dir / ("libcecore-dl-" + tag + ".so.debug");
    {
        std::ofstream sf(src);
        sf << "__attribute__((noinline,used)) static int dbglink_static_probe(int x){return x*3;}\n"
              "int dbglink_exported(int x){return dbglink_static_probe(x)+1;}\n";
    }
    std::string cmd = "cd '" + dir.string() + "' && "
        "gcc -shared -fPIC -g -o '" + so.filename().string() + "' '" + src.filename().string() + "' && "
        "objcopy --only-keep-debug '" + so.filename().string() + "' '" + dbg.filename().string() + "' && "
        "strip '" + so.filename().string() + "' && "
        "objcopy --add-gnu-debuglink='" + dbg.filename().string() + "' '" + so.filename().string() + "' 2>/dev/null";
    bool built = (system(cmd.c_str()) == 0) && fs::exists(so) && fs::exists(dbg);
    if (!built) {
        printf("  static symbol from .gnu_debuglink: SKIPPED (toolchain unavailable)\n");
        std::error_code ec; fs::remove(src, ec); fs::remove(so, ec); fs::remove(dbg, ec);
        return;
    }

    // Without the debug file, the static symbol is gone (stripped).
    fs::path hidden = dir / ("cecore-dl-hidden-" + tag);
    fs::rename(dbg, hidden);
    SymbolResolver a; a.loadModule(so.string(), "d", 0);
    bool absentWithoutDebug = (a.lookup("dbglink_static_probe") == 0);
    fs::rename(hidden, dbg);

    // With the .gnu_debuglink sidecar present, it resolves.
    SymbolResolver b; b.loadModule(so.string(), "d", 0);
    bool resolvedWithDebug = (b.lookup("dbglink_static_probe") != 0);

    std::error_code ec;
    fs::remove(src, ec); fs::remove(so, ec); fs::remove(dbg, ec);
    bool ok = absentWithoutDebug && resolvedWithDebug;
    printf("  static symbol from .gnu_debuglink: %s (absent-without=%d resolved-with=%d)\n",
           ok ? "OK" : "FAILED", (int)absentWithoutDebug, (int)resolvedWithDebug);
}

// Value-filtered pointer rescan: the game-restart workflow where the target's
// address changed but its value is known.
static void test_pointer_rescan_by_value() {
    printf("\n── Test: pointer rescan by value ──\n");
    const uintptr_t moduleBase = 0x400000;
    const uintptr_t heapBase   = 0x10000000;
    std::vector<uint8_t> module(0x100, 0);
    std::vector<uint8_t> heap(0x100, 0);
    std::memcpy(module.data() + 0x10, &heapBase, sizeof(heapBase));  // module+0x10 -> heap
    int32_t value = 1337;
    std::memcpy(heap.data() + 0x20, &value, sizeof(value));          // heap+0x20 = 1337

    FakeProcessHandle proc({
        {{moduleBase, module.size(), MemProt::Read, MemType::Image, MemState::Committed, "/tmp/game"}, module},
        {{heapBase, heap.size(), MemProt::ReadWrite, MemType::Private, MemState::Committed, "[heap]"}, heap},
    }, {
        {moduleBase, module.size(), "game", "/tmp/game", true},
    });

    PointerPath path;
    path.module = "game"; path.moduleBase = moduleBase; path.baseOffset = 0x10;
    path.offsets = {0x20};
    std::vector<PointerPath> paths = { path };

    bool derefOk = (PointerScanner::dereference(proc, path) == heapBase + 0x20);
    auto keptMatch = rescanPointerPathsByValue(proc, paths, 1337, 4);
    auto keptMiss  = rescanPointerPathsByValue(proc, paths, 9999, 4);

    bool ok = derefOk && keptMatch.size() == 1 && keptMiss.empty();
    printf("  rescan-by-value keeps match / drops mismatch: %s (deref=%d keep=%zu miss=%zu)\n",
           ok ? "OK" : "FAILED", (int)derefOk, keptMatch.size(), keptMiss.size());
}

// 8-byte value written only by a sibling thread, to exercise a non-default
// (8-byte) hardware watch size in find-what-writes.
static volatile uint64_t g_cf_watched8 = 0;
static void cf_writer8() {
    for (int i = 0; i < 200000; ++i) { g_cf_watched8 = g_cf_watched8 + 1; usleep(100); }
}
static void test_codefinder_watch_size() {
    printf("\n── Test: find-what-writes 8-byte watch size ──\n");
    int fds[2];
    if (pipe(fds) != 0) { printf("  8-byte watch: FAILED\n"); return; }
    pid_t child = fork();
    if (child == 0) {
        close(fds[0]);
        std::thread(cf_writer8).detach();
        ssize_t wr = write(fds[1], "x", 1); (void)wr;
        for (;;) usleep(100000);
        _exit(0);
    }
    close(fds[1]);
    char tk = 0; (void)read(fds[0], &tk, 1); close(fds[0]);

    LinuxProcessHandle proc(child);
    LinuxDebugger dbg;
    CodeFinder finder;
    bool started = finder.start(proc, dbg, reinterpret_cast<uintptr_t>(&g_cf_watched8), true, 8);
    for (int i = 0; i < 200 && finder.results().empty(); ++i) usleep(10000);
    auto results = finder.results();
    finder.stop();
    usleep(50000);
    bool survived = (kill(child, 0) == 0);
    kill(child, SIGKILL); waitpid(child, nullptr, 0);

    bool ok = started && !results.empty() && survived;
    printf("  8-byte watch catches 8-byte write: %s (%zu sites, target %s)\n",
           ok ? "OK" : "FAILED", results.size(), survived ? "survived" : "KILLED");
}

// CE-compat Lua symbol helpers.
static void test_lua_symbol_info() {
    printf("\n── Test: Lua getSymbolInfo / reinitializeSymbolhandler ──\n");
    SymbolResolver resolver;
    LuaEngine eng;
    eng.setResolver(&resolver);
    std::string err = eng.execute(R"(
        registerSymbol('mysym', 0xdeadbeef)
        local i = getSymbolInfo('mysym')
        assert(i ~= nil, 'getSymbolInfo returned nil')
        assert(i.address == 0xdeadbeef, 'wrong address')
        assert(getSymbolInfo('nope') == nil, 'unknown symbol should be nil')
        reinitializeSymbolhandler()
    )");
    bool ok = err.empty();
    printf("  getSymbolInfo + reinitializeSymbolhandler: %s\n",
           ok ? "OK" : ("FAILED (" + err + ")").c_str());
}

static void test_lua_region_info() {
    printf("\n── Test: Lua getRegionInfo ──\n");
    // Point at a known-mapped address in our own process (.bss) and query the
    // region it lives in via the self-attached process handle.
    static volatile int probe = 0; probe = 7;
    uintptr_t addr = reinterpret_cast<uintptr_t>(&probe);
    LuaEngine eng;
    eng.setOwnedProcess(std::make_unique<LinuxProcessHandle>(getpid()));
    std::string script =
        "local addr = " + std::to_string(addr) + "\n"
        "local r = getRegionInfo(addr)\n"
        "assert(r ~= nil, 'no region for a mapped address')\n"
        "assert(addr >= r.BaseAddress and addr < r.BaseAddress + r.MemorySize, 'address outside its region')\n"
        "assert(r.MemorySize > 0, 'zero-size region')\n"
        "assert(getRegionInfo(0) == nil, 'null page should be unmapped')\n";
    std::string err = eng.execute(script);
    bool ok = err.empty();
    printf("  getRegionInfo finds the containing region: %s\n",
           ok ? "OK" : ("FAILED (" + err + ")").c_str());
}

static void test_structure_tools() {
    printf("\n── Test: Structure tools ──\n");

    StructureDefinition structure;
    structure.name = "Player State";
    structure.size = 24;
    structure.fields.push_back({"health", 0, ValueType::Int32, 4});
    structure.fields.push_back({"mana value", 4, ValueType::Float, 4});
    structure.fields.push_back({"target", 16, ValueType::Pointer, sizeof(uintptr_t)});
    structure.fields.push_back({"coords", 8, ValueType::ByteArray, 8});
    structure.fields[0].displayMethod = "hex";
    structure.fields[1].displayMethod = "float";
    structure.fields[3].nestedStructure = "Vector2";

    auto path = std::filesystem::temp_directory_path() /
        ("cecore-structure-" + std::to_string(getpid()) + ".json");
    bool saveOk = saveStructureTemplate(structure, path.string());
    auto loaded = loadStructureTemplate(path.string());
    std::filesystem::remove(path);

    auto cpp = generateCppStruct(structure);
    bool loadOk = loaded &&
        loaded->name == structure.name &&
        loaded->size == structure.size &&
        loaded->fields.size() == structure.fields.size() &&
        loaded->fields[1].name == "mana value" &&
        loaded->fields[0].displayMethod == "hex" &&
        loaded->fields[2].type == ValueType::Pointer &&
        loaded->fields[3].nestedStructure == "Vector2";
    bool cppOk = cpp.find("struct Player_State") != std::string::npos &&
        cpp.find("int32_t health; // 0x0") != std::string::npos &&
        cpp.find("float mana_value; // 0x4") != std::string::npos &&
        cpp.find("Vector2 coords; // 0x8") != std::string::npos &&
        cpp.find("uintptr_t target; // 0x10") != std::string::npos;

    std::vector<uint8_t> before(24, 0);
    std::vector<uint8_t> after = before;
    int32_t oldHealth = 0x11223344;
    int32_t newHealth = 0x55667788;
    float mana = 12.5f;
    std::memcpy(before.data(), &oldHealth, sizeof(oldHealth));
    std::memcpy(after.data(), &newHealth, sizeof(newHealth));
    std::memcpy(before.data() + 4, &mana, sizeof(mana));
    std::memcpy(after.data() + 4, &mana, sizeof(mana));
    auto diffs = compareStructureSnapshots(structure, before, after);
    auto hasDiff = [&](const std::string& name, bool changed) {
        return std::any_of(diffs.begin(), diffs.end(), [&](const StructureFieldDiff& diff) {
            return diff.name == name && diff.changed == changed;
        });
    };
    bool diffOk = diffs.size() == 4 &&
        hasDiff("health", true) &&
        hasDiff("mana value", false) &&
        hasDiff("target", false) &&
        hasDiff("coords", false);

    auto detected = autoDetectStructureFields(before, after);
    bool detectOk = detected.size() == 2 &&
        detected[0].offset == 0 && detected[0].size == 4 &&
        detected[0].changed && detected[0].suggestedType == ValueType::Int32 &&
        detected[1].offset == 4 && detected[1].size == 20 &&
        !detected[1].changed;

    const uintptr_t rootBase = 0x80000000;
    const uintptr_t nodeA = rootBase + 0x100;
    const uintptr_t nodeB = rootBase + 0x200;
    std::vector<uint8_t> memory(0x1000, 0);
    std::memcpy(memory.data() + 16, &nodeA, sizeof(nodeA));
    std::memcpy(memory.data() + 0x100, &nodeB, sizeof(nodeB));
    FakeProcessHandle proc({
        {{rootBase, memory.size(), MemProt::ReadWrite, MemType::Private, MemState::Committed, "[structure]"}, memory},
    }, {});
    auto chains = followStructurePointers(proc, rootBase, structure, 3);
    bool pointerOk = chains.size() == 1 &&
        chains[0].fieldName == "target" &&
        chains[0].fieldOffset == 16 &&
        chains[0].addresses.size() == 2 &&
        chains[0].addresses[0] == nodeA &&
        chains[0].addresses[1] == nodeB;

    bool displayOk = formatStructureFieldValue(structure.fields[0], after) == "88 77 66 55" &&
        formatStructureFieldValue(structure.fields[1], after).find("12.5") == 0 &&
        formatStructureFieldValue(structure.fields[2], memory).find("0x") == 0;

    printf("  template save/load: %s\n", (saveOk && loadOk) ? "OK" : "FAILED");
    printf("  C++ struct export: %s\n", cppOk ? "OK" : "FAILED");
    printf("  snapshot comparison: %s\n", diffOk ? "OK" : "FAILED");
    printf("  changed field detection: %s\n", detectOk ? "OK" : "FAILED");
    printf("  pointer chain following: %s\n", pointerOk ? "OK" : "FAILED");
    printf("  custom field display: %s\n", displayOk ? "OK" : "FAILED");
}

// ── Stand-in IAddressList for headless Lua tests ──
class StubAddressList : public IAddressList {
public:
    int count() const override { return (int)entries_.size(); }
    std::optional<AddressEntrySnapshot> at(int index) const override {
        if (index < 0 || index >= (int)entries_.size()) return std::nullopt;
        return entries_[index];
    }
    std::optional<AddressEntrySnapshot> byId(int id) const override {
        for (auto& e : entries_) if (e.id == id) return e;
        return std::nullopt;
    }
    int findIdByDescription(const std::string& d) const override {
        for (auto& e : entries_) if (e.description == d) return e.id;
        return -1;
    }
    std::vector<int> ids() const override {
        std::vector<int> out;
        for (auto& e : entries_) out.push_back(e.id);
        return out;
    }
    int createEntry(uintptr_t addr, ValueType t, const std::string& d) override {
        AddressEntrySnapshot e;
        e.id = nextId_++;
        e.address = addr; e.type = t; e.description = d;
        entries_.push_back(e);
        return e.id;
    }
    int createGroup(const std::string& d) override {
        AddressEntrySnapshot e;
        e.id = nextId_++; e.description = d; e.isGroup = true;
        entries_.push_back(e);
        return e.id;
    }
    bool deleteById(int id) override {
        for (auto it = entries_.begin(); it != entries_.end(); ++it)
            if (it->id == id) { entries_.erase(it); return true; }
        return false;
    }
    bool disableAllWithoutExecute() override {
        for (auto& e : entries_) e.active = false;
        return true;
    }
    AddressEntrySnapshot* find(int id) {
        for (auto& e : entries_) if (e.id == id) return &e;
        return nullptr;
    }
    bool setDescription(int id, const std::string& v) override { auto* e = find(id); if (!e) return false; e->description = v; return true; }
    bool setAddress(int id, uintptr_t v) override { auto* e = find(id); if (!e) return false; e->address = v; return true; }
    bool setType(int id, ValueType v) override { auto* e = find(id); if (!e) return false; e->type = v; return true; }
    bool setValue(int id, const std::string& v) override { auto* e = find(id); if (!e) return false; e->value = v; return true; }
    bool setActive(int id, bool active) override {
        auto* e = find(id); if (!e) return false;
        if (e->active == active) return true;
        e->active = active;
        if (cb_) cb_(id, active);
        return true;
    }
    bool setColor(int id, const std::string& v) override { auto* e = find(id); if (!e) return false; e->color = v; return true; }
    bool setScript(int id, const std::string& v) override { auto* e = find(id); if (!e) return false; e->script = v; return true; }
    void setActivationCallback(ActivationCallback cb) override { cb_ = std::move(cb); }
private:
    std::vector<AddressEntrySnapshot> entries_;
    ActivationCallback cb_;
    int nextId_ = 1;
};

static void test_lua_memrec() {
    printf("\n── Test: Lua MemoryRecord/AddressList surface ──\n");

    StubAddressList list;
    LuaEngine eng;
    eng.setAddressList(&list);

    // Seed two entries C++-side so getMemoryRecord(0) and lookup-by-description work.
    int seedId = list.createEntry(0xDEAD, ValueType::Int32, "Seeded");
    list.createGroup("Group A");

    auto run = [&](const char* label, const char* code) {
        std::string err = eng.execute(code);
        printf("  %s: %s\n", label, err.empty() ? "OK" : err.c_str());
        if (!err.empty()) std::abort();
    };

    run("count + indexing", R"(
        assert(getAddressList().Count == 2, "expected 2 entries, got " .. tostring(getAddressList().Count))
        local mr = getAddressList():getMemoryRecord(0)
        assert(mr ~= nil, "getMemoryRecord(0) returned nil")
        assert(mr.Description == "Seeded", "wrong description: " .. tostring(mr.Description))
        assert(mr.Address == 0xDEAD, "wrong address")
    )");

    run("property writes flow back", R"(
        local mr = getAddressList():getMemoryRecord(0)
        mr.Description = "Renamed"
        mr.Address = 0xCAFE
        mr.Value = "42"
    )");
    if (auto s = list.byId(seedId)) {
        if (s->description != "Renamed" || s->address != 0xCAFE || s->value != "42") {
            printf("  property persistence: FAILED (desc=%s, addr=0x%lx, val=%s)\n",
                s->description.c_str(), (unsigned long)s->address, s->value.c_str());
            std::abort();
        }
        printf("  property persistence: OK\n");
    }

    run("createMemoryRecord global + by-description lookup", R"(
        local m = createMemoryRecord()
        assert(m ~= nil)
        m.Description = "Made by Lua"
        local found = getAddressList():getMemoryRecordByDescription("Made by Lua")
        assert(found ~= nil and found.ID == m.ID, "by-description lookup failed")
    )");

    run("OnActivate fires on activation flip", R"(
        _G._mr_test_hits = 0
        local mr = getAddressList():getMemoryRecord(0)
        mr.OnActivate = function(active) _G._mr_test_hits = _G._mr_test_hits + (active and 1 or 10) end
        mr.Active = true
        mr.Active = false
        assert(_G._mr_test_hits == 11, "expected 11, got " .. tostring(_G._mr_test_hits))
    )");

    run("disableAllWithoutExecute deactivates", R"(
        local mr = getAddressList():getMemoryRecord(0)
        mr.Active = true
        getAddressList():disableAllWithoutExecute()
        assert(mr.Active == false)
    )");

    run("delete removes from list", R"(
        local before = getAddressList().Count
        local m = createMemoryRecord()
        assert(getAddressList().Count == before + 1)
        m:delete()
        assert(getAddressList().Count == before)
    )");

    run("addresslist global resolves to same singleton", R"(
        assert(addresslist.Count == AddressList.Count)
        assert(addresslist:getMemoryRecord(0).ID == getAddressList():getMemoryRecord(0).ID)
    )");

    // Detached behavior — calls return nil after the list is removed.
    eng.setAddressList(nullptr);
    run("detached after setAddressList(nullptr)", R"(
        assert(getAddressList():getMemoryRecord(0) == nil)
        assert(getAddressList().Count == 0)
    )");
}

static void test_autoassembler_unregister_symbol(pid_t pid) {
    printf("\n── Test: AutoAssembler unregistersymbol ──\n");

    LinuxProcessHandle proc(pid);
    AutoAssembler aa;
    aa.registerSymbol("stale_symbol", 0x1234);

    auto result = aa.execute(proc, "[ENABLE]\nunregistersymbol(stale_symbol)\n");
    bool ok = result.success && aa.resolveSymbol("stale_symbol") == 0;
    printf("  unregistersymbol: %s\n", ok ? "OK" : "FAILED");
}

static void test_autoassembler_dealloc(pid_t pid) {
    printf("\n── Test: AutoAssembler dealloc ──\n");

    LinuxProcessHandle proc(pid);
    AutoAssembler aa;

    auto allocResult = aa.execute(proc, "[ENABLE]\nalloc(tempblock, 4096)\n");
    auto deallocResult = aa.execute(proc, "[ENABLE]\ndealloc(tempblock)\n");

    bool sawDeallocLog = false;
    for (const auto& line : deallocResult.log) {
        if (line == "DEALLOC: tempblock") {
            sawDeallocLog = true;
            break;
        }
    }

    bool ok = allocResult.success && deallocResult.success && sawDeallocLog;
    printf("  dealloc: %s\n", ok ? "OK" : "FAILED");
}

static void test_autoassembler_far_forward_jump(pid_t pid) {
    printf("\n── Test: AutoAssembler far forward jump sizing ──\n");

    LinuxProcessHandle proc(pid);
    AutoAssembler aa;
    // je to a label >127 bytes ahead. The near (6-byte) form is required; if the
    // sizing pass under-sizes it as a 2-byte short jump, farend diverges from the
    // execute layout and the cave is corrupt. This checks the fixed-point sizing
    // (resolveForwardLabels iterating until addresses stabilize) converges.
    auto r = aa.execute(proc,
        "[ENABLE]\n"
        "alloc(newmem, 1024)\n"
        "registersymbol(newmem)\n"
        "newmem:\n"
        "je farend\n"
        "nop 200\n"
        "farend:\n"
        "ret\n");
    uintptr_t newmemAddr = aa.resolveSymbol("newmem");

    bool ok = r.success && newmemAddr;
    if (ok) {
        // je near = 6 bytes (0F 84 rel32); farend/ret at newmem+206.
        uint8_t je[6] = {}; proc.read(newmemAddr, je, 6);
        ok = je[0] == 0x0F && je[1] == 0x84;
        int32_t rel = (int32_t)(je[2] | (je[3]<<8) | (je[4]<<16) | ((uint32_t)je[5]<<24));
        ok = ok && ((uintptr_t)(newmemAddr + 6 + rel) == newmemAddr + 206);
        uint8_t bret = 0; proc.read(newmemAddr + 206, &bret, 1);
        ok = ok && bret == 0xC3;                          // ret at farend
    }
    if (r.success) aa.disable(proc, "", r.disableInfo);
    printf("  far forward jump sizing: %s\n", ok ? "OK" : "FAILED");
}

static void test_autoassembler_dealloc_no_cross_evict(pid_t pid) {
    printf("\n── Test: AutoAssembler dealloc namespace not cross-evicted ──\n");

    LinuxProcessHandle proc(pid);
    AutoAssembler aa;
    // Two activations reuse the same alloc name; the global dealloc(name) namespace
    // ends up holding the SECOND. Disabling the FIRST must not evict that entry
    // (address-matched erase), so a later dealloc(name) still finds it.
    auto a = aa.execute(proc, "[ENABLE]\nalloc(shared, 4096)\n");
    auto b = aa.execute(proc, "[ENABLE]\nalloc(shared, 4096)\n");
    aa.disable(proc, "", a.disableInfo);
    auto d = aa.execute(proc, "[ENABLE]\ndealloc(shared)\n");

    bool sawDealloc = false;
    for (const auto& line : d.log)
        if (line == "DEALLOC: shared") sawDealloc = true;

    bool ok = a.success && b.success && d.success && sawDealloc;
    printf("  dealloc namespace not cross-evicted: %s\n", ok ? "OK" : "FAILED");
}

static void test_autoassembler_data_directive_widths(pid_t pid) {
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

static void test_autoassembler_comment_in_string(pid_t pid) {
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

static void test_autoassembler_nop_fillmem(pid_t pid) {
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
    proc.free(addr, 4096);
    printf("  nop/fillmem: %s\n", ok ? "OK" : "FAILED");
}

static void test_autoassembler_try_except(pid_t pid) {
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

static void test_autoassembler_forward_labels(pid_t pid) {
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

static void test_autoassembler_module_offset() {
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

static void test_autoassembler_code_injection_template(pid_t pid) {
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

static void test_autoassembler_assert(pid_t pid) {
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

static void test_autoassembler_create_thread(pid_t pid) {
    printf("\n── Test: AutoAssembler createthread ──\n");

    LinuxProcessHandle proc(pid);

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
        if (asyncValue == 0x55667788)
            break;
        usleep(10000);
    }

    bool ok = waited.success && waitedValue == 0x11223344 &&
        async.success && asyncValue == 0x55667788;

    waitedAssembler.disable(proc, "", waited.disableInfo);
    asyncAssembler.disable(proc, "", async.disableInfo);
    printf("  createthread/andwait: %s\n", ok ? "OK" : "FAILED");
}

static void test_autoassembler_ds(pid_t pid) {
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

static void test_autoassembler_custom_commands(pid_t pid) {
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

static void test_autoassembler_processing_hooks(pid_t pid) {
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

static void test_autoassembler_loadbinary(pid_t pid) {
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

static void test_autoassembler_loadlibrary(pid_t pid) {
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

    LinuxProcessHandle proc(pid);
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

static void test_autoassembler_struct_definitions(pid_t pid) {
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

static void test_autoassembler_aobscanmodule(pid_t pid) {
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

static void test_autoassembler_aobscanregion(pid_t pid) {
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

static void test_autoassembler_aobscanall(pid_t pid) {
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
static void test_autoassembler_aobscan_inject_label(pid_t pid) {
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

static void test_autoassembler_requires_target(pid_t pid) {
    printf("\n── Test: AutoAssembler requires target ──\n");

    LinuxProcessHandle proc(pid);
    AutoAssembler aa;

    auto result = aa.execute(proc, "[ENABLE]\nmov eax, 1\n");
    bool ok = !result.success && result.error.find("No active assembly address") != std::string::npos;
    printf("  missing target: %s\n", ok ? "OK" : "FAILED");
}

static void test_breakpoint_conditions() {
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

static void test_one_shot_breakpoints() {
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

static void test_thread_filtered_breakpoints() {
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

static void test_managed_method_breakpoints() {
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

static void test_kernel_symbol_resolver() {
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

static void test_kernel_driver_client() {
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

static void test_vulkan_overlay_injector() {
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

static void test_lua_file_aliases() {
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

static void test_lua_local_memory() {
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
    unsetenv("CECORE_LUA_ALLOW_UNSAFE");

    printf("  read/write local variants: %s\n",
           err.empty() ? "OK" : ("FAILED (" + err + ")").c_str());
}

static void test_lua_autoassemble_check() {
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

static void test_lua_utility_bindings() {
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

static void test_lua_hotkey_bindings() {
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

static void test_lua_thread_bindings() {
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

static void test_lua_custom_type_bindings() {
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

static void test_lua_address_list_bindings() {
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

static void test_lua_debug_bindings() {
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

static void test_lua_process_bindings(pid_t pid) {
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

static void test_lua_memscan() {
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
    unsetenv("CECORE_LUA_ALLOW_UNSAFE");
    munmap(page, pageSize);

    printf("  firstScan/nextScan: %s\n",
           err.empty() ? "OK" : ("FAILED (" + err + ")").c_str());
}

static void test_binary_scan_bitmask() {
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

static void test_between_numeric_scan() {
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

static void test_nextscan_size_guard() {
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

static void test_unicode_string_scan() {
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

static void test_codepage_string_scan() {
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

static void test_all_types_scan() {
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

    munmap(page, pageSize);

    printf("  vtAll numeric match: %s\n", ok ? "OK" : "FAILED");
    printf("  vtAll value(i) stays in lockstep with address(i): %s\n", valuesAligned ? "OK" : "FAILED");
    printf("  vtAll nextScan does not throw: %s\n", nextOk ? "OK" : "FAILED");
}

static void test_grouped_scan() {
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

static void test_custom_formula_scan() {
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

    munmap(page, pageSize);

    printf("  custom Lua formula: %s\n", ok ? "OK" : "FAILED");
}

static void test_lua_memscan_grouped_custom() {
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

static void test_percentage_scan() {
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

static void test_same_as_first_scan() {
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

static void test_pointer_type_scan() {
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

static void test_float_rounding_scan() {
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

static void test_process_enumeration() {
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
}

static void test_process_memory(pid_t pid) {
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

static void test_write_memory(pid_t pid) {
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

static void test_string_case_insensitive_scan() {
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

static void test_between_reversed_bounds() {
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

static void test_unknown_scan_chain() {
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

static void test_scan_alignment() {
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

static void test_nextscan_comparators() {
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

static void test_cpp_symbol_demangling() {
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

static void test_symbol_size0_extent_cap() {
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

static void test_plt_import_resolution() {
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

static void test_freeze_should_write() {
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

static void test_expression_parser() {
    printf("── Test: Expression Parser ──\n");
    const uintptr_t base  = 0x100000;
    const uintptr_t nodeA = base + 0x100;
    const uintptr_t nodeB = base + 0x200;
    const uintptr_t nodeC = base + 0x300;
    std::vector<uint8_t> mem(0x1000, 0);
    std::memcpy(mem.data() + 0,     &nodeA, sizeof(nodeA));   // [base]     = nodeA
    std::memcpy(mem.data() + 0x100, &nodeB, sizeof(nodeB));   // [nodeA]    = nodeB
    std::memcpy(mem.data() + 0x108, &nodeC, sizeof(nodeC));   // [nodeA+8]  = nodeC
    FakeProcessHandle proc({
        {{base, mem.size(), MemProt::ReadWrite, MemType::Private, MemState::Committed, "[heap]"}, mem},
    }, {
        {base, 0x1000, "game", "/tmp/game", true},   // a named module based at `base`
    });
    ExpressionParser p(&proc, nullptr);
    auto eq = [](std::optional<uintptr_t> v, uintptr_t want) { return v && *v == want; };
    bool ok =
        eq(p.parse("game"),           base)         &&   // bare module name -> base
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
        eq(p.parse("0x1000+[[0x100000]+8]"), 0x1000 + nodeC);
    printf("  multi-level pointers + inner/outer hex offsets: %s\n", ok ? "OK" : "FAILED");
}

int main(int argc, char* argv[]) {
    if (getuid() != 0) {
        fprintf(stderr, "WARNING: Not running as root. Some operations may fail.\n");
    }

    pid_t targetPid = 0;

    if (argc > 1) {
        targetPid = atoi(argv[1]);
        printf("Using target PID: %d\n", targetPid);
    } else {
        // Spawn a test process
        targetPid = fork();
        if (targetPid == 0) {
            // Child — just sleep
            execl("/usr/bin/sleep", "sleep", "9999", nullptr);
            _exit(1);
        }
        printf("Spawned test process: sleep 9999 (PID %d)\n", targetPid);
        usleep(200000); // Wait for it to start
    }

    test_cheat_table_json();
    test_ce_table_import();
    test_trainer_generation();
    test_code_analysis_references();
    test_cpp_symbol_demangling();
    test_symbol_size0_extent_cap();
    test_plt_import_resolution();
    test_freeze_should_write();
    test_expression_parser();
    test_string_case_insensitive_scan();
    test_between_reversed_bounds();
    test_unknown_scan_chain();
    test_scan_alignment();
    test_nextscan_comparators();
    test_managed_runtime_detection();
    test_managed_object_enumeration();
    test_managed_type_extraction();
    test_gdb_remote_client();
    test_ceserver_client();
    test_ceserver_memory_ops();
    test_ceserver_extended_ops();
    test_ceserver_debug_ops();
    test_remote_process_adapter();
    test_remote_debugger();
    test_network_compression();
    test_distributed_pointer_scan();
    test_pointer_scan_shard_through_static();
    test_pointer_scan_persistence();
    test_ct_table_luascript_after_entries();
    test_dwarf_symbols();
    test_plugin_abi();
    test_autoasm_lua_blocks();
    test_autoasm_conditional_blocks();
    test_autoasm_anonymous_labels();
    test_autoasm_globalalloc_break();
    test_code_injection_builder();
    test_lua_streams();
    test_snapshot_engine();
    test_stack_trace_frame_walk();
    test_break_and_trace();
    test_break_and_trace_multithread();
#ifndef __SANITIZE_ADDRESS__
    test_exception_breakpoint();   // deliberate bad-pointer fault trips UBSan (skip under ASan)
#endif
    test_software_breakpoint();
    test_multithread_watchpoint();
    test_multithread_software_breakpoint();
    test_speedhack_got_injection();
    test_parser_fuzz_negatives();
    test_lua_shellexecute_gate();
    test_lua_localwrite_gate();
    test_lua_exception_firewall();
    test_symbol_build_id_debuglink();
    test_pointer_rescan_by_value();
    test_lua_symbol_info();
    test_lua_region_info();
    test_codefinder_watch_size();
    test_structure_tools();
    test_lua_memrec();
    test_autoassembler_unregister_symbol(targetPid);
    test_autoassembler_dealloc(targetPid);
    test_autoassembler_dealloc_no_cross_evict(targetPid);
    test_autoassembler_far_forward_jump(targetPid);
    test_autoassembler_data_directive_widths(targetPid);
    test_autoassembler_comment_in_string(targetPid);
    test_autoassembler_nop_fillmem(targetPid);
    test_autoassembler_try_except(targetPid);
    test_autoassembler_forward_labels(targetPid);
    test_autoassembler_module_offset();
    test_autoassembler_code_injection_template(targetPid);
    test_autoassembler_assert(targetPid);
    test_autoassembler_create_thread(targetPid);
    test_autoassembler_ds(targetPid);
    test_autoassembler_custom_commands(targetPid);
    test_autoassembler_processing_hooks(targetPid);
    test_autoassembler_loadbinary(targetPid);
#ifndef __SANITIZE_ADDRESS__
    test_autoassembler_loadlibrary(targetPid);  // dlopen-injects a lib; conflicts with ASan
#endif
    test_autoassembler_struct_definitions(targetPid);
    test_autoassembler_aobscanmodule(targetPid);
    test_autoassembler_aobscanregion(targetPid);
    test_autoassembler_aobscanall(targetPid);
    test_autoassembler_aobscan_inject_label(targetPid);
    test_autoassembler_requires_target(targetPid);
    test_breakpoint_conditions();
    test_one_shot_breakpoints();
    test_thread_filtered_breakpoints();
    test_managed_method_breakpoints();
    test_kernel_symbol_resolver();
    test_kernel_driver_client();
    test_vulkan_overlay_injector();
    test_lua_file_aliases();
    test_lua_local_memory();
    test_lua_autoassemble_check();
    test_lua_utility_bindings();
    test_lua_hotkey_bindings();
    test_lua_thread_bindings();
    test_lua_custom_type_bindings();
    test_lua_address_list_bindings();
    test_lua_debug_bindings();
    test_lua_process_bindings(targetPid);
    test_lua_memscan();
    test_binary_scan_bitmask();
    test_between_numeric_scan();
    test_nextscan_size_guard();
    test_unicode_string_scan();
    test_codepage_string_scan();
    test_all_types_scan();
    test_grouped_scan();
    test_custom_formula_scan();
    test_percentage_scan();
    test_same_as_first_scan();
    test_pointer_type_scan();
    test_float_rounding_scan();
    test_lua_memscan_grouped_custom();
    test_process_enumeration();
    test_process_memory(targetPid);
    test_write_memory(targetPid);

    // Cleanup spawned process
    if (argc <= 1) {
        kill(targetPid, SIGTERM);
        waitpid(targetPid, nullptr, 0);
        printf("\nKilled test process %d\n", targetPid);
    }

    // Gate self-check: with this env set, force one failure to prove the exit
    // code actually flips (CECORE_TEST_FORCE_FAIL=1 ./cecore_test => exit 1).
    if (std::getenv("CECORE_TEST_FORCE_FAIL")) printf("  gate selfcheck: FAILED\n");

    std::fflush(stdout);
    if (g_test_failures) {
        std::fprintf(stderr, "\n%d check(s) reported failure (see FAILED lines above).\n",
                     g_test_failures);
        return 1;
    }
    printf("\nAll tests complete.\n");
    return 0;
}
