// cecore_test: pointer rescans, PE exports, signatures, IL2CPP and
// structure tools, memory records.
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

// Value-filtered pointer rescan: the game-restart workflow where the target's
// address changed but its value is known.
void test_pointer_rescan_by_value() {
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

// PE export-table parsing: a synthetic PE32+ with one named export ("foo" @ rva
// 0x1234, ordinal 1) exercises the header + section + export-directory walk. A
// real GameAssembly.dll (via CE_IL2CPP_GAMEASSEMBLY) is also checked when present.
void test_pe_exports() {
    printf("\n── Test: PE export table parsing ──\n");
    std::vector<uint8_t> f(0x1400, 0);
    auto pU16 = [&](size_t o, uint16_t v) { f[o] = (uint8_t)v; f[o + 1] = (uint8_t)(v >> 8); };
    auto pU32 = [&](size_t o, uint32_t v) { for (int i = 0; i < 4; ++i) f[o + i] = (uint8_t)(v >> (8 * i)); };
    f[0] = 'M'; f[1] = 'Z'; pU32(0x3C, 0x80);
    f[0x80] = 'P'; f[0x81] = 'E';
    pU16(0x84, 0x8664); pU16(0x86, 1); pU16(0x94, 0xF0);   // machine, nSec, optSize
    pU16(0x98, 0x20B);                                     // PE32+
    pU32(0x104, 2);                                       // NumberOfRvaAndSizes
    pU32(0x108, 0x1000); pU32(0x10C, 0x100);               // DataDirectory[0] export {rva,size}
    const char* sn = ".rdata"; for (int i = 0; i < 6; ++i) f[0x188 + i] = sn[i];
    pU32(0x190, 0x1000); pU32(0x194, 0x1000); pU32(0x198, 0x1000); pU32(0x19C, 0x400);
    // Export directory at file 0x400 (rva 0x1000).
    pU32(0x414, 1); pU32(0x418, 1);        // NumberOfFunctions, NumberOfNames
    pU32(0x410, 1);                        // Base (ordinal base)
    pU32(0x41C, 0x1030); pU32(0x420, 0x1040); pU32(0x424, 0x1050);  // funcs, names, ordinals
    pU32(0x430, 0x1234);                   // AddressOfFunctions[0] = func rva
    pU32(0x440, 0x1060);                   // AddressOfNames[0] = name rva
    pU16(0x450, 0);                        // AddressOfNameOrdinals[0]
    const char* nm = "foo"; for (int i = 0; i < 3; ++i) f[0x460 + i] = nm[i];   // name @ rva 0x1060

    // Import table: one descriptor importing "bar" from "OTHER.dll". Placed at rva
    // 0x1100 (file 0x500); DataDirectory[1] points at it.
    auto pU64 = [&](size_t o, uint64_t v) { for (int i = 0; i < 8; ++i) f[o + i] = (uint8_t)(v >> (8 * i)); };
    pU32(0x110, 0x1100); pU32(0x114, 0x40);   // DataDirectory[1] import {rva,size}
    pU32(0x500 + 0x00, 0x1130);   // OriginalFirstThunk (ILT) rva
    pU32(0x500 + 0x0C, 0x1170);   // Name (dll name) rva
    pU32(0x500 + 0x10, 0x1148);   // FirstThunk (IAT) rva
    pU64(0x530, 0x1160);          // ILT[0] -> IMAGE_IMPORT_BY_NAME rva (ILT[1]=0 terminates)
    pU64(0x548, 0x1160);          // IAT[0]
    // IMAGE_IMPORT_BY_NAME @ rva 0x1160 (file 0x560): u16 hint (0) then "bar".
    const char* imp = "bar"; for (int i = 0; i < 3; ++i) f[0x562 + i] = imp[i];
    const char* dll = "OTHER.dll"; for (int i = 0; i < 9; ++i) f[0x570 + i] = dll[i];  // rva 0x1170

    namespace fs = std::filesystem;
    std::error_code ec;
    fs::path tmp = fs::temp_directory_path() / ("ce-pe-" + std::to_string(getpid()) + ".dll");
    { std::ofstream o(tmp, std::ios::binary); o.write(reinterpret_cast<char*>(f.data()), (std::streamsize)f.size()); }
    auto exps = ce::parsePEExports(tmp.string());
    bool ok = exps.size() == 1 && exps[0].name == "foo" && exps[0].ordinal == 1 &&
              exps[0].rva == 0x1234 && exps[0].forward.empty();
    bool rvaOk = ce::peExportRva(tmp.string(), "foo") == 0x1234;

    auto imps = ce::parsePEImports(tmp.string());
    bool impOk = imps.size() == 1 && imps[0].dll == "OTHER.dll" &&
                 imps[0].name == "bar" && imps[0].iatRva == 0x1148;

    fs::path jp = fs::temp_directory_path() / ("ce-pe-junk-" + std::to_string(getpid()) + ".bin");
    { std::ofstream o(jp, std::ios::binary); std::vector<uint8_t> j(64, 0x41); o.write(reinterpret_cast<char*>(j.data()), 64); }
    bool junkOk = ce::parsePEExports(jp.string()).empty();

    // SymbolResolver integration: loadModule on a PE symbolicates its exports.
    ce::SymbolResolver res;
    res.loadModule(tmp.string(), "test.dll", 0x140000000);
    bool symOk = res.resolve(0x140000000 + 0x1234).find("foo") != std::string::npos &&
                 res.lookup("foo") == 0x140000000 + 0x1234;

    fs::remove(tmp, ec); fs::remove(jp, ec);

    printf("  parses a named export (foo @0x1234, ordinal 1): %s\n", ok ? "OK" : "FAILED");
    printf("  peExportRva(foo) == 0x1234: %s\n", rvaOk ? "OK" : "FAILED");
    printf("  parses an import (OTHER.dll!bar, iat rva 0x1148): %s\n", impOk ? "OK" : "FAILED");
    printf("  non-PE input rejected cleanly: %s\n", junkOk ? "OK" : "FAILED");
    printf("  SymbolResolver symbolicates PE exports: %s\n", symOk ? "OK" : "FAILED");

    if (const char* ga = std::getenv("CE_IL2CPP_GAMEASSEMBLY"); ga && *ga) {
        auto real = ce::parsePEExports(ga);
        size_t il2 = 0;
        for (const auto& e : real) if (e.name.rfind("il2cpp_", 0) == 0) ++il2;
        printf("  real GameAssembly.dll exports il2cpp_* API (%zu of %zu): %s\n",
               il2, real.size(), (real.size() > 0 && il2 > 0) ? "OK" : "FAILED");
    }
}

// AOB signature generation: a region with two `mov rax,[rip+disp]` sites means
// "48 8B 05 ?? ?? ?? ??" is not unique, so makeSignature must wildcard the
// displacement AND extend past it (to the following `ret`) to disambiguate.
void test_signature_generation() {
    printf("\n── Test: AOB signature generation ──\n");
    const uintptr_t base = 0x400000;
    std::vector<uint8_t> code;
    auto nops = [&](int n) { for (int i = 0; i < n; ++i) code.push_back(0x90); };

    nops(16);
    size_t targetOff = code.size();
    // A: mov rax, [rip+0x123456] ; ret
    for (uint8_t b : {0x48, 0x8B, 0x05, 0x56, 0x34, 0x12, 0x00}) code.push_back(b);
    code.push_back(0xC3);   // ret  <- disambiguating byte
    nops(16);
    // B: mov rax, [rip+0x778899] ; nop  (same opcode, different disp + follower)
    for (uint8_t b : {0x48, 0x8B, 0x05, 0x99, 0x88, 0x77, 0x00}) code.push_back(b);
    code.push_back(0x90);
    nops(16);

    FakeProcessHandle proc({
        {{base, code.size(), MemProt::ReadExec, MemType::Image, MemState::Committed, "/tmp/game"}, code},
    }, {});

    auto sig = ce::makeSignature(proc, base + targetOff, base, code.size(), 64);
    bool startsRight = sig.pattern.rfind("48 8B 05", 0) == 0;
    bool hasWildcards = sig.pattern.find("??") != std::string::npos;
    bool endsRet = sig.pattern.size() >= 2 && sig.pattern.substr(sig.pattern.size() - 2) == "C3";

    printf("  pattern: %s (unique=%d)\n", sig.pattern.c_str(), sig.unique ? 1 : 0);
    printf("  wildcards rip-disp + extends to unique (ends C3): %s\n",
           (sig.unique && startsRight && hasWildcards && endsRet) ? "OK" : "FAILED");

    // The same bytes in another mapping of the module (a second executable
    // segment) make the signature ambiguous for AOBScanModule: uniqueness is
    // checked across every readable mapping of the file, not just one VMA.
    const uintptr_t second = base + 0x10000;
    FakeProcessHandle twoSegments({
        {{base, code.size(), MemProt::ReadExec, MemType::Image, MemState::Committed, "/tmp/game"}, code},
        {{second, code.size(), MemProt::ReadExec, MemType::Image, MemState::Committed, "/tmp/game"}, code},
    }, {});
    auto moduleSig = ce::makeSignature(twoSegments, base + targetOff, 64);
    bool moduleOk = moduleSig.moduleWide && !moduleSig.unique && !moduleSig.incomplete;
    printf("  uniqueness covers every mapping of the module: %s\n", moduleOk ? "OK" : "FAILED");

    // A mapping that cannot be read in full cannot confirm uniqueness.
    std::vector<uint8_t> head(code.begin(), code.begin() + 40);
    FakeProcessHandle shortRead({
        {{base, code.size(), MemProt::ReadExec, MemType::Image, MemState::Committed, "/tmp/game"}, head},
    }, {});
    auto partial = ce::makeSignature(shortRead, base + targetOff, 64);
    bool partialOk = !partial.pattern.empty() && partial.incomplete && !partial.unique;
    printf("  a short read leaves uniqueness unverified: %s\n", partialOk ? "OK" : "FAILED");
}

// Reusable PointerMap: build the pointer graph once, scan multiple targets and
// re-resolve saved paths without re-reading the process. One module pointer
// (game+0x10 -> heap) reaches two targets (heap+0x20, heap+0x30).
void test_pointer_map_reuse() {
    printf("\n── Test: pointer map (reuse + fast rescan) ──\n");
    const uintptr_t M = 0x400000, H = 0x10000000;
    std::vector<uint8_t> module(0x1000, 0), heap(0x1000, 0);
    std::memcpy(module.data() + 0x10, &H, sizeof(H));      // game+0x10 -> heap base
    int32_t v1 = 1337, v2 = 4242;
    std::memcpy(heap.data() + 0x20, &v1, 4);               // heap+0x20 = 1337
    std::memcpy(heap.data() + 0x30, &v2, 4);               // heap+0x30 = 4242

    FakeProcessHandle proc({
        {{M, module.size(), MemProt::Read, MemType::Image, MemState::Committed, "/tmp/game"}, module},
        {{H, heap.size(), MemProt::ReadWrite, MemType::Private, MemState::Committed, "[heap]"}, heap},
    }, {
        {M, module.size(), "game", "/tmp/game", true},
    });

    PointerScanner scanner;
    PointerScanConfig cfg;
    cfg.maxDepth = 4; cfg.maxOffset = 2048; cfg.alignedOnly = true; cfg.staticOnly = true;

    auto c1 = cfg; c1.targetAddress = H + 0x20;
    auto c2 = cfg; c2.targetAddress = H + 0x30;
    auto s1 = scanner.scan(proc, c1);
    auto s2 = scanner.scan(proc, c2);

    PointerMap map = buildPointerMap(proc, cfg);
    auto m1 = scanner.scanWithMap(map, c1);
    auto m2 = scanner.scanWithMap(map, c2);

    auto sig = [](const std::vector<PointerPath>& v) {
        std::vector<std::string> s;
        for (const auto& p : v) s.push_back(p.toString());
        std::sort(s.begin(), s.end());
        return s;
    };
    bool reuseOk = !m1.empty() && sig(m1) == sig(s1) && sig(m2) == sig(s2) && sig(m1) != sig(m2);

    PointerPath path1;
    path1.module = "game"; path1.moduleBase = M; path1.baseOffset = 0x10; path1.offsets = {0x20};
    bool resolveOk = map.resolve(path1) == H + 0x20 &&
        map.resolve(path1) == PointerScanner::dereference(proc, path1) &&
        map.valueAt(M + 0x10).value_or(0) == H &&
        !map.valueAt(M + 0x18).has_value();

    const char* td = std::getenv("TMPDIR");
    std::string mp = std::string(td ? td : "/tmp") + "/ce-pmap-" + std::to_string(getpid()) + ".bin";
    bool saveOk = map.save(mp);
    std::string err;
    PointerMap loaded = PointerMap::load(mp, &err);
    bool loadOk = saveOk && err.empty() && loaded.size() == map.size() &&
        loaded.resolve(path1) == H + 0x20;
    std::remove(mp.c_str());

    std::vector<PointerPath> paths = {path1};
    auto byMap     = rescanPointerPathsWithMap(map, paths, H + 0x20);
    auto byMapMiss = rescanPointerPathsWithMap(map, paths, H + 0x99);
    auto valMap    = rescanPointerPathsByValueWithMap(proc, map, paths, 1337, 4);
    auto valMapMs  = rescanPointerPathsByValueWithMap(proc, map, paths, 9999, 4);
    auto valOld    = rescanPointerPathsByValue(proc, paths, 1337, 4);
    bool rescanOk = byMap.size() == 1 && byMapMiss.empty() &&
        valMap.size() == 1 && valMapMs.empty() && valMap.size() == valOld.size();

    printf("  build-once, scan two targets == independent scans: %s\n", reuseOk ? "OK" : "FAILED");
    printf("  resolve == dereference, valueAt correct: %s\n", resolveOk ? "OK" : "FAILED");
    printf("  map save/load round-trip resolves: %s\n", loadOk ? "OK" : "FAILED");
    printf("  map-based rescan (addr + value) matches: %s\n", rescanOk ? "OK" : "FAILED");

    // A cancel that lands before the worker thread enters scan() (the window
    // closed right after Scan) must still stop it.
    PointerScanner cancelledFirst;
    cancelledFirst.cancel();
    const bool cancelOk = cancelledFirst.scan(proc, c1).empty() && cancelledFirst.wasCancelled();
    printf("  a cancel before the scan starts stops it: %s\n", cancelOk ? "OK" : "FAILED");
}

// The breadth-first search the scanner used before it searched depth first,
// kept as the reference for which paths a scan returns and in what order.
static std::vector<PointerPath> referencePointerBfs(const PointerMap& map, const PointerScanConfig& config,
                                                    bool& truncated) {
    const auto& entries = map.entriesByTarget();
    const auto& modules = map.modules();
    auto findModule = [&](uintptr_t addr) -> const ModuleInfo* {
        for (const auto& m : modules)
            if (addr >= m.base && addr - m.base < m.size) return &m;
        return nullptr;
    };
    struct Item { uintptr_t address; std::vector<int32_t> offsets; int depth; std::vector<uintptr_t> ancestors; };
    std::vector<Item> queue{{config.targetAddress, {}, 0, {config.targetAddress}}};
    std::vector<PointerPath> results;
    truncated = false;
    for (size_t head = 0; head < queue.size(); ++head) {
        const Item item = queue[head];
        uintptr_t searchMin = item.address > (uintptr_t)config.maxOffset ? item.address - config.maxOffset : 0;
        uintptr_t searchMax = item.address;
        if (config.negativeOffsets)
            searchMax = item.address + std::min<uintptr_t>(config.maxOffset, UINTPTR_MAX - item.address);
        auto lo = std::lower_bound(entries.begin(), entries.end(), searchMin,
            [](const PointerMap::Entry& e, uintptr_t v) { return e.pointsTo < v; });
        auto hi = std::upper_bound(entries.begin(), entries.end(), searchMax,
            [](uintptr_t v, const PointerMap::Entry& e) { return v < e.pointsTo; });
        for (auto it = lo; it != hi; ++it) {
            const int32_t offset = (int32_t)(item.address - it->pointsTo);
            auto offsets = item.offsets;
            offsets.insert(offsets.begin(), offset);
            if (const auto* mod = findModule(it->locatedAt)) {
                const size_t index = mod - modules.data();
                if (config.shardCount <= 1 || index % config.shardCount == config.shardIndex) {
                    if (results.size() >= config.maxResults) { truncated = true; return results; }
                    results.push_back({mod->name, mod->base, it->locatedAt - mod->base, offsets});
                }
            } else if (!config.staticOnly &&
                       (config.shardCount <= 1 || ((it->locatedAt >> 12) % config.shardCount) == config.shardIndex)) {
                if (results.size() >= config.maxResults) { truncated = true; return results; }
                results.push_back({"", 0, it->locatedAt, offsets});
            }
            if (item.depth + 1 < config.maxDepth &&
                std::find(item.ancestors.begin(), item.ancestors.end(), it->locatedAt) == item.ancestors.end()) {
                auto ancestors = item.ancestors;
                ancestors.push_back(it->locatedAt);
                queue.push_back({it->locatedAt, offsets, item.depth + 1, std::move(ancestors)});
            }
        }
    }
    return results;
}

static bool samePointerPaths(const std::vector<PointerPath>& a, const std::vector<PointerPath>& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (a[i].module != b[i].module || a[i].moduleBase != b[i].moduleBase ||
            a[i].baseOffset != b[i].baseOffset || a[i].offsets != b[i].offsets) return false;
    return true;
}

// The depth-first search returns what the breadth-first search returned, in the
// same order, holds a bounded amount of memory, stops at its work limit and
// answers a cancel quickly. Map building keeps only pointers into readable
// memory, reads each region at its own pointer width and stops at its entry
// limit; duplicate module names are not used as bases; value rescans decode in
// the target's byte order.
void test_pointer_scan_search_limits() {
    printf("\n── Test: pointer scan search order and limits ──\n");
    constexpr uintptr_t G = 0x400000, L = 0x500000, H = 0x10000000;
    PointerMap graph;
    graph.setModules({{G, 0x1000, "game", "/tmp/game", true}, {L, 0x1000, "lib", "/tmp/lib", true}});
    std::vector<uintptr_t> slots;
    for (uintptr_t a = G; a < G + 0x1000; a += 8) slots.push_back(a);
    for (uintptr_t a = L; a < L + 0x1000; a += 8) slots.push_back(a);
    for (uintptr_t a = H; a < H + 0x2000; a += 8) slots.push_back(a);
    uint64_t seed = 0x9e3779b97f4a7c15ull;
    auto next = [&] { seed = seed * 6364136223846793005ull + 1442695040888963407ull; return seed >> 33; };
    for (size_t i = slots.size() - 1; i > 0; --i) std::swap(slots[i], slots[next() % (i + 1)]);
    std::vector<PointerMap::Entry> random;
    for (size_t i = 0; i < 400; ++i)   // one value per slot, as in a real map
        random.push_back({H + (uintptr_t)(next() % 0x2000), slots[i]});
    graph.setEntries(random);

    bool sameOrder = true;
    size_t compared = 0;
    for (int depth = 1; depth <= 5; ++depth)
        for (bool negative : {false, true})
            for (bool staticOnly : {true, false})
                for (size_t cap : {size_t(100000), size_t(7)})
                    for (size_t shards : {size_t(1), size_t(3)})
                        for (size_t shard = 0; shard < shards; ++shard) {
                            PointerScanConfig cfg;
                            cfg.targetAddress = H + 0x1000; cfg.maxDepth = depth; cfg.maxOffset = 0x60;
                            cfg.negativeOffsets = negative; cfg.staticOnly = staticOnly; cfg.maxResults = cap;
                            cfg.shardCount = shards; cfg.shardIndex = shard;
                            bool refTruncated = false;
                            auto expected = referencePointerBfs(graph, cfg, refTruncated);
                            PointerScanner scanner;
                            auto found = scanner.scanWithMap(graph, cfg);
                            sameOrder &= samePointerPaths(found, expected) &&
                                (scanner.limitReached() == PointerScanLimit::Results) == refTruncated &&
                                scanner.truncated() == refTruncated;
                            compared += expected.size();
                        }
    printf("  depth-first search returns the breadth-first paths in order (%zu paths): %s\n",
           compared, sameOrder && compared > 1000 ? "OK" : "FAILED");

    PointerScanConfig deep;
    deep.targetAddress = H + 0x1000; deep.maxDepth = 5; deep.maxOffset = 0x80; deep.staticOnly = false;
    PointerScanner fullScanner;
    const auto full = fullScanner.scanWithMap(graph, deep);
    deep.maxVisits = 200;
    PointerScanner budgetScanner;
    const auto cut = budgetScanner.scanWithMap(graph, deep);
    bool budgetOk = !full.empty() && fullScanner.limitReached() == PointerScanLimit::None &&
        budgetScanner.limitReached() == PointerScanLimit::Work && budgetScanner.truncated() &&
        cut.size() < full.size() &&
        samePointerPaths(cut, std::vector<PointerPath>(full.begin(), full.begin() + cut.size()));
    printf("  the work limit stops the search and keeps the shortest paths: %s\n", budgetOk ? "OK" : "FAILED");

    // 64 heap slots that all point at the same place: fanout 64 at every level,
    // 64^7 chains. A queue of them exhausted memory; the search is bounded.
    PointerMap dense;
    std::vector<PointerMap::Entry> clique;
    for (uintptr_t i = 0; i < 64; ++i) clique.push_back({H, H + 8 * i});
    dense.setEntries(clique);
    PointerScanConfig wide;
    wide.targetAddress = H + 0x100; wide.maxDepth = 7; wide.maxOffset = 0x400;
    wide.staticOnly = true;   // nothing to record: only the walk itself runs
    wide.maxVisits = 2'000'000;
    PointerScanner denseScanner;
    const auto denseStart = std::chrono::steady_clock::now();
    const auto densePaths = denseScanner.scanWithMap(dense, wide);
    const auto denseSeconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - denseStart).count();
    bool denseOk = denseScanner.limitReached() == PointerScanLimit::Work && densePaths.empty() && denseSeconds < 30;
    wide.staticOnly = false;
    PointerScanner denseResults;
    denseOk &= denseResults.scanWithMap(dense, wide).size() == wide.maxResults &&
        denseResults.limitReached() == PointerScanLimit::Results;
    printf("  a fanout-64 depth-7 graph stops at its limits (%.2f s): %s\n", denseSeconds, denseOk ? "OK" : "FAILED");

    wide.maxVisits = uint64_t(1) << 40;
    wide.staticOnly = true;
    PointerScanner cancelScanner;
    std::vector<PointerPath> cancelled{PointerPath{}};
    const auto cancelStart = std::chrono::steady_clock::now();
    std::thread cancelWorker([&] { cancelled = cancelScanner.scanWithMap(dense, wide); });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    cancelScanner.cancel();
    cancelWorker.join();
    const auto cancelSeconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - cancelStart).count();
    printf("  a cancel stops a running search promptly (%.2f s): %s\n", cancelSeconds,
           cancelled.empty() && cancelSeconds < 5 ? "OK" : "FAILED");

    // Map building: a value pointing into an unreadable reservation is no
    // pointer; the entry limit stops the read and is reported.
    constexpr uintptr_t R = 0x20000000;
    std::vector<uint8_t> module(0x100, 0), heap(0x100, 0), reserved(0x100, 0);
    const uintptr_t intoReserved = R + 0x40, intoHeap = H + 0x40, intoHeap2 = H + 0x80;
    std::memcpy(module.data() + 0x00, &intoReserved, 8);
    std::memcpy(module.data() + 0x08, &intoHeap, 8);
    std::memcpy(module.data() + 0x10, &intoHeap2, 8);
    FakeProcessHandle proc({
        {{G, module.size(), MemProt::Read, MemType::Image, MemState::Committed, "/tmp/game"}, module},
        {{H, heap.size(), MemProt::ReadWrite, MemType::Private, MemState::Committed, "[heap]"}, heap},
        {{R, reserved.size(), MemProt::None, MemType::Private, MemState::Committed, ""}, reserved},
    }, {{G, module.size(), "game", "/tmp/game", true}});
    PointerScanConfig cfg;
    cfg.targetAddress = H + 0x40; cfg.maxDepth = 1; cfg.maxOffset = 0;
    const auto map = buildPointerMap(proc, cfg);
    bool readableOk = !map.valueAt(G).has_value() && map.valueAt(G + 8) == H + 0x40 &&
        map.valueAt(G + 0x10) == H + 0x80 && !map.truncated();
    printf("  only pointers into readable memory enter the map: %s\n", readableOk ? "OK" : "FAILED");
    cfg.maxMapEntries = 1;
    const auto capped = buildPointerMap(proc, cfg);
    PointerScanner cappedScanner;
    cappedScanner.scan(proc, cfg);
    bool capOk = capped.truncated() && capped.size() == 1 &&
        cappedScanner.limitReached() == PointerScanLimit::MapEntries;
    printf("  the map entry limit stops the read and is reported: %s\n", capOk ? "OK" : "FAILED");
    // A path limit after a cut map reports both.
    cfg.maxResults = 0;
    PointerScanner bothScanner;
    bothScanner.scan(proc, cfg);
    printf("  a cut map stays reported when the path limit also stops the search: %s\n",
           bothScanner.limitReached() == PointerScanLimit::Results && bothScanner.mapTruncated() &&
           bothScanner.limitHit(PointerScanLimit::Results) && !bothScanner.limitHit(PointerScanLimit::Work) &&
           !cappedScanner.limitHit(PointerScanLimit::Results) && cappedScanner.mapTruncated() ? "OK" : "FAILED");
    cfg.maxResults = PointerScanConfig{}.maxResults;

    // Two modules with one name: only the first can be named in a path.
    constexpr uintptr_t D1 = 0x400000, D2 = 0x600000;
    std::vector<uint8_t> first(0x100, 0), second(0x100, 0), heap2(0x100, 0);
    const uintptr_t target = H + 0x40;
    std::memcpy(first.data() + 0x10, &target, 8);
    std::memcpy(second.data() + 0x20, &target, 8);
    FakeProcessHandle twice({
        {{D1, first.size(), MemProt::Read, MemType::Image, MemState::Committed, "/a/dup.dll"}, first},
        {{D2, second.size(), MemProt::Read, MemType::Image, MemState::Committed, "/b/dup.dll"}, second},
        {{H, heap2.size(), MemProt::ReadWrite, MemType::Private, MemState::Committed, "[heap]"}, heap2},
    }, {{D1, first.size(), "dup.dll", "/a/dup.dll", true}, {D2, second.size(), "dup.dll", "/b/dup.dll", true}});
    PointerScanConfig dupCfg;
    dupCfg.targetAddress = target; dupCfg.maxDepth = 1; dupCfg.maxOffset = 0;
    PointerScanner dupScanner;
    const auto dupStatic = dupScanner.scan(twice, dupCfg);
    dupCfg.staticOnly = false;
    const auto dupAll = dupScanner.scan(twice, dupCfg);
    bool dupOk = dupStatic.size() == 1 && dupStatic[0].module == "dup.dll" && dupStatic[0].baseOffset == 0x10 &&
        PointerScanner::dereference(twice, dupStatic[0]) == target &&
        std::any_of(dupAll.begin(), dupAll.end(), [&](const PointerPath& p) {
            return p.module.empty() && p.baseOffset == D2 + 0x20 && PointerScanner::dereference(twice, p) == target;
        }) &&
        std::none_of(dupAll.begin(), dupAll.end(), [&](const PointerPath& p) {
            return p.module == "dup.dll" && p.baseOffset == 0x20;
        });
    printf("  a second module with the same name is no static base: %s\n", dupOk ? "OK" : "FAILED");

    // WoW64: a 64-bit module keeps 8-byte pointers inside a 32-bit program. The
    // map reads it at the width dereference() uses there.
    struct Wow64Fake : FakeProcessHandle {
        using FakeProcessHandle::FakeProcessHandle;
        uintptr_t wideBase = 0, wideSize = 0;
        bool runs32BitCode() override { return true; }
        TargetMachine machineAt(uintptr_t address) override {
            auto d = targetDescription();
            return address >= wideBase && address - wideBase < wideSize ? d.host : d.program;
        }
    };
    constexpr uintptr_t N64 = 0x180000000ull, H64 = 0x200000000ull, E32 = 0x400000;
    std::vector<uint8_t> ntdll(0x100, 0), heap64(0x100, 0), exe(0x100, 0), heap32(0x100, 0);
    const uint64_t wideTarget = H64;
    const uint32_t narrowTarget = H;
    std::memcpy(ntdll.data() + 0x10, &wideTarget, 8);
    std::memcpy(exe.data() + 0x8, &narrowTarget, 4);
    Wow64Fake wow({
        {{E32, exe.size(), MemProt::Read, MemType::Image, MemState::Committed, "/w/game.exe"}, exe},
        {{H, heap32.size(), MemProt::ReadWrite, MemType::Private, MemState::Committed, ""}, heap32},
        {{N64, ntdll.size(), MemProt::Read, MemType::Image, MemState::Committed, "/w/ntdll.dll"}, ntdll},
        {{H64, heap64.size(), MemProt::ReadWrite, MemType::Private, MemState::Committed, ""}, heap64},
    }, {{E32, exe.size(), "game.exe", "/w/game.exe", false}, {N64, ntdll.size(), "ntdll.dll", "/w/ntdll.dll", true}});
    wow.wideBase = N64; wow.wideSize = ntdll.size();
    PointerScanConfig wowCfg;
    wowCfg.maxDepth = 1; wowCfg.maxOffset = 0x40;
    PointerScanner wowScanner;
    wowCfg.targetAddress = H64 + 0x20;
    const auto widePaths = wowScanner.scan(wow, wowCfg);
    wowCfg.targetAddress = H + 0x10;
    const auto narrowPaths = wowScanner.scan(wow, wowCfg);
    bool wowOk = widePaths.size() == 1 && widePaths[0].module == "ntdll.dll" && widePaths[0].baseOffset == 0x10 &&
        PointerScanner::dereference(wow, widePaths[0]) == H64 + 0x20 &&
        narrowPaths.size() == 1 && narrowPaths[0].module == "game.exe" && narrowPaths[0].baseOffset == 0x8 &&
        PointerScanner::dereference(wow, narrowPaths[0]) == H + 0x10;
    printf("  each region is read at the pointer width dereference uses: %s\n", wowOk ? "OK" : "FAILED");

    // A big-endian target: the rescan compares the value in its byte order.
    struct BigEndianFake : FakeProcessHandle {
        using FakeProcessHandle::FakeProcessHandle;
        TargetDescription targetDescription() override {
            auto d = FakeProcessHandle::targetDescription();
            d.host.byteOrder = d.program.byteOrder = ByteOrder::Big;
            return d;
        }
    };
    std::vector<uint8_t> beModule(0x100, 0), beHeap(0x100, 0);
    for (int i = 0; i < 8; ++i) beModule[0x10 + i] = uint8_t(uint64_t(H) >> (56 - 8 * i));
    const uint32_t beValue = 1337;
    for (int i = 0; i < 4; ++i) beHeap[0x20 + i] = uint8_t(beValue >> (24 - 8 * i));
    BigEndianFake be({
        {{G, beModule.size(), MemProt::Read, MemType::Image, MemState::Committed, "/tmp/game"}, beModule},
        {{H, beHeap.size(), MemProt::ReadWrite, MemType::Private, MemState::Committed, "[heap]"}, beHeap},
    }, {{G, beModule.size(), "game", "/tmp/game", true}});
    PointerPath bePath{"game", G, 0x10, {0x20}};
    PointerScanConfig beCfg;
    const auto beMap = buildPointerMap(be, beCfg);
    bool beOk = PointerScanner::dereference(be, bePath) == H + 0x20 && beMap.resolve(bePath) == H + 0x20 &&
        rescanPointerPathsByValue(be, {bePath}, 1337, 4).size() == 1 &&
        rescanPointerPathsByValue(be, {bePath}, 0x39050000, 4).empty() &&
        rescanPointerPathsByValueWithMap(be, beMap, {bePath}, 1337, 4).size() == 1 &&
        rescanPointerPathsByValueWithMap(be, beMap, {bePath}, 0x39050000, 4).empty();
    printf("  value rescans decode in the target's byte order: %s\n", beOk ? "OK" : "FAILED");

    // A rescan can be cancelled and reports progress.
    std::atomic<bool> stopRescan{true};
    std::atomic<float> rescanProgress{0};
    const bool rescanCancelOk = rescanPointerPaths(be, {bePath}, H + 0x20, &stopRescan, &rescanProgress).empty();
    stopRescan = false;
    const bool rescanRunOk = rescanPointerPaths(be, {bePath}, H + 0x20, &stopRescan, &rescanProgress).size() == 1 &&
        rescanProgress.load() == 1.0f;
    printf("  a rescan honours cancel and reports progress: %s\n", rescanCancelOk && rescanRunOk ? "OK" : "FAILED");
}

// 8-byte value written only by a sibling thread, to exercise a non-default
// (8-byte) hardware watch size in find-what-writes.
static volatile uint64_t g_cf_watched8 = 0;
static void cf_writer8() {
    for (int i = 0; i < 200000; ++i) { g_cf_watched8 = g_cf_watched8 + 1; usleep(100); }
}
void test_codefinder_watch_size() {
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
    char tk = 0; (void)!read(fds[0], &tk, 1); close(fds[0]);

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
void test_lua_symbol_info() {
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
        -- reverse lookup (getNameFromAddress) + CE-compat hex fallback
        assert(getNameFromAddress(0xdeadbeef) == 'mysym', 'reverse lookup exact')
        assert(getNameFromAddress(0xdeadbeef + 0x10) == 'mysym+0x10', 'reverse lookup + offset')
        assert(getNameFromAddress(0x1000) == '1000', 'unresolved must fall back to hex, got '..getNameFromAddress(0x1000))
        reinitializeSymbolhandler()
    )");
    bool ok = err.empty();
    printf("  getSymbolInfo + reinitializeSymbolhandler: %s\n",
           ok ? "OK" : ("FAILED (" + err + ")").c_str());
}

void test_lua_region_info() {
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

// Parses a synthetic IL2CPP global-metadata.dat built to the documented header
// layout (magic + version, then the string-literal table/data and identifier
// pool). Asserts both string pools decode, the magic gates detection, and the
// bounds checks reject a wrong magic, an out-of-range region, and a runt buffer.
void test_il2cpp_metadata() {
    printf("\n── Test: IL2CPP global-metadata.dat parser ──\n");

    auto putU32 = [](std::vector<uint8_t>& v, size_t off, uint32_t x) {
        v[off + 0] = static_cast<uint8_t>(x);
        v[off + 1] = static_cast<uint8_t>(x >> 8);
        v[off + 2] = static_cast<uint8_t>(x >> 16);
        v[off + 3] = static_cast<uint8_t>(x >> 24);
    };

    std::vector<uint8_t> f(32, 0);   // 32-byte header, patched below
    auto pushU32 = [&](uint32_t x) {
        f.push_back(static_cast<uint8_t>(x));
        f.push_back(static_cast<uint8_t>(x >> 8));
        f.push_back(static_cast<uint8_t>(x >> 16));
        f.push_back(static_cast<uint8_t>(x >> 24));
    };

    // string-literal table: {len=5, dataIndex=0}, {len=6, dataIndex=5}
    const uint32_t litOff = static_cast<uint32_t>(f.size());
    pushU32(5); pushU32(0);
    pushU32(6); pushU32(5);
    const uint32_t litSize = static_cast<uint32_t>(f.size()) - litOff;   // 16
    // string-literal data
    const uint32_t litDataOff = static_cast<uint32_t>(f.size());
    const std::string litData = "helloworld!";
    f.insert(f.end(), litData.begin(), litData.end());
    const uint32_t litDataSize = static_cast<uint32_t>(litData.size());  // 11
    // identifier pool: null-terminated names
    const uint32_t strOff = static_cast<uint32_t>(f.size());
    const std::string idPool("System\0GameObject\0Player\0", 25);
    f.insert(f.end(), idPool.begin(), idPool.end());
    const uint32_t strSize = static_cast<uint32_t>(idPool.size());       // 25

    putU32(f, 0, 0xFAB11BAFu);   // sanity
    putU32(f, 4, 29);            // version
    putU32(f, 8, litOff);
    putU32(f, 12, litSize);
    putU32(f, 16, litDataOff);
    putU32(f, 20, litDataSize);
    putU32(f, 24, strOff);
    putU32(f, 28, strSize);

    auto md = parseIl2CppMetadata(f.data(), f.size());
    bool ok = md.has_value() && md->version == 29 &&
        md->strings.size() == 3 &&
        md->strings[0] == "System" && md->strings[1] == "GameObject" &&
        md->strings[2] == "Player" &&
        md->stringLiterals.size() == 2 &&
        md->stringLiterals[0] == "hello" && md->stringLiterals[1] == "world!";

    bool detectOk = isIl2CppMetadata(f.data(), f.size());

    std::vector<uint8_t> bad = f;
    bad[0] ^= 0xFF;                              // corrupt the magic
    bool rejectOk = !parseIl2CppMetadata(bad.data(), bad.size()).has_value() &&
        !isIl2CppMetadata(bad.data(), bad.size());

    std::vector<uint8_t> oob = f;
    putU32(oob, 28, static_cast<uint32_t>(f.size()));  // stringSize overruns buffer
    bool boundsOk = !parseIl2CppMetadata(oob.data(), oob.size()).has_value();

    std::vector<uint8_t> tiny(8, 0);
    putU32(tiny, 0, 0xFAB11BAFu);               // right magic, too short for header
    bool tinyOk = !parseIl2CppMetadata(tiny.data(), tiny.size()).has_value();

    printf("  header + string pools parse: %s\n", ok ? "OK" : "FAILED");
    printf("  magic detection: %s\n", detectOk ? "OK" : "FAILED");
    printf("  wrong-magic reject: %s\n", rejectOk ? "OK" : "FAILED");
    printf("  out-of-bounds region reject: %s\n", boundsOk ? "OK" : "FAILED");
    printf("  short-buffer reject: %s\n", tinyOk ? "OK" : "FAILED");
}

// Build a synthetic v29 global-metadata.dat: a full header, a fields table, two
// type definitions (Game.Player {health, mana} and Enemy {name}), and one image
// (Assembly-CSharp.dll owning both types). Shared by the parser, locate, and Lua
// tests. NOTE: this only proves the parser reads back the v29 layout it declares;
// real-file validation (against an actual Unity build) is a separate step.
static std::vector<uint8_t> buildSyntheticV29Metadata() {
    auto putU32 = [](std::vector<uint8_t>& v, size_t off, uint32_t x) {
        v[off + 0] = static_cast<uint8_t>(x);
        v[off + 1] = static_cast<uint8_t>(x >> 8);
        v[off + 2] = static_cast<uint8_t>(x >> 16);
        v[off + 3] = static_cast<uint8_t>(x >> 24);
    };
    auto appU32 = [](std::vector<uint8_t>& v, uint32_t x) {
        v.push_back(static_cast<uint8_t>(x));
        v.push_back(static_cast<uint8_t>(x >> 8));
        v.push_back(static_cast<uint8_t>(x >> 16));
        v.push_back(static_cast<uint8_t>(x >> 24));
    };

    // String region: concatenated NUL-terminated identifiers; record byte offsets
    // (StringIndex values are byte offsets into this region).
    std::vector<uint8_t> strs;
    auto addStr = [&](const std::string& s) {
        uint32_t off = static_cast<uint32_t>(strs.size());
        strs.insert(strs.end(), s.begin(), s.end());
        strs.push_back('\0');
        return off;
    };
    uint32_t sEmpty  = addStr("");                     // 0 -> empty namespace
    uint32_t sGame   = addStr("Game");
    uint32_t sPlayer = addStr("Player");
    uint32_t sEnemy  = addStr("Enemy");
    uint32_t sHealth = addStr("health");
    uint32_t sMana   = addStr("mana");
    uint32_t sName   = addStr("name");
    uint32_t sAsm    = addStr("Assembly-CSharp.dll");

    // Fields table: 12-byte records {nameIndex, typeIndex, token}.
    std::vector<uint8_t> fields;
    auto addField = [&](uint32_t nameOff, int32_t typeIdx, uint32_t token) {
        appU32(fields, nameOff);
        appU32(fields, static_cast<uint32_t>(typeIdx));
        appU32(fields, token);
    };
    addField(sHealth, 5, 0x04000001);  // field 0
    addField(sMana,   5, 0x04000002);  // field 1
    addField(sName,   6, 0x04000003);  // field 2

    // Type definitions: 88-byte (0x58) records; patch the fields we read.
    auto addType = [](std::vector<uint8_t>& td, uint32_t nameOff, uint32_t nsOff,
                      int32_t fieldStart, uint16_t fieldCount, uint32_t token) {
        size_t base = td.size();
        td.resize(base + 0x58, 0);
        td[base + 0x00] = (uint8_t)nameOff;  td[base + 0x01] = (uint8_t)(nameOff >> 8);
        td[base + 0x02] = (uint8_t)(nameOff >> 16); td[base + 0x03] = (uint8_t)(nameOff >> 24);
        td[base + 0x04] = (uint8_t)nsOff;    td[base + 0x05] = (uint8_t)(nsOff >> 8);
        td[base + 0x06] = (uint8_t)(nsOff >> 16);   td[base + 0x07] = (uint8_t)(nsOff >> 24);
        uint32_t fs = (uint32_t)fieldStart;
        td[base + 0x20] = (uint8_t)fs; td[base + 0x21] = (uint8_t)(fs >> 8);
        td[base + 0x22] = (uint8_t)(fs >> 16); td[base + 0x23] = (uint8_t)(fs >> 24);
        td[base + 0x44] = (uint8_t)fieldCount; td[base + 0x45] = (uint8_t)(fieldCount >> 8);
        td[base + 0x54] = (uint8_t)token; td[base + 0x55] = (uint8_t)(token >> 8);
        td[base + 0x56] = (uint8_t)(token >> 16); td[base + 0x57] = (uint8_t)(token >> 24);
    };
    std::vector<uint8_t> typedefs;
    addType(typedefs, sPlayer, sGame,  0, 2, 0x02000001);  // Game.Player {health, mana}
    addType(typedefs, sEnemy,  sEmpty, 2, 1, 0x02000002);  // Enemy {name}

    // Methods table: 0x1C-byte records {nameIndex@0, ..., token@0x18}. Player owns
    // "Update" (method 0), Enemy owns "Attack" (method 1). Wire methodStart@0x24 +
    // method_count@0x40 into the type records.
    uint32_t sUpdate = static_cast<uint32_t>(strs.size());
    { std::string s = "Update"; strs.insert(strs.end(), s.begin(), s.end()); strs.push_back('\0'); }
    uint32_t sAttack = static_cast<uint32_t>(strs.size());
    { std::string s = "Attack"; strs.insert(strs.end(), s.begin(), s.end()); strs.push_back('\0'); }
    auto addMethod = [](std::vector<uint8_t>& mt, uint32_t nameOff, uint32_t token) {
        size_t base = mt.size();
        mt.resize(base + 0x1C, 0);
        mt[base + 0] = (uint8_t)nameOff; mt[base + 1] = (uint8_t)(nameOff >> 8);
        mt[base + 2] = (uint8_t)(nameOff >> 16); mt[base + 3] = (uint8_t)(nameOff >> 24);
        mt[base + 0x18] = (uint8_t)token; mt[base + 0x19] = (uint8_t)(token >> 8);
        mt[base + 0x1A] = (uint8_t)(token >> 16); mt[base + 0x1B] = (uint8_t)(token >> 24);
    };
    std::vector<uint8_t> methods;
    addMethod(methods, sUpdate, 0x06000001);   // method 0: Player.Update
    addMethod(methods, sAttack, 0x06000002);   // method 1: Enemy.Attack
    typedefs[0x24] = 0;        typedefs[0x40] = 1;   // Player: methodStart 0, count 1
    typedefs[0x58 + 0x24] = 1; typedefs[0x58 + 0x40] = 1;  // Enemy: methodStart 1, count 1

    // Images: 40-byte (0x28) records; patch name/typeStart/typeCount.
    std::vector<uint8_t> images;
    {
        size_t base = images.size();
        images.resize(base + 0x28, 0);
        images[base + 0x00] = (uint8_t)sAsm; images[base + 0x01] = (uint8_t)(sAsm >> 8);
        images[base + 0x02] = (uint8_t)(sAsm >> 16); images[base + 0x03] = (uint8_t)(sAsm >> 24);
        // typeStart @0x08 = 0, typeCount @0x0C = 2
        images[base + 0x0C] = 2;
    }

    // Assemble: 0x100-byte header, then fields, typedefs, images, strings.
    std::vector<uint8_t> f(0x100, 0);
    auto place = [&](const std::vector<uint8_t>& region) {
        uint32_t off = static_cast<uint32_t>(f.size());
        f.insert(f.end(), region.begin(), region.end());
        return off;
    };
    uint32_t fieldsOff = place(fields);
    uint32_t typedefsOff = place(typedefs);
    uint32_t imagesOff = place(images);
    uint32_t methodsOff = place(methods);
    uint32_t stringOff = place(strs);

    putU32(f, 0x00, 0xFAB11BAFu);   // sanity
    putU32(f, 0x04, 29);            // version
    putU32(f, 0x08, 0x08);          // stringLiteral offset (empty region, in-bounds)
    putU32(f, 0x0C, 0);             // stringLiteral size
    putU32(f, 0x10, 0x08);          // stringLiteralData offset
    putU32(f, 0x14, 0);             // stringLiteralData size
    putU32(f, 0x18, stringOff);     // string offset
    putU32(f, 0x1C, static_cast<uint32_t>(strs.size()));
    putU32(f, 0x30, methodsOff);    // methods offset
    putU32(f, 0x34, static_cast<uint32_t>(methods.size()));
    putU32(f, 0x60, fieldsOff);
    putU32(f, 0x64, static_cast<uint32_t>(fields.size()));
    putU32(f, 0xA0, typedefsOff);
    putU32(f, 0xA4, static_cast<uint32_t>(typedefs.size()));
    putU32(f, 0xA8, imagesOff);
    putU32(f, 0xAC, static_cast<uint32_t>(images.size()));
    return f;
}

void test_il2cpp_metadata_tables() {
    printf("\n── Test: IL2CPP metadata type/field tables (v29) ──\n");

    auto putU32 = [](std::vector<uint8_t>& v, size_t off, uint32_t x) {
        v[off + 0] = static_cast<uint8_t>(x);
        v[off + 1] = static_cast<uint8_t>(x >> 8);
        v[off + 2] = static_cast<uint8_t>(x >> 16);
        v[off + 3] = static_cast<uint8_t>(x >> 24);
    };
    std::vector<uint8_t> f = buildSyntheticV29Metadata();

    auto md = parseIl2CppMetadata(f.data(), f.size());
    bool base = md.has_value() && md->version == 29 && md->tablesDecoded;

    bool typesOk = base && md->types.size() == 2 &&
        md->types[0].name == "Player" && md->types[0].namespaceName == "Game" &&
        md->types[0].fullName() == "Game.Player" &&
        md->types[0].fields.size() == 2 &&
        md->types[0].fields[0].name == "health" &&
        md->types[0].fields[0].typeIndex == 5 &&
        md->types[0].fields[1].name == "mana" &&
        md->types[1].name == "Enemy" && md->types[1].namespaceName.empty() &&
        md->types[1].fullName() == "Enemy" &&
        md->types[1].fields.size() == 1 &&
        md->types[1].fields[0].name == "name";

    bool imagesOk = base && md->images.size() == 1 &&
        md->images[0].name == "Assembly-CSharp.dll" &&
        md->images[0].typeStart == 0 && md->images[0].typeCount == 2;

    bool methodsOk = base && md->types.size() == 2 &&
        md->types[0].methods.size() == 1 && md->types[0].methods[0].name == "Update" &&
        md->types[0].methods[0].token == 0x06000001u &&
        md->types[1].methods.size() == 1 && md->types[1].methods[0].name == "Attack" &&
        md->types[1].methods[0].token == 0x06000002u;

    bool supportOk = il2cppTablesSupported(27) && il2cppTablesSupported(29) &&
        il2cppTablesSupported(31) && !il2cppTablesSupported(24) && !il2cppTablesSupported(16);

    // Unsupported version: string pools still parse, tables are skipped.
    std::vector<uint8_t> older = f;
    putU32(older, 0x04, 24);
    auto mdOlder = parseIl2CppMetadata(older.data(), older.size());
    bool versionGateOk = mdOlder.has_value() && !mdOlder->tablesDecoded &&
        mdOlder->types.empty();

    // Corrupt a table region: decode is skipped (non-fatal), string pool survives.
    std::vector<uint8_t> corrupt = f;
    putU32(corrupt, 0xA4, static_cast<uint32_t>(f.size()));  // typeDefs size overruns
    auto mdCorrupt = parseIl2CppMetadata(corrupt.data(), corrupt.size());
    bool corruptOk = mdCorrupt.has_value() && !mdCorrupt->tablesDecoded &&
        !mdCorrupt->strings.empty();

    printf("  types + fields decode (Game.Player{health,mana}, Enemy{name}): %s\n",
           typesOk ? "OK" : "FAILED");
    printf("  image grouping (Assembly-CSharp.dll -> 2 types): %s\n",
           imagesOk ? "OK" : "FAILED");
    printf("  method decode (Player.Update, Enemy.Attack + tokens): %s\n",
           methodsOk ? "OK" : "FAILED");
    printf("  version support gate (27/29/31 yes, 24/16 no): %s\n",
           supportOk ? "OK" : "FAILED");
    printf("  unsupported version keeps string pools, skips tables: %s\n",
           versionGateOk ? "OK" : "FAILED");
    printf("  corrupt table region is non-fatal: %s\n", corruptOk ? "OK" : "FAILED");
}

// findIl2CppMetadataPath locates a game's global-metadata.dat from its mapped
// file paths, and the getIl2CppClasses Lua binding browses it. Builds a temp
// Unity-like tree (<base>/MyGame_Data/il2cpp_data/Metadata/global-metadata.dat)
// so both the on-disk locate and the Lua path run without a live process.
void test_il2cpp_locate() {
    printf("\n── Test: IL2CPP metadata locate + Lua browse ──\n");
    namespace fs = std::filesystem;
    std::error_code ec;

    fs::path base = fs::temp_directory_path() / ("ce-il2cpp-" + std::to_string(getpid()));
    fs::path metaDir = base / "MyGame_Data" / "il2cpp_data" / "Metadata";
    fs::remove_all(base, ec);
    fs::create_directories(metaDir, ec);
    fs::path metaFile = metaDir / "global-metadata.dat";
    {
        auto bytes = buildSyntheticV29Metadata();
        std::ofstream out(metaFile, std::ios::binary);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }
    const std::string want = metaFile.string();
    const std::string exe = (base / "MyGame.x86_64").string();
    const std::string managedDll = (base / "MyGame_Data" / "Managed" / "Assembly-CSharp.dll").string();
    const std::string sysLib = "/usr/lib/x86_64-linux-gnu/libc.so.6";

    // Case 2: the executable sits next to <Game>_Data (scan its siblings).
    auto viaExe = ce::findIl2CppMetadataPath({sysLib, exe});
    bool exeOk = viaExe.has_value() && *viaExe == want;
    // Case 1: a path already inside the <Game>_Data tree.
    auto viaData = ce::findIl2CppMetadataPath({managedDll});
    bool dataOk = viaData.has_value() && *viaData == want;
    // System-only mappings: nothing game-relevant to derive from.
    auto viaSys = ce::findIl2CppMetadataPath({sysLib, "/lib/ld-linux-x86-64.so.2"});
    bool sysOk = !viaSys.has_value();
    // A game-looking exe whose folder has no metadata: no false positive.
    auto viaUnrelated = ce::findIl2CppMetadataPath(
        {(fs::temp_directory_path() / "ce-il2cpp-nope" / "Foo.x86_64").string()});
    bool unrelatedOk = !viaUnrelated.has_value();

    printf("  locate via executable next to _Data: %s\n", exeOk ? "OK" : "FAILED");
    printf("  locate via path inside _Data tree: %s\n", dataOk ? "OK" : "FAILED");
    printf("  system-only paths locate nothing: %s\n", sysOk ? "OK" : "FAILED");
    printf("  unrelated game dir without metadata: %s\n", unrelatedOk ? "OK" : "FAILED");

    // Lua browse of the located file (explicit path, no process needed).
    LuaEngine engine;
    std::string code =
        "local m = getIl2CppClasses([[" + want + "]])\n"
        "if not m then return 'nil' end\n"
        "if not m.decoded then return 'notdecoded' end\n"
        "local c = m.classes\n"
        "return m.version..'|'..#c..'|'..c[1].fullName..'|'..c[1].image..'|'"
        "..(c[1].fields[1] or '?')..'|'..(c[1].fields[2] or '?')..'|'"
        "..c[2].fullName..'|'..(c[2].fields[1] or '?')\n";
    auto res = engine.evalToString(code);
    bool luaOk = res.has_value() &&
        *res == "29|2|Game.Player|Assembly-CSharp.dll|health|mana|Enemy|name";

    std::string errCode =
        "local m, err = getIl2CppClasses([[/nonexistent/xyz.dat]])\n"
        "return (m == nil and type(err) == 'string') and 'ok' or 'bad'\n";
    auto errRes = engine.evalToString(errCode);
    bool luaErrOk = errRes.has_value() && *errRes == "ok";

    printf("  Lua getIl2CppClasses(path) browses classes/fields: %s\n", luaOk ? "OK" : "FAILED");
    printf("  Lua getIl2CppClasses bad path returns nil+error: %s\n", luaErrOk ? "OK" : "FAILED");

    fs::remove_all(base, ec);
}

// Real-file validation, reproducible on demand: point CE_IL2CPP_METADATA at a
// real Unity global-metadata.dat and this asserts the decode against ground truth
// (System.Collections.Generic.List`1 must carry the real BCL fields, and an
// Assembly-CSharp.dll image must exist). Skipped when the env var is unset, so CI
// stays green without shipping a game file. The v27/v31 layout was validated this
// way against Disco Elysium and Esoteric Ebb / Zero Parades.
void test_il2cpp_real_file() {
    printf("\n── Test: IL2CPP real file (set CE_IL2CPP_METADATA to run) ──\n");
    const char* path = std::getenv("CE_IL2CPP_METADATA");
    if (!path || !*path) { printf("  CE_IL2CPP_METADATA unset: SKIPPED\n"); return; }
    std::ifstream in(path, std::ios::binary);
    if (!in) { printf("  cannot open %s: SKIPPED\n", path); return; }
    std::vector<uint8_t> buf((std::istreambuf_iterator<char>(in)),
                             std::istreambuf_iterator<char>());
    auto md = parseIl2CppMetadata(buf.data(), buf.size());
    if (!md) { printf("  parse failed: FAILED\n"); return; }
    printf("  version=%d names=%zu types=%zu images=%zu decoded=%d\n", md->version,
           md->strings.size(), md->types.size(), md->images.size(), md->tablesDecoded ? 1 : 0);
    if (!md->tablesDecoded) {
        printf("  tables not decoded for this metadata version: SKIPPED\n");
        return;
    }
    const Il2CppTypeDef* list = nullptr;
    for (const auto& t : md->types)
        if (t.name == "List`1" && t.namespaceName == "System.Collections.Generic") { list = &t; break; }
    bool fieldsOk = false;
    if (list) {
        auto has = [&](const char* n) {
            for (const auto& fld : list->fields) if (fld.name == n) return true;
            return false;
        };
        fieldsOk = has("_items") && has("_size") && has("_version");
    }
    bool imgOk = false;
    for (const auto& img : md->images)
        if (img.name == "Assembly-CSharp.dll") { imgOk = true; break; }
    printf("  List`1 decodes with _items/_size/_version: %s\n", (list && fieldsOk) ? "OK" : "FAILED");
    printf("  Assembly-CSharp.dll image present: %s\n", imgOk ? "OK" : "FAILED");

    // If a GameAssembly binary is also provided, resolve offsets and check a
    // known layout (UnityEngine.Vector3 x@0x10, y@0x14, z@0x18, all instance).
    const char* ga = std::getenv("CE_IL2CPP_GAMEASSEMBLY");
    if (ga && *ga) {
        auto layout = ce::resolveIl2CppLayout(*md, ga);
        if (!layout.ok) { printf("  GameAssembly resolve failed: %s (SKIPPED)\n", layout.error.c_str()); return; }
        const ce::Il2CppClassLayout* v3 = nullptr;
        for (const auto& c : layout.classes)
            if (c.name == "Vector3" && c.namespaceName == "UnityEngine") { v3 = &c; break; }
        bool v3ok = false;
        if (v3) {
            auto off = [&](const char* n) -> long {
                for (const auto& fl : v3->fields)
                    if (fl.name == n && !fl.isStatic) return fl.offset;
                return -1;
            };
            v3ok = off("x") == 0x10 && off("y") == 0x14 && off("z") == 0x18;
        }
        printf("  Vector3 x/y/z resolve to 0x10/0x14/0x18: %s\n", v3ok ? "OK" : "FAILED");

        // Managed typing: Vector3's x/y/z should type as Float (Il2CppTypeEnum R4).
        bool typeOk = false;
        if (v3) {
            auto def = ce::il2cppClassToStructure(*v3);
            auto isFloat = [&](const char* n) {
                for (const auto& f : def.fields)
                    if (f.name == n) return f.type == ce::ValueType::Float && f.size == 4;
                return false;
            };
            typeOk = isFloat("x") && isFloat("y") && isFloat("z");
        }
        printf("  Vector3 fields type as float: %s\n", typeOk ? "OK" : "FAILED");

        // Managed type NAMES: x/y/z resolve to "System.Single", and every field
        // across the whole binary resolves to a non-empty managed type name
        // (primitives, classes, strings, arrays, generics, pointers all covered).
        bool nameOk = false;
        if (v3) {
            auto tn = [&](const char* n) -> std::string {
                for (const auto& fl : v3->fields) if (fl.name == n && !fl.isStatic) return fl.typeName;
                return {};
            };
            nameOk = tn("x") == "System.Single" && tn("y") == "System.Single" &&
                     tn("z") == "System.Single";
        }
        size_t totalF = 0, emptyF = 0, arityLeak = 0;
        for (const auto& c : layout.classes)
            for (const auto& fl : c.fields) {
                ++totalF;
                if (fl.typeName.empty()) ++emptyF;
                // A concrete generic must read "List<Foo>", never "List`1<Foo>": no
                // arity marker ("`<digits>") should remain immediately before a '<'.
                if (auto lt = fl.typeName.find('<'); lt != std::string::npos && lt > 0 &&
                    std::isdigit((unsigned char)fl.typeName[lt - 1])) {
                    auto tick = fl.typeName.rfind('`', lt);
                    if (tick != std::string::npos && tick < lt) ++arityLeak;
                }
            }
        printf("  Vector3 x/y/z type-name = System.Single: %s\n", nameOk ? "OK" : "FAILED");
        printf("  every field resolves a managed type name (%zu fields, %zu empty): %s\n",
               totalF, emptyF, (totalF > 0 && emptyF == 0) ? "OK" : "FAILED");
        printf("  generics spelled Name<...> (no arity leak, %zu offenders): %s\n",
               arityLeak, arityLeak == 0 ? "OK" : "FAILED");

        // Base-class chain: Transform : Component : Object is the canonical Unity
        // hierarchy, so it doubles as a check that parentIndex parses correctly.
        auto parentOf = [&](const char* full) -> std::string {
            for (const auto& c : layout.classes) if (c.fullName() == full) return c.parentName;
            return "<missing>";
        };
        bool chainOk = parentOf("UnityEngine.Transform") == "UnityEngine.Component" &&
                       parentOf("UnityEngine.Component") == "UnityEngine.Object";
        printf("  base-class chain Transform:Component:Object: %s\n", chainOk ? "OK" : "FAILED");

        // Inherited layout: a Component-derived type has no own instance fields,
        // but its full object layout must inherit Object.m_CachedPtr (the native
        // handle every UnityEngine.Object carries), tagged with its declaring type.
        auto full = ce::il2cppObjectFieldLayout(layout, "UnityEngine.BoxCollider");
        bool inheritOk = false;
        for (const auto& f : full)
            if (f.name == "m_CachedPtr" && f.declaringType == "UnityEngine.Object") { inheritOk = true; break; }
        printf("  BoxCollider inherits Object.m_CachedPtr (declaringType set): %s\n",
               inheritOk ? "OK" : "FAILED");

        // Generic instantiations spell their type arguments: List`1<System.String>,
        // Dictionary`2<K, V>. Count spelled generics (typeName has "`N<...>").
        size_t spelledGenerics = 0;
        for (const auto& c : layout.classes)
            for (const auto& fl : c.fields)
                if (fl.typeName.find('`') != std::string::npos &&
                    fl.typeName.find('<') != std::string::npos &&
                    !fl.typeName.empty() && fl.typeName.back() == '>')
                    ++spelledGenerics;
        printf("  generic fields spell their type args (%zu found): %s\n",
               spelledGenerics, spelledGenerics > 0 ? "OK" : "FAILED");

        // Method resolution: a common BCL class should have methods that resolve
        // to non-zero code RVAs within the binary.
        auto methods = ce::resolveIl2CppMethods(*md, ga, "System.String");
        size_t withBody = 0;
        for (const auto& m : methods) if (m.rva != 0) ++withBody;
        printf("  System.String methods resolve to code (%zu with a body): %s\n",
               withBody, (methods.size() > 0 && withBody > 0) ? "OK" : "FAILED");
    }
}

// Field-offset resolution from the GameAssembly binary, CI-coverable via a
// synthetic PE32+: it carries an Il2CppMetadataRegistration whose fieldOffsets
// give Player{health@0x10 static, mana@0x8 static} and Enemy{name@0x18 instance}
// (matched to buildSyntheticV29Metadata), plus a types array whose Il2CppType
// attrs drive the static/instance classification. Exercises the PE loader, the
// count-match registration finder, and offset + attrs extraction without a game.
void test_il2cpp_binary_offsets() {
    printf("\n── Test: IL2CPP field-offset resolution (synthetic PE) ──\n");
    namespace fs = std::filesystem;

    auto md = parseIl2CppMetadata(buildSyntheticV29Metadata().data(),
                                  buildSyntheticV29Metadata().size());
    if (!md || !md->tablesDecoded || md->types.size() != 2) { printf("  metadata setup: FAILED\n"); return; }

    std::vector<uint8_t> f(0x2400, 0);
    auto pU16 = [&](size_t o, uint16_t v) { f[o] = (uint8_t)v; f[o + 1] = (uint8_t)(v >> 8); };
    auto pU32 = [&](size_t o, uint32_t v) { for (int i = 0; i < 4; ++i) f[o + i] = (uint8_t)(v >> (8 * i)); };
    auto pU64 = [&](size_t o, uint64_t v) { for (int i = 0; i < 8; ++i) f[o + i] = (uint8_t)(v >> (8 * i)); };
    const uint64_t IB = 0x140000000ull;   // image base
    // DOS + PE headers.
    f[0] = 'M'; f[1] = 'Z'; pU32(0x3C, 0x80);
    f[0x80] = 'P'; f[0x81] = 'E';
    pU16(0x84, 0x8664);          // machine x86-64
    pU16(0x86, 1);               // 1 section
    pU16(0x94, 0xF0);            // SizeOfOptionalHeader
    pU16(0x98, 0x20B);           // PE32+
    pU64(0xB0, IB);              // ImageBase (opt+24)
    // Section header (.data): vaddr 0x1000, rawptr 0x400, size 0x2000.
    const char* sn = ".data"; for (int i = 0; i < 5; ++i) f[0x188 + i] = sn[i];
    pU32(0x190, 0x2000); pU32(0x194, 0x1000); pU32(0x198, 0x2000); pU32(0x19C, 0x400);
    // Section body at file 0x400 == rva 0x1000 == VA IB+0x1000.
    auto VA = [&](uint64_t srel) { return IB + 0x1000 + srel; };
    pU32(0x400, 0x10); pU32(0x404, 0x8);   // Player field offsets: health, mana
    pU32(0x408, 0x18);                     // Enemy field offset: name
    pU64(0x410, VA(0x00)); pU64(0x418, VA(0x08));   // fieldOffsets[2] -> the two arrays
    for (int i = 0; i < 7; ++i) pU32(0x430 + i * 0x10 + 8, (i == 5) ? 0x10 : 0);  // Il2CppType.attrs
    for (int i = 0; i < 7; ++i) pU64(0x4B0 + i * 8, VA(0x30 + i * 0x10));         // types[] -> structs
    // Il2CppMetadataRegistration at srel 0x100 (VA IB+0x1100), file 0x500.
    pU32(0x530, 7);           pU64(0x538, VA(0xB0));   // typesCount, types
    pU32(0x550, 2);           pU64(0x558, VA(0x10));   // fieldOffsetsCount, fieldOffsets
    pU32(0x560, 2);           pU64(0x568, VA(0x00));   // typeDefinitionsSizesCount, ...

    fs::path tmp = fs::temp_directory_path() /
        ("ce-il2cpp-ga-" + std::to_string(getpid()) + ".bin");
    { std::ofstream out(tmp, std::ios::binary);
      out.write(reinterpret_cast<const char*>(f.data()), (std::streamsize)f.size()); }

    auto layout = ce::resolveIl2CppLayout(*md, tmp.string());
    std::error_code ec;

    bool ok = layout.ok && layout.classes.size() == 2;
    auto field = [&](size_t c, const char* name) -> const ce::Il2CppResolvedField* {
        if (c >= layout.classes.size()) return nullptr;
        for (const auto& fl : layout.classes[c].fields) if (fl.name == name) return &fl;
        return nullptr;
    };
    const auto* health = ok ? field(0, "health") : nullptr;
    const auto* mana   = ok ? field(0, "mana")   : nullptr;
    const auto* name   = ok ? field(1, "name")   : nullptr;
    bool offOk = health && health->offset == 0x10 && mana && mana->offset == 0x8 &&
                 name && name->offset == 0x18;
    bool kindOk = health && health->isStatic && mana && mana->isStatic &&
                  name && !name->isStatic;

    printf("  finds Il2CppMetadataRegistration + resolves: %s\n", ok ? "OK" : "FAILED");
    printf("  field offsets health=0x10 mana=0x8 name=0x18: %s\n", offOk ? "OK" : "FAILED");
    printf("  static/instance from Il2CppType.attrs: %s\n", kindOk ? "OK" : "FAILED");

    // Lua getIl2CppClassLayout(class, metadataPath, binaryPath): end-to-end through
    // the binding with the same synthetic metadata + PE on disk.
    fs::path metaTmp = fs::temp_directory_path() /
        ("ce-il2cpp-md-" + std::to_string(getpid()) + ".dat");
    { auto mb = buildSyntheticV29Metadata();
      std::ofstream out(metaTmp, std::ios::binary);
      out.write(reinterpret_cast<const char*>(mb.data()), (std::streamsize)mb.size()); }
    LuaEngine engine;
    std::string code =
        "local cs = getIl2CppClassLayout('Player', [[" + metaTmp.string() + "]], [[" +
            tmp.string() + "]])\n"
        "if not cs then return 'nil' end\n"
        "local p\n"
        "for _,c in ipairs(cs) do if c.fullName=='Game.Player' then p=c end end\n"
        "if not p then return 'noplayer' end\n"
        "local h,m\n"
        "for _,f in ipairs(p.fields) do if f.name=='health' then h=f elseif f.name=='mana' then m=f end end\n"
        "if not h or not m then return 'nofield' end\n"
        "return h.offset..'|'..tostring(h.static)..'|'..m.offset\n";
    auto res = engine.evalToString(code);
    bool luaOk = res.has_value() && *res == "16|true|8";
    printf("  Lua getIl2CppClassLayout resolves offsets: %s\n", luaOk ? "OK" : "FAILED");

    fs::remove(tmp, ec);
    fs::remove(metaTmp, ec);

    // A non-il2cpp / truncated binary must fail cleanly, not crash.
    std::vector<uint8_t> junk(64, 0x7f);
    fs::path jp = fs::temp_directory_path() / ("ce-il2cpp-junk-" + std::to_string(getpid()) + ".bin");
    { std::ofstream out(jp, std::ios::binary);
      out.write(reinterpret_cast<const char*>(junk.data()), (std::streamsize)junk.size()); }
    auto bad = ce::resolveIl2CppLayout(*md, jp.string());
    fs::remove(jp, ec);
    printf("  non-il2cpp binary rejected cleanly: %s\n", (!bad.ok && !bad.error.empty()) ? "OK" : "FAILED");
}

// Managed structure typing (#21): turn a resolved IL2CPP class layout into a
// structure-dissector definition, typed from each field's Il2CppTypeEnum, with
// statics/consts dropped. Pure unit test on a hand-built layout (no game file).
void test_il2cpp_structure_typing() {
    printf("\n── Test: IL2CPP managed structure typing ──\n");
    ce::Il2CppClassLayout cls;
    cls.namespaceName = "Game"; cls.name = "Player";
    cls.fields.push_back({"health", 0x10, false, false, 0x08});  // I4 -> Int32
    cls.fields.push_back({"speed",  0x14, false, false, 0x0C});  // R4 -> Float
    cls.fields.push_back({"target", 0x18, false, false, 0x12});  // CLASS -> Pointer
    cls.fields.push_back({"maxHp",  0x00, true,  false, 0x08});  // static -> skipped
    cls.fields.push_back({"kName",  0x00, false, true,  0x0E});  // const  -> skipped

    auto def = ce::il2cppClassToStructure(cls);
    bool ok = def.name == "Game.Player" && def.fields.size() == 3 &&
        def.fields[0].name == "health" && def.fields[0].offset == 0x10 &&
        def.fields[0].type == ce::ValueType::Int32 && def.fields[0].size == 4 &&
        def.fields[1].name == "speed" && def.fields[1].type == ce::ValueType::Float &&
        def.fields[2].name == "target" && def.fields[2].type == ce::ValueType::Pointer &&
        def.fields[2].size == 8 &&
        def.size == 0x18 + 8;

    bool mapOk =
        ce::il2cppTypeEnumToValueType(0x02) == ce::ValueType::Byte &&   // Boolean
        ce::il2cppTypeEnumToValueType(0x08) == ce::ValueType::Int32 &&  // I4
        ce::il2cppTypeEnumToValueType(0x0A) == ce::ValueType::Int64 &&  // I8
        ce::il2cppTypeEnumToValueType(0x0C) == ce::ValueType::Float &&  // R4
        ce::il2cppTypeEnumToValueType(0x0D) == ce::ValueType::Double && // R8
        ce::il2cppTypeEnumToValueType(0x12) == ce::ValueType::Pointer;  // CLASS

    printf("  class layout -> typed structure (statics/consts skipped): %s\n", ok ? "OK" : "FAILED");
    printf("  Il2CppTypeEnum -> ValueType mapping: %s\n", mapOk ? "OK" : "FAILED");
}

// generateInjectionScript reads code at an address, disassembles whole
// instructions until >= 5 bytes are covered (the jmp size), resolves the module,
// and emits a CE auto-assembler code-injection or AOB-injection template. The
// underlying aa_templates are tested separately; this covers the integration
// (read -> disassemble -> steal whole instructions -> module lookup -> delegate).
void test_injection_script_generation() {
    printf("\n── Test: injection script generation ──\n");

    // x86-64 prologue: push rbp; mov rbp,rsp; sub rsp,0x10 (1 + 3 + 4 bytes). The
    // generator must steal all three to cover >= 5 bytes of whole instructions.
    const uintptr_t base = 0x400000;
    const uintptr_t addr = base + 0x1000;
    std::vector<uint8_t> code = {
        0x55,                    // push rbp
        0x48, 0x89, 0xE5,        // mov rbp, rsp
        0x48, 0x83, 0xEC, 0x10,  // sub rsp, 0x10
        0x90, 0x90, 0x90, 0x90,  // trailing padding so the read window is ample
    };
    MemoryRegion region{addr, 0x1000, MemProt::ReadExec, MemType::Image,
        MemState::Committed, "game.bin"};
    const std::vector<ModuleInfo> modules{
        {base, 0x100000, "game.bin", "/opt/game/game.bin", true}};
    FakeProcessHandle proc({{region, code}}, modules);

    std::string err;
    std::string script = generateInjectionScript(proc, addr, /*aob=*/false, err);
    bool codeOk = err.empty() && !script.empty() &&
        script.find("alloc(newmem") != std::string::npos &&
        script.find("jmp near newmem") != std::string::npos &&
        script.find("[DISABLE]") != std::string::npos &&
        script.find("push") != std::string::npos &&   // stolen prologue mnemonics
        script.find("sub") != std::string::npos;

    std::string aobErr;
    std::string aob = generateInjectionScript(proc, addr, /*aob=*/true, aobErr);
    bool aobOk = aobErr.empty() && !aob.empty() &&
        aob.find("aobscanmodule(INJECT,game.bin") != std::string::npos &&
        aob.find("jmp near newmem") != std::string::npos;

    // Error path: fewer than 5 readable bytes cannot host a 5-byte jmp.
    std::vector<uint8_t> tiny = {0x90, 0x90, 0x90};
    FakeProcessHandle small(
        {{MemoryRegion{addr, 0x10, MemProt::ReadExec, MemType::Image,
            MemState::Committed, "game.bin"}, tiny}}, modules);
    std::string tinyErr;
    bool tinyOk = generateInjectionScript(small, addr, false, tinyErr).empty() &&
        !tinyErr.empty();

    // Error path: AOB injection requires the address to sit inside a module.
    FakeProcessHandle noModule({{region, code}}, {});
    std::string nmErr;
    bool noModuleOk = generateInjectionScript(noModule, addr, true, nmErr).empty() &&
        !nmErr.empty();

    printf("  code injection script: %s\n", codeOk ? "OK" : "FAILED");
    printf("  AOB injection script: %s\n", aobOk ? "OK" : "FAILED");
    printf("  short-read error: %s\n", tinyOk ? "OK" : "FAILED");
    printf("  AOB-without-module error: %s\n", noModuleOk ? "OK" : "FAILED");

    // i386 PIC reads the return address of a call: a stolen call must see the
    // original address, not one in the cave. Enable the scripts and read the cave.
    struct Buffer32 final : ProcessHandle {
        std::vector<uint8_t> bytes = std::vector<uint8_t>(0x10000);
        pid_t pid() const override { return getpid(); }
        bool is64bit() const override { return false; }
        TargetDescription targetDescription() override { return ce::test::x86Target(false, true); }
        Result<size_t> read(uintptr_t at, void* out, size_t n) override {
            if (at > bytes.size() || n > bytes.size() - at) return std::unexpected(std::make_error_code(std::errc::bad_address));
            std::memcpy(out, bytes.data() + at, n); return n;
        }
        Result<size_t> write(uintptr_t at, const void* in, size_t n) override {
            if (at > bytes.size() || n > bytes.size() - at) return std::unexpected(std::make_error_code(std::errc::bad_address));
            std::memcpy(bytes.data() + at, in, n); return n;
        }
        std::vector<MemoryRegion> queryRegions() override {
            return {{0, bytes.size(), MemProt::All, MemType::Private, MemState::Committed, "game32.bin"}};
        }
        std::optional<MemoryRegion> queryRegion(uintptr_t at) override {
            return at < bytes.size() ? std::optional<MemoryRegion>(queryRegions()[0]) : std::nullopt;
        }
        Result<uintptr_t> allocate(size_t, MemProt, uintptr_t) override { return uintptr_t(0x8000); }
        Result<void> free(uintptr_t, size_t) override { return {}; }
        Result<void> protect(uintptr_t, size_t, MemProt) override { return {}; }
        std::vector<ModuleInfo> modules() override { return {{0x1000, 0x1000, "game32.bin", "", true}}; }
        std::vector<ThreadInfo> threads() override { return {}; }
    };
    auto cave = [](Buffer32& target, uintptr_t at, size_t overwrite, std::string& script) {
        std::string why;
        script = generateInjectionScript(target, at, InjectionKind::Code, why, "", overwrite);
        AutoAssembler assembler;
        auto enabled = !script.empty() && assembler.execute(target, script).success;
        if (!enabled) printf("    i386 call injection: %s\n", why.c_str());
        return enabled ? std::vector<uint8_t>(target.bytes.begin() + 0x8000, target.bytes.begin() + 0x8010) : std::vector<uint8_t>{};
    };
    auto word = [](const std::vector<uint8_t>& b, size_t at) {
        uint32_t v = 0; if (b.size() >= at + 4) std::memcpy(&v, b.data() + at, 4); return v;
    };
    Buffer32 thunkTarget;
    const uint8_t thunkCall[] = {0xe8, 0xfb, 0x00, 0x00, 0x00, 0x81, 0xc3, 0x34, 0x12, 0x00, 0x00}; // call 0x1200; add ebx,0x1234
    const uint8_t thunkBody[] = {0x8b, 0x1c, 0x24, 0xc3};                                        // mov ebx,[esp]; ret
    std::memcpy(thunkTarget.bytes.data() + 0x1100, thunkCall, sizeof(thunkCall));
    std::memcpy(thunkTarget.bytes.data() + 0x1200, thunkBody, sizeof(thunkBody));
    std::string thunkScript;
    auto thunkCave = cave(thunkTarget, 0x1100, 5, thunkScript);
    bool thunkOk = thunkCave.size() == 16 && thunkCave[0] == 0xbb && word(thunkCave, 1) == 0x1105 &&
        thunkScript.find("mov ebx, return") != std::string::npos;

    Buffer32 nextTarget;
    const uint8_t callNext[] = {0xe8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x90, 0x90};                // call $+5; pop eax
    std::memcpy(nextTarget.bytes.data() + 0x1300, callNext, sizeof(callNext));
    std::string nextScript;
    auto nextCave = cave(nextTarget, 0x1300, 6, nextScript);
    bool nextOk = nextCave.size() == 16 && nextCave[0] == 0x68 && word(nextCave, 1) == 0x1305 && nextCave[5] == 0x58;

    Buffer32 lastTarget;
    const uint8_t lastCall[] = {0xe8, 0xfb, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90};                // call 0x1500
    const uint8_t callee[] = {0x31, 0xc0, 0xc3};                                                 // xor eax,eax; ret
    std::memcpy(lastTarget.bytes.data() + 0x1400, lastCall, sizeof(lastCall));
    std::memcpy(lastTarget.bytes.data() + 0x1500, callee, sizeof(callee));
    std::string lastScript;
    auto lastCave = cave(lastTarget, 0x1400, 5, lastScript);
    bool lastOk = lastCave.size() == 16 && lastCave[0] == 0x68 && word(lastCave, 1) == 0x1405 &&
        lastCave[5] == 0xe9 && 0x8005 + 5 + word(lastCave, 6) == 0x1500;

    const std::vector<uint8_t> next64 = {0xe8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x90, 0x90};
    FakeProcessHandle nextProc({{region, next64}}, modules);
    std::string next64Error;
    bool next64Ok = generateInjectionScript(nextProc, addr, false, next64Error).empty() &&
        next64Error.find("return address") != std::string::npos;

    printf("  i386 get_pc thunk call becomes a mov of the original address: %s\n", thunkOk ? "OK" : "FAILED");
    printf("  i386 call $+5 pushes the original address: %s\n", nextOk ? "OK" : "FAILED");
    printf("  a final stolen call returns to the original code: %s\n", lastOk ? "OK" : "FAILED");
    printf("  x86-64 call to the next instruction is refused: %s\n", next64Ok ? "OK" : "FAILED");
}

void test_structure_tools() {
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
        cpp.find("uint64_t target; // 0x10") != std::string::npos &&
        cpp.find("#pragma pack(push, 1)") != std::string::npos &&
        cpp.find("#pragma pack(pop)") != std::string::npos &&
        cpp.find("static_assert(offsetof(Player_State, target) == 0x10);") != std::string::npos &&
        cpp.find("static_assert(sizeof(Player_State) == 0x18);") != std::string::npos;
    // A 32-bit target's pointer is 4 bytes; a size that does not fit the type
    // becomes a byte array rather than shifting later offsets.
    StructureDefinition narrow;
    narrow.name = "Narrow";
    narrow.fields.push_back({"next", 0, ValueType::Pointer, 4});
    narrow.fields.push_back({"odd", 4, ValueType::Int32, 3});
    narrow.fields.push_back({"tail", 7, ValueType::Byte, 1});
    auto narrowCpp = generateCppStruct(narrow);
    cppOk = cppOk && narrowCpp.find("uint32_t next; // 0x0") != std::string::npos &&
        narrowCpp.find("uint8_t odd[3]; // 0x4") != std::string::npos &&
        narrowCpp.find("static_assert(offsetof(Narrow, tail) == 0x7);") != std::string::npos &&
        narrowCpp.find("static_assert(sizeof(Narrow) == 0x8);") != std::string::npos;

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

    // N-instance dissector: four snapshots of the same 24-byte struct. Bytes
    // 0..3 differ per instance (health), 4..7 are identical (mana), byte 8
    // differs in a single instance (team), 9..23 identical. The detector must
    // flag exactly the runs that vary across the whole set.
    std::vector<std::vector<uint8_t>> instances(4, std::vector<uint8_t>(24, 0));
    for (size_t s = 0; s < instances.size(); ++s)
        for (size_t b = 0; b < 4; ++b)
            instances[s][b] = static_cast<uint8_t>(s + 1);
    instances[2][8] = 1;
    auto multi = autoDetectStructureFieldsMulti(instances);
    bool multiOk = multi.size() == 4 &&
        multi[0].offset == 0 && multi[0].size == 4 && multi[0].changed &&
        multi[1].offset == 4 && multi[1].size == 4 && !multi[1].changed &&
        multi[2].offset == 8 && multi[2].size == 1 && multi[2].changed &&
        multi[3].offset == 9 && multi[3].size == 15 && !multi[3].changed;
    // A single instance has nothing to vary against; the whole struct is one
    // unchanged run. Zero instances yield nothing.
    auto single = autoDetectStructureFieldsMulti({std::vector<uint8_t>(8, 0xAB)});
    multiOk = multiOk && single.size() == 1 && single[0].size == 8 &&
        !single[0].changed && autoDetectStructureFieldsMulti({}).empty();

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

    // A 32-bit target: 4-byte pointers, followed with the target's width.
    {
        const uintptr_t base32 = 0x10000;
        std::vector<uint8_t> mem32(0x100, 0xEE);
        auto put32 = [&](size_t at, uint32_t v) { std::memcpy(mem32.data() + at, &v, 4); };
        put32(0x10, base32 + 0x40);     // field -> node
        put32(0x40, base32 + 0x80);     // node -> next node
        put32(0x80, 0);
        FakeProcessHandle proc32({
            {{base32, mem32.size(), MemProt::ReadWrite, MemType::Private, MemState::Committed, "[structure]"}, mem32},
        }, {}, /*is64bit=*/false);
        StructureDefinition s32;
        s32.fields.push_back({"link", 0x10, ValueType::Pointer, 4});
        auto chains32 = followStructurePointers(proc32, base32, s32, 3);
        pointerOk = pointerOk && chains32.size() == 1 && chains32[0].addresses.size() == 2 &&
            chains32[0].addresses[0] == base32 + 0x40 && chains32[0].addresses[1] == base32 + 0x80;
    }

    StructureField ptr4{"p", 0, ValueType::Pointer, 4};
    const std::vector<uint8_t> ptrBytes = {0x12, 0x34, 0x56, 0x78, 0xFF, 0xFF, 0xFF, 0xFF};
    StructureField be16{"v", 0, ValueType::Int16, 2};
    bool displayOk = formatStructureFieldValue(structure.fields[0], after) == "88 77 66 55" &&
        formatStructureFieldValue(structure.fields[1], after).find("12.5") == 0 &&
        formatStructureFieldValue(structure.fields[2], memory).find("0x") == 0 &&
        formatStructureFieldValue(ptr4, ptrBytes, ByteOrder::Little) == "0x78563412" &&
        formatStructureFieldValue(ptr4, ptrBytes, ByteOrder::Big) == "0x12345678" &&
        formatStructureFieldValue(be16, ptrBytes, ByteOrder::Big) == "4660";

    printf("  template save/load: %s\n", (saveOk && loadOk) ? "OK" : "FAILED");
    printf("  C++ struct export: %s\n", cppOk ? "OK" : "FAILED");
    printf("  snapshot comparison: %s\n", diffOk ? "OK" : "FAILED");
    printf("  changed field detection: %s\n", detectOk ? "OK" : "FAILED");
    printf("  N-instance field detection: %s\n", multiOk ? "OK" : "FAILED");
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

void test_lua_memrec() {
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
        -- __tostring used lua_pushfstring("%llx"), which raises
        -- "invalid option '%l'"; it must return a string instead.
        local str = tostring(m)
        assert(type(str) == "string" and str:find("MemoryRecord") ~= nil,
               "tostring(mr) failed: " .. tostring(str))
    )");

    run("OnActivate fires on activation flip", R"(
        _G._mr_test_hits = 0
        local mr = getAddressList():getMemoryRecord(0)
        mr.OnActivate = function(sender, before, current) _G._mr_test_hits = _G._mr_test_hits + (current and 1 or 100) end
        mr.OnDeactivate = function(sender, before, current) _G._mr_test_hits = _G._mr_test_hits + (current and 100 or 10) end
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

// MemoryRecord group hierarchy: Count / getChild / getParent walk the flat+indent
// tree. Build G > {A, B > {C}} and navigate it from Lua.
void test_lua_memrec_groups() {
    printf("\n── Test: Lua MemoryRecord group hierarchy ──\n");
    SimpleAddressList list;
    int g = list.createGroup("G");
    int a = list.createEntry(0x1000, ValueType::Int32, "A");
    int b = list.createEntry(0x2000, ValueType::Int32, "B");
    int cc = list.createEntry(0x3000, ValueType::Int32, "C");
    (void)g;
    list.setIndent(a, 1);
    list.setIndent(b, 1);
    list.setIndent(cc, 2);   // C nests under B

    LuaEngine eng;
    eng.setAddressList(&list);
    auto res = eng.evalToString(R"(
        local al = getAddressList()
        local g = al:getMemoryRecord(0)
        if g.Description ~= 'G' then return 'g?' end
        if g.Count ~= 2 then return 'gcount='..tostring(g.Count) end
        local a, b = g:getChild(0), g:getChild(1)
        if not a or a.Description ~= 'A' then return 'childA' end
        if not b or b.Description ~= 'B' then return 'childB' end
        if a:getParent().Description ~= 'G' then return 'parentA' end
        if b.Count ~= 1 then return 'bcount='..tostring(b.Count) end
        local c = b:getChild(0)
        if not c or c.Description ~= 'C' then return 'childC' end
        if c:getParent().Description ~= 'B' then return 'parentC' end
        if g:getChild(5) ~= nil then return 'oob' end
        if g:getParent() ~= nil then return 'rootparent' end
        return 'ok'
    )");
    bool ok = res.has_value() && *res == "ok";
    printf("  Count/getChild/getParent walk the group tree: %s (%s)\n",
           ok ? "OK" : "FAILED", res ? res->c_str() : "nil");
}

// Target state for the headless-bindings test. Because the child is a fork() of
// this test binary, these globals live at the SAME address in the child, so the
// parent can hand their addresses to the Lua tool bindings running against the
// child. Two entities that differ in hp+team (mana constant) drive the structure
// dissector; g_lb_player is a static pointer for the pointer scanner; lb_bump
// writes g_lb_counter for find-what-writes and is the trace/breakpoint target.
struct LbEntity { int hp; int mana; int team; };
[[maybe_unused]] static LbEntity  g_lb_ents[2];
[[maybe_unused]] static LbEntity* g_lb_player = nullptr;
static volatile int g_lb_counter = 0;
[[maybe_unused]] __attribute__((noinline)) static void lb_bump() { g_lb_counter = g_lb_counter + 1; asm volatile("nop" ::: "memory"); }

// Step 5 of the CLI-parity plan: exercise the headless Lua tool bindings end to
// end against live forked children, so "does everything work?" is an automated
// yes/no. Each ptrace-exclusive tool gets its own fresh child to avoid tracer
// contention.
void test_lua_headless_bindings() {
    printf("\n── Test: Lua headless tool bindings (CLI parity) ──\n");

    // ---- cheat-table save/load round-trip (no process needed) ----
    {
        const char* path = "/tmp/ce_lua_bindtest.ct";
        SimpleAddressList l1; LuaEngine e1; e1.setAddressList(&l1);
        std::string errSave = e1.execute(
            "local a=createMemoryRecord(); a.Description='Health'; a.Address=0x1000; a.Type=4\n"
            "local b=createMemoryRecord(); b.Description='Ammo';   b.Address=0x2000; b.Type=4\n"
            "assert(saveTable('/tmp/ce_lua_bindtest.ct'), 'saveTable returned false')\n"
            "local src=generateTrainerSource()\n"
            "assert(src and #src>100 and src:find('int main')~=nil, 'generateTrainerSource looks wrong')\n");
        SimpleAddressList l2; LuaEngine e2; e2.setAddressList(&l2);
        std::string errLoad = e2.execute(
            "assert(loadTable('/tmp/ce_lua_bindtest.ct'), 'loadTable returned false')\n"
            "assert(getAddressList().Count == 2, 'expected 2 reloaded entries')\n"
            "local m=getMemoryRecordByDescription('Health')\n"
            "assert(m~=nil and m.Address==0x1000, 'reloaded entry mismatch')\n");
        std::remove(path);
        bool ok = errSave.empty() && errLoad.empty();
        printf("  saveTable/loadTable round-trip: %s\n", ok ? "OK" : "FAILED");
        if (!errSave.empty()) printf("    save err: %s\n", errSave.c_str());
        if (!errLoad.empty()) printf("    load err: %s\n", errLoad.c_str());
    }

    // ---- address-list grouping + indent/outdent (no process needed) ----
    {
        SimpleAddressList l; LuaEngine e; e.setAddressList(&l);
        std::string err = e.execute(
            "local g=createGroup('Weapons')\n"
            "assert(g and g.IsGroupHeader, 'createGroup did not make a group header')\n"
            "local a=createMemoryRecord(); a.Description='Ammo'; a.Indent=2\n"
            "assert(a.Indent==2, 'Indent set/get mismatch')\n"
            "a.Indent=1\n"                                   // outdent
            "assert(a.Indent==1, 'outdent did not apply')\n"
            "assert(getAddressList():createGroup('Stats').IsGroupHeader, 'list:createGroup failed')\n"
            "assert(getAddressList().Count==3, 'expected 2 groups + 1 record')\n");
        printf("  createGroup + Indent (group/indent/outdent): %s\n", err.empty() ? "OK" : "FAILED");
        if (!err.empty()) printf("    err: %s\n", err.c_str());
    }

    // ---- loading another table retires record handles and OnActivate callbacks ----
    {
        struct ReplacingList : SimpleAddressList {
            std::uint64_t generation = 0;
            std::uint64_t replaceGeneration() const override { return generation; }
        } l;
        LuaEngine e; e.setAddressList(&l);
        std::string err = e.execute(
            "_G.oldRecord=createMemoryRecord(); oldRecord.Description='old'\n"
            "_G.fired=false\n"
            "oldRecord.OnActivate=function() _G.fired=true end\n");
        const int id = l.ids().empty() ? 0 : l.ids().front();
        l.generation = 1;   // a table load: the same id now names another record
        if (err.empty()) err = e.execute(
            "assert(not pcall(function() return oldRecord.Description end),"
            " 'a handle from the previous table still reaches the record with its id')\n");
        l.setActive(id, true);
        if (err.empty()) err = e.execute("assert(not _G.fired, 'an OnActivate from the previous table ran for the new record')\n");
        if (err.empty()) err = e.execute(
            "local r=getAddressList():getMemoryRecord(0)\n"
            "r.OnDeactivate=function() _G.fired=true end\n");
        l.setActive(id, false);
        if (err.empty()) err = e.execute("assert(_G.fired, 'OnDeactivate set after the load does not run')\n");
        printf("  table load retires record handles and OnActivate: %s\n", err.empty() ? "OK" : "FAILED");
        if (!err.empty()) printf("    err: %s\n", err.c_str());
    }

    // The live-process tools (fork a child, then ptrace-SEIZE / scan it) are skipped
    // under ASan: a pointer scan of an ASan-instrumented target walks its ~20 TB
    // shadow address space and takes hours, and fork+ptrace conflicts with the
    // sanitizer runtime. The normal build job exercises these; the sanitizer job
    // only needs the pure-memory paths above (save/load, grouping) + below.
#ifndef __SANITIZE_ADDRESS__
    g_lb_ents[0] = LbEntity{100, 50, 1};
    g_lb_ents[1] = LbEntity{250, 50, 2};
    g_lb_player  = &g_lb_ents[0];

    auto forkSpinner = [](useconds_t period) -> pid_t {
        pid_t c = fork();
        if (c == 0) {
            prctl(PR_SET_PTRACER, -1L, 0, 0, 0);
            for (;;) { lb_bump(); usleep(period); }
            _exit(0);
        }
        usleep(90000);   // let it start spinning
        return c;
    };

    // ---- inspect tools (no ptrace): getManagedRuntimes / dissect / pointerScan ----
    {
        pid_t c = forkSpinner(1500);
        if (c > 0) {
            SimpleAddressList l; LuaEngine e; e.setAddressList(&l);
            char code[2048];
            snprintf(code, sizeof code,
                "assert(openProcess(%d), 'openProcess failed')\n"
                "assert(#getManagedRuntimes()==0, 'native target should have no managed runtimes')\n"
                "local f=dissectStructure({%lu,%lu}, %zu)\n"
                "assert(f~=nil and #f>=1, 'dissectStructure returned nothing')\n"
                "local anyDiff=false\n"
                "for _,x in ipairs(f) do if x.changed then anyDiff=true end end\n"
                "assert(anyDiff, 'dissectStructure flagged no differing field')\n"
                // staticOnly=false: g_lb_player holds &g_lb_ents[0] exactly, so the
                // scan must surface at least that pointer. (Module attribution of
                // .bss is covered by test_pointer_scan_shard_through_static.)
                "local paths=pointerScan(%lu, 2, 64, {staticOnly=false})\n"
                "assert(paths~=nil and #paths>=1, 'pointerScan found no pointer to target')\n"
                "local st=findStatics()\n"
                "assert(type(st)=='table', 'findStatics did not return a table')\n",
                c,
                (unsigned long)&g_lb_ents[0], (unsigned long)&g_lb_ents[1], sizeof(LbEntity),
                (unsigned long)&g_lb_ents[0]);
            std::string err = e.execute(code);
            printf("  getManagedRuntimes/dissectStructure/pointerScan: %s\n", err.empty() ? "OK" : "FAILED");
            if (!err.empty()) printf("    err: %s\n", err.c_str());
            kill(c, SIGKILL); waitpid(c, nullptr, 0);
        } else {
            printf("  getManagedRuntimes/dissectStructure/pointerScan: FAILED (fork)\n");
        }
    }

    // ---- find-what-writes (self-SEIZE HW watchpoint) ----
    {
        pid_t c = forkSpinner(1000);
        if (c > 0) {
            SimpleAddressList l; LuaEngine e; e.setAddressList(&l);
            char code[1024];
            snprintf(code, sizeof code,
                "assert(openProcess(%d), 'openProcess failed')\n"
                "local w=findWhatWrites(%lu, 1)\n"
                "assert(w~=nil and #w>=1, 'findWhatWrites found no writer')\n"
                "assert(w[1].hitCount>0, 'writer had zero hits')\n",
                c, (unsigned long)&g_lb_counter);
            std::string err = e.execute(code);
            printf("  findWhatWrites: %s\n", err.empty() ? "OK" : "FAILED");
            if (!err.empty()) printf("    err: %s\n", err.c_str());
            kill(c, SIGKILL); waitpid(c, nullptr, 0);
        } else {
            printf("  findWhatWrites: FAILED (fork)\n");
        }
    }

    // ---- break-and-trace (self-SEIZE single-step) ----
    {
        pid_t c = forkSpinner(1000);
        if (c > 0) {
            SimpleAddressList l; LuaEngine e; e.setAddressList(&l);
            char code[1024];
            snprintf(code, sizeof code,
                "assert(openProcess(%d), 'openProcess failed')\n"
                "local t=breakAndTrace(%lu, 6)\n"
                "assert(t~=nil and #t>=1, 'breakAndTrace produced no steps')\n"
                "assert(t[1].address==%lu, 'trace did not start at lb_bump')\n",
                c, (unsigned long)&lb_bump, (unsigned long)&lb_bump);
            std::string err = e.execute(code);
            printf("  breakAndTrace: %s\n", err.empty() ? "OK" : "FAILED");
            if (!err.empty()) printf("    err: %s\n", err.c_str());
            kill(c, SIGKILL); waitpid(c, nullptr, 0);
        } else {
            printf("  breakAndTrace: FAILED (fork)\n");
        }
    }

    // ---- register / stack read-write at a live breakpoint (DebugSession) ----
    {
        pid_t c = forkSpinner(2000);
        if (c > 0) {
            SimpleAddressList l; LuaEngine e; e.setAddressList(&l);
            char code[2048];
            snprintf(code, sizeof code,
                "assert(openProcess(%d), 'openProcess failed')\n"
                "_G.seen=false\n"
                "function debugger_onBreakpoint()\n"
                "  local r=debug_getRegisters()\n"
                "  assert(r.RIP==%lu, 'RIP mismatch at breakpoint')\n"
                "  local s=debug_getStack(2)\n"
                "  assert(s~=nil and #s>=1, 'debug_getStack empty')\n"
                "  assert(debug_setRegister('RAX', 0x1234), 'debug_setRegister failed')\n"
                "  assert(debug_getRegisters().RAX==0x1234, 'RAX edit not reflected')\n"
                "  _G.seen=true\n"
                "  return 1\n"
                "end\n"
                "debug_setBreakpoint(%lu)\n"
                "debug_pumpEvents(3000)\n"
                "assert(_G.seen, 'breakpoint never fired')\n",
                c, (unsigned long)&lb_bump, (unsigned long)&lb_bump);
            std::string err = e.execute(code);
            printf("  debug_getRegisters/setRegister/getStack: %s\n", err.empty() ? "OK" : "FAILED");
            if (!err.empty()) printf("    err: %s\n", err.c_str());
            kill(c, SIGKILL); waitpid(c, nullptr, 0);
        } else {
            printf("  debug_getRegisters/setRegister/getStack: FAILED (fork)\n");
        }
    }
#else
    printf("  live-process tools (pointerScan/findWhatWrites/breakAndTrace/debug): SKIPPED under ASan\n");
#endif

    // ---- branch mapper availability (hardware-gated; just assert it answers) ----
    {
        SimpleAddressList l; LuaEngine e; e.setAddressList(&l);
        std::string err = e.execute(
            "local ok = branchMapAvailable()\n"
            "assert(ok==true or ok==false, 'branchMapAvailable did not return a bool')\n");
        printf("  branchMapAvailable: %s\n", err.empty() ? "OK" : "FAILED");
        if (!err.empty()) printf("    err: %s\n", err.c_str());
    }
}

// Headless equivalent of the GUI's File -> Connect: connectToCeserver must open a
// remote process over a ceserver TCP link and install it as the engine's target.
// Uses the same in-process stub server as the RemoteProcessHandle tests.
void test_lua_ceserver_connect() {
    printf("\n── Test: Lua connectToCeserver (remote target) ──\n");
    StubFixture fx;
    if (!startStub(fx)) { printf("  start stub server: FAILED\n"); return; }
    {
        SimpleAddressList l; LuaEngine e; e.setAddressList(&l);
        char code[512];
        snprintf(code, sizeof code,
            "local pid = connectToCeserver('127.0.0.1', %d, %d)\n"
            "assert(pid == %d, 'connectToCeserver did not return the pid')\n"
            "assert(getOpenedProcessID() == %d, 'remote process not installed as target')\n",
            (int)fx.port, (int)kStubPid, (int)kStubPid, (int)kStubPid);
        std::string err = e.execute(code);
        printf("  connectToCeserver + target install: %s\n", err.empty() ? "OK" : "FAILED");
        if (!err.empty()) printf("    err: %s\n", err.c_str());
    }
    stopStub(fx);
}

void test_autoassembler_unregister_symbol(pid_t pid) {
    printf("\n── Test: AutoAssembler unregistersymbol ──\n");

    LinuxProcessHandle proc(pid);
    AutoAssembler aa;
    aa.registerSymbol("stale_symbol", 0x1234);

    auto result = aa.execute(proc, "[ENABLE]\nunregistersymbol(stale_symbol)\n");
    bool ok = result.success && aa.resolveSymbol("stale_symbol") == 0;
    printf("  unregistersymbol: %s\n", ok ? "OK" : "FAILED");
}

void test_autoassembler_dealloc(pid_t pid) {
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

void test_autoassembler_far_forward_jump(pid_t pid) {
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

void test_autoassembler_dealloc_no_cross_evict(pid_t pid) {
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
