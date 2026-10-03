#include "analysis/pe_exports.hpp"
#include "analysis/il2cpp_binary.hpp"
#include "core/guest_view.hpp"
#include "core/value_io.hpp"
#include "core/autoasm.hpp"
#include "core/injection_gen.hpp"
#include "core/expression.hpp"
#include "debug/debug_session.hpp"
#include "platform/linux/linux_process.hpp"
#include "scanner/memory_scanner.hpp"
#include "scripting/lua_engine.hpp"
#include "symbols/elf_symbols.hpp"

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <atomic>
#include <chrono>
#include <thread>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <signal.h>
#include <unistd.h>

using namespace ce;
namespace fs = std::filesystem;

static int failures = 0;
static void check(bool ok, const char* name) {
    std::printf("%s: %s\n", ok ? "OK" : "FAILED", name);
    if (!ok) ++failures;
}
static void writeFile(const fs::path& path, const std::vector<uint8_t>& data) {
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(data.data()), data.size());
}
static void put(std::vector<uint8_t>& b, size_t at, uint64_t value, size_t n = 4) {
    for (size_t i = 0; i < n; ++i) b.at(at + i) = value >> (i * 8);
}

class BufferProcess final : public ProcessHandle {
public:
    std::vector<uint8_t> bytes;
    std::vector<ModuleInfo> mappedModules;
    bool wide = true;
    bool shortRead = false, shortWrite = false;
    uintptr_t allocationAddress = 0;
    explicit BufferProcess(size_t n) : bytes(n) {}
    pid_t pid() const override { return getpid(); }
    bool is64bit() const override { return wide; }
    Result<size_t> read(uintptr_t at, void* out, size_t n) override {
        if (at > bytes.size() || n > bytes.size() - at)
            return std::unexpected(std::make_error_code(std::errc::bad_address));
        if (shortRead && n) --n;
        std::memcpy(out, bytes.data() + at, n);
        return n;
    }
    Result<size_t> write(uintptr_t at, const void* in, size_t n) override {
        if (at > bytes.size() || n > bytes.size() - at)
            return std::unexpected(std::make_error_code(std::errc::bad_address));
        if (shortWrite && n) --n;
        std::memcpy(bytes.data() + at, in, n);
        return n;
    }
    std::vector<MemoryRegion> queryRegions() override {
        if (!allocationAddress) return {};
        return {{0, bytes.size(), MemProt::All, MemType::Private, MemState::Committed, "game32.bin"}};
    }
    std::optional<MemoryRegion> queryRegion(uintptr_t at) override {
        return allocationAddress && at < bytes.size() ? std::optional<MemoryRegion>(queryRegions()[0]) : std::nullopt;
    }
    Result<uintptr_t> allocate(size_t, MemProt, uintptr_t) override {
        if (allocationAddress) return allocationAddress;
        return std::unexpected(std::make_error_code(std::errc::not_supported));
    }
    Result<void> free(uintptr_t, size_t) override { return {}; }
    Result<void> protect(uintptr_t, size_t, MemProt) override { return {}; }
    std::vector<ModuleInfo> modules() override { return mappedModules; }
    std::vector<ThreadInfo> threads() override { return {}; }
};

class InjectionProcess final : public ProcessHandle {
public:
    static constexpr size_t capacity = 0x10000;
    uint8_t* data = static_cast<uint8_t*>(mmap(nullptr, capacity, PROT_READ | PROT_WRITE | PROT_EXEC,
                                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    uintptr_t base = reinterpret_cast<uintptr_t>(data);
    uintptr_t cave = base + 0x2000;
    bool available() const { return data != MAP_FAILED; }
    ~InjectionProcess() { if (available()) munmap(data, capacity); }
    pid_t pid() const override { return getpid(); }
    bool is64bit() const override { return true; }
    Result<size_t> read(uintptr_t at, void* out, size_t n) override {
        if (at < base || at - base > capacity || n > capacity - (at - base))
            return std::unexpected(std::make_error_code(std::errc::bad_address));
        std::memcpy(out, reinterpret_cast<void*>(at), n); return n;
    }
    Result<size_t> write(uintptr_t at, const void* in, size_t n) override {
        if (at < base || at - base > capacity || n > capacity - (at - base))
            return std::unexpected(std::make_error_code(std::errc::bad_address));
        std::memcpy(reinterpret_cast<void*>(at), in, n); return n;
    }
    std::vector<MemoryRegion> queryRegions() override {
        return {{base, capacity, MemProt::All, MemType::Private, MemState::Committed, "test game.bin"}};
    }
    std::optional<MemoryRegion> queryRegion(uintptr_t at) override {
        return at >= base && at - base < capacity ? std::optional<MemoryRegion>(queryRegions()[0]) : std::nullopt;
    }
    Result<uintptr_t> allocate(size_t n, MemProt, uintptr_t) override {
        return cave >= base && cave - base < capacity && n <= capacity - (cave - base)
            ? Result<uintptr_t>(cave) : Result<uintptr_t>(std::unexpected(std::make_error_code(std::errc::not_enough_memory)));
    }
    Result<void> free(uintptr_t, size_t) override { return {}; }
    Result<void> protect(uintptr_t, size_t, MemProt) override { return {}; }
    std::vector<ModuleInfo> modules() override { return {{base, 0x1000, "test game.bin", "", true}}; }
    std::vector<ThreadInfo> threads() override { return {}; }
};

static void injectionTemplateTests() {
    InjectionProcess process;
    check(process.available(), "executable injection fixture allocated");
    if (!process.available()) return;
    auto run = [&](const char* name, const std::vector<uint8_t>& bytes, int expected, InjectionKind kind = InjectionKind::Code) {
        std::memset(process.data, 0, process.capacity);
        std::memcpy(process.data + 0x100, bytes.data(), bytes.size());
        process.cave = process.base + 0x2000;
        std::string error;
        auto script = generateInjectionScript(process, process.base + 0x100, kind, error);
        AutoAssembler assembler;
        auto result = assembler.execute(process, script);
        if (!result.success) std::printf("injection error: %s %s\n%s\n", error.c_str(), result.error.c_str(), script.c_str());
        bool ok = !script.empty() && result.success;
        if (ok) ok = reinterpret_cast<int(*)()>(process.data + 0x100)() == expected;
        if (result.success) {
            auto disabled = assembler.disable(process, script, result.disableInfo);
            ok = ok && disabled.success && !std::memcmp(process.data + 0x100, bytes.data(), bytes.size());
        }
        check(ok, name);
        return script;
    };
    // mov eax,[rip+0x3a]; add eax,3; ret. Data resides at function offset 0x40.
    std::vector<uint8_t> rip(0x44, 0);
    const uint8_t code[] = {0x8b, 0x05, 0x3a, 0, 0, 0, 0x83, 0xc0, 3, 0xc3};
    std::memcpy(rip.data(), code, sizeof(code)); rip[0x40] = 7;
    auto script = run("site-specific RIP-relative injection preserves executed behavior and restores bytes", rip, 10);
    check(script.find("define(INJECT,\"test game.bin\"+0x100)") != std::string::npos &&
          script.find("mov eax, dword ptr [rel INJECT+0x40]") != std::string::npos &&
          script.find("<original") == std::string::npos && script.find("assert(INJECT,") != std::string::npos,
          "template contains module offset, editable original code and byte assertion");
    InjectionProcess rebased;
    if (rebased.available()) {
        std::memcpy(rebased.data + 0x100, rip.data(), rip.size());
        AutoAssembler rebasedAssembler;
        auto active = rebasedAssembler.execute(rebased, script);
        bool ok = active.success && reinterpret_cast<int(*)()>(rebased.data + 0x100)() == 10;
        if (active.success) ok = rebasedAssembler.disable(rebased, script, active.disableInfo).success && ok;
        check(ok, "module-relative hook and operands remain correct after rebasing");
    }
    std::string selectionError;
    auto range = generateInjectionScript(process, process.base + 0x100, false, selectionError, 9);
    check(!range.empty() && range.find("  add eax, 3\n") != std::string::npos &&
        range.find("db 8B 05 3A 00 00 00 83 C0 03") != std::string::npos,
        "instruction range selection captures all selected instructions and restore bytes");
    run("AOB injection executes the selected site's original code", rip, 10, InjectionKind::Aob);
    run("full injection executes with originalcode and exit labels", rip, 10, InjectionKind::Full);
    run("branches inside stolen code target relocated instructions", {0x31, 0xc0, 0xeb, 0, 0xff, 0xc0, 0xc3}, 1);
    run("branch to the end of the overwritten instructions returns to the original site", {0x31, 0xc0, 0xeb, 1, 0x90, 0xb8, 7, 0, 0, 0, 0xc3}, 7);
    std::vector<uint8_t> call(0x16);
    call[0] = 0xe8; call[1] = 0x0b; call[5] = 0xc3;
    call[0x10] = 0xb8; call[0x11] = 42; call[0x15] = 0xc3;
    run("external relative call preserves its original destination", call, 42);
    run("unsupported position-independent CET instruction keeps its exact encoding", {0xf3, 0x0f, 0x1e, 0xfa, 0x90, 0xb8, 3, 0, 0, 0, 0xc3}, 3);

    std::memset(process.data, 0, process.capacity);
    const uint8_t pointerCode[] = {0x8b, 0x07, 0x83, 0xc0, 1, 0xc3};
    std::memcpy(process.data + 0x100, pointerCode, sizeof(pointerCode));
    std::string error;
    auto pointer = generateInjectionScript(process, process.base + 0x100, InjectionKind::Pointer, error, "rdi");
    AutoAssembler assembler;
    auto result = assembler.execute(process, pointer);
    int value = 55;
    bool captured = result.success;
    if (captured) {
        auto slot = assembler.resolveSymbol("pPlayerBase");
        uintptr_t stored = 0;
        if (slot) std::memcpy(&stored, reinterpret_cast<void*>(slot), sizeof(stored));
        captured = slot && stored == 0 && reinterpret_cast<int(*)(int*)>(process.data + 0x100)(&value) == 56;
        if (slot) std::memcpy(&stored, reinterpret_cast<void*>(slot), sizeof(stored));
        captured = captured && stored == reinterpret_cast<uintptr_t>(&value);
        captured = assembler.disable(process, pointer, result.disableInfo).success && captured &&
            assembler.resolveSymbol("pPlayerBase") == 0;
    }
    if (!result.success) std::printf("pointer injection error: %s\n%s\n", result.error.c_str(), pointer.c_str());
    check(captured, "pointer injection captures the chosen register without changing executed behavior");
    check(generateInjectionScript(process, process.base + 0x100, InjectionKind::Pointer, error, "eax").empty(),
          "pointer injection rejects registers of the wrong width");

    // A cave within short-jump distance must still occupy the five bytes used
    // to calculate the stolen instructions, NOP padding and return label.
    std::memset(process.data, 0, process.capacity);
    std::memcpy(process.data + 0x100, rip.data(), rip.size());
    process.cave = process.base + 0x160;
    auto near = generateInjectionScript(process, process.base + 0x100, false, error);
    result = assembler.execute(process, near);
    bool shortJump = result.success && process.data[0x100] == 0xe9 && process.data[0x105] == 0x90;
    if (result.success) {
        shortJump = shortJump && reinterpret_cast<int(*)()>(process.data + 0x100)() == 10;
        shortJump = assembler.disable(process, near, result.disableInfo).success && shortJump;
    }
    check(shortJump, "nearby caves retain a five-byte hook and the exact return boundary");

    process.data[0x100] = 0x90;
    auto before = std::vector<uint8_t>(process.data + 0x100, process.data + 0x110);
    result = assembler.execute(process, near);
    check(!result.success && !std::memcmp(before.data(), process.data + 0x100, before.size()),
          "changed code fails the site assertion without patching the hook");
    std::memset(process.data, 0x90, 0x1000);
    auto ambiguous = generateInjectionScript(process, process.base + 0x100, true, error);
    check(ambiguous.empty() && error.find("unique") != std::string::npos, "ambiguous AOBs fail instead of hooking another site");
    for (const auto& t : builtinAaTemplates())
        if (t.injection != InjectionKind::None) check(t.body.empty(), "injection menu entries have no generic placeholder script");

    BufferProcess target32(0x10000);
    target32.wide = false;
    target32.allocationAddress = 0x2000;
    target32.mappedModules = {{0x1000, 0x1000, "game32.bin", "", true}};
    const uint8_t code32[] = {0x8b, 0x01, 0x83, 0xc0, 1, 0xc3};
    std::memcpy(target32.bytes.data() + 0x1100, code32, sizeof(code32));
    auto script32 = generateInjectionScript(target32, 0x1100, InjectionKind::Pointer, error, "ecx");
    AutoAssembler assembler32;
    auto enabled32 = assembler32.execute(target32, script32);
    bool pointer32 = enabled32.success && script32.find("dd 0") != std::string::npos &&
        script32.find("mov [pPlayerBase], ecx") != std::string::npos &&
        script32.find("rel pPlayerBase") == std::string::npos && assembler32.resolveSymbol("pPlayerBase") != 0;
    if (enabled32.success) pointer32 = assembler32.disable(target32, script32, enabled32.disableInfo).success && pointer32 &&
        !std::memcmp(target32.bytes.data() + 0x1100, code32, sizeof(code32));
    check(pointer32, "32-bit pointer templates use a four-byte slot and target registers");

    target32.mappedModules[0].name = "32-bit+game.bin";
    check(ExpressionParser(&target32).parse("\"32-bit+game.bin\"+0x100") == 0x1100 &&
        !ExpressionParser(&target32).parse("\"32-bit+game.bin+0x100"),
        "quoted module expressions preserve spaces and arithmetic characters");
    BufferProcess aobChunks(0x31000);
    aobChunks.allocationAddress = 0x30000;
    aobChunks.mappedModules = {{0x1000, 0x30000, "large.bin", "", true}};
    const uint8_t prefix[] = {0xa1, 0x71, 0x32, 0xa9, 0xc8, 0xea, 0x19, 0x47, 0x11};
    std::memcpy(aobChunks.bytes.data() + 0x1200, prefix, sizeof(prefix));
    std::memcpy(aobChunks.bytes.data() + 0x10ffb, prefix, sizeof(prefix));
    aobChunks.bytes[0x10ffb + 8] = 0x22;
    auto chunkSignature = uniqueAobSignature(aobChunks, aobChunks.mappedModules[0], 0x1200, 5, 16);
    check(chunkSignature == "A1 71 32 A9 C8 EA 19 47 11", "unique AOB scanning detects duplicate prefixes across chunk boundaries");
    // Named defines can refer to other expressions, but cycles cannot recurse indefinitely.
    check(!assembler.execute(process, "[ENABLE]\ndefine(a,b)\ndefine(b,a)\na:\nnop\n").success,
          "cyclic address defines fail safely");
}

static void usabilityTests() {
    BufferProcess process(256);
    ValueIoOptions options;
    auto roundTrip = [&](ValueType type, const std::string& value, const std::string& expected) {
        auto written = writeTypedValue(process, 16, type, value, options);
        auto read = readTypedValue(process, 16, type, options);
        return written && read && *read == expected;
    };
    options.isSigned = false;
    check(roundTrip(ValueType::Int64, "18446744073709551615", "18446744073709551615"), "typed values retain full unsigned 64-bit precision");
    check(writeTypedValue(process, 16, ValueType::Int64, "9007199254740992", options) &&
          compareTypedValue(process, 16, ValueType::Int64, "9007199254740993", options) == -1,
          "directional comparisons retain adjacent integer values above double precision");
    check(compareTypedValue(process, 16, ValueType::Int64, "18446744073709551615", options) == -1,
          "directional comparisons honor unsigned 64-bit order");
    options.isSigned = true;
    check(roundTrip(ValueType::Int32, "-2147483648", "-2147483648"), "typed signed minimum round trips");
    check(!encodeTypedValue(ValueType::Byte, "256") && !encodeTypedValue(ValueType::Byte, "-129"), "narrow values fail with a range error instead of truncating");
    auto before = process.bytes;
    check(!writeTypedValue(process, 16, ValueType::Int32, "12oops") && process.bytes == before, "malformed typed edits leave memory unchanged");
    check(!writeTypedValue(process, 16, ValueType::ByteArray, "90 ZZ 90") && process.bytes == before, "invalid array bytes never produce a partial edit");
    options.bigEndian = true; options.codec = *ValueCodec::parse("xor:0x12345678");
    check(roundTrip(ValueType::Int32, "305419896", "305419896") && process.bytes[16] == 0, "typed values share codec and byte-order handling");
    options = {}; process.wide = false;
    std::fill(process.bytes.begin(), process.bytes.end(), 0xAA);
    check(roundTrip(ValueType::Pointer, "0x12345678", "0x12345678") && process.bytes[20] == 0xAA, "pointer reads and writes honor a 32-bit target width");
    check(!writeTypedValue(process, 16, ValueType::Pointer, "0x100000000"), "out-of-range pointers are rejected before touching memory");
    process.wide = true;
    check(roundTrip(ValueType::Double, "1.2345678901234567", "1.2345678901234567"), "double text preserves every stored bit on write-back");
    check(roundTrip(ValueType::Float, "1.2345678", "1.2345678"), "float text round trips without losing its final digits");
    check(roundTrip(ValueType::Double, "2,5", "2.5"), "typed floats accept both decimal separators");
    check(!encodeTypedValue(ValueType::Float, "1e100"), "float overflow points users to the double type");
    options.size = 4;
    check(roundTrip(ValueType::ByteArray, "0x90,90\t48\n8B", "90 90 48 8B"), "byte array pastes accept commas and line breaks");
    options.terminate = true; options.size = 64;
    check(roundTrip(ValueType::String, "İstanbul 😀", "İstanbul 😀"), "typed UTF-8 reads preserve non-ASCII text");
    options.bigEndian = true;
    check(roundTrip(ValueType::UnicodeString, "世界 😀", "世界 😀"), "UTF-16 big-endian text round trips with surrogate pairs");
    options.bigEndian = false; options.encoding = "CP1252";
    check(roundTrip(ValueType::String, "café", "café"), "typed string access supports code pages");
    options.encoding = "UTF-16LE";
    check(roundTrip(ValueType::String, "AB世界", "AB世界"), "code-page reads find terminators after decoding multi-byte encodings");
    options.encoding = "UTF-16";
    check(roundTrip(ValueType::String, "AB世界", "AB世界"), "terminated UTF-16 encoding emits only the initial byte-order mark");
    options.encoding = "NOT-A-CHARSET";
    check(!readTypedValue(process, 16, ValueType::String, options), "unsupported read encodings return a clear error");
    check(!encodeTypedValue(ValueType::String, "text", options), "unsupported write encodings return an actionable error");
    options = {}; process.shortRead = true;
    check(!readTypedValue(process, 16, ValueType::Int32), "typed scalar reads reject incomplete transfers");
    process.shortRead = false; process.shortWrite = true;
    check(!writeTypedValue(process, 16, ValueType::Int32, "7"), "typed writes report incomplete transfers");
    process.shortWrite = false;

    SymbolResolver resolver; resolver.addUserSymbol(16, "value_slot");
    LuaEngine lua; lua.setProcess(&process); lua.setResolver(&resolver);
    auto error = lua.execute(R"(
        local ok, count = writeValue('value_slot+8', 'u64', '18446744073709551615', {bigEndian=true, codec='xor:0x25'})
        assert(ok and count == 8)
        assert(readValue('value_slot+8', 'u64', {bigEndian=true, codec='xor:0x25'}) == '18446744073709551615')
        assert(writeValue(64, 'unicode', '世界 😀', {bigEndian=true, terminate=true}))
        assert(readValue(64, 'unicode', {bigEndian=true}) == '世界 😀')
        assert(writeValue(96, 'aob', '90, 48\n8B'))
        assert(readValue(96, 'aob', {size=3}) == '90 48 8B')
        local ok, error = writeValue(96, 'byte', '256')
        assert(ok == false and type(error) == 'string')
        local defaults = setmetatable({}, {__index={bigEndian=true, codec='xor:0x25'}})
        assert(readValue('value_slot+8', 'U64', defaults) == '18446744073709551615')
        local value, error = readValue(96, 'i32', setmetatable({}, {__index=function() _G.error('option lookup') end}))
        assert(value == nil and error:find('option lookup'))
        local value, error = readValue(96, 'aob', {size=-1})
        assert(value == nil and type(error) == 'string')
    )");
    if (!error.empty()) std::printf("Lua typed access error: %s\n", error.c_str());
    check(error.empty(), "Lua typed access shares names, expressions, encodings, codecs and precise values");
    lua.setProcess(nullptr);
    check(lua.execute("local value, err = readValue(16, 'i32'); assert(value == nil and err:find('process'))").empty(), "Lua typed access explains the missing target");

    AutoAssembler assembler;
    assembler.setLuaEvaluator([&](const std::string& chunk) { return lua.evalToString(chunk); });
    for (auto condition : {"true", "0", "''", "{}", "'false'", "'nil'", "'}'", "{value={1}}", "[=[}]=]", "(true -- braces { } in a comment\n)"}) {
        auto script = std::string("[ENABLE]\n{$if ") + condition + "}\nalloc(good, 16)\n{$else}\nnot_an_instruction\n{$endif}\n[DISABLE]\n";
        check(assembler.check(script).success, (std::string("AA condition follows Lua truthiness: ") + condition).c_str());
    }
    auto nested = assembler.check(R"([ENABLE]
{$if true}
{$if false}
not_an_instruction
{$else}
alloc(good, 16)
{$endif}
{$else}
{$if error('inactive condition executed')}
{$lua} error('inactive Lua executed') {$asm}
{$ccode} this is deliberately invalid C {$endccode}
{$endif}
{$endif}
[DISABLE]
)");
    check(nested.success, "nested AA branches skip inactive conditions, Lua and C blocks");
    auto ordered = assembler.check(R"([ENABLE]
{$ lua } selected = true; return '' {$endlua}
{$if selected}
alloc(good, 16)
{$else}
not_an_instruction
{$endif}
[DISABLE]
)");
    check(ordered.success, "AA Lua blocks run in source order and accept spaced delimiters");
    check(!assembler.check("[ENABLE]\n{$else}\n[DISABLE]\n").success &&
          !assembler.check("[ENABLE]\n{$if true}\n{$else}\n{$else}\n{$endif}\n[DISABLE]\n").success,
          "AA rejects orphan and duplicate branch delimiters");
}

static void scanTests(const fs::path& root) {
    auto dir = root / "scan";
    ScanResult result(dir);
    uint64_t values[] = {0x1111111122222222ull, 0x3333333344444444ull};
    uint64_t first[] = {0x5555555566666666ull, 0x7777777788888888ull};
    result.addResult(0x100000000ull, &values[0], &first[0], 8);
    result.addResult(0x100000008ull, &values[1], &first[1], 8);
    result.finalize();
    ScanResult loaded(dir);
    uint32_t v = 0;
    loaded.value(1, &v, 4);
    check(v == 0x44444444, "partial scan value reads retain the persisted record stride");
    loaded.firstValue(1, &v, 4);
    check(v == 0x88888888, "partial first-value reads retain the persisted record stride");
    v = 0xdeadbeef;
    loaded.value(20, &v, 4);
    check(v == 0, "out-of-range scan reads clear stale output");
    size_t rows = 0;
    bool correct = true;
    loaded.forEach([&](uintptr_t addr, const void* value, size_t n) {
        uint32_t x = 0; std::memcpy(&x, value, n);
        correct &= rows < 2 && addr == 0x100000000ull + rows * 8 && x == uint32_t(values[rows]);
        ++rows;
    }, 4);
    check(correct && rows == 2, "streamed partial scan values stay paired with their addresses");
    loaded.finalize();
    check(loaded.address(1) == 0x100000008ull, "finalizing a loaded result preserves its address frames");

    fs::remove(dir / "frames.bin");
    ScanResult missingFrames(dir);
    check(missingFrames.hasWriteError() && missingFrames.address(1) == 0,
          "missing address frames are detected instead of producing low addresses");
    auto badManifest = root / "manifest";
    fs::create_directory(badManifest);
    { std::ofstream out(badManifest / "shards.txt"); out << "-1 " << dir.string() << '\n'; }
    ScanResult manifest(badManifest);
    check(manifest.hasWriteError() && manifest.count() == 0, "negative shard counts are rejected");

    auto badOpen = root / "bad-open";
    fs::create_directory(badOpen);
    fs::create_directory(badOpen / "values.bin");
    ScanResult failed(badOpen);
    failed.addResult(0x1000, &v, 4);
    failed.finalize();
    check(failed.hasWriteError(), "backing-file open failures mark scan output unreliable");
    ScanResult widths(root / "widths");
    widths.addResult(0x1000, &v, 4);
    widths.addResult(0x1008, &values[1], 8);
    widths.finalize();
    check(widths.hasWriteError() && widths.count() == 1, "mixed record widths cannot corrupt scan output");

    auto countFds = [] { size_t n = 0; for (const auto& e : fs::directory_iterator("/proc/self/fd")) { (void)e; ++n; } return n; };
    size_t before = countFds();
    { ScanResult abandoned(root / "abandoned"); }
    check(countFds() == before, "abandoned scan writers close their file descriptors");
    BufferProcess proc(0);
    bool refused = false;
    try { MemoryScanner(1).nextScan(proc, ScanConfig{}, missingFrames); }
    catch (const std::invalid_argument&) { refused = true; }
    check(refused, "next scans reject incomplete persisted results");
    auto empty = MemoryScanner(1).firstScan(proc, ScanConfig{});
    auto permissions = fs::status(empty.directory().parent_path()).permissions();
    check((permissions & (fs::perms::group_all | fs::perms::others_all)) == fs::perms::none,
          "scan directories keep process memory private");
    fs::remove_all(empty.directory().parent_path());
}

static std::vector<uint8_t> peFixture() {
    std::vector<uint8_t> b(0x1400);
    b[0] = 'M'; b[1] = 'Z'; put(b, 0x3c, 0x80);
    b[0x80] = 'P'; b[0x81] = 'E';
    put(b, 0x84, 0x8664, 2); put(b, 0x86, 1, 2); put(b, 0x94, 0xf0, 2);
    put(b, 0x98, 0x20b, 2); put(b, 0xd4, 0x400); put(b, 0x104, 2);
    put(b, 0x108, 0x1000); put(b, 0x10c, 0x100);
    put(b, 0x110, 0x1100); put(b, 0x114, 0x28);
    put(b, 0x190, 0x1000); put(b, 0x194, 0x1000);
    put(b, 0x198, 0x1000); put(b, 0x19c, 0x400);
    put(b, 0x410, 1); put(b, 0x414, 1); put(b, 0x418, 1);
    put(b, 0x41c, 0x1030); put(b, 0x420, 0x1040); put(b, 0x424, 0x1050);
    put(b, 0x430, 0x1234); put(b, 0x440, 0x1060);
    std::memcpy(b.data() + 0x460, "foo", 4);
    put(b, 0x500, 0x1130); put(b, 0x50c, 0x1170); put(b, 0x510, 0x1148);
    put(b, 0x530, 0x1160, 8); put(b, 0x548, 0x1160, 8);
    std::memcpy(b.data() + 0x562, "bar", 4); std::memcpy(b.data() + 0x570, "OTHER.dll", 10);
    return b;
}

static void peTests(const fs::path& root) {
    auto file = root / "fixture.dll";
    auto b = peFixture(); writeFile(file, b);
    check(parsePEExports(file.string()).size() == 1 && parsePEImports(file.string()).size() == 1,
          "valid PE exports and imports still parse");
    BufferProcess proc(0);
    proc.mappedModules = {{0x10000, b.size(), "fixture.dll", file.string(), true}};
    SymbolResolver resolver;
    resolver.loadProcess(proc);
    check(resolver.lookup("foo") == 0x11234, "loading process symbols includes mapped PE modules");
    resolver.clear();
    resolver.loadModule(file.string(), "fixture.dll", UINTPTR_MAX - 10);
    check(resolver.count() == 0, "PE symbol relocation cannot wrap into a low address");
    put(b, 0x430, 0); writeFile(file, b);
    check(parsePEExports(file.string()).empty(), "empty export slots do not become named symbols");
    b = peFixture(); put(b, 0x198, 0x63); b[0x463] = 'X'; writeFile(file, b);
    check(parsePEExports(file.string()).empty(), "export names must terminate inside section raw bytes");
    b = peFixture(); b.resize(0x1402); put(b, 0x41c, 0x1ffe); put(b, 0x13fe, 0x1234); writeFile(file, b);
    check(parsePEExports(file.string()).empty(), "export table elements cannot cross section raw bounds");
    b = peFixture(); put(b, 0x86, 2, 2); b.resize(0x400 + 0x61); writeFile(file, b);
    // The second section is present but its raw data extends beyond the file.
    check(parsePEExports(file.string()).empty(), "truncated section data is rejected");
    b = peFixture(); put(b, 0x104, 0); writeFile(file, b);
    check(parsePEExports(file.string()).empty() && parsePEImports(file.string()).empty(),
          "PE data-directory count is respected");
    b = peFixture(); put(b, 0x114, 19); writeFile(file, b);
    check(parsePEImports(file.string()).empty(), "imports do not read descriptors outside the directory");
    b = peFixture(); put(b, 0x530, 0x100001160ull, 8); writeFile(file, b);
    check(parsePEImports(file.string()).empty(), "64-bit import RVAs cannot silently truncate to 32 bits");
    b = peFixture(); put(b, 0x94, 0x70, 2);
    std::memcpy(b.data() + 0x108, b.data() + 0x188, 40);
    put(b, 0x108, 0x1000); put(b, 0x10c, 0x100); writeFile(file, b);
    check(parsePEExports(file.string()).empty(), "section bytes cannot masquerade as optional-header directories");
    b = peFixture(); put(b, 0x430, 0x10ff);
    std::memcpy(b.data() + 0x4ff, "OTHER.foo", 10); writeFile(file, b);
    check(parsePEExports(file.string()).empty(), "forwarder strings must terminate inside the export directory");
}

static void il2cppTests(const fs::path& root) {
    Il2CppMetadata md;
    md.tablesDecoded = true;
    md.types.resize(1);
    md.types[0].name = "Fixture";
    std::vector<uint8_t> b(0x400);
    std::memcpy(b.data(), "\x7f" "ELF", 4);
    b[4] = 2; b[5] = 1; b[6] = 1;
    put(b, 0x12, 62, 2); put(b, 0x14, 1); put(b, 0x20, 0x40, 8);
    put(b, 0x34, 64, 2); put(b, 0x36, 56, 2); put(b, 0x38, 1, 2);
    put(b, 0x40, 1); put(b, 0x48, 0x100, 8); put(b, 0x50, 0x1000, 8);
    put(b, 0x60, 0x300, 8); put(b, 0x68, 0x300, 8);
    put(b, 0x130, 1); put(b, 0x138, 0x1100, 8);
    put(b, 0x150, 1); put(b, 0x158, 0x1120, 8); put(b, 0x160, 1);
    auto file = root / "GameAssembly.so";
    writeFile(file, b);
    check(resolveIl2CppLayout(md, file.string()).ok, "valid ELF IL2CPP registration still resolves");
    auto malformed = [&](const std::vector<uint8_t>& bad, const char* name) {
        writeFile(file, bad);
        check(!resolveIl2CppLayout(md, file.string()).ok, name);
    };
    auto bad = b; bad[5] = 2;
    malformed(bad, "big-endian ELF images cannot be decoded as little-endian IL2CPP");
    bad = b; put(bad, 0x12, 183, 2);
    malformed(bad, "unsupported ELF machine types are rejected");
    bad = b; put(bad, 0x36, 1, 2);
    malformed(bad, "ELF program-header entries must cover their declared fields");
    bad = b; put(bad, 0x38, 18, 2);
    malformed(bad, "truncated ELF program-header tables are rejected");
    bad = b; put(bad, 0x60, 0x301, 8);
    malformed(bad, "ELF segment file extents cannot exceed the file");
    bad = b; put(bad, 0x68, 0x200, 8);
    malformed(bad, "ELF segment file size cannot exceed its memory size");
    bad = b; put(bad, 0x60, 0x124, 8);
    malformed(bad, "IL2CPP pointer reads cannot cross the segment raw boundary");
    md.images.push_back({"Assembly-CSharp.dll", 0, 1});
    md.types[0].methods.push_back({"Tick", 0x06000001});
    put(b, 0x280, 1, 8); put(b, 0x288, 0x1200, 8);
    put(b, 0x300, 0x1220, 8); put(b, 0x320, 0x1260, 8);
    put(b, 0x328, 1, 8); put(b, 0x330, 0x1280, 8); put(b, 0x380, 0x12a0, 8);
    std::memcpy(b.data() + 0x360, "Assembly-CSharp.dll", 20);
    writeFile(file, b);
    auto layout = resolveIl2CppLayout(md, file.string());
    check(layout.ok && layout.classes.size() == 1 && layout.classes[0].methods.size() == 1 &&
          layout.classes[0].methods[0].rva == 0x12a0,
          "IL2CPP method resolution works with fewer than eight assembly images");
}

static void luaTests(const fs::path& root) {
    LuaEngine lua;
    auto run = [&](const std::string& code, const char* name) {
        auto error = lua.execute(code);
        check(error.empty(), name);
        if (!error.empty()) std::fprintf(stderr, "%s\n", error.c_str());
    };
    auto file = root / "stream.bin";
    writeFile(file, {'a', 'b', 'c', 'd', 'e', 'f'});
    std::string path = "'" + file.string() + "'";
    run("local s=assert(createFileStream(" + path + ")); assert(s:read(6)=='abcdef'); s:close()",
        "default read/write stream preserves existing contents");
    writeFile(file, {'a', 'b', 'c', 'd', 'e', 'f'});
    run("local s=assert(createFileStream(" + path + ",'rw')); assert(s:read(6)=='abcdef'); s:close()",
        "explicit rw stream preserves existing contents");
    run("local s=assert(createFileStream('" + (root / "new.bin").string() + "')); assert(s:write('new')==3); s:seek(0); assert(s:read(3)=='new'); s:close()",
        "default read/write stream still creates new files");
    run("local s=createMemoryStream(); s:write('abc'); assert(not s:saveToFile('/dev/full'))",
        "stream save detects buffered write failures");
    run("local s=createStringList(); s:add('abc'); assert(not s:saveToFile('/dev/full'))",
        "string-list save detects buffered write failures");
    run("local s=createStringList(); s:add('abc'); assert(s:getString(4294967296)==nil); s:delete(4294967296); s:setString(4294967296,'wrong'); assert(s:getString(0)=='abc')",
        "large string-list indices cannot wrap onto another entry");
    run("local s=createStringList(); s:add('abc'); assert(not s:loadFromFile('" + root.string() + "')); assert(s:getString(0)=='abc')",
        "failed string-list loads preserve their contents and report failure");
    writeFile(file, {'a', 'b', 'c', 'd', 'e', 'f'});
    run("local s=assert(createFileStream(" + path + ",'r')); s:seek(2); assert(s:saveToFile(" + path + ")); assert(s:read(4)=='cdef'); s:close()",
        "saving a stream onto itself preserves data and position");
    run("local s=assert(createFileStream('/dev/full','w')); assert(not pcall(function() s:write('abc') end)); s:close()",
        "stream write reports I/O failure");
    run("local s=assert(createFileStream(" + path + ",'r')); s:close(); assert(not pcall(function() s:read(1) end))",
        "closed streams reject reads");
    auto small = root / "small.bin"; writeFile(small, {'x', 'y'});
    writeFile(file, {'a', 'b', 'c', 'd', 'e', 'f'});
    run("local s=assert(createFileStream(" + path + ",'r+')); assert(s:loadFromFile('" + small.string() + "')); assert(s:getSize()==2); s:seek(0); assert(s:read(9)=='xy'); s:close()",
        "loading a shorter file removes stale stream suffixes");
    {
        run("local s=createMemoryStream(); local gc=getmetatable(s).__gc; gc(s); gc(s); assert(not pcall(function() s:write('a') end))",
            "destroyed memory streams reject use and tolerate repeated collection");
        run("local s=createStringList(); local gc=getmetatable(s).__gc; gc(s); gc(s); assert(not pcall(function() s:add('a') end))",
            "destroyed string lists reject use and tolerate repeated collection");
    }
}

static void guestTests() {
    constexpr size_t chunk = 1u << 20;
    BufferProcess proc(chunk + 16);
    proc.bytes[chunk] = 0x7f;
    proc.bytes[chunk + 2] = 0x7f;
    GuestView gv{&proc, 0, proc.bytes.size(), false};
    check(guestScanExact<uint8_t>(gv, 0x7f, 3) == std::vector<uint64_t>{chunk + 2},
          "guest scan alignment is consistent across chunk boundaries");
    gv.base = std::numeric_limits<uintptr_t>::max() - 1;
    check(!gv.contains(3, 1) && !gv.contains(0, 3), "guest address translation rejects host-address overflow");
}

static bool waitUntil(const std::function<bool()>& ready) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (!ready() && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    return ready();
}

static bool reattachAfterExit() {
    pid_t child = fork();
    if (child < 0) return false;
    if (!child) { prctl(PR_SET_PDEATHSIG, SIGKILL); for (;;) pause(); }
    os::LinuxProcessHandle proc(child);
    DebugSession session;
    if (!session.attach(child, &proc)) { kill(child, SIGKILL); waitpid(child, nullptr, 0); return false; }
    session.continueExecution();
    kill(child, SIGKILL);
    bool exited = waitUntil([&] { return !session.isAttached(); });
    pid_t next = fork();
    if (!next) { prctl(PR_SET_PDEATHSIG, SIGKILL); for (;;) pause(); }
    if (next < 0) return false;
    os::LinuxProcessHandle nextProc(next);
    bool attached = exited && session.attach(next, &nextProc);
    session.detach();
    kill(next, SIGKILL); waitpid(next, nullptr, 0);
    return attached;
}

static void debuggerTests() {
    // Isolate the regression: assigning over a joinable std::thread aborts the
    // process, so the parent must be able to report that as a failed check.
    pid_t test = fork();
    if (!test) _exit(reattachAfterExit() ? 0 : 1);
    int status = 0;
    bool joined = test > 0 && waitpid(test, &status, 0) == test;
    check(joined && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "a debugger session can attach again after its previous target exits");

    auto* code = static_cast<uint8_t*>(mmap(nullptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                                         MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    auto* counter = static_cast<unsigned*>(mmap(nullptr, 4096, PROT_READ | PROT_WRITE,
                                              MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    if (code == MAP_FAILED || counter == MAP_FAILED) { check(false, "debugger fixture allocation"); return; }
    // call callee; ret; callee: inc dword ptr [rdi]; ret
    const uint8_t bytes[] = {0xe8, 1, 0, 0, 0, 0xc3, 0xff, 0x07, 0xc3};
    std::memcpy(code, bytes, sizeof(bytes));
    pid_t child = fork();
    if (!child) {
        auto fn = reinterpret_cast<void (*)(unsigned*)>(code);
        for (;;) { fn(counter); usleep(2000); }
    }
    if (child < 0) { check(false, "debugger fixture fork"); return; }
    {
        os::LinuxProcessHandle proc(child);
        DebugSession session;
        std::atomic<int> hits{0}, steps{0};
        session.setEventCallback([&](const DebugEvent& event) {
            if (event.type == DebugEventType::BreakpointHit) ++hits;
            if (event.type == DebugEventType::SingleStep) ++steps;
        });
        bool attached = session.attach(child, &proc);
        if (attached) {
            session.continueExecution();
            pid_t unrelated = fork();
            if (!unrelated) _exit(77);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            int exitStatus = 0;
            auto waited = unrelated > 0 ? waitpid(unrelated, &exitStatus, WNOHANG) : -1;
            check(waited == unrelated && WIFEXITED(exitStatus) && WEXITSTATUS(exitStatus) == 77,
                  "debugger polling leaves unrelated child exit statuses available");
            if (waited == 0) { kill(unrelated, SIGKILL); waitpid(unrelated, nullptr, 0); }
        }
        bool bp = attached && session.setSoftwareBreakpoint(reinterpret_cast<uintptr_t>(code)) >= 0;
        if (bp) session.continueExecution();
        bool hit = bp && waitUntil([&] { return hits.load() > 0; });
        unsigned before = *counter;
        if (hit) {
            session.step(StepMode::RunToCursor, reinterpret_cast<uintptr_t>(code));
            check(session.getStopContext().rip == reinterpret_cast<uintptr_t>(code) && *counter == before && steps.load() == 0,
                  "running to the current breakpoint is a harmless no-op");
        }
        if (hit) session.step(StepMode::Over);
        check(hit && steps.load() == 1 && session.getStopContext().rip == reinterpret_cast<uintptr_t>(code + 5) && *counter == before + 1,
              "step-over at a call breakpoint executes the whole call");
        if (hit) {
            auto beforeStep = session.getStopContext().rip;
            int events = steps.load();
            session.step(StepMode::RunToCursor, 1);
            check(session.isStopped() && session.getStopContext().rip == beforeStep && steps.load() == events,
                  "an invalid run-to-cursor address leaves the target stopped");
        }
        session.detach();
    }
    kill(child, SIGKILL); waitpid(child, nullptr, 0);
    munmap(code, 4096); munmap(counter, 4096);
}

int runUnderlyingReviewTests(const fs::path& root);

int main() {
    char temp[] = "/tmp/ce-deep-test-XXXXXX";
    char* dir = mkdtemp(temp);
    if (!dir) return 1;
    fs::path root(dir);
    injectionTemplateTests();
    usabilityTests();
    scanTests(root);
    peTests(root);
    il2cppTests(root);
    luaTests(root);
    guestTests();
    debuggerTests();
    failures += runUnderlyingReviewTests(root);
    fs::remove_all(root);
    std::printf("%d failed checks\n", failures);
    return failures ? 1 : 0;
}
