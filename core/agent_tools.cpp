#include "core/agent_tools.hpp"

#include "arch/disassembler.hpp"
#include "arch/target_arch.hpp"
#include "core/autoasm.hpp"
#include "core/injection_gen.hpp"
#include "debug/code_finder.hpp"
#include "debug/instruction_access.hpp"
#include "platform/linux/ptrace_wrapper.hpp"
#include "core/ct_file.hpp"
#include "core/expression.hpp"
#include "core/target_capabilities.hpp"
#include "core/target_profile.hpp"
#include "core/target_machine.hpp"
#include "core/types.hpp"
#include "core/value_io.hpp"
#include "core/value_transform.hpp"
#include "platform/linux/linux_process.hpp"
#include "scanner/memory_scanner.hpp"
#include "scanner/pointer_scanner.hpp"
#include "symbols/elf_symbols.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <atomic>
#include <cctype>
#include <condition_variable>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

namespace ce {

namespace {

using json::Value;

constexpr size_t kMaxCandidates = 50;
constexpr size_t kMaxInstructions = 40;
constexpr size_t kMaxReadBytes = 256;
constexpr size_t kMaxScriptBytes = 64 * 1024;
constexpr int kMaxWatchSeconds = 30;
constexpr size_t kMaxPaths = 20;
constexpr size_t kMaxStructureBytes = 512;

std::string hex(uint64_t v) {
    char buffer[24];
    std::snprintf(buffer, sizeof buffer, "0x%llx", static_cast<unsigned long long>(v));
    return buffer;
}

AgentToolResult fail(const std::string& message) {
    return {true, Value::object().set("error", Value::string(message))};
}

AgentToolResult ok(Value content) { return {false, std::move(content)}; }

// Schema helpers.
Value prop(const char* type, const char* description) {
    return Value::object().set("type", Value::string(type)).set("description", Value::string(description));
}
Value enumProp(std::vector<const char*> values, const char* description) {
    Value list = Value::array();
    for (const char* v : values) list.push(Value::string(v));
    return Value::object().set("type", Value::string("string")).set("enum", list)
                          .set("description", Value::string(description));
}
Value schema(std::vector<std::pair<const char*, Value>> properties, std::vector<const char*> required) {
    Value props = Value::object();
    for (auto& [name, p] : properties) props.set(name, std::move(p));
    Value req = Value::array();
    for (const char* r : required) req.push(Value::string(r));
    return Value::object().set("type", Value::string("object")).set("properties", props)
                          .set("required", req).set("additionalProperties", Value::boolean(false));
}

const std::vector<const char*> kTypes = {"byte", "i16", "i32", "i64", "float", "double", "string", "aob"};

std::optional<ScanCompare> parseCompare(const std::string& s) {
    if (s == "exact") return ScanCompare::Exact;
    if (s == "greater") return ScanCompare::Greater;
    if (s == "less") return ScanCompare::Less;
    if (s == "between") return ScanCompare::Between;
    if (s == "unknown") return ScanCompare::Unknown;
    if (s == "changed") return ScanCompare::Changed;
    if (s == "unchanged") return ScanCompare::Unchanged;
    if (s == "increased") return ScanCompare::Increased;
    if (s == "decreased") return ScanCompare::Decreased;
    if (s == "same_as_first") return ScanCompare::SameAsFirst;
    if (s == "increased_by") return ScanCompare::IncreasedBy;
    if (s == "decreased_by") return ScanCompare::DecreasedBy;
    return std::nullopt;
}

bool comparisonTakesValue(ScanCompare c) {
    return c == ScanCompare::Exact || c == ScanCompare::Greater || c == ScanCompare::Less || c == ScanCompare::Between ||
           c == ScanCompare::IncreasedBy || c == ScanCompare::DecreasedBy;
}

// Comparisons that only make sense against an earlier scan.
bool comparisonNeedsPrevious(ScanCompare c) {
    return c != ScanCompare::Exact && c != ScanCompare::Greater && c != ScanCompare::Less &&
           c != ScanCompare::Between && c != ScanCompare::Unknown;
}

// A field's likely type, from its bytes, for compare_structures.
std::string guessFieldType(const uint8_t* bytes, size_t available, bool pointerAligned, ProcessHandle& process) {
    if (pointerAligned && available >= 8) {
        uint64_t q;
        std::memcpy(&q, bytes, 8);
        if (q >= 0x10000 && q < 0x800000000000ull)
            if (auto region = process.queryRegion(static_cast<uintptr_t>(q)); region && q >= region->base && q < region->base + region->size)
                return "pointer";
    }
    size_t printable = 0;
    while (printable < 4 && printable < available && std::isprint(bytes[printable])) ++printable;
    if (printable >= 2 && (printable == 4 || (printable < available && bytes[printable] == 0))) return "string";
    // Small integers are tiny denormals as floats; real floats have an exponent.
    uint32_t u;
    std::memcpy(&u, bytes, 4);
    float f;
    std::memcpy(&f, bytes, 4);
    if (u != 0 && std::isfinite(f) && std::fabs(f) >= 0.001f && std::fabs(f) < 1e9f) return "float";
    return "i32";
}

std::string formatField(const std::string& type, const uint8_t* bytes, size_t available) {
    char text[64];
    if (type == "pointer") {
        uint64_t q;
        std::memcpy(&q, bytes, 8);
        std::snprintf(text, sizeof text, "0x%llx", static_cast<unsigned long long>(q));
    } else if (type == "string") {
        std::string out;
        for (size_t i = 0; i < 4 && i < available && bytes[i]; ++i)
            out += std::isprint(bytes[i]) ? static_cast<char>(bytes[i]) : '.';
        return out;
    } else if (type == "float") {
        float f;
        std::memcpy(&f, bytes, 4);
        std::snprintf(text, sizeof text, "%g", static_cast<double>(f));
    } else {
        int32_t v;
        std::memcpy(&v, bytes, 4);
        std::snprintf(text, sizeof text, "%d", v);
    }
    return text;
}

// Fill the search value(s) of a scan, mirroring the CLI's parsing.
std::optional<std::string> setScanValue(ScanConfig& config, const std::string& value, const std::string& value2) {
    const ValueType t = config.valueType;
    if (t == ValueType::Float || t == ValueType::Double) {
        if (!config.parseFloatingValues(value, value2)) return "value is not a number";
    } else if (t == ValueType::String) {
        if (value.empty()) return "value must not be empty";
        config.stringValue = value;
    } else if (t == ValueType::ByteArray) {
        if (!config.parseAOB(value)) return "value must be bytes like \"48 8B ?? 05\"";
    } else {
        bool valid = false;
        config.intValue = parseIntegerScalar(value, false, valid);
        if (!valid) return "value is not an integer";
        if (!value2.empty()) {
            config.intValue2 = parseIntegerScalar(value2, false, valid);
            if (!valid) return "value2 is not an integer";
        }
    }
    if (config.compareType == ScanCompare::Between && value2.empty()) return "a between scan needs value2";
    return std::nullopt;
}

size_t alignmentFor(ValueType t) {
    switch (t) {
        case ValueType::Byte: case ValueType::String: case ValueType::ByteArray: return 1;
        case ValueType::Int16: return 2;
        default: return 4;
    }
}

uint64_t residentBytes(pid_t pid) {
    std::ifstream f("/proc/" + std::to_string(pid) + "/statm");
    unsigned long size = 0, resident = 0;
    if (f >> size >> resident) return static_cast<uint64_t>(resident) * static_cast<uint64_t>(sysconf(_SC_PAGESIZE));
    return 0;
}

std::string argString(const Value& args, const char* key) {
    if (auto s = args.getString(key)) return *s;
    if (const Value* v = args.get(key); v && v->isNumber()) return v->stringValue;   // numbers given as JSON numbers
    return {};
}


// Runs an Auto Assembler script against the real process without changing it:
// reads come from the game, while writes and allocations land in a private
// overlay. A dry run assembles every instruction, resolves symbols and checks
// assert() against the live code, which the structural check() cannot do.
class DryRunProcess : public ProcessHandle {
public:
    explicit DryRunProcess(ProcessHandle& inner) : inner_(inner), regions_(inner.queryRegions()) {}

    pid_t pid() const override { return inner_.pid(); }
    bool is64bit() const override { return inner_.is64bit(); }
    bool runs32BitCode() override { return inner_.runs32BitCode(); }
    TargetDescription targetDescription() override { return inner_.targetDescription(); }
    TargetMachine machineAt(uintptr_t address) override { return inner_.machineAt(address); }
    std::vector<MemoryRegion> queryRegions() override { return inner_.queryRegions(); }
    std::optional<MemoryRegion> queryRegion(uintptr_t address) override {
        for (const auto& [base, bytes] : allocations_)
            if (address >= base && address < base + bytes.size())
                return MemoryRegion{base, bytes.size(), MemProt::All, MemType::Private, MemState::Committed, ""};
        return inner_.queryRegion(address);
    }
    std::vector<ModuleInfo> modules() override { return inner_.modules(); }
    std::vector<ThreadInfo> threads() override { return inner_.threads(); }

    Result<size_t> read(uintptr_t address, void* buffer, size_t size) override {
        auto* out = static_cast<uint8_t*>(buffer);
        if (auto* block = allocationAt(address, size)) {
            std::memcpy(out, block->second.data() + (address - block->first), size);
            return size;
        }
        auto got = inner_.read(address, buffer, size);
        if (!got) return got;
        for (const auto& [at, bytes] : writes_)   // show the script its own earlier writes
            for (size_t i = 0; i < bytes.size(); ++i)
                if (at + i >= address && at + i < address + *got) out[at + i - address] = bytes[i];
        return got;
    }
    Result<size_t> write(uintptr_t address, const void* buffer, size_t size) override {
        const auto* in = static_cast<const uint8_t*>(buffer);
        if (auto* block = allocationAt(address, size)) {
            std::memcpy(block->second.data() + (address - block->first), in, size);
            return size;
        }
        writes_.push_back({address, std::vector<uint8_t>(in, in + size)});
        return size;
    }
    Result<size_t> writeCode(uintptr_t address, const void* buffer, size_t size) override { return write(address, buffer, size); }
    Result<uintptr_t> allocate(size_t size, MemProt, uintptr_t preferredBase) override {
        // A free spot near the preferred address, so rel32 jumps encode as they will for real.
        const uintptr_t step = 0x10000;
        uintptr_t candidate = (preferredBase ? preferredBase : 0x10000000) & ~(step - 1);
        const size_t rounded = (size + step - 1) & ~(step - 1);
        for (int attempt = 0; attempt < 32768; ++attempt, candidate += step)
            if (isFree(candidate, rounded)) {
                allocations_.push_back({candidate, std::vector<uint8_t>(rounded, 0)});
                return candidate;
            }
        return std::unexpected(std::make_error_code(std::errc::not_enough_memory));
    }
    Result<void> free(uintptr_t, size_t) override { return {}; }
    Result<void> protect(uintptr_t, size_t, MemProt) override { return {}; }

    size_t patchedBytes() const {
        size_t total = 0;
        for (const auto& w : writes_) total += w.second.size();
        return total;
    }
    size_t allocations() const { return allocations_.size(); }

private:
    std::pair<uintptr_t, std::vector<uint8_t>>* allocationAt(uintptr_t address, size_t size) {
        for (auto& block : allocations_)
            if (address >= block.first && address + size <= block.first + block.second.size()) return &block;
        return nullptr;
    }
    bool isFree(uintptr_t base, size_t size) const {
        for (const auto& r : regions_) if (base < r.base + r.size && r.base < base + size) return false;
        for (const auto& a : allocations_) if (base < a.first + a.second.size() && a.first < base + size) return false;
        return true;
    }

    ProcessHandle& inner_;
    std::vector<MemoryRegion> regions_;
    std::vector<std::pair<uintptr_t, std::vector<uint8_t>>> allocations_;
    std::vector<std::pair<uintptr_t, std::vector<uint8_t>>> writes_;
};
} // namespace

struct AgentSession::State {
    struct Record {
        CheatEntry entry;
        std::string expression;   // a pointer path, followed again before every use
        bool frozen = false;
        std::string frozenValue;
    };

    AgentSessionOptions options;
    std::mutex mutex;
    std::unique_ptr<os::LinuxProcessHandle> process;
    pid_t pid = 0;
    std::string processName;
    std::vector<ModuleInfo> modules;
    std::unique_ptr<SymbolResolver> symbols;
    MemoryScanner scanner;
    std::unique_ptr<ScanResult> result, undo;
    ValueType scanType = ValueType::Int32;
    size_t scanValueSize = 4;
    std::vector<Record> records;
    std::vector<PointerPath> paths;   // the last pointer_scan, narrowed by pointer_rescan

    // Scripts the agent enabled, kept so they can be disabled (original bytes
    // restored, allocations released) on request, on a new attach, or at exit.
    struct ActiveScript {
        int id = 0;
        std::string description;
        std::string script;
        DisableInfo disable;
    };
    AutoAssembler assembler;   // no Lua evaluator: agent scripts cannot run {$lua}
    std::vector<ActiveScript> scripts;
    int nextScriptId = 1;

    struct DryRunResult { bool ok = false; std::string error; size_t patchedBytes = 0, allocations = 0; };
    // Structural check, then a full assemble against the live code with every
    // write and allocation kept in an overlay: nothing in the game changes.
    DryRunResult dryRun(const std::string& script) {
        DryRunResult out;
        if (auto checked = assembler.check(script); !checked.success) { out.error = "script error: " + checked.error; return out; }
        DryRunProcess dry(*process);
        AutoAssembler scratch;   // its own symbol table: a dry run registers nothing for real
        auto result = scratch.execute(dry, script);
        if (!result.success) { out.error = "script error: " + result.error; return out; }
        out.ok = true;
        out.patchedBytes = dry.patchedBytes();
        out.allocations = dry.allocations();
        return out;
    }

    // Disable every enabled script. Returns the ones that failed.
    std::vector<std::string> disableAll() {
        std::vector<std::string> failures;
        for (auto it = scripts.rbegin(); it != scripts.rend(); ++it) {
            auto result = assembler.disable(*process, it->script, it->disable);
            if (!result.success) failures.push_back("#" + std::to_string(it->id) + ": " + result.error);
        }
        scripts.clear();
        return failures;
    }

    std::atomic<bool> stopping{false};
    std::condition_variable wake;
    std::thread freezer;

    SymbolResolver& resolver() {
        if (!symbols) {
            symbols = std::make_unique<SymbolResolver>();
            symbols->loadProcess(*process);
        }
        return *symbols;
    }

    std::string location(uintptr_t address) {
        std::string where = moduleOffsetString(modules, address);
        return where;
    }

    std::optional<uintptr_t> address(const std::string& text) {
        if (text.empty()) return std::nullopt;
        if (auto a = ExpressionParser(process.get()).parse(text)) return a;
        return ExpressionParser(process.get(), &resolver()).parse(text);
    }

    ValueIoOptions ioOptions(uintptr_t address, ValueType type, size_t size) {
        ValueIoOptions options;
        options.size = size;
        options.pointerWidth = process->pointerWidth();
        if (auto target = valueOptionsForTarget(*process, address, type, options)) return *target;
        return options;
    }

    std::vector<CheatEntry> entries() {
        std::vector<CheatEntry> out;
        for (auto& r : records) {
            CheatEntry entry = r.entry;
            entry.active = r.frozen;
            if (!r.expression.empty())
                if (auto chain = parsePointerExpression(r.expression)) {
                    entry.addressString = chain->base;
                    entry.offsets = chain->offsets;
                }
            if (entry.autoAsmScript.empty() && process)
                entry.value = r.frozen ? r.frozenValue : (refresh(r) ? readValue(r.entry.address, r.entry.type) : "");
            out.push_back(std::move(entry));
        }
        return out;
    }

    // Follow a pointer record's path to where the value is now. False when a
    // pointer on the way is null or unreadable.
    bool refresh(Record& r) {
        if (r.expression.empty()) return true;
        auto now = address(r.expression);
        if (!now) return false;
        r.entry.address = *now;
        return true;
    }

    std::optional<MemoryOperand> memoryOperand(uintptr_t at) {
        auto arch = disassemblerArchFor(*process, at);
        if (!arch) return std::nullopt;
        uint8_t code[16];
        auto got = process->read(at, code, sizeof code);
        if (!got || *got == 0) return std::nullopt;
        Disassembler disassembler(*arch);
        auto decoded = disassembler.disassemble(at, {code, *got}, 1);
        if (decoded.empty() || !decoded.front().memory.present) return std::nullopt;
        return decoded.front().memory;
    }

    Value pathList(size_t limit) {
        Value list = Value::array();
        for (size_t i = 0; i < paths.size() && i < limit; ++i) list.push(Value::string(paths[i].toString()));
        return list;
    }

    std::string readValue(uintptr_t address, ValueType type, size_t size = 32) {
        auto value = readTypedValue(*process, address, type, ioOptions(address, type, size));
        return value ? *value : std::string("?");
    }

    Value candidates(size_t offset, size_t limit) {
        Value list = Value::array();
        if (!result) return list;
        const size_t end = std::min(result->count(), offset + limit);
        for (size_t i = offset; i < end; ++i) {
            const uintptr_t a = result->address(i);
            Value item = Value::object().set("address", Value::string(hex(a)));
            if (auto where = location(a); !where.empty()) item.set("location", Value::string(where));
            item.set("value", Value::string(readValue(a, scanType, scanValueSize)));
            list.push(std::move(item));
        }
        return list;
    }

    Value scanSummary(const char* hint) {
        const size_t count = result ? result->count() : 0;
        Value out = Value::object().set("count", Value::number(static_cast<uint64_t>(count)));
        out.set("candidates", candidates(0, std::min<size_t>(10, count)));
        if (count > 10) out.set("more", Value::number(static_cast<uint64_t>(count - 10)));
        if (hint) out.set("next", Value::string(hint));
        return out;
    }

    void freezeLoop() {
        std::unique_lock lock(mutex);
        while (!stopping) {
            wake.wait_for(lock, std::chrono::milliseconds(options.freezeIntervalMs));
            if (stopping || !process) continue;
            for (auto& r : records)
                if (r.frozen && refresh(r))
                    (void)writeTypedValue(*process, r.entry.address, r.entry.type, r.frozenValue,
                                          ioOptions(r.entry.address, r.entry.type, r.frozenValue.size()));
        }
    }
};

AgentSession::AgentSession(AgentSessionOptions options) : state_(std::make_unique<State>()) {
    state_->options = options;
    state_->freezer = std::thread([s = state_.get()] { s->freezeLoop(); });
}

AgentSession::~AgentSession() {
    {
        std::lock_guard lock(state_->mutex);
        state_->stopping = true;
        // Leave the game as it was: undo injected code the agent enabled.
        if (state_->process) state_->disableAll();
    }
    state_->wake.notify_all();
    if (state_->freezer.joinable()) state_->freezer.join();
}

pid_t AgentSession::attachedPid() {
    std::lock_guard lock(state_->mutex);
    return state_->process ? state_->pid : 0;
}

std::vector<std::string> AgentSession::detach() {
    std::lock_guard lock(state_->mutex);
    auto& s = *state_;
    std::vector<std::string> failures;
    if (s.process) failures = s.disableAll();
    s.process.reset();
    s.pid = 0;
    s.processName.clear();
    s.modules.clear();
    s.symbols.reset();
    s.result.reset();
    s.undo.reset();
    s.records.clear();
    s.paths.clear();
    return failures;
}

void AgentSession::setAllowWrites(bool allow) {
    std::lock_guard lock(state_->mutex);
    state_->options.allowWrites = allow;
}

std::vector<CheatEntry> AgentSession::tableEntries() {
    std::lock_guard lock(state_->mutex);
    return state_->entries();
}

std::string AgentSession::instructions() {
    return "Cheat Engine for Linux: find and change values in a running program.\n"
           "Typical workflow: list_processes, attach, then first_scan for the value the user sees "
           "(for example health 100, type i32). Ask the user to change that value in the game, then "
           "next_scan with the new value (or compare increased/decreased/changed when the exact value "
           "is unknown). Repeat until a few candidates remain. Confirm one by reading it, or by writing "
           "a test value and asking the user whether the game shows it. Then add_record, set_frozen to "
           "keep it, and save_table so the user can reuse it.\n"
           "Floats: use type float and the value the game shows. Unknown starting value: first_scan "
           "with compare unknown, then next_scan increased/decreased/unchanged.\n"
           "To change behaviour (for example health never decreasing): find_what_writes on the address while "
           "the user makes the value change, aa_template on the writing instruction, edit the code under newmem "
           "(for example remove the subtraction), aa_check, then aa_enable and ask the user to confirm. Save "
           "working scripts with add_record script so they land in the table. Scripts cannot contain {$lua}.\n"
           "Values that move (the game reallocates them): pointer_scan the address, ask the user to make the value move "
           "(for example load a level), find it again and pointer_rescan with its new address. add_record with a path "
           "from the result keeps following the pointer, also when frozen. find_what_writes also reports the pointer "
           "value an instruction used, which you can scan for (type i64) to follow a pointer by hand.\n"
           "Code shared by several objects (one instruction writes the health of player and enemies): "
           "find_accessed_addresses on the instruction lists the objects it touches; compare_structures with the "
           "player's objects as group1 and the enemies' as group2 finds the field that tells them apart (a team "
           "or owner id). Then write an injection that checks that field before the original instruction.\n"
           "Only use this for single-player games or software the user may analyze. Writes change the "
           "running program; they are refused unless the server was started with writes enabled.";
}

std::vector<AgentToolInfo> AgentSession::tools() {
    const Value address = prop("string", "Address: hex (0x7f12a0), module+offset (game+0x301c), symbol, or pointer expression ([game+0x10]+8)");
    const Value type = enumProp(kTypes, "Value type: byte, i16, i32 (most game values), i64, float, double, string, aob (byte pattern)");
    return {
        {"list_processes", "List running processes of this user, largest memory first. Use a filter to find the game.",
         schema({{"filter", prop("string", "Case-insensitive part of the process name")}}, {})},
        {"attach", "Attach to a process by PID or unique name. Required before any other tool except list_processes.",
         schema({{"target", prop("string", "PID or process name")}}, {"target"})},
        {"target_info", "Describe the attached process: name, PID, kind (native, Wine, emulator...), architecture, modules.",
         schema({}, {})},
        {"first_scan", "Start a new scan of writable memory for a value. Returns the match count and the first candidates.",
         schema({{"type", type},
                 {"compare", enumProp({"exact", "greater", "less", "between", "unknown"}, "How to match; unknown records every value for later comparison (default exact)")},
                 {"value", prop("string", "Value to find (not needed for compare unknown)")},
                 {"value2", prop("string", "Upper bound for compare between")}},
                {"type"})},
        {"next_scan", "Narrow the previous scan after the value changed in the game.",
         schema({{"compare", enumProp({"exact", "greater", "less", "between", "changed", "unchanged", "increased", "decreased", "same_as_first",
                                       "increased_by", "decreased_by"}, "How the value changed (default exact)")},
                 {"value", prop("string", "The new value for exact/greater/less/between, or the amount for increased_by/decreased_by")},
                 {"value2", prop("string", "Upper bound for between")}},
                {})},
        {"undo_scan", "Restore the results from before the last next_scan.", schema({}, {})},
        {"scan_results", "Page through the current scan results with their live values.",
         schema({{"offset", prop("integer", "First result index (default 0)")},
                 {"limit", prop("integer", "How many (default 20, at most 50)")}}, {})},
        {"read", "Read a typed value from memory.",
         schema({{"address", address}, {"type", type},
                 {"size", prop("integer", "Bytes to read for string and aob (default 32, at most 256)")}},
                {"address", "type"})},
        {"write", "Write a typed value to memory (changes the running program; needs writes enabled).",
         schema({{"address", address}, {"type", type}, {"value", prop("string", "Value to write")}},
                {"address", "type", "value"})},
        {"disassemble", "Disassemble instructions at an address, with symbols.",
         schema({{"address", address}, {"count", prop("integer", "Instructions (default 12, at most 40)")}},
                {"address"})},
        {"find_what_writes", "Watch an address and report the instructions that write to it (or read it, with accesses true). "
                             "Blocks for the given seconds: ask the user to make the value change in the game during that time.",
         schema({{"address", address},
                 {"seconds", prop("integer", "How long to watch (default 8, at most 30)")},
                 {"size", prop("integer", "Bytes to watch: 1, 2, 4 or 8 (default 4)")},
                 {"accesses", prop("boolean", "Also report reads (default false: writes only)")}},
                {"address"})},
        {"find_accessed_addresses", "Watch one instruction (usually from find_what_writes) and list every address it reads or "
                                    "writes, with hit counts: shows whether code is shared by several objects (player and enemies). "
                                    "Pauses the game briefly at each hit; ask the user to play during the given seconds.",
         schema({{"address", address},
                 {"seconds", prop("integer", "How long to watch (default 4, at most 30)")}},
                {"address"})},
        {"compare_structures", "Dissect structures side by side: each 4-byte field with a guessed type (i32, float, string, "
                               "pointer) and its value in every structure. With group2, marks the fields that are equal within "
                               "each group but different between the groups, such as a team field.",
         schema({{"group1", Value::object().set("type", Value::string("array")).set("items", Value::object().set("type", Value::string("string")))
                                .set("description", Value::string("Structure start addresses (for example the player's)"))},
                 {"group2", Value::object().set("type", Value::string("array")).set("items", Value::object().set("type", Value::string("string")))
                                .set("description", Value::string("Optional second group (for example the enemies')"))},
                 {"size", prop("integer", "Bytes to compare from each address (default 64, at most 512)")}},
                {"group1"})},
        {"pointer_scan", "Find pointer paths from the game's static memory to an address, so a value the game moves can be "
                         "found again (and frozen) after it moves. Returns the shortest paths; then pointer_rescan.",
         schema({{"address", address},
                 {"max_depth", prop("integer", "Pointer levels (default 4, at most 6)")},
                 {"max_offset", prop("integer", "Largest offset at each level (default 1024)")}},
                {"address"})},
        {"pointer_rescan", "After the value moved, keep only the paths from pointer_scan that lead to its new address.",
         schema({{"address", prop("string", "The value's new address")}}, {"address"})},
        {"aa_template", "Generate an Auto Assembler code-injection script for an instruction (usually one from find_what_writes). "
                        "It relocates the original instructions into a code cave and restores the exact bytes on disable; "
                        "edit the code under newmem, then aa_check and aa_enable.",
         schema({{"address", address},
                 {"kind", enumProp({"code", "aob"}, "code: module+offset address (default); aob: found by a unique byte signature, survives game updates")}},
                {"address"})},
        {"aa_check", "Check an Auto Assembler script for errors without touching the game.",
         schema({{"script", prop("string", "The full script with [ENABLE] and [DISABLE] sections")}}, {"script"})},
        {"aa_enable", "Enable an Auto Assembler script in the game (patches its code; needs writes enabled). "
                      "Returns an id for aa_disable. A wrong script can crash the game: check it first and tell the user what it changes.",
         schema({{"script", prop("string", "The full script with [ENABLE] and [DISABLE] sections")},
                 {"description", prop("string", "What the script does, e.g. Infinite health")}},
                {"script", "description"})},
        {"aa_disable", "Disable a script enabled with aa_enable: restores the original code and frees its memory.",
         schema({{"id", prop("integer", "Id returned by aa_enable")}}, {"id"})},
        {"aa_list", "List the scripts currently enabled in the game.", schema({}, {})},
        {"add_record", "Add an entry to the cheat table: a value (address and type) or a script (script), with a description the user will recognize. "
                       "A pointer path such as [[game+0x2010]+0x10]+0x18 is followed again on every read and freeze.",
         schema({{"address", address}, {"type", type}, {"description", prop("string", "What the entry is, e.g. Health or Infinite health")},
                 {"script", prop("string", "An Auto Assembler script, for a script entry instead of a value")}},
                {"description"})},
        {"list_records", "List the cheat table with live values.", schema({}, {})},
        {"set_frozen", "Freeze a record at a value (kept in memory continuously), or unfreeze it. Freezing needs writes enabled.",
         schema({{"index", prop("integer", "Record index from list_records")},
                 {"frozen", prop("boolean", "true to freeze, false to unfreeze")},
                 {"value", prop("string", "Value to hold (default: the current value)")}},
                {"index", "frozen"})},
        {"save_table", "Save the cheat table to a .CT (Cheat Engine) or .json file the user can open later.",
         schema({{"path", prop("string", "File path ending in .CT or .json")},
                 {"overwrite", prop("boolean", "Replace an existing file (default false)")}},
                {"path"})},
    };
}

AgentToolResult AgentSession::call(const std::string& name, const json::Value& args) {
    State& s = *state_;
    std::lock_guard lock(s.mutex);
    if (!args.isObject() && !args.isNull()) return fail("arguments must be an object");
    try {
        if (name == "list_processes") {
            std::string filter = argString(args, "filter");
            std::transform(filter.begin(), filter.end(), filter.begin(), [](unsigned char c) { return std::tolower(c); });
            struct Row { pid_t pid; std::string name; uint64_t rss; };
            std::vector<Row> rows;
            const uid_t me = geteuid();
            for (const auto& p : os::LinuxProcessEnumerator().list()) {
                struct stat st{};
                if (::stat(("/proc/" + std::to_string(p.pid)).c_str(), &st) != 0 || st.st_uid != me) continue;
                if (p.pid == getpid()) continue;
                std::string lower = p.name;
                std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return std::tolower(c); });
                if (!filter.empty() && lower.find(filter) == std::string::npos) continue;
                const uint64_t rss = residentBytes(p.pid);
                if (rss == 0) continue;
                rows.push_back({p.pid, p.name, rss});
            }
            std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) { return a.rss > b.rss; });
            Value list = Value::array();
            for (size_t i = 0; i < rows.size() && i < 30; ++i)
                list.push(Value::object().set("pid", Value::number(static_cast<int64_t>(rows[i].pid)))
                              .set("name", Value::string(rows[i].name))
                              .set("memory_mb", Value::number(static_cast<uint64_t>(rows[i].rss >> 20))));
            return ok(Value::object().set("processes", list).set("shown", Value::number(static_cast<uint64_t>(list.arrayValue.size())))
                                     .set("total", Value::number(static_cast<uint64_t>(rows.size()))));
        }

        if (name == "attach") {
            const std::string target = argString(args, "target");
            if (target.empty()) return fail("target is required");
            pid_t pid = 0;
            if (std::all_of(target.begin(), target.end(), [](unsigned char c) { return std::isdigit(c); })) {
                pid = static_cast<pid_t>(std::stol(target));
            } else {
                std::vector<ProcessInfo> matches;
                for (const auto& p : os::LinuxProcessEnumerator().list())
                    if (p.name == target || std::filesystem::path(p.path).filename() == target) matches.push_back(p);
                if (matches.empty()) return fail("no process named '" + target + "'; use list_processes");
                if (matches.size() > 1) {
                    std::string pids;
                    for (const auto& p : matches) pids += (pids.empty() ? "" : ", ") + std::to_string(p.pid);
                    return fail("several processes are named '" + target + "' (PIDs " + pids + "); attach by PID");
                }
                pid = matches.front().pid;
            }
            if (pid <= 0 || ::kill(pid, 0) != 0) return fail("process " + std::to_string(pid) + " is not running");
            auto process = std::make_unique<os::LinuxProcessHandle>(pid);
            if (auto problem = memoryAccessProblem(*process)) return fail("cannot read this process: " + *problem);
            const bool sameProcess = s.pid == pid;
            if (s.process) s.disableAll();   // never leave a previous target patched
            s.process = std::move(process);
            s.pid = pid;
            s.modules = s.process->modules();
            s.symbols.reset();
            s.result.reset();
            s.undo.reset();
            if (!sameProcess) { s.records.clear(); s.paths.clear(); }
            std::string procName;
            for (const auto& p : os::LinuxProcessEnumerator().list()) if (p.pid == pid) procName = p.name;
            s.processName = procName.empty() ? std::to_string(pid) : procName;
            return ok(Value::object().set("attached", Value::string(s.processName))
                                     .set("pid", Value::number(static_cast<int64_t>(pid)))
                                     .set("kind", Value::string(probeTarget(pid).summary())));
        }

        if (!s.process) return fail("no process attached; call attach first");

        if (name == "target_info") {
            const auto description = s.process->targetDescription();
            Value out = Value::object().set("name", Value::string(s.processName))
                .set("pid", Value::number(static_cast<int64_t>(s.pid)))
                .set("kind", Value::string(probeTarget(s.pid).summary()))
                .set("architecture", Value::string(cpuArchitectureName(description.program.architecture)))
                .set("pointer_bytes", Value::number(static_cast<int64_t>(description.program.pointerWidth)))
                .set("modules", Value::number(static_cast<uint64_t>(s.modules.size())));
            if (!s.modules.empty())
                out.set("main_module", Value::string(s.modules.front().name + " at " + hex(s.modules.front().base)));
            return ok(out);
        }

        if (name == "first_scan" || name == "next_scan") {
            const bool first = name == "first_scan";
            if (!first && !s.result) return fail("no scan yet; call first_scan");
            ValueType type = s.scanType;
            if (first) {
                auto parsed = parseValueType(argString(args, "type"));
                if (!parsed || std::find(kTypes.begin(), kTypes.end(), argString(args, "type")) == kTypes.end())
                    return fail("type must be one of byte, i16, i32, i64, float, double, string, aob");
                type = *parsed;
            }
            const std::string compareText = argString(args, "compare").empty() ? "exact" : argString(args, "compare");
            auto compare = parseCompare(compareText);
            if (!compare) return fail("unknown compare '" + compareText + "'");
            const bool firstOnly = *compare == ScanCompare::Unknown;
            const bool nextOnly = comparisonNeedsPrevious(*compare);
            if (first && nextOnly) return fail("compare " + compareText + " needs an earlier scan; use next_scan");
            if (!first && firstOnly) return fail("compare unknown starts a scan; use first_scan");
            ScanConfig config;
            config.valueType = type;
            config.compareType = *compare;
            config.alignment = alignmentFor(type);
            config.writableMatch = ProtMatch::Yes;
            const std::string value = argString(args, "value");
            if (comparisonTakesValue(*compare)) {
                if (value.empty()) return fail("compare " + compareText + " needs a value");
                if (auto error = setScanValue(config, value, argString(args, "value2"))) return fail(*error);
            }
            if ((type == ValueType::String || type == ValueType::ByteArray) && !comparisonTakesValue(*compare))
                return fail("string and aob scans need an exact value");
            if (first) {
                if (auto problem = memoryAccessProblem(*s.process)) return fail("cannot read this process: " + *problem);
                auto scanned = std::make_unique<ScanResult>(s.scanner.firstScan(*s.process, config));
                s.undo.reset();
                s.result = std::move(scanned);
                s.scanType = type;
                s.scanValueSize = type == ValueType::String ? value.size() : std::max<size_t>(1, s.result->valueSize());
            } else {
                auto narrowed = std::make_unique<ScanResult>(s.scanner.nextScan(*s.process, config, *s.result));
                s.undo = std::move(s.result);
                s.result = std::move(narrowed);
            }
            const size_t count = s.result->count();
            const char* hint = count == 0 ? "Nothing matched. Check the type (float vs i32) or undo_scan."
                             : count == 1 ? "One candidate: confirm it with read or a test write, then add_record."
                             : count <= 10 ? "Few candidates: confirm one by changing the value in the game and reading them."
                                           : "Ask the user to change the value in the game, then call next_scan.";
            return ok(s.scanSummary(hint));
        }

        if (name == "undo_scan") {
            if (!s.undo) return fail("nothing to undo");
            s.result = std::move(s.undo);
            return ok(s.scanSummary(nullptr));
        }

        if (name == "scan_results") {
            if (!s.result) return fail("no scan yet; call first_scan");
            const int64_t offset = std::max<int64_t>(0, args.getInt("offset").value_or(0));
            const int64_t limit = std::clamp<int64_t>(args.getInt("limit").value_or(20), 1, kMaxCandidates);
            return ok(Value::object().set("count", Value::number(static_cast<uint64_t>(s.result->count())))
                                     .set("offset", Value::number(offset))
                                     .set("candidates", s.candidates(static_cast<size_t>(offset), static_cast<size_t>(limit))));
        }

        auto needAddress = [&]() -> std::optional<uintptr_t> { return s.address(argString(args, "address")); };
        auto needType = [&]() -> std::optional<ValueType> {
            const std::string t = argString(args, "type");
            if (std::find(kTypes.begin(), kTypes.end(), t) == kTypes.end()) return std::nullopt;
            return parseValueType(t);
        };

        if (name == "read") {
            auto address = needAddress();
            if (!address) return fail("cannot resolve address '" + argString(args, "address") + "'");
            auto type = needType();
            if (!type) return fail("type must be one of byte, i16, i32, i64, float, double, string, aob");
            const size_t size = static_cast<size_t>(std::clamp<int64_t>(args.getInt("size").value_or(32), 1, kMaxReadBytes));
            auto value = readTypedValue(*s.process, *address, *type, s.ioOptions(*address, *type, size));
            if (!value) return fail("read failed: " + value.error());
            Value out = Value::object().set("address", Value::string(hex(*address)));
            if (auto where = s.location(*address); !where.empty()) out.set("location", Value::string(where));
            return ok(out.set("value", Value::string(*value)));
        }

        if (name == "write") {
            if (!s.options.allowWrites)
                return fail("writes are disabled; the user must start the server with --allow-writes");
            auto address = needAddress();
            if (!address) return fail("cannot resolve address '" + argString(args, "address") + "'");
            auto type = needType();
            if (!type) return fail("type must be one of byte, i16, i32, i64, float, double, string, aob");
            const std::string value = argString(args, "value");
            if (value.empty()) return fail("value is required");
            auto written = writeTypedValue(*s.process, *address, *type, value, s.ioOptions(*address, *type, value.size()));
            if (!written) return fail("write failed: " + written.error());
            return ok(Value::object().set("address", Value::string(hex(*address)))
                                     .set("bytes", Value::number(static_cast<uint64_t>(*written)))
                                     .set("value_now", Value::string(s.readValue(*address, *type, value.size()))));
        }

        if (name == "disassemble") {
            auto address = needAddress();
            if (!address) return fail("cannot resolve address '" + argString(args, "address") + "'");
            const size_t count = static_cast<size_t>(std::clamp<int64_t>(args.getInt("count").value_or(12), 1, kMaxInstructions));
            auto arch = disassemblerArchFor(*s.process, *address);
            if (!arch) return fail(arch.error());
            std::vector<uint8_t> code(count * 15);
            auto got = s.process->read(*address, code.data(), code.size());
            if (!got || *got == 0) return fail("cannot read code at " + hex(*address));
            Disassembler disassembler(*arch);
            Value lines = Value::array();
            for (const auto& instruction : disassembler.disassemble(*address, {code.data(), *got}, count)) {
                Value line = Value::object().set("address", Value::string(hex(instruction.address)));
                std::string where = s.resolver().resolve(instruction.address);
                if (where.empty()) where = s.location(instruction.address);
                if (!where.empty()) line.set("location", Value::string(where));
                lines.push(line.set("text", Value::string(instruction.toString())));
            }
            return ok(Value::object().set("instructions", lines));
        }


        if (name == "find_what_writes") {
            auto address = needAddress();
            if (!address) return fail("cannot resolve address '" + argString(args, "address") + "'");
            const int seconds = static_cast<int>(std::clamp<int64_t>(args.getInt("seconds").value_or(8), 1, kMaxWatchSeconds));
            const int size = static_cast<int>(args.getInt("size").value_or(4));
            if (size != 1 && size != 2 && size != 4 && size != 8) return fail("size must be 1, 2, 4 or 8");
            const bool writesOnly = !args.getBool("accesses").value_or(false);
            // Wine/Proton: watch the main thread only with a hardware register; stopping
            // the whole thread group or the software page guard would freeze the game.
            const bool wine = probeTarget(s.pid).wine;
            os::LinuxDebugger debugger;
            CodeFinder finder;
            if (!finder.start(*s.process, debugger, *address, writesOnly, size, /*software=*/false, /*singleThread=*/wine))
                return fail("could not watch the address: " +
                            targetOperationError(*s.process, TargetFeature::HardwareWatchpoint, finder.lastError()));
            std::this_thread::sleep_for(std::chrono::seconds(seconds));
            finder.stop();
            Value list = Value::array();
            bool pointerHint = false;
            for (const auto& hit : finder.results()) {
                uintptr_t at = hit.instructionAddress;
                std::string text = hit.instructionText;
                // A hardware trap stops after the store; recover the exact instruction.
                auto recovered = recoverStoreInstruction(*s.process, s.resolver(), hit.firstContext.instructionPointer(),
                                                         s.process->is64bit());
                if (recovered.ok) { at = recovered.address; text = recovered.text; }
                Value item = Value::object().set("address", Value::string(hex(at)));
                std::string where = s.resolver().resolve(at);
                if (where.empty()) where = s.location(at);
                if (!where.empty()) item.set("location", Value::string(where));
                item.set("instruction", Value::string(text)).set("hits", Value::number(static_cast<uint64_t>(hit.hitCount)));
                // [reg+offset]: the pointer the game followed is the address minus the
                // offset, whatever the register holds after the instruction ran.
                if (auto memory = s.memoryOperand(at); memory && !memory->ripRelative && memory->indexReg.empty() && !memory->baseReg.empty()) {
                    item.set("pointer", Value::string(hex(*address - static_cast<uintptr_t>(memory->disp))));
                    item.set("offset", Value::string(memory->disp < 0 ? "-" + hex(static_cast<uint64_t>(-memory->disp)) : hex(static_cast<uint64_t>(memory->disp))));
                    pointerHint = true;
                }
                list.push(std::move(item));
                if (list.arrayValue.size() >= 10) break;
            }
            Value out = Value::object().set("watched_seconds", Value::number(seconds)).set("instructions", list);
            if (list.arrayValue.empty())
                out.set("next", Value::string(std::string("Nothing ") + (writesOnly ? "wrote" : "touched") +
                    " the address. Ask the user to make the value change, then watch again." +
                    (wine ? " (Wine: only the main thread is watched.)" : "")));
            else
                out.set("next", Value::string(std::string("Pass the instruction address to aa_template to build an injection.") +
                    (pointerHint ? " The value sits at pointer+offset: if the game moves it, pointer_scan it, or first_scan "
                                   "type i64 for the pointer value to find where that pointer is kept." : "")));
            return ok(out);
        }

        if (name == "find_accessed_addresses") {
            auto address = needAddress();
            if (!address) return fail("cannot resolve address '" + argString(args, "address") + "'");
            const int seconds = static_cast<int>(std::clamp<int64_t>(args.getInt("seconds").value_or(4), 1, kMaxWatchSeconds));
            if (!s.memoryOperand(*address)) return fail("the instruction at " + hex(*address) + " does not access memory");
            auto accesses = findInstructionAccesses(*s.process, *address, 4096, seconds * 1000);
            Value list = Value::array();
            for (const auto& access : accesses) {
                Value item = Value::object().set("address", Value::string(hex(access.address)))
                                            .set("hits", Value::number(static_cast<int64_t>(access.hitCount)));
                if (auto where = s.location(access.address); !where.empty()) item.set("location", Value::string(where));
                list.push(std::move(item));
                if (list.arrayValue.size() >= 32) break;
            }
            Value out = Value::object().set("watched_seconds", Value::number(seconds)).set("addresses", list);
            out.set("next", Value::string(list.arrayValue.empty()
                ? "The instruction did not run. Ask the user to play so it runs, then watch again."
                : "Several addresses mean shared code. The structure starts at address minus the instruction's offset; "
                  "compare_structures with the player's and the enemies' structures to find what tells them apart."));
            return ok(out);
        }

        if (name == "compare_structures") {
            auto collect = [&](const char* key, std::vector<uintptr_t>& out) -> std::optional<std::string> {
                const Value* list = args.get(key);
                if (!list) return std::nullopt;
                if (!list->isArray()) return std::string(key) + " must be a list of addresses";
                for (const auto& item : list->arrayValue) {
                    std::string text = item.isString() ? item.stringValue : std::string();
                    auto resolved = text.empty() ? std::nullopt : s.address(text);
                    if (!resolved) return "cannot resolve address '" + text + "' in " + key;
                    out.push_back(*resolved);
                }
                return std::nullopt;
            };
            std::vector<uintptr_t> group1, group2;
            if (auto error = collect("group1", group1)) return fail(*error);
            if (auto error = collect("group2", group2)) return fail(*error);
            if (group1.empty()) return fail("group1 needs at least one address");
            if (group1.size() + group2.size() > 8) return fail("compare at most 8 structures at a time");
            const size_t size = static_cast<size_t>(std::clamp<int64_t>(args.getInt("size").value_or(64), 4, kMaxStructureBytes)) & ~size_t{3};
            std::vector<uintptr_t> all = group1;
            all.insert(all.end(), group2.begin(), group2.end());
            std::vector<std::vector<uint8_t>> snapshots;
            for (uintptr_t base : all) {
                std::vector<uint8_t> bytes(size + 8, 0);
                auto got = s.process->read(base, bytes.data(), bytes.size());
                if (!got || *got < size) return fail("cannot read " + std::to_string(size) + " bytes at " + hex(base));
                snapshots.push_back(std::move(bytes));
            }
            Value fields = Value::array();
            Value discriminators = Value::array();
            for (size_t offset = 0; offset < size; offset += 4) {
                // The first structure decides the type; an 8-byte pointer covers two fields.
                const std::string type = guessFieldType(snapshots[0].data() + offset, size + 8 - offset, offset % 8 == 0, *s.process);
                const size_t width = type == "pointer" ? 8 : 4;
                Value values = Value::array();
                std::vector<std::vector<uint8_t>> raw;
                for (const auto& snapshot : snapshots) {
                    values.push(Value::string(formatField(type, snapshot.data() + offset, size + 8 - offset)));
                    raw.emplace_back(snapshot.begin() + offset, snapshot.begin() + offset + width);
                }
                Value field = Value::object().set("offset", Value::string(hex(offset))).set("type", Value::string(type))
                                             .set("values", values);
                bool differs = false;
                if (!group2.empty()) {
                    auto same = [&](size_t from, size_t to) {
                        for (size_t i = from + 1; i < to; ++i) if (raw[i] != raw[from]) return false;
                        return true;
                    };
                    differs = same(0, group1.size()) && same(group1.size(), raw.size()) && raw[0] != raw[group1.size()];
                    if (differs) {
                        field.set("differs_between_groups", Value::boolean(true));
                        discriminators.push(Value::string(hex(offset)));
                    }
                }
                fields.push(std::move(field));
                if (width == 8) offset += 4;
            }
            Value out = Value::object().set("structures", Value::number(static_cast<uint64_t>(all.size())))
                                       .set("fields", fields);
            if (!group2.empty()) out.set("differs_between_groups", discriminators);
            return ok(out);
        }

        if (name == "pointer_scan") {
            auto address = needAddress();
            if (!address) return fail("cannot resolve address '" + argString(args, "address") + "'");
            PointerScanConfig config;
            config.targetAddress = *address;
            config.maxDepth = static_cast<int>(std::clamp<int64_t>(args.getInt("max_depth").value_or(4), 1, 6));
            config.maxOffset = static_cast<int>(std::clamp<int64_t>(args.getInt("max_offset").value_or(1024), 8, 1 << 20));
            PointerScanner scanner;
            s.paths = scanner.scan(*s.process, config);
            sortPointerPaths(s.paths, PointerSortKey::Depth);
            Value out = Value::object().set("count", Value::number(static_cast<uint64_t>(s.paths.size())))
                                       .set("paths", s.pathList(kMaxPaths));
            if (scanner.truncated())
                out.set("truncated", Value::string("stopped at " + std::to_string(config.maxResults) +
                                                   " paths, so longer ones may be missing; a smaller max_offset finds them"));
            out.set("next", Value::string(s.paths.empty()
                ? "No path found. Try a larger max_depth or max_offset."
                : "Ask the user to make the value move (restart the level, or whatever reallocates it), find it again, "
                  "then pointer_rescan with its new address. add_record accepts a path directly."));
            return ok(out);
        }

        if (name == "pointer_rescan") {
            if (s.paths.empty()) return fail("no pointer paths; call pointer_scan first");
            auto address = needAddress();
            if (!address) return fail("cannot resolve address '" + argString(args, "address") + "'");
            const size_t before = s.paths.size();
            s.paths = rescanPointerPaths(*s.process, s.paths, *address);
            return ok(Value::object().set("before", Value::number(static_cast<uint64_t>(before)))
                                     .set("count", Value::number(static_cast<uint64_t>(s.paths.size())))
                                     .set("paths", s.pathList(kMaxPaths)));
        }

        if (name == "aa_template") {
            auto address = needAddress();
            if (!address) return fail("cannot resolve address '" + argString(args, "address") + "'");
            const std::string kind = argString(args, "kind").empty() ? "code" : argString(args, "kind");
            if (kind != "code" && kind != "aob") return fail("kind must be code or aob");
            std::string error;
            std::string script = generateInjectionScript(*s.process, *address,
                kind == "aob" ? InjectionKind::Aob : InjectionKind::Code, error);
            if (script.empty()) return fail("cannot build an injection here: " + error);
            return ok(Value::object().set("script", Value::string(script))
                .set("next", Value::string("Edit the code under newmem (keep the relocated original instructions unless "
                                           "you mean to skip them), then aa_check and aa_enable.")));
        }

        auto needScript = [&]() -> std::optional<std::string> {
            std::string script = argString(args, "script");
            if (script.empty() || script.size() > kMaxScriptBytes) return std::nullopt;
            return script;
        };

        if (name == "aa_check") {
            auto script = needScript();
            if (!script) return fail("script is required (at most 64 KiB)");
            if (auto checked = s.dryRun(*script); !checked.ok) return fail(checked.error);
            else return ok(Value::object().set("ok", Value::boolean(true))
                                          .set("would_patch_bytes", Value::number(static_cast<uint64_t>(checked.patchedBytes)))
                                          .set("would_allocate", Value::number(static_cast<uint64_t>(checked.allocations))));
        }

        if (name == "aa_enable") {
            if (!s.options.allowWrites)
                return fail("enabling a script patches the game; the user must start the server with --allow-writes");
            auto script = needScript();
            if (!script) return fail("script is required (at most 64 KiB)");
            const std::string description = argString(args, "description");
            if (description.empty()) return fail("description is required");
            if (auto checked = s.dryRun(*script); !checked.ok) return fail(checked.error);
            auto result = s.assembler.execute(*s.process, *script);
            if (!result.success) return fail("enable failed: " + result.error);
            Value patches = Value::array();
            for (const auto& original : result.disableInfo.originals) {
                Value patch = Value::object().set("address", Value::string(hex(original.address)))
                                             .set("bytes", Value::number(static_cast<uint64_t>(original.bytes.size())));
                if (auto where = s.location(original.address); !where.empty()) patch.set("location", Value::string(where));
                patches.push(std::move(patch));
            }
            Value allocations = Value::array();
            for (const auto& allocation : result.disableInfo.allocs)
                allocations.push(Value::object().set("name", Value::string(allocation.name))
                                                .set("address", Value::string(hex(allocation.address)))
                                                .set("size", Value::number(static_cast<uint64_t>(allocation.size))));
            State::ActiveScript active{s.nextScriptId++, description, *script, std::move(result.disableInfo)};
            const int id = active.id;
            s.scripts.push_back(std::move(active));
            return ok(Value::object().set("id", Value::number(id)).set("patched", patches).set("allocated", allocations)
                .set("next", Value::string("Ask the user whether it works in the game. aa_disable undoes it; add_record "
                                           "with the script saves it to the table.")));
        }

        if (name == "aa_disable") {
            auto id = args.getInt("id");
            auto it = std::find_if(s.scripts.begin(), s.scripts.end(), [&](const auto& a) { return id && a.id == *id; });
            if (it == s.scripts.end()) return fail("no enabled script with that id; see aa_list");
            auto result = s.assembler.disable(*s.process, it->script, it->disable);
            if (!result.success) return fail("disable failed: " + result.error);
            s.scripts.erase(it);
            return ok(Value::object().set("disabled", Value::number(*id)));
        }

        if (name == "aa_list") {
            Value list = Value::array();
            for (const auto& a : s.scripts)
                list.push(Value::object().set("id", Value::number(a.id)).set("description", Value::string(a.description)));
            return ok(Value::object().set("enabled", list));
        }

        if (name == "add_record" && !argString(args, "script").empty()) {
            auto script = needScript();
            if (!script) return fail("script must be at most 64 KiB");
            const std::string description = argString(args, "description");
            if (description.empty()) return fail("description is required");
            // An enabled script already passed its dry run, and its assert() would
            // now see the patched code; check only its structure.
            const bool enabled = std::any_of(s.scripts.begin(), s.scripts.end(), [&](const auto& a) { return a.script == *script; });
            if (enabled) {
                if (auto checked = s.assembler.check(*script); !checked.success) return fail("script error: " + checked.error);
            } else if (auto checked = s.dryRun(*script); !checked.ok) {
                return fail(checked.error);
            }
            State::Record record;
            record.entry.id = static_cast<int>(s.records.size()) + 1;
            record.entry.description = description;
            record.entry.autoAsmScript = *script;
            s.records.push_back(record);
            return ok(Value::object().set("index", Value::number(static_cast<uint64_t>(s.records.size() - 1)))
                                     .set("kind", Value::string("script")));
        }

        if (name == "add_record") {
            auto address = needAddress();
            if (!address) return fail("cannot resolve address '" + argString(args, "address") + "'");
            auto type = needType();
            if (!type) return fail("type must be one of byte, i16, i32, i64, float, double, string, aob");
            const std::string description = argString(args, "description");
            if (description.empty()) return fail("description is required");
            State::Record record;
            record.entry.id = static_cast<int>(s.records.size()) + 1;
            record.entry.description = description;
            record.entry.address = *address;
            record.entry.type = *type;
            const std::string text = argString(args, "address");
            if (text.find('[') != std::string::npos) {
                record.expression = text;   // a pointer path: follow it on every use
                record.entry.addressString = text;
            } else {
                // Module-relative addresses keep working after the game restarts (ASLR).
                const std::string where = s.location(*address);
                record.entry.addressString = where.empty() ? hex(*address) : where;
            }
            if (*type == ValueType::String || *type == ValueType::ByteArray) record.entry.length = 32;
            s.records.push_back(record);
            Value out = Value::object().set("index", Value::number(static_cast<uint64_t>(s.records.size() - 1)))
                                       .set("address", Value::string(record.entry.addressString))
                                       .set("value", Value::string(s.readValue(*address, *type)));
            if (!record.expression.empty()) out.set("follows_pointer", Value::boolean(true));
            return ok(out);
        }

        if (name == "list_records") {
            Value list = Value::array();
            for (size_t i = 0; i < s.records.size(); ++i) {
                auto& r = s.records[i];
                if (!r.entry.autoAsmScript.empty()) {
                    list.push(Value::object().set("index", Value::number(static_cast<uint64_t>(i)))
                                             .set("description", Value::string(r.entry.description))
                                             .set("kind", Value::string("script")));
                    continue;
                }
                const bool resolved = s.refresh(r);
                Value item = Value::object().set("index", Value::number(static_cast<uint64_t>(i)))
                    .set("description", Value::string(r.entry.description))
                    .set("address", Value::string(r.entry.addressString))
                    .set("type", Value::string(valueTypeName(r.entry.type)))
                    .set("value", Value::string(resolved ? s.readValue(r.entry.address, r.entry.type) : "?"))
                    .set("frozen", Value::boolean(r.frozen));
                if (!r.expression.empty()) item.set("points_to", Value::string(resolved ? hex(r.entry.address) : "unresolved"));
                if (r.frozen) item.set("frozen_value", Value::string(r.frozenValue));
                list.push(std::move(item));
            }
            return ok(Value::object().set("records", list));
        }

        if (name == "set_frozen") {
            auto index = args.getInt("index");
            auto frozen = args.getBool("frozen");
            if (!index || *index < 0 || static_cast<size_t>(*index) >= s.records.size())
                return fail("index must be a record index from list_records");
            if (!frozen) return fail("frozen must be true or false");
            auto& r = s.records[static_cast<size_t>(*index)];
            if (!r.entry.autoAsmScript.empty()) return fail("that record is a script; use aa_enable and aa_disable");
            if (!s.refresh(r)) return fail("the record's pointer path does not lead anywhere right now");
            if (*frozen) {
                if (!s.options.allowWrites)
                    return fail("freezing writes to the game; the user must start the server with --allow-writes");
                std::string value = argString(args, "value");
                if (value.empty()) value = s.readValue(r.entry.address, r.entry.type);
                if (value == "?") return fail("cannot read the current value to freeze");
                auto written = writeTypedValue(*s.process, r.entry.address, r.entry.type, value,
                                               s.ioOptions(r.entry.address, r.entry.type, value.size()));
                if (!written) return fail("write failed: " + written.error());
                r.frozenValue = value;
            }
            r.frozen = *frozen;
            return ok(Value::object().set("index", Value::number(*index)).set("frozen", Value::boolean(r.frozen))
                                     .set("value", Value::string(s.readValue(r.entry.address, r.entry.type))));
        }

        if (name == "save_table") {
            const std::string path = argString(args, "path");
            std::string extension = std::filesystem::path(path).extension().string();
            std::transform(extension.begin(), extension.end(), extension.begin(), [](unsigned char c) { return std::tolower(c); });
            if (extension != ".ct" && extension != ".json") return fail("path must end in .CT or .json");
            if (s.records.empty()) return fail("the table is empty; add_record first");
            if (std::filesystem::exists(path) && !args.getBool("overwrite").value_or(false))
                return fail("file exists; pass overwrite true to replace it");
            CheatTable table;
            table.gameName = s.processName;
            table.comment = "Created with Cheat Engine for Linux by an AI agent.";
            table.entries = s.entries();
            const bool saved = extension == ".ct" ? table.save(path) : table.saveJson(path);
            if (!saved) return fail("could not write " + path);
            return ok(Value::object().set("saved", Value::string(std::filesystem::absolute(path).string()))
                                     .set("records", Value::number(static_cast<uint64_t>(s.records.size()))));
        }
    } catch (const std::exception& error) {
        return fail(std::string(name) + " failed: " + error.what());
    }
    return fail("unknown tool '" + name + "'");
}

} // namespace ce
