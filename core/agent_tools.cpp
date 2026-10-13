#include "core/agent_tools.hpp"

#include "arch/disassembler.hpp"
#include "arch/target_arch.hpp"
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
#include "symbols/elf_symbols.hpp"

#include <algorithm>
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
    return std::nullopt;
}

bool comparisonTakesValue(ScanCompare c) {
    return c == ScanCompare::Exact || c == ScanCompare::Greater || c == ScanCompare::Less || c == ScanCompare::Between;
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

} // namespace

struct AgentSession::State {
    struct Record {
        CheatEntry entry;
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
                if (r.frozen)
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
    }
    state_->wake.notify_all();
    if (state_->freezer.joinable()) state_->freezer.join();
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
         schema({{"compare", enumProp({"exact", "greater", "less", "between", "changed", "unchanged", "increased", "decreased", "same_as_first"}, "How the value changed (default exact)")},
                 {"value", prop("string", "The new value, for exact/greater/less/between")},
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
        {"add_record", "Add an address to the cheat table, with a description the user will recognize.",
         schema({{"address", address}, {"type", type}, {"description", prop("string", "What the value is, e.g. Health")}},
                {"address", "type", "description"})},
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
            s.process = std::move(process);
            s.pid = pid;
            s.modules = s.process->modules();
            s.symbols.reset();
            s.result.reset();
            s.undo.reset();
            if (!sameProcess) s.records.clear();
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
            const bool nextOnly = !comparisonTakesValue(*compare) && !firstOnly;
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
            // Module-relative addresses keep working after the game restarts (ASLR).
            const std::string where = s.location(*address);
            record.entry.addressString = where.empty() ? hex(*address) : where;
            if (*type == ValueType::String || *type == ValueType::ByteArray) record.entry.length = 32;
            s.records.push_back(record);
            return ok(Value::object().set("index", Value::number(static_cast<uint64_t>(s.records.size() - 1)))
                                     .set("address", Value::string(record.entry.addressString))
                                     .set("value", Value::string(s.readValue(*address, *type))));
        }

        if (name == "list_records") {
            Value list = Value::array();
            for (size_t i = 0; i < s.records.size(); ++i) {
                const auto& r = s.records[i];
                Value item = Value::object().set("index", Value::number(static_cast<uint64_t>(i)))
                    .set("description", Value::string(r.entry.description))
                    .set("address", Value::string(r.entry.addressString))
                    .set("type", Value::string(valueTypeName(r.entry.type)))
                    .set("value", Value::string(s.readValue(r.entry.address, r.entry.type)))
                    .set("frozen", Value::boolean(r.frozen));
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
            for (const auto& r : s.records) {
                CheatEntry entry = r.entry;
                entry.active = r.frozen;
                entry.value = r.frozen ? r.frozenValue : s.readValue(r.entry.address, r.entry.type);
                table.entries.push_back(std::move(entry));
            }
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
