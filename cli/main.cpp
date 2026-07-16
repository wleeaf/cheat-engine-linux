/// cescan — Cheat Engine CLI for Linux
/// Usage: sudo cescan <command> [args...]

#include "core/log.hpp"
#include <clocale>
#include "platform/linux/linux_process.hpp"
#include "platform/linux/ptrace_wrapper.hpp"
#include "scanner/memory_scanner.hpp"
#include "arch/disassembler.hpp"
#include "arch/assembler.hpp"
#include "core/autoasm.hpp"
#include "symbols/elf_symbols.hpp"
#include "scanner/pointer_scanner.hpp"
#include "scripting/lua_engine.hpp"
#include "core/simple_address_list.hpp"
#include "analysis/il2cpp_metadata.hpp"
#include "analysis/il2cpp_binary.hpp"
#include "analysis/signature.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cerrno>
#include <climits>
#include <string>
#include <algorithm>
#include <getopt.h>
#include <unistd.h>

using namespace ce;
using namespace ce::os;

// ── Helpers ──

static void usage() {
    fprintf(stderr,
        "cescan — Cheat Engine CLI for Linux\n"
        "\n"
        "Usage: sudo cescan <command> [args...]\n"
        "\n"
        "Commands:\n"
        "  list                          List all processes\n"
        "  scan <pid> [options]          Scan process memory\n"
        "  read <pid> <addr> [size]      Read memory (default 64 bytes)\n"
        "  write <pid> <addr> <val>      Write value to address\n"
        "  disasm <pid> <addr> [count]   Disassemble instructions\n"
        "  modules <pid>                 List loaded modules\n"
        "  regions <pid>                 List memory regions\n"
        "  lua <script.lua>|-e <code>|-  Run a Lua script (same API as the GUI console)\n"
        "  lua                           Interactive Lua REPL\n"
        "  il2cpp <global-metadata.dat>  Browse a Unity IL2CPP metadata file's classes/fields (offline)\n"
        "  signature <pid> <addr> [max]  Generate a unique AOB signature for a code address\n"
        "\n"
        "Scan options:\n"
        "  --type <type>     byte, i16, i32, i64, pointer, float, double, string, unicode, aob, binary, all, grouped, custom (default: i32)\n"
        "  --value <val>     Value to search for\n"
        "  --value2 <val>    Second value (for 'between')\n"
        "  --encoding <enc>  String encoding/codepage for --type string (e.g. UTF-8, ISO-8859-1, CP1252)\n"
        "  --value-size <n>  Custom value byte size (for --type custom, default: 4)\n"
        "                    grouped --value format: type:value@offset;type:value@offset\n"
        "                    custom --value must be a Lua chunk returning true/false\n"
        "  --compare <cmp>   exact, greater, less, between, changed,\n"
        "                    unchanged, increased, decreased, unknown, samefirst\n"
        "  --previous <dir>  Previous scan result directory (for next scan)\n"
        "  --percent <pct>   Percentage threshold for next-scan compare\n"
        "  --percent2 <pct>  Upper bound for percentage 'between'\n"
        "  --rounding <mode> Float exact mode: exact, rounded, truncated, extreme\n"
        "  --tolerance <n>   Override tolerance for extreme float matching\n"
        "  --align <n>       Scan alignment (default: 4)\n"
        "  --writable        Only scan writable memory\n"
        "\n"
        "Write options:\n"
        "  --type <type>     byte, i16, i32, i64, pointer, float, double (default: i32)\n"
    );
}

// Parse a non-negative decimal/hex integer token, validating the whole token
// and rejecting negatives, overflow, and trailing garbage. Bounds to [0, maxVal].
// Errors out (matching parseType/parseCompare idiom) so callers stay simple.
static unsigned long long parseUInt(const char* s, const char* what,
                                    unsigned long long maxVal) {
    if (!s || *s == '\0') {
        fprintf(stderr, "Missing %s argument\n", what);
        exit(1);
    }
    // strtoull silently negates a leading '-' into a huge value; reject it.
    const char* p = s;
    while (*p == ' ' || *p == '\t') ++p;
    if (*p == '-') {
        fprintf(stderr, "Invalid %s '%s': must not be negative\n", what, s);
        exit(1);
    }
    errno = 0;
    char* end = nullptr;
    unsigned long long v = strtoull(s, &end, 0);
    if (end == s || *end != '\0') {
        fprintf(stderr, "Invalid %s '%s': not a number\n", what, s);
        exit(1);
    }
    if (errno == ERANGE || v > maxVal) {
        fprintf(stderr, "Invalid %s '%s': out of range (max %llu)\n", what, s, maxVal);
        exit(1);
    }
    return v;
}

// Parse a PID token: validate numeric and positive (PIDs are > 0).
static pid_t parsePid(const char* s) {
    unsigned long long v = parseUInt(s, "pid", static_cast<unsigned long long>(INT_MAX));
    if (v == 0) {
        fprintf(stderr, "Invalid pid '%s': must be positive\n", s);
        exit(1);
    }
    return static_cast<pid_t>(v);
}

static ValueType parseType(const char* s) {
    if (!strcmp(s, "byte"))   return ValueType::Byte;
    if (!strcmp(s, "i16"))    return ValueType::Int16;
    if (!strcmp(s, "i32"))    return ValueType::Int32;
    if (!strcmp(s, "i64"))    return ValueType::Int64;
    if (!strcmp(s, "pointer") || !strcmp(s, "ptr")) return ValueType::Pointer;
    if (!strcmp(s, "float"))  return ValueType::Float;
    if (!strcmp(s, "double")) return ValueType::Double;
    if (!strcmp(s, "string")) return ValueType::String;
    if (!strcmp(s, "unicode")) return ValueType::UnicodeString;
    if (!strcmp(s, "aob"))    return ValueType::ByteArray;
    if (!strcmp(s, "binary")) return ValueType::Binary;
    if (!strcmp(s, "all"))    return ValueType::All;
    if (!strcmp(s, "grouped") || !strcmp(s, "group")) return ValueType::Grouped;
    if (!strcmp(s, "custom")) return ValueType::Custom;
    fprintf(stderr, "Unknown type: %s\n", s);
    exit(1);
}

static ScanCompare parseCompare(const char* s) {
    if (!strcmp(s, "exact"))     return ScanCompare::Exact;
    if (!strcmp(s, "greater"))   return ScanCompare::Greater;
    if (!strcmp(s, "less"))      return ScanCompare::Less;
    if (!strcmp(s, "between"))   return ScanCompare::Between;
    if (!strcmp(s, "changed"))   return ScanCompare::Changed;
    if (!strcmp(s, "unchanged")) return ScanCompare::Unchanged;
    if (!strcmp(s, "increased")) return ScanCompare::Increased;
    if (!strcmp(s, "decreased")) return ScanCompare::Decreased;
    if (!strcmp(s, "unknown"))   return ScanCompare::Unknown;
    if (!strcmp(s, "samefirst") || !strcmp(s, "same-as-first") || !strcmp(s, "sameasfirst"))
        return ScanCompare::SameAsFirst;
    fprintf(stderr, "Unknown compare: %s\n", s);
    exit(1);
}

static int parseRounding(const char* s) {
    if (!strcmp(s, "exact")) return 0;
    if (!strcmp(s, "rounded")) return 1;
    if (!strcmp(s, "truncated")) return 2;
    if (!strcmp(s, "extreme")) return 3;
    return 0;
}

static size_t typeSize(ValueType vt) {
    switch (vt) {
        case ValueType::Byte:   return 1;
        case ValueType::Int16:  return 2;
        case ValueType::Int32:  return 4;
        case ValueType::Int64:  return 8;
        case ValueType::Pointer: return sizeof(uintptr_t);
        case ValueType::Float:  return 4;
        case ValueType::Double: return 8;
        default: return 4;
    }
}

// ── Commands ──

static int cmd_list() {
    LinuxProcessEnumerator enumerator;
    auto procs = enumerator.list();
    printf("%-8s  %s\n", "PID", "NAME");
    for (auto& p : procs)
        printf("%-8d  %s\n", p.pid, p.name.c_str());
    printf("\n%zu processes\n", procs.size());
    return 0;
}

static int cmd_regions(pid_t pid) {
    LinuxProcessHandle proc(pid);
    auto regions = proc.queryRegions();
    printf("%-18s  %-18s  %10s  %-4s  %s\n", "START", "END", "SIZE", "PERM", "PATH");
    size_t totalReadable = 0;
    for (auto& r : regions) {
        char perms[4] = "---";
        if (r.protection & MemProt::Read)  perms[0] = 'r';
        if (r.protection & MemProt::Write) perms[1] = 'w';
        if (r.protection & MemProt::Exec)  perms[2] = 'x';
        printf("%018lx  %018lx  %10zu  %s   %s\n",
            r.base, r.base + r.size, r.size, perms, r.path.c_str());
        if (r.protection & MemProt::Read) totalReadable += r.size;
    }
    printf("\n%zu regions, %zu bytes (%.1f MB) readable\n",
        regions.size(), totalReadable, totalReadable / 1048576.0);
    return 0;
}

static int cmd_modules(pid_t pid) {
    LinuxProcessHandle proc(pid);
    auto mods = proc.modules();
    printf("%-18s  %10s  %s\n", "BASE", "SIZE", "NAME");
    for (auto& m : mods)
        printf("%018lx  %10zu  %s\n", m.base, m.size, m.name.c_str());
    printf("\n%zu modules\n", mods.size());
    return 0;
}

static int cmd_read(pid_t pid, uintptr_t addr, size_t size) {
    LinuxProcessHandle proc(pid);
    std::vector<uint8_t> buf(size);
    auto r = proc.read(addr, buf.data(), size);
    if (!r) {
        fprintf(stderr, "Read failed: %s\n", r.error().message().c_str());
        return 1;
    }
    size_t n = *r;
    for (size_t i = 0; i < n; i += 16) {
        printf("%018lx  ", addr + i);
        for (size_t j = 0; j < 16 && i + j < n; ++j)
            printf("%02x ", buf[i + j]);
        for (size_t j = n - i; j < 16; ++j)
            printf("   ");
        printf(" ");
        for (size_t j = 0; j < 16 && i + j < n; ++j) {
            uint8_t c = buf[i + j];
            printf("%c", (c >= 32 && c < 127) ? c : '.');
        }
        printf("\n");
    }
    return 0;
}

// Parse a signed integer token for cmd_write, accepting either the signed or
// unsigned range for the destination width (CE-style leniency). Errors out on
// non-numeric input or values that don't fit the width.
static int64_t parseWriteInt(const char* s, int64_t signedMin, uint64_t unsignedMax) {
    if (!s || *s == '\0') {
        fprintf(stderr, "Invalid write value: empty\n");
        exit(1);
    }
    errno = 0;
    char* end = nullptr;
    // Try signed first; if it ranges out, accept the unsigned form (e.g. 0xFF for a byte).
    long long sv = strtoll(s, &end, 0);
    if (end != s && *end == '\0' && errno != ERANGE
        && sv >= signedMin && sv <= static_cast<long long>(unsignedMax)) {
        return static_cast<int64_t>(sv);
    }
    errno = 0;
    end = nullptr;
    unsigned long long uv = strtoull(s, &end, 0);
    const char* p = s;
    while (*p == ' ' || *p == '\t') ++p;
    if (*p != '-' && end != s && *end == '\0' && errno != ERANGE && uv <= unsignedMax) {
        return static_cast<int64_t>(uv);
    }
    fprintf(stderr, "Invalid write value '%s': not a number or out of range\n", s);
    exit(1);
}

static int cmd_write(pid_t pid, uintptr_t addr, const char* valStr, ValueType vt) {
    LinuxProcessHandle proc(pid);
    uint8_t buf[8] = {};
    size_t sz = typeSize(vt);

    switch (vt) {
        case ValueType::Byte:   { uint8_t  v = (uint8_t) parseWriteInt(valStr, INT8_MIN,  UINT8_MAX);  memcpy(buf, &v, 1); break; }
        case ValueType::Int16:  { int16_t  v = (int16_t)parseWriteInt(valStr, INT16_MIN, UINT16_MAX); memcpy(buf, &v, 2); break; }
        case ValueType::Int32:  { int32_t  v = (int32_t)parseWriteInt(valStr, INT32_MIN, UINT32_MAX); memcpy(buf, &v, 4); break; }
        case ValueType::Int64:  { int64_t v = atoll(valStr); memcpy(buf, &v, 8); break; }
        case ValueType::Pointer:{ uintptr_t v = strtoull(valStr, nullptr, 0); memcpy(buf, &v, sizeof(v)); break; }
        case ValueType::Float:  { float v = atof(valStr); memcpy(buf, &v, 4); break; }
        case ValueType::Double: { double v = atof(valStr); memcpy(buf, &v, 8); break; }
        default:
            // String/Unicode/ByteArray/Binary/All/Grouped/Custom are not supported
            // here; refuse rather than silently writing zero bytes and reporting success.
            fprintf(stderr, "write: unsupported --type for this command "
                            "(use byte, i16, i32, i64, pointer, float, double)\n");
            return 1;
    }

    auto r = proc.write(addr, buf, sz);
    if (!r) {
        fprintf(stderr, "Write failed: %s\n", r.error().message().c_str());
        return 1;
    }
    printf("Wrote %zu bytes to 0x%lx\n", sz, addr);
    return 0;
}

static int cmd_disasm(pid_t pid, uintptr_t addr, size_t count) {
    LinuxProcessHandle proc(pid);

    // Load symbols for annotation
    SymbolResolver resolver;
    resolver.loadProcess(proc);

    std::vector<uint8_t> buf(count * 15);
    auto r = proc.read(addr, buf.data(), buf.size());
    if (!r) {
        fprintf(stderr, "Read failed: %s\n", r.error().message().c_str());
        return 1;
    }

    Disassembler dis(Arch::X86_64);
    auto insns = dis.disassemble(addr, {buf.data(), *r}, count);
    for (auto& i : insns) {
        // Resolve the instruction address itself
        auto addrSym = resolver.resolve(i.address);
        if (!addrSym.empty())
            printf("  ; %s\n", addrSym.c_str());
        printf("%s\n", i.toString().c_str());
    }
    printf("\n%zu instructions\n", insns.size());
    return 0;
}

static int cmd_scan(pid_t pid, int argc, char** argv) {
    ScanConfig config;
    config.valueType = ValueType::Int32;
    config.compareType = ScanCompare::Exact;
    config.alignment = 4;
    const char* previousDir = nullptr;
    const char* valueStr = nullptr;
    const char* value2Str = nullptr;
    const char* percentStr = nullptr;
    const char* percent2Str = nullptr;
    const char* roundingStr = nullptr;
    const char* toleranceStr = nullptr;
    const char* valueSizeStr = nullptr;
    const char* encodingStr = nullptr;

    static struct option long_opts[] = {
        {"type",     required_argument, nullptr, 't'},
        {"value",    required_argument, nullptr, 'v'},
        {"value2",   required_argument, nullptr, '2'},
        {"encoding", required_argument, nullptr, 'e'},
        {"value-size", required_argument, nullptr, 's'},
        {"compare",  required_argument, nullptr, 'c'},
        {"previous", required_argument, nullptr, 'p'},
        {"percent",  required_argument, nullptr, 'P'},
        {"percent2", required_argument, nullptr, 'q'},
        {"rounding", required_argument, nullptr, 'r'},
        {"tolerance", required_argument, nullptr, 'T'},
        {"align",    required_argument, nullptr, 'a'},
        {"writable", no_argument,       nullptr, 'w'},
        {nullptr, 0, nullptr, 0}
    };

    optind = 1; // reset getopt
    int opt;
    while ((opt = getopt_long(argc, argv, "t:v:2:e:s:c:p:P:q:r:T:a:w", long_opts, nullptr)) != -1) {
        switch (opt) {
            case 't': config.valueType = parseType(optarg); break;
            case 'v': valueStr = optarg; break;
            case '2': value2Str = optarg; break;
            case 'e': encodingStr = optarg; break;
            case 's': valueSizeStr = optarg; break;
            case 'c': config.compareType = parseCompare(optarg); break;
            case 'p': previousDir = optarg; break;
            case 'P': percentStr = optarg; break;
            case 'q': percent2Str = optarg; break;
            case 'r': roundingStr = optarg; break;
            case 'T': toleranceStr = optarg; break;
            case 'a': config.alignment = std::max<size_t>(1,
                          static_cast<size_t>(parseUInt(optarg, "alignment", SIZE_MAX))); break;
            case 'w': config.scanWritableOnly = true; break;
        }
    }

    if (valueSizeStr)
        config.customValueSize = std::max<size_t>(1, strtoull(valueSizeStr, nullptr, 0));
    if (encodingStr)
        config.stringEncoding = encodingStr;

    if (valueStr) {
        if (config.valueType == ValueType::String || config.valueType == ValueType::UnicodeString) {
            config.stringValue = valueStr;
            config.alignment = 1;
        } else if (config.valueType == ValueType::ByteArray) {
            config.parseAOB(valueStr);
            config.alignment = 1;
        } else if (config.valueType == ValueType::Binary) {
            config.parseBinary(valueStr);
            config.alignment = 1;
        } else if (config.valueType == ValueType::Float || config.valueType == ValueType::Double) {
            config.floatValue = atof(valueStr);
            if (value2Str) config.floatValue2 = atof(value2Str);
        } else if (config.valueType == ValueType::Pointer) {
            config.intValue = static_cast<int64_t>(strtoull(valueStr, nullptr, 0));
            if (value2Str) config.intValue2 = static_cast<int64_t>(strtoull(value2Str, nullptr, 0));
        } else if (config.valueType == ValueType::All) {
            config.intValue = atoll(valueStr);
            config.floatValue = atof(valueStr);
            if (value2Str) {
                config.intValue2 = atoll(value2Str);
                config.floatValue2 = atof(value2Str);
            }
        } else if (config.valueType == ValueType::Grouped) {
            std::string error;
            if (!config.parseGrouped(valueStr, &error)) {
                fprintf(stderr, "Invalid grouped expression: %s\n", error.c_str());
                return 1;
            }
        } else if (config.valueType == ValueType::Custom) {
            config.customFormula = valueStr;
            if (config.compareType == ScanCompare::Exact && config.customFormula.empty()) {
                fprintf(stderr, "Custom scan with exact compare requires a Lua formula in --value\n");
                return 1;
            }
        } else {
            config.intValue = atoll(valueStr);
            if (value2Str) config.intValue2 = atoll(value2Str);
        }
    } else if (config.valueType == ValueType::Grouped) {
        fprintf(stderr, "Grouped scan requires --value expression\n");
        return 1;
    } else if (config.valueType == ValueType::Custom && config.compareType == ScanCompare::Exact) {
        fprintf(stderr, "Custom exact scan requires --value Lua formula\n");
        return 1;
    }

    if (percentStr) {
        config.percentageScan = true;
        config.percentageValue = atof(percentStr);
        config.percentageValue2 = percent2Str ? atof(percent2Str) : config.percentageValue;
    }
    if (roundingStr) config.roundingType = parseRounding(roundingStr);
    if (toleranceStr) config.floatTolerance = atof(toleranceStr);

    LinuxProcessHandle proc(pid);
    MemoryScanner scanner;

    if (previousDir) {
        // Next scan
        ScanResult previous{std::filesystem::path(previousDir)};
        printf("Next scan on %zu previous results...\n", previous.count());
        auto result = scanner.nextScan(proc, config, previous);
        printf("Found: %zu results\n", result.count());
        printf("Results: %s\n", result.directory().c_str());

        size_t vs = typeSize(config.valueType);
        if (config.valueType == ValueType::Grouped)
            vs = std::max<size_t>(1, config.groupedValueSize());
        else if (config.valueType == ValueType::Custom)
            vs = std::max<size_t>(1, config.customValueSize);
        size_t show = std::min(result.count(), size_t(20));
        for (size_t i = 0; i < show; ++i) {
            uintptr_t addr = result.address(i);
            std::vector<uint8_t> val(vs);
            result.value(i, val.data(), vs);
            printf("  0x%lx = ", addr);
            switch (config.valueType) {
                case ValueType::Int32: { int32_t v; memcpy(&v, val.data(), 4); printf("%d", v); break; }
                case ValueType::Pointer: { uintptr_t v; memcpy(&v, val.data(), sizeof(v)); printf("0x%lx", v); break; }
                case ValueType::Float: { float v; memcpy(&v, val.data(), 4); printf("%f", v); break; }
                default: {
                    for (size_t j = 0; j < vs; ++j) printf("%02x", val[j]);
                }
            }
            printf("\n");
        }
        if (result.count() > 20) printf("  ... and %zu more\n", result.count() - 20);
    } else {
        // First scan
        printf("Scanning PID %d...\n", pid);
        auto result = scanner.firstScan(proc, config);
        printf("Found: %zu results\n", result.count());
        printf("Results: %s\n", result.directory().c_str());

        size_t vs = typeSize(config.valueType);
        if (config.valueType == ValueType::Grouped)
            vs = std::max<size_t>(1, config.groupedValueSize());
        else if (config.valueType == ValueType::Custom)
            vs = std::max<size_t>(1, config.customValueSize);
        size_t show = std::min(result.count(), size_t(20));
        for (size_t i = 0; i < show; ++i) {
            uintptr_t addr = result.address(i);
            std::vector<uint8_t> val(vs);
            result.value(i, val.data(), vs);
            printf("  0x%lx = ", addr);
            switch (config.valueType) {
                case ValueType::Int32: { int32_t v; memcpy(&v, val.data(), 4); printf("%d", v); break; }
                case ValueType::Pointer: { uintptr_t v; memcpy(&v, val.data(), sizeof(v)); printf("0x%lx", v); break; }
                case ValueType::Float: { float v; memcpy(&v, val.data(), 4); printf("%f", v); break; }
                default: {
                    for (size_t j = 0; j < vs; ++j) printf("%02x", val[j]);
                }
            }
            printf("\n");
        }
        if (result.count() > 20) printf("  ... and %zu more\n", result.count() - 20);
    }
    return 0;
}

static int cmd_symbols(pid_t pid) {
    LinuxProcessHandle proc(pid);
    SymbolResolver resolver;
    resolver.loadProcess(proc);
    printf("%-18s  %-8s  %-30s  %s\n", "ADDRESS", "SIZE", "NAME", "MODULE");
    int shown = 0;
    for (auto& s : resolver.symbols()) {
        if (s.address == 0) continue;
        printf("%018lx  %8zu  %-30s  %s\n", s.address, s.size, s.name.c_str(), s.module.c_str());
        if (++shown >= 200) { printf("... and %zu more\n", resolver.count() - 200); break; }
    }
    printf("\n%zu symbols loaded\n", resolver.count());
    return 0;
}

static int cmd_pointerscan(pid_t pid, uintptr_t target, int depth, int maxOffset) {
    LinuxProcessHandle proc(pid);
    PointerScanner scanner;
    PointerScanConfig config;
    config.targetAddress = target;
    config.maxDepth = depth;
    config.maxOffset = maxOffset;

    printf("Pointer scan: PID %d, target 0x%lx, depth %d, offset %d\n", pid, target, depth, maxOffset);
    printf("Building reverse pointer map...\n");

    auto results = scanner.scan(proc, config);
    printf("Found %zu pointer paths:\n\n", results.size());

    for (size_t i = 0; i < std::min(results.size(), size_t(50)); ++i) {
        auto& p = results[i];
        auto current = PointerScanner::dereference(proc, p);
        printf("  %s", p.toString().c_str());
        if (current) printf("  -> 0x%lx", current);
        printf("\n");
    }
    if (results.size() > 50) printf("  ... and %zu more\n", results.size() - 50);
    return 0;
}

static int cmd_deref(pid_t pid, int argc, char** argv) {
    // cescan deref <pid> <module+offset> <off1> <off2> ...
    if (argc < 1) { fprintf(stderr, "Usage: cescan deref <pid> <module+offset> [off1] [off2] ...\n"); return 1; }

    LinuxProcessHandle proc(pid);
    PointerPath path;

    // Parse module+offset
    std::string base = argv[0];
    auto plus = base.find('+');
    if (plus != std::string::npos) {
        path.module = base.substr(0, plus);
        path.baseOffset = strtoul(base.substr(plus + 1).c_str(), nullptr, 16);
    } else {
        path.module = base;
        path.baseOffset = 0;
    }

    // Parse offsets
    for (int i = 1; i < argc; ++i)
        path.offsets.push_back((int32_t)strtol(argv[i], nullptr, 16));

    // Find module base
    auto modules = proc.modules();
    for (auto& m : modules) {
        if (m.name == path.module) { path.moduleBase = m.base; break; }
    }

    auto addr = PointerScanner::dereference(proc, path);
    printf("Path: %s\n", path.toString().c_str());
    printf("Result: 0x%lx\n", addr);
    return addr ? 0 : 1;
}

static int cmd_asm(pid_t pid, const char* scriptFile, bool disableMode) {
    // Read script
    std::ifstream f(scriptFile);
    if (!f) { fprintf(stderr, "Cannot open: %s\n", scriptFile); return 1; }
    std::string script((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

    LinuxProcessHandle proc(pid);
    AutoAssembler autoAsm;

    if (disableMode) {
        printf("Disable mode not supported from CLI (no saved state)\n");
        return 1;
    }

    printf("Executing script on PID %d...\n", pid);
    auto result = autoAsm.execute(proc, script);

    for (auto& msg : result.log)
        printf("  %s\n", msg.c_str());

    if (result.success) {
        printf("SUCCESS: %zu patches, %zu allocations\n",
            result.disableInfo.originals.size(), result.disableInfo.allocs.size());
    } else {
        printf("FAILED: %s\n", result.error.c_str());
        return 1;
    }
    return 0;
}

// ── Main ──

// Headless Lua runner: runs the SAME LuaEngine the GUI's Lua console uses, so
// everything the Lua API can do (open process, scan, read/write, address list,
// auto-assemble, breakpoints, speedhack, ...) is scriptable and testable from the
// terminal. Scripts open their target with openProcess(pid) themselves.
//   cescan lua <script.lua>     run a file
//   cescan lua -e "<code>"      run a one-liner
//   cescan lua -                run a script from stdin
//   cescan lua                  interactive REPL
static int cmd_lua(int argc, char** argv) {
    // Declare the list + resolver BEFORE the engine so they outlive its teardown.
    SimpleAddressList addressList;
    SymbolResolver resolver;
    LuaEngine engine;
    engine.setAddressList(&addressList);
    engine.setResolver(&resolver);
    // print()/output arrives one message per call without a trailing newline
    // (the GUI console adds line breaks itself); terminate each line here.
    engine.setOutputCallback([](const std::string& s) {
        std::fputs(s.c_str(), stdout);
        std::fputc('\n', stdout);
    });

    auto report = [](const std::string& err) -> int {
        if (!err.empty()) { std::fprintf(stderr, "lua: %s\n", err.c_str()); return 1; }
        return 0;
    };

    // argv here is offset so argv[0] == "lua".
    if (argc >= 2 && !std::strcmp(argv[1], "-e")) {
        if (argc < 3) { std::fprintf(stderr, "cescan lua -e needs a code string\n"); return 1; }
        return report(engine.execute(argv[2]));
    }
    if (argc >= 2 && std::strcmp(argv[1], "-") != 0) {
        return report(engine.executeFile(argv[1]));       // script file
    }
    if (argc >= 2 && !std::strcmp(argv[1], "-")) {
        std::string code((std::istreambuf_iterator<char>(std::cin)),
                         std::istreambuf_iterator<char>());
        return report(engine.execute(code));              // stdin as a script
    }

    // Interactive REPL: try each line as an expression (so `getCEVersion()` prints
    // its value), falling back to a statement (`x = 5`).
    std::fprintf(stderr, "cescan lua REPL — Ctrl+D to exit\n");
    std::string line;
    while (true) {
        std::fputs("lua> ", stderr);
        if (!std::getline(std::cin, line)) { std::fputs("\n", stderr); break; }
        if (line.empty()) continue;
        auto val = engine.evalToString("return " + line);
        if (val) {
            if (!val->empty()) std::printf("%s\n", val->c_str());
        } else {
            std::string err = engine.execute(line);
            if (!err.empty()) std::fprintf(stderr, "error: %s\n", err.c_str());
        }
    }
    return 0;
}

// Offline browse of a Unity IL2CPP `global-metadata.dat`: recovers the class
// layout (assembly image -> class namespace.name -> field names) without a live
// process. Field byte OFFSETS and field TYPE names are not in the metadata (they
// live in GameAssembly.so), so this lists names/grouping only. Doubles as the
// harness for validating the version-specific table layout against a real file.
// Try to find the GameAssembly binary next to a metadata file. Layout:
// <Game>/GameAssembly.{so,dll} with metadata at <Game>/<X>_Data/il2cpp_data/
// Metadata/global-metadata.dat, so the game root is three parents up.
static std::string autoLocateGameAssembly(const std::string& metaPath) {
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::path root = fs::path(metaPath).parent_path().parent_path().parent_path().parent_path();
    for (const char* n : {"GameAssembly.so", "GameAssembly.dll", "libil2cpp.so"}) {
        fs::path c = root / n;
        if (fs::is_regular_file(c, ec)) return c.string();
    }
    return {};
}

static int cmd_il2cpp(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: cescan il2cpp <global-metadata.dat> [--class <substr>] "
                        "[--fields] [--methods] [--binary <GameAssembly>]\n");
        return 1;
    }
    const char* path = argv[1];
    std::string filter, binaryPath;
    bool showFields = false, showMethods = false;
    for (int i = 2; i < argc; ++i) {
        if (!strcmp(argv[i], "--class") && i + 1 < argc) filter = argv[++i];
        else if (!strcmp(argv[i], "--fields")) showFields = true;
        else if (!strcmp(argv[i], "--methods")) showMethods = true;
        else if (!strcmp(argv[i], "--binary") && i + 1 < argc) binaryPath = argv[++i];
    }

    std::ifstream in(path, std::ios::binary);
    if (!in) { fprintf(stderr, "cescan il2cpp: cannot open %s\n", path); return 1; }
    std::vector<uint8_t> buf((std::istreambuf_iterator<char>(in)),
                             std::istreambuf_iterator<char>());
    if (!isIl2CppMetadata(buf.data(), buf.size())) {
        fprintf(stderr, "cescan il2cpp: %s is not a global-metadata.dat (bad magic)\n", path);
        return 1;
    }
    auto md = parseIl2CppMetadata(buf.data(), buf.size());
    if (!md) { fprintf(stderr, "cescan il2cpp: failed to parse %s\n", path); return 1; }

    printf("global-metadata.dat: version %d, %zu names, %zu string literals\n",
           md->version, md->strings.size(), md->stringLiterals.size());
    if (!md->tablesDecoded) {
        printf("type/field tables: not decoded (metadata version %d has no known layout here;\n"
               "supported: 27-31). The names above are still available.\n", md->version);
        if (md->version > 31)
            printf("note: version %d is newer than this build knows; even the names may be "
                   "unreliable (the header layout can differ).\n", md->version);
        return 0;
    }

    printf("type/field tables: %zu types across %zu images\n",
           md->types.size(), md->images.size());

    // Resolve field byte offsets from the GameAssembly binary if we can find one.
    if (binaryPath.empty()) binaryPath = autoLocateGameAssembly(path);
    ce::Il2CppBinaryLayout layout;
    if (!binaryPath.empty()) {
        layout = ce::resolveIl2CppLayout(*md, binaryPath);
        if (layout.ok)
            printf("field offsets: resolved from %s\n", binaryPath.c_str());
        else
            printf("field offsets: unavailable (%s)\n", layout.error.c_str());
    } else {
        printf("field offsets: no GameAssembly binary found (pass --binary <path>)\n");
    }
    const bool haveOffsets = layout.ok && layout.classes.size() == md->types.size();

    printf("\nclasses%s%s:\n",
           filter.empty() ? " (add --class <substr> to filter, --fields to list fields)" : "",
           haveOffsets ? "" : " (offsets need the GameAssembly binary)");
    size_t matched = 0, printed = 0;
    const size_t kCap = 200;
    for (size_t ti = 0; ti < md->types.size(); ++ti) {
        const auto& t = md->types[ti];
        std::string full = t.fullName();
        if (!filter.empty() && full.find(filter) == std::string::npos) continue;
        ++matched;
        if (printed >= kCap) continue;
        printf("  %s  (%zu fields)\n", full.c_str(), t.fields.size());
        if (showFields) {
            for (size_t fi = 0; fi < t.fields.size(); ++fi) {
                if (haveOffsets) {
                    const auto& rf = layout.classes[ti].fields[fi];
                    const char* kind = rf.isConst ? "const" : (rf.isStatic ? "static" : "");
                    printf("      +0x%-5x %-26s %s\n", rf.offset, rf.name.c_str(), kind);
                } else {
                    printf("      %s\n", t.fields[fi].name.c_str());
                }
            }
        }
        // Methods (resolved from the binary in the same pass as field offsets).
        if (showMethods && haveOffsets) {
            const auto& methods = layout.classes[ti].methods;
            for (const auto& m : methods)
                printf("      method +0x%-8lx %s\n", (unsigned long)m.rva, m.name.c_str());
            if (methods.empty())
                printf("      (no methods with a compiled body)\n");
        }
        ++printed;
    }
    if (matched > printed)
        printf("  ... %zu more (narrow with --class <substr>)\n", matched - printed);
    printf("(%zu matching class%s)\n", matched, matched == 1 ? "" : "es");
    return 0;
}

// Generate a unique AOB signature for a code address (portable across restarts).
static int cmd_signature(pid_t pid, uintptr_t addr, size_t maxBytes) {
    LinuxProcessHandle proc(pid);
    auto sig = ce::makeSignature(proc, addr, maxBytes);
    if (sig.pattern.empty()) {
        fprintf(stderr, "cescan signature: cannot build one at 0x%lx (unreadable/out of range)\n",
                (unsigned long)addr);
        return 1;
    }
    printf("%s\n", sig.pattern.c_str());
    fprintf(stderr, "# %zu bytes, %s\n", sig.length,
            sig.unique ? "unique in module" : "NOT unique within maxbytes (raise it)");
    return 0;
}

int main(int argc, char** argv) {
    // Force the C locale so atof()/strtod() on scan values always use a '.'
    // decimal separator. cescan never calls setlocale(LC_ALL, "") so it is in the
    // C locale already, but pin it explicitly: this environment runs
    // LC_NUMERIC=tr_TR.UTF-8 (comma decimal), and a future dependency that
    // activates the environment locale would otherwise silently parse "3.14" as 3.
    std::setlocale(LC_ALL, "C");

    // Diagnostics: `CE_LOG=debug cescan …` (or per-category `CE_LOG=ptrace:trace`)
    // and `CE_LOG_FILE=/path` turn on cecore's logging with no rebuild.
    ce::log::initFromEnv();

    if (argc < 2) { usage(); return 1; }

    const char* cmd = argv[1];

    if (!strcmp(cmd, "--version") || !strcmp(cmd, "-v") || !strcmp(cmd, "version")) {
        printf("cescan (cheat-engine-linux) %s\n", CECORE_VERSION);
        return 0;
    }

    if (!strcmp(cmd, "list")) {
        return cmd_list();
    }
    else if (!strcmp(cmd, "regions") && argc >= 3) {
        return cmd_regions(parsePid(argv[2]));
    }
    else if (!strcmp(cmd, "modules") && argc >= 3) {
        return cmd_modules(parsePid(argv[2]));
    }
    else if (!strcmp(cmd, "symbols") && argc >= 3) {
        return cmd_symbols(parsePid(argv[2]));
    }
    else if (!strcmp(cmd, "read") && argc >= 4) {
        // Cap the requested size so an adversarial/typo'd argument can't trigger
        // an uncaught std::bad_alloc that terminates the process. 256 MB ceiling.
        constexpr unsigned long long kMaxReadSize = 256ull * 1024 * 1024;
        size_t size = (argc >= 5) ? static_cast<size_t>(parseUInt(argv[4], "read size", kMaxReadSize)) : 64;
        return cmd_read(parsePid(argv[2]), strtoul(argv[3], nullptr, 0), size);
    }
    else if (!strcmp(cmd, "write") && argc >= 5) {
        ValueType vt = ValueType::Int32;
        // Check for --type flag after the required args
        for (int i = 5; i < argc - 1; ++i)
            if (!strcmp(argv[i], "--type")) vt = parseType(argv[i+1]);
        return cmd_write(parsePid(argv[2]), strtoul(argv[3], nullptr, 0), argv[4], vt);
    }
    else if (!strcmp(cmd, "disasm") && argc >= 4) {
        // Bound count before the buffer's count*15 multiply (which would otherwise
        // overflow/throw on huge or negative input).
        constexpr unsigned long long kMaxDisasmCount = 100000;
        size_t count = (argc >= 5) ? static_cast<size_t>(parseUInt(argv[4], "disasm count", kMaxDisasmCount)) : 20;
        return cmd_disasm(parsePid(argv[2]), strtoul(argv[3], nullptr, 0), count);
    }
    else if (!strcmp(cmd, "scan") && argc >= 3) {
        pid_t pid = parsePid(argv[2]);
        return cmd_scan(pid, argc - 2, argv + 2);
    }
    else if (!strcmp(cmd, "pointerscan") && argc >= 4) {
        pid_t pid = parsePid(argv[2]);
        uintptr_t target = strtoul(argv[3], nullptr, 0);
        int depth = (argc >= 5) ? static_cast<int>(parseUInt(argv[4], "depth", 64)) : 4;
        int offset = (argc >= 6) ? static_cast<int>(parseUInt(argv[5], "offset", INT_MAX)) : 2048;
        return cmd_pointerscan(pid, target, depth, offset);
    }
    else if (!strcmp(cmd, "deref") && argc >= 4) {
        return cmd_deref(parsePid(argv[2]), argc - 3, argv + 3);
    }
    else if (!strcmp(cmd, "asm") && argc >= 4) {
        bool disable = false;
        const char* file = argv[3];
        if (argc >= 5 && !strcmp(argv[3], "--disable")) { disable = true; file = argv[4]; }
        return cmd_asm(parsePid(argv[2]), file, disable);
    }
    else if (!strcmp(cmd, "lua")) {
        return cmd_lua(argc - 1, argv + 1);
    }
    else if (!strcmp(cmd, "il2cpp") && argc >= 3) {
        return cmd_il2cpp(argc - 1, argv + 1);
    }
    else if (!strcmp(cmd, "signature") && argc >= 4) {
        size_t maxBytes = (argc >= 5) ? (size_t)parseUInt(argv[4], "maxbytes", 1024) : 64;
        return cmd_signature(parsePid(argv[2]), strtoul(argv[3], nullptr, 0), maxBytes);
    }
    else if (!strcmp(cmd, "help") || !strcmp(cmd, "--help") || !strcmp(cmd, "-h")) {
        usage();
        return 0;
    }
    else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        usage();
        return 1;
    }
}
