/// cescan: Cheat Engine CLI for Linux
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
#include "debug/code_finder.hpp"
#include "scripting/lua_engine.hpp"
#include "core/simple_address_list.hpp"
#include "core/types.hpp"   // ce::moduleOffsetString
#include "core/target_profile.hpp"
#include "core/guest_view.hpp"
#include "core/value_codec.hpp"
#include <type_traits>
#include <utility>
#include "analysis/il2cpp_metadata.hpp"
#include "analysis/il2cpp_binary.hpp"
#include "analysis/signature.hpp"
#include "analysis/code_analysis.hpp"
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
#include <csignal>
#include <ctime>
#include <vector>
#include <algorithm>
#include <getopt.h>
#include <unistd.h>

using namespace ce;
using namespace ce::os;

// ── Helpers ──

static void usage() {
    fprintf(stderr,
        "cescan: Cheat Engine CLI for Linux\n"
        "\n"
        "Usage: sudo cescan <command> [args...]\n"
        "\n"
        "Commands:\n"
        "  list                          List all processes\n"
        "  scan <pid> [options]          Scan process memory\n"
        "  read <pid> <addr> [size] [--type <t>] [--codec <c>]  Read memory: hex dump,\n"
        "                                or the interpreted value with --type (i32,\n"
        "                                float, pointer, string, ...); size caps a\n"
        "                                string read; --codec also shows the decoded value\n"
        "  write <pid> <addr> <val> [--type <t>] [--codec <c>] [--verify[-ms <n>]]\n"
        "        [--find-writer[-secs <s>]]  Write value to address (--codec writes the\n"
        "                                encoded form; --verify re-reads after n ms\n"
        "                                (default 200) to detect a protected/reverted\n"
        "                                value; --find-writer then finds what reverts it)\n"
        "  freeze <pid> <addr> <val> [--type <t>] [--codec <c>] [--interval <ms>]\n"
        "         [--mode normal|floor|ceil]  Lock a value: re-write it until Ctrl-C\n"
        "                                (floor = never let it drop, ceil = never rise;\n"
        "                                 --codec locks an obfuscated value by its value)\n"
        "  watch <pid> <addr> [--access] [--size <n>] [--duration <s>] [--mode hw|sw|st]\n"
        "                                Find what writes (or --access: reads+writes) an\n"
        "                                address: lists the instructions that touch it.\n"
        "                                Wine-safe by default (main-thread hardware watch)\n"
        "  disasm <pid> <addr> [count]   Disassemble instructions\n"
        "  modules <pid>                 List loaded modules\n"
        "  regions <pid>                 List memory regions\n"
        "  info <pid>                    Probe the target: arch, Wine/emulator/runtime,\n"
        "                                sandbox, already-traced, and what that limits\n"
        "  guest-scan <pid> <value> [--type <t>] [--be] [--align <n>]\n"
        "                                Scan a recognized emulator's guest RAM for a\n"
        "                                value (--be byte-swaps for big-endian consoles)\n"
        "  guest-scan <pid> --unknown [--type <t>] [--be]\n"
        "                                Snapshot guest RAM for an unknown initial value\n"
        "  guest-scan <pid> [<value>] --next|--changed|--unchanged|--increased|--decreased\n"
        "                                Narrow the previous guest scan (--next needs a\n"
        "                                value; the comparisons do not)\n"
        "  guest-write <pid> <guest-addr> <value> [--type <t>] [--be]\n"
        "                                Write a value to a guest address (region/type\n"
        "                                reused from the last guest-scan)\n"
        "  lua <script.lua>|-e <code>|-  Run a Lua script (same API as the GUI console)\n"
        "  lua                           Interactive Lua REPL\n"
        "  il2cpp <global-metadata.dat>  Browse a Unity IL2CPP metadata file's classes/fields (offline)\n"
        "  signature <pid> <addr> [max]  Generate a unique AOB signature for a code address\n"
        "  analyze <pid> <what> [...]    Static RE toolkit: strings, statics, caves [min],\n"
        "                                functions, xrefs <addr>, asm \"<insn>\"  [--module <name>]\n"
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
        "  --codec <c>       Obfuscated value: search for the encoded form of --value.\n"
        "                    c = xor:0xKEY | add:N | rol:N | ror:N (exact integer scans).\n"
        "                    Pair with `write --codec` / `read --codec` to edit and verify.\n"
        "  --writable        Only scan writable memory (--no-writable for read-only)\n"
        "  --executable      Only scan executable memory (--no-executable to exclude code)\n"
        "\n"
        "Write options:\n"
        "  --type <type>     byte, i16, i32, i64, pointer, float, double,\n"
        "                    string (raw text), aob (\"90 90 05\" hex bytes) (default: i32)\n"
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

static int cmd_read(pid_t pid, uintptr_t addr, size_t size, const char* typeStr = nullptr,
                    ce::ValueCodec codec = {}) {
    LinuxProcessHandle proc(pid);

    // --type interprets the bytes instead of dumping hex. Fixed-width types read
    // their own size; string/aob use `size` as a length cap.
    if (typeStr) {
        ValueType vt = parseType(typeStr);
        size_t need;
        switch (vt) {
            case ValueType::Byte:                                        need = 1; break;
            case ValueType::Int16:                                       need = 2; break;
            case ValueType::Int32: case ValueType::Float:                need = 4; break;
            case ValueType::Int64: case ValueType::Double:
            case ValueType::Pointer:                                     need = 8; break;
            default:                                                     need = size; break;
        }
        std::vector<uint8_t> b(need ? need : 1);
        auto r = proc.read(addr, b.data(), b.size());
        if (!r) { fprintf(stderr, "Read failed: %s\n", r.error().message().c_str()); return 1; }
        size_t got = *r;
        if (need <= 8 && got < need) { fprintf(stderr, "Read failed: short read (%zu/%zu)\n", got, need); return 1; }
        printf("0x%lx: ", (unsigned long)addr);
        switch (vt) {
            case ValueType::Byte:   printf("%u (0x%02x)\n", b[0], b[0]); break;
            case ValueType::Int16:  { int16_t v;   memcpy(&v, b.data(), 2); printf("%d (0x%x)\n", v, (unsigned)(uint16_t)v); break; }
            case ValueType::Int32:  { int32_t v;   memcpy(&v, b.data(), 4); printf("%d (0x%x)\n", v, (unsigned)(uint32_t)v); break; }
            case ValueType::Int64:  { int64_t v;   memcpy(&v, b.data(), 8); printf("%ld (0x%lx)\n", (long)v, (unsigned long)(uint64_t)v); break; }
            case ValueType::Pointer:{ uintptr_t v; memcpy(&v, b.data(), 8); printf("0x%lx\n", (unsigned long)v); break; }
            case ValueType::Float:  { float v;     memcpy(&v, b.data(), 4); printf("%g\n", v); break; }
            case ValueType::Double: { double v;    memcpy(&v, b.data(), 8); printf("%g\n", v); break; }
            case ValueType::String: { size_t len = strnlen((char*)b.data(), got); printf("\"%.*s\"\n", (int)len, (char*)b.data()); break; }
            default:                { for (size_t i = 0; i < got; ++i) printf("%02X ", b[i]); printf("\n"); break; }
        }
        // Show the decoded logical value for an obfuscated integer.
        if (codec.active()) {
            int wbytes = 0;
            switch (vt) {
                case ValueType::Byte:    wbytes = 1; break;
                case ValueType::Int16:   wbytes = 2; break;
                case ValueType::Int32:   wbytes = 4; break;
                case ValueType::Int64:
                case ValueType::Pointer: wbytes = 8; break;
                default: break;
            }
            if (wbytes) {
                uint64_t raw = 0; memcpy(&raw, b.data(), wbytes);
                uint64_t logical = codec.decode(raw, wbytes);
                // Sign-extend for a readable signed display.
                int64_t s = (wbytes < 8 && (logical >> (wbytes * 8 - 1)) & 1)
                          ? (int64_t)(logical | ~ce::ValueCodec::maskFor(wbytes)) : (int64_t)logical;
                printf("  decoded (%s): %lld (0x%llx)\n", codec.describe().c_str(),
                       (long long)s, (unsigned long long)logical);
            } else {
                fprintf(stderr, "  (--codec applies to integer types only)\n");
            }
        }
        return 0;
    }

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

// Forward declaration: write --find-writer chains into find-what-writes after the write.
static int cmd_watch(pid_t pid, uintptr_t addr, bool writesOnly, int watchSize,
                     int durationSec, int modeOverride);

static int cmd_write(pid_t pid, uintptr_t addr, const char* valStr, ValueType vt,
                     ce::ValueCodec codec = {}, int verifyMs = 0, int findWriterSecs = 0) {
    LinuxProcessHandle proc(pid);

    if (codec.active() && vt != ValueType::Byte && vt != ValueType::Int16 &&
        vt != ValueType::Int32 && vt != ValueType::Int64 && vt != ValueType::Pointer) {
        fprintf(stderr, "write: --codec applies to integer types only "
                        "(byte/i16/i32/i64/pointer)\n");
        return 1;
    }

    // Variable-length writes: a raw string (its UTF-8 bytes) or a concrete byte
    // array ("90 90 05", for patching code). These write exactly their length.
    if (vt == ValueType::String || vt == ValueType::ByteArray) {
        std::vector<uint8_t> bytes;
        if (vt == ValueType::String) {
            for (const char* p = valStr; *p; ++p) bytes.push_back((uint8_t)*p);
        } else {
            // Parse space/comma-separated hex bytes; wildcards make no sense for an
            // in-place write, so reject them instead of guessing.
            std::string tok;
            auto flush = [&]() -> int {
                if (tok.empty()) return 0;
                if (tok == "??" || tok == "?" || tok == "*") {
                    fprintf(stderr, "write: wildcard '%s' not allowed when writing bytes\n", tok.c_str());
                    return 1;
                }
                char* end = nullptr;
                long b = strtol(tok.c_str(), &end, 16);
                if (*end != 0 || b < 0 || b > 255) {
                    fprintf(stderr, "write: '%s' is not a hex byte\n", tok.c_str());
                    return 1;
                }
                bytes.push_back((uint8_t)b);
                tok.clear();
                return 0;
            };
            for (const char* p = valStr;; ++p) {
                if (*p == ' ' || *p == ',' || *p == '\0') { if (flush()) return 1; if (!*p) break; }
                else tok.push_back(*p);
            }
        }
        if (bytes.empty()) { fprintf(stderr, "write: nothing to write\n"); return 1; }
        auto r = proc.write(addr, bytes.data(), bytes.size());
        if (!r) { fprintf(stderr, "Write failed: %s\n", r.error().message().c_str()); return 1; }
        printf("Wrote %zu bytes to 0x%lx\n", bytes.size(), addr);
        return 0;
    }

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
            // Unicode/Binary/All/Grouped/Custom are not supported here; refuse
            // rather than silently writing zero bytes and reporting success.
            fprintf(stderr, "write: unsupported --type for this command "
                            "(use byte, i16, i32, i64, pointer, float, double, string, aob)\n");
            return 1;
    }

    // Encode the value into its stored (obfuscated) form so the user edits by the
    // logical value the game shows. buf holds the raw little-endian integer.
    if (codec.active()) {
        uint64_t raw = 0; memcpy(&raw, buf, sz);
        uint64_t enc = codec.encode(raw, static_cast<int>(sz));
        memcpy(buf, &enc, sz);
    }

    auto r = proc.write(addr, buf, sz);
    if (!r) {
        fprintf(stderr, "Write failed: %s\n", r.error().message().c_str());
        return 1;
    }
    if (codec.active())
        printf("Wrote %zu bytes to 0x%lx (encoded %s)\n", sz, addr, codec.describe().c_str());
    else
        printf("Wrote %zu bytes to 0x%lx\n", sz, addr);

    // --verify: re-read after a short window to catch a value the game or an integrity
    // check overwrites (the classic "my edit does not stick"). Reports whether it held
    // and, if not, what it was reverted to.
    if (verifyMs > 0) {
        const struct timespec ts{ verifyMs/1000, (long)(verifyMs%1000)*1000000L };
        nanosleep(&ts, nullptr);
        uint8_t now[8] = {};
        auto rr = proc.read(addr, now, sz);
        if (!rr || *rr < sz) {
            printf("verify: could not re-read 0x%lx (region unmapped?)\n", addr);
        } else if (memcmp(now, buf, sz) == 0) {
            printf("verify: value held after %d ms (not protected here)\n", verifyMs);
        } else {
            uint64_t wrote = 0, cur = 0;
            memcpy(&wrote, buf, sz); memcpy(&cur, now, sz);
            if (codec.active()) { wrote = codec.decode(wrote, (int)sz); cur = codec.decode(cur, (int)sz); }
            auto sx = [](uint64_t v, int b) -> long long {
                return (b < 8 && ((v >> (b*8-1)) & 1))
                     ? (long long)(v | ~ce::ValueCodec::maskFor(b)) : (long long)v;
            };
            printf("verify: value was REVERTED after %d ms (wrote %lld, now %lld / 0x%llx).\n",
                   verifyMs, sx(wrote, (int)sz), sx(cur, (int)sz),
                   (unsigned long long)(cur & ce::ValueCodec::maskFor((int)sz)));
            if (findWriterSecs <= 0)
                printf("  Locate the writer with find-what-writes (GUI) or "
                       "`cescan watch %d 0x%lx` on 0x%lx.\n", pid, addr, addr);
        }
    }

    // Chain into find-what-writes so a protected value is diagnosed in one step: the
    // instruction that reverts it shows up among the writers.
    if (findWriterSecs > 0) {
        printf("\nfind-writer: watching 0x%lx for %ds to catch what writes it...\n",
               addr, findWriterSecs);
        return cmd_watch(pid, addr, /*writesOnly=*/true, (int)sz, findWriterSecs, /*mode auto*/0);
    }
    return 0;
}

static volatile sig_atomic_t g_freezeStop = 0;
static void onFreezeSignal(int) { g_freezeStop = 1; }

// Build the little-endian STORED bytes to write for a logical value, and the frozen
// value as a double (for directional freeze comparisons). Returns byte width, 0 on
// unsupported type. Applies the codec so an obfuscated value is frozen by its logical
// value.
static int freezeEncode(const char* valStr, ValueType vt, const ce::ValueCodec& codec,
                        uint8_t out[8], double& frozenNum) {
    const int sz = static_cast<int>(typeSize(vt));
    switch (vt) {
        case ValueType::Byte:   { int64_t v = parseWriteInt(valStr, INT8_MIN,  UINT8_MAX);  uint8_t t=(uint8_t)v; memcpy(out,&t,1); frozenNum=(double)(int8_t)v; break; }
        case ValueType::Int16:  { int64_t v = parseWriteInt(valStr, INT16_MIN, UINT16_MAX); int16_t t=(int16_t)v; memcpy(out,&t,2); frozenNum=(double)t; break; }
        case ValueType::Int32:  { int64_t v = parseWriteInt(valStr, INT32_MIN, UINT32_MAX); int32_t t=(int32_t)v; memcpy(out,&t,4); frozenNum=(double)t; break; }
        case ValueType::Int64:  { int64_t v = atoll(valStr); memcpy(out,&v,8); frozenNum=(double)v; break; }
        case ValueType::Pointer:{ uintptr_t v = strtoull(valStr,nullptr,0); memcpy(out,&v,8); frozenNum=(double)v; break; }
        case ValueType::Float:  { float v = (float)atof(valStr); memcpy(out,&v,4); frozenNum=v; break; }
        case ValueType::Double: { double v = atof(valStr); memcpy(out,&v,8); frozenNum=v; break; }
        default: return 0;
    }
    if (codec.active()) {
        uint64_t raw=0; memcpy(&raw,out,sz);
        uint64_t enc=codec.encode(raw,sz);
        memcpy(out,&enc,sz);
    }
    return sz;
}

// Read the current LOGICAL value at addr as a double (decoding via codec for ints).
static bool freezeReadCurrent(LinuxProcessHandle& proc, uintptr_t addr, ValueType vt,
                              const ce::ValueCodec& codec, double& cur) {
    uint8_t b[8]={}; const int sz = static_cast<int>(typeSize(vt));
    auto r = proc.read(addr, b, sz);
    if (!r || *r < (size_t)sz) return false;
    switch (vt) {
        case ValueType::Byte:   { uint64_t raw=b[0];                if(codec.active())raw=codec.decode(raw,1); cur=(double)(int8_t)raw;  return true; }
        case ValueType::Int16:  { uint64_t raw=0; memcpy(&raw,b,2); if(codec.active())raw=codec.decode(raw,2); cur=(double)(int16_t)raw; return true; }
        case ValueType::Int32:  { uint64_t raw=0; memcpy(&raw,b,4); if(codec.active())raw=codec.decode(raw,4); cur=(double)(int32_t)raw; return true; }
        case ValueType::Int64:  { int64_t v; memcpy(&v,b,8); uint64_t raw=(uint64_t)v; if(codec.active())raw=codec.decode(raw,8); cur=(double)(int64_t)raw; return true; }
        case ValueType::Pointer:{ uint64_t v; memcpy(&v,b,8); if(codec.active())v=codec.decode(v,8); cur=(double)v; return true; }
        case ValueType::Float:  { float v;  memcpy(&v,b,4); cur=v; return true; }
        case ValueType::Double: { double v; memcpy(&v,b,8); cur=v; return true; }
        default: return false;
    }
}

// Continuously re-write a value so the game cannot change it (CE's freeze/lock).
// --mode floor/ceil use the directional FreezeMode logic; --codec locks an obfuscated
// value by its logical value. Runs until SIGINT/SIGTERM.
static int cmd_freeze(pid_t pid, uintptr_t addr, const char* valStr, ValueType vt,
                      ce::ValueCodec codec, unsigned intervalMs, ce::FreezeMode mode) {
    LinuxProcessHandle proc(pid);
    if (codec.active() && (vt == ValueType::Float || vt == ValueType::Double)) {
        fprintf(stderr, "freeze: --codec applies to integer types only\n"); return 1;
    }
    uint8_t buf[8]={}; double frozen=0;
    const int sz = freezeEncode(valStr, vt, codec, buf, frozen);
    if (!sz) { fprintf(stderr, "freeze: unsupported --type for this command\n"); return 1; }

    g_freezeStop = 0;
    signal(SIGINT, onFreezeSignal);
    signal(SIGTERM, onFreezeSignal);
    const char* modeStr = mode==ce::FreezeMode::NeverDecrease ? " (floor)"
                        : mode==ce::FreezeMode::NeverIncrease ? " (ceiling)" : "";
    printf("Freezing 0x%lx = %s%s%s every %u ms. Ctrl-C to stop.\n", addr, valStr,
           codec.active() ? " [encoded]" : "", modeStr, intervalMs);

    unsigned long long writes=0, misses=0;
    const struct timespec ts{ intervalMs/1000, (long)(intervalMs%1000)*1000000L };
    while (!g_freezeStop) {
        bool doWrite = true;
        if (mode != ce::FreezeMode::Normal) {
            double cur;
            if (freezeReadCurrent(proc, addr, vt, codec, cur))
                doWrite = ce::freezeShouldWrite(mode, cur, frozen);
            else { ++misses; doWrite = false; }
        }
        if (doWrite) { auto wr = proc.write(addr, buf, sz); if (wr) ++writes; else ++misses; }
        nanosleep(&ts, nullptr);
    }
    printf("\nStopped: %llu write(s)%s.\n", writes,
           misses ? (" (" + std::to_string(misses) + " miss(es))").c_str() : "");
    return 0;
}

// A hardware watchpoint traps AFTER the store retires, so firstContext.rip points at
// the instruction FOLLOWING the writer. CodeFinder's backward-disassembly picks the
// longest decode ending at rip, which can land a few bytes early on dense code. Recover
// the exact store by disassembling FORWARD from the enclosing function (from the symbol)
// and returning the instruction that ends exactly at rip.
static bool recoverStore(LinuxProcessHandle& proc, Disassembler& dis, SymbolResolver& resolver,
                         uintptr_t rip, uintptr_t& outAddr, std::string& outText) {
    if (rip == 0) return false;
    uintptr_t anchor = (rip > 48) ? rip - 48 : 0;
    std::string s = resolver.resolve(rip - 1);            // symbol inside the store
    if (auto plus = s.rfind("+0x"); plus != std::string::npos) {
        uintptr_t off = strtoull(s.c_str() + plus + 3, nullptr, 16);
        uintptr_t fstart = (rip - 1) - off;
        if (fstart < rip && rip - fstart <= 4096) anchor = fstart;   // enclosing function
    }
    const size_t span = rip - anchor;
    std::vector<uint8_t> buf(span + 16);
    auto r = proc.read(anchor, buf.data(), buf.size());
    if (!r || *r < span) return false;
    auto insns = dis.disassemble(anchor, {buf.data(), *r}, span + 4);
    for (auto& in : insns) {
        if (in.address >= rip) break;
        if (in.address + in.size == rip) {
            outAddr = in.address;
            outText = in.operands.empty() ? in.mnemonic : in.mnemonic + " " + in.operands;
            return true;
        }
    }
    return false;
}

// Find what writes/accesses an address (CE's headline feature), exposed for scripting.
// modeOverride: 0=auto (single-thread hardware on Wine, all-thread hardware natively),
// 1=hw all-thread, 2=software page-guard, 3=single-thread hardware.
static int cmd_watch(pid_t pid, uintptr_t addr, bool writesOnly, int watchSize,
                     int durationSec, int modeOverride) {
    LinuxProcessHandle proc(pid);
    LinuxDebugger dbg;
    CodeFinder finder;

    // Wine-safe backend selection, mirroring the GUI: never seize a Wine game's whole
    // thread group or use the software page-guard (both freeze it); watch a hardware
    // debug register on the main thread only.
    ce::TargetProfile prof = ce::probeTarget(pid);
    bool software = false, singleThread = prof.wine;
    if      (modeOverride == 1) { software = false; singleThread = false; }
    else if (modeOverride == 2) { software = true;  singleThread = false; }
    else if (modeOverride == 3) { software = false; singleThread = true;  }

    const char* backend = software ? "software page-guard"
                        : singleThread ? "single-thread hardware (Wine-safe)" : "hardware";
    printf("Watching 0x%lx for %s via %s watchpoint (size %d) for up to %ds. Ctrl-C to stop.\n",
           addr, writesOnly ? "writes" : "accesses", backend, watchSize, durationSec);

    if (!finder.start(proc, dbg, addr, writesOnly, watchSize, software, singleThread)) {
        fprintf(stderr, "watch: could not arm the watchpoint (need cap_sys_ptrace, and the "
                        "target must not already be traced)\n");
        return 1;
    }

    g_freezeStop = 0;   // reuse the interrupt flag
    signal(SIGINT, onFreezeSignal);
    signal(SIGTERM, onFreezeSignal);
    const struct timespec tick{0, 200 * 1000000L};   // 200 ms
    for (int i = 0; i < durationSec * 5 && !g_freezeStop; ++i) nanosleep(&tick, nullptr);
    finder.stop();

    auto results = finder.results();
    if (results.empty()) {
        printf("No %s to 0x%lx observed in %ds.%s\n", writesOnly ? "writes" : "accesses",
               addr, durationSec,
               prof.wine ? " (Wine: only the main thread was watched; if the value is "
                           "written by a background thread, that write is not caught.)" : "");
        return 0;
    }

    // Symbolicate each writer instruction (symbol, else module+offset), like disasm.
    SymbolResolver resolver; resolver.loadProcess(proc);
    auto modules = proc.modules();
    Disassembler dis(proc.is64bit() ? Arch::X86_64 : Arch::X86_32);
    printf("\n%zu instruction(s) %s 0x%lx (most hits first):\n", results.size(),
           writesOnly ? "wrote" : "accessed", addr);
    for (auto& r : results) {
        // For a hardware trap (after the store), recover the exact store from the trap
        // rip; the software page-guard already stops on the faulting instruction.
        uintptr_t insAddr = r.instructionAddress;
        std::string insText = r.instructionText;
        if (!software) {
            uintptr_t a; std::string t;
            if (recoverStore(proc, dis, resolver, r.firstContext.rip, a, t)) { insAddr = a; insText = t; }
        }
        std::string loc = resolver.resolve(insAddr);
        if (loc.empty()) loc = ce::moduleOffsetString(modules, insAddr);
        printf("  %6d x  0x%lx  %s%s%s\n", r.hitCount, (unsigned long)insAddr,
               insText.c_str(), loc.empty() ? "" : "   ; ", loc.c_str());
    }
    return 0;
}

// Absolute target of a DIRECT branch ("jmp 0x401234"); 0 for register/indirect
// operands ("call rax", "jmp qword ptr [0x...]"). Mirrors the GUI's parseImmediate.
static uintptr_t branchImmTarget(const std::string& operands) {
    if (operands.find('[') != std::string::npos) return 0;
    auto pos = operands.find("0x");
    if (pos == std::string::npos) return 0;
    try { return (uintptr_t)std::stoull(operands.substr(pos + 2), nullptr, 16); }
    catch (...) { return 0; }
}

static int cmd_disasm(pid_t pid, uintptr_t addr, size_t count) {
    LinuxProcessHandle proc(pid);

    // Load symbols for annotation
    SymbolResolver resolver;
    resolver.loadProcess(proc);
    auto modules = proc.modules();   // for module+offset fallback on unnamed targets

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
        // Annotate a direct call/jmp target with its symbol, or its module+offset
        // when unnamed (stripped binary), matching the GUI disassembler.
        std::string anno;
        const bool branch = i.mnemonic == "call" || i.mnemonic == "jmp" ||
                            (!i.mnemonic.empty() && i.mnemonic[0] == 'j');
        if (branch) {
            if (uintptr_t target = branchImmTarget(i.operands)) {
                auto sym = resolver.resolve(target);
                if (!sym.empty()) anno = "  ; " + sym;
                else if (i.mnemonic == "call" || i.mnemonic == "jmp") {
                    auto mo = ce::moduleOffsetString(modules, target);
                    if (!mo.empty()) anno = "  ; " + mo;
                }
            }
        }
        // RIP-relative data reference (mov/lea/cmp [rip+x], ...): the operand
        // already shows the absolute effective address; annotate what lives there
        // (symbol, else module+offset), like the GUI's data-ref annotation.
        if (anno.empty() && i.ripTarget) {
            auto sym = resolver.resolve(i.ripTarget);
            if (!sym.empty()) anno = "  ; -> " + sym;
            else if (auto mo = ce::moduleOffsetString(modules, i.ripTarget); !mo.empty())
                anno = "  ; -> " + mo;
        }
        printf("%s%s\n", i.toString().c_str(), anno.c_str());
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
    ce::ValueCodec codec;

    static struct option long_opts[] = {
        {"codec",    required_argument, nullptr, 1003},
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
        {"executable",    no_argument,  nullptr, 'x'},
        {"no-writable",   no_argument,  nullptr, 1001},
        {"no-executable", no_argument,  nullptr, 1002},
        {nullptr, 0, nullptr, 0}
    };

    optind = 1; // reset getopt
    int opt;
    while ((opt = getopt_long(argc, argv, "t:v:2:e:s:c:p:P:q:r:T:a:wx", long_opts, nullptr)) != -1) {
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
            case 'w': config.writableMatch = ce::ProtMatch::Yes; break;
            case 'x': config.executableMatch = ce::ProtMatch::Yes; break;
            case 1001: config.writableMatch = ce::ProtMatch::No; break;
            case 1002: config.executableMatch = ce::ProtMatch::No; break;
            case 1003: {
                auto c = ce::ValueCodec::parse(optarg);
                if (!c) { fprintf(stderr, "Invalid --codec '%s' (use xor:0xKEY, add:N, rol:N, ror:N)\n", optarg); return 1; }
                codec = *c;
                break;
            }
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

    if (codec.active()) {
        // Obfuscated values: search for the ENCODED needle so the user scans by the
        // logical value the game displays. Only exact integer scans make sense (a
        // non-order-preserving codec like xor breaks changed/increased/decreased).
        const bool intType =
            config.valueType == ValueType::Byte  || config.valueType == ValueType::Int16 ||
            config.valueType == ValueType::Int32 || config.valueType == ValueType::Int64 ||
            config.valueType == ValueType::Pointer;
        if (config.compareType != ScanCompare::Exact || !intType || !valueStr) {
            fprintf(stderr, "--codec applies to exact integer scans only "
                            "(byte/i16/i32/i64/pointer, --compare exact, with --value)\n");
            return 1;
        }
        const int wbytes = static_cast<int>(typeSize(config.valueType));
        const uint64_t stored =
            codec.encode(static_cast<uint64_t>(config.intValue), wbytes);
        config.intValue = static_cast<int64_t>(stored);
        printf("scanning for %s-encoded value (stored bytes = 0x%llx)\n",
               codec.describe().c_str(), (unsigned long long)(stored & ce::ValueCodec::maskFor(wbytes)));
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

// Guest-scan state (candidates + their last value + region/type) is persisted
// per-pid so a later --next / --changed / --increased / --decreased can narrow it
// (cescan is stateless across invocations; the running pid keeps its region base).
static std::string guestResultPath(pid_t pid) { return "/tmp/.cescan_guest_" + std::to_string(pid); }

template <class T> static uint64_t valBits(T v) { uint64_t u = 0; std::memcpy(&u, &v, sizeof(T)); return u; }
template <class T> static T bitsVal(uint64_t u) { T v; std::memcpy(&v, &u, sizeof(T)); return v; }
template <class T> static T parseVal(const char* s) {
    if constexpr (std::is_same_v<T, float>)  return strtof(s, nullptr);
    else if constexpr (std::is_same_v<T, double>) return strtod(s, nullptr);
    else return static_cast<T>(strtoll(s, nullptr, 0));
}

static void writeGuestResults(pid_t pid, const ce::TargetProfile::GuestRegion& g, bool be,
                              ValueType vt, const std::vector<std::pair<uint64_t, uint64_t>>& hits) {
    FILE* f = fopen(guestResultPath(pid).c_str(), "w");
    if (!f) return;
    fprintf(f, "GUESTSCAN 2 base %lx size %lx be %d type %d\n",
            (unsigned long)g.base, (unsigned long)g.size, be ? 1 : 0, (int)vt);
    for (const auto& [a, v] : hits)
        fprintf(f, "%llx %llx\n", (unsigned long long)a, (unsigned long long)v);
    fclose(f);
}

enum class GsOp { ExactFirst, UnknownFirst, ExactNext, Compare };

static std::string guestSnapPath(pid_t pid) { return guestResultPath(pid) + ".snap"; }

static int cmd_guest_scan(pid_t pid, const char* valStr, ValueType vt, bool be, size_t align,
                          GsOp op, ce::GuestCompare cmpOp) {
    LinuxProcessHandle proc(pid);
    ce::TargetProfile::GuestRegion region;
    std::vector<std::pair<uint64_t, uint64_t>> prev;   // (guest addr, value bits)
    std::vector<uint8_t> snapOld;
    bool fromSnapshot = false;

    // Unknown-value first scan: snapshot the whole region, defer picking candidates
    // to the first comparison narrowing.
    if (op == GsOp::UnknownFirst) {
        ce::TargetProfile p = ce::probeTarget(pid);
        if (p.guestCandidates.empty()) {
            fprintf(stderr, "guest-scan: no guest-RAM region for pid %d (recognized emulator?)\n", pid);
            return 1;
        }
        region = p.guestCandidates.front();
        ce::GuestView gv{ &proc, region.base, region.size, be };
        auto bytes = ce::guestReadRegion(gv);
        if (FILE* sf = fopen(guestSnapPath(pid).c_str(), "wb")) {
            fwrite(bytes.data(), 1, bytes.size(), sf); fclose(sf);
        }
        if (FILE* f = fopen(guestResultPath(pid).c_str(), "w")) {
            fprintf(f, "GUESTSCAN 3 base %lx size %lx be %d type %d\n",
                    (unsigned long)region.base, (unsigned long)region.size, be ? 1 : 0, (int)vt);
            fclose(f);
        }
        printf("snapshot taken: %zu MB of %s guest RAM (%s-endian). Change the value "
               "in-game, then narrow with:\n"
               "  cescan guest-scan %d --changed | --increased | --decreased | --unchanged\n",
               static_cast<size_t>(bytes.size() >> 20), p.emulator.c_str(), be ? "big" : "little", pid);
        return 0;
    }

    if (op != GsOp::ExactFirst) {
        FILE* f = fopen(guestResultPath(pid).c_str(), "r");
        if (!f) { fprintf(stderr, "guest-scan: no prior scan for pid %d\n", pid); return 1; }
        int ver = 0, beI = 0, typeI = 0; unsigned long base = 0, size = 0;
        if (fscanf(f, "GUESTSCAN %d base %lx size %lx be %d type %d", &ver, &base, &size, &beI, &typeI) != 5) {
            fclose(f); fprintf(stderr, "guest-scan: corrupt state file\n"); return 1;
        }
        region.base = base; region.size = size; be = beI != 0; vt = (ValueType)typeI;  // carry over
        if (ver >= 3) {
            fclose(f);
            if (op != GsOp::Compare) {
                fprintf(stderr, "guest-scan: after --unknown, narrow first with a comparison "
                                "(--changed/--increased/--decreased/--unchanged)\n");
                return 1;
            }
            fromSnapshot = true;
            FILE* sf = fopen(guestSnapPath(pid).c_str(), "rb");
            if (!sf) { fprintf(stderr, "guest-scan: snapshot missing; re-run --unknown\n"); return 1; }
            fseek(sf, 0, SEEK_END); long n = ftell(sf); fseek(sf, 0, SEEK_SET);
            if (n > 0) { snapOld.resize((size_t)n); snapOld.resize(fread(snapOld.data(), 1, (size_t)n, sf)); }
            fclose(sf);
        } else {
            unsigned long long a, v;
            while (fscanf(f, "%llx %llx", &a, &v) == 2) prev.push_back({a, v});
            fclose(f);
        }
    } else {
        ce::TargetProfile p = ce::probeTarget(pid);
        if (p.guestCandidates.empty()) {
            fprintf(stderr, "guest-scan: no guest-RAM region for pid %d (recognized emulator? "
                            "try `cescan info %d`)\n", pid, pid);
            return 1;
        }
        region = p.guestCandidates.front();   // largest, already sorted
    }

    ce::GuestView gv{ &proc, region.base, region.size, be };
    const char* verb = op == GsOp::ExactFirst ? "scanning"
                     : op == GsOp::Compare    ? "compare-scanning" : "next-scanning";
    printf("%s %zu MB guest RAM at host 0x%lx (%s-endian)\n", verb,
           static_cast<size_t>(region.size >> 20), static_cast<unsigned long>(region.base),
           be ? "big" : "little");

    std::vector<uint8_t> liveBytes;
    if (fromSnapshot) liveBytes = ce::guestReadRegion(gv);

    std::vector<std::pair<uint64_t, uint64_t>> result;
    auto run = [&]<class T>() {
        if (op == GsOp::Compare) {
            if (fromSnapshot) {
                for (const auto& h : ce::guestCompareBuffers<T>(snapOld, liveBytes, be, cmpOp,
                                                                align ? align : sizeof(T)))
                    result.emplace_back(h.first, valBits(h.second));
            } else {
                std::vector<std::pair<uint64_t, T>> pairs;
                pairs.reserve(prev.size());
                for (const auto& [a, v] : prev) pairs.emplace_back(a, bitsVal<T>(v));
                for (const auto& h : ce::guestNextCompare<T>(gv, pairs, cmpOp))
                    result.emplace_back(h.first, valBits(h.second));
            }
        } else {
            const T val = parseVal<T>(valStr);
            const uint64_t vb = valBits(val);
            std::vector<uint64_t> hits;
            if (op == GsOp::ExactFirst) {
                hits = ce::guestScanExact<T>(gv, val, align ? align : sizeof(T));
            } else {
                std::vector<uint64_t> addrs; addrs.reserve(prev.size());
                for (const auto& p : prev) addrs.push_back(p.first);
                hits = ce::guestNextExact<T>(gv, addrs, val);
            }
            for (uint64_t h : hits) result.emplace_back(h, vb);
        }
    };
    switch (vt) {
        case ValueType::Byte:   run.template operator()<int8_t>();  break;
        case ValueType::Int16:  run.template operator()<int16_t>(); break;
        case ValueType::Int32:  run.template operator()<int32_t>(); break;
        case ValueType::Int64:  run.template operator()<int64_t>(); break;
        case ValueType::Float:  run.template operator()<float>();   break;
        case ValueType::Double: run.template operator()<double>();  break;
        default: fprintf(stderr, "guest-scan supports byte/i16/i32/i64/float/double\n"); return 1;
    }

    if (fromSnapshot) remove(guestSnapPath(pid).c_str());   // now have an explicit set
    writeGuestResults(pid, region, be, vt, result);
    printf("%zu match(es):\n", result.size());
    const size_t shown = std::min<size_t>(result.size(), 200);
    for (size_t i = 0; i < shown; ++i)
        printf("  guest 0x%llx  (host 0x%lx)\n",
               (unsigned long long)result[i].first, (unsigned long)gv.toHost(result[i].first));
    if (result.size() > shown) printf("  ... (%zu more)\n", result.size() - shown);
    return 0;
}

static int cmd_guest_write(pid_t pid, uint64_t guestAddr, const char* valStr,
                           ValueType vt, bool be, bool typeSet, bool beSet) {
    LinuxProcessHandle proc(pid);
    ce::TargetProfile::GuestRegion region{};
    bool haveRegion = false;
    // Reuse the last scan's region/endian/type so `guest-scan` then `guest-write
    // <addr> <val>` just works; explicit --type/--be override.
    if (FILE* f = fopen(guestResultPath(pid).c_str(), "r")) {
        int ver = 0, beI = 0, typeI = 0; unsigned long base = 0, size = 0;
        if (fscanf(f, "GUESTSCAN %d base %lx size %lx be %d type %d", &ver, &base, &size, &beI, &typeI) == 5) {
            region.base = base; region.size = size; haveRegion = true;
            if (!beSet) be = beI != 0;
            if (!typeSet) vt = (ValueType)typeI;
        }
        fclose(f);
    }
    if (!haveRegion) {
        ce::TargetProfile p = ce::probeTarget(pid);
        if (p.guestCandidates.empty()) {
            fprintf(stderr, "guest-write: no guest-RAM region for pid %d (scan first, or "
                            "recognized emulator?)\n", pid);
            return 1;
        }
        region = p.guestCandidates.front();
    }
    ce::GuestView gv{ &proc, region.base, region.size, be };
    bool ok = false;
    auto run = [&]<class T>() { ok = gv.write<T>(guestAddr, parseVal<T>(valStr)); };
    switch (vt) {
        case ValueType::Byte:   run.template operator()<int8_t>();  break;
        case ValueType::Int16:  run.template operator()<int16_t>(); break;
        case ValueType::Int32:  run.template operator()<int32_t>(); break;
        case ValueType::Int64:  run.template operator()<int64_t>(); break;
        case ValueType::Float:  run.template operator()<float>();   break;
        case ValueType::Double: run.template operator()<double>();  break;
        default: fprintf(stderr, "guest-write supports byte/i16/i32/i64/float/double\n"); return 1;
    }
    if (ok) printf("wrote %s to guest 0x%llx (host 0x%lx, %s-endian)\n", valStr,
                   (unsigned long long)guestAddr, (unsigned long)gv.toHost(guestAddr), be ? "big" : "little");
    else    fprintf(stderr, "guest-write: failed (guest 0x%llx out of range or unwritable)\n",
                    (unsigned long long)guestAddr);
    return ok ? 0 : 1;
}

static int cmd_info(pid_t pid) {
    ce::TargetProfile p = ce::probeTarget(pid);
    if (!p.valid) { fprintf(stderr, "pid %d: not inspectable (gone, or permission)\n", pid); return 1; }
    printf("pid:      %d\n", pid);
    printf("summary:  %s\n", p.summary().c_str());
    printf("arch:     %s\n", p.archName().c_str());
    printf("wine:     %s\n", p.wine ? "yes" : "no");
    if (p.tracerPid)      printf("tracer:   %d (already being traced)\n", p.tracerPid);
    if (p.seccomp)        printf("seccomp:  filter active\n");
    if (p.pidNamespaced)  printf("sandbox:  PID namespace (Flatpak/Snap/container)\n");
    if (!p.emulator.empty()) printf("emulator: %s\n", p.emulator.c_str());
    for (const auto& g : p.guestCandidates)
        printf("guest-ram:0x%lx (%zu MB)\n", (unsigned long)g.base, g.size >> 20);
    for (const auto& r : p.runtimes) printf("runtime:  %s\n", r.c_str());
    if (!p.notes.empty()) {
        printf("\nnotes:\n");
        for (const auto& n : p.notes) printf("  - %s\n", n.c_str());
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
    std::fprintf(stderr, "cescan lua REPL (Ctrl+D to exit)\n");
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
                        "[--fields] [--methods] [--object <class>] [--binary <GameAssembly>]\n");
        return 1;
    }
    const char* path = argv[1];
    std::string filter, binaryPath, objectClass;
    bool showFields = false, showMethods = false;
    for (int i = 2; i < argc; ++i) {
        if (!strcmp(argv[i], "--class") && i + 1 < argc) filter = argv[++i];
        else if (!strcmp(argv[i], "--fields")) showFields = true;
        else if (!strcmp(argv[i], "--methods")) showMethods = true;
        else if (!strcmp(argv[i], "--binary") && i + 1 < argc) binaryPath = argv[++i];
        else if (!strcmp(argv[i], "--object") && i + 1 < argc) objectClass = argv[++i];
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

    // --object: print one class's COMPLETE instance layout (own + inherited).
    if (!objectClass.empty()) {
        if (!haveOffsets) {
            fprintf(stderr, "cescan il2cpp --object: needs the GameAssembly binary (pass --binary)\n");
            return 1;
        }
        std::string full;
        for (const auto& c : layout.classes) if (c.fullName() == objectClass) { full = objectClass; break; }
        if (full.empty())
            for (const auto& c : layout.classes) if (c.name == objectClass) { full = c.fullName(); break; }
        if (full.empty())
            for (const auto& c : layout.classes)
                if (c.fullName().find(objectClass) != std::string::npos) { full = c.fullName(); break; }
        if (full.empty()) { fprintf(stderr, "cescan il2cpp --object: class '%s' not found\n", objectClass.c_str()); return 1; }
        auto fields = ce::il2cppObjectFieldLayout(layout, full);
        printf("\nobject layout of %s (%zu instance fields, incl. inherited):\n", full.c_str(), fields.size());
        for (const auto& f : fields) {
            std::string from = (f.declaringType != full) ? ("  <- " + f.declaringType) : "";
            printf("  +0x%-5x %-24s %s%s\n", f.offset, f.typeName.c_str(), f.name.c_str(), from.c_str());
        }
        return 0;
    }

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
                    printf("      +0x%-5x %-24s %-26s %s\n", rf.offset, rf.typeName.c_str(),
                           rf.name.c_str(), kind);
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

// cescan analyze <pid> <what> [args] [--module <name>]
// Surfaces the static reverse-engineering toolkit (the same cecore functions the
// GUI and Lua use) from the shell. `what` is one of: strings, statics, caves
// [minSize], functions, xrefs <addr>, asm "<instruction>".
static int cmd_analyze(pid_t pid, int argc, char** argv) {
    if (argc < 1) {
        fprintf(stderr, "usage: cescan analyze <pid> <strings|statics|caves|functions|"
                        "xrefs <addr>|asm \"<insn>\"> [--module <name>]\n");
        return 1;
    }
    const char* what = argv[0];

    // Pull an optional --module <name> out of the tail; the rest are positionals.
    std::string modName;
    std::vector<const char*> pos;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--module") && i + 1 < argc) modName = argv[++i];
        else pos.push_back(argv[i]);
    }

    LinuxProcessHandle proc(pid);
    auto mods = proc.modules();
    if (mods.empty()) { fprintf(stderr, "cescan analyze: no modules for pid %d\n", pid); return 1; }
    const ce::ModuleInfo* mod = nullptr;
    if (!modName.empty()) {
        for (auto& m : mods) if (m.name == modName) { mod = &m; break; }
        if (!mod) { fprintf(stderr, "cescan analyze: module '%s' not found\n", modName.c_str()); return 1; }
    } else {
        mod = &mods.front();   // main executable is enumerated first
    }

    ce::CodeAnalyzer an;
    if (!strcmp(what, "strings")) {
        for (const auto& r : an.findReferencedStrings(proc, *mod))
            printf("0x%lx  %s\n", (unsigned long)r.target, r.text.c_str());
    } else if (!strcmp(what, "statics")) {
        for (const auto& s : an.findStatics(proc, *mod))
            printf("0x%lx  %zu refs\n", (unsigned long)s.address, s.references);
    } else if (!strcmp(what, "caves")) {
        size_t minSize = !pos.empty() ? (size_t)strtoul(pos[0], nullptr, 0) : 16;
        for (const auto& c : an.findCodeCaves(proc, *mod, minSize))
            printf("0x%lx  %zu bytes\n", (unsigned long)c.address, c.size);
    } else if (!strcmp(what, "functions")) {
        for (const auto& f : an.enumerateFunctions(proc, *mod))
            printf("0x%lx  %zu refs\n", (unsigned long)f.address, f.references);
    } else if (!strcmp(what, "xrefs")) {
        if (pos.empty()) { fprintf(stderr, "cescan analyze xrefs: need <addr>\n"); return 1; }
        uintptr_t target = strtoul(pos[0], nullptr, 0);
        for (const auto& r : an.findReferencesTo(proc, *mod, target))
            printf("0x%lx  %s\n", (unsigned long)r.address, r.text.c_str());
    } else if (!strcmp(what, "asm")) {
        if (pos.empty()) { fprintf(stderr, "cescan analyze asm: need \"<instruction>\"\n"); return 1; }
        for (const auto& r : an.findAssemblyPattern(proc, *mod, pos[0]))
            printf("0x%lx  %s\n", (unsigned long)r.address, r.text.c_str());
    } else {
        fprintf(stderr, "cescan analyze: unknown '%s'\n", what);
        return 1;
    }
    fprintf(stderr, "# module %s @ 0x%lx\n", mod->name.c_str(), (unsigned long)mod->base);
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
    else if (!strcmp(cmd, "info") && argc >= 3) {
        return cmd_info(parsePid(argv[2]));
    }
    else if (!strcmp(cmd, "guest-scan") && argc >= 4) {
        ValueType vt = ValueType::Int32; bool be = false; size_t align = 0;
        GsOp op = GsOp::ExactFirst; ce::GuestCompare cmp = ce::GuestCompare::Changed;
        const char* val = nullptr;
        for (int i = 3; i < argc; ++i) {
            if (!strcmp(argv[i], "--type") && i + 1 < argc) vt = parseType(argv[++i]);
            else if (!strcmp(argv[i], "--be")) be = true;
            else if (!strcmp(argv[i], "--align") && i + 1 < argc)
                align = static_cast<size_t>(strtoul(argv[++i], nullptr, 0));
            else if (!strcmp(argv[i], "--unknown")) op = GsOp::UnknownFirst;
            else if (!strcmp(argv[i], "--next")) op = GsOp::ExactNext;
            else if (!strcmp(argv[i], "--changed"))   { op = GsOp::Compare; cmp = ce::GuestCompare::Changed; }
            else if (!strcmp(argv[i], "--unchanged")) { op = GsOp::Compare; cmp = ce::GuestCompare::Unchanged; }
            else if (!strcmp(argv[i], "--increased")) { op = GsOp::Compare; cmp = ce::GuestCompare::Increased; }
            else if (!strcmp(argv[i], "--decreased")) { op = GsOp::Compare; cmp = ce::GuestCompare::Decreased; }
            else if (!val) val = argv[i];   // first positional after pid is the value
        }
        if ((op == GsOp::ExactFirst || op == GsOp::ExactNext) && !val) {
            fprintf(stderr, "guest-scan: missing <value>\n"); return 1;
        }
        return cmd_guest_scan(parsePid(argv[2]), val, vt, be, align, op, cmp);
    }
    else if (!strcmp(cmd, "guest-write") && argc >= 5) {
        ValueType vt = ValueType::Int32; bool be = false, typeSet = false, beSet = false;
        for (int i = 5; i < argc; ++i) {
            if (!strcmp(argv[i], "--type") && i + 1 < argc) { vt = parseType(argv[++i]); typeSet = true; }
            else if (!strcmp(argv[i], "--be")) { be = true; beSet = true; }
        }
        return cmd_guest_write(parsePid(argv[2]), strtoull(argv[3], nullptr, 0), argv[4],
                               vt, be, typeSet, beSet);
    }
    else if (!strcmp(cmd, "read") && argc >= 4) {
        // Cap the requested size so an adversarial/typo'd argument can't trigger
        // an uncaught std::bad_alloc that terminates the process. 256 MB ceiling.
        constexpr unsigned long long kMaxReadSize = 256ull * 1024 * 1024;
        size_t size = 64;
        const char* typeStr = nullptr;
        ce::ValueCodec codec;
        int i = 4;
        // Optional positional [size] (only if it isn't the --type flag), then --type.
        if (argc >= 5 && argv[4][0] != '-') {
            size = static_cast<size_t>(parseUInt(argv[4], "read size", kMaxReadSize));
            i = 5;
        }
        for (; i < argc; ++i) {
            if (!strcmp(argv[i], "--type") && i + 1 < argc) typeStr = argv[++i];
            else if (!strcmp(argv[i], "--codec") && i + 1 < argc) {
                auto c = ce::ValueCodec::parse(argv[++i]);
                if (!c) { fprintf(stderr, "Invalid --codec (use xor:0xKEY, add:N, rol:N, ror:N)\n"); return 1; }
                codec = *c;
            }
        }
        return cmd_read(parsePid(argv[2]), strtoul(argv[3], nullptr, 0), size, typeStr, codec);
    }
    else if (!strcmp(cmd, "write") && argc >= 5) {
        ValueType vt = ValueType::Int32;
        ce::ValueCodec codec;
        int verifyMs = 0, findWriterSecs = 0;
        for (int i = 5; i < argc; ++i) {
            if (!strcmp(argv[i], "--type") && i + 1 < argc) vt = parseType(argv[i+1]);
            else if (!strcmp(argv[i], "--codec") && i + 1 < argc) {
                auto c = ce::ValueCodec::parse(argv[i+1]);
                if (!c) { fprintf(stderr, "Invalid --codec (use xor:0xKEY, add:N, rol:N, ror:N)\n"); return 1; }
                codec = *c;
            }
            else if (!strcmp(argv[i], "--verify")) verifyMs = 200;
            else if (!strcmp(argv[i], "--verify-ms") && i + 1 < argc)
                verifyMs = (int)strtoul(argv[++i], nullptr, 0);
            else if (!strcmp(argv[i], "--find-writer")) findWriterSecs = 5;
            else if (!strcmp(argv[i], "--find-writer-secs") && i + 1 < argc)
                findWriterSecs = (int)strtoul(argv[++i], nullptr, 0);
        }
        return cmd_write(parsePid(argv[2]), strtoul(argv[3], nullptr, 0), argv[4], vt,
                         codec, verifyMs, findWriterSecs);
    }
    else if (!strcmp(cmd, "freeze") && argc >= 5) {
        ValueType vt = ValueType::Int32;
        ce::ValueCodec codec;
        unsigned interval = 100;
        ce::FreezeMode mode = ce::FreezeMode::Normal;
        for (int i = 5; i < argc; ++i) {
            if (!strcmp(argv[i], "--type") && i + 1 < argc) vt = parseType(argv[++i]);
            else if (!strcmp(argv[i], "--codec") && i + 1 < argc) {
                auto c = ce::ValueCodec::parse(argv[++i]);
                if (!c) { fprintf(stderr, "Invalid --codec (use xor:0xKEY, add:N, rol:N, ror:N)\n"); return 1; }
                codec = *c;
            }
            else if (!strcmp(argv[i], "--interval") && i + 1 < argc)
                interval = (unsigned)strtoul(argv[++i], nullptr, 0);
            else if (!strcmp(argv[i], "--mode") && i + 1 < argc) {
                const char* m = argv[++i];
                if (!strcmp(m, "normal")) mode = ce::FreezeMode::Normal;
                else if (!strcmp(m, "floor")) mode = ce::FreezeMode::NeverDecrease;
                else if (!strcmp(m, "ceil"))  mode = ce::FreezeMode::NeverIncrease;
                else { fprintf(stderr, "freeze: --mode must be normal|floor|ceil\n"); return 1; }
            }
        }
        if (interval < 1) interval = 1;
        return cmd_freeze(parsePid(argv[2]), strtoul(argv[3], nullptr, 0), argv[4], vt, codec, interval, mode);
    }
    else if (!strcmp(cmd, "watch") && argc >= 4) {
        bool writesOnly = true; int watchSize = 4, duration = 10, mode = 0;
        for (int i = 4; i < argc; ++i) {
            if (!strcmp(argv[i], "--access")) writesOnly = false;
            else if (!strcmp(argv[i], "--writes")) writesOnly = true;
            else if (!strcmp(argv[i], "--size") && i + 1 < argc) watchSize = (int)strtoul(argv[++i], nullptr, 0);
            else if (!strcmp(argv[i], "--duration") && i + 1 < argc) duration = (int)strtoul(argv[++i], nullptr, 0);
            else if (!strcmp(argv[i], "--mode") && i + 1 < argc) {
                const char* m = argv[++i];
                if (!strcmp(m, "hw")) mode = 1;
                else if (!strcmp(m, "sw")) mode = 2;
                else if (!strcmp(m, "st")) mode = 3;
                else { fprintf(stderr, "watch: --mode must be hw|sw|st\n"); return 1; }
            }
        }
        if (watchSize != 1 && watchSize != 2 && watchSize != 4 && watchSize != 8) watchSize = 4;
        if (duration < 1) duration = 1;
        return cmd_watch(parsePid(argv[2]), strtoul(argv[3], nullptr, 0),
                         writesOnly, watchSize, duration, mode);
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
    else if (!strcmp(cmd, "analyze") && argc >= 4) {
        return cmd_analyze(parsePid(argv[2]), argc - 3, argv + 3);
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
