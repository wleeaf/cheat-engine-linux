#include "core/target_profile.hpp"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <utility>
#include <set>

namespace ce {

namespace {

std::string slurp(const std::string& path, size_t cap = 1 << 20) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::string s;
    s.resize(cap);
    f.read(s.data(), static_cast<std::streamsize>(cap));
    s.resize(static_cast<size_t>(f.gcount()));
    return s;
}

std::string lower(std::string s) {
    for (auto& c : s) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    return s;
}

// argv joined with spaces (from the NUL-separated /proc/<pid>/cmdline).
std::string cmdlineJoined(pid_t pid) {
    std::string raw = slurp("/proc/" + std::to_string(pid) + "/cmdline", 64 * 1024);
    for (auto& c : raw) if (c == '\0') c = ' ';
    while (!raw.empty() && raw.back() == ' ') raw.pop_back();
    return raw;
}

std::string basenameOf(const std::string& p) {
    auto slash = p.find_last_of("/\\");
    return slash == std::string::npos ? p : p.substr(slash + 1);
}

void elfIdent(pid_t pid, TargetProfile& p) {
    std::string hdr = slurp("/proc/" + std::to_string(pid) + "/exe", 32);
    if (hdr.size() < 20 || hdr[0] != 0x7f || hdr[1] != 'E' || hdr[2] != 'L' || hdr[3] != 'F')
        return;
    p.endianness = (static_cast<uint8_t>(hdr[5]) == 2)   // EI_DATA: 2 = big-endian
        ? TargetProfile::Endian::Big : TargetProfile::Endian::Little;
    // e_machine is at offset 18, read in the header's declared byte order.
    const bool big = p.endianness == TargetProfile::Endian::Big;
    const uint8_t b0 = static_cast<uint8_t>(hdr[18]), b1 = static_cast<uint8_t>(hdr[19]);
    const uint16_t machine = big ? static_cast<uint16_t>((b0 << 8) | b1)
                                 : static_cast<uint16_t>(b0 | (b1 << 8));
    switch (machine) {
        case 3:   p.arch = TargetProfile::Arch::X86_32;  break;  // EM_386
        case 62:  p.arch = TargetProfile::Arch::X86_64;  break;  // EM_X86_64
        case 40:  p.arch = TargetProfile::Arch::Arm32;   break;  // EM_ARM
        case 183: p.arch = TargetProfile::Arch::Arm64;   break;  // EM_AARCH64
        case 243: p.arch = TargetProfile::Arch::RiscV64; break;  // EM_RISCV
        default:  p.arch = TargetProfile::Arch::Other;   break;
    }
}

// A Go binary carries a build-info blob whose header begins "\xff Go buildinf:".
// Stream the exe (bounded) looking for the printable part; handles chunk splits.
bool isGoBinary(pid_t pid) {
    std::ifstream f("/proc/" + std::to_string(pid) + "/exe", std::ios::binary);
    if (!f) return false;
    static const std::string kNeedle = "Go buildinf:";
    std::string chunk(1u << 20, '\0');   // 1 MB
    std::string carry;
    size_t total = 0;
    const size_t kCap = 64u << 20;        // give up after 64 MB
    while (f && total < kCap) {
        f.read(chunk.data(), static_cast<std::streamsize>(chunk.size()));
        const size_t n = static_cast<size_t>(f.gcount());
        if (n == 0) break;
        std::string window = carry;
        window.append(chunk.data(), n);
        if (window.find(kNeedle) != std::string::npos) return true;
        const size_t keep = kNeedle.size() - 1;
        carry = window.size() > keep ? window.substr(window.size() - keep) : window;
        total += n;
    }
    return false;
}

// Known standalone emulators, matched against the exe basename / comm.
std::string detectEmulator(pid_t pid, const std::string& cmdline) {
    static const std::array<std::pair<const char*, const char*>, 16> kEmus = {{
        {"rpcs3", "RPCS3"}, {"dolphin-emu", "Dolphin"}, {"dolphin", "Dolphin"},
        {"pcsx2", "PCSX2"}, {"yuzu", "yuzu"}, {"ryujinx", "Ryujinx"},
        {"citra", "Citra"}, {"duckstation", "DuckStation"}, {"retroarch", "RetroArch"},
        {"ppsspp", "PPSSPP"}, {"melonds", "melonDS"}, {"mgba", "mGBA"},
        {"cemu", "Cemu"}, {"xemu", "xemu"}, {"flycast", "Flycast"}, {"mupen64", "Mupen64"},
    }};
    std::string comm = slurp("/proc/" + std::to_string(pid) + "/comm");
    while (!comm.empty() && (comm.back() == '\n' || comm.back() == ' ')) comm.pop_back();
    const std::string hay = lower(comm) + " " + lower(basenameOf(cmdline));
    for (auto& [needle, label] : kEmus)
        if (hay.find(needle) != std::string::npos) return label;
    return {};
}

// Managed runtimes / JITs present, from the mapped file paths in /proc/<pid>/maps.
std::vector<std::string> detectRuntimes(pid_t pid) {
    std::set<std::string> found;
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    std::string line;
    while (std::getline(maps, line)) {
        // The path is the last field; a cheap contains-check is enough.
        const std::string l = lower(line);
        if (l.find("libcoreclr.so") != std::string::npos ||
            l.find("system.private.corelib") != std::string::npos ||
            l.find("libclrjit.so") != std::string::npos)
            found.insert("CoreCLR (.NET)");
        if (l.find("libmonosgen") != std::string::npos ||
            l.find("libmono-2.0") != std::string::npos ||
            l.find("/mono/") != std::string::npos)
            found.insert("Mono");
        if (l.find("libjvm.so") != std::string::npos)
            found.insert("JVM (Java)");
        if (l.find("libnode.so") != std::string::npos ||
            l.find("libv8") != std::string::npos)
            found.insert("V8 / Node");
    }
    return {found.begin(), found.end()};
}

void parseStatus(pid_t pid, TargetProfile& p) {
    std::ifstream st("/proc/" + std::to_string(pid) + "/status");
    std::string line;
    while (std::getline(st, line)) {
        if (line.rfind("TracerPid:", 0) == 0) {
            p.tracerPid = static_cast<pid_t>(std::strtol(line.c_str() + 10, nullptr, 10));
        } else if (line.rfind("Seccomp:", 0) == 0) {
            p.seccomp = std::strtol(line.c_str() + 8, nullptr, 10) != 0;
        } else if (line.rfind("NSpid:", 0) == 0) {
            // "NSpid: <host-pid> <ns-pid> ..." -> more than one field means the
            // process is inside a nested PID namespace (sandbox / container).
            std::istringstream ss(line.substr(6));
            int n = 0; long v;
            while (ss >> v) ++n;
            p.pidNamespaced = n > 1;
        }
    }
}

void buildNotes(TargetProfile& p) {
    if (p.tracerPid != 0)
        p.notes.push_back(
            "Already being traced (by PID " + std::to_string(p.tracerPid) + "): "
            "watchpoints, code injection and the debugger will fail until it detaches. "
            "If nothing else is debugging it, the process is tracing itself (anti-debug).");

    if (p.wine)
        p.notes.push_back(
            "Wine/Proton (Windows) game: find-what-writes watches the main thread only, "
            "and the software page-guard watchpoint is disabled here (it fights Proton's "
            "write-watch). Memory scan and edit are unaffected.");

    if (!p.emulator.empty())
        p.notes.push_back(
            p.emulator + " emulator: the game's memory is guest memory inside the "
            "emulator's address space, so scanned addresses are guest-relative and may be "
            "byte-swapped, and a per-guest 'find what writes' is not yet supported. Scan, "
            "edit and freeze still work.");

    // Go is AOT-compiled (no JIT) but moves goroutine stacks and migrates goroutines
    // across OS threads, so it warrants a distinct note; the moving-GC + JIT note below
    // covers .NET/JVM/V8.
    std::vector<std::string> managed;
    bool go = false;
    for (const auto& r : p.runtimes) { if (r == "Go") go = true; else managed.push_back(r); }
    if (!managed.empty()) {
        std::string names;
        for (size_t i = 0; i < managed.size(); ++i)
            names += (i ? ", " : "") + managed[i];
        p.notes.push_back(
            "Managed runtime (" + names + "): values can move when its garbage collector "
            "runs, so a found address may go stale, and the code that writes a value is "
            "JIT-compiled and can relocate. Prefer structure/pointer resolution over raw "
            "pointer scans.");
    }
    if (go)
        p.notes.push_back(
            "Go runtime: goroutine stacks move (stack values relocate) and the scheduler "
            "migrates goroutines across OS threads, so a per-thread hardware watchpoint may "
            "not follow a goroutine. Heap objects are mostly address-stable.");

    if (p.pidNamespaced)
        p.notes.push_back(
            std::string("Sandboxed (PID namespace): the process runs in a "
            "Flatpak/Snap/Firejail/container namespace; attaching may need elevated "
            "privileges") + (p.seccomp ? ", and a seccomp filter is active." : "."));

    if (p.arch != TargetProfile::Arch::X86_64 && p.arch != TargetProfile::Arch::X86_32 &&
        p.arch != TargetProfile::Arch::Unknown)
        p.notes.push_back(
            "Non-x86 architecture (" + p.archName() + "): hardware watchpoints and code "
            "injection are x86-only for now; memory scan and edit work.");

    if (p.endianness == TargetProfile::Endian::Big)
        p.notes.push_back(
            "Big-endian target: multi-byte values are byte-swapped relative to this host; "
            "scans and edits must account for it.");
}

} // namespace

std::string TargetProfile::archName() const {
    switch (arch) {
        case Arch::X86_64:  return "x86-64";
        case Arch::X86_32:  return "x86-32";
        case Arch::Arm64:   return "ARM64";
        case Arch::Arm32:   return "ARM32";
        case Arch::RiscV64: return "RISC-V 64";
        case Arch::Other:   return "other";
        default:            return "unknown";
    }
}

std::string TargetProfile::summary() const {
    if (!valid) return "unknown target";
    std::string a = archName();
    if (!emulator.empty()) return emulator + " emulator (" + a + ")";
    if (wine)              return "Wine/Proton " + a + " game";
    if (!runtimes.empty()) return runtimes.front() + " app (" + a + ")";
    return a + " native process";
}

TargetProfile probeTarget(pid_t pid) {
    TargetProfile p;
    p.pid = pid;
    if (pid <= 0) return p;

    // Cheapest signal of a live, inspectable process.
    std::string status = slurp("/proc/" + std::to_string(pid) + "/status", 16 * 1024);
    if (status.empty()) return p;   // gone or unreadable
    p.valid = true;

    const std::string cmdline = cmdlineJoined(pid);
    elfIdent(pid, p);   // sets arch + endianness
    p.wine = lower(cmdline).find(".exe") != std::string::npos;
    p.emulator = detectEmulator(pid, cmdline);
    p.runtimes = detectRuntimes(pid);
    if (isGoBinary(pid)) p.runtimes.push_back("Go");
    parseStatus(pid, p);
    buildNotes(p);
    return p;
}

} // namespace ce
