#include "core/log.hpp"

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <mutex>
#include <thread>

namespace ce::log {
namespace {

constexpr int kCount = static_cast<int>(Cat::Count_);

// Index by Cat; keep in sync with the enum.
constexpr std::array<const char*, kCount> kCatNames = {
    "general", "scan", "memory", "ptrace", "debugger",
    "ct", "lua", "symbols", "ceserver", "gui",
};

// Per-category current level. Relaxed atomics: the hot-path check (`enabled`)
// must be cheap and lock-free. The baseline is set at STATIC-init time (below),
// not inside lazy init: otherwise a setLevel() before the first log call would be
// clobbered when doInit() later ran. doInit() then only layers CE_LOG on top.
std::array<std::atomic<int>, kCount> g_levels{};
const bool g_levelsBaseline = [] {
    // Default Warn: an unconfigured run still surfaces errors + warnings.
    for (auto& v : g_levels) v.store(static_cast<int>(Level::Warn), std::memory_order_relaxed);
    return true;
}();

std::mutex g_sinkMutex;      // serializes writes to stderr + file
std::FILE* g_file = nullptr; // optional file sink (owned)
std::once_flag g_initOnce;

Cat catFromName(std::string_view s) {
    for (int i = 0; i < kCount; ++i)
        if (s == kCatNames[i]) return static_cast<Cat>(i);
    return Cat::Count_;   // sentinel: not found
}

char levelChar(Level l) {
    switch (l) {
        case Level::Error: return 'E';
        case Level::Warn:  return 'W';
        case Level::Info:  return 'I';
        case Level::Debug: return 'D';
        case Level::Trace: return 'T';
        case Level::Off:   return '-';
    }
    return '?';
}

// CE_LOG grammar: a comma list of `name:level` or a bare `level`. `*` (or a bare
// level with no colon) sets every category; explicit names override. Whitespace
// is ignored. Unknown names/levels are skipped.
void applyEnvSpec(std::string_view spec) {
    size_t i = 0;
    while (i < spec.size()) {
        size_t comma = spec.find(',', i);
        std::string_view tok = spec.substr(i, comma == std::string_view::npos ? comma : comma - i);
        i = (comma == std::string_view::npos) ? spec.size() : comma + 1;

        // trim
        while (!tok.empty() && (tok.front() == ' ' || tok.front() == '\t')) tok.remove_prefix(1);
        while (!tok.empty() && (tok.back() == ' ' || tok.back() == '\t')) tok.remove_suffix(1);
        if (tok.empty()) continue;

        size_t colon = tok.find(':');
        if (colon == std::string_view::npos) {
            // bare level => applies to all categories
            Level lv;
            if (parseLevel(tok, lv)) setLevelAll(lv);
            continue;
        }
        std::string_view catName = tok.substr(0, colon);
        std::string_view lvName = tok.substr(colon + 1);
        Level lv;
        if (!parseLevel(lvName, lv)) continue;
        if (catName == "*") { setLevelAll(lv); continue; }
        Cat c = catFromName(catName);
        if (c != Cat::Count_) setLevel(c, lv);
    }
}

void doInit() {
    // Baseline (Warn) is already set at static-init; here we only layer CE_LOG on.
    if (const char* spec = std::getenv("CE_LOG"); spec && *spec)
        applyEnvSpec(spec);
    if (const char* path = std::getenv("CE_LOG_FILE"); path && *path)
        setLogFile(path);
}

void ensureInit() { std::call_once(g_initOnce, doInit); }

} // namespace

void initFromEnv() { ensureInit(); }

void setLevel(Cat cat, Level lvl) {
    int i = static_cast<int>(cat);
    if (i >= 0 && i < kCount)
        g_levels[i].store(static_cast<int>(lvl), std::memory_order_relaxed);
}

void setLevelAll(Level lvl) {
    for (auto& v : g_levels) v.store(static_cast<int>(lvl), std::memory_order_relaxed);
}

void setLogFile(const std::string& path) {
    std::lock_guard<std::mutex> lk(g_sinkMutex);
    if (g_file) { std::fclose(g_file); g_file = nullptr; }
    if (!path.empty()) g_file = std::fopen(path.c_str(), "ae");  // append, close-on-exec
}

Level level(Cat cat) {
    ensureInit();
    int i = static_cast<int>(cat);
    if (i < 0 || i >= kCount) return Level::Off;
    return static_cast<Level>(g_levels[i].load(std::memory_order_relaxed));
}

bool parseLevel(std::string_view s, Level& out) {
    // case-insensitive compare against the known names
    auto eq = [&](std::string_view name) {
        if (s.size() != name.size()) return false;
        for (size_t k = 0; k < s.size(); ++k)
            if (std::tolower(static_cast<unsigned char>(s[k])) != name[k]) return false;
        return true;
    };
    if (eq("off"))   { out = Level::Off;   return true; }
    if (eq("error")) { out = Level::Error; return true; }
    if (eq("warn") || eq("warning")) { out = Level::Warn; return true; }
    if (eq("info"))  { out = Level::Info;  return true; }
    if (eq("debug")) { out = Level::Debug; return true; }
    if (eq("trace")) { out = Level::Trace; return true; }
    return false;
}

const char* name(Cat c) {
    int i = static_cast<int>(c);
    return (i >= 0 && i < kCount) ? kCatNames[i] : "?";
}

const char* name(Level l) {
    switch (l) {
        case Level::Off: return "off";     case Level::Error: return "error";
        case Level::Warn: return "warn";   case Level::Info: return "info";
        case Level::Debug: return "debug"; case Level::Trace: return "trace";
    }
    return "?";
}

void write(Cat cat, Level lvl, std::string_view msg) {
    // Local wall-clock timestamp with milliseconds.
    using namespace std::chrono;
    auto now = system_clock::now();
    auto secs = time_point_cast<seconds>(now);
    int ms = static_cast<int>(duration_cast<milliseconds>(now - secs).count());
    std::time_t t = system_clock::to_time_t(now);
    std::tm tm{};
    localtime_r(&t, &tm);
    char ts[16];
    std::snprintf(ts, sizeof(ts), "%02d:%02d:%02d.%03d", tm.tm_hour, tm.tm_min, tm.tm_sec, ms);

    // A short thread tag helps when the tracer thread and UI thread interleave.
    auto tid = std::hash<std::thread::id>{}(std::this_thread::get_id()) & 0xffff;

    std::string line = std::format("{} {} [{}] t{:04x} {}\n",
        ts, levelChar(lvl), name(cat), static_cast<unsigned>(tid), msg);

    std::lock_guard<std::mutex> lk(g_sinkMutex);
    std::fwrite(line.data(), 1, line.size(), stderr);
    if (g_file) { std::fwrite(line.data(), 1, line.size(), g_file); std::fflush(g_file); }
}

} // namespace ce::log
