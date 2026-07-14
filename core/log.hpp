#pragma once
/// Lightweight diagnostic logging for cecore (Qt-free, shared by the CLI, GUI and
/// tests). Silent by default; turn it up at runtime with no rebuild:
///
///   CE_LOG=debug                 all categories at Debug
///   CE_LOG=ptrace:trace,ct:debug,*:warn   per-category, `*` sets the default
///   CE_LOG_FILE=/tmp/ce.log      also append every line to this file
///
/// Call sites use std::format and are compiled inline so nothing is formatted
/// when the category/level is disabled (one relaxed atomic load + a branch):
///
///   ce::log::debug(ce::log::Cat::Ptrace, "read {} bytes @ {:#x} -> {}", n, addr, ret);

#include <atomic>
#include <format>
#include <string>
#include <string_view>
#include <utility>

namespace ce::log {

enum class Level : int { Off = 0, Error, Warn, Info, Debug, Trace };

// One tag per subsystem so `CE_LOG=ptrace:trace` can single out a noisy area.
// Keep in sync with kCatNames in log.cpp.
enum class Cat : int {
    General = 0, Scan, Memory, Ptrace, Debugger, Ct, Lua, Symbols, Ceserver, Gui,
    Count_
};

/// Parse CE_LOG / CE_LOG_FILE from the environment. Idempotent; also runs lazily
/// on first use, so calling it from main() is optional (but makes intent clear).
void initFromEnv();

void setLevel(Cat cat, Level level);
void setLevelAll(Level level);
void setLogFile(const std::string& path);   // "" disables the file sink
Level level(Cat cat);

/// Parse a level name ("off"/"error"/"warn"/"info"/"debug"/"trace", any case);
/// returns Level::Off-.. or std::nullopt if unrecognized (for --log-level).
bool parseLevel(std::string_view name, Level& out);

const char* name(Cat c);
const char* name(Level l);

inline bool enabled(Cat cat, Level lvl) {
    return static_cast<int>(lvl) <= static_cast<int>(level(cat));
}

/// Emit an already-formatted line (timestamp/level/category prefix added here).
/// Prefer the level helpers below; this is the sink entry point.
void write(Cat cat, Level lvl, std::string_view msg);

template <class... Args>
inline void logf(Cat cat, Level lvl, std::format_string<Args...> fmt, Args&&... args) {
    if (!enabled(cat, lvl)) return;                 // no formatting when disabled
    write(cat, lvl, std::format(fmt, std::forward<Args>(args)...));
}

template <class... Args>
inline void error(Cat c, std::format_string<Args...> f, Args&&... a) {
    logf(c, Level::Error, f, std::forward<Args>(a)...);
}
template <class... Args>
inline void warn(Cat c, std::format_string<Args...> f, Args&&... a) {
    logf(c, Level::Warn, f, std::forward<Args>(a)...);
}
template <class... Args>
inline void info(Cat c, std::format_string<Args...> f, Args&&... a) {
    logf(c, Level::Info, f, std::forward<Args>(a)...);
}
template <class... Args>
inline void debug(Cat c, std::format_string<Args...> f, Args&&... a) {
    logf(c, Level::Debug, f, std::forward<Args>(a)...);
}
template <class... Args>
inline void trace(Cat c, std::format_string<Args...> f, Args&&... a) {
    logf(c, Level::Trace, f, std::forward<Args>(a)...);
}

} // namespace ce::log
