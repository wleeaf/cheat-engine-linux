#pragma once
/// One line of /proc/<pid>/maps:
///   start-end perms offset dev inode [path]
/// The first five fields are separated by runs of blanks; the path is the
/// rest of the line, kept as it is (the kernel pads before it, never after,
/// so a trailing space belongs to the file name).

#include <charconv>
#include <cstdint>
#include <optional>
#include <string_view>

namespace ce::os {

struct ProcMapsLine {
    uint64_t start = 0;
    uint64_t end = 0;
    std::string_view perms;    // "rwxp"
    uint64_t offset = 0;       // 0 when the field is missing or not hex
    std::string_view device;   // "fd:01"
    uint64_t inode = 0;
    std::string_view path;     // empty for an anonymous mapping
};

/// nullopt when the address range does not parse or ends before it starts.
/// The views point into `line`.
inline std::optional<ProcMapsLine> parseProcMapsLine(std::string_view line) {
    auto blank = [](char c) { return c == ' ' || c == '\t'; };
    size_t pos = 0;
    auto skipBlanks = [&] { while (pos < line.size() && blank(line[pos])) ++pos; };
    auto field = [&] {
        skipBlanks();
        const size_t begin = pos;
        while (pos < line.size() && !blank(line[pos])) ++pos;
        return line.substr(begin, pos - begin);
    };
    auto number = [](std::string_view text, uint64_t& value, int base) {
        const char* last = text.data() + text.size();
        auto [stop, error] = std::from_chars(text.data(), last, value, base);
        return !text.empty() && error == std::errc{} && stop == last;
    };
    const std::string_view range = field();
    ProcMapsLine out;
    out.perms = field();
    const std::string_view offset = field();
    out.device = field();
    const std::string_view inode = field();
    skipBlanks();
    out.path = line.substr(pos);
    const size_t dash = range.find('-');
    if (dash == std::string_view::npos || !number(range.substr(0, dash), out.start, 16) ||
        !number(range.substr(dash + 1), out.end, 16) || out.end < out.start)
        return std::nullopt;
    if (!number(offset, out.offset, 16)) out.offset = 0;
    if (!number(inode, out.inode, 10)) out.inode = 0;
    return out;
}

} // namespace ce::os
