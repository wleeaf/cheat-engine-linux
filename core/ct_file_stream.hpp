#pragma once
#include <iosfwd>
namespace ce {
struct CheatTable;
// Serialize into a caller-owned stream. The caller flushes and commits its
// destination, which lets GUI saves use an atomic file without an extra copy.
bool writeTableXml(const CheatTable& table, std::ostream& output);
bool writeTableJson(const CheatTable& table, std::ostream& output);
}
