#pragma once
/// Trainer generator — creates standalone executables from cheat tables.

#include "core/ct_file.hpp"
#include <string>

namespace ce {

class TrainerGenerator {
public:
    /// Generate a standalone C trainer source from a cheat table.
    /// Returns the generated C code as a string.
    std::string generateSource(const CheatTable& table) const;

    /// Generate and compile a trainer binary.
    /// Returns empty string on success, error message on failure.
    std::string generateBinary(const CheatTable& table, const std::string& outputPath) const;
};

} // namespace ce
