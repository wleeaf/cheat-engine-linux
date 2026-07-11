#pragma once
/// x86 Assembler wrapping Keystone library.

#include <cstdint>
#include <string>
#include <vector>
#include <expected>
#include <system_error>

namespace ce {

enum class AsmArch { X86_32, X86_64 };

class Assembler {
public:
    explicit Assembler(AsmArch arch = AsmArch::X86_64);
    ~Assembler();

    Assembler(const Assembler&) = delete;
    Assembler& operator=(const Assembler&) = delete;

    /// Assemble a single instruction or block at the given address.
    /// Returns the assembled bytes, or an error string.
    std::expected<std::vector<uint8_t>, std::string>
    assemble(const std::string& code, uintptr_t address = 0);

    /// Assemble and return the number of statements processed.
    std::expected<std::vector<uint8_t>, std::string>
    assembleEx(const std::string& code, uintptr_t address, size_t& statementsOut);

    AsmArch arch() const { return arch_; }

private:
    AsmArch arch_;
    size_t handle_ = 0;
};

} // namespace ce
