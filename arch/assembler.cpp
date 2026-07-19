#include "arch/assembler.hpp"
#include <keystone/keystone.h>
#include <stdexcept>
#include <cctype>

namespace {
// Capstone emits Intel size specifiers with the "ptr" keyword ("qword ptr [..]",
// "byte ptr [..]"), but Keystone (LLVM MC) rejects "ptr" and wants "qword [..]".
// Strip the standalone word "ptr" so disassembly text re-assembles. "ptr" is not
// a valid mnemonic/register/symbol, so removing it everywhere is safe.
std::string stripPtrKeyword(const std::string& in) {
    auto isWord = [](unsigned char c) { return std::isalnum(c) || c == '_'; };
    std::string out;
    out.reserve(in.size());
    size_t i = 0;
    while (i < in.size()) {
        bool boundaryL = (i == 0) || !isWord(static_cast<unsigned char>(in[i - 1]));
        if (boundaryL && i + 3 <= in.size() &&
            std::tolower(static_cast<unsigned char>(in[i]))     == 'p' &&
            std::tolower(static_cast<unsigned char>(in[i + 1])) == 't' &&
            std::tolower(static_cast<unsigned char>(in[i + 2])) == 'r' &&
            (i + 3 == in.size() || !isWord(static_cast<unsigned char>(in[i + 3])))) {
            i += 3;                                   // drop "ptr"
            if (i < in.size() && in[i] == ' ') ++i;   // and one trailing space
            continue;                                 // leaves "qword [" (single space)
        }
        out += in[i++];
    }
    return out;
}
} // namespace

namespace ce {

Assembler::Assembler(AsmArch arch) : arch_(arch) {
    ks_arch ka;
    ks_mode km;
    switch (arch) {
        case AsmArch::X86_32: ka = KS_ARCH_X86;   km = KS_MODE_32; break;
        case AsmArch::X86_64: ka = KS_ARCH_X86;   km = KS_MODE_64; break;
        case AsmArch::ARM32:  ka = KS_ARCH_ARM;   km = KS_MODE_ARM; break;
        case AsmArch::ARM64:  ka = KS_ARCH_ARM64; km = KS_MODE_LITTLE_ENDIAN; break;
    }

    ks_engine* ks;
    if (ks_open(ka, km, &ks) != KS_ERR_OK)
        throw std::runtime_error("Failed to initialize Keystone");

    // NASM syntax matches CE's assembler style; it applies to x86 only (ARM uses its
    // own syntax, and setting NASM on an ARM engine is rejected).
    if (arch == AsmArch::X86_32 || arch == AsmArch::X86_64)
        ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_NASM);
    handle_ = reinterpret_cast<size_t>(ks);
}

Assembler::~Assembler() {
    if (handle_)
        ks_close(reinterpret_cast<ks_engine*>(handle_));
}

std::expected<std::vector<uint8_t>, std::string>
Assembler::assemble(const std::string& code, uintptr_t address) {
    size_t stmts;
    return assembleEx(code, address, stmts);
}

std::expected<std::vector<uint8_t>, std::string>
Assembler::assembleEx(const std::string& code, uintptr_t address, size_t& statementsOut) {
    auto* ks = reinterpret_cast<ks_engine*>(handle_);
    unsigned char* encoded = nullptr;
    size_t size = 0;
    size_t count = 0;

    std::string normalized = stripPtrKeyword(code);
    int r = ks_asm(ks, normalized.c_str(), address, &encoded, &size, &count);
    if (r != 0) {
        auto err = ks_errno(ks);
        return std::unexpected(std::string("Assembly error: ") + ks_strerror(err));
    }

    // Free the Keystone-allocated buffer on every exit path, including if the
    // vector construction below throws (OOM).
    struct EncodedGuard {
        unsigned char* p;
        ~EncodedGuard() { if (p) ks_free(p); }
    } guard{encoded};

    // Keystone can return KS_ERR_OK yet emit zero bytes for input it silently
    // rejects (e.g. some Capstone-style "qword ptr [reg+disp], reg64" forms).
    // Treat "non-blank input assembled to nothing" as a failure — otherwise
    // callers see success with an empty buffer (the GUI would then NOP-pad over
    // the original instruction, corrupting code).
    if (size == 0) {
        bool hasContent = code.find_first_not_of(" \t\r\n") != std::string::npos;
        if (hasContent)
            return std::unexpected(std::string(
                "Assembly produced no output (unsupported or invalid syntax)"));
    }

    std::vector<uint8_t> result(encoded, encoded + size);
    statementsOut = count;
    return result;
}

} // namespace ce
