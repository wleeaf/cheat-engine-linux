#pragma once
/// Decode x86/x86-64 EFLAGS/RFLAGS into the set of named status/control flags, the
/// way a debugger shows them next to the register value. Qt-free so both the GUI
/// (debugger register panel) and headless tools/tests can use it.

#include <optional>
#include <string>
#include <cstdint>

namespace ce {

/// Space-separated names of the flags that are set in `rflags`, in the conventional
/// order CF PF AF ZF SF TF IF DF OF. Reserved bits (e.g. bit 1, always 1) are not
/// flags and are ignored. Returns "" when no named flag is set.
inline std::string describeEflags(uint64_t rflags) {
    struct Flag { uint64_t bit; const char* name; };
    static const Flag kFlags[] = {
        {1ull << 0,  "CF"},   // carry
        {1ull << 2,  "PF"},   // parity
        {1ull << 4,  "AF"},   // auxiliary carry
        {1ull << 6,  "ZF"},   // zero
        {1ull << 7,  "SF"},   // sign
        {1ull << 8,  "TF"},   // trap
        {1ull << 9,  "IF"},   // interrupt enable
        {1ull << 10, "DF"},   // direction
        {1ull << 11, "OF"},   // overflow
    };
    std::string out;
    for (const auto& f : kFlags)
        if (rflags & f.bit) { if (!out.empty()) out += ' '; out += f.name; }
    return out;
}

/// Whether an x86 conditional jump (`mnemonic`, lowercase Capstone form like "je",
/// "jne", "jbe", "jg") would be taken given `rflags`. `jmp` is always taken. Returns
/// nullopt for anything that is not a flag-testing jump (including jcxz/jecxz/jrcxz,
/// which depend on a register, not the flags). A debugger annotates the paused line
/// with this so you can see, at a glance, whether a branch is about to be taken.
inline std::optional<bool> conditionalJumpTaken(const std::string& mnemonic, uint64_t rflags) {
    const bool cf = rflags & (1ull << 0);
    const bool pf = rflags & (1ull << 2);
    const bool zf = rflags & (1ull << 6);
    const bool sf = rflags & (1ull << 7);
    const bool of = rflags & (1ull << 11);
    const std::string& m = mnemonic;

    if (m == "jmp")                          return true;
    if (m == "je"  || m == "jz")             return zf;
    if (m == "jne" || m == "jnz")            return !zf;
    if (m == "js")                           return sf;
    if (m == "jns")                          return !sf;
    if (m == "jo")                           return of;
    if (m == "jno")                          return !of;
    if (m == "jp"  || m == "jpe")            return pf;
    if (m == "jnp" || m == "jpo")            return !pf;
    if (m == "jc"  || m == "jb"  || m == "jnae") return cf;
    if (m == "jnc" || m == "jae" || m == "jnb")  return !cf;
    if (m == "ja"  || m == "jnbe")           return !cf && !zf;
    if (m == "jbe" || m == "jna")            return cf || zf;
    if (m == "jg"  || m == "jnle")           return !zf && (sf == of);
    if (m == "jge" || m == "jnl")            return sf == of;
    if (m == "jl"  || m == "jnge")           return sf != of;
    if (m == "jle" || m == "jng")            return zf || (sf != of);
    return std::nullopt;
}

} // namespace ce
