#pragma once
/// Decode x86/x86-64 EFLAGS/RFLAGS into the set of named status/control flags, the
/// way a debugger shows them next to the register value. Qt-free so both the GUI
/// (debugger register panel) and headless tools/tests can use it.

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

} // namespace ce
