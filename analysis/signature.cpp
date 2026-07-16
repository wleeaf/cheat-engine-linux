#include "analysis/signature.hpp"
#include "arch/disassembler.hpp"

#include <algorithm>
#include <cstdio>
#include <vector>

namespace ce {

namespace {

// A pattern byte: a concrete value or a wildcard.
struct PatByte { uint8_t value; bool wild; };

// Count matches of `pat` in `region`, stopping once a second is found. Sets
// `firstPos` to the first match offset.
int countMatches(const std::vector<PatByte>& pat, const std::vector<uint8_t>& region,
                 size_t& firstPos) {
    const size_t pl = pat.size();
    if (pl == 0 || pl > region.size()) return 0;
    int cnt = 0;
    for (size_t p = 0; p + pl <= region.size(); ++p) {
        bool m = true;
        for (size_t j = 0; j < pl; ++j)
            if (!pat[j].wild && region[p + j] != pat[j].value) { m = false; break; }
        if (m) {
            if (cnt == 0) firstPos = p;
            if (++cnt > 1) break;
        }
    }
    return cnt;
}

std::string toAob(const std::vector<PatByte>& pat) {
    // Trim trailing wildcards (they add no specificity).
    size_t end = pat.size();
    while (end > 0 && pat[end - 1].wild) --end;
    std::string s;
    for (size_t j = 0; j < end; ++j) {
        if (j) s += ' ';
        if (pat[j].wild) { s += "??"; continue; }
        char hb[3];
        std::snprintf(hb, sizeof(hb), "%02X", pat[j].value);
        s += hb;
    }
    return s;
}

} // namespace

SignatureResult makeSignature(ProcessHandle& proc, uintptr_t address,
                              uintptr_t regionBase, size_t regionSize, size_t maxBytes) {
    SignatureResult out;
    if (regionSize == 0 || address < regionBase || address >= regionBase + regionSize)
        return out;

    // Read the region once (this is the search space for uniqueness).
    const size_t cap = std::min<size_t>(regionSize, 128u * 1024 * 1024);
    std::vector<uint8_t> region(cap);
    auto rr = proc.read(regionBase, region.data(), cap);
    if (!rr || *rr == 0) return out;
    region.resize(*rr);

    const size_t codeOff = static_cast<size_t>(address - regionBase);
    if (codeOff >= region.size()) return out;

    Arch arch = proc.runs32BitCode() ? Arch::X86_32 : Arch::X86_64;
    Disassembler dis(arch);
    const size_t codeLen = std::min<size_t>(region.size() - codeOff, maxBytes + 16);
    auto insns = dis.disassemble(address,
        std::span<const uint8_t>(region.data() + codeOff, codeLen), 0, /*emitDataBytes=*/true);

    std::vector<PatByte> pat;
    for (const auto& in : insns) {
        const bool ripWild = in.ripTarget != 0;
        for (size_t k = 0; k < in.bytes.size(); ++k) {
            bool wild = false;
            // rip-relative displacement: always relocatable.
            if (ripWild && in.dispSize && k >= in.dispOffset &&
                k < static_cast<size_t>(in.dispOffset) + in.dispSize)
                wild = true;
            // address-sized immediate that looks like a pointer (skip stack offsets
            // / small constants, which are stable and add specificity).
            if (in.immSize >= 4 && k >= in.immOffset &&
                k < static_cast<size_t>(in.immOffset) + in.immSize) {
                uint64_t v = 0;
                for (size_t b = 0; b < in.immSize && b < 8; ++b)
                    v |= static_cast<uint64_t>(in.bytes[in.immOffset + b]) << (8 * b);
                if (v >= 0x10000 && v <= 0x7fffffffffffull) wild = true;
            }
            pat.push_back({in.bytes[k], wild});
        }

        size_t firstPos = 0;
        if (countMatches(pat, region, firstPos) == 1) {
            out.unique = (regionBase + firstPos == address);
            break;
        }
        if (pat.size() >= maxBytes) break;
    }

    if (!out.unique) {
        size_t firstPos = 0;
        out.unique = (countMatches(pat, region, firstPos) == 1 && regionBase + firstPos == address);
    }
    out.pattern = toAob(pat);
    out.length = pat.size();
    return out;
}

SignatureResult makeSignature(ProcessHandle& proc, uintptr_t address, size_t maxBytes) {
    auto region = proc.queryRegion(address);
    if (!region) return {};
    return makeSignature(proc, address, region->base, region->size, maxBytes);
}

} // namespace ce
