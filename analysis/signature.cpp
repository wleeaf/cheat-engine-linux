#include "analysis/signature.hpp"
#include "arch/disassembler.hpp"
#include "arch/target_arch.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <vector>

namespace ce {

namespace {

// A pattern byte: a concrete value or a wildcard.
struct PatByte { uint8_t value; bool wild; };

// The pattern without its trailing wildcards: what is emitted, and so what
// must be unique.
std::vector<PatByte> trimmed(std::vector<PatByte> pat) {
    while (!pat.empty() && pat.back().wild) pat.pop_back();
    return pat;
}

// Count matches of `pat` in a buffer holding [base, ...), stopping once a
// second is found. Sets `first` to the first match's address.
int countInBuffer(const std::vector<PatByte>& pat, const std::vector<uint8_t>& buffer, uintptr_t base, uintptr_t& first) {
    const size_t pl = pat.size();
    if (pl == 0 || pl > buffer.size()) return 0;
    int cnt = 0;
    for (size_t p = 0; p + pl <= buffer.size(); ++p) {
        bool m = true;
        for (size_t j = 0; j < pl; ++j)
            if (!pat[j].wild && buffer[p + j] != pat[j].value) { m = false; break; }
        if (m) {
            if (cnt == 0) first = base + p;
            if (++cnt > 1) break;
        }
    }
    return cnt;
}

// The same over [base, base + size) of the process, read in overlapping
// chunks: for regions too large to keep in memory.
int countMatches(ProcessHandle& proc, const std::vector<PatByte>& pat, uintptr_t base, size_t size,
                 uintptr_t& first, bool& incomplete) {
    const size_t pl = pat.size();
    if (pl == 0 || pl > size) return 0;
    constexpr size_t kChunk = size_t(16) << 20;
    std::vector<uint8_t> buffer;
    int cnt = 0;
    for (size_t offset = 0; offset + pl <= size;) {
        const size_t want = std::min(kChunk + pl - 1, size - offset);
        buffer.resize(want);
        auto got = proc.read(base + offset, buffer.data(), want);
        if (!got || *got < want) incomplete = true;
        if (!got || *got < pl) break;
        const size_t limit = *got - pl + 1;
        for (size_t p = 0; p < limit; ++p) {
            bool m = true;
            for (size_t j = 0; j < pl; ++j)
                if (!pat[j].wild && buffer[p + j] != pat[j].value) { m = false; break; }
            if (m) {
                if (cnt == 0) first = base + offset + p;
                if (++cnt > 1) return cnt;
            }
        }
        if (*got < want) break;
        offset += limit;
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

struct SearchRange { uintptr_t base; size_t size; };

// Build the signature for `address`, which lies in `codeRegion`, and check its
// uniqueness across every range in `scope`.
SignatureResult makeSignatureIn(ProcessHandle& proc, uintptr_t address, SearchRange codeRegion,
                                const std::vector<SearchRange>& scope, size_t maxBytes) {
    SignatureResult out;
    if (codeRegion.size == 0 || address < codeRegion.base || address - codeRegion.base >= codeRegion.size)
        return out;

    const size_t codeOff = static_cast<size_t>(address - codeRegion.base);
    std::vector<uint8_t> code(std::min<size_t>(codeRegion.size - codeOff, maxBytes + 16));
    auto rr = proc.read(address, code.data(), code.size());
    if (!rr || *rr == 0) return out;
    code.resize(*rr);

    auto arch = disassemblerArchFor(proc, address);
    if (!arch) return out;
    Disassembler dis(*arch);
    auto insns = dis.disassemble(address, std::span<const uint8_t>(code.data(), code.size()), 0, /*emitDataBytes=*/true);

    // Ranges of ordinary total size are read once and searched in memory;
    // larger ones are searched in chunks from the process (a large .text is
    // hundreds of MB). Any short read means uniqueness cannot be confirmed.
    bool incomplete = false;
    size_t total = 0;
    for (const auto& r : scope) total += std::min(r.size, SIZE_MAX - total);
    const bool useCache = total <= (size_t(128) << 20);
    std::vector<std::vector<uint8_t>> cached(scope.size());
    if (useCache) {
        for (size_t i = 0; i < scope.size(); ++i) {
            cached[i].resize(scope[i].size);
            auto got = proc.read(scope[i].base, cached[i].data(), cached[i].size());
            const size_t n = got ? std::min(*got, cached[i].size()) : 0;
            if (n < cached[i].size()) incomplete = true;
            cached[i].resize(n);
        }
    }
    auto count = [&](const std::vector<PatByte>& pattern, uintptr_t& first) {
        int found = 0;
        for (size_t i = 0; i < scope.size() && found < 2; ++i) {
            uintptr_t at = 0;
            const int c = useCache ? countInBuffer(pattern, cached[i], scope[i].base, at)
                                   : countMatches(proc, pattern, scope[i].base, scope[i].size, at, incomplete);
            if (c && !found) first = at;
            found += c;
        }
        return found;
    };

    std::vector<PatByte> pat;
    for (const auto& in : insns) {
        const bool ripWild = in.ripTarget != 0;
        for (size_t k = 0; k < in.bytes.size(); ++k) {
            bool wild = false;
            // rip-relative displacement: always relocatable.
            if (ripWild && in.dispSize && k >= in.dispOffset &&
                k < static_cast<size_t>(in.dispOffset) + in.dispSize)
                wild = true;
            // An absolute address in a displacement (32-bit code reaches globals
            // as [abs32] or [reg*4+table]): it moves when the module is rebased.
            if (!ripWild && in.dispSize == 4 && k >= in.dispOffset && k < static_cast<size_t>(in.dispOffset) + 4) {
                uint32_t disp = 0;
                for (size_t b = 0; b < 4; ++b) disp |= static_cast<uint32_t>(in.bytes[in.dispOffset + b]) << (8 * b);
                if ((in.memory.present && in.memory.baseReg.empty()) || (disp >= 0x10000 && disp < 0xFFFF0000u)) wild = true;
            }
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

        uintptr_t first = 0;
        if (count(trimmed(pat), first) == 1) {
            out.unique = (first == address);
            break;
        }
        if (pat.size() >= maxBytes) break;
    }

    pat = trimmed(pat);
    if (!out.unique) {
        uintptr_t first = 0;
        out.unique = (count(pat, first) == 1 && first == address);
    }
    out.incomplete = incomplete;
    if (incomplete) out.unique = false;
    out.pattern = toAob(pat);
    out.length = pat.size();
    return out;
}

} // namespace

SignatureResult makeSignature(ProcessHandle& proc, uintptr_t address,
                              uintptr_t regionBase, size_t regionSize, size_t maxBytes) {
    if (regionSize == 0 || regionSize - 1 > UINTPTR_MAX - regionBase) return {};
    const SearchRange region{regionBase, regionSize};
    return makeSignatureIn(proc, address, region, {region}, maxBytes);
}

SignatureResult makeSignature(ProcessHandle& proc, uintptr_t address, size_t maxBytes) {
    auto region = proc.queryRegion(address);
    if (!region) return {};
    // A file-backed mapping is one piece of a module: the signature must be
    // unique across all of its readable mappings, which is what AOBScanModule
    // searches. Anonymous memory (JIT code) has only its own mapping.
    std::vector<SearchRange> scope;
    const bool fileBacked = !region->path.empty() && region->path.front() == '/';
    if (fileBacked)
        for (const auto& r : proc.queryRegions())
            if (r.path == region->path && (r.protection & MemProt::Read) && r.size)
                scope.push_back({r.base, r.size});
    const bool moduleWide = !scope.empty();
    if (!moduleWide) scope.push_back({region->base, region->size});
    auto out = makeSignatureIn(proc, address, {region->base, region->size}, scope, maxBytes);
    out.moduleWide = moduleWide;
    return out;
}

} // namespace ce
