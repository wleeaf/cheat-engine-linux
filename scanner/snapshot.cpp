/// Memory snapshot — capture, diff, restore, serialise.

#include "scanner/snapshot.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <limits>

namespace ce {

namespace {
constexpr char kSnapshotMagic[8] = {'C','E','S','N','A','P','0','1'};

// The overlap of [aBase, aBase+aLen) and [bBase, bBase+bLen), as [lo, hi).
// Lengths are clamped so an end past the top of the address space cannot wrap.
bool overlap(uint64_t aBase, uint64_t aLen, uint64_t bBase, uint64_t bLen,
             uint64_t& lo, uint64_t& hi) {
    constexpr uint64_t top = std::numeric_limits<uint64_t>::max();
    const uint64_t aEnd = aBase + std::min(aLen, top - aBase);
    const uint64_t bEnd = bBase + std::min(bLen, top - bBase);
    lo = std::max(aBase, bBase);
    hi = std::min(aEnd, bEnd);
    return lo < hi;
}
} // namespace

Snapshot Snapshot::capture(ProcessHandle& proc, uint64_t maxBytes) {
    Snapshot snap;
    uint64_t budget = maxBytes;
    for (const auto& r : proc.queryRegions()) {
        if (!(r.protection & MemProt::Write)) continue;
        if (r.size == 0) continue;
        if (budget == 0) { snap.truncated_ = true; break; }

        SnapshotRegion saved;
        saved.base = r.base;
        saved.size = r.size;
        saved.protection = (uint32_t)r.protection;

        uint64_t take = std::min<uint64_t>(r.size, budget);
        if (take < r.size) snap.truncated_ = true;
        saved.bytes.resize((size_t)take);
        auto got = proc.read(r.base, saved.bytes.data(), (size_t)take);
        if (!got || *got == 0) continue;
        saved.bytes.resize(*got);
        budget -= (uint64_t)*got;
        snap.regions_.push_back(std::move(saved));
    }
    return snap;
}

Snapshot Snapshot::recapture(ProcessHandle& proc) const {
    Snapshot now;
    const auto live = proc.queryRegions();
    for (const auto& saved : regions_) {
        for (const auto& r : live) {
            if (!(r.protection & MemProt::Write) || r.size == 0) continue;
            uint64_t lo = 0, hi = 0;
            if (!overlap(saved.base, saved.bytes.size(), r.base, r.size, lo, hi)) continue;
            SnapshotRegion part;
            part.base = lo;
            part.size = hi - lo;
            part.protection = (uint32_t)r.protection;
            part.bytes.resize((size_t)(hi - lo));
            auto got = proc.read((uintptr_t)lo, part.bytes.data(), part.bytes.size());
            if (!got || *got == 0) continue;
            part.bytes.resize(*got);
            now.regions_.push_back(std::move(part));
        }
    }
    return now;
}

uint64_t Snapshot::byteCount() const {
    uint64_t total = 0;
    for (const auto& r : regions_) total += r.bytes.size();
    return total;
}

std::vector<Snapshot::ByteDiff> Snapshot::diff(const Snapshot& later, size_t maxDiffs,
                                               uint64_t* changedBytes) const {
    std::vector<ByteDiff> out;
    uint64_t changed = 0;
    // Walk both region lists in address order and compare wherever they
    // overlap, so [heap] growth or merged mappings do not hide a region.
    auto sorted = [](const std::vector<SnapshotRegion>& regions) {
        std::vector<const SnapshotRegion*> v;
        v.reserve(regions.size());
        for (const auto& r : regions) if (!r.bytes.empty()) v.push_back(&r);
        std::sort(v.begin(), v.end(), [](const SnapshotRegion* a, const SnapshotRegion* b) {
            return a->base < b->base;
        });
        return v;
    };
    const auto a = sorted(regions_), b = sorted(later.regions_);
    auto endOf = [](const SnapshotRegion* r) {
        return r->base + std::min<uint64_t>(r->bytes.size(),
                                            std::numeric_limits<uint64_t>::max() - r->base);
    };
    for (size_t i = 0, j = 0; i < a.size() && j < b.size();) {
        uint64_t lo = 0, hi = 0;
        if (overlap(a[i]->base, a[i]->bytes.size(), b[j]->base, b[j]->bytes.size(), lo, hi)) {
            const uint8_t* before = a[i]->bytes.data() + (lo - a[i]->base);
            const uint8_t* after = b[j]->bytes.data() + (lo - b[j]->base);
            for (uint64_t k = 0; k < hi - lo; ++k) {
                if (before[k] == after[k]) continue;
                ++changed;
                if (out.size() < maxDiffs) out.push_back({lo + k, before[k], after[k]});
            }
        }
        if (endOf(a[i]) <= endOf(b[j])) ++i; else ++j;
    }
    std::sort(out.begin(), out.end(), [](const ByteDiff& x, const ByteDiff& y) {
        return x.address < y.address;
    });
    if (changedBytes) *changedBytes = changed;
    return out;
}

uint64_t Snapshot::restore(ProcessHandle& proc) const {
    // Only mappings that are writable data now. A snapshot loaded from a file,
    // taken in another run or before a remap may cover code or unmapped pages;
    // a write there could reach the code-patching path, so it is skipped.
    std::vector<MemoryRegion> targets;
    for (const auto& r : proc.queryRegions())
        if ((r.protection & MemProt::Write) && !(r.protection & MemProt::Exec) && r.size)
            targets.push_back(r);
    uint64_t total = 0;
    for (const auto& saved : regions_) {
        for (const auto& t : targets) {
            uint64_t lo = 0, hi = 0;
            if (!overlap(saved.base, saved.bytes.size(), t.base, t.size, lo, hi)) continue;
            auto w = proc.write((uintptr_t)lo, saved.bytes.data() + (lo - saved.base), (size_t)(hi - lo));
            if (w) total += (uint64_t)*w;
        }
    }
    return total;
}

bool Snapshot::save(const std::string& path) const {
    if (regions_.size() > std::numeric_limits<uint32_t>::max()) return false;
    for (const auto& r : regions_)
        if (r.bytes.size() > std::numeric_limits<uint32_t>::max()) return false;
    FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) return false;
    auto writeAll = [&](const void* p, size_t n) {
        return std::fwrite(p, 1, n, f) == n;
    };
    bool ok = writeAll(kSnapshotMagic, sizeof(kSnapshotMagic));
    uint32_t count = (uint32_t)regions_.size();
    ok = ok && writeAll(&count, sizeof(count));
    for (const auto& r : regions_) {
        if (!ok) break;
        uint64_t base = r.base, size = r.size;
        uint32_t prot = r.protection;
        uint32_t byteCount = (uint32_t)r.bytes.size();
        ok = writeAll(&base, sizeof(base)) &&
             writeAll(&size, sizeof(size)) &&
             writeAll(&prot, sizeof(prot)) &&
             writeAll(&byteCount, sizeof(byteCount));
        if (ok && byteCount > 0) ok = writeAll(r.bytes.data(), byteCount);
    }
    if (std::fclose(f) != 0) ok = false;
    return ok;
}

bool Snapshot::load(const std::string& path, std::string* error) {
    if (error) error->clear();
    auto fail = [&](const char* msg) {
        if (error) *error = msg;
        return false;
    };
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return fail("open failed");
    auto readAll = [&](void* p, size_t n) {
        return std::fread(p, 1, n, f) == n;
    };
    char magic[8] = {};
    if (!readAll(magic, sizeof(magic)) ||
        std::memcmp(magic, kSnapshotMagic, sizeof(kSnapshotMagic)) != 0) {
        std::fclose(f);
        return fail("bad magic");
    }
    uint32_t count = 0;
    if (!readAll(&count, sizeof(count))) { std::fclose(f); return fail("truncated header"); }
    if (count > (1u << 24)) { std::fclose(f); return fail("region count too large"); }
    const long recordsStart = std::ftell(f);
    if (recordsStart < 0 || std::fseek(f, 0, SEEK_END) != 0) {
        std::fclose(f); return fail("seek failed");
    }
    const long end = std::ftell(f);
    if (end < recordsStart || std::fseek(f, recordsStart, SEEK_SET) != 0) {
        std::fclose(f); return fail("seek failed");
    }
    if (count > static_cast<uint64_t>(end - recordsStart) / 24) {
        std::fclose(f); return fail("truncated records");
    }
    // Commit only a complete, validated snapshot. Failed loads preserve the
    // checkpoint so callers cannot accidentally restore a partial file.
    std::vector<SnapshotRegion> loaded;
    loaded.reserve(std::min<uint32_t>(count, 4096));
    for (uint32_t i = 0; i < count; ++i) {
        uint64_t base = 0, size = 0;
        uint32_t prot = 0, byteCount = 0;
        if (!readAll(&base, sizeof(base)) ||
            !readAll(&size, sizeof(size)) ||
            !readAll(&prot, sizeof(prot)) ||
            !readAll(&byteCount, sizeof(byteCount))) {
            std::fclose(f); return fail("truncated record");
        }
        // Bound byteCount by the bytes actually left in the file instead of an
        // arbitrary per-region cap: save() writes a uint32 byteCount, so a
        // snapshot of a large region (>256 MB) could be saved but never loaded.
        // A corrupt/hostile size still cannot force a huge allocation, because
        // the file must really contain that many bytes.
        const long pos = std::ftell(f);
        if (pos < 0 || pos > end) { std::fclose(f); return fail("seek failed"); }
        if ((uint64_t)byteCount > (uint64_t)(end - pos)) {
            std::fclose(f); return fail("truncated bytes");
        }
        if (byteCount > size ||
            (size && size - 1 > std::numeric_limits<uint64_t>::max() - base)) {
            std::fclose(f); return fail("invalid region bounds");
        }
        SnapshotRegion r;
        r.base = base; r.size = size; r.protection = prot;
        r.bytes.resize(byteCount);
        if (byteCount > 0 && !readAll(r.bytes.data(), byteCount)) {
            std::fclose(f); return fail("truncated bytes");
        }
        loaded.push_back(std::move(r));
    }
    std::fclose(f);
    regions_ = std::move(loaded);
    return true;
}

} // namespace ce
