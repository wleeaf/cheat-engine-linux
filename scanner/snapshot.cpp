/// Memory snapshot — capture, diff, restore, serialise.

#include "scanner/snapshot.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <unordered_map>

namespace ce {

namespace {
constexpr char kSnapshotMagic[8] = {'C','E','S','N','A','P','0','1'};
}

Snapshot Snapshot::capture(ProcessHandle& proc, uint64_t maxBytes) {
    Snapshot snap;
    uint64_t budget = maxBytes;
    for (const auto& r : proc.queryRegions()) {
        if (!(r.protection & MemProt::Write)) continue;
        if (r.size == 0) continue;

        SnapshotRegion saved;
        saved.base = r.base;
        saved.size = r.size;
        saved.protection = (uint32_t)r.protection;

        uint64_t take = std::min<uint64_t>(r.size, budget);
        if (take == 0) break;
        saved.bytes.resize((size_t)take);
        auto got = proc.read(r.base, saved.bytes.data(), (size_t)take);
        if (!got) continue;
        saved.bytes.resize(*got);
        budget -= (uint64_t)*got;
        snap.regions_.push_back(std::move(saved));
        if (budget == 0) break;
    }
    return snap;
}

uint64_t Snapshot::byteCount() const {
    uint64_t total = 0;
    for (const auto& r : regions_) total += r.bytes.size();
    return total;
}

std::vector<Snapshot::ByteDiff> Snapshot::diff(const Snapshot& later) const {
    std::vector<ByteDiff> out;
    // Index `later` by base for O(1) lookup; we only diff regions that share
    // both base and size. (Region bases are unique, so base is a safe key and
    // we confirm the size on lookup.)
    std::unordered_map<uint64_t, const SnapshotRegion*> byBase;
    byBase.reserve(later.regions_.size());
    for (const auto& b : later.regions_)
        byBase.emplace(b.base, &b);

    for (const auto& a : regions_) {
        auto it = byBase.find(a.base);
        if (it == byBase.end()) continue;
        const SnapshotRegion* matched = it->second;
        if (matched->size != a.size) continue;
        size_t n = std::min(a.bytes.size(), matched->bytes.size());
        for (size_t i = 0; i < n; ++i) {
            if (a.bytes[i] != matched->bytes[i])
                out.push_back({a.base + i, a.bytes[i], matched->bytes[i]});
        }
    }
    return out;
}

uint64_t Snapshot::restore(ProcessHandle& proc) const {
    uint64_t total = 0;
    for (const auto& r : regions_) {
        if (r.bytes.empty()) continue;
        auto w = proc.write(r.base, r.bytes.data(), r.bytes.size());
        if (w) total += (uint64_t)*w;
    }
    return total;
}

bool Snapshot::save(const std::string& path) const {
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
    std::fclose(f);
    return ok;
}

bool Snapshot::load(const std::string& path, std::string* error) {
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
    regions_.clear();
    regions_.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        uint64_t base = 0, size = 0;
        uint32_t prot = 0, byteCount = 0;
        if (!readAll(&base, sizeof(base)) ||
            !readAll(&size, sizeof(size)) ||
            !readAll(&prot, sizeof(prot)) ||
            !readAll(&byteCount, sizeof(byteCount))) {
            std::fclose(f); return fail("truncated record");
        }
        if (byteCount > (1u << 28)) { std::fclose(f); return fail("byte count out of range"); }
        SnapshotRegion r;
        r.base = base; r.size = size; r.protection = prot;
        r.bytes.resize(byteCount);
        if (byteCount > 0 && !readAll(r.bytes.data(), byteCount)) {
            std::fclose(f); return fail("truncated bytes");
        }
        regions_.push_back(std::move(r));
    }
    std::fclose(f);
    return true;
}

} // namespace ce
