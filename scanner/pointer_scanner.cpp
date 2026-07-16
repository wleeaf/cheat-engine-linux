#include "scanner/pointer_scanner.hpp"
#include "scanner/cuda_search.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unordered_map>
#include <queue>
#include <set>
#include <stdexcept>

namespace ce {

std::string PointerPath::toString() const {
    std::string result;
    // Build from inside out: [[module+base]+off1]+off2
    for (int i = (int)offsets.size() - 1; i >= 0; --i)
        result += "[";

    char buf[64];
    snprintf(buf, sizeof(buf), "%s+%lx", module.c_str(), baseOffset);
    result += buf;

    for (auto off : offsets) {
        result += "]";
        if (off >= 0)
            snprintf(buf, sizeof(buf), "+0x%x", off);
        else
            snprintf(buf, sizeof(buf), "-0x%x", -off);
        result += buf;
    }
    return result;
}

// ── Reverse pointer map ──
// Maps: pointed_to_address → vector of (address_containing_pointer)
// We use a sorted vector for cache-friendly binary search.

static bool isInRange(uintptr_t addr, const std::vector<MemoryRegion>& regions) {
    for (auto& r : regions)
        if (addr >= r.base && addr < r.base + r.size)
            return true;
    return false;
}

std::vector<PointerScanConfig> makePointerScanShards(const PointerScanConfig& base, size_t shardCount) {
    if (shardCount == 0)
        throw std::invalid_argument("pointer scan shard count must be greater than zero");

    std::vector<PointerScanConfig> shards;
    shards.reserve(shardCount);
    for (size_t i = 0; i < shardCount; ++i) {
        auto shard = base;
        shard.shardIndex = i;
        shard.shardCount = shardCount;
        shards.push_back(shard);
    }
    return shards;
}

// ── PointerMap ──

namespace {
constexpr char kPointerMapMagic[8] = {'P', 'M', 'A', 'P', '0', '0', '0', '1'};
}

void PointerMap::setEntries(std::vector<Entry> entries) {
    byTarget_ = std::move(entries);
    std::sort(byTarget_.begin(), byTarget_.end(),
              [](const Entry& a, const Entry& b) { return a.pointsTo < b.pointsTo; });
    byLocated_.resize(byTarget_.size());
    for (size_t i = 0; i < byLocated_.size(); ++i) byLocated_[i] = static_cast<uint32_t>(i);
    std::sort(byLocated_.begin(), byLocated_.end(), [&](uint32_t a, uint32_t b) {
        return byTarget_[a].locatedAt < byTarget_[b].locatedAt;
    });
}

std::optional<uintptr_t> PointerMap::valueAt(uintptr_t addr) const {
    auto lo = std::lower_bound(byLocated_.begin(), byLocated_.end(), addr,
        [&](uint32_t idx, uintptr_t a) { return byTarget_[idx].locatedAt < a; });
    if (lo != byLocated_.end() && byTarget_[*lo].locatedAt == addr)
        return byTarget_[*lo].pointsTo;
    return std::nullopt;
}

uintptr_t PointerMap::moduleBase(const std::string& name) const {
    for (const auto& m : modules_)
        if (m.name == name) return m.base;
    return 0;
}

uintptr_t PointerMap::resolve(const PointerPath& path) const {
    uintptr_t base = moduleBase(path.module);
    if (base == 0) return 0;
    uintptr_t addr = base + path.baseOffset;
    for (auto off : path.offsets) {
        auto v = valueAt(addr);
        if (!v || *v == 0) return 0;
        addr = *v + off;   // off is int32_t; two's-complement add handles negatives
    }
    return addr;
}

bool PointerMap::save(const std::string& path) const {
    FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) return false;
    auto w = [&](const void* p, size_t n) { return std::fwrite(p, 1, n, f) == n; };
    bool ok = w(kPointerMapMagic, sizeof(kPointerMapMagic));
    uint64_t nEntries = byTarget_.size(), nModules = modules_.size();
    ok = ok && w(&nEntries, 8) && w(&nModules, 8);
    for (const auto& e : byTarget_) {
        if (!ok) break;
        uint64_t pt = e.pointsTo, la = e.locatedAt;
        ok = w(&pt, 8) && w(&la, 8);
    }
    for (const auto& m : modules_) {
        if (!ok) break;
        uint64_t base = m.base, size = m.size;
        uint32_t nameLen = static_cast<uint32_t>(m.name.size());
        uint8_t is64 = m.is64bit ? 1 : 0;
        ok = w(&base, 8) && w(&size, 8) && w(&nameLen, 4) && w(&is64, 1);
        if (ok && nameLen) ok = w(m.name.data(), nameLen);
    }
    std::fclose(f);
    return ok;
}

PointerMap PointerMap::load(const std::string& path, std::string* error) {
    auto fail = [&](const char* m) { if (error) *error = m; return PointerMap{}; };
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return fail("open failed");
    auto r = [&](void* p, size_t n) { return std::fread(p, 1, n, f) == n; };
    char magic[8] = {};
    if (!r(magic, 8) || std::memcmp(magic, kPointerMapMagic, 8) != 0) {
        std::fclose(f); return fail("bad magic");
    }
    uint64_t nEntries = 0, nModules = 0;
    if (!r(&nEntries, 8) || !r(&nModules, 8)) { std::fclose(f); return fail("truncated header"); }
    if (nEntries > (1ull << 32) || nModules > (1u << 20)) { std::fclose(f); return fail("counts too large"); }
    std::vector<Entry> entries;
    entries.reserve(std::min<uint64_t>(nEntries, 1u << 20));
    for (uint64_t i = 0; i < nEntries; ++i) {
        uint64_t pt = 0, la = 0;
        if (!r(&pt, 8) || !r(&la, 8)) { std::fclose(f); return fail("truncated entries"); }
        entries.push_back({static_cast<uintptr_t>(pt), static_cast<uintptr_t>(la)});
    }
    std::vector<ModuleInfo> mods;
    mods.reserve(std::min<uint64_t>(nModules, 4096));
    for (uint64_t i = 0; i < nModules; ++i) {
        uint64_t base = 0, size = 0;
        uint32_t nameLen = 0;
        uint8_t is64 = 0;
        if (!r(&base, 8) || !r(&size, 8) || !r(&nameLen, 4) || !r(&is64, 1)) {
            std::fclose(f); return fail("truncated module");
        }
        if (nameLen > (1u << 16)) { std::fclose(f); return fail("module name too long"); }
        ModuleInfo m;
        m.base = static_cast<uintptr_t>(base);
        m.size = static_cast<size_t>(size);
        m.is64bit = is64 != 0;
        m.name.resize(nameLen);
        if (nameLen && !r(m.name.data(), nameLen)) { std::fclose(f); return fail("truncated module name"); }
        mods.push_back(std::move(m));
    }
    std::fclose(f);
    PointerMap map;
    map.setModules(std::move(mods));
    map.setEntries(std::move(entries));
    return map;
}

PointerMap buildPointerMap(ProcessHandle& proc, const PointerScanConfig& config,
                           std::atomic<bool>* cancel, std::atomic<float>* progress,
                           float progressSpan) {
    auto cancelled = [&] { return cancel && cancel->load(std::memory_order_relaxed); };
    auto regions = proc.queryRegions();

    // ── Read all memory and find pointer-like values ──
    std::vector<PointerMap::Entry> entries;
    entries.reserve(1024 * 1024); // Preallocate ~16MB

    size_t totalMem = 0;
    for (auto& r : regions) totalMem += r.size;
    if (totalMem == 0) totalMem = 1;

    size_t scanned = 0;
    std::vector<uint8_t> buf;

    // Pointer-shaped value range: anything that could plausibly be a userspace
    // pointer on x86_64 / aarch64 Linux. We narrow further via isInRange on
    // the candidates returned by the bulk filter.
    constexpr uint64_t kPtrLow  = 0x10000ULL;
    constexpr uint64_t kPtrHigh = 0x7fffffffffffULL;

    // GPU acceleration is opt-in and gated on CudaSearch::available(); we
    // construct the engine once and re-use it across regions for cheap
    // memory reallocation amortisation.
    const bool gpuActive = config.useGpu && CudaSearch::available();
    CudaSearch gpu;

    for (auto& region : regions) {
        if (cancelled()) break;
        if (!(region.protection & MemProt::Read)) continue;
        // Read EVERY readable region (all module regions included) so Phase-2
        // traversal is complete even under sharding: a path routed THROUGH a
        // static intermediate must be walkable no matter which shard "owns" that
        // intermediate's region. Sharding partitions only the recorded endpoints
        // (module-index check in Phase 2), so merged shards == a full scan.

        // Read the region in bounded windows so a single multi-GB mapping in a
        // hostile target can't drive one buf.resize(region.size) into bad_alloc.
        // Each window keeps a 7-byte overlap so an 8-byte pointer straddling a
        // window boundary is still examined (owning offsets stay consecutive).
        constexpr size_t kPtrReadWindow = 64u * 1024 * 1024; // 64 MB
        const size_t ptrStep = config.alignedOnly ? 8 : 1;
        const size_t ownedLen = std::max<size_t>(ptrStep, (kPtrReadWindow / ptrStep) * ptrStep);
        for (size_t windowStart = 0; windowStart < region.size; windowStart += ownedLen) {
            if (cancelled()) break;
            size_t want = std::min<size_t>(ownedLen + 7, region.size - windowStart);
            buf.resize(want);
            auto rr = proc.read(region.base + windowStart, buf.data(), want);
            if (!rr || *rr < 8) continue;
            size_t bytesRead = *rr;
            uintptr_t winBase = region.base + windowStart;

            const bool useGpuHere = gpuActive &&
                bytesRead >= config.gpuMinRegionBytes &&
                config.alignedOnly; // GPU kernel walks 8-byte slots

            if (useGpuHere) {
                auto candidates = gpu.searchU64Range(buf.data(), bytesRead, kPtrLow, kPtrHigh);
                for (size_t off : candidates) {
                    uintptr_t val;
                    if (off + 8 > bytesRead) continue;
                    std::memcpy(&val, buf.data() + off, 8);
                    if (!isInRange(val, regions)) continue;
                    entries.push_back({val, winBase + off});
                }
            } else {
                size_t limit = bytesRead - 7;
                for (size_t offset = 0; offset < limit; offset += ptrStep) {
                    uintptr_t val;
                    std::memcpy(&val, buf.data() + offset, 8);

                    if (val < kPtrLow || val > kPtrHigh) continue;
                    if (!isInRange(val, regions)) continue;

                    entries.push_back({val, winBase + offset});
                }
            }
        }

        scanned += region.size;
        if (progress) progress->store(progressSpan * scanned / totalMem);
    }

    PointerMap map;
    if (cancelled()) return map;    // empty
    map.setModules(proc.modules());
    map.setEntries(std::move(entries));   // sorts by target + builds by-location index
    return map;
}

std::vector<PointerPath> PointerScanner::scan(ProcessHandle& proc, const PointerScanConfig& config) {
    cancelled_.store(false);
    progress_.store(0);
    if (config.shardCount == 0 || config.shardIndex >= config.shardCount)
        return {};

    PointerMap map = buildPointerMap(proc, config, &cancelled_, &progress_, 0.5f);
    if (cancelled_.load()) return {};
    return scanWithMap(map, config);
}

std::vector<PointerPath> PointerScanner::scanWithMap(const PointerMap& map,
                                                     const PointerScanConfig& config) {
    if (config.shardCount == 0 || config.shardIndex >= config.shardCount)
        return {};

    const std::vector<PointerMap::Entry>& entries = map.entriesByTarget();
    const std::vector<ModuleInfo>& modules = map.modules();

    // Build quick lookup: is address in a module? (static pointer)
    auto findModule = [&](uintptr_t addr) -> const ModuleInfo* {
        for (auto& m : modules)
            if (addr >= m.base && addr < m.base + m.size)
                return &m;
        return nullptr;
    };

    // ── Reverse BFS from target ──

    struct WorkItem {
        uintptr_t address;          // Address to find pointers TO
        std::vector<int32_t> offsets; // Offsets collected so far
        int depth;
    };

    std::vector<PointerPath> results;
    std::queue<WorkItem> queue;
    std::set<uintptr_t> visited; // Prevent cycles

    queue.push({config.targetAddress, {}, 0});
    visited.insert(config.targetAddress);

    size_t totalWork = 1;
    size_t doneWork = 0;

    while (!queue.empty() && !cancelled_.load()) {
        auto item = queue.front();
        queue.pop();
        ++doneWork;

        if (item.depth > 0)
            progress_.store(0.5f + 0.5f * doneWork / std::max(totalWork, size_t(1)));

        // Search window: find all pointers that point to [address - maxOffset, address + (negativeOffsets ? maxOffset : 0)]
        uintptr_t searchMin = (item.address > (uintptr_t)config.maxOffset) ?
            item.address - config.maxOffset : 0;
        uintptr_t searchMax = item.address;
        if (config.negativeOffsets)
            searchMax = item.address + config.maxOffset;

        // Binary search for range [searchMin, searchMax] in sorted entries
        auto lo = std::lower_bound(entries.begin(), entries.end(), searchMin,
            [](const PointerMap::Entry& e, uintptr_t val) { return e.pointsTo < val; });
        auto hi = std::upper_bound(entries.begin(), entries.end(), searchMax,
            [](uintptr_t val, const PointerMap::Entry& e) { return val < e.pointsTo; });

        for (auto it = lo; it != hi && !cancelled_.load(); ++it) {
            int32_t offset = (int32_t)(item.address - it->pointsTo);

            // Build new offset chain
            auto newOffsets = item.offsets;
            newOffsets.insert(newOffsets.begin(), offset); // Prepend (innermost first)

            // Check if this pointer is in a static module
            auto* mod = findModule(it->locatedAt);
            if (mod) {
                // Found a static path. Under sharding, partition the recorded
                // endpoints by MODULE index (Phase 1 read all regions, so the
                // traversal already saw every intermediate): each module's paths
                // go to exactly one shard, and the union across shards is the full
                // result set. Do this only for the RECORDING, never the traversal.
                size_t moduleIndex = (size_t)(mod - modules.data());
                bool ownedByShard = config.shardCount <= 1 ||
                    (moduleIndex % config.shardCount) == config.shardIndex;
                if (ownedByShard) {
                    PointerPath path;
                    path.module = mod->name;
                    path.moduleBase = mod->base;
                    path.baseOffset = it->locatedAt - mod->base;
                    path.offsets = newOffsets;
                    results.push_back(std::move(path));

                    // Cap results
                    if (results.size() >= 10000) goto done;
                }
            }

            // Go deeper if not at max depth and not static-only
            if (item.depth + 1 < config.maxDepth) {
                if (!visited.count(it->locatedAt)) {
                    visited.insert(it->locatedAt);
                    queue.push({it->locatedAt, newOffsets, item.depth + 1});
                    ++totalWork;
                }
            }
        }
    }

done:
    progress_.store(1.0f);
    // Honour the cancellation contract used elsewhere (a cancelled scan yields
    // no results, not a nondeterministic partial set). Reaching the result cap
    // via `goto done` is a normal completion and still returns its results.
    if (cancelled_.load())
        return {};
    return results;
}

uintptr_t PointerScanner::dereference(ProcessHandle& proc, const std::vector<ModuleInfo>& modules,
                                      const PointerPath& path) {
    uintptr_t base = 0;
    for (auto& m : modules) {
        if (m.name == path.module) { base = m.base; break; }
    }
    if (base == 0) return 0;

    uintptr_t addr = base + path.baseOffset;
    for (auto off : path.offsets) {
        uintptr_t ptr = 0;
        auto r = proc.read(addr, &ptr, sizeof(ptr));
        if (!r || *r < sizeof(ptr) || ptr == 0) return 0;
        addr = ptr + off;
    }
    return addr;
}

uintptr_t PointerScanner::dereference(ProcessHandle& proc, const PointerPath& path) {
    return dereference(proc, proc.modules(), path);
}

// ── Persistence and post-processing ──

namespace {
constexpr char kPointerScanMagic[8] = {'P','S','C','A','N','0','0','1'};
constexpr uint32_t kPointerScanVersion = 1;
}

bool savePointerPaths(const std::string& path, const std::vector<PointerPath>& paths) {
    FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) return false;

    auto writeAll = [&](const void* ptr, size_t n) {
        return std::fwrite(ptr, 1, n, f) == n;
    };

    bool ok = writeAll(kPointerScanMagic, sizeof(kPointerScanMagic));
    ok = ok && writeAll(&kPointerScanVersion, sizeof(kPointerScanVersion));
    uint32_t count = static_cast<uint32_t>(paths.size());
    ok = ok && writeAll(&count, sizeof(count));

    for (const auto& p : paths) {
        if (!ok) break;
        uint64_t base = p.moduleBase, baseOff = p.baseOffset;
        uint32_t offCount = static_cast<uint32_t>(p.offsets.size());
        uint32_t nameLen = static_cast<uint32_t>(p.module.size());
        ok = writeAll(&base, sizeof(base)) &&
             writeAll(&baseOff, sizeof(baseOff)) &&
             writeAll(&offCount, sizeof(offCount)) &&
             writeAll(&nameLen, sizeof(nameLen));
        if (ok && nameLen > 0) ok = writeAll(p.module.data(), nameLen);
        if (ok && offCount > 0) ok = writeAll(p.offsets.data(), offCount * sizeof(int32_t));
    }

    std::fclose(f);
    return ok;
}

std::vector<PointerPath> loadPointerPaths(const std::string& path, std::string* error) {
    auto fail = [&](const char* msg) {
        if (error) *error = msg;
        return std::vector<PointerPath>{};
    };

    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return fail("open failed");

    auto readAll = [&](void* ptr, size_t n) {
        return std::fread(ptr, 1, n, f) == n;
    };

    char magic[8] = {};
    uint32_t version = 0, count = 0;
    if (!readAll(magic, sizeof(magic)) ||
        std::memcmp(magic, kPointerScanMagic, sizeof(kPointerScanMagic)) != 0) {
        std::fclose(f); return fail("bad magic");
    }
    if (!readAll(&version, sizeof(version)) || version != kPointerScanVersion) {
        std::fclose(f); return fail("unsupported version");
    }
    if (!readAll(&count, sizeof(count))) {
        std::fclose(f); return fail("truncated header");
    }
    if (count > (1u << 28)) { std::fclose(f); return fail("path count too large"); }

    std::vector<PointerPath> result;
    // Don't trust the header count for a huge up-front reserve; grow on demand.
    result.reserve(std::min<size_t>(count, 4096));
    for (uint32_t i = 0; i < count; ++i) {
        uint64_t base = 0, baseOff = 0;
        uint32_t offCount = 0, nameLen = 0;
        if (!readAll(&base, sizeof(base)) ||
            !readAll(&baseOff, sizeof(baseOff)) ||
            !readAll(&offCount, sizeof(offCount)) ||
            !readAll(&nameLen, sizeof(nameLen))) {
            std::fclose(f); return fail("truncated record header");
        }
        if (offCount > 64 || nameLen > (1u << 16)) {
            std::fclose(f); return fail("record fields out of range");
        }
        PointerPath p;
        p.moduleBase = static_cast<uintptr_t>(base);
        p.baseOffset = static_cast<uintptr_t>(baseOff);
        p.module.resize(nameLen);
        p.offsets.resize(offCount);
        if (nameLen > 0 && !readAll(p.module.data(), nameLen)) {
            std::fclose(f); return fail("truncated module name");
        }
        if (offCount > 0 && !readAll(p.offsets.data(), offCount * sizeof(int32_t))) {
            std::fclose(f); return fail("truncated offset list");
        }
        result.push_back(std::move(p));
    }
    std::fclose(f);
    return result;
}

std::vector<PointerPath>
rescanPointerPaths(ProcessHandle& proc, const std::vector<PointerPath>& paths, uintptr_t newTarget) {
    auto modules = proc.modules();   // parse /proc maps once, not per path
    std::vector<PointerPath> kept;
    kept.reserve(paths.size());
    for (const auto& p : paths) {
        if (PointerScanner::dereference(proc, modules, p) == newTarget)
            kept.push_back(p);
    }
    return kept;
}

std::vector<PointerPath>
rescanPointerPathsByValue(ProcessHandle& proc, const std::vector<PointerPath>& paths,
                          uint64_t expectedValue, size_t valueSize) {
    std::vector<PointerPath> kept;
    if (valueSize == 0 || valueSize > 8) return kept;
    auto modules = proc.modules();   // parse /proc maps once, not per path
    kept.reserve(paths.size());
    const uint64_t mask = (valueSize == 8) ? ~0ull : ((1ull << (valueSize * 8)) - 1);
    for (const auto& p : paths) {
        uintptr_t addr = PointerScanner::dereference(proc, modules, p);
        if (addr == 0) continue;
        uint64_t val = 0;
        auto r = proc.read(addr, &val, valueSize);
        if (r && *r == valueSize && (val & mask) == (expectedValue & mask))
            kept.push_back(p);
    }
    return kept;
}

std::vector<PointerPath>
rescanPointerPathsWithMap(const PointerMap& map, const std::vector<PointerPath>& paths,
                          uintptr_t newTarget) {
    std::vector<PointerPath> kept;
    kept.reserve(paths.size());
    for (const auto& p : paths)
        if (map.resolve(p) == newTarget) kept.push_back(p);
    return kept;
}

std::vector<PointerPath>
rescanPointerPathsByValueWithMap(ProcessHandle& proc, const PointerMap& map,
                                 const std::vector<PointerPath>& paths,
                                 uint64_t expectedValue, size_t valueSize) {
    std::vector<PointerPath> kept;
    if (valueSize == 0 || valueSize > 8) return kept;

    // Resolve every chain from the map (no syscalls), collecting live targets.
    std::vector<uintptr_t> addrs;
    std::vector<size_t> pathIdx;
    addrs.reserve(paths.size());
    pathIdx.reserve(paths.size());
    for (size_t i = 0; i < paths.size(); ++i) {
        uintptr_t a = map.resolve(paths[i]);
        if (a) { addrs.push_back(a); pathIdx.push_back(i); }
    }
    if (addrs.empty()) return kept;

    // One batched read of the survivors' values (readMany), then filter.
    std::vector<uint8_t> out(addrs.size() * valueSize);
    std::vector<uint8_t> okFlags(addrs.size());
    proc.readMany(addrs.data(), addrs.size(), valueSize, out.data(), okFlags.data());
    const uint64_t mask = (valueSize == 8) ? ~0ull : ((1ull << (valueSize * 8)) - 1);
    for (size_t k = 0; k < addrs.size(); ++k) {
        if (!okFlags[k]) continue;
        uint64_t val = 0;
        std::memcpy(&val, out.data() + k * valueSize, valueSize);
        if ((val & mask) == (expectedValue & mask)) kept.push_back(paths[pathIdx[k]]);
    }
    return kept;
}

void sortPointerPaths(std::vector<PointerPath>& paths, PointerSortKey key) {
    auto offsetSum = [](const PointerPath& p) {
        int64_t sum = 0;
        for (auto o : p.offsets) sum += std::abs(static_cast<int64_t>(o));
        return sum;
    };
    switch (key) {
        case PointerSortKey::Depth:
            std::sort(paths.begin(), paths.end(),
                [](const PointerPath& a, const PointerPath& b) {
                    return a.offsets.size() < b.offsets.size();
                });
            break;
        case PointerSortKey::BaseOffset:
            std::sort(paths.begin(), paths.end(),
                [](const PointerPath& a, const PointerPath& b) {
                    return a.baseOffset < b.baseOffset;
                });
            break;
        case PointerSortKey::OffsetSum:
            std::sort(paths.begin(), paths.end(),
                [&](const PointerPath& a, const PointerPath& b) {
                    return offsetSum(a) < offsetSum(b);
                });
            break;
        case PointerSortKey::Module:
            std::sort(paths.begin(), paths.end(),
                [](const PointerPath& a, const PointerPath& b) {
                    if (a.module != b.module) return a.module < b.module;
                    return a.baseOffset < b.baseOffset;
                });
            break;
    }
}

std::vector<PointerPath>
mergePointerPaths(const std::vector<PointerPath>& a, const std::vector<PointerPath>& b,
                  bool deduplicate) {
    std::vector<PointerPath> out;
    out.reserve(a.size() + b.size());
    out.insert(out.end(), a.begin(), a.end());
    if (!deduplicate) {
        out.insert(out.end(), b.begin(), b.end());
        return out;
    }
    auto sameAs = [](const PointerPath& x, const PointerPath& y) {
        return x.module == y.module && x.baseOffset == y.baseOffset && x.offsets == y.offsets;
    };
    for (const auto& p : b) {
        bool dup = false;
        for (const auto& existing : out) {
            if (sameAs(existing, p)) { dup = true; break; }
        }
        if (!dup) out.push_back(p);
    }
    return out;
}

} // namespace ce
