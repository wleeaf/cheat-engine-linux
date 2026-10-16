#include "scanner/pointer_scanner.hpp"
#include "scanner/cuda_search.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <unordered_map>
#include <set>
#include <stdexcept>
#include <limits>

namespace ce {

std::string PointerPath::toString() const {
    std::string result;
    // Build from inside out: [[module+base]+off1]+off2
    for (int i = (int)offsets.size() - 1; i >= 0; --i)
        result += "[";

    char buf[64];
    // Module-less (absolute) bases print as the bare address.
    snprintf(buf, sizeof(buf), module.empty() ? "%lx" : "+%lx", baseOffset);
    // A name with '+', spaces or brackets ("libstdc++.so.6", "Game Name.exe")
    // is quoted, as Cheat Engine writes it, so the path parses back.
    const bool plainName = std::all_of(module.begin(), module.end(), [](unsigned char c) {
        return std::isalnum(c) || c == '_' || c == '.' || c == '-';
    });
    result += (plainName ? module : "\"" + module + "\"") + buf;

    for (auto off : offsets) {
        result += "]";
        if (off >= 0)
            snprintf(buf, sizeof(buf), "+0x%x", (unsigned)off);
        else
            // Negate in 64-bit: -INT32_MIN overflows a 32-bit int (UB).
            snprintf(buf, sizeof(buf), "-0x%x", (unsigned)(-(int64_t)off));
        result += buf;
    }
    return result;
}

// ── Reverse pointer map ──
// Maps: pointed_to_address → vector of (address_containing_pointer)
// We use a sorted vector for cache-friendly binary search.

namespace {

// Sorted, merged [first, last] spans of readable memory: the test for "this
// value could be a pointer". Unreadable reservations are left out (Wine
// reserves most of the low 4 GB, which would make nearly every small integer
// and float a candidate). Tested once per slot, so it is a range check and a
// binary search rather than a walk over every region.
class ReadableSpans {
public:
    explicit ReadableSpans(const std::vector<MemoryRegion>& regions) {
        std::vector<Span> spans;
        for (const auto& r : regions) {
            if (!(r.protection & MemProt::Read) || r.size == 0) continue;
            const uintptr_t last = r.size - 1 > UINTPTR_MAX - r.base ? UINTPTR_MAX : r.base + (r.size - 1);
            spans.push_back({r.base, last});
        }
        std::sort(spans.begin(), spans.end(), [](const Span& a, const Span& b) { return a.first < b.first; });
        for (const auto& s : spans) {
            if (!spans_.empty() && (spans_.back().last == UINTPTR_MAX || s.first <= spans_.back().last + 1))
                spans_.back().last = std::max(spans_.back().last, s.last);
            else
                spans_.push_back(s);
        }
    }

    bool contains(uintptr_t value) const {
        if (spans_.empty() || value < spans_.front().first || value > spans_.back().last) return false;
        auto it = std::upper_bound(spans_.begin(), spans_.end(), value,
                                   [](uintptr_t v, const Span& s) { return v < s.first; });
        return it != spans_.begin() && value <= std::prev(it)->last;
    }

private:
    struct Span { uintptr_t first, last; };
    std::vector<Span> spans_;
};

} // namespace

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
    // A path without a module has an absolute base (a heap or JIT pointer).
    uintptr_t base = 0;
    if (!path.module.empty()) {
        base = moduleBase(path.module);
        if (base == 0) return 0;
    }
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
    if (std::fclose(f) != 0) ok = false;
    return ok;
}

PointerMap PointerMap::load(const std::string& path, std::string* error) {
    if (error) error->clear();
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

    const size_t programWidth = proc.pointerWidth();
    const ByteOrder programOrder = proc.byteOrder();
    if ((programWidth != 4 && programWidth != 8) || programWidth > sizeof(uintptr_t) ||
        programOrder == ByteOrder::Unknown)
        throw std::runtime_error("Pointer scanning requires a known target pointer width and byte order");
    // Only a Wine or mixed-code target has modules of another machine; any
    // other reports the program's machine everywhere, and asking per region
    // costs a server round trip each on a ceserver target.
    const auto description = proc.targetDescription();
    const bool machinePerRegion = description.mixedCode || description.runtime == TargetRuntime::Wine;

    const ReadableSpans readable(regions);
    // Untouched pages of anonymous memory read as zero, and zero is no pointer
    // unless page 0 is mapped: skip them as the value scanner does. Aligned
    // slots never straddle a page, so no pointer is lost.
    const bool skipNonResident = config.alignedOnly && !readable.contains(0);
    constexpr size_t kPagemapMinRegion = 256u * 1024;

    // Read EVERY readable region (all module regions included) so the path
    // search is complete even under sharding: a path routed THROUGH a static
    // intermediate must be walkable no matter which shard "owns" that
    // intermediate's region. Sharding partitions only the recorded endpoints
    // (in scanWithMap), so merged shards == a full scan.
    struct ReadSpan { uintptr_t base; size_t size; size_t ptrSize; ByteOrder order; };
    std::vector<ReadSpan> spans;
    size_t totalMem = 0;
    for (const auto& region : regions) {
        if (!(region.protection & MemProt::Read) || region.size == 0) continue;
        // The width and byte order dereference() uses at this address: on WoW64
        // a 64-bit module keeps 8-byte pointers inside a 32-bit program.
        const size_t ptrSize = machinePerRegion ? proc.pointerWidth(region.base) : programWidth;
        const ByteOrder order = machinePerRegion ? proc.byteOrder(region.base) : programOrder;
        if ((ptrSize != 4 && ptrSize != 8) || ptrSize > sizeof(uintptr_t) || order == ByteOrder::Unknown)
            continue;   // dereference() cannot read a pointer here either
        const size_t ptrStep = config.alignedOnly ? ptrSize : 1;
        if (skipNonResident && region.type == MemType::Private && region.size >= kPagemapMinRegion &&
            region.size <= UINTPTR_MAX - region.base) {
            const uintptr_t regionEnd = region.base + region.size;
            for (auto [begin, end] : proc.residentRanges(region.base, region.size)) {
                begin = std::max<uintptr_t>(begin, region.base);
                end = std::min<uintptr_t>(end, regionEnd);
                // Keep the slots on the region's own grid.
                begin += (ptrStep - (begin - region.base) % ptrStep) % ptrStep;
                if (end <= begin) continue;
                spans.push_back({begin, end - begin, ptrSize, order});
                totalMem += end - begin;
            }
        } else {
            spans.push_back({region.base, region.size, ptrSize, order});
            totalMem += region.size;
        }
    }
    if (totalMem == 0) totalMem = 1;

    // ── Read the spans and keep pointer-like values ──
    const size_t maxEntries = std::min<size_t>(config.maxMapEntries, UINT32_MAX);
    std::vector<PointerMap::Entry> entries;
    entries.reserve(std::min<size_t>(1024 * 1024, maxEntries)); // ~16 MB
    bool full = false;
    size_t scanned = 0;
    std::vector<uint8_t> buf;

    // GPU acceleration is opt-in and gated on CudaSearch::available(); we
    // construct the engine once and re-use it across regions for cheap
    // memory reallocation amortisation.
    const bool gpuActive = config.useGpu && CudaSearch::available();
    CudaSearch gpu;
    // Check for a cancel every megabyte of slots, not only per read window.
    constexpr size_t kCancelMask = (1u << 20) - 1;

    for (const auto& span : spans) {
        if (full || cancelled()) break;
        const size_t ptrSize = span.ptrSize;
        const ByteOrder order = span.order;

        // Read the span in bounded windows so a single multi-GB mapping in a
        // hostile target can't drive one buf.resize(region.size) into bad_alloc.
        // Each window keeps an overlap so a target pointer straddling a
        // window boundary is still examined (owning offsets stay consecutive).
        constexpr size_t kPtrReadWindow = 64u * 1024 * 1024; // 64 MB
        const size_t ptrStep = config.alignedOnly ? ptrSize : 1;
        const size_t ownedLen = std::max<size_t>(ptrStep, (kPtrReadWindow / ptrStep) * ptrStep);
        for (size_t windowStart = 0; windowStart < span.size; windowStart += ownedLen) {
            if (full || cancelled()) break;
            const size_t owned = std::min(ownedLen, span.size - windowStart);
            size_t want = std::min<size_t>(ownedLen + ptrSize - 1, span.size - windowStart);
            buf.resize(want);
            auto rr = proc.read(span.base + windowStart, buf.data(), want);
            if (rr && *rr >= ptrSize) {
                size_t bytesRead = *rr;
                uintptr_t winBase = span.base + windowStart;

                const bool useGpuHere = gpuActive && order == ByteOrder::Little &&
                    nativeTargetMachine().byteOrder == ByteOrder::Little &&
                    bytesRead >= config.gpuMinRegionBytes &&
                    config.alignedOnly && ptrSize == 8; // GPU kernel walks 8-byte slots

                if (useGpuHere) {
                    auto candidates = gpu.searchU64Range(buf.data(), bytesRead, 0, UINTPTR_MAX);
                    for (size_t off : candidates) {
                        uintptr_t val;
                        if (off + 8 > bytesRead) continue;
                        std::memcpy(&val, buf.data() + off, 8);
                        if (!readable.contains(val)) continue;
                        if (entries.size() >= maxEntries) { full = true; break; }
                        entries.push_back({val, winBase + off});
                    }
                } else {
                    size_t limit = std::min(ownedLen, bytesRead - ptrSize + 1);
                    for (size_t offset = 0; offset < limit; offset += ptrStep) {
                        if ((offset & kCancelMask) == 0 && cancelled()) break;
                        uintptr_t val = static_cast<uintptr_t>(*decodeTargetUnsigned(
                            {buf.data() + offset, ptrSize}, order));
                        if (!readable.contains(val)) continue;
                        if (entries.size() >= maxEntries) { full = true; break; }
                        entries.push_back({val, winBase + offset});
                    }
                }
            }
            scanned += owned;
            if (progress) progress->store(progressSpan * static_cast<float>(
                static_cast<double>(scanned) / static_cast<double>(totalMem)));
        }
    }

    PointerMap map;
    if (cancelled()) return map;    // empty
    map.setModules(proc.modules());
    map.setEntries(std::move(entries));   // sorts by target + builds by-location index
    map.setTruncated(full);
    return map;
}

std::vector<PointerPath> PointerScanner::scan(ProcessHandle& proc, const PointerScanConfig& config) {
    // Do not clear cancelled_ here: a window closed right after Scan cancels
    // before its worker thread reaches this point, and clearing it would run
    // the whole scan while the window waits to join the worker.
    progress_.store(0);
    limit_.store(0);
    if (config.shardCount == 0 || config.shardIndex >= config.shardCount ||
        config.maxDepth <= 0 || config.maxOffset < 0)
        return {};

    PointerMap map = buildPointerMap(proc, config, &cancelled_, &progress_, 0.5f);
    if (cancelled_.load()) return {};
    return scanWithMap(map, config);
}

std::vector<PointerPath> PointerScanner::scanWithMap(const PointerMap& map,
                                                     const PointerScanConfig& config) {
    limit_.store(0);
    if (config.shardCount == 0 || config.shardIndex >= config.shardCount ||
        config.maxDepth <= 0 || config.maxOffset < 0)
        return {};

    if (map.truncated()) reachLimit(PointerScanLimit::MapEntries);
    const std::vector<PointerMap::Entry>& entries = map.entriesByTarget();
    const std::vector<ModuleInfo>& modules = map.modules();

    // ── Static bases ──
    // A path names its module, and every resolver (dereference, PointerMap::
    // resolve, address expressions) takes the first module of that name. So a
    // later module with the same name (WoW64's two ntdll.dll, one file loaded
    // twice), or one without a name, cannot be a base: its slots count as
    // plain memory.
    std::vector<size_t> nameable;   // module indices, in list order
    {
        std::set<std::string> seen;
        for (size_t i = 0; i < modules.size(); ++i)
            if (!modules[i].name.empty() && modules[i].size > 0 && seen.insert(modules[i].name).second)
                nameable.push_back(i);
    }
    std::vector<size_t> byBase = nameable;
    std::sort(byBase.begin(), byBase.end(),
              [&](size_t a, size_t b) { return modules[a].base < modules[b].base; });
    bool overlapping = false;
    for (size_t k = 1; k < byBase.size() && !overlapping; ++k)
        overlapping = modules[byBase[k]].base - modules[byBase[k - 1]].base < modules[byBase[k - 1]].size;

    // The first nameable module that holds `addr`. Without overlaps at most one
    // does, so a binary search finds the same one as the walk.
    auto findModule = [&](uintptr_t addr) -> const ModuleInfo* {
        if (overlapping) {
            for (size_t i : nameable)
                if (addr >= modules[i].base && addr - modules[i].base < modules[i].size) return &modules[i];
            return nullptr;
        }
        auto it = std::upper_bound(byBase.begin(), byBase.end(), addr,
                                   [&](uintptr_t a, size_t i) { return a < modules[i].base; });
        if (it == byBase.begin()) return nullptr;
        const ModuleInfo& m = modules[*std::prev(it)];
        return addr - m.base < m.size ? &m : nullptr;
    };

    // Entries [first, second) whose pointer lands within maxOffset below
    // `address` (or above it, with negativeOffsets).
    auto window = [&](uintptr_t address) -> std::pair<size_t, size_t> {
        uintptr_t searchMin = (address > (uintptr_t)config.maxOffset) ? address - config.maxOffset : 0;
        uintptr_t searchMax = address;
        if (config.negativeOffsets)
            searchMax = address + std::min<uintptr_t>(config.maxOffset,
                std::numeric_limits<uintptr_t>::max() - address);
        auto lo = std::lower_bound(entries.begin(), entries.end(), searchMin,
            [](const PointerMap::Entry& e, uintptr_t val) { return e.pointsTo < val; });
        auto hi = std::upper_bound(entries.begin(), entries.end(), searchMax,
            [](uintptr_t val, const PointerMap::Entry& e) { return val < e.pointsTo; });
        return {static_cast<size_t>(lo - entries.begin()), static_cast<size_t>(hi - entries.begin())};
    };

    // ── Iterative-deepening search back from the target ──
    // Pass N walks depth first to depth N and records only the paths of N
    // links. That gives the order a breadth-first search gives (shortest first,
    // and within one length in entry order) while holding one chain at a time
    // instead of a queue that grows as fanout^depth.
    struct Frame {
        uintptr_t address;   // the address pointers are searched for
        size_t next, end;    // the entries still to examine
    };
    std::vector<Frame> stack;
    std::vector<int32_t> chain;         // chain[d]: the offset taken at depth d
    std::vector<uintptr_t> ancestors;   // the target and every slot on the chain
    std::vector<PointerPath> results;
    uint64_t visits = 0;
    bool stop = false;

    // Record the path that ends at `e` (a slot pointing `offset` below the
    // current chain's head). False when the result cap is reached.
    auto record = [&](const PointerMap::Entry& e, int32_t offset) -> bool {
        PointerPath path;
        if (const ModuleInfo* mod = findModule(e.locatedAt)) {
            // Under sharding, partition the recorded endpoints by MODULE index
            // (the map holds every region, so the walk already saw every
            // intermediate): each module's paths go to exactly one shard, and the
            // union across shards is the full result set.
            const size_t moduleIndex = static_cast<size_t>(mod - modules.data());
            if (config.shardCount > 1 && moduleIndex % config.shardCount != config.shardIndex) return true;
            path.module = mod->name;
            path.moduleBase = mod->base;
            path.baseOffset = e.locatedAt - mod->base;
        } else {
            // Heap, JIT or guest-RAM base (no module): an absolute base, valid
            // until that memory moves. Shards split these by page.
            if (config.staticOnly) return true;
            if (config.shardCount > 1 && ((e.locatedAt >> 12) % config.shardCount) != config.shardIndex)
                return true;
            path.moduleBase = 0;
            path.baseOffset = e.locatedAt;
        }
        // Full: this path is one too many, so the result is cut short.
        if (results.size() >= config.maxResults) {
            reachLimit(PointerScanLimit::Results);
            return false;
        }
        path.offsets.reserve(chain.size() + 1);
        path.offsets.push_back(offset);   // innermost first
        for (auto it = chain.rbegin(); it != chain.rend(); ++it) path.offsets.push_back(*it);
        results.push_back(std::move(path));
        return true;
    };

    const auto [rootBegin, rootEnd] = window(config.targetAddress);
    const float passCount = static_cast<float>(config.maxDepth);
    for (int pass = 1; pass <= config.maxDepth && !stop; ++pass) {
        if (cancelled_.load(std::memory_order_relaxed)) break;
        // Whether a slot recorded in this pass could be walked further: if none
        // can, deeper passes find nothing new.
        bool deeper = false;
        stack.assign(1, Frame{config.targetAddress, rootBegin, rootEnd});
        chain.clear();
        ancestors.assign(1, config.targetAddress);
        while (!stack.empty()) {
            Frame& frame = stack.back();
            if (frame.next == frame.end) {
                stack.pop_back();
                if (!stack.empty()) { chain.pop_back(); ancestors.pop_back(); }
                continue;
            }
            if (visits >= config.maxVisits) {
                reachLimit(PointerScanLimit::Work);
                stop = true;
                break;
            }
            if ((++visits & 1023) == 0) {
                if (cancelled_.load(std::memory_order_relaxed)) { stop = true; break; }
                const size_t rootTotal = rootEnd - rootBegin;
                const float done = rootTotal ? static_cast<float>(stack.front().next - rootBegin) / rootTotal : 1.0f;
                progress_.store(0.5f + 0.5f * (static_cast<float>(pass - 1) + done) / passCount);
            }
            const PointerMap::Entry& e = entries[frame.next++];
            const int32_t offset = static_cast<int32_t>(frame.address - e.pointsTo);
            const bool fresh = std::find(ancestors.begin(), ancestors.end(), e.locatedAt) == ancestors.end();
            const size_t depth = stack.size() - 1;
            if (static_cast<int>(depth) + 1 == pass) {
                if (!record(e, offset)) { stop = true; break; }
                deeper = deeper || fresh;
            } else if (fresh) {
                chain.push_back(offset);
                ancestors.push_back(e.locatedAt);
                const auto [begin, end] = window(e.locatedAt);
                stack.push_back({e.locatedAt, begin, end});   // invalidates `frame`
            }
        }
        if (!deeper) break;
    }

    progress_.store(1.0f);
    // Honour the cancellation contract used elsewhere (a cancelled scan yields
    // no results, not a nondeterministic partial set). Reaching the result or
    // work cap is a normal completion and still returns its results.
    if (cancelled_.load())
        return {};
    return results;
}

uintptr_t PointerScanner::dereference(ProcessHandle& proc, const std::vector<ModuleInfo>& modules,
                                      const PointerPath& path) {
    uintptr_t base = 0;
    if (!path.module.empty()) {
        for (auto& m : modules) {
            if (m.name == path.module) { base = m.base; break; }
        }
        if (base == 0) return 0;
    }

    uintptr_t addr = base + path.baseOffset;
    if (path.baseOffset > UINTPTR_MAX - base) return 0;
    for (auto off : path.offsets) {
        const size_t ptrSize = proc.pointerWidth(addr);
        if ((ptrSize != 4 && ptrSize != 8) || ptrSize > sizeof(uintptr_t)) return 0;
        uint8_t bytes[8]{};
        auto r = proc.read(addr, bytes, ptrSize);
        if (!r || *r != ptrSize) return 0;
        auto decoded = decodeTargetUnsigned({bytes, ptrSize}, proc.byteOrder(addr));
        if (!decoded || !*decoded || *decoded > UINTPTR_MAX) return 0;
        uintptr_t ptr = static_cast<uintptr_t>(*decoded);
        uint64_t distance = off < 0 ? -int64_t(off) : off;
        if ((off < 0 && distance > ptr) || (off >= 0 && distance > UINTPTR_MAX - ptr)) return 0;
        addr = off < 0 ? ptr - distance : ptr + distance;
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

    if (std::fclose(f) != 0) ok = false;
    return ok;
}

std::vector<PointerPath> loadPointerPaths(const std::string& path, std::string* error) {
    if (error) error->clear();
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
rescanPointerPaths(ProcessHandle& proc, const std::vector<PointerPath>& paths, uintptr_t newTarget,
                   std::atomic<bool>* cancel, std::atomic<float>* progress) {
    auto modules = proc.modules();   // parse /proc maps once, not per path
    std::vector<PointerPath> kept;
    kept.reserve(paths.size());
    for (size_t i = 0; i < paths.size(); ++i) {
        if ((i & 255) == 0) {
            if (cancel && cancel->load(std::memory_order_relaxed)) return {};
            if (progress) progress->store(static_cast<float>(i) / static_cast<float>(paths.size()));
        }
        if (PointerScanner::dereference(proc, modules, paths[i]) == newTarget)
            kept.push_back(paths[i]);
    }
    if (cancel && cancel->load()) return {};
    if (progress) progress->store(1.0f);
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
        uint8_t bytes[8]{};
        auto r = proc.read(addr, bytes, valueSize);
        if (!r || *r != valueSize) continue;
        // In the target's byte order, as the value scanner reads it.
        auto val = decodeTargetUnsigned({bytes, valueSize}, proc.byteOrder(addr));
        if (val && (*val & mask) == (expectedValue & mask))
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
        auto val = decodeTargetUnsigned({out.data() + k * valueSize, valueSize}, proc.byteOrder(addrs[k]));
        if (val && (*val & mask) == (expectedValue & mask)) kept.push_back(paths[pathIdx[k]]);
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
