#pragma once
/// A view over an emulator's guest RAM: a region inside the host process at `base`
/// (where guest address 0 lives), of `size` bytes, with a guest endianness. It
/// translates guest addresses to host and byte-swaps multi-byte values so a
/// big-endian console value (PS3/Wii/GameCube) reads and writes correctly.
///
/// This is the foundation of emulator support (docs/CHALLENGING_TARGETS.md block
/// 2/D): the value the user cares about is a GUEST address, and the bytes in host
/// memory are in the guest's byte order. `probeTarget()` supplies candidate
/// `base`/`size` for known emulators.
///
/// Header-only and pure aside from ProcessHandle::read/write, so it is trivially
/// unit-testable against any process (including self).

#include "platform/process_api.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <utility>
#include <vector>

namespace ce {

inline uint16_t bswap16(uint16_t v) { return __builtin_bswap16(v); }
inline uint32_t bswap32(uint32_t v) { return __builtin_bswap32(v); }
inline uint64_t bswap64(uint64_t v) { return __builtin_bswap64(v); }

struct GuestView {
    ProcessHandle* proc = nullptr;
    uintptr_t base = 0;        // host address of guest address 0
    uint64_t  size = 0;        // guest RAM size in bytes
    bool      bigEndian = false;

    bool contains(uint64_t guestAddr, size_t n) const {
        constexpr auto maxHost = std::numeric_limits<uintptr_t>::max();
        return proc && n > 0 && guestAddr <= size && n <= size - guestAddr &&
               guestAddr <= maxHost - base && n - 1 <= maxHost - base - guestAddr;
    }
    uintptr_t toHost(uint64_t guestAddr) const { return base + static_cast<uintptr_t>(guestAddr); }

    // Swap a trivially-copyable value's bytes (handles ints and float/double alike).
    template <class T>
    static T byteswap(T v) {
        if constexpr (sizeof(T) == 2) { uint16_t x; std::memcpy(&x, &v, 2); x = bswap16(x); std::memcpy(&v, &x, 2); }
        else if constexpr (sizeof(T) == 4) { uint32_t x; std::memcpy(&x, &v, 4); x = bswap32(x); std::memcpy(&v, &x, 4); }
        else if constexpr (sizeof(T) == 8) { uint64_t x; std::memcpy(&x, &v, 8); x = bswap64(x); std::memcpy(&v, &x, 8); }
        return v;   // sizeof 1 (or odd sizes): nothing to swap
    }

    std::vector<uint8_t> readBytes(uint64_t guestAddr, size_t n) const {
        if (!contains(guestAddr, n)) return {};
        std::vector<uint8_t> buf(n);
        auto r = proc->read(toHost(guestAddr), buf.data(), n);
        if (!r || *r < n) return {};
        return buf;
    }
    bool writeBytes(uint64_t guestAddr, const void* data, size_t n) const {
        if (!contains(guestAddr, n)) return false;
        auto r = proc->write(toHost(guestAddr), data, n);
        return r && *r == n;
    }

    // Typed read/write in guest byte order.
    template <class T>
    std::optional<T> read(uint64_t guestAddr) const {
        auto b = readBytes(guestAddr, sizeof(T));
        if (b.size() != sizeof(T)) return std::nullopt;
        T v; std::memcpy(&v, b.data(), sizeof(T));
        return bigEndian ? byteswap(v) : v;
    }
    template <class T>
    bool write(uint64_t guestAddr, T value) const {
        if (bigEndian) value = byteswap(value);
        return writeBytes(guestAddr, &value, sizeof(T));
    }
};

// Bounds for whole-region work. A Switch or PS3 guest is several GB; an unknown
// scan holds two snapshots, and a common value (0) matches almost every offset.
constexpr uint64_t kGuestSnapshotMaxBytes = uint64_t(512) << 20;
constexpr size_t   kGuestMaxHits = size_t(4) << 20;

// Exact-value first scan over a guest region: returns the GUEST addresses whose
// bytes equal `value` in the guest's byte order. `alignment` (1/2/4/8) restricts
// matches to aligned offsets, as CE's fast scan does. Chunked so multi-GB guest RAM
// streams, with a sizeof(T)-1 overlap so a value straddling a chunk boundary is not
// missed and not double-counted. Stops after `maxHits` matches and sets
// `*truncated` when it did.
template <class T>
std::vector<uint64_t> guestScanExact(const GuestView& gv, T value, size_t alignment = sizeof(T),
                                     size_t maxHits = kGuestMaxHits, bool* truncated = nullptr) {
    std::vector<uint64_t> hits;
    if (truncated) *truncated = false;
    if (gv.size < sizeof(T) || gv.size > SIZE_MAX || !gv.contains(0, gv.size)) return hits;
    if (alignment == 0) alignment = 1;

    const T needle = gv.bigEndian ? GuestView::byteswap(value) : value;
    uint8_t np[sizeof(T)];
    std::memcpy(np, &needle, sizeof(T));

    constexpr uint64_t kStride = 1u << 20;   // 1 MB windows
    std::vector<uint8_t> buf(kStride + sizeof(T));
    for (uint64_t off = 0; off + sizeof(T) <= gv.size; off += kStride) {
        const uint64_t want = std::min<uint64_t>(kStride + sizeof(T) - 1, gv.size - off);
        auto r = gv.proc->read(gv.toHost(off), buf.data(), want);
        if (!r) continue;
        const size_t got = std::min<size_t>(*r, want);
        if (got < sizeof(T)) continue;
        // Report starts only within [0, kStride); the sizeof(T)-1 tail is rescanned
        // as the next window's head, so straddlers are caught exactly once.
        const size_t limit = std::min<size_t>(kStride, got - sizeof(T) + 1);
        const size_t remainder = off % alignment;
        for (size_t i = remainder ? alignment - remainder : 0; i < limit;) {
            if (std::memcmp(buf.data() + i, np, sizeof(T)) == 0) {
                if (hits.size() >= maxHits) {
                    if (truncated) *truncated = true;
                    return hits;
                }
                hits.push_back(off + i);
            }
            if (alignment >= limit - i) break;
            i += alignment;
        }
    }
    return hits;
}

// Next scan: keep only the previously-found guest addresses whose current value
// still equals `value` (CE's exact next-scan, for narrowing a changing value).
template <class T>
std::vector<uint64_t> guestNextExact(const GuestView& gv, const std::vector<uint64_t>& prev, T value) {
    std::vector<uint64_t> out;
    out.reserve(prev.size());
    for (uint64_t g : prev) {
        auto cur = gv.read<T>(g);
        if (cur && *cur == value) out.push_back(g);
    }
    return out;
}

// Comparison next-scan: narrow a candidate set of (guest address, prior value) by how
// each value changed, without knowing the exact new value (CE's changed / unchanged /
// increased / decreased). Returns the survivors with their CURRENT value, so the caller
// can chain further comparisons.
enum class GuestCompare { Changed, Unchanged, Increased, Decreased };
template <class T>
std::vector<std::pair<uint64_t, T>> guestNextCompare(
        const GuestView& gv, const std::vector<std::pair<uint64_t, T>>& prev, GuestCompare op) {
    std::vector<std::pair<uint64_t, T>> out;
    out.reserve(prev.size());
    for (const auto& [addr, oldv] : prev) {
        auto cur = gv.read<T>(addr);
        if (!cur) continue;
        const T c = *cur;
        bool keep = false;
        switch (op) {
            case GuestCompare::Changed:   keep = c != oldv; break;
            case GuestCompare::Unchanged: keep = c == oldv; break;
            case GuestCompare::Increased: keep = c >  oldv; break;
            case GuestCompare::Decreased: keep = c <  oldv; break;
        }
        if (keep) out.emplace_back(addr, c);
    }
    return out;
}

// A snapshot of guest RAM for an unknown-value scan. `bytes` covers guest offsets
// [0, bytes.size()); `readable` lists the [begin, end) offsets that were actually
// read (unreadable gaps are left zero and never compared). `truncated` is set
// when the region was larger than the byte cap and only its start was taken.
struct GuestRegionSnapshot {
    std::vector<uint8_t> bytes;
    std::vector<std::pair<uint64_t, uint64_t>> readable;
    bool truncated = false;

    uint64_t readableBytes() const {
        uint64_t n = 0;
        for (const auto& [b, e] : readable) n += e - b;
        return n;
    }
};

// Snapshot up to `maxBytes` of the guest region in 1 MB reads. An unreadable
// page is skipped and reading continues after it.
inline GuestRegionSnapshot guestSnapshotRegion(const GuestView& gv,
                                               uint64_t maxBytes = kGuestSnapshotMaxBytes) {
    GuestRegionSnapshot snap;
    if (gv.size > SIZE_MAX || !gv.contains(0, gv.size)) return snap;
    const uint64_t n = std::min<uint64_t>(gv.size, maxBytes);
    snap.truncated = n < gv.size;
    snap.bytes.resize(n);
    constexpr uint64_t kPage = 4096;
    uint64_t off = 0;
    while (off < n) {
        const uint64_t want = std::min<uint64_t>(1u << 20, n - off);
        auto r = gv.proc->read(gv.toHost(off), snap.bytes.data() + off, want);
        const uint64_t got = r ? std::min<uint64_t>(*r, want) : 0;
        if (got) {
            if (!snap.readable.empty() && snap.readable.back().second == off)
                snap.readable.back().second = off + got;
            else
                snap.readable.emplace_back(off, off + got);
            off += got;
            continue;
        }
        // Unreadable: step to the next host page.
        off += kPage - gv.toHost(off) % kPage;
    }
    return snap;
}

// Read the whole guest region into a buffer (chunked, at most `maxBytes`). The
// returned size is how many bytes were readable from the start; reading stops at
// the first unreadable gap. guestSnapshotRegion keeps reading past gaps.
inline std::vector<uint8_t> guestReadRegion(const GuestView& gv,
                                            uint64_t maxBytes = kGuestSnapshotMaxBytes) {
    auto snap = guestSnapshotRegion(gv, maxBytes);
    const uint64_t prefix =
        !snap.readable.empty() && snap.readable.front().first == 0 ? snap.readable.front().second : 0;
    snap.bytes.resize(prefix);
    return std::move(snap.bytes);
}

template <class T>
bool guestCompareKeep(T o, T c, GuestCompare op) {
    switch (op) {
        case GuestCompare::Changed:   return c != o;
        case GuestCompare::Unchanged: return c == o;
        case GuestCompare::Increased: return c >  o;
        case GuestCompare::Decreased: return c <  o;
    }
    return false;
}

// Compare two snapshots of the same region (old vs new) at aligned offsets and
// return the (guest offset, current value) that match `op`. This is the first
// narrowing of an unknown-value scan, where the candidate set was the whole region.
// Stops after `maxHits` results and sets `*truncated` when it did.
template <class T>
std::vector<std::pair<uint64_t, T>> guestCompareBuffers(
        const std::vector<uint8_t>& oldB, const std::vector<uint8_t>& newB,
        bool bigEndian, GuestCompare op, size_t alignment = sizeof(T),
        size_t maxHits = kGuestMaxHits, bool* truncated = nullptr) {
    std::vector<std::pair<uint64_t, T>> out;
    if (truncated) *truncated = false;
    if (alignment == 0) alignment = 1;
    const size_t n = std::min(oldB.size(), newB.size());
    for (size_t off = 0; off + sizeof(T) <= n; off += alignment) {
        T o, c;
        std::memcpy(&o, oldB.data() + off, sizeof(T));
        std::memcpy(&c, newB.data() + off, sizeof(T));
        if (bigEndian) { o = GuestView::byteswap(o); c = GuestView::byteswap(c); }
        if (!guestCompareKeep(o, c, op)) continue;
        if (out.size() >= maxHits) {
            if (truncated) *truncated = true;
            break;
        }
        out.emplace_back(off, c);
    }
    return out;
}

// The same over two guestSnapshotRegion results, comparing only the offsets that
// were readable in both.
template <class T>
std::vector<std::pair<uint64_t, T>> guestCompareSnapshots(
        const GuestRegionSnapshot& oldS, const GuestRegionSnapshot& newS,
        bool bigEndian, GuestCompare op, size_t alignment = sizeof(T),
        size_t maxHits = kGuestMaxHits, bool* truncated = nullptr) {
    std::vector<std::pair<uint64_t, T>> out;
    if (truncated) *truncated = false;
    if (alignment == 0) alignment = 1;
    const uint64_t n = std::min<uint64_t>(oldS.bytes.size(), newS.bytes.size());
    size_t i = 0, j = 0;
    while (i < oldS.readable.size() && j < newS.readable.size()) {
        const uint64_t lo = std::max(oldS.readable[i].first, newS.readable[j].first);
        const uint64_t hi = std::min({oldS.readable[i].second, newS.readable[j].second, n});
        if (oldS.readable[i].second <= newS.readable[j].second) ++i; else ++j;
        uint64_t off = lo + (alignment - lo % alignment) % alignment;
        for (; hi >= sizeof(T) && off <= hi - sizeof(T); off += alignment) {
            T o, c;
            std::memcpy(&o, oldS.bytes.data() + off, sizeof(T));
            std::memcpy(&c, newS.bytes.data() + off, sizeof(T));
            if (bigEndian) { o = GuestView::byteswap(o); c = GuestView::byteswap(c); }
            if (!guestCompareKeep(o, c, op)) continue;
            if (out.size() >= maxHits) {
                if (truncated) *truncated = true;
                return out;
            }
            out.emplace_back(off, c);
        }
    }
    return out;
}

} // namespace ce
