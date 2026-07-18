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
        return proc && n > 0 && guestAddr + n >= guestAddr && guestAddr + n <= size;
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

// Exact-value first scan over a guest region: returns the GUEST addresses whose
// bytes equal `value` in the guest's byte order. `alignment` (1/2/4/8) restricts
// matches to aligned offsets, as CE's fast scan does. Chunked so multi-GB guest RAM
// streams, with a sizeof(T)-1 overlap so a value straddling a chunk boundary is not
// missed and not double-counted.
template <class T>
std::vector<uint64_t> guestScanExact(const GuestView& gv, T value, size_t alignment = sizeof(T)) {
    std::vector<uint64_t> hits;
    if (!gv.proc || gv.size < sizeof(T)) return hits;
    if (alignment == 0) alignment = 1;

    const T needle = gv.bigEndian ? GuestView::byteswap(value) : value;
    uint8_t np[sizeof(T)];
    std::memcpy(np, &needle, sizeof(T));

    constexpr uint64_t kStride = 1u << 20;   // 1 MB windows (a multiple of any align)
    std::vector<uint8_t> buf(kStride + sizeof(T));
    for (uint64_t off = 0; off + sizeof(T) <= gv.size; off += kStride) {
        const uint64_t want = std::min<uint64_t>(kStride + sizeof(T) - 1, gv.size - off);
        auto r = gv.proc->read(gv.toHost(off), buf.data(), want);
        if (!r) continue;
        const size_t got = *r;
        if (got < sizeof(T)) continue;
        // Report starts only within [0, kStride); the sizeof(T)-1 tail is rescanned
        // as the next window's head, so straddlers are caught exactly once.
        const size_t limit = std::min<size_t>(kStride, got - sizeof(T) + 1);
        for (size_t i = 0; i < limit; i += alignment)
            if (std::memcmp(buf.data() + i, np, sizeof(T)) == 0)
                hits.push_back(off + i);
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

// Read the whole guest region into a buffer (chunked). The returned size is how
// many bytes were actually readable (== size for a normal contiguous mapping);
// reading stops at the first unreadable gap. Used to snapshot for an unknown-value
// first scan.
inline std::vector<uint8_t> guestReadRegion(const GuestView& gv) {
    std::vector<uint8_t> buf;
    if (!gv.proc || gv.size == 0) return buf;
    buf.resize(gv.size);
    uint64_t off = 0;
    while (off < gv.size) {
        const uint64_t want = std::min<uint64_t>(1u << 20, gv.size - off);
        auto r = gv.proc->read(gv.toHost(off), buf.data() + off, want);
        if (!r || *r == 0) { buf.resize(off); break; }
        off += *r;
    }
    return buf;
}

// Compare two snapshots of the same region (old vs new) at aligned offsets and
// return the (guest offset, current value) that match `op`. This is the first
// narrowing of an unknown-value scan, where the candidate set was the whole region.
template <class T>
std::vector<std::pair<uint64_t, T>> guestCompareBuffers(
        const std::vector<uint8_t>& oldB, const std::vector<uint8_t>& newB,
        bool bigEndian, GuestCompare op, size_t alignment = sizeof(T)) {
    std::vector<std::pair<uint64_t, T>> out;
    if (alignment == 0) alignment = 1;
    const size_t n = std::min(oldB.size(), newB.size());
    for (size_t off = 0; off + sizeof(T) <= n; off += alignment) {
        T o, c;
        std::memcpy(&o, oldB.data() + off, sizeof(T));
        std::memcpy(&c, newB.data() + off, sizeof(T));
        if (bigEndian) { o = GuestView::byteswap(o); c = GuestView::byteswap(c); }
        bool keep = false;
        switch (op) {
            case GuestCompare::Changed:   keep = c != o; break;
            case GuestCompare::Unchanged: keep = c == o; break;
            case GuestCompare::Increased: keep = c >  o; break;
            case GuestCompare::Decreased: keep = c <  o; break;
        }
        if (keep) out.emplace_back(off, c);
    }
    return out;
}

} // namespace ce
