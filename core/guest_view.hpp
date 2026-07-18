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

} // namespace ce
