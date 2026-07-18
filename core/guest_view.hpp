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

} // namespace ce
