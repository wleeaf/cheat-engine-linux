#pragma once
/// Value codecs for obfuscated in-memory values (docs/CHALLENGING_TARGETS.md block 6).
///
/// Some games store a value in an encoded form to defeat naive scanners: XOR'd with a
/// constant key, shifted by a constant offset, or bit-rotated. The logical value the
/// player sees (health, money) is never in memory verbatim, so a plain scan for it
/// finds nothing, and even after locating the address by change-scan the user must
/// hand-compute the encoded bytes to edit it.
///
/// A ValueCodec is the reversible transform between the LOGICAL value (what the user
/// wants) and the STORED value (the bytes in memory):
///   encode(logical) -> stored   (what to search for, and what to write)
///   decode(stored)  -> logical   (how to display what is there)
/// All ops are width-aware (1/2/4/8 bytes) and mask to that width, so a codec on an
/// i16 does not smear into neighbouring bytes.
///
/// This handles the common constant-transform cases without any Lua; a non-constant
/// or split-byte layout is still the job of the `--type custom` Lua scan.

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <optional>
#include <string>

namespace ce {

struct ValueCodec {
    enum class Op { None, Xor, Add, Rol, Ror };
    Op       op  = Op::None;
    uint64_t key = 0;   // XOR key / ADD offset / rotate count (bits)

    static uint64_t maskFor(int bytes) {
        return bytes >= 8 ? ~0ull : ((1ull << (bytes * 8)) - 1);
    }
    static uint64_t rotl(uint64_t v, unsigned n, int bytes) {
        const unsigned w = static_cast<unsigned>(bytes) * 8;
        n %= w;
        const uint64_t m = maskFor(bytes);
        v &= m;
        return n ? (((v << n) | (v >> (w - n))) & m) : v;
    }
    static uint64_t rotr(uint64_t v, unsigned n, int bytes) {
        const unsigned w = static_cast<unsigned>(bytes) * 8;
        n %= w;
        const uint64_t m = maskFor(bytes);
        v &= m;
        return n ? (((v >> n) | (v << (w - n))) & m) : v;
    }

    // logical -> stored
    uint64_t encode(uint64_t logical, int bytes) const {
        const uint64_t m = maskFor(bytes);
        const uint64_t v = logical & m;
        switch (op) {
            case Op::None: return v;
            case Op::Xor:  return (v ^ key) & m;
            case Op::Add:  return (v + key) & m;
            case Op::Rol:  return rotl(v, static_cast<unsigned>(key), bytes);
            case Op::Ror:  return rotr(v, static_cast<unsigned>(key), bytes);
        }
        return v;
    }
    // stored -> logical (inverse of encode)
    uint64_t decode(uint64_t stored, int bytes) const {
        const uint64_t m = maskFor(bytes);
        const uint64_t v = stored & m;
        switch (op) {
            case Op::None: return v;
            case Op::Xor:  return (v ^ key) & m;              // XOR is its own inverse
            case Op::Add:  return (v - key) & m;
            case Op::Rol:  return rotr(v, static_cast<unsigned>(key), bytes);
            case Op::Ror:  return rotl(v, static_cast<unsigned>(key), bytes);
        }
        return v;
    }

    bool active() const { return op != Op::None; }

    // Parse "xor:0xKEY", "add:N", "rol:N", "ror:N" (N in any strtoull base). Returns
    // nullopt on a malformed spec so the caller can report it.
    static std::optional<ValueCodec> parse(const std::string& spec) {
        const auto colon = spec.find(':');
        if (colon == std::string::npos) return std::nullopt;
        const std::string name = spec.substr(0, colon);
        const std::string arg  = spec.substr(colon + 1);
        if (arg.empty()) return std::nullopt;
        errno = 0;
        char* end = nullptr;
        const uint64_t key = std::strtoull(arg.c_str(), &end, 0);
        if (end == arg.c_str() || *end != '\0' || errno == ERANGE) return std::nullopt;
        ValueCodec c;
        c.key = key;
        if      (name == "xor") c.op = Op::Xor;
        else if (name == "add") c.op = Op::Add;
        else if (name == "rol") c.op = Op::Rol;
        else if (name == "ror") c.op = Op::Ror;
        else return std::nullopt;
        return c;
    }

    std::string describe() const {
        char b[48];
        switch (op) {
            case Op::None: return "none";
            case Op::Xor: std::snprintf(b, sizeof b, "xor:0x%llx", (unsigned long long)key); break;
            case Op::Add: std::snprintf(b, sizeof b, "add:%llu",   (unsigned long long)key); break;
            case Op::Rol: std::snprintf(b, sizeof b, "rol:%llu",   (unsigned long long)key); break;
            case Op::Ror: std::snprintf(b, sizeof b, "ror:%llu",   (unsigned long long)key); break;
        }
        return b;
    }
};

} // namespace ce
