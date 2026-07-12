#pragma once
/// Disassembler wrapping Capstone library.
/// Supports x86-32, x86-64, ARM32, ARM64.

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <span>
#include <functional>

#include "core/types.hpp"   // CpuContext

namespace ce {

// Decoded memory operand of an instruction (x86: base + index*scale + disp, or
// RIP-relative). Register identity travels as its lower-case name so the header
// stays free of Capstone types; computeEffectiveAddress maps names to registers.
struct MemoryOperand {
    bool        present = false;     // instruction references memory
    bool        ripRelative = false; // operand is [rip + disp]
    std::string baseReg;             // e.g. "rbx"; empty if none
    std::string indexReg;            // e.g. "rcx"; empty if none
    int32_t     scale = 1;
    int64_t     disp  = 0;
};

struct Instruction {
    uintptr_t    address;
    std::vector<uint8_t> bytes;
    std::string  mnemonic;
    std::string  operands;
    uint8_t      size;
    // Resolved absolute effective address of a RIP-relative memory operand
    // (0 if the instruction has none). The operand text is also rewritten to
    // "[0x<ripTarget>]"; consumers that need the numeric target use this field.
    uintptr_t    ripTarget = 0;
    // First memory operand (for "what addresses does this instruction access").
    MemoryOperand memory;

    std::string toString() const;
};

/// Resolve the absolute address that `inst`'s memory operand refers to, given
/// register state `ctx`. Returns 0 when the instruction has no memory operand.
/// RIP-relative operands use the pre-resolved ripTarget; base/index/scale forms
/// compute base + index*scale + disp from the 64-bit registers.
uintptr_t computeEffectiveAddress(const Instruction& inst, const CpuContext& ctx);

enum class Arch { X86_32, X86_64, ARM32, ARM64 };

class Disassembler {
public:
    explicit Disassembler(Arch arch = Arch::X86_64);
    ~Disassembler();

    Disassembler(const Disassembler&) = delete;
    Disassembler& operator=(const Disassembler&) = delete;

    /// Disassemble `count` instructions starting at `address` from `code`.
    /// If count == 0, disassembles as many as possible.
    /// If `emitDataBytes` is true, an undecodable byte is emitted as a 1-byte
    /// "db 0xXX" pseudo-instruction and disassembly continues past it (like CE),
    /// instead of stopping at the first byte Capstone can't decode.
    std::vector<Instruction> disassemble(uintptr_t address, std::span<const uint8_t> code,
                                         size_t count = 0, bool emitDataBytes = false);

    /// Disassemble a single instruction. Returns nullopt if invalid.
    std::optional<Instruction> disassembleOne(uintptr_t address, std::span<const uint8_t> code);

    /// Start address of the instruction immediately preceding `addr` (x86
    /// back-disassembly). Returns the largest length L in 1..15 such that the
    /// instruction decoded at addr-L is exactly L bytes (ends at addr); falls
    /// back to addr-1. `read(a, buf, n)` must fill buf with n bytes at `a` and
    /// return true, or return false if unreadable (so a region boundary can't
    /// force reading unmapped memory).
    uintptr_t previousInstruction(uintptr_t addr,
        const std::function<bool(uintptr_t, uint8_t*, size_t)>& read);

    Arch arch() const { return arch_; }

private:
    Arch arch_;
    size_t handle_ = 0; // csh handle
};

} // namespace ce
