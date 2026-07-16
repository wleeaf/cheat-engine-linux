#pragma once
/// Array-of-bytes signature generation: a stable, portable byte pattern that
/// locates a code address across game restarts / rebuilds. The relocatable parts
/// of each instruction (rip-relative displacements, address-sized immediates) are
/// wildcarded so the pattern survives ASLR and minor recompiles, while the opcode
/// structure and stable operands keep it specific.

#include "platform/process_api.hpp"

#include <string>

namespace ce {

struct SignatureResult {
    std::string pattern;   ///< CE AOB pattern, e.g. "48 8B 05 ?? ?? ?? ??"
    size_t      length = 0;///< bytes the pattern covers
    bool        unique = false;  ///< matches exactly once in the region (at `address`)
};

/// Build a signature for the code at `address`, extended instruction by
/// instruction until it is unique within [regionBase, regionBase+regionSize) or
/// `maxBytes` is reached. Wildcards rip-relative displacements and address-like
/// immediates. Returns an empty pattern if the address is out of range/unreadable.
SignatureResult makeSignature(ProcessHandle& proc, uintptr_t address,
                              uintptr_t regionBase, size_t regionSize, size_t maxBytes = 64);

/// Convenience: unique within the process mapping that contains `address`.
SignatureResult makeSignature(ProcessHandle& proc, uintptr_t address, size_t maxBytes = 64);

} // namespace ce
