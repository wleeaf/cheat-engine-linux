#pragma once
/// Target capability probe: cheap, read-only /proc inspection that tells the user
/// (and the tool) what kind of process they are looking at BEFORE scanning or
/// attaching, so a limitation becomes an up-front, plain-language note instead of a
/// silent freeze or failure. See docs/CHALLENGING_TARGETS.md (building block E).
///
/// This never ptraces, allocates in, or otherwise perturbs the target; it only
/// reads /proc/<pid>/{exe,maps,status,cmdline,comm}. Safe to call on any pid.

#include <sys/types.h>
#include <cstdint>
#include <string>
#include <vector>

namespace ce {

struct TargetProfile {
    pid_t pid = 0;
    bool  valid = false;   // false if the pid could not be inspected

    // Host process architecture, from the main ELF (for a Wine target this is the
    // 64-bit host/loader arch; `wine` flags that it runs a Windows PE).
    enum class Arch { Unknown, X86_64, X86_32, Arm64, Arm32, RiscV64, Other };
    Arch arch = Arch::Unknown;

    enum class Endian { Unknown, Little, Big };
    Endian endianness = Endian::Unknown;   // from the ELF; big-endian matters for scans

    bool  wine = false;            // runs a Windows PE under Wine/Proton
    pid_t tracerPid = 0;           // non-zero: already ptrace'd (debugger or anti-debug)
    bool  seccomp = false;         // a seccomp-bpf filter is installed
    bool  pidNamespaced = false;   // inside a nested PID namespace (sandbox/container)
    pid_t nsInnerPid = 0;          // pid as the process sees itself in its innermost
                                   // namespace (== pid when not namespaced)

    std::vector<std::string> runtimes;   // managed runtimes present, e.g. "CoreCLR (.NET)"
    std::string emulator;                // "" or a known emulator name, e.g. "Dolphin"

    // Large RW mappings that are likely the emulator's guest RAM (only populated for
    // emulator targets). The value you want is a GUEST address inside one of these,
    // so scans should be restricted here (and may need byte-swapping on big-endian
    // consoles). See docs/CHALLENGING_TARGETS.md block 2/D.
    // `base` is the HOST address of the region's start; `guestBase` is the console
    // address that host address represents (Dolphin MEM1 = 0x80000000, MEM2 =
    // 0x90000000), so a scan hit at host offset N is console address guestBase + N --
    // matching existing cheat tables. 0 means guest addresses are region-relative (the
    // console's physical addressing is already 0-based, e.g. PS2 EE / PS1 RAM).
    struct GuestRegion {
        uintptr_t base = 0; size_t size = 0; bool fileBacked = false; uintptr_t guestBase = 0;
    };
    std::vector<GuestRegion> guestCandidates;

    // Plain-language limitations/warnings derived from the above (empty = nothing
    // notable). Suitable for a tooltip, a status line, or `cescan`.
    std::vector<std::string> notes;

    std::string archName() const;   // "x86-64", "ARM64", ...
    std::string summary() const;    // one short human line, e.g. "Wine/Proton x86-64 game"
};

/// Inspect a running pid. Never throws; returns {valid=false} if /proc is unreadable.
TargetProfile probeTarget(pid_t pid);

} // namespace ce
