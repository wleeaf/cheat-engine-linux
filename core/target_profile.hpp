#pragma once
/// Target capability probe: cheap, read-only /proc inspection that tells the user
/// (and the tool) what kind of process they are looking at BEFORE scanning or
/// attaching, so a limitation becomes an up-front, plain-language note instead of a
/// silent freeze or failure. See docs/CHALLENGING_TARGETS.md (building block E).
///
/// This never ptraces, allocates in, or otherwise perturbs the target; it only
/// reads /proc/<pid>/{exe,maps,status,cmdline,comm}. Safe to call on any pid.

#include <sys/types.h>
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

    bool  wine = false;            // runs a Windows PE under Wine/Proton
    pid_t tracerPid = 0;           // non-zero: already ptrace'd (debugger or anti-debug)
    bool  seccomp = false;         // a seccomp-bpf filter is installed
    bool  pidNamespaced = false;   // inside a nested PID namespace (sandbox/container)

    std::vector<std::string> runtimes;   // managed runtimes present, e.g. "CoreCLR (.NET)"
    std::string emulator;                // "" or a known emulator name, e.g. "Dolphin"

    // Plain-language limitations/warnings derived from the above (empty = nothing
    // notable). Suitable for a tooltip, a status line, or `cescan`.
    std::vector<std::string> notes;

    std::string archName() const;   // "x86-64", "ARM64", ...
    std::string summary() const;    // one short human line, e.g. "Wine/Proton x86-64 game"
};

/// Inspect a running pid. Never throws; returns {valid=false} if /proc is unreadable.
TargetProfile probeTarget(pid_t pid);

} // namespace ce
