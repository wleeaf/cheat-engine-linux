#pragma once
/// Namespace-aware attach helpers (docs/CHALLENGING_TARGETS.md block C).
///
/// A sandboxed target (Flatpak, Snap, Firejail, Docker/Podman) runs in its own
/// mount + PID namespace. `process_vm_readv`/ptrace still work on the HOST pid, so
/// scan/read/write are fine, but the file paths in `/proc/<pid>/maps` (e.g.
/// `/app/bin/game`, `/usr/lib/libfoo.so`) name files that exist only inside the
/// sandbox's mount namespace. Opening them from the host fails, so symbol loading,
/// module analysis, and disasm-from-file silently come up empty even though the
/// process is fully readable.
///
/// The fix is to open those files through the kernel's per-process root symlink,
/// `/proc/<pid>/root/<path>`, which the host can traverse with ptrace privilege.
/// These helpers are dependency-free (standard library + /proc only) so they can be
/// unit-tested and reused anywhere a `/proc/<pid>/maps` path must be opened.

#include <sys/types.h>
#include <string>

namespace ce {

/// Return a version of `rawPath` (a path as it appears in `/proc/<pid>/maps`) that
/// can be opened from the host. If `rawPath` is empty or not absolute (`[heap]`,
/// anonymous, `[stack]`) it is returned unchanged. If it already exists on the host
/// it is returned as-is (the common, non-sandboxed case). Otherwise, if it exists
/// under the target's mount namespace root (`/proc/<pid>/root<rawPath>`), that
/// host-openable path is returned. If neither exists, `rawPath` is returned unchanged
/// so the caller fails exactly as it would have before.
std::string resolveProcPath(pid_t pid, const std::string& rawPath);

/// The pid as the process sees itself in its innermost PID namespace, from the last
/// field of the `NSpid:` line in `/proc/<pid>/status`. Equals `pid` for a process in
/// the root PID namespace (or when the field is absent). Useful for display and for
/// matching a pid the sandboxed app reports about itself.
pid_t nsInnerPid(pid_t pid);

/// True if `pid` lives in a nested PID namespace (its `NSpid:` line has more than one
/// entry), i.e. it is sandboxed/containerized.
bool isPidNamespaced(pid_t pid);

} // namespace ce
