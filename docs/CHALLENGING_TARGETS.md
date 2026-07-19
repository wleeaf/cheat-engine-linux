# Challenging target architectures: analysis and plan

Status: forward-looking design notes (2026-07-18). Not a commitment; a map of the
hard targets, why they break the current design, and a concrete plan for each.
Authoritative near-term roadmap stays in `docs/DEVELOPMENT.md`.

## Why this document exists

The Wine/Proton work (v0.6.6) was not really about "32-bit" or "WoW64". It was the
first instance of a general pattern: **the target runs its own runtime that manages
threads and memory in ways that fight a naive external ptrace + scan tool.** Wine's
wineserver/esync/fsync/GPU threads and its userfaultfd write-watch broke the
assumption that we can freely stop threads and mprotect pages. Every other hard
target below is the same lesson at a different scale.

Framed that way, the failure modes are predictable. The tool rests on five
mechanisms, each with an assumption some targets violate:

| Mechanism | Assumes | Violated by |
|---|---|---|
| `process_vm_readv/writev` | the value is a plain resident page in *this* PID | sandboxes/namespaces, GPU/device memory, emulator guest RAM, swapped/huge pages |
| Hardware watchpoint (DR0-3, per-OS-thread) | the writer is a stable OS thread | Wine (fixed), Go goroutines, fibers, a JIT re-emitting the writer |
| Software page-guard (mprotect + SIGSEGV) | we own the page's write protection | Wine userfaultfd write-watch, transparent huge pages (2 MB granularity) |
| Code injection (mmap cave + patch bytes) | code pages are stable and patchable | W^X JITs, checksummed/packed code, hardened `execmem` policies |
| ptrace SEIZE/stop/hijack | we can freely stop and hijack any thread | anti-debug self-ptrace, seccomp sandboxes, latency-critical threads |

The through-line: **the more layers a target puts between the logical value/code and
the physical bytes (a GC, a JIT, an emulator, a sandbox, a VM-packer), the less a raw
ptrace+scan tool can do, and the more we must either understand that layer or report
the limitation honestly.**

---

## Cross-cutting building blocks

Several hard categories are unlocked by the same infrastructure. Build these first;
they pay off across many targets.

### A. Architecture abstraction layer
Today injection literally emits `int 0x80`/`syscall` and watchpoints program x86
DR0-3. Capstone/Keystone already abstract disasm/asm. Extract a `TargetArch`
interface: syscall injection gadget, hardware-watchpoint programming, breakpoint
encoding (int3 vs `brk`), register map, calling convention, endianness. This is the
prerequisite for ARM64 and for cleaner WoW64 handling. Effort: large. Unlocks: ARM64,
RISC-V, big-endian.

### B. In-process agent framework (generalize the Mono agent)
The Mono/IL2CPP dissector already injects a Linux `.so` that runs *inside* the target
and talks back. Generalize it into a first-class mechanism: a small agent loaded into
the target that (1) resolves runtime-managed state (GC handles, JIT maps), (2) can be
called from Lua, (3) survives GC moves by pinning/rooting. This is the honest answer
to managed runtimes and W^X JITs: instead of fighting the runtime from outside, ask
it from inside. Effort: medium (foundation exists). Unlocks: .NET, JVM, Go, V8,
emulators (agent inside the emulator), W^X patching (the agent flips its own pages).

### C. Namespace-aware attach  [STARTED]
Resolve a target that lives in a PID/mount/user namespace (Flatpak, Snap, Firejail,
Docker): translate host<->namespace PIDs (`/proc/<pid>/status` `NSpid`), read the
right `/proc/<pid>/root/...` for maps/exe, and enter the namespace
(`setns`) when needed for `process_vm_readv`. Effort: medium. Unlocks: sandboxed apps,
containers, multi-process browsers.
Shipped: `core/ns_attach.hpp` (`resolveProcPath`/`nsInnerPid`/`isPidNamespaced`).
`LinuxProcessHandle::modules()` now redirects each module's backing-file path through
`/proc/<pid>/root` when it exists only inside the target's mount namespace, so symbol
loading and module analysis work on sandboxed targets (`process_vm_readv` already
worked; the files did not open). IL2CPP discovery resolves file-backed *region* paths
too, so `global-metadata.dat` (a data file, not a module) opens on Flatpak/Steam-Proton
(pressure-vessel) Unity games. `TargetProfile` reports the inner-namespace pid.
The process picker badges sandboxed processes ([sandboxed] tag + tooltip, filterable)
via `ProcessInfo::sandboxed`. Validated against real private-mount-namespace processes
and a live Flatpak app. Remaining: `setns` for the rare targets where cross-namespace
`process_vm_readv` is refused (not reproducible with CAP_SYS_PTRACE), and multi-process
renderer discovery (overlaps block 3).

### D. Guest-memory / address-translation model
A generic "the interesting memory is a buffer inside another process, at an offset,
possibly byte-swapped" abstraction: a scan/read/write view that maps guest addresses
to host offsets. Effort: medium. Unlocks: all emulators, and conceptually Wine.

### E. Target capability probe + honest reporting  [IMPLEMENTED]
Shipped: `ce::probeTarget(pid)` -> `TargetProfile` (`core/target_profile.hpp`),
surfaced on GUI attach (status line + tooltip + already-traced warning) and via
`cescan info <pid>`. Detects arch, Wine/Proton, TracerPid, seccomp, PID namespace,
managed runtimes (CoreCLR/Mono/JVM/V8/Go), endianness, and known emulators, with a
plain-language notes list. Remaining/future: packer/entropy heuristics, per-thread
state (which threads are latency-critical) for the hijack/watch-thread picker.

Before scanning/attaching, detect and *report*: architecture and endianness, whether
the process is already traced (`TracerPid`), whether it self-checksums or is packed,
whether a managed runtime/JIT is present (module names: `libcoreclr`, `libjvm`,
`v8`, Go's `runtime.g0`), whether it is sandboxed, whether it uses huge pages. Turn
silent freezes/failures into a clear "this target is X; feature Y is limited because
Z". Effort: small-medium. Unlocks: better UX everywhere; prerequisite for not
repeating the Wine "silent freeze" experience.

---

## 1. Managed runtimes with moving GCs and JITs

**Examples:** .NET / CoreCLR, Java / JVM (HotSpot, OpenJDK), Go, Godot (GDScript +
its own VM), modern JS engines (V8 in Electron/Node, JavaScriptCore), LuaJIT, Python
3.12+ (adaptive specializing interpreter). Unity/Mono is the already-handled friendly
case.

**Why it breaks the tool:** two independent problems.
- **Moving/compacting GC:** the value's address changes when the GC compacts the
  heap. A found address is stale after the next collection; pointer scans through
  managed objects are unstable; "freeze" writes to a moved address corrupt unrelated
  data. Editing works for a few seconds, then the value teleports.
- **JIT / tiered compilation:** the instruction that writes the value is JIT-emitted
  and can be re-compiled and relocated (interpreter -> baseline -> optimized). A
  "find what writes" result becomes garbage after re-JIT, and an AA patch is
  overwritten. **W^X JITs** (V8, CoreCLR, modern JITs) keep code pages
  executable-XOR-writable, sometimes via `memfd`/dual-mapping or `pkey`/MPK, so an
  external byte-patch either faults or races the runtime flipping the page.
- GC write barriers and card tables mean the "store" is wrapped in barrier code, so
  find-what-writes often surfaces the barrier, not the logical assignment.

**Plan (phased):**
1. **Detect and label** (block E): identify the runtime from loaded modules and
   report "managed heap: addresses move on GC; use structure/pointer resolution via
   the runtime, not raw pointer scans."
2. **Runtime-assisted resolution via the agent** (block B), per runtime:
   - .NET: use the CoreCLR debugging/diagnostics surface (DAC, `ICorDebug`, or the
     `dotnet-dump`/EventPipe path) to walk managed objects and get stable handles.
   - JVM: JVMTI agent (`Agent_OnAttach` via the attach API) to enumerate objects and
     fields with stable tags.
   - Go: parse the Go runtime type metadata (`runtime._type`, moduledata) from memory;
     Go's non-moving-ish heap for most objects helps, but stacks move.
   - Godot: it exposes an object database (`ObjectDB`) and a script debugger protocol;
     talk to it rather than scanning.
3. **Pinning / rooting:** the agent pins the object of interest so its address is
   stable while the user edits (GC handle / GCHandle.Pinned / JNI global ref).
4. **W^X-safe patching:** do code patches from *inside* via the agent (the runtime
   already owns permission to flip its own code), or use the runtime's own hook
   points (managed method interception, `Harmony`-style, JVMTI bytecode
   instrumentation) instead of raw byte patching.

**Effort:** large, and per-runtime. **Priority:** high for .NET/Godot/Go (the big
engines after Unity); the GC-address-instability is the single most common reason a
found value "stops working" and is worth solving properly.

## 2. Emulators (guest memory inside a host process)

**Examples:** RPCS3 (PS3), Dolphin (GameCube/Wii), PCSX2 (PS2), yuzu/Ryujinx (Switch),
Citra (3DS), DuckStation/PCSX (PS1), MAME, and x86-on-ARM translators (Box64, FEX-emu,
Hangover). Very popular on Linux and directly the same shape as Wine.

**Why it breaks the tool:** the game's RAM is a **big `mmap`'d buffer inside the
emulator's address space**. A "value" is at a *guest* address, not a host address, so
naive scanning searches the emulator (and finds the guest RAM buffer plus emulator
state). The guest CPU is interpreted or JIT'd, so find-what-writes surfaces the
emulator's dispatcher/JIT, not a guest instruction. Consoles may be **big-endian**
(PS3, Wii, GameCube), so values are byte-swapped. Guest<->host address translation is
required, and it can be non-linear (paged MMU emulation).

**Plan (phased):**
1. **Emulator-aware target mode** (blocks D + E): recognize known emulators, locate
   the guest-RAM region(s) in the host maps (often a large fixed-size anonymous or
   `memfd` mapping; several emulators expose the base via a symbol or a known offset),
   and expose a *guest view*: scan/read/write in guest address space with the right
   size and endianness.  [CLI DONE] `probeTarget` locates candidate guest RAM;
   `core/guest_view.hpp` (`GuestView` + `guestScanExact`/`guestNextExact`/
   `guestNextCompare`/`guestCompareBuffers`) does the translation and endianness;
   `cescan guest-scan` drives the FULL CE scan workflow from the shell: exact and
   `--unknown` first scans, `--next`, and `--changed`/`--unchanged`/`--increased`/
   `--decreased` comparison narrowing, all with `--be`. GUI: Tools -> "Emulator guest
   scan" (`gui/guest_scan_dialog`) drives the full workflow with type + endianness:
   exact first/next scans, Unknown Scan, and Changed/Increased/Decreased/Unchanged
   narrowing, and adds results (as host addresses) to the cheat table -- reusing the
   same `guest_view` primitives as the CLI. Cheat-table entries are endianness-aware: an
   entry can be flagged big-endian (right-click -> "Big-endian value"; guest-scan sets it
   automatically), so display byte-swaps to host order and edits swap back -- a
   big-endian guest value now reads and edits correctly in the list. Remaining: more
   emulator base adapters; guest MMU translation; per-guest find-what-writes.
2. **Endianness:** add byte-swap to the scanner value stream for big-endian guests
   (the scanner already handles width; add an endianness flag on the guest view).
   [DONE for the guest-view/`cescan guest-scan` path; the main GUI scanner is not
   yet endianness-aware.]
3. **Per-emulator adapters:** a small table (or agent) per emulator that gives the
   guest-RAM base and, where available, the guest MMU translation. Start with the most
   popular (Dolphin, PCSX2, RPCS3, DuckStation). [Dolphin DONE] `findGuestRam` detects
   Dolphin's `/dev/shm/dolphin-emu`(`dolphinmem`) shm and collapses its fastmem mirror
   views by file offset, so the candidates are the real MEM1 (24 MB) + MEM2 (64 MB), not
   a dozen duplicates or unrelated arenas -- the same shm-name + offset approach as
   `aldelaro5/dolphin-memory-engine`. Validated on a synthetic Dolphin process and in
   cecore_test. PCSX2/RPCS3/DuckStation adapters TODO (need the shm/arena signatures).
4. **Guest code analysis (stretch):** to do a real "find what writes" on the *guest*
   instruction, watch the guest RAM buffer at the host level (page-guard on the host
   buffer works, it is our own page) and, on a host fault, decode the guest PC from
   the emulator's CPU state. This needs an emulator adapter that exposes the guest
   register file. Big lift; the scan/edit/freeze path (steps 1-3) delivers 80% of the
   value first.

**Effort:** medium for scan/edit/freeze (steps 1-3), large for guest code analysis.
**Priority:** very high. This is a killer feature no Linux tool does well, and it is
squarely in scope (single-player console games).

## 3. Sandboxed and multi-process apps

**Examples:** Flatpak / Snap / Firejail-packaged games and apps (the Linux desktop
default now), Chromium/Firefox (site isolation), Electron apps, anything in a Docker/
Podman container.

**Why it breaks the tool:** the value lives in a **child/renderer process inside a
PID + mount + user namespace**. From outside: the PID differs from what the app sees,
`/proc/<pid>/maps` paths point into the sandbox root, `process_vm_readv`/ptrace across
the namespace boundary need privilege or are blocked by the sandbox's seccomp-bpf
filter, and the value may be in one of many renderer processes.

**Plan (phased):**
1. **Namespace-aware attach** (block C): map host<->sandbox PIDs (`NSpid` in
   `/proc/<pid>/status`), read maps/exe via `/proc/<pid>/root`, and `setns` where
   `process_vm_readv` needs it. Surface sandboxed processes in the picker with a
   badge.
2. **Multi-process discovery:** enumerate the process tree of an app (Chromium's
   `--type=renderer`, Electron's helpers) and let the user pick, or scan across a
   process group and report which PID a hit is in. [STARTED] `ce::processDescendants`
   (`core/ns_attach.hpp`) walks the tree from /proc; `cescan tree <pid>` lists a
   process and its descendants largest-RSS-first with a sandbox badge, so the user can
   pick the right renderer (validated on a real Discord bwrap tree). Remaining: a
   grouped tree in the GUI picker, and scan-across-the-group.
3. **Sandbox limits, reported:** when a target's seccomp filter blocks ptrace, say so
   (block E) and fall back to read-only `process_vm_readv` if permitted, so scan/edit
   still work even when watchpoints do not.

**Effort:** medium. **Priority:** medium-high and rising as Flatpak/Snap become the
norm.

## 4. Anti-debug, anti-tamper, packers (detect, do not bypass)

**Examples:** VMProtect, Themida/WinLicense, Enigma, Denuvo, and homegrown checks;
even single-player DRM. Kernel anti-cheat (EAC, BattlEye, Vanguard) is a separate,
explicitly out-of-scope world.

**Why it breaks the tool:** `PTRACE_TRACEME` self-attach means only one tracer, so our
attach fails. `TracerPid`/`/proc/self/status` checks detect us. `rdtsc` timing checks
see our single-step/stop as a multi-second stall. Code checksumming detects int3/jmp
patches. **Code virtualization** (VMProtect-style) means there is no native
instruction that writes the value; the logic runs in a custom bytecode VM, so
find-what-writes only ever finds the VM dispatcher.

**Plan:** **detect and report, never bypass.** This is a hard project boundary
(CLAUDE.md: no detection-evasion / anti-cheat-bypass). The valuable, in-scope work is
block E: recognize "this process self-traces / is packed (entropy, known packer
signatures) / virtualizes its code" and tell the user plainly why find-what-writes or
patching will not work, instead of freezing or silently failing. No evasion, no
un-packing tooling.

## 5. Non-x86 architectures

**Examples:** ARM64/aarch64 (Asahi on Apple Silicon, ARM Chromebooks, SBCs like the
Pi, cloud ARM, phones), and x86-on-ARM translators (Box64/FEX, see also Emulators).
RISC-V later. Big-endian mostly via emulated consoles (see Emulators).

**Why it breaks the tool:** injection emits x86 syscall gadgets; hardware watchpoints
program x86 DR0-3; breakpoints assume int3. ARM64 has different watchpoint registers
(`DBGWCR`/`DBGBCR`, a variable number of them), a different syscall ABI (`svc #0`,
args in x0-x5), and `brk #imm` breakpoints. Disasm/asm already work via Capstone/
Keystone.

**Plan (phased):**
1. **Arch abstraction** (block A) is the real prerequisite.
2. **ARM64 backend:** implement the `TargetArch` interface for aarch64: `svc`
   injection gadget, `DBGWCR/DBGBCR` watchpoints via `PTRACE_SETREGSET`
   (`NT_ARM_HW_WATCH`), `brk` breakpoints, x0-x30 register map. Reuse the whole
   scanner/AA/Lua layer unchanged.
3. **Validate** on native ARM64 Linux (an SBC or ARM VM on this effort's box, or a
   cloud ARM instance) with the same wp_target harness pattern.

**Effort:** large (arch layer + backend). **Priority:** medium now, rising fast;
worth doing the arch abstraction (block A) soon even before the full ARM64 backend so
the codebase stops hard-coding x86.

## 6. Obfuscated or non-stored values

**Examples:** health stored as a checksummed struct (patch it -> CRC mismatch ->
crash), values XOR'd/encoded/split across bytes, values recomputed each frame and
never stored, "safe" wrappers (Il2Cpp `SecureValue`, Unreal `TVariant` tricks).

**Why it breaks the tool:** there is no plain integer at a fixed address to scan or
freeze. CE's "encrypted value" and "unknown initial value" scans help find *movement*,
but the address may hold an encoded form, and freezing raw bytes trips an integrity
check.

**Plan (phased):**
1. **Unknown-value + changed/increased/decreased scan chains** already exist; document
   the workflow for encoded values (scan by change, not by value).
2. **Encoded-value templates:** let the user declare a codec (XOR key, add/rotate,
   split-byte layout) so the scanner searches for `decode(bytes) == value` and the
   editor writes `encode(value)`. A small pluggable "value codec" hook on the scan.
   [DONE for constant codecs] `core/value_codec.hpp` (`ValueCodec`: xor/add/rol/ror,
   width-aware) plus `cescan scan/read/write --codec xor:0xKEY|add:N|rol:N|ror:N`. The
   scan searches for the encoded needle, `write` stores the encoded form, and `read`
   shows the decoded logical value, and `cescan freeze --codec` locks it (re-writing the
   encoded form, with floor/ceil modes via `freezeShouldWrite`), so the whole
   find/verify/edit/lock loop is by the value the game displays, no Lua. Validated
   end-to-end on an XOR-obfuscated target (scan, read, write, and freeze incl. floor
   mode). Split-byte / non-constant layouts remain the job of the `--type custom` Lua
   scan; GUI wiring is a follow-up.
3. **Checksum-aware editing:** when a write is reverted quickly (an integrity thread
   restored it), detect and report it, and offer to find-what-writes the restorer so
   the user can neutralize the check (in-scope: it is the game's own logic, not an
   anti-cheat). Depends on find-what-writes working on the target.
   [DETECTION DONE] `cescan write --verify[-ms n]` re-reads after a window (default
   200 ms) and reports whether the value held or was reverted (and to what), pointing
   the user at find-what-writes. Find-what-writes is scriptable too: `cescan watch
   <pid> <addr> [--access]` lists the instructions that write/read an address (Wine-safe
   main-thread hardware watch by default, exact store recovery from the trap rip). And
   `cescan write <val> --verify --find-writer` chains the whole diagnosis into one
   command: write, detect the revert, then find and name the exact restoring
   instruction. Validated end-to-end against a target whose watchdog thread restores a
   value: the chain reports the revert and pinpoints `mov [rax],0x64` at guard+0x17.
   [DONE] The remaining stretch is neutralizing the check (NOP the restorer), which the
   GUI code list already does.

**Effort:** medium. **Priority:** medium; mostly a scanner/UX feature, largely
arch-agnostic.

## 7. Unusual memory and threading models

**Examples:** transparent huge pages (THP), io_uring-heavy servers/games, and any
program with latency-critical threads (audio, GPU, VR, real-time).

**Why it breaks the tool:** THP makes a "page" 2 MB, so the software page-guard is
2 MB-coarse (one guarded value faults on writes to a huge neighborhood). io_uring
threads sit in `io_uring_enter` and are rarely at a clean interruptible point.
Latency-critical threads glitch or crash if stopped even briefly, exactly the Wine
GPU-thread failure.

**Plan:**
1. **Prefer hardware watchpoints** (byte-granular, no page effect) whenever available;
   the single-thread Wine fix already points this way. Fall back to page-guard only on
   native targets without THP on the value's region.
2. **Never stop latency-critical threads for transient ops** (already the rule from
   v0.6.6; extend the capability probe to flag such threads and avoid them when
   picking a hijack/watch thread).
3. **THP awareness:** detect `AnonHugePages` on the value's region (`/proc/<pid>/smaps`)
   and warn that page-guard granularity is coarse there; prefer hardware.

**Effort:** small-medium. **Priority:** low-medium; mostly hardening rules the Wine
work already established.

---

## Prioritized sequencing

Ordered by relevance-times-tractability for the project's mission (single-player
games, RE, learning, native Linux):

1. **Capability probe + honest reporting (block E).** DONE (probeTarget /
   `cescan info`). Small, unlocks better UX everywhere, and prevents repeating the
   "silent freeze" discovery loop.
2. **Emulators, scan/edit/freeze (block D + adapters).** Highest user value, in scope,
   medium effort. Start with Dolphin, PCSX2, RPCS3, DuckStation.
3. **Namespace-aware attach (block C).** Flatpak/Snap are the desktop default; medium
   effort. Mostly landed: mount-namespace backing-file resolution (symbols + IL2CPP
   metadata on sandboxed targets), inner-PID reporting, and a picker sandbox badge.
   `setns` fallback and multi-process renderer discovery remain.
4. **Agent framework generalization (block B)** then a **.NET / Godot / Go** resolver.
   The honest fix for moving-GC targets.
5. **Arch abstraction (block A)** then an **ARM64 backend.** Large but increasingly
   necessary; do the abstraction early even if the backend lands later.
6. **Encoded-value codecs + THP/latency hardening.** Smaller scanner/robustness wins.

## Explicit non-goals

- **No anti-cheat / anti-tamper bypass, no detection evasion, no un-packing tooling.**
  For those targets we detect and report only. This is a hard boundary (CLAUDE.md,
  project scope).
- **No Windows / kernel-stealth (DBVM/DBK).** Parked.
- The point is to be the best *native Linux* memory tool for legitimate targets, not
  to defeat protections.
