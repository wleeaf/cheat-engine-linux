# Compatibility work: progress and remaining work

Checkpoint: 7 October 2026. This records the work accumulated since release
0.9.5 and accompanies the current source checkpoint. The full six-area
compatibility objective is **not complete**. A target being recognized, a build
succeeding, or a generic byte read working does not prove that debugging,
injection, runtime objects and every frontend work on that target.

[COMPATIBILITY.md](COMPATIBILITY.md) contains the feature-by-target matrix,
implementation details and individual evidence records. The
[earlier checkpoint report](compatibility-evidence/checkpoint.json) records
its own local checks. Older evidence snapshots describe the source and
binaries tested at their own checkpoint; their counts must not be added together
as a count of unique tests or presented as fresh checks of every environment.

The ordered, breadth-first execution plan for the remaining work is
[COVERAGE_PLAN.md](COVERAGE_PLAN.md).

## GUI polish from a full screenshot review: 13 October 2026

`gui_lifecycle_smoke --screenshots DIR` now renders about 180 PNGs: every
window and dialog in both themes, the menu bar and Memory Viewer menus, the
address list and results context menus, the dialogs those menus open, and the
main window before and after a real scan. Each was inspected and the problems
fixed: Settings options that were saved but never read are wired up or
removed (with the placeholder pages), stub menu items are gone, tables share
one style with readable sizes, filters and empty-state hints, the process
picker shows untruncated names, Save writes in place, and several dialogs are
redesigned. One root cause worth knowing: a font set with `setFont()` on an
item view is dropped when Qt's stylesheet engine re-polishes the reparented
widget, so data tables now take the monospace font from the theme sheet
(`monospace` property). The full lifecycle, debugger, register, search,
hex-view, disassembler, Lua console, guest-scan, code-finder, change-address,
structure and theme smokes pass locally, and CI is green.
The installed `cheatengine` binary was also captured directly (`CE_SCREENSHOT`,
first run, attached, Memory Viewer, Settings) at 1x, 1.5x and 2x in both
themes, and the whole harness was rendered at `QT_SCALE_FACTOR=1.5`; chevrons,
check marks and text stay sharp at every scale. Analysis windows were captured
with real data (code references, find statics, pointer scan, ELF tabs), which
surfaced versioned C++ symbols (`...@Qt_6`) left mangled; they now demangle.
Finally the real binary ran on an actual X11 server (a private headless mutter
with rootful Xwayland, in its own D-Bus session) with the GTK3 platform theme
that GNOME selects, and the screen was captured with ImageMagick. That showed
the native GTK file chooser hides `.CT` tables because its patterns are
case-sensitive; table and script filters now list both spellings, and Save As
adds the extension of the chosen file type.
The window frame was checked too, by running the app as a native Wayland
client on that headless mutter and recording its virtual monitor through
`org.gnome.Mutter.ScreenCast` (a private PipeWire). Qt's Adwaita title bar
takes its colours from the portal's `color-scheme`, not from the app, so on a
`prefer-dark` desktop a first launch showed light content under a dark frame
(the GTK3 palette reports light). The first-run theme now follows that same
portal preference; an explicit Theme choice in Settings still wins.
A last capture reproduced the user's own GNOME configuration (1920x1080 at
scale 1, `text-scaling-factor` 1.35, Adwaita Sans 11 and Adwaita Mono 11,
`prefer-dark`) on the headless mutter. The monospace default now follows the
desktop font; resolving it through `QFontDatabase::systemFont(FixedFont)`
was rejected after that capture showed it switching combo boxes, line edits
and group boxes to the fixed font under the GTK3 theme in dark mode, so the
family is resolved through fontconfig instead.

## Frontends inside every ISA guest; coverage complete: 12 October 2026

Item 2.1 of the [coverage plan](COVERAGE_PLAN.md) for the remaining guests.
cecore compiles unchanged for RISC-V64, s390x, PowerPC64LE and ARM32: each
ISA job now cross-builds a Qt-free `cescan` (Capstone and Keystone from
source, plus a static position-independent zlib 1.3.1 pinned by SHA-256,
since cecore links zlib for CEServer compression). The guest driver runs it
against the fixture in the same boot: `cescan info` names the program and its
ABI, `cescan write` reaches the program, `cescan scan` finds the value and a
`cescan lua` script reads and writes it. All four guests pass 17 checks,
s390x included (big-endian). The gate now requires the four frontend checks
whenever it adds a frontend, and the steps are required. ARM32, RISC-V and
the other-ISA row reach C10 at `B` (GUI not run in guests).

Every applicable cell of the matrix now has live evidence or an explicit,
documented block: coverage is **268/268 (100%)**. Depth (`V` cells) is 7/268;
per the plan, depth comes next, then Waves 6 and 7.

## A live ARM64EC program, and frontends inside the x32 guest: 12 October 2026

Item 3.4 of the [coverage plan](COVERAGE_PLAN.md) went further than planned.
ARM64EC executables declare the x64 machine in their PE header, so cecore took
them for plain x86-64 Windows code and would have decoded ARM64 instructions
as x86. A PE32+ image whose load config carries a CHPE metadata pointer is now
classified ARM64EC (x64-declared) or ARM64X (ARM64-declared), and disassembly
refuses it with the reason: choosing ARM64 or x64 per address needs the
image's CHPE code-range map, which is not implemented.

The hosted ARM64 runner now builds an ARM64EC console fixture with llvm-mingw
(20260908) and runs it under Hangover 11.16's Wine (both pinned by SHA-256).
`test/arm64ec_target_gate.py` passes 10 checks: the CLI and Lua frontends
identify the Wine-hosted ARM64EC program, write and read its value, scan and
rescan it, and resolve a static pointer path through its module (C1 to C4 at
`B`). Disassembly, injection, native calls, find-what-writes and the debugger
each refuse with an explicit reason, which the gate requires verbatim (C5 to
C9 at `X`), and the program keeps running afterwards. The step is required.

`isa_vm_gate.py --frontend` copies a `cescan` and the shared libraries it
needs (interpreter, `DT_NEEDED` and `RUNPATH`, resolved with `readelf`) into
the guest's initramfs, and the guest driver then drives the fixture through
`cescan info`, `write`, `scan` and a `cescan lua` script. The x32 guest runs
the host-built CLI against the x32 program that way (x32 C10 at `B`). Cross
builds of the CLI for the RISC-V, s390x, PowerPC64 and ARM32 guests run as an
exploratory step. Coverage is now 265/268 (98.9%).

## IL2CPP: blocked for live checks: 12 October 2026

Item 1.5 of the [coverage plan](COVERAGE_PLAN.md). No legally redistributable
IL2CPP Linux build exists for CI: IL2CPP output needs a licensed Unity editor,
and no open-source Unity project publishes an IL2CPP Linux release. Following
the plan, the parser tests stay (including a real Disco Elysium v27
`global-metadata.dat` with 16187 types, checked locally) and the ten live
IL2CPP cells are `X` with that reason. This is an environment block, not a
refusal by the tool: an IL2CPP game is a native process, and attaching to one
locally (for example a game the user owns) would upgrade the row. Coverage is
now 254/268 (94.8%).

## Unreadable targets, .NET ReadyToRun modules, and a live mGBA: 12 October 2026

Three product defects surfaced while finishing items 5.3 and the CoreCLR open
item of the [coverage plan](COVERAGE_PLAN.md):

- **Silent empty scans.** Under Yama `ptrace_scope` 1 every read of a process
  that is not a descendant fails with `EPERM`, and `cescan scan`, `guest-scan`
  and the GUI First Scan reported that as zero results. The new cecore
  `memoryAccessProblem()` probes a few readable regions first; when none can
  be read, all three stop with the reason and a `ptrace_scope` hint
  (core-suite check with a fake `EPERM` target). This is why the mGBA probe
  found nothing on CI; it now runs as root, like the JIT runtime gate.
- **ReadyToRun PE machines.** .NET ReadyToRun assemblies (System.Private.CoreLib
  and friends) store the PE machine XORed with an OS constant (Linux, Apple,
  FreeBSD, NetBSD, SunOS), so cecore classified them as an unknown
  architecture. `modules()` also stretched each PE module across every mapping
  of its file. When CoreCLR placed JIT code inside that span, the Auto
  Assembler built the code cave for "other" and failed: the CoreCLR
  intermittency, which depended only on address layout. `parsePeTarget`
  decodes the override, a PE module keeps its SizeOfImage extent, and the
  Auto Assembler never takes an unusable architecture from a module.
- The CoreCLR checks now run with .NET's default W^X double mapping, so code
  patches go through the backing-file path added earlier today.

With these, the CoreCLR injection, breakpoint and GUI checks pass in the main
run and in three required repeat rounds (five of five in the measuring run),
and CoreCLR C6, C9 and C10 return at `B`.

The mGBA gate now passes **11 checks** on a real emulator running the
generated ROM: identification, a value scan that tells live guest RAM from
mGBA's rewind snapshots (a host write at +0 must be copied by the guest
program to +8), typed writes the guest observes, a next scan, a non-static
pointer path to the guest RAM buffer, disassembly of the guest's ARM code
from the emulator's ROM image, find-what-writes reporting mGBA's host store,
a Lua breakpoint there, and the GUI main and debugger windows. Writer and
breakpoint results are host instructions, not guest ones, as the matrix
evidence states. The step is required. Console emulators reach `B` in every
applicable capability. Coverage is now 244/268 (91.0%).

## Code patches in W^X double-mapped JIT code: 12 October 2026

.NET 7+ (and other W^X JITs) map generated code as an executable read-only
view of a shared memfd, writing it through a separate, short-lived writable
view. The kernel refuses forced remote writes (`PTRACE_POKETEXT`,
`/proc/PID/mem`) to shared read-only mappings, so software breakpoints,
Auto Assembler hooks and code writes at such addresses failed. cecore now
falls back to `writeSharedMappingBacking`: it finds the mapping's file
(device and inode), reopens the target's own open descriptor for it through
`/proc/PID/fd` (the same ptrace access check), and writes at the mapping's
file offset; both views share the page. Breakpoint planting and
`LinuxProcessHandle::write`/`writeCode` use it. A new core-suite check
reproduces the layout (a memfd page mapped writable, written, unmapped, and
executed through a read-only view) and requires both a write and a debugger
breakpoint to land there. The hosted CoreCLR runtime checks still run with
W^X off until their intermittent failure is understood.

## Console emulators: first live evidence: 12 October 2026

Item 5.3 of the [coverage plan](COVERAGE_PLAN.md), time-boxed.
`test/emulator_target_gate.py` generates a minimal homebrew GBA ROM (a dozen
ARM7 instructions, no game data) and runs the real mGBA (`mgba-sdl`) under
Xvfb on the hosted runner. `cescan info` identifies the live mGBA process
(console emulators C1 at `B`). The ROM's marker was not found in the
emulator's memory, so the ROM most likely did not start executing (header or
boot path); that part, guest-RAM writes and scans, remains open, and the CI
step stays non-blocking. Coverage is now 234/268 (87.3%).

## Snap confinement, and a CoreCLR open item: 12 October 2026

Hosted runners have `snapd`, and `snap run --shell <snap> -c <command>` runs a
command under the snap's real AppArmor profile, seccomp filter and mount
namespace. The static fixture, placed in the snap's user-data directory,
passes all **15 frontend checks** from the host under strict confinement
(native calls refused as for any static program). The step is now required
in the hosted build job, with the GUI stage. Matrix: the Snap row reaches `B`
in eight capabilities and `X` for native calls.

CoreCLR's breakpoint and code-cave checks at the correct optimized writer
passed in two hosted runs and failed in the next, so they are not claimed:
C6, C9 and C10 for CoreCLR return to `-` as an open item, and the gate skips
them with a printed note. Coverage is now 232/268 (86.6%).

## Explicit refusals inside RISC-V, s390x, PowerPC64 and ARM32 guests: 12 October 2026

On instruction sets without allocation, native-call, watchpoint or debugger
backends, the guest driver now calls the real APIs (`allocate`,
`createRemoteThread`, `CodeFinder::start`, `DebugSession::attach`) and
requires each to refuse with its capability reason ("Target syscall ABI has no
backend yet", "No complete backend for this target/transport"). All four
guests pass 13 checks on hosted CI, so these cells are verified `X`: the tool
says what it cannot do instead of failing silently. The whole hosted matrix
(14 jobs) is green. Coverage is now 226/268 (84.3%).

## ARM32 and x32 guests, GDB CLI on real QEMU: 12 October 2026

The ISA guest matrix gained **armhf** (Ubuntu 6.8 armhf kernel on QEMU virt;
the static program is Thumb-2, so the driver follows the EABI interworking
bit to decode Thumb) and **x32** (the LP64 static driver against a `-mx32`
static program under the pinned x32-enabled Debian kernel; the expected
pointer width now comes from the program's ELF class). Both pass all checks
on hosted CI, as do RISC-V64, s390x and ppc64el. The GDB gate now also runs
one CLI command (`cescan gdb ... reg pc`) against the real stopped QEMU CPU,
and its Lua run requires a non-static pointer path over guest RAM.

Hosted CI also surfaced: remote code patches on ARM64 over CEServer are
refused ("Code write failed: Operation not supported"); the gate now requires
that explicit refusal on ARM rather than a hook. CoreCLR's tiered compilation
keeps replacing hot methods, so an instruction found by find-what-writes can
stop running; the runtime checks use one compiled version
(`DOTNET_TieredCompilation=0`). The diagnostics then showed the real cause:
.NET 7+ maps JIT code W^X, an executable read-only view of a shared memfd plus
a separate writable view, and forced writes are refused on shared read-only
mappings, so breakpoints and hooks at JIT addresses never land. The CoreCLR
checks run with `DOTNET_EnableWriteXorExecute=0`; writing through the
writable alias is an open item. With that, Mono and CoreCLR pass every
runtime check on hosted CI, including native calls and the Qt windows.
Coverage is now 216/268 (80.6%).

## s390x and PowerPC64 guests: 12 October 2026

Item 3.3 of the [coverage plan](COVERAGE_PLAN.md). The disassembler gained
PowerPC64 (both byte orders), s390x and MIPS64 through Capstone (decoding
only; this build's Keystone has no such targets, which is reported), the
native-machine detection learned s390x, PowerPC64 and MIPS hosts, and
`tools/check-isa-vm.sh` takes the ISA as a parameter with pinned Ubuntu 24.04
kernels. In real guests, **s390x (big-endian) and ppc64el pass all 9 checks**:
identification, ELF symbols, writes, first/next scans, pointer path and
decoding (`larl`, `l`, `ahi`, `st` on s390x).

s390x exposed one real limitation: the ELF symbol loader accepted only
little-endian files, even on a big-endian host reading its own programs. It
reads ELF structures in host order, so it now accepts files in the host's
byte order (cross-endian files are still refused rather than misread). The
`isa-compatibility` workflow runs RISC-V64, s390x and ppc64el as a matrix.
MIPS has decoding support but no guest yet. Coverage is now 191/268 (71.3%).

## cecore inside a real RISC-V64 guest: 12 October 2026

Item 3.2 of the [coverage plan](COVERAGE_PLAN.md), at the `B` level. The new
`test/isa_vm/` project cross-builds a static driver from cecore's
architecture-generic parts (process handle, memory-syscall service, memory and
pointer scanners, ELF symbol loader, Capstone disassembler) plus the static
libc fixture. Every source compiled for RISC-V64 unchanged. `tools/check-isa-vm.sh`
pins an Ubuntu 24.04 RISC-V kernel package (its `vmlinuz` is a raw boot Image)
and the same Capstone commit as the ARM64 guest, built with RISC-V only;
`test/isa_vm_gate.py` boots the driver as `/init` in `qemu-system-riscv64`
(virt, OpenSBI) and requires its checks.

In the guest, all **9 checks** pass: the fixture runs, the target description
reports RISC-V64 / Linux RISC-V with the right module list, the ELF symbol
table names the writer and value, a process write reaches the program, first
and next scans find the value, a pointer scan finds and dereferences the
static path, and the writer's instructions decode as RISC-V. A new
`isa-compatibility` hosted workflow runs this on every build and gates
releases. Debugging, injection and native calls on RISC-V still need
architecture-specific backends. Coverage is now 186/268 (69.4%).

## Native ARM64 programs, RISC-V decoding and ARM over CEServer: 12 October 2026

The frontend gate is now architecture-aware (ELF machine, ARM64 hook scripts
with `movz`/`movk`/`str` and a `b` into the cave, the portable `BPAddress` at
breakpoints) and runs on GitHub's native ARM64 runner against an ordinary
ARM64 glibc program. Every CLI and Lua check passed there: identification,
typed writes, first/next scans, pointer scan, the hook and its undo,
find-what-writes, the Lua breakpoint and native calls (AArch64 C3 and C4 at
`B`). Lua breakpoints on ARM now also publish `X0`..`X30`/`R0`..`R12`, `SP`,
`PC` and `PSTATE`.

Its CEServer stage exposed a client limitation: ARM targets over CEServer kept
an unknown data byte order (the wire architecture code has none), so every
typed access was refused. The protocol frames all integers in the server's
host order, so a working connection implies a little-endian server, and Linux
ARM userland byte order is system-wide; ARM targets over CEServer are now
little-endian.

The disassembler gained RISC-V32/64 (with the compressed extension) through
Capstone; the target model already classified RISC-V. Keystone has no RISC-V,
so `assemblerArchFor` now reports that instead of throwing, the capability
report shows assembling as unsupported for RISC-V, and the CLI, Lua, GUI and
code analyzer show the reason. A unit check decodes full-width and compressed
instructions. Coverage is now 181/268 (67.5%).

## Pointer paths and code caves in JIT code: 12 October 2026

Lua gained CE's injection-template functions (`generateCodeInjectionScript`,
`generateAOBInjectionScript`, `generateFullInjectionScript`), which return the
same templates the GUI generates. The runtime gate now also requires, for
Node/V8 and HotSpot, a non-static pointer scan whose path resolves to the
off-heap value (the runtimes keep its address in a heap object), and a code
injection at the JIT instruction that find-what-writes reported: the program
keeps computing correctly through the code cave, and undoing the script
restores the JIT code's bytes and behavior. With a busy runtime thread
(the fixtures' new `s`/`x` commands start a Java thread or a Node worker),
Lua `executeCode` and `injectLibrary` also run inside both runtimes'
processes. Matrix: C4, C6 and C7 at `B` for the V8 and JVM rows. Coverage is
now 179/268 (66.8%).

## Go programs: 12 October 2026

Item 4.2 of the [coverage plan](COVERAGE_PLAN.md). `test/runtimes/go_fixture.go`
speaks the same stdin protocol as the C fixture, with one extra header field
naming its writer's Go symbol (`main.ce_writer`), so the whole frontend gate
applies: identification and the Go symbol table, typed writes, scans, pointer
scan, an Auto Assembler hook named by the Go symbol, find-what-writes, a Lua
breakpoint, the Qt windows and the ceserver transport. A CGO-free Go binary
has no `pthread_detach` or `dlopen`, so native calls are refused with those
reasons. A Go 1.24 build (made in Alpine locally) passes all **25 checks**;
the hosted build job builds the fixture with Ubuntu's Go and runs the gate.
Goroutine migration between threads is not an issue for these checks, which
watch the shared value. Matrix: the Go row reaches `B` in nine capabilities
and `X` for native calls. Coverage is now 173/268 (64.6%).

## JIT runtimes: perf-map symbols for Node/V8 and HotSpot: 12 October 2026

Item 4.1 of the [coverage plan](COVERAGE_PLAN.md). `SymbolResolver` now reads
the target's `/tmp/perf-<pid>.map` (through the target's root and with its
namespaced PID, so containers work) and names JIT-generated code. HotSpot
(`jcmd <pid> Compiler.perfmap`), CoreCLR (`DOTNET_PerfMapEnabled=1`), V8/Node
(`--perf-basic-prof`) and LuaJIT all write this format. The file comes from
the target, so it is treated as untrusted: capped at 1 M entries and 64 MB,
lines over 4 KB and malformed lines skipped, and a recompiled function's latest
entry wins. JIT names then appear wherever symbols do: `cescan symbols`,
disassembly annotations, find-what-writes output and Lua `getAddress`.

`test/runtime_target_gate.py` drives Node and the JVM as a user would.
Fixtures (`test/runtimes/`) keep a value in off-heap memory (a
`SharedArrayBuffer`, a direct `ByteBuffer`) that a JIT-compiled function
updates. The gate finds the value with a marker scan and a next scan after a
real change, writes it, disassembles the named JIT code, runs find-what-writes
(on HotSpot it correctly names `DirectByteBuffer.putInt`, the compiled code
that really writes), breaks on that exact instruction from Lua, and drives the
Qt main and debugger windows. Locally, Node 22 and OpenJDK 21 pass all **9
checks each**; the hosted build job installs Node and OpenJDK 21 and runs the
gate. Matrix: V8 and JVM rows C1 to C3, C5 and C8 to C10 at `B`. Coverage is
now 163/268 (60.8%).

## Non-static pointer paths and GDB guest refusals: 12 October 2026

`PointerScanConfig::staticOnly` existed (and Lua accepted it), but the scanner
never read it: paths were recorded only when their base lay inside a module,
so a pointer scan of guest RAM, JIT code or heap-only data found nothing even
with "static only" turned off. With `staticOnly=false` the scanner now also
records module-less bases as absolute addresses (printed as the bare
address, dereferenced without a module, sharded by page). A unit check
covers resolution and shard merging.

The GDB guest checks now require a non-static pointer scan over real QEMU
guest RAM, and refusals with their capability reason for native calls and
find-what-writes, in both the stub and QEMU runs (C7 and C8 `X`).

## A usable CEServer and Lua script undo: 12 October 2026

Wave 2 of the [coverage plan](COVERAGE_PLAN.md) for the CEServer row. The
ceserver-protocol server (`CeserverServer`) existed and was tested, but no
frontend could start it. `cescan ceserver [--port N]` now serves local
processes to Cheat Engine or another cecore on 127.0.0.1 (default port
52736, CE's own); remote use goes through an SSH tunnel, because the protocol
grants full memory access.

Lua `autoAssemble` now follows CE: on success it returns `true` and a
disable-info object, and `autoAssemble(script, disableInfo)` undoes that
activation (original bytes, protections and allocations). Before, Lua could
enable a script but never disable it.

`frontend_target_gate.py --ceserver` drives a live glibc program through
`cescan ceserver` with a Lua client: typed writes, whole-address-space first
and next scans, a pointer scan, an Auto Assembler hook that changes the
program and is undone through the disable info, and a native call that is
refused with its reason. The hosted build job runs it. The GUI's connect
logic moved out of its dialog into `MainWindow::attachToCeserver`, and
`gui_lifecycle_smoke --ceserver-target` drives a whole-target scan, a next
scan and an address-list edit through that connection. Matrix: CEServer C3 to
C6 and C10 at `B`, C7 `X`. Coverage is now 147/268 (54.9%).

## Native calls, Lua symbols and the symbols listing: 12 October 2026

Wave 2 of the [coverage plan](COVERAGE_PLAN.md), capability C7. Driving
native calls through the frontends on ordinary programs exposed three gaps:

- **Lua symbols after `openProcess`.** The Lua engine's shared symbol
  resolver was cleared on every target change and never reloaded, so
  `getAddress('function')` returned nil and `injectLibrary` reported that
  `dlopen` was missing (it lives in `libc.so.6` since glibc 2.34) until a
  script called `reinitializeSymbolhandler()`. It now loads the attached
  process on first use, as CE's symbol handler does.
- **Parked programs.** Native calls borrow a thread that is executing user
  code; a program whose every thread is blocked in a system call is refused
  by design (restarting its waits could change their timing). The refusal
  used to read "Resource temporarily unavailable"; it now says that no thread
  is running user code. A program with an active thread (a game loop) works:
  the fixture's new `s`/`x` commands start and stop such a thread.
- **Static programs** carry only the thread functions they use. Without
  `pthread_detach`, native calls are refused, and the message now says so.

`cescan symbols` also gained a name filter (every match, no 200-entry cap)
and `--all`, and is now listed in `cescan help`.

The frontend gate checks all of this on live programs: the Lua symbol lookup,
the parked refusal, `executeCode` running the program's own function, and
`injectLibrary` loading the real `libm.so.6` into an unsandboxed glibc
program; static programs must refuse with their reasons. It passes for
dynamic glibc, static musl (x86-64 and i386), Flatpak, bubblewrap and the
Podman container, with the GUI stage. Matrix: C7 at `B` for bubblewrap and
Podman, `X` (explicit refusal) for the static and Flatpak rows. Coverage is
now 142/268 (53.0%).

## Windows programs through every frontend: 12 October 2026

Wave 2 of the [coverage plan](COVERAGE_PLAN.md) for the Windows rows. The
frontend gate (renamed from `libc_target_gate.py` to
`test/frontend_target_gate.py`) gained `--wine-launcher`, which runs the PE32 and PE32+
fixtures under `wine` or a Proton launcher. Both kinds of program share one
check flow: CLI identification, modules, typed write/read, first/next scans,
pointer scan, an Auto Assembler hook and disable (hex addresses, since the PE
fixtures carry no symbols), find-what-writes, a Lua breakpoint session, and
with `--gui` the Qt main and debugger windows.

Windows targets add one more check. Native calls into a Wine process need
Wine-safe loader and thread backends that do not exist yet, so Lua
`injectLibrary` and `executeCode` must refuse with that explicit reason
instead of attempting the call. This turns C7 into a verified `X` for the
Windows rows.

`wine_compatibility_test.py` and `proton_compatibility_gate.py` now run this
stage after the driver, with the GUI part whenever the build has Qt. Locally
it passes **14 checks per PE width** under Wine 11 and under Proton 9 and
Experimental 11, both on the host and inside the Steam Runtime containers.
The hosted Wine and Proton jobs build without Qt, so they cover CLI and Lua.
Matrix: C10 at `B` and C7 at `X` for the three Wine rows, Proton and the Steam
Runtime row. Coverage is now 139/268 (51.9%).

## GUI on any live target: 12 October 2026

Start of Wave 2 (frontend breadth) in the [coverage plan](COVERAGE_PLAN.md).
`gui_lifecycle_smoke --target PID VALUE WRITER` drives the real Qt main window
and debugger window against an arbitrary live process: a GUI first scan over
the whole target, a next scan after a real change, an address-list value edit
that must reach the target, and a debugger-window breakpoint at the writer
that the program itself hits, followed by detach. Reusing the existing smoke
binary avoids compiling the whole GUI a second time. `frontend_target_gate.py
--gui` runs it after the CLI and Lua stages and requires the interrupted call
to complete after detach.

The GUI stage passes for dynamic glibc, i386 static musl, Flatpak, bubblewrap
(static musl and dynamic glibc) and the Podman Alpine container; the hosted
build job runs it for every configuration except Flatpak. C10 (GUI, CLI and
Lua) reaches `B` for the static libc, Flatpak, bubblewrap and Podman rows.
Coverage is now 129/268 (48.1%).

## Sandboxed programs: Flatpak, bubblewrap and Podman: 12 October 2026

Item 1.7 of the [coverage plan](COVERAGE_PLAN.md). `frontend_target_gate.py`
gained `--launcher`, which starts each real libc fixture inside a sandbox.
The program then reports its namespaced PID (2 inside Flatpak), and the gate
operates on the host PID of that process, found through `NSpid`, exactly as
a user picking it from the host's process list would. Container engines
reparent the workload (Podman's conmon), so the gate also accepts the single
matching process started after the launcher.

All **12 frontend checks** (CLI and Lua: identification, symbols, typed
writes, scans, pointer scan, Auto Assembler hook and undo, find-what-writes,
Lua breakpoint) pass for:

- a static musl program under `flatpak run org.freedesktop.Platform//25.08`;
- static musl and dynamic glibc programs under `bwrap --unshare-all`
  (user, PID, network, IPC, UTS and cgroup namespaces);
- a dynamic musl program in its own rootless Alpine Podman container, with
  the target's musl loader and root filesystem.

The hosted build job now runs the bubblewrap case (as root, because Ubuntu's
AppArmor blocks unprivileged user namespaces for bwrap) and the Podman case.
Flatpak stays local: a hosted runner would need a large runtime download.
Snap is not installed here or on hosted runners, so its row has no evidence.
Matrix: Flatpak and bubblewrap rows C1 to C6, C8 and C9 at `B`; Podman gains
C3 to C6, C8 and C9. Coverage is now 125/268 (46.6%).

## Real libc programs and two Auto Assembler fixes: 12 October 2026

Item 1.6 of the [coverage plan](COVERAGE_PLAN.md). The new
`test/static_fixture.c` is an ordinary C program (a static value, a static
pointer to it and a non-inlined writer), built as static musl, static glibc,
dynamic glibc and i386. `test/frontend_target_gate.py` drives it only through the
user-facing frontends: `cescan info/symbols/modules`, typed write and read,
first/next scans, `pointerscan`, an `autoasm` hook with a code cave and
`--disable-after`, `watch`, and a `cescan lua` debugger breakpoint session.
Locally, static musl x86-64 and i386 (built in pinned Alpine containers) and
dynamic glibc x86-64 pass all **12 checks each**; the hosted build job builds
static glibc, static musl, dynamic glibc and `-m32` glibc and runs all four.
This is also the first live pointer-scan evidence for x86-64 and i386.

Writing the hook exposed two Auto Assembler gaps that affect real cheat tables:

- **CE operand numbers.** Bare numbers were already hex, as in Cheat Engine,
  but `#decimal` (`mov eax,#1000`), `$hex` and hex that starts with a letter
  or mixes digits and letters (`[rsi+1C]`, `mov [rax+C8],ecx`, `mov al,FF`)
  failed to assemble. x86 operands are now normalized before Keystone;
  mnemonics, quoted text and labels defined in the same block are untouched,
  and all-decimal-digit tokens keep their existing meaning. Unit checks cover
  each form on x86-64 and x86-32 plus a hex-looking label.
- **Process symbols.** Name references in scripts (`alloc(newmem,256,Func)`,
  `define(hook,Func)`, `[Func+5]`, `Func+0:`) did not consult the target's
  symbol table, so a named cave location silently fell back to "anywhere"
  and a define resolved to nothing. The resolver now loads the process
  symbol table lazily during `execute()`. An undeclared plain `name:` line
  deliberately stays a local label: auto-declared labels such as `exit:`
  must never turn into libc functions.

Matrix: the static libc / musl row gains C1 to C6, C8 and C9; x86-64 and
i386 pointer scans and i386 scans reach `B`; i386 frontends reach `B`.
Coverage is now 103/268 (38.4%).

## Full debugger on Wine and Proton: 12 October 2026

Item 1.3 of the [coverage plan](COVERAGE_PLAN.md). The shared Wine driver now
runs the full debugger against the live PE fixtures: an all-stop
`DebugSession` attach, a software breakpoint at the real PE writer, the hit
reported in the program's own register mode (x86-32 for PE32, also on the
64-bit WoW64 loader), one single step that advances exactly one Windows
instruction, breakpoint removal with the original byte restored, and the
interrupted call completing with the correct result. After detach the program
keeps answering. Break-and-trace then arms the same function, records its
instructions in the right mode, and the traced call completes.

Stopping the whole Wine process is this feature's purpose (see AGENTS.md's
Wine rules); transient operations elsewhere still never stop the whole group.
The checks pass on local Wine 11 (new WoW64) and through both Proton builds on
the host and inside their Steam Runtime containers, **110 checks per build**
in each mode. The hosted Wine 9, Wine 11 and GE-Proton jobs run the same
driver. Matrix: C9 at `B` for the three Wine rows, Proton and the Steam
Runtime row.

## Proton inside the Steam Runtime container: 12 October 2026

Item 1.2 of the [coverage plan](COVERAGE_PLAN.md). Steam does not run Proton
on the host: it wraps it in the Steam Linux Runtime container that the Proton
build declares (`require_tool_appid`), using pressure-vessel and bwrap with a
separate mount namespace and the runtime's own `/usr`. The Proton gate's new
`--in-steam-runtime` mode resolves that runtime from the Steam library exactly
as Steam does, and `--runtime DIR` names one explicitly.

Locally, Proton 9 inside SteamLinuxRuntime_sniper and Proton Experimental 11
inside SteamLinuxRuntime_4 each pass all **92 checks** while cheat-engine
operates from the host on the containerized process: identification, typed
writes, value and pointer scans, Auto Assembler injection with exact undo,
main-thread hardware find-what-writes and busy-loop memory operations with
exact register preservation. The hosted Proton job now also downloads a
pinned, checksum-verified Steam Linux Runtime 4 (`4.0.20260805.254769`) and
runs GE-Proton11-7 inside it.

The container connects the game's stdin to `/dev/null` (stdout passes
through), so the fixture's command channel is relayed through a FIFO on the
shared home path. Two shell details mattered: a background job in a
non-interactive shell reads `/dev/null` unless stdin is redirected explicitly,
and the FIFO path is embedded in the inner command rather than forwarded as an
argument. The Wine driver now also retries target identification briefly and
prints its candidates on failure. Matrix: Steam Runtime row C1 to C6 and C8
at `B`.

## Proton and Windows scans: 12 October 2026

Item 1.1 of the [coverage plan](COVERAGE_PLAN.md). The new
`test/proton_compatibility_gate.py` runs the existing PE32 and PE32+ console
fixtures through real Proton builds: Valve Proton 9.0 and Proton Experimental
11 locally, and a pinned, checksum-verified GE-Proton11-7 in a new hosted job
(`wine-compatibility.yml`, `proton`). Proton's `run` verb creates the private
prefix exactly as Steam does; the fixtures start with `runinprefix`, which
uses the same Proton Wine and environment (esync/fsync and, on Experimental,
`ntsync`) but skips the `steam.exe` wrapper. That wrapper exits without a
running Steam client and does not pass console handles. The gate works without
any Steam client directory, as on a hosted runner.

Two facts found on the way: both Valve builds run PE32 programs on a 32-bit
Unix loader (`i386-unix`), not new WoW64, so the gate detects the loader per
build; and Proton sets `WINEPREFIX` with a trailing slash, which the gate now
matches so the driver identifies its fixture by prefix.

The shared Wine driver also gained value and pointer scans: a whole-process
first scan and a next scan after a real change, and a depth-1 pointer scan
that must find the static PE data path and resolve it to the field. These run
in every Wine job too. Locally, each Proton build passes **92 checks** (both
widths): attach and ABI identification, typed writes, scans, pointer scan,
Auto Assembler injection with exact undo, three main-thread hardware
find-what-writes cycles, and allocation/protection during a busy Windows loop
with exact register preservation. Local Wine 11 (new WoW64) passes the same
driver. Matrix: Proton C1 to C6 and C8 at `B`; scans and pointer scans at `B`
for all three Wine rows. Coverage is now 79/268 (29.5%).

Remaining for Proton: the Steam Runtime container (plan item 1.2), the
`steam.exe` launch path with a running client, native calls, the full
debugger (item 1.3) and frontend checks (Wave 2).

## Coverage matrix and explicit refusals: 12 October 2026

Items 0.2 and 0.3 of the [coverage plan](COVERAGE_PLAN.md).

**Matrix.** `docs/compatibility-matrix.json` now holds one state per target
and capability (27 targets by 10 capabilities) with an evidence pointer or
reason for every cell. It was seeded by reading the existing gates, not by
new runs: a cell is `B` only when a live test on a real target of that kind
exists, `V` when it also has a failure/restore case and GUI, CLI and Lua
coverage. `tools/coverage_matrix.py --write` renders the table in
COMPATIBILITY.md; `--check` runs in `tools/ci-check.sh --config` and the
hosted build job. The honest baseline is **coverage 66/268 (25%) and depth
7/268 (3%)**. Visible gaps: no live pointer scan on any target, no scans on
i386/x32/ARM/Wine, no Proton, sandbox, JVM/CoreCLR/Go/V8 or RISC-V coverage.

**Refusals.** A new cecore helper, `targetOperationError`, turns a capability
refusal into the user-visible reason. Previously Lua `allocateMemory`,
`createSimpleHook` and `fullAccess` returned a bare nil or nothing,
`breakAndTrace` returned an empty table, `findWhatWrites` and the CLI `watch`
blamed missing privileges, and the GUI debugger said "need ptrace
permission?" even when the real cause was, for example, another debugger
already tracing the target. Now all of these name the actual reason; Lua
returns `nil, reason` (CE-compatible, extra results are ignored by CE
scripts). The new `blocked_target_gate.py` (CLI and Lua) and a new
`gui_debugger_smoke` case hold a real target under a separate tracer (its
parent, so Yama scope 1 permits it) and require the "traced by another
debugger" reason on every frontend while plain reads keep working.

## Unreaped service recovery: 12 October 2026

This closes the first remaining item of the unreaped-task entry below and is
item 0.1 of the [coverage plan](COVERAGE_PLAN.md). The new
`--unreaped-service-only` mode of `target_syscall_integration` runs the real
`TargetSyscallService` broker in a separate controller process. A completed
mmap fails original-register restoration, so the broker retains the real
unreturned allocation. The service owner thread is then paused right after a
genuine empty `WNOHANG` poll (the fault hook does not alter its result) while
the controller's main thread consumes the owner's actual SIGKILL terminal
report. The fixture's original parent keeps the zombie unreaped and verifies
its unchanged birth and released tracer.

Two phases run per ABI: explicit `recover()` and service destruction. Both
must finish within their bounds, drain the retained allocation and context,
leave no pending record, and complete **before** the parent reaps the zombie.
The existing product code already handles this window (the recovery change
from `62a3067`); no product change was needed. The required native gate passes
**24 assertions per ABI** for x86-64 and i386 in the normal build, alongside
every existing native gate count.

Per the coverage plan, further recovery corner cases (live `PTRACE_EVENT_EXIT`
stops, surviving old-mm peers, nonleader group death) move to its Wave 7
unless a normal workflow reproduces one.

## Hosted verification before the unreaped-task follow-up: 7 October 2026

The [completed run for `d4172a2`](https://github.com/wleeaf/cheat-engine-linux/actions/runs/37632710873)
passed **all seven required jobs**: normal native build/runtime/GUI/CLI checks,
ASan/UBSan, x32, legacy Wine32/Wine64, WoW64, ARM64 kernels and ARM64 frontends.
This published checkpoint includes the applied-detach recovery fix, required
36-check children for each native ABI and the watchpoint race timing correction.
The [final hosted evidence](compatibility-evidence/final-hosted-ci.json) records
its exact revision, current product/test hashes, all job links/steps and actual
kernel observations. Both hosted native and sanitizer logs contain six genuine
hardware races and six applied detach events; every detach phase drains with
zero obsolete context-write attempts.

The earlier [run for `64a62bc`](https://github.com/wleeaf/cheat-engine-linux/actions/runs/37623927661)
and [documentation run for `50c2bc6`](https://github.com/wleeaf/cheat-engine-linux/actions/runs/37625438177)
also passed all seven jobs; their original
[publication evidence](compatibility-evidence/publication-hosted-ci.json) is retained.
The intervening
[run for `2a843aa`](https://github.com/wleeaf/cheat-engine-linux/actions/runs/37629935823)
passed six jobs but exposed the native watchpoint-race setup issue described
below. Older red runs remain historical evidence. This closes the reported
red-check investigation for the current product/test checkpoint. The final
documentation closeout preserves those exact source hashes. Subsequent code
changes must pass the required gates for their own revision. No new release is
created. All six
broader compatibility requirements remain active, with the specific remaining
work listed in this checkpoint and the six-area backlog below.

## Unreaped task recovery: 7 October 2026

Two additional recovery failures were reproduced on both native x86-64 and
i386. After a real completed mmap failed original-register restoration, a
separate tracer consumed the target's terminal notification. The real parent's
child remained a zombie with its original PID and birth. Recovery kept returning
`EAGAIN` because executable metadata had disappeared although `/proc/PID/stat`
still existed. Completed-function recovery instead returned `ECHILD` before
checking the task's lifetime, and stayed stuck even after the parent reaped it.
Both before-fix runs failed five of the same 25 assertions, including normal
controller cleanup for the completed-function case.

Recovery now checks the original task's actual state as well as its birth.
Confirmed `Z`, `X` or `x` states retire the dead context through the existing
original-mm cleanup path. A function poll's `ECHILD` permits that lifetime check;
it does not establish death on its own. Live tasks still retain errors and
ownership. The existing nonleader EXEC adoption path remains available when
the original group can still supply its notification. Completed recovery stays
idempotent, and the initial retirement reports `no_such_process`.

The new mandatory gate runs separate bounded children for x86-64 and i386,
requiring exactly 25 successful assertions and both memory/function phase
observations. A separate controller process owns the real ptrace stop. The
fixture's original parent sends SIGKILL, independently observes the authentic
terminal event with `WNOWAIT`, verifies zombie state, unchanged birth and zero
tracer, and checks recovery **before** reaping. The pinned original mm must
already be retired. The completed function must have returned its actual
`87654321` result before the controlled restoration failure. These tests do not
fabricate wait statuses, register values, task identity or death.

[Unreaped recovery evidence](compatibility-evidence/unreaped-recovery.json)
records the before/after observations, exact source and binary hashes, and
the completed verification for this checkpoint. Existing historical evidence
keeps the hashes from its own tested revision. All builds and suites use cached
resources serially at reduced priority.

The complete normal and ASan/UBSan native gates pass all existing **940 x86-64
and 667 i386 main assertions**, **38 service thread-death and 36 applied-detach
assertions per ABI**, and the **400 lifecycle, 288 shared-exec, 369 shared-death
and 57 completed-ticket assertions**. Each configuration additionally passes
the new **25 unreaped recovery assertions per ABI**. These counts are separate
suites, not a claim about unique feature combinations. The containing revision
also requires its own [hosted build workflow](https://github.com/wleeaf/cheat-engine-linux/actions/workflows/build.yml);
the earlier seven-job green evidence above belongs to its recorded revision.

Both normal and sanitizer library/pthread call gates also pass **45 injection,
83 retained-image and 475 callee-EXEC assertions per ABI**, exercising the
existing nonleader identity adoption and released-cleanup paths after the
common recovery change. Both memory-image gates pass **42 assertions**. A
fresh cached ARM64 cross-build and the real full-system 4 KiB kernel gate pass
**906 assertions with no excluded cases**, using two guest CPUs and 128 MiB.
That ARM64 run is a regression check of existing behavior, not a claim that
the new x86 zombie fixture has been ported to ARM64.

**Remaining:** separately prove the service broker's explicit recovery and
shutdown when another thread consumes its terminal event while the parent keeps
a zombie. Also cover live `PTRACE_EVENT_EXIT` stops and other exiting-task
windows; `PF_EXITING` alone is deliberately not treated as terminal death by
this change. A dead nonleader whose separate old-mm peer survives still needs
safe peer discovery and ownership. Nonleader whole-group death with an unreaped
leader also needs its own proof without breaking EXEC notification adoption.
Longer concurrency/scheduler stress and
the six-area backlog below remain open. This narrow fix does not establish
universal Linux process compatibility.

## Hosted watchpoint race setup: 7 October 2026

The native job for `2a843aa` completed its build but failed two assertions in
the existing CodeFinder teardown fixture, before reaching the new applied-detach
children. Its first two real hardware races occurred after 51,753 and 27,289
attempts. The SIGSTOP variant exhausted the unchanged five-second race-setup
budget without producing the required interrupt stop with a queued hardware
trap. Because the fixture sends its application signal only after observing
that race, it did not send SIGSTOP; the subsequent stopped-application assertion
failed too. The later screenshot upload had no screenshots because the failed
regression step prevented the frontend smoke steps from running.

The x86 controller hook now sweeps short CPU pause delays between actual CONT
and INTERRUPT requests as well as retaining immediate interrupts and scheduler
yields. This varies the overlap with the target's real watched store across
scheduler and virtual-CPU latency. It does not replace any wait result or
siginfo, inject a fabricated hardware signal, skip a case, or extend a deadline.
The queued kernel hardware trap, original hardware bank/affinity restoration,
genuine application SIGUSR1/SIGSTOP and original console work remain mandatory.
The ARM timing branch and production debugger implementation are unchanged.

With both controller and target restricted to two available CPUs, twelve local
before-change x86-64 profiles all passed but needed a median 24,113 and maximum
810,428 attempts across their 36 actual kernel races. This local sample does
not reproduce the hosted negative result. After the sweep, twelve x86-64 and
twelve i386 profiles pass all 22 assertions per profile and produce all 72 real
races, with a median 2,464.5 and maximum 21,711 attempts. The same 24 profiles
also pass under ASan/UBSan. These timing samples demonstrate improved overlap
coverage; they do not establish every kernel or scheduler configuration.

Both complete native gates pass again after this change: 940 x86-64 and 667
i386 main assertions, 38 thread-death and 36 applied-detach checks per ABI,
plus 400 lifecycle, 288 shared-exec, 369 shared-death and 57 completed-ticket
checks in each normal and sanitizer configuration. Builds and suites remain
serial, cached and at reduced priority.

[Watchpoint setup evidence](compatibility-evidence/watchpoint-timing.json)
records the hosted failure, repeated local observations, source/binary hashes
and complete follow-up gate results. All earlier native gate assertion counts
and deadlines remain required, including the 36 applied-detach checks per ABI.
The earlier applied-detach evidence retains the exact hashes from its own
checkpoint rather than being rewritten to describe this follow-up.

Remaining: broader scheduler/CPU/hypervisor stress, additional instruction-level
teardown windows and the full six-area backlog. This corrects test race setup;
the hosted failure does not demonstrate lost application SIGSTOP in production.

## Applied detach and live-task ESRCH recovery: 7 October 2026

An actual detach can release a restored task even when its caller reports an
error afterward. The retained recovery previously attempted to replay its saved context
against that now-running, untraced task. The kernel correctly rejected those
writes, but recovery could not drain and service destruction waited for the
application to exit.

The new recovery path records that restoration was independently verified and
that detach was attempted. After checking the original task birth, it uses an
actual kernel siginfo request and `/proc` tracer ownership to distinguish
release from a running, still-traced task. ESRCH alone cannot complete recovery.
Unavailable ownership metadata and a nonzero tracer retain a retryable owner.
Confirmed release finishes without writing old registers, instructions or
signal state. Confirmed image retirement remains cancellation and cannot replay
old context into its replacement, including after a failed detach.

The new x86-64 and i386 checks cover three distinct handoffs:

- Release before the service records an error: the completed mmap is returned
  and remains caller-owned until the caller independently frees it.
- Release after the service retains its recovery record: explicit recovery
  reclaims the unreturned allocation while its original mm remains alive.
- Release during service destruction: the owner drains and joins within two
  seconds, reclaims the unreturned map and leaves the same application running.

The fault hook first verifies all saved GP, extended-register and signal-mask
bytes, executes the real DETACH, then reports EIO. A subsequent real GETREGS
returns ESRCH while the task is alive. No registers, wait events, process status
or target identity are fabricated. Independent checks require tracer zero,
the original pinned mm, CPU heartbeat progress, exact allocation ownership,
unchanged console work, normal exit and actual reaping. A failed detach before
kernel application must still retain the real ptrace stop.

Both definitive before-fix runs fail eight assertions, with ten, four and
38 post-release write attempts across the three phases. Shutdown needs bounded
fixture termination; its final liveness failure follows that failure cleanup.
After the fix both focused profiles pass all 36 assertions with zero replay
attempts. The native gate requires these cases as separate bounded children;
all earlier counts and deadlines remain mandatory.

The first sanitizer pass exposed an old fixture binary: its command table
predated the already-published lowercase `o` correction, while the rebuilt
driver used the current command. Rebuilding both tiny native fixtures resolves
that input mismatch. The driver target now depends on both fixture targets, so
building only that integration target also refreshes its required test inputs.
This intermediate failure is retained separately from product before/after
evidence and from the fresh full sanitizer gate.

Both complete normal and ASan/UBSan native gates pass: 940 x86-64 and 667
i386 main checks, 38 thread-death and 36 applied-detach assertions per ABI,
plus 400 lifecycle, 288 shared-exec, 369 shared-death and 57 completed-ticket
assertions in each configuration. These are repeated configurations and
scenarios, not a count of unique supported programs. The shared production core
also rebuilds successfully with the fix.

Related normal and sanitizer checks pass all 42 shared-mm affinity assertions
and, for each native ABI, 45 library/thread injection, 83 retained-image and
475 callee-exec assertions. A fresh ARM64 cross-build and real 4 KiB kernel
guest pass the existing 906-assertion regression with two CPUs and 128 MiB RAM.
Its first compile attempt exhausted the temporary-directory quota; retrying
with scratch files on the cached build's disk succeeds. This is ARM regression
evidence, not an ARM reproduction of the new x86-only detach fault scenario.

[Applied-detach evidence](compatibility-evidence/applied-detach-recovery.json)
records source/binary hashes, actual before/after observations and full
regression results. Checks and builds use cached dependencies, one compiler job,
reduced priority and serial execution. No host packages or kernels are changed.

Remaining in this part: prove additional still-owned running/ESRCH transitions,
exit before ownership confirmation (including unreaped tasks), concurrent
re-attachment, namespace visibility and transient ownership-metadata failures.
This adds live native x86 memory-service evidence; it does not establish the
same applied-detach scenarios for ARM, x32, Wine, remote transports, native-call
owners or independent GUI/CLI/Lua workflows. The six-area backlog remains open.

## Publication checkpoint: 7 October 2026

This checkpoint publishes the accumulated mixed-ABI and ownership fixes below.
The entries labeled local or unpublished describe their historical test states;
publication does not expand their verified scope. No new release is cut here.

Completed in this part:

- Preserve an ELF64 task's actual i386 INT80 restart ABI and original timer
  deadline across injected native memory syscalls, including exact signal-mask,
  GP, extended-state and instruction restoration.
- Handle the tested asynchronous delivery and SIGSTOP/LISTEN/SIGCONT cases,
  including retries after failures before and after kernel application.
- Retire old task context after confirmed death or exec, distinguish dead tasks
  from a still-live shared mm, and retain retryable restoration of owned private
  code/probe bytes while another process keeps that mm alive.
- Check actual private-map alias identity before restoring saved context or
  using completed tickets, including same-file exec with identical addresses and
  bytes. Provide a stopped-peer cleanup overload without reopening a dead TID.
- Retain unreturned mmap ownership before transient retry and reclaim it through
  a surviving thread after the selected member exits. Explicit recovery and
  service shutdown now pass the same ownership and survivor-context checks.
- Require bounded native gate children with exact assertion counts, genuine
  kernel events, independent readback, allocation cleanup and process reaping.

The pre-publication product/test sources match the recorded source hashes in
[service handoff evidence](compatibility-evidence/service-thread-death.json).
Both normal and ASan/UBSan native gates pass 940 x86-64 and 667 i386 checks,
38 service-handoff assertions per ABI, plus 400 lifecycle, 288 shared-exec,
369 shared-death and 57 completed-ticket assertions in each build. The production
shared core rebuilds successfully. The changed freestanding fixture cross-links
for AArch64; this is compile evidence only. Builds and suites remain serial,
cached and at reduced priority with one compiler job.

The final shared-mm affinity gate also passes all 42 assertions. Native-call
regressions pass 45 injection/lifetime, 83 retained-image and 475 callee-exec
checks for each of x86-64 and i386. The local CMake configuration lacks dynamic
i386 fixtures, so that profile explicitly uses cached fixtures and private
cached runtimes; no host package installation was needed.
[Publication evidence](compatibility-evidence/publication-closeout.json) records
these final checks, binary/report hashes and their scope limits.

Remaining in this part:

- Distinguish ambiguous ptrace ESRCH for a running, still-owned task from actual
  death; prove recovery and shutdown retain ownership in those transitions.
- Discover and acquire a separate old-mm process automatically for allocation
  cleanup. The explicit stopped-peer primitive is tested; discovery is pending.
- Prove concurrent/nonleader exec and additional death windows, incomplete proof
  cleanup, cancellation and bounded execution/restoration waits.
- Support read-only proof transports and additional synchronous signal,
  seccomp/syscall-user-dispatch and permanent-policy failure combinations.
- Extend mixed entry ABI/restart classes, x32, other kernels and architectures,
  and independent GUI/CLI/Lua ownership workflows. Mixed-ABI recovery currently
  requires caller-owned private scratch and a writable pinned old mm; unsupported
  borrowed/quiesced mixed sites reject before context mutation.
- Keep all seven hosted jobs required for subsequent code changes. The current
  published code revision is green, as recorded in the latest verification above;
  future revisions require their own results.

The detailed six-area backlog below remains active. These fixes establish the
tested cases and do not establish compatibility with every Linux process.

### Publication CI follow-up: fixture command collision

The [run for `7e36970`](https://github.com/wleeaf/cheat-engine-linux/actions/runs/37619340206)
exposed a runtime fixture regression that the earlier AArch64 cross-link could
not detect. The new selected-thread-death protocol reused uppercase `O`, already
used by ARM64 to configure its autodisarmed alternate signal stack. Both handlers
ran: stack configuration succeeded, then the new owner-recovery handler exited
the leader and redirected later policy/vector commands to its console sibling.
The ARM64 kernel gate reported 20 failed assertions. The hosted sanitizer, x32
and both Wine profiles passed; the other jobs were still running when this
follow-up was prepared.

The owner-recovery protocol now uses the previously unused lowercase `o`.
The existing ARM64 uppercase `O`, policy setup, vector state, alternate-stack
and real-exec assertions are preserved. Both native service children pass all
38 assertions after the rename. A cached serial ARM rebuild and full real-kernel
gate pass all **906 assertions**, including the failing SVE/SME policy and
alternate-stack cases, with 128 MiB RAM and the existing two-CPU concurrency
matrix. No builds or suites overlapped. Product sources are unchanged by this
fixture correction. [Command-isolation evidence](compatibility-evidence/fixture-command-isolation.json)
records the hosted failure, current source hashes and actual kernel follow-up.
The corrected pushed revision still requires its own seven-job hosted result.

### Hosted mixed-ABI context follow-up

The [run for `c95356a`](https://github.com/wleeaf/cheat-engine-linux/actions/runs/37620541399)
passed all six other jobs, including the corrected ARM64 kernel job and the
complete sanitizer profile. Its normal native job failed the combined extended
state/instruction/scratch/mask assertion in variants 9, 14 and 17. Those variants
passed exact GP restoration, actual syscall ABI, original timer completion and
allocation/process cleanup. The old assertion did not identify the differing
field, so this is not yet an established production-restoration defect or a
diagnosed fixture-only failure.

The fixture now captures the complete actual extended bank at the owned timer
stop immediately before injection, matching the executor's restoration contract.
Its old snapshot preceded actual timer execution. The test retains a comparison
with that earlier bank and reports per-regset byte differences, GP fields,
scratch/instruction checks and exact signal masks before and after injection.
All preservation assertions, counts and deadlines remain required. Production
code is unchanged by this follow-up. A stale setup snapshot is a possible
contributor; the hosted diagnostics must determine whether it explains any
recurrent failure.

Focused native runs pass all 298 x86-64 and 24 i386 assertions with the owned-stop
baseline. A diagnostic run before that baseline correction also passes all 298
cases under the cached real Linux 6.1.0-50 x86 kernel with one CPU and 128 MiB;
neither that guest nor the host reproduced a before/after mismatch. Builds and
suites ran serially with cached tools and reduced priority. No host packages or
kernel settings changed. [Context evidence](compatibility-evidence/mixed-abi-context-diagnostics.json)
records the failure, local controls and the unresolved proof limits. Another
hosted run is required to verify the corrected fixture and diagnose any remaining
failure before declaring CI closeout.

### Hosted baseline diagnosis and CEServer terminal replies

The [run for `b0245f7`](https://github.com/wleeaf/cheat-engine-linux/actions/runs/37622481616)
passed the complete normal job and five other jobs. Its actual native diagnostics
establish the stale-baseline problem: regset `0x202`, byte 512, changed from `2`
to `0` **before injection** in multiple timer variants. GP, code and scratch were
unchanged at that point. The complete bank at the operation's owned stop was
then restored exactly. All 298 x86-64 mixed-restart assertions and the complete
native recovery/lifecycle gates passed. This confirms a fixture snapshot error;
the preservation check still compares every byte of the actual saved bank.

The sanitizer job instead failed earlier in the CEServer multi-client suite,
at its combined shutdown assertion. That assertion required an error from a
debug-event waiter. The API returns `expected<optional<event>, error>` and also
supports a successful empty reply. A shutdown/no-event reply can therefore end
the wait without an error. The corrected assertion permits error or empty,
rejects a returned event, and retains the **800 ms** deadline, stopped listener,
zero port, released real ptrace ownership and live-target requirements. It logs
the actual elapsed time and reply category, so any recurrent latency or event
failure is directly diagnosable. Production server behavior is unchanged.

Eight baseline normal runs and eight baseline ASan/UBSan runs passed locally,
all with error replies. They did not reproduce the hosted failure, so the old
combined result alone does not establish which shutdown component failed there.
The reply correction follows the existing protocol contract; hosted confirmation
of the complete suite is still required. Serial cached builds and repeated live
32/64-bit multi-client checks are recorded in the
[follow-up evidence](compatibility-evidence/hosted-context-and-shutdown.json), alongside
the authoritative before-injection regset diagnostics and their scope limits.
Eight corrected normal runs and eight corrected ASan/UBSan runs also pass all
31 assertions each, with actual shutdown durations between 1 and 3 ms. The new
pushed revision subsequently passes all seven jobs, including the complete
sanitizer profile, as recorded in the latest verification above. The old CEServer
combined failure's exact reply/timing component remains unrecorded; the current
protocol assertion and diagnostic gates remain enabled.

## Earlier hosted CI closeout: 7 October 2026

The [full workflow for `6834260`](https://github.com/wleeaf/cheat-engine-linux/actions/runs/37596245380)
completed successfully with **all seven required jobs passing**:

| Job | Hosted result |
|---|---|
| Ubuntu native build, runtime, GUI, CLI and transport checks | Passed |
| ASan/UBSan native and runtime checks | Passed |
| x32 native calls, debugger, image-affinity and exec checks | Passed |
| Legacy Wine32 and Wine64 compatibility | Passed |
| Wine WoW64 compatibility | Passed |
| ARM64 kernel compatibility, including 4 KiB and 64 KiB profiles | Passed |
| ARM64 application, GUI, CLI and runtime frontends | Passed |

The [completed-run record](compatibility-evidence/hosted-ci-green.json) preserves
the tested revision, branch, job links, steps and authoritative conclusions.
This resolves the red-check investigation described in the historical entries
below. Required tests and their failure gates remain enabled. The published
fixes cover real Qt buffered-save data loss, repeat Mono installation staging,
Wine fixture privileges, replacement-image setup, portable program traps and
register/race/worker-startup assumptions in the integration fixtures.

The broader six-area objective below remains unfinished. In particular, the
mixed-ABI restart adapter was an unpublished draft at that checkpoint; its
subsequent publication, additional proofs and remaining limits are recorded above. Other remaining
targets and feature combinations retain their documented limits. Passing this
workflow establishes the required tested profiles, not compatibility with every
Linux process, and does not create a new release.

## Local mixed-ABI recovery follow-up: 7 October 2026

The unpublished adapter now temporarily defers blockable asynchronous signals
while restoring the original kernel syscall ABI. It records the application's
signal mask before changing it, verifies the actual kernel mask, and restores
the exact original mask during owned recovery. The temporary mask leaves
SIGKILL, SIGSTOP and synchronous fault signals available; blocking a forced
fault can change its disposition in Linux's
[signal handling](https://raw.githubusercontent.com/torvalds/linux/v6.18/kernel/signal.c).
This is a deliberate limitation of
the mask, not evidence that those stops have been handled by the adapter.

The tests run an actual two-second nanosleep through INT80 in a 64-bit process,
including a zero-extended stopped EAX edit. They cover 13 controlled recovery
failures: the eight earlier ABI-entry/interrupt/resume/verification failures,
plus mask capture, writes before and after kernel application, readback, and
restoration after kernel application. Every case begins with SIGUSR1 already
blocked and requires exact restoration of the full GP bank, extended state,
instructions, scratch bytes and signal mask. Recovery retries remain owned and
idempotent, and actual execution must finish the original timer deadline.

An additional case queues a real SIGWINCH immediately before the emulated
entry. Independent kernel inspection verifies its original sender, UID and
queued value while deferred, then verifies the same data at its actual delivery
stop. Forwarding the real signal must preserve timer completion. The caller
handles that pending signal before performing another injected operation.
The native gate now requires all 219 x86-64 and 24 i386 mixed-restart assertions,
including their success markers, rather than accepting a run with this suite
absent.

Both complete native gates pass with **861 x86-64 and 667 i386 checks** in each
of the normal and ASan/UBSan builds. Leak detection and abort-on-error settings
were enabled for the sanitizer run. Builds reused cached objects, ran serially
with reduced priority, and did not overlap the test suites.
[Recovery evidence](compatibility-evidence/mixed-abi-async-recovery.json)
records the tested source and binary hashes, actual mixed-restart observations,
complete gate outcomes, sanitizer settings and proof limits.

**Remaining at this checkpoint:** handle actual SIGSTOP/group-stop/SIGCONT
transitions, foreign synchronous delivery stops and syscall-user-dispatch
policy; prove cancellation and target exit/exec during each recovery phase;
exercise x32, other restart classes and additional kernels. Unexpected stops
still retain ownership and can leave retry awaiting an unresolved stop. These
changes are a local draft and have not been committed or tested by hosted CI.
The published seven-job green result above applies to its recorded revision.
The six-area backlog below remains open.

## Local group-stop recovery follow-up: 7 October 2026

The next unpublished draft handles a real SIGSTOP arriving before the emulated
mixed-ABI entry. It restores and verifies the original instructions, GP and
extended state and application mask before forwarding the actual signal. An
owned interrupt guards that transition even if SIGCONT has already canceled
the stop. A genuine kernel group stop enters LISTEN; bounded recovery waits
without allowing application instructions, and continues restoration only
after the actual SIGCONT notification. It never substitutes a new SIGSTOP for
the original delivery. Event reporting reflects observed kernel events.

Four actual process scenarios cover the group stop, SIGCONT canceling a held
delivery, and LISTEN errors both before and after kernel application. Independent
kernel reads at LISTEN verify the original GP bank and nonempty signal mask;
procfs confirms the process stays stopped. Each case retains its completed mmap
and ptrace owner, verifies the real SIGCONT delivery data, finishes the original
two-second timer, reclaims its mappings and resumes the original console work.

Those scenarios exposed a race between an empty wait poll and stop inspection:
SIGCONT can already have created a new interrupt stop by the time GETSIGINFO
runs. Recovery now collects that real wait notification instead of rejecting
it or replaying LISTEN. A deterministic test sends the actual SIGCONT after an
actual empty poll, waits for the kernel's new stop to become inspectable, and
leaves its wait notification available for the production owner. Neither wait
statuses nor signal data are fabricated.

The resume phase also records progress before CONT and checks the actual
emulated-entry stop before retrying a request that may already have applied.
A new before-application CONT failure joins the earlier after-application
failure and other 14 controlled ABI/mask recovery failures. The native gate
requires all **298 x86-64 and 24 i386** mixed-restart assertions. Complete normal
and ASan/UBSan gates pass **940 x86-64 and 667 i386 checks each**, retaining the
existing individual timer and overall gate deadlines.

The shared context-restoration helper retains the published restoration
sequence, with member qualification and one local variable renamed. Its current
ARM64 product unit and test driver/wrapper compile against cached remaining
objects. One real 4 KiB ARM64 kernel guest passes **162 native-call checks**
across normal, SVE, maximum SVE, SME and maximum SME profiles, including original
GP/vector/mask/stack restoration. The guest used 128 MiB and two CPUs. Builds,
native suites and the guest ran sequentially at reduced priority.
[Group-stop evidence](compatibility-evidence/mixed-abi-group-stop-recovery.json)
records actual stops and deadlines, source/binary/kernel hashes, complete native
outcomes, the deterministic race and the ARM64 shared-helper regression check.

**Still required:** group stops in other recovery phases and repeated/concurrent
job-control transitions; foreign synchronous signal decisions; syscall policy;
cancellation and exit/exec throughout recovery; x32, other restart classes and
additional kernels; and integration through the full GUI, CLI and Lua ownership
paths. This remains unpublished work and does not complete any broader target
or the six-area objective. Hosted CI still applies to its published revision.

## Local lifecycle recovery follow-up: 7 October 2026

A separate mandatory lifecycle suite now exercises the retained mixed-ABI
recovery record at all 14 controlled ABI/mask failure points. Each row starts
with a real interrupted INT80 nanosleep, a completed native mmap, and a
nonempty application signal mask. A foreign controller thread must be denied
recovery while the original ptrace owner and allocation remain intact.

The death matrix kills the actual target at those 14 failures and three LISTEN
states: ordinary LISTEN and failures before/after its kernel application.
Some exit notifications are consumed by the caller before recovery; others are
observed with WNOWAIT and left for the recovery owner. Both paths must report
actual target death, become idempotent, and retire access to the dead memory
image. The WNOWAIT cases independently verify that recovery consumed the
kernel notification.

The replacement matrix deliberately redirects the retained caller-owned task
to its published native exec site, executes the same file, and consumes the
real EXEC event before retrying recovery. It requires unchanged PID, start time
and executable inode, actual replacement of the private mappings, retirement
of the pinned old mm, exact preservation of the replacement's GP/extended bank
and inherited mask, and working replacement console I/O. The fixture first
collects real pending interrupt stops before requiring the actual EXEC event;
it never substitutes an interrupt event for exec.

The gate requires **218 death assertions and 182 replacement assertions**, in
addition to all existing 940 x86-64 and 667 i386 normal checks. The lifecycle
matrix has its own 60-second bound; individual two-second lifecycle transitions,
original timer deadlines and the existing normal-suite bounds stay enforced.
Its results are recorded separately rather than counted as unique additional
program features or folded into the earlier normal-suite totals.

Complete normal and ASan/UBSan gates pass the existing **940 x86-64 and 667 i386
checks**, plus the separate **400 lifecycle assertions** in each build. The
previous adapter's retirement paths passed these cases without further product
changes. Cached builds and suites ran serially at reduced priority; no additional
kernel guest or host configuration change was needed.
[Lifecycle evidence](compatibility-evidence/mixed-abi-lifecycle-recovery.json)
records source/binary hashes, all actual lifecycle observations and gate
outcomes, sanitizer settings and the exact proof limits. The single-task old-mm
probe is consistent with Linux's
[/proc memory implementation](https://raw.githubusercontent.com/torvalds/linux/v6.18/fs/proc/base.c);
it does not prove retirement while another process keeps that mm alive.

**Proof limits and remaining work:** these checks cover controlled retained
states and an externally redirected single-task exec. They do not establish
asynchronous death/exec in every instruction-sized race window, nonleader TID
replacement, an old mm kept alive by a separate CLONE_VM process, caller-requested
cancellation or full frontend/broker shutdown. Foreign synchronous signals,
syscall policy, additional restart classes/kernels and the broader six-area
backlog remain open. The adapter and its new mandatory gate remain unpublished.

## Local shared-mm exec recovery follow-up: 7 October 2026

The separate CLONE_VM fixture reproduced an additional unsafe recovery path.
The caller consumed a real same-file EXEC event while a separate process kept
the original mm alive. PID, start time and executable inode remained unchanged,
and the pinned old memory descriptor stayed readable. All 14 retained ABI/mask
failure rows failed to retire. Four rows replayed an old program counter into
the replacement; two also changed its inherited signal mask. The test restored
only its independently captured replacement context for cleanup, then required
actual replacement console work and reaping of both fixture processes.

The private-scratch adapter now proves that the selected, actually stopped task
still shares its saved mm before changing/restoring context and after collecting
new recovery stops. It reuses the private-mapping alias check with a one-byte
probe, so a syscall ending at a page boundary needs no additional scratch
space. The probe changes only the owned unpublished old scratch mapping. An
actual different mm retires recovery without replaying old GP, extended state,
mask, code or mapping cleanup into the replacement. Failed restoration retains
the original probe byte across retries, including subsequent exec; an ambiguous
write is verified against the pinned old image rather than assumed to have failed.

The sanitizer closeout exposed another product bug. Entering-phase recovery
could see a real SIGSTOP with the same GP bank as the prepared emulated entry
and mistakenly replay SYSEMU. That suppressed the actual signal and replaced
its notification with an emulated syscall stop. Normal successful requests now
wait for their real event directly. Ambiguous failed requests are replayed only
if both the full GP bank and the actual original prepared-stop signal data
match. Merely matching registers does not prove a request was never applied.

The group-stop fixture now guarantees its requested pre-entry SIGSTOP using a
real owned interrupt. It consumes only that test-created interrupt after
independently verifying every entry register, then leaves the actual queued
SIGSTOP notification for production recovery. No statuses, GP banks or signal
sender data are fabricated. The old adapter reliably lost that verified stop;
the fixed adapter must preserve it. The gate requires four verified pre-entry
stops in the normal x86-64 suite and three in the death matrix, retaining all
earlier assertions and deadlines. This proves the pre-entry cases; SIGSTOP in
other phases still needs separate coverage.

The mandatory shared-mm suite covers all 14 retained failure rows, alternates
real probe-restoration failures before/after kernel application, and verifies
old-byte cleanup after exec. Two further rows run an identical same-file image,
recreate identical private scratch bytes at the same virtual address, and use a
syscall at the page end. This requires actual alias identity rather than PID,
inode, address or byte equality. Every replacement must preserve its entire
GP/extended bank and mask, leave replacement scratch untouched, finish console
work, reap its CLONE_VM peer and exit normally. The suite requires exactly
**252 shared-exec and 36 identical shared-exec assertions** in its own bounded
60-second gate child. Its fixture is now a dependency of the native test driver.
The earlier 400 lifecycle assertions and normal-suite requirements remain intact.

Complete normal and ASan/UBSan gates pass **940 x86-64 and 667 i386 checks**,
plus the separate **400 lifecycle and 288 shared-mm assertions** per build.
Each gate enforces the deterministic real pre-entry stops as well as all older
success markers, exact counts and deadlines. The standalone pinned-image suite
passes **42 existing checks** in both builds, covering its refactored 16-byte
alias helper. Leak detection and halt-on-error settings were enabled in the
sanitizer runs. Builds reused cached dependencies, used one compiler job at
reduced priority, and did not overlap builds or suites. No additional kernel
guest or host configuration change was needed for this follow-up.

[Shared-mm evidence](compatibility-evidence/mixed-abi-shared-mm-recovery.json)
records the baseline failures, current source and binary hashes, gate outcomes
and proof limits. This section supplements the earlier lifecycle checkpoint;
that snapshot deliberately retains its narrower single-task evidence.

**Remaining and current boundary:** the mixed-ABI restart adapter requires a
caller-owned private scratch site and a writable pinned old mm. Borrowed and
quiesced sites need a private identity-proof owner and therefore reject this
mixed restart before context mutation; read-only proc-memory support also
needs a safe old-mm proof transport. Completed recovery records reused as
expected-image guards also need their own live task/image-affinity proof. The
fixture reclaims old-mm allocations by exiting its peer; independent cleanup
while a separate old-mm peer remains alive still needs an ownership path.
Unexpected synchronous delivery decisions,
syscall policy, cancellation/shutdown, nonleader exec, other recovery race
windows and restart classes, x32, further kernels, and full GUI/CLI/Lua routing
remain open. This draft is unpublished. The broader six-area objective remains
active; the hosted green revision is still the separately recorded checkpoint.

## Local shared-mm task-death recovery follow-up: 7 October 2026

The next fixture killed the actual selected task with SIGKILL while a separate,
untraced CLONE_VM process retained its old mm. It covered all 14 retained
ABI/mask failures and three real SIGSTOP/LISTEN states, alternating terminal
events consumed by recovery with events already reaped by the caller. The
baseline marked recovery complete, but its image guard still accepted the dead
task because the pinned old memory descriptor remained readable. Failed probe
restoration also abandoned an owned marker. An expanded, independently captured
32-byte scratch comparison then exposed abandoned injected code in 13 ordinary
rows and both probe rows. The two failing baselines are retained separately;
they are not evidence of a successful fix.

Recovery now records confirmed task death independently of mm retirement.
`checkImage()` rejects that dead context immediately, including while cleanup
is blocked. Owner-only retries restore the saved marker and owned private code
bytes through the pinned old descriptor, without reopening the dead numeric TID
or attaching to the surviving peer. Readback verifies ambiguous writes already
applied by the kernel; failed restoration retains the snapshots for another
retry. Byte masks preserve unowned neighbors. Only after cleanup verifies does
recovery complete with `no_such_process`; subsequent retries remain idempotent.
The mm is still alive, so `imageRetired()` remains false. This preserves the
native-call owner's existing ability to select a surviving sibling and reclaim
its frame instead of treating task death as an exec replacement.

The new mandatory gate child has its own 60-second deadline and requires exactly
**322 shared-death and 47 shared-death-probe assertions**, plus three actual
queued pre-entry SIGSTOP notifications. Probe cases exercise failure before and
after kernel application, another failure during final code rollback, foreign
owner rejection, verified retry and complete original scratch restoration.
Every row proves that the independent old mm stays readable and the peer stays
untraced until explicit cleanup, then requires the real peer's death/reaping and
old-mm retirement. A temporary process-local subreaper setting is restored.
The keepalive fixture watches a pidfd for its controller, so the peer can survive
the target while still terminating if the test controller dies.

Complete normal and ASan/UBSan gates pass **940 x86-64 and 667 i386 checks**,
plus **400 lifecycle, 288 shared-exec and 369 shared-death assertions** per
build. The existing counts, success markers and deadlines remain mandatory.
Standalone native-call regressions pass in both builds, including real main
`pthread_exit`, surviving siblings, constructor execution and worker-exit
ownership. A separate bounded fixture check actually kills its controller:
the busy target dies from its parent-death SIGKILL, the CLONE_VM peer exits
normally after pidfd notification, and all three processes are reaped with the
original subreaper setting restored. That controller-death check is recorded
local evidence, not a new hosted requirement. Sanitizer runs enable leak
detection and abort/halt on errors. All builds and suites ran serially with
cached dependencies, one compiler job and reduced priority; no new guest or
host configuration change was needed.

[Task-death evidence](compatibility-evidence/mixed-abi-shared-mm-death-recovery.json)
records both failing baselines, exact source and binary hashes, verification
results and limits. Earlier evidence files retain their historical checkpoints.

**Remaining:** this closes dead-context acceptance and old private marker/code
rollback for the tested retained states. It does not provide an allocator owner
that can independently unmap an old private frame through a separate CLONE_VM
process. Completed tickets whose task is still alive need a fresh image-affinity
guard. Death in other windows, nonleader exec, foreign synchronous delivery,
syscall policy, cancellation/shutdown, other restart classes, borrowed/quiesced
and read-only transports, x32 and other architectures/kernels, and complete
GUI/CLI/Lua routing still need implementation and live proofs. This adapter
remains an unpublished draft; the six-area goal remains active. The published
seven-job checkpoint is green, and has not tested these local changes.

## Local completed-ticket operation guard follow-up: 7 October 2026

Reusing a completed recovery as an operation's expected image exposed another
unsafe authorization path. The guard sampled only its readable pinned old mm.
A CLONE_VM peer retained that mm after same-file exec, so PID, start time,
executable inode and a readable original program counter all still looked
valid. Two real replacement allocations recreated the old address and byte
contents. The old guard actually unmapped both replacements. The baseline
failed four assertions while complete replacement register/mask/code comparisons,
normal console work and process cleanup passed. One row released its original
private scratch before exec, ruling out dependence on that scratch's lifetime.

Expected-ticket operations now duplicate the original memory descriptor with
its original access mode and use the same fresh private-mapping alias proof as
saved-image operations. The proof belongs to the actually stopped destination,
is reclaimed before the requested operation, and retains its existing nested
recovery owner if restoration or release fails. A merely live old mm can no
longer authorize `munmap` in a replacement. Supplying an expected ticket does
not discard a separately supplied saved-image guard; both are checked. This
does not reopen the source numeric TID or require its original scratch to remain
mapped. `checkImage()` itself remains a pinned-mm liveness/known-retirement
query; callers authorize operations through the stronger stopped-image guard.

An overload also makes the expected-ticket guard available when the caller
already owns the stop. The focused fixture verifies ordinary same-mm cleanup,
two same-file replacement rejections, and explicit cleanup through an owned
CLONE_VM peer after the original task's real SIGKILL. The peer's old allocation
is independently absent while its old mm is still live, before the peer exits.
All cases preserve every selected GP/extended register, mask, program byte and
actual ptrace owner. Rejections also preserve the complete replacement map list
and byte contents. Every process is reaped and the original temporary subreaper
setting is restored. A separate 60-second mandatory gate child requires exactly
**57 assertions** with no failed or missing markers.

Complete normal and ASan/UBSan gates pass **940 x86-64 and 667 i386 checks**,
plus **400 lifecycle, 288 shared-exec, 369 shared-death and 57 completed-ticket
guard assertions** per build. The old counts, success markers and deadlines
remain enforced. Sanitizer runs enable leak detection and abort/halt on errors.
Builds reused cached dependencies at reduced priority with one compiler job;
builds and suites did not overlap. No new kernel guest or host configuration
change was needed. These native results do not substitute for fresh x32, ARM,
Wine or complete frontend proof of the new guard transitions.

[Completed-ticket evidence](compatibility-evidence/completed-image-guard.json)
records the unsafe baseline, source and binary checkpoints, verification and
limits. Earlier evidence files remain historical snapshots.

**Remaining:** this supplies an explicit stopped-peer cleanup primitive, not
automatic discovery/ownership of a separate old-mm peer. The service's selected
thread-death fallback still needs a dedicated retained-allocation proof, including
its early liveness query and owner handoff. Standalone liveness queries do not
prove current affinity. These new guard cases run on native ELF64 only; policy,
read-only proof transports, incomplete/probe-cleanup and concurrent exec windows,
other restart classes, x32/other architectures/kernels and full GUI/CLI/Lua paths
still need implementation or stronger evidence. The local adapter remains
unpublished and all six compatibility requirements remain active.

## Local service selected-thread death follow-up: 7 October 2026

The service follow-up reproduced two allocation leaks on both native x86-64
and i386. Its first path discarded an unreturned mapping when recovery's dead
selected context failed `checkImage()`, even though a sibling kept the original
process and mm alive. Its second path lost a completed mmap before recording
ownership: the selected task died during the first transient retry, and the
`no_such_process` branch erased the record before assigning its allocation.
Both explicit recovery and service destruction could finish while leaving that
old mapping behind. Each corrected baseline failed six assertions, with all
real process/console cleanup assertions passing. The baseline had 41 assertions
because it also required independent reclamation of its three leaked mappings;
that failure cleanup does not count as a successful ownership proof.

The service now records its completed mmap and original image before attempting
the transient retry, and retains that ownership after selected-task death.
Member selection and process-identity checks still precede cleanup. The guarded
unmap proves actual affinity through the surviving member; a dead saved context
no longer falsely retires its live mm. This reuses the completed-ticket guard
without reopening the dead TID or replaying its old registers into a sibling.

The freestanding fixture's new owner-recovery mode creates a CPU-loop sibling
and a console sibling on separate stacks, then exits its original leader.
Link-only fault hooks retain a real completed mmap at a failed detach. The
actual service owner verifies the restored program counter/stop, samples the
live kernel allocation, writes the fixture's own exit flag and resumes its
original code. That code executes a real thread-only exit. A bounded WNOWAIT
observation leaves the actual terminal event for production recovery; no GP
bank, terminal status or signal information is fabricated. A separate actual
kernel snapshot verifies every surviving GP/extended register and mask bit
before its real detach, alongside independent map absence, unchanged program
bytes, live console work and final process reaping.

Each ABI now has its own mandatory 60-second child requiring exactly **38
assertions**, three verified real exit notifications and all three outcomes:
after-record recovery, before-record recovery and shutdown. The six cases prove
that allocations disappear while their original mm is still alive, before the
surviving console exits. Historical evidence files retain their checkpoints.
Complete normal and ASan/UBSan gates pass **940 x86-64 and 667 i386 checks**,
plus **38 service-handoff assertions per ABI** and the existing **400 lifecycle,
288 shared-exec, 369 shared-death and 57 completed-ticket assertions** per build.
Each gate still enforces every older count, marker and deadline. Sanitizers
enable leak detection and abort/halt on errors. Serial cached builds use one
compiler job at reduced priority, with no overlapping builds or suites. The
changed freestanding fixture also cross-links as a static AArch64 executable
using the cached container compiler; that compile-only check does not establish
ARM64 runtime coverage. No new guest or host configuration change was needed.
The shared production core also rebuilds successfully from the current sources,
so the existing frontend binaries can load the fixes; their full new handoff
workflows still need independent runtime coverage.

[Service handoff evidence](compatibility-evidence/service-thread-death.json)
records the failing baselines, actual kernel events, current hashes and gate
results.

**Remaining:** this closes the tested service member-death handoff within a
still-live original thread group. Automatic discovery/ownership of a separate
old-mm process remains unfinished. Exit in other phases, ambiguous ESRCH while
a task is running, concurrent/nonleader exec, policy and read-only proof
transports, cancellation, mixed entry ABIs and other restart classes still need
live proofs. The new cases do not establish ARM/x32/Wine or complete GUI/CLI/Lua
coverage. The mixed-ABI adapter remains unpublished and all six compatibility
requirements remain active.

## Hosted CI investigation: 7 October 2026

GitHub completed the [checkpoint workflow](https://github.com/wleeaf/cheat-engine-linux/actions/runs/37518824607)
for `1f5a198` with four failed jobs. Compilation passed. Native and sanitizer
jobs failed the return/restart context and queued-hardware-trap tests. Legacy
Wine64 failed process access (`Permission denied`); PE32 passed. The x32 exec
fixture failed replacement mapping with `EEXIST`. ARM64 kernel, ARM64 frontend
and Wine WoW64 jobs passed. The red check therefore represents actual failing
required tests and is not a release badge or a compilation failure.

This follow-up updates the boundary tests to capture the actual bank immediately
before each operation, with per-field diagnostics while retaining exact GP,
extended-state, code and scratch comparisons. The hardware race fixture now
includes immediate interrupts as well as scheduler yields and sleeps; it still
requires an actual kernel interrupt stop with a queued hardware trap. Callee-exec
notification fixtures start a clean replacement while explicit image-affinity
scenarios retain identical-address frame copying. The isolated legacy Wine CI
step receives explicit ptrace privileges, like the existing WoW64 container;
its report records the effective UID. Host kernel settings are unchanged.

Local verification used a separately compiled driver from the selected CI
source, with baseline product code and cached objects. Both complete native
x86-64/i386 profiles passed. The native exec gate and a real 128 MiB x32 kernel
exec gate each passed all 475 required assertions. Builds were serial at reduced
priority. [Investigation evidence](compatibility-evidence/hosted-ci-investigation.json)
records the hosted failures, local results, source hashes and their limits.

**Still required:** observe the replacement hosted run, use the new diagnostics
to resolve any remaining register or hardware-race failure, and confirm legacy
Wine privileges on Ubuntu. Local passes do not establish a green hosted check.
The separate mixed-ABI restart adapter remains work in progress and is excluded
from this CI commit; additional recovery, policy, signal and exit/exec proofs
are still required before publication.

### First hosted follow-up

The [run for `23c97b6`](https://github.com/wleeaf/cheat-engine-linux/actions/runs/37586986110)
passed both complete native syscall profiles in normal and sanitizer jobs,
including the formerly failing exact context and hardware-race checks. Legacy
Wine and WoW64 passed. The x32 call, image-affinity and 475-case exec suites
passed, as did the ARM64 kernel job.

Later required checks exposed three further failures: a repeat Mono gate found
an already existing installed library symlink; the i386 native injection helper
failed a check using a two-second whole-process budget; and the x32 debugger program-trap
notification case failed without reporting its actual wait status. Mono staging
now resolves the source symlink and removes dangling destinations before making
a hard link. Its broken-link, repeated-run and cross-filesystem copy controls
pass. The shutdown helper budget now includes startup, symbol discovery and a
native call whose own timeout is two seconds, while still enforcing bounded
shutdown and a genuinely running detached target worker. Failures now log the
actual exit status and worker state. The debugger check retains all assertions
and logs requested versus actual wait notifications. It passed four local full
x32 debugger guest runs; its hosted failure remains unrooted until reproduced
or diagnosed.

[Follow-up evidence](compatibility-evidence/hosted-ci-followup.json) preserves
these observed results and limits. Another hosted run must verify the further
fixes; a local pass alone is insufficient.

### Diagnosed x32 trap mismatch

The [next hosted run](https://github.com/wleeaf/cheat-engine-linux/actions/runs/37588282496)
logged a real `SIGILL` stop (`status=0x047f`) for the INT1 program-trap fixture,
rather than `SIGTRAP`. Its QEMU version is 8.2.2; the same scenarios passed on
local QEMU 10.2.2. This points to the older emulator's INT1 implementation.
The x86 fixture now uses a genuine INT3 instruction. All program-trap stepping,
exact signal delivery and competing-launcher ownership assertions remain;
AArch64 continues using BRK. A full local x32 debugger guest passed all 627
required checks with the changed fixture, and both native x86-64/i386 session
exit and notification suites passed. [Trap evidence](compatibility-evidence/hosted-ci-int3.json)
records the actual hosted status, emulator version, inference and local proof.
The replacement hosted run must confirm the fixture on QEMU 8.2.2.

### Hardware-race fixture stability

The hosted x32 job now passes with INT3, alongside both Wine profiles and the
ARM64 kernel/frontend jobs. Normal and sanitizer jobs still intermittently miss
the real queued-hardware-trap precondition. The generator used sleeps that often
allowed a delivery stop to win, and a 131,072-iteration cap could end its search
before the existing five-second deadline. A local diagnostic reproduced this
premature-cap failure.

The fixture now runs its tracee and tracer on distinct available CPUs during
race generation, uses immediate interrupts with periodic yields, and relies on
the existing real deadline rather than the arbitrary iteration cap. It restores
both original CPU affinity masks and verifies the target affinity together with
its exact original debug-register bank. Twenty local teardown runs passed for
x86-64 and i386, observing 60 genuine queued hardware traps across normal,
SIGUSR1 and SIGSTOP cases. [Race-fixture evidence](compatibility-evidence/hardware-race-fixture.json)
retains the failing pre-cap-removal control, successful runs and source hashes.
These changes retain all signal, stop, bank and original-console requirements;
no synthetic kernel status is used. Hosted confirmation is still required.

### ARM scheduling and independent GUI register readback

The [run for `c0669be`](https://github.com/wleeaf/cheat-engine-linux/actions/runs/37590115311)
passed five of seven jobs: sanitizers, x32, both Wine profiles and ARM64
frontends. The normal job passed its syscall, injection and Mono checks before
failing standalone GUI register readback. The ARM64 kernel job failed to
generate two queued-watchpoint races on its 64 KiB kernel.

ARM watchpoints stop before their access. Repeated immediate interrupts can
prevent an emulated target from reaching that access. The generator now keeps
the earlier ARM yield/sleep pattern and limits separate-CPU affinity to x86.
The five-second deadline and every actual queued-trap, signal, bank and target
continuation requirement remain. Targeted real-kernel teardown suites passed
all three scenarios on both 4 KiB and 64 KiB guests. The 4 KiB guest used
128 MiB; the Ubuntu 64 KiB kernel exhausted memory during boot at 128 MiB and
completed at 256 MiB. Only one guest ran at a time.

The standalone register editor releases its ptrace stop after each transaction.
The fixture's later independent read raced running target code, which can
restore R15 from its stack. It now holds the target in an acknowledged loop
whose instructions preserve the edited R15 or X28, while retaining independent
real kernel readback. It restores the original primary register before detach,
restores the standalone edit and releases the loop before CLI, Lua and full
application checks. Normal and leader-exit frontend gates passed 33 and 36
checks respectively with all four screenshots. A trial using a job-control stop
was rejected by the current inspection interface; this fixture does not claim
new group-stop editing support.

[ARM and GUI evidence](compatibility-evidence/hosted-ci-arm-gui.json) records the
observed hosted results, actual guest scenarios, out-of-memory control and local
frontend checks. Local GUI checks used cached working-tree core binaries, which
also contain the separate unpublished mixed-ABI prototype. The next hosted run
must verify all seven jobs from the selected published source. The broader
mixed-ABI recovery work remains unfinished and is excluded from this CI fix.

### Older Qt buffered-save data loss

The [run for `2db0de4`](https://github.com/wleeaf/cheat-engine-linux/actions/runs/37592370883)
passed six of seven jobs, including both complete native register frontend
profiles, ARM64 kernel/frontends, sanitizers, x32 and both Wine profiles. The
normal job then failed the required GUI table-save rollback check. Its earlier
native syscall, injection, Mono and other GUI checks passed.

A real Qt 6.4.2 kernel guest reproduced the underlying data-loss mechanism:
with a 64-byte file-size limit, `QSaveFile::write` accepted buffered data and
`commit` reported success while replacing each original 3,000-byte file with
64 bytes. The recent-file history also changed, and no error dialog appeared.
Flushing settings beforehand did not repair this behavior. An explicit checked
device flush before commit rejected both writes, displayed both errors and
preserved the complete independently read original bytes and recent history.

Table saves, scan-result exports and script saves now check `QSaveFile::flush`
before committing. Table failures explicitly cancel staged output before the
error dialog. The existing rollback regression retains every original-file,
history, dialog, cleanup and restored-limit assertion; it also isolates pending
settings writes and reports each condition if rollback fails. The focused
table-save and full GUI lifecycle suites pass locally on Qt 6.11.2. The small
older-Qt mechanism probe ran in one 256 MiB, one-CPU guest; builds stayed cached,
serial and at reduced priority.

[Buffered-save evidence](compatibility-evidence/qt-buffered-save.json) includes
the hosted failure, older-Qt control and corrected probe sources, binary and
kernel hashes, exact independently compared file results and local product
checks. The small Qt probe tests the shared file-device mechanism rather than
Cheat Engine serialization. The next full hosted run must confirm the product
on the runner's Qt version. Separate mixed-ABI recovery work remains pending.

### Callee startup after a valid timeout

The [run for `5d4ec36`](https://github.com/wleeaf/cheat-engine-linux/actions/runs/37594542807)
passed the complete native and sanitizer jobs, both Wine jobs, x32 and ARM64
frontends. The real GUI rollback regression now passes on the runner's Qt.
The ARM64 kernel job passed its hardware teardown races but one SME native-call
profile failed its unfinished-callee timeout assertion. That assertion previously
assumed the callee must enter its busy loop before a ten-millisecond timeout and
did not report which condition failed.

The fixture now verifies its control writes and permits an already-owned,
timed-out call to reach the actual startup marker through bounded recovery of
that same invocation. Startup receives at most one second, while the existing
two-second whole-check bound remains. A zero-timeout case deliberately exercises
the legitimate before-entry stop alongside the ten-millisecond case. Actual
timed-out ownership, no fabricated result, foreign-thread rejection, independent
signal decisions and exact GP/vector/mask/stack restoration remain mandatory.
New diagnostics report every condition, requested timeout and startup retries.

Both complete native profiles passed again with selected CI source and baseline
product code: 642 x86-64 and 643 i386 assertions. Small focused ARM64 guests
passed normal, SVE, maximum SVE, SME and maximum SME stopped-function profiles
on the 4 KiB kernel, and all three available profiles on the 64 KiB non-SME
kernel. Their true zero-budget calls reached the marker only after an owned
retry and then passed all signal and context checks. Guests ran one at a time
with 128 MiB and 256 MiB respectively; only the changed driver was compiled.

[Callee-startup evidence](compatibility-evidence/callee-timeout-startup.json)
records these real stops, diagnostics, full native results and source/kernel
hashes. The original hosted log cannot identify its precise failed predicate;
the new diagnostics preserve that distinction. The next full hosted run must
confirm all required profiles. Mixed-ABI recovery remains separate unfinished
work and is excluded from this publication.

## 1. Feature-by-target compatibility matrix

### Completed work

- Added a target and feature matrix with separate states for classification,
  data access, instruction encoding/decoding, allocation/injection and debugging.
- Added capability reporting so unsupported operations can return an explicit
  error rather than silently assuming a local native process.
- Established operation-level fixtures for native x86-64, i386, x32 and AArch64;
  ARM32/Thumb backend primitives; Wine 9 legacy Wine32/x64 and Wine 11 WoW64/x64;
  GDB/QEMU guest CPU/RAM; CEServer TCP processes; Mono; and selected namespace
  environments.
- Exercised shared GUI, CLI and Lua behavior where the corresponding frontend
  fixtures exist, including typed scans, target formats, register views and
  target replacement/leader exit.

### Remaining work

- Complete a live feature-by-target matrix instead of treating the tested native
  paths as proof for every target and every panel.
- Expand whole-application GUI, CLI and Lua coverage for x32, ARM32/Thumb, Wine,
  remote debugging, containers and managed runtimes.
- Cover sustained concurrent attach/detach, thread exhaustion and longer stress
  runs on more distributions and kernel versions.
- Verify the feature combinations that are currently represented only by unit
  data-format tests, classification or a partial backend.

## 2. Explicit target descriptions and mixed execution modes

### Completed work

- Added explicit CPU architecture, instruction mode, ABI, pointer width, data
  byte order and instruction byte order. The selected program is distinguished
  from its Unix host/loader and its debug transport.
- Added module/address-specific format resolution and executable identity
  refresh after exec. Unknown or malformed metadata stays unknown.
- Distinguished Wine PE32 program data from an ELF64 WoW64 loader. Pointer
  operations preserve adjacent bytes at the actual target width.
- Added XML-negotiated GDB CPU descriptions and real guest register/RAM checks.
- Preserved process identity when the original group leader exits and a sibling
  continues to own the address space; frontend and runtime operations can select
  a live member without adopting a different process.

### Remaining work

- Complete ARM/Thumb interworking and per-address execution-mode handling across
  the full debugger, assembler, injection and frontend workflows.
- Add execution adapters for hybrid PE ARM64EC/ARM64X modules.
- Model logical guest processes, guest page tables and MMU translation separately
  from a QEMU guest CPU and physical RAM connection.
- Complete guest threading, nonlinear emulator memory mappings and guest writer
  attribution.
- Integrate recovery of a mixed x86 syscall-entry ABI. The newly reproduced
  hidden-state defect is described below; restoring visible registers alone is
  insufficient in that case.

## 3. Architecture-specific execution and debugging backends

### Completed work

- Verified native x86-64, i386 and AArch64 memory syscalls, registers,
  breakpoints, stepping, DebugSession ownership, Tracer and CodeFinder recovery.
- Verified real native libc/loader/pthread calls on x86-64, i386, x32 and AArch64,
  including image replacement and retained cleanup ownership.
- Added actual x32-enabled kernel fixtures. Four-byte target pointers are kept
  separate from its x86-64 instruction and syscall execution mode; mmap offsets
  are not truncated to the pointer width.
- Executed AArch64 relocation and executable-memory writes under both 4 KiB and
  64 KiB kernels. Built the ARM64 core/Qt application and ran dedicated native
  application, debugger, CLI and Lua checks.
- Added ARM32/Thumb full GP reads/edits with verification and rollback, exact
  software-trap PC/byte restoration, and VFP capture/recovery on native ARMv7 and
  AArch64 compat kernels. Preserved exposed compat TLS.
- Executed private caller-owned ARM/Thumb mmap2, mprotect and munmap, including
  live Thumb IT-state restoration, signals and sparse-file offsets above 4 GiB.
- Fixed two return-code defects: a destructive syscall could remove the second
  page of a saved x86/Thumb instruction, or the preceding x86 syscall page needed
  when an interrupted read restarts. Short instructions and completed syscalls
  can still release pages they no longer need.

### Remaining work

- Complete ARM32 process/session/allocation/call ownership, borrowed syscall
  sites and parked-syscall adapters; full frontend integration and vector editing.
- Add ARM32 hardware watchpoints, relocation, general unwinding, native TLS and
  IWMMXt preservation, and actual BE32/BE8 execution.
- Find and prove a safe native legacy FPA restoration path. The tested regset
  write panics the pinned hardened-usercopy kernel; the current backend preserves
  that bank read-only and reports the limitation.
- Complete general unwinding, native hook coordination and physical instruction
  cache/coherency coverage on ARM.
- Add architecture-specific instruction, register, trap, syscall/call, relocation
  and cache backends for RISC-V, MIPS, PowerPC, s390x and other ISAs. Generic ELF
  classification and endian-aware data access are not these backends.
- Extend live coverage for other restart errors, syscall-entry/exit stop types,
  extended vector states and mixed Windows/Unix call modes.

## 4. Real integration environments and runtime lifetime

### Completed work

- Ran native x86-64/i386 fixtures and real x32 and ARM64 full-system guests.
  ARM64 evidence includes 4 KiB and 64 KiB pages. ARM32/Thumb primitive evidence
  comes from actual native ARMv7 and ARM64 compat kernels.
- Verified Wine 9 legacy Wine32/x64 and Wine 11 x64/WoW64 memory, injection,
  restoration and main-thread hardware monitoring paths.
- Verified standalone and privately embedded Mono metadata, field/static flags,
  JIT addresses, late assemblies, pinned-object access across GC, request
  cancellation, refresh, shutdown and unload, including namespace and sanitizer
  runs.
- Verified selected Podman PID/mount namespace operations, native worker identity
  translation and a Wine fixture in a container.
- Tested real CEServer TCP identity refresh, partial transfers, transactions,
  cancellation, reconnect and multi-client isolation/resource recovery.
- Tested real GDB transport/register-bank behavior and guest GUI/CLI/Lua access.

### Remaining work

- Add Proton and broader Wine versions, full Wine DebugSession/trace and
  Wine-safe loader/library call coverage.
- Add ARM64EC/ARM64X execution environments and physical ARM hardware checks.
- Extend x32 distribution/kernel and whole-frontend coverage.
- Add Flatpak/Snap and broader host-to-container and separate-host networking
  fixtures, including transport/permission combinations.
- Complete CEServer upstream interoperability, foreign targets, DNS/queue bounds,
  context/step/signal/thread completeness and larger client/resource stress.
- Add Mono moving/unpinned-object handles, domain unload, concurrent shutdown,
  separate linker namespaces, more runtime versions/architectures and GUI checks.
- Add runtime-aware object/JIT lifetime adapters for JVM, CoreCLR, Go and V8.
- Validate real console-emulator adapters and nonlinear guest memory mappings.

## 5. Failure, restoration and ownership

### Completed work

- Retained recovery ownership after partial instruction/register/vector writes,
  failed cleanup/detach, interrupted injection and completed calls whose cleanup
  is still pending. Recovery is tied to the original process image and owner.
- Completed recovery after a genuinely applied detach reported as an error,
  with live-task ESRCH, zero obsolete context-write attempts, correct returned
  versus unreturned allocation ownership and bounded service shutdown on x86-64
  and i386. Still-owned running ESRCH and the additional windows above remain.
- Verified leader/nonleader exit and exec, thread-group changes, cloned writer
  threads, queued traps, application signal delivery and repeated attach/detach.
- Protected saved operation undo against exec, replaced code, copied/completed
  undo, independently released allocations and reused address ranges.
- Added private address-space affinity checks so an image or cleanup owner is
  not reused against an unrelated or replaced mapping.
- Fixed executable-memory write rollback, shared-code ownership, pthread cleanup
  and released-lease recovery paths.
- Improved scanner worker failure/join/cleanup/retry, numeric data formats and
  floating-point rounding paths.
- Improved CT/XML/JSON persistence and deterministic saving, including exact
  integer values and GUI/core interchange.
- Fixed GUI record/editor injection ownership and lifecycle cleanup, and Auto
  Assembler module snapshot/symbol ownership across target changes and failures.
- Added real before/after regressions for the two page-boundary defects. The old
  executor actually succeeds in its unsafe operation and the target then faults;
  cleanup after that failure is not counted as successful return execution.

### Remaining work

- Extend the integrated private-scratch mixed-ABI recovery beyond its tested
  signal, group-stop, death/exec and retry cases; prove ambiguous ESRCH ownership,
  cancellation, policy failures and additional concurrent transitions.
- Automatically discover/own a separate surviving old-mm process for cleanup;
  extend the explicit stopped-peer and selected-thread handoff proofs.
- Bound memory-syscall execution/restoration waits without losing an in-flight
  operation or its target stop.
- Extend hidden timed restart-block checks to x32 and ARM restart-stop adapters,
  additional error classes and policy/signal combinations.
- Complete remaining concurrent transport/runtime/cleanup races, controlled
  thread/resource exhaustion and ThreadSanitizer coverage.
- Extend lifetime/ownership proofs to additional ISA backends, runtimes and remote
  transports instead of assuming the local native ownership model applies.

## 6. Required checks and release gates

### Completed work

- Added normal and sanitizer core/model/native checks and operation-specific gates
  for frontend, persistence, symbols, injection, transport and runtime behavior.
- Configured required legacy Wine32, WoW64, x32, ARM32/Thumb kernel primitives,
  ARM64 kernel/frontend and real Mono profiles before release packaging.
- Added pinned kernel/input hashes, ELF/ABI validation, timeouts with partial-log
  preservation, exact profile/operation counts and evidence uploads.
- Tested gate rejection of missing/failed rows, incomplete profiles and absent,
  duplicate or contradictory summaries. Synthetic verifier controls are labeled
  separately from actual kernel-operation evidence.
- Kept builds cached, serial and at reduced priority, with one compiler job.
  Small guests use 128 MiB and one CPU, or two CPUs for existing concurrency
  matrices. Host packages and kernel settings were not changed for these checks.

### Remaining work

- Keep the now-passing hosted workflow required for subsequent changes. All
  seven jobs passed for `6834260`; future revisions need their own hosted result.
- Add mandatory gates for the additional supported environments/features as
  those adapters and real fixtures become available.
- Run a new release against the required gates when a release is requested.
  This checkpoint does not create a new release or claim universal compatibility.

## Earlier checkpoint verification

| Checkpoint | Actual results | Scope limits |
|---|---|---|
| [Return instruction boundaries](compatibility-evidence/return-boundaries.json) | ARM32/compat: 345 normal plus 345 aborting UBSan assertions; host native: 1,185 normal plus 1,185 sanitizer assertions; broader AArch64: 906; x32 debugger: 577 | Historical checkpoint; ordinary saved user-code instructions, with real unsafe-backend comparisons |
| [Interrupted-read restart boundaries](compatibility-evidence/restart-boundaries.json) | Host x86-64: 642 and i386: 643 assertions, repeated with ASan/UBSan; x32 debugger: 627; broader AArch64: 906; 18 verifier controls | 4,103 passing operation assertions across repeated variants, not 4,103 unique scenarios; interrupted reads and safe completed/user-code controls |
| [Earlier source checkpoint](compatibility-evidence/checkpoint.json) | Full serial cached build and 23 local checks passed; GUI injection: 310 assertions; normal and leader-exit frontend gates: 30 and 33 checks; JSON: 33 core plus 384 independent decimal checks | Historical results; mixed-ABI defect was still pending then; subsequent fixes and their remaining limits are recorded above |

### Checks at that earlier source checkpoint

- The complete normal application/test build passed with cached dependencies,
  one compiler job and `nice -n 10`. Both normal and no-GUI sanitizer
  configurations passed; the normal build after configuration had no work left.
- Core, deep review, target compatibility, cross-process scanning, table
  persistence and the independent JSON integer oracle passed.
- CLI usability and both actual GUI/CLI/Lua frontend profiles passed. The second
  profile exercises a process whose original group leader has exited. Their
  application, debugger, register-editor and stack screenshots are preserved in
  [checkpoint-images](compatibility-evidence/checkpoint-images/).
- Eleven GUI smoke suites passed: debugger, theme, guest scanning, structure
  dissection, hex view, disassembly, search, address editing, Lua console,
  CodeFinder and lifecycle. The separate GUI record/editor injection gate passed
  all 310 required assertions against real x86-64 and i386 targets.
- Optional cases inside the general core suite reported skips for a missing
  local Mono runtime, unavailable `gcc -m32` shared-library toolchain, absent
  DWARF in its selected binary and an unset `CE_IL2CPP_METADATA` fixture. These
  skips do not replace the dedicated earlier Mono/i386 evidence or establish
  IL2CPP coverage.
- Seven fresh kernel diagnostic runs confirmed the mixed-ABI failure, its
  direct-resume control, native/compat controls and the two prototypes. One
  product path and the emulation-only prototype intentionally reproduce failure;
  that issue remains open despite the other local checks passing.
- Python, JSON, workflow YAML, shell syntax, documentation links and staged
  whitespace are checked before publication. Hosted workflow execution still
  needs to be observed for the pushed revision.

## Initial mixed-ABI restart investigation (historical)

The following describes the original failing checkpoint. Integration and live
recovery proofs completed since then are recorded in the publication checkpoint
and follow-up entries above; their remaining limitations still apply.

A native 64-bit process can enter a compat syscall through INT 80 while its code
segment remains in 64-bit mode. The live timer fixture confirms the original
kernel syscall ABI is i386. After a stopped EAX edit zero-extends the restart
error, direct resume still restarts the original two-second sleep correctly.
Intervening native memory syscalls restore every visible GP register exactly but
leave the kernel's syscall ABI as x86-64. The same resume then returns the
error-looking value after about 1.5 seconds instead of completing the original
sleep. This is a reproduced product defect, not a completed fix.

The [investigation report](compatibility-evidence/mixed-abi-restart-investigation.json)
preserves the direct-resume control, the failing product path, normal/native and
compat timer controls, and two restoration prototypes. An emulated INT 80 entry
alone restores the advertised ABI but does not arrange the kernel restart path.
The prototype that also obtains an owned interrupt stop preserves the full
visible bank and the original deadline. It has **not** been integrated into the
product and has no fault/retry, policy, signal, exit/exec or x32 coverage yet.
That integration and those proofs are the next execution-recovery task.
