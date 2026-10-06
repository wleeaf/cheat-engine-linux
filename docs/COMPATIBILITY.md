# Process compatibility

This is the implementation and verification record for the compatibility work.
The [progress checkpoint](PROGRESS.md) lists completed work and detailed remaining
requirements, including the newly reproduced mixed-ABI restart defect.
It covers all six requested areas. A passing row requires operation-level evidence;
architecture detection or a successful build alone is insufficient.

The goal is broad, tested support with clear errors and recoverable failures.
It cannot promise access forbidden by the kernel or identical features on every
debug transport. Backend availability and verified coverage are separate concepts.

## Requirements and completion evidence

| Requirement | Required evidence | Current state |
|---|---|---|
| 1. Feature-by-target compatibility matrix | Per-feature results for native architectures, Wine/Proton/WoW64, remote transports, managed runtimes, emulators, and containers | Matrix and runtime capability API started; broad live coverage is pending |
| 2. Explicit target descriptions | Host/program ISA, instruction mode, data/instruction byte order, ABI, pointer width, transport; mixed modules and exec transitions tested | Model implemented; native/Wine transitions and mixed-module cases tested; XML-negotiated GDB guest CPU descriptions added; guest process/MMU and broader remote coverage pending |
| 3. Architecture-specific backends | Registers, breakpoints, watchpoints, syscall/call ABI, relocation, and instruction-cache handling for each supported architecture | Native x86/i386 and AArch64 session registers, breakpoints, stepping, trace, CodeFinder and memory/call recovery verified under real kernels; real native libc library/pthread calls tested on x86-64, i386, x32 and AArch64; complete ARM64 core/Qt GUI cross-build and real interactive debugger/CLI/Lua/startup checks pass; byte-level AArch64 relocation executes on both kernel page sizes; ARM32/Thumb GP registers, VFP context recovery, software traps and private stopped memory syscalls pass under native ARMv7 and ARM64 compat kernels; full ARM32 sessions, additional panels, general unwinding, native hook coordination/hardware caches, parked-call adapters and other ISAs remain pending |
| 4. Real integration environments | Native 32/64-bit, multiple Wine/Proton versions, real WoW64, ARM64 hardware/full-system VMs, containers, managed runtimes, and emulators | Native ARMv7/Thumb register/trap/private-memory fixtures plus native x86 32/64-bit, real x32 and ARM64 full-system fixtures on 4/64 KiB pages exercise the actual DebugSession owner/event loop, exec, cloned writer threads, signal delivery and destruction recovery; Wine 9 legacy Wine32/x64 and Wine 11 x64/WoW64 have live memory/injection/main-thread watchpoint evidence; native Mono 6.8/SGen metadata/JIT/GC and shutdown pass on host, in a container and with sanitizers; Proton, additional foreign features and runtimes pending |
| 5. Failure and recovery coverage | Exit/exec, thread changes, unmapped/partial memory, disconnects, interrupted injection, repeated attach/detach; target liveness and restoration verified | Exit/exec, failed and partial injection cleanup, FULLACCESS rollback, saved undo retirement/copy/reuse ownership, split return-instruction and interrupted-read restart-page protection, replaced-code conflicts, repeated Wine watchpoint attach/detach and scanner worker failure/join/cleanup/retry covered; newly reproduced mixed-ABI timed-restart defect, remaining concurrency, transport, and runtime cases pending |
| 6. Required release gates | Required environments cannot skip; packaging waits for their checks and publishes an evidence report | Native/model gates added; required GDB/QEMU CPU/RAM, legacy Wine32, WoW64, x32, ARM32/Thumb kernel primitives, ARM64 kernel/frontend and real Mono runtime checks precede release packaging and save evidence; remote workflow execution and broader environments pending |

Do not mark this work complete until every row has sufficient current evidence.
Update this table as implementation and live validation progress.

## Target and feature matrix

These states describe current verification, not promises about arbitrary programs.
"Fixture" means a dedicated live program exercised through the real process API.
"Unit" means in-memory fixtures or fixed instruction bytes; it does not prove
debugging or injection in a live foreign-architecture process.

| Target | Description/data ABI | Read/write and pointers | Encoding/decoding | Allocate/protect/inject | Debug/watch/trace | Remaining live evidence |
|---|---|---|---|---|---|---|
| Linux x86-64 | Fixture | Fixture | Existing suite + fixture | Fixture, including restoration | Existing suite + native session fixture | Concurrent exit/exec, extended register state, stress and distribution matrix |
| Linux i386 on x86-64 | Fixture | Fixture | Existing suite + fixture | Freestanding memory fixture and real libc/pthread injection fixture | Native session fixture including cloned threads, stepping, exec and recovery | General unwinding, runtime and stress coverage |
| Linux x32 | Real ELF32 x86-64 glibc and freestanding fixtures under an x32-enabled Linux 6.1 kernel | Fixture, including four-byte pthread/loader handles | x86-64 encoder and live instruction/session/trace fixtures | Actual memory operations, 64-bit mmap offsets, integer calls, library/pthread injection and exec/image recovery fixtures | Actual DebugSession, register edits, stepping, trace, hardware/software CodeFinder and recovery fixtures | Whole GUI/CLI/Lua, general unwinding, newer-kernel dispatch introspection and distribution coverage |
| Wine Windows x64 | Wine 9/11 fixtures | Wine 9/11 fixtures | Backend + live fixture | Wine 9/11 injection/restoration fixtures | Main-thread HW fixture; full debug/trace pending | Library injection, full debug/trace and Proton |
| Wine i386 / new WoW64 | Wine 9 legacy Wine32 + Wine 11 WoW64 fixtures; ELF loader and PE32 program distinguished | Both loader variants, adjacent pointer bytes preserved | Unit + real PE32 injection in both variants | Legacy Wine32 + WoW64 injection/restoration fixtures | Main-thread HW fixture; full debug/trace pending | Full debug/trace, Wine-safe loader calls and Proton |
| Wine ARM64EC / ARM64X | PE classification; mixed-code adapter pending | Width classified | Explicit code-mode adapter pending | Pending | Pending | Hybrid-module execution fixtures |
| ARM32 / Thumb / BE8 | ELF/PE unit coverage + actual ARM/Thumb kernel fixtures | Unit data-format coverage; full process API pending | Independent fixed bytes; ARM, Thumb, BE32 and BE8 | GP/VFP, traps and private caller-owned mmap2/protect/unmap verified on native ARMv7 and ARM64 compat, including Thumb IT state and sparse-file offsets; native FPA restoration limited by a reproduced kernel panic; general syscall/call adapters, relocation and BE8 backends pending | GP read/edit/rollback, ARM/Thumb trap PC and exact cleanup verified as primitives; full sessions, vector editors and hardware watchpoints pending | Real ARMv7 and ARM64 compat kernels; full application/frontend coverage, interworking transitions and BE8 execution pending |
| ARM64 | ELF/PE unit coverage + native guest fixture | Native guest fixture + unit data-format coverage | Independent fixed bytes; instructions remain LE with BE data | Process API memory/call recovery, ptrace code patch/cache and real libc library/pthread injection verified under Linux 6.18.52 (4 KiB) and 6.8.0-146 (64 KiB); shared relocation and external RX-page writes execute on both kernels; native hook coordination and hardware caches pending | Actual DebugSession, Tracer and CodeFinder hardware/page-guard monitoring, native SIMD/integer edits, data/software breakpoints, cloned threads, stepping, exec and recovery verified; complete UI/general unwinding pending | Complete core/Qt GUI cross-build and real debugger/CLI/Lua/application startup checks pass; broader whole-application runtime coverage, hardware, additional kernel/page-size configurations and BE runtime pending |
| RISC-V32 / RISC-V64 | ELF unit coverage | Generic data paths | Instruction backend pending | Pending | Pending | Full-system VM/hardware |
| MIPS / PowerPC / s390x and other ISAs | ELF classification | Generic known-width/endian data paths | Pending | Pending | Pending | Architecture-specific ABI validation and fixtures |
| CEServer | Wire ISA refreshed across actual x86-64 → i386 exec; unavailable loader/runtime metadata and ARM byte order stay unknown | Actual 32/64-bit TCP fixtures, typed pointers, exact partial transfers and mapping flags | ISA dependent | Actual TCP allocation/protection/free and failure results; local helpers rejected | Actual TCP software/hardware traps, removal, reconnect and detach on x86-64/i386; context/step/signal/thread completeness pending | Separate-host/namespace networking, ARM targets, upstream interoperability, DNS/queue bounds and multi-client resource stress |
| GDB/QEMU guest | XML-derived CPU description and explicit data format | Shared adapter, GUI, CLI and Lua; real ARM64 guest RAM edits/scans and exact restoration | Real ARM64 guest instructions decoded; invalid ARM/Thumb encodings preserve instruction boundaries | Allocation/protection/injection unsupported | Real scalar/vector register edits through backend, XML GUI editor and Lua; low-level CPU stepping; full debugger pending | Logical guest processes, MMU address translation, threading and backend-specific watchpoints |
| Containers / Flatpak / Snap | Namespace probing exists; native worker TIDs translated | Existing namespace support | Native ISA dependent | Host engine verifies native i386 pthread ownership in a Podman PID namespace; permission and ABI dependent | Permission and ABI dependent | Wine 9 fixture passes inside an Ubuntu 24.04 PID/mount namespace; broader host-to-container, Flatpak and Snap fixtures pending |
| Mono | Actual native runtime and managed assembly distinguished from Wine; standalone and private-library embeddings verified | Real runtime field offsets, types and static flags; pinned-object read/write verified across GC | Exact runtime JIT addresses, long names and late-loaded assemblies verified through C++, CLI and Lua | Agent injection and resident refresh verified on host and across PID/mount namespaces; scoped runtime references permit actual library unload | Full managed debugging and JIT replacement pending; cleanup and unload reject stale requests | Unpinned/moving object handles, child-domain unload, concurrent shutdown, separate linker namespaces, other versions/architectures and GUI runtime coverage |
| JVM / CoreCLR / Go / V8 | Runtime probing exists | Raw bytes are accessible; logical objects need runtime adapters | Native/JIT code dependent | Runtime-aware lifetime/patching pending | Runtime-dependent | GC moves, JIT replacement and stable object access |
| Console emulators | Guest RAM adapters exist for several emulators | Guest scan/edit support | Guest ISA and MMU adapters pending | Pending | Guest writer attribution pending | Real emulator adapters and non-linear mappings |

## Target model and capability API

`TargetMachine` records CPU architecture, ABI, instruction mode, pointer width,
data byte order, and instruction byte order. `TargetDescription` distinguishes
the Unix host/loader from the selected program and records transport and liveness.
`ProcessHandle::machineAt(address)` resolves module-specific formats on mixed-code
targets; the program ABI is the default for anonymous program data.

Native handles retain a pidfd where supported, reject exited process identities,
and refresh executable metadata after `exec`. An unavailable or malformed header
produces unknown metadata. It must not become an assumed x86-64 target.

A main thread can terminate with [`pthread_exit`](https://man7.org/linux/man-pages/man3/pthread_exit.3.html)
while siblings continue running. Local handles retain the original process PID
and birth but select a live member for address-space and filesystem metadata.
Memory reads/writes, batched scans, maps, module paths, separate symbols, runtime
probing and selected-thread inspection use that member. Transient memory and
native loader/pthread operations retain recovery against the original process
identity; failed restoration and unreturned mappings remain recoverable through
another frontend. Thread selectors exclude exited members. Dedicated native
fixtures verify real leader exit, mapping permissions, final group exit, actual
glibc `pthread_exit`, library constructors and completed pthread workers on
x86-64, native i386 and an ARM64 full-system kernel. Task
directory availability still depends on the kernel; a missing directory gives
an operation error rather than probing unrelated processes.

Full debugger startup now accepts a stopped group whose leader has already
exited and selects an actual stopped member for its initial register bank. The
public process PID remains unchanged. Native single-thread CodeFinder selects a
live member; Wine still restricts hardware monitoring to its original main thread.
Live cases exercise software breakpoints, native single-step, instruction tracing,
both native hardware-monitoring modes and their real cleanup after leader exit.
Separate live Qt cases verify debugger and standalone-editor thread selection,
register edits, stack reads, CLI/Lua and application startup in this state on
x86-64 (33 checks) and a full-system ARM64 kernel (34 checks).
Additional debugger cases cover leader, worker and final-thread exit during
all-stop stepping. The owner detaches at Linux's irreversible EXIT stop instead
of waiting for a leader notification that depends on frozen siblings. Failed
detach retains its actual stop and recovery record. Surviving contexts and thread
snapshots replace departed tasks; final exit publishes a terminal event. A
nonleader exec case drains sibling EXIT stops, adopts the kernel's replacement
TID and retires old-image traps. These are dedicated full-debugger cases;
concurrent transport and transient syscall/call-owner lifecycle coverage remains
incomplete.

An application can launch its own target and consume its debugger's wait
notifications on another parent thread. The owner verifies real kernel siginfo
before recovering signal, CLONE, EXEC or EXIT stops. A second wait drains reports
that become available during the probe to prevent duplicate stop handling,
preserving actual signal delivery and retiring old-image traps. A running worker's exit and final-process
death remain observable without another debugger command. Failed EXIT-stop detach
retains its owner and freezes survivors for recovery. Paused sessions also poll
for kernel events, so SIGKILL cannot leave a dead target displayed as an editable
stop. Idle recovery probes one recorded task per poll instead of scanning the
whole group. When the original leader has retired, an additional probe of the process PID
can discover a renamed exec; it requires actual EXEC siginfo and a kernel
event message naming a recorded former TID before adopting the replacement.
Bounded real launchers reproduce consumed notifications; separate live
Qt checks verify automatic session retirement and disabled stale register edits.
These launchers cover same-thread exec and consumed nonleader exec notifications
across kernel TID replacement, both while running and during all-stop stepping.
They hold userspace bookkeeping only after a real leader detach, consume the
replacement task's real EXEC report, and verify fresh registers, no old-image
code writes, original console work and normal final exit. A failed replacement
context read still publishes image retirement with an unavailable register bank;
the same owner can reread the real bank without another attach. Other concurrent
ownership/transport races remain unverified.

Live member selection also excludes Linux's `PF_POSTCOREDUMP` and `PF_EXITING`
task flags. The [kernel exit path](https://github.com/torvalds/linux/blob/v6.18/kernel/exit.c)
sets these before releasing the address space and before zombie state, so an
owned EXIT stop and its running cleanup cannot supply a usable application thread.
Native syscall-return stepping recognizes the real x86 `TRAP_BRKPT` notification
using its syscall register state and exact return PC. A genuine program INT1
trap remains a signal; ARM64's syscall pseudo-step remains separate from BRK.

Module backing paths use the target's filesystem view. A host pathname is retained
only when its device and inode match the target-root file. This prevents a host
library at the same pathname from supplying a container module's ISA or symbols.
Resolved target-root paths are reusable; inaccessible or deleted target files
retain unknown metadata rather than selecting another host binary. A real
host-to-container fixture verifies a 32-bit target library shadowed by a 64-bit
host file, its correct symbol-based execution, and deletion while mapped with
the original application still running.

Little-endian ELF32 and ELF64 symbol loading also follows separate debug files.
Candidates must
match the module's ELF class, byte order and machine, together with either its
full-file `.gnu_debuglink` checksum or its GNU build ID. A wrong adjacent file
does not hide a valid `.debug` fallback. Container global debug directories are
searched through the target root; host debuginfo can be used only after the same
identity checks. Debuglink directory components and missing or truncated
checksums are rejected. The checksum format and directory layout follow the
[GNU separate-debug-file specification](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Separate-Debug-Files.html).
These checks verify symbol-file selection, not every DWARF or unwind feature.
Process symbol loading keeps the target root even when a mapped ELF is the same
inode as a host file. An idle real i386 fixture verifies target-only global
debuginfo for that shared ELF and normal completion of its original kernel read.

Pointer expressions, typed values, pointer paths, and Lua scalar/pointer operations
use target data formats. Auto-assembler caves inherit the preferred injection
module's instruction format. Data directives use the target's data byte order.
Unknown pointer width or byte order must be explicitly resolved before typed access;
raw byte access remains possible where permissions allow it.

`targetCapabilities()` reports `available`, `partial`, `unsupported`, `blocked`, or
`unknown` for individual operations, with reasons. "Available" means the backend is
implemented, not that permissions are granted or every environment has been tested.
The memory operation's syscall result remains authoritative.

The CLI reports descriptors and capabilities in `cescan info <pid>`. The GUI puts
them in the attached process tooltip. Lua exposes `getTargetInfo()` and
`getTargetCapabilities()`. For mixed-code instruction operations, the code address
must select the module's ISA rather than the loader's bitness.

## Required checks implemented so far

```bash
./build/cecore_compatibility_test
python3 test/gdb_transport_gate.py build --require-qemu --report build/compatibility-evidence/gdb-transport.json
python3 test/gdb_gui_gate.py build --require-qemu --report build/compatibility-evidence/gdb-gui.json
python3 test/elf_debug_gate.py build --require-i386 --report build/compatibility-evidence/elf-debug.json
python3 test/autoasm_module_gate.py build --report build/compatibility-evidence/autoasm-modules.json
python3 test/native_syscall_gate.py build --report build/compatibility-evidence/native-syscalls.json
python3 test/native_call_gate.py build --require-i386 --report build/compatibility-evidence/native-injector.json
python3 test/mono_compatibility_gate.py build --report build/compatibility-evidence/mono-runtime.json
python3 test/code_write_gate.py build --output build/compatibility-evidence/code-write.log --report build/compatibility-evidence/code-write.json
python3 test/wine_compatibility_test.py build --require-wow64 --report build/compatibility-evidence/wine-local.json
python3 test/gui_runtime_gate.py build --report build/compatibility-evidence/native-frontends.json
python3 test/gui_runtime_gate.py build --leader-exit --report build/compatibility-evidence/native-frontends-leader-exit.json
bash tools/check-arm64-vm.sh
CECORE_VM_PAGE_SIZE=65536 bash tools/check-arm64-vm.sh
CECORE_CI_JOBS=1 CECORE_REQUIRE_WINE=1 tools/ci-check.sh
```

The GDB gate combines independent TCP peers with a stopped, single-CPU, 64 MiB
ARM64 QEMU guest. It verifies real guest RAM, scalar/vector register edits,
instruction stepping, disassembly, ordinary byte scans and exact restoration.
It also runs the production CLI Lua runner against an independent big-endian
stub and a separate real ARM64 guest, including actual binary vector edits,
typed access, failed-connection preservation and exact restoration.
Raw probes against the
released GDB client fail 11 of 14 cases, reproducing the prior packet and memory
reply errors. These are local worktree results, not completed remote CI jobs.
The 2026-10-05 snapshots record [59 normal cases](compatibility-evidence/gdb-transport.json),
[57 ASan/UBSan cases](compatibility-evidence/gdb-transport-sanitizers.json), and
[six GUI scenarios](compatibility-evidence/gdb-gui.json). The GUI report includes
hashes for eight [actual widget screenshots](compatibility-evidence/gdb-gui/).
Archived reports were checked against the tested binaries and PNG hashes. The
full local CI mirror passed; these snapshots remain uncommitted worktree evidence.
This is a bare-metal CPU/RAM fixture. It does not establish Linux guest-process
selection, virtual-to-physical translation or full DebugSession support.
Native build and release workflows require QEMU and fail if it cannot run;
the sanitizer workflow requires protocol, adapter, CLI and Lua cases. Local CI uses
`CECORE_REQUIRE_GDB_QEMU=1`, or `CECORE_GDB_QEMU_CONTAINER=<existing-container>`
for QEMU installed in an existing container, to require the real guest checks.

The separate GUI gate reuses the existing lifecycle executable and runs five
independent-stub scenarios plus one real QEMU guest. It drives the production
File connection dialog, cancellation, target replacement, Memory Viewer, shared
Lua console, XML register editor and ordinary GUI scanner. Failed XML and
cancellation preserve the old native target; explicit four-byte big-endian
pointers work on an ARM64 CPU; unknown-format pointers and unavailable registers
remain unavailable. Live guest edits verify full 128-bit vectors, reject an
invalid edit set before its first write, preserve unedited registers that changed
after Refresh, and restore all captured registers and all 4096 RAM bytes exactly.
Disconnect freezes old views, releases target-bound editors and clears the
console target. Required native and release workflows save its JSON report and
actual PNG screenshots. Socket cancellation keeps the dialog responsive; system
DNS lookup still follows the system resolver's timing. Register and memory
refreshes use bounded synchronous transactions; complete asynchronous GUI
refresh and arbitrary guest-process debugging remain pending.
Shared host-operation guards reject remote, unknown or exited targets before
signals, `/proc` path lookup or branch sampling. Model cases use a remote target
identifier equal to the fixture's real host PID; CLI Lua, the shared GUI console,
the GUI pause action and disabled Branch Mapper also verify the guest path.

Numeric scans resolve the selected program's data byte order and pointer width,
with the frontend's full representable address range as the default. Independent
model and TCP cases exercise memory above the old 47-bit ceiling; boundary fixtures
include complete values ending at `UINTPTR_MAX`. Next scans apply From/To before
their batched reads. Invalid or overflowing map spans and reversed ranges fail
before memory reads. Explicit `ScanConfig`, GUI, native CLI and Lua overrides support independently
encoded data. Integer, floating-point, Unicode and grouped comparisons retain
raw target bytes; saved result metadata carries their format through reloads,
pruning, next scans and GUI/CLI/Lua display. Unknown byte order or pointer width
cannot silently become the frontend's format. Automatic next scans reject a
changed format; explicit byte-order overrides reinterpret saved and current
samples together, while the record width must stay constant. Invalid metadata
is bounded and rejected, including nonregular files, links, truncation and
numeric overflow. Legacy snapshots without metadata remain loadable.
GUI Memory Scan Options expose Auto/Little/Big data order and Auto/4/8-byte pointer
sizes. These override the scanned data encoding without changing CPU metadata.
Transferred numeric records retain their captured format for live reads, edits,
freezing and table persistence; scan-only result types become meaningful raw-byte
records. Per-record context menus can change the value format or restore Auto.
The shared typed I/O supports explicit pointer widths even when target metadata
is unknown. XML uses `LinuxDataByteOrder`/`LinuxPointerWidth` extension tags;
JSON stores `dataByteOrder`/`pointerWidth`, and protected tables retain the XML
fields. Invalid metadata is rejected rather than silently selecting a host format.
The [GUI data-format evidence](compatibility-evidence/gui-data-formats.json)
records five added model checks (166 normal and sanitizer checks in total), actual
native GUI scans/record edits/freezing/table saves, an unknown-format GDB peer and
BE32 pointers in real ARM64 QEMU RAM. Guest edits preserve neighboring bytes and
are restored. These are explicit value-data encodings, not guest MMU translation
or new native foreign-architecture backend evidence.
Independent byte fixtures verify both orders, both pointer widths, raw saved
values, delta/percentage comparisons, first-value retention, UTF-16 BMP/surrogate
pairs, ASCII case folding and inclusive scan boundaries. The real CLI Lua runner
also exercises numeric/pointer/float/Unicode and custom pointer-formula scans
against the independent BE32 stub and LE64 ARM64 CPU. Explicit BE32 samples in
the ARM64 RAM fixture verify an independent data encoding, without claiming a
big-endian CPU/kernel runtime. The actual GUI verifies BE32 numeric/pointer
scans and independent live/captured columns, with two additional screenshots.

All-type scans retain per-address numeric candidates across saved samples,
reloads, pruning and subsequent scans. Narrowing compares each surviving type
numerically, including float/double changes, integer deltas, percentages and
first values. It retries narrower candidates when wider reads fail, applies
inclusive bounds to each candidate width, and supports selecting a surviving
concrete numeric type with a new record stride. Invalid candidate streams fail
instead of reconstructing types from bytes. Legacy All snapshots require a fresh
All scan. GUI, CLI and Lua display only meaningful candidate bytes; Lua exposes
candidate queries and selected numeric decoding. Independent model fixtures
cover both byte orders, sharding and concurrent batches. A separate GUI model
check uses a real protected-page boundary and verifies live/captured columns
and change highlighting. These are data-path checks, not additional foreign
Linux backend coverage.
Actual GUI scan controls also exercise both floating Between bounds and selection
of a concrete candidate. The CLI Lua gate repeats short-tail and floating All
scans against the independent BE32 peer and actual LE64 ARM64 QEMU RAM, retaining
its exact restoration checks.
The [All-scan evidence](compatibility-evidence/all-types.json) records 155 normal
and 155 sanitizer model checks, actual GUI controls and protected-page reads,
source/binary hashes and a successful full host CI mirror. The shared number
parser retains exact integer magnitude/fraction boundaries independently of
double conversion, including scientific and hexadecimal input. Malformed values
preserve old results; floating relational bounds retain double input precision,
and finite values overflowing a float cannot become infinity matches. GUI
scientific rounding and Lua `format.value2` cover their actual frontend paths.
Percentage scans use their own thresholds, independently of ordinary All bounds.
The [number checks](compatibility-evidence/all-numbers.json) include 51,102 exact
rational comparisons per build and live native CLI numeric/percentage workflows.
Text input is bounded to 4096 characters and the parser's double range. These
checks do not add live foreign Linux kernel scan coverage.

[Scanner failure evidence](compatibility-evidence/scanner-failures.json) adds
six checks to the compatibility model suite (161 per build). Controlled allocation,
transport and unknown exceptions exercise single and parallel first/next scans
with ordinary Byte and All snapshots. Worker exceptions now reach the caller
after every worker joins, instead of first scans returning false success or
parallel next scans terminating the engine. A synchronized sibling read verifies
that reporting waits for the remaining worker. Failed operations remove their
partial directories and release file descriptors, preserve the original snapshot
files and target bytes, and permit retry on the same scanner and Lua scan object.
Worker ownership also uses automatic joining during thread-creation failure;
controlled operating-system thread-creation exhaustion remains unverified.
These are bounded fault fixtures, not tests that exhaust this workstation's
memory or evidence for every concurrent transport lifecycle.

[Floating-rounding evidence](compatibility-evidence/floating-rounding.json)
adds nine model checks for original-input precision, scalar/SSE2/AVX2 results,
typed and All first/next scans, grouped values and Lua controls. Shared floating
parsing retains scientific precision. Rounded, truncated, tolerance and relational
comparisons avoid premature float narrowing; Exact still compares at the stored
type's precision. Actual GUI controls accept large and small tolerances, preserve
results after invalid input and report scan completion. The live native CLI has
22 workflow checks, and the production Lua runner verifies the options against
both the independent BE32 peer and real ARM64 QEMU RAM. These remain data-path
checks, with separate reports for Linux kernel/debugger coverage.

`GdbProcessHandle` implements the shared memory API using the stopped stub's
XML architecture and register numbering. It retains independent data and
instruction byte order, accepts explicit guest ranges or an advertised memory
map, and never fabricates a local PID or host ABI. A pointer-width override
invalidates an incompatible ABI rather than inventing one. Allocation, protection,
injection and full guest debugging remain unsupported or partial.
The client bounds socket transactions, XML size/depth and packet sizes,
handles retransmissions and console packets, and reports only confirmed memory
write prefixes. Malformed stops/maps and failed setup cannot resume the guest.
XML includes support namespace aliases and QEMU's conventional `xi` form,
without fetching external DTDs. These protocol details follow the
[GNU remote protocol](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Overview.html)
and [target descriptions](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Target-Description-Format.html).

Individual-register support is optional. An empty `p`/`P` response selects
the shared `g`/`G` fallback, independently for reads and writes. The client
orders XML fields by register number without padding absent numbers, validates
the returned bank and rereads it for each edit. Complete returned prefixes stay
usable; omitted or unavailable registers do not become invented zeros.
Malformed/error individual replies cannot trigger fallback writes. A `G` edit
must fit the negotiated packet size and preserve every unrelated known byte;
unknown unrelated fields cause an error before the bank write.
Independent peers cover sparse mixed-width banks, vector and scalar edits,
fresh unrelated state, malformed banks, failed writes, disconnects and deadlines.
A separately framed proxy disables individual packets against real ARM64 QEMU:
its actual core `g`/`G` registers support edits, MOV/ADD execution and exact bank
restoration. QEMU's vectors are omitted from its core bank and remain unavailable
in this mode; ordinary individual-packet vector checks remain separate. This
does not establish logical guest-process or MMU support.

The [register-bank snapshot](compatibility-evidence/gdb-register-bank.json)
records 79 native and 75 sanitizer protocol/frontend cases, seven GUI scenarios
and ten screenshots. Fifteen independent bank cases cover the fallback and its
failure paths. The earlier [GUI data-format snapshot](compatibility-evidence/gui-data-formats.json)
retains its own source and binary hashes.

The native integration fixtures are freestanding ELF programs and require no
32-bit libc. Their build and execution are mandatory on the x86-64 compatibility
runner; failure to build or run i386 is a failure, not a skip.

Separate dynamic fixtures exercise actual native `dlopen`, constructors,
`pthread_create`, bounded waits and actual detached-thread exit on x86-64, i386 and ARM64.
The x86-64 build/release runners require multilib libc and
`CECORE_REQUIRE_NATIVE_CALL_I386=ON`; a missing dynamic i386 toolchain fails
configuration. The ARM64 gate includes the real guest libc and loader, recording
their hashes alongside the executable and injected library. Ordinary local
builds can run their native fixture without a multilib toolchain; that result
does not establish i386 libc coverage.

The model checks cover x32, ELF byte order and malformed headers, PE32/PE32+ and
hybrid PE classification, WoW64 data pointers, mixed-code allocation selection,
big-endian integer/float/pointer operations, Lua overrides, and target exit.
The live native checks cover target metadata, pointer reads, observable writes,
allocation, protection, deallocation, generated injection, execution of relocated
instructions, exact restoration, executable page permissions, continued target
liveness, and a 64-bit-to-32-bit `exec` transition on the same handle.

The Wine fixture builder creates real PE32/PE32+ console programs using the
project assembler and Windows kernel32 APIs, with no MinGW or 32-bit Unix library
requirement. Each run uses a fresh isolated prefix. The Wine integration driver
checks module ISA, program-width pointers and neighboring-field preservation,
observable writes, generated injection, relocated execution, exact byte and page
permission restoration, continued execution, and three immediate-write hardware
watchpoint attach/detach cycles. Startup must arm the watchpoint before reporting
success. Wine main-thread selection is enforced in the shared backend. Native library
and pthread injection helpers are rejected for Wine until a dedicated Wine-safe
loader and Windows thread initialization backend exists; the native helpers
quiesce sibling threads and cannot safely serve this runtime.

Local evidence:

- Wine 11.0 (Staging), Fedora 44, x86-64 Linux kernel 7.1.8: Windows x64 and a
  real PE32 program inside an ELF64 Wine loader.
- Wine 9.0 (Ubuntu 9.0~repack-4build3), Ubuntu 24.04 userspace in a Podman
  PID/mount namespace on the same kernel: Windows x64 and a real PE32 program
  inside an ELF32 Wine loader. The engine was compiled inside that container.

The architecture-specific memory-syscall executor selects the stopped thread's
register ABI. When a busy WoW64 thread runs PE32 code without any suitable ELF32
syscall site, the x86-64 backend temporarily selects Linux's native 64-bit code
segment and Unix loader ABI. It restores the complete original register image,
including the Windows execution mode and syscall restart state, before detach.
Transient operations execute an existing non-writable Unix ELF
syscall instruction of the execution ISA, leaving program code unchanged while siblings run.
Wine PE opcode matches are excluded, because they can belong to Windows syscall
dispatch. Private-page and all-stopped executors still verify code and register
restoration before releasing ownership.
Its x86-64 and i386 live tests cover blocked-read restart, quiesced busy-code restoration,
actual kernel errno, rejected destructive syscall-page operations, failed register
and opcode restoration, failed detach, owner-thread enforcement, completed-but-
unreturned allocation cleanup, exit during recovery, and real user SIGTRAP delivery.
Equivalent tests run inside an ARM64 Linux 6.18.52 full-system guest with QEMU TCG;
this is real guest-kernel ptrace, not QEMU user-mode emulation.
The required kernel workflow now runs two profiles sequentially against the same
cached driver: 881 checks under that kernel with 4 KiB pages and all positive
SME/deferred-state cases, and 722 checks under Ubuntu's pinned Linux
6.8.0-146-generic-64k with actual 64 KiB pages. The additional kernel lacks SME;
its gate verifies both the missing userspace capability and rejected vector
control, retains live SVE syscall/call preservation at default and maximum lengths,
and explicitly lists 11 excluded SME cases. Its SVE fixtures independently
schedule and verify deferred vector lengths through real exec after transient,
private, quiesced and native-call operations. Seccomp and alternate-stack guards
also verify SVE rejection and retained deferred state without requiring SME.
Both profiles retain real
memory, debugger, trace, CodeFinder, native libc/pthread and recovery requirements.
See the [kernel profiles and input hashes](compatibility-evidence/arm64-kernel-profiles.json).
These fixtures use two guest CPUs and 512 MiB RAM each, one guest at a time;
they do not establish other page configurations or hardware perf support.

Hardware tracing uses runtime page sizes, kernel-reported data-ring layouts and
bounded record payloads. Independent fixtures cover 4/16/64 KiB page layouts,
physical and 64-bit counter wrap, larger branch stacks, malformed records and
AUX notification consumption. Inactive start/drain/stop concurrency is also
tested; live PMU sampling concurrency and Intel PT decoding remain unverified.
The layout and publication rules follow the
[kernel perf ring interface](https://docs.kernel.org/userspace-api/perf_ring_buffer.html).

Recovery keeps an
owned ticket and a completed syscall result when restoration fails. Linux ARM64's
syscall pseudo-step trap is distinguished from a signal with a real sender.
A shared-code fixture keeps two threads executing the same function through repeated
mmap/mprotect/munmap, forbids all ptrace code writes and verifies sibling progress
and unchanged executable mappings. A separate real seccomp filter traps mmap:
the executor reports permission failure without inventing a completed allocation,
consumes the queued owned step trap and restores the original context before detach.
The process continues under its unchanged filter. This verifies trap denial, not
all seccomp actions.

For Linux syscall-user-dispatch, the executor reads the stopped thread's kernel
configuration and prefers syscall sites whose post-instruction PC is in the
always-native range. The kernel exports the normalized range, including a
wraparound complement for inclusive dispatch. It can also use another Unix site
when the selector allows it. Configuration and selector bytes are never changed.
The native x86-64 and i386 gates install real exclusive dispatch and verify a
one-byte native range with blocked or invalid selectors, an allowing selector
without a native range, and rejection before mutation when no usable site exists.
They compare the complete kernel configuration and selector before/after and
verify CPU progress, actual mapping/protection/removal and normal console work.
Inclusive dispatch, older kernels without the configuration query, and selector
races with other threads still need live coverage. The Wine 9/11 fixtures report
their kernel dispatch mode; their successful busy runs have dispatch disabled.

Busy PE32/PE32+ Wine fixtures execute a Windows CPU loop and verify their actual
stopped Windows register mode. Repeated memory syscalls preserve every general
register and segment, maintain loop progress, and resume normal Windows console
work. Default allocations fit the program's pointer width, including a PE32
program under an ELF64 loader. Module-specific allocation near the 64-bit Unix
loader retains that module's wider address range. Oversized page-rounded 32-bit
requests are rejected before target mutation.
When the kernel's preferred low-address allocation window is exhausted, the
allocator searches the rest of the program's 32-bit address space without
replacing existing mappings. The WoW64 fixture fills that window using unpopulated
PROT_NONE reservations, verifies a usable default allocation outside it and
removes every temporary mapping before the Windows program resumes.

The application's `LinuxProcessHandle` now delegates allocation, protection and
free to a shared owner service. GUI/CLI/Lua callers share that service thread,
which retains recovery and completed-but-unreturned allocations across caller and
handle destruction. A new handle can explicitly retry through
`retryPendingOperations()`; automatic retries use the same owner thread. Service
shutdown drains restoration and orphan allocation cleanup before the owner exits.
If an external condition keeps restoration impossible, shutdown waits rather than
implicitly detaching an unrestored target. Target descriptions report
`pendingRecovery`, and debugger/injection capabilities explain that blocked state.
The live suite checks concurrent callers and owner-thread shutdown cleanup. It
also retains the original memory-image descriptor so cleanup can reject a same-file
exec even when PID, start time and executable inode are unchanged.

Recovery ownership is reserved before attachment, including failures while
capturing registers, validating a request or allocating preflight buffers. A
failed interrupt can leave the seized thread running: recovery obtains a real
stop before detaching it, without replaying an unfinished register snapshot.
Detach failures retain an owner record even when no syscall ran and no allocation
completed. Live tests inject these failures, verify that another host thread
cannot replay recovery, release the original relationship on retry and check
blocked-read restart and console liveness. Allocation failure before attachment
leaves the target untouched; allocation failure after attachment preserves
recovery. The actual process API also retains preflight cleanup through handle
destruction, and target exit retires the record idempotently. Initialization
writes are tracked before attempting them, so an error reported after code,
register or syscall-slot mutation still restores the changed state.

Page rounding uses the host kernel's actual page size and rejects overflow and
zero-length requests before mutation. Kernel errno reaches the caller. The process
API and DebugSession are independently compiled with their real support sources
for ARM64 VM checks. The complete ARM64 application also cross-builds and its
debugger/startup paths run in the guest; native hook installation, non-ptrace cache handling,
additional frontend paths and other foreign-host builds remain required.
The shared native debug backend reads the stopped thread's actual register bank,
including i386 compat contexts on an x86-64 host and all 31 ARM64 integer registers.
It reads x86 XMM and ARM64 FPSIMD registers, validates register-context ISA before
writes, and preserves unmodeled syscall state. `DebugSession` now uses this backend
for integer/vector capture, integer edits, software trap storage, watchpoint banks,
and its stop/event loop. The required native and guest suites execute the actual
session owner thread through repeated watchpoint hits, a newly cloned writer,
thread selection, single-step, native-call step-over, entry step-out, run-to-cursor,
same-image exec, detach and destruction after failed code-cleanup verification.
The child can report its automatic stop before the parent's clone event; it stays
frozen until its watchpoint bank is armed. ARM64's pre-access watchpoints execute
the stopped instruction with owned watchpoints lifted, then rearm before resuming.
Kernel-rejected x86 register writes restore earlier fields even when SETREGS has
already partially updated the bank. Genuine user SIGTRAP delivery survives a
full-session exception breakpoint and produces a process-exit event.
Single-step drains an outstanding all-stop interrupt rather than resuming a
thread with a lifted software trap. A genuine signal during stepping keeps the
target frozen through trap rearming and is forwarded on the next continue.
The real instruction tracer uses native PC/register and execution-breakpoint
banks, selects the decoder from each instruction address, and steps over native
calls using decoder call groups. It preserves occupied breakpoint slots and
original hardware state, follows newly cloned writers, stops on exec without
replaying old-image state, and forwards genuine signals. Failed cleanup retains
the ptrace owner until restoration and detach succeed; target exit retires the
dead bank. Cancellation and overlapping trace requests have live tests on all
three ABIs. Trace table rows, full register dumps and saved traces use ARM64 or
i386 register names where appropriate, and invalid GUI addresses/ranges produce
errors before starting a trace.


CodeFinder now uses a shared owner/event loop for native hardware and software
page guards. Hardware mode reserves a free slot, preserves independently occupied
slots and restores saved addresses and control state before detach. Previously
configured disabled ARM64 slots are briefly enabled while stopped to restore their
length/type attributes, then disabled again. ARM64's kernel
retains length/type bits in disabled perf events after a slot has been used; cleanup
verifies that such slots are disabled, restores their addresses and avoids creating
unused later-slot events. Occupied slots retain their exact values. The actual
CodeFinder tests cover repeated stores, cloned writers, exec, genuine SIGTRAP,
job-control SIGSTOP/SIGCONT, failed startup/cleanup and exit during recovery.

Software watchpoints stop every owned thread before lifting the guard, execute the
faulting instruction and rearm before allowing other writers to run. Memory syscalls
use a private executable scratch page with the stopped thread's native ABI, preserve
register/syscall state and leave ptrace ownership with the caller. Cleanup restores
original page permissions and frees the scratch page through an all-stopped syscall
before detaching. Live checks compare the entire mapping/protection list before and
after monitoring and exercise interrupted syscall execution and failed restoration.
Kernel writes and bulk accesses that overlap a watched range still need broader
coverage, so software-watchpoint capability remains partial. Wine software guards
remain unsupported; Wine hardware monitoring continues to watch the main thread.
CodeFinder views and text exports display ARM64 or i386 native registers and show
operation/recovery errors.

The interactive debugger selects the stopped thread's actual register bank:
EIP/ESP and ten general-register rows for i386, eighteen rows for x86-64, or
PC/SP/X0-X30/PSTATE for ARM64. ARM64 displays all 32 FPSIMD vectors and FPCR/FPSR;
unavailable banks remain visibly unavailable. Native register edits refresh the
cached stop context, instruction highlight and stack position from kernel
readback. ARM64 conditions expose native register names and FP/LR aliases; branch
hints decode NZCV rather than x86 flags. Full four-byte BRK instructions are
masked for display and restored on detach. Raw stack slots follow the stopped
register ABI rather than the program's default pointer width.
Register layouts and NZCV positions follow the
[Linux ARM64 ptrace UAPI](https://github.com/torvalds/linux/blob/master/arch/arm64/include/uapi/asm/ptrace.h).

Real offscreen Qt tests verify these debugger operations on native x86-64 and
inside an ARM64 Linux 6.18.52 guest. The same ARM64 guest executes the actual CLI
metadata and Lua/disassembly paths and launches the complete GUI application,
attaches to a live target, opens the memory viewer, saves its screenshot and exits
cleanly. The guest uses one virtual CPU and 512 MiB RAM; its archive is streamed
to keep host packaging memory bounded. Unattached views initialize their decoder
for the engine's native ISA, allowing the ARM64 GUI to start with an ARM-only
Capstone build. Disassembly export selects the requested code address's ISA.

The complete core and Qt GUI cross-build with GCC 13, actual ARM64 Qt, libdw,
X11, Capstone and cross-built Keystone. This verifies the tested runtime paths,
not every panel or workload. General unwinding, extended-vector UI and a physical
ARM64 desktop remain pending. Full debugger capability stays partial. Required native ARM64 frontend
checks now run in the reusable workflow; local guest results do not establish
that those GitHub jobs have executed.
The standalone register editor and raw stack window use a shared selected-thread
inspection service. Registers, base SIMD and stack bytes are captured before
releasing that thread's stop; symbol-file parsing follows afterward. Register
Apply merges only values changed from the displayed snapshot into fresh kernel
state, preserving unedited PC/SP, flags, segments and general registers. A failed
callback restores its original GP image; a failed detach remains owned by the
native service and is visible/recoverable through the process, including when the
selected task is a sibling. Inspection uses SEIZE/INTERRUPT on one selected task,
without executing an injected syscall or stopping its siblings. The callback is
restricted to register reads, optional GP writes and read-only process inspection;
vector or memory mutations require their own recovery machinery. Thread identity
and execution mode must still match when applying edits. The window refreshes
its thread list and disables edits if a snapshot cannot be obtained. Actual Wine
11 PE32/PE32+ CPU loops also verify this inspection path, including Windows
register mode, consecutive stack words and release of the selected stop.

Wine fixtures and prefixes now use `BUILD/.wine-compat` by default, with
`--work-dir` available for another scratch location. This avoids placing large
prefixes in a RAM-backed `/tmp`; cleanup remains restricted to each test's
isolated prefix.

Vector reads currently cover the base x86 XMM and ARM64 FPSIMD banks. Extended
register snapshots now retain the complete kernel-exposed x86 XSAVE bank (with
legacy FP/SSE fallback), compat TLS descriptors and supported ARM64 FP/TLS,
SVE/streaming-SVE, ZA/ZT and extension control banks. Memory-syscall recovery
restores and verifies these images before releasing the owner stop. Restoration
uses buffers allocated before mutation; a failure retains the stop, images and
completed allocation for retry. A completely unchanged context requires no
register writes; unchanged vector configuration and matrix banks are left alone.
Writing an inactive streaming bank changes CPU mode and writing ZT enables ZA.

The ARM64 VM gate requires live SVE and streaming-SVE/ZA checks at both the
default and maximum 256-byte vector lengths. The fixtures keep vectors and
predicates live in a CPU loop, avoiding a normal fixture syscall that would erase
the seeded state. Tests compare every captured register byte after the actual
process API's allocate/protect/free, force failed extension restoration, verify
the target stays stopped, recover on the original owner and remove the unreturned
allocation. Direct kernel mutation also discards a live bank, changes its vector
length and destroys ZA; verified restoration recovers the complete captured
images and original streaming mode before allowing CPU/console progress.

Linux does not export deferred SVE/SME vector lengths scheduled for the next exec
through GETREGSET; writing a vector regset can reset that configuration
([Linux SVE interface](https://www.kernel.org/doc/html/latest/arch/arm64/sve.html),
[vector-length setter](https://github.com/torvalds/linux/blob/v6.18/arch/arm64/kernel/fpsimd.c)).
Live scalable-vector memory operations now restore through a guarded native
signal frame instead of writing those regsets. The kernel restores the vector
payload and execution mode without replacing the deferred configuration
([signal-return implementation](https://github.com/torvalds/linux/blob/v6.18/arch/arm64/kernel/signal.c)).
Real fixtures schedule different SVE and SME lengths for the next exec, run live
vector loops during transient, private and quiesced memory operations, then
actually exec and verify both scheduled lengths take effect. Control fixtures
verify the same transition without memory operations.

The frame borrows only an existing writable kernel-labelled main-stack range
below SP. Every borrowed byte is backed up and verified after restoration.
Signal masks and configured alternate stacks, including SS_AUTODISARM, are
preserved. The return frame deliberately supplies an invalid zero-size enabled
alternate stack: Linux rejects that update without changing the current stack,
and its signal-return helper suppresses the validation error
([alternate-stack restoration](https://github.com/torvalds/linux/blob/v6.18/kernel/signal.c)).
Real tests seed nonzero stack bytes and FP control/TLS state, force partially
failed frame writes and failed stack cleanup, retain the stopped owner, and
verify recovery before CPU progress. The required VM gate now has 749 checks,
including preflight ownership, partially failed initialization writes and
debugger, tracer and hardware-monitoring startup after leader exit.

This backend requires no syscall in progress, no seccomp filter, no active GCS,
and a kernel-labelled main stack. It rejects unsupported contexts before target
mutation. Real seccomp filters denying signal return and handlers running on an
alternate stack verify exact rejection, continued execution, unchanged signal
configuration and preservation of both deferred lengths through exec. Thread
stacks, coroutine stacks, active alternate stacks and filtered live-vector
targets still need an alternative restoration backend; ARM64 memory capabilities
remain partial. The generic ptrace register-image setter alone does not preserve
unexposed deferred configuration. Arbitrary call contexts, advanced-vector editing
and real AVX/AVX-512/AMX/SME2 coverage also remain pending.

The stopped-function primitive now executes up to eight integer/pointer arguments
using native SysV AMD64, i386 cdecl and AAPCS64 conventions. Live x86-64, i386 and
ARM64 fixtures verify register and stack arguments, real scalar return values,
callee FP-register and signal-mask changes, complete context restoration, guarded
private stacks and reuse of the same frame. Completion requires the exact private
INT3/BRK opcode, PC, SP and kernel signal information. A genuine callee SIGSEGV and
an external SIGTRAP cannot become a successful return.

Timeouts retain the live callee and its owner; unexpected signals and ptrace events
require an explicit owner decision before continuing. Transient return-register
or opcode read failures retain the unclassified stop for retry. A timeout interrupt
racing an already queued return trap is drained in private code before restoring
the original context. Failed restoration retains both the verified return value
and the recovery ticket. A separate owned memory-syscall path releases private
frames using an existing Unix syscall instruction while siblings keep running.
Initialization faults, return-read faults, signal decisions, real interrupt races,
target exit and final console liveness are mandatory gate checks.

ARM64 calls restore live SVE and streaming-SVE/ZA at default and maximum vector
lengths, including deferred SVE/SME lengths verified through actual exec. Ordinary
AAPCS64 callees run with streaming mode disabled. Callees must not change vector
length configuration. The primitive rejects interrupted kernel syscalls before
mutation; arbitrary parked threads require a safe call adapter. Floating-point or
aggregate call arguments and mixed Windows/Unix call modes remain pending.

Library and pthread injection now use a shared native call owner on the existing
syscall-service thread. It reserves ownership before attachment and retains the
private code, guarded stack and payload across timeouts, failed restoration and
frontend destruction. Other operations cannot seize that retained thread.
Successful but unreturned pthread handles remain leased until actual join or
detachment, with orphan cleanup performed by the owner. Real x86-64/i386 and
ARM64 fixtures verify signal decisions, sibling progress, restored mapping lists
and original console liveness. Native libc fixtures additionally verify actual
constructors, symlink and cached library loads, actual kernel thread exit,
deadline detachment and subsequent completion. Wholly parked targets reject calls without creating
threads, retaining ownership or changing their original relative sleep's
completion. Lua resolves loader symbols when no external resolver is installed,
rejects embedded NUL paths and overflowing timeouts, and reports an actual thread
timeout instead of claiming completion.

The native high-level call capability remains partial. Call selection needs an
eligible user-mode thread; arbitrary parked threads and calls made while the
selected thread holds runtime/application locks need a rendezvous or worker
adapter. Native pthread workers now enter through a target-ABI wrapper which
publishes its Linux TID before user code starts. The owner detaches the handle
before releasing that wrapper and pins storage until actual kernel exit,
including self-detachment and `pthread_exit`. A late, unreturned worker is
cancelled before user code starts. Auto-assembler rollback and disable retain
allocations, original patches and protection records while any such worker is
alive; memory unmap/protection operations reject overlapping live leases.
Private wrappers belonging to an exited worker remain retained if no eligible
application thread can reclaim them safely. Engine process shutdown leaves
fully detached workers and their target mappings alive, allowing them to return
without waiting for their former owner. The target kernel reclaims those
mappings when the target exits. Failed ptrace restoration still requires owner
recovery before shutdown. Arbitrary caller data, secondary
threads spawned by the function and accesses performed outside the engine still
require caller-managed lifetimes. Nonleader exec routing, kernel restart-block timing,
additional libc/runtime variants and whole-application runtime coverage remain
unfinished.
Wine loader/thread initialization still requires its own backend.

Hardware breakpoint operations select ARM64 execution and watchpoint regsets,
query the kernel slot counts, validate byte ranges, preserve other slots and verify
updates. Failed updates restore the original state or report `state_not_recoverable`
while the caller still owns the stop. Live fault checks exercise both restoration
and explicit saved-bank recovery. DebugSession retains failed cleanup on its owner
through caller destruction; failures remain visible to GUI/Lua breakpoint removal,
and Lua's target info and retry API include session recovery. Additional hardware
cleanup fault/destruction scenarios remain required. ARM64 guest watchpoint traps occur at
the store before its value update, unlike the tested x86 post-store traps; tests
verify the watched address and completion after stepping with the watchpoint removed.

Software-breakpoint primitives use INT3 for x86, BRK for ARM64 and mode-specific
UDF traps for ARM/Thumb, preserve adjacent
bytes through aligned ptrace word writes and verify installation/restoration. Failed
verification and restoration retain the original bytes in an explicit recovery
record. The live suite verifies trap PC semantics, exact cleanup, instruction
execution after restoration, repeated attach/detach and final target liveness.
The full native DebugSession also has a live final-page-byte breakpoint regression;
its byte patcher now aligns the ptrace word so an unmapped next page cannot break
installation or cleanup.
ARM64 ptrace writes to executable mappings use the kernel's instruction-cache
synchronization path ([Linux implementation](https://github.com/torvalds/linux/blob/v6.18/arch/arm64/mm/flush.c)).
These tests validate that path, not cache handling for future process_vm-based caves.
Frame-chain walking now uses register-bank PC/SP/FP and the target byte order;
model checks include ARM64 BE data and x32's 64-bit saved-register slots with 32-bit
pointers. General DWARF/runtime unwinding and ARM64 pointer-authentication handling
still need coverage.

The syscall planner also checks x32's number bit, pointer/length width and 64-bit
file offsets, Linux-vs-Windows ABI selection, and ARM/Thumb instruction byte order.
The separate x32 kernel fixtures below exercise its native execution. ARM32
planner checks still lack live execution coverage.

The ARM64 gate requires cross GCC/G++, CMake, Python 3, curl and `qemu-system-aarch64`.
`tools/check-arm64-vm.sh` verifies a pinned Alpine guest-kernel SHA256 before boot.
It also verifies and cross-builds the same pinned Capstone source as cecore for
real target-ISA decoding in the session tests.
`test/fullsystem_vm.py` verifies the actual guest machine, target ABI, operation
results and success marker. It preserves timeout/failure logs and a JSON report
containing kernel and binary hashes. `CECORE_REQUIRE_ARM64_VM=1` adds this gate to
local `tools/ci-check.sh`; missing inputs fail the requested gate.

The same script also builds the shared AArch64 relocation backend into a
separate static Linux execution fixture. `test/aarch64_relocation_gate.py`
requires 21 checks and 1,119 original/relocated code executions on each page-size
profile using one vCPU and 128 MiB. GNU-assembled source code is mapped one GiB
from its relocated destination, with W^X transitions and explicit instruction
cache synchronization. Tests cover ADR/ADRP, integer and SIMD literals,
prefetch/zero-register loads, internal forward/backward branches, far calls,
all sixteen NZCV condition predicates, register widths and high tested bits.
Mutable literal data remains live at its original address; flags, return links,
original code/data restoration and mapping cleanup are verified. The
[relocation snapshot](compatibility-evidence/aarch64-relocation.json) records
both kernels, 182 normal/sanitizer model checks and the exact source/driver
hashes. A standalone before/after probe reproduces a successful script with
a stale forward-label reference, then verifies rejection and complete rollback
with the same probe executable.

The byte-level backend reserves deterministic expanded slots and maps static
branches into the relocated block. ADR/literal references retain original
addresses. Far vector/zero-register literals and jumps require an explicitly
permitted scratch register; indirect branches require the caller to establish
compatible landing sites. Auto Assembler REASSEMBLE uses the conservative
default policy and exact expanded sizes, and rolls back earlier writes when
the source cannot be reassembled or changes output size after label sizing.
Same-size updates remain usable; variable-length x86 reassembly uses the same
size-change guard. Execution is verified in owned mappings. Native hook
installation, hardware cache validation and other ISA backends remain required
work. The later executable-memory checkpoint below adds a native RX-page adapter.

The operation logs are saved in [compatibility-evidence](compatibility-evidence/).
They prove the listed fixture operations for these environments, not all
Wine/Proton programs.

`.github/workflows/wine-compatibility.yml` defines required legacy Wine32 and
64-bit-loader WoW64 jobs. Both build the same source revision, run real operation
checks and upload JSON evidence. Build CI calls these jobs; release packaging
waits for them and attaches their evidence. A loader of the wrong width fails the
required job. These remote jobs are configured but have not yet been executed for
this change. `.github/workflows/arm64-compatibility.yml` also blocks packaging on
the full-system process API, actual debugger session and instruction tracer,
native debug primitives and syscall/breakpoint recovery suite. Trace, hardware and
software CodeFinder, stopped-syscall, shared-code syscall, real policy-denial and
watchpoint-signal success markers are
mandatory in native and ARM64 gates. Native x86 gates also require the actual
syscall-user-dispatch result marker. Wine gates require busy memory-operation
markers for both Windows program ABIs and record core/driver/assembler/fixture hashes.
Native syscall reports and
ARM64 guest memory/debug reports are attached to releases with the Wine evidence. Proton and
broader foreign-architecture release gates remain required work.

Cleanup faults are injected separately: failed/short restoration writes must retain
recovery state and keep caves allocated, failed deallocation must be reported, and
retry must complete cleanup. A failed enable path must run the same cleanup routine.
Additional recovery work must include CLI/Lua persistence, interrupted remote
threads, target identity changes during operations, and transport failures.
Native cleanup now checks task birth independently of executable metadata.
An unavailable executable image retains prepared restoration and an unreturned
allocation for retry; preflight cleanup can release an unmodified task without
that image metadata. Tests also verify a stale caller birth cannot redirect
cleanup away from the task actually seized. Concurrent handle metadata and
inspection callbacks query the owner before locking handle metadata, avoiding
lock inversion. These checks do not establish safe recovery after a nonleader
exec changes its visible task ID.
Transient syscalls return unsupported if no suitable Unix instruction is found;
private or shared code is never patched as a fallback while siblings run. Busy
WoW64 compat code in an ELF64 loader has a native-host ABI adapter and busy fixture.
Additional syscall-user-dispatch modes, early stop/exec/signal races and unknown
syscall-completion events need additional recovery tests.
Software-watchpoint scratch cleanup before attachment also needs a retained
memory-image identity so exec cannot redirect its fallback deallocation into a
replacement image. The verified all-stopped software cleanup path already frees
its scratch page before releasing ownership.

## External constraints

Kernel security settings can prohibit debugger attachment. Report these separately
from missing architecture backends. See the [Linux Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html).

Emulator guest state needs an emulator interface or a guest agent. Host CPU registers
and host watchpoints cannot be presented as guest registers or guest writers. QEMU
watchpoint support depends on its execution backend; TCG user-mode emulation does
not provide watchpoints. See [QEMU's debugger documentation](https://www.qemu.org/docs/master/system/gdb.html).

PE architecture identifiers and hybrid Windows formats follow the
[Microsoft PE specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).

### Native executable-memory writes

`ProcessHandle::writeCode` distinguishes code edits from ordinary data writes.
The native Linux adapter opens a descriptor against the original address space,
saves original bytes before mutation, verifies the complete transfer, and keeps
failed restoration owned by the shared native service. Pending recovery blocks
new native memory mutators until restoration succeeds or the original mm retires.
Recovery uses that descriptor rather than reopening a numeric PID after exec.

Linux writes through `/proc/<tid>/mem` reach `copy_to_user_page`; the
[ARM64 kernel implementation](https://github.com/torvalds/linux/blob/v6.8/arch/arm64/mm/flush.c)
performs instruction-cache synchronization for executable VMAs. The native ARM64
code adapter requires the complete destination range to be executable. Generic
native ARM64 writes that overlap executable memory also use this path. Native
x86 writes use it as a fallback for RX pages. Neither path changes page permissions
or target registers. Kernel proc-mem access policy remains authoritative, and
permission failures return an operation error.

Dedicated tests warm and execute original code, patch a two-page RX range, execute
the replacement, and restore exact original execution and neighboring bytes.
They also edit while another debugger owner holds an actual all-stop, verify its
register bank and original syscall restart, exercise self-code writes and force
short/dropped/post-mutation failures. A blocked undo retains a recovery record;
protection changes remain blocked until successful retry. An actual same-file
exec verifies that the old descriptor retires without replaying old bytes into
the new image. Host checks include production Auto Assembler, Lua and CLI; guest
checks compile the actual native backend but exclude Auto Assembler and Lua.

The caller still coordinates thread execution and mapping lifetime for edits
spanning multiple instructions. Cache synchronization does not make those edits
atomic. This checkpoint does not establish native ARM64 hook installation,
non-executable emission followed by permission transitions, hardware instruction
caches, all proc-mem policy configurations or remote/other-ISA cache adapters.
Saved frontend undo records across arbitrary mapping replacement need further
lifecycle validation.

The [executable-memory snapshot](compatibility-evidence/code-write.json) records
30 host backend plus five production CLI/Lua checks in normal and sanitizer
builds, 27 checks on each ARM64 page-size profile, and 192 model checks per host
build. It also retains fresh existing 881/722-check kernel suites and both
1,119-execution relocation suites. The required kernel workflow runs each guest
sequentially; the new code-write guest uses one CPU and 128 MiB. Native ARM64
frontend code-write checks are configured as a release prerequisite, with remote
execution for this worktree still pending.

### Saved operation ownership

Saved native Auto Assembler operations and x86 simple hooks now keep the original
memory descriptor through disable/removal. A live reproduction first patches a
function from 42 to 17, then replaces the process with the same executable whose
function returns 55. Before the fix, disable succeeds but restores 42 into the
replacement. The final binary leaves 55 intact and discards the retired patch,
allocation, protection and symbol records. Using saved native undo with another
PID fails before cleanup. Native loader/pthread requests carrying a script's saved
image check it before execution, including after the selected thread stops.

Undo copies share completion state. Allocation leases also share release state
across explicit DEALLOC, saved patches, and scripts which patch another script's
cave. Old cleanup cannot free or restore into recycled storage or remove symbols
owned by a later operation. Allocation records cover the actual rounded native
mapping. A failed same-script DEALLOC unlocks before rollback; adapter exceptions
after mutation still restore bytes and retain failed deallocations for retry.
Previously registered symbols remain address targets instead of being shadowed
by automatically declared local labels.

Before any undo mutation, instruction patches and external executable DB patches
must match one of the operation's saved byte states. Conflicting replacement code
fails with saved undo retained. Overlapping and partially restored owned states
remain recoverable. Typed storage, including pointer-capture slots inside
executable caves, may change at runtime and does not cause a false code conflict.
Native simple hooks preserve RX permissions and verify restoration; their caves
remain mapped because a target thread may still be inside a trampoline.

The [lifecycle snapshot](compatibility-evidence/undo-lifecycle.json) records
205 normal and sanitizer model checks, 40 host backend plus five production
CLI/Lua checks in each build, full host CI including GUI/GDB/Wine checks, and the
before/after reproduction. Fresh ARM64 backend checks pass under both pinned
kernels: 27 executable-memory checks, 881/722 existing kernel checks, and
21 relocation checks with 1,119 executions per profile. These guest drivers
exclude Auto Assembler, Lua and simple-hook installation; new ARM64 frontend
lifecycle execution remains pending. Builds used one compiler at low priority,
and heavier builds, Wine checks and guests ran sequentially.

This checkpoint does not establish universal mapping identity or atomic hot-hook
installation. An anonymous mapping replaced with identical layout and bytes
cannot be distinguished by the saved byte states. Callers still coordinate
mapping and execution lifetimes. If another process keeps an old address space
alive through CLONE_VM, descriptor liveness alone does not prove that subsequent
numeric-PID syscalls or calls target that same image. A live fixture reproduced
allocation, protection and free requests affecting a same-file replacement while
the old descriptor remained readable. This follows Linux
[proc-mem descriptor handling](https://github.com/torvalds/linux/blob/v6.8/fs/proc/base.c#L748-L838)
and [CLONE_VM memory sharing](https://github.com/torvalds/linux/blob/v6.8/kernel/fork.c#L1608-L1642).
The affinity checks described below address these saved-image requests. Partial ranges crossing allocation ownership
boundaries, remote saved-undo affinity, native ARM64 hooks, hardware caches and
broader architectures/runtimes also remain unfinished. The goal remains active.

### Shared address-space affinity

Saved-image memory syscalls now hold the selected thread's ptrace stop, create a
fresh private anonymous page in its current address space, and test whether the
saved descriptor observes a temporary marker written through the current image's
descriptor. Only the unpublished private page is written; an old descriptor is
read-only during this check. Identical process IDs, executable files, mapping
layouts and bytes therefore do not establish affinity. The marker is restored
and the private page reclaimed before the requested mutation begins. Native
function calls use their freshly allocated private frame for the same check
before staging payloads or executing the function.

Incomplete proof cleanup retains its page and ptrace recovery on the original
owner. Nested syscall recovery is drained before outer cleanup. A completed
private probe allocation is never reported as completion of the caller's
requested operation. Short, dropped, ambiguous and blocked marker writes must
leave caller mappings unchanged; a retained cleanup must also retire after the
selected task exits, even before its parent reaps it. Real application signals
received during nested proof syscalls are preserved through outer detach; a
denial SIGSYS caused by the engine's synthetic syscall is handled as a policy
error. Required host, sanitizer and ARM64 kernel gates exercise
these behaviors with a separate CLONE_VM process holding the old image across
same-file exec, including a replacement with identical code and data bytes.

The [shared-memory snapshot](compatibility-evidence/mm-affinity.json) records
42 affinity checks in each normal, sanitizer and ARM64 page-size profile. It
also includes current host CI with GUI/GDB/Wine checks, 40 backend plus five
CLI/Lua executable-memory checks in each host build, 27 executable-memory checks
per ARM64 profile, 884/725 broader kernel checks and 1,119 relocation executions
per profile. A direct private-page test confirms that two distinct images with
identical bytes at the same address do not pass the alias check, and verifies
that both original pages remain unchanged. The before/after reproduction uses
the preserved library from the preceding lifecycle snapshot.

The initial host CI failed once when a GUI lifecycle fixture died with SIGTRAP.
Five current-library and five preceding-library repetitions, followed by final
host CI, passed. The snapshot retains those original observations. A follow-up
reproduced a CodeFinder teardown race that can produce this failure; see
[queued hardware-trap cleanup](#queued-hardware-trap-cleanup).

This check requires permission to allocate and reclaim a temporary anonymous
mapping for saved-image syscalls, in addition to access to proc-mem and ptrace.
Kernel policy or address-space exhaustion may refuse a safe operation. Native
calls reuse their existing frame. Callers still coordinate execution and mapping
lifetimes; this does not prove safety against arbitrary concurrent sibling exec
or in-place anonymous mapping reuse. Retained native-call cleanup has the
additional checks below. Broader lifecycle races and remote ownership remain pending.

## Retained native-call cleanup

A retained worker's original memory descriptor can stay readable after exec
when an independent CLONE_VM process keeps the old address space alive. A live
reproduction copied the entire old call frame into an identical mapping in the
same-file replacement. Before the fix, recovery reported success and unmapped
that replacement frame. Executable metadata, descriptor liveness and matching
bytes were insufficient to establish ownership.

Native call records now retain their original descriptor separately from the
descriptor opened for a newly selected cleanup thread. While owning that thread's
actual ptrace stop, cleanup checks address-space affinity using a fresh private
page before replacing its descriptor or touching retained storage. A changed
image retires the record without unmapping replacement storage or calling
pthread_detach on an old handle in the replacement. This also covers plain
pthread leases whose original call frame was already reclaimed.

A failed proof keeps the ptrace owner and private-page recovery. Finishing that
recovery does not establish the original call's affinity: the original check is
repeated before cleanup can continue. Live fault cases block proof restoration
and then retry both ordinary worker cleanup and cleanup after exec. Worker
return needs no repeated writes to its control fields; ownership remains until
actual kernel thread exit.

The required regression driver exercises real pthreads and an independent
CLONE_VM peer. It verifies exact replacement bytes and permissions, original
frame reclamation, failed-cleanup retry, abandoned-handle affinity, application
responsiveness and normal final exit. Fixtures use large-file proc-mem offsets
for high i386 addresses. If replacement-loader ASLR occupies the old frame's
address, the fixture retries its own exec within a fixed bound; it never replaces
loader mappings to manufacture an identical frame.

The [retained-call snapshot](compatibility-evidence/native-call-image.json)
records 83 checks per native x86-64/i386 ABI in normal and sanitizer builds,
and 83 under each pinned ARM64 kernel page-size profile. It also records current
native libc/pthread injection checks and 205 model checks per host build, plus
the preserved before/after reproduction. ARM64 guests used one CPU and 128 MiB;
builds used one compiler at reduced priority and ran sequentially. Required CI
and release gates include these checks; remote workflow execution remains pending.

This checkpoint does not certify arbitrary concurrent sibling exec, nonleader
exec during a retained function, or transferring old-image cleanup to an
independent CLONE_VM process. Retired storage in that old image remains until its
remaining users exit. The private proof requires writable proc-mem access and
permission to allocate and reclaim its temporary page. A denied proof retains
cleanup for retry instead of operating on unverified memory. General read-only
proc-mem recovery adapters and remote ownership remain pending.

## Native callee exec

A native callee can exec the same file while an independent CLONE_VM process
keeps its original address space alive. A real fixture reproduced cleanup
attempting to write the replacement's GP registers for a stale-frame syscall.
Blocking those writes left the replacement frozen. A call resumed after a genuine
SIGUSR1 also kept its old owner instead of releasing the replacement's exec stop.
The kernel's [ptrace exec notification](https://man7.org/linux/man-pages/man2/ptrace.2.html)
is authoritative even when process and executable metadata remain identical.

The stopped-function backend now reports its actual EXEC event and permanently
marks the saved context retired. The native call owner retires its frame and
resource records before any further memory syscall or function execution.
Explicit signal resume and automatic signal forwarding inspect the same retained
ticket, including after recovery has completed. A failed detach retains the actual
replacement stop; retry releases it without replaying old context. Retired tickets
reject image checks and function resume even when their original descriptor is
still readable. Completed recovery remains idempotent.

The regression driver executes real same-file execs through the production call
owner and through a direct borrowed stopped-function recovery. It observes actual
kernel EXEC reports before rejecting subsequent GP register writes. Separate
cases cover immediate exec, explicit signal suppression, automatic signal delivery,
failed detach and retry, retired ticket APIs, replacement console work and normal
exit of both the replacement and its old-mm peer. No kernel wait status or signal
information is fabricated.

The [callee-exec snapshot](compatibility-evidence/native-callee-exec.json) records
59 checks per native x86-64/i386 ABI in normal and sanitizer builds, and 59 under
each ARM64 page-size profile. Current runs also pass all 83 retained-call checks
per profile, 566/567 broader native checks per host build, 205 model checks per
host build, native libc/pthread injection checks, and 906/747 broader ARM64 checks.
Focused guests use one CPU and 128 MiB; full concurrency guests use two CPUs and
256 MiB. Builds and guests ran sequentially at reduced priority.

The snapshot retains a full ARM64 run with one CPU that failed to observe two
required queued-watchpoint races within the coordinator's bound. Its dependent
SIGUSR1 assertion also failed: the coordinator only sends that application signal
after observing the race. The same binary passes the full suite with two CPUs.
This does not establish a product failure or reliable race forcing on every
single-CPU kernel. Required remote CI and release execution remains pending.

These cases use TRACEEXEC on the actual selected leader. Generic borrowed calls
without that option, additional thread-group lifecycles and unrelated
concurrent sibling exec and transferring old-mm cleanup to a separate CLONE_VM
process need additional coverage. Current private-page affinity checks still
require their stated proc-mem and mapping permissions. Broad managed-runtime,
foreign-architecture and remote compatibility remains unfinished.

## Native nonleader callee exec

The earlier callee-exec tests selected a live leader. A new fixture parks the
leader in its original stdin read and supplies a busy application pthread. Its
native callee executes the same file while an independent CLONE_VM process keeps
the old address space alive. The original backend misses the EXEC notification
under the group leader's TID and leaves the replacement stopped. The initial
native x86-64 reproduction failed 26 of 46 checks.

Stopped-function recovery now saves the original group leader and birth. It
peeks that group's actual EXEC notification without consuming other child stops,
then consumes and retains the real status before inspecting GETEVENTMSG. Linux
[rejects ptrace inspection of a changed TID until its EXEC event is consumed](https://raw.githubusercontent.com/torvalds/linux/v6.8/kernel/ptrace.c).
A failed former-TID inspection keeps the stop owned for retry; saved-image checks
reject that consumed exec while the handoff remains pending. Successful recovery
reports the replacement TID and birth to its borrowed caller. The native call
owner adopts that actual stop before detaching, clears obsolete signal state and
never attempts a syscall or register restoration from the old call frame.

The required callee-exec driver now covers leader and nonleader immediate exec,
explicit signal suppression, automatic signal forwarding, failed detach/retry,
direct borrowed recovery and failed former-TID inspection/retry. The nonleader
cases inspect the kernel's real former-TID message and read the live independent
old-mm peer. No wait status, siginfo or event message is fabricated. Replacement
console work and normal shutdown verify that the handed-off stop was released.

The [thread-exec snapshot](compatibility-evidence/native-thread-exec.json) records
136 checks per x86-64/i386 ABI in normal and sanitizer builds and under each
ARM64 4/64 KiB kernel. The same production sources also pass all 83 retained-call
checks per profile, 566/567 broader native checks per host build, 205 model
checks per host build, native libc/pthread injection, and 906/747 broader ARM64
checks. Builds use one job and reduced priority. Focused guests use one CPU and
128 MiB; full concurrency guests use two CPUs and 256 MiB, all run sequentially.
The preserved baseline uses the original core, backend sources and a byte-for-byte
reconstructed original header whose hashes match the earlier callee-exec snapshot.
With only the unavailable replacement-task API assertion removed from the expanded
thread driver, that backend fails 32 of 55 reached checks; missing replacement
readiness skips the dependent liveness assertions. The current full gate requires
all 136 checks. Remote CI and release execution remains pending.

This closes the selected live nonleader callee case. An already-exited leader, unrelated sibling exec,
multiple borrowed contexts in one group need further integration coverage; generic calls without TRACEEXEC, old-mm cleanup transfer,
foreign architectures, managed runtimes and remote compatibility remain pending.

## Native pthread cleanup callees

Pthread-handle cleanup makes another native call after creation succeeds. Its
callee can execute exec or receive a real application signal. A wrapped-worker
fixture reproduced the old startup path consuming EXEC but retaining the old
resource owner and leaving the replacement stopped. A plain handle lease exposed
a second bug: after its callee stopped on SIGUSR1, public resume searched only
active calls and rejected the stopped lease. Neither case released the replacement
or original application context.

Worker startup now retires its call on the callee's actual EXEC event or retained
ticket retirement, adopting the replacement TID and birth before detach. Primary
calls, startup detachers and abandoned-handle detachers share the same bounded
signal-forwarding helper. Explicit resume also finds retained function recoveries
in leases for the original process and birth. Normal returning detachers finish
restoration and cleanup; exec detachers cancel the old operation and retire its
private storage without calling into the replacement.

The required driver covers wrapped workers and abandoned ordinary pthread handles
on leaders and nonleaders. Each path exercises immediate exec, explicit signal
resume, automatic signal forwarding, failed detach/retry and failed former-TID
inspection/retry. Wrapped-worker replacements also copy the original private
frame at its old address while a separate CLONE_VM peer keeps the old mm alive.
Four additional cases deliver or suppress real SIGUSR1 in a returning libc
pthread detacher, verify it executes exactly once, and exercise the restored
program's own loop, worker release and normal exit. Wait statuses, signals and
exec event messages come from the actual kernel.

The initial failed reproduction also revealed that the fixture destructor could
wait for the killed leader while its traced sibling exit was unreaped. The fixture
now drains only its known selected sibling and leader with bounded waits. A fresh
baseline using the original core and backend with that corrected fixture fails
12 of 37 reached checks and exits normally with status 1. The same four cases
pass all 49 checks after the production fix; replacement readiness adds the
previously unreachable liveness assertions.

The [pthread-cleanup snapshot](compatibility-evidence/native-pthread-cleanup.json)
records all 395 required checks per native x86-64/i386 ABI in normal and
sanitizer builds and under both ARM64 4/64 KiB kernels. Current sources also pass
all 83 retained-call checks per profile, 566/567 broader native checks per host
build, 205 model checks per host build, native libc/pthread injection and 906/747
broader ARM64 checks. Builds and guests ran sequentially at reduced priority,
with one build job. Focused guests used one CPU and 128 MiB; the broader
concurrency guests used two CPUs and 256 MiB. An already-exited leader, unrelated
sibling exec, multiple borrowed contexts in one group and old-mm cleanup transfer
still need additional integration coverage. Calls without TRACEEXEC, other ISAs,
managed runtimes and remote transports remain unfinished; required remote CI and
release execution remains pending.

## Independently released pthread leases

A handle can be detached by the target while its abandoned-handle cleanup callee
still owns a genuine signal stop. `ThreadLease` copies share their release
notification independently of the returned lease object's lifetime. A fixture
parks the leader in its original stdin read, starts cleanup on an application
pthread and stops that callee on SIGUSR1. The target leader then detaches the
actual created pthread and reports libc success before the copied notification
calls `release()`.

The old process and global recovery paths erased that released lease immediately.
Pending queries hid it, and explicit resume could no longer find its recovery,
although ptrace still reported the real SIGUSR1 delivery stop. The baseline fails
six of nineteen reached checks across those two recovery paths.

Handle release now marks the orphan handle handled while retaining all owned
ptrace relationships, recovery tickets, private frames and pending affinity
cleanup. Process and global recovery share the same lease maintenance helper.
Pending queries include these resources even after release. A stopped cleanup
callee still requires the owner's normal signal decision; completed restoration,
unmap and detach precede erasure. A failed detach keeps the released lease
retryable. Exec retirement still reports cancellation after the replacement stop
has been released. A released lease with no cleanup resources keeps its immediate
forgetting path and does not invoke another target function.

The driver verifies process and global recovery, failed-detach retry through each,
release before cleanup starts, and exec after independent release. Returning
cases read the actual libc EINVAL result and count one cleanup invocation. The
created worker remains live until the interrupted detacher returns; this fixture
does not prove safety for a concurrently destroyed pthread descriptor after join.
The selected original loop, target-controlled worker release and normal exit
check recovery liveness. Exec cases also verify replacement console work with
its independent original-mm peer still readable. No kernel wait status, signal
information or exec message is invented.

The [released-lease snapshot](compatibility-evidence/released-pthread-leases.json)
records all 475 required call/cleanup checks per x86-64/i386 ABI in normal and
sanitizer builds and under both ARM64 4/64 KiB kernels. Current production sources
also pass 83 retained-call checks per profile, 566/567 broader native checks per
host build, 205 model checks per host build, native libc/pthread injection, and
906/747 broader ARM64 checks. Builds use one job; heavy jobs run sequentially at
reduced priority. Focused guests use one CPU and 128 MiB, and full concurrency
guests use two CPUs and 256 MiB. The snapshot pins the original core and embedded
backend, whose hashes match the earlier pthread-cleanup snapshot. Replaying that
baseline explicitly binds its original shared library and again fails six of
nineteen checks; the same two cases pass 29 after the fix, including ten previously
unreachable liveness assertions. Broader handle-lifetime coordination,
already-exited leaders, unrelated sibling exec, multiple borrowed contexts in
one group, cleanup transfer to another old-mm process, calls without TRACEEXEC,
other architectures, managed runtimes and remote transports remain pending.
Required remote CI and release execution remains pending.

## Linux x32 execution

An LP64 engine now runs native calls against actual ELF32 `EM_X86_64` programs
under a Debian Linux 6.1.0-50-amd64 guest with `syscall.x32=y`. These are x32
programs executing in long mode, with four-byte pointers and pthread handles;
no i386 fixture or user-mode syscall emulator substitutes for that ABI.
The host kernel remains unchanged. Linux's
[x32 kernel configuration](https://raw.githubusercontent.com/torvalds/linux/v6.8/arch/x86/Kconfig)
separates this ABI from ordinary i386 execution.

The backend now accepts x32 library/pthread operations and uses a dedicated
worker entry. Its control fields and indirect callback pointer are four bytes,
while its return stack and nanosleep timespec use the required 64-bit layouts.
Its syscall numbers carry x32's number bit. Native integer calls preserve
64-bit arguments in all six register and two stack slots, together with the
full 64-bit return value. Function/code/stack addresses still must fit x32
pointers. The memory syscall planner also preserves the 64-bit file offset
for x32 mmap without widening pointer or length types. A real sparse-file test
first reproduced rejection of an offset above four GiB, then read the exact
sentinel through the corrected mapping and released it normally.

Call fixtures now publish a separate user-loop flag after their output syscall
returns. The tests wait for that flag before borrowing a user context. This
removes a timing assumption exposed by the one-CPU KVM guest: a flushed ready
message alone could leave its writer in an ineligible kernel syscall. The
parked-call fixture continues to require that actual timed kernel waits are
rejected without restarting or shortening them.

The [x32 execution snapshot](compatibility-evidence/linux-x32.json) records
40 native libc/library/pthread and wide-ABI checks, 83 retained-image checks,
and 475 callee-exec/cleanup checks, all passing under both KVM and software
CPU emulation. The drivers are ELF64 x86-64, and all target programs and runtime
libraries are verified ELF32 x86-64. Reports pin the guest kernel, loader,
libc, unwind runtime, drivers, fixtures and complete output. The syscall offset
reproduction retains both its failed pre-fix report and the passing result.
Current native and sanitizer x86-64/i386 and ARM64 4/64 KiB regressions are
recorded alongside those reports.

The separate [x32 debugger snapshot](compatibility-evidence/linux-x32-debug.json)
records 551 checks passing under both KVM and software emulation: real debugger
sessions and register editing, stepping, tracing, hardware/software CodeFinder
watchpoints, queued-trap cleanup, leader/thread exit and native syscall/call
recovery. Its freestanding ELF32 x86-64 fixture uses actual x32 syscall numbers,
including the ABI's separate execve entry. Test instruction decoding and SIMD
register selection use the execution architecture independently of pointer width.

Linux 6.1 implements syscall-user-dispatch but lacks the ptrace request that
exports its configuration. The explicitly selected legacy profile verifies that
the request is unavailable, a real allowing selector permits memory operations,
and a blocked selector denies them without inventing an allocation or delivering
the synthetic SIGSYS. Both targets preserve their selector and resume console
work. Exact native-range introspection remains covered by the existing native
x86-64/i386 tests on the newer host kernel; that interface still needs a newer
x32 guest. See Linux's [6.1 ptrace implementation](https://raw.githubusercontent.com/torvalds/linux/v6.1/kernel/ptrace.c)
and [dispatch implementation](https://raw.githubusercontent.com/torvalds/linux/v6.1/kernel/entry/syscall_user_dispatch.c).
Fresh native and sanitizer regressions pass 566 x86-64 and 567 i386 checks each.

`tools/check-x32-vm.sh` reproduces the gate with a prebuilt, hash-verified Debian
kernel and the same pinned Capstone revision as the engine. It needs GCC/G++,
x32 multilib/glibc/unwind libraries, CMake, binutils, curl, Python, dpkg-deb,
and `qemu-system-x86_64`. It verifies the worker bytecode against its assembly,
builds the engine with one job and boots each guest sequentially with 128 MiB.
Calls, image and exec guests use one CPU; the debugger guest uses two to exercise
actual queued hardware-trap races. The snapshot preserves the original one-CPU
race-setup failures and the passing two-CPU baseline. The sibling-progress test
now initializes both samples equally and waits for actual progress instead of
assuming that a single one-millisecond sleep was sufficient. Software CPU
emulation is the default; an available KVM setup can
use `CECORE_X32_ACCEL=kvm`. The x32 workflow is required before future release
packaging, and its JSON reports and complete logs are included in release assets.
Remote workflow/release execution remains pending.

This validates an LP64 engine operating on the tested x32 fixtures. Complete
x32 GUI/CLI/Lua, general unwinding, newer-kernel dispatch introspection, other libc/kernel
combinations and an engine itself compiled for x32 still need live coverage.
The broader six-area compatibility objective remains incomplete.

## Queued hardware-trap cleanup

A hardware watchpoint can queue its synchronous SIGTRAP immediately before
PTRACE_INTERRUPT produces an interrupt stop. The old CodeFinder cleanup checked
only the current stop, restored the original debug bank and detached. Its own
queued signal then reached the application, potentially terminating it. A live
probe reproduced the failure and recorded TRAP_HWBKPT in the private signal queue
and the owned slot in DR6 before restoration.

Cleanup now checks the real pending signal queue while the watchpoint and its
status remain available for attribution. It advances an owned synchronous trap
to its actual delivery stop and suppresses it before restoring the original bank
and detaching. Application signals retain their signal information. Ownership
uses the engine's x86 debug-slot status or ARM64 watched range. Read, resume and restoration
failures keep the ptrace owner for recovery.

The integration test coordinates real CONT, INTERRUPT and wait operations until
the kernel exposes the queued-trap race. It does not fabricate wait statuses or
signal information, and fails if it cannot observe the race within its bounded
attempts. Separate targets verify normal computation and console work, genuine
SIGUSR1 termination, and SIGSTOP followed by application SIGCONT. The surviving
targets also verify complete restoration of the original hardware bank.

The [queued-trap snapshot](compatibility-evidence/queued-trap.json) records the
pre-fix backend failing the same cases, five passing repetitions per x86 ABI in
both normal and sanitizer builds, and 300 repeated CodeFinder/DebugSession
attach/stop cycles. The stress run observes four actual queued hardware traps
being consumed without reaching the target. Required full suites pass 566/567
checks for native x86-64/i386 in each host build and 906/747 checks under the
4 KiB/64 KiB ARM64 kernels. Each kernel profile observes all three queue races.

The snapshot also retains two test failures encountered while extending the
gate: a coordinator waited for a new interrupt event from an already stopped
task, and two GUI lifecycle runs timed out after their printed scan-control checks.
The coordinator now resumes its own consumed stop before requesting a new
event. GUI edit-verification waits use a later Qt timer to process overdue
callbacks before fixture bytes are reused; unexpected save dialogs fail the
test explicitly. A stack captured from the passing final GUI run shows active
debugger symbol parsing; the earlier particular GUI timeouts remain unexplained
and are not claimed fixed. This does not certify every combination of external watchpoints,
signals, debugger owners, or real ARM64 hardware.

## Mono runtime requests

The [Mono runtime snapshot](compatibility-evidence/mono-runtime.json) records a
real Mono 6.8/SGen x86-64 fixture on the host and inside an Ubuntu 24.04 container
with distinct PID/mount namespaces. Each runs 61 C++ and production Lua checks,
plus fresh CLI/Lua injection from a staged custom library layout, partial-request
disconnect, invalid magic/command/length/parameter-count rejection, actual garbage
collection and normal application exit. Nine additional checks in each environment
use a test-only 1 KiB metadata cap to exercise overflow, repeated errors, subsequent
method resolution and normal exit without generating a large assembly. A separate
ASan/UBSan engine runs the same native matrix. The injected agent and native
fixture helper use the ordinary target ABI, as required for loading into an
unsanitized managed application.

A controlled baseline with the previous dissector and a correctly loaded symbol
resolver reproduces failed refresh, truncated long names and lost concurrent
method responses. The snapshot preserves those failures alongside the passing
replacement; its separate classification baseline records the blocked initial
injection.

A native Mono executable maps PE-format CIL assemblies whose filenames end in
`.exe`. The previous descriptor selected their PE32 machine as the program ABI
and classified them as Wine, incorrectly blocking native loader calls and
restricting debugging. Descriptions and the target profile now require a Wine
Unix loader/runtime instead of a command-line suffix. The actual Mono descriptor
retains its Linux x86-64/eight-byte ABI; real Wine 11 x64/WoW64 regressions remain
passing.

The previous dissector deleted a dump before every injection. Reopening the
already loaded library does not rerun its constructor, so a refresh could never
recreate that dump. Method lookups also shared request/response files, truncated
name fields to 255 bytes and used host PID/temporary paths for namespaced targets.
The agent now serves fresh dumps and exact method names through independent
framed Unix connections. The client verifies the actual peer PID, follows the
process's root and inner group PID, and translates bind-mounted agent paths only
when device/inode identity matches. Initial injection remains a native loader
operation; resident requests avoid repeated loader reference-count increments.

Runtime metadata and JIT compilation happen on a short-lived attached pthread.
Mono 6.x's public detach removes its managed thread while its low-level GC thread
record survives until pthread TLS teardown. An intermediate implementation that
parked that same pthread in socket I/O passed metadata checks but stalled the
target's real GC. The final implementation ends and joins the request pthread
before publishing its response. The fixture then performs actual collections,
keeps its pinned object and original field bytes, loads another assembly, obtains
its newly compiled method and exits normally with the listener still resident.
Mono-allocated field type names use `mono_free`, following the
[embedding API allocator contract](https://www.mono-project.com/docs/advanced/embedding/).

Metadata generation enforces the 64 MiB response cap while writing its buffer;
it stops enumerating on overflow and reports an error instead of a partial dump.
The previous late check could grow the target's heap before rejecting the response.
The production agent is installed alongside the engine and explicitly bundled
into AppImage builds. Lookup follows the actual loaded engine library's directory,
including custom and `lib64` layouts. The CLI gate runs outside the build tree
with its engine and agent in a custom directory. AppImage compilation now defaults
to one job; `CECORE_BUILD_JOBS` can override it.

The gate fails when Mono or its C# compiler is missing; native, sanitizer and
release workflows require it and retain the JSON report. Local CI can require it
with `CECORE_REQUIRE_MONO=1`. An existing container can be tested with
`--container`, `--container-runtime` and a source bind mount; the snapshot records
the exact invocation. Builds used cached dependencies, one compiler at low
priority and sequential runtimes. Only 7.9 MB of authenticated runtime/compiler
packages were extracted into owned test storage; no host runtime installation
or kernel build was needed. Remote workflow/release execution remains pending.

This establishes actual runtime metadata/JIT requests and pinned-object raw
access for the tested Mono profile. Moving-object handles, general object
enumeration, domain unload and concurrent runtime shutdown, managed breakpoints,
other Mono/Unity versions and architectures, broader GUI runtime testing, CoreCLR,
JVM, Go and V8 adapters remain incomplete. The six-area objective remains active.

## Embedded Mono loading and lifetime

The [embedded runtime snapshot](compatibility-evidence/mono-embedded.json) extends
the Mono evidence to an actual shared SGen runtime loaded with `RTLD_LOCAL` by
a native application. The original agent's global/executable symbol lookup
reported that the initialized root domain was unavailable. A controlled baseline
preserves that failure. The agent now discovers an already loaded provider through
its own handle with `RTLD_NOLOAD`, which
[does not load another library](https://man7.org/linux/man-pages/man3/dlopen.3.html).
It keeps the runtime's private visibility and borrows a reference only for the
request and its completed pthread teardown. API pointers are cleared before the
next request; the application can subsequently close and actually unmap Mono.

Each embedding profile runs 106 checks: the existing 70 metadata/JIT/GC/overflow
checks and four nine-check cleanup stages. The original native application first
calls the real `mono_jit_cleanup` and remains alive with its library mapped and
its runtime shutdown flag set. Requests return a shutdown error before entering
the retired runtime. The application then calls `dlclose`; its own `RTLD_NOLOAD`
probe proves that the runtime has unloaded. Repeated C++ and production Lua
requests return no layout or JIT address, and its native loop and normal final
exit still work. Both stages are tested after ordinary and bounded metadata
requests, on the host, in the PID/mount namespace and with ASan/UBSan clients.
Fresh standalone profiles still run 70 checks in those same environments.

Three additional socket fixtures verify process-handle ownership: invalidated
handles send neither metadata nor method requests to a reachable numeric PID,
and invalidation after connection stops dispatch before any request byte. All
three failed with the previous client. The corrected native and sanitizer
compatibility models each pass 210 checks. These are logical-handle/transport
contracts, not proof of real kernel PID recycling or every exit race.

The gate reads pipe bytes into its own bounded line buffer. This fixes a harness
failure where `TextIOWrapper.readline` prefetched a second marker while the next
selector poll waited for new FD data. The snapshot preserves that failed
observation separately from application failures. Required native, sanitizer,
release and enabled local Mono gates now run `--embedded` and require the shared
runtime package as well as Mono and its compiler. Only one additional 1.9 MB
authenticated package was extracted for local testing; builds remain cached,
single-job and low priority. Remote workflow execution remains pending.

This proves sequential cleanup and actual library unload for the tested Mono
6.8 x86-64 embedding. Concurrent cleanup during an in-flight runtime request,
child-domain unload, independently loaded linker namespaces, moving objects,
other Mono versions/architectures and full managed GUI/debugger coverage remain
incomplete. The full six-area objective remains active.

## CEServer target identity and TCP recovery

The [CEServer TCP snapshot](compatibility-evidence/ceserver.json) records actual
x86-64 and freestanding i386 Linux applications reached through the production
TCP server, client, process adapter and remote debugger. This is a loopback
integration profile; it does not establish operation across a separate host,
network namespace or upstream CEServer build.

The original implementation returned a PID as a handle and recreated a local
process object for each operation. Closing a handle did not revoke it, nonexistent
PIDs opened successfully, and every target reported x86-64. The server now retains
an independently closeable Linux process identity for each opened handle and
releases its handles when that connection ends. The architecture response follows
the actual target. A real x86-64 application execs a real i386 image under the same
PID; the same remote handle refreshes its program ISA, pointer width, typed reads
and expression dereferences. Legacy architecture responses do not describe the
remote Unix loader or managed/Wine runtime, so those fields remain unknown.
The legacy protocol does not provide a complete process-liveness query; the remote
`live` flag reflects connection ownership, while target exit returns no memory
bytes and an unknown architecture in this server.

Region replies previously sent engine enum ordinals and Linux rwx bits where the
[CEServer protocol](https://raw.githubusercontent.com/cheat-engine/cheat-engine/master/Cheat%20Engine/ceserver/ceserver.h)
expects CE memory types and Windows page protection values. Actual remote region
lists now match the target's mappings. Allocation honors its requested protection
instead of unconditionally creating executable writable memory. Single-region
queries and protection changes have handlers, and zero FREE/protection results
propagate as operation failures. Reads and writes crossing an inaccessible page
retain their exact transferred prefix; unread destination bytes remain unchanged.

Process and debugger owners capture the TCP connection generation. Reconnecting
the client cannot revive those owners, send their requests to a replacement handle,
or let their destructors close/detach a newly opened target with the same wire
handle number. Socket failures and malformed response lengths/counts retire the
connection before another command can consume remaining reply bytes. Nine
independent peers cover invalid read/write counts, regions, threads, module names,
contexts, symbol payloads and truncated framing.

Each native and ASan/UBSan run performs 143 checks. Actual software traps and
hardware write watchpoints fire in both applications; removal restores instruction
bytes and lets subsequent writes proceed. Closing a debug connection releases its
ptrace session before another client is served. Idle server shutdown is repeated
16 times; accepted descriptors stay owned by the serving thread while shutdown
wakes it, avoiding close/reuse races. A separate saved build fails 70 of these
143 checks, including remote ABI, protection, ownership, framing and breakpoint
lifetime cases. Both applications and the exec-transition application finish
normally in the corrected runs.

Native, sanitizer, release and x86-64 local CI now require the TCP gate and retain
its report before packaging. Tests use existing small target fixtures and cached,
single-job, low-priority builds. No additional runtime packages or kernels are
needed. Remote workflow execution is pending.

At this earlier checkpoint, network timeouts and concurrent client transactions
were pending; the next section records their subsequent fixes. Separate-host/namespace
targets, remote ARM/big-endian and x32 profiles, upstream interoperability, remote symbols, comprehensive remote
contexts/stepping/signal and thread semantics, remote managed/Wine metadata,
compressed transfers and GUI remote lifecycle coverage remain incomplete. The
full six-area objective remains active.

## CEServer transactions and cancellation

The [transaction snapshot](compatibility-evidence/ceserver-transactions.json)
extends the TCP evidence with complete command serialization, socket deadlines
and cancellation. Twenty-five client protocol commands share one recursive
transaction lock. Persistent process/debugger operations acquire that lock before
checking their connection generation, including opening and destruction. Four
simultaneous callers send 32 complete frames to an independent TCP peer and
receive their own distinct address-specific payloads. Reconnect tests queue an
old process owner and ARM32/ARM64 context owners behind a stalled request;
cancellation ends the old operation, and queued owners cannot dispatch onto either
the retired or replacement stream. The context-owner checks exercise connection
ownership, not actual ARM execution.

Socket transfers are nonblocking and use one steady-clock deadline for the entire
command. A peer cannot keep a command alive by trickling another header or payload
byte before each individual read. Silent replies, slowly fragmented replies,
partial payloads and outbound backpressure reach the configured budget and retire
the incomplete connection. Unread destination bytes remain unchanged. Explicit
debug-event waits add their requested wait duration to the transport budget, so a
legitimate wait longer than the ordinary budget still succeeds.

`close` marks the old generation retired and uses
[`shutdown`](https://man7.org/linux/man-pages/man2/shutdown.2.html) to wake socket
I/O before waiting for its transaction lock. It closes the descriptor only after
the operation releases ownership. Cancellation therefore cannot close a descriptor
that a reconnect has already reused. Nonblocking connect candidates share a
single socket deadline; cancellation is checked while polling them. System
hostname resolution remains a blocking resolver operation and is not proven to
finish within that deadline. Waiting for earlier queued operations is also outside
a command's own socket budget.

C++ callers can choose a positive budget with `CEServerClient::setTimeoutMs`.
Lua, GUI Lua console and CLI scripts can pass a fourth argument to
`connectToCeserver(host, port, pid, timeoutMs)`; the default is 5000 ms. Lua validates
port, PID and timeout ranges before connecting and preserves its original opened
process on failure. This also removes the previous silent integer truncation in
those arguments.

The required TCP gate now combines the original 143 actual-target checks with
30 connection checks in native and ASan/UBSan profiles. The preserved previous
client fails 17 of those 30 connection checks. A focused ThreadSanitizer build
instruments the actual client and 23 socket/cancellation/concurrency assertions
without rebuilding the full engine. It reproduces the previous socket close/receive
race and passes all 23 assertions with no reported race in the updated client.
The cached Ubuntu container provides its existing compiler/runtime; the host's optional TSan runtime is missing, so no host
package installation is needed. Native and sanitizer full-engine regressions and
frontend lifecycle evidence are recorded separately in the snapshot. The GUI
lifecycle run initially hit its 25-second alarm at the save-JSON stage; a diagnostic
run and a retry of the same command passed. The intermittent timeout has no
established root cause and remains pending.

Separate-host and namespace networking, blocking hostname resolution, bounded
queue admission/fairness, broad stress, concurrent server clients, full-engine
ThreadSanitizer coverage, remote ARM/x32/big-endian targets and upstream
interoperability remain pending, alongside the other debugger/runtime/GUI gaps.
The full six-area objective remains active.


## CEServer multi-client isolation and resource recovery

The [multi-client snapshot](compatibility-evidence/ceserver-multiclient.json)
records independent connections against the production server. An idle peer or a
peer that sends only part of a command no longer blocks another client's version
query, process open or actual memory read. Each connection owns its process
handles, debug session, event queue and breakpoint slots. Two real x86-64/i386
applications simultaneously retain ptrace owners and software traps even when
their connection-local handles have the same numeric value. Simultaneous waiters
receive only their own target's event. Disconnecting one client restores and
resumes its target while preserving the other client's stopped trap and owner.
The surviving debugger independently restores and resumes its application.

A new client can complete requests while another connection waits for a debug
event. Server shutdown wakes those event waiters together with idle sockets and
partially received commands, joins all connection workers and detaches their
targets. Event notification holds the queue mutex across shutdown notification
so the predicate-to-wait transition cannot lose the wakeup. Start and stop calls
serialize their complete ownership changes; the advertised port is atomic.
Eight cycles verify simultaneous start callers, four stop callers and subsequent
restart. A completion event wakes the accept owner to join and reclaim finished
workers even when no new connection arrives. The backlog uses the kernel's
`SOMAXCONN` instead of an arbitrary four-client application backlog.

The owned test process lowers its descriptor limit to at most 256, fills all
remaining descriptor slots and queues another TCP connection. Actual `EMFILE`
does not kill the accept owner or existing clients. Releasing one descriptor
allows that queued client to complete its handshake; cleanup restores the
process's original limit. No host limit, package or kernel is changed. Thread
creation and allocation failures close the affected newly accepted connection;
large-scale memory/thread exhaustion is not established by this descriptor test.

The required gate now checks 143 original actual-target assertions, 30 client
transaction assertions and 31 multi-client assertions in both native and
ASan/UBSan profiles (204 per profile). The retained previous server fails four
of ten idle/partial-peer assertions using the identical current source and
`--blocking-only`; this baseline deliberately isolates the original serialized
accept limitation. Native and sanitizer engine regressions are recorded along
with GUI observations. The initial GUI run after this rebuild hit the same
save-JSON-stage deadline as the preceding checkpoint. Three observations before
the server changes and nine subsequent observations passed, as did a fresh-build
retry and the final run with additional stage markers. No blocked stack was
obtained because diagnostic runs completed before capture. Stage markers now
distinguish return from the save action, saved-table parsing and the final next
scan. The intermittent timeout remains unresolved.

Separate-host/namespace networking, upstream interoperability, full-engine
ThreadSanitizer and large client/resource stress remain pending. Remote ISA and
full debugger/runtime/frontend gaps in the matrix also remain pending. The full
six-area objective remains active.


## Table persistence and GUI/core interchange

The [table persistence snapshot](compatibility-evidence/table-persistence.json)
records actual filesystem failures and table round trips. XML, JSON and protected
core saves now check flushing and closing instead of reporting success while a
buffered write has failed. The owned integration process temporarily lowers its
file-size limit, verifies all three failure results and restores its original
limit. GUI table saves use a staged `QSaveFile` with direct-write fallback
disabled; the same kernel write failures preserve the previous XML/JSON files,
leave the recent-table list unchanged, display an error and remove staged files.
Core path saves report errors but still write directly to the destination; they
do not provide the GUI's replacement guarantee.

The core reads the GUI's JSON field names and value-type names, including pointer
records, and translates GUI parent rows into stable parent IDs. XML nesting
retains a valid group ID of zero. GUI XML saves retain stable record IDs and
accept uppercase `.CT`. Loading and resaving retains imported game/version,
author, notes, table Lua, structure definitions and raw form metadata. Native
and protected JSON retain raw form metadata as well. GUI JSON retains its
additional codec settings. These checks establish preservation of stored
metadata, not execution of imported trainer forms or universal codec support
across every format.

JSON loads validate common record formats before replacing GUI rows or the
window title. Both core-native and GUI-native JSON table Lua require user
consent. A focused offscreen GUI test rejects a malformed pointer width without
replacing the current rows/title and declines Lua in both schemas. The original
scan-format lifecycle test continues to exercise the real Save menu and file
dialogue. The intermittent save-JSON-stage timeout recurred twice during this checkpoint.
An actual blocked stack places the GUI inside Qt's file chooser, before table
serialization; all other threads were waiting for events. Four subsequent
lifecycle observations passed, including all new table checks. Chooser diagnostics
now report the active widget, selected path and filter on a delayed run and can
save an optional diagnostic image. No further delayed run was captured with these
diagnostics, so the particular chooser stall remains unresolved. Fixing the
independently reproduced filesystem errors does not resolve that stall.

The preserved previous engine fails eight of the identical ten core assertions.
The persistence executable is required by native, ASan/UBSan, release and local
CI alongside existing engine regressions. Builds use cached dependencies and one
compiler job for local verification. This checkpoint does not complete the six
compatibility areas or establish compatibility with every Linux process.


## Exact JSON values and deterministic GUI saving checks

The [JSON and chooser snapshot](compatibility-evidence/table-json.json) records
33 core regression assertions and 384 independently computed decimal comparisons
in each native and ASan/UBSan profile. Numeric JSON addresses, structure sizes
and signed pointer offsets keep their complete integer values, including both
signed 64-bit endpoints and integral decimal/exponent notation. Conversion uses
the original decimal token and checked integer arithmetic, so it works without
assuming extended `long double` precision. Legacy integer strings retain their
hexadecimal/octal bases and signed offsets. Fractional or out-of-range integer
fields, negative lengths/sizes, unknown value/freeze types and malformed record
collections fail before replacing the current table.

Escaped Unicode retains exact UTF-8, including supplementary characters expressed
as surrogate pairs. Invalid escapes, unpaired surrogates, raw string control
bytes and malformed number grammar are rejected. JSON output escapes every
ASCII control byte. Duplicate object fields use the same last-value semantics as
Qt. The core parses into a temporary model and commits after all records validate.
GUI JSON loading captures one payload for both parsers, avoiding a second file
read and preserving exact common fields through the core conversion. Codecs and
presentation settings are retained; explicit group activation/deactivation flags
also survive native and GUI JSON round trips. GUI imports normalize duplicate or
missing IDs, preserve valid IDs including zero and `INT_MAX`, and allocate unused
positive IDs after wrapping without signed overflow. The focused GUI fixture
verifies escaped metadata, maximum numeric addresses, codecs, group flags,
failed-load preservation, ID allocation and the preceding filesystem-failure checks.

The intermittent Save-JSON deadline now has a reproduced explanation in the test
automation. The captured delayed run repeatedly selected the directory with an
empty filename field. Qt's visible, focused filename edit deliberately ignores
`selectFile()` text updates; see the
[Qt implementation](https://raw.githubusercontent.com/qt/qtbase/v6.11.2/src/widgets/dialogs/qfiledialog.cpp).
An owned Qt fixture deterministically reproduces that state and saves
[before](compatibility-evidence/gui-chooser-before.png) and
[after](compatibility-evidence/gui-chooser-after.png) screenshots. The automation
now selects the requested format, focuses and types the filename, verifies the
selected path, then queues acceptance. Both actual Save dialogues run with the
formerly failing focus state. A focused run and two complete lifecycle runs pass
without extending their deadlines. This resolves the identified automation stall;
it does not establish that every native desktop dialog/plugin is covered. The
preceding 15 focused and eight full observations passed without reproducing the
stall, illustrating why successful retries alone were insufficient. Historical
timeout records above remain unchanged.

The preserved previous engine fails 31 of the identical 33 regression assertions.
The required gate also verifies executable integer widths and exact native output
against Python decimal arithmetic. Separate negative checks verify failure reports
for a missing executable, incomplete check count, invalid integer profile, old
round-trip precision loss and an actual deadline with retained partial output.
Native/sanitizer/release/local CI require this gate; both profile reports are
uploaded with compatibility evidence. Native and sanitizer engine regressions
and current GUI lifecycle results are archived separately. This checkpoint does
not complete the six-area compatibility objective.

## GUI record injection ownership and cleanup

The [GUI injection snapshot](compatibility-evidence/gui-injection.json) records
78 required assertions on each real x86-64 and i386 child process. The tests
observe patched executable bytes and data, discover the injected allocation
through a target-width pointer, then require exact byte restoration and removal
of the mapping. Both original applications observe their restored data and exit
normally. These are owned native processes, rather than simulated process models.

Active table imports now run through the address-list model and retain the
resulting undo information. Paste preserves existing injection owners and freeze
anchors. Deleting scripts or groups, editing scripts, replacing tables,
disconnecting/switching targets and accepting normal window close clean records
against the original process before retiring their handles. A flag-only disable
retains pending undo; a later disable cleans it, and re-enable retires the previous
allocation before executing again. Window destruction attempts record cleanup
while the borrowed process and assembler are still alive.

An external change to an injected executable byte produces a real ownership
conflict. Tests require failed replacement to retain rows, undo, title and recent
tables; failed deletion/editing, target switching and window close preserve the
original context. Repairing the conflicting byte allows successful restoration
and deallocation. Forced destruction attempts cleanup and detaches remaining
viewers without opening a modal dialog; it cannot preserve an interactive retry
after the owning window itself has been destroyed.

Before-execution callbacks and actual Lua blocks may append records and grow the
vector. Activation stores stable IDs and reacquires entries after callbacks.
Reentrant execution, deletion, reset, editing and target changes are rejected
while a script is executing. Completed activation callbacks can replace the
table or delete the record; a table/target revision stops an earlier import from
activating reused IDs in the replacement. Checkbox and group cascades also use
stable IDs. The runtime fixture covers these callback cases.

The real i386 tests also exposed an assembler parser ambiguity: bare hexadecimal
addresses starting with A–F were implicitly declared as zero-address labels.
Such literals now remain addresses; explicit hexadecimal-looking label names
retain their symbol meaning. Independent engine regressions cover both cases.
The preserved previous GUI fails 22 of the comparable 57 earlier assertions on
each target when run with the corrected parser. The previous parser fails the
new hexadecimal-address regression. Baseline sources, hashes and complete
outputs are retained in the snapshot; the final fixture extends that initial
subset to 78 checks per target.

The existing full GUI lifecycle, table-save, Lua-console and code-finder suites
pass, together with native core, deeper and compatibility regressions. Cached
ASan/UBSan core regressions and the existing real x86-64/i386 backend fixture
suite also pass; GUI objects are not sanitizer-instrumented in this checkpoint.
Separate gate controls reject a missing binary, a missing profile, incomplete
assertions and an actual 50-second deadline, retaining partial timeout output.
These synthetic gate controls do not count as target compatibility evidence.

Native build/release validation requires both profiles and complete assertion
counts. The local CI mirror requires this gate on x86-64, where the two native
fixture executables are built. Other native architectures, Wine/Proton, remote
transports and standalone assembler-editor ownership need their own lifecycle
coverage. This checkpoint does not complete the six-area compatibility objective
or establish compatibility with every Linux process.

## Auto Assembler editor lifecycle and shared ownership

The [editor lifecycle snapshot](compatibility-evidence/gui-editor.json) extends
the preceding record checks to standalone editor injections. The required native
GUI gate now runs 78 record checks and 77 editor checks on each real x86-64 and
i386 child process, for 310 assertions. Editor tests observe injected data/code,
the actual allocated target mapping, exact restoration, deallocation, target
liveness and normal application exit.

Editor close and normal main-window retirement clean owned injections before
discarding their original process handles. A conflicting executable byte refuses
editor close, process replacement, disconnect and main-window close while
retaining the recovery UI and undo. Repairing the conflict permits cleanup.
Repeated direct Execute calls preserve the existing owner instead of replacing
its undo. Displayed script edits keep the original execution context available
for Disable. Destruction attempts cleanup while the borrowed process/assembler
dependencies remain alive; callers of the editor's borrowed-pointer constructor
must preserve that lifetime contract. Forced destruction can attempt cleanup but
cannot guarantee an interactive retry after destroying its owner.

A GUI operation guard covers shared assembler execution, syntax checking,
cleanup and target retirement. Hooks and actual Lua callbacks cannot reenter a
second script on that engine or replace its target while it is running. Ordinary
record creation during Lua remains supported. Completed operations receive a
shared activation order; editor/record retirement, Disable All, group cascade,
multi-row deletion and table replacement undo overlapping patches newest first.
Tests include both editor/record activation orders, editors activated in a
different order from their creation, and moved rows. CodeFinder monitoring stops
before restoration, but finder objects remain alive until their windows and
destruction callbacks finish. The monitored-conflict fixture verifies subsequent
recovery against the original process. A normally exiting injected target also
retires undo without writing into a new application's reused virtual addresses.

The preserved previous GUI fails 15 of the initial 45 editor assertions on each
ABI. The final fixture extends that subset to 77 assertions. Focused ASan/UBSan
builds also pass all 310 record/editor assertions. These builds instrument the
main-window and editor implementation, their generated Qt meta-object code and
the test driver; other GUI objects, the core library and system Qt retain their
cached native builds. The previous editor, instrumented with its matching headers
and tested against the same final fixtures, produces a heap-use-after-free when
target replacement destroys its currently executing callback. The operation
guard and copied callback keep that lifetime safe in the current implementation.

Native GUI lifecycle, table-save, Lua-console and CodeFinder regressions pass as
well. Seven gate controls reject missing binaries, missing record/editor profiles,
incomplete record/editor assertions, the previous GUI and an actual 50-second
editor deadline. Timeout reporting retains the successful record run and partial
editor output. The previous-GUI control runs real fixtures; the other controls
exercise gate validation and do not add target compatibility coverage. Required
native/release/local validation includes both suites; target failures fail the
gate. This extends native lifecycle evidence, while the full runtime,
architecture and transport matrix remains incomplete.

## Auto Assembler module snapshots and symbol ownership

The [module lifecycle snapshot](compatibility-evidence/autoasm-modules.json)
records 24 new assertions on each actual x86-64/i386 child process. The fixtures
run distinct executable copies at overlapping virtual addresses, perform real
same-ABI `exec` through an existing handle, observe their own patched data and
exit normally after exact restoration. Quoted module names include both `+` and
`-`, so arithmetic must preserve the filename.

Module names now resolve from the selected process's current module snapshot
for each execution. They no longer enter the persistent registered-symbol table.
Target replacement and `exec` retire absent names before another script can
write through their reused addresses. Syntax-only checking and failed target
capture clear the module snapshot. Explicit symbols remain registered, take
precedence over module names and keep their undo ownership across other script
executions. Unregistering an explicit symbol reveals the current module again.
The script owner's cleanup removes only its own registered symbol. Five separate
model regressions cover bare identifier module injection points, unload while
the old address remains mapped, reload at another base, explicit zero-valued
symbols and subsequent unregistration. These model cases supplement the live
fixtures; they do not establish live dynamic-loader unload coverage.

The preserved previous core, loaded by the same final driver and fixture inputs,
fails 10 of the 24 assertions on each ABI. Its earlier 22-assertion subset fails
nine per ABI. At both replacement stages the old engine's actual application
prints `111`; the corrected engine preserves `123456789`. Loader output,
baseline sources, hashes and complete test output are retained. Current native
and cached ASan/UBSan core regressions and all 48
live module assertions pass. Native GUI lifecycle and all 310 record/editor
injection checks pass with the updated core as well. Sanitizer builds instrument
the core and integration driver; the freestanding target children remain actual
unsanitized programs. Leak detection is disabled as in the existing core gate.

Required native, sanitizer, release and local x86-64 gates require both complete
profiles, every assertion and completion of the preceding live process suite.
Seven negative controls reject missing binaries, a missing ABI, incomplete
assertions, a failed assertion despite a successful declared summary, missing
preceding-suite completion, the actual previous core and a real 50-second
deadline with partial output retained. Six controls are synthetic validator
checks; the previous-core control runs the real target fixtures. Remote workflow
execution, other architectures, Wine/Proton, remote module refresh and concurrent
loader activity are not covered by this checkpoint. The six-area objective
remains incomplete.


## ARM32 and Thumb registers

The shared Linux GP backend now probes `NT_PRSTATUS` with space for the full
272-byte AArch64 bank and classifies the returned 72-byte ARM32 bank. It preserves
R0-R12, SP, LR, PC and CPSR without signed extension and leaves `ORIG_R0` intact.
ARM32 edits require 32-bit values and PC alignment for the selected CPSR T bit.
Every ARM register write is read back in full; failure restores and verifies the
original bank. A failed restoration reports `state_not_recoverable`, leaving the
caller responsible for keeping the thread stopped and retrying its saved context.
The layout follows the [Linux ARM ptrace UAPI](https://github.com/torvalds/linux/blob/v6.18/arch/arm/include/uapi/asm/ptrace.h).

ARM and Thumb software-breakpoint primitives use the kernel's corresponding UDF
encodings, align patches to the correct instruction width, preserve neighboring
bytes and retain cleanup after a code conflict. Trap PCs identify the trapping
instruction without x86's one-byte subtraction. Actual target execution confirms
trap delivery and successful original-code execution after restoration, using
ptrace's kernel instruction-cache path. The [Linux ARM ptrace implementation](https://github.com/torvalds/linux/blob/v6.18/arch/arm/kernel/ptrace.c)
defines these traps. The current interface rejects ambiguous ARM32 big-endian
instruction formats; BE32/BE8 execution is still pending.

Shared register consumers expose 17 named 32-bit rows and ARM status flags. Lua
breakpoint conditions receive R0-R15, PC/SP/LR/CPSR and R11/FP aliases, without
fabricated x86 names. Applying edits after a live ARM/Thumb T-bit change requires
refreshing the snapshot. These view/condition paths have host model coverage;
this checkpoint does not establish full ARM32 GUI or Lua process workflows.

The [ARM32 register snapshot](compatibility-evidence/arm32-registers.json) records
26 actual assertions for ARM and 26 for Thumb on each of two real kernels: Alpine
6.18.52-lts on ARMv7 and 6.18.52-virt on AArch64 with actual ARM32 children. The
AArch64 controller also requires 13 native AArch64 regression assertions, totaling
117 assertions per normal or UBSan run. Both runs pass. Fault tests perform real
kernel writes, then inject an error in the controller's ptrace wrapper; they verify
complete rollback and caller recovery after an injected restoration failure.
These are controlled failures, not spontaneous kernel errors. The programs
observe their edited R8 and exit normally after restoration and detach.

The final identical driver against preserved pre-change backend/header sources
fails 15 of 26 ARM assertions and 15 of 26 Thumb assertions on each kernel. The
previous AArch64 backend also fails two of its 13 native error-recovery assertions.
The baseline driver uses a raw-register fallback solely to complete cleanup after
the unsupported read; it cannot satisfy the product register/edit assertions.
Its ARM32 children observe the original R8 and exit normally. Logs, source/binary
hashes, compiler-package provenance and separate gate rejection controls are saved
in the snapshot. Host core, register/Lua model and register GUI smoke checks pass;
host ASan/UBSan evidence covers model consumers, while the ARM guest drivers use
UBSan with aborting checks.

`tools/check-arm32-vm.sh` reuses tiny Ninja cross-builds at one compiler job and
runs guests sequentially with one CPU and 128 MiB. It verifies both pinned kernel
hashes. `CECORE_ARM32_UBSAN=1` selects instrumented drivers; the gate rejects wrong
ELF architectures, missing or failed assertions, sanitizer diagnostics and
timeouts, preserving partial output. `CECORE_REQUIRE_ARM32_VM=1` adds both variants
to local CI. The required ARM32 workflow now precedes release packaging and
publishes its reports and logs. Remote workflow execution has not been verified.

At this register checkpoint, full ARM32 DebugSession ownership/event handling,
hardware watchpoints, VFP, syscall and call injection, worker threads, relocation, general unwinding,
interworking transitions, BE8 and whole-application runtime coverage remain
pending. Capability gates are not expanded to advertise those unimplemented
features. The VFP and private stopped-memory checkpoints below extend this
coverage; the full six-area compatibility objective remains active.


## ARM32 VFP and context recovery

The latest [extension recovery snapshot](compatibility-evidence/arm32-extended.json)
adds ARM32 VFP to the opaque context backend. It probes the stopped task's GP
regset to select ARM32 or AArch64; an ARM64 controller cannot ask its ARM32 child
for native FPSIMD state. ARM32 capture now requires the actual 260-byte VFP bank
(D0-D31 and FPSCR). A failed required-bank read fails capture instead of silently
omitting floating-point state. Native ARM kernels additionally capture exposed
legacy FPA bytes, while ARM64 compat kernels expose a four-byte TLS bank.
The layout and separate views follow the [ARM Linux implementation](https://github.com/torvalds/linux/blob/v6.18/arch/arm/kernel/ptrace.c)
and [ARM64 compat implementation](https://github.com/torvalds/linux/blob/v6.18/arch/arm64/kernel/ptrace.c).

Actual ARM and Thumb functions seed D8, D31 and FPSCR before their stopped loops.
The tests change real VFP registers and rounding control, detect the difference
without overwriting the saved image, restore every byte and independently compare
all GP registers. Restoring an already exact image sends no register writes.
Controlled write errors leave the stop and snapshot available for verified retry.
On ARM64 compat, tests also change and restore the actual TLS bank before resuming.
The original programs observe their restored VFP state and finish normally after
register/trap cleanup. A separate actual AArch64 child verifies its unchanged
528-byte FPSIMD ABI and preservation of all captured extension banks.

The initial native ARM test exposed a kernel limitation. Writing the legacy FPA
bank through `SETREGSET` panicked Alpine's pinned ARMv7 6.18.52-lts kernel in
`fpa_set`: hardened-usercopy rejected a copy into `task_struct`. Its full boot and
panic log is retained as failed evidence. The engine now verifies native FPA
read-only and refuses changed-image restoration before invoking that write path,
retaining recovery. A simulated changed FPA read verifies refusal with zero
kernel register writes; this is not evidence of successful FPA mutation/restoration.
The actual original FPA bytes remain unchanged. A safe legacy FPA restoration
adapter, native ARM TLS and IWMMXt preservation remain pending. The guest kernel
and host configuration were not changed to obtain a passing test.

At the context checkpoint, the expanded mandatory suite required 80 checks under the native ARMv7 kernel
and 101 under the ARM64 compat kernel: the earlier 117 GP/trap checks plus 64
context checks, including controlled read/write failure conditions. Normal and
aborting UBSan runs pass all 181 each. Linking the identical final driver against
the immediately preceding context backend fails 11 of 14 new ARM and Thumb checks
on each kernel; its eight native AArch64 extension checks still pass. Raw kernel
cleanup lets these baseline programs exit normally without satisfying product
capture or recovery assertions. All existing GP/trap assertions still pass.

Required gates reject missing extension profiles/assertions, failed rows despite
clean summaries, wrong counts, sanitizer diagnostics and kernel panic/oops logs.
Separate synthetic rejection controls are saved alongside the actual baseline
and kernel results. The unchanged 70-second timeout and ELF/kernel-hash checks
retain their earlier [gate-control evidence](compatibility-evidence/arm32-registers.json).
The required ARM32 workflow, local checks and release artifact dependencies now
include these context assertions. Host core/model regressions pass normally and
with ASan/UBSan. The architecture drivers and builds run serially at reduced
priority, with one compiler job and one CPU/128 MiB per ARM32 guest.
The freshly rebuilt broader AArch64 syscall/debugger suite also passes all 906
checks under the pinned 4 KiB kernel, including required SVE/SME and real
libc/pthread injection. Its concurrency cases use two CPUs and 128 MiB, running
after the serial build. This additional run does not claim fresh 64 KiB coverage.

This context primitive is a prerequisite for ARM32 syscall and call recovery.
The private stopped-memory primitive below builds on it; general syscall/call
adapters, full DebugSession ownership, native VFP GUI editing, hardware
watchpoints, native TLS/IWMMXt, BE8 and broader whole-application coverage remain
pending. The original six-area compatibility objective remains active.

## ARM32 private memory syscalls

The [private-syscall snapshot](compatibility-evidence/arm32-syscalls.json) builds
on the GP and opaque VFP primitives above. A caller that already owns a stopped
ARM32 user thread and a private executable scratch page can execute real Linux
EABI `mmap2`, `mprotect` and `munmap`. Both ARM and Thumb modes run under the pinned
native ARMv7 kernel and as actual ELF32 children of the ARM64 compat controller.
The executor probes the actual task's 72-byte GP bank; native AArch64 remains a
separate 272-byte ABI. A compat task cannot enter the AAPCS64 function-call path.
This does not enable general process allocation or full ARM32 injection.

Native ARM lacks the single-step mechanism used by the existing executors. The
private ARM32 path patches SVC followed by an owned UDF trap, verifies the written
instruction bytes before executing, and requires the exact kernel trap address
and type. It clears CPSR ITSTATE only for this private execution and restores the
entire original GP bank, exposed VFP/TLS/FPA images and scratch bytes. Actual
Thumb execution stops inside an `ITE EQ` block: both private operations finish
independently of its opposite conditions, recover the exact IT state and let the
original application finish with its edited R8 and seeded VFP state.

Each kernel has 27 ARM and 27 Thumb memory assertions plus four live Thumb IT
assertions. They check real mapping permissions, independent reads/writes,
read-only write refusal, kernel EINVAL, oversized arguments, scratch alignment,
return/scratch page protection, and a sparse-file marker at six GiB. Native
32-bit sources use 64-bit file offsets for proc-mem and inode reads; the actual
`mmap2` offset remains measured in 4096-byte units. The six-GiB sparse fixture
writes only one data page and does not allocate six GiB of guest RAM.

Controlled faults drop a private instruction write despite a successful ptrace
return, report an error after a real GP write, and refuse GP restoration after a
completed mmap. The executor verifies writes before running, rolls back failed
setup, retains a completed value and recovery record after failed restoration,
rejects retry from a different host ptrace owner, and supports verified idempotent
retry on the original owner. Actual temporary mappings are then reclaimed.
A real SIGUSR2 queued before private execution is retained for the caller,
creates no mapping, and is explicitly delivered exactly once to the application's
handler before returning to a real owned stop.

A shared safety defect also affected native backends: when separate scratch was
used, destructive memory operations checked its page but overlooked the original
PC's return-code page. The guard now checks both. Four additional native AArch64
assertions preserve the original page's permissions and all 4096 bytes, full
register banks and private instructions. The immediately preceding executor,
linked with the identical final driver, actually removes the owned native
AArch64 child's original page. That baseline child is terminated by its owner;
its later trap/liveness failures are retained as evidence, not repaired into a
claimed successful run. The old backend also fails 23 of 27 ARM/Thumb memory
checks and two of four IT checks under each kernel; its earlier GP/VFP checks
still pass for those ARM32 children.

At the private-syscall checkpoint, the mandatory suite required 138 native ARMv7 assertions and 163 ARM64 compat /
native AArch64 assertions: 301 per normal or aborting UBSan variant, 602 combined.
The expanded workflow cache includes the private executor and memory assertions;
local checks and release packaging retain the same required kernel profiles.
Gate controls reject missing/failed memory or IT rows, false clean summaries,
wrong counts and missing native return guards, alongside replays of actual failed
runs. Earlier timeout, actual-ELF and pinned-kernel checks remain required.

The initial UBSan native run caught a tagged Thumb function-reference alignment
failure in logging's `std::call_once` invocation. A lambda now invokes the same
initializer. The static ARM64 sanitizer driver additionally selected an
instrumented inline RTTI equality function used by libubsan itself, recursively
entering its own vptr handler until the stack faulted. The minimal test link now
selects libstdc++'s existing implementation before application COMDATs. Application
translation units retain full undefined/vptr instrumentation and abort on errors;
no sanitizer category is disabled. Failed logs, the diagnostic PC and disassembly,
link commands and final object symbols are recorded in the snapshot.

Builds run serially at reduced priority with one compiler job. Small guests use
one CPU and 128 MiB. Host core/model and native x86-64/i386 owner/syscall regressions
run normally and with ASan/UBSan. The freshly rebuilt broader AArch64 suite runs
separately with two CPUs and 128 MiB for its concurrency cases; this checkpoint
does not claim new 64 KiB kernel or physical ARM hardware results.

Borrowed ARM32 syscall sites, native restart metadata not exposed by ptrace,
parked/restart-stop adapters, bounded memory-syscall waits, full allocation/call
and DebugSession owners, hardware watchpoints, native TLS/IWMMXt, legacy FPA
writes, BE8 and broader frontend/runtime coverage remain pending. The six-area
compatibility objective remains active.

## Return instructions at page boundaries

The [boundary snapshot](compatibility-evidence/return-boundaries.json) extends the
original-PC page guard above for stopped user-code contexts. A saved instruction
can require bytes from its
next page. Checking only the page containing its first byte allowed `munmap`,
`mprotect` without execute permission and `MAP_FIXED` to destroy its remaining
bytes while a syscall executed in separate scratch. The operation reported
success, restored the saved PC, and the actual target then faulted on instruction
fetch with SIGSEGV. Identical-driver comparisons reproduce all three failures on
x86-64, i386, x32, native ARMv7 Thumb and ARM64 compat Thumb.

The executor now checks the saved instruction's complete page span before any
code or register mutation. It uses the existing x86 decoder in the stopped
thread's actual instruction mode and the Thumb prefix's 16/32-bit width. Reads
use aligned ptrace words and retain a partial window when the next page is
already absent. Fixed-width ARM/AArch64 instructions keep their existing guard.
Instruction reads and decoding are needed only when the requested destructive
operation affects the next page; unrelated operations retain their usual path.

This protects the actual instruction without reserving an arbitrary maximum
span. Real one-byte x86 RET and two-byte Thumb BX LR cases can unmap their unused
next page and then branch to mapped code. A repeated unmap with that next page
already absent verifies the partial-read path. Each target really executes its
original instruction and reaches an owned trap with an independently checked
result. The tests restore the original application context, reclaim every
scratch/code/stack mapping and verify subsequent application work and exit.

The native suite adds 26 mandatory assertions each for x86-64 and i386. The
actual x32-enabled Linux 6.1 guest also requires those 26 with its LP64 controller
and four-byte target pointers; it runs the existing debugger/recovery matrix as
well. Native ARMv7 and ARM64 compat each add 22 Thumb assertions to the existing
GP, VFP, private-syscall and live IT-state profiles. The ARM mandatory suite now
requires 160 plus 185 assertions per variant: 345 normal and 345 aborting UBSan,
690 combined. Host core/model and native suites also pass with ASan/UBSan.
The broader native AArch64 regression runs separately under the pinned 4 KiB
kernel; no fresh 64 KiB or physical hardware result is claimed here.

The preceding executor linked with identical final driver objects fails nine
of 26 boundary assertions for x86-64, i386 and x32, and nine of 22 for
native ARMv7 Thumb and ARM64 compat Thumb. Its destructive
operations really succeed, and each split instruction then really receives
SIGSEGV. Baseline cleanup explicitly restores the owned fixture's original
application bank after recording those failures. That cleanup does not satisfy
the failed return-instruction execution checks. Its short-instruction cases still
pass, as do the earlier ARM GP/VFP/private-memory/IT/native-AArch64 profiles.

Native, ARM and x32 release gates require both the operation rows and their exact
profile counts. Synthetic controls distinguish valid output from missing/failed
rows, missing summaries, wrong counts and actual failing baselines. The native
result marker is flushed before later fixture forks so inherited stdio buffers
cannot duplicate the profile. The failed initial gate and its successful
correction are retained in the snapshot. Builds reuse cached dependencies, use
one compiler job at reduced priority and run sequentially; guests use 128 MiB
and one CPU, or two for the existing concurrency matrices.

These checks extend memory-execution safety for stopped user-code contexts.
Kernel syscall restart can rewind the saved PC to an instruction in a preceding
page. The following section verifies interrupted x86 reads; other restart-stop
and hidden restart-block contexts still need separate live checks.
They do not establish the remaining ARM32 session/call/restart adapters,
additional ISA backends, full runtime and
frontend coverage, or physical instruction-cache behavior. All six compatibility
requirements remain active.


## Syscall restarts at page boundaries

The [restart snapshot](compatibility-evidence/restart-boundaries.json) closes a
second return-code defect on x86-64, i386 and x32. An interrupted blocked read
has an actual `-ERESTARTSYS` result and a saved PC after its SYSCALL or INT 80.
When that two-byte instruction ends at a page boundary, the saved PC names the
next page. The previous executor allowed private `munmap`, non-executable
`mprotect` or `MAP_FIXED` to destroy the preceding page. It restored every visible
register exactly, but actual resume rewound the PC and faulted with SIGSEGV
before the read could receive its input byte.

The kernel's [x86 restart path](https://github.com/torvalds/linux/blob/v6.1/arch/x86/kernel/signal.c)
rewinds the PC by two bytes for its four restart results. The guard now checks
both the active original syscall number and the saved error before protecting
that instruction's page, without changing code or registers. It interprets
compat error values at their actual width. A completed syscall and an ordinary
user-code value resembling a restart error do not reserve the unused preceding
page. ARM64 has a [different restart ordering](https://github.com/torvalds/linux/blob/v6.1/arch/arm64/kernel/signal.c);
this checkpoint does not add an ARM restart adapter.

Each x86 target requires 50 assertions across five real owned fixtures. Three
fixtures execute an actual read at the page end, independently confirm its
blocked syscall and arguments through procfs, and interrupt it into a real
kernel restart stop. They test the three destructive operations, exact full GP
and original syscall metadata, extended registers, code and scratch preservation.
Actual resume receives the separately supplied input byte, returns one, and
reaches the owned next-page trap. A fourth fixture reaches a real successful
syscall-exit stop and then releases its unused preceding page. A fifth uses
ordinary user code with an error-looking register value and no active syscall;
it also releases that page and executes successfully.

All fixtures restore the original application context, reclaim private mappings,
detach and verify original blocked-read console work. Identical final driver
objects linked with the immediately preceding executor fail nine of 50 checks
for each of x86-64, i386 and x32. All three unsafe operations actually succeed and
all three restart attempts actually receive SIGSEGV; both safe controls still
pass. Baseline cleanup follows the recorded failed resume assertions and does
not turn those failures into claimed successful execution.

The full host suites pass 642 x86-64 plus 643 i386 assertions normally and with
ASan/UBSan. The x32-enabled guest requires all 627 debugger and recovery
assertions, including the new 50, with an LP64 controller and four-byte target
pointers. The broader pinned 4 KiB AArch64 regression also passes its existing
906 assertions. Native and x32 local/workflow/release gates require every new row
and exactly one matching result summary. Synthetic replay controls separately
check missing or failed rows, absent, duplicated or contradictory summaries,
wrong counts or architecture, and actual preceding-backend failures.

Builds remain sequential, reuse cached dependencies, use one compiler job at
reduced priority, and run the existing concurrency guests with two CPUs and
128 MiB. No host packages or kernel settings change. The earlier ARM32/Thumb
boundary and sanitizer snapshot remains separate; no fresh ARM32, 64 KiB,
physical hardware, x32 call/image/exec matrix or hosted CI execution is claimed.

Other restart error classes and hidden timed restart-block state, mixed syscall
entry ABIs, ARM32/AArch64 restart-stop adapters, bounded memory-execution waits,
additional ISAs and the broader frontend/runtime matrix still need live coverage.
All six compatibility requirements remain active.
