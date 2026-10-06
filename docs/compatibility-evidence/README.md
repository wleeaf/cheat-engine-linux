# Local compatibility evidence

These JSON reports contain operation-level results from local unreleased
working-tree snapshots. Each report records its UTC timestamp and binary hashes.
They are local verification
snapshots, not records of completed GitHub Actions jobs or promises about
arbitrary applications.

- `gdb-transport.json`: 59 independent protocol, shared-adapter, CLI and
  real ARM64 QEMU CPU/RAM cases. Verifies XML register descriptions and namespace
  includes, packet limits, escaping/RLE, checksum retries, deadlines, short reads,
  confirmed partial writes, unavailable registers, failed setup without detach,
  program-width overrides, high-address scans and exited-target retirement. The real guest uses one
  CPU and 64 MiB RAM, edits actual guest scalar/vector registers, executes MOV/ADD,
  scans its RAM and restores every edited byte and captured register. Records
  driver/core/CLI hashes and the exact guest command. This is a bare-metal guest,
  not evidence of Linux guest-process selection or virtual-memory translation.
- `gdb-transport-sanitizers.json`: 57 equivalent protocol, adapter, CLI and
  private-parser linkage cases against the ASan/UBSan engine. QEMU is exercised
  separately by the required normal gate.
- `gdb-gui.json`: six production GUI scenarios, including a real ARM64 QEMU
  CPU/RAM target and independent BE32 data on an ARM64 register description.
  Eight actual widget screenshots include numeric live/Previous columns and
  four-byte pointer results. Records the driver, core and GUI binary hashes and
  verifies exact RAM/register restoration, cancellation and target lifetime.
- `scanner-formats.json`: 155 native and 155 ASan/UBSan model checks with independent
  integer/IEEE/UTF-16 fixtures in both byte orders and both pointer widths,
  captured-format reload/pruning, inclusive ranges, integer delta extremes,
  unknown-format rejection, malformed metadata, high-address/next-scan bounds
  and 4/16/64 KiB perf layouts with wrapped counters and malformed records.
  All-type candidates cover numeric narrowing, short tails, concrete selection,
  reload/pruning, multi-shard batches and Lua sample decoding. Literal checks
  retain exact fractional/64-bit boundaries, full signed-endpoint deltas,
  scientific precision, infinity and independent percentage thresholds.
  Tracer concurrency uses inactive backends. This covers data paths;
  it does not establish a live PowerPC or big-endian Linux backend.
- `all-types.json`: hashes of the tested source/binaries, model checks, actual
  GUI scan controls and protected-page display, plus the production CLI Lua
  All-scan checks against an independent BE32 peer and LE64 ARM64 QEMU RAM.
  `all-types-gui.png` shows distinct live/captured rows and actual change
  highlighting. `all-types-host-ci.log` records the successful full local mirror,
  with separate `all-types-host-*.json` reports for native recovery, frontends and
  isolated Wine. Builds use one compiler at low priority and heavy checks run
  sequentially. Dynamic libc injection in this host run covers x86-64; the host
  lacks its dynamic i386 fixture. Earlier i386 container reports retain their
  own snapshot scope.
- `all-numbers.json`: ten additional model checks, including 51,102 independent
  exact rational comparisons per build. Real GUI controls verify malformed
  upper-bound recovery and scientific precision; live native CLI tests cover
  fractional/scientific/hex values, percentage comparisons without ordinary
  bounds and rejected percentage flags. Production CLI Lua repeats strict
  parsing and explicit Between bounds on the independent BE32 peer and actual
  LE64 ARM64 QEMU RAM, with exact restoration. It references the current
  All-scan and full host CI evidence by hash. Input is bounded to 4096 characters
  and the parser's double range; broader runtime/ISA requirements remain open.
- `floating-rounding.json`: nine additional model checks for floating boundaries,
  original-input precision, grouped scans, independent scalar/SSE2/AVX2 expected
  addresses and Lua options. Records 22 live native CLI workflows, actual GUI
  controls and error recovery, and Lua options through BE32 TCP and ARM64 QEMU
  RAM. [The scan controls](floating-rounding-gui.png) show live/captured values
  and the refreshed completion status. Before/after self-process probe logs
  reproduce rounded false negatives and truncated false positives; the earlier
  observation has no captured binary hash and is not a release baseline.
- `scanner-failures.json`: a later snapshot with 161 native and sanitizer model
  checks, including six checks for worker exceptions, sibling joining, unchanged
  saved/target bytes, partial-file/descriptor cleanup and Lua retry. The independent
  before/after probe captures the loaded core's hash and reproduces false first-scan
  success and next-scan termination. Faults are injected into small owned fixtures;
  the test does not exhaust host memory or establish operating-system thread-creation
  exhaustion coverage. Earlier All/number/rounding reports retain their own source
  and binary snapshots.
- `arm64-kernel-profiles.json`: pinned inputs and hashes for two sequential
  full-system kernel checks sharing the same driver build. `arm64-syscalls.json`
  retains all 881 original checks on 4 KiB pages. `arm64-syscalls-64k.json` records
  722 checks on actual 64 KiB pages, including live SVE preservation and real
  native injection; it verifies SME is absent and explicitly lists 11 cases
  requiring that interface. SVE deferred-state exec, syscall/private/quiesced/native
  call, seccomp and alternate-stack guard cases run independently of SME.
  Both profiles retain actual debugger, trace,
  CodeFinder and recovery checks. Their separate logs preserve every result.
  Neither kernel profile proves live hardware branch-stack/PT sampling.
  The SVE-only expansion was verified under both kernels and the affected native
  targets rebuilt. Local TCP and ptrace became available for the subsequent
  successful full host CI mirror archived with the All-scan changes. The ARM64
  profiles retain their separately hashed builds and do not prove All scans
  against a live ARM64 Linux process.
- `gdb-transport-before.json`: deliberately failing comparison against the
  released GDB client's source. Eleven of the original 14 raw probes fail, reproducing
  E-prefixed data rejection, missing escaping/retries, console framing, stale
  connections, stalled transactions and oversized memory replies. The probe
  combines released client sources with the current raw-test portion, so this
  report does not represent a complete released application build.
- `wine-11-wow64.json`: Wine 11 on Fedora 44, actual ELF64-loader WoW64,
  including memory operations while Windows i386 code executes a busy CPU loop.
  Both program widths also verify shared thread inspection, actual Windows CPU
  register mode and architectural stack words before releasing the selected stop.
- `wine-9-legacy.json`: Wine 9 in an Ubuntu 24.04 Podman container, actual ELF32
  Wine32 loader. The engine was built in that container with GCC 13.
- `native-syscalls.json`: real process API and syscall owner service, actual native x86-64 and
  i386 fixtures, including failed instruction/register restoration and detach,
  allocation cleanup, target exit, and signal delivery. Also verifies the real
  integer/SIMD register bank, register edits, hardware/software breakpoints,
  single-step, programming/patch recovery and target liveness. The actual
  DebugSession owner/event loop now exercises two independent watchpoint slots,
  cloned writer threads, register selection, call step-over, entry step-out,
  run-to-cursor, exec retirement, signal-interrupted stepping, genuine user
  SIGTRAP delivery and destruction with failed cleanup. Instruction tracing adds
  native decoding/call step-over, cloned writers, exec, cancellation, concurrent
  request rejection, signal delivery, failed cleanup and exit during recovery.
  CodeFinder adds actual hardware and page-guard stores, cloned writers, occupied
  slot preservation, job-control stops, exec, genuine/interrupted signals, failed
  cleanup/startup and exit recovery. Private stopped-thread syscalls and all-stopped
  scratch cleanup restore register/restart state, permissions and mapping lists.
  Concurrent shared-code syscalls perform no program-code writes while a sibling
  runs; a real seccomp trap denial preserves target liveness and filter state,
  consumes its queued owned step trap and reports no invented allocation.
  Real exclusive syscall-user-dispatch checks verify exact native range selection,
  unchanged selectors/configuration, allowing/blocked/invalid selectors, safe
  rejection and CPU progress. Preflight failures retain ptrace ownership before
  any target syscall, including failed interrupts, failed detach, allocation
  failure, caller destruction and target exit. Initialization writes that change
  real kernel state before reporting an error restore the exact original image.
  Native stopped calls additionally verify eight arguments, FP and mask changes,
  guarded private stacks, exact return traps, genuine faults, explicit signal
  decisions, partial initialization, transient return reads, retained recovery
  and real return/interrupt races. Cleanup borrows an existing syscall without
  shared-code writes. Native x86-64 passes 541 operation checks and i386 passes 542, including
  rejection of overflowing rounded 32-bit allocation sizes. Selected-thread
  inspection also verifies changed-only GP editing with deliberately stale PC/SP,
  callback rollback, retained detach ownership, process-level sibling recovery and
  original syscall restart while unseized siblings continue running.
  Missing executable metadata retains real cleanup ownership and unreturned
  allocations; stale caller birth still releases the actual seized task. A bounded
  concurrent inspection test verifies metadata lock ordering without relying on
  kernel wait-channel names. Both lifecycle and lock-order regressions were
  reproduced before their fixes.
  Leader-exit checks keep public process identity stable while verifying live
  member reads/writes, batched scanning, module/mapping metadata, stack inspection,
  allocation/protection/free, retained recovery across frontends and final group
  exit. The old implementation failed eight of these checks.
  Additional full-debugger startup, software breakpoint stepping, instruction
  tracing and both hardware CodeFinder modes operate on the surviving writer.
  Six of these debug/monitoring checks failed before the startup-selection fix.
  Further bounded full-debugger cases step the real leader, worker and final-task
  exit instructions, retry a failed EXIT-stop detach, and verify a usable surviving
  register bank and original console work. Metadata and thread selection omit an
  irreversible EXIT stop before zombie state. Actual nonleader exec drains sibling
  exits and adopts the renamed task without replaying old-image traps. Native
  syscall tracing remains distinct from genuine program INT1/BRK signals. A real
  launcher additionally consumes its child's EXIT wait notification while the
  debugger callback is occupied; destruction still releases the owned kernel stop.
  The original exit-step bugs and same-process cleanup hang were reproduced before
  their fixes. Failed cases have bounded owners and fixtures terminate with their
  parent to avoid leaving test processes behind.
  Additional launchers consume actual program-trap, CLONE, same-thread EXEC and
  running worker/final EXIT notifications while the owner callback is occupied.
  The owner recovers each kernel stop, preserves signal delivery and original
  console work, and retains failed EXIT detach until retry. Paused SIGKILL is
  observed both with an available wait report and after another parent consumes
  it. A second wait after the siginfo probe drains newly available notifications
  so cloned-thread watchpoints are not handled twice. Same-thread exec is covered;
  Additional real nonleader exec cases hold owner bookkeeping after an actual
  leader detach and consume the replacement task's kernel EXEC report. Running
  and all-stop stepping recover the renamed identity, fresh register bank and
  normal replacement-program exit. Removing retired breakpoint IDs performs no
  code writes. A failed replacement-context read still notifies image retirement
  with an unavailable bank; the same owner then rereads its actual registers.
- `arm64-syscalls.json`: equivalent process API, owner-service and native debug primitive checks inside an ARM64
  full-system Linux 6.18.52 guest using QEMU 8.2.2 TCG. Includes kernel, driver and
  fixture SHA256 hashes and 881 operation checks, including the real
  DebugSession, native instruction decoding, pre-access watchpoint continuation,
  cloned threads, instruction tracing, hardware/software CodeFinder and destruction
  recovery. Preflight failures, allocation failures and partially failed
  initialization writes verify original owner retention, complete restoration,
  caller destruction and target exit. Additional checks retain live SVE and streaming-SVE/ZA state at
  default and maximum 256-byte vector lengths. Actual kernel mutation changes
  vector length and destroys a bank/matrix before verified restoration. Memory
  operations preserve every captured extension byte; failed restoration retains
  the owner stop and its unreturned allocation until retry, then verifies CPU
  progress and console liveness. Guarded signal-return restoration also preserves
  hidden deferred SVE/SME vector lengths through real exec transitions after
  transient, private and quiesced memory operations. Partial frame writes and
  failed stack cleanup retain recovery; seeded stack bytes, FP control/TLS state,
  masks and alternate-stack settings are verified. Real seccomp filters and active
  alternate-stack handlers verify safe rejection before mutation and continued
  execution with both deferred lengths intact. Other filtered/custom-stack/GCS
  contexts still need an alternative backend. Native stopped calls also retain
  live SVE and streaming-SVE/ZA at default and maximum lengths, and preserve both
  deferred lengths through real exec after FP and signal-mask changes. The shared
  call owner retains private frames through timeout/signal recovery and frontend
  destruction, with orphan pthread-handle cleanup and running siblings. Actual
  guest glibc/loader fixtures verify library constructors, symlink/cached loading,
  real pthread execution, deadline detachment and actual kernel thread exit,
  self-detachment, `pthread_exit`, retained worker storage and cancelled late creation.
  Their binaries and runtime files have separate SHA256 hashes.
  Leader-exit coverage also verifies live member memory/metadata, selected-thread
  inspection, mapping/recovery ownership and final group exit. Actual guest glibc
  `pthread_exit` additionally verifies library constructors and completed native
  pthread creation while the original leader is already a zombie.
  Full debugger startup, breakpoint stepping, tracing and both native hardware
  monitoring modes also operate on the surviving member and restore its console.
  The guest also verifies bounded leader/worker/final-task exit steps, retained
  EXIT-stop detach recovery, nonleader exec, genuine BRK versus syscall-step
  notifications and cleanup after a launcher consumes the EXIT wait report.
  It additionally verifies consumed program BRK, CLONE and same-thread EXEC
  stops, automatic running-worker/final exit handling, retained failed detach
  and paused SIGKILL with available or consumed kernel notifications.
  Consumed nonleader EXEC reports recover kernel TID replacement during both
  running and all-stop stepping. A failed replacement-context read still publishes
  image retirement with an unavailable bank, followed by successful rereading on
  the same owner, no old-image code writes and normal replacement-program exit.
  The decoder uses verified pinned
  Capstone sources. This does not prove full ARM64 application support.
- `arm64-application-build.json`: complete core, Qt GUI and CLI cross-build with
  GCC 13 and actual ARM64 dependencies. Records the three AArch64 binary hashes.
  Its status is `built` and `runtimeVerified` is false: this report establishes
  compilation/linking, with separate guest reports establishing tested backend
  operations. It does not establish a working ARM64 desktop GUI.
- `arm64-gui.json`: real offscreen Qt debugger under the same ARM64 Linux 6.18.52
  guest, with 31 checks for native PC/SP, general and link-register edits, NZCV,
  V31, stack reads, complete BRK display/restoration and disabled detached cells.
  Also executes the actual CLI metadata and Lua/disassembly paths, and starts
  the full application against a live target with its memory viewer open.
  Also verifies the standalone register editor and raw stack window, including
  changed-only Apply, invalid edits and snapshot refresh. Records all runtime
  library hashes and all four screenshot hashes, with elapsed-time stage markers. Runs with one
  virtual CPU and 512 MiB RAM. This is operation-level frontend evidence, not
  coverage of every panel or a physical desktop.
  The captured [debugger](arm64-debugger.png) and [memory viewer](arm64-memory-viewer.png)
  and standalone [register editor](arm64-register-editor.png) and [stack](arm64-stack.png)
  show the actual guest-rendered windows; `arm64-gui.log` contains the kernel and
  operation results.
- `arm64-gui-leader-exit.json`: 34 equivalent Qt/CLI/Lua checks under the same
  real ARM64 kernel after the target's main thread calls `pthread_exit`.
  Verifies live debugger attachment, breakpoint stepping, native register edits,
  and selection of the surviving pthread in both register windows. The original
  process PID remains usable for CLI and application startup. Records the same
  rebuilt application hashes as the normal case and hashes all four captures:
  [debugger](arm64-leader-exit-debugger.png),
  [memory viewer](arm64-leader-exit-memory-viewer.png),
  [register editor](arm64-leader-exit-register-editor.png) and
  [stack](arm64-leader-exit-stack.png). Runs separately with one virtual CPU and
  512 MiB RAM; `arm64-gui-leader-exit.log` contains the operation results.
  The guest application test has a 180-second deadline within the VM's
  480-second limit. Both ARM frontend cases additionally verify real paused-target
  death, automatic debugger retirement, disabled register edits and final reaping.
  Its earlier 90-second deadline expired on this limited host;
  the timed repeat completed in about 51 seconds with the same CPU/RAM limits.
- `native-frontends.json`: equivalent native x86-64 live debugger, application
  startup, standalone register/stack windows, CLI and Lua checks. All 30 checks
  pass, recording core and frontend binary hashes. The [register editor](native-register-editor.png)
  and [stack](native-stack.png) screenshots show the actual native windows.
- `native-frontends-leader-exit.json`: 33 equivalent Qt/CLI/Lua checks against a
  real pthread target whose original leader has exited. Verifies full debugger
  attachment, actual breakpoint/register editing, and omission of the dead leader
  from both debugger and standalone editor thread selection. The target remains
  live through application startup. Saves all four [debugger](native-leader-exit-debugger.png),
  [memory viewer](native-leader-exit-memory-viewer.png),
  [register editor](native-leader-exit-register-editor.png) and [stack](native-leader-exit-stack.png)
  captures and `native-frontends-leader-exit.log`.
  Both native frontend reports also verify actual paused-target death, automatic
  debugger retirement, disabled register editing and normal final child reaping.
- `native-injector.json`: real native x86-64 and i386 glibc library/pthread
  fixtures, verifying constructors, symlink and cached library loading,
  non-executable entry rejection, actual kernel thread exit and timeout detachment,
  later completion, Lua path/timeout validation and original application liveness.
  Each ABI has 45 checks, including retained worker storage, creating-frontend
  destruction, self-detachment, `pthread_exit`, cancelled late creation, engine
  process shutdown, and AA rollback/disable/retry with a live code cave.
  Eight checks exercise a real glibc process after its main thread calls
  `pthread_exit`, including symbol resolution, library constructors, pthread
  completion, mapping permissions, surviving CPU progress and final console work.
  Wholly parked targets reject calls without changing their relative timed wait.
  Records core, driver, fixture and injected-library hashes. The i386 fixture uses
  Ubuntu 24.04 glibc on the host kernel; it does not establish all libc variants.
- `native-injector-sanitizers.json` and `native-syscalls-sanitizers.json`: the
  same native x86-64/i386 checks with an ASan/UBSan-instrumented engine and driver.
  Target fixtures use their normal native runtime so that injected code runs
  against actual libc and pthread implementations.
- `native-thread-namespace.json`: the host engine starts and waits for a native
  i386 pthread in an existing Ubuntu 24.04 Podman PID namespace. Records the
  distinct visible and inner PID chain, actual visible worker TID, binary hashes,
  and original console completion. This verifies thread-ID translation and
  pthread ownership across PID namespaces, with a shared host kernel. It does
  not establish arbitrary container permissions or complete container coverage.
- `native-module-namespace.json` and `native-module-namespace-sanitizers.json`:
  the normal and ASan/UBSan engines in the same host-to-container environment with
  different ELF32/ELF64 libraries at the identical absolute pathname. Verifies
  target-file selection, correct module ISA/ABI, actual symbol-based execution,
  and reuse of resolved paths. After unlinking the target library, a same-named
  host shadow including the kernel's deleted-name suffix cannot supply metadata
  or symbols; the mapped target data remains readable and console work completes.
  Records both conflicting library hashes and the engine/fixture hashes.
- `elf-debug.json` and `elf-debug-sanitizers.json`: actual stripped ELF32/ELF64
  shared libraries with `objcopy` debug sidecars and independent `nm` symbol
  references. Verify full-file checksums, invalid checksums, `.debug` fallback,
  absent sidecars, truncated links, directory traversal, ISA mismatch and files
  spanning several checksum buffers. Additional checks use an existing Podman
  container's global debug directory and build-ID directory with i386 and ARM64
  files, including wrong or removed identity notes. These exercise symbol-file
  parsing and selection; those library files are not executed. A further real
  idle i386 program shares its ELF inode with the host and verifies `loadProcess`
  against target-only global debuginfo, then finishes its original kernel read.
  Its short-lived container uses a cached local image without downloading one.
  None of these checks establishes DWARF unwinding.

Both Wine reports include Windows x64 and PE32 results, exact byte and protection
restoration, continued execution, and three watchpoint attach/detach cycles that
identify the exact Windows writer instruction. Busy loops verify actual Windows
register mode, allocation/protection/free and exact general-register/segment
restoration. WoW64 also verifies wide allocation near its Unix loader and default
allocation with the kernel's preferred low-address window exhausted. Temporary
PROT_NONE reservations do not populate physical pages and are fully removed.
Reports record core, driver, assembler and PE-fixture SHA256 hashes.
The container shares the Fedora
host kernel, so it does not establish coverage for Ubuntu's kernel builds.

Future release gates generate fresh reports from their release source revision.

`gui-data-formats.json` records a later snapshot with 166 native and sanitizer
model checks. Five added checks cover explicit pointer encodings on unknown
targets, automatic ABI behavior, neighbor preservation, table persistence and
malformed metadata. Actual GUI scans, transfers, edits, freezing, XML/JSON saves
and [scan controls](gui-data-formats.png) verify native encoded data. Separate
GDB GUI cases exercise an unknown-format peer and BE32 pointer edits in real
ARM64 QEMU RAM, restoring every changed byte. This does not establish a native
big-endian Linux backend or logical guest process/MMU support.

`gdb-register-bank.json` records the subsequent whole-register fallback snapshot.
Its protocol reports contain 79 native and 75 ASan/UBSan cases, including fifteen
independent bank scenarios and production CLI/Lua workflows. A proxy disables
individual-register packets against real ARM64 QEMU; core edits, MOV/ADD execution
and exact whole-core-bank/RAM restoration pass through actual `g`/`G` packets.
QEMU vectors omitted from that bank remain unavailable, while separate ordinary
packet tests retain their live vector coverage. Seven GUI scenarios and ten
screenshots include actual scalar/vector Apply actions against the independent
bank-only peer. The before-fix CLI probes reproduce failed reads/edits. The full
local CI mirror, Wine and existing native gates passed; only evidence counters
changed afterward, with all protocol and GUI gates rerun. Older snapshots remain
separate and this does not establish logical guest process/MMU support.

`aarch64-relocation.json` records the subsequent byte-level ARM64 relocation
snapshot. The independent GNU-assembled fixture executes original and relocated
code 1,119 times on each pinned 4 KiB/64 KiB Linux kernel, with one vCPU and
128 MiB. It verifies far branches/calls, every NZCV condition predicate, live
mutable literal pools, scalar/vector loads, address arithmetic, W^X/cache
synchronization and exact source restoration. Sixteen added host model checks
bring the model suite to 182 checks and cover encoding, rejection policies,
Auto Assembler layout/disable and rollback after an unreadable or resized source
instruction. The snapshot retains the full host CI log, the initial GUI deadline
failure and its successful diagnostic/full-CI retries; the cause of that initial
timeout remains unconfirmed.
Native ARM64 hook installation, general external-process cache synchronization,
hardware/BE runtime validation and other ISA backends remain pending. The older
complete ARM64 core/Qt application snapshot remains separate; this relocation
snapshot builds the actual backend and execution fixture, with current GUI/CLI/Lua
validation on the native host.

`code-write.json` records the later native executable-memory checkpoint.
The host backend and production CLI/Lua workflows pass 30 and five checks in
both normal and ASan/UBSan builds. Dedicated ARM64 Linux drivers pass 27 checks
on each pinned 4 KiB/64 KiB kernel, using one vCPU and 128 MiB. Actual warmed
code spans two RX pages; edits and undo change real execution without borrowing
registers or promoting page permissions. Three-chunk transfers verify every byte
and neighboring bytes; later short/post-mutation failures restore the complete
owned prefix. Blocked undo remains owned and prevents protection changes until
retry succeeds. A real same-file exec retires the original mm without replaying
its undo bytes into the replacement image.

Ten added model checks bring the model suite to 192 and cover unverified cache
adapters, little-endian ARM64 NOP instructions with big-endian data, alignment,
full-instruction NOP counts, forward-label layout, malformed count rejection,
partial x86 restoration and retired-image errors. They exposed the old Auto
Assembler NOP directive's x86-only encoding. Guest code-write drivers exclude
Auto Assembler and Lua; the native ARM64 workflow now requires those frontend
paths, with remote execution for this worktree still pending. The snapshot also
retains the existing 881/722-check kernel suites and both 1,119-execution
relocation suites. Native ARM64 hook coordination, arbitrary mapping/undo
lifecycle, real hardware caches, other ISA/cache adapters and broader kernel
proc-mem policy validation remain incomplete.
