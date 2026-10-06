# Compatibility work: progress and remaining work

Checkpoint: 6 October 2026. This records the work accumulated since release
0.9.5 and accompanies the current source checkpoint. The full six-area
compatibility objective is **not complete**. A target being recognized, a build
succeeding, or a generic byte read working does not prove that debugging,
injection, runtime objects and every frontend work on that target.

[COMPATIBILITY.md](COMPATIBILITY.md) contains the feature-by-target matrix,
implementation details and individual evidence records. The
[checkpoint report](compatibility-evidence/checkpoint.json) records the final
local checks for this commit. Older evidence snapshots describe the source and
binaries tested at their own checkpoint; their counts must not be added together
as a count of unique tests or presented as fresh checks of every environment.

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

- Integrate the mixed-ABI restart restoration prototype with owned recovery,
  cancellation, signal handling, target exit/exec and retry fault tests.
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

- Observe the hosted workflows for the pushed source revision and resolve any
  environment-specific failures. Local reports do not prove hosted CI completed.
- Add mandatory gates for the additional supported environments/features as
  those adapters and real fixtures become available.
- Run a new release against the required gates when a release is requested.
  This checkpoint does not create a new release or claim universal compatibility.

## Latest completed verification

| Checkpoint | Actual results | Scope limits |
|---|---|---|
| [Return instruction boundaries](compatibility-evidence/return-boundaries.json) | ARM32/compat: 345 normal plus 345 aborting UBSan assertions; host native: 1,185 normal plus 1,185 sanitizer assertions; broader AArch64: 906; x32 debugger: 577 | Historical checkpoint; ordinary saved user-code instructions, with real unsafe-backend comparisons |
| [Interrupted-read restart boundaries](compatibility-evidence/restart-boundaries.json) | Host x86-64: 642 and i386: 643 assertions, repeated with ASan/UBSan; x32 debugger: 627; broader AArch64: 906; 18 verifier controls | 4,103 passing operation assertions across repeated variants, not 4,103 unique scenarios; interrupted reads and safe completed/user-code controls |
| [Current source checkpoint](compatibility-evidence/checkpoint.json) | Full serial cached build and 23 local checks passed; GUI injection: 310 assertions; normal and leader-exit frontend gates: 30 and 33 checks; JSON: 33 core plus 384 independent decimal checks | Optional core cases skipped as detailed below; new mixed-ABI issue remains pending; foreign-environment and hosted-workflow reports retain their own checkpoint scope |

### Fresh checks for this source checkpoint

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

## Newly found mixed-ABI restart defect

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
