# Coverage plan

Status: active plan, adopted 12 October 2026. This restructures the six-area
compatibility objective (see [COMPATIBILITY.md](COMPATIBILITY.md) and
[PROGRESS.md](PROGRESS.md)) into ordered, testable work that maximizes
coverage. It is written to be executed autonomously, one item at a time.

## Why restructure

The six areas (matrix, target descriptions, backends, environments, recovery,
release gates) describe *what* compatibility means but give no order and no
finish line. In practice the work drifted depth-first into area 5: the last
twenty commits proved rarer and rarer ptrace recovery windows while whole
targets (Proton, RISC-V, JVM, Flatpak, ...) had no live check at all.

Coverage is maximized by the opposite strategy: **breadth first**. Every
(target, capability) cell gets a basic live check before any cell is hardened
further. "Every Linux program" cannot be guaranteed (kernel policy, anti-debug,
GPU memory), so a cell may also end as *blocked*, provided the tool reports a
clear error instead of failing silently.

## Scoreboard: the target-by-capability matrix

### Capabilities (columns)

| Id | Capability |
|---|---|
| C1 | Attach and identify: target description, modules, symbols |
| C2 | Read and write typed values, freeze |
| C3 | Value scan: first/next scans, all value types, strings |
| C4 | Pointer scan and rescan |
| C5 | Disassemble and assemble (Auto Assembler script) |
| C6 | Allocate, inject a code cave, undo/restore |
| C7 | Native call (Lua `executeCode*`, library load) |
| C8 | Find what writes/accesses (watchpoints) |
| C9 | Debugger: breakpoints, stepping, registers, trace |
| C10 | Frontends: the row's working capabilities exercised through GUI, CLI and Lua |

### Targets (rows)

- **Native Linux:** x86-64 glibc; i386; x32; x86-64 static/musl; AArch64;
  ARM32/Thumb; RISC-V64; MIPS / PPC64LE / s390x.
- **Windows on Linux:** Wine legacy Wine32; Wine64; new WoW64; Proton;
  Proton inside the Steam Runtime (pressure-vessel) container.
- **Sandboxes:** Podman/Docker; Flatpak app; Snap app; bubblewrap.
- **Managed runtimes:** Mono/Unity; IL2CPP; JVM; CoreCLR (.NET); Go;
  V8 (Node/Electron).
- **Remote and emulated:** CEServer (ours and upstream); GDB/QEMU system guest;
  console emulators.
- **Hybrid PE:** ARM64EC / ARM64X.

### Cell states

| State | Meaning |
|---|---|
| `-` | No live evidence |
| `B` | Basic: one positive live test through the real API on a real target |
| `V` | Verified: basic, plus a failure or restore case, plus GUI, CLI and Lua where applicable |
| `X` | Blocked: documented reason; the tool returns an explicit "unsupported on this target" error |
| `n/a` | Not meaningful for this target |

**Coverage score** = cells at `B`, `V` or `X` divided by applicable cells.
**Depth score** = cells at `V` divided by applicable cells. The goal is to
push coverage to 100% first, then depth.

The matrix is kept machine-readable in `docs/compatibility-matrix.json`
(item 0.2) and the Markdown table in COMPATIBILITY.md is generated from it.

## Working rules

1. **Breadth first.** Do not raise a cell to `V` while an earlier-wave cell is
   still `-`. Within a wave, prefer the item that fills the most cells.
2. **Time box.** One item gets at most about one long working session. If it is
   stuck, record what was learned, mark the cells honestly and move on.
3. **Recovery tail is frozen.** New ptrace recovery corner cases (area 5) are
   only worked on when a defect is reproduced from a normal workflow: attach,
   scan, write, freeze, inject, debug, detach, or the target exiting/execing
   during one of those. Otherwise they go to Wave 7.
4. **Light evidence.** One evidence JSON per item at most, plus the matrix
   update. No per-build-variant log copies. The matrix is the source of truth.
5. **Reuse gates.** Add checks to existing gates and fixtures where they fit;
   create a new gate only for a new environment.
6. **Scarce resources.** One compiler job under `nice -n 10`, build only the
   targets needed, reuse caches, run guests and Wine sequentially, 128 MiB / 1
   CPU guests unless a test needs two, large temporaries on the build disk.
   Never run two heavy jobs at once.
7. **Green and committed.** Each finished item: relevant local tests pass,
   `tools/ci-check.sh --config` passes, matrix and PROGRESS.md updated, one
   commit, push. Fix a red hosted CI run before starting the next item.
8. **Safety rules from CLAUDE.md still apply** (Wine/Proton ptrace rules,
   default-deny Lua, no anti-cheat bypass).

## Waves

Each item lists the cells it fills and its completion test.

### Wave 0: foundation (small, do first)

- **0.1 Close out the unreaped-service check.** The uncommitted
  `--unreaped-service-only` check already passes 24/24 on x86-64 and i386.
  Done when: documented in PROGRESS/COMPATIBILITY, native gate passes,
  committed. This is the last planned area-5 item before Wave 7.
- **0.2 Machine-readable matrix.** `docs/compatibility-matrix.json` (cell
  state, evidence link, note) plus `tools/coverage_matrix.py` that renders the
  COMPATIBILITY.md table and prints both scores; `ci-check.sh --config` fails if
  the table is out of sync. Seed it from the current hand-written matrix.
  Done when: the scores are printed and the table is generated.
- **0.3 Explicit unsupported errors.** A refused operation reports the
  capability reason through GUI, CLI and Lua (one cecore helper,
  `targetOperationError`) instead of a silent nil, an empty result or a
  generic permission guess. Done when: a live blocked target is refused with
  its reason on every frontend. Each later `X` cell must add its own live
  refusal check.

### Wave 1: games (highest user impact)

- **1.1 Proton.** A real Proton build (GE-Proton or Valve Proton launched via
  umu-launcher, no Steam client needed) running the existing PE32/PE64 fixtures.
  Fills C1 to C8 for Proton. Done when: a required gate covers attach, scan,
  write, AA injection with undo and main-thread find-what-writes.
- **1.2 Steam Runtime container.** The same fixtures inside pressure-vessel (how
  Steam actually runs Proton games). Attach from the host with PID namespace
  translation. Done when: C1 to C3 and C6 pass from the host.
- **1.3 Wine full debugger.** C9 for Wine64, WoW64 and Wine32: breakpoints,
  stepping, registers and trace, following the Wine ptrace rules. Done when: a
  live session gate passes and the game-fixture threads stay responsive.
- **1.4 Unity Mono in the GUI.** Mono dissector, field edit and JIT symbols
  exercised in the Qt GUI against the real Mono fixture. Fills Mono C10.
- **1.5 IL2CPP.** `global-metadata.dat` parsing plus live class/field
  dissection against a real IL2CPP Linux build. If no redistributable IL2CPP
  binary can be obtained legally, keep parser tests and mark the live cells `X`
  with that reason.
- **1.6 Native game shapes.** Static and musl binaries, non-PIE, and a
  SDL/OpenGL-linked fixture (no GPU required for memory work). Fills the
  static/musl row.
- **1.7 Flatpak and Snap.** Attach to a Flatpak app and a Snap app from the
  host (same user and root). Fills C1 to C3, then C6 where permitted; anything
  the sandbox forbids becomes `X` with the kernel/LSM reason.

### Wave 2: frontend breadth

- **2.1** For every row whose backend cells are at `B`, add GUI, CLI and Lua
  smoke checks: x32, ARM32/Thumb, Wine (all three), CEServer, GDB guest,
  containers. Done when: C10 is at least `B` on each of those rows.

### Wave 3: architectures

- **3.1 ARM32 full session.** DebugSession ownership, hardware watchpoints
  (`PTRACE_SETHBPREGS`), call/injection adapters, frontends. Fills the ARM32 row.
- **3.2 RISC-V64.** Registers, software breakpoints, syscall injection, native
  call and disassembly (Capstone) in a QEMU full-system guest. Assembly falls
  back to explicit `X` where Keystone has no RISC-V support.
- **3.3 MIPS, PPC64LE, s390x at `B`.** Attach, read/write, scan, disassembly
  and a software breakpoint in QEMU guests. s390x doubles as the big-endian
  data-path check.
- **3.4 ARM64EC/ARM64X.** Classification and explicit errors only (`X`): there
  is no way to execute hybrid PE modules on this host.

### Wave 4: managed runtimes

- **4.1 perf-map JIT symbols.** One adapter for `/tmp/perf-PID.map`, which
  HotSpot, CoreCLR (`DOTNET_PerfMapEnabled=1`), V8 (`--perf-basic-prof`) and
  LuaJIT can emit. Fills C1 and C5 for JVM, CoreCLR and V8 at once.
- **4.2 Go.** `pclntab` symbols on stripped binaries, goroutine-aware notes
  on watchpoints (a writer can migrate between OS threads).
- **4.3 Logical objects.** Read-level field access for one non-Mono runtime
  (CoreCLR first: closest to the existing Mono work). Moving-GC limitations
  are reported, not hidden.

### Wave 5: remote and emulated

- **5.1 CEServer upstream interoperability.** The official Windows CE client
  (under Wine) connected to our `ceserver`, and our client against an upstream
  `ceserver` built from CE sources.
- **5.2 GDB guest MMU.** Guest page-table translation (x86-64 and ARM64) so a
  logical guest process can be scanned, not just physical RAM.
- **5.3 Console emulators.** Validate the existing guest-RAM adapters against
  real emulators running legal homebrew (for example Dolphin, PCSX2, PPSSPP).

### Wave 6: distributions, kernels and stress

- **6.1** Build and run the core suite in Debian stable, Ubuntu LTS, Fedora,
  Arch and Alpine containers, one at a time with a shared cache.
- **6.2** Run the native gate on older LTS kernels (5.15, 6.1, 6.6) in guests.
- **6.3** Bounded concurrency stress and a ThreadSanitizer job.
- **6.4** Controlled thread and resource exhaustion.

### Wave 7: deep recovery tail

The remaining area-5 items from PROGRESS.md (live `PTRACE_EVENT_EXIT` windows,
surviving old-mm peers, nonleader group death, ambiguous ESRCH ownership,
bounded syscall waits). Prioritize any that a Wave 1 to 6 item exposed.

## Out of reach (stay `X`, keep the explicit error)

- Physical ARM hardware checks (guests and compat kernels only).
- Executing ARM64EC/ARM64X modules.
- GPU memory and live Vulkan overlay checks without a GPU in CI.
- Kernel-enforced denials: Yama `ptrace_scope` 3, seccomp, LSM policies.
- Anti-cheat protected games: out of scope by project policy.

## Progress log

Record each finished item here (date, item, cells changed, commit), newest
first. Detailed write-ups continue in PROGRESS.md.

- 2026-10-12, **0.1** done: unreaped-service recovery and shutdown verified on
  x86-64 and i386 (24 assertions per ABI, normal and sanitizer builds). No
  matrix cells change; this closes the planned area-5 work before Wave 7.
- 2026-10-12, **0.2** done: `docs/compatibility-matrix.json` seeded from the
  existing gates (conservatively: partial evidence counts as `B`, unit-only
  as `-`), `tools/coverage_matrix.py` renders COMPATIBILITY.md and is checked
  by `ci-check.sh --config` and CI. Baseline: coverage 66/268 (25%), depth
  7/268 (3%). Notable gap: pointer scan has no live test on any target.
- 2026-10-12, **0.3** done: refused ptrace, allocation, protection, hook,
  watchpoint and trace operations name their capability reason in the GUI
  (debugger, code finder, tracer), CLI (`watch`) and Lua. Verified on a real
  target held by another debugger (`blocked_target_gate.py`,
  `gui_debugger_smoke blocked=1`).
- 2026-10-12, **1.1** done: real Proton (Valve 9, Experimental 11 locally;
  GE-Proton11-7 in a new hosted job) passes the full Wine driver, which now
  also scans and pointer-scans. Proton C1 to C6 and C8 to `B`; C3/C4 to `B` on
  all Wine rows. Coverage 79/268 (29.5%).
- 2026-10-12, **1.2** done: Proton 9 (sniper) and Experimental 11 (SLR 4)
  pass the full driver inside the real Steam Runtime container; the hosted
  job adds pinned SLR 4 with GE-Proton11-7. Steam Runtime row C1 to C6 and C8
  to `B`.
- 2026-10-12, **1.3** done: all-stop debugger (breakpoint, mode-correct
  context, single step, removal, detach) and break-and-trace on Wine 11 and
  both Proton builds, host and Steam Runtime. C9 to `B` on five Windows rows.
- 2026-10-12, **1.6** done: real libc programs (static musl/glibc, dynamic
  glibc, i386) pass 12 frontend checks each; fixed CE `#`/`$`/letter-hex
  operands and process-symbol names in the Auto Assembler. Coverage 103/268
  (38.4%).
- 2026-10-12, **1.7** done (Snap untestable here): Flatpak, bubblewrap and
  Podman sandboxes pass the 12 frontend checks with host-PID resolution;
  bubblewrap and Podman also in CI. Coverage 125/268 (46.6%).
- 2026-10-12, **2.1** started: a generic GUI target mode covers the static
  libc, Flatpak, bubblewrap and Podman rows (C10 to `B`). Coverage 129/268
  (48.1%).
- 2026-10-12, **2.1** Windows rows: Wine 11 and Proton 9/11 (host and Steam
  Runtime) pass CLI, Lua and GUI frontend checks; native calls are refused
  with the explicit Wine reason. C10 to `B`, C7 to `X` on five rows. Coverage
  139/268 (51.9%).
- 2026-10-12, **C7 on libc rows**: Lua symbols load on first use; explicit
  parked and static-program refusals; `executeCode` and `injectLibrary`
  verified on live programs. Coverage 142/268 (53.0%).
- 2026-10-12, **CEServer row**: `cescan ceserver` exposes the server; Lua
  `autoAssemble` returns disable info and can undo; scans, pointer scan and
  hooks verified over the transport. Coverage 146/268 (54.5%).
- 2026-10-12, **4.1** done for V8 and HotSpot: perf-map JIT symbols, and
  Node/JVM pass 9 frontend checks each (CoreCLR/LuaJIT use the same loader,
  not yet verified live). Coverage 163/268 (60.8%).
- 2026-10-12, **4.2** done: a Go program passes every frontend check
  (pclntab-only stripped binaries still pending). Coverage 173/268 (64.6%).
- 2026-10-12, **3.2** (B level): cecore runs inside a real RISC-V64 guest:
  identification, symbols, writes, scans, pointer scan and disassembly pass;
  new `isa-compatibility` workflow. Coverage 186/268 (69.4%).
- 2026-10-12, **3.3** (B level for s390x and ppc64el): real guests pass all
  checks; big-endian ELF symbols on big-endian hosts fixed. Coverage 191/268
  (71.3%).
- 2026-10-12, **3.1 / Wave 2**: armhf and x32 guests pass (ARM32 C2 to C5,
  x32 C3/C4); GDB CLI on real QEMU and guest pointer paths (GDB C4, C10).
  Coverage 212/268 (79.1%).
