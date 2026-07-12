# Changelog

All notable releases of Cheat Engine for Linux (a Linux-native C++/Qt6
reimplementation of Cheat Engine).

> **Repository note (2026-07-11):** the repository was consolidated into a
> single top-level repo with a fresh git history (the earlier upstream-CE
> Pascal fork and the separate project history were collapsed). The
> per-version notes below are preserved here because that rewrite dropped the
> original release tags. Build instructions in old release notes that referred
> to a `cecore/` subdirectory or an `../Cheat Engine` Pascal checkout no longer
> apply; the project now builds from the repository root.

---

## v0.3.0 — Complete interactive debugger, ceserver, and security hardening (2026-07-12)

A large release that finishes the interactive debugger, turns cecore into a
remote-debug **server**, and closes the untrusted-`.CT` security gaps. Every
change below shipped CI-green (build + ASan/UBSan) with backend tests and a
headless offscreen-Qt GUI smoke test.

### Interactive debugger — complete (#15, #16)

- **Real Lua `debug_*` API** (was a facade): `debug_setBreakpoint` plants a real
  software breakpoint through a `LuaEngine`-owned `DebugSession`; hits are queued
  on the tracer thread and drained by `debug_pumpEvents` on the Lua thread, which
  publishes the register context and fires the CE-compatible `debugger_onBreakpoint`.
  The handler can **read and rewrite registers**; `debug_removeBreakpoint` unplants.
- **Hardware data watchpoints**: a non-zero `type` arms DR0-3 on every thread; the
  event loop reports the watched address on `TRAP_HWBKPT` and disarms the debug
  registers before detach (verified: the tracee survives detach).
- **Debugger window**: editable GP/R8-R15/**XMM** registers, a thread switcher,
  a memory/hex pane, and a disassembly right-click menu (set breakpoint / NOP).

### Be a ceserver, not just a client (#24)

- New `CeserverServer` serves the CE ceserver protocol over TCP:
  GETVERSION, OPENPROCESS, CLOSEHANDLE, READ/WRITEPROCESSMEMORY, VIRTUALQUERYEXFULL
  (regions), GETARCHITECTURE, and CREATETOOLHELP32SNAPSHOTEX (threads + modules).
  A remote CE (or another cecore) can now attach for memory access and inspection.

### Security hardening (#6)

- `shellExecute` and the `write*Local` self-memory functions are **default-deny**,
  enabled only by the out-of-band `CECORE_LUA_ALLOW_UNSAFE=1`.
- Every Lua binding is wrapped by a central exception firewall (a C++ exception
  can no longer unwind through liblua's C frames).

### Analysis, symbols, and formats

- "Find what addresses this instruction accesses" (`findInstructionAccesses`),
  the `computeEffectiveAddress` primitive, and length-preserving NOP with undo.
- Multi-thread all-stop Break&Trace; build-id / `.gnu_debuglink` stripped-symbol
  resolution; pointer rescan-by-value.
- Embedded `<Forms>` are now preserved across `.CT` load/save.
- Lua additions: `getRegionInfo`, `getNameFromAddress` (hex fallback),
  `nopInstruction`, `getSymbolInfo`, `reinitializeSymbolhandler`.

---

## v0.2.1 — AOB injection fix + 32-bit/WoW64/Wine support (2026-07-10)

A correctness release headlined by a fix that makes **AOB injection scripts
actually work**, plus the 32-bit / WoW64 / Wine support that landed since v0.2.0.

### Headline fix — AOB injection scripts

The standard auto-assembler idiom
(`aobscanmodule(INJECT, game, <pattern>)` + `alloc` + `INJECT: jmp newmem`)
silently failed to patch its target. The auto-assembler's label pre-pass built
its "already declared" set from `alloc`/`define`/`registersymbol`/`label` but
**not** the `aobscan` family, so it auto-declared a phantom `label(INJECT)` that
shadowed the scanned address with a zero-address forward label. The injection
`jmp` and stolen bytes were written into the code cave instead of over the
target instruction, while `execute()` still reported success.

Now the result name of `aobscan` / `aobscanmodule` / `aobscanregion` /
`aobscanall` resolves to the scanned address when used as an injection label, so
`INJECT:` lands the hook where it belongs. AOB *scanning* was always correct;
only the inject-label binding was broken. Verified end-to-end on **64-bit
no-PIE, 64-bit PIE (ASLR), and 32-bit** targets, guarded by a regression test
(`test_autoassembler_aobscan_inject_label`).

### Also since v0.2.0

- **32-bit code injection (WoW64).** Detects 32-bit code execution,
  assembles/disassembles caves in the target's actual code bitness, and uses a
  CS-aware remote syscall so hooks and allocations work in 32-bit and WoW64
  processes.
- **Wine / Proton targets.** Enumerates Wine PE modules with correct WoW64
  attribution and bitness, so `aobscanmodule(name, game.exe, ...)` resolves
  against the right module.
- **Injection reliability.** Fixed a ptrace self-conflict that could block code
  injection outright.
- **Auto-assembler workflow.** Pre-filled injection templates from the memory
  browser, syntax-highlighted AA scripts, and saving AA scripts as toggleable
  cheat-table entries.
- **Scanning & UI.** Live progress bar during threaded scans, save/export
  code-finder findings, and a simplified Open Process picker.

Single-player and reverse-engineering focus; does not target multiplayer
anti-cheat. Regression suite: 233 assertions.

---

## v0.2.0 — Real-time results, CE-parity scanning, hardened core (2026-07-06)

A large stability, correctness, and feature release. The project now covers the
full Cheat Engine workflow natively on Linux, with nine subsystems independently
audited and every reported defect verified and fixed with a regression test
where practical.

### Highlights

- **Real-time scan results.** The scan-result and address lists refresh live
  from target memory (500 ms), highlight changed values, and cost nothing on
  million-row result sets because only the visible rows are re-read. F5 forces
  an immediate refresh.
- **CE-parity float scanning.** Float scans default to "Rounded" and match at
  the entered decimal precision (within half the last place), like Cheat Engine.
- **Persistent disassembler annotations.** User comments and labels are saved
  with the cheat table (`.CT` and JSON), keyed module-relative so they survive
  ASLR.
- **Batch address-list editing.** Set the value of every selected entry at once,
  alongside batch freeze-mode and type changes.
- **Complete auto-assembler template set** (Ctrl+I): Allocate memory, Code
  injection, AOB injection, Full code injection, Pointer injection, Cheat table
  framework, and Lua script.

### Correctness and safety fixes

Nine subsystems were reviewed line by line (Lua bindings, auto-assembler,
disassembler, pointer scanner, scan-comparison engine, ptrace/injector platform
layer, ELF/DWARF parsers, scan-result storage, analysis). Notable fixes:

- **Platform:** near-allocation used `MAP_FIXED` where `MAP_FIXED_NOREPLACE` was
  intended (could silently unmap and crash a live target region);
  `createRemoteThread` now quiesces sibling threads to avoid a loader-lock
  deadlock; hardware-breakpoint `PTRACE_PEEKUSER` reads now clear/check `errno`.
- **Scanner:** the "all types" scan stored variable-width records that desynced
  from the address list and crashed next-scan (now uniform records); short
  backing-file writes (disk full) are detected instead of returning zeroed
  garbage; sharded pointer scans read all regions so a path through a static
  intermediate is never lost.
- **Auto-assembler:** a failed line during execute now rolls the target back
  cleanly instead of leaving a half-applied hook; `//` comment stripping is
  quote-aware so `db "http://x"` survives.
- **Lua:** fixed a use-after-free of the Lua state through GUI timer/widget
  callbacks on shutdown, bounded file reads, non-throwing filesystem calls,
  target-width pointer reads, and an uncapped scan-result table.
- **Debugger:** breakpoint conditions from untrusted tables now run in a
  sandboxed, execution-bounded Lua state and can no longer hang the debugger.

~40,000 lines across ~158 files; 229-assertion regression suite.

---

## v0.1.1 — PortProton/Lutris/Heroic support + deferred-list catch-up (2026-05-21)

Patch release with a stack of features and fixes since v0.1.0. **Most relevant
user fix:** PortProton / Lutris / Heroic / Bottles Wine-wrapped games now show up
in the Open Process dialog
([#2](https://github.com/wleeaf/cheat-engine-linux/issues/2)).

### Fixes

- **PortProton / Lutris / Heroic / Bottles compatibility** — process enumerator
  now picks up Wine-wrapped games regardless of what their `/proc/<pid>/comm`
  reads; filter and tooltip prefer the recognisable `.exe` name from `cmdline`.
- **CI hardening** — DWARF code path compiles cleanly with `libdw-dev` (was
  missing `<dwarf.h>`).

### New features since v0.1.0

- **Auto-assembler:** `{$if}/{$else}/{$endif}` conditionals; `@@:` anonymous
  labels with `@F`/`@B`; `globalalloc()` and `break`; inline `{$ccode}` blocks
  via libtcc.
- **Debugger:** LBR tracer via `perf_event_open` + Branch Mapper window; Intel PT
  raw-capture wrapper; follow fork/vfork/clone/exec; ARM64 + ARM32 CONTEXT
  marshalling; ceserver `CMD_GETSYMBOLLISTFROMFILE`; in-process VEH shim.
- **Analysis & symbols:** find-statics pass; DWARF function-name lookup in the
  disassembler pane.
- **GUI:** Form Designer (visual Lua-trainer builder); File Patcher; ELF
  Inspector; Snapshot/freezer engine; Process Watcher auto-attach.
- **Lua:** `Stream` and `StringList` userdata; `setProcessName`/`getProcessName`.
- **Process-name camouflage** (documented limits): `prctl(PR_SET_NAME)` binding
  plus optional kernel-side `/proc/<pid>` filtering via `cecore_kmod`
  (CAP_SYS_ADMIN, up to 32 PIDs). Does **not** defeat multiplayer anti-cheat.
- **Speedhack:** now covers `clock_nanosleep`, `usleep`, `sleep`, `select`,
  `poll`, `SDL_GetTicks`, `SDL_Delay`.
- **Network:** Mono soft-debugger client. **i18n:** `QTranslator` scaffolding.
  **GPU:** `CudaSearch` foundation (gated behind CUDA).

---

## v0.1.0 — first tagged release (2026-05-08)

First tagged release: Linux-native C++23/Qt6 reimplementation of Cheat Engine.
Build green on Ubuntu 24.04, regression suite passing, the surface below
exercised end-to-end via tests or interactive use.

- **Memory scanning:** numeric / string (UTF-8/Unicode/codepage via iconv) / AOB
  (`??` wildcards) / binary (bitmask) / all-types / grouped / custom Lua-formula;
  full compare-op set; float rounding modes; multi-threaded with progress +
  cancellation; disk-backed result buffers.
- **Pointer scanning:** reverse-BFS path discovery with depth/offset/alignment/
  static-only filters; distributed sharding; save/load, sort, dedup-merge,
  rescan against a new target.
- **Debugger (local + remote):** ptrace attach; software int3 + hardware DR0-3
  breakpoints; conditional Lua breakpoints, one-shot, thread-filtered;
  single-step (Into/Over/Out), break-and-trace; frame-pointer stack trace;
  GDB remote client; full **ceserver** remote target support.
- **Auto-assembler:** `alloc` (±2GB near-alloc), `dealloc`, multi-pass labels;
  `aobscan*`; data directives; `loadbinary`/`loadlibrary`/`createthread`;
  `struct/endstruct`; `{$try}/{$except}`; `{$lua}...{$asm}` preprocess blocks;
  plugin-extensible commands.
- **Code analysis:** module dissect + call graph; referenced strings;
  RIP-relative scan; code-cave detection; assembly-pattern scan;
  find-what-accesses/writes with per-hit register snapshots.
- **Cheat tables:** CE-compatible `.CT` XML; password-wrapped `.CETRAINER`;
  embedded enable/disable AA + Lua scripts; persisted structure definitions;
  standalone trainer generator.
- **Lua (5.3):** typed memory R/W; `AOBScan`; `assemble`/`disassemble`/
  `autoAssemble`; process/module/thread enumeration; `MemoryRecord`/`AddressList`
  userdata; GUI component factory; hotkeys, threads, custom types, structures.
- **GUI (Qt6):** process selection + inline scan controls; memory browser (hex +
  disassembler split, symbol + RIP-relative + DWARF source-line annotations);
  find-what-accesses window; tracer; breakpoint list; register editor (incl. FPU);
  thread/stack/regions/heap/module/xref views; six-tab settings; ceserver
  connect; Lua console; Catppuccin dark theme.
- **Symbols:** ELF `.dynsym`/`.symtab`; `module!symbol+offset` arithmetic;
  `/proc/kallsyms`; optional DWARF line tables via libdw.
- **Plugin ABI:** structured C ABI (`plugins/cecore_plugin.h`) with a host
  callback vtable; legacy symbol-based ABI as fallback.
- **Network / remote:** ceserver TCP client (24 of ~40 wire commands);
  `RemoteProcessHandle`/`RemoteDebugger` adapters; zlib compression; GDB client.
- **Optional kernel helper:** `cecore_kmod` with CAP_SYS_ADMIN-gated ioctls for
  privileged VM access and phys-mem R/W. Process hiding intentionally omitted.
- **Speedhack:** LD_PRELOAD time-function intercept with a live shared-memory
  multiplier. **Vulkan overlay:** explicit loader layer + X11 click-through OSD.

**Known limits at the time:** no kernel process hiding (rootkit-style stealth is
out of scope); DWARF needs `libdw-dev`; ARM/ARM64 backend not exercised in tests;
Form Designer not yet implemented; ceserver `get/setThreadContext` x86_64-only.

Thanks to @Twig6943 for prompting the build polish that made this release
possible (#1).
