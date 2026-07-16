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

## Unreleased

### Performance

Heavy optimization of the memory scanner (finding values), with no change to
results (verified against a brute-force reference across every value width,
alignment, comparator, and both scan phases, and clean under ASan/UBSan).

- **Cache-blocked first scan (~3x).** A worker read a region in 8 MiB chunks,
  then scanned each chunk — but by scan time the chunk had been evicted from
  cache and was re-fetched from RAM, so the value read cost twice. Reading in
  small (128 KiB) chunks instead keeps the just-read data hot in L2 for the scan
  (and the small reused read buffer stays cached too), so a 1 GiB scan runs at
  ~13 GB/s instead of ~3.5. On this machine a sparse 1 GiB first scan dropped
  ~0.28s to ~0.083s. Tune with `CE_SCAN_CHUNK_KB` if a different cache size
  wants a different block.

- **First scan now uses every core on a single big region.** Work was split
  per memory region, so a process dominated by one large heap/mapping (common in
  games) scanned on a single thread. Scanning is now split into fixed-size
  chunks handed to threads as contiguous, address-ordered runs, so one big
  region saturates all cores while the merged result stays sorted. Roughly 5x
  faster on a one-region scan on a 12-thread machine.
- **SIMD exact-value scan.** The hot path (an exact integer or float/double
  over an aligned buffer) is vectorized with a runtime-selected AVX2 path and an
  SSE2 baseline (scalar elsewhere), replacing a per-element function-pointer
  compare. Float equality uses an ordered SIMD compare that matches C++ exactly
  (NaN never matches, -0.0 equals 0.0); rounded/tolerant searches keep the
  scalar path. Set `CE_SCAN_SIMD=off|sse2|avx2` to override for testing.
- **Next scan is batched and multi-threaded.** Re-reading previous results used
  one `process_vm_readv` syscall per address on a single thread; it now reads up
  to 1024 addresses per syscall (scatter read) and fans big result sets across
  cores.
- **Coalesced next-scan reads (~14x on contiguous results).** Even batched, the
  scatter read described each address as its own tiny iovec, so a dense result
  (consecutive matched values, e.g. after an unknown-value scan, or an array
  field) cost the kernel millions of size-byte copies. Back-to-back addresses
  are now merged into one large iovec per run, so the kernel does one big copy
  instead. A 16.7M-result contiguous next scan dropped ~1.7s to ~0.12s;
  scattered results are unaffected. Around 8x faster on a large result set (and it degrades gracefully:
  handles that cannot be read concurrently, e.g. a socket-backed ceserver
  handle, stay single-threaded, which also fixes a latent first-scan data race
  on those handles).
- **Skip reserved-but-untouched memory on first scan.** Games map large address
  ranges they never touch; those pages are demand-zero, and we were reading every
  one of them. The first scan now consults `/proc/pid/pagemap` and reads only the
  resident/swapped pages of anonymous regions, coalesced into runs. On a sparse
  512 MiB region with a handful of touched pages that is ~80x faster; it does not
  change results and is guarded three ways: only when an all-zero window can't
  match the search (so 0/unknown searches still read everything), only when a
  value can't straddle a page (aligned scans), and only for anonymous mappings
  (a file-backed page still holds file data). Falls back to a full read if
  pagemap is unavailable. Override with `CE_SCAN_PAGEMAP=off`.
- **First scan stores its value stream once.** On a first scan every match's
  "first value" equals its current value, yet both streams were written to disk,
  duplicating a third of the output for a 4-byte type. The first scan now skips
  the `first_values` stream and reads fall back to `values` (a later next scan
  writes distinct first-values as before). About 25% less first-scan output; a
  dense 16.7M-result first scan drops ~0.099s to ~0.074s.
- **Compact result addresses (half the size).** A matched address was stored as
  8 bytes; it is now a 4-byte offset from a per-shard frame base (a new frame
  opens only when an address is >= 2^32 past the base, so usually one frame per
  region). `address = frameBase + offset`. This halves the address storage of
  every result, so the tool holds roughly twice as many results in the same
  RAM/temp space, and large scans that spill past the OS page cache to real disk
  are faster. On results that fit in cache the wall-clock is unchanged (these
  scans are not disk-bound). Public `ScanResult` API is unchanged.
- **No result-merge copy.** A scan wrote each worker's matches to its own file
  and then concatenated them into one merged file, so every result byte was
  written twice and read once more. The result now references the worker files
  in place through a small manifest (`ScanResult` reads transparently across the
  shards), which cut a dense first scan (16.7 M results) from ~0.44 s to ~0.10 s
  and shaved the large next scan further. Public `ScanResult` API is unchanged.
- Smaller win: results are appended without a redundant zero-fill.

## v0.5.0 — Mono/Unity dissector, diagnostics, Lua table compatibility, debugger polish (2026-07-14)

Feature release. The headline is a native **Mono/Unity dissector** (the biggest
gap vs Cheat Engine for Linux gaming), plus a diagnostic logging system, a large
batch of Lua functions real cheat tables need, `.CT` round-trip fixes verified
against real downloaded tables, and a round of interactive-debugger polish.

### Added

- **Native Mono dissector (live).** An injected in-process agent
  (`libcecore_mono_agent.so`) queries the Mono runtime for ground-truth class and
  field layout (real offsets, types, static flags). Host side injects + parses it
  into a model; browse it in **Tools ▸ Mono dissector...** (assemblies → classes →
  fields, filter, double-click a field to add `base+offset` to the address list),
  or from Lua via `monoDissect()`. `findMonoFunction(ns, class, method)` resolves a
  method's address on demand (targeted JIT compile via the resident agent, never
  mass-compiles). IL2CPP targets are detected and reported (live IL2CPP dissection
  is a separate track).
- **Diagnostic logging (`CE_LOG`).** Silent by default; `CE_LOG=ptrace:debug`
  (per-category) or `CE_LOG=debug` and `CE_LOG_FILE=/path` turn on cecore logging
  with no rebuild — e.g. the exact `process_vm_readv` error behind a blank memory
  pane.
- **Lua functions real tables use:** `isKeyPressed` (evdev), the timer API
  (`createTimer`/`timer_setInterval`/`timer_onTimer`), `createStringlist` +
  `stringlist_*`, `selectFilePath`, `playSound`, and `createSimpleHook` /
  `removeSimpleHook` (a safe jmp-detour hook that refuses to patch
  position-dependent code rather than corrupt it).
- **Debugger:** conditional breakpoints (a Lua expression over register state;
  the debugger auto-continues when it's false), hardware **data breakpoints**
  (break on write/access), a **Break-on-exceptions** menu (SIGSEGV/…), breakpoint
  **enable/disable** checkboxes and **hit counts**.
- **Memory Viewer** got its own CE-style menu bar and a **stacktrace** panel; its
  step buttons now open the Debugger instead of being dead stubs.

### Fixed

- **`.CT` compatibility.** Tables are detected by content, not a case-sensitive
  extension, so an uppercase `GAME.CT` or a mislabelled table loads. Fixed three
  saver bugs found against 14 real downloaded tables (address over-escaping,
  Auto-Assembler records mis-typed, negative pointer offsets dropped); all 14 now
  round-trip faithfully.
- **Theme.** The auto-assembler console and other custom-painted widgets (structure
  dissector, scan-results highlight, form-designer canvas, disassembler-preference
  swatches) now follow light/dark instead of being hardcoded dark.

---

## v0.4.1 — Theme, memory-access, and packaging fixes (2026-07-13)

Bug-fix release on top of v0.4.0.

### Fixes

- **Light/dark theme now works.** Toggling "Dark theme" in Settings applies live
  (no restart), and the startup default and the Settings checkbox agree (both
  default to light). The two stylesheets moved into a shared `gui/theme` module so
  startup and the dialog use the same sheets.
- **Memory browser no longer fails silently.** When a process can't be read
  because of the kernel's ptrace policy (`kernel.yama.ptrace_scope`), the
  disassembler shows a clear explanation instead of a blank pane, and opening such
  a process pops a warning naming the exact remedies. This is why "browse memory"
  appeared to work only on some processes.

### Packaging

- **Automatic ptrace access.** The `.deb` now runs `setcap cap_sys_ptrace+ep` on
  the installed binaries at install time (via a postinst; depends on `libcap2-bin`),
  so scanning/browsing/debugging works without running as root. For AppImage or
  ad-hoc runs, the "process not readable" dialog has a one-click **Grant access…**
  button (via `pkexec`).
- **Working AppImage.** The AppImage is now built with linuxdeploy + the Qt plugin,
  so it bundles the Qt platform plugins and actually runs (the earlier hand-rolled
  bundle was missing them).

## v0.4.0 — CLI / headless parity for every GUI tool (2026-07-13)

Everything the GUI can do is now doable from the terminal. The guiding principle:
a GUI action must only gather input and call a shared core function (in `cecore`
or exposed via Lua), never hold its own copy of the logic, so the terminal path
and the GUI path run the same code and any GUI-only failure is provably a GUI bug.
Every item below is exercised by an automated test in `cecore_test`
(`test_lua_headless_bindings`, `test_lua_ceserver_connect`, `test_trainer_generation`);
the full suite is green.

### Headless runner

- **`cescan lua <file> | -e "<code>" | -`** plus a REPL — runs the same `LuaEngine`
  the GUI console uses, backed by a headless in-memory address list, so the whole
  Lua API (now ~205 functions) works from the terminal.

### New Lua tool bindings (each calls the same core code as the GUI)

- **Cheat table:** `saveTable(path)` / `loadTable(path)` (the GUI's `.CT`/JSON format).
- **Create trainer:** `generateTrainer(path)` compiles a standalone trainer binary;
  `generateTrainerSource()` returns the C source.
- **Pointer scanner:** `pointerScan(target[, maxDepth[, maxOffset[, opts]]])`.
- **Structure dissect:** `dissectStructure(addr | {addrs}, size)` — the
  discriminating-field detector across N instances.
- **Detect Mono/.NET:** `getManagedRuntimes()`.
- **Find what accesses / writes:** `findWhatWrites` / `findWhatAccesses`
  (hardware data watchpoint via the code finder).
- **Break and trace:** `breakAndTrace(start[, maxSteps[, opts]])`.
- **Branch mapper:** `branchMap([secs[, tid]])` / `branchMapAvailable()` (hardware LBR).
- **Debug register / stack:** `debug_getRegisters` / `debug_setRegister` /
  `debug_getStack`; `debug_pumpEvents` now publishes the full GP register set.
- **Find statics:** `findStatics([module])`.
- **Connect to ceserver:** `connectToCeserver(host, port, pid)` installs a remote
  process as the target so the whole read/write/scan API works over the network.
- **Address-list grouping:** `createGroup([desc])` and memory-record `.Indent`
  (indent / outdent).

### Fixes

- **Trainer code generation:** a whole-number float value (e.g. `9999`) was emitted
  as `9999f` — an invalid integer-with-`f`-suffix that failed to compile. Now forces
  a fractional part (`9999.0f`), guards against inf/nan, and defines `_GNU_SOURCE` in
  the generated source so `process_vm_readv`/`writev` use their real `ssize_t`
  prototype (was implicitly declared, truncating the 64-bit return on x86-64). This
  also fixed the GUI's Create Trainer.

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
