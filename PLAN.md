# Cheat Engine — Linux-Only C++ Rewrite

**Tech Stack:** C++23, Qt6, CMake, Capstone, Keystone, Lua 5.3  
**Current state:** 6190 lines, 48 source files — core engine working  
**Target:** Full CE feature parity (~25K-30K lines estimated)

---

## What's Built (Phase 1-9, complete)

| Component | Lines | Status |
|-----------|-------|--------|
| Platform APIs (process_vm_readv, /proc, ptrace) | 470 | Done |
| Ptrace debugger + HW breakpoints (DR0-3) | 200 | Done |
| Multi-threaded memory scanner (8 types + string + AOB) | 500 | Done |
| Capstone disassembler wrapper | 110 | Done |
| Keystone assembler wrapper | 90 | Done |
| Auto-assembler (alloc, label, define, aobscan, db, enable/disable) | 570 | Done |
| ELF symbol resolver | 200 | Done |
| Pointer scanner (reverse BFS) | 260 | Done |
| Expression parser | 100 | Done |
| Lua 5.3 engine + 10 CE bindings | 250 | Done |
| Plugin system (.so loader) | 100 | Done |
| .so injector (ptrace + dlopen) | 150 | Done |
| Speedhack (LD_PRELOAD, clock_gettime/nanosleep interception) | 130 | Done |
| cescan CLI (all commands) | 490 | Done |
| Qt6 GUI: main window, process list, scan, address list, memory browser, script editor, pointer scan dialog, structure dissector, Lua console | 2250 | Done |
| Dark Catppuccin theme | 50 | Done |
| AppImage packaging script | 50 | Done |
| **Total** | **~6200** | |

---

## What's Missing (gap analysis vs original CE)

### Tier 1 — Critical for Real Usage (~8K lines, 4-6 weeks)

**1.1 Complete Scan Engine**
- [x] Binary scan with bitmask wildcards
- [x] "All Types" scan (vtAll) — scan byte/word/dword/qword/float/double simultaneously
- [x] Grouped scan — multiple value types in one pass with offsets
- [x] Custom Lua formula scan (`soCustom`)
- [x] Percentage-based comparisons (increased by %, between %)
- [x] Float rounding options (rounded, truncated, extreme)
- [x] Unicode string scan (separate from UTF-8)
- [x] Codepage-aware string scan
- [x] "Same as first scan" comparison
- [x] Pointer-type scan

**1.2 Complete Debugger**
- [x] Conditional breakpoints (Lua expression-based)
- [x] "Find what accesses this address" (log all instructions reading an address)
- [x] "Find what writes to this address" (log all instructions writing an address)
- [x] Break and trace (step N instructions, log each, with filters)
- [x] Exception breakpoints (SIGSEGV-based memory access detection)
- [x] Thread-specific breakpoints
- [x] One-time breakpoints (auto-remove after hit)
- [x] Breakpoint list manager window
- [x] Stack trace window
- [x] Register editor window (modify registers live)
- [x] Floating point register panel (XMM/YMM)

**1.3 Complete Auto-Assembler**
- [x] `createthread(address)` — remote thread creation via ptrace
- [x] `createthreadandwait(address, timeout)`
- [x] `include(file.cea)` — script inclusion
- [x] `reassemble(address)` — disassemble + reassemble for relocation
- [x] `struct name ... ends` — structure definitions with size calculation
- [x] `{$try} ... {$except}` — exception handling regions
- [x] `loadlibrary(path)` — .so injection from scripts
- [x] `loadbinary(address, file)` — binary file loading
- [x] Forward label resolution with NOP padding (multi-pass)
- [x] Near-allocation preference (within ±2GB for short jumps)
- [x] Custom registered commands (plugin-extensible)
- [x] Auto-assembler prologues (pre/post processing hooks)

Completed in the 2026-04-24 main merge:
- `aobscanmodule`, `aobscanregion`, and `aobscanall`
- `ds`, `nop`, and `fillmem`
- `db`/`dw`/`dd`/`dq` little-endian width enforcement with overflow errors
- `fullaccess`, `assert`, enable-time `dealloc`, and enable-time `unregistersymbol`
- strict unresolved-target errors and fixed `symbol/address+offset` resolution

Note: `loadlibrary(path)` now uses the Linux ptrace/dlopen injector from auto-assembler scripts, validates the target .so path, and has a regression test against the built speedhack plugin.

Note: custom auto-assembler commands can now be registered from C++ with case-insensitive names; handlers can expand into normal auto-assembler lines, append log entries, and fail syntax checking with explicit errors.

Note: auto-assembler preprocessor and postprocessor hooks now transform the extracted enable section for both execution and syntax checks, with explicit hook failure errors.

Note: auto-assembler `struct ... ends`/`endstruct` blocks now calculate field offsets and struct sizes, exposing both `struct.field` and plain field names as script symbols.

Note: auto-assembler forward labels now resolve through a bounded multi-pass sizing step before injection, so jumps over later NOP/data padding assemble with stable target addresses.

Note: auto-assembler `createthread` and `createthreadandwait` now execute injected entry points through ptrace-driven remote `pthread_create`, using `pthread_tryjoin_np` for timeout-aware waits and detaching async workers.

Note: auto-assembler scripts now support `{$try}`, `{$except}`, and `{$endtry}` guarded regions. Guarded branches are selected before label resolution and writes; failed guarded assertions fall through to the except block, with malformed regions rejected by syntax checks.

Note: break-and-trace has regression coverage for start-address breakpoints followed by fixed-count single stepping with decoded instruction logging.

Note: debug sessions now support explicit signal exception breakpoints, with SIGSEGV stops delivered as exception-breakpoint events and covered by a forked faulting-process regression test.

**1.4 Memory Records (Address List)**
- [x] Freeze direction: increase only, decrease only, never decrease, never increase
- [x] Auto-inject on enable (run auto-assembler script when checkbox toggled)
- [x] Value increase/decrease by hotkey
- [x] Dropdown list for address entries (predefined value choices)
- [x] Parent-child hierarchy (tree structure in address list)
- [x] Color coding per entry
- [x] Custom type support (Lua-defined value interpreters)
- [x] Description editing inline
- [x] Copy/paste address entries

Note: address-list entries now support separate increase/decrease value hotkeys with configurable step sizes, persisted through JSON, `.CT`, and protected `.CETRAINER` table paths.

**1.5 Cheat Table Format (.CT)**
- [x] XML-based save/load (matching CE's format for compatibility)
- [x] Embedded Lua scripts in table
- [x] Embedded auto-assembler scripts
- [x] Structure definitions in table
- [x] Table metadata (game name, version, author)
- [x] Table encryption/protection for .CETRAINER format

Note: active auto-assembler records loaded from a table now run their enable script when a process is open; otherwise they are loaded inactive with a warning.

Note: cheat tables now persist named structure definitions and fields through both native JSON and `.CT` XML round trips.

Note: percentage comparisons are implemented for next scans, with CLI `--percent`/`--percent2` options and GUI next-scan controls.

Note: float rounding modes are implemented for Float/Double exact scans, exposed through CLI `--rounding`/`--tolerance` and GUI scan controls.

Note: same-as-first next scans now retain first-scan baseline values across result narrowing, with CLI `--compare samefirst` and a GUI scan-type option.

Note: pointer-type scans are implemented as native pointer-width value scans, exposed in CLI/GUI/Lua and covered by first/next scan tests.

Note: grouped scans are implemented for CLI/GUI/Lua with `type:value@offset` terms, including next-scan changed/unchanged/same-as-first behavior.

Note: custom Lua formula scans (`soCustom`) are implemented with per-result Lua predicates over raw value bytes (`current`/`old`), exposed in CLI/Lua and covered by regression tests.

Note: grouped/custom scan results preserve their dynamic value sizes in the GUI result table and undo flow.

Note: codepage-aware string scans use `iconv` to convert UTF-8 search text into a selected single-byte target encoding, exposed through CLI `--encoding`, GUI text encoding choices, and Lua optional scan arguments.

Note: scan ranges now clip overlapping memory regions to the requested start/stop bounds instead of skipping regions whose mapping starts before the scan start; this stabilizes self-scan tests when Linux merges adjacent anonymous mappings.

Note: the Stack Trace window now attaches to the selected thread, preserves the raw stack dump, and adds a frame-pointer call chain with symbol resolution plus a regression test for frame walking.

### Tier 2 — Important for Power Users (~6K lines, 3-4 weeks)

**2.1 Lua API Expansion (from ~10 to ~200 core functions)**
- [x] Memory: readByte, readSmallInteger, readQword, readPointer, readString (all variants)
- [x] Memory: writeByte, writeSmallInteger, writeQword, writePointer, writeString
- [x] Memory: local variants (readByteLocal, etc. for CE's own memory)
- [x] Process: openProcess, getProcessIDFromProcessName, getProcessList
- [x] Scanning: createMemScan, firstScan, nextScan, getFoundCount, getAddress
- [x] Assembly: autoAssemble, autoAssembleCheck, assemble, disassemble
- [x] Debug: debug_setBreakpoint, debug_removeBreakpoint, debug_continueFromBreakpoint
- [x] Debug: debug_getBreakpointList, debug_isDebugging, debug_isBroken
- [x] Symbols: registerSymbol, unregisterSymbol, getNameFromAddress, getAddressFromName
- [x] GUI forms: createForm, createButton, createLabel, createEdit, createCheckBox, createListView
- [x] GUI component properties: setProperty, getProperty, component.Caption, component.Visible, etc.
- [x] GUI events: OnClick, OnChange, OnClose, etc. bound to Lua functions
- [x] Utility: showMessage, inputQuery, messageDialog, getScreenCanvas
- [x] Timer: createTimer, timer.Enabled, timer.Interval, timer.OnTimer
- [x] File I/O: readFile, writeFile, getCheatEngineDir, getTempDir
- [x] Table: getTableEntry, setTableEntry, addressList manipulation
- [x] Hotkeys: createHotkey, setHotkeyAction
- [x] Threads: createThread (Lua thread), synchronize, queue
- [x] AddressList / MemoryRecord live object surface — getAddressList, addresslist global, AddressList:getMemoryRecord/getMemoryRecordByID/getMemoryRecordByDescription/createMemoryRecord/disableAllWithoutExecute, MemoryRecord property + method API (Description/Address/Type/Value/Active/Color/Script + getters/setters), OnActivate event slot dispatching back through IAddressList::setActivationCallback. Backed by core/address_list.hpp interface implemented by the Qt AddressListModel.

**2.2 Code Analysis**
- [x] Dissect Code — analyze a module's code sections
  - [x] Enumerate all functions (by call targets)
  - [x] Find referenced strings
  - [x] Find referenced functions
  - [x] Detect conditional/unconditional jumps
  - [x] Build call graph
- [x] Code cave scanner — find unused regions in module code
- [x] RIP-relative instruction scanner
- [x] Assembly scan — find specific instruction patterns

**2.3 Advanced Structure Dissector**
- [x] Nested structures (struct within struct)
- [x] Structure comparison (diff two snapshots)
- [x] Auto-detect fields by comparing changed/unchanged regions
- [x] Pointer chain following in structures
- [x] Custom display methods per field
- [x] Structure templates (save/load structure definitions)
- [x] Generate C/C++ struct definition from dissected layout

**2.4 Additional GUI Windows**
- [x] Breakpoint list manager
- [x] Thread list with register context per thread
- [x] Stack view (per-thread)
- [x] Referenced strings window
- [x] Referenced functions window
- [x] Memory regions window (full list with protection info)
- [x] Heap enumeration window
- [x] DLL/module list window
- [x] Settings dialog (all scan/debugger/display preferences)
- [x] Hotkey configuration dialog
- [x] Find dialog (Ctrl+F in hex view and disassembler)
- [x] Goto address dialog (Ctrl+G)

Note: referenced strings, referenced functions, function summaries, call graph edges, jumps, RIP-relative instructions, assembly pattern scanning, and code caves are exposed through a combined Code References window. The analyzer now resolves RIP-relative operands and direct call targets.

Note: heap enumeration is implemented as a Linux Heap Regions window over `/proc/<pid>/maps`, showing `[heap]` and writable anonymous private mappings.

Note: Lua utility bindings now include `messageDialog` modal-result constants and a headless `getScreenCanvas` canvas object with basic drawing/text methods for script compatibility.

Note: structure definitions now have reusable template save/load helpers and C/C++ struct export with padding, backed by regression tests.

Note: structure snapshot comparison now reports per-field before/after bytes and changed status for dissected structure definitions.

Note: structure tooling now auto-detects changed/unchanged field runs from snapshots and follows pointer fields into readable pointer chains through the process API.

Note: structure fields now persist optional display methods and can format snapshot values as hex bytes, signed/unsigned integers, floats, or pointers.

Note: structure fields now support nested structure references, persisted through JSON/`.CT` templates and emitted as nested field types in C/C++ struct export.

Note: Lua hotkey bindings now expose `createHotkey`/`setHotkeyAction` objects with key storage, enabled state, callback replacement, explicit trigger methods, and cleanup for headless script compatibility.

Note: Lua table/address-list bindings now include a headless address-list store with `getTableEntry`, `setTableEntry`, add/remove/clear helpers, and count queries for script compatibility.

Note: Lua debug bindings now expose headless breakpoint metadata state for set/remove/continue/list/isDebugging/isBroken; actual ptrace stop/resume behavior remains in the native debugger/session layer.

Note: Lua thread helpers now expose `createThread`, `synchronize`, and `queue` as main-state compatibility APIs with suspended/resumed thread objects, termination state, wait status, names, and callback error tracking.

Note: the address-list context menu now includes a hotkey configuration dialog backed by `QKeySequenceEdit`; configured keys are preserved in address-list JSON and .CT save/load conversion.

Note: .CT XML now writes CE-style textual variable types such as `4 Bytes`, `Float`, and `Array of byte`, while the loader still accepts older numeric type IDs for backward compatibility.

Note: the register editor now includes a read-only floating-point/SIMD panel populated from Linux `PTRACE_GETREGSET` xstate data, showing XMM low 128-bit values and YMM high 128-bit values when the target exposes AVX state.

Note: `.CETRAINER` save/load now supports a lightweight password-protected payload wrapper around the native JSON table format, with encrypted bytes, password verification, and wrong-password regression coverage.

Note: Lua-defined custom value types can now be registered with `registerCustomTypeLua`/`registerCustomType`, queried by name, converted from raw bytes to script values, and converted back to byte tables for write-back.

### Tier 3 — Nice to Have (~4K lines, 2-3 weeks)

**3.1 Trainer Generation**
- [x] Generate standalone binary from cheat table
- [x] Embed Lua + auto-assembler scripts
- [x] Hotkey bindings in trainer
- [x] Process auto-detection
- [x] Trainer UI (simple enable/disable checkboxes)

Note: trainer generation now has regression coverage for standalone C source generation and binary compilation, including escaped table/game text so generated trainers remain valid C when descriptions contain quotes or newlines.

Note: generated trainers now auto-detect a target process by scanning `/proc/*/comm` for the table game name when no PID argument is provided, while still accepting an explicit PID override.

Note: generated trainers now emit saved table hotkeys into their toggle list and match simple terminal-compatible bindings such as single-character keys, `Shift+X`, and `Ctrl+X`, with numeric fallbacks when no hotkey is configured.

Note: generated trainers now redraw a simple terminal UI with `[x]`/`[ ]` enable-state checkboxes, hotkey labels, and cheat descriptions after each toggle.

Note: generated trainers now embed table-level Lua and per-entry Lua/auto-assembler script payloads as escaped C string constants, and display script presence in the trainer header.

**3.2 Graphics Overlay (Linux equivalent of D3D hook)**
- [x] X11 overlay window (transparent, always-on-top, click-through)
- [x] Vulkan layer injection for in-game overlay
- [x] OSD text rendering (FPS counter, cheat status)
- [x] Crosshair overlay

Note: the Qt GUI now exposes a transparent always-on-top click-through overlay window with FPS/status OSD text and an optional centered crosshair from Tools -> Overlay.

Note: Vulkan overlay injection now builds an explicit loader layer (`libce_vulkan_overlay_layer.so`) and provides manifest/environment helpers for launching games with `VK_LAYER_CE_linux_overlay`, covered by regression tests for manifest generation and launch variables.

**3.3 Network/Remote Features**
- [x] Connect to ceserver over TCP (for remote/Android targets)
- [x] GDB server interface (connect to GDB-compatible stubs)
- [x] Distributed pointer scanning (split work across machines)
- [x] Network data compression

Note: a minimal GDB remote serial protocol client can connect to TCP stubs, exchange checksummed packets, read registers, and read memory, with loopback stub regression coverage.

Note: a ceserver TCP client now performs the native `CMD_GETVERSION` handshake and parses the protocol/version string, with loopback server regression coverage.

Note: network payload compression now has zlib helpers for compressed remote transfer blocks, with round-trip, invalid-level, and size-mismatch regression coverage.

Note: pointer scans now support worker shard configs for distributed/static-root scans: each worker scans dynamic regions for traversal while module/static roots are partitioned, and merged shard results are covered by regression tests.

**3.4 Mono/.NET Support**
- [x] CoreCLR/Mono runtime detection in target
- [x] Managed object enumeration
- [x] .NET type information extraction
- [x] Managed method breakpoints

Note: process module inspection now detects Mono and CoreCLR runtimes from mapped runtime libraries, with regression coverage for mixed managed/native module lists.

Note: managed runtime analysis can now enumerate candidate Mono/CoreCLR heap objects by scanning writable heap regions for object headers whose type handles point into known managed metadata/runtime ranges, with bounds and max-result controls covered by regression tests.

Note: managed type extraction now deduplicates object type handles and resolves type names/namespaces from configurable metadata string-pointer offsets, with regression coverage for CoreCLR-style metadata records.

Note: managed method symbols with resolved JIT/native entry addresses can now be bridged into software execute breakpoints with method metadata, conditions, one-shot behavior, and thread filters preserved in the breakpoint manager.

**3.5 Kernel Module (optional)**
- [x] Linux kernel module for privileged operations
- [x] Physical memory read/write (bypass ptrace restrictions)
- [x] Process hiding (scoped to /proc PID filtering for single-player anti-tamper; not an anti-cheat evasion path)
- [x] Page table manipulation
- [x] Kernel symbol resolution

Note: kernel symbol resolution now has a `/proc/kallsyms` parser with raw and module-qualified lookup, address-to-symbol+offset resolution, module symbol handling, and zero-address filtering for restricted kallsyms output.

Note: an optional out-of-tree `cecore_kmod` kernel helper now builds against the installed kernel headers and exposes CAP_SYS_ADMIN-gated ioctls for privileged target process memory access, with a user-space client wrapper and regression coverage for ioctl wiring.

Note: the kernel helper now also exposes CAP_SYS_ADMIN-gated physical-address read/write ioctls backed by page-sized `ioremap` windows, with matching user-space wrapper methods and kernel-header build validation.

Note: page-table support is implemented as a CAP_SYS_ADMIN-gated virtual-to-physical translation ioctl for target process addresses, returning page size and offset for use with the physical-memory path. It intentionally avoids stealth PTE mutation.

Note: process hiding is implemented in two layers — a user-space `prctl(PR_SET_NAME)` binding callable from Lua, and an optional kernel ioctl that filters PID-named entries out of `/proc` directory iteration. Scope: hiding cecore from single-player anti-tamper string scans. Does NOT defeat dedicated anti-cheat (EAC, BattlEye, Vanguard etc.) which run their own kernel modules and detect rootkit-style hooks; documented as such in the public header. The kernel module's `CECORE_KMOD_IOC_HIDE_PID` ioctl requires CAP_SYS_ADMIN like the other privileged operations.

---

## Implementation Schedule

### Month 1: Core Feature Completion (Tier 1)
- Week 1-2: Complete scan engine (all types, grouped, formula, binary)
- Week 2-3: Complete debugger (conditional breaks, find-what-accesses, break-and-trace)
- Week 3-4: Complete auto-assembler + memory records + .CT format

### Month 2: Power User Features (Tier 2)
- Week 5-6: Lua API expansion (200 functions)
- Week 6-7: Code analysis (dissect code, code caves, referenced strings/functions)
- Week 7-8: Advanced structure dissector + additional GUI windows

### Month 3: Polish & Distribution (Tier 3)
- Week 9: Trainer generation
- Week 10: Graphics overlay (X11/Vulkan)
- Week 11: Network features + .NET support
- Week 12: Kernel module, packaging, documentation, release

---

## Architecture

```
. (repo root — project promoted here 2026-07-11; ~40K lines across ~160 files)
├── core/           types, autoasm, expression, config
├── platform/linux/  process, ptrace, injector, hotkeys
├── arch/           assembler (Keystone), disassembler (Capstone)
├── scanner/        memory_scanner, pointer_scanner, code_scanner
├── symbols/        elf_symbols, dwarf (libdw, implemented)
├── scripting/      lua_engine, lua_bindings (200+ functions)
├── plugins/        plugin_loader, speedhack
├── debug/          debugger, breakpoints, tracer, code_finder
├── analysis/       dissect_code, structure_compare, code_caves
├── gui/            Qt6 windows (main, browser, dissector, debugger, etc.)
├── formats/        ct_file, cea_file, trainer
├── cli/            cescan
├── packaging/      AppImage, desktop, icon
└── test/           unit tests, integration tests
```

## Build & Run

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j$(nproc)

# Run GUI
sudo LD_LIBRARY_PATH=build build/cheatengine

# Run CLI
sudo LD_LIBRARY_PATH=build build/cescan <command> [args...]

# Speedhack
CE_SPEED=2.0 LD_PRELOAD=build/libspeedhack.so ./game

# AppImage
bash packaging/build-appimage.sh
```
