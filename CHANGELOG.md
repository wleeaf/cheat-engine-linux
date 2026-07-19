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

Follow-ups since v0.7.0, mostly deepening the hard-target work and unifying the value
transforms across surfaces.

- **Big-endian everywhere.** `cescan read` / `write` / `freeze` gain `--be`, so a
  big-endian value at any host address (a console value found via guest-scan and
  addressed by host address, a network/file buffer) reads, edits, and freezes by its
  logical value. All value paths -- these, the GUI cheat table, and guest-scan -- now
  route through one Qt-free, unit-tested transform (`core/value_transform.hpp`), so
  endianness and obfuscation codecs compose the same way everywhere.
- **Emulator cheat-table entries are endianness-aware** (GUI): right-click -> "Big-endian
  value" (guest-scan sets it automatically), so a big-endian guest value reads and edits
  correctly in the list.
- **`cescan il2cpp --pid <pid>`** resolves a running Unity game's class layouts (field
  offsets + method RVAs) directly, auto-locating the metadata and GameAssembly from the
  process (through the sandbox root for Proton/Flatpak).
- **`cescan tree <pid>`** lists a process and its descendants (largest RSS first, with a
  sandbox badge) to find the right renderer/helper of a browser or Electron game.
- **IL2CPP generics** now spell concrete arguments as `List<PlayerData>`, not
  `List` + backtick-arity + `<PlayerData>` (validated across all fields of a real game).
- **Guest-scan dialog** gained an end-to-end offscreen regression test (exact + unknown
  + comparison narrowing), now in the CI mirror.
- **Structure Dissector compare mode is now side-by-side** (CE Dissect Data): entering one
  or more compare addresses lays each instance out as its own value column next to the
  base, and any cell that differs from the base at that offset is coloured, so the fields
  that discriminate between instances stand out (same = default, different = red). Before,
  only the base's values were shown with the whole differing row tinted. Covered by a new
  offscreen `gui_structdissect_smoke` in the CI mirror.
- **Memory Viewer marks the current instruction** when the debugger is paused: the line at
  the stopped thread's RIP paints green with a ► marker, and the first open viewer follows
  execution. See the debugger notes below.
- **yuzu/Citra guest RAM** is now recognized: the Switch/3DS emulator family (and its
  suyu / sudachi / citron / Lime3DS / Azahar forks) backs guest memory with a
  `memfd_create("HostMemory")` fastmem mapping, so `findGuestRam` picks it up as a named
  guest-RAM marker and collapses the fastmem mirrors by file offset, exactly like the
  Dolphin / PCSX2 / DuckStation adapters. Switch/3DS are little-endian with no fixed
  console base, so the regions surface 0-based and unswapped. Validated against a
  synthetic `HostMemory` process in cecore_test.
- **Emulator guest-RAM mirror dedup now keys on the backing inode**, not just a named
  shm's offset, so an emulator that maps guest RAM at several virtual addresses via
  *unnamed* memfds no longer shows duplicate candidates. RPCS3 maps every object at both
  `g_base_addr` and a `g_sudo` write-mirror (`memfd_create("")` / `"2M"`), which carry no
  usable name -- its guest RAM now surfaces once through the generic large-region
  heuristic with the mirrors collapsed. Anonymous arenas (inode 0) stay distinct.

---

## v0.7.0 — emulators, sandboxes, obfuscated values, scriptable find-what-writes (2026-07-19)

A large release that turns hard targets from silent failures into first-class,
honestly-reported workflows: console emulators, sandboxed (Flatpak / Snap / Proton)
games, and games that obfuscate or protect their values. Most new backend work is also
exposed on the `cescan` CLI, so it is scriptable and testable headlessly. See
`docs/CHALLENGING_TARGETS.md` for the design map behind this work.

### Know the target before you scan (capability probe)

- Attaching now probes the target and reports, in plain language, what it is and what
  that limits: architecture and endianness, Wine/Proton, whether it is already traced
  (anti-debug), seccomp, PID namespace (sandbox), managed runtimes (.NET / Mono / JVM /
  V8 / Go), and recognized emulators. Shown on the GUI status line + tooltip and via
  `cescan info <pid>`.

### Emulators — scan a console game's guest memory

- **`cescan guest-scan`** scans a recognized emulator's guest RAM in guest-address
  space, with correct byte order for big-endian consoles (PS3 / Wii / GameCube). Full
  workflow: exact and unknown-value first scans, `--next`, and
  `--changed` / `--increased` / `--decreased` / `--unchanged` narrowing, all with `--be`.
- **`cescan guest-write`** edits a guest address by its logical value (translated and
  byte-swapped for you). Recognizes Dolphin, PCSX2, RPCS3, DuckStation, yuzu, Ryujinx,
  Citra, PPSSPP and more, locating candidate guest-RAM regions.

### Sandboxed and containerized apps (Flatpak / Snap / Proton)

- Symbol loading and module analysis now work on sandboxed targets: their backing files
  exist only inside the sandbox mount namespace, so paths are resolved through
  `/proc/<pid>/root`. IL2CPP metadata (a data file) resolves the same way, so
  `global-metadata.dat` opens on Flatpak and Steam-Proton (pressure-vessel) Unity games.
- The process picker badges sandboxed processes, and the probe reports the target's
  inner-namespace PID.

### Obfuscated and protected values

- **Value codecs**: a value stored XOR'd, offset, or bit-rotated can be found, read,
  edited, and frozen by its logical value. In the GUI, right-click a cheat-table entry
  → "Set value codec…" (`none | xor:0xKEY | add:N | rol:N | ror:N`); the value displays
  decoded and every write (edit, freeze, adjust, hotkey) stores the encoded form. On the
  CLI: `scan` / `read` / `write` / `freeze --codec`.
- **Reverted-value detection**: `cescan write --verify` (and the GUI, after a manual
  edit) re-reads shortly after and warns if the game or an integrity check overwrote the
  value, pointing you to find-what-writes.

### Find what writes — scriptable, and more precise in the GUI

- **`cescan watch <pid> <addr>`** exposes find-what-writes/accesses on the CLI (Wine-safe
  main-thread hardware watch by default). `--regs` reports the register holding the
  target address, or `[reg + offset]` — the base for a pointer path.
- **Exact store recovery**: a hardware watchpoint traps one instruction past the writer;
  both the CLI and the GUI now recover the precise store instruction instead of an
  occasional backward-disassembly mis-decode.
- **`cescan write --verify --find-writer`** chains write → detect revert → name the exact
  restoring instruction in one command.
- The GUI "Find what writes" window gains a **Pointer path** column.

### Freeze

- **`cescan freeze <pid> <addr> <val>`** locks a value (normal / floor / ceil), and is
  codec-aware for obfuscated values.

---

## v0.6.6 — find-what-writes and code injection on Wine/Proton (2026-07-18)

"Find what writes/accesses" and auto-assembler code injection used to freeze or
crash a game running under Wine/Proton (validated against Mount & Blade Warband
under Proton 9.0). This release makes every transient debug operation Wine-safe.

### Watchpoints ("Find what writes / accesses")

- **No longer freezes Wine/Proton games.** The watchpoint used to `PTRACE_SEIZE` +
  stop the game's entire thread group to arm; stopping wineserver, esync/fsync and
  GPU/driver threads deadlocks the game (it went unresponsive, black screen). On a
  Wine/Proton target it now arms a **hardware watchpoint on the main thread only**
  (the game-logic thread that writes money/HP), touching nothing else. Native Linux
  keeps the full all-thread watch. The software page-guard backend (which fought
  Proton's kernel write-watch / userfaultfd) is no longer used on Wine.
- **Repeatable.** A finished monitor kept the thread traced, so a second
  find-what-writes silently found nothing; finished monitors are now stopped (and
  released when their window closes) before a new one starts.
- Fixed a **use-after-free crash at exit** (the monitor thread could call into a
  debugger object that had already been destroyed).
- `CE_CODEFINDER_MODE=hw|sw|st` overrides the backend for diagnostics;
  `CE_LOG=debugger:debug` logs arming, hits and teardown.

### Code injection (auto-assembler scripts, loadlibrary, Mono agent)

- **AA code-injection scripts work on Wine/Proton.** The code-cave allocation
  (`remoteSyscall` -> `mmap`) used `PTRACE_ATTACH` and hijacked a thread parked in a
  syscall, which on Wine (threads sit in esync/fsync/wineserver waits) corrupted the
  wineserver RPC and froze the game. Switched to `PTRACE_SEIZE + PTRACE_INTERRUPT`, a
  clean stop that preserves the interrupted syscall's restart state.
- **WoW64 allocations no longer wrongly reported as failures.** A valid 32-bit
  `mmap2` address at or above 2 GB (e.g. `0xEBDF9000`) was sign-extended to a
  negative value, so `allocate()` rejected a successful mapping. Only the i386
  `-errno` range is treated as an error now.
- The **dlopen injector** (`loadlibrary()`, `createthread()`, the Mono agent) and
  the WoW64 bitness probe were switched to the same Wine-safe stop.
- The full debugger and break-and-trace still stop the whole process on purpose
  (that is what they do); everything meant to be quick and transparent does not.

## v0.6.5 — whole-app UI/UX overhaul + IL2CPP dissector depth (2026-07-18)

A comprehensive, panel-by-panel usability pass over the entire app, on top of
IL2CPP dissector depth and a batch of Cheat-Engine-parity scanning details.
Every panel, window, dialog and settings page was audited (screenshot-verified
in both the light and dark themes via a new `--pid` / `--panel` /
`--settings-page` launch harness).

### UI / UX overhaul (every panel audited)

- **Table columns stop clipping their contents.** Every list/table in the app
  (pointer scanner, memory/heap/module/thread regions, find-statics, structure
  dissector, code-finder, break-and-trace, register/SIMD editor, code references,
  stacktrace, advanced options, settings hotkeys) used to leave its columns at
  Qt's 100px default, so 16-digit hex addresses and 64/128-bit register values
  were truncated. Each table now sizes its fixed columns to content and lets the
  one variable column take the slack.
- **No more text-less or cryptic controls.** Spinbox/combo dropdown arrows were
  unstyled and rendered blank app-wide (now drawn); the Structure Dissector's
  "Compare" field had collapsed to a bare "..." because its toolbar overflowed a
  single row (now a two-row layout with the field spelled out); the Lua console
  grew explicit **Run** and **Clear** buttons instead of relying on the Enter key.
- **Analysis tools are findable from the main window.** Auto Assemble, Pointer
  scan, Dissect data/structures, Find static addresses, the Mono dissector, the
  Lua engine and the ELF inspector were only in the Memory Viewer's own menus;
  they now also appear in the main window's Tools menu.
- **Decluttered layout.** The Structure Dissector toolbar was split into an
  address row and an actions row; the dead Windows-only **D3D** menu (every item
  permanently disabled on Linux) was removed; the Fill Memory dialog's fields are
  aligned in a form layout, and the process picker groups Open/Cancel on the right.
- **Colours fit both themes.** The two remaining hardcoded disassembler colours
  (DWARF source-line annotations and the breakpoint gutter glyph) washed out on
  the light theme; both are now theme-gated. The Lua console dims echoed commands
  and shows errors in red.
- **Code References no longer looks frozen.** Analyzing a module drives a
  cancelable progress dialog across its eight scan passes instead of hanging.
- **System theme on first launch, working scrollbars, real breakpoint toggle**
  (from the same pass): the app follows the desktop's light/dark preference on
  first run; the memory-view scrollbars track an absolute flattened-memory model
  so dragging no longer snaps back; and Toggle Breakpoint truly toggles.

### IL2CPP (Unity) dissector

- **Managed field type names** resolved offline from the GameAssembly binary:
  `System.Single`, `UnityEngine.Vector3` (VALUETYPE/CLASS), arrays (`MyClass[]`),
  pointers, and generics spelled out (``List`1<System.String>``,
  ``Dictionary`2<K, V>``). Every field on real v27/v31 games resolves a name.
- **Base class** of each type (parent chain), rendered as `Foo : Bar` in the
  dissector; and **full object layouts** with inherited fields
  (`getIl2CppObjectLayout`, `cescan il2cpp --object <class>`), each field tagged
  with its declaring type.

### Scanning

- **Tri-state Writable/Executable region filters** (CE's grey/checked/unchecked
  boxes): must-have / must-not-have / don't-care.
- **"Pause target while scanning"** — SIGSTOP the target for a consistent snapshot
  during each scan, then resume (skips a target that's already stopped).
- **New Scan flow**: First Scan becomes New Scan after scanning and locks the
  value type; a **Previous column** shows the scan-time value next to the live one.
- **AOB / string result values fixed** — they showed "?"; AOB now renders as
  `48 8B 05` and strings as text, in both the results list and the cheat table
  (which also keeps AOB/string entry types across save/load).
- Enter-to-scan, type-aware value placeholders (`48 8B ?? 05` for AOB), the value
  box greys out for no-value compares, thousands-separated result counts, clear
  status feedback when there's no process, and **Save current scanresults** to
  txt/csv.

### UI / memory viewer

- **Scan panel rebuilt** with real Qt layouts (was absolute pixel coordinates:
  dead space, no scaling); results list expands into the reclaimed width.
- **Memory-view scrollbars work** — the disassembly/hex panes had a dead or
  missing scrollbar; both now scroll memory, and scrolling up past mapped memory
  no longer strands the view ("no memory" with no way back).
- **Jumping to unmapped memory now says so**: a Go / follow / back-forward that
  lands on an unreadable address shows `0x… is not readable (unmapped or
  protected page)` in the status bar, instead of a silent pane of `??`.
- **Memory viewer gives the disassembly/hex more width by default**: the register
  and stack panels only show placeholders (live registers are in the Debugger
  window), so they no longer take a quarter of the width, and the disassembler's
  `module+offset` / data-reference annotations stop truncating off the edge.
- **Every "Browse this memory region" opens the full memory viewer.** Opening it
  from a scan result, a cheat-table entry, Advanced Options, or the Memory
  Regions/Heap/Module/referenced-strings windows used to give a stripped-down
  viewer with no breakpoints, "add to list", Tools/Debug menus or debugger launch;
  all of those now open the same fully-wired viewer as the Memory View button.
- **No crash when the target exits with a Memory Viewer or Structure Dissector
  open.** When the attached process ends (or you attach to a different one), open
  Memory Viewers and Structure Dissectors are frozen and the Lua engine's process
  pointer is cleared before the process handle is destroyed, so a refresh timer or
  table script can't read the freed handle.
- **Dark-theme tree fix** — tree widgets (Mono dissector, breakpoint/thread/module
  lists, structure dissector) rendered class rows as unreadable white stripes;
  now themed. Tool buttons, radios, and the speedhack slider themed to match.
- **Addresses as `module+offset`** (`game.bin+0x1234`) in the cheat table, stable
  across restarts; empty-state hints on the results and cheat-table panes; the
  window title shows the attached process.
- **Static scan results shown in green** (CE's cue): a result address inside a
  loaded module is pointer-stable across restarts, so it is coloured green and
  hovering it reveals the `module+offset` it belongs to.
- **Disassembler annotates unnamed call/jmp targets** with `module+offset`
  (e.g. `jmp 0x… ; GameAssembly.so+0x1234`) when no symbol exists, so stripped
  game binaries are still navigable; conditional jumps stay uncluttered.
- **Hex view: multi-byte range selection** by drag or shift+click (highlighted
  in both the hex and ASCII columns), with right-click "Copy selection as AOB"
  and "Copy selection (hex, no spaces)". Editing or arrow-navigating collapses
  the range back to a single byte.
- **Scan result count no longer looks truncated**: the results table shows at
  most 10,000 rows for responsiveness, so when a scan finds more the "Found"
  label now says e.g. `Found: 2,000,000  (showing first 10,000)` instead of
  leaving the capped list unexplained.
- **Disassembler colours fixed for the light theme.** The operand text, the
  selected/branch-target row highlights, and the user-comment colour were
  hardcoded to dark-theme values, so on the light theme operands rendered as
  near-invisible pale lavender and a selected row became a dark bar. These are
  now theme-aware (readable dark-slate operands and a soft selection tint on
  light; unchanged on dark).
- **Memory viewer debug toolbar decluttered**: the six near-identical Run/Step
  buttons (which all just opened the separate Debugger window) collapse to a
  single "Debugger" button, leaving Toggle BP / Debugger / Preferences.
- **Memory viewer hides the register/stack panels by default.** They only
  populate during a debug session (which runs in the separate Debugger window),
  so they were dead `-` placeholders taking a quarter of the width; now the
  disassembly and hex use the full width, and a persisted View toggle ("CPU
  registers & stack panels") brings them back for CE's layout.
- **Settings dialog redesigned with a vertical category sidebar.** The 15
  categories used to overflow a horizontal tab bar (most tab names hidden); they
  now sit in an always-visible left-hand list (horizontal text) with the page on
  the right, the standard modern settings layout. `--settings` opens the dialog
  straight on launch.
- **Zebra-striped result and cheat-table rows** for easier scanning of dense
  address/value lists. The theme already defined the alternating colour but the
  views never enabled it; enabled now, with the light stripe nudged from nearly
  invisible to a soft, readable grey.
- **Scan panel declutters for the value type**: the float-only Rounding and
  Tolerance controls are now hidden (not just greyed) for integer/text scans, so
  the row collapses instead of leaving dead controls under Value Type. They
  reappear when you pick Float/Double (Tolerance only in "Extreme" mode).
- **Percentage scan fields hide until needed**: the "Compare by %" value and the
  "Percent max" row now appear only when "Compare by %" is ticked (and the max
  only for a "between" compare), instead of sitting greyed on every scan.
- **The main window and Memory Viewer remember their size, position and panel
  layout** across runs (window geometry and every splitter are saved on close,
  restored on launch), instead of always reopening at the default 760x560 /
  900x600.
- **File > Load Recent now works.** It was a permanently empty menu; it now
  lists the last 10 cheat tables you opened or saved (most recent first, full
  path on hover), greys out ones that have since moved, and has a "Clear list".
- **Paste records copied from Cheat Engine.** Ctrl+V in the cheat table now
  accepts CE's `<CheatEntries>` XML clipboard format (addresses, types, pointer
  offsets, groups) in addition to our own JSON, so records copied straight from a
  CE session or a shared table snippet drop in.
- **Table > Show Cheat Table Lua Script (Ctrl+Alt+L)** now works (was a dead menu
  item). View and edit the table-level Lua that runs when the table loads, run it
  on demand, and it is saved back into the `.CT`/JSON, so you can author trainer
  logic, not just import a script that already runs.
- **Help > Cheat Engine Help / Lua documentation** now open the shipped README /
  `docs/SCRIPTING.md` in a rendered Markdown viewer (with an "Open on GitHub"
  button), instead of being dead menu items; they fall back to the online copy
  when the docs aren't installed next to the binary.
- **Lua Engine now follows the attached process.** Attaching to a new target
  re-points the shared Lua engine (and any open Lua Engine console) at it, and the
  console binds the address list, so `getMemoryRecord`/`readInteger` etc. act on
  the current process instead of a stale one (or failing when no table was loaded).
- **Debugger highlights changed registers** (CE's cue): after each step or
  breakpoint stop, the registers the instruction modified paint red (general
  purpose and XMM0-15), so what an instruction touched reads at a glance. The
  first stop of a session stays neutral.
- **One shared Debugger window.** Opening it twice (the Memory Viewer's step
  buttons, or Debug > Full debugger) used to spawn a second window whose
  ptrace-attach then failed; now the existing one is raised instead, and it is
  torn down cleanly when you attach to a different process.
- **`--pid <N>`** attaches to a process on launch (no picker dialog).

### Scripting / RE

- Wayland global hotkeys wired into `GlobalHotkeyManager` (xdg-desktop-portal).
- Lua: `findReferencedStrings`, `findCodeCaves`, `findAssemblyPattern`,
  `disassembleRange`, `getIl2CppObjectLayout`; `cescan analyze` surfaces the
  static RE toolkit from the shell. New `docs/SCRIPTING.md` + `examples/`.
- `cescan scan` gained `--executable` / `--no-executable` (and `--no-writable`),
  exposing the tri-state region filters the GUI already has, so a shell scan can
  target code vs data the same way.
- `cescan disasm` annotates a direct call/jmp target with its symbol, or its
  `module+offset` when unnamed (e.g. `jmp 0x… ; sleep+0x2020`), matching the GUI
  disassembler; register/indirect branches stay unannotated. RIP-relative data
  references also get a `; -> symbol` / `; -> module+offset` note for what the
  effective address points at (e.g. `mov rax, [0x…]  ; -> libc!environ`).
- `cescan write` gained `--type string` (raw text) and `--type aob` (`"90 90 05"`
  hex bytes), so you can patch code (NOP a branch) or write a string from the
  shell, not just numeric values. Wildcards are rejected for an in-place byte write.
- `cescan read --type <t>` interprets the bytes instead of dumping hex: an integer
  (`123 (0x7b)`), float/double, pointer, or a `"string"` (with the size argument as
  its length cap). Without `--type` it still hex-dumps as before.

## v0.6.0: scanner performance overhaul (2026-07-16)

Performance release. The value scanner (first scan and next scan) was rebuilt
around the memory pipeline: cache-blocked reads, all cores on one region,
resident-page skipping, SIMD numeric and byte-pattern compares, and coalesced
next-scan reads. Results are unchanged, verified against a brute-force reference
and clean under ASan/UBSan. In a same-machine head-to-head it is now the fastest
scanner on Linux: a first scan is about 2x faster than Cheat Engine 7.7 and 30 to
40x faster than scanmem, GameConqueror, and PINCE, with larger margins on some
scans. A new [BENCHMARK.md](BENCHMARK.md) documents the full comparison and how
to reproduce it.

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
  (NaN never matches, -0.0 equals 0.0). Rounded/truncated/extreme float searches
  are vectorized too, via a superset reject (a window around the search value)
  then the exact scalar check on the few survivors, so results are identical to
  the scalar path (~12x faster on a 1 GiB rounded-float scan). Set
  `CE_SCAN_SIMD=off|sse2|avx2` to override for testing.
- **SIMD array-of-bytes and string scans (~2x).** An AOB/string scan checks
  every unaligned offset, so it was compute-bound. It now anchors on one fixed
  pattern byte and uses an SSE2 byte search to reject 16 non-matching offsets at
  a time, verifying the full pattern only at candidates (a 6-byte AOB over 1 GiB
  went 3.5 to 7.9 GB/s). Handles wildcard/nibble masks (anchors on the first
  full byte; an all-wildcard pattern falls back to scalar) and leading
  wildcards; case-insensitive string search stays scalar.
- **Next scan is batched and multi-threaded.** Re-reading previous results used
  one `process_vm_readv` syscall per address on a single thread; it now reads up
  to 1024 addresses per syscall (scatter read) and fans big result sets across
  cores (~8x on a large result set). It degrades gracefully: handles that cannot
  be read concurrently, e.g. a socket-backed ceserver handle, stay
  single-threaded, which also fixes a latent first-scan data race on those.
- **Coalesced next-scan reads (~14x contiguous, ~5-9x tight strides).** Even
  batched, the scatter read described each address as its own tiny iovec, so a
  dense result (consecutive matched values after an unknown-value scan, or an
  array field) cost the kernel millions of size-byte copies. Back-to-back
  addresses are now merged into one large iovec per run (a 16.7M-result
  contiguous next scan dropped ~1.7s to ~0.12s), and a batch whose matches are a
  small stride apart (a struct-array field, gap <= 64 bytes) is read as one span
  into a scratch buffer and scattered out instead of per-match (stride 8 ~8.9x,
  16 ~7x, 32 ~5.8x, 64 ~4.5x). Larger strides and scattered results keep the
  per-address scatter read; a fault on a span read falls back to it.
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
