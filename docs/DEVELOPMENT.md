# Development & project status

Consolidated development notes for cheat-engine-linux: the roadmap / gap
analysis, the CLI / headless parity status, and how the project compares to the
official Cheat Engine Linux build. (User-facing docs live in `README.md`; release
history in `CHANGELOG.md`; contribution + security policy in `CONTRIBUTING.md` /
`SECURITY.md`.)

## Before pushing: `tools/ci-check.sh`

Run `tools/ci-check.sh --config` (seconds) before every push, and
`tools/ci-check.sh` (full build + tests) before anything non-trivial. It mirrors
both CI jobs, crucially the `sanitizers` job, which installs **no Qt**, so the GUI
is skipped and nothing pulls in transitive targets. A dev machine always has Qt,
so a missing `find_package()` (or any GUI-masked dependency gap) builds fine
locally but reddens CI. The script reproduces that with
`-DCMAKE_DISABLE_FIND_PACKAGE_Qt6=ON`. If the no-Qt configure is green, CI will be.


---

<!-- was: ROADMAP.md -->

## Roadmap — complete gap analysis (2026-07-12)

A systematic "what do we lack" sweep, produced by four parallel gap-detection
passes over the real code (CE feature parity; debugger + Lua; platform/GUI/
packaging; quality/testing/security/docs), cross-checked against the planning
docs. Every item is grounded in a file citation.

**How this relates to `FEATURE_GAP.md`:** that tracker follows the CE-tutorial
parity checklist and is now essentially complete (scanner, AA, disassembler,
pointer/dissect, cheat tables, and the just-shipped interactive debugger all
work). This roadmap is the *fuller* picture: the deeper functional, platform,
security, and quality gaps that the checklist never covered.

Effort key: **S** < 1 day · **M** a few days · **L** 1-2 weeks+.

By-design omissions (NOT gaps): DBVM, DBK kernel driver, Ultimap/BTS, kernel
stealth — Windows-kernel-specific; the Linux kmod + LBR mapper are the analogs.

### Progress (loop, 2026-07-12)

Done and CI-green:
- **all P0** (1-5): CI gates on test failures, LICENSE/SECURITY.md, versioning, doc annotations.
- **P1 #7** parser adversarial-input tests · **P1 #8** ASan+UBSan option + CI job (product
  code memory-clean) · **P1 #14** installable/embeddable `libcecore` · **P1 #6**
  `shellExecute` + `write*Local` RCE gates + central Lua exception firewall (done)
  · **P1 #13** `.deb`/tarball + AppStream + `.CT` MIME
  (Flatpak dropped — sandbox blocks ptrace).
- **P2 #17** Break&Trace multi-thread (all-stop; follows the thread that hits the
  start breakpoint, including child threads) · **P2 #20** stripped-binary symbols via
  build-id / `.gnu_debuglink` · **P2 #19 (partial)** pointer rescan-by-value
  (game-restart workflow) · **P2 #23 (partial)** Lua `getSymbolInfo`
  + `reinitializeSymbolhandler` + `getRegionInfo` + `getNameFromAddress` hex fallback
  + `nopInstruction` + `readRegionToFile`/`writeRegionFromFile` + `getModuleAddress`
  + `compareMemory` + the float/double/byteTable conversion family + `stringToMD5String`
  · **P2 #18 (partial)** configurable
  find-what-writes watch size + "find what addresses this instruction accesses"
  (`findInstructionAccesses`: a DebugSession execute-breakpoint monitor that
  resolves each hit's data address via `computeEffectiveAddress` —
  base+index*scale+disp and RIP-relative) + NOP-an-instruction
  (`nopInstruction`/`restoreBytes`: length-preserving 0x90 fill with undo) · **P2 #16
  (partial)** register editing end-to-end: backend `DebugSession::setStopContext`
  writes the full GP set + RFLAGS to the stopped thread (`getStopContext` now
  captures r8-r15), and the debugger window's register table is editable and
  writes back (gui_debugger_smoke verifies the edit reaches the thread); plus a
  a thread switcher: backend (`stoppedThreads`/`selectThread`: enumerate the
  all-stopped threads and retarget register read/edit/step) + a debugger-window
  dropdown (gui_debugger_smoke `threadsw=1`); a memory/hex pane in the debugger
  (address input + hex+ASCII dump that refreshes on stop, smoke-tested
  `memview=1`); and XMM0-15 capture (`getXmmRegisters` via GETFPREGS) shown in
  the register table (`xmm=1`) — completing GP/flags/XMM · **P2
  #22 (partial)** embedded `<Forms>` preserved verbatim across `.CT` load/save
  (Delphi form designs no longer dropped on re-save) · **P2 #15 (core)** the Lua
  `debug_*` API is no longer a facade: `debug_setBreakpoint` plants a real
  software breakpoint through a `LuaEngine`-owned `DebugSession`, hits are queued
  on the tracer thread and drained by `debug_pumpEvents` on the Lua thread, which
  publishes the register context (RIP/RSP/RAX.. globals) and fires the
  CE-compatible `debugger_onBreakpoint` handler, then resumes;
  `debug_removeBreakpoint` unplants the real breakpoint (test confirms pumping
  goes quiet after removal). The handler can also REWRITE registers (assign the
  RIP/RSP/RAX.. globals) and the pump applies them to the hit thread before
  resuming (test observes a handler's RAX edit land in a subsequent store).
- **P3 #27** light theme (dead toggle fixed) · **P3 #28** `CONTRIBUTING.md`.

The debugger window's disassembly now has a right-click menu ("Set breakpoint
here" / "Replace with NOPs") wired through the session + the `nopInstruction`
backend (gui_debugger_smoke `disasmbp=1`). And `debug_setBreakpoint`'s non-zero
`type` now plants a real **hardware DATA watchpoint** (DR0-3 on every thread) via
a new `DebugSession::setHardwareBreakpoint`; `handleStop` reports the watched
address on a `TRAP_HWBKPT`, and detach disarms the debug registers first (a test
confirms the watchpoint fires on a write AND the tracee survives detach — a
left-armed DR would kill it). **#15 (debugger unification) is complete.**

**#24 (core)** cecore can now BE a ceserver, not just a client: a new
`CeserverServer` listens on TCP and serves the core CE protocol commands
(GETVERSION / OPENPROCESS / CLOSEHANDLE / READ- / WRITEPROCESSMEMORY /
VIRTUALQUERYEXFULL / GETARCHITECTURE / CREATETOOLHELP32SNAPSHOTEX for
threads+modules) against local process memory. Verified by a full round-trip —
our own `CEServerClient` connects, reads/writes memory, enumerates regions, and
lists threads+modules through it, AND remotely debugs it (STARTDEBUG /
SETBREAKPOINT / WAITFORDEBUGEVENT / CONTINUEFROMDEBUGEVENT / STOPDEBUG — the
server drives a DebugSession and marshals breakpoint events back over the wire;
tested against a forked child, breakpoint fires + tracee survives detach). ALLOC/FREE
allocate/free memory in the target via ptrace remoteSyscall mmap (tested: alloc a
page in a child, write+read it back through the protocol). **#24 is complete.**

Remaining: #21 dissector RTTI typing (depends on #10); more of #23.
The #21 N-instance/multi-column half is done (backend detector + GUI multi-address compare).

Test-coverage hardening (this pass): added tests for previously-untested real code
that needed no special environment — the Mono soft-debugger client framing
(`test_mono_debugger_client`), `generateInjectionScript` integration
(`test_injection_script_generation`), and `ProcessWatcher` new-process detection
(`test_process_watcher`, deterministic via comm-inheritance-across-fork). The
still-untested modules are genuinely gated: `lbr_tracer`/`intel_pt` need
perf/PT hardware, `lua_gui`/`lua_bitmap` need a display, and `lua_snapshot` is a
thin wrapper over the already-tested `Snapshot` core.

Genuinely blocked on real-world testing / a strategic call: **#10 Mono/Unity**
(detection/enumeration/extraction + soft-debugger framing are tested; full
type-introspection + IL2CPP need a live Unity target), **#11 Vulkan overlay**
(GPU), **#12 Wayland hotkeys** (compositor+portal), #25 ARM (registers/ptrace;
disassembly of ARM32/ARM64 is verified), #26 32-bit inject (injection; x86-32
disassembly is verified).

---

### P0 — Integrity & blockers (small, do first)

These are cheap and they underpin trust in everything else.

1. **`cecore_test` doesn't gate CI.** `main()` runs ~110 tests then
   `return 0;` unconditionally (`test/main.cpp:5857`); 291 `FAILED` prints never
   touch the exit code. CI only checks "built + didn't crash," so a real
   regression stays green. Add a failure counter → non-zero exit. **[S]**
2. **Run the tests that already have exit codes.** `gui_debugger_smoke`
   (`return ok?0:1`) and `scan_test` (root-gated) are built but never run in CI
   (`.github/workflows/build.yml` runs only `cecore_test`). Add steps. **[S]**
3. **No `LICENSE`.** No top-level license and no `third_party/lua/LICENSE`
   (Lua's MIT notice lives only in `lua.h`). The release AppImage statically
   links Lua, whose MIT terms require the notice travel with it — a real
   distribution blocker. Add a project license + carry Lua's. **[S]**
4. **Version drift.** `CMakeLists.txt` says `VERSION 0.1.0`, `CHANGELOG.md` is at
   `v0.2.1`, and there's no `--version`. Single-source the version and surface
   it. **[S]**
5. **Stale audit docs overstate risk.** `CODE_ANALYSIS.md` / `FIXES_APPLIED.md`
   still list resolved items as open (sibling-Lua dep, "no hardening flags",
   unignored kernel artifacts). Annotate them RESOLVED. **[S]**

### P1 — Security (this tool runs as root and loads shared tables)

6. **Ungated untrusted-Lua RCE.** `l_shellExecute` → `system()`
   (`scripting/lua_bindings.cpp:1754`) and the `*Local` raw-pointer R/W family
   are ungated; loading a shared `.CT`/`.CETRAINER` with embedded Lua = arbitrary
   code + host-memory access, usually as root. Add an opt-in trust/consent gate,
   and route every `lua_register` through one exception-translating trampoline
   (today each binding must remember its own try/catch). **[M]**
7. **No fuzzing / negative-input tests** on any untrusted parser (ELF, DWARF,
   `.CT`/`.CETRAINER`, Mono net protocol, `ExpressionParser`). README claims
   these treat input as untrusted; that's untested. Add libFuzzer harnesses +
   a negative corpus. **[M]**
8. **No sanitizers in CI.** Hardening flags are solid, but there's no
   ASan/UBSan/TSan job and no `-Werror`; the multithread ptrace/all-stop code
   (25 `TODO(security)` markers) is exactly what TSan/ASan would catch. **[M]**
9. **`SECURITY.md` + ptrace-permission/troubleshooting docs.** None exist for a
   root-privileged tool. **[S]**

### P1 — Realize the Linux-first differentiators (the strategic bet)

The reassessment (`VS_OFFICIAL_CE_LINUX.md`) leans on these to justify existing
alongside official CE 7.7 Linux. Today each is materially short of the claim.

10. **Native Mono / Unity / IL2CPP dissector — the single highest-impact gap.**
    Today: runtime detection, heap object enumeration, and type-name extraction
    all exist and are unit-tested (`analysis/managed_runtime.cpp`,
    `test_managed_runtime_detection` / `_object_enumeration` / `_type_extraction`),
    and the Mono soft-debugger client is now validated against a REAL mono agent
    (`test_mono_debugger_real_agent`: compiles + runs a C# probe under
    `mono --debugger-agent`, then checks the handshake + VM/Version + VM/AllThreads
    against the genuine agent; `test_mono_debugger_client` keeps the deterministic
    mock for CI). That real-agent test caught two protocol bugs the mock had
    hidden: `sendCommand` did not drain the agent's asynchronous event packets
    (VM_START etc.), and the VM command numbers were wrong (ALL_THREADS is 2 not 6;
    SUSPEND/RESUME/EXIT/DISPOSE were each off) with 4-byte, not 8-byte, object ids.
    Both are fixed. *IL2CPP started:* `analysis/il2cpp_metadata.cpp` parses a
    `global-metadata.dat` header + both string pools (identifier names + string
    literals) with full bounds-checking (`test_il2cpp_metadata`, synthetic file);
    those leading header fields are version-stable so it is correct for real files.
    It now ALSO decodes the deeper type/field/image tables (metadata v29-31) to
    recover the class layout OFFLINE: assembly image, class namespace.name, field
    names, surfaced by a `cescan il2cpp <global-metadata.dat>` browser
    (`--class <substr>`, `--fields`) and `test_il2cpp_metadata_tables` (synthetic
    v29 round-trip: types, fields, image grouping, version gate, corrupt-region
    non-fatal). For a live target, `findIl2CppMetadataPath` auto-locates the file
    from the process's mapped paths (the `<Game>_Data/il2cpp_data/Metadata` tree
    next to the executable/GameAssembly.so; system libs are ignored), and Lua
    `getIl2CppMetadataPath()` / `getIl2CppClasses([path])` expose the browser to
    scripts (`test_il2cpp_locate` covers both). The GUI surface is deliberately
    deferred until the layout is validated against a real file. Two honest caveats live in the code: (a) the table struct offsets
    are transcribed from public reversing refs (Il2CppDumper) and validated only
    synthetically, they need a real Unity `global-metadata.dat` to confirm, and
    unsupported versions or invalid regions skip table decode (`tablesDecoded`);
    (b) field byte OFFSETS and field TYPE names are NOT in the metadata (they live
    in GameAssembly.so), so this gives names/grouping, not in-object offsets. That
    offset resolution is the separate live/binary track.
    *Remaining:* validate the layout against a real file, extend to v24/v27 (the
    integer version can't split v27.0 from v27.2's byref change), resolve field
    offsets/types from the binary, plus the full soft-debugger type-introspection chain
    (AppDomain→Assembly→Type→Field) — now developable against the real agent — and
    the deeper per-Unity-version IL2CPP metadata tables. **Most Linux/Proton games
    are Unity** — this remains the niche to win. **[L]**
11. **In-game overlay actually renders.** `platform/vulkan_overlay_layer.cpp`
    advertises a layer but only forwards `vkCreateInstance/Device` — it never
    hooks `vkQueuePresentKHR` and draws nothing. *Layer contract now validated:*
    `test_vulkan_overlay_layer_interface` dlopen's the built layer and checks its
    loader-facing interface end-to-end (negotiate → GetInstanceProcAddr
    resolution of hooked vs unknown entry points → layer enumeration), gated on
    `find_package(Vulkan)` with `libvulkan-dev` in CI. *Remaining:* the actual
    `vkQueuePresentKHR` present-hook + OSD blit (the renderer), and the X11-only
    Qt overlay (`gui/overlay.cpp`) for Wayland/gamescope. Real-VkInstance
    layer-chain testing is blocked locally by the headless NVIDIA ICD hanging in
    `vkCreateInstance`; it needs a software driver that initialises headlessly.
    **[L]**
12. **Wayland global hotkeys.** `gui/globalhotkeys.cpp` is entirely
    `XGrabKey`/xcb; on Wayland it degrades to focus-only Qt shortcuts — dead
    exactly when the game has focus. *Backend built + tested:* new
    `gui/wayland_global_shortcuts.cpp` — a QtDBus `xdg-desktop-portal`
    GlobalShortcuts client (CreateSession → BindShortcuts via the async
    Request/Response pattern, plus the Activated signal → `activated(id)`).
    `test/wayland_shortcuts_test.cpp` drives it against a mock portal that
    implements the authoritative interface (run under `dbus-run-session` in CI):
    it validates the message FORMAT against the real spec (`a{sv}` options, the
    `a(sa{sv})` shortcuts marshalling, the `Activated` signature) plus the
    round-trip + signal decode. *Remaining:* wiring it into `GlobalHotkeyManager`
    (the sync X11 API vs the portal's async session flow) + a QKeySequence→trigger
    mapping, and true end-to-end behaviour against a real compositor's portal
    (not headlessly automatable — its bind-confirmation UI needs a live session).
    **[M-L]**
13. **Native packaging.** ~~Flatpak~~ + AppStream + `.CT` MIME. **DONE (partly),
    with a correction:** a `.deb` + tarball are now produced via CPack (unsandboxed,
    apt-installable, and the release workflow attaches the `.deb`). **Flatpak was
    dropped on purpose:** its sandbox runs the app in its own PID namespace and
    blocks `ptrace`/memory access to other processes — which defeats a memory
    scanner. AppImage + `.deb` (both unsandboxed) are the right fit. Still open:
    an AppStream `metainfo.xml` and a `.CT` MIME association. **[S]**
14. **Make `libcecore` embeddable.** `CMakeLists.txt` has zero `install()`
    rules, no `SOVERSION`, no pkg-config/CMake package, no curated public
    headers — the "reusable engine" differentiator is unrealized. Add install +
    a public API surface. **[M]**

### P2 — Finish the debugger (just shipped v1) — unify the breakpoint layer

The biggest lever: **three breakpoint systems don't talk.** `BreakpointManager`
(conditions/HW/thread-filter) fed by the disassembler right-click is never armed
(`applyToThread`/`removeFromThread` have zero callers); the Lua `debug_*` API is
a facade that stores a table and never plants anything
(`scripting/lua_bindings.cpp:1437`); the new `DebuggerWindow` uses its own bare
int3 path. Wiring `DebugSession` to accept type/size/condition/callback and
routing both the disassembler and Lua through it closes many at once.

15. **Unify breakpoints + make the disassembler right-click and Lua `debug_*`
    actually fire**, with HW/data + conditional breakpoints. **[L, high leverage]**

    *Implementation approach (needs one strategic call before coding):* make
    `DebugSession` the single breakpoint authority — it already owns the sole
    tracer thread, all-stop, software int3, `setStopContext` (register edit),
    and marshals events to the UI. Extend its breakpoint record to carry
    `{kind: exec|hw-exec|hw-read|hw-write, size, condition, callback}` (the HW
    path already exists in `CodeFinder`/`Debugger::setBreakpoint`; fold it in).
    Then route both front-ends through one session: the disassembler right-click
    ("set breakpoint", plus the now-built `findInstructionAccesses` and
    `nopInstruction`) and the Lua `debug_*` facade (`lua_bindings.cpp:1437`).
    **The one decision:** the Lua debug API's firing model. CE is async
    (`debugger_onBreakpoint` callback) — to stay CE-compatible, marshal each hit
    from the tracer thread onto the thread that owns the Lua state and invoke the
    callback there (the same queued-invocation pattern `DebuggerWindow` already
    uses for `onDebugEvent`; never call Lua from the tracer thread). The
    Linux-native alternative is a blocking `debug_continueFromBreakpoint` /
    `debug_waitForBreakpoint` — simpler and trivial to test, but not
    CE-script-compatible. Recommend async-marshaled for CE parity. Increment
    plan: (a) `LuaEngine` owns a `DebugSession`; (b) `debug_setBreakpoint` plants
    a real int3 through it + keeps the table for `debug_getBreakpointList`;
    (c) marshal hits to a main-thread pump that runs `debugger_onBreakpoint`;
    (d) wire the disassembler menu. Each step is testable against a forked child.
16. **Debugger window completeness:** register *editing* + full GP/flags/XMM
    (view-only today, missing R8-R15), a thread switcher (all-stop already
    captures every thread; UI shows only the trapping one), a memory/hex + watch
    pane, richer disasm (reuse `MemoryBrowser`: symbols/xrefs/goto/follow), and
    breakpoint persistence to the table. **[M]**
17. **Break&Trace:** multi-thread (single-tid `PTRACE_ATTACH` today,
    `debug/tracer.cpp:18`), Lua stop-conditions, and trace the thread that hit
    the breakpoint. **[M]**
18. **find-what-writes follow-ups:** NOP-the-instruction, "find what this
    instruction accesses", and configurable watch size (hardcoded 4-byte,
    `debug/code_finder.cpp:63`). **[M]**

### P2 — Breadth / CE parity

19. **Pointer scanner: reusable pointermap + value-filtered rescan.** No
    pointermap (CE reuses one for fast rescans) and rescan filters only by exact
    resolved address, not by the pointed-to value — so the canonical
    scan/restart/rescan-by-value workflow is manual. **[M]**
20. **Symbols: build-id / `.gnu_debuglink` / MiniDebugInfo + DWARF types.** No
    separate-debug-file resolution (stripped libc/drivers/games show raw
    addresses), and DWARF extraction is line-table + function names only (no
    struct/member/variable types). **[M]**
21. **Structure dissector: multi-instance columns + RTTI/managed typing.**
    *Multi-instance done:* `analysis/structure_tools.cpp` gains
    `autoDetectStructureFieldsMulti` (flags the byte-runs that vary across N
    snapshots; the two-snapshot detector is now the N=2 case that delegates to
    it), and `gui/structuredissector.cpp` accepts a comma/space-separated list of
    compare addresses, highlighting rows that differ from the base in any
    instance. *Remaining:* RTTI/managed class-name typing, which depends on #10.
    **[M]**
22. **Cheat table: embed Form Designer forms + custom types.** No `<Forms>`
    handling; the Form Designer saves standalone `.json` instead of into the
    `.CT`, so full trainers don't round-trip. **[S-M]**
23. **Lua surface breadth.** Missing chunks of CE's API: `executeCode`,
    `createDissectCode`/`dissectCode`, structure-definition APIs, the
    `disassembler()`/`getMemoryViewForm` objects, symbol-handler control, and
    `memoryrecord` pointer/offset + child/group methods (can't script pointer
    chains or group hierarchies). **[L overall, S-M each]**

### P3 — Reach & polish

24. **ceserver daemon** (be a server, not just a client) — expose a headless/
    embedded Linux box as a target. **[M]**
25. **ARM64/ARM32 support** — `CpuContext` and the injector are x86-64-only;
    excludes Asahi/ARM handhelds. **[L]**
26. **32-bit / WoW64 injection — DONE (library injection).** `injectLibrary`
    now handles 32-bit targets via a dedicated i386 path (`injectLibrary32` +
    `remoteSyscall32`/`remoteCall32`: int 0x80, mmap2/munmap, cdecl
    `__libc_dlopen_mode`), backed by new ELFCLASS32 symbol parsing in
    `symbols/elf_symbols.cpp`. Verified end-to-end against a real compiled 32-bit
    target (`test_inject_library_32bit`: exec a 32-bit process, inject a 32-bit
    .so, confirm it maps; `test_elf32_symbols` covers the symbol path), and CI
    installs `gcc-multilib` so both run. *Remaining:* `createRemoteThread` is
    still x86_64-only (32-bit injected-speedhack thread), a smaller follow-up.
    **[M]**
27. **Light theme** (the settings toggle is a dead no-op, `gui/main.cpp:56`
    always applies dark) + a HiDPI/fractional-scaling audit of the custom
    painters. **[S]**
28. **`CONTRIBUTING.md` + Lua API reference + a tutorial** + issue/PR templates —
    none exist; contributor/adoption blockers. **[M]**
29. **Kernel-module ioctl test harness** — `kernel/cecore_kmod.c` (an
    `ioremap`/`memcpy_toio` write primitive) is the most security-sensitive code
    and is never loaded/tested; CI build is `continue-on-error`. **[M]**

---

### Quick-win batch (all S, high value — recommended first sprint)

P0 items 1-5 + Flatpak/AppStream (13, the S part) + light theme (27) +
`SECURITY.md` (9). A day or two of work that makes CI actually protective, makes
the project legally distributable, and lands two visible user wins.

### Suggested sequencing

1. **Sprint 0 (quick wins):** P0 1-5, + LICENSE, + Flatpak, + `--version`.
2. **Harden:** security P1 (6-9) — matters most because the tool is root + loads
   shared tables.
3. **Pick the strategic bet:** commit to the Linux-first direction from
   `VS_OFFICIAL_CE_LINUX.md`, then do #10 (Mono/Unity) and #11-14 in that order.
   If instead the direction is "clean engine others embed," do #14 first.
4. **Finish the debugger:** #15 (unify breakpoints) unlocks #16-18 and the Lua
   debug API together.
5. **Breadth** (#19-23) and **reach** (#24-29) as capacity allows.

---

<!-- was: docs/CLI_PARITY.md -->

## CLI / headless parity audit

**Principle:** everything the GUI can do should be doable from the terminal, so
every feature is scriptable + testable headlessly, and any failure that only
happens in the GUI is provably a GUI-layer bug.

**Rule that makes it hold:** a GUI slot must only *gather input and call a shared
core function* (in `cecore` or exposed via Lua) — never contain its own copy of
the logic. Then the terminal path and the GUI path run the same code.

**Status:** every functional GUI feature now has a headless path (no ❌ rows
remain). The five prioritized gaps are done, plus save/load table, trainer
generation, pointer scan, structure dissect, managed-runtime detect, code finder,
break-and-trace, branch mapper, register/stack read-write, find-statics, ceserver
connect, and address-list grouping/indent. Each is exercised by an automated test
in `cecore_test` (`test_lua_headless_bindings`, `test_lua_ceserver_connect`,
`test_trainer_generation`). The three remaining ⚠️ rows are partial-but-usable
(the capability exists; only a fuller dedicated helper is missing).

### Current headless surface

- **`cescan` CLI**: `list`, `read`, `write`, `scan` (exact/greater/less/between/
  changed/unchanged/increased/decreased/unknown), `pointerscan`.
- **Lua API**: 200 functions (memory read/write incl. locals, `createMemScan`
  first/next scan, `AOBScan[Ex|Module]`, address list + `createMemoryRecord`,
  `autoAssemble`/`assemble`/`disassemble`, `debug_*` breakpoints, `openProcess`/
  process list, symbols, `injectLibrary`/`allocateMemory`, `speedhack_setSpeed`,
  `captureSnapshot`/snapshot `:diff`/`:restore`, modules, regions, custom types,
  file I/O, the Lua form/trainer API, `saveTable`/`loadTable`, `pointerScan`,
  `dissectStructure`, `getManagedRuntimes`, `findWhatWrites`/`findWhatAccesses`,
  `breakAndTrace`, `branchMap`, and `debug_getRegisters`/`debug_setRegister`/
  `debug_getStack`).

### The enabling gap — DONE

- [x] **Headless Lua runner** (`cescan lua <file.lua> | -e "<code>" | - | <REPL>`).
      Runs the *same* `LuaEngine` the GUI console uses, with a headless
      `SimpleAddressList` so the table API works too. Verified end to end against a
      live process: `openProcess`, `readInteger`/`writeInteger`, and
      `createMemScan:firstScan` (found the value) all work from the terminal.

### Parity table

Legend: ✅ headless · ⚠️ partial · ❌ no headless equivalent · 🖼️ GUI view only

#### Process / table
| Feature | GUI | Headless | Note |
|---|---|---|---|
| Open process | File / crosshair | ✅ | `openProcess(pid)`, `getProcessList`, `cescan` (pid arg) |
| Connect to ceserver | File | ✅ | Lua `connectToCeserver(host, port, pid)` installs the remote process as the target |
| Pause / unpause | Process | ✅ | `pause()` / `unpause()` |
| Save / load cheat table | File, Table Extras | ✅ | Lua `saveTable(path)` / `loadTable(path)` |
| Create trainer | File | ✅ | Lua `generateTrainer(path)` (compiles a binary) / `generateTrainerSource()` |

#### Scan
| Feature | GUI | Headless | Note |
|---|---|---|---|
| First / next / undo scan | scan panel | ✅ | `createMemScan` (`firstScan`/`nextScan`), `cescan scan` |
| Scan/value type, hex, fast-scan, range | scan panel | ✅ | scan config fields on the MemScan/cescan call |
| Add result → address list | found-list menu | ✅ | `addressList_addEntry` / `createMemoryRecord` |

#### Address list
| Feature | GUI | Headless | Note |
|---|---|---|---|
| Add / remove / edit / type | table | ✅ | `createMemoryRecord`, `setTableEntry`, `addressList_*` |
| Freeze / freeze mode | table | ✅ | memory-record `Active` + freeze fields |
| Value hotkeys | table menu | ⚠️ | `createHotkey`/`setHotkeyAction` exist; not the full per-entry config |
| Group / indent / outdent | table menu | ✅ | Lua `createGroup([desc])` + memrec `.Indent` (indent = raise, outdent = lower) |

#### Memory view / disassembler
| Feature | GUI | Headless | Note |
|---|---|---|---|
| Disassemble / assemble | mem view | ✅ | `disassemble`, `assemble`, `autoAssemble` |
| Read/write at address | hex view | ✅ | `read*`/`write*` |
| NOP instruction / restore bytes | disasm menu | ✅ | `nopInstruction`, `writeBytes` |
| Navigate / bookmarks / goto | toolbar | 🖼️ | view state; the underlying reads are ✅ |
| File Patcher | Tools | ⚠️ | no dedicated verb; the GUI keeps its own QFile logic, but Lua file I/O (open/seek/write) patches a file on disk |

#### Debugger
| Feature | GUI | Headless | Note |
|---|---|---|---|
| Set / remove breakpoint | disasm, list | ✅ | `debug_setBreakpoint` / `debug_removeBreakpoint` |
| Continue / pump events | debugger | ✅ | `debug_continueFromBreakpoint` / `debug_pumpEvents` |
| Thread list | Tools | ✅ | `debug_getThreadList` / `getThreadList` |
| Register editor | Tools | ✅ | `debug_getRegisters([tid])` / `debug_setRegister(name,val)` (full GP + seg + debug regs; EAX-style aliases) |
| Stack view | Tools | ✅ | `debug_getStack([count])` → `{address,value}` at RSP (word size tracks bitness) |
| Find what accesses / writes | table/disasm menu | ✅ | `findWhatWrites(addr,secs,size)` / `findWhatAccesses(...)` (HW watchpoint) |
| Break and Trace | Tools | ✅ | `breakAndTrace(start,maxSteps,opts)` → decoded step list |
| Branch Mapper (LBR) | Tools | ✅ | `branchMap(secs,tid)` / `branchMapAvailable()` (hardware LBR; gated on perf) |

#### Other tools
| Feature | GUI | Headless | Note |
|---|---|---|---|
| Auto Assembler | Tools | ✅ | `autoAssemble` / `autoAssembleCheck` |
| Pointer Scanner | Tools | ✅ | `cescan pointerscan`; Lua `pointerScan(target,depth,off,opts)` |
| Structure Dissector | Tools | ✅ | Lua `dissectStructure(addr\|{addrs},size)` (discriminating-field detector) |
| Snapshot capture / diff / restore | Tools | ✅ | `captureSnapshot`, snapshot `:diff` / `:restore` |
| Speedhack | Tools | ✅ | `speedhack_setSpeed` / `setSpeed` |
| Detect Mono/.NET | Tools | ✅ | Lua `getManagedRuntimes()` → `detectManagedRuntimes` |
| ELF Inspector | Tools | ⚠️ | `getSymbolInfo` / symbols partial; no full inspector |
| Find Statics | Tools | ✅ | Lua `findStatics([module])` → `CodeAnalyzer::findStatics` |
| AOB scan | (scripts) | ✅ | `AOBScan[Ex|Module]` |
| Module list / memory regions | Tools | ✅ | `getModuleList`, `enumMemoryRegions`, `getRegionInfo` |
| Form Designer / overlay | Tools | 🖼️ | GUI/rendering; Lua form API exists for building forms |

### Gap list (prioritized)

1. **Headless Lua runner** — `cheatengine --script/-e` + REPL. Unlocks everything
   the 187-fn API already covers. (Highest leverage.)
2. ~~**Cheat-table save/load** as Lua fns~~ — **DONE**: `saveTable(path)` /
   `loadTable(path)` serialize the live address list to a `.CT/.json` (same format
   as the GUI). Verified round-trip from the terminal.
3. **Bind the unbound tools to Lua** (core logic already exists):
   ~~pointer scan~~ (**DONE** `pointerScan`), ~~structure dissect~~ (**DONE**
   `dissectStructure`), ~~detect-managed-runtime~~ (**DONE** `getManagedRuntimes`).
   ~~Remaining: find-what-accesses/writes, break-and-trace, branch mapper.~~ —
   **DONE**: `findWhatWrites`/`findWhatAccesses` (CodeFinder over a HW watchpoint),
   `breakAndTrace` (single-step Tracer), `branchMap`/`branchMapAvailable` (LBR;
   hardware-gated). Verified: findWhatWrites pinned the exact store instruction,
   breakAndTrace decoded the traced function, LBR reports availability cleanly.
4. ~~**Register / stack** read-write Lua fns for debug scripting.~~ — **DONE**:
   `debug_getRegisters` / `debug_setRegister` / `debug_getStack`, plus the
   breakpoint globals now publish the full register set (RSI/RDI/RBP/R8-R15/RFLAGS,
   not just 6). Verified at a live breakpoint.
5. ~~**Per-feature headless tests** in `cecore_test`.~~ — **DONE**:
   `test_lua_headless_bindings` forks live children and drives every new binding
   through the real `LuaEngine` (saveTable/loadTable, getManagedRuntimes,
   dissectStructure, pointerScan, findWhatWrites, breakAndTrace, debug register /
   stack read-write at a breakpoint, branchMapAvailable). "Does it work?" is now an
   automated yes/no in the suite.

### Not applicable (GUI-only, expected)

Pure view/render/interaction: window navigation, bookmarks UI, overlay rendering,
form-designer canvas. These stay GUI-tested (offscreen smoke tests).

---

<!-- was: VS_OFFICIAL_CE_LINUX.md -->

## cheat-engine-linux (cecore) vs. official Cheat Engine 7.7 Linux

**Purpose:** a reassessment doc. On 2026-05-29, Cheat Engine 7.7 shipped the first
*official* native Linux build. That removes this project's original one-line
reason to exist ("there is no native Linux CE"). This file compares the two
honestly so we can decide whether to differentiate, pivot, continue, or wind down.

**Date:** 2026-07-11. **Confidence note:** cecore's column is verified (from
`FEATURE_GAP.md` + test suite). The official-CE-Linux column is partly *inferred*:
the 7.7 Linux source is not public yet (repo issue #3357 open) and the changelog is
Patreon-walled, so items marked "(inferred)" are reasoned from CE's architecture,
not confirmed on a running Linux 7.7 build. Re-verify before betting the project on
any single row.

---

### 1. TL;DR

- The official Linux CE is **the real CE codebase** (Lazarus/FreePascal) cross-compiled
  with a **GTK/Qt5 widgetset** — not Wine. Dark Byte's own words: *"works, mostly."*
  Because it's the same app, it inherits ~all of CE's mature, cross-platform feature
  set on day one. We **cannot** win on breadth or maturity.
- What the official build likely **lacks on Linux** is the Windows-kernel stack:
  DBVM hypervisor, DBK kernel driver, kernel-mode debugger, Ultimap (BTS/PT). The
  `.NET`/Mono dissector is an open question (its collector is a Windows DLL).
- **cecore's only defensible edges:** open-source & hackable (their Linux source
  isn't even public), a clean **C++20/23 + native Qt6** codebase (vs a 20-year-old
  Object-Pascal/LCL shim), **free** (no Patreon wall), and room to go **Linux-first**
  (Wayland, Vulkan OSD, Proton/Wine game introspection, distro packaging, embeddable
  `libcecore`). Chasing raw CE feature-parity is now a treadmill we lose.

---

### 2. What officially shipped (facts)

| | Detail |
|---|---|
| Version | Cheat Engine **7.7**, released **2026-05-29** (first official Linux support) |
| How | Native **Lazarus/FreePascal** CE, **GTK/Qt5** widgetset (from the internal 7.5.4 gtk/qt5 test). **Not Wine.** |
| Backend | Local memory access via CE's existing **ceserver** path (`/proc`, `process_vm_readv`, ptrace) — mature, years old |
| Maturity | Dark Byte: *"actually works, mostly."* Linux-support tracking issue #3216 still **open** |
| Distribution | **Patreon-first** for newest builds; a public build exists. **7.7 source not on GitHub yet** (issue #3357 open); public tree still at 7.5 |
| License | CE's own restrictive license (not OSI). Source availability for the Linux build is currently unclear |

---

### 3. Feature-by-feature

Legend: ✅ solid · 🟡 partial/weak · ❌ absent · ❔ unknown/unverified

#### 3a. Core (where we're at rough parity)

| Capability | cecore | Official CE 7.7 Linux | Notes |
|---|---|---|---|
| Memory scanner (all types, all comparators, %, float rounding, AOB wildcards, case-insensitive) | ✅ | ✅ | CE is the reference impl; ours is verified feature-complete |
| Value types incl. grouped, custom Lua formula | ✅ | ✅ | |
| Cheat table `.CT` (CE-compatible XML, groups, pointer records) | ✅ round-trips CE tables | ✅ native | We import/export CE's format; real interop |
| Memory browser: hex + live disassembly | ✅ | ✅ | |
| Disassembler (Capstone): RIP resolution, jump arrows, xrefs, C++ demangling, DWARF source lines, db-fallback | ✅ | ✅ (inferred) | Ours is genuinely strong here |
| Assembler (Keystone), inline assemble/NOP | ✅ | ✅ | |
| Auto Assembler: alloc/label/aobscanmodule, code-injection + AOB-injection templates, `[ENABLE]/[DISABLE]` | ✅ | ✅ | The AA language is CE's; we implement a large subset |
| Structure dissector (multi-type, pointer follow, compare, save/load) | ✅ | ✅ (redesigned in 7.7) | 7.7 explicitly reworked dissect internals |
| Pointer scanner (BFS paths, rescan, save/load `.ptr`) | ✅ | ✅ | |
| Lua scripting (broad CE-compatible API) | 🟡 large subset | ✅ full | CE's Lua surface is huge; we cover the common core |
| ELF inspector | ✅ | ❔ | CE has a PE-centric memory view; ELF-native tooling may be an edge for us |
| ceserver client (connect to remote target) | ✅ | ✅ | Same protocol |

#### 3b. Debugging

| Capability | cecore | Official CE 7.7 Linux | Notes |
|---|---|---|---|
| Find what writes/accesses (HW watchpoints, DR0-3, multi-thread) | ✅ verified | ✅ | Ours works on non-root via `PR_SET_PTRACER_ANY` |
| Software breakpoints (int3) | 🟡 single-thread | ✅ | |
| **Interactive step debugger** (attach, step, continue, breakpoint UI, multi-thread) | ✅ shipped + polished (2026-07) | ✅ | `DebuggerWindow`: attach, step into/over, continue, multi-thread (`PTRACE_O_TRACECLONE`). Polish: **conditional breakpoints** (Lua expr on register state, auto-continue when false), **data breakpoints** (hardware DR0-3 watchpoints, break on write/access), **break-on-exceptions** menu (SIGSEGV/…), and the Memory Viewer step buttons now open it. Verified by `gui_debugger_smoke`. |
| Register / FPU / stack / thread / module / heap views | ✅ | ✅ (7.7 improved FPU-change display) | |
| Break-and-trace | ✅ | ✅ | |
| Branch tracing | 🟡 LBR branch mapper (our Ultimap analog) | ✅ Ultimap/Ultimap2 (Windows; Linux ❔) | |

#### 3c. Windows-kernel stack (structural)

| Capability | cecore | Official CE 7.7 Linux | Notes |
|---|---|---|---|
| DBVM hypervisor | ❌ (Linux kmod + LBR instead) | ❔ likely ❌ on Linux | DBVM is x86 VT-x; not a Linux user feature |
| DBK kernel driver / kernel-mode debug / stealth | ❌ | ❔ likely ❌ on Linux | Windows-only driver |
| Mono dissector (live) | ✅ **complete end to end** | ❔ (collector is a Windows DLL) | **Big deal for Linux:** most Linux/Proton games are Unity. Agent (`plugins/mono_agent.c`) resolves the mono_* API in-process for GROUND-TRUTH image/class/field offsets; host (`analysis/mono_dissector`) injects + parses into a model; `monoDissect()` Lua binding; Tools ▸ "Mono dissector..." GUI (browse assemblies→classes→fields, add base+offset to the list). Verified live via runtime injection: 5046 classes, Player.health@0x18, statics tagged |
| IL2CPP dissector (live) | 🟡 detected + reported; live deferred | ❔ | `detectManagedKind()` classifies Mono/IL2CPP/none from modules; GUI+Lua report IL2CPP distinctly instead of failing. Offline `global-metadata.dat` string parser exists. Live field-offset resolution (metadata tables + runtime registration) needs a real IL2CPP game to build+validate — separate track |

#### 3d. Linux-native / gaming (our natural turf)

| Capability | cecore | Official CE 7.7 Linux | Notes |
|---|---|---|---|
| Proton/Wine game introspection (WoW64, Wine PE modules, 32-bit inject) | ✅ real work done | ❔ not a CE focus | **Strongest differentiator** — this is where Linux gaming actually lives |
| Vulkan overlay OSD | ✅ | ❔ | |
| Speedhack | 🟡 LD_PRELOAD works; injected-lib path doesn't scale time yet | ✅ (7.7 improved mono/unity speedhack) | Known limitation documented in our tracker |
| Library injection | 🟡 userspace-thread hijack; fragile at safe-points | ✅ | |
| Native Qt6 GUI (HiDPI/Wayland-friendly) | ✅ | 🟡 LCL→GTK/Qt5 shim | Ours is architecturally cleaner for modern Linux desktops |
| Packaging (AppImage/Flatpak) | 🟡 AppImage target exists | ❔ | Issue #3216 specifically asks for this — an easy win to own |
| **Open source / hackable** | ✅ MIT-ish, public | ❌ source not public, restrictive license | Our clearest structural advantage |

---

### 4. Where cecore is genuinely ahead

1. **Open, modern, hackable codebase.** C++20/23 + native Qt6, ~40k lines, 229-assertion
   test suite. Their Linux source isn't even published. For anyone who wants to *read,
   fork, embed, or extend* a Linux memory tool, we're the only option.
2. **Linux-first, Proton-aware.** The WoW64 / Wine-PE / 32-bit-injection work targets the
   *actual* Linux gaming reality (Proton). CE treats Linux as a port target, not home.
3. **Embeddable potential (`libcecore`).** A clean C++ engine + CLI other tools can build on.
   CE is a monolithic GUI app; it can't be a library.
4. **Free and unwalled.** Latest official Linux builds are Patreon-first.

### 5. Where the official build is (and will stay) ahead

1. **Breadth & maturity** — 20 years of features, the canonical AA/Lua semantics, the
   mono/Unity tooling, the full interactive debugger. We will always trail.
2. **Ecosystem** — community cheat tables, the CE tutorial, thousands of existing Lua
   scripts and trainers, name recognition. This is the real moat, and it's not code.
3. **Authority** — it's *the* Cheat Engine. "CE-parity clone" is a weak pitch when the
   real thing now runs natively.

---

### 6. Options & recommendation

| Option | Bet | Verdict |
|---|---|---|
| **A. Chase CE parity (status quo `/loop`)** | Match CE feature-for-feature | ❌ Weakest. We lose to the real thing on its own terms |
| **B. Differentiate, Linux-first** | Open-source, free, Proton/Wine-aware, Wayland/Vulkan, packaged | ✅ Strongest product angle. Plays to work already done |
| **C. Pivot to `libcecore` + CLI** | Reusable engine other tools embed | ✅ Strong if we value being infrastructure over being an app |
| **D. Reframe as portfolio/learning** | It's a serious systems-programming showcase | ✅ Always valid; low stakes |
| **E. Wind down** | Official CE covers the need | Honest, but premature given B/C exist |

**Recommendation:** stop framing it as "reimplement CE for Linux." Lead with **B**
(Linux-first, Proton-aware, open, packaged), optionally carved so the engine is reusable
(**C**). Concretely, the highest-leverage next moves are:
- Own the **Proton/Wine gaming** story (the one thing CE won't prioritize).
- Ship **AppImage/Flatpak** (issue #3216 literally asks for it).
- Close the **interactive multi-thread debugger** gap (our most visible functional hole).
- Attack **native Mono/Unity dissection** (where Linux games actually are).
- Drop the "match every CE menu item" north star from the loop.

None of this requires deciding today — but the loop's current target ("CE parity") should
change before more iterations run against it.
