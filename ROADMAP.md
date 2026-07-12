# Roadmap — complete gap analysis (2026-07-12)

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

## Progress (loop, 2026-07-12)

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
  + `nopInstruction`
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
  dropdown (gui_debugger_smoke `threadsw=1`) · **P2
  #22 (partial)** embedded `<Forms>` preserved verbatim across `.CT` load/save
  (Delphi form designs no longer dropped on re-save).
- **P3 #27** light theme (dead toggle fixed) · **P3 #28** `CONTRIBUTING.md`.

Remaining: **#15** debugger unification (the big P2 lever); #16 full flags/XMM
register view + #21 dissector work; #24 ceserver daemon; more of #23.
Genuinely blocked on real-world testing / a strategic call: **#10 Mono/Unity**,
**#11 Vulkan overlay**, **#12 Wayland hotkeys**, #25 ARM, #26 32-bit inject.

---

## P0 — Integrity & blockers (small, do first)

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

## P1 — Security (this tool runs as root and loads shared tables)

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

## P1 — Realize the Linux-first differentiators (the strategic bet)

The reassessment (`VS_OFFICIAL_CE_LINUX.md`) leans on these to justify existing
alongside official CE 7.7 Linux. Today each is materially short of the claim.

10. **Native Mono / Unity / IL2CPP dissector — the single highest-impact gap.**
    Today: a detection message box + a heap-scanning heuristic that guesses class
    names from printable bytes (`analysis/managed_runtime.cpp:213-295`); the Mono
    soft-debugger client is wired to nothing and needs `--debugger-agent`; zero
    IL2CPP, zero `mono_*` Lua. CE injects a collector that walks real Mono
    metadata (Assembly→Class→Field/Method, true offsets, method invocation).
    **Most Linux/Proton games are Unity** — this is the niche the project says it
    can win, and it's currently opaque. Build an injected Mono-embedding-API
    collector; then IL2CPP `global-metadata.dat` parsing. **[L]**
11. **In-game overlay actually renders.** `platform/vulkan_overlay_layer.cpp`
    advertises a layer but only forwards `vkCreateInstance/Device` — it never
    hooks `vkQueuePresentKHR` and draws nothing. The Qt overlay
    (`gui/overlay.cpp`) uses X11-only window hints, so it won't float over a
    game on Wayland/gamescope (the Steam Deck reality). Implement a real
    present-hook that blits an OSD. **[L]**
12. **Wayland global hotkeys.** `gui/globalhotkeys.cpp` is entirely
    `XGrabKey`/xcb; on Wayland it degrades to focus-only Qt shortcuts — dead
    exactly when the game has focus. Add an `xdg-desktop-portal` GlobalShortcuts
    (or evdev) backend. **[M-L]**
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

## P2 — Finish the debugger (just shipped v1) — unify the breakpoint layer

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

## P2 — Breadth / CE parity

19. **Pointer scanner: reusable pointermap + value-filtered rescan.** No
    pointermap (CE reuses one for fast rescans) and rescan filters only by exact
    resolved address, not by the pointed-to value — so the canonical
    scan/restart/rescan-by-value workflow is manual. **[M]**
20. **Symbols: build-id / `.gnu_debuglink` / MiniDebugInfo + DWARF types.** No
    separate-debug-file resolution (stripped libc/drivers/games show raw
    addresses), and DWARF extraction is line-table + function names only (no
    struct/member/variable types). **[M]**
21. **Structure dissector: multi-instance columns + RTTI/managed typing.**
    Single base address today (`gui/structuredissector.cpp`); CE diffs many live
    instances side-by-side and detects class names. **[M]** (managed typing
    depends on #10)
22. **Cheat table: embed Form Designer forms + custom types.** No `<Forms>`
    handling; the Form Designer saves standalone `.json` instead of into the
    `.CT`, so full trainers don't round-trip. **[S-M]**
23. **Lua surface breadth.** Missing chunks of CE's API: `executeCode`,
    `createDissectCode`/`dissectCode`, structure-definition APIs, the
    `disassembler()`/`getMemoryViewForm` objects, symbol-handler control, and
    `memoryrecord` pointer/offset + child/group methods (can't script pointer
    chains or group hierarchies). **[L overall, S-M each]**

## P3 — Reach & polish

24. **ceserver daemon** (be a server, not just a client) — expose a headless/
    embedded Linux box as a target. **[M]**
25. **ARM64/ARM32 support** — `CpuContext` and the injector are x86-64-only;
    excludes Asahi/ARM handhelds. **[L]**
26. **32-bit / WoW64 injection** — `injector.cpp` refuses 32-bit targets
    (`:152,:295`), so `injectLibrary`/injected-speedhack don't work on 32-bit
    Proton games (scanning + AA hooks do). Honestly scope this in the docs
    meanwhile. **[M]**
27. **Light theme** (the settings toggle is a dead no-op, `gui/main.cpp:56`
    always applies dark) + a HiDPI/fractional-scaling audit of the custom
    painters. **[S]**
28. **`CONTRIBUTING.md` + Lua API reference + a tutorial** + issue/PR templates —
    none exist; contributor/adoption blockers. **[M]**
29. **Kernel-module ioctl test harness** — `kernel/cecore_kmod.c` (an
    `ioremap`/`memcpy_toio` write primitive) is the most security-sensitive code
    and is never loaded/tested; CI build is `continue-on-error`. **[M]**

---

## Quick-win batch (all S, high value — recommended first sprint)

P0 items 1-5 + Flatpak/AppStream (13, the S part) + light theme (27) +
`SECURITY.md` (9). A day or two of work that makes CI actually protective, makes
the project legally distributable, and lands two visible user wins.

## Suggested sequencing

1. **Sprint 0 (quick wins):** P0 1-5, + LICENSE, + Flatpak, + `--version`.
2. **Harden:** security P1 (6-9) — matters most because the tool is root + loads
   shared tables.
3. **Pick the strategic bet:** commit to the Linux-first direction from
   `VS_OFFICIAL_CE_LINUX.md`, then do #10 (Mono/Unity) and #11-14 in that order.
   If instead the direction is "clean engine others embed," do #14 first.
4. **Finish the debugger:** #15 (unify breakpoints) unlocks #16-18 and the Lua
   debug API together.
5. **Breadth** (#19-23) and **reach** (#24-29) as capacity allows.
