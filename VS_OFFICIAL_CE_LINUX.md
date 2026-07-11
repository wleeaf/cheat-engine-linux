# cheat-engine-linux (cecore) vs. official Cheat Engine 7.7 Linux

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

## 1. TL;DR

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

## 2. What officially shipped (facts)

| | Detail |
|---|---|
| Version | Cheat Engine **7.7**, released **2026-05-29** (first official Linux support) |
| How | Native **Lazarus/FreePascal** CE, **GTK/Qt5** widgetset (from the internal 7.5.4 gtk/qt5 test). **Not Wine.** |
| Backend | Local memory access via CE's existing **ceserver** path (`/proc`, `process_vm_readv`, ptrace) — mature, years old |
| Maturity | Dark Byte: *"actually works, mostly."* Linux-support tracking issue #3216 still **open** |
| Distribution | **Patreon-first** for newest builds; a public build exists. **7.7 source not on GitHub yet** (issue #3357 open); public tree still at 7.5 |
| License | CE's own restrictive license (not OSI). Source availability for the Linux build is currently unclear |

---

## 3. Feature-by-feature

Legend: ✅ solid · 🟡 partial/weak · ❌ absent · ❔ unknown/unverified

### 3a. Core (where we're at rough parity)

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

### 3b. Debugging

| Capability | cecore | Official CE 7.7 Linux | Notes |
|---|---|---|---|
| Find what writes/accesses (HW watchpoints, DR0-3, multi-thread) | ✅ verified | ✅ | Ours works on non-root via `PR_SET_PTRACER_ANY` |
| Software breakpoints (int3) | 🟡 single-thread | ✅ | |
| **Interactive step debugger** (attach, step, continue, breakpoint UI, multi-thread) | ❌ **not shipped** | ✅ | **Our biggest functional gap.** Needs `PTRACE_O_TRACECLONE` + task iteration in the tracer loop |
| Register / FPU / stack / thread / module / heap views | ✅ | ✅ (7.7 improved FPU-change display) | |
| Break-and-trace | ✅ | ✅ | |
| Branch tracing | 🟡 LBR branch mapper (our Ultimap analog) | ✅ Ultimap/Ultimap2 (Windows; Linux ❔) | |

### 3c. Windows-kernel stack (structural)

| Capability | cecore | Official CE 7.7 Linux | Notes |
|---|---|---|---|
| DBVM hypervisor | ❌ (Linux kmod + LBR instead) | ❔ likely ❌ on Linux | DBVM is x86 VT-x; not a Linux user feature |
| DBK kernel driver / kernel-mode debug / stealth | ❌ | ❔ likely ❌ on Linux | Windows-only driver |
| `.NET` / Mono / IL2CPP dissector | 🟡 runtime **detection** only | ❔ (collector is a Windows DLL) | **Big deal for Linux:** most Linux/Proton games are Unity. Whoever nails native Mono/Unity dissection wins that niche |

### 3d. Linux-native / gaming (our natural turf)

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

## 4. Where cecore is genuinely ahead

1. **Open, modern, hackable codebase.** C++20/23 + native Qt6, ~40k lines, 229-assertion
   test suite. Their Linux source isn't even published. For anyone who wants to *read,
   fork, embed, or extend* a Linux memory tool, we're the only option.
2. **Linux-first, Proton-aware.** The WoW64 / Wine-PE / 32-bit-injection work targets the
   *actual* Linux gaming reality (Proton). CE treats Linux as a port target, not home.
3. **Embeddable potential (`libcecore`).** A clean C++ engine + CLI other tools can build on.
   CE is a monolithic GUI app; it can't be a library.
4. **Free and unwalled.** Latest official Linux builds are Patreon-first.

## 5. Where the official build is (and will stay) ahead

1. **Breadth & maturity** — 20 years of features, the canonical AA/Lua semantics, the
   mono/Unity tooling, the full interactive debugger. We will always trail.
2. **Ecosystem** — community cheat tables, the CE tutorial, thousands of existing Lua
   scripts and trainers, name recognition. This is the real moat, and it's not code.
3. **Authority** — it's *the* Cheat Engine. "CE-parity clone" is a weak pitch when the
   real thing now runs natively.

---

## 6. Options & recommendation

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
