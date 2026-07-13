# CLI / headless parity audit

**Principle:** everything the GUI can do should be doable from the terminal, so
every feature is scriptable + testable headlessly, and any failure that only
happens in the GUI is provably a GUI-layer bug.

**Rule that makes it hold:** a GUI slot must only *gather input and call a shared
core function* (in `cecore` or exposed via Lua) — never contain its own copy of
the logic. Then the terminal path and the GUI path run the same code.

## Current headless surface

- **`cescan` CLI**: `list`, `read`, `write`, `scan` (exact/greater/less/between/
  changed/unchanged/increased/decreased/unknown), `pointerscan`.
- **Lua API**: 187 functions (memory read/write incl. locals, `createMemScan`
  first/next scan, `AOBScan[Ex|Module]`, address list + `createMemoryRecord`,
  `autoAssemble`/`assemble`/`disassemble`, `debug_*` breakpoints, `openProcess`/
  process list, symbols, `injectLibrary`/`allocateMemory`, `speedhack_setSpeed`,
  `captureSnapshot`/snapshot `:diff`/`:restore`, modules, regions, custom types,
  file I/O, and the Lua form/trainer API).

## The enabling gap — DONE

- [x] **Headless Lua runner** (`cescan lua <file.lua> | -e "<code>" | - | <REPL>`).
      Runs the *same* `LuaEngine` the GUI console uses, with a headless
      `SimpleAddressList` so the table API works too. Verified end to end against a
      live process: `openProcess`, `readInteger`/`writeInteger`, and
      `createMemScan:firstScan` (found the value) all work from the terminal.

## Parity table

Legend: ✅ headless · ⚠️ partial · ❌ no headless equivalent · 🖼️ GUI view only

### Process / table
| Feature | GUI | Headless | Note |
|---|---|---|---|
| Open process | File / crosshair | ✅ | `openProcess(pid)`, `getProcessList`, `cescan` (pid arg) |
| Connect to ceserver | File | ❌ | client exists in core; no Lua/CLI binding |
| Pause / unpause | Process | ✅ | `pause()` / `unpause()` |
| Save / load cheat table | File, Table Extras | ❌ | `CheatTable::saveJson/loadJson` in core; not bound to Lua/CLI |
| Create trainer | File | ❌ | no headless generator |

### Scan
| Feature | GUI | Headless | Note |
|---|---|---|---|
| First / next / undo scan | scan panel | ✅ | `createMemScan` (`firstScan`/`nextScan`), `cescan scan` |
| Scan/value type, hex, fast-scan, range | scan panel | ✅ | scan config fields on the MemScan/cescan call |
| Add result → address list | found-list menu | ✅ | `addressList_addEntry` / `createMemoryRecord` |

### Address list
| Feature | GUI | Headless | Note |
|---|---|---|---|
| Add / remove / edit / type | table | ✅ | `createMemoryRecord`, `setTableEntry`, `addressList_*` |
| Freeze / freeze mode | table | ✅ | memory-record `Active` + freeze fields |
| Value hotkeys | table menu | ⚠️ | `createHotkey`/`setHotkeyAction` exist; not the full per-entry config |
| Group / indent / outdent | table menu | ❌ | no headless binding |

### Memory view / disassembler
| Feature | GUI | Headless | Note |
|---|---|---|---|
| Disassemble / assemble | mem view | ✅ | `disassemble`, `assemble`, `autoAssemble` |
| Read/write at address | hex view | ✅ | `read*`/`write*` |
| NOP instruction / restore bytes | disasm menu | ✅ | `nopInstruction`, `writeBytes` |
| Navigate / bookmarks / goto | toolbar | 🖼️ | view state; the underlying reads are ✅ |
| File Patcher | Tools | ❌ | no headless patcher |

### Debugger
| Feature | GUI | Headless | Note |
|---|---|---|---|
| Set / remove breakpoint | disasm, list | ✅ | `debug_setBreakpoint` / `debug_removeBreakpoint` |
| Continue / pump events | debugger | ✅ | `debug_continueFromBreakpoint` / `debug_pumpEvents` |
| Thread list | Tools | ✅ | `debug_getThreadList` / `getThreadList` |
| Register editor | Tools | ⚠️ | registers surface at a stop; no dedicated read/write-register Lua fn |
| Stack view | Tools | ⚠️ | reachable via memory reads at RSP; no dedicated binding |
| Find what accesses / writes | table/disasm menu | ❌ | code-finder not bound (could ride HW watchpoints) |
| Break and Trace | Tools | ❌ | no headless binding |
| Branch Mapper (LBR) | Tools | ❌ | no headless binding |

### Other tools
| Feature | GUI | Headless | Note |
|---|---|---|---|
| Auto Assembler | Tools | ✅ | `autoAssemble` / `autoAssembleCheck` |
| Pointer Scanner | Tools | ✅ | `cescan pointerscan`; Lua `pointerScan(target,depth,off,opts)` |
| Structure Dissector | Tools | ✅ | Lua `dissectStructure(addr\|{addrs},size)` (discriminating-field detector) |
| Snapshot capture / diff / restore | Tools | ✅ | `captureSnapshot`, snapshot `:diff` / `:restore` |
| Speedhack | Tools | ✅ | `speedhack_setSpeed` / `setSpeed` |
| Detect Mono/.NET | Tools | ✅ | Lua `getManagedRuntimes()` → `detectManagedRuntimes` |
| ELF Inspector | Tools | ⚠️ | `getSymbolInfo` / symbols partial; no full inspector |
| Find Statics | Tools | ❌ | no headless binding |
| AOB scan | (scripts) | ✅ | `AOBScan[Ex|Module]` |
| Module list / memory regions | Tools | ✅ | `getModuleList`, `enumMemoryRegions`, `getRegionInfo` |
| Form Designer / overlay | Tools | 🖼️ | GUI/rendering; Lua form API exists for building forms |

## Gap list (prioritized)

1. **Headless Lua runner** — `cheatengine --script/-e` + REPL. Unlocks everything
   the 187-fn API already covers. (Highest leverage.)
2. ~~**Cheat-table save/load** as Lua fns~~ — **DONE**: `saveTable(path)` /
   `loadTable(path)` serialize the live address list to a `.CT/.json` (same format
   as the GUI). Verified round-trip from the terminal.
3. **Bind the unbound tools to Lua** (core logic already exists):
   ~~pointer scan~~ (**DONE** `pointerScan`), ~~structure dissect~~ (**DONE**
   `dissectStructure`), ~~detect-managed-runtime~~ (**DONE** `getManagedRuntimes`).
   Remaining: find-what-accesses/writes (code finder), break-and-trace, branch
   mapper — these need a live debug session, so they land with Step 4.
4. **Register / stack** read-write Lua fns for debug scripting.
5. **Per-feature headless tests** in `cecore_test` (or a Lua test dir) as each gap
   closes — so "does everything work?" becomes an automated yes/no.

## Not applicable (GUI-only, expected)

Pure view/render/interaction: window navigation, bookmarks UI, overlay rendering,
form-designer canvas. These stay GUI-tested (offscreen smoke tests).
