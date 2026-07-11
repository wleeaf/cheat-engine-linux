# cecore vs Cheat Engine — capability gap tracker

Living document for the "implement everything CE has" effort. Updated each loop
iteration. Sources: cheat-engine wiki, CE tutorial, and direct GUI testing of
cecore this session.

> **Repo status (2026-07-11):** the project is now a single self-contained
> repository at the top level (no `cecore/` subdir); Lua 5.3 is vendored under
> `third_party/lua` and the build is offline. Note that Cheat Engine 7.7 (2026-05-29)
> shipped an official native Linux build — see `VS_OFFICIAL_CE_LINUX.md` for the
> repositioning discussion. Still-open items (not counting intentional Windows-kernel
> omissions): the **interactive step-debugger UI** (🔧, not shipped) and
> **speedhack-by-injection timing** (🟡, only LD_PRELOAD scales time).

## Legend
✅ have (verified in GUI) · 🟡 partial · ❌ missing · 🔧 in progress

## Have (verified working in the GUI this session)
- ✅ Memory scanner: exact / bigger / smaller / **between** / unknown / increased /
  decreased / changed / unchanged / same-as-first; %compare; float rounding.
- ✅ Value types: Byte/2/4/8, Float, Double, Text, Unicode, AOB, Binary, All, Pointer,
  Grouped, Custom(Lua formula). Fast scan + alignment. From/To range.
- ✅ Next scan (all comparators). **Live-refreshing results list** (fixed this iter).
- ✅ Address list / cheat table: add manually, groups, indent, freeze (+ freeze modes),
  save/load .CT (CE-compatible XML), value + inc/dec hotkeys.
- ✅ Memory Browser: live disassembly + hex, go-to-address, ELF symbol labels.
- ✅ Structure Dissector (Int8/16/32/Float/pointer columns, pointer detection).
- ✅ Pointer Scanner (BFS paths, save/load .ptr, GPU option).
- ✅ Auto Assembler: templates, Syntax Check, Execute (real inject), Disable/restore,
  **auto code-injection generator** (with original-bytes db), **AOB injection**
  (aobscanmodule + alloc near symbol), mprotect-on-write for r-x pages.
- 🟡 Debugger: **HW watchpoint find-what-writes/accesses (multithread, all
  threads)** is the fully-wired, functional GUI feature. Software bp (int3/
  POKETEXT), exception bp, and breakpoint-list arming exist as real, unit-tested
  backends (`DebugSession`, `BreakpointManager`) but are NOT yet wired into the
  shipped GUI/Lua — corrected by the 2026-07-11 code audit; being wired up by the
  interactive step-debugger work.
- ✅ Register editor (GP+XMM/YMM), stack view, thread list, module list, memory
  regions, heap regions.
- ✅ Code analysis: strings, calls, jumps, RIP-relative, code caves, find statics.
- ✅ ELF Inspector (header/sections/segments/dynamic/symbols/notes).
- ✅ Lua console (readInteger/writeInteger/…), Form Designer (trainer forms),
  File Patcher, Snapshot capture/diff/restore, Break&Trace, Branch Mapper (LBR),
  Overlay (OSD), Speedhack, ceserver connect, Wait-for-process.

## Priority gaps (next iterations)

### Memory view
- ✅ Hex-view in-place byte editing: select a byte and type hex digits to patch
  memory (nibble-by-nibble, auto-advance; mprotect fallback for r-x pages).
  Arrow keys move the cursor. Clicking the ASCII column edits as characters.
- ✅ Memory search (Ctrl+F): find hex bytes OR "quoted text" region-aware from
  the current address; F3 = find next.
- ✅ Address bar accepts expressions: symbols (worker), module+offset
  (target2+0x100), pointer derefs ([rax+8]), #decimal, or hex. (Extended the old hex-only find.)

### Lua API
- ✅ Added the core process reads/writes that were missing: readInteger,
  writeInteger, readFloat, writeFloat, readBytes (table + multi-return). The
  most-used CE Lua functions; previously only *Local variants existed.
- ✅ AOBScan / AOBScanEx with ?? wildcards (verified: pattern -> correct addr).
- ✅ getModuleBase / getModuleSize (case-insensitive by name or basename), enabling
  the getModuleBase("game")+offset addressing pattern.
- ✅ FIXED: getAddressFromName / registerSymbol / unregisterSymbol were no-ops
  (no SymbolResolver was ever wired into the LuaEngine); now the console loads
  process symbols + registered names resolve.

### Scanning
- ✅ Next-scan: added "Increased value by..." / "Decreased value by..." (exact-delta
  relative compares) alongside the existing increased/decreased/changed/unchanged/
  same-as-first/between/bigger/smaller/unknown set.
- ✅ Scan From/To range fields accept expressions (module name, module+offset,
  symbol, hex) e.g. target2 .. target2+0x8000.
- ✅ FIXED dead "Add Address" button; both it and "Add Address Manually" accept
  symbol/module+offset expressions.
- ✅ "Hex" checkbox: parse integer scan values (and the between upper bound) as
  hexadecimal.
- ✅ Address-list per-entry "Show as hexadecimal": display + edit an entry value
  in hex (checkable toggle).
- ✅ Address-list "Change type" submenu: switch an entry's value type in place
  (Byte/2/4/8/Float/Double/Pointer), value reinterprets.

### Scan results UX
- ✅ Results right-click menu: add selected (multi) to address list, browse
  region, copy address(es); extended multi-selection.

### P0 — disassembler tech (user asked explicitly) — DONE
- ✅ Cross-references: "Find references to this address" scans the module for
  call/jump/data refs and lists them (double-click navigates).
- ✅ Jump/branch arrows: visual lines from jmp/jcc to on-screen targets (blue=jmp,
  peach=conditional), lane-assigned to avoid overlap, arrowhead at the target.
- ✅ Inline resolved comments: RIP-relative data refs now show effective address,
  symbol, and the referenced value/string (mov/lea/cmp/…); call/jmp target symbols.
- 🟡 Right-click in disassembler: ✅ Assemble/replace, ✅ NOP, ✅ set/remove breakpoint,
  ✅ follow jump/call, ✅ copy bytes, ✅ go-to-address history (back/fwd),
  ✅ user labels, ✅ inline user comments, ✅ follow RIP-relative data refs,
  ✅ copy line (addr - bytes - text).
- ✅ User-defined symbols: 'Label this address…' names an address; the label shows
  in the symbol line and in call/jmp/data annotations (highest resolve() priority).
- 🟡 Operand-level detail from Capstone (CS_OPT_DETAIL) — needed for xrefs/arrows.

### P1 — scanning / results
- ✅ Manual "Refresh values" (F5) forces an immediate results/address-list refresh.
- ✅ Configurable auto-refresh interval: the Settings > Memory View interval now
  drives the results/address-list AND memory-browser timers (was saved but
  ignored — hardcoded 1000/2000).
- ✅ Results colouring: values that changed since the last refresh render red
  (revert to normal when stable).
- ✅ Pointer scan rescan (filter paths against a new target after the value moved)
  + Save/Load .ptr, exposed in the GUI.
- ✅ "Add selected result(s) to address list": multi-select context menu + Enter key.

### P1 — pointer records
- ✅ Pointer memory records: a record's Address can be an expression
  ("[base+off]+off2", multi-level derefs) that is re-resolved live on every refresh,
  so the entry follows a moving pointer chain. Set via mr.Address='[..]' (Lua) or a
  non-numeric address string; persisted as addressExpr in the cheat table. Verified vs
  target2: [cave]->g_val resolves, and follows when the pointer is repointed.
  ✅ Creatable from the GUI: 'Add Address Manually' with a '[pointer]+off' string makes
  a live pointer record (verified: entry Address resolves to g_val, Value tracks it).
  ✅ FIXED multi-level pointers: the deref used find(']') (first bracket) so '[[base]]' split its
  inner bracket and failed — now finds the MATCHING ']' by depth. Verified 2-level '[[c1]]'=7777.
  ✅ FIXED single-digit hex offsets: resolveToken required size>=2 for plain-hex, so '[base]+8'
  resolved as +0 — now single digits 0-9 parse as hex. Verified '[[c1]]+4'=8888. 172/172 tests pass.
  ✅ Also a lone hex LETTER offset ('+c','+a','+f') now resolves: added a hex fallback in
  resolveToken AFTER symbol/module lookup (CE tries symbol first, then hex). Verified '[[c1]]+c'=9999.

### P1 — structure dissect
- 🟡 ✅ Autoguess field types (pointer/float/int, readability-verified pointers) +
  ✅ add field to address list with guessed type, ✅ configurable size,
  ✅ named fields (double-click), ✅ save/load defs (JSON), ✅ compare structs (Compare address field red-highlights rows whose 8 bytes differ).
  Verified: base=g_val vs compare=g_val+8 -> rows +0x00/+0x08 red (differ), zero-filled
  +0x10/+0x18 not highlighted (match).

### P1 — Lua API breadth
- 🟡 CE Lua surface: ✅ createTimer (lua_gui), ✅ createHotkey, ✅ getTickCount,
  ✅ outputDebugString, ✅ byteTableToString/stringToByteTable, ✅ word/dword/qwordToByteTable + byteTableToDwordTable, ✅ extractFileName/Path/Ext + getCEVersion, ✅ read/writeShortInteger (aliases), ✅ allocateMemory/deAlloc (RWX code caves), ✅ enumMemoryRegions, ✅ copyMemory, ✅ pause/unpause, ✅ inModule/isAddress, ✅ AOBScanModule, ✅ getInstructionSize/getPreviousOpcode; ✅ disassemble(), ✅ getNameFromAddress, ✅ registerSymbol, ✅ autoAssemble(),
  ✅ memoryrecord API (createMemoryRecord/getMemoryRecordByDescription + mr.Value/
  Address/Type/Active/Description), ✅ readString/Bytes writers.

### P2 — memory view extras
- 🟡 ✅ Bookmarks (★ toggle + Bookmarks menu, navigate); ✅ hex-view "Bytes per row" (8/16/32) display width; ✅ hex-view "Display type" (Byte/Word/Dword/Qword/Float/Double)
  toggle, dissect-region shortcut.
- ✅ Hex-view data inspector: status bar shows the byte(s) at the cursor as
  i8/u8/i16/i32/float/i64/double.
- ✅ Results 'Hex' display toggle: show integer result values in hexadecimal.

- ✅ Tools > "Pause the process" toggle (SIGSTOP/SIGCONT); verified via /proc state S->T->S.

### Out of scope (Windows/kernel-specific)
- DBVM hypervisor, Ultimap (Intel BTS on Windows), .NET/Mono info injector on Win,
  driver-based DBK features. (We have a Linux kmod + LBR branch mapper instead.)

## Bug watchlist (find & fix)
- ✅ Scan results not live — FIXED (this iter).
- (add newly-found bugs here as they surface during testing)
- ✅ Grouped scan float/double terms silently failed: parseDoubleToken used std::strtod
  (C-locale, comma-decimal under Qt) so '3.14' parsed as 3 and the term parse errored.
  Now locale-independent (std::from_chars, ','->'.'). Verified: 'i32:1337@0; float:3.14@0xc'
  finds g_val's block. Also added natural grouped type aliases (int8/16/32/64,
  short/long, 1/2/4/8) so 'int32:...' works, not just 'i32:...'.
- ✅ Swept remaining locale-fragile float parses: ct_file.cpp JSON number loader
  (would corrupt float values loaded from a saved .CT under a comma locale — now
  from_chars), trainer.cpp freeze float/double values, and lua scan float values
  (atof). All -> locale-independent std::from_chars. 171/171 tests pass.
  NOTE: this is a REAL bug in the dev/user environment — LC_NUMERIC=tr_TR.UTF-8 (Turkish,
  comma-decimal). Demonstrated: under setlocale(LC_ALL,'') strtod('3.14')=3.0 vs from_chars=3.14.
- ✅ AOB nibble wildcards ('4?','?8') were unsupported (byteArrayMask was vector<bool>,
  so scanBufferAOB did a full-byte compare) — now a per-byte AND-mask; nibble AOB works
  and binary per-bit masks are no longer collapsed to bool. Verified: '4? 65 6c' etc. find g_text.
- ✅ FIXED: the 'Code injection (auto)' address dialog rejected a '0x' prefix
  (toULongLong base16); now strips it. Verified live: injecting at worker+0x10 stole the
  6-byte 'mov eax,[rip+..]' and generated the correct cave+hook+[DISABLE].
- ✅ AA template menu is comprehensive (Code injection auto/at-address, Allocate memory,
  AOB injection, Full code injection, Pointer injection, Cheat table framework, Lua block).
  Verified AOB-injection generates a correct CE-style aobscanmodule+cave+hook skeleton.
- ✅ AA 'Code injection at address (auto)' template generator (aa_templates.cpp): emits a
  CE-style full injection — alloc near target, jmp hook + nop padding, stolen bytes as db
  (disasm as comments), jmp return, [ENABLE]/[DISABLE]. Matches CE's Ctrl+I output.
- ✅ Verified: pointer records created via Lua (mr.Address='[cave]') follow the pointer
  ([cave]->g_val->4242 after refresh). Audit: other __newindex handlers (lua_streams) are
  index-correct; only the memrec freeze setters had the stack-index bug (fixed).
- ✅ Disassembler resolves RIP-relative operands to absolute addresses (CE-style):
  '[rip + 0x1234]' -> '[0x<abs>]' (abs = insn.addr + insn.size + disp). Verified:
  48 8b 05 34 12 00 00 at C -> 'mov rax, qword ptr [0x<C+0x123b>]'. Benefits the memory
  browser disasm too (same Disassembler). Improves the 'deassembler tech'. Edge cases
  verified: negative disp (lea rax,[rip-0x10] -> [c-9]) and non-RIP mem ([rax]) left untouched.
- ✅ REGRESSION FIX: rewriting the operand broke DisasmView::ripEffectiveAddress (it parsed
  'rip' from the operand text, now gone). Store the resolved target as Instruction.ripTarget;
  ripEffectiveAddress reads the field; disassemble() Lua returns it as a 3rd value. Verified:
  ripTarget=0x<abs> for a RIP instr, 0 for non-RIP. Audited ALL operand-text consumers:
  also fixed analysis/code_analysis.cpp parseRipRelativeTarget (was parsing 'rip') to use
  inst.ripTarget. 171/171 tests pass (RIP-relative instructions, Referenced strings/functions).
- ✅ DisasmView RIP annotation confirmed restored by the ripTarget fix (ripRefAnnotation ->
  ripEffectiveAddress -> ripTarget). Decluttered it: operand already shows '[0x<abs>]', so the
  annotation now omits the duplicated '->0x<abs>' and shows only the target symbol + live
  value (e.g. ' ; g_val = 12345'), returning empty when there's nothing to add.
- 🟡 injectLibrary(path) Lua binding added (ptrace + remote dlopen). Hardened the injector:
  prefer public dlopen (RTLD_NOW) and OR __RTLD_DLOPEN (0x80000000) for __libc_dlopen_mode;
  VERIFY the .so is actually mapped in /proc/pid/maps afterward and return an honest error
  instead of a bogus handle. KNOWN LIMITATION: remote dlopen still fails on multi-threaded
  targets (target2) — the hijacked-thread call returns a bogus 34 / crashes inside dlopen
  because sibling threads keep running (needs all-thread stop + safe-point injection; TODO).
  Now fails cleanly (nil,err) rather than lying.
  DIAGNOSED (this iter): added all-thread-stop (attach every /proc/pid/task/tid before the
  hijacked dlopen). Root cause is NOT threading — injected dlopen crashes internally (returns
  vary: 34 for target2, 219 for a single-thread target; fails single-threaded too). The
  hijacked thread is blocked in a syscall (nanosleep/futex) and/or libspeedhack's constructor
  faults in that context. Real fix = safe-point injection (breakpoint at known userspace code,
  let the thread reach it, then hijack) — substantial follow-up.
- ✅ Speedhack Lua API: added speedhack_setSpeed(factor) + setSpeed alias (writes the
  double to /dev/shm/ce_speedhack, same secure open as the GUI dialog). Verified the WHOLE
  feature end-to-end: plugin scales time (CE_SPEED=10 -> a perceived-1.0s sleep is 0.10s
  real; 0.5 -> 2.0s real) and the Lua binding writes the shm live (setSpeed(7)/speedhack_setSpeed(3.5)
  return true, shm reads 3.5). (Was briefly mis-read as broken until measuring REAL wall-clock:
  perceived time stays ~1.0s because nanosleep+clock_gettime scale consistently.)
- ✅ injectLibrary works on multi-threaded targets (userspace-thread hijack; iters 103-106).
- ✅ FIXED integer value-write parsing: byte '-1' wrote 0 (toUInt rejects negatives) and
  int16 '40000' wrote 0 (toShort rejects >signed-max). New parseIntField accepts sign,
  0x-hex, and full-width unsigned, truncating to the type width. Verified: byte -1 -> 0xFF (255),
  int16 40000 -> 40000. Affects both the GUI value edit and Lua mr.Value. The SCAN integer
  path was NOT affected (it parses via toLongLong->int64 and scanBuffer casts to the type width
  T, so byte -1 and 255 both map to 0xFF) — the bug was isolated to writeValueToProcess.
- ✅ Verified mr.Value write+read round-trip across ALL numeric types: byte 200, i16 30000,
  i64 5000000000 (beyond int32), float 3.14, double 2.718281828 all set+read back correctly.
- ✅ Verified readString/writeString round-trip (read 'HelloWorld', wrote 'PWNED!', read back).
  writeString now returns a success boolean like CE (was returning nothing).
- 🟡 GUI 'Speedhack...' Apply injects libspeedhack.so into the running target (verified: 5 segments
  mapped) then writes the speed. BUT injected speedhack does NOT scale time: libspeedhack.c relies
  on SYMBOL INTERPOSITION (defining clock_gettime/nanosleep), which only overrides callers under
  LD_PRELOAD (bound at load time). A dlopen-injected lib doesn't re-bind already-resolved PLT/GOT,
  so its interposers never run. VERIFIED by MEASURING EFFECT (not just the map): a 50ms-nanosleep
  target stays ~20 lines/sec with the lib injected and shm=10 (LD_PRELOAD 10x -> ~200). LD_PRELOAD
  speedhack works. REAL FIX (substantial): plugin constructor must actively hook the target's time
  funcs (GOT patch via dl_iterate_phdr, or inline-hook libc prologues) instead of interposition.
  Lesson: verify the actual runtime EFFECT, not just that injection mapped the lib.
- ✅ Added a permanent unit test 'Disassembler RIP resolution' (test/main.cpp): the lea at
  codeBase resolves to [0x2000], ripTarget==stringBase, and 'rip' is gone from the operand.
  172/172 tests pass. Locks in the RIP feature deterministically (the GUI screenshot was flaky).
- ✅ mr.Value now does a LIVE read (IAddressList::liveValue re-resolves the pointer expr
  + reads the process on access), matching CE. Verified: mr.Address='[cave]'; mr.Value read
  synchronously (no refresh wait) returns 4242 ([cave]->g_val->4242).
- ✅ Lua mr.ShowAsHex (display/edit value in hex) — added setHexView to IAddressList +
  snapshot showAsHex; verified setter+getter (false->true).
- ✅ BUGFIX: the freeze-direction setters (added same day) read stack index 3, but
  __newindex does lua_remove(L,2) first so the value is at index 2 — FreezeDirection=N
  errored (checkinteger on nil) and Allow*=... ignored the assigned value. Fixed to index 2.
- ✅ Directional freeze via Lua (CE-style mr.AllowIncrease/AllowDecrease/FreezeDirection):
  added setFreezeMode to IAddressList + AddressListModel. Verified vs target2:
  AllowDecrease=false froze 5000 -> external write 3000 reverted to 5000 (decrease
  blocked), external write 7000 stayed 7000 (increase allowed).
- ✅ Verified: Pointer Scanner rescan re-resolves each path against a new target and
  filters (30 module-anchored paths to g_val -> 0 still reach g_val+8, correct since the
  static pointers didn't move).
- ✅ Verified: Pointer Scanner end-to-end — with a static pointer planted to g_val, a
  depth-1 scan found 31 module-anchored paths all resolving (Current Address) to g_val
  with Value 1337.
- ✅ Verified: memory dump/restore — writeRegionToFile dumps a region to disk and
  readRegionFromFile writes it back (round-trip 0xCAFE via g_val).
- ✅ Verified: GUI Array-of-Bytes scan with nibble wildcard '4? 65 6c 6c 6f' finds g_text
  (nibble fix works in the GUI scan path, not just Lua AOBScan).
- ✅ Verified: Text/string scan — scanning Text 'HelloWorld' finds exactly g_text.
- ✅ Verified: Float scan with rounding — scanning Float '3.14' finds exactly g_float
  (stored 3.140000104904175) via default rounding.
- ✅ Verified: signed/unsigned integer handling — writeInteger(-1) reads -1 signed /
  4294967295 unsigned; 0x80000000 -> -2147483648; writeSmallInteger(-100) round-trips;
  writeQword(0x100000000) preserves 64-bit.
- ✅ Verified: user-symbol system — registerSymbol('mysym',0xdeadbeef) makes
  getAddress('mysym')=deadbeef and getAddress('mysym+0x10')=deadbeff (resolves in
  expressions); unregisterSymbol makes it nil.
- ✅ Verified: disassembler 'NOP this instruction' quick-cheat — NOPing target2's
  'mov [g_counter],eax' froze g_counter (51212 stable). Also confirmed the disasm's rich
  inline annotations (resolved data refs show symbol + live value: g_counter, g_val=1337,
  g_text="HelloWorld", g_float).
- ✅ Verified: full AA code injection (jmp hook) end-to-end on the live multi-threaded
  worker — alloc a cave near the target (within jmp range), jmp-hook the instruction,
  run injected code + replicate the stolen op: g_val forced to 0x1234 each loop while
  g_counter keeps incrementing. (jmp hooks work multi-threaded, unlike int3 breakpoints.)
- ✅ Verified: 'Find what writes this address' (hardware watchpoint) catches the writing
  instruction with hit count + full register state (works on the multi-threaded target;
  the earlier multi-thread limitation was software int3 breakpoints only).
- ✅ Verified: Unknown-initial-value First Scan (2.19M) then Increased-value Next Scan
  narrows to exactly the values that grew (=1: g_counter) and stays correct on repeat.
- ✅ Verified: freeze (mr.Active) pins a value the game actively changes — g_counter
  (growing ~975/s) held near 777 when frozen (100ms freeze interval, minor oscillation as in CE).
- ✅ createTimer() defaulted to enabled=false, so a no-arg timer never ticked; CE
  defaults enabled=true. Fixed. Verified: OnTimer fires at the set Interval, Enabled=false stops it.
- ✅ Verified: memrec OnActivate fires with the correct state on enable and disable.
- ✅ Verified: AA [ENABLE]/[DISABLE] trainer lifecycle via mr.Active (patch on enable,
  restore on disable) works end-to-end.
- ✅ getAddress() was symbol-only; now also parses hex, module+offset, arithmetic and
  [pointer] derefs via ExpressionParser (CE-compatible). Verified vs target2.
- ✅ registersymbol'd names from autoAssemble() (Lua) were lost (local AutoAssembler);
  now exported to the Lua resolver so getAddress('name') resolves. Verified: alloc+
  registersymbol+dd cave resolves and holds 12345 after the call.
- ✅ AA db/dw/dd/dq directives rejected CE's '#' decimal prefix (only hex) — now
  '#9999' writes decimal 9999, plain tokens stay hex. Verified via autoAssemble() from Lua.
- ✅ AOBScan returned only the first match as an integer; CE returns a list of ALL
  matches — now returns a 0-indexed table of hex strings with .Count and .destroy(). FIXED.
- ✅ mr.Value = <int> wrote "555.000000" (double) -> integer parser gave 0 — FIXED.
- ✅ getMemoryRecordByDescription was an addresslist method only, not a global — FIXED.
- ✅ mr.Value = <float> wrote 0: std::to_string used Qt's comma C-locale, QString::toFloat
  ('.') rejected it. Now formats via std::to_chars ('.'). Verified: 2.5/3.25 land correctly.
- ✅ GUI float/double value entry + scan input now accept ',' or '.' as the decimal
  separator (writeValueToProcess + scan parse via parseUserDouble). Verified: a Float
  scan for '12,5' finds a value set to 12.5.

- ✅ Address-list "Enable all" / "Disable all" context actions.

### Debugger (interactive break/step)
- 🔧 Interactive debugger UI drafted (attach + set software BP + register view +
  continue/step) but NOT shipped: DebugSession::attach only PTRACE_ATTACHes the
  main tid (no PTRACE_O_TRACECLONE / task-iteration), so an int3 in a child
  thread (e.g. target2's worker pthread) fires in an untraced thread and kills
  the target. Needs multi-thread tracing in the tracer event loop first — a
  focused effort, not a loop iteration. (UI code saved in scratchpad.)

## Recent verifications (loop, appended)
- ✅ ExpressionParser: multi-level `[[...]]` pointers + single-digit/hex-letter offsets fixed; permanent unit test (173/173 pass).
- ✅ autoAssemble end-to-end (Lua): alloc(m,32)+registersymbol(m)+`db 11 22 33 44` -> true; getAddress('m') resolves the cave; readInteger = 0x44332211.
- ✅ getUserDefinedSymbolByName/ByAddress, getOpenedProcesses, writeString success-bool, mr.Value all-types round-trip, integer value-write signedness fix — all verified this session.
- ✅ Assembler<->disassembler round-trip: autoAssemble('mov eax,0x1234; ret') emits `b8 34 12 00 00 c3`; disassemble reads back 'mov eax, 0x1234' (5) + 'ret' (1). Keystone+Capstone both correct.
- ✅ FIXED: forward jumps to named labels defined later ('jmp skip ... skip:') now assemble
  without an explicit label(skip) — CE auto-collects such labels; our sizing pass aborted on
  the forward ref (KS_ERR_ASM_SYMBOL_MISSING). autoDeclareNamedLabels pre-emits label() for
  every genuine identifier `name:` not already declared (excludes address injection points
  like 00401000:/module+off:). Verified '[[...]]jmp skip;db*5;skip:mov eax,5' -> jmp lands at
  skip; 173/173 tests pass (all AA tests, no regression).
- ✅ Permanent unit test 'forward named label without label() decl' (test_autoassembler_forward_labels):
  alloc(fwd2)+jmp skiplbl+nop 200+skiplbl:ret assembles (e9 near jmp, ret at +205). 174/174 pass.
- ✅ Permanent unit test 'Next-scan comparators': Increased/Decreased/Changed/Unchanged/
  IncreasedBy/DecreasedBy/Greater/Less each verified with positive AND negative cases
  (100->150/50/100 on a live mmap page). Several were previously untested. 175/175 pass.
- ✅ Verified common Lua utils vs target2: copyMemory(c1,c2,8) copies (c2=deadbeefcafe),
  readBytes(c1,4,true)=fe ca ef be, isAddress(g_val)=true/isAddress(1)=false, inModule(g_val)=target2.
- ✅ Disassembler robustness (tricky real-world insns): 'mov rax,fs:[0x28]' (TLS canary) -> correct,
  ripTarget=0 (segment-relative NOT mis-resolved as RIP); endbr64 (CET), syscall, vzeroupper (AVX)
  all decode correctly. Confirms resolveRipRelative's base-register guard.
- ✅ Verified AA enable/disable auto-restore (core cheat toggle): a memrec Script patching a cave
  ('db 90 90 90 90') on enable and restoring on disable — mr.Active=true -> 90909090,
  mr.Active=false -> original aabbccdd restored (disableInfo captured/restored the bytes).
- ✅ FIXED getPreviousOpcode (back-disassembly): the fixed 20-byte lookback read unmapped memory
  before a page-aligned region -> read failed -> fell back to addr-1, so a multi-byte previous
  instruction was mis-reported (e.g. prev-of-ret returned mov's last byte, not its start).
  Now bounded largest-length-exact-fit (len 15..1: instruction at addr-len is exactly len bytes).
  Verified: nop;nop;mov eax,1;ret -> getPreviousOpcode(ret) = mov start (a+2), a+2->a+1, a+1->a+0.
- ✅ Extracted back-disassembly into Disassembler::previousInstruction (reusable + testable); Lua
  getPreviousOpcode now calls it. Permanent unit test with a region-boundary read callback
  (nop;nop;mov eax,1;ret -> prev(ret)=mov@+2, prev(+2)=+1, prev(+1)=+0). 176/176 pass.
- ✅ DisasmView up-scroll (scrollBack) is now region-safe: when the 128-byte lookback read fails
  at a mapped-region start it steps back via previousInstruction (bounded, no unmapped read)
  instead of the naive addr-count*4 guess that showed misaligned instructions past a section start.
- ✅ Verified assemble() Lua: 'mov eax,5' -> {b8 05 00 00 00}, 'nop' -> {0x90}, invalid mnemonic
  -> nil + 'Invalid mnemonic (KS_ERR_ASM_MNEMONICFAIL)'. Keystone single-insn assembly + error path OK.
- ✅ Permanent unit test 'Scan alignment': an Int32 at a 4-misaligned offset (65) is MISSED by an
  alignment=4 scan and FOUND by alignment=1. Confirms fast-scan alignment discrimination. Tests pass.
- ✅ NEW: case-insensitive string/Text scan (CE 'Case sensitive' toggle). ScanConfig.caseSensitive
  (default true) + scanBufferString ASCII case-fold when off + GUI 'Case sensitive (text)' checkbox
  (both first/next-scan builders). Unit test: case-sensitive misses 'HeLLoWorld' for 'helloworld',
  case-insensitive finds it. 181 OK / 0 FAILED.
- ✅ Extended case-insensitive scan to Unicode/UTF-16 text too (CE's toggle covers both): fold the
  low byte of each UTF-16LE code unit, compare the high byte exactly. Unit-tested (Text + Unicode).
- ✅ FIXED: AA data directives (db/dw/dd/dq) now resolve symbol/label references (pointer/jump
  tables). parseDataDirective only parsed numbers/strings, so 'dq tgt' errored. Now the value is
  run through substituteForSizing (sizing, forward-ref safe) / substituteSymbols (assembly) first.
  Unit test: 'dq tgt' stores the address of tgt (= dqmem+8). 0 regressions.
- ✅ Verified AA aobscan honors wildcards (real cheat tables rely on ??): aobscanmodule with
  '7F ?? 4C 46' finds the same ELF-header address as the fixed '7F 45 4C 46'. Permanent test.
- ✅ FIXED: AA data directives evaluate +/- arithmetic (e.g. 'dq label+8' for indexed pointer
  tables). Previously stoull stopped at '+' and dropped the offset. Added evalDataToken (hex/#dec
  terms summed with +/-). Unit test: 'dq tgt2+4' stores dqmem2+12. 0 regressions.
- ✅ Pointer-scan roundtrip now tested: every found path dereferences back to the target, and a
  rescan against the same target keeps all valid paths (was only scan/shard-merge before). Pass.
- ✅ NEW: AA data-directive (float)/(double) casts — 'dd (float)1.5' / 'dq (double)2.5' store the
  IEEE-754 bit pattern (patching float/double constants: speed, damage, ...). Locale-safe parse
  (from_chars + comma->dot; strtod would break under this host's tr_TR comma locale). Unit-tested.
- ✅ Disassembler db-fallback (improve disassembler): undecodable bytes now render as 'db 0xXX' and
  disassembly continues (Disassembler::disassemble emitDataBytes=true), so the DisasmView pane no
  longer blanks out at data/obfuscated regions (CE behavior). Strict path unchanged. Unit-tested.
- ✅ Verified DisasmView is CE-complete (address|bytes|mnemonic|operands, labels/comments/annotations/
  jump-arrows, follow, bp, assemble-with-NOP-pad + longer-insn warning, NOP, xrefs, save-region,
  db-fallback). Also: RIP-resolved operand '[0x<abs>]' re-assembles to the SAME bytes (Keystone
  re-encodes RIP-relative), so 'Assemble' on a RIP-relative insn round-trips. Permanent test added.
- ✅ FIXED (code-corruption): Assembler returned SUCCESS with 0 bytes when Keystone silently rejected
  input (e.g. Capstone's 'mov qword ptr [rax+8], rbx'). assembleAt then NOP-padded -> editing an
  instruction to itself via the Assemble dialog NOPped it out. Now assemble() errors on non-blank
  input that yields 0 bytes; assembleAt also refuses empty output. Round-trip safety test:
  14 match / 1 clean-error / 0 unsafe. AA suite unaffected.
- ✅ FIXED: assembler now accepts Capstone's 'ptr' size-specifier syntax. Keystone rejects the 'ptr'
  keyword ('qword ptr [..]' fails, 'qword [..]' works), but Capstone emits it — so the Assemble
  dialog couldn't re-assemble many disassembled instructions (mov to mem from reg64, movzx, ...).
  Added stripPtrKeyword() normalizer. Round-trip test: all 16 common insns now match (was 14). 
- ✅ Unknown-initial-value scan chain now unit-tested (classic 'I don't know the value' workflow):
  firstScan(Unknown) snapshots every aligned dword, then Increased/Unchanged/Changed refine
  against the snapshot correctly (100->150 survives Increased/Changed; unchanged zeros drop). Pass.
- ✅ Round-trip battery extended to SSE/float math (movss/addss/mulss/movsd/cvtsi2ss/comiss/subps/
  movaps): all 24 common insns assemble<->disassemble<->re-assemble identically (ptr normalizer
  handles 'dword ptr'/'qword ptr' on xmm loads). Confirms float-injection code paths work.
- ✅ Round-trip battery extended to prefixed insns (lock inc/xadd/cmpxchg, rep movsb/stosd, pause):
  all 30 common insns assemble<->disassemble<->re-assemble identically. Confirms lock/rep prefixes
  survive the asm/disasm round-trip (relevant to atomic ops at injection sites).
- ✅ FIXED (CE .CT interop): loading a Cheat-Engine-authored table left the description wrapped in
  CE's double quotes (<Description>"Health"</Description>) -> descriptions showed as '"Health"'.
  Loader now strips surrounding quotes; saver now writes them (CE format) so CE reads our tables
  too. Unit test loads a CE-authored .CT (quoted desc, '4 Bytes', hex addr) correctly. Round-trip OK.
- ✅ FIXED (CE .CT pointer entries): CheatEntry had no address-string or offsets field, so loading a
  CE pointer record dropped its <Offsets> chain and turned a symbolic base ('game.exe+1C') into 0.
  Added addressString + offsets to CheatEntry; loader parses <Offsets> (getTagBlocks returns blocks
  WITH tags, so extract inner text via getTag) and keeps the raw address; saver emits both. Test:
  a CE pointer entry loads base='game.exe+1C', offsets=[0x10,0x8]. Real CE tables now import intact.
- ✅ CE pointer entries now RESOLVE in the GUI: onLoadTable builds an addressExpr from the symbolic
  base + offsets via buildPointerExpression() (CE order: [[base]+off_last]..+off_first), fed to the
  address list's re-evaluated addressExpr. Unit-tested: (game.exe+1C,{10,8})->'[[game.exe+1C]+8]+10'.
  (String + data fidelity unit-verified; live GUI resolution not screenshot-verified this session.)
- ✅ FIXED (CE .CT groups): the loader found entries with a flat find('<CheatEntry>')/find('</CheatEntry>'),
  which breaks on CE's nested groups (children live inside a group's own <CheatEntries>) — the first
  close tag matched a child's, truncating the parent. Added depth-aware findMatchingClose + recursive
  parseCheatEntriesBlock (sets parentId). Test: a group + nested child load with correct hierarchy.
- ✅ CE .CT group SAVE now nests children (was a flat list, losing hierarchy): index-based recursive
  writer (parent->children by id, done[] guard for cycles/dup-ids/orphans). Save/reload preserves
  the group hierarchy and CE can read our grouped tables. Bidirectional group support complete.
- ✅ GUI group round-trip wired: onSaveTable now sets e.id = row index (matching toJson's row-based
  'parent' refs) so the nested ct saver links children; onLoadTable computes indent from the
  parentId tree so imported CE groups show indented. Core saver/loader unit-tested; GUI glue
  inspection-verified (Xvfb capture degraded this session).
- ✅ LIVE-VERIFIED case-insensitive scan in the GUI (xwd capture): attached target2, Text scan
  'helloworld' (lowercase) with 'Case sensitive (text)' UNCHECKED -> Found: 1 (target2's mixed-case
  g_text 'HelloWorld'). Confirms checkbox->config->scanner end-to-end, not just unit tests.
  (GUI screenshots recovered via xwd -id $WID after ImageMagick import failed session-wide.)
- ✅ Save-side of CE pointer entries now tested: an entry with addressString='game.exe+1C' and
  offsets=[0x10,0x8] saves and reloads with both intact (SAVE emit of <Address>text + <Offsets>).
  (Live GUI .CT load blocked by GTK file-chooser automation; loader/save fully unit-tested instead.)
- ✅ LIVE-VERIFIED disassembler on real code (Memory Browser vs target2!_init, xwd): address|bytes|
  mnemonic|operands, function label 'target2!_init:', RIP-relative resolved+annotated
  ('mov rax,[0x..afe8] ; target2!_GLOBAL_OFFSET_TABLE'), jump/call targets resolved with
  symbol+offset ('je 0x..8016 ; target2!_init+0x16'), endbr64 (CET) decoded, jump arrows, synced
  hex view. All prior disassembler improvements confirmed working end-to-end on real code.
- ✅ Round-trip battery extended to x64-specific insns (movabs/cqo/cdqe/rdtsc/bswap/bt/shld/imul/shl):
  all 39 common insns assemble<->disassemble<->re-assemble identically (match=39, unsafe=0). The
  asm/disasm round-trip is now comprehensive (int/mem/branch/SSE/prefixed/x64).
- ✅ RE-VERIFIED LIVE (user's original #1 complaint 'scan results dont update in real time'): added
  target2's g_counter to the address list; its Value auto-updated 6528 -> 7493 over ~2s with no
  manual refresh (two xwd frames). The periodic real-time refresh works end-to-end.
- ✅ FIXED: Between scan now auto-orders bounds. cmpBetween was 'c>=v && c<=v2', so 'between 200
  and 100' (reversed) silently found NOTHING. Now uses min/max, matching the percentage-between
  path. Covers int AND float (compareFloating delegates to getCompare<T>). Unit-tested both.
- ✅ FIXED: float 'Increased/Decreased value by N' used an exact == on the delta, so an FP-inexact
  change (0.1->0.3 is a delta of ~0.20000002, not 0.2f) silently missed. Floats now use a relative
  tolerance (max(1e-6, |d|*1e-5)); integers still compare exactly. Unit-tested.
- ✅ NEW: address-list String/Unicode/Array-of-Bytes entries (read/display/write) + editable Type
  column. Before: Type column wasn't editable at all, and String/AOB values were refused for both
  read (showed '?') and write (silently no-op). Now: double-click Type -> 'Text'/'Array of Bytes'/
  etc., updateValues formats the string/hex, writeValueToProcess writes UTF-8/UTF-16LE/hex bytes.
  LIVE-VERIFIED: added target2 g_text, set Type=Text, Value showed 'HelloWorld' (xwd).
- ✅ LIVE-VERIFIED string WRITE (address-list Text entry): edited g_text's value to 'PWNED' in the
  GUI; reading target2's /proc/PID/mem showed bytes 50 57 4e 45 44 57 6f 72 6c 64 = 'PWNEDWorld'
  ('PWNED' over the first 5 bytes of 'HelloWorld'). String read+write both confirmed at the byte level.
- ✅ Lua mr.Value now reads String/Unicode/ByteArray consistently with the address-list display
  (shared formatVariableLengthValue helper). Was 'default: return ?'. LIVE-VERIFIED via Lua console:
  writeString(c,'LiveString'); mr.Type=6; mr.Value -> 'LiveString'.
- ✅ NEW: hex-view 'Display type' (CE 'show as type'): right-click Memory View hex pane -> Display type
  -> Byte/Word/Dword/Qword/Float/Double. Groups N bytes into one value (int hex or float/double
  decimal), ASCII column preserved. LIVE-VERIFIED: Dword mode shows 'fa1e0ff3 08ec8348 ...' (xwd).
  This was the LAST explicit missing (❌) item in the tracker.
- ✅ hex 'Display type' layout made consistent: asciiX and byteOffsetAt (click hit-testing) now account
  for the grouped field width, so wide types (Float/Double) don't overlap the ASCII column and clicks
  map to the right group. LIVE-VERIFIED Float mode: floats shown, ASCII correctly placed after them.
- ✅ NEW: C++ symbol demangling in the symbol resolver (disassembler shows 'Foo::bar()' not
  '_ZN3Foo3barEv', like CE). Itanium names ('_Z...') are run through abi::__cxa_demangle on load;
  raw name kept on failure. Unit-tested: a compiled .so's void ceDemangleProbe() resolves demangled.
- ✅ Disassembler RIP annotation now follows a pointer target to its symbol (CE-style): if the RIP
  data (e.g. a GOT slot) holds a pointer resolving to a symbol, show '-> sym' instead of the low
  int32. LIVE: code path exercised on target2!_init GOT slot (holds 0 -> '= 0'); resolved pointers
  show '-> symbol'. Strings still show '= "..."'.
- ✅ FIXED: 'Add Address' button now creates a live pointer record for a '[expr]' input (was a static
  snapshot), matching the context-menu 'Add Address Manually'. LIVE-VERIFIED: set up [c]=g_counter in
  Lua, added '[0x..]' via the button -> Address shows 'P->0x..'(=g_counter), Value=g_counter's live
  value. Also confirms the addressExpr pointer-deref mechanism (shared with CE .CT pointer entries).
- ✅ Added Lua getAddressSafe (CE alias of getAddress that returns nil on failure; cheat tables use it).
  Our getAddress already returns nil, so it's aliased. LIVE: getAddressSafe('bad')=nil, ('0x1000')=4096.
- ✅ LIVE-VERIFIED symbol-name navigation + disasm annotations on target2!main (xwd): typing 'main' in
  the Memory View address bar jumped to main; RIP-relative operands resolved each global with symbol
  AND value: g_text="HelloWorld", g_counter=7321 (live), g_val=1337, g_float, _IO_stdin_used+8="TARGET..".
  Confirms the expression parser's symbol lookup and CE-style symbol+value/string comments together.
- ✅ LIVE-VERIFIED Pointer Scanner GUI (Tools->Pointer Scanner, xwd): scanned for g_counter -> 'Found
  3244 paths', all module-anchored (ld-linux/libc), each resolving to the correct Current Address
  (g_counter) with Value=45980 (its live value). Multilevel pointer scan (CE tutorial step 8) works
  end-to-end. Tools menu confirmed rich: Pointer Scanner/Structure Dissector/File Patcher/Find
  Statics/Form Designer/ELF Inspector/Branch Mapper(LBR)/Break-and-Trace/Overlay/Speedhack.
- ✅ Pointer scan no-duplicate invariant unit-tested: no two result paths share (module, baseOffset,
  offsets). Confirms the live 3244 paths were distinct (identical-looking GUI rows were column
  truncation; all paths correctly resolving to the same target is expected). Pass.
- ✅ LIVE-VERIFIED Structure Dissector (Tools->Structure Dissector, xwd): dissected g_val's region into a
  multi-type field grid (Offset|Name|Hex|Int8|Int32|Float|Pointer). Correct: g_val=1337 at +0x00,
  g_text bytes as int/ASCII at +0x20, and a pointer field at +0x40 followed ('-> 0x7ab1420..').
  Save/Load struct defs + Compare + configurable byte size present. Tutorial step 9 works end-to-end.
- ✅ Regression check: hex-view byte editing still works after the Display-type changes (byteOffsetAt).
  LIVE: navigated to g_val (1337), edited its low byte to 0xff -> /proc shows ff 05 00 00 = 1535.
- ✅ Round-trip covers segment-override + size-specifier insns ('mov qword ptr fs:[0x28], rax',
  'mov eax, dword ptr gs:[0x10]'): all 41 round-trip. Confirms stripPtrKeyword doesn't corrupt
  'qword ptr fs:[..]' (-> 'qword fs:[..]', which Keystone accepts).
- ✅ AA db string literal with comma/space is quote-aware (not split): 'db "a, b"' writes the 4 bytes
  a , SP b (splitDataValues tracks quotes). Unit-tested.
- ✅ FIXED (regression from iter133): AA symbol substitution corrupted db string literals containing a
  symbol name (db "mylabel" -> the label's address in the string), because data directives now run
  substituteSymbols (for dq label refs). Made substituteSymbols quote-aware: quoted spans are copied
  verbatim, only unquoted spans get symbol substitution. dq label refs still work. Unit-tested.
- ✅ Completed quote-aware fix: the AA SIZING pass (substituteForSizing placeholder loop) is now also
  quote-aware, so a db string whose text is an unresolved forward-label name keeps its true length
  and the following label lands at the right offset. Unit-tested (db "fwd"; fwd: db 90 -> +3).
- ✅ AA assert(address, bytes) behavior unit-tested: matching bytes -> injection proceeds; mismatching
  bytes -> injection aborts with 'ASSERT failed' (the safety guard so a table fails cleanly when the
  target's original bytes changed). Both paths verified.
- ✅ AA code-injection template pattern unit-tested end-to-end: alloc(newmem,0x1000,<addr>) + stolen code
  + jmp back, hooking <addr> with 'jmp newmem' -> the target now starts with 0xe9 (jmp to cave). The
  canonical CE code-injection template (wired into the ScriptEditor's Ctrl+I menu) produces working
  injection. Templates present: Code/AOB/Full/Pointer injection, Cheat table framework, Lua block.
- ✅ LIVE-VERIFIED 'Find what accesses this address' (code finder / HW watchpoint, tutorial step 6, xwd):
  monitored g_counter -> caught 2 accessing instructions with hit counts + full register state:
  'add eax, 1' (RAX=0x513f, the worker's increment, 738 hits) and 'mov edi, 0x7d0'. HW watchpoints
  (DR regs via ptrace) work on this non-root env (target uses PR_SET_PTRACER_ANY). Columns: Address|
  Instruction|Hits|RAX|RBX|RCX|RDX|RIP; double-click for full register state.
- ✅ FIXED (code finder): reported the instruction AFTER the memory access, not the accessing one. x86
  data watchpoints (DR0-3 r/w) trap AFTER the instruction retires, so ctx.rip is the NEXT instruction;
  the finder disassembled at rip -> showed register-only ops ('add eax,1','mov edi,0x7d0'). Now it
  back-disassembles (previousInstruction) to the accessing instruction. LIVE: find-what-accesses
  g_counter now shows 'mov eax,[g_counter]' + 'mov [g_counter],eax' (was the following reg ops).
- ✅ Audited all breakpoint-hit RIP handling after the code-finder fix: (1) software int3 correctly
  rewinds regs.rip = rip-1, restores the byte, reports bpAddr, re-arms (test: hitAddr==marker OK);
  (2) data watchpoint back-disassembles rip -> accessing instruction (fixed prev iter); (3) hw-exec
  faults before the instruction so rip is already the instruction (no rewind). All three correct.
- ✅ FIXED (symbol resolver): the 4KB 'grace' cap on attributing an address to a preceding symbol only
  applied when sym.size>0, so a size-0 symbol (hand-written asm, many NOTYPE entries) would claim
  every address after it (misleading disasm annotations like 'foo+0x9000' far past foo). Now the cap
  is measured from the symbol start for size-0 symbols too. Unit-tested (asm .so, verified the test
  fails without the fix).
- ✅ FIXED (disasm follow): double-clicking an INDIRECT branch (jmp/call qword ptr [rip+disp], e.g. a
  PLT stub) navigated to the bare displacement (0x2ede) because parseImmediate grabbed the first hex
  from a memory operand. Now parseImmediate bails when the operand contains '[', so the handler falls
  through to ripEffectiveAddress (inst.ripTarget) and follows to the pointer slot. Unit-tested: the
  disassembler resolves ripTarget for 'ff 25 de 2e 00 00' (jmp [rip+0x2ede]) to at+6+0x2ede and the
  operand has '['. Live disasm showed the PLT jmp resolved to '[0x..afa8] ; target2!_GLOBAL_OFFSET_TABLE_'.
- ✅ Locale audit (comma-decimal cluster): swept all atof/strtod/stod/stof. GUI/scanner/AA float
  parsing already uses from_chars or C-locale-aware strtod. The remaining atof() calls are safe: the
  CLI (cescan) never calls setlocale(LC_ALL,"") so it stays in the C locale (empirically: parses
  atof('3.14')=3.14 under LC_NUMERIC=tr_TR); audiohack parses CE_SPEED in its __constructor__ before
  the target's setlocale. Hardened cescan with an explicit setlocale(LC_ALL,"C") as insurance.
- ✅ Trainer generation Float/Double emission now tested under tr_TR: comma-decimal input ('2,5','1,25')
  is normalized and emitted as valid C ('2.5f','1.25'), and generateBinary COMPILES the result
  (a leaked ',' would be a compile error). Also fixed a stale comment that said strtod where the code
  uses from_chars. Trainer test previously only covered Int32.
- ✅ Expression parser now tested for the CE pointer format with offsets INSIDE bracket levels
  ('[[base]+8]' = deref base, add 8, deref again; '[[base]+8]+10' adds a final offset). This is the
  exact shape buildPointerExpression emits ('[[game.exe+1C]+8]+10') and what real pointer records
  loaded from a .CT resolve through. Passes.
- ✅ Scanner float value parse now accepts a leading '+' (e.g. '+3.14'), matching integer parsing
  (strtoll accepts '+', but from_chars rejects it). parseDoubleToken skips one leading '+'. Tested via
  parseGrouped('float:+2.5@0').
- ✅ LIVE-VERIFIED value Freeze (Active checkbox): froze g_counter (normally climbs hundreds/sec) and
  /proc sampled it held at ~22 (spread 1) over 1.8s instead of climbing. Directional freeze reviewed:
  IncreaseOnly/NeverDecrease = floor at frozen; DecreaseOnly/NeverIncrease = cap at frozen (fixed
  floor/cap, matches CE; not a ratchet). Headline freeze/lock feature works end-to-end.
- ✅ Assembler address-relative encoding now directly tested: 'jmp 0x401500' @ 0x401000 encodes to
  exactly e9 fb 04 00 00 (rel32 = target-(addr+5)), and the same instruction at 0x402000 encodes a
  different rel32 (address is consumed, not ignored). This is what the memory-view Assemble patch
  path relies on. Reviewed assembleAt: passes addr, checks 0-byte, warns on overwrite, NOP-pads.
- ✅ FIXED (memory Find): the FIRST 'Find in memory' used a strict found>start, so a match sitting
  exactly at the current address was skipped. Made first Find inclusive (found>=start) while Find-Next
  stays exclusive (advances past the current match). LIVE: navigated to g_text and Find "HelloWorld"
  stayed at g_text (0x..429040) instead of skipping past it.
- ✅ Expression parser module+offset resolution now tested: 'game' -> module base, 'game+0x100' ->
  base+0x100 (the ubiquitous CE 'module.exe+1C' address format), '[game+0x100]' -> deref. resolveToken
  matches a module name to its base; onGotoAddress routes the address bar through this parser.
- ✅ FIXED (hex view): mousePressEvent computed the hex-column width with the Byte-mode formula while
  paintEvent/byteOffsetAt were display-aware, so in grouped display modes (Dword/Qword/Float/Double)
  the ASCII/hex column boundary (editAscii_) was wrong and ASCII-column editing broke. Extracted a
  single hexColWidth() helper used by all three (paint, hit-test, click) so the layout can't drift.
- ✅ LIVE-VERIFIED ELF Inspector (Tools->ELF Inspector, xwd): a full readelf-equivalent with tabs
  Header|Sections|Segments|Dynamic|Symbols|Notes. Auto-loaded target2 and parsed the header
  correctly (ELF64, little-endian, DYN/PIE, x86-64, entry 0x1120, 13 phdrs, 31 sections). CE's
  PE-header-viewer analog for Linux. Also reviewed the tracer (Break and Trace): correct step-over via
  return breakpoint + documented single-thread limitation; no bug.
- ✅ NEW disassembler feature: PLT/GOT IMPORT RESOLUTION. The symbol resolver now parses .rela.plt/
  .rela.dyn relocations and names each GOT slot '<func>@got'. A PLT stub's 'jmp [got]' now resolves
  to the imported function instead of '_GLOBAL_OFFSET_TABLE_+off'. LIVE on target2: 8 imports named
  (printf@got, getpid@got, pthread_create@got, __cxa_finalize@got, prctl@got, pause@got, fflush@got,
  usleep@got), each also pointer-followed to '-> libc.so.6!<func>'. Unit-tested (getpid@got). Names
  added to nameIndex_ too so 'printf@got' is navigable in the address bar.
- ✅ NEW disassembler feature: PLT STUB naming (<func>@plt). Third symbol pass scans .plt/.plt.sec/
  .plt.got entries for the indirect jmp (ff 25 disp32), matches its GOT target to the @got map, and
  names the sh_entsize-aligned stub start '<func>@plt' (the call target). Now `call <stub>` resolves
  to the import (CE's 'call printf'). LIVE on target2 main: 'call .. ; target2!getpid@plt' and
  'call .. ; target2!prctl@plt'. Unit-tested: getpid@got and getpid@plt resolve at distinct addrs.
- ✅ LIVE-VERIFIED File Patcher (Tools->File Patcher, xwd): patched a test file AA BB CC DD -> AA FF FF
  DD by writing 'FF FF' at offset 0x1. Confirm dialog showed correct path/count/offset; patch applied
  (file flushes when onApply returns, i.e. after the modal 'Patched' dialog is dismissed - not a bug).
  Reviewed parseHexBytes (strips ws, validates odd length + per-chunk hex) and onApply (validates,
  confirms, handles file-extend, verifies write count) - correct. Makes cheats permanent by patching.
- ✅ REGRESSION-VERIFIED the headline complaint (scan results update in real time): scanned g_val for
  1337 (1 result), externally wrote 9999 via /proc, and the results-list Value column refreshed to
  9999 within ~1s, highlighted RED (changed-value indication, matching CE). Confirmed still working
  end-to-end after all recent changes.
- ✅ CodeAnalyzer::findStatics (Tools->Find Statics) now unit-tested: aggregates RIP-relative data
  targets by reference count, sorted most-referenced first. Reviewed as correct; test asserts the one
  rip-relative insn's target is reported once.
- ✅ FIXED (robustness, memory Find): searchMemory did buf.resize(region.size) then read the whole
  region — a real game's multi-GB region (big heap / mapped file) would OOM. Now reads in 16MB chunks
  overlapping by pat.size()-1 (so boundary-spanning matches still hit), preserving the inclusive
  first-Find / exclusive Find-Next semantics. LIVE regression: Find "HelloWorld" still lands on g_text.
- ✅ Pointer-scan rescan now covers the discard half: rescanPointerPaths against a DIFFERENT target keeps
  none (paths deref to the old target). Confirms the restart workflow: dereference re-resolves the
  module base BY NAME (surviving ASLR), and paths that no longer reach the value's new address drop.
- ✅ FIXED (injection-path locale): speedhack & audiohack parsed CE_SPEED with atof, which honours the
  active locale. When INJECTED (dlopen) into a running game that already set a comma-decimal locale,
  CE_SPEED=1.5 read as 1.0 (truncated at '.'). speedhack now forces the C locale via uselocale; audiohack
  parses via from_chars (','->'.'). Proven with an injection harness (setlocale then dlopen): both now
  yield 1.5 under LC_ALL=tr_TR (atof probe confirms plain atof('1.5')=1.0). LD_PRELOAD path was already
  safe (ctor runs before the game's setlocale); this hardens the inject path.
- ✅ Locale FORMATTING audit (complements the parsing audit): float->string is locale-safe everywhere.
  Qt QString::number/arg emit '.' regardless of LC_NUMERIC (directly probed under tr_TR: number('f'),
  number('g'), arg all -> '3.14'); no raw snprintf/%f writes to files/data; trainer uses to_chars; CLI
  pinned to C. Combined with the from_chars parsing audit, the comma-decimal hazard is closed BOTH
  ways (parse AND format), including the plugin injection path (speedhack/audiohack).
- ✅ SECURITY: verified the two most-reachable userspace criticals from the CODE_ANALYSIS audit are FIXED.
  (1) lua_gui UAF (CONFIRMED high): widget userdata now holds QPointer<QWidget> (auto-nulls on
  destruction), liveWidget null-checks before every deref (Lua error, not UAF), and all four callback
  maps are erased on QObject::destroyed (trackDestroyed + the OnClose lambda). (2) ELF heap overflow
  (CONFIRMED critical): parseElfSymbols rejects a hostile sh_entsize (!= sizeof(Elf64_Sym/Rela)) and
  bounds every section [offset,size) against the real file size; the new reloc/PLT import passes keep
  the same hardening. Kernel-module UAF/ioremap and LBR OOB (root-only) remain to re-verify separately.
- ✅ SECURITY: LBR ring-buffer OOB read (CONFIRMED critical, Branch Mapper) verified FIXED. The perf-ring
  drain copies each record via copyFromRing (wrap-aware, bounded by dataSize -> never reads past the
  mapping), validates hdr.size (>=header, <=dataSize, <=avail), linearizes only records that fit the
  scratch buffer, and checks the branch-entry count nr (<=256 AND fits within hdr.size) before reading
  entries. 3 of the audit's userspace criticals now verified fixed (ELF overflow, lua_gui UAF, LBR OOB);
  only the root-only kernel-module UAF/ioremap remain to re-verify.
- ✅ LIVE-VERIFIED disassembler jump arrows: at target2 main's while(1)pause() loop, the 'jmp 0x..e2df'
  (backward) draws a blue arrow with the arrowhead at its on-screen target e2df (greedy lane assignment,
  blue=jmp/peach=conditional, only for on-screen direct-branch targets; parseImmediate bails on
  indirect). Same view re-confirmed import resolution: every call annotated (pthread_create@plt,
  pause@plt, fflush@plt, printf@plt). Reviewed the arrow construction as correct.
- ✅ NEW disassembler feature: OFF-SCREEN jump arrows. Previously branch arrows only drew when the target
  was an on-screen instruction; a jmp/jcc to an address above/below the window drew nothing. Now such
  branches draw an arrow running to the top/bottom edge with an arrowhead pointing off-screen (like CE),
  so you can see a branch goes beyond the view. LIVE-VERIFIED: at main+0xaf the 'jmp main+0xaa' (target
  scrolled off the top) draws a '^' arrow off the top edge.
- ✅ FIXED (major): the auto-assembler could not resolve CE's universal 'module+offset' address format
  (game.exe+1C). resolveAddress checked allocs/labels/defines/globalSymbols/hex but never looked up a
  loaded module's base, so an AA script (or an AA-script memory record loaded from a .CT) that patched
  'target2+4020' resolved the base to 0 and failed. Now execute()/disable() seed every loaded module's
  name->base into globalSymbols_ before parsing. Unit-tested (patch a module-relative global; verified
  the test FAILS without the fix). AA-script memory record toggle logic (execute/disable) reviewed OK.
- ✅ Verified the module+offset fix is complete across all AA entry points: execute() and disable()
  seed module bases (fixed); the Lua autoAssemble binding calls execute() so it inherits the fix;
  autoAssembleCheck()->check() is a syntax-only validator (no process, intentionally doesn't resolve
  module-relative symbols). .CT AA-script entries (<AssemblerScript>) round-trip in XML+JSON+protected
  and are unit-tested. The full AA-script cheat-table workflow now works end-to-end.
- ✅ LIVE-VERIFIED module+offset in the address list (complements the AA fix): 'Add Address target2+4020'
  resolved to g_val's exact address (base+0x4020 = 0x..562020) and displayed value 1337. (Value briefly
  shows '?' until the first refresh tick, then reads correctly.) updateValues re-resolves addressExpr
  via ExpressionParser(proc,...) which looks up module bases through proc->modules(). CE's module+offset
  address form now works everywhere: AA scripts, address-list entries, and the expression parser.
- ✅ FIXED (address persistence): 'Add Address' only stored the addressExpr for bracket-pointers, so a
  module+offset or symbol entry (target2+4020) saved just the RESOLVED absolute address and went stale
  after ASLR/restart (CE stores 'game.exe+1C' and re-resolves). Now the expression is kept whenever the
  text isn't a plain hex literal, so pointer chains, module+offset, and symbols re-resolve every refresh
  and survive save/reload. LIVE: 'target2+4020' now shows the P-> (re-resolved) address prefix + 1337.
- ✅ FIXED (.CT re-save dropped address expressions): onSaveTable set the CheatEntry from the RESOLVED
  absolute address and ignored addressExpr, so re-saving any table with module+offset or pointer
  entries wrote raw absolutes ('game.exe+1C' -> 0x...) that go stale after restart. Now it copies
  addressExpr into CheatEntry.addressString, which the .CT saver writes verbatim into <Address> and
  the loader re-resolves. Core addressString round-trip is unit-tested; completes the persistence chain
  (Add Address keeps expr [iter209] -> toJson emits it -> .CT <Address> -> reload re-resolves).
- ✅ FIXED (Lua robustness): readBytes(addr,count) and readBytesLocal(addr,size) had no upper bound on
  count/size, so an accidental huge value (readBytes(addr,1e9)) OOM-crashed on the buffer alloc, and the
  *Local variant SIGSEGV'd reading past addr. Capped both at 16MB. Also guard readBytes' multi-value
  return with luaL_checkstack so a large count raises a clean 'use returnAsTable' error instead of
  overflowing the Lua stack. (Verified persistence chain for module+offset is complete: save/load
  round-trip addressExpr<->addressString<->.CT <Address> via buildPointerExpression.)
- ✅ IMPROVED (AOB validation): parseAOB silently turned an invalid token (a typo like '8Z') into a
  nibble-wildcard, so a mistyped AOB pattern scanned the wrong bytes. parseAOB now returns bool (false
  for empty OR any token that isn't hex/wildcard); Lua AOBScan/Ex/Module raise 'invalid AOB pattern'
  and both GUI AOB scan sites reject it. Unit-tested (valid '48 8B ?? 05 4?' -> true, '8Z' -> false).
  Audit checkpoint: full suite 213 OK / 0 failed / 0 skipped; Lua read/write bindings + memrec API +
  scanner untrusted-input paths reviewed safe (readBytes capped last iter).
- ✅ NEW disassembler feature: selecting a direct branch (jmp/jcc/call) TINTS its on-screen target row
  (subtle green), so you can see where the selected branch lands - like CE. LIVE: selecting main's
  'jmp main+0xaa' tinted the target row (the call pause). Audit checkpoint: Overlay, conditional
  breakpoints (sandboxed Lua conditions), AA alloc near-address (+-2GB for rel32), and CLI read (size
  capped) all reviewed correct/safe.
- ✅ Verified two more Tools features real+correct: (1) Snapshot — capture writable regions, byte-level
  diff (indexes by base, skips unmatched/resized regions, bounds the compare, baseline->current), plus
  restore (undo) and Lua bindings. (2) Form Designer — a 446-line visual UI builder (palette/canvas)
  that generates Lua GUI code; every emitted API (createForm/Label/Button/Panel/Edit/CheckBox/GroupBox)
  exists in the lua_gui bindings, so the generated code runs. The full Tools suite is now confirmed real
  and complete: Pointer Scanner, Structure Dissector, ELF Inspector, File Patcher, Find Statics, Form
  Designer, Snapshot, Overlay, Branch Mapper(LBR), Break-and-Trace, Auto Assembler, Speedhack, Lua Console.
- ✅ Verified the last Tools feature + protected format. (1) Wait for process (auto-attach): ProcessWatcher
  atomically claims ownership (no double-start thread leak), joins any old thread, snapshots existing
  PIDs so it only fires for NEWLY-launched processes; the callback marshals to the GUI thread
  (QueuedConnection) and attaches. Correct. (2) Protected .CETRAINER: password verified via fnv1a, XOR-
  decrypted to a SECURE temp file that is removed after load and on error (no decrypted-table disk
  leak); round-trip is unit-tested. All 14 Tools features and all 3 save/load formats (JSON, CE XML,
  protected) now verified real and correct.
- ✅ AVX/VEX round-trip coverage added: 'vmovups ymm0,[rax]', 'vaddps ymm0,ymm1,ymm2', 'vxorps xmm0,..',
  'vmovaps ymm5,ymm6', 'vmulsd xmm0,..' all round-trip asm<->disasm (46/46). Confirms 256-bit ymm and
  3-operand VEX forms encode/decode correctly in the assembler and disassembler (modern game code).
  Also verified: scanner IncreasedBy/DecreasedBy comparators (direction-guarded exact-delta / float
  tolerance) are correct and tested.
- ✅ ENABLED + tested DWARF source-line disassembly: the feature is libdw-gated and was in stub mode here
  (libdw-dev headers missing). Installed libdw-dev, reconfigured (DWARF support: enabled), rebuilt.
  Added a lookup test: compile a -g .so, resolve a function's address from its symtab, and confirm
  DwarfInfo::lookup maps it back to the source file + line -> passes. The disassembler now annotates
  debug-built code with source locations (DwarfRegistry wired into DisasmView via setDwarf).
- ✅ FIXED 2 DWARF bugs (found by live-verifying source-line disasm): (1) ET_EXEC bias: DwarfInfo::lookup
  subtracted the runtime load base unconditionally, but ET_EXEC (-no-pie / classic executables) have
  ABSOLUTE DWARF addresses and load at their fixed vaddr, so the subtraction missed every line. Now
  load() reads e_type and uses bias 0 for ET_EXEC (base for ET_DYN/PIE/.so). (2) Rendering regression:
  the DWARF functionName label had no entry guard, so once ET_EXEC lookups worked it drew a 'func:'
  label for EVERY instruction (replacing the disasm). Now it only labels when the resolver is clueless
  AND the function name changes (one header per function). LIVE: -no-pie target shows compute:/main:
  headers + per-instruction '; dwtarget.c:4..11' source annotations mapping exactly to the source.
- ✅ Disassembler feature-completeness verified against CE: right-click menu has NOP-this-instruction,
  Assemble-instruction (in-place, NOP-padded), set/remove sw+hw breakpoints, Label, Set comment, Find
  references (xref via CodeAnalyzer.findReferencesTo - real scan, tested), Follow operand, Copy
  addr/bytes/line, Save region to file (size-bounded 256MB), Goto, Find writes/accesses, Data type.
  Annotations: DWARF source lines, @plt/@got imports, on/off-screen jump arrows, branch-target tint,
  RIP-relative data refs with resolved values. DWARF per-instruction lookup is cheap (libdw caches the
  CU line table). No gaps found this pass.
- ✅ Verified + locked RIP-relative code-injection correctness: the disassembler rewrites [rip+disp] to
  its absolute [0x<abs>] (arch/disassembler.cpp), so a stolen RIP-relative instruction re-assembled at
  the cave (a different address) still references the SAME absolute target - Keystone recomputes the
  displacement (or picks moffs). Without this it would silently retarget. Added a relocation-invariant
  test (assemble [rip+0x1234] at A -> absolute -> re-assemble at cave B -> same target). Also verified:
  pointer-scan rescan (re-resolves module base by name, ASLR-safe, tested) and AA templates (AOB
  injection / Full injection / Pointer injection / CT framework + auto code-injection, tested).
- ✅ FIXED refresh-interval default inconsistency + made real-time snappier: the settings dialog defaulted
  the auto-refresh interval to 2000ms while the main window's timer defaulted to 1000ms, so the dialog
  displayed a value that didn't match the actual refresh, and both were sluggish for 'real time'.
  Unified all three call sites to 500ms (CE's default display-update interval). The value timer already
  re-reads address-list values AND the VISIBLE scan-result rows each tick (efficient for million-row
  sets), skipping only while a cell editor is open; now it ticks twice as often for a live feel.
- ✅ FIXED (directional freeze mode dropped on save): an entry's freeze direction (Allow Increase /
  Decrease Only / Never Increase / Never Decrease) was never persisted. CheatEntry HAD a freezeMode
  field, but onSaveTable never set it from obj, onLoadTable never read it back, and ct_file serialized
  neither JSON nor CE XML — so any directional freeze reverted to Normal on save/reload. Wired the full
  chain: JSON save/load ('freezeMode' int), CE XML save/load (<freezeMode> custom tag CE ignores),
  onSaveTable/onLoadTable GUI mapping. Round-trip unit-tested (DecreaseOnly survives, non-vacuous).
- ✅ FIXED (show-as-hex dropped on save): the per-entry 'display value as hex' flag lived only in the GUI
  model - CheatEntry had no field, onSaveTable/onLoadTable didn't map it, and ct_file serialized neither
  format - so a hex-displayed entry reverted to decimal on reload. Added CheatEntry.showAsHex and wired
  the full chain: JSON ('showAsHex'), CE XML (<ShowAsHex> - CE's own standard tag, so it interops both
  ways), and both GUI mappings. Round-trip unit-tested (non-vacuous). Same class of persistence gap as
  freezeMode - auditing every per-entry setting round-trips.
- ✅ NEW: global (system-wide) hotkeys via X11 XGrabKey — CE's headline usage (toggle cheats WHILE the
  game is focused). Previously hotkeys were Qt::ApplicationShortcut (only fired when a cheatengine
  window was active). New GlobalHotkeyManager grabs on the root window (all CapsLock/NumLock variants),
  filters xcb KeyPress via a native event filter, maps Qt keys->X11 keysyms. Gated on X11
  (CECORE_HAVE_X11_HOTKEYS) with QShortcut fallback. LIVE-VERIFIED: with xclock focused (NOT cheatengine),
  pressing the increase hotkey twice drove target2's g_val 1337 -> 11337 (2x5000).
- ✅ FIXED: the toggle-active hotkey (hotkeyKeys) was configured + saved but NEVER wired to any action -
  it did nothing. Now registered (global) and flips the entry's active state via toggleActive().
- ✅ NEW: command-line table open ('cheatengine table.ct' / double-click a .CT) - main() loads argv[1]
  via the extracted loadTableFromPath(); matches CE's file-association behaviour.
- ✅ FIXED (hotkey on pointer entry wrote stale address): adjustEntryValue (increase/decrease hotkeys)
  used the cached e.address, refreshed only every 500ms, so a hotkey on a pointer/expression record
  could read+write the WRONG (possibly unrelated) memory if the pointer moved since the last refresh.
  Now it re-resolves addressExpr via ExpressionParser at action time, like updateValues does. Full
  suite still 215 OK after the global-hotkey / ct_file changes.
- ✅ FIXED (paste created duplicate entry ids): onPasteAddresses appended the copied JSON verbatim, and
  fromJson honors obj['id'] when present, so pasting entries into a table that already holds those ids
  produced duplicate ids - making getMemoryRecordByID / byId / Lua record references ambiguous (first
  match wins). Strip 'id' from pasted objects so a fresh unique id is allocated; the row/indent-based
  hierarchy is unaffected. Also verified: hex-view nibble editing writes correctly, and 'Value between'
  parses BOTH bounds through parseUserDouble (comma-locale safe).
- ✅ FIXED (Next Scan honored a mid-session value-type change): onNextScan read the value type from the
  live combo, but the previous results are stored at the FIRST scan's type/size. If the user changed the
  type combo after the first scan, Next Scan reinterpreted the stored results at the wrong stride,
  corrupting the narrowing (and mis-sizing the increased/decreased/changed comparisons). Pin
  config.valueType = lastResultType_ in Next Scan (CE locks the combo after the first scan; we pin it).
- ✅ NEW hex-view feature: 'Follow pointer here (qword)' context-menu action reads the 8-byte value under
  the cursor and jumps both the hex and disasm views to where it points - manual pointer traversal, like
  CE's memory view. Reuses the existing requestGoto path (bounds-checked read; ignores null/short reads).
  Also verified: Custom-formula scan (compiled-once Lua evaluator) is implemented + tested; hex-view
  nibble editing writes correctly.
- ✅ Verification pass (all correct): in-place Assemble warns before overwriting on a longer instruction
  and NOP-pads a shorter one; Unknown-initial -> Increased/Unchanged/Changed scan chain is implemented
  + tested; the new 'Follow pointer' navigates BOTH views AND joins the back-stack (via syncViews);
  showAsHex value edits round-trip (parseIntField honors the 0x prefix); String/UnicodeString/ByteArray
  writes match CE (raw bytes, no forced terminator).
- ⏭ NEXT feature target: interactive debugger polish — highlight the current instruction (RIP) in the
  disassembler when stopped at a breakpoint, and a 'set value to X' hotkey action (the one CE hotkey
  action we still lack alongside toggle/increase/decrease).
- ✅ NEW: 'set value to X' hotkey action - the one CE hotkey action we lacked (alongside toggle / increase
  / decrease). Configure Value Hotkeys dialog gains a Set-value hotkey + target-value field; the hotkey
  is registered through the global (X11) manager so it fires while the game is focused; the action
  (setEntryValueTo) re-resolves pointer records before writing. Persists across JSON + CE XML
  (<SetValueHotkey>/<SetValueHotkeyValue>) + both GUI mappings; round-trip unit-tested. The CE hotkey
  action set (toggle-active, increase, decrease, set-value) is now complete.
- ✅ FIXED (Fast Scan checkbox was dead): fastScanCheck_ was created and shown but its isChecked() was
  never read - toggling it did nothing. Now First Scan uses alignment from the field when Fast Scan is
  ON, and forces alignment=1 (scan every byte offset -> finds MISALIGNED values) when OFF, matching CE.
  Also grey out the alignment field when Fast Scan is unchecked. (Interactive step-debugger with a
  current-RIP highlight noted as a larger separate gap: no wait/poll loop surfaces an execution-
  breakpoint hit in the main GUI yet.)
- ✅ NEW: target-process death detection. The GUI polled a dead pid forever (stale values, scan buttons
  still live) when the game exited/crashed. The refresh timer now checks kill(pid,0)==ESRCH; on death it
  clears process_, resets currentPid_, detaches the models, disables scanning, and shows 'Process N has
  exited' in the label + status bar. LIVE-VERIFIED: killing target2 flipped the label to 'Process
  3422032 has exited' within ~500ms. Also audited all scan-panel controls are wired (only Fast Scan was
  dead, already fixed); onUndoScan correctly restores the prior result + type + size.
- ✅ NEW disassembler keyboard nav: Enter / Space now follow the SELECTED instruction's branch target
  (call/jmp/jcc) or RIP-relative data address, matching CE (previously follow was mouse-double-click
  only). Refactored the follow logic into DisasmView::followRow, shared by the double-click and keyboard
  paths (no duplication).
- ✅ Disassembler keyboard selection nav (completes the Enter-follow from last iter): Up/Down now move the
  SELECTION cursor (CE-style) and auto-scroll one instruction when the cursor reaches the top/bottom,
  instead of only scrolling the view. Combined with Enter/Space follow, you can now navigate and follow
  branches entirely by keyboard. PageUp/PageDown remain bulk scroll. (Flagged larger gaps: interactive
  step-debugger with RIP highlight; disasm comment/label persistence to the .CT via module+offset.)
- ✅ NEW: Space toggles active/frozen for ALL selected address-list entries (CE-style), from any focused
  column. Previously Space only toggled the current cell's checkbox (Qt default), and only when the
  Active column was focused. A WidgetShortcut intercepts before the table's default (no double-toggle)
  and doesn't fire during cell editing. (Verified Delete/Copy/Paste are already bound to Del/Ctrl+C/V.)
- ✅ NEW: Ctrl+C copies the selected disassembly line ('addr - bytes - mnemonic ops'), matching CE and the
  context menu's 'Copy line' - previously copy was menu-only in the disasm view. (Disasm comment/label
  persistence still deferred: it needs the comment store moved out of the transient DisasmView into a
  MainWindow-owned, module+offset-keyed store synced on open/close - a dedicated larger iteration.)
- ✅ FIXED (table Lua script never ran / never parsed): two bugs. (1) The .CT loader searched only the
  substring BEFORE <CheatEntries> for table-level tags, but CE writes <LuaScript> AFTER the entries
  block - so real CE tables' Lua was never parsed. Now it searches everything OUTSIDE the entries block
  (per-entry <LuaScript> stays inside, never mismatched). (2) Even when parsed, loadTableFromPath never
  executed table.luaScript. Now it runs the table Lua after the records load (with process+addresslist
  set), surfacing errors in the status bar. LIVE-VERIFIED: a table whose <LuaScript> (after entries)
  writes a marker file produced it on load. Unit-tested + suite green. CE trainer framework scripts now work.
- ✅ NEW: the window title now shows the loaded table's file name ('Cheat Engine - mytable.ct'), like CE -
  previously the title was a static 'Cheat Engine'. (Verified Enable-all/Disable-all are wired in the
  address-list context menu.)
- ✅ NEW: Ctrl+C in the scan-results list copies the selected result addresses (was context-menu only),
  matching the address list's copy shortcut. (Results context menu already had Add-to-list / Browse /
  Copy-addresses.) Disasm comment/label persistence remains deferred (needs a MainWindow-owned,
  module+offset-keyed store synced from the transient DisasmView - a dedicated session).
- ✅ FIXED (latent scan-result corruption on short writes): ScanResult::flush and the multi-thread result
  merge used bare ::write, whose return was ignored. A short write (EINTR, nearly-full disk) on the
  addresses file but not the values file would leave them at mismatched lengths, silently pairing the
  wrong address with every value past that point. Added writeAll() (retries EINTR + short writes) and
  used it in flush and all three merge concatenations. Reviewed the threaded scan as safe otherwise
  (per-thread ScanResult in its own subdir, merged after join; chunked reads with overlap - no races).
- ✅ Debug/breakpoint core reviewed correct (critical subsystem): hardware DR7 encoding places enable
  (reg*2), RW (16+reg*4) and LEN (18+reg*4) bits correctly; the non-linear x86 LEN map is right
  (1B=0,2B=1,4B=3,8B=2) and other sizes are rejected, not silently 1-byte'd; execute breakpoints use
  size=1 so LEN=0 as x86 requires. AA disable restores patched bytes in REVERSE first, THEN frees the
  caves (so the game stops jumping into a cave before it's freed) and erases the allocations (no leak).
  Code finder arms + clears DR7 on EVERY thread (no per-thread HW-breakpoint leak). No bugs found here.
- ✅ FIXED (XML unescape missed &apos;): xmlUnescape decoded &lt;/&gt;/&amp;/&quot; but not &apos;, so a
  CE table that escaped an apostrophe (e.g. a description 'It&apos;s') showed the literal '&apos;'.
  Added &apos; -> '. Also reviewed the .CT XML parser: entry hierarchy uses a depth-aware
  parseCheatEntriesBlock/findMatchingClose (nested CE groups load correctly); naive getTagBlocks is
  only used for non-nesting tags (Offset/Structure/Element). Numeric entities (&#NN;) still unhandled
  (rare in CE tables) - noted.
- ✅ FIXED (comma-locale inconsistency in freeze/adjust): parseComparableValue (directional-freeze compare
  + hotkey adjust) parsed floats with bare toDouble (dot only), while writeValueToProcess already
  accepts ',' or '.'. A comma-format frozen/current value there failed to parse and silently degraded
  a directional freeze (Allow Increase/Decrease) to an unconditional write. Now it replaces ','->'.'
  first, matching the write path. Reviewed the rest of the freeze/adjust path as consistent (internal
  values are dot-formatted; fallbacks write comma-aware).
- ✅ NEW (wired existing core to GUI): 'Create Trainer (C source)...' in the File menu. The TrainerGenerator
  (generates a standalone C trainer from a cheat table, injection-safe) existed and was unit-tested but
  had no UI. Now File -> Create Trainer builds the current table via the extracted buildCheatTable() and
  writes the generated C source (compile with gcc). buildCheatTable() also de-duplicates onSaveTable
  (both now share the JSON->CheatEntry mapping). Reviewed the pointer scanner core as correct (BFS with
  prepended offset chain, correct offset sign/order, intentional visited-dedup).
- ✅ NEW (exposed a dead subsystem's entry point): Tools -> 'Detect Mono/.NET Runtime'. The 319-line
  managed_runtime analyzer (detect Mono/CoreCLR, enumerate managed objects/types - CE's 'Mono Features'
  for Unity/.NET games) was implemented and unit-tested but had NO GUI/CLI/Lua access at all. Added a
  Tools action that runs the tested detectManagedRuntimes() and reports each runtime's kind/module/base
  (or 'native process' when none). Full managed object/type dissection UI is a larger follow-up. This
  is the same class of gap as Create Trainer - built+tested core with no reachable UI.
- ✅ NEW (wired tested core to GUI): Structure Dissector 'Copy as C++' button. structure_tools'
  generateCppStruct (export a structure as a C++ struct - a CE convenience for pasting into code/AA)
  was unit-tested but unreachable from any UI. The button builds a StructureDefinition from the
  dissector's named fields (types via guessType, sizes per type) and copies the generated C++ struct
  to the clipboard. Audit note: structure_tools' autoDetectStructureFields/followStructurePointers and
  debug/managed_breakpoint remain unwired (candidates for later).
- ✅ FIXED (ExpressionParser misparsed non-leading bracket with inner offset): an expression like
  '0x1000+[[0x100000]+8]' (a term plus a bracketed pointer that has its own +offset) resolved wrong.
  Two coordinated bugs: (1) the arithmetic +/- split wasn't bracket-depth-aware, so it split the inner
  '+8' and mangled the bracket; (2) the split terms were resolved via resolveToken (simple
  hex/decimal/symbol only), which returns 0 for a '[...]' term instead of dereferencing. Now the split
  tracks bracket depth (counting the term's own leading '['), and any term containing '[' recurses
  through parseImpl so the deref happens. Unit-tested; suite green. (Leading-bracket pointer
  expressions - the common address-list form - already worked.)
- ✅ Verified correct this pass: File Patcher (in-place ReadWrite, extend-past-EOF warning, seek + write-
  count checks, confirmation dialog); assembler (Keystone engine opened once per instance and closed in
  the dtor - no per-call leak; encoded buffer freed via RAII guard on all paths; silent-zero-byte
  Keystone output treated as failure so the GUI won't NOP-pad over code). A background agent is
  reviewing the Lua bindings (lua_bindings/lua_memrec/lua_gui) for stack/bounds/type bugs.
- ✅ FIXED (use-after-free of lua_State — background-agent find, verified): the Lua GUI bindings keep a
  static guiLuaState + callback maps (createTimer OnTimer, createForm button OnClick, ...). guiLuaState
  was set to the engine's lua_State but NEVER reset on teardown, so ~LuaEngine's lua_close left it
  dangling; a Qt timer/widget callback firing during shutdown then did lua_rawgeti/lua_pcall on freed
  memory (invokeLuaCallback's !guiLuaState guard passed because the pointer was non-null-but-freed).
  Added shutdownLuaGuiBindings() (nulls guiLuaState first, then clears the maps) and call it from a new
  MainWindow destructor before luaEngine_ is destroyed. A background agent surfaced this; I verified and
  fixed it. (It has more lower-severity Lua findings queued for later.)
- ✅ FIXED (Lua file-IO undefined behavior — agent finds, verified): three lua_CFunctions could throw a C++
  exception out into liblua's C frames (UB). readFromFile/readRegionFromFile slurped an entire file with
  no bound - readFile('/dev/zero') never EOFs and a huge file OOMs, and the bad_alloc unwinds through
  liblua. fileExists/getTempDir used the THROWING std::filesystem overloads (filesystem_error on a bad
  path). Now the reads are capped at 64MB in a try/catch (luaL_error on failure) and the filesystem
  calls use the std::error_code overloads. Remaining agent finds queued: readPointer/writePointer
  hardcode 8-byte size (32-bit targets), AOBScanEx silent 1000-result cap.
- ✅ FIXED (remaining Lua agent finds): (1) readPointer/writePointer hardcoded sizeof(uintptr_t)=8 bytes,
  wrong for 32-bit TARGETS (supported via is64bit()) - readPointer put garbage in the upper dword and
  writePointer clobbered the following dword. Now they use the target's pointer width (8 or 4). (2)
  AOBScanEx silently capped results at 1000 (std::min) while AOBScan and CE return all - removed the cap
  (with a luaL_checkstack guard). All five background-agent findings (UAF, 2 file-IO UB, filesystem UB,
  32-bit pointer, AOBScanEx cap) now fixed. Suite green.
- ✅ Reviewed the ceserver client network protocol (remote/Android debugging) - safe against a hostile
  server: sendAll/recvAll loop until complete (MSG_WAITALL); the version string uses a uint8_t size with
  the buffer sized before the read; server-provided region/thread counts are bounds-checked
  (reject <0 or >2^20) before reserve(); memory reads use a client-controlled size. No overflow/OOM
  vector found. A background agent is reviewing the auto-assembler engine (core/autoasm.cpp).
- ✅ Reviewed CodeAnalyzer::findReferencesTo (xref scan) - correct: it disassembles only EXECUTABLE regions
  within the target module (skips data, so no false call/jmp refs from disassembling data), bounds each
  region read (kMaxAnalysisRegion), and classifies call/jmp/jcc + RIP-relative refs from real
  instructions (not a naive byte scan). Awaiting the auto-assembler agent's findings.
- ✅ FIXED (AA execute corrupted the target on a mid-script failure — background-agent find, verified):
  on a Keystone assembly error the execute loop logged and `continue`d WITHOUT advancing currentAddr,
  so the next instruction/db was written over the failed slot and every later label shifted - with the
  jmp-to-cave hook already live, the game then executed a corrupt cave. Hard patchMemory failures also
  returned without freeing already-committed RWX caves (leak). Added a rollback() (restore patched
  bytes in reverse, free the caves - same as disable(), using the incrementally-built disableInfo) and
  return it from EVERY hard execute failure (assembly error + all 8 patchMemory sites). Suite green.
  Remaining agent finds queued: sizing/execute jump-relaxation size divergence (far forward jcc),
  quote-unaware // comment strip mangling db strings, cross-script dealloc name collision.
- ⏭ KNOWN LIMITATION flagged (AA agent find #1, deferred): a forward jmp/jcc to a label MORE than 127
  bytes ahead is mis-sized. The sizing pass fills the unresolved forward label with a placeholder equal
  to the jump's own address (displacement ~0), so Keystone emits a 2-byte SHORT jump, but at execute
  the real far target assembles to 5/6 bytes, shifting every later label. Attempted fix (force the near
  form) FAILED: Keystone's NASM rejects 'jmp near 0x...'. Correct fix needs fixed-point sizing (iterate
  resolveForwardLabels until label addresses stabilize with real jump lengths) or a displacement-fixup
  pass. Affects only LARGE caves with far forward branches; small caves (<128B) are unaffected. The
  execute-failure rollback (previous commit) already prevents the separate error-path corruption.
- ✅ FIXED (AA // comment strip mangled db strings — agent find #2, verified+tested): stripInlineComment
  and the parseLine inline-comment strip did a plain find("//") that ignored quotes, so db "http://x",0
  truncated to db "http: and failed to assemble. Made stripInlineComment quote-aware (skip // inside
  '/" spans) and routed the parseLine strip through it. New test (db "ab//cd",0 writes the full literal).
- ✅ IMPROVED + triaged (AA agent find #3, cross-script dealloc): cross-script dealloc(name) is an
  INTENDED feature (a test allocs in one script and deallocs in another), and the name-keyed dealloc
  namespace matches CE's global alloc names - so a same-name 'collision' is the user's naming choice,
  not a fixable bug (scoping it to the current script breaks the [DISABLE]-block dealloc pattern, since
  enable/disable are separate execute() calls). Kept a genuine defensive fix: disable() and the execute
  rollback now erase the knownAllocations_ entry ONLY when its address matches the freed block, so
  tearing down one activation can't evict a different activation's same-named dealloc entry. New test.
  All auto-assembler agent findings now resolved except the deferred far-forward-jump relaxation.
- ✅ RESOLVED (AA far-forward-jump relaxation was a FALSE POSITIVE): the deferred 'relaxation sizing'
  concern is NOT a bug. resolveForwardLabels already iterates (maxPasses=8) and substituteSymbols
  substitutes a resolved label with its real address on later passes, so the sizing converges to the
  true jump lengths - a je to a label >127 bytes ahead is correctly sized as the 6-byte near form and
  the label lands at the right address. Proven with a new regression test (je farend; nop 200; farend:
  ret -> 0F 84 rel32 at newmem+0, ret at newmem+206, rel32 points to it). My earlier forceNearBranch
  attempt (iter reverted) was unnecessary AND wrong (Keystone rejects 'jmp near 0x...'). All
  auto-assembler agent findings are now fully resolved (3 real fixes, 1 improvement, 1 false positive).
- ✅ Re-verified the user's named complaint ('scan results dont update in real time') is fully solved
  end-to-end: valueRefreshTimer_ fires every 500ms (configurable memview/refreshMs) and calls
  resultsModel_->refreshRange(first,last) over ONLY the currently-visible rows (indexAt top/bottom), so
  million-row result sets stay responsive. refreshRange re-reads each visible row from process memory,
  flags rows whose value changed since the last tick (CE-style red highlight), and bounds the
  liveValues_ cache to on-screen rows. F5 forces an immediate refresh; target death (kill ESRCH) stops
  polling and clears state; a focused cell-editor guard prevents clobbering an in-progress edit.
  A background agent is reviewing the disassembler (arch/disassembler.cpp).
- ✅ Disassembler independently reviewed by a background agent - NO genuine bugs. Verified clean:
  resolveRipRelative (in.address+in.size+disp is the correct RIP-end base; in.size already includes the
  trailing immediate, so no missing-immediate error; sign/displacement correct); no buffer over-read
  (cs_disasm bounded by code.size()-offset; previousInstruction reads <=15 bytes into buf[16]);
  Capstone handle opened in ctor/closed in dtor (non-copyable), insn array freed via RAII on every
  path; decode-failure resync emits a db byte and advances offset by 1 (forward progress, no infinite
  loop); no 64->32 truncation; exact bytes/size slicing. Only note: ripTarget==0 doubles as 'no target'
  and 'absolute 0' - unhittable (page 0 unmapped), not worth a bool-flag API change. Branch/jump target
  math lives in code_analysis.cpp (already reviewed), not the disassembler.
- ✅ Scan feature-completeness audit (user's 'features CE has and we dont' emphasis) - no gaps found:
  ScanCompare covers the full CE set (Exact/Greater/Less/Between/Unknown/Changed/Unchanged/Increased/
  Decreased/IncreasedBy/DecreasedBy/SameAsFirst). ScanConfig covers rounding (exact/rounded/truncated/
  extreme), percentage + percentage-between, float tolerance, string scans with iconv encoding +
  case-insensitivity, AOB with per-nibble wildcard masks, binary bit-pattern scans, grouped scanning
  (parseGrouped 'i32:100@0;float:1.5@4;byte:7@8'), and custom-formula/custom-size scans. Undo Scan is
  present and correct (onUndoScan swaps in the saved previous result, single-level like CE). The core
  scan engine is at CE parity.
- ✅ NEW (disassembler comment/label persistence - storage layer): the DisasmView held user comments +
  labels only in-memory (lost on window close, not saved). Added CheatTable::disassemblerComments
  (DisassemblerComment{address-expression, comment, label}) with JSON + .CT XML round-trip
  serialization. Address is stored as an EXPRESSION ('libgame.so+0x1234') so module-relative
  annotations survive ASLR (resolved via ExpressionParser on apply). Round-trip tested. NEXT: wire the
  MemoryBrowser/DisasmView to read from + write to this store (MainWindow-owned) on save/load.
- ⏭ Pointer-scanner agent review: verified correct (offset inversion, depth, window over-read, save/load
  bounds, rescan). One MEDIUM to fix next: sharded staticOnly scan skips other shards' module regions in
  Phase 1 but expands all in Phase 2, so a chain through a static intermediate owned by another shard is
  lost from the merged set (fix: read all module regions in Phase 1, shard only the endpoint recording).
  One LOW completeness tradeoff (global visited cycle-guard) is deliberate; left as-is.
- ✅ FIXED (pointer-scanner sharded scan lost paths through a static intermediate — agent find, verified):
  in staticOnly sharded mode Phase 1 SKIPPED other shards' module regions, but Phase 2 traverses through
  located nodes, so a chain routed THROUGH a static intermediate owned by another shard (gameA -> gameB
  -> heap -> target, gameA/gameB in different shards) was lost from EVERY shard - violating the
  'merged shards == full scan' contract. Now Phase 1 reads ALL readable regions (complete traversal) and
  the sharding partitions only the RECORDED endpoints, by module index (each module's paths go to one
  shard; union == full). New regression test with a 2-module through-static chain (fails on the old
  code: merged would miss the gameA path). Removed the now-dead isModuleRegion/staticRegionIndex.
- ✅ NEW COMPLETE (disassembler comment persistence - GUI wiring): user comments set in the memory
  browser now PERSIST across window close and save/load. MemoryBrowser::setAnnotationStore seeds the
  DisasmView from the stored comments (resolving each module-relative address expression to the current
  base) and pushes changes back via a saver callback; MainWindow owns disasmAnnotations_ and wires every
  browser it creates (wireBrowserAnnotations x6 sites). buildCheatTable() serializes them; onSaveTable
  writes them (.ct via CheatTable::save, .json via the Qt writer) and loadTableFromPath restores them
  (both formats). Address stored as 'module+0xoff' so comments survive ASLR. Build + suite green.
  Follow-up: persist user LABELS too (the .label field already serializes; needs resolver user-symbol
  enumeration wired the same way).
- ✅ COMPLETE (disassembler annotation persistence - LABELS too): the follow-up is done. persistComments
  now merges inline comments (DisasmView) AND user labels (SymbolResolver::userSymbols) by
  module-relative address expression into one DisassemblerComment per address; setAnnotationStore
  re-applies both (setComment + addUserSymbol) on browser open; the label (requestSetSymbol) handler
  persists on change. Added SymbolResolver::userSymbols() accessor. So disassembler comments AND labels
  now survive window close and save/load (.ct + JSON), keyed to survive ASLR. Build + suite green.
- ✅ Reviewed the memory-scanner comparison paths - all correct: float rounding (roundingType 1 rounds via
  llround with a >9.2e18 guard using std::round to dodge llround UB; 2=trunc; 3=relative tolerance
  max(1e-6, |val|*1e-6); 0=exact; non-finite current rejected), string encoding (encodeStringBytes uses
  iconv with an E2BIG grow loop that recomputes outPtr from the resized buffer and iconv_close on every
  path), and case-insensitive matching (both operands are uint8_t, so std::tolower is well-defined - no
  signed-char UB). Note (not changed): the float rounding combo defaults to 'Exact' (index 0) whereas CE
  defaults float scans to 'Rounded (default)'; Exact gives precise narrowing and is defensible, but a
  future CE-parity pass could default to Rounded and align roundingType 1 with CE's decimal-precision
  rounding (currently integer rounding, looser for fractional values).
- ✅ IMPROVED (float scan CE parity): (1) the float rounding combo now defaults to 'Rounded' (index 1)
  like CE's 'Rounded (default)', instead of bit-exact 'Exact'. (2) roundingType 1 now matches at the
  search value's DECIMAL PRECISION - a value matches when it's within half the last decimal place (3.14
  with 2 dp matches [3.135,3.145), rejecting 3.15) - CE's real behavior, instead of the previous integer
  rounding (which loosely matched anything rounding to 3). The precision (ScanConfig.floatDecimals) is
  counted from the typed value, '.'/',' comma-locale-aware; non-GUI callers (floatDecimals=-1) keep the
  guarded integer-rounding fallback. Regression test added. Suite green.
- ✅ HARDENED (breakpoint condition can't hang the debugger): breakpoint Lua conditions run in a strong
  sandbox (curated libs + stripped load/dofile/require/rawset - no RCE), but a condition from an
  untrusted CT file could loop forever ('while true do end') and hang the debugger on every hit. Added a
  LUA_MASKCOUNT hook that aborts the chunk after 2M instructions; the abort surfaces as an eval error and
  falls through to the existing fail-safe break. Regression test asserts recordHit RETURNS on a
  looping condition (no hang) - runs to completion, exit 0. Also confirmed the debugger breakpoint
  feature set is at CE parity: conditional (Lua), hitCount, per-thread filter, one-shot, hardware+
  software, data breakpoints (1/2/4/8).
- ✅ NEW (batch 'Set value' for the address list): CE lets you select multiple cheat-table entries and
  set them all to one value at once; we only had per-cell editing. Added a 'Set value...' context action
  (multi-select) that prompts once and calls setEntryValueTo for every selected row - which re-resolves
  each pointer expression to the live target and writes via the shared writeValueToProcess path
  (comma-locale-aware, per value type), updating the frozen value for active rows. The address list
  already had batch Freeze-Mode, Change-Type, Copy/Delete, and Indent/Outdent; this fills the set-value
  gap. A background agent is reviewing the ptrace/injector platform layer.
- ✅ FIXED (platform-layer, background-agent finds, verified): (1) HIGH - near-allocation used flags|0x10,
  which is plain MAP_FIXED (unmaps whatever occupies the address), NOT MAP_FIXED_NOREPLACE (0x100000).
  The gap walk relies on mmap FAILING when the chosen gap address is already taken (the region snapshot
  can go stale before the target is stopped), so MAP_FIXED could silently clobber a live mapping (thread
  stack, JIT page) and crash the target. Now uses MAP_FIXED_NOREPLACE (named constant + fallback define).
  (2) LOW - setBreakpoint/removeBreakpoint read DR7 via PTRACE_PEEKUSER without clearing/checking errno,
  so a transient read failure (returns -1) would OR/AND garbage and poke a corrupted debug control
  register; now clear errno and treat -1-with-errno as failure (matching getContext's peekDr).
  Agent-flagged, still to do: createRemoteThread should quiesce sibling threads like injectLibrary does.
- ✅ FIXED (createRemoteThread loader-lock deadlock — agent find #2, verified): createRemoteThread attached
  ONLY the main thread and hijacked it unconditionally to call pthread_create. If a sibling thread was
  inside the dynamic linker or held a glibc lock (malloc/TLS/stack-cache), the injected pthread_create
  (which takes those locks) would deadlock and remoteCall's waitpid never return, hanging the tool with
  the target stopped. Now mirrors injectLibrary: a SiblingGuard stops every /proc/<pid>/task sibling for
  the duration (detaching all on return), and it hijacks a thread in USERSPACE (not rewound onto a
  `syscall` instruction), falling back to the main thread. All 5 remoteCalls (create + tryjoin/join/
  detach) route through the selected injPid. All THREE platform-agent findings now fixed. Build+suite green.
- ✅ Verified the Lua memscan scripting API (CE automation parity): createMemScan() returns a MemScan
  object with firstScan(scanType,valueType,value[,start,stop,align,encoding]), nextScan, getFoundCount,
  getAddress(idx), and a __gc finalizer. All scans are wrapped in try/catch (no C++ exception escapes
  into Lua; returns ok,error), getAddress is bounds-checked (idx out of range -> nil), and luaScanConfig
  parses float/double values via parseLocaleDouble (comma-locale-aware) and maps scan/value type enums.
  Functionally equivalent to CE's memscan (synchronous, so no waitTillDone needed). A background agent
  is reviewing the ELF/DWARF symbol parsers.
- ✅ ELF/DWARF symbol parser independently reviewed by a background agent - NO memory-safety bugs. It
  traced every attacker-controlled offset/size/count: sh_entsize overflow guarded; section [off,size)
  bounded non-wrapping (off>fileSize || size>fileSize-off); string-table st_name/sh_name checked <sh_size
  with a forced NUL before every strlen/demangle; sh_link + e_shstrndx bounds-checked; no sh_entsize==0
  divide (divides by the compile-time sizeof); ELF32 rejected (ELFCLASS64 only); PLT scan in-bounds;
  DWARF depth-capped + delegated to libdw. Fixed two flagged robustness quirks: (1) loadProtected now
  rejects a >64MB .CETRAINER up front (untrusted shared trainers can't drive the whole-payload read into
  bad_alloc); (2) elf_symbols reused one ifstream whose failbit persisted, so a bad section silently
  suppressed later symbol/reloc reads - added f.clear() before each seekg so each section read is
  independent. Build + suite green.
- ✅ Verified the auto-assembler TEMPLATE system is at CE parity (user's 'how they created templates'
  emphasis): builtinAaTemplates() ships the CE Code-Templates (Ctrl+I) set in CE's menu order - Allocate
  memory, Code injection (at address), AOB injection, Full code injection, Pointer injection, Cheat table
  framework, Lua Script. The AOB-injection body matches CE exactly (aobscanmodule INJECT for
  update-resilience, alloc(newmem,$1000,INJECT) to keep the cave in jmp range, label(code)/label(return),
  newmem/code with the original code + jmp return, INJECT: jmp newmem, registersymbol, and [DISABLE]
  restoring db <original bytes> + unregistersymbol + dealloc). The 'Code injection at address (auto)'
  generator (buildCodeInjectionScript, fills original bytes/disasm from a live address) is already tested.
- ✅ Verified + regression-tested directional freeze (IncreaseOnly/DecreaseOnly/NeverIncrease/NeverDecrease):
  the freezeWrite decision was correct but untested and inline. Extracted ce::freezeShouldWrite(mode,
  current, frozen) into core/types.hpp (Normal always writes; allow-increase == never-decrease = floor,
  write iff current<frozen; allow-decrease == never-increase = ceiling, write iff current>frozen; no
  directional write at equality), used it in freezeWrite, and added a unit test covering all 5 modes and
  the equality edge. Correctness-sensitive freeze logic is now regression-protected. Build + suite green.
- ✅ Verified disassembler readability (user's 'improve the disassembler' focus): a call/jmp/jcc to an
  immediate target is annotated with the resolved symbol ('call 0x7f... ; malloc'), including @plt/@got
  imports; RIP-relative data operands get ripRefAnnotation (effective address + symbol + the live
  value/string pointed at); user comments render in green immediately after the operands; and DWARF
  source-line info is appended. Combined with jump arrows, branch-target row tint, and keyboard nav,
  the disassembler is at/above CE's readability. A background agent is reviewing the ScanResult
  file-backed storage + nextScan reduction mechanics.
- ✅ Verified in-place assembly editing (memory view -> Assemble) is correct: assembleAt NOP-pads (0x90)
  when the new instruction is shorter than the original so the next instruction boundary is preserved,
  warns+confirms before writing a LONGER instruction (which would overwrite the following instruction),
  refuses to write an empty/zero-byte assembly, and reports a write failure. Matches CE's assembler
  edit behavior. Awaiting the ScanResult storage agent's findings.
- ✅ FIXED (HIGH: ValueType::All scan produced garbage values + crashed nextScan — agent find, verified):
  scanBufferAllTypes recorded each match with the matched type's WIDTH (1/2/4/8 bytes), but ScanResult
  stores one valueSize_ and value(i)/firstValue(i) index at i*valueSize_ (fixed stride), and the GUI
  reads All-results at size 8. So after the first sub-8-byte record the value stream desynced from the
  address list (garbage displayed values) and nextScan's stride guard threw invalid_argument. Now every
  All match stores a UNIFORM 8-byte window (the memory at the match offset, zero-padded at the region
  tail), so value(i)=i*8 stays in lockstep and the result is view- and next-scannable. Strengthened the
  All-scan test: value(i) must equal memory at address(i), and nextScan must not throw. Suite green.
  Remaining agent find (LOW): flush()/merge ignore writeAll's bool, so a real short write (ENOSPC) leaves
  count_ > file content and trailing entries read back zeroed - to be propagated as a truncation error.
- ✅ FIXED (LOW: scan-result short write silently produced garbage — agent find #2): ScanResult::flush and
  the multi-thread merge concatenation ignored writeAll's bool, so a real short/failed write (ENOSPC/EIO)
  left count_ ahead of the backing file and trailing entries read back as zeroes with no error. Added a
  writeError_ flag set on any short write in flush() and propagated from the merge (markWriteError on the
  returned merged result), exposed via hasWriteError(). The GUI now shows a 'Scan results truncated' (disk
  full) warning after first-scan and next-scan when the flag is set, instead of silently displaying garbage.
  Both ScanResult-storage agent findings (All-desync + short-write) now resolved. Build + suite green.
- ✅ Verified the code finder ('find what accesses/writes this address') is at CE parity + register-complete:
  the results table shows each unique instruction with a hit count and inline RAX/RBX/RCX/RDX/RIP;
  double-clicking a row opens a full CPU-context dump - all GP registers (rax..r15), rip, rflags, the
  segment registers (cs/ss/ds/es/fs/gs), and the debug registers (dr0-3,dr6,dr7). Matches (and slightly
  exceeds) CE's hit-list + register view. A background agent is reviewing the analysis layer
  (structure_tools auto-detect/follow-pointers + code_analysis call-graph/guessType).
- ✅ Analysis layer independently reviewed by a background agent - NO memory-safety bugs. Verified clean:
  structure_tools formatStructureFieldValue/readSnapshotValue bound every read by
  min(fieldSize, size-offset) and reject size-offset<sizeof(T); followStructurePointers is maxDepth-
  capped (self-referential pointer terminates); isReadablePointer validates region+prot+range;
  buildCallGraph seeds starts with module.base (no empty front()/prev()), off-module targets never
  dereferenced, region reads capped at 512MB; guessType gates the 8-byte read behind offset+8>validBytes_
  (=min(*r,structSize_)); defaultSizeFor never returns 0. Fixed the one flagged cosmetic quirk: the
  struct-dissector compare-diff highlight didn't track the COMPARE read's valid length, so a partial
  compare read (struct straddles an unmapped page) could flag stale-but-in-buffer bytes as a diff. Now
  the row highlight only fires where BOTH snapshots have real bytes (off+8<=compareValid). Build green.
