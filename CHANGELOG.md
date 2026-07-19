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
- **Hex pane "Add address to the list" uses the current display type** (CE-style): adding
  from Float display makes a Float record, Qword display an 8-byte record, etc., instead of
  always Int32. Asserted in `gui_hexview_smoke`.
- **Memory-viewer Find supports wildcard AOBs**: `48 8B ?? 05` (or `488b??05`) now matches
  any byte at the `??` positions, so you can search for a pattern regardless of a
  displacement or immediate. Exact byte and quoted-string search are unchanged. Covered by a
  new offscreen `gui_search_smoke` in the CI mirror.
- **Memory-viewer "Find previous" (Shift+F3)**: searches backward for the closest match
  strictly below the cursor, complementing Find next (F3). Asserted in `gui_search_smoke`.
- **A search hit highlights the matched bytes** in the hex pane, so you can see exactly what
  Find landed on instead of just the address. Asserted in `gui_hexview_smoke`.
- **Fixed: "Follow pointer" now sizes the pointer to the target** (4 bytes on a 32-bit
  process, 8 on a 64-bit one). It previously always read an 8-byte qword, so following a
  32-bit pointer jumped to a bogus address built from unrelated high bytes. Asserted in
  `gui_hexview_smoke`.
- **Debugger annotates register-relative memory operands** (CE parity): when paused, an
  instruction like `mov [rax+8],rbx` or `mov rax,[rbx+rcx*4+10]` now shows the effective
  address it touches (resolved from the live registers) and the symbol / value there, not just
  RIP-relative operands, in **both** the Debugger window and the Memory Viewer's disassembler.
  Uses the existing (previously unused) `ce::computeEffectiveAddress`; the current-instruction
  highlight now carries the full register context, not just the flags.
- **Debugger flags show every state, not just the set ones** (CE parity): the register panel's
  Flags line now reads `CF=0 PF=1 AF=0 ZF=1 SF=0 DF=0 OF=0` instead of just the names of the set
  flags, so you can read a clear flag's state next to a conditional jump. Backed by a Qt-free
  `ce::describeEflagsVerbose`, unit-tested in `cecore_test`.
- **Debugger "Run to cursor" gets F4 and a context-menu item** (CE parity): the Run to Cursor
  button now carries CE's **F4** shortcut, and right-clicking a disassembly line offers "Run to
  cursor" (enabled only while paused), so you can run to a clicked instruction without setting a
  temporary breakpoint.
- **Debugger predicts conditional jumps** (CE parity): when the target is paused on a
  conditional branch (`je`, `jne`, `jbe`, `jg`, ...), the disassembly line now reads
  `(will jump)` or `(no jump)` based on the live flags, so you can see the path before you
  step, in **both** the Debugger window and the Memory Viewer's disassembler (which follows the
  stop). The mnemonic+flags decision is a Qt-free `ce::conditionalJumpTaken`, unit-tested in
  `cecore_test`.
- **Scan value input parses through the same hex-aware helper**: the integer scan value (and the
  "Value between" upper bound) went through `toLongLong(base)`, which mishandled a `0x`-prefixed
  entry in Hex mode; they now use the shared `parseIntField` / `ce::parseIntegerScalar`, so a
  scan value parses exactly like a cheat-table value (bare hex or `0x`, signed). This was the last
  integer-parse site not on the shared helper.
- **Fixed: value comparison ignored the signed-display flag**: the memory-read side interpreted
  a Byte as unsigned but wider ints as signed (a fixed per-type choice), while the frozen/typed
  text follows the record's Signed flag. So a signed-shown byte over 127 (now the default) or an
  unsigned-shown int never equalled its own frozen text, breaking directional freeze, the step
  hotkeys, and edit-revert detection. The read side now honors the record's Signed flag, matching
  the parse, and the edit-verify target is parsed hex/signed-aware too.
- **Fixed: directional freeze (Increase/Decrease Only) silently broke on hex-display records**:
  a hex record stores its frozen value with a `0x` prefix, but the freeze comparison parsed it
  as base-10 and failed, falling through to an unconditional write, so "Increase Only" etc.
  behaved like a plain freeze. The comparison now parses via the shared hex-aware
  `ce::parseIntegerScalar`, so directional freezes hold correctly regardless of hex display.
- **Fixed: increase/decrease-value hotkeys corrupted hex-display records**: the step hotkeys
  built the new value as a bare decimal but told the writer to parse it in the record's display
  base, so a hex record turned an increment into a hex misread (e.g. `256` written as `0x256`).
  The new value is now rendered in the record's own display format (via the shared
  `formatIntegerScalar` / `formatFloatScalar`), so it writes back correctly and also matches the
  column immediately; floats no longer flash fixed-decimal text before the next refresh.
- **"Set value" on a group applies to its children** (CE `moRecursiveSetValue`): since a group
  header has no value of its own, setting a value on a selected group now writes it to all the
  group's child entries recursively (deduped when a group and a child are both selected). The
  subtree-span logic is a Qt-free `ce::descendantRange`, unit-tested in `cecore_test`.
- **Group collapse state persists** (CE `Collapsed`): a collapsed group stays collapsed after
  saving and reopening a table (CE XML `.CT`, `.CETRAINER`, and native JSON), via a
  `<Collapsed>1</Collapsed>` tag, and re-hides its children on load. Asserted in `cecore_test`.
- **Cheat-table groups collapse and expand** (CE tree parity): double-clicking a group header
  (outside its Description) now hides or shows its child rows, with a `▾`/`▸` marker on the
  group. Nested groups collapse independently, and the hidden state re-applies after refreshes
  and reorders. The "which rows to hide" logic is a Qt-free `ce::hiddenByCollapse`, unit-tested
  in `cecore_test`.
- **Float values display trimmed of trailing zeros** (CE parity): a float of `100.0` now reads
  `100`, not `100.0000`, and `99.5` reads `99.5`; precision matches the type (~7 significant
  digits for Float, ~15 for Double). The cheat table, scan results, and Structure Dissector all
  share one Qt-free `ce::formatFloatScalar`, unit-tested in `cecore_test`.
- **.Net menu is functional; empty menus removed**: the top-level **.Net** menu (previously an
  empty dropdown) now opens the Mono/IL2CPP dissector (shared with Tools via a new
  `openMonoDissector`), and the empty **Plugins** / **Languages** menus are dropped (no plugin
  loader, English-only), the same treatment the dead D3D menu already got.
- **"Set value" pre-fills the current value** (CE parity): right-click -> "Set value..." now
  opens with the first selected entry's current value (in its display format) already in the
  box, so you edit from it instead of a blank field.
- **Scan results and the cheat table format integers identically**: scan-result values now
  render through the same shared `ce::formatIntegerScalar` (signed by default, hex
  width-masked) as the cheat table, so a value reads the same in the results list and after
  "Add to the address list" (previously a byte could show unsigned in results but signed once
  added). Removes the internal quirk where results showed Byte unsigned but wider ints signed.
- **"Add Address Manually" opens the full address dialog** (CE parity): instead of a bare
  text prompt, adding an address by hand now uses the same `formAddressChangeUnit` dialog as
  "Change address", so a new entry gets its type, hex/signed flags, length, and an optional
  structured pointer chain in one step. `AddressListModel::addEntry` now returns the new id so
  the flags can be applied.
- **Memory Viewer can load a region from a file** (CE parity): the disassembler right-click gains
  "Load region from file..." to complement "Save region to file...", writing a saved/prepared
  binary back into the target at the clicked address (with a confirmation of the byte count and
  destination, since it patches live memory) and refreshing the panes.
- **Memory Viewer Tools menu is populated** (CE parity): the previously empty **Tools** menu
  now offers **Auto Assemble...** (opens a script editor) and **Dissect data/structures...**
  (opens a Structure Dissector at the current address), routed through the openers MainWindow
  owns. Asserted in `gui_search_smoke`.
- **Fixed: address expressions broke on hyphenated library names**: the expression parser split
  on `-`, so a Linux library whose name contains a hyphen (e.g. `libssl-1.1.so+0x10`) was split
  at the hyphen and failed to resolve, which also broke the symbolic address bar's round-trip for
  such modules. The parser now recognizes a known module-name prefix (longest match) and takes it
  whole, so its internal `-` is not mistaken for subtraction. Unit-tested in `cecore_test`.
- **Hex pane offers 64 bytes per row** (CE parity): the "Bytes per row" menu now includes 64
  alongside 8/16/32 for wider dumps; 64 divides by every display-type group size, so grouped
  views stay valid.
- **Memory Viewer remembers "Bytes per row" and "Display type"** (CE parity): both hex-pane
  choices now persist across sessions. Bytes-per-row was loaded from settings but the menu
  change never saved it (so it always reverted to 16), and display type wasn't persisted at all;
  both are now written on change and restored when a Memory Viewer opens.
- **Fixed: inline-editing a record's Type parsed the new type names wrong**: after the Type
  column was renamed to CE's wording, the reverse parser still only knew the old names, so
  committing a Type-cell edit on a Unicode-String record (or "All") fell back to 4 Bytes. The
  reverse parser now derives from the same `ce::valueTypeName`, so every displayed name
  round-trips, with the old names kept as synonyms.
- **Scan value-type dropdown uses the same names as the cheat table**: the scanner said "Text" /
  "Unicode Text" / "Array of Bytes" / "All Types" while the address list and Change-address dialog
  said "String" / "Unicode String" / "Array of byte" / "All" (`ce::valueTypeName`); the scanner now
  matches, so a type reads the same when you scan it and when it lands in the list.
- **Cheat-table Type column uses CE's wording and shows element length**: the list column
  said "Text" / "Array of Bytes" / "Unicode Text" while the Change-address dialog (and CE)
  said "String" / "Array of byte"; both now agree via one shared `ce::valueTypeName`. String
  and Array records also show their element length in brackets ("String[10]",
  "Array of byte[8]"). Unit-tested in `cecore_test`.
- **Editing a hex-displayed value reads the input as hex** (CE parity): when a record shows
  its value in hexadecimal, typing a bare `1a` into the Value cell now writes `0x1A`, not a
  failed decimal parse. Integer value input goes through a Qt-free `ce::parseIntegerScalar`
  (the input counterpart of `formatIntegerScalar`): hex mode reads a bare token as hex, a
  `0x` prefix always forces hex, and signs/decimal still work. Unit-tested in `cecore_test`.
- **Signed display persists to `.CT` tables** (CE `<ShowAsSigned>`): a record's signed/unsigned
  choice now survives save/load in every format (CE XML `.CT`, `.CETRAINER`, and our native
  JSON), so a table shared or reopened keeps its value display. Signed is the default, so only
  an unsigned override is written (`<ShowAsSigned>0</ShowAsSigned>`); a table without the tag
  loads as signed. Asserted in `cecore_test` (round-trip + absent-tag default + explicit
  override).
- **"Change address" dialog: Signed toggle now works** (CE `ShowAsSigned`): the last dead
  control is wired. Ticking **Signed** shows integer values as signed (e.g. a byte `200`
  reads `-56`), unticking shows unsigned (`200`); the box is offered only for integer types,
  round-trips a record's flag, and persists in saved tables. This also makes the value
  formatter consistent (Byte was always unsigned, the wider ints always signed). The
  signed/unsigned/hex rendering is a Qt-free `ce::formatIntegerScalar`, unit-tested in
  `cecore_test`; the dialog wiring is asserted in `gui_changeaddr_smoke`.
- **"Change address" dialog: structured pointer editor** (CE parity): ticking **Pointer**
  reveals a base-address field plus an offset chain (Add offset / remove per row), and the
  address field shows the composed `[[base]+..]` as you edit. Opening an existing pointer
  record parses its expression back into the base and offset rows, so it round-trips. The
  compose/parse pair is the Qt-free `buildPointerExpression` / new `parsePointerExpression`
  (unit-tested inverse) in `core/ct_file`; the editor is asserted in `gui_changeaddr_smoke`.
- **"Change address" dialog: Unicode box and Length now work** (CE parity): ticking
  **Unicode** on a String record makes it a Unicode string (CE has no separate type, it is
  String + the box), and it round-trips: a Unicode record reopens as String with the box
  ticked. The **Length** field is seeded from the record's actual element length (not a hard
  1) and is applied on OK, so String/Array/Unicode lengths can be edited. Unicode is offered
  only for the String type. Asserted in the new `gui_changeaddr_smoke`.
- **AOB injection generates a unique signature** (CE parity): "Create AOB injection here"
  now scans the containing module and extends the byte pattern past the stolen bytes until
  it matches only the hook site, so the generated `aobscanmodule(...)` finds exactly one
  address instead of the raw (possibly repeated) opcode bytes. The uniqueness search is a
  pure, unit-tested helper (`ce::shortestUniqueAobLen` / `ce::uniqueAobSignature`); it falls
  back to the raw bytes when the module can't be scanned. Asserted in `cecore_test`.
- **Memory Viewer address bar shows the location symbolically** (CE parity): after any
  jump the box reads `module+offset` (e.g. `libc.so.6+0x1234`) when the address is inside a
  mapped module, instead of a bare hex number, so you can see where you are at a glance. The
  symbolic form round-trips: pressing Enter on it navigates back to the same address.
  Off-module addresses (heap, stack, anonymous) still show as hex. Asserted in
  `gui_search_smoke`.
- **Structure Dissector resolves where pointer fields point** (CE Dissect Data): a pointer field
  now reads `-> module+0xoffset` when it lands inside a mapped module (e.g. `-> libgame.so+0x1234`)
  instead of a bare `-> 0xADDRESS`, so you can tell a pointer into game code/data from a heap
  pointer at a glance. Falls back to the raw address off-module.
- **Structure Dissector follows pointers on double-click** (CE Dissect Data spider):
  double-clicking a pointer field re-bases the dissector to the pointed-to structure, so
  you can walk a linked structure by clicking through it. Non-pointer cells still open the
  field-name dialog. Asserted in `gui_structdissect_smoke` (follows a real pointer, and a
  plain integer field does not follow).
- **Double-clicking a cheat-table Address browses it in the Memory Viewer** (CE parity):
  the viewer opens at that address and focuses the disassembler for code or the hex dump
  for data, with **Shift** forcing the disassembler and **Ctrl** forcing the hex dump. The
  pane-choice policy is a Qt-free helper (`core/memview_nav.hpp`), unit-tested in
  `cecore_test`; `focusPane` is asserted in `gui_search_smoke`.
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
  only the base's values were shown with the whole differing row tinted. Single-struct mode
  also gained a **live-change highlight**: a value that changes between refreshes paints
  red (like CE's Dissect Data and the hex pane), reset on a base-address change. Both are
  covered by the offscreen `gui_structdissect_smoke` in the CI mirror.
- **Structure Dissector Base and Compare addresses accept expressions**: both the base and
  the compare-address fields now take a CE-style expression (module+offset `game.exe+0x100`,
  pointer deref `[rax+8]`, decimal `#1234`) via the shared ExpressionParser, not just a bare
  hex address. Asserted in `gui_structdissect_smoke`.
- **Structure Dissector "Add All to List"**: after labelling a struct's fields (by hand or
  via Type as IL2CPP / C struct), one button adds every named field to the cheat table
  (base+offset, name, type) instead of adding them one at a time. Fields typed via Type-as
  now keep their **declared type** (float stays float, int32 stays int32) in the compare
  columns and when added to the list, rather than re-guessing from the bytes; the type is
  saved/loaded with the structure definition. Asserted in `gui_structdissect_smoke`.
- **Memory Viewer marks the current instruction** when the debugger is paused: the line at
  the stopped thread's RIP paints green with a ► marker, and the first open viewer follows
  execution. See the debugger notes below.
- **Debugger memory pane highlights changed bytes** as you step: bytes that differ from the
  previous dump at the same address paint red, so you can watch what the code writes (like
  the standalone hex pane). A new address resets the baseline. Asserted in
  `gui_debugger_smoke`.
- **F5 toggles a breakpoint** at the disassembly cursor in the debugger (adds one if none
  is there, removes it if there is), matching CE's debugger which already binds F7/F8/F9 to
  step-into/over/continue. Asserted in `gui_debugger_smoke`.
- **Fixed: debugger disassembly showed `int3` when stopped at a breakpoint.** A software
  breakpoint replaces the instruction's first byte with 0xCC; reading it back for the
  disassembly rendered `int3` and desynced the whole pane (it collapsed to a single line).
  Planted breakpoint bytes are now un-masked to their originals before disassembling, so the
  paused code reads as its real, correctly-aligned instructions. Asserted in
  `gui_debugger_smoke`.
- **Debugger disassembly keeps the caret on its instruction across re-renders**: toggling a
  breakpoint, stepping, or an auto-refresh no longer jerks the caret to the top of the pane
  (it is restored to the same address). Asserted in `gui_debugger_smoke`.
- **Debugger disassembly annotates data references**: a memory operand is resolved (via the
  disassembler's pre-computed effective address) to the symbol / module+offset it points at
  **and its current value** — sized by the operand's byte/word/dword/qword prefix, or shown
  as a quoted string when the target is printable text — as a `; -> name = value` /
  `; -> name "text"` comment. So you can see which global the paused code reads or writes and
  what it holds. Asserted in `gui_debugger_smoke`.
- **Debugger shows decoded CPU flags**: a "Flags:" line under the register table spells out
  the status/control flags set in RFLAGS (CF PF AF ZF SF TF IF DF OF), instead of leaving
  you to decode the raw hex. Backed by a Qt-free `ce::describeEflags()` unit-tested in
  cecore_test and asserted end to end in `gui_debugger_smoke`.
- **Debugger stack pane reads as a call stack**: stack slots whose value points into code
  (return addresses) are annotated with the **function name** (`func+0xNN` from the symbol
  table), falling back to "module+offset" when there is no symbol, so you can read the call
  chain instead of raw pointers. Asserted in `gui_debugger_smoke`.
- **Debugger disassembly is symbol-annotated**: a direct call/jmp shows its target's symbol
  and the current (`=>`) line shows the function it is stopped in, appended inline as a
  `; symbol` comment (so it never shifts the line/address mapping the breakpoint actions
  rely on). The current line also gets a **full-width background highlight** so the stopped
  location stands out at a glance. Both asserted in `gui_debugger_smoke`.
- **Disassembler multi-instruction selection**: Shift+Up/Down and Shift+click select a
  range of instructions (the whole range highlights), and Ctrl+C copies every selected line
  as a block. A plain move or click collapses back to a single line; right-clicking inside a
  range keeps it so the menu acts on the whole selection. The context menu is range-aware
  too: "Copy bytes", "Copy lines", and "NOP N instructions (M bytes)" all operate on every
  selected instruction. **Ctrl+A** selects every visible instruction (then Copy/NOP acts on
  the whole block). **Home/End** jump the cursor to the first/last visible instruction
  (Shift extends the range) and **Escape** collapses a range back to a single line.
  Covered by a new offscreen `gui_disasm_smoke` in the CI mirror.
- **Hex pane highlights changed bytes** (CE-style): bytes whose value differs from the
  previous refresh paint red across the hex and ASCII columns, so live-changing memory is
  obvious at a glance. Navigating to a new address resets the baseline (no false "changed"
  flash). Covered by a new offscreen `gui_hexview_smoke` in the CI mirror.
- **Paste bytes into the hex pane**: the right-click menu gains "Paste N bytes here" when
  the clipboard holds an array of bytes ("90 90 c3", "9090c3", or "?? c3" with wildcards),
  patching memory at the cursor so you can copy an AOB and paste it as a patch. Wildcards
  leave the existing byte untouched. **Ctrl+V** pastes and **Ctrl+C** copies the selected
  bytes as an AOB, from the keyboard. A **"Fill selection with…"** action writes one byte
  value across the whole selected range (e.g. 0x90 to NOP a region). **Shift+Left/Right**
  extends the byte selection from the keyboard, **Home/End** jump the cursor to the
  start/end of its row (Shift extends), and **Ctrl+A** selects every readable byte in the
  window. Asserted in `gui_hexview_smoke`.
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
