# Scripting the reverse-engineering toolkit

Everything the GUI does is a thin wrapper over a cecore function, so the same
work is fully scriptable from Lua, in the GUI's **Lua console** or headless via
`cescan lua <script.lua>` / `cescan lua -e "<code>"`. This guide covers the
static analysis and IL2CPP APIs added on top of the classic CE memory/scan/AA
bindings. Runnable versions of every snippet here live in [`../examples/`](../examples).

All of these functions operate on the **currently open process** (`openProcess`)
unless a file path is given, and they return `nil, "message"` on failure rather
than raising, so guard the result:

```lua
local layout = getIl2CppClassLayout("Player")
if not layout then print("no IL2CPP here"); return end
```

---

## Typed memory access

### CEServer targets

`connectToCeserver(host, port, pid [, timeoutMs])` opens a remote target and returns
its PID or `nil, error`. The optional positive millisecond transport budget defaults
to 5000. For a slow connection, choose a larger budget:

```lua
local pid, err = connectToCeserver("127.0.0.1", 52736, 1234, 15000)
assert(pid, err)
```

The budget covers one complete command, including its header and payload, instead
of restarting for each arriving byte. Debug-event waits additionally allow their
requested wait duration. A failed connection preserves the previously opened
process. Port, PID and timeout values are checked before any network request.
The same function works in the GUI Lua console and in `cescan lua` scripts.
System hostname resolution can still outlive this socket budget.

### GDB / QEMU targets

Connect to a stopped stub using an endpoint instead of a local process ID:

```lua
local ok, err = connectToGdb("127.0.0.1", 1234, {
  byteOrder = "little",
  pointerWidth = 8,
  timeoutMs = 2000,
  regions = {{base=0x40000000, size=0x1000}}
})
assert(ok, err)
print(getTargetInfo().program.architecture, getTargetInfo().transport)
local original = assert(readGdbRegister("v0"))
assert(#original == 16)
assert(writeGdbRegister("v0", original))
assert(disconnectProcess())
```

The example range and `v0` register apply to an ARM64 QEMU `virt` CPU. Use the
actual target's addresses, data format and register names. All options are
optional: omitted ranges use the stub's memory map, and omitted data order or
pointer width retain XML-derived metadata (possibly unknown). `byteOrder` accepts
`little`, `big`, or `unknown`; `pointerWidth` accepts 4 or 8; `timeoutMs` is a
socket transaction timeout from 1 to 60000 milliseconds. System DNS resolution
uses the system resolver and can take longer. Regions are scan/map declarations,
not an access-control boundary for explicit reads or writes.

`connectToGdb` returns `true` or `nil, error`; a failed connection preserves the
existing target. `getGdbRegisterInfo()` returns an array of `{name,bits,number,type}`
from the stub's XML. Register reads return binary strings of the described width;
writes require that exact width. Unavailable registers return `nil, error`, never
invented zeros. `disconnectProcess` returns `true` or `nil, error`, clears the Lua
target and rejects stale accesses. A successful detach normally resumes the stub.

When the stub reports individual-register packets as unsupported, the shared
client uses its XML layout to read or edit the whole register bank. Wire fields
follow increasing register numbers, including sparse or out-of-order XML.
Each edit rereads the bank and preserves its other known bytes. Missing trailing
registers remain unavailable. Whole-bank writes are rejected when they cannot
preserve an unrelated unavailable field or exceed the negotiated packet size;
errors and malformed individual replies never trigger a fallback write.

The GUI's File connection action points the shared console at its GDB target.
Calling `connectToGdb` inside Lua selects the Lua engine's target; it does not
retarget the main GUI. Raw bytes and supported guest disassembly remain available
when data byte order is unknown. Typed access needs known data order and pointer
width. Numeric, pointer and Unicode scans follow the program's data format; raw byte
scans remain available when that format is unknown. This transport does not yet implement logical guest
process selection, MMU translation, native allocation/injection, or a full
`DebugSession`.
Host-only `pause`/`unpause` return `false` for remote or exited targets;
`getProcessDir` returns an empty string, and `branchMap` returns `nil, error`.
Remote identifiers cannot select a frontend-host process or perf sampler.

### Memory scans and captured values

`createMemScan()` uses the selected program's data byte order and pointer width,
including big-endian data and four-byte pointers on a 64-bit CPU. Its methods are
`firstScan(scanType, valueType, value[, start, stop, alignment, stringEncoding, format])`
and `nextScan` with the same arguments. Bounds default to the frontend's full
address range. `stop` is the inclusive last byte; the complete value must fit
inside either scan's range. Narrowed next-scan bounds exclude old rows before
reading target memory.
The optional `format` table accepts `byteOrder="auto"|"little"|"big"` and
`pointerWidth=4|8`. This permits known encoded data independently of the CPU ABI.
Custom formulas using the pointer value type also use that chosen width.
Unknown formats require an explicit choice for numeric or pointer scans;
raw byte patterns retain their normal behavior. Invalid values/options return
`false, error` and preserve the previous successful result.

```lua
local scan = createMemScan()
local format = {byteOrder="big", pointerWidth=4}
assert(scan:firstScan(0, 2, "0x12345678", 0x1000, 0x1003, 1, nil, format))
for i=0,scan:getFoundCount()-1 do
  print(string.format("0x%x",scan:getAddress(i)),scan:getValue(i))
end
assert(scan:nextScan(7, 2, "0", 0x1000, 0x1003, 1, nil, format))
print(scan:getValue(0),scan:getValue(0,true))
```

Here scan type `0` is exact, `7` is changed, and value type `2` is a four-byte
integer (`13` selects pointers). Result indexes start at zero.
`getValue(index[, first[, valueType]])` decodes saved sample bytes without rereading the
process; `first=true` returns the original first-scan sample. It returns a string,
or `nil` for an absent row; decoding/backing-file errors return `nil, error`.
Grouped, custom, binary and all-type samples display their raw hexadecimal bytes.
All scans (`valueType=10`) retain the numeric types that matched at each address.
Subsequent All scans compare those types numerically and remove failing candidates;
they cannot introduce a type that failed an earlier scan. Short readable fields
remain valid when adjacent bytes become unreadable. Displayed hex bytes cover
only the widest surviving candidate, excluding saved-record padding.
`getValueTypes(index)` returns an array of surviving type codes: `0` byte,
`1` two-byte integer, `2` four-byte integer, `3` eight-byte integer, `4` float,
and `5` double. Pass one of those codes as the third `getValue` argument to decode
that candidate, for example `scan:getValue(0, false, 4)`. A next scan can also
select a concrete surviving numeric type, producing ordinary typed results.
All values use one strict parser across GUI, CLI and Lua. Decimal and scientific
notation, a comma decimal separator, signs and `0x` hexadecimal values are
accepted. Fractional integer boundaries remain exact, including values near
64-bit limits; invalid tokens return an error instead of scanning a truncated
prefix or zero. GUI rounding precision includes the exponent. `inf`, `-inf` and
`nan` describe floating values; NaN never compares equal and creates no integer
candidate. Numeric input outside the parser's double range is rejected.
Float and Double scans use the same strict floating parser and retain scientific
notation's decimal precision across GUI, CLI and Lua. The optional format fields
`rounding="exact"|"rounded"|"truncated"|"extreme"` and `tolerance` apply to
Float, Double and All scans. Exact compares at the stored type's precision;
Rounded uses half a decimal place from the original input; Truncated compares
integer parts; Extreme compares absolute differences with the supplied tolerance.
Rounded, Truncated and Extreme retain the original search value rather than
narrowing it to a float first. Tolerance must be finite and nonnegative;
zero selects the automatic tolerance. Invalid options preserve the last result.

For any ordinary numeric Between scan, including integer, pointer, Float,
Double and All, put the upper value in `format.value2`:

```lua
assert(scan:firstScan(1, 10, "1.5", start, stop, 1, nil, {value2="2.5"}))
assert(scan:firstScan(0, 4, "1e-1", start, stop, 1, nil, {rounding="rounded"}))
assert(scan:nextScan(0, 4, "0.1", start, stop, 1, nil,
                    {rounding="extreme", tolerance=0.05}))
```

Here scan type `1` is Between. Both bounds are required and can be reversed.
Comparisons that do not use a search value ignore the value text.
Worker allocation/backend failures return `false, error` after worker cleanup.
The previous successful scan remains available, so the same scan object can retry
once the failure is resolved. Failed operations attempt to remove their partial
result files without hiding the original error if cleanup itself fails.
Percentage comparisons use their percentage thresholds independently of ordinary
All search bounds. CLI `--percent` and `--percent2` require finite numeric values;
`--percent2` requires `--percent`.
Legacy All snapshots without candidate metadata require a fresh All first scan;
their original matching types cannot be recovered from raw bytes alone.
Keep explicit format options on subsequent scans of manually encoded data.
Automatic next scans reject byte-order or pointer-width changes from the captured
format; changing an ordinary typed result's record width requires a fresh first scan.
GUI scan format controls use the same backend options. Results added to the
address list retain their captured encoding for the record's live value, edits
and freezing, including Lua reads of that GUI memory record's value. Table
formats persist `dataByteOrder` (`little`/`big`, absent means Auto) and
`pointerWidth` (`4`/`8`, absent or zero means Auto); XML tables use the
`LinuxDataByteOrder` and `LinuxPointerWidth` extension tags. These describe value
bytes; pointer-chain address expressions continue to use the selected target's ABI.

### Program data format

Target-aware reads and writes use the selected program's pointer width and byte
order. This can differ from its Unix loader under WoW64. An explicit
`{bigEndian=false}` or `{bigEndian=true}` overrides detection.

```lua
local target = getTargetInfo()
print(target.program.architecture, target.program.pointerWidth, target.program.byteOrder)
print(target.host.abi, target.transport)
local features = getTargetCapabilities()
print(features["hardware watchpoint"].state, features["hardware watchpoint"].reason)
```

Capability states describe backend availability. Permissions and changing memory
mappings are checked when an operation runs. See the [compatibility matrix](COMPATIBILITY.md).

`getTargetInfo().pendingRecovery` reports pending native syscall/call restoration,
private-frame cleanup or active Lua debugger-session recovery.
`retryPendingOperations()` retries those owners and returns `true` after recovery, or
`nil, error`. Native allocation/protection/free share one ptrace owner thread and
retry automatically; a failed caller or a new handle does not discard its recovery
record. Shutdown waits for verified restoration before that owner exits.

An interrupted native call retains its code, stack and owner until it actually
returns and restoration succeeds. `resumePendingCallSignal(deliver)` explicitly
continues a call stopped on a genuine signal, delivering it when `deliver` is
`true`, or suppressing it when `false`. It returns `true` on completed recovery,
or `nil, error` while recovery remains pending. Suppressing a synchronous fault
can fault again at the same instruction; it does not turn that fault into a return.

`debug_removeBreakpoint(id)` returns `nil, error` if cleanup fails and retains its
bookkeeping for retry. A previously removed session breakpoint can be removed
again after automatic recovery. When the process executes a replacement program,
the event pump clears its old breakpoint list, calls `debugger_onProcessExecuted()`
if defined, and resumes the replacement. Events from an older memory image cannot
apply their register edits to the new program.
An ordinary signal that interrupts stepping stays stopped while breakpoint code
is restored. The pump calls `debugger_onSignalReceived()` if defined and exposes
its number as `DebugSignal`, then resumes with the original signal delivery.
If the selected task exits while stepping and another thread survives, the pump
calls `debugger_onThreadExiting()` if defined. `DebugExitingThread` identifies the
departing task; the register globals describe the real selected survivor. The
pump does not apply register-global edits from this notification, then resumes
the remaining group. Failed exit-stop detach retains recovery on its original
owner until retry succeeds.

`readValue(address, type[, options])` returns a text value, or `nil, error`.
`writeValue(address, type, value[, options])` returns `true, bytesWritten`, or
`false, error`. Both accept numeric addresses and GUI address expressions.
Text preserves every bit of unsigned 64-bit integers; use decimal or hex strings
when a value exceeds Lua's integer range.

```lua
assert(openProcess("game"))
local slot = "[game+0x120]+0x8"
local ok, bytes = writeValue(slot, "u64", "18446744073709551615", {
  bigEndian = true,
  codec = "xor:0x25"
})
assert(ok, bytes)
local value, err = readValue(slot, "u64", {bigEndian=true, codec="xor:0x25"})
assert(value, err)
print(value)
assert(writeValue(0x123400, "unicode", "世界 😀", {terminate=true}))
```

Types include `byte`/`i8`/`u8`, `i16`/`u16`, `i32`/`u32`, `i64`/`u64`,
`pointer`, `float`, `double`, `string`/`utf8`, `unicode`/`utf16`, and `aob`.
Options are `hex`, `signed`, `bigEndian`, `codec`, `encoding`, `size`, and
`terminate`. The default string read size is 64 bytes; array reads use `size`
as their exact byte count. The pointer width follows the target. `terminate`
is false by default. `unicode` follows `bigEndian`; `string` uses `encoding`
(default UTF-8). Write values may be strings or numbers. Byte arrays contain
concrete hex bytes separated by whitespace or commas.

Auto Assembler supports nested `{$if expression}`, `{$else}`, and `{$endif}`
blocks. Conditions use Lua truthiness, including truthy zero and empty strings.
Inactive branches do not evaluate their conditions or execute embedded
`{$lua}`/`{$ccode}` blocks. Active Lua blocks run in source order, so later
conditions can use variables defined by earlier blocks. The CLI runs these
scripts through `cescan autoasm <target> <file.aa>`.

Module expressions in Auto Assembler use the selected process's current module
snapshot for each execution, including after `exec`. Removed modules no longer
resolve merely because the same assembler previously saw them. Explicitly
registered symbols take precedence over module names and retain their cleanup
ownership; unregistering them exposes the current module again. Syntax-only
checking has no process snapshot and preserves explicit symbols.

The Auto Assembler's injection templates use the live disassembler selection.
Code, AOB, Full, and Pointer injection prompt with its module offset already
filled in. Addresses, quoted module offsets, and symbol expressions are accepted.
Selected instruction ranges are preserved; shorter selections expand to whole
instructions covering the five-byte hook. Generated scripts contain editable
original instructions, a byte assertion, exact disable bytes, and a disassembly
snapshot. Relative branches and RIP-relative operands are relocated into the cave.
AOB templates require a verified unique signature. Pointer templates capture a
chosen target-sized register into the registered `pPlayerBase` symbol.

`reassemble(address)` emits the source instruction at the current assembly
address. ARM64 uses its original bytes to preserve ADR/ADRP addresses, live
literal addresses and relative branch targets; following labels account for
expanded instructions. A source whose output size changes after label sizing
fails with rollback; same-size updates remain usable. An unreadable/invalid
source or a relocation requiring
unapproved register clobbers/indirect branches fails with rollback of earlier
writes. Native ARM64 executable-page writes use the shared kernel cache adapter,
as do `nopInstruction` and its `writeBytes` undo. NOP encoding follows the actual
instruction ISA: x86 uses `90`, ARM64 uses `1F 20 03 D5` on aligned four-byte
instructions. Other transports/ISAs need their own code-cache adapter. The caller
still coordinates execution and mapping lifetime for edits spanning multiple
instructions; native ARM64 hook templates remain pending.

Auto Assembler `nop` emits one instruction for the selected code architecture;
`nop 3` emits three complete NOP instructions (three bytes on x86, twelve on
ARM64). Forward-label sizing uses that same encoding. Misaligned ARM instructions,
negative/trailing counts, overflowing ranges and buffers above 256 MiB fail
before mutation. `loadbinary` uses the same destination-aware patch path.

---

## Mono dissection

`monoDissect([timeoutMs])` returns a fresh `{ready, error, images}` view from the
target's Mono runtime, including field types, offsets and static flags. Repeated
calls reuse the resident agent and enumerate currently loaded assemblies.
Request, runtime and injection errors appear in `error` with `ready=false`;
missing targets or agents return `nil` and a message. The default timeout is
10 seconds. `findMonoFunction(namespace, class, method[, parameterCount])`
returns the runtime's native JIT address for that exact method, or `nil` when
unavailable. Negative parameter count `-1` accepts any overload. Long CLR names
are preserved rather than truncated to a fixed 255-byte field.

Initial injection requires the native loader/call backend and ptrace permission.
Native Mono `.exe` assemblies retain their Unix pointer and execution ABI.
The agent uses a separate connection for each request and finishes its runtime
thread before replying. Host access follows the target's PID and mount namespaces;
an agent exposed by a bind mount is resolved only after file identity matches.
Other filesystem layouts require the agent to be accessible inside the target.
The installed agent is located beside the loaded engine library, including
custom library directories. Metadata beyond the 64 MiB response cap returns a
clear error; subsequent method lookups can still succeed.
Privately loaded Mono libraries are supported without changing their symbol
visibility. Requests borrow the runtime library only while its API is in use.
After runtime cleanup or library unload, dissection reports an unavailable
runtime and method lookup returns no address. Invalidated process handles are
rejected before dispatching a request.
Returned raw object/code addresses still need runtime lifetime coordination for
GC movement, domain unloading and JIT replacement.

## IL2CPP (Unity) dissection

Unity's IL2CPP backend compiles C# to native code and strips the managed
metadata into a `global-metadata.dat` file next to the `GameAssembly` module.
cecore parses both, entirely offline (no runtime hooks, works on Proton/Wine
targets), to recover class layouts, field offsets, value types, and method code
addresses. Metadata versions **27-31** are supported.

| Function | Returns |
|---|---|
| `getIl2CppMetadataPath()` | path to the located `global-metadata.dat`, or `nil` |
| `getIl2CppClasses([path])` | offline metadata view: `{version, decoded, classes = { {image, namespace, name, fullName, fields = {"name",…}} }}` (names only, no offsets) |
| `getIl2CppClassLayout(filter)` | full layout for classes whose `fullName` matches the substring: fields (offsets/types) **and** methods (rva) |
| `getIl2CppObjectLayout(class)` | one class's **complete** instance layout: own fields **plus every inherited field** (walking the base chain), each tagged with `declaringType` |
| `getIl2CppMethods(class)` | `{ {name, rva, address}, ... }` for one class |
| `findIl2CppMethod(class, method)` | the live code address of one method, or `nil` |
| `getIl2CppStructure(class)` | the class as a dissector `StructureDefinition` |

`getIl2CppClassLayout` is the workhorse: one call resolves an entire class (or
every class matching a substring) against the binary in a single pass. Each class
also carries `parent` (its base class's full name, e.g. `UnityEngine.Component`).

```lua
for _, c in ipairs(getIl2CppClassLayout("UnityEngine.Vector3")) do
  print(c.fullName)                                  -- "UnityEngine.Vector3"
  for _, f in ipairs(c.fields) do
    print(string.format("  +0x%X %s", f.offset, f.name))   -- +0x0 x, +0x4 y, +0x8 z
  end
  for _, m in ipairs(c.methods) do
    print(string.format("  method rva=0x%X %s", m.rva, m.name))
  end
end
```

Field entries carry `name`, `offset` (byte offset inside the object),
`static`, `const`, and `typeName`, the resolved managed type (`System.Single`,
`UnityEngine.Vector3`, `System.String`, `List\`1<System.String>`,
`Dictionary\`2<System.String, System.TimeZoneInfo>`, `MyClass[]`, …), read offline
from the binary's `Il2CppType` table with generic arguments spelled out. Method
entries carry `name` and `rva` (offset inside the GameAssembly module); add the
module base for a live address, or use `findIl2CppMethod` which does that for
you:

```lua
local addr = findIl2CppMethod("Player", "TakeDamage")   -- 0x7f... live address
```

`getIl2CppClassLayout` lists a class's **own** fields. To overlay a live object
you usually want its **full** layout, including inherited fields, from
`getIl2CppObjectLayout`:

```lua
local o = getIl2CppObjectLayout("Enemy")     -- Enemy : Character : Entity
for _, f in ipairs(o.fields) do              -- own + inherited, sorted by offset
  local from = f.declaringType ~= o.class and ("  (from " .. f.declaringType .. ")") or ""
  print(string.format("  +0x%X %s %s%s", f.offset, f.typeName, f.name, from))
end
```

See [`examples/il2cpp_dump.lua`](../examples/il2cpp_dump.lua) and
[`examples/il2cpp_hook.lua`](../examples/il2cpp_hook.lua). The CLI mirrors this
offline (no attach needed), straight from a `global-metadata.dat`:

```sh
cescan il2cpp <global-metadata.dat> --class Player --fields   # offsets + managed types
cescan il2cpp <global-metadata.dat> --object Player           # full inherited object layout
```

### Turning a class into a dissectable structure

`getIl2CppStructure` returns the class as a `StructureDefinition` (the same type
the GUI's Structure Dissector uses), so you can overlay it on a live object
address, walk instance fields with their resolved value types, and read them.
Statics and constants are dropped (they are not part of the instance).

---

## Native structs from DWARF

The native analog for C/C++ targets built with debug info (`-g`): recover struct
layouts from DWARF and lay them over live memory.

| Function | Returns |
|---|---|
| `listDwarfStructs([elfPath])` | `{ "GameState", "Entity", ... }` |
| `getDwarfStructure(name[, elfPath])` | `{name, size, fields = { {name, offset, size, type, typeName} } }` |

`typeName` is a short cecore value-type name (`int32`, `float`, `pointer`, …)
resolved through typedef/const/pointer/array chains, so you can pick the right
`read*` for each field. See [`examples/native_struct.lua`](../examples/native_struct.lua).

---

## PE modules (Wine / Proton)

Windows games under Proton map real PE modules (`GameAssembly.dll`,
`UnityPlayer.dll`, …). cecore parses their export and import tables so you can
resolve a function by name to a live address (an ideal hook target), or find
which IAT slot a module uses to reach an imported API.

| Function | Returns |
|---|---|
| `getModuleExports(nameOrPath)` | `{ {name, ordinal, rva, address, forward?}, ... }` |
| `getModuleImports(nameOrPath)` | `{ {dll, name, ordinal, iatRva, iatAddress}, ... }` |

`address` is the live VA (module base + rva); `iatAddress` is the live address
of the import's IAT slot. Exported symbols are also folded into the normal
symbol resolver, so `getAddress("GameAssembly.dll+il2cpp_domain_get")`-style
lookups work too.

```lua
for _, e in ipairs(getModuleExports("GameAssembly.dll")) do
  if e.name == "il2cpp_runtime_invoke" then print(string.format("0x%X", e.address)) end
end
```

---

## Reverse engineering

Static helpers that read and disassemble the target without running its code.

| Function | Returns |
|---|---|
| `createSignature(address[, maxBytes])` | `pattern, unique` — an AOB signature, wildcarded and grown until unique |
| `findReferences(address)` | `{ {address, target, type, text}, ... }` — static xrefs (calls, jumps, lea/mov rip-rel) |
| `enumerateFunctions([module])` | `{ {address, references}, ... }` — candidate function entry points |
| `buildCallGraph([module])` | `{ {caller, callee, callSite}, ... }` — static call edges |
| `findReferencedStrings([module])` | `{ {address, target, text}, ... }` — string literals the code points at (find code by its UI text) |
| `findStatics([module])` | `{ {address, references}, ... }` — global addresses the code touches, hottest first |
| `findCodeCaves([module[, minSize]])` | `{ {address, size}, ... }` — padding runs usable to host injected code |
| `findAssemblyPattern(asm[, module])` | `{ {address, text}, ... }` — every place the assembled instruction's bytes occur (instruction-level AOB) |
| `disassembleRange(address, count)` | `{ {address, size, text, ripTarget?}, ... }` |

```lua
-- A relocatable signature for a scan hit, so it survives ASLR / a restart.
local sig, unique = createSignature(0x7f1234560000)
print(sig, unique and "unique" or "NOT unique")

-- What calls this function?
for _, r in ipairs(findReferences(funcAddr)) do
  print(string.format("%s @0x%X  %s", r.type, r.address, r.text))
end
```

See [`examples/reverse_engineer.lua`](../examples/reverse_engineer.lua). The same
toolkit is on the CLI without writing Lua:

```sh
cescan analyze <pid> strings              # referenced string literals
cescan analyze <pid> statics              # hot global addresses
cescan analyze <pid> functions            # function entry points
cescan analyze <pid> xrefs 0x<addr>       # what references an address
cescan analyze <pid> asm "call rax"       # every match of an assembled instruction
cescan analyze <pid> caves 64 --module GameAssembly.dll
```

---

## Running target code

`executeCode(address[, timeoutMs])` runs a function on a fresh native pthread in
the target and waits (default 5000 ms) for it to finish. Its entry point must be
executable and use the target's native pthread entry ABI: SysV AMD64, i386 cdecl,
or AAPCS64. It receives a null argument. Returning normally or calling
`pthread_exit` ends the worker.
Successful completion returns `true`; errors return `nil, error`.
Timeout values must be integers between 0 and `INT_MAX` milliseconds.
At the deadline a timeout error is returned. The detached thread can still run.
The owner tracks its actual Linux thread ID and retains its entry mapping until
kernel exit. Auto-assembler workers also retain their script allocations, saved
patches and page protections. Disabling or rolling back such a script reports
that the thread is still running and preserves cleanup information for retry.
Keep additional caller-owned data alive until the thread exits; the owner cannot
infer arbitrary addresses referenced by a function.
Pair this API with the auto-assembler to allocate and populate a stub, then call it.

`injectLibrary(path)` loads a native shared library through the same call owner.
It resolves target loader symbols itself when no external resolver is installed.
Both operations currently need an eligible native user-mode thread; a wholly
syscall-parked process is rejected without changing its original wait.

```lua
-- (after an AA [ENABLE] block allocated `mycode` as a ret-terminated stub)
local ok, err = executeCode(getAddress("mycode"), 3000)
```

---

## Where the boundary is

These are **static** and **read/exec** primitives: metadata parsing, table
resolution, disassembly, signatures, and thread-based code execution. Live
hooking, stepping, and breakpoints are the debugger API (`debug_*`,
`createSimpleHook`) documented alongside the classic CE bindings. Nothing here
does anti-cheat evasion, and it will not (out of scope, see the project README).

The standalone CLI assembler accepts `--origin <address>` to encode branches and
memory references at their intended execution address. For example,
`cescan asm "call 0x401100" --origin 0x401000` emits a call from `0x401000`.
X64 numeric memory destinations and explicit `[rel 0xADDRESS]` operands are
verified against the emitted instruction, including multiline blocks with labels.
