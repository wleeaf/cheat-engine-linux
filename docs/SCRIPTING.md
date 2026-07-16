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
| `getIl2CppMethods(class)` | `{ {name, rva, address}, ... }` for one class |
| `findIl2CppMethod(class, method)` | the live code address of one method, or `nil` |
| `getIl2CppStructure(class)` | the class as a dissector `StructureDefinition` |

`getIl2CppClassLayout` is the workhorse: one call resolves an entire class (or
every class matching a substring) against the binary in a single pass.

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
`static`, and `const`. Method entries carry `name` and `rva` (offset inside the
GameAssembly module); add the module base for a live address, or use
`findIl2CppMethod` which does that for you:

```lua
local addr = findIl2CppMethod("Player", "TakeDamage")   -- 0x7f... live address
```

See [`examples/il2cpp_dump.lua`](../examples/il2cpp_dump.lua) and
[`examples/il2cpp_hook.lua`](../examples/il2cpp_hook.lua).

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

See [`examples/reverse_engineer.lua`](../examples/reverse_engineer.lua).

---

## Running target code

`executeCode(address[, timeoutMs])` runs a `cdecl`, `ret`-terminated function on
a fresh thread in the target and waits (default 5000 ms) for it to finish,
returning `ok, err`. This is CE's `executeCodeEx`/`createThread`-with-wait: pair
it with the auto-assembler to allocate and populate a stub, then call it.

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
