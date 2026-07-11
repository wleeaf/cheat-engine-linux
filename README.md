# Cheat Engine for Linux

A Linux-native memory scanner, debugger, disassembler, and trainer toolkit inspired by [Cheat Engine](https://github.com/cheat-engine/cheat-engine).

This is a from-scratch implementation in modern C++ (C++20/23) with a Qt6 interface. It targets Linux directly through native kernel and userspace facilities (`process_vm_readv`/`writev`, `ptrace`, `/proc`, an optional privileged kernel helper) rather than running the Windows Cheat Engine under Wine. The result is a fast, native tool that mirrors Cheat Engine's workflow and file formats while fitting the Linux platform.

Roughly 40,000 lines of C/C++ across ~158 source and header files, exercised by a 229-assertion regression suite.

> **Scope.** cecore is intended for single-player games, reverse engineering, and learning. It is *not* designed to defeat multiplayer anti-cheat systems (EAC, BattlEye, Vanguard, and similar), which run their own kernel components and actively detect this class of tool. Please use it responsibly and only against software you are permitted to analyze.

---

## Highlights

- **Real-time results.** The scan-result and address lists refresh live from target memory, highlighting changed values as they move, the way Cheat Engine does.
- **Complete scan engine.** Exact / bigger / smaller / between / unknown-initial first scans, and changed / unchanged / increased / decreased / increased-by / decreased-by / same-as-first next scans, across every value type.
- **Full auto-assembler.** A Cheat Engine compatible assembler with `alloc`/`globalalloc`, labels, symbols, `aobscanmodule`, data directives, `readmem`/`reassemble`/`loadbinary`/`loadlibrary`/`createthread`, `{$try}/{$except}` blocks, and the standard code-injection templates.
- **Real debugger.** Hardware and software breakpoints with Lua conditions, hit counts, per-thread filters, one-shot mode, break-and-trace, and a full CPU register view on every hit.
- **Import-aware disassembler.** Capstone-backed disassembly with jump arrows, branch-target and cross-reference resolution, `@plt`/`@got` import naming, DWARF source lines, persistent user comments and labels, and full keyboard navigation.
- **Scriptable.** A Lua compatibility surface for memory access, scans, the address list, the disassembler, GUI dialogs, hotkeys, and timers.
- **Cheat Engine file formats.** Reads and writes `.CT` tables (XML), password-protected `.CETRAINER` payloads, and a native JSON format, and can emit standalone C trainers.

## Features

### Memory scanning
- Value types: byte, 2/4/8-byte integers, float, double, pointer, string (with iconv encodings), Unicode, array-of-bytes with per-nibble wildcards, binary bit patterns, all-types, grouped, and custom Lua-formula scans.
- Float scans match Cheat Engine's rounding modes (rounded to the entered precision, truncated, extreme tolerance, or exact).
- Region filters (writable / executable / private / image / mapped), configurable alignment, undo scan, and multi-threaded scanning with disk-backed result sets for very large scans.
- Pointer scanning with rescan against a re-randomized target and shardable (distributed) scans whose merged output equals a full scan.

### Memory editing
- Typed reads and writes, freeze with directional modes (locked, increase-only, decrease-only, never-increase, never-decrease), grouped and batch edits, and configurable value hotkeys (toggle, set-value, increase, decrease).
- Address-list records with descriptions, hierarchy/grouping, pointer expressions (`module+offset`, multi-level `[[base]+off]`), colors, dropdown lists, and hex display.

### Debugging and analysis
- Hardware (DR0-DR3) and software breakpoints, execute/read/write watchpoints, Lua break conditions (sandboxed and execution-bounded), break-and-trace, and exception breakpoints.
- "Find out what accesses / writes this address" with per-instruction hit counts and full register state.
- Code cave finder, cross-reference and call-graph discovery, structure dissection with type auto-detection and pointer following, and stack traces.

### Tables, trainers, and scripting
- `.CT` (Cheat Engine XML), `.CETRAINER`, and native JSON tables, with table-level and per-record Lua.
- Standalone C trainer generation and struct-to-C++ export.
- Managed-runtime support: Mono/CoreCLR detection, object and type enumeration, and a JIT-address method breakpoint bridge.

### Platform integration
- ceserver TCP client and a GDB remote client for remote and cross-device debugging.
- X11 click-through overlay (OSD/crosshair) and a Vulkan explicit-layer injection foundation.
- Pitch-preserving speedhack (`LD_PRELOAD`) and an audio companion.
- An optional, explicitly `CAP_SYS_ADMIN`-gated kernel helper for privileged process/physical memory access and virtual-to-physical translation.

## Building

### Dependencies (Ubuntu/Debian)

```bash
sudo apt install build-essential cmake qt6-base-dev libcapstone-dev \
                 zlib1g-dev libdw-dev linux-headers-$(uname -r)
```

Keystone (the assembler backend) is not packaged on most distributions. The build fetches and compiles it automatically when no system copy is found, so no manual step is normally required.

Lua 5.3 is taken from the adjacent Cheat Engine source tree:

```bash
cd "../Cheat Engine/lua53/lua53" && make linux MYCFLAGS="-fPIC" && cd -
```

### Compile

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

### Optional kernel helper

```bash
make -C /lib/modules/$(uname -r)/build M="$PWD/kernel" modules
sudo insmod kernel/cecore_kmod.ko    # loads /dev/cecore
# ... use ...
sudo rmmod cecore_kmod
```

## Running

```bash
# GUI
sudo LD_LIBRARY_PATH=build build/cheatengine

# CLI scanner
sudo LD_LIBRARY_PATH=build build/cescan --help

# Speedhack (2x, pitch-preserving)
CE_SPEED=2.0 LD_PRELOAD=build/libspeedhack.so ./game
```

`ptrace`-based attach usually requires elevated privileges or a permissive `ptrace_scope`. Test targets in this repository opt in with `PR_SET_PTRACER_ANY`.

## Command-line reference

```text
cescan list                          List all processes
cescan scan <pid> [options]          Scan process memory
cescan read <pid> <addr> [size]      Hex dump memory
cescan write <pid> <addr> <val>      Write a typed value
cescan disasm <pid> <addr> [count]   Disassemble instructions
cescan modules <pid>                 List loaded modules
cescan regions <pid>                 List memory regions
```

Common scan options:

```text
--type    byte|i16|i32|i64|pointer|float|double|string|unicode|aob|binary|all|grouped|custom
--value <v>   --value2 <v>
--compare exact|greater|less|between|changed|unchanged|increased|decreased|unknown|samefirst
--encoding <iconv-name>    --rounding exact|rounded|truncated|extreme
--percent <pct>   --percent2 <pct>   --previous <result-dir>   --writable
```

## Auto-assembler example

```asm
[ENABLE]
aobscanmodule(INJECT, game, 48 89 45 10)   // unique signature
alloc(newmem, $1000, INJECT)
label(return)

newmem:
  mov dword [rax+10], 999
  jmp return

INJECT:
  jmp newmem
return:
registersymbol(INJECT)

[DISABLE]
INJECT:
  db 48 89 45 10
unregistersymbol(INJECT)
dealloc(newmem)
```

## Testing

```bash
cmake --build build -j"$(nproc)"
./build/cecore_test        # 229 assertions
./build/cescan --help
```

## Architecture

```text
cecore/
├── analysis/        code analysis, managed-runtime helpers, structure tools
├── arch/            Capstone disassembler and Keystone assembler wrappers
├── cli/             cescan command-line tool
├── core/            types, auto-assembler, expressions, tables, trainers
├── debug/           breakpoint manager, debug session, tracing, GDB remote
├── gui/             Qt6 application windows, disassembler, and overlay
├── kernel/          optional cecore_kmod privileged helper
├── platform/        network compression, Vulkan layer helpers
├── platform/linux/  process API, ptrace, injector, ceserver, kernel client
├── plugins/         plugin loader, speedhack, audio companion
├── scanner/         memory scanner and pointer scanner
├── scripting/       Lua engine and bindings
├── symbols/         ELF/DWARF and kernel symbol resolvers
└── test/            regression harness
```

## Security and scope

- **Single-player focus.** cecore is a debugging and reverse-engineering tool. It does not attempt to evade multiplayer anti-cheat.
- **Kernel helper.** `kernel/cecore_kmod.c` is optional and exposes only explicit `CAP_SYS_ADMIN`-gated ioctls through `/dev/cecore` (process memory, physical memory via page-sized `ioremap` windows, virtual-to-physical translation). It does not hide modules, files, or sockets. An optional PID filter limits itself to `/proc/<pid>` directory listings.
- **Untrusted input.** The ELF/DWARF parsers, table loaders, auto-assembler, and Lua breakpoint conditions treat their input as untrusted: reads are bounds-checked, `.CETRAINER` loads are size-capped, and breakpoint conditions run in a sandboxed, execution-bounded Lua state.

## License

Inspired by [Cheat Engine](https://github.com/cheat-engine/cheat-engine) by Dark Byte. Review upstream licensing before distributing derived assets or compatibility data.
