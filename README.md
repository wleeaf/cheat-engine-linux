# Cheat Engine for Linux

A native Linux memory scanner, debugger, disassembler, and trainer toolkit, a from-scratch C++20/Qt6 reimplementation of [Cheat Engine](https://github.com/cheat-engine/cheat-engine). It talks to the kernel directly (`process_vm_readv`/`writev`, `ptrace`, `/proc`, an optional kernel helper) instead of running the Windows build under Wine, and it reads and writes Cheat Engine's `.CT` tables so you can bring your existing ones.

> ⚠️ **Early and immature.** This is a young project (v0.6.6) under active development. Expect bugs, rough edges, and missing pieces, it does not match Cheat Engine's breadth or maturity yet. Keep backups, use it only on software you're allowed to analyze, and please [report issues](../../issues); they're what drive it forward.

> **Scope.** Built for single-player games, reverse engineering, and learning. It is *not* designed to defeat multiplayer anti-cheat (EAC, BattlEye, Vanguard, and similar), which run kernel components and will detect this class of tool. Use responsibly.

~53k lines of C/C++ across ~200 files, with a ~320-check regression suite plus ASan/UBSan and offscreen-GUI smoke tests in CI.

---

## Performance

The fastest memory scanner on Linux. In a same-machine, same-target benchmark, a first scan for a value is about **2x faster than Cheat Engine 7.7** (the official native Linux build) and **30 to 40x faster than scanmem, GameConqueror, and PINCE**, with larger margins on some scans (up to ~13x vs Cheat Engine and ~145x vs scanmem).\*

| First scan, 1 GB, exact int32 | Time | Throughput |
|---|---:|---:|
| This project | **0.085 s** | ~12 GB/s |
| Cheat Engine 7.7 (native Linux) | 0.156 s | ~6.6 GB/s |
| gdb `find` | 0.749 s | ~1.4 GB/s |
| scanmem 0.17 / GameConqueror | 2.924 s | ~0.34 GB/s |
| PINCE (libmemscan) | 3.480 s | ~0.29 GB/s |

\* "Up to" figures are best cases (rounded-float and byte-pattern scans vs Cheat Engine; reserved/untouched memory vs scanmem); the typical first-scan lead over CE 7.7 is ~2x. One machine (Intel i5-10500H, 12 threads); Cheat Engine timed excluding its GUI startup (in its favor). GameConqueror uses scanmem's engine; PINCE uses its own Zig backend (libmemscan), benchmarked here on exact-value scans. Full numbers, methodology, and reproduction steps: **[BENCHMARK.md](BENCHMARK.md)**.

---

## Features

- **Scanning** — every value type (int/float/double, string with iconv encodings, array-of-bytes with wildcards, binary, grouped, custom-Lua); all Cheat Engine comparisons (exact/bigger/smaller/between/unknown → changed/unchanged/increased/decreased/by-N/same-as-first); CE float rounding modes; region filters; alignment; multi-threaded, disk-backed scans for huge targets; undo; and pointer scanning with rescan and shardable distributed scans.
- **Editing** — typed reads/writes, directional freeze (locked / increase-only / decrease-only / …), grouped and batch edits, value hotkeys, and address-list records with pointer expressions (`module+offset`, `[[base]+off]`), grouping, colors, and dropdowns.
- **Debugger** — hardware (DR0-DR3) and software breakpoints, data (write/access) watchpoints, **conditional breakpoints** (sandboxed Lua over register state), enable/disable and hit counts, break-on-exceptions, single-stepping, break-and-trace, register/stack/thread views, and "find what accesses / writes this address".
- **Disassembler** — Capstone-backed, with jump arrows, cross-reference and branch-target resolution, `@plt`/`@got` import naming, DWARF source lines, and persistent user comments and labels.
- **Mono / Unity dissector** — an injected in-process agent asks the Mono runtime for ground-truth class and field layout (real offsets, types, statics), browsable in the GUI (**Tools ▸ Mono dissector**) or from Lua (`monoDissect()`, `findMonoFunction()`). IL2CPP targets are detected.
- **Tables and scripting** — reads/writes CE `.CT` (XML), password-protected `.CETRAINER`, and native JSON; runs table Lua; generates standalone C trainers. A broad, CE-compatible Lua API (memory, scans, address list, disassembler, hotkeys, timers, hooks) that real cheat tables use.
- **Auto-assembler** — Cheat Engine compatible: `alloc`/`globalalloc`, labels, symbols, `aobscanmodule`, data directives, `{$lua}` blocks, and the standard code-injection templates.
- **Platform** — ceserver and GDB-remote clients for remote/cross-device debugging, an X11 click-through overlay, a pitch-preserving speedhack (`LD_PRELOAD`), and an optional `CAP_SYS_ADMIN`-gated kernel helper for privileged memory access.
- **Diagnostics** — `CE_LOG=debug` (or per-subsystem, e.g. `CE_LOG=ptrace:trace`) turns on runtime logging with no rebuild.

## Building

```bash
sudo apt install build-essential cmake qt6-base-dev libcapstone-dev \
                 zlib1g-dev libdw-dev linux-headers-$(uname -r)

cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

Keystone (the assembler backend) is fetched and compiled automatically when no system copy is found; Lua 5.3 is vendored, so the repo builds offline with no extra steps. Prebuilt `.deb` and AppImage packages are attached to each [release](../../releases).

Optional kernel helper:

```bash
make -C /lib/modules/$(uname -r)/build M="$PWD/kernel" modules
sudo insmod kernel/cecore_kmod.ko    # /dev/cecore ; sudo rmmod cecore_kmod to unload
```

## Running

```bash
sudo LD_LIBRARY_PATH=build build/cheatengine        # GUI
sudo LD_LIBRARY_PATH=build build/cescan --help      # CLI scanner
CE_SPEED=2.0 LD_PRELOAD=build/libspeedhack.so ./game # speedhack (pitch-preserving)
```

`ptrace`-based attach needs elevated privileges or a permissive `ptrace_scope`; the installed `.deb`/AppImage set `cap_sys_ptrace` so no root is required.

## Command-line reference

```text
cescan list                          List all processes
cescan scan <pid> [options]          Scan process memory
cescan read <pid> <addr> [size]      Hex dump memory
cescan write <pid> <addr> <val>      Write a typed value
cescan disasm <pid> <addr> [count]   Disassemble instructions
cescan modules|regions <pid>         List loaded modules / memory regions
cescan signature <pid> <addr> [max]  Generate a unique AOB signature
cescan analyze <pid> <what>          Static RE: strings|statics|caves|functions|xrefs|asm
cescan il2cpp <global-metadata.dat>  Browse Unity IL2CPP metadata (offline)
cescan lua <script.lua>|-e <code>    Run Lua (same API as the GUI console)
```

Common scan options: `--type byte|i16|i32|i64|float|double|string|aob|…`, `--value`/`--value2`, `--compare exact|greater|less|between|changed|…`, `--rounding`, `--previous <dir>`, `--writable`.

## Scripting & reverse engineering

The Lua API (GUI console or `cescan lua`) also drives the static analysis stack:
IL2CPP (Unity) class/field/method resolution, DWARF struct typing, PE
export/import parsing, AOB signature generation, cross-references, and range
disassembly. See **[docs/SCRIPTING.md](docs/SCRIPTING.md)** for the reference and
runnable scripts in **[examples/](examples)**.

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

## Development

```bash
./build/cecore_test              # regression suite
tools/ci-check.sh --config       # mirror CI locally before pushing (see docs/DEVELOPMENT.md)
```

```text
analysis/  code analysis, managed-runtime + Mono dissector       gui/       Qt6 app, disassembler, overlay
arch/      Capstone disassembler / Keystone assembler            kernel/    optional privileged helper
cli/       cescan command-line tool                              platform/  process API, ptrace, injector, ceserver
core/      types, auto-assembler, expressions, tables, hooks     plugins/   speedhack, mono agent, audio
debug/     breakpoints, debug session, tracing, GDB remote       scanner/   memory + pointer scanners
scripting/ Lua engine and bindings                               symbols/   ELF/DWARF + kernel symbols
```

## Security

- **Untrusted input.** ELF/DWARF parsers, table loaders, the auto-assembler, and Lua breakpoint conditions treat input as untrusted: reads are bounds-checked, `.CETRAINER` loads are size-capped, and conditions run in a sandboxed, execution-bounded Lua state. Only open `.CT`/`.CETRAINER` files you trust, a table's Lua/AA can manipulate the target, and running it prompts for confirmation. `shellExecute` and the unsafe file-write functions are default-denied.
- **Kernel helper.** `kernel/cecore_kmod.c` is optional and exposes only explicit `CAP_SYS_ADMIN`-gated ioctls through `/dev/cecore`. It does not hide modules, files, or sockets.

## License

MIT. Inspired by [Cheat Engine](https://github.com/cheat-engine/cheat-engine) by Dark Byte; review upstream licensing before redistributing derived assets or compatibility data.
