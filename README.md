# Cheat Engine for Linux

A native Linux memory scanner, debugger, disassembler, and trainer toolkit, a from-scratch C++20/Qt6 reimplementation of [Cheat Engine](https://github.com/cheat-engine/cheat-engine). It talks to the kernel directly (`process_vm_readv`/`writev`, `ptrace`, `/proc`, an optional kernel helper) instead of running the Windows build under Wine, and it reads and writes Cheat Engine's `.CT` tables so you can bring your existing ones.

> ⚠️ **Early and immature.** This is a young project (v0.9.5) under active development. Expect bugs, rough edges, and missing pieces, it does not match Cheat Engine's breadth or maturity yet. Keep backups, use it only on software you're allowed to analyze, and please [report issues](../../issues); they're what drive it forward.

> **Scope.** Built for single-player games, reverse engineering, and learning. It is *not* designed to defeat multiplayer anti-cheat (EAC, BattlEye, Vanguard, and similar), which run kernel components and will detect this class of tool. Use responsibly.

The GUI, CLI, and Lua share a Qt-free backend, with regression suites, ASan/UBSan coverage, and 11 offscreen GUI checks in CI.

## New in 0.9.5

[Download v0.9.5](https://github.com/wleeaf/cheat-engine-linux/releases/tag/v0.9.5), or read the full [changelog](CHANGELOG.md).

- **Injection templates use the selected code.** Code, AOB, full-code, and pointer templates disassemble the injection site, preserve complete instructions, restore the exact original bytes, and use module-relative addresses or unique AOB signatures.
- **Consistent typed memory operations.** The GUI, CLI, and Lua share integer, pointer, floating-point, string, and byte-array handling. The CLI accepts unique process names and address expressions; scan results load incrementally and CSV export includes every match.
- **A more usable GUI.** Improved table widths, compact-window scrolling, light/dark contrast, live fonts and themes, toolbar overflow, process filtering, and settings behavior. Memory and register views show more useful information, and large form canvases scroll within the designer.
- **Deeper correctness fixes.** Scanning, snapshots, parsers, debugging, hooks, and Lua resource lifetimes have additional regression coverage.

<img src="artifacts/gui-review/after/dark-main-populated.png" alt="Dark-theme GUI with scan results and saved addresses, captured by the visual review fixture" width="960">

The [visual review captures](artifacts/gui-review) include both themes, compact layouts, and larger fonts. Open `artifacts/gui-review/index.html` locally for the before/after gallery.

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
- **Auto-assembler**: Cheat Engine compatible `alloc`/`globalalloc`, labels, symbols, `aobscanmodule`, data directives, `{$lua}` blocks, and site-specific code, AOB, full-code, and pointer injection templates.
- **Platform** — ceserver and GDB-remote clients for remote/cross-device debugging, an X11 click-through overlay, a pitch-preserving speedhack (`LD_PRELOAD`), and an optional `CAP_SYS_ADMIN`-gated kernel helper for privileged memory access.
- **Diagnostics** — `CE_LOG=debug` (or per-subsystem, e.g. `CE_LOG=ptrace:trace`) turns on runtime logging with no rebuild.

## Building

```bash
sudo apt install build-essential cmake ninja-build qt6-base-dev libcapstone-dev \
                 zlib1g-dev libdw-dev libasound2-dev libsoundtouch-dev \
                 linux-headers-$(uname -r)

cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

Capstone and Keystone are fetched and compiled automatically when no system copy is found; that first build needs network access, and subsequent builds reuse the cached sources. Lua 5.3 is vendored. Prebuilt `.deb` and AppImage packages are attached to each [release](../../releases).

Optional kernel helper:

```bash
make -C /lib/modules/$(uname -r)/build M="$PWD/kernel" modules
sudo insmod kernel/cecore_kmod.ko    # /dev/cecore ; sudo rmmod cecore_kmod to unload
```

## Running

```bash
sudo LD_LIBRARY_PATH=build build/cheatengine        # GUI
LD_LIBRARY_PATH=build build/cescan --help      # CLI scanner
CE_SPEED=2.0 LD_PRELOAD=build/libspeedhack.so ./game # speedhack (pitch-preserving)
```

`ptrace`-based attach needs sufficient privileges or a permissive `ptrace_scope`. The `.deb` grants `cap_sys_ptrace` during installation so no root is required. Source builds and AppImages need suitable ptrace permissions; the GUI offers a permission prompt when a target is not readable.

## Command-line reference

```text
cescan list                          List all processes
cescan scan <pid> [options]          Scan process memory
cescan read <pid> <addr> [size]      Hex dump memory
cescan write <pid> <addr> <val>      Write a typed value
cescan freeze <pid> <addr> <val>     Keep a value fixed; --count N limits the cycles
cescan autoasm <pid> <script.aa>     Run a script; --disable-after N restores it
cescan disasm <pid> <addr> [count]   Disassemble instructions
cescan modules|regions <pid>         List loaded modules / memory regions
cescan signature <pid> <addr> [max]  Generate a unique AOB signature
cescan analyze <pid> <what>          Static RE: strings|statics|caves|functions|xrefs|asm
cescan il2cpp <global-metadata.dat>  Browse Unity IL2CPP metadata (offline)
cescan lua <script.lua>|-e <code>    Run Lua (same API as the GUI console)
```

Common scan options: `--type byte|i16|i32|i64|float|double|string|aob|…`, `--value`/`--value2`, `--compare exact|greater|less|between|changed|…`, `--rounding`, `--previous <dir>`, `--writable`.

Targets accept either a PID or a unique process name. Ambiguous names report the matching PIDs. Host address arguments accept the same expressions as the GUI, including `module+0xoffset`, symbols, and `[pointer]+0xoffset`.

```bash
cescan read game 'game+0x120' --type u64
cescan write game '[game+0x120]+0x8' '2,5' --type float --verify
cescan write game 0x123400 '世界' --type unicode --be --terminate
cescan freeze game 0x123400 '90 48 8B' --type aob --count 20 --interval 50
cescan autoasm game patch.aa --disable-after 10
```

Typed reads, writes, and freezes support signed and unsigned integer aliases, target-width pointers, float/double, UTF-8, UTF-16 (`unicode`), code pages (`--encoding CP1252`), and concrete byte arrays. Integer overflow and malformed input produce errors before writing. `--terminate` appends the encoding's zero terminator to a string; raw writes omit it by default. Byte arrays accept spaces, commas, tabs, and line breaks. `write --verify` returns a failing exit status if the value changes, and `--find-writer` can investigate that change. `autoasm --disable-after` restores saved bytes and releases allocations after the delay or Ctrl-C.

The GUI loads more scan rows as you scroll and exports every stored match with **Save current scan results**. CSV values are quoted correctly; export can be canceled without replacing the destination file. UTF-8 address-list values display their full text, edits retain their new byte length, and shorter strings receive a zero terminator within their previous length. Clearing a string writes a zero terminator. Floating-point text preserves the stored value when written back.

## Scripting & reverse engineering

The Lua API (GUI console or `cescan lua`) also drives the static analysis stack:
IL2CPP (Unity) class/field/method resolution, DWARF struct typing, PE
export/import parsing, AOB signature generation, cross-references, and range
disassembly. See **[docs/SCRIPTING.md](docs/SCRIPTING.md)** for the reference and
runnable scripts in **[examples/](examples)**.

## Auto-assembler example

In the Memory Viewer, select the instructions to inject at and open **Tools > Auto Assemble**. Choose an injection template from **Templates**, or press **Ctrl+I** for code injection. The generated script uses that site's instructions, overwrite length, original bytes, and module context. AOB templates require a unique signature; ambiguous sites report an error.

The example below assumes a unique six-byte instruction in `game.bin`. Use the generated template for your actual target, then edit the code in `newmem`.

```asm
[ENABLE]
aobscanmodule(INJECT, game.bin, 8B 83 20 01 00 00)
assert(INJECT, 8B 83 20 01 00 00)
alloc(newmem, $1000, INJECT)
label(return)
newmem:
  mov eax, [rbx+0x120]   // original six-byte instruction
  mov eax, 999
  jmp return
INJECT:
  jmp near newmem       // five-byte jump
  nop                  // covers the remaining original byte
return:
registersymbol(INJECT)

[DISABLE]
INJECT:
  db 8B 83 20 01 00 00
unregistersymbol(INJECT)
dealloc(newmem)
```

## Development

```bash
./build/cecore_test              # regression suite
./build/cecore_deep_test         # deeper correctness and injection regressions
tools/ci-check.sh --config       # validate full and no-Qt configurations
CECORE_CI_JOBS=4 tools/ci-check.sh # build and test both configurations before pushing
./build/gui_lifecycle_smoke --screenshots /tmp/ce-gui-review # repeatable GUI captures
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
