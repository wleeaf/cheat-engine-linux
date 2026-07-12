# Contributing

Thanks for your interest. This is a Linux-native reimplementation of Cheat
Engine in C++20 / Qt6 / CMake. It is single-player / reverse-engineering focused
and does not target multiplayer anti-cheat.

## Build

```bash
sudo apt install build-essential cmake ninja-build qt6-base-dev \
                 libcapstone-dev zlib1g-dev libdw-dev linux-headers-$(uname -r)
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

Lua 5.3 is vendored under `third_party/lua`; Keystone is fetched and built
automatically. Optional features (`libtcc-dev`, `libasound2-dev` +
`libsoundtouch-dev`, CUDA) are auto-detected.

## Run

```bash
sudo LD_LIBRARY_PATH=build build/cheatengine     # GUI
build/cescan --help                              # CLI scanner
```

`ptrace` of another process needs permission: either run as root, set
`/proc/sys/kernel/yama/ptrace_scope` to `0`, or have the target call
`PR_SET_PTRACER`.

## Tests — and how CI gates

- `build/cecore_test` — the main suite. **It now exits non-zero if any check
  prints `FAILED`**, and CI enforces that. When you add a test, print a line
  containing `OK` or `FAILED` (see existing tests); a `FAILED` fails the build.
- `sudo build/scan_test` — cross-process scan/write (root-gated).
- `build/gui_debugger_smoke` — offscreen Qt smoke test for the debugger window.
- **Sanitizers:** `cmake -B build-asan -DCECORE_SANITIZE=ON && cmake --build
  build-asan --target cecore_test && ./build-asan/cecore_test`. CI runs this too.
  Tests that deliberately fault or inject code are guarded by
  `#ifndef __SANITIZE_ADDRESS__`.

Please add a regression test for any bug fix or new feature where practical.

## Code layout

```
core/       types, autoassembler, expression, cheat tables (.CT)
platform/   process access (process_vm_readv, ptrace, /proc), injector
arch/       assembler (Keystone), disassembler (Capstone)
scanner/    memory scanner, pointer scanner
symbols/    ELF + DWARF resolvers
debug/      debug session, breakpoints, tracer, code finder, LBR
scripting/  Lua engine + bindings
analysis/   code analysis, managed-runtime detection
gui/        Qt6 windows
plugins/    speedhack, audiohack, Vulkan overlay, plugin ABI
```

`ROADMAP.md` tracks the current gaps and priorities; `FEATURE_GAP.md` tracks
CE-tutorial parity.

## Style

Match the surrounding code (comment density, naming, idiom). No em dashes in
comments. Keep the build warning-clean (`-Wall -Wextra` are on; no `-Werror`
yet, but don't add new warnings).

## Security

This tool reads/writes other processes' memory and is often run as root. Do not
add script surfaces that execute code or dereference untrusted pointers without a
gate (see `SECURITY.md`; e.g. `shellExecute` is default-denied). Report
vulnerabilities privately per `SECURITY.md`.
