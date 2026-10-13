# Cheat Engine for Linux: guide for agents

A native Linux reimplementation of Cheat Engine in C++20/23, Qt6 and CMake,
with Capstone, Keystone, vendored Lua 5.3 and libdw. One repository with the
project at its root; `origin` is github.com/wleeaf/cheat-engine-linux, branch
`main`. MIT licensed. The aim is the best native Linux memory tool, not feature
parity with Cheat Engine on Windows.

## Layout

- `cecore`: the Qt-free backend shared library (`core/`, `scanner/`, `debug/`,
  `scripting/`, `arch/`, `symbols/`, `analysis/`, `platform/`).
- `cheatengine`: the Qt GUI (`gui/`). `cescan`: the CLI and `cescan lua`.
- Tests: `cecore_test` (main regression suite), `cecore_deep_test`, and the
  offscreen GUI smokes (`gui_*_smoke`). Live-target gates are `test/*_gate.py`.
- Docs: `docs/COMPATIBILITY.md` (feature by target), `docs/PROGRESS.md`
  (work log, newest first), `docs/COVERAGE_PLAN.md`, `docs/SCRIPTING.md`,
  `CHANGELOG.md`. The version is `project(... VERSION ...)` in `CMakeLists.txt`.

## Machine limits

This workstation has limited CPU and memory and its owner runs other work.
Build with one job at low priority (`nice -n 19 cmake --build build -j1`),
check `uptime` first and wait if the load is high, run one heavy thing at a
time, and never touch the user's own processes (for example their Wine
prefixes). Leave heavy work (Wine, VMs, cross builds, emulators) to CI.
Changing `CECORE_VERSION` or a widely included header rebuilds everything.

## Build, test, ship

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release && nice -n 19 cmake --build build -j1
./build/cecore_test
QT_QPA_PLATFORM=offscreen ./build/gui_lifecycle_smoke   # the broadest GUI test
```

- Run `tools/ci-check.sh --config` before every push. The CI `sanitizers` job
  has no Qt, so a target that links a library needs its own `find_package`.
- Watch CI after pushing (`gh run list`, `gh run view <id>`); cancel superseded
  runs. Known intermittent checks under ASan: `mt soft bp` and "step-over at a
  call breakpoint"; re-run the failed job once before investigating.
- `cmake --install build --prefix ~/.local` gives a self-contained app (RPATH
  `$ORIGIN`, bundled Capstone/Keystone, speedhack, docs, desktop file).
- Release: bump the version, add a `CHANGELOG.md` section and an AppStream
  `<release>` in `packaging/*.metainfo.xml`, then push a `vX.Y.Z` tag;
  `release.yml` uploads only the `.deb`, the AppImage and their checksums;
  test evidence stays on the workflow run as an artifact.
- Commit messages and PRs carry no AI attribution lines.

## GUI conventions

- GUI slots only gather input and call a shared cecore function, so everything
  stays scriptable from Lua and `cescan` and testable headlessly.
- Shared helpers live in `gui/theme.hpp`: `styleDataTable()` for read-only
  tables, `setEmptyHint()` for empty views, `makeTableFilter()`,
  `formatByteSize()`, `threadLabel()`, `monospaceFont()`, and `CodeEditor`
  (`gui/code_editor.hpp`) for editors with line numbers. Use them instead of
  styling widgets one by one.
- Fonts on item views must come from the theme sheet: set the `monospace`
  property, not `setFont()`; Qt's stylesheet engine drops widget fonts when it
  re-polishes a reparented widget. Mark the main action with the `primary`
  property. Avoid fixed point sizes; scale from `QApplication::font()`.
- The theme follows the desktop until Settings picks one (portal
  `color-scheme`), and on GNOME Wayland `main.cpp` turns `text-scaling-factor`
  into `QT_FONT_DPI` before the application starts.
- Menu items that open a window or dialog end in "...". Keep context menus to
  one column on a 1080p screen at large text sizes.
- Visual review: `QT_QPA_PLATFORM=offscreen build/gui_lifecycle_smoke
  --screenshots DIR` renders every window, menu and dialog in both themes
  (about 210 images). Add `QT_FONT_DPI=130` and
  `QT_QPA_PLATFORM=offscreen:configfile=...` with a 1920x1080 screen to check
  large text. Inspect them as contact sheets (`montage`), fix, and re-render.
  `docs/screenshot.png` is `readme-main.png` from a run with
  `CE_README_GAME` set to `test/readme_game.c` compiled as `game`.

## Safety rules

- Default-deny Lua: `shellExecute` and the `write*Local` functions stay disabled
  unless `CECORE_LUA_ALLOW_UNSAFE=1` is set outside the table. Table Lua and
  Auto Assembler scripts ask before running.
- Treat `.CT`, `.CETRAINER`, ELF and DWARF input as untrusted: bounds-check,
  cap sizes, sandbox and instruction-limit Lua conditions.
- No detection evasion or anti-cheat bypass features.
- Wine and Proton: never `PTRACE_SEIZE` or stop a whole thread group for a
  transient operation, and never hijack a syscall-parked thread with
  `PTRACE_ATTACH` (both deadlock the game). Use `PTRACE_SEIZE` plus
  `PTRACE_INTERRUPT`; arm hardware watchpoints on the main thread only; never
  use the software page guard on Wine. The full debugger and break-and-trace
  stop the whole process on purpose. WoW64 32-bit syscall results: only
  `[0xFFFFF001, 0xFFFFFFFF]` is `-errno`; zero-extend everything else.

## Diagnostics

`CE_LOG=debug`, per subsystem `CE_LOG=ptrace:trace`, and `CE_LOG_FILE=path`
enable logging without a rebuild. `CE_CODEFINDER_MODE=hw|sw|st` forces the
find-what-writes backend.

## Writing style

No em or en dashes as punctuation; use commas, colons, parentheses or separate
sentences. Keep comments and docs plain and specific.
