# Cheat Engine for Linux — project guide

Native Linux reimplementation of Cheat Engine in **C++20/23 + Qt6 + CMake**
(Capstone, Keystone, vendored Lua 5.3, libdw). Single repo, project at the root
(no `cecore/` subdir), `origin` = github.com/wleeaf/cheat-engine-linux, branch
`main`. Free and open-source (MIT), no monetization; the goal is to be the best
**native Linux** memory tool, not to out-feature CE on Windows.

## Layout
- **`cecore`** — the Qt-free backend shared lib: `core/` `scanner/` `debug/`
  `scripting/` `arch/` `symbols/` `analysis/` `platform/`.
- **`cheatengine`** — the Qt GUI (`gui/`). **`cescan`** — CLI + `cescan lua`
  runner. **`cecore_test`** — regression suite. **`gui_debugger_smoke`** /
  **`gui_theme_smoke`** — offscreen Qt tests.
- Status / roadmap / CE-gap analysis: **`docs/DEVELOPMENT.md`**. Release notes:
  `CHANGELOG.md`. Version lives in `CMakeLists.txt` `project(... VERSION ...)`.

## Build & test
```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j"$(nproc)"
./build/cecore_test
QT_QPA_PLATFORM=offscreen ./build/gui_debugger_smoke
QT_QPA_PLATFORM=offscreen ./build/gui_theme_smoke
```

## Before pushing — keep CI green
Run **`tools/ci-check.sh --config`** (seconds) before every push, and the full
`tools/ci-check.sh` before non-trivial changes. The CI `sanitizers` job installs
**NO Qt**, so the GUI is skipped and nothing pulls in transitive targets (e.g. a
target that links `Threads::Threads` with no `find_package(Threads)`): such gaps
build fine locally (Qt imports them) but redden only CI. The script reproduces the
no-Qt condition with `-DCMAKE_DISABLE_FIND_PACKAGE_Qt6=ON`. When you add a target
that links a library target, add the matching `find_package(... REQUIRED)`.
A red `sanitizers` job is a real portability issue; the one flaky test to ignore is
the multithread `mt soft bp` timing check (already retried in-test).

## Conventions
- **GUI slots only gather input and call a shared cecore function** — never a
  second copy of the logic, so everything the GUI does stays scriptable and
  testable headlessly (Lua / `cescan`). Test new backend behavior in `cecore_test`.
- **Security (default-deny):** `shellExecute` and the `write*Local` Lua functions
  are disabled unless the out-of-band env var `CECORE_LUA_ALLOW_UNSAFE=1` is set
  (a Lua table cannot set it). A table's Lua/AA prompts for confirmation before
  running. Treat `.CT` / `.CETRAINER` / ELF / DWARF as untrusted (bounds-checked,
  size-capped, Lua conditions sandboxed + instruction-limited). Don't add
  detection-evasion or anti-cheat-bypass features — out of scope.
- **Diagnostics:** `CE_LOG=debug`, per-subsystem `CE_LOG=ptrace:trace`, or
  `CE_LOG_FILE=/path` turn on `ce::log` at runtime with no rebuild.
- **Writing style:** never use em dashes (`—`) or en dashes (`–`) as punctuation;
  use commas, parentheses, colons, or separate sentences.

## Scope
Single-player games, reverse engineering, learning. Windows / kernel-stealth
(DBVM/DBK) is parked; IL2CPP live dissection and in-Memory-Viewer stepping are
known open items (see `docs/DEVELOPMENT.md`).
