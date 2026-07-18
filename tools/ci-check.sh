#!/usr/bin/env bash
# Local mirror of the GitHub `build` workflow — run before pushing to keep CI green.
#
# The trap this catches: developer machines have Qt installed, so the full build
# always configures. But the CI `sanitizers` job installs NO Qt, so the GUI is
# skipped and nothing pulls in transitive targets (e.g. Threads::Threads). We
# reproduce that no-GUI condition with -DCMAKE_DISABLE_FIND_PACKAGE_Qt6=ON, which
# is how a missing find_package() slips past a local build but reddens CI.
#
# Usage:
#   tools/ci-check.sh            # configure + build + test, both configs (full)
#   tools/ci-check.sh --config   # configure only, both configs (fast; catches
#                                #   CMake/dependency-resolution errors in seconds)
set -euo pipefail
cd "$(dirname "$0")/.."

MODE="${1:-full}"
JOBS="$(nproc)"
# CI uses Ninja; fall back to the default generator locally if it's not installed
# (the generator doesn't affect dependency resolution — the gaps we care about
# surface at configure/link time either way).
GEN=(); command -v ninja >/dev/null && GEN=(-G Ninja)
ok()  { printf '\033[32m✓ %s\033[0m\n' "$1"; }
step(){ printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

# ── Job 1: sanitizers (ASan+UBSan, NO Qt) — the one that catches portability gaps ──
step "sanitizers job (ASan, no-GUI): configure"
rm -rf build-ci-asan
cmake -S . -B build-ci-asan "${GEN[@]}" -DCMAKE_BUILD_TYPE=Debug \
    -DCECORE_SANITIZE=ON -DCMAKE_DISABLE_FIND_PACKAGE_Qt6=ON >/dev/null
ok "configured (Qt disabled, as in CI)"
if [ "$MODE" != "--config" ]; then
    step "sanitizers job: build test targets (instrumented)"
    cmake --build build-ci-asan --target cecore_test speedhack -j"$JOBS" >/dev/null
    ok "built"
    step "sanitizers job: run suite under ASan + UBSan"
    ./build-ci-asan/cecore_test >/dev/null
    ok "suite passed under ASan+UBSan"
fi

# ── Job 2: ubuntu-build (full, with GUI) ──
step "ubuntu-build job (full, GUI): configure"
cmake -S . -B build "${GEN[@]}" -DCMAKE_BUILD_TYPE=Release >/dev/null
ok "configured"
if [ "$MODE" != "--config" ]; then
    step "ubuntu-build job: build"
    cmake --build build -j"$JOBS" >/dev/null
    ok "built"
    step "ubuntu-build job: regression suite + GUI smokes"
    ./build/cecore_test >/dev/null && ok "cecore_test"
    QT_QPA_PLATFORM=offscreen ./build/gui_debugger_smoke >/dev/null && ok "gui_debugger_smoke"
    QT_QPA_PLATFORM=offscreen ./build/gui_theme_smoke >/dev/null && ok "gui_theme_smoke"
    QT_QPA_PLATFORM=offscreen ./build/gui_guest_scan_smoke >/dev/null && ok "gui_guest_scan_smoke"
    ./build/cescan list >/dev/null && ok "cescan launches"
fi

printf '\n\033[32m== CI mirror passed — safe to push ==\033[0m\n'
