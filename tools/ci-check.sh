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
# Keep large compiler/Wine temporary files on the build filesystem. Respect an
# explicit temporary directory, including CI/user choices.
if [ -z "${TMPDIR:-}" ]; then
    mkdir -p build/.ci-tmp
    export TMPDIR="$PWD/build/.ci-tmp"
fi

MODE="${1:-full}"
# Use one compiler by default on shared/limited developer machines. Larger
# runners can explicitly opt into parallel builds with CECORE_CI_JOBS.
JOBS="${CECORE_CI_JOBS:-1}"
ceserver_targets=()
if [ "$(uname -m)" = x86_64 ]; then
    ceserver_targets=(ceserver_integration ceserver_connection_integration ceserver_multiclient_integration compatibility_fixture64 compatibility_fixture32)
fi
# CI uses Ninja; fall back to the default generator locally if it's not installed
# (the generator doesn't affect dependency resolution — the gaps we care about
# surface at configure/link time either way).
GEN=(); command -v ninja >/dev/null && GEN=(-G Ninja)
ok()  { printf '\033[32m✓ %s\033[0m\n' "$1"; }
step(){ printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

# Keep failure evidence even when successful suites are quiet. A nonzero check
# must show its own output instead of disappearing behind stdout suppression.
run_check() {
    local label="$1"
    shift
    mkdir -p build/ci-logs
    local logfile="build/ci-logs/${label//[^[:alnum:]_.-]/_}.log"
    if "$@" >"$logfile" 2>&1; then
        return 0
    else
        local failure=$?
        printf 'Check %s failed (exit %s). Full output: %s\n' "$label" "$failure" "$logfile" >&2
        tail -n 100 "$logfile" >&2
        return "$failure"
    fi
}

# ── Job 1: sanitizers (ASan+UBSan, NO Qt) — the one that catches portability gaps ──
step "sanitizers job (ASan, no-GUI): configure"
# Reconfigure the existing tree so repeated checks can reuse compiled dependencies.
cmake -S . -B build-ci-asan "${GEN[@]}" -DCMAKE_BUILD_TYPE=Debug \
    -DCECORE_SANITIZE=ON -DCMAKE_DISABLE_FIND_PACKAGE_Qt6=ON >/dev/null
ok "configured (Qt disabled, as in CI)"
if [ "$MODE" != "--config" ]; then
    step "sanitizers job: build test targets (instrumented)"
    run_check asan-build cmake --build build-ci-asan --target cecore_test cecore_deep_test cecore_compatibility_test table_persistence_integration table_json_integration elf_symbol_integration gdb_transport_integration "${ceserver_targets[@]}" cescan speedhack -j"$JOBS"
    ok "built"
    step "sanitizers job: run suite under ASan + UBSan"
    if [ "$(uname -m)" = x86_64 ]; then
        run_check asan-autoasm-modules-build cmake --build build-ci-asan --target compatibility_integration compatibility_fixture64 compatibility_fixture32 -j"$JOBS"
        ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1}" \
            UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" \
            run_check asan-autoasm-modules python3 test/autoasm_module_gate.py build-ci-asan --report build-ci-asan/compatibility-evidence/autoasm-modules.json
    fi
    ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1}" \
        UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" \
        run_check asan-core ./build-ci-asan/cecore_test
    ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1}" \
        UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" \
        run_check asan-deep ./build-ci-asan/cecore_deep_test
    ok "suite passed under ASan+UBSan"
    if [ "${CECORE_REQUIRE_MONO:-0}" = 1 ] || command -v mono >/dev/null 2>&1; then
        run_check asan-mono-build cmake --build build-ci-asan --target mono_integration mono_fixture_control cecore_mono_agent mono_limit_agent mono_embed_fixture -j"$JOBS"
        ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1}" \
            UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" \
            run_check asan-mono python3 test/mono_compatibility_gate.py build-ci-asan --report build-ci-asan/compatibility-evidence/mono-runtime.json
        ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1}" \
            UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" \
            run_check asan-mono-embedded python3 test/mono_compatibility_gate.py build-ci-asan --embedded --report build-ci-asan/compatibility-evidence/mono-embedded.json
        ok "real standalone and embedded Mono runtime lifecycle under ASan+UBSan"
    fi
    ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1}" \
        UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" \
        run_check asan-compatibility ./build-ci-asan/cecore_compatibility_test
    ok "target compatibility under ASan+UBSan"
    ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1}" \
        UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" \
        run_check asan-table-persistence ./build-ci-asan/table_persistence_integration
    ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1}" \
        UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" \
        run_check asan-table-json python3 test/table_json_gate.py build-ci-asan --report build-ci-asan/compatibility-evidence/table-json.json
    if [ "$(uname -m)" = x86_64 ]; then
        ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1}" \
            UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" \
            run_check asan-ceserver python3 test/ceserver_compatibility_gate.py build-ci-asan --report build-ci-asan/compatibility-evidence/ceserver.json
        ok "real CEServer TCP memory and lifetime under ASan+UBSan"
    fi
    ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1}" \
        UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" \
        run_check asan-gdb python3 test/gdb_transport_gate.py build-ci-asan --report build-ci-asan/compatibility-evidence/gdb-transport.json
    ok "GDB transport and shared adapter under ASan+UBSan"
    elf_flags=()
    if [ "$(uname -m)" = x86_64 ]; then elf_flags+=(--require-i386); fi
    ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1}" \
        UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" \
        python3 test/elf_debug_gate.py build-ci-asan "${elf_flags[@]}" --report build-ci-asan/compatibility-evidence/elf-debug.json
    ok "verified separate ELF debug files under ASan+UBSan"
    if [ "$(uname -m)" = x86_64 ]; then
        run_check asan-native-build cmake --build build-ci-asan --target target_syscall_integration code_write_integration memory_image_integration compatibility_fixture64 compatibility_fixture32 native_call_integration native_call_image_integration native_call_exec_integration native_call_fixture native_call_library -j"$JOBS"
        ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1}" \
            UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" \
            python3 test/native_syscall_gate.py build-ci-asan --report build-ci-asan/compatibility-evidence/native-syscalls.json
        ok "syscall restoration and recovery under ASan+UBSan"
        ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1}" \
            UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" \
            python3 test/native_call_gate.py build-ci-asan --report build-ci-asan/compatibility-evidence/native-injector.json
        ok "real libc/pthread injection under ASan+UBSan"
        ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1}" \
            UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" \
            run_check asan-code-write python3 test/code_write_gate.py build-ci-asan --output build-ci-asan/compatibility-evidence/code-write.log --report build-ci-asan/compatibility-evidence/code-write.json
        ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1}" \
            UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" \
            run_check asan-memory-image python3 test/memory_image_gate.py build-ci-asan --output build-ci-asan/compatibility-evidence/memory-image.log --report build-ci-asan/compatibility-evidence/memory-image.json
        ok "executable code writes and recovery under ASan+UBSan"
    fi
fi

# ── Job 2: ubuntu-build (full, with GUI) ──
step "ubuntu-build job (full, GUI): configure"
cmake -S . -B build "${GEN[@]}" -DCMAKE_BUILD_TYPE=Release >/dev/null
ok "configured"
if [ "$MODE" != "--config" ]; then
    step "ubuntu-build job: build"
    run_check native-build cmake --build build -j"$JOBS"
    ok "built"
    step "ubuntu-build job: regression suite + GUI smokes"
    # Keep checks out of && lists: Bash suppresses errexit for their left-hand
    # commands, which used to print "passed" after a failed regression test.
    run_check native-core ./build/cecore_test
    ok "cecore_test"
    run_check native-deep ./build/cecore_deep_test
    ok "cecore_deep_test"
    run_check native-compatibility ./build/cecore_compatibility_test
    ok "target compatibility"
    run_check native-table-persistence ./build/table_persistence_integration
    run_check native-table-json python3 test/table_json_gate.py build --report build/compatibility-evidence/table-json.json
    if [ "$(uname -m)" = x86_64 ]; then
        run_check native-ceserver python3 test/ceserver_compatibility_gate.py build --report build/compatibility-evidence/ceserver.json
        ok "real CEServer TCP 32/64-bit memory and lifetime"
    fi
    if [ "${CECORE_REQUIRE_MONO:-0}" = 1 ] || command -v mono >/dev/null 2>&1; then
        run_check native-mono python3 test/mono_compatibility_gate.py build --report build/compatibility-evidence/mono-runtime.json
        run_check native-mono-embedded python3 test/mono_compatibility_gate.py build --embedded --report build/compatibility-evidence/mono-embedded.json
        ok "real standalone and embedded Mono metadata, JIT, collection and exit"
    fi
    gdb_flags=()
    if [ "${CECORE_REQUIRE_GDB_QEMU:-0}" = 1 ]; then gdb_flags+=(--require-qemu); fi
    if [ -n "${CECORE_GDB_QEMU_CONTAINER:-}" ]; then gdb_flags+=(--require-qemu --qemu-container "$CECORE_GDB_QEMU_CONTAINER"); fi
    run_check native-gdb python3 test/gdb_transport_gate.py build "${gdb_flags[@]}" --report build/compatibility-evidence/gdb-transport.json
    ok "GDB transport and shared guest adapter"
    run_check native-gdb-gui python3 test/gdb_gui_gate.py build "${gdb_flags[@]}" --report build/compatibility-evidence/gdb-gui.json
    ok "GDB GUI connection, ownership and XML registers"
    elf_flags=()
    if [ "$(uname -m)" = x86_64 ]; then elf_flags+=(--require-i386); fi
    python3 test/elf_debug_gate.py build "${elf_flags[@]}" --report build/compatibility-evidence/elf-debug.json
    ok "verified separate ELF debug files"
    if [ "$(uname -m)" = x86_64 ] || [ -x ./build/compatibility_integration ]; then
        run_check native-autoasm-modules python3 test/autoasm_module_gate.py build --report build/compatibility-evidence/autoasm-modules.json
        ok "native 64/32-bit live integration and exec transition"
        python3 test/native_syscall_gate.py build --report build/compatibility-evidence/native-syscalls.json
        ok "native syscall restoration faults and recovery"
        native_call_flags=()
        if [ "${CECORE_REQUIRE_NATIVE_CALL_I386:-0}" = 1 ]; then
            native_call_flags+=(--require-i386)
        fi
        python3 test/native_call_gate.py build "${native_call_flags[@]}" --report build/compatibility-evidence/native-injector.json
        ok "real libc/pthread injection"
        run_check native-code-write python3 test/code_write_gate.py build --output build/compatibility-evidence/code-write.log --report build/compatibility-evidence/code-write.json
        run_check native-memory-image python3 test/memory_image_gate.py build --output build/compatibility-evidence/memory-image.log --report build/compatibility-evidence/memory-image.json
        ok "executable code writes and recovery"
    fi
    run_check scan ./build/scan_test
    ok "scan_test"
    run_check gui-register-frontends python3 test/gui_runtime_gate.py build --report build/compatibility-evidence/native-frontends.json
    run_check gui-register-leader-exit python3 test/gui_runtime_gate.py build --leader-exit --report build/compatibility-evidence/native-frontends-leader-exit.json
    for test in gui_debugger_smoke gui_theme_smoke gui_guest_scan_smoke \
                gui_structdissect_smoke gui_hexview_smoke gui_disasm_smoke \
                gui_search_smoke gui_changeaddr_smoke gui_luaconsole_smoke \
                gui_codefinder_smoke gui_lifecycle_smoke; do
        QT_QPA_PLATFORM=offscreen run_check "$test" "./build/$test"
        ok "$test"
    done
    if [ "$(uname -m)" = x86_64 ]; then
        run_check gui-injection-lifecycle python3 test/gui_injection_gate.py build --report build/compatibility-evidence/gui-injection.json
    fi
    if [ -x ./build/wayland_shortcuts_test ]; then
        run_check wayland-shortcuts dbus-run-session -- ./build/wayland_shortcuts_test
        ok "wayland_shortcuts_test"
    fi
    ./build/cescan list >/dev/null
    ok "cescan launches"
    python3 test/cli_usability_test.py build/cescan
    ok "CLI usability workflows"
    if command -v wine >/dev/null || command -v wine64 >/dev/null; then
        python3 test/wine_compatibility_test.py build --report build/compatibility-evidence/wine-local.json
        ok "real Wine PE32/PE32+ integration"
    elif [ "${CECORE_REQUIRE_WINE:-0}" = 1 ]; then
        printf 'Wine is required by CECORE_REQUIRE_WINE=1 but is unavailable\n' >&2
        exit 1
    else
        printf 'Wine local coverage is unavailable; required remote Wine gates still apply\n'
    fi
    if [ "${CECORE_REQUIRE_ARM32_VM:-0}" = 1 ]; then
        bash tools/check-arm32-vm.sh
        CECORE_ARM32_UBSAN=1 bash tools/check-arm32-vm.sh
        ok "required ARM/Thumb register and breakpoint checks under both kernels"
    fi
    if [ "${CECORE_REQUIRE_ARM64_VM:-0}" = 1 ]; then
        bash tools/check-arm64-vm.sh
        CECORE_VM_PAGE_SIZE=65536 bash tools/check-arm64-vm.sh
        ok "required ARM64 full-system syscall and recovery checks"
    fi
fi

printf '\n\033[32m== CI mirror passed — safe to push ==\033[0m\n'
