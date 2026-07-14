cmake_minimum_required(VERSION 3.20)
project(cecore VERSION 0.4.1 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Single source of truth for the version — surfaced via --version in the CLI/GUI.
add_compile_definitions(CECORE_VERSION="${PROJECT_VERSION}")

# ── Options ──
option(CECORE_BUILD_TESTS "Build test programs" ON)
option(CECORE_FORCE_FETCHCONTENT "Always use FetchContent for Capstone/Keystone, even if installed" OFF)
option(CECORE_SANITIZE "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
if(CECORE_SANITIZE)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
    add_link_options(-fsanitize=address,undefined)
    message(STATUS "Sanitizers: ASan + UBSan enabled")
endif()

include(FetchContent)

# Capstone and Keystone declare older cmake_minimum_required values that fail
# to configure with CMake >= 3.27 unless this is set. Applies to nested
# FetchContent CMakeLists too.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

# ── Capstone ──
# Try system install first; fall back to FetchContent so a fresh checkout
# builds without manual dependency setup.
if(NOT CECORE_FORCE_FETCHCONTENT)
    find_library(CAPSTONE_LIB capstone)
    find_path(CAPSTONE_INCLUDE capstone/capstone.h)
endif()
if(NOT CAPSTONE_LIB OR NOT CAPSTONE_INCLUDE)
    message(STATUS "Capstone: not found via find_library — fetching from upstream")
    set(CAPSTONE_BUILD_TESTS    OFF CACHE BOOL "" FORCE)
    set(CAPSTONE_BUILD_CSTOOL   OFF CACHE BOOL "" FORCE)
    set(CAPSTONE_INSTALL        OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(capstone
        GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
        # Immutable commit SHA that tag 5.0.1 resolves to (a tag is mutable; a
        # SHA is not). GIT_SHALLOW is dropped because shallow fetch of an
        # arbitrary SHA is not reliably supported.
        GIT_TAG        097c04d9413c59a58b00d4d1c8d5dc0ac158ffaa)
    FetchContent_MakeAvailable(capstone)
    set(CAPSTONE_LIB capstone)
    # capstone's own includes pick up automatically through its target.
    set(CAPSTONE_INCLUDE "${capstone_SOURCE_DIR}/include")
else()
    message(STATUS "Capstone: using system ${CAPSTONE_LIB}")
endif()

# ── Keystone ──
if(NOT CECORE_FORCE_FETCHCONTENT)
    find_library(KEYSTONE_LIB keystone)
    find_path(KEYSTONE_INCLUDE keystone/keystone.h)
endif()
if(NOT KEYSTONE_LIB OR NOT KEYSTONE_INCLUDE)
    message(STATUS "Keystone: not found via find_library — fetching from upstream (this can take several minutes the first time)")
    set(BUILD_LIBS_ONLY        ON  CACHE BOOL   "" FORCE)
    set(LLVM_TARGETS_TO_BUILD  "X86;AArch64;ARM" CACHE STRING "" FORCE)
    set(BUILD_SHARED_LIBS      ON  CACHE BOOL   "" FORCE)
    FetchContent_Declare(keystone
        GIT_REPOSITORY https://github.com/keystone-engine/keystone.git
        # Immutable commit SHA that tag 0.9.2 resolves to (see capstone note).
        GIT_TAG        dc7932ef2b2c4a793836caec6ecab485005139d6)
    FetchContent_MakeAvailable(keystone)
    set(KEYSTONE_LIB keystone)
    set(KEYSTONE_INCLUDE "${keystone_SOURCE_DIR}/include")
else()
    message(STATUS "Keystone: using system ${KEYSTONE_LIB}")
endif()

# ── Optional DWARF support via elfutils' libdw ──
find_path(LIBDW_INCLUDE elfutils/libdw.h)
find_library(LIBDW_LIB dw)
if(LIBDW_INCLUDE AND LIBDW_LIB)
    set(CECORE_HAVE_DWARF ON)
    message(STATUS "DWARF support: enabled (${LIBDW_LIB})")
else()
    set(CECORE_HAVE_DWARF OFF)
    message(STATUS "DWARF support: disabled (install libdw-dev to enable)")
endif()

# ── Optional TinyCC bridge for AA {$ccode} blocks ──
find_path(LIBTCC_INCLUDE libtcc.h)
find_library(LIBTCC_LIB tcc)
if(LIBTCC_INCLUDE AND LIBTCC_LIB)
    set(CECORE_HAVE_TINYCC ON)
    message(STATUS "TinyCC support: enabled (${LIBTCC_LIB})")
else()
    set(CECORE_HAVE_TINYCC OFF)
    message(STATUS "TinyCC support: disabled (install libtcc-dev to enable {$ccode})")
endif()

# ── Optional SoundTouch (pitch-preserving audio resampling for the
#    audiohack LD_PRELOAD library). ──
find_path(SOUNDTOUCH_INCLUDE soundtouch/SoundTouch.h)
find_library(SOUNDTOUCH_LIB SoundTouch)
if(SOUNDTOUCH_INCLUDE AND SOUNDTOUCH_LIB)
    set(CECORE_HAVE_SOUNDTOUCH ON)
    message(STATUS "SoundTouch: enabled (${SOUNDTOUCH_LIB}) — audiohack will pitch-correct")
else()
    set(CECORE_HAVE_SOUNDTOUCH OFF)
    message(STATUS "SoundTouch: disabled (install libsoundtouch-dev to enable pitch correction in audiohack)")
endif()

# ── ALSA dev headers — required for the audiohack target. ──
find_path(ASOUND_INCLUDE alsa/asoundlib.h)
find_library(ASOUND_LIB asound)

# ── Optional CUDA acceleration ──
# When the CUDA toolkit (nvcc + cudart) is present, build the GPU search
# kernel into a separate target and link. The .cu source has its own
# nvcc-driven compile rules; without the toolkit, cuda_search_stub.cpp
# provides the same API as a no-op.
include(CheckLanguage)
check_language(CUDA)
if(CMAKE_CUDA_COMPILER)
    enable_language(CUDA)
    set(CECORE_HAVE_CUDA ON)
    message(STATUS "CUDA support: enabled (${CMAKE_CUDA_COMPILER})")
else()
    set(CECORE_HAVE_CUDA OFF)
    message(STATUS "CUDA support: disabled (install nvidia-cuda-toolkit to enable)")
endif()

# ── Lua 5.3 (vendored, built from source) ──
# Lua 5.3 sources are vendored under third_party/lua and built by CMake, so the
# repo is self-contained (offline builds, no upstream checkout). Override the
# tree with: cmake -B build -DLUA_DIR=/path/to/lua-5.3/src
set(LUA_DIR "${CMAKE_SOURCE_DIR}/third_party/lua/src" CACHE PATH "Lua 5.3 source dir")
if(NOT EXISTS "${LUA_DIR}/lua.h")
    message(FATAL_ERROR "Lua 5.3 sources not found at LUA_DIR='${LUA_DIR}'. "
        "Expected the vendored tree at third_party/lua/src, or pass -DLUA_DIR=/path/to/lua-5.3/src.")
endif()

# Compile Lua into a static PIC library (excluding the interpreter/compiler
# mains). Declared before the project-wide -Wall/-Wextra below so Lua's own C
# sources don't emit warning noise (-w).
file(GLOB LUA_LIB_SOURCES CONFIGURE_DEPENDS "${LUA_DIR}/*.c")
list(REMOVE_ITEM LUA_LIB_SOURCES "${LUA_DIR}/lua.c" "${LUA_DIR}/luac.c")
add_library(lua_static STATIC ${LUA_LIB_SOURCES})
target_compile_definitions(lua_static PRIVATE LUA_USE_LINUX)
target_include_directories(lua_static PUBLIC ${LUA_DIR})
set_target_properties(lua_static PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_options(lua_static PRIVATE -w)

# ── First-party hardening & warnings ──
# Applied only to cecore's own targets (declared below this point); the
# fetched/system Capstone & Keystone targets above are unaffected. No -Werror:
# warnings are surfaced but never fail the build. _FORTIFY_SOURCE needs an
# optimized build, so it is only added for optimized configs.
add_compile_options(-Wall -Wextra -fstack-protector-strong)
add_link_options(-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)
if(CMAKE_BUILD_TYPE MATCHES "Release|RelWithDebInfo|MinSizeRel")
    add_compile_definitions(_FORTIFY_SOURCE=2)
endif()

# ── ceserver ──
# The upstream ceserver C daemon sources were dropped in the single-repo
# consolidation: the old ceserver_c target was built but never linked, and
# remote-target support is the first-party C++ client in
# platform/linux/ceserver_client.cpp (no upstream C sources required).

# ── libcecore C++ library ──
add_library(cecore SHARED
    core/types.cpp
    core/autoasm.cpp
    core/aa_templates.cpp
    core/injection_gen.cpp
    core/expression.cpp
    core/ct_file.cpp
    core/trainer.cpp
    analysis/code_analysis.cpp
    analysis/il2cpp_metadata.cpp
    analysis/managed_runtime.cpp
    analysis/structure_tools.cpp
    platform/network_compression.cpp
    platform/vulkan_overlay_injector.cpp
    platform/linux/ceserver_client.cpp
    platform/linux/ceserver_server.cpp
    platform/linux/ceserver_process.cpp
    platform/linux/ceserver_debugger.cpp
    platform/linux/mono_debugger_client.cpp
    platform/linux/kernel_driver.cpp
    platform/linux/linux_process.cpp
    platform/linux/ptrace_wrapper.cpp
    platform/linux/injector.cpp
    platform/linux/process_watcher.cpp
    platform/linux/ceserver_stubs.c
    arch/disassembler.cpp
    arch/assembler.cpp
    symbols/elf_symbols.cpp
    symbols/dwarf_symbols.cpp
    debug/breakpoint_manager.cpp
    debug/code_finder.cpp
    debug/instruction_access.cpp
    debug/patch.cpp
    debug/stack_trace.cpp
    debug/tracer.cpp
    debug/lbr_tracer.cpp
    debug/intel_pt.cpp
    debug/debug_session.cpp
    debug/gdb_remote.cpp
    debug/managed_breakpoint.cpp
    symbols/kernel_symbols.cpp
    scanner/memory_scanner.cpp
    scanner/pointer_scanner.cpp
    scanner/snapshot.cpp
    $<$<NOT:$<BOOL:${CECORE_HAVE_CUDA}>>:scanner/cuda_search_stub.cpp>
    scripting/lua_engine.cpp
    scripting/lua_bindings.cpp
    scripting/lua_memrec.cpp
    scripting/lua_streams.cpp
    scripting/lua_snapshot.cpp
    plugins/plugin_loader.cpp
)
target_include_directories(cecore PUBLIC
    ${CMAKE_SOURCE_DIR}
    ${CAPSTONE_INCLUDE}
    ${KEYSTONE_INCLUDE}
    ${LUA_DIR}
)
target_link_libraries(cecore PRIVATE
    dl pthread z ${CAPSTONE_LIB} ${KEYSTONE_LIB}
    lua_static m  # Static Lua (built from third_party/lua)
)

if(CECORE_HAVE_DWARF)
    target_compile_definitions(cecore PUBLIC CECORE_HAVE_DWARF)
    target_include_directories(cecore PRIVATE ${LIBDW_INCLUDE})
    target_link_libraries(cecore PRIVATE ${LIBDW_LIB})
endif()

if(CECORE_HAVE_TINYCC)
    target_compile_definitions(cecore PUBLIC CECORE_HAVE_TINYCC)
    target_include_directories(cecore PRIVATE ${LIBTCC_INCLUDE})
    target_link_libraries(cecore PRIVATE ${LIBTCC_LIB})
endif()

if(CECORE_HAVE_CUDA)
    target_compile_definitions(cecore PUBLIC CECORE_HAVE_CUDA)
    target_sources(cecore PRIVATE scanner/cuda_search.cu)
    set_source_files_properties(scanner/cuda_search.cu PROPERTIES LANGUAGE CUDA)
    set_target_properties(cecore PROPERTIES CUDA_STANDARD 17)
endif()

# ── CLI tool ──
add_executable(cescan cli/main.cpp)
target_link_libraries(cescan PRIVATE cecore)

# ── Speedhack .so ──
add_library(speedhack SHARED plugins/speedhack.c)
target_link_libraries(speedhack PRIVATE dl rt)
# -Bsymbolic-functions: the lib's own references to its wrapper functions (e.g.
# taking &nanosleep for the GOT-patch table) must bind to OUR definitions, not
# to libc's global one. Without it, a dlopen-injected lib patches GOT slots back
# to libc (no-op). Exported symbols still interpose for the LD_PRELOAD path.
target_link_options(speedhack PRIVATE -Wl,-Bsymbolic-functions)
set_target_properties(speedhack PROPERTIES PREFIX "lib")

# ── In-process VEH shim (LD_PRELOAD library) ──
add_library(cecore_inprocess_veh SHARED plugins/inprocess_veh.c)
target_link_libraries(cecore_inprocess_veh PRIVATE dl)
set_target_properties(cecore_inprocess_veh PROPERTIES PREFIX "lib")

# ── audiohack (pitch-preserving speedhack companion, ALSA-side) ──
if(ASOUND_INCLUDE AND ASOUND_LIB)
    add_library(cecore_audiohack SHARED plugins/audiohack.cpp)
    target_include_directories(cecore_audiohack PRIVATE ${ASOUND_INCLUDE})
    target_link_libraries(cecore_audiohack PRIVATE dl rt ${ASOUND_LIB})
    set_target_properties(cecore_audiohack PROPERTIES PREFIX "lib")
    if(CECORE_HAVE_SOUNDTOUCH)
        target_compile_definitions(cecore_audiohack PRIVATE CECORE_HAVE_SOUNDTOUCH)
        target_include_directories(cecore_audiohack PRIVATE ${SOUNDTOUCH_INCLUDE})
        target_link_libraries(cecore_audiohack PRIVATE ${SOUNDTOUCH_LIB})
    endif()
else()
    message(STATUS "ALSA headers not found — skipping cecore_audiohack target")
endif()

# ── Sample plugin (regression coverage for the structured plugin ABI) ──
add_library(cecore_sample_plugin SHARED plugins/sample_plugin.c)
target_include_directories(cecore_sample_plugin PRIVATE ${CMAKE_SOURCE_DIR})
set_target_properties(cecore_sample_plugin PROPERTIES PREFIX "lib")

# ── Vulkan explicit overlay layer ──
add_library(ce_vulkan_overlay_layer SHARED platform/vulkan_overlay_layer.cpp)
set_target_properties(ce_vulkan_overlay_layer PROPERTIES
    PREFIX "lib"
    OUTPUT_NAME "ce_vulkan_overlay_layer"
)

# ── Qt6 GUI ──
find_package(Qt6 COMPONENTS Widgets)
if(Qt6_FOUND)
    set(CMAKE_AUTOMOC ON)
    qt_add_executable(cheatengine
        gui/resources.qrc
        gui/main.cpp
        gui/theme.cpp
        gui/mainwindow.cpp
        gui/processlistdialog.cpp
        gui/memorybrowser.cpp
        gui/scripteditor.cpp
        gui/pointerscan_dialog.cpp
        gui/registereditor.cpp
        gui/structuredissector.cpp
        gui/luaconsole.cpp
        gui/breakpointlist.cpp
        gui/codefinder.cpp
        gui/codereferences.cpp
        gui/advancedoptions.cpp
        gui/heapregions.cpp
        gui/memoryregions.cpp
        gui/modulelist.cpp
        gui/overlay.cpp
        gui/stackview.cpp
        gui/threadlist.cpp
        gui/settingsdialog.cpp
        gui/memoryfill.cpp
        gui/tracerwindow.cpp
        gui/branchmapper.cpp
        gui/elfinspector.cpp
        gui/filepatcher.cpp
        gui/formdesigner.cpp
        gui/canvaswidget.cpp
        gui/findstaticswindow.cpp
        gui/globalhotkeys.cpp
        gui/debuggerwindow.cpp
        scripting/lua_gui.cpp
        scripting/lua_bitmap.cpp
    )
    target_include_directories(cheatengine PRIVATE ${LUA_DIR})
    target_link_libraries(cheatengine PRIVATE cecore Qt6::Widgets)
    # Global hotkeys need X11 (XGrabKey). Optional: without it, hotkeys fall back
    # to Qt::ApplicationShortcut (only active when a cheatengine window is focused).
    find_package(X11)
    if(X11_FOUND)
        target_link_libraries(cheatengine PRIVATE X11::X11 ${X11_xcb_LIB} xcb)
        target_compile_definitions(cheatengine PRIVATE CECORE_HAVE_X11_HOTKEYS)
        message(STATUS "Global hotkeys: enabled (X11)")
    else()
        message(STATUS "Global hotkeys: disabled (X11 not found)")
    endif()
    message(STATUS "Qt6 found — building GUI")

    # Headless offscreen smoke test for the interactive debugger window.
    if(CECORE_BUILD_TESTS)
        qt_add_executable(gui_debugger_smoke
            test/gui_debugger_smoke.cpp
            gui/debuggerwindow.cpp
        )
        target_include_directories(gui_debugger_smoke PRIVATE ${CMAKE_SOURCE_DIR} ${LUA_DIR})
        target_link_libraries(gui_debugger_smoke PRIVATE cecore Qt6::Widgets)

        # Offscreen smoke test for light/dark theme switching.
        qt_add_executable(gui_theme_smoke
            test/gui_theme_smoke.cpp
            gui/theme.cpp
        )
        target_include_directories(gui_theme_smoke PRIVATE ${CMAKE_SOURCE_DIR})
        target_link_libraries(gui_theme_smoke PRIVATE Qt6::Widgets)
    endif()

    # Wayland global hotkeys via the XDG GlobalShortcuts portal (QtDBus). Under
    # Wayland XGrabKey is unavailable, so this is the only path to shortcuts that
    # fire while the game is focused. Optional: needs the Qt6 DBus module.
    find_package(Qt6 COMPONENTS DBus QUIET)
    if(Qt6DBus_FOUND)
        target_sources(cheatengine PRIVATE gui/wayland_global_shortcuts.cpp)
        target_link_libraries(cheatengine PRIVATE Qt6::DBus)
        target_compile_definitions(cheatengine PRIVATE CECORE_HAVE_WAYLAND_HOTKEYS)
        message(STATUS "Global hotkeys: Wayland portal backend enabled (Qt6::DBus)")
        if(CECORE_BUILD_TESTS)
            qt_add_executable(wayland_shortcuts_test
                test/wayland_shortcuts_test.cpp
                gui/wayland_global_shortcuts.cpp
            )
            target_include_directories(wayland_shortcuts_test PRIVATE ${CMAKE_SOURCE_DIR})
            target_link_libraries(wayland_shortcuts_test PRIVATE Qt6::Core Qt6::DBus)
        endif()
    else()
        message(STATUS "Global hotkeys: Wayland portal backend disabled (Qt6::DBus not found)")
    endif()
else()
    message(STATUS "Qt6 not found — skipping GUI build")
endif()

# ── Test programs ──
if(CECORE_BUILD_TESTS)
    add_executable(cecore_test test/main.cpp)
    target_link_libraries(cecore_test PRIVATE cecore)

    # When the Vulkan loader is available, the overlay-layer test creates a real
    # VkInstance with our explicit layer enabled and checks the layer's hook ran.
    # It skips gracefully at runtime if no Vulkan driver can create an instance.
    find_package(Vulkan)
    if(Vulkan_FOUND)
        add_dependencies(cecore_test ce_vulkan_overlay_layer)
        target_link_libraries(cecore_test PRIVATE Vulkan::Vulkan)
        target_compile_definitions(cecore_test PRIVATE
            CE_HAVE_VULKAN
            CE_VK_OVERLAY_LAYER_SO="$<TARGET_FILE:ce_vulkan_overlay_layer>")
    endif()

    add_executable(scan_test test/scan_test.cpp)
    target_link_libraries(scan_test PRIVATE cecore)
endif()

# ── Install / embeddability ──
# Makes libcecore.so installable, versioned, and discoverable (pkg-config) so
# other projects can link the engine. NOTE: the whole header set is installed as
# "public" for now; a curated public-API subset + a CMake package config with
# transitive Capstone/Keystone handling is a tracked follow-up (see ROADMAP.md).
include(GNUInstallDirs)
set_target_properties(cecore PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR})
install(TARGETS cecore
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
foreach(dir core platform arch scanner symbols analysis debug scripting plugins)
    install(DIRECTORY ${dir}/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cecore/${dir}
        FILES_MATCHING PATTERN "*.hpp" PATTERN "*.h")
endforeach()
if(TARGET cescan)
    install(TARGETS cescan RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
if(TARGET cheatengine)
    install(TARGETS cheatengine RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    install(FILES packaging/cheatengine.desktop
            DESTINATION ${CMAKE_INSTALL_DATADIR}/applications)
    install(FILES packaging/cheatengine.png
            DESTINATION ${CMAKE_INSTALL_DATADIR}/icons/hicolor/256x256/apps)
    install(FILES packaging/io.github.wleeaf.CheatEngineLinux.metainfo.xml
            DESTINATION ${CMAKE_INSTALL_DATADIR}/metainfo)
    install(FILES packaging/cheat-engine-linux.mime.xml
            DESTINATION ${CMAKE_INSTALL_DATADIR}/mime/packages)
endif()
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/packaging/cecore.pc.in
               ${CMAKE_CURRENT_BINARY_DIR}/cecore.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/cecore.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

# ── CPack: apt-installable .deb + tarball ──
# An unsandboxed native package: unlike Flatpak (whose sandbox isolates the app
# in its own PID namespace and blocks ptrace/memory access to other processes,
# defeating a memory scanner), a .deb runs with the user's privileges and works.
set(CPACK_PACKAGE_NAME "cheat-engine-linux")
set(CPACK_PACKAGE_VENDOR "wleeaf")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Linux-native Cheat Engine: memory scanner, debugger, injector")
set(CPACK_PACKAGE_CONTACT "https://github.com/wleeaf/cheat-engine-linux")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_GENERATOR "DEB;TGZ")
set(CPACK_DEBIAN_PACKAGE_SECTION "devel")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)         # auto-detect Qt6/capstone/dw/etc.
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
# libcap2-bin provides setcap, used by the postinst to grant cap_sys_ptrace so the
# app can read other processes' memory without root (SHLIBDEPS appends the rest).
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libcap2-bin")
# postinst runs setcap cap_sys_ptrace+ep on the installed binaries (dpkg runs it as
# root); postrm/postinst also refresh ldconfig for libcecore.
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
    "${CMAKE_CURRENT_SOURCE_DIR}/packaging/deb/postinst;${CMAKE_CURRENT_SOURCE_DIR}/packaging/deb/postrm")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "cheat-engine-linux")
include(CPack)
