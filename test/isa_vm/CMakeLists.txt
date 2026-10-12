cmake_minimum_required(VERSION 3.21)
# Cross-built static guest programs for instruction sets without a full
# debugger backend (RISC-V first). Only architecture-generic cecore parts are
# compiled: process handle, memory syscall service, scanners, pointer scanner,
# symbol loader and the Capstone disassembler. See tools/check-isa-vm.sh.
project(cecore_isa_vm LANGUAGES C CXX)
find_package(Threads REQUIRED)

if(NOT EXISTS "${CECORE_VM_CAPSTONE_LIBRARY}" OR NOT EXISTS "${CECORE_VM_CAPSTONE_INCLUDE}/capstone/capstone.h")
    message(FATAL_ERROR "The ISA VM driver requires the verified guest Capstone build")
endif()
get_filename_component(ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)

file(GLOB ISA_LUA_SOURCES "${ROOT}/third_party/lua/src/*.c")
list(REMOVE_ITEM ISA_LUA_SOURCES "${ROOT}/third_party/lua/src/lua.c" "${ROOT}/third_party/lua/src/luac.c")
add_library(isa_lua STATIC ${ISA_LUA_SOURCES})
target_compile_definitions(isa_lua PRIVATE LUA_USE_LINUX)
target_include_directories(isa_lua PUBLIC "${ROOT}/third_party/lua/src")
target_compile_options(isa_lua PRIVATE -O2 -w)

add_library(isa_core STATIC
    ${ROOT}/platform/linux/linux_process.cpp ${ROOT}/platform/process_api.cpp
    ${ROOT}/platform/linux/target_syscall.cpp ${ROOT}/platform/linux/syscall_service.cpp
    ${ROOT}/platform/linux/memory_image.cpp ${ROOT}/platform/linux/call_service.cpp
    ${ROOT}/platform/linux/code_write.cpp ${ROOT}/platform/linux/thread_entry.cpp
    ${ROOT}/platform/linux/target_profile.cpp ${ROOT}/platform/linux/ns_attach.cpp
    ${ROOT}/platform/linux/target_debug.cpp ${ROOT}/platform/linux/register_image.cpp
    ${ROOT}/core/target_machine.cpp ${ROOT}/core/target_capabilities.cpp ${ROOT}/core/log.cpp
    ${ROOT}/arch/target_arch.cpp ${ROOT}/arch/disassembler.cpp
    ${ROOT}/symbols/elf_symbols.cpp ${ROOT}/analysis/pe_exports.cpp
    ${ROOT}/scanner/memory_scanner.cpp ${ROOT}/scanner/scan_number.cpp ${ROOT}/scanner/pointer_scanner.cpp
    ${ROOT}/scanner/snapshot.cpp ${ROOT}/scanner/cuda_search_stub.cpp
    # The operations that must refuse explicitly on instruction sets without
    # their backends (allocation, native calls, watchpoints, debugger).
    ${ROOT}/platform/linux/injector.cpp ${ROOT}/platform/linux/ptrace_wrapper.cpp
    ${ROOT}/platform/linux/arm64_vector_return.cpp
    ${ROOT}/debug/debug_session.cpp ${ROOT}/debug/tracer.cpp ${ROOT}/debug/code_finder.cpp
    ${ROOT}/debug/stack_trace.cpp ${ROOT}/debug/thread_inspection.cpp ${ROOT}/core/cpu_registers.cpp
    ${ROOT}/debug/patch.cpp)
set_target_properties(isa_core PROPERTIES CXX_STANDARD 23 CXX_STANDARD_REQUIRED ON)
target_include_directories(isa_core PUBLIC "${ROOT}" "${CECORE_VM_CAPSTONE_INCLUDE}")
target_compile_options(isa_core PRIVATE -O2)
target_link_libraries(isa_core PUBLIC isa_lua Threads::Threads "${CECORE_VM_CAPSTONE_LIBRARY}")

add_executable(init ../isa_vm_integration.cpp)
set_target_properties(init PROPERTIES CXX_STANDARD 23 CXX_STANDARD_REQUIRED ON)
target_compile_options(init PRIVATE -O2)
target_link_libraries(init PRIVATE isa_core)
target_link_options(init PRIVATE -static)

# CECORE_ISA_FIXTURE_FLAGS selects another program ABI on the same ISA (-mx32).
separate_arguments(ISA_FIXTURE_FLAGS UNIX_COMMAND "${CECORE_ISA_FIXTURE_FLAGS}")
add_executable(fixture ../static_fixture.c)
target_compile_options(fixture PRIVATE -O1 ${ISA_FIXTURE_FLAGS})
target_link_options(fixture PRIVATE -static -pthread ${ISA_FIXTURE_FLAGS})
