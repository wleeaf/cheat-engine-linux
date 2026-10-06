cmake_minimum_required(VERSION 3.21)
project(cecore_arm64_vm LANGUAGES C CXX ASM)
find_package(Threads REQUIRED)
option(CECORE_VM_X32_TESTS "Build the LP64 engine driver for x32 target checks" OFF)

if(NOT EXISTS "${CECORE_VM_CAPSTONE_LIBRARY}" OR NOT EXISTS "${CECORE_VM_CAPSTONE_INCLUDE}/capstone/capstone.h")
    message(FATAL_ERROR "The VM driver requires the verified guest Capstone build")
endif()
get_filename_component(CECORE_VM_SOURCE_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)

# Compile kernel fixtures independently of the Qt application and dynamic libc.
# CMake tracks header dependencies so a local check rebuilds only changed files.
add_library(vm_core OBJECT
    ../../platform/linux/injector.cpp ../../platform/linux/thread_entry.cpp
    ../../platform/linux/target_syscall.cpp ../../platform/linux/syscall_service.cpp ../../platform/linux/code_write.cpp ../../platform/linux/memory_image.cpp ../../platform/linux/call_service.cpp
    ../../platform/linux/linux_process.cpp ../../platform/process_api.cpp
    ../../core/target_machine.cpp ../../core/target_capabilities.cpp ../../arch/target_arch.cpp
    ../../core/log.cpp ../../platform/linux/ns_attach.cpp
    ../../platform/linux/target_debug.cpp ../../platform/linux/register_image.cpp
    ../../platform/linux/arm64_vector_return.cpp ../../platform/linux/ptrace_wrapper.cpp
    ../../debug/debug_session.cpp ../../debug/tracer.cpp ../../debug/code_finder.cpp
    ../../debug/stack_trace.cpp ../../debug/thread_inspection.cpp ../../core/cpu_registers.cpp
    ../../arch/disassembler.cpp ../../symbols/elf_symbols.cpp ../../analysis/pe_exports.cpp ../../debug/patch.cpp)
set_target_properties(vm_core PROPERTIES CXX_STANDARD 23 CXX_STANDARD_REQUIRED ON)
target_include_directories(vm_core PUBLIC "${CECORE_VM_SOURCE_ROOT}" "${CECORE_VM_CAPSTONE_INCLUDE}")
target_compile_options(vm_core PRIVATE -O2)
target_link_libraries(vm_core PUBLIC Threads::Threads "${CECORE_VM_CAPSTONE_LIBRARY}")
add_executable(init ../target_syscall_integration.cpp ../syscall_faults.cpp ../native_call_integration.cpp)
set_target_properties(init PROPERTIES CXX_STANDARD 23 CXX_STANDARD_REQUIRED ON)
target_compile_options(init PRIVATE -O2)
target_compile_definitions(init PRIVATE CECORE_NATIVE_CALL_EMBEDDED CECORE_VM_NATIVE_CALL)
target_link_libraries(init PRIVATE vm_core)
target_link_options(init PRIVATE -static -Wl,--wrap=ptrace -Wl,--wrap=pwrite -Wl,--wrap=_Znwm -Wl,--wrap=stat -Wl,--wrap=waitpid)

add_executable(code_write_init ../code_write_integration.cpp ../code_write_faults.cpp)
set_target_properties(code_write_init PROPERTIES CXX_STANDARD 23 CXX_STANDARD_REQUIRED ON)
target_compile_options(code_write_init PRIVATE -O2)
target_compile_definitions(code_write_init PRIVATE CE_CODE_WRITE_GUEST)
target_link_libraries(code_write_init PRIVATE vm_core)
target_link_options(code_write_init PRIVATE -static -Wl,--wrap=pwrite)

add_executable(fixture ../compatibility_fixture.c)
add_executable(memory_image_init ../memory_image_integration.cpp ../code_write_faults.cpp)
set_target_properties(memory_image_init PROPERTIES CXX_STANDARD 23 CXX_STANDARD_REQUIRED ON)
target_compile_options(memory_image_init PRIVATE -O2)
target_link_libraries(memory_image_init PRIVATE vm_core)
target_link_options(memory_image_init PRIVATE -static -Wl,--wrap=pwrite)
add_executable(shared_mm_fixture ../shared_mm_fixture.c)
target_compile_options(shared_mm_fixture PRIVATE -O2)
target_link_options(shared_mm_fixture PRIVATE -static)
target_compile_options(fixture PRIVATE
    -O2 -ffreestanding -fno-builtin -fno-pie -fno-stack-protector -fomit-frame-pointer)
target_link_options(fixture PRIVATE -nostdlib -static -no-pie)

# Actual guest glibc/pthread/loader behavior complements the freestanding fixture.
add_executable(native_call_fixture ../native_call_fixture.c)
if(CECORE_VM_X32_TESTS)
    add_executable(x32_debug_init ../target_syscall_integration.cpp ../syscall_faults.cpp)
    set_target_properties(x32_debug_init PROPERTIES CXX_STANDARD 23 CXX_STANDARD_REQUIRED ON)
    target_compile_options(x32_debug_init PRIVATE -O2)
    target_link_libraries(x32_debug_init PRIVATE vm_core)
    target_link_options(x32_debug_init PRIVATE -static -Wl,--wrap=ptrace -Wl,--wrap=pwrite -Wl,--wrap=_Znwm -Wl,--wrap=stat -Wl,--wrap=waitpid)
    add_executable(x32_call_init ../x32_call_vm_integration.cpp ../native_call_integration.cpp)
    set_target_properties(x32_call_init PROPERTIES CXX_STANDARD 23 CXX_STANDARD_REQUIRED ON)
    target_compile_options(x32_call_init PRIVATE -O2)
    target_compile_definitions(x32_call_init PRIVATE CECORE_NATIVE_CALL_EMBEDDED CECORE_VM_X32)
    target_link_libraries(x32_call_init PRIVATE vm_core)
    target_link_options(x32_call_init PRIVATE -static)
endif()
add_executable(native_call_image_init ../native_call_image_integration.cpp ../code_write_faults.cpp)
set_target_properties(native_call_image_init PROPERTIES CXX_STANDARD 23 CXX_STANDARD_REQUIRED ON)
target_compile_options(native_call_image_init PRIVATE -O2)
target_link_libraries(native_call_image_init PRIVATE vm_core)
target_link_options(native_call_image_init PRIVATE -static -Wl,--wrap=pwrite)
add_executable(native_call_exec_init ../native_call_exec_integration.cpp)
set_target_properties(native_call_exec_init PROPERTIES CXX_STANDARD 23 CXX_STANDARD_REQUIRED ON)
target_compile_options(native_call_exec_init PRIVATE -O2)
target_link_libraries(native_call_exec_init PRIVATE vm_core)
target_link_options(native_call_exec_init PRIVATE -static -Wl,--wrap=ptrace -Wl,--wrap=waitpid)
add_executable(native_call_image_fixture ../native_call_image_fixture.c)
target_compile_options(native_call_image_fixture PRIVATE -O2 -fno-pie)
target_link_options(native_call_image_fixture PRIVATE -no-pie)
target_link_libraries(native_call_image_fixture PRIVATE Threads::Threads)
target_compile_options(native_call_fixture PRIVATE -O2)
target_link_options(native_call_fixture PRIVATE -rdynamic)
target_link_libraries(native_call_fixture PRIVATE Threads::Threads)
add_library(native_call_library SHARED ../native_call_library.c)
target_link_libraries(native_call_library PRIVATE ${CMAKE_DL_LIBS})
set_target_properties(native_call_library PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")

add_executable(relocation_init ../arm64_relocation_integration.cpp ../arm64_relocation_fixtures.S
    ../../arch/aarch64_relocator.cpp ../../arch/disassembler.cpp ../../arch/target_arch.cpp
    ../../core/target_machine.cpp ../../platform/process_api.cpp)
set_target_properties(relocation_init PROPERTIES CXX_STANDARD 23 CXX_STANDARD_REQUIRED ON)
target_include_directories(relocation_init PRIVATE "${CECORE_VM_SOURCE_ROOT}" "${CECORE_VM_CAPSTONE_INCLUDE}")
target_compile_options(relocation_init PRIVATE -O2)
target_link_libraries(relocation_init PRIVATE "${CECORE_VM_CAPSTONE_LIBRARY}")
target_link_options(relocation_init PRIVATE -static)
