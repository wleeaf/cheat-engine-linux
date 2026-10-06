cmake_minimum_required(VERSION 3.21)
project(cecore_arm32_register_vm LANGUAGES C CXX)
get_filename_component(CECORE_SOURCE_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
add_executable(register_init ../arm32_register_integration.cpp
    ../../platform/linux/target_debug.cpp ../../platform/linux/register_image.cpp ../../core/cpu_registers.cpp
    ../../platform/linux/target_syscall.cpp ../../platform/linux/memory_image.cpp
    ../../platform/linux/arm64_vector_return.cpp ../../core/target_machine.cpp ../../core/log.cpp)
set_target_properties(register_init PROPERTIES CXX_STANDARD 23 CXX_STANDARD_REQUIRED ON)
target_include_directories(register_init PRIVATE "${CECORE_SOURCE_ROOT}")
target_compile_options(register_init PRIVATE -O2 -ffunction-sections -fdata-sections)
target_link_options(register_init PRIVATE -static -pthread -Wl,--gc-sections -Wl,--wrap=ptrace)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_FLAGS MATCHES "fsanitize=[^ ]*undefined")
    # The static UBSan runtime uses RTTI internally. Select libstdc++'s existing
    # type_info equality before application COMDATs, so its own vptr check does
    # not recursively enter an instrumented inline replacement. All application
    # translation units retain full undefined/vptr instrumentation.
    target_link_options(register_init PRIVATE -Wl,-u,_ZNKSt9type_infoeqERKS_ -lstdc++)
endif()
if(CMAKE_SYSTEM_PROCESSOR STREQUAL "arm")
    add_executable(register_fixture ../arm32_register_fixture.c)
    target_compile_options(register_fixture PRIVATE -O2 -fomit-frame-pointer)
    target_link_options(register_fixture PRIVATE -static)
endif()
