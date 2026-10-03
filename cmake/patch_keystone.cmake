# Idempotent source patch for the FetchContent'd Keystone (0.9.2).
#
# Run by FetchContent's PATCH_COMMAND, whose working directory is the Keystone
# source tree, so all paths below are relative to it. Fixes upstream issues
# on modern toolchains:
#
#   1. `cmake_policy(SET CMP0051 OLD)` is rejected by CMake >= 4.0 (the OLD
#      behavior was removed). Switching to NEW is fine for building a static
#      Keystone; the comment in upstream's CMakeLists is about stripping
#      generator expressions from SOURCES, which does not apply here.
#   2. llvm/ADT/STLExtras.h uses intptr_t without including <cstdint>; newer
#      GCC (16) no longer pulls it in transitively.
#   3. MemoryBuffer uses oversized allocations with sized delete, which fails
#      ASan's new-delete-type-mismatch check.
#
# All edits are guarded so re-running the patch is a no-op.

foreach(_f "CMakeLists.txt" "llvm/CMakeLists.txt")
    if(EXISTS "${_f}")
        file(READ "${_f}" _contents)
        string(REPLACE "cmake_policy(SET CMP0051 OLD)" "cmake_policy(SET CMP0051 NEW)" _contents "${_contents}")
        file(WRITE "${_f}" "${_contents}")
    endif()
endforeach()

set(_stlextras "llvm/include/llvm/ADT/STLExtras.h")
if(EXISTS "${_stlextras}")
    file(READ "${_stlextras}" _contents)
    if(NOT _contents MATCHES "include <cstdint>")
        string(REPLACE
            "#include <cstddef> // for std::size_t"
            "#include <cstddef> // for std::size_t\n#include <cstdint> // for intptr_t"
            _contents "${_contents}")
        file(WRITE "${_stlextras}" "${_contents}")
    endif()
endif()

# MemoryBuffer allocates the object, name and sometimes data in one oversized
# block. Modern sized delete otherwise supplies sizeof(the class) to the allocator,
# which trips ASan's new-delete-type-mismatch on every assembly operation.
set(_memorybuffer "llvm/include/llvm/Support/MemoryBuffer.h")
if(EXISTS "${_memorybuffer}")
    file(READ "${_memorybuffer}" _contents)
    if(NOT _contents MATCHES "static void operator delete")
        string(REPLACE
            "virtual ~MemoryBuffer();"
            "virtual ~MemoryBuffer();\n  static void operator delete(void *p) { ::operator delete(p); }"
            _contents "${_contents}")
        file(WRITE "${_memorybuffer}" "${_contents}")
    endif()
endif()
