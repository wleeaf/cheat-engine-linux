#pragma once
/// Inject a shared library (.so) into a running process via ptrace + dlopen.

#include "platform/process_api.hpp"
#include "symbols/elf_symbols.hpp"
#include <string>
#include <expected>
#include <cstddef>
#include <sys/types.h>

namespace ce::os {

struct RemoteThreadInfo {
    pid_t tid = 0;
    uintptr_t handle = 0;
    uintptr_t stackAddress = 0;
    size_t stackSize = 0;
    bool completed = false;
};

/// Inject a .so file into a target process.
/// Returns the handle returned by dlopen, or an error string.
std::expected<uintptr_t, std::string>
injectLibrary(ProcessHandle& proc, SymbolResolver& resolver, const std::string& soPath);

/// Start a target function on a new Linux thread using libc clone().
std::expected<RemoteThreadInfo, std::string>
createRemoteThread(ProcessHandle& proc, SymbolResolver& resolver, uintptr_t entryPoint,
                   bool waitForCompletion = false, int timeoutMs = 5000);

} // namespace ce::os
