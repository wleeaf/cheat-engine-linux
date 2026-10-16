#pragma once

#include "platform/process_api.hpp"

namespace ce {

// Module and region paths of a ceserver or GDB target name files on the remote
// system. A file at the same path on this machine is a different binary (or
// absent), so parsers of module files (ELF and PE symbols, DWARF, IL2CPP
// metadata and GameAssembly) must not open them. An Unknown transport is not
// trusted either. Local targets, live or snapshot, map files of this machine.
inline bool moduleFilesAreLocal(ProcessHandle& process) {
    return process.targetDescription().transport == TargetTransport::Local;
}

inline constexpr const char* kRemoteModuleFilesError =
    "module files of a remote target are not available locally";

} // namespace ce
