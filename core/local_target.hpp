#pragma once

#include "platform/process_api.hpp"
#include <optional>

namespace ce {
// Host signals, /proc and perf operations must never interpret a remote target's
// identifier (or GDB's zero sentinel) as a Linux PID on the frontend machine.
inline std::optional<pid_t> localTargetPid(ProcessHandle* process) {
    if (!process) return std::nullopt;
    const auto description=process->targetDescription();
    if (!description.live || description.transport!=TargetTransport::Local || process->pid()<=0)
        return std::nullopt;
    return process->pid();
}
}
