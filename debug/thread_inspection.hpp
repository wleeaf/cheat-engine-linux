#pragma once
#include "platform/linux/target_debug.hpp"
#include "platform/linux/target_syscall.hpp"
#include "debug/stack_trace.hpp"
#include <span>

namespace ce {
struct RawStackValue {
    uintptr_t address = 0;
    uint64_t value = 0;
    unsigned width = 0;
    bool available = false;
};
struct ThreadSnapshot {
    os::TargetProcessIdentity identity;
    CpuContext context;
    os::NativeVectorContext vectors;
    Error vectorError;
    std::array<std::array<uint8_t,16>,16> ymmHigh{};
    unsigned ymmCount = 0;
    std::vector<RawStackValue> stack;
    std::vector<StackFrame> frames;
};
// All reads and optional changed-register writes share one selected-thread stop.
// Ownership and failed cleanup outlive the frontend through the native service.
std::expected<ThreadSnapshot,std::string> inspectThread(
    ProcessHandle& process,pid_t tid,bool includeStack = false,
    const ThreadSnapshot* displayed = nullptr,std::span<const uint64_t> editedValues = {});
// Pure data helper, also used by model checks; the caller must keep the thread stopped.
std::vector<RawStackValue> readRawStack(ProcessHandle& process,const CpuContext& context,
                                      ByteOrder order,size_t count = 32);
} // namespace ce
