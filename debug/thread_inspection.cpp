#include "debug/thread_inspection.hpp"
#include "core/cpu_registers.hpp"
#include "platform/linux/syscall_service.hpp"
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/uio.h>

#ifndef NT_X86_XSTATE
#define NT_X86_XSTATE 0x202
#endif

namespace ce {
std::vector<RawStackValue> readRawStack(ProcessHandle& process,const CpuContext& context,
                                      ByteOrder order,size_t count) {
    const unsigned width = context.architecture == CpuArchitecture::X86_32 ? 4 :
        context.architecture == CpuArchitecture::X86_64 || context.architecture == CpuArchitecture::Arm64 ? 8 : 0;
    std::vector<RawStackValue> result;
    if (!width || order == ByteOrder::Unknown || count > 4096) return result;
    result.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        const uintptr_t offset = i * width;
        if (context.stackPointer() > UINTPTR_MAX - offset) break;
        const uintptr_t address = context.stackPointer() + offset;
        if (address > UINTPTR_MAX - (width - 1)) break;
        std::array<uint8_t,8> bytes{};
        auto read = process.read(address,bytes.data(),width);
        const bool full = read && *read == width;
        result.push_back({address,full ? *decodeTargetUnsigned({bytes.data(),width},order) : 0,width,full});
    }
    return result;
}

std::expected<ThreadSnapshot,std::string> inspectThread(
    ProcessHandle& process,pid_t tid,bool includeStack,const ThreadSnapshot* displayed,
    std::span<const uint64_t> editedValues) {
    const auto description = process.targetDescription();
    if (description.transport != TargetTransport::Local || !description.live)
        return std::unexpected("Thread inspection requires a live local process");
    if (description.pendingRecovery)
        return std::unexpected("Native recovery is pending; recover the process before inspecting threads");
    auto parent = os::processMemoryIdentity(process.pid());
    auto identity = os::targetProcessIdentity(tid);
    if (!parent || !identity) return std::unexpected((!parent ? parent.error() : identity.error()).message());
    std::error_code error;
    const auto task = std::filesystem::path("/proc") / std::to_string(process.pid()) / "task" / std::to_string(tid);
    if (!std::filesystem::is_directory(task,error)) return std::unexpected("Selected thread no longer belongs to this process");
    if (displayed && displayed->identity != *identity)
        return std::unexpected("Selected thread identity changed; refresh before applying edits");
    ThreadSnapshot snapshot;
    snapshot.identity = *identity;
    std::string detail;
    auto inspected = os::memorySyscallService().inspectThread(*identity,*parent,description.host,displayed != nullptr,
        [&]() -> Result<void> {
            auto actualParent = os::processMemoryIdentity(process.pid());
            if (!actualParent || *actualParent != *parent || !std::filesystem::is_directory(task,error))
                return std::unexpected(std::make_error_code(std::errc::operation_canceled));
            auto current = os::readNativeContext(tid);
            if (!current) return std::unexpected(current.error());
            if (cpuRegisterValues(*current).empty()) return std::unexpected(std::make_error_code(std::errc::not_supported));
            if (displayed) {
                auto merged = mergeCpuRegisterEdits(*current,displayed->context,editedValues);
                if (!merged) { detail = merged.error(); return std::unexpected(std::make_error_code(std::errc::invalid_argument)); }
                // The editor changes general registers, never debug-register banks.
                merged->debugRegistersValid = false;
                auto applied = os::writeNativeContext(tid,*merged);
                if (!applied) return std::unexpected(applied.error());
                current = os::readNativeContext(tid);
                if (!current) return std::unexpected(current.error());
                const auto expected = cpuRegisterValues(*merged);
                const auto actual = cpuRegisterValues(*current);
                if (actual.size() != expected.size()) return std::unexpected(std::make_error_code(std::errc::io_error));
                for (size_t row = 0; row < expected.size(); ++row) {
                    // The kernel canonicalizes privileged/reserved status bits.
                    // Present its actual status; verify all GP values exactly.
                    if (expected[row].name == "PSTATE" || expected[row].name == "RFLAGS" || expected[row].name == "EFLAGS") continue;
                    if (actual[row].value != expected[row].value)
                        return std::unexpected(std::make_error_code(std::errc::io_error));
                }
            }
            snapshot.context = *current;
            auto vectors = os::readNativeVectors(tid);
            if (vectors) snapshot.vectors = *vectors;
            else snapshot.vectorError = vectors.error();
#if defined(__x86_64__)
            std::array<uint8_t,832> xstate{};
            iovec io{xstate.data(),xstate.size()};
            uint64_t mask = 0;
            if (ptrace(PTRACE_GETREGSET,tid,reinterpret_cast<void*>(NT_X86_XSTATE),&io) == 0 && io.iov_len >= 832) {
                std::memcpy(&mask,xstate.data()+512,sizeof(mask));
                if (mask & 4) {
                    snapshot.ymmCount = current->architecture == CpuArchitecture::X86_32 ? 8 : 16;
                    std::memcpy(snapshot.ymmHigh.data(),xstate.data()+576,sizeof(snapshot.ymmHigh));
                }
            }
#endif
            if (includeStack) {
                const auto order = current->architecture == CpuArchitecture::Arm64 ? description.host.byteOrder : ByteOrder::Little;
                snapshot.stack = readRawStack(process,*current,order);
                snapshot.frames = buildStackTrace(process,*current,64);
            }
            return {};
        });
    if (!inspected) {
        if (detail.empty()) detail = inspected.error().message();
        if (os::memorySyscallService().pending(parent->pid,parent->startTime)) detail += "; native cleanup pending";
        return std::unexpected(detail);
    }
    return snapshot;
}
} // namespace ce
