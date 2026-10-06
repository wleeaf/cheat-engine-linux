#include "platform/linux/injector.hpp"
#include "platform/linux/syscall_service.hpp"
#include "platform/linux/memory_image.hpp"
#include "core/target_capabilities.hpp"
#include <cerrno>
#include <chrono>
#include <thread>

namespace ce::os {
namespace {
std::expected<NativeCallResult,std::string> invoke(ProcessHandle& process,NativeCallRequest request) {
    auto identity=request.image ? Result<TargetProcessIdentity>(request.image->identity()) : processMemoryIdentity(process.pid());
    if (!identity) return std::unexpected(identity.error().message());
    request.forwardSignals=true;
    auto result=memorySyscallService().invoke(*identity,process.targetDescription().host,std::move(request));
    if (!result) {
        std::string message=result.error().message();
        if (hasPendingMemorySyscalls(identity->pid,identity->startTime))
            message+="; native call and private frame retained for recovery";
        return std::unexpected(std::move(message));
    }
    return std::move(*result);
}
int status(uint64_t value) { return static_cast<int32_t>(value); }
}

std::expected<uintptr_t,std::string> injectLibrary(
    ProcessHandle& process,SymbolResolver& resolver,const std::string& path,std::shared_ptr<NativeMemoryImage> image) {
    if (auto reason=unsupportedTargetOperation(process,TargetFeature::LibraryInjection)) return std::unexpected(*reason);
    if (path.empty() || path.size()>=4096 || path.find('\0')!=std::string::npos)
        return std::unexpected("invalid shared library path");
    uintptr_t function=resolver.lookup("dlopen");
    uint64_t flags=2;
    if (!function) { function=resolver.lookup("__libc_dlopen_mode"); flags|=0x80000000u; }
    if (!function) return std::unexpected("dlopen not found in target process symbols");
    NativeCallRequest request;
    request.image=std::move(image);
    request.function=function; request.arguments[1]=flags; request.dataArguments=1;
    request.data.assign(path.begin(),path.end()); request.data.push_back(0);
    auto called=invoke(process,std::move(request));
    if (!called) return std::unexpected("dlopen: "+called.error());
    if (!called->value) return std::unexpected("dlopen returned NULL in target process");
    // A basename substring in /proc/maps cannot validate opaque loader handles
    // and rejects legitimate symlinks. Exact native call completion is authoritative.
    return static_cast<uintptr_t>(called->value);
}

std::expected<RemoteThreadInfo,std::string> createRemoteThread(
    ProcessHandle& process,SymbolResolver& resolver,uintptr_t entry,bool wait,int timeoutMs) {
    return createRemoteThread(process,resolver,entry,wait,timeoutMs,{});
}

std::expected<RemoteThreadInfo,std::string> createRemoteThread(
    ProcessHandle& process,SymbolResolver& resolver,uintptr_t entry,bool wait,int timeoutMs,
    std::span<const NativeThreadRange> retainedStorage,std::shared_ptr<NativeMemoryImage> image) {
    if (auto reason=unsupportedTargetOperation(process,TargetFeature::RemoteThread)) return std::unexpected(*reason);
    if (!entry || timeoutMs<0) return std::unexpected("invalid remote thread entry or timeout");
    auto description=process.targetDescription();
    auto region=process.queryRegion(entry);
    if (!region || !(region->protection & MemProt::Exec))
        return std::unexpected("remote thread entry point must be in executable target memory");
    auto entryMachine=process.machineAt(entry);
    if (entryMachine.architecture!=description.host.architecture || entryMachine.abi!=description.host.abi)
        return std::unexpected("remote thread entry point must use the native host calling convention");
    uintptr_t create=resolver.lookup("pthread_create");
    if (!create) create=resolver.lookup("__pthread_create");
    uintptr_t detach=resolver.lookup("pthread_detach");
    if (!create || !detach) return std::unexpected("pthread_create/pthread_detach not found in target process symbols");
    NativeCallRequest request;
    request.image=std::move(image);
    request.function=create; request.workerEntry=entry;
    request.workerRanges.assign(retainedStorage.begin(),retainedStorage.end());
    request.workerRanges.push_back({region->base,region->size});
    request.outputSize=description.host.pointerWidth; request.dataArguments=1;
    request.orphanDetach=detach;
    auto created=invoke(process,std::move(request));
    if (!created) return std::unexpected("pthread_create: "+created.error());
    if (int code=status(created->value)) return std::unexpected("pthread_create: "+std::error_code(code,std::system_category()).message());
    auto handle=decodeTargetUnsigned(created->data,description.host.byteOrder);
    if (!handle || !*handle) return std::unexpected("pthread_create returned an empty or invalid thread handle");
    RemoteThreadInfo info;
    info.handle=static_cast<uintptr_t>(*handle);
    info.tid=created->worker->tid;
    if (wait) {
        auto identity=processMemoryIdentity(process.pid());
        if (!identity) return std::unexpected(identity.error().message());
        auto deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(timeoutMs);
        do {
            auto recovered=memorySyscallService().recover(*identity);
            if (!recovered) return std::unexpected("pthread cleanup: "+recovered.error().message());
            if (created->worker->exited.load(std::memory_order_acquire)) { info.completed=true; return info; }
            if (std::chrono::steady_clock::now()>=deadline) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        } while (std::chrono::steady_clock::now()<deadline);
    }
    // The owner detached the real handle before releasing the entry wrapper.
    // Storage stays pinned until this Linux TID exits, independently of this result.
    return info;
}
} // namespace ce::os
