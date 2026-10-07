#include "platform/linux/syscall_service.hpp"
#include "platform/linux/code_write.hpp"
#include "platform/linux/memory_image.hpp"
#include <chrono>
#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <future>
#include <map>
#include <mutex>
#include <new>
#include <thread>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>

namespace ce::os {
namespace {
using Key = std::pair<pid_t, uint64_t>;
bool gone(const std::error_code& error) {
    return error == std::errc::no_such_process || error == std::errc::no_such_file_or_directory ||
           error == std::errc::operation_canceled;
}
}

struct TargetSyscallService::Impl {
    struct Pending {
        TargetProcessIdentity identity;
        TargetMachine host;
        std::shared_ptr<TargetSyscallRecovery> recovery;
        std::shared_ptr<TargetSyscallRecovery> image;
        std::optional<uint64_t> allocation;
        uint64_t allocationSize = 0;
        std::optional<TargetProcessIdentity> inspectionProcess;
    };
    std::mutex mutex;
    std::condition_variable ready;
    std::deque<std::function<void()>> jobs;
    // Accessed exclusively on the ptrace owner thread.
    std::map<Key, Pending> records;
    std::map<Key,std::shared_ptr<CodeWriteRecovery>> codeRecords;
    NativeCallOwner calls;
    std::atomic<bool> stopping{false};
    bool processLifetime=false;
    std::thread owner;
    static thread_local Impl* activeOwner;

    explicit Impl(bool lifetime) : processLifetime(lifetime),owner([this] { loop(); }) {}
    ~Impl() {
        { std::lock_guard lock(mutex); stopping = true; }
        ready.notify_one();
        owner.join();
    }

    template<class Function> auto submit(Function function) {
        if (activeOwner == this) return function();
        using Value = decltype(function());
        auto task = std::make_shared<std::packaged_task<Value()>>(std::move(function));
        auto result = task->get_future();
        { std::lock_guard lock(mutex); jobs.emplace_back([task] { (*task)(); }); }
        ready.notify_one();
        return result.get();
    }

    std::expected<uint64_t,TargetSyscallFailure> executeInProcess(const TargetProcessIdentity& identity,
        const TargetMachine& host,MemorySyscall operation,std::array<uint64_t,6> arguments,
        const TargetSyscallRecovery* image=nullptr,const NativeMemoryImage* savedImage=nullptr) {
        auto actual=processMemoryIdentity(identity.pid);
        if (!actual) return std::unexpected(actual.error());
        if (*actual!=identity) return std::unexpected(std::make_error_code(std::errc::operation_canceled));
        auto task=processMemoryTask(identity.pid);
        if (!task) return std::unexpected(task.error());
        auto thread=targetProcessIdentity(*task);
        if (!thread) return std::unexpected(thread.error());
        struct stat member{};
        const auto path="/proc/"+std::to_string(identity.pid)+"/task/"+std::to_string(*task);
        if (stat(path.c_str(),&member)!=0) return std::unexpected(std::make_error_code(std::errc::operation_canceled));
        if (thread->executableDevice!=identity.executableDevice || thread->executableInode!=identity.executableInode)
            return std::unexpected(std::make_error_code(std::errc::operation_canceled));
        return executeMemorySyscall(*task,host,operation,arguments,&*thread,image,savedImage);
    }

    std::expected<void, std::error_code> retry(Pending& record) {
        try {
        if (record.recovery) {
            auto recovered = record.recovery->retry();
            if (!recovered) {
                // A selected member can exit without destroying the shared mm.
                // Keep an unreturned mapping owned by the original process.
                if (recovered.error()!=std::errc::no_such_process || !record.allocation) return recovered;
                auto actual=processMemoryIdentity(record.identity.pid);
                if (!actual) return std::unexpected(actual.error());
                if (*actual!=record.identity) return std::unexpected(std::make_error_code(std::errc::operation_canceled));
                // A dead selected context does not retire the original mm.
                // The guarded unmap below proves its affinity with the newly
                // selected member before modifying that member's memory.
            }
            record.recovery.reset();
        }
        if (record.allocation) {
            auto cleanup = executeInProcess(record.identity,record.host,MemorySyscall::Unmap,
                {*record.allocation,record.allocationSize,0,0,0,0},record.image.get());
            if (!cleanup) {
                record.recovery = cleanup.error().recovery;
                if (cleanup.error().completedValue) record.allocation.reset();
                return std::unexpected(cleanup.error().code);
            }
            record.allocation.reset();
        }
        return {};
        } catch (const std::bad_alloc&) {
            return std::unexpected(std::make_error_code(std::errc::not_enough_memory));
        }
    }

    void recoverAll() {
        calls.recoverAll();
        for (auto it=codeRecords.begin();it!=codeRecords.end();) {
            auto restored=it->second->restore();
            if (restored || gone(restored.error())) it=codeRecords.erase(it);
            else ++it;
        }
        for (auto it = records.begin(); it != records.end();) {
            auto recovered = retry(it->second);
            if (recovered || gone(recovered.error())) it = records.erase(it);
            else ++it;
        }
    }

    void loop() {
        activeOwner = this;
        for (;;) {
            std::function<void()> job;
            {
                std::unique_lock lock(mutex);
                ready.wait_for(lock, std::chrono::milliseconds(100), [&] { return stopping || !jobs.empty(); });
                if (!jobs.empty()) { job = std::move(jobs.front()); jobs.pop_front(); }
                else if (stopping && records.empty() && codeRecords.empty() && calls.empty()) { activeOwner = nullptr; return; }
            }
            if (job) job();
            recoverAll();
            if (stopping && processLifetime) calls.releaseDetachedWorkersAtProcessExit();
            // A failed restoration retains ownership even during shutdown.
            // Wait for a real retry interval instead of spinning on stopping.
            if (stopping && (!records.empty() || !codeRecords.empty() || !calls.empty())) {
                std::unique_lock lock(mutex);
                ready.wait_for(lock, std::chrono::milliseconds(100), [&] { return !jobs.empty(); });
            }
        }
    }

    std::expected<uint64_t, std::error_code> execute(TargetProcessIdentity identity, TargetMachine host,
        MemorySyscall operation, std::array<uint64_t, 6> arguments,const NativeMemoryImage* savedImage=nullptr) {
        Key key{identity.pid, identity.startTime};
        auto code=codeRecords.find(key);
        if (code!=codeRecords.end()) {
            auto restored=code->second->restore();
            if (!restored && !gone(restored.error())) return std::unexpected(restored.error());
            codeRecords.erase(code);
        }
        auto callRecovery=calls.recover(identity);
        if (!callRecovery) return std::unexpected(callRecovery.error());
        if ((operation==MemorySyscall::Unmap || operation==MemorySyscall::Protect) &&
            calls.busy(identity.pid,arguments[0],arguments[1]))
            return std::unexpected(std::make_error_code(std::errc::device_or_resource_busy));
        auto found = records.find(key);
        if (found != records.end()) {
            if (!found->second.recovery && !found->second.allocation)
                return std::unexpected(std::make_error_code(std::errc::device_or_resource_busy));
            auto recovered = retry(found->second);
            if (!recovered && !gone(recovered.error())) return std::unexpected(recovered.error());
            records.erase(found);
            if (!recovered) return std::unexpected(recovered.error());
        }
        // Reserve ownership before the executor changes the target. Recording a
        // failed operation must not allocate memory after target mutation.
        auto [it, inserted] = records.try_emplace(key, Pending{identity, host, {}, {}, {}, 0, {}});
        (void)inserted;
        auto result = executeInProcess(identity,host,operation,arguments,nullptr,savedImage);
        if (result) { records.erase(it); return *result; }
        auto& error = result.error();
        it->second.recovery = error.recovery;
        if (operation == MemorySyscall::Map && error.completedValue && error.recovery) {
            // Own the kernel-completed allocation before a transient retry can
            // discover that its selected task died. Siblings may retain the mm.
            it->second.allocation = error.completedValue;
            it->second.image = error.recovery;
            it->second.allocationSize = arguments[1];
        }
        if (error.completedValue && error.recovery) {
            // A transient failure may be recoverable before reporting back.
            auto recovered = error.recovery->retry();
            if (recovered) { records.erase(it); return *error.completedValue; }
            if (gone(recovered.error())) {
                if (recovered.error()!=std::errc::no_such_process || !it->second.allocation) records.erase(it);
                return std::unexpected(recovered.error());
            }
        }
        if (error.completedValue && !error.recovery) { records.erase(it); return *error.completedValue; }
        if (!it->second.recovery && !it->second.allocation) records.erase(it);
        return std::unexpected(error.code);
    }
};

thread_local TargetSyscallService::Impl* TargetSyscallService::Impl::activeOwner = nullptr;

TargetSyscallService::TargetSyscallService(bool processLifetime) : impl_(std::make_unique<Impl>(processLifetime)) {}
TargetSyscallService::~TargetSyscallService() = default;
std::expected<uint64_t, std::error_code> TargetSyscallService::execute(const TargetProcessIdentity& identity,
    const TargetMachine& host, MemorySyscall operation, std::array<uint64_t, 6> arguments,const NativeMemoryImage* image) {
    try { return impl_->submit([=, this] { return impl_->execute(identity, host, operation, arguments,image); }); }
    catch (const std::bad_alloc&) { return std::unexpected(std::make_error_code(std::errc::not_enough_memory)); }
}
std::expected<void, std::error_code> TargetSyscallService::recover(const TargetProcessIdentity& identity) {
    return impl_->submit([=, this]() -> std::expected<void, std::error_code> {
        auto code=impl_->codeRecords.find({identity.pid,identity.startTime});
        if (code!=impl_->codeRecords.end()) {
            auto restored=code->second->restore();
            if (!restored && !gone(restored.error())) return restored;
            impl_->codeRecords.erase(code);
        }
        auto callRecovery=impl_->calls.recover(identity);
        if (!callRecovery) return callRecovery;
        for (auto it = impl_->records.begin(); it != impl_->records.end();) {
            if (it->first != Key{identity.pid,identity.startTime} &&
                (!it->second.inspectionProcess || *it->second.inspectionProcess != identity)) { ++it; continue; }
            if (!it->second.recovery && !it->second.allocation)
                return std::unexpected(std::make_error_code(std::errc::device_or_resource_busy));
            auto result = impl_->retry(it->second);
            if (result || gone(result.error())) it = impl_->records.erase(it);
            else return result;
        }
        return {};
    });
}
bool TargetSyscallService::pending(pid_t pid, uint64_t startTime) {
    return impl_->submit([=, this] {
        return impl_->codeRecords.contains({pid,startTime}) || impl_->records.contains({pid, startTime}) || impl_->calls.pending(pid,startTime) ||
            std::any_of(impl_->records.begin(),impl_->records.end(),[&](const auto& record) {
                const auto& process = record.second.inspectionProcess;
                return process && process->pid == pid && process->startTime == startTime;
            });
    });
}

std::expected<size_t,std::error_code> TargetSyscallService::writeCode(
    const TargetProcessIdentity& identity,uintptr_t address,std::span<const uint8_t> bytes,const NativeMemoryImage* image) {
    if (bytes.empty()) return size_t(0);
    try {
        return impl_->submit([&,this]() -> std::expected<size_t,std::error_code> {
            auto recovered=recover(identity);
            if (!recovered) return std::unexpected(recovered.error());
            if (impl_->calls.pending(identity.pid,identity.startTime) || impl_->calls.busy(identity.pid,address,bytes.size()))
                return std::unexpected(std::make_error_code(std::errc::device_or_resource_busy));
            const Key key{identity.pid,identity.startTime};
            auto prepared=CodeWriteRecovery::prepare(identity,address,bytes.size(),image);
            if (!prepared) return std::unexpected(prepared.error());
            // Reserve initialized recovery ownership before the first mutation.
            auto [it,inserted]=impl_->codeRecords.try_emplace(key,*prepared);
            if (!inserted) return std::unexpected(std::make_error_code(std::errc::device_or_resource_busy));
            auto written=it->second->write(bytes);
            if (written) {impl_->codeRecords.erase(it);return bytes.size();}
            auto restored=it->second->restore();
            if (restored || gone(restored.error())) impl_->codeRecords.erase(it);
            if (!restored && !gone(restored.error())) return std::unexpected(std::make_error_code(std::errc::state_not_recoverable));
            return std::unexpected(written.error());
        });
    } catch (const std::bad_alloc&) {return std::unexpected(std::make_error_code(std::errc::not_enough_memory));}
}

std::expected<void,std::error_code> TargetSyscallService::inspectThread(
    const TargetProcessIdentity& identity,const TargetProcessIdentity& processIdentity,
    const TargetMachine& host,bool registerWrites,
    const std::function<std::expected<void,std::error_code>()>& callback) {
    try {
        return impl_->submit([&,this]() -> std::expected<void,std::error_code> {
            auto recovered = recover(processIdentity);
            if (!recovered) return recovered;
            if (impl_->calls.pending(processIdentity.pid,processIdentity.startTime))
                return std::unexpected(std::make_error_code(std::errc::device_or_resource_busy));
            const Key key{identity.pid,identity.startTime};
            auto [it,inserted] = impl_->records.try_emplace(key,Impl::Pending{identity,host,{},{},{},0,processIdentity});
            if (!inserted) return std::unexpected(std::make_error_code(std::errc::device_or_resource_busy));
            auto result = executeThreadInspection(identity,host,registerWrites,callback);
            if (result || !result.error().recovery) impl_->records.erase(it);
            else it->second.recovery = result.error().recovery;
            if (!result) return std::unexpected(result.error().code);
            return {};
        });
    } catch (const std::bad_alloc&) { return std::unexpected(std::make_error_code(std::errc::not_enough_memory)); }
}
bool TargetSyscallService::threadStorageBusy(pid_t pid,uintptr_t address,size_t size) {
    return impl_->submit([=,this] { impl_->calls.recoverAll(); return impl_->calls.busy(pid,address,size); });
}

std::expected<NativeCallResult,std::error_code> TargetSyscallService::invoke(
    const TargetProcessIdentity& identity,const TargetMachine& host,NativeCallRequest request) {
    try {
        return impl_->submit([this,identity,host,request=std::move(request)]() mutable -> std::expected<NativeCallResult,std::error_code> {
            auto code=impl_->codeRecords.find({identity.pid,identity.startTime});
            if (code!=impl_->codeRecords.end()) {
                auto restored=code->second->restore();
                if (!restored && !gone(restored.error())) return std::unexpected(restored.error());
                impl_->codeRecords.erase(code);
            }
            auto found=impl_->records.find({identity.pid,identity.startTime});
            if (found!=impl_->records.end()) {
                auto recovered=impl_->retry(found->second);
                if (!recovered) return std::unexpected(recovered.error());
                impl_->records.erase(found);
            }
            return impl_->calls.invoke(identity,host,std::move(request));
        });
    } catch (const std::bad_alloc&) { return std::unexpected(std::make_error_code(std::errc::not_enough_memory)); }
}
std::expected<void,std::error_code> TargetSyscallService::resumeCall(const TargetProcessIdentity& identity,bool deliverSignal) {
    return impl_->submit([=,this] { return impl_->calls.resume(identity,deliverSignal); });
}

namespace {
std::mutex serviceMutex;
TargetSyscallService* service = nullptr;
void beforeFork() { serviceMutex.lock(); }
void afterForkParent() { serviceMutex.unlock(); }
void afterForkChild() {
    // The child has no copy of the owner thread. Do not destroy inherited
    // mutexes/thread objects or reuse an inherited service in a fork child.
    service = nullptr;
    serviceMutex.unlock();
}
struct ServiceLifetime {
    ServiceLifetime() { pthread_atfork(beforeFork, afterForkParent, afterForkChild); }
    ~ServiceLifetime() { delete service; }
} serviceLifetime;
}
TargetSyscallService& memorySyscallService() {
    std::lock_guard lock(serviceMutex);
    if (!service) service = new TargetSyscallService(true);
    return *service;
}
bool hasPendingMemorySyscalls(pid_t pid, uint64_t startTime) {
    TargetSyscallService* current;
    { std::lock_guard lock(serviceMutex); current = service; }
    // Never hold the global lifetime mutex while waiting for the owner: an
    // inspection callback may itself request target metadata on that owner.
    return current && current->pending(pid, startTime);
}
} // namespace ce::os
