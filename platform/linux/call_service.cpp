#include "platform/linux/call_service.hpp"
#include "platform/linux/target_debug.hpp"
#include "platform/linux/thread_entry.hpp"
#include "platform/linux/memory_image.hpp"
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <map>
#include <list>
#include <signal.h>
#include <sstream>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

namespace ce::os {
namespace {
using Key=std::pair<pid_t,uint64_t>;
std::error_code error() { return {errno,std::system_category()}; }
std::error_code invalid() { return std::make_error_code(std::errc::invalid_argument); }
bool gone(const std::error_code& e) { return e==std::errc::no_such_process || e==std::errc::no_such_file_or_directory; }
}

struct NativeCallOwner::Impl {
    struct Call;
    using Leases=std::list<std::unique_ptr<Call>>;
    struct Call {
        TargetProcessIdentity identity,threadIdentity;
        TargetMachine host;
        NativeCallRequest request;
        std::shared_ptr<NativeMemoryImage> originImage;
        NativeCallResult result;
        pid_t tid=0;
        int memoryFd=-1,signal=0;
        std::optional<siginfo_t> signalInfo;
        uintptr_t originalPc=0,frame=0,dataAddress=0,stackTop=0;
        size_t frameSize=0;
        bool seized=false,stopped=false,interruptRequested=false,done=false;
        bool abandoned=false,completed=false,aborted=false,outputRead=false;
        bool functionRecovery=false,orphanRecovery=false,orphanDetached=false;
        bool memoryWritable=false,retired=false,affinityPending=false;
        bool leaseReserved=false;
        uint64_t orphanHandle=0;
        Leases::iterator leaseSlot;
        std::weak_ptr<NativeCallResult::ThreadLease> threadLease;
        std::shared_ptr<std::atomic<bool>> leaseReleased;
        std::error_code operationError;
        std::shared_ptr<TargetSyscallRecovery> recovery;
        std::optional<NativeThreadEntry> workerCode;
        std::shared_ptr<NativeCallResult::WorkerState> workerState;
        std::optional<TargetProcessIdentity> workerIdentity;
        bool workerStarted=false,workerOwned=false;
        ~Call() { if (memoryFd>=0) close(memoryFd); }
    };
    std::map<Key,std::unique_ptr<Call>> calls;
    Leases leases;

    Result<void> readBytes(Call& c,uintptr_t address,void* data,size_t size) {
        size_t offset=0;
        while (offset<size) {
            auto n=pread(c.memoryFd,static_cast<uint8_t*>(data)+offset,size-offset,static_cast<off_t>(address+offset));
            if (n<0 && errno==EINTR) continue;
            if (n<=0) return std::unexpected(n<0 ? error() : std::make_error_code(std::errc::io_error));
            offset+=static_cast<size_t>(n);
        }
        return {};
    }
    Result<void> writeBytes(Call& c,uintptr_t address,const uint8_t* data,size_t size) {
        size_t offset=0;
        while (offset<size) {
            ssize_t n=0;
            if (c.memoryWritable) n=pwrite(c.memoryFd,data+offset,size-offset,static_cast<off_t>(address+offset));
            else {
                if (!c.seized || !c.stopped) return std::unexpected(std::make_error_code(std::errc::permission_denied));
                size_t count=std::min(sizeof(long),size-offset);
                long word=0;
                if (count<sizeof(long)) {
                    errno=0;
                    word=ptrace(PTRACE_PEEKDATA,c.tid,reinterpret_cast<void*>(address+offset),nullptr);
                    if (errno) return std::unexpected(error());
                }
                std::memcpy(&word,data+offset,count);
                if (ptrace(PTRACE_POKEDATA,c.tid,reinterpret_cast<void*>(address+offset),reinterpret_cast<void*>(word))<0)
                    return std::unexpected(error());
                n=static_cast<ssize_t>(count);
            }
            if (n<0 && errno==EINTR) continue;
            if (n<=0) return std::unexpected(n<0 ? error() : std::make_error_code(std::errc::io_error));
            offset+=static_cast<size_t>(n);
        }
        return {};
    }
    Result<uint64_t> workerField(Call& c,NativeThreadField field) {
        std::array<uint8_t,8> data{};
        auto read=readBytes(c,c.dataAddress+c.host.pointerWidth+c.workerCode->offset(field),data.data(),c.host.pointerWidth);
        if (!read) return std::unexpected(read.error());
        auto value=decodeTargetUnsigned({data.data(),c.host.pointerWidth},c.host.byteOrder);
        if (!value) return std::unexpected(invalid());
        return *value;
    }
    Result<void> setWorkerField(Call& c,NativeThreadField field,uint64_t value) {
        std::array<uint8_t,8> data{};
        for (unsigned i=0;i<c.host.pointerWidth;++i) data[i]=static_cast<uint8_t>(value>>(8*i));
        return writeBytes(c,c.dataAddress+c.host.pointerWidth+c.workerCode->offset(field),data.data(),c.host.pointerWidth);
    }
    Result<TargetProcessIdentity> workerIdentity(Call& c,pid_t namespaceTid) {
        auto path="/proc/"+std::to_string(c.identity.pid)+"/task";
        DIR* directory=opendir(path.c_str());
        if (!directory) return std::unexpected(error());
        std::unique_ptr<DIR,decltype(&closedir)> owned(directory,&closedir);
        while (auto* entry=readdir(directory)) {
            char* end=nullptr;
            long visibleTid=strtol(entry->d_name,&end,10);
            if (!*entry->d_name || *end || visibleTid<=0 || visibleTid>INT32_MAX) continue;
            std::ifstream status(path+"/"+entry->d_name+"/status");
            if (!status) continue;
            bool hasNamespaceIds=false,matches=false;
            std::string line;
            while (std::getline(status,line)) if (line.starts_with("NSpid:")) {
                hasNamespaceIds=true;
                std::istringstream ids(line.substr(6));
                long id=0,last=0;
                while (ids>>id) last=id;
                matches=last==namespaceTid;
                break;
            }
            // On kernels without PID namespace support, gettid is already visible.
            if (matches || (!hasNamespaceIds && visibleTid==namespaceTid))
                return targetProcessIdentity(static_cast<pid_t>(visibleTid));
        }
        return std::unexpected(std::make_error_code(std::errc::resource_unavailable_try_again));
    }
    std::expected<uint64_t,TargetSyscallFailure> function(Call& c,uintptr_t address,
        std::array<uint64_t,8> arguments,int timeout) {
        auto deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(timeout);
        auto result=executeStoppedFunction(c.tid,c.host,address,arguments,c.frame,c.stackTop,timeout);
        if (!result && result.error().code==std::errc::interrupted && c.request.forwardSignals && result.error().recovery) {
            auto ticket=result.error().recovery;
            auto resumed=ticket->resumeFunction(true);
            while (!resumed && std::chrono::steady_clock::now()<deadline &&
                (resumed.error()==std::errc::timed_out || resumed.error()==std::errc::interrupted)) {
                resumed=resumed.error()==std::errc::interrupted ? ticket->resumeFunction(true) : ticket->retry();
            }
            if (resumed && ticket->functionResult()) result=*ticket->functionResult();
            else if (!resumed) result.error().code=resumed.error();
        }
        return result;
    }
    Result<void> startWorker(Call& c) {
        if (!c.workerIdentity) {
            auto deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(100);
            do {
                auto tid=workerField(c,NativeThreadField::Tid);
                if (!tid) return std::unexpected(tid.error());
                if (*tid>INT32_MAX) return std::unexpected(invalid());
                if (*tid) {
                    auto identity=workerIdentity(c,static_cast<pid_t>(*tid));
                    if (!identity) return std::unexpected(identity.error());
                    c.workerIdentity=*identity; c.workerState->tid=identity->pid;
                    break;
                }
                usleep(1000);
            } while (std::chrono::steady_clock::now()<deadline);
            if (!c.workerIdentity) return std::unexpected(std::make_error_code(std::errc::timed_out));
        }
        if (!c.orphanDetached) {
            auto released=function(c,c.request.orphanDetach,{c.orphanHandle,0,0,0,0,0,0,0},100);
            if (!released) {
                c.recovery=released.error().recovery; c.functionRecovery=true; c.orphanRecovery=true;
                if (released.error().pendingEvent==PTRACE_EVENT_EXEC || (c.recovery && c.recovery->imageRetired()))
                    return retire(c,released.error().replacementTask);
                return std::unexpected(released.error().code);
            }
            int code=static_cast<int32_t>(*released);
            if (code!=0 && code!=ESRCH && code!=EINVAL) return std::unexpected(std::error_code(code,std::system_category()));
            c.orphanDetached=true;
        }
        if (!c.workerStarted) {
            // The wrapper can return independently even if the engine exits.
            // Its mappings remain owned until actual kernel exit, never just Done.
            auto exitAllowed=setWorkerField(c,NativeThreadField::Exit,1);
            if (!exitAllowed) return exitAllowed;
            auto started=setWorkerField(c,NativeThreadField::Start,c.abandoned ? 2 : 1);
            if (!started) return started;
            c.workerStarted=true;
        }
        return {};
    }
    Result<void> maintainWorker(Call& c) {
        c.done=false;
        auto checked=image(c);
        if (!checked) {
            if (!gone(checked.error()) && checked.error()!=std::errc::operation_canceled) return checked;
            c.workerState->exited.store(true,std::memory_order_release);
            c.frame=0;
            auto detached=detach(c);
            if (!detached) return detached;
            c.done=true; return {};
        }
        if (!c.workerState->exited.load(std::memory_order_acquire)) {
            auto identity=targetProcessIdentity(c.workerIdentity->pid);
            if ((!identity && gone(identity.error())) || (identity && *identity!=*c.workerIdentity)) {
                c.workerState->exited.store(true,std::memory_order_release);
            } else {
                if (!identity) return std::unexpected(identity.error());
                // startWorker already permitted independent wrapper return.
                // Done is not kernel exit and needs no repeated control write.
                return {};
            }
        }
        // A parked application thread must not have its relative wait restarted
        // just to reclaim a wrapper. Retain storage until an eligible thread exists.
        auto restored=recovered(c);
        if (!restored) return restored;
        if (c.frame && !c.seized) {
            auto selected=prepare(c);
            if (!selected) return selected;
        }
        if (c.frame) {
            auto freed=memory(c,MemorySyscall::Unmap,{c.frame,c.frameSize,0,0,0,0});
            if (!freed) return freed;
        }
        auto detached=detach(c);
        if (!detached) return detached;
        c.done=true;
        return {};
    }

    Result<void> image(Call& c) {
        if (c.retired) return std::unexpected(std::make_error_code(std::errc::operation_canceled));
        auto identity=processMemoryIdentity(c.identity.pid);
        if (!identity) return std::unexpected(identity.error());
        if (*identity!=c.identity) return std::unexpected(std::make_error_code(std::errc::operation_canceled));
        if (c.memoryFd>=0) {
            uint8_t byte=0;
            auto size=pread(c.memoryFd,&byte,1,static_cast<off_t>(c.originalPc));
            if (!size) return std::unexpected(std::make_error_code(std::errc::operation_canceled));
            if (size<0 && errno!=EIO && errno!=EFAULT) return std::unexpected(error());
        }
        return {};
    }
    Result<void> stop(Call& c) {
        if (c.stopped) return {};
        auto deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(100);
        if (!c.interruptRequested) {
            if (ptrace(PTRACE_INTERRUPT,c.tid,nullptr,nullptr)<0) return std::unexpected(error());
            c.interruptRequested=true;
        }
        do {
            int status=0;
            pid_t waited=waitpid(c.tid,&status,__WALL|__WNOTHREAD|WNOHANG);
            if (waited<0 && errno==EINTR) continue;
            if (waited<0) return std::unexpected(error());
            if (waited==c.tid) {
                if (WIFEXITED(status) || WIFSIGNALED(status)) { c.seized=false; return std::unexpected(std::make_error_code(std::errc::no_such_process)); }
                if (!WIFSTOPPED(status)) return std::unexpected(std::make_error_code(std::errc::state_not_recoverable));
                c.stopped=true; c.interruptRequested=false;
                if ((status>>16)==0) {
                    c.signal=WSTOPSIG(status);
                    siginfo_t info{};
                    if (ptrace(PTRACE_GETSIGINFO,c.tid,nullptr,&info)==0) c.signalInfo=info;
                }
                if ((status>>16)==PTRACE_EVENT_STOP && WSTOPSIG(status)!=SIGTRAP) c.signal=WSTOPSIG(status);
                if ((status>>16)!=PTRACE_EVENT_STOP || WSTOPSIG(status)!=SIGTRAP)
                    return std::unexpected(std::make_error_code(std::errc::interrupted));
                return {};
            }
            usleep(1000);
        } while (std::chrono::steady_clock::now()<deadline);
        return std::unexpected(std::make_error_code(std::errc::timed_out));
    }
    Result<void> detach(Call& c) {
        if (!c.seized) return {};
        auto identity=targetProcessIdentity(c.tid);
        if (!identity && gone(identity.error())) { c.seized=false; return {}; }
        if (identity && identity->startTime!=c.threadIdentity.startTime) {
            c.seized=false; return {};
        }
        if (!identity) return std::unexpected(identity.error());
        auto stopped=stop(c);
        if (!stopped && !c.stopped) return stopped;
        if (c.signalInfo && ptrace(PTRACE_SETSIGINFO,c.tid,nullptr,&*c.signalInfo)<0) return std::unexpected(error());
        if (ptrace(PTRACE_DETACH,c.tid,nullptr,reinterpret_cast<void*>(static_cast<intptr_t>(c.signal)))<0)
            return std::unexpected(error());
        c.seized=false; c.stopped=false; c.signal=0; c.signalInfo.reset();
        return {};
    }
    Result<void> retire(Call& c,std::optional<TargetTaskIdentity> replacement=std::nullopt) {
        if (!replacement && c.recovery) replacement=c.recovery->replacementTask();
        if (replacement) {
            c.tid=replacement->tid;c.threadIdentity.pid=replacement->tid;
            c.threadIdentity.startTime=replacement->startTime;
            c.stopped=true;c.interruptRequested=false;c.signal=0;c.signalInfo.reset();
        }
        c.retired=true;c.frame=0;c.affinityPending=false;
        c.recovery.reset();c.functionRecovery=false;c.orphanRecovery=false;c.aborted=true;
        if (c.workerState) c.workerState->exited.store(true,std::memory_order_release);
        auto detached=detach(c);
        if (!detached) return detached;
        c.done=true;
        return std::unexpected(std::make_error_code(std::errc::operation_canceled));
    }
    Result<void> recovered(Call& c) {
        if (!c.recovery) return c.affinityPending && c.seized && c.stopped ? bindMemory(c) : Result<void>{};
        auto recovered=c.recovery->retry();
        if (!recovered && recovered.error()==std::errc::interrupted && c.request.forwardSignals && c.functionRecovery)
            recovered=c.recovery->resumeFunction(true);
        if (c.recovery->imageRetired() || (!recovered && recovered.error()==std::errc::operation_canceled))
            return retire(c);
        if (!recovered) return recovered;
        if (c.functionRecovery) {
            auto value=c.recovery->functionResult();
            if (c.orphanRecovery) c.orphanDetached=
                (c.leaseReleased && c.leaseReleased->load(std::memory_order_acquire)) ||
                (value && (static_cast<int32_t>(*value)==0 || static_cast<int32_t>(*value)==ESRCH || static_cast<int32_t>(*value)==EINVAL));
            else if (value) { c.completed=true; c.result.value=*value; }
            else c.aborted=true;
        }
        c.recovery.reset(); c.functionRecovery=false; c.orphanRecovery=false; c.stopped=true;
        return c.affinityPending ? bindMemory(c) : Result<void>{};
    }
    Result<void> memory(Call& c,MemorySyscall operation,std::array<uint64_t,6> arguments) {
        auto checked=image(c);
        if (!checked) return checked;
        auto result=executeOwnedMemorySyscall(c.tid,c.host,operation,arguments);
        auto value=result ? std::optional<uint64_t>(*result) : result.error().completedValue;
        if (operation==MemorySyscall::Map && value) c.frame=*value;
        if (operation==MemorySyscall::Unmap && value) c.frame=0;
        if (!result) {
            c.recovery=result.error().recovery; c.functionRecovery=false;
            c.signal=result.error().pendingSignal;
            if (result.error().pendingEvent==PTRACE_EVENT_EXEC || (c.recovery && c.recovery->imageRetired()))
                return retire(c,result.error().replacementTask);
            return std::unexpected(result.error().code);
        }
        return {};
    }
    Result<void> finish(Call& c) {
        if (c.workerOwned) return maintainWorker(c);
        auto restored=recovered(c);
        if (!restored) {
            if (gone(restored.error())) {
                // A selected sibling can exit while the process and its private
                // mapping remain live. Recover that mapping on another thread.
                c.recovery.reset(); c.functionRecovery=false; c.orphanRecovery=false;
                c.seized=false; c.stopped=false; c.interruptRequested=false;
                c.aborted=true;
            }
            else if (restored.error()!=std::errc::operation_canceled) return restored;
        }
        auto checked=image(c);
        if (!checked) {
            if (c.workerState && (gone(checked.error()) || checked.error()==std::errc::operation_canceled))
                c.workerState->exited.store(true,std::memory_order_release);
            if (gone(checked.error())) { c.done=true; return checked; }
            if (checked.error()!=std::errc::operation_canceled) return checked;
            // Never unmap a stale frame from an exec-replaced address space.
            c.frame=0;
            auto detached=detach(c);
            if (!detached) return detached;
            c.done=true;
            return checked;
        }
        if (c.seized && !c.recovery) {
            auto owned=targetProcessIdentity(c.tid);
            if ((!owned && gone(owned.error())) || (owned && owned->startTime!=c.threadIdentity.startTime)) {
                c.seized=false; c.stopped=false; c.interruptRequested=false;
            } else if (!owned) return std::unexpected(owned.error());
        }
        if (!c.seized && c.frame) {
            auto selected=prepare(c,c.completed && c.abandoned && c.request.orphanDetach && !c.orphanDetached);
            if (!selected) return selected;
        }
        if (c.completed && !c.outputRead) {
            size_t size=c.result.data.size(),offset=0;
            while (offset<size) {
                auto n=pread(c.memoryFd,c.result.data.data()+offset,size-offset,static_cast<off_t>(c.dataAddress+offset));
                if (n<0 && errno==EINTR) continue;
                if (n<=0) return std::unexpected(n<0 ? error() : std::make_error_code(std::errc::io_error));
                offset+=static_cast<size_t>(n);
            }
            c.outputRead=true;
            if (c.request.orphanDetach && c.result.value==0) {
                if (c.result.data.size()<c.host.pointerWidth) return std::unexpected(invalid());
                auto handle=decodeTargetUnsigned({c.result.data.data(),c.host.pointerWidth},c.host.byteOrder);
                if (!handle || !*handle) return std::unexpected(invalid());
                c.orphanHandle=*handle;
            }
        }
        if (c.workerCode && c.completed && c.result.value==0) {
            auto started=startWorker(c);
            if (!started) return started;
            auto detached=detach(c);
            if (!detached) return detached;
            c.done=true;
            return {};
        }
        if (c.completed && c.abandoned && c.request.orphanDetach && !c.orphanDetached && c.result.value==0) {
            if (!c.orphanHandle) return std::unexpected(invalid());
            if (!c.seized) {
                auto selected=prepare(c);
                if (!selected) return selected;
            }
            if (!c.frame) {
                auto allocated=memory(c,MemorySyscall::Map,{0,c.frameSize,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,UINT64_MAX,0});
                if (!allocated) return allocated;
                auto page=sysconf(_SC_PAGESIZE);
                if (page<=0) return std::unexpected(error());
                // The original payload has already been copied into result.
                // A fresh frame is needed only when a completed unmap was
                // followed by a recovery/detach error before handle delivery.
                c.stackTop=c.frame+c.frameSize-page;
            }
            auto page=sysconf(_SC_PAGESIZE);
            if (page<=0) return std::unexpected(error());
            for (auto [address,protection] : {std::pair<uintptr_t,int>{c.frame,PROT_READ|PROT_EXEC},
                                            {c.frame+page,PROT_NONE},{c.stackTop,PROT_NONE}}) {
                auto guarded=memory(c,MemorySyscall::Protect,{address,static_cast<uint64_t>(page),static_cast<uint64_t>(protection),0,0,0});
                if (!guarded) return guarded;
            }
            auto detached=function(c,c.request.orphanDetach,{c.orphanHandle,0,0,0,0,0,0,0},100);
            if (!detached) {
                c.recovery=detached.error().recovery; c.functionRecovery=true; c.orphanRecovery=true;
                if (detached.error().pendingEvent==PTRACE_EVENT_EXEC || (c.recovery && c.recovery->imageRetired()))
                    return retire(c,detached.error().replacementTask);
                return std::unexpected(detached.error().code);
            }
            int code=static_cast<int32_t>(*detached);
            if (code!=0 && code!=ESRCH && code!=EINVAL) return std::unexpected(std::error_code(code,std::system_category()));
            c.orphanDetached=true;
        }
        if (c.frame) {
            auto freed=memory(c,MemorySyscall::Unmap,{c.frame,c.frameSize,0,0,0,0});
            if (!freed) return freed;
        }
        auto detached=detach(c);
        if (!detached) return detached;
        c.done=true;
        return {};
    }
    static bool ownsCleanup(const Call& c) {
        return c.seized || bool(c.recovery) || c.frame || c.affinityPending;
    }
    Result<void> maintainLease(Call& c) {
        c.done=false;
        if (c.leaseReleased->load(std::memory_order_acquire)) {
            // Handle release cannot release an in-flight call's context or
            // private frame. Drain those resources before forgetting the lease.
            c.orphanDetached=true;
            if (!ownsCleanup(c)) {
                c.done=true;
                if (c.retired) return std::unexpected(std::make_error_code(std::errc::operation_canceled));
                return {};
            }
        } else if (!c.abandoned && !c.threadLease.expired()) return {};
        c.abandoned=true;
        return finish(c);
    }
    // A retained proof recovery does not establish affinity by itself. Retry
    // the original check before replacing the descriptor or touching the frame.
    Result<void> bindMemory(Call& c) {
        auto context=readNativeContext(c.tid);
        if (!context) return std::unexpected(context.error());
        if (c.originImage) {
            auto same=verifyStoppedMemoryImage(c.tid,c.host,*c.originImage);
            if (!same) {
                c.recovery=same.error().recovery;c.functionRecovery=false;c.orphanRecovery=false;
                c.signal=same.error().pendingSignal;
                if (c.signal) {
                    siginfo_t info{};
                    if (ptrace(PTRACE_GETSIGINFO,c.tid,nullptr,&info)==0 && info.si_signo==c.signal) c.signalInfo=info;
                }
                if (same.error().code==std::errc::operation_canceled && !c.recovery) return retire(c);
                // A preflight rejection left this stop unchanged; keep
                // its record but do not unnecessarily freeze the target.
                if (!c.recovery) {
                    auto detached=detach(c);
                    if (!detached) return detached;
                }
                return std::unexpected(same.error().code);
            }
            // The private proof borrows and restores this current stop.
            // Capture the PC again before opening its memory descriptor.
            context=readNativeContext(c.tid);
            if (!context) return std::unexpected(context.error());
        }
        char path[64]; snprintf(path,sizeof(path),"/proc/%ld/mem",static_cast<long>(c.tid));
        int fd=open(path,O_RDWR|O_CLOEXEC);
        c.memoryWritable=fd>=0;
        if (fd<0) fd=open(path,O_RDONLY|O_CLOEXEC);
        if (fd<0) return std::unexpected(error());
        if (!c.originImage) {
            auto origin=NativeMemoryImage::retainStoppedFd(fd,c.identity,c.host);
            if (!origin) {close(fd);return std::unexpected(origin.error());}
            c.originImage=std::move(*origin);
        }
        if (c.memoryFd>=0) close(c.memoryFd);
        c.memoryFd=fd;
        c.originalPc=context->instructionPointer();
        c.affinityPending=false;
        return {};
    }
    Result<void> prepare(Call& c,bool requireFunction=true) {
        std::vector<pid_t> tids{c.identity.pid};
        std::string taskPath="/proc/"+std::to_string(c.identity.pid)+"/task";
        DIR* directory=opendir(taskPath.c_str());
        if (!directory) return std::unexpected(error());
        try {
            while (auto* entry=readdir(directory)) {
                char* end=nullptr;
                long tid=strtol(entry->d_name,&end,10);
                if (*entry->d_name && !*end && tid>0 && tid<=INT32_MAX && tid!=c.identity.pid) tids.push_back(static_cast<pid_t>(tid));
            }
        } catch (...) { closedir(directory); throw; }
        closedir(directory);
        for (pid_t tid : tids) {
            auto checked=image(c);
            if (!checked) return checked;
            auto identity=targetProcessIdentity(tid);
            if (!identity) continue;
            c.tid=tid; c.threadIdentity=*identity;
            if (ptrace(PTRACE_SEIZE,tid,nullptr,reinterpret_cast<void*>(PTRACE_O_TRACEEXEC))<0) continue;
            c.seized=true;
            // Rebind cleanup to the task actually seized, then reject a stale PID.
            auto ownedIdentity=targetProcessIdentity(tid);
            if (!ownedIdentity) return std::unexpected(ownedIdentity.error());
            c.threadIdentity=*ownedIdentity;
            if (*identity!=*ownedIdentity) return std::unexpected(std::make_error_code(std::errc::operation_canceled));
            auto stopped=stop(c);
            if (!stopped) return stopped;
            auto checkedOwned=image(c);
            if (!checkedOwned) return checkedOwned;
            if (c.request.image) {
                auto saved = c.request.image->check();
                if (!saved) return saved;
            }
            auto eligible=requireFunction ? checkStoppedFunctionAbi(tid,c.host) : Result<void>{};
            if (eligible) {
                c.affinityPending=true;
                return bindMemory(c);
            }
            auto detached=detach(c);
            if (!detached) return detached;
        }
        return std::unexpected(std::make_error_code(std::errc::resource_unavailable_try_again));
    }
    Result<void> run(Call& c) {
        auto prepared=prepare(c);
        if (!prepared) return prepared;
        auto page=sysconf(_SC_PAGESIZE);
        if (page<=0) return std::unexpected(error());
        size_t payload=std::max(c.request.data.size(),c.request.outputSize);
        size_t dataPages=std::max<size_t>(1,(payload+page-1)/page);
        size_t stackPages=(1024*1024+page-1)/page;
        c.frameSize=(3+stackPages+dataPages)*page;
        auto mapped=memory(c,MemorySyscall::Map,{0,c.frameSize,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,UINT64_MAX,0});
        if (!mapped) return mapped;
        if (c.request.image) {
            auto identity=processMemoryIdentity(c.tid);
            if (!identity) return std::unexpected(identity.error());
            auto current=NativeMemoryImage::capture(*identity,c.host);
            if (!current) return std::unexpected(current.error());
            auto same=c.request.image->sharesPrivateMapping(**current,c.frame);
            if (!same) return same;
        }
        c.stackTop=c.frame+(2+stackPages)*page;
        c.dataAddress=c.stackTop+page;
        if (c.workerCode) {
            auto written=writeBytes(c,c.frame+64,c.workerCode->code.data(),c.workerCode->code.size());
            if (!written) return written;
        }
        for (auto [address,protection] : {std::pair<uintptr_t,int>{c.frame,PROT_READ|PROT_EXEC},
                                        {c.frame+page,PROT_NONE},{c.stackTop,PROT_NONE}}) {
            auto protectedPage=memory(c,MemorySyscall::Protect,{address,static_cast<uint64_t>(page),static_cast<uint64_t>(protection),0,0,0});
            if (!protectedPage) return protectedPage;
        }
        size_t offset=0;
        while (offset<c.request.data.size()) {
            ssize_t n=0;
            if (c.memoryWritable) n=pwrite(c.memoryFd,c.request.data.data()+offset,c.request.data.size()-offset,static_cast<off_t>(c.dataAddress+offset));
            else {
                long word=0;
                size_t count=std::min(sizeof(word),c.request.data.size()-offset);
                std::memcpy(&word,c.request.data.data()+offset,count);
                if (ptrace(PTRACE_POKEDATA,c.tid,reinterpret_cast<void*>(c.dataAddress+offset),reinterpret_cast<void*>(word))<0)
                    return std::unexpected(error());
                n=static_cast<ssize_t>(count);
            }
            if (n<0 && errno==EINTR) continue;
            if (n<=0) return std::unexpected(n<0 ? error() : std::make_error_code(std::errc::io_error));
            offset+=static_cast<size_t>(n);
        }
        auto arguments=c.request.arguments;
        for (unsigned i=0;i<arguments.size();++i) if (c.request.dataArguments&(1u<<i)) arguments[i]+=c.dataAddress;
        if (c.workerCode) { arguments[2]=c.frame+64; arguments[3]=c.dataAddress+c.host.pointerWidth; }
        auto result=function(c,c.request.function,arguments,c.request.timeoutMs);
        if (!result) {
            c.recovery=result.error().recovery; c.functionRecovery=true;
            if (result.error().pendingEvent==PTRACE_EVENT_EXEC || (c.recovery && c.recovery->imageRetired()))
                return retire(c,result.error().replacementTask);
            if (result.error().completedValue) { c.completed=true; c.result.value=*result.error().completedValue; }
            if (!c.recovery) c.aborted=true;
            return std::unexpected(result.error().code);
        }
        c.completed=true; c.result.value=*result;
        return finish(c);
    }
};

NativeCallOwner::NativeCallOwner() : impl_(std::make_unique<Impl>()) {}
NativeCallOwner::~NativeCallOwner()=default;
std::expected<NativeCallResult,std::error_code> NativeCallOwner::invoke(
    const TargetProcessIdentity& identity,const TargetMachine& host,NativeCallRequest request) {
    if (request.image) {
        if (request.image->identity()!=identity) return std::unexpected(invalid());
        auto live = request.image->check();
        if (!live) return std::unexpected(live.error());
    }
    std::optional<NativeThreadEntry> workerCode;
    if (request.workerEntry) {
        if (!request.orphanDetach || !request.data.empty() || request.outputSize!=host.pointerWidth || request.dataArguments!=1)
            return std::unexpected(invalid());
        auto entry=nativeThreadEntry(host);
        if (!entry) return std::unexpected(entry.error());
        auto control=nativeThreadControl(host,request.workerEntry);
        if (!control) return std::unexpected(control.error());
        request.data.resize(host.pointerWidth);
        request.data.insert(request.data.end(),control->begin(),control->end());
        workerCode=std::move(*entry);
        for (const auto& range : request.workerRanges)
            if (!range.size || range.size-1>UINTPTR_MAX-range.address) return std::unexpected(invalid());
    }
    if (!request.function || request.timeoutMs<0 || request.timeoutMs>60000 || request.data.size()>1024*1024 || request.outputSize>1024*1024)
        return std::unexpected(invalid());
    size_t dataSize=std::max(request.data.size(),request.outputSize);
    for (unsigned i=0;i<request.arguments.size();++i)
        if ((request.dataArguments&(1u<<i)) && request.arguments[i]>=dataSize) return std::unexpected(invalid());
    Key key{identity.pid,identity.startTime};
    auto previous=recover(identity);
    if (!previous) return std::unexpected(previous.error());
    if (impl_->calls.contains(key)) return std::unexpected(std::make_error_code(std::errc::device_or_resource_busy));
    auto call=std::make_unique<Impl::Call>();
    call->identity=identity; call->host=host; call->request=std::move(request);
    call->workerCode=std::move(workerCode);
    if (call->workerCode) {
        call->result.worker=std::make_shared<NativeCallResult::WorkerState>();
        call->workerState=call->result.worker;
    }
    call->result.data.resize(call->request.outputSize);
    if (call->request.orphanDetach) {
        call->result.threadLease=std::make_shared<NativeCallResult::ThreadLease>();
        call->threadLease=call->result.threadLease;
        call->leaseReleased=call->result.threadLease->released;
    }
    auto [position,inserted]=impl_->calls.emplace(key,std::move(call));
    (void)inserted;
    auto& c=*position->second;
    Result<void> executed;
    try {
        if (c.request.orphanDetach) { c.leaseSlot=impl_->leases.insert(impl_->leases.end(),nullptr); c.leaseReserved=true; }
        executed=impl_->run(c);
    }
    catch (const std::bad_alloc&) { executed=std::unexpected(std::make_error_code(std::errc::not_enough_memory)); }
    catch (...) { executed=std::unexpected(std::make_error_code(std::errc::io_error)); }
    if (executed) {
        auto result=std::move(c.result);
        if (c.leaseReserved && c.completed && c.result.value==0 && c.orphanHandle) {
            c.done=false;
            c.workerOwned=bool(c.workerCode);
            *c.leaseSlot=std::move(position->second);
        } else if (c.leaseReserved) impl_->leases.erase(c.leaseSlot);
        impl_->calls.erase(position); return result;
    }
    c.operationError=executed.error(); c.abandoned=true;
    c.result.threadLease.reset();
    if (c.leaseReserved && !c.workerCode) { impl_->leases.erase(c.leaseSlot); c.leaseReserved=false; }
    // Preparation can fail without ever entering a function. Its private frame
    // still belongs to this record until every syscall recovery and detach succeeds.
    if (!c.functionRecovery) c.aborted=true;
    if (!c.recovery || !c.functionRecovery) {
        auto cleanup=impl_->finish(c);
        if (!cleanup && gone(cleanup.error())) c.done=true;
    }
    auto reported=c.operationError;
    if (c.done) {
        if (c.workerStarted && c.frame) {
            c.workerOwned=true; c.done=false;
            *c.leaseSlot=std::move(position->second);
        } else if (c.leaseReserved) impl_->leases.erase(c.leaseSlot);
        impl_->calls.erase(position);
    }
    return std::unexpected(reported);
}
Result<void> NativeCallOwner::recover(const TargetProcessIdentity& identity) {
    auto found=impl_->calls.find({identity.pid,identity.startTime});
    if (found!=impl_->calls.end()) {
        auto result=impl_->finish(*found->second);
        if (found->second->done) {
            auto& c=*found->second;
            if (c.workerStarted && c.frame) {
                c.workerOwned=true; c.done=false;
                *c.leaseSlot=std::move(found->second);
            } else if (c.leaseReserved) impl_->leases.erase(c.leaseSlot);
            impl_->calls.erase(found);
        }
        if (!result) return result;
    }
    for (auto it=impl_->leases.begin();it!=impl_->leases.end();) {
        if (!*it) { ++it; continue; }
        auto& call=**it;
        if (call.identity.pid!=identity.pid || call.identity.startTime!=identity.startTime) { ++it; continue; }
        if (call.workerOwned) {
            auto result=impl_->finish(call);
            bool ownsStop=call.seized || bool(call.recovery);
            if (call.done) it=impl_->leases.erase(it); else ++it;
            if (!result && ownsStop) return result;
            continue;
        }
        auto result=impl_->maintainLease(call);
        if (call.done) it=impl_->leases.erase(it); else ++it;
        if (!result) return result;
    }
    return {};
}
Result<void> NativeCallOwner::resume(const TargetProcessIdentity& identity,bool deliverSignal) {
    auto found=impl_->calls.find({identity.pid,identity.startTime});
    Impl::Call* call=found!=impl_->calls.end() ? found->second.get() : nullptr;
    if (!call) for (auto& lease : impl_->leases) {
        if (lease && lease->identity.pid==identity.pid && lease->identity.startTime==identity.startTime &&
            lease->recovery && lease->functionRecovery) { call=lease.get();break; }
    }
    if (!call || !call->recovery || !call->functionRecovery) return std::unexpected(invalid());
    auto result=call->recovery->resumeFunction(deliverSignal);
    if (call->recovery->imageRetired()) {
        auto retired=impl_->retire(*call);
        if (!retired && retired.error()!=std::errc::operation_canceled) return retired;
        return recover(identity);
    }
    if (!result) return result;
    return recover(identity);
}

void NativeCallOwner::recoverAll() {
    for (auto it=impl_->calls.begin();it!=impl_->calls.end();) {
        Result<void> result;
        try { result=impl_->finish(*it->second); }
        catch (...) { result=std::unexpected(std::make_error_code(std::errc::not_enough_memory)); }
        if (it->second->done) {
            auto& c=*it->second;
            if (c.workerStarted && c.frame) {
                c.workerOwned=true; c.done=false;
                *c.leaseSlot=std::move(it->second);
            } else if (c.leaseReserved) impl_->leases.erase(c.leaseSlot);
            it=impl_->calls.erase(it);
        } else ++it;
    }
    for (auto it=impl_->leases.begin();it!=impl_->leases.end();) {
        if (!*it) { ++it; continue; }
        auto& call=**it;
        if (call.workerOwned) {
            try { (void)impl_->finish(call); } catch (...) {}
            if (call.done) it=impl_->leases.erase(it); else ++it;
            continue;
        }
        try { (void)impl_->maintainLease(call); } catch (...) {}
        if (call.done) it=impl_->leases.erase(it); else ++it;
    }
}
bool NativeCallOwner::pending(pid_t pid,uint64_t start) const {
    if (impl_->calls.contains({pid,start})) return true;
    for (const auto& pointer : impl_->leases) if (pointer && pointer->identity.pid==pid && pointer->identity.startTime==start &&
        (pointer->workerOwned ? (pointer->seized || bool(pointer->recovery)) :
        (Impl::ownsCleanup(*pointer) || (!pointer->leaseReleased->load(std::memory_order_acquire) &&
         (pointer->abandoned || pointer->threadLease.expired()))))) return true;
    return false;
}
bool NativeCallOwner::empty() const { return impl_->calls.empty() && impl_->leases.empty(); }
void NativeCallOwner::releaseDetachedWorkersAtProcessExit() {
    for (auto it=impl_->leases.begin();it!=impl_->leases.end();) {
        if (*it && (*it)->workerOwned && !(*it)->seized && !(*it)->recovery)
            it=impl_->leases.erase(it);
        else ++it;
    }
}
bool NativeCallOwner::busy(pid_t pid,uintptr_t address,size_t size) const {
    if (!size) return false;
    auto overlap=[&](uintptr_t base,size_t length) {
        return length && (base<=address ? address-base<length : base-address<size);
    };
    auto pinned=[&](const Impl::Call& call) {
        if (call.identity.pid!=pid || !call.workerCode) return false;
        if (call.workerState->exited.load(std::memory_order_acquire) && !call.seized && !call.recovery) return false;
        if (call.frame && overlap(call.frame,call.frameSize)) return true;
        for (const auto& range : call.request.workerRanges) if (overlap(range.address,range.size)) return true;
        return false;
    };
    for (const auto& [key,call] : impl_->calls) if (pinned(*call)) return true;
    for (const auto& call : impl_->leases) if (call && pinned(*call)) return true;
    return false;
}
} // namespace ce::os
