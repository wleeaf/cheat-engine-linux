#include "platform/linux/arm64_vector_return.hpp"
#if defined(__aarch64__)
#include <algorithm>
#include <asm/sigcontext.h>
#include <asm/ucontext.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <fstream>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

namespace ce::os {
namespace {
Error kernelError() { return {errno,std::system_category()}; }
Error unsupported() { return std::make_error_code(std::errc::not_supported); }
Error failedRestore() { return std::make_error_code(std::errc::state_not_recoverable); }
constexpr size_t frameSize=4688,reservedOffset=592;
constexpr size_t stackOffset=144,maskOffset=168,registerOffset=312;
constexpr uint32_t fpMagic=0x46508001,sveMagic=0x53564501,extraMagic=0x45585401;
constexpr uint32_t zaMagic=0x54366345,ztMagic=0x5a544e01,fpmrMagic=0x46504d52,poeMagic=0x504f4530;
static_assert(sizeof(siginfo_t)==128 && sizeof(user_pt_regs)==272);
static_assert(128+offsetof(ucontext,uc_stack)==stackOffset);
static_assert(128+offsetof(ucontext,uc_sigmask)==maskOffset);
static_assert(128+offsetof(ucontext,uc_mcontext)+offsetof(sigcontext,regs)==registerOffset);
static_assert(128+offsetof(ucontext,uc_mcontext)+offsetof(sigcontext,__reserved)==reservedOffset);
static_assert(128+sizeof(ucontext)==frameSize && sizeof(fpsimd_context)==528);
size_t align16(size_t size) { return (size+15)&~size_t{15}; }
template<class T> T read(const uint8_t* at) { T value; std::memcpy(&value,at,sizeof(value)); return value; }
template<class T> void put(std::vector<uint8_t>& data,size_t offset,T value) {
    std::memcpy(data.data()+offset,&value,sizeof(value));
}
const NativeExtendedContext::Regset* find(const NativeExtendedContext& saved,unsigned note) {
    for (const auto& image : saved.regsets) if (image.note==note) return &image;
    return nullptr;
}
bool live(const NativeExtendedContext::Regset* image) {
    return image && image->bytes.size()>16 && (read<uint16_t>(image->bytes.data()+12)&1);
}
bool readMemory(int fd,uintptr_t at,std::vector<uint8_t>& bytes) {
    size_t done=0;
    while (done<bytes.size()) {
        ssize_t count=pread(fd,bytes.data()+done,bytes.size()-done,static_cast<off_t>(at+done));
        if (count<0 && errno==EINTR) continue;
        if (count<=0) { if (!count) errno=EIO; return false; }
        done+=static_cast<size_t>(count);
    }
    return true;
}
bool writeMemory(pid_t tid,int memoryFd,bool writable,uintptr_t at,const std::vector<uint8_t>& bytes) {
    if (writable) {
        size_t done=0;
        while (done<bytes.size()) {
            ssize_t count=pwrite(memoryFd,bytes.data()+done,bytes.size()-done,static_cast<off_t>(at+done));
            if (count<0 && errno==EINTR) continue;
            if (count<=0) { if (!count) errno=EIO; return false; }
            done+=static_cast<size_t>(count);
        }
        return true;
    }
    for (size_t offset=0;offset<bytes.size();offset+=sizeof(long)) {
        long word=read<long>(bytes.data()+offset);
        if (ptrace(PTRACE_POKEDATA,tid,reinterpret_cast<void*>(at+offset),reinterpret_cast<void*>(word))<0)
            return false;
    }
    return true;
}
bool sameRegisters(user_pt_regs actual,user_pt_regs expected) {
    actual.pstate&=~(uint64_t{1}<<21); expected.pstate&=~(uint64_t{1}<<21);
    return std::memcmp(&actual,&expected,sizeof(actual))==0;
}
}

Result<std::optional<Arm64VectorReturn>> Arm64VectorReturn::prepare(
    pid_t tid,int memoryFd,uintptr_t syscallSite,const user_pt_regs& registers,int originalSyscall,
    const NativeExtendedContext& saved,MemorySyscall operation,const std::array<uint64_t,6>& arguments) {
    const auto* ssve=find(saved,0x40b);
    bool streaming=live(ssve);
    const auto* vector=streaming ? ssve : find(saved,0x405);
    if (!live(vector)) return std::optional<Arm64VectorReturn>{};
    // rt_sigreturn clears restart_block. A live user-mode bank requires no
    // syscall in progress; never use this path to recover a parked syscall.
    if (originalSyscall!=-1) return std::unexpected(unsupported());
    const auto* gcs=find(saved,0x410);
    if (gcs && (gcs->bytes.size()<8 || (read<uint64_t>(gcs->bytes.data())&1)))
        return std::unexpected(unsupported());
    // A filter can permit mmap but deny rt_sigreturn irreversibly. Until a
    // userspace restoration backend exists, reject before mutating that task.
    std::ifstream status("/proc/"+std::to_string(tid)+"/status");
    std::string line;
    bool policyKnown=false;
    while (std::getline(status,line)) if (line.starts_with("Seccomp:")) {
        unsigned policy=1;
        if (std::sscanf(line.c_str(),"Seccomp: %u",&policy)!=1 || policy)
            return std::unexpected(unsupported());
        policyKnown=true; break;
    }
    if (!policyKnown) return std::unexpected(unsupported());
    const auto* fp=find(saved,NT_PRFPREG);
    if (!fp || fp->bytes.size()!=sizeof(user_fpsimd_state)) return std::unexpected(unsupported());
    uint16_t vl=read<uint16_t>(vector->bytes.data()+8);
    if (!vl || vl%16 || vl>256) return std::unexpected(unsupported());
    size_t payload=32*size_t(vl)+17*(size_t(vl)/8);
    if (vector->bytes.size()<16+payload) return std::unexpected(unsupported());
    std::vector<uint8_t> records;
    auto append=[&](uint32_t magic,size_t size) {
        size_t offset=records.size();
        records.resize(offset+align16(size));
        put(records,offset,magic); put(records,offset+4,static_cast<uint32_t>(align16(size)));
        return offset;
    };
    size_t vectorOffset=append(sveMagic,16+payload);
    put(records,vectorOffset+8,vl);
    put(records,vectorOffset+10,uint16_t(streaming ? 1 : 0));
    std::memcpy(records.data()+vectorOffset+16,vector->bytes.data()+16,payload);
    if (const auto* za=find(saved,0x40c)) {
        if (za->bytes.size()<16) return std::unexpected(unsupported());
        size_t at=append(zaMagic,za->bytes.size());
        put(records,at+8,read<uint16_t>(za->bytes.data()+8));
        std::memcpy(records.data()+at+16,za->bytes.data()+16,za->bytes.size()-16);
        if (za->bytes.size()>16) if (const auto* zt=find(saved,0x40d)) {
            if (zt->bytes.size()!=64) return std::unexpected(unsupported());
            at=append(ztMagic,80); put(records,at+8,uint16_t{1});
            std::memcpy(records.data()+at+16,zt->bytes.data(),zt->bytes.size());
        }
    }
    for (auto [note,magic] : {std::pair{0x40eu,fpmrMagic},std::pair{0x40fu,poeMagic}}) {
        if (const auto* image=find(saved,note)) {
            if (image->bytes.size()!=8) return std::unexpected(unsupported());
            size_t at=append(magic,16);
            std::memcpy(records.data()+at+8,image->bytes.data(),8);
        }
    }
    records.resize(records.size()+16); // Extension-list terminator.
    bool extra=528+records.size()>4096;
    size_t dataOffset=reservedOffset+528+(extra ? 48 : 0);
    Arm64VectorReturn state;
    state.frame.resize(std::max(frameSize,align16(dataOffset+records.size())));
    // AArch64 has no stack red zone. Borrow below SP, back up every byte and
    // restore it before detaching; tagged SP is preserved in the saved GP bank.
    uintptr_t sp=registers.sp & UINT64_C(0x00ffffffffffffff);
    if (sp<state.frame.size()+16) return std::unexpected(unsupported());
    state.address=(sp-state.frame.size())&~uintptr_t{15};
    state.syscallAddress=syscallSite;
    int openFlags=fcntl(memoryFd,F_GETFL);
    if (openFlags<0) return std::unexpected(kernelError());
    state.memoryWritable=(openFlags&O_ACCMODE)==O_RDWR;
    std::ifstream maps("/proc/"+std::to_string(tid)+"/maps");
    bool kernelStack=false;
    while (std::getline(maps,line)) {
        unsigned long long start=0,end=0,offset=0,inode=0;
        unsigned major=0,minor=0;
        int nameOffset=0;
        char permissions[5]{};
        if (std::sscanf(line.c_str(),"%llx-%llx %4s %llx %x:%x %llu %n",&start,&end,permissions,
            &offset,&major,&minor,&inode,&nameOffset)!=7 || start>=end) continue;
        // Writable memory alone does not prove stack ownership. A coroutine
        // or alternate stack can occupy one small allocation in a large heap
        // mapping. Never borrow outside a kernel-labelled main-stack VMA.
        if (!inode && !major && !minor && line.substr(static_cast<size_t>(nameOffset))=="[stack]" &&
            permissions[0]=='r' && permissions[1]=='w' && start<=state.address && sp<=end) {
            kernelStack=true; break;
        }
    }
    if (!kernelStack) return std::unexpected(unsupported());
    auto pageSize=sysconf(_SC_PAGESIZE);
    if (pageSize<=0) return std::unexpected(kernelError());
    bool destructive=operation==MemorySyscall::Unmap ||
        (operation==MemorySyscall::Protect && !(arguments[2]&PROT_READ)) ||
        (operation==MemorySyscall::Map && (arguments[3]&MAP_FIXED));
    if (destructive && arguments[1]) {
        uint64_t page=static_cast<uint64_t>(pageSize);
        if (arguments[0]>UINT64_MAX-arguments[1] || arguments[0]+arguments[1]>UINT64_MAX-(page-1))
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        uint64_t end=(arguments[0]+arguments[1]+page-1)/page*page;
        if (arguments[0]<sp && end>state.address)
            return std::unexpected(std::make_error_code(std::errc::operation_not_permitted));
    }
    if (ptrace(PTRACE_GETSIGMASK,tid,reinterpret_cast<void*>(sizeof(state.signalMask)),&state.signalMask)<0)
        return std::unexpected(kernelError());
    put(state.frame,maskOffset,state.signalMask);
    std::memcpy(state.frame.data()+registerOffset,&registers,sizeof(registers));
    // A zero-size non-disabled alternate stack is rejected before any change.
    // Linux restore_altstack squashes that validation error, preserving the
    // current alternate stack, including SS_AUTODISARM and on-stack state.
    // Validate this behavior with a real configured alternate-stack fixture.
    put(state.frame,reservedOffset,fpMagic); put(state.frame,reservedOffset+4,uint32_t{528});
    std::memcpy(state.frame.data()+reservedOffset+8,fp->bytes.data()+512,8);
    std::memcpy(state.frame.data()+reservedOffset+16,fp->bytes.data(),512);
    if (extra) {
        put(state.frame,reservedOffset+528,extraMagic);
        put(state.frame,reservedOffset+532,uint32_t{32});
        put(state.frame,reservedOffset+536,uint64_t(state.address+dataOffset));
        put(state.frame,reservedOffset+544,static_cast<uint32_t>(records.size()));
    }
    std::memcpy(state.frame.data()+dataOffset,records.data(),records.size());
    state.original.resize(state.frame.size()); state.verification.resize(state.frame.size());
    if (!readMemory(memoryFd,state.address,state.original)) return std::unexpected(kernelError());
    return std::optional<Arm64VectorReturn>{std::move(state)};
}

Result<void> Arm64VectorReturn::restore(pid_t tid,int memoryFd,const user_pt_regs& registers,
    NativeExtendedContext& saved,int& pendingSignal,std::optional<siginfo_t>& pendingInfo,
    bool& pendingStepTrap,uintptr_t& stepEnd) {
    if (!contextRestored && verifyNativeExtendedContext(tid,saved)) contextRestored=true;
    if (!contextRestored) {
        frameChanged=true; // Even a failed kernel write can have changed bytes.
        if (!writeMemory(tid,memoryFd,memoryWritable,address,frame)) return std::unexpected(failedRestore());
        user_pt_regs injected=registers; injected.pc=syscallAddress; injected.sp=address;
        injected.regs[8]=139; // Linux AArch64 rt_sigreturn.
        iovec io{&injected,sizeof(injected)};
        if (ptrace(PTRACE_SETREGSET,tid,reinterpret_cast<void*>(NT_PRSTATUS),&io)<0)
            return std::unexpected(failedRestore());
        int none=-1; io={&none,sizeof(none)};
        if (ptrace(PTRACE_SETREGSET,tid,reinterpret_cast<void*>(NT_ARM_SYSTEM_CALL),&io)<0)
            return std::unexpected(failedRestore());
        if (ptrace(PTRACE_SINGLESTEP,tid,nullptr,nullptr)<0) return std::unexpected(failedRestore());
        int status=0;
        pid_t waited;
        do { waited=waitpid(tid,&status,__WALL); } while (waited<0 && errno==EINTR);
        if (waited!=tid || !WIFSTOPPED(status))
            return std::unexpected(std::make_error_code(std::errc::no_such_process));
        if ((status>>16)!=0) return std::unexpected(failedRestore());
        siginfo_t info{};
        if (ptrace(PTRACE_GETSIGINFO,tid,nullptr,&info)<0) return std::unexpected(failedRestore());
        user_pt_regs actual{}; io={&actual,sizeof(actual)};
        if (ptrace(PTRACE_GETREGSET,tid,reinterpret_cast<void*>(NT_PRSTATUS),&io)<0 || io.iov_len!=sizeof(actual))
            return std::unexpected(failedRestore());
        bool ownTrap=WSTOPSIG(status)==SIGTRAP && info.si_signo==SIGTRAP &&
            (info.si_code==TRAP_TRACE || (info.si_code==SI_USER && !info.si_pid && !info.si_uid));
        if (!ownTrap) {
            if (WSTOPSIG(status)==SIGSYS && info.si_code>0 && info.si_syscall==139) {
                pendingStepTrap=true; stepEnd=syscallAddress+4;
            } else { pendingSignal=WSTOPSIG(status); pendingInfo=info; }
            return std::unexpected(failedRestore());
        }
        if (!sameRegisters(actual,registers) || !verifyNativeExtendedContext(tid,saved))
            return std::unexpected(failedRestore());
        uint64_t actualMask=0;
        if (ptrace(PTRACE_GETSIGMASK,tid,reinterpret_cast<void*>(sizeof(actualMask)),&actualMask)<0 || actualMask!=signalMask)
            return std::unexpected(failedRestore());
        contextRestored=true;
    }
    if (frameChanged) {
        if (!writeMemory(tid,memoryFd,memoryWritable,address,original) ||
            !readMemory(memoryFd,address,verification) || verification!=original)
            return std::unexpected(failedRestore());
        frameChanged=false;
    }
    return {};
}

} // namespace ce::os
#endif
