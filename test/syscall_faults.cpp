// Link-time interposition is confined to the integration test executable.
// All non-failing requests reach the real kernel; no product fault controls.
#include "test/syscall_faults.hpp"
#include <cstdarg>
#include <cstddef>
#include <chrono>
#include <cerrno>
#include <csignal>
#include <atomic>
#include <new>
#include <sched.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <cstdio>
#include <cstring>
#include <elf.h>
#include <unistd.h>
#if defined(__x86_64__)
#include <sys/user.h>
#elif defined(__aarch64__)
#include <asm/ptrace.h>
#endif

namespace syscall_test {
static std::atomic<Fault> current{Fault::None};
static thread_local bool stepped;
static thread_local bool contextReturnStarted;
static thread_local bool functionContinued;
static thread_local uintptr_t functionWaitingPointer;
static std::atomic<unsigned> failures{0};
static std::atomic<unsigned> steps{0};
static thread_local bool failAllocation;
static thread_local uintptr_t savedPc;
static thread_local bool resultSaved;
static std::atomic<uint64_t> returnedValue{0};
static std::atomic<unsigned> hardwareWrites{0};
static std::atomic<unsigned> textWrites{0};
static std::atomic<pid_t> seizedPid{0};
static std::atomic<pid_t> watchedAllocator{0};
static std::atomic<bool> observedAllocation{false};
static std::atomic<pid_t> heldDetachTid{0};
static std::atomic<bool> detachReached{false}, detachReleased{true};
static std::atomic<pid_t> hardwareRaceTid{0};
static std::atomic<uintptr_t> hardwareRaceAddress{0};
static std::atomic<int> hardwareRaceSignal{0};
static std::atomic<bool> hardwareRaceSeen{false};
void arm(Fault fault) { current=fault; stepped=false; contextReturnStarted=false; failures=0; hardwareWrites=0; textWrites=0;
    steps=0; seizedPid=0; functionContinued=false; functionWaitingPointer=0; failAllocation=fault==Fault::AllocationBeforeSeize; }
void clear() { current=Fault::None; stepped=false; failAllocation=false; hardwareRaceTid=0; }
uintptr_t originalPc() { return savedPc; }
unsigned triggered() { return failures; }
unsigned singleSteps() { return steps; }
uint64_t completedResult() { return returnedValue; }
void watchAllocation(pid_t tid) { observedAllocation=false; watchedAllocator=tid; }
bool allocationObserved() { return observedAllocation; }
void holdAfterDetach(pid_t tid) { detachReached=false; detachReleased=false; heldDetachTid=tid; }
bool detachHeld() { return detachReached; }
void releaseDetach() { detachReleased=true; }
void queueHardwareRace(pid_t tid,uintptr_t address,int signal) {
    hardwareRaceSeen=false;hardwareRaceAddress=address;hardwareRaceSignal=signal;hardwareRaceTid=tid;
}
bool hardwareRaceObserved() {return hardwareRaceSeen;}
}
extern "C" long __real_ptrace(enum __ptrace_request, ...);
extern "C" pid_t __real_waitpid(pid_t,int*,int);
extern "C" pid_t __wrap_waitpid(pid_t pid,int* status,int options) {
    using namespace syscall_test;
    auto result=__real_waitpid(pid,status,options);
    if (pid<=0 || !status || !(options&WNOHANG) || hardwareRaceTid!=pid) return result;
    hardwareRaceTid=0;
#if defined(__x86_64__)
    struct RaceAffinity {
        pid_t target;cpu_set_t ownerMask{},targetMask{};bool ownerChanged=false,targetChanged=false;
        explicit RaceAffinity(pid_t tid):target(tid) {
            if (sched_getaffinity(0,sizeof(ownerMask),&ownerMask) || sched_getaffinity(target,sizeof(targetMask),&targetMask)) return;
            int targetCpu=-1,ownerCpu=-1;
            for (int cpu=0;cpu<CPU_SETSIZE;++cpu) {
                if (targetCpu<0 && CPU_ISSET(cpu,&targetMask) && CPU_ISSET(cpu,&ownerMask)) targetCpu=cpu;
                else if (targetCpu>=0 && CPU_ISSET(cpu,&ownerMask)) {ownerCpu=cpu;break;}
            }
            if (ownerCpu<0) return;
            cpu_set_t targetOne{},ownerOne{};CPU_SET(targetCpu,&targetOne);CPU_SET(ownerCpu,&ownerOne);
            targetChanged=sched_setaffinity(target,sizeof(targetOne),&targetOne)==0;
            if (targetChanged) ownerChanged=sched_setaffinity(0,sizeof(ownerOne),&ownerOne)==0;
            if (ownerChanged) std::printf("HARDWARE_RACE_CPUS target=%d owner=%d\n",targetCpu,ownerCpu);
        }
        ~RaceAffinity() {
            if (targetChanged) sched_setaffinity(target,sizeof(targetMask),&targetMask);
            if (ownerChanged) sched_setaffinity(0,sizeof(ownerMask),&ownerMask);
        }
    } affinity(pid);
#endif
    // The interrupt must race actual execution on another CPU. Scheduler
    // migration otherwise makes many attempts unable to produce this stop.
    if (!result) {
        // Cleanup may already have consumed a hardware delivery stop. An
        // INTERRUPT of that stopped task produces no new wait event until it
        // resumes; do not wait forever for an event that cannot arrive.
        siginfo_t stopped{};
        if (__real_ptrace(PTRACE_GETSIGINFO,pid,nullptr,&stopped)==0) {
            if (stopped.si_signo!=SIGTRAP || (stopped.si_code!=TRAP_HWBKPT &&
                stopped.si_code!=((PTRACE_EVENT_STOP<<8)|SIGTRAP))) return result;
            if (__real_ptrace(PTRACE_CONT,pid,nullptr,nullptr)<0) return result;
        }
        if (__real_ptrace(PTRACE_INTERRUPT,pid,nullptr,nullptr)<0) return result;
        result=__real_waitpid(pid,status,__WALL|__WNOTHREAD);
    }
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
    for (unsigned attempt=0;result==pid && WIFSTOPPED(*status) &&
         std::chrono::steady_clock::now()<deadline;++attempt) {
        const auto event=*status>>16;
        siginfo_t current{};
        if (__real_ptrace(PTRACE_GETSIGINFO,pid,nullptr,&current)<0) return result;
        if (event!=PTRACE_EVENT_STOP && !(event==0 && current.si_signo==SIGTRAP && current.si_code==TRAP_HWBKPT)) return result;
        struct {uint64_t offset;uint32_t flags;int32_t count;} peek{0,0,32};
        siginfo_t pending[32]{};
        auto count=__real_ptrace(PTRACE_PEEKSIGINFO,pid,&peek,pending);
        for (long index=0;index<count;++index) {
            if (pending[index].si_signo!=SIGTRAP || pending[index].si_code!=TRAP_HWBKPT) continue;
#if defined(__x86_64__)
            errno=0;
            auto dr6=__real_ptrace(PTRACE_PEEKUSER,pid,
                reinterpret_cast<void*>(offsetof(struct user,u_debugreg)+6*sizeof(unsigned long)),nullptr);
            if ((dr6==-1 && errno) || !(dr6&1)) continue;
#elif defined(__aarch64__)
            if (reinterpret_cast<uintptr_t>(pending[index].si_addr)!=hardwareRaceAddress) continue;
#endif
            if (event!=PTRACE_EVENT_STOP) continue;
            hardwareRaceSeen=true;
            printf("HARDWARE_TEARDOWN_RACE event=interrupt queuedSignal=%d queuedCode=%d attempts=%u applicationSignal=%d\n",
                   pending[index].si_signo,pending[index].si_code,attempt+1,hardwareRaceSignal.load());
            if (hardwareRaceSignal) kill(pid,hardwareRaceSignal);
            return result;
        }
        // Run only between real kernel stops. No siginfo or wait status is
        // fabricated; the test returns only after observing the actual race.
        if (__real_ptrace(PTRACE_CONT,pid,nullptr,nullptr)<0) return result;
        // Interrupt immediately on the other CPU. Sleeping first lets the
        // target enter its delivery stop before the interrupt can race it.
#if defined(__aarch64__)
        // ARM watchpoints stop before their access. Let the emulated target
        // reach that access instead of repeatedly interrupting its wakeup.
        if (attempt%3==0) sched_yield(); else usleep(attempt%3);
#else
        if (attempt%64==63) sched_yield();
#endif
        if (__real_ptrace(PTRACE_INTERRUPT,pid,nullptr,nullptr)<0) return result;
        result=__real_waitpid(pid,status,__WALL|__WNOTHREAD);
    }
    if (!hardwareRaceSeen) std::printf("HARDWARE_TEARDOWN_RACE_MISSING tid=%d result=%d status=%x errno=%d\n",pid,result,*status,errno);
    return result;
}
extern "C" long __wrap_ptrace(enum __ptrace_request request, ...) {
    using namespace syscall_test;
    va_list args;
    va_start(args,request);
    pid_t pid=va_arg(args,pid_t);
    void* address=va_arg(args,void*);
    void* data=va_arg(args,void*);
    va_end(args);
    if (request==PTRACE_SEIZE) { stepped=false; resultSaved=false; contextReturnStarted=false; }
    bool preflightRegisters=false;
#if defined(__x86_64__)
    preflightRegisters=request==PTRACE_GETREGS;
#elif defined(__aarch64__)
    preflightRegisters=request==PTRACE_GETREGSET && reinterpret_cast<uintptr_t>(address)==NT_PRSTATUS;
#endif
    if ((current==Fault::InterruptFailure && request==PTRACE_INTERRUPT) ||
        (current==Fault::PreflightRegistersAndDetach && preflightRegisters) ||
        ((current==Fault::PreflightDetach || current==Fault::PreflightRegistersAndDetach ||
          current==Fault::PreflightAllocationAndDetach || current==Fault::MetadataAfterSeize) && request==PTRACE_DETACH)) {
        ++failures; errno=EIO; return -1;
    }
    if (current==Fault::ForbidTextWrite && request==PTRACE_POKETEXT) {
        ++failures; errno=EIO; return -1;
    }
    if (current==Fault::SoftwareVerifyAndRestore) {
        if (request==PTRACE_PEEKTEXT && textWrites>0) { ++failures; errno=EIO; return -1; }
        if (request==PTRACE_POKETEXT) ++textWrites;
    }
    bool registerWrite=false;
    bool hardwareWrite=false;
#if defined(__x86_64__)
    registerWrite=request==PTRACE_SETREGS;
    hardwareWrite=request==PTRACE_POKEUSER;
#elif defined(__aarch64__)
    registerWrite=request==PTRACE_SETREGSET && reinterpret_cast<uintptr_t>(address)==NT_PRSTATUS;
    hardwareWrite=request==PTRACE_SETREGSET &&
        (reinterpret_cast<uintptr_t>(address)==NT_ARM_HW_BREAK || reinterpret_cast<uintptr_t>(address)==NT_ARM_HW_WATCH);
#endif
    bool initialMutation=current==Fault::InitialInstructionWrite && request==PTRACE_POKETEXT;
    if (!failures && functionContinued &&
        ((current==Fault::FunctionReturnRead && preflightRegisters) ||
         (current==Fault::FunctionReturnOpcode && request==PTRACE_PEEKTEXT))) {
        ++failures; errno=EIO; return -1;
    }
    if (current==Fault::FunctionInterruptRace && request==PTRACE_CONT && !functionContinued) {
#if defined(__x86_64__)
        user_regs_struct registers{};
        if (__real_ptrace(PTRACE_GETREGS,pid,nullptr,&registers)==0) {
            if ((registers.cs&0xff)==0x23) {
                errno=0;
                long word=__real_ptrace(PTRACE_PEEKDATA,pid,reinterpret_cast<void*>(registers.rsp),nullptr);
                if (word!=-1 || !errno) functionWaitingPointer=static_cast<uint32_t>(word);
            } else functionWaitingPointer=registers.rdi;
        }
#elif defined(__aarch64__)
        user_pt_regs registers{}; iovec io{&registers,sizeof(registers)};
        if (__real_ptrace(PTRACE_GETREGSET,pid,reinterpret_cast<void*>(NT_PRSTATUS),&io)==0)
            functionWaitingPointer=registers.regs[0];
#endif
    }
    if (current==Fault::FunctionInterruptRace && request==PTRACE_INTERRUPT && functionContinued && !failures && functionWaitingPointer) {
        uint32_t zero=0;
        iovec local{&zero,sizeof(zero)},remote{reinterpret_cast<void*>(functionWaitingPointer),sizeof(zero)};
        if (process_vm_writev(pid,&local,1,&remote,1,0)==sizeof(zero)) {
            // Let the real callee return and queue its hardware trap before
            // the owner's real timeout interrupt reaches the kernel.
            usleep(20000); ++failures;
        }
    }
    if (current==Fault::FunctionRestoreRegisters && functionContinued && registerWrite) {
        ++failures; errno=EIO; return -1;
    }
    if (request==PTRACE_CONT) functionContinued=true;
    initialMutation=initialMutation || (current==Fault::InitialRegistersWrite && registerWrite);
#if defined(__aarch64__)
    if (current==Fault::InitialSyscallWrite && request==PTRACE_SETREGSET &&
        reinterpret_cast<uintptr_t>(address)==NT_ARM_SYSTEM_CALL && !stepped && !failures) {
        int changed=0; iovec io{&changed,sizeof(changed)};
        long applied=__real_ptrace(request,pid,address,&io);
        if (applied<0) return applied;
        ++failures; errno=EIO; return -1;
    }
#endif
    if (initialMutation && !stepped && !failures) {
        long applied=__real_ptrace(request,pid,address,data);
        if (applied<0) return applied;
        ++failures; errno=EIO; return -1;
    }
    if (hardwareWrite && current==Fault::HardwareCleanupFailure) {
        ++failures; errno=EIO; return -1;
    }
    if (hardwareWrite && (current==Fault::HardwareWriteOnce || current==Fault::HardwareRestoreFailure)) {
        unsigned index=hardwareWrites++;
        if (index==1 || (index>1 && current==Fault::HardwareRestoreFailure)) {
            // Exercise an error reported after target mutation, so cleanup
            // must restore a changed bank rather than an already safe no-op.
            if (index==1) __real_ptrace(request,pid,address,data);
            ++failures; errno=EIO; return -1;
        }
    }
    if (stepped && ((current==Fault::RestoreRegisters && registerWrite) ||
                    (current==Fault::RestoreExtended && request==PTRACE_SETREGSET &&
                     reinterpret_cast<uintptr_t>(address)!=NT_PRSTATUS && !hardwareWrite) ||
                    (current==Fault::RestoreInstruction && request==PTRACE_POKETEXT) ||
                    (current==Fault::Detach && request==PTRACE_DETACH) ||
                    (request==PTRACE_POKEDATA && (current==Fault::FrameWriteFailure ||
                     (current==Fault::FrameRestoreFailure && contextReturnStarted))))) {
        ++failures; errno=EIO; return -1;
    }
    if (request==PTRACE_SINGLESTEP) {
        ++steps;
#if defined(__aarch64__)
        user_pt_regs registers{}; iovec io{&registers,sizeof(registers)};
        if (__real_ptrace(PTRACE_GETREGSET,pid,reinterpret_cast<void*>(NT_PRSTATUS),&io)==0 &&
            io.iov_len==sizeof(registers) && registers.regs[8]==139) contextReturnStarted=true;
#endif
        stepped=true;
        if(current==Fault::UserTrap) { ++failures; kill(pid,SIGTRAP); }
        if(current==Fault::IgnoredStepSignal) { ++failures; kill(pid,SIGWINCH); }
    }
    long result=__real_ptrace(request,pid,address,data);
    if (!result && request==PTRACE_DETACH && heldDetachTid==pid) {
        // Hold only userspace bookkeeping after the actual kernel detach. This
        // lets a parent consume the real renamed nonleader EXEC notification.
        heldDetachTid=0; detachReached=true;
        while (!detachReleased) usleep(1000);
    }
    if (!result && request==PTRACE_SEIZE) seizedPid=pid;
    if (!result && request==PTRACE_SEIZE && current==Fault::PreflightAllocationAndDetach) failAllocation=true;
    if (!result && stepped && !resultSaved) {
#if defined(__x86_64__)
        if(request==PTRACE_GETREGS) { returnedValue=static_cast<user_regs_struct*>(data)->rax; resultSaved=true; }
#elif defined(__aarch64__)
        if(request==PTRACE_GETREGSET && reinterpret_cast<uintptr_t>(address)==NT_PRSTATUS) {
            auto* io=static_cast<iovec*>(data);
            if(io->iov_len==sizeof(user_pt_regs)) { returnedValue=static_cast<user_pt_regs*>(io->iov_base)->regs[0]; resultSaved=true; }
        }
#endif
    }
    if (!result && !stepped) {
#if defined(__x86_64__)
        if(request==PTRACE_GETREGS) savedPc=static_cast<user_regs_struct*>(data)->rip;
#elif defined(__aarch64__)
        if(request==PTRACE_GETREGSET && reinterpret_cast<uintptr_t>(address)==NT_PRSTATUS) {
            auto* io=static_cast<iovec*>(data);
            if(io->iov_len==sizeof(user_pt_regs)) savedPc=static_cast<user_pt_regs*>(io->iov_base)->pc;
        }
#endif
    }
    return result;
}
extern "C" int __real_stat(const char*,struct stat*);
extern "C" int __wrap_stat(const char* path,struct stat* result) {
    using namespace syscall_test;
    if ((current==Fault::MetadataAfterSeize || (current==Fault::MetadataAfterStep && stepped)) && seizedPid>0) {
        char executable[64];
        std::snprintf(executable,sizeof(executable),"/proc/%ld/exe",static_cast<long>(seizedPid.load()));
        if (std::strcmp(path,executable)==0) { ++failures; errno=ENOENT; return -1; }
    }
    return __real_stat(path,result);
}
extern "C" void* __real__Znwm(size_t);
extern "C" void* __wrap__Znwm(size_t size) {
    using namespace syscall_test;
    if (watchedAllocator && syscall(SYS_gettid)==watchedAllocator) observedAllocation=true;
    if (failAllocation && (current==Fault::PreflightAllocationAndDetach || current==Fault::AllocationBeforeSeize)) {
        failAllocation=false;
        ++failures;
        throw std::bad_alloc{};
    }
    return __real__Znwm(size);
}
extern "C" ssize_t __real_pwrite(int,const void*,size_t,off_t);
extern "C" ssize_t __wrap_pwrite(int fd,const void* bytes,size_t size,off_t offset) {
    using namespace syscall_test;
    if (current==Fault::FrameWriteFailure || (current==Fault::FrameRestoreFailure && contextReturnStarted)) {
        if (current==Fault::FrameWriteFailure && size)
            __real_pwrite(fd,bytes,size<8 ? size : 8,offset);
        ++failures; errno=EIO; return -1;
    }
    return __real_pwrite(fd,bytes,size,offset);
}
