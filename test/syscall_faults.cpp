// Link-time interposition is confined to the integration test executable.
// All non-failing requests reach the real kernel; no product fault controls.
#include "test/syscall_faults.hpp"
#include "platform/linux/register_image.hpp"
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
static thread_local bool restartEmulated, restartInterrupted, restartResumed;
static thread_local bool restartMaskWritten, restartSignalQueued;
#if defined(__x86_64__)
static thread_local user_regs_struct restartGroupBank;
static thread_local uint64_t restartGroupMask;
#endif
static thread_local bool restartGroupSeen;
static thread_local unsigned restartProbeWrites;
static thread_local pid_t restartContinueTid;
static thread_local bool restartContinueSeen;
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
static std::atomic<pid_t> exitingDetachTid{0},survivorDetachTid{0},exitingOwner{0};
static std::atomic<bool> exitedBeforeDetach{false},exitContextReady{false},survivorVerified{false};
static std::atomic<uintptr_t> exitingFlag{0};
static std::atomic<uint64_t> exitingAllocation{0};
static std::atomic<bool> exitingAllocationPresent{false};
static std::atomic<pid_t> releasingDetachTid{0},releasedOwner{0};
static std::atomic<bool> releasedDetach{false},releasedContext{false},releasedMapped{false},releasedNoSuch{false};
static std::atomic<uint64_t> releasedAllocation{0};
static std::atomic<unsigned> releasedReplayAttempts{0};
#if defined(__x86_64__)
static thread_local bool releasedRunning=false;
static thread_local user_regs_struct survivorOriginal;
static thread_local uint64_t survivorMask;
static thread_local std::optional<ce::os::NativeExtendedContext> survivorBanks;
static thread_local bool survivorCaptured=false,survivorCapturing=false;
#endif
static std::atomic<pid_t> hardwareRaceTid{0};
static std::atomic<uintptr_t> hardwareRaceAddress{0};
static std::atomic<int> hardwareRaceSignal{0};
static std::atomic<bool> hardwareRaceSeen{false};
void arm(Fault fault) { current=fault; stepped=false; contextReturnStarted=false; failures=0; hardwareWrites=0; textWrites=0;
    steps=0; seizedPid=0; functionContinued=false; functionWaitingPointer=0; failAllocation=fault==Fault::AllocationBeforeSeize;
    restartEmulated=false;restartInterrupted=false;restartResumed=false;restartMaskWritten=false;restartSignalQueued=false;restartGroupSeen=false;restartProbeWrites=0; }
void clear() { current=Fault::None; stepped=false; failAllocation=false; hardwareRaceTid=0;
    restartEmulated=false;restartInterrupted=false;restartResumed=false;restartMaskWritten=false;restartSignalQueued=false;restartContinueTid=0; }
uintptr_t originalPc() { return savedPc; }
unsigned triggered() { return failures; }
unsigned singleSteps() { return steps; }
uint64_t completedResult() { return returnedValue; }
void watchAllocation(pid_t tid) { observedAllocation=false; watchedAllocator=tid; }
bool allocationObserved() { return observedAllocation; }
void holdAfterDetach(pid_t tid) { detachReached=false; detachReleased=false; heldDetachTid=tid; }
bool detachHeld() { return detachReached; }
void releaseDetach() { detachReleased=true; }
void exitBeforeDetach(pid_t selected,pid_t survivor,uintptr_t exitFlag) {
    exitedBeforeDetach=false;exitContextReady=false;survivorVerified=false;exitingOwner=0;
    exitingAllocation=0;exitingAllocationPresent=false;exitingFlag=exitFlag;
    survivorDetachTid=survivor;exitingDetachTid=selected;
}
bool detachExitObserved() {return exitedBeforeDetach;}
pid_t detachExitOwner() {return exitingOwner;}
bool detachExitContextReady() {return exitContextReady;}
uint64_t detachExitAllocation() {return exitingAllocation;}
bool detachExitAllocationPresent() {return exitingAllocationPresent;}
bool survivorContextVerified() {return survivorVerified;}
void clearDetachExit() {exitingDetachTid=0;survivorDetachTid=0;}
void watchDetachRelease(pid_t tid) {
    releasingDetachTid=0;releasedDetach=false;releasedContext=false;releasedMapped=false;
    releasedNoSuch=false;releasedOwner=0;releasedAllocation=0;
    releasedReplayAttempts=0;
    survivorVerified=false;survivorDetachTid=tid;
}
void releaseBeforeDetachError(pid_t tid) {releasingDetachTid=tid;}
DetachReleaseObservation detachReleaseObservation() {
    return {releasedDetach.load(),releasedContext.load(),releasedMapped.load(),releasedNoSuch.load(),releasedOwner.load(),releasedAllocation.load(),releasedReplayAttempts.load()};
}
void clearDetachRelease() {releasingDetachTid=0;survivorDetachTid=0;}
void queueHardwareRace(pid_t tid,uintptr_t address,int signal) {
    hardwareRaceSeen=false;hardwareRaceAddress=address;hardwareRaceSignal=signal;hardwareRaceTid=tid;
}
bool hardwareRaceObserved() {return hardwareRaceSeen;}
void queueRestartContinueRace(pid_t tid) {restartContinueTid=tid;restartContinueSeen=false;}
bool restartContinueRaceObserved() {return restartContinueSeen;}
bool restartGroupStopMatches(const void* registers,size_t size,uint64_t mask) {
#if defined(__x86_64__)
    return restartGroupSeen && size==sizeof(restartGroupBank) && restartGroupMask==mask &&
        !std::memcmp(registers,&restartGroupBank,size);
#else
    return false;
#endif
}
}
extern "C" long __real_ptrace(enum __ptrace_request, ...);
extern "C" pid_t __real_waitpid(pid_t,int*,int);
extern "C" pid_t __wrap_waitpid(pid_t pid,int* status,int options) {
    using namespace syscall_test;
    auto result=__real_waitpid(pid,status,options);
#if defined(__x86_64__)
    if (!result && pid>0 && pid==restartContinueTid && status && (options&WNOHANG)) {
        restartContinueTid=0;
        if (kill(pid,SIGCONT)==0) {
            const auto deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(100);
            do {
                siginfo_t info{};
                if (__real_ptrace(PTRACE_GETSIGINFO,pid,nullptr,&info)==0 &&
                    (info.si_code>>8)==PTRACE_EVENT_STOP && info.si_signo==SIGTRAP) {
                    restartContinueSeen=true;break;
                }
                usleep(1000);
            } while (std::chrono::steady_clock::now()<deadline);
        }
        // Return the actual empty poll. SIGCONT and its real notification
        // occurred afterwards; leave that new wait status for the owner.
        return result;
    }
#endif
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
#if defined(__x86_64__)
    if (releasedRunning && (request==PTRACE_SETREGS || request==PTRACE_SETREGSET || request==PTRACE_POKETEXT ||
        request==PTRACE_SETSIGMASK || request==PTRACE_SETSIGINFO)) ++releasedReplayAttempts;
    if (request==PTRACE_SEIZE && survivorDetachTid==pid) {survivorCaptured=false;survivorBanks.reset();}
    if (request==PTRACE_DETACH && current==Fault::Detach && exitingDetachTid==pid) {
        exitingDetachTid=0;exitingOwner=static_cast<pid_t>(syscall(SYS_gettid));
        user_regs_struct actual{};siginfo_t stop{};
        exitContextReady=__real_ptrace(PTRACE_GETREGS,pid,nullptr,&actual)==0 && actual.rip==savedPc &&
            __real_ptrace(PTRACE_GETSIGINFO,pid,nullptr,&stop)==0 && stop.si_signo==SIGTRAP;
        exitingAllocation=actual.cs==0x23 ? static_cast<uint32_t>(returnedValue.load()) : returnedValue.load();
        uint8_t byte=1;unsigned flag=0;
        iovec local{&byte,1},remote{reinterpret_cast<void*>(static_cast<uintptr_t>(exitingAllocation.load())),1};
        exitingAllocationPresent=process_vm_readv(pid,&local,1,&remote,1,0)==1 && byte==0;
        iovec flagLocal{&flag,sizeof(flag)},flagRemote{reinterpret_cast<void*>(exitingFlag.load()),sizeof(flag)};
        const bool flagWritten=exitContextReady && process_vm_writev(pid,&flagLocal,1,&flagRemote,1,0)==sizeof(flag);
        // The fixture's own loop now observes its exit flag. Do not manufacture
        // an exit status or change its saved registers to simulate death.
        if (flagWritten && __real_ptrace(PTRACE_CONT,pid,nullptr,nullptr)==0) {
            const auto until=std::chrono::steady_clock::now()+std::chrono::seconds(2);
            while (std::chrono::steady_clock::now()<until) {
                siginfo_t terminal{};
                if (waitid(P_PID,pid,&terminal,__WALL|__WNOTHREAD|WEXITED|WNOHANG|WNOWAIT)==0 &&
                    terminal.si_pid==pid && terminal.si_code==CLD_EXITED && terminal.si_status==0) {
                    exitedBeforeDetach=true;break;
                }
                usleep(1000);
            }
        }
        std::fprintf(stderr,"SERVICE_REAL_EXIT tid=%ld owner=%ld context=%d flag=%d allocation=%llx mapped=%d terminal=%d leftWait=1\n",
            static_cast<long>(pid),static_cast<long>(exitingOwner.load()),exitContextReady.load(),flagWritten,
            static_cast<unsigned long long>(exitingAllocation.load()),exitingAllocationPresent.load(),exitedBeforeDetach.load());
        ++failures;errno=EIO;return -1;
    }
    if (request==PTRACE_DETACH && survivorDetachTid==pid && survivorCaptured) {
        user_regs_struct actual{};uint64_t mask=0;
        survivorCapturing=true;
        auto banks=survivorBanks ? ce::os::verifyNativeExtendedContext(pid,*survivorBanks) :
            std::expected<void,std::error_code>(std::unexpected(std::make_error_code(std::errc::io_error)));
        survivorCapturing=false;
        survivorVerified=banks && __real_ptrace(PTRACE_GETREGS,pid,nullptr,&actual)==0 &&
            !std::memcmp(&actual,&survivorOriginal,sizeof(actual)) &&
            __real_ptrace(PTRACE_GETSIGMASK,pid,reinterpret_cast<void*>(sizeof(mask)),&mask)==0 && mask==survivorMask;
    }
    if (request==PTRACE_DETACH && releasingDetachTid==pid) {
        releasingDetachTid=0;releasedOwner=static_cast<pid_t>(syscall(SYS_gettid));
        releasedContext=survivorVerified.load();
        user_regs_struct before{};
        if (__real_ptrace(PTRACE_GETREGS,pid,nullptr,&before)==0)
            releasedAllocation=before.cs==0x23 ? static_cast<uint32_t>(returnedValue.load()) : returnedValue.load();
        uint8_t byte=1;iovec local{&byte,1},remote{reinterpret_cast<void*>(static_cast<uintptr_t>(releasedAllocation.load())),1};
        releasedMapped=process_vm_readv(pid,&local,1,&remote,1,0)==1 && byte==0;
        const long applied=__real_ptrace(request,pid,address,data);
        if (applied<0) return applied;
        user_regs_struct running{};errno=0;
        releasedNoSuch=__real_ptrace(PTRACE_GETREGS,pid,nullptr,&running)<0 && errno==ESRCH && kill(pid,0)==0;
        releasedDetach=true;
        releasedRunning=true;
        std::fprintf(stderr,"SERVICE_REAL_DETACH tid=%ld owner=%ld context=%d allocation=%llx mapped=%d alive=1 esrch=%d\n",
            static_cast<long>(pid),static_cast<long>(releasedOwner.load()),releasedContext.load(),
            static_cast<unsigned long long>(releasedAllocation.load()),releasedMapped.load(),releasedNoSuch.load());
        ++failures;errno=EIO;return -1;
    }
#endif
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
#if defined(__x86_64__)
    if (request==PTRACE_GETSIGMASK && stepped &&
        (current==Fault::RestartMaskRead || (current==Fault::RestartMaskVerify && restartMaskWritten))) {
        ++failures;errno=EIO;return -1;
    }
    if (request==PTRACE_SETSIGMASK && stepped) {
        if (current==Fault::RestartMaskWriteBefore) {++failures;errno=EIO;return -1;}
        const long applied=__real_ptrace(request,pid,address,data);
        if (!applied) restartMaskWritten=true;
        if (!applied && (current==Fault::RestartMaskWriteAfter ||
            (current==Fault::RestartMaskRestoreAfter && restartResumed))) {
            ++failures;errno=EIO;return -1;
        }
        return applied;
    }
    if ((current==Fault::RestartInfoAfterStep && stepped && static_cast<unsigned>(request)==0x420e) ||
        (current==Fault::RestartEntryRead && restartEmulated && preflightRegisters) ||
        (current==Fault::RestartVerification && restartResumed && static_cast<unsigned>(request)==0x420e)) {
        ++failures;errno=EIO;return -1;
    }
    if (static_cast<unsigned>(request)==31) {
        bool guardStop=false;user_regs_struct guardedEntry{};
        if ((current==Fault::RestartQueuedSignal || current==Fault::RestartQueuedStop || current==Fault::RestartCanceledStop ||
            current==Fault::RestartListenBefore || current==Fault::RestartListenAfter) && !restartSignalQueued) {
            union sigval value{};value.sival_int=0x41534947;
            if (sigqueue(pid,current==Fault::RestartQueuedSignal ? SIGWINCH : SIGSTOP,value)!=0) return -1;
            restartSignalQueued=true;++failures;
            if (current!=Fault::RestartQueuedSignal) {
                // Queueing alone does not fix delivery before the emulated
                // entry. Guard this requested pre-entry test with a real
                // interrupt, and consume only that test-owned notification.
                if (__real_ptrace(PTRACE_GETREGS,pid,nullptr,&guardedEntry)<0 ||
                    __real_ptrace(PTRACE_INTERRUPT,pid,nullptr,nullptr)<0) return -1;
                guardStop=true;
            }
        }
        if (current==Fault::RestartEmulateBefore) {++failures;errno=EIO;return -1;}
        long applied=__real_ptrace(request,pid,address,data);
        if (!applied && guardStop) {
            const auto deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(100);
            bool delivered=false;
            while (!delivered && std::chrono::steady_clock::now()<deadline) {
                siginfo_t notification{};
                if (waitid(P_PID,pid,&notification,__WALL|__WNOTHREAD|WSTOPPED|WNOHANG|WNOWAIT)<0) return -1;
                if (!notification.si_pid) {usleep(1000);continue;}
                siginfo_t info{};
                if (__real_ptrace(PTRACE_GETSIGINFO,pid,nullptr,&info)<0) return -1;
                if (notification.si_code==CLD_TRAPPED && notification.si_status==SIGSTOP &&
                    info.si_signo==SIGSTOP && info.si_code==SI_QUEUE && info.si_pid==getpid() &&
                    info.si_value.sival_int==0x41534947) {
                    std::fprintf(stderr,"RESTART_PREENTRY_STOP actualStop=%d queuedCode=%d leftWait=1\n",notification.si_status,info.si_code);
                    delivered=true;break;
                }
                user_regs_struct actual{};int observed=0;
                if (notification.si_code!=CLD_TRAPPED || notification.si_status!=(SIGTRAP|(PTRACE_EVENT_STOP<<8)) ||
                    __real_ptrace(PTRACE_GETREGS,pid,nullptr,&actual)<0 || std::memcmp(&actual,&guardedEntry,sizeof(actual)) ||
                    __real_waitpid(pid,&observed,__WALL|__WNOTHREAD|WNOHANG)!=pid || !WIFSTOPPED(observed) ||
                    WSTOPSIG(observed)!=SIGTRAP || (observed>>16)!=PTRACE_EVENT_STOP) {errno=EIO;return -1;}
                applied=__real_ptrace(request,pid,address,data);
                if (applied) return applied;
            }
            if (!delivered) {errno=ETIMEDOUT;return -1;}
        }
        if (!applied) restartEmulated=true;
        if (!applied && current==Fault::RestartEmulateAfter) {++failures;errno=EIO;return -1;}
        return applied;
    }
    if (request==PTRACE_LISTEN) {
        siginfo_t info{};
        restartGroupSeen=__real_ptrace(PTRACE_GETSIGINFO,pid,nullptr,&info)==0 &&
            (info.si_code>>8)==PTRACE_EVENT_STOP && info.si_signo==SIGSTOP &&
            __real_ptrace(PTRACE_GETREGS,pid,nullptr,&restartGroupBank)==0 &&
            __real_ptrace(PTRACE_GETSIGMASK,pid,reinterpret_cast<void*>(sizeof(restartGroupMask)),&restartGroupMask)==0;
        if (current==Fault::RestartListenBefore) {++failures;errno=EIO;return -1;}
        const long applied=__real_ptrace(request,pid,address,data);
        if (!applied && current==Fault::RestartListenAfter) {++failures;errno=EIO;return -1;}
        return applied;
    }
    if (request==PTRACE_INTERRUPT && restartEmulated) {
        if (current==Fault::RestartInterruptBefore) {++failures;errno=EIO;return -1;}
        const long applied=__real_ptrace(request,pid,address,data);
        if (!applied) restartInterrupted=true;
        if (!applied && current==Fault::RestartInterruptAfter) {++failures;errno=EIO;return -1;}
        return applied;
    }
    if (request==PTRACE_CONT && restartInterrupted) {
        if (current==Fault::RestartResumeBefore) {++failures;errno=EIO;return -1;}
        const long applied=__real_ptrace(request,pid,address,data);
        if (!applied) restartResumed=true;
        if (!applied && current==Fault::RestartResumeAfter) {++failures;errno=EIO;return -1;}
        return applied;
    }
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
    if (!result && request==PTRACE_SEIZE) {
#if defined(__x86_64__)
        releasedRunning=false;
#endif
    }
    if (!result && !stepped) {
#if defined(__x86_64__)
        if(request==PTRACE_GETREGS) savedPc=static_cast<user_regs_struct*>(data)->rip;
        if(request==PTRACE_GETREGS && survivorDetachTid==pid && !survivorCaptured && !survivorCapturing) {
            survivorCapturing=true;
            survivorOriginal=*static_cast<user_regs_struct*>(data);
            auto banks=ce::os::captureNativeExtendedContext(pid);
            survivorCaptured=banks && __real_ptrace(PTRACE_GETSIGMASK,pid,reinterpret_cast<void*>(sizeof(survivorMask)),&survivorMask)==0;
            if(banks) survivorBanks=std::move(*banks);
            survivorCapturing=false;
        }
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
    if ((current==Fault::RestartProbeRestoreBefore || current==Fault::RestartProbeRestoreAfter) && size==1 && ++restartProbeWrites>1) {
        if (current==Fault::RestartProbeRestoreAfter) __real_pwrite(fd,bytes,size,offset);
        ++failures;errno=EIO;return -1;
    }
    if (current==Fault::FrameWriteFailure || (current==Fault::FrameRestoreFailure && contextReturnStarted)) {
        if (current==Fault::FrameWriteFailure && size)
            __real_pwrite(fd,bytes,size<8 ? size : 8,offset);
        ++failures; errno=EIO; return -1;
    }
    return __real_pwrite(fd,bytes,size,offset);
}
