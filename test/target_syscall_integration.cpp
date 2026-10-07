#include "platform/linux/target_syscall.hpp"
#include "platform/linux/syscall_service.hpp"
#include "platform/linux/memory_image.hpp"
#include "platform/linux/linux_process.hpp"
#include "platform/linux/ptrace_wrapper.hpp"
#include "platform/linux/target_debug.hpp"
#include "platform/linux/register_image.hpp"
#include "debug/debug_session.hpp"
#include "debug/thread_inspection.hpp"
#include "core/cpu_registers.hpp"
#include "debug/tracer.hpp"
#include "debug/code_finder.hpp"
#include <atomic>
#include <sys/ptrace.h>
#include "test/syscall_faults.hpp"
#include <array>
#include <chrono>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <poll.h>
#include <signal.h>
#include <sstream>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <thread>
#include <sys/utsname.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <elf.h>
#if defined(__x86_64__)
#include <sys/user.h>
#elif defined(__aarch64__)
#include <asm/ptrace.h>
#include <asm/hwcap.h>
#include <sys/auxv.h>
#endif

using namespace ce;
using namespace ce::os;
static int failures;
static void check(bool ok, const char* name) {
    printf("%s: %s\n", ok ? "OK" : "FAILED", name); fflush(stdout); failures += !ok;
}
class Fixture {
public:
    pid_t pid = -1; int input = -1, output = -1;
    explicit Fixture(const char* path) {
        int in[2], out[2];
        if (pipe(in)) return;
        if (pipe(out)) { close(in[0]); close(in[1]); return; }
        const pid_t parent=getpid();
        pid = fork();
        if (!pid) {
            // Bounded owner tests may terminate by alarm. Their fixtures must
            // also terminate if the owner dies before normal RAII cleanup.
            if (prctl(PR_SET_PDEATHSIG,SIGKILL)<0 || getppid()!=parent) _exit(126);
            dup2(in[0],0); dup2(out[1],1);
            close(in[0]); close(in[1]); close(out[0]); close(out[1]);
            execl(path,path,path,nullptr); _exit(127);
        }
        close(in[0]); close(out[1]); input=in[1]; output=out[0];
    }
    std::string line() {
        std::string text;
        while (text.size()<4096) {
            pollfd fd{output,POLLIN,0};
            if (poll(&fd,1,5000)<=0) return {};
            char c;
            if (::read(output,&c,1)!=1) return {};
            if(c=='\n') return text;
            text+=c;
        }
        return {};
    }
    bool value() { char c='r'; return ::write(input,&c,1)==1 && line()=="123456789"; }
    ~Fixture() {
        if(pid>0) { kill(pid,SIGKILL); int status; while(waitpid(pid,&status,0)<0&&errno==EINTR){} }
        if(input>=0) close(input);
        if(output>=0) close(output);
    }
};
static ssize_t readMemory(pid_t pid,uintptr_t address,void* buffer,size_t size) {
    iovec local{buffer,size},remote{reinterpret_cast<void*>(address),size};
    return process_vm_readv(pid,&local,1,&remote,1,0);
}
static ssize_t writeMemory(pid_t pid,uintptr_t address,const void* buffer,size_t size) {
    iovec local{const_cast<void*>(buffer),size},remote{reinterpret_cast<void*>(address),size};
    return process_vm_writev(pid,&local,1,&remote,1,0);
}
static pid_t fixtureTracer(pid_t pid) {
    std::ifstream status("/proc/"+std::to_string(pid)+"/status");
    std::string line;
    while (std::getline(status,line)) if (line.starts_with("TracerPid:")) {
        int tracer=0;
        if (std::sscanf(line.c_str(),"TracerPid: %d",&tracer)==1) return tracer;
    }
    return -1;
}
static void preflightRecovery(const char* path) {
    int initial=failures;
    CpuArchitecture architecture=CpuArchitecture::Unknown;
    for (auto fault : {syscall_test::Fault::PreflightDetach,syscall_test::Fault::PreflightRegistersAndDetach,
                       syscall_test::Fault::InterruptFailure,syscall_test::Fault::PreflightAllocationAndDetach,
                       syscall_test::Fault::MetadataAfterSeize}) {
        Fixture fixture(path);
        check(fixture.line().starts_with("CE_TARGET "),"preflight recovery starts a real native target");
        std::ifstream executable(path,std::ios::binary);
        std::array<uint8_t,64> header{};
        executable.read(reinterpret_cast<char*>(header.data()),header.size());
        auto machine=parseElfTarget({header.data(),static_cast<size_t>(executable.gcount())});
        if (!machine) { check(false,"preflight recovery identifies the real native ABI"); return; }
        architecture=machine->architecture;
        syscall_test::arm(fault);
        auto operation=fault==syscall_test::Fault::PreflightDetach ? MemorySyscall::Unmap : MemorySyscall::Map;
        std::array<uint64_t,6> args=fault==syscall_test::Fault::PreflightDetach ?
            std::array<uint64_t,6>{UINT64_MAX,4096,0,0,0,0} :
            std::array<uint64_t,6>{0,4096,3,0x22,UINT64_MAX,0};
        auto failed=executeMemorySyscall(fixture.pid,*machine,operation,args);
        check(!failed && syscall_test::triggered()>0 && syscall_test::singleSteps()==0 && failed.error().recovery && !failed.error().completedValue &&
              fixtureTracer(fixture.pid)==getpid(),
              "failure before syscall execution retains the actual ptrace owner without an invented allocation");
        if (!failed && failed.error().recovery) {
            bool refused=false;
            std::thread other([&] { auto result=failed.error().recovery->retry();
                refused=!result && result.error()==std::errc::operation_not_permitted; });
            other.join();
            check(refused,"preflight recovery refuses a different host owner thread");
        }
        syscall_test::clear();
        bool restored=!failed && failed.error().recovery && failed.error().recovery->retry().has_value() &&
            failed.error().recovery->retry().has_value();
        check(restored && fixtureTracer(fixture.pid)==0,"preflight recovery releases the original attachment and is idempotent");
        // Release the old implementation's abandoned stop so a failing baseline
        // reports the regression without hanging or leaving the fixture traced.
        if (fixtureTracer(fixture.pid)>0 && ptrace(PTRACE_DETACH,fixture.pid,nullptr,nullptr)<0) {
            ptrace(PTRACE_INTERRUPT,fixture.pid,nullptr,nullptr);
            int status=0;
            if (waitpid(fixture.pid,&status,__WALL|WNOHANG)==0) {
                while (waitpid(fixture.pid,&status,__WALL)<0 && errno==EINTR) {}
            }
            ptrace(PTRACE_DETACH,fixture.pid,nullptr,nullptr);
        }
        check(fixture.value(),"the untouched target resumes its original blocked read and console work after preflight recovery");
    }
    {
        Fixture fixture(path);
        check(fixture.line().starts_with("CE_TARGET "),"allocation preflight starts a separate real native target");
        syscall_test::arm(syscall_test::Fault::AllocationBeforeSeize);
        auto failed=executeMemorySyscall(fixture.pid,nativeTargetMachine(),MemorySyscall::Map,{0,4096,3,0x22,UINT64_MAX,0});
        check(!failed && failed.error().code==std::errc::not_enough_memory && !failed.error().recovery &&
            syscall_test::triggered()>0 && syscall_test::singleSteps()==0 && fixtureTracer(fixture.pid)==0,
            "failure allocating recovery ownership occurs before any ptrace attachment or target execution");
        syscall_test::clear();
        check(fixture.value(),"allocation failure before attachment leaves the target running normally");
    }
    {
        Fixture fixture(path);
        check(fixture.line().starts_with("CE_TARGET "),"exit preflight recovery starts a separate real native target");
        syscall_test::arm(syscall_test::Fault::PreflightRegistersAndDetach);
        auto failed=executeMemorySyscall(fixture.pid,nativeTargetMachine(),MemorySyscall::Map,{0,4096,3,0x22,UINT64_MAX,0});
        check(!failed && failed.error().recovery,"an untouched stopped target retains preflight ownership before exit");
        kill(fixture.pid,SIGKILL);
        int status=0;
        pid_t waited;
        do { waited=waitpid(fixture.pid,&status,__WALL); } while (waited<0 && errno==EINTR);
        syscall_test::clear();
        bool retired=false;
        if (!failed && failed.error().recovery) {
            auto result=failed.error().recovery->retry();
            retired=!result && (result.error()==std::errc::no_such_process || result.error()==std::errc::no_such_file_or_directory) &&
                failed.error().recovery->retry().has_value();
        }
        check(waited==fixture.pid && WIFSIGNALED(status) && retired,
              "preflight ownership retires idempotently after real target exit without replaying an unfinished snapshot");
    }
    {
        Fixture fixture(path);
        check(fixture.line().starts_with("CE_TARGET "),"service preflight recovery starts a separate real native target");
        {
            LinuxProcessHandle caller(fixture.pid);
            syscall_test::arm(syscall_test::Fault::PreflightRegistersAndDetach);
            auto failed=caller.allocate(4096,MemProt::ReadWrite);
            check(!failed && syscall_test::triggered()>0 && syscall_test::singleSteps()==0 &&
                  caller.targetDescription().pendingRecovery && fixtureTracer(fixture.pid)>0,
                  "the application service retains preflight detach failure through caller destruction");
        }
        syscall_test::clear();
        LinuxProcessHandle caller(fixture.pid);
        check(caller.retryPendingOperations() && !caller.targetDescription().pendingRecovery && fixtureTracer(fixture.pid)==0,
              "a new application handle recovers the original preflight ptrace owner without a register snapshot");
        check(fixture.value(),"service preflight recovery preserves the real target's blocked read and continued execution");
    }
    printf("PREFLIGHT_RECOVERY_RESULT=%s architecture=%s\n",initial==failures ? "PASSED" : "FAILED",
        cpuArchitectureName(architecture)); fflush(stdout);
}
static void plans() {
    TargetMachine x64{CpuArchitecture::X86_64,ByteOrder::Little,TargetAbi::LinuxX86_64,
                      InstructionMode::X86_64,8,ByteOrder::Little};
    TargetMachine x32=x64; x32.abi=TargetAbi::LinuxX32; x32.pointerWidth=4;
    TargetMachine arm{CpuArchitecture::Arm32,ByteOrder::Little,TargetAbi::LinuxArmEabi,
                     InstructionMode::Arm,4,ByteOrder::Little};
    TargetMachine a64{CpuArchitecture::Arm64,ByteOrder::Little,TargetAbi::LinuxAarch64,
                     InstructionMode::Aarch64,8,ByteOrder::Little};
    auto map64=targetSyscallPlan(x64,InstructionMode::X86_64,MemorySyscall::Map,{0,4096,3,0x22,UINT64_MAX,0});
    check(map64 && map64->number==9 && map64->instruction==std::vector<uint8_t>{0x0f,0x05},"x64 syscall plan uses its Linux number and opcode");
    auto compat=targetSyscallPlan(x64,InstructionMode::X86_32,MemorySyscall::Map,{0,4096,3,0x22,UINT64_MAX,0});
    check(compat && compat->number==192 && compat->resultWidth==4 && compat->arguments[4]==UINT32_MAX &&
          compat->instruction==std::vector<uint8_t>{0xcd,0x80},"compat mode in an ELF64 host uses mmap2 and the signed fd sentinel");
    auto map32=targetSyscallPlan(x32,InstructionMode::X86_64,MemorySyscall::Map,{0,4096,3,0x22,UINT64_MAX,0});
    auto file32=targetSyscallPlan(x32,InstructionMode::X86_64,MemorySyscall::Map,{0,4096,1,2,3,UINT64_C(0x100002000)});
    check(map32 && map32->number==(0x40000000u|9u) && map32->resultWidth==8 && map32->arguments[4]==UINT32_MAX &&
          file32 && file32->arguments[5]==UINT64_C(0x100002000),
          "x32 retains a 64-bit result register and file offset with its separate syscall-number bit");
    check(!targetSyscallPlan(x32,InstructionMode::X86_64,MemorySyscall::Protect,{UINT64_C(0x100000000),4096,3,0,0,0}) &&
          !targetSyscallPlan(x64,InstructionMode::X86_32,MemorySyscall::Map,{0,UINT64_C(0x100000000),3,0x22,UINT64_MAX,0}),
          "32-bit syscall arguments cannot silently truncate addresses or lengths");
    auto armCall=targetSyscallPlan(arm,InstructionMode::Arm,MemorySyscall::Unmap,{});
    auto thumbCall=targetSyscallPlan(arm,InstructionMode::Thumb,MemorySyscall::Protect,{});
    check(armCall && armCall->number==91 && armCall->instruction==std::vector<uint8_t>{0,0,0,0xef} &&
          thumbCall && thumbCall->number==125 && thumbCall->instruction==std::vector<uint8_t>{0,0xdf},
          "ARM and Thumb plans have distinct instruction widths");
    arm.instructionByteOrder=ByteOrder::Big;
    auto bigArm=targetSyscallPlan(arm,InstructionMode::Arm,MemorySyscall::Unmap,{});
    auto bigThumb=targetSyscallPlan(arm,InstructionMode::Thumb,MemorySyscall::Protect,{});
    check(bigArm && bigArm->instruction==std::vector<uint8_t>{0xef,0,0,0} &&
          bigThumb && bigThumb->instruction==std::vector<uint8_t>{0xdf,0},"ARM instruction byte order is independent of target data byte order");
    arm.instructionByteOrder=ByteOrder::Unknown;
    check(!targetSyscallPlan(arm,InstructionMode::Thumb,MemorySyscall::Map,{}),"unknown ARM instruction order cannot select an opcode");
    auto callA64=targetSyscallPlan(a64,InstructionMode::Aarch64,MemorySyscall::Map,{});
    check(callA64 && callA64->number==222 && callA64->instruction==std::vector<uint8_t>{1,0,0,0xd4},"ARM64 syscall plan uses svc zero and the native mmap number");
    x64.abi=TargetAbi::WindowsX64;
    check(!targetSyscallPlan(x64,InstructionMode::X86_64,MemorySyscall::Map,{}) &&
          !targetSyscallPlan(x64,InstructionMode::X86_32,MemorySyscall::Map,{}) &&
          !targetSyscallPlan({},InstructionMode::X86_64,MemorySyscall::Map,{}),
          "a Windows or unknown program descriptor cannot masquerade as a Linux syscall host");
}
static void exercise(const char* path) {
    Fixture fixture(path);
    std::istringstream line(fixture.line()); std::string magic;
    pid_t pid=0; unsigned width=0; uintptr_t value=0,pointer=0,code=0;
    line>>magic>>pid>>width>>std::hex>>value>>pointer>>code;
    check(line && magic=="CE_TARGET" && pid==fixture.pid, "real native syscall fixture starts");
    if(!line || magic!="CE_TARGET" || pid!=fixture.pid) return;
    std::ifstream executable(path,std::ios::binary);
    std::array<uint8_t,64> header{}; executable.read(reinterpret_cast<char*>(header.data()),header.size());
    auto machine=parseElfTarget({header.data(),static_cast<size_t>(executable.gcount())});
    check(machine && machine->pointerWidth==width,"fixture ELF declares the actual syscall ABI");
    if(!machine) return;
    printf("SYSCALL_TARGET architecture=%s abi=%s width=%u pageSize=%ld\n",cpuArchitectureName(machine->architecture),targetAbiName(machine->abi),width,sysconf(_SC_PAGESIZE));
    utsname system{};
    if(uname(&system)==0) printf("SYSCALL_KERNEL release=%s machine=%s\n",system.release,system.machine);
    std::array<uint8_t,32> before{},after{};
    check(readMemory(pid,code,before.data(),before.size())==ssize_t(before.size()),"original target instructions are readable");
    size_t size=static_cast<size_t>(sysconf(_SC_PAGESIZE));
    for(int cycle=0;cycle<3;++cycle) {
        auto allocation=executeMemorySyscall(pid,*machine,MemorySyscall::Map,{0,size,3,0x22,UINT64_MAX,0});
        if(!allocation) printf("map error: %s\n",allocation.error().message().c_str());
        check(allocation.has_value(),"target mmap executes using its native register and syscall ABI");
        if(!allocation) return;
        uint32_t sentinel=0x12345678, observed=0;
        check(writeMemory(pid,*allocation,&sentinel,4)==4 && readMemory(pid,*allocation,&observed,4)==4 && observed==sentinel,
              "allocated target memory is observable through real process_vm access");
        auto protection=executeMemorySyscall(pid,*machine,MemorySyscall::Protect,{*allocation,size,1,0,0,0});
        check(protection && writeMemory(pid,*allocation,&sentinel,4)<0,"target mprotect removes write access");
        auto free=executeMemorySyscall(pid,*machine,MemorySyscall::Unmap,{*allocation,size,0,0,0,0});
        check(free && readMemory(pid,*allocation,&observed,4)<0,"target munmap removes the allocated mapping");
        check(readMemory(pid,code,after.data(),after.size())==ssize_t(after.size()) && before==after,
              "syscall injection leaves original target instructions unchanged");
        check(fixture.value(),"syscall restart state survives repeated attach/inject/restore/detach");
    }
    auto invalid=executeMemorySyscall(pid,*machine,MemorySyscall::Protect,{1,size,1,0,0,0});
    check(!invalid && invalid.error().value()==EINVAL && fixture.value(),"kernel syscall errors preserve target liveness and report the actual errno");
    uintptr_t instructionPage=syscall_test::originalPc();
    instructionPage-=instructionPage%size;
    auto unsafe=executeMemorySyscall(pid,*machine,MemorySyscall::Unmap,{instructionPage,size,0,0,0,0});
    check(!unsafe && unsafe.error().value()==EPERM && fixture.value(),
          "unmapping the current syscall instruction is rejected before any mutation");
    auto unsafeProtection=executeMemorySyscall(pid,*machine,MemorySyscall::Protect,{instructionPage,size,0,0,0,0});
    check(!unsafeProtection && unsafeProtection.error().value()==EPERM && fixture.value(),
          "removing execute access from the current syscall page preserves liveness");
    {
        // This is the same LinuxProcessHandle/service implementation linked
        // into cecore, with test-only kernel failure interposition.
        LinuxProcessHandle process(pid);
        auto allocation=process.allocate(size,MemProt::ReadWrite);
        check(allocation && process.protect(*allocation,size,MemProt::Read) && process.free(*allocation,size) && fixture.value(),
              "application process API executes allocation/protection/free through the owner service");
        auto lowPreferred=process.allocate(size,MemProt::ReadWrite,0x1000);
        check(lowPreferred && process.free(*lowPreferred,size) && fixture.value(),
              "a rejected low-address near-allocation candidate falls back to a usable gap");
        syscall_test::arm(syscall_test::Fault::RestoreRegisters);
        uintptr_t orphan=0;
        {
            LinuxProcessHandle caller(pid);
            auto failed=caller.allocate(size,MemProt::ReadWrite);
            check(!failed && syscall_test::triggered()>0 && caller.targetDescription().pendingRecovery,
                  "application API exposes retained recovery after a real kernel restoration failure");
            orphan=static_cast<uintptr_t>(syscall_test::completedResult());
        }
        syscall_test::clear();
        LinuxProcessHandle reattached(pid);
        check(reattached.retryPendingOperations() && !reattached.targetDescription().pendingRecovery && fixture.value(),
              "a new process handle recovers the original ptrace owner and cleans its unreturned allocation");
        uint32_t discarded=0;
        check(orphan && readMemory(pid,orphan,&discarded,4)<0,"caller destruction retains the completed allocation until it is actually unmapped");
        std::array<bool,4> concurrent{};
        std::array<std::thread,4> callers;
        for(size_t i=0;i<callers.size();++i) callers[i]=std::thread([&,i] {
            LinuxProcessHandle caller(pid);
            auto memory=caller.allocate(size,MemProt::ReadWrite);
            concurrent[i]=memory && caller.free(*memory,size);
        });
        for(auto& caller:callers) caller.join();
        check(std::all_of(concurrent.begin(),concurrent.end(),[](bool ok){return ok;}) && fixture.value(),
              "independent frontend threads share syscall ownership without conflicting ptrace attachment");
        check(!process.allocate(0,MemProt::ReadWrite) && !process.allocate(SIZE_MAX,MemProt::ReadWrite) &&
              !process.protect(UINTPTR_MAX-1,4,MemProt::Read) && fixture.value(),
              "zero-size and overflowing application requests are rejected before target mutation");
        if (width==4) {
            auto tooWide=process.allocate(UINT32_MAX,MemProt::ReadWrite);
            auto outside=process.allocate(size,MemProt::ReadWrite,UINT64_C(0x100000000));
            check(!tooWide && tooWide.error()==std::errc::invalid_argument &&
                  !outside && outside.error()==std::errc::invalid_argument && fixture.value(),
                  "page-rounded 32-bit allocations and preferred addresses cannot overflow the program address space");
        }
        auto identity=targetProcessIdentity(pid);
        check(identity.has_value(),"service shutdown fixture has a stable target identity");
        if(identity) {
            auto service=std::make_unique<TargetSyscallService>();
            syscall_test::arm(syscall_test::Fault::RestoreRegisters);
            auto failed=service->execute(*identity,*machine,MemorySyscall::Map,{0,size,3,0x22,UINT64_MAX,0});
            uintptr_t unreturned=static_cast<uintptr_t>(syscall_test::completedResult());
            check(!failed && service->pending(pid,identity->startTime),"isolated service owns a real pending restoration at shutdown");
            std::thread shutdown([&] { service.reset(); });
            usleep(10000);
            syscall_test::clear();
            shutdown.join();
            check(unreturned && readMemory(pid,unreturned,&discarded,4)<0 && fixture.value(),
                  "service shutdown finishes restoration and allocation cleanup on the original owner thread");
        }
    }
    for(auto fault : {syscall_test::Fault::RestoreRegisters,syscall_test::Fault::RestoreInstruction,syscall_test::Fault::Detach}) {
        uintptr_t spinAddress=0;
        if(fault==syscall_test::Fault::RestoreInstruction) {
            char command='s';
            check(::write(fixture.input,&command,1)==1,"busy-code restoration fixture receives its command");
            std::istringstream response(fixture.line());
            std::string marker;
            response>>marker>>std::hex>>spinAddress;
            check(response && marker=="CE_SPIN" && spinAddress,"busy-code fixture publishes its wait flag");
            if(!response || marker!="CE_SPIN" || !spinAddress) return;
            usleep(10000);
            // Instruction restoration belongs to the quiesced executor. The
            // transient executor now uses existing code without patching it.
            int status=0;
            check(ptrace(PTRACE_SEIZE,pid,nullptr,nullptr)==0 && ptrace(PTRACE_INTERRUPT,pid,nullptr,nullptr)==0 &&
                  waitpid(pid,&status,__WALL)==pid && WIFSTOPPED(status),
                  "code-restoration fault owns the only stopped thread before patching its busy instruction");
        }
        syscall_test::arm(fault);
        auto failed=spinAddress ? executeQuiescedMemorySyscall(pid,*machine,MemorySyscall::Map,{0,size,3,0x22,UINT64_MAX,0}) :
            executeMemorySyscall(pid,*machine,MemorySyscall::Map,{0,size,3,0x22,UINT64_MAX,0});
        check(!failed && syscall_test::triggered()>0 && failed.error().recovery && failed.error().completedValue,
              "real completed mmap retains its allocation and a recovery ticket on restoration failure");
        syscall_test::clear();
        if(failed || !failed.error().recovery) return;
        auto ticket=failed.error().recovery;
        bool refused=false;
        std::thread other([&] { auto retry=ticket->retry(); refused=!retry && retry.error().value()==EPERM; });
        other.join();
        check(refused,"a different thread cannot replay a ptrace owner's recovery record");
        auto retry=ticket->retry();
        check(retry && ticket->retry(),"recovery restores the actual target and is idempotent");
        if(!retry) return;
        if(spinAddress) {
            check(ptrace(PTRACE_DETACH,pid,nullptr,nullptr)==0,
                  "quiesced instruction recovery retains attachment until the original owner detaches");
            uint32_t zero=0;
            check(writeMemory(pid,spinAddress,&zero,4)==4,"restored busy-code target can leave its wait loop");
        }
        check(fixture.value(),"target continues executing after verified recovery");
        if(failed.error().completedValue) {
            auto cleanup=executeMemorySyscall(pid,*machine,MemorySyscall::Unmap,{*failed.error().completedValue,size,0,0,0,0});
            uint32_t observed=0;
            check(cleanup && readMemory(pid,*failed.error().completedValue,&observed,4)<0,
                  "completed-but-unreturned mmap can be cleaned up after recovery");
        }
    }
    {
        Fixture replacing(path);
        check(replacing.line().starts_with("CE_TARGET "),"same-file exec fixture starts");
        auto identity=targetProcessIdentity(replacing.pid);
        syscall_test::arm(syscall_test::Fault::RestoreRegisters);
        auto failed=executeMemorySyscall(replacing.pid,*machine,MemorySyscall::Map,{0,size,3,0x22,UINT64_MAX,0});
        syscall_test::clear();
        check(!failed && failed.error().recovery && failed.error().completedValue,
              "same-file exec fixture retains its original memory image");
        if(!failed && failed.error().recovery && failed.error().completedValue && identity) {
            auto image=failed.error().recovery;
            check(image->retry().has_value(),"original image is restored before fixture exec");
            char command='x';
            check(::write(replacing.input,&command,1)==1 && replacing.line().starts_with("CE_TARGET "),
                  "target really execs the same ELF file on the same PID");
            auto nextIdentity=targetProcessIdentity(replacing.pid);
            check(nextIdentity && *nextIdentity==*identity,"same-file exec cannot be detected by PID/start-time/executable-inode alone");
            auto stale=executeMemorySyscall(replacing.pid,*machine,MemorySyscall::Unmap,
                {*failed.error().completedValue,size,0,0,0,0},&*identity,image.get());
            check(!stale && stale.error().code==std::errc::operation_canceled && replacing.value(),
                  "old memory-image ownership rejects cleanup into a same-file replacement process");
        }
    }
    {
        Fixture exiting(path);
        check(exiting.line().starts_with("CE_TARGET "),"separate target starts for exit during recovery");
        syscall_test::arm(syscall_test::Fault::RestoreRegisters);
        auto failed=executeMemorySyscall(exiting.pid,*machine,MemorySyscall::Map,{0,size,3,0x22,UINT64_MAX,0});
        syscall_test::clear();
        check(!failed && failed.error().recovery,"exiting target retains a real failed-restoration record");
        if(!failed && failed.error().recovery) {
            kill(exiting.pid,SIGKILL);
            int status=0;
            pid_t waited;
            do { waited=waitpid(exiting.pid,&status,__WALL); } while(waited<0 && errno==EINTR);
            check(waited==exiting.pid && WIFSIGNALED(status),"stopped recovery target can exit normally through the kernel");
            if(waited==exiting.pid) exiting.pid=-1;
            auto retry=failed.error().recovery->retry();
            check(!retry && retry.error().value()==ESRCH && failed.error().recovery->retry(),
                  "exit clears recovery ownership without replaying dead registers or memory");
        }
    }
    {
        Fixture savedSignal(path);const auto ready=savedSignal.line();
        LinuxProcessHandle savedProcess(savedSignal.pid);
        auto pinned=pinNativeMemoryImage(savedProcess);
        if (ready.empty() || !pinned || !*pinned) {check(false,"capture image for nested proof signal recovery");return;}
        syscall_test::arm(syscall_test::Fault::UserTrap);
        auto failed=executeMemorySyscall(savedSignal.pid,*machine,MemorySyscall::Map,
            {0,size,3,0x22,UINT64_MAX,0},nullptr,nullptr,pinned->get());
        syscall_test::clear();
        if (!failed && failed.error().recovery) (void)failed.error().recovery->retry();
        int status=0;pid_t exited=0;
        for (unsigned attempt=0;attempt<200 && !exited;++attempt) {
            exited=waitpid(savedSignal.pid,&status,WNOHANG);
            if (!exited) usleep(10000);
        }
        check(!failed && !failed.error().completedValue && exited==savedSignal.pid &&
              WIFSIGNALED(status) && WTERMSIG(status)==SIGTRAP,
              "a real user SIGTRAP during a nested affinity syscall is delivered without inventing caller completion");
        if (exited==savedSignal.pid) savedSignal.pid=-1;
    }
    syscall_test::arm(syscall_test::Fault::UserTrap);
    auto interrupted=executeMemorySyscall(pid,*machine,MemorySyscall::Map,{0,size,3,0x22,UINT64_MAX,0});
    syscall_test::clear();
    if(!interrupted && interrupted.error().recovery) {
        check(interrupted.error().recovery->retry().has_value(),"signal-interrupted operation can finish restoration");
    }
    int status=0;
    pid_t exited=0;
    for(int attempt=0;attempt<200 && !exited;++attempt) {
        exited=waitpid(pid,&status,WNOHANG);
        if(!exited) usleep(10000);
    }
    check(exited==pid && WIFSIGNALED(status) && WTERMSIG(status)==SIGTRAP,
          "a real user SIGTRAP is delivered rather than swallowed as a single-step trap");
    if(exited==pid) fixture.pid=-1;
}
static bool stopped(pid_t pid) {
    for (unsigned attempt=0; attempt<500; ++attempt) {
        int status=0;
        pid_t waited=waitpid(pid,&status,__WALL|__WNOTHREAD|WNOHANG);
        if (waited==pid) return WIFSTOPPED(status);
        if (waited<0 && errno!=EINTR) return false;
        usleep(1000);
    }
    return false;
}
static void debugBackend(const char* path) {
    int failuresBefore=failures;
    syscall_test::clear();
    Fixture fixture(path);
    std::istringstream line(fixture.line()); std::string magic;
    pid_t pid=0; unsigned width=0; uintptr_t value=0,pointer=0,code=0;
    line>>magic>>pid>>width>>std::hex>>value>>pointer>>code;
    check(line && magic=="CE_TARGET" && pid==fixture.pid,"native debugger fixture starts");
    if (!line || magic!="CE_TARGET" || pid!=fixture.pid) return;
    char seed='v';
    check(::write(fixture.input,&seed,1)==1 && fixture.line()=="CE_VECTORS",
          "native fixture seeds independent low and high SIMD register sentinels");
    LinuxDebugger debugger;
    auto attached=debugger.attach(pid);
    if (!attached) printf("debug attach error: %s\n",attached.error().message().c_str());
    check(attached.has_value(),"native debugger seizes a syscall-parked thread without a signal");
    if (!attached) return;
    auto original=debugger.getContext(pid);
    LinuxProcessHandle described(pid);
    auto expected=described.targetDescription().host.architecture;
    check(original && original->architecture==expected && original->instructionPointer() && original->stackPointer(),
          "register context identifies the stopped thread ISA and native PC/SP");
    if (!original) return;
    auto vectors=readNativeVectors(pid);
    check(vectors && vectors->count==(expected==CpuArchitecture::Arm64 ? 32u : 16u),
          "native SIMD register bank is read through its architecture ABI");
    std::array<uint64_t,2> first{0x1111222233334444ULL,0x5555666677778888ULL};
    std::array<uint64_t,2> last{0x9999aaaabbbbccccULL,0xddddeeeeffff0000ULL};
    unsigned lastRegister=expected==CpuArchitecture::Arm64 ? 31 : expected==CpuArchitecture::X86_32 ? 7 : 15;
    check(vectors && std::memcmp(vectors->registers[0].data(),first.data(),16)==0 &&
          std::memcmp(vectors->registers[lastRegister].data(),last.data(),16)==0,
          "SIMD reads preserve the fixture's independent 128-bit low and high register values");
    auto edit=*original;
    constexpr uint64_t sentinel=0x12345678;
    if (expected==CpuArchitecture::Arm64) edit.x[19]=sentinel; else edit.rbx=sentinel;
    auto written=debugger.setContext(pid,edit);
    auto changed=debugger.getContext(pid);
    check(written && changed && (expected==CpuArchitecture::Arm64 ? changed->x[19] : changed->rbx)==sentinel,
          "native register edits reach the actual kernel register bank");
    check(debugger.setContext(pid,*original).has_value(),"original register bank is restored before target execution");
    auto invalidRegisters=*original;
    if (expected==CpuArchitecture::Arm64) { invalidRegisters.x[19]=sentinel; invalidRegisters.pc|=1; }
    else { invalidRegisters.rbx=sentinel; invalidRegisters.cs=0; }
    auto rejectedRegisters=debugger.setContext(pid,invalidRegisters);
    auto afterRejectedRegisters=debugger.getContext(pid);
    check(!rejectedRegisters && afterRejectedRegisters &&
          afterRejectedRegisters->instructionPointer()==original->instructionPointer() &&
          (expected==CpuArchitecture::Arm64 ? afterRejectedRegisters->x[19]==original->x[19] :
           afterRejectedRegisters->rbx==original->rbx && afterRejectedRegisters->cs==original->cs),
          "a rejected register write restores earlier fields rather than leaving a partial kernel update");
    auto wrong=*original;
    wrong.architecture=expected==CpuArchitecture::Arm64 ? CpuArchitecture::X86_64 : CpuArchitecture::Arm64;
    check(!debugger.setContext(pid,wrong),"a foreign register context cannot corrupt a stopped thread");
    auto bank=readNativeHardwareBank(pid,true);
    check(bank && bank->count>0,"kernel reports the native hardware breakpoint bank");
    if (!bank) return;
    auto invalid=setNativeHardwareBreakpoint(pid,bank->count,code,HardwareBreakpointAccess::Execute,
                                            expected==CpuArchitecture::Arm64 ? 4 : 1);
    auto afterInvalid=readNativeHardwareBank(pid,true);
    check(!invalid && afterInvalid && bank->entries[0].address==afterInvalid->entries[0].address &&
          bank->entries[0].control==afterInvalid->entries[0].control,
          "an invalid breakpoint slot is rejected without changing another slot");
    auto execution=debugger.setBreakpoint(pid,0,code,0,0);
    if (!execution) printf("execution breakpoint error: %s\n",execution.error().message().c_str());
    check(execution.has_value(),"native hardware execution breakpoint arms at the real writer function");
    if (!execution) return;
    char command='b';
    bool sent=::write(fixture.input,&command,1)==1;
    bool continued=ptrace(PTRACE_CONT,pid,nullptr,nullptr)==0;
    bool hit=sent && continued && stopped(pid);
    siginfo_t info{};
    auto atHit=debugger.getContext(pid);
    check(hit && ptrace(PTRACE_GETSIGINFO,pid,nullptr,&info)==0 && info.si_signo==SIGTRAP &&
          info.si_code==TRAP_HWBKPT && atHit && atHit->instructionPointer()==code,
          "execution breakpoint traps at the exact native instruction address");
    if (!hit) return;
    check(debugger.removeBreakpoint(pid,0).has_value(),"native execution breakpoint is removed from its own bank");
    auto savedBank=readNativeHardwareBank(pid,true);
    syscall_test::arm(syscall_test::Fault::HardwareWriteOnce);
    auto failedArm=debugger.setBreakpoint(pid,0,code,0,0);
    syscall_test::clear();
    auto restoredBank=readNativeHardwareBank(pid,true);
    check(savedBank && !failedArm && failedArm.error().value()==EIO && syscall_test::triggered()==1 && restoredBank &&
          savedBank->entries[0].address==restoredBank->entries[0].address &&
          savedBank->entries[0].control==restoredBank->entries[0].control,
          "a real hardware programming failure restores and verifies the previous native slot");
    syscall_test::arm(syscall_test::Fault::HardwareRestoreFailure);
    auto brokenArm=debugger.setBreakpoint(pid,0,code,0,0);
    syscall_test::clear();
    check(!brokenArm && brokenArm.error()==std::make_error_code(std::errc::state_not_recoverable),
          "a failed hardware rollback is reported while ptrace ownership remains retained");
    check(savedBank && restoreNativeHardwareBank(pid,true,*savedBank).has_value(),
          "explicit recovery restores the saved native hardware bank before execution");
    check(debugger.removeBreakpoint(pid,0).has_value(),"recovered breakpoint ownership can be released");
    auto step=debugger.singleStep(pid);
    auto afterStep=debugger.getContext(pid);
    check(step && afterStep && atHit && afterStep->instructionPointer()>atHit->instructionPointer(),
          "native single-step advances a real instruction and captures the new PC");
    check(ptrace(PTRACE_CONT,pid,nullptr,nullptr)==0 && fixture.line()=="123456790",
          "single-stepped writer completes before a separate watchpoint operation");
    bool restopped=ptrace(PTRACE_INTERRUPT,pid,nullptr,nullptr)==0 && stopped(pid);
    check(restopped,"native debugger interrupts the running target without SIGSTOP");
    if (!restopped) return;
    auto watch=debugger.setBreakpoint(pid,0,value,1,3);
    if (!watch) printf("watchpoint error: %s\n",watch.error().message().c_str());
    check(watch.has_value(),"native four-byte hardware write watchpoint arms at the actual data address");
    if (!watch) return;
    sent=::write(fixture.input,&command,1)==1;
    hit=sent && ptrace(PTRACE_CONT,pid,nullptr,nullptr)==0 && stopped(pid);
    info={};
    uint32_t observed=0;
    bool infoRead=ptrace(PTRACE_GETSIGINFO,pid,nullptr,&info)==0;
    check(hit && infoRead && info.si_signo==SIGTRAP && info.si_code==TRAP_HWBKPT,
          "a native write produces a genuine hardware-watchpoint trap");
    bool valueRead=readMemory(pid,value,&observed,sizeof(observed))==sizeof(observed);
    // x86 data traps retire the store. ARM64 reports a precise fault at the
    // store and can stop before its effect, as the full-system guest verifies.
    check(valueRead && (expected==CpuArchitecture::Arm64 ?
          (observed==123456790 || observed==123456791) && reinterpret_cast<uintptr_t>(info.si_addr)==value :
          observed==123456791), "native watchpoint reports the correct watched access and architecture timing");
    if (valueRead) printf("HARDWARE_WATCHPOINT timing=%s\n",observed==123456790 ? "before-access" : "after-access");
    if (!hit) return;
    check(debugger.removeBreakpoint(pid,0).has_value() && clearNativeHardwareStatus(pid).has_value(),
          "watchpoint removal and status cleanup succeed before detach");
    auto postWatchStep=debugger.singleStep(pid);
    check(postWatchStep && readMemory(pid,value,&observed,sizeof(observed))==sizeof(observed) && observed==123456791,
          "stepping with the watchpoint removed completes the actual native store");
    auto detached=debugger.detach();
    check(detached && fixture.line()=="123456791", "target completes its command after native debugger detach");
    command='r';
    check(::write(fixture.input,&command,1)==1 && fixture.line()=="123456791",
          "target keeps executing with its original registers and no residual breakpoint");

    auto reattached=debugger.attach(pid);
    check(reattached.has_value(),"same target can reattach for native software-breakpoint checks");
    if (!reattached) return;
    std::array<uint8_t,32> originalCode{},restoredCode{};
    check(readMemory(pid,code,originalCode.data(),originalCode.size())==ssize_t(originalCode.size()),
          "software-breakpoint fixture retains its exact original instruction bytes");
    auto mode=expected==CpuArchitecture::Arm64 ? InstructionMode::Aarch64 :
        expected==CpuArchitecture::X86_32 ? InstructionMode::X86_32 : InstructionMode::X86_64;
    syscall_test::arm(syscall_test::Fault::SoftwareVerifyAndRestore);
    auto failedPatch=installNativeSoftwareBreakpoint(pid,code,mode);
    syscall_test::clear();
    check(!failedPatch && failedPatch.error().recovery && syscall_test::triggered()>=2,
          "failed software-breakpoint verification retains the original bytes and recovery record");
    if (failedPatch || !failedPatch.error().recovery) return;
    check(removeNativeSoftwareBreakpoint(pid,*failedPatch.error().recovery).has_value() &&
          !failedPatch.error().recovery->installed,
          "software-breakpoint recovery restores real target code before another operation");
    auto software=installNativeSoftwareBreakpoint(pid,code,mode);
    check(software.has_value(),"architecture-specific software trap installs on read-only executable code");
    if (!software) return;
    command='b';
    sent=::write(fixture.input,&command,1)==1;
    hit=sent && ptrace(PTRACE_CONT,pid,nullptr,nullptr)==0 && stopped(pid);
    auto softwareHit=debugger.getContext(pid);
    info={};
    check(hit && ptrace(PTRACE_GETSIGINFO,pid,nullptr,&info)==0 && info.si_signo==SIGTRAP &&
          (info.si_code==TRAP_BRKPT || (expected!=CpuArchitecture::Arm64 && info.si_code==SI_KERNEL)) &&
          softwareHit && nativeSoftwareBreakpointAddress(*softwareHit)==code,
          "native software trap fires with the correct architecture-specific PC semantics");
    if (!hit || !softwareHit) return;
    check(removeNativeSoftwareBreakpoint(pid,*software).has_value() &&
          removeNativeSoftwareBreakpoint(pid,*software).has_value() &&
          readMemory(pid,code,restoredCode.data(),restoredCode.size())==ssize_t(restoredCode.size()) &&
          originalCode==restoredCode,
          "software breakpoint restores exact code and adjacent bytes, and cleanup is idempotent");
    softwareHit->setInstructionPointer(code);
    check(debugger.setContext(pid,*softwareHit).has_value() && debugger.singleStep(pid).has_value(),
          "restored original instruction executes after the software trap is removed");
    check(debugger.detach().has_value() && fixture.line()=="123456792",
          "target completes the original writer after software-breakpoint recovery and detach");
    command='r';
    check(::write(fixture.input,&command,1)==1 && fixture.line()=="123456792",
          "target stays live after both native software and hardware breakpoint cycles");
    printf("DEBUG_BACKEND_RESULT=%s architecture=%s\n",failures==failuresBefore ? "PASSED" : "FAILED",
           cpuArchitectureName(expected));
}
template<class Predicate> static bool awaitState(Predicate predicate) {
    for (unsigned attempt=0;attempt<5000;++attempt) {
        if (predicate()) return true;
        usleep(1000);
    }
    return false;
}
static void fullSession(const char* path) {
    int failuresBefore=failures;
    Fixture fixture(path);
    std::istringstream line(fixture.line()); std::string magic;
    pid_t pid=0; unsigned width=0; uintptr_t value=0,pointer=0,code=0,call=0,afterCall=0,ret=0;
    line>>magic>>pid>>width>>std::hex>>value>>pointer>>code>>call>>afterCall>>ret;
    check(line && magic=="CE_TARGET" && pid==fixture.pid,"full debugger session fixture exposes actual code and call sites");
    if (!line || magic!="CE_TARGET" || pid!=fixture.pid) return;
    LinuxProcessHandle process(pid);
    auto expected=process.targetDescription().host.architecture;
    std::array<uint8_t,32> original{},restored{};
    if (readMemory(pid,code,original.data(),original.size())!=ssize_t(original.size())) return;
    char command='v';
    check(::write(fixture.input,&command,1)==1 && fixture.line()=="CE_VECTORS","full session fixture seeds native SIMD values before attachment");
    DebugSession session;
    std::atomic<unsigned> hits{0},steps{0},execs{0};
    std::atomic<uintptr_t> address{0}; std::atomic<pid_t> hitThread{0};
    session.setEventCallback([&](const DebugEvent& event) {
        address=event.address; hitThread=event.tid;
        if (event.type==DebugEventType::BreakpointHit) ++hits;
        if (event.type==DebugEventType::SingleStep) ++steps;
        if (event.type==DebugEventType::ProcessExecuted) ++execs;
    });
    bool attached=session.attach(pid,&process);
    if (!attached) printf("full session attach: %s\n",session.lastError().message().c_str());
    check(attached && session.isStopped(),"application DebugSession attaches through its real owner thread and all-stop loop");
    if (!attached) return;
    auto context=session.getStopContext();
    auto vectors=session.getVectorRegisters();
    const std::array<uint64_t,2> last{0x9999aaaabbbbccccULL,0xddddeeeeffff0000ULL};
    unsigned lastRegister=expected==CpuArchitecture::Arm64 ? 31 : expected==CpuArchitecture::X86_32 ? 7 : 15;
    check(context.architecture==expected && vectors.count==(expected==CpuArchitecture::Arm64 ? 32u : 16u) &&
          std::memcmp(vectors.registers[lastRegister].data(),last.data(),16)==0,
          "full session publishes the actual ISA and complete native SIMD register bank");
    auto edited=context;
    if (expected==CpuArchitecture::Arm64) edited.x[19]=0x76543210; else edited.rbx=0x76543210;
    bool editedOk=session.setStopContext(edited);
    auto observedContext=session.getStopContext();
    check(editedOk && (expected==CpuArchitecture::Arm64 ? observedContext.x[19] : observedContext.rbx)==0x76543210 &&
          session.setStopContext(context),"frontend register edits execute on the session owner and restore the original bank");

    syscall_test::arm(syscall_test::Fault::SoftwareVerifyAndRestore);
    int failed=session.setSoftwareBreakpoint(code);
    check(failed<0 && session.hasPendingRecovery(),"full session retains a failed software installation and its original code");
    syscall_test::clear();
    check(session.retryPendingOperations() && !session.hasPendingRecovery() &&
          readMemory(pid,code,restored.data(),restored.size())==ssize_t(restored.size()) && original==restored,
          "full session retries failed code restoration on the same ptrace owner");
    int software=session.setSoftwareBreakpoint(code);
    check(software>0,"full session installs its native software breakpoint");
    if (software<0) return;
    command='b'; ::write(fixture.input,&command,1); session.continueExecution();
    bool hit=awaitState([&]{return hits.load()==1 && session.isStopped();});
    context=session.getStopContext();
    check(hit && address==code && context.instructionPointer()==code && context.architecture==expected,
          "full event loop attributes the software trap and restores the correct native PC");
    if (!hit) return;
    session.step(StepMode::Into);
    check(steps==1 && session.getStopContext().instructionPointer()!=code,
          "full session steps the original instruction and rearms the software breakpoint");
    check(session.removeSoftwareBreakpoint(software) &&
          readMemory(pid,code,restored.data(),restored.size())==ssize_t(restored.size()) && original==restored,
          "session removal restores all native instruction bytes and their neighbors");
    session.continueExecution();
    check(fixture.line()=="123456790","target completes its original writer after session single-step");

    int otherHardware=session.setHardwareBreakpoint(pointer,1,width);
    check(otherHardware>0,"full session preserves a separate watchpoint in another native slot");
    int hardware=session.setHardwareBreakpoint(value,1,4);
    check(hardware>0,"full session arms a data watchpoint while the target is running");
    if (hardware<0) return;
    for (unsigned cycle=0;cycle<3;++cycle) {
        command='b'; ::write(fixture.input,&command,1);
        hit=awaitState([&]{return hits.load()==cycle+2 && session.isStopped();});
        check(hit && address==value && hitThread==pid,"full session attributes the actual native hardware watchpoint");
        if (!hit) return;
        session.continueExecution();
        auto output=fixture.line();
        check(output==std::to_string(123456791+cycle),"continuing a native watchpoint executes its store without retrapping or losing liveness");
        if (output.empty()) return;
    }
    command='t'; ::write(fixture.input,&command,1);
    hit=awaitState([&]{return hits.load()==5 && session.isStopped();});
    if (!hit || hitThread==pid || address!=value || session.stoppedThreads().size()<2)
        printf("clone stop: hits=%u tid=%d main=%d address=%lx watched=%lx threads=%zu attached=%d stopped=%d pending=%d error=%s\n",
               hits.load(),hitThread.load(),pid,(unsigned long)address.load(),(unsigned long)value,
               session.stoppedThreads().size(),session.isAttached(),session.isStopped(),session.hasPendingRecovery(),
               session.lastError().message().c_str());
    check(hit && hitThread!=pid && address==value && session.stoppedThreads().size()>=2,
          "session follows a newly cloned writer thread and stops the whole target at its watchpoint");
    if (!hit) return;
    check(session.selectThread(pid) && session.selectThread(hitThread),"full session can inspect and select both stopped thread register banks");
    session.continueExecution();
    check(fixture.line()=="123456794","new writer thread continues and exits after its native watchpoint");
    check(session.removeHardwareBreakpoint(hardware),"full session removes the native data watchpoint from every traced thread");
    check(session.removeHardwareBreakpoint(otherHardware),"removing one native watchpoint preserves the independently owned slot until its removal");

    unsigned priorHits=hits;
    int callBp=session.setSoftwareBreakpoint(call);
    command='c'; ::write(fixture.input,&command,1);
    hit=awaitState([&]{return hits.load()>priorHits && session.isStopped();});
    check(callBp>0 && hit && address==call,"full session stops at the real native call instruction");
    if (!hit) return;
    unsigned priorSteps=steps;
    session.step(StepMode::Over);
    check(steps==priorSteps+1 && session.getStopContext().instructionPointer()==afterCall,
          "step-over decodes the target ISA and completes at the native call return address");
    check(session.removeSoftwareBreakpoint(callBp),"native call breakpoint removes cleanly after step-over");
    session.continueExecution();
    check(fixture.line()=="123456795","native caller completes after step-over without code or stack corruption");

    priorHits=hits;
    software=session.setSoftwareBreakpoint(code);
    command='c'; ::write(fixture.input,&command,1);
    hit=awaitState([&]{return hits.load()>priorHits && session.isStopped();});
    if (!hit) { check(false,"native callee entry breakpoint for step-out"); return; }
    priorSteps=steps;
    session.step(StepMode::Out);
    check(steps==priorSteps+1 && session.getStopContext().instructionPointer()==afterCall,
          "entry step-out uses the native saved return register or stack slot");
    session.removeSoftwareBreakpoint(software);
    session.continueExecution();
    check(fixture.line()=="123456796","native caller keeps executing after callee step-out");

    priorHits=hits;
    callBp=session.setSoftwareBreakpoint(call);
    command='c'; ::write(fixture.input,&command,1);
    hit=awaitState([&]{return hits.load()>priorHits && session.isStopped();});
    if (!hit) { check(false,"native call breakpoint for run-to-cursor"); return; }
    priorSteps=steps;
    session.step(StepMode::RunToCursor,ret);
    check(steps==priorSteps+1 && session.getStopContext().instructionPointer()==ret,
          "run-to-cursor executes and restores its architecture-specific temporary breakpoint");
    session.removeSoftwareBreakpoint(callBp);
    session.continueExecution();
    check(fixture.line()=="123456797","native return instruction executes after temporary breakpoint cleanup");

    software=session.setSoftwareBreakpoint(code);
    command='x'; ::write(fixture.input,&command,1);
    bool executed=awaitState([&]{return execs.load()==1 && session.isStopped();});
    check(executed && session.removeSoftwareBreakpoint(software) &&
          readMemory(pid,code,restored.data(),restored.size())==ssize_t(restored.size()) && original==restored,
          "exec discards old breakpoint ownership without writing old code into the replacement image");
    if (!executed) return;
    session.continueExecution();
    check(fixture.line().starts_with("CE_TARGET "),"replacement program starts after the full debugger exec stop");
    command='b'; ::write(fixture.input,&command,1);
    check(fixture.line()=="123456790","replacement program runs with no residual old-image breakpoint");
    session.detach();
    check(!session.isAttached() && !session.hasPendingRecovery(),"full session detach drains restoration on its original owner thread");
    command='r'; ::write(fixture.input,&command,1);
    check(fixture.line()=="123456790","target remains live after full session detach and exec transition");
    printf("DEBUG_SESSION_RESULT=%s architecture=%s\n",failures==failuresBefore ? "PASSED" : "FAILED",cpuArchitectureName(expected));
}
static void sessionRecovery(const char* path) {
    int failuresBefore=failures;
    {
        Fixture fixture(path);
        std::istringstream line(fixture.line()); std::string magic;
        pid_t pid=0; unsigned width=0; uintptr_t value=0,pointer=0,code=0;
        line>>magic>>pid>>width>>std::hex>>value>>pointer>>code;
        check(line && magic=="CE_TARGET" && pid==fixture.pid,"session interrupted-step fixture starts");
        if (!line || magic!="CE_TARGET" || pid!=fixture.pid) return;
        LinuxProcessHandle process(pid);
        DebugSession session;
        std::atomic<bool> breakpointHit{false},signalStopped{false};
        session.setEventCallback([&](const DebugEvent& event) {
            if (event.type==DebugEventType::BreakpointHit) breakpointHit=true;
            if (event.type==DebugEventType::SignalReceived && event.signal==SIGWINCH) signalStopped=true;
        });
        bool attached=session.attach(pid,&process);
        int bp=attached ? session.setSoftwareBreakpoint(code) : -1;
        char command='b';
        bool sent=::write(fixture.input,&command,1)==1;
        session.continueExecution();
        bool hit=sent && awaitState([&] { return breakpointHit.load() && session.isStopped(); });
        check(attached && bp>0 && hit,"session reaches an owned trap before an interrupted instruction step");
        if (!hit) return;
        syscall_test::arm(syscall_test::Fault::IgnoredStepSignal);
        session.step(StepMode::Into);
        syscall_test::clear();
        check(signalStopped && session.isStopped() && !session.hasPendingRecovery(),
              "a signal during single-step keeps the target stopped until software traps are safely rearmed");
        session.continueExecution();
        check(fixture.line()=="123456790","continuing an interrupted step forwards its signal and executes the original instruction");
        check(session.removeSoftwareBreakpoint(bp),"interrupted-step breakpoint cleanup succeeds");
    }
    {
        Fixture fixture(path);
        std::istringstream line(fixture.line()); std::string magic;
        pid_t pid=0; unsigned width=0; uintptr_t value=0,pointer=0,code=0;
        line>>magic>>pid>>width>>std::hex>>value>>pointer>>code;
        check(line && magic=="CE_TARGET" && pid==fixture.pid,"session destruction fixture starts");
        if (!line || magic!="CE_TARGET" || pid!=fixture.pid) return;
        LinuxProcessHandle process(pid);
        std::array<uint8_t,32> original{},restored{};
        if (readMemory(pid,code,original.data(),original.size())!=ssize_t(original.size())) return;
        auto session=std::make_unique<DebugSession>();
        bool attached=session->attach(pid,&process);
        check(attached && session->setSoftwareBreakpoint(code)>0,"session owns a planted trap before caller destruction");
        if (!attached) return;
        syscall_test::arm(syscall_test::Fault::SoftwareVerifyAndRestore);
        std::atomic<bool> faultObserved{false},ownerRetained{false};
        std::thread releaseFault([&] {
            faultObserved=awaitState([] { return syscall_test::triggered()>0; });
            if (faultObserved) {
                std::ifstream status("/proc/"+std::to_string(pid)+"/status");
                std::string text;
                while (std::getline(status,text))
                    if (text.starts_with("TracerPid:")) ownerRetained=std::stoi(text.substr(10))>0;
            }
            syscall_test::clear();
        });
        session.reset();
        releaseFault.join();
        check(faultObserved && ownerRetained,"caller destruction retains ptrace ownership until failed code cleanup can be verified");
        check(readMemory(pid,code,restored.data(),restored.size())==ssize_t(restored.size()) && original==restored,
              "session destruction retries and verifies the exact original instruction bytes");
        char command='b';
        check(::write(fixture.input,&command,1)==1 && fixture.line()=="123456790",
              "target remains live after session destruction and failed cleanup recovery");
    }
    {
        Fixture fixture(path);
        std::istringstream line(fixture.line()); std::string magic;
        pid_t pid=0; unsigned width=0; uintptr_t value=0,pointer=0,code=0;
        line>>magic>>pid>>width>>std::hex>>value>>pointer>>code;
        check(line && magic=="CE_TARGET" && pid==fixture.pid,"session signal-delivery fixture starts");
        if (!line || magic!="CE_TARGET" || pid!=fixture.pid) return;
        LinuxProcessHandle process(pid);
        DebugSession session;
        std::atomic<bool> signalStopped{false},signalExited{false};
        session.setEventCallback([&](const DebugEvent& event) {
            if (event.type==DebugEventType::ExceptionBreakpointHit && event.signal==SIGTRAP) signalStopped=true;
            if (event.type==DebugEventType::ProcessExited && event.signal==SIGTRAP) signalExited=true;
        });
        bool attached=session.attach(pid,&process);
        check(attached,"full session attaches before testing a genuine user signal");
        if (!attached) return;
        session.addExceptionBreakpoint(SIGTRAP);
        session.continueExecution();
        bool sent=kill(pid,SIGTRAP)==0;
        check(sent && awaitState([&] { return signalStopped.load() && session.isStopped(); }),
              "a genuine user SIGTRAP is surfaced without being confused with an owned breakpoint");
        session.continueExecution();
        check(awaitState([&] { return signalExited.load() && !session.isAttached(); }),
              "continuing an exception breakpoint preserves genuine signal delivery and process-exit notification");
    }
    printf("DEBUG_RECOVERY_RESULT=%s\n",failures==failuresBefore ? "PASSED" : "FAILED");
}
static void codeFinderBackend(const char* path) {
    int failuresBefore=failures;
    Fixture fixture(path);
    std::istringstream header(fixture.line()); std::string magic;
    pid_t pid=0; unsigned width=0; uintptr_t value=0,pointer=0,code=0;
    header>>magic>>pid>>width>>std::hex>>value>>pointer>>code;
    check(header && magic=="CE_TARGET" && pid==fixture.pid,"native CodeFinder fixture starts");
    if (!header || magic!="CE_TARGET" || pid!=fixture.pid) return;
    LinuxProcessHandle process(pid); LinuxDebugger debugger;
    bool arm64=process.targetDescription().host.architecture==CpuArchitecture::Arm64;
    Disassembler decoder(arm64 ? Arch::ARM64 : process.targetDescription().host.architecture==CpuArchitecture::X86_32 ? Arch::X86_32 : Arch::X86_64);
    std::array<uint8_t,32> bytes{};
    auto read=process.read(code,bytes.data(),bytes.size());
    auto instructions=read ? decoder.disassemble(code,{bytes.data(),*read}) : std::vector<Instruction>{};
    auto store=std::find_if(instructions.begin(),instructions.end(),[&](const auto& instruction) {
        auto bracket=instruction.operands.find('['),comma=instruction.operands.find(',');
        return arm64 ? instruction.mnemonic=="str" :
            (instruction.mnemonic=="mov" || instruction.mnemonic=="add") && bracket<comma;
    });
    check(store!=instructions.end(),"fixture exposes an independently decoded native store instruction");
    if (store==instructions.end()) return;
    auto stopForBank=[&] {
        int status=0;
        return ptrace(PTRACE_SEIZE,pid,nullptr,nullptr)==0 && ptrace(PTRACE_INTERRUPT,pid,nullptr,nullptr)==0 &&
            waitpid(pid,&status,__WALL)==pid && WIFSTOPPED(status);
    };
    bool stopped=stopForBank();
    auto originalBank=readNativeHardwareBank(pid,false);
    auto occupied=stopped ? setNativeHardwareBreakpoint(pid,0,0x1000,HardwareBreakpointAccess::Write,4) :
        Result<void>(std::unexpected(std::make_error_code(std::errc::no_such_process)));
    auto configuredSlot=occupied ? setNativeHardwareBreakpoint(pid,1,0x2000,HardwareBreakpointAccess::ReadWrite,2) : occupied;
    auto disabledSlot=configuredSlot ? removeNativeHardwareBreakpoint(pid,1,false) : configuredSlot;
    auto reservedBank=readNativeHardwareBank(pid,false);
    bool released=ptrace(PTRACE_DETACH,pid,nullptr,nullptr)==0;
    check(stopped && originalBank && occupied && disabledSlot && reservedBank && released,
          "CodeFinder fixture retains occupied and previously configured disabled slots before monitoring");
    CodeFinder finder;
    bool started=finder.start(process,debugger,value,true,4);
    check(started,"real CodeFinder arms native data banks before reporting startup success");
    if (!started) return;
    for (unsigned i=0;i<3;++i) {
        char command='b';
        check(::write(fixture.input,&command,1)==1 && fixture.line()==std::to_string(123456790+i),
              "target completes a native store while CodeFinder records and rearms its watchpoint");
    }
    auto hits=finder.results();
    check(std::any_of(hits.begin(),hits.end(),[&](const auto& hit) {
        return hit.instructionAddress==store->address && hit.hitCount==3 &&
            hit.firstContext.instructionPointer()==store->address+(arm64 ? 0 : store->size) &&
            !hit.instructionBytes.empty() && hit.firstContext.architecture==process.targetDescription().host.architecture;
    }),"CodeFinder reports the exact native store and correct pre/post-access register timing");
    char command='t';
    check(::write(fixture.input,&command,1)==1 && fixture.line()=="123456793",
          "CodeFinder arms a newly cloned writer before its first store and lets it exit");
    hits=finder.results();
    check(std::any_of(hits.begin(),hits.end(),[&](const auto& hit) { return hit.instructionAddress==store->address && hit.hitCount==4; }),
          "CodeFinder attributes cloned-thread accesses to the same real writer instruction");
    finder.stop(); command='b';
    check(!finder.running() && !finder.hasPendingRecovery() && ::write(fixture.input,&command,1)==1 && fixture.line()=="123456794",
          "CodeFinder restores every original native bank and detaches without a residual watchpoint");
    stopped=stopForBank();
    auto restoredBank=readNativeHardwareBank(pid,false);
    check(stopped && restoredBank && reservedBank && restoredBank->count==reservedBank->count &&
          restoredBank->control==reservedBank->control && restoredBank->status==reservedBank->status &&
          std::equal(restoredBank->entries.begin(),restoredBank->entries.end(),reservedBank->entries.begin(),
              [arm64](const auto& a,const auto& b) {
                  return a.address==b.address && (arm64 && !b.control ? !(a.control&1u) : a.control==b.control);
              }),
          "CodeFinder preserves the independent slot exactly and restores all addresses and enable/control state");
    check(!arm64 || (reservedBank && restoredBank &&
          restoredBank->entries[2].control==reservedBank->entries[2].control &&
          restoredBank->entries[3].control==reservedBank->entries[3].control),
          "ARM64 hardware cleanup does not create unused later-slot perf events");
    bool bankReset=originalBank && restoreNativeHardwareBank(pid,false,*originalBank).has_value();
    released=ptrace(PTRACE_DETACH,pid,nullptr,nullptr)==0;
    check(bankReset && released,"independently owned test watchpoint removes cleanly after CodeFinder restoration");

    started=finder.start(process,debugger,value,true,4);
    syscall_test::arm(syscall_test::Fault::HardwareCleanupFailure);
    std::atomic<bool> finished=false;
    std::thread cleanup([&] { finder.stop(); finished=true; });
    bool fault=awaitState([] { return syscall_test::triggered()>1; });
    check(started && fault && !finished && finder.hasPendingRecovery() && process.targetDescription().tracerPid>0,
          "failed CodeFinder cleanup keeps its owner, stopped target and exact original hardware bank");
    syscall_test::clear(); cleanup.join(); command='b';
    check(!finder.hasPendingRecovery() && ::write(fixture.input,&command,1)==1 && fixture.line()=="123456795",
          "CodeFinder retries failed hardware restoration before releasing the target");

    syscall_test::arm(syscall_test::Fault::HardwareRestoreFailure);
    cleanup=std::thread([&] { started=finder.start(process,debugger,value,true,4); });
    fault=awaitState([&] { return syscall_test::triggered()>1 && finder.hasPendingRecovery(); });
    check(fault && finder.hasPendingRecovery() && process.targetDescription().tracerPid>0,
          "failed CodeFinder startup retains cleanup ownership after a partially written bank");
    syscall_test::clear(); cleanup.join(); command='b';
    check(!started && ::write(fixture.input,&command,1)==1 && fixture.line()=="123456796",
          "failed CodeFinder startup restores the target before returning failure");

    started=finder.start(process,debugger,value,true,4);
    command='x'; bool sent=::write(fixture.input,&command,1)==1;
    std::istringstream replacement(fixture.line()); replacement>>magic>>pid;
    bool retired=awaitState([&] { return !finder.running(); });
    finder.stop();
    check(started && sent && retired && replacement && magic=="CE_TARGET" && pid==fixture.pid,
          "CodeFinder ends on exec without replaying old-image debug banks");
    command='b';
    check(::write(fixture.input,&command,1)==1 && fixture.line()=="123456790",
          "replacement image runs without an old-image CodeFinder watchpoint");

    {
        Fixture signalled(path); std::istringstream line(signalled.line());
        line>>magic>>pid>>width>>std::hex>>value>>pointer>>code;
        LinuxProcessHandle target(signalled.pid); CodeFinder signalFinder;
        started=signalFinder.start(target,debugger,value,true,4);
        bool delivered=kill(signalled.pid,SIGTRAP)==0;
        bool exited=awaitState([&] { return !signalFinder.running(); }); signalFinder.stop();
        check(line && started && delivered && exited && !target.targetDescription().live,
              "CodeFinder preserves genuine user SIGTRAP delivery instead of swallowing the signal");
    }
    {
        Fixture exiting(path); std::istringstream line(exiting.line());
        line>>magic>>pid>>width>>std::hex>>value>>pointer>>code;
        LinuxProcessHandle target(exiting.pid); CodeFinder exitFinder;
        started=exitFinder.start(target,debugger,value,true,4);
        syscall_test::arm(syscall_test::Fault::HardwareCleanupFailure);
        cleanup=std::thread([&] { exitFinder.stop(); });
        fault=awaitState([] { return syscall_test::triggered()>1; });
        bool killed=kill(exiting.pid,SIGKILL)==0;
        cleanup.join(); syscall_test::clear();
        check(line && started && fault && killed && !exitFinder.hasPendingRecovery(),
              "target exit drains failed CodeFinder cleanup without hanging on a dead bank");
    }
    printf("CODEFINDER_BACKEND_RESULT=%s architecture=%s\n",failures==failuresBefore ? "PASSED" : "FAILED",
           cpuArchitectureName(process.targetDescription().host.architecture));
}

static void codeFinderTeardownBackend(const char* path) {
    const int initial=failures;
    CpuArchitecture architecture=CpuArchitecture::Unknown;
    for (int signal : {0,SIGUSR1,SIGSTOP}) {
        Fixture fixture(path);
        std::istringstream header(fixture.line()); std::string magic;
        pid_t pid=0; unsigned width=0; uintptr_t value=0,pointer=0,code=0;
        header>>magic>>pid>>width>>std::hex>>value>>pointer>>code;
        check(header && magic=="CE_TARGET" && pid==fixture.pid,"teardown race starts an independent native target");
        if (!header || magic!="CE_TARGET" || pid!=fixture.pid) continue;
        char command='S';
        bool sent=::write(fixture.input,&command,1)==1;
        std::istringstream busy(fixture.line()); uintptr_t flag=0,counter=0;
        busy>>magic>>std::hex>>flag>>counter;
        check(sent && busy && magic=="CE_CALL_BUSY" && flag && counter,"teardown fixture continuously executes a real watched store");
        if (!busy || !flag || !counter) continue;
        LinuxProcessHandle process(pid); LinuxDebugger debugger; CodeFinder finder;
        architecture=process.targetDescription().host.architecture;
        auto stopForBank=[&] {
            int status=0;
            return ptrace(PTRACE_SEIZE,pid,nullptr,nullptr)==0 && ptrace(PTRACE_INTERRUPT,pid,nullptr,nullptr)==0 &&
                waitpid(pid,&status,__WALL)==pid && WIFSTOPPED(status);
        };
        bool stopped=stopForBank();
        auto original=readNativeHardwareBank(pid,false);
        bool released=ptrace(PTRACE_DETACH,pid,nullptr,nullptr)==0;
        check(stopped && original && released,"teardown saves the real original hardware bank before CodeFinder takes ownership");
        if (!stopped || !original || !released) continue;
        bool started=finder.start(process,debugger,counter,true,4);
        if (started) syscall_test::queueHardwareRace(pid,counter,signal);
        finder.stop();
        bool raced=syscall_test::hardwareRaceObserved(); syscall_test::clear();
        check(started && raced,"cleanup encounters a kernel queued hardware SIGTRAP behind an interrupt stop");
        check(!finder.running() && !finder.hasPendingRecovery() && fixtureTracer(pid)==0,
              "teardown drains the owned trap and releases its actual ptrace owner");
        if (signal==SIGUSR1) {
            int status=0; pid_t waited=0;
            for (unsigned attempt=0;attempt<2000 && !waited;++attempt) {
                waited=waitpid(pid,&status,WNOHANG); if (!waited) usleep(1000);
            }
            check(waited==pid && WIFSIGNALED(status) && WTERMSIG(status)==SIGUSR1,
                  "cleanup preserves the application SIGUSR1 instead of replacing it with its hardware SIGTRAP");
            if (waited==pid) fixture.pid=-1;
            continue;
        }
        if (signal==SIGSTOP) {
            int status=0; pid_t waited=0;
            for (unsigned attempt=0;attempt<2000 && !waited;++attempt) {
                waited=waitpid(pid,&status,WUNTRACED|WNOHANG); if (!waited) usleep(1000);
            }
            unsigned before=0,after=0;
            bool readable=readMemory(pid,counter,&before,sizeof(before))==sizeof(before);
            usleep(20000);
            readable=readable && readMemory(pid,counter,&after,sizeof(after))==sizeof(after);
            check(waited==pid && WIFSTOPPED(status) && WSTOPSIG(status)==SIGSTOP && readable && before==after,
                  "queued application SIGSTOP remains a genuine stopped target after watchpoint cleanup");
            check(kill(pid,SIGCONT)==0,"the application's SIGCONT resumes its preserved stop");
        }
        stopped=stopForBank();
        auto restored=readNativeHardwareBank(pid,false);
        released=ptrace(PTRACE_DETACH,pid,nullptr,nullptr)==0;
        const bool arm64=architecture==CpuArchitecture::Arm64;
        check(stopped && restored && released && original->count==restored->count &&
              original->control==restored->control && original->status==restored->status &&
              std::equal(original->entries.begin(),original->entries.end(),restored->entries.begin(),
                  [arm64](const auto& a,const auto& b) {
                      return a.address==b.address && (arm64 && !a.control ? !(b.control&1u) : a.control==b.control);
                  }),"queued-trap cleanup restores the original hardware addresses, control and status");
        unsigned zero=0;
        bool resumed=writeMemory(pid,flag,&zero,sizeof(zero))==sizeof(zero);
        check(resumed && fixture.line()=="CE_CALL_DONE" && fixture.value(),
              "the original program continues its computation and console work without a leaked hardware trap");
    }
    printf("CODEFINDER_TEARDOWN_RESULT=%s architecture=%s\n",failures==initial ? "PASSED" : "FAILED",
           cpuArchitectureName(architecture));
}

static void stoppedFunctionBackend(const char* path,char loopCommand='S') {
    int initial=failures;
    Fixture fixture(path);
    check(fixture.line().starts_with("CE_TARGET "),"native function fixture starts a real process");
    char command='j';
    bool sent=::write(fixture.input,&command,1)==1;
    std::istringstream addresses(fixture.line()); std::string magic;
    uintptr_t sum=0,wait=0,fault=0,waiting=0,entered=0;
    addresses>>magic>>std::hex>>sum>>wait>>fault>>waiting>>entered;
    check(sent && addresses && magic=="CE_FUNCTION" && sum && wait && fault && waiting && entered,
          "fixture publishes real native callable functions and their wait controls");
    if (!addresses || !sum || !wait || !fault || !waiting || !entered) return;
    LinuxProcessHandle process(fixture.pid);
    auto host=process.targetDescription().host;
    auto page=static_cast<uintptr_t>(sysconf(_SC_PAGESIZE));
    auto frame=process.allocate(18*page,MemProt::Read|MemProt::Write);
    bool guards=frame && process.protect(*frame,page,MemProt::Read|MemProt::Exec) &&
        process.protect(*frame+page,page,MemProt::None) && process.protect(*frame+17*page,page,MemProt::None);
    check(guards,"native call uses an executable private page and a separate guarded private stack");
    if (!guards) return;
    int blockedStatus=0;
    bool blockedOwned=ptrace(PTRACE_SEIZE,fixture.pid,nullptr,nullptr)==0 && ptrace(PTRACE_INTERRUPT,fixture.pid,nullptr,nullptr)==0 &&
        waitpid(fixture.pid,&blockedStatus,__WALL)==fixture.pid && WIFSTOPPED(blockedStatus);
    auto blocked=readNativeContext(fixture.pid);
    std::array<uint8_t,16> beforeCode{},afterCode{};
    bool privateSaved=readMemory(fixture.pid,*frame,beforeCode.data(),beforeCode.size())==ssize_t(beforeCode.size());
    auto refused=executeStoppedFunction(fixture.pid,host,sum,{1,2,3,4,5,6,7,8},*frame,*frame+17*page);
    auto blockedAfter=readNativeContext(fixture.pid);
    check(blockedOwned && blocked && blockedAfter && !refused && refused.error().code==std::errc::not_supported &&
          !refused.error().recovery && !refused.error().completedValue && privateSaved &&
          readMemory(fixture.pid,*frame,afterCode.data(),afterCode.size())==ssize_t(afterCode.size()) && beforeCode==afterCode &&
          blocked->instructionPointer()==blockedAfter->instructionPointer() && blocked->stackPointer()==blockedAfter->stackPointer(),
          "a real blocked read, including ARM64's cleared syscall slot and rewound SVC, rejects a native call before private code or context mutation");
    check(ptrace(PTRACE_DETACH,fixture.pid,nullptr,nullptr)==0 && fixture.value(),
          "the refused parked-thread call resumes the original blocked read and console work");
    command=loopCommand;
    sent=::write(fixture.input,&command,1)==1;
    std::istringstream ready(fixture.line()); uintptr_t spinning=0,counter=0;
    ready>>magic>>std::hex>>spinning>>counter;
    uint32_t heartbeat=0;
    bool seeded=false;
    for (unsigned attempt=0;attempt<1000 && !seeded;++attempt) {
        seeded=counter && readMemory(fixture.pid,counter,&heartbeat,4)==4 && heartbeat;
        if (!seeded) usleep(1000);
    }
    check(sent && ready && spinning && seeded,"call fixture seeds SIMD state and reaches an actual user-mode stop");
    if (!sent || !ready || !spinning || !seeded) return;
    int status=0;
    bool stopped=ptrace(PTRACE_SEIZE,fixture.pid,nullptr,reinterpret_cast<void*>(PTRACE_O_TRACEEXEC))==0 &&
        ptrace(PTRACE_INTERRUPT,fixture.pid,nullptr,nullptr)==0 && waitpid(fixture.pid,&status,__WALL)==fixture.pid && WIFSTOPPED(status);
#if defined(__x86_64__)
    using Registers=user_regs_struct;
#else
    using Registers=user_pt_regs;
#endif
    auto registers=[&]() -> Result<Registers> {
        Registers r{};
#if defined(__x86_64__)
        if (ptrace(PTRACE_GETREGS,fixture.pid,nullptr,&r)<0)
#else
        iovec io{&r,sizeof(r)};
        if (ptrace(PTRACE_GETREGSET,fixture.pid,reinterpret_cast<void*>(NT_PRSTATUS),&io)<0 || io.iov_len!=sizeof(r))
#endif
            return std::unexpected(std::error_code(errno,std::system_category()));
        return r;
    };
    auto original=registers();
    auto extended=captureNativeExtendedContext(fixture.pid);
    uint64_t mask=0;
    bool maskSaved=ptrace(PTRACE_GETSIGMASK,fixture.pid,reinterpret_cast<void*>(sizeof(mask)),&mask)==0;
    auto context=readNativeContext(fixture.pid);
    std::array<uint8_t,2048> stack{},afterStack{};
    uintptr_t stackAddress=context ? context->stackPointer()-stack.size() : 0;
    bool stackSaved=stackAddress && readMemory(fixture.pid,stackAddress,stack.data(),stack.size())==ssize_t(stack.size());
    check(stopped && original && extended && maskSaved && stackSaved,
          "native function snapshots every kernel GP and extended register, signal mask and original stack bytes");
    if (!stopped || !original || !extended || !maskSaved || !stackSaved) return;
    auto unchanged=[&]() {
        auto actual=registers();
#if defined(__aarch64__)
        // PSTATE.SS belongs to the kernel's ptrace single-step state, including
        // the signal-return step. Compare every target-owned GP bit exactly.
        Registers expected=*original;
        expected.pstate&=~(uint64_t{1}<<21);
        if (actual) actual->pstate&=~(uint64_t{1}<<21);
#else
        Registers expected=*original;
#endif
        uint64_t actualMask=0;
        bool gp=actual && std::memcmp(&expected,&*actual,sizeof(Registers))==0;
        bool banks=verifyNativeExtendedContext(fixture.pid,*extended).has_value();
        bool maskSame=ptrace(PTRACE_GETSIGMASK,fixture.pid,reinterpret_cast<void*>(sizeof(actualMask)),&actualMask)==0 && actualMask==mask;
        bool stackSame=readMemory(fixture.pid,stackAddress,afterStack.data(),afterStack.size())==ssize_t(afterStack.size()) && stack==afterStack;
        bool owner=fixtureTracer(fixture.pid)==getpid();
        if (!gp || !banks || !maskSame || !stackSame || !owner)
            fprintf(stderr,"call context mismatch loop=%c gp=%d extensions=%d mask=%d stack=%d owner=%d\n",loopCommand,gp,banks,maskSame,stackSame,owner);
        return gp && banks && maskSame && stackSame && owner;
    };
    std::array<uint64_t,8> args{1,2,3,4,5,6,7,8};
    auto result=executeStoppedFunction(fixture.pid,host,sum,args,*frame,*frame+17*page);
    if (!result) fprintf(stderr,"native function sum error: %s signal=%d recovery=%d\n",result.error().message().c_str(),result.error().pendingSignal,bool(result.error().recovery));
    check(result && *result==87654321 && unchanged(),
          "eight native arguments, including x86 stack arguments, return exactly and restore SIMD, GP, mask and original stack bytes");
    if (!result) return;
    auto again=executeStoppedFunction(fixture.pid,host,sum,args,*frame,*frame+17*page);
    check(again && *again==87654321 && unchanged(),"a private call frame can be reused without leaking target register or stack state");
    for (auto readFault : {syscall_test::Fault::FunctionReturnRead,syscall_test::Fault::FunctionReturnOpcode}) {
        syscall_test::arm(readFault);
        auto unread=executeStoppedFunction(fixture.pid,host,sum,args,*frame,*frame+17*page);
        bool held=!unread && unread.error().recovery && !unread.error().completedValue && syscall_test::triggered()>0;
        syscall_test::clear();
        check(held,"a transient return-register or opcode read failure retains the unclassified stop without reporting a result");
        check(held && unread.error().recovery->retry() && unread.error().recovery->functionResult()==87654321 && unchanged(),
              "retry classifies the saved return stop before continuing and restores the completed call exactly");
        if (!held) return;
    }
    uint32_t raceOne=1,raceZero=0;
    writeMemory(fixture.pid,waiting,&raceOne,4); writeMemory(fixture.pid,entered,&raceZero,4);
    syscall_test::arm(syscall_test::Fault::FunctionInterruptRace);
    auto raced=executeStoppedFunction(fixture.pid,host,wait,{waiting,0,0,0,0,0,0,0},*frame,*frame+17*page,10);
    bool realRace=syscall_test::triggered()>0;
    syscall_test::clear();
    if (!raced && raced.error().recovery) {
        auto ticket=raced.error().recovery;
        auto recovered=ticket->retry();
        if (recovered && ticket->functionResult()) raced=*ticket->functionResult();
    }
    check(realRace && raced && *raced==73 && unchanged(),
          "a real timeout interrupt racing the queued return trap is drained in private code before original context restoration");
    auto afterRace=executeStoppedFunction(fixture.pid,host,sum,args,*frame,*frame+17*page);
    check(afterRace && *afterRace==87654321 && unchanged(),"a raced timeout leaves no stale owned interrupt for the next native call");
    if (!raced || !afterRace) return;
    std::vector<syscall_test::Fault> initialFaults{syscall_test::Fault::InitialInstructionWrite,syscall_test::Fault::InitialRegistersWrite};
#if defined(__aarch64__)
    initialFaults.push_back(syscall_test::Fault::InitialSyscallWrite);
#endif
    for (auto faultKind : initialFaults) {
        syscall_test::arm(faultKind);
        auto rejected=executeStoppedFunction(fixture.pid,host,sum,args,*frame,*frame+17*page);
        bool applied=syscall_test::triggered()>0;
        syscall_test::clear();
        check(!rejected && applied && !rejected.error().completedValue && !rejected.error().recovery && unchanged(),
              "a reported setup error after a real private instruction or register write restores the original context without running the callee");
    }
    syscall_test::arm(syscall_test::Fault::FunctionRestoreRegisters);
    auto recoveryFailure=executeStoppedFunction(fixture.pid,host,sum,args,*frame,*frame+17*page);
    bool recoveryHeld=!recoveryFailure && recoveryFailure.error().recovery && recoveryFailure.error().completedValue==87654321 &&
        syscall_test::triggered()>0 && recoveryFailure.error().recovery->functionResult()==87654321;
    syscall_test::clear();
    check(recoveryHeld,"failure restoring a completed native call retains the actual return value and exact owner recovery");
    check(recoveryHeld && recoveryFailure.error().recovery->retry() && unchanged(),
          "retry restores a completed call without invoking the function a second time");
    if (!recoveryHeld) return;
    for (auto signal : {SIGWINCH,SIGTRAP}) {
        uint32_t one=1,zero=0;
        writeMemory(fixture.pid,waiting,&one,4); writeMemory(fixture.pid,entered,&zero,4);
        auto start=std::chrono::steady_clock::now();
        auto pending=executeStoppedFunction(fixture.pid,host,wait,{},*frame,*frame+17*page,10);
        auto elapsed=std::chrono::steady_clock::now()-start;
        uint32_t started=0;
        bool retained=!pending && pending.error().recovery && pending.error().code==std::errc::timed_out &&
            !pending.error().completedValue && elapsed<std::chrono::seconds(2) &&
            readMemory(fixture.pid,entered,&started,4)==4 && started==1;
        check(retained,"a real unfinished callee is bounded by its timeout and retains ownership without inventing a return value");
        if (!retained) return;
        auto ticket=pending.error().recovery;
        bool refused=false;
        std::thread other([&] { auto attempted=ticket->retry(); refused=!attempted && attempted.error()==std::errc::operation_not_permitted; });
        other.join();
        check(refused,"an unfinished native call refuses recovery from a different host owner thread");
        kill(fixture.pid,signal);
        auto interrupted=ticket->retry();
        check(!interrupted && interrupted.error()==std::errc::interrupted && !ticket->functionResult(),
              "an external signal or foreign SIGTRAP remains a delivery stop rather than being mistaken for the private return trap");
        auto undecided=ticket->retry();
        check(!undecided && undecided.error()==std::errc::interrupted,"retry does not silently suppress an undecided native call signal");
        bool released=writeMemory(fixture.pid,waiting,&zero,4)==4;
        auto resumed=ticket->resumeFunction(signal==SIGWINCH);
        for (unsigned attempt=0;attempt<20 && !resumed && resumed.error()==std::errc::timed_out;++attempt) resumed=ticket->retry();
        check(released && resumed && ticket->functionResult()==73 && ticket->retry() && unchanged(),
              "an explicit signal decision completes the original callee, restores its context and makes recovery idempotent");
        if (!resumed) return;
    }
    syscall_test::arm(syscall_test::Fault::ForbidTextWrite);
    auto freed=executeOwnedMemorySyscall(fixture.pid,host,MemorySyscall::Unmap,{*frame,18*page,0,0,0,0});
    bool noPatch=syscall_test::triggered()==0; syscall_test::clear();
    check(freed && noPatch && unchanged(),"an owned existing syscall releases the private frame without touching shared code or detaching");
    uint32_t zero=0;
    bool detached=ptrace(PTRACE_DETACH,fixture.pid,nullptr,nullptr)==0;
    bool finished=detached && writeMemory(fixture.pid,spinning,&zero,4)==4;
    const char* done=loopCommand=='S' ? "CE_CALL_DONE" : (loopCommand=='E' || loopCommand=='F' ? "CE_SVE_DONE" : "CE_SME_DONE");
    check(finished && fixture.line()==done && fixture.value(),"native call and cleanup resume the original CPU loop and console work");
    if (loopCommand=='S') {
        auto crashFrame=process.allocate(18*page,MemProt::Read|MemProt::Write);
        bool executable=crashFrame && process.protect(*crashFrame,page,MemProt::Read|MemProt::Exec);
        command='S';
        sent=::write(fixture.input,&command,1)==1;
        std::istringstream crashReady(fixture.line());
        crashReady>>magic>>std::hex>>spinning>>counter;
        seeded=false;
        for (unsigned attempt=0;attempt<1000 && !seeded;++attempt) {
            seeded=readMemory(fixture.pid,counter,&heartbeat,4)==4 && heartbeat;
            if (!seeded) usleep(1000);
        }
        bool owned=executable && sent && crashReady && seeded &&
            ptrace(PTRACE_SEIZE,fixture.pid,nullptr,reinterpret_cast<void*>(PTRACE_O_TRACEEXEC))==0 &&
            ptrace(PTRACE_INTERRUPT,fixture.pid,nullptr,nullptr)==0 && waitpid(fixture.pid,&status,__WALL)==fixture.pid && WIFSTOPPED(status);
        auto crashed=owned ? executeStoppedFunction(fixture.pid,host,fault,{},*crashFrame,*crashFrame+18*page) :
            std::expected<uint64_t,TargetSyscallFailure>(std::unexpected(std::make_error_code(std::errc::no_such_process)));
        check(!crashed && crashed.error().code==std::errc::interrupted && crashed.error().pendingSignal==SIGSEGV &&
              crashed.error().recovery && !crashed.error().completedValue && !crashed.error().recovery->functionResult(),
              "a genuine callee segmentation fault retains its real signal stop and never reports a successful function result");
        if (!crashed && crashed.error().recovery) {
            auto ticket=crashed.error().recovery;
            kill(fixture.pid,SIGKILL);
            auto retired=ticket->retry();
            for (unsigned attempt=0;attempt<100 && !retired;++attempt) {
                usleep(1000); retired=ticket->retry();
            }
            check(retired && ticket->retry() && !ticket->functionResult(),
                  "a dead faulting callee retires recovery without replaying registers or fabricating a result");
        }
    }
    const char* marker=loopCommand=='S' ? "STOPPED_FUNCTION_RESULT" :
        loopCommand=='E' ? "SVE_FUNCTION_RESULT" : loopCommand=='F' ? "MAXIMUM_SVE_FUNCTION_RESULT" :
        loopCommand=='M' ? "SME_FUNCTION_RESULT" : "MAXIMUM_SME_FUNCTION_RESULT";
    printf("%s=%s architecture=%s\n",marker,failures==initial ? "PASSED" : "FAILED",cpuArchitectureName(host.architecture));
}

static void nativeCallOwnerBackend(const char* path) {
    int initial=failures;
    Fixture fixture(path);
    check(fixture.line().starts_with("CE_TARGET "),"shared native call owner starts a real target");
    char command='j';
    bool sent=::write(fixture.input,&command,1)==1;
    std::istringstream addresses(fixture.line()); std::string magic;
    uintptr_t sum=0,wait=0,fault=0,waiting=0,entered=0,create=0,detach=0,detachedFlag=0,signal=0;
    addresses>>magic>>std::hex>>sum>>wait>>fault>>waiting>>entered>>create>>detach>>detachedFlag>>signal;
    check(sent && addresses && magic=="CE_FUNCTION" && sum && wait && create && detach && detachedFlag,
          "shared owner fixture publishes callable ABI and resource-lease functions");
    if (!addresses || !sum || !wait || !create || !detach || !detachedFlag) return;
    LinuxProcessHandle process(fixture.pid);
    auto host=process.targetDescription().host;
    auto identity=targetProcessIdentity(fixture.pid);
    if (!identity) { check(false,"shared owner records the live target identity"); return; }
    command='u';
    sent=::write(fixture.input,&command,1)==1;
    std::istringstream ready(fixture.line()); uintptr_t spinning=0,counter=0;
    ready>>magic>>std::hex>>spinning>>counter;
    uint32_t count=0;
    bool seeded=false;
    for (unsigned attempt=0;attempt<1000 && !seeded;++attempt) {
        seeded=counter && readMemory(fixture.pid,counter,&count,4)==4 && count;
        if (!seeded) usleep(1000);
    }
    check(sent && ready && magic=="CE_SHARED" && spinning && seeded,
          "two real threads keep running while the call owner selects only one thread");
    if (!seeded) return;
    auto maps=[&] { std::ifstream file("/proc/"+std::to_string(fixture.pid)+"/maps"); return std::string(std::istreambuf_iterator<char>(file),{}); };
    auto originalMaps=maps();
    NativeCallRequest basic;
    basic.function=sum; basic.arguments={1,2,3,4,5,6,7,8};
    auto completed=memorySyscallService().invoke(*identity,host,basic);
    check(completed && completed->value==87654321 && originalMaps==maps() && !process.targetDescription().pendingRecovery,
          "shared owner completes a native call and restores the exact mapping/protection list before releasing ownership");
    NativeCallRequest naturalSignal;
    naturalSignal.function=signal; naturalSignal.forwardSignals=true;
    auto signaled=memorySyscallService().invoke(*identity,host,naturalSignal);
    check(signaled && signaled->value==92 && originalMaps==maps() && !process.targetDescription().pendingRecovery,
          "a callee's real thread-directed signal follows the requested delivery policy and still returns its actual result");
    uint32_t one=1,zero=0;
    writeMemory(fixture.pid,waiting,&one,4); writeMemory(fixture.pid,entered,&zero,4);
    NativeCallRequest pending;
    pending.function=wait; pending.timeoutMs=10;
    auto unfinished=memorySyscallService().invoke(*identity,host,pending);
    auto pendingMaps=maps();
    check(!unfinished && unfinished.error()==std::errc::timed_out && process.targetDescription().pendingRecovery && pendingMaps!=originalMaps,
          "a timed-out call retains its private frame and shared owner across frontend failure");
    uint32_t before=0,after=0;
    bool running=readMemory(fixture.pid,counter,&before,4)==4;
    after=before;
    for (unsigned attempt=0;attempt<1000 && running && before==after;++attempt) {
        running=readMemory(fixture.pid,counter,&after,4)==4;
        if (after==before) usleep(1000);
    }
    running=running && before!=after;
    check(running,"a sibling makes real CPU progress while the selected native call retains ownership");
    bool declined=false;
    {
        LinuxProcessHandle caller(fixture.pid);
        auto allocation=caller.allocate(4096,MemProt::ReadWrite);
        declined=!allocation && caller.targetDescription().pendingRecovery;
    }
    LinuxProcessHandle replacement(fixture.pid);
    check(declined && replacement.targetDescription().pendingRecovery && maps()==pendingMaps,
          "memory operations and caller destruction cannot seize a second owner or discard a live call frame");
    pid_t ownedTid=0;
    for (const auto& thread : process.threads()) if (fixtureTracer(thread.tid)>0) { ownedTid=thread.tid; break; }
    bool signaledOwner=ownedTid>0 && syscall(SYS_tgkill,fixture.pid,ownedTid,SIGTRAP)==0;
    auto undecided=replacement.retryPendingOperations();
    check(signaledOwner && !undecided && undecided.error()==std::errc::interrupted && replacement.targetDescription().pendingRecovery,
          "shared owner retains a genuine external SIGTRAP until an explicit signal decision");
    bool released=writeMemory(fixture.pid,waiting,&zero,4)==4;
    auto resumed=replacement.resumePendingCallSignal(false);
    for (unsigned attempt=0;attempt<100 && !resumed && resumed.error()==std::errc::timed_out;++attempt) resumed=replacement.retryPendingOperations();
    check(released && resumed && !replacement.targetDescription().pendingRecovery && originalMaps==maps(),
          "a new frontend resumes the original call on its existing owner and releases every private mapping");
    NativeCallRequest lease;
    lease.function=create; lease.outputSize=host.pointerWidth; lease.dataArguments=1; lease.orphanDetach=detach;
    auto resource=memorySyscallService().invoke(*identity,host,lease);
    check(resource && resource->value==0 && resource->threadLease && originalMaps==maps() && !process.targetDescription().pendingRecovery,
          "a successful resource-producing call keeps a client lease without retaining a private frame or blocking other calls");
    resource=std::unexpected(std::make_error_code(std::errc::interrupted));
    uint32_t cleaned=0;
    bool retired=false;
    for (unsigned attempt=0;attempt<1000 && !retired;++attempt) {
        process.retryPendingOperations();
        retired=readMemory(fixture.pid,detachedFlag,&cleaned,4)==4 && cleaned==1 && !process.targetDescription().pendingRecovery && originalMaps==maps();
        if (!retired) usleep(1000);
    }
    check(retired,"destroying the resource result schedules one native detach and cleans its replacement frame without frontend ownership");
    auto claimed=memorySyscallService().invoke(*identity,host,lease);
    bool joined=claimed && claimed->threadLease;
    if (joined) claimed->threadLease->release();
    claimed=std::unexpected(std::make_error_code(std::errc::interrupted));
    auto drained=process.retryPendingOperations();
    check(joined && drained && readMemory(fixture.pid,detachedFlag,&cleaned,4)==4 && cleaned==1 && originalMaps==maps(),
          "a resource lease explicitly released after target cleanup never performs a duplicate detach");
    check(writeMemory(fixture.pid,spinning,&zero,4)==4 && fixture.line()=="CE_SHARED_DONE" && fixture.value(),
          "shared call recovery leaves both original threads and console work live");
    printf("NATIVE_CALL_OWNER_RESULT=%s architecture=%s\n",failures==initial ? "PASSED" : "FAILED",cpuArchitectureName(host.architecture));
}

static void stoppedSyscallBackend(const char* path) {
    int failuresBefore=failures;
    Fixture fixture(path);
    std::istringstream line(fixture.line()); std::string magic;
    pid_t pid=0; unsigned width=0; uintptr_t value=0,pointer=0,code=0;
    line>>magic>>pid>>width>>std::hex>>value>>pointer>>code;
    check(line && magic=="CE_TARGET" && pid==fixture.pid,"stopped native syscall fixture starts");
    if (!line || magic!="CE_TARGET" || pid!=fixture.pid) return;
    LinuxProcessHandle process(pid);
    size_t page=static_cast<size_t>(sysconf(_SC_PAGESIZE));
    auto scratch=process.allocate(page,MemProt::All);
    check(scratch.has_value(),"stopped syscall fixture owns a private executable scratch page");
    if (!scratch) return;
    bool seized=ptrace(PTRACE_SEIZE,pid,nullptr,nullptr)==0 && ptrace(PTRACE_INTERRUPT,pid,nullptr,nullptr)==0;
    int status=0;
    bool stopped=seized && waitpid(pid,&status,__WALL)==pid && WIFSTOPPED(status);
    auto before=stopped ? readNativeContext(pid) : Result<CpuContext>(std::unexpected(std::make_error_code(std::errc::no_such_process)));
    std::array<uint8_t,32> original{},after{};
    bool saved=readMemory(pid,code,original.data(),original.size())==ssize_t(original.size());
    if (before) {
#if defined(__x86_64__)
        using NativeRegisters=user_regs_struct;
#else
        using NativeRegisters=user_pt_regs;
#endif
        auto registers=[&]() -> Result<NativeRegisters> {
            NativeRegisters image{};
#if defined(__x86_64__)
            if (ptrace(PTRACE_GETREGS,pid,nullptr,&image)<0)
#else
            iovec io{&image,sizeof(image)};
            if (ptrace(PTRACE_GETREGSET,pid,reinterpret_cast<void*>(NT_PRSTATUS),&io)<0 || io.iov_len!=sizeof(image))
#endif
                return std::unexpected(std::error_code(errno,std::system_category()));
            return image;
        };
        std::vector<syscall_test::Fault> faults{syscall_test::Fault::InitialInstructionWrite,syscall_test::Fault::InitialRegistersWrite};
#if defined(__aarch64__)
        faults.push_back(syscall_test::Fault::InitialSyscallWrite);
#endif
        auto host=process.targetDescription().host;
        for (auto fault : faults) {
            auto savedRegisters=registers();
            std::array<uint8_t,16> savedInstruction{},restoredInstruction{};
            uintptr_t site=before->instructionPointer();
            bool codeSaved=readMemory(pid,site,savedInstruction.data(),savedInstruction.size())==ssize_t(savedInstruction.size());
#if defined(__aarch64__)
            int savedSyscall=-1; iovec io{&savedSyscall,sizeof(savedSyscall)};
            bool syscallSaved=ptrace(PTRACE_GETREGSET,pid,reinterpret_cast<void*>(NT_ARM_SYSTEM_CALL),&io)==0;
#endif
            syscall_test::arm(fault);
            auto failed=executeQuiescedMemorySyscall(pid,host,MemorySyscall::Protect,{value-value%page,page,3,0,0,0});
            bool injected=syscall_test::triggered()>0 && syscall_test::singleSteps()==0;
            syscall_test::clear();
            auto restoredRegisters=registers();
            bool syscallRestored=true;
#if defined(__aarch64__)
            int actualSyscall=-2; io={&actualSyscall,sizeof(actualSyscall)};
            syscallRestored=syscallSaved && ptrace(PTRACE_GETREGSET,pid,reinterpret_cast<void*>(NT_ARM_SYSTEM_CALL),&io)==0 && actualSyscall==savedSyscall;
#endif
            check(!failed && !failed.error().completedValue && !failed.error().recovery && injected &&
                savedRegisters && restoredRegisters && std::memcmp(&*savedRegisters,&*restoredRegisters,sizeof(NativeRegisters))==0 &&
                syscallRestored && codeSaved && readMemory(pid,site,restoredInstruction.data(),restoredInstruction.size())==ssize_t(restoredInstruction.size()) &&
                savedInstruction==restoredInstruction && fixtureTracer(pid)==getpid(),
                "an initialization error reported after real target mutation restores every native register, syscall slot and instruction before returning ownership");
        }
    }
    auto changed=stopped ? executeStoppedMemorySyscall(pid,process.targetDescription().host,MemorySyscall::Protect,
        {value-value%page,page,1,0,0,0},*scratch) : std::expected<uint64_t,TargetSyscallFailure>(std::unexpected(std::make_error_code(std::errc::no_such_process)));
    uint32_t sentinel=77;
    check(stopped && changed && writeMemory(pid,value,&sentinel,4)<0,
          "stopped syscall uses the native register ABI and really changes target protection");
    auto context=readNativeContext(pid);
    check(saved && before && context && context->instructionPointer()==before->instructionPointer() &&
          context->stackPointer()==before->stackPointer() &&
          readMemory(pid,code,after.data(),after.size())==ssize_t(after.size()) && original==after &&
          process.targetDescription().tracerPid>0,
          "private-gadget syscall restores native registers, shared code and the existing ptrace relationship");
    syscall_test::arm(syscall_test::Fault::RestoreRegisters);
    auto failed=executeStoppedMemorySyscall(pid,process.targetDescription().host,MemorySyscall::Protect,
        {value-value%page,page,3,0,0,0},*scratch);
    check(!failed && failed.error().recovery && failed.error().completedValue==0 && syscall_test::triggered()>0,
          "stopped syscall failure retains exact register recovery and the completed protection result");
    syscall_test::clear();
    bool recovered=!failed && failed.error().recovery && failed.error().recovery->retry().has_value();
    check(recovered && readNativeContext(pid) && process.targetDescription().tracerPid>0,
          "stopped syscall recovery restores on the existing owner without detaching it");
    auto unmapped=executeQuiescedMemorySyscall(pid,process.targetDescription().host,MemorySyscall::Unmap,
        {*scratch,page,0,0,0,0});
    check(unmapped && readMemory(pid,*scratch,after.data(),1)<0 &&
          readMemory(pid,code,after.data(),after.size())==ssize_t(after.size()) && original==after,
          "quiesced syscall releases its scratch page and restores exact shared program instructions");
    bool detached=ptrace(PTRACE_DETACH,pid,nullptr,nullptr)==0;
    check(detached && fixture.value(),
          "stopped syscall scratch cleanup and detach preserve the original blocked-read restart state");
    printf("STOPPED_SYSCALL_RESULT=%s architecture=%s\n",failures==failuresBefore ? "PASSED" : "FAILED",
           cpuArchitectureName(process.targetDescription().host.architecture));
}

static void softwareFinderBackend(const char* path) {
    int failuresBefore=failures;
    Fixture fixture(path);
    std::istringstream header(fixture.line()); std::string magic;
    pid_t pid=0; unsigned width=0; uintptr_t value=0,pointer=0,code=0;
    header>>magic>>pid>>width>>std::hex>>value>>pointer>>code;
    check(header && magic=="CE_TARGET" && pid==fixture.pid,"native software CodeFinder fixture starts");
    if (!header || magic!="CE_TARGET" || pid!=fixture.pid) return;
    LinuxProcessHandle process(pid); LinuxDebugger debugger;
    auto originalRegions=process.queryRegions();
    auto sameRegions=[&] {
        auto current=process.queryRegions();
        return current.size()==originalRegions.size() && std::equal(current.begin(),current.end(),originalRegions.begin(),
            [](const auto& a,const auto& b) { return a.base==b.base && a.size==b.size && a.protection==b.protection; });
    };
    CodeFinder finder;
    bool started=finder.start(process,debugger,value,true,4,true);
    check(started,"software CodeFinder arms its real native page guard before startup succeeds");
    if (!started) return;
    for (unsigned i=0;i<3;++i) {
        char command='b';
        check(::write(fixture.input,&command,1)==1 && fixture.line()==std::to_string(123456790+i),
              "software watchpoint executes a native store and rearms its page guard without losing liveness");
    }
    auto hits=finder.results();
    check(std::any_of(hits.begin(),hits.end(),[&](const auto& hit) {
        return hit.instructionAddress>=code && hit.instructionAddress<code+32 && hit.hitCount==3 &&
            hit.firstContext.instructionPointer()==hit.instructionAddress && !hit.instructionBytes.empty();
    }),"software CodeFinder records the native faulting store and its register context");
    char command='t';
    check(::write(fixture.input,&command,1)==1 && fixture.line()=="123456793",
          "software CodeFinder follows a newly cloned writer without exposing an untraced page fault");
    finder.stop(); command='b';
    check(!finder.hasPendingRecovery() && sameRegions() && ::write(fixture.input,&command,1)==1 && fixture.line()=="123456794",
          "software CodeFinder restores exact page permissions and releases its syscall scratch mapping before detach");

    started=finder.start(process,debugger,value,true,4,true);
    syscall_test::arm(syscall_test::Fault::RestoreRegisters);
    std::atomic<bool> finished=false;
    std::thread cleanup([&] { finder.stop(); finished=true; });
    bool fault=awaitState([&] { return syscall_test::triggered()>0 && finder.hasPendingRecovery(); });
    check(started && fault && !finished && finder.hasPendingRecovery() && process.targetDescription().tracerPid>0,
          "software cleanup retains native register recovery and the real stopped-thread owner");
    syscall_test::clear(); cleanup.join(); command='b';
    check(sameRegions() && ::write(fixture.input,&command,1)==1 && fixture.line()=="123456795",
          "software cleanup retries native restoration and leaves no permission or mapping residue");

    started=finder.start(process,debugger,value,true,4,true);
    command='x'; bool sent=::write(fixture.input,&command,1)==1;
    std::istringstream replacement(fixture.line()); replacement>>magic>>pid;
    bool retired=awaitState([&] { return !finder.running(); }); finder.stop();
    check(started && sent && retired && replacement && magic=="CE_TARGET" && pid==fixture.pid,
          "software CodeFinder retires old page/scratch ownership on exec without changing the replacement image");
    command='b';
    check(::write(fixture.input,&command,1)==1 && fixture.line()=="123456790",
          "replacement program executes after software watchpoint exec cleanup");
    printf("SOFTWARE_CODEFINDER_RESULT=%s architecture=%s\n",failures==failuresBefore ? "PASSED" : "FAILED",
           cpuArchitectureName(process.targetDescription().host.architecture));
}

static void codeFinderSignalBackend(const char* path) {
    int failuresBefore=failures;
    CpuArchitecture architecture=CpuArchitecture::Unknown;
    for (bool software : {false,true}) {
        Fixture fixture(path); std::istringstream header(fixture.line()); std::string magic;
        pid_t pid=0; unsigned width=0; uintptr_t value=0,pointer=0,code=0;
        header>>magic>>pid>>width>>std::hex>>value>>pointer>>code;
        LinuxProcessHandle process(fixture.pid); LinuxDebugger debugger; CodeFinder finder;
        architecture=process.targetDescription().host.architecture;
        bool started=header && magic=="CE_TARGET" && finder.start(process,debugger,value,true,4,software);
        check(started,software ? "software job-control fixture arms" : "hardware job-control fixture arms");
        if (!started) continue;
        auto stopped=[&] {
            std::ifstream input("/proc/"+std::to_string(fixture.pid)+"/status");
            std::string line;
            while (std::getline(input,line)) if (line.starts_with("State:"))
                return line.find("stopped")!=std::string::npos || line.find("tracing stop")!=std::string::npos;
            return false;
        };
        bool stoppedSignal=kill(fixture.pid,SIGSTOP)==0 && awaitState(stopped);
        char command='b'; bool sent=::write(fixture.input,&command,1)==1;
        usleep(50000); uint32_t observed=0;
        check(stoppedSignal && sent && readMemory(fixture.pid,value,&observed,4)==4 && observed==123456789,
              "CodeFinder preserves a real group stop while a requested write stays pending");
        bool continued=kill(fixture.pid,SIGCONT)==0;
        check(continued && fixture.line()=="123456790" && finder.running() && !finder.results().empty(),
              "SIGCONT resumes the target and native monitoring still records its pending store");
        stoppedSignal=kill(fixture.pid,SIGSTOP)==0 && awaitState(stopped);
        finder.stop(); sent=::write(fixture.input,&command,1)==1;
        usleep(50000);
        check(stoppedSignal && sent && readMemory(fixture.pid,value,&observed,4)==4 && observed==123456790,
              "detaching CodeFinder preserves the target's preexisting job-control stop");
        continued=kill(fixture.pid,SIGCONT)==0;
        check(continued && fixture.line()=="123456791",
              "the detached target runs normally after its owner sends SIGCONT");
    }
    {
        Fixture fixture(path); std::istringstream header(fixture.line()); std::string magic;
        pid_t pid=0; unsigned width=0; uintptr_t value=0,pointer=0,code=0;
        header>>magic>>pid>>width>>std::hex>>value>>pointer>>code;
        LinuxProcessHandle process(fixture.pid); LinuxDebugger debugger; CodeFinder finder;
        bool started=header && finder.start(process,debugger,value,true,4,true);
        syscall_test::arm(syscall_test::Fault::IgnoredStepSignal);
        char command='b'; bool sent=::write(fixture.input,&command,1)==1;
        bool signalled=awaitState([] { return syscall_test::triggered()>0; });
        syscall_test::clear(); finder.stop();
        check(started && sent && signalled && fixture.line()=="123456790",
              "a real ignored signal during software gadget execution survives cleanup and the original store completes");
        command='b';
        check(::write(fixture.input,&command,1)==1 && fixture.line()=="123456791",
              "signal-interrupted software watchpoint cleanup leaves no page guard or scratch residue");
    }
    printf("CODEFINDER_SIGNAL_RESULT=%s architecture=%s\n",failures==failuresBefore ? "PASSED" : "FAILED",
           cpuArchitectureName(architecture));
}

static void traceBackend(const char* path) {
    int failuresBefore=failures;
    Fixture fixture(path);
    std::istringstream line(fixture.line()); std::string magic;
    pid_t pid=0; unsigned width=0; uintptr_t value=0,pointer=0,code=0,call=0,afterCall=0,ret=0;
    line>>magic>>pid>>width>>std::hex>>value>>pointer>>code>>call>>afterCall>>ret;
    check(line && magic=="CE_TARGET" && pid==fixture.pid,"native instruction-trace fixture starts");
    if (!line || magic!="CE_TARGET" || pid!=fixture.pid) return;
    LinuxProcessHandle process(pid);
    LinuxDebugger debugger;
    Tracer tracer;
    std::vector<TraceEntry> records;
    TraceConfig config;
    config.startAddress=code; config.maxSteps=4;
    std::thread worker([&] { records=tracer.trace(process,debugger,config); });
    bool armed=awaitState([&] { return tracer.ready(); });
    check(armed,"instruction tracing reports readiness only after native execution breakpoints are armed");
    auto concurrent=armed ? tracer.trace(process,debugger,config) : std::vector<TraceEntry>{};
    check(armed && concurrent.empty() && tracer.ready() && tracer.lastError()==std::errc::device_or_resource_busy,
          "overlapping trace requests cannot reset cancellation or seize a second owner");
    char command='b';
    bool sent=::write(fixture.input,&command,1)==1;
    if (!armed) tracer.cancel();
    worker.join();
    check(sent && armed && records.size()==4 && records.front().address==code &&
          records.front().context.architecture==process.targetDescription().host.architecture &&
          std::all_of(records.begin(),records.end(),[](const auto& record) {
              return record.context.instructionPointer()==record.address && record.instruction!="??";
          }),"real instruction tracing publishes native PCs, register banks and decoded instructions");
    check(fixture.line()=="123456790","instruction tracing restores native hardware state and leaves the writer alive");

    records.clear();
    config.startAddress=call; config.stepOverCalls=true; config.maxSteps=8; config.stopAddress=afterCall;
    worker=std::thread([&] { records=tracer.trace(process,debugger,config); });
    armed=awaitState([&] { return tracer.ready(); });
    command='c'; sent=::write(fixture.input,&command,1)==1;
    if (!armed) tracer.cancel();
    worker.join();
    check(sent && armed && records.size()==2 && records.front().address==call && records.back().address==afterCall,
          "instruction trace steps over native calls and stops at the requested return instruction");
    check(fixture.line()=="123456791","native call trace restores its temporary execution breakpoint without stack corruption");

    config.startAddress=code; config.stepOverCalls=false; config.stopAddress=0;
    worker=std::thread([&] { records=tracer.trace(process,debugger,config); });
    armed=awaitState([&] { return tracer.ready(); });
    tracer.cancel(); worker.join();
    check(armed && !tracer.ready() && tracer.progress()==1,"waiting instruction trace cancels and drains its ptrace owner");
    command='b';
    check(::write(fixture.input,&command,1)==1 && fixture.line()=="123456792",
          "target continues after cancelling an armed instruction trace");

    worker=std::thread([&] { records=tracer.trace(process,debugger,config); });
    armed=awaitState([&] { return tracer.ready(); });
    syscall_test::arm(syscall_test::Fault::HardwareCleanupFailure);
    tracer.cancel();
    bool fault=awaitState([&] { return syscall_test::triggered()>1 && bool(tracer.lastError()); });
    bool retained=process.targetDescription().tracerPid>0;
    check(armed && fault && retained && tracer.lastError(),"failed trace hardware cleanup retains the real ptrace stop and its original bank");
    syscall_test::clear(); worker.join();
    command='b';
    check(::write(fixture.input,&command,1)==1 && fixture.line()=="123456793",
          "trace cleanup retries on its owner and leaves no residual execution breakpoint");

    config.maxSteps=4;
    worker=std::thread([&] { records=tracer.trace(process,debugger,config); });
    armed=awaitState([&] { return tracer.ready(); });
    command='t'; sent=::write(fixture.input,&command,1)==1;
    if (!armed) tracer.cancel();
    worker.join();
    check(sent && armed && records.size()==4 && records.front().address==code,
          "instruction tracing adopts and arms a newly cloned writer before its first instruction");
    check(fixture.line()=="123456794","new writer exits and target stays live after cloned-thread trace cleanup");

    worker=std::thread([&] { records=tracer.trace(process,debugger,config); });
    armed=awaitState([&] { return tracer.ready(); });
    command='x'; sent=::write(fixture.input,&command,1)==1;
    if (!armed) tracer.cancel();
    worker.join();
    std::istringstream replacement(fixture.line());
    replacement>>magic>>pid;
    check(sent && armed && records.empty() && replacement && magic=="CE_TARGET" && pid==fixture.pid,
          "exec ends an armed trace and discards old-image hardware restoration records");
    command='b';
    check(::write(fixture.input,&command,1)==1 && fixture.line()=="123456790",
          "replacement image runs after trace exec without an old-image breakpoint");

    {
        Fixture exiting(path);
        std::istringstream header(exiting.line());
        header>>magic>>pid>>width>>std::hex>>value>>pointer>>code;
        LinuxProcessHandle killedProcess(exiting.pid);
        Tracer killedTracer;
        config.startAddress=code;
        worker=std::thread([&] { killedTracer.trace(killedProcess,debugger,config); });
        armed=awaitState([&] { return killedTracer.ready(); });
        syscall_test::arm(syscall_test::Fault::HardwareCleanupFailure);
        killedTracer.cancel();
        fault=awaitState([] { return syscall_test::triggered()>1; });
        bool killed=kill(exiting.pid,SIGKILL)==0;
        worker.join(); syscall_test::clear();
        check(header && armed && fault && killed && killedTracer.progress()==1 && !killedTracer.ready(),
              "exit during failed trace cleanup retires ownership without hanging on a dead register bank");
    }
    {
        Fixture signalled(path);
        std::istringstream header(signalled.line());
        header>>magic>>pid>>width>>std::hex>>value>>pointer>>code;
        LinuxProcessHandle signalledProcess(signalled.pid);
        Tracer signalTracer;
        config.startAddress=code;
        std::atomic<bool> finished=false;
        worker=std::thread([&] { signalTracer.trace(signalledProcess,debugger,config); finished=true; });
        armed=awaitState([&] { return signalTracer.ready(); });
        bool delivered=kill(signalled.pid,SIGTRAP)==0;
        bool exited=awaitState([&] { return finished.load(); });
        if (!exited) signalTracer.cancel();
        worker.join();
        check(header && armed && delivered && exited && !signalledProcess.targetDescription().live,
              "an armed trace forwards genuine user SIGTRAP rather than swallowing it as its own breakpoint");
    }
    printf("TRACE_BACKEND_RESULT=%s architecture=%s\n",failures==failuresBefore ? "PASSED" : "FAILED",
           cpuArchitectureName(process.targetDescription().host.architecture));
}
static void sharedCodeSyscalls(const char* path) {
    int failuresBefore=failures;
    Fixture fixture(path);
    std::istringstream header(fixture.line()); std::string magic;
    pid_t pid=0; unsigned width=0; uintptr_t value=0,pointer=0,code=0;
    header>>magic>>pid>>width>>std::hex>>value>>pointer>>code;
    LinuxProcessHandle process(pid);
    check(header && magic=="CE_TARGET" && pid==fixture.pid,"shared-code syscall fixture starts");
    if (!header || magic!="CE_TARGET" || pid!=fixture.pid) return;
    char command='u';
    bool sent=::write(fixture.input,&command,1)==1;
    std::istringstream ready(fixture.line()); uintptr_t flag=0,counter=0;
    ready>>magic>>std::hex>>flag>>counter;
    check(sent && ready && magic=="CE_SHARED" && flag && counter && process.threads().size()==2,
          "two real native threads execute the same busy function while sharing program code");
    if (!ready || magic!="CE_SHARED" || !flag || !counter) return;
    std::vector<std::pair<uintptr_t,std::vector<uint8_t>>> snapshots;
    for (const auto& region : process.queryRegions()) {
        if (!(region.protection&MemProt::Exec) || (region.protection&MemProt::Write)) continue;
        std::vector<uint8_t> bytes(region.size);
        auto read=process.read(region.base,bytes.data(),bytes.size());
        if (read && *read==bytes.size()) snapshots.emplace_back(region.base,std::move(bytes));
    }
    uint32_t before=0,after=0;
    bool saved=readMemory(pid,counter,&before,sizeof(before))==sizeof(before);
    size_t page=static_cast<size_t>(sysconf(_SC_PAGESIZE));
    syscall_test::arm(syscall_test::Fault::ForbidTextWrite);
    bool operations=true;
    for (unsigned i=0;i<12;++i) {
        auto mapped=executeMemorySyscall(pid,process.targetDescription().host,MemorySyscall::Map,
            {0,page,3,0x22,UINT64_MAX,0});
        if (!mapped) { operations=false; break; }
        auto protectedPage=executeMemorySyscall(pid,process.targetDescription().host,MemorySyscall::Protect,
            {*mapped,page,1,0,0,0});
        auto unmapped=executeMemorySyscall(pid,process.targetDescription().host,MemorySyscall::Unmap,
            {*mapped,page,0,0,0,0});
        operations=protectedPage && unmapped && operations;
    }
    unsigned writes=syscall_test::triggered(); syscall_test::clear();
    check(operations && !writes,
          "transient mmap/mprotect/munmap use existing native syscall instructions without any program-code write");
    check(saved && readMemory(pid,counter,&after,sizeof(after))==sizeof(after) && before!=after && process.threads().size()==2,
          "the unseized sibling keeps making progress through shared code during transient memory operations");
    bool unchanged=!snapshots.empty();
    for (const auto& [address,bytes] : snapshots) {
        std::vector<uint8_t> observed(bytes.size()); auto read=process.read(address,observed.data(),observed.size());
        unchanged=read && *read==bytes.size() && observed==bytes && unchanged;
    }
    check(unchanged,"all readable non-writable executable mappings stay byte-for-byte unchanged");
    uint32_t zero=0;
    check(writeMemory(pid,flag,&zero,sizeof(zero))==sizeof(zero) && fixture.line()=="CE_SHARED_DONE" && fixture.value(),
          "both busy threads finish normally and the original blocked-read restart state survives");
    printf("SHARED_SYSCALL_RESULT=%s architecture=%s\n",failures==failuresBefore ? "PASSED" : "FAILED",
           cpuArchitectureName(process.targetDescription().host.architecture));
}
static void deniedSyscall(const char* path) {
    int failuresBefore=failures;
    Fixture fixture(path);
    std::istringstream header(fixture.line()); std::string magic;
    pid_t pid=0; unsigned width=0; uintptr_t value=0,pointer=0,code=0;
    header>>magic>>pid>>width>>std::hex>>value>>pointer>>code;
    LinuxProcessHandle process(pid);
    check(header && magic=="CE_TARGET" && pid==fixture.pid,"syscall-policy fixture starts");
    if (!header || magic!="CE_TARGET" || pid!=fixture.pid) return;
    char command='f';
    bool installed=::write(fixture.input,&command,1)==1 && fixture.line()=="CE_FILTER_READY";
    check(installed,"the actual target installs a kernel seccomp filter trapping its native mmap syscall");
    if (!installed) return;
    auto denied=executeMemorySyscall(pid,process.targetDescription().host,MemorySyscall::Map,
        {0,static_cast<uint64_t>(sysconf(_SC_PAGESIZE)),3,0x22,UINT64_MAX,0});
    check(!denied && denied.error().code==std::errc::operation_not_permitted &&
          !denied.error().completedValue && !denied.error().recovery && !denied.error().pendingSignal,
          "a kernel-denied synthetic syscall reports permission failure without inventing a completed allocation");
    bool resumed=fixture.value();
    check(process.targetDescription().live && !process.targetDescription().pendingRecovery && resumed,
          "the denied operation preserves the filter and original target context without injecting a synthetic SIGSYS");
    auto invalid=executeMemorySyscall(pid,process.targetDescription().host,MemorySyscall::Protect,
        {1,static_cast<uint64_t>(sysconf(_SC_PAGESIZE)),1,0,0,0});
    check(!invalid && invalid.error().value()==EINVAL && fixture.value(),
          "other native syscalls still reach the kernel under the unchanged target policy");
    auto pinned=pinNativeMemoryImage(process);
    auto baseline=process.queryRegion(value);
    auto guarded=pinned && *pinned ? (*pinned)->protect(value,4,MemProt::ReadWrite) :
        Result<void>(std::unexpected(std::make_error_code(std::errc::io_error)));
    auto after=process.queryRegion(value);
    check(!guarded && guarded.error()==std::errc::operation_not_permitted && baseline && after &&
          baseline->protection==after->protection && !process.targetDescription().pendingRecovery && fixture.value(),
          "saved-image protection refuses a denied affinity allocation without changing caller mappings or injecting SIGSYS");
    auto allocation=pinned && *pinned ? (*pinned)->allocate(static_cast<size_t>(sysconf(_SC_PAGESIZE)),MemProt::ReadWrite,0) :
        Result<uintptr_t>(std::unexpected(std::make_error_code(std::errc::io_error)));
    check(!allocation && allocation.error()==std::errc::operation_not_permitted &&
          !process.targetDescription().pendingRecovery && fixture.value(),
          "saved-image allocation preserves seccomp policy without inventing an unreturned probe mapping");
    printf("SYSCALL_POLICY_RESULT=%s architecture=%s\n",failures==failuresBefore ? "PASSED" : "FAILED",
           cpuArchitectureName(process.targetDescription().host.architecture));
}
// Older kernels implement dispatch but cannot expose its configuration to a
// tracer. Exercise their allow/deny behavior rather than pretending the newer
// introspection API exists. This profile must be selected explicitly by the VM.
static void legacyDispatchSyscalls(const char* path) {
#if defined(__x86_64__)
    int initial=failures;
    for (char command : {'a','n'}) {
        Fixture fixture(path);
        LinuxProcessHandle process(fixture.pid);
        check(fixture.line().starts_with("CE_TARGET "),"legacy dispatch fixture starts a real target");
        bool sent=::write(fixture.input,&command,1)==1;
        std::istringstream ready(fixture.line()); std::string magic;
        uintptr_t flag=0,counter=0,selector=0,offset=0,length=0;
        ready>>magic>>std::hex>>flag>>counter>>selector>>offset>>length;
        check(sent && ready && magic=="CE_DISPATCH" && flag && counter && selector && !offset && !length,
              "legacy dispatch fixture publishes its selector and empty native range");
        if (!ready || !flag || !counter || !selector) continue;
        int status=0;
        bool seized=ptrace(PTRACE_SEIZE,fixture.pid,nullptr,nullptr)==0;
        bool stopped=seized && ptrace(PTRACE_INTERRUPT,fixture.pid,nullptr,nullptr)==0 &&
            waitpid(fixture.pid,&status,__WALL)==fixture.pid && WIFSTOPPED(status);
        std::array<uint64_t,4> config{};
        errno=0;
        long queried=stopped ? ptrace(static_cast<enum __ptrace_request>(0x4211),fixture.pid,
            reinterpret_cast<void*>(sizeof(config)),config.data()) : 0;
        int queryError=errno;
        bool detached=seized && ptrace(PTRACE_DETACH,fixture.pid,nullptr,nullptr)==0;
        check(stopped && detached && queried<0 && (queryError==EIO || queryError==EINVAL || queryError==ENOSYS),
              "the legacy guest really lacks dispatch configuration introspection");
        uint32_t before=0,after=0;
        bool running=false;
        for (unsigned attempt=0;attempt<1000 && !running;++attempt) {
            running=readMemory(fixture.pid,counter,&before,4)==4 && before;
            if (!running) usleep(1000);
        }
        check(running,"the legacy kernel enables dispatch and reaches the actual target CPU loop");
        if (!running) continue;
        uint8_t selectorBefore=0,selectorAfter=0;
        bool saved=readMemory(fixture.pid,selector,&selectorBefore,1)==1;
        size_t page=static_cast<size_t>(sysconf(_SC_PAGESIZE));
        syscall_test::arm(syscall_test::Fault::ForbidTextWrite);
        auto mapped=executeMemorySyscall(fixture.pid,process.targetDescription().host,MemorySyscall::Map,
            {0,page,3,0x22,UINT64_MAX,0});
        bool operations=false;
        if (command=='n') {
            operations=!mapped && mapped.error().code==std::errc::operation_not_permitted &&
                !mapped.error().completedValue && !mapped.error().recovery && !mapped.error().pendingSignal;
        } else if (mapped) {
            uint32_t value=0x4567abcd,observed=0;
            bool bytes=writeMemory(fixture.pid,*mapped,&value,4)==4 &&
                readMemory(fixture.pid,*mapped,&observed,4)==4 && observed==value;
            auto protectedPage=executeMemorySyscall(fixture.pid,process.targetDescription().host,
                MemorySyscall::Protect,{*mapped,page,1,0,0,0});
            bool readonly=protectedPage && writeMemory(fixture.pid,*mapped,&value,4)<0;
            auto freed=executeMemorySyscall(fixture.pid,process.targetDescription().host,
                MemorySyscall::Unmap,{*mapped,page,0,0,0,0});
            operations=bytes && readonly && freed && !process.queryRegion(*mapped);
        }
        unsigned writes=syscall_test::triggered(); syscall_test::clear();
        check(operations && !writes,command=='n' ?
              "legacy dispatch denial restores context without inventing an allocation or delivering synthetic SIGSYS" :
              "legacy allowing dispatch completes real mmap/mprotect/munmap without patching code");
        check(saved && readMemory(fixture.pid,selector,&selectorAfter,1)==1 && selectorBefore==selectorAfter,
              "legacy dispatch operations preserve the original selector byte");
        bool progressed=false;
        for (unsigned attempt=0;attempt<1000 && !progressed;++attempt) {
            progressed=readMemory(fixture.pid,counter,&after,4)==4 && before!=after;
            if (!progressed) usleep(1000);
        }
        check(progressed && process.targetDescription().live,
              "the original legacy dispatch CPU loop continues after memory operations");
        uint32_t zero=0;
        check(writeMemory(fixture.pid,flag,&zero,4)==4 && fixture.line()=="CE_DISPATCH_DONE" && fixture.value(),
              "the legacy target disables its own dispatch mode and resumes console work");
    }
    printf("SYSCALL_DISPATCH_LEGACY_RESULT=%s\n",failures==initial ? "PASSED" : "FAILED");
#else
    (void)path;
#endif
}
static void dispatchSyscalls(const char* path) {
#if defined(__x86_64__)
    const char* profile=getpid()==1 ? getenv("ce_vm_dispatch") : nullptr;
    if (profile && std::strcmp(profile,"legacy")==0) { legacyDispatchSyscalls(path); return; }
    int failuresBefore=failures;
    for (char command : {'d','D','a','n'}) {
        Fixture fixture(path);
        std::istringstream header(fixture.line()); std::string magic;
        pid_t pid=0; unsigned width=0; uintptr_t value=0,pointer=0,code=0;
        header>>magic>>pid>>width>>std::hex>>value>>pointer>>code;
        LinuxProcessHandle process(pid);
        check(header && magic=="CE_TARGET" && pid==fixture.pid,"real native syscall-user-dispatch fixture starts");
        if (!header || magic!="CE_TARGET" || pid!=fixture.pid) continue;
        bool sent=::write(fixture.input,&command,1)==1;
        std::istringstream ready(fixture.line()); uintptr_t flag=0,counter=0,selector=0,offset=0,length=0;
        ready>>magic>>std::hex>>flag>>counter>>selector>>offset>>length;
        check(sent && ready && magic=="CE_DISPATCH" && flag && counter && selector,
              "the fixture publishes its real dispatch selector, exact syscall range and CPU-loop counters");
        if (!ready || magic!="CE_DISPATCH" || !flag || !counter || !selector) continue;
        struct Dispatch { uint64_t mode=0,selector=0,offset=0,length=0;
            bool operator==(const Dispatch&) const = default;
        };
        auto peek=[&](Dispatch& config) {
            int status=0;
            bool seized=ptrace(PTRACE_SEIZE,pid,nullptr,nullptr)==0;
            bool stopped=seized && ptrace(PTRACE_INTERRUPT,pid,nullptr,nullptr)==0 &&
                waitpid(pid,&status,__WALL)==pid && WIFSTOPPED(status);
            bool read=stopped && ptrace(static_cast<enum __ptrace_request>(0x4211),pid,
                reinterpret_cast<void*>(sizeof(config)),&config)==0;
            bool detached=seized && ptrace(PTRACE_DETACH,pid,nullptr,nullptr)==0;
            return read && detached;
        };
        Dispatch original;
        bool enabled=false;
        for (unsigned attempt=0;attempt<100 && !enabled;++attempt) {
            enabled=peek(original) && original.mode==1;
            if (!enabled) usleep(1000);
        }
        check(enabled && original.selector==selector && original.offset==offset && original.length==length,
              "the actual kernel enables syscall-user-dispatch with the fixture's exact configuration");
        if (!enabled) continue;
        uint8_t selectorBefore=0,selectorAfter=0;
        uint32_t before=0,after=0;
        bool running=false;
        for (unsigned attempt=0;attempt<1000 && !running;++attempt) {
            running=readMemory(pid,counter,&before,sizeof(before))==sizeof(before) && before!=0;
            if (!running) usleep(1000);
        }
        check(running,"the configured syscall-user-dispatch target reaches its real CPU loop before memory operations");
        bool saved=running && readMemory(pid,selector,&selectorBefore,sizeof(selectorBefore))==sizeof(selectorBefore) &&
            readMemory(pid,counter,&before,sizeof(before))==sizeof(before);
        size_t page=static_cast<size_t>(sysconf(_SC_PAGESIZE));
        syscall_test::arm(syscall_test::Fault::ForbidTextWrite);
        auto mapped=executeMemorySyscall(pid,process.targetDescription().host,MemorySyscall::Map,
            {0,page,3,0x22,UINT64_MAX,0});
        bool operations=false;
        if (command=='n') {
            operations=!mapped && mapped.error().code==std::errc::not_supported &&
                !mapped.error().completedValue && !mapped.error().recovery;
        } else if (mapped) {
            uint32_t sentinel=0x4567abcd,observed=0;
            bool bytes=writeMemory(pid,*mapped,&sentinel,sizeof(sentinel))==sizeof(sentinel) &&
                readMemory(pid,*mapped,&observed,sizeof(observed))==sizeof(observed) && observed==sentinel;
            auto protectedPage=executeMemorySyscall(pid,process.targetDescription().host,MemorySyscall::Protect,
                {*mapped,page,1,0,0,0});
            bool readonly=protectedPage && writeMemory(pid,*mapped,&sentinel,sizeof(sentinel))<0;
            auto freed=executeMemorySyscall(pid,process.targetDescription().host,MemorySyscall::Unmap,
                {*mapped,page,0,0,0,0});
            operations=bytes && readonly && freed && !process.queryRegion(*mapped);
        }
        unsigned codeWrites=syscall_test::triggered(); syscall_test::clear();
        check(operations && !codeWrites,command=='n' ?
              "a blocked selector without a native dispatcher rejects the operation before any target mutation" :
              "real memory syscalls use the exact always-native range or an allowing selector without patching code");
        Dispatch restored;
        check(saved && peek(restored) && original==restored &&
              readMemory(pid,selector,&selectorAfter,sizeof(selectorAfter))==sizeof(selectorAfter) && selectorBefore==selectorAfter,
              "the dispatch selector and complete kernel configuration remain unchanged");
        bool progressed=false;
        for (unsigned attempt=0;attempt<1000 && !progressed;++attempt) {
            progressed=readMemory(pid,counter,&after,sizeof(after))==sizeof(after) && before!=after;
            if (!progressed) usleep(1000);
        }
        check(progressed && process.targetDescription().live,
              "the CPU loop continues under its original syscall-user-dispatch configuration");
        uint32_t zero=0;
        check(writeMemory(pid,flag,&zero,sizeof(zero))==sizeof(zero) && fixture.line()=="CE_DISPATCH_DONE" && fixture.value(),
              "the target disables its own dispatch mode and resumes ordinary console work after context restoration");
    }
    printf("SYSCALL_DISPATCH_RESULT=%s\n",failures==failuresBefore ? "PASSED" : "FAILED");
#else
    (void)path; // Linux syscall-user-dispatch has an x86 execution backend.
#endif
}
static void extendedSyscallContextCase(const char* path,bool streaming,bool maximum) {
#if defined(__aarch64__)
    int failuresBefore=failures;
    Fixture fixture(path);
    std::istringstream header(fixture.line()); std::string magic;
    pid_t pid=0; unsigned width=0; uintptr_t value=0,pointer=0,code=0;
    header>>magic>>pid>>width>>std::hex>>value>>pointer>>code;
    LinuxProcessHandle process(pid);
    check(header && magic=="CE_TARGET" && pid==fixture.pid,"real ARM64 extension syscall-preservation fixture starts");
    if (!header || magic!="CE_TARGET" || pid!=fixture.pid) return;
    char contextCommand=maximum ? 'O' : 'A';
    check(::write(fixture.input,&contextCommand,1)==1 && fixture.line()=="CE_CONTEXT_READY",
          "the vector target configures an actual alternate stack and blocked signal mask");
    char command=streaming ? (maximum ? 'N' : 'M') : (maximum ? 'F' : 'E');
    bool sent=::write(fixture.input,&command,1)==1;
    std::istringstream ready(fixture.line()); uintptr_t flag=0,counter=0;
    ready>>magic>>std::hex>>flag>>counter;
    const char* marker=streaming ? "CE_SME" : "CE_SVE";
    check(sent && ready && magic==marker && flag && counter,"the target enters a native scalable-vector CPU loop");
    if (!ready || magic!=marker || !flag || !counter) return;
    uint32_t before=0,after=0;
    bool seeded=false;
    for (unsigned attempt=0;attempt<100 && !seeded;++attempt) {
        seeded=readMemory(pid,counter,&before,sizeof(before))==sizeof(before) && before;
        if (!seeded) usleep(1000);
    }
    uintptr_t stackPointer=0;
    std::array<uint8_t,16384> stackBefore{},stackAfter{};
    bool stackCaptured=false;
    auto snapshot=[&]() -> Result<NativeExtendedContext> {
        int status=0;
        bool seized=ptrace(PTRACE_SEIZE,pid,nullptr,nullptr)==0;
        bool stopped=seized && ptrace(PTRACE_INTERRUPT,pid,nullptr,nullptr)==0 &&
            waitpid(pid,&status,__WALL)==pid && WIFSTOPPED(status);
        auto image=stopped ? captureNativeExtendedContext(pid) :
            Result<NativeExtendedContext>(std::unexpected(std::make_error_code(std::errc::no_such_process)));
        if (stopped && !stackPointer) {
            user_pt_regs registers{}; iovec io{&registers,sizeof(registers)};
            if (ptrace(PTRACE_GETREGSET,pid,reinterpret_cast<void*>(NT_PRSTATUS),&io)==0 && io.iov_len==sizeof(registers)) {
                stackPointer=registers.sp;
                stackCaptured=readMemory(pid,stackPointer-stackBefore.size(),stackBefore.data(),stackBefore.size())==ssize_t(stackBefore.size());
            }
        }
        bool detached=seized && ptrace(PTRACE_DETACH,pid,nullptr,nullptr)==0;
        if (!detached) return std::unexpected(std::make_error_code(std::errc::io_error));
        return image;
    };
    auto original=snapshot();
    bool liveSve=false,liveZa=!streaming;
    if (original) for (const auto& image : original->regsets) {
        if (image.note==(streaming ? 0x40bu : 0x405u) && image.bytes.size()>16) {
            uint16_t flags=0,vl=0;
            std::memcpy(&flags,image.bytes.data()+12,sizeof(flags));
            std::memcpy(&vl,image.bytes.data()+8,sizeof(vl));
            liveSve=(flags&1)!=0 && (!maximum || vl==256);
        }
        if (streaming && image.note==0x40c && image.bytes.size()>16)
            liveZa=std::any_of(image.bytes.begin()+16,image.bytes.end(),[](uint8_t byte) {return byte!=0;});
    }
    check(seeded && original && liveSve && liveZa,streaming ?
          "kernel register images contain real streaming SVE state and a live nonzero ZA matrix" :
          "kernel register images contain real live SVE vectors, predicates and FFR");
    if (!original || !liveSve || !liveZa) return;
    // Exercise complete restoration, including a genuinely destroyed matrix
    // and vector length. A memory syscall preserves ZA by itself, so its happy
    // path alone cannot validate the matrix restoration branch.
    unsigned mutationNote=streaming ? 0x40cu : 0x405u;
    std::array<uint8_t,16> mutationHeader{};
    for (const auto& image : original->regsets) if (image.note==mutationNote)
        std::copy_n(image.bytes.begin(),mutationHeader.size(),mutationHeader.begin());
    uint16_t minimumVl=16;
    std::memcpy(mutationHeader.data()+8,&minimumVl,sizeof(minimumVl));
    int status=0;
    bool stopped=ptrace(PTRACE_SEIZE,pid,nullptr,nullptr)==0 && ptrace(PTRACE_INTERRUPT,pid,nullptr,nullptr)==0 &&
        waitpid(pid,&status,__WALL)==pid && WIFSTOPPED(status);
    iovec mutation{mutationHeader.data(),mutationHeader.size()};
    bool mutated=stopped && ptrace(PTRACE_SETREGSET,pid,reinterpret_cast<void*>(uintptr_t(mutationNote)),&mutation)==0;
    auto damaged=mutated ? captureNativeExtendedContext(pid) :
        Result<NativeExtendedContext>(std::unexpected(std::make_error_code(std::errc::io_error)));
    bool different=false;
    if (damaged) for (const auto& bank : damaged->regsets) if (bank.note==mutationNote)
        for (const auto& saved : original->regsets) if (saved.note==mutationNote)
            different=bank.bytes!=saved.bytes;
    check(mutated && different,"the real kernel changes vector length and discards a captured live register bank");
    bool repaired=stopped && restoreNativeExtendedContext(pid,*original).has_value();
    check(repaired,"opaque extension recovery restores destroyed data, vector lengths and the original streaming mode");
    bool detached=repaired && ptrace(PTRACE_DETACH,pid,nullptr,nullptr)==0;
    check(detached,"a directly restored vector target resumes only after complete verification");
    if (!detached) return;
    size_t page=static_cast<size_t>(sysconf(_SC_PAGESIZE));
    auto allocation=process.allocate(page,MemProt::ReadWrite);
    bool operations=allocation && process.protect(*allocation,page,MemProt::Read) && process.free(*allocation,page);
    check(operations,"real application memory operations complete while scalable-vector state is live");
    for (auto fault : {syscall_test::Fault::RestoreExtended,syscall_test::Fault::FrameWriteFailure,
                       syscall_test::Fault::FrameRestoreFailure}) {
        syscall_test::arm(fault);
        auto failed=process.allocate(page,MemProt::ReadWrite);
        uintptr_t orphan=static_cast<uintptr_t>(syscall_test::completedResult());
        check(!failed && syscall_test::triggered()>0 && process.targetDescription().pendingRecovery,
              "failed extension restoration retains the actual mmap result and the original owner stop");
        uint32_t stoppedBefore=0,stoppedAfter=1;
        bool observedStop=readMemory(pid,counter,&stoppedBefore,sizeof(stoppedBefore))==sizeof(stoppedBefore);
        usleep(1000);
        check(observedStop && readMemory(pid,counter,&stoppedAfter,sizeof(stoppedAfter))==sizeof(stoppedAfter) &&
              stoppedBefore==stoppedAfter,"a target with damaged vector state remains stopped until verified recovery");
        syscall_test::clear();
        uint32_t discarded=0;
        check(process.retryPendingOperations() && !process.targetDescription().pendingRecovery && orphan &&
              readMemory(pid,orphan,&discarded,sizeof(discarded))<0,
              "retry restores extensions on the original owner and unmaps the completed but unreturned allocation");
    }
    auto restored=snapshot();
    bool exact=original && restored && original->regsets.size()==restored->regsets.size();
    if (exact) for (size_t i=0;i<original->regsets.size();++i)
        exact=original->regsets[i].note==restored->regsets[i].note &&
            original->regsets[i].bytes==restored->regsets[i].bytes && exact;
    check(exact,"memory syscalls and failed-restoration recovery preserve every captured extension byte and the original CPU mode");
    check(stackCaptured && readMemory(pid,stackPointer-stackAfter.size(),stackAfter.data(),stackAfter.size())==ssize_t(stackAfter.size()) &&
          stackBefore==stackAfter,"the borrowed stack bytes, including nonzero sentinel data, are restored exactly");
    uint32_t zero=0;
    check(readMemory(pid,counter,&after,sizeof(after))==sizeof(after) && before!=after &&
          writeMemory(pid,flag,&zero,sizeof(zero))==sizeof(zero) &&
          fixture.line()==(streaming ? "CE_SME_DONE" : "CE_SVE_DONE") && fixture.value(),
          "the vector target remains live, makes progress and resumes normal console work");
    contextCommand='K';
    check(::write(fixture.input,&contextCommand,1)==1 && fixture.line()=="CE_CONTEXT_UNCHANGED",
          "the original alternate-stack configuration and blocked signal mask survive the actual vector returns");
    printf("%s%s=%s architecture=ARM64\n",maximum ? "MAXIMUM_" : "",
           streaming ? "SME_SYSCALL_RESULT" : "SVE_SYSCALL_RESULT",
           failures==failuresBefore ? "PASSED" : "FAILED");
#else
    (void)path;
    (void)streaming;
    (void)maximum;
#endif
}
static void extendedSyscallContext(const char* path,bool includeSme=true) {
    for (bool maximum : {false,true}) {
        extendedSyscallContextCase(path,false,maximum);
        if (includeSme) extendedSyscallContextCase(path,true,maximum);
    }
}
static void deferredSyscallContext(const char* path,bool streaming,unsigned mode,bool includeSme=true) {
#if defined(__aarch64__)
    int failuresBefore=failures;
    Fixture fixture(path);
    check(fixture.line().starts_with("CE_TARGET "),"a real ARM64 target starts for deferred-vector exec verification");
    if (!includeSme) {
        const char command='I';
        check(::write(fixture.input,&command,1)==1 && fixture.line()=="CE_SVE_ONLY_READY",
              "the SVE-only fixture verifies absent SME controls before scheduling its supported vector length");
    }
    LinuxProcessHandle process(fixture.pid);
    size_t page=static_cast<size_t>(sysconf(_SC_PAGESIZE));
    std::optional<uintptr_t> scratch;
    std::optional<uintptr_t> callFrame;
    uintptr_t function=0;
    if (mode==2) {
        auto memory=process.allocate(page,MemProt::All);
        check(memory.has_value(),"the private executor allocates its actual scratch page before scalable state is live");
        if (!memory) return;
        scratch=*memory;
    }
    if (mode==4) {
        char query='j';
        bool queried=::write(fixture.input,&query,1)==1;
        std::istringstream addresses(fixture.line()); std::string magic;
        addresses>>magic>>std::hex>>function;
        auto memory=process.allocate(18*page,MemProt::ReadWrite);
        bool prepared=queried && addresses && magic=="CE_FUNCTION" && function && memory &&
            process.protect(*memory,page,MemProt::Read|MemProt::Exec);
        check(prepared,"the deferred-call executor reserves its private executable code and stack before scalable state is live");
        if (!prepared) return;
        callFrame=*memory;
    }
    char command=streaming ? 'W' : 'V';
    bool sent=::write(fixture.input,&command,1)==1;
    std::istringstream ready(fixture.line());
    std::string marker;
    uintptr_t flag=0,counter=0;
    ready>>marker>>std::hex>>flag>>counter;
    check(sent && ready && marker==(streaming ? "CE_SME" : "CE_SVE") && flag && counter,
          includeSme ? "the target schedules distinct SVE and SME vector lengths for its next exec before entering the CPU loop" :
          "the target schedules its SVE vector length for next exec without requiring an unavailable SME interface");
    if (!ready || !flag || !counter) return;
    uint32_t count=0;
    bool seeded=false;
    for (unsigned attempt=0;attempt<100 && !seeded;++attempt) {
        seeded=readMemory(fixture.pid,counter,&count,sizeof(count))==sizeof(count) && count;
        if (!seeded) usleep(1000);
    }
    check(seeded,"deferred-vector verification waits until scalable state is really live");
    if (mode==1) {
        auto memory=process.allocate(page,MemProt::ReadWrite);
        check(memory && process.protect(*memory,page,MemProt::Read) && process.free(*memory,page),
              "the deferred-vector target completes the actual allocation/protection/free operations");
    } else if (mode>=2) {
        int status=0;
        bool stopped=ptrace(PTRACE_SEIZE,fixture.pid,nullptr,nullptr)==0 &&
            ptrace(PTRACE_INTERRUPT,fixture.pid,nullptr,nullptr)==0 &&
            waitpid(fixture.pid,&status,__WALL)==fixture.pid && WIFSTOPPED(status);
        check(stopped,"the direct executor owns the real stopped vector target");
        if (!stopped) return;
        auto syscall=[&](MemorySyscall operation,std::array<uint64_t,6> arguments) {
            return scratch ? executeStoppedMemorySyscall(fixture.pid,nativeTargetMachine(),operation,arguments,*scratch) :
                executeQuiescedMemorySyscall(fixture.pid,nativeTargetMachine(),operation,arguments);
        };
        bool worked=false;
        if (mode==4) {
            auto called=executeStoppedFunction(fixture.pid,nativeTargetMachine(),function,{1,2,3,4,5,6,7,8},*callFrame,*callFrame+18*page);
            auto freed=called ? executeOwnedMemorySyscall(fixture.pid,nativeTargetMachine(),MemorySyscall::Unmap,
                {*callFrame,18*page,0,0,0,0}) :
                std::expected<uint64_t,TargetSyscallFailure>(std::unexpected(std::make_error_code(std::errc::interrupted)));
            worked=called && *called==87654321 && freed;
            check(worked,"a real native callee changes FP state and its signal mask, then restores scalable state and frees its private frame");
        } else {
            auto memory=syscall(MemorySyscall::Map,{0,page,3,0x22,UINT64_MAX,0});
            worked=memory && syscall(MemorySyscall::Protect,{*memory,page,1,0,0,0}) &&
                syscall(MemorySyscall::Unmap,{*memory,page,0,0,0,0});
            check(worked,"the private/quiesced executor completes real memory operations with live scalable state");
        }
        check(worked && ptrace(PTRACE_DETACH,fixture.pid,nullptr,nullptr)==0,
              "the direct executor returns ownership after complete register and stack restoration");
        if (!worked) return;
    }
    uint32_t zero=0;
    check(writeMemory(fixture.pid,flag,&zero,sizeof(zero))==sizeof(zero) &&
          fixture.line()==(streaming ? "CE_SME_DONE" : "CE_SVE_DONE") && fixture.value(),
          "the deferred-vector target leaves its CPU loop and continues normally");
    if (scratch) check(process.free(*scratch,page).has_value(),"the private executor removes its original scratch mapping before exec");
    command='x';
    check(::write(fixture.input,&command,1)==1 && fixture.line().starts_with("CE_TARGET "),
          "the target actually execs its own ARM64 image on the same PID");
    command='L';
    sent=::write(fixture.input,&command,1)==1;
    std::istringstream lengths(fixture.line());
    int64_t sve=0,sme=0;
    lengths>>marker>>sve>>sme;
    check(sent && lengths && marker=="CE_LENGTHS" && sve==16 && sme==(includeSme ? 16 : -EINVAL),
          includeSme ? "both previously scheduled vector lengths take effect after the real exec transition" :
          "the scheduled SVE length survives real exec and the unavailable SME interface remains rejected");
    printf("%s_%s=%s architecture=ARM64\n",streaming ? "DEFERRED_SME" : "DEFERRED_SVE",
           mode==0 ? "CONTROL_RESULT" : mode==1 ? "SYSCALL_RESULT" : mode==2 ? "PRIVATE_RESULT" : mode==3 ? "QUIESCED_RESULT" : "FUNCTION_RESULT",
           failures==failuresBefore ? "PASSED" : "FAILED");
#else
    (void)path; (void)streaming; (void)mode; (void)includeSme;
#endif
}
static void guardedVectorSyscall(const char* path,bool streaming,bool alternate,bool includeSme=true) {
#if defined(__aarch64__)
    int failuresBefore=failures;
    Fixture fixture(path);
    check(fixture.line().starts_with("CE_TARGET "),"a real ARM64 target starts for vector-restoration preflight safety");
    if (!includeSme) {
        const char command='I';
        check(::write(fixture.input,&command,1)==1 && fixture.line()=="CE_SVE_ONLY_READY",
              "the guarded SVE-only fixture verifies the absent SME interface before entering scalable code");
    }
    char command='O';
    check(::write(fixture.input,&command,1)==1 && fixture.line()=="CE_CONTEXT_READY",
          "the guarded target configures a real alternate stack and blocked signal mask");
    if (!alternate) {
        command='P';
        check(::write(fixture.input,&command,1)==1 && fixture.line()=="CE_POLICY_READY",
              "a real seccomp filter denies signal return while allowing memory syscalls");
    }
    command=alternate ? (streaming ? 'Z' : 'Y') : (streaming ? 'W' : 'V');
    bool sent=::write(fixture.input,&command,1)==1;
    std::istringstream ready(fixture.line());
    std::string marker; uintptr_t flag=0,counter=0;
    ready>>marker>>std::hex>>flag>>counter;
    check(sent && ready && marker==(streaming ? "CE_SME" : "CE_SVE") && flag && counter,
          "the guarded target enters a live scalable-vector CPU loop");
    if (!ready || !flag || !counter) return;
    uint32_t before=0,after=0;
    bool seeded=false;
    for (unsigned attempt=0;attempt<100 && !seeded;++attempt) {
        seeded=readMemory(fixture.pid,counter,&before,sizeof(before))==sizeof(before) && before;
        if (!seeded) usleep(1000);
    }
    auto snapshot=[&]() -> Result<NativeExtendedContext> {
        int status=0;
        bool stopped=ptrace(PTRACE_SEIZE,fixture.pid,nullptr,nullptr)==0 &&
            ptrace(PTRACE_INTERRUPT,fixture.pid,nullptr,nullptr)==0 &&
            waitpid(fixture.pid,&status,__WALL)==fixture.pid && WIFSTOPPED(status);
        auto state=stopped ? captureNativeExtendedContext(fixture.pid) :
            Result<NativeExtendedContext>(std::unexpected(std::make_error_code(std::errc::io_error)));
        if (!stopped || ptrace(PTRACE_DETACH,fixture.pid,nullptr,nullptr)<0)
            return std::unexpected(std::make_error_code(std::errc::io_error));
        return state;
    };
    auto original=snapshot();
    LinuxProcessHandle process(fixture.pid);
    auto allocation=process.allocate(static_cast<size_t>(sysconf(_SC_PAGESIZE)),MemProt::ReadWrite);
    check(seeded && !allocation && allocation.error()==std::errc::not_supported && !process.targetDescription().pendingRecovery,
          "unsupported live-vector restoration is rejected before any target mutation or retained recovery");
    auto restored=snapshot();
    bool exact=original && restored && original->regsets.size()==restored->regsets.size();
    if (exact) for (size_t i=0;i<original->regsets.size();++i)
        exact=original->regsets[i].note==restored->regsets[i].note && original->regsets[i].bytes==restored->regsets[i].bytes && exact;
    check(exact,"preflight rejection preserves every captured vector, matrix, control and TLS byte");
    uint32_t zero=0;
    check(readMemory(fixture.pid,counter,&after,sizeof(after))==sizeof(after) && before!=after &&
          writeMemory(fixture.pid,flag,&zero,sizeof(zero))==sizeof(zero) &&
          fixture.line()==(streaming ? "CE_SME_DONE" : "CE_SVE_DONE") && fixture.value(),
          "the guarded target remains live and finishes its actual signal handler or CPU loop");
    command='K';
    check(::write(fixture.input,&command,1)==1 && fixture.line()=="CE_CONTEXT_UNCHANGED",
          "preflight rejection and real signal return preserve alternate-stack settings and the original signal mask");
    command='x';
    check(::write(fixture.input,&command,1)==1 && fixture.line().starts_with("CE_TARGET "),
          "the guarded target really execs its ARM64 image after rejected memory operations");
    command='L'; sent=::write(fixture.input,&command,1)==1;
    std::istringstream lengths(fixture.line()); int64_t sve=0,sme=0;
    lengths>>marker>>sve>>sme;
    check(sent && lengths && marker=="CE_LENGTHS" && sve==16 && sme==(includeSme ? 16 : -EINVAL),
          includeSme ? "guarded rejection retains both scheduled vector lengths through the real exec transition" :
          "guarded rejection retains the scheduled SVE length through exec without inventing SME support");
    printf("%s_%s_GUARD_RESULT=%s architecture=ARM64\n",streaming ? "SME" : "SVE",
           alternate ? "ALTSTACK" : "SECCOMP",failures==failuresBefore ? "PASSED" : "FAILED");
#else
    (void)path; (void)streaming; (void)alternate; (void)includeSme;
#endif
}
#ifdef CECORE_VM_NATIVE_CALL
int nativeCallIntegration(int argc,char** argv);
#endif
static void sessionThreadExitBackend(const char* path) {
    const int initial=failures;
    for (unsigned mode=0;mode<7;++mode) {
        // The parent owns and always kills the fixture. An alarm bounds an old
        // owner-thread deadlock without leaving an orphaned console sibling.
        Fixture fixture(path);
        std::istringstream header(fixture.line()); std::string magic;
        pid_t pid=0; unsigned width=0;
        uintptr_t value=0,pointer=0,writer=0,call=0,after=0,ret=0,exitSite=0,userTrap=0,execSite=0,syscallSite=0;
        header>>magic>>pid>>width>>std::hex>>value>>pointer>>writer>>call>>after>>ret>>exitSite>>userTrap>>execSite>>syscallSite;
        if (!header || magic!="CE_TARGET" || !exitSite) {
            check(false,"thread-exit stepping fixture publishes its actual exit instruction"); continue;
        }
        const pid_t owner=fork();
        if (!owner) {
            alarm(8);
            const int before=failures;
            LinuxProcessHandle process(fixture.pid);
            if (mode==6) {
                LinuxDebugger debugger; Tracer tracer; TraceConfig config;
                config.startAddress=syscallSite; config.maxSteps=2;
                std::vector<TraceEntry> records;
                std::thread trace([&] { records=tracer.trace(process,debugger,config); });
                const bool armed=awaitState([&] {return tracer.ready();});
                const char command='g'; const bool sent=armed && ::write(fixture.input,&command,1)==1;
                if (!sent) tracer.cancel();
                trace.join();
                check(sent && records.size()==2 && records.front().address==syscallSite &&
                      records.back().address==syscallSite+(width==8 && process.targetDescription().host.architecture==CpuArchitecture::Arm64 ? 4 : 2),
                      "instruction tracing recognizes an actual native syscall-return step trap");
                check(fixture.line()==std::to_string(fixture.pid) && fixtureTracer(fixture.pid)==0,
                      "syscall tracing preserves its real return value and original console liveness");
                _exit(failures==before ? 0 : 5);
            }
            DebugSession session;
            std::atomic<unsigned> hits{0},steps{0},exits{0},otherEvents{0},signals{0},execs{0};
            std::atomic<pid_t> tracerThreadTid{0};
            session.setEventCallback([&](const DebugEvent& event) {
                tracerThreadTid=static_cast<pid_t>(syscall(SYS_gettid));
                if (getenv("CE_SESSION_EXIT_DIAGNOSTIC"))
                    printf("EXIT_EVENT type=%d tid=%d exiting=%d signal=%d pc=%lx\n",static_cast<int>(event.type),
                           event.tid,event.exitingTid,event.signal,event.context.instructionPointer());
                if (event.type==DebugEventType::BreakpointHit) ++hits;
                else if (event.type==DebugEventType::SingleStep) ++steps;
                else if (event.type==DebugEventType::ProcessExited) ++exits;
                else if (event.type==DebugEventType::SignalReceived && event.signal==SIGTRAP) ++signals;
                else if (event.type==DebugEventType::ProcessExecuted) ++execs;
                else if (event.type==DebugEventType::ThreadExiting && event.exitingTid>0 && event.tid!=event.exitingTid &&
                         event.tid==session.activeThread() && event.context.instructionPointer()==session.getStopContext().instructionPointer())
                    ++otherEvents;
            });
            const bool attached=session.attach(fixture.pid,&process);
            const auto site=mode==4 ? userTrap : mode==5 ? execSite : exitSite;
            std::array<uint8_t,4> original{}; const unsigned instructionBytes=width==8 && process.targetDescription().host.architecture==CpuArchitecture::Arm64 ? 4 : 2;
            const auto readOriginal=process.read(site,original.data(),instructionBytes);
            const auto generation=session.imageGeneration();
            const int bp=attached ? session.setSoftwareBreakpoint(site) : -1;
            check(attached && bp>0,"lifecycle stepping attaches and traps the selected native instruction");
            if (!attached || bp<=0) _exit(3);
            const char command=mode==0 || mode==3 ? 'l' : mode==1 ? 't' : mode==4 ? 'B' : mode==5 ? 'H' : 'q';
            const bool sent=::write(fixture.input,&command,1)==1;
            session.continueExecution();
            const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
            while (!hits && std::chrono::steady_clock::now()<deadline) usleep(1000);
            const pid_t exiting=session.activeThread();
            check(sent && hits==1 && session.isStopped() && session.getStopContext().instructionPointer()==site &&
                  (mode==1 || mode==5 ? exiting!=fixture.pid : exiting==fixture.pid),
                  "the selected task reaches its real instruction with the thread group frozen");
            if (!hits) _exit(4);
            if (mode!=2 && mode!=4) {
                const auto ready=fixture.line();
                check(mode==1 ? ready=="123456790" : !ready.empty() && ready!="CE_LEADER_FAILED",
                      "the fixture publishes its original console work before the trapped exit");
            }
            if (mode==3) syscall_test::arm(syscall_test::Fault::PreflightDetach);
            session.step(StepMode::Into);
            if (mode==3) {
                if (getenv("CE_SESSION_EXIT_DIAGNOSTIC")) printf("EXIT_RECOVERY pending=%d stopped=%d tids=%zu fault=%u tracer=%d owner=%d events=%u\n",
                    session.hasPendingRecovery(),session.isStopped(),session.stoppedThreads().size(),syscall_test::triggered(),fixtureTracer(exiting),getpid(),otherEvents.load());
                check(session.hasPendingRecovery() && session.isStopped() && session.stoppedThreads().size()==2 &&
                      syscall_test::triggered()>0 && fixtureTracer(exiting)==tracerThreadTid && otherEvents==0,
                      "a failed EXIT-stop detach retains the actual owner and frozen siblings without publishing completion");
                const auto memoryTask=processMemoryTask(fixture.pid);
                const auto live=process.threads();
                check(memoryTask && *memoryTask!=exiting && live.size()==1 && live.front().tid==*memoryTask &&
                      process.targetDescription().host.architecture==session.getStopContext().architecture,
                      "process metadata and thread selection omit the irreversibly exiting leader before it becomes a zombie");
                syscall_test::clear();
                check(session.retryPendingOperations() && !session.hasPendingRecovery(),
                      "EXIT-stop recovery retries detach and rearms the original shared instruction before reporting the survivor");
            }
            if (mode==4) {
                const bool unpatched=steps==1 && session.removeSoftwareBreakpoint(bp);
                session.step(StepMode::Into);
                check(unpatched && signals==1 && steps==1 && session.isStopped(),
                      "stepping a genuine program INT1 or BRK preserves its signal instead of inventing syscall completion");
                session.continueExecution();
                const bool terminated=awaitState([&] {return exits.load()>0;});
                check(terminated && exits==1 && !session.isAttached(),
                      "the original program trap is delivered and its actual process exit remains observable");
            } else if (mode==5) {
                const auto tids=session.stoppedThreads(); std::array<uint8_t,4> fresh{};
                const auto read=process.read(site,fresh.data(),instructionBytes);
                check(execs==1 && otherEvents==0 && session.isAttached() && session.isStopped() &&
                      session.activeThread()==fixture.pid && tids==std::vector<pid_t>{fixture.pid} &&
                      session.imageGeneration()>generation && readOriginal && read && fresh==original,
                      "a nonleader exec drains sibling EXIT stops, adopts the renamed task and retires old-image traps");
                session.detach();
                check(fixture.line().starts_with("CE_TARGET ") && fixture.value(),
                      "the replacement program starts and completes console work after an all-stop nonleader exec step");
            } else if (mode==2) {
                check(!session.isAttached() && !session.isStopped() && exits==1 && session.stoppedThreads().empty(),
                      "stepping the final thread's exit publishes process exit and retires the stopped snapshot");
            } else {
                const auto tids=session.stoppedThreads();
                const pid_t active=session.activeThread();
                const auto context=session.getStopContext();
                const auto described=process.targetDescription();
                if (mode==3 && getenv("CE_SESSION_EXIT_DIAGNOSTIC")) printf("EXIT_SURVIVOR attached=%d stopped=%d tids=%zu active=%d exiting=%d arch=%d described=%d pc=%lx events=%u exits=%u steps=%u\n",
                    session.isAttached(),session.isStopped(),tids.size(),active,exiting,static_cast<int>(context.architecture),
                    static_cast<int>(described.host.architecture),context.instructionPointer(),otherEvents.load(),exits.load(),steps.load());
                check(session.isAttached() && session.isStopped() && tids.size()==1 && tids.front()==active && active!=exiting &&
                      context.architecture==described.host.architecture && context.instructionPointer()!=exitSite &&
                      otherEvents==1 && exits==0 && steps==0,
                      "an exiting step selects a real surviving register bank without inventing a single-step result");
                check(session.pid()==fixture.pid && session.selectThread(active) && session.setStopContext(context) &&
                      session.removeSoftwareBreakpoint(bp) && !session.hasPendingRecovery(),
                      "the surviving debugger remains editable and restores the complete shared exit trap");
                const char read='r';
                const bool queued=::write(fixture.input,&read,1)==1;
                session.step(StepMode::Into);
                if (steps!=1) printf("EXIT_STEP_DIAGNOSTIC steps=%u other=%u active=%d stopped=%d error=%s\n",
                    steps.load(),otherEvents.load(),session.activeThread(),session.isStopped(),session.lastError().message().c_str());
                check(queued && steps==1 && session.activeThread()==active && session.isStopped(),
                      "native stepping continues on the explicitly selected live sibling after task exit");
                session.detach();
                check(fixture.line()==(mode==1 ? "123456790" : "123456789") && fixtureTracer(active)==0,
                      "task-exit cleanup resumes the original console and releases the surviving kernel stop");
            }
            session.detach();
            _exit(failures==before ? 0 : 5);
        }
        int status=0; pid_t waited=-1;
        if (owner>0) do { waited=waitpid(owner,&status,0); } while (waited<0 && errno==EINTR);
        check(owner>0 && waited==owner && WIFEXITED(status) && WEXITSTATUS(status)==0,
              mode==0 ? "leader exit during an all-stop step completes without waiting for stopped siblings" :
              mode==1 ? "worker exit during an all-stop step retires its selected context" :
              mode==2 ? "last-thread exit during an all-stop step publishes its terminal event" :
              mode==3 ? "failed thread-exit detach is recoverable on the original debugger owner" :
              mode==4 ? "real program traps stay distinct from kernel syscall-step notifications" :
              mode==5 ? "a nonleader exec step completes despite sibling exit and kernel TID replacement" :
                        "native syscall instruction tracing restores its owner and preserves the program");
    }
    // Model an application which launches its own target and reaps it from
    // its parent thread while the debugger owner is waiting for commands.
    // waitpid without __WNOTHREAD can consume that owner's EXIT notification.
    for (unsigned reaperMode=0;reaperMode<9;++reaperMode) {
        const pid_t launcher=fork();
        if (!launcher) {
            alarm(8);
            const int before=failures;
            Fixture launched(path);
            std::istringstream header(launched.line()); std::string magic;
            pid_t pid=0; unsigned width=0;
            uintptr_t value=0,pointer=0,writer=0,call=0,after=0,ret=0,exitSite=0,userTrap=0,execSite=0,syscallSite=0;
            header>>magic>>pid>>width>>std::hex>>value>>pointer>>writer>>call>>after>>ret>>exitSite>>userTrap>>execSite>>syscallSite;
            check(header && magic=="CE_TARGET" && syscallSite,"a debugger's parent process launches its own real target");
            LinuxProcessHandle process(launched.pid);
            DebugSession session;
            const bool workerExit=reaperMode==2 || reaperMode==3;
            const bool pausedExit=reaperMode>=7;
            const bool kernelWork=reaperMode>=4 && reaperMode<=6;
            std::atomic<bool> ownerHeld{false},releaseOwner{false};
            std::atomic<unsigned> exits{0},threadExits{0},signals{0},execs{0};
            std::atomic<pid_t> departingTid{0},tracerTid{0};
            session.setEventCallback([&](const DebugEvent& event) {
                if (event.type==DebugEventType::ProcessExited) ++exits;
                if (event.type==DebugEventType::ProcessExecuted) ++execs;
                if ((event.type==DebugEventType::ExceptionBreakpointHit || event.type==DebugEventType::SignalReceived) && event.signal==SIGTRAP)
                    ++signals;
                if (event.type==DebugEventType::ThreadExiting && event.exitingTid==departingTid &&
                    event.tid==launched.pid && event.context.instructionPointer()==session.getStopContext().instructionPointer())
                    ++threadExits;
                if (event.type!=DebugEventType::BreakpointHit) return;
                departingTid=event.tid; tracerTid=static_cast<pid_t>(syscall(SYS_gettid));
                if (!pausedExit) session.continueExecution();
                ownerHeld=true;
                while (!releaseOwner) usleep(1000);
            });
            if (reaperMode==4) session.addExceptionBreakpoint(SIGTRAP);
            const bool attached=session.attach(launched.pid,&process);
            std::array<uint8_t,4> originalSyscall{};
            const unsigned syscallBytes=process.targetDescription().host.architecture==CpuArchitecture::Arm64 ? 4 : 2;
            const auto originalRead=process.read(syscallSite,originalSyscall.data(),syscallBytes);
            const auto generation=session.imageGeneration();
            const int bp=attached ? session.setSoftwareBreakpoint(workerExit ? writer : syscallSite) : -1;
            const char command=workerExit ? 't' : 'g';
            const bool sent=bp>0 && ::write(launched.input,&command,1)==1;
            if (sent) session.continueExecution();
            const bool held=sent && awaitState([&] {return ownerHeld.load();});
            check(held && session.isStopped()==pausedExit,
                  "the debugger callback establishes the requested running or paused state before the launcher competes for notifications");
            int status=0;
            bool triggered=held;
            std::string initialOutput;
            if (kernelWork) {
                initialOutput=launched.line();
                const char next=reaperMode==4 ? 'B' : reaperMode==5 ? 't' : 'x';
                triggered=triggered && initialOutput==std::to_string(launched.pid) && ::write(launched.input,&next,1)==1;
            } else if (!workerExit) triggered=triggered && kill(launched.pid,SIGKILL)==0;
            const pid_t departing=workerExit ? departingTid.load() : launched.pid;
            pid_t waited=-1;
            if (triggered && reaperMode!=7) do { waited=waitpid(departing,&status,__WALL); } while (waited<0 && errno==EINTR);
            const unsigned event=reaperMode==4 ? 0 : reaperMode==5 ? PTRACE_EVENT_CLONE : reaperMode==6 ? PTRACE_EVENT_EXEC : PTRACE_EVENT_EXIT;
            const bool expectedStop=triggered && (reaperMode==7 || (waited==departing && WIFSTOPPED(status) && (status>>8)==(SIGTRAP|(event<<8))));
            if (!expectedStop) std::printf("LAUNCHER_STOP_DIAGNOSTIC mode=%u triggered=%d tid=%d waited=%d status=%x expectedEvent=%u errno=%d initial=%s\n",
                reaperMode,triggered,departing,waited,status,event,errno,initialOutput.c_str());
            check(expectedStop,
                  reaperMode==7 ? "the paused target is killed while its EXIT wait notification remains available to the debugger" :
                                  "the launcher consumes the actual requested stop notification while the debugger retains ownership");
            if (reaperMode==3) syscall_test::arm(syscall_test::Fault::PreflightDetach);
            releaseOwner=true;
            if (reaperMode==1 || pausedExit) {
                const bool completed=awaitState([&] {return exits.load()>0;});
                check(completed && exits==1 && !session.isAttached() && !session.isStopped() &&
                      session.activeThread()==0 && session.stoppedThreads().empty(),
                      pausedExit ? "a paused debugger reports final exit automatically whether its launcher consumes the EXIT notification or leaves it queued" :
                                   "a running debugger reports final exit automatically after its launcher consumes the EXIT notification");
            } else if (workerExit) {
                if (reaperMode==3) {
                    const bool retained=awaitState([&] {return session.hasPendingRecovery() && session.isStopped();});
                    check(retained && session.stoppedThreads().size()==2 && syscall_test::triggered()>0 &&
                          fixtureTracer(departing)==tracerTid && fixtureTracer(launched.pid)==tracerTid && threadExits==0,
                          "failed automatic EXIT-stop detach retains the original owner and freezes the surviving thread for recovery");
                    syscall_test::clear();
                    const bool recovered=session.retryPendingOperations();
                    const bool departed=awaitState([&] {return !targetProcessIdentity(departing);});
                    check(recovered && departed && !session.hasPendingRecovery() && session.isStopped() &&
                          session.activeThread()==launched.pid && session.stoppedThreads()==std::vector<pid_t>{launched.pid} &&
                          threadExits==1,
                          "automatic EXIT-stop recovery publishes the actual surviving register bank only after owned cleanup completes");
                } else {
                    const bool retired=awaitState([&] {return !targetProcessIdentity(departing);});
                    check(retired && session.isAttached() && !session.isStopped() && !session.hasPendingRecovery() &&
                          fixtureTracer(launched.pid)==tracerTid && exits==0,
                          "a running debugger automatically releases a worker EXIT stop consumed by its launcher without stopping the survivor");
                }
                const bool restored=session.removeSoftwareBreakpoint(bp);
                if (reaperMode==3) session.continueExecution();
                const auto workerOutput=launched.line();
                const char read='r'; const bool queued=::write(launched.input,&read,1)==1;
                check(restored && queued && workerOutput=="123456790" && launched.line()=="123456790",
                      "automatic worker-exit retirement preserves shared code and the original console work");
            } else if (reaperMode==4) {
                const bool surfaced=awaitState([&] {return signals.load()>0;});
                const auto context=session.getStopContext();
                check(surfaced && signals==1 && session.isStopped() && session.activeThread()==launched.pid &&
                      context.instructionPointer()>=userTrap && context.instructionPointer()<userTrap+12,
                      "a consumed program-trap notification still publishes its actual signal and fresh stopped register bank");
                session.continueExecution();
                check(awaitState([&] {return exits.load()>0;}) && exits==1 && !session.isAttached(),
                      "continuing a consumed program-trap stop delivers the original fatal signal exactly once");
            } else if (reaperMode==5) {
                check(launched.line()=="123456790" && session.isAttached() && !session.isStopped() && !session.hasPendingRecovery(),
                      "a consumed CLONE notification still adopts and runs the real worker to completion");
                const bool restored=session.removeSoftwareBreakpoint(bp);
                std::array<uint8_t,4> fresh{}; const auto freshRead=process.read(syscallSite,fresh.data(),syscallBytes);
                check(restored && originalRead && freshRead && fresh==originalSyscall,
                      "a consumed CLONE stop restores every original shared syscall instruction byte");
                const char read='r'; const bool queued=::write(launched.input,&read,1)==1;
                check(queued && launched.line()=="123456790",
                      "the original parent console remains live after consumed CLONE and real worker exit");
            } else if (reaperMode==6) {
                const bool executed=awaitState([&] {return execs.load()>0;});
                std::array<uint8_t,4> fresh{}; const auto freshRead=process.read(syscallSite,fresh.data(),syscallBytes);
                check(executed && execs==1 && session.isStopped() && session.activeThread()==launched.pid &&
                      session.imageGeneration()>generation && originalRead && freshRead && fresh==originalSyscall,
                      "a consumed EXEC notification retires old-image traps and publishes the replacement kernel register bank");
                session.detach();
                check(launched.line().starts_with("CE_TARGET ") && launched.value(),
                      "the replacement program starts and completes original console work after a consumed EXEC stop");
            }
            session.detach();
            if (workerExit || reaperMode==5 || reaperMode==6) kill(launched.pid,SIGKILL);
            do { waited=waitpid(launched.pid,&status,0); } while (waited<0 && errno==EINTR);
            const bool reaped=waited==launched.pid && WIFSIGNALED(status) && WTERMSIG(status)==(reaperMode==4 ? SIGTRAP : SIGKILL);
            if (reaped) launched.pid=-1;
            check(reaped && !session.isAttached() && session.stoppedThreads().empty(),
                  "debugger cleanup releases an EXIT stop whose wait notification was consumed by its launcher");
            _exit(failures==before ? 0 : 5);
        }
        int launcherStatus=0; pid_t reapedLauncher=-1;
        if (launcher>0) do { reapedLauncher=waitpid(launcher,&launcherStatus,0); } while (reapedLauncher<0 && errno==EINTR);
        check(launcher>0 && reapedLauncher==launcher && WIFEXITED(launcherStatus) && WEXITSTATUS(launcherStatus)==0,
              reaperMode==0 ? "same-process child reaping cannot deadlock debugger destruction" :
              reaperMode==1 ? "same-process child reaping preserves automatic final-exit notification" :
              reaperMode==2 ? "same-process child reaping preserves automatic worker-exit retirement and target liveness" :
              reaperMode==3 ? "same-process child reaping preserves recoverable automatic EXIT-stop cleanup" :
              reaperMode==4 ? "same-process child reaping preserves genuine program-trap handling and delivery" :
              reaperMode==5 ? "same-process child reaping preserves real CLONE adoption and worker execution" :
              reaperMode==6 ? "same-process child reaping preserves actual EXEC adoption and replacement-image liveness" :
                             "paused target death is observable without requiring another debugger command");
    }
    for (unsigned execMode=0;execMode<3;++execMode) {
        const pid_t execLauncher=fork();
        if (!execLauncher) {
            alarm(10);
            const int before=failures;
            Fixture launched(path);
            std::istringstream header(launched.line()); std::string magic;
            pid_t pid=0; unsigned width=0;
            uintptr_t value=0,pointer=0,writer=0,call=0,after=0,ret=0,exitSite=0,userTrap=0,execSite=0,syscallSite=0;
            header>>magic>>pid>>width>>std::hex>>value>>pointer>>writer>>call>>after>>ret>>exitSite>>userTrap>>execSite>>syscallSite;
            check(header && magic=="CE_TARGET" && pid==launched.pid && syscallSite,
                  "a same-process launcher publishes its real nonleader-exec target");
            LinuxProcessHandle process(launched.pid);
            DebugSession session;
            const bool stepping=execMode==1, missingContext=execMode==2;
            std::atomic<unsigned> execs{0},exits{0},hits{0};
            std::atomic<bool> emptyExecContext{false};
            session.setEventCallback([&](const DebugEvent& event) {
                if (event.type==DebugEventType::ProcessExecuted) {
                    emptyExecContext=event.context.architecture==CpuArchitecture::Unknown && event.context.instructionPointer()==0;
                    ++execs;
                }
                if (event.type==DebugEventType::ProcessExited) ++exits;
                if (event.type==DebugEventType::BreakpointHit) ++hits;
            });
            const unsigned bytes=process.targetDescription().host.architecture==CpuArchitecture::Arm64 ? 4 : 2;
            std::array<uint8_t,4> original{};
            const auto originalRead=process.read(syscallSite,original.data(),bytes);
            const bool attached=session.attach(launched.pid,&process);
            const int bp=attached ? session.setSoftwareBreakpoint(syscallSite) : -1;
            const int execBp=stepping && attached ? session.setSoftwareBreakpoint(execSite) : -1;
            const auto generation=session.imageGeneration();
            syscall_test::holdAfterDetach(launched.pid);
            const char command='H';
            const bool sent=bp>0 && ::write(launched.input,&command,1)==1;
            if (sent) session.continueExecution();
            pid_t formerTid=0;
            if (sent) { std::istringstream tidLine(launched.line()); tidLine>>formerTid; }
            std::thread stepper;
            if (stepping) {
                const bool ready=execBp>0 && awaitState([&] {return hits.load()>0;}) &&
                    session.isStopped() && session.activeThread()==formerTid;
                check(ready,"the actual nonleader exec instruction is selected with its sibling frozen before an all-stop step");
                if (ready) stepper=std::thread([&] {session.step(StepMode::Into);});
            }
            const bool held=sent && awaitState([&] {return syscall_test::detachHeld();});
            check(held && formerTid>0 && formerTid!=launched.pid,
                  "nonleader exec replaces its real TID while the owner is held after the actual leader detach");
            int status=0; pid_t waited=-1;
            if (held) do { waited=waitpid(launched.pid,&status,__WALL); } while (waited<0 && errno==EINTR);
            check(waited==launched.pid && WIFSTOPPED(status) && (status>>8)==(SIGTRAP|(PTRACE_EVENT_EXEC<<8)),
                  "the parent consumes the actual nonleader EXEC report at its replacement process TID");
            if (missingContext) syscall_test::arm(syscall_test::Fault::PreflightRegistersAndDetach);
            syscall_test::releaseDetach();
            const bool adopted=awaitState([&] {return execs.load()>0;});
            if (stepper.joinable()) stepper.join();
            check(adopted && execs==1 && exits==0 && session.isAttached() && session.isStopped() &&
                  session.activeThread()==launched.pid && session.stoppedThreads()==std::vector<pid_t>{launched.pid} &&
                  session.imageGeneration()>generation && (missingContext || session.getStopContext().instructionPointer()!=0),
                  "the debugger recovers a consumed nonleader EXEC and adopts its actual replacement thread");
            if (missingContext) {
                check(adopted && emptyExecContext && session.getStopContext().architecture==CpuArchitecture::Unknown &&
                      session.getStopContext().instructionPointer()==0 && syscall_test::triggered()>0 && session.lastError().value()==EIO,
                      "an actual exec with a failed context read still notifies image retirement without retaining an old register bank");
                syscall_test::clear();
                check(session.selectThread(launched.pid) && session.getStopContext().instructionPointer()!=0 &&
                      session.getStopContext().architecture==process.targetDescription().host.architecture,
                      "the existing exec owner retries a transient context read and exposes the real replacement register bank");
            }
            syscall_test::arm(syscall_test::Fault::ForbidTextWrite);
            const bool removed=adopted && session.removeSoftwareBreakpoint(bp) && (!stepping || session.removeSoftwareBreakpoint(execBp));
            const bool untouched=syscall_test::triggered()==0;
            syscall_test::clear();
            std::array<uint8_t,4> fresh{}; const auto freshRead=process.read(syscallSite,fresh.data(),bytes);
            check(removed && untouched && originalRead && freshRead && fresh==original,
                  "recovered nonleader EXEC retires old-image traps without replaying them into the replacement program");
            session.detach();
            check(launched.line().starts_with("CE_TARGET ") && launched.value(),
                  "a recovered nonleader replacement image starts and completes its original console work");
            const char quit='q'; const bool quitSent=::write(launched.input,&quit,1)==1;
            do { waited=waitpid(launched.pid,&status,0); } while (waited<0 && errno==EINTR);
            check(quitSent && waited==launched.pid && WIFEXITED(status) && WEXITSTATUS(status)==0,
                  "the recovered replacement process exits normally without retaining a kernel owner");
            if (waited==launched.pid) launched.pid=-1;
            _exit(failures==before ? 0 : 5);
        }
        int execLauncherStatus=0; pid_t execLauncherWaited=-1;
        if (execLauncher>0) do { execLauncherWaited=waitpid(execLauncher,&execLauncherStatus,0); } while (execLauncherWaited<0 && errno==EINTR);
        check(execLauncher>0 && execLauncherWaited==execLauncher && WIFEXITED(execLauncherStatus) && WEXITSTATUS(execLauncherStatus)==0,
              "same-process child reaping preserves nonleader EXEC across kernel TID replacement");
    }
    printf("SESSION_THREAD_EXIT_RESULT=%s\n",failures==initial ? "PASSED" : "FAILED"); fflush(stdout);
}

static void exitedLeaderBackend(const char* path) {
    const int initial=failures;
    Fixture fixture(path);
    const auto hello=fixture.line();
    unsigned pid=0,width=0; unsigned long long valueAddress=0,pointerAddress=0,writerAddress=0;
    check(std::sscanf(hello.c_str(),"CE_TARGET %u %u %llx %llx %llx",&pid,&width,&valueAddress,&pointerAddress,&writerAddress)==5,
          "leader-exit fixture publishes its actual target format and memory");
    LinuxProcessHandle process(fixture.pid);
    const auto before=process.targetDescription();
    const char command='l';
    const bool sent=::write(fixture.input,&command,1)==1;
    const auto tidLine=fixture.line();
    pid_t tid=-1; try { tid=static_cast<pid_t>(std::stol(tidLine)); } catch (...) {}
    bool zombie=false;
    for (unsigned attempt=0;attempt<200 && !zombie;++attempt) {
        std::ifstream stat("/proc/"+std::to_string(fixture.pid)+"/stat"); std::string line;
        if (std::getline(stat,line)) {
            const auto close=line.rfind(')'); zombie=close!=std::string::npos && line.substr(close+1).starts_with(" Z ");
        }
        if (!zombie) usleep(1000);
    }
    check(sent && tid>0 && zombie && fixture.value(),
          "the actual kernel retires the leader while its console sibling remains alive");
    const auto description=process.targetDescription();
    LinuxProcessHandle reopened(fixture.pid);
    check(description.live && description.host==before.host && description.program.pointerWidth==width &&
          reopened.targetDescription().host==before.host,
          "existing and newly opened handles retain real metadata after leader exit");
    uint32_t value=0;
    auto read=process.read(static_cast<uintptr_t>(valueAddress),&value,sizeof(value));
    check(read && *read==sizeof(value) && value==123456789,
          "process reads use a live member after the group leader releases its memory");
    const uint32_t changed=123456790;
    auto written=process.write(static_cast<uintptr_t>(valueAddress),&changed,sizeof(changed));
    auto restored=process.write(static_cast<uintptr_t>(valueAddress),&value,sizeof(value));
    check(written && *written==sizeof(changed) && restored && fixture.value(),
          "process writes preserve original console work after leader exit");
    std::array<uintptr_t,8> addresses; addresses.fill(static_cast<uintptr_t>(valueAddress));
    std::array<uint32_t,8> values{}; std::array<uint8_t,8> ok{};
    process.readMany(addresses.data(),addresses.size(),sizeof(value),reinterpret_cast<uint8_t*>(values.data()),ok.data());
    check(std::all_of(ok.begin(),ok.end(),[](auto v){return v==1;}) &&
          std::all_of(values.begin(),values.end(),[](auto v){return v==123456789;}),
          "batched scanner reads follow the live address space after leader exit");
    const auto threads=process.threads();
    check(process.queryRegion(static_cast<uintptr_t>(valueAddress)).has_value() && !process.modules().empty() &&
          std::any_of(threads.begin(),threads.end(),[&](const auto& t){return t.tid==tid;}),
          "memory maps, module backing files and surviving threads remain available");
    auto snapshot=ce::inspectThread(process,tid,true);
    check(snapshot && !snapshot->stack.empty() && snapshot->stack.front().available && fixtureTracer(tid)==0,
          "selected-thread inspection reads the surviving thread and releases its real stop");
    auto allocation=process.allocate(4096,MemProt::Read|MemProt::Write);
    check(allocation.has_value(),"process-level memory allocation selects a live thread after leader exit");
    if (allocation) {
        auto protectedPage=process.protect(*allocation,4096,MemProt::Read);
        auto denied=process.write(*allocation,&changed,sizeof(changed));
        auto freed=process.free(*allocation,4096);
        check(protectedPage && !denied && freed && !process.read(*allocation,&value,sizeof(value)) && fixture.value(),
              "live-thread memory operations preserve protection, remove allocations and resume console work");
    } else check(false,"live-thread memory operations preserve protection, remove allocations and resume console work");
    syscall_test::arm(syscall_test::Fault::MetadataAfterStep);
    auto retained=process.allocate(4096,MemProt::Read|MemProt::Write);
    const auto unreturned=syscall_test::completedResult();
    check(!retained && process.targetDescription().pendingRecovery && fixtureTracer(tid)>0,
          "failed live-member restoration retains its unreturned mapping against the original process identity");
    syscall_test::clear();
    auto recovered=reopened.retryPendingOperations();
    check(recovered && !reopened.targetDescription().pendingRecovery && fixtureTracer(tid)==0 &&
          unreturned && !process.read(unreturned,&value,sizeof(value)) && fixture.value(),
          "another frontend recovers the live member and releases its unreturned mapping after leader exit");
    {
        DebugSession session;
        std::atomic<unsigned> hits=0,steps=0;
        std::atomic<pid_t> hitTid=0;
        session.setEventCallback([&](const DebugEvent& event) {
            hitTid=event.tid;
            if (event.type==DebugEventType::BreakpointHit) ++hits;
            if (event.type==DebugEventType::SingleStep) ++steps;
        });
        const bool attached=session.attach(fixture.pid,&process);
        check(attached && session.pid()==fixture.pid && session.activeThread()==tid && session.isStopped() &&
              session.getStopContext().architecture==before.host.architecture,
              "full debugger retains the original process PID and selects an actual surviving stopped thread");
        const int breakpoint=attached ? session.setSoftwareBreakpoint(writerAddress) : -1;
        bool sentWriter=false,hit=false,stepped=false,removed=false;
        if (breakpoint>0) {
            session.continueExecution(); const char writer='b'; sentWriter=::write(fixture.input,&writer,1)==1;
            hit=sentWriter && awaitState([&]{return hits==1 && session.isStopped();});
            if (hit) {
                session.step(StepMode::Into);
                stepped=awaitState([&]{return steps==1 && session.isStopped();});
                removed=session.removeSoftwareBreakpoint(breakpoint);
            }
        }
        check(hit && hitTid==tid && session.activeThread()==tid,
              "leaderless debugger reports the real surviving writer's software breakpoint");
        check(stepped && removed,"leaderless debugger single-steps native code and restores its complete trap bytes");
        session.detach();
        const auto response=sentWriter ? fixture.line() : std::string{};
        const uint32_t originalValue=123456789;
        auto reset=process.write(valueAddress,&originalValue,sizeof(originalValue));
        check(attached && (!sentWriter || response=="123456790") && reset && fixtureTracer(tid)==0 && fixture.value(),
              "leaderless debugger cleanup releases the selected stop and preserves original console execution");
    }
    {
        LinuxDebugger debugger; Tracer tracer; TraceConfig config;
        config.startAddress=writerAddress; config.maxSteps=4;
        std::vector<TraceEntry> records;
        std::thread worker([&]{records=tracer.trace(process,debugger,config);});
        const bool armed=awaitState([&]{return tracer.ready();});
        const char writer='b'; const bool sentWriter=armed && ::write(fixture.input,&writer,1)==1;
        if (!sentWriter) tracer.cancel();
        worker.join();
        check(sentWriter && records.size()>=2 && records.front().address==writerAddress &&
              records.front().context.architecture==before.host.architecture && records.front().instruction!="??",
              "leaderless instruction tracing captures actual surviving-thread registers and native decoding");
        const auto response=sentWriter ? fixture.line() : std::string{};
        const uint32_t originalValue=123456789;
        auto reset=process.write(valueAddress,&originalValue,sizeof(originalValue));
        check(sentWriter && response=="123456790" && reset && fixtureTracer(tid)==0 && fixture.value(),
              "leaderless trace cleanup restores the real hardware bank and original console work");
    }
    for (bool single : {false,true}) {
        LinuxDebugger debugger; CodeFinder finder;
        const bool started=finder.start(process,debugger,valueAddress,true,4,false,single);
        const char writer='b'; const bool sentWriter=started && ::write(fixture.input,&writer,1)==1;
        const bool hit=sentWriter && awaitState([&]{return !finder.results().empty();});
        finder.stop();
        const auto results=finder.results();
        check(started && hit && !results.empty() && !results.front().instructionBytes.empty() &&
              results.front().firstContext.architecture==before.host.architecture,
              single ? "native single-thread CodeFinder selects a live member after leader exit" :
                       "all-thread CodeFinder monitors the actual surviving writer after leader exit");
        const auto response=sentWriter ? fixture.line() : std::string{};
        const uint32_t originalValue=123456789;
        auto reset=process.write(valueAddress,&originalValue,sizeof(originalValue));
        check(started && response=="123456790" && reset && fixtureTracer(tid)==0 && fixture.value(),
              "leaderless CodeFinder cleanup restores kernel watchpoints and resumes console work");
    }
    const char quit='q'; const bool quitSent=::write(fixture.input,&quit,1)==1;
    int status=0; pid_t waited; do { waited=waitpid(fixture.pid,&status,0); } while (waited<0 && errno==EINTR);
    check(quitSent && waited==fixture.pid && WIFEXITED(status) && WEXITSTATUS(status)==0 && !process.targetDescription().live,
          "the original process handle retires only after the last live member exits");
    fixture.pid=-1;
    printf("LEADER_EXIT_RESULT=%s\n",failures==initial ? "PASSED" : "FAILED");
}

static void concurrentMetadataBackend(const char* path) {
    const pid_t worker=fork();
    if (!worker) {
        // A deadlock regression terminates this isolated owner, never the driver.
        signal(SIGALRM,SIG_DFL);
        alarm(5);
        Fixture fixture(path);
        if (!fixture.line().starts_with("CE_TARGET ")) _exit(2);
        LinuxProcessHandle process(fixture.pid);
        auto identity=targetProcessIdentity(fixture.pid);
        if (!identity) _exit(3);
        const auto host=process.targetDescription().host;
        std::atomic<bool> callbackEntered=false,readerComplete=false;
        bool inside=false,queued=false,inspected=false;
        std::thread inspection([&] {
            inspected=memorySyscallService().inspectThread(*identity,*identity,host,false,[&]() -> Result<void> {
                callbackEntered=true;
                const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
                while (std::chrono::steady_clock::now()<deadline && !queued) {
                    // The reader's first allocation occurs after entering
                    // targetDescription (the owner request always allocates).
                    // This barrier works even when kernel wait names are hidden.
                    queued=syscall_test::allocationObserved();
                    if (!queued) usleep(1000);
                }
                inside=queued && process.targetDescription().live;
                return {};
            }).has_value();
        });
        const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
        while (!callbackEntered && std::chrono::steady_clock::now()<deadline) usleep(1000);
        std::thread reader([&] {
            syscall_test::watchAllocation(static_cast<pid_t>(syscall(SYS_gettid)));
            readerComplete=process.targetDescription().live;
        });
        inspection.join(); reader.join();
        syscall_test::watchAllocation(0);
        alarm(0);
        // Cleanup the fixture before exiting so an isolated regression leaves no
        // running descendants or inherited process-level owner thread.
        const bool ok=queued && inside && inspected && readerComplete && fixtureTracer(fixture.pid)==0 && fixture.value();
        kill(fixture.pid,SIGKILL);
        int status=0; while (waitpid(fixture.pid,&status,0)<0 && errno==EINTR) {}
        fixture.pid=-1;
        _exit(ok ? 0 : 4);
    }
    if (worker<0) { check(false,"metadata concurrency regression can create its isolated owner"); return; }
    int status=0; pid_t waited;
    do { waited=waitpid(worker,&status,0); } while (waited<0 && errno==EINTR);
    check(worker>0 && waited==worker && WIFEXITED(status) && WEXITSTATUS(status)==0,
          "concurrent frontend metadata and an owned inspection callback complete without a lock-order deadlock");
}

static void metadataRecoveryBackend(const char* path) {
    Fixture fixture(path);
    check(fixture.line().starts_with("CE_TARGET "),"image-metadata recovery starts a real syscall-parked target");
    LinuxProcessHandle process(fixture.pid);
    const auto host=process.targetDescription().host;
    syscall_test::arm(syscall_test::Fault::MetadataAfterStep);
    auto failed=executeMemorySyscall(fixture.pid,host,MemorySyscall::Map,{0,4096,3,0x22,UINT64_MAX,0});
    check(!failed && syscall_test::triggered()>0 && failed.error().recovery && failed.error().completedValue &&
          fixtureTracer(fixture.pid)==getpid(),
          "unavailable executable metadata after real mmap retains its allocation and original stopped owner");
    syscall_test::clear();
    if (failed || !failed.error().recovery || !failed.error().completedValue) return;
    const auto allocation=*failed.error().completedValue;
    check(failed.error().recovery->retry().has_value() && fixtureTracer(fixture.pid)==0 && fixture.value(),
          "restored executable metadata permits verified GP/restart recovery and original console work");
    auto freed=executeMemorySyscall(fixture.pid,host,MemorySyscall::Unmap,{allocation,4096,0,0,0,0});
    uint32_t word=0;
    check(freed && readMemory(fixture.pid,allocation,&word,sizeof(word))<0,
          "completed but unreturned mmap is released after metadata and register recovery");

    auto stale=targetProcessIdentity(fixture.pid);
    if (!stale) { check(false,"stale-birth cleanup starts with a readable task identity"); return; }
    ++stale->startTime;
    bool callbackCalled=false;
    syscall_test::arm(syscall_test::Fault::MetadataAfterSeize);
    auto guarded=executeThreadInspection(*stale,host,false,[&]() -> Result<void> { callbackCalled=true; return {}; });
    check(!guarded && guarded.error().recovery && !callbackCalled && fixtureTracer(fixture.pid)==getpid(),
          "unavailable image metadata with a stale requested birth retains the actual seized task without calling user code");
    syscall_test::clear();
    check(!guarded && guarded.error().recovery && guarded.error().recovery->retry().has_value() &&
          fixtureTracer(fixture.pid)==0 && fixture.value(),
          "cleanup binds to the actual seized task birth rather than retiring a stale caller identity");

    Fixture brokered(path);
    check(brokered.line().starts_with("CE_TARGET "),"brokered metadata recovery starts a separate real target");
    LinuxProcessHandle caller(brokered.pid);
    syscall_test::arm(syscall_test::Fault::MetadataAfterStep);
    auto allocationResult=caller.allocate(4096,MemProt::ReadWrite);
    check(!allocationResult && caller.targetDescription().pendingRecovery && fixtureTracer(brokered.pid)>0,
          "the application broker never returns a mapping while live metadata failure leaves GP restoration pending");
    const auto unreturned=syscall_test::completedResult();
    syscall_test::clear();
    if (allocationResult) return;
    auto recovered=caller.retryPendingOperations();
    check(recovered && !caller.targetDescription().pendingRecovery && fixtureTracer(brokered.pid)==0 &&
          unreturned && readMemory(brokered.pid,unreturned,&word,sizeof(word))<0 && brokered.value(),
          "process recovery owns and unmaps the unreturned allocation after executable metadata becomes readable");
}

static void threadInspectionBackend(const char* path) {
    Fixture fixture(path);
    check(fixture.line().starts_with("CE_TARGET "),"thread inspection starts a real syscall-parked native target");
    usleep(10000);
    LinuxProcessHandle process(fixture.pid);
    auto initial=ce::inspectThread(process,fixture.pid,true);
    check(initial && initial->stack.size()==32 && !initial->frames.empty() && fixtureTracer(fixture.pid)==0,
          "owned inspection reads registers and stack together then releases the actual kernel stop");
    if (!initial) return;
    ThreadSnapshot stale=*initial;
    if (stale.context.architecture==CpuArchitecture::Arm64) { stale.context.pc+=4; stale.context.sp+=16; }
    else { stale.context.rip+=4; stale.context.rsp+=16; }
    std::vector<uint64_t> values;
    for (const auto& reg : cpuRegisterValues(stale.context)) values.push_back(reg.value);
    const size_t edited=stale.context.architecture==CpuArchitecture::Arm64 ? 32 :
        stale.context.architecture==CpuArchitecture::X86_32 ? 7 : 17;
    values[edited]^=1;
    auto applied=ce::inspectThread(process,fixture.pid,false,&stale,values);
    check(applied && applied->context.instructionPointer()==initial->context.instructionPointer() &&
          applied->context.stackPointer()==initial->context.stackPointer() &&
          cpuRegisterValues(applied->context)[edited].value==values[edited],
          "real kernel edit merges a changed GP register without replaying stale PC or SP");
    if (applied) {
        values.clear();
        for (const auto& reg : cpuRegisterValues(applied->context)) values.push_back(reg.value);
        values[edited]=cpuRegisterValues(initial->context)[edited].value;
        check(ce::inspectThread(process,fixture.pid,false,&*applied,values).has_value(),
              "register edit can restore the target's original general register");
    }
    auto identity=targetProcessIdentity(fixture.pid);
    if (!identity) { check(false,"inspection target identity remains live"); return; }
    auto& service=memorySyscallService();
    CpuContext original{};
    auto aborted=service.inspectThread(*identity,*identity,process.targetDescription().host,true,[&]() -> Result<void> {
        auto context=readNativeContext(fixture.pid);
        if (!context) return std::unexpected(context.error());
        original=*context;
        const auto registers=cpuRegisterValues(original);
        context->debugRegistersValid=false;
        if (!setCpuRegisterValue(*context,edited,registers[edited].value^1))
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        auto written=writeNativeContext(fixture.pid,*context);
        if (!written) return written;
        // Exercise reentrant target metadata on the ptrace owner, not just GP IO.
        auto metadata=process.targetDescription();
        if (!metadata.live) return std::unexpected(std::make_error_code(std::errc::no_such_process));
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    });
    auto restored=ce::inspectThread(process,fixture.pid);
    check(!aborted && restored && cpuRegisterValues(restored->context)[edited].value==cpuRegisterValues(original)[edited].value &&
          fixtureTracer(fixture.pid)==0,"failed inspection callback restores its real register mutation and retains syscall restart");
    syscall_test::arm(syscall_test::Fault::PreflightDetach);
    auto failed=service.inspectThread(*identity,*identity,process.targetDescription().host,false,[]() -> Result<void> { return {}; });
    check(!failed && syscall_test::triggered()>0 && service.pending(identity->pid,identity->startTime) &&
          fixtureTracer(fixture.pid)>0,"inspection detach failure retains ownership beyond the frontend callback");
    syscall_test::clear();
    check(service.recover(*identity).has_value() && fixtureTracer(fixture.pid)==0 &&
          !service.pending(identity->pid,identity->startTime),"native service recovers retained inspection ownership on its original thread");
    check(fixture.value(),"all inspections and edit rollback preserve the target's original blocked read");
    Fixture concurrent(path);
    std::istringstream header(concurrent.line()); std::string magic;
    pid_t pid=0; unsigned width=0; uintptr_t value=0;
    header>>magic>>pid>>width>>std::hex>>value;
    LinuxProcessHandle siblings(concurrent.pid);
    const char command='u';
    bool started=::write(concurrent.input,&command,1)==1;
    std::istringstream ready(concurrent.line()); uintptr_t flag=0,counter=0;
    ready>>magic>>std::hex>>flag>>counter;
    auto parent=targetProcessIdentity(concurrent.pid);
    const auto threads=siblings.threads();
    auto thread=std::find_if(threads.begin(),threads.end(),[&](const auto& t) { return t.tid!=concurrent.pid; });
    check(started && ready && magic=="CE_SHARED" && parent && thread!=threads.end(),
          "inspection concurrency fixture has a real running sibling");
    if (!ready || !parent || thread==threads.end()) return;
    bool progressed=false;
    auto inspected=service.inspectThread(*parent,*parent,siblings.targetDescription().host,false,[&]() -> Result<void> {
        uint32_t before=0,after=0;
        const bool read=readMemory(concurrent.pid,counter,&before,sizeof(before))==sizeof(before);
        usleep(10000);
        progressed=read && readMemory(concurrent.pid,counter,&after,sizeof(after))==sizeof(after) && before!=after;
        return {};
    });
    check(inspected && progressed,"inspecting one selected thread leaves its shared-code sibling running");
    auto selected=targetProcessIdentity(thread->tid);
    if (!selected) { check(false,"selected sibling identity is available for retained recovery checks"); return; }
    if (selected) {
        syscall_test::arm(syscall_test::Fault::PreflightDetach);
        auto held=service.inspectThread(*selected,*parent,siblings.targetDescription().host,false,[]() -> Result<void> { return {}; });
        check(!held && service.pending(parent->pid,parent->startTime) && fixtureTracer(concurrent.pid)==0 && fixtureTracer(selected->pid)>0,
              "failed sibling inspection reports pending recovery against its process without seizing the whole group");
        syscall_test::clear();
        check(service.recover(*parent).has_value() && fixtureTracer(selected->pid)==0,
              "process-level recovery releases the retained selected sibling on its original owner");
    }
    uint32_t zero=0;
    check(writeMemory(concurrent.pid,flag,&zero,sizeof(zero))==sizeof(zero) && concurrent.line()=="CE_SHARED_DONE" && concurrent.value(),
          "selected-thread inspections preserve both real threads and original console work");

}

#include "test/return_boundary_checks.inc"
#include "test/restart_boundary_checks.inc"

int main(int argc,char** argv) {
    signal(SIGPIPE,SIG_IGN);
    bool init=getpid()==1;
    if(init) { mkdir("/proc",0755); mount("proc","/proc","proc",0,nullptr); }
    bool includeSme=true;
#if defined(__aarch64__)
    // The additional 64 KiB kernel profile explicitly requires SME to be absent.
    // The original profile still requires every positive SME/deferred-state case.
    const char* vectorProfile=init ? getenv("ce_vm_sme") : nullptr;
    if (vectorProfile && std::strcmp(vectorProfile,"unavailable")==0) {
        const int before=failures;
        const bool advertised=(getauxval(AT_HWCAP2)&HWCAP2_SME)!=0;
        errno=0;const int length=prctl(PR_SME_GET_VL,0,0,0,0);const int error=errno;
        check(!advertised && length==-1 && error==EINVAL,
              "the declared non-SME kernel profile lacks the userspace capability and rejects SME vector control");
        check((getauxval(AT_HWCAP)&HWCAP_SVE)!=0 && prctl(PR_SVE_GET_VL,0,0,0,0)>0,
              "the non-SME kernel still provides real SVE instructions and vector control");
        printf("VECTOR_PROFILE_RESULT=%s sve=available sme=unavailable\n",failures==before ? "PASSED" : "FAILED");
        includeSme=false;
    }
#endif
    if (!init && argc==3 && std::strcmp(argv[1],"--session-exit-only")==0) {
        sessionThreadExitBackend(argv[2]); return failures ? 1 : 0;
    }
    if (!init && argc==3 && std::strcmp(argv[1],"--finder-teardown-only")==0) {
        codeFinderTeardownBackend(argv[2]); return failures ? 1 : 0;
    }
#if defined(__x86_64__)
    if (!init && argc==3 && std::strcmp(argv[1],"--restart-boundary-only")==0) {
        restartBoundaryBackend(argv[2]); return failures ? 1 : 0;
    }
    if (!init && argc==3 && std::strcmp(argv[1],"--return-boundary-only")==0) {
        returnBoundaryBackend(argv[2]); return failures ? 1 : 0;
    }
    returnBoundaryBackend(init ? "/fixture" : argc==2 ? argv[1] : "");
    restartBoundaryBackend(init ? "/fixture" : argc==2 ? argv[1] : "");
#endif
    sessionThreadExitBackend(init ? "/fixture" : argc==2 ? argv[1] : "");
    plans();
    if(init) { exercise("/fixture"); debugBackend("/fixture"); fullSession("/fixture"); sessionRecovery("/fixture"); traceBackend("/fixture"); codeFinderBackend("/fixture"); stoppedSyscallBackend("/fixture"); softwareFinderBackend("/fixture"); codeFinderSignalBackend("/fixture"); }
    else if(argc==2) { exercise(argv[1]); debugBackend(argv[1]); fullSession(argv[1]); sessionRecovery(argv[1]); traceBackend(argv[1]); codeFinderBackend(argv[1]); stoppedSyscallBackend(argv[1]); softwareFinderBackend(argv[1]); codeFinderSignalBackend(argv[1]); }
    else { fprintf(stderr,"usage: target_syscall_integration <native fixture>\n"); return 2; }
    codeFinderTeardownBackend(init ? "/fixture" : argv[1]);
    exitedLeaderBackend(init ? "/fixture" : argv[1]);
    concurrentMetadataBackend(init ? "/fixture" : argv[1]);
    metadataRecoveryBackend(init ? "/fixture" : argv[1]);
    threadInspectionBackend(init ? "/fixture" : argv[1]);
    preflightRecovery(init ? "/fixture" : argv[1]);
    stoppedFunctionBackend(init ? "/fixture" : argv[1]);
    nativeCallOwnerBackend(init ? "/fixture" : argv[1]);
#if defined(__aarch64__)
    for (char command : {'E','F','M','N'})
        if (includeSme || command=='E' || command=='F') stoppedFunctionBackend(init ? "/fixture" : argv[1],command);
#endif
    if (init) sharedCodeSyscalls("/fixture");
    else sharedCodeSyscalls(argv[1]);
    if (init) deniedSyscall("/fixture");
    else deniedSyscall(argv[1]);
    if (init) dispatchSyscalls("/fixture");
    else dispatchSyscalls(argv[1]);
    extendedSyscallContext(init ? "/fixture" : argv[1],includeSme);
    for (unsigned mode=0;mode<5;++mode) for (bool streaming : {false,true})
        if (includeSme || !streaming) deferredSyscallContext(init ? "/fixture" : argv[1],streaming,mode,includeSme);
    for (bool alternate : {false,true}) for (bool streaming : {false,true})
        if (includeSme || !streaming) guardedVectorSyscall(init ? "/fixture" : argv[1],streaming,alternate,includeSme);
#ifdef CECORE_VM_NATIVE_CALL
    if (init) {
        char program[]="native_call_integration",fixture[]="/native_call_fixture",library[]="/libnative_call_library.so";
        char* arguments[]={program,fixture,library,nullptr};
        check(nativeCallIntegration(3,arguments)==0,"real ARM64 library/pthread injection completes under the guest kernel");
    }
#endif
    printf("%d failed target syscall checks\n",failures);
    if(init) {
        printf("CE_VM_RESULT=%s\n",failures ? "FAILED" : "PASSED"); fflush(stdout);
        reboot(RB_POWER_OFF); for(;;) pause();
    }
    return failures ? 1 : 0;
}
