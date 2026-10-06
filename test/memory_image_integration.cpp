#include "platform/linux/linux_process.hpp"
#include "platform/linux/memory_image.hpp"
#include "platform/linux/syscall_service.hpp"
#include "test/code_write_faults.hpp"
#include <array>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <fstream>
#include <poll.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace ce;
static unsigned checks, failures;
static void check(bool ok, const char* name) {
    ++checks; failures += !ok;
    printf("%s: %s\n", ok ? "OK" : "FAILED", name); fflush(stdout);
}
struct Fixture {
    pid_t pid=-1; int input=-1, output=-1;
    Fixture(const char* path, bool identical) {
        int commands[2], replies[2];
        if (pipe(commands)) return;
        if (pipe(replies)) {close(commands[0]);close(commands[1]);return;}
        const auto parent=getpid();
        pid=fork();
        if (!pid) {
            if (prctl(PR_SET_PDEATHSIG,SIGKILL) || getppid()!=parent) _exit(126);
            dup2(commands[0],0);dup2(replies[1],1);
            close(commands[0]);close(commands[1]);close(replies[0]);close(replies[1]);
            if (identical) execl(path,path,"--identical",nullptr);
            else execl(path,path,nullptr);
            _exit(127);
        }
        close(commands[0]);close(replies[1]);input=commands[1];output=replies[0];
    }
    bool send(char c) {return write(input,&c,1)==1;}
    std::string line() {
        std::string answer;
        while (answer.size()<1024) {
            pollfd descriptor{output,POLLIN,0};
            if (poll(&descriptor,1,5000)<=0) return {};
            char c; if (read(output,&c,1)!=1) return {};
            if (c=='\n') return answer;
            answer+=c;
        }
        return {};
    }
    bool value(unsigned value) {return send('E') && line()=="SHARED_VALUE="+std::to_string(value);}
    bool quit() {
        if (!send('Q')) return false;
        int status;pid_t result;
        do {result=waitpid(pid,&status,0);} while(result<0 && errno==EINTR);
        if (result!=pid) return false;
        pid=-1;return WIFEXITED(status) && !WEXITSTATUS(status);
    }
    ~Fixture() {
        if (pid>0) {kill(pid,SIGKILL);while(waitpid(pid,nullptr,0)<0 && errno==EINTR){}}
        if (input>=0) close(input);
        if (output>=0) close(output);
    }
};
static std::string mappings(pid_t pid) {
    std::ifstream file("/proc/"+std::to_string(pid)+"/maps");
    return {std::istreambuf_iterator<char>(file),std::istreambuf_iterator<char>()};
}
static bool resume(Fixture& fixture,ProcessHandle& process) {
    const uint8_t zero=0;
    auto written=process.write(0x31000008,&zero,1);
    return written && *written==1 && fixture.line()=="SHARED_RESUMED";
}
int main(int argc,char** argv) {
    alarm(60);
    signal(SIGPIPE,SIG_IGN);
    const bool guest=getpid()==1;
    if (guest && mount("proc","/proc","proc",0,nullptr)) return 2;
    const char* path=argc==2 ? argv[1] : "/shared_mm_fixture";
    const size_t page=static_cast<size_t>(sysconf(_SC_PAGESIZE));
    printf("MEMORY_IMAGE_PAGE_SIZE=%zu\n",page);
    for (bool identical : {false,true}) {
        Fixture fixture(path,identical);
        const auto ready=fixture.line();
        check(ready.find("SHARED_READY")==0 && ready.find("value=42")!=std::string::npos,
              "a separate CLONE_VM process keeps the original image alive");
        if (ready.empty()) return 1;
        os::LinuxProcessHandle process(fixture.pid);
        auto pinned=os::pinNativeMemoryImage(process);
        check(pinned && *pinned,"capture the original native address space");
        if (!pinned || !*pinned) return 1;
        auto saved=*pinned;
        const auto baseline=mappings(fixture.pid);
        auto allocation=saved->allocate(page,MemProt::ReadWrite,0x32000000);
        auto protectedPage=allocation ? saved->protect(*allocation,page,MemProt::Read) : Result<void>(std::unexpected(std::make_error_code(std::errc::io_error)));
        auto region=allocation ? process.queryRegion(*allocation) : std::optional<MemoryRegion>{};
        check(allocation && protectedPage && region && region->protection==MemProt::Read,
              "saved-image allocation and protection succeed in their original image");
        auto freed=allocation ? saved->free(*allocation,page) : Result<void>(std::unexpected(std::make_error_code(std::errc::io_error)));
        check(freed && mappings(fixture.pid)==baseline && fixture.value(42),
              "saved-image free releases its allocation and every private affinity page");
        for (auto fault : {code_write_test::Fault::ShortWrite,code_write_test::Fault::DropWrite,
                           code_write_test::Fault::AfterMutation,code_write_test::Fault::RestoreBlocked}) {
            code_write_test::arm(fault);
            auto denied=saved->protect(0x30000000,page,MemProt::ReadWrite);
            const auto triggered=code_write_test::triggered();code_write_test::clear();
            auto recovered=process.retryPendingOperations();
            check(!denied && triggered && recovered && !process.targetDescription().pendingRecovery &&
                  mappings(fixture.pid)==baseline && fixture.value(42),
                  "short, dropped, ambiguous or blocked proof writes leave caller code and mappings intact");
        }
        check(fixture.send('B') && fixture.line()=="SHARED_BUSY","hold a real user-mode native-call rendezvous");
        os::NativeCallRequest call;call.image=saved;call.function=0x30000000;
        auto invoked=os::memorySyscallService().invoke(saved->identity(),process.targetDescription().host,std::move(call));
        check(invoked && invoked->value==42 && !process.targetDescription().pendingRecovery &&
              mappings(fixture.pid)==baseline,"a saved-image native call succeeds and releases its private frame");
        check(resume(fixture,process),"the native call preserves the application's user-mode loop");
        auto oldProbe=saved->allocate(page,MemProt::ReadWrite,0x33000000);
        std::array<uint8_t,16> oldBytes{},newBytes{};
        auto oldBaseline=oldProbe ? saved->read(*oldProbe,oldBytes.data(),oldBytes.size()) :
            Result<size_t>(std::unexpected(std::make_error_code(std::errc::io_error)));
        check(oldProbe && oldBaseline && *oldBaseline==oldBytes.size() &&
              oldBytes==std::array<uint8_t,16>{},
              "the old image retains a private zero-filled probe mapping at a known address");
        const unsigned replacement=identical ? 42 : 55;
        check(fixture.send('X') && fixture.line().find("value="+std::to_string(replacement))!=std::string::npos && saved->check(),
              "same-file exec replaces the caller image while its old descriptor remains live");
        const auto replacementMaps=mappings(fixture.pid);
        auto newProbe=process.allocate(page,MemProt::ReadWrite,oldProbe ? *oldProbe : 0x33000000);
        auto currentImage=os::pinNativeMemoryImage(process);
        auto identity=os::targetProcessIdentity(fixture.pid);
        auto alias=oldProbe && newProbe && *newProbe==*oldProbe && currentImage && *currentImage && identity ?
            os::executeThreadInspection(*identity,process.targetDescription().host,false,[&]() -> Result<void> {
                return saved->sharesPrivateMapping(**currentImage,*newProbe);
            }) : std::expected<void,os::TargetSyscallFailure>(std::unexpected(std::make_error_code(std::errc::io_error)));
        auto oldAfter=saved->read(oldProbe ? *oldProbe : 0,oldBytes.data(),oldBytes.size());
        auto newAfter=process.read(newProbe ? *newProbe : 0,newBytes.data(),newBytes.size());
        auto released=newProbe ? process.free(*newProbe,page) :
            Result<void>(std::unexpected(std::make_error_code(std::errc::io_error)));
        check(!alias && alias.error().code==std::errc::operation_canceled && oldAfter && *oldAfter==oldBytes.size() &&
              newAfter && *newAfter==newBytes.size() &&
              oldBytes==std::array<uint8_t,16>{} && newBytes==oldBytes && released &&
              mappings(fixture.pid)==replacementMaps,
              "identical private bytes at the same address in distinct images fail alias proof and both originals stay intact");
        auto protect=saved->protect(0x30000000,page,MemProt::ReadWrite);
        auto free=saved->free(0x31000000,page);
        auto allocate=saved->allocate(page,MemProt::ReadWrite,0x32000000);
        check(!protect && protect.error()==std::errc::operation_canceled &&
              !free && free.error()==std::errc::operation_canceled &&
              !allocate && allocate.error()==std::errc::operation_canceled &&
              mappings(fixture.pid)==replacementMaps && fixture.value(replacement),
              "old-image mmap, mprotect and munmap never affect same-file replacement, including identical bytes");
        uint8_t old=0,current=0;
        auto oldRead=saved->read(0x31000000,&old,1);
        auto currentRead=process.read(0x31000000,&current,1);
        check(oldRead && currentRead && old==42 && current==replacement,
              "the saved descriptor still reads the old image independently of the replacement");
        check(fixture.send('B') && fixture.line()=="SHARED_BUSY","the replacement exposes an eligible user-mode call thread");
        os::NativeCallRequest stale;stale.image=saved;stale.function=0x30000000;
        auto refused=os::memorySyscallService().invoke(saved->identity(),process.targetDescription().host,std::move(stale));
        check(!refused && refused.error()==std::errc::operation_canceled &&
              !process.targetDescription().pendingRecovery && mappings(fixture.pid)==replacementMaps,
              "an old-image native call is rejected before invocation and its private frame is reclaimed");
        check(resume(fixture,process) && fixture.value(replacement),"replacement execution survives every refused stale operation");
        check(fixture.quit(),"both CLONE_VM fixture processes exit normally without retained trace ownership");
    }
    {
        Fixture fixture(path,false);const auto ready=fixture.line();
        os::LinuxProcessHandle process(fixture.pid);
        auto pinned=os::pinNativeMemoryImage(process);
        if (ready.empty() || !pinned || !*pinned) return 1;
        code_write_test::arm(code_write_test::Fault::RestoreBlocked);
        auto failed=os::executeMemorySyscall(fixture.pid,process.targetDescription().host,os::MemorySyscall::Protect,
            {0x30000000,page,PROT_READ|PROT_WRITE,0,0,0},nullptr,nullptr,pinned->get());
        code_write_test::clear();
        const auto code=process.queryRegion(0x30000000);
        check(!failed && failed.error().recovery && !failed.error().completedValue && code &&
              code->protection==(MemProt::Read|MemProt::Exec),
              "a failed affinity-page cleanup retains its stop without reporting the private map as caller completion");
        kill(fixture.pid,SIGKILL);
        siginfo_t exited{};
        int observed;do {observed=waitid(P_PID,fixture.pid,&exited,WEXITED|WNOWAIT);} while(observed<0 && errno==EINTR);
        auto recovery=!failed ? failed.error().recovery : nullptr;
        auto retired=recovery ? recovery->retry() : Result<void>(std::unexpected(std::make_error_code(std::errc::io_error)));
        check(!observed && exited.si_pid==fixture.pid && recovery && !retired &&
              retired.error()==std::errc::no_such_process && recovery->retry(),
              "unreaped target exit retires retained affinity storage and subsequent recovery is idempotent");
        pid_t reaped;do {reaped=waitpid(fixture.pid,nullptr,0);} while(reaped<0 && errno==EINTR);
        if (reaped==fixture.pid) fixture.pid=-1;
    }
    printf("MEMORY_IMAGE_RESULT=%s checks=%u failures=%u\n",failures ? "FAILED" : "PASSED",checks,failures);fflush(stdout);
    if (guest) {sync();reboot(RB_POWER_OFF);}
    return failures ? 1 : 0;
}
