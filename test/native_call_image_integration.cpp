#include "platform/linux/call_service.hpp"
#include "platform/linux/linux_process.hpp"
#include "test/code_write_faults.hpp"
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <fcntl.h>
#include <poll.h>
#include <sstream>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace ce;
namespace {
int failures=0,checks=0;
void check(bool value,const char* text) {
    printf("%s: %s\n",value ? "OK" : "FAILED",text);
    fflush(stdout);
    failures+=!value;
    ++checks;
}
struct Fixture {
    pid_t pid=-1;
    int input=-1,output=-1;
    explicit Fixture(const char* path) {
        int in[2],out[2];
        if (pipe(in)) return;
        if (pipe(out)) {close(in[0]);close(in[1]);return;}
        const auto parent=getpid();
        pid=fork();
        if (!pid) {
            prctl(PR_SET_PDEATHSIG,SIGKILL);
            if (getppid()!=parent) _exit(126);
            dup2(in[0],0);dup2(out[1],1);
            close(in[0]);close(in[1]);close(out[0]);close(out[1]);
            execl(path,path,nullptr);_exit(127);
        }
        close(in[0]);close(out[1]);input=in[1];output=out[0];
    }
    bool command(char c) {return input>=0 && write(input,&c,1)==1;}
    std::string line() {
        std::string result;
        const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
        while (result.size()<2048 && std::chrono::steady_clock::now()<deadline) {
            pollfd fd{output,POLLIN,0};
            int available=poll(&fd,1,100);
            if (available<0 && errno==EINTR) continue;
            if (available<0) break;
            if (!available) continue;
            char c;
            if (read(output,&c,1)!=1) break;
            if (c=='\n') return result;
            result+=c;
        }
        return {};
    }
    ~Fixture() {
        if (pid>0) {
            kill(pid,SIGKILL);
            while (waitpid(pid,nullptr,0)<0 && errno==EINTR) {}
        }
        if (input>=0) close(input);
        if (output>=0) close(output);
    }
};
struct Ready {
    pid_t pid=0,peer=0;
    size_t size=0;
    uintptr_t create=0,detach=0,entry=0,busy=0,frame=0,frameSlot=0,detachCalls=0,userReady=0;
    bool parse(const std::string& line) {
        std::istringstream input(line);
        std::string magic;
        input>>magic>>pid>>peer>>size>>std::hex>>create>>detach>>entry>>busy>>frame>>frameSlot>>detachCalls;
        uintptr_t callee=0,execDetach=0,signalExecDetach=0,signalDetach=0,detachResult=0;
        input>>callee>>execDetach>>signalExecDetach>>signalDetach>>detachResult>>userReady;
        return bool(input) && magic=="CALL_IMAGE_READY" && pid>0 && peer>0 && size && create && entry;
    }
};
bool startBusy(Fixture& fixture,ProcessHandle& process,const Ready& ready) {
    if (!fixture.command('B') || fixture.line()!="CALL_IMAGE_BUSY") return false;
    for (unsigned attempt=0;attempt<300;++attempt) {
        unsigned entered=0;
        auto read=process.read(ready.userReady,&entered,sizeof(entered));
        if (read && *read==sizeof(entered) && entered==1) return true;
        usleep(1000);
    }
    return false;
}
bool resume(Fixture& fixture,ProcessHandle& process,uintptr_t busy) {
    unsigned zero=0;
    auto written=process.write(busy,&zero,sizeof(zero));
    return written && *written==sizeof(zero) && fixture.line()=="CALL_IMAGE_RESUMED";
}
// Read guards too, through a descriptor of the replacement's actual mm.
std::optional<uint64_t> digest(pid_t pid,uintptr_t address,size_t size) {
    const std::string path="/proc/"+std::to_string(pid)+"/mem";
    int fd=open(path.c_str(),O_RDONLY|O_CLOEXEC);
    if (fd<0) return {};
    std::array<uint8_t,4096> buffer{};
    uint64_t value=14695981039346656037ULL;
    size_t offset=0;
    while (offset<size) {
        ssize_t got=pread(fd,buffer.data(),std::min(buffer.size(),size-offset),address+offset);
        if (got<0 && errno==EINTR) continue;
        if (got<=0) {close(fd);return {};}
        for (ssize_t i=0;i<got;++i) {value^=buffer[i];value*=1099511628211ULL;}
        offset+=static_cast<size_t>(got);
    }
    close(fd);return value;
}
unsigned scenario(const char* path,bool exec,bool fault=false) {
    Fixture fixture(path);
    Ready ready;
    const bool parsed=ready.parse(fixture.line()) && ready.pid==fixture.pid;
    check(parsed,"real pthread fixture and CLONE_VM peer started");
    if (!parsed) return 0;
    os::LinuxProcessHandle process(fixture.pid);
    const auto host=process.targetDescription().host;
    const auto identity=os::processMemoryIdentity(fixture.pid);
    bool busy=startBusy(fixture,process,ready);
    check(busy && bool(identity),"original process is eligible for a stopped native call");
    if (!busy || !identity) return host.pointerWidth;
    os::NativeCallOwner owner;
    os::NativeCallRequest request;
    request.function=ready.create;request.orphanDetach=ready.detach;
    request.workerEntry=ready.entry;request.dataArguments=1;
    request.outputSize=host.pointerWidth;request.timeoutMs=2000;
    auto called=owner.invoke(*identity,host,std::move(request));
    check(called && called->worker && called->worker->tid>0 && !owner.empty(),
          "native worker starts with its private frame retained");
    check(resume(fixture,process,ready.busy),"original application resumes after native call");
    if (!called || !called->worker) return host.pointerWidth;
    if (exec) {
        bool requested=fixture.command('X');
        Ready next;
        bool replaced=requested && next.parse(fixture.line()) && next.pid==ready.pid && next.peer==ready.peer;
        check(replaced,"same-file exec copies the original frame at the identical address");
        if (!replaced) return host.pointerWidth;
        ready=next;
        auto current=os::processMemoryIdentity(fixture.pid);
        check(current && *current==*identity,"executable metadata cannot distinguish the replacement image");
    } else {
        std::array<uint8_t,8> bytes{};
        auto read=process.read(ready.frameSlot,bytes.data(),host.pointerWidth);
        auto frame=decodeTargetUnsigned({bytes.data(),host.pointerWidth},host.byteOrder);
        check(read && *read==host.pointerWidth && frame && *frame,"original frame address is observable");
        if (!read || !frame || !*frame) return host.pointerWidth;
        ready.frame=*frame;
        check(fixture.command('R') && fixture.line()=="CALL_IMAGE_RELEASED","real pthread worker is permitted to exit");
        // The wrapper writes Done on return. Snapshot after actual kernel exit
        // so those legitimate final writes cannot race the byte comparison.
        const std::string workerPath="/proc/"+std::to_string(fixture.pid)+"/task/"+std::to_string(called->worker->tid);
        const auto exitedDeadline=std::chrono::steady_clock::now()+std::chrono::seconds(3);
        while (access(workerPath.c_str(),F_OK)==0 && std::chrono::steady_clock::now()<exitedDeadline) usleep(1000);
    }
    auto before=digest(fixture.pid,ready.frame,ready.size);
    auto region=process.queryRegion(ready.frame);
    check(before && region && region->base==ready.frame,"private frame exists before cleanup");
    busy=startBusy(fixture,process,ready);
    check(busy,"cleanup owns an eligible thread in the current image");
    if (fault) {
        const std::string workerPath="/proc/"+std::to_string(fixture.pid)+"/task/"+std::to_string(called->worker->tid);
        const auto exitedDeadline=std::chrono::steady_clock::now()+std::chrono::seconds(3);
        while (access(workerPath.c_str(),F_OK)==0 && std::chrono::steady_clock::now()<exitedDeadline) usleep(1000);
        check(access(workerPath.c_str(),F_OK)<0 && errno==ENOENT,"kernel worker exit precedes the failed cleanup attempt");
        code_write_test::arm(code_write_test::Fault::RestoreBlocked);
        auto failed=owner.recover(*identity);
        const auto triggered=code_write_test::triggered();
        code_write_test::clear();
        check(!failed && triggered && !owner.empty(),"failed proof restoration retains the cleanup owner for retry");
        auto untouched=digest(fixture.pid,ready.frame,ready.size);
        check(before && untouched && *before==*untouched,"failed proof leaves every caller-frame byte intact");
    }
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(3);
    Result<void> recovered;
    do {
        recovered=owner.recover(*identity);
        if (owner.empty()) break;
        usleep(1000);
    } while (std::chrono::steady_clock::now()<deadline);
    check(recovered && owner.empty() && called->worker->exited.load(),"worker cleanup retires its owner and reports exit");
    auto after=digest(fixture.pid,ready.frame,ready.size);
    auto afterRegion=process.queryRegion(ready.frame);
    if (exec) {
        check(before && after && *before==*after,"replacement frame retains every original byte");
        check(region && afterRegion && region->base==afterRegion->base && region->size==afterRegion->size &&
              region->protection==afterRegion->protection,"replacement frame permissions and range remain intact");
    } else {
        check(!after && !afterRegion,"same-image worker cleanup reclaims the original frame");
    }
    check(resume(fixture,process,ready.busy),"application remains responsive after cleanup");
    check(fixture.command('Q'),"application accepts normal shutdown after cleanup");
    int status=0;
    pid_t exited;
    do {exited=waitpid(fixture.pid,&status,0);} while (exited<0 && errno==EINTR);
    check(exited==fixture.pid && WIFEXITED(status) && WEXITSTATUS(status)==0,"application and old-mm peer shut down normally");
    if (exited==fixture.pid) fixture.pid=-1;
    return host.pointerWidth;
}
unsigned plainLease(const char* path,bool exec) {
    Fixture fixture(path);
    Ready ready;
    bool parsed=ready.parse(fixture.line()) && ready.pid==fixture.pid;
    check(parsed,"plain pthread lease fixture starts with an old-mm peer");
    if (!parsed) return 0;
    os::LinuxProcessHandle process(fixture.pid);
    auto host=process.targetDescription().host;
    auto identity=os::processMemoryIdentity(fixture.pid);
    bool busy=startBusy(fixture,process,ready);
    check(busy && identity,"plain pthread call owns an eligible original stop");
    if (!busy || !identity) return host.pointerWidth;
    os::NativeCallOwner owner;
    os::NativeCallRequest request;
    request.function=ready.create;request.orphanDetach=ready.detach;
    request.arguments[2]=ready.entry;request.dataArguments=1;
    request.outputSize=host.pointerWidth;request.timeoutMs=2000;
    auto called=owner.invoke(*identity,host,std::move(request));
    check(called && called->threadLease && !called->worker && !owner.empty(),
          "plain pthread result retains its handle after the call frame is reclaimed");
    check(resume(fixture,process,ready.busy),"plain pthread call restores normal application work");
    if (!called || !called->threadLease) return host.pointerWidth;
    if (exec) {
        Ready next;
        bool replaced=fixture.command('X') && next.parse(fixture.line()) && next.pid==ready.pid && next.peer==ready.peer;
        check(replaced && !next.frame,"same-file exec replaces a frame-free pthread lease");
        if (!replaced) return host.pointerWidth;
        ready=next;
    } else {
        check(fixture.command('R') && fixture.line()=="CALL_IMAGE_RELEASED","original plain pthread can return independently");
    }
    called->threadLease.reset();
    busy=startBusy(fixture,process,ready);
    check(busy,"abandoned handle cleanup owns an eligible current stop");
    auto recovered=owner.recover(*identity);
    check(owner.empty() && (exec ? !recovered && recovered.error()==std::errc::operation_canceled : bool(recovered)),
          "abandoned handle cleanup completes or retires on an image change");
    unsigned detached=UINT32_MAX;
    auto read=process.read(ready.detachCalls,&detached,sizeof(detached));
    check(read && *read==sizeof(detached) && detached==(exec ? 0u : 1u),
          "orphan pthread detach executes only in its original address space");
    check(resume(fixture,process,ready.busy),"handle cleanup leaves the current application responsive");
    check(fixture.command('Q'),"plain lease application accepts shutdown");
    int status=0;pid_t exited;
    do {exited=waitpid(fixture.pid,&status,0);} while (exited<0 && errno==EINTR);
    check(exited==fixture.pid && WIFEXITED(status) && WEXITSTATUS(status)==0,"plain lease application exits normally");
    if (exited==fixture.pid) fixture.pid=-1;
    return host.pointerWidth;
}
}
int main(int argc,char** argv) {
    const bool guest=getpid()==1;
    const char* path=argc==2 ? argv[1] : guest ? "/native_call_image_fixture" : nullptr;
    if (!path) return 2;
    if (guest && mount("proc","/proc","proc",0,nullptr) && errno!=EBUSY) return 3;
    alarm(30);
    signal(SIGPIPE,SIG_IGN);
    utsname kernel{};
    if (!uname(&kernel)) printf("CALL_IMAGE_KERNEL release=%s machine=%s\n",kernel.release,kernel.machine);
    printf("CALL_IMAGE_PAGE_SIZE=%ld\n",sysconf(_SC_PAGESIZE));
    unsigned width=scenario(path,false);
    unsigned replacementWidth=scenario(path,true);
    unsigned retryWidth=scenario(path,false,true);
    unsigned replacementRetryWidth=scenario(path,true,true);
    unsigned plainWidth=plainLease(path,false);
    unsigned replacementPlainWidth=plainLease(path,true);
    check(width && width==replacementWidth && width==retryWidth && width==replacementRetryWidth &&
          width==plainWidth && width==replacementPlainWidth,
          "all cleanup and retry cases use the selected native ABI");
    printf("NATIVE_CALL_IMAGE_RESULT=%s width=%u\n",failures ? "FAILED" : "PASSED",width);
    printf("NATIVE_CALL_IMAGE_CHECKS=%d failures=%d\n",checks,failures);fflush(stdout);
    if (guest) {sync();reboot(RB_POWER_OFF);}
    return failures ? 1 : 0;
}
