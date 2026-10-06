#include "platform/linux/call_service.hpp"
#include "platform/linux/linux_process.hpp"
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <fstream>
#include <poll.h>
#include <sstream>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/utsname.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/elf.h>

using namespace ce;
namespace {
bool execObserved=false,denyDetach=false,denyExecMessage=false,denyReleasedDetach=false;
unsigned registerWrites=0,detachFailures=0,checks=0,failures=0;
pid_t execTid=0,formerTid=0,expectedLeader=0,expectedThread=0;
unsigned messageFailures=0;

void check(bool value,const char* message) {
    printf("%s: %s\n",value ? "OK" : "FAILED",message);fflush(stdout);
    ++checks;failures+=!value;
}
struct Fixture {
    pid_t pid=-1,thread=0;
    int input=-1,output=-1;
    explicit Fixture(const char* path) {
        int in[2],out[2];
        if (pipe(in)) return;
        if (pipe(out)) {close(in[0]);close(in[1]);return;}
        const auto parent=getpid();pid=fork();
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
        while (result.size()<2048) {
            pollfd fd{output,POLLIN,0};
            if (poll(&fd,1,3000)<=0) break;
            char c;if (read(output,&c,1)!=1) break;
            if (c=='\n') return result;
            result+=c;
        }
        return {};
    }
    ~Fixture() {
        denyDetach=false;denyExecMessage=false;denyReleasedDetach=false;
        if (pid>0) {
            kill(pid,SIGKILL);
            // Reap a selected traced sibling as well: its unreaped exit can
            // otherwise keep the killed leader waiting for the thread group.
            for (unsigned attempt=0;attempt<3000;++attempt) {
                int status=0;
                if (thread>0 && thread!=pid) {
                    auto waited=waitpid(thread,&status,__WALL|__WNOTHREAD|WNOHANG);
                    if (waited==thread && WIFSTOPPED(status)) ptrace(PTRACE_CONT,thread,nullptr,reinterpret_cast<void*>(SIGKILL));
                }
                auto waited=waitpid(pid,&status,__WALL|__WNOTHREAD|WNOHANG);
                if ((waited==pid && (WIFEXITED(status) || WIFSIGNALED(status))) || (waited<0 && errno==ECHILD)) break;
                if (waited==pid && WIFSTOPPED(status)) ptrace(PTRACE_CONT,pid,nullptr,reinterpret_cast<void*>(SIGKILL));
                usleep(1000);
            }
        }
        if (input>=0) close(input);
        if (output>=0) close(output);
    }
};
bool userLoop(pid_t pid,uintptr_t address) {
    os::LinuxProcessHandle process(pid);
    for (unsigned attempt=0;attempt<300;++attempt) {
        unsigned entered=0;
        auto read=process.read(address,&entered,sizeof(entered));
        if (read && *read==sizeof(entered) && entered==1) return true;
        usleep(1000);
    }
    return false;
}
bool startThread(Fixture& fixture,pid_t& tid) {
    if (!fixture.command('T')) return false;
    std::istringstream in(fixture.line());std::string magic;uintptr_t address=0,entered=0;
    in>>magic>>tid>>std::hex>>address>>entered;
    if (!in || magic!="CALL_EXEC_THREAD" || tid<=0 || tid==fixture.pid || !address || !userLoop(tid,entered)) return false;
    fixture.thread=tid;
    for (unsigned attempt=0;attempt<300;++attempt) {
        std::ifstream syscall("/proc/"+std::to_string(fixture.pid)+"/syscall");
        long number=-1;uint64_t descriptor=~uint64_t{};
        if (syscall>>number>>std::hex>>descriptor && descriptor==0 &&
            (number==0 || number==3 || number==63 || number==0x40000000)) return true;
        usleep(1000);
    }
    return false;
}
struct Ready {
    pid_t pid=0,peer=0;
    uintptr_t busy=0,callee=0,create=0,detach=0,worker=0,count=0,execDetach=0,signalExecDetach=0,signalDetach=0,detachResult=0,userReady=0;
    bool parse(const std::string& line) {
        std::istringstream in(line);std::string magic;size_t size=0;
        uintptr_t frame=0,slot=0;
        in>>magic>>pid>>peer>>size>>std::hex>>create>>detach>>worker>>busy>>frame>>slot>>count>>callee>>execDetach>>signalExecDetach>>signalDetach>>detachResult>>userReady;
        return in && magic=="CALL_IMAGE_READY" && pid>0 && peer>0 && busy && callee;
    }
};
bool startBusy(Fixture& fixture,const Ready& ready) {
    return fixture.command('B') && fixture.line()=="CALL_IMAGE_BUSY" && userLoop(fixture.pid,ready.userReady);
}
bool oldPeerAlive(const Ready& ready) {
    auto task=os::processMemoryTask(ready.peer);
    if (!task || *task!=ready.peer) return false;
    os::LinuxProcessHandle peer(ready.peer);uint8_t byte=0;
    auto read=peer.read(ready.callee,&byte,1);
    return read && *read==1;
}
unsigned scenario(const char* path,unsigned mode,bool thread=false) {
    execObserved=false;registerWrites=0;detachFailures=0;denyDetach=mode==2;
    denyExecMessage=mode==4;messageFailures=0;execTid=formerTid=0;
    Fixture fixture(path);Ready ready;
    bool started=ready.parse(fixture.line()) && ready.pid==fixture.pid;
    check(started,"real callee-exec fixture starts with an independent old-mm peer");
    if (!started) return 0;
    os::LinuxProcessHandle process(fixture.pid);
    auto host=process.targetDescription().host;
    auto identity=os::processMemoryIdentity(fixture.pid);
    pid_t selected=fixture.pid;
    bool busy=thread ? startThread(fixture,selected) : startBusy(fixture,ready);
    check(identity && busy,"callee exec begins from an eligible original user stop");
    if (!identity || !busy) return host.pointerWidth;
    expectedLeader=fixture.pid;expectedThread=selected;
    os::NativeCallOwner owner;os::NativeCallRequest request;
    request.function=ready.callee;request.arguments[0]=mode==1 || mode==3;request.timeoutMs=1000;
    request.forwardSignals=mode==3;
    auto invoked=owner.invoke(*identity,host,std::move(request));
    if (!invoked) printf("CALL_EXEC_DIAGNOSTIC mode=%u nonleader=%d error=%d:%s\n",mode,thread,
                        invoked.error().value(),invoked.error().message().c_str());
    if (mode==1) {
        check(!invoked && invoked.error()==std::errc::interrupted && owner.pending(identity->pid,identity->startTime) && !execObserved,
              "a genuine callee SIGUSR1 retains the original call before exec");
        auto resumed=owner.resume(*identity,false);
        check(!resumed && resumed.error()==std::errc::operation_canceled,
              "explicit signal suppression reports the callee's subsequent real exec");
    } else if (mode==4) {
        check(!invoked && invoked.error()==std::errc::io_error && messageFailures &&
              owner.pending(identity->pid,identity->startTime) && execObserved,
              "failed actual former-TID inspection retains the consumed exec stop");
        denyExecMessage=false;
        auto retried=owner.recover(*identity);
        check(!retried && retried.error()==std::errc::operation_canceled,
              "retry verifies and releases the retained replacement stop after inspection succeeds");
    } else {
        check(!invoked && (mode==2 || invoked.error()==std::errc::operation_canceled),
              mode==3 ? "automatic delivery of a real callee signal reports its subsequent exec" :
                        "exec replaces the callee instead of returning an invented value");
    }
    check(execObserved,"the owner consumes the kernel's actual EXEC notification");
    if (thread) check(execTid==ready.pid && formerTid==selected && oldPeerAlive(ready),
        "actual EXEC identifies the selected nonleader while its independent original-mm peer stays readable");
    check(registerWrites==0,"retired call cleanup never writes registers in the replacement image");
    if (mode==2) {
        check(detachFailures>=1 && !owner.empty() && owner.pending(identity->pid,identity->startTime),
              "failed replacement detach retains the actual new-image stop for retry");
        denyDetach=false;
        auto retried=owner.recover(*identity);
        check(!retried && retried.error()==std::errc::operation_canceled && owner.empty() && !registerWrites,
              "detach retry retires the old call without restoring old context");
    } else {
        check(owner.empty(),"callee exec releases the old native call owner");
    }
    Ready replacement;bool replaced=replacement.parse(fixture.line()) && replacement.pid==ready.pid && replacement.peer==ready.peer;
    check(replaced,"replacement reaches its own entry and retains the original mm peer");
    if (replaced) {
        auto current=os::processMemoryIdentity(fixture.pid);
        check(current && *current==*identity,"same-file exec preserves the metadata that cannot establish mm affinity");
        bool active=startBusy(fixture,ready);
        unsigned zero=0;auto wrote=process.write(replacement.busy,&zero,sizeof(zero));
        check(active && wrote && *wrote==sizeof(zero) && fixture.line()=="CALL_IMAGE_RESUMED",
              "replacement remains responsive with its own executable context");
        check(fixture.command('Q'),"replacement accepts normal shutdown after callee exec");
        int status=0;pid_t exited;
        do {exited=waitpid(fixture.pid,&status,0);} while (exited<0 && errno==EINTR);
        check(exited==fixture.pid && WIFEXITED(status) && WEXITSTATUS(status)==0,"replacement and old-mm peer exit normally");
        if (exited==fixture.pid) fixture.pid=-1;
    }
    denyDetach=false;
    return host.pointerWidth;
}
unsigned stoppedRecovery(const char* path,bool thread=false) {
    execObserved=false;registerWrites=0;denyDetach=false;denyExecMessage=false;detachFailures=0;execTid=formerTid=0;
    Fixture fixture(path);Ready ready;
    bool started=ready.parse(fixture.line()) && ready.pid==fixture.pid;
    check(started,"borrowed stopped-function fixture starts with an old-mm peer");
    if (!started) return 0;
    os::LinuxProcessHandle process(fixture.pid);
    auto host=process.targetDescription().host;
    auto page=static_cast<size_t>(sysconf(_SC_PAGESIZE));
    auto frame=process.allocate(18*page,MemProt::ReadWrite);
    bool executable=frame && process.protect(*frame,page,MemProt::Read|MemProt::Exec);
    check(executable,"borrowed function has real private code and stack storage");
    pid_t selected=fixture.pid;
    bool busy=thread ? startThread(fixture,selected) : startBusy(fixture,ready);
    int status=0;
    bool owned=executable && busy && ptrace(PTRACE_SEIZE,selected,nullptr,reinterpret_cast<void*>(PTRACE_O_TRACEEXEC))==0 &&
        ptrace(PTRACE_INTERRUPT,selected,nullptr,nullptr)==0 && waitpid(selected,&status,__WALL)==selected && WIFSTOPPED(status);
    check(owned,"direct caller owns the actual user stop and EXEC tracing option");
    if (!owned) return host.pointerWidth;
    auto called=os::executeStoppedFunction(selected,host,ready.callee,{1,0,0,0,0,0,0,0},*frame,*frame+18*page,1000);
    if (!called) printf("CALL_EXEC_DIRECT_DIAGNOSTIC nonleader=%d error=%d:%s signal=%d event=%d\n",thread,
                       called.error().code.value(),called.error().code.message().c_str(),
                       called.error().pendingSignal,called.error().pendingEvent);
    auto ticket=!called ? called.error().recovery : nullptr;
    check(!called && called.error().code==std::errc::interrupted && ticket && !called.error().completedValue,
          "direct recovery retains a genuine callee signal without a function result");
    if (!ticket) return host.pointerWidth;
    check(ticket->checkImage() && !ticket->imageRetired(),"the direct ticket initially belongs to the original live image");
    auto resumed=ticket->resumeFunction(false);
    check(!resumed && resumed.error()==std::errc::operation_canceled && execObserved && ticket->imageRetired(),
          "real callee exec permanently retires the borrowed recovery context");
    if (thread) check(execTid==ready.pid && formerTid==selected && oldPeerAlive(ready),
        "direct recovery observes the former nonleader TID with the independent original-mm peer still readable");
    if (thread) {
        auto task=ticket->replacementTask();auto identity=os::targetProcessIdentity(fixture.pid);
        check(task && task->tid==fixture.pid && identity && task->startTime==identity->startTime,
              "borrowed owner receives the replacement TID and birth for releasing its stop");
    }
    auto checked=ticket->checkImage();
    check(!checked && checked.error()==std::errc::operation_canceled,
          "a retired recovery fails its image check even while the old mm is still alive");
    auto again=ticket->resumeFunction(false);
    check(!again && again.error()==std::errc::operation_canceled && ticket->retry() && !ticket->functionResult() && !registerWrites,
          "repeated recovery cannot resume or restore an exec-retired function");
    check(ptrace(PTRACE_DETACH,fixture.pid,nullptr,nullptr)==0,"direct caller releases the replacement's unchanged exec stop");
    Ready replacement;bool replaced=replacement.parse(fixture.line()) && replacement.pid==ready.pid && replacement.peer==ready.peer;
    check(replaced,"direct replacement reaches its own entry with the original mm peer alive");
    if (replaced) {
        check(fixture.command('Q'),"direct replacement accepts normal shutdown");
        pid_t exited;do {exited=waitpid(fixture.pid,&status,0);} while (exited<0 && errno==EINTR);
        check(exited==fixture.pid && WIFEXITED(status) && WEXITSTATUS(status)==0,"direct replacement and old-mm peer exit normally");
        if (exited==fixture.pid) fixture.pid=-1;
    }
    return host.pointerWidth;
}
unsigned cleanupExec(const char* path,bool wrapped,unsigned mode,bool thread) {
    execObserved=false;registerWrites=0;detachFailures=0;denyDetach=mode==2;
    denyExecMessage=mode==4;messageFailures=0;execTid=formerTid=0;
    printf("CLEANUP_EXEC wrapped=%u mode=%u nonleader=%u\n",wrapped,mode,thread);fflush(stdout);
    Fixture fixture(path);Ready ready;
    bool started=ready.parse(fixture.line()) && ready.pid==fixture.pid && ready.execDetach && ready.signalExecDetach;
    check(started,"cleanup callee fixture starts with real pthread functions and an old-mm peer");
    if (!started) return 0;
    os::LinuxProcessHandle process(fixture.pid);auto host=process.targetDescription().host;
    auto identity=os::processMemoryIdentity(fixture.pid);pid_t selected=fixture.pid;
    bool busy=thread ? startThread(fixture,selected) : startBusy(fixture,ready);
    check(identity && busy,"pthread creation and cleanup use an eligible original application thread");
    if (!identity || !busy) return host.pointerWidth;
    expectedLeader=fixture.pid;expectedThread=selected;
    os::NativeCallOwner owner;os::NativeCallRequest request;
    request.function=ready.create;request.orphanDetach=mode==1 || mode==3 ? ready.signalExecDetach : ready.execDetach;
    request.outputSize=host.pointerWidth;request.dataArguments=1;request.timeoutMs=1000;request.forwardSignals=mode==3;
    if (wrapped) request.workerEntry=ready.worker;
    else request.arguments[2]=ready.worker;
    auto invoked=owner.invoke(*identity,host,std::move(request));
    std::error_code result=invoked ? std::error_code{} : invoked.error();
    if (!wrapped) {
        check(invoked && !invoked->value && invoked->threadLease && !execObserved,
              "real pthread_create returns a handle lease before its cleanup callee executes");
        if (!invoked) return host.pointerWidth;
        invoked->threadLease.reset();
        auto recovered=owner.recover(*identity);result=recovered ? std::error_code{} : recovered.error();
    }
    if (mode==1) {
        check(result==std::errc::interrupted && owner.pending(identity->pid,identity->startTime) && !execObserved,
              "cleanup callee retains its genuine SIGUSR1 stop for the owner");
        auto resumed=owner.resume(*identity,false);
        check(!resumed && resumed.error()==std::errc::operation_canceled,
              "explicit resume works for the retained cleanup callee and reports its actual exec");
    } else if (mode==4) {
        check(result==std::errc::io_error && messageFailures && owner.pending(identity->pid,identity->startTime),
              "failed former-TID inspection retains the cleanup callee's actual exec stop");
        denyExecMessage=false;auto recovered=owner.recover(*identity);
        check(!recovered && recovered.error()==std::errc::operation_canceled,
              "cleanup recovery verifies and releases the replacement after inspection retry");
    } else check(result && (mode==2 || result==std::errc::operation_canceled),
                 mode==3 ? "cleanup callee applies automatic signal forwarding before reporting exec" :
                           "cleanup callee exec cancels the original pthread operation");
    check(execObserved && execTid==ready.pid && (!thread || formerTid==selected),
          "cleanup consumes the kernel EXEC event under the actual replacement TID");
    check(oldPeerAlive(ready),"the cleanup replacement still has an independent readable original-mm peer");
    check(!registerWrites,"cleanup callee exec never restores GP registers into the replacement");
    if (mode==2) {
        check(detachFailures && owner.pending(identity->pid,identity->startTime),
              "failed cleanup detach retains the replacement stop and original resource owner");
        denyDetach=false;auto recovered=owner.recover(*identity);
        check(!recovered && recovered.error()==std::errc::operation_canceled && !registerWrites,
              "failed cleanup detach retries without executing stale cleanup syscalls");
    }
    check(owner.empty(),"cleanup exec releases pending calls and retained pthread leases");
    Ready replacement;bool replaced=replacement.parse(fixture.line()) && replacement.pid==ready.pid && replacement.peer==ready.peer;
    check(replaced,"pthread cleanup replacement reaches its own executable entry");
    if (replaced) {
        bool active=startBusy(fixture,ready);unsigned zero=0;
        auto wrote=process.write(replacement.busy,&zero,sizeof(zero));
        check(active && wrote && *wrote==sizeof(zero) && fixture.line()=="CALL_IMAGE_RESUMED",
              "pthread cleanup replacement performs its own console work");
        check(fixture.command('Q'),"pthread cleanup replacement accepts normal shutdown");
        int status=0;pid_t exited;do {exited=waitpid(fixture.pid,&status,0);} while (exited<0 && errno==EINTR);
        check(exited==fixture.pid && WIFEXITED(status) && WEXITSTATUS(status)==0,
              "pthread cleanup replacement and original-mm peer exit normally");
        if (exited==fixture.pid) fixture.pid=-1;
    }
    return host.pointerWidth;
}

unsigned returningCleanup(const char* path,bool thread,bool forward) {
    execObserved=false;registerWrites=0;denyDetach=denyExecMessage=false;execTid=formerTid=0;
    printf("RETURNING_CLEANUP nonleader=%u forward=%u\n",thread,forward);fflush(stdout);
    Fixture fixture(path);Ready ready;
    bool started=ready.parse(fixture.line()) && ready.pid==fixture.pid && ready.signalDetach;
    check(started,"returning cleanup fixture exposes the real signal-delivering pthread detacher");
    if (!started) return 0;
    os::LinuxProcessHandle process(fixture.pid);auto host=process.targetDescription().host;
    auto identity=os::processMemoryIdentity(fixture.pid);pid_t selected=fixture.pid;
    bool busy=thread ? startThread(fixture,selected) : startBusy(fixture,ready);
    check(identity && busy,"returning cleanup starts under the selected original application context");
    if (!identity || !busy) return host.pointerWidth;
    os::NativeCallOwner owner;os::NativeCallRequest request;
    request.function=ready.create;request.arguments[2]=ready.worker;request.orphanDetach=ready.signalDetach;
    request.outputSize=host.pointerWidth;request.dataArguments=1;request.timeoutMs=1000;request.forwardSignals=forward;
    auto invoked=owner.invoke(*identity,host,std::move(request));
    check(invoked && !invoked->value && invoked->threadLease,"real pthread_create supplies the returning cleanup's lease");
    if (!invoked) return host.pointerWidth;
    invoked->threadLease.reset();auto recovered=owner.recover(*identity);
    if (!forward) {
        check(!recovered && recovered.error()==std::errc::interrupted && owner.pending(identity->pid,identity->startTime),
              "returning detacher retains its actual SIGUSR1 delivery stop in the lease");
        recovered=owner.resume(*identity,false);
    }
    check(recovered && owner.empty() && !execObserved,
          "returning detacher restores and releases the original context without inventing exec");
    unsigned count=0;auto read=process.read(ready.count,&count,sizeof(count));
    int result=0;auto resultRead=process.read(ready.detachResult,&result,sizeof(result));
    check(read && *read==sizeof(count) && count==1 && resultRead && *resultRead==sizeof(result) && result==0,
          "the returning cleanup callee executes exactly once and reports actual libc success");
    unsigned zero=0;auto wrote=process.write(ready.busy,&zero,sizeof(zero));
    check(wrote && *wrote==sizeof(zero) && (thread || fixture.line()=="CALL_IMAGE_RESUMED"),
          "the restored selected application thread resumes its own user loop");
    check(fixture.command('R') && fixture.line()=="CALL_IMAGE_RELEASED",
          "the original program can independently release its detached pthread");
    check(fixture.command('Q'),"the original program accepts normal shutdown after returning cleanup");
    int status=0;pid_t exited;do {exited=waitpid(fixture.pid,&status,0);} while (exited<0 && errno==EINTR);
    check(exited==fixture.pid && WIFEXITED(status) && WEXITSTATUS(status)==0,
          "the original program and old-mm peer exit normally after context restoration");
    if (exited==fixture.pid) fixture.pid=-1;
    return host.pointerWidth;
}

unsigned releasedCleanup(const char* path,unsigned mode) {
    execObserved=false;registerWrites=0;denyDetach=denyExecMessage=denyReleasedDetach=false;detachFailures=0;
    printf("RELEASED_CLEANUP mode=%u\n",mode);fflush(stdout);
    Fixture fixture(path);Ready ready;
    bool started=ready.parse(fixture.line()) && ready.pid==fixture.pid;
    check(started,"release-race fixture exposes real pthread creation and cleanup");
    if (!started) return 0;
    os::LinuxProcessHandle process(fixture.pid);auto host=process.targetDescription().host;
    auto identity=os::processMemoryIdentity(fixture.pid);pid_t selected=0;
    bool busy=startThread(fixture,selected);
    check(identity && busy,"an original nonleader runs cleanup while the leader remains available for independent work");
    if (!identity || !busy) return host.pointerWidth;
    expectedThread=selected;
    os::NativeCallOwner owner;os::NativeCallRequest request;
    request.function=ready.create;request.arguments[2]=ready.worker;request.orphanDetach=mode==5 ? ready.signalExecDetach : ready.signalDetach;
    request.outputSize=host.pointerWidth;request.dataArguments=1;request.timeoutMs=1000;
    auto invoked=owner.invoke(*identity,host,std::move(request));
    check(invoked && !invoked->value && invoked->threadLease,"the real created pthread supplies a shareable release notification");
    if (!invoked) return host.pointerWidth;
    os::NativeCallResult::ThreadLease notification=*invoked->threadLease;
    invoked->threadLease.reset();
    if (mode!=4) {
        auto stopped=owner.recover(*identity);
        check(!stopped && stopped.error()==std::errc::interrupted && owner.pending(identity->pid,identity->startTime),
              "the abandoned handle's cleanup owns a genuine SIGUSR1 stop before independent release");
    }
    check(fixture.command('D') && fixture.line()=="CALL_LEASE_DETACHED 0",
          "the target independently detaches its actual live pthread while the cleanup owner remains separate");
    notification.release();
    if (mode==4) {
        auto recovered=owner.recover(*identity);unsigned count=0;auto read=process.read(ready.count,&count,sizeof(count));
        check(recovered && owner.empty() && !owner.pending(identity->pid,identity->startTime) &&
              read && *read==sizeof(count) && count==0,
              "an independently released handle with no owned stop needs no synthetic cleanup call");
    } else {
        check(owner.pending(identity->pid,identity->startTime) && !owner.empty(),
              "handle release does not hide an owned cleanup stop from pending queries");
        bool sweep=mode==1 || mode==3;
        if (sweep) {
            owner.recoverAll();
            check(owner.pending(identity->pid,identity->startTime) && !owner.empty(),
                  "global recovery retains the released lease until its actual signal stop is resumed");
        } else {
            auto retained=owner.recover(*identity);
            check(!retained && retained.error()==std::errc::interrupted && owner.pending(identity->pid,identity->startTime) && !owner.empty(),
                  "process recovery retains the released lease until its actual signal stop is resumed");
        }
        siginfo_t signal{};
        check(ptrace(PTRACE_GETSIGINFO,selected,nullptr,&signal)==0 && signal.si_signo==SIGUSR1,
              "the retained stop is still the kernel's original SIGUSR1 delivery stop");
        denyReleasedDetach=mode==2 || mode==3;
        auto resumed=owner.resume(*identity,false);
        if (denyReleasedDetach) {
            check(!resumed && resumed.error()==std::errc::io_error && detachFailures &&
                  owner.pending(identity->pid,identity->startTime) && !owner.empty(),
                  "failed detach after context restoration keeps released-lease ownership retryable");
            denyReleasedDetach=false;
            if (sweep) {owner.recoverAll();resumed=owner.empty() ? Result<void>{} : Result<void>{std::unexpected(std::make_error_code(std::errc::device_or_resource_busy))};}
            else resumed=owner.recover(*identity);
        }
        if (mode==5) {
            check(!resumed && resumed.error()==std::errc::operation_canceled && owner.empty() &&
                  !owner.pending(identity->pid,identity->startTime) && execObserved && execTid==ready.pid && formerTid==selected,
                  "an independently released handle preserves cancellation when its retained cleanup callee execs");
            Ready replacement;bool replaced=replacement.parse(fixture.line()) && replacement.pid==ready.pid && replacement.peer==ready.peer;
            check(replaced && oldPeerAlive(ready),"released-lease exec reaches the replacement with its original-mm peer still readable");
            if (!replaced) return host.pointerWidth;
            bool active=startBusy(fixture,ready);unsigned zero=0;
            auto wrote=process.write(replacement.busy,&zero,sizeof(zero));
            check(active && wrote && *wrote==sizeof(zero) && fixture.line()=="CALL_IMAGE_RESUMED",
                  "released-lease exec leaves the replacement's own console work responsive");
            check(fixture.command('Q'),"released-lease exec accepts normal replacement shutdown");
            int status=0;pid_t exited;do {exited=waitpid(fixture.pid,&status,0);} while (exited<0 && errno==EINTR);
            check(exited==fixture.pid && WIFEXITED(status) && WEXITSTATUS(status)==0,
                  "released-lease exec replacement and original-mm peer exit normally");
            if (exited==fixture.pid) fixture.pid=-1;
            return host.pointerWidth;
        }
        check(resumed && owner.empty() && !owner.pending(identity->pid,identity->startTime) && !execObserved,
              "released-lease recovery restores the application context and releases every owned stop");
        if (!resumed) return host.pointerWidth;
        unsigned count=0;auto read=process.read(ready.count,&count,sizeof(count));
        int result=0;auto resultRead=process.read(ready.detachResult,&result,sizeof(result));
        check(read && *read==sizeof(count) && count==1 && resultRead && *resultRead==sizeof(result) && result==EINVAL,
              "the interrupted cleanup callee returns EINVAL for the already detached handle without repeating its call");
    }
    unsigned zero=0;auto wrote=process.write(ready.busy,&zero,sizeof(zero));
    check(wrote && *wrote==sizeof(zero),"the released lease leaves the selected application's own loop writable");
    check(fixture.command('R') && fixture.line()=="CALL_IMAGE_RELEASED","the original program independently releases the detached worker");
    check(fixture.command('Q'),"the original program accepts normal shutdown after released-lease recovery");
    int status=0;pid_t exited;do {exited=waitpid(fixture.pid,&status,0);} while (exited<0 && errno==EINTR);
    check(exited==fixture.pid && WIFEXITED(status) && WEXITSTATUS(status)==0,
          "the original application and its old-mm peer exit normally after released-lease recovery");
    if (exited==fixture.pid) fixture.pid=-1;
    return host.pointerWidth;
}

}
extern "C" pid_t __real_waitpid(pid_t,int*,int);
extern "C" pid_t __wrap_waitpid(pid_t pid,int* status,int options) {
    auto result=__real_waitpid(pid,status,options);
    if (result>0 && status && WIFSTOPPED(*status) && (*status>>16)==PTRACE_EVENT_EXEC) {
        execObserved=true;execTid=result;
        unsigned long former=0;
        if (ptrace(PTRACE_GETEVENTMSG,result,nullptr,&former)==0) formerTid=static_cast<pid_t>(former);
    }
    return result;
}
extern "C" long __real_ptrace(enum __ptrace_request,...);
extern "C" long __wrap_ptrace(enum __ptrace_request request,...) {
    va_list args;va_start(args,request);
    pid_t tid=va_arg(args,pid_t);void* address=va_arg(args,void*);void* data=va_arg(args,void*);va_end(args);
    const bool gpWrite=(request==PTRACE_SETREGSET && reinterpret_cast<uintptr_t>(address)==NT_PRSTATUS)
#if defined(__x86_64__)
        || request==PTRACE_SETREGS
#endif
        ;
    if (execObserved && gpWrite) {
        ++registerWrites;errno=EIO;return -1;
    }
    if (execObserved && denyDetach && request==PTRACE_DETACH) {
        ++detachFailures;errno=EIO;return -1;
    }
    if (denyReleasedDetach && request==PTRACE_DETACH && tid==expectedThread) {
        ++detachFailures;errno=EIO;return -1;
    }
    auto result=__real_ptrace(request,tid,address,data);
    if (result==0 && request==PTRACE_GETEVENTMSG && denyExecMessage && tid==expectedLeader &&
        data && *static_cast<unsigned long*>(data)==static_cast<unsigned long>(expectedThread)) {
        ++messageFailures;errno=EIO;return -1;
    }
    if (result==0 && execObserved && request==PTRACE_GETEVENTMSG && tid==expectedLeader && data)
        formerTid=static_cast<pid_t>(*static_cast<unsigned long*>(data));
    return result;
}
int main(int argc,char** argv) {
    const bool guest=getpid()==1;
    const bool threadsOnly=argc==3 && std::string_view(argv[2])=="--threads";
    const bool cleanupOnly=argc==3 && std::string_view(argv[2])=="--cleanup";
    const bool releaseOnly=argc==3 && std::string_view(argv[2])=="--release";
    const char* path=argc==2 || threadsOnly || cleanupOnly || releaseOnly ? argv[1] : guest ? "/native_call_image_fixture" : nullptr;
    if (!path) return 2;
    if (guest && mount("proc","/proc","proc",0,nullptr) && errno!=EBUSY) return 3;
    alarm(30);signal(SIGPIPE,SIG_IGN);
    utsname kernel{};
    if (!uname(&kernel)) printf("CALL_EXEC_KERNEL release=%s machine=%s\n",kernel.release,kernel.machine);
    printf("CALL_EXEC_PAGE_SIZE=%ld\n",sysconf(_SC_PAGESIZE));fflush(stdout);
    if (releaseOnly) {
        auto width=releasedCleanup(path,0);auto global=releasedCleanup(path,1);
        check(width && width==global,"release-race reproductions exercise the selected native ABI");
        printf("NATIVE_CALL_EXEC_RESULT=%s width=%u checks=%u failures=%u\n",failures ? "FAILED" : "PASSED",width,checks,failures);
        fflush(stdout);return failures ? 1 : 0;
    }
    if (cleanupOnly) {
        auto width=cleanupExec(path,true,0,false);
        auto worker=cleanupExec(path,true,0,true),lease=cleanupExec(path,false,1,false),threadLease=cleanupExec(path,false,1,true);
        check(width && width==worker && width==lease && width==threadLease,"cleanup reproductions exercise the selected native ABI");
        printf("NATIVE_CALL_EXEC_RESULT=%s width=%u checks=%u failures=%u\n",failures ? "FAILED" : "PASSED",width,checks,failures);
        fflush(stdout);return failures ? 1 : 0;
    }
    unsigned width=scenario(path,0,threadsOnly);
    auto deferred=scenario(path,1,threadsOnly),retained=scenario(path,2,threadsOnly),forwarded=scenario(path,3,threadsOnly),direct=stoppedRecovery(path,threadsOnly);
    auto threadWidth=threadsOnly ? width : scenario(path,0,true);
    auto threadDeferred=threadsOnly ? deferred : scenario(path,1,true);
    auto threadRetained=threadsOnly ? retained : scenario(path,2,true);
    auto threadForwarded=threadsOnly ? forwarded : scenario(path,3,true);
    auto threadDirect=threadsOnly ? direct : stoppedRecovery(path,true);
    auto messageRetry=scenario(path,4,true);
    bool cleanupWidths=true;
    if (!threadsOnly) for (bool wrapped : {true,false}) for (bool thread : {false,true})
        for (unsigned mode=0;mode<(thread ? 5u : 4u);++mode)
            cleanupWidths=cleanupExec(path,wrapped,mode,thread)==width && cleanupWidths;
    if (!threadsOnly) for (bool thread : {false,true}) for (bool forward : {false,true})
        cleanupWidths=returningCleanup(path,thread,forward)==width && cleanupWidths;
    if (!threadsOnly) for (unsigned mode=0;mode<6;++mode)
        cleanupWidths=releasedCleanup(path,mode)==width && cleanupWidths;
    check(cleanupWidths && width && width==deferred && width==retained && width==forwarded && width==direct &&
          width==threadWidth && width==threadDeferred && width==threadRetained && width==threadForwarded &&
          width==threadDirect && width==messageRetry,"all callee exec cases exercise the selected native ABI");
    printf("NATIVE_CALL_EXEC_RESULT=%s width=%u checks=%u failures=%u\n",failures ? "FAILED" : "PASSED",width,checks,failures);
    fflush(stdout);
    if (guest) {sync();reboot(RB_POWER_OFF);}
    return failures ? 1 : 0;
}
