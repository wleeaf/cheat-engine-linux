#include "platform/linux/ceserver_client.hpp"
#include "platform/linux/ceserver_server.hpp"
#include "platform/linux/ceserver_process.hpp"
#include "platform/linux/ceserver_debugger.hpp"
#include "platform/linux/linux_process.hpp"
#include "core/value_io.hpp"
#include "core/expression.hpp"
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <limits>
#include <sstream>
#include <thread>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace ce;
static unsigned checks,failures;
static void check(bool ok,const char* name) {
    ++checks;failures+=!ok;
    printf("%s: %s\n",ok ? "OK" : "FAILED",name);fflush(stdout);
}
class Fixture {
public:
    pid_t pid=-1;
    int input=-1,output=-1;
    unsigned width=0;
    uintptr_t value=0,pointer=0,code=0;
    explicit Fixture(const char* path,const char* next=nullptr) {
        int in[2],out[2];
        if (pipe(in)) return;
        if (pipe(out)) { close(in[0]);close(in[1]);return; }
        auto parent=getpid();pid=fork();
        if (!pid) {
            prctl(PR_SET_PDEATHSIG,SIGKILL);
            if (getppid()!=parent) _exit(127);
            dup2(in[0],0);dup2(out[1],1);
            close(in[0]);close(in[1]);close(out[0]);close(out[1]);
            if (next) execl(path,path,next,nullptr);
            else execl(path,path,nullptr);
            _exit(127);
        }
        close(in[0]);close(out[1]);input=in[1];output=out[0];
        refresh();
    }
    void refresh() {
        std::istringstream s(line());std::string marker;pid_t announced=0;
        s>>marker>>announced>>width>>std::hex>>value>>pointer>>code;
        if (!s || marker!="CE_TARGET" || announced!=pid) width=0;
    }
    std::string line() {
        std::string result;
        while (result.size()<4096) {
            pollfd p{output,POLLIN,0};
            if (poll(&p,1,3000)<=0) return {};
            char c;
            if (::read(output,&c,1)!=1) return {};
            if (c=='\n') return result;
            result+=c;
        }
        return {};
    }
    bool command(char c) { return ::write(input,&c,1)==1; }
    bool finish() {
        if (!command('q')) return false;
        int status=0;
        while (waitpid(pid,&status,0)<0) if (errno!=EINTR) return false;
        pid=-1;return WIFEXITED(status) && WEXITSTATUS(status)==0;
    }
    ~Fixture() {
        if (pid>0) { kill(pid,SIGKILL);while (waitpid(pid,nullptr,0)<0 && errno==EINTR) {} }
        if (input>=0) close(input);
        if (output>=0) close(output);
    }
};
static bool transfer(int fd,void* buffer,size_t size,bool sending) {
    auto* p=static_cast<char*>(buffer);
    while (size) {
        auto n=sending ? send(fd,p,size,MSG_NOSIGNAL) : recv(fd,p,size,0);
        if (n<0 && errno==EINTR) continue;
        if (n<=0) return false;
        p+=n;size-=n;
    }
    return true;
}
static void execTransition(const char* native,const char* compat) {
    printf("CESERVER_EXEC x86-64-to-i386\n");
    Fixture target(native,compat);
    os::CeserverServer server;auto port=server.start(0);
    os::CEServerClient client;std::string error;
    check(target.width==8 && port && client.connectTcp("127.0.0.1",port,error),
        "a real remote exec-transition target and TCP connection start");
    auto remote=os::RemoteProcessHandle::open(client,target.pid);
    if (!remote) { check(false,"the remote exec target opens");return; }
    auto oldHandle=remote->serverHandle();auto originalPid=target.pid;
    check(remote->targetDescription().program.pointerWidth==8,"the remote exec target begins with its 64-bit pointer ABI");
    if (target.command('x')) target.refresh();
    check(target.width==4 && target.pid==originalPid,"the original target execs a real i386 image without changing its PID");
    auto d=remote->targetDescription();
    check(d.program.pointerWidth==4 && d.program.architecture==CpuArchitecture::X86_32 && !remote->is64bit() &&
        remote->serverHandle()==oldHandle,"the same remote handle refreshes its architecture and width after exec");
    auto pointerValue=readTypedValue(*remote,target.pointer,ValueType::Pointer);
    check(pointerValue && std::stoull(*pointerValue,nullptr,16)==target.value,
        "typed pointer reads use the new remote image's four-byte pointer width");
    std::ostringstream expression;expression<<"[0x"<<std::hex<<target.pointer<<"]";
    check(ExpressionParser(remote.get()).parse(expression.str())==target.value,
        "an existing remote expression owner dereferences the new image correctly");
    auto write=writeTypedValue(*remote,target.value,ValueType::Int32,"31415926");
    check(write && target.command('r') && target.line()=="31415926",
        "the new i386 application observes its remote typed write after exec");
    check(bool(writeTypedValue(*remote,target.value,ValueType::Int32,"123456789")),
        "the new image's original field bytes are restored");
    check(target.finish(),"the original remote application exits normally after its ABI transition");
    uint32_t value=0;auto read=remote->read(target.value,&value,sizeof(value));auto arch=client.getArchitecture(oldHandle);
    check(read && !*read && arch && *arch==os::CeArchitecture::Unknown,
        "the retained server handle cannot read or invent an architecture after actual target exit");
    remote.reset();client.close();server.stop();
}
static std::optional<os::CeDebugEvent> trap(os::RemoteDebugger& debugger,uintptr_t address) {
    for (unsigned i=0;i<30;++i) {
        auto event=debugger.waitForEvent(100);
        if (!event) continue;
        if (event->debugEvent==SIGTRAP && event->address==address) return event;
        (void)debugger.continueAfterEvent(static_cast<pid_t>(event->threadId));
    }
    return std::nullopt;
}
static void live(const char* executable,unsigned width) {
    printf("CESERVER_PROFILE width=%u\n",width);
    Fixture target(executable);
    check(target.width==width,"a real Linux target starts with the required pointer ABI");
    if (target.width!=width) return;
    os::LinuxProcessHandle local(target.pid);
    os::CeserverServer server;auto port=server.start(0);
    os::CEServerClient client;std::string error;
    auto connected=port && client.connectTcp("127.0.0.1",port,error);
    check(connected,"the production CEServer client connects to the production TCP server");
    if (!connected) return;
    auto remote=os::RemoteProcessHandle::open(client,target.pid);
    check(bool(remote),"OPENPROCESS retains a real target handle");
    if (!remote) return;
    auto d=remote->targetDescription();
    check(d.live && d.transport==TargetTransport::CEServer && d.program.pointerWidth==width &&
        d.program.architecture==(width==4 ? CpuArchitecture::X86_32 : CpuArchitecture::X86_64),
        "the server reports the target architecture instead of its own architecture");
    auto pointerValue=readTypedValue(*remote,target.pointer,ValueType::Pointer);
    check(pointerValue && std::stoull(*pointerValue,nullptr,16)==target.value,
        "production typed pointer reads use the remote target width");
    std::ostringstream expression;expression<<"[0x"<<std::hex<<target.pointer<<"]";
    check(ExpressionParser(remote.get()).parse(expression.str())==target.value,
        "expression dereferences use the remote pointer ABI");
    auto wrote=writeTypedValue(*remote,target.value,ValueType::Int32,"31415926");
    check(wrote && target.command('r') && target.line()=="31415926",
        "the original target observes its remote typed write");
    check(bool(writeTypedValue(*remote,target.value,ValueType::Int32,"123456789")),
        "the original target bytes are restored through TCP");
    auto localRegions=local.queryRegions(),remoteRegions=remote->queryRegions();
    bool regionsMatch=!localRegions.empty() && localRegions.size()==remoteRegions.size();
    for (size_t i=0;regionsMatch && i<localRegions.size();++i) {
        const auto& a=localRegions[i];const auto& b=remoteRegions[i];
        regionsMatch=a.base==b.base && a.size==b.size && a.protection==b.protection && a.type==b.type;
    }
    check(regionsMatch,"full remote region protections and types match the actual Linux mappings");
    check(!remote->modules().empty() && !remote->threads().empty(),
        "remote module and thread enumeration reaches the actual target");
    auto second=client.openProcess(target.pid);
    check(second && *second>0 && *second!=remote->serverHandle(),
        "two opens have independently closeable server handles");
    if (second) (void)client.closeHandle(*second);
    auto impossible=client.openProcess(std::numeric_limits<int32_t>::max());
    check(impossible && !*impossible,"OPENPROCESS rejects a nonexistent target");

    // QueryRegion was previously unsupported and disconnected the server, so
    // exercise it after the independent full-list/protection baseline checks.
    auto page=remote->allocate(8192,MemProt::ReadWrite);
    check(bool(page),"a remote native syscall allocates two actual target pages");
    if (page) {
        auto region=local.queryRegion(*page);
        check(region && region->protection==MemProt::ReadWrite,
            "allocation honors read/write protection without adding execute permission");
        std::array<uint8_t,32> bytes{};bytes.fill(0x5a);
        auto wr=remote->write(*page+4096-16,bytes.data(),bytes.size());
        check(wr && *wr==bytes.size(),"a remote write crosses two owned target pages");
        auto changed=remote->protect(*page+4096,4096,MemProt::None);
        auto native=local.queryRegion(*page+4096);
        check(changed && native && native->protection==MemProt::None,
            "CHANGEMEMORYPROTECTION changes the actual target mapping");
        std::array<uint8_t,32> readback{};readback.fill(0xa5);
        auto rd=remote->read(*page+4096-16,readback.data(),readback.size());
        check(rd && *rd==16 && readback[0]==0x5a && readback[15]==0x5a && readback[16]==0xa5,
            "a partial remote read preserves the unread suffix and its exact byte count");
        bytes.fill(0x33);wr=remote->write(*page+4096-16,bytes.data(),bytes.size());
        check(wr && *wr==16,"a partial remote write reports its exact transferred prefix");
        // Restore through the local owner too, so baseline failures cannot
        // strand an owned page when an unsupported command closes the stream.
        (void)local.protect(*page,8192,MemProt::ReadWrite);
        if (!client.isConnected()) client.connectTcp("127.0.0.1",port,error);
        if (!remote->targetDescription().live) remote=os::RemoteProcessHandle::open(client,target.pid);
        auto freed=remote->free(*page,8192);
        check(freed && !local.queryRegion(*page),"remote free actually retires its owned target mapping");
        if (!freed) (void)local.free(*page,8192);
    }
    // Use a fresh connection after an old unsupported protection command.
    client.close();client.connectTcp("127.0.0.1",port,error);
    remote=os::RemoteProcessHandle::open(client,target.pid);
    auto readonly=remote->allocate(4096,MemProt::Read);
    check(readonly && local.queryRegion(*readonly) && local.queryRegion(*readonly)->protection==MemProt::Read,
        "a read-only remote allocation is read-only in the real process");
    if (readonly) { (void)remote->free(*readonly,4096);(void)local.free(*readonly,4096); }
    check(!remote->free(target.value,0),"a zero server FREE result is an operation failure");
    auto single=remote->queryRegion(target.value);auto actual=local.queryRegion(target.value);
    check(single && actual && single->base==actual->base && single->size==actual->size &&
        single->protection==actual->protection && single->type==actual->type,
        "VIRTUALQUERYEX returns the actual containing target region");
    client.close();client.connectTcp("127.0.0.1",port,error);remote=os::RemoteProcessHandle::open(client,target.pid);
    check(!remote->protect(1,4096,MemProt::Read),"a zero server protection result is an operation failure");
    client.close();client.connectTcp("127.0.0.1",port,error);remote=os::RemoteProcessHandle::open(client,target.pid);
    uint32_t value=0;
    check(!remote->read(target.value,&value,size_t(UINT32_MAX)+1) &&
        !remote->write(target.value,&value,size_t(INT32_MAX)+1),
        "oversized remote requests fail before any truncated wire transfer");
    auto closed=client.closeHandle(remote->serverHandle());
    auto deadRead=remote->read(target.value,&value,sizeof(value));
    check(closed && deadRead && !*deadRead,"a closed server handle cannot access its former target");
    check(!client.closeHandle(remote->serverHandle()),"closing an already closed handle reports the server's failure");
    remote.reset();
    auto stale=os::RemoteProcessHandle::open(client,target.pid);
    client.close();
    check(!stale->targetDescription().live,"disconnect invalidates the remote process description");
    check(client.connectTcp("127.0.0.1",port,error),"the client reconnects after an orderly disconnect");
    auto fresh=os::RemoteProcessHandle::open(client,target.pid);
    check(fresh && !stale->read(target.value,&value,sizeof(value)) && !stale->targetDescription().live,
        "old process handles cannot dispatch on a replacement TCP connection");
    stale.reset();
    auto freshRead=fresh->read(target.value,&value,sizeof(value));
    check(freshRead && *freshRead==sizeof(value) && value==123456789,
        "destruction of an old handle cannot close a newly opened handle with the same number");
    std::array<uint8_t,1> original{};
    auto originalRead=local.read(target.code,original.data(),original.size());
    auto oldDebugger=std::make_unique<os::RemoteDebugger>(client,fresh->serverHandle());
    check(bool(oldDebugger->attach(target.pid)),"a remote debug session attaches to the opened target identity");
    client.close();
    auto until=std::chrono::steady_clock::now()+std::chrono::seconds(2);
    while (local.targetDescription().tracerPid && std::chrono::steady_clock::now()<until)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    check(!local.targetDescription().tracerPid,"a disconnected debug client releases its actual ptrace ownership");
    client.connectTcp("127.0.0.1",port,error);
    auto debugProcess=os::RemoteProcessHandle::open(client,target.pid);
    os::RemoteDebugger debugger(client,debugProcess->serverHandle());
    check(bool(debugger.attach(target.pid)),"a replacement TCP connection attaches a fresh remote debug session");
    check(!oldDebugger->setBreakpoint(target.pid,0,target.code,0,1),
        "a debugger from an old connection cannot change the replacement target");
    oldDebugger.reset();fresh.reset();
    auto set=debugger.setBreakpoint(target.pid,0,target.code,0,1);
    std::array<uint8_t,1> patched{};
    auto patchedRead=local.read(target.code,patched.data(),patched.size());
    check(set && originalRead && patchedRead && patched[0]==0xcc,
        "destruction of old owners preserves the fresh session and its actual software trap");
    std::optional<os::CeDebugEvent> event;
    if (set && target.command('b')) event=trap(debugger,target.code);
    check(event && event->threadId==target.pid,"the TCP debug event names the actual target instruction and thread");
    auto removed=debugger.removeBreakpoint(target.pid,0);
    auto restored=local.read(target.code,patched.data(),patched.size());
    check(removed && restored && patched==original,"software breakpoint removal restores the real original instruction byte");
    auto continued=debugger.continueAfterEvent(target.pid);
    check(event && continued && target.line()=="123456790","the original application executes the restored instruction and continues");
    auto watch=debugger.setBreakpoint(target.pid,1,target.value,1,4);
    event.reset();
    if (watch && target.command('b')) event=trap(debugger,target.value);
    check(watch && event && event->threadId==target.pid,"an actual remote hardware watchpoint reports the target's write");
    auto watchRemoved=debugger.removeBreakpoint(target.pid,1);
    continued=debugger.continueAfterEvent(target.pid);
    check(watchRemoved && continued && event && target.line()=="123456791",
        "hardware breakpoint removal permits the actual stopped writer to resume");
    check(target.command('b') && target.line()=="123456792",
        "a subsequent target write completes without the removed hardware watchpoint");
    check(bool(debugger.detach()) && !local.targetDescription().tracerPid,
        "explicit remote detach releases the real target without retaining traps");
    check(bool(writeTypedValue(*debugProcess,target.value,ValueType::Int32,"123456789")),
        "the original target field is restored after remote software and hardware debugging");
    debugProcess.reset();client.close();server.stop();
    check(local.targetDescription().live && !local.targetDescription().pendingRecovery,
        "remote memory operations preserve the original target and leave no pending cleanup");
    check(target.finish(),"the original 32/64-bit application exits normally after remote operations");
}

static void malformed(unsigned mode) {
    int listener=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);
    sockaddr_in address{};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    bool ready=listener>=0 && bind(listener,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0 && listen(listener,1)==0;
    socklen_t len=sizeof(address);
    ready=ready && getsockname(listener,reinterpret_cast<sockaddr*>(&address),&len)==0;
    if (!ready) { if(listener>=0) close(listener);check(false,"independent malformed-reply peer starts");return; }
    bool extra=false,received=false;
    std::thread peer([&] {
        int fd=accept4(listener,nullptr,nullptr,SOCK_CLOEXEC);
        if (fd<0) return;
        timeval timeout{2,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
        const size_t sizes[]={18,18,21,6,9,9,9,10,18};
        std::array<char,32> request{};
        received=transfer(fd,request.data(),sizes[mode],false);
        if (received) {
            int32_t invalid=mode==0 ? 5 : -1;
            if (mode==2) invalid=5;
            if (mode==6) { uint32_t present=1;transfer(fd,&present,4,true);invalid=0; }
            if (mode==8) { transfer(fd,&invalid,2,true);shutdown(fd,SHUT_RDWR);close(fd);return; }
            if (mode==5) {
                std::array<uint8_t,28> header{};
                int32_t present=1;std::memcpy(header.data(),&present,4);
                std::memcpy(header.data()+24,&invalid,4);transfer(fd,header.data(),header.size(),true);
            }
            else if (mode==7) { uint32_t header[2]={0,7};transfer(fd,header,8,true); }
            else transfer(fd,&invalid,4,true);
            pollfd p{fd,POLLIN,0};
            if (poll(&p,1,500)>0) { char byte;extra=recv(fd,&byte,1,0)>0; }
        }
        shutdown(fd,SHUT_RDWR);close(fd);
    });
    os::CEServerClient client;std::string error;client.connectTcp("127.0.0.1",ntohs(address.sin_port),error);
    std::array<uint8_t,4> bytes{};bool rejected=false;
    switch (mode) {
        case 0: case 1: case 8: rejected=!client.readProcessMemory(1,0,bytes.data(),4);break;
        case 2: rejected=!client.writeProcessMemory(1,0,bytes.data(),4);break;
        case 3: rejected=!client.virtualQueryExFull(1);break;
        case 4: rejected=!client.enumThreads(1);break;
        case 5: rejected=!client.enumModules(1);break;
        case 6: rejected=!client.getThreadContext(1,1);break;
        case 7: rejected=!client.getSymbolListFromFile("x");break;
    }
    bool disconnected=!client.isConnected();auto version=client.getVersion();peer.join();close(listener);
    printf("CESERVER_MALFORMED mode=%u\n",mode);
    check(received && rejected,"an independent peer's malformed reply is rejected");
    check(disconnected,"a malformed reply retires the desynchronized connection");
    check(!version && !extra,"no subsequent command is sent on a rejected protocol stream");
}
int main(int argc,char** argv) {
    alarm(120);signal(SIGPIPE,SIG_IGN);
    if (argc!=3) return 2;
    live(argv[1],8);live(argv[2],4);execTransition(argv[1],argv[2]);
    for (unsigned mode=0;mode<9;++mode) malformed(mode);
    os::CeserverServer server;
    for (unsigned i=0;i<16;++i) {
        auto port=server.start(0);os::CEServerClient client;std::string error;
        bool connected=port && client.connectTcp("127.0.0.1",port,error);
        auto begin=std::chrono::steady_clock::now();server.stop();
        auto elapsed=std::chrono::steady_clock::now()-begin;
        check(connected && elapsed<std::chrono::seconds(2) && !server.running(),
            "repeated shutdown wakes an accepted or pending idle connection without hanging");
    }
    printf("CESERVER_INTEGRATION_RESULT=%s checks=%u failures=%u\n",failures ? "FAILED" : "PASSED",checks,failures);
    return failures ? 1 : 0;
}
