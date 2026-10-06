#include "platform/linux/ceserver_server.hpp"
#include "platform/linux/ceserver_client.hpp"
#include "platform/linux/ceserver_process.hpp"
#include "platform/linux/ceserver_debugger.hpp"
#include "platform/linux/linux_process.hpp"
#include <array>
#include <algorithm>
#include <barrier>
#include <chrono>
#include <cstdio>
#include <future>
#include <sstream>
#include <thread>
#include <vector>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <unistd.h>
using namespace ce;
using namespace std::chrono_literals;
using Clock=std::chrono::steady_clock;
static unsigned checks,failures;
static void check(bool ok,const char* name) {
    ++checks;failures+=!ok;printf("%s: %s\n",ok ? "OK" : "FAILED",name);fflush(stdout);
}
static bool transfer(int fd,void* data,size_t size,bool sending=false) {
    auto* p=static_cast<char*>(data);
    while(size) {
        auto n=sending ? send(fd,p,size,MSG_NOSIGNAL) : recv(fd,p,size,0);
        if(n<0 && errno==EINTR)continue;
        if(n<=0)return false;
        p+=n;size-=static_cast<size_t>(n);
    }
    return true;
}
static int connectRaw(uint16_t port) {
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);
    sockaddr_in address{};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);address.sin_port=htons(port);
    if(fd<0 || connect(fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))) {
        if(fd>=0)close(fd);
        return -1;
    }
    timeval timeout{1,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    return fd;
}
static bool rawVersion(int fd) {
    uint8_t command=0,size=0;int32_t protocol=0;
    if(!transfer(fd,&command,1,true) || !transfer(fd,&protocol,4) || !transfer(fd,&size,1))return false;
    std::array<char,256> version{};
    return transfer(fd,version.data(),size) && protocol==1 && size>0;
}
static void blockedPeer(unsigned mode) {
    printf("CESERVER_MULTICLIENT_BLOCKED mode=%u\n",mode);
    os::CeserverServer server;auto port=server.start(0);
    check(port!=0,"the production multi-client server binds an owned loopback endpoint");
    int stalled=connectRaw(port);
    check(stalled>=0 && rawVersion(stalled),"the first peer completes its handshake before becoming idle");
    if(mode==1 && stalled>=0) {uint8_t partial[]={3,1};transfer(stalled,partial,sizeof(partial),true);}
    os::CEServerClient client;client.setTimeoutMs(400);std::string error;
    auto begin=Clock::now();bool connected=client.connectTcp("127.0.0.1",port,error);
    auto version=client.getVersion();
    check(connected && version && Clock::now()-begin<800ms,"another client receives a complete version while the first is idle or has a partial command");
    uint32_t marker=0xaabbccdd,readback=0;
    auto handle=client.openProcess(getpid());
    auto read=handle ? client.readProcessMemory(*handle,reinterpret_cast<uintptr_t>(&marker),&readback,4)
        : std::expected<int32_t,std::string>(std::unexpected("no handle"));
    check(handle && *handle && read && *read==4 && readback==marker,
        "an independent connection opens and reads actual process memory without waiting for the stalled peer");
    client.close();begin=Clock::now();server.stop();
    check(Clock::now()-begin<800ms && !server.running() && !server.port(),"shutdown cancels idle and partially received commands and joins their workers");
    if(stalled>=0)close(stalled);
}
class Fixture {
    int input_=-1,output_=-1;
public:
    pid_t pid=-1;unsigned width=0;uintptr_t value=0,code=0;
    explicit Fixture(const char* path) {
        int in[2],out[2];if(pipe(in))return;
        if(pipe(out)){close(in[0]);close(in[1]);return;}
        auto parent=getpid();pid=fork();
        if(!pid) {
            prctl(PR_SET_PDEATHSIG,SIGKILL);if(getppid()!=parent)_exit(127);
            dup2(in[0],0);dup2(out[1],1);close(in[0]);close(in[1]);close(out[0]);close(out[1]);
            execl(path,path,nullptr);_exit(127);
        }
        close(in[0]);close(out[1]);input_=in[1];output_=out[0];
        std::istringstream s(line());std::string marker;pid_t announced=0;uintptr_t pointer=0;
        s>>marker>>announced>>width>>std::hex>>value>>pointer>>code;
        if(!s || marker!="CE_TARGET" || announced!=pid)width=0;
    }
    std::string line() {
        std::string result;
        while(result.size()<4096) {
            pollfd p{output_,POLLIN,0};if(poll(&p,1,2000)<=0)return {};
            char c;if(::read(output_,&c,1)!=1)return {};
            if(c=='\n')return result;
            result+=c;
        }
        return {};
    }
    bool command(char c) {return ::write(input_,&c,1)==1;}
    bool finish() {
        if(!command('q'))return false;
        int status=0;
        for(unsigned i=0;i<200;++i) {
            auto result=waitpid(pid,&status,WNOHANG);
            if(result==pid){pid=-1;return WIFEXITED(status)&&WEXITSTATUS(status)==0;}
            if(result<0 && errno!=EINTR)return false;
            std::this_thread::sleep_for(10ms);
        }
        return false;
    }
    ~Fixture() {
        if(pid>0){kill(pid,SIGKILL);while(waitpid(pid,nullptr,0)<0 && errno==EINTR){}}
        if(input_>=0)close(input_);
        if(output_>=0)close(output_);
    }
};
static std::optional<os::CeDebugEvent> trap(os::RemoteDebugger& debugger,uintptr_t address) {
    for(unsigned i=0;i<20;++i) {
        auto event=debugger.waitForEvent(100);
        if(!event)continue;
        if(event->debugEvent==SIGTRAP && event->address==address)return event;
        (void)debugger.continueAfterEvent(static_cast<pid_t>(event->threadId));
    }
    return std::nullopt;
}
static void live(const char* native,const char* compat) {
    printf("CESERVER_MULTICLIENT_LIVE x86-64+i386\n");
    Fixture a(native),b(compat);
    check(a.width==8 && b.width==4,"two actual target applications start with different pointer ABIs");
    os::CeserverServer server;auto port=server.start(0);
    os::CEServerClient ca,cb;ca.setTimeoutMs(1000);cb.setTimeoutMs(1000);std::string error;
    bool connected=port && ca.connectTcp("127.0.0.1",port,error) && cb.connectTcp("127.0.0.1",port,error);
    auto pa=os::RemoteProcessHandle::open(ca,a.pid),pb=os::RemoteProcessHandle::open(cb,b.pid);
    check(connected && pa && pb,"two connections simultaneously retain independently opened live targets");
    if(!pa || !pb)return;
    check(pa->serverHandle()==pb->serverHandle() && pa->is64bit() && !pb->is64bit(),
        "equal numeric handles on different connections retain their distinct target identities and ABIs");
    uint32_t av=17,bv=29,ar=0,br=0;
    auto wa=pa->write(a.value,&av,4),wb=pb->write(b.value,&bv,4);
    auto ra=pa->read(a.value,&ar,4),rb=pb->read(b.value,&br,4);
    check(wa && wb && ra && rb && ar==av && br==bv && a.command('r') && a.line()=="17" && b.command('r') && b.line()=="29",
        "writes through equal connection-local handles reach only their own actual target applications");
    os::LinuxProcessHandle la(a.pid),lb(b.pid);
    std::array<uint8_t,1> originalA{},originalB{},byte{};
    auto originalReadA=la.read(a.code,originalA.data(),1),originalReadB=lb.read(b.code,originalB.data(),1);
    os::RemoteDebugger da(ca,pa->serverHandle()),db(cb,pb->serverHandle());
    bool attachedA=bool(da.attach(a.pid)),attachedB=bool(db.attach(b.pid));
    check(attachedA && attachedB && la.targetDescription().tracerPid && lb.targetDescription().tracerPid,
        "both remote debug sessions retain real ptrace ownership at the same time");
    auto sa=da.setBreakpoint(a.pid,0,a.code,0,1),sb=db.setBreakpoint(b.pid,0,b.code,0,1);
    auto ba=la.read(a.code,byte.data(),1);bool patchedA=ba && byte[0]==0xcc;
    auto bb=lb.read(b.code,byte.data(),1);
    check(sa && sb && patchedA && bb && byte[0]==0xcc,"each connection installs its own actual software breakpoint");
    bool commands=a.command('b') && b.command('b');
    auto fa=std::async(std::launch::async,[&]{return trap(da,a.code);});
    auto fb=std::async(std::launch::async,[&]{return trap(db,b.code);});
    auto ea=fa.get(),eb=fb.get();
    check(commands && ea && eb && ea->threadId==a.pid && eb->threadId==b.pid,
        "simultaneous debug-event waiters receive only their own target instruction and thread");
    ca.close();
    auto until=Clock::now()+2s;
    while(la.targetDescription().tracerPid && Clock::now()<until)std::this_thread::sleep_for(10ms);
    auto restoredA=la.read(a.code,byte.data(),1);
    check(!la.targetDescription().tracerPid && originalReadA && restoredA && byte==originalA,
        "disconnecting one client detaches its target and restores that target's instruction");
    auto stillB=lb.read(b.code,byte.data(),1);
    check(lb.targetDescription().tracerPid && stillB && byte[0]==0xcc,
        "one client's teardown preserves the other client's ptrace owner and stopped breakpoint");
    auto removeB=db.removeBreakpoint(b.pid,0),continueB=db.continueAfterEvent(b.pid);
    auto restoredB=lb.read(b.code,byte.data(),1);
    check(removeB && continueB && originalReadB && restoredB && byte==originalB && b.line()=="30",
        "the surviving debugger independently restores and resumes its original application");
    check(a.line()=="18","the disconnected debugger's original application also resumes normally");
    // Drain start/resume notifications before deliberately waiting without a trap.
    for(unsigned i=0;i<8;++i) {auto event=db.waitForEvent(0);if(!event)break;(void)db.continueAfterEvent(static_cast<pid_t>(event->threadId));}
    auto waiter=std::async(std::launch::async,[&]{return cb.waitForDebugEvent(pb->serverHandle(),2000);});
    std::this_thread::sleep_for(40ms);
    os::CEServerClient fresh;fresh.setTimeoutMs(400);
    auto begin=Clock::now();bool freshConnected=fresh.connectTcp("127.0.0.1",port,error);auto version=fresh.getVersion();
    check(freshConnected && version && Clock::now()-begin<800ms && waiter.wait_for(0ms)==std::future_status::timeout,
        "a new client makes progress while another client waits for a debug event");
    int partial=connectRaw(port);if(partial>=0){uint8_t op=3;transfer(partial,&op,1,true);}
    begin=Clock::now();server.stop();
    auto waited=waiter.get();
    check(Clock::now()-begin<800ms && !waited && !server.running() && !server.port(),
        "server shutdown wakes debug-event waiters, idle clients and partial commands together");
    check(!lb.targetDescription().tracerPid && lb.targetDescription().live,
        "multi-client shutdown releases the remaining real debug target without killing it");
    if(partial>=0)close(partial);
    fresh.close();cb.close();pa.reset();pb.reset();
    check(a.finish() && b.finish(),"both original 32/64-bit target applications exit normally after isolated debugging and shutdown");
}
static void lifecycle() {
    printf("CESERVER_MULTICLIENT_LIFECYCLE\n");
    os::CeserverServer server;bool starts=true,stops=true,restarts=true;
    for(unsigned iteration=0;iteration<8;++iteration) {
        std::barrier ready(3);std::array<uint16_t,2> ports{};
        std::thread a([&]{ready.arrive_and_wait();ports[0]=server.start(0);});
        std::thread b([&]{ready.arrive_and_wait();ports[1]=server.start(0);});
        ready.arrive_and_wait();a.join();b.join();
        starts=starts && (bool(ports[0])!=bool(ports[1])) && server.port()==(ports[0] ? ports[0] : ports[1]);
        int idle=connectRaw(server.port()),partial=connectRaw(server.port());
        if(partial>=0){uint8_t op=3;transfer(partial,&op,1,true);}
        std::array<std::thread,4> workers;std::array<bool,4> stopped{};
        std::barrier closing(5);auto begin=Clock::now();
        for(unsigned i=0;i<4;++i)workers[i]=std::thread([&,i]{closing.arrive_and_wait();server.stop();stopped[i]=!server.running() && !server.port();});
        closing.arrive_and_wait();for(auto& worker:workers)worker.join();
        stops=stops && Clock::now()-begin<800ms;
        for(bool stoppedState:stopped)stops=stops && stoppedState;
        if(idle>=0)close(idle);
        if(partial>=0)close(partial);
        auto port=server.start(0);os::CEServerClient client;client.setTimeoutMs(400);std::string error;
        restarts=restarts && port && client.connectTcp("127.0.0.1",port,error) && bool(client.getVersion());
        client.close();server.stop();
    }
    check(starts,"concurrent start callers create exactly one listener and one accept owner");
    check(stops,"concurrent stop callers all return after the same complete worker shutdown");
    check(restarts,"eight concurrent lifecycle cycles leave the server restartable and responsive");
}
static void descriptorPressure() {
    printf("CESERVER_MULTICLIENT_DESCRIPTOR_PRESSURE\n");
    os::CeserverServer server;auto port=server.start(0);
    os::CEServerClient client;client.setTimeoutMs(400);std::string error;
    bool ready=port && client.connectTcp("127.0.0.1",port,error) && bool(client.getVersion());
    // This process owns the server, clients and limits. No host-wide setting is
    // changed, and the original limit is restored before any other test runs.
    int pending=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);
    rlimit original{},limited{};
    bool bounded=getrlimit(RLIMIT_NOFILE,&original)==0;
    limited=original;limited.rlim_cur=std::min<rlim_t>(original.rlim_cur,256);
    bounded=bounded && setrlimit(RLIMIT_NOFILE,&limited)==0;
    std::vector<int> fillers;
    int exhausted=0;
    if(bounded) {
        for(;;) {int fd=open("/dev/null",O_RDONLY|O_CLOEXEC);if(fd<0){exhausted=errno;break;}fillers.push_back(fd);}
    }
    sockaddr_in address{};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);address.sin_port=htons(port);
    bool queued=pending>=0 && connect(pending,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0;
    timeval timeout{1,0};if(pending>=0)setsockopt(pending,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    std::this_thread::sleep_for(150ms);
    auto response=client.getVersion();
    check(ready && bounded && exhausted==EMFILE && queued && response && server.running(),
        "actual descriptor exhaustion leaves established clients responsive and the accept owner alive");
    if(!fillers.empty()){close(fillers.back());fillers.pop_back();}
    check(pending>=0 && rawVersion(pending),"the queued connection completes after one descriptor becomes available");
    for(int fd:fillers)close(fd);
    bool restored=!bounded || setrlimit(RLIMIT_NOFILE,&original)==0;
    auto begin=Clock::now();server.stop();client.close();if(pending>=0)close(pending);
    check(restored && Clock::now()-begin<800ms && !server.running() && !server.port(),
        "descriptor-pressure recovery restores process limits and preserves complete shutdown");
}
int main(int argc,char** argv) {
    alarm(40);signal(SIGPIPE,SIG_IGN);
    blockedPeer(0);blockedPeer(1);
    if(argc==3){live(argv[1],argv[2]);lifecycle();descriptorPressure();}
    else if(argc!=2 || std::string(argv[1])!="--blocking-only")return 2;
    printf("CESERVER_MULTICLIENT_RESULT=%s checks=%u failures=%u\n",failures ? "FAILED":"PASSED",checks,failures);
    return failures ? 1:0;
}
