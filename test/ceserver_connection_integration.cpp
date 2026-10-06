#include "platform/linux/ceserver_client.hpp"
#ifndef CE_CESERVER_TRANSPORT_ONLY
#include "platform/linux/ceserver_process.hpp"
#include "platform/linux/ceserver_debugger.hpp"
#include "platform/linux/linux_process.hpp"
#include "scripting/lua_engine.hpp"
#endif
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <future>
#include <thread>
#include <vector>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
using namespace ce;
using namespace std::chrono_literals;
using Clock=std::chrono::steady_clock;
static unsigned checks,failures;
static void check(bool ok,const char* name) {
    ++checks;failures+=!ok;printf("%s: %s\n",ok ? "OK" : "FAILED",name);fflush(stdout);
}
static bool transfer(int fd,void* buffer,size_t size,bool sending=false) {
    auto* p=static_cast<char*>(buffer);
    while (size) {
        auto n=sending ? send(fd,p,size,MSG_NOSIGNAL) : recv(fd,p,size,0);
        if (n<0 && errno==EINTR) continue;
        if (n<=0) return false;
        size-=n;p+=n;
    }
    return true;
}
class Peer {
    int listener_=-1;
    std::thread thread_;
public:
    uint16_t port=0;
    Peer(std::function<void(int,unsigned)> serve,unsigned connections=1) {
        listener_=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);
        sockaddr_in address{};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        if (listener_<0 || bind(listener_,reinterpret_cast<sockaddr*>(&address),sizeof(address)) || listen(listener_,4)) return;
        socklen_t size=sizeof(address);
        if (getsockname(listener_,reinterpret_cast<sockaddr*>(&address),&size)) return;
        port=ntohs(address.sin_port);
        thread_=std::thread([this,serve,connections] {
            for (unsigned i=0;i<connections;++i) {
                pollfd p{listener_,POLLIN,0};if (poll(&p,1,1000)<=0) break;
                int fd=accept4(listener_,nullptr,nullptr,SOCK_CLOEXEC);if (fd<0) break;
                timeval timeout{1,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
                serve(fd,i);shutdown(fd,SHUT_RDWR);close(fd);
            }
        });
    }
    void join() { if (thread_.joinable()) thread_.join(); }
    ~Peer() { if (listener_>=0) shutdown(listener_,SHUT_RDWR);join();if (listener_>=0) close(listener_); }
};
static void timeout(os::CEServerClient& client,int ms) {
#ifndef CE_CESERVER_BASELINE
    if (!client.setTimeoutMs(ms)) { check(false,"the configured transport budget is accepted"); }
#else
    (void)client;(void)ms;
#endif
}
static bool version(int fd,const char* text) {
    int32_t protocol=1;uint8_t size=static_cast<uint8_t>(strlen(text));
    return transfer(fd,&protocol,4,true) && transfer(fd,&size,1,true) && transfer(fd,const_cast<char*>(text),size,true);
}
static void deadline(unsigned mode) {
    std::atomic<bool> received=false;
    Peer peer([&](int fd,unsigned) {
        if (mode==3) { int small=4096;setsockopt(fd,SOL_SOCKET,SO_RCVBUF,&small,sizeof(small)); }
        const size_t sizes[]={1,1,18,17,9};char request[18];
        received=transfer(fd,request,sizes[mode]);if (!received) return;
        if (mode==1) {
            const uint8_t reply[]={1,0,0,0,4,'s','l','o','w'};
            for (auto byte:reply) { std::this_thread::sleep_for(40ms);if (!transfer(fd,&byte,1,true)) break; }
        } else if (mode==2) {
            int32_t size=4;uint8_t prefix[]={0xaa,0xbb};
            transfer(fd,&size,4,true);transfer(fd,prefix,2,true);std::this_thread::sleep_for(350ms);
        } else if (mode==4) {
            std::this_thread::sleep_for(120ms);int32_t empty=0;transfer(fd,&empty,4,true);
        } else std::this_thread::sleep_for(350ms);
    });
    os::CEServerClient client;timeout(client,100);std::string error;
    bool connected=peer.port && client.connectTcp("127.0.0.1",peer.port,error);
    bool rejected=false,validWait=false;std::string failure;
    std::vector<uint8_t> bytes(mode==3 ? 4*1024*1024 : 4,0xa5);
    auto begin=Clock::now();
    if (mode<2) { auto r=client.getVersion();rejected=!r;if (!r) failure=r.error(); }
    if (mode==2) { auto r=client.readProcessMemory(42,0,bytes.data(),4);rejected=!r;if (!r) failure=r.error(); }
    if (mode==3) { auto r=client.writeProcessMemory(42,0,bytes.data(),static_cast<int32_t>(bytes.size()));rejected=!r;if (!r) failure=r.error(); }
    if (mode==4) { auto r=client.waitForDebugEvent(42,150);validWait=r && !r->has_value(); }
    auto elapsed=Clock::now()-begin;
    printf("CESERVER_DEADLINE mode=%u elapsed_ms=%lld\n",mode,static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()));
    if (mode==4) {
        check(connected && validWait && elapsed>=100ms && client.isConnected(),
            "an explicitly requested debug wait extends the transport budget without disconnecting a valid peer");
    } else {
        check(connected && rejected && elapsed<220ms,"one whole-message deadline bounds stalled or fragmented socket I/O");
        check(failure.find("timed out")!=std::string::npos,"a transport timeout returns its actual deadline failure");
        check(!client.isConnected(),"an incomplete timed-out transaction cannot remain reusable");
        if (mode==2) check(bytes[0]==0xaa && bytes[1]==0xbb && bytes[2]==0xa5 && bytes[3]==0xa5,
            "a timed-out partial reply preserves its received prefix and untouched destination suffix");
    }
    client.close();peer.join();check(received,"the independent peer observes the complete original command header");
}
static void cancel() {
    std::promise<void> waiting;auto ready=waiting.get_future();
    Peer peer([&](int fd,unsigned) {
        char command;
        if (transfer(fd,&command,1)) waiting.set_value();
        std::this_thread::sleep_for(500ms);
    });
    os::CEServerClient client;timeout(client,2000);std::string error;
    client.connectTcp("127.0.0.1",peer.port,error);
    std::promise<bool> finished;auto done=finished.get_future();
    std::thread worker([&] { finished.set_value(!client.getVersion()); });
    bool entered=ready.wait_for(1s)==std::future_status::ready;
    auto begin=Clock::now();client.close();
    bool interrupted=done.wait_for(150ms)==std::future_status::ready;
    auto elapsed=Clock::now()-begin;
    worker.join();peer.join();
    check(entered && interrupted && elapsed<200ms,"close wakes active socket I/O before the request or peer timeout");
    check(done.get() && !client.isConnected(),"cancellation returns an error and retires the interrupted connection");
}
static void concurrent() {
    std::atomic<unsigned> commands=0;
    std::atomic<bool> frames=true,correct=true;
    Peer peer([&](int fd,unsigned) {
        while (commands<32) {
            uint8_t op=0,compress=0;int32_t handle=0;uint64_t address=0;uint32_t size=0;
            if (!transfer(fd,&op,1) || !transfer(fd,&handle,4) || !transfer(fd,&address,8) ||
                !transfer(fd,&size,4) || !transfer(fd,&compress,1)) break;
            if (op!=9 || handle!=42 || size!=8 || compress || address<1 || address>32) { frames=false;break; }
            int32_t length=8;uint64_t payload=0x100000000ull+address;
            if (!transfer(fd,&length,4,true) || !transfer(fd,&payload,8,true)) break;
            ++commands;
        }
    });
    os::CEServerClient client;timeout(client,1000);std::string error;
    bool connected=client.connectTcp("127.0.0.1",peer.port,error);
    std::vector<std::thread> workers;
    for (unsigned thread=0;thread<4;++thread) workers.emplace_back([&,thread] {
        for (unsigned i=0;i<8;++i) {
            uint64_t payload=0,address=thread*8+i+1;
            auto r=client.readProcessMemory(42,address,&payload,8);
            if (!r || *r!=8 || payload!=0x100000000ull+address) { correct=false;break; }
        }
    });
    for (auto& worker:workers) worker.join();
    client.close();peer.join();
    check(connected && frames && commands==32,"four simultaneous callers send 32 complete independent TCP command frames");
    check(correct,"concurrent callers receive their own address-specific response payloads");
}
#ifndef CE_CESERVER_TRANSPORT_ONLY
static void reconnect() {
    std::promise<void> waiting;auto ready=waiting.get_future();
    std::atomic<bool> extra=false;
    std::atomic<unsigned> freshCloses=0;
    Peer peer([&](int fd,unsigned connection) {
        uint8_t op;
        while (transfer(fd,&op,1)) {
            if (op==3 || op==21 || op==7) {
                int32_t value=0;if (!transfer(fd,&value,4)) break;
                if (op==21) { uint8_t arch=1;if (!transfer(fd,&arch,1,true)) break; }
                else { if (op==7 && connection) ++freshCloses;value=op==3 ? 42 : 1;if (!transfer(fd,&value,4,true)) break; }
            } else if (op==0 && !connection) {
                waiting.set_value();pollfd p{fd,POLLIN,0};
                while (poll(&p,1,500)>0) { char bytes[128];auto n=recv(fd,bytes,sizeof(bytes),0);if (n<=0) break;extra=true; }
                break;
            } else if (op==0) { if (!version(fd,"fresh")) break; }
            else { extra=true;break; }
        }
    },2);
    os::CEServerClient client;timeout(client,2000);std::string error;
    client.connectTcp("127.0.0.1",peer.port,error);
    auto owner=os::RemoteProcessHandle::open(client,getpid());
    if (!owner) { check(false,"the independent reconnect peer opens an original logical target");return; }
    os::RemoteDebugger contextOwner(client,owner->serverHandle());
    std::thread active([&] { (void)client.getVersion(); });
    bool entered=ready.wait_for(1s)==std::future_status::ready;
    std::atomic<unsigned> queued=0;bool rejected=false,arm64Rejected=false,arm32Rejected=false;
    std::thread borrower([&] { ++queued;uint32_t value=0;rejected=!owner->read(0,&value,4); });
    std::thread arm64([&] { ++queued;arm64Rejected=!contextOwner.getArm64Context(getpid()); });
    std::thread arm32([&] { ++queued;arm32Rejected=!contextOwner.getArm32Context(getpid()); });
    while (queued<3) std::this_thread::yield();
    std::this_thread::sleep_for(20ms);
    auto begin=Clock::now();bool connected=client.connectTcp("127.0.0.1",peer.port,error);
    auto elapsed=Clock::now()-begin;
    active.join();borrower.join();arm64.join();arm32.join();
    auto fresh=client.getVersion();owner.reset();auto after=client.getVersion();
    client.close();peer.join();
    check(entered && connected && elapsed<200ms,"reconnect cancels the old active transaction before replacing its socket");
    check(rejected && arm64Rejected && arm32Rejected && !extra,
        "queued process and ARM context owners revalidate generation under the transaction lock before dispatch");
    check(fresh && fresh->versionString=="fresh" && after && after->versionString=="fresh" && !freshCloses,
        "late completion and destruction of old owners cannot retire or consume the replacement stream");
}
static void lua() {
    LuaEngine engine;engine.setOwnedProcess(std::make_unique<os::LinuxProcessHandle>(getpid()));
    auto* previous=engine.process();
    Peer stalled([](int fd,unsigned) { char header[5];if (transfer(fd,header,5)) std::this_thread::sleep_for(350ms); });
    auto begin=Clock::now();
    auto error=engine.execute("local p,e=connectToCeserver('127.0.0.1',"+std::to_string(stalled.port)+","+std::to_string(getpid())+",100);assert(p==nil and type(e)=='string')");
    auto elapsed=Clock::now()-begin;
    stalled.join();
    check(error.empty() && elapsed<220ms,"production Lua connectToCeserver honors its optional millisecond transport budget");
    check(engine.process()==previous,"a timed-out Lua connection preserves its original opened process");
    std::atomic<unsigned> accepted=0;
    Peer invalid([&](int fd,unsigned) {
        ++accepted;uint8_t op;
        while (transfer(fd,&op,1)) {
            int32_t value=0;if (!transfer(fd,&value,4)) break;
            if (op==21) { uint8_t arch=1;transfer(fd,&arch,1,true); }
            else { value=op==3 ? 42 : 1;transfer(fd,&value,4,true); }
        }
    },3);
    auto call=[&](uint64_t port,uint64_t pid,int ms,const char* field) {
        auto script="local p,e=connectToCeserver('127.0.0.1',"+std::to_string(port)+","+std::to_string(pid)+","+std::to_string(ms)+");assert(p==nil and e:find('"+field+"'))";
        return engine.execute(script).empty();
    };
    bool bounds=call(uint64_t(invalid.port)+65536,getpid(),100,"port") &&
        call(invalid.port,uint64_t(getpid())+0x100000000ull,100,"pid") && call(invalid.port,getpid(),0,"timeout");
    // No command is needed to stop this peer when validation happens before connect.
    check(bounds && engine.process()==previous,"Lua validates port, PID and timeout without truncation or replacing its old target");
    invalid.join();check(!accepted,"invalid Lua wire arguments never connect or dispatch to a peer");
}
#endif
int main() {
    alarm(30);signal(SIGPIPE,SIG_IGN);
    for (unsigned mode=0;mode<5;++mode) deadline(mode);
    cancel();concurrent();
#ifndef CE_CESERVER_TRANSPORT_ONLY
    reconnect();lua();
#endif
    printf("CESERVER_CONNECTION_RESULT=%s checks=%u failures=%u\n",failures ? "FAILED" : "PASSED",checks,failures);
    return failures ? 1 : 0;
}
