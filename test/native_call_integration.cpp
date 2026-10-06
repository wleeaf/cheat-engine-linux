#include "platform/linux/linux_process.hpp"
#include "platform/linux/injector.hpp"
#include "platform/linux/syscall_service.hpp"
#include "core/ns_attach.hpp"
#ifndef CECORE_NATIVE_CALL_EMBEDDED
#include "scripting/lua_engine.hpp"
#include "core/autoasm.hpp"
#endif
#include <array>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <poll.h>
#include <signal.h>
#include <sstream>
#include <string_view>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#ifdef CECORE_VM_X32
#include <sys/mman.h>
#endif

using namespace ce;
namespace {
int failures;
void check(bool value,const char* message) {
    printf("%s: %s\n",value ? "OK" : "FAILED",message);
    fflush(stdout);
    failures+=!value;
}
struct Fixture {
    pid_t pid=-1;
    int input=-1,output=-1;
    explicit Fixture(const char* path,const char* mode=nullptr) {
        int in[2],out[2];
        if (pipe(in)) return;
        if (pipe(out)) { close(in[0]); close(in[1]); return; }
        pid=fork();
        if (!pid) {
            dup2(in[0],0); dup2(out[1],1);
            close(in[0]); close(in[1]); close(out[0]); close(out[1]);
            if (mode) execl(path,path,mode,nullptr);
            else execl(path,path,nullptr);
            _exit(127);
        }
        close(in[0]); close(out[1]); input=in[1]; output=out[0];
    }
    std::string line() {
        std::string result;
        while (result.size()<4096) {
            pollfd fd{output,POLLIN,0};
            if (poll(&fd,1,5000)<=0) break;
            char c;
            if (read(output,&c,1)!=1) break;
            if (c=='\n') return result;
            result+=c;
        }
        return {};
    }
    ~Fixture() {
        if (pid>0) { kill(pid,SIGKILL); while (waitpid(pid,nullptr,0)<0 && errno==EINTR) {} }
        if (input>=0) close(input);
        if (output>=0) close(output);
    }
};
unsigned value(ProcessHandle& p,uintptr_t address) {
    unsigned result=0;
    auto read=p.read(address,&result,sizeof(result));
    return read && *read==sizeof(result) ? result : UINT32_MAX;
}
bool waitValue(ProcessHandle& p,uintptr_t address,unsigned expected) {
    auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
    while (std::chrono::steady_clock::now()<deadline) {
        if (value(p,address)==expected) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return false;
}
bool waitThreadGone(ProcessHandle& p,pid_t tid) {
    auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
    while (std::chrono::steady_clock::now()<deadline) {
        auto threads=p.threads();
        if (std::none_of(threads.begin(),threads.end(),[&](const auto& t){return t.tid==tid;})) return true;
        (void)p.retryPendingOperations();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return false;
}

void leaderExitCalls(const char* path,const char* libraryPath) {
    const int initial=failures;
    Fixture fixture(path,"--leader-exit");
    unsigned width=0; std::string magic; uintptr_t loaded=0,completed=0,running=0,release=0,heartbeat=0,entry=0;
    std::istringstream ready(fixture.line());
    ready>>magic>>width>>std::hex>>loaded>>completed>>running>>release>>heartbeat>>entry;
    bool zombie=false;
    auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
    while (!zombie && std::chrono::steady_clock::now()<deadline) {
        std::ifstream stat("/proc/"+std::to_string(fixture.pid)+"/stat"); std::string line;
        if (std::getline(stat,line)) {
            auto end=line.rfind(')'); zombie=end!=std::string::npos && line.substr(end+1).starts_with(" Z ");
        }
        if (!zombie) usleep(1000);
    }
    check(ready && magic=="CE_NATIVE_CALL" && zombie,
          "actual glibc pthread_exit retires main while console and CPU-loop siblings survive");
    os::LinuxProcessHandle process(fixture.pid);
    const auto description=process.targetDescription();
    check(description.live && description.program.pointerWidth==width && value(process,heartbeat)!=UINT32_MAX,
          "a newly opened handle reads the real ABI and memory of a leaderless glibc process");
    SymbolResolver resolver; resolver.loadProcess(process);
    check(resolver.lookup("ce_call_entry")==entry && resolver.lookup("dlopen"),
          "leaderless process symbol loading follows live module and filesystem metadata");
    auto injected=os::injectLibrary(process,resolver,std::filesystem::absolute(libraryPath).string());
    if (!injected) printf("leaderless library error: %s\n",injected.error().c_str());
    check(injected && *injected && value(process,loaded)==1,
          "native library constructors execute in a real glibc process after main pthread_exit");
    auto thread=os::createRemoteThread(process,resolver,entry,true,2000);
    if (!thread) printf("leaderless thread error: %s\n",thread.error().c_str());
    check(thread && thread->completed && value(process,completed)==1 && value(process,running)==0 &&
          waitThreadGone(process,thread->tid),
          "native pthread creation and actual worker-exit ownership remain usable after leader exit");
    auto storage=process.allocate(4096,MemProt::ReadWrite);
    unsigned word=42;
    bool memory=false;
    if (storage) {
        auto written=process.write(*storage,&word,sizeof(word));
        auto protection=process.protect(*storage,4096,MemProt::Read);
        auto denied=process.write(*storage,&word,sizeof(word));
        auto freed=process.free(*storage,4096);
        memory=written && protection && !denied && freed && !process.read(*storage,&word,sizeof(word));
    }
    check(memory,"leaderless glibc memory operations preserve protection and release the actual mapping");
    const auto before=value(process,heartbeat); usleep(1000);
    check(before!=UINT32_MAX && value(process,heartbeat)!=before && !process.targetDescription().pendingRecovery,
          "surviving glibc siblings continue CPU work without residual native recovery");
    const char quit='x'; const bool sent=write(fixture.input,&quit,1)==1;
    const auto done=fixture.line(); int status=0; pid_t waited;
    do { waited=waitpid(fixture.pid,&status,0); } while (waited<0 && errno==EINTR);
    check(sent && done=="CE_NATIVE_CALL_DONE" && waited==fixture.pid && WIFEXITED(status) &&
          WEXITSTATUS(status)==0 && !process.targetDescription().live,
          "the last glibc siblings finish console work and retire the original process identity");
    fixture.pid=-1;
    printf("LEADER_NATIVE_CALL_RESULT=%s width=%u\n",failures==initial ? "PASSED" : "FAILED",width);
}
}
int nativeCallIntegration(int argc,char** argv) {
    signal(SIGPIPE,SIG_IGN);
#ifndef CECORE_NATIVE_CALL_EMBEDDED
    if (argc==5 && std::string_view(argv[1])=="--namespace-deleted-probe") {
        os::LinuxProcessHandle process(static_cast<pid_t>(std::stol(argv[2])));
        std::string rawPath=argv[3];
        auto resolved=ce::resolveProcPath(process.pid(),rawPath);
        check(std::filesystem::exists(rawPath) && !std::filesystem::exists(resolved) && resolved!=rawPath,
              "a deleted target module never selects a colliding host file");
        auto modules=process.modules();
        auto module=std::find_if(modules.begin(),modules.end(),[&](const auto& m) {
            return m.name==std::filesystem::path(rawPath).filename().string();
        });
        check(module!=modules.end() && module->path==resolved && module->machine.architecture==CpuArchitecture::Unknown,
              "unavailable module backing files preserve unknown ISA metadata");
        SymbolResolver resolver; resolver.loadProcess(process);
        check(!resolver.lookup("ce_namespace_marker") && !resolver.lookup("ce_namespace_entry"),
              "unavailable target symbols do not fall back to another host binary");
        check(value(process,std::stoull(argv[4]))==0x54415248u,
              "the target's mapped library data remains readable after its backing file is deleted");
        printf("DELETED_MODULE_NAMESPACE_RESULT=%s pid=%ld\n",failures ? "FAILED" : "PASSED",static_cast<long>(process.pid()));
        return failures ? 1 : 0;
    }
    if (argc==4 && std::string_view(argv[1])=="--namespace-symbol-probe") {
        os::LinuxProcessHandle process(static_cast<pid_t>(std::stol(argv[2])));
        std::string rawPath=argv[3];
        auto resolved=ce::resolveProcPath(process.pid(),rawPath);
        std::error_code error;
        check(std::filesystem::exists(rawPath) && std::filesystem::exists(resolved) &&
              !std::filesystem::equivalent(rawPath,resolved,error) && !error,
              "colliding host and target module paths select different backing files");
        check(ce::resolveProcPath(process.pid(),resolved)==resolved,
              "a resolved target-root module path can be reused without double-prefixing");
        auto modules=process.modules();
        auto module=std::find_if(modules.begin(),modules.end(),[&](const auto& m) {
            return m.name==std::filesystem::path(rawPath).filename().string();
        });
        auto machine=process.targetDescription().host;
        check(module!=modules.end() && module->path==resolved && module->machine.architecture==machine.architecture &&
              module->machine.abi==machine.abi && module->machine.pointerWidth==machine.pointerWidth,
              "a colliding host ELF does not change the target module ISA or ABI");
        SymbolResolver resolver; resolver.loadProcess(process);
        auto marker=resolver.lookup("ce_namespace_marker");
        auto entry=resolver.lookup("ce_namespace_entry");
        check(marker && entry && value(process,marker)==0x54415247u,
              "symbols resolve to the actual target module and its initialized data");
        if (!failures) {
            auto thread=os::createRemoteThread(process,resolver,entry,true,2000);
            if (!thread) printf("namespace symbol call error: %s\n",thread.error().c_str());
            check(thread && thread->completed && value(process,marker)==0x54415248u,
                  "the target library entry executes using its own native calling convention");
        }
        printf("NATIVE_MODULE_NAMESPACE_RESULT=%s pid=%ld\n",failures ? "FAILED" : "PASSED",static_cast<long>(process.pid()));
        printf("NATIVE_NAMESPACE_MARKER=%llu\n",static_cast<unsigned long long>(marker));
        return failures ? 1 : 0;
    }
    if (argc==4 && (std::string_view(argv[1])=="--shutdown-probe" ||
                    std::string_view(argv[1])=="--namespace-probe")) {
        bool namespaceProbe=std::string_view(argv[1])=="--namespace-probe";
        os::LinuxProcessHandle process(static_cast<pid_t>(std::stol(argv[2])));
        SymbolResolver resolver; resolver.loadProcess(process);
        auto thread=os::createRemoteThread(process,resolver,std::stoull(argv[3]),namespaceProbe,2000);
        bool passed=thread && thread->tid>0 && thread->completed==namespaceProbe;
        if (namespaceProbe) {
            if (!thread) printf("namespace thread error: %s\n",thread.error().c_str());
            printf("NATIVE_THREAD_NAMESPACE_RESULT=%s pid=%ld tid=%ld\n",passed ? "PASSED" : "FAILED",
                   static_cast<long>(process.pid()),thread ? static_cast<long>(thread->tid) : 0L);
        }
        return passed ? 0 : 1;
    }
#endif
    if (argc!=3) return 2;
    Fixture fixture(argv[1]);
    std::istringstream ready(fixture.line());
    std::string magic;
    unsigned width=0;
    uintptr_t loaded=0,completed=0,running=0,release=0,heartbeat=0,entry=0,selfDetach=0,selfExit=0;
    ready>>magic>>width>>std::hex>>loaded>>completed>>running>>release>>heartbeat>>entry>>selfDetach>>selfExit;
    check(ready && magic=="CE_NATIVE_CALL" && (width==4 || width==8),"real dynamic libc/pthread fixture starts");
    if (!ready || !entry) return 1;
    os::LinuxProcessHandle process(fixture.pid);
    SymbolResolver resolver;
    resolver.loadProcess(process);
    check(process.targetDescription().host.pointerWidth==width,"live native call ABI matches the real process");
#ifdef CECORE_VM_X32
    int wideFailures=failures;
    const auto host=process.targetDescription().host;
    check(host.architecture==CpuArchitecture::X86_64 && host.abi==TargetAbi::LinuxX32 &&
          host.instructionMode==InstructionMode::X86_64 && width==4,
          "real x32 process has 64-bit instructions and four-byte pointers");
    os::NativeCallRequest wide;
    wide.function=resolver.lookup("ce_call_sum64");
    wide.arguments={0x1122334455667788ull,0x8877665544332211ull,0x0123456789abcdefull,
                    0xfedcba9876543210ull,0x2468ace013579bdfull,0x13579bdf2468ace0ull,
                    0xa1b2c3d4e5f60718ull,0x1928374655aabbccull};
    uint64_t expected=0;
    constexpr std::array<uint64_t,8> weights{1,3,5,7,11,13,17,19};
    for (size_t i=0;i<weights.size();++i) expected+=weights[i]*wide.arguments[i];
    auto callIdentity=os::processMemoryIdentity(fixture.pid);
    check(wide.function && callIdentity,"x32 resolves the real exported 64-bit scalar callback");
    auto wideCall=callIdentity ? os::memorySyscallService().invoke(*callIdentity,host,std::move(wide)) :
        std::expected<os::NativeCallResult,std::error_code>{std::unexpected(std::make_error_code(std::errc::no_such_process))};
    if (!wideCall) printf("X32_WIDE_CALL_DIAGNOSTIC error=%s\n",wideCall.error().message().c_str());
    check(wideCall && wideCall->value==expected && expected>UINT32_MAX,
          "x32 preserves all eight 64-bit scalar arguments and its full 64-bit result");
    check(!process.targetDescription().pendingRecovery && value(process,completed)==0,
          "x32 wide scalar call restores the application and releases its owner");
    const auto fileFd=resolver.lookup("ce_call_file_fd");
    const auto descriptor=fileFd ? value(process,fileFd) : UINT32_MAX;
    check(fileFd && descriptor!=UINT32_MAX,"x32 fixture opens a sparse file with data beyond four GiB");
    auto mapped=callIdentity ? os::memorySyscallService().execute(*callIdentity,host,os::MemorySyscall::Map,
        {0,4096,PROT_READ,MAP_PRIVATE,descriptor,UINT64_C(0x100002000)}) :
        std::expected<uint64_t,std::error_code>{std::unexpected(std::make_error_code(std::errc::no_such_process))};
    uint64_t observed=0;
    auto read=mapped ? process.read(*mapped,&observed,sizeof(observed)) :
        Result<size_t>{std::unexpected(std::make_error_code(std::errc::bad_address))};
    if (!mapped) printf("X32_MMAP_DIAGNOSTIC error=%s\n",mapped.error().message().c_str());
    check(mapped && *mapped<=UINT32_MAX && read && *read==sizeof(observed) && observed==UINT64_C(0x7461726765747832),
          "x32 mmap preserves its 64-bit file offset and returns a four-byte address");
    auto unmapped=mapped ? process.free(*mapped,4096) :
        Result<void>{std::unexpected(std::make_error_code(std::errc::bad_address))};
    check(unmapped && !process.targetDescription().pendingRecovery,
          "x32 file-backed mapping is released without retaining syscall recovery");
    printf("X32_WIDE_CALL_RESULT=%s width=%u\n",failures==wideFailures ? "PASSED" : "FAILED",width);
#endif
    auto library=std::filesystem::absolute(argv[2]);
    // A deliberately different basename exposes maps-substring validation bugs.
    auto link=library.parent_path()/("native-call-alias-"+std::to_string(getpid())+".so");
    std::error_code error;
    std::filesystem::create_symlink(library,link,error);
    check(!error,"library symlink with a different basename is created");
    if (!error) {
        auto injected=os::injectLibrary(process,resolver,link.string());
        if (!injected) printf("injection error: %s\n",injected.error().c_str());
        check(injected && value(process,loaded)==1,"dlopen through a symlink runs the real target constructor");
        auto repeated=os::injectLibrary(process,resolver,library.string());
        check(injected && repeated && *injected==*repeated && value(process,loaded)==1,
              "an already loaded library returns its native handle without rerunning its constructor");
        std::filesystem::remove(link,error);
    }
    std::string embedded=library.string(); embedded.push_back(0); embedded+="ignored";
    auto invalid=os::injectLibrary(process,resolver,embedded);
    check(!invalid && value(process,loaded)==1,"embedded NUL library paths are rejected before target execution");
    auto badEntry=os::createRemoteThread(process,resolver,release,true,10);
    check(!badEntry && value(process,completed)==0,"non-executable thread entries are rejected before pthread_create");
    auto thread=os::createRemoteThread(process,resolver,entry,true,2000);
    if (!thread) printf("thread error: %s\n",thread.error().c_str());
    check(thread && thread->completed && value(process,completed)==1 && value(process,running)==0,
          "a real native pthread executes, returns, and exits before completion is reported");
    unsigned zero=0,one=1;
    auto wrote=process.write(release,&zero,sizeof(zero));
    auto before=value(process,heartbeat);
    auto start=std::chrono::steady_clock::now();
    auto storage=process.allocate(4096,MemProt::ReadWrite);
    check(bool(storage),"owned thread data is allocated for lifetime checks");
    if (!storage) return 1;
    std::array<os::NativeThreadRange,1> retained{{{*storage,4096}}};
    auto delayed=[&] {
        os::LinuxProcessHandle temporary(fixture.pid);
        return os::createRemoteThread(temporary,resolver,entry,true,20,retained);
    }();
    auto elapsed=std::chrono::steady_clock::now()-start;
    if (!delayed) printf("timeout thread error: %s\n",delayed.error().c_str());
    check(wrote && delayed && !delayed->completed && elapsed<std::chrono::seconds(2) && value(process,running)==1,
          "a waiting pthread reaches the deadline and is detached without an unbounded join");
    auto liveThreads=process.threads();
    check(delayed && delayed->tid>0 && std::any_of(liveThreads.begin(),liveThreads.end(),[&](const auto& t){return t.tid==delayed->tid;}),
          "the remote pthread has an actual Linux thread identity");
    auto prematureFree=process.free(*storage,4096);
    auto prematureProtect=process.protect(*storage,4096,MemProt::None);
    check(!prematureFree && prematureFree.error()==std::errc::device_or_resource_busy &&
          !prematureProtect && prematureProtect.error()==std::errc::device_or_resource_busy,
          "destroying the creating frontend does not permit freeing or protecting live worker storage");
    check(value(process,heartbeat)!=before,"the target's main loop keeps running while its new pthread waits");
    wrote=process.write(release,&one,sizeof(one));
    check(wrote && waitValue(process,completed,2) && waitValue(process,running,0),
          "the timed-out detached pthread later returns normally using its still-mapped code and data");
    check(delayed && waitThreadGone(process,delayed->tid) && bool(process.free(*storage,4096)),
          "owned worker storage can be freed after actual kernel thread exit");
    auto detached=os::createRemoteThread(process,resolver,entry,false,2000);
    check(detached && !detached->completed && waitValue(process,completed,3),
          "a fire-and-forget pthread is detached and completes normally");
#ifndef CECORE_NATIVE_CALL_EMBEDDED
    LuaEngine lua;
    auto luaResult=lua.evalToString("assert(openProcess("+std::to_string(fixture.pid)+"))\n"
        "local handle,pathError=injectLibrary('/invalid'..string.char(0))\n"
        "assert(handle==nil and pathError:find('invalid shared library path'))\n"
        "local ok,err=executeCode("+std::to_string(entry)+",4294967296)\n"
        "assert(ok==nil and err:find('timeout'))\n"
        "assert(readInteger("+std::to_string(completed)+")==3)\n"
        "assert(executeCode("+std::to_string(entry)+",2000))\n"
        "assert(readInteger("+std::to_string(completed)+")==4)\n"
        "assert(writeInteger("+std::to_string(release)+",0))\n"
        "local timed,timeoutError=executeCode("+std::to_string(entry)+",0)\n"
        "assert(timed==nil and timeoutError:find('timed out'))\n"
        "assert(readInteger("+std::to_string(completed)+")==4)\n"
        "assert(writeInteger("+std::to_string(release)+",1))\n"
        "return 'native-call-ok'\n");
    if (!luaResult) printf("Lua error: %s\n",luaResult.error().c_str());
    check(luaResult && *luaResult=="native-call-ok" && waitValue(process,completed,5) && waitValue(process,running,0),
          "Lua validates paths/timeouts, completes native calls, and reports an actual running-thread timeout");
#endif
    auto count=value(process,completed);
    auto selfDetached=os::createRemoteThread(process,resolver,selfDetach,true,2000);
    check(selfDetached && selfDetached->completed && value(process,completed)==count+1,
          "a worker that calls pthread_detach on itself still completes by kernel thread identity");
    auto exited=os::createRemoteThread(process,resolver,selfExit,true,2000);
    check(exited && exited->completed && value(process,completed)==count+2,
          "pthread_exit without returning through the wrapper releases ownership after kernel exit");
    auto delayedCreate=resolver.lookup("ce_call_create_delayed");
    auto identity=os::targetProcessIdentity(process.pid());
    auto lateStorage=process.allocate(4096,MemProt::ReadWrite);
    check(delayedCreate && identity && lateStorage,"late pthread creation has a real target callback and owned storage");
    if (delayedCreate && identity && lateStorage) {
        count=value(process,completed);
        wrote=process.write(release,&zero,sizeof(zero));
        os::NativeCallRequest late;
        late.function=delayedCreate; late.workerEntry=entry; late.outputSize=width;
        late.dataArguments=1; late.timeoutMs=20; late.forwardSignals=true;
        late.orphanDetach=resolver.lookup("pthread_detach");
        late.workerRanges.push_back({*lateStorage,4096});
        auto abandoned=os::memorySyscallService().invoke(*identity,process.targetDescription().host,std::move(late));
        auto cannotFree=process.free(*lateStorage,4096);
        check(wrote && !abandoned && abandoned.error()==std::errc::timed_out && !cannotFree &&
              bool(process.queryRegion(*lateStorage)) && process.targetDescription().pendingRecovery,
              "timed-out pthread creation retains ownership and storage before returning its handle");
        wrote=process.write(release,&one,sizeof(one));
        auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
        while (std::chrono::steady_clock::now()<deadline) {
            (void)process.retryPendingOperations();
            if (!process.targetDescription().pendingRecovery && process.threads().size()==2) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        check(wrote && !process.targetDescription().pendingRecovery && process.threads().size()==2 &&
              value(process,completed)==count && bool(process.free(*lateStorage,4096)),
              "an abandoned late-created worker is cancelled before entering user code and releases its storage");
    }
#ifndef CECORE_NATIVE_CALL_EMBEDDED
    wrote=process.write(release,&zero,sizeof(zero));
    count=value(process,completed);
    auto pidText=std::to_string(process.pid()),entryText=std::to_string(entry);
    auto probe=fork();
    if (!probe) {
        execl("/proc/self/exe","native_call_integration","--shutdown-probe",pidText.c_str(),entryText.c_str(),nullptr);
        _exit(127);
    }
    auto shutdownDeadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
    int status=0;
    pid_t waited=0;
    while (probe>0 && std::chrono::steady_clock::now()<shutdownDeadline) {
        waited=waitpid(probe,&status,WNOHANG);
        if (waited==probe) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    bool shutdownSucceeded=wrote && waited==probe && WIFEXITED(status) && WEXITSTATUS(status)==0 &&
                           value(process,running)==1;
    if (probe>0 && waited!=probe) { kill(probe,SIGKILL); while(waitpid(probe,nullptr,0)<0 && errno==EINTR) {} }
    check(shutdownSucceeded,"engine process exit does not wait for a detached running target worker");
    wrote=process.write(release,&one,sizeof(one));
    auto exitDeadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
    while (process.threads().size()>2 && std::chrono::steady_clock::now()<exitDeadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    check(wrote && waitValue(process,completed,count+1) && process.threads().size()==2,
          "a detached worker returns normally after its engine process has exited");
#endif
    printf("NATIVE_THREAD_LIFETIME_RESULT=%s width=%u\n",failures ? "FAILED" : "PASSED",width);
#ifndef CECORE_NATIVE_CALL_EMBEDDED
    auto aaFailures=failures;
    for (unsigned mode=0;mode<3;++mode) {
        AutoAssembler assembler;
        wrote=process.write(release,&zero,sizeof(zero));
        std::ostringstream source;
        source<<"alloc(worker,$1000)\nworker:\nmov "<<(width==4 ? "eax" : "rax")<<",0x"<<std::hex<<release
              <<"\nbusy:\ncmp dword ptr ["<<(width==4 ? "eax" : "rax")<<"],0\nje busy\nxor eax,eax\nret\n";
        if (mode==0) source<<"createthreadandwait(worker,10)\n";
        else source<<"createthread(worker)\n";
        if (mode==2) source<<"createthread(0x1)\n";
        auto script=source.str();
        auto enabled=assembler.execute(process,script);
        bool expectedOutcome=mode==1 ? enabled.success : !enabled.success;
        check(wrote && expectedOutcome && !enabled.disableInfo.allocs.empty(),
              mode==0 ? "timed-out AA execution retains its running code cave for retry" :
              mode==1 ? "asynchronous AA execution retains its worker allocation" :
                        "failure to create a second AA thread retains the first worker's code");
        if (!expectedOutcome || enabled.disableInfo.allocs.empty()) {
            printf("AA lifetime error: %s\n",enabled.error.c_str());
            (void)process.write(release,&one,sizeof(one));
            continue;
        }
        auto allocation=enabled.disableInfo.allocs.front();
        auto disabled=assembler.disable(process,script,enabled.disableInfo);
        check(!disabled.success && disabled.error.find("still running")!=std::string::npos &&
              !disabled.disableInfo.allocs.empty() && bool(process.queryRegion(allocation.address)),
              "AA disable refuses to restore or unmap code while its detached worker is alive");
        wrote=process.write(release,&one,sizeof(one));
        auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
        while (process.threads().size()>2 && std::chrono::steady_clock::now()<deadline) {
            (void)process.retryPendingOperations();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        auto retried=assembler.disable(process,script,enabled.disableInfo);
        check(wrote && retried.success && !process.queryRegion(allocation.address),
              "retrying AA cleanup after actual worker exit frees the retained code cave");
    }
    printf("AUTOASM_THREAD_LIFETIME_RESULT=%s width=%u\n",failures==aaFailures ? "PASSED" : "FAILED",width);
#endif
    char command='x';
    check(write(fixture.input,&command,1)==1 && fixture.line()=="CE_NATIVE_CALL_DONE",
          "the original application and blocked-read sibling finish normally after injection");
    leaderExitCalls(argv[1],argv[2]);
    int parkedFailures=failures;
    Fixture parked(argv[1],"--parked");
    std::istringstream parkedReady(parked.line());
    parkedReady>>magic>>width>>std::hex>>loaded>>completed>>running>>release>>heartbeat>>entry;
    if (parkedReady && magic=="CE_NATIVE_CALL") {
        os::LinuxProcessHandle parkedProcess(parked.pid);
        SymbolResolver parkedResolver;
        parkedResolver.loadProcess(parkedProcess);
        // Symbol loading can outlast a short timer under full-system emulation.
        // Finish it before letting the fixture enter the timed wait being tested.
        auto startParked=std::chrono::steady_clock::now();
        char begin='p';
        bool started=write(parked.input,&begin,1)==1 && parked.line()=="CE_NATIVE_CALL_PARKED_WAIT";
        check(started,"a real native process starts its relative timed kernel wait");
        if (started) {
        // Wait until the published main thread has actually entered the kernel.
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        auto rejected=os::createRemoteThread(parkedProcess,parkedResolver,entry,true,20);
        auto loadedRejected=os::injectLibrary(parkedProcess,parkedResolver,library.string());
        bool pending=parkedProcess.targetDescription().pendingRecovery;
        unsigned completedValue=value(parkedProcess,completed);
        bool safe=!rejected && !loadedRejected && !pending && completedValue==0;
        if (!safe) printf("PARKED_NATIVE_DIAGNOSTIC thread=%s library=%s pending=%d completed=%u elapsed_ms=%lld\n",
                          rejected ? "completed" : rejected.error().c_str(),
                          loadedRejected ? "completed" : loadedRejected.error().c_str(),pending,completedValue,
                          static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(
                              std::chrono::steady_clock::now()-startParked).count()));
        check(safe,
              "wholly syscall-parked native targets reject calls without creating a thread or retaining ownership");
        auto finished=parked.line();
        auto parkedElapsed=std::chrono::steady_clock::now()-startParked;
        check(finished=="CE_NATIVE_CALL_PARKED_DONE" && parkedElapsed>=std::chrono::milliseconds(1500) && parkedElapsed<std::chrono::seconds(10),
              "rejected calls preserve the original timed kernel wait and normal process completion");
        }
    } else check(false,"a real native process starts its relative timed kernel wait");
    printf("PARKED_NATIVE_CALL_RESULT=%s width=%u\n",failures==parkedFailures ? "PASSED" : "FAILED",width);
    printf("NATIVE_INJECTOR_RESULT=%s width=%u\n",failures ? "FAILED" : "PASSED",width);
    return failures ? 1 : 0;
}

#ifndef CECORE_NATIVE_CALL_EMBEDDED
int main(int argc,char** argv) { return nativeCallIntegration(argc,argv); }
#endif
