#if defined(__x86_64__)
static void serviceDetachReleaseBackend(const char* path) {
    const int initial=failures;unsigned count=0;CpuArchitecture architecture=CpuArchitecture::Unknown;
    auto require=[&](bool ok,const char* name) {
        ++count;failures+=!ok;std::printf("SERVICE_DETACH_RELEASE_CHECK %s: %s\n",ok ? "OK" : "FAILED",name);fflush(stdout);
    };
    for(unsigned variant=0;variant<3;++variant) {
        const bool early=variant==0,shutdown=variant==2;
        Fixture fixture(path);const auto hello=fixture.line();
        LinuxProcessHandle process(fixture.pid);auto host=process.targetDescription().host;architecture=host.architecture;
        auto identity=processMemoryIdentity(fixture.pid);
        require(hello.starts_with("CE_TARGET ") && identity && (host.pointerWidth==4 || host.pointerWidth==8),
            "the actual native fixture publishes its original process identity and ABI");if(!identity) return;
        const char spin='S';std::istringstream ready(::write(fixture.input,&spin,1)==1 ? fixture.line() : "");
        std::string marker;uintptr_t flag=0,heartbeat=0;ready>>marker>>std::hex>>flag>>heartbeat;
        auto image=NativeMemoryImage::capture(*identity,host);
        require(ready && marker=="CE_CALL_BUSY" && flag && heartbeat && image && fixtureTracer(fixture.pid)==0,
            "the original application runs its nonempty-vector CPU loop while the controller pins its mm");if(!ready || !image) return;
        auto service=std::make_unique<TargetSyscallService>();
        // Failure cleanup retires the owned fixture before joining the service,
        // so the unsafe baseline cannot hang the test or leak a live child.
        struct Cleanup {
            Fixture& fixture;std::unique_ptr<TargetSyscallService>& service;
            ~Cleanup() {syscall_test::clear();syscall_test::clearDetachRelease();
                if(service && fixture.pid>0) {
                    const pid_t original=fixture.pid;kill(original,SIGKILL);int terminal=0;
                    pid_t found;do {found=waitpid(original,&terminal,0);} while(found<0 && errno==EINTR);
                    if(found==original) fixture.pid=-1;
                }
                service.reset();}
        } cleanup{fixture,service};
        syscall_test::watchDetachRelease(fixture.pid);syscall_test::arm(syscall_test::Fault::Detach);
        if(early) syscall_test::releaseBeforeDetachError(fixture.pid);
        auto allocated=service->execute(*identity,host,MemorySyscall::Map,{0,4096,3,MAP_PRIVATE|MAP_ANONYMOUS,UINT64_MAX,0});
        require(early ? allocated.has_value() : !allocated && allocated.error()==std::errc::io_error,
            early ? "an already applied detach reports its completed mmap without retaining obsolete context" :
            "a detach failure before kernel application retains the real stop and unreturned allocation");
        if(!early) {
            require(service->pending(identity->pid,identity->startTime) && fixtureTracer(fixture.pid)>0,
                "a failure before application cannot falsely report its ptrace ownership as released");
            syscall_test::releaseBeforeDetachError(fixture.pid);
        }
        bool drained=false,baselineReaped=false;
        if(shutdown) {
            std::atomic<bool> joined=false;
            std::thread destroy([&] {service.reset();joined=true;});
            const auto until=std::chrono::steady_clock::now()+std::chrono::seconds(2);
            while(!joined && std::chrono::steady_clock::now()<until) {
                if(syscall_test::detachReleaseObservation().released) syscall_test::clear();
                usleep(1000);
            }
            drained=joined.load();
            if(!drained && fixture.pid>0) {
                syscall_test::clear();const pid_t original=fixture.pid;kill(original,SIGKILL);int terminal=0;
                baselineReaped=waitpid(original,&terminal,0)==original && WIFSIGNALED(terminal) && WTERMSIG(terminal)==SIGKILL;
                if(baselineReaped) fixture.pid=-1;
            }
            destroy.join();
        } else {
            auto result=service->recover(*identity);
            if(syscall_test::detachReleaseObservation().released) {
                syscall_test::clear();result=service->recover(*identity);
            }
            drained=result && !service->pending(identity->pid,identity->startTime);
        }
        auto actual=syscall_test::detachReleaseObservation();
        syscall_test::clear();
        require(actual.released && actual.context && actual.mapped && actual.kernelNoSuch && actual.allocation &&
            actual.owner>0 && actual.owner!=static_cast<pid_t>(syscall(SYS_gettid)),
            "the real owner verifies every original GP/extended/mask byte, actually detaches, and observes real ESRCH on the live task");
        require(drained && fixtureTracer(fixture.pid)==0,
            shutdown ? "service destruction completes and joins after the real detach without waiting for application exit" :
            "recovery completes without trying to restore an already released running context");
        require(actual.replayAttempts==0,
            "recovery makes no register, instruction or signal-state write attempt after releasing its original ownership");
        auto same=processMemoryIdentity(fixture.pid);unsigned before=0,after=0;
        bool busy=readMemory(fixture.pid,heartbeat,&before,sizeof(before))==sizeof(before);
        usleep(20000);busy=busy && readMemory(fixture.pid,heartbeat,&after,sizeof(after))==sizeof(after) && before!=after;
        require(same && *same==*identity && (*image)->check() && busy,
            "the same original application and mm stay alive and make actual CPU progress after recovery");
        if(!drained) {
            if(!baselineReaped && fixture.pid>0) {
                const pid_t original=fixture.pid;kill(original,SIGKILL);int terminal=0;
                baselineReaped=waitpid(original,&terminal,0)==original && WIFSIGNALED(terminal) && WTERMSIG(terminal)==SIGKILL;
                if(baselineReaped) fixture.pid=-1;
            }
            service.reset();
            require(baselineReaped,"bounded baseline failure cleanup really terminates and reaps its owned fixture before joining recovery");
            std::printf("SERVICE_DETACH_RELEASE_OBSERVATION architecture=%s phase=%s drained=0 replays=%u\n",
                cpuArchitectureName(architecture),early ? "before-record" : shutdown ? "shutdown" : "after-record",actual.replayAttempts);
            continue;
        }
        uint8_t byte=1;auto present=(*image)->read(actual.allocation,&byte,1);
        if(early) {
            require(allocated && *allocated==actual.allocation && present && *present==1 && byte==0,
                "the returned allocation remains mapped and belongs to the caller after successful release recovery");
            if(allocated) {auto freed=service->execute(*identity,host,MemorySyscall::Unmap,{*allocated,4096,0,0,0,0});
                require(freed.has_value(),"the caller can independently reclaim its returned allocation");}
        } else require(!present && present.error()==std::errc::io_error && boundaryPermissions(fixture.pid,actual.allocation).empty(),
            "retained-allocation recovery reclaims the unreturned map while the original mm is still alive");
        unsigned stop=0;
        bool resumed=writeMemory(fixture.pid,flag,&stop,sizeof(stop))==sizeof(stop) && fixture.line()=="CE_CALL_DONE" && fixture.value();
        require(resumed,"the original application leaves its loop and completes its unchanged console work");
        syscall_test::clearDetachRelease();service.reset();
        const char quit='q';int terminal=0;
        const bool ended=resumed && ::write(fixture.input,&quit,1)==1 && waitpid(fixture.pid,&terminal,0)==fixture.pid &&
            WIFEXITED(terminal) && WEXITSTATUS(terminal)==0;
        require(ended,"the actual fixture exits normally and is reaped after recovery and service shutdown");
        if(ended) fixture.pid=-1;
        auto retired=(*image)->check();require(!retired && retired.error()==std::errc::operation_canceled,
            "only final application exit retires the independently pinned original mm");
        std::printf("SERVICE_DETACH_RELEASE_OBSERVATION architecture=%s phase=%s drained=%d replays=%u\n",
            cpuArchitectureName(architecture),early ? "before-record" : shutdown ? "shutdown" : "after-record",drained,actual.replayAttempts);
    }
    std::printf("SERVICE_DETACH_RELEASE_RESULT=%s architecture=%s checks=%u\n",initial==failures ? "PASSED" : "FAILED",cpuArchitectureName(architecture),count);
}
#endif
