#if defined(__x86_64__)
static void serviceThreadDeathBackend(const char* path) {
    const int initial=failures;unsigned count=0;CpuArchitecture architecture=CpuArchitecture::Unknown;
    auto require=[&](bool ok,const char* name) {
        ++count;failures+=!ok;std::printf("SERVICE_THREAD_DEATH_CHECK %s: %s\n",ok ? "OK" : "FAILED",name);fflush(stdout);
    };
    for(unsigned variant=0;variant<3;++variant) {
        const bool early=variant==1,shutdown=variant==2;
        Fixture fixture(path);std::istringstream hello(fixture.line());std::string marker;
        unsigned width=0;pid_t pid=0;uintptr_t valueAddress=0,pointer=0,code=0;
        hello>>marker>>pid>>width>>std::hex>>valueAddress>>pointer>>code;
        require(hello && marker=="CE_TARGET" && pid==fixture.pid && (width==4 || width==8),
            "the actual fixture publishes its ABI, data and code before creating its owner-exit threads");if(!hello) return;
        LinuxProcessHandle process(fixture.pid);auto host=process.targetDescription().host;architecture=host.architecture;
        auto identity=processMemoryIdentity(fixture.pid);
        const char command='O';std::istringstream ready(::write(fixture.input,&command,1)==1 ? fixture.line() : "");
        pid_t selected=0,survivor=0;uintptr_t exitFlag=0,heartbeat=0;
        ready>>marker>>selected>>survivor>>std::hex>>exitFlag>>heartbeat;
        auto stable=awaitState([&] {auto task=processMemoryTask(fixture.pid);return task && *task==selected;});
        require(ready && marker=="CE_OWNER_RECOVERY" && selected>0 && survivor>0 && selected!=survivor && selected!=fixture.pid &&
            survivor!=fixture.pid && exitFlag && heartbeat && stable && fixtureTracer(selected)==0 && fixtureTracer(survivor)==0,
            "the original leader really exits and the service selects a CPU-loop sibling while a separate console sibling survives");
        if(!ready || !stable || !identity) return;
        auto image=NativeMemoryImage::capture(*identity,host);std::array<uint8_t,16> originalCode{},afterCode{};
        require(image && readMemory(selected,code,originalCode.data(),originalCode.size())==ssize_t(originalCode.size()),
            "the test independently pins the original mm and captures its executable bytes");if(!image) return;
        auto service=std::make_unique<TargetSyscallService>();
        struct FaultScope {~FaultScope() {syscall_test::clear();syscall_test::clearDetachExit();}} faults;
        syscall_test::arm(syscall_test::Fault::Detach);
        if(early) syscall_test::exitBeforeDetach(selected,survivor,exitFlag);
        auto allocated=service->execute(*identity,host,MemorySyscall::Map,{0,4096,3,MAP_PRIVATE|MAP_ANONYMOUS,UINT64_MAX,0});
        require(!allocated && allocated.error()==(early ? std::errc::no_such_process : std::errc::io_error),
            early ? "actual selected-thread death during the first failed detach reports an error before returning its completed allocation" :
            "a completed mmap retains its allocation and real owner after a controlled detach failure");
        if(!early) {
            const uintptr_t allocation=width==4 ? static_cast<uint32_t>(syscall_test::completedResult()) : syscall_test::completedResult();
            uint8_t byte=1;auto present=(*image)->read(allocation,&byte,1);
            require(allocation && present && *present==1 && byte==0 && service->pending(identity->pid,identity->startTime) &&
                fixtureTracer(selected)>0 && fixtureTracer(survivor)==0,
                "before actual task death the service owns an unreturned live mapping against the original process identity");
            syscall_test::exitBeforeDetach(selected,survivor,exitFlag);
        }
        const bool exited=awaitState([] {return syscall_test::detachExitObserved();});
        const uintptr_t allocation=syscall_test::detachExitAllocation();
        require(exited && syscall_test::detachExitContextReady() && syscall_test::detachExitAllocationPresent() && allocation &&
            syscall_test::detachExitOwner()>0 && syscall_test::detachExitOwner()!=static_cast<pid_t>(syscall(SYS_gettid)),
            "the actual service owner resumes verified restored code, which exits its own thread, and leaves the real terminal notification unconsumed");
        syscall_test::clear();
        if(!exited) return;
        auto actual=processMemoryIdentity(fixture.pid);auto member=processMemoryTask(fixture.pid);
        require(actual && *actual==*identity && member && *member==survivor && (*image)->check(),
            "after selected-thread death the same original process and pinned mm remain live through the actual console sibling");
        bool recovered=false;
        if(shutdown) {service.reset();recovered=true;}
        else {auto result=service->recover(*identity);recovered=result && !service->pending(identity->pid,identity->startTime);}
        require(recovered && fixtureTracer(survivor)==0 && fixtureTracer(selected)<=0,
            shutdown ? "service destruction drains its retained allocation and releases its actual ptrace owner before joining" :
            "explicit service recovery drains its original ownership record and releases every real stop");
        uint8_t byte=1;auto absent=(*image)->read(allocation,&byte,1);
        require(!absent && absent.error()==std::errc::io_error && boundaryPermissions(survivor,allocation).empty() && (*image)->check(),
            "recovery independently removes the unreturned allocation before the surviving original mm exits");
        const bool preserved=syscall_test::survivorContextVerified();
        require(preserved,
            "handoff through the real console sibling preserves every captured GP/extended register and signal-mask bit");
        require(readMemory(survivor,code,afterCode.data(),afterCode.size())==ssize_t(afterCode.size()) && originalCode==afterCode && fixture.value(),
            "the survivor retains its original program bytes, data value and actual console work after cleanup");
        // Reclaim a leaked baseline mapping before continuing. This independent
        // cleanup does not turn the preceding failed ownership assertion green.
        if(absent) {
            syscall_test::clearDetachExit();
            auto cleanup=process.free(allocation,4096);
            require(cleanup.has_value(),"the independent baseline cleanup reclaims its leaked old-mm allocation");
        }
        const char quit='q';int terminal=0;
        bool finished=::write(fixture.input,&quit,1)==1 && waitpid(fixture.pid,&terminal,0)==fixture.pid && WIFEXITED(terminal) && WEXITSTATUS(terminal)==0;
        require(finished && kill(survivor,0)<0 && errno==ESRCH,"all actual fixture threads finish and the original process is reaped normally");
        if(finished) fixture.pid=-1;
        auto retired=(*image)->check();
        require(!retired && retired.error()==std::errc::operation_canceled,"only final real process exit retires the independently pinned original mm");
        std::printf("SERVICE_THREAD_DEATH_OBSERVATION architecture=%s phase=%s allocation=%llx absent=%d context=%d\n",
            cpuArchitectureName(architecture),early ? "before-record" : shutdown ? "shutdown" : "after-record",
            static_cast<unsigned long long>(allocation),!absent,preserved);
    }
    std::printf("SERVICE_THREAD_DEATH_RESULT=%s architecture=%s checks=%u\n",initial==failures ? "PASSED" : "FAILED",cpuArchitectureName(architecture),count);
}
#endif
