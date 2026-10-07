#if defined(__x86_64__)
static void unreapedRecoveryBackend(const char* path) {
    const int initial=failures;unsigned count=0;
    auto require=[&](bool ok,const char* name) {
        ++count;failures+=!ok;std::printf("UNREAPED_RECOVERY_CHECK %s: %s\n",ok ? "OK" : "FAILED",name);fflush(stdout);
    };
    auto birthState=[](pid_t pid,char& state) -> uint64_t {
        std::ifstream file("/proc/"+std::to_string(pid)+"/stat");std::string line;std::getline(file,line);
        const auto close=line.rfind(')');if(close==std::string::npos) return 0;
        std::istringstream fields(line.substr(close+1));std::string field;
        for(unsigned index=3;index<22;++index) {if(!(fields>>field)) return 0;if(index==3) state=field.front();}
        uint64_t birth=0;fields>>birth;return fields ? birth : 0;
    };
    auto transfer=[](int fd,void* data,size_t bytes,bool writing) {
        const auto until=std::chrono::steady_clock::now()+std::chrono::seconds(2);
        size_t done=0;
        while(done<bytes && std::chrono::steady_clock::now()<until) {
            pollfd pending{fd,static_cast<short>(writing ? POLLOUT : POLLIN),0};
            int available;do {available=poll(&pending,1,20);} while(available<0 && errno==EINTR);
            if(available<=0) continue;
            const auto result=writing ? ::write(fd,static_cast<char*>(data)+done,bytes-done) :
                ::read(fd,static_cast<char*>(data)+done,bytes-done);
            if(result<0 && errno==EINTR) continue;
            if(result<=0) return false;
            done+=static_cast<size_t>(result);
        }
        return done==bytes;
    };
    struct Observation {pid_t owner=0;uint64_t allocation=0;bool held=false,terminal=false,retired=false,complete=false;int error=0;};
    CpuArchitecture architecture=CpuArchitecture::Unknown;
    for(unsigned variant=0;variant<2;++variant) {
    const bool function=variant==1;
    Fixture fixture(path);const auto hello=fixture.line();
    std::ifstream executable(path,std::ios::binary);std::array<uint8_t,64> header{};
    executable.read(reinterpret_cast<char*>(header.data()),header.size());
    auto host=parseElfTarget({header.data(),static_cast<size_t>(executable.gcount())});
    if(host) architecture=host->architecture;
    char state=0;const auto originalBirth=birthState(fixture.pid,state);
    require(hello.starts_with("CE_TARGET ") && host && originalBirth && state!='Z',
        "the original parent launches an actual live native fixture and records its original birth");if(!host || !originalBirth) return;
    uintptr_t sum=0;
    if(function) {
        char command='j';std::istringstream callable(::write(fixture.input,&command,1)==1 ? fixture.line() : "");std::string marker;
        callable>>marker>>std::hex>>sum;
        command='S';const bool spinning=::write(fixture.input,&command,1)==1 && fixture.line().starts_with("CE_CALL_BUSY ");
        require(callable && marker=="CE_FUNCTION" && sum && spinning,
            "the real fixture publishes its callable function and enters its nonempty-vector CPU loop");if(!callable || !sum || !spinning) return;
    }
    int commands[2],observations[2];
    if(pipe(commands)) {require(false,"create the controller command pipe");return;}
    if(pipe(observations)) {close(commands[0]);close(commands[1]);require(false,"create the controller observation pipe");return;}
    const pid_t parent=getpid(),target=fixture.pid;
    const pid_t controller=fork();
    if(!controller) {
        close(commands[1]);close(observations[0]);
        if(prctl(PR_SET_PDEATHSIG,SIGKILL)<0 || getppid()!=parent) _exit(126);
        // This owner is a separate process from the fixture's real parent.
        // Consuming its ptrace terminal report leaves the parent's child zombie.
        std::shared_ptr<TargetSyscallRecovery> recovery;
        const auto page=static_cast<uint64_t>(sysconf(_SC_PAGESIZE));
        Observation seen;seen.owner=static_cast<pid_t>(syscall(SYS_gettid));
        if(function) {
            auto frame=executeMemorySyscall(target,*host,MemorySyscall::Map,
                {0,18*page,7,MAP_PRIVATE|MAP_ANONYMOUS,UINT64_MAX,0});
            int stop=0;
            const bool owned=frame && ptrace(PTRACE_SEIZE,target,nullptr,nullptr)==0 &&
                ptrace(PTRACE_INTERRUPT,target,nullptr,nullptr)==0 && waitpid(target,&stop,__WALL|__WNOTHREAD)==target && WIFSTOPPED(stop);
            if(owned) {
                syscall_test::arm(syscall_test::Fault::FunctionRestoreRegisters);
                auto failed=executeStoppedFunction(target,*host,sum,{1,2,3,4,5,6,7,8},*frame,*frame+17*page);
                seen.held=!failed && failed.error().recovery && failed.error().completedValue==87654321 &&
                    failed.error().recovery->functionResult()==87654321;
                if(seen.held) {seen.allocation=*frame;recovery=failed.error().recovery;}
            }
        } else {
            syscall_test::arm(syscall_test::Fault::RestoreRegisters);
            auto failed=executeMemorySyscall(target,*host,MemorySyscall::Map,{0,page,3,MAP_PRIVATE|MAP_ANONYMOUS,UINT64_MAX,0});
            seen.held=!failed && failed.error().recovery && failed.error().completedValue;
            if(seen.held) {seen.allocation=*failed.error().completedValue;recovery=failed.error().recovery;}
        }
        syscall_test::clear();
        if(!transfer(observations[1],&seen,sizeof(seen),true)) _exit(125);
        char command=0;if(!transfer(commands[0],&command,1,false) || command!='k' || !seen.held) _exit(124);
        int terminal=0;pid_t waited;
        do {waited=waitpid(target,&terminal,__WALL|__WNOTHREAD);} while(waited<0 && errno==EINTR);
        seen.terminal=waited==target && WIFSIGNALED(terminal) && WTERMSIG(terminal)==SIGKILL;
        if(!transfer(observations[1],&seen,sizeof(seen),true)) _exit(123);
        if(!transfer(commands[0],&command,1,false) || command!='r') _exit(122);
        auto image=recovery->checkImage();seen.retired=!image && image.error()==std::errc::operation_canceled;
        auto retried=recovery->retry();seen.error=retried ? 0 : retried.error().value();
        seen.complete=recovery->retry().has_value();
        if(!transfer(observations[1],&seen,sizeof(seen),true)) _exit(121);
        if(!transfer(commands[0],&command,1,false) || command!='q') _exit(120);
        // The baseline can retire only after the real parent reaps its child.
        // Finish that owned recovery before exiting even when assertions failed.
        auto cleanup=recovery->retry();
        _exit(cleanup || cleanup.error()==std::errc::no_such_process ? 0 : 119);
    }
    close(commands[0]);close(observations[1]);
    struct Controller {
        pid_t pid;int command,observation;
        ~Controller() {close(command);close(observation);if(pid>0) {kill(pid,SIGKILL);int terminal=0;while(waitpid(pid,&terminal,0)<0 && errno==EINTR){}}}
    } owned{controller,commands[1],observations[0]};
    require(controller>0,"the actual ptrace owner is a separate process from the real parent");if(controller<=0) return;
    Observation seen;
    require(transfer(owned.observation,&seen,sizeof(seen),false) && seen.held && seen.allocation &&
        seen.owner==controller && fixtureTracer(target)==controller,
        function ? "a real completed function retains its exact result and original-context restoration on the separate ptrace owner" :
            "a real completed mmap retains failed original-register restoration on the separate ptrace owner");if(!seen.held) return;
    char command='k';require(kill(target,SIGKILL)==0 && transfer(owned.command,&command,1,true),
        "the real parent kills its own stopped child through the kernel");
    require(transfer(owned.observation,&seen,sizeof(seen),false) && seen.terminal,
        "the actual tracer consumes its real terminal ptrace notification without reaping the parent's child");if(!seen.terminal) return;
    siginfo_t terminal{};
    const bool witnessed=waitid(P_PID,target,&terminal,WEXITED|WNOHANG|WNOWAIT)==0 && terminal.si_pid==target &&
        terminal.si_code==CLD_KILLED && terminal.si_status==SIGKILL;
    state=0;const auto zombieBirth=birthState(target,state);
    require(witnessed && state=='Z' && zombieBirth==originalBirth && fixtureTracer(target)==0,
        "the real parent independently observes an unreaped kernel zombie with its unchanged original birth and zero tracer");
    command='r';const bool response=transfer(owned.command,&command,1,true) && transfer(owned.observation,&seen,sizeof(seen),false);
    require(response && seen.retired,"the pinned original mm is retired while the original PID remains unreaped");
    require(response && seen.error==ESRCH,"owner recovery retires a confirmed dead context before the parent reaps its original PID");
    require(response && seen.complete,"confirmed task death completes recovery idempotently instead of retaining unavailable executable metadata");
    state=0;require(birthState(target,state)==originalBirth && state=='Z',
        "the recovery result is observed before actual parent reaping rather than after disappearance of the numeric PID");
    int status=0;pid_t reaped;do {reaped=waitpid(target,&status,0);} while(reaped<0 && errno==EINTR);
    const bool retired=reaped==target && WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL;
    require(retired,"the real parent finally reaps its original child's authentic SIGKILL exit");if(retired) fixture.pid=-1;
    command='q';const bool sent=transfer(owned.command,&command,1,true);
    do {reaped=waitpid(controller,&status,0);} while(reaped<0 && errno==EINTR);
    require(sent && reaped==controller && WIFEXITED(status) && WEXITSTATUS(status)==0,
        "the separate owner finishes its retained recovery and the parent reaps it normally");if(reaped==controller) owned.pid=-1;
    std::printf("UNREAPED_RECOVERY_OBSERVATION architecture=%s phase=%s state=Z birth=%llu recoveryError=%d complete=%d terminal=%d\n",
        cpuArchitectureName(host->architecture),function ? "function" : "memory",static_cast<unsigned long long>(originalBirth),seen.error,seen.complete,seen.terminal);
    }
    std::printf("UNREAPED_RECOVERY_RESULT=%s architecture=%s checks=%u\n",initial==failures ? "PASSED" : "FAILED",cpuArchitectureName(architecture),count);
}
#endif
