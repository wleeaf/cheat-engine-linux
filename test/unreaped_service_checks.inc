#if defined(__x86_64__)
static void unreapedServiceBackend(const char* path) {
    const int initial=failures;unsigned count=0;CpuArchitecture architecture=CpuArchitecture::Unknown;
    auto require=[&](bool ok,const char* name) {
        ++count;failures+=!ok;std::printf("UNREAPED_SERVICE_CHECK %s: %s\n",ok ? "OK" : "FAILED",name);fflush(stdout);
    };
    auto birthState=[](pid_t pid,char& state) -> uint64_t {
        std::ifstream file("/proc/"+std::to_string(pid)+"/stat");std::string line;std::getline(file,line);
        const auto close=line.rfind(')');if(close==std::string::npos) return 0;
        std::istringstream fields(line.substr(close+1));std::string field;
        for(unsigned index=3;index<22;++index) {if(!(fields>>field)) return 0;if(index==3) state=field.front();}
        uint64_t birth=0;fields>>birth;return fields ? birth : 0;
    };
    auto transfer=[](int fd,void* data,size_t bytes,bool writing) {
        const auto until=std::chrono::steady_clock::now()+std::chrono::seconds(2);size_t done=0;
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
    struct Observation {pid_t owner=0;uint64_t allocation=0;bool held=false,terminal=false,retired=false,drained=false;int error=0;};
    for(unsigned variant=0;variant<2;++variant) {
        const bool shutdown=variant==1;
        Fixture fixture(path);const auto hello=fixture.line();
        // Keep the real parent thread-free before fork: ELF parsing and /proc
        // observation do not initialize a process-global syscall service.
        std::ifstream executable(path,std::ios::binary);std::array<uint8_t,64> header{};
        executable.read(reinterpret_cast<char*>(header.data()),header.size());
        auto host=parseElfTarget({header.data(),static_cast<size_t>(executable.gcount())});
        if(host) architecture=host->architecture;
        char state=0;const auto originalBirth=birthState(fixture.pid,state);
        const char spin='S';const bool busy=::write(fixture.input,&spin,1)==1 && fixture.line().starts_with("CE_CALL_BUSY ");
        require(hello.starts_with("CE_TARGET ") && host && originalBirth && state!='Z' && busy,
            "the real parent records a live native fixture's original ABI and birth");if(!host || !originalBirth) return;
        int commands[2],observations[2];
        if(pipe(commands)) {require(false,"create the service controller command pipe");return;}
        if(pipe(observations)) {close(commands[0]);close(commands[1]);require(false,"create the service observation pipe");return;}
        const pid_t parent=getpid(),target=fixture.pid,controller=fork();
        if(!controller) {
            close(commands[1]);close(observations[0]);
            if(prctl(PR_SET_PDEATHSIG,SIGKILL)<0 || getppid()!=parent) _exit(126);
            auto identity=processMemoryIdentity(target);
            if(!identity) _exit(125);
            auto image=NativeMemoryImage::capture(*identity,*host);
            if(!image) _exit(124);
            auto service=std::make_unique<TargetSyscallService>();
            syscall_test::arm(syscall_test::Fault::RestoreRegisters);
            const auto page=static_cast<uint64_t>(sysconf(_SC_PAGESIZE));
            auto allocated=service->execute(*identity,*host,MemorySyscall::Map,
                {0,page,3,MAP_PRIVATE|MAP_ANONYMOUS,UINT64_MAX,0});
            Observation seen;
            seen.allocation=syscall_test::completedResult();
            if(host->pointerWidth==4) seen.allocation=static_cast<uint32_t>(seen.allocation);
            uint8_t byte=1;auto mapped=(*image)->read(seen.allocation,&byte,1);
            seen.held=!allocated && allocated.error()==std::errc::state_not_recoverable && syscall_test::triggered() &&
                service->pending(identity->pid,identity->startTime) && mapped && *mapped==1 && byte==0;
            syscall_test::holdEmptyRecoveryPoll(target);
            const auto until=std::chrono::steady_clock::now()+std::chrono::seconds(2);
            while(!syscall_test::emptyRecoveryPollHeld() && std::chrono::steady_clock::now()<until) usleep(1000);
            seen.owner=syscall_test::emptyRecoveryPollOwner();
            seen.held=seen.held && syscall_test::emptyRecoveryPollHeld() && seen.owner!=getpid();
            std::fprintf(stderr,"UNREAPED_SERVICE_READY owner=%ld allocation=%llx held=%d mmapError=%d mapped=%d\n",
                static_cast<long>(seen.owner),static_cast<unsigned long long>(seen.allocation),seen.held,
                allocated ? 0 : allocated.error().value(),mapped && *mapped==1 && byte==0);
            if(!transfer(observations[1],&seen,sizeof(seen),true)) _exit(123);
            char command=0;if(!transfer(commands[0],&command,1,false) || command!='k' || !seen.held) _exit(122);
            // This is the actual controller main thread, not the service owner.
            // Linux permits it to consume the owner's real ptrace child report.
            int terminal=0;pid_t waited;
            do {waited=waitpid(target,&terminal,__WALL);} while(waited<0 && errno==EINTR);
            seen.terminal=waited==target && WIFSIGNALED(terminal) && WTERMSIG(terminal)==SIGKILL;
            auto retired=(*image)->check();seen.retired=!retired && retired.error()==std::errc::operation_canceled;
            if(!transfer(observations[1],&seen,sizeof(seen),true)) _exit(121);
            if(!transfer(commands[0],&command,1,false) || command!='r') _exit(120);
            syscall_test::clear();syscall_test::releaseEmptyRecoveryPoll();
            if(shutdown) {service.reset();seen.drained=true;}
            else {
                auto recovered=service->recover(*identity);seen.error=recovered ? 0 : recovered.error().value();
                seen.drained=recovered && !service->pending(identity->pid,identity->startTime);
            }
            if(!transfer(observations[1],&seen,sizeof(seen),true)) _exit(119);
            if(!transfer(commands[0],&command,1,false) || command!='q') _exit(118);
            // Bounded baseline cleanup: the real parent has now reaped its
            // fixture, so the old owner can also retire its retained record.
            service.reset();_exit(0);
        }
        close(commands[0]);close(observations[1]);
        struct Controller {
            pid_t pid;int command,observation;
            ~Controller() {close(command);close(observation);if(pid>0) {kill(pid,SIGKILL);int terminal=0;while(waitpid(pid,&terminal,0)<0 && errno==EINTR){}}}
        } owned{controller,commands[1],observations[0]};
        require(controller>0,"a separate controller process creates the actual service ptrace owner");if(controller<=0) return;
        Observation seen;
        require(transfer(owned.observation,&seen,sizeof(seen),false) && seen.held && seen.allocation &&
            seen.owner>0 && seen.owner!=controller && fixtureTracer(target)==seen.owner,
            "the actual service owner retains the real unreturned mmap and is paused after its genuine empty poll");if(!seen.held) return;
        char command='k';require(kill(target,SIGKILL)==0 && transfer(owned.command,&command,1,true),
            "the original parent sends authentic SIGKILL to its own stopped child");
        require(transfer(owned.observation,&seen,sizeof(seen),false) && seen.terminal,
            "another actual thread consumes the service owner's real terminal notification");if(!seen.terminal) return;
        siginfo_t terminal{};
        const bool witnessed=waitid(P_PID,target,&terminal,WEXITED|WNOHANG|WNOWAIT)==0 && terminal.si_pid==target &&
            terminal.si_code==CLD_KILLED && terminal.si_status==SIGKILL;
        state=0;require(witnessed && birthState(target,state)==originalBirth && state=='Z' && fixtureTracer(target)==0,
            "the real parent independently verifies its unreaped zombie's unchanged birth and released tracer");
        require(seen.retired,"the independently pinned original mm is already retired before releasing the owner's genuine poll");
        command='r';const bool response=transfer(owned.command,&command,1,true) && transfer(owned.observation,&seen,sizeof(seen),false);
        require(response && seen.error==0,
            shutdown ? "service destruction returns within the bound while the real parent still holds its zombie" :
                "explicit service recovery succeeds while the real parent still holds its zombie");
        require(response && seen.drained,
            shutdown ? "destruction joins the real owner after draining its retained allocation and context" :
                "the real owner drains its unreturned allocation and no pending service record remains");
        state=0;require(birthState(target,state)==originalBirth && state=='Z',
            "service completion is checked before parent reaping rather than after numeric PID disappearance");
        int status=0;pid_t reaped;do {reaped=waitpid(target,&status,0);} while(reaped<0 && errno==EINTR);
        const bool retired=reaped==target && WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL;
        require(retired,"the original parent finally reaps its actual fixture's authentic SIGKILL exit");if(retired) fixture.pid=-1;
        command='q';const bool sent=transfer(owned.command,&command,1,true);
        do {reaped=waitpid(controller,&status,0);} while(reaped<0 && errno==EINTR);
        require(sent && reaped==controller && WIFEXITED(status) && WEXITSTATUS(status)==0,
            "the actual controller finishes service cleanup and is reaped normally");if(reaped==controller) owned.pid=-1;
        std::printf("UNREAPED_SERVICE_OBSERVATION architecture=%s phase=%s state=Z birth=%llu reply=%d recoveryError=%d drained=%d terminal=%d retired=%d\n",
            cpuArchitectureName(architecture),shutdown ? "shutdown" : "recover",static_cast<unsigned long long>(originalBirth),response,seen.error,seen.drained,seen.terminal,seen.retired);
    }
    std::printf("UNREAPED_SERVICE_RESULT=%s architecture=%s checks=%u\n",initial==failures ? "PASSED" : "FAILED",cpuArchitectureName(architecture),count);
}
#endif
