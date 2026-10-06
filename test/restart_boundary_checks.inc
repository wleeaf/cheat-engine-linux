#if defined(__x86_64__)
static bool restartBoundaryStop(pid_t tid,int& status) {
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(3);
    while (std::chrono::steady_clock::now()<deadline) {
        const auto waited=waitpid(tid,&status,__WALL|WNOHANG);
        if (waited==tid) return WIFSTOPPED(status);
        if (waited<0 && errno!=EINTR) return false;
        usleep(10000);
    }
    return false;
}
static bool restartBoundaryRead(pid_t tid,uint64_t number,uintptr_t buffer,uintptr_t after) {
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(3);
    while (std::chrono::steady_clock::now()<deadline) {
        std::ifstream input("/proc/"+std::to_string(tid)+"/syscall");std::string line;std::getline(input,line);
        std::istringstream fields(line);int64_t actual=-1;std::array<uint64_t,8> arguments{};
        fields>>actual>>std::hex;for (auto& value:arguments) fields>>value;
        if (fields && actual==static_cast<int64_t>(number) && arguments[0]==0 &&
            arguments[1]==buffer && arguments[2]==1 && arguments[7]==after) return true;
        usleep(10000);
    }
    return false;
}
static void restartBoundaryBackend(const char* path) {
    const int initial=failures;unsigned count=0;CpuArchitecture architecture=CpuArchitecture::Unknown;
    const auto require=[&](bool ok,const char* name) {
        ++count;failures+=!ok;
        std::printf("RESTART_BOUNDARY_CHECK %s: %s\n",ok ? "OK" : "FAILED",name);fflush(stdout);
    };
    for (unsigned variant=0;variant<5;++variant) {
        const bool completed=variant==3,userCode=variant==4;
        Fixture fixture(path);LinuxProcessHandle process(fixture.pid);
        require(fixture.line().starts_with("CE_TARGET "),"restart-boundary fixture starts an actual native application");
        const auto host=process.targetDescription().host;architecture=host.architecture;
        const size_t page=sysconf(_SC_PAGESIZE);
        auto scratch=process.allocate(page,MemProt::All),storage=process.allocate(3*page,MemProt::All);
        require(scratch && storage,"restart fixtures own a code pair, read buffer and separate syscall scratch");
        if (!scratch || !storage) return;
        const uintptr_t edge=*storage+page-2,after=edge+2,buffer=*storage+2*page;
        int status=0;user_regs_struct original{};
        const bool owned=ptrace(PTRACE_SEIZE,fixture.pid,nullptr,reinterpret_cast<void*>(PTRACE_O_TRACESYSGOOD))==0 &&
            ptrace(PTRACE_INTERRUPT,fixture.pid,nullptr,nullptr)==0 && restartBoundaryStop(fixture.pid,status) &&
            ptrace(PTRACE_GETREGS,fixture.pid,nullptr,&original)==0;
        auto extended=owned ? captureNativeExtendedContext(fixture.pid) :
            std::expected<NativeExtendedContext,std::error_code>(std::unexpected(std::make_error_code(std::errc::io_error)));
        std::array<uint8_t,32> savedScratch{},scratchAfter{};
        require(owned && extended && readMemory(fixture.pid,*scratch,savedScratch.data(),savedScratch.size())==savedScratch.size(),
            "the original stop supplies independently captured full GP, extended state and private instructions");
        if (!owned || !extended) return;
        const bool compat=host.architecture==CpuArchitecture::X86_32;
        const uint64_t number=compat ? 3 : host.abi==TargetAbi::LinuxX32 ? 0x40000000 : 0;
        const std::array<uint8_t,3> code=compat ? std::array<uint8_t,3>{0xcd,0x80,0xcc} : std::array<uint8_t,3>{0x0f,0x05,0xcc};
        auto prepared=original;prepared.rip=userCode ? after : edge;prepared.orig_rax=UINT64_MAX;
        prepared.rax=userCode ? static_cast<uint64_t>(-512) : number;
        if (compat) {prepared.rbx=0;prepared.rcx=buffer;prepared.rdx=1;}
        else {prepared.rdi=0;prepared.rsi=buffer;prepared.rdx=1;}
        require(writeMemory(fixture.pid,edge,code.data(),code.size())==code.size() &&
            ptrace(PTRACE_SETREGS,fixture.pid,nullptr,&prepared)==0,
            "actual SYSCALL or INT 80 ends at the page boundary beside a mapped owned return trap");
        user_regs_struct parked{};bool ready=false;
        if (userCode) {
            ready=ptrace(PTRACE_GETREGS,fixture.pid,nullptr,&parked)==0 && !std::memcmp(&parked,&prepared,sizeof(parked));
        } else if (completed) {
            const char value='z';
            ready=::write(fixture.input,&value,1)==1 && ptrace(PTRACE_SYSCALL,fixture.pid,nullptr,nullptr)==0 &&
                restartBoundaryStop(fixture.pid,status) && WSTOPSIG(status)==(SIGTRAP|0x80) &&
                ptrace(PTRACE_SYSCALL,fixture.pid,nullptr,nullptr)==0 && restartBoundaryStop(fixture.pid,status) &&
                WSTOPSIG(status)==(SIGTRAP|0x80) && ptrace(PTRACE_GETREGS,fixture.pid,nullptr,&parked)==0 &&
                parked.rip==after && parked.orig_rax==number && parked.rax==1;
        } else {
            ready=ptrace(PTRACE_CONT,fixture.pid,nullptr,nullptr)==0 && restartBoundaryRead(fixture.pid,number,buffer,after) &&
                ptrace(PTRACE_INTERRUPT,fixture.pid,nullptr,nullptr)==0 && restartBoundaryStop(fixture.pid,status) &&
                ptrace(PTRACE_GETREGS,fixture.pid,nullptr,&parked)==0 && parked.rip==after &&
                parked.orig_rax==number && static_cast<int64_t>(parked.rax)==-512;
        }
        std::printf("RESTART_BOUNDARY_STOP variant=%u pc=%llx syscall=%llx result=%llx ready=%d\n",variant,
            static_cast<unsigned long long>(parked.rip),static_cast<unsigned long long>(parked.orig_rax),
            static_cast<unsigned long long>(parked.rax),ready);
        require(ready,userCode ? "a user-code error-looking value has no active kernel syscall to restart" : completed ?
            "a real completed read reaches its syscall-exit stop with no restart error" :
            "an actual blocked read exposes its real restart error with the saved PC on the following page");
        if (!ready) return;
        const auto operation=variant==1 ? MemorySyscall::Protect : variant==2 ? MemorySyscall::Map : MemorySyscall::Unmap;
        std::array<uint64_t,6> arguments{*storage,page,0,0,0,0};
        if (variant==1) arguments[2]=PROT_READ;
        if (variant==2) arguments={*storage,page,PROT_READ|PROT_WRITE,MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS,UINT64_MAX,0};
        const auto permissions=boundaryPermissions(fixture.pid,*storage);
        auto result=executeStoppedMemorySyscall(fixture.pid,host,operation,arguments,*scratch);
        require(completed || userCode ? result && *result==0 && boundaryPermissions(fixture.pid,*storage).empty() :
            !result && result.error().code==std::errc::operation_not_permitted && !result.error().completedValue,
            completed || userCode ? "an unused preceding page can be released after syscall completion or from ordinary user code" :
            "destructive memory operations cannot destroy the preceding page needed by the kernel restart");
        user_regs_struct observed{};std::array<uint8_t,3> observedCode{};uint8_t trap=0;
        const bool bytes=completed || userCode ? readMemory(fixture.pid,after,&trap,1)==1 && trap==0xcc :
            readMemory(fixture.pid,edge,observedCode.data(),observedCode.size())==observedCode.size() && observedCode==code &&
            boundaryPermissions(fixture.pid,*storage)==permissions;
        require(bytes && ptrace(PTRACE_GETREGS,fixture.pid,nullptr,&observed)==0 && !std::memcmp(&parked,&observed,sizeof(parked)) &&
            verifyNativeExtendedContext(fixture.pid,*extended) && readMemory(fixture.pid,*scratch,scratchAfter.data(),scratchAfter.size())==scratchAfter.size() && scratchAfter==savedScratch,
            "the operation returns exact GP, syscall restart metadata, extended state and original private instructions");
        const char value='z';
        bool resumed=(completed || userCode || ::write(fixture.input,&value,1)==1) &&
            ptrace(PTRACE_CONT,fixture.pid,nullptr,nullptr)==0 && restartBoundaryStop(fixture.pid,status);
        const bool bank=resumed && ptrace(PTRACE_GETREGS,fixture.pid,nullptr,&observed)==0;
        char read=0;const bool received=userCode || (readMemory(fixture.pid,buffer,&read,1)==1 && read==value);
        std::printf("RESTART_BOUNDARY_OBSERVATION variant=%u operation=%d success=%d stop=%d pc=%llx result=%llx byte=%d\n",variant,
            int(operation),bool(result),resumed ? WSTOPSIG(status) : 0,static_cast<unsigned long long>(observed.rip),
            static_cast<unsigned long long>(observed.rax),int(read));
        require(bank && WSTOPSIG(status)==SIGTRAP && observed.rip==after+1 && received &&
            observed.rax==(userCode ? static_cast<uint64_t>(-512) : 1),
            "actual resume restarts the original read when needed, receives its byte and reaches the owned return trap");
        if (!resumed) return;
        const bool restored=ptrace(PTRACE_SETREGS,fixture.pid,nullptr,&original)==0;
        auto freed=executeStoppedMemorySyscall(fixture.pid,host,MemorySyscall::Unmap,{*storage,3*page,0,0,0,0},*scratch);
        require(restored && freed && boundaryPermissions(fixture.pid,*storage).empty() && boundaryPermissions(fixture.pid,buffer).empty(),
            "the caller restores the original application stop and reclaims its real code and read-buffer mappings");
        auto scratchFreed=executeQuiescedMemorySyscall(fixture.pid,host,MemorySyscall::Unmap,{*scratch,page,0,0,0,0});
        require(scratchFreed && ptrace(PTRACE_DETACH,fixture.pid,nullptr,nullptr)==0 && fixture.value(),
            "scratch cleanup and detach preserve the original application's blocked read and console work");
    }
    std::printf("RESTART_BOUNDARY_RESULT=%s architecture=%s checks=%u\n",failures==initial ? "PASSED" : "FAILED",cpuArchitectureName(architecture),count);
    fflush(stdout);
}
#endif
