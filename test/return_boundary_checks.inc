#if defined(__x86_64__)
static std::string boundaryPermissions(pid_t tid,uintptr_t address) {
    std::ifstream maps("/proc/"+std::to_string(tid)+"/maps");std::string line;
    while (std::getline(maps,line)) {
        unsigned long long first=0,last=0;char flags[5]{};
        if (std::sscanf(line.c_str(),"%llx-%llx %4s",&first,&last,flags)==3 && address>=first && address<last) return flags;
    }
    return {};
}
static void returnBoundaryBackend(const char* path) {
    const int initial=failures;unsigned count=0;
    const auto require=[&](bool ok,const char* name) {
        ++count;failures+=!ok;
        std::printf("RETURN_BOUNDARY_CHECK %s: %s\n",ok ? "OK" : "FAILED",name);fflush(stdout);
    };
    Fixture fixture(path);LinuxProcessHandle process(fixture.pid);
    require(fixture.line().starts_with("CE_TARGET "),"return-boundary fixture starts an actual native application");
    const auto host=process.targetDescription().host;const size_t page=sysconf(_SC_PAGESIZE);
    auto scratch=process.allocate(page,MemProt::All);std::array<uintptr_t,4> storage{};
    bool allocated=scratch.has_value();
    for (auto& address:storage) {auto mapped=process.allocate(3*page,MemProt::All);if(mapped) address=*mapped;else allocated=false;}
    require(allocated,"boundary fixtures own real executable page pairs, private stacks and separate syscall scratch");
    if (!allocated) return;
    int status=0;
    const bool stopped=ptrace(PTRACE_SEIZE,fixture.pid,nullptr,nullptr)==0 && ptrace(PTRACE_INTERRUPT,fixture.pid,nullptr,nullptr)==0 &&
        waitpid(fixture.pid,&status,__WALL)==fixture.pid && WIFSTOPPED(status);
    user_regs_struct original{};
    require(stopped && ptrace(PTRACE_GETREGS,fixture.pid,nullptr,&original)==0,"the original application supplies a full real register bank under its ptrace owner");
    if (!stopped) return;
    auto extended=captureNativeExtendedContext(fixture.pid);std::array<uint8_t,32> savedScratch{},scratchAfter{};
    require(extended && readMemory(fixture.pid,*scratch,savedScratch.data(),savedScratch.size())==savedScratch.size(),
        "the boundary owner independently snapshots the original extended state and private code");
    if (!extended) return;
    for (unsigned variant=0;variant<4;++variant) {
        const bool shortInstruction=variant==3;const uintptr_t base=storage[variant],edge=base+page-1,endpoint=base+64;
        const std::array<uint8_t,6> program{0xb8,0x78,0x56,0x34,0x12,0xcc};const uint8_t ret=0xc3;
        const uintptr_t stack=base+3*page-16;
        bool written=writeMemory(fixture.pid,shortInstruction ? endpoint : edge,program.data(),program.size())==program.size();
        if (shortInstruction) {
            const uint64_t destination=endpoint;
            written=written && writeMemory(fixture.pid,edge,&ret,1)==1 &&
                writeMemory(fixture.pid,stack,&destination,host.pointerWidth)==host.pointerWidth;
        }
        auto prepared=original;prepared.rip=edge;prepared.rax=0;prepared.orig_rax=UINT64_MAX;
        if (shortInstruction) prepared.rsp=stack;
        const auto permissions=boundaryPermissions(fixture.pid,base+page);
        require(written && ptrace(PTRACE_SETREGS,fixture.pid,nullptr,&prepared)==0,
            shortInstruction ? "a real one-byte RET fits at the page end and owns a stack return to mapped code" :
            "a real five-byte MOV begins at the last page byte and requires the following page");
        const auto operation=variant==1 ? MemorySyscall::Protect : variant==2 ? MemorySyscall::Map : MemorySyscall::Unmap;
        std::array<uint64_t,6> args{base+page,page,0,0,0,0};
        if (variant==1) args[2]=PROT_READ;
        if (variant==2) args={base+page,page,PROT_READ|PROT_WRITE,MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS,UINT64_MAX,0};
        auto result=executeStoppedMemorySyscall(fixture.pid,host,operation,args,*scratch);
        require(shortInstruction ? result && *result==0 && boundaryPermissions(fixture.pid,base+page).empty() :
            !result && result.error().code==std::errc::operation_not_permitted && !result.error().completedValue,
            shortInstruction ? "an unrelated next page can actually be unmapped when the saved instruction fits before it" :
            "unmap, lost execute permission or MAP_FIXED cannot remove the tail of the saved return instruction");
        if (shortInstruction) {
            auto repeated=executeStoppedMemorySyscall(fixture.pid,host,MemorySyscall::Unmap,{base+page,page,0,0,0,0},*scratch);
            require(repeated && *repeated==0,"the actual short x86 instruction remains usable with a partial decode window beside an already unmapped page");
        }
        user_regs_struct observed{};std::array<uint8_t,6> code{};uint8_t afterRet=0;
        const bool bytes=shortInstruction ? readMemory(fixture.pid,edge,&afterRet,1)==1 && afterRet==ret :
            readMemory(fixture.pid,edge,code.data(),code.size())==code.size() && code==program && boundaryPermissions(fixture.pid,base+page)==permissions;
        require(bytes && ptrace(PTRACE_GETREGS,fixture.pid,nullptr,&observed)==0 && !std::memcmp(&prepared,&observed,sizeof(prepared)) &&
            verifyNativeExtendedContext(fixture.pid,*extended) && readMemory(fixture.pid,*scratch,scratchAfter.data(),scratchAfter.size())==scratchAfter.size() && scratchAfter==savedScratch,
            "the page-boundary operation preserves exact code, GP, extended state and private instructions");
        const bool resumed=ptrace(PTRACE_CONT,fixture.pid,nullptr,nullptr)==0 && waitpid(fixture.pid,&status,__WALL)==fixture.pid && WIFSTOPPED(status);
        const bool bank=resumed && ptrace(PTRACE_GETREGS,fixture.pid,nullptr,&observed)==0;
        const uintptr_t expectedEnd=(shortInstruction ? endpoint : edge)+program.size();
        std::printf("RETURN_BOUNDARY_OBSERVATION variant=%u instruction=%s operation=%d success=%d stop=%d pc=%llx value=%llx\n",
            variant,shortInstruction ? "ret1" : "mov5",int(operation),bool(result),resumed ? WSTOPSIG(status) : 0,
            static_cast<unsigned long long>(observed.rip),static_cast<unsigned long long>(observed.rax));
        require(bank && WSTOPSIG(status)==SIGTRAP && observed.rip==expectedEnd && observed.rax==0x12345678,
            "actual execution reads the complete original instruction and reaches its owned trap with the exact result");
        const bool restored=resumed && ptrace(PTRACE_SETREGS,fixture.pid,nullptr,&original)==0;
        auto freed=executeStoppedMemorySyscall(fixture.pid,host,MemorySyscall::Unmap,{base,3*page,0,0,0,0},*scratch);
        require(restored && freed && boundaryPermissions(fixture.pid,base).empty() && boundaryPermissions(fixture.pid,base+2*page).empty(),
            "the owner restores its original application stop and reclaims all boundary code and stack pages");
    }
    auto freed=executeQuiescedMemorySyscall(fixture.pid,host,MemorySyscall::Unmap,{*scratch,page,0,0,0,0});
    require(freed && ptrace(PTRACE_DETACH,fixture.pid,nullptr,nullptr)==0 && fixture.value(),
        "boundary cleanup releases scratch and preserves actual application console work after the original stop resumes");
    std::printf("RETURN_BOUNDARY_RESULT=%s architecture=%s checks=%u\n",failures==initial ? "PASSED" : "FAILED",cpuArchitectureName(host.architecture),count);
    fflush(stdout);
}
#endif
