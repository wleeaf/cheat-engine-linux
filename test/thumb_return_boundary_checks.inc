static void thumbReturnBoundary(pid_t tid,uintptr_t scratch,const char* fixture,Checks& check) {
    std::ifstream executable(fixture,std::ios::binary);std::array<uint8_t,64> header{};
    executable.read(reinterpret_cast<char*>(header.data()),header.size());
    auto machine=parseElfTarget({header.data(),static_cast<size_t>(executable.gcount())});
    Bank original{},after{};std::array<uint8_t,16> originalScratch{},scratchAfter{};
    auto extended=ce::os::captureNativeExtendedContext(tid);
    const bool ready=machine && rawBank(tid,original) && (original[16]&0x20) && extended &&
        armMemoryTransfer(tid,scratch,originalScratch.data(),originalScratch.size())==originalScratch.size();
    check(ready,"a real stopped Thumb application supplies complete GP VFP and private-code boundary snapshots");
    if (!ready) return;
    const auto setBank=[&](Bank& bank) {iovec io{bank.data(),sizeof(bank)};return ptrace(PTRACE_SETREGSET,tid,reinterpret_cast<void*>(NT_PRSTATUS),&io)==0;};
    const auto execute=[&](ce::os::MemorySyscall op,std::array<uint64_t,6> args) {
        return ce::os::executeStoppedMemorySyscall(tid,*machine,op,args,scratch);
    };
    const auto writeCode=[&](uintptr_t address,const auto& bytes) {
        for (size_t done=0;done<bytes.size();) {
            const uintptr_t at=address+done,aligned=at-at%sizeof(long);errno=0;
            long word=ptrace(PTRACE_PEEKTEXT,tid,reinterpret_cast<void*>(aligned),nullptr);
            if (word==-1 && errno) return false;
            const size_t offset=at-aligned,size=std::min(bytes.size()-done,sizeof(long)-offset);
            std::memcpy(reinterpret_cast<uint8_t*>(&word)+offset,bytes.data()+done,size);
            if (ptrace(PTRACE_POKETEXT,tid,reinterpret_cast<void*>(aligned),reinterpret_cast<void*>(word))<0) return false;
            done+=size;
        }
        return true;
    };
    for (unsigned variant=0;variant<4;++variant) {
        const bool shortInstruction=variant==3;constexpr size_t page=4096;
        auto allocated=execute(ce::os::MemorySyscall::Map,{0,2*page,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,UINT64_MAX,0});
        const uintptr_t base=allocated ? *allocated : 0,edge=base+page-2,endpoint=base+64;
        const std::array<uint8_t,6> program{0x45,0xf2,0x78,0x60,0x01,0xde};
        const std::array<uint8_t,2> branch{0x70,0x47};
        bool written=allocated && writeCode(shortInstruction ? endpoint : edge,program);
        if (shortInstruction) written=written && writeCode(edge,branch);
        auto prepared=original;prepared[15]=edge;prepared[0]=0;prepared[17]=UINT32_MAX;prepared[16]&=~uint32_t(0x0600fc00);
        if (shortInstruction) prepared[14]=endpoint|1;
        const auto permissions=armPermissions(tid,base+page);
        check(written && setBank(prepared),shortInstruction ?
            "an actual 16-bit BX LR fits at the page end and branches into mapped Thumb code" :
            "an actual 32-bit MOVW begins at the last halfword and requires both executable pages");
        const auto op=variant==1 ? ce::os::MemorySyscall::Protect : variant==2 ? ce::os::MemorySyscall::Map : ce::os::MemorySyscall::Unmap;
        std::array<uint64_t,6> args{base+page,page,0,0,0,0};
        if (variant==1) args[2]=PROT_READ;
        if (variant==2) args={base+page,page,PROT_READ|PROT_WRITE,MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS,UINT64_MAX,0};
        auto result=execute(op,args);
        check(shortInstruction ? result && *result==0 && armPermissions(tid,base+page).empty() :
            !result && result.error().code==std::errc::operation_not_permitted && !result.error().completedValue,
            shortInstruction ? "a next page outside the actual 16-bit return instruction can be unmapped" :
            "unmap, lost execute permission and MAP_FIXED cannot destroy the second half of a Thumb return instruction");
        if (shortInstruction) {
            auto repeated=execute(ce::os::MemorySyscall::Unmap,{base+page,page,0,0,0,0});
            check(repeated && *repeated==0,"a complete 16-bit Thumb prefix remains usable beside an already unmapped next page");
        }
        std::array<uint8_t,6> bytes{};std::array<uint8_t,2> afterBranch{};
        const bool code=shortInstruction ? armMemoryTransfer(tid,edge,afterBranch.data(),afterBranch.size())==afterBranch.size() && afterBranch==branch :
            armMemoryTransfer(tid,edge,bytes.data(),bytes.size())==bytes.size() && bytes==program && armPermissions(tid,base+page)==permissions;
        check(code && rawBank(tid,after) && after==prepared && ce::os::verifyNativeExtendedContext(tid,*extended) &&
            armMemoryTransfer(tid,scratch,scratchAfter.data(),scratchAfter.size())==scratchAfter.size() && scratchAfter==originalScratch,
            "the boundary operation returns exact Thumb code, full GP VFP and private syscall bytes");
        int status=0;const bool resumed=ptrace(PTRACE_CONT,tid,nullptr,nullptr)==0 && waitpid(tid,&status,__WALL)==tid && WIFSTOPPED(status);
        const bool bank=resumed && rawBank(tid,after);
        const uintptr_t trap=(shortInstruction ? endpoint : edge)+4;
        std::printf("THUMB_RETURN_BOUNDARY_OBSERVATION variant=%u instruction=%s operation=%d success=%d stop=%d pc=%x value=%x\n",
            variant,shortInstruction ? "bx2" : "movw4",int(op),bool(result),resumed ? WSTOPSIG(status) : 0,after[15],after[0]);
        check(bank && WSTOPSIG(status)==SIGTRAP && after[15]==trap && after[0]==0x5678,
            "actual Thumb execution fetches its full original instruction and reaches its owned UDF with the expected value");
        const bool restored=resumed && setBank(original);
        auto freed=execute(ce::os::MemorySyscall::Unmap,{base,2*page,0,0,0,0});
        check(allocated && restored && freed && armPermissions(tid,base).empty() && armPermissions(tid,base+page).empty() &&
            rawBank(tid,after) && after==original && ce::os::verifyNativeExtendedContext(tid,*extended),
            "the owner restores the original live Thumb IT context and reclaims both boundary pages");
    }
}
