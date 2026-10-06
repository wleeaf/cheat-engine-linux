static ssize_t armMemoryTransfer(pid_t tid,uintptr_t address,void* bytes,size_t size,bool writing=false) {
    iovec local{bytes,size},remote{reinterpret_cast<void*>(address),size};
    return writing ? process_vm_writev(tid,&local,1,&remote,1,0) : process_vm_readv(tid,&local,1,&remote,1,0);
}
static std::string armMaps(pid_t tid) {
    std::ifstream stream("/proc/"+std::to_string(tid)+"/maps");
    return std::string(std::istreambuf_iterator<char>(stream),{});
}
static std::string armPermissions(pid_t tid,uintptr_t address) {
    std::istringstream maps(armMaps(tid));std::string line;
    while (std::getline(maps,line)) {
        unsigned long long first=0,last=0;char permissions[5]{};
        if (std::sscanf(line.c_str(),"%llx-%llx %4s",&first,&last,permissions)==3 && address>=first && address<last)
            return permissions;
    }
    return {};
}
static void arm32Memory(pid_t tid,uintptr_t scratch,int file,uintptr_t applicationSignal,const char* fixture,Checks& check) {
    std::ifstream executable(fixture,std::ios::binary); std::array<uint8_t,64> header{};
    executable.read(reinterpret_cast<char*>(header.data()),header.size());
    auto machine=parseElfTarget({header.data(),static_cast<size_t>(executable.gcount())});
    check(machine && machine->architecture==CpuArchitecture::Arm32 && machine->abi==TargetAbi::LinuxArmEabi &&
          machine->pointerWidth==4 && scratch && scratch<=UINT32_MAX && file>=0,
          "the actual ELF32 target supplies private scratch and a real sparse-file descriptor");
    if (!machine || !scratch || file<0) return;
    Bank original{},observed{};std::array<uint8_t,16> code{},codeAfter{};
    auto extended=ce::os::captureNativeExtendedContext(tid);
    const bool snapshot=rawBank(tid,original) && extended && armMemoryTransfer(tid,scratch,code.data(),code.size())==code.size();
    check(snapshot,"the memory executor starts with independent full GP VFP and private-code snapshots");
    if (!snapshot) return;
    const auto intact=[&] {
        return rawBank(tid,observed) && observed==original && ce::os::verifyNativeExtendedContext(tid,*extended) &&
            armMemoryTransfer(tid,scratch,codeAfter.data(),codeAfter.size())==codeAfter.size() && codeAfter==code;
    };
    const auto execute=[&](ce::os::MemorySyscall operation,std::array<uint64_t,6> args,uintptr_t at=0) {
        return ce::os::executeStoppedMemorySyscall(tid,*machine,operation,args,at ? at : scratch);
    };
    const auto mapArgs=std::array<uint64_t,6>{0,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,UINT64_MAX,0};
    auto mapped=execute(ce::os::MemorySyscall::Map,mapArgs);
    if (!mapped) std::printf("ARM32_MEM_DIAGNOSTIC mode=%s error=%d recovery=%d\n",check.mode,mapped.error().code.value(),bool(mapped.error().recovery));
    const uintptr_t address=mapped ? *mapped : 0;
    check(mapped && address && address<=UINT32_MAX,"the product executes an actual ARM32 mmap2 and returns its mapping");
    check(address && armPermissions(tid,address)=="rw-p","the kernel publishes the actual requested target mapping permissions");
    uint64_t value=UINT64_C(0x123456789abcdef0),readback=0;
    check(address && armMemoryTransfer(tid,address,&value,sizeof(value),true)==sizeof(value) &&
          armMemoryTransfer(tid,address,&readback,sizeof(readback))==sizeof(readback) && readback==value,
          "the new target page can be independently read and edited");
    check(intact(),"mmap returns the exact GP VFP and private code snapshots to the stopped owner");
    auto protectedPage=execute(ce::os::MemorySyscall::Protect,{address,4096,PROT_READ,0,0,0});
    check(address && protectedPage && *protectedPage==0 && armPermissions(tid,address)=="r--p",
          "ARM32 mprotect changes actual target permissions without altering the original program");
    errno=0;const auto refused=armMemoryTransfer(tid,address,&value,sizeof(value),true);
    check(address && refused<0 && errno==EFAULT && intact(),"read-only target pages reject independent writes and retain the original context");
    auto writable=execute(ce::os::MemorySyscall::Protect,{address,4096,PROT_READ|PROT_WRITE,0,0,0});
    check(address && writable && *writable==0 && armPermissions(tid,address)=="rw-p" && intact(),
          "actual write protection is restored through the same private syscall owner");
    auto badAlignment=execute(ce::os::MemorySyscall::Protect,{address+1,1,PROT_READ,0,0,0});
    check(!badAlignment && badAlignment.error().code==std::errc::invalid_argument && !badAlignment.error().completedValue && intact(),
          "a kernel EINVAL result is not mistaken for a mapping and restores the original context");
    auto tooWide=mapArgs;tooWide[1]=UINT64_C(0x100000000);
    auto overflow=execute(ce::os::MemorySyscall::Map,tooWide);
    check(!overflow && overflow.error().code==std::errc::invalid_argument && intact(),
          "oversized ARM32 arguments are rejected before mutating code or registers");
    auto badScratch=execute(ce::os::MemorySyscall::Map,mapArgs,scratch+1);
    check(!badScratch && badScratch.error().code==std::errc::invalid_argument && intact(),
          "misaligned private ARM or Thumb instruction sites are rejected without mutation");
    const uint64_t returnPage=original[15]-original[15]%4096;
    auto destroyReturn=execute(ce::os::MemorySyscall::Unmap,{returnPage,4096,0,0,0,0});
    check(!destroyReturn && destroyReturn.error().code==std::errc::operation_not_permitted &&
          !armPermissions(tid,original[15]).empty() && intact(),
          "the original return-code page cannot be unmapped while using a different private scratch page");
    auto destroyScratch=execute(ce::os::MemorySyscall::Unmap,{scratch,4096,0,0,0,0});
    check(!destroyScratch && destroyScratch.error().code==std::errc::operation_not_permitted && intact(),
          "the private syscall and return-trap page cannot unmap itself");
    auto fixed=mapArgs;fixed[0]=returnPage;fixed[3]|=MAP_FIXED;
    auto replaceReturn=execute(ce::os::MemorySyscall::Map,fixed);
    check(!replaceReturn && replaceReturn.error().code==std::errc::operation_not_permitted && intact(),
          "MAP_FIXED cannot replace the original code restored after a private syscall");
    auto fileArgs=mapArgs;fileArgs[3]=MAP_PRIVATE;fileArgs[4]=file;fileArgs[5]=(UINT64_C(6)*1024*1024*1024)/4096;
    auto fileMap=execute(ce::os::MemorySyscall::Map,fileArgs);uint64_t marker=0;
    check(fileMap && armMemoryTransfer(tid,*fileMap,&marker,sizeof(marker))==sizeof(marker) && marker==UINT64_C(0x445566778899aabb) && intact(),
          "mmap2 maps actual sparse-file data above four GiB using page-based offsets");
    auto fileFree=fileMap ? execute(ce::os::MemorySyscall::Unmap,{*fileMap,4096,0,0,0,0}) : decltype(mapped)(std::unexpected(ce::os::TargetSyscallFailure(std::make_error_code(std::errc::invalid_argument))));
    check(fileMap && fileFree && armPermissions(tid,*fileMap).empty() && intact(),
          "the high-offset file mapping is reclaimed without changing other target memory");
    const auto beforeFault=armMaps(tid);
    memoryFaultTarget=tid;droppedMemoryPatches=0;dropMemoryPatch=true;
    auto patchFailure=execute(ce::os::MemorySyscall::Map,mapArgs);
    memoryFaultTarget=0;dropMemoryPatch=false;
    check(!patchFailure && droppedMemoryPatches==1 && patchFailure.error().code==std::errc::io_error &&
          !patchFailure.error().completedValue && armMaps(tid)==beforeFault && intact(),
          "a falsely successful private-code write is rejected before target execution and leaves no mapping");
    armFault(tid,false);
    auto setupFailure=execute(ce::os::MemorySyscall::Map,mapArgs);
    clearArmFault();
    check(!setupFailure && forwardedMutation && !setupFailure.error().completedValue &&
          armMaps(tid)==beforeFault && intact(),
          "an error after a real injected-register write rolls back before any syscall or new mapping");
    memoryFaultTarget=tid;memoryRan=false;refuseMemoryRestore=true;
    auto restoreFailure=execute(ce::os::MemorySyscall::Map,mapArgs);
    memoryFaultTarget=0;refuseMemoryRestore=false;
    const bool retained=!restoreFailure && restoreFailure.error().code==std::errc::state_not_recoverable &&
        restoreFailure.error().recovery && restoreFailure.error().completedValue && memoryRan;
    check(retained && rawBank(tid,observed) && observed!=original,
          "a completed real mmap retains its value and stopped recovery owner when GP restoration fails");
    bool wrongOwner=false;
    if (retained) {
        std::thread other([&] {auto result=restoreFailure.error().recovery->retry();wrongOwner=!result && result.error()==std::errc::operation_not_permitted;});other.join();
    }
    check(wrongOwner,"failed ARM32 syscall restoration refuses a different host ptrace owner");
    const bool recovered=retained && restoreFailure.error().recovery->retry().has_value() &&
        restoreFailure.error().recovery->retry().has_value();
    check(recovered && intact(),"verified restoration retry returns the exact original context and is idempotent");
    auto orphanFree=retained ? execute(ce::os::MemorySyscall::Unmap,{*restoreFailure.error().completedValue,4096,0,0,0,0}) :
        decltype(mapped)(std::unexpected(ce::os::TargetSyscallFailure(std::make_error_code(std::errc::invalid_argument))));
    check(recovered && orphanFree && armMaps(tid)==beforeFault && intact(),
          "the recovered completed mmap is reclaimed without leaking private target storage");
    auto unmapped=execute(ce::os::MemorySyscall::Unmap,{address,4096,0,0,0,0});
    check(address && unmapped && armPermissions(tid,address).empty() &&
          armMemoryTransfer(tid,address,&readback,sizeof(readback))<0 && intact(),
          "actual ARM32 munmap removes the target page and restores all original executable bytes");
    auto callAbi=ce::os::checkStoppedFunctionAbi(tid,*machine);
    check(!callAbi && callAbi.error()==std::errc::not_supported && intact(),
          "an ARM32 context cannot accidentally enter the native AArch64 function-call ABI");
    const auto beforeSignal=armMaps(tid);
    memoryFaultTarget=tid;sendMemorySignal=true;memorySignalSent=false;
    auto interrupted=execute(ce::os::MemorySyscall::Map,mapArgs);
    memoryFaultTarget=0;sendMemorySignal=false;
    std::printf("ARM32_MEM_SIGNAL_DIAGNOSTIC mode=%s success=%d sent=%d error=%d pending=%d completed=%d maps=%d intact=%d\n",
        check.mode,bool(interrupted),memorySignalSent,interrupted ? 0 : interrupted.error().code.value(),
        interrupted ? 0 : interrupted.error().pendingSignal,!interrupted && interrupted.error().completedValue.has_value(),
        armMaps(tid)==beforeSignal,intact());
    check(!interrupted && memorySignalSent && interrupted.error().code==std::errc::interrupted &&
          interrupted.error().pendingSignal==SIGUSR2 && !interrupted.error().completedValue && armMaps(tid)==beforeSignal && intact(),
          "a genuine application signal before private syscall execution retains delivery and creates no mapping");
    const bool resumed=!interrupted && interrupted.error().pendingSignal==SIGUSR2 &&
        ptrace(PTRACE_CONT,tid,nullptr,reinterpret_cast<void*>(uintptr_t(SIGUSR2)))==0;
    uint32_t delivered=0;bool stopped=false;
    if (resumed) {
        for (unsigned attempt=0;attempt<100 && delivered!=1;++attempt) {
            usleep(1000);armMemoryTransfer(tid,applicationSignal,&delivered,sizeof(delivered));
        }
        int status=0;stopped=ptrace(PTRACE_INTERRUPT,tid,nullptr,nullptr)==0 && waitpid(tid,&status,__WALL)==tid && WIFSTOPPED(status);
    }
    check(resumed && stopped && delivered==1 && armMemoryTransfer(tid,applicationSignal,&delivered,sizeof(delivered))==sizeof(delivered) && delivered==1,
          "the original target handles the preserved signal exactly once and returns to a real owned stop");

}

static void thumbMemoryIt(pid_t tid,uintptr_t scratch,const char* fixture,Checks& check) {
    Bank original{},after{};std::array<uint8_t,16> code{},afterCode{};
    auto extended=ce::os::captureNativeExtendedContext(tid);
    const bool ready=rawBank(tid,original) && (original[16]&0x0600fc00u) && (original[16]&0x20u) && extended &&
        armMemoryTransfer(tid,scratch,code.data(),code.size())==code.size();
    check(ready,"actual Thumb execution stopped inside a live conditional IT block with independent GP VFP and code snapshots");
    if (!ready) return;
    std::ifstream executable(fixture,std::ios::binary);std::array<uint8_t,64> header{};
    executable.read(reinterpret_cast<char*>(header.data()),header.size());
    auto machine=parseElfTarget({header.data(),static_cast<size_t>(executable.gcount())});
    const auto intact=[&] {return rawBank(tid,after) && after==original && ce::os::verifyNativeExtendedContext(tid,*extended) &&
        armMemoryTransfer(tid,scratch,afterCode.data(),afterCode.size())==afterCode.size() && afterCode==code;};
    if (!machine) {check(false,"actual IT fixture retains its ELF32 ABI");return;}
    auto mapped=ce::os::executeStoppedMemorySyscall(tid,*machine,ce::os::MemorySyscall::Map,
        {0,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,UINT64_MAX,0},scratch);
    check(mapped && armPermissions(tid,*mapped)=="rw-p","private mmap2 executes both SVC and its trap independently of the original IT conditions");
    check(intact(),"private completion restores the exact live Thumb IT state with every GP VFP and code byte");
    auto freed=mapped ? ce::os::executeStoppedMemorySyscall(tid,*machine,ce::os::MemorySyscall::Unmap,
        {*mapped,4096,0,0,0,0},scratch) : decltype(mapped)(std::unexpected(ce::os::TargetSyscallFailure(std::make_error_code(std::errc::invalid_argument))));
    check(mapped && freed && armPermissions(tid,*mapped).empty() && intact(),"private munmap restores the same conditional Thumb return and reclaims its actual mapping");
}

#if defined(__aarch64__)
static void native64ReturnGuard(pid_t tid,uintptr_t scratch,Checks& check) {
    auto context=ce::os::readNativeContext(tid);
    auto extended=ce::os::captureNativeExtendedContext(tid);
    std::array<uint64_t,34> original{},observed{};
    const auto bank=[&](auto& values) {
        iovec io{values.data(),sizeof(values)};
        return ptrace(PTRACE_GETREGSET,tid,reinterpret_cast<void*>(NT_PRSTATUS),&io)==0 && io.iov_len==sizeof(values);
    };
    std::array<uint8_t,4096> page{},afterPage{};std::array<uint8_t,16> code{},afterCode{};
    const uintptr_t returnPage=context ? context->pc-context->pc%4096 : 0;
    const auto permissions=armPermissions(tid,returnPage);
    const bool ready=context && context->architecture==CpuArchitecture::Arm64 && extended && scratch && returnPage &&
        scratch/4096!=returnPage/4096 && bank(original) &&
        armMemoryTransfer(tid,returnPage,page.data(),page.size())==page.size() &&
        armMemoryTransfer(tid,scratch,code.data(),code.size())==code.size();
    check(ready,"actual native ARM64 code and separate private scratch have independent full snapshots");
    if (!ready) return;
    auto unmap=ce::os::executeStoppedMemorySyscall(tid,nativeTargetMachine(),ce::os::MemorySyscall::Unmap,
        {returnPage,4096,0,0,0,0},scratch);
    const bool removed=armPermissions(tid,returnPage).empty();
    std::printf("AARCH64_RETURN_GUARD_OBSERVATION removed=%d succeeded=%d completed=%d\n",removed,bool(unmap),!unmap && unmap.error().completedValue.has_value());
    check(!unmap && unmap.error().code==std::errc::operation_not_permitted && !removed,
          "the native ARM64 executor refuses to unmap its original code while using separate private scratch");
    check(!removed && armPermissions(tid,returnPage)==permissions &&
        armMemoryTransfer(tid,returnPage,afterPage.data(),afterPage.size())==afterPage.size() && page==afterPage,
        "the actual original code page retains its permissions and every byte after refusal");
    check(bank(observed) && observed==original && ce::os::verifyNativeExtendedContext(tid,*extended) &&
        armMemoryTransfer(tid,scratch,afterCode.data(),afterCode.size())==afterCode.size() && code==afterCode,
        "native ARM64 refusal preserves the full original register banks and private instructions");
    // A preserved unsafe baseline can remove this owned child's return code.
    // The surrounding Child owner terminates it instead of resuming invalid code.
}
#endif
