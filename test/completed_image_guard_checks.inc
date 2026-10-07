#if defined(__x86_64__)
static void completedImageGuardBackend(const char* path) {
    const int initial=failures;unsigned count=0;
    auto require=[&](bool ok,const char* name) {
        ++count;failures+=!ok;
        std::printf("COMPLETED_IMAGE_GUARD_CHECK %s: %s\n",ok ? "OK" : "FAILED",name);fflush(stdout);
    };
    struct Reaper {
        int original=-1;bool active=false;
        bool enable() {active=prctl(PR_GET_CHILD_SUBREAPER,&original)==0 && prctl(PR_SET_CHILD_SUBREAPER,1)==0;return active;}
        bool restore() {if (!active) return false;int actual=-1;bool ok=prctl(PR_SET_CHILD_SUBREAPER,original)==0 &&
            prctl(PR_GET_CHILD_SUBREAPER,&actual)==0 && actual==original;if(ok) active=false;return ok;}
        ~Reaper() {if(active) prctl(PR_SET_CHILD_SUBREAPER,original);}
    } reaper;
    require(reaper.enable(),"the controller can reap a CLONE_VM descendant and records its original subreaper setting");
    if (!reaper.active) return;
    const long page=sysconf(_SC_PAGESIZE);
    for (unsigned variant=0;variant<4;++variant) {
        const bool replaced=variant==1 || variant==2,peerGuard=variant==3;
        struct Peer {
            pid_t pid=-1;
            bool cleanup() {if(pid<0) return true;kill(pid,SIGKILL);int status=0;
                auto until=std::chrono::steady_clock::now()+std::chrono::seconds(2);
                while(std::chrono::steady_clock::now()<until) {
                    auto found=waitpid(pid,&status,__WALL|__WNOTHREAD|WNOHANG);
                    if(found==pid) {pid=-1;return WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL;}
                    if(found<0 && errno!=EINTR) break;usleep(1000);
                }return false;
            }
            ~Peer() {if(pid>0 && !cleanup()) {++failures;std::fprintf(stderr,"FAILED: completed-image peer cleanup\n");}}
        } owner;
        Fixture fixture(path,peerGuard ? "--keepalive" : nullptr);const auto banner=fixture.line();
        long main=0,peer=0;int value=0;
        const bool ready=std::sscanf(banner.c_str(),"SHARED_READY pid=%ld peer=%ld value=%d",&main,&peer,&value)==3 &&
            main==fixture.pid && peer>0 && value==42;
        require(ready,"the real target has a separate untraced CLONE_VM memory peer");if(!ready) return;
        owner.pid=peer;
        LinuxProcessHandle process(fixture.pid);auto host=process.targetDescription().host;
        auto identity=targetProcessIdentity(fixture.pid);
        auto image=identity ? NativeMemoryImage::capture(*identity,host) :
            std::expected<std::shared_ptr<NativeMemoryImage>,std::error_code>(std::unexpected(std::make_error_code(std::errc::io_error)));
        auto scratch=process.allocate(page,MemProt::Read|MemProt::Write|MemProt::Exec);
        require(identity && image && scratch && page>0,"the controller pins the original mm and creates its private scratch");
        if(!identity || !image || !scratch) return;
        char command='B';int status=0;
        bool owned=::write(fixture.input,&command,1)==1 && fixture.line()=="SHARED_BUSY" &&
            ptrace(PTRACE_SEIZE,fixture.pid,nullptr,reinterpret_cast<void*>(PTRACE_O_TRACESYSGOOD))==0 &&
            ptrace(PTRACE_INTERRUPT,fixture.pid,nullptr,nullptr)==0 && restartBoundaryStop(fixture.pid,status);
        require(owned,"the caller owns an actual user-mode stop before its completed memory operation");if(!owned) return;
        syscall_test::arm(syscall_test::Fault::RestoreRegisters);
        auto allocated=executeStoppedMemorySyscall(fixture.pid,host,MemorySyscall::Map,
            {0,static_cast<uint64_t>(page),3,MAP_PRIVATE|MAP_ANONYMOUS,UINT64_MAX,0},*scratch);
        syscall_test::clear();
        bool retained=!allocated && allocated.error().completedValue && allocated.error().recovery;
        require(retained,"a real completed mmap retains its original image ticket after register restoration fails");if(!retained) return;
        auto ticket=allocated.error().recovery;uintptr_t allocation=*allocated.error().completedValue;
        require(ticket->retry() && ticket->retry() && ticket->checkImage(),"recovery completes and remains idempotent while its task and old mm are live");
        const uint8_t cookie=0xa7;
        require(writeMemory(fixture.pid,allocation,&cookie,1)==1,"the old allocation contains an independently chosen byte");
        if(variant==2) {
            auto freed=executeOwnedMemorySyscall(fixture.pid,host,MemorySyscall::Unmap,{*scratch,static_cast<uint64_t>(page),0,0,0,0});
            require(freed && boundaryPermissions(fixture.pid,*scratch).empty(),"the caller releases its old scratch before reusing the completed ticket");
        }
        pid_t selected=fixture.pid;
        if(replaced) {
            const uint8_t clear=0;command='X';
            bool exec=writeMemory(fixture.pid,0x31000008,&clear,1)==1 && ptrace(PTRACE_DETACH,fixture.pid,nullptr,nullptr)==0 &&
                fixture.line()=="SHARED_RESUMED" && ::write(fixture.input,&command,1)==1 && fixture.line().starts_with("SHARED_READY ");
            command='B';exec=exec && ::write(fixture.input,&command,1)==1 && fixture.line()=="SHARED_BUSY" &&
                ptrace(PTRACE_SEIZE,fixture.pid,nullptr,reinterpret_cast<void*>(PTRACE_O_TRACESYSGOOD))==0 &&
                ptrace(PTRACE_INTERRUPT,fixture.pid,nullptr,nullptr)==0 && restartBoundaryStop(fixture.pid,status);
            auto actual=targetProcessIdentity(fixture.pid);
            auto recreated=exec ? executeOwnedMemorySyscall(fixture.pid,host,MemorySyscall::Map,
                {allocation,static_cast<uint64_t>(page),3,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,UINT64_MAX,0}) :
                std::expected<uint64_t,TargetSyscallFailure>(std::unexpected(std::make_error_code(std::errc::io_error)));
            require(exec && actual && *actual==*identity && recreated && *recreated==allocation &&
                writeMemory(fixture.pid,allocation,&cookie,1)==1,
                "same-file exec preserves PID, birth and inode but recreates a private allocation at the old address with identical bytes");
            if(!exec || !recreated) return;
        } else if(peerGuard) {
            bool killed=kill(fixture.pid,SIGKILL)==0,exited=false;
            auto until=std::chrono::steady_clock::now()+std::chrono::seconds(2);
            while(killed && !exited && std::chrono::steady_clock::now()<until) {
                auto found=waitpid(fixture.pid,&status,__WALL|__WNOTHREAD|WNOHANG);
                exited=found==fixture.pid && WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL;if(!exited) usleep(1000);
            }
            require(exited && (*image)->check() && kill(peer,0)==0,"the real original task dies while its untraced peer keeps the pinned mm alive");
            if(!exited) return;fixture.pid=-1;selected=peer;
            owned=ptrace(PTRACE_SEIZE,peer,nullptr,reinterpret_cast<void*>(PTRACE_O_TRACESYSGOOD))==0 &&
                ptrace(PTRACE_INTERRUPT,peer,nullptr,nullptr)==0 && restartBoundaryStop(peer,status);
            require(owned,"the same controller explicitly owns the surviving peer's actual interrupted kernel wait");if(!owned) return;
        }
        user_regs_struct before{},after{};uint64_t mask=0,afterMask=0;std::array<uint8_t,16> bytes{},afterBytes{};
        auto banks=captureNativeExtendedContext(selected);
        bool captured=banks && ptrace(PTRACE_GETREGS,selected,nullptr,&before)==0 &&
            ptrace(PTRACE_GETSIGMASK,selected,reinterpret_cast<void*>(sizeof(mask)),&mask)==0 &&
            readMemory(selected,0x30000000,bytes.data(),bytes.size())==ssize_t(bytes.size());
        const auto maps=[&] {std::ifstream file("/proc/"+std::to_string(selected)+"/maps");return std::string(std::istreambuf_iterator<char>(file),{});};
        const auto originalMaps=maps();uint8_t oldByte=0;auto oldRead=(*image)->read(allocation,&oldByte,1);
        require(captured && oldRead && *oldRead==1 && oldByte==cookie && !originalMaps.empty(),
            "independent snapshots capture complete selected context, mappings, code and the still-readable original allocation");if(!captured) return;
        auto result=executeOwnedMemorySyscall(selected,host,MemorySyscall::Unmap,{allocation,static_cast<uint64_t>(page),0,0,0,0},*ticket);
        const bool acceptable=replaced ? !result && result.error().code==std::errc::operation_canceled && !result.error().completedValue && !result.error().recovery : result.has_value();
        require(acceptable,replaced ? "a completed ticket rejects unmapping the replacement's identical-address allocation" :
            "a completed ticket permits cleanup in its actual original mm, including through the explicitly owned surviving peer");
        bool unchanged=ptrace(PTRACE_GETREGS,selected,nullptr,&after)==0 && !std::memcmp(&before,&after,sizeof(before)) &&
            verifyNativeExtendedContext(selected,*banks) && ptrace(PTRACE_GETSIGMASK,selected,reinterpret_cast<void*>(sizeof(afterMask)),&afterMask)==0 &&
            mask==afterMask && readMemory(selected,0x30000000,afterBytes.data(),afterBytes.size())==ssize_t(afterBytes.size()) && bytes==afterBytes && fixtureTracer(selected)==getpid();
        require(unchanged,"guard success or rejection preserves every GP/extended register, signal mask, program byte and actual ptrace owner");
        if(replaced) {
            uint8_t current=0;auto old=(*image)->read(allocation,&oldByte,1);
            require(readMemory(selected,allocation,&current,1)==1 && current==cookie && maps()==originalMaps && old && *old==1 && oldByte==cookie,
                "guard rejection leaves the replacement mapping and bytes intact, releases its proof mapping and preserves old-mm bytes");
            auto cleanup=executeOwnedMemorySyscall(selected,host,MemorySyscall::Unmap,{allocation,static_cast<uint64_t>(page),0,0,0,0});
            require(cleanup.has_value(),"the actual replacement owner can release its own allocation after rejection");
        } else {
            auto absent=(*image)->read(allocation,&oldByte,1);
            require(!absent && absent.error()==std::errc::io_error && boundaryPermissions(selected,allocation).empty() && (*image)->check(),
                "successful cleanup independently removes the old allocation while its original mm remains alive");
        }
        if(peerGuard) {
            require(ptrace(PTRACE_DETACH,peer,nullptr,nullptr)==0 && owner.cleanup(),"the controller releases and actually kills/reaps the adopted peer after independent cleanup");
        } else {
            if(!replaced) executeOwnedMemorySyscall(selected,host,MemorySyscall::Unmap,{*scratch,static_cast<uint64_t>(page),0,0,0,0});
            const uint8_t clear=0;command='E';
            bool console=writeMemory(selected,0x31000008,&clear,1)==1 && ptrace(PTRACE_DETACH,selected,nullptr,nullptr)==0 &&
                fixture.line()=="SHARED_RESUMED" && ::write(fixture.input,&command,1)==1 &&
                fixture.line()==(replaced ? "SHARED_VALUE=55" : "SHARED_VALUE=42");
            command='Q';int terminal=0;
            bool reaped=console && ::write(fixture.input,&command,1)==1 && waitpid(selected,&terminal,0)==selected && WIFEXITED(terminal) && WEXITSTATUS(terminal)==0;
            require(reaped && kill(peer,0)<0 && errno==ESRCH,"the actual main and CLONE_VM peer finish normal console work and are both reaped");
            if(reaped) {fixture.pid=-1;owner.pid=-1;}
        }
        auto dead=(*image)->check();
        require(!dead && dead.error()==std::errc::operation_canceled,"only final actual process cleanup retires the independently pinned old mm");
        std::printf("COMPLETED_IMAGE_GUARD_OBSERVATION variant=%u result=%d error=%d replacement=%d peer=%d\n",variant,bool(result),result ? 0 : result.error().code.value(),replaced,peerGuard);
    }
    require(reaper.restore(),"the controller restores its exact original process-local subreaper setting");
    std::printf("COMPLETED_IMAGE_GUARD_RESULT=%s architecture=x86-64 checks=%u\n",initial==failures ? "PASSED" : "FAILED",count);
}
#endif
