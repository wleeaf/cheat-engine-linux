#if defined(__x86_64__)
static void mixedAbiRestartBackend(const char* path,bool groupOnly=false,unsigned lifecycle=0) {
    const int initial=failures;unsigned count=0;CpuArchitecture architecture=CpuArchitecture::Unknown;
    const auto require=[&](bool ok,const char* name) {
        ++count;failures+=!ok;
        std::printf("%s_CHECK %s: %s\n",lifecycle ? "MIXED_ABI_LIFECYCLE" : "MIXED_ABI_RESTART",ok ? "OK" : "FAILED",name);fflush(stdout);
    };
    const bool sharedDeath=lifecycle>=5,death=lifecycle==1 || sharedDeath;
    struct Subreaper {
        int original=-1;bool active=false;
        bool enable() {
            active=prctl(PR_GET_CHILD_SUBREAPER,&original)==0 && prctl(PR_SET_CHILD_SUBREAPER,1)==0;
            return active;
        }
        bool restore() {
            if (!active) return original>=0;
            int actual=-1;const bool restored=prctl(PR_SET_CHILD_SUBREAPER,original)==0 &&
                prctl(PR_GET_CHILD_SUBREAPER,&actual)==0 && actual==original;
            if (restored) active=false;
            return restored;
        }
        ~Subreaper() {if (active) restore();}
    } reaper;
    if (sharedDeath) {require(reaper.enable(),"the isolated controller owns and can reap its surviving CLONE_VM descendants");if (!reaper.active) return;}
    struct PeerOwner {
        pid_t pid=-1;
        bool cleanup() {
            if (pid<0) return true;
            const bool killed=kill(pid,SIGKILL)==0;int status=0;
            const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
            while (std::chrono::steady_clock::now()<deadline) {
                auto found=waitpid(pid,&status,__WALL|__WNOTHREAD|WNOHANG);
                if (found==pid) {pid=-1;return killed && WIFSIGNALED(status) && WTERMSIG(status)==SIGKILL;}
                if (found<0 && errno!=EINTR) break;
                usleep(1000);
            }
            return false;
        }
        ~PeerOwner() {if (pid>0 && !cleanup()) {++failures;std::fprintf(stderr,"FAILED: surviving CLONE_VM peer cleanup\n");}}
    };
    using Fault=syscall_test::Fault;
    const std::array<Fault,14> faults{Fault::RestartInfoAfterStep,Fault::RestartEmulateBefore,Fault::RestartEmulateAfter,
        Fault::RestartEntryRead,Fault::RestartInterruptBefore,Fault::RestartInterruptAfter,Fault::RestartResumeAfter,Fault::RestartVerification,Fault::RestartMaskRead,Fault::RestartMaskWriteBefore,
        Fault::RestartMaskWriteAfter,Fault::RestartMaskVerify,Fault::RestartMaskRestoreAfter,Fault::RestartResumeBefore};
    const std::array<Fault,4> stops{Fault::RestartQueuedStop,Fault::RestartCanceledStop,Fault::RestartListenBefore,Fault::RestartListenAfter};
    for (unsigned variant=lifecycle ? 4 : groupOnly ? 5+faults.size() : 0;variant<5+faults.size()+stops.size();++variant) {
        if (architecture==CpuArchitecture::X86_32 && variant!=0 && variant!=2) continue;
        // Skip unused rows before forking, especially independent mm peers.
        if (lifecycle && (variant==4+faults.size() || variant==6+faults.size() ||
            (!death && variant>4+faults.size()))) continue;
        if ((lifecycle==4 || lifecycle==6) && variant!=12 && variant!=14) continue;
        PeerOwner peerOwner;
        Fixture fixture(path,sharedDeath ? "--keepalive" : nullptr);const auto line=fixture.line();
        LinuxProcessHandle process(fixture.pid);const auto host=process.targetDescription().host;
        architecture=host.architecture;
        if ((groupOnly || lifecycle) && (architecture!=CpuArchitecture::X86_64 || host.abi!=TargetAbi::LinuxX86_64)) {
            require(false,"focused mixed-ABI group-stop proof requires an actual ELF64 target");return;
        }
        const bool mixed=architecture==CpuArchitecture::X86_64 && variant!=0,edited=variant>=2;
        const bool compat=architecture==CpuArchitecture::X86_32 || mixed,direct=variant==3,queued=variant==4+faults.size(),job=variant>4+faults.size(),faulted=variant>=4 && !queued && !job;
        const bool canceled=job && stops[variant-5-faults.size()]==Fault::RestartCanceledStop;
        const bool listenFailure=job && variant>=7+faults.size();
        if (lifecycle && ((!faulted && !job) || canceled || (!death && job))) continue;
        const bool shared=lifecycle>=3,identical=lifecycle==4;
        pid_t peer=-1;
        if (shared) std::sscanf(line.c_str(),"SHARED_READY pid=%*d peer=%d value=42",&peer);
        if (sharedDeath) peerOwner.pid=peer;
        require(shared ? line.starts_with("SHARED_READY ") && peer>0 : line.starts_with("CE_TARGET "),
            "timed restart fixture is an actual native application");
        const size_t page=sysconf(_SC_PAGESIZE);
        auto scratch=process.allocate(page,MemProt::All);
        auto storage=executeMemorySyscall(fixture.pid,host,MemorySyscall::Map,
            {0,3*page,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS|(mixed ? MAP_32BIT : 0),UINT64_MAX,0});
        require(scratch && storage && (!compat || *storage+3*page<=UINT32_MAX),
            "real code pair and timer data use valid syscall-ABI addresses beside separate private scratch");
        if (!scratch || !storage) return;
        const uintptr_t edge=*storage+page-2,after=edge+2,buffer=*storage+2*page;
        const uintptr_t scratchSite=identical ? *scratch+page-2 : *scratch;
        int status=0;user_regs_struct original{};uint64_t mask=0;
        const bool owned=ptrace(PTRACE_SEIZE,fixture.pid,nullptr,reinterpret_cast<void*>(PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACEEXEC))==0 &&
            ptrace(PTRACE_INTERRUPT,fixture.pid,nullptr,nullptr)==0 && restartBoundaryStop(fixture.pid,status) &&
            ptrace(PTRACE_GETREGS,fixture.pid,nullptr,&original)==0 &&
            ptrace(PTRACE_GETSIGMASK,fixture.pid,reinterpret_cast<void*>(sizeof(mask)),&mask)==0;
        const uint64_t applicationMask=mask;
        mask|=uint64_t{1}<<(SIGUSR1-1);
        const bool configured=owned && ptrace(PTRACE_SETSIGMASK,fixture.pid,reinterpret_cast<void*>(sizeof(mask)),&mask)==0 &&
            ptrace(PTRACE_GETSIGMASK,fixture.pid,reinterpret_cast<void*>(sizeof(mask)),&mask)==0 &&
            (mask&(uint64_t{1}<<(SIGUSR1-1)));
        auto extended=owned ? captureNativeExtendedContext(fixture.pid) :
            std::expected<NativeExtendedContext,std::error_code>(std::unexpected(std::make_error_code(std::errc::io_error)));
        std::array<uint8_t,32> savedScratch{},scratchAfter{};
        require(configured && extended && readMemory(fixture.pid,*scratch,savedScratch.data(),savedScratch.size())==savedScratch.size(),
            "caller captures complete original GP, extended state, signal mask and scratch bytes");
        if (!configured || !extended) return;
        std::shared_ptr<NativeMemoryImage> retained;
        if (shared) {
            auto identity=processMemoryIdentity(fixture.pid);
            auto image=identity ? NativeMemoryImage::capture(*identity,host) :
                std::expected<std::shared_ptr<NativeMemoryImage>,std::error_code>(std::unexpected(std::make_error_code(std::errc::io_error)));
            require(image.has_value(),"the fixture independently pins the original mm kept alive by a real CLONE_VM process");
            if (!image) return;
            retained=*image;
        }
        const std::array<uint8_t,3> code=compat ? std::array<uint8_t,3>{0xcd,0x80,0xcc} : std::array<uint8_t,3>{0x0f,0x05,0xcc};
        const std::array<int64_t,2> duration64{2,0};const std::array<int32_t,2> duration32{2,0};
        const uint64_t number=compat ? 162 : 35|(host.abi==TargetAbi::LinuxX32 ? 0x40000000 : 0);
        auto prepared=original;prepared.rip=edge;prepared.orig_rax=UINT64_MAX;prepared.rax=number;
        if (compat) {prepared.rbx=buffer;prepared.rcx=0;} else {prepared.rdi=buffer;prepared.rsi=0;}
        require(writeMemory(fixture.pid,edge,code.data(),code.size())==code.size() &&
            (compat ? writeMemory(fixture.pid,buffer,duration32.data(),sizeof(duration32))==sizeof(duration32) :
                writeMemory(fixture.pid,buffer,duration64.data(),sizeof(duration64))==sizeof(duration64)) &&
            ptrace(PTRACE_SETREGS,fixture.pid,nullptr,&prepared)==0,
            "the target owns a two-second nanosleep ending at the page boundary beside INT3");
        const auto started=std::chrono::steady_clock::now();
        bool blocked=false;std::string syscallLine;
        if (ptrace(PTRACE_CONT,fixture.pid,nullptr,nullptr)==0) {
            const auto deadline=started+std::chrono::seconds(3);
            while (!blocked && std::chrono::steady_clock::now()<deadline) {
                std::ifstream in("/proc/"+std::to_string(fixture.pid)+"/syscall");std::getline(in,syscallLine);
                int64_t actual=-1;std::array<uint64_t,8> arguments{};std::istringstream fields(syscallLine);
                fields>>actual>>std::hex;for (auto& value:arguments) fields>>value;
                blocked=fields && actual==static_cast<int64_t>(number) && arguments[0]==buffer && arguments[7]==after;
                if (!blocked) usleep(1000);
            }
        }
        usleep(1000000);user_regs_struct parked{};
        require(blocked && ptrace(PTRACE_INTERRUPT,fixture.pid,nullptr,nullptr)==0 && restartBoundaryStop(fixture.pid,status) &&
            ptrace(PTRACE_GETREGS,fixture.pid,nullptr,&parked)==0 && parked.rip==after && parked.orig_rax==number &&
            static_cast<int64_t>(parked.rax)==-516,
            "procfs and the real interrupted stop prove the original live restart-block timer");
        if (!blocked || parked.rip!=after) return;
        struct Info {uint8_t operation,pad[3];uint32_t architecture;uint64_t pc,sp;} before{},observedInfo{};
        if (edited) parked.rax=static_cast<uint32_t>(parked.rax);
        require((!edited || ptrace(PTRACE_SETREGS,fixture.pid,nullptr,&parked)==0) &&
            ptrace(static_cast<enum __ptrace_request>(0x420e),fixture.pid,reinterpret_cast<void*>(sizeof(before)),&before)>=sizeof(before) &&
            before.architecture==(compat ? 0x40000003u : 0xc000003eu) && (!mixed || parked.cs==0x33),
            "actual kernel entry ABI is independent of CS and the zero-extended stopped EAX edit");
        auto guard=executeStoppedMemorySyscall(fixture.pid,host,MemorySyscall::Unmap,{*storage,page,0,0,0,0},scratchSite);
        user_regs_struct observed{};
        require(!guard && guard.error().code==std::errc::operation_not_permitted && !guard.error().completedValue &&
            ptrace(PTRACE_GETREGS,fixture.pid,nullptr,&observed)==0 && !std::memcmp(&parked,&observed,sizeof(parked)),
            "the preceding restart page stays protected even when a compat error is zero-extended in a 64-bit bank");
        syscall_test::arm(job ? stops[variant-5-faults.size()] : faulted ? faults[variant-4] : queued ? Fault::RestartQueuedSignal : Fault::None);
        auto mapped=direct ? std::expected<uint64_t,TargetSyscallFailure>(uint64_t{0}) :
            executeStoppedMemorySyscall(fixture.pid,host,MemorySyscall::Map,{0,page,3,MAP_PRIVATE|MAP_ANONYMOUS,UINT64_MAX,0},scratchSite);
        bool completed=direct,restored=direct;uintptr_t allocation=0;
        if (faulted || job) {
            completed=!mapped && mapped.error().completedValue && mapped.error().recovery && syscall_test::triggered()>0 &&
                fixtureTracer(fixture.pid)==getpid() && !boundaryPermissions(fixture.pid,*mapped.error().completedValue).empty();
            if (completed) allocation=*mapped.error().completedValue;
        } else if (!direct && mapped) allocation=*mapped;
        if ((lifecycle || groupOnly) && !completed) {
            user_regs_struct actual{};siginfo_t info{};
            const bool bank=ptrace(PTRACE_GETREGS,fixture.pid,nullptr,&actual)==0;
            const bool signal=ptrace(PTRACE_GETSIGINFO,fixture.pid,nullptr,&info)==0;
            std::printf("MIXED_ABI_LIFECYCLE_FAILURE variant=%u mapped=%d error=%d completed=%d recovery=%d triggered=%u bank=%d pc=%llx rax=%llx signal=%d signo=%d code=%d\n",
                variant,bool(mapped),mapped ? 0 : mapped.error().code.value(),mapped ? 1 : bool(mapped.error().completedValue),
                mapped ? 0 : bool(mapped.error().recovery),syscall_test::triggered(),bank,static_cast<unsigned long long>(actual.rip),
                static_cast<unsigned long long>(actual.rax),signal,info.si_signo,info.si_code);fflush(stdout);
        }
        require(faulted || job ? completed : direct || mapped.has_value(),faulted || job ?
            "a real completed mmap retains its value, mapping and same ptrace owner after controlled restart-recovery failure" :
            "the normal memory operation or independent direct-resume control completes without losing ownership");
        if (lifecycle && completed) {
            auto ticket=mapped.error().recovery;
            if (job) {
                siginfo_t info{};
                require(ptrace(PTRACE_GETSIGINFO,fixture.pid,nullptr,&info)==0 && info.si_signo==SIGSTOP &&
                    info.si_code==SI_QUEUE && info.si_pid==getpid(),
                    "lifecycle interruption starts at an actual SIGSTOP delivery rather than a fabricated event");
                auto paused=ticket->retry();
                if (listenFailure) {syscall_test::clear();paused=ticket->retry();}
                require(!paused && paused.error()==std::errc::timed_out &&
                    syscall_test::restartGroupStopMatches(&parked,sizeof(parked),mask),
                    "death during LISTEN begins at a genuine group stop with the original context and mask");
            }
            syscall_test::clear();
            std::error_code foreign;
            std::thread intruder([&] {auto result=ticket->retry();if (!result) foreign=result.error();});intruder.join();
            require(foreign==std::errc::operation_not_permitted && fixtureTracer(fixture.pid)==getpid() &&
                !boundaryPermissions(fixture.pid,allocation).empty(),
                "a foreign thread cannot consume lifecycle recovery or its completed allocation");
            if (death) {
                uint8_t originalProbe=0;
                if (lifecycle==6) {
                    auto read=retained->read(scratchSite,&originalProbe,1);
                    syscall_test::arm(variant==12 ? Fault::RestartProbeRestoreBefore : Fault::RestartProbeRestoreAfter);
                    auto paused=ticket->retry();uint8_t actual=0;auto changed=retained->read(scratchSite,&actual,1);
                    require(read && *read==1 && !paused && paused.error()==std::errc::state_not_recoverable &&
                        syscall_test::triggered()>0 && changed && *changed==1 &&
                        actual==(variant==12 ? static_cast<uint8_t>(originalProbe^0xff) : originalProbe),
                        "death with pending probe cleanup starts after a real restoration write fails before or after kernel application");
                }
                bool exited=false;int terminal=0;const bool killed=kill(fixture.pid,SIGKILL)==0;
                const bool ownerReaps=variant%2==0;
                const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
                while (killed && !exited && std::chrono::steady_clock::now()<deadline) {
                    if (ownerReaps) {
                        siginfo_t info{};
                        const auto got=waitid(P_PID,fixture.pid,&info,__WALL|__WNOTHREAD|WEXITED|WNOHANG|WNOWAIT);
                        exited=got==0 && info.si_pid==fixture.pid && info.si_code==CLD_KILLED && info.si_status==SIGKILL;
                        if (exited) terminal=info.si_status;
                    } else {
                        const auto got=waitpid(fixture.pid,&terminal,__WALL|__WNOTHREAD|WNOHANG);
                        exited=got==fixture.pid && WIFSIGNALED(terminal) && WTERMSIG(terminal)==SIGKILL;
                    }
                    if (!exited) usleep(1000);
                }
                require(exited,"the owned target actually exits from SIGKILL during retained recovery");
                if (sharedDeath) {
                    uint8_t value=0;auto read=retained->read(0x30000001,&value,1);
                    require(retained->check() && read && *read==1 && value==42 && kill(peer,0)==0 && fixtureTracer(peer)==0,
                        "after target death a separate untraced CLONE_VM process keeps the actual original mm readable");
                }
                if (lifecycle==6 && variant==12) {
                    auto blocked=ticket->retry();const auto invalid=ticket->checkImage();
                    require(!blocked && blocked.error()==std::errc::state_not_recoverable && !ticket->imageRetired() &&
                        !invalid && invalid.error()==std::errc::operation_canceled && retained->check(),
                        "failed old probe cleanup retains ownership while the actual dead task's context is already invalid");
                    std::error_code denied;
                    std::thread intruder([&] {auto result=ticket->retry();if (!result) denied=result.error();});intruder.join();
                    require(denied==std::errc::operation_not_permitted,"a foreign thread cannot drain retained probe cleanup after actual task death");
                    syscall_test::arm(Fault::RestartProbeRestoreBefore);
                    auto wordsBlocked=ticket->retry();uint8_t restoredProbe=0;auto oldByte=retained->read(scratchSite,&restoredProbe,1);
                    require(!wordsBlocked && wordsBlocked.error()==std::errc::state_not_recoverable && !ticket->imageRetired() &&
                        oldByte && *oldByte==1 && restoredProbe==originalProbe && retained->check(),
                        "a second cleanup failure restores the old probe but retains the original private instruction bytes until they can be verified");
                    syscall_test::clear();
                }
                const auto recovered=ticket->retry();const auto oldImage=ticket->checkImage();
                require(!recovered && recovered.error()==std::errc::no_such_process && ticket->retry() && ticket->retry() && (!sharedDeath || !ticket->imageRetired()),
                    "actual target death terminates recovery without replay and subsequent retries are idempotent");
                require(!oldImage && oldImage.error()==std::errc::operation_canceled,
                    "the saved task context is invalid after its real exit, independently of the old mm lifetime");
                bool reaped=!ownerReaps;
                if (ownerReaps) {
                    int checked=0;errno=0;
                    reaped=waitpid(fixture.pid,&checked,__WALL|__WNOTHREAD|WNOHANG)<0 && errno==ECHILD;
                    require(reaped,"the recovery owner consumes the actual exit notification observed non-destructively by the fixture");
                }
                std::printf("MIXED_ABI_LIFECYCLE_OBSERVATION action=death variant=%u ownerReaps=%d terminal=%x recoveryError=%d pinnedError=%d\n",
                    variant,ownerReaps,terminal,recovered ? 0 : recovered.error().value(),oldImage ? 0 : oldImage.error().value());
                if (exited && reaped) fixture.pid=-1;
                if (sharedDeath) {
                    uint8_t allocationByte=1;auto mapped=retained->read(allocation,&allocationByte,1);
                    require(retained->check() && mapped && *mapped==1 && allocationByte==0 && kill(peer,0)==0,
                        "retiring a dead task leaves the surviving peer's original mm and completed allocation intact");
                    std::array<uint8_t,32> privateBytes{};auto codeRead=retained->read(*scratch,privateBytes.data(),privateBytes.size());
                    require(codeRead && *codeRead==privateBytes.size() && privateBytes==savedScratch,
                        "after task death recovery restores every owned private instruction byte while preserving all surrounding scratch bytes");
                    if (lifecycle==6) {
                        uint8_t actual=0;auto read=retained->read(scratchSite,&actual,1);
                        require(read && *read==1 && actual==savedScratch[0] && (variant!=14 || syscall_test::triggered()==3),
                            "death recovery restores an owned old-mm marker or verifies an already-applied restoration without rewriting it");
                        syscall_test::clear();
                    }
                    require(peerOwner.cleanup(),"the controller kills and reaps the actual adopted peer after checking the live old mm");
                    auto gone=retained->check();
                    require(!gone && gone.error()==std::errc::operation_canceled && ticket->retry(),
                        "only the peer's real exit retires the independently pinned old mm and no fixture process is left alive");
                }
            } else {
                std::istringstream header(line);std::string magic;pid_t pid=0;unsigned width=0;std::array<uintptr_t,10> sites{};
                header>>magic>>pid>>width>>std::hex;for (auto& site:sites) header>>site;
                const std::string executable="/proc/self/exe";const uintptr_t pathAddress=buffer+128,argvAddress=buffer+256;
                const std::array<uint64_t,5> argv{pathAddress,shared ? buffer+384 : pathAddress,shared ? buffer+416 : 0,shared ? buffer+448 : 0,0};
                const std::string peerText=std::to_string(peer);
                const std::array<uint8_t,3> execCode{0x0f,0x05,0xcc};
                const auto identity=targetProcessIdentity(fixture.pid);
                auto exec=original;exec.rip=shared ? buffer+512 : sites[8];exec.rax=SYS_execve;exec.orig_rax=UINT64_MAX;
                exec.rdi=pathAddress;exec.rsi=argvAddress;exec.rdx=0;
                bool ready=false;user_regs_struct temporary{};
                const auto stopDeadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
                while (!ready && std::chrono::steady_clock::now()<stopDeadline) {
                    int observed=0;const auto polled=waitpid(fixture.pid,&observed,__WALL|__WNOTHREAD|WNOHANG);
                    if (polled==fixture.pid && !WIFSTOPPED(observed)) break;
                    ready=ptrace(PTRACE_GETREGS,fixture.pid,nullptr,&temporary)==0;
                    if (!ready) usleep(1000);
                }
                int queued=0;waitpid(fixture.pid,&queued,__WALL|__WNOTHREAD|WNOHANG);
                uint8_t probeByte=0;
                if (shared && !identical) {
                    auto read=retained->read(scratchSite,&probeByte,1);
                    syscall_test::arm(variant%2 ? Fault::RestartProbeRestoreAfter : Fault::RestartProbeRestoreBefore);
                    auto failed=ticket->retry();uint8_t actual=0;auto changed=retained->read(scratchSite,&actual,1);
                    require(read && *read==1 && !failed && failed.error()==std::errc::state_not_recoverable && syscall_test::triggered()>0 &&
                        changed && *changed==1 && actual==(variant%2 ? probeByte : static_cast<uint8_t>(probeByte^0xff)) && fixtureTracer(fixture.pid)==getpid(),
                        "a real private probe restoration failure before or after its write retains the original byte and ptrace owner");
                    syscall_test::clear();
                }
                const bool sharedPrepared=!shared ||
                    (writeMemory(fixture.pid,buffer+384,"--replacement",14)==14 &&
                    writeMemory(fixture.pid,buffer+416,peerText.c_str(),peerText.size()+1)==peerText.size()+1 &&
                    writeMemory(fixture.pid,buffer+448,identical ? "1" : "0",2)==2 &&
                    writeMemory(fixture.pid,buffer+512,execCode.data(),execCode.size())==execCode.size());
                bool launched=ready && (shared || header) && sharedPrepared && writeMemory(fixture.pid,pathAddress,executable.c_str(),executable.size()+1)==executable.size()+1 &&
                    writeMemory(fixture.pid,argvAddress,argv.data(),sizeof(argv))==sizeof(argv) &&
                    ptrace(PTRACE_SETREGS,fixture.pid,nullptr,&exec)==0 && ptrace(PTRACE_CONT,fixture.pid,nullptr,nullptr)==0;
                bool prepared=false;unsigned interrupts=0;
                const auto execDeadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
                while (launched && !prepared && std::chrono::steady_clock::now()<execDeadline) {
                    const auto polled=waitpid(fixture.pid,&status,__WALL|__WNOTHREAD|WNOHANG);
                    if (!polled) {usleep(1000);continue;}
                    if (polled!=fixture.pid || !WIFSTOPPED(status)) break;
                    if ((status>>16)==PTRACE_EVENT_EXEC) {prepared=true;break;}
                    user_regs_struct held{};
                    if ((status>>16)!=PTRACE_EVENT_STOP || WSTOPSIG(status)!=SIGTRAP ||
                        ptrace(PTRACE_GETREGS,fixture.pid,nullptr,&held)<0 || held.rip!=exec.rip) break;
                    ++interrupts;launched=ptrace(PTRACE_CONT,fixture.pid,nullptr,nullptr)==0;
                }
                std::printf("MIXED_ABI_LIFECYCLE_EXEC_ENTRY variant=%u ready=%d launched=%d exec=%d interrupts=%u status=%x\n",
                    variant,ready,launched,prepared,interrupts,status);
                require(prepared,"the real retained target execs the same file and the caller consumes its actual EXEC stop");
                if (!prepared) return;
                bool replacementReady=false;
                std::array<uint8_t,2> recreatedBytes{};
                if (identical) {
                    char command='B';
                    replacementReady=ptrace(PTRACE_CONT,fixture.pid,nullptr,nullptr)==0 && fixture.line().starts_with("SHARED_READY ") &&
                        ::write(fixture.input,&command,1)==1 && fixture.line()=="SHARED_BUSY" &&
                        ptrace(PTRACE_INTERRUPT,fixture.pid,nullptr,nullptr)==0 && restartBoundaryStop(fixture.pid,status);
                    auto read=retained->read(scratchSite,recreatedBytes.data(),recreatedBytes.size());
                    auto recreated=replacementReady ? executeOwnedMemorySyscall(fixture.pid,host,MemorySyscall::Map,
                        {*scratch,page,7,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,UINT64_MAX,0}) :
                        std::expected<uint64_t,TargetSyscallFailure>(std::unexpected(std::make_error_code(std::errc::io_error)));
                    require(replacementReady && read && *read==recreatedBytes.size() && recreated && *recreated==*scratch &&
                        writeMemory(fixture.pid,scratchSite,recreatedBytes.data(),recreatedBytes.size())==recreatedBytes.size(),
                        "an identical same-file replacement owns identical private scratch bytes at the same address ending at a page boundary");
                    if (!recreated) return;
                }
                user_regs_struct replacement{},afterRecovery{};uint64_t replacementMask=0,afterMask=0;
                auto nextIdentity=targetProcessIdentity(fixture.pid);auto nextExtended=captureNativeExtendedContext(fixture.pid);
                const bool captured=identity && nextIdentity && *identity==*nextIdentity && nextExtended &&
                    ptrace(PTRACE_GETREGS,fixture.pid,nullptr,&replacement)==0 &&
                    ptrace(PTRACE_GETSIGMASK,fixture.pid,reinterpret_cast<void*>(sizeof(replacementMask)),&replacementMask)==0;
                require(captured && boundaryPermissions(fixture.pid,allocation).empty() && boundaryPermissions(fixture.pid,*storage).empty(),
                    "the same PID, birth and executable inode now own an actual new mm, GP bank and inherited mask");
                if (shared) {
                    uint8_t value=0;
                    auto read=retained->read(0x30000001,&value,1);
                    require(retained->check() && read && *read==1 && value==42 && kill(peer,0)==0,
                        "after actual same-file exec the separate CLONE_VM peer still owns the readable original mm");
                }
                const auto recovered=ticket->retry();const auto oldImage=ticket->checkImage();
                const bool bank=ptrace(PTRACE_GETREGS,fixture.pid,nullptr,&afterRecovery)==0 &&
                    ptrace(PTRACE_GETSIGMASK,fixture.pid,reinterpret_cast<void*>(sizeof(afterMask)),&afterMask)==0;
                if (shared) std::printf("MIXED_ABI_SHARED_EXEC_BANK variant=%u observed=%d freshPC=%llx recoveredPC=%llx freshMask=%llx recoveredMask=%llx retired=%d\n",
                    variant,bank,static_cast<unsigned long long>(replacement.rip),static_cast<unsigned long long>(afterRecovery.rip),
                    static_cast<unsigned long long>(replacementMask),static_cast<unsigned long long>(afterMask),ticket->imageRetired());
                const bool preserved=!recovered && recovered.error()==std::errc::operation_canceled && ticket->imageRetired() &&
                    !oldImage && oldImage.error()==std::errc::operation_canceled && ticket->retry() && ticket->retry() &&
                    bank && !std::memcmp(&replacement,&afterRecovery,sizeof(replacement)) && afterMask==replacementMask &&
                    nextExtended && verifyNativeExtendedContext(fixture.pid,*nextExtended);
                require(preserved,
                    "same-file exec retires the old recovery without changing any replacement GP, extended state or inherited mask");
                // A failing pre-fix reproducer still restores only the independently
                // captured replacement context so its peer can be reaped normally.
                if (shared && !preserved) {
                    ptrace(PTRACE_SETREGS,fixture.pid,nullptr,&replacement);
                    ptrace(PTRACE_SETSIGMASK,fixture.pid,reinterpret_cast<void*>(sizeof(replacementMask)),&replacementMask);
                    if (nextExtended) restoreNativeExtendedContext(fixture.pid,*nextExtended);
                }
                if (shared && !identical) {
                    uint8_t actual=0;auto read=retained->read(scratchSite,&actual,1);
                    require(read && *read==1 && actual==probeByte,"recovery restores the retained original probe byte in the old mm after actual exec");
                }
                if (identical) {
                    std::array<uint8_t,2> actual{};
                    require(readMemory(fixture.pid,scratchSite,actual.data(),actual.size())==actual.size() && actual==recreatedBytes,
                        "identity checking leaves identical replacement scratch bytes untouched");
                    const uint8_t clear=0;
                    replacementReady=replacementReady && writeMemory(fixture.pid,0x31000008,&clear,1)==1;
                }
                const bool released=ptrace(PTRACE_DETACH,fixture.pid,nullptr,nullptr)==0;
                bool console=false;
                if (released && shared) {
                    char command='E';
                    console=(identical ? replacementReady && fixture.line()=="SHARED_RESUMED" : fixture.line().starts_with("SHARED_READY ")) &&
                        ::write(fixture.input,&command,1)==1 && fixture.line()==(identical ? "SHARED_VALUE=42" : "SHARED_VALUE=55");
                    command='Q';int terminal=0;
                    const bool reaped=::write(fixture.input,&command,1)==1 && waitpid(fixture.pid,&terminal,0)==fixture.pid && WIFEXITED(terminal) && WEXITSTATUS(terminal)==0;
                    require(reaped && kill(peer,0)<0 && errno==ESRCH,"the replacement reaps its actual CLONE_VM peer and both fixture processes exit cleanly");
                    if (reaped) fixture.pid=-1;
                } else if (released) console=fixture.line().starts_with("CE_TARGET ") && fixture.value();
                require(released && console,
                    "the caller releases the real replacement and its original console work remains usable");
                std::printf("MIXED_ABI_LIFECYCLE_OBSERVATION action=exec variant=%u recoveryError=%d oldPC=%llx newPC=%llx replacementMask=%llx\n",
                    variant,recovered ? 0 : recovered.error().value(),static_cast<unsigned long long>(parked.rip),
                    static_cast<unsigned long long>(replacement.rip),static_cast<unsigned long long>(replacementMask));
            }
            continue;
        }
        if (queued) {
            struct {uint64_t offset;uint32_t flags;int32_t count;} peek{0,1,16};
            std::array<siginfo_t,16> signals{};
            const auto amount=ptrace(PTRACE_PEEKSIGINFO,fixture.pid,&peek,signals.data());
            const bool preserved=amount>0 && std::any_of(signals.begin(),signals.begin()+amount,[&](const auto& info) {
                return info.si_signo==SIGWINCH && info.si_code==SI_QUEUE && info.si_pid==getpid() &&
                    info.si_uid==getuid() && info.si_value.sival_int==0x41534947;
            });
            require(mapped && syscall_test::triggered()==1 && preserved,
                "ABI restoration defers an actual queued asynchronous signal without changing its sender or value");
        }
        if (job && completed) {
            siginfo_t info{};
            require(mapped.error().code==std::errc::interrupted && !mapped.error().pendingSignal &&
                !mapped.error().pendingEvent && ptrace(PTRACE_GETSIGINFO,fixture.pid,nullptr,&info)==0 &&
                info.si_signo==SIGSTOP && info.si_code==SI_QUEUE && info.si_pid==getpid() &&
                info.si_uid==getuid() && info.si_value.sival_int==0x41534947,
                "a real queued SIGSTOP retains its delivery data and same owned completed mmap during ABI restoration");
            auto ticket=mapped.error().recovery;
            if (canceled) {
                restored=kill(fixture.pid,SIGCONT)==0 && ticket->retry().has_value();
                require(restored && !syscall_test::restartGroupStopMatches(&parked,sizeof(parked),mask),
                    "SIGCONT canceling a held SIGSTOP does not create a replacement group stop or run the borrowed context");
            } else {
                auto paused=ticket->retry();
                if (listenFailure) {
                    require(!paused && paused.error().value()==EIO && fixtureTracer(fixture.pid)==getpid() &&
                        !boundaryPermissions(fixture.pid,allocation).empty(),
                        "a LISTEN failure before or after kernel application retains the actual task, stop and completed allocation");
                    syscall_test::clear();paused=ticket->retry();
                }
                auto state=[&] {
                    std::ifstream in("/proc/"+std::to_string(fixture.pid)+"/stat");std::string stat;std::getline(in,stat);
                    const auto end=stat.rfind(')');return end!=std::string::npos && end+2<stat.size() ? stat[end+2] : '?';
                };
                const char beforeState=state();usleep(20000);const char afterState=state();
                require(!paused && paused.error()==std::errc::timed_out &&
                    syscall_test::restartGroupStopMatches(&parked,sizeof(parked),mask) &&
                    (beforeState=='T' || beforeState=='t') && (afterState=='T' || afterState=='t') &&
                    fixtureTracer(fixture.pid)==getpid(),
                    "bounded recovery preserves a real kernel group stop with the original GP bank and signal mask until SIGCONT");
                if (stops[variant-5-faults.size()]==Fault::RestartQueuedStop) {
                    syscall_test::queueRestartContinueRace(fixture.pid);
                    restored=ticket->retry().has_value();
                    require(restored && syscall_test::restartContinueRaceObserved(),
                        "a real SIGCONT notification between an empty wait poll and stop inspection is collected without replaying LISTEN");
                } else restored=kill(fixture.pid,SIGCONT)==0 && ticket->retry().has_value();
            }
            restored=restored && ticket->retry().has_value();
        }
        syscall_test::clear();
        if (faulted && completed) restored=mapped.error().recovery->retry().has_value() && mapped.error().recovery->retry().has_value();
        if (queued) restored=mapped.has_value();
        if (!direct && !queued && !job && allocation && (!faulted || restored)) {
            auto protectedPage=executeStoppedMemorySyscall(fixture.pid,host,MemorySyscall::Protect,{allocation,page,1,0,0,0},scratchSite);
            auto freed=executeStoppedMemorySyscall(fixture.pid,host,MemorySyscall::Unmap,{allocation,page,0,0,0,0},scratchSite);
            restored=protectedPage && freed && boundaryPermissions(fixture.pid,allocation).empty();
        }
        require(restored && ptrace(PTRACE_GETREGS,fixture.pid,nullptr,&observed)==0 && !std::memcmp(&parked,&observed,sizeof(parked)) &&
            ptrace(static_cast<enum __ptrace_request>(0x420e),fixture.pid,reinterpret_cast<void*>(sizeof(observedInfo)),&observedInfo)>=sizeof(observedInfo) &&
            observedInfo.architecture==before.architecture,
            "normal completion and retry restore the full visible bank and actual kernel syscall-entry ABI");
        uint64_t actualMask=0;std::array<uint8_t,3> actualCode{};
        require(verifyNativeExtendedContext(fixture.pid,*extended) &&
            readMemory(fixture.pid,*scratch,scratchAfter.data(),scratchAfter.size())==scratchAfter.size() && scratchAfter==savedScratch &&
            readMemory(fixture.pid,edge,actualCode.data(),actualCode.size())==actualCode.size() && actualCode==code &&
            ptrace(PTRACE_GETSIGMASK,fixture.pid,reinterpret_cast<void*>(sizeof(actualMask)),&actualMask)==0 && actualMask==mask,
            "recovery preserves extended state, both original instructions, private scratch and the application signal mask");
        usleep(500000);
        bool continued=ptrace(PTRACE_CONT,fixture.pid,nullptr,nullptr)==0 && restartBoundaryStop(fixture.pid,status);
        if (queued || job) {
            siginfo_t info{};
            const bool delivered=continued && (status>>16)==0 && WSTOPSIG(status)==(job ? SIGCONT : SIGWINCH) &&
                ptrace(PTRACE_GETSIGINFO,fixture.pid,nullptr,&info)==0 && info.si_code==(job ? SI_USER : SI_QUEUE) &&
                info.si_pid==getpid() && info.si_uid==getuid() && (job || info.si_value.sival_int==0x41534947);
            require(delivered,"the real resumed target receives the original asynchronous signal at its original context");
            continued=delivered && ptrace(PTRACE_CONT,fixture.pid,nullptr,reinterpret_cast<void*>(job ? SIGCONT : SIGWINCH))==0 &&
                restartBoundaryStop(fixture.pid,status);
        }
        const bool resumed=continued && ptrace(PTRACE_GETREGS,fixture.pid,nullptr,&observed)==0;
        const auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-started).count();
        std::printf("MIXED_ABI_RESTART_OBSERVATION variant=%u syscall=%llu entry=%x restoredEntry=%x edited=%d elapsed=%lld result=%llx stop=%d\n",
            variant,static_cast<unsigned long long>(number),before.architecture,observedInfo.architecture,edited,
            static_cast<long long>(elapsed),static_cast<unsigned long long>(observed.rax),resumed ? WSTOPSIG(status) : 0);
        require(resumed && WSTOPSIG(status)==SIGTRAP && observed.rip==after+1 && observed.rax==0 && elapsed>=1800 && elapsed<3500,
            "actual target resume completes the original timer deadline and reaches INT3 with success");
        if (!resumed) return;
        if ((queued || job) && allocation) {
            auto protectedPage=executeStoppedMemorySyscall(fixture.pid,host,MemorySyscall::Protect,{allocation,page,1,0,0,0},scratchSite);
            auto released=executeStoppedMemorySyscall(fixture.pid,host,MemorySyscall::Unmap,{allocation,page,0,0,0,0},scratchSite);
            require(protectedPage && released && boundaryPermissions(fixture.pid,allocation).empty(),
                "after actual signal delivery and timer completion the owned allocation can be protected and reclaimed");
        }
        const bool originalRestored=ptrace(PTRACE_SETREGS,fixture.pid,nullptr,&original)==0 &&
            ptrace(PTRACE_SETSIGMASK,fixture.pid,reinterpret_cast<void*>(sizeof(applicationMask)),&applicationMask)==0;
        auto freed=executeStoppedMemorySyscall(fixture.pid,host,MemorySyscall::Unmap,{*storage,3*page,0,0,0,0},scratchSite);
        auto scratchFreed=executeQuiescedMemorySyscall(fixture.pid,host,MemorySyscall::Unmap,{*scratch,page,0,0,0,0});
        const bool absent=boundaryPermissions(fixture.pid,*storage).empty() && boundaryPermissions(fixture.pid,*scratch).empty();
        const bool detached=ptrace(PTRACE_DETACH,fixture.pid,nullptr,nullptr)==0;
        const bool console=detached && fixture.value();
        std::printf("MIXED_ABI_RESTART_CLEANUP variant=%u original=%d storage=%d storageError=%d scratch=%d scratchError=%d absent=%d detach=%d console=%d\n",
            variant,originalRestored,bool(freed),freed ? 0 : freed.error().value(),bool(scratchFreed),scratchFreed ? 0 : scratchFreed.error().value(),absent,detached,console);
        require(originalRestored && freed && scratchFreed && absent && detached && console,
            "owned cleanup reclaims all mappings and preserves the original application console work");
    }
    if (sharedDeath) require(reaper.restore(),"the controller restores its original subreaper setting after all actual peer cleanup");
    if (lifecycle) std::printf("MIXED_ABI_LIFECYCLE_RESULT=%s architecture=%s action=%s checks=%u\n",failures==initial ? "PASSED" : "FAILED",cpuArchitectureName(architecture),lifecycle==5 ? "shared-death" : lifecycle==6 ? "shared-death-probe" : lifecycle==1 ? "death" : lifecycle==3 ? "shared-exec" : lifecycle==4 ? "identical-shared-exec" : "exec",count);
    else std::printf("MIXED_ABI_RESTART_RESULT=%s architecture=%s checks=%u\n",failures==initial ? "PASSED" : "FAILED",cpuArchitectureName(architecture),count);
    fflush(stdout);
}
#endif
