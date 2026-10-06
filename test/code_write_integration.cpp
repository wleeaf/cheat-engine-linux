#include "platform/linux/linux_process.hpp"
#include "platform/linux/syscall_service.hpp"
#include "platform/linux/code_write.hpp"
#include "platform/linux/memory_image.hpp"
#include "debug/debug_session.hpp"
#include "debug/patch.hpp"
#include "core/cpu_registers.hpp"
#include "test/code_write_faults.hpp"
#ifndef CE_CODE_WRITE_GUEST
#include "core/autoasm.hpp"
#include "core/simple_hook.hpp"
#include "scripting/lua_engine.hpp"
#endif
#include <array>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <csignal>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace ce;
static unsigned checks,failures;
static void check(bool ok,const char* detail) {
    ++checks;failures+=!ok;std::printf("%s: %s\n",ok ? "OK" : "FAILED",detail);std::fflush(stdout);
}
static std::array<uint8_t,8> code(unsigned value) {
#if defined(__aarch64__)
    const uint32_t move=0x52800000u|(value<<5);
    return {uint8_t(move),uint8_t(move>>8),uint8_t(move>>16),uint8_t(move>>24),0xc0,0x03,0x5f,0xd6};
#else
    return {0xb8,uint8_t(value),uint8_t(value>>8),uint8_t(value>>16),uint8_t(value>>24),0xc3,0x90,0x90};
#endif
}
static size_t pageSize() {return static_cast<size_t>(sysconf(_SC_PAGESIZE));}
static size_t imageSize() {return pageSize()*3+131072;}
static uintptr_t codeAddress() {return 0x30000000+pageSize()-4;}
static unsigned char* image(unsigned value) {
    const auto page=pageSize();
    auto* memory=static_cast<unsigned char*>(mmap(reinterpret_cast<void*>(0x30000000),imageSize(),PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0));
    if (memory==MAP_FAILED) return nullptr;
    std::memset(memory,0xa5,imageSize());
    const auto bytes=code(value);std::memcpy(memory+page-4,bytes.data(),bytes.size());
    __builtin___clear_cache(reinterpret_cast<char*>(memory),reinterpret_cast<char*>(memory+imageSize()));
    if (mprotect(memory,imageSize(),PROT_READ|PROT_EXEC)) {munmap(memory,imageSize());return nullptr;}
    return memory;
}
static int call() {return reinterpret_cast<int(*)()>(codeAddress())();}
static int fixture(bool replacement) {
    if (!image(replacement ? 55 : 42)) return 2;
    prctl(PR_SET_PTRACER,PR_SET_PTRACER_ANY,0,0,0);
    std::printf("CE_CODE_READY pid=%ld address=%lx value=%d\n",static_cast<long>(getpid()),codeAddress(),call());std::fflush(stdout);
    char command;
    while (read(STDIN_FILENO,&command,1)==1) {
        if (command=='Q') return 0;
        if (command=='X') {execl("/proc/self/exe","code_write_integration","--replacement",nullptr);return 3;}
        if (command=='U') {
            if (munmap(reinterpret_cast<void*>(0x30000000),imageSize()) || !image(55)) return 5;
            std::printf("CE_CODE_REMAPPED value=%d\n",call());std::fflush(stdout);
        }
        if (command=='E') {std::printf("CE_CODE_VALUE=%d\n",call());std::fflush(stdout);}
    }
    return 0;
}
struct Child {
    pid_t pid=-1;int input=-1;FILE* output=nullptr;
    Child() {
        int commands[2],responses[2];
        if (pipe(commands) || pipe(responses)) return;
        pid=fork();
        if (!pid) {
            prctl(PR_SET_PDEATHSIG,SIGKILL);
            dup2(commands[0],STDIN_FILENO);dup2(responses[1],STDOUT_FILENO);
            close(commands[0]);close(commands[1]);close(responses[0]);close(responses[1]);
            execl("/proc/self/exe","code_write_integration","--fixture",nullptr);_exit(4);
        }
        close(commands[0]);close(responses[1]);input=commands[1];output=fdopen(responses[0],"r");
    }
    ~Child() {if (input>=0) close(input);if (output) fclose(output);if (pid>0) {kill(pid,SIGKILL);waitpid(pid,nullptr,0);}}
    std::string line() {char buffer[256];return output && fgets(buffer,sizeof(buffer),output) ? buffer : "";}
    bool send(char value) {return input>=0 && write(input,&value,1)==1;}
    bool value(int expected) {return send('E') && line()=="CE_CODE_VALUE="+std::to_string(expected)+"\n";}
};
static bool exact(ProcessHandle& process,const std::array<uint8_t,8>& expected) {
    std::array<uint8_t,8> actual{};auto read=process.read(codeAddress(),actual.data(),actual.size());
    return read && *read==actual.size() && actual==expected;
}
static bool rx(ProcessHandle& process) {
    const auto a=process.queryRegion(codeAddress()),b=process.queryRegion(codeAddress()+7);
    const auto wanted=MemProt::Read|MemProt::Exec;
    return a && b && a->protection==wanted && b->protection==wanted;
}
int main(int argc,char** argv) {
    alarm(60);
    if (getpid()==1 && mount("proc","/proc","proc",0,nullptr)) return 2;
    if (argc==2 && !std::strcmp(argv[1],"--fixture")) return fixture(false);
    if (argc==2 && !std::strcmp(argv[1],"--replacement")) return fixture(true);
    struct utsname kernel{};uname(&kernel);
    std::printf("CODE_WRITE_KERNEL=%s pageSize=%zu\n",kernel.release,pageSize());
    Child child;
    const auto ready=child.line();
    check(child.pid>0 && ready.find("CE_CODE_READY")==0 && ready.find("value=42")!=std::string::npos,"independent executable fixture warms its original code before remote edits");
    if (ready.empty()) return 1;
    os::LinuxProcessHandle process(child.pid);
    const auto original=code(42),changed=code(17);
    check(rx(process) && exact(process,original),"original code straddles two real RX pages with exact baseline bytes");
    auto written=process.writeCode(codeAddress(),changed.data(),changed.size());
    check(written && *written==changed.size() && exact(process,changed) && rx(process) && child.value(17),"remote code write changes actual execution across page boundaries without adding write permission");
    std::array<uint8_t,2> neighbours{};
    auto left=process.read(codeAddress()-1,&neighbours[0],1),right=process.read(codeAddress()+8,&neighbours[1],1);
    check(left && right && neighbours==std::array<uint8_t,2>{0xa5,0xa5},"cross-page code transfer preserves both neighboring bytes");
    check(restoreBytes(process,codeAddress(),{original.begin(),original.end()}) && exact(process,original) && child.value(42) && rx(process),"shared restoration restores actual execution and RX protection exactly");
    auto nops=nopInstruction(process,codeAddress());
    const size_t firstSize=nativeTargetMachine().architecture==CpuArchitecture::Arm64 ? 4 : 5;
    auto expectedNops=nopBytesFor(process,codeAddress(),firstSize);
    std::vector<uint8_t> actualNops(firstSize);auto nread=process.read(codeAddress(),actualNops.data(),actualNops.size());
    check(nops==std::vector<uint8_t>(original.begin(),original.begin()+firstSize) && expectedNops && nread && actualNops==*expectedNops && rx(process),"production NOP helper uses target instruction bytes and preserves the RX mapping");
    check(restoreBytes(process,codeAddress(),nops) && child.value(42) && exact(process,original),"production NOP undo restores the complete original instruction and execution");
    DebugSession session;
    bool attached=session.attach(child.pid,&process);
    check(attached && session.isStopped(),"actual debugger holds the fixture at an all-stop before a code edit");
    if (attached) {
        const auto before=cpuRegisterValues(session.getStopContext());
        written=process.writeCode(codeAddress(),changed.data(),changed.size());
        const auto refreshed=session.selectThread(session.activeThread());
        const auto after=cpuRegisterValues(session.getStopContext());
        bool registers=before.size()==after.size();
        for (size_t at=0;registers && at<before.size();++at) registers=before[at].name==after[at].name && before[at].value==after[at].value;
        check(written && refreshed && registers && session.isStopped() && exact(process,changed) && rx(process),"code edits work with a different debugger owner thread without borrowing registers or resuming the target");
        session.detach();
        check(!session.isAttached() && child.value(17),"the debugger releases its original syscall wait and edited code executes normally");
    }
    check(restoreBytes(process,codeAddress(),{original.begin(),original.end()}) && child.value(42),"original execution survives debugger-owned code editing and restoration");
#ifndef CE_CODE_WRITE_GUEST
    AutoAssembler assembler;
    char address[32];std::snprintf(address,sizeof(address),"0x%lx",codeAddress());
    const std::string instruction=nativeTargetMachine().architecture==CpuArchitecture::Arm64 ? "mov w0, #0x11" : "mov eax, 0x11";
    auto enabled=assembler.execute(process,"[ENABLE]\n"+std::string(address)+":\n"+instruction+"\n");
    check(enabled.success && child.value(17) && rx(process),"actual AutoAssembler edits executable code through the cache-aware shared adapter");
    auto disabled=assembler.disable(process,"[DISABLE]",enabled.disableInfo);
    check(enabled.success && disabled.success && child.value(42) && exact(process,original) && rx(process),"AutoAssembler disable restores real execution without a writable-page residue");
    LuaEngine lua;lua.setProcess(&process);
    auto luaError=lua.execute("local a=0x"+std::string(address+2)+"; local old=nopInstruction(a); assert(old); writeBytes(a,old); local restored=readBytes(a,#old,true); assert(restored); for i,b in ipairs(old) do assert(restored[i]==b) end");
    if (!luaError.empty()) std::printf("CODE_WRITE_LUA_ERROR=%s\n",luaError.c_str());
    check(luaError.empty() && child.value(42) && exact(process,original) && rx(process),"production Lua NOP and undo use the same executable-code backend");
    {
        Child replaced;
        const auto ready = replaced.line();
        os::LinuxProcessHandle savedProcess(replaced.pid), otherProcess(getpid());
        AutoAssembler savedAssembler;
        const std::string script = "[ENABLE]\nalloc(exec_cave,64," + std::string(address) + ")\nregistersymbol(exec_cave)\nFULLACCESS(" + address + ",8)\n" + address + ":\n" + instruction + "\n";
        auto active = savedAssembler.execute(savedProcess,script);
        check(ready.find("value=42")!=std::string::npos && active.success && replaced.value(17) &&
              savedAssembler.resolveSymbol("exec_cave")!=0,"saved AutoAssembler undo owns real code, permissions, allocation and registered symbol state");
        auto wrongTarget = savedAssembler.disable(otherProcess,"",active.disableInfo);
        check(!wrongTarget.success && replaced.value(17) && !wrongTarget.disableInfo.originals.empty(),
              "a saved native undo refuses another process before any byte, protection or allocation cleanup");
        const bool exec = replaced.send('X') && replaced.line().find("value=55")!=std::string::npos;
        const auto copied = active.disableInfo;
        auto retired = savedAssembler.disable(savedProcess,"",active.disableInfo);
        check(exec && active.success && retired.success && retired.disableInfo.allocs.empty() &&
              savedAssembler.resolveSymbol("exec_cave")==0 && exact(savedProcess,code(55)) && rx(savedProcess) && replaced.value(55),
              "saved undo discards retired ownership after same-file exec and preserves replacement code and RX pages");
        os::NativeCallRequest staleCall;
        staleCall.function=codeAddress();staleCall.image=copied.image;
        auto staleResult=os::memorySyscallService().invoke(copied.image->identity(),savedProcess.targetDescription().host,std::move(staleCall));
        check(!staleResult && staleResult.error()==std::errc::operation_canceled && !savedProcess.targetDescription().pendingRecovery && replaced.value(55),
              "a native loader or pthread request carrying retired script ownership is rejected before executing replacement code");
        auto current = savedAssembler.execute(savedProcess,"[ENABLE]\n"+std::string(address)+":\n"+instruction+"\n");
        auto replay = savedAssembler.disable(savedProcess,"",copied);
        check(current.success && replay.success && replaced.value(17) && rx(savedProcess),
              "a copied retired undo cannot touch a newly enabled patch in the replacement address space");
        check(savedAssembler.disable(savedProcess,"",current.disableInfo).success && replaced.value(55) && rx(savedProcess),
              "the replacement patch restores its own baseline independently of older undo copies");
    }
    {
        Child remapped; remapped.line();
        os::LinuxProcessHandle remappedProcess(remapped.pid);
        AutoAssembler remappedAssembler;
        auto active = remappedAssembler.execute(remappedProcess,"[ENABLE]\n"+std::string(address)+":\n"+instruction+"\n");
        const bool replacement = remapped.send('U') && remapped.line()=="CE_CODE_REMAPPED value=55\n";
        auto undo = remappedAssembler.disable(remappedProcess,"",active.disableInfo);
        check(active.success && replacement && !undo.success && !undo.disableInfo.originals.empty() &&
              exact(remappedProcess,code(55)) && rx(remappedProcess) && remapped.value(55),
              "a new executable mapping at the same address rejects stale AutoAssembler undo without altering replacement execution");
    }
    if (nativeTargetMachine().isX86()) {
        Child hooked; hooked.line();
        os::LinuxProcessHandle hookedProcess(hooked.pid);
        const auto replacement = code(99);
        const uintptr_t destination = codeAddress()+64;
        auto targetWrite = hookedProcess.writeCode(destination,replacement.data(),replacement.size());
        auto hook = installSimpleHook(hookedProcess,codeAddress(),destination);
        check(targetWrite && hook && hooked.value(99) && rx(hookedProcess),
              "a real simple hook changes execution while preserving original RX permissions");
        const bool removed = hook && removeSimpleHook(hookedProcess,*hook);
        auto newPatch = hookedProcess.writeCode(codeAddress(),changed.data(),changed.size());
        const bool replay = hook && removeSimpleHook(hookedProcess,*hook);
        check(removed && newPatch && replay && hooked.value(17) && rx(hookedProcess),
              "a completed simple-hook removal copy cannot restore over a later native code edit");
        hookedProcess.writeCode(codeAddress(),original.data(),original.size());
        auto active = installSimpleHook(hookedProcess,codeAddress(),destination);
        const bool exec = hooked.send('X') && hooked.line().find("value=55")!=std::string::npos;
        check(active && exec && removeSimpleHook(hookedProcess,*active) && hooked.value(55) && exact(hookedProcess,code(55)) && rx(hookedProcess),
              "simple-hook removal retires its pinned address space after exec without restoring stale replacement bytes");
    } else {
        check(!installSimpleHook(process,codeAddress(),codeAddress()+64),"simple hooks refuse an ISA without a live installation backend before mutation");
        check(child.value(42) && rx(process),"refused hooks preserve target execution and page permissions");
        check(exact(process,original),"refused hooks preserve every original target instruction byte");
    }
#endif
    const uintptr_t bulkAddress=0x30000000+pageSize()*2;
    std::vector<uint8_t> bulkOriginal(131089,0xa5),bulkChanged(bulkOriginal.size(),0x5a),bulkActual(bulkOriginal.size());
    auto bulkExact=[&](const auto& wanted) {
        auto read=process.read(bulkAddress,bulkActual.data(),bulkActual.size());
        uint8_t left=0,right=0;
        auto before=process.read(bulkAddress-1,&left,1),after=process.read(bulkAddress+bulkActual.size(),&right,1);
        return read && *read==bulkActual.size() && bulkActual==wanted && before && after && left==0xa5 && right==0xa5 && rx(process);
    };
    auto bulkWrite=process.writeCode(bulkAddress,bulkChanged.data(),bulkChanged.size());
    check(bulkWrite && *bulkWrite==bulkChanged.size() && bulkExact(bulkChanged) && child.value(42),"a three-chunk executable transfer verifies every byte, both neighbors and unchanged original execution");
    bulkWrite=process.writeCode(bulkAddress,bulkOriginal.data(),bulkOriginal.size());
    check(bulkWrite && bulkExact(bulkOriginal),"a three-chunk executable transfer restores its complete original RX image");
    for (auto fault:{code_write_test::Fault::SecondShortWrite,code_write_test::Fault::ThirdAfterMutation}) {
        code_write_test::arm(fault);
        auto partial=process.writeCode(bulkAddress,bulkChanged.data(),bulkChanged.size());
        const auto triggered=code_write_test::triggered();code_write_test::clear();
        check(!partial && triggered && bulkExact(bulkOriginal) && !process.targetDescription().pendingRecovery && child.value(42),
              "a later-chunk short or post-mutation failure restores the full completed prefix and ambiguous chunk");
    }
    for (auto fault:{code_write_test::Fault::ShortWrite,code_write_test::Fault::DropWrite,code_write_test::Fault::AfterMutation}) {
        code_write_test::arm(fault);
        auto failed=process.writeCode(codeAddress(),changed.data(),changed.size());
        const auto triggered=code_write_test::triggered();code_write_test::clear();
        check(!failed && triggered && exact(process,original) && rx(process) && child.value(42) && !process.targetDescription().pendingRecovery,
              "short, dropped or post-mutation code writes report failure and restore the actual original code");
    }
    code_write_test::arm(code_write_test::Fault::RestoreBlocked);
    auto failed=process.writeCode(codeAddress(),changed.data(),changed.size());
    check(!failed && failed.error()==std::errc::state_not_recoverable && process.targetDescription().pendingRecovery && exact(process,changed),"failed original-byte restoration retains native recovery ownership before returning an error");
    auto blocked=process.protect(codeAddress(),8,MemProt::ReadWrite);
    check(!blocked && rx(process) && process.targetDescription().pendingRecovery,"pending code restoration blocks protection changes instead of discarding its recovery storage");
    code_write_test::clear();
    check(process.retryPendingOperations() && !process.targetDescription().pendingRecovery && exact(process,original) && rx(process) && child.value(42),"explicit recovery restores original code and releases the retained failure record");
    os::TargetSyscallService nested;
    auto identity=os::processMemoryIdentity(child.pid);
    auto member=os::targetProcessIdentity(child.pid);
    bool nestedBlocked=false;
    auto inspected=identity && member ? nested.inspectThread(*member,*identity,process.targetDescription().host,false,[&]() -> Result<void> {
        auto code=nested.writeCode(*identity,codeAddress(),changed);
        auto syscall=nested.execute(*identity,process.targetDescription().host,os::MemorySyscall::Protect,{codeAddress(),8,PROT_READ,0,0,0});
        nestedBlocked=!code && code.error()==std::errc::device_or_resource_busy && !syscall && syscall.error()==std::errc::device_or_resource_busy;
        return {};
    }) : Result<void>(std::unexpected(std::make_error_code(std::errc::no_such_process)));
    check(inspected && nestedBlocked && exact(process,original) && child.value(42),"reentrant mutators cannot erase an in-progress native inspection's recovery reservation");
    code_write_test::arm(code_write_test::Fault::RestoreBlocked);
    failed=process.writeCode(codeAddress(),changed.data(),changed.size());
    check(!failed && process.targetDescription().pendingRecovery && child.send('X') && child.line().find("value=55")!=std::string::npos,"a real same-file exec replaces the address space while original-code recovery is pending");
    code_write_test::clear();
    check(process.retryPendingOperations() && !process.targetDescription().pendingRecovery && exact(process,code(55)) && child.value(55),"pinned-mm recovery retires after exec without writing stale bytes into the replacement image");
    bool quit=child.send('Q');int status=0;pid_t exited=-1;
    if (quit) {do {exited=waitpid(child.pid,&status,0);} while (exited<0 && errno==EINTR);}
    check(quit && exited==child.pid && WIFEXITED(status) && !WEXITSTATUS(status),"the independent fixture exits normally after all actual code and recovery operations");
    if (exited==child.pid) child.pid=-1;
    if (image(42)) {
        os::LinuxProcessHandle self(getpid());
        auto selfWrite=self.writeCode(codeAddress(),changed.data(),changed.size());
        check(selfWrite && call()==17 && rx(self),"the same kernel-backed code path edits the frontend's own RX mapping without ptrace self-attachment");
        check(restoreBytes(self,codeAddress(),{original.begin(),original.end()}) && call()==42 && rx(self) && !munmap(reinterpret_cast<void*>(0x30000000),imageSize()),"self-code restoration preserves execution and releases its owned mappings");
    } else check(false,"create the self-code fixture");
    std::printf("CODE_WRITE_RESULT=%s checks=%u failures=%u\n",failures ? "FAILED" : "PASSED",checks,failures);std::fflush(stdout);
    if (getpid()==1) {sync();reboot(RB_POWER_OFF);}
    return failures ? 1 : 0;
}
