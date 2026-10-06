#include "platform/linux/linux_process.hpp"
#include "platform/linux/ptrace_wrapper.hpp"
#include "platform/linux/target_syscall.hpp"
#include "arch/target_arch.hpp"
#include "core/autoasm.hpp"
#include "core/expression.hpp"
#include "core/injection_gen.hpp"
#include "core/value_io.hpp"
#include "debug/code_finder.hpp"
#include "debug/thread_inspection.hpp"
#include "core/cpu_registers.hpp"
#include <array>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <poll.h>
#include <signal.h>
#include <sstream>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <thread>
#include <unistd.h>

using namespace ce;
static int failures;
static void check(bool ok, const char* text) {
    printf("%s: %s\n", ok ? "OK" : "FAILED", text);
    fflush(stdout);
    failures += !ok;
}
class WineFixture {
public:
    pid_t pid = -1;
    int input = -1, output = -1;
    WineFixture(const char* wine, const char* executable) {
        int in[2], out[2];
        if (pipe(in)) return;
        if (pipe(out)) { close(in[0]); close(in[1]); return; }
        pid = fork();
        if (!pid) {
            dup2(in[0], 0); dup2(out[1], 1);
            close(in[0]); close(in[1]); close(out[0]); close(out[1]);
            execl(wine, wine, executable, nullptr);
            _exit(127);
        }
        close(in[0]); close(out[1]); input = in[1]; output = out[0];
    }
    bool receive(void* buffer, size_t count, int timeout = 15000) {
        auto* bytes = static_cast<uint8_t*>(buffer);
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout);
        while (count) {
            auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
            if (remaining <= 0) return false;
            pollfd fd{output, POLLIN, 0};
            if (poll(&fd, 1, static_cast<int>(remaining)) <= 0) return false;
            ssize_t n = ::read(output, bytes, count);
            if (n <= 0) return false;
            bytes += n; count -= n;
        }
        return true;
    }
    std::string line() {
        std::string text;
        for (char c; text.size() < 4096 && receive(&c, 1);) {
            if (c == '\n') return text;
            text += c;
        }
        return {};
    }
    bool value(char command, uint32_t expected) {
        std::array<uint8_t, 4> bytes{};
        if (::write(input, &command, 1) != 1 || !receive(bytes.data(), bytes.size())) return false;
        auto value = decodeTargetUnsigned(bytes, ByteOrder::Little);
        return value && *value == expected;
    }
    ~WineFixture() {
        if (input >= 0) close(input);
        if (output >= 0) close(output);
        if (pid > 0) {
            kill(pid, SIGKILL);
            int status;
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
        }
    }
};
static pid_t findTarget(pid_t launcher, const char* executable) {
    auto name = std::filesystem::path(executable).filename().string();
    for (const auto& entry : std::filesystem::directory_iterator("/proc")) {
        auto pidText = entry.path().filename().string();
        if (pidText.empty() || pidText.find_first_not_of("0123456789") != std::string::npos) continue;
        pid_t pid = std::stoi(pidText);
        std::ifstream maps(entry.path() / "maps");
        std::string line;
        bool found = false;
        while (std::getline(maps, line)) if (line.find(name) != std::string::npos) { found = true; break; }
        if (!found) continue;
        std::ifstream environment(entry.path() / "environ", std::ios::binary);
        std::string variables((std::istreambuf_iterator<char>(environment)), {});
        const char* prefix = std::getenv("WINEPREFIX");
        if (prefix && variables.find(std::string("WINEPREFIX=") + prefix + '\0') != std::string::npos)
            return pid;
        // Only inspect a target descended from this test, even with another Wine running.
        pid_t ancestor = pid;
        for (int depth = 0; ancestor > 1 && depth < 64; ++depth) {
            if (ancestor == launcher) return pid;
            std::ifstream stat("/proc/" + std::to_string(ancestor) + "/stat");
            if (!std::getline(stat, line)) break;
            auto end = line.rfind(')');
            if (end == std::string::npos) break;
            std::istringstream fields(line.substr(end + 1)); char state;
            if (!(fields >> state >> ancestor)) break;
        }
    }
    return -1;
}
static void exercise(const char* wine, const char* path, unsigned width, bool requireWow64, bool requireLegacy) {
    WineFixture fixture(wine, path);
    auto line = fixture.line();
    std::istringstream ready(line); std::string magic;
    unsigned actualWidth = 0;
    uintptr_t value = 0, pointer = 0, code = 0;
    ready >> magic >> actualWidth >> std::hex >> value >> pointer >> code;
    check(ready && magic == "CE_WINE" && actualWidth == width, width == 4 ? "real PE32 console fixture runs" : "real PE32+ console fixture runs");
    if (!ready || magic != "CE_WINE" || actualWidth != width) return;
    pid_t pid = findTarget(fixture.pid, path);
    check(pid > 0, "Windows fixture has an identified descendant Linux process");
    if (pid <= 0) return;
    os::LinuxProcessHandle process(pid);
    auto description = process.targetDescription();
    printf("Wine target pid=%d host=%s program=%s pointers=%u\n", pid,
           targetAbiName(description.host.abi), targetAbiName(description.program.abi), description.program.pointerWidth);
    check(description.runtime == TargetRuntime::Wine && description.program.pointerWidth == width &&
          description.program.abi == (width == 4 ? TargetAbi::WindowsI386 : TargetAbi::WindowsX64),
          "Wine metadata reports the Windows program ABI");
    if (width == 4 && requireWow64)
        check(description.host.abi == TargetAbi::LinuxX86_64 && description.host.pointerWidth == 8,
              "required WoW64 fixture uses an actual 64-bit Unix loader");
    if (width == 4 && requireLegacy)
        check(description.host.abi == TargetAbi::LinuxI386 && description.host.pointerWidth == 4,
              "required legacy Wine32 fixture uses an actual 32-bit Unix loader");
    std::array<uint8_t, 4> sentinel{}, after{};
    auto sentinelRead = process.read(pointer + width, sentinel.data(), sentinel.size());
    check(writeTypedValue(process, pointer, ValueType::Pointer, std::to_string(value)).has_value() &&
          sentinelRead && *sentinelRead == sentinel.size() &&
          process.read(pointer + width, after.data(), after.size()) && sentinel == after &&
          ExpressionParser(&process).parse("[#" + std::to_string(pointer) + "]") == value,
          "program-width pointer writes preserve the neighboring Windows field");
    check(writeTypedValue(process, value, ValueType::Int32, "31415926").has_value() && fixture.value('r', 31415926),
          "Windows program observes the cross-process typed write");
    auto architecture = disassemblerArchFor(process, code);
    check(architecture && *architecture == (width == 4 ? Arch::X86_32 : Arch::X86_64),
          "instruction selection follows the PE code module");
    std::array<uint8_t, 32> original{}, restored{};
    auto before = process.read(code, original.data(), original.size());
    auto originalRegion = process.queryRegion(code);
    std::string error;
    auto script = generateInjectionScript(process, code, InjectionKind::Code, error);
    AutoAssembler assembler;
    auto injected = assembler.execute(process, script);
    if (!injected.success) printf("Wine injection error: %s %s\n", error.c_str(), injected.error.c_str());
    check(before && !script.empty() && injected.success, "injection activates at the real Windows function");
    if (!injected.success) return;
    check(fixture.value('b', 31415927), "Windows instructions execute correctly through the relocated injection");
    auto disabled = assembler.disable(process, script, injected.disableInfo);
    auto read = process.read(code, restored.data(), restored.size());
    auto finalRegion = process.queryRegion(code);
    check(disabled.success && read && *read == restored.size() && restored == original && originalRegion && finalRegion &&
          originalRegion->protection == finalRegion->protection, "Wine cleanup restores exact bytes and page permissions");
    check(fixture.value('b', 31415928), "Windows target keeps executing after injection cleanup");
    for (int cycle = 0; cycle < 3; ++cycle) {
        os::LinuxDebugger debugger;
        CodeFinder finder;
        bool started = finder.start(process, debugger, value, true, 4, false, true);
        check(started, "Wine main-thread hardware watchpoint attaches");
        if (!started) break;
        check(fixture.value('b', 31415929 + cycle), "Windows target runs while the watchpoint records its writer");
        auto hits = finder.results();
        finder.stop();
        check(std::any_of(hits.begin(), hits.end(), [&](const auto& hit) {
                  return hit.instructionAddress == code && hit.firstContext.rip == code + 6;
              }), "Wine hardware watchpoint identifies the exact Windows writer instruction");
        check(fixture.value('r', 31415929 + cycle), "Wine target stays live after watchpoint detach");
    }
    int busyFailuresBefore=failures;
    uintptr_t busyFlag=value+0x48,heartbeat=value+0x4c;
    char command='s';
    bool busy=::write(fixture.input,&command,1)==1 && fixture.line()=="CE_BUSY";
    check(busy,"Windows fixture enters a real CPU loop with no Unix syscall parked on its main thread");
    if (!busy) return;
    uint32_t beforeHeartbeat=0,afterHeartbeat=0;
    auto firstHeartbeat=process.read(heartbeat,&beforeHeartbeat,sizeof(beforeHeartbeat));
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    auto nextHeartbeat=process.read(heartbeat,&afterHeartbeat,sizeof(afterHeartbeat));
    check(firstHeartbeat && nextHeartbeat && beforeHeartbeat!=afterHeartbeat,
          "the busy Windows loop makes progress before transient memory operations");
    os::LinuxDebugger debugger;
    int status=0;
    bool stopped=ptrace(PTRACE_SEIZE,pid,nullptr,nullptr)==0 && ptrace(PTRACE_INTERRUPT,pid,nullptr,nullptr)==0 &&
        waitpid(pid,&status,__WALL)==pid && WIFSTOPPED(status);
    auto context=debugger.getContext(pid);
    struct { uint64_t mode,selector,offset,length; } dispatch{};
    auto dispatchRead=ptrace(static_cast<enum __ptrace_request>(0x4211),pid,reinterpret_cast<void*>(sizeof(dispatch)),&dispatch);
    printf("Wine busy dispatch query=%ld mode=%llu selector=%llx range=%llx/%llx\n",dispatchRead,
        static_cast<unsigned long long>(dispatch.mode),static_cast<unsigned long long>(dispatch.selector),
        static_cast<unsigned long long>(dispatch.offset),static_cast<unsigned long long>(dispatch.length));
    bool released=ptrace(PTRACE_DETACH,pid,nullptr,nullptr)==0;
    check(stopped && context && released && context->architecture==(width==4 ? CpuArchitecture::X86_32 : CpuArchitecture::X86_64) &&
          context->instructionPointer()>=code-0x300 && context->instructionPointer()<code,
          "the busy target is stopped in the actual Windows register mode and PE instruction range");
    auto snapshot=ce::inspectThread(process,pid,true);
    if (!snapshot) printf("Wine thread inspection error: %s\n",snapshot.error().c_str());
    check(snapshot && snapshot->context.architecture==(width==4 ? CpuArchitecture::X86_32 : CpuArchitecture::X86_64) &&
          cpuRegisterValues(snapshot->context).size()==(width==4 ? 10u : 18u) &&
          snapshot->context.instructionPointer()>=code-0x300 && snapshot->context.instructionPointer()<code &&
          snapshot->stack.size()==32 && snapshot->stack[0].available && snapshot->stack[0].width==width &&
          snapshot->stack[1].address==snapshot->stack[0].address+width && !process.targetDescription().pendingRecovery,
          "shared thread inspection reads real Windows register mode and target-width stack without retaining a stop");
    size_t page=static_cast<size_t>(sysconf(_SC_PAGESIZE));
    if (width==4) {
        auto tooWide=process.allocate(UINT32_MAX,MemProt::ReadWrite);
        check(!tooWide && tooWide.error()==std::errc::invalid_argument,
              "a page-rounded allocation wider than Windows pointers is rejected before target mutation");
    }
    for (unsigned cycle=0;cycle<3;++cycle) {
        auto allocation=process.allocate(page,MemProt::ReadWrite);
        if (!allocation) printf("Wine busy allocation error: %s\n",allocation.error().message().c_str());
        check(allocation && (width==8 || *allocation<=UINT32_MAX-page),
              "busy Wine memory allocation uses the Unix host ABI and fits the Windows pointer width");
        if (!allocation) break;
        uint32_t sentinel=0x1234abcd,observed=0;
        auto written=process.write(*allocation,&sentinel,sizeof(sentinel));
        auto read=process.read(*allocation,&observed,sizeof(observed));
        check(written && *written==sizeof(sentinel) && read && *read==sizeof(observed) && observed==sentinel,
              "allocated memory is accessible while the Windows CPU loop continues");
        auto protectedPage=process.protect(*allocation,page,MemProt::Read);
        iovec local{&sentinel,sizeof(sentinel)},remote{reinterpret_cast<void*>(*allocation),sizeof(sentinel)};
        check(protectedPage && process_vm_writev(pid,&local,1,&remote,1,0)<0,
              "busy Wine protection really removes direct kernel write access");
        auto freed=process.free(*allocation,page);
        check(freed && !process.queryRegion(*allocation),"busy Wine cleanup removes the real allocation");
    }
    if (width==4 && description.host.pointerWidth==8) {
        // Reserve only holes in MAP_32BIT's search window. PROT_NONE mappings
        // do not populate pages, so this tests address exhaustion without
        // consuming a gigabyte of the developer machine's physical memory.
        std::vector<std::pair<uintptr_t,size_t>> reservations;
        uintptr_t previous=0x40000000;
        bool reserved=true;
        for (const auto& region : process.queryRegions()) {
            uintptr_t end=std::min<uintptr_t>(region.base,0x80000000);
            if (previous<end) {
                auto occupied=process.allocate(end-previous,MemProt::None,previous);
                if (occupied) reservations.emplace_back(*occupied,end-previous);
                reserved=occupied && *occupied==previous && reserved;
            }
            previous=std::max(previous,region.base+region.size);
            if (previous>=0x80000000) break;
        }
        check(reserved && !reservations.empty(),"virtual reservations occupy the low native allocation window without touching existing Wine mappings");
        auto lowProbe=os::executeMemorySyscall(pid,description.host,os::MemorySyscall::Map,
            {0,page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_32BIT,UINT64_MAX,0});
        check(!lowProbe && lowProbe.error().code==std::errc::not_enough_memory &&
              !lowProbe.error().completedValue && !lowProbe.error().recovery,
              "the actual kernel rejects its exhausted low-address allocation window with ENOMEM");
        if (lowProbe) process.free(*lowProbe,page);
        auto outside=process.allocate(page,MemProt::ReadWrite);
        check(outside && *outside<=UINT32_MAX-page && (*outside<0x40000000 || *outside>=0x80000000),
              "default WoW64 allocation remains usable when the kernel's preferred low-address window is exhausted");
        bool releasedReservations=!outside || process.free(*outside,page).has_value();
        for (const auto& [address,size] : reservations)
            releasedReservations=process.free(address,size).has_value() && releasedReservations;
        check(releasedReservations,"the pressure test removes every temporary allocation and reservation");
        auto modules=process.modules();
        auto loader=std::find_if(modules.begin(),modules.end(),[](const auto& module) {
            return module.machine.abi==TargetAbi::LinuxX86_64 && module.base>UINT32_MAX;
        });
        auto allocation=loader!=modules.end() ? process.allocate(page,MemProt::ReadWrite,loader->base) :
            Result<uintptr_t>(std::unexpected(std::make_error_code(std::errc::no_such_file_or_directory)));
        if (!allocation) printf("Wine loader allocation error: %s\n",allocation.error().message().c_str());
        if (loader!=modules.end()) printf("Wine loader allocation module=%s base=%llx selectedAbi=%s result=%llx\n",
            loader->name.c_str(),static_cast<unsigned long long>(loader->base),
            targetAbiName(process.machineAt(loader->base).abi),
            static_cast<unsigned long long>(allocation ? *allocation : 0));
        auto freed=allocation ? process.free(*allocation,page) : Result<void>(std::unexpected(std::make_error_code(std::errc::invalid_argument)));
        if (allocation && !freed) printf("Wine loader cleanup error: %s\n",freed.error().message().c_str());
        check(allocation && *allocation>UINT32_MAX && freed,
              "module-specific allocation near the 64-bit Unix loader retains its own wide address space in WoW64");
    }
    auto finalHeartbeat=process.read(heartbeat,&afterHeartbeat,sizeof(afterHeartbeat));
    check(finalHeartbeat && beforeHeartbeat!=afterHeartbeat && process.targetDescription().live,
          "the Windows CPU loop stays live and makes progress through repeated transient operations");
    status=0;
    bool stoppedAgain=ptrace(PTRACE_SEIZE,pid,nullptr,nullptr)==0 && ptrace(PTRACE_INTERRUPT,pid,nullptr,nullptr)==0 &&
        waitpid(pid,&status,__WALL)==pid && WIFSTOPPED(status);
    auto restoredContext=debugger.getContext(pid);
    bool releasedAgain=ptrace(PTRACE_DETACH,pid,nullptr,nullptr)==0;
    auto stableRegisters=[](const CpuContext& state) {
        return std::array{state.rax,state.rbx,state.rcx,state.rdx,state.rsi,state.rdi,state.rbp,state.rsp,
            state.r8,state.r9,state.r10,state.r11,state.r12,state.r13,state.r14,state.r15,
            state.cs,state.ss,state.ds,state.es,state.fs,state.gs};
    };
    check(stoppedAgain && releasedAgain && context && restoredContext &&
          restoredContext->architecture==context->architecture &&
          restoredContext->instructionPointer()>=code-0x300 && restoredContext->instructionPointer()<code &&
          stableRegisters(*restoredContext)==stableRegisters(*context),
          "all Windows general registers, segments and execution mode survive native memory operations exactly");
    uint32_t zero=0;
    auto cleared=process.write(busyFlag,&zero,sizeof(zero));
    check(cleared && *cleared==sizeof(zero) && fixture.value('r',31415931),
          "the Windows program exits its loop and resumes normal console work with its original register state");
    printf("WINE_BUSY_RESULT=%s programWidth=%u\n",failures==busyFailuresBefore ? "PASSED" : "FAILED",width);
}
int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc < 4 || argc > 5) { fprintf(stderr, "usage: wine_integration <wine> <fixture64.exe> <fixture32.exe> [--require-wow64|--require-legacy-wine32]\n"); return 2; }
    bool wow64 = argc == 5 && std::string(argv[4]) == "--require-wow64";
    bool legacy = argc == 5 && std::string(argv[4]) == "--require-legacy-wine32";
    if (argc == 5 && !wow64 && !legacy) return 2;
    exercise(argv[1], argv[2], 8, false, false);
    exercise(argv[1], argv[3], 4, wow64, legacy);
    printf("%d failed Wine integration checks\n", failures);
    return failures ? 1 : 0;
}
