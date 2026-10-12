// Architecture-generic process checks for instruction sets without a full
// debugger backend (RISC-V first). Runs as /init in a full-system guest of
// that architecture: it starts the static libc fixture (test/static_fixture.c)
// and drives it through cecore's own process handle, scanners, pointer
// scanner, symbol loader and disassembler. Nothing is emulated or faked: the
// guest kernel provides ptrace, /proc and process_vm_readv/writev.
#include "arch/disassembler.hpp"
#include "core/target_capabilities.hpp"
#include "debug/code_finder.hpp"
#include "debug/debug_session.hpp"
#include "platform/linux/injector.hpp"
#include "platform/linux/ptrace_wrapper.hpp"
#include "arch/target_arch.hpp"
#include "platform/linux/linux_process.hpp"
#include "scanner/memory_scanner.hpp"
#include "scanner/pointer_scanner.hpp"
#include "symbols/elf_symbols.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace ce;

static int checks = 0, failures = 0;
static void check(bool ok, const char* name) {
    ++checks;
    failures += !ok;
    std::printf("ISA_VM_CHECK %s: %s\n", ok ? "OK" : "FAILED", name);
    std::fflush(stdout);
}

// Runs the real CLI (/cescan, present when the gate adds the frontends) and
// returns its combined output.
static std::string cescan(std::vector<std::string> args) {
    int out[2];
    if (pipe(out)) return {};
    pid_t child = fork();
    if (child == 0) {
        dup2(out[1], 1); dup2(out[1], 2);
        close(out[0]); close(out[1]);
        std::vector<char*> argv{const_cast<char*>("/cescan")};
        for (auto& arg : args) argv.push_back(arg.data());
        argv.push_back(nullptr);
        execv("/cescan", argv.data());
        _exit(127);
    }
    close(out[1]);
    std::string text;
    char buffer[4096];
    ssize_t n;
    while ((n = ::read(out[0], buffer, sizeof(buffer))) > 0) text.append(buffer, static_cast<size_t>(n));
    close(out[0]);
    waitpid(child, nullptr, 0);
    return text;
}

struct Fixture {
    pid_t pid = -1;
    int input = -1;
    FILE* output = nullptr;
    std::string line() {
        char buffer[256];
        return std::fgets(buffer, sizeof(buffer), output) ? std::string(buffer) : std::string();
    }
    long command(char letter) {
        if (::write(input, &letter, 1) != 1) return -1;
        return std::strtol(line().c_str(), nullptr, 10);
    }
};

static int run() {
    struct utsname name{};
    uname(&name);
    std::printf("ISA_VM_KERNEL release=%s machine=%s\n", name.release, name.machine);
    int in[2], out[2];
    if (pipe(in) || pipe(out)) { check(false, "create the fixture pipes"); return 1; }
    Fixture fixture;
    fixture.pid = fork();
    if (fixture.pid == 0) {
        dup2(in[0], 0); dup2(out[1], 1);
        close(in[0]); close(in[1]); close(out[0]); close(out[1]);
        execl("/fixture", "fixture", nullptr);
        _exit(127);
    }
    close(in[0]); close(out[1]);
    fixture.input = in[1];
    fixture.output = fdopen(out[0], "r");
    unsigned long value = 0, pointer = 0, writer = 0;
    int reported = 0;
    const auto header = fixture.line();
    const bool started = std::sscanf(header.c_str(), "CE_STATIC %d %lx %lx %lx", &reported, &value, &pointer, &writer) == 4 &&
        reported == fixture.pid;
    check(started, "the static libc fixture runs under the guest kernel");
    if (!started) return 1;

    os::LinuxProcessHandle process(fixture.pid);
    const auto description = process.targetDescription();
    const auto native = nativeTargetMachine();
    std::printf("ISA_VM_TARGET architecture=%s abi=%s width=%u\n", cpuArchitectureName(description.program.architecture),
                targetAbiName(description.program.abi), description.program.pointerWidth);
    const auto modules = process.modules();
    // The program's ABI can differ from the engine's on the same ISA (x32).
    unsigned char ident[5]{};
    if (FILE* elf = std::fopen("/fixture", "rb")) { std::fread(ident, 1, sizeof(ident), elf); std::fclose(elf); }
    const unsigned width = ident[4] == 1 ? 4 : 8;
    check(description.live && description.program.architecture == native.architecture &&
          description.program.pointerWidth == width &&
          std::any_of(modules.begin(), modules.end(), [](const ModuleInfo& m) { return m.name == "fixture"; }),
          "the target description and module list identify the native program");
    SymbolResolver symbols;
    symbols.loadProcess(process);
    check(symbols.lookup("ce_writer") == writer && symbols.lookup("ce_value") == value,
          "the ELF symbol table names the writer and the value");

    int32_t written = 7654321;
    auto wrote = process.write(value, &written, sizeof(written));
    check(wrote && fixture.command('r') == 7654321, "a write through process memory reaches the program");

    MemoryScanner scanner(1);
    ScanConfig scan;
    scan.valueType = ValueType::Int32;
    scan.intValue = 7654321;
    auto contains = [&](const ScanResult& result) {
        for (size_t i = 0; i < result.count(); ++i) if (result.address(i) == value) return true;
        return false;
    };
    auto first = scanner.firstScan(process, scan);
    check(contains(first), "a whole-process first scan finds the value");
    written = 7654322;
    process.write(value, &written, sizeof(written));
    scan.intValue = 7654322;
    auto next = scanner.nextScan(process, scan, first);
    check(contains(next) && next.count() <= first.count(), "a next scan follows the changed value");

    PointerScanner pointers;
    PointerScanConfig pointerScan;
    pointerScan.targetAddress = value;
    pointerScan.maxDepth = 1;
    pointerScan.maxOffset = 64;
    auto paths = pointers.scan(process, pointerScan);
    check(std::any_of(paths.begin(), paths.end(), [&](const PointerPath& path) {
              return path.module == "fixture" && path.moduleBase + path.baseOffset == pointer &&
                     PointerScanner::dereference(process, path) == value;
          }), "a pointer scan finds the static pointer path and it resolves");

    auto architecture = disassemblerArchFor(process, writer);
    uintptr_t codeAddress = writer;
#if defined(__arm__)
    // ARM EABI interworking: a function pointer with its low bit set is Thumb code.
    if (architecture && (writer & 1)) { architecture = Arch::ARMThumb; codeAddress = writer & ~uintptr_t(1); }
#endif
    uint8_t code[32]{};
    auto read = process.read(codeAddress, code, sizeof(code));
    bool decoded = false;
    if (architecture && read) {
        Disassembler disassembler(*architecture);
        auto instructions = disassembler.disassemble(codeAddress, std::span<const uint8_t>(code, *read));
        decoded = !instructions.empty() && instructions.front().address == codeAddress && instructions.front().mnemonic != "db";
        for (size_t i = 0; i < std::min<size_t>(instructions.size(), 4); ++i)
            std::printf("ISA_VM_DISASM %lx %s %s\n", (unsigned long)instructions[i].address,
                        instructions[i].mnemonic.c_str(), instructions[i].operands.c_str());
    } else if (!architecture) {
        std::printf("ISA_VM_DISASM unavailable: %s\n", architecture.error().c_str());
    }
    check(decoded, "the writer's instructions decode with the native instruction set");
    if (!native.isX86() && native.architecture != CpuArchitecture::Arm64) {
        // No allocation, native-call, watchpoint or debugger backend exists for
        // this instruction set: each real API must refuse with its reason.
        auto explained = [&](TargetFeature feature, std::error_code error, const char* what) {
            auto reason = targetOperationError(process, feature, error);
            std::printf("ISA_VM_REFUSAL %s: %s\n", what, reason.c_str());
            return reason.find("backend") != std::string::npos;
        };
        auto allocated = process.allocate(4096, MemProt::ReadWrite);
        check(!allocated && explained(TargetFeature::Allocate, allocated.error(), "allocate"),
              "allocation is refused with an explicit reason");
        auto thread = os::createRemoteThread(process, symbols, writer, true, 1000);
        if (!thread) std::printf("ISA_VM_REFUSAL remote thread: %s\n", thread.error().c_str());
        check(!thread && thread.error().find("backend") != std::string::npos,
              "native calls (remote threads) are refused with an explicit reason");
        os::LinuxDebugger debugger;
        CodeFinder finder;
        bool watching = finder.start(process, debugger, value, true, 4);
        if (watching) finder.stop();
        check(!watching && explained(TargetFeature::HardwareWatchpoint, finder.lastError(), "watchpoint"),
              "find-what-writes is refused with an explicit reason");
        DebugSession session;
        bool attached = session.attach(fixture.pid, &process);
        if (attached) session.detach();
        check(!attached && explained(TargetFeature::Debugger, session.lastError(), "debugger"),
              "the debugger is refused with an explicit reason");
    }
    check(fixture.command('b') == 7654323, "the program keeps running after every check");

    if (access("/cescan", X_OK) == 0) {
        // The same target through the user-facing CLI and Lua frontends.
        const std::string pid = std::to_string(fixture.pid);
        char address[32];
        std::snprintf(address, sizeof(address), "%#lx", value);
        auto shown = [](const char* what, const std::string& output) {
            std::printf("ISA_VM_FRONTEND %s:\n%s\n", what, output.substr(output.size() > 1500 ? output.size() - 1500 : 0).c_str());
        };
        auto info = cescan({"info", pid});
        bool identified = info.find(std::string("program:  ") + cpuArchitectureName(description.program.architecture)) != std::string::npos &&
                          info.find(targetAbiName(description.program.abi)) != std::string::npos;
        if (!identified) shown("info", info);
        check(identified, "cescan info identifies the program and its ABI");
        auto written = cescan({"write", pid, address, "2468", "--type", "i32"});
        bool reached = fixture.command('r') == 2468;
        if (!reached) shown("write", written);
        check(reached, "cescan write reaches the program");
        auto scanned = cescan({"scan", pid, "--type", "i32", "--value", "2468"});
        bool found = scanned.find(address) != std::string::npos;
        if (!found) shown("scan", scanned);
        check(found, "cescan scan finds the value");
        auto script = cescan({"lua", "-e", "assert(openProcess(" + pid + "))\nassert(readInteger(" + address +
                              ") == 2468)\nassert(writeInteger(" + address + ", 1357))\nprint('LUA_FRONTEND_OK')"});
        bool scripted = script.find("LUA_FRONTEND_OK") != std::string::npos && fixture.command('r') == 1357;
        if (!scripted) shown("lua", script);
        check(scripted, "a cescan lua script reads and writes the program");
    }

    kill(fixture.pid, SIGKILL);
    waitpid(fixture.pid, nullptr, 0);
    std::printf("ISA_VM_RESULT=%s architecture=%s checks=%d\n", failures ? "FAILED" : "PASSED",
                cpuArchitectureName(native.architecture), checks);
    return failures ? 1 : 0;
}

int main() {
    mount("proc", "/proc", "proc", 0, nullptr);
    setvbuf(stdout, nullptr, _IOLBF, 0);
    run();
    std::fflush(stdout);
    sync();
    reboot(RB_POWER_OFF);
    return 0;
}
