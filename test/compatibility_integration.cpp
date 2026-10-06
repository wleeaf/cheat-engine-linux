#include "platform/linux/linux_process.hpp"
#include "core/target_capabilities.hpp"
#include "core/injection_gen.hpp"
#include "core/autoasm.hpp"
#include "core/value_io.hpp"
#include "core/expression.hpp"
#include <cstdio>
#include <array>
#include <cstring>
#include <string>
#include <sstream>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/prctl.h>

using namespace ce;
static int failures;
static void check(bool ok, const char* name) {
    printf("%s: %s\n", ok ? "OK" : "FAILED", name);
    failures += !ok;
}
class Fixture {
public:
    pid_t pid = -1;
    int input = -1, output = -1;
    explicit Fixture(const char* executable, const char* next = nullptr) {
        int in[2], out[2];
        if (pipe(in)) return;
        if (pipe(out)) { close(in[0]); close(in[1]); return; }
        pid = fork();
        if (pid == 0) {
            prctl(PR_SET_PDEATHSIG, SIGKILL);
            dup2(in[0], 0); dup2(out[1], 1);
            close(in[0]); close(in[1]); close(out[0]); close(out[1]);
            if (next) execl(executable, executable, next, nullptr);
            else execl(executable, executable, nullptr);
            _exit(127);
        }
        close(in[0]); close(out[1]); input = in[1]; output = out[0];
    }
    bool command(char c) { return ::write(input, &c, 1) == 1; }
    std::string line() {
        std::string line;
        while (line.size() < 4096) {
            pollfd fd{output, POLLIN, 0};
            if (poll(&fd, 1, 5000) <= 0) return {};
            char c;
            if (::read(output, &c, 1) != 1) return {};
            if (c == '\n') return line;
            line += c;
        }
        return {};
    }
    bool finish() {
        if (!command('q')) return false;
        int status = 0;
        pid_t result;
        do { result = waitpid(pid, &status, 0); } while (result < 0 && errno == EINTR);
        if (result == pid) pid = -1;
        return result > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }
    ~Fixture() {
        if (pid > 0) { kill(pid, SIGKILL); int status; while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {} }
        if (input >= 0) close(input);
        if (output >= 0) close(output);
    }
};
struct Ready { unsigned width = 0; uintptr_t value = 0, pointer = 0, code = 0; };
static Ready ready(Fixture& fixture) {
    Ready r;
    auto line = fixture.line();
    std::istringstream stream(line); std::string magic; pid_t pid;
    stream >> magic >> pid >> r.width >> std::hex >> r.value >> r.pointer >> r.code;
    if (!stream || magic != "CE_TARGET" || pid != fixture.pid || (r.width != 4 && r.width != 8)) return {};
    return r;
}
#include "autoasm_module_lifecycle_checks.inc"
static void exercise(const char* path, unsigned width) {
    Fixture fixture(path);
    auto r = ready(fixture);
    check(r.width == width, width == 4 ? "real i386 fixture starts without a 32-bit libc" : "real x86-64 fixture starts");
    if (!r.width) return;
    os::LinuxProcessHandle process(fixture.pid);
    auto d = process.targetDescription();
    check(d.live && d.program.pointerWidth == width && d.host.pointerWidth == width &&
          d.program.architecture == (width == 4 ? CpuArchitecture::X86_32 : CpuArchitecture::X86_64),
          "process metadata matches the live fixture ABI");
    auto pointer = readTypedValue(process, r.pointer, ValueType::Pointer);
    char expression[64]; snprintf(expression, sizeof(expression), "[0x%lx]", static_cast<unsigned long>(r.pointer));
    check(pointer.has_value() && ExpressionParser(&process).parse(expression) == r.value,
          "live pointer reads and expression dereferences use the target width");
    auto write = writeTypedValue(process, r.value, ValueType::Int32, "31415926");
    fixture.command('r');
    check(write && fixture.line() == "31415926", "the target observes a typed cross-process write");
    auto cave = process.allocate(4096, MemProt::ReadWrite);
    if (!cave) printf("allocation error: %s\n", cave.error().message().c_str());
    check(cave.has_value(), "live target syscall allocation succeeds");
    if (cave) {
        auto wrote = writeTypedValue(process, *cave, ValueType::Int32, "12345");
        auto protection = process.protect(*cave, 4096, MemProt::Read);
        auto denied = writeTypedValue(process, *cave, ValueType::Int32, "0");
        check(wrote && protection && !denied && readTypedValue(process, *cave, ValueType::Int32) == "12345",
              "read-only target protection rejects writes without altering data");
        auto freed = process.free(*cave, 4096);
        check(freed && !readTypedValue(process, *cave, ValueType::Int32), "deallocated target memory becomes unreadable");
    }
    std::array<uint8_t, 32> original{};
    auto before = process.read(r.code, original.data(), original.size());
    std::string error;
    auto script = generateInjectionScript(process, r.code, InjectionKind::Code, error);
    AutoAssembler assembler;
    auto injected = assembler.execute(process, script);
    if (!injected.success) printf("injection error: %s %s\n", error.c_str(), injected.error.c_str());
    check(before && injected.success, "generated injection template activates in the live target");
    if (injected.success) {
        fixture.command('b');
        check(fixture.line() == "31415927", "relocated target instructions execute with unchanged behavior");
        auto disabled = assembler.disable(process, script, injected.disableInfo);
        std::array<uint8_t, 32> restored{};
        auto after = process.read(r.code, restored.data(), restored.size());
        auto region = process.queryRegion(r.code);
        check(disabled.success && after && restored == original && region && !(region->protection & MemProt::Write),
              "live injection cleanup restores exact code bytes and original page permissions");
        fixture.command('b');
        check(fixture.line() == "31415928", "the target continues executing after injection cleanup");
    }
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    alarm(45);
    if (argc != 3) { fprintf(stderr, "usage: compatibility_integration <native64> <native32>\n"); return 2; }
    exercise(argv[1], 8); exercise(argv[2], 4);
    Fixture transition(argv[1], argv[2]);
    auto initial = ready(transition);
    os::LinuxProcessHandle process(transition.pid);
    auto before = process.targetDescription();
    transition.command('x');
    auto changed = ready(transition);
    auto after = process.targetDescription();
    check(initial.width == 8 && changed.width == 4 && before.program.pointerWidth == 8 &&
          after.program.pointerWidth == 4 && after.program.architecture == CpuArchitecture::X86_32,
          "an existing handle refreshes ABI and instruction mode across exec");
    check(readTypedValue(process, changed.value, ValueType::Int32) == "123456789",
          "memory access follows the new executable after exec");
    autoasm_module_test::run(argv[1], argv[2]);
    printf("%d failed live integration checks\n", failures);
    return failures ? 1 : 0;
}
