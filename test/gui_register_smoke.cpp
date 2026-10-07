// Live kernel ptrace through the real Qt debugger. Runs on x86-64 and ARM64.
#include "gui/debuggerwindow.hpp"
#include "gui/registereditor.hpp"
#include "gui/stackview.hpp"
#include "debug/thread_inspection.hpp"
#include "platform/linux/syscall_service.hpp"
#include <QPushButton>
#include <chrono>
#include "core/cpu_registers.hpp"
#include "platform/linux/linux_process.hpp"
#include <QApplication>
#include <QTableWidget>
#include <QHeaderView>
#include <QFile>
#include <QFontDatabase>
#include <QProcess>
#include <QComboBox>
#include <thread>
#include <pthread.h>
#include <cstdio>
#include <cerrno>
#include <cstring>
#include <signal.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/utsname.h>
#include <unistd.h>

extern "C" void register_gui_hot();
#if defined(__aarch64__)
asm(".text\n.balign 4\n.global register_gui_hot\n.type register_gui_hot,%function\n"
    "register_gui_hot:\n nop\n nop\n ret\n.size register_gui_hot,.-register_gui_hot\n");
#elif defined(__x86_64__)
asm(".text\n.global register_gui_hot\n.type register_gui_hot,@function\n"
    "register_gui_hot:\n nop\n nop\n ret\n.size register_gui_hot,.-register_gui_hot\n");
#else
#error This live GUI fixture requires an implemented native debugger ISA
#endif

static volatile uint32_t* fixtureHold;

static void targetLoop() {
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    prctl(PR_SET_PTRACER, getppid()); // Permit frontend children under Yama scope 1.
    for (;;) {
        const uint64_t value = 0x0102030405060708ull;
#if defined(__aarch64__)
        asm volatile("fmov d0,%0\n fmov d31,%0" :: "r"(value) : "v0", "v31");
#else
        asm volatile("movq %0,%%xmm0\n movq %0,%%xmm15" :: "r"(value) : "xmm0", "xmm15");
#endif
        register_gui_hot();
        // Cooperatively hold the real target in instructions that leave the
        // edited callee-saved register untouched between inspection stops.
        // The acknowledgement is emitted inside that same loop.
        if (fixtureHold[0]) {
#if defined(__aarch64__)
            asm volatile("mov x9,%0\n add x10,x9,#4\n mov w11,#1\n stlr w11,[x10]\n"
                         "1: yield\n ldar w11,[x9]\n cbnz w11,1b\n stlr wzr,[x10]"
                         :: "r"(fixtureHold) : "x9", "x10", "x11", "memory");
#else
            asm volatile("movl $1,4(%%rax)\n 1: pause\n cmpl $0,(%%rax)\n jne 1b\n movl $0,4(%%rax)"
                         :: "a"(fixtureHold) : "cc", "memory");
#endif
        }
        usleep(1000);
    }
}

int main(int argc, char** argv) {
    const bool init = getpid() == 1;
    if (init) {
        mkdir("/proc", 0755); mount("proc", "/proc", "proc", 0, nullptr);
        mkdir("/tmp", 01777); mount("tmpfs", "/tmp", "tmpfs", 0, "size=16m");
        setenv("LD_LIBRARY_PATH", "/lib", 1);
        setenv("QT_PLUGIN_PATH", "/qt/plugins", 1);
        setenv("CECORE_GUI_SCREENSHOT", "/tmp/debugger.png", 1);
        setenv("CECORE_GUI_APPLICATION", "/cheatengine", 1);
        setenv("CECORE_GUI_CLI", "/cescan", 1);
        mkdir("/tmp/fontconfig", 0755);
        setenv("XDG_CACHE_HOME", "/tmp", 1);
    }
    setvbuf(stdout, nullptr, _IONBF, 0);
    utsname system{};
    if (uname(&system) == 0) std::printf("GUI_KERNEL release=%s machine=%s\n", system.release, system.machine);
    qputenv("QT_QPA_PLATFORM", "offscreen");
    const auto began=std::chrono::steady_clock::now();
    auto stage=[&](const char* name) {
        const auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-began).count();
        std::printf("GUI_STAGE name=%s elapsedMs=%lld\n",name,static_cast<long long>(elapsed));
    };
    stage("begin");
    int failures = 0;
    auto check = [&](bool ok, const char* message) {
        std::printf("%s: %s\n", ok ? "OK" : "FAILED", message); failures += !ok;
    };
    const bool leaderExit=getenv("CECORE_GUI_LEADER_EXIT") && std::strcmp(getenv("CECORE_GUI_LEADER_EXIT"),"1")==0;
    auto* shared=mmap(nullptr,4096,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    if (shared==MAP_FAILED) { std::perror("mmap"); return 1; }
    fixtureHold=static_cast<volatile uint32_t*>(shared);
    pid_t child = fork();
    if (!child) {
        if (leaderExit) {
            std::thread worker(targetLoop); worker.detach();
            pthread_exit(nullptr);
        }
        targetLoop();
    }
    if (child < 0) { std::perror("fork"); return 1; }
    pid_t selectedTid=child;
    if (leaderExit) {
        const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
        while (std::chrono::steady_clock::now()<deadline) {
            auto task=ce::os::processMemoryTask(child);
            if (task && *task!=child) { selectedTid=*task; break; }
            usleep(1000);
        }
        check(selectedTid!=child,"the real GUI fixture leader exits while its pthread target continues running");
        std::printf("GUI_LEADER_EXIT_RESULT=%s\n",selectedTid!=child ? "PASSED" : "FAILED");
    }
    {
        QApplication app(argc, argv);
        if (init) QFontDatabase::addApplicationFont("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf");
        ce::os::LinuxProcessHandle process(child);
        ce::gui::DebuggerWindow window(&process);
        window.show();
        const bool arm = ce::nativeTargetMachine().architecture == ce::CpuArchitecture::Arm64;
        auto* table = window.findChild<QTableWidget*>("debuggerRegisters");
        auto pump = [&] { app.processEvents(); usleep(5000); };
        for (int i = 0; i < 10; ++i) pump();
        check(window.debugAttached() && window.debugStopped(), "GUI attaches and reads a real stopped thread");
        if (leaderExit) check(window.threadCount()==1,
                              "the full debugger thread selector omits the exited process leader");
        const uintptr_t hot = reinterpret_cast<uintptr_t>(&register_gui_hot);
        const size_t instructionSize = arm ? 4 : 1;
        window.addBreakpointAt(hot);
        QMetaObject::invokeMethod(&window, "onContinue");
        bool hit = false;
        for (int i = 0; i < 600 && !hit; ++i) {
            pump(); hit = window.debugStopped() && window.currentStopRip() == hot;
        }
        check(hit && window.currentStopContext().instructionPointer() == hot,
              "GUI follows the native program counter at a software breakpoint");
        auto context = window.currentStopContext();
        check(table && table->rowCount() == (arm ? 68 : 35) &&
              table->verticalHeaderItem(0)->text() == (arm ? "PC" : "RIP") &&
              table->verticalHeaderItem(1)->text() == (arm ? "SP" : "RSP"),
              "register names and row count match the stopped thread ISA");
        check(table && table->verticalHeaderItem(arm ? 65 : 33)->text() == (arm ? "V31" : "XMM15") &&
              window.vectorRegisterShowsForTest(arm ? 31 : 15, 0x0102030405060708ull),
              "highest architectural SIMD register displays actual kernel state");
        auto edit = [&](size_t row, uint64_t value) {
            return hit && window.pokeRegisterForTest(static_cast<int>(row), value) &&
                   ce::cpuRegisterValues(window.currentStopContext())[row].value == value;
        };
        check(edit(arm ? 4 : 17, 0x123456789abcdef0ull),
              "general register edit is read back from the real kernel and cached stop context");
        check(edit(2, 0x1122334455667788ull) && edit(2, context.framePointer()),
              "frame pointer edit and restoration reach the stopped thread");
        if (arm) check(edit(3, hot + 8) && edit(3, context.x[30]),
                       "ARM64 link register edit and restoration reach the stopped thread");
        check(edit(0, hot + instructionSize) && window.disasmCurrentLineHighlightedForTest() &&
              window.currentStopRip() == hot + instructionSize && edit(0, hot),
              "program counter edit refreshes navigation and current instruction highlighting");
        check(edit(1, context.stackPointer() + 16) &&
              window.stackTextForTest().startsWith(QStringLiteral("0x%1:").arg(context.stackPointer() + 16, 0, 16)) &&
              edit(1, context.stackPointer()), "stack pointer edit refreshes the stack pane from the native register");
        check(edit(arm ? 33 : 9, arm ? ((context.pstate & ~0xf0000000ull) | 0x60000000) : 0x246) &&
              window.flagsTextForTest().contains(arm ? "N=0 Z=1 C=1 V=0" : "ZF=1"),
              "status edit displays native NZCV or EFLAGS from kernel readback");
        window.addBreakpointAt(hot + instructionSize);
        const auto disassembly = window.disasmTextForTest();
        check(disassembly.count(" nop") >= 2 && !disassembly.contains(arm ? "brk" : "int3"),
              "disassembly restores the complete planted breakpoint instruction");
        uint8_t planted[4]{};
        auto read = process.read(hot + instructionSize, planted, instructionSize);
        check(read && *read == instructionSize && (arm ? planted[3] == 0xd4 : planted[0] == 0xcc),
              "instruction view masking preserves the real software trap in target memory");
        uint8_t saved[16]{};
        auto stackRead = process.read(context.stackPointer(), saved, sizeof(saved));
        bool stack = false;
        if (stackRead && *stackRead == sizeof(saved)) {
            const uint64_t words[] = {0x1020304050607080ull, 0x2131415161718191ull};
            auto written = process.write(context.stackPointer(), words, sizeof(words));
            if (written && *written == sizeof(words) && edit(arm ? 4 : 17, 0x123456789abcdef1ull)) {
                const auto text = window.stackTextForTest();
                stack = text.contains("0x1020304050607080") && text.contains("0x2131415161718191");
            }
            const uint64_t zero = 0;
            auto zeroWrite = process.write(context.stackPointer(), &zero, sizeof(zero));
            check(zeroWrite && *zeroWrite == sizeof(zero) && edit(arm ? 4 : 17, 0x123456789abcdef2ull) &&
                  window.stackTextForTest().section('\n', 0, 0) == QStringLiteral("0x%1: 0x0").arg(context.stackPointer(), 0, 16),
                  "null stack values never acquire a misleading absolute symbol annotation");
            const auto restoredStack = process.write(context.stackPointer(), saved, sizeof(saved));
            stack = stack && restoredStack && *restoredStack == sizeof(saved);
        }
        check(stack, "stack pane reads consecutive native-width values from the live target");
        for (int i = 0; i < 5; ++i) pump();
        if (const char* screenshot = getenv("CECORE_GUI_SCREENSHOT"))
            check(window.grab().save(QString::fromLocal8Bit(screenshot)), "debugger screenshot saved");
        stage("primary-screenshot");
        if (init) {
            QFile png("/tmp/debugger.png");
            if (png.open(QIODevice::ReadOnly))
                std::printf("CE_GUI_SCREENSHOT_PNG=%s\n", png.readAll().toBase64().constData());
        }
        check(edit(arm ? 4 : 17, ce::cpuRegisterValues(context)[arm ? 4 : 17].value),
              "the fixture restores its original general register before resuming target execution");
        QMetaObject::invokeMethod(&window, "onDetach");
        check(!window.debugAttached() && table && !table->isEnabled(),
              "detached register cells cannot submit stale edits");
        uint8_t restored[8]{};
        auto restoredRead = process.read(hot, restored, instructionSize * 2);
        check(restoredRead && *restoredRead == instructionSize * 2 &&
              (arm ? restored[0] == 0x1f && restored[3] == 0xd5 && restored[4] == 0x1f && restored[7] == 0xd5 :
                     restored[0] == 0x90 && restored[1] == 0x90),
              "GUI detach restores every original instruction byte");
        stage("standalone-begin");
        // These editors release their ptrace stop after each transaction. Hold
        // target execution so later independent kernel reads cannot
        // race target code restoring a callee-saved register from its stack.
        fixtureHold[0]=1;
        const auto stopDeadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
        while (!fixtureHold[1] && std::chrono::steady_clock::now()<stopDeadline) usleep(1000);
        check(fixtureHold[1],"the real target acknowledges its register-preserving loop before standalone edits");
        {
            ce::gui::RegisterEditorWindow editor(&process);
            editor.show(); pump();
            auto* general = editor.findChild<QTableWidget*>("registerEditorGeneral");
            auto* vectors = editor.findChild<QTableWidget*>("registerEditorVectors");
            auto* status = editor.findChild<QLabel*>("registerEditorStatus");
            if (leaderExit) {
                auto* threads=editor.findChild<QComboBox*>("registerEditorThreads");
                check(threads && threads->count()==1 && threads->currentData().toInt()==selectedTid,
                      "the standalone editor selects the actual surviving pthread by default");
            }
            check(general && general->isEnabled() && general->rowCount() == (arm ? 34 : 18) &&
                  general->item(0,0)->text() == (arm ? "PC" : "RIP") &&
                  vectors && vectors->rowCount() == (arm ? 34 : 17) &&
                  vectors->item(arm ? 31 : 15,0)->text() == (arm ? "V31" : "XMM15/YMM15"),
                  "standalone editor exposes the actual general and SIMD register banks");
            auto* apply = editor.findChild<QPushButton*>("registerEditorApply");
            if (apply) apply->click();
            check(status && status->text() == "No register values changed",
                  "applying unchanged editor cells never replays a stale register snapshot");
            if (general && general->isEnabled()) {
                const unsigned row=arm ? 32 : 17;
                bool parsed=false;
                const auto original=general->item(row,1)->text().toULongLong(&parsed,16);
                general->item(row,1)->setText(QString::number(original^1,16));
                if (apply) apply->click();
                auto actual=ce::inspectThread(process,selectedTid);
                check(parsed && status && status->text().startsWith("Applied changes") && actual && fixtureHold[1] &&
                      ce::cpuRegisterValues(actual->context)[row].value==(original^1),
                      "standalone editor applies changed general registers through the real kernel owner");
                general->item(row,1)->setText(QString::number(original,16));
                if (apply) apply->click();
                check(status && status->text().startsWith("Applied changes"),
                      "standalone editor refreshes kernel state after applying and restoring an edit");
            }
            if (general && general->rowCount()) {
                general->item(0,1)->setText("invalid");
                if (apply) apply->click();
            }
            check(status && status->text().startsWith("Invalid") && general->isEnabled(),
                  "invalid register text leaves the live target and editable snapshot intact");
            if (auto* refresh = editor.findChild<QPushButton*>("registerEditorRefresh")) refresh->click();
            check(status && status->text().startsWith("Loaded TID") && general->isEnabled(),
                  "refresh replaces invalid editor text with a fresh kernel snapshot");
            ce::gui::StackViewWindow stackWindow(&process);
            stackWindow.show(); pump();
            auto* raw = stackWindow.findChild<QTableWidget*>("stackViewRaw");
            auto* stackStatus = stackWindow.findChild<QLabel*>("stackViewStatus");
            bool words = raw && raw->rowCount() == 32 && stackStatus &&
                stackStatus->text().contains(arm ? " SP=" : " RSP=");
            if (words) {
                bool ok0=false,ok1=false;
                auto first=raw->item(0,0)->text().toULongLong(&ok0,16);
                auto next=raw->item(1,0)->text().toULongLong(&ok1,16);
                words=ok0 && ok1 && next==first+8;
            }
            check(words,"standalone stack reads stopped-thread native SP and consecutive architectural words");
            if (const char* screenshot = getenv("CECORE_GUI_SCREENSHOT")) {
                check(editor.grab().save(QString::fromLocal8Bit(screenshot)+".register-editor.png") &&
                      stackWindow.grab().save(QString::fromLocal8Bit(screenshot)+".stack.png"),
                      "standalone register and stack screenshots saved");
            }
            stage("standalone-screenshots");
            if (init) for (const auto& entry : {std::pair{"REGISTER_EDITOR", "/tmp/debugger.png.register-editor.png"},
                                              std::pair{"STACK", "/tmp/debugger.png.stack.png"}}) {
                QFile png(entry.second);
                if (png.open(QIODevice::ReadOnly))
                    std::printf("CE_%s_SCREENSHOT_PNG=%s\n", entry.first, png.readAll().toBase64().constData());
            }
        }
        fixtureHold[0]=0;
        const auto continueDeadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
        while (fixtureHold[1] && std::chrono::steady_clock::now()<continueDeadline) usleep(1000);
        check(!fixtureHold[1],"the standalone fixture resumes target execution before CLI and application checks");
        stage("cli-begin");
        if (const char* cli = getenv("CECORE_GUI_CLI")) {
            QProcess command;
            command.start(QString::fromLocal8Bit(cli), {"info", QString::number(child)});
            const bool completed = command.waitForFinished(30000);
            const auto info = command.readAllStandardOutput();
            check(completed && command.exitStatus() == QProcess::NormalExit && command.exitCode() == 0 &&
                  info.contains(arm ? "ARM64 (Linux AArch64, 8-byte pointers, little-endian)" : "x86-64 (Linux x86-64, 8-byte pointers, little-endian)"),
                  "actual CLI inspects the running native target");
            const QString code = QStringLiteral("assert(openProcess(%1)); local t=getTargetInfo(); "
                "assert(t.program.architecture=='%2' and t.program.pointerWidth==8); "
                "assert(disassemble(%3):find('nop')); print('CE_ARM_FRONTEND_LUA=PASSED')")
                .arg(child).arg(arm ? "ARM64" : "x86-64").arg(hot);
            command.start(QString::fromLocal8Bit(cli), {"lua", "-e", code});
            const bool luaCompleted = command.waitForFinished(30000);
            check(luaCompleted && command.exitStatus() == QProcess::NormalExit && command.exitCode() == 0 &&
                  command.readAllStandardOutput().contains("CE_ARM_FRONTEND_LUA=PASSED"),
                  "actual CLI Lua runner resolves metadata and disassembles live native code");
        }
        stage("application-begin");
        if (const char* application = getenv("CECORE_GUI_APPLICATION")) {
            const QString shot = init ? "/tmp/application.png" : QString::fromLocal8Bit(application) + ".smoke.png";
            QFile::remove(shot);
            QProcess frontend;
            auto environment = QProcessEnvironment::systemEnvironment();
            environment.insert("CE_SCREENSHOT", shot); frontend.setProcessEnvironment(environment);
            frontend.start(QString::fromLocal8Bit(application), {"--pid", QString::number(child), "--memview", QString::number(hot)});
            stage("application-started");
            // On this resource-limited host, startup in a one-CPU TCG guest
            // took 67 seconds and a leaderless target missed a 90-second limit.
            // Keep a bounded guest budget within the outer 480-second VM limit.
            const bool completed = frontend.waitForFinished(init ? 180000 : 30000);
            stage("application-finished");
            if (!completed) { frontend.kill(); frontend.waitForFinished(5000); }
            if (!completed || frontend.exitCode() != 0)
                std::printf("APPLICATION_DIAGNOSTIC completed=%d exit=%d stderr=%s\n", completed,
                            frontend.exitCode(), frontend.readAllStandardError().constData());
            QFile png(shot);
            check(completed && frontend.exitStatus() == QProcess::NormalExit && frontend.exitCode() == 0 &&
                  png.open(QIODevice::ReadOnly) && png.peek(8) == QByteArray::fromHex("89504e470d0a1a0a"),
                  "actual GUI application attaches, opens the memory viewer, renders and exits cleanly");
            if (init && png.isOpen())
                std::printf("CE_APPLICATION_SCREENSHOT_PNG=%s\n", png.readAll().toBase64().constData());
        }
        stage("paused-exit-begin");
        {
            ce::gui::DebuggerWindow deathWindow(&process);
            deathWindow.show();
            auto* deathRegisters=deathWindow.findChild<QTableWidget*>("debuggerRegisters");
            check(deathWindow.debugAttached() && deathWindow.debugStopped() && deathRegisters && deathRegisters->isEnabled(),
                  "the GUI owns a real paused target before external process death");
            const bool killed=kill(child,SIGKILL)==0;
            bool retired=false;
            for (int i=0;i<600 && !retired;++i) {
                pump();
                retired=!deathWindow.debugAttached() && !deathWindow.debugStopped() && deathRegisters && !deathRegisters->isEnabled();
            }
            check(killed && retired,"a paused target's actual death automatically retires the GUI session and disables stale register edits");
            QMetaObject::invokeMethod(&deathWindow,"onDetach");
        }
        int status=0; pid_t reaped=-1;
        do { reaped=waitpid(child,&status,0); } while (reaped<0 && errno==EINTR);
        check(reaped==child && (WIFEXITED(status) || WIFSIGNALED(status)),
              "the GUI releases its kernel owner so actual final process death can be reaped normally");
        stage("paused-exit-finished");
    }
    munmap(shared,4096);
    std::printf("GUI_REGISTER_RESULT=%s architecture=%s\n", failures ? "FAILED" : "PASSED",
                ce::cpuArchitectureName(ce::nativeTargetMachine().architecture));
    if (init) { sync(); reboot(RB_POWER_OFF); for (;;) pause(); }
    return failures ? 1 : 0;
}
