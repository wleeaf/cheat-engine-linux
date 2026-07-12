// Headless (offscreen Qt) smoke test for the interactive DebuggerWindow.
// Drives the real GUI class against a forked multi-threaded target: constructs
// the window (which attaches), sets a breakpoint on a function only sibling
// threads call, continues, and verifies the window reports a stop at that
// address with the whole target frozen (all-stop) and still alive. This exercises
// the GUI attach + tracer-thread→UI event marshalling + refresh + breakpoint/
// continue path end to end. Exit 0 on success.

#include "gui/debuggerwindow.hpp"
#include "platform/linux/linux_process.hpp"

#include <QApplication>
#include <thread>
#include <cstdio>
#include <cstdint>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

static volatile long g_smoke_counter = 0;
__attribute__((noinline)) static void smoke_hot() { static volatile int s = 0; s = s + 1; }
static void smoke_worker() { for (;;) { smoke_hot(); usleep(300); } }
static void smoke_counter() { for (;;) { g_smoke_counter = g_smoke_counter + 1; usleep(50); } }

int main(int argc, char** argv) {
    qputenv("QT_QPA_PLATFORM", "offscreen");

    int fds[2];
    if (pipe(fds) != 0) { printf("gui debugger smoke: FAILED (pipe)\n"); return 1; }
    pid_t child = fork();
    if (child == 0) {
        close(fds[0]);
        std::thread(smoke_worker).detach();
        std::thread(smoke_counter).detach();
        ssize_t wr = write(fds[1], "x", 1); (void)wr;
        for (;;) usleep(100000);
        _exit(0);
    }
    close(fds[1]);
    char t = 0; (void)read(fds[0], &t, 1); close(fds[0]);
    usleep(80000);   // let the threads spin up

    QApplication app(argc, argv);
    ce::os::LinuxProcessHandle proc(child);
    ce::gui::DebuggerWindow win(&proc);   // constructor attaches (all-stop)
    win.show();
    for (int i = 0; i < 40; ++i) { app.processEvents(); usleep(5000); }

    bool attached = win.debugAttached();
    bool stoppedInitially = win.debugStopped();

    auto hotAddr = reinterpret_cast<uintptr_t>(&smoke_hot);
    win.addBreakpointAt(hotAddr);
    QMetaObject::invokeMethod(&win, "onContinue");   // private slot, invoked by name

    bool hit = false;
    for (int i = 0; i < 400 && !hit; ++i) {
        app.processEvents();
        usleep(10000);
        if (win.debugStopped() && win.currentStopRip() == hotAddr) hit = true;
    }

    // All-stop: the free-running counter thread must be frozen at the stop.
    long c1 = 0, c2 = 0;
    proc.read(reinterpret_cast<uintptr_t>(&g_smoke_counter), &c1, sizeof(c1));
    usleep(60000);
    proc.read(reinterpret_cast<uintptr_t>(&g_smoke_counter), &c2, sizeof(c2));
    bool allStop = hit && (c1 == c2);
    bool alive = (kill(child, 0) == 0);

    // Register editing: type a sentinel into RBX (row 4) through the register
    // table exactly as a user would; the value must reach the stopped thread.
    bool regEdit = hit && win.pokeRegisterForTest(4 /*RBX*/, 0x00000000BADF00D5ull);

    // Thread switcher: the child has >= 2 frozen threads; the dropdown lists them
    // and switching moves the session's active thread.
    bool threadSwitch = hit && win.threadCount() >= 2 && win.switchToOtherThreadForTest();

    // Detach before reaping: a ptrace tracee can only be waited on by its tracer
    // thread, so waitpid() from main would block until the session detaches.
    QMetaObject::invokeMethod(&win, "onDetach");
    app.processEvents();

    kill(child, SIGKILL);
    waitpid(child, nullptr, 0);

    bool ok = attached && stoppedInitially && hit && allStop && alive && regEdit && threadSwitch;
    printf("gui debugger smoke: %s (attached=%d stopped0=%d hit=%d allstop=%d alive=%d regedit=%d threadsw=%d)\n",
           ok ? "OK" : "FAILED", attached, stoppedInitially, hit, allStop, alive, regEdit, threadSwitch);
    return ok ? 0 : 1;
}
