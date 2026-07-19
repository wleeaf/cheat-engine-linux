// Headless (offscreen Qt) smoke test for the interactive DebuggerWindow.
// Drives the real GUI class against a forked multi-threaded target: constructs
// the window (which attaches), sets a breakpoint on a function only sibling
// threads call, continues, and verifies the window reports a stop at that
// address with the whole target frozen (all-stop) and still alive. This exercises
// the GUI attach + tracer-thread→UI event marshalling + refresh + breakpoint/
// continue path end to end. Exit 0 on success.

#include "gui/debuggerwindow.hpp"
#include "gui/memorybrowser.hpp"
#include "platform/linux/linux_process.hpp"

#include <QApplication>
#include <thread>
#include <cstdio>
#include <cstdint>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

static volatile long g_smoke_counter = 0;
// External linkage so the disassembly's current-line annotation can resolve RIP to
// this function's name (the breakpoint sits at its entry).
__attribute__((noinline)) void smoke_hot() { static volatile int s = 0; s = s + 1; }
// External linkage (not static) so its symbol lands in .symtab and the stack pane can
// resolve the return address into it to a function name, not just module+offset.
__attribute__((noinline)) void smoke_worker() {
    for (;;) {
        // Load a known value into xmm0 so the XMM register view can be verified.
        asm volatile("movq %0, %%xmm0" :: "r"(0x0102030405060708ULL) : "xmm0");
        smoke_hot();
        usleep(300);
    }
}
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
    // The stopped(rip) signal drives the Memory Viewer's current-line highlight.
    // Latch whether it ever fired for the breakpoint address (a later thread-switch
    // stop re-emits it with another thread's RIP, so don't just check the last one).
    bool sawStopAtHot = false;
    QObject::connect(&win, &ce::gui::DebuggerWindow::stopped,
                     [&](uintptr_t rip) { if (rip == hotAddr) sawStopAtHot = true; });
    win.addBreakpointAt(hotAddr);
    QMetaObject::invokeMethod(&win, "onContinue");   // private slot, invoked by name

    bool hit = false;
    for (int i = 0; i < 400 && !hit; ++i) {
        app.processEvents();
        usleep(10000);
        if (win.debugStopped() && win.currentStopRip() == hotAddr) hit = true;
    }

    // Step highlight (CE-style): moving from the attach stop to the breakpoint hit
    // changed at least RIP, so at least one GP register must paint in the "changed"
    // colour. Sample now, before the register edit below re-renders the table.
    bool regHighlight = hit && win.anyRegisterChangedHighlightForTest();

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

    // Decoded-flags line: set RFLAGS to a known value (PF|ZF|IF + reserved) and
    // confirm the "Flags:" label decodes the individual flags.
    bool flagsOk = false;
    if (hit) {
        win.pokeRegisterForTest(9 /*RFLAGS*/, 0x246);
        QString ft = win.flagsTextForTest();
        flagsOk = ft.startsWith("Flags:") && ft.contains("PF") && ft.contains("ZF");
    }

    // Call-stack annotation: stopped at smoke_hot's entry, [RSP] holds the return
    // address into smoke_worker, so the stack pane resolves it to the function name.
    bool stackAnno = hit && win.stackTextForTest().contains("smoke_worker");

    // Disassembly symbol annotation: the current (=>) line is at smoke_hot's entry,
    // so the disassembly pane annotates it with the function name.
    bool disasmSym = hit && win.disasmTextForTest().contains("smoke_hot");

    // XMM view: the worker loads a known value into xmm0 before the breakpoint.
    // Check this while the trapping worker is still the active thread (before the
    // thread switch below retargets the register view to another thread).
    bool xmmView = hit && win.xmm0ShowsForTest(0x0102030405060708ULL);

    // Disassembler right-click: set a breakpoint at a disasm line via the cursor
    // path the context menu uses (while the worker's code is shown).
    bool disasmBp = hit && win.disasmSetBreakpointForTest(1);

    // Thread switcher: the child has >= 2 frozen threads; the dropdown lists them
    // and switching moves the session's active thread.
    bool threadSwitch = hit && win.threadCount() >= 2 && win.switchToOtherThreadForTest();

    // Memory/hex pane: point it at a known global in the child and confirm it
    // renders the bytes actually there.
    bool memView = hit && win.memoryViewShowsForTest(reinterpret_cast<uintptr_t>(&g_smoke_counter));

    // Current-instruction highlight (CE parity): the debugger emits stopped(rip),
    // and a Memory Viewer told that rip paints the paused line in the distinct
    // current-IP colour. Verify the signal carried the breakpoint address and that
    // the disassembler actually renders the highlight (a filled row = many pixels).
    bool stopSignal = hit && sawStopAtHot;
    int ipPixels = 0;
    if (hit) {
        ce::gui::MemoryBrowser browser(&proc);
        browser.resize(900, 600);
        browser.show();
        browser.showCurrentInstruction(hotAddr, /*follow=*/true);
        for (int i = 0; i < 30; ++i) { app.processEvents(); usleep(3000); }
        ipPixels = browser.currentIpHighlightPixelsForTest();
    }
    bool ipHighlight = ipPixels > 200;

    // Detach before reaping: a ptrace tracee can only be waited on by its tracer
    // thread, so waitpid() from main would block until the session detaches.
    QMetaObject::invokeMethod(&win, "onDetach");
    app.processEvents();

    kill(child, SIGKILL);
    waitpid(child, nullptr, 0);

    bool ok = attached && stoppedInitially && hit && allStop && alive && regEdit && threadSwitch && memView && xmmView && disasmBp && regHighlight && stopSignal && ipHighlight && flagsOk && stackAnno && disasmSym;
    printf("gui debugger smoke: %s (attached=%d stopped0=%d hit=%d allstop=%d alive=%d regedit=%d threadsw=%d memview=%d xmm=%d disasmbp=%d reghl=%d stopsig=%d iphl=%d[%d] flags=%d stackanno=%d disasmsym=%d)\n",
           ok ? "OK" : "FAILED", attached, stoppedInitially, hit, allStop, alive, regEdit, threadSwitch, memView, xmmView, disasmBp, regHighlight, stopSignal, ipHighlight, ipPixels, flagsOk, stackAnno, disasmSym);
    return ok ? 0 : 1;
}
