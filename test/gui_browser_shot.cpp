// Offscreen render harness for the Memory Viewer (MemoryBrowser). Forks a small
// spinning target, attaches, constructs the real browser window, points it at a
// known function, and grabs the widget to a PNG. Lets us verify layout + theme
// without a running window manager (the offscreen Qt platform renders to memory).
//
//   gui_browser_shot <out.png> [dark]
//
// With "dark" the dark theme is applied first; otherwise the light theme is used
// (so the same run can prove the hex/disasm panes follow the theme).

#include "gui/memorybrowser.hpp"
#include "gui/theme.hpp"
#include "platform/linux/linux_process.hpp"

#include <QApplication>
#include <cstdio>
#include <cstdint>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

__attribute__((noinline)) static int shot_compute(int x) { return x * 3 + 7; }
static void shot_spin() {
    volatile int v = 0;
    for (;;) { v = shot_compute(v); if (v > 1000000) v = 0; usleep(50000); }
}

int main(int argc, char** argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: %s <out.png> [dark]\n", argv[0]); return 2; }
    const char* out = argv[1];
    const bool dark = argc > 2 && std::string(argv[2]) == "dark";

    qputenv("QT_QPA_PLATFORM", "offscreen");

    pid_t child = fork();
    if (child == 0) { shot_spin(); _exit(0); }
    usleep(80000);  // let it start spinning

    QApplication app(argc, argv);
    ce::gui::applyTheme(dark);

    ce::os::LinuxProcessHandle proc(child);
    ce::gui::MemoryBrowser browser(&proc);
    browser.resize(1000, 720);
    browser.gotoAddress(reinterpret_cast<uintptr_t>(&shot_compute));
    browser.show();
    for (int i = 0; i < 60; ++i) { app.processEvents(); usleep(5000); }

    const bool ok = browser.grab().save(QString::fromLocal8Bit(out));
    std::printf("gui browser shot: %s (%s theme) -> %s\n",
                ok ? "OK" : "FAILED", dark ? "dark" : "light", out);

    kill(child, SIGKILL);
    int st = 0; waitpid(child, &st, 0);
    return ok ? 0 : 1;
}
