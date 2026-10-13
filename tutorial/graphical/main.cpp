// cegtutorial: the graphical tutorial, three small game levels to change with
// Cheat Engine.
//
//   cegtutorial            the window
//   cegtutorial --text     the same game without a window (used by the tests)

#include "tutorial/graphical/game.h"
#include "tutorial/graphical/text_mode.hpp"
#include "tutorial/graphical/window.hpp"

#include <QApplication>
#include <QDir>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/prctl.h>

int main(int argc, char** argv) {
#ifdef PR_SET_PTRACER
    // Meant to be debugged: let Cheat Engine attach where Yama restricts ptrace.
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
#endif
    bool text = false;
    unsigned seed = 0;
    int level = 1;
    const char* screenshots = nullptr;
    for (int i = 1; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--text")) text = true;
        else if (!std::strcmp(argv[i], "--seed") && i + 1 < argc) seed = static_cast<unsigned>(std::strtoul(argv[++i], nullptr, 0));
        else if (!std::strcmp(argv[i], "--level") && i + 1 < argc) level = std::atoi(argv[++i]);
        else if (!std::strcmp(argv[i], "--screenshots") && i + 1 < argc) screenshots = argv[++i];
        else if (!std::strcmp(argv[i], "--help") || !std::strcmp(argv[i], "-h")) {
            std::printf("Usage: cegtutorial [--text] [--level N] [--seed N]\n"
                        "Three small game levels to learn Cheat Engine on.\n"
                        "  --text      run without a window, with typed commands\n"
                        "  --level N   start at level N\n"
                        "  --seed N    repeatable random numbers\n");
            return 0;
        }
    }
    if (level < 1 || level > GT_LEVELS) level = 1;
    const bool display = std::getenv("DISPLAY") || std::getenv("WAYLAND_DISPLAY") || std::getenv("QT_QPA_PLATFORM");
    if (text || !display) return runGraphicalTextMode(seed, level);

    QApplication app(argc, argv);
    QApplication::setApplicationName("cegtutorial");
    QApplication::setApplicationDisplayName("Cheat Engine Graphical Tutorial");
    GraphicalWindow window(seed, level);
    window.show();
    if (screenshots) {
        // Render each level to DIR/level-N.png and exit (docs and visual review).
        QDir().mkpath(screenshots);
        for (int n = 1; n <= GT_LEVELS; ++n) {
            window.openLevel(n);
            QApplication::processEvents();
            window.grab().save(QString("%1/level-%2.png").arg(screenshots).arg(n));
        }
        return 0;
    }
    return app.exec();
}
