// cetutorial: a small game to practice Cheat Engine on, step by step.
//
//   cetutorial            the window
//   cetutorial --text     the same steps in a terminal (also used by the tests)

#include "tutorial/game.h"
#include "tutorial/text_mode.hpp"
#include "tutorial/window.hpp"

#include <QApplication>
#include <QDir>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/prctl.h>

int main(int argc, char** argv) {
#ifdef PR_SET_PTRACER
    // The tutorial is meant to be debugged: let Cheat Engine attach to it even
    // where Yama allows tracing only by a parent process.
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
#endif
    bool text = false;
    unsigned seed = 0;
    const char* screenshots = nullptr;
    for (int i = 1; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--text")) text = true;
        else if (!std::strcmp(argv[i], "--seed") && i + 1 < argc) seed = static_cast<unsigned>(std::strtoul(argv[++i], nullptr, 0));
        else if (!std::strcmp(argv[i], "--screenshots") && i + 1 < argc) screenshots = argv[++i];
        else if (!std::strcmp(argv[i], "--help") || !std::strcmp(argv[i], "-h")) {
            std::printf("Usage: cetutorial [--text] [--seed N]\n"
                        "A step-by-step game to learn Cheat Engine on.\n"
                        "  --text     run in the terminal instead of a window\n"
                        "  --seed N   repeatable random numbers\n");
            return 0;
        }
    }
    const bool display = std::getenv("DISPLAY") || std::getenv("WAYLAND_DISPLAY") || std::getenv("QT_QPA_PLATFORM");
    if (text || !display) return runTutorialTextMode(seed);

    QApplication app(argc, argv);
    QApplication::setApplicationName("cetutorial");
    QApplication::setApplicationDisplayName("Cheat Engine Tutorial");
    TutorialWindow window(seed);
    window.show();
    if (screenshots) {
        // Render every step to DIR/step-N.png and exit (docs and visual review).
        QDir().mkpath(screenshots);
        for (int step = 1; step <= TUT_STEPS; ++step) {
            window.openStep(step);
            QApplication::processEvents();
            window.grab().save(QString("%1/step-%2.png").arg(screenshots).arg(step));
        }
        return 0;
    }
    return app.exec();
}
