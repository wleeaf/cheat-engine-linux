#include "gui/mainwindow.hpp"
#include "gui/theme.hpp"
#include <QFile>
#include <QApplication>
#include <QIcon>
#include <QPixmap>
#include <QDir>
#include <QFileInfo>
#include <QLocale>
#include <QTranslator>
#include <QLibraryInfo>
#include <unistd.h>
#include <QSettings>
#include <QTimer>
#include <cstring>
#include <cstdio>
#include <cstdlib>

int main(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--version") == 0 || std::strcmp(argv[i], "-v") == 0) {
            std::printf("cheatengine (cheat-engine-linux) %s\n", CECORE_VERSION);
            return 0;
        }
    }

    QApplication app(argc, argv);
    app.setApplicationName("Cheat Engine");
    app.setOrganizationName("cecore");
    // Honor the Settings dialog's "Dark theme" toggle. Default to LIGHT so the app
    // looks like Cheat Engine (which uses a light/native theme) out of the box.
    // The same helper is used by the Settings dialog so a toggle applies live.
    ce::gui::applyStoredTheme();

    // ── i18n ──
    // Two translators: one for Qt's own strings (so dialogs etc. localise),
    // and one for cecore's translations. The cecore .qm files live next to
    // the binary under translations/cheatengine_<locale>.qm. Translations
    // aren't shipped yet, but the load is best-effort and silently skips
    // when no file matches — the wiring is ready for translators to drop
    // .qm files in.
    QLocale locale;
    {
        QString locName = qEnvironmentVariable("LANG", locale.name());
        // Strip ".UTF-8" etc. — Qt only wants "en_US" or "tr_TR".
        locName = locName.section('.', 0, 0);
        if (!locName.isEmpty()) locale = QLocale(locName);
    }
    QLocale::setDefault(locale);

    auto* qtTranslator = new QTranslator(&app);
    if (qtTranslator->load(locale, "qt", "_",
            QLibraryInfo::path(QLibraryInfo::TranslationsPath))) {
        app.installTranslator(qtTranslator);
    }
    auto* ceTranslator = new QTranslator(&app);
    {
        // Search a few likely locations for cheatengine_<locale>.qm:
        //   <exe-dir>/translations/, <exe-dir>/../translations/, current dir.
        QStringList searchDirs;
        char exeBufLocal[4096];
        ssize_t exeLenLocal = readlink("/proc/self/exe", exeBufLocal, sizeof(exeBufLocal) - 1);
        if (exeLenLocal > 0) {
            exeBufLocal[exeLenLocal] = 0;
            auto exeDir = QFileInfo(exeBufLocal).absolutePath();
            searchDirs << (exeDir + "/translations")
                       << (exeDir + "/../translations");
        }
        searchDirs << "translations";
        for (const auto& dir : searchDirs) {
            if (ceTranslator->load(locale, "cheatengine", "_", dir)) {
                app.installTranslator(ceTranslator);
                break;
            }
        }
    }

    // Set application icon — resolve exe path via /proc/self/exe
    QIcon appIcon;
    char exeBuf[4096];
    ssize_t exeLen = readlink("/proc/self/exe", exeBuf, sizeof(exeBuf) - 1);
    if (exeLen > 0) {
        exeBuf[exeLen] = 0;
        auto exeDir = QFileInfo(exeBuf).absolutePath();
        QStringList iconPaths = {
            exeDir + "/cheatengine.png",
            exeDir + "/../packaging/cheatengine.png",
        };
        for (auto& p : iconPaths) {
            QPixmap pm(p);
            if (!pm.isNull()) {
                appIcon = QIcon(pm);
                break;
            }
        }
    }

    // Fallback to embedded resource
    if (appIcon.isNull()) {
        QPixmap pm(":/icon.png");
        if (!pm.isNull()) appIcon = QIcon(pm);
    }

    app.setWindowIcon(appIcon);

    ce::gui::MainWindow w;
    w.setWindowIcon(appIcon);
    w.show();

    // Dev hook: CE_SCREENSHOT=<path> grabs the main window shortly after it is
    // shown and exits (used for UI/layout verification; no effect unless set).
    if (const char* shot = std::getenv("CE_SCREENSHOT")) {
        const QString shotPath = QString::fromLocal8Bit(shot);
        QTimer::singleShot(600, [&w, shotPath]() {
            w.grab().save(shotPath);
            QApplication::quit();
        });
    }

    // Open a cheat table passed on the command line (double-click a .CT / .json,
    // or `cheatengine table.ct`), matching CE's file-association behaviour.
    const QStringList cliArgs = app.arguments();
    if (cliArgs.size() > 1) {
        const QString& tablePath = cliArgs.at(1);
        if (QFile::exists(tablePath))
            w.loadTableFromPath(tablePath);
    }

    return app.exec();
}
