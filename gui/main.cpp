#include "gui/mainwindow.hpp"
#include "gui/memorybrowser.hpp"
#include "core/log.hpp"
#include "gui/theme.hpp"
#include <QFile>
#include <QApplication>
#include <QDialog>
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

    // Diagnostics: CE_LOG / CE_LOG_FILE turn on cecore logging with no rebuild
    // (e.g. `CE_LOG=ptrace:debug ./cheatengine` to see why a memory pane is blank).
    ce::log::initFromEnv();

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

    // `--pid <N>` attaches to a running process on launch (no picker dialog);
    // `--memview <addr>` then opens the Memory Viewer there.
    const QStringList cliArgs = app.arguments();
    uintptr_t memviewAddr = 0;
    bool wantMemview = false, wantSettings = false;
    QString wantPanel, wantSettingsPage;
    for (int i = 1; i < cliArgs.size(); ++i) {
        if (cliArgs.at(i) == QLatin1String("--settings")) {
            wantSettings = true;
        } else if (i + 1 < cliArgs.size() && cliArgs.at(i) == QLatin1String("--settings-page")) {
            wantSettings = true;
            wantSettingsPage = cliArgs.at(i + 1);
        } else if (i + 1 < cliArgs.size() && cliArgs.at(i) == QLatin1String("--panel")) {
            wantPanel = cliArgs.at(i + 1);
        } else if (i + 1 < cliArgs.size() && cliArgs.at(i) == QLatin1String("--pid")) {
            bool ok = false;
            const long pid = cliArgs.at(i + 1).toLong(&ok);
            if (ok && pid > 0) w.attachToPid(static_cast<pid_t>(pid), QString());
        } else if (i + 1 < cliArgs.size() && cliArgs.at(i) == QLatin1String("--memview")) {
            bool ok = false;
            memviewAddr = static_cast<uintptr_t>(cliArgs.at(i + 1).toULongLong(&ok, 0));
            wantMemview = ok;
        }
    }
    QWidget* shotTarget = &w;
    if (wantMemview) {
        if (auto* mb = w.openMemoryView(memviewAddr))
            shotTarget = mb;   // MemoryBrowser is-a QWidget (implicit upcast)
    }
    // `--settings` opens the Settings dialog on launch (jump straight to it).
    if (wantSettings) {
        if (auto* dlg = w.openSettingsDialog(wantSettingsPage))
            shotTarget = dlg;
    }
    // `--panel <name>` opens the panel whose menu entry contains <name> (for
    // screenshot/UI auditing), e.g. `--panel Dissect`, `--panel "Pointer scan"`.
    if (!wantPanel.isEmpty()) {
        if (auto* p = w.openPanelByName(wantPanel))
            shotTarget = p;
    }

    // Dev hook: CE_SCREENSHOT=<path> grabs the target window shortly after it is
    // shown and exits (used for UI/layout verification; no effect unless set).
    // With --memview it grabs the Memory Viewer, otherwise the main window.
    if (const char* shot = std::getenv("CE_SCREENSHOT")) {
        const QString shotPath = QString::fromLocal8Bit(shot);
        QTimer::singleShot(600, [shotTarget, shotPath]() {
            shotTarget->grab().save(shotPath);
            QApplication::quit();
        });
    }

    // Open a cheat table passed on the command line (double-click a .CT / .json,
    // or `cheatengine table.ct`), matching CE's file-association behaviour.
    for (int i = 1; i < cliArgs.size(); ++i) {
        const QString& arg = cliArgs.at(i);
        if (arg == QLatin1String("--pid")) { ++i; continue; }   // --pid consumes its value
        if (arg.startsWith(QLatin1String("--"))) continue;      // other flags: no value
        if (QFile::exists(arg)) { w.loadTableFromPath(arg); break; }
    }

    return app.exec();
}
