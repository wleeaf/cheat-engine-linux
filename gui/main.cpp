#include "gui/mainwindow.hpp"
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

static const char* darkStyleSheet = R"(
    QWidget { background-color: #1e1e2e; color: #cdd6f4; }
    QMenuBar { background-color: #181825; color: #cdd6f4; }
    QMenuBar::item:selected { background-color: #313244; }
    QMenu { background-color: #1e1e2e; color: #cdd6f4; border: 1px solid #45475a; }
    QMenu::item:selected { background-color: #313244; }
    QPushButton { background-color: #313244; color: #cdd6f4; border: 1px solid #45475a;
                  padding: 4px 12px; border-radius: 4px; }
    QPushButton:hover { background-color: #45475a; }
    QPushButton:pressed { background-color: #585b70; }
    QPushButton:disabled { color: #585b70; }
    QLineEdit, QSpinBox { background-color: #313244; color: #cdd6f4; border: 1px solid #45475a;
                          padding: 3px; border-radius: 3px; }
    QComboBox { background-color: #313244; color: #cdd6f4; border: 1px solid #45475a;
                padding: 3px; border-radius: 3px; }
    QComboBox QAbstractItemView { background-color: #1e1e2e; color: #cdd6f4; selection-background-color: #313244; }
    QComboBox::drop-down { border: none; }
    QTableView, QListWidget, QTableWidget { background-color: #181825; color: #cdd6f4;
        gridline-color: #313244; selection-background-color: #313244; alternate-background-color: #1e1e2e; }
    QHeaderView::section { background-color: #181825; color: #a6adc8; border: 1px solid #313244; padding: 4px; }
    QSplitter::handle { background-color: #313244; }
    QGroupBox { color: #a6adc8; border: 1px solid #45475a; border-radius: 4px; margin-top: 8px; padding-top: 8px; }
    QGroupBox::title { subcontrol-origin: margin; left: 8px; padding: 0 4px; }
    QCheckBox { color: #cdd6f4; }
    QLabel { color: #cdd6f4; }
    QProgressBar { background-color: #313244; border: 1px solid #45475a; border-radius: 3px; text-align: center; }
    QProgressBar::chunk { background-color: #89b4fa; border-radius: 3px; }
    QToolBar { background-color: #181825; border: none; spacing: 4px; }
    QTabWidget::pane { border: 1px solid #45475a; }
    QTabBar::tab { background-color: #181825; color: #a6adc8; padding: 6px 12px; border: 1px solid #45475a; }
    QTabBar::tab:selected { background-color: #313244; color: #cdd6f4; }
    QPlainTextEdit, QTextEdit { background-color: #1e1e2e; color: #cdd6f4; border: 1px solid #45475a; }
    QScrollBar:vertical { background: #181825; width: 10px; }
    QScrollBar::handle:vertical { background: #45475a; border-radius: 5px; min-height: 20px; }
    QScrollBar:horizontal { background: #181825; height: 10px; }
    QScrollBar::handle:horizontal { background: #45475a; border-radius: 5px; min-width: 20px; }
    QScrollBar::add-line, QScrollBar::sub-line { height: 0; width: 0; }
)";

// Light theme — Cheat Engine's classic neutral-grey (Windows-native) look:
// #f0f0f0 surfaces, black text, square-ish grey buttons, white inputs, and the
// familiar light-blue selection. Applied when display/dark is false.
static const char* lightStyleSheet = R"(
    QWidget { background-color: #f0f0f0; color: #000000; }
    QMainWindow, QDialog { background-color: #f0f0f0; }
    QMenuBar { background-color: #f0f0f0; color: #000000; }
    QMenuBar::item:selected { background-color: #cce8ff; }
    QMenu { background-color: #f0f0f0; color: #000000; border: 1px solid #a0a0a0; }
    QMenu::item:selected { background-color: #cce8ff; }
    QPushButton, QToolButton { background-color: #e1e1e1; color: #000000; border: 1px solid #adadad;
                  padding: 3px 10px; border-radius: 2px; }
    QPushButton:hover, QToolButton:hover { background-color: #e5f1fb; border-color: #0078d7; }
    QPushButton:pressed, QToolButton:pressed { background-color: #cce4f7; }
    QPushButton:disabled, QToolButton:disabled { color: #a0a0a0; background-color: #f0f0f0; }
    QLineEdit, QSpinBox { background-color: #ffffff; color: #000000; border: 1px solid #7a7a7a;
                          padding: 2px; border-radius: 1px; }
    QComboBox { background-color: #ffffff; color: #000000; border: 1px solid #7a7a7a;
                padding: 2px; border-radius: 1px; }
    QComboBox QAbstractItemView { background-color: #ffffff; color: #000000;
                selection-background-color: #cce8ff; selection-color: #000000; }
    QTableView, QListWidget, QTableWidget { background-color: #ffffff; color: #000000;
        gridline-color: #d0d0d0; selection-background-color: #cce8ff; selection-color: #000000; alternate-background-color: #f5f5f5; }
    QHeaderView::section { background-color: #f0f0f0; color: #000000; border: 1px solid #d0d0d0; padding: 3px; }
    QSplitter::handle { background-color: #e0e0e0; }
    QGroupBox { color: #000000; border: 1px solid #c0c0c0; border-radius: 2px; margin-top: 8px; padding-top: 8px; }
    QGroupBox::title { subcontrol-origin: margin; left: 8px; padding: 0 4px; }
    QCheckBox, QRadioButton, QLabel { color: #000000; }
    QProgressBar { background-color: #e6e6e6; border: 1px solid #a0a0a0; border-radius: 1px; text-align: center; color: #000000; }
    QProgressBar::chunk { background-color: #06b025; }
    QToolBar { background-color: #f0f0f0; border: none; spacing: 3px; }
    QTabWidget::pane { border: 1px solid #a0a0a0; }
    QTabBar::tab { background-color: #f0f0f0; color: #000000; padding: 5px 12px; border: 1px solid #c0c0c0; }
    QTabBar::tab:selected { background-color: #ffffff; }
    QPlainTextEdit, QTextEdit { background-color: #ffffff; color: #000000; border: 1px solid #7a7a7a; }
    QScrollBar:vertical { background: #f0f0f0; width: 14px; }
    QScrollBar::handle:vertical { background: #cdcdcd; min-height: 20px; }
    QScrollBar::handle:vertical:hover { background: #a6a6a6; }
    QScrollBar:horizontal { background: #f0f0f0; height: 14px; }
    QScrollBar::handle:horizontal { background: #cdcdcd; min-width: 20px; }
    QScrollBar::handle:horizontal:hover { background: #a6a6a6; }
    QScrollBar::add-line, QScrollBar::sub-line { height: 0; width: 0; }
)";

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
    QSettings themeSettings;
    bool useDark = themeSettings.value("display/dark", false).toBool();
    app.setStyleSheet(useDark ? darkStyleSheet : lightStyleSheet);

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
