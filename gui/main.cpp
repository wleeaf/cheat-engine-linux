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

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName("Cheat Engine");
    app.setOrganizationName("cecore");
    app.setStyleSheet(darkStyleSheet);

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
