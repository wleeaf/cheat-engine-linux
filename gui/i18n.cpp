#include "gui/i18n.hpp"

#include "core/log.hpp"
#include "core/secure_exec.hpp"
#include <QApplication>
#include <QDir>
#include <QFileInfo>
#include <QLibraryInfo>
#include <QLocale>
#include <QProcess>
#include <QSettings>
#include <QStringList>
#include <QTranslator>
#include <unistd.h>

namespace ce::gui {
namespace {

/// Qt wants "zh_CN" from a desktop locale name such as "zh_CN.UTF-8".
QString desktopLocaleName() {
    QString name = qEnvironmentVariable("LANG");
    if (name.isEmpty()) name = QLocale().name();
    return name.section('.', 0, 0);
}

/// Where a translator may live: beside the executable (installed or build
/// directory), its translations/ subdirectory, or a translations/ directory
/// relative to the working directory.
QStringList translationSearchDirs() {
    QStringList dirs;
    char exeBuf[4096];
    const ssize_t len = readlink("/proc/self/exe", exeBuf, sizeof(exeBuf) - 1);
    if (len > 0) {
        exeBuf[len] = '\0';
        const QString exeDir = QFileInfo(QString::fromLocal8Bit(exeBuf)).absolutePath();
        dirs << exeDir + "/translations" << exeDir + "/../translations" << exeDir;
    }
    dirs << "translations";
    return dirs;
}

} // namespace

QString configuredUiLanguage() {
    return QSettings().value(QStringLiteral("ui/language")).toString();
}

QString installTranslators(QApplication& app, const QString& explicitLocale) {
    // Number and date formatting keeps following the desktop locale, as before;
    // only the interface language changes when Settings picks one.
    const QLocale desktopLocale(desktopLocaleName());
    QLocale::setDefault(desktopLocale);

    QString wanted = explicitLocale;
    if (wanted.isEmpty()) wanted = configuredUiLanguage();
    if (wanted.isEmpty()) wanted = desktopLocale.name();
    const QLocale uiLocale(wanted);

    auto* qtTranslator = new QTranslator(&app);
    if (qtTranslator->load(uiLocale, QStringLiteral("qt"), QStringLiteral("_"),
                           QLibraryInfo::path(QLibraryInfo::TranslationsPath))) {
        app.installTranslator(qtTranslator);
    }

    // A catalogue dropped next to the executable wins over the built-in one, so
    // translators can test a .qm without rebuilding. A binary holding a file
    // capability (the .deb grants cap_sys_ptrace) is a secure-exec process: the
    // person who starts it must not be able to replace the interface strings of
    // its confirmation dialogs, so only the built-in catalogue is used then.
    auto* ceTranslator = new QTranslator(&app);
    QString loadedFrom;
    const bool secure = ce::secureExecution();
    if (!secure) {
        const QStringList dirs = translationSearchDirs();
        for (const QString& dir : dirs) {
            if (ceTranslator->load(uiLocale, QStringLiteral("cheatengine"), QStringLiteral("_"), dir)) {
                loadedFrom = dir;
                break;
            }
        }
    }
    if (loadedFrom.isEmpty()) {
        // Installed builds embed the catalogue in a resource.
        if (ceTranslator->load(QStringLiteral(":/i18n/cheatengine_%1.qm").arg(uiLocale.name())))
            loadedFrom = QStringLiteral("built-in");
    }
    if (!loadedFrom.isEmpty()) app.installTranslator(ceTranslator);

    ce::log::info(ce::log::Cat::Gui, "interface language {} (catalogue: {}){}",
                  uiLocale.name().toStdString(),
                  loadedFrom.isEmpty() ? std::string("none") : loadedFrom.toStdString(),
                  secure ? " (secure-exec: built-in only)" : "");
    return uiLocale.name();
}

bool launchRestart() {
    QStringList arguments = QCoreApplication::arguments();
    if (!arguments.isEmpty()) arguments.removeFirst();
    const QString appImage = qEnvironmentVariable("APPIMAGE");
    const QString program = appImage.isEmpty() ? QCoreApplication::applicationFilePath() : appImage;
    return QProcess::startDetached(program, arguments, QDir::currentPath());
}

} // namespace ce::gui
