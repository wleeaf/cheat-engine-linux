#pragma once
/// Interface language: translator setup shared by the application and the GUI
/// smoke test.

#include <QString>

class QApplication;

namespace ce::gui {

/// The interface language stored in Settings ("ui/language"), or empty when the
/// interface follows the desktop locale.
QString configuredUiLanguage();

/// Installs the Qt and Cheat Engine translators and returns the locale that was
/// chosen. explicitLocale, when non-empty, wins over Settings and the desktop
/// locale (used by tests and screenshot runs).
QString installTranslators(QApplication& app, const QString& explicitLocale = {});

/// Starts a new instance of the program with the same arguments, for the restart
/// offered after an interface-language change. Under an AppImage the AppImage
/// file itself is started, not the mount path that disappears with this process.
/// Returns false when the new process could not be started.
bool launchRestart();

} // namespace ce::gui
