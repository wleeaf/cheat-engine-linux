#pragma once
/// Application theme (light / dark). Both stylesheets live here so startup
/// (main.cpp) and the Settings dialog apply the SAME sheets, and a theme change
/// takes effect live via qApp->setStyleSheet — no restart needed.

namespace ce::gui {

/// The QSettings key holding the dark-theme flag (shared so main + settings agree).
inline constexpr const char* kDarkThemeKey = "display/dark";

/// Whether dark mode is enabled, per QSettings. Default is LIGHT (false) so the
/// app looks like Cheat Engine's native theme out of the box.
bool isDarkTheme();

/// Apply the light or dark stylesheet to the whole application (qApp), live.
void applyTheme(bool dark);

/// Apply the theme currently stored in QSettings.
void applyStoredTheme();

} // namespace ce::gui
