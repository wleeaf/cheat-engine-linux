// Offscreen smoke test for light/dark theme support. Verifies that applyTheme
// actually swaps the application stylesheet (so the Settings toggle has a live
// effect), updates custom-view palettes, and honors the saved theme preference.
// Regression guard for the "theme toggle does nothing" bug.
//
// Run under QT_QPA_PLATFORM=offscreen. Prints one summary line; exits non-zero on
// failure (like gui_debugger_smoke).

#include "gui/theme.hpp"

#include <QApplication>
#include <QSettings>
#include <cstdio>
#include <QTemporaryDir>
#include <QPalette>

int main(int argc, char** argv) {
    qputenv("QT_QPA_PLATFORM", "offscreen");   // no display needed (CI-safe)
    QTemporaryDir config;
    qputenv("XDG_CONFIG_HOME", config.path().toUtf8());
    QApplication app(argc, argv);
    app.setApplicationName("Cheat Engine");
    app.setOrganizationName("cecore");

    QSettings().setValue(ce::gui::kDarkThemeKey, false);
    ce::gui::applyTheme(false);
    const QString light = app.styleSheet();
    bool lightPalette = !ce::gui::isDarkTheme() && app.palette().color(QPalette::Base).lightness() > 128;
    ce::gui::applyTheme(true);
    const QString dark = app.styleSheet();
    bool darkPalette = ce::gui::isDarkTheme() && app.palette().color(QPalette::Base).lightness() < 128;

    // Light sheet: modern soft-grey canvas, no dark base color. Dark sheet: Catppuccin base.
    const bool lightApplied = light.contains("#f4f5f7") && !light.contains("#1e1e2e");
    const bool darkApplied  = dark.contains("#1e1e2e") && dark.contains("#cdd6f4");
    const bool differ       = !light.isEmpty() && !dark.isEmpty() && light != dark;

    // A saved light preference must override the currently active dark palette.
    QSettings s;
    s.setValue(ce::gui::kDarkThemeKey, false);
    ce::gui::applyStoredTheme();
    const bool defaultLight = (ce::gui::isDarkTheme() == false);

    const bool ok = lightApplied && darkApplied && differ && defaultLight && lightPalette && darkPalette;
    std::printf("gui theme smoke: %s (lightApplied=%d darkApplied=%d differ=%d defaultLight=%d)\n",
                ok ? "OK" : "FAILED", lightApplied, darkApplied, differ, defaultLight);
    return ok ? 0 : 1;
}
