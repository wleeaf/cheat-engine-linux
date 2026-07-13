// Offscreen smoke test for light/dark theme support. Verifies that applyTheme
// actually swaps the application stylesheet (so the Settings toggle has a live
// effect) and that the default theme is LIGHT (matching main.cpp / the Settings
// checkbox default). Regression guard for the "theme toggle does nothing" bug.
//
// Run under QT_QPA_PLATFORM=offscreen. Prints one summary line; exits non-zero on
// failure (like gui_debugger_smoke).

#include "gui/theme.hpp"

#include <QApplication>
#include <QSettings>
#include <cstdio>

int main(int argc, char** argv) {
    qputenv("QT_QPA_PLATFORM", "offscreen");   // no display needed (CI-safe)
    QApplication app(argc, argv);
    app.setApplicationName("Cheat Engine");
    app.setOrganizationName("cecore");

    ce::gui::applyTheme(false);
    const QString light = app.styleSheet();
    ce::gui::applyTheme(true);
    const QString dark = app.styleSheet();

    // Light sheet: CE grey surfaces, no dark base color. Dark sheet: Catppuccin base.
    const bool lightApplied = light.contains("#f0f0f0") && !light.contains("#1e1e2e");
    const bool darkApplied  = dark.contains("#1e1e2e") && dark.contains("#cdd6f4");
    const bool differ       = !light.isEmpty() && !dark.isEmpty() && light != dark;

    // Default (no stored value) must be LIGHT so the Settings checkbox reflects reality.
    QSettings s;
    s.remove("display/dark");
    const bool defaultLight = (ce::gui::isDarkTheme() == false);

    const bool ok = lightApplied && darkApplied && differ && defaultLight;
    std::printf("gui theme smoke: %s (lightApplied=%d darkApplied=%d differ=%d defaultLight=%d)\n",
                ok ? "OK" : "FAILED", lightApplied, darkApplied, differ, defaultLight);
    return ok ? 0 : 1;
}
