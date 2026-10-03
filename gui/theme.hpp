#pragma once
/// Application theme (light / dark). Both stylesheets live here so startup
/// (main.cpp) and the Settings dialog apply the SAME sheets, and a theme change
/// takes effect live via qApp->setStyleSheet, no restart needed.

#include <QColor>
class QTextDocument;

namespace ce::gui {

/// The QSettings key holding the dark-theme flag (shared so main + settings agree).
inline constexpr const char* kDarkThemeKey = "display/dark";

/// The active theme, falling back to the saved preference or the system palette.
bool isDarkTheme();

/// Apply the light or dark stylesheet to the whole application (qApp), live.
void applyTheme(bool dark);

/// Apply the theme currently stored in QSettings.
void applyStoredTheme();

/// Theme-aware palette for widgets that paint their own colors (syntax
/// highlighters, output consoles, design canvases) and therefore can't inherit
/// the application stylesheet. Follows isDarkTheme(). Custom-painted widgets
/// should read this rather than hardcoding a dark palette (which is why the
/// auto-assembler console, form-designer canvas, etc. stayed dark in light mode).
struct EditorPalette {
    QColor background, text, dim;
    // Auto-assembler syntax highlighting.
    QColor comment, directive, keyword, reg, number, label, string;
    // Console line colors chosen to read on `background`.
    QColor error, success;
    // Design/preview canvas.
    QColor canvas, canvasBorder;
};
EditorPalette editorPalette();
/// Update existing console text when switching themes without losing its roles.
void recolorConsole(QTextDocument* document, const EditorPalette& previous, const EditorPalette& current);

} // namespace ce::gui
