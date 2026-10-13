#pragma once
/// Application theme (light / dark). Both stylesheets live here so startup
/// (main.cpp) and the Settings dialog apply the SAME sheets, and a theme change
/// takes effect live via qApp->setStyleSheet, no restart needed.

#include <QColor>
#include <QFont>
#include <QString>
class QTextDocument;
class QTableView;
class QAbstractItemView;
class QTableWidget;
class QLineEdit;

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

/// Defaults for Settings > Display before the user picks a font: the desktop's
/// own fixed-width font (Adwaita Mono on GNOME) at the application font's size,
/// so code and tables match the surrounding text.
QString defaultMonospaceFamily();
int defaultMonospaceSize();

/// The monospace font chosen in Settings > Display, `delta` points from its size.
QFont monospaceFont(int delta = 0);

/// One look for read-only data grids (modules, regions, threads, stack...):
/// whole-row selection, no row-number column, no in-place editing, zebra rows,
/// long text elided in the middle so both ends of a path stay visible.
void styleDataTable(QTableView* table, bool monospace = true);

/// A search box that hides the rows of `table` whose cells don't contain its
/// text (case-insensitive). The caller places it in its layout.
QLineEdit* makeTableFilter(QTableWidget* table, const QString& placeholder);

/// "4321  (main)" or "4325  gmain": a thread id with its /proc name, for thread
/// pickers. `pid` is the local process (0 for a remote target: id only).
QString threadLabel(int pid, int tid);

/// A thread's /proc name. The kernel cuts names to 15 characters; for the main
/// thread the untruncated name is the executable's, which is used when it fits.
QString threadName(int pid, int tid);

/// A centred, dimmed message over `view` while its model has no rows, e.g.
/// "Pick a module and click Analyze." Follows the model and the view's size.
void setEmptyHint(QAbstractItemView* view, const QString& text);

/// A byte count for people: "512 B", "4 KiB", "2.4 MiB".
QString formatByteSize(unsigned long long bytes);

} // namespace ce::gui
