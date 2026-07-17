#include "gui/theme.hpp"

#include <QApplication>
#include <QPalette>
#include <QSettings>
#include <QImage>
#include <QPainter>
#include <QStandardPaths>
#include <QDir>
#include <QFile>

// A small chevron (up/down) drawn in `color`, cached to a PNG file whose path the
// QSS references. (Qt's QSS url() loads via QPixmap, which can't read data: URIs,
// so a real file is required.) Used to give QSpinBox/QComboBox clean arrows:
// styling those widgets via QSS suppresses the native sub-control arrows, which
// otherwise render as broken default glyphs.
static QString arrowFile(const QColor& color, bool up) {
    QString dir = QStandardPaths::writableLocation(QStandardPaths::CacheLocation) + "/arrows";
    QDir().mkpath(dir);
    QString path = QString("%1/%2_%3.png").arg(dir, color.name().mid(1), up ? "up" : "dn");
    if (!QFile::exists(path)) {
        QImage img(28, 18, QImage::Format_ARGB32);
        img.fill(Qt::transparent);
        QPainter p(&img);
        p.setRenderHint(QPainter::Antialiasing);
        QPen pen(color); pen.setWidthF(3.0);
        pen.setCapStyle(Qt::RoundCap); pen.setJoinStyle(Qt::RoundJoin);
        p.setPen(pen);
        if (up) { p.drawLine(6, 12, 14, 6); p.drawLine(14, 6, 22, 12); }
        else    { p.drawLine(6, 6, 14, 12); p.drawLine(14, 12, 22, 6); }
        p.end();
        img.save(path, "PNG");
    }
    return path;
}

namespace ce::gui {

static const char* kDarkStyleSheet = R"(
    QWidget { background-color: #1e1e2e; color: #cdd6f4; }
    QMainWindow, QDialog { background-color: #1e1e2e; }
    QMenuBar { background-color: #181825; color: #cdd6f4; }
    QMenuBar::item { padding: 4px 8px; border-radius: 4px; }
    QMenuBar::item:selected { background-color: #313244; }
    QMenu { background-color: #1e1e2e; color: #cdd6f4; border: 1px solid #45475a; padding: 4px; }
    QMenu::item { padding: 5px 24px 5px 12px; border-radius: 4px; }
    QMenu::item:selected { background-color: #313244; }
    QMenu::separator { height: 1px; background: #313244; margin: 4px 8px; }
    QPushButton, QToolButton { background-color: #313244; color: #cdd6f4; border: 1px solid #45475a;
                  padding: 5px 12px; border-radius: 5px; }
    QPushButton:hover, QToolButton:hover { background-color: #3b3d52; border-color: #585b70; }
    QPushButton:pressed, QToolButton:pressed { background-color: #585b70; }
    QPushButton:disabled, QToolButton:disabled { color: #585b70; border-color: #313244; }
    QPushButton#primaryButton { background-color: #89b4fa; color: #1e1e2e; border: 1px solid #89b4fa; font-weight: 600; }
    QPushButton#primaryButton:hover { background-color: #a6c8ff; border-color: #a6c8ff; }
    QPushButton#primaryButton:pressed { background-color: #74a0e8; }
    QPushButton#primaryButton:disabled { background-color: #45475a; border-color: #45475a; color: #6c7086; }
    QLineEdit, QSpinBox { background-color: #313244; color: #cdd6f4; border: 1px solid #45475a;
                          padding: 4px 6px; border-radius: 5px; selection-background-color: #585b70; }
    QLineEdit:focus, QSpinBox:focus { border-color: #89b4fa; }
    QComboBox { background-color: #313244; color: #cdd6f4; border: 1px solid #45475a;
                padding: 4px 6px; border-radius: 5px; }
    QComboBox:focus, QComboBox:on { border-color: #89b4fa; }
    QComboBox QAbstractItemView { background-color: #1e1e2e; color: #cdd6f4; border: 1px solid #45475a;
                selection-background-color: #313244; }
    QComboBox::drop-down { border: none; width: 18px; }
    QComboBox::down-arrow { image: url("%DOWN_ARROW%"); width: 12px; height: 8px; }
    QSpinBox::up-button, QDoubleSpinBox::up-button { subcontrol-origin: border;
        subcontrol-position: top right; width: 17px; border-left: 1px solid #45475a; }
    QSpinBox::down-button, QDoubleSpinBox::down-button { subcontrol-origin: border;
        subcontrol-position: bottom right; width: 17px; border-left: 1px solid #45475a; }
    QSpinBox::up-arrow, QDoubleSpinBox::up-arrow { image: url("%UP_ARROW%"); width: 11px; height: 7px; }
    QSpinBox::down-arrow, QDoubleSpinBox::down-arrow { image: url("%DOWN_ARROW%"); width: 11px; height: 7px; }
    QTableView, QListWidget, QTableWidget, QTreeView, QTreeWidget { background-color: #181825; color: #cdd6f4;
        gridline-color: #313244; selection-background-color: #3a4463; selection-color: #cdd6f4;
        alternate-background-color: #1e1e2e; border: 1px solid #313244; }
    QTreeView::item:selected, QTreeWidget::item:selected { background-color: #3a4463; color: #cdd6f4; }
    QHeaderView::section { background-color: #181825; color: #a6adc8; border: none;
        border-right: 1px solid #313244; border-bottom: 1px solid #313244; padding: 5px 6px; font-weight: 600; }
    QSplitter::handle { background-color: #313244; }
    QGroupBox { color: #a6adc8; border: 1px solid #45475a; border-radius: 6px; margin-top: 10px;
        padding-top: 10px; font-weight: 600; }
    QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; color: #89b4fa; }
    QCheckBox, QRadioButton { color: #cdd6f4; }
    QLabel { color: #cdd6f4; }
    QProgressBar { background-color: #313244; border: none; border-radius: 5px; text-align: center; color: #cdd6f4; }
    QProgressBar::chunk { background-color: #89b4fa; border-radius: 5px; }
    QToolBar { background-color: #181825; border: none; spacing: 4px; padding: 2px; }
    QTabWidget::pane { border: 1px solid #45475a; border-radius: 6px; }
    QTabBar::tab { background-color: #181825; color: #a6adc8; padding: 6px 14px; border: 1px solid #45475a;
        border-bottom: none; border-top-left-radius: 5px; border-top-right-radius: 5px; }
    QTabBar::tab:selected { background-color: #313244; color: #cdd6f4; }
    QPlainTextEdit, QTextEdit { background-color: #1e1e2e; color: #cdd6f4; border: 1px solid #45475a;
        border-radius: 5px; selection-background-color: #585b70; }
    QStatusBar { background-color: #181825; color: #a6adc8; }
    QScrollBar:vertical { background: transparent; width: 12px; margin: 0; }
    QScrollBar::handle:vertical { background: #45475a; border-radius: 6px; min-height: 24px; }
    QScrollBar::handle:vertical:hover { background: #585b70; }
    QScrollBar:horizontal { background: transparent; height: 12px; margin: 0; }
    QScrollBar::handle:horizontal { background: #45475a; border-radius: 6px; min-width: 24px; }
    QScrollBar::handle:horizontal:hover { background: #585b70; }
    QScrollBar::add-line, QScrollBar::sub-line { height: 0; width: 0; }
    QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }
    QSlider::groove:horizontal { background: #45475a; height: 4px; border-radius: 2px; }
    QSlider::handle:horizontal { background: #89b4fa; width: 14px; margin: -6px 0; border-radius: 7px; }
    QSlider::handle:horizontal:hover { background: #b4befe; }
)";

// Light theme — a clean, modern flat look: a soft cool-grey canvas, white
// rounded controls with subtle borders, a blue focus/primary accent, and
// low-contrast table chrome. Keeps CE's familiar layout, just less "Windows 95".
static const char* kLightStyleSheet = R"(
    QWidget { background-color: #f4f5f7; color: #1b1f24; }
    QMainWindow, QDialog { background-color: #f4f5f7; }
    QMenuBar { background-color: #f4f5f7; color: #1b1f24; }
    QMenuBar::item { padding: 4px 8px; border-radius: 4px; }
    QMenuBar::item:selected { background-color: #e4ecfb; }
    QMenu { background-color: #ffffff; color: #1b1f24; border: 1px solid #d4d7dd; padding: 4px; }
    QMenu::item { padding: 5px 24px 5px 12px; border-radius: 4px; }
    QMenu::item:selected { background-color: #e4ecfb; }
    QMenu::separator { height: 1px; background: #e6e8ec; margin: 4px 8px; }
    QPushButton, QToolButton { background-color: #ffffff; color: #1b1f24; border: 1px solid #cdd1d9;
                  padding: 5px 12px; border-radius: 5px; }
    QPushButton:hover, QToolButton:hover { background-color: #f0f5ff; border-color: #4a7fe0; }
    QPushButton:pressed, QToolButton:pressed { background-color: #dfeafc; }
    QPushButton:disabled, QToolButton:disabled { color: #a8adb6; background-color: #f4f5f7; border-color: #e0e2e7; }
    QPushButton#primaryButton { background-color: #2f6fed; color: #ffffff; border: 1px solid #2f6fed; font-weight: 600; }
    QPushButton#primaryButton:hover { background-color: #4a7fe0; border-color: #4a7fe0; }
    QPushButton#primaryButton:pressed { background-color: #2258c9; }
    QPushButton#primaryButton:disabled { background-color: #c3d3f5; border-color: #c3d3f5; color: #eef2fb; }
    QLineEdit, QSpinBox { background-color: #ffffff; color: #1b1f24; border: 1px solid #cdd1d9;
                          padding: 4px 6px; border-radius: 5px; selection-background-color: #cfe0fb; }
    QLineEdit:focus, QSpinBox:focus { border-color: #2f6fed; }
    QComboBox { background-color: #ffffff; color: #1b1f24; border: 1px solid #cdd1d9;
                padding: 4px 6px; border-radius: 5px; }
    QComboBox:focus, QComboBox:on { border-color: #2f6fed; }
    QComboBox QAbstractItemView { background-color: #ffffff; color: #1b1f24; border: 1px solid #d4d7dd;
                selection-background-color: #e4ecfb; selection-color: #1b1f24; }
    QComboBox::drop-down { border: none; width: 18px; }
    QComboBox::down-arrow { image: url("%DOWN_ARROW%"); width: 12px; height: 8px; }
    QSpinBox::up-button, QDoubleSpinBox::up-button { subcontrol-origin: border;
        subcontrol-position: top right; width: 17px; border-left: 1px solid #cdd1d9; }
    QSpinBox::down-button, QDoubleSpinBox::down-button { subcontrol-origin: border;
        subcontrol-position: bottom right; width: 17px; border-left: 1px solid #cdd1d9; }
    QSpinBox::up-arrow, QDoubleSpinBox::up-arrow { image: url("%UP_ARROW%"); width: 11px; height: 7px; }
    QSpinBox::down-arrow, QDoubleSpinBox::down-arrow { image: url("%DOWN_ARROW%"); width: 11px; height: 7px; }
    QTableView, QListWidget, QTableWidget, QTreeView, QTreeWidget { background-color: #ffffff; color: #1b1f24;
        gridline-color: #e9ebef; selection-background-color: #dbe8fd; selection-color: #1b1f24;
        alternate-background-color: #eef1f6; border: 1px solid #e0e2e7; }
    QTreeView::item:selected, QTreeWidget::item:selected { background-color: #dbe8fd; color: #1b1f24; }
    QHeaderView::section { background-color: #f0f1f4; color: #4b5563; border: none;
        border-right: 1px solid #e3e5ea; border-bottom: 1px solid #dfe1e6; padding: 5px 6px; font-weight: 600; }
    QSplitter::handle { background-color: #e6e8ec; }
    QGroupBox { color: #4b5563; border: 1px solid #e0e2e7; border-radius: 6px; margin-top: 10px;
        padding-top: 10px; font-weight: 600; }
    QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; color: #6b7280; }
    QCheckBox, QRadioButton, QLabel { color: #1b1f24; }
    QProgressBar { background-color: #eceef1; border: none; border-radius: 5px; text-align: center; color: #1b1f24; }
    QProgressBar::chunk { background-color: #2f6fed; border-radius: 5px; }
    QToolBar { background-color: #f4f5f7; border: none; spacing: 4px; padding: 2px; }
    QTabWidget::pane { border: 1px solid #e0e2e7; border-radius: 6px; }
    QTabBar::tab { background-color: #eceef1; color: #4b5563; padding: 6px 14px; border: 1px solid #e0e2e7;
        border-bottom: none; border-top-left-radius: 5px; border-top-right-radius: 5px; }
    QTabBar::tab:selected { background-color: #ffffff; color: #1b1f24; }
    QPlainTextEdit, QTextEdit { background-color: #ffffff; color: #1b1f24; border: 1px solid #e0e2e7;
        border-radius: 5px; selection-background-color: #cfe0fb; }
    QStatusBar { background-color: #f0f1f4; color: #4b5563; }
    QScrollBar:vertical { background: transparent; width: 12px; margin: 0; }
    QScrollBar::handle:vertical { background: #c4c8d0; border-radius: 6px; min-height: 24px; }
    QScrollBar::handle:vertical:hover { background: #a6abb5; }
    QScrollBar:horizontal { background: transparent; height: 12px; margin: 0; }
    QScrollBar::handle:horizontal { background: #c4c8d0; border-radius: 6px; min-width: 24px; }
    QScrollBar::handle:horizontal:hover { background: #a6abb5; }
    QScrollBar::add-line, QScrollBar::sub-line { height: 0; width: 0; }
    QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }
    QSlider::groove:horizontal { background: #d4d7dd; height: 4px; border-radius: 2px; }
    QSlider::handle:horizontal { background: #2f6fed; width: 14px; margin: -6px 0; border-radius: 7px; }
    QSlider::handle:horizontal:hover { background: #4a7fe0; }
)";

bool isDarkTheme() {
    QSettings s;
    if (s.contains(kDarkThemeKey))
        return s.value(kDarkThemeKey).toBool();
    // No explicit choice yet (first launch): follow the desktop. Qt maps the
    // system palette on Linux, so a dark default window colour means dark mode.
    // (Qt 6.4 has no QStyleHints::colorScheme(); this palette check is the
    // dependency-free equivalent. The Settings toggle stores an explicit choice
    // that wins here afterwards.)
    if (auto* app = qApp)
        return app->palette().color(QPalette::Window).lightness() < 128;
    return false;
}

void applyTheme(bool dark) {
    auto* app = qApp;
    if (!app) return;
    QString qss = QString::fromLatin1(dark ? kDarkStyleSheet : kLightStyleSheet);
    // Substitute the spinbox/combo arrow glyphs, drawn in a colour that reads on
    // this theme's control background.
    const QColor arrow = dark ? QColor(0xa6, 0xad, 0xc8) : QColor(0x4b, 0x55, 0x63);
    qss.replace(QStringLiteral("%DOWN_ARROW%"), arrowFile(arrow, /*up=*/false));
    qss.replace(QStringLiteral("%UP_ARROW%"),   arrowFile(arrow, /*up=*/true));
    app->setStyleSheet(qss);
}

void applyStoredTheme() {
    applyTheme(isDarkTheme());
}

EditorPalette editorPalette() {
    if (isDarkTheme()) {
        // Catppuccin Mocha (pastels on a dark base), matching the disassembler.
        return EditorPalette{
            .background = QColor(0x1e, 0x1e, 0x2e), .text = QColor(0xcd, 0xd6, 0xf4),
            .dim = QColor(0x6c, 0x70, 0x86),
            .comment = QColor(0x6c, 0x70, 0x86), .directive = QColor(0xf9, 0xe2, 0xaf),
            .keyword = QColor(0xcb, 0xa6, 0xf7), .reg = QColor(0x89, 0xdc, 0xeb),
            .number = QColor(0xfa, 0xb3, 0x87), .label = QColor(0xa6, 0xe3, 0xa1),
            .string = QColor(0xa6, 0xe3, 0xa1),
            .error = QColor(0xf3, 0x8b, 0xa8), .success = QColor(0xa6, 0xe3, 0xa1),
            .canvas = QColor(0x31, 0x32, 0x44), .canvasBorder = QColor(0x6c, 0x70, 0x86),
        };
    }
    // Catppuccin Latte equivalents: dark, saturated ink on a white base so every
    // token stays legible on a light editor.
    return EditorPalette{
        .background = QColor(0xff, 0xff, 0xff), .text = QColor(0x00, 0x00, 0x00),
        .dim = QColor(0x8c, 0x8f, 0xa1),
        .comment = QColor(0x7c, 0x7f, 0x93), .directive = QColor(0xdf, 0x8e, 0x1d),
        .keyword = QColor(0x88, 0x39, 0xef), .reg = QColor(0x04, 0x9d, 0xd5),
        .number = QColor(0xfe, 0x64, 0x0b), .label = QColor(0x40, 0xa0, 0x2b),
        .string = QColor(0x40, 0xa0, 0x2b),
        .error = QColor(0xd2, 0x0f, 0x39), .success = QColor(0x2e, 0x7d, 0x32),
        .canvas = QColor(0xf5, 0xf5, 0xf5), .canvasBorder = QColor(0xb0, 0xb0, 0xb0),
    };
}

} // namespace ce::gui
