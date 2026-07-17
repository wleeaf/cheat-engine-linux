#include "gui/theme.hpp"

#include <QApplication>
#include <QSettings>

namespace ce::gui {

static const char* kDarkStyleSheet = R"(
    QWidget { background-color: #1e1e2e; color: #cdd6f4; }
    QMenuBar { background-color: #181825; color: #cdd6f4; }
    QMenuBar::item:selected { background-color: #313244; }
    QMenu { background-color: #1e1e2e; color: #cdd6f4; border: 1px solid #45475a; }
    QMenu::item:selected { background-color: #313244; }
    QPushButton, QToolButton { background-color: #313244; color: #cdd6f4; border: 1px solid #45475a;
                  padding: 4px 12px; border-radius: 4px; }
    QPushButton:hover, QToolButton:hover { background-color: #45475a; }
    QPushButton:pressed, QToolButton:pressed { background-color: #585b70; }
    QPushButton:disabled, QToolButton:disabled { color: #585b70; }
    QLineEdit, QSpinBox { background-color: #313244; color: #cdd6f4; border: 1px solid #45475a;
                          padding: 3px; border-radius: 3px; }
    QComboBox { background-color: #313244; color: #cdd6f4; border: 1px solid #45475a;
                padding: 3px; border-radius: 3px; }
    QComboBox QAbstractItemView { background-color: #1e1e2e; color: #cdd6f4; selection-background-color: #313244; }
    QComboBox::drop-down { border: none; }
    QTableView, QListWidget, QTableWidget, QTreeView, QTreeWidget { background-color: #181825; color: #cdd6f4;
        gridline-color: #313244; selection-background-color: #313244; alternate-background-color: #1e1e2e; }
    QTreeView::item:selected, QTreeWidget::item:selected { background-color: #313244; color: #cdd6f4; }
    QHeaderView::section { background-color: #181825; color: #a6adc8; border: 1px solid #313244; padding: 4px; }
    QSplitter::handle { background-color: #313244; }
    QGroupBox { color: #a6adc8; border: 1px solid #45475a; border-radius: 4px; margin-top: 8px; padding-top: 8px; }
    QGroupBox::title { subcontrol-origin: margin; left: 8px; padding: 0 4px; }
    QCheckBox, QRadioButton { color: #cdd6f4; }
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
// familiar light-blue selection.
static const char* kLightStyleSheet = R"(
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
    QTableView, QListWidget, QTableWidget, QTreeView, QTreeWidget { background-color: #ffffff; color: #000000;
        gridline-color: #d0d0d0; selection-background-color: #cce8ff; selection-color: #000000; alternate-background-color: #f5f5f5; }
    QTreeView::item:selected, QTreeWidget::item:selected { background-color: #cce8ff; color: #000000; }
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

bool isDarkTheme() {
    QSettings s;
    return s.value(kDarkThemeKey, false).toBool();
}

void applyTheme(bool dark) {
    if (auto* app = qApp)
        app->setStyleSheet(dark ? kDarkStyleSheet : kLightStyleSheet);
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
