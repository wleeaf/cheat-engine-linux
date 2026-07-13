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
    QTableView, QListWidget, QTableWidget { background-color: #ffffff; color: #000000;
        gridline-color: #d0d0d0; selection-background-color: #cce8ff; selection-color: #000000; alternate-background-color: #f5f5f5; }
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

} // namespace ce::gui
