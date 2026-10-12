#pragma once
/// Settings dialog: a category sidebar and one titled page per category.
/// Persisted via QSettings; nothing is written until Apply or OK.

#include <QDialog>
#include <QSpinBox>
#include <QDoubleSpinBox>
#include <QCheckBox>
#include <QComboBox>
#include <QLineEdit>
#include <QFontComboBox>

class QFormLayout;
class QVBoxLayout;

namespace ce::gui {

class SettingsDialog : public QDialog {
    Q_OBJECT
public:
    explicit SettingsDialog(QWidget* parent = nullptr);
signals:
    void settingsApplied();
private slots:
    void onApply();
private:
    QWidget* buildScanPage();
    QWidget* buildDisplayPage();
    QWidget* buildMemoryViewPage();
    QWidget* buildDebuggerPage();
    QWidget* buildHotkeysPage();
    QWidget* buildNetworkPage();
    QWidget* buildLuaPage();

    // Scan
    QComboBox* defaultValueTypeCombo_;
    QSpinBox* alignSpin_;
    QCheckBox* fastScanCheck_;
    QCheckBox* writableCheck_;
    QCheckBox* executableCheck_;
    QSpinBox* threadsSpin_;
    QDoubleSpinBox* defaultFloatToleranceSpin_;

    // Display
    QComboBox* themeCombo_;
    QFontComboBox* fontFamilyCombo_;
    QSpinBox* fontSizeSpin_;
    QCheckBox* hexUpperCheck_;
    QComboBox* addressWidthCombo_;

    // Memory View
    QSpinBox* bytesPerRowSpin_;
    QCheckBox* autoRefreshCheck_;
    QSpinBox* refreshIntervalSpin_;

    // Debugger
    QComboBox* dataBpSizeCombo_;
    QComboBox* watchSizeCombo_;

    // Hotkeys
    QLineEdit* valueStepEdit_;

    // Network
    QLineEdit* ceserverHostEdit_;
    QSpinBox* ceserverPortSpin_;
};

} // namespace ce::gui
