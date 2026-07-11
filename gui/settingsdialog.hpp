#pragma once
/// Settings dialog with tabs: Scan / Display / Debugger / Memory View / Hotkeys / Network.
/// Persisted via QSettings under the org "cecore".

#include <QDialog>
#include <QSpinBox>
#include <QDoubleSpinBox>
#include <QCheckBox>
#include <QComboBox>
#include <QLineEdit>
#include <QFontComboBox>
#include <QTableWidget>

namespace ce::gui {

class SettingsDialog : public QDialog {
    Q_OBJECT
public:
    explicit SettingsDialog(QWidget* parent = nullptr);
private slots:
    void onApply();
private:
    QWidget* buildScanTab();
    QWidget* buildDisplayTab();
    QWidget* buildDebuggerTab();
    QWidget* buildMemoryViewTab();
    QWidget* buildHotkeysTab();
    QWidget* buildNetworkTab();

    // Scan
    QSpinBox* alignSpin_;
    QCheckBox* writableCheck_;
    QCheckBox* executableCheck_;
    QCheckBox* fastScanCheck_;
    QSpinBox* threadsSpin_;
    QComboBox* defaultValueTypeCombo_;
    QDoubleSpinBox* defaultFloatToleranceSpin_;

    // Display
    QCheckBox* hexUpperCheck_;
    QSpinBox* fontSizeSpin_;
    QFontComboBox* fontFamilyCombo_;
    QComboBox* addressWidthCombo_;
    QCheckBox* darkThemeCheck_;

    // Debugger
    QComboBox* bpTypeCombo_;
    QSpinBox* bpSizeSpin_;
    QSpinBox* attachDelaySpin_;
    QSpinBox* conditionTimeoutSpin_;
    QCheckBox* breakOnSignalsCheck_;

    // Memory View
    QSpinBox* bytesPerRowSpin_;
    QSpinBox* refreshIntervalSpin_;
    QCheckBox* autoRefreshCheck_;
    QComboBox* defaultArchCombo_;

    // Hotkeys (only the address-list value hotkey defaults are stored here for now)
    QTableWidget* hotkeyTable_;

    // Network
    QLineEdit* ceserverHostEdit_;
    QSpinBox* ceserverPortSpin_;
    QSpinBox* compressionLevelSpin_;
    QSpinBox* gdbDefaultPortSpin_;
};

} // namespace ce::gui
