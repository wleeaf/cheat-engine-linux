/// Tabbed settings dialog. All values persist via QSettings — runtime consumers
/// read them lazily; absence of a key falls back to the same defaults seen here.

#include "gui/settingsdialog.hpp"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QLabel>
#include <QPushButton>
#include <QTabWidget>
#include <QSettings>
#include <QHeaderView>

namespace ce::gui {

namespace {
constexpr const char* SCAN_ALIGN_KEY        = "scan/alignment";
constexpr const char* SCAN_WRITABLE_KEY     = "scan/writable";
constexpr const char* SCAN_EXEC_KEY         = "scan/executable";
constexpr const char* SCAN_FAST_KEY         = "scan/fast";
constexpr const char* SCAN_THREADS_KEY      = "scan/threads";
constexpr const char* SCAN_DEFAULT_VT_KEY   = "scan/defaultValueType";
constexpr const char* SCAN_FLOAT_TOL_KEY    = "scan/floatTolerance";

constexpr const char* DISP_HEX_UPPER_KEY    = "display/hexUpper";
constexpr const char* DISP_FONT_SIZE_KEY    = "display/fontSize";
constexpr const char* DISP_FONT_FAMILY_KEY  = "display/fontFamily";
constexpr const char* DISP_ADDR_WIDTH_KEY   = "display/addressWidth";
constexpr const char* DISP_DARK_KEY         = "display/dark";

constexpr const char* DBG_BP_TYPE_KEY       = "debug/bpType";
constexpr const char* DBG_BP_SIZE_KEY       = "debug/bpSize";
constexpr const char* DBG_ATTACH_DELAY_KEY  = "debug/attachDelayMs";
constexpr const char* DBG_COND_TIMEOUT_KEY  = "debug/conditionTimeoutMs";
constexpr const char* DBG_BREAK_SIGNALS_KEY = "debug/breakOnSignals";

constexpr const char* MV_BYTES_PER_ROW_KEY  = "memview/bytesPerRow";
constexpr const char* MV_REFRESH_MS_KEY     = "memview/refreshMs";
constexpr const char* MV_AUTO_REFRESH_KEY   = "memview/autoRefresh";
constexpr const char* MV_DEFAULT_ARCH_KEY   = "memview/defaultArch";

constexpr const char* HK_VALUE_STEP_KEY     = "hotkeys/valueStep";

constexpr const char* NET_CESERVER_HOST_KEY = "network/ceserverHost";
constexpr const char* NET_CESERVER_PORT_KEY = "network/ceserverPort";
constexpr const char* NET_COMPRESSION_KEY   = "network/compressionLevel";
constexpr const char* NET_GDB_PORT_KEY      = "network/gdbDefaultPort";
}

SettingsDialog::SettingsDialog(QWidget* parent) : QDialog(parent) {
    setWindowTitle("Settings");
    resize(560, 480);

    auto* root = new QVBoxLayout(this);

    auto* tabs = new QTabWidget;
    tabs->addTab(buildScanTab(),       "Scan");
    tabs->addTab(buildDisplayTab(),    "Display");
    tabs->addTab(buildDebuggerTab(),   "Debugger");
    tabs->addTab(buildMemoryViewTab(), "Memory View");
    tabs->addTab(buildHotkeysTab(),    "Hotkeys");
    tabs->addTab(buildNetworkTab(),    "Network");
    root->addWidget(tabs);

    auto* btnRow = new QHBoxLayout;
    btnRow->addStretch();
    auto* applyBtn = new QPushButton("Apply");
    connect(applyBtn, &QPushButton::clicked, this, &SettingsDialog::onApply);
    auto* okBtn = new QPushButton("OK");
    connect(okBtn, &QPushButton::clicked, this, [this]() { onApply(); accept(); });
    auto* cancelBtn = new QPushButton("Cancel");
    connect(cancelBtn, &QPushButton::clicked, this, &QDialog::reject);
    btnRow->addWidget(applyBtn);
    btnRow->addWidget(okBtn);
    btnRow->addWidget(cancelBtn);
    root->addLayout(btnRow);
}

QWidget* SettingsDialog::buildScanTab() {
    auto* w = new QWidget;
    auto* form = new QFormLayout(w);

    QSettings s;
    alignSpin_ = new QSpinBox;
    alignSpin_->setRange(1, 16);
    alignSpin_->setValue(s.value(SCAN_ALIGN_KEY, 4).toInt());
    form->addRow("Default alignment:", alignSpin_);

    writableCheck_ = new QCheckBox("Scan writable memory only by default");
    writableCheck_->setChecked(s.value(SCAN_WRITABLE_KEY, true).toBool());
    form->addRow("", writableCheck_);

    executableCheck_ = new QCheckBox("Scan executable memory only by default");
    executableCheck_->setChecked(s.value(SCAN_EXEC_KEY, false).toBool());
    form->addRow("", executableCheck_);

    fastScanCheck_ = new QCheckBox("Fast scan (alignment-aware)");
    fastScanCheck_->setChecked(s.value(SCAN_FAST_KEY, true).toBool());
    form->addRow("", fastScanCheck_);

    threadsSpin_ = new QSpinBox;
    threadsSpin_->setRange(1, 256);
    threadsSpin_->setValue(s.value(SCAN_THREADS_KEY, 0).toInt());
    threadsSpin_->setSpecialValueText("auto");
    form->addRow("Worker threads:", threadsSpin_);

    defaultValueTypeCombo_ = new QComboBox;
    defaultValueTypeCombo_->addItems({"Byte", "2 Bytes", "4 Bytes", "8 Bytes",
                                      "Float", "Double", "String", "Array of byte", "Pointer"});
    defaultValueTypeCombo_->setCurrentIndex(s.value(SCAN_DEFAULT_VT_KEY, 2).toInt());
    form->addRow("Default value type:", defaultValueTypeCombo_);

    defaultFloatToleranceSpin_ = new QDoubleSpinBox;
    defaultFloatToleranceSpin_->setRange(0.0, 1e9);
    defaultFloatToleranceSpin_->setDecimals(6);
    defaultFloatToleranceSpin_->setValue(s.value(SCAN_FLOAT_TOL_KEY, 0.0).toDouble());
    form->addRow("Default float tolerance:", defaultFloatToleranceSpin_);

    return w;
}

QWidget* SettingsDialog::buildDisplayTab() {
    auto* w = new QWidget;
    auto* form = new QFormLayout(w);

    QSettings s;
    hexUpperCheck_ = new QCheckBox("Uppercase hex");
    hexUpperCheck_->setChecked(s.value(DISP_HEX_UPPER_KEY, false).toBool());
    form->addRow("", hexUpperCheck_);

    fontFamilyCombo_ = new QFontComboBox;
    fontFamilyCombo_->setFontFilters(QFontComboBox::MonospacedFonts);
    fontFamilyCombo_->setCurrentFont(QFont(s.value(DISP_FONT_FAMILY_KEY, "Monospace").toString()));
    form->addRow("Monospace font:", fontFamilyCombo_);

    fontSizeSpin_ = new QSpinBox;
    fontSizeSpin_->setRange(7, 24);
    fontSizeSpin_->setValue(s.value(DISP_FONT_SIZE_KEY, 10).toInt());
    form->addRow("Font size:", fontSizeSpin_);

    addressWidthCombo_ = new QComboBox;
    addressWidthCombo_->addItems({"32-bit (8 hex chars)", "64-bit (16 hex chars)"});
    addressWidthCombo_->setCurrentIndex(s.value(DISP_ADDR_WIDTH_KEY, 1).toInt());
    form->addRow("Address width:", addressWidthCombo_);

    darkThemeCheck_ = new QCheckBox("Dark theme (Catppuccin)");
    darkThemeCheck_->setChecked(s.value(DISP_DARK_KEY, true).toBool());
    form->addRow("", darkThemeCheck_);

    return w;
}

QWidget* SettingsDialog::buildDebuggerTab() {
    auto* w = new QWidget;
    auto* form = new QFormLayout(w);

    QSettings s;
    bpTypeCombo_ = new QComboBox;
    bpTypeCombo_->addItems({"Hardware (DR0-3)", "Software (int3)"});
    bpTypeCombo_->setCurrentIndex(s.value(DBG_BP_TYPE_KEY, 0).toInt());
    form->addRow("Default breakpoint type:", bpTypeCombo_);

    bpSizeSpin_ = new QSpinBox;
    bpSizeSpin_->setRange(1, 8);
    bpSizeSpin_->setValue(s.value(DBG_BP_SIZE_KEY, 4).toInt());
    form->addRow("Default data BP size (bytes):", bpSizeSpin_);

    attachDelaySpin_ = new QSpinBox;
    attachDelaySpin_->setRange(0, 5000);
    attachDelaySpin_->setValue(s.value(DBG_ATTACH_DELAY_KEY, 100).toInt());
    attachDelaySpin_->setSuffix(" ms");
    form->addRow("ptrace attach settle delay:", attachDelaySpin_);

    conditionTimeoutSpin_ = new QSpinBox;
    conditionTimeoutSpin_->setRange(1, 60'000);
    conditionTimeoutSpin_->setValue(s.value(DBG_COND_TIMEOUT_KEY, 1000).toInt());
    conditionTimeoutSpin_->setSuffix(" ms");
    form->addRow("Lua condition eval timeout:", conditionTimeoutSpin_);

    breakOnSignalsCheck_ = new QCheckBox("Break on SIGSEGV / SIGFPE / SIGILL");
    breakOnSignalsCheck_->setChecked(s.value(DBG_BREAK_SIGNALS_KEY, true).toBool());
    form->addRow("", breakOnSignalsCheck_);

    return w;
}

QWidget* SettingsDialog::buildMemoryViewTab() {
    auto* w = new QWidget;
    auto* form = new QFormLayout(w);

    QSettings s;
    bytesPerRowSpin_ = new QSpinBox;
    bytesPerRowSpin_->setRange(4, 64);
    bytesPerRowSpin_->setSingleStep(4);
    bytesPerRowSpin_->setValue(s.value(MV_BYTES_PER_ROW_KEY, 16).toInt());
    form->addRow("Hex bytes per row:", bytesPerRowSpin_);

    refreshIntervalSpin_ = new QSpinBox;
    refreshIntervalSpin_->setRange(100, 30'000);
    refreshIntervalSpin_->setSingleStep(100);
    refreshIntervalSpin_->setValue(s.value(MV_REFRESH_MS_KEY, 500).toInt());
    refreshIntervalSpin_->setSuffix(" ms");
    form->addRow("Auto-refresh interval:", refreshIntervalSpin_);

    autoRefreshCheck_ = new QCheckBox("Auto-refresh memory view");
    autoRefreshCheck_->setChecked(s.value(MV_AUTO_REFRESH_KEY, true).toBool());
    form->addRow("", autoRefreshCheck_);

    defaultArchCombo_ = new QComboBox;
    defaultArchCombo_->addItems({"x86-64", "x86-32", "ARM64", "ARM32", "Auto-detect"});
    defaultArchCombo_->setCurrentIndex(s.value(MV_DEFAULT_ARCH_KEY, 0).toInt());
    form->addRow("Default architecture:", defaultArchCombo_);

    return w;
}

QWidget* SettingsDialog::buildHotkeysTab() {
    auto* w = new QWidget;
    auto* layout = new QVBoxLayout(w);

    layout->addWidget(new QLabel(
        "Per-table hotkeys are configured from the Address List right-click menu.\n"
        "These are global default values used when adding new entries."));

    QSettings s;
    hotkeyTable_ = new QTableWidget;
    hotkeyTable_->setColumnCount(2);
    hotkeyTable_->setHorizontalHeaderLabels({"Setting", "Value"});
    hotkeyTable_->horizontalHeader()->setStretchLastSection(true);
    hotkeyTable_->setRowCount(1);
    hotkeyTable_->setItem(0, 0, new QTableWidgetItem("Default value step"));
    hotkeyTable_->setItem(0, 1, new QTableWidgetItem(s.value(HK_VALUE_STEP_KEY, "1").toString()));
    layout->addWidget(hotkeyTable_, /*stretch=*/1);

    return w;
}

QWidget* SettingsDialog::buildNetworkTab() {
    auto* w = new QWidget;
    auto* form = new QFormLayout(w);

    QSettings s;
    ceserverHostEdit_ = new QLineEdit;
    ceserverHostEdit_->setText(s.value(NET_CESERVER_HOST_KEY, "127.0.0.1").toString());
    form->addRow("ceserver host:", ceserverHostEdit_);

    ceserverPortSpin_ = new QSpinBox;
    ceserverPortSpin_->setRange(1, 65535);
    ceserverPortSpin_->setValue(s.value(NET_CESERVER_PORT_KEY, 52736).toInt());
    form->addRow("ceserver port:", ceserverPortSpin_);

    compressionLevelSpin_ = new QSpinBox;
    compressionLevelSpin_->setRange(0, 9);
    compressionLevelSpin_->setValue(s.value(NET_COMPRESSION_KEY, 6).toInt());
    form->addRow("zlib compression level:", compressionLevelSpin_);

    gdbDefaultPortSpin_ = new QSpinBox;
    gdbDefaultPortSpin_->setRange(1, 65535);
    gdbDefaultPortSpin_->setValue(s.value(NET_GDB_PORT_KEY, 1234).toInt());
    form->addRow("Default GDB stub port:", gdbDefaultPortSpin_);

    return w;
}

void SettingsDialog::onApply() {
    QSettings s;
    s.setValue(SCAN_ALIGN_KEY,        alignSpin_->value());
    s.setValue(SCAN_WRITABLE_KEY,     writableCheck_->isChecked());
    s.setValue(SCAN_EXEC_KEY,         executableCheck_->isChecked());
    s.setValue(SCAN_FAST_KEY,         fastScanCheck_->isChecked());
    s.setValue(SCAN_THREADS_KEY,      threadsSpin_->value());
    s.setValue(SCAN_DEFAULT_VT_KEY,   defaultValueTypeCombo_->currentIndex());
    s.setValue(SCAN_FLOAT_TOL_KEY,    defaultFloatToleranceSpin_->value());

    s.setValue(DISP_HEX_UPPER_KEY,    hexUpperCheck_->isChecked());
    s.setValue(DISP_FONT_SIZE_KEY,    fontSizeSpin_->value());
    s.setValue(DISP_FONT_FAMILY_KEY,  fontFamilyCombo_->currentFont().family());
    s.setValue(DISP_ADDR_WIDTH_KEY,   addressWidthCombo_->currentIndex());
    s.setValue(DISP_DARK_KEY,         darkThemeCheck_->isChecked());

    s.setValue(DBG_BP_TYPE_KEY,       bpTypeCombo_->currentIndex());
    s.setValue(DBG_BP_SIZE_KEY,       bpSizeSpin_->value());
    s.setValue(DBG_ATTACH_DELAY_KEY,  attachDelaySpin_->value());
    s.setValue(DBG_COND_TIMEOUT_KEY,  conditionTimeoutSpin_->value());
    s.setValue(DBG_BREAK_SIGNALS_KEY, breakOnSignalsCheck_->isChecked());

    s.setValue(MV_BYTES_PER_ROW_KEY,  bytesPerRowSpin_->value());
    s.setValue(MV_REFRESH_MS_KEY,     refreshIntervalSpin_->value());
    s.setValue(MV_AUTO_REFRESH_KEY,   autoRefreshCheck_->isChecked());
    s.setValue(MV_DEFAULT_ARCH_KEY,   defaultArchCombo_->currentIndex());

    if (auto* item = hotkeyTable_->item(0, 1))
        s.setValue(HK_VALUE_STEP_KEY, item->text());

    s.setValue(NET_CESERVER_HOST_KEY, ceserverHostEdit_->text());
    s.setValue(NET_CESERVER_PORT_KEY, ceserverPortSpin_->value());
    s.setValue(NET_COMPRESSION_KEY,   compressionLevelSpin_->value());
    s.setValue(NET_GDB_PORT_KEY,      gdbDefaultPortSpin_->value());
}

} // namespace ce::gui
