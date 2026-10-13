/// Settings dialog. All values persist via QSettings; runtime consumers read them
/// lazily, and an absent key falls back to the same defaults seen here.

#include "gui/settingsdialog.hpp"
#include "gui/theme.hpp"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QLabel>
#include <QPushButton>
#include <QListWidget>
#include <QStackedWidget>
#include <QSettings>
#include <QScrollArea>
#include <QFontMetrics>
#include <QDoubleValidator>
#include <QStandardPaths>
#include <QDesktopServices>
#include <QDir>
#include <QUrl>

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

constexpr const char* MV_BYTES_PER_ROW_KEY  = "memview/bytesPerRow";
constexpr const char* MV_REFRESH_MS_KEY     = "memview/refreshMs";
constexpr const char* MV_AUTO_REFRESH_KEY   = "memview/autoRefresh";

constexpr const char* DBG_BP_SIZE_KEY       = "debug/bpSize";
constexpr const char* CF_WATCH_SIZE_KEY     = "codefinder/watchSize";

constexpr const char* HK_VALUE_STEP_KEY     = "hotkeys/valueStep";

constexpr const char* NET_CESERVER_HOST_KEY = "network/ceserverHost";
constexpr const char* NET_CESERVER_PORT_KEY = "network/ceserverPort";

// Fields sized for their content instead of stretching across the page.
constexpr int kFieldWidth = 260;

// A page: bold title, one-line explanation, a hairline, then a form.
QFormLayout* makePage(QWidget* page, const QString& title, const QString& subtitle) {
    auto* layout = new QVBoxLayout(page);
    layout->setContentsMargins(4, 2, 8, 8);
    layout->setSpacing(4);
    auto* heading = new QLabel(title);
    heading->setObjectName("pageTitle");
    layout->addWidget(heading);
    auto* note = new QLabel(subtitle);
    note->setProperty("secondary", true);
    note->setWordWrap(true);
    layout->addWidget(note);
    auto* line = new QFrame;
    line->setObjectName("hairline");
    layout->addSpacing(6);
    layout->addWidget(line);
    layout->addSpacing(8);
    auto* form = new QFormLayout;
    form->setLabelAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    form->setFieldGrowthPolicy(QFormLayout::FieldsStayAtSizeHint);
    form->setHorizontalSpacing(16);
    form->setVerticalSpacing(10);
    layout->addLayout(form);
    layout->addStretch(1);
    return form;
}

template <typename W> W* sized(W* widget) {
    widget->setMinimumWidth(kFieldWidth);
    widget->setMaximumWidth(kFieldWidth);
    return widget;
}

QLabel* hint(const QString& text) {
    auto* label = new QLabel(text);
    label->setProperty("secondary", true);
    label->setWordWrap(true);
    // A wrapped label's size hint is narrow; give it the field width and more.
    label->setMinimumWidth(kFieldWidth + 60);
    return label;
}

QComboBox* sizeCombo(const QString& current) {
    auto* combo = new QComboBox;
    for (const char* size : {"1", "2", "4", "8"})
        combo->addItem(QString("%1 %2").arg(size).arg(QString(size) == "1" ? "byte" : "bytes"), QString(size));
    combo->setCurrentIndex(std::max(0, combo->findData(current)));
    return sized(combo);
}
} // namespace

SettingsDialog::SettingsDialog(QWidget* parent) : QDialog(parent) {
    setWindowTitle("Settings");
    resize(760, 520);

    auto* root = new QVBoxLayout(this);
    root->setSpacing(12);

    // Vertical category sidebar: every page name is visible at once.
    auto* nav = new QListWidget;
    nav->setObjectName("settingsNav");
    nav->setFixedWidth(std::max(160, QFontMetrics(nav->font()).horizontalAdvance("Memory View") + 48));
    nav->setUniformItemSizes(true);
    nav->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    nav->setStyleSheet("QListWidget#settingsNav { padding: 4px; }"
                       "QListWidget#settingsNav::item { padding: 6px 10px; border-radius: 4px; }");
    auto* pages = new QStackedWidget;
    auto addPage = [&](QWidget* w, const QString& name) {
        auto* scroll = new QScrollArea;
        scroll->setWidgetResizable(true);
        scroll->setFrameShape(QFrame::NoFrame);
        scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        scroll->setWidget(w);
        nav->addItem(name);
        pages->addWidget(scroll);
    };
    addPage(buildScanPage(),       "Scan");
    addPage(buildDisplayPage(),    "Display");
    addPage(buildMemoryViewPage(), "Memory View");
    addPage(buildDebuggerPage(),   "Debugger");
    addPage(buildHotkeysPage(),    "Hotkeys");
    addPage(buildNetworkPage(),    "Network");
    addPage(buildLuaPage(),        "Lua");

    connect(nav, &QListWidget::currentRowChanged, pages, &QStackedWidget::setCurrentIndex);
    nav->setCurrentRow(0);

    auto* body = new QHBoxLayout;
    body->setSpacing(16);
    body->addWidget(nav);
    body->addWidget(pages, 1);
    root->addLayout(body, 1);

    auto* btnRow = new QHBoxLayout;
    btnRow->addStretch();
    auto* okBtn = new QPushButton("OK");
    okBtn->setObjectName("primaryButton");
    okBtn->setDefault(true);
    connect(okBtn, &QPushButton::clicked, this, [this]() { onApply(); accept(); });
    auto* cancelBtn = new QPushButton("Cancel");
    connect(cancelBtn, &QPushButton::clicked, this, &QDialog::reject);
    auto* applyBtn = new QPushButton("Apply");
    connect(applyBtn, &QPushButton::clicked, this, &SettingsDialog::onApply);
    for (auto* button : {okBtn, cancelBtn, applyBtn}) {
        button->setMinimumWidth(84);
        btnRow->addWidget(button);
    }
    root->addLayout(btnRow);
}

QWidget* SettingsDialog::buildScanPage() {
    auto* w = new QWidget;
    auto* form = makePage(w, "Scan", "Defaults for a new scan. The main window's scan options start from these.");
    QSettings s;

    defaultValueTypeCombo_ = sized(new QComboBox);
    defaultValueTypeCombo_->addItems({"Byte", "2 Bytes", "4 Bytes", "8 Bytes",
                                      "Float", "Double", "String", "Array of byte", "Pointer"});
    defaultValueTypeCombo_->setCurrentIndex(s.value(SCAN_DEFAULT_VT_KEY, 2).toInt());
    form->addRow("Value type:", defaultValueTypeCombo_);

    alignSpin_ = sized(new QSpinBox);
    alignSpin_->setRange(1, 16);
    alignSpin_->setSuffix(" bytes");
    alignSpin_->setValue(s.value(SCAN_ALIGN_KEY, 4).toInt());
    form->addRow("Fast scan alignment:", alignSpin_);

    fastScanCheck_ = new QCheckBox("Fast scan (only aligned addresses)");
    fastScanCheck_->setChecked(s.value(SCAN_FAST_KEY, true).toBool());
    form->addRow("", fastScanCheck_);
    writableCheck_ = new QCheckBox("Only writable memory");
    writableCheck_->setChecked(s.value(SCAN_WRITABLE_KEY, true).toBool());
    form->addRow("", writableCheck_);
    executableCheck_ = new QCheckBox("Only executable memory");
    executableCheck_->setChecked(s.value(SCAN_EXEC_KEY, false).toBool());
    form->addRow("", executableCheck_);

    threadsSpin_ = sized(new QSpinBox);
    threadsSpin_->setRange(0, 256);
    threadsSpin_->setSpecialValueText("Automatic (one per CPU)");
    threadsSpin_->setValue(s.value(SCAN_THREADS_KEY, 0).toInt());
    form->addRow("Worker threads:", threadsSpin_);

    defaultFloatToleranceSpin_ = sized(new QDoubleSpinBox);
    defaultFloatToleranceSpin_->setRange(0.0, 1e9);
    defaultFloatToleranceSpin_->setDecimals(6);
    defaultFloatToleranceSpin_->setSpecialValueText("Automatic");
    defaultFloatToleranceSpin_->setValue(s.value(SCAN_FLOAT_TOL_KEY, 0.0).toDouble());
    form->addRow("Float tolerance:", defaultFloatToleranceSpin_);
    form->addRow("", hint("Used by the \"Extreme\" float rounding mode."));
    return w;
}

QWidget* SettingsDialog::buildDisplayPage() {
    auto* w = new QWidget;
    auto* form = makePage(w, "Display", "Theme and the font used by tables, the disassembler and hex views.");
    QSettings s;

    themeCombo_ = sized(new QComboBox);
    themeCombo_->setObjectName("displayTheme");
    themeCombo_->addItems({"Light", "Dark"});
    themeCombo_->setCurrentIndex(isDarkTheme() ? 1 : 0);
    form->addRow("Theme:", themeCombo_);

    fontFamilyCombo_ = sized(new QFontComboBox);
    fontFamilyCombo_->setFontFilters(QFontComboBox::MonospacedFonts);
    fontFamilyCombo_->setCurrentFont(QFont(s.value(DISP_FONT_FAMILY_KEY, defaultMonospaceFamily()).toString()));
    form->addRow("Monospace font:", fontFamilyCombo_);

    fontSizeSpin_ = sized(new QSpinBox);
    fontSizeSpin_->setObjectName("displayFontSize");
    fontSizeSpin_->setRange(7, 24);
    fontSizeSpin_->setSuffix(" pt");
    fontSizeSpin_->setValue(s.value(DISP_FONT_SIZE_KEY, defaultMonospaceSize()).toInt());
    form->addRow("Font size:", fontSizeSpin_);

    addressWidthCombo_ = sized(new QComboBox);
    addressWidthCombo_->addItems({"32-bit (8 hex digits)", "64-bit (16 hex digits)"});
    addressWidthCombo_->setCurrentIndex(s.value(DISP_ADDR_WIDTH_KEY, 1).toInt());
    form->addRow("Address width:", addressWidthCombo_);

    hexUpperCheck_ = new QCheckBox("Uppercase hexadecimal (0x7F3A, not 0x7f3a)");
    hexUpperCheck_->setChecked(s.value(DISP_HEX_UPPER_KEY, false).toBool());
    form->addRow("", hexUpperCheck_);
    return w;
}

QWidget* SettingsDialog::buildMemoryViewPage() {
    auto* w = new QWidget;
    auto* form = makePage(w, "Memory View", "Layout and refresh of the hex dump in the Memory Viewer.");
    QSettings s;

    bytesPerRowSpin_ = sized(new QSpinBox);
    bytesPerRowSpin_->setRange(4, 64);
    bytesPerRowSpin_->setSingleStep(4);
    bytesPerRowSpin_->setValue(s.value(MV_BYTES_PER_ROW_KEY, 16).toInt());
    form->addRow("Bytes per row:", bytesPerRowSpin_);

    autoRefreshCheck_ = new QCheckBox("Refresh values while the view is open");
    autoRefreshCheck_->setChecked(s.value(MV_AUTO_REFRESH_KEY, true).toBool());
    form->addRow("", autoRefreshCheck_);

    refreshIntervalSpin_ = sized(new QSpinBox);
    refreshIntervalSpin_->setRange(100, 30'000);
    refreshIntervalSpin_->setSingleStep(100);
    refreshIntervalSpin_->setSuffix(" ms");
    refreshIntervalSpin_->setValue(s.value(MV_REFRESH_MS_KEY, 500).toInt());
    refreshIntervalSpin_->setEnabled(autoRefreshCheck_->isChecked());
    connect(autoRefreshCheck_, &QCheckBox::toggled, refreshIntervalSpin_, &QWidget::setEnabled);
    form->addRow("Refresh interval:", refreshIntervalSpin_);
    form->addRow("", hint("The address list's live values use the same interval."));
    return w;
}

QWidget* SettingsDialog::buildDebuggerPage() {
    auto* w = new QWidget;
    auto* form = makePage(w, "Debugger", "Defaults for hardware watchpoints.");
    QSettings s;

    dataBpSizeCombo_ = sizeCombo(s.value(DBG_BP_SIZE_KEY, "4").toString());
    form->addRow("Data breakpoint size:", dataBpSizeCombo_);
    watchSizeCombo_ = sizeCombo(s.value(CF_WATCH_SIZE_KEY, "4").toString());
    form->addRow("Find-what-writes size:", watchSizeCombo_);
    form->addRow("", hint("How many bytes from the address a watchpoint covers. "
                          "x86 watchpoints must be aligned to their size."));
    return w;
}

QWidget* SettingsDialog::buildHotkeysPage() {
    auto* w = new QWidget;
    auto* form = makePage(w, "Hotkeys", "Hotkeys belong to cheat table entries: right-click an entry and "
                                        "choose Hotkeys.");
    QSettings s;
    valueStepEdit_ = sized(new QLineEdit(s.value(HK_VALUE_STEP_KEY, "1").toString()));
    valueStepEdit_->setValidator(new QDoubleValidator(valueStepEdit_));
    form->addRow("Default value step:", valueStepEdit_);
    form->addRow("", hint("How much an increase or decrease hotkey changes a value, "
                          "until the entry sets its own step."));
    return w;
}

QWidget* SettingsDialog::buildNetworkPage() {
    auto* w = new QWidget;
    auto* form = makePage(w, "Network", "The ceserver that File > Connect to ceserver offers by default.");
    QSettings s;
    ceserverHostEdit_ = sized(new QLineEdit(s.value(NET_CESERVER_HOST_KEY, "127.0.0.1").toString()));
    ceserverHostEdit_->setPlaceholderText("host name or IP address");
    form->addRow("ceserver host:", ceserverHostEdit_);
    ceserverPortSpin_ = sized(new QSpinBox);
    ceserverPortSpin_->setRange(1, 65535);
    ceserverPortSpin_->setGroupSeparatorShown(false);
    ceserverPortSpin_->setValue(s.value(NET_CESERVER_PORT_KEY, 52736).toInt());
    form->addRow("ceserver port:", ceserverPortSpin_);
    return w;
}

QWidget* SettingsDialog::buildLuaPage() {
    auto* w = new QWidget;
    auto* form = makePage(w, "Lua", "Scripts in the autorun folder run once at startup, like Cheat Engine's autorun.");
    const QString folder = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation) + "/autorun";
    auto* path = new QLineEdit(QDir::toNativeSeparators(folder));
    path->setReadOnly(true);
    path->setToolTip(path->text());
    path->setMinimumWidth(kFieldWidth);
    auto* open = new QPushButton("Open folder");
    connect(open, &QPushButton::clicked, this, [folder]() {
        QDir().mkpath(folder);
        QDesktopServices::openUrl(QUrl::fromLocalFile(folder));
    });
    auto* row = new QHBoxLayout;
    row->addWidget(path, 1);
    row->addWidget(open);
    form->addRow("Autorun folder:", row);
    form->addRow("", hint("Lua cannot run shell commands or write local files unless Cheat Engine "
                          "was started with CECORE_LUA_ALLOW_UNSAFE=1 in its environment. A cheat "
                          "table cannot turn this on by itself."));
    form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    return w;
}

void SettingsDialog::onApply() {
    QSettings s;
    s.setValue(SCAN_DEFAULT_VT_KEY,   defaultValueTypeCombo_->currentIndex());
    s.setValue(SCAN_ALIGN_KEY,        alignSpin_->value());
    s.setValue(SCAN_FAST_KEY,         fastScanCheck_->isChecked());
    s.setValue(SCAN_WRITABLE_KEY,     writableCheck_->isChecked());
    s.setValue(SCAN_EXEC_KEY,         executableCheck_->isChecked());
    s.setValue(SCAN_THREADS_KEY,      threadsSpin_->value());
    s.setValue(SCAN_FLOAT_TOL_KEY,    defaultFloatToleranceSpin_->value());

    s.setValue(DISP_FONT_FAMILY_KEY,  fontFamilyCombo_->currentFont().family());
    s.setValue(DISP_FONT_SIZE_KEY,    fontSizeSpin_->value());
    s.setValue(DISP_ADDR_WIDTH_KEY,   addressWidthCombo_->currentIndex());
    s.setValue(DISP_HEX_UPPER_KEY,    hexUpperCheck_->isChecked());
    const bool dark = themeCombo_->currentIndex() == 1;
    s.setValue(kDarkThemeKey, dark);
    // Re-apply the theme live: a theme change takes effect immediately, and the
    // sheet also carries the data tables' monospace font.
    applyTheme(dark);

    s.setValue(MV_BYTES_PER_ROW_KEY,  bytesPerRowSpin_->value());
    s.setValue(MV_AUTO_REFRESH_KEY,   autoRefreshCheck_->isChecked());
    s.setValue(MV_REFRESH_MS_KEY,     refreshIntervalSpin_->value());

    s.setValue(DBG_BP_SIZE_KEY,       dataBpSizeCombo_->currentData().toString());
    s.setValue(CF_WATCH_SIZE_KEY,     watchSizeCombo_->currentData().toString());

    s.setValue(HK_VALUE_STEP_KEY,     valueStepEdit_->text().trimmed().isEmpty() ? "1" : valueStepEdit_->text().trimmed());

    s.setValue(NET_CESERVER_HOST_KEY, ceserverHostEdit_->text().trimmed());
    s.setValue(NET_CESERVER_PORT_KEY, ceserverPortSpin_->value());
    emit settingsApplied();
}

} // namespace ce::gui
