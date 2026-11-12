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
#include <QCoreApplication>
#include <QMessageBox>
#include <QProcess>

#include "core/agent_chat.hpp"
#include "gui/agent_panel.hpp"
#include "gui/secret_store.hpp"
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

constexpr const char* UI_LANGUAGE_KEY       = "ui/language";

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
    for (const char* size : {"1", "2", "4", "8"}) {
        const QString unit = QString(size) == "1"
            ? QCoreApplication::translate("SettingsDialog", "byte")
            : QCoreApplication::translate("SettingsDialog", "bytes");
        combo->addItem(QCoreApplication::translate("SettingsDialog", "%1 %2")
                           .arg(size)
                           .arg(unit),
                       QString(size));
    }
    combo->setCurrentIndex(std::max(0, combo->findData(current)));
    return sized(combo);
}

// Relaunch the program so a new interface language takes effect without the user
// restarting it by hand. Under an AppImage, the mount that applicationFilePath()
// points into disappears when this process exits, so the AppImage file itself is
// started again.
void restartApplication(QWidget* parent) {
    QStringList arguments = QCoreApplication::arguments();
    if (!arguments.isEmpty()) arguments.removeFirst();
    const QString appImage = qEnvironmentVariable("APPIMAGE");
    const QString program = appImage.isEmpty() ? QCoreApplication::applicationFilePath() : appImage;
    if (QProcess::startDetached(program, arguments, QDir::currentPath()))
        QCoreApplication::quit();
    else
        QMessageBox::warning(parent, QCoreApplication::translate("SettingsDialog", "Language"),
            QCoreApplication::translate("SettingsDialog",
                "Cheat Engine could not restart itself. Start it again to apply the language."));
}
} // namespace

SettingsDialog::SettingsDialog(QWidget* parent) : QDialog(parent) {
    setWindowTitle(tr("Settings"));
    resize(760, 520);

    auto* root = new QVBoxLayout(this);
    root->setSpacing(12);

    // Vertical category sidebar: every page name is visible at once.
    auto* nav = new QListWidget;
    nav->setObjectName("settingsNav");
    const QStringList pageNames = {
        tr("Scan"), tr("Display"), tr("Language"), tr("Memory View"), tr("Debugger"),
        tr("Hotkeys"), tr("Network"), tr("Lua"), tr("AI Assistant"),
    };
    int navTextWidth = 0;
    const QFontMetrics navMetrics(nav->font());
    for (const QString& name : pageNames)
        navTextWidth = std::max(navTextWidth, navMetrics.horizontalAdvance(name));
    nav->setFixedWidth(std::max(160, navTextWidth + 48));
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
    addPage(buildScanPage(),       pageNames[0]);
    addPage(buildDisplayPage(),    pageNames[1]);
    addPage(buildLanguagePage(),   pageNames[2]);
    addPage(buildMemoryViewPage(), pageNames[3]);
    addPage(buildDebuggerPage(),   pageNames[4]);
    addPage(buildHotkeysPage(),    pageNames[5]);
    addPage(buildNetworkPage(),    pageNames[6]);
    addPage(buildLuaPage(),        pageNames[7]);
    addPage(buildAgentPage(),      pageNames[8]);

    connect(nav, &QListWidget::currentRowChanged, pages, &QStackedWidget::setCurrentIndex);
    nav->setCurrentRow(0);

    auto* body = new QHBoxLayout;
    body->setSpacing(16);
    body->addWidget(nav);
    body->addWidget(pages, 1);
    root->addLayout(body, 1);

    auto* btnRow = new QHBoxLayout;
    btnRow->addStretch();
    auto* okBtn = new QPushButton(tr("OK"));
    okBtn->setObjectName("primaryButton");
    okBtn->setDefault(true);
    connect(okBtn, &QPushButton::clicked, this, [this]() { onApply(); accept(); });
    auto* cancelBtn = new QPushButton(tr("Cancel"));
    connect(cancelBtn, &QPushButton::clicked, this, &QDialog::reject);
    auto* applyBtn = new QPushButton(tr("Apply"));
    connect(applyBtn, &QPushButton::clicked, this, &SettingsDialog::onApply);
    for (auto* button : {okBtn, cancelBtn, applyBtn}) {
        button->setMinimumWidth(84);
        btnRow->addWidget(button);
    }
    root->addLayout(btnRow);
}

QWidget* SettingsDialog::buildScanPage() {
    auto* w = new QWidget;
    auto* form = makePage(w, tr("Scan"),
        tr("Defaults for a new scan. The main window's scan options start from these."));
    QSettings s;

    defaultValueTypeCombo_ = sized(new QComboBox);
    defaultValueTypeCombo_->addItems({tr("Byte"), tr("2 Bytes"), tr("4 Bytes"), tr("8 Bytes"),
                                      tr("Float"), tr("Double"), tr("String"),
                                      tr("Array of byte"), tr("Pointer")});
    defaultValueTypeCombo_->setCurrentIndex(s.value(SCAN_DEFAULT_VT_KEY, 2).toInt());
    form->addRow(tr("Value type:"), defaultValueTypeCombo_);

    alignSpin_ = sized(new QSpinBox);
    alignSpin_->setRange(1, 16);
    alignSpin_->setSuffix(tr(" bytes"));
    alignSpin_->setValue(s.value(SCAN_ALIGN_KEY, 4).toInt());
    form->addRow(tr("Fast scan alignment:"), alignSpin_);

    fastScanCheck_ = new QCheckBox(tr("Fast scan (only aligned addresses)"));
    fastScanCheck_->setChecked(s.value(SCAN_FAST_KEY, true).toBool());
    form->addRow("", fastScanCheck_);
    writableCheck_ = new QCheckBox(tr("Only writable memory"));
    writableCheck_->setChecked(s.value(SCAN_WRITABLE_KEY, true).toBool());
    form->addRow("", writableCheck_);
    executableCheck_ = new QCheckBox(tr("Only executable memory"));
    executableCheck_->setChecked(s.value(SCAN_EXEC_KEY, false).toBool());
    form->addRow("", executableCheck_);

    threadsSpin_ = sized(new QSpinBox);
    threadsSpin_->setRange(0, 256);
    threadsSpin_->setSpecialValueText(tr("Automatic (one per CPU)"));
    threadsSpin_->setValue(s.value(SCAN_THREADS_KEY, 0).toInt());
    form->addRow(tr("Worker threads:"), threadsSpin_);

    defaultFloatToleranceSpin_ = sized(new QDoubleSpinBox);
    defaultFloatToleranceSpin_->setRange(0.0, 1e9);
    defaultFloatToleranceSpin_->setDecimals(6);
    defaultFloatToleranceSpin_->setSpecialValueText(tr("Automatic"));
    defaultFloatToleranceSpin_->setValue(s.value(SCAN_FLOAT_TOL_KEY, 0.0).toDouble());
    form->addRow(tr("Float tolerance:"), defaultFloatToleranceSpin_);
    form->addRow("", hint(tr("Used by the \"Extreme\" float rounding mode.")));
    return w;
}

QWidget* SettingsDialog::buildDisplayPage() {
    auto* w = new QWidget;
    auto* form = makePage(w, tr("Display"),
        tr("Theme and the font used by tables, the disassembler and hex views."));
    QSettings s;

    themeCombo_ = sized(new QComboBox);
    themeCombo_->setObjectName("displayTheme");
    themeCombo_->addItems({tr("Light"), tr("Dark")});
    themeCombo_->setCurrentIndex(isDarkTheme() ? 1 : 0);
    form->addRow(tr("Theme:"), themeCombo_);

    fontFamilyCombo_ = sized(new QFontComboBox);
    fontFamilyCombo_->setFontFilters(QFontComboBox::MonospacedFonts);
    fontFamilyCombo_->setCurrentFont(QFont(s.value(DISP_FONT_FAMILY_KEY, defaultMonospaceFamily()).toString()));
    form->addRow(tr("Monospace font:"), fontFamilyCombo_);

    fontSizeSpin_ = sized(new QSpinBox);
    fontSizeSpin_->setObjectName("displayFontSize");
    fontSizeSpin_->setRange(7, 24);
    fontSizeSpin_->setSuffix(tr(" pt"));
    fontSizeSpin_->setValue(s.value(DISP_FONT_SIZE_KEY, defaultMonospaceSize()).toInt());
    form->addRow(tr("Font size:"), fontSizeSpin_);

    addressWidthCombo_ = sized(new QComboBox);
    addressWidthCombo_->addItems({tr("32-bit (8 hex digits)"), tr("64-bit (16 hex digits)")});
    addressWidthCombo_->setCurrentIndex(s.value(DISP_ADDR_WIDTH_KEY, 1).toInt());
    form->addRow(tr("Address width:"), addressWidthCombo_);

    hexUpperCheck_ = new QCheckBox(tr("Uppercase hexadecimal (0x7F3A, not 0x7f3a)"));
    hexUpperCheck_->setChecked(s.value(DISP_HEX_UPPER_KEY, false).toBool());
    form->addRow("", hexUpperCheck_);
    return w;
}

QWidget* SettingsDialog::buildLanguagePage() {
    auto* w = new QWidget;
    auto* form = makePage(w, tr("Language"),
        tr("Language of the interface. A restart is offered when it changes."));

    languageCombo_ = sized(new QComboBox);
    languageCombo_->addItem(tr("Follow system"), QString());
    // Language names stay in their own language.
    languageCombo_->addItem(QStringLiteral("English"), QStringLiteral("en"));
    languageCombo_->addItem(QStringLiteral("简体中文"), QStringLiteral("zh_CN"));
    languageCombo_->setCurrentIndex(std::max(0, languageCombo_->findData(
        QSettings().value(UI_LANGUAGE_KEY).toString())));
    form->addRow(tr("Interface language:"), languageCombo_);
    form->addRow("", hint(tr("English and Simplified Chinese are available for now.")));
    return w;
}

QWidget* SettingsDialog::buildMemoryViewPage() {
    auto* w = new QWidget;
    auto* form = makePage(w, tr("Memory View"),
        tr("Layout and refresh of the hex dump in the Memory Viewer."));
    QSettings s;

    bytesPerRowSpin_ = sized(new QSpinBox);
    bytesPerRowSpin_->setRange(8, 64);   // the view uses 8, 16, 32 or 64
    bytesPerRowSpin_->setSingleStep(8);
    bytesPerRowSpin_->setValue(s.value(MV_BYTES_PER_ROW_KEY, 16).toInt());
    form->addRow(tr("Bytes per row:"), bytesPerRowSpin_);

    autoRefreshCheck_ = new QCheckBox(tr("Refresh values while the view is open"));
    autoRefreshCheck_->setChecked(s.value(MV_AUTO_REFRESH_KEY, true).toBool());
    form->addRow("", autoRefreshCheck_);

    refreshIntervalSpin_ = sized(new QSpinBox);
    refreshIntervalSpin_->setRange(100, 30'000);
    refreshIntervalSpin_->setSingleStep(100);
    refreshIntervalSpin_->setSuffix(tr(" ms"));
    refreshIntervalSpin_->setValue(s.value(MV_REFRESH_MS_KEY, 2000).toInt());   // the Memory Viewer default
    refreshIntervalSpin_->setEnabled(autoRefreshCheck_->isChecked());
    connect(autoRefreshCheck_, &QCheckBox::toggled, refreshIntervalSpin_, &QWidget::setEnabled);
    form->addRow(tr("Refresh interval:"), refreshIntervalSpin_);
    form->addRow("", hint(tr("Applies to Memory Viewer windows opened from now on.")));
    return w;
}

QWidget* SettingsDialog::buildDebuggerPage() {
    auto* w = new QWidget;
    auto* form = makePage(w, tr("Debugger"), tr("Defaults for hardware watchpoints."));
    QSettings s;

    dataBpSizeCombo_ = sizeCombo(s.value(DBG_BP_SIZE_KEY, "4").toString());
    form->addRow(tr("Data breakpoint size:"), dataBpSizeCombo_);
    watchSizeCombo_ = sizeCombo(s.value(CF_WATCH_SIZE_KEY, "4").toString());
    form->addRow(tr("Find-what-writes size:"), watchSizeCombo_);
    form->addRow("", hint(tr("How many bytes from the address a watchpoint covers. "
                             "x86 watchpoints must be aligned to their size.")));
    return w;
}

QWidget* SettingsDialog::buildHotkeysPage() {
    auto* w = new QWidget;
    auto* form = makePage(w, tr("Hotkeys"), tr("Hotkeys belong to cheat table entries: right-click an entry and "
                                               "choose Hotkeys."));
    QSettings s;
    valueStepEdit_ = sized(new QLineEdit(s.value(HK_VALUE_STEP_KEY, "1").toString()));
    valueStepEdit_->setValidator(new QDoubleValidator(valueStepEdit_));
    form->addRow(tr("Default value step:"), valueStepEdit_);
    form->addRow("", hint(tr("How much an increase or decrease hotkey changes a value, "
                             "until the entry sets its own step.")));
    return w;
}

QWidget* SettingsDialog::buildNetworkPage() {
    auto* w = new QWidget;
    auto* form = makePage(w, tr("Network"),
        tr("The ceserver that File > Connect to ceserver offers by default."));
    QSettings s;
    ceserverHostEdit_ = sized(new QLineEdit(s.value(NET_CESERVER_HOST_KEY, "127.0.0.1").toString()));
    ceserverHostEdit_->setPlaceholderText(tr("host name or IP address"));
    form->addRow(tr("ceserver host:"), ceserverHostEdit_);
    ceserverPortSpin_ = sized(new QSpinBox);
    ceserverPortSpin_->setRange(1, 65535);
    ceserverPortSpin_->setGroupSeparatorShown(false);
    ceserverPortSpin_->setValue(s.value(NET_CESERVER_PORT_KEY, 52736).toInt());
    form->addRow(tr("ceserver port:"), ceserverPortSpin_);
    return w;
}

QWidget* SettingsDialog::buildLuaPage() {
    auto* w = new QWidget;
    auto* form = makePage(w, tr("Lua"),
        tr("Scripts in the autorun folder run once at startup, like Cheat Engine's autorun."));
    const QString folder = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation) + "/autorun";
    auto* path = new QLineEdit(QDir::toNativeSeparators(folder));
    path->setReadOnly(true);
    path->setToolTip(path->text());
    path->setMinimumWidth(kFieldWidth);
    auto* open = new QPushButton(tr("Open folder"));
    connect(open, &QPushButton::clicked, this, [folder]() {
        QDir().mkpath(folder);
        QDesktopServices::openUrl(QUrl::fromLocalFile(folder));
    });
    auto* row = new QHBoxLayout;
    row->addWidget(path, 1);
    row->addWidget(open);
    form->addRow(tr("Autorun folder:"), row);
    form->addRow("", hint(tr("Lua cannot run shell commands or write local files unless Cheat Engine "
                             "was started with CECORE_LUA_ALLOW_UNSAFE=1 in its environment. A cheat "
                             "table cannot turn this on by itself.")));
    form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    return w;
}

namespace {
const char* const kAgentAccounts[2] = {"anthropic", "openai-compatible"};
const char* const kAgentEnv[2] = {"ANTHROPIC_API_KEY", "OPENAI_API_KEY"};
QString agentKeyState(int provider, const QString& baseUrl) {
    if (!qEnvironmentVariableIsEmpty(kAgentEnv[provider])) {
        if (agentEnvKeyApplies(provider == 1, baseUrl))
            return QCoreApplication::translate("SettingsDialog", "Using %1 from the environment.")
                .arg(kAgentEnv[provider]);
        // Not sent to another server, so a key for it is set here.
    }
    QSettings s;
    const QString saved = s.value(QString("agent/%1/keyStored").arg(kAgentAccounts[provider])).toString();
    // A key is only sent to the address it was saved for.
    QString refusal = agentKeyRefusal(provider == 1, baseUrl, s.value(QString("agent/%1/keyOrigin").arg(kAgentAccounts[provider])).toString());
    if (!refusal.isEmpty()) refusal.prepend(' ');
    if (saved == "keyring")
        return QCoreApplication::translate("SettingsDialog", "A key is saved in the system keyring.") + refusal;
    if (SecretStore(kAgentAccounts[provider]).inMemory())
        return QCoreApplication::translate("SettingsDialog",
                   "A key is set until Cheat Engine closes (no keyring was available).") + refusal;
    return provider == 0
        ? QCoreApplication::translate("SettingsDialog",
              "No key yet. Create one at console.anthropic.com.")
        : QCoreApplication::translate("SettingsDialog",
              "No key set; local servers usually need none.");
}
} // namespace

QWidget* SettingsDialog::buildAgentPage() {
    auto* w = new QWidget;
    auto* form = makePage(w, tr("AI Assistant"),
        tr("The model behind Tools > AI Assistant. You bring the API key, "
           "or run a model on your own computer."));
    QSettings s;
    agentProviderCombo_ = sized(new QComboBox);
    agentProviderCombo_->addItem(tr("Anthropic (Claude)"));
    agentProviderCombo_->addItem(tr("OpenAI-compatible (OpenAI, Ollama, LM Studio)"));
    for (int i = 0; i < 2; ++i) {
        agentModels_[i] = s.value(QString("agent/%1/model").arg(kAgentAccounts[i])).toString();
        agentUrls_[i] = s.value(QString("agent/%1/baseUrl").arg(kAgentAccounts[i])).toString();
    }
    form->addRow(tr("Provider:"), agentProviderCombo_);
    agentModelEdit_ = sized(new QLineEdit);
    form->addRow(tr("Model:"), agentModelEdit_);
    agentUrlEdit_ = sized(new QLineEdit);
    form->addRow(tr("API address:"), agentUrlEdit_);
    agentKeyEdit_ = sized(new QLineEdit);
    agentKeyEdit_->setEchoMode(QLineEdit::Password);
    agentKeyEdit_->setPlaceholderText(tr("Paste a new key to save it"));
    auto* forget = new QPushButton(tr("Forget key"));
    auto* keyRow = new QHBoxLayout;
    keyRow->addWidget(agentKeyEdit_);
    keyRow->addWidget(forget);
    keyRow->addStretch(1);
    form->addRow(tr("API key:"), keyRow);
    agentKeyStatus_ = hint(QString());
    form->addRow("", agentKeyStatus_);
    form->addRow("", hint(tr("Keys are kept in the system keyring, never in Cheat Engine's settings file; "
                             "ANTHROPIC_API_KEY or OPENAI_API_KEY in the environment take precedence. A saved "
                             "key is only sent to the API address it was entered with. Your "
                             "messages and what the tools find in the game are sent to this provider, and "
                             "every change to the game waits for your Allow.")));
    connect(agentProviderCombo_, &QComboBox::currentIndexChanged, this, &SettingsDialog::showAgentProvider);
    connect(forget, &QPushButton::clicked, this, [this]() {
        const int provider = agentProviderCombo_->currentIndex();
        QString error;
        SecretStore(kAgentAccounts[provider]).remove(&error);
        QSettings().remove(QString("agent/%1/keyStored").arg(kAgentAccounts[provider]));
        QSettings().remove(QString("agent/%1/keyOrigin").arg(kAgentAccounts[provider]));
        agentKeyStatus_->setText(error.isEmpty()
            ? agentKeyState(provider, agentUrlEdit_->text())
            : tr("Could not remove the key: %1").arg(error));
    });
    agentProviderCombo_->setCurrentIndex(s.value("agent/provider", 0).toInt() == 1 ? 1 : 0);
    showAgentProvider(agentProviderCombo_->currentIndex());
    return w;
}

void SettingsDialog::showAgentProvider(int index) {
    if (agentShown_ >= 0) {
        agentModels_[agentShown_] = agentModelEdit_->text().trimmed();
        agentUrls_[agentShown_] = agentUrlEdit_->text().trimmed();
    }
    agentShown_ = index;
    agentModelEdit_->setText(agentModels_[index]);
    agentModelEdit_->setPlaceholderText(index == 0
        ? QString(ChatProvider::defaultAnthropicModel())
        : tr("for example gpt-5 or qwen3"));
    agentUrlEdit_->setText(agentUrls_[index]);
    agentUrlEdit_->setPlaceholderText(index == 0
        ? QStringLiteral("https://api.anthropic.com")
        : tr("https://api.openai.com/v1 or http://localhost:11434/v1"));
    agentKeyEdit_->clear();
    agentKeyStatus_->setText(agentKeyState(index, agentUrls_[index]));
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
    // Store a choice only when there is one: OK with the theme untouched keeps
    // following the desktop's light/dark preference.
    if (s.contains(kDarkThemeKey) || dark != isDarkTheme())
        s.setValue(kDarkThemeKey, dark);
    // Re-apply the theme live: a theme change takes effect immediately, and the
    // sheet also carries the data tables' monospace font.
    applyTheme(dark);

    // A translator can only be installed before the windows are built, so the new
    // language starts with the next run.
    const QString language = languageCombo_->currentData().toString();
    const bool languageChanged = language != s.value(UI_LANGUAGE_KEY).toString();
    s.setValue(UI_LANGUAGE_KEY, language);

    s.setValue(MV_BYTES_PER_ROW_KEY,  bytesPerRowSpin_->value());
    s.setValue(MV_AUTO_REFRESH_KEY,   autoRefreshCheck_->isChecked());
    s.setValue(MV_REFRESH_MS_KEY,     refreshIntervalSpin_->value());

    s.setValue(DBG_BP_SIZE_KEY,       dataBpSizeCombo_->currentData().toString());
    s.setValue(CF_WATCH_SIZE_KEY,     watchSizeCombo_->currentData().toString());

    s.setValue(HK_VALUE_STEP_KEY,     valueStepEdit_->text().trimmed().isEmpty() ? "1" : valueStepEdit_->text().trimmed());

    s.setValue(NET_CESERVER_HOST_KEY, ceserverHostEdit_->text().trimmed());
    s.setValue(NET_CESERVER_PORT_KEY, ceserverPortSpin_->value());

    // Read the key before showAgentProvider, which clears the field.
    const QString key = agentKeyEdit_->text().trimmed();
    showAgentProvider(agentProviderCombo_->currentIndex());   // keep the fields being edited
    s.setValue("agent/provider", agentProviderCombo_->currentIndex());
    for (int i = 0; i < 2; ++i) {
        s.setValue(QString("agent/%1/model").arg(kAgentAccounts[i]), agentModels_[i]);
        s.setValue(QString("agent/%1/baseUrl").arg(kAgentAccounts[i]), agentUrls_[i]);
    }
    if (!key.isEmpty()) {
        const int provider = agentProviderCombo_->currentIndex();
        SecretStore store(kAgentAccounts[provider]);
        QString error;
        store.store(key, &error);
        // The key goes only to the address it was entered for.
        s.setValue(QString("agent/%1/keyOrigin").arg(kAgentAccounts[provider]), agentOrigin(provider == 1, agentUrls_[provider]));
        // A key kept in memory dies with this run, so only the keyring is remembered.
        if (store.persisted()) s.setValue(QString("agent/%1/keyStored").arg(kAgentAccounts[provider]), "keyring");
        else s.remove(QString("agent/%1/keyStored").arg(kAgentAccounts[provider]));
        agentKeyEdit_->clear();
        agentKeyStatus_->setText(store.persisted()
            ? agentKeyState(provider, agentUrls_[provider])
            : tr("Kept until Cheat Engine closes: %1").arg(error));
    }
    emit settingsApplied();
    if (languageChanged) {
        // A new language needs a fresh start: every window builds its texts in its
        // constructor, so offer the restart instead of leaving the choice to the
        // next manual start. Unsaved table state is the user's call.
        QMessageBox box(this);
        box.setIcon(QMessageBox::Question);
        box.setWindowTitle(tr("Language"));
        box.setText(tr("Restart Cheat Engine to apply the new interface language."));
        box.setInformativeText(tr("Save the table first if you need the current addresses and scan results."));
        auto* restart = box.addButton(tr("Restart now"), QMessageBox::AcceptRole);
        box.addButton(tr("Later"), QMessageBox::RejectRole);
        box.exec();
        if (box.clickedButton() == restart) restartApplication(this);
    }
}

} // namespace ce::gui
